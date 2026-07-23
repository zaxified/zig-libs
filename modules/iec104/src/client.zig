// SPDX-License-Identifier: MIT

//! A controlling-station (master) client: the control-centre end of an
//! IEC 60870-5-104 link.
//!
//! It glues the three pure layers together — `apci.Framer` for the byte
//! stream, `state.Connection` for k/w and t0..t3, `asdu` for the payload — and
//! adds the operations a real master performs: `STARTDT`, general and counter
//! interrogation, monitoring-data reception, commands (including
//! select-before-operate), clock synchronisation, read and test commands, and
//! `STOPDT`.
//!
//! **The transport is a seam, and the clock is a parameter.** The client
//! speaks through a `Transport` with one `read` and one `write`, and every
//! entry point takes `now_ms` from the caller. There is no thread, no timer
//! and no socket inside — which is what makes the whole thing testable against
//! an in-memory pipe. `TcpTransport` is an optional adapter onto
//! `std.Io.net`; nothing else in this module touches I/O.

const std = @import("std");
const apci = @import("apci.zig");
const asdu_mod = @import("asdu.zig");
const info = @import("info.zig");
const state = @import("state.zig");
const transport_mod = @import("transport.zig");

pub const TransportError = transport_mod.TransportError;
pub const Transport = transport_mod.Transport;
pub const TcpTransport = transport_mod.TcpTransport;
pub const LoopTransport = transport_mod.LoopTransport;
pub const default_port = transport_mod.default_port;

pub const Options = struct {
    /// Per-system address widths.
    params: asdu_mod.Params = asdu_mod.default_params,
    /// Flow-control parameters k, w, t0..t3.
    config: state.Config = .{},
    /// Originator address stamped into every ASDU this client sends.
    originator: u8 = 0,
    /// Mark every ASDU this client sends as a test (the COT T bit).
    test_mode: bool = false,
};

pub const Error = TransportError || state.Error || asdu_mod.Error || apci.FramerError || apci.EncodeError;

/// What one `poll` produced.
pub const Incoming = union(enum) {
    /// Nothing happened this round.
    none,
    /// An ASDU arrived. It aliases the client's receive buffer and stays
    /// valid only until the next `poll`.
    asdu: asdu_mod.Asdu,
    /// An ASDU arrived whose type id this module does not model; the data
    /// unit identifier is still readable. The connection is fine — a master
    /// simply ignores what it does not understand.
    unsupported_asdu: asdu_mod.Header,
    /// Data transfer is now active (STARTDT confirmed).
    started,
    /// Data transfer has stopped (STOPDT confirmed).
    stopped,
    /// The link was tested and answered.
    test_confirmed,
    /// A protocol timeout fired; the caller must close the connection.
    closed: state.CloseReason,
};

pub const Client = struct {
    conn: state.Connection,
    transport: Transport,
    opts: Options,
    framer: apci.Framer,
    /// Scratch for one outgoing APDU.
    tx: [apci.max_apdu_len]u8 = undefined,
    /// Scratch for one outgoing ASDU body.
    tx_asdu: [apci.max_asdu_len]u8 = undefined,
    /// Scratch for one stream read.
    rx_chunk: [apci.max_apdu_len]u8 = undefined,

    /// `frame_buf` must hold at least `apci.max_apdu_len` octets; twice that
    /// lets a single read carry more than one frame without a compaction.
    pub fn init(transport: Transport, frame_buf: []u8, opts: Options) Error!Client {
        try opts.params.validate();
        return .{
            .conn = try state.Connection.init(opts.config, .controlling),
            .transport = transport,
            .opts = opts,
            .framer = apci.Framer.init(frame_buf),
        };
    }

    // ── connection lifecycle ────────────────────────────────────────────────

    /// Tell the client a TCP connect is in flight (arms t0).
    pub fn beginConnect(self: *Client, now: u64) void {
        self.conn.beginConnect(now);
    }

    /// Tell the client the TCP connection is up.
    pub fn onConnected(self: *Client, now: u64) void {
        self.conn.onTcpConnected(now);
    }

    /// Tell the client the TCP connection went away.
    pub fn onDisconnected(self: *Client) void {
        self.conn.onTcpClosed();
        self.framer.len = 0;
        self.framer.pos = 0;
    }

    /// Sends `STARTDT act`. Data transfer becomes active when the peer's
    /// `STARTDT con` arrives — watch for `Incoming.started`.
    pub fn startDataTransfer(self: *Client, now: u64) Error!void {
        const func = try self.conn.startDataTransfer(now);
        try self.writeU(func);
    }

    /// Sends `STOPDT act`.
    pub fn stopDataTransfer(self: *Client, now: u64) Error!void {
        const func = try self.conn.stopDataTransfer(now);
        try self.writeU(func);
    }

    /// Sends `TESTFR act` on demand (t3 does it automatically when idle).
    pub fn testLink(self: *Client, now: u64) Error!void {
        const func = try self.conn.sendTestFrame(now);
        try self.writeU(func);
    }

    pub fn isStarted(self: *const Client) bool {
        return self.conn.isStarted();
    }

    /// When `poll` should next be called even with no data pending.
    pub fn nextDeadline(self: *const Client) ?u64 {
        return self.conn.nextDeadline();
    }

    // ── sending ─────────────────────────────────────────────────────────────

    /// Sends one single-object ASDU as an I-frame.
    pub fn send(
        self: *Client,
        type_id: asdu_mod.TypeId,
        cot: asdu_mod.Cot,
        common_address: u16,
        ioa: u32,
        element: asdu_mod.Element,
        time: asdu_mod.TimeTag,
        now: u64,
    ) Error!void {
        const body = try asdu_mod.buildSingle(
            &self.tx_asdu,
            self.opts.params,
            type_id,
            .{ .cot = cot, .originator = self.opts.originator, .is_test = self.opts.test_mode },
            common_address,
            ioa,
            element,
            time,
        );
        try self.sendAsdu(body, now);
    }

    /// Sends an already-encoded ASDU as an I-frame. Fails with
    /// `error.SendWindowFull` when k frames are outstanding — the caller then
    /// polls until an acknowledgement frees a slot.
    pub fn sendAsdu(self: *Client, body: []const u8, now: u64) Error!void {
        const control = try self.conn.prepareI(now);
        const frame = try apci.encode(control, body, &self.tx);
        try self.transport.write(frame);
    }

    /// General (station) interrogation — `C_IC_NA_1`, IOA 0, QOI 20.
    pub fn interrogate(self: *Client, common_address: u16, qoi: info.Qoi, now: u64) Error!void {
        try self.send(.c_ic_na_1, .activation, common_address, 0, .{ .qoi = qoi }, .none, now);
    }

    /// Counter interrogation — `C_CI_NA_1`, IOA 0.
    pub fn interrogateCounters(self: *Client, common_address: u16, qcc: info.Qcc, now: u64) Error!void {
        try self.send(.c_ci_na_1, .activation, common_address, 0, .{ .qcc = qcc }, .none, now);
    }

    /// Clock synchronisation — `C_CS_NA_1`, IOA 0. The time is the caller's:
    /// this module never reads a system clock.
    pub fn syncClock(self: *Client, common_address: u16, time: info.CP56Time2a, now: u64) Error!void {
        try self.send(.c_cs_na_1, .activation, common_address, 0, .{ .empty = {} }, .{ .cp56 = time }, now);
    }

    /// Read command — `C_RD_NA_1`. Note its cause of transmission is
    /// `request` (5), not `activation`.
    pub fn readPoint(self: *Client, common_address: u16, ioa: u32, now: u64) Error!void {
        try self.send(.c_rd_na_1, .request, common_address, ioa, .{ .empty = {} }, .none, now);
    }

    /// Test command — `C_TS_NA_1`, IOA 0, with the standard fixed test
    /// pattern.
    pub fn testCommand(self: *Client, common_address: u16, pattern: u16, now: u64) Error!void {
        try self.send(.c_ts_na_1, .activation, common_address, 0, .{ .fbp = pattern }, .none, now);
    }

    /// Reset process command — `C_RP_NA_1`, IOA 0.
    pub fn resetProcess(self: *Client, common_address: u16, qrp: info.Qrp, now: u64) Error!void {
        try self.send(.c_rp_na_1, .activation, common_address, 0, .{ .qrp = qrp }, .none, now);
    }

    /// Sends a command with cause `activation`.
    ///
    /// **Select-before-operate** is two of these: first with the element's
    /// S/E bit set to `.select`, then — after the outstation's positive
    /// activation confirmation — the identical command with `.execute`. The
    /// two frames differ in exactly that one bit; `selectThenExecute` in the
    /// tests shows the sequence.
    pub fn command(
        self: *Client,
        type_id: asdu_mod.TypeId,
        common_address: u16,
        ioa: u32,
        element: asdu_mod.Element,
        time: asdu_mod.TimeTag,
        now: u64,
    ) Error!void {
        try self.send(type_id, .activation, common_address, ioa, element, time, now);
    }

    // ── receiving ───────────────────────────────────────────────────────────

    /// Advances the connection by one step: performs any timer-driven writes,
    /// then delivers at most one received frame, reading from the transport
    /// only when nothing is already buffered.
    ///
    /// Call it in a loop; `nextDeadline` says when to call it again if there
    /// is no data.
    pub fn poll(self: *Client, now: u64) Error!Incoming {
        // 1. Timer-driven output first, so acknowledgements and test frames
        //    go out even on a completely idle link.
        while (true) {
            switch (self.conn.tick(now)) {
                .none => break,
                .close => |r| return .{ .closed = r },
                .send_s_frame => |nr| try self.writeRaw(&apci.encodeS(nr)),
                .send_u => |f| try self.writeU(f),
            }
        }

        // 2. Anything already framed?
        if (try self.framer.next()) |apdu| return try self.dispatch(apdu, now);

        // 3. Otherwise take one read from the stream.
        const n = try self.transport.read(&self.rx_chunk);
        if (n == 0) return .none;
        try self.framer.feed(self.rx_chunk[0..n]);
        if (try self.framer.next()) |apdu| return try self.dispatch(apdu, now);
        return .none;
    }

    fn dispatch(self: *Client, apdu: apci.Apdu, now: u64) Error!Incoming {
        const event = try self.conn.onFrame(apdu, now);
        return switch (event) {
            .none => .none,
            .started => .started,
            .stopped => .stopped,
            .test_confirmed => .test_confirmed,
            // The confirmation goes out on the next `tick`; report nothing.
            .test_requested => .none,
            .asdu => |body| blk: {
                const header = try asdu_mod.decodeHeader(body, self.opts.params);
                if (asdu_mod.shapeOf(header.type_id) == null) {
                    break :blk .{ .unsupported_asdu = header };
                }
                break :blk .{ .asdu = try asdu_mod.decode(body, self.opts.params) };
            },
        };
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn writeU(self: *Client, func: apci.UFunction) Error!void {
        try self.writeRaw(&apci.encodeU(func));
    }

    fn writeRaw(self: *Client, bytes: []const u8) Error!void {
        try self.transport.write(bytes);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "client: connect, STARTDT, interrogate, receive data, STOPDT" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{});

    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    try testing.expectEqualSlices(u8, &hex("680407000000"), loop.sent());
    loop.clearSent();

    // Nothing may be sent before the confirmation.
    try testing.expectError(error.NotStarted, c.interrogate(47, .station, 0));

    loop.deliver(&hex("68040b000000"));
    try testing.expectEqual(Incoming.started, try c.poll(0));
    try testing.expect(c.isStarted());

    try c.interrogate(47, .station, 0);
    // Byte-for-byte the frame the third-party master sent in the capture,
    // apart from the sequence numbers (this is our first I-frame).
    try testing.expectEqualSlices(u8, &hex("680e00000000640106002f0000000014"), loop.sent());
    loop.clearSent();

    // The outstation confirms, then sends one monitoring point.
    loop.deliver(&hex("680e00000200640107002f0000000014"));
    const con = try c.poll(0);
    try testing.expectEqual(asdu_mod.TypeId.c_ic_na_1, con.asdu.header.type_id);
    try testing.expectEqual(asdu_mod.Cot.activation_con, con.asdu.header.cause.cot);

    loop.deliver(&hex("680e02000200018114002f0065000001"));
    const data = try c.poll(0);
    var it = data.asdu.objects();
    const o = (try it.next()).?;
    try testing.expectEqual(@as(u32, 101), o.ioa);
    try testing.expect(o.element.siq.on);

    try c.stopDataTransfer(0);
    try testing.expectEqualSlices(u8, &hex("680413000000"), loop.sent());
    loop.clearSent();
    loop.deliver(&hex("680423000000"));
    try testing.expectEqual(Incoming.stopped, try c.poll(0));
    try testing.expect(!c.isStarted());
}

test "client: select-before-operate is two frames differing in the S/E bit" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{});
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);
    loop.clearSent();

    // 1. select
    try c.command(.c_sc_na_1, 47, 301, .{ .sco = .{ .on = true, .select = .select } }, .none, 0);
    const select_frame = hex("680e000000002d0106002f002d010081");
    try testing.expectEqualSlices(u8, &select_frame, loop.sent());
    loop.clearSent();

    // 2. the outstation confirms the selection (positive)
    loop.deliver(&hex("680e000002002d0107002f002d010081"));
    const con = try c.poll(0);
    try testing.expectEqual(asdu_mod.Cot.activation_con, con.asdu.header.cause.cot);
    try testing.expect(!con.asdu.header.cause.negative);
    var ci = con.asdu.objects();
    try testing.expectEqual(info.SelectExecute.select, (try ci.next()).?.element.sco.select);

    // 3. execute: the identical command with S/E cleared
    try c.command(.c_sc_na_1, 47, 301, .{ .sco = .{ .on = true, .select = .execute } }, .none, 0);
    try testing.expectEqualSlices(u8, &hex("680e020002002d0106002f002d010001"), loop.sent());
}

test "client: a negative activation confirmation is visible, not an error" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{});
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);

    // The ASDU is exactly the negative confirmation the third-party server
    // produced for an unknown IOA; only the APCI sequence numbers are
    // adapted, since this client has not sent an I-frame yet.
    loop.deliver(&hex("680e000000002d0147002f00e7030001"));
    const r = try c.poll(0);
    try testing.expectEqual(asdu_mod.Cot.activation_con, r.asdu.header.cause.cot);
    try testing.expect(r.asdu.header.cause.negative);
}

test "client: an unmodelled type id is reported, not fatal" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{});
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);

    // A well-formed I-frame carrying type id 200, which has no modelled
    // element layout here.
    loop.deliver(&hex("680e00000000c80106002f0000000000"));
    const r = try c.poll(0);
    try testing.expectEqual(@as(u8, 200), @intFromEnum(r.unsupported_asdu.type_id));
    try testing.expectEqual(asdu_mod.Cot.activation, r.unsupported_asdu.cause.cot);
    // The connection survives it.
    try testing.expect(c.isStarted());
}

test "client: k exhaustion is reported and released by an acknowledgement" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{ .config = .{ .k = 2, .w = 1 } });
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);

    try c.interrogate(47, .station, 0);
    try c.interrogate(47, .station, 0);
    try testing.expectError(error.SendWindowFull, c.interrogate(47, .station, 0));
    loop.deliver(&hex("680401000400")); // S-format, N(R) = 2
    _ = try c.poll(0);
    try c.interrogate(47, .station, 0);
}

test "client: t2 makes the client acknowledge on its own" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{
        .config = .{ .k = 12, .w = 8, .t0_ms = 1000, .t1_ms = 100, .t2_ms = 50, .t3_ms = 100_000 },
    });
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);
    loop.clearSent();

    loop.deliver(&hex("680e00000000018114002f0065000001"));
    _ = try c.poll(0);
    try testing.expectEqual(@as(usize, 0), loop.sent().len); // below w, t2 not due
    _ = try c.poll(50);
    try testing.expectEqualSlices(u8, &hex("680401000200"), loop.sent()); // N(R) = 1
}

test "client: t3 sends a test frame and t1 reports a dead peer" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{
        .config = .{ .k = 12, .w = 8, .t0_ms = 1000, .t1_ms = 100, .t2_ms = 50, .t3_ms = 30 },
    });
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);
    loop.clearSent();

    try testing.expectEqual(Incoming.none, try c.poll(30));
    try testing.expectEqualSlices(u8, &hex("680443000000"), loop.sent());
    // The peer never confirms: t1 fires and the caller is told to close.
    switch (try c.poll(130)) {
        .closed => |r| try testing.expectEqual(state.CloseReason.confirm_timeout, r),
        else => return error.TestUnexpectedResult,
    }
}

test "client: a TESTFR act from the peer is confirmed automatically" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{});
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);
    loop.clearSent();

    loop.deliver(&hex("680443000000"));
    try testing.expectEqual(Incoming.none, try c.poll(0));
    try testing.expectEqual(Incoming.none, try c.poll(0)); // tick emits the con
    try testing.expectEqualSlices(u8, &hex("680483000000"), loop.sent());
}

test "client: the originator address and test bit reach the wire" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{ .originator = 7, .test_mode = true });
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);
    loop.clearSent();

    try c.interrogate(47, .station, 0);
    const sent = loop.sent();
    const a = try asdu_mod.decode(sent[apci.apci_len..], asdu_mod.default_params);
    try testing.expectEqual(@as(u8, 7), a.header.cause.originator);
    try testing.expect(a.header.cause.is_test);
    // COT 6 | T bit 0x80 = 0x86.
    try testing.expectEqual(@as(u8, 0x86), sent[apci.apci_len + 2]);
}

test "client: a frame split across two reads is reassembled" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{});
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    const con = hex("68040b000000");
    loop.deliver(con[0..2]);
    try testing.expectEqual(Incoming.none, try c.poll(0));
    loop.deliver(con[2..]);
    try testing.expectEqual(Incoming.started, try c.poll(0));
}

test "client: alternative address sizing changes the frames it emits" {
    var loop = LoopTransport{};
    var frame_buf: [apci.max_apdu_len * 2]u8 = undefined;
    var c = try Client.init(loop.transport(), &frame_buf, .{
        .params = .{ .ioa_size = 2, .ca_size = 1, .cot_size = 1 },
    });
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    _ = try c.poll(0);
    loop.clearSent();

    try c.interrogate(9, .station, 0);
    // 68 0B | 00 00 00 00 | type 100, VSQ 1, COT 6, CA 9 | IOA 0 (2 octets) | QOI 20
    try testing.expectEqualSlices(u8, &hex("680b0000000064010609000014"), loop.sent());
}

// ── live interop (skips when no peer is present) ────────────────────────────
//
// Set IEC104_TEST_SERVER=host:port to run a real round trip against a live
// IEC 60870-5-104 controlled station (a `c104`/lib60870 server on :2404, for
// instance). Without it the test prints SKIPPED and passes, exactly like the
// live tests in `netconf`, `ssh` and `tc`.

const builtin = @import("builtin");

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

test "live: STARTDT + general interrogation against a real outstation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("IEC104_TEST_SERVER") orelse {
        std.debug.print("SKIPPED: live IEC 104 interop (set IEC104_TEST_SERVER=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ca_text = envVar("IEC104_TEST_CA") orelse "47";
    const common_address = std.fmt.parseInt(u16, ca_text, 10) catch return error.SkipZigTest;

    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return error.SkipZigTest;
    const host = endpoint[0..colon];
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(host, port) catch return error.SkipZigTest;
    var tt = TcpTransport.connect(io, addr) catch {
        std.debug.print("SKIPPED: live IEC 104 interop (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer tt.close();
    // Bound the blocking reads so an unresponsive peer fails the test rather
    // than hanging it.
    try tt.setReadTimeout(500);

    var frame_buf: [apci.max_apdu_len * 4]u8 = undefined;
    var c = try Client.init(tt.transport(), &frame_buf, .{});
    var now: u64 = 0;
    c.beginConnect(now);
    c.onConnected(now);
    try c.startDataTransfer(now);

    var saw_started = false;
    var saw_con = false;
    var saw_termination = false;
    var monitoring: usize = 0;
    var rounds: usize = 0;
    var interrogated = false;
    while (rounds < 200 and !saw_termination) : (rounds += 1) {
        now += 100;
        switch (try c.poll(now)) {
            .started => {
                saw_started = true;
                try c.interrogate(common_address, .station, now);
                interrogated = true;
            },
            .asdu => |a| {
                if (a.header.type_id == .c_ic_na_1) {
                    switch (a.header.cause.cot) {
                        .activation_con => saw_con = true,
                        .activation_termination => saw_termination = true,
                        else => {},
                    }
                } else if (a.header.type_id.isMonitoring()) {
                    monitoring += 1;
                }
            },
            .closed => break,
            else => {},
        }
    }
    std.debug.print(
        "live IEC 104: started={} act_con={} act_term={} monitoring_asdus={d}\n",
        .{ saw_started, saw_con, saw_termination, monitoring },
    );
    try testing.expect(saw_started);
    try testing.expect(saw_con);
    try testing.expect(interrogated);
    try testing.expect(saw_termination);
    try testing.expect(monitoring > 0);

    // Select-before-operate against the live peer: IOA 301 is configured
    // select-and-execute on the server side, so the select must be positively
    // confirmed before the execute is accepted.
    const sbo_ioa = std.fmt.parseInt(u32, envVar("IEC104_TEST_SBO_IOA") orelse "301", 10) catch 301;
    try c.command(.c_sc_na_1, common_address, sbo_ioa, .{ .sco = .{ .on = true, .select = .select } }, .none, now);
    var select_con = false;
    var execute_con = false;
    var sent_execute = false;
    rounds = 0;
    while (rounds < 200 and !execute_con) : (rounds += 1) {
        now += 100;
        switch (try c.poll(now)) {
            .asdu => |a| {
                if (a.header.type_id != .c_sc_na_1) continue;
                if (a.header.cause.cot != .activation_con) continue;
                try testing.expect(!a.header.cause.negative);
                var oi = a.objects();
                const obj = (try oi.next()).?;
                try testing.expectEqual(sbo_ioa, obj.ioa);
                switch (obj.element.sco.select) {
                    .select => {
                        select_con = true;
                        try c.command(.c_sc_na_1, common_address, sbo_ioa, .{ .sco = .{ .on = true, .select = .execute } }, .none, now);
                        sent_execute = true;
                    },
                    .execute => execute_con = true,
                }
            },
            .closed => break,
            else => {},
        }
    }
    std.debug.print(
        "live IEC 104 select-before-operate: select_con={} sent_execute={} execute_con={}\n",
        .{ select_con, sent_execute, execute_con },
    );
    try testing.expect(select_con);
    try testing.expect(execute_con);

    try c.stopDataTransfer(now);
    // The peer must confirm the STOPDT.
    var stopped = false;
    rounds = 0;
    while (rounds < 100 and !stopped) : (rounds += 1) {
        now += 100;
        switch (try c.poll(now)) {
            .stopped => stopped = true,
            .closed => break,
            else => {},
        }
    }
    try testing.expect(stopped);
    std.debug.print("live IEC 104: STOPDT confirmed\n", .{});
}

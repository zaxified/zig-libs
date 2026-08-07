// SPDX-License-Identifier: MIT

//! A controlled-station (outstation / RTU) responder — the field end of an
//! IEC 60870-5-104 link, and therefore also a **fleet-simulation target**: a
//! whole substation of these can be stood up in one process to exercise a
//! master, with no hardware and no C stack.
//!
//! It is a pure ASDU-level responder: `handle` takes one received ASDU and
//! emits zero or more reply ASDUs through a `Sink`. Nothing here reads a
//! clock, opens a socket or allocates; the APCI framing and the k/w/t0..t3
//! flow control belong to `apci` and `state`, and the caller wires the three
//! together (see `root.zig`'s loopback test for exactly how).
//!
//! Implemented: general and group interrogation, counter interrogation, read,
//! clock synchronisation, test command, reset process, and the six command
//! types in both direct and **select-before-operate** mode, plus the three
//! error causes of transmission (unknown type id / common address /
//! information-object address / cause) that a real RTU produces.

const std = @import("std");
const apci = @import("apci.zig");
const asdu_mod = @import("asdu.zig");
const info = @import("info.zig");
const state = @import("state.zig");
const transport_mod = @import("transport.zig");

pub const Transport = transport_mod.Transport;
pub const TransportError = transport_mod.TransportError;

pub const SinkError = error{
    /// The caller's output buffer or send window cannot take another ASDU.
    SinkFull,
};

/// Where reply ASDUs go. One `send` per ASDU; the caller frames each into an
/// I-frame and writes it.
pub const Sink = struct {
    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, asdu_bytes: []const u8) SinkError!void,

    pub fn send(self: Sink, bytes: []const u8) SinkError!void {
        return self.sendFn(self.ctx, bytes);
    }
};

/// How a command point must be operated.
pub const CommandMode = enum {
    /// A single activation fires the output.
    direct,
    /// A `select` activation must be positively confirmed before the matching
    /// `execute` activation is accepted (§7.2.6.26's S/E bit).
    select_and_execute,
};

/// One point in the outstation's database.
pub const Point = struct {
    ioa: u32,
    type_id: asdu_mod.TypeId,
    /// The point's current value (monitoring points) or the last accepted
    /// command (control points).
    element: asdu_mod.Element,
    /// Time tag reported with the value, for the `*_TB_1`/`*_TA_1` types.
    time: asdu_mod.TimeTag = .none,
    /// Inventory group 1..16 this point also answers, or 0 for "station
    /// interrogation only".
    group: u8 = 0,
    command_mode: CommandMode = .direct,
    /// Set while a select is outstanding (select-before-operate).
    selected: bool = false,
};

/// Optional application hook: decide whether a command is accepted and act on
/// it. Returning false produces a negative activation confirmation.
pub const CommandHook = struct {
    ctx: *anyopaque,
    acceptFn: *const fn (ctx: *anyopaque, point: *Point, element: asdu_mod.Element) bool,
};

pub const Options = struct {
    /// This station's common address.
    common_address: u16,
    /// Per-system address widths.
    params: asdu_mod.Params = asdu_mod.default_params,
    /// Encode interrogation replies with SQ = 1 (one address, consecutive
    /// elements). lib60870-derived stacks do this even for a single object;
    /// SQ = 0 is equally legal and slightly larger.
    interrogation_sq: bool = true,
    /// Emit an `ACTIVATION TERMINATION` after a successfully executed
    /// command, as §7.2.3 prescribes for commands that take time.
    command_termination: bool = true,
};

pub const Error = SinkError || asdu_mod.Error;

/// §7.2.4: which type ids the global (broadcast) common address is valid for.
/// Only station/counter interrogation, clock synchronisation and reset process.
/// Everything else — every control-direction command in particular — must be
/// ignored when addressed to the broadcast address. Matches lib60870's CS101/
/// CS104 slave, whose broadcast handling covers exactly these four type ids.
fn broadcastable(type_id: asdu_mod.TypeId) bool {
    return switch (type_id) {
        .c_ic_na_1, .c_ci_na_1, .c_cs_na_1, .c_rp_na_1 => true,
        else => false,
    };
}

pub const Outstation = struct {
    opts: Options,
    points: []Point,
    hook: ?CommandHook = null,
    /// Scratch for one reply ASDU.
    scratch: [apci.max_asdu_len]u8 = undefined,

    pub fn init(opts: Options, points: []Point) Error!Outstation {
        try opts.params.validate();
        return .{ .opts = opts, .points = points };
    }

    /// Looks up a point by address (and, when `type_id` is given, by type).
    pub fn find(self: *Outstation, ioa: u32, type_id: ?asdu_mod.TypeId) ?*Point {
        for (self.points) |*p| {
            if (p.ioa != ioa) continue;
            if (type_id) |t| if (p.type_id != t) continue;
            return p;
        }
        return null;
    }

    /// Handles one received ASDU, emitting every reply through `sink`.
    ///
    /// Malformed input never panics: a body that disagrees with the object
    /// count, an unmodelled type id or an impossible time tag all resolve to a
    /// typed error or to the standard's own "unknown …" reply.
    pub fn handle(self: *Outstation, request: []const u8, sink: Sink) Error!void {
        const header = try asdu_mod.decodeHeader(request, self.opts.params);

        // Unknown type identification (§7.2.3 cause 44).
        if (asdu_mod.shapeOf(header.type_id) == null) {
            try self.echoRaw(request, header, .unknown_type_id, true, sink);
            return;
        }

        // Wrong station. Broadcast is accepted by every station.
        const is_broadcast = header.common_address == self.opts.params.broadcastCa();
        if (header.common_address != self.opts.common_address and !is_broadcast) {
            // Matches what a real RTU does: a negative activation
            // confirmation first, then a separate ASDU carrying cause 46.
            try self.echoRaw(request, header, .activation_con, true, sink);
            try self.echoRaw(request, header, .unknown_common_address, false, sink);
            return;
        }

        // §7.2.4: the global (broadcast) common address is defined only for the
        // interrogation / clock-sync / reset-process system commands. Any other
        // type id addressed to it — above all a control-direction command — must
        // never be acted on: a broadcast C_SC_NA_1 that operated the point would
        // fire that output on *every* station on the link, unauthenticated. Such
        // a frame is dropped silently (no actuation, and no reply storm from the
        // whole link answering one broadcast).
        if (is_broadcast and header.common_address != self.opts.common_address and
            !broadcastable(header.type_id))
        {
            return;
        }

        const a = try asdu_mod.decode(request, self.opts.params);
        switch (header.type_id) {
            .c_ic_na_1 => try self.onInterrogation(a, sink),
            .c_ci_na_1 => try self.onCounterInterrogation(a, sink),
            .c_cs_na_1, .c_ts_na_1, .c_ts_ta_1, .c_rp_na_1 => {
                if (header.cause.cot != .activation) {
                    try self.echoDecoded(a, .unknown_cause, true, sink);
                    return;
                }
                // echoDecoded, not echoRaw: it walks the objects, so an
                // impossible CP56Time2a in a clock-sync command is caught
                // here rather than mirrored back to the master.
                try self.echoDecoded(a, .activation_con, false, sink);
            },
            .c_rd_na_1 => try self.onRead(a, request, sink),
            else => {
                if (header.type_id.isCommand()) {
                    try self.onCommand(a, request, sink);
                } else {
                    // A monitor-direction type has no business arriving here.
                    try self.echoRaw(request, header, .unknown_type_id, true, sink);
                }
            },
        }
    }

    /// Builds a spontaneous report of one point (cause 3).
    pub fn reportSpontaneous(self: *Outstation, ioa: u32, sink: Sink) Error!void {
        const p = self.find(ioa, null) orelse return;
        try self.emitPoint(p, .spontaneous, sink);
    }

    // ── request handlers ────────────────────────────────────────────────────

    fn onInterrogation(self: *Outstation, a: asdu_mod.Asdu, sink: Sink) Error!void {
        if (a.header.cause.cot != .activation and a.header.cause.cot != .deactivation) {
            try self.echoDecoded(a, .unknown_cause, true, sink);
            return;
        }
        var it = a.objects();
        const o = (try it.next()) orelse return;
        const qoi = o.element.qoi;
        // §7.2.3 pairs each activation cause with its own confirmation cause:
        // a deactivation (cause 8, which this function never actually
        // performs — it only confirms and returns, below) must be answered
        // with deactivation_con (cause 9), not activation_con.
        const con_cause: asdu_mod.Cot = if (a.header.cause.cot == .deactivation)
            .deactivation_con
        else
            .activation_con;
        try self.echoDecoded(a, con_cause, false, sink);
        if (a.header.cause.cot == .deactivation) return;

        const qoi_value = @intFromEnum(qoi);
        const group: u8 = if (qoi_value >= 21 and qoi_value <= 36) qoi_value - 20 else 0;
        const cause: asdu_mod.Cot = if (group == 0)
            .interrogated_by_station
        else
            asdu_mod.Cot.interrogatedByGroup(group);

        for (self.points) |*p| {
            if (!p.type_id.isMonitoring()) continue;
            // Counters answer a counter interrogation, not this one.
            if (p.type_id == .m_it_na_1 or p.type_id == .m_it_ta_1 or p.type_id == .m_it_tb_1) continue;
            if (group != 0 and p.group != group) continue;
            try self.emitPoint(p, cause, sink);
        }
        try self.echoDecoded(a, .activation_termination, false, sink);
    }

    fn onCounterInterrogation(self: *Outstation, a: asdu_mod.Asdu, sink: Sink) Error!void {
        if (a.header.cause.cot != .activation) {
            try self.echoDecoded(a, .unknown_cause, true, sink);
            return;
        }
        try self.echoDecoded(a, .activation_con, false, sink);
        for (self.points) |*p| {
            switch (p.type_id) {
                .m_it_na_1, .m_it_ta_1, .m_it_tb_1 => try self.emitPoint(p, .requested_by_general_counter, sink),
                else => {},
            }
        }
        try self.echoDecoded(a, .activation_termination, false, sink);
    }

    fn onRead(self: *Outstation, a: asdu_mod.Asdu, request: []const u8, sink: Sink) Error!void {
        if (a.header.cause.cot != .request) {
            try self.echoRaw(request, a.header, .unknown_cause, true, sink);
            return;
        }
        var it = a.objects();
        const o = (try it.next()) orelse return;
        const p = self.find(o.ioa, null) orelse {
            try self.echoDecoded(a, .activation_con, true, sink);
            try self.echoDecoded(a, .unknown_ioa, false, sink);
            return;
        };
        try self.echoDecoded(a, .activation_con, false, sink);
        try self.emitPointWithLayout(p, .request, false, sink);
    }

    fn onCommand(self: *Outstation, a: asdu_mod.Asdu, request: []const u8, sink: Sink) Error!void {
        if (a.header.cause.cot != .activation and a.header.cause.cot != .deactivation) {
            try self.echoRaw(request, a.header, .unknown_cause, true, sink);
            return;
        }
        var it = a.objects();
        const o = (try it.next()) orelse return;

        const p = self.find(o.ioa, a.header.type_id) orelse {
            // Same cause-pairing rule as onInterrogation above: an unknown
            // IOA is still negatively confirmed, but a deactivation naming
            // it must get deactivation_con (cause 9), not activation_con.
            const con_cause: asdu_mod.Cot = if (a.header.cause.cot == .deactivation)
                .deactivation_con
            else
                .activation_con;
            try self.echoDecoded(a, con_cause, true, sink);
            try self.echoDecoded(a, .unknown_ioa, false, sink);
            return;
        };

        // A deactivation (cause 8) asks for a *pending* command to be
        // cancelled. It must never operate the output — a "cancel" that fires
        // the breaker is the worst direction a control system can fail in — so
        // it short-circuits ahead of the select/execute machine below.
        //
        // §7.2.3: the answer is a deactivation confirmation (cause 9), with
        // the P/N bit set when there was nothing to cancel. Here "pending"
        // means exactly one thing: an outstanding select. A direct-mode point
        // never holds one, so it always negative-confirms.
        if (a.header.cause.cot == .deactivation) {
            const had_pending = p.selected;
            p.selected = false;
            try self.echoDecoded(a, .deactivation_con, !had_pending, sink);
            return;
        }

        const se = o.element.selectExecute() orelse info.SelectExecute.execute;
        if (p.command_mode == .select_and_execute) {
            if (se == .select) {
                p.selected = true;
                try self.echoDecoded(a, .activation_con, false, sink);
                return;
            }
            if (!p.selected) {
                // An execute with no prior select is refused (§7.2.6.26).
                try self.echoDecoded(a, .activation_con, true, sink);
                return;
            }
            p.selected = false;
        } else if (se == .select) {
            // A direct-mode point cannot be selected.
            try self.echoDecoded(a, .activation_con, true, sink);
            return;
        }

        const accepted = if (self.hook) |h| h.acceptFn(h.ctx, p, o.element) else true;
        if (!accepted) {
            try self.echoDecoded(a, .activation_con, true, sink);
            return;
        }
        p.element = o.element;
        p.time = o.time;
        try self.echoDecoded(a, .activation_con, false, sink);
        if (self.opts.command_termination) {
            try self.echoDecoded(a, .activation_termination, false, sink);
        }
    }

    // ── reply builders ──────────────────────────────────────────────────────

    fn emitPoint(self: *Outstation, p: *const Point, cause: asdu_mod.Cot, sink: Sink) Error!void {
        try self.emitPointWithLayout(p, cause, self.opts.interrogation_sq, sink);
    }

    fn emitPointWithLayout(self: *Outstation, p: *const Point, cause: asdu_mod.Cot, sq: bool, sink: Sink) Error!void {
        var b = try asdu_mod.Builder.init(
            &self.scratch,
            self.opts.params,
            p.type_id,
            .{ .cot = cause },
            self.opts.common_address,
            sq,
        );
        try b.add(p.ioa, p.element, p.time);
        try sink.send(try b.finish());
    }

    /// Re-emits a *decoded* ASDU with a different cause of transmission —
    /// the shape of every confirmation, termination and error reply.
    fn echoDecoded(
        self: *Outstation,
        a: asdu_mod.Asdu,
        cause: asdu_mod.Cot,
        negative: bool,
        sink: Sink,
    ) Error!void {
        var b = try asdu_mod.Builder.init(
            &self.scratch,
            self.opts.params,
            a.header.type_id,
            .{
                .cot = cause,
                .negative = negative,
                .is_test = a.header.cause.is_test,
                .originator = a.header.cause.originator,
            },
            a.header.common_address,
            a.header.vsq.sq,
        );
        var it = a.objects();
        while (try it.next()) |o| try b.add(o.ioa, o.element, o.time);
        try sink.send(try b.finish());
    }

    /// Re-emits a *raw* ASDU with a different cause of transmission, without
    /// decoding its objects — needed when the type id has no known element
    /// layout, which is exactly the case cause 44 exists for.
    fn echoRaw(
        self: *Outstation,
        request: []const u8,
        header: asdu_mod.Header,
        cause: asdu_mod.Cot,
        negative: bool,
        sink: Sink,
    ) Error!void {
        const hdr_len = self.opts.params.headerLen();
        if (request.len < hdr_len) return error.ShortAsdu;
        const body = request[hdr_len..];
        if (hdr_len + body.len > self.scratch.len) return error.BufferTooSmall;
        const hdr = try asdu_mod.encodeHeader(.{
            .type_id = header.type_id,
            .vsq = header.vsq,
            .cause = .{
                .cot = cause,
                .negative = negative,
                .is_test = header.cause.is_test,
                .originator = header.cause.originator,
            },
            .common_address = header.common_address,
        }, self.opts.params, &self.scratch);
        @memcpy(self.scratch[hdr.len..][0..body.len], body);
        try sink.send(self.scratch[0 .. hdr.len + body.len]);
    }
};

// ── a complete controlled-station peer ──────────────────────────────────────

/// A controlled station that owns everything below the point database: the
/// APCI framing, the k/w/t0..t3 state machine and the reply queue. Point it at
/// a `Transport` and drive it with `poll`; a fleet simulator stands up one of
/// these per simulated RTU.
///
/// Replies are queued rather than written straight out, because one
/// interrogation can produce far more ASDUs than the send window `k` allows —
/// the queue drains as the master acknowledges.
pub const Server = struct {
    outstation: Outstation,
    conn: state.Connection,
    transport: Transport,
    framer: apci.Framer,
    /// Queue of reply ASDUs waiting for a free send-window slot.
    queue: []u8,
    queue_used: usize = 0,
    queue_read: usize = 0,
    tx: [apci.max_apdu_len]u8 = undefined,
    rx_chunk: [apci.max_apdu_len]u8 = undefined,

    pub const Event = union(enum) {
        none,
        /// The master started data transfer.
        started,
        /// The master stopped data transfer.
        stopped,
        /// An ASDU was received and answered; its header is reported so an
        /// application can log or react.
        request: asdu_mod.Header,
        /// A protocol timeout fired; the caller must close the connection.
        closed: state.CloseReason,
    };

    pub const ServerError = Error || state.Error || TransportError ||
        apci.FramerError || apci.EncodeError;

    /// `frame_buf` holds at least one APDU; `queue_buf` holds the pending
    /// reply ASDUs (a general interrogation of N points needs roughly
    /// N * element size, plus two octets of length prefix per ASDU).
    pub fn init(
        opts: Options,
        points: []Point,
        transport: Transport,
        frame_buf: []u8,
        queue_buf: []u8,
        config: state.Config,
    ) ServerError!Server {
        return .{
            .outstation = try Outstation.init(opts, points),
            .conn = try state.Connection.init(config, .controlled),
            .transport = transport,
            .framer = apci.Framer.init(frame_buf),
            .queue = queue_buf,
        };
    }

    /// The TCP connection is up.
    pub fn onConnected(self: *Server, now: u64) void {
        self.conn.onTcpConnected(now);
    }

    pub fn onDisconnected(self: *Server) void {
        self.conn.onTcpClosed();
        self.framer.len = 0;
        self.framer.pos = 0;
        self.queue_used = 0;
        self.queue_read = 0;
    }

    pub fn isStarted(self: *const Server) bool {
        return self.conn.isStarted();
    }

    pub fn nextDeadline(self: *const Server) ?u64 {
        return self.conn.nextDeadline();
    }

    /// Queues a spontaneous report of one point.
    pub fn reportSpontaneous(self: *Server, ioa: u32, now: u64) ServerError!void {
        _ = now;
        var q = QueueSink{ .server = self };
        try self.outstation.reportSpontaneous(ioa, q.sink());
    }

    /// One step: timer-driven output, then queued replies, then at most one
    /// received frame.
    pub fn poll(self: *Server, now: u64) ServerError!Event {
        while (true) {
            switch (self.conn.tick(now)) {
                .none => break,
                .close => |r| return .{ .closed = r },
                .send_s_frame => |nr| try self.transport.write(&apci.encodeS(nr)),
                .send_u => |f| try self.transport.write(&apci.encodeU(f)),
            }
        }
        try self.drain(now);

        if (try self.framer.next()) |apdu| return try self.dispatch(apdu, now);
        const n = try self.transport.read(&self.rx_chunk);
        if (n == 0) return .none;
        try self.framer.feed(self.rx_chunk[0..n]);
        if (try self.framer.next()) |apdu| return try self.dispatch(apdu, now);
        return .none;
    }

    /// Sends as many queued reply ASDUs as the send window allows.
    fn drain(self: *Server, now: u64) ServerError!void {
        while (self.queue_read < self.queue_used) {
            if (!self.conn.isStarted() or self.conn.sendWindowFull()) return;
            const len = @as(usize, self.queue[self.queue_read]) |
                (@as(usize, self.queue[self.queue_read + 1]) << 8);
            const body = self.queue[self.queue_read + 2 ..][0..len];
            const control = try self.conn.prepareI(now);
            const frame = try apci.encode(control, body, &self.tx);
            try self.transport.write(frame);
            self.queue_read += 2 + len;
        }
        self.queue_read = 0;
        self.queue_used = 0;
    }

    fn dispatch(self: *Server, apdu: apci.Apdu, now: u64) ServerError!Event {
        const event = try self.conn.onFrame(apdu, now);
        switch (event) {
            .none, .test_requested, .test_confirmed => return .none,
            .started => return .started,
            .stopped => return .stopped,
            .asdu => |body| {
                const header = try asdu_mod.decodeHeader(body, self.outstation.opts.params);
                var q = QueueSink{ .server = self };
                try self.outstation.handle(body, q.sink());
                try self.drain(now);
                return .{ .request = header };
            },
        }
    }

    const QueueSink = struct {
        server: *Server,

        fn sink(self: *QueueSink) Sink {
            return .{ .ctx = self, .sendFn = sendFn };
        }

        fn sendFn(ctx: *anyopaque, bytes: []const u8) SinkError!void {
            const self: *QueueSink = @ptrCast(@alignCast(ctx));
            const s = self.server;
            if (s.queue_used + 2 + bytes.len > s.queue.len) return error.SinkFull;
            s.queue[s.queue_used] = @truncate(bytes.len);
            s.queue[s.queue_used + 1] = @truncate(bytes.len >> 8);
            @memcpy(s.queue[s.queue_used + 2 ..][0..bytes.len], bytes);
            s.queue_used += 2 + bytes.len;
        }
    };
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Collects reply ASDUs so a test can inspect them.
pub const CollectSink = struct {
    buf: [8192]u8 = undefined,
    used: usize = 0,
    starts: [64]usize = undefined,
    ends: [64]usize = undefined,
    count: usize = 0,

    pub fn sink(self: *CollectSink) Sink {
        return .{ .ctx = self, .sendFn = sendFn };
    }

    pub fn get(self: *const CollectSink, i: usize) []const u8 {
        return self.buf[self.starts[i]..self.ends[i]];
    }

    pub fn reset(self: *CollectSink) void {
        self.used = 0;
        self.count = 0;
    }

    fn sendFn(ctx: *anyopaque, bytes: []const u8) SinkError!void {
        const self: *CollectSink = @ptrCast(@alignCast(ctx));
        if (self.count == self.starts.len or self.used + bytes.len > self.buf.len) return error.SinkFull;
        @memcpy(self.buf[self.used..][0..bytes.len], bytes);
        self.starts[self.count] = self.used;
        self.ends[self.count] = self.used + bytes.len;
        self.used += bytes.len;
        self.count += 1;
    }
};

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn demoPoints() [4]Point {
    return .{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 105, .type_id = .m_me_na_1, .element = .{ .normalized = .{ .value = .{ .raw = 16384 }, .quality = .{} } } },
        .{ .ioa = 108, .type_id = .m_it_na_1, .element = .{ .counter = .{ .counter = 0 } } },
        .{ .ioa = 301, .type_id = .c_sc_na_1, .element = .{ .sco = .{} }, .command_mode = .select_and_execute },
    };
}

test "outstation: general interrogation answers con, data, termination" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    // The master's own C_IC_NA_1 activation, taken from the capture.
    try o.handle(&hex("640106002f0000000014"), s.sink());
    try testing.expectEqual(@as(usize, 4), s.count);
    // 1. activation confirmation — byte-identical to the recorded RTU reply.
    try testing.expectEqualSlices(u8, &hex("640107002f0000000014"), s.get(0));
    // 2/3. the two non-counter monitoring points.
    try testing.expectEqualSlices(u8, &hex("018114002f0065000001"), s.get(1));
    try testing.expectEqualSlices(u8, &hex("098114002f00690000004000"), s.get(2));
    // 4. activation termination.
    try testing.expectEqualSlices(u8, &hex("64010a002f0000000014"), s.get(3));
}

test "outstation: counter interrogation answers with the counters only" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    try o.handle(&hex("650106002f0000000005"), s.sink());
    try testing.expectEqual(@as(usize, 3), s.count);
    try testing.expectEqualSlices(u8, &hex("650107002f0000000005"), s.get(0));
    try testing.expectEqualSlices(u8, &hex("0f8125002f006c00000000000000"), s.get(1));
    try testing.expectEqualSlices(u8, &hex("65010a002f0000000005"), s.get(2));
}

test "outstation: group interrogation answers only that group" {
    var points = [_]Point{
        .{ .ioa = 1, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } }, .group = 1 },
        .{ .ioa = 2, .type_id = .m_sp_na_1, .element = .{ .siq = .{} }, .group = 2 },
    };
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    // QOI 21 = inventory group 1.
    try o.handle(&hex("640106002f0000000015"), s.sink());
    try testing.expectEqual(@as(usize, 3), s.count); // con + one point + term
    const a = try asdu_mod.decode(s.get(1), asdu_mod.default_params);
    try testing.expectEqual(asdu_mod.Cot.interrogated_by_group_1, a.header.cause.cot);
    var it = a.objects();
    try testing.expectEqual(@as(u32, 1), (try it.next()).?.ioa);
}

test "outstation: select-before-operate needs the select first" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};

    // An execute with no prior select is refused.
    try o.handle(&hex("2d0106002f002d010001"), s.sink());
    try testing.expectEqual(@as(usize, 1), s.count);
    var a = try asdu_mod.decode(s.get(0), asdu_mod.default_params);
    try testing.expectEqual(asdu_mod.Cot.activation_con, a.header.cause.cot);
    try testing.expect(a.header.cause.negative);

    // Select: positively confirmed, echoing the S/E bit.
    s.reset();
    try o.handle(&hex("2d0106002f002d010081"), s.sink());
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0107002f002d010081"), s.get(0));
    try testing.expect(o.find(301, .c_sc_na_1).?.selected);

    // Execute: confirmed and terminated, and the selection is consumed.
    s.reset();
    try o.handle(&hex("2d0106002f002d010001"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0107002f002d010001"), s.get(0));
    try testing.expectEqualSlices(u8, &hex("2d010a002f002d010001"), s.get(1));
    try testing.expect(!o.find(301, .c_sc_na_1).?.selected);
    try testing.expect(o.find(301, .c_sc_na_1).?.element.sco.on);

    // A second execute now needs a fresh select.
    s.reset();
    try o.handle(&hex("2d0106002f002d010001"), s.sink());
    a = try asdu_mod.decode(s.get(0), asdu_mod.default_params);
    try testing.expect(a.header.cause.negative);
}

test "outstation: a deactivation with nothing pending is negatively confirmed" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};

    // C_SC_NA_1, cause 8 (deactivation), S/E = execute, SCO on. There is no
    // select outstanding, so there is nothing to cancel.
    // Effect first, status second: the value must be the assertion that trips.
    try o.handle(&hex("2d0108002f002d010001"), s.sink());
    try testing.expect(!points[3].element.sco.on);
    try testing.expect(!points[3].selected);
    // Cause 9 with the P/N bit.
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0149002f002d010001"), s.get(0));

    // The same with the S/E bit set. A deactivation must not *arm* the point
    // either — cause 8 is never a select.
    s.reset();
    try o.handle(&hex("2d0108002f002d010081"), s.sink());
    try testing.expect(!points[3].selected);
    try testing.expect(!points[3].element.sco.on);
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0149002f002d010081"), s.get(0));

    // A direct-mode point never holds a selection, so it answers the same way
    // and, again, does not operate.
    var direct = [_]Point{
        .{ .ioa = 302, .type_id = .c_dc_na_1, .element = .{ .dco = .{} }, .command_mode = .direct },
    };
    var od = try Outstation.init(.{ .common_address = 47 }, &direct);
    s.reset();
    try od.handle(&hex("2e0108002f002e010002"), s.sink());
    try testing.expectEqual(info.DoublePoint.off, direct[0].element.dco.state);
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("2e0149002f002e010002"), s.get(0));
}

test "outstation: a deactivation cancels the select instead of executing it" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};

    // Select the point.
    try o.handle(&hex("2d0106002f002d010081"), s.sink());
    try testing.expectEqualSlices(u8, &hex("2d0107002f002d010081"), s.get(0));
    try testing.expect(points[3].selected);

    // Cancel it, with the S/E bit clear — the form that used to fall straight
    // through into the execute branch and operate the output. The value is
    // asserted before the reply bytes on purpose: the regression this test
    // exists for must show up as a *value* failure, not merely a wrong COT.
    s.reset();
    try o.handle(&hex("2d0108002f002d010001"), s.sink());
    try testing.expect(!points[3].element.sco.on);
    try testing.expect(!points[3].selected);
    // Cause 9, no P/N — there really was something to cancel — and no
    // activation termination, because nothing was activated.
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0109002f002d010001"), s.get(0));

    // The execute that follows the cancelled select is now refused, and — the
    // assertion the whole bug turns on — the point value is still untouched.
    s.reset();
    try o.handle(&hex("2d0106002f002d010001"), s.sink());
    try testing.expect(!points[3].element.sco.on);
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0147002f002d010001"), s.get(0));

    // The same cancel sent with the S/E bit still set (a master mirroring its
    // own select) must also clear the selection rather than re-arm the point.
    s.reset();
    try o.handle(&hex("2d0106002f002d010081"), s.sink());
    try testing.expect(points[3].selected);
    s.reset();
    try o.handle(&hex("2d0108002f002d010081"), s.sink());
    try testing.expect(!points[3].selected);
    try testing.expect(!points[3].element.sco.on);
    try testing.expectEqualSlices(u8, &hex("2d0109002f002d010081"), s.get(0));
    s.reset();
    try o.handle(&hex("2d0106002f002d010001"), s.sink());
    try testing.expect(!points[3].element.sco.on);
    try testing.expectEqualSlices(u8, &hex("2d0147002f002d010001"), s.get(0));

    // A fresh select/execute pair still works, so cancelling did not wedge the
    // point: the activation path survives end to end.
    s.reset();
    try o.handle(&hex("2d0106002f002d010081"), s.sink());
    try o.handle(&hex("2d0106002f002d010001"), s.sink());
    try testing.expectEqual(@as(usize, 3), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0107002f002d010081"), s.get(0));
    try testing.expectEqualSlices(u8, &hex("2d0107002f002d010001"), s.get(1));
    try testing.expectEqualSlices(u8, &hex("2d010a002f002d010001"), s.get(2));
    try testing.expect(points[3].element.sco.on);
    try testing.expect(!points[3].selected);
}

test "outstation: an interrogation deactivation is confirmed with cause 9, not 7" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};

    // The same C_IC_NA_1 station interrogation as the general-interrogation
    // test, but with cause 8 (deactivation) instead of 6. onInterrogation
    // already refuses to perform the scan for this cause — this only checks
    // that the confirmation names the cause it actually is.
    try o.handle(&hex("640108002f0000000014"), s.sink());
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("640109002f0000000014"), s.get(0));
}

test "outstation: a command deactivation naming an unknown IOA gets cause 9" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};

    // C_SC_NA_1, cause 8 (deactivation), IOA 999 — the same unknown address
    // as the "three error causes" test, but as a deactivation. The negative
    // confirmation must still name cause 9 (deactivation_con), not 7
    // (activation_con); the trailing cause-47 (unknown_ioa) ASDU is
    // unaffected by which activation-class cause triggered it.
    try o.handle(&hex("2d0108002f00e7030001"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0149002f00e7030001"), s.get(0));
    try testing.expectEqualSlices(u8, &hex("2d012f002f00e7030001"), s.get(1));
}

test "outstation: a direct-mode point refuses a select" {
    var points = [_]Point{
        .{ .ioa = 302, .type_id = .c_dc_na_1, .element = .{ .dco = .{} }, .command_mode = .direct },
    };
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    try o.handle(&hex("2e0106002f002e010082"), s.sink()); // DCO with S/E set
    const a = try asdu_mod.decode(s.get(0), asdu_mod.default_params);
    try testing.expect(a.header.cause.negative);

    s.reset();
    try o.handle(&hex("2e0106002f002e010002"), s.sink()); // direct execute
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expectEqual(info.DoublePoint.on, o.find(302, .c_dc_na_1).?.element.dco.state);
}

test "outstation: the command hook can veto a command" {
    const Veto = struct {
        fn accept(_: *anyopaque, _: *Point, _: asdu_mod.Element) bool {
            return false;
        }
    };
    var points = [_]Point{
        .{ .ioa = 302, .type_id = .c_dc_na_1, .element = .{ .dco = .{} } },
    };
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var dummy: u8 = 0;
    o.hook = .{ .ctx = &dummy, .acceptFn = Veto.accept };
    var s = CollectSink{};
    try o.handle(&hex("2e0106002f002e010002"), s.sink());
    try testing.expectEqual(@as(usize, 1), s.count);
    const a = try asdu_mod.decode(s.get(0), asdu_mod.default_params);
    try testing.expect(a.header.cause.negative);
    // The point was not modified.
    try testing.expectEqual(info.DoublePoint.off, points[0].element.dco.state); // the default, untouched
}

test "outstation: the three error causes match the recorded RTU byte for byte" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};

    // Unknown common address 99: negative act-con, then cause 46.
    try o.handle(&hex("64010600630000000014"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expectEqualSlices(u8, &hex("64014700630000000014"), s.get(0));
    try testing.expectEqualSlices(u8, &hex("64012e00630000000014"), s.get(1));

    // Unknown information-object address 999: negative act-con, then 47.
    s.reset();
    try o.handle(&hex("2d0106002f00e7030001"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expectEqualSlices(u8, &hex("2d0147002f00e7030001"), s.get(0));
    try testing.expectEqualSlices(u8, &hex("2d012f002f00e7030001"), s.get(1));

    // Unknown cause of transmission: cause 45 with P/N set.
    s.reset();
    try o.handle(&hex("640163002f0000000014"), s.sink());
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("64016d002f0000000014"), s.get(0));
}

test "outstation: an unmodelled type id is answered with cause 44" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    // The type-200 probe from the capture. Cause 6 becomes cause 44 (0x2C)
    // with the P/N bit set: 0x6C.
    try o.handle(&hex("c80106002f0000000000"), s.sink());
    try testing.expectEqual(@as(usize, 1), s.count);
    try testing.expectEqualSlices(u8, &hex("c8016c002f0000000000"), s.get(0));
    // A monitor-direction type sent in the control direction gets the same.
    s.reset();
    try o.handle(&hex("010106002f0065000001"), s.sink());
    try testing.expectEqualSlices(u8, &hex("01016c002f0065000001"), s.get(0));
}

test "outstation: read command answers with the point value, cause 5" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    try o.handle(&hex("660105002f00650000"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expectEqualSlices(u8, &hex("660107002f00650000"), s.get(0));
    // Exactly the reply the recorded RTU produced (SQ = 0 for a read).
    try testing.expectEqualSlices(u8, &hex("010105002f0065000001"), s.get(1));

    // An unknown address gets the negative con plus cause 47.
    s.reset();
    try o.handle(&hex("660105002f00e70300"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    const a = try asdu_mod.decode(s.get(1), asdu_mod.default_params);
    try testing.expectEqual(asdu_mod.Cot.unknown_ioa, a.header.cause.cot);
}

test "outstation: clock sync, test and reset commands are confirmed" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    // C_CS_NA_1 from the capture -> the recorded confirmation.
    try o.handle(&hex("670106002f00000000cb9c120317071a"), s.sink());
    try testing.expectEqualSlices(u8, &hex("670107002f00000000cb9c120317071a"), s.get(0));
    // C_TS_TA_1 from the capture -> the recorded confirmation.
    s.reset();
    try o.handle(&hex("6b0106002f00000000000091a6120317071a"), s.sink());
    try testing.expectEqualSlices(u8, &hex("6b0107002f00000000000091a6120317071a"), s.get(0));
    // C_RP_NA_1.
    s.reset();
    try o.handle(&hex("690106002f0000000001"), s.sink());
    const a = try asdu_mod.decode(s.get(0), asdu_mod.default_params);
    try testing.expectEqual(asdu_mod.Cot.activation_con, a.header.cause.cot);
}

test "outstation: the broadcast common address is accepted" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    // CA 0xFFFF.
    // type 100, VSQ 1, COT 6, OA 0, CA 0xFFFF, IOA 0, QOI 20.
    try o.handle(&hex("64010600ffff00000014"), s.sink());
    try testing.expect(s.count > 1);
    const a = try asdu_mod.decode(s.get(0), asdu_mod.default_params);
    try testing.expectEqual(asdu_mod.Cot.activation_con, a.header.cause.cot);
    try testing.expect(!a.header.cause.negative);
}

test "outstation: a broadcast control command never operates the point (§7.2.4)" {
    // A direct-mode single command so one execute would, unguarded, fire the
    // output immediately.
    var points = [_]Point{
        .{ .ioa = 301, .type_id = .c_sc_na_1, .element = .{ .sco = .{} }, .command_mode = .direct },
    };
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};

    // C_SC_NA_1 (0x2d), activation, CA 0xffff (global), IOA 301, SCO on/execute.
    // Effect first, status second: the actuation is the assertion that must trip.
    try o.handle(&hex("2d010600ffff2d010001"), s.sink());
    try testing.expect(!points[0].element.sco.on); // point must NOT have operated
    try testing.expectEqual(@as(usize, 0), s.count); // dropped: no reply storm

    // The same command to this station's own CA still operates it — proof the
    // guard rejects only the broadcast case, not the type outright.
    s.reset();
    try o.handle(&hex("2d0106002f002d010001"), s.sink());
    try testing.expect(points[0].element.sco.on);
}

test "outstation: the originator address and test bit are echoed back" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    // Originator 7, test bit set (COT 0x86).
    try o.handle(&hex("640186072f0000000014"), s.sink());
    const a = try asdu_mod.decode(s.get(0), asdu_mod.default_params);
    try testing.expectEqual(@as(u8, 7), a.header.cause.originator);
    try testing.expect(a.header.cause.is_test);
    try testing.expectEqual(asdu_mod.Cot.activation_con, a.header.cause.cot);
}

test "outstation: spontaneous reporting of a point" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    points[0].element = .{ .siq = .{ .on = false, .quality = .{ .nt = true } } };
    try o.reportSpontaneous(101, s.sink());
    try testing.expectEqual(@as(usize, 1), s.count);
    const a = try asdu_mod.decode(s.get(0), asdu_mod.default_params);
    try testing.expectEqual(asdu_mod.Cot.spontaneous, a.header.cause.cot);
    var it = a.objects();
    const p = (try it.next()).?;
    try testing.expect(!p.element.siq.on);
    try testing.expect(p.element.siq.quality.nt);
}

test "outstation: hostile ASDUs produce typed errors, never a crash" {
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    try testing.expectError(error.ShortAsdu, o.handle(&hex("6401"), s.sink()));
    // Object count says two, body holds one.
    try testing.expectError(error.ObjectCountMismatch, o.handle(&hex("640206002f0000000014"), s.sink()));
    // Zero objects.
    try testing.expectError(error.ZeroObjectCount, o.handle(&hex("640006002f00"), s.sink()));
    // An impossible CP56Time2a (month 0) inside a clock-sync command.
    try testing.expectError(error.ImpossibleTime, o.handle(&hex("670106002f00000000cb9c120317001a"), s.sink()));
}

test "fuzz: the outstation never panics on arbitrary ASDU bytes" {
    try std.testing.fuzz({}, fuzzHandle, .{});
}

fn fuzzHandle(_: void, smith: *std.testing.Smith) !void {
    var buf: [apci.max_asdu_len]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var points = demoPoints();
    var o = try Outstation.init(.{ .common_address = 47 }, &points);
    var s = CollectSink{};
    o.handle(buf[0..len], s.sink()) catch return;
}

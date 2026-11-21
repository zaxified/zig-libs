// SPDX-License-Identifier: MIT

//! iec104 — pure-Zig **IEC 60870-5-104** telecontrol: the TCP/IP profile of
//! IEC 60870-5-101 that European power grids run their SCADA on, between
//! control centres (controlling stations) and RTUs (controlled stations).
//!
//! Five layers, each usable on its own:
//!
//! * **`apci`** (§5.1–§5.3) — the fixed six-octet header: start octet `0x68`,
//!   the length octet (counting everything after itself, capped at 253) and
//!   the four control octets that select I-format (information transfer, with
//!   the 15-bit N(S)/N(R) sequence numbers), S-format (supervisory,
//!   acknowledge-only) or U-format (`STARTDT`/`STOPDT`/`TESTFR`, act or con),
//!   plus a stream `Framer` because TCP gives no message boundaries.
//! * **`state`** (§5.4–§5.6, §9.6) — the flow control that is the heart of the
//!   protocol: `k` outstanding I-frames, acknowledge at latest after `w`, and
//!   the four timers t0/t1/t2/t3. **Pure and time-injected**: the caller
//!   supplies `now_ms` and performs the I/O the machine asks for, so k/w
//!   exhaustion, the 15-bit sequence wrap and every timer are testable with a
//!   fake clock and no socket. Sequence numbers wrap at 32768 — an
//!   implementation that gets that wrong stalls after 32767 frames.
//! * **`info`** (IEC 60870-5-101 §7.2.6) — the information elements: the
//!   quality descriptor (IV/NT/SB/BL/OV), the point values (SIQ/DIQ/VTI/BSI/
//!   NVA/SVA/R32/BCR), the command qualifiers with their **S/E bit** (which is
//!   what carries select-before-operate) and the CP56Time2a/CP24Time2a/
//!   CP16Time2a tags, milliseconds and seconds sharing one 16-bit field.
//! * **`asdu`** (§7.2) — the data unit identifier (type id, the variable
//!   structure qualifier with its **SQ bit** and count, the cause of
//!   transmission with P/N and T plus the originator address, the common
//!   address) and the information objects in **both** layouts the SQ bit
//!   selects. The three address widths are explicit `Params`, not constants.
//! * **`client` / `outstation`** — a controlling station (connect, `STARTDT`,
//!   interrogation, monitoring data, commands with select-before-operate,
//!   clock sync, teardown) and a controlled station (a point database that
//!   answers all of it), both over the same `Transport` seam.
//!
//! Verified against **real traffic between two independent third-party
//! implementations** and by a **live round trip** against one of them; see
//! `goldens.zig` and SPEC.md for exactly which frames came from where.
//!
//! Provenance: clean-room from IEC 60870-5-104 / IEC 60870-5-101. No
//! third-party source was consulted; a third-party stack was used as a black
//! box — to generate wire traffic and to decode ours — which is a test oracle,
//! not a design reference. See SPEC.md.

const std = @import("std");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "IEC 60870-5-104 telecontrol — APCI/APDU framing, I/S/U formats with k/w flow control, ASDU codec, transport-agnostic master (controlling station)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // The codecs and the state machine are pure computation; only the
    // optional TcpTransport touches std.Io.net.
    .targets = .{.linux64},
    .platform = .any,
    .role = .both, // controlling station (client) + controlled station (outstation)
    // One Client/Server owns one connection's framer, sequence counters and
    // buffers; nothing shared or global. Concurrency and the clock belong to
    // the caller.
    .concurrency = .single_owner,
    .model_after = "IEC 60870-5-104 + IEC 60870-5-101; wire behaviour cross-checked against captured traffic between two independent third-party stacks (see SPEC.md)",
    .deps = .{},
};

// ── layers ──────────────────────────────────────────────────────────────────

/// APCI framing (§5.1–§5.3): I/S/U formats, sequence numbers, stream framer.
pub const apci = @import("apci.zig");
/// Information elements (IEC 60870-5-101 §7.2.6): quality, values, qualifiers,
/// time tags.
pub const info = @import("info.zig");
/// ASDU codec (§7.2): data unit identifier plus information objects.
pub const asdu = @import("asdu.zig");
/// File transfer (type ids 120-127): the sender and receiver state machines.
pub const file = @import("file.zig");
/// The k/w + t0..t3 flow-control state machine (§5.4–§5.6, §9.6).
pub const state = @import("state.zig");
/// The byte-stream seam and its adapters.
pub const transport = @import("transport.zig");
/// A controlling station (master).
pub const client = @import("client.zig");
/// A controlled station (outstation/RTU), and a complete peer built on it.
pub const outstation = @import("outstation.zig");
/// Redundancy groups of a controlled station: which connection is active.
pub const redundancy = @import("redundancy.zig");
/// The IEC 60870-5-101 serial link layer frame format FT1.2.
pub const ft12 = @import("ft12.zig");
/// Byte-exact goldens captured from third-party traffic.
pub const goldens = @import("goldens.zig");

// ── top-level names (the ones a consumer actually types) ────────────────────

/// A controlling station over any byte stream.
pub const Client = client.Client;
/// A controlled station's point database and responder.
pub const Outstation = outstation.Outstation;
/// A complete controlled-station peer: point database + framing + flow control.
pub const OutstationServer = outstation.Server;
pub const Point = outstation.Point;
pub const CommandMode = outstation.CommandMode;

/// The byte-stream seam: one `read`, one `write`.
pub const Transport = transport.Transport;
pub const TransportError = transport.TransportError;
/// Optional adapter onto a real socket.
pub const TcpTransport = transport.TcpTransport;
/// In-memory pipe, for offline round trips.
pub const LoopTransport = transport.LoopTransport;
/// The registered IEC 60870-5-104 TCP port.
pub const default_port = transport.default_port;

/// Per-system address widths (IOA 1..3 octets, CA 1..2, originator on/off).
pub const Params = asdu.Params;
/// The 3/2/with-originator profile IEC 60870-5-104 fixes.
pub const default_params = asdu.default_params;
/// Flow-control parameters k, w, t0..t3.
pub const Config = state.Config;

pub const TypeId = asdu.TypeId;
pub const Cot = asdu.Cot;
pub const Cause = asdu.Cause;
pub const Element = asdu.Element;
pub const TimeTag = asdu.TimeTag;
pub const Quality = info.Quality;
pub const CP56Time2a = info.CP56Time2a;
pub const SelectExecute = info.SelectExecute;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s tests
// into the test binary on its own — every submodule must be named here too.
test {
    _ = apci;
    _ = info;
    _ = asdu;
    _ = file;
    _ = state;
    _ = transport;
    _ = client;
    _ = outstation;
    _ = goldens;
    _ = redundancy;
    _ = ft12;
    _ = @import("mutation_test.zig");
}

// ── tests: the whole stack, master against outstation ──────────────────────

const testing = std.testing;

test "meta names no sibling dependencies" {
    try testing.expectEqual(@as(usize, 0), meta.deps.len);
}

/// A bidirectional in-memory wire: what the master writes the RTU reads, and
/// the other way round. This is the whole network for the round-trip tests.
const Wire = struct {
    m2r: Chan = .{},
    r2m: Chan = .{},

    const Chan = struct {
        buf: [64 * 1024]u8 = undefined,
        len: usize = 0,
        pos: usize = 0,

        fn write(self: *Chan, bytes: []const u8) TransportError!void {
            if (self.len + bytes.len > self.buf.len) return error.WriteFailed;
            @memcpy(self.buf[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        fn read(self: *Chan, out: []u8) TransportError!usize {
            const avail = self.len - self.pos;
            if (avail == 0) return 0;
            const n = @min(avail, out.len);
            @memcpy(out[0..n], self.buf[self.pos..][0..n]);
            self.pos += n;
            return n;
        }
    };
};

const MasterEnd = struct {
    wire: *Wire,
    fn transportSeam(self: *MasterEnd) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = rd, .write = wr } };
    }
    fn rd(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const s: *MasterEnd = @ptrCast(@alignCast(ctx));
        return s.wire.r2m.read(buf);
    }
    fn wr(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const s: *MasterEnd = @ptrCast(@alignCast(ctx));
        return s.wire.m2r.write(bytes);
    }
};

const RtuEnd = struct {
    wire: *Wire,
    fn transportSeam(self: *RtuEnd) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = rd, .write = wr } };
    }
    fn rd(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const s: *RtuEnd = @ptrCast(@alignCast(ctx));
        return s.wire.m2r.read(buf);
    }
    fn wr(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const s: *RtuEnd = @ptrCast(@alignCast(ctx));
        return s.wire.r2m.write(bytes);
    }
};

const Rig = struct {
    master: *Client,
    rtu: *OutstationServer,
    now: u64 = 0,
    /// Type ids of every ASDU the master received during the last `settle`.
    seen: std.ArrayList(TypeId) = .empty,
    /// True if any of them carried the P/N bit.
    saw_negative: bool = false,

    fn deinit(self: *Rig, gpa: std.mem.Allocator) void {
        self.seen.deinit(gpa);
    }

    /// Runs both peers until neither makes progress for four rounds.
    fn settle(self: *Rig, gpa: std.mem.Allocator) !void {
        self.seen.clearRetainingCapacity();
        self.saw_negative = false;
        var idle: usize = 0;
        while (idle < 4) {
            self.now += 1;
            var progress = false;
            switch (try self.rtu.poll(self.now)) {
                .none => {},
                .closed => return error.RtuClosed,
                else => progress = true,
            }
            switch (try self.master.poll(self.now)) {
                .none => {},
                .closed => return error.MasterClosed,
                .asdu => |a| {
                    progress = true;
                    try self.seen.append(gpa, a.header.type_id);
                    if (a.header.cause.negative) self.saw_negative = true;
                },
                else => progress = true,
            }
            idle = if (progress) 0 else idle + 1;
        }
    }
};

test "round trip: master interrogates our own outstation over a wire" {
    const gpa = testing.allocator;
    var wire = Wire{};
    var m_end = MasterEnd{ .wire = &wire };
    var r_end = RtuEnd{ .wire = &wire };

    var points = [_]Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 102, .type_id = .m_dp_na_1, .element = .{ .diq = .{ .state = .on } } },
        .{ .ioa = 105, .type_id = .m_me_nc_1, .element = .{ .short_float = .{ .value = 3.5, .quality = .{} } } },
        .{ .ioa = 108, .type_id = .m_it_na_1, .element = .{ .counter = .{ .counter = 4242 } } },
        .{ .ioa = 301, .type_id = .c_sc_na_1, .element = .{ .sco = .{} }, .command_mode = .select_and_execute },
    };

    var m_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_queue: [8192]u8 = undefined;
    var master = try Client.init(m_end.transportSeam(), &m_frames, .{});
    var rtu = try OutstationServer.init(
        .{ .common_address = 47 },
        &points,
        r_end.transportSeam(),
        &r_frames,
        &r_queue,
        .{},
    );
    var rig = Rig{ .master = &master, .rtu = &rtu };
    defer rig.deinit(gpa);

    master.beginConnect(0);
    master.onConnected(0);
    rtu.onConnected(0);
    try master.startDataTransfer(0);
    try rig.settle(gpa);
    try testing.expect(master.isStarted());
    try testing.expect(rtu.isStarted());

    // General interrogation: confirmation, the three non-counter monitoring
    // points, termination.
    try master.interrogate(47, .station, rig.now);
    try rig.settle(gpa);
    try testing.expectEqualSlices(TypeId, &.{
        .c_ic_na_1, .m_sp_na_1, .m_dp_na_1, .m_me_nc_1, .c_ic_na_1,
    }, rig.seen.items);

    // Counter interrogation brings the counter, and only the counter.
    try master.interrogateCounters(47, .{ .request = .general, .freeze = .read }, rig.now);
    try rig.settle(gpa);
    try testing.expectEqualSlices(TypeId, &.{ .c_ci_na_1, .m_it_na_1, .c_ci_na_1 }, rig.seen.items);

    // Clock synchronisation is confirmed.
    try master.syncClock(47, .{ .millisecond = 1, .second = 2, .minute = 3, .hour = 4, .day = 5, .month = 6, .year = 26 }, rig.now);
    try rig.settle(gpa);
    try testing.expectEqualSlices(TypeId, &.{.c_cs_na_1}, rig.seen.items);

    // Read command returns the point value.
    try master.readPoint(47, 105, rig.now);
    try rig.settle(gpa);
    try testing.expectEqualSlices(TypeId, &.{ .c_rd_na_1, .m_me_nc_1 }, rig.seen.items);

    // An interrogation for the wrong station is refused, twice over.
    try master.interrogate(99, .station, rig.now);
    try rig.settle(gpa);
    try testing.expectEqual(@as(usize, 2), rig.seen.items.len);
    try testing.expect(rig.saw_negative);

    // Teardown.
    try master.stopDataTransfer(rig.now);
    try rig.settle(gpa);
    try testing.expect(!master.isStarted());
    try testing.expect(!rtu.isStarted());
}

test "round trip: select-before-operate across the whole stack" {
    const gpa = testing.allocator;
    var wire = Wire{};
    var m_end = MasterEnd{ .wire = &wire };
    var r_end = RtuEnd{ .wire = &wire };
    var points = [_]Point{
        .{ .ioa = 301, .type_id = .c_sc_na_1, .element = .{ .sco = .{} }, .command_mode = .select_and_execute },
        .{ .ioa = 302, .type_id = .c_dc_na_1, .element = .{ .dco = .{} } },
    };
    var m_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_queue: [4096]u8 = undefined;
    var master = try Client.init(m_end.transportSeam(), &m_frames, .{});
    var rtu = try OutstationServer.init(.{ .common_address = 47 }, &points, r_end.transportSeam(), &r_frames, &r_queue, .{});
    var rig = Rig{ .master = &master, .rtu = &rtu };
    defer rig.deinit(gpa);

    master.beginConnect(0);
    master.onConnected(0);
    rtu.onConnected(0);
    try master.startDataTransfer(0);
    try rig.settle(gpa);

    // An execute with no prior select is refused and changes nothing.
    try master.command(.c_sc_na_1, 47, 301, .{ .sco = .{ .on = true, .select = .execute } }, .none, rig.now);
    try rig.settle(gpa);
    try testing.expect(rig.saw_negative);
    try testing.expect(!points[0].element.sco.on);

    // Select, then execute.
    try master.command(.c_sc_na_1, 47, 301, .{ .sco = .{ .on = true, .select = .select } }, .none, rig.now);
    try rig.settle(gpa);
    try testing.expect(!rig.saw_negative);
    try testing.expect(points[0].selected);
    try master.command(.c_sc_na_1, 47, 301, .{ .sco = .{ .on = true, .select = .execute } }, .none, rig.now);
    try rig.settle(gpa);
    try testing.expect(!points[0].selected);
    try testing.expect(points[0].element.sco.on);

    // The direct-mode point fires on one activation.
    try master.command(.c_dc_na_1, 47, 302, .{ .dco = .{ .state = .on } }, .none, rig.now);
    try rig.settle(gpa);
    try testing.expectEqual(info.DoublePoint.on, points[1].element.dco.state);
}

test "round trip: a big interrogation drains through the k window" {
    const gpa = testing.allocator;
    var wire = Wire{};
    var m_end = MasterEnd{ .wire = &wire };
    var r_end = RtuEnd{ .wire = &wire };

    // 60 points against k = 3 forces the outstation to queue and drain.
    var points: [60]Point = undefined;
    for (&points, 0..) |*p, i| p.* = .{
        .ioa = @intCast(1000 + i),
        .type_id = .m_sp_na_1,
        .element = .{ .siq = .{ .on = i % 2 == 1 } },
    };

    var m_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_queue: [8192]u8 = undefined;
    const cfg = Config{ .k = 3, .w = 2, .t0_ms = 100_000, .t1_ms = 50_000, .t2_ms = 1_000, .t3_ms = 100_000 };
    var master = try Client.init(m_end.transportSeam(), &m_frames, .{ .config = cfg });
    var rtu = try OutstationServer.init(.{ .common_address = 47 }, &points, r_end.transportSeam(), &r_frames, &r_queue, cfg);
    var rig = Rig{ .master = &master, .rtu = &rtu };
    defer rig.deinit(gpa);

    master.beginConnect(0);
    master.onConnected(0);
    rtu.onConnected(0);
    try master.startDataTransfer(0);
    try rig.settle(gpa);

    try master.interrogate(47, .station, rig.now);
    try rig.settle(gpa);
    // Confirmation + 60 points + termination.
    try testing.expectEqual(@as(usize, 62), rig.seen.items.len);
    try testing.expectEqual(TypeId.c_ic_na_1, rig.seen.items[0]);
    try testing.expectEqual(TypeId.c_ic_na_1, rig.seen.items[61]);
    for (rig.seen.items[1..61]) |t| try testing.expectEqual(TypeId.m_sp_na_1, t);
    // The window really was exercised rather than bypassed.
    try testing.expect(master.conn.recv_seq > cfg.k);
}

test "round trip: a spontaneous report reaches the master with its time tag" {
    const gpa = testing.allocator;
    var wire = Wire{};
    var m_end = MasterEnd{ .wire = &wire };
    var r_end = RtuEnd{ .wire = &wire };
    var points = [_]Point{
        .{ .ioa = 201, .type_id = .m_sp_tb_1, .element = .{ .siq = .{} }, .time = .{ .cp56 = .{ .day = 1, .month = 1 } } },
    };
    var m_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_queue: [4096]u8 = undefined;
    var master = try Client.init(m_end.transportSeam(), &m_frames, .{});
    var rtu = try OutstationServer.init(.{ .common_address = 47 }, &points, r_end.transportSeam(), &r_frames, &r_queue, .{});
    var rig = Rig{ .master = &master, .rtu = &rtu };
    defer rig.deinit(gpa);

    master.beginConnect(0);
    master.onConnected(0);
    rtu.onConnected(0);
    try master.startDataTransfer(0);
    try rig.settle(gpa);

    points[0].element = .{ .siq = .{ .on = true, .quality = .{ .sb = true } } };
    points[0].time = .{ .cp56 = .{ .millisecond = 500, .second = 30, .minute = 15, .hour = 12, .day = 23, .month = 7, .year = 26 } };
    try rtu.reportSpontaneous(201, rig.now);

    var got: ?asdu.Object = null;
    var idle: usize = 0;
    while (idle < 4) {
        rig.now += 1;
        var progress = false;
        switch (try rtu.poll(rig.now)) {
            .none => {},
            else => progress = true,
        }
        switch (try master.poll(rig.now)) {
            .asdu => |a| {
                progress = true;
                try testing.expectEqual(Cot.spontaneous, a.header.cause.cot);
                var it = a.objects();
                got = try it.next();
            },
            .none => {},
            else => progress = true,
        }
        idle = if (progress) 0 else idle + 1;
    }
    try testing.expect(got != null);
    try testing.expectEqual(@as(u32, 201), got.?.ioa);
    try testing.expect(got.?.element.siq.on);
    try testing.expect(got.?.element.siq.quality.sb);
    try testing.expectEqual(@as(u8, 30), got.?.time.cp56Time().?.second);
}

// ── live: a third-party master drives our outstation ───────────────────────
//
// Set IEC104_TEST_LISTEN=host:port and point a real controlling station at it
// (a `c104`/lib60870 client, for instance). Without the variable the test
// prints SKIPPED and passes.

const builtin = @import("builtin");

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

test "live: a third-party controlling station drives our outstation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("IEC104_TEST_LISTEN") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 104 outstation (set IEC104_TEST_LISTEN=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const colon = std.mem.findScalarLast(u8, endpoint, ':') orelse return error.SkipZigTest;
    const host = endpoint[0..colon];
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(host, port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 104 outstation (cannot bind {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer listener.socket.close(io);
    std.debug.print("live IEC 104 outstation listening on {s}\n", .{endpoint});

    const stream = listener.accept(io) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live IEC 104 outstation (no peer connected)\n", .{});
        return error.SkipZigTest;
    };

    var tt = TcpTransport{ .io = io, .stream = stream };
    defer tt.close();
    try tt.setReadTimeout(500);

    var points = [_]Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 102, .type_id = .m_dp_na_1, .element = .{ .diq = .{ .state = .on } } },
        .{ .ioa = 105, .type_id = .m_me_nc_1, .element = .{ .short_float = .{ .value = 3.14159, .quality = .{} } } },
        .{ .ioa = 108, .type_id = .m_it_na_1, .element = .{ .counter = .{ .counter = 4242 } } },
        .{ .ioa = 301, .type_id = .c_sc_na_1, .element = .{ .sco = .{} }, .command_mode = .select_and_execute },
    };
    var frames: [apci.max_apdu_len * 2]u8 = undefined;
    var queue: [16384]u8 = undefined;
    var rtu = try OutstationServer.init(
        .{ .common_address = 47 },
        &points,
        tt.transport(),
        &frames,
        &queue,
        .{},
    );

    var now: u64 = 0;
    rtu.onConnected(now);
    var saw_start = false;
    var saw_interrogation = false;
    var saw_command = false;
    var commands: usize = 0;
    var rounds: usize = 0;
    // Run until the peer disconnects rather than stopping at the first
    // command: select-before-operate takes two of them.
    while (rounds < 400) : (rounds += 1) {
        now += 100;
        const ev = rtu.poll(now) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        switch (ev) {
            .started => saw_start = true,
            .request => |h| switch (h.type_id) {
                .c_ic_na_1 => saw_interrogation = true,
                .c_sc_na_1 => {
                    saw_command = true;
                    commands += 1;
                },
                else => {},
            },
            .closed => break,
            else => {},
        }
    }
    std.debug.print(
        "live IEC 104 outstation: startdt={} interrogation={} commands={d} sco_on={}\n",
        .{ saw_start, saw_interrogation, commands, points[4].element.sco.on },
    );
    try testing.expect(saw_start);
    try testing.expect(saw_interrogation);
    if (saw_command) {
        // A select-before-operate peer sends two activations; the second one
        // must actually have operated the output.
        try testing.expectEqual(@as(usize, 2), commands);
        try testing.expect(points[4].element.sco.on);
    }
}

test "a frame split across TCP segments survives a frame_buf at the documented minimum" {
    // `Transport` is a generic byte stream, and `TcpTransport` only hides this
    // by happening to deliver exactly one whole APDU per read. With the
    // framer holding a partial frame, `pending + chunk` used to exceed a
    // buffer sized at `max_apdu_len` and `feed` returned `BufferTooSmall` —
    // an error whose own doc said it could not happen
    // (W2 re-audit, `iec104` F5).
    var loop = transport.LoopTransport{};
    var frame_buf: [apci.max_apdu_len]u8 = undefined; // the documented minimum
    var c = try Client.init(loop.transport(), &frame_buf, .{});
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    const startdt_con = [_]u8{ 0x68, 0x04, 0x0b, 0x00, 0x00, 0x00 };
    loop.deliver(&startdt_con); // STARTDT con
    _ = try c.poll(0);

    var f2: [apci.max_apdu_len]u8 = undefined;
    const full = try apci.encode(
        .{ .i = .{ .send_seq = 0, .recv_seq = 0 } },
        &@as([apci.max_asdu_len]u8, @splat(0)),
        &f2,
    );
    loop.deliver(full[0..200]);
    _ = try c.poll(0);
    loop.deliver(full[200..]);
    loop.deliver(full); // a second frame coalesced behind the tail
    // The point is that this returns rather than erroring out of the framer.
    _ = try c.poll(0);
}

// ── file transfer across the whole stack ────────────────────────────────────

const RigFiles = struct {
    data: [4000]u8 = undefined,
    sink_buf: [4000]u8 = undefined,
    sink_len: usize = 0,
    sink_ended: ?bool = null,

    fn fill(self: *RigFiles) void {
        for (&self.data, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    }

    fn source(self: *RigFiles) file.Source {
        return .{ .ctx = self, .entryFn = entryFn, .readFn = readFn };
    }

    fn entryFn(ctx: ?*anyopaque, i: usize) ?file.DirEntry {
        const self: *RigFiles = @ptrCast(@alignCast(ctx));
        return switch (i) {
            0 => .{ .nof = 3, .length = @intCast(self.data.len), .time = .{ .year = 26, .month = 11, .day = 20 } },
            1 => .{ .nof = 4, .length = 0 },
            else => null,
        };
    }

    fn readFn(ctx: ?*anyopaque, nof: u16, offset: u32, out: []u8) usize {
        const self: *RigFiles = @ptrCast(@alignCast(ctx));
        if (nof != 3 or offset >= self.data.len) return 0;
        const n = @min(out.len, self.data.len - offset);
        @memcpy(out[0..n], self.data[offset..][0..n]);
        return n;
    }

    fn sink(self: *RigFiles) file.Sink {
        return .{ .ctx = self, .beginFn = beginFn, .writeFn = writeFn, .endFn = endFn };
    }

    fn beginFn(ctx: ?*anyopaque, _: u16, length: u32) bool {
        const self: *RigFiles = @ptrCast(@alignCast(ctx));
        self.sink_len = 0;
        self.sink_ended = null;
        return length <= self.sink_buf.len;
    }

    fn writeFn(ctx: ?*anyopaque, _: u16, offset: u32, data: []const u8) bool {
        const self: *RigFiles = @ptrCast(@alignCast(ctx));
        if (offset != self.sink_len) return false;
        @memcpy(self.sink_buf[self.sink_len..][0..data.len], data);
        self.sink_len += data.len;
        return true;
    }

    fn endFn(ctx: ?*anyopaque, _: u16, ok: bool) void {
        const self: *RigFiles = @ptrCast(@alignCast(ctx));
        self.sink_ended = ok;
    }
};

test "round trip: a master lists and reads a file from the outstation through a small k window" {
    const gpa = testing.allocator;
    var wire = Wire{};
    var m_end = MasterEnd{ .wire = &wire };
    var r_end = RtuEnd{ .wire = &wire };
    var rtu_files = RigFiles{};
    rtu_files.fill();
    var master_files = RigFiles{};

    var points = [_]Point{.{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } }};
    var m_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_frames: [apci.max_apdu_len * 2]u8 = undefined;
    var r_queue: [16384]u8 = undefined;
    const cfg = Config{ .k = 3, .w = 2, .t0_ms = 100_000, .t1_ms = 50_000, .t2_ms = 1_000, .t3_ms = 100_000 };
    var master = try Client.init(m_end.transportSeam(), &m_frames, .{ .config = cfg });
    var rtu = try OutstationServer.init(.{
        .common_address = 47,
        .files = rtu_files.source(),
        .file_section_len = 1500,
    }, &points, r_end.transportSeam(), &r_frames, &r_queue, cfg);
    var rig = Rig{ .master = &master, .rtu = &rtu };
    defer rig.deinit(gpa);

    master.beginConnect(0);
    master.onConnected(0);
    rtu.onConnected(0);
    try master.startDataTransfer(0);
    try rig.settle(gpa);

    // The directory: one F_DR_TA_1 per file.
    try master.requestDirectory(47, rig.now);
    try rig.settle(gpa);
    try testing.expectEqualSlices(TypeId, &.{ .f_dr_ta_1, .f_dr_ta_1 }, rig.seen.items);

    // The file: 4000 octets, 3 sections of 1500/1500/1000, 17+... segments.
    try master.fetchFile(47, 3, master_files.sink(), rig.now);
    try rig.settle(gpa);
    try testing.expectEqual(file.Result.Kind.completed, master.takeFileResult().?.kind);
    try testing.expectEqual(@as(?bool, true), master_files.sink_ended);
    try testing.expectEqualSlices(u8, &rtu_files.data, master_files.sink_buf[0..master_files.sink_len]);
    try testing.expect(rtu.outstation.takeFileResult().?.kind == .completed);
    try testing.expect(master.conn.recv_seq > cfg.k);

    // A file the station does not have is refused, and the master is free again.
    try master.fetchFile(47, 99, master_files.sink(), rig.now);
    try rig.settle(gpa);
    try testing.expectEqual(file.Result.Kind.refused, master.takeFileResult().?.kind);
    try testing.expect(master.takeFileResult() == null);
    try master.fetchFile(47, 3, master_files.sink(), rig.now);
}

test "round trip: a master sends a file to the outstation's sink; without a sink the offer is refused" {
    const gpa = testing.allocator;
    var master_files = RigFiles{};
    master_files.fill();
    var rtu_files = RigFiles{};
    var points = [_]Point{.{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } }};

    inline for ([_]bool{ true, false }) |with_sink| {
        var wire = Wire{};
        var m_end = MasterEnd{ .wire = &wire };
        var r_end = RtuEnd{ .wire = &wire };
        var m_frames: [apci.max_apdu_len * 2]u8 = undefined;
        var r_frames: [apci.max_apdu_len * 2]u8 = undefined;
        var r_queue: [4096]u8 = undefined;
        var master = try Client.init(m_end.transportSeam(), &m_frames, .{});
        var rtu = try OutstationServer.init(.{
            .common_address = 47,
            .file_sink = if (with_sink) rtu_files.sink() else null,
        }, &points, r_end.transportSeam(), &r_frames, &r_queue, .{});
        var rig = Rig{ .master = &master, .rtu = &rtu };
        defer rig.deinit(gpa);
        master.beginConnect(0);
        master.onConnected(0);
        rtu.onConnected(0);
        try master.startDataTransfer(0);
        try rig.settle(gpa);
        try master.sendFile(47, 3, master_files.source(), 1500, rig.now);
        try testing.expectError(error.FileTransferBusy, master.sendFile(47, 3, master_files.source(), 1500, rig.now));
        try rig.settle(gpa);
        if (with_sink) {
            try testing.expectEqual(file.Result.Kind.completed, master.takeFileResult().?.kind);
            try testing.expectEqual(file.Result.Kind.completed, rtu.outstation.takeFileResult().?.kind);
            try testing.expectEqual(@as(?bool, true), rtu_files.sink_ended);
            try testing.expectEqualSlices(u8, &master_files.data, rtu_files.sink_buf[0..rtu_files.sink_len]);
        } else {
            // No file service: the type id is answered with cause 44, negative.
            try testing.expect(rig.saw_negative);
            try testing.expectEqualSlices(TypeId, &.{.f_fr_na_1}, rig.seen.items);
            master.abortFiles();
            try testing.expectError(error.FileNotFound, master.sendFile(47, 99, master_files.source(), 1500, rig.now));
        }
    }
}

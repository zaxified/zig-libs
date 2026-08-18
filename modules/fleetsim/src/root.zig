// SPDX-License-Identifier: MIT

//! fleetsim — an in-process fleet of simulated industrial devices.
//!
//! This repository grew a **responder** for every industrial protocol it
//! speaks — Modbus, DNP3, IEC 60870-5-104, S7comm, BACnet/IP, EtherNet/IP and
//! OPC UA — each one pure, packet-to-packet, clock-injected and driven in anger
//! by a real third-party master. What did not exist was the thing that composes
//! them: a *fleet*, addressable and schedulable together, that a test harness
//! or a management plane can point at. That is this module.
//!
//! Three pieces:
//!
//!  - **`Node`** (`node.zig`) — the one vtable all seven responders satisfy
//!    (`deliver` / `tick` / `nextDeadline` / `control`), plus the framing rules
//!    that cut a responder's output back into wire frames. The adapters in
//!    `adapters.zig` implement it *from the outside*: not one line of any
//!    responder module changed.
//!  - **`Fleet`** (`fleet.zig`) — N nodes, one injected clock, one event queue
//!    ordered by `(time, insertion sequence)`, one seed. No threads, no
//!    sockets, no wall-clock reads. Same seed + same input ⇒ byte-identical
//!    trace, which is what lets a harness replay a failure exactly.
//!  - **`Signal`** (`drivers.zig`) — point behaviour. Constant, ramp, sine,
//!    seeded random walk, step-on-schedule and recorded replay, feeding any
//!    number of protocol-shaped sinks, so one driver instance can animate a
//!    Modbus holding register, a DNP3 analog input and an OPC UA variable at
//!    once.
//!
//! Fault injection is the point of the exercise: per-node link delay, jitter,
//! loss, duplication and reordering, plus protocol-level faults — a node that
//! goes silent, one that answers late, one that reports device trouble, one
//! that restarts so the master sees the restart indication. Every one of them
//! is a function of the injected clock and the seed. `netsim`'s fault-schedule
//! fuzzer and replayable trace format are reused wholesale
//! (`Fleet.applyNetsimTrace`) rather than reinvented.
//!
//! `tcp.zig` is the only file that touches a socket, and it is optional: the
//! core is usable with no I/O at all.
//!
//! Provenance: clean-room. The determinism methodology (seeded PRNG, total
//! event order, replayable fault trace) follows `netsim`, which in turn follows
//! TigerBeetle's VOPR — see the repository NOTICE.

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
    .targets = .{.linux64},
    .platform = .any, // the core is pure; only `tcp.zig` needs a POSIX socket
    .role = .server, // it answers masters
    .concurrency = .single_owner, // one thread owns a Fleet; no locks anywhere
    .model_after = "TigerBeetle VOPR determinism via netsim; SCADA device simulators (ModbusPal, Kepware sim)",
    .deps = .{ "modbus", "dnp3", "iec104", "s7comm", "bacnet", "enip", "opcua", "netsim" },
};

// ── public API ──────────────────────────────────────────────────────────────

pub const node = @import("node.zig");
pub const drivers = @import("drivers.zig");
pub const fleet = @import("fleet.zig");
pub const adapters = @import("adapters.zig");
pub const tcp = @import("tcp.zig");

pub const Node = node.Node;
pub const NodeId = node.NodeId;
pub const NodeError = node.NodeError;
pub const Time = node.Time;
pub const Protocol = node.Protocol;
pub const Framing = node.Framing;
pub const FrameIterator = node.FrameIterator;
pub const Control = node.Control;

pub const Fleet = fleet.Fleet;
pub const Options = fleet.Options;
pub const NodeSpec = fleet.NodeSpec;
pub const LinkFaults = fleet.LinkFaults;
pub const Fault = fleet.Fault;
pub const FaultKind = fleet.FaultKind;
pub const TraceEntry = fleet.TraceEntry;
pub const TraceKind = fleet.TraceKind;
pub const OutFrame = fleet.OutFrame;
pub const NodeStats = fleet.NodeStats;

pub const Driver = drivers.Driver;
pub const Sink = drivers.Sink;
pub const Signal = drivers.Signal;
pub const StepLevel = drivers.StepLevel;
pub const Sample = drivers.Sample;
pub const ScaledRegister = drivers.ScaledRegister;
pub const Threshold = drivers.Threshold;
pub const FloatBytes = drivers.FloatBytes;
pub const Cell = drivers.Cell;

pub const ModbusNode = adapters.Modbus;
pub const Dnp3Node = adapters.Dnp3;
pub const Iec104Node = adapters.Iec104;
pub const S7Node = adapters.S7comm;
pub const BacnetNode = adapters.DefaultBacnet;
pub const BacnetNodeWith = adapters.Bacnet;
pub const EnipNode = adapters.Enip;
pub const OpcuaNode = adapters.Opcua;

pub const serveTcp = tcp.serveTcp;
pub const serveTcpOn = tcp.serveTcpOn;
pub const serveTcpMulti = tcp.serveTcpMulti;
pub const serveUdp = tcp.serveUdp;
pub const Binding = tcp.Binding;
pub const MultiOptions = tcp.MultiOptions;
pub const MultiReport = tcp.MultiReport;

pub const shim = @import("shim.zig");
pub const Window = shim.Window;
pub const StreamShim = shim.StreamShim;
pub const DatagramShim = shim.DatagramShim;

/// The fleet plugged into `netsim` as a `Protocol`, so a fault schedule can be
/// SEARCHED for rather than handed over: `netsim.findFailing` +
/// `netsim.shrinkTrace` return a minimised fault trace instead of a seed. See
/// the file header for the division of labour between the two simulators, and
/// for why `Fleet.applyNetsimTrace` (which borrows netsim's fuzzer but has no
/// oracle) could not do this on its own.
pub const vopr = @import("vopr.zig");
pub const Vopr = vopr.Vopr;
pub const VoprViolation = vopr.Violation;

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");

const modbus = @import("modbus");
const dnp3 = @import("dnp3");
const iec104 = @import("iec104");
const s7comm = @import("s7comm");
const bacnet = @import("bacnet");
const enip = @import("enip");
const opcua = @import("opcua");
const netsim = @import("netsim");

/// A Modbus TCP request builder used all over the tests below.
fn readHolding(buf: []u8, txid: u16, unit: u8, addr: u16, count: u16) []u8 {
    var pdu: [5]u8 = undefined;
    pdu[0] = 0x03;
    std.mem.writeInt(u16, pdu[1..3], addr, .big);
    std.mem.writeInt(u16, pdu[3..5], count, .big);
    return modbus.tcp.encodeAdu(buf, txid, unit, &pdu) catch unreachable;
}

// ── a heterogeneous fleet ───────────────────────────────────────────────────

test "a fleet of five protocols answers on one clock" {
    var f = try Fleet.init(testing.allocator, .{ .seed = 7, .max_frame_len = 2048 });
    defer f.deinit();

    // 1. Modbus slave.
    var holdings = [_]u16{ 10, 20, 30, 40 };
    var mb_node = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const mb_id = try f.addNode(.{ .node = mb_node.node(), .tag = 1 });

    // 2. IEC 104 outstation.
    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 105, .type_id = .m_me_nc_1, .element = .{ .short_float = .{ .value = 1.5, .quality = .{} } } },
    };
    var iec_frames: [512]u8 = undefined;
    var iec_queue: [4096]u8 = undefined;
    var iec_node: Iec104Node = undefined;
    try iec_node.init(.{ .common_address = 47 }, &points, &iec_frames, &iec_queue, .{});
    const iec_id = try f.addNode(.{ .node = iec_node.node(), .tag = 2, .tick_period_ms = 1000 });

    // 3. S7 CPU.
    var db1 = [_]u8{0} ** 64;
    const areas = [_]s7comm.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var s7_node = S7Node.init(.{}, &areas);
    const s7_id = try f.addNode(.{ .node = s7_node.node(), .tag = 3 });

    // 4. EtherNet/IP adapter.
    var tag_bytes = [_]u8{0} ** 16;
    const tags = [_]enip.TagBinding{.{ .name = "Speed", .type = .dint, .bytes = &tag_bytes }};
    var enip_node = EnipNode.init(.{}, &tags);
    const enip_id = try f.addNode(.{ .node = enip_node.node(), .tag = 4 });

    // 5. DNP3 outstation.
    var binaries = [_]dnp3.outstation.BinaryInput{.{ .value = true, .class = .class1 }} ** 4;
    var events: [16]dnp3.outstation.Event = undefined;
    var rx_buf: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx_fragment: [2048]u8 = undefined;
    var dnp_node: Dnp3Node = undefined;
    dnp_node.init(
        .{ .address = 1024, .master_address = 1 },
        .{ .binary_inputs = &binaries },
        dnp3.outstation.EventBuffer.init(&events),
        &rx_buf,
        &scratch,
        &tx_fragment,
    );
    const dnp_id = try f.addNode(.{ .node = dnp_node.node(), .tag = 5 });

    try testing.expectEqual(@as(usize, 5), f.nodeCount());

    // Drive every one of them with a frame its own protocol would send.
    var mb_buf: [modbus.tcp.max_adu_len]u8 = undefined;
    try f.submit(mb_id, readHolding(&mb_buf, 1, 1, 0, 4), 0);
    try f.submit(iec_id, &.{ 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 }, 0); // STARTDT act
    try f.submit(s7_id, &.{
        0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
    }, 0);
    var enip_req: [28]u8 = @splat(0);
    std.mem.writeInt(u16, enip_req[0..2], @intFromEnum(enip.Command.register_session), .little);
    std.mem.writeInt(u16, enip_req[2..4], 4, .little);
    std.mem.writeInt(u16, enip_req[24..26], 1, .little);
    try f.submit(enip_id, &enip_req, 0);
    var link_buf: [64]u8 = undefined;
    const reset = try dnp3.link.encodeFrame(
        .{ .dir = true, .prm = true, .function = @intFromEnum(dnp3.link.PrimaryFunction.reset_link_states) },
        1024,
        1,
        &.{},
        &link_buf,
    );
    try f.submit(dnp_id, reset, 0);

    _ = try f.advance(10);

    // Every one of them answered, and every answer parses as its own framing.
    var seen = [_]bool{false} ** 5;
    for (f.outbound()) |out| {
        seen[out.node] = true;
        const bytes = f.frameBytes(out);
        const framing = switch (out.node) {
            0 => Framing.modbus_tcp,
            1 => Framing.iec104_apci,
            2 => Framing.tpkt,
            3 => Framing.enip_encap,
            else => Framing.dnp3_link,
        };
        try testing.expectEqual(@as(?usize, bytes.len), try framing.frameLen(bytes));
    }
    for (seen) |s| try testing.expect(s);

    // The Modbus answer really carries the register values.
    for (f.outbound()) |out| {
        if (out.node != mb_id) continue;
        const bytes = f.frameBytes(out);
        try testing.expectEqualSlices(u8, &.{ 0x03, 0x08, 0, 10, 0, 20, 0, 30, 0, 40 }, bytes[7..]);
    }
}

// ── determinism ─────────────────────────────────────────────────────────────

const TraceDigest = struct {
    fingerprint: u64,
    entries: usize,
    events: u64,
    /// A second, independent hash over the emitted frames only.
    out_hash: u64,
    /// Trace entries that record a fault actually biting (loss, duplication,
    /// a silenced node, a restart).
    faulted: usize,
    /// `applyNetsimTrace`'s unmapped-event count (currently only
    /// `clock_jump`, which has no fleet meaning — see `Fleet.applyNetsimTrace`).
    /// Threaded through so a test can assert on it instead of the caller
    /// discarding it with `_ = try …`.
    unmapped: usize,
};

/// One canned run: a Modbus slave and a DNP3 outstation behind a lossy,
/// jittery, duplicating link, animated by a random walk, with a fault schedule
/// borrowed from netsim's fuzzer.
fn cannedRun(seed: u64, collect: ?*std.ArrayList(u8)) !TraceDigest {
    const gpa = testing.allocator;
    var f = try Fleet.init(gpa, .{
        .seed = seed,
        .max_frame_len = 512,
        .inflight_capacity = 256,
        .trace_capacity = 8192,
        .trace_bytes = 512 * 1024,
    });
    defer f.deinit();

    var holdings = [_]u16{0} ** 8;
    var mb_node = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const mb_id = try f.addNode(.{
        .node = mb_node.node(),
        .link = .{ .delay_ms = 3, .jitter_ms = 5, .loss_permille = 80, .dup_permille = 60, .reorder_permille = 90 },
    });

    var binaries = [_]dnp3.outstation.BinaryInput{.{ .value = false, .class = .class1 }} ** 4;
    var analogs = [_]dnp3.outstation.AnalogInput{.{ .value = 0, .class = .class2 }} ** 2;
    var events: [32]dnp3.outstation.Event = undefined;
    var rx_buf: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx_fragment: [1024]u8 = undefined;
    var dnp_node: Dnp3Node = undefined;
    dnp_node.init(
        .{ .address = 1024, .master_address = 1 },
        .{ .binary_inputs = &binaries, .analog_inputs = &analogs },
        dnp3.outstation.EventBuffer.init(&events),
        &rx_buf,
        &scratch,
        &tx_fragment,
    );
    const dnp_id = try f.addNode(.{
        .node = dnp_node.node(),
        .link = .{ .delay_ms = 7, .jitter_ms = 3, .loss_permille = 50 },
    });

    // One driver instance, two protocols' worth of sinks.
    var s_reg = ScaledRegister{ .cell = &holdings[0], .scale = 100 };
    var walk_cell: f64 = 0;
    var s_cell = Cell{ .cell = &walk_cell };
    const sinks = [_]Sink{ s_reg.sink(), s_cell.sink() };
    var sig = Signal{
        .driver = .{ .random_walk = .{ .value = 50, .step = 4, .min = 0, .max = 100 } },
        .sinks = &sinks,
        .period_ms = 250,
    };
    try f.addSignal(&sig);

    // netsim generates the fault schedule; the fleet just executes it.
    const links = [_]netsim.Link{.{ .a = 0, .b = 1 }};
    var trace = try netsim.generateFaultTrace(
        gpa,
        seed,
        .{ .node_count = 2, .links = &links },
        .{ .horizon = 4000, .max_events = 8 },
    );
    defer trace.deinit();
    const unmapped = try f.applyNetsimTrace(trace.events);

    var mb_buf: [modbus.tcp.max_adu_len]u8 = undefined;
    var link_buf: [64]u8 = undefined;
    const reset = try dnp3.link.encodeFrame(
        .{ .dir = true, .prm = true, .function = @intFromEnum(dnp3.link.PrimaryFunction.reset_link_states) },
        1024,
        1,
        &.{},
        &link_buf,
    );

    var out_hash: u64 = 0xcbf29ce484222325;
    var t: Time = 0;
    var txid: u16 = 1;
    while (t < 5000) : (t += 50) {
        try f.submit(mb_id, readHolding(&mb_buf, txid, 1, 0, 4), t);
        txid +%= 1;
        if (t % 200 == 0) try f.submit(dnp_id, reset, t);
        _ = try f.advance(t);
        for (f.outbound()) |o| {
            const bytes = f.frameBytes(o);
            for (bytes) |b| {
                out_hash ^= b;
                out_hash *%= 0x100000001b3;
            }
            if (collect) |c| try c.appendSlice(gpa, bytes);
        }
    }
    _ = try f.advance(6000);

    const entries = try gpa.alloc(TraceEntry, f.traceLen());
    defer gpa.free(entries);
    var faulted: usize = 0;
    for (f.traceInto(entries)) |e| {
        switch (e.kind) {
            .dropped_in, .dropped_out, .duplicated_in, .duplicated_out, .delayed_in, .silent, .control_applied => faulted += 1,
            else => {},
        }
    }

    return .{
        .fingerprint = f.fingerprint,
        .entries = f.traceLen(),
        .events = f.events_processed,
        .out_hash = out_hash,
        .faulted = faulted,
        .unmapped = unmapped,
    };
}

test "determinism: the same seed reproduces a byte-identical emitted stream" {
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(testing.allocator);
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(testing.allocator);

    const d1 = try cannedRun(0xC0FFEE, &a);
    const d2 = try cannedRun(0xC0FFEE, &b);

    try testing.expectEqual(d1.fingerprint, d2.fingerprint);
    try testing.expectEqual(d1.events, d2.events);
    try testing.expectEqual(d1.entries, d2.entries);
    try testing.expectEqualSlices(u8, a.items, b.items);
    // Teeth: the run actually produced traffic.
    // Teeth: real traffic happened, and the injected faults really bit.
    try testing.expect(a.items.len > 1000);
    try testing.expect(d1.events > 200);
    try testing.expect(d1.faulted > 20);
    try testing.expectEqual(d1.faulted, d2.faulted);

    // Absolute golden (F4): every prior assertion above is purely
    // self-consistency (same seed -> equal, different seed -> unequal), so a
    // change that alters every emitted byte identically on both sides of a
    // same-seed comparison would pass silently. Pin canonical seed 0xC0FFEE's
    // fingerprint/out_hash to a captured constant so such a change is caught.
    try testing.expectEqual(@as(u64, 0xdfd7130c1cf5bb4d), d1.fingerprint);
    try testing.expectEqual(@as(u64, 0x78c0521f7775613b), d1.out_hash);
}

test "determinism: cannedRun surfaces applyNetsimTrace's unmapped (clock_jump) count, not discards it" {
    // F5: the only production caller of `applyNetsimTrace` was
    // `_ = try f.applyNetsimTrace(trace.events);` — the unmapped-event
    // count (currently only `netsim`'s clock_jump, which has no fleet
    // meaning) was computed and thrown away, so a canned run could not tell
    // whether a seed's fault schedule was applied in full or partially
    // dropped. Seed 2 is a concrete draw whose schedule contains a
    // clock_jump (found by scanning small seeds against this horizon/
    // max_events config); pin the exact unmapped count `cannedRun` now
    // surfaces for it.
    const d = try cannedRun(2, null);
    try testing.expectEqual(@as(usize, 1), d.unmapped);
}

test "determinism: a different seed diverges" {
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(testing.allocator);
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(testing.allocator);

    const d1 = try cannedRun(0xC0FFEE, &a);
    const d2 = try cannedRun(0xDEADBEEF, &b);

    try testing.expect(d1.fingerprint != d2.fingerprint);
    try testing.expect(d1.out_hash != d2.out_hash);
    try testing.expect(!std.mem.eql(u8, a.items, b.items));
}

fn grabTrace(seed: u64, out: *std.ArrayList(TraceEntry), bytes: *std.ArrayList(u8)) !void {
    const gpa = testing.allocator;
    var f = try Fleet.init(gpa, .{ .seed = seed, .max_frame_len = 300, .trace_capacity = 4096 });
    defer f.deinit();
    var holdings = [_]u16{ 1, 2, 3, 4 };
    var mb_node = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const id = try f.addNode(.{ .node = mb_node.node(), .link = .{
        .delay_ms = 2,
        .jitter_ms = 4,
        .loss_permille = 150,
        .dup_permille = 150,
    } });
    var buf: [modbus.tcp.max_adu_len]u8 = undefined;
    var t: Time = 0;
    while (t < 2000) : (t += 25) {
        try f.submit(id, readHolding(&buf, @intCast(t / 25 + 1), 1, 0, 4), t);
        _ = try f.advance(t);
    }
    _ = try f.advance(3000);
    const entries = try gpa.alloc(TraceEntry, f.traceLen());
    defer gpa.free(entries);
    for (f.traceInto(entries)) |e| {
        try out.append(gpa, e);
        try bytes.appendSlice(gpa, f.traceBytes(e));
    }
}

test "determinism: the trace entries themselves replay identically" {
    const gpa = testing.allocator;
    var e1: std.ArrayList(TraceEntry) = .empty;
    defer e1.deinit(gpa);
    var b1: std.ArrayList(u8) = .empty;
    defer b1.deinit(gpa);
    var e2: std.ArrayList(TraceEntry) = .empty;
    defer e2.deinit(gpa);
    var b2: std.ArrayList(u8) = .empty;
    defer b2.deinit(gpa);
    var e3: std.ArrayList(TraceEntry) = .empty;
    defer e3.deinit(gpa);
    var b3: std.ArrayList(u8) = .empty;
    defer b3.deinit(gpa);

    try grabTrace(99, &e1, &b1);
    try grabTrace(99, &e2, &b2);
    try grabTrace(100, &e3, &b3);

    try testing.expectEqual(e1.items.len, e2.items.len);
    for (e1.items, e2.items) |x, y| {
        try testing.expectEqual(x.time, y.time);
        try testing.expectEqual(x.node, y.node);
        try testing.expectEqual(x.kind, y.kind);
        try testing.expectEqual(x.len, y.len);
    }
    try testing.expectEqualSlices(u8, b1.items, b2.items);
    try testing.expect(e1.items.len > 100);
    // A different seed must not accidentally produce the same trace.
    const same = e1.items.len == e3.items.len and std.mem.eql(u8, b1.items, b3.items);
    try testing.expect(!same);
}

// ── faults ──────────────────────────────────────────────────────────────────

test "faults: silent, trouble and slow are all visible to a master" {
    var f = try Fleet.init(testing.allocator, .{ .seed = 1, .max_frame_len = 300 });
    defer f.deinit();
    var holdings = [_]u16{ 7, 8 };
    var mb_node = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const id = try f.addNode(.{ .node = mb_node.node() });

    try f.addFault(.{ .at_ms = 1000, .node = id, .kind = .{ .silent = .{ .until_ms = 2000 } } });
    try f.addFault(.{ .at_ms = 2000, .node = id, .kind = .{ .trouble = .{ .on = true } } });
    try f.addFault(.{ .at_ms = 3000, .node = id, .kind = .heal });
    try f.addFault(.{ .at_ms = 4000, .node = id, .kind = .{ .slow = .{ .extra_ms = 500, .until_ms = 5000 } } });

    var buf: [modbus.tcp.max_adu_len]u8 = undefined;
    const Probe = struct { at: Time, expect_reply: bool, expect_exception: bool };
    const probes = [_]Probe{
        .{ .at = 500, .expect_reply = true, .expect_exception = false },
        .{ .at = 1500, .expect_reply = false, .expect_exception = false },
        .{ .at = 2500, .expect_reply = true, .expect_exception = true },
        .{ .at = 3500, .expect_reply = true, .expect_exception = false },
    };
    for (probes) |p| {
        try f.submit(id, readHolding(&buf, 1, 1, 0, 2), p.at);
        _ = try f.advance(p.at + 10);
        if (!p.expect_reply) {
            try testing.expectEqual(@as(usize, 0), f.outbound().len);
            continue;
        }
        try testing.expectEqual(@as(usize, 1), f.outbound().len);
        const bytes = f.frameBytes(f.outbound()[0]);
        try testing.expectEqual(p.expect_exception, bytes[7] & 0x80 != 0);
        if (p.expect_exception) try testing.expectEqual(@as(u8, 0x04), bytes[8]);
    }

    // The slow window really delays a reply rather than dropping it.
    try f.submit(id, readHolding(&buf, 1, 1, 0, 2), 4100);
    _ = try f.advance(4200);
    try testing.expectEqual(@as(usize, 0), f.outbound().len);
    _ = try f.advance(4800);
    try testing.expectEqual(@as(usize, 1), f.outbound().len);
}

test "faults: a restart makes a DNP3 master see IIN1.7 again" {
    var f = try Fleet.init(testing.allocator, .{ .seed = 3, .max_frame_len = 512 });
    defer f.deinit();

    var binaries = [_]dnp3.outstation.BinaryInput{.{ .value = true, .class = .class1 }} ** 4;
    var events: [16]dnp3.outstation.Event = undefined;
    var rx_buf: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx_fragment: [1024]u8 = undefined;
    var dnp_node: Dnp3Node = undefined;
    dnp_node.init(
        .{ .address = 1024, .master_address = 1 },
        .{ .binary_inputs = &binaries },
        dnp3.outstation.EventBuffer.init(&events),
        &rx_buf,
        &scratch,
        &tx_fragment,
    );
    const id = try f.addNode(.{ .node = dnp_node.node() });

    dnp_node.station.restart = false; // as if the master had cleared it
    try testing.expect(!dnp_node.station.iin().device_restart);

    try f.addFault(.{ .at_ms = 100, .node = id, .kind = .restart });
    _ = try f.advance(200);
    try testing.expect(dnp_node.station.iin().device_restart);
    try testing.expectEqual(@as(u64, 1), f.stats(id).restarts);
}

test "faults: a schedule that expires mid-frame does not strand the frame" {
    var f = try Fleet.init(testing.allocator, .{ .seed = 5, .max_frame_len = 300 });
    defer f.deinit();
    var holdings = [_]u16{ 1, 2 };
    var mb_node = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    // A 400 ms link delay means the frame is in flight when the fault window
    // opens at 100 and again when it closes at 300.
    const id = try f.addNode(.{ .node = mb_node.node(), .link = .{ .delay_ms = 400 } });
    try f.addFault(.{ .at_ms = 100, .node = id, .kind = .{ .silent = .{ .until_ms = 300 } } });

    var buf: [modbus.tcp.max_adu_len]u8 = undefined;
    try f.submit(id, readHolding(&buf, 1, 1, 0, 2), 0);
    _ = try f.advance(2000);
    // It arrived at t=400, after the window closed, so it is answered.
    try testing.expectEqual(@as(usize, 1), f.outbound().len);
    try testing.expectEqual(@as(u64, 0), f.stats(id).silent_drops);

    // The same frame submitted so it lands *inside* the window is eaten.
    try f.addFault(.{ .at_ms = 3000, .node = id, .kind = .{ .silent = .{ .until_ms = 4000 } } });
    try f.submit(id, readHolding(&buf, 2, 1, 0, 2), 3100);
    _ = try f.advance(5000);
    try testing.expectEqual(@as(usize, 0), f.outbound().len);
    try testing.expectEqual(@as(u64, 1), f.stats(id).silent_drops);
    // And the slot came back: nothing leaked.
    try testing.expectEqual(f.opts.inflight_capacity, f.free_count);
}

// ── hostile input ───────────────────────────────────────────────────────────

test "hostile: a frame for an unknown node is a typed error, not a crash" {
    var f = try Fleet.init(testing.allocator, .{});
    defer f.deinit();
    try testing.expectError(error.UnknownNode, f.submit(0, "x", 0));
    try testing.expectError(error.UnknownNode, f.submitStream(7, "x", 0));
}

test "hostile: garbage aimed at every adapter is answered or ignored, never fatal" {
    var f = try Fleet.init(testing.allocator, .{ .seed = 11, .max_frame_len = 2048 });
    defer f.deinit();

    var holdings = [_]u16{0} ** 4;
    var mb_node = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const mb_id = try f.addNode(.{ .node = mb_node.node() });
    var db1 = [_]u8{0} ** 16;
    const areas = [_]s7comm.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var s7_node = S7Node.init(.{}, &areas);
    const s7_id = try f.addNode(.{ .node = s7_node.node() });
    var tag_bytes = [_]u8{0} ** 8;
    const tags = [_]enip.TagBinding{.{ .name = "T", .type = .dint, .bytes = &tag_bytes }};
    var enip_node = EnipNode.init(.{}, &tags);
    const enip_id = try f.addNode(.{ .node = enip_node.node() });

    const junk = [_][]const u8{
        &.{0x00},
        &.{ 0xFF, 0xFF, 0xFF, 0xFF },
        &.{ 0x03, 0x00, 0xFF, 0xFF, 0x00 },
        &[_]u8{0xAA} ** 200,
        &.{ 0x68, 0xFF, 0x00, 0x00, 0x00, 0x00 },
    };
    for ([_]NodeId{ mb_id, s7_id, enip_id }) |id| {
        for (junk, 0..) |j, i| {
            f.submit(id, j, @intCast(i * 10)) catch |e| switch (e) {
                error.FrameTooLarge => continue,
                else => return e,
            };
        }
    }
    _ = try f.advance(1000);
    for (f.outbound()) |o| {
        try testing.expect(f.frameBytes(o).len > 0);
    }
    // No slot leaked.
    try testing.expectEqual(f.opts.inflight_capacity, f.free_count);
}

// ── fuzz ────────────────────────────────────────────────────────────────────

fn fuzzSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    return fuzzDispatch({}, buf[0..len]);
}

fn fuzzDispatch(_: void, input: []const u8) anyerror!void {
    if (input.len == 0) return;
    var f = try Fleet.init(testing.allocator, .{
        .seed = input[0],
        .max_frame_len = 512,
        .inflight_capacity = 32,
        .trace_capacity = 64,
        .trace_bytes = 4096,
        .outbox_bytes = 8192,
    });
    defer f.deinit();

    var holdings = [_]u16{0} ** 8;
    var mb_node = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const mb_id = try f.addNode(.{
        .node = mb_node.node(),
        .link = .{ .loss_permille = 100, .dup_permille = 100 },
    });

    var db1 = [_]u8{0} ** 32;
    const areas = [_]s7comm.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var s7_node = S7Node.init(.{}, &areas);
    const s7_id = try f.addNode(.{ .node = s7_node.node() });

    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
    };
    var iec_frames: [512]u8 = undefined;
    var iec_queue: [2048]u8 = undefined;
    var iec_node: Iec104Node = undefined;
    try iec_node.init(.{ .common_address = 47 }, &points, &iec_frames, &iec_queue, .{});
    const iec_id = try f.addNode(.{ .node = iec_node.node(), .tick_period_ms = 500 });

    // W2 A3 (F3) recorded that only these three of the module's eight adapters
    // were fuzzed, so `dnp3`, `enip` and `bacnet` — all three of which a
    // `serveTcp`/`serveUdp` run exposes to a real socket, i.e. to whatever a
    // peer sends — had no fuzz coverage at all despite being reachable the
    // same way. Nothing structural was in the way; the adapter list simply
    // stopped at three. The three below are stack-allocated, so adding them
    // costs the harness nothing per iteration.
    //
    // `opcua` is the one deliberate omission: an `OpcuaNode` needs a
    // `NodeStore` with the standard node set plus a 64 KiB receive buffer and
    // a 256 KiB message buffer, built per node. Constructing that on every
    // fuzz input would dominate the harness's own cost, and sharing one across
    // inputs would let a session table grow without bound over a long sweep.
    // It needs its own harness with a shared fixture and a per-input reset —
    // recorded here rather than bolted on badly.
    var binaries = [_]dnp3.outstation.BinaryInput{.{ .value = true, .class = .class1 }} ** 4;
    var events: [16]dnp3.outstation.Event = undefined;
    var dnp_rx: [512]u8 = undefined;
    var dnp_scratch: [512]u8 = undefined;
    var dnp_tx: [2048]u8 = undefined;
    var dnp_node: Dnp3Node = undefined;
    dnp_node.init(
        .{ .address = 1024, .master_address = 1 },
        .{ .binary_inputs = &binaries },
        dnp3.outstation.EventBuffer.init(&events),
        &dnp_rx,
        &dnp_scratch,
        &dnp_tx,
    );
    const dnp_id = try f.addNode(.{ .node = dnp_node.node() });

    var tag_bytes = [_]u8{0} ** 16;
    const tags = [_]enip.TagBinding{.{ .name = "Speed", .type = .dint, .bytes = &tag_bytes }};
    var enip_node = EnipNode.init(.{}, &tags);
    const enip_id = try f.addNode(.{ .node = enip_node.node() });

    var ai_props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "AI 1" } },
        .{ .id = .present_value, .value = .{ .real = 1.0 } },
    };
    var dev_props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "zig-fleetsim device" } },
        .{ .id = .vendor_name, .value = .{ .string = "zig-libs" } },
    };
    var objects = [_]bacnet.Object{
        .{ .id = .{ .type = .analog_input, .instance = 1 }, .properties = &ai_props },
        .{ .id = .{ .type = .device, .instance = 260_001 }, .properties = &dev_props },
    };
    var bac_node: BacnetNode = undefined;
    bac_node.init(
        .{ .instance = 260_001, .vendor_id = 999 },
        &objects,
        .{ .ip = .{ 0, 0, 0, 0 }, .port = 47808 },
        .{ .ip = .{ 0, 0, 0, 0 }, .port = 47808 },
    );
    const bac_id = try f.addNode(.{ .node = bac_node.node(), .tick_period_ms = 500 });

    // Every byte of the corpus becomes a frame boundary decision, a node choice
    // and a clock step, so the fuzzer explores dispatch, not just one parser.
    var pos: usize = 0;
    var t: Time = 0;
    const ids = [_]NodeId{ mb_id, s7_id, iec_id, dnp_id, enip_id, bac_id };
    while (pos < input.len) {
        const chunk_len = @min(@as(usize, input[pos]) + 1, input.len - pos);
        const chunk = input[pos..][0..chunk_len];
        const id = ids[chunk[0] % ids.len];
        _ = f.submitStream(id, chunk, t) catch |e| switch (e) {
            error.UnknownNode, error.FrameTooLarge => {},
            else => return e,
        };
        _ = try f.advance(t);
        t += 1 + @as(Time, chunk[chunk_len - 1]);
        pos += chunk_len;
    }
    _ = try f.advance(t + 5000);
    // The invariant that must hold no matter what came in: every in-flight
    // slot is back in the pool once the queue has drained.
    try testing.expectEqual(f.opts.inflight_capacity, f.free_count);
}

test "fuzz: frame dispatch across six adapters survives arbitrary bytes" {
    try std.testing.fuzz({}, fuzzSmith, .{});
}

test "fuzz: the seed corpus (deterministic, runs in CI)" {
    const corpus = [_][]const u8{
        &.{0x00},
        &.{ 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04, 0xE9, 0x21 },
        &.{ 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 },
        &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02 },
        &.{ 0x03, 0x00, 0x00, 0x16, 0x11, 0xE0 },
        &[_]u8{0xFF} ** 64,
        &[_]u8{0x00} ** 64,
    };
    for (corpus) |c| try fuzzDispatch({}, c);
}

// ── scale ───────────────────────────────────────────────────────────────────

fn residentBytes() ?usize {
    if (builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    var buf: [256]u8 = undefined;
    const raw = linux.open("/proc/self/statm", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(raw) != .SUCCESS) return null;
    const fd: i32 = @intCast(raw);
    defer _ = linux.close(fd);
    const got = linux.read(fd, &buf, buf.len);
    if (linux.errno(got) != .SUCCESS) return null;
    const n: usize = @intCast(got);
    var it = std.mem.tokenizeScalar(u8, buf[0..n], ' ');
    _ = it.next() orelse return null; // total program size
    const rss_pages = it.next() orelse return null;
    const pages = std.fmt.parseInt(usize, std.mem.trim(u8, rss_pages, " \n"), 10) catch return null;
    return pages * std.heap.pageSize();
}

test "scale: 1000 in-process Modbus nodes, advanced over simulated minutes" {
    const gpa = testing.allocator;
    const n_nodes = 1000;
    const regs_per_node = 16;

    const before = residentBytes();

    var f = try Fleet.init(gpa, .{
        .seed = 0x5CA1E,
        .max_frame_len = 300,
        .inflight_capacity = 4096,
        // A 1000-node run's full trace would never fit; the fingerprint covers
        // every entry regardless, so the ring can stay small.
        .trace_capacity = 64,
        .trace_bytes = 4096,
        .outbox_bytes = 1 << 20,
        .record_frames = false,
    });
    defer f.deinit();

    const storage = try gpa.alloc(u16, n_nodes * regs_per_node);
    defer gpa.free(storage);
    @memset(storage, 0);
    const slaves = try gpa.alloc(ModbusNode, n_nodes);
    defer gpa.free(slaves);

    for (slaves, 0..) |*s, i| {
        s.* = ModbusNode.init(
            .{ .unit_id = @intCast(1 + (i % 247)), .framing = .tcp, .accept_any_unit = true },
            .{ .holding_registers = .{
                .base = 0,
                .values = storage[i * regs_per_node ..][0..regs_per_node],
            } },
        );
        _ = try f.addNode(.{
            .node = s.node(),
            .link = .{ .delay_ms = 1, .jitter_ms = 3, .loss_permille = 10 },
            .tag = @intCast(i),
        });
    }

    // 64 signals animating the process image, shared across the fleet.
    const n_signals = 64;
    const sinks = try gpa.alloc(ScaledRegister, n_signals);
    defer gpa.free(sinks);
    const sink_views = try gpa.alloc([1]Sink, n_signals);
    defer gpa.free(sink_views);
    const signals = try gpa.alloc(Signal, n_signals);
    defer gpa.free(signals);
    for (0..n_signals) |i| {
        sinks[i] = .{ .cell = &storage[i * regs_per_node], .scale = 10 };
        sink_views[i] = .{sinks[i].sink()};
        signals[i] = .{
            .driver = if (i % 2 == 0)
                .{ .sine = .{ .mean = 500, .amplitude = 200, .period_ms = 10_000, .phase_ms = i * 100 } }
            else
                .{ .random_walk = .{ .value = 500, .step = 20, .min = 0, .max = 1000 } },
            .sinks = &sink_views[i],
            .period_ms = 1000,
        };
        try f.addSignal(&signals[i]);
    }

    const setup = residentBytes();

    var req_buf: [modbus.tcp.max_adu_len]u8 = undefined;
    const start = tcp.nowMs();
    var polls: usize = 0;
    var replies: usize = 0;
    var t: Time = 0;
    // Six simulated minutes at a 1 s poll cycle.
    while (t < 360_000) : (t += 1000) {
        for (0..n_nodes) |i| {
            const req = readHolding(&req_buf, @intCast(t / 1000 + 1), @intCast(1 + (i % 247)), 0, 4);
            try f.submit(@intCast(i), req, t);
            polls += 1;
        }
        _ = try f.advance(t + 999);
        replies += f.outbound().len;
    }
    _ = try f.advance(t + 10_000);
    const elapsed = tcp.nowMs() - start;
    const peak = residentBytes();

    // Informational, not a failure — same stderr rule as the skip reasons.
    if (verboseSkip()) std.debug.print(
        "\nscale: {d} nodes, {d} signals, {d} polls, {d} replies, {d} events, {d} ms wall" ++
            " ({d:.2} us/poll), rss {?d} -> {?d} -> {?d} KiB, capacity losses {d}\n",
        .{
            n_nodes,
            n_signals,
            polls,
            replies,
            f.events_processed,
            elapsed,
            @as(f64, @floatFromInt(elapsed)) * 1000.0 / @as(f64, @floatFromInt(polls)),
            if (before) |v| v / 1024 else null,
            if (setup) |v| v / 1024 else null,
            if (peak) |v| v / 1024 else null,
            f.capacity_losses,
        },
    );

    // The fleet really answered (loss is 1% each way, so allow slack).
    try testing.expect(replies > polls * 90 / 100);
    try testing.expectEqual(f.opts.inflight_capacity, f.free_count);
    // The signals really moved the process image.
    var moved: usize = 0;
    for (0..n_signals) |i| {
        if (storage[i * regs_per_node] != 0) moved += 1;
    }
    try testing.expect(moved > n_signals / 2);
}

// ── live: a real third-party master drives a simulated node ─────────────────
//
// Set the endpoint variable and point a real master at it. Without it these
// print SKIPPED and pass.

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

const Endpoint = struct { host: []const u8, port: u16 };

fn splitEndpoint(s: []const u8) ?Endpoint {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;
    return .{ .host = s[0..colon], .port = port };
}

/// Every live test below follows the same shape: one binding through
/// `serveTcpMulti` (one global clock across every session, unlike `serveTcp`,
/// whose per-session clock restarts at each accept), a `trouble` fault
/// scheduled at a fixed simulated instant, and the master on the other side
/// polling across that instant so it observes the device degrade under it.
const live_run_ms: u64 = 60_000;
const live_trouble_at: Time = 15_000;

fn liveBindings(node_id: NodeId, ep: Endpoint, out: *[1]Binding) ![]const Binding {
    out[0] = .{
        .node = node_id,
        .address = try std.Io.net.IpAddress.parse(ep.host, ep.port),
    };
    return out;
}

/// Is the caller running the **live lane**? `FLEETSIM_EXPECT_LIVE=1` says "a
/// real third-party master is standing by; a live test that does not run is a
/// failure, not a skip".
///
/// This exists because the default run's summary line — "59 pass, 8 skip" —
/// is byte-identical whether the live lane is correctly wired or has silently
/// regressed to zero third-party interop. `error.SkipZigTest` at least shows
/// on the summary line (unlike a bare `return`), but nothing *fails*, so the
/// module's only external anchor can rot indefinitely. Under this flag every
/// gate below turns loud.
fn expectLive() bool {
    const v = envVar("FLEETSIM_EXPECT_LIVE") orelse return false;
    return v.len > 0 and !std.mem.eql(u8, v, "0");
}

/// The endpoint gate every live test opens with. Returns `error.SkipZigTest`
/// normally, `error.LiveTestDidNotRun` in the live lane.
fn liveGate(label: []const u8, var_name: []const u8) anyerror!void {
    if (expectLive()) {
        std.debug.print(
            "FLEETSIM_EXPECT_LIVE is set but {s} is unset: {s} did NOT run\n",
            .{ var_name, label },
        );
        return error.LiveTestDidNotRun;
    }
    if (verboseSkip())
        std.debug.print("SKIPPED: {s} (set {s}=host:port)\n", .{ label, var_name });
    return error.SkipZigTest;
}

fn liveSkip(name: []const u8, e: anyerror) anyerror {
    switch (e) {
        error.BindFailed, error.NoPeer => {
            if (expectLive()) {
                std.debug.print("FLEETSIM_EXPECT_LIVE is set but {s} got no peer\n", .{name});
                return error.LiveTestDidNotRun;
            }
            if (verboseSkip()) std.debug.print("SKIPPED: {s} (no listener/peer)\n", .{name});
            return error.SkipZigTest;
        },
        else => return e,
    }
}

test "live: a real DNP3 master drives a simulated outstation, and sees IIN1.6" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_DNP3_LISTEN") orelse
        return liveGate("live fleetsim DNP3", "FLEETSIM_DNP3_LISTEN");
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(testing.allocator, .{
        .seed = 5,
        .max_frame_len = 292, // one DNP3 link frame, at most
        .outbox_bytes = 1 << 16,
    });
    defer f.deinit();

    // The monitored fixture, then the control-direction verdict channel. See
    // `dnp3_verdict`: analog output points 0..10 are the g41v1 slots the master
    // writes its marks into, point 11 is bounded so a big write is *refused*,
    // and binary outputs 0 and 1 are the two g12v1 control-relay bits.
    //
    // Deliberately more than one measured TYPE — three g30v1 signed integers,
    // one g30v5 short float, two g20v1 unsigned counters and eight packed
    // binaries — because a mark that spans two different decodes is one no
    // echo of either operand can produce.
    //
    // Nothing here is animated. The earlier version of this test drove analog
    // input 0 with a ramp, which made every response a function of when the
    // poll landed and would have made the frozen replay in `master_goldens.zig`
    // pin the scheduler instead of the protocol. The dynamic element of this
    // test is the scheduled fault, which is what its name is about.
    var binaries: [8]dnp3.outstation.BinaryInput = undefined;
    for (&binaries, dnp3_verdict.binary_pattern) |*b, v| b.* = .{ .value = v, .class = .class1 };
    var analogs = [_]dnp3.outstation.AnalogInput{
        .{ .value = dnp3_verdict.analog_int[0], .class = .class2 },
        .{ .value = dnp3_verdict.analog_int[1], .class = .class2 },
        .{ .value = dnp3_verdict.analog_int[2], .class = .class2 },
        // g30v5: an IEEE-754 short float, so the master has two different
        // analog codecs to disagree with us about.
        .{ .value = dnp3_verdict.analog_float, .class = .class2, .static_variation = 5 },
    };
    var counters = [_]dnp3.outstation.Counter{
        .{ .value = dnp3_verdict.counters[0], .class = .class3 },
        .{ .value = dnp3_verdict.counters[1], .class = .class3 },
    };
    var binary_outputs = [_]dnp3.outstation.BinaryOutputStatus{.{}} ** dnp3_verdict.binary_output_count;
    var analog_outputs = [_]dnp3.outstation.AnalogOutputStatus{.{}} ** dnp3_verdict.analog_output_count;
    // The last analog output is range-bounded, so the OUTSTATION gets to
    // choose the refusal code for a write outside it. What the master writes
    // back is the code opendnp3 read off the echoed command object — not our
    // arithmetic wearing its name.
    analog_outputs[dnp3_verdict.bounded_slot] = .{ .min = 0, .max = 100 };
    var events: [64]dnp3.outstation.Event = undefined;
    var rx_buf: [2048]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx_fragment: [2048]u8 = undefined;
    var station: Dnp3Node = undefined;
    // opendnp3's `master-demo` uses LocalAddr 1 / RemoteAddr 10 and dials
    // 127.0.0.1:20000; matching it is what makes the live oracle a two-line
    // setup instead of a patched example.
    station.init(
        .{ .address = 10, .master_address = 1, .unsolicited_supported = true },
        .{
            .binary_inputs = &binaries,
            .analog_inputs = &analogs,
            .counters = &counters,
            .binary_outputs = &binary_outputs,
            .analog_outputs = &analog_outputs,
        },
        dnp3.outstation.EventBuffer.init(&events),
        &rx_buf,
        &scratch,
        &tx_fragment,
    );
    const id = try f.addNode(.{ .node = station.node(), .tag = 1, .tick_period_ms = 500 });

    try f.addFault(.{ .at_ms = live_trouble_at, .node = id, .kind = .{ .trouble = .{ .on = true } } });

    var storage: [1]Binding = undefined;
    const bindings = liveBindings(id, ep, &storage) catch return error.SkipZigTest;
    std.debug.print("live fleetsim DNP3 outstation listening on {s} (trouble at t={d} ms)\n", .{ endpoint, live_trouble_at });
    const report = serveTcpMulti(testing.allocator, io, &f, bindings, .{
        .idle_ms = 100,
        .run_ms = live_run_ms,
        .max_peers = 4,
    }) catch |e| return liveSkip("live fleetsim DNP3", e);

    const st = f.stats(id);
    std.debug.print(
        "live fleetsim DNP3: peers={d} peak={d} frames_in={d} frames_out={d} bytes_in={d} bytes_out={d}" ++
            " delivered={d} replied={d} device_trouble={} restart_iin={}\n",
        .{
            report.peers_accepted,                report.peak_concurrent, report.frames_in,
            report.frames_out,                    report.bytes_in,        report.bytes_out,
            st.delivered,                         st.replied,             station.station.device_trouble,
            station.station.iin().device_restart,
        },
    );
    try testing.expect(st.delivered > 0);
    try testing.expect(st.replied > 0);
    // The scheduled fault really landed on the outstation.
    try testing.expect(station.station.device_trouble);
    // …and the part that grades what the master DECODED. See `dnp3_verdict`.
    try dnp3_verdict.expectAllPassed(&binary_outputs, &analog_outputs);
}

/// The contract between `scripts/vm/guests/fleetsim-dnp3-master.cpp` and the
/// live DNP3 test.
///
/// **The write-back channel DNP3 offers.** The control direction: g41 analog
/// output blocks and g12 control relay output blocks. `modules/dnp3`'s
/// outstation implements both (`executeCommand`, `outstation.zig`) and stores
/// what it accepted into `Database.analog_outputs` / `Database.binary_outputs`,
/// so a mark commanded over the wire is readable here after the run. Nothing
/// in the outstation was changed to make this lane work — the two write types
/// this needs were already there.
///
/// **Why these marks and not an echo.** An echo is the exact inverse of the
/// read, so a codec wrong in *both* directions round-trips clean and the fault
/// hides inside it. So: `binary_bitmap` is packed from eight separate decodes;
/// `analog_sum` is a sum over three; `counter_minus_analog` is a difference
/// across two different type decodes (g20 unsigned counter minus g30 signed
/// analog), which no echo of either operand can produce; `float_minus_analog`
/// leaves the float domain entirely (a g30v5 short float scaled x100) and is
/// then differenced against a g30v1 integer decode; `poll_checksum` folds every
/// point of the integrity poll together with the DNP3 *group* opendnp3's own
/// dispatch chose for it, so a superset, a missing header or right-values-under
/// -the-wrong-type all fail it; `out_of_range` and `not_supported` are two
/// different refusals the OUTSTATION chose and opendnp3 named, so collapsing
/// "no such point" into "value out of range" is caught; and `iin_mask` is read
/// off the application header rather than the object data, a channel no point
/// value can reach.
const dnp3_verdict = struct {
    const binary_pattern = [8]bool{ true, false, true, true, false, true, false, true };
    const analog_int = [3]f64{ 12345, -6789, 1000 };
    const analog_float: f64 = 21.5;
    const counters = [2]u32{ 100_000, 777 };

    const binary_output_count = 4;
    const analog_output_count = 12;
    /// The range-bounded analog output. Also the LAST one, so it is still part
    /// of the integrity poll and therefore of `poll_checksum`.
    const bounded_slot = analog_output_count - 1;

    /// Verdict slots, in the order the master writes them.
    const slot_magic = 0;
    const slot_checks = 1;
    const slot_failures = 2;
    const slot_bitmap = 3;
    const slot_analog_sum = 4;
    const slot_counter_minus_analog = 5;
    const slot_float_minus_analog = 6;
    const slot_poll_checksum = 7;
    const slot_out_of_range = 8;
    const slot_not_supported = 9;
    const slot_iin_mask = 10;

    /// Control relay output blocks.
    const bo_pass = 0;
    const bo_trouble_seen = 1;

    const magic: i32 = 53619; // 0xD173
    /// Prime; the running sum stays far inside an i32.
    const checksum_mod: i64 = 30011;
    /// Every `check(...)` in the master, counted where the master counts them:
    /// after the two refusals and before the marks are written, so the verdict
    /// writes do not count themselves.
    const graded_checks: i32 = 20;

    /// IEEE 1815 §A "Command status" codes, as opendnp3's `CommandStatus`
    /// enumerates them. Not our numbering: the master writes back
    /// `static_cast<int32_t>` of what its own parser produced.
    const out_of_range_code: i32 = 12;
    const not_supported_code: i32 = 4;

    /// bit0 IIN1.7 seen at startup · bit1 IIN1.6 clear before the fault ·
    /// bit2 IIN1.6 set after it.
    const iin_mask_all: i32 = 0b111;

    fn bitmap() i32 {
        var m: i32 = 0;
        for (binary_pattern, 0..) |v, i| {
            if (v) m |= @as(i32, 1) << @intCast(i);
        }
        return m;
    }

    fn analogSum() i32 {
        var s: f64 = 0;
        for (analog_int) |v| s += v;
        return @intFromFloat(s);
    }

    fn floatX100() i32 {
        return @intFromFloat(@round(analog_float * 100));
    }

    fn counterMinusAnalog() i32 {
        return @as(i32, @intCast(counters[0])) - @as(i32, @intFromFloat(analog_int[0]));
    }

    fn floatMinusAnalog() i32 {
        return floatX100() - @as(i32, @intFromFloat(analog_int[1]));
    }

    /// Recomputed from the fixture, exactly as the master computes it from what
    /// it decoded: `sum(index * 7 + group)` over every point of the integrity
    /// response, mod a prime. The group is the one opendnp3 chose by handing
    /// the values to a particular typed `ISOEHandler::Process` overload.
    fn pollChecksum() i32 {
        const kinds = [_]struct { n: usize, group: i64 }{
            .{ .n = binary_pattern.len, .group = 1 },
            .{ .n = analog_int.len + 1, .group = 30 },
            .{ .n = counters.len, .group = 20 },
            .{ .n = binary_output_count, .group = 10 },
            .{ .n = analog_output_count, .group = 40 },
        };
        var sum: i64 = 0;
        for (kinds) |k| {
            for (0..k.n) |i| sum += @as(i64, @intCast(i)) * 7 + k.group;
        }
        return @intCast(@rem(sum, checksum_mod));
    }

    fn mark(analog_outputs: []const dnp3.outstation.AnalogOutputStatus, i: usize) i32 {
        return @intFromFloat(analog_outputs[i].value);
    }

    fn expectAllPassed(
        binary_outputs: []const dnp3.outstation.BinaryOutputStatus,
        analog_outputs: []const dnp3.outstation.AnalogOutputStatus,
    ) !void {
        const got_magic = mark(analog_outputs, slot_magic);
        if (got_magic != magic) {
            std.debug.print(
                "live fleetsim DNP3: no verdict block (analog output {d}={d}, want {d}) — the" ++
                    " master never commanded its marks, so nothing here graded the outstation\n",
                .{ slot_magic, got_magic, magic },
            );
            return error.NoMasterVerdict;
        }
        std.debug.print(
            "live fleetsim DNP3 verdict: checks={d} failures={d} bitmap=0b{b} analog_sum={d}" ++
                " counter_minus_analog={d} float_minus_analog={d} poll_checksum={d}" ++
                " out_of_range={d} not_supported={d} iin_mask=0b{b} trouble_seen={} pass={}\n",
            .{
                mark(analog_outputs, slot_checks),
                mark(analog_outputs, slot_failures),
                @as(u32, @bitCast(mark(analog_outputs, slot_bitmap))),
                mark(analog_outputs, slot_analog_sum),
                mark(analog_outputs, slot_counter_minus_analog),
                mark(analog_outputs, slot_float_minus_analog),
                mark(analog_outputs, slot_poll_checksum),
                mark(analog_outputs, slot_out_of_range),
                mark(analog_outputs, slot_not_supported),
                @as(u32, @bitCast(mark(analog_outputs, slot_iin_mask))),
                binary_outputs[bo_trouble_seen].value,
                binary_outputs[bo_pass].value,
            },
        );
        try testing.expectEqual(graded_checks, mark(analog_outputs, slot_checks));
        try testing.expectEqual(@as(i32, 0), mark(analog_outputs, slot_failures));
        try testing.expectEqual(bitmap(), mark(analog_outputs, slot_bitmap));
        try testing.expectEqual(analogSum(), mark(analog_outputs, slot_analog_sum));
        try testing.expectEqual(counterMinusAnalog(), mark(analog_outputs, slot_counter_minus_analog));
        try testing.expectEqual(floatMinusAnalog(), mark(analog_outputs, slot_float_minus_analog));
        try testing.expectEqual(pollChecksum(), mark(analog_outputs, slot_poll_checksum));
        try testing.expectEqual(out_of_range_code, mark(analog_outputs, slot_out_of_range));
        try testing.expectEqual(not_supported_code, mark(analog_outputs, slot_not_supported));
        try testing.expectEqual(iin_mask_all, mark(analog_outputs, slot_iin_mask));
        // The bounded slot must still be untouched: its refusal is a mark in
        // itself, and a device that accepted 999999 there would show up here.
        try testing.expectEqual(@as(f64, 0), analog_outputs[bounded_slot].value);
        try testing.expect(binary_outputs[bo_trouble_seen].value);
        // Commanded last and commanded either way: `false` is a real master
        // saying, over the wire, that it was here and is not satisfied.
        try testing.expect(binary_outputs[bo_pass].value);
    }
};

test "live: a real IEC 104 master drives a simulated outstation, and sees iv quality" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_IEC104_LISTEN") orelse
        return liveGate("live fleetsim IEC 104", "FLEETSIM_IEC104_LISTEN");
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(testing.allocator, .{ .seed = 6, .max_frame_len = 512, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    // The monitored fixture, then the control-direction verdict channel. See
    // `iec104_verdict`: IOA 900..909 are `C_SE_NB_1` set-point commands the
    // master writes its marks into, and 910 is the `C_SC_NA_1` pass bit.
    // Deliberately more than one measured TYPE — a single short float grades
    // one codec, and mark 905 is a difference across two of them.
    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 102, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = false } } },
        .{ .ioa = 103, .type_id = .m_dp_na_1, .element = .{ .diq = .{ .state = .on } } },
        .{ .ioa = 201, .type_id = .m_me_nc_1, .element = .{
            .short_float = .{ .value = iec104_verdict.float_value, .quality = .{} },
        } },
        .{ .ioa = 202, .type_id = .m_me_nb_1, .element = .{
            .scaled = .{ .value = iec104_verdict.scaled_value, .quality = .{} },
        } },
        .{ .ioa = 301, .type_id = .m_it_na_1, .element = .{ .counter = .{
            .counter = iec104_verdict.counter_value,
            .sequence = iec104_verdict.counter_sequence,
        } } },
    } ++ iec104_verdict.commandPoints();
    var frame_buf: [512]u8 = undefined;
    var queue_buf: [16384]u8 = undefined;
    var rtu: Iec104Node = undefined;
    try rtu.init(.{ .common_address = iec104_verdict.common_address }, &points, &frame_buf, &queue_buf, .{});
    const id = try f.addNode(.{ .node = rtu.node(), .tag = 2, .tick_period_ms = 500 });

    try f.addFault(.{ .at_ms = live_trouble_at, .node = id, .kind = .{ .trouble = .{ .on = true } } });

    var storage: [1]Binding = undefined;
    const bindings = liveBindings(id, ep, &storage) catch return error.SkipZigTest;
    std.debug.print("live fleetsim IEC 104 outstation listening on {s} (trouble at t={d} ms)\n", .{ endpoint, live_trouble_at });
    const report = serveTcpMulti(testing.allocator, io, &f, bindings, .{
        .idle_ms = 100,
        .run_ms = live_run_ms,
        .max_peers = 4,
    }) catch |e| return liveSkip("live fleetsim IEC 104", e);

    const st = f.stats(id);
    std.debug.print(
        "live fleetsim IEC 104: peers={d} frames_in={d} frames_out={d} delivered={d} replied={d}" ++
            " started={} iv101={} iv201={}\n",
        .{
            report.peers_accepted,            report.frames_in,
            report.frames_out,                st.delivered,
            st.replied,                       rtu.server.isStarted(),
            points[0].element.siq.quality.iv, points[3].element.short_float.quality.iv,
        },
    );
    try testing.expect(st.delivered > 0);
    try testing.expect(st.replied > 0);
    try testing.expect(points[3].element.short_float.quality.iv);
    // …and the part that grades what the master DECODED. See `iec104_verdict`.
    try iec104_verdict.expectAllPassed(&points);
}

/// The contract between `scripts/vm/guests/fleetsim-iec104-master.py` and the
/// live IEC 104 test.
///
/// **The write-back channel IEC 104 offers.** Commands in the control
/// direction. Ten `C_SE_NB_1` set-point points at IOA 900..909 carry the marks
/// and a `C_SC_NA_1` at 910 carries the pass bit, sent last and sent either
/// way. The outstation stores a commanded value into the point (`onCommand`:
/// `p.element = o.element`), so the marks are readable here after the run.
///
/// **Why these marks and not an echo.** The measured value on the wire is an
/// IEEE-754 short float; commanding it back as a short float is the exact
/// inverse of the read, so an outstation whose float codec was wrong in both
/// directions would round-trip cleanly. Mark 904 leaves the float domain
/// (scaled to a tenth-integer); mark 905 is a *difference across two different
/// type decodes* — the SVA of `M_ME_NB_1` minus that scaled float — which no
/// echo of either operand can produce; mark 906 checksums the whole
/// interrogation SET (which IOAs, under which type ids), so a device reporting
/// a superset or the right values under the wrong types fails it; marks 907
/// and 908 are causes the outstation itself chose for two *different* errors,
/// as c104 itself named them, so collapsing "no such IOA" into "not my common
/// address" is caught.
const iec104_verdict = struct {
    const common_address: u16 = 47;
    const foreign_ca: u16 = 99;

    const float_value: f32 = 21.5;
    const scaled_value: i16 = -12345;
    const counter_value: i32 = 1_234_567;
    const counter_sequence: u5 = 5;

    const base_ioa: u32 = 900;
    const slots = 10;
    const pass_ioa: u32 = 910;
    /// Prime, and small enough that the running sum stays inside an `i16`.
    const checksum_mod: i32 = 30011;

    const magic: i16 = 26104;
    /// One `open_connection` record, two interrogations, the two named
    /// refusals, and the post-fault interrogation. The eleven verdict commands
    /// are appended *after* this count is taken, so it does not count itself.
    const graded_checks: i16 = 6;
    /// §7.2.3 cause 47, "unknown information object address".
    const unknown_ioa_cause: i16 = 47;
    /// §7.2.3 cause 46, "unknown common address of ASDU".
    const unknown_ca_cause: i16 = 46;

    /// The six monitored fixture points, in the order the master bits them.
    const graded_ioas = [_]u32{ 101, 102, 103, 201, 202, 301 };
    /// Every fixture point decoded correctly, plus the "reported set is
    /// exactly these six" bit.
    const observed_all: i16 = (1 << (graded_ioas.len + 1)) - 1;
    /// `trouble_on` sets `iv` on every element that *has* a quality octet.
    /// `M_IT_NA_1` carries its IV inside the BCR instead of a QDS, so the
    /// counter is deliberately not in this mask — see `Iec104.setQuality`.
    const invalid_after_fault: i16 = (1 << (graded_ioas.len - 1)) - 1;

    fn commandPoints() [slots + 1]iec104.Point {
        var out: [slots + 1]iec104.Point = undefined;
        for (0..slots) |i| {
            out[i] = .{
                .ioa = base_ioa + @as(u32, @intCast(i)),
                .type_id = .c_se_nb_1,
                .element = .{ .setpoint_scaled = .{ .value = 0, .qos = .{} } },
            };
        }
        out[slots] = .{ .ioa = pass_ioa, .type_id = .c_sc_na_1, .element = .{ .sco = .{} } };
        return out;
    }

    /// Recomputed from the fixture, exactly as the master computes it from what
    /// it decoded: `sum(ioa * 7 + type_id)` over the reported set, mod a prime.
    fn giChecksum(points: []const iec104.Point) i16 {
        var sum: i32 = 0;
        for (points) |p| {
            if (!p.type_id.isMonitoring()) continue;
            sum = @rem(sum + @as(i32, @intCast(p.ioa)) * 7 + @intFromEnum(p.type_id), checksum_mod);
        }
        return @intCast(sum);
    }

    fn measuredX10() i16 {
        return @intFromFloat(@round(float_value * 10));
    }

    fn mark(points: []const iec104.Point, i: usize) ?i16 {
        for (points) |p| {
            if (p.ioa != base_ioa + i) continue;
            return switch (p.element) {
                .setpoint_scaled => |v| v.value,
                else => null,
            };
        }
        return null;
    }

    fn passBit(points: []const iec104.Point) ?bool {
        for (points) |p| {
            if (p.ioa != pass_ioa) continue;
            return switch (p.element) {
                .sco => |v| v.on,
                else => null,
            };
        }
        return null;
    }

    fn expectAllPassed(points: []const iec104.Point) !void {
        const got_magic = mark(points, 0) orelse {
            std.debug.print(
                "live fleetsim IEC 104: IOA {d} is not a scaled set-point — the point" ++
                    " database is wrong\n",
                .{base_ioa},
            );
            return error.NoMasterVerdict;
        };
        if (got_magic != magic) {
            std.debug.print(
                "live fleetsim IEC 104: no verdict block (IOA {d}={d}, want {d}) — the master" ++
                    " never commanded its marks, so nothing here graded the outstation\n",
                .{ base_ioa, got_magic, magic },
            );
            return error.NoMasterVerdict;
        }
        std.debug.print(
            "live fleetsim IEC 104 verdict: checks={?d} failures={?d} observed=0b{b}" ++
                " measured_x10={?d} scaled_minus_measured={?d} gi_checksum={?d}" ++
                " unknown_ioa={?d} unknown_ca={?d} iv_mask=0b{b} pass={?}\n",
            .{
                mark(points, 1),                              mark(points, 2),
                @as(u16, @bitCast(mark(points, 3) orelse 0)), mark(points, 4),
                mark(points, 5),                              mark(points, 6),
                mark(points, 7),                              mark(points, 8),
                @as(u16, @bitCast(mark(points, 9) orelse 0)), passBit(points),
            },
        );
        try testing.expectEqual(@as(?i16, graded_checks), mark(points, 1));
        try testing.expectEqual(@as(?i16, 0), mark(points, 2));
        try testing.expectEqual(@as(?i16, observed_all), mark(points, 3));
        try testing.expectEqual(@as(?i16, measuredX10()), mark(points, 4));
        try testing.expectEqual(@as(?i16, scaled_value - measuredX10()), mark(points, 5));
        try testing.expectEqual(@as(?i16, giChecksum(points)), mark(points, 6));
        try testing.expectEqual(@as(?i16, unknown_ioa_cause), mark(points, 7));
        try testing.expectEqual(@as(?i16, unknown_ca_cause), mark(points, 8));
        try testing.expectEqual(@as(?i16, invalid_after_fault), mark(points, 9));
        // Commanded last and commanded either way: `false` is a real master
        // saying, over the wire, that it was here and is not satisfied.
        try testing.expectEqual(@as(?bool, true), passBit(points));
    }
};

test "live: a real S7 client drives a simulated CPU, and sees it go to STOP" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_S7_LISTEN") orelse
        return liveGate("live fleetsim S7comm", "FLEETSIM_S7_LISTEN");
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(testing.allocator, .{ .seed = 7, .max_frame_len = 2048, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    var db1 = [_]u8{0} ** 64;
    for (&db1, 0..) |*b, i| b.* = @intCast(i);
    // DB2 is the verdict channel — see `s7_verdict`. Sized for its ten
    // big-endian u32 marks and nothing else, so a client that wrote past the
    // block is refused rather than quietly scribbling into a neighbour.
    var db2 = [_]u8{0} ** (4 * s7_verdict.slots);
    // DB3 is a fixed typed record the client decodes with its OWN accessors:
    // a REAL, an INT and a DINT, all big-endian per the S7 process image. It
    // exists because DB1 is bytes — a byte sum grades framing but not typed
    // decoding, and a sine drives DB1.DBD8 so DB1 cannot be summed whole.
    var db3 = [_]u8{0} ** 16;
    std.mem.writeInt(u32, db3[0..4], @bitCast(s7_verdict.real_value), .big);
    std.mem.writeInt(i16, db3[4..6], s7_verdict.int_value, .big);
    std.mem.writeInt(i32, db3[6..10], s7_verdict.dint_value, .big);
    const areas = [_]s7comm.AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = &db1 },
        .{ .area = .db, .db_number = 2, .bytes = &db2 },
        .{ .area = .db, .db_number = 3, .bytes = &db3 },
    };
    var plc = S7Node.init(.{}, &areas);
    const id = try f.addNode(.{ .node = plc.node(), .tag = 3 });

    // A sine drives DB1.DBD8 as a big-endian REAL, so a client watching that
    // address sees the process image move while it polls.
    var s_word = FloatBytes{ .bytes = db1[8..12], .offset = 0, .endian = .big };
    const sinks = [_]Sink{s_word.sink()};
    var sig = Signal{
        .driver = .{ .sine = .{ .mean = 500, .amplitude = 400, .period_ms = 5000 } },
        .sinks = &sinks,
        .period_ms = 250,
    };
    try f.addSignal(&sig);

    try f.addFault(.{ .at_ms = live_trouble_at, .node = id, .kind = .{ .trouble = .{ .on = true } } });

    var storage: [1]Binding = undefined;
    const bindings = liveBindings(id, ep, &storage) catch return error.SkipZigTest;
    std.debug.print("live fleetsim S7 CPU listening on {s} (STOP at t={d} ms)\n", .{ endpoint, live_trouble_at });
    const report = serveTcpMulti(testing.allocator, io, &f, bindings, .{
        .idle_ms = 100,
        .run_ms = live_run_ms,
        .max_peers = 4,
    }) catch |e| return liveSkip("live fleetsim S7comm", e);

    const st = f.stats(id);
    std.debug.print(
        "live fleetsim S7comm: peers={d} frames_in={d} frames_out={d} delivered={d} replied={d}" ++
            " connected={} pdu={d} cpu_status={s}\n",
        .{
            report.peers_accepted,    report.frames_in,
            report.frames_out,        st.delivered,
            st.replied,               plc.responder.connected,
            plc.responder.pdu_length, @tagName(plc.responder.config.cpu_status),
        },
    );
    try testing.expect(st.delivered > 0);
    try testing.expect(st.replied > 0);
    try testing.expectEqual(s7comm.CpuStatus.stop, plc.responder.config.cpu_status);
    // …and the part that grades what the client DECODED. See `s7_verdict`.
    try s7_verdict.expectAllPassed(&db2, plc.responder.pdu_length);
}

/// The contract between `scripts/vm/guests/fleetsim-s7-master.py` and the live
/// S7comm test.
///
/// **The write-back channel S7 offers.** A DB write. DB2 exists for nothing
/// else: the client commands ten big-endian `u32` marks into it, the last of
/// them in a separate write issued unconditionally.
///
/// **Why these marks and not an echo.** A byte-range sum over DB1 grades the
/// read's framing and offset without echoing anything; a REAL scaled to a
/// tenth-integer and a `DINT - INT` difference grade typed big-endian decoding
/// (and the difference cannot be produced by echoing either operand); the two
/// S7 return codes grade that the device distinguishes "no such block" from
/// "address out of range" — a device that collapsed them into one answer would
/// still satisfy any single-error test.
const s7_verdict = struct {
    const slots = 10;

    /// DB3's typed record, kept here so the expectations are derived once.
    const real_value: f32 = 21.5;
    const int_value: i16 = -1234;
    const dint_value: i32 = 100_000;
    /// The DB1 window the client sums. Deliberately starts at 16: a sine
    /// drives DB1.DBD8, so bytes 8..11 are not freezable.
    const db1_from = 16;
    const db1_len = 32;

    const magic: u32 = 0x0000_F157;
    /// Includes the recorded COTP/setup-communication exchange.
    const graded_checks: u32 = 8;
    /// S7 data-section return codes, as python-snap7's own `S7_RETURN_CODES`
    /// table names them: `0x0A Object does not exist` for a DB that is not
    /// bound, `0x05 Invalid address` for a read that runs past one that is.
    const no_such_block: u32 = 0x0A;
    const invalid_address: u32 = 0x05;

    fn db1Sum() u32 {
        var s: u32 = 0;
        for (db1_from..db1_from + db1_len) |i| s += @intCast(i);
        return s;
    }

    fn slot(db: []const u8, i: usize) u32 {
        return std.mem.readInt(u32, db[i * 4 ..][0..4], .big);
    }

    fn expectAllPassed(db2: []const u8, pdu_length: u16) !void {
        if (slot(db2, 0) != magic) {
            std.debug.print(
                "live fleetsim S7comm: no verdict block (DB2.DBD0=0x{X:0>8}, want 0x{X:0>8}) —" ++
                    " the client never wrote its marks, so nothing here graded the device\n",
                .{ slot(db2, 0), magic },
            );
            return error.NoMasterVerdict;
        }
        std.debug.print(
            "live fleetsim S7comm verdict: checks={d} failures={d} db1_sum={d} real_x10={d}" ++
                " dint_minus_int={d} no_such_block={d} invalid_address={d} pdu={d} pass={d}\n",
            .{
                slot(db2, 1), slot(db2, 2), slot(db2, 3), slot(db2, 4),
                slot(db2, 5), slot(db2, 6), slot(db2, 7), slot(db2, 8),
                slot(db2, 9),
            },
        );
        try testing.expectEqual(graded_checks, slot(db2, 1));
        try testing.expectEqual(@as(u32, 0), slot(db2, 2));
        try testing.expectEqual(db1Sum(), slot(db2, 3));
        try testing.expectEqual(@as(u32, @intFromFloat(@round(real_value * 10))), slot(db2, 4));
        try testing.expectEqual(
            @as(u32, @intCast(dint_value - @as(i32, int_value))),
            slot(db2, 5),
        );
        try testing.expectEqual(no_such_block, slot(db2, 6));
        try testing.expectEqual(invalid_address, slot(db2, 7));
        // The PDU length is the DEVICE's choice, learned by the client during
        // the S7 setup-communication negotiation — so this grades the
        // negotiation, not a data read.
        try testing.expectEqual(@as(u32, pdu_length), slot(db2, 8));
        // Written last and written either way: 0 is a real client saying, over
        // the wire, that it was here and is not satisfied.
        try testing.expectEqual(@as(u32, 1), slot(db2, 9));
    }
};

test "live: a real OPC UA client drives a simulated server, and sees BadDeviceFailure" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_OPCUA_LISTEN") orelse
        return liveGate("live fleetsim OPC UA", "FLEETSIM_OPCUA_LISTEN");
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The endpoint URL a client is told to reconnect to must be the one it
    // dialled, or it will chase an address nothing is listening on.
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "opc.tcp://{s}:{d}", .{ ep.host, ep.port });

    var fx: OpcuaFixture = undefined;
    try fx.init(testing.allocator, url);
    defer fx.deinit();

    var f = try Fleet.init(testing.allocator, .{
        .seed = 8,
        .max_frame_len = 64 * 1024,
        .inflight_capacity = 64,
        .outbox_bytes = 1 << 20,
    });
    defer f.deinit();
    const id = try f.addNode(.{ .node = fx.node.node(), .tag = 4 });

    try f.addFault(.{ .at_ms = live_trouble_at, .node = id, .kind = .{ .trouble = .{ .on = true } } });

    var storage: [1]Binding = undefined;
    const bindings = liveBindings(id, ep, &storage) catch return error.SkipZigTest;
    std.debug.print("live fleetsim OPC UA server listening on {s} ({s}, trouble at t={d} ms)\n", .{ endpoint, url, live_trouble_at });
    const report = serveTcpMulti(testing.allocator, io, &f, bindings, .{
        .idle_ms = 100,
        .run_ms = live_run_ms,
        .read_buf = 65536,
        .max_peers = 4,
    }) catch |e| return liveSkip("live fleetsim OPC UA", e);

    const st = f.stats(id);
    std.debug.print(
        "live fleetsim OPC UA: peers={d} peak={d} frames_in={d} frames_out={d} bytes_in={d}" ++
            " bytes_out={d} delivered={d} replied={d} sessions={d} measurement_status=0x{X:0>8}\n",
        .{
            report.peers_accepted, report.peak_concurrent,
            report.frames_in,      report.frames_out,
            report.bytes_in,       report.bytes_out,
            st.delivered,          st.replied,
            fx.srv.sessionCount(), fx.measurementStatus() orelse 0,
        },
    );
    try testing.expect(st.delivered > 0);
    try testing.expect(st.replied > 0);
    try testing.expectEqual(
        @as(?opcua.encoding.StatusCode, OpcuaNode.status_bad_device_failure),
        fx.measurementStatus(),
    );
    // …and the part that grades what the client DECODED. See `opcua_verdict`.
    try opcua_verdict.expectAllPassed(&fx);
}

/// The contract between `scripts/vm/guests/fleetsim-opcua-master.py` and the
/// live OPC UA test.
///
/// **The write-back channel OPC UA offers.** The `Write` service on a Variable
/// whose `AccessLevel` includes `CurrentWrite`. The address space therefore
/// carries eight writable `Int32` nodes and one writable `Boolean`, all under
/// string NodeIds in namespace 1 — so the client has to encode the identifier
/// as well as address the node.
///
/// **Why these marks and not an echo.** This one matters more here than
/// anywhere else in this module: an Int32 read followed by an Int32 write is
/// *exactly* the shape that a server whose integer codec is wrong in both
/// directions round-trips cleanly. Every numeric mark is therefore a
/// combination — the Int32 measurement plus the scaled Double setpoint, a
/// checksum over a decoded String, the numeric `StatusCode` the client named
/// for an unknown node, the DataType and AccessLevel attributes folded into
/// one number — so a symmetric codec fault moves the mark instead of
/// cancelling inside it.
const opcua_verdict = struct {
    const slots = 8;
    const slot_ids = [slots][]const u8{
        "verdict.0", "verdict.1", "verdict.2", "verdict.3",
        "verdict.4", "verdict.5", "verdict.6", "verdict.7",
    };

    /// The fixture, kept here so the expectations are derived once.
    const measurement_value: i32 = 42;
    const setpoint: f64 = 21.5;
    const label = "zig-fleetsim";
    const ns_uri = "urn:zig-libs:fleetsim";

    const magic: i32 = 0x0000_F10C;
    /// Includes the recorded session bring-up.
    const graded_checks: i32 = 7;
    /// OPC 10000-4 Table 178 `Bad_NodeIdUnknown` = 0x8034_0000, which is what
    /// this server answers for a node it does not have and what asyncua
    /// *named* it. Stored as the two's-complement `Int32` an OPC UA client
    /// writes when it puts a StatusCode into an Int32 node.
    const bad_node_id_unknown: i32 = @bitCast(@as(u32, 0x8034_0000));
    /// `Int32`'s numeric NodeId in namespace 0, times 100, plus the
    /// measurement's AccessLevel (`CurrentRead | CurrentWrite` = 3). One mark
    /// over two attributes, so neither can be right by accident.
    const datatype_and_access: i32 = 6 * 100 + 3;

    fn checksum(s: []const u8) i32 {
        var t: i32 = 0;
        for (s) |c| t += c;
        return t;
    }

    fn expectAllPassed(fx: *OpcuaFixture) !void {
        const got0 = fx.verdictSlot(0) orelse {
            std.debug.print(
                "live fleetsim OPC UA: verdict.0 is not an Int32 — the address space is wrong\n",
                .{},
            );
            return error.NoMasterVerdict;
        };
        if (got0 != magic) {
            // Printed through `u32` because the slot is a SIGNED Int32 — a
            // client writing a StatusCode into one of these makes negative
            // values ordinary, and `{X}` on a negative signed integer prints a
            // sign, not a word.
            std.debug.print(
                "live fleetsim OPC UA: no verdict block (verdict.0=0x{X:0>8}, want 0x{X:0>8}) —" ++
                    " the client never wrote its marks, so nothing here graded the server\n",
                .{ @as(u32, @bitCast(got0)), @as(u32, @bitCast(magic)) },
            );
            return error.NoMasterVerdict;
        }
        std.debug.print(
            "live fleetsim OPC UA verdict: checks={?d} failures={?d} value_plus_setpoint={?d}" ++
                " label_checksum={?d} bad_node_status=0x{X:0>8} ns_uri_checksum={?d}" ++
                " datatype_access={?d} pass={?}\n",
            .{
                fx.verdictSlot(1),                       fx.verdictSlot(2),
                fx.verdictSlot(3),                       fx.verdictSlot(4),
                @as(u32, @bitCast(fx.verdictSlot(5).?)), fx.verdictSlot(6),
                fx.verdictSlot(7),                       fx.verdictPass(),
            },
        );
        try testing.expectEqual(@as(?i32, graded_checks), fx.verdictSlot(1));
        try testing.expectEqual(@as(?i32, 0), fx.verdictSlot(2));
        try testing.expectEqual(
            @as(?i32, measurement_value + @as(i32, @intFromFloat(@round(setpoint * 10)))),
            fx.verdictSlot(3),
        );
        try testing.expectEqual(@as(?i32, checksum(label)), fx.verdictSlot(4));
        try testing.expectEqual(@as(?i32, bad_node_id_unknown), fx.verdictSlot(5));
        try testing.expectEqual(@as(?i32, checksum(ns_uri)), fx.verdictSlot(6));
        try testing.expectEqual(@as(?i32, datatype_and_access), fx.verdictSlot(7));
        // Written last and written either way: `false` is a real client saying,
        // over the wire, that it was here and is not satisfied.
        try testing.expectEqual(@as(?bool, true), fx.verdictPass());
    }
};

test "live: two real masters, two nodes, one binding thread" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_MULTI_LISTEN") orelse
        return liveGate("live fleetsim multi-peer", "FLEETSIM_MULTI_LISTEN");
    const comma = std.mem.indexOfScalar(u8, endpoint, ',') orelse return error.SkipZigTest;
    const ep_a = splitEndpoint(endpoint[0..comma]) orelse return error.SkipZigTest;
    const port_b = std.fmt.parseInt(u16, endpoint[comma + 1 ..], 10) catch return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(testing.allocator, .{ .seed = 9, .max_frame_len = 512, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    // Node A: Modbus. Node B: IEC 104. Two protocols, two sockets, one thread.
    var holdings = [_]u16{0} ** 16;
    for (&holdings, 0..) |*h, i| h.* = @intCast(1000 + i);
    var slave = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp, .accept_any_unit = true },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const id_a = try f.addNode(.{ .node = slave.node(), .tag = 1 });

    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 201, .type_id = .m_me_nc_1, .element = .{ .short_float = .{ .value = 3.25, .quality = .{} } } },
    };
    var frame_buf: [512]u8 = undefined;
    var queue_buf: [8192]u8 = undefined;
    var rtu: Iec104Node = undefined;
    try rtu.init(.{ .common_address = 47 }, &points, &frame_buf, &queue_buf, .{});
    const id_b = try f.addNode(.{ .node = rtu.node(), .tag = 2, .tick_period_ms = 500 });

    const bindings = [_]Binding{
        .{ .node = id_a, .address = std.Io.net.IpAddress.parse(ep_a.host, ep_a.port) catch return error.SkipZigTest },
        .{ .node = id_b, .address = std.Io.net.IpAddress.parse(ep_a.host, port_b) catch return error.SkipZigTest },
    };

    std.debug.print("live fleetsim multi-peer listening on {s}:{d} (modbus) and {s}:{d} (iec104)\n", .{ ep_a.host, ep_a.port, ep_a.host, port_b });
    const report = serveTcpMulti(testing.allocator, io, &f, &bindings, .{
        .idle_ms = 100,
        .run_ms = live_run_ms,
        .max_peers = 8,
    }) catch |e| return liveSkip("live fleetsim multi-peer", e);

    std.debug.print(
        "live fleetsim multi-peer: peers={d} peak_concurrent={d} refused={d} frames_in={d}" ++
            " frames_out={d} modbus_replied={d} iec104_replied={d}\n",
        .{
            report.peers_accepted, report.peak_concurrent, report.peers_refused,
            report.frames_in,      report.frames_out,      f.stats(id_a).replied,
            f.stats(id_b).replied,
        },
    );
    // The claim under test: both masters were connected at the same time.
    try testing.expect(report.peak_concurrent >= 2);
    try testing.expect(f.stats(id_a).replied > 0);
    try testing.expect(f.stats(id_b).replied > 0);
}

test "live: a real Modbus master drives a simulated slave over the TCP binding" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_TEST_LISTEN") orelse
        return liveGate("live fleetsim Modbus", "FLEETSIM_TEST_LISTEN");
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;

    var f = try Fleet.init(testing.allocator, .{ .seed = 1, .max_frame_len = 300, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    var holdings = [_]u16{0} ** 32;
    var coils = [_]bool{false} ** 32;
    var inputs = [_]u16{ 1000, 2000, 3000, 4000 };
    for (&holdings, 0..) |*h, i| h.* = @intCast(i * 111);
    var slave = ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp, .accept_any_unit = true, .slave_id = "zig-fleetsim" },
        .{
            .holding_registers = .{ .base = 0, .values = &holdings },
            .input_registers = .{ .base = 0, .values = &inputs },
            .coils = .{ .base = 0, .values = &coils },
            .discrete_inputs = .{ .base = 0, .values = &coils },
        },
    );
    const id = try f.addNode(.{ .node = slave.node() });

    // A sine drives holding register 0 while the master polls it.
    var s_reg = ScaledRegister{ .cell = &holdings[0], .scale = 1 };
    const sinks = [_]Sink{s_reg.sink()};
    var sig = Signal{
        .driver = .{ .sine = .{ .mean = 500, .amplitude = 400, .period_ms = 5000 } },
        .sinks = &sinks,
        .period_ms = 250,
    };
    try f.addSignal(&sig);

    std.debug.print("live fleetsim Modbus slave listening on {s}\n", .{endpoint});
    const report = serveTcp(testing.allocator, io, &f, id, addr, .{
        .idle_ms = 200,
        .run_ms = 60_000,
        .max_sessions = 8,
    }) catch |e| switch (e) {
        error.BindFailed => {
            if (expectLive()) return e;
            if (verboseSkip()) std.debug.print("SKIPPED: live fleetsim Modbus (cannot bind {s})\n", .{endpoint});
            return error.SkipZigTest;
        },
        error.NoPeer => {
            if (expectLive()) return e;
            if (verboseSkip()) std.debug.print("SKIPPED: live fleetsim Modbus (no peer connected)\n", .{});
            return error.SkipZigTest;
        },
        else => return e,
    };

    const st = f.stats(id);
    std.debug.print(
        "live fleetsim Modbus: sessions={d} frames_in={d} frames_out={d} bytes_in={d} bytes_out={d}" ++
            " delivered={d} replied={d} signal_fires={d} hr0={d} hr5=0x{X:0>4} coil3={}\n",
        .{ report.sessions, report.frames_in, report.frames_out, report.bytes_in, report.bytes_out, st.delivered, st.replied, sig.fires, holdings[0], holdings[5], coils[3] },
    );
    try testing.expect(st.delivered > 0);
    try testing.expect(st.replied > 0);
    // …and then the part that makes this an anchor rather than a frame
    // counter. See `modbus_verdict` below: everything asserted from here on is
    // a mark the third-party master computed from what IT decoded.
    try modbus_verdict.expectAllPassed(&holdings, &coils);
}

/// The contract between `scripts/vm/guests/fleetsim-modbus-master.py` and the
/// live Modbus test — and the reason that test is worth running.
///
/// **The defect this closes.** The live test used to end at `delivered > 0`
/// and `replied > 0`. Both are liveness: frames arrived, frames left. Measured
/// consequence — with `modules/modbus/src/server.zig`'s register encoder
/// byte-swapped, so that *every value the master read was wrong*, the live test
/// still passed. The run went red only because the master printed a FAIL line
/// and a shell `grep` in `run.sh` missed its OK marker. A third-party master a
/// wrong implementation still satisfies is not an oracle; it is a liveness
/// check wearing an anchor's clothes.
///
/// **The mechanism.** A master that only reads leaves no trace of what it
/// understood. So this one grades itself — it knows the fixture, it compares
/// what pymodbus decoded against it — and then writes its marks back into the
/// device through ordinary Modbus writes. Those marks are device state, which
/// this test can read directly.
///
/// **Why marks and not an echo.** Echoing the decoded registers back would be
/// the inverse of the read, so a device that encoded and decoded with the same
/// wrong convention would round-trip cleanly and the mutation would vanish —
/// the "consistent mutation hides from every local test" trap. A *sum* and a
/// *bitmap* are computed in the master's number domain and land on constants
/// derived here from the fixture, so a wrong decode lands on a wrong constant
/// in either direction.
const modbus_verdict = struct {
    /// "A real master was here." Absent ⇒ nothing ever wrote the block, which
    /// is a broken lane, not a broken device — a distinction the old test could
    /// not make at all.
    const magic: u16 = 0xF135;
    /// Operations the master runs before writing the block. Pinned exactly: a
    /// script that died halfway would otherwise report a clean pass over the
    /// prefix it managed.
    const graded_checks: u16 = 10;
    /// 111 + 222 + … + 888 — the fixture's `holding[i] = i*111` for i in 1..8,
    /// as pymodbus decoded them.
    const holding_sum: u16 = 3996;
    /// 1000 + 2000 + 3000 + 4000, as pymodbus decoded the input registers.
    const input_sum: u16 = 10_000;
    /// The eight coils after `write_coil(3, true)`, packed LSB-first the way
    /// pymodbus unpacked them: bit 3 set, nothing else. Grades the bit order
    /// against a third party's unpacking rather than against our own.
    const coil_bitmap: u16 = 0b0000_1000;
    /// MODBUS Application Protocol §7: 0x02 Illegal Data Address, which is what
    /// pymodbus *named* the reply to a read past the end of the bank. Distinct
    /// from the 0x04 Server Device Failure the trouble state uses — the two
    /// must not collapse into one.
    const oob_exception: u16 = 0x02;

    const base = 24; // holding[24..31] is the block; coil[31] is the verdict bit

    fn expectAllPassed(holdings: []const u16, coils: []const bool) !void {
        if (holdings[base] != magic) {
            std.debug.print(
                "live fleetsim Modbus: no verdict block (holding[{d}]=0x{X:0>4}, want 0x{X:0>4}) —" ++
                    " the master never wrote its marks, so nothing here graded the device\n",
                .{ base, holdings[base], magic },
            );
            return error.NoMasterVerdict;
        }
        std.debug.print(
            "live fleetsim Modbus verdict: checks={d} failures={d} exception={d}" ++
                " holding_sum={d} input_sum={d} coil_bitmap=0b{b:0>8} all_passed={}\n",
            .{
                holdings[base + 1], holdings[base + 2], holdings[base + 3],
                holdings[base + 4], holdings[base + 5], holdings[base + 6],
                coils[31],
            },
        );
        try testing.expectEqual(graded_checks, holdings[base + 1]);
        try testing.expectEqual(@as(u16, 0), holdings[base + 2]);
        try testing.expectEqual(oob_exception, holdings[base + 3]);
        try testing.expectEqual(holding_sum, holdings[base + 4]);
        try testing.expectEqual(input_sum, holdings[base + 5]);
        try testing.expectEqual(coil_bitmap, holdings[base + 6]);
        // Written last and written either way: `false` is the master saying it
        // was here and is not satisfied.
        try testing.expect(coils[31]);
    }
};

test "live: a real EtherNet/IP master drives a simulated adapter" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_ENIP_LISTEN") orelse
        return liveGate("live fleetsim EtherNet/IP", "FLEETSIM_ENIP_LISTEN");
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(testing.allocator, .{ .seed = 2, .max_frame_len = 4096, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    var speed = [_]u8{0} ** 4;
    var level = [_]u8{0} ** 4;
    std.mem.writeInt(i32, speed[0..4], 1500, .little);
    // `Counts` is a DINT array with six deliberately unequal elements, and
    // `Setpoint` a fixed REAL. Neither is driven by a signal, so both are
    // freezable — and both exist so the master has something to *sum* and
    // something to *scale*, rather than something to echo. See `enip_verdict`.
    var counts = [_]u8{0} ** (4 * enip_verdict.counts.len);
    for (enip_verdict.counts, 0..) |v, i| {
        std.mem.writeInt(i32, counts[i * 4 ..][0..4], v, .little);
    }
    var setpoint = [_]u8{0} ** 4;
    std.mem.writeInt(u32, setpoint[0..4], @bitCast(enip_verdict.setpoint), .little);
    // The verdict channel: an eight-element DINT array the master writes its
    // marks into, and a separate DINT it writes its pass mark into.
    var verdict = [_]u8{0} ** (4 * enip_verdict.slots);
    var verdict_pass = [_]u8{0} ** 4;
    const tags = [_]enip.TagBinding{
        .{ .name = "Speed", .type = .dint, .bytes = &speed },
        .{ .name = "Level", .type = .real, .bytes = &level },
        .{ .name = "Counts", .type = .dint, .bytes = &counts },
        .{ .name = "Setpoint", .type = .real, .bytes = &setpoint },
        .{ .name = "Verdict", .type = .dint, .bytes = &verdict },
        .{ .name = "VerdictPass", .type = .dint, .bytes = &verdict_pass },
    };
    var dev = EnipNode.init(.{ .product_name = "zig-fleetsim adapter" }, &tags);
    const id = try f.addNode(.{ .node = dev.node() });

    var s_level = FloatBytes{ .bytes = &level, .offset = 0, .endian = .little };
    const sinks = [_]Sink{s_level.sink()};
    var sig = Signal{
        .driver = .{ .ramp = .{ .start = 0, .per_ms = 0.01, .min = 0, .max = 100, .wrap = true } },
        .sinks = &sinks,
        .period_ms = 250,
    };
    try f.addSignal(&sig);

    try f.addFault(.{ .at_ms = live_trouble_at, .node = id, .kind = .{ .trouble = .{ .on = true } } });

    var storage: [1]Binding = undefined;
    const bindings = liveBindings(id, ep, &storage) catch return error.SkipZigTest;
    std.debug.print("live fleetsim EtherNet/IP adapter listening on {s} (fault at t={d} ms)\n", .{ endpoint, live_trouble_at });
    // `serveTcpMulti`, not `serveTcp`: pycomm3 opens a *separate* socket for
    // `list_identity` and another for a connected read, and only the multi
    // binding keeps one clock across all of them (so a scheduled fault lands
    // where the master expects it).
    const report = serveTcpMulti(testing.allocator, io, &f, bindings, .{
        .idle_ms = 100,
        .run_ms = live_run_ms,
        .max_peers = 8,
    }) catch |e| return liveSkip("live fleetsim EtherNet/IP", e);

    std.debug.print(
        "live fleetsim EtherNet/IP: peers={d} peak={d} frames_in={d} frames_out={d} reads={d}" ++
            " writes={d} identity={d} speed={d} identity_status=0x{X:0>4} state={s}\n",
        .{
            report.peers_accepted,           report.peak_concurrent,
            report.frames_in,                report.frames_out,
            dev.adapter.reads,               dev.adapter.writes,
            dev.adapter.identity_requests,   std.mem.readInt(i32, speed[0..4], .little),
            dev.adapter.cfg.identity_status, @tagName(dev.adapter.cfg.state),
        },
    );
    try testing.expect(f.stats(id).replied > 0);
    // The scheduled fault landed: the Identity status word says major fault.
    try testing.expect(dev.adapter.cfg.identity_status != 0x0030);
    // …and the part that grades what the master DECODED. See `enip_verdict`.
    try enip_verdict.expectAllPassed(&verdict, &verdict_pass);
}

/// The contract between `scripts/vm/guests/fleetsim-enip-master.py` and the
/// live EtherNet/IP test — the same shape as `modbus_verdict`, for the same
/// reason: `replied > 0` is liveness, not interop.
///
/// **The write-back channel this protocol offers.** CIP `Write Tag` (0x4D) by
/// symbolic name. The master commands its marks into a `Verdict` DINT[8] and a
/// separate `VerdictPass` DINT, both of which are ordinary tags this adapter
/// serves — so the marks are device state the test reads directly.
///
/// **Why these marks and not an echo.** Every one of them is a number pycomm3
/// computed *from* what it decoded, never the decoded bytes handed back: the
/// sum of a six-element DINT array, the sum of a three-element slice of that
/// same array starting at element 2 (which grades array-element addressing),
/// a REAL scaled to a tenth-integer (which grades float32 decoding without
/// letting a symmetric encoding error cancel), a checksum of the ASCII product
/// name it read out of `ListIdentity`, and the CIP general status *it* named
/// for a tag the device does not have. A device that encoded and decoded with
/// the same wrong convention would round-trip an echo cleanly; it cannot reach
/// these numbers.
const enip_verdict = struct {
    /// The `Counts` DINT array's contents. Deliberately unequal and spread
    /// across byte boundaries so a truncation or a swap moves the sum.
    const counts = [_]i32{ 7, 140, 3300, 41_000, 555, 66 };
    /// The `Setpoint` REAL. 21.5 is exactly representable, so the scaled mark
    /// is exact and a mismatch means a decode fault, not a rounding one.
    const setpoint: f32 = 21.5;
    /// The device's `product_name`, which `ListIdentity` reports and pycomm3
    /// decodes as a SHORT_STRING. Kept here so the checksum below is derived
    /// rather than restated.
    const product_name = "zig-fleetsim adapter";
    /// How many DINTs the `Verdict` tag holds.
    const slots = 8;

    /// "A real master was here." Absent ⇒ nothing wrote the block at all,
    /// which is a broken lane rather than a broken device.
    const magic: i32 = 0x0000_F1E9;
    /// Operations the master grades before writing the block — the session
    /// bring-up counts, because it is recorded too (the frozen corpus has to
    /// replay from the adapter's initial state). Pinned exactly: a script that
    /// died halfway would otherwise report a clean pass over the prefix it
    /// managed.
    const graded_checks: i32 = 7;
    /// CIP Vol 1 §B-1.1 `0x05 Path destination unknown` — what this adapter
    /// answers for a tag it does not serve, and what pycomm3 *named* it.
    const missing_tag_status: i32 = 0x05;

    fn countsSum() i32 {
        var s: i32 = 0;
        for (counts) |v| s += v;
        return s;
    }

    fn countsSliceSum() i32 {
        var s: i32 = 0;
        for (counts[2..5]) |v| s += v;
        return s;
    }

    fn nameChecksum() i32 {
        var s: i32 = 0;
        for (product_name) |c| s += c;
        return s;
    }

    fn slot(bytes: []const u8, i: usize) i32 {
        return std.mem.readInt(i32, bytes[i * 4 ..][0..4], .little);
    }

    fn expectAllPassed(verdict: []const u8, verdict_pass: []const u8) !void {
        if (slot(verdict, 0) != magic) {
            std.debug.print(
                "live fleetsim EtherNet/IP: no verdict block (Verdict[0]=0x{X:0>8}, want 0x{X:0>8}) —" ++
                    " the master never wrote its marks, so nothing here graded the device\n",
                .{ slot(verdict, 0), magic },
            );
            return error.NoMasterVerdict;
        }
        std.debug.print(
            "live fleetsim EtherNet/IP verdict: checks={d} failures={d} counts_sum={d}" ++
                " setpoint_x10={d} name_checksum={d} missing_tag_status={d} slice_sum={d} pass={d}\n",
            .{
                slot(verdict, 1), slot(verdict, 2),      slot(verdict, 3),
                slot(verdict, 4), slot(verdict, 5),      slot(verdict, 6),
                slot(verdict, 7), slot(verdict_pass, 0),
            },
        );
        try testing.expectEqual(graded_checks, slot(verdict, 1));
        try testing.expectEqual(@as(i32, 0), slot(verdict, 2));
        try testing.expectEqual(countsSum(), slot(verdict, 3));
        try testing.expectEqual(@as(i32, @intFromFloat(@round(setpoint * 10))), slot(verdict, 4));
        try testing.expectEqual(nameChecksum(), slot(verdict, 5));
        try testing.expectEqual(missing_tag_status, slot(verdict, 6));
        try testing.expectEqual(countsSliceSum(), slot(verdict, 7));
        // Written in both outcomes: 0 is a real master saying, over the wire,
        // that it was here and is not satisfied.
        try testing.expectEqual(@as(i32, 1), slot(verdict_pass, 0));
    }
};

test "live: a real BACnet client discovers a simulated device over UDP" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_BACNET_LISTEN") orelse
        return liveGate("live fleetsim BACnet", "FLEETSIM_BACNET_LISTEN");
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;

    var f = try Fleet.init(testing.allocator, .{ .seed = 4, .max_frame_len = 1500, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    // Clause 12's fault triple, so `trouble` has something real to move and a
    // client has something real to read.
    //
    // `status_flags` is deliberately NOT all-clear: bit 2 (`overridden`) is set
    // so the bitmap the client unpacks is a number that can be wrong in both
    // directions. An all-zero bit string is decoded identically by a client
    // that reads the bit order backwards, which makes it useless as a mark.
    const healthy_flags = [_]u8{bacnet_verdict.status_flags_byte};
    var ai_props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = bacnet_verdict.ai_name } },
        .{ .id = .present_value, .value = .{ .real = bacnet_verdict.present_value }, .cov_reported = true },
        .{ .id = .units, .value = .{ .enumerated = 62 } },
        .{ .id = .status_flags, .value = .{ .bit_string = .{ .unused_bits = 4, .bytes = &healthy_flags } }, .cov_reported = true },
        .{ .id = .reliability, .value = .{ .enumerated = 0 } },
        .{ .id = .out_of_service, .value = .{ .boolean = false }, .writable = true },
    };
    var dev_props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "zig-fleetsim device" } },
        .{ .id = .vendor_name, .value = .{ .string = "zig-libs" } },
    };
    // The verdict channel: one analog-value object per mark, whose
    // `present_value` is writable, plus a binary-value carrying the pass mark.
    // BACnet has no "write eight numbers at once" service that a plain client
    // reaches for, so the marks are eight objects rather than one array — and
    // a REAL holds every integer below 2^24 exactly, so nothing here rounds.
    var verdict_props: [bacnet_verdict.slots][1]bacnet.Property = undefined;
    var pass_props = [_]bacnet.Property{
        .{ .id = .present_value, .value = .{ .enumerated = 0 }, .writable = true },
    };
    var objects: [bacnet_verdict.slots + 3]bacnet.Object = undefined;
    objects[0] = .{ .id = .{ .type = .analog_input, .instance = 1 }, .properties = &ai_props };
    objects[1] = .{ .id = .{ .type = .device, .instance = 260_001 }, .properties = &dev_props };
    for (0..bacnet_verdict.slots) |i| {
        verdict_props[i] = .{
            .{ .id = .present_value, .value = .{ .real = 0 }, .writable = true },
        };
        objects[2 + i] = .{
            .id = .{ .type = .analog_value, .instance = @intCast(bacnet_verdict.first_instance + i) },
            .properties = &verdict_props[i],
        };
    }
    objects[2 + bacnet_verdict.slots] = .{
        .id = .{ .type = .binary_value, .instance = bacnet_verdict.pass_instance },
        .properties = &pass_props,
    };
    var dev: BacnetNode = undefined;
    dev.init(
        .{ .instance = 260_001, .vendor_id = 999 },
        &objects,
        .{ .ip = .{ 0, 0, 0, 0 }, .port = 47808 },
        .{ .ip = .{ 0, 0, 0, 0 }, .port = 47808 },
    );
    const id = try f.addNode(.{ .node = dev.node(), .tick_period_ms = 500 });

    try f.addFault(.{ .at_ms = live_trouble_at, .node = id, .kind = .{ .trouble = .{ .on = true } } });

    std.debug.print("live fleetsim BACnet device listening on {s} (fault at t={d} ms)\n", .{ endpoint, live_trouble_at });
    const report = serveUdp(testing.allocator, io, &f, id, addr, .{
        .idle_ms = 100,
        .run_ms = live_run_ms,
    }) catch |e| switch (e) {
        error.BindFailed => {
            if (expectLive()) return e;
            if (verboseSkip()) std.debug.print("SKIPPED: live fleetsim BACnet (cannot bind {s})\n", .{endpoint});
            return error.SkipZigTest;
        },
        else => return e,
    };
    const ai = &objects[0];
    std.debug.print(
        "live fleetsim BACnet: datagrams_in={d} datagrams_out={d} delivered={d} replied={d}" ++
            " reliability={d} status_flags=0x{X:0>2} out_of_service={}\n",
        .{
            report.frames_in,
            report.frames_out,
            f.stats(id).delivered,
            f.stats(id).replied,
            ai.find(.reliability).?.value.enumerated,
            ai.find(.status_flags).?.value.bit_string.bytes[0],
            ai.find(.out_of_service).?.value.boolean,
        },
    );
    try testing.expect(report.frames_in > 0);
    // The scheduled fault landed on the object model a client reads.
    try testing.expectEqual(@as(u32, 7), ai.find(.reliability).?.value.enumerated);
    try testing.expect(ai.find(.out_of_service).?.value.boolean);
    // …and the part that grades what the client DECODED. See `bacnet_verdict`.
    try bacnet_verdict.expectAllPassed(objects[2..], &pass_props);
}

/// The contract between `scripts/vm/guests/fleetsim-bacnet-master.py` and the
/// live BACnet test.
///
/// **The write-back channel BACnet offers.** `WriteProperty` (Clause 15.9) on
/// a property whose `writable` flag is set. The device therefore carries eight
/// `analog-value` objects whose `present_value` is writable — one per mark —
/// and a `binary-value` for the pass mark. Eight objects rather than one
/// array property because that is what a stock client writes without being
/// told about array indices, and because a wrong object instance then lands on
/// a wrong slot instead of silently overwriting a neighbour.
///
/// **Why these marks and not an echo.** The present value is scaled to a
/// tenth-integer, the object name becomes a checksum, the status flags become
/// a bitmap the *client* packed from the bits it unpacked, and the device
/// instance is the one the client learned from an `I-Am` rather than the one
/// it was told to ask. Each is a number computed from a decode, so a device
/// that mis-encoded and a client that mis-decoded cannot cancel.
const bacnet_verdict = struct {
    /// `analog-value` instances 1..8 carry the marks; `binary-value` 1 the pass
    /// mark.
    const slots = 8;
    const first_instance = 1;
    const pass_instance = 1;

    /// The fixture, kept here so the expectations below are derived from one
    /// place rather than restated in two.
    const ai_name = "Zone-1-Temp";
    const present_value: f32 = 21.5;
    /// `overridden` (bit 2 of Clause 12's four-bit BACnetStatusFlags), with the
    /// four unused bits zero. A bit string whose only content is zeroes cannot
    /// grade a bit order.
    const status_flags_byte: u8 = 0b0010_0000;
    /// What the client packs from the four flags it unpacked, LSB-first:
    /// in_alarm, fault, overridden, out_of_service.
    const status_flags_bitmap: i64 = 1 << 2;
    const device_instance: i64 = 260_001;
    /// ASHRAE 135 Clause 18 `unknown-property` (error class `property`, code
    /// 32) — what this device answers for a property it does not carry, and
    /// what bacpypes3 *named* it.
    const unknown_property_code: i64 = 32;

    const magic: i64 = 61_882;
    const graded_checks: i64 = 7;

    fn nameChecksum() i64 {
        var s: i64 = 0;
        for (ai_name) |c| s += c;
        return s;
    }

    /// Signed on purpose: the client writes `-1` into a slot whose mark it
    /// could not compute, and a slot read as an unsigned integer would panic
    /// on exactly the case worth seeing.
    fn slot(objs: []const bacnet.Object, i: usize) i64 {
        const v = objs[i].find(.present_value).?.value.real;
        return @intFromFloat(@round(v));
    }

    fn expectAllPassed(verdict_objs: []const bacnet.Object, pass: []const bacnet.Property) !void {
        if (slot(verdict_objs, 0) != magic) {
            std.debug.print(
                "live fleetsim BACnet: no verdict block (analog-value,{d} present_value={d}," ++
                    " want {d}) — the client never wrote its marks, so nothing here graded" ++
                    " the device\n",
                .{ first_instance, slot(verdict_objs, 0), magic },
            );
            return error.NoMasterVerdict;
        }
        std.debug.print(
            "live fleetsim BACnet verdict: checks={d} failures={d} pv_x10={d} name_checksum={d}" ++
                " status_bitmap={d} device_instance={d} unknown_property={d} pass={d}\n",
            .{
                slot(verdict_objs, 1), slot(verdict_objs, 2),
                slot(verdict_objs, 3), slot(verdict_objs, 4),
                slot(verdict_objs, 5), slot(verdict_objs, 6),
                slot(verdict_objs, 7), pass[0].value.enumerated,
            },
        );
        try testing.expectEqual(graded_checks, slot(verdict_objs, 1));
        try testing.expectEqual(@as(i64, 0), slot(verdict_objs, 2));
        try testing.expectEqual(
            @as(i64, @intFromFloat(@round(present_value * 10))),
            slot(verdict_objs, 3),
        );
        try testing.expectEqual(nameChecksum(), slot(verdict_objs, 4));
        try testing.expectEqual(status_flags_bitmap, slot(verdict_objs, 5));
        try testing.expectEqual(device_instance, slot(verdict_objs, 6));
        try testing.expectEqual(unknown_property_code, slot(verdict_objs, 7));
        // Written in both outcomes: `inactive` is a real client saying, over
        // the wire, that it was here and is not satisfied.
        try testing.expectEqual(@as(u32, 1), pass[0].value.enumerated);
    }
};

// ── OPC UA: a whole simulated server, offline and live ──────────────────────

/// Everything an `OpcuaNode` needs behind it: an address space, a server and
/// the two buffers a connection negotiates against. Heavy by OPC UA's nature
/// (see SPEC.md's memory note) — this is why an OPC UA fleet is measured in
/// hundreds of nodes, not thousands.
const OpcuaFixture = struct {
    gpa: std.mem.Allocator,
    store: opcua.nodestore.NodeStore,
    srv: opcua.server.Server = undefined,
    prng: std.Random.DefaultPrng,
    recv_buf: []u8,
    msg_buf: []u8,
    node: OpcuaNode = undefined,
    endpoints: [1]opcua.services.EndpointDescription = undefined,
    start_time: opcua.encoding.DateTime,

    /// `ns=1;s=the.measurement` — the process value a client reads and the one
    /// `trouble` degrades.
    const measurement: opcua.encoding.NodeId =
        .{ .string = .{ .namespace = 1, .id = "the.measurement" } };
    /// A Double and a String beside it, so the verdict marks are not all
    /// derived from one built-in type.
    const setpoint: opcua.encoding.NodeId =
        .{ .string = .{ .namespace = 1, .id = "the.setpoint" } };
    const label: opcua.encoding.NodeId =
        .{ .string = .{ .namespace = 1, .id = "the.label" } };
    const pass_node: opcua.encoding.NodeId =
        .{ .string = .{ .namespace = 1, .id = "verdict.pass" } };
    const ns_uri = "urn:zig-libs:fleetsim";

    /// The DataValue a client reads back for one verdict slot.
    fn verdictSlot(self: *OpcuaFixture, i: usize) ?i32 {
        const nid: opcua.encoding.NodeId =
            .{ .string = .{ .namespace = 1, .id = opcua_verdict.slot_ids[i] } };
        const n = self.store.getNode(nid) orelse return null;
        return switch (n.attributes) {
            .variable => |v| switch (v.value.value orelse return null) {
                .scalar => |sc| switch (sc) {
                    .int32 => |x| x,
                    else => null,
                },
                else => null,
            },
            else => null,
        };
    }

    fn verdictPass(self: *OpcuaFixture) ?bool {
        const n = self.store.getNode(pass_node) orelse return null;
        return switch (n.attributes) {
            .variable => |v| switch (v.value.value orelse return null) {
                .scalar => |sc| switch (sc) {
                    .boolean => |b| b,
                    else => null,
                },
                else => null,
            },
            else => null,
        };
    }

    fn init(self: *OpcuaFixture, gpa: std.mem.Allocator, endpoint_url: []const u8) !void {
        self.* = .{
            .gpa = gpa,
            .store = opcua.nodestore.NodeStore.init(gpa),
            .prng = std.Random.DefaultPrng.init(0xC0FFEE),
            .recv_buf = try gpa.alloc(u8, 64 * 1024),
            .msg_buf = try gpa.alloc(u8, 256 * 1024),
            .start_time = 0,
        };
        try self.store.addStandardNodes(.{ .start_time = self.start_time });
        const ns = try self.store.addNamespace(ns_uri);
        std.debug.assert(ns == 1);
        try self.store.refreshNamespaceArray();
        try self.store.addVariable(.{
            .node_id = measurement,
            .parent_id = opcua.nodestore.n0(opcua.nodestore.id.objects_folder),
            .reference_type_id = opcua.nodestore.n0(opcua.nodestore.id.organizes),
            .browse_name = .{ .namespace_index = 1, .name = "the.measurement" },
            .display_name = .{ .locale = "en", .text = "the measurement" },
            .value = .{ .scalar = .{ .int32 = 42 } },
            .data_type = opcua.nodestore.n0(opcua.nodestore.id.int32),
            .access_level = opcua.nodestore.access_level.read_write,
            .timestamp = self.start_time,
        });

        // Two more typed process values, so a client has something to decode
        // that is NOT an Int32 — a mark built only from Int32 reads could be
        // cancelled by a byte order that is wrong on both the read and the
        // write path. See `opcua_verdict`.
        try self.store.addVariable(.{
            .node_id = setpoint,
            .parent_id = opcua.nodestore.n0(opcua.nodestore.id.objects_folder),
            .reference_type_id = opcua.nodestore.n0(opcua.nodestore.id.organizes),
            .browse_name = .{ .namespace_index = 1, .name = "the.setpoint" },
            .display_name = .{ .locale = "en", .text = "the setpoint" },
            .value = .{ .scalar = .{ .double = opcua_verdict.setpoint } },
            .data_type = opcua.nodestore.n0(opcua.nodestore.id.double),
            .access_level = opcua.nodestore.access_level.current_read,
            .timestamp = self.start_time,
        });
        try self.store.addVariable(.{
            .node_id = label,
            .parent_id = opcua.nodestore.n0(opcua.nodestore.id.objects_folder),
            .reference_type_id = opcua.nodestore.n0(opcua.nodestore.id.organizes),
            .browse_name = .{ .namespace_index = 1, .name = "the.label" },
            .display_name = .{ .locale = "en", .text = "the label" },
            .value = .{ .scalar = .{ .string = opcua_verdict.label } },
            .data_type = opcua.nodestore.n0(opcua.nodestore.id.string),
            .access_level = opcua.nodestore.access_level.current_read,
            .timestamp = self.start_time,
        });

        // The verdict channel: eight writable Int32 nodes and one writable
        // Boolean. `ns=1;s=verdict.N` — a string NodeId, so the client has to
        // encode the identifier as well as address the node.
        for (0..opcua_verdict.slots) |i| {
            try self.store.addVariable(.{
                .node_id = .{ .string = .{ .namespace = 1, .id = opcua_verdict.slot_ids[i] } },
                .parent_id = opcua.nodestore.n0(opcua.nodestore.id.objects_folder),
                .reference_type_id = opcua.nodestore.n0(opcua.nodestore.id.organizes),
                .browse_name = .{ .namespace_index = 1, .name = opcua_verdict.slot_ids[i] },
                .display_name = .{ .locale = "en", .text = opcua_verdict.slot_ids[i] },
                .value = .{ .scalar = .{ .int32 = 0 } },
                .data_type = opcua.nodestore.n0(opcua.nodestore.id.int32),
                .access_level = opcua.nodestore.access_level.read_write,
                .timestamp = self.start_time,
            });
        }
        try self.store.addVariable(.{
            .node_id = pass_node,
            .parent_id = opcua.nodestore.n0(opcua.nodestore.id.objects_folder),
            .reference_type_id = opcua.nodestore.n0(opcua.nodestore.id.organizes),
            .browse_name = .{ .namespace_index = 1, .name = "verdict.pass" },
            .display_name = .{ .locale = "en", .text = "verdict pass" },
            .value = .{ .scalar = .{ .boolean = false } },
            .data_type = opcua.nodestore.n0(opcua.nodestore.id.boolean),
            .access_level = opcua.nodestore.access_level.read_write,
            .timestamp = self.start_time,
        });

        self.endpoints = .{opcua.server.noneEndpoint(endpoint_url, .{
            .application_uri = "urn:zig-libs:fleetsim:server",
            .product_uri = "urn:zig-libs:fleetsim",
            .application_name = .{ .locale = "en", .text = "zig-fleetsim opcua device" },
            .application_type = .server,
            .gateway_server_uri = null,
            .discovery_profile_uri = null,
            .discovery_urls = null,
        })};
        self.srv = opcua.server.Server.init(self.gpa, &self.store, .{
            .application_uri = "urn:zig-libs:fleetsim:server",
            .application_name = .{ .locale = "en", .text = "zig-fleetsim opcua device" },
            .endpoints = &self.endpoints,
        }, self.prng.random());
        try self.node.init(&self.srv, self.recv_buf, self.msg_buf);
        self.node.trouble_nodes = &.{measurement};
    }

    fn deinit(self: *OpcuaFixture) void {
        self.srv.deinit();
        self.store.deinit();
        self.gpa.free(self.recv_buf);
        self.gpa.free(self.msg_buf);
    }

    /// The DataValue a client would read back for the measurement, status and
    /// all — the exact thing `trouble` is supposed to change.
    fn measurementStatus(self: *OpcuaFixture) ?opcua.encoding.StatusCode {
        const n = self.store.getNode(measurement) orelse return null;
        return switch (n.attributes) {
            .variable => |v| v.value.status,
            else => null,
        };
    }
};

test "anchor: Wireshark reads the OPC UA adapter's ACKF handshake reply" {
    // External anchor (Wireshark 4.6.4 / sharkd, tcp 4840 -> 40000). See
    // `goldens.zig` for the method and for why this module needs one at all;
    // this vector lives here rather than there because it needs `OpcuaFixture`.
    //
    //   OpcUa Binary Protocol
    //     Message Type: ACK          [opcua.transport.type == "ACK"]
    //     Chunk Type: F              [opcua.transport.chunk == "F"]
    //     Message Size: 28           [opcua.transport.size == 28]
    //     Version: 0                 [opcua.transport.ver == 0]
    //     ReceiveBufferSize: 65536   [opcua.transport.rbs == 65536]
    //     SendBufferSize: 65536      [opcua.transport.sbs == 65536]
    //     MaxMessageSize: 1048576    [opcua.transport.mms == 1048576]
    //     MaxChunkCount: 256         [opcua.transport.mcc == 256]
    //
    // The negotiated limits are what a real client uses to size its own
    // buffers, so a third party reading them back in the right order and
    // endianness is the part of the UA-TCP handshake worth anchoring.
    const gpa = testing.allocator;
    var fx: OpcuaFixture = undefined;
    try fx.init(gpa, "opc.tcp://127.0.0.1:4840");
    defer fx.deinit();

    var f = try Fleet.init(gpa, .{
        .seed = 8,
        .max_frame_len = 64 * 1024,
        .inflight_capacity = 32,
        .outbox_bytes = 256 * 1024,
    });
    defer f.deinit();
    const id = try f.addNode(.{ .node = fx.node.node(), .tag = 9 });

    const url = "opc.tcp://127.0.0.1:4840";
    var hel: [32 + url.len]u8 = undefined;
    @memcpy(hel[0..4], "HELF");
    std.mem.writeInt(u32, hel[4..8], hel.len, .little);
    std.mem.writeInt(u32, hel[8..12], 0, .little);
    std.mem.writeInt(u32, hel[12..16], 65536, .little);
    std.mem.writeInt(u32, hel[16..20], 65536, .little);
    std.mem.writeInt(u32, hel[20..24], 1 << 20, .little);
    std.mem.writeInt(u32, hel[24..28], 0, .little);
    std.mem.writeInt(u32, hel[28..32], url.len, .little);
    @memcpy(hel[32..], url);

    try f.submit(id, &hel, 0);
    _ = try f.advance(10);
    try testing.expectEqual(@as(usize, 1), f.outbound().len);
    try testing.expectEqualSlices(u8, &.{
        0x41, 0x43, 0x4B, 0x46, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x01, 0x00, 0x00,
    }, f.frameBytes(f.outbound()[0]));
}

test "opcua adapter: a HEL/OPN/CreateSession sequence round-trips through the node" {
    const gpa = testing.allocator;
    var fx: OpcuaFixture = undefined;
    try fx.init(gpa, "opc.tcp://127.0.0.1:4840");
    defer fx.deinit();

    var f = try Fleet.init(gpa, .{
        .seed = 8,
        .max_frame_len = 64 * 1024,
        .inflight_capacity = 32,
        .outbox_bytes = 256 * 1024,
    });
    defer f.deinit();
    const id = try f.addNode(.{ .node = fx.node.node(), .tag = 9 });

    // A real UA-TCP HELLO: "HELF", length, protocol version, four limits, then
    // the endpoint URL as an Int32-prefixed string.
    const url = "opc.tcp://127.0.0.1:4840";
    var hel: [32 + url.len]u8 = undefined;
    @memcpy(hel[0..4], "HELF");
    std.mem.writeInt(u32, hel[4..8], hel.len, .little);
    std.mem.writeInt(u32, hel[8..12], 0, .little); // protocol version
    std.mem.writeInt(u32, hel[12..16], 65536, .little); // receive buffer
    std.mem.writeInt(u32, hel[16..20], 65536, .little); // send buffer
    std.mem.writeInt(u32, hel[20..24], 1 << 20, .little); // max message size
    std.mem.writeInt(u32, hel[24..28], 0, .little); // max chunk count
    std.mem.writeInt(u32, hel[28..32], url.len, .little);
    @memcpy(hel[32..], url);

    try f.submit(id, &hel, 0);
    _ = try f.advance(10);

    // An ACKF back, and the framing rule agrees with what came out.
    try testing.expectEqual(@as(usize, 1), f.outbound().len);
    const ack = f.frameBytes(f.outbound()[0]);
    try testing.expectEqualSlices(u8, "ACKF", ack[0..4]);
    try testing.expectEqual(@as(?usize, ack.len), try Framing.opcua_uatcp.frameLen(ack));

    // Garbage on an open connection is refused, not fatal.
    try f.submit(id, &.{ 'X', 'X', 'X', 'F', 8, 0, 0, 0 }, 20);
    _ = try f.advance(30);

    // Restart drops the channel: the next HEL is answered afresh.
    try testing.expect(fx.node.node().control(.restart, 40));
    try f.submit(id, &hel, 50);
    _ = try f.advance(60);
    try testing.expect(f.outbound().len > 0);
    try testing.expectEqualSlices(u8, "ACKF", f.frameBytes(f.outbound()[0])[0..4]);
}

test "opcua adapter: trouble stamps BadDeviceFailure and moves ServerStatus.State" {
    const gpa = testing.allocator;
    var fx: OpcuaFixture = undefined;
    try fx.init(gpa, "opc.tcp://127.0.0.1:4840");
    defer fx.deinit();
    const n = fx.node.node();

    try testing.expectEqual(@as(?opcua.encoding.StatusCode, 0), fx.measurementStatus());
    try testing.expect(n.control(.trouble_on, 0));
    try testing.expectEqual(
        @as(?opcua.encoding.StatusCode, OpcuaNode.status_bad_device_failure),
        fx.measurementStatus(),
    );

    // ServerStatus.State (i=2259) really says Failed(1), which is what a
    // client's Server-object view shows.
    const state_id = opcua.encoding.NodeId{
        .numeric = .{ .namespace = 0, .id = opcua.nodestore.id.server_status_state },
    };
    const state_node = fx.store.getNode(state_id).?;
    try testing.expectEqual(@as(i32, 1), state_node.attributes.variable.value.value.?.scalar.int32);

    try testing.expect(n.control(.trouble_off, 0));
    try testing.expectEqual(@as(?opcua.encoding.StatusCode, 0), fx.measurementStatus());
    try testing.expectEqual(@as(i32, 0), state_node.attributes.variable.value.value.?.scalar.int32);

    // The same read path a client uses reports the status, not just the field.
    try testing.expect(n.control(.trouble_on, 0));
    const dv = fx.store.readAttribute(
        OpcuaFixture.measurement,
        opcua.services.attribute_id.value,
    );
    try testing.expectEqual(OpcuaNode.status_bad_device_failure, dv.status.?);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("node.zig");
    _ = @import("drivers.zig");
    _ = @import("fleet.zig");
    _ = @import("adapters.zig");
    _ = @import("tcp.zig");
    _ = @import("shim.zig");
    _ = @import("goldens.zig");
    _ = @import("master_goldens.zig");
    _ = @import("vopr.zig");
}

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

    var binaries = [_]dnp3.outstation.BinaryInput{.{ .value = false, .class = .class1 }} ** 8;
    var analogs = [_]dnp3.outstation.AnalogInput{.{ .value = 0, .class = .class2 }} ** 4;
    var counters = [_]dnp3.outstation.Counter{.{ .value = 0, .class = .class3 }} ** 2;
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
        .{ .binary_inputs = &binaries, .analog_inputs = &analogs, .counters = &counters },
        dnp3.outstation.EventBuffer.init(&events),
        &rx_buf,
        &scratch,
        &tx_fragment,
    );
    const id = try f.addNode(.{ .node = station.node(), .tag = 1, .tick_period_ms = 500 });

    // A ramp animates analog input 0 while the master polls it.
    var ai0: f64 = 0;
    var s_ai = Cell{ .cell = &ai0 };
    const sinks = [_]Sink{s_ai.sink()};
    var sig = Signal{
        .driver = .{ .ramp = .{ .start = 0, .per_ms = 0.01, .min = 0, .max = 100, .wrap = true } },
        .sinks = &sinks,
        .period_ms = 500,
    };
    try f.addSignal(&sig);

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
}

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

    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 102, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = false } } },
        .{ .ioa = 201, .type_id = .m_me_nc_1, .element = .{ .short_float = .{ .value = 21.5, .quality = .{} } } },
    };
    var frame_buf: [512]u8 = undefined;
    var queue_buf: [8192]u8 = undefined;
    var rtu: Iec104Node = undefined;
    try rtu.init(.{ .common_address = 47 }, &points, &frame_buf, &queue_buf, .{});
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
            points[0].element.siq.quality.iv, points[2].element.short_float.quality.iv,
        },
    );
    try testing.expect(st.delivered > 0);
    try testing.expect(st.replied > 0);
    try testing.expect(points[2].element.short_float.quality.iv);
}

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
    var db2 = [_]u8{0} ** 32;
    const areas = [_]s7comm.AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = &db1 },
        .{ .area = .db, .db_number = 2, .bytes = &db2 },
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
}

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
}

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
}

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
    const tags = [_]enip.TagBinding{
        .{ .name = "Speed", .type = .dint, .bytes = &speed },
        .{ .name = "Level", .type = .real, .bytes = &level },
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
}

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
    const healthy_flags = [_]u8{0x00};
    var ai_props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "Zone-1-Temp" } },
        .{ .id = .present_value, .value = .{ .real = 21.5 }, .cov_reported = true },
        .{ .id = .units, .value = .{ .enumerated = 62 } },
        .{ .id = .status_flags, .value = .{ .bit_string = .{ .unused_bits = 4, .bytes = &healthy_flags } }, .cov_reported = true },
        .{ .id = .reliability, .value = .{ .enumerated = 0 } },
        .{ .id = .out_of_service, .value = .{ .boolean = false }, .writable = true },
    };
    var dev_props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "zig-fleetsim device" } },
        .{ .id = .vendor_name, .value = .{ .string = "zig-libs" } },
    };
    var objects = [_]bacnet.Object{
        .{ .id = .{ .type = .analog_input, .instance = 1 }, .properties = &ai_props },
        .{ .id = .{ .type = .device, .instance = 260_001 }, .properties = &dev_props },
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
}

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
    const ns_uri = "urn:zig-libs:fleetsim";

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
}

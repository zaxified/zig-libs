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
pub const serveUdp = tcp.serveUdp;

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");

const modbus = @import("modbus");
const dnp3 = @import("dnp3");
const iec104 = @import("iec104");
const s7comm = @import("s7comm");
const bacnet = @import("bacnet");
const enip = @import("enip");
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
    _ = try f.applyNetsimTrace(trace.events);

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

    // Every byte of the corpus becomes a frame boundary decision, a node choice
    // and a clock step, so the fuzzer explores dispatch, not just one parser.
    var pos: usize = 0;
    var t: Time = 0;
    const ids = [_]NodeId{ mb_id, s7_id, iec_id };
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

test "fuzz: frame dispatch across three adapters survives arbitrary bytes" {
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

    std.debug.print(
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

test "live: a real Modbus master drives a simulated slave over the TCP binding" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_TEST_LISTEN") orelse {
        std.debug.print("SKIPPED: live fleetsim Modbus (set FLEETSIM_TEST_LISTEN=host:port)\n", .{});
        return error.SkipZigTest;
    };
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
            std.debug.print("SKIPPED: live fleetsim Modbus (cannot bind {s})\n", .{endpoint});
            return error.SkipZigTest;
        },
        error.NoPeer => {
            std.debug.print("SKIPPED: live fleetsim Modbus (no peer connected)\n", .{});
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
    const endpoint = envVar("FLEETSIM_ENIP_LISTEN") orelse {
        std.debug.print("SKIPPED: live fleetsim EtherNet/IP (set FLEETSIM_ENIP_LISTEN=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;

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

    std.debug.print("live fleetsim EtherNet/IP adapter listening on {s}\n", .{endpoint});
    const report = serveTcp(testing.allocator, io, &f, id, addr, .{
        .idle_ms = 200,
        .run_ms = 60_000,
        .max_sessions = 8,
    }) catch |e| switch (e) {
        error.BindFailed, error.NoPeer => {
            std.debug.print("SKIPPED: live fleetsim EtherNet/IP (no listener/peer)\n", .{});
            return error.SkipZigTest;
        },
        else => return e,
    };

    std.debug.print(
        "live fleetsim EtherNet/IP: sessions={d} frames_in={d} frames_out={d} reads={d} writes={d} identity={d} speed={d}\n",
        .{ report.sessions, report.frames_in, report.frames_out, dev.adapter.reads, dev.adapter.writes, dev.adapter.identity_requests, std.mem.readInt(i32, speed[0..4], .little) },
    );
    try testing.expect(f.stats(id).replied > 0);
}

test "live: a real BACnet client discovers a simulated device over UDP" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const endpoint = envVar("FLEETSIM_BACNET_LISTEN") orelse {
        std.debug.print("SKIPPED: live fleetsim BACnet (set FLEETSIM_BACNET_LISTEN=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;

    var f = try Fleet.init(testing.allocator, .{ .seed = 4, .max_frame_len = 1500, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    var ai_props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "Zone-1-Temp" } },
        .{ .id = .present_value, .value = .{ .real = 21.5 }, .cov_reported = true },
        .{ .id = .units, .value = .{ .enumerated = 62 } },
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
    const id = try f.addNode(.{ .node = dev.node() });

    std.debug.print("live fleetsim BACnet device listening on {s}\n", .{endpoint});
    const report = serveUdp(testing.allocator, io, &f, id, addr, .{
        .idle_ms = 200,
        .run_ms = 60_000,
    }) catch |e| switch (e) {
        error.BindFailed => {
            std.debug.print("SKIPPED: live fleetsim BACnet (cannot bind {s})\n", .{endpoint});
            return error.SkipZigTest;
        },
        else => return e,
    };
    std.debug.print(
        "live fleetsim BACnet: datagrams_in={d} datagrams_out={d} delivered={d} replied={d}\n",
        .{ report.frames_in, report.frames_out, f.stats(id).delivered, f.stats(id).replied },
    );
    try testing.expect(report.frames_in > 0);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("node.zig");
    _ = @import("drivers.zig");
    _ = @import("fleet.zig");
    _ = @import("adapters.zig");
    _ = @import("tcp.zig");
}

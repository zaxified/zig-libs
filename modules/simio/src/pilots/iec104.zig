// SPDX-License-Identifier: MIT

//! Pilot: the `iec104` controlling station (`Client` + `TcpTransport`) and
//! controlled station (`OutstationServer` + `TcpTransport`), unchanged, over a
//! simulated network. The property is the one a SCADA master relies on after
//! a link outage: once the link is back, a general interrogation makes its
//! picture of the process equal the outstation's. Spontaneous reports sent
//! into a partition are gone for good (the outstation's t1 closes the dead
//! connection), so only a master that interrogates again after reconnecting
//! converges, and the broken variant that does not is caught.
//!
//! A master must also never hold a value the process has not produced yet
//! (checked as an invariant on every step).

const std = @import("std");
const iec104 = @import("iec104");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const n_points = 4;
const common_address = 7;
const port = iec104.default_port;
/// The process stops changing here, inside the longest outage below.
const process_stop_ms = 4500;

/// Short timers so an outage is noticed within a few simulated seconds.
const config: iec104.Config = .{ .k = 12, .w = 4, .t0_ms = 3000, .t1_ms = 1500, .t2_ms = 500, .t3_ms = 3000 };

const State = struct {
    /// What the process really is.
    truth: [n_points]f32 = @splat(0),
    /// What the master has been told.
    seen: [n_points]f32 = @splat(0),
    /// The broken variant: no interrogation after the first connection.
    interrogate_again: bool = true,
    connections: u32 = 0,
    served: u32 = 0,
};

fn nowMs(io: Io) u64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .awake).nanoseconds, ns_per_ms));
}

// ── the controlled station ─────────────────────────────────────────────────

fn process(io: Io, st: *State) !void {
    var k: usize = 0;
    while (nowMs(io) < process_stop_ms) : (k += 1) {
        try io.sleep(.fromMilliseconds(200), .awake);
        st.truth[k % n_points] += 1;
    }
}

fn outstationMain(io: Io, st: *State) !void {
    var listener = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var points: [n_points]iec104.Point = undefined;
    for (&points, 0..) |*p, i| p.* = .{
        .ioa = @intCast(i + 1),
        .type_id = .m_me_nc_1,
        .element = .{ .short_float = .{ .value = st.truth[i], .quality = .{} } },
    };
    while (true) {
        const stream = try listener.accept(io);
        st.served += 1;
        serve(io, stream, st, &points) catch {};
    }
}

fn serve(io: Io, stream: net.Stream, st: *State, points: []iec104.Point) !void {
    var tt: iec104.TcpTransport = .{ .io = io, .stream = stream };
    defer tt.close();
    try tt.setReadTimeout(50);
    var frames: [iec104.apci.max_apdu_len * 2]u8 = undefined;
    var queue: [4096]u8 = undefined;
    var rtu = try iec104.OutstationServer.init(.{ .common_address = common_address }, points, tt.transport(), &frames, &queue, config);
    rtu.onConnected(nowMs(io));
    while (true) {
        const now = nowMs(io);
        for (points, 0..) |*p, i| {
            if (p.element.short_float.value == st.truth[i]) continue;
            p.element.short_float.value = st.truth[i];
            if (rtu.isStarted()) try rtu.reportSpontaneous(p.ioa, now);
        }
        switch (try rtu.poll(now)) {
            .closed => return,
            else => {},
        }
    }
}

// ── the controlling station ────────────────────────────────────────────────

fn masterMain(io: Io, server: net.IpAddress, st: *State) !void {
    while (true) {
        runOnce(io, server, st) catch {};
        try io.sleep(.fromMilliseconds(300), .awake);
    }
}

fn runOnce(io: Io, server: net.IpAddress, st: *State) !void {
    var tt = try iec104.TcpTransport.connect(io, server);
    defer tt.close();
    st.connections += 1;
    try tt.setReadTimeout(50);
    var frames: [iec104.apci.max_apdu_len * 2]u8 = undefined;
    var c = try iec104.Client.init(tt.transport(), &frames, .{ .config = config });
    var now = nowMs(io);
    c.onConnected(now);
    try c.startDataTransfer(now);
    while (true) {
        now = nowMs(io);
        switch (try c.poll(now)) {
            .started => if (st.connections == 1 or st.interrogate_again) {
                try c.interrogate(common_address, .station, now);
            },
            .asdu => |a| if (a.header.type_id == .m_me_nc_1) {
                var it = a.objects();
                while (try it.next()) |o| st.seen[o.ioa - 1] = o.element.short_float.value;
            },
            .closed => return,
            else => {},
        }
    }
}

// ── the world ──────────────────────────────────────────────────────────────

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    const rtu = try sim.addHost(.{}); // 10.0.0.1
    const master = try sim.addHost(.{});
    try sim.link(rtu, master, .{ .latency_ns = 5 * ns_per_ms, .jitter_ns = 2 * ns_per_ms });
    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = rtu.ip4, .port = port } };
    try rtu.spawnBoot(outstationMain, .{ rtu.io(), st });
    try rtu.spawnBoot(process, .{ rtu.io(), st });
    try master.spawnBoot(masterMain, .{ master.io(), addr, st });
}

fn invariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    for (st.seen, st.truth) |s, t| if (s > t) return error.ValueFromTheFuture;
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (!std.mem.eql(f32, &st.seen, &st.truth)) return error.MasterDiverged;
}

fn reset(ctx: ?*anyopaque) void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    st.* = .{ .interrogate_again = st.interrogate_again };
}

fn case(st: *State) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 512 * 1024 },
        .setup = setup,
        .invariant = invariant,
        .final = final,
        .reset = reset,
        .ctx = st,
        .duration_ns = 40 * ns_per_s,
    };
}

fn at(time_ms: u64, kind: @FieldType(search.TraceEvent, "kind")) search.TraceEvent {
    return .{ .time = time_ms, .kind = kind };
}

test "pilot iec104: on a healthy network the master follows the process after one interrogation" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 1), st.connections);
    try testing.expect(st.truth[0] > 0);
}

test "pilot iec104: after an outage longer than t1 the master reconnects and converges" {
    var st: State = .{};
    const cut = [_]u32{1};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(3000, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(9000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expect(st.connections >= 2);
    try testing.expect(st.served >= 2);
}

test "pilot iec104: a master that never interrogates again diverges, and the check sees it" {
    var st: State = .{ .interrogate_again = false };
    const cut = [_]u32{1};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(3000, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(9000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(anyerror, error.MasterDiverged), r.violation.?.err);
}

test "pilot iec104: the master converges across seeds of loss, duplication and partitions" {
    var st: State = .{};
    const faults: search.FaultConfig = .{
        .schedule = .{
            .max_events = 6,
            .horizon = 8000,
            .repair_permille = 1000,
            .enable_crash = false,
            .enable_clock_jump = false,
        },
    };
    if (try search.findFailing(testing.allocator, case(&st), faults, 0, 20)) |*failing| {
        defer @constCast(failing).deinit();
        std.debug.print("seed {d}: {t} at {d} ms\n", .{ failing.case.seed, failing.violation.err, failing.violation.at_ns / ns_per_ms });
        return error.TestUnexpectedResult;
    }
}

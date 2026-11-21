// SPDX-License-Identifier: MIT

//! Pilot: the `s7comm` `Client` and `Responder` over `TcpTransport`,
//! unchanged, on a simulated network. A programming-device client writes a
//! counter into a data block of a simulated PLC, one write after another, and
//! keeps on until every value has been acknowledged. Under loss, duplication
//! and partitions:
//!
//! - the data block never holds a value the client has not sent yet, and
//!   never one older than the last write the client saw acknowledged (an
//!   acknowledged write was applied, and nothing applies out of order);
//! - the client gets through to the last value once the network is quiet,
//!   which needs a new connection when the old one is dead. The broken
//!   variant that keeps using the dead connection is caught.

const std = @import("std");
const s7comm = @import("s7comm");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const port = s7comm.default_port;
const last_value: u32 = 40;
/// The PLC drops a connection it has heard nothing on for this long.
const idle_limit_ms = 3000;

const State = struct {
    /// The data block, which outlives every connection.
    db: [4]u8 = @splat(0),
    /// Highest value the client has put on the wire.
    sent: u32 = 0,
    /// Highest value whose write the client saw acknowledged.
    acked: u32 = 0,
    /// The broken variant: stay on the connection whatever happens.
    reconnect: bool = true,
    connections: u32 = 0,
};

fn nowMs(io: Io) u64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .awake).nanoseconds, ns_per_ms));
}

// ── the PLC ────────────────────────────────────────────────────────────────

fn plcMain(io: Io, st: *State) !void {
    var listener = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var areas = [_]s7comm.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &st.db }};
    while (true) {
        const stream = try listener.accept(io);
        var plc = s7comm.Responder.init(.{}, &areas);
        serve(io, stream, &plc) catch {};
    }
}

fn serve(io: Io, stream: net.Stream, plc: *s7comm.Responder) !void {
    var tt = s7comm.TcpTransport.fromStream(io, stream);
    defer tt.close();
    tt.setReadTimeout(50);
    const t = tt.transport();
    var in: [1024]u8 = undefined;
    var out: [1024]u8 = undefined;
    var heard = nowMs(io);
    while (nowMs(io) - heard < idle_limit_ms) {
        const n = try t.read(&in);
        if (n == 0) continue;
        heard = nowMs(io);
        const reply = (plc.handle(in[0..n], &out) catch continue) orelse return;
        try t.write(reply);
    }
}

// ── the programming device ─────────────────────────────────────────────────

fn clientMain(io: Io, server: net.IpAddress, st: *State) !void {
    while (st.acked < last_value) {
        session(io, server, st) catch {};
        try io.sleep(.fromMilliseconds(300), .awake);
    }
}

fn session(io: Io, server: net.IpAddress, st: *State) !void {
    var tt = try s7comm.TcpTransport.connect(io, server);
    defer tt.close();
    tt.setReadTimeout(100);
    var buf: [s7comm.Client.bufferSize(480)]u8 = undefined;
    var c = try s7comm.Client.init(tt.transport(), &buf, .{});
    try c.connect();
    st.connections += 1;
    while (st.acked < last_value) {
        try io.sleep(.fromMilliseconds(100), .awake);
        const next = st.acked + 1;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, next, .big);
        st.sent = @max(st.sent, next);
        c.writeBytes(.db, 1, 0, &payload) catch |e| {
            if (st.reconnect) return e;
            continue;
        };
        st.acked = next;
    }
}

// ── the world ──────────────────────────────────────────────────────────────

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    const plc = try sim.addHost(.{}); // 10.0.0.1
    const pg = try sim.addHost(.{});
    try sim.link(plc, pg, .{ .latency_ns = 5 * ns_per_ms, .jitter_ns = 2 * ns_per_ms });
    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = plc.ip4, .port = port } };
    try plc.spawnBoot(plcMain, .{ plc.io(), st });
    try pg.spawnBoot(clientMain, .{ pg.io(), addr, st });
}

fn invariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    const db = std.mem.readInt(u32, &st.db, .big);
    if (db > st.sent) return error.ValueFromTheFuture;
    if (db < st.acked) return error.AcknowledgedWriteLost;
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (st.acked != last_value or std.mem.readInt(u32, &st.db, .big) != last_value) return error.WritesNeverFinished;
}

fn reset(ctx: ?*anyopaque) void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    st.* = .{ .reconnect = st.reconnect };
}

fn case(st: *State) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 512 * 1024 },
        .setup = setup,
        .invariant = invariant,
        .final = final,
        .reset = reset,
        .ctx = st,
        .duration_ns = 60 * ns_per_s,
    };
}

fn at(time_ms: u64, kind: @FieldType(search.TraceEvent, "kind")) search.TraceEvent {
    return .{ .time = time_ms, .kind = kind };
}

test "pilot s7comm: on a healthy network every write lands over one connection" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 1), st.connections);
    try testing.expectEqual(last_value, st.acked);
}

test "pilot s7comm: after an outage the client reconnects and finishes" {
    var st: State = .{};
    const cut = [_]u32{1};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(1500, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(8000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expect(st.connections >= 2);
}

test "pilot s7comm: a client that never leaves a dead connection never finishes, and the check sees it" {
    var st: State = .{ .reconnect = false };
    const cut = [_]u32{1};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(1500, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(8000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(anyerror, error.WritesNeverFinished), r.violation.?.err);
}

test "pilot s7comm: writes are applied in order across seeds of loss, duplication and partitions" {
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

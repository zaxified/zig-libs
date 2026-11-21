// SPDX-License-Identifier: MIT

//! Pilot: the `iec61850` MMS `Client` and `Server` over `TcpTransport`,
//! unchanged, on a simulated network. An IED publishes two values that move
//! with its process (a counter, and a second one offset by a million); a
//! client reads both over one association, one request at a time. Under loss,
//! duplication and partitions three things must hold:
//!
//! - a reply is never taken for the answer to another request (every value
//!   read for the first variable is below a million, every one for the second
//!   is above), which the client's invoke-id matching has to guarantee after
//!   a timed-out request's late reply turns up;
//! - the client never reports a value the process has not reached yet;
//! - once the network is quiet again the client's last reading equals the
//!   process, which needs it to build a new association when the old one is
//!   dead. The broken variant that keeps using the dead association is caught.

const std = @import("std");
const iec61850 = @import("iec61850");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const port = iec61850.default_port;
const offset = 1_000_000;
const ref_a = "LD1/GGIO1.Cnt.i";
const ref_b = "LD1/GGIO1.Cnt2.i";
/// The process stops changing here, inside the longest outage below.
const process_stop_ms = 4500;
/// The IED drops an association it has heard nothing on for this long.
const idle_limit_ms = 3000;

const State = struct {
    truth: i64 = 0,
    seen_a: i64 = -1,
    seen_b: i64 = -1,
    /// The broken variant: stay on the association whatever happens.
    reconnect: bool = true,
    associations: u32 = 0,
    served: u32 = 0,
};

fn nowMs(io: Io) u64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .awake).nanoseconds, ns_per_ms));
}

// ── the IED ────────────────────────────────────────────────────────────────

fn process(io: Io, st: *State) !void {
    while (nowMs(io) < process_stop_ms) {
        try io.sleep(.fromMilliseconds(200), .awake);
        st.truth += 1;
    }
}

fn setValue(v: *iec61850.Variable, value: i64) void {
    var w = iec61850.ber.Writer.init(v.storage);
    iec61850.Emit.integer(&w, value) catch unreachable;
    // The writer fills the buffer from its end: move the value to the front.
    const d = w.done();
    std.mem.copyForwards(u8, v.storage[0..d.len], d);
    v.len = d.len;
}

fn iedMain(io: Io, st: *State) !void {
    var listener = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var store_a: [16]u8 = undefined;
    var store_b: [16]u8 = undefined;
    var vars = [_]iec61850.Variable{
        .{ .domain = "LD1", .item = "GGIO1$MX$Cnt$i", .storage = &store_a, .len = 0 },
        .{ .domain = "LD1", .item = "GGIO1$MX$Cnt2$i", .storage = &store_b, .len = 0 },
    };
    const domains = [_][]const u8{"LD1"};
    var srv = iec61850.Server.init(.{}, .{ .variables = &vars, .domains = &domains });
    while (true) {
        const stream = try listener.accept(io);
        st.served += 1;
        srv.peer = st.served;
        serve(io, stream, st, &srv, &vars) catch {};
        srv.releaseAssociationOf(srv.peer);
    }
}

fn serve(io: Io, stream: net.Stream, st: *State, srv: *iec61850.Server, vars: []iec61850.Variable) !void {
    var tt = iec61850.TcpTransport.fromStream(io, stream);
    defer tt.close();
    tt.setReadTimeout(50);
    const t = tt.transport();
    var in: [16384]u8 = undefined;
    var out: [32768]u8 = undefined;
    var heard = nowMs(io);
    while (nowMs(io) - heard < idle_limit_ms) {
        setValue(&vars[0], st.truth);
        setValue(&vars[1], st.truth + offset);
        const n = try t.read(&in);
        if (n == 0) continue;
        heard = nowMs(io);
        const reply = (srv.handle(in[0..n], &out) catch continue) orelse return;
        try t.write(reply);
    }
}

// ── the client ─────────────────────────────────────────────────────────────

fn clientMain(io: Io, server: net.IpAddress, st: *State) !void {
    while (true) {
        associate(io, server, st) catch {};
        try io.sleep(.fromMilliseconds(300), .awake);
    }
}

fn associate(io: Io, server: net.IpAddress, st: *State) !void {
    var tt = try iec61850.TcpTransport.connect(io, server);
    defer tt.close();
    tt.setReadTimeout(100);
    var buf: [16384]u8 = undefined;
    var c = try iec61850.Client.init(tt.transport(), &buf, .{ .max_read_rounds = 10 });
    try c.connect();
    st.associations += 1;
    while (true) {
        try io.sleep(.fromMilliseconds(100), .awake);
        readBoth(&c, st) catch |e| {
            if (st.reconnect) return e;
        };
    }
}

fn readBoth(c: *iec61850.Client, st: *State) !void {
    st.seen_a = try (try c.readObject(ref_a, .MX)).integer(i64);
    st.seen_b = try (try c.readObject(ref_b, .MX)).integer(i64);
}

// ── the world ──────────────────────────────────────────────────────────────

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    const ied = try sim.addHost(.{}); // 10.0.0.1
    const client = try sim.addHost(.{});
    try sim.link(ied, client, .{ .latency_ns = 5 * ns_per_ms, .jitter_ns = 2 * ns_per_ms });
    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = ied.ip4, .port = port } };
    try ied.spawnBoot(iedMain, .{ ied.io(), st });
    try ied.spawnBoot(process, .{ ied.io(), st });
    try client.spawnBoot(clientMain, .{ client.io(), addr, st });
}

fn invariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (st.seen_a >= offset or (st.seen_b >= 0 and st.seen_b < offset)) return error.ReplyForAnotherRequest;
    if (st.seen_a > st.truth or st.seen_b - offset > st.truth) return error.ValueFromTheFuture;
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (st.seen_a != st.truth or st.seen_b != st.truth + offset) return error.ClientDiverged;
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
        .duration_ns = 40 * ns_per_s,
    };
}

fn at(time_ms: u64, kind: @FieldType(search.TraceEvent, "kind")) search.TraceEvent {
    return .{ .time = time_ms, .kind = kind };
}

test "pilot iec61850: on a healthy network the client follows the process over one association" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 1), st.associations);
    try testing.expect(st.truth > 0);
}

test "pilot iec61850: after an outage the client builds a new association and converges" {
    var st: State = .{};
    const cut = [_]u32{1};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(3000, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(9000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expect(st.associations >= 2);
}

test "pilot iec61850: a client that never leaves a dead association diverges, and the check sees it" {
    var st: State = .{ .reconnect = false };
    const cut = [_]u32{1};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(3000, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(9000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(anyerror, error.ClientDiverged), r.violation.?.err);
}

test "pilot iec61850: the client converges across seeds of loss, duplication and partitions" {
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

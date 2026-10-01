// SPDX-License-Identifier: MIT

//! Pilot: the `http` client (unchanged: pooling, the stale-connection retry,
//! `connect_timeout_ms`/`total_timeout_ms` enforced by canceling a concurrent
//! task) against a small HTTP/1.1 server written here, over simulated TCP.
//! The server is this file's own rather than `http.Server`, whose stall
//! timeouts still poll the raw socket (see SPEC § Pilots).
//!
//! The property: every response the client hands back as complete carries
//! exactly the body the server sent. Reading a body is deliberately not
//! bounded by the client (its module doc), so a caller that wants an answer
//! from a server that may die mid-body bounds the read itself; one that does
//! not is caught waiting forever.

const std = @import("std");
const http = @import("http");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const body_len = 3000;
const n_fetches = 20;

fn bodyByte(n: u32, i: usize) u8 {
    return @intCast((n * 7 + i) % 251);
}

fn bodyOk(n: u32, body: []const u8) bool {
    if (body.len != body_len) return false;
    for (body, 0..) |b, i| if (b != bodyByte(n, i)) return false;
    return true;
}

// ── the server ─────────────────────────────────────────────────────────────

const Server = struct {
    /// Close each connection after one response, while announcing keep-alive:
    /// the client pools a connection that is already gone.
    one_shot: bool = false,
    /// The first `/data` response stops after a third of its body.
    stall_once: bool = false,
    stalled: bool = false,
    requests: u32 = 0,
};

fn serverMain(io: Io, srv: *Server) !void {
    var listener = try net.IpAddress.listen(&.{ .ip4 = .unspecified(80) }, io, .{});
    defer listener.deinit(io);
    var group: Io.Group = .init;
    defer group.cancel(io);
    while (true) {
        const stream = try listener.accept(io);
        group.async(io, serveConn, .{ io, stream, srv });
    }
}

fn serveConn(io: Io, stream: net.Stream, srv: *Server) Io.Cancelable!void {
    defer stream.close(io);
    serveConnInner(io, stream, srv) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {},
    };
}

fn serveConnInner(io: Io, stream: net.Stream, srv: *Server) !void {
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    const r = &sr.interface;
    const w = &sw.interface;
    while (true) {
        const line = r.takeDelimiterInclusive('\n') catch return;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        _ = it.next(); // method
        const target = it.next() orelse return;
        var path_buf: [64]u8 = undefined;
        const path = path_buf[0..@min(target.len, path_buf.len)];
        @memcpy(path, target[0..path.len]);
        while (true) { // the rest of the head
            const h = r.takeDelimiterInclusive('\n') catch return;
            if (std.mem.eql(u8, h, "\r\n")) break;
        }
        srv.requests += 1;

        if (std.mem.eql(u8, path, "/silent")) {
            try io.sleep(.fromSeconds(3600), .awake);
            return;
        }
        const n = if (std.mem.startsWith(u8, path, "/data/"))
            std.fmt.parseInt(u32, path[6..], 10) catch return
        else
            return;
        try w.print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{body_len});
        const stall = srv.stall_once and !srv.stalled;
        const send: usize = if (stall) body_len / 3 else body_len;
        for (0..send) |i| try w.writeByte(bodyByte(n, i));
        try w.flush();
        if (stall) {
            srv.stalled = true;
            try io.sleep(.fromSeconds(3600), .awake);
        }
        if (srv.one_shot) return;
    }
}

// ── the client ─────────────────────────────────────────────────────────────

fn url(buf: []u8, ip: [4]u8, path: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "http://{d}.{d}.{d}.{d}{s}", .{ ip[0], ip[1], ip[2], ip[3], path }) catch unreachable;
}

fn get(c: *http.Client, gpa: std.mem.Allocator, ip: [4]u8, path: []const u8) ![]u8 {
    var ub: [64]u8 = undefined;
    var res = try c.request(.get, url(&ub, ip, path), .{});
    defer res.deinit();
    if (res.status != 200) return error.UnexpectedStatus;
    return res.readAllAlloc(gpa, 1 << 20);
}

const Fetcher = struct {
    server_ip: [4]u8 = undefined,
    /// The broken variant: no deadline of its own around a fetch.
    unbounded: bool = false,
    next: u32 = 0,
    attempts: u32 = 0,
    wrong: bool = false,
    dials: usize = 0,
};

/// Fetches `/data/0` .. `/data/19`, retrying a failed fetch; each attempt
/// gets 10 s, body included, unless `unbounded`.
fn fetcher(io: Io, gpa: std.mem.Allocator, f: *Fetcher) !void {
    var client = http.Client.init(io, gpa, .{ .connect_timeout_ms = 2000, .total_timeout_ms = 5000 });
    defer client.deinit();
    try io.sleep(.fromMilliseconds(100), .awake);
    while (f.next < n_fetches) {
        f.attempts += 1;
        if (f.unbounded) {
            fetchOne(io, &client, gpa, f) catch {};
        } else {
            var attempt = io.async(fetchOne, .{ io, &client, gpa, f });
            const start = f.next;
            var waited: u32 = 0;
            while (f.next == start and waited < 100) : (waited += 1) try io.sleep(.fromMilliseconds(100), .awake);
            attempt.cancel(io) catch {};
        }
        f.dials = client.dialCount();
        if (f.next < n_fetches) try io.sleep(.fromMilliseconds(50), .awake);
    }
}

fn fetchOne(io: Io, client: *http.Client, gpa: std.mem.Allocator, f: *Fetcher) !void {
    _ = io;
    var pb: [16]u8 = undefined;
    const path = std.fmt.bufPrint(&pb, "/data/{d}", .{f.next}) catch unreachable;
    const body = try get(client, gpa, f.server_ip, path);
    defer gpa.free(body);
    if (!bodyOk(f.next, body)) f.wrong = true;
    f.next += 1;
}

// ── the world ──────────────────────────────────────────────────────────────

const World = struct { server: Server = .{}, fetcher: Fetcher = .{} };

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const w: *World = @ptrCast(@alignCast(ctx.?));
    const s = try sim.addHost(.{}); // node 0
    const c = try sim.addHost(.{}); // node 1
    try sim.link(s, c, .{ .latency_ns = 15 * ns_per_ms, .jitter_ns = 5 * ns_per_ms });
    try s.spawnBoot(serverMain, .{ s.io(), &w.server });
    w.fetcher.server_ip = s.ip4;
    try c.spawnBoot(fetcher, .{ c.io(), c.allocator(), &w.fetcher });
}

fn invariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const w: *const World = @ptrCast(@alignCast(ctx.?));
    if (w.fetcher.wrong) return error.WrongBody;
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    try invariant(sim, ctx);
    const w: *const World = @ptrCast(@alignCast(ctx.?));
    if (w.fetcher.next != n_fetches) return error.NeverCompleted;
}

fn reset(ctx: ?*anyopaque) void {
    const w: *World = @ptrCast(@alignCast(ctx.?));
    w.* = .{
        .server = .{ .one_shot = w.server.one_shot, .stall_once = w.server.stall_once },
        .fetcher = .{ .unbounded = w.fetcher.unbounded },
    };
}

fn case(w: *World) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 1024 * 1024 },
        .setup = setup,
        .invariant = invariant,
        .final = final,
        .reset = reset,
        .ctx = w,
        .duration_ns = 120 * ns_per_s,
    };
}

test "pilot http: twenty fetches over one pooled connection, every body exact" {
    var w: World = .{};
    const r = try search.replay(testing.allocator, case(&w), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, n_fetches), w.fetcher.attempts);
    try testing.expectEqual(@as(usize, 1), w.fetcher.dials);
}

test "pilot http: a pooled connection the server already closed is retried transparently" {
    var w: World = .{ .server = .{ .one_shot = true } };
    const r = try search.replay(testing.allocator, case(&w), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    // No attempt failed: each stale connection cost a redial inside `request`.
    try testing.expectEqual(@as(u32, n_fetches), w.fetcher.attempts);
    try testing.expectEqual(@as(usize, n_fetches), w.fetcher.dials);
}

test "pilot http: a caller that bounds its fetch gets past a server stalled mid-body" {
    var w: World = .{ .server = .{ .stall_once = true } };
    const r = try search.replay(testing.allocator, case(&w), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, n_fetches + 1), w.fetcher.attempts);
}

test "pilot http: a caller that does not bound the body read waits forever, and the check sees it" {
    var w: World = .{ .server = .{ .stall_once = true }, .fetcher = .{ .unbounded = true } };
    const r = try search.replay(testing.allocator, case(&w), &.{}, ns_per_ms);
    try testing.expectEqual(@as(anyerror, error.NeverCompleted), r.violation.?.err);
    try testing.expectEqual(@as(u32, 0), w.fetcher.next);
}

const Timed = struct {
    ip: [4]u8 = undefined,
    path: []const u8,
    err: ?anyerror = null,
    elapsed_ms: i64 = 0,
};

fn timedGet(io: Io, gpa: std.mem.Allocator, t: *Timed) !void {
    var client = http.Client.init(io, gpa, .{ .connect_timeout_ms = 2000, .total_timeout_ms = 3000 });
    defer client.deinit();
    const start = Io.Timestamp.now(io, .awake);
    if (get(&client, gpa, t.ip, t.path)) |body| gpa.free(body) else |err| t.err = err;
    t.elapsed_ms = @intCast(@divFloor(start.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds, ns_per_ms));
}

fn runTimed(t: *Timed, cut: bool) !void {
    var sim: Sim = undefined;
    sim.init(testing.allocator, .{ .seed = 1, .stack_size = 1024 * 1024 });
    defer sim.deinit();
    var srv: Server = .{};
    const s = try sim.addHost(.{});
    const c = try sim.addHost(.{});
    try sim.link(s, c, .{ .latency_ns = 15 * ns_per_ms });
    if (cut) try sim.setLinkUp(s, c, false);
    try s.spawn(serverMain, .{ s.io(), &srv });
    t.ip = s.ip4;
    try c.spawn(timedGet, .{ c.io(), c.allocator(), t });
    _ = sim.runFor(60 * ns_per_s);
}

test "pilot http: total_timeout_ms bounds a server that never answers, to the millisecond" {
    var t: Timed = .{ .path = "/silent" };
    try runTimed(&t, false);
    try testing.expectEqual(@as(?anyerror, error.Timeout), t.err);
    try testing.expectEqual(@as(i64, 3000), t.elapsed_ms);
}

test "pilot http: connect_timeout_ms bounds a dial to an unreachable server" {
    var t: Timed = .{ .path = "/data/1" };
    try runTimed(&t, true);
    try testing.expectEqual(@as(?anyerror, error.Timeout), t.err);
    try testing.expectEqual(@as(i64, 2000), t.elapsed_ms);
}

test "pilot http: every completed body is exact across seeds of loss, partitions and crashes" {
    var w: World = .{};
    const faults: search.FaultConfig = .{
        .schedule = .{
            .max_events = 6,
            .horizon = 5000,
            .repair_permille = 1000,
            .enable_clock_jump = false,
        },
    };
    if (try search.findFailing(testing.allocator, case(&w), faults, 0, 20)) |*failing| {
        defer @constCast(failing).deinit();
        std.debug.print("seed {d}: {t} at {d} ms\n", .{ failing.case.seed, failing.violation.err, failing.violation.at_ns / ns_per_ms });
        return error.TestUnexpectedResult;
    }
}

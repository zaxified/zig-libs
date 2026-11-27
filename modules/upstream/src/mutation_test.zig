// SPDX-License-Identifier: MIT
//! Tests that came out of the 2026-11-25 whole-module mutation run of upstream:
//! what the older tests did not pin. Public API only (the private helpers have
//! their own test at the end of `root.zig`). Window counters of the outlier
//! detector are set directly (`win_total` / `win_ok` are public atomics), so each
//! case states its success rates exactly instead of steering them through picks.

const std = @import("std");
const testing = std.testing;
const resilience = @import("resilience");
const up = @import("root.zig");
const Pool = up.Pool;
const Upstream = up.Upstream;

const s = std.time.ns_per_s;

fn addN(pool: *Pool, comptime n: usize) !void {
    const ids = [_][]const u8{ "m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7", "m8", "m9" };
    const addrs = [_][]const u8{ "10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80", "10.0.0.4:80", "10.0.0.5:80", "10.0.0.6:80", "10.0.0.7:80", "10.0.0.8:80", "10.0.0.9:80", "10.0.1.0:80" };
    for (0..n) |i| _ = try pool.add(.{ .id = ids[i], .address = addrs[i] });
}

/// Set one outlier window: member `i` gets `total[i]` reports of which `ok[i]` succeeded.
fn setWindow(pool: *Pool, total: []const u32, ok: []const u32) void {
    for (pool.upstreams.items, 0..) |u, i| {
        u.win_total.store(total[i], .monotonic);
        u.win_ok.store(ok[i], .monotonic);
    }
}

fn ejectedCount(pool: *Pool) usize {
    var n: usize = 0;
    for (pool.upstreams.items) |u| {
        if (u.ejected.load(.seq_cst)) n += 1;
    }
    return n;
}

test "mutation 2026-11-25: priority bookkeeping: a pool of only a higher level, and the flag after a remove" {
    var only: Pool = .init(testing.allocator, .{});
    defer only.deinit();
    const three = try only.add(.{ .id = "three", .address = "10.0.0.1:80", .priority = 3 });
    try testing.expect(only.pick().? == three);
    only.report(three, true, null);

    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    const spare = try pool.add(.{ .id = "spare", .address = "10.0.0.2:80", .priority = 1 });
    try testing.expect(try pool.remove("a"));
    // the higher level is all that is left: it must still be reachable
    try testing.expect(pool.pick().? == spare);
    pool.report(spare, true, null);
}

test "mutation 2026-11-25: ringOwner is null for other strategies and for an empty ring or table" {
    var rr: Pool = .init(testing.allocator, .{});
    defer rr.deinit();
    try addN(&rr, 3);
    try testing.expectEqual(null, rr.ringOwner("k")); // no ring for round_robin
    var ring: Pool = .init(testing.allocator, .{ .strategy = .ring_hash });
    defer ring.deinit();
    try testing.expectEqual(null, ring.ringOwner("k"));
    var mag: Pool = .init(testing.allocator, .{ .strategy = .maglev, .maglev_table_size = 13 });
    defer mag.deinit();
    try testing.expectEqual(null, mag.ringOwner("k"));
    // one member: every key is its
    const only = try mag.add(.{ .id = "only", .address = "10.0.0.1:80" });
    var buf: [16]u8 = undefined;
    for (0..40) |i| try testing.expect(mag.ringOwner(std.mem.print(&buf, "k{d}", .{i}) catch unreachable).? == only);
    // and an emptied pool has no owner again
    try testing.expect(try mag.remove("only"));
    try testing.expectEqual(null, mag.ringOwner("k"));
}

test "mutation 2026-11-25: maglev with more members than table slots still ends when every member is refused" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .maglev, .maglev_table_size = 3 });
    defer pool.deinit();
    try addN(&pool, 7);
    for (pool.upstreams.items) |u| u.down.store(true, .seq_cst);
    try testing.expectEqual(null, pool.pickByKey("k"));
}

/// The table of the weighted Maglev fill, straight from its doc comment: member `i` has
/// the permutation `(off_i + j * skip_i) mod M`; each round a member earns `weight` credit and
/// claims its next free slot once per `max_weight` of credit.
fn oracleTable(a: std.mem.Allocator, ids: []const []const u8, ws: []const u32, m: usize) ![]u32 {
    const none = std.math.maxInt(u32);
    const table = try a.alloc(u32, m);
    @memset(table, none);
    const next = try a.alloc(u64, ids.len);
    defer a.free(next);
    const credit = try a.alloc(u64, ids.len);
    defer a.free(credit);
    @memset(next, 0);
    @memset(credit, 0);
    var max_w: u64 = 1;
    for (ws) |w| max_w = @max(max_w, w);
    var filled: usize = 0;
    while (filled < m) {
        for (ids, 0..) |id, i| {
            credit[i] += ws[i];
            while (credit[i] >= max_w and filled < m) {
                credit[i] -= max_w;
                const off = std.hash.XxHash64.hash(0, id) % m;
                const skip = std.hash.XxHash64.hash(1, id) % (m - 1) + 1;
                while (true) {
                    const slot: usize = @intCast((off + next[i] * skip) % m);
                    next[i] += 1;
                    if (table[slot] == none) {
                        table[slot] = @intCast(i);
                        filled += 1;
                        break;
                    }
                }
            }
        }
    }
    return table;
}

test "mutation 2026-11-25: the Maglev table is exactly the weighted fill the doc comment describes" {
    const a = testing.allocator;
    {
        var pool: Pool = .init(a, .{ .strategy = .maglev, .maglev_table_size = 31 });
        defer pool.deinit();
        _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80", .weight = 1 });
        _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80", .weight = 2 });
        _ = try pool.add(.{ .id = "c", .address = "10.0.0.3:80", .weight = 3 });
        const want = try oracleTable(a, &.{ "a", "b", "c" }, &.{ 1, 2, 3 }, 31);
        defer a.free(want);
        try testing.expectEqualSlices(u32, want, pool.maglev);
    }
    {
        var pool: Pool = .init(a, .{ .strategy = .maglev, .maglev_table_size = 101 });
        defer pool.deinit();
        try addN(&pool, 5);
        const want = try oracleTable(a, &.{ "m0", "m1", "m2", "m3", "m4" }, &.{ 1, 1, 1, 1, 1 }, 101);
        defer a.free(want);
        try testing.expectEqualSlices(u32, want, pool.maglev);
    }
    {
        // an id whose second hash is 0 modulo M-1: its permutation step must still be 1
        var storage: [16]u8 = undefined;
        var found: []const u8 = "";
        var i: usize = 0;
        while (i < 5000) : (i += 1) {
            const id = std.mem.print(&storage, "z{d}", .{i}) catch unreachable;
            if (std.hash.XxHash64.hash(1, id) % 12 == 0) {
                found = id;
                break;
            }
        }
        try testing.expect(found.len > 0);
        var pool: Pool = .init(a, .{ .strategy = .maglev, .maglev_table_size = 13 });
        defer pool.deinit();
        _ = try pool.add(.{ .id = found, .address = "10.0.0.1:80" });
        _ = try pool.add(.{ .id = "other", .address = "10.0.0.2:80" });
        const want = try oracleTable(a, &.{ found, "other" }, &.{ 1, 1 }, 13);
        defer a.free(want);
        try testing.expectEqualSlices(u32, want, pool.maglev);
    }
}

test "mutation 2026-11-25: remove with a failing rebuild drops the ring (and the table), never keeps freed memory" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
    inline for (.{ up.Strategy.ring_hash, up.Strategy.maglev }) |strategy| {
        failing = std.testing.FailingAllocator.init(testing.allocator, .{});
        var pool: Pool = .init(failing.allocator(), .{ .strategy = strategy, .maglev_table_size = 7 });
        defer pool.deinit();
        try addN(&pool, 3);
        try testing.expect(try pool.remove("m0")); // grows the retired list: the next remove allocates only for the rebuild
        failing.fail_index = failing.alloc_index; // the rebuild's allocation fails
        try testing.expect(try pool.remove("m1"));
        try testing.expectEqual(@as(usize, 0), pool.ring.len);
        try testing.expectEqual(@as(usize, 0), pool.maglev.len);
        try testing.expectEqual(null, pool.ringOwner("k"));
        try testing.expectEqual(@as(usize, 1), pool.count());
    }
}

test "mutation 2026-11-25: weighted_round_robin with a down member splits exactly by the others' weights" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .weighted_round_robin });
    defer pool.deinit();
    _ = try pool.add(.{ .id = "a", .address = "10.0.0.1:80", .weight = 1 });
    _ = try pool.add(.{ .id = "b", .address = "10.0.0.2:80", .weight = 2 });
    const c = try pool.add(.{ .id = "c", .address = "10.0.0.3:80", .weight = 3 });
    c.down.store(true, .seq_cst);
    var hits = [_]usize{ 0, 0, 0 };
    for (0..30) |_| {
        const u = pool.pick().?;
        hits[u.id[0] - 'a'] += 1;
        pool.report(u, true, null);
    }
    try testing.expectEqual([_]usize{ 10, 20, 0 }, hits);
}

test "mutation 2026-11-25: least_request breaks a tie for the first member drawn" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .least_request, .seed = 11 });
    defer pool.deinit();
    try addN(&pool, 3);
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    for (0..40) |_| {
        const first = r.uintLessThan(usize, 3);
        _ = r.uintLessThan(usize, 2);
        const u = pool.pick().?;
        try testing.expect(u == pool.upstreams.items[first]);
        pool.report(u, true, null); // back to all-equal in_flight: a tie
    }
}

test "mutation 2026-11-25: the EWMA starts at the first sample and then smooths with alpha" {
    var pool: Pool = .init(testing.allocator, .{ .strategy = .ewma_latency, .ewma_alpha = 0.25 });
    defer pool.deinit();
    const a = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    var u = pool.pick().?;
    pool.report(u, true, 1000);
    try testing.expectEqual(@as(f64, 1000.0), a.ewma_ns);
    u = pool.pick().?;
    pool.report(u, true, 2000);
    try testing.expectApproxEqAbs(@as(f64, 0.25 * 2000 + 0.75 * 1000), a.ewma_ns, 1e-9);
}

test "mutation 2026-11-25: reportById of an unknown id is false and reports nothing" {
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    try addN(&pool, 2);
    try testing.expect(!pool.reportById("nobody", true, null));
    const u = pool.pick().?;
    try testing.expect(pool.reportById(u.id, true, null));
    try testing.expectEqual(@as(u32, 0), u.in_flight.load(.seq_cst));
}

const StepClock = struct {
    ns: u64 = 1000 * std.time.ns_per_ms,
    fn clock(c: *StepClock) resilience.Clock {
        return .{ .ctx = c, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) u64 {
        const c: *StepClock = @ptrCast(@alignCast(ctx.?));
        return c.ns;
    }
};

const SlowOp = struct {
    clk: *StepClock,
    calls: u32 = 0,
    pub fn call(self: *SlowOp, u: *Upstream) error{Boom}!u32 {
        _ = u;
        self.calls += 1;
        self.clk.ns += 5 * std.time.ns_per_ms;
        return 1;
    }
};

const FailOp = struct {
    calls: u32 = 0,
    pub fn call(self: *FailOp, u: *Upstream) error{Boom}!u32 {
        _ = u;
        self.calls += 1;
        return error.Boom;
    }
};

test "mutation 2026-11-25: call(): max_tries 0 still makes one attempt, and the RTT it reports is the elapsed time" {
    var clk: StepClock = .{};
    var pool: Pool = .init(testing.allocator, .{ .clock = clk.clock() });
    defer pool.deinit();
    const a = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    var op: SlowOp = .{ .clk = &clk };
    try testing.expectEqual(@as(u32, 1), try pool.call(&op, .{ .max_tries = 0 }));
    try testing.expectEqual(@as(u32, 1), op.calls);
    const st = pool.upstreamStats(a);
    try testing.expectEqual(@as(u64, 5 * std.time.ns_per_ms), st.latency.min_ns);
    try testing.expectEqual(@as(u64, 5 * std.time.ns_per_ms), st.latency.avg_ns);
    // a failing op with max_tries 0: exactly one attempt, its error, a counted failure
    var bad: FailOp = .{};
    try testing.expectError(error.Boom, pool.call(&bad, .{ .max_tries = 0 }));
    try testing.expectEqual(@as(u32, 1), bad.calls);
    try testing.expectEqual(@as(u64, 1), pool.upstreamStats(a).failures);
}

test "mutation 2026-11-25: stats: a down, drained or ejected member is not healthy" {
    var pool: Pool = .init(testing.allocator, .{});
    defer pool.deinit();
    try addN(&pool, 4);
    const items = pool.upstreams.items;
    try testing.expectEqual(@as(usize, 4), pool.stats().healthy);
    items[0].down.store(true, .seq_cst);
    try testing.expectEqual(@as(usize, 3), pool.stats().healthy);
    try testing.expect(!pool.upstreamStats(items[0]).healthy);
    items[1].ejected.store(true, .seq_cst);
    try testing.expectEqual(@as(usize, 2), pool.stats().healthy);
    try testing.expect(!pool.upstreamStats(items[1]).healthy);
    try testing.expect(pool.upstreamStats(items[1]).ejected);
    items[2].draining.store(true, .seq_cst);
    try testing.expectEqual(@as(usize, 1), pool.stats().healthy);
    try testing.expect(!pool.upstreamStats(items[2]).healthy);
    try testing.expect(pool.upstreamStats(items[3]).healthy);
}

test "mutation 2026-11-25: a bulkhead slot taken before the breaker refused is given back" {
    var clk: StepClock = .{};
    var pool: Pool = .init(testing.allocator, .{
        .max_per_upstream = 1,
        .breaker = .{ .failure_threshold = 1, .cooldown_ms = 1000, .clock = clk.clock() },
    });
    defer pool.deinit();
    const a = try pool.add(.{ .id = "a", .address = "10.0.0.1:80" });
    const u = pool.pick().?;
    pool.report(u, false, null); // trips the breaker
    try testing.expectEqual(.open, a.breaker.state());
    for (0..5) |_| try testing.expectEqual(null, pool.pick()); // each refusal must hand the slot back
    clk.ns += 1500 * std.time.ns_per_ms;
    const probe = pool.pick();
    try testing.expect(probe != null); // cooldown over: the probe needs a free bulkhead slot
    pool.report(probe.?, true, null);
}

// ── outlier detector ─────────────────────────────────────────────────────────

const oc_base: up.Outlier = .{ .interval_ns = 10 * s, .base_ejection_ns = 30 * s, .request_volume = 10, .minimum_hosts = 5 };

test "mutation 2026-11-25: outlier: a member under request_volume, or with no reports, is never ejected" {
    var pool: Pool = .init(testing.allocator, .{ .outlier = oc_base });
    defer pool.deinit();
    try addN(&pool, 6);
    pool.tick(0);
    // five qualifying members at 100 %, the sixth has 3 reports, all failed (under the volume)
    setWindow(&pool, &.{ 100, 100, 100, 100, 100, 3 }, &.{ 100, 100, 100, 100, 100, 0 });
    pool.tick(10 * s);
    try testing.expectEqual(@as(usize, 0), ejectedCount(&pool));
    // request_volume 0: a member without any report (0/0) is no data point
    var zero: Pool = .init(testing.allocator, .{ .outlier = .{ .interval_ns = 10 * s, .request_volume = 0, .minimum_hosts = 5 } });
    defer zero.deinit();
    try addN(&zero, 6);
    zero.tick(0);
    setWindow(&zero, &.{ 100, 100, 100, 100, 100, 0 }, &.{ 100, 100, 100, 100, 100, 0 });
    zero.tick(10 * s);
    try testing.expectEqual(@as(usize, 0), ejectedCount(&zero));
}

test "mutation 2026-11-25: outlier: exactly request_volume reports and exactly minimum_hosts members count" {
    var pool: Pool = .init(testing.allocator, .{ .outlier = oc_base });
    defer pool.deinit();
    try addN(&pool, 5);
    pool.tick(0);
    setWindow(&pool, &.{ 10, 10, 10, 10, 10 }, &.{ 10, 10, 10, 10, 0 });
    pool.tick(10 * s);
    try testing.expectEqual(@as(usize, 1), ejectedCount(&pool));
    try testing.expect(pool.upstreams.items[4].ejected.load(.seq_cst));
}

test "mutation 2026-11-25: outlier: the threshold uses the real mean and the standard deviation" {
    // one member at 80 % among four at 100 %: with stdev_factor 2.2 it is inside the band
    var wide: Pool = .init(testing.allocator, .{ .outlier = .{ .interval_ns = 10 * s, .request_volume = 10, .minimum_hosts = 5, .stdev_factor = 2.2 } });
    defer wide.deinit();
    try addN(&wide, 5);
    wide.tick(0);
    setWindow(&wide, &.{ 100, 100, 100, 100, 100 }, &.{ 100, 100, 100, 100, 80 });
    wide.tick(10 * s);
    try testing.expectEqual(@as(usize, 0), ejectedCount(&wide));
    // two members at 98 % among five at 100 %: inside the 1.9 sigma band, nobody is ejected
    var band: Pool = .init(testing.allocator, .{ .outlier = oc_base });
    defer band.deinit();
    try addN(&band, 7);
    band.tick(0);
    setWindow(&band, &.{ 100, 100, 100, 100, 100, 100, 100 }, &.{ 100, 100, 100, 100, 100, 98, 98 });
    band.tick(10 * s);
    try testing.expectEqual(@as(usize, 0), ejectedCount(&band));
}

test "mutation 2026-11-25: outlier: the cap counts members that are still ejected from earlier windows" {
    var pool: Pool = .init(testing.allocator, .{ .outlier = .{ .interval_ns = 10 * s, .base_ejection_ns = 20 * s, .request_volume = 10, .minimum_hosts = 5, .max_ejection_percent = 10 } });
    defer pool.deinit();
    try addN(&pool, 10);
    pool.tick(0);
    var total: [10]u32 = @splat(100);
    var ok: [10]u32 = @splat(100);
    ok[0] = 0;
    ok[1] = 0;
    setWindow(&pool, &total, &ok);
    pool.tick(10 * s);
    try testing.expectEqual(@as(usize, 1), ejectedCount(&pool));
    try testing.expect(pool.upstreams.items[0].ejected.load(.seq_cst));
    // next window: the first is still out (until 30 s) and sends nothing; the second is bad
    total[0] = 0;
    setWindow(&pool, &total, &ok);
    pool.tick(20 * s);
    try testing.expectEqual(@as(usize, 1), ejectedCount(&pool)); // the cap is 1: the second stays in
    try testing.expect(!pool.upstreams.items[1].ejected.load(.seq_cst));
}

test "mutation 2026-11-25: outlier: an ejected member is not ejected again; a repeat offender waits twice as long" {
    var pool: Pool = .init(testing.allocator, .{ .outlier = .{ .interval_ns = 10 * s, .base_ejection_ns = 30 * s, .request_volume = 10, .minimum_hosts = 5, .max_ejection_percent = 50 } });
    defer pool.deinit();
    try addN(&pool, 6);
    const x = pool.upstreams.items[0];
    pool.tick(0);
    const total: [6]u32 = @splat(100);
    var ok: [6]u32 = @splat(100);
    ok[0] = 0;
    setWindow(&pool, &total, &ok);
    pool.tick(10 * s);
    try testing.expect(x.ejected.load(.seq_cst));
    try testing.expectEqual(@as(u32, 1), x.ejections);
    try testing.expectEqual(@as(u64, 40 * s), x.eject_until_ns);
    // still ejected and still reported bad (as if it sent traffic): nothing changes
    for ([_]u64{ 20 * s, 30 * s }) |t| {
        setWindow(&pool, &total, &ok);
        pool.tick(t);
        try testing.expectEqual(@as(u32, 1), x.ejections);
        try testing.expectEqual(@as(u64, 40 * s), x.eject_until_ns);
    }
    // back at 40 s and bad again: the second ejection lasts base x 2
    setWindow(&pool, &total, &ok);
    pool.tick(40 * s);
    try testing.expect(x.ejected.load(.seq_cst));
    try testing.expectEqual(@as(u32, 2), x.ejections);
    try testing.expectEqual(@as(u64, 100 * s), x.eject_until_ns);
}

test "mutation 2026-11-25: outlier: a member earns back one ejection per clean window" {
    var pool: Pool = .init(testing.allocator, .{ .outlier = .{ .interval_ns = 10 * s, .base_ejection_ns = 30 * s, .request_volume = 10, .minimum_hosts = 5, .max_ejection_percent = 50 } });
    defer pool.deinit();
    try addN(&pool, 6);
    const x = pool.upstreams.items[0];
    pool.tick(0);
    const total: [6]u32 = @splat(100);
    var bad: [6]u32 = @splat(100);
    bad[0] = 0;
    const good: [6]u32 = @splat(100);
    setWindow(&pool, &total, &bad);
    pool.tick(10 * s);
    try testing.expectEqual(@as(u32, 1), x.ejections);
    for ([_]u64{ 20 * s, 30 * s, 40 * s }) |t| {
        setWindow(&pool, &total, &good);
        pool.tick(t);
    }
    try testing.expect(!x.ejected.load(.seq_cst));
    try testing.expectEqual(@as(u32, 0), x.ejections);
}

test "mutation 2026-11-25: outlier: the window restarts at each evaluation and its counters are cleared" {
    var pool: Pool = .init(testing.allocator, .{ .outlier = oc_base });
    defer pool.deinit();
    try addN(&pool, 6);
    pool.tick(0);
    const total: [6]u32 = @splat(100);
    const ok: [6]u32 = @splat(100);
    setWindow(&pool, &total, &ok);
    pool.tick(10 * s); // evaluation
    for (pool.upstreams.items) |u| try testing.expectEqual(@as(u32, 0), u.win_total.load(.monotonic));
    setWindow(&pool, &total, &ok);
    pool.tick(11 * s); // only 1 s into the next window: no evaluation, counters stay
    for (pool.upstreams.items) |u| try testing.expectEqual(@as(u32, 100), u.win_total.load(.monotonic));
    pool.tick(19 * s);
    for (pool.upstreams.items) |u| try testing.expectEqual(@as(u32, 100), u.win_total.load(.monotonic));
    pool.tick(20 * s);
    for (pool.upstreams.items) |u| try testing.expectEqual(@as(u32, 0), u.win_total.load(.monotonic));
}

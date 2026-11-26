// SPDX-License-Identifier: MIT
//
//! Concurrency tests for `readthrough` — real OS threads throughout (via
//! `std.Thread.spawn`), each with its own `std.Io.Threaded` for the futex. The
//! single-flight rendezvous is made deterministic (not timing-dependent) with a
//! **gate**: the leader blocks *inside* the loader until the test has observed
//! that every follower has coalesced, so "the loader ran exactly once" is a hard
//! guarantee, never a lucky interleaving. `testing.allocator` (leak-checking)
//! proves no leaked `Call`, in-flight key, or value across the concurrent
//! lifecycle. Run under both Debug and ReleaseFast.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const rt = @import("root.zig");

/// A loader that blocks inside `load` until `gate` is opened by the test, and
/// counts its invocations. This turns the single-flight window into something
/// the test controls exactly: while the leader is parked here, every other
/// caller must find the in-flight `Call` and coalesce.
const GatedLoader = struct {
    io: std.Io,
    value: []const u8,
    calls: std.atomic.Value(u64) = .init(0),
    gate: std.atomic.Value(u32) = .init(0),

    fn open(self: *GatedLoader) void {
        self.gate.store(1, .release);
        self.io.futexWake(u32, &self.gate.raw, std.math.maxInt(u32));
    }
    fn loadFn(ctx: ?*anyopaque, key: []const u8) anyerror!rt.LoadOutcome {
        const self: *GatedLoader = @ptrCast(@alignCast(ctx.?));
        _ = key;
        _ = self.calls.fetchAdd(1, .monotonic);
        while (self.gate.load(.acquire) == 0) {
            self.io.futexWaitTimeout(u32, &self.gate.raw, 0, .{ .duration = .{
                .raw = .fromMilliseconds(50),
                .clock = .awake,
            } }) catch {};
        }
        return .{ .value = self.value };
    }
    fn loader(self: *GatedLoader) rt.Loader {
        return .{ .ctx = self, .load = loadFn };
    }
};

const n_threads = 8;

const GetWorker = struct {
    cache: *rt.Cache,
    key: []const u8,
    want: []const u8,
    ok: bool = false,

    fn run(self: *GetWorker) void {
        const res = self.cache.get(self.key) catch return;
        defer self.cache.free(res);
        switch (res) {
            .value => |v| self.ok = std.mem.eql(u8, v, self.want),
            .missing => self.ok = false,
        }
    }
};

/// Spin/park until `pred` holds or a generous deadline passes (a fail-safe so a
/// bug can never hang the suite — the assertion afterward still catches it).
fn waitUntil(io: std.Io, dummy: *std.atomic.Value(u32), pred: anytype) void {
    var spins: usize = 0;
    while (!pred.check() and spins < 4000) : (spins += 1) {
        io.futexWaitTimeout(u32, &dummy.raw, 0, .{ .duration = .{
            .raw = .fromMilliseconds(1),
            .clock = .awake,
        } }) catch {};
    }
}

test "single-flight: N concurrent gets of the same key ⇒ the loader runs EXACTLY once" {
    // This is the core correctness claim AND the permanent positive control:
    // it asserts `calls == 1` and `coalesced == n_threads - 1`. Deleting the
    // in-flight dedup in `Cache.get` turns both RED (calls == n_threads,
    // coalesced == 0) — that is exactly what proves single-flight is real.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var dummy = std.atomic.Value(u32).init(0);

    // Repeat to shake out races (bounded — no large allocations).
    var iter: usize = 0;
    while (iter < 50) : (iter += 1) {
        var gl = GatedLoader{ .io = io, .value = "v" };
        var c = rt.Cache.init(testing.allocator, .{
            .io = io,
            .loader = gl.loader(),
            .max_bytes = 1 << 20,
            .max_entries = 64,
        });
        defer c.deinit();

        var workers: [n_threads]GetWorker = undefined;
        var threads: [n_threads]std.Thread = undefined;
        for (&workers) |*w| w.* = .{ .cache = &c, .key = "k", .want = "v" };
        for (&threads, &workers) |*t, *w| t.* = try std.Thread.spawn(.{}, GetWorker.run, .{w});

        // Wait until the leader is parked in the loader and every other caller
        // has coalesced, THEN release the gate. Now single-flight is provable,
        // not incidental.
        const Pred = struct {
            c: *rt.Cache,
            fn check(self: @This()) bool {
                return self.c.getStats().coalesced >= n_threads - 1;
            }
        };
        waitUntil(io, &dummy, Pred{ .c = &c });
        gl.open();

        for (&threads) |t| t.join();

        for (&workers) |*w| try testing.expect(w.ok); // all N saw "v"
        const s = c.getStats();
        try testing.expectEqual(@as(u64, 1), gl.calls.load(.monotonic)); // loader ran once
        try testing.expectEqual(@as(u64, 1), s.loads);
        try testing.expectEqual(@as(u64, n_threads - 1), s.coalesced);
    }
}

test "single-flight followers all receive an independently-owned copy (no leak, no double-free)" {
    // The leak-checking allocator is the assertion here: N threads each get and
    // free their own copy of the coalesced value.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var dummy = std.atomic.Value(u32).init(0);

    var gl = GatedLoader{ .io = io, .value = "shared-payload" };
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = gl.loader(),
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();

    var workers: [n_threads]GetWorker = undefined;
    var threads: [n_threads]std.Thread = undefined;
    for (&workers) |*w| w.* = .{ .cache = &c, .key = "k", .want = "shared-payload" };
    for (&threads, &workers) |*t, *w| t.* = try std.Thread.spawn(.{}, GetWorker.run, .{w});

    const Pred = struct {
        c: *rt.Cache,
        fn check(self: @This()) bool {
            return self.c.getStats().coalesced >= n_threads - 1;
        }
    };
    waitUntil(io, &dummy, Pred{ .c = &c });
    gl.open();
    for (&threads) |t| t.join();
    for (&workers) |*w| try testing.expect(w.ok);
}

test "invalidate during an in-flight load: waiters get the value, but the cache is NOT populated" {
    // Contract: an invalidation while a load is in flight still delivers the
    // loaded value to the coalesced callers of THAT load, but does not write it
    // to the cache — so the very next get reloads (the invalidation is not lost).
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var dummy = std.atomic.Value(u32).init(0);

    var gl = GatedLoader{ .io = io, .value = "v" };
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = gl.loader(),
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();

    var w = GetWorker{ .cache = &c, .key = "k", .want = "v" };
    const t = try std.Thread.spawn(.{}, GetWorker.run, .{&w});

    // Wait until the leader has entered the loader (loads == 1), then invalidate
    // the key mid-flight and release the gate.
    const Pred = struct {
        c: *rt.Cache,
        fn check(self: @This()) bool {
            return self.c.getStats().loads >= 1;
        }
    };
    waitUntil(io, &dummy, Pred{ .c = &c });
    c.invalidate("k"); // poisons the in-flight Call
    gl.open();
    t.join();

    try testing.expect(w.ok); // the in-flight caller still got "v"
    try testing.expectEqual(@as(u64, 1), gl.calls.load(.monotonic));

    // The poisoned result was not cached → the next get reloads.
    const again = try c.get("k");
    defer c.free(again);
    try testing.expectEqualStrings("v", again.value);
    try testing.expectEqual(@as(u64, 2), gl.calls.load(.monotonic)); // reloaded
}

test "concurrent mixed keys: no lock-up, no leak, every key resolves" {
    // A soak over many keys and threads with an immediate (non-gated) loader —
    // exercises the leader/follower handoff, in-flight insert/remove, and cache
    // stores under real contention. Small enough never to stress memory.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Immediate = struct {
        fn loadFn(ctx: ?*anyopaque, key: []const u8) anyerror!rt.LoadOutcome {
            _ = ctx;
            return .{ .value = key }; // value == key, so each thread can self-check
        }
    };
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = .{ .ctx = null, .load = Immediate.loadFn },
        .max_bytes = 1 << 20,
        .max_entries = 256,
    });
    defer c.deinit();

    const Soak = struct {
        cache: *rt.Cache,
        seed: u64,
        ok: bool = false,
        fn run(self: *@This()) void {
            var s = self.seed;
            var buf: [24]u8 = undefined;
            var i: usize = 0;
            while (i < 500) : (i += 1) {
                s = s *% 6364136223846793005 +% 1442695040888963407;
                const id = s % 40; // 40 shared keys → heavy coalescing + eviction
                const key = std.mem.print(&buf, "key{d}", .{id}) catch unreachable;
                const res = self.cache.get(key) catch return;
                defer self.cache.free(res);
                switch (res) {
                    .value => |v| if (!std.mem.eql(u8, v, key)) return,
                    .missing => return,
                }
            }
            self.ok = true;
        }
    };
    var soaks: [n_threads]Soak = undefined;
    var threads: [n_threads]std.Thread = undefined;
    for (&soaks, 0..) |*sk, i| sk.* = .{ .cache = &c, .seed = @intCast(i + 1) };
    for (&threads, &soaks) |*t, *sk| t.* = try std.Thread.spawn(.{}, Soak.run, .{sk});
    for (&threads) |t| t.join();
    for (&soaks) |*sk| try testing.expect(sk.ok);
}

test "a leader that OOMs on the result copy hands EVERY follower the error, not an empty value" {
    // The follower half of the fail-open defect: the leader used to substitute
    // `&[_]u8{}` for a failed result copy and publish it, so all N coalesced
    // callers got `.value` with `len == 0` — indistinguishable from a backend
    // that really returned "" — while the cache held the correct bytes and the
    // whole thing self-healed on the next get. Every participant must instead
    // see `error.OutOfMemory`.
    const value_len = 4093;
    const big = strRepeat("y", value_len);

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var dummy = std.atomic.Value(u32).init(0);

    var fa: rt.SizeFailAllocator = .{ .child = testing.allocator, .fail_len = value_len };
    var gl = GatedLoader{ .io = io, .value = big };
    var c = rt.Cache.init(fa.allocator(), .{
        .io = io,
        .loader = gl.loader(),
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();

    const Probe = struct {
        cache: *rt.Cache,
        /// null = `get` returned a value/missing rather than an error.
        err: ?anyerror = null,
        empty_value: bool = false,
        fn run(self: *@This()) void {
            const res = self.cache.get("k") catch |e| {
                self.err = e;
                return;
            };
            defer self.cache.free(res);
            self.empty_value = (res == .value and res.value.len == 0);
        }
    };

    var probes: [n_threads]Probe = undefined;
    var threads: [n_threads]std.Thread = undefined;
    for (&probes) |*p| p.* = .{ .cache = &c };
    for (&threads, &probes) |*t, *p| t.* = try std.Thread.spawn(.{}, Probe.run, .{p});

    const Pred = struct {
        c: *rt.Cache,
        fn check(self: @This()) bool {
            return self.c.getStats().coalesced >= n_threads - 1;
        }
    };
    waitUntil(io, &dummy, Pred{ .c = &c });
    gl.open();
    for (&threads) |t| t.join();

    // The rig really did coalesce (otherwise this proves nothing about
    // followers) and really did refuse the copy.
    try testing.expectEqual(@as(u64, n_threads - 1), c.getStats().coalesced);
    try testing.expect(fa.denied.load(.monotonic) > 0);

    for (&probes) |*p| {
        try testing.expect(!p.empty_value);
        try testing.expectEqual(@as(?anyerror, error.OutOfMemory), p.err);
    }
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

const TestClock = struct {
    t: std.atomic.Value(i64) = .init(0),
    fn nowFn(ctx: *anyopaque) i64 {
        return @as(*TestClock, @ptrCast(@alignCast(ctx))).t.load(.monotonic);
    }
    fn clock(self: *TestClock) rt.Clock {
        return .{ .ctx = self, .now_fn = nowFn };
    }
};

test "refresh_after_ns: while one caller reloads a due entry, every other get is served the old value at once" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var dummy = std.atomic.Value(u32).init(0);

    var gl = GatedLoader{ .io = io, .value = "v1" };
    var clk = TestClock{};
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = gl.loader(),
        .clock = clk.clock(),
        .ttl_ns = 1000,
        .refresh_after_ns = 10,
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();

    gl.open();
    c.free(try c.get("k")); // prime with "v1"
    gl.gate.store(0, .release); // the next load parks
    gl.value = "v2";
    clk.t.store(11, .monotonic); // due, far from expiry

    var w = GetWorker{ .cache = &c, .key = "k", .want = "v2" };
    const t = try std.Thread.spawn(.{}, GetWorker.run, .{&w});
    const Pred = struct {
        c: *rt.Cache,
        fn check(self: @This()) bool {
            return self.c.getStats().refreshes >= 1;
        }
    };
    waitUntil(io, &dummy, Pred{ .c = &c });

    // The refresher is parked inside the loader: these must not block.
    for (0..5) |_| {
        const r = try c.get("k");
        defer c.free(r);
        try testing.expectEqualStrings("v1", r.value);
    }
    try testing.expectEqual(@as(u64, 2), gl.calls.load(.monotonic));
    gl.open();
    t.join();
    try testing.expect(w.ok); // the refresher itself got the new value
    const after = try c.get("k");
    defer c.free(after);
    try testing.expectEqualStrings("v2", after.value);
    try testing.expectEqual(@as(u64, 2), gl.calls.load(.monotonic));
}

// ── delta mutation run 2026-11-25 (whole-module) ────────────────────────────

/// A bulk loader for the stats and follower tests: key "n..." is missing, every
/// other key loads "v"; a gate (optional) parks the call, `calls` counts it.
const MutBulk = struct {
    io: std.Io,
    calls: std.atomic.Value(u64) = .init(0),
    gate: std.atomic.Value(u32) = .init(1),

    fn open(self: *MutBulk) void {
        self.gate.store(1, .release);
        self.io.futexWake(u32, &self.gate.raw, std.math.maxInt(u32));
    }
    fn loadFn(ctx: ?*anyopaque, keys: []const []const u8, out: []rt.LoadOutcome) anyerror!void {
        const self: *MutBulk = @ptrCast(@alignCast(ctx.?));
        _ = self.calls.fetchAdd(1, .monotonic);
        while (self.gate.load(.acquire) == 0) {
            self.io.futexWaitTimeout(u32, &self.gate.raw, 0, .{ .duration = .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            } }) catch {};
        }
        for (keys, out) |k, *o| o.* = if (k[0] == 'n') .missing else .{ .value = "v" };
    }
    fn bulk(self: *MutBulk) rt.BulkLoader {
        return .{ .ctx = self, .load = loadFn };
    }
};

fn singleV(_: ?*anyopaque, _: []const u8) anyerror!rt.LoadOutcome {
    return .{ .value = "v" };
}

test "mutation 2026-11-25: getAll counts hits, negative hits, misses and one load per bulk call" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bl = MutBulk{ .io = io };
    var clk = TestClock{};
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = .{ .load = singleV },
        .bulk_loader = bl.bulk(),
        .clock = clk.clock(),
        .ttl_ns = 1000,
        .negative_ttl_ns = 1000,
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();
    const keys = [_][]const u8{ "a", "n1" };
    const r1 = try c.getAll(&keys);
    c.freeAll(r1);
    var st = c.getStats();
    try testing.expectEqual(@as(u64, 2), st.misses);
    try testing.expectEqual(@as(u64, 1), st.loads);
    try testing.expectEqual(@as(u64, 0), st.hits);
    const r2 = try c.getAll(&keys);
    c.freeAll(r2);
    st = c.getStats();
    try testing.expectEqual(@as(u64, 2), st.hits); // the value and the cached "missing"
    try testing.expectEqual(@as(u64, 1), st.negative_hits);
    try testing.expectEqual(@as(u64, 2), st.misses);
    try testing.expectEqual(@as(u64, 1), st.loads);
    try testing.expectEqual(@as(u64, 1), bl.calls.load(.monotonic));
}

test "mutation 2026-11-25: refresh() counts a refresh and coalesces onto a load in flight" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var dummy = std.atomic.Value(u32).init(0);
    var gl = GatedLoader{ .io = io, .value = "v1" };
    var clk = TestClock{};
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = gl.loader(),
        .clock = clk.clock(),
        .ttl_ns = 1000,
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();

    // An explicit refresh of an idle key is a load and a refresh.
    gl.open();
    try c.refresh("k");
    try testing.expectEqual(@as(u64, 1), c.getStats().refreshes);
    try testing.expectEqual(@as(u64, 1), c.getStats().loads);

    // A refresh that meets a load in flight joins it instead of loading again.
    for (0..4) |_| {
        c.invalidate("k");
        gl.gate.store(0, .release);
        var w = GetWorker{ .cache = &c, .key = "k", .want = "v1" };
        const t = try std.Thread.spawn(.{}, GetWorker.run, .{&w});
        const Pred = struct {
            gl: *GatedLoader,
            n: u64,
            fn check(self: @This()) bool {
                return self.gl.calls.load(.monotonic) >= self.n;
            }
        };
        const before = gl.calls.load(.monotonic);
        waitUntil(io, &dummy, Pred{ .gl = &gl, .n = before + 1 });
        const Refresher = struct {
            cache: *rt.Cache,
            fn run(self: *@This()) void {
                self.cache.refresh("k") catch {};
            }
        };
        var rf = Refresher{ .cache = &c };
        const t2 = try std.Thread.spawn(.{}, Refresher.run, .{&rf});
        std.Io.sleep(io, .fromMilliseconds(30), .awake) catch {};
        gl.open();
        t.join();
        t2.join();
        try testing.expect(w.ok);
    }
}

test "mutation 2026-11-25: getAll followers of another thread's call, and a thread that follows getAll's bulk call, get the value" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var dummy = std.atomic.Value(u32).init(0);
    var gl = GatedLoader{ .io = io, .value = "v1" };
    var bl = MutBulk{ .io = io, .gate = .init(0) };
    var clk = TestClock{};
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = gl.loader(),
        .bulk_loader = bl.bulk(),
        .clock = clk.clock(),
        .ttl_ns = 1000,
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();
    const Pred = struct {
        calls: *std.atomic.Value(u64),
        fn check(self: @This()) bool {
            return self.calls.load(.monotonic) >= 1;
        }
    };

    // (1) getAll follows a single get that is parked in its loader.
    var w = GetWorker{ .cache = &c, .key = "k", .want = "v1" };
    const t = try std.Thread.spawn(.{}, GetWorker.run, .{&w});
    waitUntil(io, &dummy, Pred{ .calls = &gl.calls });
    const AllWorker = struct {
        cache: *rt.Cache,
        keys: []const []const u8,
        ok: bool = false,
        fn run(self: *@This()) void {
            const res = self.cache.getAll(self.keys) catch return;
            defer self.cache.freeAll(res);
            self.ok = res.len == self.keys.len and res[0] == .value and std.mem.eql(u8, res[0].value, "v1");
        }
    };
    const only_k = [_][]const u8{"k"};
    var aw = AllWorker{ .cache = &c, .keys = &only_k };
    const t2 = try std.Thread.spawn(.{}, AllWorker.run, .{&aw});
    std.Io.sleep(io, .fromMilliseconds(30), .awake) catch {};
    gl.open();
    t.join();
    t2.join();
    try testing.expect(w.ok);
    try testing.expect(aw.ok);

    // (2) a get follows getAll's bulk call that is parked in the bulk loader.
    const only_x = [_][]const u8{"x"};
    var lead = AllWorker{ .cache = &c, .keys = &only_x };
    lead.ok = false;
    const t3 = try std.Thread.spawn(.{}, AllWorker.run, .{&lead});
    waitUntil(io, &dummy, Pred{ .calls = &bl.calls });
    var fw = GetWorker{ .cache = &c, .key = "x", .want = "v" };
    const t4 = try std.Thread.spawn(.{}, GetWorker.run, .{&fw});
    std.Io.sleep(io, .fromMilliseconds(30), .awake) catch {};
    bl.open();
    t3.join();
    t4.join();
    try testing.expect(fw.ok);
}

test "mutation 2026-11-25: a refresh-tagged entry shorter than its 8-byte deadline is corrupt; exactly the deadline is an empty value" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var clk = TestClock{};
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = .{ .load = singleV },
        .clock = clk.clock(),
        .ttl_ns = 1000,
        .refresh_after_ns = 10,
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();
    const now: i64 = clk.t.load(.monotonic);
    c.store.put("short", "R\x01\x02\x03", now, 1000, c.generation);
    try testing.expectError(error.CorruptEntry, c.get("short"));
    var exact: [9]u8 = undefined;
    exact[0] = 'R';
    std.mem.writeInt(i64, exact[1..9], std.math.maxInt(i64), .little); // never due
    c.store.put("exact", &exact, now, 1000, c.generation);
    const r = try c.get("exact");
    defer c.free(r);
    try testing.expectEqual(@as(usize, 0), r.value.len);
}

test "mutation 2026-11-25: a value stored with refresh_after_ns still expires at its TTL" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var clk = TestClock{};
    var calls = std.atomic.Value(u64).init(0);
    const L = struct {
        fn load(ctx: ?*anyopaque, _: []const u8) anyerror!rt.LoadOutcome {
            const n: *std.atomic.Value(u64) = @ptrCast(@alignCast(ctx.?));
            _ = n.fetchAdd(1, .monotonic);
            return .{ .value = "v" };
        }
    };
    var c = rt.Cache.init(testing.allocator, .{
        .io = io,
        .loader = .{ .ctx = &calls, .load = L.load },
        .clock = clk.clock(),
        .ttl_ns = 1000,
        .refresh_after_ns = 400,
        .max_bytes = 1 << 20,
        .max_entries = 64,
    });
    defer c.deinit();
    clk.t.store(1, .monotonic);
    c.free(try c.get("k"));
    clk.t.store(300, .monotonic); // within the TTL and before the refresh deadline: a plain hit
    c.free(try c.get("k"));
    try testing.expectEqual(@as(u64, 1), c.getStats().hits);
    try testing.expectEqual(@as(u64, 1), calls.load(.monotonic));
    clk.t.store(5000, .monotonic); // far past the TTL: a miss that loads again
    c.free(try c.get("k"));
    try testing.expectEqual(@as(u64, 2), c.getStats().misses);
    try testing.expectEqual(@as(u64, 2), calls.load(.monotonic));
}

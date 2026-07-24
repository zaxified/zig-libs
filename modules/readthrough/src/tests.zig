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
                const key = std.fmt.bufPrint(&buf, "key{d}", .{id}) catch unreachable;
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

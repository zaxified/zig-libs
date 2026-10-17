// SPDX-License-Identifier: MIT

//! Streaming-quantile `Summary` (Prometheus `summary` metric type).
//!
//! Standalone instrument; behaviour matches client_golang `Summary` with
//! `Objectives` (prometheus/summary.go v1.24.1) on top of the CKMS targeted
//! quantile stream of beorn7/perks `quantile` (stream.go v1.0.1). Both are
//! MIT/Apache; this file is an independent Zig implementation of the same
//! algorithm, checked against them as black-box oracles (see
//! `tools/go_summary_oracle`).
//!
//! What it does:
//!   * `observe(v, now_ns)` adds a value. `_sum` and `_count` are cumulative
//!     forever; the quantiles cover a sliding window of `max_age_ns`.
//!   * The window is `age_buckets` quantile streams. EVERY observation is
//!     inserted into EVERY stream (client_golang does the same: the perks
//!     stream cannot be merged); the head stream answers; each
//!     `max_age_ns / age_buckets` the head is reset and the next stream
//!     becomes the head. An observation made at `t` is therefore visible in
//!     the quantiles while `now <= t + max_age` (up to one bucket longer when
//!     the head had just rotated) and gone after.
//!   * Observations are appended to a buffer of `buf_cap` values and only
//!     pushed into the streams when it is full, on rotation and on `snapshot`.
//!
//! Time is injected: every call takes `now_ns` (any monotonic u64 origin).
//! The window starts at the FIRST call that carries a time (client_golang
//! starts it at construction, which has no clock here). Times going
//! backwards are treated as "no time has passed".
//!
//! Deviations from client_golang:
//!   * NaN observations count toward `_count` and poison `_sum` (as in Go) but
//!     are NOT inserted into the quantile streams (Go inserts them and sorts
//!     them with an inconsistent order; the result is unspecified there).
//!   * The buffer flush runs inline in the observing thread (Go hands it to
//!     a goroutine).
//!   * If the allocator fails while growing a stream, that observation is not
//!     recorded in the quantile streams (`droppedInserts` counts it); `_sum`
//!     and `_count` are still updated.
//!   * Thread safety: ONE spinlock per Summary guards everything.

const std = @import("std");

/// One targeted quantile: `quantile` in [0, 1] with an allowed absolute rank
/// error `epsilon` in [0, 1) (the reported value is the φ-quantile for some
/// φ in `quantile ± epsilon`).
pub const Objective = struct { quantile: f64, epsilon: f64 };

pub const Options = struct {
    /// Empty: only `_sum` / `_count` are kept (no streams, no buffer).
    objectives: []const Objective = &.{},
    max_age_ns: u64 = 10 * std.time.ns_per_min,
    age_buckets: u8 = 5,
    buf_cap: u32 = 500,
};

pub const InitError = error{
    OutOfMemory,
    InvalidQuantile,
    InvalidEpsilon,
    InvalidAgeBuckets,
    InvalidBufCap,
    /// `max_age_ns / age_buckets` must be at least 1 ns.
    InvalidMaxAge,
};

pub const Snapshot = struct { count: u64, sum: f64 };

/// perks' per-stream sample buffer (`make(Samples, 0, 500)`), independent of
/// the Summary's `BufCap`; it decides when a stream flushes and compresses.
const stream_buf_cap = 500;

const Sample = struct { value: f64, width: f64, delta: f64 };

/// perks `quantile.Stream` built by `NewTargeted`.
const Stream = struct {
    /// Total width of the compressed list `l`.
    n: f64 = 0,
    l: std.ArrayList(Sample) = .empty,
    /// Unflushed raw values (capacity `stream_buf_cap`, preallocated).
    b: std.ArrayList(f64) = .empty,
    sorted: bool = true,

    fn deinit(s: *Stream, gpa: std.mem.Allocator) void {
        s.l.deinit(gpa);
        s.b.deinit(gpa);
    }

    /// The CKMS invariant f(r, n) for targeted quantiles.
    fn invariant(s: *const Stream, targets: []const Objective, r: f64) f64 {
        var m: f64 = std.math.floatMax(f64);
        for (targets) |t| {
            const f = if (t.quantile * s.n <= r)
                (2 * t.epsilon * r) / t.quantile
            else
                (2 * t.epsilon * (s.n - r)) / (1 - t.quantile);
            if (f < m) m = f;
        }
        return m;
    }

    fn insert(s: *Stream, gpa: std.mem.Allocator, targets: []const Objective, v: f64) !void {
        s.b.appendAssumeCapacity(v);
        s.sorted = false;
        if (s.b.items.len == stream_buf_cap) try s.flush(gpa, targets);
    }

    fn maybeSort(s: *Stream) void {
        if (!s.sorted) {
            s.sorted = true;
            std.sort.pdq(f64, s.b.items, {}, std.sort.asc(f64));
        }
    }

    fn flush(s: *Stream, gpa: std.mem.Allocator, targets: []const Objective) !void {
        s.maybeSort();
        // Whatever happens, the buffer is spent (a failed merge has already
        // moved the prefix it managed into `l`).
        defer s.b.clearRetainingCapacity();
        try s.merge(gpa, targets, s.b.items);
    }

    /// Merge sorted raw values into the list, then compress.
    fn merge(s: *Stream, gpa: std.mem.Allocator, targets: []const Objective, values: []const f64) !void {
        var r: f64 = 0;
        var i: usize = 0;
        for (values) |v| {
            var placed = false;
            while (i < s.l.items.len) : (i += 1) {
                const c = s.l.items[i];
                if (c.value > v) {
                    try s.l.insert(gpa, i, .{
                        .value = v,
                        .width = 1,
                        .delta = @max(0, @floor(s.invariant(targets, r)) - 1),
                    });
                    i += 1;
                    placed = true;
                    break;
                }
                r += c.width;
            }
            if (!placed) {
                try s.l.append(gpa, .{ .value = v, .width = 1, .delta = 0 });
                i += 1;
            }
            s.n += 1;
            r += 1;
        }
        s.compress(targets);
    }

    fn compress(s: *Stream, targets: []const Objective) void {
        if (s.l.items.len < 2) return;
        var xi = s.l.items.len - 1;
        var x = s.l.items[xi];
        var r = s.n - 1 - x.width;
        var i = s.l.items.len - 1;
        while (i > 0) {
            i -= 1;
            const c = s.l.items[i];
            if (c.width + x.width + x.delta <= s.invariant(targets, r)) {
                x.width += c.width;
                s.l.items[xi] = x;
                _ = s.l.orderedRemove(i);
                xi -= 1;
            } else {
                x = c;
                xi = i;
            }
            r -= c.width;
        }
    }

    fn count(s: *const Stream) usize {
        return s.b.items.len + @as(usize, @intFromFloat(s.n));
    }

    fn reset(s: *Stream) void {
        s.l.clearRetainingCapacity();
        s.n = 0;
        s.b.clearRetainingCapacity();
    }

    /// Value for quantile `q`; the stream must not be empty (`count() > 0`).
    fn query(s: *Stream, gpa: std.mem.Allocator, targets: []const Objective, q: f64) f64 {
        if (s.l.items.len == 0) {
            // Nothing flushed yet: answer exactly from the sorted buffer.
            const len = s.b.items.len;
            var i: usize = @intFromFloat(@ceil(@as(f64, @floatFromInt(len)) * q));
            if (i > 0) i -= 1;
            s.maybeSort();
            return s.b.items[i];
        }
        s.flush(gpa, targets) catch {};
        var t = @ceil(q * s.n);
        t += @ceil(s.invariant(targets, t) / 2);
        var p = s.l.items[0];
        var r: f64 = 0;
        for (s.l.items[1..]) |c| {
            r += p.width;
            if (r + c.width + c.delta > t) return p.value;
            p = c;
        }
        return p.value;
    }
};

pub const Summary = struct {
    gpa: std.mem.Allocator,
    lock: std.atomic.Mutex = .unlocked,
    /// Owned copy.
    objectives: []Objective,
    bucket_ns: u64,
    streams: []Stream,
    head: usize = 0,
    /// Window anchor: set by the first timed call.
    anchored: bool = false,
    /// End of the head stream's current bucket.
    expires_ns: u64 = 0,
    hot: std.ArrayList(f64) = .empty,
    sum_: f64 = 0,
    count_: u64 = 0,
    dropped: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, options: Options) InitError!Summary {
        for (options.objectives) |o| {
            if (!(o.quantile >= 0 and o.quantile <= 1)) return error.InvalidQuantile;
            if (!(o.epsilon >= 0 and o.epsilon < 1)) return error.InvalidEpsilon;
        }
        if (options.age_buckets < 1) return error.InvalidAgeBuckets;
        if (options.buf_cap < 1) return error.InvalidBufCap;
        const bucket_ns = options.max_age_ns / options.age_buckets;
        if (bucket_ns < 1) return error.InvalidMaxAge;

        const objectives = try gpa.dupe(Objective, options.objectives);
        errdefer gpa.free(objectives);
        const n_streams: usize = if (objectives.len == 0) 0 else options.age_buckets;
        const streams = try gpa.alloc(Stream, n_streams);
        errdefer gpa.free(streams);
        var made: usize = 0;
        errdefer for (streams[0..made]) |*s| s.deinit(gpa);
        while (made < n_streams) {
            streams[made] = .{};
            made += 1;
            try streams[made - 1].b.ensureTotalCapacityPrecise(gpa, stream_buf_cap);
        }
        var hot: std.ArrayList(f64) = .empty;
        errdefer hot.deinit(gpa);
        if (n_streams != 0) try hot.ensureTotalCapacityPrecise(gpa, options.buf_cap);
        return .{
            .gpa = gpa,
            .objectives = objectives,
            .bucket_ns = bucket_ns,
            .streams = streams,
            .hot = hot,
        };
    }

    pub fn deinit(s: *Summary) void {
        for (s.streams) |*st| st.deinit(s.gpa);
        s.gpa.free(s.streams);
        s.gpa.free(s.objectives);
        s.hot.deinit(s.gpa);
        s.* = undefined;
    }

    /// Add one observation at time `now_ns`. Steady state: one append under
    /// the spinlock; the streams are touched when the buffer fills or the
    /// current age bucket ends.
    pub fn observe(s: *Summary, v: f64, now_ns: u64) void {
        lockSpin(&s.lock);
        defer s.lock.unlock();
        s.sum_ += v;
        s.count_ += 1;
        if (s.streams.len == 0 or std.math.isNan(v)) return;
        s.anchor(now_ns);
        if (now_ns > s.expires_ns) s.flushHot(now_ns);
        s.hot.appendAssumeCapacity(v);
        if (s.hot.items.len == s.hot.capacity) s.flushHot(now_ns);
    }

    /// Cumulative count and sum, and the window's quantiles:
    /// `out_quantiles[i]` is the value for `objectives[i]`, NaN when the
    /// window holds no observation. Rotates the window to `now_ns`.
    pub fn snapshot(s: *Summary, now_ns: u64, out_quantiles: []f64) Snapshot {
        std.debug.assert(out_quantiles.len >= s.objectives.len);
        lockSpin(&s.lock);
        defer s.lock.unlock();
        if (s.streams.len != 0) {
            s.anchor(now_ns);
            s.flushHot(now_ns);
        }
        for (s.objectives, 0..) |o, i| {
            out_quantiles[i] = if (s.streams.len == 0 or s.streams[s.head].count() == 0)
                std.math.nan(f64)
            else
                s.streams[s.head].query(s.gpa, s.objectives, o.quantile);
        }
        return .{ .count = s.count_, .sum = s.sum_ };
    }

    /// Quantile-stream inserts lost to allocation failure (normally 0).
    pub fn droppedInserts(s: *Summary) u64 {
        lockSpin(&s.lock);
        defer s.lock.unlock();
        return s.dropped;
    }

    fn anchor(s: *Summary, now_ns: u64) void {
        if (s.anchored) return;
        s.anchored = true;
        s.expires_ns = now_ns +| s.bucket_ns;
    }

    /// Push the hot buffer into every stream, then advance the window to
    /// `now_ns` (reset the heads that expired). Order as in client_golang:
    /// the buffered values enter all streams first, rotation resets after.
    fn flushHot(s: *Summary, now_ns: u64) void {
        var steps: u64 = 0;
        if (now_ns > s.expires_ns) {
            steps = (now_ns - s.expires_ns - 1) / s.bucket_ns + 1;
            s.expires_ns +|= steps *| s.bucket_ns;
        }
        for (s.hot.items) |v| {
            for (s.streams) |*st| {
                st.insert(s.gpa, s.objectives, v) catch {
                    s.dropped += 1;
                };
            }
        }
        s.hot.clearRetainingCapacity();
        const n = s.streams.len;
        const resets: usize = @intCast(@min(steps, n));
        var idx = s.head;
        for (0..resets) |_| {
            s.streams[idx].reset();
            idx += 1;
            if (idx == n) idx = 0;
        }
        s.head = @intCast((s.head + steps % n) % n);
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    var spins: u32 = 0;
    while (!m.tryLock()) {
        if (spins < 64) {
            spins += 1;
            std.atomic.spinLoopHint();
        } else {
            std.Thread.yield() catch {};
        }
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const nan = std.math.nan(f64);

const std_objectives = [_]Objective{
    .{ .quantile = 0.5, .epsilon = 0.05 },
    .{ .quantile = 0.9, .epsilon = 0.01 },
    .{ .quantile = 0.99, .epsilon = 0.001 },
};

test "validation" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidQuantile, Summary.init(a, .{ .objectives = &.{.{ .quantile = 1.1, .epsilon = 0.01 }} }));
    try testing.expectError(error.InvalidQuantile, Summary.init(a, .{ .objectives = &.{.{ .quantile = -0.1, .epsilon = 0.01 }} }));
    try testing.expectError(error.InvalidQuantile, Summary.init(a, .{ .objectives = &.{.{ .quantile = nan, .epsilon = 0.01 }} }));
    try testing.expectError(error.InvalidEpsilon, Summary.init(a, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 1 }} }));
    try testing.expectError(error.InvalidEpsilon, Summary.init(a, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = -0.1 }} }));
    try testing.expectError(error.InvalidAgeBuckets, Summary.init(a, .{ .age_buckets = 0 }));
    try testing.expectError(error.InvalidBufCap, Summary.init(a, .{ .buf_cap = 0 }));
    try testing.expectError(error.InvalidMaxAge, Summary.init(a, .{ .max_age_ns = 4, .age_buckets = 5 }));
    var ok = try Summary.init(a, .{ .objectives = &.{.{ .quantile = 0, .epsilon = 0 }} });
    ok.deinit();
}

test "no objectives: only sum and count" {
    var s = try Summary.init(testing.allocator, .{});
    defer s.deinit();
    s.observe(1.5, 0);
    s.observe(2.5, 1);
    const snap = s.snapshot(10, &.{});
    try testing.expectEqual(@as(u64, 2), snap.count);
    try testing.expectEqual(@as(f64, 4), snap.sum);
}

test "empty window is NaN" {
    var s = try Summary.init(testing.allocator, .{ .objectives = &std_objectives });
    defer s.deinit();
    var q: [3]f64 = undefined;
    const snap = s.snapshot(0, &q);
    try testing.expectEqual(@as(u64, 0), snap.count);
    for (q) |x| try testing.expect(std.math.isNan(x));
}

test "small input is exact (buffer path)" {
    var s = try Summary.init(testing.allocator, .{ .objectives = &std_objectives });
    defer s.deinit();
    // Shuffled 1..10.
    for ([_]f64{ 7, 3, 10, 1, 9, 5, 2, 8, 4, 6 }) |v| s.observe(v, 0);
    var q: [3]f64 = undefined;
    const snap = s.snapshot(0, &q);
    try testing.expectEqual(@as(u64, 10), snap.count);
    try testing.expectEqual(@as(f64, 55), snap.sum);
    try testing.expectEqual(@as(f64, 5), q[0]); // ceil(10 * 0.5)  = rank 5
    try testing.expectEqual(@as(f64, 9), q[1]); // ceil(10 * 0.9)  = rank 9
    try testing.expectEqual(@as(f64, 10), q[2]); // ceil(10 * 0.99) = rank 10
}

/// True when `v`'s rank interval in `sorted` (1-based, ties span a range)
/// comes within `2 * eps * n + 2` ranks of `q * n`. The CKMS paper promises
/// `eps * n`; perks' integer rounding (floor(f) - 1 on insert, ceil(f / 2) on
/// query) measurably overshoots that when `eps * n` is near 1 (2.24 ranks at
/// n = 1024, eps = 0.001, found by this test; the Go engine gives the
/// identical value, see the differential test), so the bound asserted is the
/// loosened one.
fn rankWithin(sorted: []const f64, v: f64, q: f64, eps: f64) bool {
    const n: f64 = @floatFromInt(sorted.len);
    var lo: usize = 0;
    while (lo < sorted.len and sorted[lo] < v) lo += 1;
    var hi = lo;
    while (hi < sorted.len and sorted[hi] <= v) hi += 1;
    if (hi == lo) return false; // not an observed value
    const lo_rank: f64 = @floatFromInt(lo + 1);
    const hi_rank: f64 = @floatFromInt(hi);
    const target = q * n;
    const dist = @max(0, @max(lo_rank - target, target - hi_rank));
    return dist <= 2 * eps * n + 2;
}

test "CKMS rank guarantee over random streams" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rnd = prng.random();
    for (0..60) |round| {
        var s = try Summary.init(a, .{ .objectives = &std_objectives, .age_buckets = 1 });
        defer s.deinit();
        const n = 1 + rnd.uintLessThan(usize, 6000);
        const vals = try a.alloc(f64, n);
        defer a.free(vals);
        for (vals, 0..) |*v, idx| {
            v.* = switch (round % 4) {
                0 => rnd.float(f64) * 1000,
                1 => @floatFromInt(rnd.uintLessThan(u32, 50)), // many ties
                2 => @exp(rnd.floatNorm(f64)), // heavy right tail
                else => @floatFromInt(n - idx), // descending
            };
            s.observe(v.*, 0);
        }
        var q: [3]f64 = undefined;
        const snap = s.snapshot(0, &q);
        try testing.expectEqual(@as(u64, n), snap.count);
        const sorted = try a.dupe(f64, vals);
        defer a.free(sorted);
        std.mem.sort(f64, sorted, {}, std.sort.asc(f64));
        for (std_objectives, 0..) |o, i| {
            if (!rankWithin(sorted, q[i], o.quantile, o.epsilon)) {
                std.debug.print("round {d} n {d} q {d}: got {d}\n", .{ round, n, o.quantile, q[i] });
                return error.TestUnexpectedResult;
            }
        }
        try testing.expectEqual(@as(u64, 0), s.droppedInserts());
    }
}

test "window expiry: quantiles drop old values, sum and count stay" {
    // max_age 10 s, 5 buckets of 2 s.
    const sec = std.time.ns_per_s;
    var s = try Summary.init(testing.allocator, .{
        .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.01 }},
        .max_age_ns = 10 * sec,
        .age_buckets = 5,
    });
    defer s.deinit();
    var q: [1]f64 = undefined;
    s.observe(100, 0); // anchors the window: first bucket ends at 2 s
    _ = s.snapshot(2 * sec, &q);
    try testing.expectEqual(@as(f64, 100), q[0]);
    // Visible up to and including t0 + max_age ...
    var snap = s.snapshot(10 * sec, &q);
    try testing.expectEqual(@as(f64, 100), q[0]);
    // ... and gone one nanosecond later.
    snap = s.snapshot(10 * sec + 1, &q);
    try testing.expect(std.math.isNan(q[0]));
    try testing.expectEqual(@as(u64, 1), snap.count);
    try testing.expectEqual(@as(f64, 100), snap.sum);
    // A later observation lives on its own; count/sum accumulate.
    s.observe(7, 11 * sec);
    snap = s.snapshot(11 * sec, &q);
    try testing.expectEqual(@as(f64, 7), q[0]);
    try testing.expectEqual(@as(u64, 2), snap.count);
    try testing.expectEqual(@as(f64, 107), snap.sum);
    // Far in the future: everything expired, the jump is O(1) not a loop.
    snap = s.snapshot(std.math.maxInt(u64) / 2, &q);
    try testing.expect(std.math.isNan(q[0]));
    try testing.expectEqual(@as(u64, 2), snap.count);
}

test "rotation happens strictly after the bucket boundary" {
    var s = try Summary.init(testing.allocator, .{
        .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.01 }},
        .max_age_ns = 1000,
        .age_buckets = 2, // buckets of 500
    });
    defer s.deinit();
    var q: [1]f64 = undefined;
    s.observe(1, 0); // first bucket ends at 500
    s.observe(2, 600); // rotation: stream 0 reset, head = stream 1 (holds 1 and 2)
    _ = s.snapshot(1000, &q); // exactly at the boundary: no rotation
    try testing.expectEqual(@as(f64, 1), q[0]); // sorted [1, 2], rank 1
    _ = s.snapshot(1001, &q); // head (1, 2) reset, head = stream 0 (only 2)
    try testing.expectEqual(@as(f64, 2), q[0]);
    _ = s.snapshot(1500, &q); // boundary again: still stream 0
    try testing.expectEqual(@as(f64, 2), q[0]);
    _ = s.snapshot(1501, &q);
    try testing.expect(std.math.isNan(q[0]));
}

test "NaN observation: counts, poisons sum, not in quantiles" {
    var s = try Summary.init(testing.allocator, .{ .objectives = &std_objectives });
    defer s.deinit();
    var q: [3]f64 = undefined;
    s.observe(nan, 0);
    var snap = s.snapshot(0, &q);
    try testing.expectEqual(@as(u64, 1), snap.count);
    try testing.expect(std.math.isNan(snap.sum));
    for (q) |x| try testing.expect(std.math.isNan(x));
    s.observe(3, 0);
    snap = s.snapshot(0, &q);
    try testing.expectEqual(@as(u64, 2), snap.count);
    try testing.expectEqual(@as(f64, 3), q[0]);
}

test "multi-bucket rotation under many observations stays within bounds" {
    // Old values (1000..) must vanish once max_age passed; new ones dominate.
    const a = testing.allocator;
    var s = try Summary.init(a, .{
        .objectives = &std_objectives,
        .max_age_ns = 5000,
        .age_buckets = 5,
        .buf_cap = 64,
    });
    defer s.deinit();
    var t: u64 = 0;
    for (0..3000) |i| {
        s.observe(1000 + @as(f64, @floatFromInt(i % 100)), t);
        t += 1;
    }
    for (0..3000) |i| {
        s.observe(@as(f64, @floatFromInt(i % 100)), t);
        t += 1;
    }
    var q: [3]f64 = undefined;
    // 3000 ns after the first batch ended nothing has expired yet (window 5000).
    _ = s.snapshot(t, &q);
    try testing.expect(q[2] >= 1000);
    // Only the low batch is inside the window at t + 3000.. (high batch older than 5000).
    const snap = s.snapshot(t + 3000, &q);
    try testing.expect(q[0] < 100 and q[2] < 100);
    try testing.expectEqual(@as(u64, 6000), snap.count);
}

test "4 threads observe: no lost counts" {
    const a = testing.allocator;
    var s = try Summary.init(a, .{ .objectives = &std_objectives, .max_age_ns = 1000, .age_buckets = 4, .buf_cap = 100 });
    defer s.deinit();
    const per_thread = 20000;
    const Worker = struct {
        fn run(sp: *Summary, id: u64) void {
            for (0..per_thread) |i| sp.observe(@floatFromInt(i % 97), id * 1000 + i / 10);
        }
    };
    var ts: [4]std.Thread = undefined;
    for (&ts, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &s, id });
    for (ts) |t| t.join();
    var q: [3]f64 = undefined;
    const snap = s.snapshot(1 << 20, &q);
    try testing.expectEqual(@as(u64, 4 * per_thread), snap.count);
    // sum of (i % 97) over 0..20000, four times; exact in f64.
    var expect_sum: f64 = 0;
    for (0..per_thread) |i| expect_sum += @floatFromInt(i % 97);
    try testing.expectEqual(4 * expect_sum, snap.sum);
    try testing.expectEqual(@as(u64, 0), s.droppedInserts());
}

test "differential vs perks quantile.Stream (client_golang's engine)" {
    const vectors = @import("summary_oracle_vectors.zig");
    const a = testing.allocator;
    for (vectors.scripts, 0..) |sc, si| {
        // One age bucket and an effectively infinite max_age: no rotation, so
        // the Summary is the bare stream (Go: Summary feeds every value to
        // Stream.Insert one at a time; the stream buffers 500).
        var s = try Summary.init(a, .{
            .objectives = sc.objectives,
            .max_age_ns = std.math.maxInt(u64) / 4,
            .age_buckets = 1,
            .buf_cap = 500,
        });
        defer s.deinit();
        var next: usize = 0;
        for (sc.snaps) |sn| {
            for (sc.values[next..sn.after]) |v| s.observe(v, 0);
            next = sn.after;
            var q: [8]f64 = undefined;
            const got = s.snapshot(0, &q);
            try testing.expectEqual(@as(u64, sn.after), got.count);
            for (sn.expect, 0..) |want, i| {
                if (@as(u64, @bitCast(want)) != @as(u64, @bitCast(q[i]))) {
                    std.debug.print("script {d} after {d} objective {d}: want {d} got {d}\n", .{ si, sn.after, i, want, q[i] });
                    return error.TestUnexpectedResult;
                }
            }
        }
    }
}

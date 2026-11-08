// SPDX-License-Identifier: MIT

//! clock — monotonic and wall-clock reads for code that has no `std.Io`, and
//! the injectable `Clock` / `WallClock` values time-dependent modules take so
//! their tests can drive time by hand.
//!
//! Reads (all total: they never fail, never panic, never allocate):
//!
//! - `monotonicNs()` — nanoseconds on a clock that never goes backwards and
//!   does not jump when the wall clock is set: Linux `CLOCK_MONOTONIC` (vDSO),
//!   Windows `QueryPerformanceCounter`. Arbitrary origin; only differences
//!   mean anything. Like Rust's `Instant::now` and Go's monotonic reading.
//! - `monotonicCoarseNs()` — the same clock at tick resolution (Linux
//!   `CLOCK_MONOTONIC_COARSE`, typically 1–4 ms), several times cheaper; for
//!   hot paths that only need "roughly now" (rate limits, idle timeouts).
//!   Windows has no coarse variant and returns `monotonicNs()`.
//! - `realtimeNs()` / `realtimeMs()` / `realtimeS()` — Unix time (Linux
//!   `CLOCK_REALTIME`, Windows `RtlGetSystemTimePrecise`), floored to the
//!   unit. Can jump in both directions when the clock is set.
//!
//! A failed OS read (which Linux documents only for an invalid clock id)
//! returns 0 — the value every copy this module replaced already returned —
//! rather than an error every caller would have to thread through.
//!
//! Injection: a module that needs time takes a `Clock` (monotonic, `u64` ns)
//! or a `WallClock` (`i64` Unix ns) with a `.monotonic` / `.system` default,
//! and a test passes `ManualClock.clock()` / `ManualWallClock.clock()`.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Monotonic, coarse-monotonic and wall-clock reads without an `std.Io` (vDSO `clock_gettime` / QueryPerformanceCounter), plus injectable `Clock`/`WallClock` values and manual clocks for tests",
    // The catalog's Platform cell.
    .platform_note = "Linux (clock_gettime), Windows (QPC, RtlGetSystemTimePrecise)",
    .targets = .{ .linux64, .linux32, .windows },
    .platform = .any,
    .role = .util,
    // The reads are stateless OS calls; `ManualClock` keeps its time behind a
    // lock, so a test may advance it while worker threads read it.
    .concurrency = .threadsafe,
    .model_after = "Rust std::time::{Instant, SystemTime}, Go time.Now, quanta 0.12 (Clock + Mock)",
    .deps = .{},
};

// ── OS reads ────────────────────────────────────────────────────────────────

/// Nanoseconds on the monotonic clock (arbitrary origin). Never decreases
/// between two calls on one machine; 0 only if the OS read fails.
pub fn monotonicNs() u64 {
    return switch (builtin.os.tag) {
        .windows => windowsQpcNs(),
        else => posixNs(.MONOTONIC),
    };
}

/// `monotonicNs` at the kernel tick's resolution (Linux
/// `CLOCK_MONOTONIC_COARSE`); same origin as `monotonicNs` on Linux, so the two
/// may be compared, but a coarse reading can lag a precise one by up to a
/// tick. Windows: `monotonicNs()`.
pub fn monotonicCoarseNs() u64 {
    return switch (builtin.os.tag) {
        .windows => windowsQpcNs(),
        .linux => posixNs(.MONOTONIC_COARSE),
        else => posixNs(.MONOTONIC),
    };
}

/// Unix time in nanoseconds (negative before 1970). Saturates at the `i64`
/// range (year ~2262) instead of overflowing.
pub fn realtimeNs() i64 {
    switch (builtin.os.tag) {
        .windows => {
            // 100 ns ticks since 1601-01-01.
            return unixNsFromFiletime(std.os.windows.ntdll.RtlGetSystemTimePrecise());
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
            return unixNsFromTimespec(ts.sec, ts.nsec);
        },
    }
}

/// Unix time in milliseconds, floored (so -1 ns is -1 ms, not 0).
pub fn realtimeMs() i64 {
    return nsToMs(realtimeNs());
}

/// Unix time in seconds, floored.
pub fn realtimeS() i64 {
    return nsToS(realtimeNs());
}

/// `later - earlier` for two monotonic readings, 0 when `later` is the
/// smaller one (a reading taken on another clock, or a manual clock set
/// back) — never a wrapped huge value.
pub fn elapsedNs(earlier: u64, later: u64) u64 {
    return later -| earlier;
}

/// 1601-01-01 → 1970-01-01 in 100 ns ticks.
const windows_epoch_ticks: i64 = 116_444_736_000_000_000;

/// Unix ns → ms, floored toward -inf (-1 ns is -1 ms). Cannot overflow: the
/// divisor is positive and not -1.
fn nsToMs(ns: i64) i64 {
    return @divFloor(ns, std.time.ns_per_ms);
}

/// Unix ns → s, floored toward -inf.
fn nsToS(ns: i64) i64 {
    return @divFloor(ns, std.time.ns_per_s);
}

/// `timespec` fields → Unix ns, saturating at the `i64` range. The fields are
/// `isize` (`i32` on 32-bit targets, `i64` elsewhere), so the widening casts
/// cannot trap.
fn unixNsFromTimespec(sec: anytype, nsec: anytype) i64 {
    const s: i64 = sec;
    const n: i64 = nsec;
    return s *| std.time.ns_per_s +| n;
}

/// Windows system time (100 ns ticks since 1601-01-01) → Unix ns, saturating.
fn unixNsFromFiletime(ticks: i64) i64 {
    return (ticks -| windows_epoch_ticks) *| 100;
}

fn posixNs(comptime id: std.posix.clockid_t) u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(id, &ts)) != .SUCCESS) return 0;
    return timespecToNs(ts.sec, ts.nsec);
}

/// Monotonic timespec → ns; a negative field (no monotonic clock reports
/// one) maps to 0 instead of a panic, and the sum saturates.
fn timespecToNs(sec: i64, nsec: i64) u64 {
    const s = std.math.cast(u64, sec) orelse return 0;
    const n = std.math.cast(u64, nsec) orelse 0;
    return s *| std.time.ns_per_s +| n;
}

fn windowsQpcNs() u64 {
    const windows = std.os.windows;
    var qpf: windows.LARGE_INTEGER = undefined;
    var qpc: windows.LARGE_INTEGER = undefined;
    if (!windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) return 0;
    if (!windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool()) return 0;
    return qpcToNs(@bitCast(qpc), @bitCast(qpf));
}

/// QPC count → ns without overflow (u128 product) or a division by zero;
/// saturates at `maxInt(u64)` (584 years of uptime).
fn qpcToNs(count: u64, freq: u64) u64 {
    if (freq == 0) return 0;
    const ns = @as(u128, count) * std.time.ns_per_s / freq;
    return std.math.cast(u64, ns) orelse std.math.maxInt(u64);
}

// ── injectable clocks ───────────────────────────────────────────────────────

/// A monotonic time source in nanoseconds. Copy it by value; `ctx` is passed
/// back to `nowFn` untouched.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// `monotonicNs` — the production default.
    pub const monotonic: Clock = .{ .nowFn = monotonicThunk };
    /// `monotonicCoarseNs`.
    pub const coarse: Clock = .{ .nowFn = coarseThunk };

    pub fn now(c: Clock) u64 {
        return c.nowFn(c.ctx);
    }

    /// Nanoseconds since `start` (a reading of this clock), saturating at 0.
    pub fn since(c: Clock, start: u64) u64 {
        return elapsedNs(start, c.now());
    }
};

/// A wall-clock time source in Unix nanoseconds.
pub const WallClock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) i64,

    /// `realtimeNs` — the production default.
    pub const system: WallClock = .{ .nowFn = realtimeThunk };

    pub fn now(c: WallClock) i64 {
        return c.nowFn(c.ctx);
    }

    /// Unix milliseconds, floored.
    pub fn nowMs(c: WallClock) i64 {
        return nsToMs(c.now());
    }

    /// Unix seconds, floored.
    pub fn nowS(c: WallClock) i64 {
        return nsToS(c.now());
    }
};

fn monotonicThunk(_: ?*anyopaque) u64 {
    return monotonicNs();
}
fn coarseThunk(_: ?*anyopaque) u64 {
    return monotonicCoarseNs();
}
fn realtimeThunk(_: ?*anyopaque) i64 {
    return realtimeNs();
}

/// A monotonic clock that moves only when told to — quanta's `Mock`. Safe to
/// read from other threads while one thread advances it. Must outlive every
/// `Clock` taken from it.
pub const ManualClock = struct {
    cell: Locked(u64),

    pub fn init(start_ns: u64) ManualClock {
        return .{ .cell = .{ .value = start_ns } };
    }

    pub fn clock(self: *ManualClock) Clock {
        return .{ .ctx = self, .nowFn = read };
    }

    pub fn now(self: *ManualClock) u64 {
        return self.cell.get();
    }

    /// Moves time forward by `delta_ns`, saturating at `maxInt(u64)`.
    pub fn advance(self: *ManualClock, delta_ns: u64) void {
        self.cell.lock();
        defer self.cell.unlock();
        self.cell.value +|= delta_ns;
    }

    /// Sets the time, backwards included (to test a consumer's handling of a
    /// reading older than the previous one).
    pub fn set(self: *ManualClock, ns: u64) void {
        self.cell.put(ns);
    }

    fn read(ctx: ?*anyopaque) u64 {
        const self: *ManualClock = @ptrCast(@alignCast(ctx.?));
        return self.now();
    }
};

/// A wall clock that moves only when told to; `advance` takes a signed delta
/// because wall clocks are set backwards in real life.
pub const ManualWallClock = struct {
    cell: Locked(i64),

    pub fn init(unix_ns: i64) ManualWallClock {
        return .{ .cell = .{ .value = unix_ns } };
    }

    pub fn clock(self: *ManualWallClock) WallClock {
        return .{ .ctx = self, .nowFn = read };
    }

    pub fn now(self: *ManualWallClock) i64 {
        return self.cell.get();
    }

    /// Moves time by `delta_ns` (either sign), saturating at the `i64` range.
    pub fn advance(self: *ManualWallClock, delta_ns: i64) void {
        self.cell.lock();
        defer self.cell.unlock();
        self.cell.value +|= delta_ns;
    }

    pub fn set(self: *ManualWallClock, unix_ns: i64) void {
        self.cell.put(unix_ns);
    }

    fn read(ctx: ?*anyopaque) i64 {
        const self: *ManualWallClock = @ptrCast(@alignCast(ctx.?));
        return self.now();
    }
};

/// A 64-bit value behind a spin lock on a `u32` flag. Not an atomic `u64`:
/// 32-bit MIPS (`.linux32`) has no 64-bit atomics. The manual clocks are test
/// fixtures, so a spin lock's cost does not matter; a torn read would.
fn Locked(comptime T: type) type {
    return struct {
        flag: std.atomic.Value(u32) = .init(0),
        value: T,

        const Self = @This();

        fn lock(self: *Self) void {
            while (self.flag.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        }

        fn unlock(self: *Self) void {
            self.flag.store(0, .release);
        }

        fn get(self: *Self) T {
            self.lock();
            defer self.unlock();
            return self.value;
        }

        fn put(self: *Self, v: T) void {
            self.lock();
            defer self.unlock();
            self.value = v;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "monotonicNs never decreases and advances across a sleep" {
    var prev = monotonicNs();
    try testing.expect(prev != 0);
    for (0..10_000) |_| {
        const cur = monotonicNs();
        try testing.expect(cur >= prev);
        prev = cur;
    }
    const before = monotonicNs();
    try std.Io.sleep(testing.io, .fromMilliseconds(20), .awake);
    const gap = elapsedNs(before, monotonicNs());
    // ≥ the sleep, and not absurdly more (a unit error — µs or s instead of
    // ns — would be off by 1000×).
    try testing.expect(gap >= 20 * std.time.ns_per_ms);
    try testing.expect(gap < 2 * std.time.ns_per_s);
}

test "monotonicNs agrees with std.Io's awake clock" {
    // Independent reading of the same OS clock through std; the two must
    // agree within the time it takes to make both calls.
    const ours_before = monotonicNs();
    const theirs = std.Io.Clock.awake.now(testing.io).nanoseconds;
    const ours_after = monotonicNs();
    try testing.expect(theirs >= 0);
    const t: u64 = @intCast(theirs);
    try testing.expect(t + 1 >= ours_before and t <= ours_after + 1);
}

test "monotonicCoarseNs is within a few ticks of monotonicNs" {
    const coarse = monotonicCoarseNs();
    const fine = monotonicNs();
    try testing.expect(coarse != 0);
    // Coarse lags by at most a tick (≤ 10 ms at HZ=100) and never leads by
    // more than a tick either.
    const diff = if (fine > coarse) fine - coarse else coarse - fine;
    try testing.expect(diff < 50 * std.time.ns_per_ms);
}

test "realtime units agree and match std.Io's real clock" {
    const ns = realtimeNs();
    const theirs = std.Io.Clock.real.now(testing.io).nanoseconds;
    // 2020-01-01 < now < 2200-01-01: catches a unit or epoch error.
    try testing.expect(ns > 1_577_836_800 * std.time.ns_per_s);
    try testing.expect(ns < 7_258_118_400 * std.time.ns_per_s);
    const diff = @abs(@as(i128, theirs) - ns);
    try testing.expect(diff < std.time.ns_per_s);
    const s = realtimeS();
    const ms = realtimeMs();
    try testing.expect(@abs(s - @divFloor(ns, std.time.ns_per_s)) <= 1);
    try testing.expect(@abs(ms - @divFloor(ns, std.time.ns_per_ms)) <= 1000);
}

test "elapsedNs saturates instead of wrapping" {
    try testing.expectEqual(@as(u64, 5), elapsedNs(10, 15));
    try testing.expectEqual(@as(u64, 0), elapsedNs(15, 10));
    try testing.expectEqual(@as(u64, 0), elapsedNs(7, 7));
}

test "timespecToNs: negative fields and overflow are total" {
    try testing.expectEqual(@as(u64, 1_500_000_000), timespecToNs(1, 500_000_000));
    try testing.expectEqual(@as(u64, 0), timespecToNs(-1, 0));
    try testing.expectEqual(@as(u64, 3 * std.time.ns_per_s), timespecToNs(3, -5));
    try testing.expectEqual(std.math.maxInt(u64), timespecToNs(std.math.maxInt(i64), 999_999_999));
}

test "qpcToNs: exact at common frequencies, total at the edges" {
    try testing.expectEqual(@as(u64, 1_000_000_000), qpcToNs(10_000_000, 10_000_000));
    try testing.expectEqual(@as(u64, 100), qpcToNs(1, 10_000_000));
    try testing.expectEqual(@as(u64, 1_000_000_000), qpcToNs(3_579_545, 3_579_545));
    try testing.expectEqual(@as(u64, 0), qpcToNs(123, 0));
    try testing.expectEqual(std.math.maxInt(u64), qpcToNs(std.math.maxInt(u64), 1));
}

test "timespecToNs: a negative second maps to 0 whatever the nanoseconds" {
    try testing.expectEqual(@as(u64, 0), timespecToNs(-1, 500));
    try testing.expectEqual(@as(u64, 0), timespecToNs(std.math.minInt(i64), std.math.maxInt(i64)));
    try testing.expectEqual(@as(u64, 7), timespecToNs(0, 7));
    try testing.expectEqual(std.math.maxInt(u64), timespecToNs(18_446_744_073, 999_999_999 + 1_000_000_000));
    try testing.expectEqual(std.math.maxInt(u64), timespecToNs(std.math.maxInt(i64), std.math.maxInt(i64)));
}

test "unixNsFromTimespec: exact, negative, 32-bit fields, saturating" {
    try testing.expectEqual(@as(i64, 1_500_000_000), unixNsFromTimespec(@as(i64, 1), @as(i64, 500_000_000)));
    try testing.expectEqual(@as(i64, -1_000_000_000 + 5), unixNsFromTimespec(@as(i64, -1), @as(i64, 5)));
    // 32-bit `time_t` / `long` fields (mips-linux): widened, never trapping.
    try testing.expectEqual(@as(i64, 2_147_483_647 * std.time.ns_per_s + 999_999_999), unixNsFromTimespec(@as(i32, std.math.maxInt(i32)), @as(i32, 999_999_999)));
    try testing.expectEqual(@as(i64, std.math.minInt(i32)) * std.time.ns_per_s, unixNsFromTimespec(@as(i32, std.math.minInt(i32)), @as(i32, 0)));
    try testing.expectEqual(std.math.maxInt(i64), unixNsFromTimespec(@as(i64, std.math.maxInt(i64)), @as(i64, 1)));
    try testing.expectEqual(std.math.maxInt(i64), unixNsFromTimespec(@as(i64, 9_223_372_036), @as(i64, 854_775_807 + 1)));
    try testing.expectEqual(std.math.minInt(i64), unixNsFromTimespec(@as(i64, std.math.minInt(i64)), @as(i64, -1)));
    try testing.expectEqual(std.math.minInt(i64), unixNsFromTimespec(@as(i64, -9_223_372_037), @as(i64, 0)));
}

test "unixNsFromFiletime: epoch, units, saturation both ways" {
    try testing.expectEqual(@as(i64, 0), unixNsFromFiletime(116_444_736_000_000_000));
    try testing.expectEqual(@as(i64, 100), unixNsFromFiletime(116_444_736_000_000_001));
    // 2023-11-14T22:13:20Z = 1_700_000_000 s.
    try testing.expectEqual(@as(i64, 1_700_000_000 * std.time.ns_per_s), unixNsFromFiletime(116_444_736_000_000_000 + 1_700_000_000 * 10_000_000));
    // Before 1970 is negative; before 1601 / the i64 range saturates.
    try testing.expectEqual(@as(i64, -100), unixNsFromFiletime(116_444_735_999_999_999));
    try testing.expectEqual(std.math.minInt(i64), unixNsFromFiletime(0));
    try testing.expectEqual(std.math.minInt(i64), unixNsFromFiletime(std.math.minInt(i64)));
    try testing.expectEqual(std.math.maxInt(i64), unixNsFromFiletime(std.math.maxInt(i64)));
}

test "nsToMs / nsToS floor toward -inf" {
    try testing.expectEqual(@as(i64, -1), nsToMs(-1));
    try testing.expectEqual(@as(i64, -1), nsToMs(-1_000_000));
    try testing.expectEqual(@as(i64, -2), nsToMs(-1_000_001));
    try testing.expectEqual(@as(i64, 0), nsToMs(999_999));
    try testing.expectEqual(@as(i64, 1), nsToMs(1_000_000));
    try testing.expectEqual(@as(i64, -1), nsToS(-1));
    try testing.expectEqual(@as(i64, -2), nsToS(-1_000_000_001));
    try testing.expectEqual(@as(i64, 0), nsToS(999_999_999));
    try testing.expectEqual(@as(i64, std.math.minInt(i64) / std.time.ns_per_s - 1), nsToS(std.math.minInt(i64)));
    try testing.expectEqual(@as(i64, std.math.maxInt(i64) / std.time.ns_per_s), nsToS(std.math.maxInt(i64)));
}

test "coarse readings repeat within a tick, precise ones never do" {
    // Linux only: CLOCK_MONOTONIC_COARSE advances once per kernel tick (1-10 ms),
    // while 2 000 back-to-back vDSO reads (~40 us) take far less than a tick.
    // A precise clock returns a new value on every read (a read costs > 1 ns).
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const Probe = struct {
        fn distinct(f: *const fn () u64) usize {
            var n: usize = 1;
            var prev = f();
            for (0..2_000) |_| {
                const cur = f();
                if (cur != prev) n += 1;
                prev = cur;
            }
            return n;
        }
        fn viaMono() u64 {
            return Clock.monotonic.now();
        }
        fn viaCoarse() u64 {
            return Clock.coarse.now();
        }
    };
    try testing.expect(Probe.distinct(&monotonicNs) >= 1_990);
    try testing.expect(Probe.distinct(&Probe.viaMono) >= 1_990);
    // At most a few tick boundaries fall inside the loop.
    try testing.expect(Probe.distinct(&monotonicCoarseNs) < 100);
    try testing.expect(Probe.distinct(&Probe.viaCoarse) < 100);
}

test "Clock defaults read the OS clocks" {
    const a = Clock.monotonic.now();
    const b = monotonicNs();
    try testing.expect(a != 0 and b >= a);
    try testing.expect(Clock.coarse.now() != 0);
    try testing.expect(Clock.monotonic.since(a) < std.time.ns_per_s);
    const w = WallClock.system.now();
    try testing.expect(@abs(w - realtimeNs()) < std.time.ns_per_s);
}

test "ManualClock drives a Clock, saturates, and can be set back" {
    var m = ManualClock.init(1_000);
    const c = m.clock();
    try testing.expectEqual(@as(u64, 1_000), c.now());
    m.advance(500);
    try testing.expectEqual(@as(u64, 1_500), c.now());
    try testing.expectEqual(@as(u64, 500), c.since(1_000));
    m.set(100);
    try testing.expectEqual(@as(u64, 100), c.now());
    try testing.expectEqual(@as(u64, 0), c.since(1_000));
    m.set(std.math.maxInt(u64) - 1);
    m.advance(10);
    try testing.expectEqual(std.math.maxInt(u64), c.now());
}

test "ManualClock: concurrent advances are not lost" {
    var m = ManualClock.init(0);
    const per_thread = 200_000;
    var go = std.atomic.Value(u32).init(0);
    const Worker = struct {
        fn run(mc: *ManualClock, start: *std.atomic.Value(u32)) void {
            while (start.load(.acquire) == 0) std.atomic.spinLoopHint();
            for (0..per_thread) |_| mc.advance(3);
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &m, &go });
    go.store(1, .release);
    for (threads) |t| t.join();
    try testing.expectEqual(@as(u64, 4 * per_thread * 3), m.now());
}

test "ManualWallClock: concurrent signed advances are not lost" {
    var w = ManualWallClock.init(-1_000_000);
    const per_thread = 200_000;
    // All workers start together (a spawn costs more than a worker's loop
    // would otherwise take, and the threads would never overlap).
    var go = std.atomic.Value(u32).init(0);
    const Worker = struct {
        fn run(wc: *ManualWallClock, start: *std.atomic.Value(u32), delta: i64) void {
            while (start.load(.acquire) == 0) std.atomic.spinLoopHint();
            for (0..per_thread) |_| wc.advance(delta);
        }
    };
    const deltas = [4]i64{ 5, 5, -2, -3 };
    var threads: [4]std.Thread = undefined;
    for (&threads, deltas) |*t, d| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &w, &go, d });
    go.store(1, .release);
    for (threads) |t| t.join();
    try testing.expectEqual(@as(i64, -1_000_000 + 5 * per_thread), w.now());
}

test "ManualWallClock: signed advance, units, saturation" {
    var w = ManualWallClock.init(1_700_000_000 * std.time.ns_per_s + 999_999_999);
    const c = w.clock();
    try testing.expectEqual(@as(i64, 1_700_000_000), c.nowS());
    try testing.expectEqual(@as(i64, 1_700_000_000_999), c.nowMs());
    w.advance(-2 * std.time.ns_per_s);
    try testing.expectEqual(@as(i64, 1_699_999_998), c.nowS());
    // Floors toward -inf before the epoch: -1 ns is second -1.
    w.set(-1);
    try testing.expectEqual(@as(i64, -1), c.nowS());
    try testing.expectEqual(@as(i64, -1), c.nowMs());
    w.set(std.math.minInt(i64) + 5);
    w.advance(-10);
    try testing.expectEqual(std.math.minInt(i64), c.now());
}

// SPDX-License-Identifier: MIT
//! No-panic sweep tests for finstats, wave GW. Findings FI1..FI8, see
//! ~/CML/20261029-panic-sweep/finstats-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const fin = @import("root.zig");

test "histogram: a range whose width overflows f64 bins every row and keeps finite edges (sweep FI1)" {
    const a = testing.allocator;
    const h = try fin.histogram(a, &.{ -1e308, 0, 1e308, 1e308, -1e308 }, 4);
    defer a.free(h);
    try testing.expectEqual(@as(usize, 4), h.len);
    var total: u64 = 0;
    for (h) |b| {
        try testing.expect(std.math.isFinite(b.lo));
        try testing.expect(std.math.isFinite(b.hi));
        total += b.count;
    }
    try testing.expectEqual(@as(u64, 5), total);
    // -1e308 x2 in bin 0, 0 in bin 2, 1e308 x2 clamped into bin 3
    try testing.expectEqual(@as(u64, 2), h[0].count);
    try testing.expectEqual(@as(u64, 0), h[1].count);
    try testing.expectEqual(@as(u64, 1), h[2].count);
    try testing.expectEqual(@as(u64, 2), h[3].count);
    try testing.expectEqual(@as(f64, -1e308), h[0].lo);
    try testing.expectEqual(@as(f64, 1e308), h[3].hi);
}

test "correlationMatrix: an allocation failure is an error, never a NaN cell (sweep FI2)" {
    // two series over the same five positions, perfectly correlated. The Dataset
    // function built a hash map per key and a pairwise list per cell; the slice one
    // allocates the matrix alone, and this stays the guard that a failure surfaces.
    const x = [_]f64{ 1, 2, 3, 4, 5 };
    const series = [_][]const f64{ &x, &x };
    var saw_err = false;
    var saw_ok = false;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        if (fin.correlationMatrix(failing.allocator(), &series, 1)) |m| {
            defer testing.allocator.free(m);
            saw_ok = true;
            // success must be the real answer, not a matrix with a silent NaN
            try testing.expectApproxEqAbs(@as(f64, 1), m[1], 1e-12);
            try testing.expectApproxEqAbs(@as(f64, 1), m[2], 1e-12);
        } else |e| {
            try testing.expectEqual(error.OutOfMemory, e);
            saw_err = true;
        }
    }
    try testing.expect(saw_err and saw_ok);
}

test "correlationMatrix: key count is capped at max_corr_keys, exactly (sweep FI3)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const one = [_]f64{1};
    const many = try a.alloc([]const f64, fin.max_corr_keys + 1);
    @memset(many, &one);
    const ok = try fin.correlationMatrix(a, many[0..fin.max_corr_keys], 1);
    try testing.expectEqual(fin.max_corr_keys * fin.max_corr_keys, ok.len);
    try testing.expectError(error.TooLarge, fin.correlationMatrix(a, many, 1));
}

test "histogram: bins above max_histogram_bins is TooLarge, the cap itself is served (sweep FI4)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = [_]f64{ 1, 2, 3 };
    const ok = try fin.histogram(a, &d, fin.max_histogram_bins);
    try testing.expectEqual(fin.max_histogram_bins, ok.len);
    try testing.expectError(error.TooLarge, fin.histogram(a, &d, fin.max_histogram_bins + 1));
    try testing.expectError(error.TooLarge, fin.histogram(a, &d, std.math.maxInt(usize)));
    // a series with no finite value used to return before looking at `bins`
    const nan = [_]f64{std.math.nan(f64)};
    try testing.expectError(error.TooLarge, fin.histogram(a, &nan, fin.max_histogram_bins + 1));
}

test "monteCarlo: paths x months above max_monte_carlo_cells is TooLarge before any allocation (sweep FI5)" {
    // The cap itself must get PAST the check: a FailingAllocator that fails the
    // first allocation turns "accepted" into error.OutOfMemory without 256 MiB.
    const cap = fin.max_monte_carlo_cells;
    const base: fin.MonteCarloSpec = .{ .start = 1, .mu_ann = 0, .vol_ann = 0, .monthly = 0, .years = 0, .paths = cap };
    // cap = paths(2^25) x 1 month-row
    try testing.expectError(error.OutOfMemory, mcWith(base));
    var over = base;
    over.paths = cap + 1;
    try testing.expectError(error.TooLarge, mcWith(over));
    // cap = 2^20 paths x 32 month-rows (years = 31/12 -> 31 months)
    var split = base;
    split.paths = 1 << 20;
    split.years = 31.0 / 12.0;
    try testing.expectError(error.OutOfMemory, mcWith(split));
    split.years = 32.0 / 12.0;
    try testing.expectError(error.TooLarge, mcWith(split));
    // product overflow and the absurd-years clamp are TooLarge, not OOM / wraparound
    var huge = base;
    huge.paths = std.math.maxInt(usize);
    huge.years = 1;
    try testing.expectError(error.TooLarge, mcWith(huge));
    var far = base;
    far.paths = 1;
    far.years = 1e300;
    try testing.expectError(error.TooLarge, mcWith(far));
}

fn mcWith(spec: fin.MonteCarloSpec) fin.Error![]fin.McRow {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    return fin.monteCarlo(failing.allocator(), spec);
}

// ── a forked child, for hangs ────────────────────────────────────────────────
fn runChild(comptime body: fn () void, timeout_ms: usize) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        body();
        linux.exit_group(0);
    }
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= timeout_ms) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    try testing.expect(!linux.W.IFSIGNALED(status));
    try testing.expectEqual(@as(u32, 0), linux.W.EXITSTATUS(status));
}

fn xirrNeverMeetsTol() void {
    // tol 0 and no rate_tol: Newton can never declare convergence, so the
    // loop runs the whole budget -- here "forever" unless it is clamped.
    const r = fin.xirrPrecise(std.heap.page_allocator, &.{ "2024-01-01", "2025-01-01" }, &.{ 100, 0 }, &.{ 100, 110 }, .none, .{ // global-alloc-ok: forked sweep child that exits or panics; testing.allocator cannot follow it into the child
        .tol = 0,
        .rate_tol = null,
        .max_newton_iter = std.math.maxInt(usize),
    }) catch linux.exit_group(3);
    if (!(r > 0.09 and r < 0.11)) linux.exit_group(4);
}

test "xirrPrecise: an unbounded max_newton_iter is clamped, the call terminates with the bisection answer (sweep FI6)" {
    // the clamp (10 000 steps, ~1 ms) is what ends this call; without it only the
    // work budget (2^26 / 2 steps, seconds) does
    try runChild(xirrNeverMeetsTol, 1500);
}

test "rollingApply / rollingBetaAlpha: rows x window above max_rolling_work is TooLarge, the cap itself is accepted (sweep FI7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // cap = 2^30 = 2^15 windows x window 2^15  => n = 2^16 - 1
    const w: usize = 1 << 15;
    const buf_v = try a.alloc(f64, 2 * w);
    const buf_b = try a.alloc(f64, 2 * w);
    @memset(buf_v, 1);
    @memset(buf_b, 2);
    const at_cap_v = buf_v[0 .. 2 * w - 1];
    const at_cap_b = buf_b[0 .. 2 * w - 1];
    try testing.expectEqual(fin.max_rolling_work, ((2 * w - 1) - w + 1) * w);
    // accepted == passes the check and reaches the output allocation (the first one)
    var f1 = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, fin.rollingMean(f1.allocator(), at_cap_v, w));
    var f2 = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try testing.expectError(error.TooLarge, fin.rollingMean(f2.allocator(), buf_v, w));
    var f3 = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, fin.rollingBetaAlpha(f3.allocator(), at_cap_v, at_cap_b, w, 252));
    var f4 = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try testing.expectError(error.TooLarge, fin.rollingBetaAlpha(f4.allocator(), buf_v, buf_b, w, 252));
    // a window of 0 or past the end stays the documented empty result
    const e0 = try fin.rollingMean(a, buf_v[0..4], 0);
    try testing.expectEqual(@as(usize, 0), e0.len);
    const e1 = try fin.rollingMean(a, buf_v[0..4], std.math.maxInt(usize));
    try testing.expectEqual(@as(usize, 0), e1.len);
}

test "quantile / drawdownEpisodes: NaN sorts last, so the finite values stay ordered (sweep FI8)" {
    // quantile: min of the finite values at q=0, NaN only at the top
    try testing.expectEqual(@as(f64, 1), try fin.quantile(testing.allocator, &.{ 3, std.math.nan(f64), 1, 2 }, 0));
    try testing.expect(std.math.isNan(try fin.quantile(testing.allocator, &.{ 3, std.math.nan(f64), 1, 2 }, 1)));
    try testing.expectEqual(@as(f64, 2.5), try fin.quantile(testing.allocator, &.{ 3, std.math.nan(f64), 1, 2 }, 0.5));
    // 300 deterministic arrays with NaN sprinkled in: q=0 is the finite minimum
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rnd = prng.random();
    var buf: [120]f64 = undefined;
    for (0..300) |_| {
        const n = rnd.uintLessThan(usize, buf.len) + 1;
        var mn: f64 = std.math.inf(f64);
        for (buf[0..n]) |*x| {
            x.* = if (rnd.uintLessThan(u8, 4) == 0) std.math.nan(f64) else rnd.float(f64) * 100 - 50;
            if (!std.math.isNan(x.*)) mn = @min(mn, x.*);
        }
        const q0 = try fin.quantile(testing.allocator, buf[0..n], 0);
        if (std.math.isInf(mn)) try testing.expect(std.math.isNan(q0)) else try testing.expectEqual(mn, q0);
    }
    // drawdownEpisodes: the NaN-depth episode must not outrank the real -50 % one
    const vals = [_]f64{ std.math.nan(f64), 100, 50, 100 };
    const dates = [_][]const u8{ "2024-01-01", "2024-01-02", "2024-01-03", "2024-01-04" };
    const eps = try fin.drawdownEpisodes(testing.allocator, &dates, &vals, 1);
    defer testing.allocator.free(eps);
    try testing.expectEqual(@as(usize, 1), eps.len);
    try testing.expectEqual(@as(f64, -50), eps[0].depth * 100);
}

test "monteCarlo: more than max_monte_carlo_months months is TooLarge even with one path (sweep FI9)" {
    try testing.expectEqual(@as(usize, 12_000), fin.max_monte_carlo_months);
    const base: fin.MonteCarloSpec = .{ .start = 1, .mu_ann = 0, .vol_ann = 0, .monthly = 0, .years = 1000, .paths = 1 };
    // 12 000 months passes both caps and reaches the first allocation (refused by mcWith)
    try testing.expectError(error.OutOfMemory, mcWith(base));
    var over = base;
    over.years = 12_001.0 / 12.0;
    try testing.expectError(error.TooLarge, mcWith(over));
    over.years = 2.7e6; // 3.2e7 months x 1 path passes the cell cap alone
    try testing.expectError(error.TooLarge, mcWith(over));
}

test "correlationMatrix: total pair work above max_corr_work is TooLarge, exactly the cap is accepted (sweep FI10)" {
    try testing.expectEqual(@as(usize, 1 << 28), fin.max_corr_work);
    // The check runs before anything is allocated and before any value is read, so a
    // failing allocator turns "accepted" into OutOfMemory, and the series need no
    // real storage: two of 2^28 values (exactly the cap, one pair) never get read.
    const far: [*]const f64 = @ptrFromInt(8);
    const two_at_cap = [_][]const f64{ far[0 .. 1 << 28], far[0 .. 1 << 28] };
    try testing.expectError(error.OutOfMemory, fin.correlationMatrix(testing.failing_allocator, &two_at_cap, 1));
    const two_over = [_][]const f64{ far[0 .. (1 << 28) + 1], far[0 .. (1 << 28) + 1] };
    try testing.expectError(error.TooLarge, fin.correlationMatrix(testing.failing_allocator, &two_over, 1));
    // The pair count is k(k-1)/2: 1024 series = 523 776 pairs, so 512 values per series
    // stays under the cap (268 173 312) and 513 goes over it (268 697 088).
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const buf = try a.alloc(f64, 513);
    @memset(buf, 1);
    const many = try a.alloc([]const f64, fin.max_corr_keys);
    @memset(many, buf[0..512]);
    try testing.expectError(error.OutOfMemory, fin.correlationMatrix(testing.failing_allocator, many, 1));
    @memset(many, buf);
    try testing.expectError(error.TooLarge, fin.correlationMatrix(testing.failing_allocator, many, 1));
}

test "correlationMatrix: the matrix is symmetric and the diagonal is 1 (sweep FI11)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // five series of 12 positions with 9, 5, 12, 7 and 1 of them present (the rest NaN)
    const sizes = [_]usize{ 9, 5, 12, 7, 1 };
    var series: [5][]const f64 = undefined;
    for (&series, sizes, 0..) |*col, n, k| {
        const v = try a.alloc(f64, 12);
        for (v, 0..) |*x, j| x.* = if (j < n) @floatFromInt((k * 7 + j * 3) % 11) else std.math.nan(f64);
        col.* = v;
    }
    const m = try fin.correlationMatrix(a, &series, 2);
    try testing.expectEqual(@as(usize, 25), m.len);
    for (0..5) |i| {
        try testing.expectEqual(@as(f64, 1), m[i * 5 + i]);
        for (0..5) |j| {
            const x = m[i * 5 + j];
            const y = m[j * 5 + i];
            // bit-identical, not approximate; NaN against NaN
            try testing.expect(std.mem.eql(u8, std.mem.asBytes(&x), std.mem.asBytes(&y)));
        }
    }
    // the 1-position series has no pair with min_overlap 2
    try testing.expect(std.math.isNan(m[4 * 5 + 0]));
    try testing.expect(!std.math.isNan(m[0 * 5 + 1]));
}

test "histogram: edges stay finite when span is finite but span x bins is not (sweep FI12)" {
    const a = testing.allocator;
    const h = try fin.histogram(a, &.{ 0, 1e308, 5e307 }, 12);
    defer a.free(h);
    try testing.expectEqual(@as(usize, 12), h.len);
    var total: u64 = 0;
    for (h, 0..) |b, i| {
        try testing.expect(std.math.isFinite(b.lo) and std.math.isFinite(b.hi));
        try testing.expect(b.lo <= b.hi);
        if (i > 0) try testing.expect(b.lo >= h[i - 1].lo);
        total += b.count;
    }
    try testing.expectEqual(@as(u64, 3), total);
    try testing.expectEqual(@as(f64, 0), h[0].lo);
    try testing.expectEqual(@as(f64, 1e308), h[11].hi);
    try testing.expectEqual(@as(u64, 1), h[0].count);
    try testing.expectEqual(@as(u64, 1), h[6].count); // 5e307 is the midpoint -> bin 6
    try testing.expectEqual(@as(u64, 1), h[11].count);
}

fn xirrLongNeverMeetsTol() void {
    const n = 100_000;
    const a = std.heap.page_allocator; // global-alloc-ok: forked sweep child that exits or panics; testing.allocator cannot follow it into the child
    const dates = a.alloc([]const u8, n) catch linux.exit_group(2);
    const flows = a.alloc(f64, n) catch linux.exit_group(2);
    const values = a.alloc(f64, n) catch linux.exit_group(2);
    const cycle = [_][]const u8{ "2024-01-01", "2024-07-01", "2024-12-31" };
    for (0..n) |i| {
        const last = i + 1 == n;
        dates[i] = if (last) "2025-12-31" else cycle[i % 3];
        flows[i] = 1;
        values[i] = if (last) 1.2 * @as(f64, @floatFromInt(n)) else 0;
    }
    // tol 0, no rate_tol, full 10 000-step cap requested: 10 000 steps x 2 x 100 000
    // cashflows is minutes of pow(); the work budget cuts it to 2^26 / n steps.
    const r = fin.xirrPrecise(a, dates, flows, values, .none, .{
        .tol = 0,
        .rate_tol = null,
        .max_newton_iter = 10_000,
    }) catch linux.exit_group(3);
    if (!std.math.isFinite(r)) linux.exit_group(4);
}

test "xirrPrecise: Newton steps x cashflows is bounded, a long series still terminates (sweep FI13)" {
    try testing.expectEqual(@as(usize, 1 << 26), fin.max_xirr_work);
    try runChild(xirrLongNeverMeetsTol, 25_000);
}

test "monteCarlo: a paths x (months + 1) product that wraps to a small number is still TooLarge (sweep audit GW-FI14)" {
    // 2^63 paths x 2 rows = 2^64 = 0 (mod 2^64): a wrapping multiply would pass the cap
    var spec: fin.MonteCarloSpec = .{ .start = 1, .mu_ann = 0, .vol_ann = 0, .monthly = 0, .years = 1.0 / 12.0, .paths = @as(usize, 1) << 63 };
    try testing.expectError(error.TooLarge, mcWith(spec));
    // 2^62 paths x 5 rows wraps to 2^62 (> cap anyway); 3 rows x (2^64 / 3 + 1) wraps to 3
    spec.paths = (std.math.maxInt(usize) / 3) + 1;
    spec.years = 2.0 / 12.0;
    try testing.expectError(error.TooLarge, mcWith(spec));
}

test "quantile: a mass of NaNs among a few finite values keeps the finite ones ordered (sweep audit GW-FI15)" {
    var buf: [300]f64 = undefined;
    @memset(&buf, std.math.nan(f64));
    // finite values placed at scattered positions, descending
    var v: f64 = 40;
    var i: usize = 7;
    while (i < buf.len) : (i += 37) {
        buf[i] = v;
        v -= 1;
    }
    const finite = (buf.len - 7 + 36) / 37;
    try testing.expectEqual(v + 1, try fin.quantile(testing.allocator, &buf, 0));
    try testing.expectEqual(@as(f64, 40), try fin.quantile(testing.allocator, &buf, @as(f64, @floatFromInt(finite - 1)) / @as(f64, @floatFromInt(buf.len - 1))));
    try testing.expect(std.math.isNan(try fin.quantile(testing.allocator, &buf, 1)));
}

test "period statistics: every pub function survives hostile parameters and values, no panic (sweep survey 2026-11-02)" {
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    const series = [_][]const f64{
        &.{},
        &.{0},
        &.{ 0.01, -0.02 },
        &.{ nan, 1 },
        &.{ inf, -inf },
        &.{ -1, -1, -1 },
        &.{ -2, 5 },
        &.{ 1e308, 1e308, -1e308 },
        &.{ 1e-320, 5e-324, 0 },
    };
    const params = [_]f64{ 0, -1, 1, 252, 1e308, nan, inf, -inf, 5e-324 };
    // a period count whose reciprocal overflows is NaN with an rf, never +-inf
    try testing.expect(std.math.isNan(fin.sharpeRatio(&.{ 0.01, 0.02 }, 0.03, 5e-324)));
    try testing.expect(std.math.isNan(fin.sortinoRatio(&.{ 0.01, -0.02 }, 0.03, 5e-324)));
    for (series) |xs| {
        _ = fin.totalReturn(xs);
        _ = fin.geometricMean(xs);
        _ = fin.maxDrawdown(xs);
        _ = fin.gainToPain(xs);
        _ = fin.recoveryFactor(xs);
        _ = fin.bestReturn(xs);
        _ = fin.worstReturn(xs);
        _ = fin.avgWin(xs);
        _ = fin.avgLoss(xs);
        _ = fin.maxConsecutiveWins(xs);
        _ = fin.maxConsecutiveLosses(xs);
        _ = fin.stability(xs);
        for (params) |p| {
            _ = fin.cagrPeriods(xs, p);
            _ = fin.calmarRatio(xs, p);
            for (params) |q| {
                _ = fin.sharpeRatio(xs, p, q);
                _ = fin.sortinoRatio(xs, p, q);
            }
        }
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        for (params) |p| {
            _ = fin.periodStats(xs, p, p);
            _ = try fin.riskMetrics(a, xs, .{ .periods_per_year = p, .rf = p });
        }
        _ = try fin.cumulativeReturns(a, xs);
        _ = try fin.drawdownSeries(a, xs);
    }
}

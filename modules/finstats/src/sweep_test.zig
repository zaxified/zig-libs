// SPDX-License-Identifier: MIT
//! No-panic sweep tests for finstats, wave GW. Findings FI1..FI8, see
//! ~/CML/20261029-panic-sweep/finstats-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const fin = @import("root.zig");
const dsmod = @import("dataset");
const Dataset = dsmod.Dataset;
const Column = dsmod.Column;
const Value = dsmod.Value;

/// One-float-column dataset "v" over `vals`, allocated from `a` (an arena).
fn floatDs(a: std.mem.Allocator, vals: []const f64) !Dataset {
    const cols = try a.alloc(Column, 1);
    cols[0] = .{ .name = "v", .type = .float };
    const rows = try a.alloc([]const Value, vals.len);
    for (vals, 0..) |v, i| {
        const r = try a.alloc(Value, 1);
        r[0] = .{ .float = v };
        rows[i] = r;
    }
    return .{ .columns = cols, .rows = rows };
}

test "histogram: a range whose width overflows f64 bins every row and keeps finite edges (sweep FI1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try floatDs(a, &.{ -1e308, 0, 1e308, 1e308, -1e308 });
    const h = try fin.histogram(a, d, .{ .value_col = "v", .bins = 4 });
    try testing.expectEqual(@as(usize, 4), h.rows.len);
    var total: i64 = 0;
    for (h.rows) |r| {
        try testing.expect(std.math.isFinite(r[0].float));
        try testing.expect(std.math.isFinite(r[1].float));
        total += r[2].int;
    }
    try testing.expectEqual(@as(i64, 5), total);
    // -1e308 x2 in bin 0, 0 in bin 2, 1e308 x2 clamped into bin 3
    try testing.expectEqual(@as(i64, 2), h.rows[0][2].int);
    try testing.expectEqual(@as(i64, 0), h.rows[1][2].int);
    try testing.expectEqual(@as(i64, 1), h.rows[2][2].int);
    try testing.expectEqual(@as(i64, 2), h.rows[3][2].int);
    try testing.expectEqual(@as(f64, -1e308), h.rows[0][0].float);
    try testing.expectEqual(@as(f64, 1e308), h.rows[3][1].float);
}

/// Dataset (key, d, r) with `keys` keys, each having one row on its own date.
fn corrDs(a: std.mem.Allocator, keys: usize) !Dataset {
    const cols = try a.alloc(Column, 3);
    cols[0] = .{ .name = "k", .type = .text };
    cols[1] = .{ .name = "d", .type = .text };
    cols[2] = .{ .name = "r", .type = .float };
    const rows = try a.alloc([]const Value, keys);
    for (0..keys) |i| {
        const r = try a.alloc(Value, 3);
        r[0] = .{ .text = try std.fmt.allocPrint(a, "k{d}", .{i}) };
        r[1] = .{ .text = try std.fmt.allocPrint(a, "d{d}", .{i}) };
        r[2] = .{ .float = @floatFromInt(i) };
        rows[i] = r;
    }
    return .{ .columns = cols, .rows = rows };
}

test "correlationMatrix: an allocation failure inside the pairwise step is an error, never a null cell (sweep FI2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // two keys over the same five dates, perfectly correlated
    const cols = try a.alloc(Column, 3);
    cols[0] = .{ .name = "k", .type = .text };
    cols[1] = .{ .name = "d", .type = .text };
    cols[2] = .{ .name = "r", .type = .float };
    const rows = try a.alloc([]const Value, 10);
    for (0..10) |i| {
        const r = try a.alloc(Value, 3);
        r[0] = .{ .text = if (i < 5) "x" else "y" };
        r[1] = .{ .text = switch (i % 5) {
            0 => "d0",
            1 => "d1",
            2 => "d2",
            3 => "d3",
            else => "d4",
        } };
        r[2] = .{ .float = @as(f64, @floatFromInt(i % 5)) + 1 };
        rows[i] = r;
    }
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const spec: fin.CorrSpec = .{ .key_col = "k", .date_col = "d", .value_col = "r", .min_overlap = 1 };
    const base = try fin.correlationMatrix(a, d, spec);
    try testing.expectApproxEqAbs(@as(f64, 1), base.rows[0][2].float, 1e-12);

    var saw_err = false;
    var saw_ok = false;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        var inner = std.heap.ArenaAllocator.init(testing.allocator);
        defer inner.deinit();
        var failing = std.testing.FailingAllocator.init(inner.allocator(), .{ .fail_index = i });
        if (fin.correlationMatrix(failing.allocator(), d, spec)) |m| {
            saw_ok = true;
            // success must be the real answer, not a matrix with a silent null
            try testing.expectApproxEqAbs(@as(f64, 1), m.rows[0][2].float, 1e-12);
            try testing.expectApproxEqAbs(@as(f64, 1), m.rows[1][1].float, 1e-12);
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
    const spec: fin.CorrSpec = .{ .key_col = "k", .date_col = "d", .value_col = "r", .min_overlap = 1 };
    const ok = try fin.correlationMatrix(a, try corrDs(a, fin.max_corr_keys), spec);
    try testing.expectEqual(fin.max_corr_keys, ok.rows.len);
    try testing.expectError(error.TooLarge, fin.correlationMatrix(a, try corrDs(a, fin.max_corr_keys + 1), spec));
}

test "histogram: bins above max_histogram_bins is TooLarge, the cap itself is served (sweep FI4)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try floatDs(a, &.{ 1, 2, 3 });
    const ok = try fin.histogram(a, d, .{ .value_col = "v", .bins = fin.max_histogram_bins });
    try testing.expectEqual(fin.max_histogram_bins, ok.rows.len);
    try testing.expectError(error.TooLarge, fin.histogram(a, d, .{ .value_col = "v", .bins = fin.max_histogram_bins + 1 }));
    try testing.expectError(error.TooLarge, fin.histogram(a, d, .{ .value_col = "v", .bins = std.math.maxInt(usize) }));
    // a dataset with no finite row used to return before looking at `bins`
    const nan = try floatDs(a, &.{std.math.nan(f64)});
    try testing.expectError(error.TooLarge, fin.histogram(a, nan, .{ .value_col = "v", .bins = fin.max_histogram_bins + 1 }));
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

fn mcWith(spec: fin.MonteCarloSpec) fin.Error!Dataset {
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

fn xirrDs(a: std.mem.Allocator) !Dataset {
    const cols = try a.alloc(Column, 3);
    cols[0] = .{ .name = "d", .type = .date };
    cols[1] = .{ .name = "f", .type = .float };
    cols[2] = .{ .name = "v", .type = .float };
    const rows = try a.alloc([]const Value, 2);
    rows[0] = try a.dupe(Value, &.{ .{ .text = "2024-01-01" }, .{ .float = 100 }, .{ .float = 100 } });
    rows[1] = try a.dupe(Value, &.{ .{ .text = "2025-01-01" }, .{ .float = 0 }, .{ .float = 110 } });
    return .{ .columns = cols, .rows = rows };
}

fn xirrNeverMeetsTol() void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const a = arena.allocator();
    const d = xirrDs(a) catch linux.exit_group(2);
    // tol 0 and no rate_tol: Newton can never declare convergence, so the
    // loop runs the whole budget -- here "forever" unless it is clamped.
    const r = fin.xirrPrecise(a, d, .{
        .date_col = "d",
        .flow_col = "f",
        .value_col = "v",
        .opening = .none,
        .tol = 0,
        .rate_tol = null,
        .max_newton_iter = std.math.maxInt(usize),
    }) catch linux.exit_group(3);
    if (!(r > 0.09 and r < 0.11)) linux.exit_group(4);
}

test "xirrPrecise: an unbounded max_newton_iter is clamped, the call terminates with the bisection answer (sweep FI6)" {
    try runChild(xirrNeverMeetsTol, 5000);
}

fn rollDs(a: std.mem.Allocator, n: usize) !Dataset {
    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = "v", .type = .float };
    cols[1] = .{ .name = "b", .type = .float };
    const rows = try a.alloc([]const Value, n);
    const cell = try a.dupe(Value, &.{ .{ .float = 1 }, .{ .float = 2 } });
    @memset(rows, cell);
    return .{ .columns = cols, .rows = rows };
}

test "rollingApply / rollingBetaAlpha: rows x window above max_rolling_work is TooLarge, the cap itself is accepted (sweep FI7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // cap = 2^30 = 2^15 windows x window 2^15  => n = 2^16 - 1
    const w: usize = 1 << 15;
    const at_cap = try rollDs(a, 2 * w - 1);
    const over = try rollDs(a, 2 * w);
    try testing.expectEqual(fin.max_rolling_work, ((2 * w - 1) - w + 1) * w);
    // accepted == passes the check and reaches the `rows` allocation (index 2 / 3)
    var f1 = std.testing.FailingAllocator.init(a, .{ .fail_index = 2 });
    try testing.expectError(error.OutOfMemory, fin.rollingMean(f1.allocator(), at_cap, .{ .value_col = "v", .window = w }));
    var f2 = std.testing.FailingAllocator.init(a, .{ .fail_index = 2 });
    try testing.expectError(error.TooLarge, fin.rollingMean(f2.allocator(), over, .{ .value_col = "v", .window = w }));
    var f3 = std.testing.FailingAllocator.init(a, .{ .fail_index = 3 });
    try testing.expectError(error.OutOfMemory, fin.rollingBetaAlpha(f3.allocator(), at_cap, .{ .port_ret_col = "v", .bench_ret_col = "b", .window = w }));
    var f4 = std.testing.FailingAllocator.init(a, .{ .fail_index = 3 });
    try testing.expectError(error.TooLarge, fin.rollingBetaAlpha(f4.allocator(), over, .{ .port_ret_col = "v", .bench_ret_col = "b", .window = w }));
    // a window of 0 or past the end stays the documented empty result
    const small = try rollDs(a, 4);
    const e0 = try fin.rollingMean(a, small, .{ .value_col = "v", .window = 0 });
    try testing.expectEqual(@as(usize, 0), e0.rows.len);
    const e1 = try fin.rollingMean(a, small, .{ .value_col = "v", .window = std.math.maxInt(usize) });
    try testing.expectEqual(@as(usize, 0), e1.rows.len);
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
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = "d", .type = .date };
    cols[1] = .{ .name = "v", .type = .float };
    const vals = [_]f64{ std.math.nan(f64), 100, 50, 100 };
    const dates = [_][]const u8{ "2024-01-01", "2024-01-02", "2024-01-03", "2024-01-04" };
    const rows = try a.alloc([]const Value, 4);
    for (0..4) |i| rows[i] = try a.dupe(Value, &.{ .{ .text = dates[i] }, .{ .float = vals[i] } });
    const d: Dataset = .{ .columns = cols, .rows = rows };
    const eps = try fin.drawdownEpisodes(a, d, .{ .date_col = "d", .value_col = "v", .top_n = 1 });
    try testing.expectEqual(@as(usize, 1), eps.rows.len);
    try testing.expectEqual(@as(f64, -50), eps.rows[0][3].float);
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

/// Refuses the first request of exactly `target` bytes, passes the rest on.
const FailOnSize = struct {
    child: std.mem.Allocator,
    target: usize,
    hit: bool = false,

    fn allocator(self: *FailOnSize) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FailOnSize = @ptrCast(@alignCast(ctx));
        if (len == self.target and !self.hit) {
            self.hit = true;
            return null;
        }
        return self.child.rawAlloc(len, al, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *FailOnSize = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(m, al, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *FailOnSize = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(m, al, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
        const self: *FailOnSize = @ptrCast(@alignCast(ctx));
        self.child.rawFree(m, al, ra);
    }
};

/// Long-form (key, date, value) dataset: `sizes[k]` dates for key k.
fn corrSizes(a: std.mem.Allocator, sizes: []const usize, extra_row_for_key0: bool) !Dataset {
    const cols = try a.alloc(Column, 3);
    cols[0] = .{ .name = "k", .type = .text };
    cols[1] = .{ .name = "d", .type = .text };
    cols[2] = .{ .name = "r", .type = .float };
    var total: usize = @intFromBool(extra_row_for_key0);
    for (sizes) |n| total += n;
    const rows = try a.alloc([]const Value, total);
    var at: usize = 0;
    var dates: std.ArrayList([]const u8) = .empty;
    for (sizes, 0..) |n, k| {
        const key = try std.fmt.allocPrint(a, "k{d}", .{k});
        const m = n + @intFromBool(extra_row_for_key0 and k == 0);
        for (0..m) |j| {
            while (dates.items.len <= j) try dates.append(a, try std.fmt.allocPrint(a, "d{d}", .{dates.items.len}));
            rows[at] = try a.dupe(Value, &.{ .{ .text = key }, .{ .text = dates.items[j] }, .{ .float = @floatFromInt((k * 7 + j * 3) % 11) } });
            at += 1;
        }
    }
    return .{ .columns = cols, .rows = rows };
}

test "correlationMatrix: total pair work above max_corr_work is TooLarge, exactly the cap is accepted (sweep FI10)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqual(@as(usize, 1 << 28), fin.max_corr_work);
    // 68 keys of 289 dates + 932 keys of 575: sum over pairs of min(len) == 2^28 exactly
    var sizes: [1000]usize = undefined;
    @memset(sizes[0..68], 289);
    @memset(sizes[68..], 575);
    const spec: fin.CorrSpec = .{ .key_col = "k", .date_col = "d", .value_col = "r", .min_overlap = 1 };
    // past the check the next request is the output column array
    var fo: FailOnSize = .{ .child = a, .target = 1001 * @sizeOf(Column) };
    try testing.expectError(error.OutOfMemory, fin.correlationMatrix(fo.allocator(), try corrSizes(a, &sizes, false), spec));
    try testing.expect(fo.hit);
    // one more date on a short key adds 932 to the work
    try testing.expectError(error.TooLarge, fin.correlationMatrix(a, try corrSizes(a, &sizes, true), spec));
}

test "correlationMatrix: the matrix is symmetric and the diagonal is 1 (sweep FI11)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const spec: fin.CorrSpec = .{ .key_col = "k", .date_col = "d", .value_col = "r", .min_overlap = 2 };
    const m = try fin.correlationMatrix(a, try corrSizes(a, &.{ 9, 5, 12, 7, 1 }, false), spec);
    try testing.expectEqual(@as(usize, 5), m.rows.len);
    for (0..5) |i| {
        try testing.expectEqual(@as(f64, 1), m.rows[i][i + 1].float);
        for (0..5) |j| {
            const x = m.rows[i][j + 1];
            const y = m.rows[j][i + 1];
            switch (x) {
                .null => try testing.expect(y == .null),
                .float => |f| try testing.expectEqual(f, y.float), // bit-identical, not approximate
                else => return error.TestUnexpectedResult,
            }
        }
    }
    // the 1-date key has no pair with min_overlap 2
    try testing.expect(m.rows[4][1] == .null);
    try testing.expect(m.rows[0][2] != .null);
}

test "histogram: edges stay finite when span is finite but span x bins is not (sweep FI12)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try floatDs(a, &.{ 0, 1e308, 5e307 });
    const h = try fin.histogram(a, d, .{ .value_col = "v", .bins = 12 });
    try testing.expectEqual(@as(usize, 12), h.rows.len);
    var total: i64 = 0;
    for (h.rows, 0..) |r, i| {
        try testing.expect(std.math.isFinite(r[0].float) and std.math.isFinite(r[1].float));
        try testing.expect(r[0].float <= r[1].float);
        if (i > 0) try testing.expect(r[0].float >= h.rows[i - 1][0].float);
        total += r[2].int;
    }
    try testing.expectEqual(@as(i64, 3), total);
    try testing.expectEqual(@as(f64, 0), h.rows[0][0].float);
    try testing.expectEqual(@as(f64, 1e308), h.rows[11][1].float);
    try testing.expectEqual(@as(i64, 1), h.rows[0][2].int);
    try testing.expectEqual(@as(i64, 1), h.rows[6][2].int); // 5e307 is the midpoint -> bin 6
    try testing.expectEqual(@as(i64, 1), h.rows[11][2].int);
}

fn longXirrDs(a: std.mem.Allocator, n: usize) !Dataset {
    const cols = try a.alloc(Column, 3);
    cols[0] = .{ .name = "d", .type = .date };
    cols[1] = .{ .name = "f", .type = .float };
    cols[2] = .{ .name = "v", .type = .float };
    const rows = try a.alloc([]const Value, n);
    const dates = [_][]const u8{ "2024-01-01", "2024-07-01", "2024-12-31" };
    for (0..n) |i| {
        const last = i + 1 == n;
        rows[i] = try a.dupe(Value, &.{
            .{ .text = if (last) "2025-12-31" else dates[i % 3] },
            .{ .float = 1 },
            .{ .float = if (last) 1.2 * @as(f64, @floatFromInt(n)) else 0 },
        });
    }
    return .{ .columns = cols, .rows = rows };
}

fn xirrLongNeverMeetsTol() void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const a = arena.allocator();
    const d = longXirrDs(a, 100_000) catch linux.exit_group(2);
    // tol 0, no rate_tol, full 10 000-step cap requested: 10 000 steps x 2 x 100 000
    // cashflows is minutes of pow(); the work budget cuts it to 2^26 / n steps.
    const r = fin.xirrPrecise(a, d, .{
        .date_col = "d",
        .flow_col = "f",
        .value_col = "v",
        .opening = .none,
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

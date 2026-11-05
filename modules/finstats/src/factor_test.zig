// SPDX-License-Identifier: MIT

//! Tests for `factor.zig`: factor exposures and performance attribution.
//!
//! External anchor: `testdata/factor_vectors.zig`, made by
//! `tools/factor_oracle.py` from empyrical-reloaded `compute_exposures` and
//! `perf_attrib` over three seeded cases (long-short book, a zero-gross period,
//! NaN position / loading / return / factor return), replayed at 1e-11
//! relative. Hand values pin the empty shapes, the error cases and the
//! additivity identity.

const std = @import("std");
const testing = std.testing;
const factor = @import("factor.zig");
const v = @import("testdata/factor_vectors.zig");

const nan = std.math.nan(f64);

/// Equal within `rel` relative (plus 1e-14 absolute); NaN equals NaN.
fn nearAll(want: []const f64, got: []const f64, rel: f64) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got, 0..) |w, g, i| {
        if (std.math.isNan(w) and std.math.isNan(g)) continue;
        if (@abs(w - g) <= 1e-14 + rel * @abs(w)) continue;
        std.debug.print("index {d}: want {d}, got {d}\n", .{ i, w, g });
        return error.TestUnexpectedResult;
    }
}

test "empyrical vectors: exposures and attribution" {
    for (v.cases) |c| {
        const shape: factor.Shape = .{ .periods = c.t, .assets = c.a, .factors = c.f };
        const ex = try factor.computeExposures(testing.allocator, shape, c.positions, c.loadings);
        defer testing.allocator.free(ex);
        try nearAll(c.exposures, ex, 1e-11);

        var at = try factor.perfAttrib(testing.allocator, shape, c.returns, c.positions, c.factor_returns, c.loadings);
        defer at.deinit(testing.allocator);
        try nearAll(c.exposures, at.exposures, 1e-11);
        try nearAll(c.contributions, at.contributions, 1e-11);
        try nearAll(c.common, at.common, 1e-11);
        try nearAll(c.specific, at.specific, 1e-11);
        try nearAll(c.total, at.total, 1e-11);
        try nearAll(c.tilt, at.tilt, 1e-11);
        try nearAll(c.timing, at.timing, 1e-11);
    }
}

test "contributions plus specific add to total; timing plus tilt is common" {
    for (v.cases) |c| {
        const shape: factor.Shape = .{ .periods = c.t, .assets = c.a, .factors = c.f };
        var at = try factor.perfAttrib(testing.allocator, shape, c.returns, c.positions, c.factor_returns, c.loadings);
        defer at.deinit(testing.allocator);
        for (0..c.t) |t| {
            if (std.math.isNan(at.total[t])) continue;
            var s: f64 = at.specific[t];
            for (0..c.f) |f| {
                const x = at.contributions[t * c.f + f];
                if (!std.math.isNan(x)) s += x;
            }
            try testing.expectApproxEqAbs(at.total[t], s, 1e-15);
            try testing.expectApproxEqAbs(at.common[t], at.tilt[t] + at.timing[t], 1e-15);
        }
    }
}

test "hand values: long-short book, zero gross, skipped NaN" {
    // T=3, A=2, F=1. Period 0: long 2 / short 1; period 1: flat; period 2: a NaN position.
    const pos = [_]f64{ 2, -1, 0, 0, nan, 3 };
    const load = [_]f64{ 0.5, 1.5, 1, 1, 9, 2 };
    const fr = [_]f64{ 0.01, 0.02, -0.01 };
    const ret = [_]f64{ 0.03, 0.005, nan };
    const shape: factor.Shape = .{ .periods = 3, .assets = 2, .factors = 1 };
    var at = try factor.perfAttrib(testing.allocator, shape, &ret, &pos, &fr, &load);
    defer at.deinit(testing.allocator);
    // exposures: 2*0.5 - 1.5 = -0.5; 0; 3*2 = 6 (NaN * 9 skipped)
    try nearAll(&.{ -0.5, 0, 6 }, at.exposures, 1e-15);
    try nearAll(&.{ -0.005, 0, -0.06 }, at.contributions, 1e-15);
    try nearAll(&.{ 0.03, 0.005, nan }, at.total, 0);
    try testing.expect(std.math.isNan(at.specific[2]));
    try testing.expectApproxEqAbs(0.035, at.specific[0], 1e-15);
    // mean exposure (-0.5 + 0 + 6) / 3
    try testing.expectApproxEqAbs(5.5 / 3.0, at.mean_exposures[0], 1e-15);
    try testing.expectApproxEqAbs(5.5 / 3.0 * 0.02, at.tilt[1], 1e-15);
    try testing.expectApproxEqAbs(-5.5 / 3.0 * 0.02, at.timing[1], 1e-15);
}

test "empty shapes have defined answers" {
    const a = testing.allocator;
    // no periods
    var at = try factor.perfAttrib(a, .{ .periods = 0, .assets = 2, .factors = 2 }, &.{}, &.{}, &.{}, &.{});
    try testing.expectEqual(@as(usize, 0), at.common.len);
    try nearAll(&.{ 0, 0 }, at.mean_exposures, 0);
    at.deinit(a);
    // no assets: zero exposures
    var at2 = try factor.perfAttrib(a, .{ .periods = 2, .assets = 0, .factors = 2 }, &.{ 0.1, 0.2 }, &.{}, &.{ 0.1, 0.2, 0.3, 0.4 }, &.{});
    defer at2.deinit(a);
    try nearAll(&.{ 0, 0, 0, 0 }, at2.exposures, 0);
    try nearAll(&.{ 0.1, 0.2 }, at2.specific, 0);
    // no factors: specific is the return
    var at3 = try factor.perfAttrib(a, .{ .periods = 2, .assets = 2, .factors = 0 }, &.{ 0.1, 0.2 }, &.{ 1, 2, 3, 4 }, &.{}, &.{});
    defer at3.deinit(a);
    try nearAll(&.{ 0.1, 0.2 }, at3.specific, 0);
    try nearAll(&.{ 0, 0 }, at3.common, 0);
    try nearAll(&.{ 0, 0 }, at3.timing, 0);
    const ex = try factor.computeExposures(a, .{ .periods = 0, .assets = 0, .factors = 0 }, &.{}, &.{});
    defer a.free(ex);
    try testing.expectEqual(@as(usize, 0), ex.len);
}

test "length mismatch and overflow" {
    const a = testing.allocator;
    const s: factor.Shape = .{ .periods = 2, .assets = 2, .factors = 1 };
    const p = [_]f64{ 1, 2, 3, 4 };
    const l = [_]f64{ 1, 2, 3, 4 };
    const fr = [_]f64{ 1, 2 };
    const r = [_]f64{ 1, 2 };
    try testing.expectError(error.LengthMismatch, factor.computeExposures(a, s, p[0..3], &l));
    try testing.expectError(error.LengthMismatch, factor.computeExposures(a, s, &p, l[0..3]));
    try testing.expectError(error.LengthMismatch, factor.perfAttrib(a, s, r[0..1], &p, &fr, &l));
    try testing.expectError(error.LengthMismatch, factor.perfAttrib(a, s, &r, p[0..3], &fr, &l));
    try testing.expectError(error.LengthMismatch, factor.perfAttrib(a, s, &r, &p, fr[0..1], &l));
    try testing.expectError(error.LengthMismatch, factor.perfAttrib(a, s, &r, &p, &fr, l[0..3]));
    const big = std.math.maxInt(usize);
    try testing.expectError(error.TooLarge, factor.computeExposures(a, .{ .periods = big, .assets = 2, .factors = 1 }, &.{}, &.{}));
    try testing.expectError(error.TooLarge, factor.computeExposures(a, .{ .periods = 1 << 40, .assets = 1 << 20, .factors = 1 << 10 }, &.{}, &.{}));
    try testing.expectError(error.TooLarge, factor.perfAttrib(a, .{ .periods = 1 << 40, .assets = 1, .factors = 1 << 40 }, &.{}, &.{}, &.{}, &.{}));
}

fn allocCase(a: std.mem.Allocator) !void {
    const c = v.cases[0];
    const shape: factor.Shape = .{ .periods = c.t, .assets = c.a, .factors = c.f };
    const ex = try factor.computeExposures(a, shape, c.positions, c.loadings);
    a.free(ex);
    var at = try factor.perfAttrib(a, shape, c.returns, c.positions, c.factor_returns, c.loadings);
    at.deinit(a);
}

test "allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, allocCase, .{});
}

test "a shape alone cannot ask for an unbounded output" {
    const a = std.testing.failing_allocator;
    const none: []const f64 = &.{};
    const big = factor.max_output_cells + 1;
    try std.testing.expectError(error.TooLarge, factor.computeExposures(a, .{ .periods = big, .assets = 0, .factors = 1 }, none, none));
    try std.testing.expectError(error.TooLarge, factor.computeExposures(a, .{ .periods = 0, .assets = 0, .factors = big }, none, none));
    try std.testing.expectError(error.TooLarge, factor.perfAttrib(a, .{ .periods = 0, .assets = 3, .factors = big }, none, none, none, none));
}

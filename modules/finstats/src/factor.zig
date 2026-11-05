// SPDX-License-Identifier: MIT
//! Factor exposures and performance attribution: empyrical-reloaded's
//! `compute_exposures` and `perf_attrib`, on flat row-major arrays instead of
//! pandas frames.
//!
//! Shape. T periods, A assets, F factors (`Shape`). `positions` is T*A
//! (`[t * A + a]`), `factor_loadings` T*A*F (`[(t * A + a) * F + f]`),
//! `factor_returns` T*F, `returns` T. A wrong length is `error.LengthMismatch`,
//! a product that does not fit `usize` or passes `max_output_cells` is
//! `error.TooLarge`. Nothing panics;
//! work is O(T*A*F).
//!
//! Conventions, each measured by running empyrical as a black box
//! (`tools/factor_oracle.py`):
//!   - exposure of factor f in period t is the plain sum over assets of
//!     position * loading. Positions are used as given: no normalisation by
//!     gross exposure, so a period with zero gross exposure has exposure 0 for
//!     every factor (and a short book simply has negative weights);
//!   - a position * loading product that is NaN (a NaN position or loading, or
//!     an asset absent that period, written as NaN) is skipped, as pandas
//!     `sum` skips it: the asset contributes 0 to that factor. A period where
//!     everything is skipped has exposure 0;
//!   - contribution of factor f = exposure * factor return;
//!   - common return = sum of the contributions, skipping NaN (a NaN factor
//!     return drops only that factor's term); specific return = return -
//!     common; total return = the input return, unchanged (so NaN in, NaN out
//!     for total and specific);
//!   - tilt return = sum over factors of (mean exposure over all T periods) *
//!     factor return, again skipping NaN; timing return = common - tilt.
//! Empty shapes: T = 0 gives empty outputs; A = 0 gives zero exposures; F = 0
//! gives no contributions, common = tilt = timing = 0 and specific = return.

const std = @import("std");

/// Errors of this file; a subset of `slice.Error`, so it coerces into it.
pub const Error = error{ OutOfMemory, TooLarge, LengthMismatch };

/// Most output cells one call will produce (T*F, and F): 2^28 `f64` = 2 GiB. With no
/// assets or no periods the inputs are empty and do not bound the shape, so a shape
/// alone could otherwise ask for any size. Above it `error.TooLarge`.
pub const max_output_cells: usize = 1 << 28;

/// Dimensions of the arrays: periods, assets, factors.
pub const Shape = struct {
    /// Number of periods T (rows of every input).
    periods: usize,
    /// Number of assets A.
    assets: usize,
    /// Number of factors F.
    factors: usize,
};

/// Result of `perfAttrib`. All slices are owned by the caller; free with `deinit`.
pub const Attribution = struct {
    /// Exposure of each factor per period, T*F row-major (`computeExposures`).
    exposures: []f64,
    /// Return contributed by each factor per period, T*F: exposure * factor return.
    contributions: []f64,
    /// Sum of the factor contributions per period (NaN terms skipped), T.
    common: []f64,
    /// Return minus the common return per period, T.
    specific: []f64,
    /// The input return per period, T.
    total: []f64,
    /// Return explained by the average exposure of the whole span per period, T.
    tilt: []f64,
    /// Common return minus tilt return per period, T.
    timing: []f64,
    /// Exposure of each factor averaged over the T periods, F (0 when T = 0).
    mean_exposures: []f64,

    /// Frees every slice with the allocator that made them.
    pub fn deinit(self: *Attribution, allocator: std.mem.Allocator) void {
        allocator.free(self.exposures);
        allocator.free(self.contributions);
        allocator.free(self.common);
        allocator.free(self.specific);
        allocator.free(self.total);
        allocator.free(self.tilt);
        allocator.free(self.timing);
        allocator.free(self.mean_exposures);
        self.* = undefined;
    }
};

fn mulSize(a: usize, b: usize) Error!usize {
    return std.math.mul(usize, a, b) catch error.TooLarge;
}

/// Checked lengths of the arrays for a shape.
const Sizes = struct { ta: usize, tf: usize, taf: usize };

fn sizesOf(shape: Shape) Error!Sizes {
    const ta = try mulSize(shape.periods, shape.assets);
    const tf = try mulSize(shape.periods, shape.factors);
    const taf = try mulSize(ta, shape.factors);
    if (tf > max_output_cells or shape.factors > max_output_cells) return error.TooLarge;
    return .{ .ta = ta, .tf = tf, .taf = taf };
}

/// Fills `out` (T*F, already length-checked) with the exposures.
fn exposuresInto(shape: Shape, positions: []const f64, loadings: []const f64, out: []f64) void {
    const nf = shape.factors;
    const na = shape.assets;
    if (out.len == 0) return; // no cells; `periods` alone may be any number
    for (0..shape.periods) |t| {
        for (0..nf) |f| {
            var s: f64 = 0;
            for (0..na) |a| {
                const p = positions[t * na + a] * loadings[(t * na + a) * nf + f];
                if (!std.math.isNan(p)) s += p;
            }
            out[t * nf + f] = s;
        }
    }
}

/// Exposure of the portfolio to each factor in each period (empyrical
/// `compute_exposures`): per period and factor, the sum over assets of
/// position * loading, skipping NaN products. Returns T*F values, row-major,
/// owned by the caller. Zero gross exposure gives 0. Errors: `LengthMismatch`
/// when `positions.len != T*A` or `factor_loadings.len != T*A*F`; `TooLarge`
/// when a product of the shape overflows.
pub fn computeExposures(
    allocator: std.mem.Allocator,
    shape: Shape,
    positions: []const f64,
    factor_loadings: []const f64,
) Error![]f64 {
    const sz = try sizesOf(shape);
    if (positions.len != sz.ta or factor_loadings.len != sz.taf) return error.LengthMismatch;
    const out = try allocator.alloc(f64, sz.tf);
    exposuresInto(shape, positions, factor_loadings, out);
    return out;
}

/// Performance attribution (empyrical `perf_attrib`): splits each period's
/// return into factor contributions, a common return and a specific return,
/// plus the tilt/timing split of the common return. See the file comment for
/// every convention. Errors as `computeExposures`, and `LengthMismatch` when
/// `returns.len != T` or `factor_returns.len != T*F`.
pub fn perfAttrib(
    allocator: std.mem.Allocator,
    shape: Shape,
    returns: []const f64,
    positions: []const f64,
    factor_returns: []const f64,
    factor_loadings: []const f64,
) Error!Attribution {
    const sz = try sizesOf(shape);
    if (returns.len != shape.periods or positions.len != sz.ta or
        factor_returns.len != sz.tf or factor_loadings.len != sz.taf)
        return error.LengthMismatch;
    const nt = shape.periods;
    const nf = shape.factors;

    const exposures = try allocator.alloc(f64, sz.tf);
    errdefer allocator.free(exposures);
    const contributions = try allocator.alloc(f64, sz.tf);
    errdefer allocator.free(contributions);
    const common = try allocator.alloc(f64, nt);
    errdefer allocator.free(common);
    const specific = try allocator.alloc(f64, nt);
    errdefer allocator.free(specific);
    const total = try allocator.alloc(f64, nt);
    errdefer allocator.free(total);
    const tilt = try allocator.alloc(f64, nt);
    errdefer allocator.free(tilt);
    const timing = try allocator.alloc(f64, nt);
    errdefer allocator.free(timing);
    const mean_exp = try allocator.alloc(f64, nf);
    errdefer allocator.free(mean_exp);

    exposuresInto(shape, positions, factor_loadings, exposures);

    for (0..nf) |f| {
        var s: f64 = 0;
        for (0..nt) |t| s += exposures[t * nf + f];
        mean_exp[f] = if (nt == 0) 0 else s / @as(f64, @floatFromInt(nt));
    }

    for (0..nt) |t| {
        var c: f64 = 0;
        var tl: f64 = 0;
        for (0..nf) |f| {
            const fr = factor_returns[t * nf + f];
            const contrib = exposures[t * nf + f] * fr;
            contributions[t * nf + f] = contrib;
            if (!std.math.isNan(contrib)) c += contrib;
            const til = mean_exp[f] * fr;
            if (!std.math.isNan(til)) tl += til;
        }
        common[t] = c;
        total[t] = returns[t];
        specific[t] = returns[t] - c;
        tilt[t] = tl;
        timing[t] = c - tl;
    }

    return .{
        .exposures = exposures,
        .contributions = contributions,
        .common = common,
        .specific = specific,
        .total = total,
        .tilt = tilt,
        .timing = timing,
        .mean_exposures = mean_exp,
    };
}

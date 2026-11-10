// SPDX-License-Identifier: MIT
//! One-dimensional interpolants behind `interpolate(method = quadratic | cubic | pchip |
//! akima)` (pandas `Series.interpolate` hands them to SciPy: `interp1d(kind="quadratic" |
//! "cubic")`, `PchipInterpolator`, `Akima1DInterpolator`). The algorithms are the
//! textbook ones SciPy documents, written out here: a not-a-knot B-spline collocation
//! with banded Gaussian elimination, Fritsch-Carlson PCHIP derivatives with the
//! one-sided three-point end rule, Akima's weighted slopes, and piecewise cubic Hermite
//! evaluation. Written from the published algorithms by the zig-libs authors (MIT); the
//! numerics deliberately match SciPy 1.18 (the PCHIP slope and end rules, the Hermite
//! coefficient form, Akima's flat-region threshold), whose `interpolate` sources and
//! pandas' `core/missing.py` (both BSD-3-Clause) were consulted as design references for
//! those edge rules — no source copied (README § Provenance).

const std = @import("std");

pub const Kind = enum { quadratic, cubic, pchip, akima };

/// `BadArgument` is what SciPy answers with a `ValueError`: too few points for the
/// method, repeated or unsorted x, a non-finite y (or a derivative that overflows) for
/// PCHIP / Akima.
pub const Error = error{ OutOfMemory, BadArgument };

pub const Fit = struct {
    kind: Kind,
    /// Non-finite input to a B-spline: SciPy returns NaN everywhere.
    poisoned: bool = false,
    /// B-spline degree (quadratic, cubic).
    k: usize = 0,
    /// B-spline knots / Hermite breakpoints.
    t: []f64 = &.{},
    /// B-spline coefficients / four Hermite coefficients per interval, highest power first.
    c: []f64 = &.{},

    pub fn deinit(f: *Fit, a: std.mem.Allocator) void {
        a.free(f.t);
        a.free(f.c);
        f.* = undefined;
    }

    /// The value at `x`, or null: outside the data for every kind but PCHIP (SciPy's
    /// `interp1d` fills NaN, `Akima1DInterpolator` does not extrapolate; PCHIP
    /// extrapolates with the first / last cubic), or where the result is not a number.
    pub fn eval(f: Fit, x: f64) ?f64 {
        if (f.poisoned or std.math.isNan(x)) return null;
        const v = switch (f.kind) {
            .quadratic, .cubic => f.evalSpline(x) orelse return null,
            .pchip, .akima => f.evalHermite(x, f.kind == .pchip) orelse return null,
        };
        return if (std.math.isNan(v)) null else v;
    }

    fn nCoef(f: Fit) usize {
        return f.c.len;
    }

    fn evalSpline(f: Fit, x: f64) ?f64 {
        const nt = f.nCoef();
        const k = f.k;
        if (!(x >= f.t[k] and x <= f.t[nt])) return null;
        const l = span(f.t, k, nt, x);
        var nb: [4]f64 = undefined;
        basis(f.t, k, l, x, &nb);
        var s: f64 = 0;
        for (0..k + 1) |j| s += f.c[l - k + j] * nb[j];
        return s;
    }

    fn evalHermite(f: Fit, x: f64, extrapolate: bool) ?f64 {
        const n = f.t.len;
        if (!extrapolate and !(x >= f.t[0] and x <= f.t[n - 1])) return null;
        var i: usize = 0;
        if (x >= f.t[n - 1]) {
            i = n - 2;
        } else if (x > f.t[0]) {
            var lo: usize = 0;
            var hi: usize = n - 1;
            while (lo + 1 < hi) {
                const mid = lo + (hi - lo) / 2;
                if (f.t[mid] <= x) lo = mid else hi = mid;
            }
            i = lo;
        }
        const dx = x - f.t[i];
        const c = f.c[4 * i ..][0..4];
        var res: f64 = 0;
        var z: f64 = 1;
        var kp: usize = 0;
        while (kp < 4) : (kp += 1) {
            res += c[3 - kp] * z;
            z *= dx;
        }
        return res;
    }
};

/// Fit `ys` over the sorted `xs`. The slices are not kept.
pub fn fit(a: std.mem.Allocator, kind: Kind, xs: []const f64, ys: []const f64) Error!Fit {
    std.debug.assert(xs.len == ys.len);
    const n = xs.len;
    const need: usize = switch (kind) {
        .quadratic => 3,
        .cubic => 4,
        .pchip, .akima => 2,
    };
    if (n < need) return error.BadArgument;
    for (1..n) |i| if (!(xs[i] > xs[i - 1])) return error.BadArgument;
    var finite = true;
    for (xs) |x| finite = finite and std.math.isFinite(x);
    for (ys) |y| finite = finite and std.math.isFinite(y);
    switch (kind) {
        .quadratic, .cubic => {
            if (!finite) return .{ .kind = kind, .poisoned = true };
            return bspline(a, kind, xs, ys);
        },
        .pchip, .akima => {
            if (!finite) return error.BadArgument;
            const d = try a.alloc(f64, n);
            defer a.free(d);
            if (kind == .pchip) pchipSlopes(xs, ys, d) else try akimaSlopes(a, xs, ys, d);
            for (d) |v| if (!std.math.isFinite(v)) return error.BadArgument;
            const t = try a.dupe(f64, xs);
            errdefer a.free(t);
            const c = try a.alloc(f64, 4 * (n - 1));
            for (0..n - 1) |i| {
                const dx = xs[i + 1] - xs[i];
                const slope = (ys[i + 1] - ys[i]) / dx;
                const tt = (d[i] + d[i + 1] - 2 * slope) / dx;
                c[4 * i] = tt / dx;
                c[4 * i + 1] = (slope - d[i]) / dx - tt;
                c[4 * i + 2] = d[i];
                c[4 * i + 3] = ys[i];
            }
            return .{ .kind = kind, .t = t, .c = c };
        },
    }
}

fn sgn(v: f64) f64 {
    return if (v > 0) 1 else if (v < 0) -1 else 0;
}

/// Fritsch-Carlson derivatives with Moler's one-sided end rule (SciPy `PchipInterpolator`).
fn pchipSlopes(x: []const f64, y: []const f64, d: []f64) void {
    const n = x.len;
    if (n == 2) {
        const m = (y[1] - y[0]) / (x[1] - x[0]);
        d[0] = m;
        d[1] = m;
        return;
    }
    // h[k], m[k] belong to the segment k .. k + 1; read on the fly.
    for (1..n - 1) |k| {
        const hk = x[k + 1] - x[k];
        const hp = x[k] - x[k - 1];
        const mk = (y[k + 1] - y[k]) / hk;
        const mp = (y[k] - y[k - 1]) / hp;
        if (sgn(mk) != sgn(mp) or mk == 0 or mp == 0) {
            d[k] = 0;
        } else {
            const w1 = 2 * hk + hp;
            const w2 = hk + 2 * hp;
            const whmean = (w1 / mp + w2 / mk) / (w1 + w2);
            d[k] = 1.0 / whmean;
        }
    }
    d[0] = pchipEnd(x[1] - x[0], x[2] - x[1], (y[1] - y[0]) / (x[1] - x[0]), (y[2] - y[1]) / (x[2] - x[1]));
    d[n - 1] = pchipEnd(x[n - 1] - x[n - 2], x[n - 2] - x[n - 3], (y[n - 1] - y[n - 2]) / (x[n - 1] - x[n - 2]), (y[n - 2] - y[n - 3]) / (x[n - 2] - x[n - 3]));
}

fn pchipEnd(h0: f64, h1: f64, m0: f64, m1: f64) f64 {
    var d = ((2 * h0 + h1) * m0 - h0 * m1) / (h0 + h1);
    const mask = sgn(d) != sgn(m0);
    const mask2 = sgn(m0) != sgn(m1) and @abs(d) > 3.0 * @abs(m0);
    if (mask) d = 0;
    if (!mask and mask2) d = 3.0 * m0;
    return d;
}

/// Akima's slopes (SciPy `Akima1DInterpolator`, method "akima").
fn akimaSlopes(a: std.mem.Allocator, x: []const f64, y: []const f64, d: []f64) Error!void {
    const n = x.len;
    if (n == 2) {
        const m = (y[1] - y[0]) / (x[1] - x[0]);
        d[0] = m;
        d[1] = m;
        return;
    }
    const m = try a.alloc(f64, n + 3);
    defer a.free(m);
    for (0..n - 1) |i| m[2 + i] = (y[i + 1] - y[i]) / (x[i + 1] - x[i]);
    m[1] = 2 * m[2] - m[3];
    m[0] = 2 * m[1] - m[2];
    m[n + 1] = 2 * m[n] - m[n - 1];
    m[n + 2] = 2 * m[n + 1] - m[n];
    // f1[i] = |m[i+3] - m[i+2]|, f2[i] = |m[i+1] - m[i]|; the largest f1 + f2 sets the cutoff.
    var mmax: f64 = -std.math.inf(f64);
    for (0..n) |i| {
        const f12 = @abs(m[i + 3] - m[i + 2]) + @abs(m[i + 1] - m[i]);
        if (f12 > mmax or std.math.isNan(f12)) mmax = f12;
    }
    for (0..n) |i| {
        const f1 = @abs(m[i + 3] - m[i + 2]);
        const f2 = @abs(m[i + 1] - m[i]);
        const f12 = f1 + f2;
        d[i] = if (f12 > 1e-9 * mmax) m[i + 1] + (f2 / f12) * (m[i + 2] - m[i + 1]) else 0.5 * (m[i + 3] + m[i]);
    }
}

/// Largest l in [k, nt - 1] with t[l] <= x.
fn span(t: []const f64, k: usize, nt: usize, x: f64) usize {
    var lo = k;
    var hi = nt - 1;
    while (lo < hi) {
        const mid = lo + (hi - lo + 1) / 2;
        if (t[mid] <= x) lo = mid else hi = mid - 1;
    }
    return lo;
}

/// The k + 1 B-splines that are not zero on [t[l], t[l+1]) at `x` (Cox-de Boor); out[j] is
/// the spline number l - k + j.
fn basis(t: []const f64, k: usize, l: usize, x: f64, out: *[4]f64) void {
    var left: [4]f64 = undefined;
    var right: [4]f64 = undefined;
    out[0] = 1;
    for (1..k + 1) |j| {
        left[j] = x - t[l + 1 - j];
        right[j] = t[l + j] - x;
        var saved: f64 = 0;
        for (0..j) |r| {
            const tmp = out[r] / (right[r + 1] + left[j - r]);
            out[r] = saved + right[r + 1] * tmp;
            saved = left[j - r] * tmp;
        }
        out[j] = saved;
    }
}

/// The interpolating spline of degree 2 or 3 with SciPy's `make_interp_spline` knots:
/// cubic: the data sites without the second and the last but one (not-a-knot); quadratic:
/// the midpoints of the sites, again without the second and the last but one.
fn bspline(a: std.mem.Allocator, kind: Kind, xs: []const f64, ys: []const f64) Error!Fit {
    const n = xs.len;
    const k: usize = if (kind == .cubic) 3 else 2;
    const nt = n;
    const t = try a.alloc(f64, nt + k + 1);
    errdefer a.free(t);
    for (0..k + 1) |i| {
        t[i] = xs[0];
        t[nt + i] = xs[n - 1];
    }
    // The nt - k - 1 interior knots: cubic xs[2 .. n - 2]; quadratic the midpoints
    // (xs[j] + xs[j + 1]) / 2 for j = 1 .. n - 3.
    for (0..nt - k - 1) |i| {
        t[k + 1 + i] = if (k == 3) xs[2 + i] else (xs[1 + i] + xs[2 + i]) / 2;
    }
    // Collocation matrix in rows of the window [i - k, i + 2k] (room for the pivoting fill).
    const w = 3 * k + 1;
    const ab = try a.alloc(f64, n * w);
    defer a.free(ab);
    @memset(ab, 0);
    const rhs = try a.dupe(f64, ys);
    defer a.free(rhs);
    var nb: [4]f64 = undefined;
    for (0..n) |i| {
        const l = span(t, k, nt, xs[i]);
        basis(t, k, l, xs[i], &nb);
        for (0..k + 1) |j| {
            const col = l - k + j;
            if (col + k < i or col > i + 2 * k) return error.BadArgument;
            ab[i * w + (col + k - i)] = nb[j];
        }
    }
    // Gaussian elimination with partial pivoting; entry (r, col) is ab[r * w + col + k - r].
    for (0..n) |c| {
        const last = @min(c + k, n - 1);
        var p = c;
        var best = @abs(ab[c * w + k]);
        for (c + 1..last + 1) |r| {
            const v = @abs(ab[r * w + (c + k - r)]);
            if (v > best) {
                best = v;
                p = r;
            }
        }
        if (!(best > 0)) return error.BadArgument;
        const hi = @min(c + 2 * k, n - 1);
        if (p != c) {
            for (c..hi + 1) |col| {
                const ic = c * w + (col + k - c);
                const ip = p * w + (col + k - p);
                std.mem.swap(f64, &ab[ic], &ab[ip]);
            }
            std.mem.swap(f64, &rhs[c], &rhs[p]);
        }
        const piv = ab[c * w + k];
        for (c + 1..last + 1) |r| {
            const f = ab[r * w + (c + k - r)] / piv;
            if (f == 0) continue;
            for (c..hi + 1) |col| ab[r * w + (col + k - r)] -= f * ab[c * w + (col + k - c)];
            rhs[r] -= f * rhs[c];
        }
    }
    const coef = try a.alloc(f64, n);
    errdefer a.free(coef);
    var i = n;
    while (i > 0) {
        i -= 1;
        var s = rhs[i];
        const hi = @min(i + 2 * k, n - 1);
        for (i + 1..hi + 1) |col| s -= ab[i * w + (col + k - i)] * coef[col];
        coef[i] = s / ab[i * w + k];
    }
    return .{ .kind = kind, .k = k, .t = t, .c = coef };
}

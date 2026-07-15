// SPDX-License-Identifier: MIT
//! fft — floating-point FFT over R[x]/(x^n+1), the transform Falcon's
//! trapdoor sampler runs in. Ported from the Falcon Round-3 reference
//! `fft.c` (`Zf(FFT)`/`Zf(iFFT)` and the `poly_*_fft` helpers), using the
//! `fpr` layer for bit-exact arithmetic.
//!
//! Internal representation matches the reference exactly: a degree-n real
//! polynomial's FFT lives in a flat `[n]f64` where slot k holds Re(f(w_j))
//! and slot k+n/2 holds Im(f(w_j)), for the reference's bit-reversed
//! ordering of the roots. All the signer math (`ffsampling.zig`) runs on
//! these flat buffers via the `raw`/`poly*` functions here; the
//! scaffold's `Complex`/`FftPoly` `fft`/`ifft` entry points are thin
//! adapters over `fftRaw`/`ifftRaw` kept for API shape.

const std = @import("std");
const fpr = @import("fpr.zig");

/// In-place forward FFT on a flat `[n]f64` (n = 1<<logn), reference layout.
pub fn fftRaw(f: []f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var t = hn;
    var u: u5 = 1;
    var m: usize = 2;
    while (u < logn) : (u += 1) {
        const ht = t >> 1;
        const hm = m >> 1;
        var ii: usize = 0;
        var j1: usize = 0;
        while (ii < hm) : (ii += 1) {
            const j2 = j1 + ht;
            const s_re = fpr.gm_tab[((m + ii) << 1) + 0];
            const s_im = fpr.gm_tab[((m + ii) << 1) + 1];
            var j = j1;
            while (j < j2) : (j += 1) {
                const x_re = f[j];
                const x_im = f[j + hn];
                var y_re = f[j + ht];
                var y_im = f[j + ht + hn];
                // (y_re,y_im) *= (s_re,s_im)
                const ny_re = fpr.sub(fpr.mul(y_re, s_re), fpr.mul(y_im, s_im));
                const ny_im = fpr.add(fpr.mul(y_re, s_im), fpr.mul(y_im, s_re));
                y_re = ny_re;
                y_im = ny_im;
                f[j] = fpr.add(x_re, y_re);
                f[j + hn] = fpr.add(x_im, y_im);
                f[j + ht] = fpr.sub(x_re, y_re);
                f[j + ht + hn] = fpr.sub(x_im, y_im);
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

/// In-place inverse FFT on a flat `[n]f64` (reference layout).
pub fn ifftRaw(f: []f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var t: usize = 1;
    var m: usize = n;
    var u: u5 = logn;
    while (u > 1) : (u -= 1) {
        const hm = m >> 1;
        const dt = t << 1;
        var ii: usize = 0;
        var j1: usize = 0;
        while (j1 < hn) : (ii += 1) {
            const j2 = j1 + t;
            const s_re = fpr.gm_tab[((hm + ii) << 1) + 0];
            const s_im = fpr.neg(fpr.gm_tab[((hm + ii) << 1) + 1]);
            var j = j1;
            while (j < j2) : (j += 1) {
                var x_re = f[j];
                var x_im = f[j + hn];
                const y_re = f[j + t];
                const y_im = f[j + t + hn];
                f[j] = fpr.add(x_re, y_re);
                f[j + hn] = fpr.add(x_im, y_im);
                x_re = fpr.sub(x_re, y_re);
                x_im = fpr.sub(x_im, y_im);
                // (f[j+t],f[j+t+hn]) = (x)*(s)
                f[j + t] = fpr.sub(fpr.mul(x_re, s_re), fpr.mul(x_im, s_im));
                f[j + t + hn] = fpr.add(fpr.mul(x_re, s_im), fpr.mul(x_im, s_re));
            }
            j1 += dt;
        }
        t = dt;
        m = hm;
    }
    if (logn > 0) {
        const ni = fpr.p2_tab[logn];
        var i: usize = 0;
        while (i < n) : (i += 1) f[i] = fpr.mul(f[i], ni);
    }
}

// ---- Flat-buffer polynomial ops in the FFT domain (reference fft.c) ----

pub fn polyAdd(a: []f64, b: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    var u: usize = 0;
    while (u < n) : (u += 1) a[u] = fpr.add(a[u], b[u]);
}

pub fn polySub(a: []f64, b: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    var u: usize = 0;
    while (u < n) : (u += 1) a[u] = fpr.sub(a[u], b[u]);
}

pub fn polyNeg(a: []f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    var u: usize = 0;
    while (u < n) : (u += 1) a[u] = fpr.neg(a[u]);
}

pub fn polyMulFft(a: []f64, b: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        const a_re = a[u];
        const a_im = a[u + hn];
        const b_re = b[u];
        const b_im = b[u + hn];
        a[u] = fpr.sub(fpr.mul(a_re, b_re), fpr.mul(a_im, b_im));
        a[u + hn] = fpr.add(fpr.mul(a_re, b_im), fpr.mul(a_im, b_re));
    }
}

pub fn polyMulAdjFft(a: []f64, b: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        const a_re = a[u];
        const a_im = a[u + hn];
        const b_re = b[u];
        const b_im = fpr.neg(b[u + hn]);
        a[u] = fpr.sub(fpr.mul(a_re, b_re), fpr.mul(a_im, b_im));
        a[u + hn] = fpr.add(fpr.mul(a_re, b_im), fpr.mul(a_im, b_re));
    }
}

pub fn polyMulselfadjFft(a: []f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        const a_re = a[u];
        const a_im = a[u + hn];
        a[u] = fpr.add(fpr.sqr(a_re), fpr.sqr(a_im));
        a[u + hn] = 0.0;
    }
}

pub fn polyMulconst(a: []f64, x: f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    var u: usize = 0;
    while (u < n) : (u += 1) a[u] = fpr.mul(a[u], x);
}

pub fn polyLdlFft(g00: []const f64, g01: []f64, g11: []f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        const g00_re = g00[u];
        const g00_im = g00[u + hn];
        const g01_re = g01[u];
        const g01_im = g01[u + hn];
        const g11_re = g11[u];
        const g11_im = g11[u + hn];
        // mu = g01 / g00
        const inv_m = fpr.inv(fpr.add(fpr.sqr(g00_re), fpr.sqr(g00_im)));
        const b_re = fpr.mul(g00_re, inv_m);
        const b_im = fpr.mul(fpr.neg(g00_im), inv_m);
        const mu_re = fpr.sub(fpr.mul(g01_re, b_re), fpr.mul(g01_im, b_im));
        const mu_im = fpr.add(fpr.mul(g01_re, b_im), fpr.mul(g01_im, b_re));
        // g01' = mu * conj(g01)
        const p_re = fpr.sub(fpr.mul(mu_re, g01_re), fpr.mul(mu_im, fpr.neg(g01_im)));
        const p_im = fpr.add(fpr.mul(mu_re, fpr.neg(g01_im)), fpr.mul(mu_im, g01_re));
        g11[u] = fpr.sub(g11_re, p_re);
        g11[u + hn] = fpr.sub(g11_im, p_im);
        g01[u] = mu_re;
        g01[u + hn] = fpr.neg(mu_im);
    }
}

pub fn polyLdlmvFft(d11: []f64, l10: []f64, g00: []const f64, g01: []const f64, g11: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        const g00_re = g00[u];
        const g00_im = g00[u + hn];
        const g01_re = g01[u];
        const g01_im = g01[u + hn];
        const g11_re = g11[u];
        const g11_im = g11[u + hn];
        const inv_m = fpr.inv(fpr.add(fpr.sqr(g00_re), fpr.sqr(g00_im)));
        const b_re = fpr.mul(g00_re, inv_m);
        const b_im = fpr.mul(fpr.neg(g00_im), inv_m);
        const mu_re = fpr.sub(fpr.mul(g01_re, b_re), fpr.mul(g01_im, b_im));
        const mu_im = fpr.add(fpr.mul(g01_re, b_im), fpr.mul(g01_im, b_re));
        const p_re = fpr.sub(fpr.mul(mu_re, g01_re), fpr.mul(mu_im, fpr.neg(g01_im)));
        const p_im = fpr.add(fpr.mul(mu_re, fpr.neg(g01_im)), fpr.mul(mu_im, g01_re));
        d11[u] = fpr.sub(g11_re, p_re);
        d11[u + hn] = fpr.sub(g11_im, p_im);
        l10[u] = mu_re;
        l10[u + hn] = fpr.neg(mu_im);
    }
}

// ---- Keygen-side helpers (reference fft.c; used by ntru.zig's NTRUSolve
// Babai reduction and NTRUGen's Gram-Schmidt norm check). Same flat
// FFT-domain layout and exact `fpr` op order as everything above. ----

/// a = adj(a) in the FFT domain (negate the imaginary halves).
pub fn polyAdjFft(a: []f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    var u = n >> 1;
    while (u < n) : (u += 1) a[u] = fpr.neg(a[u]);
}

/// d = 1 / (a*adj(a) + b*adj(b)) (auto-adjoint, so only hn real slots).
pub fn polyInvnorm2Fft(d: []f64, a: []const f64, b: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        const a_re = a[u];
        const a_im = a[u + hn];
        const b_re = b[u];
        const b_im = b[u + hn];
        d[u] = fpr.inv(fpr.add(
            fpr.add(fpr.sqr(a_re), fpr.sqr(a_im)),
            fpr.add(fpr.sqr(b_re), fpr.sqr(b_im)),
        ));
    }
}

/// d = F*adj(f) + G*adj(g).
pub fn polyAddMuladjFft(
    d: []f64,
    big_f: []const f64,
    big_g: []const f64,
    f: []const f64,
    g: []const f64,
    logn: u5,
) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        const f_re = big_f[u];
        const f_im = big_f[u + hn];
        const g_re = big_g[u];
        const g_im = big_g[u + hn];
        const sf_re = f[u];
        const sf_im = fpr.neg(f[u + hn]);
        const sg_re = g[u];
        const sg_im = fpr.neg(g[u + hn]);
        const a_re = fpr.sub(fpr.mul(f_re, sf_re), fpr.mul(f_im, sf_im));
        const a_im = fpr.add(fpr.mul(f_re, sf_im), fpr.mul(f_im, sf_re));
        const b_re = fpr.sub(fpr.mul(g_re, sg_re), fpr.mul(g_im, sg_im));
        const b_im = fpr.add(fpr.mul(g_re, sg_im), fpr.mul(g_im, sg_re));
        d[u] = fpr.add(a_re, b_re);
        d[u + hn] = fpr.add(a_im, b_im);
    }
}

/// a *= b where b is auto-adjoint (imaginary halves of b are zero and
/// only its first hn slots are read).
pub fn polyMulAutoadjFft(a: []f64, b: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        a[u] = fpr.mul(a[u], b[u]);
        a[u + hn] = fpr.mul(a[u + hn], b[u]);
    }
}

/// a /= b where b is auto-adjoint (only its first hn slots are read).
pub fn polyDivAutoadjFft(a: []f64, b: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    var u: usize = 0;
    while (u < hn) : (u += 1) {
        const ib = fpr.inv(b[u]);
        a[u] = fpr.mul(a[u], ib);
        a[u + hn] = fpr.mul(a[u + hn], ib);
    }
}

pub fn polySplitFft(f0: []f64, f1: []f64, f: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    const qn = hn >> 1;
    f0[0] = f[0];
    f1[0] = f[hn];
    var u: usize = 0;
    while (u < qn) : (u += 1) {
        const a_re = f[(u << 1) + 0];
        const a_im = f[(u << 1) + 0 + hn];
        const b_re = f[(u << 1) + 1];
        const b_im = f[(u << 1) + 1 + hn];
        var t_re = fpr.add(a_re, b_re);
        var t_im = fpr.add(a_im, b_im);
        f0[u] = fpr.half(t_re);
        f0[u + qn] = fpr.half(t_im);
        t_re = fpr.sub(a_re, b_re);
        t_im = fpr.sub(a_im, b_im);
        const s_re = fpr.gm_tab[((u + hn) << 1) + 0];
        const s_im = fpr.neg(fpr.gm_tab[((u + hn) << 1) + 1]);
        const m_re = fpr.sub(fpr.mul(t_re, s_re), fpr.mul(t_im, s_im));
        const m_im = fpr.add(fpr.mul(t_re, s_im), fpr.mul(t_im, s_re));
        f1[u] = fpr.half(m_re);
        f1[u + qn] = fpr.half(m_im);
    }
}

pub fn polyMergeFft(f: []f64, f0: []const f64, f1: []const f64, logn: u5) void {
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;
    const qn = hn >> 1;
    f[0] = f0[0];
    f[hn] = f1[0];
    var u: usize = 0;
    while (u < qn) : (u += 1) {
        const a_re = f0[u];
        const a_im = f0[u + qn];
        const s_re = fpr.gm_tab[((u + hn) << 1) + 0];
        const s_im = fpr.gm_tab[((u + hn) << 1) + 1];
        const b_re = fpr.sub(fpr.mul(f1[u], s_re), fpr.mul(f1[u + qn], s_im));
        const b_im = fpr.add(fpr.mul(f1[u], s_im), fpr.mul(f1[u + qn], s_re));
        var t_re = fpr.add(a_re, b_re);
        var t_im = fpr.add(a_im, b_im);
        f[(u << 1) + 0] = t_re;
        f[(u << 1) + 0 + hn] = t_im;
        t_re = fpr.sub(a_re, b_re);
        t_im = fpr.sub(a_im, b_im);
        f[(u << 1) + 1] = t_re;
        f[(u << 1) + 1 + hn] = t_im;
    }
}

/// FFT/iFFT over a `poly.Ring(logn)` instantiation's degree n. Kept for the
/// scaffold's API shape; the signer uses `fftRaw`/`ifftRaw` directly.
pub fn Fft(comptime Ring: type) type {
    return struct {
        pub const n = Ring.n;
        pub const hn = n / 2;

        pub const Complex = struct { re: f64, im: f64 };
        pub const FftPoly = [hn]Complex;

        /// Forward FFT: real coefficients -> FFT domain (spec §3.4 Alg.1).
        pub fn fft(a: *const [n]f64, out: *FftPoly) void {
            var work: [n]f64 = a.*;
            fftRaw(&work, Ring.logn);
            for (out, 0..) |*c, k| c.* = .{ .re = work[k], .im = work[k + hn] };
        }

        /// Inverse FFT: FFT domain -> real coefficients (spec §3.4 Alg.2).
        pub fn ifft(a: *const FftPoly, out: *[n]f64) void {
            var work: [n]f64 = undefined;
            for (a, 0..) |c, k| {
                work[k] = c.re;
                work[k + hn] = c.im;
            }
            ifftRaw(&work, Ring.logn);
            out.* = work;
        }
    };
}

test "Fft(Ring) instantiates for both parameter sets" {
    const poly = @import("poly.zig");
    try std.testing.expectEqual(@as(usize, 256), Fft(poly.Ring512).hn);
    try std.testing.expectEqual(@as(usize, 512), Fft(poly.Ring1024).hn);
}

test "fftRaw/ifftRaw round-trip is near-identity" {
    var prng = std.Random.DefaultPrng.init(0xf7);
    const random = prng.random();
    var a: [512]f64 = undefined;
    for (&a) |*x| x.* = @floatFromInt(random.intRangeAtMost(i32, -1000, 1000));
    const orig = a;
    fftRaw(&a, 9);
    ifftRaw(&a, 9);
    for (a, orig) |x, o| try std.testing.expect(@abs(x - o) < 1e-6);
}

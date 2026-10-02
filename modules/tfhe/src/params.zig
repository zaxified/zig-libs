// SPDX-License-Identifier: MIT

//! params — TFHE parameter sets and the **noise / probability-of-failure
//! ledger** that makes bootstrapping correctness auditable.
//!
//! TFHE fixes the torus modulus at `q = 2^32` (see `torus.zig`). A parameter
//! set then chooses:
//!   - `n`   — LWE dimension (the "small" key; input/output ciphertexts).
//!   - `k`   — GLWE dimension (mask polynomials per GLWE ciphertext).
//!   - `N`   — GLWE/accumulator ring degree (power of two). The big LWE key
//!             that sample extraction produces has dimension `k·N`.
//!   - `(bg_bits, ell)`     — the GGSW / bootstrap-key gadget base and levels.
//!   - `(bks_bits, ell_ks)` — the key-switch gadget base and levels.
//!   - `lwe_noise`  — the error of everything encrypted under the small key:
//!                    input ciphertexts and the key-switch key.
//!   - `glwe_noise` — the error of everything encrypted under the GLWE key:
//!                    GLWE/GGSW ciphertexts and the bootstrap key.
//!
//! ## The tfhe-rs sets
//!
//! `tfhers_default`, `tfhers_tfhe_lib` and `tfhers_2m165` are tfhe-rs 1.8.1's
//! `boolean::parameters::{DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS,
//! PARAMETERS_ERROR_PROB_2_POW_MINUS_165}`, read from the crate's public
//! constants by `tools/tfhers` (a black box; no tfhe-rs source was read) and
//! pinned against that tool's output by `interop_test.zig`. The security level
//! and the failure probability are Zama's sizing, not ours: this module
//! reproduces the dimensions, the gadgets, the binary key distribution and the
//! Gaussian error widths, and the interop test shows the two implementations
//! agree on what the parameters mean. tfhe-rs's boolean parameter page
//! (`docs/references/fine-grained-apis/boolean/parameters.md`, read
//! 2026-10-02) states "the standard security of 128 bits", an error
//! probability of at most `2^-64` for the default set and `2^-165` for the
//! `…_2_POW_MINUS_165` set; it states nothing separate for `TFHE_LIB_PARAMETERS`,
//! which exists for compatibility with the original library.
//!
//! ## Ledger for `toy` (`n=64, k=1, N=256, B_g=2^7, ℓ=4, B_ks=2^4, ℓ_ks=8,
//!    uniform error in [−2^10, 2^10]`)
//!
//! Messages are bits encoded at `Δ = q/4 = 2^30` (padding-bit convention:
//! valid messages stay in the lower half `[0, q/2)`), so decryption is
//! correct while the noise magnitude stays below `Δ/2 = q/8 = 2^29`.
//!
//! Why a *probability* ledger (and not a worst-case one): blind rotation adds
//! noise from `n` chained CMux/external-products. A worst-case `‖·‖_∞` bound
//! over that chain is `n·(k+1)·ℓ·N·(B_g/2)·err_bound` — which for any usable
//! dimension exceeds `q`. TFHE's correctness is an **average-case** argument:
//! the digit×error cross terms are zero-mean and independent, so the output
//! noise is a sum of `≈ n·(k+1)·ℓ·N` such terms and concentrates around its
//! stddev.
//!
//! With `σ² = err_bound²/3 = 2^20/3 ≈ 3.50e5`:
//!
//!   Blind-rotation output variance (CGGI):
//!     Var_BR ≈ n·(k+1)·ℓ·N·(B_g²/12)·σ²
//!            = 64·2·4·256·(2^14/12)·σ²  ≈ 1.79e8·σ²  ≈ 6.26e13
//!   plus the gadget-approximation term  n·(kN+1)/2·ε²,  ε = q/(2·B_g^ℓ) = 8,
//!            ≈ 64·128.5·64 ≈ 5.3e5  (negligible),
//!   plus the key-switch output noise
//!     Var_KS ≈ kN·ℓ_ks·(B_ks²/12)·σ² ≈ 256·8·(256/12)·σ² ≈ 4.4e4·σ²  (negligible).
//!
//!   ⇒ σ_out ≈ √Var_BR ≈ 7.9e6.
//!
//!   Failure per bit: P = erfc( (q/8) / (√2·σ_out) ) = erfc( 2^29 / (√2·7.9e6) )
//!                      = erfc( ≈ 48 )  ≈ 10^{-1000}.
//!
//! The `q/8` decision margin is `≈ 68·σ_out`. These are toy dimensions; NO
//! security level is claimed for `toy`.

const std = @import("std");
const gadget = @import("gadget.zig");
const ntt = @import("ntt.zig");

/// An error distribution on the torus `Z_{2^32}`.
pub const Noise = union(enum) {
    /// Uniform on the integers `[−bound, bound]` (bounded, reproducible;
    /// stddev `bound/√3`). The `toy` set's distribution.
    uniform: u32,
    /// Centred Gaussian whose standard deviation is given as a **fraction of
    /// `q`** — tfhe-rs's `StandardDev` convention, so its constants carry over
    /// verbatim. Sampled by `noise.zig` (constant-time Box–Muller) and rounded
    /// to the nearest integer.
    gaussian: f64,

    /// Standard deviation in torus units (multiples of `1/q`).
    pub fn stddev(self: Noise) f64 {
        return switch (self) {
            .uniform => |b| @as(f64, @floatFromInt(b)) / @sqrt(3.0),
            .gaussian => |s| s * 4294967296.0,
        };
    }

    /// Bytes of `std.Random` one error sample consumes — a constant per
    /// distribution, never an average.
    pub fn drawBytes(self: Noise) usize {
        return switch (self) {
            .uniform => 8,
            .gaussian => 16,
        };
    }
};

pub const Params = struct {
    /// LWE dimension (small key).
    n: usize,
    /// GLWE dimension: mask polynomials per GLWE ciphertext.
    k: usize = 1,
    /// GLWE ring degree (power of two).
    N: usize,
    /// GGSW / bootstrap-key gadget base `B_g = 2^bg_bits`.
    bg_bits: u6,
    /// GGSW / bootstrap-key gadget levels.
    ell: usize,
    /// Key-switch gadget base `B_ks = 2^bks_bits`.
    bks_bits: u6,
    /// Key-switch gadget levels.
    ell_ks: usize,
    /// Error of encryptions under the small LWE key (inputs, key-switch key).
    lwe_noise: Noise,
    /// Error of encryptions under the GLWE key (GLWE, GGSW, bootstrap key).
    glwe_noise: Noise,

    /// Structural validity (NOT a security check): positive dimensions, `N` a
    /// power of two, both gadget decompositions fit in the 32-bit torus, and a
    /// prepared external product stays exact (see `tfhe.zig`,
    /// `PreparedBootstrapKey`).
    pub fn validate(self: Params) !void {
        if (self.n == 0) return error.ZeroLweDimension;
        if (self.k == 0) return error.ZeroGlweDimension;
        if (self.N < 2 or (self.N & (self.N - 1)) != 0) return error.RingDegreeNotPowerOfTwo;
        if (self.N > ntt.max_degree) return error.RingDegreeTooLarge;
        // A digit is an i32 in [−B/2, B/2]: B = 2^32 would not fit.
        if (self.bg_bits == 0 or self.bg_bits > 31 or @as(u32, self.bg_bits) * self.ell > 32 or self.ell == 0) return error.BadGgswGadget;
        if (self.bks_bits == 0 or self.bks_bits > 31 or @as(u32, self.bks_bits) * self.ell_ks > 32 or self.ell_ks == 0) return error.BadKeySwitchGadget;
        // The error distribution of an LWE encryption is chosen by its key's
        // dimension (`n`: small key, `k·N`: big key); equal ones are ambiguous.
        if (self.n == self.k * self.N) return error.AmbiguousLweDimension;
        switch (self.lwe_noise) {
            .uniform => |b| if (b == 0 or b >= (1 << 30)) return error.BadNoise,
            .gaussian => |s| if (!(s > 0 and s < 0.25)) return error.BadNoise,
        }
        switch (self.glwe_noise) {
            .uniform => |b| if (b == 0 or b >= (1 << 30)) return error.BadNoise,
            .gaussian => |s| if (!(s > 0 and s < 0.25)) return error.BadNoise,
        }
        if (self.preparedBoundLog2() >= 61) return error.PreparedProductNotExact;
    }

    /// `log2(2N)` — the bit-width of a modulus-switched coordinate.
    pub fn logTwoN(self: Params) u6 {
        return @intCast(std.math.log2_int(usize, 2 * self.N));
    }

    /// Dimension of the big LWE key sample extraction produces.
    pub fn bigDim(self: Params) usize {
        return self.k * self.N;
    }

    /// GGSW rows: `(k+1)·ℓ`.
    pub fn ggswRows(self: Params) usize {
        return (self.k + 1) * self.ell;
    }

    /// `⌈log2⌉` of the largest absolute coefficient of a prepared external
    /// product before reduction: `(k+1)·ℓ` rows, each an `N`-term negacyclic
    /// sum of a digit (`|d| ≤ B_g/2`) times a torus coefficient (`< 2^32`).
    /// Must stay below `log2(p/2) ≈ 63`; `validate` keeps two bits of margin.
    pub fn preparedBoundLog2(self: Params) u32 {
        const rows = self.ggswRows();
        const terms: u64 = @as(u64, rows) * self.N;
        return std.math.log2_int_ceil(u64, terms) + (self.bg_bits - 1) + 32;
    }
};

/// Correctness-only toy parameters (see the ledger above). NOT secure.
pub const toy = Params{
    .n = 64,
    .k = 1,
    .N = 256,
    .bg_bits = 7, // B_g = 128
    .ell = 4, // covers top 28 bits; gadget error ≤ 8
    .bks_bits = 4, // B_ks = 16
    .ell_ks = 8, // covers all 32 bits (exact key-switch decomposition)
    .lwe_noise = .{ .uniform = 1 << 10 },
    .glwe_noise = .{ .uniform = 1 << 10 },
};

/// tfhe-rs 1.8.1 `boolean::parameters::DEFAULT_PARAMETERS`.
pub const tfhers_default = Params{
    .n = 805,
    .k = 3,
    .N = 512,
    .bg_bits = 10,
    .ell = 2,
    .bks_bits = 3,
    .ell_ks = 5,
    .lwe_noise = .{ .gaussian = 5.8615896642671336e-6 },
    .glwe_noise = .{ .gaussian = 9.315272083503367e-10 },
};

/// tfhe-rs 1.8.1 `boolean::parameters::TFHE_LIB_PARAMETERS` — the original
/// TFHE library's gate-bootstrapping set (`k = 1`, `N = 1024`).
pub const tfhers_tfhe_lib = Params{
    .n = 630,
    .k = 1,
    .N = 1024,
    .bg_bits = 7,
    .ell = 3,
    .bks_bits = 2,
    .ell_ks = 8,
    .lwe_noise = .{ .gaussian = 3.0517578125e-5 },
    .glwe_noise = .{ .gaussian = 2.980232238769531e-8 },
};

/// tfhe-rs 1.8.1 `boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165`.
pub const tfhers_2m165 = Params{
    .n = 837,
    .k = 2,
    .N = 1024,
    .bg_bits = 10,
    .ell = 2,
    .bks_bits = 3,
    .ell_ks = 5,
    .lwe_noise = .{ .gaussian = 3.374714376692653e-6 },
    .glwe_noise = .{ .gaussian = 9.313225746198247e-10 },
};

const testing = std.testing;

test "toy validates and has the documented shape" {
    try toy.validate();
    try testing.expectEqual(@as(usize, 1), toy.k);
    try testing.expectEqual(@as(u6, 9), toy.logTwoN()); // 2N = 512
    // The GGSW gadget error the ledger cites.
    try testing.expectEqual(@as(u64, 8), gadget.maxError(toy.bg_bits, toy.ell));
    // The key-switch gadget is exact (covers all 32 bits).
    try testing.expectEqual(@as(u64, 0), gadget.maxError(toy.bks_bits, toy.ell_ks));
}

test "the tfhe-rs sets validate and keep the prepared product exact" {
    inline for (.{ tfhers_default, tfhers_tfhe_lib, tfhers_2m165 }) |s| try s.validate();
    // DEFAULT: 8 rows · 512 coefficients · 2^9 · 2^32 = 2^53.
    try testing.expectEqual(@as(u32, 53), tfhers_default.preparedBoundLog2());
    try testing.expectEqual(@as(usize, 3 * 512), tfhers_default.bigDim());
    try testing.expectEqual(@as(usize, 8), tfhers_default.ggswRows());
    // Torus-unit widths: σ_lwe·2^32 ≈ 25 175, σ_glwe·2^32 ≈ 4.0.
    try testing.expectApproxEqRel(@as(f64, 25175.5), tfhers_default.lwe_noise.stddev(), 1e-4);
    try testing.expectApproxEqRel(@as(f64, 4.0008), tfhers_default.glwe_noise.stddev(), 1e-4);
}

test "validate rejects malformed sets" {
    const ok = Params{ .n = 7, .N = 8, .bg_bits = 4, .ell = 2, .bks_bits = 4, .ell_ks = 2, .lwe_noise = .{ .uniform = 1 }, .glwe_noise = .{ .uniform = 1 } };
    try ok.validate();
    var p = ok;
    p.N = 6;
    try testing.expectError(error.RingDegreeNotPowerOfTwo, p.validate());
    p = ok;
    p.bg_bits = 8;
    p.ell = 5;
    try testing.expectError(error.BadGgswGadget, p.validate());
    p = ok;
    p.lwe_noise = .{ .uniform = 0 };
    try testing.expectError(error.BadNoise, p.validate());
    p = ok;
    p.glwe_noise = .{ .gaussian = 0 };
    try testing.expectError(error.BadNoise, p.validate());
    p = ok;
    p.n = 0;
    try testing.expectError(error.ZeroLweDimension, p.validate());
    p = ok;
    p.k = 0;
    try testing.expectError(error.ZeroGlweDimension, p.validate());
    p = ok;
    p.bks_bits = 8;
    p.ell_ks = 5;
    try testing.expectError(error.BadKeySwitchGadget, p.validate());
    p = ok;
    p.ell = 0;
    try testing.expectError(error.BadGgswGadget, p.validate());
    p = ok;
    p.bks_bits = 32;
    p.ell_ks = 1;
    try testing.expectError(error.BadKeySwitchGadget, p.validate());
    p = ok;
    p.bg_bits = 32;
    p.ell = 1;
    try testing.expectError(error.BadGgswGadget, p.validate());
    p = ok;
    p.N = 1 << 14;
    try testing.expectError(error.RingDegreeTooLarge, p.validate());
    p = ok;
    p.n = 8; // = k·N
    try testing.expectError(error.AmbiguousLweDimension, p.validate());
    // 2^13 coefficients · 4 rows · 2^15 digits: the prepared product would
    // overflow p/2.
    p = ok;
    p.N = 1 << 13;
    p.bg_bits = 16;
    p.ell = 2;
    try testing.expectError(error.PreparedProductNotExact, p.validate());
}

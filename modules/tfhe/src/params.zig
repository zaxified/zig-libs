// SPDX-License-Identifier: MIT

//! params — TFHE parameter sets and the **noise / probability-of-failure
//! ledger** that makes bootstrapping correctness auditable.
//!
//! TFHE fixes the torus modulus at `q = 2^32` (see `torus.zig`). A parameter
//! set then chooses:
//!   - `n`   — LWE dimension (the "small" key; input/output ciphertexts).
//!   - `N`   — GLWE/accumulator ring degree (power of two). `k = 1` (RLWE),
//!             the standard TFHE choice, is fixed by this module.
//!   - `(bg_bits, ell)`     — the GGSW / bootstrap-key gadget base and levels.
//!   - `(bks_bits, ell_ks)` — the key-switch gadget base and levels.
//!   - `err_bound` — errors are sampled uniformly in `[−err_bound, err_bound]`
//!                   (bounded, reproducible; stddev `σ = err_bound/√3`).
//!
//! Messages are bits encoded at `Δ = q/4 = 2^30` (padding-bit convention: valid
//! messages stay in the lower half `[0, q/2)`), so decryption is correct while
//! the noise magnitude stays below `Δ/2 = q/8 = 2^29`.
//!
//! ## Why a *probability* ledger (and not a worst-case one)
//!
//! Blind rotation adds noise from `n` chained CMux/external-products. A
//! worst-case `‖·‖_∞` bound over that chain is `n·(k+1)·ℓ·N·(B_g/2)·err_bound`
//! — which for any usable dimension exceeds `q` and is uselessly loose. This is
//! intrinsic to TFHE: its correctness is an **average-case** argument. The
//! digit×error cross terms are zero-mean and independent, so the output noise
//! is a sum of `≈ n·(k+1)·ℓ·N` such terms and concentrates around its stddev.
//! Hence, unlike `bfv`'s leveled multiply (a worst-case ledger), the honest
//! artifact here is a **failure-probability** ledger. (This is exactly the
//! Fable trigger: no deterministic worst-case oracle bounds the hard part.)
//!
//! ## Ledger for `toy` (`n=64, N=256, k=1, B_g=2^7, ℓ=4, B_ks=2^4, ℓ_ks=8,
//!    err_bound=2^10`)
//!
//! With `σ² = err_bound²/3 = 2^20/3 ≈ 3.50e5`:
//!
//!   Blind-rotation output variance (CGGI, k=1):
//!     Var_BR ≈ n·(k+1)·ℓ·N·(B_g²/12)·σ²
//!            = 64·2·4·256·(2^14/12)·σ²  ≈ 1.79e8·σ²  ≈ 6.26e13
//!   plus the gadget-approximation term  n·(kN+1)/2·ε²,  ε = q/(2·B_g^ℓ) = 8,
//!            ≈ 64·128.5·64 ≈ 5.3e5  (negligible),
//!   plus modulus-switch input noise and the key-switch output noise
//!     Var_KS ≈ kN·ℓ_ks·(B_ks²/12)·σ² ≈ 256·8·(256/12)·σ² ≈ 4.4e4·σ²  (negligible).
//!
//!   ⇒ σ_out ≈ √Var_BR ≈ 7.9e6.
//!
//!   Failure per bit: P = erfc( (q/8) / (√2·σ_out) ) = erfc( 2^29 / (√2·7.9e6) )
//!                      = erfc( ≈ 48 )  ≈ 10^{-1000}.
//!
//! The `q/8` decision margin is `≈ 68·σ_out` — an enormous safety factor, so a
//! chain of thousands of bootstraps is still overwhelmingly correct. (These are
//! toy dimensions; NO security level is claimed. A security-grade set sizes `σ`
//! upward for a hard LWE problem and re-balances `(ℓ, B_g)` to keep the same
//! `erfc` margin — the formula above is the sizing tool.)

const std = @import("std");
const gadget = @import("gadget.zig");

pub const Params = struct {
    /// LWE dimension (small key).
    n: usize,
    /// GLWE ring degree (power of two). `k = 1` is fixed.
    N: usize,
    /// GGSW / bootstrap-key gadget base `B_g = 2^bg_bits`.
    bg_bits: u6,
    /// GGSW / bootstrap-key gadget levels.
    ell: usize,
    /// Key-switch gadget base `B_ks = 2^bks_bits`.
    bks_bits: u6,
    /// Key-switch gadget levels.
    ell_ks: usize,
    /// Uniform error amplitude: errors sampled in `[−err_bound, err_bound]`.
    err_bound: u32,

    pub const k: usize = 1;

    /// Structural validity (NOT a security check): `N` a power of two, positive
    /// dimensions, and both gadget decompositions fit in the 32-bit torus.
    pub fn validate(self: Params) !void {
        if (self.n == 0) return error.ZeroLweDimension;
        if (self.N == 0 or (self.N & (self.N - 1)) != 0) return error.RingDegreeNotPowerOfTwo;
        if (self.bg_bits == 0 or @as(u32, self.bg_bits) * self.ell > 32) return error.BadGgswGadget;
        if (self.bks_bits == 0 or @as(u32, self.bks_bits) * self.ell_ks > 32) return error.BadKeySwitchGadget;
        if (self.err_bound == 0) return error.ZeroError;
    }

    /// `log2(2N)` — the number of rotation slots' bit-width for modulus switch.
    pub fn logTwoN(self: Params) u6 {
        return @intCast(std.math.log2_int(usize, 2 * self.N));
    }
};

/// Correctness-only toy parameters (see the ledger above). NOT secure.
pub const toy = Params{
    .n = 64,
    .N = 256,
    .bg_bits = 7, // B_g = 128
    .ell = 4, // covers top 28 bits; gadget error ≤ 8
    .bks_bits = 4, // B_ks = 16
    .ell_ks = 8, // covers all 32 bits (exact key-switch decomposition)
    .err_bound = 1 << 10,
};

const testing = std.testing;

test "toy validates and has the documented shape" {
    try toy.validate();
    try testing.expectEqual(@as(usize, 1), Params.k);
    try testing.expectEqual(@as(u6, 9), toy.logTwoN()); // 2N = 512
    // The GGSW gadget error the ledger cites.
    try testing.expectEqual(@as(u64, 8), gadget.maxError(toy.bg_bits, toy.ell));
    // The key-switch gadget is exact (covers all 32 bits).
    try testing.expectEqual(@as(u64, 0), gadget.maxError(toy.bks_bits, toy.ell_ks));
}

test "validate rejects malformed sets" {
    try testing.expectError(error.RingDegreeNotPowerOfTwo, (Params{ .n = 8, .N = 6, .bg_bits = 4, .ell = 2, .bks_bits = 4, .ell_ks = 2, .err_bound = 1 }).validate());
    try testing.expectError(error.BadGgswGadget, (Params{ .n = 8, .N = 8, .bg_bits = 8, .ell = 5, .bks_bits = 4, .ell_ks = 2, .err_bound = 1 }).validate());
    try testing.expectError(error.ZeroError, (Params{ .n = 8, .N = 8, .bg_bits = 4, .ell = 2, .bks_bits = 4, .ell_ks = 2, .err_bound = 0 }).validate());
}

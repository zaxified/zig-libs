// SPDX-License-Identifier: MIT
//! ntru — NTRUGen + NTRUSolve, Falcon/FN-DSA key generation's
//! number-theoretic core (spec §3.8.1 Algorithm 5 `NTRUGen`, §3.8.2
//! Algorithm 6 `NTRUSolve`): sample a small secret pair (f, g), then
//! solve the NTRU equation f*G - g*F = q over Z[x]/(x^n+1) for the
//! co-basis (F, G).
//!
//! Needs a big-integer / exact-rational polynomial layer this module
//! does not have. NTRUSolve works via the "tower of number fields"
//! resultant-reduction trick: recurse the problem from degree n down to
//! degree n/2, n/4, ... 1 via field norms, solve the degree-1 base case
//! exactly (ordinary extended-GCD-style Bezout over Z), then lift the
//! solution back up the tower one level at a time with Babai rounding to
//! keep the intermediate coefficients bounded. None of that exists here
//! yet, and it is not a small addition on top of what this module has —
//! it is comparable in scope to `poly.zig`'s entire NTT layer, just over
//! big integers/rationals instead of a fixed small modulus.
//!
//! `f`/`g` sampling itself (before NTRUSolve runs) draws each coefficient
//! from `gaussian.samplerZ` with sigma_fg (spec Table 3.1) and
//! rejects-and-resamples the pair until it passes the Gram-Schmidt norm
//! bound and `f` is invertible both mod q (`poly.Ring.pointwiseDiv`
//! already covers that check, reused) and mod 2 (a separate, cheaper
//! invertibility test this file would also need). That acceptance loop
//! is comparatively easy; it is bundled into the same stub below because
//! it cannot be usefully separated from NTRUSolve (there is nothing to
//! return until NTRUSolve also succeeds for the accepted f/g).

const std = @import("std");

/// NTRU basis generation, specialized to one `poly.Ring(logn)` degree.
pub fn Ntru(comptime Ring: type) type {
    return struct {
        /// The full NTRU secret basis: (f, g) plus the co-basis (F, G)
        /// solving f*G - g*F = q. Only (f, g, F) are ever written to the
        /// wire (`root.zig`'s `SecretKey`, `keygen.zig`'s
        /// `toSecretKeyBytes`); G is kept in memory only, to build the
        /// ffSampling tree (`ffsampling.buildTree`) at signing time.
        pub const Basis = struct {
            f: [Ring.n]i8,
            g: [Ring.n]i8,
            big_f: [Ring.n]i8,
            big_g: [Ring.n]i8,
        };

        /// Generate a fresh NTRU basis. `rng` drives both the (f, g)
        /// Gaussian sampling (via `gaussian.samplerZ`) and whatever
        /// randomness NTRUSolve's reduction needs; the acceptance loop
        /// (Gram-Schmidt norm bound, `f` invertible mod q AND mod 2)
        /// retries internally until a valid basis is found — the spec's
        /// own analysis says this succeeds with overwhelming probability
        /// on the first few tries, so no iteration cap is exposed here.
        pub fn generate(rng: std.Random) Basis {
            _ = rng;
            @panic("TODO(fable/core): NTRUGen/NTRUSolve — Falcon spec §3.8.1 " ++
                "Algorithm 5 (NTRUGen: sample small (f,g) via gaussian.samplerZ " ++
                "with sigma_fg per Table 3.1, reject-resample until the " ++
                "Gram-Schmidt norm bound holds and f is invertible mod q " ++
                "[poly.Ring.pointwiseDiv already covers that check] AND mod 2) " ++
                "composed with §3.8.2 Algorithm 6 (NTRUSolve: solve f*G - g*F = q " ++
                "for the co-basis (F,G) via the tower-of-number-fields resultant " ++
                "reduction + Babai-rounded lifting) — needs a big-integer/exact-" ++
                "rational polynomial layer not present anywhere in this module. " ++
                "This is the single hardest piece of Falcon keygen. FIPS 206 " ++
                "Appendix A carries the same algorithm under new numbering, if " ++
                "that ends up being the target once it finalizes.");
        }
    };
}

test "Ntru(Ring) instantiates for both parameter sets without evaluating the stub" {
    const poly = @import("poly.zig");
    // Same instantiation-does-not-panic guarantee as fft.zig's test:
    // pins down that the panic only fires when `generate` is CALLED.
    _ = Ntru(poly.Ring512).Basis;
    _ = Ntru(poly.Ring1024).Basis;
}

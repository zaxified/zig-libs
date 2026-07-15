// SPDX-License-Identifier: MIT
//! gaussian — SamplerZ, Falcon/FN-DSA's discrete Gaussian sampler over Z
//! (spec §3.9.2, Algorithm 12 `BaseSampler` + Algorithm 13
//! `ApproxExp`/`BerExp`): draws an integer distributed as a discrete
//! Gaussian of a given mean `mu` and standard deviation `sigma`.
//!
//! ================================================================
//! *** THE side-channel-critical primitive in this whole module. ***
//! ================================================================
//!
//! Every leaf of `ffsampling.sampleSignature`'s recursion calls this;
//! `ntru.zig`'s keygen sampler needs the same shape of draw. A sampler
//! whose timing, branches, or memory-access pattern depends on the
//! SAMPLED VALUE (as opposed to only `mu`/`sigma`, which are not secret)
//! leaks the secret NTRU basis through completely valid, correctly
//! verifying signatures — the private key is recoverable from a
//! transcript of otherwise-unremarkable signatures alone. This is the
//! well-documented failure mode of Falcon-family and BLISS-family
//! signers with a non-constant-time Gaussian sampler (see e.g. Barthe et
//! al., "GALACTICS", and the original BLISS timing-attack literature the
//! Falcon spec's own security-considerations section cites).
//!
//! This is NOT a "get it correct first, harden later" function: ordinary
//! functional correctness (matching the spec's distribution, passing
//! statistical tests, even matching the standalone SamplerZ KAT vectors
//! below) is necessary but NOT sufficient. It needs a constant-time
//! implementation AND a dedicated side-channel audit before this module
//! ever signs with a real (non-test) key — treat it as its own
//! owner-gated review, separate from and in addition to the rest of the
//! signing path's review.
//!
//! The Falcon spec's appendix ships standalone SamplerZ test vectors
//! (input mu/sigma/uniform-randomness -> output integer) precisely so
//! the sampler can be KAT'd in ISOLATION from the rest of signing — wire
//! those, not just end-to-end sign KATs, when this is implemented; an
//! end-to-end sign KAT alone cannot distinguish "correct sampler" from
//! "wrong sampler that happens to still pass the norm bound often
//! enough," and says nothing about constant-time-ness either way.

const std = @import("std");

/// Draw one integer from a discrete Gaussian of mean `mu`, standard
/// deviation `sigma` (`sigma` in [sigma_min, sigma_max] — Falcon spec
/// Table 3.1, degree-dependent: Falcon-512 and Falcon-1024 use different
/// sigma ranges), using `rng` for the underlying uniform randomness
/// (BaseSampler's RCDT table lookup, then BerExp's rejection coin
/// flips). See this file's module doc comment before touching this
/// function: it is the side-channel-critical core of the whole module.
pub fn samplerZ(mu: f64, sigma: f64, rng: std.Random) i32 {
    _ = mu;
    _ = sigma;
    _ = rng;
    @panic("TODO(fable/core): SamplerZ — Falcon spec §3.9.2, Algorithm 12 " ++
        "(BaseSampler: sample from a fixed half-Gaussian via the spec's RCDT " ++
        "table, defined at sigma_max) composed with Algorithm 13 (ApproxExp + " ++
        "BerExp rejection, reshaping the BaseSampler draw to the requested " ++
        "mu/sigma) — MUST be constant-time (see this file's module doc " ++
        "comment: this is THE side-channel-critical primitive in the whole " ++
        "module; a data-dependent branch or table lookup here leaks the " ++
        "secret key through valid signatures). Port the RCDT and ApproxExp " ++
        "coefficient tables from spec Tables 3.2/3.3, and wire the spec " ++
        "appendix's standalone SamplerZ test vectors as a dedicated KAT " ++
        "(separate from end-to-end sign KATs) before trusting this.");
}

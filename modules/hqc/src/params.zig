// SPDX-License-Identifier: MIT
//! params — HQC (Hamming Quasi-Cyclic) parameter sets.
//!
//! Source of truth: the official HQC specification, "Hamming Quasi-Cyclic
//! (HQC)", 22/08/2025 (pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf),
//! which is the spec accompanying reference-implementation tag `v5.0.0` at
//! gitlab.com/pqc-hqc/hqc (confirmed: that tag's commit date is 2025-08-22,
//! matching the spec's changelog date, and its `kats/ref/hqc-*/PQCkemKAT_*`
//! filenames — `PQCkemKAT_2321.rsp` etc — encode the exact `|dkKEM|` byte
//! sizes below). This is HQC as NIST selected it for standardization
//! (March 2025); see SPEC.md for the full provenance trail and why this
//! version was chosen over an older round-4 snapshot.
//!
//! Every field below is transcribed from Table 5 ("Parameter sets for
//! HQC") and Table 6 ("... sizes") of that spec, cross-checked against
//! the reference implementation's `src/ref/hqc-*/parameters.h`
//! (`PARAM_*` macros) downloaded from the same tag. `n1`/`n2`/`delta`
//! additionally match §3.4's concatenated-code table (Table 3/4).

/// One HQC parameter set (Table 5 + Table 6 of the spec).
pub const Params = struct {
    /// Spec name, e.g. "hqc-128" (NIST category / HQC-1,3,5 naming both
    /// appear in the spec; "hqc-128/192/256" ties to the security level).
    name: []const u8,
    /// n — ambient ring length: the smallest primitive prime > n1*n2
    /// (§2.1: primitive means (X^n-1)/(X-1) is irreducible over F2).
    n: u32,
    /// n1 — Reed-Solomon code length (the shortened RS-S1/S2/S3 code).
    n1: u32,
    /// n2 — (duplicated) Reed-Muller code length.
    n2: u32,
    /// delta — Reed-Solomon error-correcting capacity (Table 3).
    delta: u32,
    /// Security level in bits (Table 5's "Security" column) — NOT a byte
    /// count; use `securityBytes()` for the message/sigma length.
    security_bits: u32,
    /// omega — Hamming weight of the secret vectors (x, y).
    omega: u32,
    /// omega_r == omega_e — Hamming weight of (r1, r2) and of e
    /// respectively; HQC fixes these equal for every parameter set
    /// (Table 5's single "omega_r = omega_e" column).
    omega_r: u32,
    /// Duplicated-Reed-Muller multiplicity (Table 4): 3 for hqc-128,
    /// 5 for hqc-192/hqc-256. Part 2 (the RM/RS decoder) consumes this;
    /// Part 1 records it for completeness since it's a Table-4 constant.
    rm_multiplicity: u32,

    /// n1 * n2 — length of the concatenated code C.
    pub fn n1n2(comptime p: Params) u32 {
        return p.n1 * p.n2;
    }

    /// Security level in bytes — the message (m) and sigma length.
    pub fn securityBytes(comptime p: Params) u32 {
        return p.security_bits / 8;
    }

    /// ceil(n / 64) — ring element size in u64 words.
    pub fn words(comptime p: Params) usize {
        return (p.n + 63) / 64;
    }

    /// ceil(n / 8) — ring element size in bytes (VEC_N_SIZE_BYTES).
    pub fn nBytes(comptime p: Params) usize {
        return (p.n + 7) / 8;
    }

    /// ceil(n1*n2 / 8) — concatenated-codeword size in bytes
    /// (VEC_N1N2_SIZE_BYTES).
    pub fn n1n2Bytes(comptime p: Params) usize {
        return (p.n1n2() + 7) / 8;
    }

    /// Barrett-reduction multiplier mu = floor(2^32 / n), used by the
    /// unbiased fixed-weight rejection sampler (prng.zig).
    pub fn nMu(comptime p: Params) u64 {
        return (@as(u64, 1) << 32) / p.n;
    }

    /// Rejection threshold t = floor(2^24 / n) * n for uniform sampling
    /// of a value in [0, n) from a 24-bit draw (prng.zig).
    pub fn rejectionThreshold(comptime p: Params) u32 {
        return @intCast(((@as(u64, 1) << 24) / p.n) * p.n);
    }

    /// |ekKEM| = |seed| + ceil(n/8)  (spec §4.2).
    pub fn ekBytes(comptime p: Params) usize {
        return seed_bytes + p.nBytes();
    }

    /// |dkKEM| = |ekKEM| + |seed|(dkPKE) + securityBytes(sigma) +
    /// |seed|(seedKEM), the DEFAULT (uncompressed) keypair format
    /// (spec §4.2 / §3.5 "Keypair format").
    pub fn dkBytes(comptime p: Params) usize {
        return p.ekBytes() + seed_bytes + p.securityBytes() + seed_bytes;
    }

    /// |cKEM| = ceil(n/8) + ceil(n1n2/8) + |salt|  (spec §4.2).
    pub fn ctBytes(comptime p: Params) usize {
        return p.nBytes() + p.n1n2Bytes() + salt_bytes;
    }
};

/// |seed| in bytes — every seed (seedKEM, seedPKE, seedPKE.dk, seedPKE.ek,
/// H(ekKEM)) is this size (spec §4.2).
pub const seed_bytes: u32 = 32;
/// |salt| in bytes (spec §4.2).
pub const salt_bytes: u32 = 16;
/// |K| — shared-secret size in bytes (spec §4.2); NOT the same as a
/// parameter set's securityBytes() (message/sigma size), though for HQC
/// both happen to differ per level: |K| is fixed at 32 for all three
/// levels while securityBytes() is 16/24/32.
pub const shared_secret_bytes: u32 = 32;

/// XOF/hash domain separators (spec Table 1, §3.1) — one trailing byte
/// absorbed after the payload, distinguishing the five SHAKE256/SHA3
/// instantiations that otherwise share the same underlying primitive.
/// Values confirmed against the reference `symmetric.h`
/// (`HQC_*_DOMAIN` macros) byte-for-byte.
pub const domain = struct {
    /// HQC's internal PRNG (prng.zig's `Prng`, also literally what the
    /// NIST KAT harness's `randombytes()`/DRBG is instantiated as in
    /// this reference — see prng.zig's module doc).
    pub const prng: u8 = 0;
    /// The XOF (prng.zig's `Xof`) used for h/x/y/r1/r2/e/theta sampling.
    pub const xof: u8 = 1;
    /// G — SHA3-512, HQC-KEM's (K, theta) derivation.
    pub const g: u8 = 0;
    /// H — SHA3-256, hashes ekKEM.
    pub const h: u8 = 1;
    /// I — SHA3-512, derives (seedPKE.dk, seedPKE.ek) from seedPKE.
    pub const i: u8 = 2;
    /// J — SHA3-256, the FO-transform implicit-rejection key.
    pub const j: u8 = 3;
};

/// HQC-128 (NIST category 1). Table 5 row "HQC-1".
pub const hqc128 = Params{
    .name = "hqc-128",
    .n = 17669,
    .n1 = 46,
    .n2 = 384,
    .delta = 15,
    .security_bits = 128,
    .omega = 66,
    .omega_r = 75,
    .rm_multiplicity = 3,
};

/// HQC-192 (NIST category 3). Table 5 row "HQC-3".
pub const hqc192 = Params{
    .name = "hqc-192",
    .n = 35851,
    .n1 = 56,
    .n2 = 640,
    .delta = 16,
    .security_bits = 192,
    .omega = 100,
    .omega_r = 114,
    .rm_multiplicity = 5,
};

/// HQC-256 (NIST category 5). Table 5 row "HQC-5".
pub const hqc256 = Params{
    .name = "hqc-256",
    .n = 57637,
    .n1 = 90,
    .n2 = 640,
    .delta = 29,
    .security_bits = 256,
    .omega = 131,
    .omega_r = 149,
    .rm_multiplicity = 5,
};

test "n1n2 matches spec Table 5's n" {
    // The spec defines n as the smallest primitive prime > n1*n2; we don't
    // re-derive primality here (that's a design-time constant, not
    // something Part 1 needs to compute), but n1*n2 must be < n and close
    // to it (spec: ell = n - n1n2 is the truncated tail).
    try @import("std").testing.expect(hqc128.n1n2() == 17664 and hqc128.n1n2() < hqc128.n);
    try @import("std").testing.expect(hqc192.n1n2() == 35840 and hqc192.n1n2() < hqc192.n);
    try @import("std").testing.expect(hqc256.n1n2() == 57600 and hqc256.n1n2() < hqc256.n);
}

test "byte sizes match spec Table 6" {
    const t = @import("std").testing;
    try t.expectEqual(@as(usize, 2241), hqc128.ekBytes());
    try t.expectEqual(@as(usize, 2321), hqc128.dkBytes());
    try t.expectEqual(@as(usize, 4433), hqc128.ctBytes());
    try t.expectEqual(@as(usize, 4514), hqc192.ekBytes());
    try t.expectEqual(@as(usize, 4602), hqc192.dkBytes());
    try t.expectEqual(@as(usize, 8978), hqc192.ctBytes());
    try t.expectEqual(@as(usize, 7237), hqc256.ekBytes());
    try t.expectEqual(@as(usize, 7333), hqc256.dkBytes());
    try t.expectEqual(@as(usize, 14421), hqc256.ctBytes());
}

test "rejection threshold and barrett mu are well-formed" {
    const t = @import("std").testing;
    // hqc-128's constants are given verbatim in the reference's
    // parameters.h (PARAM_N_MU=243079, UTILS_REJECTION_THRESHOLD=16767881)
    // — cross-check our formula reproduces them exactly.
    try t.expectEqual(@as(u64, 243079), hqc128.nMu());
    try t.expectEqual(@as(u32, 16767881), hqc128.rejectionThreshold());
    try t.expect(hqc128.rejectionThreshold() <= (1 << 24));
    try t.expect(hqc192.rejectionThreshold() <= (1 << 24));
    try t.expect(hqc256.rejectionThreshold() <= (1 << 24));
}

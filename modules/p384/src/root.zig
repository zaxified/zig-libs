// SPDX-License-Identifier: MIT

//! p384 — NIST P-384 (secp384r1): field, group, ECDH and ECDSA-P384, faster
//! than std's `std.crypto.ecc.P384` and constant time on every secret path.
//!
//! std ships P-384, but its generic windowed ladder over complete formulas
//! made jwt `ES384` sign 4.2× and verify 2.8× slower than golang-jwt and a
//! TLS client's P-384 key share ~1 ms (2026-10-11/13). This module is the
//! P-384 sibling of `p521`: the same group algorithms over a 384-bit field.
//!
//! * Field: GF(p), p = 2^384 − 2^128 − 2^96 + 2^32 − 1, six 64-bit limbs in
//!   the Montgomery domain (R = 2^384; the same representation as std's
//!   `P384.Fe`, so limbs convert one to one) (`field.zig`).
//! * Scalars: Montgomery mod n, six 64-bit limbs (`scalar.zig`).
//! * Group: complete Renes–Costello–Batina formulas for the public point
//!   API; scalar multiplication in Jacobian coordinates — secret scalars
//!   through masked signed windows (and a fixed-base comb for G), public
//!   ones through width-5 NAF (`group.zig`).
//! * ECDSA: RFC 6979 deterministic nonces (optional §3.6 additional data),
//!   raw and strict-DER signatures, any hash up to 64 bytes (`sign.zig`).
//!
//! Verified against NIST CAVP (186-4 ECDSA SigGen/SigVer/KeyPair/PKV, ECC
//! CDH), Wycheproof (ECDH, ECDSA DER and P1363), RFC 6979 A.2.6 and OpenSSL
//! (keys, RFC 6979 signatures byte for byte, ECDH). See `SPEC.md`.

const std = @import("std");

pub const field = @import("field.zig");
pub const scalar = @import("scalar.zig");
const group = @import("group.zig");
const sign = @import("sign.zig");

/// A base-field element.
pub const Fe = field.Fe;
/// A P-384 point (std `P384`'s shape).
pub const P384 = group.P384;
/// A point in affine coordinates.
pub const AffineCoordinates = group.AffineCoordinates;
/// A scalar mod the group order n.
pub const Scalar = scalar.Scalar;

/// ECDH: x-coordinate of `secret · peer` (48 bytes); compressed or
/// uncompressed peer points. `ecdhInto` is the dead-stack-clean form.
pub const ecdh = group.ecdh;
pub const ecdhInto = group.ecdhInto;
pub const EcdhError = group.EcdhError;

/// ECDSA over P-384 with SHA-384 — the drop-in for std's `EcdsaP384Sha384`.
pub const EcdsaP384Sha384 = sign.EcdsaP384Sha384;
/// ECDSA over P-384 with another hash (any digest ≤ 64 bytes; longer than
/// 48 is truncated by bits2int), e.g. X.509's `ecdsa-with-SHA256`.
pub const Ecdsa = sign.Ecdsa;

pub const meta = .{
    // The module catalog's one-line entry. README.md's table is rendered
    // from it by `zig build gen-catalog`.
    .doc = "NIST P-384 (secp384r1): Montgomery field, constant-time ECDH and ECDSA-P384 (RFC 6979) with std `P384`/`Ecdsa`-shaped API, faster than std; CAVP + Wycheproof + OpenSSL anchored.",
    .platform_note = "amd64 asm (ADX/BMI2) + portable fallback",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation, no I/O
    .concurrency = .reentrant, // no globals; values are plain types
    .model_after = "std.crypto.ecc.P384 + std.crypto.sign.ecdsa (API shape); FIPS 186-5, SP 800-186, RFC 6979; OpenSSL as the differential oracle",
    .deps = .{"entropy"},
};

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule).
test {
    _ = field;
    _ = scalar;
    _ = group;
    _ = sign;
    _ = @import("kat_test.zig");
    _ = @import("audit_test.zig");
    _ = @import("oracle_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("sweep_test.zig");
    _ = @import("bench.zig");
}

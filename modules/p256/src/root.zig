// SPDX-License-Identifier: MIT

//! p256 — an asm-accelerated pure-Zig NIST P-256, the fast alternative to
//! `std.crypto.ecc.P256`.
//!
//! std's P-256 is portable pure-Zig (a fiat-crypto Montgomery field, no asm, no
//! endomorphism), which makes it several× slower than OpenSSL's nistz256
//! (measured ~16× ECDSA sign / ~9× verify vs OpenSSL on the audited host). It is
//! on the P2 HTTPS-API hot path (per-request JWT ES256 verify, TLS), 2FA/WebAuthn
//! (ctap2pin), spake2plus, and the P-256 suites of hpke/voprf/mls/jwe — and we
//! cannot patch std. p256 is our OWN P-256 built for speed while keeping the
//! zero-C/no-libc invariant: the P-256 special-prime (Solinas) field reduction
//! (`2^256 ≡ 2^224 − 2^192 − 2^96 + 1`), windowed + fixed-base-comb constant-time
//! scalar multiplies (P-256 has NO GLV endomorphism), and an amd64 `MULX/ADX`
//! field multiply, with a portable fallback everywhere. Target: ~2–3× OpenSSL
//! nistz256 (the k256 secp256k1 arc hit ~2.5× libsecp256k1 with the same recipe).
//! See `SPEC.md` for the dedup justification.
//!
//! ## Status: cores IMPLEMENTED (both gates on; portable oracle remains)
//!
//! The PORTABLE path is **real, constant-time, and byte-exact vs
//! `std.crypto.ecc.P256` + the RFC 6979 ECDSA-P256 vectors + std's ECDSA
//! signer** — it is the correctness ORACLE and the non-amd64 fallback. Both
//! irreducible Fable cores are live (`gate.field_asm_implemented` /
//! `gate.fast_scalarmul_implemented`): the amd64 `MULX/ADX` field mul+square
//! with the NIST word-shuffle reduction, and the fast constant-time scalar
//! multiplies (fixed-base comb `k·G` + windowed variable-base, both with the
//! `blackBox`-guarded masked table scan). The core-vs-portable differentials in
//! `oracle_test.zig` are live and pin each core to the portable path + std.
//! See `gate.zig`, `fast_core.zig`, `SPEC.md`.

const std = @import("std");

pub const field = @import("field.zig");
pub const group = @import("group.zig");
pub const scalar = @import("scalar.zig");
pub const sign = @import("sign.zig");
pub const gate = @import("gate.zig");
pub const fast_core = @import("fast_core.zig");

/// The P-256 base field element (over `p = 2^256 − 2^224 + 2^192 + 2^96 − 1`).
pub const Fe = field.Fe;
/// A NIST P-256 curve point.
pub const P256 = group.P256;
/// A point in affine coordinates.
pub const AffineCoordinates = group.AffineCoordinates;
/// A scalar-field element (mod the group order `n`).
pub const Scalar = scalar.Scalar;

/// Std-compatible ECDSA-P256/SHA-256 over p256's fast curve — the drop-in for
/// `std.crypto.sign.ecdsa.EcdsaP256Sha256` (byte-exact; same struct surface:
/// `KeyPair`/`PublicKey`/`Signature`, `generateDeterministic`, DER + raw
/// codecs). Sign commits `k·G` constant-time; `verify` is vartime on public
/// inputs. Rewired onto by jwt (ES256) + jwe (ECDH-ES). See `sign.zig`.
pub const EcdsaP256Sha256 = sign.EcdsaP256Sha256;

/// True iff the field multiply/square hot path is running on the amd64
/// `MULX/ADX` core rather than the portable Solinas reduction. Both gates are
/// now `true`, so this is `true` on x86-64+ADX+BMI2 targets and `false`
/// (portable fallback) everywhere else.
pub const field_asm_active = field.field_asm_active;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any, // portable Solinas everywhere; amd64 MULX/ADX is an accel path
    .role = .util, // pure computation — no I/O
    .concurrency = .reentrant, // no globals; all values are plain types
    .model_after = "OpenSSL nistz256 (P-256 special-prime/Solinas reduction + windowed/comb scalarmul + MULX/ADX field asm); std.crypto.ecc.P256 as the byte-exact correctness oracle",
    .deps = .{}, // std only
};

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule: a bare re-export does NOT pull a file's tests in).
test {
    _ = field;
    _ = group;
    _ = scalar;
    _ = sign;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("wycheproof_kat_vectors.zig");
    _ = @import("wycheproof_der_kat_vectors.zig");
    _ = @import("wycheproof_kat_test.zig");
    _ = @import("oracle_test.zig");
    _ = @import("bench.zig");
}

test "meta.model_after names nistz256 and the std oracle" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "nistz256") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "P256") != null);
}

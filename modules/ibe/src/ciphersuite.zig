// SPDX-License-Identifier: MIT

//! ciphersuite — the DST/domain-separation-tag and hash machinery
//! `ibe.zig`'s `Encrypt`/`Decrypt` are built on: `h1` (identity string
//! -> `G1`, RFC 9380 hash-to-curve), and `h2`/`h3`/`h4` (this module's
//! OWN SHA-256/SHA-512-based domain-separated constructions — see this
//! file's module doc comment for how they differ from the sibling
//! `tlock` module's drand-interop-pinned `h2`/`h3`/`h4`).
//!
//! ## Relationship to `tlock`'s ciphersuite
//!
//! `tlock` (this repo's sibling module) implements the SAME
//! Boneh-Franklin "FullIdent" shape but is pinned byte-exactly to
//! drand/kyber's Go implementation (specific DSTs, a little-endian
//! rejection-sampling `h3` counter, and — critically — hashing the
//! pairing value's CUBE because `kilic/bls12-381`'s final
//! exponentiation differs from this repo's own). This module (`ibe`) is
//! a STANDALONE scheme: there is no external implementation to
//! interop with, so:
//!
//! - DSTs are this module's OWN (`dst_g1` below), not drand's.
//! - `h2`/`h4` use this module's OWN domain tags.
//! - `h3` uses `Fr.reduceWide` over a SHA-512 digest (a direct,
//!   spec-sanctioned hash-to-scalar reduction — see that function's
//!   own doc comment) instead of `tlock`'s little-endian
//!   rejection-sampling loop; both are valid ways to turn a hash output
//!   into a canonical `Fr` scalar, `reduceWide` is simply the more
//!   idiomatic one available in THIS repo when there is no external
//!   byte-exact target to match.
//! - The pairing value fed to `h2` is `bls12_381.pairing.pairing`'s
//!   CANONICAL output, used AS-IS — no cube, no representation
//!   adapter. `tlock`'s `gtToDrandRepr` (`gt -> gt³`) exists ONLY to
//!   match `kilic/bls12-381`'s specific final-exponentiation
//!   convention; `ibe` has no such external target, so as long as
//!   `Encrypt` and `Decrypt` both feed `h2` the SAME (canonical)
//!   representation — which they do, both via
//!   `bls12_381.pairing.pairing` — correctness only requires internal
//!   consistency, not matching any third party's convention. See
//!   `SPEC.md`'s "No drand-style cube" section.

const std = @import("std");
const bls12_381 = @import("bls12_381");
const entropy = @import("entropy");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const g1 = bls12_381.g1;
pub const g2 = bls12_381.g2;
pub const Fr = bls12_381.Fr;
pub const Fp12 = bls12_381.Fp12;

// ── ciphersuite constants ────────────────────────────────────────────

/// This module's own RFC-9380 hash-to-curve DST for `G1` — used by
/// `h1` to hash an arbitrary identity string onto `G1`. Distinct from
/// `tlock.ciphersuite.dst_g1` (drand's DST) and from
/// `bls12_381.bls_sig`'s DST (a different application) — RFC 9380 §3.1
/// requires every distinct application/protocol to use its own DST so
/// hash-to-curve outputs never collide across unrelated uses of the
/// same curve.
pub const dst_g1 = "ZIGLIBS-IBE-BF-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// Domain-separation tag for `h2` (hashing a `Gt` element to a mask).
pub const h2_tag = "zig-libs/ibe/H2";
/// Domain-separation tag for `h3` (hashing `(sigma, msg)` to a scalar).
pub const h3_tag = "zig-libs/ibe/H3";
/// Domain-separation tag for `h4` (hashing `sigma` to a mask).
pub const h4_tag = "zig-libs/ibe/H4";

/// The fixed message-block width `Ciphertext`'s `V`/`W` fields use.
/// This module's OWN choice (not `tlock`'s 16-byte drand DEK width):
/// 32 bytes is wide enough to wrap a 256-bit symmetric key (AES-256,
/// ChaCha20) directly as `Encrypt`'s `message` argument, matching
/// `Sha256.digest_length` exactly (so `h2`/`h4` need no truncation —
/// see their doc comments). Larger payloads are expected to be
/// encrypted with a symmetric scheme keyed by THIS module's output
/// (KEM-then-DEM), the same layering `tlock`'s own module doc comment
/// documents as "out of scope" for the raw BF-IBE primitive.
pub const block_bytes = 32;

comptime {
    std.debug.assert(block_bytes == Sha256.digest_length);
}

// ── H1: id -> G1 (REAL) ──────────────────────────────────────────────

/// `H1(id) = hashToCurveG1(id, dst_g1)` — RFC 9380 hash-to-curve,
/// delegating entirely to `bls12_381`'s already-real, byte-exact-KAT'd
/// hash-to-curve implementation. `id` is an arbitrary identity string
/// (an email address, a round number's digest, a device serial — this
/// module places no format requirement on it, unlike `tlock`'s
/// `beaconId`-shaped 32-byte SHA-256 digest).
pub fn h1(id: []const u8) g1.Affine {
    return bls12_381.hash_to_curve.hashToCurveG1(id, dst_g1);
}

// ── H2: Gt -> block (REAL) ───────────────────────────────────────────

/// `H2(gt) = SHA-256("zig-libs/ibe/H2" || gt_bytes)` — one SHA-256
/// call over the element's canonical `Fp12.toBytes` encoding, tag-
/// prefixed for domain separation from `h4`. `block_bytes ==
/// Sha256.digest_length` so no truncation is needed (unlike `tlock`'s
/// `h2`, which truncates to a smaller 16-byte width).
pub fn h2(gt: Fp12) [block_bytes]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(h2_tag);
    hasher.update(&gt.toBytes());
    var out: [block_bytes]u8 = undefined;
    hasher.final(&out);
    return out;
}

// ── H3: (sigma, msg) -> scalar (REAL) ────────────────────────────────

/// `H3(sigma, msg) -> r ∈ Fr`: `SHA-512("zig-libs/ibe/H3" || sigma ||
/// msg)` reduced mod the curve order via `Fr.reduceWide` — a direct,
/// single-hash-then-reduce construction (RFC 9380 §5's
/// `hash_to_field`-style approach: draw MORE bits than the field needs,
/// 512 vs. `Fr`'s 255, so the reduction bias is statistically
/// negligible — see `Fr.reduceWide`'s own doc comment). This is
/// simpler than `tlock.ciphersuite.h3`'s little-endian
/// rejection-sampling loop, which exists ONLY to match drand/kyber's
/// exact Go construction byte-for-byte; `ibe` has no such external
/// target, so the more idiomatic single-hash reduction is used instead
/// (still fully deterministic and canonical — `reduceWide`'s output is
/// always `< r` by construction).
pub fn h3(sigma: []const u8, msg: []const u8) Fr {
    var hasher = Sha512.init(.{});
    hasher.update(h3_tag);
    hasher.update(sigma);
    hasher.update(msg);
    var digest: [Sha512.digest_length]u8 = undefined;
    hasher.final(&digest);
    return Fr.reduceWide(&digest);
}

// ── H4: sigma -> block (REAL) ────────────────────────────────────────

/// `H4(sigma) = SHA-256("zig-libs/ibe/H4" || sigma)` — same
/// one-hash-then-return shape as `h2`, no `Gt` marshaling step, tag-
/// prefixed for domain separation from `h2`.
pub fn h4(sigma: []const u8) [block_bytes]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(h4_tag);
    hasher.update(sigma);
    var out: [block_bytes]u8 = undefined;
    hasher.final(&out);
    return out;
}

// ── randomness (REAL; explicit-parameter convention) ────────────────

/// Draws a fresh `block_bytes`-wide `sigma` from `io`'s entropy source
/// — the random padding `Encrypt` needs (BF-IBE's "FullIdent"
/// randomness). Mirrors `tlock.ciphersuite.randomSigma` /
/// `bbs`/`frost`'s "randomness is an explicit parameter, never an
/// internal `std.Io` read inside the crypto core" convention: `Encrypt`
/// itself takes `sigma` as a plain `[block_bytes]u8` parameter, sourced
/// from EITHER this function (production) or a fixed KAT value
/// (deterministic ciphertext reproduction).
///
/// Fail-closed (`entropy.fill`, not `io.random`): `sigma` is the FO
/// transform's only secret input, so IND-CCA rests entirely on it being
/// unpredictable, and this signature returns a value with no error
/// channel to say the draw degraded.
pub fn randomSigma(io: std.Io) [block_bytes]u8 {
    var buf: [block_bytes]u8 = undefined;
    entropy.fill(io, &buf);
    return buf;
}

// ── tests: REAL, ungated ──────────────────────────────────────────────

test "h1 lands on-curve and in the order-r G1 subgroup for an arbitrary identity" {
    const id = "alice@example.com";
    const p = h1(id);
    try std.testing.expect(g1.Jacobian.fromAffine(p).isOnCurve());
    try std.testing.expect(g1.Jacobian.fromAffine(p).subgroupCheck());
    try std.testing.expect(!p.infinity);
}

test "h1 is deterministic and injective-in-practice across distinct identities" {
    const p_alice = h1("alice@example.com");
    const p_bob = h1("bob@example.com");
    try std.testing.expect(!p_alice.x.eql(p_bob.x));
    try std.testing.expect(h1("alice@example.com").x.eql(p_alice.x)); // deterministic
}

test "h2/h4 are deterministic, tag-domain-separated, and exactly block_bytes wide" {
    const gt = Fp12.one;
    const a = h2(gt);
    const b = h2(gt);
    try std.testing.expectEqual(@as(usize, block_bytes), a.len);
    try std.testing.expectEqualSlices(u8, &a, &b); // deterministic

    const sigma = [_]u8{0x42} ** block_bytes;
    const c = h4(&sigma);
    const d = h4(&sigma);
    try std.testing.expectEqualSlices(u8, &c, &d);

    // h2 and h4 must NOT collide trivially (different domain tags):
    // Fp12.one's canonical bytes are mostly zero, sigma is 0x42
    // repeated — different inputs AND different tags, so equality here
    // would be a real red flag, not just an astronomically unlikely
    // coincidence.
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}

test "h3 is deterministic and produces a canonical (< r) Fr scalar" {
    const sigma = [_]u8{0x11} ** block_bytes;
    const msg = [_]u8{0x22} ** block_bytes;
    const r1 = h3(&sigma, &msg);
    const r2 = h3(&sigma, &msg);
    try std.testing.expect(r1.eql(r2));
    try std.testing.expect(!r1.isZero());

    // A different sigma must (overwhelmingly likely) give a different r.
    const other_sigma = [_]u8{0x99} ** block_bytes;
    const r3 = h3(&other_sigma, &msg);
    try std.testing.expect(!r1.eql(r3));
}

test "h3 is domain-separated from an unrelated SHA-512 use (tag matters)" {
    // Same (sigma, msg) input, but hashed without the tag, must differ
    // (sanity that the tag is actually mixed in, not a no-op).
    const sigma = [_]u8{0x33} ** block_bytes;
    const msg = [_]u8{0x44} ** block_bytes;
    var hasher = Sha512.init(.{});
    hasher.update(&sigma);
    hasher.update(&msg);
    var digest: [Sha512.digest_length]u8 = undefined;
    hasher.final(&digest);
    const untagged = Fr.reduceWide(&digest);
    const tagged = h3(&sigma, &msg);
    try std.testing.expect(!untagged.eql(tagged));
}

test "block_bytes equals Sha256.digest_length (32) so h2/h4 never truncate" {
    try std.testing.expectEqual(@as(usize, 32), block_bytes);
}

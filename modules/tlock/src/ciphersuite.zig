// SPDX-License-Identifier: MIT

//! ciphersuite — the mechanical hash/DST/domain-separation machinery
//! `tlock.zig`'s `encrypt`/`decrypt` (the Fable-gated BF-IBE core) are
//! built on: `beaconId` (the drand "unchained" beacon digest, which
//! doubles as the IBE identity string), `h1` (identity -> `G1`,
//! RFC 9380 hash-to-curve), and `h2`/`h3`/`h4` (drand/kyber's own
//! `encrypt/ibe` domain-separated SHA-256 constructions). Everything in
//! this file is REAL — recipe, not research: get the DST/tag/byte-order
//! right and it is done, unlike `tlock.zig`'s `encrypt`/`decrypt`, which
//! must additionally get the FO-transform ASSEMBLY (which hash feeds
//! which XOR, and the `U == r*gen` consistency check) right — see that
//! file's module doc comment.
//!
//! ## Source / provenance
//!
//! Every constant and construction below is transcribed from drand's
//! ACTUAL production Go source, fetched 2026-07-16 (see `NOTICE`):
//!
//! - DSTs: `github.com/drand/drand/v2/crypto` `schemes.go`,
//!   `NewPedersenBLSUnchainedG1` (the `SigsOnG1ID` /
//!   `"bls-unchained-g1-rfc9380"` scheme — quicknet's actual scheme,
//!   confirmed live against `https://api.drand.sh/v2/beacons/quicknet/info`
//!   returning `"scheme":"bls-unchained-g1-rfc9380"`).
//! - `beaconId`: the same file's unchained `DigestFunc` —
//!   `sha256(BigEndian(round_number))`, no previous signature folded in
//!   (that is what makes it "unchained" and thus safe to hash ahead of
//!   time, before the round is reached — the entire premise of
//!   timelock encryption).
//! - `h1`/`h2`/`h3`/`h4`: `github.com/drand/kyber`
//!   `encrypt/ibe/ibe.go`'s `EncryptCCAonG2`/`DecryptCCAonG2`/`h3`/`h4`/
//!   `gtToHash` (quicknet uses the "CCAonG2" pair — master public key
//!   and `U` in `G2`, identity/signature in `G1` — see `tlock.zig`'s
//!   module doc comment for why "on G2" is the variant this module
//!   targets despite the scheme's own G1-suggesting name).
//!
//! ## Variant confirmation (read before wiring a KAT)
//!
//! drand runs FOUR schemes total; only two are usable for timelock
//! encryption (`tlock.go`'s `TimeLock`/`TimeUnlock` `switch` — the
//! chained default scheme is EXCLUDED, its digest folds in the previous
//! signature, which is unknowable ahead of a future round). Of the two
//! usable ones, quicknet (this module's target) is `SigsOnG1ID`
//! (`"bls-unchained-g1-rfc9380"`): master public key in `G2` (96-byte
//! compressed), beacon/round signatures in `G1` (48-byte compressed) —
//! the SAME group layout `bls12_381.bls_sig`'s min-pk ciphersuite uses,
//! and RFC-9380-conformant DSTs (unlike the OLDER, deprecated
//! `ShortSigSchemeID`/`"bls-unchained-on-g1"`, which reuses the G2 DST
//! for G1 hashing — a known non-conformance kept only for
//! retro-compatibility, and NOT what this module targets).
//!
//! `tlock.go`'s `TimeLock` routes `SigsOnG1ID` through
//! `ibe.EncryptCCAonG2` (master on `G2`, `U` on `G2`, identity hashed to
//! `G1`) — so despite the scheme's own name suggesting "signatures/
//! everything on G1", the ENCRYPTION-SIDE ciphertext point `U` lives in
//! `G2`, and only the beacon signature (`decrypt`'s private-key
//! argument) is the `G1` element. See `tlock.zig`'s `Ciphertext` doc
//! comment.

const std = @import("std");
const bls12_381 = @import("bls12_381");
const entropy = @import("entropy");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const g1 = bls12_381.g1;
pub const g2 = bls12_381.g2;
pub const Fr = bls12_381.Fr;
pub const Fp12 = bls12_381.Fp12;

// ── ciphersuite constants ────────────────────────────────────────────

/// `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` — the RFC-9380-default
/// hash-to-curve DST for `G1`, used by drand's `SigsOnG1ID` scheme to
/// hash the beacon identity (`beaconId`, below) onto `G1` (`h1`).
/// Source: `drand/drand` `crypto/schemes.go`,
/// `NewPedersenBLSUnchainedG1`'s `bls.NewBLS12381SuiteWithDST` first
/// argument.
pub const dst_g1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` — the RFC-9380-default
/// `G2` DST. `SigsOnG1ID` never actually hashes anything onto `G2`
/// itself (the master public key lives there but is never a
/// hash-to-curve OUTPUT), but this is recorded for completeness/parity
/// with the scheme's own constructor call and because a future sibling
/// scheme (`ShortSigSchemeID`) would need it. Same source as `dst_g1`.
pub const dst_g2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Domain-separation tag for `h2` (hashing a `Gt` element to a mask).
/// Source: `drand/kyber` `encrypt/ibe/ibe.go`, `H2Tag()`.
pub const h2_tag = "IBE-H2";
/// Domain-separation tag for `h3` (hashing `(sigma, msg)` to a scalar).
/// Source: same file, `H3Tag()`.
pub const h3_tag = "IBE-H3";
/// Domain-separation tag for `h4` (hashing `sigma` to a mask).
/// Source: same file, `H4Tag()`.
pub const h4_tag = "IBE-H4";

/// The fixed message-block width `tlock.Ciphertext`'s `V`/`W` fields
/// use — drand's own `tlock.go` `cipherVLen`/`cipherWLen` constants
/// (both `16`): the IBE layer never encrypts arbitrary-length data
/// directly, only a 16-byte symmetric file key that an outer hybrid
/// `age` layer (out of this module's scope — see `SPEC.md`'s "Out of
/// scope") uses to bulk-encrypt the real payload. `kyber`'s
/// `encrypt/ibe` core is itself GENERIC in message length (bounded only
/// by `sha256.digest_length`, 32 — see `h2`/`h4` below) but this module
/// pins the same 16-byte width drand's CLI (`tle`) actually ships, so a
/// `Ciphertext`'s wire size matches drand's byte-for-byte.
pub const block_bytes = 16;

comptime {
    std.debug.assert(block_bytes <= Sha256.digest_length);
}

// ── beacon identity (REAL) ───────────────────────────────────────────

/// drand's "unchained" `DigestBeacon`: `SHA-256(I2OSP(round, 8))`,
/// big-endian — the round number ALONE, no previous signature folded
/// in. This is the byte string that is (a) what the beacon threshold-
/// signs for `round` (`crypto.Scheme.VerifyBeacon` hashes the same way)
/// and (b) the IBE "identity" `h1` below hashes onto `G1` — the same
/// digest serves both purposes, which is what makes `round_signature ==
/// sk * h1(beaconId(round))`: the beacon signature over the round IS
/// the BF-IBE private key for that identity. Source:
/// `drand/drand` `crypto/schemes.go`, `NewPedersenBLSUnchainedG1`'s
/// `DigestFunc`.
///
/// **Not** the chained scheme's digest (which additionally folds in
/// `GetPreviousSignature()`) — that scheme is excluded from timelock
/// encryption entirely (see this file's module doc comment), so this
/// function has no "chained" counterpart to confuse it with.
pub fn beaconId(round: u64) [32]u8 {
    var round_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &round_be, round, .big);
    var out: [32]u8 = undefined;
    Sha256.hash(&round_be, &out, .{});
    return out;
}

// ── H1: identity -> G1 (REAL) ────────────────────────────────────────

/// `H1(id) = hash_to_curve.hashToCurveG1(id, dst_g1)` — RFC 9380
/// hash-to-curve, delegating entirely to `bls12_381`'s already-real,
/// byte-exact-KAT'd Part 3 (`hash_to_curve.hashToCurveG1`, itself pinned
/// against RFC 9380 Appendix J.9.1). The `id` argument is `beaconId`'s
/// 32-byte SHA-256 digest, NOT the raw round number — see `beaconId`'s
/// doc comment.
pub fn h1(id: [32]u8) g1.Affine {
    return bls12_381.hash_to_curve.hashToCurveG1(&id, dst_g1);
}

// ── H2: Gt -> block (REAL) ───────────────────────────────────────────

/// `H2(gt) = SHA-256("IBE-H2" || gt_bytes)[0..len]` — drand/kyber's
/// `gtToHash`: ONE SHA-256 call (not an XOF/`expand_message`), the
/// element's canonical byte encoding fed in after the tag, truncated to
/// `len` bytes. `len` is `comptime` (every call site in `tlock.zig`
/// uses the fixed `block_bytes`) and MUST be `<= Sha256.digest_length`
/// (32) — enforced by the `comptime` assert below, mirroring `kyber`'s
/// own `h.Sum(nil)[:length]` truncation (kyber never pads past its hash
/// width either; a `len` beyond 32 would need a different construction
/// entirely, which drand's own `tlock.go` never exercises since
/// `block_bytes` is fixed at 16).
///
/// **Serialization caveat — RESOLVED (2026-07-16 Fable pass,
/// vector-verified):** `gt_bytes` in drand/kyber is
/// `kilic/bls12-381`'s `GT.ToBytes`, whose byte NESTING is confirmed
/// IDENTICAL to `bls12_381.Fp12.toBytes` (`c1 || c0` high-to-low at
/// every tower level — verified byte-exactly against kilic's own
/// published pairing-output vectors, not just by source read). The
/// caveat's real payload turned out to be the pairing VALUE, not the
/// byte order: kilic's `GT` elements are the CANONICAL optimal-ate
/// pairing value's CUBE (FCKRH `f^(3d)` final exponentiation vs
/// `bls12_381.pairing`'s exact-`d` chain), so `tlock.zig`'s callers
/// pass this function the element in drand's representation via the
/// private `gtToDrandRepr` (`gt -> gt³`) adapter — see that helper's
/// doc comment and `SPEC.md`'s "Gt serialization" section for the
/// full derivation and the drand interop vector that pins it. This
/// function itself hashes exactly the `Fp12` it is given; its
/// definition never changed.
pub fn h2(comptime len: usize, gt: Fp12) [len]u8 {
    comptime std.debug.assert(len <= Sha256.digest_length);
    var hasher = Sha256.init(.{});
    hasher.update(h2_tag);
    hasher.update(&gt.toBytes());
    var full: [Sha256.digest_length]u8 = undefined;
    hasher.final(&full);
    return full[0..len].*;
}

// ── H3: (sigma, msg) -> scalar (REAL) ────────────────────────────────

/// `H3(sigma, msg) -> r ∈ Fr` — drand/kyber's `h3`: hash `("IBE-H3" ||
/// sigma || msg)` once to get a binding `buffer`, then REJECTION-SAMPLE
/// a canonical `Fr` scalar by repeatedly hashing
/// `(LE16(i) || buffer)` for `i = 1, 2, ...` and masking off the
/// (single, for BLS12-381's 255-bit `r`) top bit that would otherwise
/// let the 256-bit hash output exceed the field. Source: `drand/kyber`
/// `encrypt/ibe/ibe.go`'s `h3` — transcribed byte-for-byte:
///
/// ```
/// buffer = SHA-256("IBE-H3" || sigma || msg)
/// for i in 1..65535:
///     hashed = SHA-256(LittleEndian16(i) || buffer)
///     hashed[0] >>= 1          // mask 1 top bit: 256 canonical - 255 actual bits
///     if hashed, read big-endian, is < r: return it
/// ```
///
/// The `LittleEndian16(i)` counter (drand's `binary.LittleEndian.
/// PutUint16`) is a genuine, easy-to-invert-by-mistake asymmetry worth
/// calling out: EVERYTHING else in this ciphersuite (scalars, points,
/// the round number in `beaconId`) is big-endian; only this one
/// 2-byte rejection-sampling counter is little-endian, because that is
/// what the upstream Go source literally does. The masking shift
/// (`hashed[0] >>= 1`) is likewise BIG-endian-relative (it clears the
/// scalar's TOP bit, i.e. the first byte of a big-endian 32-byte
/// buffer) — `Fr.fromBytes` itself does the canonical `< r` rejection
/// (`error.NonCanonical`), so this function's own job is only the
/// masking + retry loop around it. Retry is astronomically unlikely to
/// exhaust `i < 65535` (each candidate is uniform over a ~255-bit
/// range within a ~256-bit field — roughly 50% acceptance per try).
pub fn h3(sigma: []const u8, msg: []const u8) Fr {
    var first = Sha256.init(.{});
    first.update(h3_tag);
    first.update(sigma);
    first.update(msg);
    var buffer: [Sha256.digest_length]u8 = undefined;
    first.final(&buffer);

    var i: u16 = 1;
    while (i < 65535) : (i += 1) {
        var hasher = Sha256.init(.{});
        var iter_le: [2]u8 = undefined;
        std.mem.writeInt(u16, &iter_le, i, .little); // LittleEndian, per drand/kyber
        hasher.update(&iter_le);
        hasher.update(&buffer);
        var hashed: [Sha256.digest_length]u8 = undefined;
        hasher.final(&hashed);
        hashed[0] >>= 1; // mask the single top bit (canonical 256 vs r's actual 255 bits)
        if (Fr.fromBytes(hashed)) |scalar| return scalar else |_| {}
    }
    // Rejection-sampling failure: ~2^-255 cumulative probability over
    // 65534 tries against a field missing only 1 bit from 2^256 — never
    // observed, and drand's own upstream code has the identical
    // (unreachable in practice) failure mode.
    unreachable;
}

// ── H4: sigma -> block (REAL) ────────────────────────────────────────

/// `H4(sigma) = SHA-256("IBE-H4" || sigma)[0..len]` — drand/kyber's
/// `h4`: same one-hash-then-truncate shape as `h2`, no `Gt` marshaling
/// step. Source: `drand/kyber` `encrypt/ibe/ibe.go`'s `h4`.
pub fn h4(comptime len: usize, sigma: []const u8) [len]u8 {
    comptime std.debug.assert(len <= Sha256.digest_length);
    var hasher = Sha256.init(.{});
    hasher.update(h4_tag);
    hasher.update(sigma);
    var full: [Sha256.digest_length]u8 = undefined;
    hasher.final(&full);
    return full[0..len].*;
}

// ── randomness (REAL; explicit-parameter convention) ────────────────

/// Draws a fresh `block_bytes`-wide `sigma` from `io`'s entropy source
/// — the ONE piece of real randomness `tlock.encrypt` needs (BF-IBE's
/// "FullIdent" random padding, drand/kyber's `rand.Read(sigma)`).
/// Mirrors `bbs`/`frost`'s "randomness is an explicit parameter, never
/// an internal `std.Io` read" convention (`bbs/src/root.zig`'s
/// "Randomness" section): `tlock.encrypt` itself takes `sigma` as a
/// plain `[block_bytes]u8` parameter, sourced from EITHER this function
/// (production) or a KAT vector's fixed bytes (deterministic
/// ciphertext reproduction) — see `tlock.zig`'s `encrypt` doc comment.
///
/// Fail-closed (`entropy.fill`, not `io.random`): a guessable `sigma`
/// unlocks a timelock ciphertext before its round, which is the one
/// property the whole construction sells. Nothing in this signature can
/// return an error, so the draw either succeeds or aborts.
pub fn randomSigma(io: std.Io) [block_bytes]u8 {
    var buf: [block_bytes]u8 = undefined;
    entropy.fill(io, &buf);
    return buf;
}

pub const meta_deps_note = "bls12_381"; // see root.zig's meta.deps

// ── tests: REAL, ungated ──────────────────────────────────────────────

test "beaconId: round 0 and round 1 produce distinct 32-byte SHA-256 digests" {
    const id0 = beaconId(0);
    const id1 = beaconId(1);
    try std.testing.expect(!std.mem.eql(u8, &id0, &id1));

    // SHA-256(8 zero bytes) — independently known constant.
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc");
    try std.testing.expectEqualSlices(u8, &expected, &id0);
}

test "beaconId(1000) matches an independently (Python) computed SHA-256 digest" {
    // Computed via: python3 -c "import hashlib,struct;
    // print(hashlib.sha256(struct.pack('>Q',1000)).hexdigest())"
    // -> f652498d092acd949bad74e40683bf3824fb817980504a0c7e6722cfc5a9c0a3
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "f652498d092acd949bad74e40683bf3824fb817980504a0c7e6722cfc5a9c0a3");
    try std.testing.expectEqualSlices(u8, &expected, &beaconId(1000));
}

test "h1 lands on-curve and in the order-r G1 subgroup for a real beacon identity" {
    const id = beaconId(1000);
    const p = h1(id);
    try std.testing.expect(g1.Jacobian.fromAffine(p).isOnCurve());
    try std.testing.expect(g1.Jacobian.fromAffine(p).subgroupCheck());
    try std.testing.expect(!p.infinity);
}

test "h1 is deterministic and injective-in-practice across distinct rounds" {
    const p1000 = h1(beaconId(1000));
    const p1001 = h1(beaconId(1001));
    try std.testing.expect(!p1000.x.eql(p1001.x));
    try std.testing.expect(h1(beaconId(1000)).x.eql(p1000.x)); // deterministic
}

test "h2/h4 are deterministic, tag-domain-separated, and truncate to the requested length" {
    const gt = Fp12.one;
    const a = h2(block_bytes, gt);
    const b = h2(block_bytes, gt);
    try std.testing.expectEqualSlices(u8, &a, &b); // deterministic

    const sigma = [_]u8{0x42} ** block_bytes;
    const c = h4(block_bytes, &sigma);
    const d = h4(block_bytes, &sigma);
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

test "h3's masking never produces a value >= r on repeated random-ish inputs" {
    // Fr.fromBytes REJECTS non-canonical (>= r) input with
    // error.NonCanonical; h3 returning at all (not looping to
    // exhaustion) on a spread of inputs is itself evidence the masking
    // step is doing its job, but assert the returned value round-trips
    // through Fr's own canonical byte codec as an extra check.
    var i: u8 = 0;
    while (i < 32) : (i += 1) {
        const sigma = [_]u8{i} ** block_bytes;
        const msg = [_]u8{i +% 1} ** block_bytes;
        const r = h3(&sigma, &msg);
        _ = try Fr.fromBytes(r.toBytes()); // must not error
    }
}

test "block_bytes matches drand's tlock.go cipherVLen/cipherWLen (16)" {
    try std.testing.expectEqual(@as(usize, 16), block_bytes);
}

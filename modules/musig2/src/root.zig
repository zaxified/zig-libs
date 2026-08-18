// SPDX-License-Identifier: MIT
//! musig2 — MuSig2 multi-signature scheme over secp256k1, per BIP327: a
//! threshold-free n-of-n multi-signature protocol whose final aggregate
//! signature is a plain, ordinary BIP340 Schnorr signature (any BIP340
//! verifier accepts it without knowing it was produced by multiple
//! signers). Builds directly on the sibling `bip340` module for tagged
//! hashing and x-only public-key handling.
//!
//! **Status: complete (v2, tweak-aware).** The full BIP327 core signing
//! flow AND key tweaking are implemented and byte-exact against the
//! official BIP327 test vectors (`kat_test.zig`):
//!
//!   - `PlainPublicKey`/`PubNonce`/`AggNonce`/`SecNonce`/`PartialSignature`:
//!     full BIP327 wire codecs (`cpoint`/`cpoint_ext`/`cbytes`/`cbytes_ext`,
//!     built on `bip340.XOnlyPublicKey` + `std.crypto.ecc.Secp256k1`), with
//!     every parse-level range/tag/on-curve check BIP327 requires.
//!   - `keySort`: BIP327's `KeySort` (pure lexicographic sort), byte-exact
//!     against the official vectors.
//!   - `nonceGen`: BIP327's full `NonceGen` algorithm (the aux-rand xor, the
//!     variable-length `m_prefixed`/`extra_in` encoding, the two tagged-hash
//!     nonce scalars, `k_i·G`), byte-exact against all 4 official vectors.
//!   - `keyAgg`: `KeyAggCoeffInternal` (the "second key" coefficient-1 rule)
//!     + `Q = Σ a_i·P_i` + the `is_infinite(Q)` rogue-key check — byte-exact
//!     aggregate keys against all 4 official `key_agg` vectors.
//!   - `nonceAgg`: `R_j = Σ R_{i,j}` with the legal point-at-infinity
//!     encoding for a cancelled sum — byte-exact against both official
//!     `nonce_agg` vectors (including the infinity one).
//!   - `getSessionValues`: `b`/`R` (with the spec's substitute-`G`-for-
//!     infinity rule)/`e` (BIP340's own challenge tag, by design).
//!   - `sign`: the nonce parity mask, the `g·gacc·d'` secret-key negation,
//!     `s = k1 + b·k2 + e·a·d`, and the spec's MANDATORY self-verify before
//!     returning — byte-exact partial signatures against all 6 official
//!     `sign_verify` vectors.
//!   - `partialSigVerify`/`partialSigVerifyInternal`: the verifier-side
//!     `g' = g·gacc` negation and the `s·G == Re* + e·a·g'·P` equation —
//!     accepts every official valid partial signature, rejects both official
//!     wrong-signature/wrong-signer vectors.
//!   - `partialSigAgg`: `s = Σs_i + e·g·tacc`, `sig = xbytes(R) ‖ bytes(s)`
//!     — byte-exact against ALL four official `sig_agg` vectors (untweaked
//!     and tweaked), and the result verifies under plain `bip340.verify`
//!     (the scheme's headline property, asserted end-to-end in
//!     `kat_test.zig`).
//!   - `KeyAggContext.applyTweak`: BIP327 `ApplyTweak` — plain (BIP32-style)
//!     and x-only (Taproot-style) tweaks, composing in sequence via the
//!     `gacc`/`tacc` accumulators (`Q' = g·Q + t·G`, `gacc' = g·gacc`,
//!     `tacc' = t + g·tacc`); `SessionContext.tweaks` threads them through
//!     `getSessionValues` into `sign`/`partialSigVerify`/`partialSigAgg`
//!     (whose formulas were tweak-general from v1). Byte-exact against all
//!     5 official `tweak_vectors.json` valid cases, plus the tweak error
//!     cases (`t >= n`, tweaked key at infinity).
//!
//! Still out of scope: `DeterministicSign` (the optional single-signer
//! convenience wrapper) — see `SPEC.md`.
//!
//! Zig std GAP: yes, same shape as `bip340` — `std.crypto.ecc.Secp256k1`
//! supplies the curve group; this module (and `bip340` beneath it) supplies
//! every BIP340/BIP327-specific convention (tagged hashing, x-only/plain-key
//! encodings, the MuSig2 aggregation/signing equations) on top.

const std = @import("std");
const bip340 = @import("bip340");
const Secp256k1 = @import("k256").Secp256k1;
const Fe = Secp256k1.Fe;
const scalar_mod = Secp256k1.scalar;
const Scalar = scalar_mod.Scalar;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; contexts/keys are plain value types
    .model_after = "BIP327 (bitcoin/bips) — MuSig2 for BIP340-compatible Multi-Signatures; the k256 module supplies the curve group (byte-exact to std.crypto.ecc.Secp256k1), the sibling bip340 module supplies tagged hashing + x-only key handling",
    .deps = .{ "bip340", "k256" }, // bip340 sibling (tagged hashing, XOnlyPublicKey, challenge tag); k256 curve group
};

// ── domain tags (BIP327 §"Notation": hash_tag(x) = SHA256(SHA256(tag) ‖
// SHA256(tag) ‖ x) — the same construction as BIP340's taggedHash, reused
// via bip340.taggedHash/taggedHasher with these five NEW tags) ────────────

pub const list_tag = "KeyAgg list";
pub const coefficient_tag = "KeyAgg coefficient";
pub const noncecoef_tag = "MuSig/noncecoef";
pub const aux_tag = "MuSig/aux";
pub const nonce_tag = "MuSig/nonce";

/// `int(bytes32) mod n`: the same reducing conversion `bip340` uses
/// internally for its challenge/nonce scalars (a 32-byte hash output can
/// exceed `n`, so a plain `Scalar.fromBytes` — which REJECTS non-canonical
/// values instead of reducing them — would be wrong here). Duplicated
/// locally rather than imported: `bip340` does not export its private
/// `reduceToScalar`.
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

/// BIP327 `has_even_y(P)` (`P` must not be the point at infinity). Only
/// ever called on PUBLIC points (the aggregate key `Q`, the final session
/// nonce `R` as consumed by `partialSigVerifyInternal`/`partialSigAgg`) —
/// `sign`'s own use of the `R`-parity bit goes through a constant-time
/// masked select instead (see `sign`).
fn hasEvenY(p: Secp256k1) bool {
    return !p.affineCoordinates().y.isOdd();
}

/// BIP327 `g`: `1` if `has_even_y(Q)`, else `-1 mod n` (`n - 1`) — the
/// sign-flip factor that keeps signing/verification consistent with the
/// X-ONLY (implicitly even-y) final aggregate public key. Computed
/// IDENTICALLY by `sign`, `partialSigVerifyInternal`, and `partialSigAgg`
/// (via this one helper, so the three can never disagree — see `SPEC.md`'s
/// threat model on the parity/`g`/`gacc` chain). `Q` is public, so the
/// branch is not secret-dependent.
fn gFromQ(q: Secp256k1) Scalar {
    return if (hasEvenY(q)) Scalar.one else Scalar.one.neg();
}

// ── cpoint / cpoint_ext / cbytes / cbytes_ext (BIP327 §"Notation") ─────────
//
// REAL — built entirely on `bip340.XOnlyPublicKey`'s already-audited x-only
// parse/lift, plus a parity-negate for the `x[0] == 3` case. No new crypto
// beyond what `bip340` already implements.

pub const PointError = error{InvalidPublicKey};

/// BIP327 `cpoint(x)`: `x` is a 33-byte compressed point (`prefix ‖
/// xonly32`). `prefix` must be `2` or `3`; `lift_x(xonly32)` (BIP340's
/// even-y convention, via `bip340.XOnlyPublicKey`) must succeed; the result
/// is negated (odd-y) iff `prefix == 3`.
fn cpoint(bytes33: [33]u8) PointError!Secp256k1 {
    const prefix = bytes33[0];
    if (prefix != 2 and prefix != 3) return error.InvalidPublicKey;
    const xonly = bip340.XOnlyPublicKey.fromBytes(bytes33[1..33].*) catch return error.InvalidPublicKey;
    const p_even = xonly.lift() catch return error.InvalidPublicKey;
    return if (prefix == 3) p_even.neg() else p_even;
}

/// BIP327 `cpoint_ext(x)`: `null` (the point at infinity) if `x` is all
/// zero bytes, else `cpoint(x)`.
fn cpointExt(bytes33: [33]u8) PointError!?Secp256k1 {
    if (std.mem.allEqual(u8, &bytes33, 0)) return null;
    return try cpoint(bytes33);
}

/// BIP327 `cbytes(P)`: `std.crypto.ecc.Secp256k1.toCompressedSec1` already
/// computes exactly this (prefix `2`/`3` from y-parity, then `xbytes(P)`) —
/// reused directly rather than reimplemented (CONVENTIONS.md §1: prefer
/// std). Caller must ensure `P` is not the point at infinity (BIP327's
/// `cbytes` is undefined there; `cbytes_ext` is the infinity-safe variant).
const cbytes = Secp256k1.toCompressedSec1;

/// BIP327 `cbytes_ext(P)`: `bytes(33, 0)` if `P` is `null` (infinity), else
/// `cbytes(P)`.
fn cbytesExt(p: ?Secp256k1) [33]u8 {
    return if (p) |point| cbytes(point) else [_]u8{0} ** 33;
}

// ── PlainPublicKey (33-byte compressed individual public key) ─────────────

/// A MuSig2 participant's individual public key: 33 bytes, SEC1-compressed
/// (`prefix(1) ‖ x(32)`) — distinct from `bip340.XOnlyPublicKey` (32-byte,
/// implicit even-y): MuSig2 aggregation needs the real, possibly-odd-y
/// point of every participant (BIP327 §"Notation"'s `cpoint`), only the
/// *aggregate* key is reduced to x-only at the end.
pub const PlainPublicKey = struct {
    bytes: [33]u8,

    pub const encoded_length = 33;

    /// Parses AND validates eagerly (mirrors `bip340.XOnlyPublicKey.fromBytes`):
    /// rejects a prefix byte that isn't `2`/`3` (key_agg_vectors.json "First
    /// byte of public key is not 2 or 3"), a non-canonical x ≥ p
    /// (key_agg_vectors.json "Public key exceeds field size"), and an x with
    /// no valid curve point (key_agg_vectors.json "Invalid public key").
    pub fn fromBytes(bytes: [33]u8) PointError!PlainPublicKey {
        _ = try cpoint(bytes);
        return .{ .bytes = bytes };
    }

    /// BIP327 `cpoint(pk)` — the real secp256k1 point (parity per the
    /// prefix byte). Re-validates so this is safe on hand-constructed values.
    pub fn point(pk: PlainPublicKey) PointError!Secp256k1 {
        return cpoint(pk.bytes);
    }

    pub fn toBytes(pk: PlainPublicKey) [33]u8 {
        return pk.bytes;
    }
};

/// BIP327 `KeySort(pk_1..u)`: sort a list of plain public keys in
/// lexicographic (byte-wise) order, in place. REAL — pure byte comparison,
/// no curve arithmetic. Byte-exact against `kat_vectors.zig`'s `key_sort`
/// vectors.
pub fn keySort(pks: []PlainPublicKey) void {
    std.mem.sort(PlainPublicKey, pks, {}, struct {
        fn lessThan(_: void, a: PlainPublicKey, b: PlainPublicKey) bool {
            return std.mem.order(u8, &a.bytes, &b.bytes) == .lt;
        }
    }.lessThan);
}

// ── PubNonce / AggNonce (66-byte pairs of compressed points) ───────────────

pub const PubNonceError = error{InvalidPubNonce};

/// A signer's public nonce pair: 66 bytes, `cbytes(R*,1) ‖ cbytes(R*,2)`
/// (BIP327 §"Nonce Generation"). Unlike `AggNonce`, neither half may ever
/// be the point-at-infinity encoding — these are freshly generated nonce
/// points, never a sum.
pub const PubNonce = struct {
    bytes: [66]u8,

    pub const encoded_length = 66;

    /// Validates both halves eagerly via `cpoint` (nonce_agg_vectors.json's
    /// "wrong tag" / "not an X coordinate" / "exceeds field size" cases,
    /// each also reachable via `sign_verify_vectors.json`'s "Invalid
    /// pubnonce" verify-error case).
    pub fn fromBytes(bytes: [66]u8) PubNonceError!PubNonce {
        _ = cpoint(bytes[0..33].*) catch return error.InvalidPubNonce;
        _ = cpoint(bytes[33..66].*) catch return error.InvalidPubNonce;
        return .{ .bytes = bytes };
    }

    /// The two lifted points `(R*,1, R*,2)`. Re-validates (safe on
    /// hand-constructed values).
    pub fn points(pn: PubNonce) PubNonceError!struct { r1: Secp256k1, r2: Secp256k1 } {
        return .{
            .r1 = cpoint(pn.bytes[0..33].*) catch return error.InvalidPubNonce,
            .r2 = cpoint(pn.bytes[33..66].*) catch return error.InvalidPubNonce,
        };
    }
};

pub const AggNonceError = error{InvalidAggNonce};

/// The aggregate public nonce: 66 bytes, `cbytes_ext(R1) ‖ cbytes_ext(R2)`
/// (BIP327 §"Nonce Aggregation") — EITHER half may be the all-zero
/// point-at-infinity encoding (see "Dealing with Infinity in Nonce
/// Aggregation" in the spec / `SPEC.md`'s threat model).
pub const AggNonce = struct {
    bytes: [66]u8,

    pub const encoded_length = 66;

    /// Validates both halves eagerly via `cpoint_ext` (sign_verify_vectors
    /// .json's three "Aggregate nonce is invalid" sign-error cases: wrong
    /// tag 0x04, second half not an X coordinate, second half exceeds
    /// field size).
    pub fn fromBytes(bytes: [66]u8) AggNonceError!AggNonce {
        _ = cpointExt(bytes[0..33].*) catch return error.InvalidAggNonce;
        _ = cpointExt(bytes[33..66].*) catch return error.InvalidAggNonce;
        return .{ .bytes = bytes };
    }

    pub fn points(an: AggNonce) AggNonceError!struct { r1: ?Secp256k1, r2: ?Secp256k1 } {
        return .{
            .r1 = cpointExt(an.bytes[0..33].*) catch return error.InvalidAggNonce,
            .r2 = cpointExt(an.bytes[33..66].*) catch return error.InvalidAggNonce,
        };
    }
};

// ── SecNonce (97-byte local secret-nonce triple) ───────────────────────────

pub const SecNonceError = error{InvalidSecNonce};

/// A signer's LOCAL secret-nonce state: 97 bytes, `bytes(32,k1) ‖
/// bytes(32,k2) ‖ pk(33)` (BIP327 footnote on `secnonce`'s storage — "not
/// meant to be sent over the wire", this exact layout is a suggestion the
/// reference implementation and official test vectors both follow).
///
/// SECURITY: a `SecNonce` MUST be used as input to `sign` at most once —
/// reusing it (with a different message/signer-set) is exactly the
/// classic Schnorr nonce-reuse key-leak, same failure mode `bip340`'s
/// `SPEC.md` documents for its own nonce. `sign` zeroes its OWN local copy
/// via `deinit` right after use (defense-in-depth — reduces the value's
/// on-stack lifetime), but that cannot reach the caller's copy: the
/// caller remains responsible for erasing/dropping its own `SecNonce`
/// after the single `sign` call, e.g. `defer secnonce.deinit();` placed
/// immediately after drawing it (see `nonceGen`).
pub const SecNonce = struct {
    bytes: [97]u8,

    pub const encoded_length = 97;

    /// Raw copy — no eager validation (mirrors the spec: an invalid
    /// `secnonce` is a `Sign`-time failure, not a parse-time one; see
    /// `k1Scalar`/`k2Scalar`).
    pub fn fromBytes(bytes: [97]u8) SecNonce {
        return .{ .bytes = bytes };
    }

    /// Zero the 97 secret bytes in place. Idempotent. Call this as soon
    /// as a `SecNonce` has served its single `sign` use (or will never be
    /// used at all) — see the struct doc comment.
    pub fn deinit(self: *SecNonce) void {
        std.crypto.secureZero(u8, &self.bytes);
    }

    fn scalarAt(sn: SecNonce, comptime start: usize) SecNonceError!Scalar {
        const s = Scalar.fromBytes(sn.bytes[start .. start + 32].*, .big) catch return error.InvalidSecNonce;
        if (s.isZero()) return error.InvalidSecNonce;
        return s;
    }

    /// `k1' = int(secnonce[0:32])`; fails if `k1' = 0` or `k1' >= n`
    /// (sign_verify_vectors.json's "Secnonce is invalid which may indicate
    /// nonce reuse" — the all-zero secnonce vector).
    pub fn k1Scalar(sn: SecNonce) SecNonceError!Scalar {
        return sn.scalarAt(0);
    }

    /// `k2' = int(secnonce[32:64])`; same range check as `k1Scalar`.
    pub fn k2Scalar(sn: SecNonce) SecNonceError!Scalar {
        return sn.scalarAt(32);
    }

    /// `pk = secnonce[64:97]` — the individual public key this secnonce
    /// was generated for (`Sign` checks this against `cbytes(d'·G)`).
    pub fn pubkeyBytes(sn: SecNonce) [33]u8 {
        return sn.bytes[64..97].*;
    }
};

// ── NonceGen (BIP327 §"Nonce Generation") ─────────────────────────────────
//
// Structurally the same shape as `bip340.sign`'s nonce derivation (tagged
// hash → `int(...) mod n` → `k·G`), with a richer preimage encoding; no
// parity ambiguity, no rogue-key surface.

pub const NonceGenError = error{InvalidNonce};

pub const NonceGenResult = struct {
    secnonce: SecNonce,
    pubnonce: PubNonce,
};

/// BIP327 `NonceGen(sk, pk, aggpk, m, extra_in)`. `rand_prime` is the
/// spec's freshly-drawn-uniformly-at-random `rand'` — taken as an explicit
/// parameter (like `bip340.sign`'s `aux_rand`) so the whole algorithm is
/// deterministic and testable; a production caller draws it from a CSPRNG.
/// All five of `sk`/`aggpk`/`msg`/`extra_in` are optional per the spec
/// (`pk` is the only mandatory public-key argument — see the spec's
/// "Signing with Tweaked Individual Keys" remark on why `pk` must always be
/// given). `io` is threaded through for API symmetry with `bip340.sign`
/// (unused: deterministic once `rand_prime` is in hand).
pub fn nonceGen(
    sk: ?[32]u8,
    pk: [33]u8,
    aggpk: ?[32]u8,
    msg: ?[]const u8,
    extra_in: ?[]const u8,
    rand_prime: [32]u8,
    io: std.Io,
) NonceGenError!NonceGenResult {
    _ = io;

    // rand = rand' xor taggedHash(MuSig/aux, rand') if sk given, else rand'.
    var rand: [32]u8 = rand_prime;
    if (sk) |sk_bytes| {
        const aux_hash = bip340.taggedHash(aux_tag, &rand_prime);
        for (&rand, sk_bytes, aux_hash) |*r, s, a| r.* = s ^ a;
    }

    const aggpk_bytes: []const u8 = if (aggpk) |*a| a else &[_]u8{};

    var k: [2]Scalar = undefined;
    inline for (0..2) |i| {
        var hasher = bip340.hash.taggedHasher(nonce_tag);
        hasher.update(&rand);
        hasher.update(&[_]u8{@intCast(pk.len)});
        hasher.update(&pk);
        hasher.update(&[_]u8{@intCast(aggpk_bytes.len)});
        hasher.update(aggpk_bytes);
        if (msg) |m| {
            hasher.update(&[_]u8{1});
            var len_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &len_buf, m.len, .big);
            hasher.update(&len_buf);
            hasher.update(m);
        } else {
            hasher.update(&[_]u8{0});
        }
        const extra: []const u8 = extra_in orelse &[_]u8{};
        var extra_len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &extra_len_buf, @as(u32, @intCast(extra.len)), .big);
        hasher.update(&extra_len_buf);
        hasher.update(extra);
        hasher.update(&[_]u8{@intCast(i)});
        k[i] = reduceToScalar(hasher.finalResult());
    }
    if (k[0].isZero() or k[1].isZero()) return error.InvalidNonce;

    const r1 = Secp256k1.combMulBase(k[0].toBytes(.big), .big) catch return error.InvalidNonce;
    const r2 = Secp256k1.combMulBase(k[1].toBytes(.big), .big) catch return error.InvalidNonce;

    var pubnonce_bytes: [66]u8 = undefined;
    pubnonce_bytes[0..33].* = cbytes(r1);
    pubnonce_bytes[33..66].* = cbytes(r2);

    var secnonce_bytes: [97]u8 = undefined;
    secnonce_bytes[0..32].* = k[0].toBytes(.big);
    secnonce_bytes[32..64].* = k[1].toBytes(.big);
    secnonce_bytes[64..97].* = pk;

    return .{
        .secnonce = SecNonce.fromBytes(secnonce_bytes),
        .pubnonce = PubNonce.fromBytes(pubnonce_bytes) catch unreachable, // k*G is never infinity for k != 0
    };
}

// ── KeyAgg (BIP327 §"Key Aggregation") ─────────────────────────────────────
//
// `keyAgg` validates every individual pubkey up front (matching every
// "invalid pubkey" vector) before any aggregation arithmetic runs, so the
// blamed-signer error always wins over a later failure.

/// Internal Algorithm `HashKeys` (BIP327): `L = taggedHash("KeyAgg list",
/// pk_1 ‖ pk_2 ‖ ... ‖ pk_u)`. REAL.
fn hashKeys(pks: []const PlainPublicKey) [32]u8 {
    var hasher = bip340.hash.taggedHasher(list_tag);
    for (pks) |pk| hasher.update(&pk.bytes);
    return hasher.finalResult();
}

/// Internal Algorithm `GetSecondKey` (BIP327): the first `pk_j` (`j > 1`)
/// that differs from `pk_1`, or the all-zero 33-byte marker if every key
/// in the list is identical (in which case NO signer gets the
/// coefficient-1 shortcut — every `a_i` is computed via the hash formula,
/// since the marker can never equal a real parsed pubkey). REAL.
fn getSecondKey(pks: []const PlainPublicKey) [33]u8 {
    if (pks.len == 0) return [_]u8{0} ** 33;
    for (pks[1..]) |pk| {
        if (!std.mem.eql(u8, &pk.bytes, &pks[0].bytes)) return pk.bytes;
    }
    return [_]u8{0} ** 33;
}

/// Internal Algorithm `KeyAggCoeffInternal(pk_1..u, pk', pk2)` (BIP327),
/// with `L = HashKeys(pk_1..u)` precomputed by the caller: `a = 1` if
/// `pk' == pk2` (the "second key" coefficient-1 rule — compared BY VALUE,
/// exactly as the spec writes it; see `SPEC.md`'s threat model on why
/// by-index would reintroduce the rogue-key weakness), else `a =
/// int(taggedHash("KeyAgg coefficient", L ‖ pk')) mod n` (`reduceToScalar`
/// — the digest can exceed `n`, so it reduces rather than rejects).
fn keyAggCoeffInternal(l: [32]u8, pk_bytes: [33]u8, pk2: [33]u8) Scalar {
    if (std.mem.eql(u8, &pk_bytes, &pk2)) return Scalar.one;
    var hasher = bip340.hash.taggedHasher(coefficient_tag);
    hasher.update(&l);
    hasher.update(&pk_bytes);
    return reduceToScalar(hasher.finalResult());
}

/// Internal Algorithm `KeyAggCoeff(pk_1..u, pk')` (BIP327): recomputes
/// `L`/`pk2` from the list and defers to `keyAggCoeffInternal`. The spec's
/// "fail if `pk'` is not in `pk_1..u`" precondition is the CALLER's job
/// (`sign`/`partialSigVerifyInternal` both check membership via
/// `findPubkeyIndex` before calling this; `keyAgg` only ever passes keys
/// drawn from the list itself).
fn keyAggCoeff(pks: []const PlainPublicKey, pk_bytes: [33]u8) Scalar {
    return keyAggCoeffInternal(hashKeys(pks), pk_bytes, getSecondKey(pks));
}

pub const KeyAggError = error{ InvalidPublicKey, PointAtInfinity };

pub const ApplyTweakError = error{
    /// `t = int(tweak) >= n` (BIP327 `ApplyTweak`: "Fail if t >= n") —
    /// key_agg_vectors.json "Tweak is out of range" / tweak_vectors.json
    /// "Tweak is invalid because it exceeds group size".
    TweakOutOfRange,
    /// `Q' = g·Q + t·G` is the point at infinity (BIP327 `ApplyTweak`:
    /// "Fail if is_infinite(Q')") — key_agg_vectors.json "Intermediate
    /// tweaking result is point at infinity".
    TweakedKeyIsInfinite,
};

/// One BIP327 tweak: the 32-byte tweak value plus its mode. A PLAIN tweak
/// (`is_xonly = false`, BIP32-style: the tweaked key stays a full 33-byte
/// plain key) adds `t·G` to `Q` as-is; an X-ONLY tweak (`is_xonly = true`,
/// Taproot/BIP341-style: the tweak is applied to the even-y x-only form of
/// `Q`) first negates `Q` if it has odd y. Carried by `SessionContext.
/// tweaks` (tweak + flag as ONE value, so the two lists BIP327 passes in
/// parallel — `tweak_1..v` and `is_xonly_t_1..v` — can never disagree in
/// length).
pub const Tweak = struct {
    tweak: [32]u8,
    is_xonly: bool,
};

/// The KeyAgg Context (BIP327 §"KeyAgg Context"): the (possibly tweaked)
/// aggregate point `Q`, plus the accumulated tweak bookkeeping `gacc`/
/// `tacc` that lets a signer recover the right secret-key sign flip (see
/// `SPEC.md`'s threat model). `keyAgg` produces the untweaked base context
/// (`gacc = 1`, `tacc = 0`); `applyTweak` absorbs tweaks one at a time,
/// updating all three fields.
pub const KeyAggContext = struct {
    q: Secp256k1,
    gacc: Scalar,
    tacc: Scalar,

    /// Algorithm `GetXonlyPubkey`: `xbytes(Q)`.
    pub fn getXonlyPubkey(ctx: KeyAggContext) [32]u8 {
        return ctx.q.affineCoordinates().x.toBytes(.big);
    }

    /// Algorithm `GetPlainPubkey`: `cbytes(Q)`.
    pub fn getPlainPubkey(ctx: KeyAggContext) [33]u8 {
        return cbytes(ctx.q);
    }

    /// Algorithm `ApplyTweak(keyagg_ctx, tweak, is_xonly_t)` (BIP327
    /// §"Applying Tweaks"):
    ///
    ///   1. `g = 1` for a plain tweak; for an x-only tweak, `g = 1` if
    ///      `has_even_y(Q)` else `n - 1` (`gFromQ` — the SAME single-source
    ///      helper `sign`/`partialSigVerifyInternal`/`partialSigAgg` use,
    ///      so the tweak-time flip and the sign/verify-time flips can never
    ///      disagree; see `SPEC.md`'s threat model).
    ///   2. `t = int(tweak)`; fail (`error.TweakOutOfRange`) if `t >= n`.
    ///   3. `Q' = g·Q + t·G`; fail (`error.TweakedKeyIsInfinite`) if `Q'`
    ///      is the point at infinity (the tweak cancelled the key exactly
    ///      — e.g. `t` maliciously chosen as the negation of the aggregate
    ///      key's discrete log; refusing it fails closed).
    ///   4. `gacc' = g·gacc mod n`, `tacc' = (t + g·tacc) mod n` — the
    ///      accumulators that make multiple tweaks COMPOSE: `sign`'s
    ///      `d = g·gacc·d'` and `partialSigAgg`'s `s = Σs_i + e·g·tacc`
    ///      then absorb the whole tweak chain in one multiply/add each.
    ///
    /// Multiple tweaks compose by applying this repeatedly, in sequence
    /// (`getSessionValues` does exactly that over `SessionContext.tweaks`).
    /// Every operand here is PUBLIC (the aggregate key and the tweak), so
    /// the variable-time `mulPublic` and the `hasEvenY` branch are fine —
    /// same rationale as `keyAgg` itself.
    pub fn applyTweak(ctx: KeyAggContext, tweak: [32]u8, is_xonly: bool) ApplyTweakError!KeyAggContext {
        const g: Scalar = if (is_xonly) gFromQ(ctx.q) else Scalar.one;
        const t = Scalar.fromBytes(tweak, .big) catch return error.TweakOutOfRange;

        // Q' = g·Q + t·G. `g` is ±1 and `Q` is never the identity in a
        // constructed context, so `g·Q` cannot be the identity; `t·G` is
        // the identity only for `t == 0` (a legal tweak value), in which
        // case it contributes nothing — both `mulPublic` identity-result
        // errors are therefore total, not failures.
        var q_prime = ctx.q.mulPublic(g.toBytes(.big), .big) catch Secp256k1.identityElement;
        if (Secp256k1.basePoint.mulPublic(t.toBytes(.big), .big)) |tg| {
            q_prime = q_prime.add(tg);
        } else |_| {}
        q_prime.rejectIdentity() catch return error.TweakedKeyIsInfinite;

        return .{
            .q = q_prime,
            .gacc = g.mul(ctx.gacc),
            .tacc = t.add(g.mul(ctx.tacc)),
        };
    }
};

/// Returns the index of the first pubkey in `pks` that fails `cpoint`, or
/// `null` if every pubkey is valid. A convenience wrapper so callers (and
/// this module's own KAT tests) can identify which signer to blame,
/// matching BIP327's "blame signer i for invalid individual public key"
/// language — kept separate from `keyAgg` itself to keep that function's
/// control flow simple.
pub fn findInvalidPubkey(pks: []const PlainPublicKey) ?usize {
    for (pks, 0..) |pk, i| {
        _ = pk.point() catch return i;
    }
    return null;
}

/// Algorithm `KeyAgg(pk_1..u)` (BIP327 §"Key Aggregation").
///
/// Real up front: fails (`error.InvalidPublicKey`) on the first pubkey
/// that does not parse (`PlainPublicKey.point`/`cpoint`) — every official
/// key_agg_vectors.json `error_test_cases` entry with `contrib = "pubkey"`
/// is caught here, for real, before the code below ever runs.
///
/// The crypto core (only reached once every `pks[i]` is individually
/// valid): `pk2 = GetSecondKey`, `L = HashKeys`, `a_i =
/// KeyAggCoeffInternal(L, pk_i, pk2)`, `Q = Σ a_i·P_i`. Each `a_i`/`P_i`
/// is PUBLIC, so the per-term multiply is the variable-time `mulPublic`
/// (per `bip340.verify`'s own precedent), accumulated with the complete
/// `Secp256k1.add`. Fails with `error.PointAtInfinity` if `Q` is the point
/// at infinity (BIP327: "Fail if is_infinite(Q)") — the scheme's defense
/// against a rogue-key point-cancellation attack (see `SPEC.md`). The
/// result is the UNTWEAKED base context (`gacc = 1`, `tacc = 0`); apply
/// tweaks via `KeyAggContext.applyTweak`.
pub fn keyAgg(pks: []const PlainPublicKey) KeyAggError!KeyAggContext {
    if (pks.len == 0) return error.InvalidPublicKey; // BIP327 requires 0 < u
    for (pks) |pk| _ = pk.point() catch return error.InvalidPublicKey;

    const pk2 = getSecondKey(pks);
    const l = hashKeys(pks);
    var q = Secp256k1.identityElement;
    for (pks) |pk| {
        const p = pk.point() catch unreachable; // validated by the loop above
        const a = keyAggCoeffInternal(l, pk.bytes, pk2);
        // `mulPublic` reports an identity RESULT as an error; `P_i` is a
        // real curve point, so that can only mean `a_i == 0 mod n`
        // (probability ~2^-256 for a hash-derived coefficient) — an
        // identity term contributes nothing to the sum, exactly like
        // `bip340.verifyBatch`'s identical `catch continue`.
        const term = p.mulPublic(a.toBytes(.big), .big) catch continue;
        q = q.add(term);
    }
    q.rejectIdentity() catch return error.PointAtInfinity;
    return .{ .q = q, .gacc = Scalar.one, .tacc = Scalar.zero };
}

// ── NonceAgg (BIP327 §"Nonce Aggregation") ─────────────────────────────────

pub const NonceAggError = error{InvalidPubNonce};

/// Algorithm `NonceAgg(pubnonce_1..u)` (BIP327 §"Nonce Aggregation").
///
/// Real up front: fails (`error.InvalidPubNonce`) on the first pubnonce
/// that does not parse (`PubNonce.points`/`cpoint`) — every official
/// nonce_agg_vectors.json `error_test_cases` entry is caught here, for
/// real, before the code below ever runs.
///
/// The crypto core (only reached once every `pubnonces[i]` is
/// individually valid): for `j = 1, 2`: `R_j = R_{1,j} + ... + R_{u,j}`
/// (plain complete point addition — PUBLIC points, no timing concern),
/// then `aggnonce = cbytes_ext(R_1) ‖ cbytes_ext(R_2)`. An aggregate
/// nonce, UNLIKE an individual `PubNonce`, legitimately CAN be the point
/// at infinity (encoded as 33 zero bytes) — see "Dealing with Infinity in
/// Nonce Aggregation" in `SPEC.md`'s threat model — so a cancelled sum is
/// NOT rejected here.
pub fn nonceAgg(pubnonces: []const PubNonce) NonceAggError!AggNonce {
    if (pubnonces.len == 0) return error.InvalidPubNonce; // BIP327 requires 0 < u
    var sums = [_]Secp256k1{ Secp256k1.identityElement, Secp256k1.identityElement };
    for (pubnonces) |pn| {
        const pts = pn.points() catch return error.InvalidPubNonce;
        sums[0] = sums[0].add(pts.r1);
        sums[1] = sums[1].add(pts.r2);
    }
    var bytes: [66]u8 = undefined;
    for (sums, 0..) |sum, j| {
        const maybe: ?Secp256k1 = if (sum.rejectIdentity()) sum else |_| null;
        bytes[j * 33 ..][0..33].* = cbytesExt(maybe);
    }
    return AggNonce.fromBytes(bytes) catch unreachable; // built from cbytesExt of real sums
}

/// Returns the index of the first pubnonce in `pubnonces` that fails to
/// parse, or `null` if every pubnonce is valid (see `findInvalidPubkey`'s
/// rationale — the same convenience, for `NonceAgg`'s blame target).
pub fn findInvalidPubNonce(pubnonces: []const PubNonce) ?usize {
    for (pubnonces, 0..) |pn, i| {
        _ = pn.points() catch return i;
    }
    return null;
}

// ── Session Context (BIP327 §"Session Context") ───────────────────────────

/// The Session Context (BIP327 §"Session Context"). The spec's parallel
/// tweak lists (`tweak_1..v`, `is_xonly_t_1..v`) are carried as ONE slice
/// of `Tweak` values (tweak + mode can never disagree in length), applied
/// in order by `getSessionValues`'s `ApplyTweak` loop. Defaults to no
/// tweaks — an untweaked session is written exactly as before.
pub const SessionContext = struct {
    aggnonce: AggNonce,
    pubkeys: []const PlainPublicKey,
    tweaks: []const Tweak = &.{},
    msg: []const u8,
};

/// The six values `GetSessionValues` computes (BIP327 §"Session Context").
pub const SessionValues = struct {
    q: Secp256k1,
    gacc: Scalar,
    tacc: Scalar,
    b: Scalar,
    r: Secp256k1,
    e: Scalar,
};

/// `AggNonceError` is included so `getSessionValues` never has to panic
/// even on a hand-constructed (never-`fromBytes`-validated) `SessionContext
/// .aggnonce` — a `fromBytes`-built one can never trip it. `ApplyTweakError`
/// covers the tweak loop (an out-of-range tweak / a tweaked key at
/// infinity is a session-level failure, per BIP327's `GetSessionValues`
/// calling `ApplyTweak` itself).
pub const SessionError = KeyAggError || AggNonceError || ApplyTweakError;

/// Algorithm `GetSessionValues(session_ctx)` (BIP327 §"Session Context").
///
/// Real up front: `ctx.aggnonce` is already a validated `AggNonce` (its
/// `cpoint_ext` checks ran at `AggNonce.fromBytes` construction time — the
/// three official "Aggregate nonce is invalid" sign-error vectors are
/// caught there, before a `SessionContext` can even be built). `keyAgg
/// (ctx.pubkeys)` runs its own real per-pubkey check next (catching every
/// "invalid pubkey" vector) — only once THAT succeeds does this function
/// reach the code below.
///
/// The crypto core:
///   0. `keyagg_ctx_0 = keyAgg(pk_1..u)`, then `keyagg_ctx_i =
///      ApplyTweak(keyagg_ctx_{i-1}, tweak_i, is_xonly_t_i)` for each of
///      `ctx.tweaks` in order — `Q`/`gacc`/`tacc` below are the FINAL
///      (tweaked) context's values; with no tweaks they are directly
///      `keyAgg`'s output, exactly as before.
///   1. `b = int(taggedHash("MuSig/noncecoef", aggnonce_bytes ‖ xbytes(Q) ‖
///      m)) mod n`.
///   2. `R' = R1 + b·R2` — either or both of `R1`/`R2` may be the point at
///      infinity per `AggNonce`'s doc comment; infinity is the identity
///      element in the sum.
///   3. If `R'` is infinite: `R = G` (BIP327's fixed substitution — see
///      `SPEC.md`'s "Dealing with Infinity in Nonce Aggregation": the
///      protocol keeps signing so the dishonest signer is surfaced by the
///      subsequent partial-signature verification, instead of deadlocking).
///   4. `e = int(taggedHash("BIP0340/challenge", xbytes(R) ‖ xbytes(Q) ‖
///      m)) mod n` — literally BIP340's own challenge tag
///      (`bip340.hash.challenge_tag`): the final aggregate signature must
///      be BIP340-challenge-compatible by design.
pub fn getSessionValues(ctx: SessionContext) SessionError!SessionValues {
    var keyagg_ctx = try keyAgg(ctx.pubkeys);
    for (ctx.tweaks) |tw| keyagg_ctx = try keyagg_ctx.applyTweak(tw.tweak, tw.is_xonly);
    const qx = keyagg_ctx.getXonlyPubkey();

    var b_hasher = bip340.hash.taggedHasher(noncecoef_tag);
    b_hasher.update(&ctx.aggnonce.bytes);
    b_hasher.update(&qx);
    b_hasher.update(ctx.msg);
    const b = reduceToScalar(b_hasher.finalResult());

    const pts = ctx.aggnonce.points() catch return error.InvalidAggNonce;
    var r_prime = Secp256k1.identityElement;
    if (pts.r1) |r1| r_prime = r_prime.add(r1);
    if (pts.r2) |r2| {
        // `mulPublic` reports an identity RESULT as an error — here only
        // possible if `b == 0 mod n` (probability ~2^-256), in which case
        // `b·R2` is the identity and contributes nothing.
        if (r2.mulPublic(b.toBytes(.big), .big)) |br2| {
            r_prime = r_prime.add(br2);
        } else |_| {}
    }
    const r: Secp256k1 = if (r_prime.rejectIdentity()) r_prime else |_| Secp256k1.basePoint;

    const rx = r.affineCoordinates().x.toBytes(.big);
    var e_hasher = bip340.hash.taggedHasher(bip340.hash.challenge_tag);
    e_hasher.update(&rx);
    e_hasher.update(&qx);
    e_hasher.update(ctx.msg);
    const e = reduceToScalar(e_hasher.finalResult());

    return .{
        .q = keyagg_ctx.q,
        .gacc = keyagg_ctx.gacc,
        .tacc = keyagg_ctx.tacc,
        .b = b,
        .r = r,
        .e = e,
    };
}

/// Returns the index of `pubkeys` whose bytes equal `target`, or `null`.
/// BIP327's `GetSessionKeyAggCoeff`/`Sign` both need "is this pubkey in the
/// session's pubkey list" — REAL, pure byte comparison.
pub fn findPubkeyIndex(pubkeys: []const PlainPublicKey, target: [33]u8) ?usize {
    for (pubkeys, 0..) |pk, i| {
        if (std.mem.eql(u8, &pk.bytes, &target)) return i;
    }
    return null;
}

// ── PartialSignature (32-byte scalar) ──────────────────────────────────────

pub const PartialSignatureError = error{InvalidPartialSignature};

/// A partial signature: 32 bytes, a scalar `s_i` (or, for `PartialSigAgg`'s
/// inputs, `s_i` from each contributing signer). REAL: the range check
/// (`s < n`) BIP327 requires everywhere a partial signature is consumed.
pub const PartialSignature = struct {
    bytes: [32]u8,

    pub const encoded_length = 32;

    /// `s = int(psig)`; fails if `s >= n` (sign_verify_vectors.json's
    /// "Signature exceeds group size" verify-fail case; sig_agg_vectors
    /// .json's "Partial signature is invalid because it exceeds group
    /// size" error case).
    pub fn fromBytes(bytes: [32]u8) PartialSignatureError!PartialSignature {
        _ = Scalar.fromBytes(bytes, .big) catch return error.InvalidPartialSignature;
        return .{ .bytes = bytes };
    }

    pub fn toScalar(ps: PartialSignature) Scalar {
        return Scalar.fromBytes(ps.bytes, .big) catch unreachable; // canonical, checked at fromBytes
    }
};

// ── Sign (BIP327 §"Signing") ───────────────────────────────────────────────

pub const SignError = SessionError || SecNonceError || error{
    /// `pk != secnonce[64:97]` — the signer's derived public key does not
    /// match the key `NonceGen` was called with (BIP327's "Signing with
    /// Tweaked Individual Keys" defense — see `SPEC.md`).
    SecretKeyMismatch,
    /// `GetSessionKeyAggCoeff` — the signer's own pubkey is not in the
    /// session's pubkey list (sign_verify_vectors.json's "signer's pubkey
    /// must be included" case — the spec marks this check optional, but
    /// this module performs it).
    PubkeyNotInSession,
    /// The MANDATORY self-verification (BIP327 `Sign`'s final
    /// `PartialSigVerifyInternal` step) failed — never returned by a
    /// correct implementation on correct hardware; exists to fail CLOSED
    /// under fault injection / silent corruption rather than emit a
    /// partial signature that could leak information about the secret key
    /// (same philosophy as `bip340.sign`'s step-10 self-check).
    SignatureVerificationFailed,
};

/// Algorithm `Sign(secnonce, sk, session_ctx)` (BIP327 §"Signing").
///
/// Input checks, in order (each can fail BEFORE `getSessionValues`/
/// `keyAgg` are ever called — this ordering is why every official
/// `sign_error_test_cases` vector reports exactly the blamed failure):
///   1. `secnonce.k1Scalar()`/`k2Scalar()` — range-checks `k1'`/`k2'`
///      (catches "Secnonce is invalid" / nonce-reuse-shaped vectors).
///   2. `d' = int(sk)` (`bip340.SecretKey`, already range-checked),
///      `P = d'·G`, `pk = cbytes(P)`; fails `error.SecretKeyMismatch` if
///      `pk != secnonce.pubkeyBytes()`.
///   3. `findPubkeyIndex(ctx.pubkeys, pk)`; fails `error.PubkeyNotInSession`
///      if absent (catches "signer's pubkey not in the list of pubkeys").
///   4. `getSessionValues(ctx)` — per-pubkey/per-aggnonce checks (catches
///      "Signer N provided an invalid public key"; the three "Aggregate
///      nonce is invalid" vectors are caught even earlier, at
///      `AggNonce.fromBytes` construction time).
///
/// The crypto core, only reached once ALL of the above succeed (every
/// input genuinely valid):
///   1. `k1, k2 = k1', k2'` if `has_even_y(R)` (from `sv.r`), else `k1, k2
///      = n - k1', n - k2'` — a CONSTANT-TIME masked select on the parity
///      bit (mirroring `bip340.sign`'s step-7 technique: never branch on
///      `R.y`'s parity directly, since which nonce got negated is exactly
///      the kind of bit a side channel could turn into a nonce-reuse leak).
///   2. `a = KeyAggCoeff(ctx.pubkeys, pk)` (recomputed per BIP327's
///      `GetSessionKeyAggCoeff`, not cached from the `keyAgg` call inside
///      `getSessionValues`).
///   3. `g = 1` if `has_even_y(sv.q)`, else `g = -1 mod n` (`gFromQ` — the
///      SAME helper `partialSigVerifyInternal`/`partialSigAgg` use, so
///      signer and verifier can never disagree on the flip).
///   4. `d = g · sv.gacc · d' mod n` — **the security-critical negation**
///      (BIP327 "Negation Of The Secret Key When Signing" — see `SPEC.md`'s
///      threat model). `d'` is SECRET; `Scalar.mul` is constant-time.
///   5. `s = (k1 + b·k2 + e·a·d) mod n`.
///   6. `pubnonce = cbytes(k1'·G) ‖ cbytes(k2'·G)` (recomputed from the
///      UNNEGATED `k1'`/`k2'` — the signer's own original pubnonce).
///   7. MANDATORY self-check (spec: "prevents publishing invalid
///      signatures which may leak information about the secret key"):
///      `partialSigVerifyInternal(s, pubnonce, pk, ctx)` must accept;
///      `error.SignatureVerificationFailed` otherwise, never the
///      unverified `s`.
pub fn sign(secnonce: SecNonce, sk: bip340.SecretKey, ctx: SessionContext) SignError!PartialSignature {
    // Local copy zeroed on every exit path (defense-in-depth — see
    // `SecNonce`'s doc comment; the caller's own copy is its own to erase).
    var sn = secnonce;
    defer sn.deinit();

    const k1_prime = try sn.k1Scalar();
    const k2_prime = try sn.k2Scalar();

    const p_point = Secp256k1.combMulBase(sk.bytes, .big) catch return error.SecretKeyMismatch;
    const pk_bytes = cbytes(p_point);
    if (!std.mem.eql(u8, &pk_bytes, &sn.pubkeyBytes())) return error.SecretKeyMismatch;
    if (findPubkeyIndex(ctx.pubkeys, pk_bytes) == null) return error.PubkeyNotInSession;

    const sv = try getSessionValues(ctx);

    // Step 1: constant-time masked parity select over both nonce scalars.
    const mask: u8 = @as(u8, 0) -% @intFromBool(sv.r.affineCoordinates().y.isOdd());
    var k: [2]Scalar = undefined;
    inline for (.{ k1_prime, k2_prime }, 0..) |k_prime, i| {
        const even = k_prime.toBytes(.big);
        const odd = k_prime.neg().toBytes(.big);
        var sel: [32]u8 = undefined;
        for (&sel, even, odd) |*si, ke, ko| si.* = (ke & ~mask) | (ko & mask);
        k[i] = Scalar.fromBytes(sel, .big) catch unreachable; // both candidates canonical
    }

    // Steps 2-4: coefficient, aggregate-key parity factor, effective secret.
    const a = keyAggCoeff(ctx.pubkeys, pk_bytes);
    const g = gFromQ(sv.q);
    const d_prime = Scalar.fromBytes(sk.bytes, .big) catch return error.SecretKeyMismatch; // canonical per SecretKey.fromBytes
    const d = g.mul(sv.gacc).mul(d_prime);

    // Step 5: s = k1 + b·k2 + e·a·d (all mod n, constant-time scalar ops).
    const s = k[0].add(sv.b.mul(k[1])).add(sv.e.mul(a).mul(d));
    const psig = PartialSignature{ .bytes = s.toBytes(.big) };

    // Steps 6-7: rebuild the signer's own pubnonce from the UNNEGATED
    // k1'/k2' and run the mandatory self-verification.
    const r1 = Secp256k1.combMulBase(k1_prime.toBytes(.big), .big) catch return error.InvalidSecNonce;
    const r2 = Secp256k1.combMulBase(k2_prime.toBytes(.big), .big) catch return error.InvalidSecNonce;
    var pubnonce_bytes: [66]u8 = undefined;
    pubnonce_bytes[0..33].* = cbytes(r1);
    pubnonce_bytes[33..66].* = cbytes(r2);
    const pubnonce = PubNonce{ .bytes = pubnonce_bytes };
    partialSigVerifyInternal(psig, pubnonce, .{ .bytes = pk_bytes }, ctx) catch return error.SignatureVerificationFailed;

    return psig;
}

// ── PartialSigVerify (BIP327 §"Partial Signature Verification") ───────────

pub const PartialSigVerifyError = SessionError || NonceAggError || PartialSignatureError;

/// Algorithm `PartialSigVerify(psig, pubnonce_1..u, pk_1..u, tweak_1..v,
/// is_xonly_t_1..v, m, i)` (BIP327 §"Partial Signature Verification") —
/// the top-level entry point, which (per the spec) computes its own
/// aggregate nonce first. `tweaks` must be the SAME tweak sequence the
/// signer's `SessionContext` carried (pass `&.{}` for an untweaked
/// session).
///
/// `psig` is already range-checked (`PartialSignature.fromBytes`, the
/// caller's job before this call). `nonceAgg(pubnonces)` validates every
/// pubnonce (catches "Invalid pubnonce" vectors);
/// `pubkeys[signer_index].point()` validates the signer's own key (catches
/// "Invalid pubkey" vectors) independently of `nonceAgg` — matching both
/// official `verify_error_test_cases`.
pub fn partialSigVerify(
    psig: PartialSignature,
    pubnonces: []const PubNonce,
    pubkeys: []const PlainPublicKey,
    tweaks: []const Tweak,
    msg: []const u8,
    signer_index: usize,
) PartialSigVerifyError!void {
    _ = pubkeys[signer_index].point() catch return error.InvalidPublicKey;
    const aggnonce = try nonceAgg(pubnonces);
    const ctx = SessionContext{ .aggnonce = aggnonce, .pubkeys = pubkeys, .tweaks = tweaks, .msg = msg };
    return partialSigVerifyInternal(psig, pubnonces[signer_index], pubkeys[signer_index], ctx);
}

/// Internal Algorithm `PartialSigVerifyInternal` (BIP327). The crypto core
/// (only reached once `getSessionValues` succeeds, i.e. every pubkey in
/// `ctx.pubkeys` is individually valid):
///   1. `Re*' = R*,1 + b·R*,2`.
///   2. `Re* = Re*'` if `has_even_y(sv.r)`, else `Re* = -Re*'`.
///   3. `a = GetSessionKeyAggCoeff(ctx, P)` where `P = cpoint(pk)`.
///   4. `g = 1` if `has_even_y(sv.q)` else `g = -1 mod n` (`gFromQ`, the
///      SAME helper `sign` uses); `g' = g · sv.gacc mod n` — the
///      verify-side analogue of `sign`'s secret-key negation ("Negation Of
///      The Individual Public Key When Partially Verifying", see
///      `SPEC.md`'s threat model: these two computations MUST agree).
///   5. Fail (`error.InvalidPartialSignature`) unless `s·G == Re* +
///      e·a·g'·P` — a PUBLIC equation check (all operands known to the
///      verifier), so variable-time `mulPublic` per `bip340.verify`'s
///      precedent. Never panics: every failure path is an error return.
fn partialSigVerifyInternal(psig: PartialSignature, pubnonce: PubNonce, pk: PlainPublicKey, ctx: SessionContext) PartialSigVerifyError!void {
    const sv = try getSessionValues(ctx);
    const s = Scalar.fromBytes(psig.bytes, .big) catch return error.InvalidPartialSignature;

    // Steps 1-2: Re*' = R*,1 + b·R*,2, negated if the session's final R
    // needed negating to become even-y.
    const pts = pubnonce.points() catch return error.InvalidPubNonce;
    var re = pts.r1;
    // `mulPublic` reports an identity RESULT as an error — only possible
    // here if `b == 0 mod n` (probability ~2^-256); an identity term
    // contributes nothing to the sum.
    if (pts.r2.mulPublic(sv.b.toBytes(.big), .big)) |br2| {
        re = re.add(br2);
    } else |_| {}
    if (!hasEvenY(sv.r)) re = re.neg();

    // Steps 3-4: coefficient + verify-side parity factor.
    if (findPubkeyIndex(ctx.pubkeys, pk.bytes) == null) return error.InvalidPublicKey;
    const p = pk.point() catch return error.InvalidPublicKey;
    const a = keyAggCoeff(ctx.pubkeys, pk.bytes);
    const g_prime = gFromQ(sv.q).mul(sv.gacc);

    // Step 5: s·G == Re* + (e·a·g')·P. Either side may legitimately be
    // the identity (e.g. s == 0, or a fully-cancelled Re* + coefficient
    // term) — `catch identityElement` keeps the comparison total, and the
    // complete `add`/`equivalent` handle identity operands.
    const lhs = Secp256k1.basePoint.mulPublic(s.toBytes(.big), .big) catch Secp256k1.identityElement;
    const rhs_term = p.mulPublic(sv.e.mul(a).mul(g_prime).toBytes(.big), .big) catch Secp256k1.identityElement;
    const rhs = re.add(rhs_term);
    if (!lhs.equivalent(rhs)) return error.InvalidPartialSignature;
}

// ── PartialSigAgg (BIP327 §"Partial Signature Aggregation") ───────────────

pub const PartialSigAggError = SessionError || PartialSignatureError;

/// Algorithm `PartialSigAgg(psig_1..u, session_ctx)` (BIP327 §"Partial
/// Signature Aggregation").
///
/// Real up front, per the spec's own algorithm (its step "let s_i =
/// int(psig_i); fail if s_i >= n and blame signer i" is genuinely part of
/// `PartialSigAgg`, not a caller-side pre-check — unlike `PlainPublicKey`/
/// `PubNonce`, which callers are expected to construct via `fromBytes`,
/// `PartialSigAgg` re-validates every `psigs[i]` itself so it is safe even
/// on hand-built values): each `psigs[i]` is re-checked (`s_i >= n` —
/// sig_agg_vectors.json's "Partial signature is invalid because it
/// exceeds group size" case is caught here, for real). `getSessionValues
/// (ctx)` then validates every pubkey (catches any "invalid pubkey"
/// vector).
///
/// The crypto core, only reached once every `psigs[i]` is individually
/// valid AND `getSessionValues` succeeds:
///   1. `g = 1` if `has_even_y(sv.q)`, else `g = -1 mod n` (`gFromQ`).
///   2. `s = (s_1 + s_2 + ... + s_u + e·g·tacc) mod n` — this is the one
///      place the accumulated tweak offset `tacc` re-enters the
///      computation: the partial signatures each cover the signers' (sign-
///      corrected) secret keys, and the single `e·g·tacc` term accounts
///      for the entire tweak chain's shift of the aggregate key at once
///      (`Scalar.zero`, contributing nothing, for an untweaked session).
///   3. `sig = xbytes(sv.r) ‖ bytes(32, s)` — a plain 64-byte
///      `bip340.Signature`, verifiable by `bip340.verify` with NO
///      knowledge that it was produced by MuSig2 (the scheme's headline
///      property, asserted end-to-end in `kat_test.zig`).
pub fn partialSigAgg(psigs: []const PartialSignature, ctx: SessionContext) PartialSigAggError![64]u8 {
    if (psigs.len == 0) return error.InvalidPartialSignature;
    for (psigs) |ps| _ = Scalar.fromBytes(ps.bytes, .big) catch return error.InvalidPartialSignature;
    const sv = try getSessionValues(ctx);

    var s = sv.e.mul(gFromQ(sv.q)).mul(sv.tacc);
    for (psigs) |ps| s = s.add(ps.toScalar());

    var sig: [64]u8 = undefined;
    sig[0..32].* = sv.r.affineCoordinates().x.toBytes(.big);
    sig[32..64].* = s.toBytes(.big);
    return sig;
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.model_after names BIP327 and the sibling bip340 dep" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BIP327") != null);
    try std.testing.expectEqualStrings("bip340", meta.deps[0]);
}

test "encoded_length constants match BIP327's wire sizes" {
    try std.testing.expectEqual(@as(usize, 33), PlainPublicKey.encoded_length);
    try std.testing.expectEqual(@as(usize, 66), PubNonce.encoded_length);
    try std.testing.expectEqual(@as(usize, 66), AggNonce.encoded_length);
    try std.testing.expectEqual(@as(usize, 97), SecNonce.encoded_length);
    try std.testing.expectEqual(@as(usize, 32), PartialSignature.encoded_length);
}

test "SecNonce.deinit zeroes all 97 secret bytes" {
    var sn = SecNonce.fromBytes([_]u8{0xAB} ** 97);
    sn.deinit();
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 97), &sn.bytes);
    // Idempotent.
    sn.deinit();
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 97), &sn.bytes);
}

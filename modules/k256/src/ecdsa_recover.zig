// SPDX-License-Identifier: MIT
//! Recoverable ECDSA/secp256k1 — deterministic (RFC 6979 §3.2) signing plus
//! standard public-key recovery, the two ECDSA operations `sign.zig`
//! deliberately left out (it ships `bip340Sign`/`bip340Verify` (Schnorr) and
//! `ecdsaVerify`, but no ECDSA **sign** and no public **key recovery** — see
//! its own doc comment: "a verification harness surface, not the module's
//! reason to exist"). This file grows that surface with the two pieces
//! several consumers need without duplicating them: Lightning's BOLT#11
//! invoice signature is exactly a *recoverable* compact ECDSA signature
//! (`r || s || recid`), letting a reader recover the payee's node ID
//! straight from the signature when no explicit signer field is present.
//! Originally implemented inside `lninvoice` (the only consumer at the
//! time); moved here once it became clear the functionality is general
//! secp256k1 machinery, not anything BOLT#11-specific.
//!
//!   * `sign` — RFC 6979 §3.2 deterministic-nonce ECDSA (HMAC-SHA256 DRBG).
//!     BOLT#11's own worked examples are generated this way ("Signatures
//!     are deterministic and generated using RFC6979 (using HMAC-SHA256)"),
//!     which is what lets `lninvoice`'s `bolt11.zig` round-trip test
//!     re-derive an official vector's signature byte-for-byte from its
//!     private key — the strongest form of "the encoder is correct" that
//!     consumer has.
//!   * `recoverPubkey` — standard ECDSA public-key recovery,
//!     `Q = r⁻¹·(s·R − e·G)`, `R` lifted from `r` + the recovery id's parity
//!     bit via `Secp256k1.recoverY`. This is the module's actual security
//!     core: it recovers the right key from a genuine signature, and
//!     recovers a WRONG (or non-recoverable) key from a tampered one.
//!
//! Both curve and hash are secp256k1/SHA-256 throughout, so RFC 6979's
//! `bits2octets` needs no bit-shifting (hash length == group-order byte
//! length == 32); the DRBG below is specialized to that case rather than
//! implemented generically.

const std = @import("std");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");
const fieldmod = @import("field.zig");
const sign_mod = @import("sign.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Secp256k1 = group.Secp256k1;
const Fe = fieldmod.Fe;
const Scalar = scalarmod.Scalar;

/// `int(bytes32) mod n` — the standard ECDSA/RFC6979 hash-to-scalar
/// reduction (a 32-byte hash can exceed the group order `n`, so a plain
/// `Scalar.fromBytes` would wrongly reject the rare oversized hash).
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide: [48]u8 = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

// ── RFC 6979 §3.2 deterministic nonce (HMAC-SHA256 DRBG) ────────────────

fn rfc6979Nonce(privkey: [32]u8, hash32: [32]u8) Scalar {
    // bits2octets(H(m)): for this curve/hash pairing (hash length == order
    // byte length) this is exactly `H(m) mod n`, re-encoded big-endian.
    const h1 = reduceToScalar(hash32).toBytes(.big);

    var v: [32]u8 = [_]u8{0x01} ** 32;
    var k: [32]u8 = [_]u8{0x00} ** 32;

    var buf: [32 + 1 + 32 + 32]u8 = undefined;
    buf[0..32].* = v;
    buf[32] = 0x00;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    HmacSha256.create(&k, &buf, &k);
    HmacSha256.create(&v, &v, &k);

    buf[0..32].* = v;
    buf[32] = 0x01;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    HmacSha256.create(&k, &buf, &k);
    HmacSha256.create(&v, &v, &k);

    while (true) {
        HmacSha256.create(&v, &v, &k);
        if (Scalar.fromBytes(v, .big)) |cand| {
            if (!cand.isZero()) return cand;
        } else |_| {}
        var buf2: [32 + 1]u8 = undefined;
        buf2[0..32].* = v;
        buf2[32] = 0x00;
        HmacSha256.create(&k, &buf2, &k);
        HmacSha256.create(&v, &v, &k);
    }
}

// ── sign ─────────────────────────────────────────────────────────────────

pub const SignError = error{ InvalidPrivateKey, InvalidNonce };

pub const Signature = struct { r: [32]u8, s: [32]u8, recid: u2 };

/// RFC 6979 deterministic ECDSA sign over secp256k1/SHA-256, returning a
/// compact recoverable signature. `hash32` is the message hash the caller
/// already computed (e.g. BOLT#11: `SHA256(hrp || data-without-signature)`).
pub fn sign(privkey: [32]u8, hash32: [32]u8) SignError!Signature {
    const d = Scalar.fromBytes(privkey, .big) catch return error.InvalidPrivateKey;
    if (d.isZero()) return error.InvalidPrivateKey;
    const e = reduceToScalar(hash32);

    const k = rfc6979Nonce(privkey, hash32);
    const R = Secp256k1.combMulBase(k.toBytes(.big), .big) catch return error.InvalidNonce;
    const Ra = R.affineCoordinates();
    const r = Scalar.fromBytes(Ra.x.toBytes(.big), .big) catch return error.InvalidNonce;
    if (r.isZero()) return error.InvalidNonce;
    const s = k.invert().mul(e.add(r.mul(d)));
    if (s.isZero()) return error.InvalidNonce;

    var recid: u2 = if (Ra.y.isOdd()) 1 else 0;
    // bit 1: whether R.x (a field element, < p) needed reduction mod the
    // (slightly smaller) group order n to produce `r` — astronomically
    // unlikely for a random R, but handled for correctness (mirrors
    // `recoverPubkey`'s symmetric handling of the same bit).
    if (Ra.x.toInt() >= scalarmod.field_order) recid |= 2;

    // Low-S canonicalization (BIP-62 style): RFC 6979 alone doesn't decide
    // between (r, s) and the equally-valid (r, n-s) [the latter corresponds
    // to the "other" nonce n-k, whose R has the OPPOSITE y parity] -- most
    // ECDSA-over-secp256k1 consumers (and BOLT#11's own worked examples)
    // always report the low-S form, so the parity bit must flip in
    // lockstep with negating `s` to keep recovery self-consistent.
    var s_final = s;
    if (!isLowS(s.toBytes(.big))) {
        s_final = s.neg();
        recid ^= 1;
    }

    return .{ .r = r.toBytes(.big), .s = s_final.toBytes(.big), .recid = recid };
}

// ── recover ──────────────────────────────────────────────────────────────

pub const RecoverError = error{ InvalidScalar, NotSquare, InvalidPoint, IdentityElement };

/// Standard ECDSA public-key recovery: `Q = r⁻¹·(s·R − e·G)`, with `R`
/// lifted from `r` (as an x-coordinate) and `recid`'s bit 0 (`R.y` parity) —
/// bit 1 (x ≥ n) is honored too, though it is essentially never set in
/// practice. Fails closed on a non-canonical `r`/`s`, an `r` that isn't a
/// valid curve x-coordinate (`error.NotSquare` — this is what makes a
/// tampered signature's recovery fail rather than silently succeed with a
/// wrong key, in the common case), or a recovered point at infinity.
pub fn recoverPubkey(hash32: [32]u8, r: [32]u8, s: [32]u8, recid: u2) RecoverError!Secp256k1 {
    const r_scalar = Scalar.fromBytes(r, .big) catch return error.InvalidScalar;
    if (r_scalar.isZero()) return error.InvalidScalar;
    const s_scalar = Scalar.fromBytes(s, .big) catch return error.InvalidScalar;
    if (s_scalar.isZero()) return error.InvalidScalar;

    // u512 headroom: `r` can be up to just under `p` (~2^256), and adding
    // the group order `n` (~2^256) for the (essentially never taken,
    // recid-bit-1) x-overflow case would overflow a plain u256.
    var x_wide: u512 = std.mem.readInt(u256, &r, .big);
    if (recid & 2 != 0) {
        x_wide += scalarmod.field_order;
        if (x_wide >= fieldmod.field_order) return error.InvalidScalar;
    }
    var x_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &x_bytes, @intCast(x_wide), .big);
    const x = Fe.fromBytes(x_bytes, .big) catch return error.InvalidScalar;
    const y = Secp256k1.recoverY(x, (recid & 1) != 0) catch return error.NotSquare;
    const R = Secp256k1.fromAffineCoordinates(.{ .x = x, .y = y }) catch return error.InvalidPoint;

    const e = reduceToScalar(hash32);
    const r_inv = r_scalar.invert();
    const coeff_g = e.neg().mul(r_inv); // coefficient of G
    const coeff_r = s_scalar.mul(r_inv); // coefficient of R
    return Secp256k1.mulDoubleBasePublic(Secp256k1.basePoint, coeff_g.toBytes(.big), R, coeff_r.toBytes(.big), .big) catch
        return error.IdentityElement;
}

/// `true` iff `s` is <= half the group order (the "low-S" / BIP-62 rule
/// several ECDSA-over-secp256k1 consumers require of a signer, e.g. BOLT#11
/// when an `n` field pins the signer — high-S is only tolerated on the
/// recovery path).
pub fn isLowS(s: [32]u8) bool {
    const v = std.mem.readInt(u256, &s, .big);
    return v <= (scalarmod.field_order >> 1);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const Sha256 = std.crypto.hash.sha2.Sha256;

test "sign then recoverPubkey round-trips to the signer's own pubkey" {
    var prng = std.Random.DefaultPrng.init(0x1CE0132E);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var privkey: [32]u8 = undefined;
        rand.bytes(&privkey);
        const d = Scalar.fromBytes(privkey, .big) catch continue;
        if (d.isZero()) continue;

        var msg: [32]u8 = undefined;
        rand.bytes(&msg);
        var hash: [32]u8 = undefined;
        Sha256.hash(&msg, &hash, .{});

        const want_pub = Secp256k1.combMulBase(privkey, .big) catch continue;
        const sig = try sign(privkey, hash);
        const recovered = try recoverPubkey(hash, sig.r, sig.s, sig.recid);
        try testing.expect(want_pub.equivalent(recovered));

        // `sign.ecdsaVerify` (this module's own, independent implementation)
        // agrees too.
        var sig_rs: [64]u8 = undefined;
        sig_rs[0..32].* = sig.r;
        sig_rs[32..64].* = sig.s;
        try testing.expect(sign_mod.ecdsaVerify(&want_pub.toCompressedSec1(), &msg, sig_rs));
    }
}

test "recoverPubkey: a bit-flipped signature recovers a DIFFERENT (or non-recoverable) key" {
    var privkey: [32]u8 = undefined;
    @memset(&privkey, 0);
    privkey[31] = 0x42;
    var hash: [32]u8 = undefined;
    @memset(&hash, 0);
    hash[31] = 0x99;

    const want_pub = try Secp256k1.combMulBase(privkey, .big);
    const sig = try sign(privkey, hash);
    const good = try recoverPubkey(hash, sig.r, sig.s, sig.recid);
    try testing.expect(want_pub.equivalent(good));

    var bad_s = sig.s;
    bad_s[31] ^= 0x01;
    if (recoverPubkey(hash, sig.r, bad_s, sig.recid)) |wrong| {
        try testing.expect(!want_pub.equivalent(wrong));
    } else |_| {} // also acceptable: recovery can fail outright
}

test "isLowS: half-order boundary" {
    var half: [32]u8 = undefined;
    std.mem.writeInt(u256, &half, scalarmod.field_order >> 1, .big);
    try testing.expect(isLowS(half));
    var high: [32]u8 = undefined;
    std.mem.writeInt(u256, &high, (scalarmod.field_order >> 1) + 1, .big);
    try testing.expect(!isLowS(high));
}

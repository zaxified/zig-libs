// SPDX-License-Identifier: MIT

//! sign — end-to-end signature schemes over k256, present so the scaffold can be
//! anchored against EXTERNAL vectors (BIP340's official test-vectors) and against
//! std's signer (ECDSA), not just against std's low-level field/group. Every
//! field multiply, point op, and scalar multiply the schemes below touch runs on
//! k256's own arithmetic, so a passing BIP340 official vector is an end-to-end
//! proof that the whole k256 stack agrees with the reference.
//!
//!   * `bip340Sign` / `bip340Verify` — BIP340 Schnorr (the scheme behind Taproot),
//!     exercised by the 19 official vectors in `kat_test.zig`.
//!   * `ecdsaVerify` — secp256k1 ECDSA/SHA-256 verification, cross-checked in
//!     `oracle_test.zig` against signatures produced by
//!     `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`.
//!
//! This layer is intentionally thin: it is a verification harness surface, not
//! the module's reason to exist. A later phase can grow it into a full drop-in
//! for `std.crypto.sign` if desired; for now it proves the primitives.

const std = @import("std");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Secp256k1 = group.Secp256k1;
const Scalar = scalarmod.Scalar;
const Fe = @import("field.zig").Fe;

// ── tagged hashing (BIP340 "Design") ────────────────────────────────────────

/// `SHA256(SHA256(tag) || SHA256(tag) || msg)` — BIP340 domain-separated hash.
fn taggedHash(comptime tag: []const u8, parts: []const []const u8) [32]u8 {
    var tag_digest: [32]u8 = undefined;
    Sha256.hash(tag, &tag_digest, .{});
    var h = Sha256.init(.{});
    h.update(&tag_digest);
    h.update(&tag_digest);
    for (parts) |p| h.update(p);
    return h.finalResult();
}

/// `int(bytes32) mod n` — reduce a 32-byte value into the scalar field (a
/// 32-byte hash can exceed `n`, so a plain `fromBytes` would wrongly reject it).
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

// ── BIP340 Schnorr ──────────────────────────────────────────────────────────

pub const SignError = error{ InvalidSecretKey, InvalidNonce };

/// BIP340 "Default Signing". Returns the 64-byte `r || s` signature.
pub fn bip340Sign(secret_key: [32]u8, msg: []const u8, aux_rand: [32]u8) SignError![64]u8 {
    // d' = int(sk), 0 < d' < n.
    const dp = Scalar.fromBytes(secret_key, .big) catch return error.InvalidSecretKey;
    if (dp.isZero()) return error.InvalidSecretKey;

    // P = d'·G; even-y-normalize the effective scalar d. Constant-time
    // fixed-base comb multiply (secret scalar `d'`).
    const P = Secp256k1.combMulBase(secret_key, .big) catch return error.InvalidSecretKey;
    const Pa = P.affineCoordinates();
    const d = if (Pa.y.isOdd()) dp.neg() else dp;
    const d_bytes = d.toBytes(.big);
    const px = Pa.x.toBytes(.big);

    // t = bytes(d) xor taggedHash("aux", aux_rand).
    const aux_hash = taggedHash("BIP0340/aux", &.{&aux_rand});
    var t: [32]u8 = undefined;
    for (&t, d_bytes, aux_hash) |*ti, di, ai| ti.* = di ^ ai;

    // rand = taggedHash("nonce", t || bytes(P) || msg); k' = int(rand) mod n.
    const rand = taggedHash("BIP0340/nonce", &.{ &t, &px, msg });
    const k0 = reduceToScalar(rand);
    if (k0.isZero()) return error.InvalidNonce;

    // R = k'·G; even-y-normalize k. Constant-time fixed-base comb multiply
    // (SECRET nonce `k'` — the security-critical call).
    const R = Secp256k1.combMulBase(k0.toBytes(.big), .big) catch return error.InvalidNonce;
    const Ra = R.affineCoordinates();
    const rx = Ra.x.toBytes(.big);
    const k = if (Ra.y.isOdd()) k0.neg() else k0;

    // e = int(taggedHash("challenge", bytes(R) || bytes(P) || msg)) mod n.
    const e = reduceToScalar(taggedHash("BIP0340/challenge", &.{ &rx, &px, msg }));

    // sig = bytes(R) || bytes((k + e·d) mod n).
    const s = k.add(e.mul(d));
    var sig: [64]u8 = undefined;
    sig[0..32].* = rx;
    sig[32..64].* = s.toBytes(.big);
    return sig;
}

/// BIP340 "Verification". Returns `false` on every failure path.
pub fn bip340Verify(pubkey_xonly: [32]u8, msg: []const u8, sig: [64]u8) bool {
    // Lift P from the x-only pubkey (even y), re-check r < p and s < n.
    const px = Fe.fromBytes(pubkey_xonly, .big) catch return false;
    const py = Secp256k1.recoverY(px, false) catch return false;
    const P = Secp256k1.fromAffineCoordinates(.{ .x = px, .y = py }) catch return false;

    const rbytes = sig[0..32].*;
    _ = Fe.fromBytes(rbytes, .big) catch return false; // r must be a valid field element
    const s = Scalar.fromBytes(sig[32..64].*, .big) catch return false; // s < n

    // e = challenge.
    const e = reduceToScalar(taggedHash("BIP0340/challenge", &.{ &rbytes, &pubkey_xonly, msg }));

    // R = s·G + (n−e)·P; reject identity; require even y and x(R) == r.
    const R = Secp256k1.mulDoubleBasePublic(
        Secp256k1.basePoint,
        s.toBytes(.big),
        P,
        e.neg().toBytes(.big),
        .big,
    ) catch return false;
    const Ra = R.affineCoordinates();
    if (Ra.y.isOdd()) return false;
    return std.mem.eql(u8, &Ra.x.toBytes(.big), &rbytes);
}

// ── secp256k1 ECDSA / SHA-256 verification ──────────────────────────────────

/// Verify a secp256k1 ECDSA signature over SHA-256(`msg`). `pubkey_sec1` is a
/// SEC1-encoded public key (compressed 33-byte or uncompressed 65-byte);
/// `sig_rs` is `r (32) || s (32)` big-endian. Variable-time (all inputs public).
///
/// **This is textbook ECDSA, so it is malleable**: `(r, s)` and `(r, n − s)`
/// are both valid signatures on the same message under the same key, and this
/// function accepts both — exactly like `std.crypto.sign.ecdsa` (which is what
/// `oracle_test.zig` differentials it against) and like OpenSSL. That is the
/// right behavior for a primitive, but it is the wrong behavior for any caller
/// that treats a signature as an identifier: deriving a transaction id, a
/// replay-cache key, or a dedup key from signature bytes lets anyone who can
/// see a signature mint a second distinct-looking one that still verifies.
///
/// Callers that need a signature to be unique per (key, message) must use
/// `ecdsaVerifyLowS` instead. `libsecp256k1`'s `secp256k1_ecdsa_verify` and
/// Bitcoin (BIP62 rule 5 / BIP146) make that the default; we do not, because
/// this function's contract is "agree with std".
pub fn ecdsaVerify(pubkey_sec1: []const u8, msg: []const u8, sig_rs: [64]u8) bool {
    const Q = Secp256k1.fromSec1(pubkey_sec1) catch return false;
    const r = Scalar.fromBytes(sig_rs[0..32].*, .big) catch return false;
    const s = Scalar.fromBytes(sig_rs[32..64].*, .big) catch return false;
    if (r.isZero() or s.isZero()) return false;

    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    const e = reduceToScalar(h);

    const sinv = s.invert();
    const uu1 = e.mul(sinv);
    const uu2 = r.mul(sinv);

    const R = Secp256k1.mulDoubleBasePublic(
        Secp256k1.basePoint,
        uu1.toBytes(.big),
        Q,
        uu2.toBytes(.big),
        .big,
    ) catch return false;
    // v = x(R) mod n; accept iff v == r.
    const v = reduceToScalar(R.affineCoordinates().x.toBytes(.big));
    return v.equivalent(r);
}

/// `ecdsaVerify`, plus the low-S rule: a signature whose `s` exceeds `n/2` is
/// rejected outright rather than accepted as the malleated twin of a valid
/// one. This is what `libsecp256k1`'s `secp256k1_ecdsa_verify` enforces and
/// what Bitcoin requires of relayed signatures (BIP62 rule 5, consensus for
/// segwit inputs via BIP146); use it whenever a verified signature's *bytes*
/// carry meaning beyond "this verified".
///
/// Exactly one of `(r, s)` and `(r, n − s)` passes this, so a signature that
/// verifies here is unique for its (key, message) pair — which is the whole
/// point. A signer that emits high-S is producing a valid-but-non-canonical
/// signature; normalise at the signer (`s = n − s`), do not relax this.
pub fn ecdsaVerifyLowS(pubkey_sec1: []const u8, msg: []const u8, sig_rs: [64]u8) bool {
    // Checked before any curve arithmetic: the cheap rejection first, and it
    // keeps the malleated form from ever reaching the expensive path.
    if (!isLowS(sig_rs[32..64].*)) return false;
    return ecdsaVerify(pubkey_sec1, msg, sig_rs);
}

/// `true` iff `s <= n/2` — the "low-S" / BIP62-rule-5 canonical form.
/// Re-exported from `ecdsa_recover` so callers reach it from the same place as
/// the verifier that enforces it; the two must never disagree on the boundary.
pub const isLowS = @import("ecdsa_recover.zig").isLowS;

// ── fuzz: bip340Verify never panics on arbitrary signature/pubkey bytes ──
//
// `bip340Verify` is a Schnorr *verifier* — by construction it runs on data
// an adversary controls end to end (a forged Taproot spend, a malicious
// relay's signature). It touches three independent byte-loaders in
// sequence (`Fe.fromBytes` on the x-only pubkey, `Fe.fromBytes` on `r`,
// `Scalar.fromBytes` on `s`) before ever doing curve arithmetic, and must
// return `false` — never panic, never accept — for anything that fails any
// of them. `msg` is also fuzzed independently since it participates in the
// challenge hash.

/// ⛔ A BIP340 signature that verifies is not reachable from arbitrary bytes,
/// so the accepting frames come from the module's own `bip340Sign`. A seed is
/// the 32-octet x-only pubkey and the 64-octet signature RAW (both are drawn
/// with `smith.bytes`, which reads no length header), then the message as a
/// `testkit.fuzz` slice seed.
const Bip340Corpus = struct {
    store: [8 * (32 + 64 + 4 + 96)]u8 = undefined,
    used: usize = 0,
    entries: [8][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *Bip340Corpus, pubkey: [32]u8, sig: [64]u8, msg: []const u8) void {
        const start = self.used;
        @memcpy(self.store[start..][0..32], &pubkey);
        @memcpy(self.store[start + 32 ..][0..64], &sig);
        var at = start + 96;
        at += testkit.fuzz.seedInto(self.store[at..], msg).len;
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    fn build(self: *Bip340Corpus) []const []const u8 {
        const sk = [_]u8{0} ** 31 ++ [_]u8{1};
        const pk = Secp256k1.basePoint.affineCoordinates().x.toBytes(.big);
        const msg = [_]u8{0xAB} ** 32;
        const sig = bip340Sign(sk, &msg, [_]u8{0} ** 32) catch unreachable;
        self.push(pk, sig, &msg); // a real signature over a real key
        var flipped = sig;
        flipped[63] ^= 0x01; // one octet in `s`: still parses, fails the equation
        self.push(pk, flipped, &msg);
        var bad_r = sig;
        @memset(bad_r[0..32], 0xff); // `r >= p`: refused by `Fe.fromBytes`
        self.push(pk, bad_r, &msg);
        var bad_s = sig;
        @memset(bad_s[32..], 0xff); // `s >= n`: refused by `Scalar.fromBytes`
        self.push(pk, bad_s, &msg);
        var bad_pk = pk;
        bad_pk[31] ^= 0x01; // an x-only key with no even-y point
        self.push(bad_pk, sig, &msg);
        // The right signature over the WRONG message — the challenge-hash
        // path, which needs a non-empty message to differ at all.
        self.push(pk, sig, "a different message entirely");
        self.push(pk, sig, ""); // an empty message is legal for BIP340
        self.push(@splat(0), @splat(0), ""); // the all-zero input this used to run
        return self.entries[0..self.n];
    }
};

test "fuzz: bip340Verify never panics on arbitrary bytes" {
    var corpus: Bip340Corpus = .{};
    try std.testing.fuzz({}, fuzzBip340Verify, .{ .corpus = corpus.build() });
}

fn fuzzBip340Verify(_: void, smith: *std.testing.Smith) !void {
    var pubkey: [32]u8 = undefined;
    smith.bytes(&pubkey);
    var sig: [64]u8 = undefined;
    smith.bytes(&sig);
    var msg_buf: [96]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length: the
    // latter drew `msg_len == 0` on every input this target ever ran outside
    // `--fuzz`, so the message — which participates in the challenge hash, and
    // which this harness's own comment says is "fuzzed independently" — was
    // the empty string every round.
    const msg_len: usize = smith.slice(&msg_buf);

    _ = bip340Verify(pubkey, msg_buf[0..msg_len], sig);
}

test "corpus: the BIP340 seeds reach the verifier, and the counts are pinned" {
    var corpus: Bip340Corpus = .{};
    var accepted: usize = 0;
    // ⛔ The number the collapsed draw could not produce: message octets that
    // actually entered the challenge hash. It was 0 on every input.
    var msg_octets: usize = 0;
    for (corpus.build()) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var pubkey: [32]u8 = undefined;
        smith.bytes(&pubkey);
        var sig: [64]u8 = undefined;
        smith.bytes(&sig);
        var msg_buf: [96]u8 = undefined;
        const msg_len: usize = smith.slice(&msg_buf);
        msg_octets += msg_len;
        if (bip340Verify(pubkey, msg_buf[0..msg_len], sig)) accepted += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), accepted);
    try std.testing.expectEqual(@as(usize, 188), msg_octets);
}

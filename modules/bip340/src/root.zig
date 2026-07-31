// SPDX-License-Identifier: MIT
//! bip340 — Schnorr signatures over secp256k1, per BIP340 (the signature
//! scheme behind Bitcoin Taproot): tagged hashing, x-only public keys
//! (even-y convention), key/signature codecs, and sign/verify/batch-verify.
//!
//! **Status: complete.** `hash.taggedHash` (the three BIP340 domain tags,
//! comptime-midstate-optimized), `XOnlyPublicKey` (parse/serialize + BIP340
//! `lift_x`), `SecretKey`/`PublicKey`/`KeyPair` (even-y normalization per
//! BIP340's "Default Signing" §, derived-pubkey computation via
//! `std.crypto.ecc.Secp256k1.basePoint.mul`), `Signature` (parse/serialize
//! + the canonical `r < p` / `s < n` range checks), and the crypto cores:
//! `sign` (BIP340 "Default Signing" incl. the mandatory
//! self-verify-before-return), `verify` (the `s*G - e*P` equation), and
//! `verifyBatch` (random-linear-combination batch equation). All 19
//! official BIP340 test vectors pass byte-exact (`kat_test.zig`): the 8
//! secret-key rows sign to the exact published signature, and all 10
//! deliberately-invalid verification rows are rejected. See `SPEC.md` for
//! the full threat model.
//!
//! Zig std GAP: yes — `std.crypto.ecc.Secp256k1` gives the curve group
//! (field, scalar, `basePoint`, `mul`, `mulDoubleBasePublic`, `recoverY` ==
//! BIP340's `lift_x`) but ships no BIP340 Schnorr layer (tagged hashing,
//! x-only convention, the sign/verify equations) — that is entirely this
//! module's own. Clean-room from the BIP340 specification (public spec,
//! not copyrightable expression — see `NOTICE`); the official
//! `bitcoin/bips` test-vectors.csv is a public spec artifact, cited (not
//! copied from any third-party test suite) in `kat_vectors.zig`.

const std = @import("std");
const Secp256k1 = @import("k256").Secp256k1;
const Fe = Secp256k1.Fe;
const scalar = Secp256k1.scalar;
const Scalar = scalar.Scalar;

pub const hash = @import("hash.zig");
pub const taggedHash = hash.taggedHash;
/// Runtime-tag variant of `taggedHash` for tags only known at runtime
/// (e.g. BOLT#12's per-stream `"LnNonce" || first_tlv` nonce-leaf tag) —
/// see `hash.zig`'s doc comment for why the comptime midstate trick doesn't
/// apply here.
pub const taggedHashRuntime = hash.taggedHashRuntime;

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; keys are plain value types
    .model_after = "BIP340 (bitcoin/bips) — Schnorr Signatures for secp256k1; the k256 module supplies the curve group (byte-exact to std.crypto.ecc.Secp256k1)",
    .deps = .{"k256"}, // k256 supplies the curve group (byte-exact to std.crypto.ecc.Secp256k1); std.crypto.hash.sha2.Sha256
};

// ── x-only public key (BIP340 §"Public Key Conversion" + lift_x) ───────────

pub const XOnlyPublicKeyError = error{InvalidPublicKey};

/// A BIP340 x-only public key: 32 bytes, the x-coordinate of a secp256k1
/// point. BIP340 always resolves the ambiguous y via `lift_x`, which picks
/// the EVEN-y solution (BIP340 §"Public Key Conversion").
pub const XOnlyPublicKey = struct {
    x: [32]u8,

    pub const encoded_length = 32;

    /// Parse a 32-byte x-only public key. Rejects a non-canonical x (`x >=
    /// p`, the field order — `Fe.fromBytes`'s canonical check) and an x
    /// with no valid y on the curve (`lift_x` failure, i.e. `x^3 + 7` is
    /// not a quadratic residue mod p — `Secp256k1.recoverY`'s
    /// `error.NotSquare`). Matches BIP340 test-vector index 14 (x exceeds
    /// the field size) and index 5 (public key not on the curve).
    pub fn fromBytes(bytes: [32]u8) XOnlyPublicKeyError!XOnlyPublicKey {
        const x = Fe.fromBytes(bytes, .big) catch return error.InvalidPublicKey;
        _ = Secp256k1.recoverY(x, false) catch return error.InvalidPublicKey;
        return .{ .x = bytes };
    }

    pub fn toBytes(pk: XOnlyPublicKey) [32]u8 {
        return pk.x;
    }

    /// BIP340 `lift_x(x)`: the unique secp256k1 point with this x
    /// coordinate and an EVEN y. Re-validates on-curve-ness (cheap; the
    /// heavy lifting is `recoverY`'s square-root test) so this function
    /// alone is a safe lift entry point even if a `XOnlyPublicKey` value
    /// were ever constructed by unusual means.
    pub fn lift(pk: XOnlyPublicKey) XOnlyPublicKeyError!Secp256k1 {
        const x = Fe.fromBytes(pk.x, .big) catch return error.InvalidPublicKey;
        const y = Secp256k1.recoverY(x, false) catch return error.InvalidPublicKey;
        return Secp256k1.fromAffineCoordinates(.{ .x = x, .y = y }) catch return error.InvalidPublicKey;
    }
};

/// Extract the 32-byte x-only view of a point field that may be encoded
/// either as a 33-byte SEC1-compressed key (`prefix (1) || x (32)`) or as
/// an already x-only 32-byte key — the point encoding several Lightning
/// specs use interchangeably (e.g. BOLT#12's `invreq_payer_id (33)` /
/// `invoice_node_id (33)`, both verified x-only per BIP340's forced-even-y
/// convention, so the parity prefix byte is simply dropped rather than
/// consulted). Purely structural: it does not validate that the extracted
/// 32 bytes are a valid curve x-coordinate — feed the result to
/// `XOnlyPublicKey.fromBytes` for that.
pub fn xonlyBytesOf(point: []const u8) error{BadPointLength}![32]u8 {
    return switch (point.len) {
        33 => point[1..33].*,
        32 => point[0..32].*,
        else => error.BadPointLength,
    };
}

// ── secret key / public key / key pair ──────────────────────────────────────

pub const SecretKeyError = error{InvalidSecretKey};

/// A BIP340 secret key: a scalar `d` in `[1, n-1]` (`n` = the curve
/// order). This is the value as originally chosen/imported — BEFORE the
/// even-y normalization `KeyPair.fromSecretKey` applies (BIP340's "Default
/// Signing" §, first two steps: `d' = int(sk)`; fail if not in
/// `[1, n-1]`).
pub const SecretKey = struct {
    bytes: [32]u8,

    pub const encoded_length = 32;

    pub fn fromBytes(bytes: [32]u8) SecretKeyError!SecretKey {
        const d = Scalar.fromBytes(bytes, .big) catch return error.InvalidSecretKey;
        if (d.isZero()) return error.InvalidSecretKey;
        return .{ .bytes = bytes };
    }
};

/// A BIP340 x-only public key derived from a secret key, i.e.
/// `PublicKey.fromSecretKey(sk).xonly == lift_x_of(d * G)` for the
/// even-y-normalized effective scalar (see `KeyPair`).
pub const PublicKey = struct {
    xonly: XOnlyPublicKey,

    /// `d * G`, serialized x-only (BIP340 §"Public Key Conversion":
    /// `pk = bytes(x(d'*G))`).
    pub fn fromSecretKey(sk: SecretKey) SecretKeyError!PublicKey {
        return .{ .xonly = (try KeyPair.fromSecretKey(sk)).public };
    }
};

/// A BIP340 key pair: the EVEN-y-normalized effective secret scalar plus
/// its x-only public key, ready for `sign` to consume directly (no
/// per-signature re-normalization needed).
pub const KeyPair = struct {
    /// The effective signing scalar: `d` if `(d*G).y` is even, else `n -
    /// d` (BIP340 "Default Signing" § step 3). NOT necessarily bytewise
    /// equal to the `SecretKey` this was derived from.
    secret: [32]u8,
    public: XOnlyPublicKey,

    pub fn fromSecretKey(sk: SecretKey) SecretKeyError!KeyPair {
        const d = Scalar.fromBytes(sk.bytes, .big) catch return error.InvalidSecretKey;
        if (d.isZero()) return error.InvalidSecretKey;
        const p = Secp256k1.combMulBase(sk.bytes, .big) catch return error.InvalidSecretKey;
        const xy = p.affineCoordinates();
        const effective: [32]u8 = if (xy.y.isOdd())
            scalar.neg(sk.bytes, .big) catch unreachable // sk.bytes already canonical (validated above)
        else
            sk.bytes;
        return .{ .secret = effective, .public = .{ .x = xy.x.toBytes(.big) } };
    }

    /// Zeroize the effective signing scalar (`secret`) in place; `public`
    /// is left untouched (it is not secret). Idempotent. Hygiene only —
    /// no effect on any signature produced before the call.
    pub fn deinit(self: *KeyPair) void {
        std.crypto.secureZero(u8, &self.secret);
    }
};

// ── signature codec ──────────────────────────────────────────────────────

pub const SignatureError = error{InvalidSignature};

/// A BIP340 signature: 64 bytes, `r (32) || s (32)`. `r` is an x
/// coordinate (must be `< p`, the field order); `s` is a scalar (must be
/// `< n`, the curve order) — BIP340 §"Default Signing"/"Verification"'s
/// range checks. Matches test-vector index 12 (`r == p`) and index 13
/// (`s == n`), both of which must be rejected.
pub const Signature = struct {
    r: [32]u8,
    s: [32]u8,

    pub const encoded_length = 64;

    pub fn fromBytes(bytes: [64]u8) SignatureError!Signature {
        const r = bytes[0..32].*;
        const s = bytes[32..64].*;
        _ = Fe.fromBytes(r, .big) catch return error.InvalidSignature;
        _ = Scalar.fromBytes(s, .big) catch return error.InvalidSignature;
        return .{ .r = r, .s = s };
    }

    pub fn toBytes(sig: Signature) [64]u8 {
        var out: [64]u8 = undefined;
        out[0..32].* = sig.r;
        out[32..64].* = sig.s;
        return out;
    }
};

// ── crypto cores ──────────────────────────────────────────────────────────

/// `int(bytes32) mod n` (`n` = the curve order): BIP340's "int(x) mod n"
/// reduction of a 32-byte big-endian hash output. Implemented by widening
/// to 48 bytes (16 leading zero bytes) and using the scalar field's
/// canonical wide reduction — a 32-byte value can exceed `n` (n < 2^256),
/// so a plain `Scalar.fromBytes` (which REJECTS non-canonical values
/// instead of reducing them) would be wrong here.
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

pub const SignError = error{
    InvalidSecretKey,
    /// Step 5's `k' == 0` (probability ~2^-256 for honest inputs).
    InvalidNonce,
    /// The mandatory step-10 self-verification failed — the freshly
    /// produced signature does not verify against its own public key and
    /// message. Never returned by a correct implementation on correct
    /// hardware; exists to fail CLOSED under fault injection / silent
    /// corruption rather than emit a secret-leaking signature.
    SignatureVerificationFailed,
};

/// BIP340 §"Default Signing".
///
/// The spec's 10 steps, mapped to this implementation:
///
/// 1. Let `d' = int(sk)`; fail if `d' == 0` or `d' >= n` — re-enforced
///    here via `KeyPair.fromSecretKey` (also `SecretKey.fromBytes`'s job).
/// 2. Let `P = d' * G`. Let `d = d'` if `has_even_y(P)`, else `d = n - d'`
///    — exactly what `KeyPair.fromSecretKey(secret_key)` computes.
/// 3. Let `t = bytes(d) xor taggedHash("BIP0340/aux", aux_rand)`.
/// 4. Let `rand = taggedHash("BIP0340/nonce", t || bytes(P) || msg)`
///    (`bytes(P)` = the 32-byte x-only encoding).
/// 5. Let `k' = int(rand) mod n`; fail if `k' == 0` (`error.InvalidNonce`).
/// 6. Let `R = k' * G`.
/// 7. Let `k = k'` if `has_even_y(R)`, else `k = n - k'` — done with a
///    constant-time masked byte select over the two candidate scalars (no
///    branch on `R.y`'s parity, which is one bit of the secret nonce hash).
/// 8. Let `e = int(taggedHash("BIP0340/challenge", bytes(R) || bytes(P) ||
///    msg)) mod n`.
/// 9. Let `sig = bytes(R) || bytes((k + e*d) mod n)` — scalar arithmetic
///    via `Secp256k1.scalar` (constant-time field ops).
/// 10. Mandatory self-check: verify `sig` against `pk = bytes(P)` and
///     `msg` before returning it (`error.SignatureVerificationFailed` if it
///     does not pass) — fail closed rather than emit a maybe-bad signature
///     (fault-injection / silent-corruption guard the spec requires).
///
/// `io` is threaded through for API symmetry with `verifyBatch` (and for a
/// future variant that synthesizes `aux_rand` itself) — the BIP340
/// algorithm above, once `aux_rand` is in hand, is fully deterministic and
/// does not consume `io`.
pub fn sign(secret_key: SecretKey, msg: []const u8, aux_rand: [32]u8, io: std.Io) SignError![64]u8 {
    _ = io; // deterministic once aux_rand is in hand (see doc comment)

    // Steps 1-2: even-y-normalized effective scalar d + x-only public key.
    var kp = try KeyPair.fromSecretKey(secret_key);
    defer kp.deinit();
    var d_bytes = kp.secret;
    defer std.crypto.secureZero(u8, &d_bytes);
    const px = kp.public.x;

    // Step 3: t = bytes(d) xor taggedHash(aux, aux_rand).
    const aux_hash = taggedHash(hash.aux_tag, &aux_rand);
    var t: [32]u8 = undefined;
    for (&t, d_bytes, aux_hash) |*ti, di, ai| ti.* = di ^ ai;

    // Step 4: rand = taggedHash(nonce, t || bytes(P) || msg).
    var nonce_hasher = hash.taggedHasher(hash.nonce_tag);
    nonce_hasher.update(&t);
    nonce_hasher.update(&px);
    nonce_hasher.update(msg);
    const rand = nonce_hasher.finalResult();

    // Step 5: k' = int(rand) mod n; fail if 0.
    const k0 = reduceToScalar(rand);
    if (k0.isZero()) return error.InvalidNonce;

    // Step 6: R = k' * G (constant-time base-point multiply). Identity is
    // impossible (k' != 0 mod n, just checked), but map it defensively.
    const r_point = Secp256k1.combMulBase(k0.toBytes(.big), .big) catch return error.InvalidNonce;
    const r_xy = r_point.affineCoordinates();
    const rx = r_xy.x.toBytes(.big);

    // Step 7: k = k' if has_even_y(R) else n - k'. Constant-time masked
    // select between the two candidates — no data-dependent branch on the
    // parity bit (it is derived from the secret nonce).
    const k_even = k0.toBytes(.big);
    const k_odd = k0.neg().toBytes(.big);
    const mask: u8 = @as(u8, 0) -% @intFromBool(r_xy.y.isOdd());
    var k_bytes: [32]u8 = undefined;
    for (&k_bytes, k_even, k_odd) |*ki, ke, ko| ki.* = (ke & ~mask) | (ko & mask);
    const k = Scalar.fromBytes(k_bytes, .big) catch unreachable; // both candidates canonical

    // Step 8: e = int(taggedHash(challenge, bytes(R) || bytes(P) || msg)) mod n.
    var challenge_hasher = hash.taggedHasher(hash.challenge_tag);
    challenge_hasher.update(&rx);
    challenge_hasher.update(&px);
    challenge_hasher.update(msg);
    const e = reduceToScalar(challenge_hasher.finalResult());

    // Step 9: sig = bytes(R) || bytes((k + e*d) mod n).
    const d = Scalar.fromBytes(d_bytes, .big) catch return error.InvalidSecretKey;
    const s = k.add(e.mul(d));
    var sig: [64]u8 = undefined;
    sig[0..32].* = rx;
    sig[32..64].* = s.toBytes(.big);

    // Step 10: mandatory self-verification before returning.
    const parsed = Signature.fromBytes(sig) catch return error.SignatureVerificationFailed;
    if (!verify(kp.public, msg, parsed)) return error.SignatureVerificationFailed;
    return sig;
}

/// BIP340 §"Verification". Returns `false` on every failure path — it
/// never panics and never errors.
///
/// Steps (`pubkey`/`sig` are normally already well-formed via
/// `XOnlyPublicKey.fromBytes`/`Signature.fromBytes`, but every check is
/// re-run here so `verify` is safe even on hand-constructed values):
///
/// 1. `P = lift_x(pubkey)` — fail if x >= p or no even-y point (vectors
///    5/14 when reached through `fromBytes`).
/// 2. `r = int(sig[0:32])` — fail if `r >= p` (vector 12).
/// 3. `s = int(sig[32:64])` — fail if `s >= n` (vector 13).
/// 4. `e = int(taggedHash("BIP0340/challenge", bytes(r) || bytes(P) ||
///    msg)) mod n`.
/// 5. `R = s*G - e*P`, computed as `mulDoubleBasePublic(basePoint, s, P,
///    n - e)` (negate `e` mod n; the helper computes `p1*s1 + p2*s2`).
/// 6. Fail if `R` is the point at infinity (`error.IdentityElement`) —
///    vectors 9/10.
/// 7. Fail if `not has_even_y(R)` — vector 6.
/// 8. Fail if `bytes(x(R)) != sig[0:32]` — vectors 7/8/11 (note vector 11:
///    its `r` is not a valid x-coordinate, so no computed `R` can ever
///    match it; single verification needs no explicit `lift_x(r)`).
///
/// Constant-time is explicitly NOT required (BIP340 §"Verification" — all
/// inputs here are public); `mulDoubleBasePublic` is the variable-time
/// double-base multiply std provides for exactly this.
pub fn verify(pubkey: XOnlyPublicKey, msg: []const u8, sig: Signature) bool {
    // Steps 1-3: lift P; re-check r < p and s < n.
    const p = pubkey.lift() catch return false;
    _ = Fe.fromBytes(sig.r, .big) catch return false;
    const s = Scalar.fromBytes(sig.s, .big) catch return false;

    // Step 4: challenge scalar.
    var challenge_hasher = hash.taggedHasher(hash.challenge_tag);
    challenge_hasher.update(&sig.r);
    challenge_hasher.update(&pubkey.x);
    challenge_hasher.update(msg);
    const e = reduceToScalar(challenge_hasher.finalResult());

    // Steps 5-6: R = s*G + (n-e)*P; identity => invalid.
    const r_point = Secp256k1.mulDoubleBasePublic(
        Secp256k1.basePoint,
        s.toBytes(.big),
        p,
        e.neg().toBytes(.big),
        .big,
    ) catch return false;

    // Steps 7-8: even y and x(R) == r.
    const r_xy = r_point.affineCoordinates();
    if (r_xy.y.isOdd()) return false;
    return std.mem.eql(u8, &r_xy.x.toBytes(.big), &sig.r);
}

/// One item for `verifyBatch`.
pub const BatchItem = struct {
    pubkey: XOnlyPublicKey,
    msg: []const u8,
    sig: Signature,
};

/// BIP340 §"Batch Verification". Returns `false` on every failure path.
///
/// For `u` signatures `(r_i, s_i)` over pubkeys `P_i` and messages `m_i`,
/// draws `u-1` random non-zero scalars `a_2..a_u` (`a_1 = 1`) and checks
/// the random linear combination:
///
/// ```
/// (sum_i a_i*s_i) * G == sum_i (a_i*R_i + (a_i*e_i)*P_i)
/// ```
///
/// where `R_i = lift_x(r_i)` (the whole batch fails if any `r_i` does not
/// lift, any pubkey does not lift, or any `s_i >= n` — per the spec) and
/// `e_i` is each item's individual challenge hash. `io` supplies the
/// `a_2..a_u` randomness (`Secp256k1.scalar.Scalar.random`, rejection-
/// sampled non-zero); BIP340 requires these to be unpredictable to an
/// attacker and drawn AFTER all `(pubkey, msg, sig)` triples are fixed —
/// satisfied here because they are drawn inside this call, from the
/// caller's CSPRNG, after the full `items` slice is bound.
///
/// Implementation note (documented deviation from a maximally-batched
/// form): the right-hand side is accumulated per item via one
/// variable-time double-base multiply (`a_i*R_i + (a_i*e_i)*P_i`) plus a
/// complete point addition, rather than one large multi-scalar
/// multiplication over all `2u+1` terms (std's API tops out at two bases
/// per call). Same equation, same acceptance set — it only forgoes part of
/// the batching speedup. If one item's combined term is the identity
/// (std's double-base multiply reports it as `error.IdentityElement`), the
/// identity contributes nothing and the item is skipped — NOT a failure:
/// the equation, not any per-item property, decides.
pub fn verifyBatch(items: []const BatchItem, io: std.Io) bool {
    // Empty batch: the equation degenerates to 0*G == identity on both
    // sides — vacuously true (matches "all zero signatures are valid").
    var lhs_scalar = Scalar.zero; // sum_i a_i * s_i (mod n)
    var rhs = Secp256k1.identityElement;
    for (items, 0..) |item, i| {
        // lift_x on the pubkey and on r_i; s_i < n. Any failure fails the batch.
        const p = item.pubkey.lift() catch return false;
        const rx = Fe.fromBytes(item.sig.r, .big) catch return false;
        const ry = Secp256k1.recoverY(rx, false) catch return false;
        const r_point = Secp256k1.fromAffineCoordinates(.{ .x = rx, .y = ry }) catch return false;
        const s = Scalar.fromBytes(item.sig.s, .big) catch return false;

        // e_i = int(taggedHash(challenge, r_i || pk_i || m_i)) mod n.
        var challenge_hasher = hash.taggedHasher(hash.challenge_tag);
        challenge_hasher.update(&item.sig.r);
        challenge_hasher.update(&item.pubkey.x);
        challenge_hasher.update(item.msg);
        const e = reduceToScalar(challenge_hasher.finalResult());

        // a_1 = 1; a_2..a_u random non-zero.
        const a: Scalar = if (i == 0) Scalar.one else Scalar.random(io);

        lhs_scalar = lhs_scalar.add(a.mul(s));

        // a_i*R_i + (a_i*e_i)*P_i. R_i and P_i are real lifted points
        // (never the identity), so the only IdentityElement case is the
        // RESULT being the identity — which contributes nothing to the sum.
        const term = Secp256k1.mulDoubleBasePublic(
            r_point,
            a.toBytes(.big),
            p,
            a.mul(e).toBytes(.big),
            .big,
        ) catch continue;
        rhs = rhs.add(term);
    }

    // (sum a_i*s_i)*G vs the accumulated right-hand side. `mul` errors iff
    // the scalar sum is 0 mod n (left side = identity): then the equation
    // holds iff the right side is the identity too.
    const lhs = Secp256k1.combMulBase(lhs_scalar.toBytes(.big), .big) catch {
        rhs.rejectIdentity() catch return true;
        return false;
    };
    rhs.rejectIdentity() catch return false;
    return lhs.equivalent(rhs);
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = hash;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.model_after names BIP340 and std's Secp256k1" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BIP340") != null);
}

test "XOnlyPublicKey encoded_length and Signature encoded_length" {
    try std.testing.expectEqual(@as(usize, 32), XOnlyPublicKey.encoded_length);
    try std.testing.expectEqual(@as(usize, 64), Signature.encoded_length);
}

test "xonlyBytesOf: 33-byte compressed drops the prefix, 32-byte passes through, other lengths reject" {
    var compressed: [33]u8 = undefined;
    compressed[0] = 0x02;
    for (compressed[1..33], 0..) |*b, i| b.* = @intCast(i);
    const from33 = try xonlyBytesOf(&compressed);
    try std.testing.expectEqualSlices(u8, compressed[1..33], &from33);

    const from32 = try xonlyBytesOf(compressed[1..33]);
    try std.testing.expectEqualSlices(u8, compressed[1..33], &from32);

    try std.testing.expectError(error.BadPointLength, xonlyBytesOf(compressed[0..30]));
    var too_long: [34]u8 = undefined;
    too_long[0..33].* = compressed;
    too_long[33] = 0x00;
    try std.testing.expectError(error.BadPointLength, xonlyBytesOf(&too_long));
}

test "SecretKey.fromBytes REJECTS the all-zero scalar (d == 0 is not in [1, n-1])" {
    // No official BIP340 test vector exercises this (all 8 secret-key
    // vectors are valid, nonzero scalars) — the zero-scalar guard is
    // otherwise unexercised by any KAT test.
    try std.testing.expectError(error.InvalidSecretKey, SecretKey.fromBytes([_]u8{0} ** 32));
}

test "KeyPair.fromSecretKey REJECTS a hand-constructed all-zero SecretKey (defense-in-depth re-check)" {
    // SecretKey.bytes is a public field, so a SecretKey can be
    // hand-constructed bypassing fromBytes's own zero-check entirely —
    // KeyPair.fromSecretKey re-validates for exactly this reason.
    const zero_sk = SecretKey{ .bytes = [_]u8{0} ** 32 };
    try std.testing.expectError(error.InvalidSecretKey, KeyPair.fromSecretKey(zero_sk));
}

test "KeyPair.deinit zeroizes the effective signing scalar but leaves public untouched (regression: fails if secureZero is removed)" {
    const sk = try SecretKey.fromBytes([_]u8{0x01} ** 32);
    var kp = try KeyPair.fromSecretKey(sk);
    const zero: [32]u8 = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &kp.secret, &zero));
    kp.deinit();
    try std.testing.expectEqualSlices(u8, &zero, &kp.secret);
    try std.testing.expect(!std.mem.eql(u8, &kp.public.x, &zero));
}

// SPDX-License-Identifier: MIT
//! XEdDSA (signal.org/docs/specifications/xeddsa) — a Schnorr-style
//! signature scheme that signs and verifies with an ordinary X25519
//! (Montgomery-curve) keypair, by converting it to/from the birationally
//! equivalent Edwards25519 point and running an Ed25519-shaped
//! sign/verify equation on the result. This is the one piece of X3DH
//! (`../root.zig`, `x3dh.zig`) that is genuinely novel cryptography rather
//! than a DH+HKDF composition: `SignedPreKey.signature` (spec: "Bob's
//! signature on SPKB using IKB") is an XEdDSA signature, and X3DH's
//! `initiate` fail-closes on `verify` before running any DH — see
//! `x3dh.zig`'s `initiate`/`initiateUnverified` split.
//!
//! **Status: IMPLEMENTED.** Both `sign` and `verify` follow the public
//! XEdDSA specification text exactly, including the spec's fixed sign-bit
//! convention: the signer forces its derived Edwards public key `A` to the
//! sign-0 (even-`x`) representative by negating the private scalar when
//! needed, and the verifier deterministically reconstructs the SAME sign-0
//! `A` from the Montgomery `u`-coordinate alone (`edwardsFromMontgomery` —
//! the Montgomery->Edwards direction std does not provide; std only ships
//! the reverse, `Curve25519.fromEdwards25519`).
//!
//! **Two variants, both implemented, chosen explicitly at the call site
//! (deployed libsignal differs from the spec paper):** Signal's shipped
//! implementations (libsignal-protocol-c/-java and the current Rust
//! libsignal — its `curve25519.rs` says so in a doc comment verbatim) do
//! NOT force sign 0. They instead sign with the natural-sign `A` and
//! smuggle `A`'s sign bit in the most-significant bit of `s`
//! (`signature[63]`), which the spec's construction leaves always-zero.
//! The two variants produce incompatible signatures for the ~half of all
//! keys whose natural Edwards point has sign 1. Top-level `sign`/`verify`
//! implement the SPEC variant (sign-0 forced, no bit smuggled — `s` is a
//! canonical scalar `< L`), so they round-trip with themselves and with
//! any other spec-faithful implementation, but reject a signature
//! produced by deployed libsignal for a sign-1 key. The `libsignal`
//! namespace below (`libsignal.sign`/`libsignal.verify`) implements
//! DEPLOYED libsignal's variant instead — natural-sign `A`, sign bit
//! smuggled into `s[31]`'s top bit — for a caller that needs to
//! interoperate with real Signal clients/servers rather than a
//! spec-faithful peer. There is no default: a caller must write either
//! `xeddsa.sign`/`xeddsa.verify` or `xeddsa.libsignal.sign`/
//! `xeddsa.libsignal.verify`, so which wire format is in play is always
//! visible at the call site — see `kat_test.zig`, which pins BOTH
//! variants against libsignal's own published test vector (whose key is
//! itself a natural-sign-1 key, the exact case the spec variant cannot
//! handle). See `SPEC.md` for the threat-model caveat (key reuse across
//! DH and signing contexts) this scheme deliberately accepts.
//!
//! Constant-time posture: `sign` handles the secret scalar exclusively
//! with `Edwards25519.scalar`'s constant-time ops and `ct25519.mulBase`;
//! the negate-if-sign-1 selection is a branchless masked select (and the
//! sign bit itself is not meaningfully secret — it is a deterministic
//! function of the public key pair `±A`, and deployed libsignal
//! literally transmits it in every signature).
//!
//! It used to say "a constant-time `basePoint.mul`", meaning std's, and
//! that was only three-quarters true. std's `Edwards25519.mul` IS a
//! constant-time 4-bit-window ladder — and then `pcMul16` ends with
//! `try q.rejectIdentity()`, a branch on a scalar-derived value. Both of
//! this module's base multiplications feed it a SECRET (the sign-0 key
//! scalar `a`; the per-signature nonce `r`, from which `s = r + h*a`
//! hands out `a`), and both had to `catch @panic(...)` — a control-flow
//! decision taken from a value only the signer's secrets determine.
//! `ct25519.mulBase` is the same ladder with that tail removed: no error
//! union, neutral element as a value, identical cost. Neither panic was
//! ever reachable in the first place (see `calculateKeyPair`), so only
//! the leak was real, and it is gone.
//!
//! `verify` operates on public inputs only (variable-time
//! `mulDoubleBasePublic` is fine, mirroring `std.crypto.sign.Ed25519`'s
//! own verifier) and fails CLOSED — every malformed input returns
//! `false`, never a panic, matching `bip340.verify`'s convention in this
//! repo.
//!
//! Provenance: clean-room from the public XEdDSA specification
//! (signal.org/docs/specifications/xeddsa — Trevor Perrin, Signal
//! Foundation). Test vector sourced from libsignal's test suite (numeric
//! facts only). See `../NOTICE`.

const std = @import("std");
const ct25519 = @import("ct25519");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Fe = Edwards25519.Fe;
const scalar = Edwards25519.scalar;
const Sha512 = std.crypto.hash.sha2.Sha512;

/// A 64-byte XEdDSA signature: `R (32 bytes, Edwards-compressed) || s (32
/// bytes, little-endian scalar)` — the same wire shape as a plain Ed25519
/// signature (`std.crypto.sign.Ed25519.Signature.encoded_length`), but
/// computed over an Edwards point derived from a Montgomery keypair
/// rather than a native Ed25519 one. The SAME 64-byte type is shared by
/// both variants this module implements (see the module doc comment):
/// under top-level `sign`/`verify` (the spec variant), `s` is always a
/// canonical scalar (`< L`, top bit clear); under `libsignal.sign`/
/// `libsignal.verify` (deployed libsignal's variant), `s`'s top bit
/// instead carries the signer's natural Edwards sign bit, and the
/// remaining 255 bits must be `< L`. A `Signature` value is only
/// meaningful together with the variant that produced it — the two
/// `verify` functions deliberately disagree on sign-1-key signatures.
pub const Signature = [64]u8;

/// `Z`, the 64-byte random-data input the spec's `sign(a, M, Z)` takes
/// (§ "Sign"). Callers should fill this with real CSPRNG output —
/// `io.random(&z)` (`std.Io.random`) — mirroring `bip340.sign`'s
/// `aux_rand`/`adaptor.preSign`'s `aux_rand` convention in this repo:
/// deterministic once `Z` is in hand, so the crypto core itself takes no
/// `io` parameter.
pub const RandomData = [64]u8;

/// The spec's `hash1` domain prefix: `hash_i(X) = SHA-512(2^b - 1 - i ||
/// X)` with `b = 256`, `i = 1`, so the prefix is the 32-byte
/// little-endian encoding of `2^256 - 2`: one `0xFE` byte followed by 31
/// `0xFF` bytes. Domain-separates the NONCE hash from both plain SHA-512
/// (the challenge hash, no prefix) and any other `hash_i` — this is what
/// makes reusing one scalar for X25519 DH and XEdDSA signing safe (see
/// `SPEC.md`'s threat model). Note the challenge hash `hash(R || A || M)`
/// carries NO prefix — it is byte-identical to Ed25519's, which is why a
/// spec-variant XEdDSA signature is also a valid Ed25519 signature under
/// the sign-0 `A` (a property `kat_test.zig` exploits to cross-check
/// `sign` against std's independent Ed25519 verifier).
const hash1_prefix: [32]u8 = [_]u8{0xFE} ++ [_]u8{0xFF} ** 31;

pub const RecoverError = error{InvalidPublicKey};

/// **The genuinely missing std primitive** (spec § "Elliptic curve
/// conversions", `convert_mont(u)`): recover the SIGN-0 (even-`x`)
/// Edwards25519 point `A` from an X25519 Montgomery public key's
/// `u`-coordinate alone, via the birational map `y = (u - 1) / (u + 1)
/// mod p` followed by decompressing `(y, sign = 0)` against the Edwards
/// curve equation. This is the exact reverse of std's
/// `Curve25519.fromEdwards25519` (`u = (1 + y) / (1 - y)`).
///
/// Fail-closed on attacker-controlled input, `error.InvalidPublicKey` when:
/// - `u` is a non-canonical field encoding (`u >= p`, or the top bit set —
///   stricter than the spec's mask-and-continue, but an honestly generated
///   X25519 public key is always canonical, and rejecting is the safe
///   direction for a verifier);
/// - `u == p - 1` (the map's `u + 1 = 0` pole — no corresponding point);
/// - the mapped `y` is not on Edwards25519 (a `u` on the curve's quadratic
///   twist — `Edwards25519.fromBytes` rejects it).
///
/// Does NOT itself reject the identity/low-order results (`u = 0` maps to
/// the order-2 point `(0, -1)`, for example) — `verify` layers
/// `rejectIdentity`/`rejectLowOrder` on top, so this function stays the
/// pure conversion the spec defines.
pub fn edwardsFromMontgomery(montgomery_pub: [32]u8) RecoverError!Edwards25519 {
    Fe.rejectNonCanonical(montgomery_pub, false) catch return error.InvalidPublicKey;
    const u = Fe.fromBytes(montgomery_pub);
    const u_plus_one = u.add(Fe.one);
    if (u_plus_one.isZero()) return error.InvalidPublicKey; // u == p - 1: map pole
    const y = u.sub(Fe.one).mul(u_plus_one.invert());
    // Fe.toBytes is canonical, so bit 255 (the compressed sign bit) is
    // already 0 — decompression below therefore picks the even-x root,
    // the spec's fixed sign-0 convention.
    const y_bytes = y.toBytes();
    return Edwards25519.fromBytes(y_bytes) catch error.InvalidPublicKey;
}

/// The spec's `calculate_key_pair(k)`: clamp the Montgomery seed
/// (RFC 7748, at use time — the same clamp `X25519.recoverPublicKey`
/// applies), compute `E = kB` on the Edwards curve, and force the
/// sign-0 convention: if `E`'s compressed sign bit is 1, the returned
/// scalar is `-k mod L` (whose point is `-E`, same `y`, sign 0) —
/// selected BRANCHLESSLY via a mask, and the returned public key bytes
/// are `E`'s encoding with the sign bit cleared (negating a point flips
/// only that bit, so clearing it IS the sign-0 representative's
/// encoding). The Montgomery public key `u` is unaffected by which of
/// `±E` is chosen — that is the spec's trick: the verifier can't tell,
/// so both sides fix sign 0 by convention.
fn calculateKeyPair(montgomery_priv: [32]u8) struct {
    scalar: scalar.CompressedScalar,
    public: [32]u8,
} {
    var t = montgomery_priv;
    defer std.crypto.secureZero(u8, &t);
    scalar.clamp(&t);
    var k = scalar.reduce(t);
    defer std.crypto.secureZero(u8, &k);
    // SECRET scalar, so `ct25519.mulBase` (std's own window ladder minus
    // the trailing `rejectIdentity`) rather than `Edwards25519.mul`. The
    // `catch @panic(...)` this replaces branched on `k` — and it could
    // never fire: a clamped seed lies in `[2^254, 2^255)` and is divisible
    // by 8, while the only multiples of `L` that reduce to 0 are `m*L`, and
    // `8L > 2^255` while `m <= 7` is never divisible by 8. So the panic was
    // unreachable AND leaked; only the leak was real.
    const e = ct25519.mulBase(k);
    var public = e.toBytes();
    const sign_bit: u8 = public[31] >> 7;
    public[31] &= 0x7F;
    var k_neg = scalar.neg(k);
    defer std.crypto.secureZero(u8, &k_neg);
    const mask: u8 = 0 -% sign_bit; // 0x00 or 0xFF — branchless select
    var a: scalar.CompressedScalar = undefined;
    for (&a, k, k_neg) |*out, plain, negated| out.* = (plain & ~mask) | (negated & mask);
    return .{ .scalar = a, .public = public };
}

/// **XEdDSA Sign** (spec § "Sign", `sign(k, M, Z)`): given a Montgomery
/// (X25519) private key `montgomery_priv` (the raw 32-byte seed
/// `std.crypto.dh.X25519.KeyPair.secret_key` stores — clamping happens
/// inside, at use time, exactly like `X25519.recoverPublicKey`), sign
/// `msg` with 64 bytes of fresh randomness `z`.
///
/// Construction (`a`/`A` = the sign-0 scalar/point from
/// `calculateKeyPair`, `M` = `msg`, `Z` = `z`):
///
/// 1. `A, a = calculate_key_pair(k)` — see `calculateKeyPair`.
/// 2. `r = hash1(a || M || Z) mod L`, where `hash1(X) = SHA-512(0xFE ||
///    0xFF*31 || X)` (see `hash1_prefix`) — note the spec hashes the
///    (possibly negated) sign-0 scalar `a`, not the raw seed. Wide-reduced
///    via `scalar.reduce64`.
/// 3. `R = rB` (constant-time precomputed base multiplication — same
///    primitive as step 1's, irrelevant here only because `r` is already
///    reduced).
/// 4. `h = hash(R || A || M) mod L` — PLAIN SHA-512, no domain prefix:
///    the ordinary Ed25519-shaped challenge, over the sign-0 `A`.
/// 5. `s = r + h*a mod L` (`scalar.mulAdd`).
/// 6. Return `R || s` — no sign bit is packed into `s`'s top bit (unlike
///    deployed libsignal's variant; see the module doc comment): `A`'s
///    sign is 0 by construction, so the verifier never needs to be told.
pub fn sign(montgomery_priv: [32]u8, msg: []const u8, z: RandomData) Signature {
    var kp = calculateKeyPair(montgomery_priv);
    defer std.crypto.secureZero(u8, &kp.scalar);

    var st = Sha512.init(.{});
    st.update(&hash1_prefix);
    st.update(&kp.scalar);
    st.update(msg);
    st.update(&z);
    var r64: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &r64);
    st.final(&r64);
    var r = scalar.reduce64(r64);
    defer std.crypto.secureZero(u8, &r);

    // `r` is the per-signature SECRET nonce — `s = r + h*a` hands `a` to
    // anyone who learns it — so the same constant-time ladder, and no
    // `catch @panic` deciding a control-flow question from `r`'s value.
    const r_point = ct25519.mulBase(r);
    const r_bytes = r_point.toBytes();

    st = Sha512.init(.{});
    st.update(&r_bytes);
    st.update(&kp.public);
    st.update(msg);
    var h64: [64]u8 = undefined;
    st.final(&h64);
    const h = scalar.reduce64(h64);

    var sig: Signature = undefined;
    sig[0..32].* = r_bytes;
    sig[32..64].* = scalar.mulAdd(h, kp.scalar, r);
    return sig;
}

/// **XEdDSA Verify** (spec § "Verify", `verify(u, M, (R || s))`): given a
/// Montgomery (X25519) PUBLIC key `montgomery_pub` (the `u`-coordinate,
/// `std.crypto.dh.X25519.KeyPair.public_key`'s 32 bytes), check `sig`
/// over `msg`. Returns `false` on every failure path (malformed point,
/// non-canonical scalar or `u`, low-order key, mismatched challenge) —
/// never panics on attacker-controlled input.
///
/// 1. `A = convert_mont(u)` — `edwardsFromMontgomery`, the sign-0
///    reconstruction (`false` on any of its rejections).
/// 2. Reject the identity element and low-order `A` (`rejectIdentity`/
///    `rejectLowOrder` — the same defensive posture
///    `std.crypto.sign.Ed25519.Verifier`'s init applies to a native
///    Ed25519 public key; also catches `u = 0`, whose map image is the
///    order-2 point `(0, -1)`).
/// 3. Reject a non-canonical `s` (`s >= L` — strictly tighter than the
///    spec's own top-3-bits check, and what makes this module's
///    signatures non-malleable; also exactly the bit deployed libsignal's
///    variant abuses, so THAT variant's sign-1 signatures land here).
/// 4. `h = hash(R || A || M) mod L` — plain SHA-512, identical preimage
///    shape to `sign` step 4.
/// 5. `R_check = sB - hA` via the variable-time `mulDoubleBasePublic`
///    (public inputs only — same rationale as `adaptor.preVerify`).
/// 6. Accept iff `R_check` encodes to exactly `sig[0..32]` (the spec's
///    own cofactorless byte comparison — a non-canonical `R` encoding
///    therefore fails without ever being decoded).
pub fn verify(montgomery_pub: [32]u8, msg: []const u8, sig: Signature) bool {
    const a_point = edwardsFromMontgomery(montgomery_pub) catch return false;
    a_point.rejectIdentity() catch return false;
    a_point.rejectLowOrder() catch return false;
    const a_bytes = a_point.toBytes();

    const s = sig[32..64].*;
    scalar.rejectNonCanonical(s) catch return false;

    var st = Sha512.init(.{});
    st.update(sig[0..32]);
    st.update(&a_bytes);
    st.update(msg);
    var h64: [64]u8 = undefined;
    st.final(&h64);
    const h = scalar.reduce64(h64);

    // s*B + h*(-A); WeakPublicKey can only fire for a low-order A, which
    // step 2 already rejected — but keep the fail-closed catch anyway.
    const r_check = Edwards25519.basePoint.mulDoubleBasePublic(s, a_point.neg(), h) catch return false;
    return std.crypto.timing_safe.eql([32]u8, r_check.toBytes(), sig[0..32].*);
}

/// The `libsignal` variant's key derivation (spec § "Sign", `calculate_
/// key_pair(k)`, WITHOUT the sign-0 forcing step): clamp + wide-reduce the
/// Montgomery seed exactly like `calculateKeyPair`, but return the scalar
/// and public point AS-IS — no negate-if-sign-1 selection. `public`'s
/// compressed sign bit is therefore whatever the key naturally has
/// (0 or 1), which is exactly the bit `libsignal.sign` smuggles into
/// `s[31]` and `libsignal.verify` reads back out.
fn naturalKeyPair(montgomery_priv: [32]u8) struct {
    scalar: scalar.CompressedScalar,
    public: [32]u8,
} {
    var t = montgomery_priv;
    defer std.crypto.secureZero(u8, &t);
    scalar.clamp(&t);
    var k = scalar.reduce(t);
    defer std.crypto.secureZero(u8, &k);
    // Same degenerate-key posture as calculateKeyPair (see its comment):
    // unreachable for an honest key, not attacker-triggerable through
    // verify.
    // SECRET scalar — see `calculateKeyPair`.
    const e = ct25519.mulBase(k);
    return .{ .scalar = k, .public = e.toBytes() };
}

/// **Deployed libsignal's XEdDSA variant** (see the module doc comment
/// and `SPEC.md`'s "Spec variant, not deployed-libsignal variant"
/// section): libsignal-protocol-c/-java and the current Rust libsignal
/// (`curve25519.rs`) sign with the signer's NATURAL-sign Edwards point —
/// no forcing — and instead smuggle that sign bit into the
/// most-significant bit of `s` (`signature[63]`, always zero in a
/// canonical scalar since the group order `L < 2^253`, so the bit is free
/// to reuse). Byte-exactly interoperable with real Signal clients/
/// servers; NOT interoperable with the top-level `sign`/`verify` for a
/// sign-1 key (see `kat_test.zig`'s KAT block, which is the reason this
/// namespace exists rather than a silent default).
pub const libsignal = struct {
    /// `libsignal.sign(k, M, Z)`: identical construction to the top-level
    /// `sign` EXCEPT step 1 uses `naturalKeyPair` (no sign forcing) and
    /// the returned `s` has the natural public key's sign bit OR'd into
    /// its top bit before being returned. Because `mulAdd`'s result is
    /// always `< L < 2^253`, that bit is guaranteed zero beforehand, so
    /// OR-ing it in never collides with the scalar's own value — this is
    /// exactly the encoding `libsignal.verify` (and real Signal) expects.
    pub fn sign(montgomery_priv: [32]u8, msg: []const u8, z: RandomData) Signature {
        var kp = naturalKeyPair(montgomery_priv);
        defer std.crypto.secureZero(u8, &kp.scalar);
        const sign_bit: u8 = kp.public[31] >> 7;

        var st = Sha512.init(.{});
        st.update(&hash1_prefix);
        st.update(&kp.scalar);
        st.update(msg);
        st.update(&z);
        var r64: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &r64);
        st.final(&r64);
        var r = scalar.reduce64(r64);
        defer std.crypto.secureZero(u8, &r);

        // SECRET nonce — see the top-level `sign`.
        const r_point = ct25519.mulBase(r);
        const r_bytes = r_point.toBytes();

        st = Sha512.init(.{});
        st.update(&r_bytes);
        st.update(&kp.public);
        st.update(msg);
        var h64: [64]u8 = undefined;
        st.final(&h64);
        const h = scalar.reduce64(h64);

        var sig: Signature = undefined;
        sig[0..32].* = r_bytes;
        sig[32..64].* = scalar.mulAdd(h, kp.scalar, r);
        sig[63] |= sign_bit << 7;
        return sig;
    }

    /// `libsignal.verify(u, M, (R || s))`: same shape as the top-level
    /// `verify` except (a) the sign-0 point `edwardsFromMontgomery`
    /// recovers is conditionally negated back to the signer's NATURAL
    /// sign using the bit smuggled in `sig[63]`, and (b) that bit is
    /// masked off `s` before the canonicality check and the `sB - hA`
    /// equation, since it is not part of the scalar. Masking is
    /// mandatory, not optional decoration: skip it and a genuine sign-1
    /// signature's `s` reads as `>= 2^255 > L` and is wrongly rejected as
    /// non-canonical; mask unconditionally without reading the bit first
    /// (e.g. always clearing it) and a corrupted top bit on a sign-0
    /// signature would be silently ignored instead of changing which `A`
    /// is checked against.
    pub fn verify(montgomery_pub: [32]u8, msg: []const u8, sig: Signature) bool {
        const a_sign0 = edwardsFromMontgomery(montgomery_pub) catch return false;
        a_sign0.rejectIdentity() catch return false;
        a_sign0.rejectLowOrder() catch return false;

        const sign_bit: u8 = sig[63] >> 7;
        const a_point = if (sign_bit == 1) a_sign0.neg() else a_sign0;
        const a_bytes = a_point.toBytes();

        var s = sig[32..64].*;
        s[31] &= 0x7F;
        scalar.rejectNonCanonical(s) catch return false;

        var st = Sha512.init(.{});
        st.update(sig[0..32]);
        st.update(&a_bytes);
        st.update(msg);
        var h64: [64]u8 = undefined;
        st.final(&h64);
        const h = scalar.reduce64(h64);

        const r_check = Edwards25519.basePoint.mulDoubleBasePublic(s, a_point.neg(), h) catch return false;
        return std.crypto.timing_safe.eql([32]u8, r_check.toBytes(), sig[0..32].*);
    }
};

// ── dark-tests aggregator note ──────────────────────────────────────────
//
// This file's in-file tests cover the internal `calculateKeyPair` <->
// `edwardsFromMontgomery` sign-0 agreement and `naturalKeyPair` <->
// `libsignal.sign`/`verify` self-consistency (only reachable from inside
// this file, both self round-trips — no external anchor); the sign/verify
// round-trip, tamper-rejection, libsignal known-answer vector (the
// EXTERNAL anchor, exercised against both variants), and X3DH end-to-end
// tests live in `kat_test.zig` (imported by `root.zig`'s aggregator).

test "a clamped X25519 seed can NEVER reduce to 0 mod L (the panic that was not)" {
    // Both secret base multiplications used to end in
    // `Edwards25519.basePoint.mul(k) catch @panic(...)`, documented as a
    // "probability 2^-251" degenerate key. It is probability ZERO, and this
    // pins why — which matters, because the comment was the justification
    // for keeping a branch on a secret in the signing path.
    //
    // `scalar.clamp` clears the low 3 bits and forces bit 254 while clearing
    // bit 255, so a clamped seed `t` satisfies `2^254 <= t < 2^255` and
    // `t % 8 == 0`. `scalar.reduce(t) == 0` iff `t == m*L` for some integer
    // `m`; `L` is odd, so `8 | m*L` requires `8 | m`, and the smallest such
    // positive `m` is 8 — but `8L > 2^255`, above the clamped range, while
    // `m = 0` gives `t = 0`, below it. No clamped seed is in the set.
    const L: u256 = scalar.field_order;
    try std.testing.expect(L % 2 == 1); // odd, so 8 | m*L  =>  8 | m
    try std.testing.expect(8 * L > (1 << 255)); // the m = 8 case is out of range
    try std.testing.expect(L < (1 << 254)); // ...and m in 1..7 is below the range floor
    try std.testing.expect(7 * L < (1 << 255));

    // Empirically, over the structural extremes of the clamped range.
    const seeds = [_][32]u8{
        [_]u8{0x00} ** 32,
        [_]u8{0xff} ** 32,
        [_]u8{0x08} ++ [_]u8{0x00} ** 31,
        [_]u8{0x00} ** 31 ++ [_]u8{0xff},
    };
    for (seeds) |seed| {
        var t = seed;
        scalar.clamp(&t);
        const v = std.mem.readInt(u256, &t, .little);
        try std.testing.expect(v >= (1 << 254) and v < (1 << 255));
        try std.testing.expect(v % 8 == 0);
        try std.testing.expect(!std.mem.allEqual(u8, &scalar.reduce(t), 0));
    }
}

test "Signature/RandomData sizes match the XEdDSA wire shape" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(Signature));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(RandomData));
}

test "hash1_prefix is the little-endian encoding of 2^256 - 2 (spec's hash_1 domain)" {
    try std.testing.expectEqual(@as(usize, 32), hash1_prefix.len);
    try std.testing.expectEqual(@as(u8, 0xFE), hash1_prefix[0]);
    for (hash1_prefix[1..]) |b| try std.testing.expectEqual(@as(u8, 0xFF), b);
}

test "sign-0 convention agrees end-to-end: verify's recovered A == sign's forced A, both sign-bit branches" {
    // Deterministic seeds (no io needed): both natural-sign branches must
    // occur within a handful of seeds, and for EVERY seed the verifier-side
    // reconstruction from the Montgomery public key alone must equal the
    // signer-side sign-0-forced public key — the property the whole scheme
    // hangs on (a mismatch here is exactly the "round-trip fails" failure
    // mode the sign-bit convention can cause).
    var seen_sign_bit = [2]bool{ false, false };
    var seed_src: [64]u8 = undefined;
    var i: u8 = 0;
    while (i < 16) : (i += 1) {
        Sha512.hash(&[_]u8{ 'x', 'e', 'd', 'd', 's', 'a', i }, &seed_src, .{});
        const seed = seed_src[0..32].*;

        const kp = calculateKeyPair(seed);
        // Which branch did the natural (pre-forcing) point take?
        var t = seed;
        scalar.clamp(&t);
        const natural = (Edwards25519.basePoint.mul(scalar.reduce(t)) catch unreachable).toBytes();
        seen_sign_bit[natural[31] >> 7] = true;

        // The forced scalar really generates the forced public key.
        const regen = (Edwards25519.basePoint.mul(kp.scalar) catch unreachable).toBytes();
        try std.testing.expectEqualSlices(u8, &kp.public, &regen);
        try std.testing.expectEqual(@as(u8, 0), kp.public[31] >> 7);

        // And the verifier reconstructs the same A from u alone.
        const mont_pub = try std.crypto.dh.X25519.recoverPublicKey(seed);
        const recovered = try edwardsFromMontgomery(mont_pub);
        try std.testing.expectEqualSlices(u8, &kp.public, &recovered.toBytes());
    }
    try std.testing.expect(seen_sign_bit[0]);
    try std.testing.expect(seen_sign_bit[1]);
}

test "libsignal variant round-trips (self-consistency, both sign-bit branches) and s carries the natural sign bit" {
    // In-house re-derivation, not an external anchor (the libsignal KAT
    // vector's sign-1 anchor lives in kat_test.zig): confirms
    // naturalKeyPair's UNFORCED public point is exactly what
    // libsignal.sign/verify agree on, for both sign-bit branches, and
    // that the smuggled bit in s[63] matches the signer's natural sign.
    var seen_sign_bit = [2]bool{ false, false };
    var seed_src: [64]u8 = undefined;
    var z: RandomData = undefined;
    for (&z, 0..) |*b, i| b.* = @intCast(i);
    var i: u8 = 0;
    while (i < 16) : (i += 1) {
        Sha512.hash(&[_]u8{ 'x', 'e', 'd', 'd', 's', 'a', 'l', 's', i }, &seed_src, .{});
        const seed = seed_src[0..32].*;

        const kp = naturalKeyPair(seed);
        const natural_sign = kp.public[31] >> 7;
        seen_sign_bit[natural_sign] = true;

        const msg = "libsignal-variant self round-trip";
        const sig = libsignal.sign(seed, msg, z);
        try std.testing.expectEqual(natural_sign, sig[63] >> 7);
        try std.testing.expect(libsignal.verify((try std.crypto.dh.X25519.recoverPublicKey(seed)), msg, sig));

        // Tampering the smuggled sign bit alone (holding every other bit
        // of s fixed) must flip verification to false: it changes WHICH
        // A the equation checks against, not a harmless spare bit.
        var flipped = sig;
        flipped[63] ^= 0x80;
        try std.testing.expect(!libsignal.verify((try std.crypto.dh.X25519.recoverPublicKey(seed)), msg, flipped));
    }
    try std.testing.expect(seen_sign_bit[0]);
    try std.testing.expect(seen_sign_bit[1]);
}

test "edwardsFromMontgomery fail-closed edges: non-canonical u, pole u = p-1, twist u, identity/low-order map images" {
    // Non-canonical: top bit set.
    var bad = [_]u8{0} ** 32;
    bad[31] = 0x80;
    try std.testing.expectError(error.InvalidPublicKey, edwardsFromMontgomery(bad));
    // Non-canonical: u >= p (p itself: 0xed, 0xff*30, 0x7f).
    var p_bytes = [_]u8{0xFF} ** 32;
    p_bytes[0] = 0xED;
    p_bytes[31] = 0x7F;
    try std.testing.expectError(error.InvalidPublicKey, edwardsFromMontgomery(p_bytes));
    // Pole: u = p - 1.
    var p_minus_one = p_bytes;
    p_minus_one[0] = 0xEC;
    try std.testing.expectError(error.InvalidPublicKey, edwardsFromMontgomery(p_minus_one));
    // u on the quadratic twist: v^2 = u^3 + 486662*u^2 + u has no root, so
    // the mapped y has no x on Edwards25519 -> fromBytes rejects. Find one
    // by scanning small u (compute twist membership, don't hardcode it),
    // and check the complementary on-curve small u converts fine.
    var found_twist = false;
    var found_curve = false;
    var small: u8 = 2;
    while (small < 64 and !(found_twist and found_curve)) : (small += 1) {
        var u_bytes = [_]u8{0} ** 32;
        u_bytes[0] = small;
        const u = Fe.fromBytes(u_bytes);
        const rhs = u.sq().mul(u).add(Fe.edwards25519a.mul(u.sq())).add(u);
        if (rhs.isSquare()) {
            _ = try edwardsFromMontgomery(u_bytes);
            found_curve = true;
        } else {
            try std.testing.expectError(error.InvalidPublicKey, edwardsFromMontgomery(u_bytes));
            found_twist = true;
        }
    }
    try std.testing.expect(found_twist);
    try std.testing.expect(found_curve);
    // u = 0 maps to the order-2 point (0, -1): the CONVERSION succeeds
    // (it is a real point) — rejecting it is verify's step 2, not this
    // function's job.
    const zero_u = [_]u8{0} ** 32;
    const low_order = try edwardsFromMontgomery(zero_u);
    try std.testing.expectError(error.WeakPublicKey, low_order.rejectLowOrder());
}

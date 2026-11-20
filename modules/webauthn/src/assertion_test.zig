// SPDX-License-Identifier: MIT
//! assertion_test — `verifyAssertion` against the real W3C §16 vectors
//! (external, byte-exact anchor covering all three mandated algorithms:
//! ES256, EdDSA, RS256) plus the mandatory adversarial reject-teeth: every
//! one of the checks `verifyAssertion` performs must independently reject a
//! tampered input with the right typed error — a verifier that only
//! accepts valid inputs proves nothing.

const std = @import("std");
const testing = std.testing;
const webauthn = @import("root.zig");
const cbor = @import("cbor");
const vectors = @import("vectors.zig");

fn keyFromHex(a: std.mem.Allocator, cose_key_bytes: []const u8) !webauthn.CoseKey {
    const decoded = try cbor.decode(a, cose_key_bytes, .{});
    return webauthn.parseCredentialKey(decoded);
}

fn baseOptions(comptime v: type) webauthn.AssertionOptions {
    return .{
        .rp_id = vectors.rp_id,
        .expected_challenge = &v.assertion_challenge,
        .expected_origin = vectors.origin,
    };
}

// ── real-vector positive anchors (one per mandated algorithm) ──────────────

test "verifyAssertion: real W3C §16.2 vector (ES256, fmt=none)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    const result = try webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    );
    try testing.expect(result.user_present);
}

test "verifyAssertion: real W3C §16.3 vector (ES256, self-attested credential)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_self_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    _ = try webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    );
}

test "verifyAssertion: real W3C §16.10 vector (RS256)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_rs256;
    const key = try keyFromHex(a, &v.credential_public_key);
    try testing.expect(key == .rsa);

    _ = try webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    );
}

test "verifyAssertion: real W3C §16.11 vector (EdDSA)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_eddsa;
    const key = try keyFromHex(a, &v.credential_public_key);
    try testing.expect(key == .okp);

    _ = try webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    );
}

test "verifyAssertion: real W3C §16.16 vector (fido-u2f-registered credential, ES256 assertion)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.fido_u2f_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    _ = try webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    );
}

// ── adversarial reject-teeth ────────────────────────────────────────────────
// Each test starts from a REAL, independently-verified-good vector (above)
// and tampers exactly one input, proving the corresponding check is
// load-bearing (not dead code the happy path never exercises).

test "reject: tampered authenticatorData byte -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    var tampered = v.authenticator_data;
    tampered[35] ^= 0x01; // inside signCount, past rpIdHash+flags -> BadSignature not RpIdMismatch
    try testing.expectError(error.BadSignature, webauthn.verifyAssertion(
        a,
        &tampered,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    ));
}

test "reject: tampered signature byte -> BadSignature/InvalidSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    var tampered = v.signature;
    tampered[10] ^= 0xff;
    const err = webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &tampered,
        key,
        baseOptions(v),
    );
    try testing.expect(err == error.BadSignature or err == error.InvalidSignature);
}

// Both reject-teeth above run through the ES256 arm of `verifySignature`. The
// RS256 and EdDSA arms had positive vectors only, so the whole suite stayed
// green against an implementation that discarded their verify results
// (confirmed by mutation). These two are the missing per-algorithm teeth: the
// tampered byte sits in signCount — inside the signed message, but past
// rpIdHash and the flags — so only the signature check can reject it.

test "reject: tampered authenticatorData byte, RS256 credential -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_rs256;
    const key = try keyFromHex(a, &v.credential_public_key);
    try testing.expect(key == .rsa); // the RSA arm, not ES256, is what runs here

    var tampered = v.authenticator_data;
    tampered[35] ^= 0x01;
    try testing.expectError(error.BadSignature, webauthn.verifyAssertion(
        a,
        &tampered,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    ));
}

test "reject: tampered authenticatorData byte, EdDSA credential -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_eddsa;
    const key = try keyFromHex(a, &v.credential_public_key);
    try testing.expect(key == .okp); // the Ed25519 arm, not ES256, is what runs here

    var tampered = v.authenticator_data;
    tampered[35] ^= 0x01;
    try testing.expectError(error.BadSignature, webauthn.verifyAssertion(
        a,
        &tampered,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    ));
}

test "reject: wrong rpId -> RpIdMismatch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    var opts = baseOptions(v);
    opts.rp_id = "attacker.example";
    try testing.expectError(error.RpIdMismatch, webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        opts,
    ));
}

test "reject: User Present flag clear -> UserNotPresent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    var tampered = v.authenticator_data;
    tampered[32] &= ~@as(u8, 0x01); // clear UP bit (bit 0)
    try testing.expectError(error.UserNotPresent, webauthn.verifyAssertion(
        a,
        &tampered,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        baseOptions(v),
    ));
}

test "reject: wrong challenge -> ChallengeMismatch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    var opts = baseOptions(v);
    opts.expected_challenge = "not the challenge that was issued";
    try testing.expectError(error.ChallengeMismatch, webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        opts,
    ));
}

test "reject: wrong origin -> OriginMismatch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    var opts = baseOptions(v);
    opts.expected_origin = "https://evil.example";
    try testing.expectError(error.OriginMismatch, webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        opts,
    ));
}

test "reject: wrong type (clientDataJSON from a registration, not an assertion) -> TypeMismatch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    var opts = baseOptions(v);
    opts.expected_challenge = &v.registration_challenge;
    try testing.expectError(error.TypeMismatch, webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.registration_client_data_json, // type == "webauthn.create", not "webauthn.get"
        &v.signature,
        key,
        opts,
    ));
}

test "reject: wrong key algorithm family (EdDSA key against an ES256 assertion)" {
    // The alg used comes from the KEY itself (`CoseKey.alg()`), not an
    // externally-asserted value -- an EdDSA key is internally self-
    // consistent (crv==Ed25519, alg==EdDSA), so `verifySignature` proceeds
    // into the Ed25519 path and rejects there: the DER-encoded ~70-byte
    // ES256 signature is not a valid 64-byte Ed25519 signature. Either way
    // the credential is rejected with a typed, non-panicking error -- this
    // proves an attacker cannot swap in an unrelated credential's key and
    // have a foreign-format signature accepted.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256; // ES256 assertion
    const wrong_key = try keyFromHex(a, &vectors.packed_eddsa.credential_public_key); // EdDSA/OKP key

    const err = webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        wrong_key,
        baseOptions(v),
    );
    try testing.expect(err == error.UnsupportedAlgorithm or err == error.InvalidSignature or err == error.BadSignature);
}

test "reject: correct key but wrong credential's signature (cross-credential swap) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // ES256 authData/clientData from none_es256, but the KEY from a
    // different ES256 credential (packed_self_es256) -- same algorithm
    // family, wrong actual key, must still fail.
    const v = vectors.none_es256;
    const wrong_key = try keyFromHex(a, &vectors.packed_self_es256.credential_public_key);

    try testing.expectError(error.BadSignature, webauthn.verifyAssertion(
        a,
        &v.authenticator_data,
        &v.assertion_client_data_json,
        &v.signature,
        wrong_key,
        baseOptions(v),
    ));
}

test "reject: require_user_verification with UV clear -> UserNotVerified" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const key = try keyFromHex(a, &v.credential_public_key);

    // none_es256's assertion authData flags byte is 0x19 = UP|UV|BE... check
    // the real UV bit; if it happens to already be clear this still proves
    // the gate (require_user_verification=true must reject a UV-clear
    // authenticatorData). We force it clear explicitly either way.
    var tampered = v.authenticator_data;
    tampered[32] &= ~@as(u8, 0x04); // clear UV bit (bit 2)

    var opts = baseOptions(v);
    opts.require_user_verification = true;
    try testing.expectError(error.UserNotVerified, webauthn.verifyAssertion(
        a,
        &tampered,
        &v.assertion_client_data_json,
        &v.signature,
        key,
        opts,
    ));
}

// ── ES384 / ES512 (COSE -35 / -36) ─────────────────────────────
// No external vector: the W3C §16 set has no P-384/P-521 credential. Keys and
// signatures are generated in-test through the sibling `p384` / `p521`
// modules (whose own verifiers are KAT/Wycheproof-anchored there).

const p384 = @import("p384");
const p521 = @import("p521");

fn ec2Key(alg: i64, crv: i64, sec1: []const u8) webauthn.CoseKey {
    const n = (sec1.len - 1) / 2;
    return .{ .ec2 = .{ .alg = alg, .crv = crv, .x = sec1[1..][0..n], .y = sec1[1 + n ..][0..n] } };
}

test "verifySignature: ES384 (P-384) round trip, tampering and mismatches" {
    const kp = try p384.EcdsaP384Sha384.KeyPair.generateDeterministic(@as([48]u8, @splat(0x21)));
    const sec1 = kp.public_key.toUncompressedSec1();
    const key = ec2Key(cbor.cose.alg_es384, cbor.cose.crv_p384, &sec1);
    const msg = "authenticatorData || clientDataHash";
    var dbuf: [p384.EcdsaP384Sha384.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (try kp.sign(msg, null)).toDer(&dbuf);
    try webauthn.verifySignature(key, cbor.cose.alg_es384, msg, sig);

    // wrong message / flipped signature byte / truncated signature
    try testing.expectError(error.BadSignature, webauthn.verifySignature(key, cbor.cose.alg_es384, "other", sig));
    var bad: [dbuf.len]u8 = dbuf;
    bad[sig.len - 3] ^= 1;
    try testing.expectError(error.BadSignature, webauthn.verifySignature(key, cbor.cose.alg_es384, msg, bad[0..sig.len]));
    try testing.expectError(error.InvalidSignature, webauthn.verifySignature(key, cbor.cose.alg_es384, msg, sig[0..3]));

    // algorithm confusion: alg/crv must pair exactly
    try testing.expectError(error.UnsupportedAlgorithm, webauthn.verifySignature(key, cbor.cose.alg_es256, msg, sig));
    try testing.expectError(error.UnsupportedAlgorithm, webauthn.verifySignature(key, cbor.cose.alg_es512, msg, sig));
    const wrong_crv = ec2Key(cbor.cose.alg_es384, cbor.cose.crv_p256, &sec1);
    try testing.expectError(error.UnsupportedAlgorithm, webauthn.verifySignature(wrong_crv, cbor.cose.alg_es384, msg, sig));
    const wrong_crv2 = ec2Key(cbor.cose.alg_es384, cbor.cose.crv_p521, &sec1);
    try testing.expectError(error.UnsupportedAlgorithm, webauthn.verifySignature(wrong_crv2, cbor.cose.alg_es384, msg, sig));

    // coordinates of the wrong length, and a point not on the curve
    var short = key;
    short.ec2.x = sec1[1..47];
    try testing.expectError(error.InvalidKey, webauthn.verifySignature(short, cbor.cose.alg_es384, msg, sig));
    var off = sec1;
    off[97 - 1] ^= 1;
    try testing.expectError(error.InvalidKey, webauthn.verifySignature(ec2Key(cbor.cose.alg_es384, cbor.cose.crv_p384, &off), cbor.cose.alg_es384, msg, sig));
}

test "verifySignature: ES512 (P-521) round trip, tampering and mismatches" {
    const kp = try p521.EcdsaP521Sha512.KeyPair.generateDeterministic(@as([66]u8, @splat(0x22)));
    const sec1 = kp.public_key.toUncompressedSec1();
    const key = ec2Key(cbor.cose.alg_es512, cbor.cose.crv_p521, &sec1);
    const msg = "authenticatorData || clientDataHash";
    var dbuf: [p521.EcdsaP521Sha512.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (try kp.sign(msg, null)).toDer(&dbuf);
    try webauthn.verifySignature(key, cbor.cose.alg_es512, msg, sig);

    try testing.expectError(error.BadSignature, webauthn.verifySignature(key, cbor.cose.alg_es512, "other", sig));
    var bad: [dbuf.len]u8 = dbuf;
    bad[sig.len - 3] ^= 1;
    try testing.expectError(error.BadSignature, webauthn.verifySignature(key, cbor.cose.alg_es512, msg, bad[0..sig.len]));

    try testing.expectError(error.UnsupportedAlgorithm, webauthn.verifySignature(key, cbor.cose.alg_es384, msg, sig));
    try testing.expectError(error.UnsupportedAlgorithm, webauthn.verifySignature(key, cbor.cose.alg_es256, msg, sig));
    const wrong_crv = ec2Key(cbor.cose.alg_es512, cbor.cose.crv_p384, &sec1);
    try testing.expectError(error.UnsupportedAlgorithm, webauthn.verifySignature(wrong_crv, cbor.cose.alg_es512, msg, sig));
    var short = key;
    short.ec2.y = sec1[67..130];
    try testing.expectError(error.InvalidKey, webauthn.verifySignature(short, cbor.cose.alg_es512, msg, sig));
}

test "verifyAssertion: ES384 credential, built assertion accepted; tampered authData refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = try p384.EcdsaP384Sha384.KeyPair.generateDeterministic(@as([48]u8, @splat(0x23)));
    const sec1 = kp.public_key.toUncompressedSec1();
    const key = ec2Key(cbor.cose.alg_es384, cbor.cose.crv_p384, &sec1);

    var auth: [37]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(vectors.rp_id, auth[0..32], .{});
    auth[32] = 0x01; // UP
    @memset(auth[33..37], 0);
    auth[36] = 7;
    const cdj = try std.fmt.allocPrint(a, "{{\"type\":\"webauthn.get\",\"challenge\":\"Y2hhbGxlbmdl\",\"origin\":\"{s}\"}}", .{vectors.origin});
    var signed: [37 + 32]u8 = undefined;
    @memcpy(signed[0..37], &auth);
    std.crypto.hash.sha2.Sha256.hash(cdj, signed[37..69], .{});
    var dbuf: [p384.EcdsaP384Sha384.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (try kp.sign(&signed, null)).toDer(&dbuf);
    const opts: webauthn.AssertionOptions = .{ .rp_id = vectors.rp_id, .expected_challenge = "challenge", .expected_origin = vectors.origin };

    const r = try webauthn.verifyAssertion(a, &auth, cdj, sig, key, opts);
    try testing.expect(r.user_present);

    var bad_auth = auth;
    bad_auth[36] = 8; // signCount changed after signing
    try testing.expectError(error.BadSignature, webauthn.verifyAssertion(a, &bad_auth, cdj, sig, key, opts));
}

// ── whole-module mutation run: the result fields and a key without an alg ──

/// A self-made ES256 assertion over a chosen authenticatorData flags byte and
/// signCount; the W3C corpus has every signCount at or near zero and no key
/// without an `alg`, so the result fields and `MissingAlgorithm` were unpinned.
fn selfSignedAssertion(a: std.mem.Allocator, flags: u8, sign_count: u32) !struct { auth: []u8, cdj: []const u8, sig: []const u8, key: webauthn.CoseKey } {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const kp = try Ecdsa.KeyPair.generateDeterministic(@as([Ecdsa.KeyPair.seed_length]u8, @splat(5)));
    const pub_sec1 = kp.public_key.toUncompressedSec1();
    const auth = try a.alloc(u8, 37);
    std.crypto.hash.sha2.Sha256.hash(vectors.rp_id, auth[0..32], .{});
    auth[32] = flags;
    std.mem.writeInt(u32, auth[33..37], sign_count, .big);
    const cdj = try std.fmt.allocPrint(a, "{{\"type\":\"webauthn.get\",\"challenge\":\"AQID\",\"origin\":\"{s}\"}}", .{vectors.origin});
    const signed = try a.alloc(u8, 69);
    @memcpy(signed[0..37], auth);
    std.crypto.hash.sha2.Sha256.hash(cdj, signed[37..69], .{});
    const dbuf = try a.alloc(u8, Ecdsa.Signature.der_encoded_length_max);
    const sig = (try kp.sign(signed, null)).toDer(dbuf[0..Ecdsa.Signature.der_encoded_length_max]);
    return .{
        .auth = auth,
        .cdj = cdj,
        .sig = sig,
        .key = .{ .ec2 = .{ .alg = cbor.cose.alg_es256, .crv = cbor.cose.crv_p256, .x = try a.dupe(u8, pub_sec1[1..33]), .y = try a.dupe(u8, pub_sec1[33..65]) } },
    };
}

test "verifyAssertion: signCount and the UV flag are reported as the authenticator sent them" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const opts: webauthn.AssertionOptions = .{ .rp_id = vectors.rp_id, .expected_challenge = &.{ 1, 2, 3 }, .expected_origin = vectors.origin };

    const uv = try selfSignedAssertion(a, 0x05, 0x01020304); // UP | UV
    const r1 = try webauthn.verifyAssertion(a, uv.auth, uv.cdj, uv.sig, uv.key, opts);
    try testing.expectEqual(@as(u32, 0x01020304), r1.sign_count);
    try testing.expect(r1.user_present);
    try testing.expect(r1.user_verified);

    const up = try selfSignedAssertion(a, 0x01, 9); // UP only, UV not required
    const r2 = try webauthn.verifyAssertion(a, up.auth, up.cdj, up.sig, up.key, opts);
    try testing.expectEqual(@as(u32, 9), r2.sign_count);
    try testing.expect(r2.user_present);
    try testing.expect(!r2.user_verified);
}

test "verifyAssertion: a credential key without an alg is MissingAlgorithm, not a guess" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const opts: webauthn.AssertionOptions = .{ .rp_id = vectors.rp_id, .expected_challenge = &.{ 1, 2, 3 }, .expected_origin = vectors.origin };
    var s = try selfSignedAssertion(a, 0x01, 1);
    s.key.ec2.alg = null;
    try testing.expectError(error.MissingAlgorithm, webauthn.verifyAssertion(a, s.auth, s.cdj, s.sig, s.key, opts));
}

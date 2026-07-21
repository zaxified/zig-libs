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

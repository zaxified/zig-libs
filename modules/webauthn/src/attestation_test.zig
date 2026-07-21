// SPDX-License-Identifier: MIT
//! attestation_test — `verifyAttestation` against the real W3C §16 vectors
//! (external, byte-exact anchor covering `none`, `packed` self-attestation,
//! `packed` x5c/basic attestation for all three mandated algorithms, and
//! `fido-u2f`), plus adversarial reject-teeth and the `tpm`/`android-key`
//! DEFER-as-unsupported structural check.

const std = @import("std");
const testing = std.testing;
const webauthn = @import("root.zig");
const cbor = @import("cbor");
const vectors = @import("vectors.zig");

fn clientDataHash(client_data_json: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(client_data_json, &h, .{});
    return h;
}

/// Generic extraction of the raw `authData` bytes out of a real
/// `attestationObject` (for hand-building a synthetic attestationObject
/// with a bogus `fmt`/`attStmt` around a REAL authData, for the reject
/// tests below) -- decodes via `cbor.decode` rather than guessing a byte
/// offset, so it stays correct regardless of a given vector's credential
/// ID length / key size.
fn extractAuthDataRaw(a: std.mem.Allocator, attestation_object: []const u8) ![]const u8 {
    const decoded = try cbor.decode(a, attestation_object, .{});
    const entries = decoded.map;
    for (entries) |e| {
        switch (e.key) {
            .text => |t| if (std.mem.eql(u8, t, "authData")) return e.value.bytes,
            else => {},
        }
    }
    return error.MissingField;
}

// ── real-vector positive anchors ────────────────────────────────────────────

test "verifyAttestation: real W3C §16.2 vector (fmt=none)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.none_es256;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.none, result.attestation_type);
    try testing.expectEqualStrings("none", result.format);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
}

test "verifyAttestation: real W3C §16.3 vector (fmt=packed, self attestation)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_self_es256;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.self_attestation, result.attestation_type);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
}

test "verifyAttestation: real W3C §16.7 vector (fmt=packed, x5c/basic, ES256)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const hash = clientDataHash(&v.registration_client_data_json);
    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.basic, result.attestation_type);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
    try testing.expect(result.credential_public_key == .ec2);
}

test "verifyAttestation: real W3C §16.10 vector (fmt=packed, x5c/basic, RS256 credential)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_rs256;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.basic, result.attestation_type);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
    // The attestation statement itself is signed by the CA's EC key (per
    // the spec preamble, all examples share one attestation CA), but the
    // extracted CREDENTIAL key must be the RSA key from authData.
    try testing.expect(result.credential_public_key == .rsa);
}

test "verifyAttestation: real W3C §16.11 vector (fmt=packed, x5c/basic, EdDSA credential)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_eddsa;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.basic, result.attestation_type);
    try testing.expect(result.credential_public_key == .okp);
}

test "verifyAttestation: real W3C §16.16 vector (fmt=fido-u2f)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.fido_u2f_es256;
    const hash = clientDataHash(&v.registration_client_data_json);

    const result = try webauthn.verifyAttestation(a, &v.attestation_object, hash);
    try testing.expectEqual(webauthn.AttestationType.basic, result.attestation_type);
    try testing.expectEqualSlices(u8, &v.credential_id, result.credential_id);
    try testing.expect(result.credential_public_key == .ec2);
}

// ── deferred formats: structurally recognized and rejected ─────────────────

test "verifyAttestation: fmt=tpm -> error.UnsupportedFormat (deferred, not half-verified)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // clientDataHash content is irrelevant here -- fmt dispatch happens
    // before any signature is touched.
    const hash: [32]u8 = @splat(0);
    try testing.expectError(error.UnsupportedFormat, webauthn.verifyAttestation(a, &vectors.tpm_es256_attestation_object, hash));
}

test "verifyAttestation: fmt=android-key -> error.UnsupportedFormat (deferred, not half-verified)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const hash: [32]u8 = @splat(0);
    try testing.expectError(error.UnsupportedFormat, webauthn.verifyAttestation(a, &vectors.android_key_es256_attestation_object, hash));
}

// ── adversarial reject-teeth ────────────────────────────────────────────────

test "reject: wrong clientDataHash (packed x5c) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const wrong_hash: [32]u8 = @splat(0xAA);

    try testing.expectError(error.BadSignature, webauthn.verifyAttestation(a, &v.attestation_object, wrong_hash));
}

test "reject: wrong clientDataHash (fido-u2f) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.fido_u2f_es256;
    const wrong_hash: [32]u8 = @splat(0xAA);

    try testing.expectError(error.BadSignature, webauthn.verifyAttestation(a, &v.attestation_object, wrong_hash));
}

test "reject: wrong clientDataHash (packed x5c, RS256 credential) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_rs256;
    const wrong_hash: [32]u8 = @splat(0xAA);

    try testing.expectError(error.BadSignature, webauthn.verifyAttestation(a, &v.attestation_object, wrong_hash));
}

test "reject: tampered attStmt.sig byte (packed x5c) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const hash = clientDataHash(&v.registration_client_data_json);

    var tampered = v.attestation_object;
    // The DER ECDSA signature bytes start right after the CBOR "sig" key +
    // length header, well before the x5c certificate -- flip a byte deep
    // inside that region (byte 40, comfortably inside attStmt.sig).
    tampered[40] ^= 0xff;
    const err = webauthn.verifyAttestation(a, &tampered, hash);
    try testing.expect(err == error.BadSignature or err == error.InvalidSignature);
}

test "reject: tampered attStmt.sig byte (fido-u2f) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.fido_u2f_es256;
    const hash = clientDataHash(&v.registration_client_data_json);

    var tampered = v.attestation_object;
    tampered[40] ^= 0xff;
    const err = webauthn.verifyAttestation(a, &tampered, hash);
    try testing.expect(err == error.BadSignature or err == error.InvalidSignature);
}

test "reject: tampered authData byte inside attestationObject (packed) -> BadSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = vectors.packed_es256_full;
    const hash = clientDataHash(&v.registration_client_data_json);

    var tampered = v.attestation_object;
    // Flip the last byte of the whole attestationObject -- for this vector
    // that lands inside the credential public key's trailing coordinate
    // byte, which is part of authData and therefore part of the signed
    // `authData || clientDataHash` message.
    tampered[tampered.len - 1] ^= 0xff;
    try testing.expectError(error.BadSignature, webauthn.verifyAttestation(a, &tampered, hash));
}

test "reject: fmt=none with non-empty attStmt -> InvalidAttestationStatement" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Hand-build {fmt:"none", attStmt:{"x":1}, authData:<real authData>} --
    // a "none" attestation is REQUIRED to carry an empty attStmt map
    // (WebAuthn §8.7); a non-empty one must be rejected, not silently
    // accepted as if it were legitimately empty.
    const v = vectors.none_es256;
    const auth_data_bytes = try extractAuthDataRaw(a, &v.attestation_object);
    const bogus_entries = [_]cbor.MapEntry{.{ .key = .{ .text = "x" }, .value = .{ .uint = 1 } }};
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .text = "fmt" }, .value = .{ .text = "none" } },
        .{ .key = .{ .text = "attStmt" }, .value = .{ .map = &bogus_entries } },
        .{ .key = .{ .text = "authData" }, .value = .{ .bytes = auth_data_bytes } },
    };
    const built = try cbor.encode(a, .{ .map = &entries }, .{});

    const hash = clientDataHash(&v.registration_client_data_json);
    try testing.expectError(error.InvalidAttestationStatement, webauthn.verifyAttestation(a, built, hash));
}

test "reject: unknown fmt string -> UnsupportedFormat" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const v = vectors.none_es256;
    const auth_data_bytes = try extractAuthDataRaw(a, &v.attestation_object);
    const empty = [_]cbor.MapEntry{};
    const entries = [_]cbor.MapEntry{
        .{ .key = .{ .text = "fmt" }, .value = .{ .text = "totally-made-up-format" } },
        .{ .key = .{ .text = "attStmt" }, .value = .{ .map = &empty } },
        .{ .key = .{ .text = "authData" }, .value = .{ .bytes = auth_data_bytes } },
    };
    const built = try cbor.encode(a, .{ .map = &entries }, .{});

    const hash = clientDataHash(&v.registration_client_data_json);
    try testing.expectError(error.UnsupportedFormat, webauthn.verifyAttestation(a, built, hash));
}

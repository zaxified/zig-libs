// SPDX-License-Identifier: MIT
//! Byte-exact KAT tests against real `minisign`-generated fixtures (see
//! `kat_vectors.zig` for provenance). These are the primary evidence this
//! module is wire-compatible: round-trip tests alone would only prove
//! self-consistency, not compatibility with the reference implementation.

const std = @import("std");
const m = @import("root.zig");
const kat = @import("kat_vectors.zig");

test "prehashed KAT: parse + verify a real minisign signature" {
    const pub_key = try m.parsePublicKeyFile(kat.unencrypted_public_key_file);
    try std.testing.expectEqualStrings("minisign public key 5903374ED1B3A96B", pub_key.untrusted_comment);

    const parsed = try m.parseSignatureFile(kat.prehashed_signature_file);
    try std.testing.expectEqual(m.Algorithm.prehashed, parsed.algorithm);
    try std.testing.expectEqualStrings("untrusted comment test 1", parsed.untrusted_comment);
    try std.testing.expectEqualStrings("trusted comment test 1", parsed.trusted_comment);

    try m.verifyFile(std.testing.allocator, pub_key.key, kat.message, parsed);
}

test "legacy KAT: parse + verify a real minisign signature" {
    const pub_key = try m.parsePublicKeyFile(kat.unencrypted_public_key_file);
    const parsed = try m.parseSignatureFile(kat.legacy_signature_file);
    try std.testing.expectEqual(m.Algorithm.legacy, parsed.algorithm);

    try m.verifyFile(std.testing.allocator, pub_key.key, kat.message, parsed);
}

test "encrypted-key KAT: parse + verify a real minisign signature" {
    const pub_key = try m.parsePublicKeyFile(kat.encrypted_public_key_file);
    const parsed = try m.parseSignatureFile(kat.encrypted_key_signature_file);
    try std.testing.expectEqual(m.Algorithm.prehashed, parsed.algorithm);

    try m.verifyFile(std.testing.allocator, pub_key.key, kat.message, parsed);
}

test "byte-exact re-sign: unencrypted key reproduces the real minisign output bit-for-bit" {
    const gpa = std.testing.allocator;
    const pub_key = try m.parsePublicKeyFile(kat.unencrypted_public_key_file);
    const sec_key = try m.parseSecretKeyFile(kat.unencrypted_secret_key_file);
    const kp = try m.openSecretKey(gpa, sec_key.key, null);
    try std.testing.expectEqual(pub_key.key.key_number, kp.key_number);
    try std.testing.expectEqual(pub_key.key.key, kp.ed25519.public_key.toBytes());

    {
        const expect = try m.parseSignatureFile(kat.prehashed_signature_file);
        const signed = try m.signFile(gpa, kp, kat.message, .prehashed, "trusted comment test 1");
        try std.testing.expectEqual(expect.signature, signed.signature);
        try std.testing.expectEqual(expect.global_signature, signed.global_signature);
    }
    {
        const expect = try m.parseSignatureFile(kat.legacy_signature_file);
        const signed = try m.signFile(gpa, kp, kat.message, .legacy, "trusted comment test 1");
        try std.testing.expectEqual(expect.signature, signed.signature);
        try std.testing.expectEqual(expect.global_signature, signed.global_signature);
    }
}

test "byte-exact re-sign: real password decrypts the real encrypted key and reproduces its signature" {
    const gpa = std.testing.allocator;
    const pub_key = try m.parsePublicKeyFile(kat.encrypted_public_key_file);
    const sec_key = try m.parseSecretKeyFile(kat.encrypted_secret_key_file);
    try std.testing.expectEqualSlices(u8, &m.kdf_alg_scrypt, &sec_key.key.kdf_alg);
    try std.testing.expectEqual(m.ops_limit_sensitive, sec_key.key.ops_limit);
    try std.testing.expectEqual(@as(u64, m.mem_limit_sensitive), sec_key.key.mem_limit);

    const kp = try m.openSecretKey(gpa, sec_key.key, kat.encrypted_secret_key_password);
    try std.testing.expectEqual(pub_key.key.key_number, kp.key_number);
    try std.testing.expectEqual(pub_key.key.key, kp.ed25519.public_key.toBytes());

    const expect = try m.parseSignatureFile(kat.encrypted_key_signature_file);
    const signed = try m.signFile(gpa, kp, kat.message, .prehashed, "trusted comment test 2");
    try std.testing.expectEqual(expect.signature, signed.signature);
    try std.testing.expectEqual(expect.global_signature, signed.global_signature);
}

test "negative: wrong password on the real encrypted key is rejected" {
    const gpa = std.testing.allocator;
    const sec_key = try m.parseSecretKeyFile(kat.encrypted_secret_key_file);
    try std.testing.expectError(error.WrongPassword, m.openSecretKey(gpa, sec_key.key, "not the password"));
    try std.testing.expectError(error.PasswordRequired, m.openSecretKey(gpa, sec_key.key, null));
}

test "negative: tampered payload fails verification of a real signature" {
    const pub_key = try m.parsePublicKeyFile(kat.unencrypted_public_key_file);
    const parsed = try m.parseSignatureFile(kat.prehashed_signature_file);

    const tampered = "Hello, minisign!\nThis is a TAMPERED file for byte-exact KAT vectors.\n";
    try std.testing.expectError(error.SignatureVerificationFailed, m.verifyMessage(pub_key.key, tampered, parsed.signature));
}

test "negative: tampered trusted comment fails verification of a real signature" {
    const gpa = std.testing.allocator;
    const pub_key = try m.parsePublicKeyFile(kat.unencrypted_public_key_file);
    const parsed = try m.parseSignatureFile(kat.prehashed_signature_file);

    // The message/key-id layer alone still checks out ...
    try m.verifyMessage(pub_key.key, kat.message, parsed.signature);
    // ... but the trusted comment was swapped for a different (still
    // printable) string, so the global signature must not validate it.
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        m.verifyTrustedComment(gpa, pub_key.key, parsed.signature, "a different trusted comment", parsed.global_signature),
    );
}

test "negative: wrong key id is rejected before signature math" {
    var pub_key = (try m.parsePublicKeyFile(kat.unencrypted_public_key_file)).key;
    const parsed = try m.parseSignatureFile(kat.prehashed_signature_file);
    pub_key.key_number[0] ^= 0xff; // now mismatches the real signature's key id
    try std.testing.expectError(error.KeyIdMismatch, m.verifyMessage(pub_key, kat.message, parsed.signature));
}

test "negative: truncated signature file (missing lines / cut mid-base64)" {
    const full = kat.prehashed_signature_file;
    const nl1 = std.mem.indexOfScalar(u8, full, '\n').?;
    const nl2 = std.mem.indexOfScalarPos(u8, full, nl1 + 1, '\n').?;
    const nl3 = std.mem.indexOfScalarPos(u8, full, nl2 + 1, '\n').?;

    // Cut right after the untrusted-comment line's own newline: the b64
    // signature "line" the iterator sees is an empty trailing segment, not
    // an absent one — a length mismatch, not a missing line.
    try std.testing.expectError(error.WrongLength, m.parseSignatureFile(full[0 .. nl1 + 1]));

    // Cut with NO trailing newline right after the signature line's content
    // (before the trusted-comment line even starts): the iterator has
    // truly run out of lines here.
    try std.testing.expectError(error.MissingLine, m.parseSignatureFile(full[0..nl2]));

    // Cut right after the trusted-comment line's own newline: the global
    // signature "line" is again an empty trailing segment.
    try std.testing.expectError(error.WrongLength, m.parseSignatureFile(full[0 .. nl3 + 1]));

    // Whole file truncated by exactly two bytes (corrupts the last base64
    // line's length without removing a whole line).
    try std.testing.expectError(error.WrongLength, m.parseSignatureFile(full[0 .. full.len - 2]));
}

test "negative: truncated / empty public key and secret key files" {
    // Trailing newline after the comment line -> the b64 "line" is an empty
    // trailing segment (WrongLength), not a genuinely absent one.
    try std.testing.expectError(error.WrongLength, m.parsePublicKeyFile("untrusted comment: only one line\n"));
    // No trailing newline at all -> the b64 line is truly absent.
    try std.testing.expectError(error.MissingLine, m.parsePublicKeyFile("untrusted comment: only one line"));
    try std.testing.expectError(error.MissingUntrustedCommentPrefix, m.parseSecretKeyFile(""));

    const pub_line1_end = std.mem.indexOfScalar(u8, kat.unencrypted_public_key_file, '\n').? + 1;
    try std.testing.expectError(error.WrongLength, m.parsePublicKeyFile(kat.unencrypted_public_key_file[0..pub_line1_end]));
}

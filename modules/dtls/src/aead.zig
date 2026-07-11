// SPDX-License-Identifier: MIT

//! dtls.aead — RFC 9147 §4.2 record protection: AEAD seal/open with the
//! DTLS-specific per-record nonce (§4.2.2) and sequence-number encryption
//! (§4.2.3). Real, KAT-validated against OpenSSL (via the `cryptography`
//! package) for the nonce/AEAD/mask constructions.
//!
//! **Cipher-suite coverage.** `Protection(comptime Aead)` is generic over
//! any std AEAD with the standard `encrypt`/`decrypt` signature. It is wired
//! and validated for the two 12-byte-nonce TLS 1.3 suites std ships that are
//! byte-checkable against OpenSSL: `aes_gcm.Aes128Gcm` /
//! `aes_gcm.Aes256Gcm` and `chacha_poly.ChaCha20Poly1305`.
//!
//! **AES-CCM caveat (honest).** DTLS/TLS 1.3 mandate a 12-byte AEAD nonce.
//! Zig 0.16 std's CCM PRESETS (`aes_ccm.Aes128Ccm8`, etc.) are all fixed at
//! a 13-byte nonce and the parametric `AesCcm(...)` generator is private, so
//! there is NO way to instantiate a 12-byte-nonce CCM from std presets. The
//! `AES_128_CCM_8_SHA256` suite (RFC 7925's CoAP default) therefore CANNOT
//! be driven correctly through `Protection(Aes128Ccm8)` — its 13-byte nonce
//! would break interop. Rather than silently ship a wrong-width nonce, CCM
//! is left UNWIRED here: a 12-byte-nonce CCM (own port, or a future std that
//! exposes the generic) is required first. This corrects the scaffold's
//! recon note, which said "AES-CCM is NOT a std gap" — true for a 13-byte
//! nonce, but the TLS/DTLS profile needs 12.

const std = @import("std");

pub const RecordProtectionError = error{
    DecryptionFailed,
    RecordTooShort,
    BufferTooShort,
};

/// Binds one AEAD type to RFC 9147 §4.2's record-protection operations.
pub fn Protection(comptime Aead: type) type {
    return struct {
        pub const key_length = Aead.key_length;
        pub const nonce_length = Aead.nonce_length;
        pub const tag_length = Aead.tag_length;

        comptime {
            // The DTLS/TLS 1.3 static IV ("iv" label) and the per-record
            // nonce are the AEAD's full nonce width; the profile requires 12.
            if (nonce_length != 12) @compileError(
                "dtls: TLS/DTLS 1.3 record protection requires a 12-byte AEAD nonce; " ++
                    @typeName(Aead) ++ " has a different nonce_length (see the AES-CCM caveat in aead.zig)",
            );
        }

        /// RFC 9147 §4.2.2: the per-record nonce is `static_iv XOR
        /// left_pad(sequence_number)` — the 64-bit sequence number placed in
        /// the LOW-order (rightmost) 8 bytes of a zero field the width of the
        /// nonce, XORed into the static IV. Per §4.2.2 the epoch is
        /// DELIBERATELY NOT mixed into the nonce ("unlike DTLS 1.2, the epoch
        /// is not included"); `epoch` is accepted for API symmetry with the
        /// record header but does not affect the nonce.
        pub fn nonce(static_iv: [nonce_length]u8, epoch: u64, sequence_number: u64) [nonce_length]u8 {
            _ = epoch; // RFC 9147 §4.2.2: epoch is not part of the AEAD nonce.
            var out = static_iv;
            var seq_be: [8]u8 = undefined;
            std.mem.writeInt(u64, &seq_be, sequence_number, .big);
            // XOR the 8 sequence bytes into the rightmost 8 nonce bytes.
            const off = nonce_length - 8;
            inline for (0..8) |i| out[off + i] ^= seq_be[i];
            return out;
        }

        /// RFC 9147 §4.2: AEAD-seal `plaintext` (the DTLSInnerPlaintext:
        /// content || content_type || zero padding) under `key`/`nonce(...)`,
        /// authenticating `additional_data` (the unified record header bytes
        /// PRIOR to sequence-number encryption). Writes `plaintext.len +
        /// tag_length` bytes into `out`; returns that count.
        pub fn protect(
            key: [key_length]u8,
            static_iv: [nonce_length]u8,
            epoch: u64,
            sequence_number: u64,
            plaintext: []const u8,
            additional_data: []const u8,
            out: []u8,
        ) RecordProtectionError!usize {
            const total = plaintext.len + tag_length;
            if (out.len < total) return error.BufferTooShort;
            const npub = nonce(static_iv, epoch, sequence_number);
            var tag: [tag_length]u8 = undefined;
            Aead.encrypt(out[0..plaintext.len], &tag, plaintext, additional_data, npub, key);
            @memcpy(out[plaintext.len..][0..tag_length], &tag);
            return total;
        }

        /// The `protect` mirror: AEAD-open `ciphertext` (ciphertext body ||
        /// trailing tag) under `key`/`nonce(...)`, authenticating
        /// `additional_data`. Writes `ciphertext.len - tag_length` bytes into
        /// `out`; returns that count. Any tag mismatch is
        /// `error.DecryptionFailed` — never a panic, never a timing leak
        /// (std AEAD open uses a constant-time tag compare).
        pub fn unprotect(
            key: [key_length]u8,
            static_iv: [nonce_length]u8,
            epoch: u64,
            sequence_number: u64,
            ciphertext: []const u8,
            additional_data: []const u8,
            out: []u8,
        ) RecordProtectionError!usize {
            if (ciphertext.len < tag_length) return error.RecordTooShort;
            const body_len = ciphertext.len - tag_length;
            if (out.len < body_len) return error.BufferTooShort;
            const npub = nonce(static_iv, epoch, sequence_number);
            var tag: [tag_length]u8 = undefined;
            @memcpy(&tag, ciphertext[body_len..][0..tag_length]);
            Aead.decrypt(out[0..body_len], ciphertext[0..body_len], tag, additional_data, npub, key) catch
                return error.DecryptionFailed;
            return body_len;
        }
    };
}

// ── sequence-number encryption (RFC 9147 §4.2.3) ────────────────────────
//
// The ciphertext sample MUST be at least 16 bytes (§4.2.3); receivers reject
// shorter records as failed deprotection, senders pad. `seq_bytes` is the
// 1- or 2-byte on-wire sequence number (record.SeqNumLen). Masking is XOR
// (self-inverse), so encrypt == decrypt.

/// RFC 9147 §4.2.3, AES suites: `Mask = AES-ECB(sn_key,
/// Ciphertext[0..15])`; `seq_bytes[i] ^= Mask[i]`. `sn_key` is 16 (AES-128)
/// or 32 (AES-256) bytes.
pub fn encryptSequenceNumberAes(
    sn_key: []const u8,
    ciphertext_sample: []const u8,
    seq_bytes: []u8,
) RecordProtectionError!void {
    if (ciphertext_sample.len < 16) return error.RecordTooShort;
    std.debug.assert(seq_bytes.len <= 16);
    var mask: [16]u8 = undefined;
    const src: *const [16]u8 = ciphertext_sample[0..16];
    switch (sn_key.len) {
        16 => std.crypto.core.aes.Aes128.initEnc(sn_key[0..16].*).encrypt(&mask, src),
        32 => std.crypto.core.aes.Aes256.initEnc(sn_key[0..32].*).encrypt(&mask, src),
        else => unreachable, // sn_key length is fixed by the negotiated suite
    }
    for (seq_bytes, 0..) |*b, i| b.* ^= mask[i];
}

/// RFC 9147 §4.2.3, ChaCha20 suites: `Mask = ChaCha20(sn_key,
/// Ciphertext[0..3] as the block counter, Ciphertext[4..15] as the nonce)`;
/// `seq_bytes[i] ^= Mask[i]`. The counter is the first 4 sample bytes read
/// little-endian (matching the ChaCha20 block layout); the nonce is the next
/// 12 bytes. `sn_key` is 32 bytes.
pub fn encryptSequenceNumberChaCha20(
    sn_key: []const u8,
    ciphertext_sample: []const u8,
    seq_bytes: []u8,
) RecordProtectionError!void {
    if (ciphertext_sample.len < 16) return error.RecordTooShort;
    std.debug.assert(sn_key.len == 32);
    std.debug.assert(seq_bytes.len <= 16);
    const counter = std.mem.readInt(u32, ciphertext_sample[0..4], .little);
    const chacha_nonce: [12]u8 = ciphertext_sample[4..16].*;
    var keystream: [16]u8 = [_]u8{0} ** 16;
    std.crypto.stream.chacha.ChaCha20IETF.stream(&keystream, counter, sn_key[0..32].*, chacha_nonce);
    for (seq_bytes, 0..) |*b, i| b.* ^= keystream[i];
}

/// XOR masking is self-inverse — decryption is the same operation.
pub fn decryptSequenceNumberAes(
    sn_key: []const u8,
    ciphertext_sample: []const u8,
    seq_bytes: []u8,
) RecordProtectionError!void {
    return encryptSequenceNumberAes(sn_key, ciphertext_sample, seq_bytes);
}

/// XOR masking is self-inverse — decryption is the same operation.
pub fn decryptSequenceNumberChaCha20(
    sn_key: []const u8,
    ciphertext_sample: []const u8,
    seq_bytes: []u8,
) RecordProtectionError!void {
    return encryptSequenceNumberChaCha20(sn_key, ciphertext_sample, seq_bytes);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "nonce: RFC 9147 §4.2.2 XOR of right-aligned seq into static IV" {
    const iv = hexTo(12, "5d313eb2671276ee13000b30");
    const P = Protection(Aes128Gcm);
    // seq = 0x2A: only the last byte (0x30 ^ 0x2A = 0x1A) changes.
    const n = P.nonce(iv, 0, 0x2A);
    try testing.expectEqualSlices(u8, &hexTo(12, "5d313eb2671276ee13000b1a"), &n);
    // epoch must NOT affect the nonce (RFC 9147 §4.2.2).
    const n_e = P.nonce(iv, 3, 0x2A);
    try testing.expectEqualSlices(u8, &n, &n_e);
}

test "nonce: multi-byte seq spans the low 8 nonce bytes" {
    const iv = [_]u8{0} ** 12;
    const P = Protection(Aes128Gcm);
    const n = P.nonce(iv, 0, 0x0102030405060708);
    try testing.expectEqualSlices(u8, &hexTo(12, "000000000102030405060708"), &n);
}

test "AES-GCM record protection: byte-exact vs OpenSSL, then round-trips" {
    // Vector from scratchpad gen_kats.py (pyca/OpenSSL AESGCM).
    const P = Protection(Aes128Gcm);
    const key = hexTo(16, "9f02283b6c9c07efc26bb9f2ac92e356");
    const iv = hexTo(12, "5d313eb2671276ee13000b30");
    const inner = hexTo(10, "48692074686572652117"); // "Hi there!" + type 23
    const aad = hexTo(5, "2e002a0018");
    var out: [64]u8 = undefined;
    const n = try P.protect(key, iv, 0, 0x2A, &inner, &aad, &out);
    try testing.expectEqualSlices(u8, &hexTo(26, "9530a24df8ffa56be28d84fd00b8bad037aa890687853264e508"), out[0..n]);

    var back: [64]u8 = undefined;
    const m = try P.unprotect(key, iv, 0, 0x2A, out[0..n], &aad, &back);
    try testing.expectEqualSlices(u8, &inner, back[0..m]);
}

test "ChaCha20-Poly1305 record protection: byte-exact vs OpenSSL" {
    const P = Protection(ChaCha20Poly1305);
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(0x10 + i);
    const iv = hexTo(12, "5d313eb2671276ee13000b30");
    const inner = hexTo(10, "48692074686572652117");
    const aad = hexTo(5, "2e002a0018");
    var out: [64]u8 = undefined;
    const n = try P.protect(key, iv, 0, 0x2A, &inner, &aad, &out);
    try testing.expectEqualSlices(u8, &hexTo(26, "fe100fc8a3e503734e8cafbddc40f5e847fcd8be3eb895158ab7"), out[0..n]);
    var back: [64]u8 = undefined;
    const m = try P.unprotect(key, iv, 0, 0x2A, out[0..n], &aad, &back);
    try testing.expectEqualSlices(u8, &inner, back[0..m]);
}

test "unprotect: tampered tag/ciphertext/AAD -> DecryptionFailed, never panic" {
    const P = Protection(Aes128Gcm);
    const key = hexTo(16, "9f02283b6c9c07efc26bb9f2ac92e356");
    const iv = hexTo(12, "5d313eb2671276ee13000b30");
    const inner = hexTo(10, "48692074686572652117");
    const aad = hexTo(5, "2e002a0018");
    var out: [64]u8 = undefined;
    const n = try P.protect(key, iv, 0, 0x2A, &inner, &aad, &out);
    var back: [64]u8 = undefined;

    var t1 = out;
    t1[0] ^= 1; // flip a ciphertext byte
    try testing.expectError(error.DecryptionFailed, P.unprotect(key, iv, 0, 0x2A, t1[0..n], &aad, &back));

    var t2 = out;
    t2[n - 1] ^= 1; // flip a tag byte
    try testing.expectError(error.DecryptionFailed, P.unprotect(key, iv, 0, 0x2A, t2[0..n], &aad, &back));

    var bad_aad = aad;
    bad_aad[0] ^= 1;
    try testing.expectError(error.DecryptionFailed, P.unprotect(key, iv, 0, 0x2A, out[0..n], &bad_aad, &back));

    // Wrong sequence number => wrong nonce => open fails.
    try testing.expectError(error.DecryptionFailed, P.unprotect(key, iv, 0, 0x2B, out[0..n], &aad, &back));
}

test "unprotect: ciphertext shorter than the tag is a typed error" {
    const P = Protection(Aes128Gcm);
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    var back: [4]u8 = undefined;
    const tiny = [_]u8{ 1, 2, 3 };
    try testing.expectError(error.RecordTooShort, P.unprotect(key, iv, 0, 0, &tiny, "", &back));
}

test "seq-number mask (AES-128 ECB): byte-exact vs OpenSSL, self-inverse" {
    const sn_key = hexTo(16, "000102030405060708090a0b0c0d0e0f");
    const sample = hexTo(16, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    // full mask = 5e18d1fef61d087ec0a33ed734a7918f (gen_kats.py)
    var two = [_]u8{ 0x00, 0x00 };
    try encryptSequenceNumberAes(&sn_key, &sample, &two);
    try testing.expectEqualSlices(u8, &.{ 0x5e, 0x18 }, &two); // first 2 mask bytes
    try decryptSequenceNumberAes(&sn_key, &sample, &two); // XOR back
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, &two);
}

test "seq-number mask (AES-256 ECB): correct key-length dispatch" {
    var sn_key: [32]u8 = undefined;
    for (&sn_key, 0..) |*b, i| b.* = @intCast(i);
    const sample = hexTo(16, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    var one = [_]u8{0x00};
    try encryptSequenceNumberAes(&sn_key, &sample, &one);
    // Round-trips (self-inverse) — the point is dispatch to Aes256 works.
    var one2 = one;
    try decryptSequenceNumberAes(&sn_key, &sample, &one2);
    try testing.expectEqual(@as(u8, 0), one2[0]);
}

test "seq-number mask (ChaCha20): byte-exact vs OpenSSL" {
    var sn_key: [32]u8 = undefined;
    for (&sn_key, 0..) |*b, i| b.* = @intCast(i);
    const sample = hexTo(16, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    // mask first 2 bytes = c827 (gen_kats.py)
    var two = [_]u8{ 0x00, 0x00 };
    try encryptSequenceNumberChaCha20(&sn_key, &sample, &two);
    try testing.expectEqualSlices(u8, &.{ 0xc8, 0x27 }, &two);
    try decryptSequenceNumberChaCha20(&sn_key, &sample, &two);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, &two);
}

test "seq-number mask: sample shorter than 16 bytes is a typed error" {
    const sn_key = [_]u8{0} ** 16;
    const short = [_]u8{0} ** 15;
    var two = [_]u8{ 1, 2 };
    try testing.expectError(error.RecordTooShort, encryptSequenceNumberAes(&sn_key, &short, &two));
    var two2 = [_]u8{ 1, 2 };
    const sk32 = [_]u8{0} ** 32;
    try testing.expectError(error.RecordTooShort, encryptSequenceNumberChaCha20(&sk32, &short, &two2));
}

test "protect: output buffer too small is a typed error" {
    const P = Protection(Aes128Gcm);
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooShort, P.protect(key, iv, 0, 0, "hello", "", &tiny));
}

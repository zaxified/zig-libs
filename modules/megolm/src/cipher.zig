// SPDX-License-Identifier: MIT

//! cipher.zig — the per-message symmetric layer: derive `AES_KEY ||
//! HMAC_KEY || AES_IV` from a 128-byte ratchet value, then AES-256-CBC/
//! PKCS#7 (via the sibling `aescbc` module) for confidentiality and
//! HMAC-SHA-256 (truncated to 8 bytes on the wire) for integrity of the
//! ciphertext. Both are spec-mandated, not this module's choice: unlike
//! `signal`'s Double Ratchet (which the Signal spec leaves free to choose
//! any AEAD), Megolm's own spec names AES-256-CBC + HMAC-SHA-256 exactly —
//! see megolm.md "Message encryption".
//!
//! ```
//! AES_KEY_i || HMAC_KEY_i || AES_IV_i = HKDF(salt=0, IKM=R_i, "MEGOLM_KEYS", 80)
//! ```
//!
//! `HKDF` here is HKDF-SHA-256 (RFC 5869) with a ZERO-LENGTH salt (the
//! spec writes the salt argument as the literal `0`, i.e. absent — RFC
//! 5869 §2.2 says an absent salt is treated as a string of `HashLen` zero
//! bytes internally, which is exactly what `HkdfSha256.extract("", ikm)`
//! computes since `HMAC` zero-pads a too-short key up to the block size
//! regardless of what that padding looks like).

const std = @import("std");
const aescbc = @import("aescbc");
const ratchet_mod = @import("ratchet.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes256 = std.crypto.core.aes.Aes256;

pub const aes_key_len = 32;
pub const hmac_key_len = 32;
/// AES-CBC IV length == the AES block size (`aescbc.block_len`, 16 bytes).
pub const iv_len = aescbc.block_len;
pub const full_mac_len = HmacSha256.mac_length; // 32
/// The spec truncates the wire MAC to the first 8 bytes ("Message
/// encryption": "The first 8 bytes of the MAC are appended to the
/// message.").
pub const wire_mac_len = 8;

const kdf_info = "MEGOLM_KEYS";
const kdf_output_len = aes_key_len + hmac_key_len + iv_len; // 80, per spec

/// The three keys/IV derived from one ratchet value. Secret — zero on
/// `deinit`.
pub const Keys = struct {
    aes_key: [aes_key_len]u8,
    hmac_key: [hmac_key_len]u8,
    iv: [iv_len]u8,

    pub fn deinit(self: *Keys) void {
        std.crypto.secureZero(u8, &self.aes_key);
        std.crypto.secureZero(u8, &self.hmac_key);
        std.crypto.secureZero(u8, &self.iv);
    }
};

/// `HKDF(salt=0, IKM=ratchet, "MEGOLM_KEYS", 80)`, split per the spec's
/// `AES_KEY || HMAC_KEY || AES_IV` order.
pub fn deriveKeys(ratchet_bytes: *const [ratchet_mod.ratchet_len]u8) Keys {
    const prk = HkdfSha256.extract(&.{}, ratchet_bytes);
    var out: [kdf_output_len]u8 = undefined;
    HkdfSha256.expand(&out, kdf_info, prk);
    defer std.crypto.secureZero(u8, &out);

    var keys: Keys = undefined;
    @memcpy(&keys.aes_key, out[0..aes_key_len]);
    @memcpy(&keys.hmac_key, out[aes_key_len..][0..hmac_key_len]);
    @memcpy(&keys.iv, out[aes_key_len + hmac_key_len ..][0..iv_len]);
    return keys;
}

/// Full (untruncated) HMAC-SHA-256 over `data`, keyed by `hmac_key`. The
/// wire MAC is this value's first `wire_mac_len` bytes (see
/// `verifyTruncatedMac`); the full value is exposed so callers that need
/// it (the outbound path, before truncating) don't recompute.
pub fn fullMac(hmac_key: *const [hmac_key_len]u8, data: []const u8) [full_mac_len]u8 {
    var out: [full_mac_len]u8 = undefined;
    HmacSha256.create(&out, data, hmac_key);
    return out;
}

/// Constant-time verification of a truncated (8-byte) wire MAC.
pub fn verifyTruncatedMac(hmac_key: *const [hmac_key_len]u8, data: []const u8, tag: *const [wire_mac_len]u8) bool {
    const full = fullMac(hmac_key, data);
    return std.crypto.timing_safe.eql([wire_mac_len]u8, full[0..wire_mac_len].*, tag.*);
}

/// AES-256-CBC-encrypt `plaintext` under PKCS#7 padding. Caller frees.
pub fn encryptCbc(allocator: std.mem.Allocator, keys: *const Keys, plaintext: []const u8) std.mem.Allocator.Error![]u8 {
    const padded_len = aescbc.paddedLenPkcs7(plaintext.len);
    const buf = try allocator.alloc(u8, padded_len);
    errdefer allocator.free(buf);

    // `padPkcs7`'s BufferTooSmall is unreachable: `buf` is sized exactly
    // to `paddedLenPkcs7(plaintext.len)`.
    _ = aescbc.padPkcs7(plaintext, buf) catch unreachable;
    // In-place CBC is safe here: `aescbc.encrypt` copies each source block
    // into a local variable before writing the corresponding output block,
    // so aliasing `out == plaintext` (both `buf`) never reads
    // already-overwritten bytes. `NotBlockAligned`/`BufferTooSmall` are
    // both unreachable: `padded_len` is block_len-aligned by construction
    // and `buf` is sized to exactly that.
    _ = aescbc.encrypt(Aes256, keys.aes_key, keys.iv, buf, buf) catch unreachable;
    return buf;
}

pub const CbcDecryptError = error{InvalidPadding} || std.mem.Allocator.Error;

/// AES-256-CBC-decrypt + PKCS#7-unpad `ciphertext`. Caller frees the
/// returned plaintext. **Callers MUST verify the MAC before calling
/// this** (see `verifyTruncatedMac`) — this function has no way to
/// distinguish "genuinely malformed padding" from "attacker-controlled
/// bytes decrypted under the wrong key", the classic CBC padding-oracle
/// setup (`aescbc`'s own SPEC.md caveat). This module's `session.zig`
/// always verifies the MAC first and never surfaces this function to a
/// caller directly.
pub fn decryptCbc(allocator: std.mem.Allocator, keys: *const Keys, ciphertext: []const u8) CbcDecryptError![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % aescbc.block_len != 0) return error.InvalidPadding;

    const buf = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(buf);
    // Alignment already checked above and `buf.len == ciphertext.len`, so
    // `NotBlockAligned`/`BufferTooSmall` are both unreachable.
    _ = aescbc.decrypt(Aes256, keys.aes_key, keys.iv, ciphertext, buf) catch unreachable;

    const plain_len = aescbc.unpadPkcs7(buf) catch return error.InvalidPadding;
    return try allocator.dupe(u8, buf[0..plain_len]);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "deriveKeys is deterministic and produces distinct key material" {
    const ratchet_bytes = [_]u8{0x42} ** ratchet_mod.ratchet_len;
    var k1 = deriveKeys(&ratchet_bytes);
    defer k1.deinit();
    var k2 = deriveKeys(&ratchet_bytes);
    defer k2.deinit();

    try testing.expectEqualSlices(u8, &k1.aes_key, &k2.aes_key);
    try testing.expectEqualSlices(u8, &k1.hmac_key, &k2.hmac_key);
    try testing.expectEqualSlices(u8, &k1.iv, &k2.iv);
    // AES key, HMAC key, and IV must not collide with each other (sanity
    // that the HKDF expand's 80-byte output was split at the right
    // offsets, not e.g. all zeros from a slicing bug).
    try testing.expect(!std.mem.eql(u8, &k1.aes_key, k1.hmac_key[0..aes_key_len]));
}

test "encryptCbc/decryptCbc round-trip, various lengths crossing the block boundary" {
    const ratchet_bytes = [_]u8{0x07} ** ratchet_mod.ratchet_len;
    var keys = deriveKeys(&ratchet_bytes);
    defer keys.deinit();

    const lengths = [_]usize{ 0, 1, 15, 16, 17, 31, 32, 100 };
    for (lengths) |len| {
        const plaintext = try testing.allocator.alloc(u8, len);
        defer testing.allocator.free(plaintext);
        for (plaintext, 0..) |*b, i| b.* = @truncate(i);

        const ct = try encryptCbc(testing.allocator, &keys, plaintext);
        defer testing.allocator.free(ct);
        try testing.expect(ct.len % aescbc.block_len == 0);

        const pt = try decryptCbc(testing.allocator, &keys, ct);
        defer testing.allocator.free(pt);
        try testing.expectEqualSlices(u8, plaintext, pt);
    }
}

test "verifyTruncatedMac rejects a tampered tag and a tampered message" {
    const ratchet_bytes = [_]u8{0x99} ** ratchet_mod.ratchet_len;
    var keys = deriveKeys(&ratchet_bytes);
    defer keys.deinit();

    const data = "the quick brown fox";
    const mac = fullMac(&keys.hmac_key, data);
    try testing.expect(verifyTruncatedMac(&keys.hmac_key, data, mac[0..wire_mac_len]));

    var bad_tag = mac[0..wire_mac_len].*;
    bad_tag[0] ^= 1;
    try testing.expect(!verifyTruncatedMac(&keys.hmac_key, data, &bad_tag));

    try testing.expect(!verifyTruncatedMac(&keys.hmac_key, "the quick brown foX", mac[0..wire_mac_len]));
}

test "decryptCbc rejects a corrupted-padding ciphertext" {
    const ratchet_bytes = [_]u8{0x55} ** ratchet_mod.ratchet_len;
    var keys = deriveKeys(&ratchet_bytes);
    defer keys.deinit();

    const ct = try encryptCbc(testing.allocator, &keys, "hello megolm");
    defer testing.allocator.free(ct);

    var tampered = try testing.allocator.dupe(u8, ct);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xFF;

    try testing.expectError(error.InvalidPadding, decryptCbc(testing.allocator, &keys, tampered));
}

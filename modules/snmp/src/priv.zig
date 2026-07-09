// SPDX-License-Identifier: MIT

//! USM privacy — **T-G**: SNMPv3 scoped-PDU encryption (RFC 3414 §8 DES-CBC and
//! RFC 3826 AES-128-CFB128). Sits on top of `des.zig` (from-scratch DES) and
//! `std.crypto.core.aes.Aes128` (single-block AES), and hands the decrypted
//! ScopedPDU to `v3.decodeScopedPdu`.
//!
//! Privacy in USM always requires authentication (RFC 3414 §1.4.2): the caller
//! first localizes the privacy password to the authoritative engine with the
//! auth protocol's hash (`usm.passwordToKey`), giving the 16-/20-byte localized
//! privacy key consumed here.
//!
//! Key/IV derivation:
//!   * DES-CBC (RFC 3414 §8.1.1.1): DES key = first 8 bytes of the localized
//!     key; pre-IV = the next 8 bytes; the 8-byte `msgPrivacyParameters` is the
//!     "salt"; IV = pre-IV XOR salt. Plaintext is zero-padded up to a multiple
//!     of 8; decrypt rejects any ciphertext whose length is not a positive
//!     multiple of 8.
//!   * AES-128-CFB (RFC 3826 §3.1.2.1): AES key = first 16 bytes of the
//!     localized key; IV = engineBoots(4, big-endian) ‖ engineTime(4,
//!     big-endian) ‖ 8-byte salt. CFB is a stream mode, so ciphertext length
//!     equals plaintext length (no padding).
//!
//! Provenance: clean-room from RFC 3414 §8 (DES) and RFC 3826 (AES-CFB); FIPS
//! 46-3 (DES tables, in `des.zig`) and NIST SP 800-38A (CFB mode). No source
//! consulted.

const std = @import("std");
const ber = @import("ber.zig");
const des = @import("des.zig");
const v3 = @import("v3.zig");
const Aes128 = std.crypto.core.aes.Aes128;

/// The USM privacy protocols supported here.
pub const PrivProtocol = enum {
    /// usmDESPrivProtocol (RFC 3414 §8) — CBC-DES, 16-byte localized key, 8-byte
    /// salt. Legacy and weak; present only for interop with old agents.
    des_cbc,
    /// usmAesCfb128Protocol (RFC 3826) — CFB128-AES-128, 16-byte localized key,
    /// 8-byte salt.
    aes128_cfb,

    /// Minimum localized-privacy-key length this protocol consumes.
    pub fn keyLen(self: PrivProtocol) usize {
        return switch (self) {
            .des_cbc => 16, // 8 key + 8 pre-IV
            .aes128_cfb => 16, // AES-128 key
        };
    }

    /// The required `msgPrivacyParameters` (salt) length — 8 for both.
    pub fn saltLen(self: PrivProtocol) usize {
        _ = self;
        return 8;
    }
};

pub const PrivError = error{
    /// `localized_priv_key` was shorter than `proto.keyLen()`.
    KeyTooShort,
    /// `priv_params` (the salt) was not exactly 8 bytes.
    BadSalt,
    /// DES ciphertext length was not a positive multiple of 8.
    InvalidLength,
    /// `out` was too small for the result.
    BufferTooSmall,
} || v3.DecodeError;

/// Encrypt a plaintext ScopedPDU (the full `SEQUENCE { ... }` TLV, already BER-
/// encoded) into `out`, returning the ciphertext slice. `engine_boots`/
/// `engine_time` are used only by AES-CFB (RFC 3826 IV); DES-CBC ignores them.
/// `priv_params` is the 8-byte salt (`msgPrivacyParameters`). For DES the output
/// is zero-padded up to a multiple of 8, so `out` may need up to 7 bytes more
/// than `plaintext.len`; for AES the output length equals `plaintext.len`.
pub fn encrypt(
    proto: PrivProtocol,
    localized_priv_key: []const u8,
    engine_boots: u32,
    engine_time: u32,
    priv_params: []const u8,
    plaintext: []const u8,
    out: []u8,
) PrivError![]u8 {
    if (localized_priv_key.len < proto.keyLen()) return error.KeyTooShort;
    if (priv_params.len != 8) return error.BadSalt;
    const salt: [8]u8 = priv_params[0..8].*;

    switch (proto) {
        .des_cbc => {
            const key: [8]u8 = localized_priv_key[0..8].*;
            const pre_iv = localized_priv_key[8..16];
            var iv: [8]u8 = undefined;
            for (&iv, pre_iv, salt) |*b, p, s| b.* = p ^ s;
            // Zero-pad up to a multiple of 8 (RFC 3414 §8.1.1.2; pad value is
            // irrelevant — the inner BER length delimits the real payload).
            const padded = std.mem.alignForward(usize, plaintext.len, des.block_len);
            if (out.len < padded) return error.BufferTooSmall;
            @memcpy(out[0..plaintext.len], plaintext);
            @memset(out[plaintext.len..padded], 0);
            return des.cbcEncrypt(key, iv, out[0..padded], out[0..padded]) catch |e| switch (e) {
                error.BufferTooSmall => error.BufferTooSmall,
                error.NotPadded, error.InvalidLength => unreachable, // we padded
            };
        },
        .aes128_cfb => {
            if (out.len < plaintext.len) return error.BufferTooSmall;
            const key: [16]u8 = localized_priv_key[0..16].*;
            const iv = aesIv(engine_boots, engine_time, salt);
            cfb128(false, Aes128.initEnc(key), iv, plaintext, out[0..plaintext.len]);
            return out[0..plaintext.len];
        },
    }
}

/// Decrypt an encrypted ScopedPDU (`v3`'s `ScopedData.encrypted` bytes) into
/// `out`, returning the plaintext slice — the full ScopedPDU `SEQUENCE` TLV,
/// possibly followed by DES pad bytes. Feed the result to `decodeScopedPdu` (or
/// call `decryptScopedPdu`, which does both). `out` must be at least
/// `ciphertext.len`.
pub fn decrypt(
    proto: PrivProtocol,
    localized_priv_key: []const u8,
    engine_boots: u32,
    engine_time: u32,
    priv_params: []const u8,
    ciphertext: []const u8,
    out: []u8,
) PrivError![]u8 {
    if (localized_priv_key.len < proto.keyLen()) return error.KeyTooShort;
    if (priv_params.len != 8) return error.BadSalt;
    if (out.len < ciphertext.len) return error.BufferTooSmall;
    const salt: [8]u8 = priv_params[0..8].*;

    switch (proto) {
        .des_cbc => {
            const key: [8]u8 = localized_priv_key[0..8].*;
            const pre_iv = localized_priv_key[8..16];
            var iv: [8]u8 = undefined;
            for (&iv, pre_iv, salt) |*b, p, s| b.* = p ^ s;
            return des.cbcDecrypt(key, iv, ciphertext, out) catch |e| switch (e) {
                error.InvalidLength => error.InvalidLength,
                error.BufferTooSmall => error.BufferTooSmall,
                error.NotPadded => unreachable,
            };
        },
        .aes128_cfb => {
            const key: [16]u8 = localized_priv_key[0..16].*;
            const iv = aesIv(engine_boots, engine_time, salt);
            cfb128(true, Aes128.initEnc(key), iv, ciphertext, out[0..ciphertext.len]);
            return out[0..ciphertext.len];
        },
    }
}

/// Decrypt an encrypted ScopedPDU and parse it: decrypt into `out`, strip the
/// outer `SEQUENCE` TLV (this ignores any DES trailing pad, since the BER length
/// delimits the payload), then decode via `v3.decodeScopedPdu`.
pub fn decryptScopedPdu(
    proto: PrivProtocol,
    localized_priv_key: []const u8,
    engine_boots: u32,
    engine_time: u32,
    priv_params: []const u8,
    ciphertext: []const u8,
    out: []u8,
) PrivError!v3.ScopedPdu {
    const plaintext = try decrypt(proto, localized_priv_key, engine_boots, engine_time, priv_params, ciphertext, out);
    // The decrypted buffer is the ScopedPDU SEQUENCE TLV (+ optional pad). Peel
    // the SEQUENCE — its length bounds the content, so trailing pad is ignored.
    var d = ber.Decoder.init(plaintext);
    const content = try d.expect(ber.tag.sequence);
    return v3.decodeScopedPdu(content);
}

/// RFC 3826 §3.1.2.1 IV: engineBoots ‖ engineTime (both 4 bytes big-endian) ‖
/// the 8-byte salt.
fn aesIv(engine_boots: u32, engine_time: u32, salt: [8]u8) [16]u8 {
    var iv: [16]u8 = undefined;
    std.mem.writeInt(u32, iv[0..4], engine_boots, .big);
    std.mem.writeInt(u32, iv[4..8], engine_time, .big);
    @memcpy(iv[8..16], &salt);
    return iv;
}

/// CFB128 (NIST SP 800-38A §6.3) over `Aes128`. IMPORTANT: CFB — for both
/// encryption AND decryption — only ever uses the AES *forward* (encrypt)
/// function to produce the keystream; there is no AES-decrypt call here. Using
/// `Aes128.initDec`/`.decrypt` would be a classic, silent CFB bug. Partial final
/// block handled like std's `modes.zig` `ctr()`: keystream truncated to the
/// remaining byte count.
fn cfb128(comptime decrypt_mode: bool, ctx: std.crypto.core.aes.AesEncryptCtx(Aes128), iv: [16]u8, in: []const u8, out: []u8) void {
    var feedback = iv;
    var i: usize = 0;
    while (i + 16 <= in.len) : (i += 16) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, &feedback); // forward AES only
        var next: [16]u8 = undefined;
        for (0..16) |j| {
            const inb = in[i + j];
            const c = inb ^ ks[j];
            out[i + j] = c;
            // The full ciphertext block feeds the next block's input register.
            next[j] = if (decrypt_mode) inb else c;
        }
        feedback = next;
    }
    const rem = in.len - i;
    if (rem > 0) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, &feedback); // forward AES only
        for (0..rem) |j| out[i + j] = in[i + j] ^ ks[j];
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const usm = @import("usm.zig");
const message = @import("message.zig");

test "NIST SP 800-38A F.3.13/F.3.14 CFB128-AES128 KAT (encrypt + decrypt)" {
    const key = [16]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const iv = [16]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const pt = [64]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const ct = [64]u8{
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
        0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
        0x26, 0x75, 0x1f, 0x67, 0xa3, 0xcb, 0xb1, 0x40, 0xb1, 0x80, 0x8c, 0xf1, 0x87, 0xa4, 0xf4, 0xdf,
        0xc0, 0x4b, 0x05, 0x35, 0x7c, 0x5d, 0x1c, 0x0e, 0xea, 0xc4, 0xc6, 0x6f, 0x9f, 0xf7, 0xf2, 0xe6,
    };

    var enc: [64]u8 = undefined;
    cfb128(false, Aes128.initEnc(key), iv, &pt, &enc);
    try testing.expectEqualSlices(u8, &ct, &enc);

    var dec: [64]u8 = undefined;
    cfb128(true, Aes128.initEnc(key), iv, &ct, &dec);
    try testing.expectEqualSlices(u8, &pt, &dec);
}

test "CFB128 partial final block round-trips (stream mode, no padding)" {
    const key = [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const iv = [16]u8{ 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    inline for (.{ 1, 7, 15, 16, 17, 31, 33 }) |n| {
        var pt: [n]u8 = undefined;
        for (&pt, 0..) |*b, i| b.* = @intCast((i *% 37 + 5) & 0xFF);
        var enc: [n]u8 = undefined;
        var dec: [n]u8 = undefined;
        cfb128(false, Aes128.initEnc(key), iv, &pt, &enc);
        cfb128(true, Aes128.initEnc(key), iv, &enc, &dec);
        try testing.expectEqualSlices(u8, &pt, &dec);
    }
}

test "keyLen / saltLen" {
    try testing.expectEqual(@as(usize, 16), PrivProtocol.des_cbc.keyLen());
    try testing.expectEqual(@as(usize, 16), PrivProtocol.aes128_cfb.keyLen());
    try testing.expectEqual(@as(usize, 8), PrivProtocol.des_cbc.saltLen());
    try testing.expectEqual(@as(usize, 8), PrivProtocol.aes128_cfb.saltLen());
}

test "encrypt rejects short key / bad salt" {
    var out: [64]u8 = undefined;
    const short_key = [_]u8{0} ** 8;
    try testing.expectError(error.KeyTooShort, encrypt(.aes128_cfb, &short_key, 0, 0, &[_]u8{0} ** 8, "hello", &out));
    const key16 = [_]u8{0} ** 16;
    try testing.expectError(error.BadSalt, encrypt(.aes128_cfb, &key16, 0, 0, &[_]u8{0} ** 4, "hello", &out));
    try testing.expectError(error.BadSalt, decrypt(.des_cbc, &key16, 0, 0, &[_]u8{0} ** 7, &[_]u8{0} ** 8, &out));
}

test "DES decrypt rejects non-multiple-of-8 ciphertext" {
    const key16 = [_]u8{0} ** 16;
    var out: [64]u8 = undefined;
    try testing.expectError(error.InvalidLength, decrypt(.des_cbc, &key16, 0, 0, &[_]u8{0} ** 8, &[_]u8{0} ** 7, &out));
    try testing.expectError(error.InvalidLength, decrypt(.des_cbc, &key16, 0, 0, &[_]u8{0} ** 8, &.{}, &out));
}

/// Round-trip both privacy protocols: encrypt a ScopedPDU, then decrypt back.
fn expectPrivRoundTrip(proto: PrivProtocol) !void {
    // Localize a privacy password to the example engine to get a realistic key.
    const engine_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    var key_buf: [usm.max_key_len]u8 = undefined;
    const key = usm.passwordToKey(.hmac_sha1, "privpassword", &engine_id, &key_buf);
    const salt = [8]u8{ 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef };
    const boots: u32 = 5;
    const time: u32 = 12345;

    // Build a real plaintext ScopedPDU SEQUENCE TLV.
    const Oid = @import("oid.zig").Oid;
    const vbs = [_]message.VarBind{
        .{ .name = try Oid.parse("1.3.6.1.2.1.1.3.0"), .value = .{ .time_ticks = 4242 } },
    };
    var scoped_buf: [256]u8 = undefined;
    var se = ber.Encoder.init(&scoped_buf);
    const scoped_mark = se.len();
    try message.encodePdu(&se, .{ .type = .response, .request_id = 77, .varbinds = &vbs });
    try se.prependTlv(ber.tag.octet_string, ""); // contextName
    try se.prependTlv(ber.tag.octet_string, &engine_id); // contextEngineID
    try se.wrap(ber.tag.sequence, scoped_mark);
    const scoped_plain = se.encoded();

    var cipher_buf: [280]u8 = undefined;
    const cipher = try encrypt(proto, key, boots, time, &salt, scoped_plain, &cipher_buf);

    // DES pads to a multiple of 8; AES is a stream cipher (exact length).
    switch (proto) {
        .des_cbc => try testing.expectEqual(@as(usize, 0), cipher.len % 8),
        .aes128_cfb => try testing.expectEqual(scoped_plain.len, cipher.len),
    }
    // Ciphertext must differ from plaintext.
    try testing.expect(!std.mem.eql(u8, scoped_plain, cipher[0..scoped_plain.len]));

    // Assemble a real v3 datagram whose msgData is the encryptedPDU OCTET STRING.
    var usm_buf: [128]u8 = undefined;
    const usm_wire = try usm.encode(&usm_buf, .{
        .engine_id = &engine_id,
        .engine_boots = boots,
        .engine_time = time,
        .user_name = "priv",
        .auth_params = &(.{0} ** usm.digest_len),
        .priv_params = &salt,
    });
    var dg_buf: [512]u8 = undefined;
    var e = ber.Encoder.init(&dg_buf);
    try e.prependTlv(ber.tag.octet_string, cipher); // msgData = encryptedPDU
    try e.prependTlv(ber.tag.octet_string, usm_wire); // msgSecurityParameters
    const hdr_mark = e.len();
    try e.prependInteger(ber.tag.integer, v3.security_model_usm);
    try e.prependTlv(ber.tag.octet_string, &.{(v3.MsgFlags{ .auth = true, .priv = true }).toByte()});
    try e.prependInteger(ber.tag.integer, 65507);
    try e.prependInteger(ber.tag.integer, 4242);
    try e.wrap(ber.tag.sequence, hdr_mark);
    try e.prependInteger(ber.tag.integer, 3);
    try e.wrap(ber.tag.sequence, 0);

    const m = try v3.decode(e.encoded());
    try testing.expect(m.header.flags.priv);
    const enc_bytes = m.data.encrypted;

    // Decrypt straight back through the parsing convenience.
    var pt_buf: [280]u8 = undefined;
    const scoped = try decryptScopedPdu(proto, key, boots, time, &salt, enc_bytes, &pt_buf);
    try testing.expectEqualSlices(u8, &engine_id, scoped.context_engine_id);
    try testing.expectEqualStrings("", scoped.context_name);
    try testing.expectEqual(@as(i32, 77), scoped.pdu.response.request_id);

    // A wrong salt (thus wrong IV) must not reproduce the ScopedPDU. For DES the
    // first block depends on the IV; for AES-CFB the whole stream does.
    const bad_salt = [8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    var bad_buf: [280]u8 = undefined;
    if (decryptScopedPdu(proto, key, boots, time, &bad_salt, enc_bytes, &bad_buf)) |sp| {
        // Decoded, but the corrupted plaintext must not match the real ScopedPDU.
        try testing.expect(!std.mem.eql(u8, sp.context_engine_id, &engine_id));
    } else |_| {
        // A BER decode failure on garbage plaintext is the expected outcome.
    }
}

test "privacy round-trip over a real v3 datagram: DES-CBC" {
    try expectPrivRoundTrip(.des_cbc);
}

test "privacy round-trip over a real v3 datagram: AES-128-CFB" {
    try expectPrivRoundTrip(.aes128_cfb);
}

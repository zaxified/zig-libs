// SPDX-License-Identifier: MIT

//! USM privacy — SNMPv3 scoped-PDU encryption (RFC 3414 §8 DES-CBC and
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
//! Salt ownership: `encrypt` does NOT take a salt from the caller. It draws one
//! from a `SaltSource` it is handed, so the never-repeat obligation is the
//! library's, not the caller's — see `SaltSource` for exactly what that buys and
//! what it does not.
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
} || SaltError || v3.DecodeError;

pub const SaltError = error{
    /// The IV this encryption would use is byte-identical to the IV the same
    /// `SaltSource` produced on the immediately preceding encryption. Only
    /// reachable through `SaltSource.fixedForInterop`; a counter source cannot
    /// hit it. See `SaltSource` for the exact scope of this check.
    SaltReuse,
    /// A DES-CBC counter source has issued all 2^32 distinct salts available
    /// under one `snmpEngineBoots` value (RFC 3414 §8.1.1.1 gives the local
    /// integer only 32 bits). Continuing would repeat an IV, so it refuses.
    SaltExhausted,
};

/// The source of `msgPrivacyParameters`. `encrypt` draws the salt from here
/// instead of accepting one from the caller, so a salt cannot be accidentally
/// repeated by whoever is calling.
///
/// What the default (`SaltSource.counter`) guarantees: within the lifetime of
/// one source, every salt — and therefore every IV — is distinct. That is
/// structural (a monotonic counter), not a check, so it holds for every pair of
/// messages, not just adjacent ones.
///
/// What it does NOT guarantee: uniqueness across two sources used with the same
/// localized key, or across a process restart that re-seeds the counter to the
/// same value. Those are outside anything in-process state can see. Seed the
/// counter with a varying value (`V3Client` does this from the discovered
/// engineBoots‖engineTime by default) so a restart does not resume from the
/// same point.
///
/// The `last_iv` check below is a *detector*, deliberately weaker than the
/// generator: it rejects only an IV identical to the one used on the
/// immediately preceding call of the same source. It does not remember any
/// earlier IV — full history would need unbounded per-key state, which this
/// zero-allocation module does not carry. Treat it as a tripwire on the
/// `fixedForInterop` path, not as "reuse is prevented".
pub const SaltSource = struct {
    mode: Mode,
    /// The IV produced by the previous encryption through this source (8 bytes
    /// for DES-CBC, 16 for AES-CFB); `last_iv_len == 0` means "none yet".
    last_iv: [16]u8 = [_]u8{0} ** 16,
    last_iv_len: u8 = 0,
    /// DES-CBC only: the `snmpEngineBoots` epoch the low 32 counter bits are
    /// being consumed under, and how many salts have gone out inside it.
    des_boots: u32 = 0,
    des_issued: u64 = 0,

    pub const Mode = union(enum) {
        /// RFC 3826 §3.3.1 / RFC 3414 §8.1.1.1: a never-repeating local integer.
        /// This is the default and the only shape suitable for live traffic.
        counter: u64,
        /// OPT-IN ESCAPE HATCH — pins the salt to a caller-chosen value so a
        /// published test vector or a captured interop datagram can be
        /// reproduced byte-for-byte. Every message drawn from such a source uses
        /// the SAME salt, which is exactly the keystream/IV reuse the counter
        /// mode exists to prevent. Never put one of these on live traffic.
        fixed_for_interop: [8]u8,
    };

    /// The safe default: a counter source. RFC 3414 §8.1.1.1 asks for the local
    /// integer to be set to a pseudo-random value at boot; pass such a `seed` if
    /// the localized keys outlive the process.
    pub fn counter(seed: u64) SaltSource {
        return .{ .mode = .{ .counter = seed } };
    }

    /// Interop/KAT only — see `Mode.fixed_for_interop`.
    pub fn fixedForInterop(salt: [8]u8) SaltSource {
        return .{ .mode = .{ .fixed_for_interop = salt } };
    }

    /// Produce the next salt. AES-CFB (RFC 3826 §3.3.1) takes the whole 64-bit
    /// counter big-endian; DES-CBC (RFC 3414 §8.1.1.1) is
    /// `snmpEngineBoots ‖ counter[31:0]`.
    fn draw(s: *SaltSource, proto: PrivProtocol, engine_boots: u32) SaltError![8]u8 {
        switch (s.mode) {
            .fixed_for_interop => |salt| return salt,
            .counter => |*n| {
                const v = n.*;
                var out: [8]u8 = undefined;
                switch (proto) {
                    .aes128_cfb => std.mem.writeInt(u64, &out, v, .big),
                    .des_cbc => {
                        // A new boots epoch restarts the 32-bit budget: the
                        // engineBoots prefix already separates the two epochs.
                        if (s.des_boots != engine_boots) {
                            s.des_boots = engine_boots;
                            s.des_issued = 0;
                        }
                        if (s.des_issued == @as(u64, 1) << 32) return error.SaltExhausted;
                        s.des_issued += 1;
                        std.mem.writeInt(u32, out[0..4], engine_boots, .big);
                        std.mem.writeInt(u32, out[4..8], @truncate(v), .big);
                    },
                }
                n.* +%= 1;
                return out;
            },
        }
    }

    /// Reject an IV identical to the previous one, then record it. Adjacent
    /// calls only — see the type doc.
    fn recordIv(s: *SaltSource, iv: []const u8) SaltError!void {
        if (s.last_iv_len == iv.len and std.mem.eql(u8, s.last_iv[0..iv.len], iv)) {
            return error.SaltReuse;
        }
        @memcpy(s.last_iv[0..iv.len], iv);
        s.last_iv_len = @intCast(iv.len);
    }
};

/// What `encrypt` produced: the ciphertext plus the salt it chose, which the
/// caller must copy into `msgPrivacyParameters`.
pub const Encrypted = struct {
    /// A subslice of the caller's `out`.
    ciphertext: []u8,
    /// The `msgPrivacyParameters` value for this message.
    salt: [8]u8,
};

/// Encrypt a plaintext ScopedPDU (the full `SEQUENCE { ... }` TLV, already BER-
/// encoded) into `out`. `engine_boots`/`engine_time` are used only by AES-CFB
/// (RFC 3826 IV); DES-CBC ignores them — which is why DES depends on the salt
/// alone for IV variation. The salt comes from `salt_source`, not from the
/// caller; it is returned in `Encrypted.salt` for the USM header. For DES the
/// output is zero-padded up to a multiple of 8, so `out` may need up to 7 bytes
/// more than `plaintext.len`; for AES the output length equals `plaintext.len`.
pub fn encrypt(
    proto: PrivProtocol,
    localized_priv_key: []const u8,
    engine_boots: u32,
    engine_time: u32,
    salt_source: *SaltSource,
    plaintext: []const u8,
    out: []u8,
) PrivError!Encrypted {
    if (localized_priv_key.len < proto.keyLen()) return error.KeyTooShort;
    const salt = try salt_source.draw(proto, engine_boots);

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
            try salt_source.recordIv(&iv);
            @memcpy(out[0..plaintext.len], plaintext);
            @memset(out[plaintext.len..padded], 0);
            const ct = des.cbcEncrypt(key, iv, out[0..padded], out[0..padded]) catch |e| switch (e) {
                error.BufferTooSmall => return error.BufferTooSmall,
                error.NotPadded, error.InvalidLength => unreachable, // we padded
            };
            return .{ .ciphertext = ct, .salt = salt };
        },
        .aes128_cfb => {
            if (out.len < plaintext.len) return error.BufferTooSmall;
            const key: [16]u8 = localized_priv_key[0..16].*;
            const iv = aesIv(engine_boots, engine_time, salt);
            try salt_source.recordIv(&iv);
            cfb128(false, Aes128.initEnc(key), iv, plaintext, out[0..plaintext.len]);
            return .{ .ciphertext = out[0..plaintext.len], .salt = salt };
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

test "encrypt rejects short key; decrypt rejects a wrong-length wire salt" {
    var out: [64]u8 = undefined;
    var src = SaltSource.counter(1);
    const short_key = [_]u8{0} ** 8;
    try testing.expectError(error.KeyTooShort, encrypt(.aes128_cfb, &short_key, 0, 0, &src, "hello", &out));
    const key16 = [_]u8{0} ** 16;
    // `decrypt` still takes the salt off the wire, so it must range-check it.
    try testing.expectError(error.BadSalt, decrypt(.des_cbc, &key16, 0, 0, &[_]u8{0} ** 7, &[_]u8{0} ** 8, &out));
    try testing.expectError(error.BadSalt, decrypt(.aes128_cfb, &key16, 0, 0, &[_]u8{0} ** 9, &[_]u8{0} ** 8, &out));
}

test "successive encryptions under one key use different salts and different IVs" {
    // The property the SaltSource buys: the SAME plaintext under the SAME key,
    // boots and time must not produce the same ciphertext twice. If the salt
    // repeated, AES-CFB would reuse the keystream outright (C1^C2 == P1^P2) and
    // DES-CBC would reuse the IV.
    const key = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 } ** 2;
    const pt = "0123456789abcdef0123456789abcdef";
    inline for (.{ PrivProtocol.aes128_cfb, PrivProtocol.des_cbc }) |proto| {
        var src = SaltSource.counter(0x0102030405060708);
        var b1: [64]u8 = undefined;
        var b2: [64]u8 = undefined;
        const e1 = try encrypt(proto, &key, 7, 900, &src, pt, &b1);
        const e2 = try encrypt(proto, &key, 7, 900, &src, pt, &b2);

        try testing.expect(!std.mem.eql(u8, &e1.salt, &e2.salt));
        try testing.expect(!std.mem.eql(u8, e1.ciphertext, e2.ciphertext));

        // And the XOR of the two ciphertexts must NOT be the XOR of the two
        // plaintexts (which are equal here, so that XOR is all-zero) — the exact
        // failure keystream reuse would produce.
        var all_zero = true;
        for (e1.ciphertext, e2.ciphertext) |a, b| {
            if (a ^ b != 0) all_zero = false;
        }
        try testing.expect(!all_zero);

        // Both still decrypt back to the plaintext under their own salt.
        var d1: [64]u8 = undefined;
        var d2: [64]u8 = undefined;
        const p1 = try decrypt(proto, &key, 7, 900, &e1.salt, e1.ciphertext, &d1);
        const p2 = try decrypt(proto, &key, 7, 900, &e2.salt, e2.ciphertext, &d2);
        try testing.expectEqualStrings(pt, p1[0..pt.len]);
        try testing.expectEqualStrings(pt, p2[0..pt.len]);
    }
}

test "counter salts have the RFC shape (AES: 64-bit BE; DES: boots ‖ counter[31:0])" {
    const key = [_]u8{0} ** 16;
    var out: [32]u8 = undefined;

    var aes_src = SaltSource.counter(0x0102030405060708);
    const a1 = try encrypt(.aes128_cfb, &key, 1, 1, &aes_src, "x" ** 16, &out);
    const a2 = try encrypt(.aes128_cfb, &key, 1, 1, &aes_src, "x" ** 16, &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &a1.salt);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 9 }, &a2.salt);

    var des_src = SaltSource.counter(0x0102030405060708);
    const d1 = try encrypt(.des_cbc, &key, 0xdeadbeef, 1, &des_src, "x" ** 16, &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, d1.salt[0..4]);
    try testing.expectEqualSlices(u8, &[_]u8{ 5, 6, 7, 8 }, d1.salt[4..8]);
}

test "a deliberately repeated salt is rejected (adjacent-IV detector)" {
    const key = [_]u8{ 0xa5, 0x5a } ** 8;
    var out: [32]u8 = undefined;
    const salt = [8]u8{ 1, 1, 1, 1, 1, 1, 1, 1 };

    // AES-CFB: the IV is boots‖time‖salt, so a pinned salt at the SAME
    // boots/time repeats the IV exactly — rejected.
    var aes_src = SaltSource.fixedForInterop(salt);
    _ = try encrypt(.aes128_cfb, &key, 3, 42, &aes_src, "x" ** 16, &out);
    try testing.expectError(error.SaltReuse, encrypt(.aes128_cfb, &key, 3, 42, &aes_src, "x" ** 16, &out));
    // A different engineTime moves the AES IV even with the salt pinned, so it
    // is accepted — the boots/time prefix really is doing work for AES.
    _ = try encrypt(.aes128_cfb, &key, 3, 43, &aes_src, "x" ** 16, &out);

    // DES-CBC has NO boots/time in its IV (iv = pre_iv XOR salt), so the very
    // same time change does not help: the IV repeats and is rejected.
    var des_src = SaltSource.fixedForInterop(salt);
    _ = try encrypt(.des_cbc, &key, 3, 42, &des_src, "x" ** 16, &out);
    try testing.expectError(error.SaltReuse, encrypt(.des_cbc, &key, 3, 43, &des_src, "x" ** 16, &out));
    try testing.expectError(error.SaltReuse, encrypt(.des_cbc, &key, 9, 999, &des_src, "x" ** 16, &out));
}

test "the detector is adjacent-only: an A,B,A salt sequence is NOT caught" {
    // Documenting the limit, not endorsing it: only the immediately preceding
    // IV is remembered, so an older repeat sails through. This is why the
    // counter source — not this check — is what the design rests on.
    const key = [_]u8{ 0xa5, 0x5a } ** 8;
    var out: [32]u8 = undefined;
    var src = SaltSource.fixedForInterop([8]u8{ 1, 1, 1, 1, 1, 1, 1, 1 });
    const a = try encrypt(.des_cbc, &key, 3, 42, &src, "x" ** 16, &out);
    src.mode = .{ .fixed_for_interop = [8]u8{ 2, 2, 2, 2, 2, 2, 2, 2 } };
    _ = try encrypt(.des_cbc, &key, 3, 42, &src, "x" ** 16, &out);
    src.mode = .{ .fixed_for_interop = [8]u8{ 1, 1, 1, 1, 1, 1, 1, 1 } };
    const c = try encrypt(.des_cbc, &key, 3, 42, &src, "x" ** 16, &out);
    try testing.expectEqualSlices(u8, &a.salt, &c.salt); // the reuse is real…
    // …and it was accepted. Adjacent-only detection, exactly as documented.
}

test "a DES counter source refuses to wrap its 32-bit budget under one boots" {
    const key = [_]u8{0} ** 16;
    var out: [32]u8 = undefined;
    var src = SaltSource.counter(0);
    _ = try encrypt(.des_cbc, &key, 4, 0, &src, "x" ** 16, &out);
    // Fast-forward to one salt short of the RFC 3414 §8.1.1.1 32-bit space.
    src.des_issued = (@as(u64, 1) << 32) - 1;
    _ = try encrypt(.des_cbc, &key, 4, 0, &src, "x" ** 16, &out);
    try testing.expectError(error.SaltExhausted, encrypt(.des_cbc, &key, 4, 0, &src, "x" ** 16, &out));
    // A new engineBoots epoch has its own 32-bit space (boots is in the salt).
    _ = try encrypt(.des_cbc, &key, 5, 0, &src, "x" ** 16, &out);
}

test "DES decrypt rejects non-multiple-of-8 ciphertext" {
    const key16 = [_]u8{0} ** 16;
    var out: [64]u8 = undefined;
    try testing.expectError(error.InvalidLength, decrypt(.des_cbc, &key16, 0, 0, &[_]u8{0} ** 8, &[_]u8{0} ** 7, &out));
    try testing.expectError(error.InvalidLength, decrypt(.des_cbc, &key16, 0, 0, &[_]u8{0} ** 8, &.{}, &out));
}

/// Round-trip both privacy protocols end-to-end through the public message
/// path: `v3.encodeScopedPdu` → `encrypt` → `v3.encodeEncrypted` → `usm.sign`,
/// then `v3.decode` → `usm.verify` → `decryptScopedPdu` — a full authPriv
/// datagram both ways.
fn expectPrivRoundTrip(proto: PrivProtocol) !void {
    // Localize a privacy password to the example engine to get a realistic key.
    const engine_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    var key_buf: [usm.max_key_len]u8 = undefined;
    const key = try usm.passwordToKey(.hmac_sha1, "privpassword", &engine_id, &key_buf);
    const salt = [8]u8{ 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef };
    const boots: u32 = 5;
    const time: u32 = 12345;

    // Build a real plaintext ScopedPDU SEQUENCE TLV via the public seam.
    const Oid = @import("oid.zig").Oid;
    const vbs = [_]message.VarBind{
        .{ .name = try Oid.parse("1.3.6.1.2.1.1.3.0"), .value = .{ .time_ticks = 4242 } },
    };
    var scoped_buf: [256]u8 = undefined;
    const scoped_plain = try v3.encodeScopedPdu(&scoped_buf, .{
        .context_engine_id = &engine_id,
        .pdu = .{ .type = .response, .request_id = 77, .varbinds = &vbs },
    });

    var cipher_buf: [280]u8 = undefined;
    // A pinned salt: this test asserts a fixed wire shape, which is exactly what
    // the opt-in interop source is for.
    var salt_src = SaltSource.fixedForInterop(salt);
    const cipher = (try encrypt(proto, key, boots, time, &salt_src, scoped_plain, &cipher_buf)).ciphertext;

    // DES pads to a multiple of 8; AES is a stream cipher (exact length).
    switch (proto) {
        .des_cbc => try testing.expectEqual(@as(usize, 0), cipher.len % 8),
        .aes128_cfb => try testing.expectEqual(scoped_plain.len, cipher.len),
    }
    // Ciphertext must differ from plaintext.
    try testing.expect(!std.mem.eql(u8, scoped_plain, cipher[0..scoped_plain.len]));

    // Frame a real authPriv v3 datagram: msgData = encryptedPDU, the salt in
    // msgPrivacyParameters, and a 12-zero auth placeholder to sign over.
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
    const dg = try v3.encodeEncrypted(&dg_buf, .{
        .msg_id = 4242,
        .security_parameters = usm_wire,
        .encrypted_pdu = cipher,
    });

    // Sign in place (mutable copy — auth_params must point INTO the signed
    // buffer), then run the full receive path: decode, verify, decrypt.
    var msg_buf: [512]u8 = undefined;
    @memcpy(msg_buf[0..dg.len], dg);
    const msg = msg_buf[0..dg.len];
    const m = try v3.decode(msg);
    try testing.expect(m.header.flags.auth and m.header.flags.priv);
    const sp = try usm.parse(m.security_parameters);
    try testing.expectEqualSlices(u8, &salt, sp.priv_params);
    const off = usm.authOffset(msg, sp) orelse return error.TestUnexpectedResult;
    usm.sign(.hmac_sha1, key, msg, off);
    try usm.verify(.hmac_sha1, key, msg, sp);
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
    if (decryptScopedPdu(proto, key, boots, time, &bad_salt, enc_bytes, &bad_buf)) |bad_scoped| {
        // Decoded, but the corrupted plaintext must not match the real ScopedPDU.
        try testing.expect(!std.mem.eql(u8, bad_scoped.context_engine_id, &engine_id));
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

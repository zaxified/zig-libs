// SPDX-License-Identifier: MIT

//! dtls.record12 — DTLS 1.2 record protection (RFC 6347 §4.1.2.1 over the
//! RFC 5246 §6.2.3.3 AEAD construction) for the two AEAD families the 1.2
//! engine wires:
//!
//!   * AES-GCM (RFC 5288 §3): the 12-byte nonce is the 4-byte implicit
//!     `salt` from the key block followed by an 8-byte `nonce_explicit`
//!     carried at the front of each record. This module sends the record's
//!     own 64-bit `epoch || sequence_number` as `nonce_explicit` (RFC 5288
//!     §3 allows any value that never repeats under one key; the record
//!     number never does, RFC 6347 §4.1).
//!   * AES-CCM and AES-CCM-8 (RFC 6655 §3, the `aesccm` module): the same
//!     salt || `nonce_explicit` layout as GCM, tags of 16 and 8 bytes.
//!   * ChaCha20-Poly1305 (RFC 7905 §2): no explicit part; the nonce is the
//!     12-byte `client/server_write_IV` XOR the left-padded 64-bit
//!     `epoch || sequence_number`.
//!
//! Additional data (RFC 6347 §4.1.2.1, RFC 5246 §6.2.3.3):
//! `epoch(2) || sequence_number(6) || type(1) || version(2) || length(2)`,
//! `length` the PLAINTEXT length.
//!
//! The 13-byte record header is `record.zig`'s `PlaintextHeader`, which is
//! exactly the DTLS 1.2 `DTLSPlaintext`/`DTLSCiphertext` header.

const std = @import("std");
const record = @import("record.zig");
const burn = @import("burn.zig");
const Aes128Gcm = @import("aesgcm").Aes128Gcm;
const Aes256Gcm = @import("aesgcm").Aes256Gcm;
const ChaCha20Poly1305 = @import("chachapoly").ChaCha20Poly1305;
const Aes128Ccm = @import("aesccm").Aes128Ccm;
const Aes128Ccm8 = @import("aesccm").Aes128Ccm8;

pub const Bulk = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
    aes_128_ccm,
    aes_128_ccm_8,

    pub fn keyLen(self: Bulk) usize {
        return switch (self) {
            .aes_128_gcm, .aes_128_ccm, .aes_128_ccm_8 => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    /// RFC 5246 §6.3 `fixed_iv_length`: 4 for GCM (RFC 5288 §3), 12 for
    /// ChaCha20-Poly1305 (RFC 7905 §2).
    pub fn fixedIvLen(self: Bulk) usize {
        return switch (self) {
            .aes_128_gcm, .aes_256_gcm, .aes_128_ccm, .aes_128_ccm_8 => 4,
            .chacha20_poly1305 => 12,
        };
    }

    /// The AEAD tag: 16 bytes, 8 for CCM_8 (RFC 6655 §3).
    pub fn tagLen(self: Bulk) usize {
        return if (self == .aes_128_ccm_8) 8 else 16;
    }

    /// Whether the record carries an 8-byte explicit nonce (RFC 5288 §3,
    /// RFC 6655 §3); ChaCha20-Poly1305 has none (RFC 7905 §2).
    pub fn hasExplicitNonce(self: Bulk) bool {
        return self != .chacha20_poly1305;
    }

    /// Bytes a protected record adds to its plaintext: the explicit nonce
    /// plus the tag.
    pub fn overhead(self: Bulk) usize {
        return (if (self.hasExplicitNonce()) @as(usize, 8) else 0) + self.tagLen();
    }
};

/// The longest tag of any bulk cipher (`Bulk.tagLen`).
pub const tag_len = 16;

/// One direction's write key and IV.
pub const DirKeys = struct {
    bulk: Bulk = .aes_128_gcm,
    key: [32]u8 = undefined,
    iv: [12]u8 = undefined,

    pub fn wipe(self: *DirKeys) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
    }
};

pub const Error = error{ BufferTooShort, RecordTooShort, DecryptionFailed };

fn recordNumber(epoch: u16, seq: u48) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, (@as(u64, epoch) << 48) | seq, .big);
    return out;
}

fn additionalData(epoch: u16, seq: u48, content_type: u8, plaintext_len: usize) [13]u8 {
    var ad: [13]u8 = undefined;
    ad[0..8].* = recordNumber(epoch, seq);
    ad[8] = content_type;
    ad[9..11].* = record.legacy_version_dtls12;
    std.mem.writeInt(u16, ad[11..13], @intCast(plaintext_len), .big);
    return ad;
}

fn nonce(keys: *const DirKeys, rn: [8]u8) [12]u8 {
    var n: [12]u8 = undefined;
    switch (keys.bulk) {
        .aes_128_gcm, .aes_256_gcm, .aes_128_ccm, .aes_128_ccm_8 => {
            n[0..4].* = keys.iv[0..4].*;
            n[4..12].* = rn;
        },
        .chacha20_poly1305 => {
            n = keys.iv;
            for (0..8) |i| n[4 + i] ^= rn[i];
        },
    }
    return n;
}

/// Builds one complete protected record (13-byte header + fragment) into
/// `out`. `plaintext.len` must leave the record length within u16.
pub fn seal(keys: *const DirKeys, epoch: u16, seq: u48, content_type: u8, plaintext: []const u8, out: []u8) Error![]u8 {
    return burn.run(burn.aead_burn, Error![]u8, sealBody, .{ keys, epoch, seq, content_type, plaintext, out });
}

fn sealBody(keys: *const DirKeys, epoch: u16, seq: u48, content_type: u8, plaintext: []const u8, out: []u8) Error![]u8 {
    const frag_len = plaintext.len + keys.bulk.overhead();
    if (frag_len > std.math.maxInt(u16)) return error.BufferTooShort;
    if (out.len < record.plaintext_header_len + frag_len) return error.BufferTooShort;
    _ = record.encodePlaintext(.{ .content_type = content_type, .epoch = epoch, .sequence_number = seq, .length = @intCast(frag_len) }, out) catch return error.BufferTooShort;
    const rn = recordNumber(epoch, seq);
    const ad = additionalData(epoch, seq, content_type, plaintext.len);
    const n = nonce(keys, rn);
    var body = out[record.plaintext_header_len..][0..frag_len];
    if (keys.bulk.hasExplicitNonce()) {
        body[0..8].* = rn;
        body = body[8..];
    }
    var tag: [tag_len]u8 = undefined;
    const ct = body[0..plaintext.len];
    switch (keys.bulk) {
        .aes_128_gcm => Aes128Gcm.encrypt(ct, &tag, plaintext, &ad, n, keys.key[0..16].*),
        .aes_256_gcm => Aes256Gcm.encrypt(ct, &tag, plaintext, &ad, n, keys.key),
        .chacha20_poly1305 => ChaCha20Poly1305.encrypt(ct, &tag, plaintext, &ad, n, keys.key),
        .aes_128_ccm => Aes128Ccm.encrypt(ct, &tag, plaintext, &ad, n, keys.key[0..16].*) catch return error.BufferTooShort,
        .aes_128_ccm_8 => Aes128Ccm8.encrypt(ct, tag[0..8], plaintext, &ad, n, keys.key[0..16].*) catch return error.BufferTooShort,
    }
    const tl = keys.bulk.tagLen();
    @memcpy(body[plaintext.len..][0..tl], tag[0..tl]);
    return out[0 .. record.plaintext_header_len + frag_len];
}

/// Opens the fragment of a record whose header was already decoded
/// (`hdr`), into `out`; returns the plaintext. Every authentication failure
/// is `error.DecryptionFailed`.
pub fn open(keys: *const DirKeys, hdr: record.PlaintextHeader, fragment: []const u8, out: []u8) Error![]u8 {
    return burn.run(burn.aead_burn, Error![]u8, openBody, .{ keys, hdr, fragment, out });
}

fn openBody(keys: *const DirKeys, hdr: record.PlaintextHeader, fragment: []const u8, out: []u8) Error![]u8 {
    if (fragment.len < keys.bulk.overhead()) return error.RecordTooShort;
    const pt_len = fragment.len - keys.bulk.overhead();
    if (out.len < pt_len) return error.BufferTooShort;
    var n: [12]u8 = undefined;
    var body = fragment;
    switch (keys.bulk) {
        .aes_128_gcm, .aes_256_gcm, .aes_128_ccm, .aes_128_ccm_8 => {
            // The explicit nonce is whatever the SENDER chose (RFC 5288 §3,
            // RFC 6655 §3), not necessarily its record number.
            n[0..4].* = keys.iv[0..4].*;
            n[4..12].* = fragment[0..8].*;
            body = fragment[8..];
        },
        .chacha20_poly1305 => n = nonce(keys, recordNumber(hdr.epoch, hdr.sequence_number)),
    }
    const ad = additionalData(hdr.epoch, hdr.sequence_number, hdr.content_type, pt_len);
    const pt = out[0..pt_len];
    const r: anyerror!void = switch (keys.bulk) {
        .aes_128_gcm => Aes128Gcm.decrypt(pt, body[0..pt_len], body[pt_len..][0..16].*, &ad, n, keys.key[0..16].*),
        .aes_256_gcm => Aes256Gcm.decrypt(pt, body[0..pt_len], body[pt_len..][0..16].*, &ad, n, keys.key),
        .chacha20_poly1305 => ChaCha20Poly1305.decrypt(pt, body[0..pt_len], body[pt_len..][0..16].*, &ad, n, keys.key),
        .aes_128_ccm => Aes128Ccm.decrypt(pt, body[0..pt_len], body[pt_len..][0..16].*, &ad, n, keys.key[0..16].*),
        .aes_128_ccm_8 => Aes128Ccm8.decrypt(pt, body[0..pt_len], body[pt_len..][0..8].*, &ad, n, keys.key[0..16].*),
    };
    r catch {
        std.crypto.secureZero(u8, pt);
        return error.DecryptionFailed;
    };
    return pt;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "record12: seal/open round trip for every bulk cipher; any flipped byte fails" {
    for ([_]Bulk{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305, .aes_128_ccm, .aes_128_ccm_8 }) |bulk| {
        var k = DirKeys{ .bulk = bulk };
        for (&k.key, 0..) |*b, i| b.* = @intCast(i);
        for (&k.iv, 0..) |*b, i| b.* = @intCast(0x80 + i);
        var buf: [128]u8 = undefined;
        const rec = try seal(&k, 1, 7, 23, "hello dtls 1.2", &buf);
        try testing.expectEqual(record.plaintext_header_len + 14 + bulk.overhead(), rec.len);
        const hdr = try record.decodePlaintext(rec);
        try testing.expectEqual(@as(u16, 1), hdr.epoch);
        try testing.expectEqual(@as(u48, 7), hdr.sequence_number);
        var out: [64]u8 = undefined;
        try testing.expectEqualStrings("hello dtls 1.2", try open(&k, hdr, rec[record.plaintext_header_len..], &out));
        // The header is authenticated: a different sequence number fails.
        var hdr2 = hdr;
        hdr2.sequence_number = 8;
        try testing.expectError(error.DecryptionFailed, open(&k, hdr2, rec[record.plaintext_header_len..], &out));
        for (record.plaintext_header_len..rec.len) |i| {
            var t = buf;
            t[i] ^= 1;
            try testing.expectError(error.DecryptionFailed, open(&k, hdr, t[record.plaintext_header_len..rec.len], &out));
        }
        try testing.expectError(error.RecordTooShort, open(&k, hdr, rec[record.plaintext_header_len..][0 .. bulk.overhead() - 1], &out));
    }
}

test "record12: RFC 5288 §3 nonce = salt || explicit, RFC 7905 §2 nonce = IV xor record number (layout check against std AEADs)" {
    var k = DirKeys{ .bulk = .aes_128_gcm };
    k.key = @splat(0x42);
    k.iv = @splat(0);
    k.iv[0..4].* = .{ 1, 2, 3, 4 };
    var buf: [64]u8 = undefined;
    const rec = try seal(&k, 2, 0x010203, 22, "abc", &buf);
    // Explicit nonce = epoch(2) || seq(6).
    try testing.expectEqualSlices(u8, &.{ 0, 2, 0, 0, 0, 1, 2, 3 }, rec[13..21]);
    var tag: [16]u8 = undefined;
    var ct: [3]u8 = undefined;
    const ad = [_]u8{ 0, 2, 0, 0, 0, 1, 2, 3, 22, 0xfe, 0xfd, 0, 3 };
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(&ct, &tag, "abc", &ad, .{ 1, 2, 3, 4, 0, 2, 0, 0, 0, 1, 2, 3 }, k.key[0..16].*);
    try testing.expectEqualSlices(u8, &ct, rec[21..24]);
    try testing.expectEqualSlices(u8, &tag, rec[24..40]);

    var c = DirKeys{ .bulk = .chacha20_poly1305 };
    c.key = @splat(0x24);
    c.iv = @splat(0xff);
    const rec2 = try seal(&c, 1, 5, 23, "xyz", &buf);
    var n: [12]u8 = @splat(0xff);
    n[5] ^= 1; // epoch 1 in byte 4..5 of the record number (offset 4 + 1)
    n[11] ^= 5;
    const ad2 = [_]u8{ 0, 1, 0, 0, 0, 0, 0, 5, 23, 0xfe, 0xfd, 0, 3 };
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(&ct, &tag, "xyz", &ad2, n, c.key);
    try testing.expectEqualSlices(u8, &ct, rec2[13..16]);
    try testing.expectEqualSlices(u8, &tag, rec2[16..32]);
}

test "record12: RFC 6655 §3 CCM nonce = salt || explicit, tags 16 and 8 (layout check against aesccm)" {
    var k = DirKeys{ .bulk = .aes_128_ccm_8 };
    k.key = @splat(0x17);
    k.iv = @splat(0);
    k.iv[0..4].* = .{ 9, 8, 7, 6 };
    var buf: [64]u8 = undefined;
    const rec = try seal(&k, 1, 0x0a0b, 23, "ccm", &buf);
    try testing.expectEqual(@as(usize, 13 + 8 + 3 + 8), rec.len);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 0, 0, 0, 0, 0x0a, 0x0b }, rec[13..21]);
    const ad = [_]u8{ 0, 1, 0, 0, 0, 0, 0x0a, 0x0b, 23, 0xfe, 0xfd, 0, 3 };
    const n = [12]u8{ 9, 8, 7, 6, 0, 1, 0, 0, 0, 0, 0x0a, 0x0b };
    var ct: [3]u8 = undefined;
    var t8: [8]u8 = undefined;
    try Aes128Ccm8.encrypt(&ct, &t8, "ccm", &ad, n, k.key[0..16].*);
    try testing.expectEqualSlices(u8, &ct, rec[21..24]);
    try testing.expectEqualSlices(u8, &t8, rec[24..32]);
    k.bulk = .aes_128_ccm;
    const rec16 = try seal(&k, 1, 0x0a0b, 23, "ccm", &buf);
    var t16: [16]u8 = undefined;
    try Aes128Ccm.encrypt(&ct, &t16, "ccm", &ad, n, k.key[0..16].*);
    try testing.expectEqualSlices(u8, &ct, rec16[21..24]);
    try testing.expectEqualSlices(u8, &t16, rec16[24..40]);
}

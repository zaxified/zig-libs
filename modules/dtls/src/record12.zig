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
    /// The AES-GCM key schedule, expanded in place by `prepare` so a record
    /// skips the AES key expansion and the GHASH key setup. `.none` (the
    /// default, and every non-GCM bulk cipher) takes the stateless call.
    gcm: Gcm = .none,

    pub const Gcm = union(enum) {
        none,
        g128: Aes128Gcm.Context,
        g256: Aes256Gcm.Context,
    };

    /// Expand the AES-GCM key schedule of `key` in place (no-op for the other
    /// bulk ciphers). Call it after setting `bulk` and `key`; `wipe` clears it.
    pub fn prepare(self: *DirKeys) void {
        switch (self.bulk) {
            .aes_128_gcm => {
                self.gcm = .{ .g128 = undefined };
                Aes128Gcm.Context.initInto(&self.gcm.g128, self.key[0..16]);
            },
            .aes_256_gcm => {
                self.gcm = .{ .g256 = undefined };
                Aes256Gcm.Context.initInto(&self.gcm.g256, &self.key);
            },
            else => self.gcm = .none,
        }
    }

    pub fn wipe(self: *DirKeys) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.gcm));
        self.gcm = .none;
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
        .aes_128_gcm => if (keys.gcm == .g128) keys.gcm.g128.encrypt(ct, &tag, plaintext, &ad, n) else Aes128Gcm.encrypt(ct, &tag, plaintext, &ad, n, keys.key[0..16].*),
        .aes_256_gcm => if (keys.gcm == .g256) keys.gcm.g256.encrypt(ct, &tag, plaintext, &ad, n) else Aes256Gcm.encrypt(ct, &tag, plaintext, &ad, n, keys.key),
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
        .aes_128_gcm => if (keys.gcm == .g128) keys.gcm.g128.decrypt(pt, body[0..pt_len], body[pt_len..][0..16].*, &ad, n) else Aes128Gcm.decrypt(pt, body[0..pt_len], body[pt_len..][0..16].*, &ad, n, keys.key[0..16].*),
        .aes_256_gcm => if (keys.gcm == .g256) keys.gcm.g256.decrypt(pt, body[0..pt_len], body[pt_len..][0..16].*, &ad, n) else Aes256Gcm.decrypt(pt, body[0..pt_len], body[pt_len..][0..16].*, &ad, n, keys.key),
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

// ── connection ID records (RFC 9146) ─────────────────────────────────────

/// RFC 9146 §4 `tls12_cid`: the outer content type of a record that carries a
/// connection ID; the real type travels inside, in `DTLSInnerPlaintext`.
pub const content_tls12_cid: u8 = 25;
/// The longest CID this module handles (`Connection.max_cid_len`).
pub const max_cid_len = 32;

/// The header of a `tls12_cid` record: `type(1) || version(2) || epoch(2) ||
/// sequence_number(6) || cid(cid_len) || length(2)` (RFC 9146 §4, Figure 3).
pub const CidHeader = struct {
    epoch: u16,
    sequence_number: u48,
    cid: []const u8,
    length: u16,

    pub fn len(cid_len: usize) usize {
        return 11 + cid_len + 2;
    }
};

/// Parses a `tls12_cid` record header whose CID is `cid_len` bytes long (the
/// receiver's own CID; the wire does not carry its length).
pub fn decodeCidHeader(buf: []const u8, cid_len: usize) error{Malformed}!CidHeader {
    if (cid_len > max_cid_len or buf.len < CidHeader.len(cid_len)) return error.Malformed;
    if (buf[0] != content_tls12_cid or buf[1] != record.legacy_version_dtls12[0] or buf[2] != record.legacy_version_dtls12[1]) return error.Malformed;
    var seq_bytes: [8]u8 = @splat(0);
    @memcpy(seq_bytes[2..8], buf[5..11]);
    return .{
        .epoch = std.mem.readInt(u16, buf[3..5], .big),
        .sequence_number = @truncate(std.mem.readInt(u64, &seq_bytes, .big)),
        .cid = buf[11..][0..cid_len],
        .length = std.mem.readInt(u16, buf[11 + cid_len ..][0..2], .big),
    };
}

/// RFC 9146 §5.3 additional data (AEAD ciphers): `seq_num_placeholder (8 ×
/// 0xff) || tls12_cid || cid_length || tls12_cid || version || epoch ||
/// sequence_number || cid || length_of_DTLSInnerPlaintext`.
fn additionalDataCid(epoch: u16, seq: u48, cid: []const u8, inner_len: usize, buf: *[23 + max_cid_len]u8) []const u8 {
    buf[0..8].* = @splat(0xff);
    buf[8] = content_tls12_cid;
    buf[9] = @intCast(cid.len);
    buf[10] = content_tls12_cid;
    buf[11..13].* = record.legacy_version_dtls12;
    std.mem.writeInt(u16, buf[13..15], epoch, .big);
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, seq, .big);
    buf[15..21].* = seq_be[2..8].*;
    @memcpy(buf[21..][0..cid.len], cid);
    std.mem.writeInt(u16, buf[21 + cid.len ..][0..2], @intCast(inner_len), .big);
    return buf[0 .. 23 + cid.len];
}

/// Seals `plaintext` of `content_type` as a `tls12_cid` record carrying
/// `cid` (the PEER's CID), no padding: `DTLSInnerPlaintext = plaintext ||
/// content_type`. The inner plaintext is assembled in `out` and encrypted in
/// place.
pub fn sealCid(keys: *const DirKeys, epoch: u16, seq: u48, content_type: u8, plaintext: []const u8, cid: []const u8, out: []u8) Error![]u8 {
    return burn.run(burn.aead_burn, Error![]u8, sealCidBody, .{ keys, epoch, seq, content_type, plaintext, cid, out });
}

fn sealCidBody(keys: *const DirKeys, epoch: u16, seq: u48, content_type: u8, plaintext: []const u8, cid: []const u8, out: []u8) Error![]u8 {
    if (cid.len > max_cid_len) return error.BufferTooShort;
    const inner_len = plaintext.len + 1;
    const frag_len = inner_len + keys.bulk.overhead();
    const hdr_len = CidHeader.len(cid.len);
    if (frag_len > std.math.maxInt(u16)) return error.BufferTooShort;
    if (out.len < hdr_len + frag_len) return error.BufferTooShort;
    out[0] = content_tls12_cid;
    out[1..3].* = record.legacy_version_dtls12;
    std.mem.writeInt(u16, out[3..5], epoch, .big);
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, seq, .big);
    out[5..11].* = seq_be[2..8].*;
    @memcpy(out[11..][0..cid.len], cid);
    std.mem.writeInt(u16, out[11 + cid.len ..][0..2], @intCast(frag_len), .big);
    const rn = recordNumber(epoch, seq);
    var ad_buf: [23 + max_cid_len]u8 = undefined;
    const ad = additionalDataCid(epoch, seq, cid, inner_len, &ad_buf);
    const n = nonce(keys, rn);
    var body = out[hdr_len..][0..frag_len];
    if (keys.bulk.hasExplicitNonce()) {
        body[0..8].* = rn;
        body = body[8..];
    }
    const inner = body[0..inner_len];
    std.mem.copyForwards(u8, inner[0..plaintext.len], plaintext);
    inner[plaintext.len] = content_type;
    var tag: [tag_len]u8 = undefined;
    switch (keys.bulk) {
        .aes_128_gcm => if (keys.gcm == .g128) keys.gcm.g128.encrypt(inner, &tag, inner, ad, n) else Aes128Gcm.encrypt(inner, &tag, inner, ad, n, keys.key[0..16].*),
        .aes_256_gcm => if (keys.gcm == .g256) keys.gcm.g256.encrypt(inner, &tag, inner, ad, n) else Aes256Gcm.encrypt(inner, &tag, inner, ad, n, keys.key),
        .chacha20_poly1305 => ChaCha20Poly1305.encrypt(inner, &tag, inner, ad, n, keys.key),
        .aes_128_ccm => Aes128Ccm.encrypt(inner, &tag, inner, ad, n, keys.key[0..16].*) catch return error.BufferTooShort,
        .aes_128_ccm_8 => Aes128Ccm8.encrypt(inner, tag[0..8], inner, ad, n, keys.key[0..16].*) catch return error.BufferTooShort,
    }
    const tl = keys.bulk.tagLen();
    @memcpy(body[inner_len..][0..tl], tag[0..tl]);
    return out[0 .. hdr_len + frag_len];
}

pub const OpenedCid = struct { content_type: u8, plaintext: []u8 };

/// Opens a `tls12_cid` record (`hdr` from `decodeCidHeader`, `fragment` its
/// `length` bytes) into `out`: the inner content type and the content,
/// padding removed. An inner plaintext of zeros only is `error.DecryptionFailed`
/// too (RFC 9146 §4: no real type), so a malformed record gives no oracle.
pub fn openCid(keys: *const DirKeys, hdr: CidHeader, fragment: []const u8, out: []u8) Error!OpenedCid {
    return burn.run(burn.aead_burn, Error!OpenedCid, openCidBody, .{ keys, hdr, fragment, out });
}

fn openCidBody(keys: *const DirKeys, hdr: CidHeader, fragment: []const u8, out: []u8) Error!OpenedCid {
    if (fragment.len < keys.bulk.overhead() + 1) return error.RecordTooShort;
    const inner_len = fragment.len - keys.bulk.overhead();
    if (out.len < inner_len) return error.BufferTooShort;
    var n: [12]u8 = undefined;
    var body = fragment;
    switch (keys.bulk) {
        .aes_128_gcm, .aes_256_gcm, .aes_128_ccm, .aes_128_ccm_8 => {
            n[0..4].* = keys.iv[0..4].*;
            n[4..12].* = fragment[0..8].*;
            body = fragment[8..];
        },
        .chacha20_poly1305 => n = nonce(keys, recordNumber(hdr.epoch, hdr.sequence_number)),
    }
    var ad_buf: [23 + max_cid_len]u8 = undefined;
    const ad = additionalDataCid(hdr.epoch, hdr.sequence_number, hdr.cid, inner_len, &ad_buf);
    const pt = out[0..inner_len];
    const r: anyerror!void = switch (keys.bulk) {
        .aes_128_gcm => if (keys.gcm == .g128) keys.gcm.g128.decrypt(pt, body[0..inner_len], body[inner_len..][0..16].*, ad, n) else Aes128Gcm.decrypt(pt, body[0..inner_len], body[inner_len..][0..16].*, ad, n, keys.key[0..16].*),
        .aes_256_gcm => if (keys.gcm == .g256) keys.gcm.g256.decrypt(pt, body[0..inner_len], body[inner_len..][0..16].*, ad, n) else Aes256Gcm.decrypt(pt, body[0..inner_len], body[inner_len..][0..16].*, ad, n, keys.key),
        .chacha20_poly1305 => ChaCha20Poly1305.decrypt(pt, body[0..inner_len], body[inner_len..][0..16].*, ad, n, keys.key),
        .aes_128_ccm => Aes128Ccm.decrypt(pt, body[0..inner_len], body[inner_len..][0..16].*, ad, n, keys.key[0..16].*),
        .aes_128_ccm_8 => Aes128Ccm8.decrypt(pt, body[0..inner_len], body[inner_len..][0..8].*, ad, n, keys.key[0..16].*),
    };
    r catch {
        std.crypto.secureZero(u8, pt);
        return error.DecryptionFailed;
    };
    var end = inner_len;
    while (end > 0 and pt[end - 1] == 0) end -= 1;
    if (end == 0) return error.DecryptionFailed;
    return .{ .content_type = pt[end - 1], .plaintext = pt[0 .. end - 1] };
}

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

test "record12 CID: sealCid/openCid round trip for every bulk cipher, the RFC 9146 header, tamper and wrong-CID refusal" {
    const cid = "cid-of-the-peer";
    for ([_]Bulk{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305, .aes_128_ccm, .aes_128_ccm_8 }) |bulk| {
        var k = DirKeys{ .bulk = bulk };
        for (&k.key, 0..) |*b, i| b.* = @intCast(i);
        for (&k.iv, 0..) |*b, i| b.* = @intCast(0x80 + i);
        var buf: [160]u8 = undefined;
        const rec = try sealCid(&k, 1, 9, 23, "hello cid", cid, &buf);
        try testing.expectEqual(CidHeader.len(cid.len) + 9 + 1 + bulk.overhead(), rec.len);
        try testing.expectEqual(content_tls12_cid, rec[0]);
        try testing.expectEqualSlices(u8, cid, rec[11..][0..cid.len]);
        const hdr = try decodeCidHeader(rec, cid.len);
        try testing.expectEqual(@as(u16, 1), hdr.epoch);
        try testing.expectEqual(@as(u48, 9), hdr.sequence_number);
        try testing.expectEqual(@as(usize, hdr.length), rec.len - CidHeader.len(cid.len));
        var out: [96]u8 = undefined;
        const got = try openCid(&k, hdr, rec[CidHeader.len(cid.len)..], &out);
        try testing.expectEqual(@as(u8, 23), got.content_type);
        try testing.expectEqualStrings("hello cid", got.plaintext);
        // The CID is authenticated: the same bytes under another CID fail.
        var hdr2 = hdr;
        hdr2.cid = "cid-of-the-peeR";
        try testing.expectError(error.DecryptionFailed, openCid(&k, hdr2, rec[CidHeader.len(cid.len)..], &out));
        for (CidHeader.len(cid.len)..rec.len) |i| {
            var t = buf;
            t[i] ^= 1;
            try testing.expectError(error.DecryptionFailed, openCid(&k, hdr, t[CidHeader.len(cid.len)..rec.len], &out));
        }
    }
    var wrong_type: [15]u8 = @splat(0);
    wrong_type[0..3].* = .{ 23, 0xfe, 0xfd };
    try testing.expectError(error.Malformed, decodeCidHeader(&wrong_type, 0));
    var short: [12]u8 = @splat(0);
    short[0..3].* = .{ 25, 0xfe, 0xfd };
    try testing.expectError(error.Malformed, decodeCidHeader(&short, 4));
}

test "record12 CID: the RFC 9146 §5.3 additional data, byte for byte" {
    var buf: [23 + max_cid_len]u8 = undefined;
    const ad = additionalDataCid(1, 0x0102030405, &.{ 0xaa, 0xbb }, 0x0123, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // seq_num_placeholder
        25, 2, 25, // tls12_cid, cid_length, tls12_cid
        0xfe, 0xfd, // version
        0x00, 0x01, // epoch
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // sequence_number
        0xaa, 0xbb, // cid
        0x01, 0x23, // length_of_DTLSInnerPlaintext
    }, ad);
}

test "record12 CID: in-place sealing equals sealing from a separate buffer, every bulk cipher and length 0..300" {
    for ([_]Bulk{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305, .aes_128_ccm, .aes_128_ccm_8 }) |bulk| {
        var k = DirKeys{ .bulk = bulk };
        for (&k.key, 0..) |*b, i| b.* = @intCast(i * 3 + 1);
        for (&k.iv, 0..) |*b, i| b.* = @intCast(0x40 + i);
        var pt: [300]u8 = undefined;
        for (&pt, 0..) |*b, i| b.* = @truncate(i * 7 + 5);
        for (0..pt.len + 1) |n| {
            var buf: [400]u8 = undefined;
            const rec = try sealCid(&k, 1, @intCast(n), 23, pt[0..n], "ab", &buf);
            const hdr = try decodeCidHeader(rec, 2);
            var out: [400]u8 = undefined;
            const got = try openCid(&k, hdr, rec[CidHeader.len(2)..], &out);
            try testing.expectEqualSlices(u8, pt[0..n], got.plaintext);
            // The same tag as a reference AEAD call over a separate inner buffer.
            var inner: [301]u8 = undefined;
            @memcpy(inner[0..n], pt[0..n]);
            inner[n] = 23;
            var ct: [301]u8 = undefined;
            var tag: [16]u8 = undefined;
            var ad_buf: [23 + max_cid_len]u8 = undefined;
            const ad = additionalDataCid(1, @intCast(n), "ab", n + 1, &ad_buf);
            const nn = nonce(&k, recordNumber(1, @intCast(n)));
            switch (bulk) {
                .aes_128_gcm => Aes128Gcm.encrypt(ct[0 .. n + 1], &tag, inner[0 .. n + 1], ad, nn, k.key[0..16].*),
                .aes_256_gcm => Aes256Gcm.encrypt(ct[0 .. n + 1], &tag, inner[0 .. n + 1], ad, nn, k.key),
                .chacha20_poly1305 => ChaCha20Poly1305.encrypt(ct[0 .. n + 1], &tag, inner[0 .. n + 1], ad, nn, k.key),
                .aes_128_ccm => try Aes128Ccm.encrypt(ct[0 .. n + 1], &tag, inner[0 .. n + 1], ad, nn, k.key[0..16].*),
                .aes_128_ccm_8 => try Aes128Ccm8.encrypt(ct[0 .. n + 1], tag[0..8], inner[0 .. n + 1], ad, nn, k.key[0..16].*),
            }
            const off = CidHeader.len(2) + @as(usize, if (bulk.hasExplicitNonce()) 8 else 0);
            try testing.expectEqualSlices(u8, ct[0 .. n + 1], rec[off..][0 .. n + 1]);
            try testing.expectEqualSlices(u8, tag[0..bulk.tagLen()], rec[off + n + 1 ..][0..bulk.tagLen()]);
        }
    }
}

test "DirKeys.prepare: the cached AES-GCM key schedule seals and opens byte for byte like the stateless call (plain and CID records); wipe clears it" {
    inline for (.{ Bulk.aes_128_gcm, Bulk.aes_256_gcm }) |bulk| {
        var plain: DirKeys = .{ .bulk = bulk };
        for (&plain.key, 0..) |*b, i| b.* = @intCast(i * 3 + 1);
        for (&plain.iv, 0..) |*b, i| b.* = @intCast(0x40 + i);
        var keyed = plain;
        keyed.prepare();
        try std.testing.expect(keyed.gcm != .none and plain.gcm == .none);
        var msg: [1200]u8 = undefined;
        for (&msg, 0..) |*b, i| b.* = @truncate(i *% 7);
        for ([_]usize{ 0, 1, 100, 1200 }, 0..) |len, k| {
            const seq: u48 = @intCast(k + 5);
            var oa: [1300]u8 = undefined;
            var ob: [1300]u8 = undefined;
            const ra = try seal(&keyed, 1, seq, 23, msg[0..len], &oa);
            const rb = try seal(&plain, 1, seq, 23, msg[0..len], &ob);
            try std.testing.expectEqualSlices(u8, rb, ra);
            const hdr = try record.decodePlaintext(ra);
            var pt: [1300]u8 = undefined;
            const back = try open(&keyed, hdr, ra[record.plaintext_header_len..], &pt);
            try std.testing.expectEqualSlices(u8, msg[0..len], back);
            const cid = [_]u8{ 9, 8, 7 };
            const ca = try sealCid(&keyed, 1, seq, 23, msg[0..len], &cid, &oa);
            const cb = try sealCid(&plain, 1, seq, 23, msg[0..len], &cid, &ob);
            try std.testing.expectEqualSlices(u8, cb, ca);
            const ch = try decodeCidHeader(ca, cid.len);
            const opened = try openCid(&keyed, ch, ca[CidHeader.len(cid.len)..][0..ch.length], &pt);
            try std.testing.expectEqualSlices(u8, msg[0..len], opened.plaintext);
        }
        keyed.wipe();
        try std.testing.expect(keyed.gcm == .none);
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&keyed.gcm), 0));
    }
}

test "mutation 2026-11-25: DirKeys.prepare caches the variant of the bulk cipher and clears it for any other (a re-prepare after a bulk change)" {
    var k: DirKeys = .{ .bulk = .aes_128_gcm };
    for (&k.key, 0..) |*b, i| b.* = @intCast(i + 1);
    k.prepare();
    try std.testing.expect(k.gcm == .g128);
    k.bulk = .aes_256_gcm;
    k.prepare();
    try std.testing.expect(k.gcm == .g256);
    k.bulk = .chacha20_poly1305;
    k.prepare();
    try std.testing.expect(k.gcm == .none);
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&k.gcm), 0));
    // Never-prepared keys open what prepared keys seal, for the 256-bit key too.
    k.bulk = .aes_256_gcm;
    var prepared = k;
    prepared.prepare();
    var out: [64]u8 = undefined;
    const sealed = try seal(&prepared, 1, 2, 23, "payload", &out);
    const hdr = try record.decodePlaintext(sealed);
    var pt: [64]u8 = undefined;
    try std.testing.expectEqualStrings("payload", try open(&k, hdr, sealed[record.plaintext_header_len..], &pt));
}

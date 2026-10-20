// SPDX-License-Identifier: MIT

//! tlsserver.record — the TLS 1.3 record layer over a byte stream (RFC 8446
//! §5): the 5-byte header, and per-direction record protection
//! (`TLSInnerPlaintext` = content ‖ type ‖ zero padding, AEAD-sealed with the
//! nonce `iv XOR seq` and the header as additional data).
//!
//! Both `Protection.seal` and `Protection.open` work IN PLACE over one
//! buffer: the content sits at `buf[header_len..]`, the header in front of
//! it, the tag after it. That is the layout qap's zero-copy record codecs
//! write and read (`docs: reuse-map §1`), and it means a record never needs
//! a second buffer.
//!
//! Policy is the engine's: when to rekey (`Protection.seq` against the AEAD's
//! limit), how much to pad, which outer content types are acceptable in
//! which state. This file only frames and protects.

const std = @import("std");
const tls13 = @import("tls13");
const burn = @import("burn.zig");

const Aes128Gcm = @import("aesgcm").Aes128Gcm;
const Aes256Gcm = @import("aesgcm").Aes256Gcm;
const ChaCha20Poly1305 = @import("chachapoly").ChaCha20Poly1305;
const ks = tls13.keyschedule.tls13;

/// RFC 8446 §B.4 cipher suites this layer protects records under.
pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
    _,

    /// Length of the suite hash's output: the traffic-secret length.
    pub fn hashLen(suite: CipherSuite) ?usize {
        return switch (suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => 32,
            .aes_256_gcm_sha384 => 48,
            _ => null,
        };
    }
};

/// RFC 8446 §5.1 `ContentType`. Non-exhaustive: an unknown outer or inner
/// type is the engine's `unexpected_message`, not a parse failure here.
pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

pub const header_len = 5;
pub const tag_len = 16;
pub const nonce_len = 12;
/// RFC 8446 §5.1: `TLSPlaintext.length` MUST NOT exceed 2^14.
pub const max_plaintext_len = 1 << 14;
/// RFC 8446 §5.2: `TLSInnerPlaintext` (content + type + padding) MUST NOT
/// exceed 2^14 + 1 octets.
pub const max_inner_len = max_plaintext_len + 1;
/// RFC 8446 §5.2: `TLSCiphertext.length` MUST NOT exceed 2^14 + 256.
pub const max_ciphertext_len = max_plaintext_len + 256;
/// The largest record a peer may send: header plus the ciphertext limit. A
/// receive buffer of this size always holds one whole record.
pub const max_record_len = header_len + max_ciphertext_len;
/// The legacy_record_version every protected record and every record after
/// the first ClientHello carries (RFC 8446 §5.1).
pub const legacy_version: u16 = 0x0303;

pub const Header = struct {
    content_type: ContentType,
    legacy_version: u16,
    length: u16,
};

/// The 5-byte record header. Pure decoding; the caller checks `length`
/// against the limit for the record's kind (`max_plaintext_len` for a
/// plaintext record, `max_ciphertext_len` for a protected one).
pub fn parseHeader(bytes: *const [header_len]u8) Header {
    return .{
        .content_type = @fromBackingInt(bytes[0]),
        .legacy_version = std.mem.readInt(u16, bytes[1..3], .big),
        .length = std.mem.readInt(u16, bytes[3..5], .big),
    };
}

pub fn writeHeader(out: *[header_len]u8, content_type: ContentType, length: u16) void {
    out[0] = @backingInt(content_type);
    std.mem.writeInt(u16, out[1..3], legacy_version, .big);
    std.mem.writeInt(u16, out[3..5], length, .big);
}

pub const InitError = error{
    /// Not one of `CipherSuite`'s named suites.
    UnsupportedSuite,
    /// A traffic secret or key whose length is not the suite's.
    BadKeyLength,
};

pub const SealError = error{
    /// `buf` cannot hold header + content + type + padding + tag.
    BufferTooSmall,
    /// content + type + padding exceeds `max_inner_len`.
    RecordOverflow,
    /// The sequence number is at 2^64 − 1: this key must be replaced
    /// (KeyUpdate) before another record goes out (RFC 8446 §5.3).
    SequenceExhausted,
};

pub const OpenError = error{
    /// `record` is not one header plus exactly the length it declares.
    BadRecordLength,
    /// The outer type of a protected record is not `application_data`.
    UnexpectedRecordType,
    /// The ciphertext exceeds `max_ciphertext_len`, or the decrypted inner
    /// plaintext exceeds `max_inner_len` (RFC 8446 §5.2: `record_overflow`).
    RecordOverflow,
    /// Authentication failed, or the ciphertext is too short to hold a tag
    /// and a type octet (RFC 8446 §5.2: `bad_record_mac`). The buffer's
    /// ciphertext is zeroed.
    BadRecordMac,
    /// The inner plaintext is all zeros — no content type (RFC 8446 §5.4:
    /// `unexpected_message`).
    MissingContentType,
    SequenceExhausted,
};

/// What `open` found: the inner content type and the content, a slice of
/// the record buffer (`record[header_len..][0..content.len]`).
pub const Opened = struct {
    content_type: ContentType,
    content: []u8,
};

/// One direction's record protection: the AEAD key state (an expanded
/// `aesgcm.Context` per direction, so a record pays no key schedule), the
/// static IV and the sequence number.
///
/// Holds secrets: `wipe` when the key is retired (KeyUpdate, close, error).
pub const Protection = struct {
    aead: Aead,
    iv: [nonce_len]u8,
    /// The next record's sequence number (RFC 8446 §5.3). Public; the engine
    /// reads it to decide when to KeyUpdate.
    seq: u64 = 0,

    const Aead = union(enum) {
        aes128: Aes128Gcm.Context,
        aes256: Aes256Gcm.Context,
        chacha: [ChaCha20Poly1305.key_length]u8,
    };

    /// `out` ← the protection for `traffic_secret` (RFC 8446 §7.3: key and
    /// IV by HKDF-Expand-Label "key" / "iv"), sequence number 0.
    pub fn init(out: *Protection, suite: CipherSuite, traffic_secret: []const u8) InitError!void {
        return burn.run(burn.init_burn, InitError!void, initBody, .{ out, suite, traffic_secret });
    }

    fn initBody(out: *Protection, suite: CipherSuite, traffic_secret: []const u8) InitError!void {
        const want = suite.hashLen() orelse return error.UnsupportedSuite;
        if (traffic_secret.len != want) return error.BadKeyLength;
        switch (suite) {
            .aes_128_gcm_sha256 => {
                var key: [16]u8 = undefined;
                defer std.crypto.secureZero(u8, &key);
                ks.deriveTrafficKeyIv(std.crypto.kdf.hkdf.HkdfSha256, 16, nonce_len, &key, &out.iv, traffic_secret[0..32]);
                out.aead = .{ .aes128 = undefined };
                Aes128Gcm.Context.initInto(&out.aead.aes128, &key);
            },
            .aes_256_gcm_sha384 => {
                var key: [32]u8 = undefined;
                defer std.crypto.secureZero(u8, &key);
                ks.deriveTrafficKeyIv(HkdfSha384, 32, nonce_len, &key, &out.iv, traffic_secret[0..48]);
                out.aead = .{ .aes256 = undefined };
                Aes256Gcm.Context.initInto(&out.aead.aes256, &key);
            },
            .chacha20_poly1305_sha256 => {
                out.aead = .{ .chacha = undefined };
                ks.deriveTrafficKeyIv(std.crypto.kdf.hkdf.HkdfSha256, 32, nonce_len, &out.aead.chacha, &out.iv, traffic_secret[0..32]);
            },
            _ => unreachable,
        }
        out.seq = 0;
    }

    /// `out` ← the protection for an explicit key and IV, sequence number 0
    /// — for known-answer tests and for keys derived elsewhere.
    pub fn initKeyIv(out: *Protection, suite: CipherSuite, key: []const u8, iv: *const [nonce_len]u8) InitError!void {
        return burn.run(burn.init_burn, InitError!void, initKeyIvBody, .{ out, suite, key, iv });
    }

    fn initKeyIvBody(out: *Protection, suite: CipherSuite, key: []const u8, iv: *const [nonce_len]u8) InitError!void {
        switch (suite) {
            .aes_128_gcm_sha256 => {
                if (key.len != 16) return error.BadKeyLength;
                out.aead = .{ .aes128 = undefined };
                Aes128Gcm.Context.initInto(&out.aead.aes128, key[0..16]);
            },
            .aes_256_gcm_sha384 => {
                if (key.len != 32) return error.BadKeyLength;
                out.aead = .{ .aes256 = undefined };
                Aes256Gcm.Context.initInto(&out.aead.aes256, key[0..32]);
            },
            .chacha20_poly1305_sha256 => {
                if (key.len != 32) return error.BadKeyLength;
                out.aead = .{ .chacha = key[0..32].* };
            },
            _ => return error.UnsupportedSuite,
        }
        out.iv = iv.*;
        out.seq = 0;
    }

    /// Zero the key state and IV. The protection is unusable afterwards.
    pub fn wipe(self: *Protection) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    /// RFC 8446 §5.3: the 64-bit sequence number, big-endian, left-padded to
    /// the IV length and XORed with it.
    fn nonce(self: *const Protection) [nonce_len]u8 {
        var n = self.iv;
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, self.seq, .big);
        for (n[nonce_len - 8 ..], seq_bytes) |*b, s| b.* ^= s;
        return n;
    }

    /// Seal one record in place. On entry `buf[header_len..][0..content_len]`
    /// holds the content; on return `buf[0..n]` is the complete record (header
    /// ‖ ciphertext ‖ tag) with `n = header_len + content_len + 1 + pad +
    /// tag_len`, and the sequence number has advanced. `pad` zero octets of
    /// padding follow the content type (RFC 8446 §5.4).
    pub fn seal(self: *Protection, buf: []u8, content_len: usize, content_type: ContentType, pad: usize) SealError![]u8 {
        return burn.run(burn.record_burn, SealError![]u8, sealBody, .{ self, buf, content_len, content_type, pad });
    }

    fn sealBody(self: *Protection, buf: []u8, content_len: usize, content_type: ContentType, pad: usize) SealError![]u8 {
        const inner_len = content_len + 1 + pad;
        if (inner_len > max_inner_len) return error.RecordOverflow;
        const ct_len = inner_len + tag_len;
        if (buf.len < header_len + ct_len) return error.BufferTooSmall;
        if (self.seq == std.math.maxInt(u64)) return error.SequenceExhausted;

        const inner = buf[header_len..][0..inner_len];
        inner[content_len] = @backingInt(content_type);
        @memset(inner[content_len + 1 ..], 0);
        writeHeader(buf[0..header_len], .application_data, @intCast(ct_len));
        const ad = buf[0..header_len];
        const tag = buf[header_len + inner_len ..][0..tag_len];
        const n = self.nonce();
        switch (self.aead) {
            .aes128 => |*c| c.encrypt(inner, tag, inner, ad, n),
            .aes256 => |*c| c.encrypt(inner, tag, inner, ad, n),
            .chacha => |*k| ChaCha20Poly1305.encryptInto(inner, tag, inner, ad, n, k),
        }
        self.seq += 1;
        return buf[0 .. header_len + ct_len];
    }

    /// Open one protected record in place. `record` is exactly one record:
    /// the header and the `length` octets it declares. On success the content
    /// is decrypted into `record[header_len..]` and returned with its inner
    /// type; padding is stripped. On `BadRecordMac` the ciphertext is zeroed.
    /// The sequence number advances only on success.
    pub fn open(self: *Protection, record: []u8) OpenError!Opened {
        return burn.run(burn.record_burn, OpenError!Opened, openBody, .{ self, record });
    }

    fn openBody(self: *Protection, record: []u8) OpenError!Opened {
        if (record.len < header_len) return error.BadRecordLength;
        const h = parseHeader(record[0..header_len]);
        if (record.len != header_len + @as(usize, h.length)) return error.BadRecordLength;
        if (h.content_type != .application_data) return error.UnexpectedRecordType;
        if (h.length > max_ciphertext_len) return error.RecordOverflow;
        if (h.length < tag_len + 1) return error.BadRecordMac;
        if (self.seq == std.math.maxInt(u64)) return error.SequenceExhausted;

        const inner_len = h.length - tag_len;
        const inner = record[header_len..][0..inner_len];
        const tag = record[header_len + inner_len ..][0..tag_len].*;
        const ad = record[0..header_len];
        const n = self.nonce();
        switch (self.aead) {
            .aes128 => |*c| c.decrypt(inner, inner, tag, ad, n) catch return error.BadRecordMac,
            .aes256 => |*c| c.decrypt(inner, inner, tag, ad, n) catch return error.BadRecordMac,
            .chacha => |*k| ChaCha20Poly1305.decryptInto(inner, inner, tag, ad, n, k) catch return error.BadRecordMac,
        }
        self.seq += 1;
        if (inner_len > max_inner_len) return error.RecordOverflow;
        // RFC 8446 §5.4: the content type is the last non-zero octet.
        var i: usize = inner_len;
        while (i > 0) {
            i -= 1;
            if (inner[i] != 0) return .{ .content_type = @fromBackingInt(inner[i]), .content = inner[0..i] };
        }
        return error.MissingContentType;
    }
};

const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const kat = @import("record_kat_vectors.zig");

test "RFC 8448 §3: every protected record seals byte-exact and opens back" {
    for (kat.vectors) |v| {
        var p: Protection = undefined;
        try p.initKeyIv(.aes_128_gcm_sha256, &v.key, &v.iv);
        p.seq = v.seq;
        var buf: [1024]u8 = undefined;
        @memcpy(buf[header_len..][0..v.plaintext.len], v.plaintext);
        const rec = try p.seal(&buf, v.plaintext.len, @fromBackingInt(v.content_type), 0);
        testing.expectEqualSlices(u8, v.record, rec) catch |e| {
            std.debug.print("record {s}\n", .{v.name});
            return e;
        };
        try testing.expectEqual(v.seq + 1, p.seq);

        var q: Protection = undefined;
        try q.initKeyIv(.aes_128_gcm_sha256, &v.key, &v.iv);
        q.seq = v.seq;
        var in: [1024]u8 = undefined;
        @memcpy(in[0..v.record.len], v.record);
        const o = try q.open(in[0..v.record.len]);
        try testing.expectEqual(@as(ContentType, @fromBackingInt(v.content_type)), o.content_type);
        try testing.expectEqualSlices(u8, v.plaintext, o.content);
    }
}

test "AES-256-GCM and ChaCha20-Poly1305 records sealed by OpenSSL: seal byte-exact, open back" {
    // RFC 8448 has only TLS_AES_128_GCM_SHA256; these come from Python
    // `cryptography` (tools/rfc8448_records.py), with padding and sequence
    // numbers up to 2^64 - 2 so every nonce octet is exercised.
    for (kat.foreign_vectors) |v| {
        const suite: CipherSuite = @fromBackingInt(v.suite);
        var p: Protection = undefined;
        try p.initKeyIv(suite, v.key, &v.iv);
        p.seq = v.seq;
        var buf: [2048]u8 = undefined;
        @memcpy(buf[header_len..][0..v.plaintext.len], v.plaintext);
        const rec = try p.seal(&buf, v.plaintext.len, @fromBackingInt(v.content_type), v.pad);
        testing.expectEqualSlices(u8, v.record, rec) catch |e| {
            std.debug.print("record {s}\n", .{v.name});
            return e;
        };
        var q: Protection = undefined;
        try q.initKeyIv(suite, v.key, &v.iv);
        q.seq = v.seq;
        var in: [2048]u8 = undefined;
        @memcpy(in[0..v.record.len], v.record);
        const o = try q.open(in[0..v.record.len]);
        try testing.expectEqual(@as(ContentType, @fromBackingInt(v.content_type)), o.content_type);
        try testing.expectEqualSlices(u8, v.plaintext, o.content);
    }
}

test "RFC 8448 §3: the traffic secret derives the record key the RFC used" {
    // §3's server handshake traffic secret; its "key expanded" / "iv
    // expanded" are the first vector's key and IV.
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    var p: Protection = undefined;
    try p.init(.aes_128_gcm_sha256, &secret);
    const v = kat.vectors[0];
    try testing.expectEqualSlices(u8, &v.iv, &p.iv);
    var buf: [1024]u8 = undefined;
    @memcpy(buf[header_len..][0..v.plaintext.len], v.plaintext);
    try testing.expectEqualSlices(u8, v.record, try p.seal(&buf, v.plaintext.len, .handshake, 0));
}

fn roundTrip(suite: CipherSuite, secret: []const u8) !void {
    var tx: Protection = undefined;
    var rx: Protection = undefined;
    try tx.init(suite, secret);
    try rx.init(suite, secret);
    defer tx.wipe();
    defer rx.wipe();
    var buf: [max_record_len]u8 = undefined;
    for ([_]usize{ 0, 1, 15, 16, 17, 255, 4096, max_plaintext_len }) |len| {
        for ([_]usize{ 0, 1, 37 }) |pad| {
            if (len + 1 + pad > max_inner_len) continue;
            for (buf[header_len..][0..len], 0..) |*b, i| b.* = @truncate(i *% 31 +% len);
            const rec = try tx.seal(&buf, len, .application_data, pad);
            try testing.expectEqual(header_len + len + 1 + pad + tag_len, rec.len);
            const o = try rx.open(rec);
            try testing.expectEqual(ContentType.application_data, o.content_type);
            try testing.expectEqual(len, o.content.len);
            for (o.content, 0..) |b, i| try testing.expectEqual(@as(u8, @truncate(i *% 31 +% len)), b);
        }
    }
    try testing.expectEqual(tx.seq, rx.seq);
}

test "seal/open round trip, every suite, lengths 0..2^14, with padding" {
    const s32: [32]u8 = @splat(0x3c);
    const s48: [48]u8 = @splat(0x4d);
    try roundTrip(.aes_128_gcm_sha256, &s32);
    try roundTrip(.aes_256_gcm_sha384, &s48);
    try roundTrip(.chacha20_poly1305_sha256, &s32);
}

test "open: a flipped bit anywhere is BadRecordMac and the ciphertext is zeroed; the sequence does not advance" {
    const s: [32]u8 = @splat(0x11);
    inline for (.{ CipherSuite.aes_128_gcm_sha256, CipherSuite.chacha20_poly1305_sha256 }) |suite| {
        var tx: Protection = undefined;
        try tx.init(suite, &s);
        var buf: [256]u8 = undefined;
        @memcpy(buf[header_len..][0..11], "hello world");
        const rec = try tx.seal(&buf, 11, .application_data, 3);
        for (header_len..rec.len) |at| {
            var rx: Protection = undefined;
            try rx.init(suite, &s);
            var bad: [256]u8 = undefined;
            @memcpy(bad[0..rec.len], rec);
            bad[at] ^= 0x01;
            try testing.expectError(error.BadRecordMac, rx.open(bad[0..rec.len]));
            try testing.expectEqual(@as(u64, 0), rx.seq);
            for (bad[header_len..][0 .. rec.len - header_len - tag_len]) |b| try testing.expectEqual(@as(u8, 0), b);
        }
        // The header is authenticated too (it is the additional data): a
        // length-preserving change to the version octets fails the tag.
        var rx: Protection = undefined;
        try rx.init(suite, &s);
        var bad: [256]u8 = undefined;
        @memcpy(bad[0..rec.len], rec);
        bad[2] ^= 0x01;
        try testing.expectError(error.BadRecordMac, rx.open(bad[0..rec.len]));
    }
}

test "open: a record under the wrong sequence number does not authenticate" {
    const s: [32]u8 = @splat(0x22);
    var tx: Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, &s);
    var buf: [64]u8 = undefined;
    @memcpy(buf[header_len..][0..2], "hi");
    const rec = try tx.seal(&buf, 2, .application_data, 0);
    var rx: Protection = undefined;
    try rx.init(.aes_128_gcm_sha256, &s);
    rx.seq = 1; // a replayed or reordered record
    try testing.expectError(error.BadRecordMac, rx.open(rec));
}

test "open: length, type and size limits" {
    const s: [32]u8 = @splat(0x33);
    var rx: Protection = undefined;
    try rx.init(.aes_128_gcm_sha256, &s);
    var buf: [max_record_len + 8]u8 = @splat(0);

    // Declared length disagrees with the slice.
    writeHeader(buf[0..5], .application_data, 40);
    try testing.expectError(error.BadRecordLength, rx.open(buf[0..44]));
    try testing.expectError(error.BadRecordLength, rx.open(buf[0..3]));
    // Outer type other than application_data.
    writeHeader(buf[0..5], .handshake, 40);
    try testing.expectError(error.UnexpectedRecordType, rx.open(buf[0..45]));
    // Over the ciphertext limit (checked before any decryption).
    writeHeader(buf[0..5], .application_data, max_ciphertext_len + 1);
    try testing.expectError(error.RecordOverflow, rx.open(buf[0 .. header_len + max_ciphertext_len + 1]));
    // Too short to carry a tag and a type octet.
    writeHeader(buf[0..5], .application_data, tag_len);
    try testing.expectError(error.BadRecordMac, rx.open(buf[0 .. header_len + tag_len]));
    try testing.expectEqual(@as(u64, 0), rx.seq);
}

test "open: an authentic record whose inner plaintext is all padding is MissingContentType" {
    // Sealed with content type 0 (`invalid`), i.e. nothing but zeros inside.
    const s: [32]u8 = @splat(0x44);
    var tx: Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, &s);
    var rx = tx;
    var buf: [64]u8 = undefined;
    const rec = try tx.seal(&buf, 0, .invalid, 9);
    try testing.expectError(error.MissingContentType, rx.open(rec));
}

test "open: an authentic inner plaintext over 2^14 + 1 is RecordOverflow" {
    // A peer may seal content + type + padding up to 2^14 + 256 − 16 octets;
    // RFC 8446 §5.2 caps the inner plaintext at 2^14 + 1 regardless.
    const s: [32]u8 = @splat(0x55);
    var tx: Protection = undefined;
    try tx.init(.chacha20_poly1305_sha256, &s);
    var rx = tx;
    var buf: [max_record_len]u8 = undefined;
    // Bypass seal's own limit: build the oversized inner plaintext by hand.
    const inner_len = max_inner_len + 1;
    @memset(buf[header_len..][0..inner_len], 0);
    buf[header_len + inner_len - 1] = @backingInt(ContentType.application_data);
    writeHeader(buf[0..5], .application_data, inner_len + tag_len);
    const inner = buf[header_len..][0..inner_len];
    ChaCha20Poly1305.encryptInto(inner, buf[header_len + inner_len ..][0..tag_len], inner, buf[0..5], tx.nonce(), &tx.aead.chacha);
    try testing.expectError(error.RecordOverflow, rx.open(buf[0 .. header_len + inner_len + tag_len]));
}

test "seal: limits and sequence exhaustion" {
    const s: [32]u8 = @splat(0x66);
    var tx: Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, &s);
    var buf: [max_record_len]u8 = undefined;
    try testing.expectError(error.RecordOverflow, tx.seal(&buf, max_plaintext_len, .application_data, 1));
    _ = try tx.seal(&buf, max_plaintext_len, .application_data, 0);
    try testing.expectError(error.BufferTooSmall, tx.seal(buf[0..30], 10, .application_data, 0));
    tx.seq = std.math.maxInt(u64);
    try testing.expectError(error.SequenceExhausted, tx.seal(&buf, 1, .application_data, 0));
    var rx: Protection = undefined;
    try rx.init(.aes_128_gcm_sha256, &s);
    rx.seq = std.math.maxInt(u64);
    writeHeader(buf[0..5], .application_data, 20);
    try testing.expectError(error.SequenceExhausted, rx.open(buf[0..25]));
}

test "init: suite and key-length errors" {
    var p: Protection = undefined;
    const s32: [32]u8 = @splat(1);
    try testing.expectError(error.UnsupportedSuite, p.init(@fromBackingInt(0x1304), &s32));
    try testing.expectError(error.BadKeyLength, p.init(.aes_256_gcm_sha384, &s32));
    try testing.expectError(error.BadKeyLength, p.initKeyIv(.aes_128_gcm_sha256, &s32, &@as([12]u8, @splat(0))));
}

test "parseHeader / writeHeader" {
    var h: [5]u8 = undefined;
    writeHeader(&h, .handshake, 0x1234);
    try testing.expectEqualSlices(u8, &.{ 22, 3, 3, 0x12, 0x34 }, &h);
    const p = parseHeader(&h);
    try testing.expectEqual(ContentType.handshake, p.content_type);
    try testing.expectEqual(@as(u16, 0x0303), p.legacy_version);
    try testing.expectEqual(@as(u16, 0x1234), p.length);
}

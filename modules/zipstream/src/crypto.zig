// SPDX-License-Identifier: MIT
//! ZIP encryption: WinZip AES (AE-1/AE-2, read and write) and the legacy
//! PKWARE "traditional" ZipCrypto (read only — it is broken and never
//! written). Both are stream transforms between the entry's stored bytes
//! and its (de)compressor.
//!
//! WinZip AES ("AES Encryption Information: Encryption Specification AE-1
//! and AE-2", WinZip, 2009): extra field 0x9901 {vendor version 1|2, "AE",
//! strength 1|2|3 = AES-128/192/256, actual method}; data = salt (8/12/16
//! bytes) ‖ 2-byte password verifier ‖ ciphertext ‖ 10-byte authentication
//! code. Keys: PBKDF2-HMAC-SHA1(password, salt, 1000 rounds) → encryption
//! key ‖ authentication key ‖ verifier. Cipher: AES in CTR mode with a
//! LITTLE-endian 128-bit counter starting at 1. Code: the first 10 bytes of
//! HMAC-SHA1(authentication key, ciphertext). AE-2 stores CRC-32 = 0 (the
//! code authenticates instead); AE-1 keeps the CRC.
//!
//! ZipCrypto (APPNOTE 6.1): three 32-bit keys stepped per byte with CRC-32
//! and a multiply; a 12-byte header whose last byte checks the password
//! against the CRC's (or, with a data descriptor, the DOS time's) high byte.
//!
//! Provenance: original work of the zig-libs authors (MIT), from the two
//! published specifications; checked against 7-Zip and Info-ZIP output
//! (`tools/crypto_fixtures.sh`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const aes = std.crypto.core.aes;
/// std has AES-128/256 only; AES-192 is the sibling module.
const aes192 = @import("aes192");

pub const extra_id_aes: u16 = 0x9901;
/// The method id an AES entry carries in its headers; the real one is in
/// the extra field.
pub const method_aes: u16 = 99;

pub const Strength = enum(u8) {
    aes128 = 1,
    aes192 = 2,
    aes256 = 3,

    pub fn keyLen(s: Strength) usize {
        return switch (s) {
            .aes128 => 16,
            .aes192 => 24,
            .aes256 => 32,
        };
    }

    pub fn saltLen(s: Strength) usize {
        return s.keyLen() / 2;
    }
};

/// The 0x9901 record.
pub const AesInfo = struct {
    /// 1 = AE-1 (CRC kept), 2 = AE-2 (CRC zero).
    version: u16,
    strength: Strength,
    /// The compression method under the encryption.
    method: u16,
};

pub fn parseAesExtra(d: []const u8) ?AesInfo {
    if (d.len < 7 or d[2] != 'A' or d[3] != 'E') return null;
    const s = std.enums.fromInt(Strength, d[4]) orelse return null;
    return .{ .version = std.mem.readInt(u16, d[0..2], .little), .strength = s, .method = std.mem.readInt(u16, d[5..7], .little) };
}

/// The 11-byte 0x9901 record for a written entry (AE-2).
pub fn aesExtra(strength: Strength, method: u16) [11]u8 {
    var r: [11]u8 = undefined;
    std.mem.writeInt(u16, r[0..2], extra_id_aes, .little);
    std.mem.writeInt(u16, r[2..4], 7, .little);
    std.mem.writeInt(u16, r[4..6], 2, .little); // AE-2
    r[6] = 'A';
    r[7] = 'E';
    r[8] = @backingInt(strength);
    std.mem.writeInt(u16, r[9..11], method, .little);
    return r;
}

pub const pbkdf2_rounds = 1000;
pub const verifier_len = 2;
pub const mac_len = 10;

/// AES-CTR with WinZip's little-endian counter.
const Ctr = struct {
    ctx: union(enum) {
        a128: aes.AesEncryptCtx(aes.Aes128),
        a192: aes192.Aes192EncryptCtx,
        a256: aes.AesEncryptCtx(aes.Aes256),
    },
    counter: u128 = 0,
    stream: [16]u8 = undefined,
    used: usize = 16,

    fn init(strength: Strength, key: []const u8) Ctr {
        return .{ .ctx = switch (strength) {
            .aes128 => .{ .a128 = aes.Aes128.initEnc(key[0..16].*) },
            .aes192 => .{ .a192 = aes192.Aes192EncryptCtx.init(key[0..24].*) },
            .aes256 => .{ .a256 = aes.Aes256.initEnc(key[0..32].*) },
        } };
    }

    fn xor(self: *Ctr, buf: []u8) void {
        for (buf) |*b| {
            if (self.used == 16) {
                self.counter +%= 1;
                var block: [16]u8 = undefined;
                std.mem.writeInt(u128, &block, self.counter, .little);
                switch (self.ctx) {
                    inline else => |*c| c.encrypt(&self.stream, &block),
                }
                self.used = 0;
            }
            b.* ^= self.stream[self.used];
            self.used += 1;
        }
    }
};

const Keys = struct { ctr: Ctr, mac: HmacSha1, verifier: [2]u8 };

fn deriveKeys(password: []const u8, salt: []const u8, strength: Strength) !Keys {
    var dk: [32 + 32 + 2]u8 = undefined;
    const kl = strength.keyLen();
    const out = dk[0 .. 2 * kl + 2];
    try std.crypto.pwhash.pbkdf2(out, password, salt, pbkdf2_rounds, HmacSha1);
    defer std.crypto.secureZero(u8, &dk);
    return .{
        .ctr = .init(strength, out[0..kl]),
        .mac = HmacSha1.init(out[kl .. 2 * kl]),
        .verifier = out[2 * kl ..][0..2].*,
    };
}

pub const Error = error{
    /// The password does not open this entry (verifier / check byte).
    ZipBadPassword,
    /// An encrypted entry without a password.
    ZipEncryptedEntry,
    /// The encrypted data is shorter than its own framing.
    ZipBadCentralDirectory,
};

/// Decrypts a WinZip AES entry's stored bytes (`source` ends with them).
/// `auth_failed` tells a forged or corrupted ciphertext from an I/O error
/// once a read has failed: the code is checked when the ciphertext ends.
pub const AesReader = struct {
    source: *std.Io.Reader,
    remaining: u64,
    ctr: Ctr,
    mac: HmacSha1,
    auth_failed: bool = false,
    mac_checked: bool = false,
    interface: std.Io.Reader,

    pub fn init(self: *AesReader, source: *std.Io.Reader, stored_size: u64, strength: Strength, password: []const u8, buffer: []u8) !void {
        const sl = strength.saltLen();
        if (stored_size < sl + verifier_len + mac_len) return Error.ZipBadCentralDirectory;
        var salt: [16]u8 = undefined;
        source.readSliceAll(salt[0..sl]) catch return Error.ZipBadCentralDirectory;
        var pv: [2]u8 = undefined;
        source.readSliceAll(&pv) catch return Error.ZipBadCentralDirectory;
        const k = try deriveKeys(password, salt[0..sl], strength);
        if (!std.crypto.timing_safe.eql([2]u8, k.verifier, pv)) return Error.ZipBadPassword;
        self.* = .{
            .source = source,
            .remaining = stored_size - sl - verifier_len - mac_len,
            .ctr = k.ctr,
            .mac = k.mac,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *AesReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.remaining == 0) {
            try self.verify();
            return error.EndOfStream;
        }
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const want: usize = @intCast(@min(dest.len, self.remaining));
        const n = self.source.readSliceShort(dest[0..want]) catch return error.ReadFailed;
        if (n == 0) {
            self.auth_failed = true; // the data ends before the code
            return error.ReadFailed;
        }
        self.mac.update(dest[0..n]);
        self.ctr.xor(dest[0..n]);
        self.remaining -= n;
        // Verified with the last ciphertext byte, before it is delivered:
        // a consumer that stops at the entry's size still gets the check.
        if (self.remaining == 0) try self.verify();
        w.advance(n);
        return n;
    }

    /// Reads and checks the authentication code (once).
    fn verify(self: *AesReader) error{ReadFailed}!void {
        if (self.mac_checked) return if (self.auth_failed) error.ReadFailed else {};
        self.mac_checked = true;
        var code: [mac_len]u8 = undefined;
        self.source.readSliceAll(&code) catch {
            self.auth_failed = true;
            return error.ReadFailed;
        };
        var full: [HmacSha1.mac_length]u8 = undefined;
        self.mac.final(&full);
        if (!std.crypto.timing_safe.eql([mac_len]u8, full[0..mac_len].*, code)) {
            self.auth_failed = true;
            return error.ReadFailed;
        }
    }

    /// Reads (and discards) whatever ciphertext a decompressor left, then
    /// checks the code — the end-of-entry guarantee.
    pub fn drainAndVerify(self: *AesReader) error{ReadFailed}!void {
        var scratch: [1024]u8 = undefined;
        while (self.remaining != 0) {
            const want: usize = @intCast(@min(scratch.len, self.remaining));
            const n = self.source.readSliceShort(scratch[0..want]) catch return error.ReadFailed;
            if (n == 0) {
                self.auth_failed = true;
                return error.ReadFailed;
            }
            self.mac.update(scratch[0..n]);
            self.remaining -= n;
        }
        try self.verify();
    }
};

/// Encrypts toward `next` as WinZip AES (the salt, verifier and code are
/// written by `start` and `finish`). `stored` counts what reaches `next`.
pub const AesWriter = struct {
    next: *std.Io.Writer,
    ctr: Ctr,
    mac: HmacSha1,
    interface: std.Io.Writer,
    scratch: [4096]u8 = undefined,

    /// Writes salt ‖ verifier. `salt` must be `strength.saltLen()` random bytes.
    pub fn start(self: *AesWriter, next: *std.Io.Writer, strength: Strength, password: []const u8, salt: []const u8, buffer: []u8) !void {
        std.debug.assert(salt.len == strength.saltLen());
        const k = try deriveKeys(password, salt, strength);
        self.* = .{
            .next = next,
            .ctr = k.ctr,
            .mac = k.mac,
            .interface = .{ .buffer = buffer, .vtable = &.{ .drain = drain, .flush = flush } },
        };
        try next.writeAll(salt);
        try next.writeAll(&k.verifier);
    }

    fn put(self: *AesWriter, bytes: []const u8) std.Io.Writer.Error!void {
        var rest = bytes;
        while (rest.len != 0) {
            const n = @min(rest.len, self.scratch.len);
            const c = self.scratch[0..n];
            @memcpy(c, rest[0..n]);
            self.ctr.xor(c);
            self.mac.update(c);
            try self.next.writeAll(c);
            rest = rest[n..];
        }
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *AesWriter = @alignCast(@fieldParentPtr("interface", w));
        try self.put(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try self.put(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try self.put(last);
        return n + last.len * splat;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *AesWriter = @alignCast(@fieldParentPtr("interface", w));
        try self.put(w.buffered());
        w.end = 0;
    }

    /// Flushes and writes the authentication code.
    pub fn finish(self: *AesWriter) std.Io.Writer.Error!void {
        try self.interface.flush();
        var full: [HmacSha1.mac_length]u8 = undefined;
        self.mac.final(&full);
        try self.next.writeAll(full[0..mac_len]);
    }
};

/// The framing an AES entry adds to its compressed size.
pub fn aesOverhead(strength: Strength) usize {
    return strength.saltLen() + verifier_len + mac_len;
}

// ── ZipCrypto (read only) ──────────────────────────────────────────────────

const crc_table = blk: {
    @setEvalBranchQuota(10_000);
    var t: [256]u32 = undefined;
    for (&t, 0..) |*e, i| {
        var c: u32 = @intCast(i);
        for (0..8) |_| c = if (c & 1 != 0) 0xEDB88320 ^ (c >> 1) else c >> 1;
        e.* = c;
    }
    const final = t;
    break :blk final;
};

inline fn crcByte(c: u32, b: u8) u32 {
    return crc_table[(c ^ b) & 0xff] ^ (c >> 8);
}

const ZipCryptoKeys = struct {
    k0: u32 = 0x12345678,
    k1: u32 = 0x23456789,
    k2: u32 = 0x34567890,

    fn update(self: *ZipCryptoKeys, b: u8) void {
        self.k0 = crcByte(self.k0, b);
        self.k1 = (self.k1 +% (self.k0 & 0xff)) *% 134775813 +% 1;
        self.k2 = crcByte(self.k2, @truncate(self.k1 >> 24));
    }

    fn streamByte(self: *const ZipCryptoKeys) u8 {
        const t: u16 = @truncate(self.k2 | 2);
        return @truncate((@as(u32, t) *% (t ^ 1)) >> 8);
    }

    fn decrypt(self: *ZipCryptoKeys, c: u8) u8 {
        const p = c ^ self.streamByte();
        self.update(p);
        return p;
    }
};

/// Decrypts a ZipCrypto entry's stored bytes. `check` is the byte the
/// header's last byte must equal: the CRC-32's high byte, or with a data
/// descriptor (flag bit 3) the DOS time's high byte.
pub const ZipCryptoReader = struct {
    source: *std.Io.Reader,
    remaining: u64,
    keys: ZipCryptoKeys,
    interface: std.Io.Reader,

    pub const header_len = 12;

    pub fn init(self: *ZipCryptoReader, source: *std.Io.Reader, stored_size: u64, password: []const u8, check: u8, buffer: []u8) !void {
        if (stored_size < header_len) return Error.ZipBadCentralDirectory;
        var keys: ZipCryptoKeys = .{};
        for (password) |b| keys.update(b);
        var hdr: [header_len]u8 = undefined;
        source.readSliceAll(&hdr) catch return Error.ZipBadCentralDirectory;
        var last: u8 = 0;
        for (hdr) |c| last = keys.decrypt(c);
        if (last != check) return Error.ZipBadPassword;
        self.* = .{
            .source = source,
            .remaining = stored_size - header_len,
            .keys = keys,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *ZipCryptoReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.remaining == 0) return error.EndOfStream;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const want: usize = @intCast(@min(dest.len, self.remaining));
        const n = self.source.readSliceShort(dest[0..want]) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;
        for (dest[0..n]) |*b| b.* = self.keys.decrypt(b.*);
        self.remaining -= n;
        w.advance(n);
        return n;
    }
};

test "AES-CTR: WinZip counter is little-endian and starts at 1" {
    var c: Ctr = .init(.aes128, &(@as([16]u8, @splat(0))));
    var buf: [32]u8 = @splat(0);
    c.xor(&buf);
    var block: [16]u8 = undefined;
    std.mem.writeInt(u128, &block, 2, .little);
    var ks: [16]u8 = undefined;
    const e = aes.Aes128.initEnc(@splat(0));
    e.encrypt(&ks, &block);
    try std.testing.expectEqualSlices(u8, &ks, buf[16..32]);
}

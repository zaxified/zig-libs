// SPDX-License-Identifier: MIT

//! aesccm — AES-CCM authenticated encryption (NIST SP 800-38C, RFC 3610) with
//! a comptime nonce length of 7..13 bytes and tag length of 4..16 (even).
//!
//! Why a module of its own: Zig's `std.crypto.aead.aes_ccm` exports only
//! 13-byte-nonce presets and keeps its generic `AesCcm` private, while the
//! TLS 1.3 / DTLS 1.3 CCM suites (RFC 8446 §B.4, RFC 6655 for TLS 1.2) use a
//! 12-byte nonce, and COSE / OSCORE use 13 bytes. One CCM core serves both.
//!
//! API: `Ccm(Aes, tag_len, nonce_len)` — `init(key)` expands the key once for
//! many records (`seal` / `open`, `deinit` wipes the schedule), and the
//! stateless `encrypt` / `decrypt` do the same for one message. Presets:
//! `Aes128Ccm`, `Aes128Ccm8`, `Aes256Ccm`, `Aes256Ccm8` (12-byte nonce, the
//! TLS profile) and `Aes128Ccm8Nonce13` (COSE algorithm 10, OSCORE's AEAD).
//! AES-192 (OpenSSL and Python `cryptography` accept 24-byte keys) is
//! `Aes192Ccm` / `Aes192Ccm8`, or `Ccm(aes192.Aes192, ...)`, over the sibling
//! `aes192` module's block cipher (std ships none).
//!
//! Errors, not asserts, at the boundary: a ciphertext buffer of the wrong
//! length is `error.BufferSizeMismatch`, a message longer than the L-byte
//! length field allows is `error.MessageTooLong`, a wrong tag
//! `error.AuthenticationFailed` (after which the plaintext buffer is zeroed).
//! The tag check is `std.crypto.timing_safe.eql`.

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const aes192 = @import("aes192");

pub const meta = .{
    .doc = "AES-CCM AEAD (NIST SP 800-38C / RFC 3610) with any nonce length 7..13 and tag 4..16 — the 12-byte-nonce TLS/DTLS 1.3 CCM and CCM_8 profile std lacks, plus COSE/OSCORE's 13-byte one",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "NIST SP 800-38C / RFC 3610 AES-CCM (OpenSSL / Python cryptography AESCCM)",
    .deps = .{"aes192"}, // the AES-192 block cipher for Aes192Ccm (std ships none)
};

pub const Error = error{ BufferSizeMismatch, MessageTooLong };
pub const OpenError = Error || crypto.errors.AuthenticationError;

/// The TLS 1.3 / DTLS 1.3 profiles (RFC 8446 §B.4: `TLS_AES_128_CCM_SHA256`,
/// `TLS_AES_128_CCM_8_SHA256`) and their AES-256 counterparts (RFC 6655).
pub const Aes128Ccm = Ccm(crypto.core.aes.Aes128, 16, 12);
pub const Aes128Ccm8 = Ccm(crypto.core.aes.Aes128, 8, 12);
pub const Aes256Ccm = Ccm(crypto.core.aes.Aes256, 16, 12);
pub const Aes256Ccm8 = Ccm(crypto.core.aes.Aes256, 8, 12);
/// AES-192 counterparts (24-byte key), over the `aes192` module's block cipher.
pub const Aes192Ccm = Ccm(aes192.Aes192, 16, 12);
pub const Aes192Ccm8 = Ccm(aes192.Aes192, 8, 12);
/// COSE algorithm 10, AES-CCM-16-64-128 (RFC 8152 §10.2): OSCORE's mandatory AEAD.
pub const Aes128Ccm8Nonce13 = Ccm(crypto.core.aes.Aes128, 8, 13);

/// AES-CCM over the block cipher `Aes` (`std.crypto.core.aes.Aes128` /
/// `Aes256` or `aes192.Aes192`), with a `tag_len`-byte tag and a `nonce_len`-byte nonce.
pub fn Ccm(comptime Aes: type, comptime tag_len: usize, comptime nonce_len: usize) type {
    comptime {
        if (tag_len < 4 or tag_len > 16 or tag_len % 2 != 0) @compileError("CCM tag length must be 4, 6, ..., 16");
        if (nonce_len < 7 or nonce_len > 13) @compileError("CCM nonce length must be 7..13");
    }
    // RFC 3610 §2: L, the size of the length field, is 15 - nonce length.
    const L = 15 - nonce_len;
    return struct {
        const Self = @This();
        pub const key_length = Aes.key_bits / 8;
        pub const tag_length = tag_len;
        pub const nonce_length = nonce_len;
        /// The longest message an L-byte length field can describe.
        pub const max_message_len: u64 = if (L >= 8) std.math.maxInt(u64) else (@as(u64, 1) << @as(u6, @intCast(8 * L))) - 1;

        ctx: @TypeOf(Aes.initEnc(@as([Aes.key_bits / 8]u8, undefined))),

        pub fn init(key: [key_length]u8) Self {
            return .{ .ctx = Aes.initEnc(key) };
        }

        /// Wipes the expanded key.
        pub fn deinit(self: *Self) void {
            crypto.secureZero(u8, mem.asBytes(&self.ctx));
        }

        /// Encrypts `m` into `c` (same length) and writes the tag.
        pub fn seal(self: *const Self, c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) Error!void {
            if (c.len != m.len) return error.BufferSizeMismatch;
            if (m.len > max_message_len) return error.MessageTooLong;
            var mac: [16]u8 = undefined;
            self.cbcMac(&mac, m, ad, npub);
            var s0: [16]u8 = undefined;
            self.ctx.encrypt(&s0, &counterBlock(npub, 0));
            for (tag, mac[0..tag_length], s0[0..tag_length]) |*t, x, y| t.* = x ^ y;
            crypto.secureZero(u8, &mac);
            crypto.secureZero(u8, &s0);
            self.ctr(c, m, npub);
        }

        /// Decrypts `c` into `m` (same length) when `tag` verifies; on
        /// `error.AuthenticationFailed` `m` is zeroed.
        pub fn open(self: *const Self, m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8) OpenError!void {
            if (c.len != m.len) return error.BufferSizeMismatch;
            if (c.len > max_message_len) return error.MessageTooLong;
            self.ctr(m, c, npub);
            var mac: [16]u8 = undefined;
            self.cbcMac(&mac, m, ad, npub);
            var s0: [16]u8 = undefined;
            self.ctx.encrypt(&s0, &counterBlock(npub, 0));
            var expected: [tag_length]u8 = undefined;
            for (&expected, mac[0..tag_length], s0[0..tag_length]) |*e, x, y| e.* = x ^ y;
            const ok = crypto.timing_safe.eql([tag_length]u8, expected, tag);
            crypto.secureZero(u8, &mac);
            crypto.secureZero(u8, &s0);
            crypto.secureZero(u8, &expected);
            if (!ok) {
                crypto.secureZero(u8, m);
                return error.AuthenticationFailed;
            }
        }

        /// One-shot `init` + `seal` + `deinit`.
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) Error!void {
            var s = init(key);
            defer s.deinit();
            return s.seal(c, tag, m, ad, npub);
        }

        /// One-shot `init` + `open` + `deinit`.
        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) OpenError!void {
            var s = init(key);
            defer s.deinit();
            return s.open(m, c, tag, ad, npub);
        }

        /// RFC 3610 §2.3 A_i: flags = L - 1, the nonce, then the counter in
        /// the last L bytes.
        fn counterBlock(npub: [nonce_length]u8, i: u64) [16]u8 {
            var a: [16]u8 = @splat(0);
            a[0] = L - 1;
            a[1..][0..nonce_length].* = npub;
            mem.writeInt(@Int(.unsigned, 8 * L), a[1 + nonce_length ..][0..L], @intCast(i), .big);
            return a;
        }

        /// CTR keystream from counter 1 (RFC 3610 §2.3).
        fn ctr(self: *const Self, dst: []u8, src: []const u8, npub: [nonce_length]u8) void {
            var i: usize = 0;
            var counter: u64 = 1;
            var ks: [16]u8 = undefined;
            while (i < src.len) : (counter += 1) {
                self.ctx.encrypt(&ks, &counterBlock(npub, counter));
                const n = @min(16, src.len - i);
                for (dst[i..][0..n], src[i..][0..n], ks[0..n]) |*d, x, k| d.* = x ^ k;
                i += n;
            }
            crypto.secureZero(u8, &ks);
        }

        /// RFC 3610 §2.2 CBC-MAC over B_0, the length-prefixed and
        /// zero-padded additional data, and the zero-padded message.
        fn cbcMac(self: *const Self, out: *[16]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) void {
            var x: [16]u8 = @splat(0);
            x[0] = (@as(u8, @intFromBool(ad.len > 0)) << 6) | (@as(u8, (tag_length - 2) / 2) << 3) | @as(u8, L - 1);
            x[1..][0..nonce_length].* = npub;
            mem.writeInt(@Int(.unsigned, 8 * L), x[1 + nonce_length ..][0..L], @intCast(m.len), .big);
            self.ctx.encrypt(&x, &x);
            if (ad.len > 0) {
                // §2.2: 2 bytes below 2^16 - 2^8, 0xfffe + 4 bytes below
                // 2^32, 0xffff + 8 bytes beyond.
                var hdr: [10]u8 = undefined;
                const hl: usize = if (ad.len < 0xff00) blk: {
                    mem.writeInt(u16, hdr[0..2], @intCast(ad.len), .big);
                    break :blk 2;
                } else if (ad.len <= 0xffff_ffff) blk: {
                    hdr[0..2].* = .{ 0xff, 0xfe };
                    mem.writeInt(u32, hdr[2..6], @intCast(ad.len), .big);
                    break :blk 6;
                } else blk: {
                    hdr[0..2].* = .{ 0xff, 0xff };
                    mem.writeInt(u64, hdr[2..10], ad.len, .big);
                    break :blk 10;
                };
                var fill: usize = 0;
                fill = self.absorb(&x, fill, hdr[0..hl]);
                fill = self.absorb(&x, fill, ad);
                if (fill != 0) self.ctx.encrypt(&x, &x);
            }
            if (self.absorb(&x, 0, m) != 0) self.ctx.encrypt(&x, &x);
            out.* = x;
            crypto.secureZero(u8, &x);
        }

        /// XORs `data` into the running CBC-MAC block from offset `fill`,
        /// enciphering every full block; returns the new offset.
        fn absorb(self: *const Self, x: *[16]u8, fill_in: usize, data: []const u8) usize {
            var fill = fill_in;
            for (data) |byte| {
                x[fill] ^= byte;
                fill += 1;
                if (fill == 16) {
                    self.ctx.encrypt(x, x);
                    fill = 0;
                }
            }
            return fill;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

test {
    _ = @import("fuzz_test.zig");
    _ = @import("mutation_test.zig");
    _ = @import("stackprobe_test.zig");
}

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "NIST SP 800-38C Appendix C Example 3: 12-byte nonce, 8-byte tag" {
    const key = hex("404142434445464748494a4b4c4d4e4f");
    const nonce = hex("101112131415161718191a1b");
    const ad = hex("000102030405060708090a0b0c0d0e0f10111213");
    const pt = hex("202122232425262728292a2b2c2d2e2f3031323334353637");
    const want = hex("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951");
    var c: [pt.len]u8 = undefined;
    var tag: [8]u8 = undefined;
    try Aes128Ccm8.encrypt(&c, &tag, &pt, &ad, nonce, key);
    try testing.expectEqualSlices(u8, want[0..pt.len], &c);
    try testing.expectEqualSlices(u8, want[pt.len..], &tag);
    var back: [pt.len]u8 = undefined;
    try Aes128Ccm8.decrypt(&back, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &pt, &back);
}

test "RFC 3610 Packet Vector #1: 13-byte nonce, 8-byte tag" {
    const key = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    const nonce = hex("00000003020100a0a1a2a3a4a5");
    const ad = hex("0001020304050607");
    const pt = hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    const want = hex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0");
    var c: [pt.len]u8 = undefined;
    var tag: [8]u8 = undefined;
    try Aes128Ccm8Nonce13.encrypt(&c, &tag, &pt, &ad, nonce, key);
    try testing.expectEqualSlices(u8, want[0..pt.len], &c);
    try testing.expectEqualSlices(u8, want[pt.len..], &tag);
}

/// SHA-256 counter expansion of `label`, the same as `tools/ccm_kats.py`.
fn expand(label: []const u8, out: []u8) void {
    var i: usize = 0;
    var ctr: usize = 0;
    while (i < out.len) : (ctr += 1) {
        var name: [32]u8 = undefined;
        const s = std.fmt.bufPrint(&name, "{s}-{d}", .{ label, ctr }) catch unreachable;
        var d: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(s, &d, .{});
        const n = @min(32, out.len - i);
        @memcpy(out[i..][0..n], d[0..n]);
        i += n;
    }
}

const Kat = struct { key_len: usize, tag_len: usize, nonce_len: usize, ad_len: usize, pt_len: usize, out: []const u8 };
/// From Python `cryptography`'s `AESCCM` (OpenSSL), `tools/ccm_kats.py`:
/// AES-128/256, tags 8/16, nonces 12/13, empty and multi-block messages,
/// additional data of 0, 5, 13, 20, 300 and 70000 bytes (the 0xfffe
/// 4-byte length encoding).
const kats = [_]Kat{
    .{ .key_len = 16, .tag_len = 8, .nonce_len = 12, .ad_len = 0, .pt_len = 0, .out = "464a110f706514b4" },
    .{ .key_len = 16, .tag_len = 8, .nonce_len = 12, .ad_len = 13, .pt_len = 16, .out = "21ff5372fc6f9ac1e16d7b8dd041340c940211d5151d6852" },
    .{ .key_len = 16, .tag_len = 16, .nonce_len = 12, .ad_len = 20, .pt_len = 33, .out = "21ff5372fc6f9ac1e16d7b8dd041340cd2d7c3ae3aec29fff6ede71f18e8f07df696c3e534a1cea7df355b5433d735bd79" },
    .{ .key_len = 32, .tag_len = 16, .nonce_len = 12, .ad_len = 0, .pt_len = 64, .out = "f5a79bfe22dc06ff43a458b0c9cb86243a3ed1b0397478f3efbcf0ca4d6eefd05ba0103d81df7d57d787670d364e9d72c353db5d8591bc40fdd3594a244b6fcecebb4a29197f7d70674f614210c9d8e3" },
    .{ .key_len = 32, .tag_len = 8, .nonce_len = 12, .ad_len = 5, .pt_len = 1, .out = "f5c0ea02106cf33eef" },
    .{ .key_len = 16, .tag_len = 16, .nonce_len = 13, .ad_len = 8, .pt_len = 31, .out = "45f38f6b56d0abd920be844fbf23c1ffc2482b9a073d1ed4a8753f0948c6c91b987328fb2f5527cdbd2c0758b01027" },
    .{ .key_len = 32, .tag_len = 8, .nonce_len = 13, .ad_len = 300, .pt_len = 17, .out = "f02633174a1f8bcbffb3632f467794a54772c49b2fa24fe4cc" },
    .{ .key_len = 16, .tag_len = 8, .nonce_len = 12, .ad_len = 70000, .pt_len = 40, .out = "21ff5372fc6f9ac1e16d7b8dd041340cd2d7c3ae3aec29fff6ede71f18e8f07df6fbe1c71dc848b4cec7e70b624d0edb" },
};

/// AES-192 rows of the same table (`tools/ccm_kats.py`, key length 24).
const kats192 = [_]Kat{
    .{ .key_len = 24, .tag_len = 8, .nonce_len = 12, .ad_len = 0, .pt_len = 0, .out = "37dff99ffdff293d" },
    .{ .key_len = 24, .tag_len = 8, .nonce_len = 12, .ad_len = 13, .pt_len = 33, .out = "3ec6d6d4d9ab0aa2a691a930446fce5b6c21a1ab011d6ffb0f694bcfd419fde7156f9e2989cb1feaf6" },
    .{ .key_len = 24, .tag_len = 16, .nonce_len = 12, .ad_len = 20, .pt_len = 16, .out = "3ec6d6d4d9ab0aa2a691a930446fce5b15e3a813756900c243f986ce3ce8fbd5" },
    .{ .key_len = 24, .tag_len = 16, .nonce_len = 12, .ad_len = 300, .pt_len = 64, .out = "3ec6d6d4d9ab0aa2a691a930446fce5b6c21a1ab011d6ffb0f694bcfd419fde71512fa5285c3914887d37c96012ceb08b2f25d9e4f9a63a6899f33597ad5114b706aab3d2a1bc2a8a6adb99bd22fba58" },
    .{ .key_len = 24, .tag_len = 8, .nonce_len = 13, .ad_len = 8, .pt_len = 31, .out = "b7a2e2bbaccbe13072fba0a0ce892061b770b7fec3644df39c4ff834208a0cba3bc056d71af507" },
    .{ .key_len = 24, .tag_len = 8, .nonce_len = 13, .ad_len = 70000, .pt_len = 17, .out = "b7a2e2bbaccbe13072fba0a0ce892061b755cbf45dfcbfa617" },
    .{ .key_len = 24, .tag_len = 16, .nonce_len = 13, .ad_len = 5, .pt_len = 1, .out = "b7287dda176a912782dc14d922fbfefa6d" },
    .{ .key_len = 24, .tag_len = 16, .nonce_len = 13, .ad_len = 0, .pt_len = 40, .out = "b7a2e2bbaccbe13072fba0a0ce892061b770b7fec3644df39c4ff834208a0c30c90e345cf61bcc21c8d6f3b02139b4dde3e69b32aad86689" },
};

fn runKat(comptime C: type, k: Kat) !void {
    const gpa = testing.allocator;
    var key: [C.key_length]u8 = undefined;
    expand("key", &key);
    var nonce: [C.nonce_length]u8 = undefined;
    expand("nonce", &nonce);
    const ad = try gpa.alloc(u8, k.ad_len);
    defer gpa.free(ad);
    expand("ad", ad);
    const pt = try gpa.alloc(u8, k.pt_len);
    defer gpa.free(pt);
    expand("pt", pt);
    const want = try gpa.alloc(u8, k.out.len / 2);
    defer gpa.free(want);
    _ = try std.fmt.hexToBytes(want, k.out);
    const c = try gpa.alloc(u8, k.pt_len);
    defer gpa.free(c);
    var tag: [C.tag_length]u8 = undefined;
    const s = C.init(key);
    try s.seal(c, &tag, pt, ad, nonce);
    try testing.expectEqualSlices(u8, want[0..k.pt_len], c);
    try testing.expectEqualSlices(u8, want[k.pt_len..], &tag);
    const back = try gpa.alloc(u8, k.pt_len);
    defer gpa.free(back);
    try s.open(back, c, tag, ad, nonce);
    try testing.expectEqualSlices(u8, pt, back);
}

test "KATs against OpenSSL (Python cryptography AESCCM)" {
    inline for (.{ crypto.core.aes.Aes128, crypto.core.aes.Aes256 }) |A| {
        inline for (.{ 8, 16 }) |t| {
            inline for (.{ 12, 13 }) |n| {
                const C = Ccm(A, t, n);
                for (kats) |k| {
                    if (k.key_len == C.key_length and k.tag_len == t and k.nonce_len == n) try runKat(C, k);
                }
            }
        }
    }
}

test "AES-192 KATs against OpenSSL (Python cryptography AESCCM)" {
    inline for (.{ 8, 16 }) |t| {
        inline for (.{ 12, 13 }) |n| {
            const C = Ccm(aes192.Aes192, t, n);
            var ran: usize = 0;
            for (kats192) |k| {
                if (k.tag_len == t and k.nonce_len == n) {
                    try runKat(C, k);
                    ran += 1;
                }
            }
            try testing.expect(ran > 0);
        }
    }
    try testing.expectEqual(@as(usize, 24), Aes192Ccm.key_length);
}

test "AES-192 CCM: every single-bit flip of ciphertext and tag is refused" {
    const key: [24]u8 = @splat(7);
    const nonce: [12]u8 = @splat(8);
    const pt = "twenty-four byte key data";
    var c: [pt.len]u8 = undefined;
    var tag: [8]u8 = undefined;
    try Aes192Ccm8.encrypt(&c, &tag, pt, "aad", nonce, key);
    var m: [pt.len]u8 = undefined;
    try Aes192Ccm8.decrypt(&m, &c, tag, "aad", nonce, key);
    try testing.expectEqualStrings(pt, &m);
    for (0..c.len * 8) |bit| {
        var bad = c;
        bad[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        try testing.expectError(error.AuthenticationFailed, Aes192Ccm8.decrypt(&m, &bad, tag, "aad", nonce, key));
        try testing.expect(std.mem.allEqual(u8, &m, 0));
    }
    for (0..tag.len * 8) |bit| {
        var bad = tag;
        bad[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        try testing.expectError(error.AuthenticationFailed, Aes192Ccm8.decrypt(&m, &c, bad, "aad", nonce, key));
    }
}

test "agrees with std's 13-byte presets" {
    const key = hex("000102030405060708090a0b0c0d0e0f");
    const nonce: [13]u8 = @splat(0x5a);
    var pt: [77]u8 = undefined;
    for (&pt, 0..) |*b, i| b.* = @truncate(i * 7);
    var c1: [pt.len]u8 = undefined;
    var c2: [pt.len]u8 = undefined;
    var t1: [16]u8 = undefined;
    var t2: [16]u8 = undefined;
    try Ccm(crypto.core.aes.Aes128, 16, 13).encrypt(&c1, &t1, &pt, "header", nonce, key);
    crypto.aead.aes_ccm.Aes128Ccm16.encrypt(&c2, &t2, &pt, "header", nonce, key);
    try testing.expectEqualSlices(u8, &c2, &c1);
    try testing.expectEqualSlices(u8, &t2, &t1);
}

test "a flipped bit anywhere fails, and the plaintext buffer is zeroed" {
    const key: [16]u8 = @splat(9);
    const nonce: [12]u8 = @splat(3);
    const pt = "constrained-device payload";
    var c: [pt.len]u8 = undefined;
    var tag: [8]u8 = undefined;
    try Aes128Ccm8.encrypt(&c, &tag, pt, "aad", nonce, key);
    var m: [pt.len]u8 = undefined;
    for (0..c.len * 8) |bit| {
        var bad = c;
        bad[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        try testing.expectError(error.AuthenticationFailed, Aes128Ccm8.decrypt(&m, &bad, tag, "aad", nonce, key));
        try testing.expect(std.mem.allEqual(u8, &m, 0));
    }
    for (0..tag.len * 8) |bit| {
        var bad = tag;
        bad[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        try testing.expectError(error.AuthenticationFailed, Aes128Ccm8.decrypt(&m, &c, bad, "aad", nonce, key));
    }
    try testing.expectError(error.AuthenticationFailed, Aes128Ccm8.decrypt(&m, &c, tag, "aaD", nonce, key));
    try testing.expectError(error.AuthenticationFailed, Aes128Ccm8.decrypt(&m, &c, tag, "", nonce, key));
    var other = nonce;
    other[11] ^= 1;
    try testing.expectError(error.AuthenticationFailed, Aes128Ccm8.decrypt(&m, &c, tag, "aad", other, key));
}

test "boundary errors instead of asserts" {
    const key: [16]u8 = @splat(1);
    const nonce: [13]u8 = @splat(2);
    var tag: [8]u8 = undefined;
    var c: [4]u8 = undefined;
    try testing.expectError(error.BufferSizeMismatch, Aes128Ccm8Nonce13.encrypt(c[0..3], &tag, "abcd", "", nonce, key));
    try testing.expectError(error.BufferSizeMismatch, Aes128Ccm8Nonce13.decrypt(c[0..3], "abcd", tag, "", nonce, key));
    // A 13-byte nonce leaves a 2-byte length field: 65535 bytes at most.
    try testing.expectEqual(@as(u64, 65535), Aes128Ccm8Nonce13.max_message_len);
    try testing.expectEqual(@as(u64, (1 << 24) - 1), Aes128Ccm8.max_message_len);
    const big = try testing.allocator.alloc(u8, 65536);
    defer testing.allocator.free(big);
    @memset(big, 0);
    try testing.expectError(error.MessageTooLong, Aes128Ccm8Nonce13.encrypt(big, &tag, big, "", nonce, key));
    try testing.expectError(error.MessageTooLong, Aes128Ccm8Nonce13.decrypt(big, big, tag, "", nonce, key));
    try Aes128Ccm8Nonce13.encrypt(big[0..65535], &tag, big[0..65535], "", nonce, key);
}

test "AD length encodings switch at 0xff00 (2 bytes) and use 0xfffe + 4 bytes above" {
    const key: [16]u8 = @splat(4);
    const nonce: [12]u8 = @splat(5);
    const ad = try testing.allocator.alloc(u8, 0xff00);
    defer testing.allocator.free(ad);
    @memset(ad, 0xa5);
    var c: [3]u8 = undefined;
    var t1: [16]u8 = undefined;
    var t2: [16]u8 = undefined;
    try Aes128Ccm.encrypt(&c, &t1, "xyz", ad[0 .. 0xff00 - 1], nonce, key);
    try Aes128Ccm.encrypt(&c, &t2, "xyz", ad, nonce, key);
    // OpenSSL (Python cryptography AESCCM) over the same inputs.
    const w1 = hex("00b852917bae60b4aa0acb076334e0b25faac2");
    const w2 = hex("00b8520802fdd0e35205f92db434faa63d671a");
    try testing.expectEqualSlices(u8, w1[0..3], &c);
    try testing.expectEqualSlices(u8, w1[3..], &t1);
    try testing.expectEqualSlices(u8, w2[3..], &t2);
    var m: [3]u8 = undefined;
    try Aes128Ccm.decrypt(&m, &c, t2, ad, nonce, key);
    try testing.expectEqualStrings("xyz", &m);
}

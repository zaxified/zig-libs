// SPDX-License-Identifier: MIT

//! BLAKE2b-512 (RFC 7693) with a row-vectorized compression function: the
//! sixteen state words are four `@Vector(4, u64)` rows, the column and
//! diagonal G steps run on all four lanes at once, and the diagonalization is a
//! lane rotation. On x86_64 with AVX2 this is 4-wide 64-bit SIMD; the 32/24/16
//! bit rotations are byte/word shuffles (`vpshufd`/`vpshufb`), 63 is add+shift.
//! The layout is the one every SIMD BLAKE2 uses (Neves' reference SSE/AVX2 code
//! is the published description of it); this file is written from RFC 7693.
//!
//! Why it exists: minisign hashes whole files with BLAKE2b-512 before signing
//! (the prehashed `ED` algorithm), and `std.crypto.hash.blake2.Blake2b512` is
//! scalar — 782 MB/s against libsodium's AVX2 code in the reference CLI, which
//! made `signFileDigest`/`verifyFileDigest` 1.3× the CLI (bench-minisign).
//!
//! Only what minisign needs: unkeyed, 64-byte output, incremental `update`.
//! Without AVX2 (or off x86_64) `Blake2b512` is std's. The output is pinned to
//! std's for every length 0..1025 and to RFC 7693's "abc" vector.

const std = @import("std");
const builtin = @import("builtin");

const has_avx2 = builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

/// BLAKE2b-512, unkeyed: `init`, `update`*, `final`. Same contract as std's.
pub const Blake2b512 = if (has_avx2) Vectorized else Std;

const Std = struct {
    inner: std.crypto.hash.blake2.Blake2b512,

    pub const digest_length = 64;

    pub fn init() Std {
        return .{ .inner = .init(.{}) };
    }
    pub fn update(self: *Std, data: []const u8) void {
        self.inner.update(data);
    }
    pub fn final(self: *Std, out: *[64]u8) void {
        self.inner.final(out);
    }
};

const V = @Vector(4, u64);

const iv = [8]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

const sigma = [12][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
};

/// Rotate every lane right by 32: swap the two u32 halves (`vpshufd`).
inline fn rotr32(x: V) V {
    const w: @Vector(8, u32) = @bitCast(x);
    return @bitCast(@shuffle(u32, w, undefined, [8]i32{ 1, 0, 3, 2, 5, 4, 7, 6 }));
}

/// Rotate every lane right by a whole number of bytes (`vpshufb`).
inline fn rotrBytes(x: V, comptime n: comptime_int) V {
    const b: @Vector(32, u8) = @bitCast(x);
    return @bitCast(@shuffle(u8, b, undefined, byteRotMask(n)));
}

fn byteRotMask(comptime n: comptime_int) [32]i32 {
    var mask: [32]i32 = undefined;
    for (0..32) |i| mask[i] = @intCast((i / 8) * 8 + (i % 8 + n) % 8);
    return mask;
}

inline fn rotr63(x: V) V {
    return (x +% x) | (x >> @splat(63));
}

inline fn g(a: *V, b: *V, c: *V, d: *V, mx: V, my: V) void {
    a.* = a.* +% b.* +% mx;
    d.* = rotr32(d.* ^ a.*);
    c.* = c.* +% d.*;
    b.* = rotrBytes(b.* ^ c.*, 3);
    a.* = a.* +% b.* +% my;
    d.* = rotrBytes(d.* ^ a.*, 2);
    c.* = c.* +% d.*;
    b.* = rotr63(b.* ^ c.*);
}

const Vectorized = struct {
    h: [2]V,
    /// Bytes compressed so far (the RFC's `t`), below 2^64 for any input this
    /// process can hold; the high word of `t` stays zero.
    t: u64 = 0,
    buf: [128]u8 = undefined,
    buf_len: usize = 0,

    pub const digest_length = 64;

    pub fn init() Vectorized {
        // Parameter block: digest length 64, no key, fanout 1, depth 1.
        var h0 = iv;
        h0[0] ^= 0x01010000 ^ 64;
        return .{ .h = .{ h0[0..4].*, h0[4..8].* } };
    }

    pub fn update(self: *Vectorized, data: []const u8) void {
        var in = data;
        // The last block must be compressed with the final flag, so a full
        // buffer is only compressed once more input follows it.
        if (self.buf_len != 0) {
            const take = @min(128 - self.buf_len, in.len);
            @memcpy(self.buf[self.buf_len..][0..take], in[0..take]);
            self.buf_len += take;
            in = in[take..];
            if (in.len == 0) return;
            self.t += 128;
            self.compress(&self.buf, false);
            self.buf_len = 0;
        }
        while (in.len > 128) {
            self.t += 128;
            self.compress(in[0..128], false);
            in = in[128..];
        }
        @memcpy(self.buf[0..in.len], in);
        self.buf_len = in.len;
    }

    pub fn final(self: *Vectorized, out: *[64]u8) void {
        @memset(self.buf[self.buf_len..], 0);
        self.t += self.buf_len;
        self.compress(&self.buf, true);
        const words: [8]u64 = @bitCast(self.h);
        for (words, 0..) |w, i| std.mem.writeInt(u64, out[i * 8 ..][0..8], w, .little);
    }

    fn compress(self: *Vectorized, block: *const [128]u8, last: bool) void {
        // Twelve fully unrolled rounds of inlined G steps.
        @setEvalBranchQuota(20000);
        var m: [16]u64 = undefined;
        for (&m, 0..) |*w, i| w.* = std.mem.readInt(u64, block[i * 8 ..][0..8], .little);
        var a = self.h[0];
        var b = self.h[1];
        var c: V = iv[0..4].*;
        var d: V = iv[4..8].*;
        d ^= V{ self.t, 0, if (last) ~@as(u64, 0) else 0, 0 };
        inline for (sigma) |s| {
            g(&a, &b, &c, &d, .{ m[s[0]], m[s[2]], m[s[4]], m[s[6]] }, .{ m[s[1]], m[s[3]], m[s[5]], m[s[7]] });
            // Diagonalize: row i rotates left by i lanes.
            b = @shuffle(u64, b, undefined, [4]i32{ 1, 2, 3, 0 });
            c = @shuffle(u64, c, undefined, [4]i32{ 2, 3, 0, 1 });
            d = @shuffle(u64, d, undefined, [4]i32{ 3, 0, 1, 2 });
            g(&a, &b, &c, &d, .{ m[s[8]], m[s[10]], m[s[12]], m[s[14]] }, .{ m[s[9]], m[s[11]], m[s[13]], m[s[15]] });
            b = @shuffle(u64, b, undefined, [4]i32{ 3, 0, 1, 2 });
            c = @shuffle(u64, c, undefined, [4]i32{ 2, 3, 0, 1 });
            d = @shuffle(u64, d, undefined, [4]i32{ 1, 2, 3, 0 });
        }
        self.h[0] ^= a ^ c;
        self.h[1] ^= b ^ d;
    }
};

const testing = std.testing;

test "BLAKE2b-512: RFC 7693 Appendix A (\"abc\")" {
    var h = Vectorized.init();
    h.update("abc");
    var out: [64]u8 = undefined;
    h.final(&out);
    var want: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    try testing.expectEqualSlices(u8, &want, &out);
}

test "BLAKE2b-512: equal to std for every length 0..1025 and every split" {
    var data: [1025]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 2654435761 >> 7);
    for (0..data.len + 1) |len| {
        var want: [64]u8 = undefined;
        std.crypto.hash.blake2.Blake2b512.hash(data[0..len], &want, .{});
        var one = Vectorized.init();
        one.update(data[0..len]);
        var got: [64]u8 = undefined;
        one.final(&got);
        try testing.expectEqualSlices(u8, &want, &got);
        // Two-part splits around the block boundaries the buffer logic cares about.
        for ([_]usize{ 0, 1, 127, 128, 129, 255, 256, 257 }) |cut| {
            if (cut > len) continue;
            var two = Vectorized.init();
            two.update(data[0..cut]);
            two.update(data[cut..len]);
            two.final(&got);
            try testing.expectEqualSlices(u8, &want, &got);
        }
    }
}

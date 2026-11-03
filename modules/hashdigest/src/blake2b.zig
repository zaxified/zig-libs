// SPDX-License-Identifier: MIT

//! BLAKE2b-256 (RFC 7693), unkeyed, with a row-vectorised compression
//! function: the four rows of the 4x4 state are `@Vector(4, u64)` and a
//! round is two column steps with the rows rotated between them (the shape
//! of the reference `blake2b-round` SIMD implementations, written here
//! from RFC 7693 section 3.2). `std.crypto.hash.blake2.Blake2b256` is the
//! scalar form of the same function; `blake2b_test` below compares the two
//! byte for byte on random inputs and lengths. The streaming layout follows
//! std's (the last block is held back until `final`) so the public
//! declarations match.

const std = @import("std");

pub const Blake2b256 = struct {
    pub const block_length = 128;
    pub const digest_length = 32;
    pub const Options = struct {};

    const Row = @Vector(4, u64);

    const iv = [8]u64{
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    };

    const sigma = [10][16]u8{
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
    };

    h: [8]u64,
    t: u128,
    buf: [128]u8,
    buf_len: u8,

    pub fn init(options: Options) Blake2b256 {
        _ = options;
        var d: Blake2b256 = undefined;
        d.h = iv;
        d.h[0] ^= 0x01010000 ^ digest_length; // fanout 1, depth 1, no key
        d.t = 0;
        d.buf_len = 0;
        return d;
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Blake2b256, b: []const u8) void {
        var off: usize = 0;
        if (d.buf_len != 0 and d.buf_len + b.len > 128) {
            off = 128 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);
            d.t += 128;
            d.compress(&d.buf, false);
            d.buf_len = 0;
        }
        while (off + 128 < b.len) : (off += 128) {
            d.t += 128;
            d.compress(b[off..][0..128], false);
        }
        const rest = b[off..];
        @memcpy(d.buf[d.buf_len..][0..rest.len], rest);
        d.buf_len += @intCast(rest.len);
    }

    pub fn final(d: *Blake2b256, out: *[digest_length]u8) void {
        @memset(d.buf[d.buf_len..], 0);
        d.t += d.buf_len;
        d.compress(&d.buf, true);
        for (&d.h) |*x| x.* = std.mem.nativeToLittle(u64, x.*);
        out.* = @as(*[digest_length]u8, @ptrCast(&d.h)).*;
    }

    pub fn finalResult(d: *Blake2b256) [digest_length]u8 {
        var r: [digest_length]u8 = undefined;
        d.final(&r);
        return r;
    }

    inline fn rotr(x: Row, comptime n: u6) Row {
        return (x >> @splat(n)) | (x << @splat(@as(u6, 0) -% n));
    }

    /// One G step on all four columns (or diagonals) at once.
    inline fn g(a: *Row, b: *Row, c: *Row, d: *Row, mx: Row, my: Row) void {
        a.* = a.* +% b.* +% mx;
        d.* = rotr(d.* ^ a.*, 32);
        c.* = c.* +% d.*;
        b.* = rotr(b.* ^ c.*, 24);
        a.* = a.* +% b.* +% my;
        d.* = rotr(d.* ^ a.*, 16);
        c.* = c.* +% d.*;
        b.* = rotr(b.* ^ c.*, 63);
    }

    fn compress(s: *Blake2b256, block: *const [128]u8, last: bool) void {
        var m: [16]u64 = undefined;
        for (&m, 0..) |*w, i| w.* = std.mem.readInt(u64, block[8 * i ..][0..8], .little);

        var a: Row = s.h[0..4].*;
        var b: Row = s.h[4..8].*;
        var c: Row = iv[0..4].*;
        var d: Row = iv[4..8].*;
        d ^= Row{ @as(u64, @truncate(s.t)), @as(u64, @truncate(s.t >> 64)), if (last) ~@as(u64, 0) else 0, 0 };

        inline for (0..12) |r| {
            const sg = sigma[r % 10];
            const mx0 = Row{ m[sg[0]], m[sg[2]], m[sg[4]], m[sg[6]] };
            const my0 = Row{ m[sg[1]], m[sg[3]], m[sg[5]], m[sg[7]] };
            const mx1 = Row{ m[sg[8]], m[sg[10]], m[sg[12]], m[sg[14]] };
            const my1 = Row{ m[sg[9]], m[sg[11]], m[sg[13]], m[sg[15]] };
            g(&a, &b, &c, &d, mx0, my0);
            // diagonalise: row b left by 1, c by 2, d by 3
            b = @shuffle(u64, b, undefined, @Vector(4, i32){ 1, 2, 3, 0 });
            c = @shuffle(u64, c, undefined, @Vector(4, i32){ 2, 3, 0, 1 });
            d = @shuffle(u64, d, undefined, @Vector(4, i32){ 3, 0, 1, 2 });
            g(&a, &b, &c, &d, mx1, my1);
            b = @shuffle(u64, b, undefined, @Vector(4, i32){ 3, 0, 1, 2 });
            c = @shuffle(u64, c, undefined, @Vector(4, i32){ 2, 3, 0, 1 });
            d = @shuffle(u64, d, undefined, @Vector(4, i32){ 1, 2, 3, 0 });
        }

        const lo: Row = s.h[0..4].*;
        const hi: Row = s.h[4..8].*;
        s.h[0..4].* = lo ^ a ^ c;
        s.h[4..8].* = hi ^ b ^ d;
    }
};

test "blake2b256 known answers" {
    var out: [32]u8 = undefined;
    Blake2b256.hash("", &out, .{});
    var hx = std.fmt.bytesToHex(out, .lower);
    try std.testing.expectEqualStrings("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", &hx);
    Blake2b256.hash("abc", &out, .{});
    hx = std.fmt.bytesToHex(out, .lower);
    try std.testing.expectEqualStrings("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", &hx);
}

test "blake2b256 equals std on every length 0..600 and random chunking" {
    var prng = std.Random.DefaultPrng.init(0xb1a4e2b);
    const rnd = prng.random();
    var data: [700]u8 = undefined;
    rnd.bytes(&data);
    for (0..601) |len| {
        var want: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2b256.hash(data[0..len], &want, .{});
        var got: [32]u8 = undefined;
        Blake2b256.hash(data[0..len], &got, .{});
        try std.testing.expectEqualSlices(u8, &want, &got);

        // random chunking through update
        var h = Blake2b256.init(.{});
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, @min(300, len - pos));
            h.update(data[pos..][0..n]);
            pos += n;
        }
        h.final(&got);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

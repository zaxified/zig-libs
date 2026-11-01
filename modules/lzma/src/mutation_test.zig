// SPDX-License-Identifier: MIT

//! Tests that pin what the 2026-10-31 mutation audit of the encoder side found
//! unpinned (mutant schemata over encoder.zig, lzma_enc.zig, lz_enc.zig,
//! rangeenc.zig, xzfmt.zig and common.zig; the existing suite and its
//! byte-exact goldens killed the rest). Every test below was written to kill
//! a named survivor and fails without the check it pins.

const std = @import("std");
const testing = std.testing;
const lzma = @import("root.zig");
const c = @import("common.zig");
const le = @import("lzma_enc.zig");
const lz = @import("lz_enc.zig");
const rcmod = @import("rangeenc.zig");
const xzfmt = @import("xzfmt.zig");

const gpa = testing.allocator;

fn sha256Hex(bytes: []const u8) [64]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &h, .{});
    return std.fmt.bytesToHex(h, .lower);
}

// ── inputs shared with the xz 5.8.3 command line (the digests below were made with it) ──

/// A linear congruential stream; `text` maps it onto 16 letters ('a'..'p').
fn lcg(buf: []u8, seed: u32, text: bool) void {
    var x = seed;
    for (buf) |*b| {
        x = x *% 1664525 +% 1013904223;
        const top: u8 = @truncate(x >> 24);
        b.* = if (text) 0x61 + (top & 15) else top;
    }
}

fn mixedInput(a: std.mem.Allocator) ![]u8 {
    const d = try a.alloc(u8, 270_000);
    lcg(d[0..100_000], 1, true);
    lcg(d[100_000..170_000], 7, false);
    lcg(d[170_000..], 3, true);
    return d;
}

// ── encoder.zig: presets ──

test "preset: the whole xz preset table, plain and extreme" {
    const Row = struct { dict_pow2: u5, fast: bool, mf: lzma.MatchFinder, nice: u32, depth: u32 };
    const rows = [10]Row{
        .{ .dict_pow2 = 18, .fast = true, .mf = .hc3, .nice = 128, .depth = 4 },
        .{ .dict_pow2 = 20, .fast = true, .mf = .hc4, .nice = 128, .depth = 8 },
        .{ .dict_pow2 = 21, .fast = true, .mf = .hc4, .nice = 273, .depth = 24 },
        .{ .dict_pow2 = 22, .fast = true, .mf = .hc4, .nice = 273, .depth = 48 },
        .{ .dict_pow2 = 22, .fast = false, .mf = .bt4, .nice = 16, .depth = 0 },
        .{ .dict_pow2 = 23, .fast = false, .mf = .bt4, .nice = 32, .depth = 0 },
        .{ .dict_pow2 = 23, .fast = false, .mf = .bt4, .nice = 64, .depth = 0 },
        .{ .dict_pow2 = 24, .fast = false, .mf = .bt4, .nice = 64, .depth = 0 },
        .{ .dict_pow2 = 25, .fast = false, .mf = .bt4, .nice = 64, .depth = 0 },
        .{ .dict_pow2 = 26, .fast = false, .mf = .bt4, .nice = 64, .depth = 0 },
    };
    for (rows, 0..) |r, level| {
        const p = lzma.preset(@intCast(level), false);
        try testing.expectEqual(@as(u32, 3), p.lc);
        try testing.expectEqual(@as(u32, 0), p.lp);
        try testing.expectEqual(@as(u32, 2), p.pb);
        try testing.expectEqual(@as(u32, 1) << r.dict_pow2, p.dict_size);
        try testing.expectEqual(if (r.fast) lzma.Mode.fast else lzma.Mode.normal, p.mode);
        try testing.expectEqual(r.mf, p.mf);
        try testing.expectEqual(r.nice, p.nice_len);
        try testing.expectEqual(r.depth, p.depth);
        // -e: the dictionary stays, the parser is always the optimal one on bt4.
        const x = lzma.preset(@intCast(level), true);
        try testing.expectEqual(p.dict_size, x.dict_size);
        try testing.expectEqual(lzma.Mode.normal, x.mode);
        try testing.expectEqual(lzma.MatchFinder.bt4, x.mf);
        const mid = level == 3 or level == 5;
        try testing.expectEqual(@as(u32, if (mid) 192 else 273), x.nice_len);
        try testing.expectEqual(@as(u32, if (mid) 0 else 512), x.depth);
    }
}

// ── encoder.zig / lzma_enc.zig / lz_enc.zig: option validation happens before any allocation ──

/// Encoder.init on an allocator that fails at once: valid options get as far as
/// the first allocation (OutOfMemory), invalid ones are refused before it.
fn initOn(o: lzma.LzmaOptions, f: lzma.EncodeFormat) !void {
    var fa: std.testing.FailingAllocator = .init(gpa, .{ .fail_index = 0 });
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = try lzma.Encoder.init(fa.allocator(), &w, f, .{ .lzma = o });
    e.deinit();
}

test "Encoder.init: every option boundary, refused before the first allocation" {
    const base = lzma.preset(6, false);
    const formats = [_]lzma.EncodeFormat{ .xz, .lzma_alone, .lzma1, .lzma2 };
    for (formats) |f| {
        // valid edges get past the checks and meet the failing allocator
        var o = base;
        o.dict_size = 4096;
        try testing.expectError(error.OutOfMemory, initOn(o, f));
        o = base;
        o.dict_size = lz.dict_size_max;
        try testing.expectError(error.OutOfMemory, initOn(o, f));
        o = base;
        o.lc = 4;
        o.lp = 0;
        try testing.expectError(error.OutOfMemory, initOn(o, f));
        o = base;
        o.lc = 0;
        o.lp = 4;
        try testing.expectError(error.OutOfMemory, initOn(o, f));
        o = base;
        o.lc = 3;
        o.lp = 1;
        try testing.expectError(error.OutOfMemory, initOn(o, f));
        o = base;
        o.pb = 4;
        try testing.expectError(error.OutOfMemory, initOn(o, f));
        o = base;
        o.nice_len = 2;
        try testing.expectError(error.OutOfMemory, initOn(o, f));
        o = base;
        o.nice_len = 273;
        try testing.expectError(error.OutOfMemory, initOn(o, f));
        // one step past every edge
        o = base;
        o.dict_size = 4095;
        try testing.expectError(error.InvalidOptions, initOn(o, f));
        o = base;
        o.dict_size = lz.dict_size_max + 1;
        try testing.expectError(error.InvalidOptions, initOn(o, f));
        o = base;
        o.lc = 4;
        o.lp = 1;
        try testing.expectError(error.InvalidOptions, initOn(o, f));
        o = base;
        o.lc = 5;
        o.lp = 0;
        try testing.expectError(error.InvalidOptions, initOn(o, f));
        o = base;
        o.lc = 0;
        o.lp = 5;
        try testing.expectError(error.InvalidOptions, initOn(o, f));
        o = base;
        o.pb = 5;
        try testing.expectError(error.InvalidOptions, initOn(o, f));
        o = base;
        o.nice_len = 1;
        try testing.expectError(error.InvalidOptions, initOn(o, f));
        o = base;
        o.nice_len = 274;
        try testing.expectError(error.InvalidOptions, initOn(o, f));
    }
}

test "Mf.init: dictionary and nice_len edges (OptionsError before any allocation)" {
    const o: lz.Options = .{ .before_size = 4096, .dict_size = 4096, .after_size = 4097, .match_len_max = 273, .nice_len = 64, .match_finder = .hc4, .depth = 4 };
    var small = o;
    small.dict_size = 4095;
    try testing.expectError(error.OptionsError, lz.Mf.init(gpa, small));
    var mf = try lz.Mf.init(gpa, o); // dict_size_min itself is valid
    mf.deinit(gpa);
    var big = o;
    big.dict_size = lz.dict_size_max;
    var fa: std.testing.FailingAllocator = .init(gpa, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, lz.Mf.init(fa.allocator(), big));
    big.dict_size = lz.dict_size_max + 1;
    try testing.expectError(error.OptionsError, lz.Mf.init(gpa, big));
    var nice = o;
    nice.nice_len = 273; // == match_len_max is valid
    var fa2: std.testing.FailingAllocator = .init(gpa, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, lz.Mf.init(fa2.allocator(), nice));
    nice.nice_len = 274;
    try testing.expectError(error.OptionsError, lz.Mf.init(gpa, nice));
}

test "Coder.init: invalid options and the dictionary cap are OptionsError" {
    const co = try gpa.create(le.Coder);
    defer gpa.destroy(co);
    @memset(std.mem.asBytes(co), 0);
    var o = lzma.preset(6, false);
    o.lc = 4;
    o.lp = 1;
    try testing.expectError(error.OptionsError, co.init(o, false));
    o = lzma.preset(6, false);
    o.dict_size = lz.dict_size_max;
    try co.init(o, false); // the cap itself is valid
    o.dict_size = lz.dict_size_max + 1;
    try testing.expectError(error.OptionsError, co.init(o, false));
}

// ── encoder.zig: a match at exactly dict_size is found, one byte farther is not ──

test "match finders: a repeat at distance dict_size is matched, at dict_size + 1 it is not" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    inline for (.{ .hc3, .hc4, .bt2, .bt3, .bt4 }) |mf| {
        inline for (.{ lzma.Mode.fast, lzma.Mode.normal }) |mode| {
            var o = lzma.preset(6, false);
            o.dict_size = 4096;
            o.mf = mf;
            o.mode = mode;
            for ([_]usize{ 4096, 4097 }) |period| {
                const data = try gpa.alloc(u8, period * 2);
                defer gpa.free(data);
                prng.random().bytes(data[0..period]);
                @memcpy(data[period..], data[0..period]);
                const z = try lzma.compress(gpa, data, .lzma_alone, .{ .lzma = o });
                defer gpa.free(z);
                if (period == 4096) {
                    try testing.expect(z.len < period + period / 8);
                } else {
                    try testing.expect(z.len > period * 2 - 32);
                }
                const back = try lzma.decompress(gpa, z, .lzma_alone, .{});
                defer gpa.free(back);
                try testing.expectEqualSlices(u8, data, back);
            }
        }
    }
}

// ── encoder.zig: the dictionary size in the .lzma header and the LZMA2 properties byte ──

fn propsFor(dict: u32) u8 {
    var b: u8 = 0;
    while (xzfmt.lzma2DictSize(b).? < dict) b += 1;
    return b;
}

test "dictionary size fields: the .lzma header and the xz block header round up to 2^n or 3 * 2^(n-1)" {
    const sizes = [_]u32{ 4096, 4097, 5000, 6144, 6145, 8192, 65535, 65536, 65537, 100_000, 1 << 20, (1 << 20) + 1, 3 << 20, (3 << 20) + 1, 1 << 22 };
    for (sizes) |dict| {
        var o = lzma.preset(0, false);
        o.dict_size = dict;
        const b = propsFor(dict);
        const want = xzfmt.lzma2DictSize(b).?;
        const al = try lzma.compress(gpa, "x", .lzma_alone, .{ .lzma = o });
        defer gpa.free(al);
        try testing.expectEqual(want, std.mem.readInt(u32, al[1..5], .little));
        const xz = try lzma.compress(gpa, "x", .xz, .{ .lzma = o });
        defer gpa.free(xz);
        try testing.expectEqual(b, xz[16]);
        // the header the encoder wrote parses, and says what the decoder will allocate
        const bh = try xzfmt.parseBlockHeader(xz[12..24]);
        try testing.expectEqual(want, bh.dict_size);
    }
}

// ── encoder.zig: sizes in the index (varint boundaries) ──

test "xz index: sizes at the 7-bit varint boundaries decode" {
    var prng = std.Random.DefaultPrng.init(99);
    const zeros_sizes = [_]usize{ 127, 128, 129, 16383, 16384, 16385, (1 << 21) - 1, 1 << 21, (1 << 21) + 1 };
    for (zeros_sizes) |n| {
        const data = try gpa.alloc(u8, n);
        defer gpa.free(data);
        @memset(data, 0);
        var o = lzma.preset(1, false);
        o.dict_size = 1 << 16;
        const z = try lzma.compress(gpa, data, .xz, .{ .lzma = o, .check = .none });
        defer gpa.free(z);
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, data, back);
    }
    // Stored chunks: 3 + n + 1 bytes, so the unpadded size is 12 + n + 4 = 128 and 16384 exactly.
    for ([_]usize{ 112, 16368 }) |n| {
        const data = try gpa.alloc(u8, n);
        defer gpa.free(data);
        prng.random().bytes(data);
        var o = lzma.preset(1, false);
        o.dict_size = 1 << 16;
        const z = try lzma.compress(gpa, data, .xz, .{ .lzma = o, .check = .none });
        defer gpa.free(z);
        try testing.expectEqual(@as(u8, 1), z[24]); // a stored chunk with a dictionary reset
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, data, back);
    }
}

// ── encoder.zig: bytes against the xz command line (xz 5.8.3, `xz -N -c`) ──

const XzCase = struct { data: enum { zeros5m, nib1m, mixed }, level: u4, len: usize, sha: []const u8 };
const xz_cases = [_]XzCase{
    .{ .data = .zeros5m, .level = 1, .len = 892, .sha = "3c34da67686751277df82f8535aaa172578a9acbf2e17190b236b0b0196c8c64" },
    .{ .data = .zeros5m, .level = 6, .len = 892, .sha = "0fefc8e0007b02245460fae78d0be28d4a5478730e2a92f55c0a32c49f590f40" },
    .{ .data = .nib1m, .level = 1, .len = 582864, .sha = "1f17ec5ca8ef280f14b8c74b93d510b9346a059e7f251bbdf06407088e3e6e36" },
    .{ .data = .nib1m, .level = 6, .len = 544432, .sha = "314fafe69e4d0d58217e82253ba39d5d5bc87b8ae3bf7b10d8e510e0998b008b" },
    .{ .data = .mixed, .level = 1, .len = 183060, .sha = "f4b815e8e9138f12da9712a9e613ea9efe0c7914b699960a3a9f1db227ce1bf6" },
    .{ .data = .mixed, .level = 6, .len = 177040, .sha = "5fcfd541cfbaf525026c1664f0c99f504a692da740f6979f0f38e01c460917f5" },
};

test "xz bytes: multi-chunk streams (2 MiB chunks, 64 KiB compressed chunks, stored chunks) equal xz's" {
    var last: ?@TypeOf(xz_cases[0].data) = null;
    var data: []u8 = &.{};
    defer gpa.free(data);
    for (xz_cases) |cs| {
        if (last == null or last.? != cs.data) {
            gpa.free(data);
            data = &.{};
            data = switch (cs.data) {
                .zeros5m => blk: {
                    const d = try gpa.alloc(u8, 5 << 20);
                    @memset(d, 0);
                    break :blk d;
                },
                .nib1m => blk: {
                    const d = try gpa.alloc(u8, 1 << 20);
                    lcg(d, 1, true);
                    break :blk d;
                },
                .mixed => try mixedInput(gpa),
            };
            last = cs.data;
        }
        const z = try lzma.compress(gpa, data, .xz, .{ .lzma = lzma.preset(cs.level, false) });
        defer gpa.free(z);
        try testing.expectEqual(cs.len, z.len);
        const hex = sha256Hex(z);
        try testing.expectEqualStrings(cs.sha, &hex);
        const back = try lzma.decompress(gpa, z, .xz, .{});
        defer gpa.free(back);
        try testing.expect(std.mem.eql(u8, data, back));
    }
}

test "lzma_alone and lzma1 streams longer than 2 MiB are not chunked" {
    const n = 3 << 20;
    const data = try gpa.alloc(u8, n);
    defer gpa.free(data);
    @memset(data, 0);
    var o = lzma.preset(1, false);
    o.dict_size = 4 << 20; // the window must hold more than 2 MiB, or read_pos never gets there
    const al = try lzma.compress(gpa, data, .lzma_alone, .{ .lzma = o });
    defer gpa.free(al);
    const back = try lzma.decompress(gpa, al, .lzma_alone, .{});
    defer gpa.free(back);
    try testing.expectEqual(@as(usize, n), back.len);
    try testing.expect(std.mem.eql(u8, data, back));
    const raw = try lzma.compress(gpa, data, .lzma1, .{ .lzma = o });
    defer gpa.free(raw);
    const fmt: lzma.Format = .{ .lzma1 = .{ .props = .{ .lc = 3, .lp = 0, .pb = 2, .dict_size = 4 << 20 } } };
    const back2 = try lzma.decompress(gpa, raw, fmt, .{});
    defer gpa.free(back2);
    try testing.expectEqual(@as(usize, n), back2.len);
}

// ── byte-exactness against xz 5.8.3: more data shapes, option sets and every tiny string ──

const Kind = enum { nib, rnd, bin, runs, per, mix2 };

fn nx(x: *u32) u32 {
    x.* = x.* *% 1664525 +% 1013904223;
    return x.*;
}

/// The generators `gen()` of the script that made the digests below (same stream, same shapes).
fn genData(a: std.mem.Allocator, kind: Kind, n: usize, seed: u32) ![]u8 {
    const buf = try a.alloc(u8, n + 600);
    defer a.free(buf);
    var len: usize = 0;
    var x = seed;
    switch (kind) {
        .nib => while (len < n) : (len += 1) {
            buf[len] = 0x61 + @as(u8, @truncate((nx(&x) >> 24) & 15));
        },
        .rnd => while (len < n) : (len += 1) {
            buf[len] = @truncate(nx(&x) >> 24);
        },
        .bin => {
            var i: u32 = 0;
            while (len < n) : (i += 1) {
                const r1: u8 = @truncate((nx(&x) >> 24) & 3);
                const r2: u8 = @truncate((nx(&x) >> 24) & 3);
                const r3: u8 = @truncate((nx(&x) >> 24) & 15);
                const rec = [16]u8{ @truncate(i), @truncate(i >> 8), @truncate(i >> 16), @truncate(i >> 24), r1, r2, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, r3, 0 };
                @memcpy(buf[len..][0..16], &rec);
                len += 16;
            }
        },
        .runs => while (len < n) {
            const v: u8 = @truncate((nx(&x) >> 24) & 3);
            const l: usize = 1 + (nx(&x) >> 16) % 300;
            @memset(buf[len..][0..l], 0x30 + v);
            len += l;
        },
        .mix2 => {
            // text, then 200 000 random bytes (whole stored chunks), then more text: several compressed chunks follow a stored one
            lcg(buf[0..30_000], seed, true);
            lcg(buf[30_000..230_000], seed + 1, false);
            lcg(buf[230_000..n], seed + 2, true);
            len = n;
        },
        .per => {
            var blk: usize = 0;
            while (len < n) : (blk += 1) {
                const p = 1 + blk % 4;
                var pat: [4]u8 = undefined;
                for (pat[0..p]) |*b| b.* = 0x61 + @as(u8, @truncate((nx(&x) >> 24) & 7));
                const reps: usize = 20 + (nx(&x) >> 16) % 100;
                for (0..reps) |_| {
                    for (pat[0..p]) |b| {
                        const v = (nx(&x) >> 24) & 31;
                        buf[len] = if (v != 0) b else 0x7A;
                        len += 1;
                    }
                }
            }
        },
    }
    return a.dupe(u8, buf[0..n]);
}

const OracleCase = struct { kind: Kind, n: usize, seed: u32, spec: []const u8, alone: bool = false, len: usize, sha: []const u8 };
const oracle_cases = [_]OracleCase{
    .{ .kind = .nib, .n = 200000, .seed = 11, .spec = "0,dict=4096", .len = 113888, .sha = "6c5b00c940fe9a8f6c8a19b07dbf554680422623942b28664619ae03b3abf534" },
    .{ .kind = .nib, .n = 200000, .seed = 11, .spec = "1,dict=65536", .len = 112452, .sha = "796e413a5825ee2b3a7532e9addca089a5d008d4d44e4388757e80fe4df9a537" },
    .{ .kind = .nib, .n = 200000, .seed = 11, .spec = "4,dict=4096,nice=8", .len = 103848, .sha = "69bea34902b14266e5dff85003ecf5161999af65b37ef7a5baddc44600cc5a65" },
    .{ .kind = .nib, .n = 200000, .seed = 11, .spec = "5,dict=65536,mf=bt3,nice=16", .len = 103868, .sha = "162bf41a0022fa0e0ac0bc33d6c69cfb36add1ca211f6875d4dde1f727f48510" },
    .{ .kind = .nib, .n = 200000, .seed = 11, .spec = "6,mf=bt2,nice=24", .len = 103868, .sha = "da0be7230284b0e086896bb2b1084577f728bccdbdc4c09d0e75c525f2e2e504" },
    .{ .kind = .nib, .n = 200000, .seed = 11, .spec = "6,lc=0,lp=2,pb=1", .len = 103964, .sha = "f27590d08f750f5de312dc6be7e17ddfb79001bb75f36b3d5636524183b0f54b" },
    .{ .kind = .nib, .n = 150000, .seed = 11, .spec = "3e", .len = 77940, .sha = "193b4dd199e2538a6cbf5c430f590093615c634d5534ce08e7c035fa0ea4ce7d" },
    .{ .kind = .nib, .n = 200000, .seed = 11, .spec = "4,nice=2", .len = 110444, .sha = "e1ff0e528d5182959f664492b0936b4e16c0df026a7b000edd6edecbb75d01ad" },
    .{ .kind = .nib, .n = 200000, .seed = 11, .spec = "1,mf=hc3,nice=3", .len = 114812, .sha = "0f7f0dddd6c8b3be85801fb6a394aa61dbb7df20dc01cac78b64f0a7691696b9" },
    .{ .kind = .rnd, .n = 200000, .seed = 12, .spec = "0,dict=4096", .len = 200072, .sha = "663c64cc5769e4aaab60cfbe0b6592681e9e011eb90d9b1fb5a769d940a3a7b6" },
    .{ .kind = .rnd, .n = 200000, .seed = 12, .spec = "6,dict=4096", .len = 200072, .sha = "110f462b73b4fc4ad7976fd3f6d1d3e7b3224a6c815f4ff208040e5790596f5a" },
    .{ .kind = .bin, .n = 200000, .seed = 13, .spec = "1,dict=65536", .len = 32736, .sha = "5c0d806db20128e5e95a66bb97ba92987c792b5ee5ed5d88e7fb07fdb62da2a7" },
    .{ .kind = .bin, .n = 200000, .seed = 13, .spec = "3,dict=65536", .len = 35140, .sha = "9abafd61a6785a187c880213754d959c63a1bdea270ae77eac0927bc74ecefae" },
    .{ .kind = .bin, .n = 200000, .seed = 13, .spec = "6", .len = 23280, .sha = "14311f35261c493f910ed89f5425f1f40ca95bd7f1048cd84df250c435f45450" },
    .{ .kind = .bin, .n = 200000, .seed = 13, .spec = "6,lc=0,lp=2,pb=4", .len = 26708, .sha = "4e69c086cb5312a16b2933bb0dadb7360d140040d19de185b4b2fad9f5cbd802" },
    .{ .kind = .bin, .n = 200000, .seed = 13, .spec = "9e", .len = 23188, .sha = "dc4e64e9e4063b36310fe6a7c9f16df3e0156081cf2525611170eefe2ae95e9f" },
    .{ .kind = .bin, .n = 200000, .seed = 13, .spec = "4,dict=4096,nice=8", .len = 27276, .sha = "7ecc797b4fd84a5a6fc8b756558f6afeb0d86a9f0ac4410921a5bde9d9701bfd" },
    .{ .kind = .runs, .n = 200000, .seed = 14, .spec = "1", .len = 2152, .sha = "30dc2561f1ae428907e4ec744bc7757dc1602cba96d036bd9b1d3cafa431d510" },
    .{ .kind = .runs, .n = 200000, .seed = 14, .spec = "6", .len = 2316, .sha = "2c230470f750eb0d7fdb1d480922f87c6c12ebfc4207869590d705f4df71b88e" },
    .{ .kind = .runs, .n = 200000, .seed = 14, .spec = "4,nice=273", .len = 2284, .sha = "99d9d2d4f6ece8e1684f18fe3bc0e6d74661d2c3074b6f9aa38d990828bff55e" },
    .{ .kind = .runs, .n = 200000, .seed = 14, .spec = "3e", .len = 2400, .sha = "67c56fdd169cdb6ad669fe06376f01d5ea777f46978fa430a8e53fefa77efb9b" },
    .{ .kind = .per, .n = 200000, .seed = 15, .spec = "1,dict=65536", .len = 15512, .sha = "26f6e99cf5909e3273a43cafc3c589a1cab932e68fe8b577fef584fbe9849663" },
    .{ .kind = .per, .n = 200000, .seed = 15, .spec = "6", .len = 12740, .sha = "8d51cb228e75648436dc8a612ba33b435a25d4164cc1c541d7bd1c5789c7a7c2" },
    .{ .kind = .per, .n = 200000, .seed = 15, .spec = "5,mf=bt3,nice=16", .len = 15448, .sha = "d44e5cab34e0e304967e4124330177d404f4f6a0fc54df17091d0d3f2112362f" },
    .{ .kind = .per, .n = 200000, .seed = 15, .spec = "6e", .len = 12160, .sha = "e141ccb9fd9d39ddc0c440190f2089902fa186449ae1a6d38db4e202edf8b9e9" },
    .{ .kind = .rnd, .n = 200000, .seed = 12, .spec = "0,dict=4096", .alone = true, .len = 202840, .sha = "2e9a44fc7a777e015fa2bbbc693658cefd9e33728d97866a9a1457202494e672" },
    .{ .kind = .rnd, .n = 200000, .seed = 12, .spec = "1,dict=4096", .alone = true, .len = 202840, .sha = "2e9a44fc7a777e015fa2bbbc693658cefd9e33728d97866a9a1457202494e672" },
    .{ .kind = .rnd, .n = 200000, .seed = 12, .spec = "6,dict=4096", .alone = true, .len = 202789, .sha = "ce491491ebcbcd700a4207641f3074196f0dc0e567d9cfb9dbdc76472318695d" },
    .{ .kind = .rnd, .n = 200000, .seed = 12, .spec = "4,dict=4096,nice=8,mf=bt3", .alone = true, .len = 202789, .sha = "ce491491ebcbcd700a4207641f3074196f0dc0e567d9cfb9dbdc76472318695d" },
    .{ .kind = .rnd, .n = 200000, .seed = 12, .spec = "5,mf=bt2,dict=4096", .alone = true, .len = 202797, .sha = "7a30f3a9a36be5c5b048889fd57f599935bf94305b78698f91c629d7b94c9192" },
    .{ .kind = .rnd, .n = 200000, .seed = 12, .spec = "1,mf=hc3,dict=4096,nice=3", .alone = true, .len = 202840, .sha = "2e9a44fc7a777e015fa2bbbc693658cefd9e33728d97866a9a1457202494e672" },
    .{ .kind = .mix2, .n = 530000, .seed = 31, .spec = "1,dict=65536", .len = 386608, .sha = "fbe3e0090b02bda4bc8cbdc47e4438c99237ca8ec5614878001ec5bb7510bebd" },
    .{ .kind = .mix2, .n = 530000, .seed = 31, .spec = "6,dict=65536", .len = 372416, .sha = "a06644b58725e3e9824b46592f7c7670e4c1cef11ebc0c729368bdd5982b9c40" },
    .{ .kind = .rnd, .n = 700000, .seed = 41, .spec = "0,dict=4096", .len = 700096, .sha = "60e4dc48099c5fd707415195126ab485cfd8fc16f7f5376dbbc295bf23daae24" },
    .{ .kind = .rnd, .n = 700000, .seed = 41, .spec = "6,dict=4096", .len = 700096, .sha = "5953d6d8124ad824e2bc5e67e14c9c310ee9d33eb9098e63779d83619eb39d4b" },
};

test "xz bytes: six data shapes under thirty-five option sets equal xz 5.8.3's (parser, match finders, price refresh)" {
    var last: ?struct { Kind, usize, u32 } = null;
    var data: []u8 = &.{};
    defer gpa.free(data);
    for (oracle_cases) |cs| {
        if (last == null or last.?[0] != cs.kind or last.?[1] != cs.n or last.?[2] != cs.seed) {
            gpa.free(data);
            data = &.{};
            data = try genData(gpa, cs.kind, cs.n, cs.seed);
            last = .{ cs.kind, cs.n, cs.seed };
        }
        const o = try lzma.interop_spec.parse(cs.spec);
        const z = try lzma.compress(gpa, data, if (cs.alone) .lzma_alone else .xz, .{ .lzma = o });
        defer gpa.free(z);
        testing.expectEqual(cs.len, z.len) catch |e| {
            std.debug.print("{s} {s} alone={}\n", .{ @tagName(cs.kind), cs.spec, cs.alone });
            return e;
        };
        const hex = sha256Hex(z);
        testing.expectEqualStrings(cs.sha, &hex) catch |e| {
            std.debug.print("{s} {s} alone={}\n", .{ @tagName(cs.kind), cs.spec, cs.alone });
            return e;
        };
    }
}

const TinyCase = struct { alpha: []const u8, maxlen: usize, spec: []const u8, count: usize, total: usize, sha: []const u8 };
const tiny_cases = [_]TinyCase{
    .{ .alpha = "ab", .maxlen = 11, .spec = "0,dict=4096", .count = 4094, .total = 121154, .sha = "93fe3b296121a04b79332644e0a0eaf8e01ff5170c81e47b0d17ecaefc6eee39" },
    .{ .alpha = "ab", .maxlen = 11, .spec = "1,dict=4096", .count = 4094, .total = 121894, .sha = "2a84e3dd0440a3b83057cfc2901db753f642d569d834fe9a7de25f21145b8e2b" },
    .{ .alpha = "ab", .maxlen = 13, .spec = "6,dict=4096", .count = 16382, .total = 492020, .sha = "0ad60a84d5722643eaf912c0fa85072ab044523401368d7e99b85fa0ea225c8b" },
    .{ .alpha = "abc", .maxlen = 7, .spec = "4,dict=4096,mf=bt3,nice=8", .count = 3279, .total = 93834, .sha = "60a649d62d16272f1fb98dabd94c49d9fcd9de8fd1deef03dafcbaa4e7b94d66" },
    .{ .alpha = "abc", .maxlen = 7, .spec = "1,dict=4096,mf=hc3,nice=3", .count = 3279, .total = 94602, .sha = "bda50555c7e52f84568428c75d49785009d2c1f8949e69798c438379f90e487b" },
};

test "xz bytes: every string over a small alphabet, as an .lzma stream, equals xz 5.8.3's (input tails, short matches)" {
    var dest: [2048]u8 = undefined;
    for (tiny_cases) |tc| {
        const o = try lzma.interop_spec.parse(tc.spec);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        var count: usize = 0;
        var total: usize = 0;
        var s: [16]u8 = undefined;
        var l: usize = 1;
        while (l <= tc.maxlen) : (l += 1) {
            var n: usize = 1;
            for (0..l) |_| n *= tc.alpha.len;
            var v: usize = 0;
            while (v < n) : (v += 1) {
                var r = v;
                var j = l;
                while (j > 0) {
                    j -= 1;
                    s[j] = tc.alpha[r % tc.alpha.len];
                    r /= tc.alpha.len;
                }
                const m = try lzma.compressInto(gpa, &dest, s[0..l], .lzma_alone, .{ .lzma = o });
                h.update(dest[0..m]);
                count += 1;
                total += m;
            }
        }
        var d: [32]u8 = undefined;
        h.final(&d);
        const hex = std.fmt.bytesToHex(d, .lower);
        testing.expectEqual(tc.count, count) catch |e| return e;
        testing.expectEqual(tc.total, total) catch |e| {
            std.debug.print("{s} {s}\n", .{ tc.alpha, tc.spec });
            return e;
        };
        testing.expectEqualStrings(tc.sha, &hex) catch |e| {
            std.debug.print("{s} {s}\n", .{ tc.alpha, tc.spec });
            return e;
        };
    }
}

// ── lz_enc.zig: the window and the position counter ──

const small_mf: lz.Options = .{ .before_size = 4096, .dict_size = 4096, .after_size = 4097, .match_len_max = 273, .nice_len = 64, .match_finder = .hc4, .depth = 4 };

test "Mf.fillWindow: slides when read_pos reaches size - keep_size_after, ends only at the end of the input" {
    var mf = try lz.Mf.init(gpa, small_mf);
    defer mf.deinit(gpa);
    const data = try gpa.alloc(u8, mf.size + 1000);
    defer gpa.free(data);
    lcg(data, 3, true);
    var pos: usize = 0;
    // .finish with input left over is not the end
    try testing.expect(!mf.fillWindow(data, &pos, .finish));
    try testing.expectEqual(@as(usize, mf.size), pos);
    try testing.expect(mf.action == .run);
    try testing.expectEqual(mf.size, mf.write_pos);
    // everything the encoder may read has been read: the next fill must make room
    mf.read_pos = mf.size - mf.keep_size_after;
    const before = pos;
    _ = mf.fillWindow(data, &pos, .run);
    try testing.expect(pos > before);
    try testing.expect(mf.write_pos < mf.size);
}

test "Mf: after a position normalisation every finder reports what it reported without it" {
    inline for (.{ lz.MatchFinder.hc3, .hc4, .bt2, .bt3, .bt4 }) |kind| {
        var o = small_mf;
        o.match_finder = kind;
        var a = try lz.Mf.init(gpa, o);
        defer a.deinit(gpa);
        var b = try lz.Mf.init(gpa, o);
        defer b.deinit(gpa);
        @memset(a.son, 0);
        @memset(b.son, 0);
        var data: [30000]u8 = undefined;
        lcg(&data, 5, true);
        var pa: usize = 0;
        var pb: usize = 0;
        _ = a.fillWindow(&data, &pa, .run);
        _ = b.fillWindow(&data, &pb, .run);
        var ma: [274]lz.Match = undefined;
        var mb: [274]lz.Match = undefined;
        var ca: u32 = 0;
        var cb: u32 = 0;
        var step: usize = 0;
        while (step < 9000) : (step += 1) {
            if (step == 5000) {
                // Push b's position counter to the edge of u32, its stored positions with it: the
                // next find normalises, and nothing observable may change.
                const new_offset = std.math.maxInt(u32) - b.read_pos - 1;
                const delta = new_offset -% b.offset;
                for (b.hash) |*h| {
                    if (h.* != 0) h.* +%= delta;
                }
                for (b.son) |*s| {
                    if (s.* != 0) s.* +%= delta;
                }
                b.offset = new_offset;
            }
            const la = a.find(&ca, &ma);
            const lb = b.find(&cb, &mb);
            try testing.expectEqual(la, lb);
            try testing.expectEqual(ca, cb);
            try testing.expectEqualSlices(lz.Match, ma[0..ca], mb[0..cb]);
        }
    }
}

test "Mf.find: a hash-chain candidate that shares only two bytes is not reported (len_best starts at 3)" {
    // "ab\x00\x39" and "ab\x01\x00" have the same hash4 under a 0xFFFF mask; the 2-byte table slot of "ab"
    // is overwritten in between by "\x02\x80" (same slot), so only the chain can offer the older gram.
    var data: [64]u8 = undefined;
    @memset(&data, 0xFE);
    data[0..6].* = .{ 0x61, 0x62, 0x00, 0x39, 0x02, 0x80 };
    @memset(data[6..46], 0xFF);
    data[46..50].* = .{ 0x61, 0x62, 0x01, 0x00 };
    inline for (.{ lz.MatchFinder.hc4, .bt4 }) |kind| {
        var o = small_mf;
        o.match_finder = kind;
        var mf = try lz.Mf.init(gpa, o);
        defer mf.deinit(gpa);
        @memset(mf.son, 0);
        var pos: usize = 0;
        _ = mf.fillWindow(&data, &pos, .run);
        var m: [274]lz.Match = undefined;
        var cnt: u32 = 0;
        var i: usize = 0;
        while (i <= 46) : (i += 1) {
            _ = mf.find(&cnt, &m);
            if (i == 46) try testing.expectEqual(@as(u32, 0), cnt);
        }
    }
}

// ── encoder.zig: a chunk whose compressed form is exactly as long as the input is stored ──

const FirstChunk = struct { payload: usize, read_ahead: u32 };

/// What the coder produces for the first LZMA2 chunk of `data` (the payload `Encoder` compares with the
/// uncompressed size, and the look-ahead it leaves behind), driven the way `Encoder` drives it.
fn firstChunk(data: []const u8, o: lzma.LzmaOptions) !FirstChunk {
    var lzo = o.lzOptions();
    if (lzo.before_size + lzo.dict_size < le.lzma2_chunk_max) lzo.before_size = le.lzma2_chunk_max - lzo.dict_size;
    var mf = try lz.Mf.init(gpa, lzo);
    defer mf.deinit(gpa);
    const co = try gpa.create(le.Coder);
    defer gpa.destroy(co);
    @memset(std.mem.asBytes(co), 0);
    try co.init(o, false);
    var in_pos: usize = 0;
    _ = mf.fillWindow(data, &in_pos, .finish);
    var buf: [le.lzma2_chunk_max]u8 = undefined;
    var out_pos: usize = 0;
    const limit: u32 = mf.read_pos - mf.read_ahead + (1 << 21) - mf.match_len_max;
    if (co.encode(&mf, &buf, &out_pos, limit) != .stream_end) return error.NotOneChunk;
    return .{ .payload = out_pos, .read_ahead = mf.read_ahead };
}

test "LZMA2: compressed size == uncompressed size is a stored chunk" {
    var o = lzma.preset(6, false);
    o.dict_size = 4096;
    var data: [400]u8 = undefined;
    var buf: [400]u8 = undefined;
    var found: ?usize = null;
    var seed: u32 = 1;
    search: while (seed <= 8) : (seed += 1) {
        lcg(&data, seed, false);
        var copy: usize = 10;
        while (copy <= 24) : (copy += 1) {
            var n: usize = 60;
            while (n <= 200) : (n += 1) {
                // random bytes whose tail repeats an earlier run: the payload hovers around n
                @memcpy(buf[0..n], data[0..n]);
                @memcpy(buf[n - copy .. n], data[10 .. 10 + copy]);
                if ((try firstChunk(buf[0..n], o)).payload == n) {
                    found = n;
                    break :search;
                }
            }
        }
    }
    const n = found orelse return error.TestUnexpectedResult;
    const z = try lzma.compress(gpa, buf[0..n], .lzma2, .{ .lzma = o });
    defer gpa.free(z);
    try testing.expectEqual(@as(u8, 1), z[0]); // stored, dictionary reset
    try testing.expectEqual(n + 3 + 1, z.len);
}

test "LZMA2: the first chunk ends at the first symbol boundary at or after 2 MiB - 273" {
    // p non-zero bytes, then zeros: after the first zero every symbol is 273 bytes long, so scanning p
    // over a whole residue class puts the limit exactly on, and exactly one byte past, a boundary.
    const limit_pos: usize = (1 << 21) - 273;
    var o = lzma.preset(1, false);
    o.dict_size = 1 << 16;
    const data = try gpa.alloc(u8, (1 << 21) + 1024 + 273);
    defer gpa.free(data);
    var exact: usize = 0;
    var p: usize = 0;
    while (p < 273) : (p += 1) {
        lcg(data[0..p], @intCast(p + 1), false);
        for (data[0..p]) |*b| b.* |= 1;
        @memset(data[p..], 0);
        const z = try lzma.compress(gpa, data, .lzma2, .{ .lzma = o });
        defer gpa.free(z);
        try testing.expect(z[0] >= 0x80);
        const size1 = ((@as(usize, z[0] & 0x1F) << 16) | (@as(usize, z[1]) << 8) | z[2]) + 1;
        try testing.expect(size1 >= limit_pos);
        try testing.expect(size1 < limit_pos + 273);
        if (size1 == limit_pos) exact += 1;
    }
    try testing.expect(exact >= 1);
}

test "LZMA2: a stored chunk that ends with look-ahead pending keeps those bytes" {
    var data: [70_000]u8 = undefined;
    var hit = false;
    var seed: u32 = 1;
    search: while (seed <= 60) : (seed += 1) {
        lcg(&data, seed, false);
        inline for (.{ lzma.Mode.normal, lzma.Mode.fast }) |mode| {
            var o = lzma.preset(6, false);
            o.dict_size = 1 << 16;
            o.mode = mode;
            if ((try firstChunk(&data, o)).read_ahead != 0) {
                const z = try lzma.compress(gpa, &data, .lzma2, .{ .lzma = o });
                defer gpa.free(z);
                const back = try lzma.decompress(gpa, z, .{ .lzma2 = .{ .dict_size = 1 << 16 } }, .{});
                defer gpa.free(back);
                try testing.expectEqualSlices(u8, &data, back);
                hit = true;
                break :search;
            }
        }
    }
    try testing.expect(hit);
}

// ── encoder.zig: compressBound ──

test "compressBound: n + n / 32 + 1024, saturating" {
    try testing.expectEqual(@as(usize, 1024), lzma.compressBound(0));
    try testing.expectEqual(@as(usize, 32 + 1 + 1024), lzma.compressBound(32));
    try testing.expectEqual(@as(usize, 6400 + 200 + 1024), lzma.compressBound(6400));
    try testing.expectEqual(std.math.maxInt(usize), lzma.compressBound(std.math.maxInt(usize)));
}

// ── encoder.zig: StreamWriter gets a splat write ──

test "StreamWriter: a splat write is delivered in full" {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [16]u8 = undefined;
    var sw = try lzma.StreamWriter.init(gpa, &out.writer, &buf, .xz, .{});
    defer sw.deinit();
    try sw.writer.splatByteAll('a', 100_000);
    try sw.writer.writeAll("tail");
    try sw.finish();
    const back = try lzma.decompress(gpa, out.written(), .xz, .{});
    defer gpa.free(back);
    try testing.expectEqual(@as(usize, 100_004), back.len);
    for (back[0..100_000]) |b| try testing.expectEqual(@as(u8, 'a'), b);
    try testing.expectEqualStrings("tail", back[100_000..]);
}

// ── rangeenc.zig ──

test "RangeEncoder: normalises only below top_value, and pending() is what a flush emits" {
    var out: [32]u8 = undefined;
    var pos: usize = 0;
    var rc: rcmod.RangeEncoder = .{};
    try testing.expectEqual(@as(u64, 5), rc.pending());
    rc.flush();
    try testing.expect(!rc.encode(&out, &pos));
    try testing.expectEqual(@as(usize, 5), pos);

    var at: rcmod.RangeEncoder = .{};
    at.range = c.top_value;
    at.direct(0, 1);
    pos = 0;
    try testing.expect(!at.encode(&out, &pos));
    try testing.expectEqual(@as(usize, 0), pos); // no byte shifted out
    try testing.expectEqual(c.top_value >> 1, at.range);

    var below: rcmod.RangeEncoder = .{};
    below.range = c.top_value - 1;
    below.direct(0, 1);
    pos = 0;
    try testing.expect(!below.encode(&out, &pos));
    try testing.expectEqual(@as(usize, 1), pos); // the cache byte left
    try testing.expectEqual(((c.top_value - 1) << 8) >> 1, below.range);
}

// ── xzfmt.zig ──

fn withCrc(comptime n: usize, body: [n - 4]u8) [n]u8 {
    var b: [n]u8 = undefined;
    b[0 .. n - 4].* = body;
    std.mem.writeInt(u32, b[n - 4 ..][0..4], std.hash.Crc32.hash(&body), .little);
    return b;
}

fn flagsCrc(flags: [2]u8) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, std.hash.Crc32.hash(&flags), .little);
    return b;
}

test "xzfmt.lzma2DictSize: the property table and its edges" {
    try testing.expectEqual(@as(?u32, 4096), xzfmt.lzma2DictSize(0));
    try testing.expectEqual(@as(?u32, 6144), xzfmt.lzma2DictSize(1));
    try testing.expectEqual(@as(?u32, 8192), xzfmt.lzma2DictSize(2));
    try testing.expectEqual(@as(?u32, 12288), xzfmt.lzma2DictSize(3));
    try testing.expectEqual(@as(?u32, 3 << 29), xzfmt.lzma2DictSize(37));
    try testing.expectEqual(@as(?u32, 2 << 30), xzfmt.lzma2DictSize(38));
    try testing.expectEqual(@as(?u32, 3 << 30), xzfmt.lzma2DictSize(39));
    try testing.expectEqual(@as(?u32, 0xFFFF_FFFF), xzfmt.lzma2DictSize(40));
    try testing.expectEqual(@as(?u32, null), xzfmt.lzma2DictSize(41));
    try testing.expectEqual(@as(?u32, null), xzfmt.lzma2DictSize(255));
}

test "xzfmt.parseStreamFlags: reserved bits, check ids and the CRC" {
    var f: [2]u8 = .{ 0, 4 };
    try testing.expectEqual(xzfmt.Check.crc64, try xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
    f = .{ 0, 0 };
    try testing.expectEqual(xzfmt.Check.none, try xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
    f = .{ 0, 1 };
    try testing.expectEqual(xzfmt.Check.crc32, try xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
    f = .{ 0, 10 };
    try testing.expectEqual(xzfmt.Check.sha256, try xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
    f = .{ 0, 4 };
    var bad = flagsCrc(f);
    bad[0] ^= 1;
    try testing.expectError(error.BadHeader, xzfmt.parseStreamFlags(&f, &bad));
    f = .{ 1, 4 }; // reserved first flag byte
    try testing.expectError(error.BadHeader, xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
    f = .{ 0, 0x14 }; // reserved bit 4 of the second byte
    try testing.expectError(error.BadHeader, xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
    f = .{ 0, 0x80 };
    try testing.expectError(error.BadHeader, xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
    f = .{ 0, 2 }; // unknown check ids
    try testing.expectError(error.UnsupportedCheck, xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
    f = .{ 0, 8 };
    try testing.expectError(error.UnsupportedCheck, xzfmt.parseStreamFlags(&f, &flagsCrc(f)));
}

fn footer(backward_field: u32, f8: u8, check_byte: u8, magic: [2]u8) [12]u8 {
    var b: [12]u8 = undefined;
    std.mem.writeInt(u32, b[4..8], backward_field, .little);
    b[8] = f8;
    b[9] = check_byte;
    std.mem.writeInt(u32, b[0..4], std.hash.Crc32.hash(b[4..10]), .little);
    b[10..12].* = magic;
    return b;
}

test "xzfmt.parseFooter: magic, reserved bits, CRC and the backward size" {
    const ok = try xzfmt.parseFooter(&footer(0, 0, 4, .{ 'Y', 'Z' }));
    try testing.expectEqual(xzfmt.Check.crc64, ok.check);
    try testing.expectEqual(@as(u64, 4), ok.backward);
    const ok5 = try xzfmt.parseFooter(&footer(5, 0, 1, .{ 'Y', 'Z' }));
    try testing.expectEqual(@as(u64, 24), ok5.backward);
    try testing.expectEqual(xzfmt.Check.crc32, ok5.check);
    try testing.expectError(error.BadFooter, xzfmt.parseFooter(&footer(0, 0, 4, .{ 'Y', 'X' })));
    try testing.expectError(error.BadFooter, xzfmt.parseFooter(&footer(0, 1, 4, .{ 'Y', 'Z' })));
    try testing.expectError(error.BadFooter, xzfmt.parseFooter(&footer(0, 0, 0x14, .{ 'Y', 'Z' })));
    try testing.expectError(error.UnsupportedCheck, xzfmt.parseFooter(&footer(0, 0, 3, .{ 'Y', 'Z' })));
    var crc_bad = footer(0, 0, 4, .{ 'Y', 'Z' });
    crc_bad[0] ^= 0x80;
    try testing.expectError(error.BadFooter, xzfmt.parseFooter(&crc_bad));
}

test "xzfmt.parseBlockHeader: filters, sizes, varints, padding and the CRC" {
    // the shape the encoder writes
    const ok = withCrc(12, .{ 0x02, 0x00, 0x21, 0x01, 0x16, 0, 0, 0 });
    const h = try xzfmt.parseBlockHeader(&ok);
    try testing.expectEqual(xzfmt.lzma2DictSize(0x16).?, h.dict_size);
    try testing.expectEqual(@as(?u64, null), h.compressed_size);
    try testing.expectEqual(@as(?u64, null), h.uncompressed_size);
    // CRC
    var crc_bad = ok;
    crc_bad[11] ^= 1;
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&crc_bad));
    // reserved flag bits
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x20, 0x21, 0x01, 0x16, 0, 0, 0 })));
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x04, 0x21, 0x01, 0x16, 0, 0, 0 })));
    // a compressed size of 0 is refused, a uncompressed size of 0 is not
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x40, 0x00, 0x21, 0x01, 0x16, 0, 0 })));
    const unc0 = try xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x80, 0x00, 0x21, 0x01, 0x16, 0, 0 }));
    try testing.expectEqual(@as(?u64, 0), unc0.uncompressed_size);
    // a property blob that ends exactly at the end of the body is fine
    const edge = try xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x40, 0x81, 0x80, 0x01, 0x21, 0x01, 0x16 }));
    try testing.expectEqual(@as(?u64, 16385), edge.compressed_size);
    // one byte longer than what is left
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x40, 0x81, 0x80, 0x01, 0x21, 0x02, 0x16 })));
    // LZMA2 properties must be one byte
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x00, 0x21, 0x02, 0x16, 0x00, 0, 0 })));
    // padding must be zero
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x00, 0x21, 0x01, 0x16, 0, 1, 0 })));
    // two filters (even two LZMA2 ones) are refused; an unknown filter is UnsupportedFilter
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x01, 0x21, 0x01, 0x16, 0x21, 0x01, 0x16 })));
    try testing.expectError(error.UnsupportedFilter, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x00, 0x03, 0x01, 0x16, 0, 0, 0 })));
    // properties byte out of range
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x00, 0x21, 0x01, 41, 0, 0, 0 })));
    // varints: a non-minimal one and one of ten bytes are malformed
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(12, .{ 0x02, 0x00, 0x21, 0x81, 0x00, 0x16, 0, 0 })));
    try testing.expectError(error.BadHeader, xzfmt.parseBlockHeader(&withCrc(20, .{ 0x04, 0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00, 0, 0, 0 })));
}

test "xzfmt.IndexHash.add: the vli_max edges, the count and the hashed sizes" {
    var h: xzfmt.IndexHash = .{};
    try h.add(xzfmt.vli_max, 0); // total == vli_max is allowed
    try testing.expectEqual(@as(u64, 1), h.count);
    var h2: xzfmt.IndexHash = .{};
    try h2.add(xzfmt.vli_max - 1, 1);
    var h3: xzfmt.IndexHash = .{};
    try testing.expectError(error.Overflow, h3.add(xzfmt.vli_max + 1, 0));
    try testing.expectError(error.Overflow, h3.add(0, xzfmt.vli_max + 1));
    try testing.expectError(error.Overflow, h3.add(xzfmt.vli_max, 1));
    try testing.expectError(error.Overflow, h3.add(std.math.maxInt(u64), std.math.maxInt(u64)));
    var a: xzfmt.IndexHash = .{};
    var b: xzfmt.IndexHash = .{};
    try a.add(100, 1000);
    try b.add(100, 1001);
    try testing.expectEqual(@as(u64, 1100), a.total - 0);
    try testing.expect(a.crc.final() != b.crc.final());
    try a.add(5, 6);
    try testing.expectEqual(@as(u64, 2), a.count);
    try testing.expectEqual(@as(u64, 1111), a.total);
}

// ── common.zig: properties byte, state machine ──

test "Lclppb: byte 225 and lc + lp over 4 are refused, the rest round-trips" {
    try testing.expect(c.Lclppb.decode(93) != null);
    try testing.expect(c.Lclppb.decode(225) == null);
    try testing.expect(c.Lclppb.decode(255) == null);
    var byte: u16 = 0;
    while (byte < 225) : (byte += 1) {
        const d = c.Lclppb.decode(@intCast(byte));
        const lc: u8 = @intCast(byte % 9);
        const lp: u8 = @intCast(byte / 9 % 5);
        const pb: u8 = @intCast(byte / 45);
        if (lc + lp > 4) {
            try testing.expect(d == null);
        } else {
            try testing.expectEqual(lc, d.?.lc);
            try testing.expectEqual(lp, d.?.lp);
            try testing.expectEqual(pb, d.?.pb);
            try testing.expectEqual(@as(u8, @intCast(byte)), d.?.encode());
        }
    }
}

test "LZMA state machine: the transitions of lzma_common.h" {
    const lit = [_]u8{ 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5 };
    for (lit, 0..) |want, s| try testing.expectEqual(want, c.updateLiteral(@intCast(s)));
    for (0..c.states) |s| {
        const st: u8 = @intCast(s);
        try testing.expectEqual(@as(u8, if (st < 7) 7 else 10), c.updateMatch(st));
        try testing.expectEqual(@as(u8, if (st < 7) 8 else 11), c.updateLongRep(st));
        try testing.expectEqual(@as(u8, if (st < 7) 9 else 11), c.updateShortRep(st));
        try testing.expectEqual(st < 7, c.isLiteralState(st));
    }
    try testing.expectEqual(@as(u32, 0), c.distState(2));
    try testing.expectEqual(@as(u32, 3), c.distState(5));
    try testing.expectEqual(@as(u32, 3), c.distState(6));
    try testing.expectEqual(@as(u32, 3), c.distState(273));
}

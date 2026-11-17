// SPDX-License-Identifier: MIT

//! Fuzz harnesses, generic over their source of choices (`fn(comptime S, *S,
//! gpa)`): `testing.fuzz` feeds them a `Smith`, the deterministic driver
//! (`LZ4_FUZZ=<runs>[,<first seed>]`, testkit's fuzz driver) a PRNG.
//!
//!   decode     arbitrary bytes, valid frames mutated anywhere or in their
//!              structure (descriptor, block size words, checksums), frames
//!              glued to skippable/legacy frames and junk, under a failing
//!              allocator. Invariants: no panic, no leak, no hang; an
//!              accepted input re-encodes and decodes to the same bytes.
//!   block      arbitrary and synthetic token streams through
//!              `decompressBlock` with a random output budget, judged
//!              against `modelDecode`, a byte-at-a-time reading of the
//!              block format written independently of `block.zig`.
//!   roundtrip  random structured input, every frame option and block size,
//!              accelerations: decode(encode(x)) == x for frames and blocks,
//!              and a short output buffer is `NoSpaceLeft`, never a panic.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const lz4 = @import("root.zig");

var reach: [reach_labels.len]usize = @splat(0);

fn labelIndex(comptime label: []const u8) ?usize {
    for (reach_labels, 0..) |l, i| if (std.mem.eql(u8, l, label)) return i;
    return null;
}

fn mark(comptime label: []const u8) void {
    fuzz_driver.hit(label);
    if (comptime labelIndex(label)) |i| reach[i] += 1;
}

fn markError(e: anyerror) void {
    inline for (@typeInfo(lz4.DecodeError).error_set.error_names.?) |n| {
        if (std.mem.eql(u8, n, @errorName(e))) {
            mark("err_" ++ n);
            return;
        }
    }
}

fn drawStructured(comptime S: type, src: *S, buf: []u8) void {
    switch (src.valueRangeAtMost(u8, 0, 5)) {
        0 => src.bytes(buf),
        1 => {
            var i: usize = 0;
            while (i < buf.len) {
                const r = @min(src.valueRangeAtMost(u16, 1, 600), buf.len - i);
                @memset(buf[i..][0..r], src.value(u8));
                i += r;
            }
        },
        2 => {
            const p = src.valueRangeAtMost(u8, 1, 20);
            var seed: [20]u8 = undefined;
            src.bytes(&seed);
            for (buf, 0..) |*c, i| c.* = seed[i % p];
        },
        3 => {
            const k = src.valueRangeAtMost(u8, 1, 4);
            for (buf) |*c| c.* = 'a' + src.valueRangeAtMost(u8, 0, k);
        },
        4 => @memset(buf, src.value(u8)),
        else => {
            const words = [_][]const u8{ "lz4 ", "frame ", "block ", "the ", "of ", "\n", "match " };
            var i: usize = 0;
            while (i < buf.len) {
                const w = words[src.valueRangeAtMost(u8, 0, words.len - 1)];
                const k = @min(w.len, buf.len - i);
                @memcpy(buf[i..][0..k], w[0..k]);
                i += k;
            }
        },
    }
}

fn drawEncodeOptions(comptime S: type, src: *S) lz4.EncodeOptions {
    return .{
        .block_size = @fromBackingInt(@intCast(src.valueRangeAtMost(u3, 4, 7))),
        .independent_blocks = src.value(bool),
        .block_checksum = src.value(bool),
        .content_checksum = src.value(bool),
        .content_size = src.value(bool),
        .acceleration = if (src.valueRangeAtMost(u8, 0, 3) == 0) src.valueRangeAtMost(u32, 0, 70_000) else 1,
    };
}

// ── the independent block model ─────────────────────────────────────────

/// The block format read one byte at a time with no shortcut: the
/// reference the fast decoder is judged against. `null` = malformed or
/// over budget (the verdict only; the error kinds are pinned by unit tests).
fn modelDecode(src: []const u8, out: []u8) ?usize {
    if (src.len == 0) return null;
    var i: usize = 0;
    var o: usize = 0;
    while (true) {
        if (i == src.len) return null;
        const t = src[i];
        i += 1;
        var lit: usize = t >> 4;
        if (lit == 15) while (true) {
            if (i == src.len) return null;
            lit += src[i];
            i += 1;
            if (src[i - 1] != 255) break;
        };
        var k: usize = 0;
        while (k < lit) : (k += 1) {
            if (i == src.len or o == out.len) return null;
            out[o] = src[i];
            o += 1;
            i += 1;
        }
        if (i == src.len) return o;
        if (i + 1 == src.len) return null;
        const off = @as(usize, src[i]) | @as(usize, src[i + 1]) << 8;
        i += 2;
        if (off == 0 or off > o) return null;
        var ml: usize = t & 15;
        if (ml == 15) while (true) {
            if (i == src.len) return null;
            ml += src[i];
            i += 1;
            if (src[i - 1] != 255) break;
        };
        ml += 4;
        k = 0;
        while (k < ml) : (k += 1) {
            if (o == out.len) return null;
            out[o] = out[o - off];
            o += 1;
        }
    }
}

/// A random but mostly well-formed token stream: literal and match lengths
/// near the 15 boundary, offsets near the history size.
fn synthBlock(comptime S: type, src: *S, list: *std.ArrayList(u8), gpa: std.mem.Allocator) !void {
    var produced: usize = 0;
    const seqs = src.valueRangeAtMost(u8, 0, 12);
    for (0..seqs) |_| {
        const lit: usize = switch (src.valueRangeAtMost(u8, 0, 3)) {
            0 => 0,
            1 => src.valueRangeAtMost(u16, 13, 17),
            2 => src.valueRangeAtMost(u16, 268, 272),
            else => src.valueRangeAtMost(u16, 1, 40),
        };
        const ml: usize = switch (src.valueRangeAtMost(u8, 0, 2)) {
            0 => src.valueRangeAtMost(u16, 4, 6),
            1 => src.valueRangeAtMost(u16, 17, 21),
            else => src.valueRangeAtMost(u16, 4, 600),
        };
        try putSeq(list, gpa, lit, ml - 4);
        for (0..lit) |_| try list.append(gpa, src.value(u8));
        produced += lit;
        const off: u16 = switch (src.valueRangeAtMost(u8, 0, 4)) {
            0 => 0,
            1 => @intCast(@min(produced + 1, 65535)),
            2 => @intCast(@max(@min(produced, 65535), 1)),
            else => src.valueRangeAtMost(u16, 1, 16),
        };
        try list.append(gpa, @truncate(off));
        try list.append(gpa, @truncate(off >> 8));
        if (ml - 4 >= 15) try putLen(list, gpa, ml - 4 - 15);
        produced += ml;
    }
    // The literal-only last sequence, mostly.
    if (src.valueRangeAtMost(u8, 0, 7) != 0) {
        const lit = src.valueRangeAtMost(u16, 0, 20);
        try putSeq(list, gpa, lit, 0);
        for (0..lit) |_| try list.append(gpa, src.value(u8));
    }
}

fn putSeq(list: *std.ArrayList(u8), gpa: std.mem.Allocator, lit: usize, mcode: usize) !void {
    const ln: u8 = @intCast(@min(lit, 15));
    const mn: u8 = @intCast(@min(mcode, 15));
    try list.append(gpa, ln << 4 | mn);
    if (lit >= 15) try putLen(list, gpa, lit - 15);
}

fn putLen(list: *std.ArrayList(u8), gpa: std.mem.Allocator, rest: usize) !void {
    var r = rest;
    while (r >= 255) : (r -= 255) try list.append(gpa, 255);
    try list.append(gpa, @intCast(r));
}

pub fn blockHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    switch (src.value(u64) % 3) {
        0 => {
            mark("blk_raw");
            var raw: [200]u8 = undefined;
            const n = src.slice(&raw);
            try list.appendSlice(gpa, raw[0..n]);
        },
        else => {
            mark("blk_synth");
            try synthBlock(S, src, &list, gpa);
        },
    }
    const cap: usize = if (src.value(bool)) src.valueRangeAtMost(u16, 0, 9000) else src.valueRangeAtMost(u16, 0, 64);
    const a = try gpa.alloc(u8, cap);
    defer gpa.free(a);
    const b = try gpa.alloc(u8, cap);
    defer gpa.free(b);
    const want = modelDecode(list.items, b);
    if (lz4.decompressBlock(list.items, a)) |n| {
        const w = want orelse return error.ModelRefused;
        try testing.expectEqual(w, n);
        try testing.expectEqualSlices(u8, b[0..w], a[0..n]);
        mark("blk_ok");
    } else |e| {
        switch (e) {
            error.Truncated => mark("blk_err_Truncated"),
            error.BadOffset => mark("blk_err_BadOffset"),
            error.OutputTooSmall => mark("blk_err_OutputTooSmall"),
        }
        if (want != null) return error.ModelAccepted;
    }
}

// ── frame decode harness ────────────────────────────────────────────────

fn decodeInput(comptime S: type, src: *S, gpa: std.mem.Allocator, input: []const u8) !void {
    const opts: lz4.DecodeOptions = .{
        .max_output = if (src.valueRangeAtMost(u8, 0, 3) == 0) src.valueRangeAtMost(u32, 0, 70_000) else 1 << 22,
        .multi_frame = src.valueRangeAtMost(u8, 0, 7) != 0,
        .ignore_trailing_garbage = src.valueRangeAtMost(u8, 0, 3) == 0,
        .verify_checksums = src.valueRangeAtMost(u8, 0, 7) != 0,
    };
    var fa = testkit.fuzz.failingAllocator(src, gpa, 16);
    const r = lz4.decompress(fa.allocator(), input, opts);
    // `decompressInto` gives `decompress`'s verdict under the cap `dst.len`:
    // the same bytes or the same error. `dst` is drawn around the decoded
    // length (or anywhere when the input is refused).
    {
        const near: usize = if (r) |out| out.len else |_| src.valueRangeAtMost(u32, 0, 70_000);
        const dlen = (near + src.valueRangeAtMost(u8, 0, 6)) -| 3;
        const dst = try gpa.alloc(u8, dlen);
        defer gpa.free(dst);
        var capped = opts;
        capped.max_output = @min(opts.max_output orelse std.math.maxInt(usize), dlen);
        const want = lz4.decompress(gpa, input, capped);
        defer if (want) |w| gpa.free(w) else |_| {};
        const got = lz4.decompressInto(input, dst, opts);
        if (want) |w| {
            try testing.expectEqualSlices(u8, w, dst[0..try got]);
            mark("into_ok");
        } else |e| {
            try testing.expectError(e, got);
            if (e == error.OutputTooLarge) mark("into_short");
        }
    }
    if (r) |out| {
        defer fa.allocator().free(out);
        if (out.len == 0) mark("ok_empty") else mark("ok_data");
        if (out.len <= 20_000) {
            const z = try lz4.compress(gpa, out, .{});
            defer gpa.free(z);
            const back = try lz4.decompress(gpa, z, .{ .max_output = null });
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, out, back);
            mark("reencoded");
        }
    } else |e| {
        if (e == error.OutOfMemory) {
            mark("fault_oom");
            return;
        }
        markError(e);
    }
}

pub fn decodeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    var data: [9000]u8 = undefined;

    // First draw from a full-range u64 (check-fuzz-reach R1).
    const mode: u8 = @intCast(src.value(u64) % 6);
    switch (mode) {
        0 => {
            mark("mode_raw");
            var junk: [300]u8 = undefined;
            const junk_len = src.slice(&junk);
            if (junk_len >= 6 and src.valueRangeAtMost(u8, 0, 2) != 0) {
                const m: u32 = switch (src.valueRangeAtMost(u8, 0, 2)) {
                    0 => lz4.frame_magic,
                    1 => lz4.legacy_frame_magic,
                    else => lz4.skippable_magic_base + src.valueRangeAtMost(u32, 0, 15),
                };
                std.mem.writeInt(u32, junk[0..4], m, .little);
                // A plausible descriptor: version 01, a valid block size id.
                if (m == lz4.frame_magic and src.value(bool)) {
                    junk[4] = 0x40 | (junk[4] & 0x3D);
                    junk[5] = @as(u8, src.valueRangeAtMost(u3, 4, 7)) << 4;
                    const desc_len: usize = 2 + @as(usize, if (junk[4] & 8 != 0) 8 else 0) + @as(usize, if (junk[4] & 1 != 0) 4 else 0);
                    if (junk_len > 4 + desc_len) junk[4 + desc_len] = @truncate(std.hash.XxHash32.hash(0, junk[4..][0..desc_len]) >> 8);
                }
            }
            try stream.appendSlice(gpa, junk[0..junk_len]);
        },
        1, 2, 3 => {
            const plain_len: usize = if (src.valueRangeAtMost(u8, 0, 3) == 0) src.valueRangeAtMost(u16, 0, 20) else src.valueRangeAtMost(u16, 0, 9000);
            drawStructured(S, src, data[0..plain_len]);
            const eo = drawEncodeOptions(S, src);
            const z = try lz4.compress(gpa, data[0..plain_len], eo);
            defer gpa.free(z);
            try stream.appendSlice(gpa, z);
            if (mode == 1) {
                mark("mode_mutated");
                for (0..src.valueRangeAtMost(u8, 1, 4)) |_| {
                    if (stream.items.len == 0) break;
                    const pos: usize = @intCast(src.value(u64) % stream.items.len);
                    switch (src.valueRangeAtMost(u8, 0, 3)) {
                        0 => stream.items[pos] ^= @as(u8, 1) << src.valueRangeAtMost(u3, 0, 7),
                        1 => stream.items[pos] = src.value(u8),
                        2 => stream.shrinkRetainingCapacity(pos),
                        else => try stream.insert(gpa, pos, src.value(u8)),
                    }
                }
            } else if (mode == 2) {
                // Aim at the structure: the descriptor, the first block size
                // word, the end mark and the trailing checksum.
                mark("mode_struct");
                const hl = 7 + @as(usize, if (eo.content_size) 8 else 0);
                const targets = [_]usize{ 4, 5, 6, hl - 1, hl, hl + 1, hl + 3, stream.items.len - 1, stream.items.len -| 5, stream.items.len -| 8 };
                const pos = @min(targets[@intCast(src.value(u64) % targets.len)], stream.items.len - 1);
                switch (src.valueRangeAtMost(u8, 0, 2)) {
                    0 => stream.items[pos] ^= @as(u8, 1) << src.valueRangeAtMost(u3, 0, 7),
                    1 => stream.items[pos] = src.value(u8),
                    else => stream.items[pos] +%= 1,
                }
                // Keep the header checksum valid half the time, so the damage
                // reaches past it.
                if (src.value(bool) and pos >= 4 and pos < hl) {
                    stream.items[hl - 1] = @truncate(std.hash.XxHash32.hash(0, stream.items[4 .. hl - 1]) >> 8);
                }
            } else {
                mark("mode_glued");
                for (0..src.valueRangeAtMost(u8, 1, 3)) |_| switch (src.valueRangeAtMost(u8, 0, 5)) {
                    0 => try stream.appendSlice(gpa, z),
                    1 => {
                        var w: [8]u8 = undefined;
                        std.mem.writeInt(u32, w[0..4], lz4.skippable_magic_base + src.valueRangeAtMost(u32, 0, 15), .little);
                        std.mem.writeInt(u32, w[4..8], src.valueRangeAtMost(u32, 0, 6), .little);
                        try stream.appendSlice(gpa, &w);
                        try stream.appendSlice(gpa, "skip..");
                    },
                    2 => {
                        // A legacy frame of one block (this module's block encoder).
                        mark("glued_legacy");
                        var w: [4]u8 = undefined;
                        std.mem.writeInt(u32, &w, lz4.legacy_frame_magic, .little);
                        try stream.appendSlice(gpa, &w);
                        var blk: [lz4.compressBlockBound(200)]u8 = undefined;
                        const k = @min(plain_len, 200);
                        const bn = try lz4.compressBlock(data[0..k], &blk, .{});
                        std.mem.writeInt(u32, &w, @intCast(bn), .little);
                        try stream.appendSlice(gpa, &w);
                        try stream.appendSlice(gpa, blk[0..bn]);
                    },
                    3 => try stream.appendSlice(gpa, "junk"),
                    4 => try stream.appendSlice(gpa, z[0..src.index(z.len)]),
                    else => try stream.appendNTimes(gpa, 0, 4),
                };
            }
        },
        4 => {
            // A hand-made frame around a synthetic block.
            mark("mode_synth");
            var w: [4]u8 = undefined;
            std.mem.writeInt(u32, &w, lz4.frame_magic, .little);
            try stream.appendSlice(gpa, &w);
            const flg: u8 = 0x40 | (src.value(u8) & 0x34);
            const desc = [2]u8{ flg, 0x40 };
            try stream.appendSlice(gpa, &desc);
            try stream.append(gpa, @truncate(std.hash.XxHash32.hash(0, &desc) >> 8));
            for (0..src.valueRangeAtMost(u8, 1, 3)) |_| {
                var blk: std.ArrayList(u8) = .empty;
                defer blk.deinit(gpa);
                try synthBlock(S, src, &blk, gpa);
                std.mem.writeInt(u32, &w, @intCast(blk.items.len), .little);
                try stream.appendSlice(gpa, &w);
                try stream.appendSlice(gpa, blk.items);
                if (flg & 0x10 != 0) {
                    std.mem.writeInt(u32, &w, std.hash.XxHash32.hash(0, blk.items), .little);
                    try stream.appendSlice(gpa, &w);
                }
            }
            try stream.appendNTimes(gpa, 0, 4);
            if (flg & 0x04 != 0) try stream.appendSlice(gpa, "\x00\x00\x00\x00");
        },
        5 => {
            mark("mode_legacy");
            var w: [4]u8 = undefined;
            std.mem.writeInt(u32, &w, lz4.legacy_frame_magic, .little);
            try stream.appendSlice(gpa, &w);
            for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
                var blk: std.ArrayList(u8) = .empty;
                defer blk.deinit(gpa);
                try synthBlock(S, src, &blk, gpa);
                std.mem.writeInt(u32, &w, @intCast(blk.items.len), .little);
                try stream.appendSlice(gpa, &w);
                try stream.appendSlice(gpa, blk.items);
            }
        },
        else => unreachable,
    }
    try decodeInput(S, src, gpa, stream.items);
}

// ── round trip harness ──────────────────────────────────────────────────

pub fn roundtripHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var data: [300_000]u8 = undefined;
    const n: usize = switch (src.value(u64) % 8) {
        0 => src.valueRangeAtMost(u16, 0, 16),
        1...4 => src.valueRangeAtMost(u16, 17, 5000),
        5 => src.valueRangeAtMost(u32, 65_530, 65_542),
        else => src.valueRangeAtMost(u32, 5000, 300_000),
    };
    drawStructured(S, src, data[0..n]);
    const input = data[0..n];
    if (n > 65_536) mark("rt_multiblock");

    const eo = drawEncodeOptions(S, src);
    const z = try lz4.compress(gpa, input, eo);
    defer gpa.free(z);
    try testing.expect(z.len <= lz4.compressBound(n, eo));
    const back = try lz4.decompress(gpa, z, .{ .max_output = null });
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, input, back);
    mark("rt_frame");

    // A buffer one byte short is NoSpaceLeft.
    {
        const short = try gpa.alloc(u8, z.len - 1);
        defer gpa.free(short);
        try testing.expectError(error.NoSpaceLeft, lz4.compressInto(input, short, eo));
    }

    // The block API on a prefix.
    const bn = @min(n, 70_000);
    const bz = try gpa.alloc(u8, lz4.compressBlockBound(bn));
    defer gpa.free(bz);
    const zn = try lz4.compressBlock(input[0..bn], bz, .{ .acceleration = eo.acceleration });
    const out = try gpa.alloc(u8, bn);
    defer gpa.free(out);
    try testing.expectEqual(bn, try lz4.decompressBlock(bz[0..zn], out));
    try testing.expectEqualSlices(u8, input[0..bn], out);
    if (modelDecode(bz[0..zn], out) != bn) return error.ModelDisagrees;
    mark("rt_block");
    if (bn > 0) {
        const cut = src.index(zn);
        if (lz4.decompressBlock(bz[0..cut], out)) |k| {
            // A cut that still parses must be a shorter prefix's encoding.
            try testing.expect(k <= bn);
        } else |_| mark("rt_block_cut");
    }
}

// ── drivers ─────────────────────────────────────────────────────────────

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    try decodeHarness(std.testing.Smith, smith, testing.allocator);
}

fn fuzzBlock(_: void, smith: *std.testing.Smith) !void {
    try blockHarness(std.testing.Smith, smith, testing.allocator);
}

fn fuzzRoundtrip(_: void, smith: *std.testing.Smith) !void {
    try roundtripHarness(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: the frame decoder never panics, leaks or hangs" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

test "fuzz: the block decoder agrees with the byte-at-a-time model" {
    try std.testing.fuzz({}, fuzzBlock, .{});
}

test "fuzz: encode then decode is the identity" {
    try std.testing.fuzz({}, fuzzRoundtrip, .{});
}

test "fuzz driver: LZ4_FUZZ, frame decoder" {
    try fuzz_driver.run(decodeHarness, .{ .prefix = "LZ4_FUZZ", .name = "lz4-decode" });
}

test "fuzz driver: LZ4_FUZZ, block decoder" {
    try fuzz_driver.run(blockHarness, .{ .prefix = "LZ4_FUZZ", .name = "lz4-block" });
}

test "fuzz driver: LZ4_FUZZ, round trip" {
    try fuzz_driver.run(roundtripHarness, .{ .prefix = "LZ4_FUZZ", .name = "lz4-roundtrip", .scale = 8 });
}

const reach_labels = [_][]const u8{
    "mode_raw",                   "mode_mutated",                "mode_struct",             "mode_glued",         "mode_synth",
    "mode_legacy",                "glued_legacy",                "ok_data",                 "ok_empty",           "reencoded",
    "fault_oom",                  "err_BadMagic",                "err_BadVersion",          "err_ReservedBitSet", "err_BadBlockSize",
    "err_HeaderChecksumMismatch", "err_TruncatedInput",          "err_BlockTooLarge",       "err_CorruptBlock",   "err_BadOffset",
    "err_BlockChecksumMismatch",  "err_ContentChecksumMismatch", "err_ContentSizeMismatch", "err_OutputTooLarge", "err_TrailingData",
    "blk_raw",                    "blk_synth",                   "blk_ok",                  "blk_err_Truncated",  "blk_err_BadOffset",
    "blk_err_OutputTooSmall",     "rt_multiblock",               "rt_frame",                "rt_block",           "rt_block_cut",
    "into_ok",                    "into_short",
};

test "fuzz harnesses: 3000 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..3000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        decodeHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("lz4 decode seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        blockHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("lz4 block seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        if (seed % 10 == 0) roundtripHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("lz4 roundtrip seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    var missing = false;
    for (reach_labels, reach) |l, n| {
        if (n == 0) {
            std.debug.print("reach: label {s} never hit in 3000 seeds\n", .{l});
            missing = true;
        }
    }
    if (missing) return error.HarnessDoesNotReach;
}

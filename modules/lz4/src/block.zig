// SPDX-License-Identifier: MIT

//! The LZ4 block format (lz4_Block_format.md, LZ4 v1.10.0): a sequence of
//! (token, literals, offset, match length) records, the last of which carries
//! literals only.
//!
//! Decoder: every length and offset is checked against the input, the output
//! slice and the history window before a byte is copied; a malformed block is
//! a typed `Error`, never a panic or an out-of-bounds read.
//!
//! Encoder: a single-probe hash table over 4-byte sequences, greedy parse,
//! the "acceleration" skip of LZ4's default compressor, and the block-end
//! rules of the format (the last 5 bytes are literals, the last match starts
//! at least 12 bytes before the end), so every block it writes is accepted by
//! liblz4's `LZ4_decompress_safe`.

const std = @import("std");

pub const Error = error{
    /// The block ends inside a sequence (a length, the literals or the
    /// offset run past the input), is empty, or ends right after a match
    /// instead of with a literal-only sequence (format rule 1).
    Truncated,
    /// A match offset of 0 (the format calls it a corrupted block) or one
    /// reaching before the start of the history window.
    BadOffset,
    /// The decoded bytes do not fit the output slice.
    OutputTooSmall,
};

pub const min_match = 4;
/// The last match must start at least this many bytes before the block end.
pub const mf_limit = 12;
/// The last this-many bytes of a block are literals.
pub const last_literals = 5;
/// The window: an offset is a u16, 1..65535.
pub const max_offset = 65535;
/// liblz4's `LZ4_MAX_INPUT_SIZE`: the largest input one block may hold.
pub const max_input_size: usize = 0x7E00_0000;

/// liblz4's `LZ4_COMPRESSBOUND`: the largest block `n` input bytes can
/// compress to (incompressible data: every literal plus the length bytes).
pub fn compressBound(n: usize) usize {
    return std.math.add(usize, n, n / 255 + 16) catch std.math.maxInt(usize);
}

fn readLength(src: []const u8, ip: *usize, base: usize) Error!usize {
    var len = base;
    while (true) {
        if (ip.* >= src.len) return error.Truncated;
        const b = src[ip.*];
        ip.* += 1;
        len = std.math.add(usize, len, b) catch return error.OutputTooSmall;
        if (b != 255) return len;
    }
}

/// Decode one block into `out[start..]`. `out[prefix_start..start]` is the
/// history a match may reach into (the previous blocks of a linked frame);
/// `prefix_start == start` means none. Returns the end index of the output.
pub fn decodeInto(src: []const u8, out: []u8, start: usize, prefix_start: usize) Error!usize {
    std.debug.assert(prefix_start <= start and start <= out.len);
    if (src.len == 0) return error.Truncated;
    var ip: usize = 0;
    var op: usize = start;
    while (true) {
        if (ip >= src.len) return error.Truncated; // ended after a match
        const token = src[ip];
        ip += 1;

        var lit: usize = token >> 4;
        if (lit == 15) lit = try readLength(src, &ip, 15);
        if (lit > src.len - ip) return error.Truncated;
        if (lit > out.len - op) return error.OutputTooSmall;
        if (lit <= 16 and src.len - ip >= 16 and out.len - op >= 16) {
            // One fixed 16-byte copy; the bytes past `lit` are scratch that
            // the next sequence overwrites (or that stay unused capacity).
            out[op..][0..16].* = src[ip..][0..16].*;
        } else @memcpy(out[op..][0..lit], src[ip..][0..lit]);
        ip += lit;
        op += lit;
        if (ip == src.len) return op; // the literal-only last sequence

        if (src.len - ip < 2) return error.Truncated;
        const offset: usize = std.mem.readInt(u16, src[ip..][0..2], .little);
        ip += 2;
        if (offset == 0 or offset > op - prefix_start) return error.BadOffset;

        var ml: usize = token & 15;
        if (ml == 15) ml = try readLength(src, &ip, 15);
        ml += min_match;
        if (ml > out.len - op) return error.OutputTooSmall;
        if (offset >= 16 and out.len - op - ml >= 16) {
            // 16-byte chunks, overshooting by up to 15 bytes of scratch: no
            // chunk overlaps itself, and a chunk reading what an earlier one
            // wrote reads the right bytes (the copy runs forwards).
            const m = op - offset;
            var i: usize = 0;
            while (i < ml) : (i += 16) out[op + i ..][0..16].* = out[m + i ..][0..16].*;
        } else copyMatch(out, op, offset, ml);
        op += ml;
    }
}

/// Copy `len` bytes from `op - offset` to `op`, overlap allowed (the copy is
/// defined byte by byte, so a short offset repeats a pattern).
inline fn copyMatch(out: []u8, op: usize, offset: usize, len: usize) void {
    const m = op - offset;
    if (offset >= len) {
        @memcpy(out[op..][0..len], out[m..][0..len]);
    } else if (offset == 1) {
        @memset(out[op..][0..len], out[m]);
    } else {
        // The pattern repeats with period `offset`. Copying from `m` while
        // `done` is a multiple of the period doubles the run each pass, and
        // the source `out[m..][0..offset + done]` never overlaps the target.
        var done: usize = 0;
        while (done < len) {
            const k = @min(offset + done, len - done);
            @memcpy(out[op + done ..][0..k], out[m..][0..k]);
            done += k;
        }
    }
}

/// Decode one block into `dst` (no history). Returns the decoded length.
/// `dst.len` is the output budget, as `dstCapacity` is for liblz4's
/// `LZ4_decompress_safe`; like it, the decoder may use `dst` past the
/// returned length as scratch (those bytes are unspecified afterwards).
pub fn decompress(src: []const u8, dst: []u8) Error!usize {
    return decodeInto(src, dst, 0, 0);
}

// ── encoder ─────────────────────────────────────────────────────────────

pub const hash_log = 12;
pub const hash_size = 1 << hash_log;
/// After this many misses in a row the search step grows by one (LZ4's
/// `skipTrigger`).
const skip_trigger = 6;

/// A hash table of input positions, reused across the blocks of a frame.
pub const Table = [hash_size]u32;

inline fn read32(b: []const u8, i: usize) u32 {
    return std.mem.readInt(u32, b[i..][0..4], .little);
}

inline fn hash(v: u32) usize {
    return @intCast((v *% 2654435761) >> (32 - hash_log));
}

const Sink = struct {
    dst: []u8,
    at: usize = 0,

    fn byte(s: *Sink, b: u8) error{NoSpaceLeft}!void {
        if (s.at >= s.dst.len) return error.NoSpaceLeft;
        s.dst[s.at] = b;
        s.at += 1;
    }

    fn bytes(s: *Sink, b: []const u8) error{NoSpaceLeft}!void {
        if (b.len > s.dst.len - s.at) return error.NoSpaceLeft;
        @memcpy(s.dst[s.at..][0..b.len], b);
        s.at += b.len;
    }

    fn length(s: *Sink, rest: usize) error{NoSpaceLeft}!void {
        var r = rest;
        while (r >= 255) : (r -= 255) try s.byte(255);
        try s.byte(@intCast(r));
    }

    fn sequence(s: *Sink, lits: []const u8, offset: ?u16, ml: usize) error{NoSpaceLeft}!void {
        const ln: u8 = if (lits.len >= 15) 15 else @intCast(lits.len);
        const mcode = if (offset == null) 0 else ml - min_match;
        const mn: u8 = if (mcode >= 15) 15 else @intCast(mcode);
        try s.byte(ln << 4 | mn);
        if (lits.len >= 15) try s.length(lits.len - 15);
        try s.bytes(lits);
        const off = offset orelse return;
        try s.byte(@truncate(off));
        try s.byte(@truncate(off >> 8));
        if (mcode >= 15) try s.length(mcode - 15);
    }
};

/// Compress `buf[start..end]` as one block into `dst`. Matches may reach back
/// into `buf[history_start..start]` (a linked frame's previous blocks), never
/// further than 65535 bytes. `table` holds positions in `buf` from earlier
/// calls over the same `buf`; positions below `history_start` are ignored.
/// `acceleration` >= 1: larger is faster and compresses less (LZ4's knob).
pub fn encodeRange(
    buf: []const u8,
    start: usize,
    end: usize,
    history_start: usize,
    table: *Table,
    acceleration: u32,
    dst: []u8,
) error{NoSpaceLeft}!usize {
    std.debug.assert(history_start <= start and start <= end and end <= buf.len);
    std.debug.assert(end <= std.math.maxInt(u32));
    var s: Sink = .{ .dst = dst };
    const n = end - start;
    var anchor = start;
    if (n >= mf_limit + 1) {
        const match_limit = end - mf_limit; // a match starts at or before this
        const extend_limit = end - last_literals; // and ends at or before this
        var ip = start;
        if (ip == history_start) {
            table[hash(read32(buf, ip))] = @intCast(ip);
            ip += 1;
        }
        outer: while (true) {
            // Search for a match.
            var misses: u32 = acceleration << skip_trigger;
            var cand: usize = undefined;
            while (true) {
                if (ip > match_limit) break :outer;
                const v = read32(buf, ip);
                const h = hash(v);
                cand = table[h];
                table[h] = @intCast(ip);
                if (cand >= history_start and cand < ip and ip - cand <= max_offset and read32(buf, cand) == v) break;
                ip += misses >> skip_trigger;
                misses += 1;
            }
            // Extend backwards into pending literals.
            while (ip > anchor and cand > history_start and buf[ip - 1] == buf[cand - 1]) {
                ip -= 1;
                cand -= 1;
            }
            // Extend forwards.
            var e = ip + min_match;
            var c = cand + min_match;
            while (e + 8 <= extend_limit) {
                const x = std.mem.readInt(u64, buf[e..][0..8], .little) ^ std.mem.readInt(u64, buf[c..][0..8], .little);
                if (x != 0) {
                    e += @ctz(x) / 8;
                    break;
                }
                e += 8;
                c += 8;
            } else {
                while (e < extend_limit and buf[e] == buf[c]) {
                    e += 1;
                    c += 1;
                }
            }
            try s.sequence(buf[anchor..ip], @intCast(ip - cand), e - ip);
            ip = e;
            anchor = ip;
            if (ip > match_limit) break;
            // Seed the table with a position inside the match, as LZ4 does.
            table[hash(read32(buf, ip - 2))] = @intCast(ip - 2);
        }
    }
    try s.sequence(buf[anchor..end], null, 0);
    return s.at;
}

pub const CompressOptions = struct {
    /// LZ4's acceleration: 1 (the default) is LZ4's default level; each step
    /// up makes the match search skip faster over incompressible data.
    /// 0 is taken as 1; above 65537 is taken as 65537 (liblz4's bounds).
    acceleration: u32 = 1,
};

/// Clamp an acceleration the way liblz4 does.
pub fn clampAcceleration(a: u32) u32 {
    return std.math.clamp(a, 1, 65537);
}

/// Compress `src` as one independent block into `dst`. `compressBound(src.len)`
/// bytes always fit; with less room `error.NoSpaceLeft` may come back.
pub fn compress(src: []const u8, dst: []u8, opts: CompressOptions) error{ NoSpaceLeft, InputTooLarge }!usize {
    if (src.len > max_input_size) return error.InputTooLarge;
    var table: Table = @splat(0);
    return encodeRange(src, 0, src.len, 0, &table, clampAcceleration(opts.acceleration), dst);
}

// ── tests ───────────────────────────────────────────────────────────────

const testing = std.testing;

fn roundTrip(input: []const u8, accel: u32) !void {
    const gpa = testing.allocator;
    const z = try gpa.alloc(u8, compressBound(input.len));
    defer gpa.free(z);
    const zn = try compress(input, z, .{ .acceleration = accel });
    try testing.expect(zn <= compressBound(input.len));
    const back = try gpa.alloc(u8, input.len);
    defer gpa.free(back);
    try testing.expectEqual(input.len, try decompress(z[0..zn], back));
    try testing.expectEqualSlices(u8, input, back);
}

test "block: hand-built sequences decode" {
    var out: [64]u8 = undefined;
    // Literals only.
    try testing.expectEqual(@as(usize, 1), try decompress("\x10a", &out));
    try testing.expectEqualStrings("a", out[0..1]);
    // The empty block is a single zero token.
    try testing.expectEqual(@as(usize, 0), try decompress("\x00", &out));
    try testing.expectEqual(@as(usize, 0), try decompress("\x00", out[0..0]));
    // 'a', a match of 4 at offset 1, then 'b': overlap repeats the byte.
    try testing.expectEqual(@as(usize, 6), try decompress("\x10a\x01\x00\x10b", &out));
    try testing.expectEqualStrings("aaaaab", out[0..6]);
    // Offset 3 over "abc", length 4+15+1 = 20: a repeating pattern.
    try testing.expectEqual(@as(usize, 24), try decompress("\x3fabc\x03\x00\x01\x10z", &out));
    try testing.expectEqualStrings("abcabcabcabcabcabcabcabz", out[0..24]);
    // A 15-literal run needs the extension byte (0 here).
    try testing.expectEqual(@as(usize, 15), try decompress("\xf0\x00xxxxxxxxxxxxxxx", &out));
    // 15 + 255 + 2 literals: two extension bytes.
    var big: [3 + 272]u8 = undefined;
    big[0] = 0xf0;
    big[1] = 255;
    big[2] = 2;
    @memset(big[3..], 'q');
    var out2: [300]u8 = undefined;
    try testing.expectEqual(@as(usize, 272), try decompress(&big, &out2));
}

test "block: malformed blocks are typed errors" {
    var out: [64]u8 = undefined;
    try testing.expectError(error.Truncated, decompress("", &out));
    try testing.expectError(error.Truncated, decompress("\x20a", &out)); // literals past end
    try testing.expectError(error.Truncated, decompress("\xf0", &out)); // missing extension
    try testing.expectError(error.Truncated, decompress("\xf0\xff", &out)); // extension continues
    try testing.expectError(error.Truncated, decompress("\x10a\x01", &out)); // half an offset
    try testing.expectError(error.Truncated, decompress("\x10a\x01\x00", &out)); // ends with a match
    try testing.expectError(error.Truncated, decompress("\x1fa\x01\x00", &out)); // match length ext missing
    try testing.expectError(error.BadOffset, decompress("\x10a\x00\x00\x10b", &out)); // offset 0
    try testing.expectError(error.BadOffset, decompress("\x10a\x02\x00\x10b", &out)); // before the start
    try testing.expectError(error.BadOffset, decompress("\x00\x01\x00\x10b", &out)); // no history at all
    try testing.expectError(error.OutputTooSmall, decompress("\x30abc", out[0..2])); // literals
    try testing.expectError(error.OutputTooSmall, decompress("\x10a\x01\x00\x10b", out[0..4])); // match
    try testing.expectError(error.OutputTooSmall, decompress("\x10a\x01\x00\x10b", out[0..5])); // last literal
    // Trailing bytes after the literal-only sequence are a new token that
    // runs out: not silently ignored.
    try testing.expectError(error.Truncated, decompress("\x10ab", &out));
}

test "block: a match may reach into the history prefix and no further" {
    var out: [32]u8 = undefined;
    @memcpy(out[0..5], "hello");
    // At position 5 with history [0, 5): offset 5 length 4 = "hell", then "!".
    try testing.expectEqual(@as(usize, 10), try decodeInto("\x00\x05\x00\x10!", &out, 5, 0));
    try testing.expectEqualStrings("hellohell!", out[0..10]);
    // The same block with history [2, 5): offset 5 reaches before it.
    try testing.expectError(error.BadOffset, decodeInto("\x00\x05\x00\x10!", &out, 5, 2));
    try testing.expectEqual(@as(usize, 10), try decodeInto("\x00\x03\x00\x10!", &out, 5, 2));
    try testing.expectEqualStrings("llollol!", out[2..10]);
}

test "block: compressBound matches liblz4's macro" {
    try testing.expectEqual(@as(usize, 16), compressBound(0));
    try testing.expectEqual(@as(usize, 272), compressBound(255));
    try testing.expectEqual(@as(usize, 65536 + 257 + 16), compressBound(65536));
}

test "block: round trips over shapes and accelerations" {
    var buf: [70_000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    for (0..13) |n| {
        for (buf[0..n], 0..) |*b, i| b.* = @intCast(i % 3);
        try roundTrip(buf[0..n], 1);
    }
    @memset(&buf, 'z');
    try roundTrip(&buf, 1);
    r.bytes(&buf);
    try roundTrip(&buf, 1);
    try roundTrip(&buf, 9);
    for (&buf, 0..) |*b, i| b.* = "the quick brown fox "[i % 20] ^ @as(u8, @intFromBool(r.uintLessThan(u8, 50) == 0));
    try roundTrip(&buf, 1);
    try roundTrip(&buf, 65537);
    try roundTrip(&buf, 0);
}

test "block: compressed sizes are those of a working matcher" {
    var buf: [65_536]u8 = undefined;
    @memset(&buf, 0);
    var z: [compressBound(65_536)]u8 = undefined;
    // All zeros: one literal, one long match, five literals.
    const n = try compress(&buf, &z, .{});
    try testing.expect(n < 300);
    // Incompressible: within the bound, larger than the input.
    var prng = std.Random.DefaultPrng.init(1);
    prng.random().bytes(&buf);
    const m = try compress(&buf, &z, .{});
    try testing.expect(m > buf.len and m <= compressBound(buf.len));
}

test "block: the encoder honours the end-of-block rules" {
    // For every input, the last match ends no later than 5 bytes before the end
    // and starts at least 12 bytes before it. Walk the encoder's own output.
    var buf: [200]u8 = undefined;
    @memset(&buf, 'a');
    var z: [compressBound(200)]u8 = undefined;
    for (13..200) |len| {
        const zn = try compress(buf[0..len], &z, .{});
        var ip: usize = 0;
        var op: usize = 0;
        var last_match_start: usize = 0;
        var last_match_end: usize = 0;
        while (true) {
            const t = z[ip];
            ip += 1;
            var lit: usize = t >> 4;
            if (lit == 15) lit = try readLength(z[0..zn], &ip, 15);
            ip += lit;
            op += lit;
            if (ip == zn) break;
            ip += 2;
            var ml: usize = t & 15;
            if (ml == 15) ml = try readLength(z[0..zn], &ip, 15);
            last_match_start = op;
            op += ml + 4;
            last_match_end = op;
        }
        try testing.expectEqual(len, op);
        try testing.expect(last_match_start + mf_limit <= len);
        try testing.expect(last_match_end + last_literals <= len);
    }
}

test "block: output too small for the encoder is NoSpaceLeft" {
    var buf: [100]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    prng.random().bytes(&buf);
    var z: [50]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, compress(&buf, &z, .{}));
    try testing.expectError(error.NoSpaceLeft, compress("", z[0..0], .{}));
}

test "block: the 13-byte minimum and the window edge" {
    var z: [compressBound(3000)]u8 = undefined;
    // 12 bytes: literals only (1 token + 12). 13 zeros: 1 literal, a 7-byte
    // match ending 5 bytes before the end, 5 literals = 10 bytes.
    const zeros: [13]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 13), try compress(zeros[0..12], &z, .{}));
    try testing.expectEqual(@as(usize, 10), try compress(&zeros, &z, .{}));
    // A 1000-byte repeat at offset 65535 is found; at 65536 it is out of
    // the window and the block stays (valid) literals.
    const shapes = @import("shapes.zig");
    var sizes: [2]usize = undefined;
    for ([_]u32{ 64_535, 64_536 }, 0..) |param, i| {
        const s: shapes.Shape = .{ .name = "far", .kind = .far_repeat, .len = 0, .param = param };
        const input = try testing.allocator.alloc(u8, shapes.length(s));
        defer testing.allocator.free(input);
        shapes.fill(s, input);
        const zz = try testing.allocator.alloc(u8, compressBound(input.len));
        defer testing.allocator.free(zz);
        sizes[i] = try compress(input, zz, .{});
        const back = try testing.allocator.alloc(u8, input.len);
        defer testing.allocator.free(back);
        try testing.expectEqual(input.len, try decompress(zz[0..sizes[i]], back));
        try testing.expectEqualSlices(u8, input, back);
    }
    try testing.expect(sizes[0] + 900 < sizes[1]);
}

test "block: a higher acceleration trades size for speed" {
    var buf: [65_536]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(4);
    const r = prng.random();
    for (&buf, 0..) |*c, i| c.* = if (r.uintLessThan(u8, 6) == 0) r.int(u8) else "acceleration knob "[i % 18];
    var z: [compressBound(65_536)]u8 = undefined;
    const slow = try compress(&buf, &z, .{});
    const fast = try compress(&buf, &z, .{ .acceleration = 64 });
    try testing.expect(fast > slow + 1000);
}

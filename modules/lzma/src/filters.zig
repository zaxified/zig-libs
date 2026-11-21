// SPDX-License-Identifier: MIT

//! The `.xz` filters that run before LZMA2: the branch/call/jump (BCJ)
//! converters for x86, ARM, ARM Thumb, ARM64, PowerPC, IA-64 and SPARC, and the delta
//! filter. Each one is a size-preserving, in-place transform of the
//! uncompressed stream; a BCJ filter turns the relative address of a branch
//! into an absolute one on encode (so equal targets repeat and compress) and
//! back on decode. Filter ids and property layouts are those of the
//! xz-file-format specification section 5.3 (the converters follow the
//! public-domain/0BSD `simple` filters of liblzma 5.8.1; the encoder output is
//! compared byte for byte with the `xz` program in `tools/interop.zig`).

const std = @import("std");

/// One filter of a block's chain (everything before the final LZMA2).
pub const Filter = union(enum) {
    x86: Bcj,
    powerpc: Bcj,
    ia64: Bcj,
    arm: Bcj,
    armthumb: Bcj,
    sparc: Bcj,
    arm64: Bcj,
    /// The distance, 1..256.
    delta: u16,

    /// Options of a branch converter: the address of the stream's first byte
    /// (xz's `start=`), 0 unless the data does not start at its load address.
    pub const Bcj = struct {
        start_offset: u32 = 0,
    };

    pub const max_chain = 3;

    /// xz-file-format filter id.
    pub fn id(f: Filter) u8 {
        return switch (f) {
            .delta => 0x03,
            .x86 => 0x04,
            .powerpc => 0x05,
            .ia64 => 0x06,
            .arm => 0x07,
            .armthumb => 0x08,
            .sparc => 0x09,
            .arm64 => 0x0A,
        };
    }

    /// The alignment a start offset must have (liblzma's `is_aligned` rules).
    fn alignment(f: Filter) u32 {
        return switch (f) {
            .x86, .delta => 1,
            .armthumb => 2,
            .ia64 => 16,
            .powerpc, .arm, .sparc, .arm64 => 4,
        };
    }

    pub fn valid(f: Filter) bool {
        return switch (f) {
            .delta => |d| d >= 1 and d <= 256,
            inline else => |b| b.start_offset % f.alignment() == 0,
        };
    }

    /// The filter properties as they appear in a block header; returns the length.
    pub fn props(f: Filter, out: *[4]u8) usize {
        switch (f) {
            .delta => |d| {
                out[0] = @intCast(d - 1);
                return 1;
            },
            inline else => |b| {
                if (b.start_offset == 0) return 0;
                std.mem.writeInt(u32, out, b.start_offset, .little);
                return 4;
            },
        }
    }

    /// The filter with this id and property bytes; null for an unknown id,
    /// wrong property size or a refused value.
    pub fn fromProps(filter_id: u64, p: []const u8) ?Filter {
        if (filter_id == 0x03) {
            if (p.len != 1) return null;
            return .{ .delta = @as(u16, p[0]) + 1 };
        }
        const bcj: Bcj = blk: {
            if (p.len == 0) break :blk .{};
            if (p.len != 4) return null;
            break :blk .{ .start_offset = std.mem.readInt(u32, p[0..4], .little) };
        };
        const f: Filter = switch (filter_id) {
            0x04 => .{ .x86 = bcj },
            0x05 => .{ .powerpc = bcj },
            0x06 => .{ .ia64 = bcj },
            0x07 => .{ .arm = bcj },
            0x08 => .{ .armthumb = bcj },
            0x09 => .{ .sparc = bcj },
            0x0A => .{ .arm64 = bcj },
            else => return null,
        };
        return if (f.valid()) f else null;
    }
};

fn test86(b: u8) bool {
    return b == 0 or b == 0xFF;
}

/// The running state of one filter.
const Stage = struct {
    f: Filter,
    /// Stream position of the next byte to convert (wraps at 2^32 as liblzma's).
    now_pos: u32,
    // x86
    prev_mask: u32 = 0,
    prev_pos: u32 = 0xFFFF_FFFB, // (uint32_t)-5
    // delta
    pos: u8 = 0,
    hist: [256]u8 = @splat(0),

    fn init(f: Filter) Stage {
        return .{ .f = f, .now_pos = switch (f) {
            .delta => 0,
            inline else => |b| b.start_offset,
        } };
    }

    /// Convert `buf` in place; returns how many leading bytes are final. The
    /// rest (fewer than 16) needs more input and is offered again, or passes
    /// through unchanged at the end of the stream.
    fn code(s: *Stage, buf: []u8, encode: bool) usize {
        const n = switch (s.f) {
            .delta => |d| return s.delta(buf, d, encode),
            .x86 => s.x86(buf, encode),
            .arm => s.arm(buf, encode),
            .armthumb => s.armthumb(buf, encode),
            .powerpc => s.ppc(buf, encode),
            .ia64 => s.ia64(buf, encode),
            .sparc => s.sparc(buf, encode),
            .arm64 => s.arm64(buf, encode),
        };
        s.now_pos +%= @intCast(n);
        return n;
    }

    fn delta(s: *Stage, buf: []u8, dist: u16, encode: bool) usize {
        for (buf) |*b| {
            const h = &s.hist[(@as(usize, dist) + s.pos) & 0xFF];
            const old = h.*;
            if (encode) {
                s.hist[s.pos] = b.*;
                b.* -%= old;
            } else {
                b.* +%= old;
                s.hist[s.pos] = b.*;
            }
            s.pos -%= 1;
        }
        return buf.len;
    }

    fn x86(s: *Stage, buf: []u8, encode: bool) usize {
        const allowed = [8]bool{ true, true, true, false, true, false, false, false };
        const bit_number = [8]u5{ 0, 1, 2, 2, 3, 3, 3, 3 };
        var prev_mask = s.prev_mask;
        var prev_pos = s.prev_pos;
        if (buf.len < 5) return 0;
        if (s.now_pos -% prev_pos > 5) prev_pos = s.now_pos -% 5;
        const limit = buf.len - 5;
        var i: usize = 0;
        while (i <= limit) {
            var b = buf[i];
            if (b != 0xE8 and b != 0xE9) {
                i += 1;
                continue;
            }
            const offset = s.now_pos +% @as(u32, @intCast(i)) -% prev_pos;
            prev_pos = s.now_pos +% @as(u32, @intCast(i));
            if (offset > 5) {
                prev_mask = 0;
            } else {
                var k: u32 = 0;
                while (k < offset) : (k += 1) {
                    prev_mask &= 0x77;
                    prev_mask <<= 1;
                }
            }
            b = buf[i + 4];
            if (test86(b) and allowed[(prev_mask >> 1) & 7] and (prev_mask >> 1) < 0x10) {
                var src: u32 = (@as(u32, b) << 24) | (@as(u32, buf[i + 3]) << 16) | (@as(u32, buf[i + 2]) << 8) | buf[i + 1];
                var dest: u32 = undefined;
                while (true) {
                    const here = s.now_pos +% @as(u32, @intCast(i)) +% 5;
                    dest = if (encode) src +% here else src -% here;
                    if (prev_mask == 0) break;
                    const bn = bit_number[(prev_mask >> 1) & 7];
                    b = @truncate(dest >> (24 - @as(u5, bn) * 8));
                    if (!test86(b)) break;
                    src = dest ^ @as(u32, @truncate((@as(u64, 1) << (32 - @as(u6, bn) * 8)) - 1));
                }
                buf[i + 4] = ~(@as(u8, @truncate((dest >> 24) & 1)) -% 1);
                buf[i + 3] = @truncate(dest >> 16);
                buf[i + 2] = @truncate(dest >> 8);
                buf[i + 1] = @truncate(dest);
                i += 5;
                prev_mask = 0;
            } else {
                i += 1;
                prev_mask |= 1;
                if (test86(b)) prev_mask |= 0x10;
            }
        }
        s.prev_mask = prev_mask;
        s.prev_pos = prev_pos;
        return i;
    }

    fn arm(s: *Stage, buf: []u8, encode: bool) usize {
        var i: usize = 0;
        while (i + 4 <= buf.len) : (i += 4) {
            if (buf[i + 3] != 0xEB) continue;
            var src: u32 = (@as(u32, buf[i + 2]) << 16) | (@as(u32, buf[i + 1]) << 8) | buf[i];
            src <<= 2;
            const here = s.now_pos +% @as(u32, @intCast(i)) +% 8;
            var dest = if (encode) here +% src else src -% here;
            dest >>= 2;
            buf[i + 2] = @truncate(dest >> 16);
            buf[i + 1] = @truncate(dest >> 8);
            buf[i] = @truncate(dest);
        }
        return i;
    }

    fn armthumb(s: *Stage, buf: []u8, encode: bool) usize {
        var i: usize = 0;
        while (i + 4 <= buf.len) : (i += 2) {
            if ((buf[i + 1] & 0xF8) != 0xF0 or (buf[i + 3] & 0xF8) != 0xF8) continue;
            var src: u32 = ((@as(u32, buf[i + 1]) & 7) << 19) | (@as(u32, buf[i]) << 11) | ((@as(u32, buf[i + 3]) & 7) << 8) | buf[i + 2];
            src <<= 1;
            const here = s.now_pos +% @as(u32, @intCast(i)) +% 4;
            var dest = if (encode) here +% src else src -% here;
            dest >>= 1;
            buf[i + 1] = 0xF0 | @as(u8, @truncate((dest >> 19) & 7));
            buf[i] = @truncate(dest >> 11);
            buf[i + 3] = 0xF8 | @as(u8, @truncate((dest >> 8) & 7));
            buf[i + 2] = @truncate(dest);
            i += 2;
        }
        return i;
    }

    fn ppc(s: *Stage, buf: []u8, encode: bool) usize {
        var i: usize = 0;
        while (i + 4 <= buf.len) : (i += 4) {
            if ((buf[i] >> 2) != 0x12 or (buf[i + 3] & 3) != 1) continue;
            const src: u32 = ((@as(u32, buf[i]) & 3) << 24) | (@as(u32, buf[i + 1]) << 16) | (@as(u32, buf[i + 2]) << 8) | (buf[i + 3] & ~@as(u8, 3));
            const here = s.now_pos +% @as(u32, @intCast(i));
            const dest = if (encode) here +% src else src -% here;
            buf[i] = 0x48 | @as(u8, @truncate((dest >> 24) & 3));
            buf[i + 1] = @truncate(dest >> 16);
            buf[i + 2] = @truncate(dest >> 8);
            buf[i + 3] &= 3;
            buf[i + 3] |= @as(u8, @truncate(dest));
        }
        return i;
    }

    fn ia64(s: *Stage, buf: []u8, encode: bool) usize {
        const branch_table = [32]u32{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0,
        };
        var i: usize = 0;
        while (i + 16 <= buf.len) : (i += 16) {
            const mask = branch_table[buf[i] & 0x1F];
            var bit_pos: u32 = 5;
            var slot: u5 = 0;
            while (slot < 3) : ({
                slot += 1;
                bit_pos += 41;
            }) {
                if (((mask >> slot) & 1) == 0) continue;
                const byte_pos: usize = bit_pos >> 3;
                const bit_res: u6 = @intCast(bit_pos & 7);
                var instruction: u64 = 0;
                for (0..6) |j| instruction += @as(u64, buf[i + j + byte_pos]) << @intCast(8 * j);
                var inst_norm = instruction >> bit_res;
                if (((inst_norm >> 37) & 0xF) == 0x5 and ((inst_norm >> 9) & 0x7) == 0) {
                    var src: u32 = @truncate((inst_norm >> 13) & 0xFFFFF);
                    src |= @as(u32, @truncate((inst_norm >> 36) & 1)) << 20;
                    src <<= 4;
                    const here = s.now_pos +% @as(u32, @intCast(i));
                    var dest = if (encode) here +% src else src -% here;
                    dest >>= 4;
                    inst_norm &= ~(@as(u64, 0x8FFFFF) << 13);
                    inst_norm |= @as(u64, dest & 0xFFFFF) << 13;
                    inst_norm |= @as(u64, dest & 0x100000) << (36 - 20);
                    instruction &= (@as(u64, 1) << bit_res) - 1;
                    instruction |= inst_norm << bit_res;
                    for (0..6) |j| buf[i + j + byte_pos] = @truncate(instruction >> @intCast(8 * j));
                }
            }
        }
        return i;
    }

    fn sparc(s: *Stage, buf: []u8, encode: bool) usize {
        var i: usize = 0;
        while (i + 4 <= buf.len) : (i += 4) {
            if (!((buf[i] == 0x40 and (buf[i + 1] & 0xC0) == 0x00) or (buf[i] == 0x7F and (buf[i + 1] & 0xC0) == 0xC0))) continue;
            var src = std.mem.readInt(u32, buf[i..][0..4], .big);
            src <<= 2;
            const here = s.now_pos +% @as(u32, @intCast(i));
            var dest = if (encode) here +% src else src -% here;
            dest >>= 2;
            dest = (((0 -% ((dest >> 22) & 1)) << 22) & 0x3FFFFFFF) | (dest & 0x3FFFFF) | 0x40000000;
            std.mem.writeInt(u32, buf[i..][0..4], dest, .big);
        }
        return i;
    }

    fn arm64(s: *Stage, buf: []u8, encode: bool) usize {
        var i: usize = 0;
        while (i + 4 <= buf.len) : (i += 4) {
            var pc = s.now_pos +% @as(u32, @intCast(i));
            var instr = std.mem.readInt(u32, buf[i..][0..4], .little);
            if ((instr >> 26) == 0x25) {
                const src = instr;
                pc >>= 2;
                if (!encode) pc = 0 -% pc;
                instr = 0x94000000 | ((src +% pc) & 0x03FFFFFF);
                std.mem.writeInt(u32, buf[i..][0..4], instr, .little);
            } else if ((instr & 0x9F000000) == 0x90000000) {
                const src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001FFFFC);
                if (((src +% 0x00020000) & 0x001C0000) != 0) continue;
                pc >>= 12;
                if (!encode) pc = 0 -% pc;
                const dest = src +% pc;
                instr &= 0x9000001F;
                instr |= (dest & 3) << 29;
                instr |= (dest & 0x0003FFFC) << 3;
                instr |= (0 -% (dest & 0x00020000)) & 0x00E00000;
                std.mem.writeInt(u32, buf[i..][0..4], instr, .little);
            }
        }
        return i;
    }
};

/// Bytes a stage may hold back between two calls (IA-64 bundles are 16).
const max_tail = 16;
/// Bytes converted per step.
pub const chunk = 64 * 1024;

/// A chain of filters over a stream, in the order the data flows through it:
/// for encoding the order of the block header, for decoding its reverse.
/// Not thread-safe; a `Chain` holds a 64 KiB work buffer plus the stage state.
pub const Chain = struct {
    n: usize,
    encode: bool,
    stage: [Filter.max_chain]Stage,
    tail: [Filter.max_chain][max_tail]u8,
    tail_len: [Filter.max_chain]u8,
    /// `work[offset..]` is where the caller puts `chunk` input bytes.
    work: [chunk + Filter.max_chain * max_tail]u8,

    /// Where `feed` expects its input.
    pub const offset = Filter.max_chain * max_tail;

    /// `filters` as listed in the block header (at most `Filter.max_chain`).
    /// The struct is large (about 70 KiB); allocate it.
    pub fn init(c: *Chain, filters: []const Filter, encode: bool) void {
        std.debug.assert(filters.len <= Filter.max_chain);
        c.n = filters.len;
        c.encode = encode;
        for (0..filters.len) |k| {
            const f = if (encode) filters[k] else filters[filters.len - 1 - k];
            c.stage[k] = Stage.init(f);
            c.tail_len[k] = 0;
        }
    }

    /// Convert the `n` bytes the caller wrote at `input()`; returns the
    /// converted bytes (valid until the next call). With `final` nothing is
    /// held back: bytes a stage cannot convert pass through unchanged.
    pub fn feed(c: *Chain, n: usize, final: bool) []u8 {
        var start: usize = offset;
        var len = n;
        for (0..c.n) |k| {
            const t: usize = c.tail_len[k];
            // Prepend the stage's held-back bytes.
            start -= t;
            @memcpy(c.work[start..][0..t], c.tail[k][0..t]);
            len += t;
            const done = c.stage[k].code(c.work[start..][0..len], c.encode);
            const rest = len - done;
            if (final) {
                c.tail_len[k] = 0;
            } else {
                @memcpy(c.tail[k][0..rest], c.work[start + done ..][0..rest]);
                c.tail_len[k] = @intCast(rest);
                len = done;
            }
        }
        return c.work[start..][0..len];
    }

    pub fn input(c: *Chain) []u8 {
        return c.work[offset..];
    }
};

fn roundTrip(f: []const Filter, data: []const u8, piece: usize) !void {
    const gpa = std.testing.allocator;
    const enc = try gpa.create(Chain);
    defer gpa.destroy(enc);
    const dec = try gpa.create(Chain);
    defer gpa.destroy(dec);
    enc.init(f, true);
    dec.init(f, false);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(gpa);
    var p: usize = 0;
    while (p < data.len) {
        const m = @min(piece, data.len - p);
        @memcpy(enc.input()[0..m], data[p..][0..m]);
        p += m;
        try encoded.appendSlice(gpa, enc.feed(m, false));
    }
    try encoded.appendSlice(gpa, enc.feed(0, true));
    try std.testing.expectEqual(data.len, encoded.items.len);
    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(gpa);
    p = 0;
    while (p < encoded.items.len) {
        const m = @min(piece, encoded.items.len - p);
        @memcpy(dec.input()[0..m], encoded.items[p..][0..m]);
        p += m;
        try decoded.appendSlice(gpa, dec.feed(m, false));
    }
    try decoded.appendSlice(gpa, dec.feed(0, true));
    try std.testing.expectEqualSlices(u8, data, decoded.items);
}

test "chains round-trip for any piece size, and the encoding does not depend on it" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    var data: [3000]u8 = undefined;
    r.bytes(&data);
    // Plant branch-looking bytes so every converter has something to rewrite.
    var i: usize = 0;
    while (i + 8 < data.len) : (i += 7 + r.uintLessThan(usize, 20)) {
        switch (r.uintLessThan(u8, 6)) {
            0 => data[i] = 0xE8,
            1 => data[i + 3] = 0xEB,
            2 => {
                data[i] = 0x48;
                data[i + 3] = 1;
            },
            3 => data[i + 3] = 0x94,
            4 => {
                data[i] = 0x40;
                data[i + 1] = 0x10;
            },
            else => data[i + 3] = 0xF8,
        }
        if (i % 3 == 0) {
            data[i + 4] = 0;
            data[i + 2] = 0xFF;
        }
    }
    const lists = [_][]const Filter{
        &.{.{ .x86 = .{} }},
        &.{.{ .x86 = .{ .start_offset = 0x1000 } }},
        &.{.{ .arm = .{} }},
        &.{.{ .armthumb = .{ .start_offset = 6 } }},
        &.{.{ .powerpc = .{} }},
        &.{.{ .ia64 = .{ .start_offset = 32 } }},
        &.{.{ .sparc = .{} }},
        &.{.{ .arm64 = .{ .start_offset = 64 } }},
        &.{.{ .delta = 1 }},
        &.{.{ .delta = 256 }},
        &.{ .{ .delta = 4 }, .{ .x86 = .{} } },
        &.{ .{ .arm64 = .{} }, .{ .delta = 7 }, .{ .sparc = .{} } },
    };
    for (lists) |l| {
        for ([_]usize{ 1, 3, 5, 64, 3000 }) |piece| try roundTrip(l, &data, piece);
    }
}

test "the encoding is independent of the piece size" {
    const gpa = std.testing.allocator;
    var data: [700]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(&data);
    for (0..100) |k| data[k * 7] = 0xE8;
    var outs: [2][700]u8 = undefined;
    for ([_]usize{ 1, 700 }, 0..) |piece, o| {
        const ch = try gpa.create(Chain);
        defer gpa.destroy(ch);
        ch.init(&.{.{ .x86 = .{} }}, true);
        var n: usize = 0;
        var p: usize = 0;
        while (p < data.len) {
            const m = @min(piece, data.len - p);
            @memcpy(ch.input()[0..m], data[p..][0..m]);
            p += m;
            const e = ch.feed(m, false);
            @memcpy(outs[o][n..][0..e.len], e);
            n += e.len;
        }
        const e = ch.feed(0, true);
        @memcpy(outs[o][n..][0..e.len], e);
    }
    try std.testing.expectEqualSlices(u8, &outs[0], &outs[1]);
}

test "property bytes round-trip and bad ones are refused" {
    var pb: [4]u8 = undefined;
    const f: Filter = .{ .arm64 = .{ .start_offset = 0x100 } };
    const n = f.props(&pb);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(f, Filter.fromProps(0x0A, pb[0..n]).?);
    try std.testing.expectEqual(@as(usize, 0), (Filter{ .x86 = .{} }).props(&pb));
    try std.testing.expectEqual(Filter{ .delta = 5 }, Filter.fromProps(0x03, &.{4}).?);
    try std.testing.expect(Filter.fromProps(0x03, &.{}) == null);
    try std.testing.expect(Filter.fromProps(0x04, &.{ 1, 2 }) == null);
    try std.testing.expect(Filter.fromProps(0x0A, &.{ 2, 0, 0, 0 }) == null); // arm64 offset not a multiple of 4
    try std.testing.expect(Filter.fromProps(0x08, &.{ 2, 0, 0, 0 }) != null);
    try std.testing.expect(Filter.fromProps(0x06, &.{ 8, 0, 0, 0 }) == null); // IA-64 offsets are multiples of 16
    try std.testing.expect(Filter.fromProps(0x0B, &.{}) == null); // RISC-V: not supported
    try std.testing.expect(!(Filter{ .delta = 0 }).valid());
    try std.testing.expect(!(Filter{ .delta = 257 }).valid());
}

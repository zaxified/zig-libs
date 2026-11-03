// SPDX-License-Identifier: MIT
//! HdrHistogram V2 interchange format: a `Histogram` to bytes the Java, C, Go
//! and Rust HdrHistogram tools read, and theirs back.
//!
//! Layout (big endian), from the published format description and checked
//! against HdrHistogram_c 0.11.10 and hdrhistogram-go (`tools/`):
//!
//!   plain      cookie 0x1c849313 (V2 | word size 8), payload length i32,
//!              normalizing index offset i32 (0), significant figures i32,
//!              lowest i64, highest i64, integer-to-double ratio f64 (1.0),
//!              then the payload: the counts slots up to the last non-empty
//!              one, each a ZigZag LEB128 (the 9th byte carries 8 bits);
//!              a run of empty slots is the negative count -run.
//!   compressed cookie 0x1c849314, length i32, then a zlib stream holding the
//!              plain form. (This encoder writes a Huffman-only deflate
//!              stream: valid for any inflater, and the payload is already
//!              run-length coded, so LZ matching gains little.)
//!
//! `decode` takes both, and treats the bytes as hostile: every length is
//! checked against the histogram the header describes, the counts array is
//! bounded by `DecodeOptions.max_counts` (default 4 Mi slots = 32 MiB, so a
//! forged `highest` cannot ask for the 50 MB widest histogram), inflation
//! stops at the declared payload length, and the totals are checked for
//! overflow. Not read: V0/V1 (old Java) cookies (`error.Unsupported`), a
//! non-zero normalizing index offset, the double-histogram ratio (ignored).

const std = @import("std");
const flate = std.compress.flate;
const Io = std.Io;
const Histogram = @import("root.zig").Histogram;

pub const plain_cookie: u32 = 0x1c849303;
pub const compressed_cookie: u32 = 0x1c849304;
const word_size: u32 = 0x10;
const header_len = 40;
const ratio_one_bits: u64 = 0x3FF0000000000000;

pub const DecodeError = error{
    /// Not a histogram: bad cookie, truncated or over-long, a count that
    /// does not fit, a corrupt zlib stream.
    BadFormat,
    /// A well-formed header this decoder does not read (V0/V1, offset != 0).
    Unsupported,
    /// The header asks for more than `DecodeOptions.max_counts` slots.
    TooLarge,
    /// The header's lowest/highest/sigfigs are not a legal configuration.
    InvalidConfig,
    OutOfMemory,
};
pub const EncodeError = Io.Writer.Error || error{
    /// A slot holds more than `maxInt(i64)` (the wire counts are signed).
    CountTooLarge,
    /// The compressed stream would not fit the format's i32 length.
    OutputTooLarge,
    OutOfMemory,
};

pub const DecodeOptions = struct {
    /// Most counts slots the decoded histogram may have.
    max_counts: usize = 1 << 22,
};

fn zigzag(v: i64) u64 {
    return @bitCast((v *% 2) ^ (v >> 63));
}

fn putVarint(buf: *[9]u8, signed: i64) usize {
    var v = zigzag(signed);
    for (0..8) |i| {
        if (v >> 7 == 0) {
            buf[i] = @intCast(v);
            return i + 1;
        }
        buf[i] = @intCast((v & 0x7f) | 0x80);
        v >>= 7;
    }
    buf[8] = @intCast(v); // the last 8 bits
    return 9;
}

/// null: truncated.
fn getVarint(data: []const u8, pos: *usize) ?i64 {
    var v: u64 = 0;
    for (0..9) |i| {
        if (pos.* >= data.len) return null;
        const b = data[pos.*];
        pos.* += 1;
        if (i == 8) {
            v |= @as(u64, b) << 56;
            break;
        }
        v |= @as(u64, b & 0x7f) << @intCast(7 * i);
        if (b & 0x80 == 0) break;
    }
    return @bitCast((v >> 1) ^ (0 -% (v & 1)));
}

/// Slots up to and including the last non-empty one.
fn usedSlots(h: *const Histogram) usize {
    var n = h.counts.len;
    while (n > 0 and h.counts[n - 1] == 0) n -= 1;
    return n;
}

/// Walk the payload: its length with `out == null`, else write it.
fn payload(h: *const Histogram, out: ?*Io.Writer) EncodeError!usize {
    const used = usedSlots(h);
    var total: usize = 0;
    var buf: [9]u8 = undefined;
    var i: usize = 0;
    while (i < used) {
        const c = h.counts[i];
        var n: usize = undefined;
        if (c == 0) {
            var z: usize = 0;
            while (i < used and h.counts[i] == 0) : (i += 1) z += 1;
            n = putVarint(&buf, -@as(i64, @intCast(z)));
        } else {
            if (c > std.math.maxInt(i64)) return error.CountTooLarge;
            n = putVarint(&buf, @intCast(c));
            i += 1;
        }
        if (out) |w| try w.writeAll(buf[0..n]);
        total += n;
    }
    return total;
}

/// The plain V2 encoding of `h` to `w`.
pub fn encode(h: *const Histogram, w: *Io.Writer) EncodeError!void {
    const len = try payload(h, null);
    try w.writeInt(u32, plain_cookie | word_size, .big);
    try w.writeInt(i32, @intCast(len), .big);
    try w.writeInt(i32, 0, .big);
    try w.writeInt(i32, h.sigfigs, .big);
    try w.writeInt(u64, h.lowest, .big);
    try w.writeInt(u64, h.highest, .big);
    try w.writeInt(u64, ratio_one_bits, .big);
    _ = try payload(h, w);
}

/// The compressed V2 encoding of `h` to `w` (cookie, length, zlib stream).
pub fn encodeCompressed(h: *const Histogram, gpa: std.mem.Allocator, w: *Io.Writer) EncodeError!void {
    var plain: Io.Writer.Allocating = try .initCapacity(gpa, header_len + 1024);
    defer plain.deinit();
    try encode(h, &plain.writer);
    try wrapZlib(plain.written(), gpa, w);
}

/// `cookie, length, zlib(plain)` to `w`.
fn wrapZlib(plain: []const u8, gpa: std.mem.Allocator, w: *Io.Writer) EncodeError!void {
    var packed_out: Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer packed_out.deinit();
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var huff = try flate.Compress.Huffman.init(&packed_out.writer, window, .zlib);
    try huff.writer.writeAll(plain);
    try huff.writer.flush();
    try huff.finish();
    const z = packed_out.written();
    try w.writeInt(u32, compressed_cookie | word_size, .big);
    try w.writeInt(i32, std.math.cast(i32, z.len) orelse return error.OutputTooLarge, .big);
    try w.writeAll(z);
}

const Header = struct {
    payload_len: usize,
    lowest: u64,
    highest: u64,
    sigfigs: u8,
};

fn parseHeader(hdr: *const [header_len]u8) DecodeError!Header {
    const be = std.mem.readInt;
    const cookie = be(u32, hdr[0..4], .big);
    const base = cookie & ~@as(u32, 0xf0);
    if (base != plain_cookie) {
        return switch (base) {
            0x1c849301, 0x1c849308 => error.Unsupported,
            else => error.BadFormat,
        };
    }
    const plen = be(i32, hdr[4..8], .big);
    const offset = be(i32, hdr[8..12], .big);
    const sig = be(i32, hdr[12..16], .big);
    const lowest = be(u64, hdr[16..24], .big);
    const highest = be(u64, hdr[24..32], .big);
    if (plen < 0) return error.BadFormat;
    if (offset != 0) return error.Unsupported;
    if (sig < 1 or sig > 5) return error.InvalidConfig;
    return .{ .payload_len = @intCast(plen), .lowest = lowest, .highest = highest, .sigfigs = @intCast(sig) };
}

/// Decode a plain or compressed V2 histogram. The result owns its counts
/// (`deinit` it with the same `gpa`). The wire carries counts only, so
/// `min()` and `max()` of the result are the bounds of the lowest and highest
/// non-empty counts slot (clamped to `lowest`/`highest`), not the exact
/// recorded extremes; every other query agrees with the encoded histogram.
pub fn decode(gpa: std.mem.Allocator, bytes: []const u8, opts: DecodeOptions) DecodeError!Histogram {
    if (bytes.len < 8) return error.BadFormat;
    const cookie = std.mem.readInt(u32, bytes[0..4], .big);
    const base = cookie & ~@as(u32, 0xf0);
    if (base == plain_cookie) {
        if (bytes.len < header_len) return error.BadFormat;
        const hd = try parseHeader(bytes[0..header_len]);
        if (bytes.len - header_len != hd.payload_len) return error.BadFormat;
        return build(gpa, hd, bytes[header_len..], opts);
    }
    if (base != compressed_cookie) {
        return switch (base) {
            0x1c849301, 0x1c849308, 0x1c849302, 0x1c849309 => error.Unsupported,
            else => error.BadFormat,
        };
    }
    const clen = std.mem.readInt(i32, bytes[4..8], .big);
    if (clen < 0 or @as(usize, @intCast(clen)) > bytes.len - 8) return error.BadFormat;
    var input: Io.Reader = .fixed(bytes[8..][0..@intCast(clen)]);
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var inf: flate.Decompress = .init(&input, .zlib, window);
    var hdr: [header_len]u8 = undefined;
    inf.reader.readSliceAll(&hdr) catch return error.BadFormat;
    const hd = try parseHeader(&hdr);
    // Inflate no more than the header declares, and only after the
    // configuration it describes has passed the memory bound.
    const slots = Histogram.countsLen(.{ .lowest = hd.lowest, .highest = hd.highest, .sigfigs = hd.sigfigs }) catch return error.InvalidConfig;
    if (slots > opts.max_counts) return error.TooLarge;
    if (hd.payload_len > slots * 9) return error.BadFormat;
    // Deflate expands at most ~1032:1 (a 258-byte match in under 2 bits):
    // a payload longer than the stream could possibly inflate to is forged,
    // and is refused before `payload_len` bytes are allocated for it.
    if (hd.payload_len > @as(usize, @intCast(clen)) *| 1032 +| 64) return error.BadFormat;
    const body = try gpa.alloc(u8, hd.payload_len);
    defer gpa.free(body);
    inf.reader.readSliceAll(body) catch return error.BadFormat;
    return build(gpa, hd, body, opts);
}

fn build(gpa: std.mem.Allocator, hd: Header, body: []const u8, opts: DecodeOptions) DecodeError!Histogram {
    const cfg: @import("root.zig").HistogramOptions = .{ .lowest = hd.lowest, .highest = hd.highest, .sigfigs = hd.sigfigs };
    const slots = Histogram.countsLen(cfg) catch return error.InvalidConfig;
    if (slots > opts.max_counts) return error.TooLarge;
    if (hd.payload_len > slots * 9) return error.BadFormat;
    var h = Histogram.init(gpa, cfg) catch |e| return e;
    errdefer h.deinit();
    var pos: usize = 0;
    var idx: usize = 0;
    var total: u64 = 0;
    var first: ?usize = null;
    var last: usize = 0;
    while (pos < body.len) {
        const v = getVarint(body, &pos) orelse return error.BadFormat;
        if (v < 0) {
            const run = std.math.cast(usize, -%v) orelse return error.BadFormat;
            if (v == std.math.minInt(i64) or run > h.counts.len - idx) return error.BadFormat;
            idx += run;
        } else {
            if (idx >= h.counts.len) return error.BadFormat;
            const c: u64 = @intCast(v);
            h.counts[idx] = c;
            if (c != 0) {
                total = std.math.add(u64, total, c) catch return error.BadFormat;
                if (first == null) first = idx;
                last = idx;
            }
            idx += 1;
        }
    }
    h.total_count = total;
    if (first) |f| {
        h.min_value = @max(h.slotLowest(f), h.lowest);
        h.max_value = @min(h.slotHighest(last), h.highest);
    }
    return h;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn sample(gpa: std.mem.Allocator) !Histogram {
    var h = try Histogram.init(gpa, .{ .highest = 3_600_000_000, .sigfigs = 3 });
    var x: u64 = 88172645463325252;
    for (0..5000) |_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        h.record(1 + x % 5_000_000);
    }
    h.record(3_000_000_000);
    h.recordCount(7, 1 << 40);
    return h;
}

fn expectSame(a: *const Histogram, b: *const Histogram) !void {
    try testing.expectEqualSlices(u64, a.counts, b.counts);
    try testing.expectEqual(a.total_count, b.total_count);
    try testing.expectEqual(a.valueAtPercentile(99), b.valueAtPercentile(99));
    try testing.expectEqual(a.lowestEquivalent(a.min()), b.lowestEquivalent(b.min()));
    try testing.expectEqual(a.highestEquivalent(a.max()), b.highestEquivalent(b.max()));
}

test "plain and compressed round trip" {
    var h = try sample(testing.allocator);
    defer h.deinit();
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try encode(&h, &aw.writer);
    var d = try decode(testing.allocator, aw.written(), .{});
    defer d.deinit();
    try expectSame(&h, &d);

    var cw: Io.Writer.Allocating = .init(testing.allocator);
    defer cw.deinit();
    try encodeCompressed(&h, testing.allocator, &cw.writer);
    try testing.expect(cw.written().len < aw.written().len);
    var d2 = try decode(testing.allocator, cw.written(), .{});
    defer d2.deinit();
    try expectSame(&h, &d2);
}

test "empty histogram round trips; varint edges" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1000 });
    defer h.deinit();
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try encode(&h, &aw.writer);
    try testing.expectEqual(@as(usize, header_len), aw.written().len);
    var d = try decode(testing.allocator, aw.written(), .{});
    defer d.deinit();
    try testing.expectEqual(@as(u64, 0), d.total_count);

    var buf: [9]u8 = undefined;
    for ([_]i64{ 0, 1, -1, 63, -64, 64, 1 << 40, -(1 << 40), std.math.maxInt(i64), std.math.minInt(i64) + 1 }) |v| {
        const n = putVarint(&buf, v);
        var pos: usize = 0;
        try testing.expectEqual(v, getVarint(buf[0..n], &pos).?);
        try testing.expectEqual(n, pos);
    }
    // Known bytes: ZigZag(1) = 2, ZigZag(-1) = 1, ZigZag(64) = 128 -> 0x80 0x01.
    try testing.expectEqual(@as(usize, 2), putVarint(&buf, 64));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, buf[0..2]);
}

test "hostile input: errors, never a panic, bounded memory" {
    var h = try sample(testing.allocator);
    defer h.deinit();
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try encode(&h, &aw.writer);
    const good = aw.written();
    // Every truncation fails cleanly.
    for (0..good.len) |n| try testing.expectError(error.BadFormat, decode(testing.allocator, good[0..n], .{}));
    // A forged huge configuration is refused before it is allocated.
    const forged = try testing.allocator.dupe(u8, good);
    defer testing.allocator.free(forged);
    std.mem.writeInt(u64, forged[24..32], std.math.maxInt(u64), .big);
    std.mem.writeInt(i32, forged[12..16], 5, .big);
    try testing.expectError(error.TooLarge, decode(testing.allocator, forged, .{}));
    std.mem.writeInt(i32, forged[12..16], 9, .big);
    try testing.expectError(error.InvalidConfig, decode(testing.allocator, forged, .{}));
    // Old format and a bad cookie.
    std.mem.writeInt(u32, forged[0..4], 0x1c849301, .big);
    try testing.expectError(error.Unsupported, decode(testing.allocator, forged, .{}));
    std.mem.writeInt(u32, forged[0..4], 0xdeadbeef, .big);
    try testing.expectError(error.BadFormat, decode(testing.allocator, forged, .{}));
}

test "a run longer than the array, an overflowing total, and a count past i64" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1000 });
    defer h.deinit();
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try encode(&h, &aw.writer);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(testing.allocator);
    try bytes.appendSlice(testing.allocator, aw.written());
    var buf: [9]u8 = undefined;
    // total overflow: two slots of maxInt(i64) .. three of them exceed u64.
    for (0..3) |_| try bytes.appendSlice(testing.allocator, buf[0..putVarint(&buf, std.math.maxInt(i64))]);
    std.mem.writeInt(i32, bytes.items[4..8], @intCast(bytes.items.len - header_len), .big);
    try testing.expectError(error.BadFormat, decode(testing.allocator, bytes.items, .{}));
    // a run far past the end
    bytes.shrinkRetainingCapacity(header_len);
    try bytes.appendSlice(testing.allocator, buf[0..putVarint(&buf, -(1 << 40))]);
    std.mem.writeInt(i32, bytes.items[4..8], @intCast(bytes.items.len - header_len), .big);
    try testing.expectError(error.BadFormat, decode(testing.allocator, bytes.items, .{}));
    // encoding a slot above i64 is refused, not wrapped
    h.recordCount(5, std.math.maxInt(u64));
    var aw2: Io.Writer.Allocating = .init(testing.allocator);
    defer aw2.deinit();
    try testing.expectError(error.CountTooLarge, encode(&h, &aw2.writer));
}

test "a forged payload length is refused before it is allocated (compressed)" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 3_600_000_000_000, .sigfigs = 3 });
    defer h.deinit();
    h.record(5);
    var aw: Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try encode(&h, &aw.writer);
    const plain = try testing.allocator.dupe(u8, aw.written());
    defer testing.allocator.free(plain);
    const slots = h.counts.len;
    std.mem.writeInt(i32, plain[4..8], @intCast(slots * 9), .big); // within the slots bound, far past the stream
    var cw: Io.Writer.Allocating = .init(testing.allocator);
    defer cw.deinit();
    try wrapZlib(plain, testing.allocator, &cw.writer);
    try testing.expect(cw.written().len < 200);
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 << 20 });
    try testing.expectError(error.BadFormat, decode(failing.allocator(), cw.written(), .{}));
    // only the 64 KiB window was ever asked for
    try testing.expect(failing.allocated_bytes <= flate.max_window_len + 1024);
}

test "countsLen equals what init allocates" {
    for ([_]struct { l: u64, hi: u64, s: u8 }{
        .{ .l = 1, .hi = 1000, .s = 1 },
        .{ .l = 1, .hi = 3_600_000_000, .s = 3 },
        .{ .l = 1000, .hi = 1 << 50, .s = 2 },
        .{ .l = 7, .hi = 1 << 20, .s = 5 },
    }) |c| {
        var h = try Histogram.init(testing.allocator, .{ .lowest = c.l, .highest = c.hi, .sigfigs = c.s });
        defer h.deinit();
        try testing.expectEqual(h.counts.len, try Histogram.countsLen(.{ .lowest = c.l, .highest = c.hi, .sigfigs = c.s }));
    }
    try testing.expectError(error.InvalidConfig, Histogram.countsLen(.{ .highest = 1, .sigfigs = 3 }));
}

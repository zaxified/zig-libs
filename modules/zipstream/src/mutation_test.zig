// SPDX-License-Identifier: MIT
//! Killing tests of the 2026-11-25 delta mutation run (Deflate64 decoder, raw copy / append / verify,
//! alignment padding, caller-extra limits).
const std = @import("std");
const testing = std.testing;
const zs = @import("root.zig");
const d64 = @import("deflate64.zig");

// ── a tiny Deflate bit writer ───────────────────────────────────────────────

const Bits = std.ArrayList(u1);

fn put(a: std.mem.Allocator, b: *Bits, v: u32, n: u6) !void {
    for (0..n) |i| try b.append(a, @intCast((v >> @intCast(i)) & 1));
}

/// A Huffman code goes out most significant bit first.
fn putCode(a: std.mem.Allocator, b: *Bits, code: u32, n: u6) !void {
    var i: u6 = n;
    while (i > 0) {
        i -= 1;
        try b.append(a, @intCast((code >> @intCast(i)) & 1));
    }
}

fn canonical(lens: []const u8, codes: []u16) void {
    var count: [16]u16 = @splat(0);
    for (lens) |l| count[l] += 1;
    count[0] = 0;
    var next: [16]u16 = @splat(0);
    var code: u16 = 0;
    for (1..16) |l| {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    for (lens, 0..) |l, i| {
        if (l == 0) continue;
        codes[i] = next[l];
        next[l] += 1;
    }
}

fn packBits(a: std.mem.Allocator, b: []const u1) ![]u8 {
    const out = try a.alloc(u8, (b.len + 7) / 8);
    @memset(out, 0);
    for (b, 0..) |bit, i| out[i / 8] |= @as(u8, bit) << @intCast(i % 8);
    return out;
}

const clen_order = [_]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

/// The header of one dynamic block (final), the code lengths written one symbol each, except the last
/// `tail_run` distance lengths (zeros), which go out as one repeat symbol 18.
fn dynHeader(a: std.mem.Allocator, b: *Bits, lit: []const u8, dist: []const u8, cl: [19]u8, tail_run: usize) !void {
    try put(a, b, 1, 1);
    try put(a, b, 2, 2);
    try put(a, b, @intCast(lit.len - 257), 5);
    try put(a, b, @intCast(dist.len - 1), 5);
    var ncode: usize = 4;
    for (clen_order, 0..) |s, pos| if (cl[s] != 0 and pos + 1 > ncode) {
        ncode = pos + 1;
    };
    try put(a, b, @intCast(ncode - 4), 4);
    for (clen_order[0..ncode]) |s| try put(a, b, cl[s], 3);
    var cl_codes: [19]u16 = @splat(0);
    canonical(&cl, &cl_codes);
    const total = lit.len + dist.len;
    var i: usize = 0;
    while (i < total) {
        if (tail_run != 0 and i == total - tail_run) {
            try putCode(a, b, cl_codes[18], @intCast(cl[18]));
            try put(a, b, @intCast(tail_run - 11), 7);
            break;
        }
        const l = if (i < lit.len) lit[i] else dist[i - lit.len];
        try putCode(a, b, cl_codes[l], @intCast(cl[l]));
        i += 1;
    }
}

const Decoded = struct { out: []u8, err: ?d64.DecodeError };

fn decode(a: std.mem.Allocator, bytes: []const u8) !Decoded {
    var in: std.Io.Reader = .fixed(bytes);
    const st = try a.create(d64.Inflate);
    defer a.destroy(st);
    st.init(&in);
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    _ = st.reader.streamRemaining(&out.writer) catch {};
    return .{ .out = try a.dupe(u8, out.written()), .err = st.err };
}

test "mutation 2026-11-25: a stored block that ends the input exactly decodes (no spurious Truncated)" {
    const a = testing.allocator;
    const d = try decode(a, &.{ 0x01, 0x00, 0x00, 0xff, 0xff });
    defer a.free(d.out);
    try testing.expectEqual(@as(?d64.DecodeError, null), d.err);
    try testing.expectEqual(@as(usize, 0), d.out.len);
}

test "mutation 2026-11-25: a final stored block whose NLEN is exactly the last two bytes of the input" {
    const a = testing.allocator;
    const d = try decode(a, &.{ 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff });
    defer a.free(d.out);
    try testing.expectEqual(@as(?d64.DecodeError, null), d.err);
    try testing.expectEqual(@as(usize, 0), d.out.len);
}

test "mutation 2026-11-25: a dynamic block with no distance code (the lengths end on a repeat), one with a single distance code" {
    const a = testing.allocator;
    var bits: Bits = .empty;
    defer bits.deinit(a);
    // literals only: 'a' and the end code, one bit each; eleven distance lengths, all zero, as ONE repeat that ends the table
    var lit: [257]u8 = @splat(0);
    lit[97] = 1;
    lit[256] = 1;
    const dist0: [11]u8 = @splat(0);
    var cl: [19]u8 = @splat(0);
    cl[18] = 1;
    cl[0] = 2;
    cl[1] = 2;
    try dynHeader(a, &bits, &lit, &dist0, cl, 11);
    try putCode(a, &bits, 0, 1);
    try putCode(a, &bits, 0, 1);
    try putCode(a, &bits, 1, 1);
    const bytes = try packBits(a, bits.items);
    defer a.free(bytes);
    const d = try decode(a, bytes);
    defer a.free(d.out);
    try testing.expectEqual(@as(?d64.DecodeError, null), d.err);
    try testing.expectEqualStrings("aa", d.out);

    // one distance code (an incomplete set of one code is allowed): 'a', then a match of 3 at distance 1
    bits.clearRetainingCapacity();
    var lit2: [258]u8 = @splat(0);
    lit2[97] = 2;
    lit2[256] = 2;
    lit2[257] = 1;
    const dist1 = [_]u8{1};
    var cl2: [19]u8 = @splat(0);
    cl2[0] = 1;
    cl2[1] = 2;
    cl2[2] = 2;
    try dynHeader(a, &bits, &lit2, &dist1, cl2, 0);
    var codes: [258]u16 = @splat(0);
    canonical(&lit2, &codes);
    try putCode(a, &bits, codes[97], 2);
    try putCode(a, &bits, codes[257], 1);
    try putCode(a, &bits, 0, 1);
    try putCode(a, &bits, codes[256], 2);
    const bytes2 = try packBits(a, bits.items);
    defer a.free(bytes2);
    const d2 = try decode(a, bytes2);
    defer a.free(d2.out);
    try testing.expectEqual(@as(?d64.DecodeError, null), d2.err);
    try testing.expectEqualStrings("aaaa", d2.out);
}

test "mutation 2026-11-25: dynamic table limits: 287 length codes is BadTable, a table without an end code is NoEndCode" {
    const a = testing.allocator;
    var bits: Bits = .empty;
    defer bits.deinit(a);
    try put(a, &bits, 1, 1);
    try put(a, &bits, 2, 2);
    try put(a, &bits, 30, 5); // 257 + 30 = 287 length codes
    try put(a, &bits, 0, 5);
    try put(a, &bits, 0, 4);
    const bytes = try packBits(a, bits.items);
    defer a.free(bytes);
    const d = try decode(a, bytes);
    defer a.free(d.out);
    try testing.expectEqual(@as(?d64.DecodeError, error.BadTable), d.err);

    bits.clearRetainingCapacity();
    var lit: [257]u8 = @splat(0);
    lit[97] = 1;
    lit[98] = 1;
    const dist = [_]u8{0};
    var cl: [19]u8 = @splat(0);
    cl[0] = 1;
    cl[1] = 1;
    try dynHeader(a, &bits, &lit, &dist, cl, 0);
    try put(a, &bits, 0, 8);
    const bytes2 = try packBits(a, bits.items);
    defer a.free(bytes2);
    const d2 = try decode(a, bytes2);
    defer a.free(d2.out);
    try testing.expectEqual(@as(?d64.DecodeError, error.NoEndCode), d2.err);
}

test "mutation 2026-11-25: fixed block: length symbol 286 is BadSymbol, symbol 285 is 3 + 16 extra bits (Deflate64)" {
    const a = testing.allocator;
    var bits: Bits = .empty;
    defer bits.deinit(a);
    try put(a, &bits, 1, 1);
    try put(a, &bits, 1, 2);
    try putCode(a, &bits, 0xc0 + (286 - 280), 8);
    const bytes = try packBits(a, bits.items);
    defer a.free(bytes);
    const d = try decode(a, bytes);
    defer a.free(d.out);
    try testing.expectEqual(@as(?d64.DecodeError, error.BadSymbol), d.err);

    bits.clearRetainingCapacity();
    try put(a, &bits, 1, 1);
    try put(a, &bits, 1, 2);
    try putCode(a, &bits, 0x30 + 'a', 8);
    try putCode(a, &bits, 0xc0 + (285 - 280), 8);
    try put(a, &bits, 1000, 16); // length 3 + 1000
    try putCode(a, &bits, 0, 5); // distance 1
    try putCode(a, &bits, 0, 7); // end of block
    const bytes2 = try packBits(a, bits.items);
    defer a.free(bytes2);
    const d2 = try decode(a, bytes2);
    defer a.free(d2.out);
    try testing.expectEqual(@as(?d64.DecodeError, null), d2.err);
    try testing.expectEqual(@as(usize, 1 + 1003), d2.out.len);
    try testing.expectEqual(@as(usize, 1004), std.mem.count(u8, d2.out, "a"));
}

// ── ArchiveWriter / Archive ─────────────────────────────────────────────────

fn rawEntry(name: []const u8, data: []const u8) zs.Entry {
    return .{ .name = name, .compression = .store, .compressed_size = data.len, .uncompressed_size = data.len, .file_offset = 0, .crc32 = 0x12345678 };
}

fn addRawBytes(a: std.mem.Allocator, out: *std.Io.Writer.Allocating, e: *const zs.Entry, data: []const u8) !void {
    var zw = zs.ArchiveWriter.init(a, &out.writer);
    defer zw.deinit();
    var r: std.Io.Reader = .fixed(data);
    try zw.addRaw(e, &r);
}

fn rawLen(a: std.mem.Allocator, e: *const zs.Entry, data: []const u8) !usize {
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try addRawBytes(a, &out, e, data);
    return out.written().len;
}

fn finishRaw(a: std.mem.Allocator, out: *std.Io.Writer.Allocating, e: *const zs.Entry, data: []const u8) !void {
    var zw = zs.ArchiveWriter.init(a, &out.writer);
    defer zw.deinit();
    var r: std.Io.Reader = .fixed(data);
    try zw.addRaw(e, &r);
    try zw.finish();
}

fn openArchive(a: std.mem.Allocator, ms: *zs.MemorySource, bytes: []const u8) !zs.Archive {
    ms.* = .{ .bytes = bytes };
    var ar: zs.Archive = undefined;
    try ar.initSource(a, ms.source(), .{});
    return ar;
}

test "mutation 2026-11-25: addRaw keeps AE-1 (version and CRC), a >4 GiB size makes zip64 sizes and a local zip64 extra" {
    const a = testing.allocator;
    var e = rawEntry("f", "01234567890123456789");
    e.compression = @fromBackingInt(@intCast(99));
    e.encrypted = true;
    e.flags = 1;
    e.aes = .{ .version = 1, .strength = .aes256, .method = 0 };
    e.crc32 = 0xdeadbeef;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try finishRaw(a, &out, &e, "01234567890123456789");
    var ms: zs.MemorySource = undefined;
    var ar = try openArchive(a, &ms, out.written());
    defer ar.deinit();
    try testing.expectEqual(@as(u16, 1), ar.entries.items[0].aes.?.version);
    try testing.expectEqual(@as(u32, 0xdeadbeef), ar.entries.items[0].crc32);

    var big = rawEntry("g", "12345");
    big.uncompressed_size = 1 << 33;
    var out2: std.Io.Writer.Allocating = .init(a);
    defer out2.deinit();
    try finishRaw(a, &out2, &big, "12345");
    var ms2: zs.MemorySource = undefined;
    var ar2 = try openArchive(a, &ms2, out2.written());
    defer ar2.deinit();
    try testing.expectEqual(@as(u64, 1 << 33), ar2.entries.items[0].uncompressed_size);
    // the local header carries the zip64 extra (extra length at offset 28)
    try testing.expectEqual(@as(u16, 20), std.mem.readInt(u16, out2.written()[28..30], .little));
}

test "mutation 2026-11-25: addRaw without zip64 refuses an offset past 4 GiB" {
    const a = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    var zw = zs.ArchiveWriter.init(a, &out.writer);
    defer zw.deinit();
    zw.allow_zip64 = false;
    zw.offset = (1 << 32) + 1;
    const e = rawEntry("f", "abc");
    var r: std.Io.Reader = .fixed("abc");
    try testing.expectError(error.ZipWriteTooLarge, zw.addRaw(&e, &r));
}

test "mutation 2026-11-25: addRaw streams a data descriptor only for a legacy-encrypted entry that sets the descriptor flag" {
    const a = testing.allocator;
    const data = "abcd";
    var aes = rawEntry("f", data);
    aes.encrypted = true;
    aes.flags = 1 | 8;
    aes.aes = .{ .version = 2, .strength = .aes128, .method = 0 };
    var aes_nodesc = aes;
    aes_nodesc.flags = 1;
    try testing.expectEqual(try rawLen(a, &aes_nodesc, data), try rawLen(a, &aes, data));
    var legacy_nodesc = rawEntry("f", data);
    legacy_nodesc.encrypted = true;
    legacy_nodesc.flags = 1;
    const plain = rawEntry("f", data);
    try testing.expectEqual(try rawLen(a, &plain, data), try rawLen(a, &legacy_nodesc, data));
    var legacy = legacy_nodesc;
    legacy.flags = 1 | 8;
    try testing.expectEqual(try rawLen(a, &plain, data) + 16, try rawLen(a, &legacy, data));
    var big = legacy;
    big.uncompressed_size = 1 << 33;
    var big_plain = plain;
    big_plain.uncompressed_size = 1 << 33;
    try testing.expectEqual(try rawLen(a, &big_plain, data) + 24, try rawLen(a, &big, data));
}

test "mutation 2026-11-25: addRaw writes the entry's own DOS stamp, attributes and masked flags" {
    const a = testing.allocator;
    const data = "abc";
    // time 0 with a nonzero date is a stamp, not "no stamp"
    var e1 = rawEntry("a", data);
    e1.dos_date = 0x5a21;
    // a stamp is not overridden by the mtime
    var e2 = rawEntry("b", data);
    e2.dos_time = 0x6000;
    e2.dos_date = 0x5a21;
    e2.mtime = 1_700_000_000;
    // host byte alone is an attribute set
    var e3 = rawEntry("c", data);
    e3.version_made_by = (10 << 8) | 20;
    // the descriptor flag is the layout's, not the source's
    var e4 = rawEntry("d", data);
    e4.flags = 8;
    // external attributes alone are an attribute set too
    var e5 = rawEntry("e", data);
    e5.external_attributes = 0o100644 << 16;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    {
        var zw = zs.ArchiveWriter.init(a, &out.writer);
        defer zw.deinit();
        for ([_]*const zs.Entry{ &e1, &e2, &e3, &e4, &e5 }) |e| {
            var r: std.Io.Reader = .fixed(data);
            try zw.addRaw(e, &r);
        }
        try zw.finish();
    }
    var ms: zs.MemorySource = undefined;
    var ar = try openArchive(a, &ms, out.written());
    defer ar.deinit();
    const es = ar.entries.items;
    try testing.expectEqual(@as(u16, 0x5a21), es[0].dos_date);
    try testing.expectEqual(@as(u16, 0x5a21), es[1].dos_date);
    try testing.expect(es[1].mtime.? != 1_700_000_000);
    try testing.expectEqual(@as(u16, 10), es[2].version_made_by >> 8);
    try testing.expectEqual(@as(u16, 0), es[3].flags & 8);
    try testing.expectEqual(@as(u32, 0o100644 << 16), es[4].external_attributes);
    // a writer-made stamp is readable back
    var out2: std.Io.Writer.Allocating = .init(a);
    defer out2.deinit();
    {
        var zw = zs.ArchiveWriter.init(a, &out2.writer);
        defer zw.deinit();
        try zw.addEntry("t", "x", .{ .mtime = 1_700_000_001 });
        try zw.finish();
    }
    var ms2: zs.MemorySource = undefined;
    var ar2 = try openArchive(a, &ms2, out2.written());
    defer ar2.deinit();
    try testing.expectEqual(zs.DosDateTime.fromUnix(1_700_000_001).date, ar2.entries.items[0].dos_date);
}

test "mutation 2026-11-25: addRaw copes with a short UT record and takes caller extra up to the exact limit" {
    const a = testing.allocator;
    const e = blk: {
        var x = rawEntry("f", "abc");
        x.extra = &.{ 0x55, 0x54, 0x04, 0x00, 0x01, 0, 0, 0 };
        break :blk x;
    };
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try addRawBytes(a, &out, &e, "abc");
    // the largest caller extra addEntry takes (central_own_extra_max = 48): one record of that length
    const max = 65535 - 48;
    const rec = try a.alloc(u8, max);
    defer a.free(rec);
    @memset(rec, 0);
    std.mem.writeInt(u16, rec[0..2], 0x1234, .little);
    std.mem.writeInt(u16, rec[2..4], max - 4, .little);
    var out2: std.Io.Writer.Allocating = .init(a);
    defer out2.deinit();
    {
        var zw = zs.ArchiveWriter.init(a, &out2.writer);
        defer zw.deinit();
        try zw.addEntry("x", "x", .{ .extra = rec });
    }
    var x2 = rawEntry("f", "abc");
    x2.extra = rec;
    var out3: std.Io.Writer.Allocating = .init(a);
    defer out3.deinit();
    try addRawBytes(a, &out3, &x2, "abc");
}

fn nameOf(comptime n: usize) [n]u8 {
    return @splat('n');
}

test "mutation 2026-11-25: alignment padding is skipped for AES, and fills the extra field up to exactly 65535" {
    const a = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    {
        var zw = zs.ArchiveWriter.init(a, &out.writer);
        defer zw.deinit();
        try zw.addEntry("secret", "0123456789", .{ .method = .store, .align_stored = 4, .encryption = .{ .password = "pw", .salt = "0123456789abcdef"[0..16] } });
        try zw.finish();
    }
    const b = out.written();
    const nl = std.mem.readInt(u16, b[26..28], .little);
    const xl = std.mem.readInt(u16, b[28..30], .little);
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, b[30 + nl ..][0..xl], &.{ 0x35, 0xd9 }));

    // name 65505 + a 4-byte caller record + pad 65531 = 65535 octets of extra
    const name = nameOf(65505);
    var out2: std.Io.Writer.Allocating = .init(a);
    defer out2.deinit();
    {
        var zw = zs.ArchiveWriter.init(a, &out2.writer);
        defer zw.deinit();
        try zw.addEntry(&name, "x", .{ .method = .store, .align_stored = 65535, .extra = &.{ 0x34, 0x12, 0, 0 } });
        try zw.finish();
    }
    try testing.expectEqual(@as(u16, 65535), std.mem.readInt(u16, out2.written()[28..30], .little));
}

// ── forged archives: openRaw, verify, append ────────────────────────────────

fn threeFiles(a: std.mem.Allocator, out: *std.Io.Writer.Allocating, n: usize) !void {
    var zw = zs.ArchiveWriter.init(a, &out.writer);
    defer zw.deinit();
    const names = [_][]const u8{ "a", "b", "c" };
    for (names[0..n]) |nm| try zw.addEntry(nm, "0123456789", .{ .method = .store });
    try zw.finish();
}

/// Point the central directory record `i` at local header offset `off`.
fn patchOffset(bytes: []u8, i: usize, off: u32) void {
    var p: usize = std.mem.readInt(u32, bytes[bytes.len - 22 + 16 ..][0..4], .little);
    for (0..i) |_| p += 46 + std.mem.readInt(u16, bytes[p + 28 ..][0..2], .little) + std.mem.readInt(u16, bytes[p + 30 ..][0..2], .little) + std.mem.readInt(u16, bytes[p + 32 ..][0..2], .little);
    std.mem.writeInt(u32, bytes[p + 42 ..][0..4], off, .little);
}

test "mutation 2026-11-25: openRaw refuses a bad signature, a size past the source; its data may end exactly at the source end" {
    const a = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try threeFiles(a, &out, 2);
    var ms: zs.MemorySource = undefined;
    var ar = try openArchive(a, &ms, out.written());
    defer ar.deinit();
    var rr: zs.RawReader = undefined;
    var bad = ar.entries.items[0];
    bad.file_offset += 1;
    try testing.expectError(error.ZipBadFileOffset, ar.openRaw(&rr, &bad));
    // a position inside zero bytes: no signature, but a plausible header; only the signature check refuses it
    var zout: std.Io.Writer.Allocating = .init(a);
    defer zout.deinit();
    {
        var zw = zs.ArchiveWriter.init(a, &zout.writer);
        defer zw.deinit();
        const zeros: [100]u8 = @splat(0);
        try zw.addEntry("z", &zeros, .{ .method = .store });
        try zw.finish();
    }
    var zms: zs.MemorySource = undefined;
    var zar = try openArchive(a, &zms, zout.written());
    defer zar.deinit();
    var inside = zar.entries.items[0];
    inside.file_offset += 40;
    try testing.expectError(error.ZipBadFileOffset, zar.openRaw(&rr, &inside));
    var huge = ar.entries.items[0];
    huge.compressed_size = 1 << 40;
    try testing.expectError(error.ZipBadFileOffset, ar.openRaw(&rr, &huge));
    // an empty entry whose data starts exactly at the end of the source
    var empty = ar.entries.items[0];
    empty.compressed_size = 0;
    const nl = std.mem.readInt(u16, out.written()[26..28], .little);
    const xl = std.mem.readInt(u16, out.written()[28..30], .little);
    ar.source.size = empty.file_offset + 30 + nl + xl;
    try ar.openRaw(&rr, &empty);
}

test "mutation 2026-11-25: verify reports overlaps (two entries, the lowest index, one octet inside), a bad offset, and an auth failure" {
    const a = testing.allocator;
    // two entries, the second at the first's offset
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try threeFiles(a, &out, 2);
    const bytes = try a.dupe(u8, out.written());
    defer a.free(bytes);
    patchOffset(bytes, 1, 0);
    var ms: zs.MemorySource = undefined;
    var ar = try openArchive(a, &ms, bytes);
    try testing.expectEqual(zs.Archive.Problem.Kind.overlap, (try ar.verify(.{})).?.kind);
    ar.deinit();
    // three at one offset: the lowest index that overlaps is reported
    var out3: std.Io.Writer.Allocating = .init(a);
    defer out3.deinit();
    try threeFiles(a, &out3, 3);
    const b3 = try a.dupe(u8, out3.written());
    defer a.free(b3);
    patchOffset(b3, 1, 0);
    patchOffset(b3, 2, 0);
    var ms3: zs.MemorySource = undefined;
    var ar3 = try openArchive(a, &ms3, b3);
    defer ar3.deinit();
    const p3 = (try ar3.verify(.{})).?;
    try testing.expectEqual(zs.Archive.Problem.Kind.overlap, p3.kind);
    try testing.expectEqual(@as(*const zs.Entry, &ar3.entries.items[1]), p3.entry);
    // the second starts one octet before the first's data ends (local header 30 + name + data)
    const b4 = try a.dupe(u8, out.written());
    defer a.free(b4);
    const first = (try openArchive(a, &ms, out.written()));
    var f = first;
    const e0 = f.entries.items[0];
    f.deinit();
    patchOffset(b4, 1, @intCast(e0.file_offset + 29 + e0.compressed_size));
    var ms4: zs.MemorySource = undefined;
    var ar4 = try openArchive(a, &ms4, b4);
    defer ar4.deinit();
    try testing.expectEqual(zs.Archive.Problem.Kind.overlap, (try ar4.verify(.{})).?.kind);
    // a bad local header offset, overlap check off
    const b5 = try a.dupe(u8, out.written());
    defer a.free(b5);
    patchOffset(b5, 1, @intCast(e0.file_offset + 3));
    var ms5: zs.MemorySource = undefined;
    var ar5 = try openArchive(a, &ms5, b5);
    defer ar5.deinit();
    try testing.expectEqual(zs.Archive.Problem.Kind.bad_offset, (try ar5.verify(.{ .check_overlap = false })).?.kind);
    // an AES entry with a damaged byte
    var out6: std.Io.Writer.Allocating = .init(a);
    defer out6.deinit();
    {
        var zw = zs.ArchiveWriter.init(a, &out6.writer);
        defer zw.deinit();
        try zw.addEntry("s", "0123456789abcdef", .{ .method = .store, .encryption = .{ .password = "pw", .salt = "0123456789abcdef"[0..16] } });
        try zw.finish();
    }
    const b6 = try a.dupe(u8, out6.written());
    defer a.free(b6);
    const nl = std.mem.readInt(u16, b6[26..28], .little);
    const xl = std.mem.readInt(u16, b6[28..30], .little);
    b6[30 + nl + xl + 16 + 2 + 4] ^= 0x55; // inside the ciphertext, past salt and password check
    var ms6: zs.MemorySource = undefined;
    var ar6 = try openArchive(a, &ms6, b6);
    defer ar6.deinit();
    try testing.expectEqual(zs.Archive.Problem.Kind.auth_failed, (try ar6.verify(.{ .password = "pw" })).?.kind);
}

test "mutation 2026-11-25: initAppend fails with a central directory that ends past the source" {
    const a = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try threeFiles(a, &out, 1);
    var ms: zs.MemorySource = undefined;
    var ar = try openArchive(a, &ms, out.written());
    defer ar.deinit();
    ar.cd_end += 100;
    var out2: std.Io.Writer.Allocating = .init(a);
    defer out2.deinit();
    var zw = try zs.ArchiveWriter.initAppend(a, &out2.writer, &ar);
    defer zw.deinit();
    try testing.expectError(error.ZipBadCentralDirectory, zw.finish());
}

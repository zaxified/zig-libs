// SPDX-License-Identifier: MIT

//! Tests that came out of the 2026-11-25 whole-module mutation audit: each
//! one kills a mutant the older suites let through (the test names say which
//! behaviour they pin). Mutants that no input can tell from the original are
//! argued in the audit record, not tested here.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const linux = std.os.linux;
const lz4 = @import("root.zig");
const block = @import("block.zig");
const shapes = @import("shapes.zig");

const gpa = testing.allocator;

// ── helpers ─────────────────────────────────────────────────────────────

/// A byte buffer that ends exactly at an inaccessible page: any access one
/// byte past `place(len)` is a SIGSEGV. Reused for many lengths.
const Guarded = struct {
    map: []align(std.heap.page_size_min) u8,

    const cap = 1 << 18;

    fn init() !Guarded {
        const page = std.heap.pageSize();
        const map = try std.posix.mmap(null, cap + page, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
        if (linux.errno(linux.mprotect(map.ptr + cap, page, .{})) != .SUCCESS) {
            std.posix.munmap(map);
            return error.SkipZigTest;
        }
        return .{ .map = map };
    }

    fn deinit(g: *Guarded) void {
        std.posix.munmap(g.map);
    }

    /// `len` bytes ending at the guard page.
    fn place(g: *Guarded, len: usize) []u8 {
        std.debug.assert(len <= cap);
        return g.map[cap - len .. cap];
    }
};

const Seq = struct { lits: usize, off: usize, ml: usize };

const Walk = struct {
    seqs: [96]Seq = undefined,
    n: usize = 0,
    out_len: usize = 0,

    fn matches(w: *const Walk) usize {
        var k: usize = 0;
        for (w.seqs[0..w.n]) |s| k += @intFromBool(s.ml != 0);
        return k;
    }
};

/// Parse a block into its sequences (no decoding).
fn walk(z: []const u8) !Walk {
    var w: Walk = .{};
    var ip: usize = 0;
    while (true) {
        const t = z[ip];
        ip += 1;
        var lits: usize = t >> 4;
        if (lits == 15) while (true) {
            const b = z[ip];
            ip += 1;
            lits += b;
            if (b != 255) break;
        };
        ip += lits;
        w.out_len += lits;
        if (ip == z.len) {
            w.seqs[w.n] = .{ .lits = lits, .off = 0, .ml = 0 };
            w.n += 1;
            return w;
        }
        const off = std.mem.readInt(u16, z[ip..][0..2], .little);
        ip += 2;
        var ml: usize = (t & 15) + 4;
        if (t & 15 == 15) while (true) {
            const b = z[ip];
            ip += 1;
            ml += b;
            if (b != 255) break;
        };
        w.out_len += ml;
        w.seqs[w.n] = .{ .lits = lits, .off = off, .ml = ml };
        w.n += 1;
    }
}

/// The block format's end rules, checked on a block's own sequences.
fn expectEndRules(z: []const u8, len: usize) !void {
    const w = try walk(z);
    try testing.expectEqual(len, w.out_len);
    var pos: usize = 0;
    for (w.seqs[0..w.n]) |s| {
        pos += s.lits;
        if (s.ml != 0) {
            try testing.expect(pos + block.mf_limit <= len); // starts >= 12 before the end
            pos += s.ml;
            try testing.expect(pos + block.last_literals <= len); // ends >= 5 before the end
        }
    }
}

fn compressAlloc(input: []const u8, opts: block.CompressOptions) ![]u8 {
    const z = try gpa.alloc(u8, block.compressBound(input.len));
    defer gpa.free(z);
    const n = try block.compress(input, z, opts);
    return gpa.dupe(u8, z[0..n]);
}

fn expectRoundTrip(input: []const u8, z: []const u8) !void {
    const back = try gpa.alloc(u8, input.len);
    defer gpa.free(back);
    try testing.expectEqual(input.len, try block.decompress(z, back));
    try testing.expectEqualSlices(u8, input, back);
}

/// Every encoder the module has: the fast matcher, the lazy HC levels and the
/// optimal parser.
const encoders = [_]block.CompressOptions{
    .{},
    .{ .hc_level = 3 },
    .{ .hc_level = 6 },
    .{ .hc_level = 9 },
    .{ .hc_level = 10 },
    .{ .hc_level = 11 },
    .{ .hc_level = 12 },
};

// ── the decoder's fast loop against guard pages ─────────────────────────

/// A valid block and the bytes it decodes to; `want` starts with `hist` bytes
/// of history that the block's matches may reach into.
fn randomBlock(r: std.Random, list: *std.ArrayList(u8), want: *std.ArrayList(u8), hist: usize) !void {
    list.clearRetainingCapacity();
    want.clearRetainingCapacity();
    for (0..hist) |i| try want.append(gpa, @truncate(i *% 31 +% 7));
    const nseq = r.intRangeAtMost(usize, 1, 7);
    for (0..nseq + 1) |si| {
        const last = si == nseq;
        const lit: usize = switch (r.uintLessThan(u8, 10)) {
            0 => 0,
            1, 2 => r.intRangeAtMost(usize, 15, 40),
            3 => r.intRangeAtMost(usize, 265, 300),
            else => r.intRangeAtMost(usize, 1, 14),
        };
        const l = if (last) r.intRangeAtMost(usize, 1, 30) else if (want.items.len + lit == 0) 1 else lit;
        const ml: usize = switch (r.uintLessThan(u8, 10)) {
            0, 1 => r.intRangeAtMost(usize, 19, 40),
            2 => r.intRangeAtMost(usize, 270, 300),
            else => r.intRangeAtMost(usize, 4, 18),
        };
        const tok: u8 = @as(u8, @intCast(@min(l, 15))) << 4 | (if (last) 0 else @as(u8, @intCast(@min(ml - 4, 15))));
        try list.append(gpa, tok);
        if (l >= 15) try putExt(list, l - 15);
        for (0..l) |_| {
            const b = r.int(u8);
            try list.append(gpa, b);
            try want.append(gpa, b);
        }
        if (last) break;
        const off = r.intRangeAtMost(usize, 1, @min(want.items.len, @as(usize, if (r.boolean()) 20 else 300)));
        try list.append(gpa, @truncate(off));
        try list.append(gpa, @truncate(off >> 8));
        if (ml - 4 >= 15) try putExt(list, ml - 4 - 15);
        for (0..ml) |_| try want.append(gpa, want.items[want.items.len - off]);
    }
}

fn putExt(list: *std.ArrayList(u8), n: usize) !void {
    var rest = n;
    while (rest >= 255) : (rest -= 255) try list.append(gpa, 255);
    try list.append(gpa, @intCast(rest));
}

test "mutation 2026-11-25: the decoder reads and writes nothing past its input and output slices (guard pages)" {
    // The fast loop is one asm block with no bounds checks, so its margins
    // (`in_end`, `out_end`, the length-byte and output limits) are only
    // visible to a page that faults: input and output end exactly at one.
    var gin = try Guarded.init();
    defer gin.deinit();
    var gout = try Guarded.init();
    defer gout.deinit();
    var prng = std.Random.DefaultPrng.init(0x6a4d);
    const r = prng.random();
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    for (0..8000) |it| {
        // Every fourth block has history in front of it (`decodeInto`).
        const hist: usize = if (it % 4 == 3) r.intRangeAtMost(usize, 1, 40) else 0;
        try randomBlock(r, &list, &want, hist);
        const src = gin.place(list.items.len);
        @memcpy(src, list.items);
        const dst = gout.place(want.items.len);
        @memcpy(dst[0..hist], want.items[0..hist]);
        const end = try block.decodeInto(src, dst, hist, 0);
        try testing.expectEqual(want.items.len, end);
        try testing.expectEqualSlices(u8, want.items[hist..], dst[hist..end]);
    }
}

// ── errors at the very end of the input and of the output ────────────────

test "mutation 2026-11-25: an offset at the very end of a block is judged before the block's ending" {
    var out: [8]u8 = undefined;
    // 'a', then only the two offset bytes: the offset is judged (0, or before
    // the start), not the missing match length.
    try testing.expectError(error.BadOffset, block.decompress("\x10a\x00\x00", &out));
    try testing.expectError(error.BadOffset, block.decompress("\x10a\x02\x00", &out));
    // A good offset, then the end: "ended after a match" -- unless the match
    // does not fit the output, which is the earlier verdict.
    try testing.expectError(error.OutputTooSmall, block.decompress("\x10a\x01\x00", out[0..2]));
    try testing.expectError(error.OutputTooSmall, block.decompress("\x10a\x01\x00", out[0..4]));
    // Exactly fitting: the match is copied, then the block ends after it.
    try testing.expectError(error.Truncated, block.decompress("\x10a\x01\x00", out[0..5]));
    try testing.expectError(error.Truncated, block.decompress("\x10a\x01\x00", out[0..8]));
}

test "mutation 2026-11-25: compressBound saturates" {
    try testing.expectEqual(std.math.maxInt(usize), block.compressBound(std.math.maxInt(usize)));
    try testing.expectEqual(std.math.maxInt(usize), block.compressBound(std.math.maxInt(usize) - 3));
    try testing.expectEqual(@as(usize, 16), block.compressBound(0));
}

// ── length bytes at their edges ──────────────────────────────────────────

test "mutation 2026-11-25: literal-only blocks of 14..16, 269..271 and 524..526 bytes are exact" {
    var prng = std.Random.DefaultPrng.init(0x270);
    const r = prng.random();
    for ([_]usize{ 13, 14, 15, 16, 17, 269, 270, 271, 524, 525, 526, 780, 781 }) |n| {
        const input = try gpa.alloc(u8, n);
        defer gpa.free(input);
        r.bytes(input);
        for (encoders) |opts| {
            const z = try compressAlloc(input, opts);
            defer gpa.free(z);
            // Token, the length bytes past 15, the literals themselves.
            const ext = if (n >= 15) 1 + (n - 15) / 255 else 0;
            try testing.expectEqual(1 + ext + n, z.len);
            try expectRoundTrip(input, z);
        }
    }
}

// ── the unchecked writer's room estimate ─────────────────────────────────

/// compress into every capacity near the full size: the exact `NoSpaceLeft`
/// below it, the same bytes at and above it.
fn expectCapSweep(input: []const u8, below: usize, above: usize) !void {
    const full = try compressAlloc(input, .{});
    defer gpa.free(full);
    const lo = full.len -| below;
    var cap = lo;
    while (cap <= full.len + above) : (cap += 1) {
        const dst = try gpa.alloc(u8, cap);
        defer gpa.free(dst);
        if (block.compress(input, dst, .{})) |n| {
            try testing.expect(cap >= full.len);
            try testing.expectEqualSlices(u8, full, dst[0..n]);
        } else |e| {
            try testing.expectEqual(error.NoSpaceLeft, e);
            try testing.expect(cap < full.len);
        }
    }
}

test "mutation 2026-11-25: a long literal run before a short match, and a short literal run before a long match, never overrun the output" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    // (a) about 6000 random literals, then a short match, then the end. The
    // search skips ahead over incompressible data, so find a position where it
    // does land on the match.
    var base: [6200]u8 = undefined;
    r.bytes(&base);
    var found = false;
    for (5900..6040) |p| {
        var a = base;
        @memcpy(a[p..][0..8], a[100..][0..8]);
        const input = a[0 .. p + 8 + 12];
        const z = try compressAlloc(input, .{});
        defer gpa.free(z);
        const w = try walk(z);
        if (w.seqs[0].ml == 0 or w.seqs[0].lits < 5000) continue;
        try expectCapSweep(input, 80, 20);
        found = true;
        break;
    }
    try testing.expect(found);
    // (b) 8 random literals, then 6000 zeros (one long match), then the end.
    var b: [8 + 6000 + 12]u8 = undefined;
    r.bytes(b[0..8]);
    @memset(b[8..6008], 0);
    r.bytes(b[6008..]);
    try expectCapSweep(&b, 80, 20);
}

// ── the end of the block and the first position ──────────────────────────

fn endRuleInput(comptime pre: usize, comptime post: usize, seed: u64) [4 + pre + 4 + post]u8 {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var buf: [4 + pre + 4 + post]u8 = undefined;
    r.bytes(&buf);
    @memcpy(buf[4 + pre ..][0..4], buf[0..4]);
    return buf;
}

test "mutation 2026-11-25: a match starts at the last allowed position and not one later" {
    for (encoders) |opts| {
        // A 4-byte repeat whose second copy starts 11 bytes before the end: no match.
        const late = endRuleInput(20, 7, 11);
        const z_late = try compressAlloc(&late, opts);
        defer gpa.free(z_late);
        try expectRoundTrip(&late, z_late);
        try testing.expectEqual(@as(usize, 0), (try walk(z_late)).matches());
        // ... and 12 bytes before the end it is taken.
        const edge = endRuleInput(20, 8, 12);
        const z_edge = try compressAlloc(&edge, opts);
        defer gpa.free(z_edge);
        try expectRoundTrip(&edge, z_edge);
        const w = try walk(z_edge);
        try testing.expectEqual(@as(usize, 1), w.matches());
        try testing.expectEqual(@as(usize, 4), w.seqs[0].ml);
        try expectEndRules(z_edge, edge.len);
    }
}

test "mutation 2026-11-25: a second match may start right where the first ends, at the last allowed position" {
    var prng = std.Random.DefaultPrng.init(0x1357);
    const r = prng.random();
    var buf: [16 + 8 + 4 + 8]u8 = undefined;
    r.bytes(&buf);
    if (buf[10] == buf[8]) buf[10] +%= 1;
    @memcpy(buf[16..24], buf[0..8]); // the first match, 8 bytes long
    @memcpy(buf[24..28], buf[10..14]); // the second one starts at len - 12
    for (encoders) |opts| {
        const z = try compressAlloc(&buf, opts);
        defer gpa.free(z);
        try expectRoundTrip(&buf, z);
        const w = try walk(z);
        try testing.expectEqual(@as(usize, 2), w.matches());
        try testing.expectEqual(@as(usize, 8), w.seqs[0].ml);
        try expectEndRules(z, buf.len);
    }
}

test "mutation 2026-11-25: every encoder keeps the end rules on tiny inputs" {
    var prng = std.Random.DefaultPrng.init(0xe2d);
    const r = prng.random();
    var buf: [64]u8 = undefined;
    for (13..64) |len| {
        for (0..12) |_| {
            const alphabet: u8 = if (r.boolean()) 2 else 3;
            for (buf[0..len]) |*c| c.* = 'a' + r.uintLessThan(u8, alphabet);
            for (encoders ++ [_]block.CompressOptions{ .{ .acceleration = 7 }, .{ .acceleration = 65537 } }) |opts| {
                const z = try compressAlloc(buf[0..len], opts);
                defer gpa.free(z);
                try expectRoundTrip(buf[0..len], z);
                try expectEndRules(z, len);
            }
        }
    }
}

test "mutation 2026-11-25: the position two before a match's end is seeded for later matches" {
    var prng = std.Random.DefaultPrng.init(0x2c0de);
    const r = prng.random();
    // P (32 random) | P[0..10] | C (8 random) | S = P[8..10] ++ C[0..2] | 24 random.
    var buf: [32 + 10 + 8 + 4 + 24]u8 = undefined;
    r.bytes(&buf);
    @memcpy(buf[32..42], buf[0..10]);
    if (buf[42] == buf[10]) buf[42] +%= 1;
    buf[50] = buf[8];
    buf[51] = buf[9];
    buf[52] = buf[42];
    buf[53] = buf[43];
    const z = try compressAlloc(&buf, .{});
    defer gpa.free(z);
    try expectRoundTrip(&buf, z);
    const w = try walk(z);
    try testing.expectEqual(@as(usize, 2), w.matches());
    try testing.expectEqual(@as(usize, 4), w.seqs[1].ml);
    try testing.expectEqual(@as(usize, 10), w.seqs[1].off);
}

test "mutation 2026-11-25: an input of exactly the u16 table's limit is hashed with the wide table" {
    // liblz4 uses its byU16 table below LZ4_64Klimit only; at the limit the
    // 4096-slot table of u32 applies, which finds other matches in text.
    const s: shapes.Shape = .{ .name = "limit", .kind = .noisy_text, .len = 65536 + block.mf_limit - 1, .param = 9 };
    const input = try shapes.generate(gpa, s);
    defer gpa.free(input);
    const z = try compressAlloc(input, .{});
    defer gpa.free(z);
    const wide = try gpa.alloc(u8, block.compressBound(input.len));
    defer gpa.free(wide);
    var table: block.Table = @splat(0);
    const n = try block.encodeRange(input, 0, input.len, 0, &table, 1, wide);
    try testing.expectEqualSlices(u8, wide[0..n], z);
    try expectRoundTrip(input, z);
}

// ── inputs of the largest size one block takes ───────────────────────────

test "mutation 2026-11-25: the largest block input is accepted and one more byte is not" {
    if (builtin.mode == .debug) return error.SkipZigTest; // reads 2 GiB of zero pages
    const len = block.max_input_size;
    const map = std.posix.mmap(null, len + 1, .{ .READ = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .NORESERVE = true }, -1, 0) catch return error.SkipZigTest;
    defer std.posix.munmap(map);
    var none: [0]u8 = undefined;
    try testing.expectError(error.InputTooLarge, block.compress(map[0 .. len + 1], &none, .{}));
    // At the limit the input is read (the output has no room, which is the
    // error that comes back instead).
    try testing.expectError(error.NoSpaceLeft, block.compress(map[0..len], &none, .{}));
    try testing.expectError(error.InputTooLarge, block.compressDict(gpa, map[0 .. len + 1], "", &none, .{}));
    try testing.expectError(error.NoSpaceLeft, block.compressDict(gpa, map[0..len], "", &none, .{}));
}

// ── frames built by hand, and the streaming codec judged against the one-shot one ──

const XxHash32 = std.hash.XxHash32;

fn putU32(list: *std.ArrayList(u8), v: u32) !void {
    var w: [4]u8 = undefined;
    std.mem.writeInt(u32, &w, v, .little);
    try list.appendSlice(gpa, &w);
}

const Hdr = struct { flg: u8 = 0x60, bd: u8 = 0x40, size: ?u64 = null };

/// Magic, FLG (with the content-size bit when `size` is set), BD, the size and
/// the header checksum.
fn putHeader(list: *std.ArrayList(u8), h: Hdr) !void {
    try putU32(list, lz4.frame_magic);
    var d: [10]u8 = undefined;
    d[0] = h.flg | @as(u8, if (h.size != null) 0x08 else 0);
    d[1] = h.bd;
    var n: usize = 2;
    if (h.size) |s| {
        std.mem.writeInt(u64, d[2..10], s, .little);
        n = 10;
    }
    try list.appendSlice(gpa, d[0..n]);
    try list.append(gpa, @truncate(XxHash32.hash(0, d[0..n]) >> 8));
}

fn putStored(list: *std.ArrayList(u8), data: []const u8) !void {
    try putU32(list, @as(u32, @intCast(data.len)) | 0x8000_0000);
    try list.appendSlice(gpa, data);
}

fn putCompressed(list: *std.ArrayList(u8), data: []const u8) !void {
    try putU32(list, @intCast(data.len));
    try list.appendSlice(gpa, data);
}

const Verdict = union(enum) {
    ok: []u8,
    err: lz4.DecodeError,

    fn deinit(v: Verdict) void {
        switch (v) {
            .ok => |b| gpa.free(b),
            .err => {},
        }
    }

    fn eql(a: Verdict, b: Verdict) bool {
        return switch (a) {
            .ok => |x| switch (b) {
                .ok => |y| std.mem.eql(u8, x, y),
                .err => false,
            },
            .err => |x| switch (b) {
                .ok => false,
                .err => |y| x == y,
            },
        };
    }

    fn name(v: Verdict, buf: []u8) []const u8 {
        return switch (v) {
            .ok => |b| std.fmt.bufPrint(buf, "ok({d} bytes)", .{b.len}) catch "ok",
            .err => |e| @errorName(e),
        };
    }
};

fn oneShot(z: []const u8, opts: lz4.DecodeOptions) !Verdict {
    if (lz4.decompress(gpa, z, opts)) |b| return .{ .ok = b } else |e| return .{ .err = e };
}

fn streamed(z: []const u8, opts: lz4.DecompressorOptions, chunk: usize) !Verdict {
    var in: std.Io.Reader = .fixed(z);
    var buf: [16]u8 = undefined;
    const d = try lz4.Decompressor.init(gpa, &in, &buf, opts);
    defer d.deinit();
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const tmp = try gpa.alloc(u8, chunk);
    defer gpa.free(tmp);
    while (true) {
        const n = d.reader.readSliceShort(tmp) catch {
            out.deinit(gpa);
            return .{ .err = d.err.? };
        };
        if (n == 0) break;
        try out.appendSlice(gpa, tmp[0..n]);
    }
    return .{ .ok = try out.toOwnedSlice(gpa) };
}

const Disagreements = struct {
    n: usize = 0,

    fn check(d: *Disagreements, label: []const u8, z: []const u8, a: Verdict, b: Verdict) void {
        defer a.deinit();
        defer b.deinit();
        if (a.eql(b)) return;
        d.n += 1;
        if (d.n <= 12) {
            var b1: [40]u8 = undefined;
            var b2: [40]u8 = undefined;
            std.debug.print("{s} (len {d}): one-shot {s}, stream {s}\n", .{ label, z.len, a.name(&b1), b.name(&b2) });
        }
    }
};

test "mutation 2026-11-25: the streaming decoder gives the one-shot decoder's verdict on damaged frames" {
    const text = try shapes.generate(gpa, .{ .name = "t", .kind = .text, .len = 70_000, .seed = 5 });
    defer gpa.free(text);
    var dis: Disagreements = .{};
    var mutated: std.ArrayList(u8) = .empty;
    defer mutated.deinit(gpa);
    var variant: usize = 0;
    while (variant < 32) : (variant += 1) {
        const eo: lz4.EncodeOptions = .{
            .independent_blocks = variant & 1 != 0,
            .block_checksum = variant & 2 != 0,
            .content_checksum = variant & 4 != 0,
            .content_size = variant & 8 != 0,
            .hc_level = if (variant & 16 != 0) 4 else 0,
        };
        const z = try lz4.compress(gpa, text, eo);
        defer gpa.free(z);
        const head = 7 + @as(usize, if (eo.content_size) 8 else 0);
        // Every bit of the header, of the first block's size word, of its first
        // bytes, and of the last 12 bytes (end mark, checksums).
        var spots: std.ArrayList(usize) = .empty;
        defer spots.deinit(gpa);
        for (0..head + 8) |i| try spots.append(gpa, i);
        for (z.len - 12..z.len) |i| try spots.append(gpa, i);
        try spots.append(gpa, head + 4 + 70); // inside the first block
        for (spots.items) |at| {
            for (0..8) |bit| {
                mutated.clearRetainingCapacity();
                try mutated.appendSlice(gpa, z);
                mutated.items[at] ^= @as(u8, 1) << @intCast(bit);
                var label_buf: [64]u8 = undefined;
                const label = std.fmt.bufPrint(&label_buf, "variant {d} byte {d} bit {d}", .{ variant, at, bit }) catch "?";
                dis.check(label, mutated.items, try oneShot(mutated.items, .{}), try streamed(mutated.items, .{}, 1 << 16));
            }
        }
        // Cut anywhere in the framing, and bytes after the last frame.
        for (1..head + 12) |cut| { // (an empty input is an empty frame list for the one-shot decoder, a truncation for the stream)
            dis.check("cut", z[0..cut], try oneShot(z[0..cut], .{}), try streamed(z[0..cut], .{}, 1 << 16));
        }
        for (z.len - 14..z.len) |cut| {
            dis.check("cut end", z[0..cut], try oneShot(z[0..cut], .{}), try streamed(z[0..cut], .{}, 1 << 16));
        }
        for ([_][]const u8{ "x", "xy", "xyz", "wxyz", "garbage!!" }) |tail| {
            mutated.clearRetainingCapacity();
            try mutated.appendSlice(gpa, z);
            try mutated.appendSlice(gpa, tail);
            dis.check("tail", mutated.items, try oneShot(mutated.items, .{}), try streamed(mutated.items, .{}, 1 << 16));
        }
        // A skippable frame, then nothing / garbage / the frame.
        var skip: [8]u8 = undefined;
        std.mem.writeInt(u32, skip[0..4], lz4.skippable_magic_base + 5, .little);
        std.mem.writeInt(u32, skip[4..8], 0, .little);
        for ([_][]const u8{ "", "garbage!!", "xy" }) |tail| {
            mutated.clearRetainingCapacity();
            try mutated.appendSlice(gpa, &skip);
            try mutated.appendSlice(gpa, tail);
            dis.check("skippable", mutated.items, try oneShot(mutated.items, .{}), try streamed(mutated.items, .{}, 1 << 16));
        }
        mutated.clearRetainingCapacity();
        try mutated.appendSlice(gpa, &skip);
        try mutated.appendSlice(gpa, z);
        try mutated.appendSlice(gpa, z);
        dis.check("skippable + two frames", mutated.items, try oneShot(mutated.items, .{}), try streamed(mutated.items, .{}, 777));
    }
    try testing.expectEqual(@as(usize, 0), dis.n);
}

test "mutation 2026-11-25: the streaming decoder on hand-built frames: sizes, caps, checksums, history" {
    var dis: Disagreements = .{};
    var f: std.ArrayList(u8) = .empty;
    defer f.deinit(gpa);
    const body = "0123456789abcdefghij";
    const cases = [_]struct { size: ?u64, cap: ?usize, verify: bool }{
        .{ .size = body.len, .cap = body.len, .verify = true }, // declared == cap: fits
        .{ .size = body.len, .cap = body.len - 1, .verify = true }, // refused before decoding
        .{ .size = 1000, .cap = 999, .verify = true }, // declared over the cap, content small
        .{ .size = 0, .cap = null, .verify = true }, // size 0 = unknown
        .{ .size = 7, .cap = null, .verify = true }, // wrong size
        .{ .size = null, .cap = body.len, .verify = true },
        .{ .size = null, .cap = body.len - 1, .verify = true },
    };
    for (cases) |c| {
        for ([_]u8{ 0x00, 0x04, 0x10, 0x14 }) |sums| { // none, content, block, both
            f.clearRetainingCapacity();
            try putHeader(&f, .{ .flg = 0x60 | sums, .size = c.size });
            try putStored(&f, body);
            if (sums & 0x10 != 0) try putU32(&f, XxHash32.hash(0, body) ^ 1); // wrong block checksum
            try putU32(&f, 0);
            if (sums & 0x04 != 0) try putU32(&f, XxHash32.hash(0, body) ^ 1); // wrong content checksum
            dis.check("hand-built", f.items, try oneShot(f.items, .{ .max_output = c.cap, .verify_checksums = c.verify }), try streamed(f.items, .{ .max_output = c.cap, .verify_checksums = c.verify }, 5));
            dis.check("hand-built, no verify", f.items, try oneShot(f.items, .{ .max_output = c.cap, .verify_checksums = false }), try streamed(f.items, .{ .max_output = c.cap, .verify_checksums = false }, 5));
        }
    }
    // Two frames in a row: sizes and checksums are per frame, and the cap is
    // for the whole input.
    f.clearRetainingCapacity();
    for (0..2) |_| {
        try putHeader(&f, .{ .flg = 0x64, .size = body.len });
        try putStored(&f, body);
        try putU32(&f, 0);
        try putU32(&f, XxHash32.hash(0, body));
    }
    for ([_]?usize{ null, 2 * body.len, 2 * body.len - 1, body.len }) |cap| {
        dis.check("two frames", f.items, try oneShot(f.items, .{ .max_output = cap }), try streamed(f.items, .{ .max_output = cap }, 7));
    }
    // A second linked frame whose block reaches back before its own first byte:
    // the first frame's bytes are not history.
    f.clearRetainingCapacity();
    try putHeader(&f, .{ .flg = 0x40 }); // linked blocks
    try putStored(&f, body);
    try putU32(&f, 0);
    try putHeader(&f, .{ .flg = 0x40 });
    try putCompressed(&f, "\x10x\x03\x00\x10y"); // 'x', then a match at offset 3: only 1 byte of history
    try putU32(&f, 0);
    dis.check("history of the previous frame", f.items, try oneShot(f.items, .{}), try streamed(f.items, .{}, 7));
    try testing.expectEqual(@as(usize, 0), dis.n);
}

test "mutation 2026-11-25: a stream that failed stays failed" {
    // Block checksums on, the first block's checksum wrong: reading fails, and
    // reading again does not skip the block and go on.
    var f: std.ArrayList(u8) = .empty;
    defer f.deinit(gpa);
    try putHeader(&f, .{ .flg = 0x70 });
    try putStored(&f, "first block");
    try putU32(&f, XxHash32.hash(0, "first block") ^ 1);
    try putStored(&f, "second block");
    try putU32(&f, XxHash32.hash(0, "second block"));
    try putU32(&f, 0);
    var in: std.Io.Reader = .fixed(f.items);
    const d = try lz4.Decompressor.init(gpa, &in, &.{}, .{});
    defer d.deinit();
    var sink: [64]u8 = undefined;
    try testing.expectError(error.ReadFailed, d.reader.readSliceShort(&sink));
    try testing.expectEqual(@as(?lz4.DecodeError, error.BlockChecksumMismatch), d.err);
    try testing.expectError(error.ReadFailed, d.reader.readSliceShort(&sink));
    try testing.expectEqual(@as(?lz4.DecodeError, error.BlockChecksumMismatch), d.err);
}

fn compressStream(data: []const u8, opts: lz4.CompressorOptions, chunk: usize) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const c = try lz4.Compressor.init(gpa, &out.writer, opts);
    defer c.deinit();
    var i: usize = 0;
    while (i < data.len) {
        const k = @min(chunk, data.len - i);
        try c.writer.writeAll(data[i..][0..k]);
        i += k;
    }
    try c.finish();
    return out.toOwnedSlice();
}

/// How many blocks a frame holds (header without a dictionary id).
fn blockCount(z: []const u8, block_checksum: bool, has_size: bool) usize {
    var at: usize = 7 + @as(usize, if (has_size) 8 else 0);
    var n: usize = 0;
    while (true) {
        const w = std.mem.readInt(u32, z[at..][0..4], .little);
        at += 4;
        if (w == 0) return n;
        at += (w & 0x7FFF_FFFF) + @as(usize, if (block_checksum) 4 else 0);
        n += 1;
    }
}

const stream_pins = [_]Pin{
    .{ .len = 113057, .hash = 0xed0b5e9962592715 }, // stream variant 0
    .{ .len = 113467, .hash = 0x4368021bfa3f5c46 }, // stream variant 1
    .{ .len = 113069, .hash = 0x2bd4387fd0a4afa }, // stream variant 2
    .{ .len = 77814, .hash = 0xa3d6007985807718 }, // stream variant 3
    .{ .len = 64518, .hash = 0x49c8dbcb1122647d }, // stream variant 4
    .{ .len = 65925, .hash = 0x1dd54be8e3c59cc7 }, // stream variant 5
    .{ .len = 75339, .hash = 0x2d0353128b31628f }, // stream variant 6
    .{ .len = 116765, .hash = 0xb47d663901b384a4 }, // stream variant 7
};

test "mutation 2026-11-25: the Compressor writes the recorded bytes, close to the one-shot encoder's" {
    const text = try shapes.generate(gpa, .{ .name = "t", .kind = .noisy_text, .len = 200_000, .seed = 6, .param = 30 });
    defer gpa.free(text);
    const variants = [_]lz4.EncodeOptions{
        .{},
        .{ .independent_blocks = true, .block_checksum = true, .content_checksum = true },
        .{ .content_checksum = true, .content_size = true },
        .{ .hc_level = 3 },
        .{ .hc_level = 9, .content_checksum = true },
        .{ .hc_level = 10 },
        .{ .hc_level = 4, .independent_blocks = true },
        .{ .block_size = .max256KB, .acceleration = 5 },
    };
    var missing: usize = 0;
    for (variants, 0..) |eo, vi| {
        const want = try lz4.compress(gpa, text, eo);
        defer gpa.free(want);
        const a = try compressStream(text, .{ .frame = eo, .content_size = text.len }, 777);
        defer gpa.free(a);
        // The header is the one-shot encoder's (flags, sizes, checksum byte), and
        // the size is within 1 %: the matchers see the same window.
        try testing.expectEqualSlices(u8, want[0..7], a[0..7]);
        try testing.expect(a.len <= want.len + want.len / 100 and want.len <= a.len + a.len / 100);
        const got: Pin = .{ .len = @intCast(a.len), .hash = std.hash.Wyhash.hash(0, a) };
        if (vi >= stream_pins.len) {
            std.debug.print(".{{ .len = {d}, .hash = 0x{x} }}, // stream variant {d}\n", .{ got.len, got.hash, vi });
            missing += 1;
        } else if (got.len != stream_pins[vi].len or got.hash != stream_pins[vi].hash) {
            std.debug.print("stream pin {d}: {d} bytes, hash 0x{x}\n", .{ vi, got.len, got.hash });
            missing += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), missing);
    // An empty stream is the one-shot encoder's empty frame, header and end mark only.
    const empty = try lz4.compress(gpa, "", .{});
    defer gpa.free(empty);
    const got = try compressStream("", .{}, 1);
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, empty, got);
    try testing.expectEqual(@as(usize, 11), got.len);
}

test "mutation 2026-11-25: flush with nothing buffered writes no block, finish twice writes the end mark once" {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const c = try lz4.Compressor.init(gpa, &out.writer, .{});
    defer c.deinit();
    try c.writer.writeAll("some data some data some data");
    try c.writer.flush();
    try c.writer.flush();
    try c.finish();
    const once = try gpa.dupe(u8, out.written());
    defer gpa.free(once);
    try c.finish();
    try testing.expectEqualSlices(u8, once, out.written());
    try testing.expectEqual(@as(usize, 1), blockCount(once, false, false));
}

test "mutation 2026-11-25: short blocks keep the history window: a block may match two blocks back" {
    var prng = std.Random.DefaultPrng.init(0x4157);
    const r = prng.random();
    var a: [3000]u8 = undefined;
    var b: [3000]u8 = undefined;
    r.bytes(&a);
    r.bytes(&b);
    for ([_]lz4.EncodeOptions{ .{}, .{ .hc_level = 4 }, .{ .hc_level = 10 } }) |eo| {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        const c = try lz4.Compressor.init(gpa, &out.writer, .{ .frame = eo });
        defer c.deinit();
        try c.writer.writeAll(&a);
        try c.writer.flush();
        try c.writer.writeAll(&b);
        try c.writer.flush();
        try c.writer.writeAll(&a); // two short blocks back
        try c.finish();
        // The third block is a match against the first: about 20 bytes.
        try testing.expect(out.written().len < 6000 + 300);
        const back = try lz4.decompress(gpa, out.written(), .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, &a, back[0..3000]);
        try testing.expectEqualSlices(u8, &b, back[3000..6000]);
        try testing.expectEqualSlices(u8, &a, back[6000..]);
        // ... and the streaming decoder keeps the same window.
        const v = try streamed(out.written(), .{}, 100);
        defer v.deinit();
        try testing.expectEqualSlices(u8, back, v.ok);
    }
}

test "mutation 2026-11-25: a block that compresses to exactly its own size is stored" {
    var prng = std.Random.DefaultPrng.init(0x24);
    const r = prng.random();
    var buf: [24]u8 = undefined;
    r.bytes(&buf);
    @memcpy(buf[8..12], buf[0..4]); // 8 literals, a 4-byte match, 12 literals: 4 + 8 + 12 = 24 bytes
    var z: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 24), try lz4.compressBlock(&buf, &z, .{}));
    const f = try lz4.compress(gpa, &buf, .{});
    defer gpa.free(f);
    try testing.expectEqual(@as(u32, 24 | 0x8000_0000), std.mem.readInt(u32, f[7..11], .little));
    const s = try compressStream(&buf, .{}, 100);
    defer gpa.free(s);
    try testing.expectEqualSlices(u8, f, s);
}

// ── the frame decoder: dictionaries and the output cap ───────────────────

fn legacyFrame(list: *std.ArrayList(u8), data: []const u8) !void {
    try putU32(list, lz4.legacy_frame_magic);
    var z: [4096]u8 = undefined;
    const n = try lz4.compressBlock(data, &z, .{});
    try putU32(list, @intCast(n));
    try list.appendSlice(gpa, z[0..n]);
}

test "mutation 2026-11-25: the dictionary is not counted as output after its frame" {
    const dict = try shapes.generate(gpa, .{ .name = "d", .kind = .text, .len = 1000, .seed = 3 });
    defer gpa.free(dict);
    const data1 = try shapes.generate(gpa, .{ .name = "a", .kind = .text, .len = 3000, .seed = 4 });
    defer gpa.free(data1);
    const data2 = try shapes.generate(gpa, .{ .name = "b", .kind = .text, .len = 2000, .seed = 5 });
    defer gpa.free(data2);
    const f1 = try lz4.compressDict(gpa, data1, dict, null, .{});
    defer gpa.free(f1);
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(gpa);
    try all.appendSlice(gpa, f1);
    try legacyFrame(&all, data2); // a frame that takes no dictionary
    const total = data1.len + data2.len;
    const got = try lz4.decompressDict(gpa, all.items, dict, .{ .max_output = total });
    defer gpa.free(got);
    try testing.expectEqual(total, got.len);
    try testing.expectError(error.OutputTooLarge, lz4.decompressDict(gpa, all.items, dict, .{ .max_output = total - 1 }));
    // One frame: the cap is the content, dictionary or not, linked or independent.
    for ([_]bool{ false, true }) |indep| {
        const z = try lz4.compressDict(gpa, data1, dict, 9, .{ .independent_blocks = indep });
        defer gpa.free(z);
        const ok = try lz4.decompressDict(gpa, z, dict, .{ .max_output = data1.len });
        defer gpa.free(ok);
        try testing.expectEqualSlices(u8, data1, ok);
        try testing.expectError(error.OutputTooLarge, lz4.decompressDict(gpa, z, dict, .{ .max_output = data1.len - 1 }));
    }
}

test "mutation 2026-11-25: a dictionary frame of incompressible data fits its buffer" {
    var prng = std.Random.DefaultPrng.init(0xd1c7);
    var data: [100]u8 = undefined;
    prng.random().bytes(&data);
    for ([_]bool{ false, true }) |indep| {
        const z = try lz4.compressDict(gpa, &data, "some dictionary text, some dictionary text", 7, .{ .independent_blocks = indep });
        defer gpa.free(z);
        const back = try lz4.decompressDict(gpa, z, "some dictionary text, some dictionary text", .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, &data, back);
    }
}

// ── dictionaries: what is seeded and what counts ─────────────────────────

fn expectFirstSequenceMatches(z: []const u8) !void {
    const w = try walk(z);
    try testing.expect(w.n >= 2);
    try testing.expectEqual(@as(usize, 0), w.seqs[0].lits); // the match comes first
}

test "mutation 2026-11-25: a 4-byte dictionary and a dictionary seeded at its last positions" {
    var prng = std.Random.DefaultPrng.init(0xd1c);
    const r = prng.random();
    var tail: [40]u8 = undefined;
    r.bytes(&tail);
    var src: [4 + 40]u8 = undefined;
    @memcpy(src[0..4], "WXYZ");
    @memcpy(src[4..], &tail);
    var z: [128]u8 = undefined;
    // dict = "WXYZ": the one position of a 4-byte dictionary is seeded.
    var n = try lz4.compressBlockDict(gpa, &src, "WXYZ", &z, .{});
    try expectFirstSequenceMatches(z[0..n]);
    // dict = 3 bytes + "WXYZ": position 3, the last one of the every-third grid.
    n = try lz4.compressBlockDict(gpa, &src, "abcWXYZ", &z, .{});
    try expectFirstSequenceMatches(z[0..n]);
    // dict = 2 bytes + "WXYZ" + 10 bytes: position 2 is off the grid, not seeded.
    n = try lz4.compressBlockDict(gpa, &src, "abWXYZ0123456789", &z, .{});
    try testing.expectEqual(@as(usize, 0), (try walk(z[0..n])).matches());
}

test "mutation 2026-11-25: only the last 64 KiB - 1 bytes of a dictionary count, for the encoder too" {
    const dict = try shapes.generate(gpa, .{ .name = "d", .kind = .noisy_text, .len = 70_000, .seed = 8, .param = 15 });
    defer gpa.free(dict);
    const src = try shapes.generate(gpa, .{ .name = "s", .kind = .noisy_text, .len = 30_000, .seed = 8, .param = 15 });
    defer gpa.free(src);
    const tail = dict[dict.len - block.max_offset ..];
    for ([_]block.CompressOptions{ .{}, .{ .hc_level = 5 } }) |opts| {
        const a = try gpa.alloc(u8, lz4.compressBlockBound(src.len));
        defer gpa.free(a);
        const b = try gpa.alloc(u8, lz4.compressBlockBound(src.len));
        defer gpa.free(b);
        const na = try lz4.compressBlockDict(gpa, src, dict, a, opts);
        const nb = try lz4.compressBlockDict(gpa, src, tail, b, opts);
        try testing.expectEqualSlices(u8, b[0..nb], a[0..na]);
    }
    // An empty dictionary is no dictionary: the same bytes as `compressBlock`.
    const a = try gpa.alloc(u8, lz4.compressBlockBound(src.len));
    defer gpa.free(a);
    const b = try gpa.alloc(u8, lz4.compressBlockBound(src.len));
    defer gpa.free(b);
    const na = try lz4.compressBlockDict(gpa, src, "", a, .{});
    const nb = try lz4.compressBlock(src, b, .{});
    try testing.expectEqualSlices(u8, b[0..nb], a[0..na]);
}

// ── HC levels: where they begin, the window edge, the chain's last link ──

test "mutation 2026-11-25: level 3 is the first HC level, with and without a dictionary" {
    const text = try shapes.generate(gpa, .{ .name = "t", .kind = .text, .len = 30_000, .seed = 21 });
    defer gpa.free(text);
    const dict = try shapes.generate(gpa, .{ .name = "d", .kind = .text, .len = 5_000, .seed = 22 });
    defer gpa.free(dict);
    const fast = try compressAlloc(text, .{ .hc_level = 2 });
    defer gpa.free(fast);
    const hc3 = try compressAlloc(text, .{ .hc_level = 3 });
    defer gpa.free(hc3);
    try testing.expect(hc3.len < fast.len);
    const dz = try gpa.alloc(u8, lz4.compressBlockBound(text.len));
    defer gpa.free(dz);
    const dn_fast = try lz4.compressBlockDict(gpa, text, dict, dz, .{ .hc_level = 2 });
    const dn_hc3 = try lz4.compressBlockDict(gpa, text, dict, dz, .{ .hc_level = 3 });
    try testing.expect(dn_hc3 < dn_fast);
    // The frame APIs: the one-shot and the buffered one.
    const f_fast = try lz4.compress(gpa, text, .{ .hc_level = 2 });
    defer gpa.free(f_fast);
    const f_hc3 = try lz4.compress(gpa, text, .{ .hc_level = 3 });
    defer gpa.free(f_hc3);
    try testing.expect(f_hc3.len < f_fast.len);
    const buf = try gpa.alloc(u8, lz4.compressBound(text.len, .{}));
    defer gpa.free(buf);
    const ni_fast = try lz4.compressInto(text, buf, .{ .hc_level = 2 });
    const ni_hc3 = try lz4.compressInto(text, buf, .{ .hc_level = 3 });
    try testing.expect(ni_hc3 < ni_fast);
    const fd_fast = try lz4.compressDict(gpa, text, dict, null, .{ .hc_level = 2 });
    defer gpa.free(fd_fast);
    const fd_hc3 = try lz4.compressDict(gpa, text, dict, null, .{ .hc_level = 3 });
    defer gpa.free(fd_hc3);
    try testing.expect(fd_hc3.len < fd_fast.len);
}

test "mutation 2026-11-25: an HC block finds a match at offset 65535 and none at 65536" {
    var sizes: [2]usize = undefined;
    for ([_]u8{ 3, 6, 10, 12 }) |level| {
        for ([_]u32{ 64_535, 64_536 }, 0..) |param, i| {
            const s: shapes.Shape = .{ .name = "far", .kind = .far_repeat, .len = 0, .param = param };
            const input = try gpa.alloc(u8, shapes.length(s));
            defer gpa.free(input);
            shapes.fill(s, input);
            const z = try compressAlloc(input, .{ .hc_level = level });
            defer gpa.free(z);
            try expectRoundTrip(input, z);
            sizes[i] = z.len;
        }
        try testing.expect(sizes[0] + 900 < sizes[1]);
    }
}

test "mutation 2026-11-25: the hash chain is followed down to the very first position" {
    // "ABCDEFGH" at 0, "ABCDxxxx" and "ABCDyyyy" later, "ABCDEFGH" last: the
    // best match is the one at position 0, three links down the chain.
    var prng = std.Random.DefaultPrng.init(0xc4a1);
    const r = prng.random();
    var buf: [8 + 30 + 8 + 30 + 8 + 30 + 8 + 30]u8 = undefined;
    r.bytes(&buf);
    @memcpy(buf[0..8], "ABCDEFGH");
    @memcpy(buf[38..46], "ABCDxxxx");
    @memcpy(buf[76..84], "ABCDyyyy");
    @memcpy(buf[114..122], "ABCDEFGH");
    for ([_]u8{ 3, 6, 9, 10, 12 }) |level| {
        const z = try compressAlloc(&buf, .{ .hc_level = level });
        defer gpa.free(z);
        try expectRoundTrip(&buf, z);
        const w = try walk(z);
        var best: usize = 0;
        for (w.seqs[0..w.n]) |q| best = @max(best, q.ml);
        try testing.expect(best >= 8);
        // The 8-byte match reaches back to position 0.
        var pos: usize = 0;
        var found = false;
        for (w.seqs[0..w.n]) |q| {
            pos += q.lits;
            if (q.ml >= 8 and pos - q.off == 0) found = true;
            pos += q.ml;
        }
        try testing.expect(found);
    }
}

// ── the encoders' output, pinned ─────────────────────────────────────────

// Which valid block the matchers choose (the order of the chain walk, ties,
// the lookahead, the optimal parser's prices) is part of what they are, and
// nothing but the bytes show it: a regression pin of each encoder's output on
// inputs that reach every one of those choices. A change of an encoder that is
// meant to change its output re-records the table (run the test: it prints
// the rows).

const Pin = struct { len: u32, hash: u64 };

const pin_inputs = [_]shapes.Shape{
    .{ .name = "text", .kind = .text, .len = 24_000, .seed = 11 },
    .{ .name = "noisy", .kind = .noisy_text, .len = 24_000, .seed = 12, .param = 12 },
    .{ .name = "runs", .kind = .runs, .len = 24_000, .seed = 13, .param = 40 },
    .{ .name = "periodic", .kind = .periodic, .len = 12_000, .seed = 14, .param = 9 },
    .{ .name = "far", .kind = .far_repeat, .len = 0, .seed = 15, .param = 20_000 },
    .{ .name = "small text", .kind = .text, .len = 3_000, .seed = 16 },
};

const pin_opts = [_]block.CompressOptions{
    .{},
    .{ .acceleration = 6 },
    .{ .hc_level = 3 },
    .{ .hc_level = 5 },
    .{ .hc_level = 9 },
    .{ .hc_level = 10 },
    .{ .hc_level = 11 },
    .{ .hc_level = 12 },
};

const pins = [_]Pin{
    .{ .len = 12412, .hash = 0x519eb9716670a5b1 }, // text level 0 accel 1
    .{ .len = 13008, .hash = 0xd8c0745cba0a6959 }, // text level 0 accel 6
    .{ .len = 8302, .hash = 0xfe8adabc9bb4d8e7 }, // text level 3 accel 1
    .{ .len = 7499, .hash = 0xf7acd8514d8366e4 }, // text level 5 accel 1
    .{ .len = 7303, .hash = 0x2b13144192184997 }, // text level 9 accel 1
    .{ .len = 7217, .hash = 0x3c1afcb157559414 }, // text level 10 accel 1
    .{ .len = 7151, .hash = 0xf22768cc2e7f6b91 }, // text level 11 accel 1
    .{ .len = 7151, .hash = 0xf22768cc2e7f6b91 }, // text level 12 accel 1
    .{ .len = 15631, .hash = 0xa72537f64906135f }, // noisy level 0 accel 1
    .{ .len = 17362, .hash = 0xba267574e9771d2 }, // noisy level 0 accel 6
    .{ .len = 12459, .hash = 0xe2e30ac3da46b114 }, // noisy level 3 accel 1
    .{ .len = 11835, .hash = 0xa8c599eb7e70893e }, // noisy level 5 accel 1
    .{ .len = 11720, .hash = 0xc5df027d9f9716fe }, // noisy level 9 accel 1
    .{ .len = 11586, .hash = 0xace80ec519d3c938 }, // noisy level 10 accel 1
    .{ .len = 11571, .hash = 0x9d64e6be2de48b7d }, // noisy level 11 accel 1
    .{ .len = 11571, .hash = 0x9d64e6be2de48b7d }, // noisy level 12 accel 1
    .{ .len = 5579, .hash = 0xc43609d7533fba61 }, // runs level 0 accel 1
    .{ .len = 6948, .hash = 0x108602aa57474455 }, // runs level 0 accel 6
    .{ .len = 4764, .hash = 0x54002590b2db4ce4 }, // runs level 3 accel 1
    .{ .len = 4524, .hash = 0xf833f1eb1e0aef05 }, // runs level 5 accel 1
    .{ .len = 4515, .hash = 0x2945687f843c97a5 }, // runs level 9 accel 1
    .{ .len = 4519, .hash = 0x70411e22a49c7431 }, // runs level 10 accel 1
    .{ .len = 4515, .hash = 0x574fc9d2609b49d3 }, // runs level 11 accel 1
    .{ .len = 4515, .hash = 0x574fc9d2609b49d3 }, // runs level 12 accel 1
    .{ .len = 65, .hash = 0x69c1859fc750a89e }, // periodic level 0 accel 1
    .{ .len = 75, .hash = 0x55d97664e7c80cfc }, // periodic level 0 accel 6
    .{ .len = 65, .hash = 0x69c1859fc750a89e }, // periodic level 3 accel 1
    .{ .len = 65, .hash = 0x69c1859fc750a89e }, // periodic level 5 accel 1
    .{ .len = 65, .hash = 0x69c1859fc750a89e }, // periodic level 9 accel 1
    .{ .len = 65, .hash = 0x69c1859fc750a89e }, // periodic level 10 accel 1
    .{ .len = 65, .hash = 0x69c1859fc750a89e }, // periodic level 11 accel 1
    .{ .len = 65, .hash = 0x69c1859fc750a89e }, // periodic level 12 accel 1
    .{ .len = 21096, .hash = 0x35e48404c8db3f01 }, // far level 0 accel 1
    .{ .len = 21096, .hash = 0x35e48404c8db3f01 }, // far level 0 accel 6
    .{ .len = 21096, .hash = 0x35e48404c8db3f01 }, // far level 3 accel 1
    .{ .len = 21096, .hash = 0x35e48404c8db3f01 }, // far level 5 accel 1
    .{ .len = 21096, .hash = 0x35e48404c8db3f01 }, // far level 9 accel 1
    .{ .len = 21096, .hash = 0x35e48404c8db3f01 }, // far level 10 accel 1
    .{ .len = 21096, .hash = 0x35e48404c8db3f01 }, // far level 11 accel 1
    .{ .len = 21096, .hash = 0x35e48404c8db3f01 }, // far level 12 accel 1
    .{ .len = 1611, .hash = 0x6cf587a05cccb6e1 }, // small text level 0 accel 1
    .{ .len = 1970, .hash = 0x5d1c9d1e79f80616 }, // small text level 0 accel 6
    .{ .len = 1302, .hash = 0x349b721b1b65d34f }, // small text level 3 accel 1
    .{ .len = 1283, .hash = 0x9f1bb5b8f9a605ef }, // small text level 5 accel 1
    .{ .len = 1283, .hash = 0x9f1bb5b8f9a605ef }, // small text level 9 accel 1
    .{ .len = 1267, .hash = 0x52492d17e500cf98 }, // small text level 10 accel 1
    .{ .len = 1267, .hash = 0x52492d17e500cf98 }, // small text level 11 accel 1
    .{ .len = 1267, .hash = 0x52492d17e500cf98 }, // small text level 12 accel 1
};

test "mutation 2026-11-25: every encoder's output on a set of inputs is the recorded one" {
    var missing: usize = 0;
    var idx: usize = 0;
    for (pin_inputs) |sh| {
        const input = try shapes.generate(gpa, sh);
        defer gpa.free(input);
        for (pin_opts) |o| {
            defer idx += 1;
            const z = try compressAlloc(input, o);
            defer gpa.free(z);
            try expectRoundTrip(input, z);
            const got: Pin = .{ .len = @intCast(z.len), .hash = std.hash.Wyhash.hash(0, z) };
            if (idx >= pins.len) {
                std.debug.print(".{{ .len = {d}, .hash = 0x{x} }}, // {s} level {d} accel {d}\n", .{ got.len, got.hash, sh.name, o.hc_level, o.acceleration });
                missing += 1;
            } else if (got.len != pins[idx].len or got.hash != pins[idx].hash) {
                std.debug.print("pin {d} ({s}, level {d}, accel {d}): {d} bytes, hash 0x{x}\n", .{ idx, sh.name, o.hc_level, o.acceleration, got.len, got.hash });
                missing += 1;
            }
        }
    }
    try testing.expectEqual(@as(usize, 0), missing);
}

test "mutation 2026-11-25: length bytes that run to the end of the input are not read past it (guard page)" {
    var gin = try Guarded.init();
    defer gin.deinit();
    var gout = try Guarded.init();
    defer gout.deinit();
    for (17..80) |k| {
        // A literal length of 15 + 255s, and a match length of 19 + 255s.
        const lit = gin.place(1 + k);
        lit[0] = 0xF0;
        @memset(lit[1..], 255);
        try testing.expectError(error.Truncated, block.decompress(lit, gout.place(200)));
        const mat = gin.place(4 + k);
        @memcpy(mat[0..4], "\x1fa\x01\x00");
        @memset(mat[4..], 255);
        try testing.expectError(error.Truncated, block.decompress(mat, gout.place(200)));
    }
}

test "mutation 2026-11-25: 13 bytes hold a match, 12 do not, in every encoder" {
    const zeros: [13]u8 = @splat(0);
    for (encoders) |opts| {
        const z13 = try compressAlloc(&zeros, opts);
        defer gpa.free(z13);
        try testing.expectEqual(@as(usize, 10), z13.len);
        const z12 = try compressAlloc(zeros[0..12], opts);
        defer gpa.free(z12);
        try testing.expectEqual(@as(usize, 13), z12.len);
    }
}

const pin2_inputs = [_]shapes.Shape{
    .{ .name = "noisy4", .kind = .noisy_text, .len = 24_000, .seed = 31, .param = 4 },
    .{ .name = "text2", .kind = .text, .len = 24_000, .seed = 32 },
    .{ .name = "runs600", .kind = .runs, .len = 30_000, .seed = 33, .param = 600 },
    .{ .name = "text3", .kind = .text, .len = 60_000, .seed = 34 },
    .{ .name = "noisy25", .kind = .noisy_text, .len = 40_000, .seed = 35, .param = 25 },
};

const pin2_opts = [_]block.CompressOptions{
    .{ .hc_level = 3 },
    .{ .hc_level = 5 },
    .{ .hc_level = 9 },
    .{ .hc_level = 10 },
    .{ .hc_level = 11 },
};

const pins2 = [_]Pin{
    .{ .len = 18678, .hash = 0x99755f2333d111bd }, // pin2 noisy4 level 3
    .{ .len = 18470, .hash = 0x5e21494703ae0af7 }, // pin2 noisy4 level 5
    .{ .len = 18467, .hash = 0x3fb2db9334b8a65c }, // pin2 noisy4 level 9
    .{ .len = 18397, .hash = 0x96245aa09e32870e }, // pin2 noisy4 level 10
    .{ .len = 18397, .hash = 0x96245aa09e32870e }, // pin2 noisy4 level 11
    .{ .len = 8329, .hash = 0xacae7955921ad340 }, // pin2 text2 level 3
    .{ .len = 7511, .hash = 0xd79567f82f8007c9 }, // pin2 text2 level 5
    .{ .len = 7349, .hash = 0x82f1184df7c25fd6 }, // pin2 text2 level 9
    .{ .len = 7250, .hash = 0x14f5703eda658cdb }, // pin2 text2 level 10
    .{ .len = 7192, .hash = 0xdf72282597770bba }, // pin2 text2 level 11
    .{ .len = 518, .hash = 0xe6ea07fcb5f92894 }, // pin2 runs600 level 3
    .{ .len = 518, .hash = 0xe6ea07fcb5f92894 }, // pin2 runs600 level 5
    .{ .len = 510, .hash = 0xb8c667cba969cb58 }, // pin2 runs600 level 9
    .{ .len = 552, .hash = 0x47bf0b758b2c7557 }, // pin2 runs600 level 10
    .{ .len = 526, .hash = 0x7a47373896064997 }, // pin2 runs600 level 11
    .{ .len = 19720, .hash = 0xac43e7c3eaa66c7d }, // pin2 text3 level 3
    .{ .len = 17395, .hash = 0x4cb83c4b6cc484fd }, // pin2 text3 level 5
    .{ .len = 16277, .hash = 0xc7c86ba9e1459883 }, // pin2 text3 level 9
    .{ .len = 16528, .hash = 0x13dd3a9e9b454b31 }, // pin2 text3 level 10
    .{ .len = 15839, .hash = 0x43970cedea26ece }, // pin2 text3 level 11
    .{ .len = 16771, .hash = 0x256ce4829a73cac3 }, // pin2 noisy25 level 3
    .{ .len = 15488, .hash = 0x26edb1d8600875b5 }, // pin2 noisy25 level 5
    .{ .len = 15063, .hash = 0x30a077ffb94f0e59 }, // pin2 noisy25 level 9
    .{ .len = 14945, .hash = 0x83639c6bb7c351f9 }, // pin2 noisy25 level 10
    .{ .len = 14771, .hash = 0xd1e21592990c6aa3 }, // pin2 noisy25 level 11
};

test "mutation 2026-11-25: the HC and optimal encoders' output on more inputs is the recorded one" {
    var missing: usize = 0;
    var idx: usize = 0;
    for (pin2_inputs) |sh| {
        const input = try shapes.generate(gpa, sh);
        defer gpa.free(input);
        for (pin2_opts) |o| {
            defer idx += 1;
            const z = try compressAlloc(input, o);
            defer gpa.free(z);
            try expectRoundTrip(input, z);
            const got: Pin = .{ .len = @intCast(z.len), .hash = std.hash.Wyhash.hash(0, z) };
            if (idx >= pins2.len) {
                std.debug.print(".{{ .len = {d}, .hash = 0x{x} }}, // pin2 {s} level {d}\n", .{ got.len, got.hash, sh.name, o.hc_level });
                missing += 1;
            } else if (got.len != pins2[idx].len or got.hash != pins2[idx].hash) {
                std.debug.print("pin2 {d} ({s}, level {d}): {d} bytes, hash 0x{x}\n", .{ idx, sh.name, o.hc_level, got.len, got.hash });
                missing += 1;
            }
        }
    }
    try testing.expectEqual(@as(usize, 0), missing);
}

test "mutation 2026-11-25: the lazy parse stops looking after improving on a match of 256 bytes or more" {
    var prng = std.Random.DefaultPrng.init(0x110);
    const r = prng.random();
    var t: [520]u8 = undefined;
    r.bytes(&t);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    var gap: [8]u8 = undefined;
    // X holds t[0..300], Y holds t[1..401] and W holds t[2..502]; each is
    // preceded and followed by a byte that is not the one in t, so the match
    // at the start of t is 300 bytes, one byte on 400, two bytes on 500.
    try buf.appendSlice(gpa, t[0..300]);
    try buf.append(gpa, ~t[300]);
    r.bytes(&gap);
    try buf.appendSlice(gpa, &gap);
    try buf.append(gpa, ~t[0]);
    try buf.appendSlice(gpa, t[1..401]);
    try buf.append(gpa, ~t[401]);
    r.bytes(&gap);
    try buf.appendSlice(gpa, &gap);
    try buf.append(gpa, ~t[1]);
    try buf.appendSlice(gpa, t[2..502]);
    try buf.append(gpa, ~t[502]);
    r.bytes(&gap);
    try buf.appendSlice(gpa, &gap);
    try buf.appendSlice(gpa, &t);
    var tail: [16]u8 = undefined;
    r.bytes(&tail);
    try buf.appendSlice(gpa, &tail);
    for ([_]u8{ 3, 6, 9 }) |level| {
        const z = try compressAlloc(buf.items, .{ .hc_level = level });
        defer gpa.free(z);
        try expectRoundTrip(buf.items, z);
        const w = try walk(z);
        var has400 = false;
        var has500 = false;
        for (w.seqs[0..w.n]) |q| {
            has400 = has400 or q.ml == 400;
            has500 = has500 or q.ml == 500;
        }
        try testing.expect(has400);
        try testing.expect(!has500);
    }
}

test "mutation 2026-11-25: decoding a block with an empty dictionary allocates nothing" {
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try lz4.decompressBlockDict(failing.allocator(), "\x10a", "", &out));
    try testing.expectEqualStrings("a", out[0..1]);
}

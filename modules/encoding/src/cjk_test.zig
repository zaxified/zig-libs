// SPDX-License-Identifier: MIT
//! Evidence for `cjk.zig`:
//!  1. the generated tables anchored to the vendored WHATWG index files,
//!     through the PUBLIC decoders/encoders: every pointer of every index
//!     decodes to its code point, every code point encodes to the pointer the
//!     Standard selects, every hole and every unencodable code point is
//!     rejected;
//!  2. a differential oracle replayed from `cjk_oracle_vectors.zig`
//!     (golang.org/x/text over ~3.6 million generated cases; see
//!     tools/cjk_oracle) -- ours equals the Standard everywhere and equals
//!     Go everywhere except the classified divergences;
//!  3. hand-checked sample text;
//!  4. streaming: the whole-buffer answer at every split point and for every
//!     output room >= the headroom.

const std = @import("std");
const testing = std.testing;
const cjk = @import("cjk.zig");
const core = @import("core.zig");
const t = @import("cjk_tables.zig");
const vec = @import("cjk_oracle_vectors.zig");

const Cjk = cjk.Cjk;
const all = [_]Cjk{ .shift_jis, .euc_jp, .iso_2022_jp, .euc_kr, .gb18030, .gbk, .big5 };

// ── small helpers ───────────────────────────────────────────────────────────

fn utf8Of(cp: u21, buf: *[4]u8) []const u8 {
    const n = std.unicode.utf8Encode(cp, buf) catch unreachable;
    return buf[0..n];
}

/// Decode `bytes` in one call into `out` (large enough); lenient.
fn dec(enc: Cjk, bytes: []const u8, out: []u8) []const u8 {
    var d: cjk.Decoder = .init(enc, .{});
    const p = d.decodeInto(bytes, out, true);
    std.debug.assert(p.status == .input_empty and p.read == bytes.len);
    return out[0..p.written];
}

/// Encode `utf8` in one call into `out`; null when unmappable (`.fatal`).
fn encFatal(enc: Cjk, utf8: []const u8, out: []u8) ?[]const u8 {
    var e: cjk.Encoder = .init(enc, .{ .unmappable = .fatal });
    const p = e.encodeInto(utf8, out, true);
    return switch (p.status) {
        .input_empty => out[0..p.written],
        .unmappable => null,
        .output_full => unreachable,
    };
}

const Index = struct {
    /// cp or null per pointer.
    cps: []?u21,
    fn deinit(self: Index, a: std.mem.Allocator) void {
        a.free(self.cps);
    }
};

fn loadIndex(a: std.mem.Allocator, text: []const u8) !Index {
    var list: std.ArrayList(?u21) = .empty;
    errdefer list.deinit(a);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.splitScalar(u8, line, '\t');
        const p = try std.fmt.parseInt(usize, std.mem.trim(u8, f.next().?, " "), 10);
        const c = try std.fmt.parseInt(u21, std.mem.trim(u8, f.next().?, " ")[2..], 16);
        while (list.items.len <= p) try list.append(a, null);
        try testing.expect(list.items[p] == null);
        list.items[p] = c;
    }
    return .{ .cps = try list.toOwnedSlice(a) };
}

/// First pointer per code point, honouring `skip` (the Standard's exclusions).
fn firstPointers(a: std.mem.Allocator, idx: Index, comptime skip: fn (usize) bool) !std.AutoHashMap(u21, usize) {
    var m = std.AutoHashMap(u21, usize).init(a);
    errdefer m.deinit();
    for (idx.cps, 0..) |maybe, p| {
        const c = maybe orelse continue;
        if (skip(p)) continue;
        const r = try m.getOrPut(c);
        if (!r.found_existing) r.value_ptr.* = p;
    }
    return m;
}

fn noSkip(_: usize) bool {
    return false;
}
fn sjisSkip(p: usize) bool {
    return p >= 8272 and p <= 8835;
}
fn big5Skip(p: usize) bool {
    return p < (0xA1 - 0x81) * 157;
}

// pointer -> bytes, the Standard's byte formulas.
fn bytes94(ptr: usize, base: u8, out: []u8) []u8 {
    out[0] = @intCast(ptr / 94 + base);
    out[1] = @intCast(ptr % 94 + base);
    return out[0..2];
}
fn bytesSjis(ptr: usize, out: []u8) []u8 {
    const leading = ptr / 188;
    const trailing = ptr % 188;
    out[0] = @intCast(leading + @as(usize, if (leading < 0x1F) 0x81 else 0xC1));
    out[1] = @intCast(trailing + @as(usize, if (trailing < 0x3F) 0x40 else 0x41));
    return out[0..2];
}
fn bytesKr(ptr: usize, out: []u8) []u8 {
    out[0] = @intCast(ptr / 190 + 0x81);
    out[1] = @intCast(ptr % 190 + 0x41);
    return out[0..2];
}
fn bytesGb(ptr: usize, out: []u8) []u8 {
    const tr = ptr % 190;
    out[0] = @intCast(ptr / 190 + 0x81);
    out[1] = @intCast(tr + @as(usize, if (tr < 0x3F) 0x40 else 0x41));
    return out[0..2];
}
fn bytesBig5(ptr: usize, out: []u8) []u8 {
    const tr = ptr % 157;
    out[0] = @intCast(ptr / 157 + 0x81);
    out[1] = @intCast(tr + @as(usize, if (tr < 0x3F) 0x40 else 0x62));
    return out[0..2];
}

/// Expected decode of a two-byte string whose pointer is a hole: one U+FFFD,
/// then the trail byte when it is ASCII (the Standard restores it).
fn expectHole(enc: Cjk, b: []const u8) !void {
    var buf: [16]u8 = undefined;
    const got = dec(enc, b, &buf);
    var want: [4]u8 = undefined;
    @memcpy(want[0..3], core.replacement);
    var n: usize = 3;
    if (b[1] < 0x80) {
        want[3] = b[1];
        n = 4;
    }
    try testing.expectEqualSlices(u8, want[0..n], got);
}

fn expectCp(enc: Cjk, b: []const u8, cp: u21) !void {
    var buf: [16]u8 = undefined;
    var u: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, utf8Of(cp, &u), dec(enc, b, &buf));
}

fn expectEnc(enc: Cjk, cp: u21, want: ?[]const u8) !void {
    var u: [4]u8 = undefined;
    var buf: [32]u8 = undefined;
    const got = encFatal(enc, utf8Of(cp, &u), &buf);
    if (want) |w| {
        try testing.expect(got != null);
        try testing.expectEqualSlices(u8, w, got.?);
    } else try testing.expect(got == null);
}

// ── 1. tables anchored to the vendored index files ──────────────────────────

test "tables: the decode arrays are exactly the vendored index files" {
    const a = testing.allocator;
    const Pair = struct { text: []const u8, dec: []const u16, base: usize };
    const sets = [_]Pair{
        .{ .text = @embedFile("testdata/index-jis0208.txt"), .dec = &t.jis0208_dec, .base = 0 },
        .{ .text = @embedFile("testdata/index-jis0212.txt"), .dec = &t.jis0212_dec, .base = t.jis0212_base },
        .{ .text = @embedFile("testdata/index-iso-2022-jp-katakana.txt"), .dec = &t.katakana_dec, .base = 0 },
        .{ .text = @embedFile("testdata/index-euc-kr.txt"), .dec = &t.euckr_dec, .base = 0 },
        .{ .text = @embedFile("testdata/index-gb18030.txt"), .dec = &t.gb_dec, .base = 0 },
    };
    for (sets) |s| {
        const idx = try loadIndex(a, s.text);
        defer idx.deinit(a);
        try testing.expectEqual(s.base + s.dec.len, idx.cps.len);
        for (s.dec, 0..) |v, i| {
            const want: u16 = if (idx.cps[s.base + i]) |c| @intCast(c) else 0xFFFF;
            try testing.expectEqual(want, v);
        }
        for (idx.cps[0..s.base]) |c| try testing.expect(c == null);
    }
    // Big5: low 16 bits and the plane bit.
    const idx = try loadIndex(a, @embedFile("testdata/index-big5.txt"));
    defer idx.deinit(a);
    try testing.expectEqual(@as(usize, t.big5_base) + t.big5_dec.len, idx.cps.len);
    var sip: usize = 0;
    for (t.big5_dec, 0..) |v, i| {
        const bit = (t.big5_sip[i / 8] >> @intCast(i % 8)) & 1;
        sip += bit;
        const want: u21 = idx.cps[t.big5_base + i] orelse {
            try testing.expectEqual(@as(u16, 0xFFFF), v);
            try testing.expectEqual(@as(u8, 0), bit);
            continue;
        };
        try testing.expectEqual(want, @as(u21, v) | (@as(u21, bit) << 17));
    }
    try testing.expectEqual(@as(usize, 1713), sip);
    for (idx.cps[0..t.big5_base]) |c| try testing.expect(c == null);
    // gb18030 ranges: both columns, ascending.
    const gr = try loadIndex(a, @embedFile("testdata/index-gb18030-ranges.txt"));
    defer gr.deinit(a);
    var k: usize = 0;
    for (gr.cps, 0..) |maybe, p| {
        const c = maybe orelse continue;
        try testing.expectEqual(@as(u32, @intCast(p)), t.gb_ranges_ptr[k]);
        try testing.expectEqual(@as(u32, c), t.gb_ranges_cp[k]);
        k += 1;
    }
    try testing.expectEqual(t.gb_ranges_ptr.len, k);
}

test "decode: every pointer of every index through the public decoders; every hole is an error" {
    const a = testing.allocator;
    var b: [4]u8 = undefined;

    // jis0208 via EUC-JP, ISO-2022-JP (< 8836) and Shift_JIS (all pointers).
    const j8 = try loadIndex(a, @embedFile("testdata/index-jis0208.txt"));
    defer j8.deinit(a);
    for (0..j8.cps.len) |p| {
        if (p < 8836) {
            const eb = bytes94(p, 0xA1, &b);
            if (j8.cps[p]) |c| try expectCp(.euc_jp, eb, c) else try expectHole(.euc_jp, eb);
            var iso: [8]u8 = undefined;
            @memcpy(iso[0..3], "\x1b$B");
            @memcpy(iso[3..5], bytes94(p, 0x21, &b));
            var buf: [16]u8 = undefined;
            var u: [4]u8 = undefined;
            if (j8.cps[p]) |c| {
                try testing.expectEqualSlices(u8, utf8Of(c, &u), dec(.iso_2022_jp, iso[0..5], &buf));
            } else {
                // the pointer is an error; the lead and trail bytes are consumed, no ASCII leaks
                try testing.expectEqualSlices(u8, core.replacement, dec(.iso_2022_jp, iso[0..5], &buf));
            }
        }
        // Shift_JIS: EUDC pointers are Private Use, not jis0208 holes.
        const sb = bytesSjis(p, &b);
        if (p >= 8836 and p <= 10715) {
            try testing.expect(j8.cps[p] == null);
            try expectCp(.shift_jis, sb, @intCast(0xE000 - 8836 + p));
        } else if (j8.cps[p]) |c| try expectCp(.shift_jis, sb, c) else try expectHole(.shift_jis, sb);
    }
    // jis0212 via 0x8F.
    const j12 = try loadIndex(a, @embedFile("testdata/index-jis0212.txt"));
    defer j12.deinit(a);
    for (0..8836) |p| {
        var eb: [3]u8 = undefined;
        eb[0] = 0x8F;
        @memcpy(eb[1..3], bytes94(p, 0xA1, &b));
        const cp: ?u21 = if (p < j12.cps.len) j12.cps[p] else null;
        var buf: [16]u8 = undefined;
        if (cp) |c| {
            var u: [4]u8 = undefined;
            try testing.expectEqualSlices(u8, utf8Of(c, &u), dec(.euc_jp, &eb, &buf));
        } else try testing.expectEqualSlices(u8, core.replacement, dec(.euc_jp, &eb, &buf));
    }
    // EUC-KR, gb18030/GBK (pointer grid 190 wide), Big5 (157 wide).
    const kr = try loadIndex(a, @embedFile("testdata/index-euc-kr.txt"));
    defer kr.deinit(a);
    for (0..126 * 190) |p| {
        const eb = bytesKr(p, &b);
        if (p < kr.cps.len and kr.cps[p] != null) try expectCp(.euc_kr, eb, kr.cps[p].?) else try expectHole(.euc_kr, eb);
    }
    const gb = try loadIndex(a, @embedFile("testdata/index-gb18030.txt"));
    defer gb.deinit(a);
    for (0..126 * 190) |p| {
        const eb = bytesGb(p, &b);
        for ([_]Cjk{ .gb18030, .gbk }) |e| {
            if (p < gb.cps.len and gb.cps[p] != null) try expectCp(e, eb, gb.cps[p].?) else try expectHole(e, eb);
        }
    }
    const b5 = try loadIndex(a, @embedFile("testdata/index-big5.txt"));
    defer b5.deinit(a);
    for (0..126 * 157) |p| {
        const eb = bytesBig5(p, &b);
        switch (p) {
            1133, 1135, 1164, 1166 => {
                // two code points; the index has no entry for them
                try testing.expect(p >= b5.cps.len or b5.cps[p] == null);
                var buf: [16]u8 = undefined;
                const got = dec(.big5, eb, &buf);
                try testing.expectEqual(@as(usize, 4), got.len);
                const base: u21 = if (p < 1150) 0xCA else 0xEA;
                const mark: u21 = if (p == 1133 or p == 1164) 0x304 else 0x30C;
                var ub1: [4]u8 = undefined;
                var ub2: [4]u8 = undefined;
                try testing.expectEqualSlices(u8, utf8Of(base, &ub1), got[0..2]);
                try testing.expectEqualSlices(u8, utf8Of(mark, &ub2), got[2..4]);
            },
            else => if (p < b5.cps.len and b5.cps[p] != null) try expectCp(.big5, eb, b5.cps[p].?) else try expectHole(.big5, eb),
        }
    }
}

test "encode: every code point of every index gets the pointer the Standard selects; the rest is unmappable" {
    const a = testing.allocator;
    var b: [4]u8 = undefined;
    var out: [32]u8 = undefined;

    // jis0208: EUC-JP / ISO-2022-JP use the first pointer, Shift_JIS the first outside 8272..8835.
    const j8 = try loadIndex(a, @embedFile("testdata/index-jis0208.txt"));
    defer j8.deinit(a);
    var first = try firstPointers(a, j8, noSkip);
    defer first.deinit();
    var sj_first = try firstPointers(a, j8, sjisSkip);
    defer sj_first.deinit();
    var cp: u21 = 0x80;
    while (cp < 0x10000) : (cp += 1) {
        if (cp >= 0xD800 and cp <= 0xDFFF) continue;
        // the encoders' own special cases come first, in every Japanese encoder
        const special = cp == 0xA5 or cp == 0x203E or cp == 0x2212 or (cp >= 0xFF61 and cp <= 0xFF9F) or cp == 0x80;
        if (special) continue;
        if (first.get(cp)) |p| {
            try expectEnc(.euc_jp, cp, bytes94(p, 0xA1, &b));
            var iso: [8]u8 = undefined;
            @memcpy(iso[0..3], "\x1b$B");
            @memcpy(iso[3..5], bytes94(p, 0x21, &b));
            @memcpy(iso[5..8], "\x1b(B");
            try expectEnc(.iso_2022_jp, cp, &iso);
        } else {
            try expectEnc(.euc_jp, cp, null);
            try expectEnc(.iso_2022_jp, cp, null);
        }
        if (sj_first.get(cp)) |p| try expectEnc(.shift_jis, cp, bytesSjis(p, &b)) else try expectEnc(.shift_jis, cp, null);
    }
    // the special cases
    try expectEnc(.shift_jis, 0x80, "\x80");
    try expectEnc(.shift_jis, 0xA5, "\x5c");
    try expectEnc(.shift_jis, 0x203E, "\x7e");
    try expectEnc(.shift_jis, 0x2212, "\x81\x7c"); // -> U+FF0D
    try expectEnc(.shift_jis, 0xFF61, "\xa1");
    try expectEnc(.shift_jis, 0xFF9F, "\xdf");
    try expectEnc(.euc_jp, 0xA5, "\x5c");
    try expectEnc(.euc_jp, 0x203E, "\x7e");
    try expectEnc(.euc_jp, 0x2212, "\xa1\xdd");
    try expectEnc(.euc_jp, 0xFF61, "\x8e\xa1");
    try expectEnc(.euc_jp, 0xFF9F, "\x8e\xdf");
    try expectEnc(.euc_jp, 0x80, null);
    try expectEnc(.shift_jis, 0x3042, "\x82\xa0");
    // ISO-2022-JP katakana: half-width -> the index code point -> jis0208 pointer
    var kata_seen: usize = 0;
    for (t.katakana_dec, 0..) |full, i| {
        const p = first.get(full).?;
        var iso: [8]u8 = undefined;
        @memcpy(iso[0..3], "\x1b$B");
        @memcpy(iso[3..5], bytes94(p, 0x21, &b));
        @memcpy(iso[5..8], "\x1b(B");
        try expectEnc(.iso_2022_jp, @intCast(0xFF61 + i), &iso);
        kata_seen += 1;
    }
    try testing.expectEqual(@as(usize, 63), kata_seen);

    // EUC-KR
    const kr = try loadIndex(a, @embedFile("testdata/index-euc-kr.txt"));
    defer kr.deinit(a);
    var kfirst = try firstPointers(a, kr, noSkip);
    defer kfirst.deinit();
    cp = 0x80;
    while (cp < 0x10000) : (cp += 1) {
        if (cp >= 0xD800 and cp <= 0xDFFF) continue;
        if (kfirst.get(cp)) |p| try expectEnc(.euc_kr, cp, bytesKr(p, &b)) else try expectEnc(.euc_kr, cp, null);
    }
    // Big5: pointers below 5024 excluded; six code points take the last pointer.
    const b5 = try loadIndex(a, @embedFile("testdata/index-big5.txt"));
    defer b5.deinit(a);
    var bfirst = try firstPointers(a, b5, big5Skip);
    defer bfirst.deinit();
    for ([_]u21{ 0x2550, 0x255E, 0x2561, 0x256A, 0x5341, 0x5345 }) |c| {
        var last: usize = 0;
        for (b5.cps, 0..) |m, p| if (m != null and m.? == c and p >= 5024) {
            last = p;
        };
        bfirst.getPtr(c).?.* = last;
    }
    var it = bfirst.iterator();
    var n_b5: usize = 0;
    while (it.next()) |e| {
        try expectEnc(.big5, e.key_ptr.*, bytesBig5(e.value_ptr.*, &b));
        n_b5 += 1;
    }
    try testing.expectEqual(@as(usize, t.big5_enc.len), n_b5);
    cp = 0x80;
    while (cp < 0x30000) : (cp += 1) {
        if (cp >= 0xD800 and cp <= 0xDFFF) continue;
        if (!bfirst.contains(cp)) try expectEnc(.big5, cp, null);
    }
    // gb18030 / GBK: index pointers, the side table, E5E5, U+20AC, ranges.
    const gb = try loadIndex(a, @embedFile("testdata/index-gb18030.txt"));
    defer gb.deinit(a);
    var gfirst = try firstPointers(a, gb, noSkip);
    defer gfirst.deinit();
    cp = 0x80;
    while (cp < 0x10000) : (cp += 1) {
        if (cp >= 0xD800 and cp <= 0xDFFF) continue;
        const side = (cp >= 0xE78D and cp <= 0xE796) or cp == 0xE81E or cp == 0xE826 or cp == 0xE82B or cp == 0xE82C or cp == 0xE832 or cp == 0xE843 or cp == 0xE854 or cp == 0xE864;
        if (side or cp == 0xE5E5 or cp == 0x20AC) continue;
        if (gfirst.get(cp)) |p| {
            try expectEnc(.gb18030, cp, bytesGb(p, &b));
            try expectEnc(.gbk, cp, bytesGb(p, &b));
        } else {
            try expectEnc(.gbk, cp, null);
            const four = encFatal(.gb18030, utf8Of(cp, &b), &out).?;
            try testing.expectEqual(@as(usize, 4), four.len);
        }
    }
    try expectEnc(.gb18030, 0xE5E5, null);
    try expectEnc(.gbk, 0xE5E5, null);
    try expectEnc(.gbk, 0x20AC, "\x80");
    try expectEnc(.gb18030, 0x20AC, "\xa2\xe3");
    try expectEnc(.gb18030, 0xE78D, "\xa6\xd9");
    try expectEnc(.gbk, 0xE864, "\xfe\xa0");
    try expectEnc(.gb18030, 0x10000, "\x90\x30\x81\x30");
    try expectEnc(.gb18030, 0x10FFFF, "\xe3\x32\x9a\x35");
    try expectEnc(.gbk, 0x10000, null);
    try expectEnc(.gb18030, 0xE7C7, "\x81\x35\xf4\x37");
}

test "gb18030: every code point except U+E5E5 round-trips through the four-byte ranges and the index" {
    var out: [32]u8 = undefined;
    var back: [16]u8 = undefined;
    var u: [4]u8 = undefined;
    var cp: u21 = 0;
    while (cp <= 0x10FFFF) : (cp += 1) {
        if (cp >= 0xD800 and cp <= 0xDFFF) continue;
        const s = utf8Of(cp, &u);
        // The side table and U+E5E5 do not round-trip by design (Standard 10.2.2).
        const side = (cp >= 0xE78D and cp <= 0xE796) or cp == 0xE81E or cp == 0xE826 or cp == 0xE82B or cp == 0xE82C or cp == 0xE832 or cp == 0xE843 or cp == 0xE854 or cp == 0xE864;
        if (side) {
            _ = encFatal(.gb18030, s, &out).?;
            continue;
        }
        if (cp == 0xE5E5) {
            try testing.expect(encFatal(.gb18030, s, &out) == null);
            continue;
        }
        const e = encFatal(.gb18030, s, &out).?;
        try testing.expectEqualSlices(u8, s, dec(.gb18030, e, &back));
    }
}

test "Big5 encoder never writes an HKSCS lead byte; Big5-HKSCS bytes still decode" {
    var out: [32]u8 = undefined;
    var u: [4]u8 = undefined;
    var cp: u21 = 0x80;
    while (cp < 0x30000) : (cp += 1) {
        if (cp >= 0xD800 and cp <= 0xDFFF) continue;
        if (encFatal(.big5, utf8Of(cp, &u), &out)) |e| try testing.expect(e[0] >= 0xA1);
    }
    try expectCp(.big5, "\x88\x59", 0xC0); // HKSCS: lead 0x88 decodes (and U+00C0 does not encode)
    try expectEnc(.big5, 0xC0, null);
}

// ── 2. the differential oracle ──────────────────────────────────────────────

fn recordHash(h: *std.crypto.hash.sha2.Sha256, a: ?[]const u8) void {
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, if (a) |x| @intCast(x.len) else 0xFFFFFFFF, .little);
    h.update(&len);
    if (a) |x| h.update(x);
}

fn hexOf(h: *std.crypto.hash.sha2.Sha256) [64]u8 {
    var d: [32]u8 = undefined;
    h.final(&d);
    return std.fmt.bytesToHex(d, .lower);
}

fn encOf(name: []const u8) Cjk {
    return std.meta.stringToEnum(Cjk, name).?;
}

/// The code point of e1 case `i` (the oracle's list: all of U+0000..U+2FFFF
/// but the surrogates, then every 7th from U+30000, then U+10FFFF).
fn e1Cp(i: u32) u21 {
    if (i < 0x2F800) return if (i < 0xD800) @intCast(i) else @intCast(i + 0x800);
    const k = i - 0x2F800;
    if (k <= 131071) return @intCast(0x30000 + 7 * k);
    return 0x10FFFF;
}

/// Our answer for case `i` of `domain`; null = error/unmappable.
fn ours(enc: Cjk, domain: []const u8, i: u32, out: []u8) ?[]const u8 {
    var inb: [4]u8 = undefined;
    if (std.mem.eql(u8, domain, "e1")) {
        var u: [4]u8 = undefined;
        return encFatal(enc, utf8Of(e1Cp(i), &u), out);
    }
    if (std.mem.eql(u8, domain, "e2")) {
        var e: cjk.Encoder = .init(enc, .{ .unmappable = .html_ncr });
        const p = e.encodeInto(vec.e2_inputs[i], out, true);
        std.debug.assert(p.status == .input_empty);
        return out[0..p.written];
    }
    const src: []const u8 = if (std.mem.eql(u8, domain, "d1")) blk: {
        inb[0] = @intCast(i);
        break :blk inb[0..1];
    } else if (std.mem.eql(u8, domain, "d2")) blk: {
        inb[0] = @intCast(i >> 8);
        inb[1] = @intCast(i & 255);
        break :blk inb[0..2];
    } else if (std.mem.eql(u8, domain, "d3")) blk: {
        inb[0] = 0x8F;
        inb[1] = @intCast(i >> 8);
        inb[2] = @intCast(i & 255);
        break :blk inb[0..3];
    } else if (std.mem.eql(u8, domain, "d4")) blk: {
        inb[0] = @intCast(0x81 + i / 12600);
        inb[1] = @intCast(0x30 + (i / 1260) % 10);
        inb[2] = @intCast(0x81 + (i / 10) % 126);
        inb[3] = @intCast(0x30 + i % 10);
        break :blk inb[0..4];
    } else if (std.mem.eql(u8, domain, "d5")) vec.d5_inputs[i] else vec.d6_inputs[i];
    return dec(enc, src, out);
}

test "oracle: ours == the Standard everywhere, ours == golang.org/x/text off the classified divergences" {
    var total: u64 = 0;
    var total_div: u64 = 0;
    for (vec.results) |res| {
        const enc = encOf(res.enc);
        var h_all = std.crypto.hash.sha2.Sha256.init(.{});
        var h_agree = std.crypto.hash.sha2.Sha256.init(.{});
        var h_div = std.crypto.hash.sha2.Sha256.init(.{});
        var out: [1024]u8 = undefined;
        var run: usize = 0; // index into res.runs (pairs)
        var in_div: u32 = 0;
        var i: u32 = 0;
        while (i < res.cases) : (i += 1) {
            while (run < res.runs.len and i >= res.runs[run] + res.runs[run + 1]) run += 2;
            const diverges = run < res.runs.len and i >= res.runs[run];
            const a = ours(enc, res.domain, i, &out);
            recordHash(&h_all, a);
            if (diverges) {
                recordHash(&h_div, a);
                in_div += 1;
            } else recordHash(&h_agree, a);
        }
        testing.expectEqualStrings(res.std_sha256, &hexOf(&h_all)) catch |e| {
            std.debug.print("oracle mismatch vs the Standard: {s} {s}\n", .{ res.enc, res.domain });
            return e;
        };
        testing.expectEqualStrings(res.go_agree_sha256, &hexOf(&h_agree)) catch |e| {
            std.debug.print("oracle mismatch vs Go off the divergences: {s} {s}\n", .{ res.enc, res.domain });
            return e;
        };
        testing.expectEqualStrings(res.std_div_sha256, &hexOf(&h_div)) catch |e| {
            std.debug.print("oracle mismatch vs the Standard on the divergences: {s} {s}\n", .{ res.enc, res.domain });
            return e;
        };
        try testing.expectEqual(res.diverging, in_div);
        // every divergence belongs to exactly one class
        var counted: u32 = 0;
        for (vec.classes) |c| {
            if (std.mem.eql(u8, c.enc, res.enc) and std.mem.eql(u8, c.domain, res.domain)) counted += c.count;
        }
        try testing.expectEqual(res.diverging, counted);
        total += res.cases;
        total_div += res.diverging;
    }
    // every class has a documented rule
    for (vec.classes) |c| {
        var found = false;
        for (vec.rules) |r| found = found or std.mem.eql(u8, r.name, c.name);
        try testing.expect(found);
    }
    try testing.expect(total > 3_000_000);
    try testing.expect(total_div > 0);
}

test "oracle: EUC-KR agrees with golang.org/x/text on every case (no divergence)" {
    for (vec.results) |res| {
        if (std.mem.eql(u8, res.enc, "euc_kr")) try testing.expectEqual(@as(u32, 0), res.diverging);
    }
}

// ── 3. sample text ──────────────────────────────────────────────────────────

fn expectBoth(enc: Cjk, bytes: []const u8, text: []const u8) !void {
    const a = testing.allocator;
    const d = try cjk.decodeToUtf8(a, bytes, enc);
    defer a.free(d);
    try testing.expectEqualStrings(text, d);
    const e = try cjk.encodeFromUtf8(a, text, enc, .{ .unmappable = .fatal });
    defer a.free(e);
    try testing.expectEqualSlices(u8, bytes, e);
}

test "samples: text in every encoding, both directions" {
    try expectBoth(.shift_jis, "\x93\xfa\x96\x7b\x8c\xea abc \xb1\xb2", "日本語 abc ｱｲ");
    try expectBoth(.euc_jp, "\xc6\xfc\xcb\xdc\xb8\xec abc \x8e\xb1\x8e\xb2", "日本語 abc ｱｲ");
    try expectBoth(.iso_2022_jp, "\x1b$BF|K\\8l\x1b(B abc", "日本語 abc");
    try expectBoth(.euc_kr, "\xc7\xd1\xb1\xb9\xbe\xee abc", "한국어 abc");
    try expectBoth(.gb18030, "\xd6\xd0\xce\xc4 abc \x90\x30\x81\x30", "中文 abc \u{10000}");
    try expectBoth(.gbk, "\xd6\xd0\xce\xc4 abc \x80", "中文 abc €");
    try expectBoth(.big5, "\xa4\xa4\xa4\xe5 abc", "中文 abc");
}

test "samples: Big5 two-code-point pointers decode but the encoder never writes them" {
    const a = testing.allocator;
    const d = try cjk.decodeToUtf8(a, "\x88\x62\x88\x64\x88\xa3\x88\xa5", .big5);
    defer a.free(d);
    try testing.expectEqualStrings("\u{CA}\u{304}\u{CA}\u{30C}\u{EA}\u{304}\u{EA}\u{30C}", d);
    // U+00CA alone has no Big5 pointer >= 5024 (it is HKSCS only)
    try expectEnc(.big5, 0xCA, null);
}

test "samples: the ISO-2022-JP encoder, the Standard's own example (U+00A5 twice)" {
    const a = testing.allocator;
    const e = try cjk.encodeFromUtf8(a, "\u{A5}", .iso_2022_jp, .{});
    defer a.free(e);
    try testing.expectEqualSlices(u8, "\x1b(J\x5c\x1b(B", e);
    const twice = try std.mem.concat(a, u8, &.{ e, e });
    defer a.free(twice);
    const d = try cjk.decodeToUtf8(a, twice, .iso_2022_jp);
    defer a.free(d);
    // concatenated outputs decode to U+00A5 U+FFFD U+00A5 (the repeated ESC ( J... is an error)
    try testing.expectEqualStrings("\u{A5}\u{FFFD}\u{A5}", d);
}

test "samples: ISO-2022-JP states, katakana, Roman, errors" {
    const a = testing.allocator;
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "A\x1b(JB\\~\x1b(B\\~", "AB\u{A5}\u{203E}\\~" },
        .{ "\x1b(I1\x1b(B", "\u{FF71}" },
        .{ "\x1b$B$\"\x1b(B", "\u{3042}" },
        .{ "\x1b$@$\"\x1b(B", "\u{3042}" },
        .{ "\x0e", "\u{FFFD}" },
        .{ "\x1b$(D", "\u{FFFD}$(D" },
        .{ "\x1b$B$\"", "\u{3042}" },
        .{ "\x1b$B$", "\u{FFFD}" },
        .{ "\x1b", "\u{FFFD}" },
        .{ "\x80", "\u{FFFD}" },
    };
    for (cases) |c| {
        const d = try cjk.decodeToUtf8(a, c[0], .iso_2022_jp);
        defer a.free(d);
        try testing.expectEqualStrings(c[1], d);
    }
}

test "samples: encoder error modes" {
    const a = testing.allocator;
    const Mode = core.Unmappable;
    // U+1F600 is in no CJK index except gb18030's ranges
    const cases = [_]struct { Cjk, Mode, []const u8, []const u8 }{
        .{ .euc_kr, .html_ncr, "a\u{1F600}b", "a&#128512;b" },
        .{ .euc_kr, .question_mark, "a\u{1F600}b", "a?b" },
        .{ .euc_kr, .ignore, "a\u{1F600}b", "ab" },
        .{ .shift_jis, .html_ncr, "\u{3042}\u{1F600}", "\x82\xa0&#128512;" },
        // jis0208 state is left (ESC ( B) before the reference, the reference is ASCII
        .{ .iso_2022_jp, .html_ncr, "\u{3042}\u{1F600}x", "\x1b$B$\"\x1b(B&#128512;x" },
        .{ .iso_2022_jp, .question_mark, "\u{3042}\u{1F600}x", "\x1b$B$\"\x1b(B?x" },
        // Roman state stays (no 0x5C / 0x7E in an NCR)
        .{ .iso_2022_jp, .html_ncr, "\u{A5}\u{1F600}", "\x1b(J\x5c&#128512;\x1b(B" },
        .{ .iso_2022_jp, .html_ncr, "a\x1b", "a&#65533;" },
        .{ .big5, .html_ncr, "\u{1F600}", "&#128512;" },
        .{ .gbk, .html_ncr, "\u{1F600}", "&#128512;" },
        .{ .gb18030, .html_ncr, "\u{1F600}\u{E5E5}", "\x94\x39\xfc\x36&#58853;" },
        // invalid UTF-8 is one U+FFFD per maximal subpart; U+FFFD itself is unmappable in EUC-KR
        .{ .euc_kr, .html_ncr, "a\xe3\x81b\xffc", "a&#65533;b&#65533;c" },
        .{ .euc_kr, .html_ncr, "\xf0\x9f\x98", "&#65533;" },
    };
    for (cases) |c| {
        const e = try cjk.encodeFromUtf8(a, c[2], c[0], .{ .unmappable = c[1] });
        defer a.free(e);
        try testing.expectEqualStrings(c[3], e);
    }
    try testing.expectError(error.Unmappable, cjk.encodeFromUtf8(a, "\u{1F600}", .euc_kr, .{ .unmappable = .fatal }));
}

test "fatal decoding: the first error stops, the decoder stays failed" {
    const a = testing.allocator;
    try testing.expectError(error.Malformed, cjk.decodeFatal(a, "ab\x81", .euc_kr)); // cut at the end
    try testing.expectError(error.Malformed, cjk.decodeFatal(a, "ab\xff", .shift_jis));
    try testing.expectError(error.Malformed, cjk.decodeFatal(a, "\x84\x31\xa5\x30", .gb18030)); // four-byte gap
    const ok = try cjk.decodeFatal(a, "\xa4\xa4\xa4\xe5", .big5);
    defer a.free(ok);
    try testing.expectEqualStrings("中文", ok);
    var d: cjk.Decoder = .init(.euc_kr, .{ .fatal = true });
    var buf: [32]u8 = undefined;
    const p = d.decodeInto("a\xff", &buf, true);
    try testing.expectEqual(core.Status.malformed, p.status);
    try testing.expectEqual(@as(usize, 1), p.written);
    try testing.expectEqual(core.Status.malformed, d.decodeInto("a", &buf, true).status);
}

test "labels and names" {
    try testing.expectEqual(Cjk.shift_jis, Cjk.fromLabel("  SJIS\r\n").?);
    try testing.expectEqual(Cjk.shift_jis, Cjk.fromLabel("windows-31j").?);
    try testing.expectEqual(Cjk.euc_jp, Cjk.fromLabel("x-euc-jp").?);
    try testing.expectEqual(Cjk.iso_2022_jp, Cjk.fromLabel("csiso2022jp").?);
    try testing.expectEqual(Cjk.euc_kr, Cjk.fromLabel("ks_c_5601-1989").?);
    try testing.expectEqual(Cjk.gbk, Cjk.fromLabel("gb2312").?);
    try testing.expectEqual(Cjk.gb18030, Cjk.fromLabel("GB18030").?);
    try testing.expectEqual(Cjk.big5, Cjk.fromLabel("big5-hkscs").?);
    try testing.expect(Cjk.fromLabel("utf-8") == null);
    try testing.expect(Cjk.fromLabel("windows-1250") == null);
    try testing.expect(Cjk.fromLabel("iso-2022-kr") == null); // the `replacement` encoding
    try testing.expect(Cjk.fromLabel("nope") == null);
    try testing.expectEqualStrings("Shift_JIS", Cjk.shift_jis.whatwgName());
    try testing.expectEqualStrings("ISO-2022-JP", Cjk.iso_2022_jp.whatwgName());
    for (all) |e| try testing.expectEqual(e, Cjk.fromLabel(e.whatwgName()).?);
}

// ── 4. streaming ────────────────────────────────────────────────────────────

/// A corpus of byte strings for the decoders: the oracle's random inputs plus
/// valid text, every two-byte lead/trail boundary and the ISO-2022-JP tokens.
fn decodeCorpus(a: std.mem.Allocator) !std.ArrayList([]const u8) {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(a);
    for (vec.d5_inputs[0..200]) |x| try list.append(a, x);
    for (vec.d6_inputs[0..200]) |x| try list.append(a, x);
    const text = [_][]const u8{
        "\x93\xfa\x96\x7b\x8c\xea abc \xb1\xb2",
        "\xc6\xfc\xcb\xdc\xb8\xec abc \x8e\xb1\x8f\xb0\xa1",
        "\xc7\xd1\xb1\xb9\xbe\xee abc",
        "\xd6\xd0\xce\xc4 abc \x90\x30\x81\x30\x84\x31\xa4\x39\x81\x30",
        "\xa4\xa4\xa4\xe5 \x88\x62\x88\x66 abc",
        "\x1b$BF|K\\8l\x1b(J\\~\x1b(I12\x1b(B",
        "\x81\x30\x81", // cut gb18030
        "\xf0\x40\xfc\xfc\x82\x40",
    };
    for (text) |x| try list.append(a, x);
    return list;
}

fn decodeWhole(a: std.mem.Allocator, enc: Cjk, fatal: bool, bytes: []const u8) !?[]u8 {
    var d: cjk.Decoder = .init(enc, .{ .fatal = fatal });
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    d.feed(a, &out, bytes) catch |e| switch (e) {
        error.Malformed => {
            out.deinit(a);
            return null;
        },
        else => return e,
    };
    d.finish(a, &out) catch |e| switch (e) {
        error.Malformed => {
            out.deinit(a);
            return null;
        },
        else => return e,
    };
    return try out.toOwnedSlice(a);
}

/// `decodeInto` with `room` bytes of output at a time and the input cut into
/// `chunk`-byte pieces.
fn decodeChunked(a: std.mem.Allocator, enc: Cjk, fatal: bool, bytes: []const u8, chunk: usize, room: usize) !?[]u8 {
    var d: cjk.Decoder = .init(enc, .{ .fatal = fatal });
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    const buf = try a.alloc(u8, room);
    defer a.free(buf);
    var pos: usize = 0;
    while (true) {
        const end = @min(bytes.len, pos + chunk);
        const last = end == bytes.len;
        var r = pos;
        while (true) {
            const p = d.decodeInto(bytes[r..end], buf, last);
            try out.appendSlice(a, buf[0..p.written]);
            r += p.read;
            switch (p.status) {
                .input_empty => break,
                .output_full => {},
                .malformed => {
                    out.deinit(a);
                    return null;
                },
            }
        }
        pos = end;
        if (last) break;
    }
    return try out.toOwnedSlice(a);
}

test "streaming decode: every split point, 1-byte chunks and every output room give the whole-buffer answer" {
    const a = testing.allocator;
    var corpus = try decodeCorpus(a);
    defer corpus.deinit(a);
    for (all) |enc| {
        for (corpus.items) |bytes| {
            for ([_]bool{ false, true }) |fatal| {
                const whole = try decodeWhole(a, enc, fatal, bytes);
                defer if (whole) |w| a.free(w);
                // every two-piece split
                var cut: usize = 0;
                while (cut <= bytes.len) : (cut += 1) {
                    var d: cjk.Decoder = .init(enc, .{ .fatal = fatal });
                    var out: std.ArrayList(u8) = .empty;
                    defer out.deinit(a);
                    var failed = false;
                    d.feed(a, &out, bytes[0..cut]) catch |e| switch (e) {
                        error.Malformed => failed = true,
                        else => return e,
                    };
                    if (!failed) d.feed(a, &out, bytes[cut..]) catch |e| switch (e) {
                        error.Malformed => failed = true,
                        else => return e,
                    };
                    if (!failed) d.finish(a, &out) catch |e| switch (e) {
                        error.Malformed => failed = true,
                        else => return e,
                    };
                    if (whole) |w| {
                        try testing.expect(!failed);
                        try testing.expectEqualSlices(u8, w, out.items);
                    } else try testing.expect(failed);
                }
                // 1-byte chunks, and the smallest legal output room
                for ([_]usize{ 1, 3 }) |chunk| {
                    for ([_]usize{ cjk.decoder_headroom, 5, 64 }) |room| {
                        const got = try decodeChunked(a, enc, fatal, bytes, chunk, room);
                        defer if (got) |g| a.free(g);
                        if (whole) |w| try testing.expectEqualSlices(u8, w, got.?) else try testing.expect(got == null);
                    }
                }
            }
        }
    }
}

test "decoder: maxUtf8Len(n) always takes n bytes in one non-final call; a final call finishes in one" {
    const a = testing.allocator;
    var corpus = try decodeCorpus(a);
    defer corpus.deinit(a);
    for (all) |enc| {
        for (corpus.items) |bytes| {
            var d: cjk.Decoder = .init(enc, .{});
            const buf = try a.alloc(u8, d.maxUtf8Len(bytes.len));
            defer a.free(buf);
            const p = d.decodeInto(bytes, buf, false);
            try testing.expectEqual(core.Status.input_empty, p.status);
            try testing.expectEqual(bytes.len, p.read);
            const q = d.decodeInto("", buf[p.written..], true);
            try testing.expectEqual(core.Status.input_empty, q.status);
            var d2: cjk.Decoder = .init(enc, .{});
            const buf2 = try a.alloc(u8, d2.maxUtf8Len(bytes.len));
            defer a.free(buf2);
            const r = d2.decodeInto(bytes, buf2, true);
            try testing.expectEqual(core.Status.input_empty, r.status);
            try testing.expectEqualSlices(u8, buf[0 .. p.written + q.written], buf2[0..r.written]);
        }
    }
}

fn encodeCorpus(a: std.mem.Allocator) !std.ArrayList([]const u8) {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(a);
    for (vec.e2_inputs[0..200]) |x| try list.append(a, x);
    const text = [_][]const u8{
        "日本語 abc ｱｲ \u{A5}\\~\u{203E}\u{2212}",
        "\u{1F600}x\u{E5E5}\u{20AC}\u{E78D}",
        "a\x1bb\x0e\x0f", // ESC, SO, SI
        "x\xe3\x81", // cut sequence at the end
        "\xe3\x81\xe3\x81\x82\xff\xf0\x9f\x98\x80\xc0\x80",
        "한국어 中文 \u{10FFFF}",
    };
    for (text) |x| try list.append(a, x);
    return list;
}

fn encodeChunked(a: std.mem.Allocator, enc: Cjk, mode: core.Unmappable, utf8: []const u8, chunk: usize, room: usize) !?[]u8 {
    var e: cjk.Encoder = .init(enc, .{ .unmappable = mode });
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    const buf = try a.alloc(u8, room);
    defer a.free(buf);
    var pos: usize = 0;
    while (true) {
        const end = @min(utf8.len, pos + chunk);
        const last = end == utf8.len;
        var r = pos;
        while (true) {
            const p = e.encodeInto(utf8[r..end], buf, last);
            try out.appendSlice(a, buf[0..p.written]);
            r += p.read;
            switch (p.status) {
                .input_empty => break,
                .output_full => {},
                .unmappable => {
                    out.deinit(a);
                    return null;
                },
            }
        }
        pos = end;
        if (last) break;
    }
    return try out.toOwnedSlice(a);
}

test "streaming encode: every split point, 1-byte chunks and every output room give the whole-buffer answer" {
    const a = testing.allocator;
    var corpus = try encodeCorpus(a);
    defer corpus.deinit(a);
    const modes = [_]core.Unmappable{ .question_mark, .ignore, .html_ncr, .fatal };
    for (all) |enc| {
        for (corpus.items) |text| {
            for (modes) |mode| {
                const whole: ?[]u8 = cjk.encodeFromUtf8(a, text, enc, .{ .unmappable = mode }) catch |e| switch (e) {
                    error.Unmappable => null,
                    else => return e,
                };
                defer if (whole) |w| a.free(w);
                var cut: usize = 0;
                while (cut <= text.len) : (cut += 1) {
                    var e: cjk.Encoder = .init(enc, .{ .unmappable = mode });
                    var out: std.ArrayList(u8) = .empty;
                    defer out.deinit(a);
                    var failed = false;
                    e.feed(a, &out, text[0..cut]) catch |err| switch (err) {
                        error.Unmappable => failed = true,
                        else => return err,
                    };
                    if (!failed) e.feed(a, &out, text[cut..]) catch |err| switch (err) {
                        error.Unmappable => failed = true,
                        else => return err,
                    };
                    if (!failed) e.finish(a, &out) catch |err| switch (err) {
                        error.Unmappable => failed = true,
                        else => return err,
                    };
                    if (whole) |w| {
                        try testing.expect(!failed);
                        try testing.expectEqualSlices(u8, w, out.items);
                    } else try testing.expect(failed);
                }
                for ([_]usize{ 1, 2, 5 }) |chunk| {
                    for ([_]usize{ cjk.encoder_headroom, 17, 100 }) |room| {
                        const got = try encodeChunked(a, enc, mode, text, chunk, room);
                        defer if (got) |g| a.free(g);
                        if (whole) |w| try testing.expectEqualSlices(u8, w, got.?) else try testing.expect(got == null);
                    }
                }
            }
        }
    }
}

test "encoder .fatal: resuming after each unmappable code point equals `.ignore`" {
    const a = testing.allocator;
    var corpus = try encodeCorpus(a);
    defer corpus.deinit(a);
    for (all) |enc| {
        for (corpus.items) |text| {
            const want = try cjk.encodeFromUtf8(a, text, enc, .{ .unmappable = .ignore });
            defer a.free(want);
            var e: cjk.Encoder = .init(enc, .{ .unmappable = .fatal });
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(a);
            var buf: [64]u8 = undefined;
            var r: usize = 0;
            while (true) {
                const p = e.encodeInto(text[r..], &buf, true);
                try out.appendSlice(a, buf[0..p.written]);
                r += p.read;
                switch (p.status) {
                    .input_empty => break,
                    .output_full => {},
                    .unmappable => {},
                }
            }
            try testing.expectEqualSlices(u8, want, out.items);
        }
    }
}

test "encoder: maxEncodedLen(n) always takes n bytes in one final call" {
    const a = testing.allocator;
    var corpus = try encodeCorpus(a);
    defer corpus.deinit(a);
    for (all) |enc| {
        for ([_]core.Unmappable{ .question_mark, .html_ncr }) |mode| {
            for (corpus.items) |text| {
                var e: cjk.Encoder = .init(enc, .{ .unmappable = mode });
                const buf = try a.alloc(u8, e.maxEncodedLen(text.len));
                defer a.free(buf);
                const p = e.encodeInto(text, buf, true);
                try testing.expectEqual(core.EncodeStatus.input_empty, p.status);
                try testing.expectEqual(text.len, p.read);
            }
        }
    }
}

test "state is reset after the last call (a decoder/encoder is reusable)" {
    var d: cjk.Decoder = .init(.gb18030, .{});
    var buf: [64]u8 = undefined;
    _ = d.decodeInto("\x81\x30\x81", &buf, true); // cut four-byte form, flushed
    const p = d.decodeInto("A", &buf, true);
    try testing.expectEqualStrings("A", buf[0..p.written]);
    var e: cjk.Encoder = .init(.iso_2022_jp, .{});
    const q = e.encodeInto("\u{3042}", &buf, true);
    try testing.expectEqualSlices(u8, "\x1b$B$\"\x1b(B", buf[0..q.written]);
    const q2 = e.encodeInto("a", &buf, true);
    try testing.expectEqualSlices(u8, "a", buf[0..q2.written]);
}

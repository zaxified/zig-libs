// SPDX-License-Identifier: MIT
//! The 2026-10-20 parity items R9-R12 and R15: `mem`-style helpers, UTF-32,
//! `x-user-defined`, the DOS pages and `Custom`. (The table anchors of the new
//! pages are in `sb_tables_test.zig`; the fuzz kinds in `fuzz_test.zig`.)

const std = @import("std");
const testing = std.testing;
const enc = @import("root.zig");
const Encoding = enc.Encoding;

// ── R10: UTF-32 ──────────────────────────────────────────────────────────────

/// Cases and answers produced by CPython 3 (`bytes.decode("utf-32-le" /
/// "utf-32-be", "replace")`): one U+FFFD per bad unit (above U+10FFFF, a
/// surrogate) and ONE for the 1 to 3 bytes of a unit cut at the end.
const Utf32Case = struct { hex: []const u8, le: []const u8, be: []const u8 };
const utf32_cases = [_]Utf32Case{
    .{ .hex = "", .le = "", .be = "" },
    .{ .hex = "41000000", .le = "A", .be = "\u{FFFD}" },
    .{ .hex = "00f6010041000000", .le = "\u{1F600}A", .be = "\u{FFFD}\u{FFFD}" },
    .{ .hex = "00d80000", .le = "\u{FFFD}", .be = "\u{FFFD}" }, // a surrogate
    .{ .hex = "ffff1000", .le = "\u{10FFFF}", .be = "\u{FFFD}" },
    .{ .hex = "00001100", .le = "\u{FFFD}", .be = "\u{1100}" }, // 0x00110000 is past U+10FFFF
    .{ .hex = "0000110041000000", .le = "\u{FFFD}A", .be = "\u{1100}\u{FFFD}" },
    .{ .hex = "41", .le = "\u{FFFD}", .be = "\u{FFFD}" }, // cut units
    .{ .hex = "4100", .le = "\u{FFFD}", .be = "\u{FFFD}" },
    .{ .hex = "410000", .le = "\u{FFFD}", .be = "\u{FFFD}" },
    .{ .hex = "4100000042", .le = "A\u{FFFD}", .be = "\u{FFFD}\u{FFFD}" },
    .{ .hex = "ffffffff", .le = "\u{FFFD}", .be = "\u{FFFD}" },
    .{ .hex = "00dc000000d8000041000000", .le = "\u{FFFD}\u{FFFD}A", .be = "\u{FFFD}\u{FFFD}\u{FFFD}" },
};

fn hex(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    errdefer a.free(out);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

/// Decode through `decodeInto`, `room` output bytes at a time, the input cut at `cut`.
fn decodeTiny32(a: std.mem.Allocator, endian: enc.Utf32Endian, src: []const u8, room: usize, cut: usize) ![]u8 {
    var d: enc.Decoder = .init(.{ .utf32 = endian }, .{});
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    const parts = [2][]const u8{ src[0..cut], src[cut..] };
    for (parts, 0..) |part, pi| {
        var r: usize = 0;
        while (true) {
            var buf: [32]u8 = undefined;
            const p = d.decodeInto(part[r..], buf[0..room], pi == 1);
            try out.appendSlice(a, buf[0..p.written]);
            r += p.read;
            if (p.status == .input_empty) break;
            try testing.expect(p.status == .output_full);
            try testing.expect(p.read != 0 or p.written != 0);
        }
    }
    return out.toOwnedSlice(a);
}

test "UTF-32 decode agrees with CPython on every case, at every cut, room and byte by byte" {
    const a = testing.allocator;
    for (utf32_cases) |c| {
        const bytes = try hex(a, c.hex);
        defer a.free(bytes);
        for ([_]enc.Utf32Endian{ .le, .be }) |endian| {
            const want = if (endian == .le) c.le else c.be;
            const got = try enc.decodeUtf32(a, bytes, endian);
            defer a.free(got);
            try testing.expectEqualStrings(want, got);
            for ([_]usize{ 4, 5, 7, 8, 32 }) |room| {
                for (0..bytes.len + 1) |cut| {
                    const t = try decodeTiny32(a, endian, bytes, room, cut);
                    defer a.free(t);
                    testing.expectEqualStrings(want, t) catch |err| {
                        std.debug.print("utf32 {t} {s} room {d} cut {d}\n", .{ endian, c.hex, room, cut });
                        return err;
                    };
                }
            }
            // Byte by byte through feed/finish.
            var d: enc.Decoder = .init(.{ .utf32 = endian }, .{});
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(a);
            for (bytes) |b| try d.feed(a, &out, &.{b});
            try d.finish(a, &out);
            try testing.expectEqualStrings(want, out.items);
            // Fatal: exactly when the lenient result holds a replacement CPython made.
            const strict = std.mem.find(u8, want, enc.replacement_char) == null;
            if (enc.decodeFatal(a, bytes, .{ .utf32 = endian })) |ok| {
                defer a.free(ok);
                try testing.expect(strict);
                try testing.expectEqualStrings(want, ok);
            } else |err| {
                try testing.expectEqual(error.Malformed, err);
                try testing.expect(!strict);
            }
        }
    }
}

test "UTF-32 encode: BOM, both orders, boundaries, and agreement with std on random text" {
    const a = testing.allocator;
    const le = try enc.encodeUtf32(a, "A\u{1F600}", .le, true);
    defer a.free(le);
    try testing.expectEqualSlices(u8, "\xff\xfe\x00\x00A\x00\x00\x00\x00\xf6\x01\x00", le);
    const be = try enc.encodeUtf32(a, "A\u{1F600}", .be, true);
    defer a.free(be);
    try testing.expectEqualSlices(u8, "\x00\x00\xfe\xff\x00\x00\x00A\x00\x01\xf6\x00", be);
    // U+FFFF / U+10000 / U+10FFFF are one unit each, no surrogate pairs in UTF-32.
    const edge = try enc.encodeUtf32(a, "\u{FFFF}\u{10000}\u{10FFFF}", .le, false);
    defer a.free(edge);
    try testing.expectEqualSlices(u8, "\xff\xff\x00\x00\x00\x00\x01\x00\xff\xff\x10\x00", edge);
    // Malformed UTF-8: one U+FFFD per maximal subpart, like the UTF-16 encoder.
    const bad = try enc.encodeUtf32(a, "a\xe2\x82,\xff", .be, false);
    defer a.free(bad);
    try testing.expectEqualSlices(u8, "\x00\x00\x00a\x00\x00\xff\xfd\x00\x00\x00,\x00\x00\xff\xfd", bad);
    const empty = try enc.encodeUtf32(a, "", .le, true);
    defer a.free(empty);
    try testing.expectEqualSlices(u8, "\xff\xfe\x00\x00", empty);

    const pieces = [_][]const u8{ "abcdefghij", "0123456789ABCDEF", " ", "é", "€", "\u{1F600}", "Příliš", "\u{FFFF}", "\u{10000}", "\u{10FFFF}" };
    var prng = std.Random.DefaultPrng.init(32);
    const r = prng.random();
    for (0..200) |_| {
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(a);
        for (0..r.uintLessThan(usize, 60)) |_| try text.appendSlice(a, pieces[r.uintLessThan(usize, pieces.len)]);
        const got_le = try enc.encodeUtf32(a, text.items, .le, false);
        defer a.free(got_le);
        const got_be = try enc.encodeUtf32(a, text.items, .be, false);
        defer a.free(got_be);
        var view = (try std.unicode.Utf8View.init(text.items)).iterator();
        var i: usize = 0;
        while (view.nextCodepoint()) |cp| : (i += 4) {
            try testing.expectEqual(@as(u32, cp), std.mem.readInt(u32, got_le[i..][0..4], .little));
            try testing.expectEqual(@as(u32, cp), std.mem.readInt(u32, got_be[i..][0..4], .big));
        }
        try testing.expectEqual(i, got_le.len);
        const back = try enc.decodeUtf32(a, got_be, .be);
        defer a.free(back);
        try testing.expectEqualStrings(text.items, back);
    }
}

test "UTF-32: BOM sniffing leaves the WHATWG answer alone" {
    const a = testing.allocator;
    // `sniffBom` is WHATWG: ff fe 00 00 is UTF-16LE there.
    try testing.expectEqual(@as(?enc.Bom, .utf16le), enc.sniffBom("\xff\xfe\x00\x00A\x00\x00\x00"));
    try testing.expectEqual(@as(?enc.Bom, null), enc.sniffBom("\x00\x00\xfe\xff"));
    try testing.expectEqual(@as(?enc.Bom, .utf32le), enc.sniffBom32("\xff\xfe\x00\x00A\x00\x00\x00"));
    try testing.expectEqual(@as(?enc.Bom, .utf32be), enc.sniffBom32("\x00\x00\xfe\xff\x00\x00\x00A"));
    // Everything else as `sniffBom`.
    try testing.expectEqual(@as(?enc.Bom, .utf16le), enc.sniffBom32("\xff\xfeA\x00"));
    try testing.expectEqual(@as(?enc.Bom, .utf16be), enc.sniffBom32("\xfe\xff\x00A"));
    try testing.expectEqual(@as(?enc.Bom, .utf8), enc.sniffBom32("\xef\xbb\xbfx"));
    try testing.expectEqual(@as(?enc.Bom, null), enc.sniffBom32("\x00\x00\xfe"));
    try testing.expectEqual(@as(?enc.Bom, null), enc.sniffBom32(""));
    try testing.expectEqual(@as(usize, 4), enc.Bom.utf32le.len());
    // `decode` (WHATWG): UTF-16LE with a leading U+0000, as the Standard has it.
    const w = try enc.decode(a, "\xff\xfe\x00\x00A\x00", .windows_1250);
    defer a.free(w.text);
    try testing.expectEqual(@as(?enc.Bom, .utf16le), w.bom);
    try testing.expectEqualStrings("\x00A", w.text);
    // `decode32`: the UTF-32 BOM wins and is removed; other BOMs and the fallback as before.
    const d = try enc.decode32(a, "\xff\xfe\x00\x00A\x00\x00\x00\xe9\x00\x00\x00", .windows_1250);
    defer a.free(d.text);
    try testing.expectEqual(@as(?enc.Bom, .utf32le), d.bom);
    try testing.expectEqualStrings("A\u{e9}", d.text);
    const d2 = try enc.decode32(a, "\x00\x00\xfe\xff\x00\x00\x00A", .utf8);
    defer a.free(d2.text);
    try testing.expectEqual(@as(?enc.Bom, .utf32be), d2.bom);
    try testing.expectEqualStrings("A", d2.text);
    const d3 = try enc.decode32(a, "\xff\xfeA\x00", .utf8);
    defer a.free(d3.text);
    try testing.expectEqualStrings("A", d3.text);
    const d4 = try enc.decode32(a, "\xf8", .windows_1250);
    defer a.free(d4.text);
    try testing.expectEqual(@as(?enc.Bom, null), d4.bom);
    try testing.expectEqualStrings("\u{159}", d4.text);
}

test "UTF-32 is not an Encoding member" {
    try testing.expect(Encoding.parse("utf-32") == null);
    try testing.expect(Encoding.parse("utf-32le") == null);
    try testing.expect(enc.lookupLabel("utf-32") == null);
}

// ── R11: x-user-defined ─────────────────────────────────────────────────────

test "x-user-defined: 0x80..0xFF is U+F780..U+F7FF, a label and an Encoding member" {
    const a = testing.allocator;
    try testing.expectEqual(Encoding.x_user_defined, Encoding.parse("x-user-defined").?);
    try testing.expectEqual(Encoding.x_user_defined, Encoding.parse(" X-User-Defined\r").?);
    try testing.expectEqual(enc.LabelTarget{ .encoding = .x_user_defined }, enc.lookupLabel("x-user-defined").?);
    try testing.expectEqualStrings("x-user-defined", Encoding.x_user_defined.whatwgName());
    try testing.expectEqualStrings("x-user-defined", Encoding.x_user_defined.canonicalName());
    const got = try enc.decodeToUtf8(a, "a\x7f\x80\xff,", .x_user_defined);
    defer a.free(got);
    try testing.expectEqualStrings("a\x7f\u{F780}\u{F7FF},", got);
    // Every byte round-trips; nothing outside U+F780..U+F7FF and ASCII encodes.
    for (0..256) |b| {
        const byte: u8 = @intCast(b);
        const text = try enc.decodeToUtf8(a, &.{byte}, .x_user_defined);
        defer a.free(text);
        const back = try enc.encodeFromUtf8(a, text, .x_user_defined);
        defer a.free(back);
        try testing.expectEqualSlices(u8, &.{byte}, back);
    }
    try testing.expectEqual(@as(?u8, null), enc.Custom(@import("sb_tables.zig").x_user_defined_decode).encodeCp(0xF77F));
    const q = try enc.encodeFromUtf8(a, "\u{F77F}\u{F800}\u{E9}", .x_user_defined);
    defer a.free(q);
    try testing.expectEqualStrings("???", q);
}

// ── R12: DOS pages ──────────────────────────────────────────────────────────

test "DOS pages: Czech text, IANA names and labels" {
    const a = testing.allocator;
    // "Příliš žluťoučký kůň" in CP852, as Czech DOS wrote it.
    const cp852 = "P\xfd\xa1li\xe7 \xa7lu\x9cou\x9fk\xec k\x85\xe5";
    const text = try enc.decodeToUtf8(a, cp852, .cp852);
    defer a.free(text);
    try testing.expectEqualStrings("Příliš žluťoučký kůň", text);
    const back = try enc.encodeFromUtf8(a, text, .cp852);
    defer a.free(back);
    try testing.expectEqualSlices(u8, cp852, back);
    // CP437 (legacy ZIP names): box drawing and accents.
    const z = try enc.decodeToUtf8(a, "\x82t\xe9\xc4\xb3\x80", .cp437);
    defer a.free(z);
    try testing.expectEqualStrings("\u{e9}t\u{398}\u{2500}\u{2502}\u{c7}", z);
    // CP850 has dotless i at 0xD5 and the Latin-1 letters.
    const w = try enc.decodeToUtf8(a, "\xd5\x85", .cp850);
    defer a.free(w);
    try testing.expectEqualStrings("\u{131}\u{e0}", w);
    // Not in CP437: an unmappable character is '?'.
    const q = try enc.encodeFromUtf8(a, "\u{159}", .cp437);
    defer a.free(q);
    try testing.expectEqualStrings("?", q);

    try testing.expectEqualStrings("IBM852", Encoding.cp852.whatwgName());
    try testing.expectEqualStrings("ibm437", Encoding.cp437.canonicalName());
    const labels = [_]struct { []const u8, Encoding }{
        .{ "cp437", .cp437 }, .{ "IBM437", .cp437 }, .{ "437", .cp437 }, .{ "csPC8CodePage437", .cp437 },
        .{ "cp850", .cp850 }, .{ "ibm850", .cp850 }, .{ "850", .cp850 }, .{ "cspc850multilingual", .cp850 },
        .{ "cp852", .cp852 }, .{ "ibm852", .cp852 }, .{ "852", .cp852 }, .{ "cspcp852", .cp852 },
    };
    for (labels) |l| try testing.expectEqual(l[1], Encoding.parse(l[0]).?);
    // Their neighbours stay unknown (CP866 is WHATWG's ibm866; 858 is not provided).
    try testing.expectEqual(Encoding.ibm866, Encoding.parse("cp866").?);
    try testing.expect(Encoding.parse("cp858") == null);
    try testing.expect(Encoding.parse("cp853") == null);
}

// ── R9: mem-style helpers ───────────────────────────────────────────────────

/// The longest prefix `std` calls valid: the reference for `utf8ValidUpTo`.
fn stdValidUpTo(s: []const u8) usize {
    var k = s.len + 1;
    while (k > 0) {
        k -= 1;
        if (std.unicode.utf8ValidateSlice(s[0..k])) return k;
    }
    unreachable; // the empty slice is valid
}

test "utf8ValidUpTo: the exact longest valid prefix, against std" {
    const cases = [_]struct { []const u8, usize }{
        .{ "", 0 },
        .{ "abc", 3 },
        .{ "ab\xff", 2 },
        .{ "ab\xe2\x82", 2 }, // cut sequence: its start
        .{ "ab\xe2\x82\xac", 5 },
        .{ "\xe2\x82\xacx\xe2\x28\xa1", 4 },
        .{ "\xed\xa0\x80", 0 }, // surrogate
        .{ "a\xc0\xaf", 1 }, // overlong
        .{ "\xf4\x90\x80\x80", 0 }, // past U+10FFFF
        .{ "\xf0\x9f\x98\x80\xf0\x9f\x98", 4 },
        .{ "\x80", 0 },
    };
    for (cases) |c| {
        try testing.expectEqual(c[1], enc.utf8ValidUpTo(c[0]));
        try testing.expectEqual(c[1], stdValidUpTo(c[0]));
    }
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();
    const alphabet = "ab\x00\x7f\x80\xbf\xc0\xc2\xdf\xe0\xe1\xed\xef\xf0\xf4\xf5\xff\xa0\x9f\x90\x8f";
    // Short inputs over the tricky bytes (every error class, all lengths).
    for (0..20_000) |_| {
        var buf: [24]u8 = undefined;
        const n = r.uintLessThan(usize, buf.len + 1);
        for (buf[0..n]) |*b| b.* = alphabet[r.uintLessThan(usize, alphabet.len)];
        try testing.expectEqual(stdValidUpTo(buf[0..n]), enc.utf8ValidUpTo(buf[0..n]));
    }
    // Long valid text (the vector blocks), spoiled at a character boundary, or cut inside a character.
    const a = testing.allocator;
    const pieces = [_][]const u8{ "abcdefghijklmnop", "0123456789", "é", "€", "\u{1F600}", "Příliš", "\u{10FFFF}" };
    for (0..300) |_| {
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(a);
        var starts: std.ArrayList(usize) = .empty;
        defer starts.deinit(a);
        for (0..1 + r.uintLessThan(usize, 80)) |_| {
            const p = pieces[r.uintLessThan(usize, pieces.len)];
            var i: usize = 0;
            while (i < p.len) {
                const l = std.unicode.utf8ByteSequenceLength(p[i]) catch unreachable;
                try starts.append(a, text.items.len + i);
                i += l;
            }
            try text.appendSlice(a, p);
        }
        try testing.expectEqual(text.items.len, enc.utf8ValidUpTo(text.items));
        const at = starts.items[r.uintLessThan(usize, starts.items.len)];
        const saved = text.items[at];
        text.items[at] = 0xFF;
        try testing.expectEqual(at, enc.utf8ValidUpTo(text.items));
        text.items[at] = saved;
        // Cut inside a multi-byte character: the valid prefix ends at its start.
        const cut = 1 + r.uintLessThan(usize, text.items.len);
        try testing.expectEqual(stdValidUpTo(text.items[0..cut]), enc.utf8ValidUpTo(text.items[0..cut]));
    }
}

test "isAscii / asciiValidUpTo" {
    try testing.expect(enc.isAscii(""));
    try testing.expect(enc.isAscii("plain text, 0123456789 and more than 32 bytes of it for the vector path"));
    try testing.expect(!enc.isAscii("caf\xc3\xa9"));
    try testing.expectEqual(@as(usize, 3), enc.asciiValidUpTo("caf\xc3\xa9"));
    try testing.expectEqual(@as(usize, 0), enc.asciiValidUpTo("\x80"));
    try testing.expectEqual(@as(usize, 2), enc.asciiValidUpTo("ab"));
    // Every position of the first high byte through the vector body and the tail.
    var buf: [100]u8 = @splat('x');
    for (0..buf.len) |p| {
        buf[p] = 0x80;
        try testing.expectEqual(p, enc.asciiValidUpTo(&buf));
        try testing.expect(!enc.isAscii(&buf));
        buf[p] = 0x7F;
    }
    try testing.expect(enc.isAscii(&buf));
}

test "latin1ToUtf8 / utf8ToLatin1Lossy: the identity page, not windows-1252" {
    const a = testing.allocator;
    const u = try enc.latin1ToUtf8(a, "caf\xe9 \x80\x93\xff");
    defer a.free(u);
    try testing.expectEqualStrings("caf\u{e9} \u{80}\u{93}\u{ff}", u); // 0x80 is a C1 control, not the euro
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    const v = try enc.latin1ToUtf8(a, &all);
    defer a.free(v);
    const back = try enc.utf8ToLatin1Lossy(a, v);
    defer a.free(back);
    try testing.expectEqualSlices(u8, &all, back);
    const lossy = try enc.utf8ToLatin1Lossy(a, "a\u{20AC}b\u{1F600}\u{e9}");
    defer a.free(lossy);
    try testing.expectEqualStrings("a?b?\xe9", lossy);
}

// ── R15: Custom ─────────────────────────────────────────────────────────────

/// A toy page: 0x80..0x9F are the Greek capitals Α..Τ (U+0391..), 0xA0..0xBF the
/// Cyrillic capitals А.. (U+0410..), the rest unmapped; plus one deliberate
/// duplicate (0xC0 is U+0391 again) to pin the first-byte-wins rule.
const toy_table: [128]u16 = blk: {
    var t: [128]u16 = @splat(0xFFFF);
    for (0..32) |i| t[i] = 0x0391 + i;
    for (0..32) |i| t[32 + i] = 0x0410 + i;
    t[0x40] = 0x0391;
    break :blk t;
};
const Toy = enc.Custom(toy_table);

test "Custom: a toy page decodes, encodes, and treats holes and duplicates like a built-in page" {
    const a = testing.allocator;
    try testing.expectEqual(@as(?u21, 'A'), Toy.decodeByte('A'));
    try testing.expectEqual(@as(?u21, 0x0391), Toy.decodeByte(0x80));
    try testing.expectEqual(@as(?u21, null), Toy.decodeByte(0xE0));
    try testing.expectEqual(@as(?u8, 0x80), Toy.encodeCp(0x0391)); // the FIRST byte of a duplicate
    try testing.expectEqual(@as(?u8, 0xA1), Toy.encodeCp(0x0411));
    try testing.expectEqual(@as(?u8, null), Toy.encodeCp(0x0100));
    try testing.expectEqual(@as(?u8, 'z'), Toy.encodeCp('z'));

    const text = try enc.decodeCustom(a, "a\x80\xa0\xc0\xe0,", Toy);
    defer a.free(text);
    try testing.expectEqualStrings("a\u{391}\u{410}\u{391}\u{FFFD},", text);
    const wire = try enc.encodeCustom(a, "a\u{391}\u{410}\u{FFFD}\u{1F600},", Toy, .question_mark);
    defer a.free(wire);
    try testing.expectEqualStrings("a\x80\xa0??,", wire);
    const ncr = try enc.encodeCustom(a, "\u{1F600}x", Toy, .html_ncr);
    defer a.free(ncr);
    try testing.expectEqualStrings("&#128512;x", ncr);
    const ign = try enc.encodeCustom(a, "a\u{1F600}b", Toy, .ignore);
    defer a.free(ign);
    try testing.expectEqualStrings("ab", ign);
    try testing.expectError(error.Unmappable, enc.encodeCustom(a, "a\u{1F600}", Toy, .fatal));

    // The caller-buffer forms: fatal decode stops at the hole, keeping what came before.
    var dst: [16]u8 = undefined;
    const p = Toy.decodeToUtf8("ok\xe0", &dst, true);
    try testing.expectEqual(enc.Status.malformed, p.status);
    try testing.expectEqualStrings("ok", dst[0..p.written]);
    // A long input forces both allocating helpers through their grow path.
    var long_buf: std.ArrayList(u8) = .empty;
    defer long_buf.deinit(a);
    for (0..40) |_| try long_buf.appendSlice(a, "\x80\xa0abcdefghijklmnopqrstuvwxyz");
    const long = long_buf.items;
    const dec = try enc.decodeCustom(a, long, Toy);
    defer a.free(dec);
    const enc_back = try enc.encodeCustom(a, dec, Toy, .question_mark);
    defer a.free(enc_back);
    try testing.expectEqualStrings(long, enc_back);
}

test "Custom: a built-in table gives the built-in page's answers" {
    const a = testing.allocator;
    const Page = enc.Custom(@import("sb_tables.zig").windows_1250_decode);
    const sample = "P\xf8\xedli\x9a \x9elu\x9dou\xe8k\xfd k\xf9\xf2 \x80 \x81!";
    const want = try enc.decodeToUtf8(a, sample, .windows_1250);
    defer a.free(want);
    const got = try enc.decodeCustom(a, sample, Page);
    defer a.free(got);
    try testing.expectEqualStrings(want, got);
    const ewant = try enc.encodeFromUtf8Opts(a, want, .windows_1250, .{ .unmappable = .html_ncr });
    defer a.free(ewant);
    const egot = try enc.encodeCustom(a, want, Page, .html_ncr);
    defer a.free(egot);
    try testing.expectEqualSlices(u8, ewant, egot);
}

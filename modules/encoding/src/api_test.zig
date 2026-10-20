// SPDX-License-Identifier: MIT
//! The 2026-10-20 API: every WHATWG single-byte page, the label table,
//! the caller-buffer core (`decodeInto`/`encodeInto`), the streaming
//! `Encoder`, unmappable-character modes and fatal mode on undefined bytes.

const std = @import("std");
const testing = std.testing;
const enc = @import("root.zig");
const Encoding = enc.Encoding;

const all_encodings = blk: {
    const vals = @typeInfo(Encoding).@"enum".field_values;
    var out: [vals.len]Encoding = undefined;
    for (vals, 0..) |v, i| out[i] = @fromBackingInt(@intCast(v));
    const final = out;
    break :blk final;
};

test "every page: each defined high byte decodes and encodes back to itself" {
    const a = testing.allocator;
    var pages: usize = 0;
    var holes: usize = 0;
    for (all_encodings) |e| {
        if (e == .utf8) continue;
        pages += 1;
        for (0x80..0x100) |b| {
            const byte: u8 = @intCast(b);
            const text = try enc.decodeToUtf8(a, &.{byte}, e);
            defer a.free(text);
            const back = try enc.encodeFromUtf8(a, text, e);
            defer a.free(back);
            if (std.mem.eql(u8, text, enc.replacement_char)) {
                holes += 1;
                try testing.expectEqualStrings("?", back);
            } else try testing.expectEqualSlices(u8, &.{byte}, back);
        }
    }
    try testing.expectEqual(@as(usize, 33), pages); // 29 WHATWG single-byte + x-user-defined + 3 DOS
    try testing.expect(holes > 0); // windows-1253, ISO-8859-8, … have undefined bytes
}

test "new pages: KOI8-R, windows-1251, ISO-8859-7, IBM866 samples" {
    const a = testing.allocator;
    const cases = [_]struct { Encoding, []const u8, []const u8 }{
        .{ .koi8_r, "\xd0\xd2\xc9\xd7\xc5\xd4", "привет" },
        .{ .windows_1251, "\xef\xf0\xe8\xe2\xe5\xf2", "привет" },
        .{ .iso_8859_7, "\xe1\xe2\xe3", "αβγ" },
        .{ .ibm866, "\xaf\xe0\xa8\xa2\xa5\xe2", "привет" },
    };
    for (cases) |c| {
        const got = try enc.decodeToUtf8(a, c[1], c[0]);
        defer a.free(got);
        try testing.expectEqualStrings(c[2], got);
        const back = try enc.encodeFromUtf8(a, c[2], c[0]);
        defer a.free(back);
        try testing.expectEqualSlices(u8, c[1], back);
    }
}

test "labels: WHATWG table, module extras, and what is known but not an Encoding" {
    try testing.expectEqual(Encoding.koi8_r, Encoding.parse(" KOI8-R\r").?);
    try testing.expectEqual(Encoding.windows_1251, Encoding.parse("cp1251").?);
    try testing.expectEqual(Encoding.iso_8859_8_i, Encoding.parse("iso-8859-8-i").?);
    try testing.expectEqual(Encoding.windows_1250, Encoding.parse("win1250").?);
    try testing.expectEqual(Encoding.iso_8859_1, Encoding.parse("latin1").?); // the departure
    try testing.expectEqual(enc.LabelTarget{ .utf16 = .le }, enc.lookupLabel("utf-16").?);
    try testing.expectEqual(enc.LabelTarget{ .utf16 = .be }, enc.lookupLabel("UTF-16BE").?);
    try testing.expectEqual(enc.LabelTarget.replacement, enc.lookupLabel("iso-2022-kr").?);
    try testing.expectEqual(enc.LabelTarget{ .encoding = .x_user_defined }, enc.lookupLabel("x-user-defined").?);
    try testing.expectEqual(enc.cjk.Cjk.shift_jis, enc.lookupLabel("sjis").?.cjk);
    try testing.expect(Encoding.parse("sjis") == null);
    try testing.expect(enc.lookupLabel("no-such-label") == null);
    try testing.expectEqualStrings("KOI8-R", Encoding.koi8_r.whatwgName());
    try testing.expectEqualStrings("koi8-r", Encoding.koi8_r.canonicalName());
    try testing.expectEqualStrings("windows-1250", Encoding.windows_1250.canonicalName());
    try testing.expect(!Encoding.windows_1250.canEncodeEverything() and Encoding.utf8.canEncodeEverything());
}

test "replacement encoding: empty stays empty, anything else is one U+FFFD" {
    const a = testing.allocator;
    const e = try enc.decodeReplacement(a, "");
    defer a.free(e);
    try testing.expectEqualStrings("", e);
    const r = try enc.decodeReplacement(a, "\x1b$)Cabc");
    defer a.free(r);
    try testing.expectEqualStrings("\u{FFFD}", r);
}

test "unmappable modes: ?, ignore, &#NNNN;, fatal with the code point" {
    const a = testing.allocator;
    const text = "a\u{1F600}b€";
    const q = try enc.encodeFromUtf8(a, text, .iso_8859_2);
    defer a.free(q);
    try testing.expectEqualStrings("a?b?", q);
    const i = try enc.encodeFromUtf8Opts(a, text, .iso_8859_2, .{ .unmappable = .ignore });
    defer a.free(i);
    try testing.expectEqualStrings("ab", i);
    const h = try enc.encodeFromUtf8Opts(a, text, .iso_8859_2, .{ .unmappable = .html_ncr });
    defer a.free(h);
    try testing.expectEqualStrings("a&#128512;b&#8364;", h);
    try testing.expectError(error.Unmappable, enc.encodeFromUtf8Opts(a, text, .iso_8859_2, .{ .unmappable = .fatal }));
    var e: enc.Encoder = .init(.{ .encoding = .iso_8859_2 }, .{ .unmappable = .fatal });
    var buf: [16]u8 = undefined;
    const p = e.encodeInto(text, &buf, true);
    try testing.expectEqual(enc.EncodeStatus.unmappable, p.status);
    try testing.expectEqual(@as(u21, 0x1F600), p.code_point);
    try testing.expectEqual(@as(usize, 1), p.read);
    try testing.expectEqualStrings("a", buf[0..p.written]);
}

test "fatal mode refuses a page's undefined byte, keeping what came before" {
    const a = testing.allocator;
    // windows-1253 leaves 0xAA undefined.
    try testing.expectError(error.Malformed, enc.decodeFatal(a, "ok\xaa", .{ .encoding = .windows_1253 }));
    var d: enc.Decoder = .init(.{ .encoding = .windows_1253 }, .{ .fatal = true });
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try testing.expectError(error.Malformed, d.feed(a, &out, "ok\xaa"));
    try testing.expectEqualStrings("ok", out.items);
    // Lenient: U+FFFD.
    const l = try enc.decodeToUtf8(a, "ok\xaa", .windows_1253);
    defer a.free(l);
    try testing.expectEqualStrings("ok\u{FFFD}", l);
}

/// Decode through `decodeInto` with a `dst` of `room` bytes at a time.
fn decodeTiny(a: std.mem.Allocator, kind: enc.Decoder.Kind, src: []const u8, room: usize, cut: usize) ![]u8 {
    var d: enc.Decoder = .init(kind, .{});
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    const parts = [2][]const u8{ src[0..cut], src[cut..] };
    for (parts, 0..) |part, pi| {
        var r: usize = 0;
        while (true) {
            var buf: [64]u8 = undefined;
            const p = d.decodeInto(part[r..], buf[0..room], pi == 1);
            try out.appendSlice(a, buf[0..p.written]);
            r += p.read;
            if (p.status == .input_empty) break;
            try testing.expect(p.read != 0 or p.written != 0);
        }
    }
    return out.toOwnedSlice(a);
}

fn encodeTiny(a: std.mem.Allocator, kind: enc.Encoder.Kind, opts: enc.Encoder.Options, src: []const u8, room: usize, cut: usize) ![]u8 {
    var e: enc.Encoder = .init(kind, opts);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    const parts = [2][]const u8{ src[0..cut], src[cut..] };
    for (parts, 0..) |part, pi| {
        var r: usize = 0;
        while (true) {
            var buf: [64]u8 = undefined;
            const p = e.encodeInto(part[r..], buf[0..room], pi == 1);
            try out.appendSlice(a, buf[0..p.written]);
            r += p.read;
            if (p.status == .input_empty) break;
            try testing.expect(p.status == .output_full);
            try testing.expect(p.read != 0 or p.written != 0);
        }
    }
    return out.toOwnedSlice(a);
}

const sample_utf8 = "Příliš žluťoučký kůň \u{1F600} € \xff\xe2\x82 \xed\xa0\x80 ok";
const sample_1250 = "P\xf8\xedli\x9a \x9elu\x9dou\xe8k\xfd k\xf9\xf2 \x80 \x81!";
const sample_u16 = "A\x00\x3d\xd8\x00\xde\x00\xd8B\x00\xac\x20\xdc\xdf";
/// UTF-32LE: A, U+1F600, a lone surrogate, B, above U+10FFFF, U+20AC, 3 stray bytes.
const sample_u32 = "A\x00\x00\x00" ++ "\x00\xf6\x01\x00" ++ "\x00\xd8\x00\x00" ++ "B\x00\x00\x00" ++ "\x00\x00\x11\x00" ++ "\xac\x20\x00\x00" ++ "\x01\x02\x03";

test "decodeInto: any output room and any cut give the whole-buffer result" {
    const a = testing.allocator;
    const cases = [_]struct { enc.Decoder.Kind, []const u8 }{
        .{ .{ .encoding = .utf8 }, sample_utf8 },
        .{ .{ .encoding = .windows_1250 }, sample_1250 },
        .{ .{ .encoding = .windows_1253 }, "a\xaa\xe1b" },
        .{ .{ .utf16 = .le }, sample_u16 },
        .{ .{ .utf16 = .be }, sample_u16 },
        .{ .{ .utf32 = .le }, sample_u32 },
        .{ .{ .utf32 = .be }, sample_u32 },
        .{ .{ .encoding = .cp852 }, "a\xe7\xfd\xd8b" },
        .{ .{ .encoding = .x_user_defined }, "a\x80\xffb" },
    };
    for (cases) |c| {
        const want = switch (c[0]) {
            .encoding => |e| try enc.decodeToUtf8(a, c[1], e),
            .utf16 => |e| try enc.decodeUtf16(a, c[1], e),
            .utf32 => |e| try enc.decodeUtf32(a, c[1], e),
        };
        defer a.free(want);
        for ([_]usize{ 7, 8, 9, 13, 64 }) |room| {
            for (0..c[1].len + 1) |cut| {
                const got = try decodeTiny(a, c[0], c[1], room, cut);
                defer a.free(got);
                testing.expectEqualStrings(want, got) catch |err| {
                    std.debug.print("decode {any} room {d} cut {d}\n", .{ c[0], room, cut });
                    return err;
                };
            }
        }
    }
}

test "Encoder: any output room and any cut give the whole-buffer result" {
    const a = testing.allocator;
    const pages = [_]Encoding{ .utf8, .windows_1250, .iso_8859_2, .koi8_r, .cp852, .x_user_defined };
    for (pages) |page| {
        for ([_]enc.Unmappable{ .question_mark, .html_ncr, .ignore }) |mode| {
            const want = try enc.encodeFromUtf8Opts(a, sample_utf8, page, .{ .unmappable = mode });
            defer a.free(want);
            for ([_]usize{ 18, 19, 25, 64 }) |room| {
                for (0..sample_utf8.len + 1) |cut| {
                    const got = try encodeTiny(a, .{ .encoding = page }, .{ .unmappable = mode }, sample_utf8, room, cut);
                    defer a.free(got);
                    testing.expectEqualSlices(u8, want, got) catch |err| {
                        std.debug.print("encode {t} {t} room {d} cut {d}\n", .{ page, mode, room, cut });
                        return err;
                    };
                }
            }
        }
    }
    for ([_]enc.Utf32Endian{ .le, .be }) |endian| {
        const want = try enc.encodeUtf32(a, sample_utf8, endian, true);
        defer a.free(want);
        for ([_]usize{ 8, 9, 11, 64 }) |room| {
            for (0..sample_utf8.len + 1) |cut| {
                const got = try encodeTiny(a, .{ .utf32 = endian }, .{ .bom = true }, sample_utf8, room, cut);
                defer a.free(got);
                testing.expectEqualSlices(u8, want, got) catch |err| {
                    std.debug.print("encode utf32 {t} room {d} cut {d}\n", .{ endian, room, cut });
                    return err;
                };
            }
        }
    }
    for ([_]enc.Utf16Endian{ .le, .be }) |endian| {
        const want = try enc.encodeUtf16(a, sample_utf8, endian, true);
        defer a.free(want);
        for ([_]usize{ 8, 9, 64 }) |room| {
            for (0..sample_utf8.len + 1) |cut| {
                const got = try encodeTiny(a, .{ .utf16 = endian }, .{ .bom = true }, sample_utf8, room, cut);
                defer a.free(got);
                try testing.expectEqualSlices(u8, want, got);
            }
        }
    }
}

test "Encoder: a sequence cut byte by byte across many feeds" {
    const a = testing.allocator;
    var e: enc.Encoder = .init(.{ .encoding = .windows_1250 }, .{});
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    for (sample_utf8) |b| try e.feed(a, &out, &.{b});
    try e.finish(a, &out);
    const want = try enc.encodeFromUtf8(a, sample_utf8, .windows_1250);
    defer a.free(want);
    try testing.expectEqualSlices(u8, want, out.items);
}

test "maxEncodedLen / maxUtf8Len: one call always takes everything" {
    const a = testing.allocator;
    for (all_encodings) |e| {
        var d: enc.Decoder = .init(.{ .encoding = e }, .{});
        const dst = try a.alloc(u8, d.maxUtf8Len(sample_1250.len));
        defer a.free(dst);
        try testing.expectEqual(enc.Status.input_empty, d.decodeInto(sample_1250, dst, true).status);
        var x: enc.Encoder = .init(.{ .encoding = e }, .{ .unmappable = .html_ncr });
        const edst = try a.alloc(u8, x.maxEncodedLen(sample_utf8.len));
        defer a.free(edst);
        try testing.expectEqual(enc.EncodeStatus.input_empty, x.encodeInto(sample_utf8, edst, true).status);
    }
}

test "UTF-16 both ways on long ASCII-heavy text (the 16-unit fast paths) agree with std" {
    const a = testing.allocator;
    const pieces = [_][]const u8{ "abcdefghij", "0123456789ABCDEF", " ", "é", "€", "\u{1F600}", "Příliš", "\u{FFFF}", "\u{10000}" };
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    for (0..300) |_| {
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(a);
        const n = r.uintLessThan(usize, 80);
        for (0..n) |_| try text.appendSlice(a, pieces[r.uintLessThan(usize, pieces.len)]);
        const units = try std.unicode.utf8ToUtf16LeAlloc(a, text.items);
        defer a.free(units);
        const le = std.mem.sliceAsBytes(units);
        const got_le = try enc.encodeUtf16(a, text.items, .le, false);
        defer a.free(got_le);
        try testing.expectEqualSlices(u8, le, got_le);
        const got_be = try enc.encodeUtf16(a, text.items, .be, false);
        defer a.free(got_be);
        for (0..units.len) |k| {
            try testing.expectEqual(le[2 * k], got_be[2 * k + 1]);
            try testing.expectEqual(le[2 * k + 1], got_be[2 * k]);
        }
        const back_le = try enc.decodeUtf16(a, got_le, .le);
        defer a.free(back_le);
        try testing.expectEqualStrings(text.items, back_le);
        const back_be = try enc.decodeUtf16(a, got_be, .be);
        defer a.free(back_be);
        try testing.expectEqualStrings(text.items, back_be);
        const valid = try enc.decodeToUtf8(a, text.items, .utf8);
        defer a.free(valid);
        try testing.expectEqualStrings(text.items, valid);
    }
}

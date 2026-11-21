// SPDX-License-Identifier: MIT
//! Character encodings of a YAML stream (YAML 1.2.2 §5.2): UTF-8, UTF-16 and
//! UTF-32 in both byte orders. The scanner reads UTF-8 only, so the parser
//! converts anything else up front. The encoding is told, as the spec's
//! table has it, by a byte order mark or, without one, by where the NUL bytes
//! of the first ASCII character stand (a valid YAML stream holds no NUL).

const std = @import("std");

pub const Encoding = enum { utf8, utf16le, utf16be, utf32le, utf32be };

/// The encoding of `src` by YAML 1.2.2 §5.2: UTF-32 before UTF-16 where the
/// bytes allow both (`FF FE 00 00` begins UTF-32LE, `FF FE` UTF-16LE).
pub fn detect(src: []const u8) Encoding {
    const n = src.len;
    if (n >= 4 and src[0] == 0 and src[1] == 0 and src[2] == 0xFE and src[3] == 0xFF) return .utf32be;
    if (n >= 4 and src[0] == 0xFF and src[1] == 0xFE and src[2] == 0 and src[3] == 0) return .utf32le;
    if (n >= 2 and src[0] == 0xFE and src[1] == 0xFF) return .utf16be;
    if (n >= 2 and src[0] == 0xFF and src[1] == 0xFE) return .utf16le;
    if (n >= 3 and src[0] == 0xEF and src[1] == 0xBB and src[2] == 0xBF) return .utf8;
    // No byte order mark: the first character is ASCII, so its NULs show.
    if (n >= 4 and src[0] == 0 and src[1] == 0 and src[2] == 0 and src[3] != 0) return .utf32be;
    if (n >= 4 and src[0] != 0 and src[1] == 0 and src[2] == 0 and src[3] == 0) return .utf32le;
    if (n >= 2 and src[0] == 0 and src[1] != 0) return .utf16be;
    if (n >= 2 and src[0] != 0 and src[1] == 0) return .utf16le;
    return .utf8;
}

pub const Error = error{ OutOfMemory, InvalidYaml };

/// `src` as UTF-8: itself when it is UTF-8 already (nothing is copied), else
/// a copy in `arena`, the byte order mark kept as U+FEFF (the scanner skips it).
/// On `error.InvalidYaml` `problem` names the fault.
pub fn toUtf8(arena: std.mem.Allocator, src: []const u8, problem: *[]const u8) Error![]const u8 {
    const enc = detect(src);
    if (enc == .utf8) return src;
    const unit: usize = switch (enc) {
        .utf16le, .utf16be => 2,
        else => 4,
    };
    if (src.len % unit != 0) {
        problem.* = "the stream's length is not a whole number of UTF-16/UTF-32 code units";
        return error.InvalidYaml;
    }
    var out: std.ArrayList(u8) = .empty;
    const per_unit: usize = if (unit == 2) 3 else 1;
    try out.ensureTotalCapacity(arena, src.len / unit * per_unit + 4);
    var i: usize = 0;
    while (i < src.len) {
        var cp: u32 = undefined;
        switch (enc) {
            .utf32le, .utf32be => {
                cp = std.mem.readInt(u32, src[i..][0..4], if (enc == .utf32le) .little else .big);
                i += 4;
            },
            else => {
                const order: std.builtin.Endian = if (enc == .utf16le) .little else .big;
                const hi = std.mem.readInt(u16, src[i..][0..2], order);
                i += 2;
                if (hi >= 0xD800 and hi <= 0xDBFF) {
                    if (i + 2 > src.len) {
                        problem.* = "a UTF-16 high surrogate ends the stream";
                        return error.InvalidYaml;
                    }
                    const lo = std.mem.readInt(u16, src[i..][0..2], order);
                    if (lo < 0xDC00 or lo > 0xDFFF) {
                        problem.* = "a UTF-16 high surrogate is not followed by a low surrogate";
                        return error.InvalidYaml;
                    }
                    i += 2;
                    cp = 0x10000 + ((@as(u32, hi) - 0xD800) << 10) + (lo - 0xDC00);
                } else if (hi >= 0xDC00 and hi <= 0xDFFF) {
                    problem.* = "a UTF-16 low surrogate has no high surrogate before it";
                    return error.InvalidYaml;
                } else cp = hi;
            },
        }
        if (cp > 0x10FFFF or (cp >= 0xD800 and cp <= 0xDFFF)) {
            problem.* = "a UTF-32 code unit is not a Unicode scalar value";
            return error.InvalidYaml;
        }
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(@intCast(cp), &buf) catch unreachable;
        try out.appendSlice(arena, buf[0..n]);
    }
    return out.items;
}

const testing = std.testing;

fn conv(arena: std.mem.Allocator, src: []const u8) ![]const u8 {
    var problem: []const u8 = "";
    return toUtf8(arena, src, &problem);
}

test "detect: the byte order marks and the NUL patterns of §5.2" {
    try testing.expectEqual(Encoding.utf8, detect("a: 1"));
    try testing.expectEqual(Encoding.utf8, detect("\xef\xbb\xbfa"));
    try testing.expectEqual(Encoding.utf8, detect(""));
    try testing.expectEqual(Encoding.utf16le, detect("\xff\xfea\x00"));
    try testing.expectEqual(Encoding.utf16be, detect("\xfe\xff\x00a"));
    try testing.expectEqual(Encoding.utf32le, detect("\xff\xfe\x00\x00a\x00\x00\x00"));
    try testing.expectEqual(Encoding.utf32be, detect("\x00\x00\xfe\xff\x00\x00\x00a"));
    try testing.expectEqual(Encoding.utf16le, detect("a\x00:\x00"));
    try testing.expectEqual(Encoding.utf16be, detect("\x00a\x00:"));
    try testing.expectEqual(Encoding.utf32le, detect("a\x00\x00\x00:\x00\x00\x00"));
    try testing.expectEqual(Encoding.utf32be, detect("\x00\x00\x00a\x00\x00\x00:"));
    try testing.expectEqual(Encoding.utf16le, detect("a\x00")); // two bytes are enough
}

test "toUtf8: all four encodings, with and without a mark, astral characters, UTF-8 untouched" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    // "é😀" is U+00E9 U+1F600.
    const want = "\xc3\xa9\xf0\x9f\x98\x80";
    const cases = [_][]const u8{
        "\xff\xfe\xe9\x00\x3d\xd8\x00\xde", // UTF-16LE, mark
        "\xfe\xff\x00\xe9\xd8\x3d\xde\x00", // UTF-16BE, mark
        "\xff\xfe\x00\x00\xe9\x00\x00\x00\x00\xf6\x01\x00", // UTF-32LE, mark
        "\x00\x00\xfe\xff\x00\x00\x00\xe9\x00\x01\xf6\x00", // UTF-32BE, mark
    };
    for (cases) |c| {
        const got = try conv(a, c);
        // The mark comes through as U+FEFF.
        try testing.expectEqualStrings("\xef\xbb\xbf" ++ want, got);
    }
    // Without a mark the first character is ASCII (the NUL pattern tells).
    const g = try conv(a, "a\x00:\x00 \x00\xe9\x00");
    try testing.expectEqualStrings("a: \xc3\xa9", g);
    const g2 = try conv(a, "\x00\x00\x00a\x00\x00\x00:");
    try testing.expectEqualStrings("a:", g2);
    // UTF-8 is returned as it is, not copied.
    const u = "k: v\n";
    try testing.expect((try conv(a, u)).ptr == u.ptr);
}

test "toUtf8: lone surrogates, a cut unit, an impossible scalar are refused with a reason" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    var problem: []const u8 = "";
    const bad = [_][]const u8{
        "\xff\xfe\x3d\xd8", // high surrogate at the end
        "\xff\xfe\x3d\xd8a\x00", // high surrogate, then not a low one
        "\xff\xfe\x00\xdea\x00", // a low surrogate alone
        "\xff\xfea", // a cut unit
        "\xff\xfe\x00\x00\x00\x00\x11\x00", // U+110000
        "\xff\xfe\x00\x00\x00\xd8\x00\x00", // U+D800 as UTF-32
    };
    for (bad) |c| {
        problem = "";
        try testing.expectError(error.InvalidYaml, toUtf8(ar.allocator(), c, &problem));
        try testing.expect(problem.len > 0);
    }
}

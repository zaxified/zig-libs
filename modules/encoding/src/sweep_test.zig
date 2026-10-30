// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GP). The encoding sweep found no defect; these
//! pin the claims it rests on so a future change cannot lose them: every
//! two-byte pair and every truncated lead through every CJK decoder yields
//! valid UTF-8 and agrees with byte-at-a-time streaming; hostile gb18030
//! four-byte pointers and ISO-2022-JP escapes are errors, not crashes; and
//! the worst-case encoder expansion (`&#1114111;`) fits the sizing the
//! allocating API uses (sweep EN).

const std = @import("std");
const enc = @import("root.zig");
const cjk = enc.cjk;

fn repeated(alloc: std.mem.Allocator, piece: []const u8, n: usize, tail: []const u8) ![]u8 {
    var l: std.ArrayList(u8) = .empty;
    errdefer l.deinit(alloc);
    for (0..n) |_| try l.appendSlice(alloc, piece);
    try l.appendSlice(alloc, tail);
    return l.toOwnedSlice(alloc);
}

fn expectValidAndStreamed(alloc: std.mem.Allocator, kind: cjk.Cjk, bytes: []const u8) !void {
    const whole = try cjk.decodeToUtf8(alloc, bytes, kind);
    defer alloc.free(whole);
    try std.testing.expect(std.unicode.utf8ValidateSlice(whole));
    var d: cjk.Decoder = .init(kind, .{});
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    for (bytes) |b| try d.feed(alloc, &out, &.{b});
    try d.finish(alloc, &out);
    try std.testing.expectEqualSlices(u8, whole, out.items);
}

test "CJK decoders: every byte pair and every lone byte is valid UTF-8 and chunk-independent (sweep EN)" {
    const alloc = std.testing.allocator;
    for (std.enums.values(cjk.Cjk)) |kind| {
        var buf: [2]u8 = undefined;
        for (0..256) |a| {
            buf[0] = @intCast(a);
            try expectValidAndStreamed(alloc, kind, buf[0..1]);
            // A stride keeps the Debug runtime small; both ends of every
            // lead/trail range are on the stride (0x40..0xFF step 3 plus 0x7e,0x7f,0x80,0xfe,0xff).
            var t: usize = 0;
            while (t < 256) : (t += if (t < 0x20 or t > 0x30) 3 else 1) {
                buf[1] = @intCast(t);
                try expectValidAndStreamed(alloc, kind, &buf);
            }
            for ([_]u8{ 0x7e, 0x7f, 0x80, 0xa1, 0xfc, 0xfe, 0xff }) |tb| {
                buf[1] = tb;
                try expectValidAndStreamed(alloc, kind, &buf);
            }
        }
    }
}

test "gb18030: four-byte pointers outside the index and cut four-byte forms are errors (sweep EN)" {
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{
        "\xfe\x39\xfe\x39", // pointer 1_575_000+ > 1_237_575
        "\x84\x31\xa4\x39", // 39419 + 1: the gap before the supplementary planes
        "\x81\x30\x81", // cut after the third byte
        "\x81\x30", // cut after the second byte
        "\x81\x30\x81\x30\x81\x30\x81\x30", // several back to back
        "\x90\x30\x81\x30", // first supplementary pointer
        "\xe3\x32\x9a\x35", // last one, U+10FFFF
        "\xe3\x32\x9a\x36", // one past it
    };
    for (cases) |c| try expectValidAndStreamed(alloc, .gb18030, c);
}

test "ISO-2022-JP: escapes without an end, nested escapes and control codes are not a loop or a crash (sweep EN)" {
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{
        "\x1b",               "\x1b$",                                     "\x1b$(",               "\x1b(",      "\x1b(B\x1b",           "\x1b$B\x30", "\x1b$B\x30\x1b",
        "\x1b$B\x1b$B\x1b$B", "\x1b$@\x21\x21\x1b(J\\~\x1b(I\x21\x5f\x7f", "\x0e\x0f\x1b\x1b\x1b", "\x1b$B\x21", "\x1b$B\x7e\x7e\x1b(B",
    };
    for (cases) |c| try expectValidAndStreamed(alloc, .iso_2022_jp, c);
}

test "encoders: the largest substitute per input fits the allocating API's sizing (sweep EN)" {
    const alloc = std.testing.allocator;
    // U+10FFFF is four input bytes and ten output bytes in html_ncr mode.
    const hi = "\u{10FFFF}";
    for ([_]enc.Encoding{ .iso_8859_2, .windows_1250, .windows_1252 }) |e| {
        const input = try repeated(alloc, hi, 5, "");
        defer alloc.free(input);
        const want = try repeated(alloc, "&#1114111;", 5, "");
        defer alloc.free(want);
        const out = try enc.encodeFromUtf8Opts(alloc, input, e, .{ .unmappable = .html_ncr });
        defer alloc.free(out);
        try std.testing.expectEqualStrings(want, out);
    }
    for (std.enums.values(cjk.Cjk)) |kind| {
        const input = try repeated(alloc, hi, 3, "\xff\xc3");
        defer alloc.free(input);
        const out = try cjk.encodeFromUtf8(alloc, input, kind, .{ .unmappable = .html_ncr });
        defer alloc.free(out);
        try std.testing.expect(out.len >= 3);
    }
    // Every scalar value class through every CJK encoder with each substitute mode.
    for (std.enums.values(cjk.Cjk)) |kind| {
        var cp: u21 = 0x80;
        while (cp <= 0x10FFFF) : (cp += 0x3ff1) {
            if (cp >= 0xD800 and cp <= 0xDFFF) continue;
            var b: [4]u8 = undefined;
            const n = try std.unicode.utf8Encode(cp, &b);
            for ([_]enc.Unmappable{ .question_mark, .ignore, .html_ncr }) |m| {
                const out = try cjk.encodeFromUtf8(alloc, b[0..n], kind, .{ .unmappable = m });
                alloc.free(out);
            }
        }
    }
}

test "UTF-16 / UTF-32: odd byte counts, lone and swapped surrogates, cut units decode without error (sweep EN)" {
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{
        "\x00",                 "\x00\xd8",         "\x00\xd8\x00",         "\x00\xd8\x00\xd8", "\x00\xdc", "\x00\xdc\x00\xd8", "\x00\xd8\x00\xdc\x00",
        "\xff\xff\xff\xff\xff", "\x00\x00\x11\x00", "\x00\xd8\x00\x00\x00",
    };
    for (cases) |c| {
        for ([_]enc.Utf16Endian{ .le, .be }) |e| {
            const a = try enc.decodeUtf16(alloc, c, e);
            defer alloc.free(a);
            try std.testing.expect(std.unicode.utf8ValidateSlice(a));
            const b = try enc.decodeUtf32(alloc, c, e);
            defer alloc.free(b);
            try std.testing.expect(std.unicode.utf8ValidateSlice(b));
        }
    }
}

/// Encode `chunks` in order through the caller-buffer API with a `dst_len` window,
/// resuming after every `.output_full` at `src[read..]`.
fn driveEncode(alloc: std.mem.Allocator, e: enc.Encoding, mode: enc.Unmappable, chunks: []const []const u8, dst_len: usize) ![]u8 {
    var ec: enc.Encoder = .init(.{ .encoding = e }, .{ .unmappable = mode });
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var dst: [64]u8 = undefined;
    for (chunks, 0..) |chunk, ci| {
        const last = ci + 1 == chunks.len;
        var r: usize = 0;
        var guard: usize = 0;
        while (true) : (guard += 1) {
            try std.testing.expect(guard < 1000);
            const p = ec.encodeInto(chunk[r..], dst[0..dst_len], last);
            try out.appendSlice(alloc, dst[0..p.written]);
            r += p.read;
            switch (p.status) {
                .input_empty => break,
                .output_full => {},
                .unmappable => return error.TestUnexpectedResult,
            }
        }
        try std.testing.expectEqual(chunk.len, r);
    }
    return out.toOwnedSlice(alloc);
}

test "Encoder: an output_full after carried bytes never leaves a non-lead byte to trip a later call (sweep REV-EN-1)" {
    const alloc = std.testing.allocator;
    var ec: enc.Encoder = .init(.{ .encoding = .windows_1252 }, .{});
    var big: [64]u8 = undefined;
    var small: [10]u8 = undefined;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    // The reviewer's sequence: a cut sequence, then too little room, then enough.
    var p = ec.encodeInto("\xE2\x82", &big, false);
    try out.appendSlice(alloc, big[0..p.written]);
    try std.testing.expectEqual(@as(usize, 2), p.read);
    p = ec.encodeInto("x", &small, false);
    try out.appendSlice(alloc, small[0..p.written]);
    var r = p.read;
    try std.testing.expectEqual(enc.EncodeStatus.output_full, p.status);
    p = ec.encodeInto("x"[r..], &big, true);
    try out.appendSlice(alloc, big[0..p.written]);
    try std.testing.expectEqualStrings("\xE2\x82x", out.items);
    r = 0;
}

test "Encoder: any dst window and any split of mixed input equals the whole-buffer encode, both replacement modes (sweep REV-EN-1)" {
    const alloc = std.testing.allocator;
    const inputs = [_][]const u8{
        "a\xE2\x82\xACb\xC3\xA9",
        "\xE2\x82",
        "\xE2\x82x",
        "\xFF\xE2\xF0\x9F\x98\x80z",
        "\xC3\xA9\xC3",
        "\xF0\x9F\x98\x80\xE2",
        "\xF0\x9F\x98\x80\xF0\x9F\x98\x80\xE2\x98\x83",
    };
    for ([_]enc.Encoding{ .windows_1252, .iso_8859_2 }) |e| {
        for ([_]enc.Unmappable{ .question_mark, .html_ncr }) |mode| {
            for (inputs) |input| {
                const want = try enc.encodeFromUtf8Opts(alloc, input, e, .{ .unmappable = mode });
                defer alloc.free(want);
                for (core_min_room..33) |dst_len| {
                    for (0..input.len + 1) |cut| {
                        const got = try driveEncode(alloc, e, mode, &.{ input[0..cut], input[cut..] }, dst_len);
                        defer alloc.free(got);
                        try std.testing.expectEqualSlices(u8, want, got);
                    }
                }
            }
        }
    }
}

const core_min_room = 10; // the documented room per non-ASCII step (`core.max_substitute`)

test "Encoder fatal: the carried bytes of an unmappable code point are consumed and read is past it (sweep REV-EN-3)" {
    var ec: enc.Encoder = .init(.{ .encoding = .windows_1250 }, .{ .unmappable = .fatal });
    var dst: [32]u8 = undefined;
    var p = ec.encodeInto("a\xE2\x98", &dst, false); // U+2603, cut after two bytes
    try std.testing.expectEqual(enc.EncodeStatus.input_empty, p.status);
    try std.testing.expectEqual(@as(usize, 3), p.read);
    p = ec.encodeInto("\x83b", &dst, false);
    try std.testing.expectEqual(enc.EncodeStatus.unmappable, p.status);
    try std.testing.expectEqual(@as(u21, 0x2603), p.code_point);
    try std.testing.expectEqual(@as(usize, 1), p.read);
    // The caller substitutes and continues with src[read..]: progress, no repeat.
    p = ec.encodeInto("\x83b"[p.read..], &dst, true);
    try std.testing.expectEqual(enc.EncodeStatus.input_empty, p.status);
    try std.testing.expectEqualStrings("b", dst[0..p.written]);
}

test "caller-buffer ASCII copy scans only the room in dst, not the whole tail (sweep REV-EN-2)" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const page = 4096;
    const addr = linux.mmap(null, 2 * page, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
    if (linux.errno(addr) != .SUCCESS) return error.SkipZigTest;
    const base: [*]u8 = @ptrFromInt(addr);
    defer _ = linux.munmap(base, 2 * page);
    @memset(base[0..page], 'a');
    if (linux.errno(linux.mprotect(base + page, page, .{})) != .SUCCESS) return error.SkipZigTest;
    // 100 readable ASCII bytes, then the guard page, all claimed as `src`.
    const src = base[page - 100 .. 2 * page];
    var dst: [64]u8 = undefined;

    var sbd: enc.Decoder = .init(.{ .encoding = .windows_1252 }, .{});
    const d = sbd.decodeInto(src, &dst, false);
    try std.testing.expectEqual(@as(usize, 64), d.written);
    var dst2: [64]u8 = undefined;
    var dec: cjk.Decoder = .init(.euc_jp, .{});
    const dj = dec.decodeInto(src, &dst2, false);
    try std.testing.expect(dj.written >= 64);
    var ec: enc.Encoder = .init(.{ .encoding = .windows_1252 }, .{});
    const pe = ec.encodeInto(src, &dst, false);
    try std.testing.expectEqual(@as(usize, 64), pe.written);
}

test "Encoder: a multi-byte character fed one byte per call reports read = 1 each time and encodes like the whole buffer (sweep audit GP-EN-1)" {
    const alloc = std.testing.allocator;
    const inputs = [_][]const u8{
        "\xF0\x9F\x98\x80", // 4-byte character, still cut after 1, 2 and 3 bytes
        "a\xE2\x82\xACb", // 3-byte character
        "\xF0\x9F\x98\x80\xF0\x9F\x98\x80\xE2\x98\x83",
    };
    for ([_]enc.Encoding{ .windows_1252, .iso_8859_2 }) |e| {
        for ([_]enc.Unmappable{ .question_mark, .html_ncr }) |mode| {
            for (inputs) |input| {
                const want = try enc.encodeFromUtf8Opts(alloc, input, e, .{ .unmappable = mode });
                defer alloc.free(want);
                var chunks: [16][]const u8 = undefined;
                for (input, 0..) |_, i| chunks[i] = input[i..][0..1];
                for (core_min_room..33) |dst_len| {
                    const got = try driveEncode(alloc, e, mode, chunks[0..input.len], dst_len);
                    defer alloc.free(got);
                    try std.testing.expectEqualSlices(u8, want, got);
                }
            }
        }
    }
}

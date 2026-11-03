// SPDX-License-Identifier: MIT
//! Checksum-file parse/verify tests, the cross-implementation goldens
//! (Python hashlib / GNU coreutils through the public API; recipe in
//! `tools/gen_golden.py`) and the SHAKE / BLAKE3 modes.
const std = @import("std");
const testing = std.testing;
const hd = @import("root.zig");
const ck = hd.checksum;

fn msg(buf: []u8, n: usize) []u8 {
    for (buf[0..n], 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    return buf[0..n];
}

fn algoNamed(s: []const u8) ?hd.Algorithm {
    return std.meta.stringToEnum(hd.Algorithm, s);
}

test "golden: every digest equals Python hashlib (OpenSSL) on generated messages" {
    const rows = @embedFile("testdata/golden.tsv");
    var lines = std.mem.splitScalar(u8, rows, '\n');
    var checked: usize = 0;
    var data: [4096]u8 = undefined;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var f = std.mem.splitScalar(u8, line, '\t');
        const name = f.next().?;
        const len = try std.fmt.parseInt(usize, f.next().?, 10);
        const want = f.next().?;
        const m = msg(&data, len);
        if (algoNamed(name)) |a| {
            var out: [hd.max_hex_len]u8 = undefined;
            try testing.expectEqualStrings(want, try hd.hex(a, m, &out));
            // incremental, in uneven pieces, agrees too
            var h = hd.MultiHasher.init(a);
            var pos: usize = 0;
            var step: usize = 1;
            while (pos < m.len) : (step = step * 3 % 97 + 1) {
                const n = @min(step, m.len - pos);
                h.update(m[pos..][0..n]);
                pos += n;
            }
            try testing.expectEqualStrings(want, try h.finalHex(&out));
        } else {
            const kind: hd.Xof = if (std.mem.eql(u8, name, "shake128")) .shake128 else .shake256;
            var raw: [100]u8 = undefined;
            hd.xof(kind, m, &raw);
            const got = std.fmt.bytesToHex(raw, .lower);
            try testing.expectEqualStrings(want, &got);
        }
        checked += 1;
    }
    try testing.expectEqual(@as(usize, 180), checked);
}

test "xof: prefix property, empty and long output; BLAKE3 empty-input vector" {
    var a: [300]u8 = undefined;
    var b: [17]u8 = undefined;
    for ([_]hd.Xof{ .shake128, .shake256, .blake3 }) |k| {
        hd.xof(k, "abc", &a);
        hd.xof(k, "abc", &b);
        try testing.expectEqualSlices(u8, a[0..b.len], &b);
        hd.xof(k, "abc", a[0..0]); // zero-length output is defined
    }
    var o: [32]u8 = undefined;
    hd.xof(.blake3, "", &o);
    const hx = std.fmt.bytesToHex(o, .lower);
    try testing.expectEqualStrings("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", &hx);
}

test "blake3 keyed and derive-key: separated from plain, from each other, deterministic" {
    const key: [32]u8 = @splat(7);
    var plain: [32]u8 = undefined;
    var keyed: [32]u8 = undefined;
    var keyed2: [32]u8 = undefined;
    hd.xof(.blake3, "data", &plain);
    hd.blake3Keyed(&key, "data", &keyed);
    hd.blake3Keyed(&key, "data", &keyed2);
    try testing.expect(!std.mem.eql(u8, &plain, &keyed));
    try testing.expectEqualSlices(u8, &keyed, &keyed2);
    var other: [32]u8 = undefined;
    const key8: [32]u8 = @splat(8);
    hd.blake3Keyed(&key8, "data", &other);
    try testing.expect(!std.mem.eql(u8, &keyed, &other));
    var d1: [48]u8 = undefined;
    var d2: [48]u8 = undefined;
    hd.blake3DeriveKey("ctx one", "material", &d1);
    hd.blake3DeriveKey("ctx two", "material", &d2);
    try testing.expect(!std.mem.eql(u8, &d1, &d2));
    var d3: [16]u8 = undefined;
    hd.blake3DeriveKey("ctx one", "material", &d3);
    try testing.expectEqualSlices(u8, d1[0..16], &d3);
}

test "parse: GNU text and binary lines, BSD tag, comments, blanks, CRLF, escapes" {
    const text =
        "# comment\n\n" ++
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc.txt\n" ++
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD *bin file\r\n" ++
        "SHA256 (tagged name) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n" ++
        "\\ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  a\\nb\\\\c\n";
    var it = ck.Iterator.init(text);
    const e1 = (try it.next()).?;
    try testing.expectEqualStrings("abc.txt", e1.name);
    try testing.expect(e1.algo == null and !e1.binary and !e1.escaped and e1.line == 3);
    const e2 = (try it.next()).?;
    try testing.expectEqualStrings("bin file", e2.name);
    try testing.expect(e2.binary);
    const e3 = (try it.next()).?;
    try testing.expectEqualStrings("tagged name", e3.name);
    try testing.expect(e3.algo.? == .sha256);
    const e4 = (try it.next()).?;
    var nb: [16]u8 = undefined;
    try testing.expectEqualStrings("a\nb\\c", try e4.unescapeName(&nb));
    try testing.expectError(error.ShortBuffer, e4.unescapeName(nb[0..3]));
    try testing.expect((try it.next()) == null);
}

test "parse: malformed lines are errors, the iterator moves on" {
    const text = "zz  x\n" ++ "abcd x\n" ++ "abcd  \n" ++ "abcd\n" ++ "NOPE (x) = abcd\n" ++ "SHA256 (x) = xyz\n" ++
        "\\abcd  bad\\q\n" ++ "abcd  ok\n";
    var it = ck.Iterator.init(text);
    var bad: usize = 0;
    var unk: usize = 0;
    var good: usize = 0;
    var bad_escape: usize = 0;
    while (true) {
        const e = it.next() catch |err| {
            if (err == error.UnknownTag) unk += 1 else bad += 1;
            continue;
        };
        const v = e orelse break;
        if (v.escaped) {
            var nb: [16]u8 = undefined;
            try testing.expectError(error.BadLine, v.unescapeName(&nb));
            bad_escape += 1;
        } else good += 1;
    }
    try testing.expectEqual(@as(usize, 1), unk);
    try testing.expectEqual(@as(usize, 5), bad);
    try testing.expectEqual(@as(usize, 1), good);
    try testing.expectEqual(@as(usize, 1), bad_escape);
}

test "tagOf names every algorithm, and a tag line parses back to it" {
    for (std.enums.values(hd.Algorithm)) |a| {
        var buf: [200]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "{s} (f) = {s}", .{ ck.tagOf(a), "00" });
        const e = try ck.parseLine(line, 1);
        try testing.expect(e.algo.? == a);
    }
}

/// Write the files the goldens name into `dir`; the name ends in the message length.
fn writeFixtures(dir: std.Io.Dir) !void {
    const names = [_][]const u8{ "f0", "f1", "f200", "a b100", "back\\slash64", "new\nline33", "star*65", "tab\there129", "(paren) = x7" };
    var data: [256]u8 = undefined;
    for (names) |nm| {
        var start = nm.len;
        while (start > 0 and std.ascii.isDigit(nm[start - 1])) start -= 1;
        const n = try std.fmt.parseInt(usize, nm[start..], 10);
        try dir.writeFile(testing.io, .{ .sub_path = nm, .data = msg(&data, n) });
    }
}

test "sums.txt from GNU coreutils (sha256sum, sha512sum, b2sum; plain, --binary, --tag) verifies entirely" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeFixtures(tmp.dir);
    const text = @embedFile("testdata/sums.txt");
    var blocks = std.mem.splitSequence(u8, text, "# algo=");
    _ = blocks.next();
    var total: usize = 0;
    while (blocks.next()) |blk| {
        const sp = std.mem.findScalar(u8, blk, ' ').?;
        const algo = algoNamed(blk[0..sp]).?;
        const body = blk[std.mem.findScalar(u8, blk, '\n').? + 1 ..]; // past the rest of the "# algo=" line
        const s = ck.verifyAll(testing.io, tmp.dir, algo, body);
        try testing.expectEqual(@as(usize, 9), s.ok);
        try testing.expect(s.allOk());
        total += s.ok;
    }
    try testing.expectEqual(@as(usize, 63), total);
}

test "verify: tampered file is a mismatch, missing is unreadable, wrong digest length and bad escape are malformed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a", .data = "abc" });
    const good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    var buf: [512]u8 = undefined;
    const ok_line = try std.fmt.bufPrint(&buf, "{s}  a\n", .{good});
    try testing.expectEqual(@as(usize, 1), ck.verifyAll(testing.io, tmp.dir, .sha256, ok_line).ok);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a", .data = "abd" });
    try testing.expectEqual(@as(usize, 1), ck.verifyAll(testing.io, tmp.dir, .sha256, ok_line).mismatch);

    const missing = try std.fmt.bufPrint(&buf, "{s}  nope\n", .{good});
    try testing.expectEqual(@as(usize, 1), ck.verifyAll(testing.io, tmp.dir, .sha256, missing).unreadable);

    const s = ck.verifyAll(testing.io, tmp.dir, .sha256, "abcd  a\n\\" ++ good ++ "  a\\q\ngarbage\n");
    try testing.expectEqual(@as(usize, 3), s.malformed);
    try testing.expect(!s.allOk());
}

test "verify: a name past max_name_len is NameTooLong, not a panic" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const name = try testing.allocator.alloc(u8, ck.max_name_len + 1);
    defer testing.allocator.free(name);
    @memset(name, 'n');
    const e = ck.Entry{ .algo = .sha256, .digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", .name = name, .escaped = false, .binary = false, .line = 1 };
    try testing.expectError(error.NameTooLong, ck.verifyEntry(testing.io, tmp.dir, .sha256, e));
}

test "hashFileIn: relative to the given directory, ShortBuffer checked" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "x", .data = "abc" });
    var out: [hd.max_hex_len]u8 = undefined;
    try testing.expectEqual(@as(?u64, 3), try hd.hashFileIn(.sha256, testing.io, tmp.dir, "x", &out));
    try testing.expect((try hd.hashFileIn(.sha256, testing.io, tmp.dir, "y", &out)) == null);
    try testing.expectError(error.ShortBuffer, hd.hashFileIn(.sha256, testing.io, tmp.dir, "x", out[0..10]));
}

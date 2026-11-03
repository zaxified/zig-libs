// SPDX-License-Identifier: MIT
//! Deterministic fuzz driver for the checksum-file parser (`checksum.zig`).
//! `HASHDIGEST_FUZZ=<runs>[,<first seed>]` runs it (testkit's driver); the
//! harness is generic over its choice source, so `testing.fuzz` (Smith) and the
//! driver (Rng) share it. Oracles: no panic, an entry's digest is hex and its
//! name non-empty, `unescapeName` is total, and a GNU line rendered back from
//! a parsed entry parses to the same digest and name.
const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const ck = @import("checksum.zig");
const fuzz_driver = testkit.fuzz.driver;
const seed = testkit.fuzz.seed;

const corpus = [_][]const u8{
    seed("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc.txt\n"),
    seed("# c\n\nBA7816BF *bin file\r\nSHA256 (tagged name) = ba7816bf\n"),
    seed("\\ba7816bf  a\\nb\\\\c\n\\SHA512 (x\\ny) = ab\n"),
    seed("SHA512/256 (a) = 00\nBLAKE2b-256 (b) = 00\nNOPE (c) = 00\nSHA256 ((p) = x) = 00\n"),
    seed("ab  (paren) = x\nab ( x\n) = \n\\\n \n"),
};

const Label = enum { empty, gnu, bsd, escaped, bad_line, unknown_tag, roundtrip };
var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    counts[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn drawInput(comptime S: type, src: *S, buf: []u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf); // Smith: one faithful slice draw first
    if (!src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const text = buf[0..drawInput(S, src, &buf)];
    var it = ck.Iterator.init(text);
    var n: usize = 0;
    while (true) {
        const e = (it.next() catch |err| {
            if (err == error.UnknownTag) mark(.unknown_tag) else mark(.bad_line);
            continue;
        }) orelse break;
        n += 1;
        if (e.algo != null) mark(.bsd) else mark(.gnu);
        if (e.digest.len == 0 or e.name.len == 0) return error.EmptyField;
        for (e.digest) |c| if (!std.ascii.isHex(c)) return error.DigestNotHex;
        var nb: [64]u8 = undefined;
        if (e.escaped) mark(.escaped);
        const name = e.unescapeName(&nb) catch continue;
        if (!e.escaped and name.len != e.name.len) return error.NameChanged;
        // Round trip a plain name through a rendered GNU line.
        if (!e.escaped and e.name.len + e.digest.len < 200 and std.mem.findAny(u8, e.name, "\\\n\r") == null) {
            var lb: [256]u8 = undefined;
            const line = try std.fmt.bufPrint(&lb, "{s}  {s}", .{ e.digest, e.name });
            const back = try ck.parseLine(line, 1);
            if (!std.mem.eql(u8, back.digest, e.digest) or !std.mem.eql(u8, back.name, e.name)) return error.RoundTrip;
            mark(.roundtrip);
        }
    }
    if (n == 0) mark(.empty);
}

fn harnessSmith(_: void, smith: *std.testing.Smith) !void {
    try harness(std.testing.Smith, smith, testing.allocator);
}

test "fuzz checksum parser never panics (Smith, corpus replay)" {
    try testing.fuzz({}, harnessSmith, .{ .corpus = &corpus });
}

test "fuzz driver: HASHDIGEST_FUZZ (checksum parser)" {
    try fuzz_driver.run(harness, .{ .prefix = "HASHDIGEST_FUZZ", .name = "hashdigest-checksum" });
}

test "fuzz harness: 2000 seeds reach every outcome" {
    counts = @splat(0);
    for (0..2000) |s| {
        var prng = std.Random.DefaultPrng.init(s);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        try harness(fuzz_driver.Rng, &rng, testing.allocator);
    }
    for (counts, 0..) |c, i| if (c == 0) {
        std.debug.print("reach: label {d} never hit\n", .{i});
        return error.HarnessDoesNotReach;
    };
}

// SPDX-License-Identifier: MIT
//! Sparse members (2026-11-04): GNU old 'S' and pax 0.0 / 0.1 / 1.0. The four
//! fixtures are GNU tar 1.35's output for one synthetic 1 053 576-byte file with
//! three data islands (`tar --sparse`, `-b 1`, recipe in `testdata/README`-free
//! form below); Go's `archive/tar` reads the same four to the same SHA-256
//! (2a179827fc2e...), which is the external anchor. Hostile maps, a size/map
//! lie that must not desynchronise the stream, and the fuzz harness are here.
//!
//! Recipe: a file truncated to 1053576 bytes with data at 0 (4096 bytes),
//! 300000 (10000) and 1000000 (700); byte at logical position p is
//! `p % 251 + 1`; mode 0640, mtime 1700000000; `tar --numeric-owner -b 1
//! --owner=1000 --group=1000 --format=gnu --sparse` (gnu_old) or
//! `--format=pax --sparse --sparse-version=1.0|0.1|0.0`.

const std = @import("std");
const testing = std.testing;
const tar = @import("root.zig");
const fz = @import("fuzz_test.zig");

const real_size: u64 = 1053576;
const islands = [_][2]u64{ .{ 0, 4096 }, .{ 300000, 10000 }, .{ 1000000, 700 } };

fn expectedByte(p: u64) u8 {
    for (islands) |i| if (p >= i[0] and p < i[0] + i[1]) return @intCast(p % 251 + 1);
    return 0;
}

/// Read the whole current entry through `read` with an awkward buffer size and
/// check it against `expected(position)`.
fn drain(tr: *tar.Reader, comptime expected: fn (u64) u8, total: u64) !void {
    var buf: [4093]u8 = undefined;
    var pos: u64 = 0;
    while (true) {
        const n = try tr.read(&buf);
        if (n == 0) break;
        for (buf[0..n], 0..) |b, i| if (b != expected(pos + i)) {
            std.debug.print("sparse: byte {d}: {d} != {d}\n", .{ pos + i, b, expected(pos + i) });
            return error.WrongContent;
        };
        pos += n;
    }
    try testing.expectEqual(total, pos);
}

fn checkFixture(bytes: []const u8) !void {
    var src: std.Io.Reader = .fixed(bytes);
    var tr = tar.Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqualStrings("sparse.bin", e.path);
    try testing.expectEqual(tar.Kind.file, e.kind);
    try testing.expectEqual(real_size, e.size);
    try testing.expectEqual(@as(u32, 1000), e.uid);
    try testing.expectEqual(@as(u32, 0o640), e.mode);
    try testing.expectEqual(@as(i64, 1700000000), e.mtime);
    try drain(&tr, expectedByte, real_size);
    try testing.expect((try tr.next()) == null);
}

test "sparse: GNU old 'S' (tar --format=gnu --sparse) reads back as the whole file" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    try checkFixture(@embedFile("testdata/read_sparse_gnu_old.tar"));
}
test "sparse: pax 1.0 (map in the data) reads back as the whole file" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    try checkFixture(@embedFile("testdata/read_sparse_pax_10.tar"));
}
test "sparse: pax 0.1 (GNU.sparse.map) reads back as the whole file" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    try checkFixture(@embedFile("testdata/read_sparse_pax_01.tar"));
}
test "sparse: pax 0.0 (repeated offset/numbytes) reads back as the whole file" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    try checkFixture(@embedFile("testdata/read_sparse_pax_00.tar"));
}

test "sparse: unread content is skipped, the next entry is found" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    inline for (.{ "gnu_old", "pax_10", "pax_01", "pax_00" }) |v| {
        var src: std.Io.Reader = .fixed(@embedFile("testdata/read_sparse_" ++ v ++ ".tar"));
        var tr = tar.Reader.init(testing.allocator, &src);
        defer tr.deinit();
        _ = (try tr.next()).?;
        var one: [7]u8 = undefined;
        _ = try tr.read(&one); // part of a hole
        try testing.expect((try tr.next()) == null);
    }
}

// ── hand-built archives ─────────────────────────────────────────────────────

const Seg = struct { off: u64, len: u64 };

fn stamp(block: *[512]u8) void {
    @memset(block[148..156], ' ');
    var sum: u32 = 0;
    for (block) |b| sum += b;
    _ = std.fmt.bufPrint(block[148..155], "{o:0>6}\x00", .{sum}) catch unreachable;
}

fn header(name: []const u8, typeflag: u8, size: u64) [512]u8 {
    var b: [512]u8 = @splat(0);
    @memcpy(b[0..name.len], name);
    _ = std.fmt.bufPrint(b[100..108], "{o:0>7}", .{@as(u32, 0o644)}) catch unreachable;
    _ = std.fmt.bufPrint(b[108..116], "{o:0>7}", .{@as(u32, 1000)}) catch unreachable;
    _ = std.fmt.bufPrint(b[116..124], "{o:0>7}", .{@as(u32, 1000)}) catch unreachable;
    _ = std.fmt.bufPrint(b[124..136], "{o:0>11}", .{size}) catch unreachable;
    _ = std.fmt.bufPrint(b[136..148], "{o:0>11}", .{@as(u32, 1700000000)}) catch unreachable;
    b[156] = typeflag;
    @memcpy(b[257..265], "ustar  \x00");
    return b;
}

const Kind = enum { gnu, v00, v01, v10 };

fn pad(list: *std.ArrayList(u8), gpa: std.mem.Allocator) !void {
    while (list.items.len % 512 != 0) try list.append(gpa, 0);
}

fn record(list: *std.ArrayList(u8), gpa: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    var len: usize = key.len + value.len + 3;
    while (std.fmt.count("{d}", .{len}) + key.len + value.len + 3 != len) len = std.fmt.count("{d}", .{len}) + key.len + value.len + 3;
    try list.print(gpa, "{d} {s}={s}\n", .{ len, key, value });
}

fn pattern(p: u64) u8 {
    return @intCast(p % 251 + 1);
}

/// One sparse member in generation `kind` with the given map, then a plain
/// file "tail" and the trailer. `stored_extra` adds that many stored bytes the
/// map does not use (a lying size), `size_lie` adjusts the header size.
fn build(gpa: std.mem.Allocator, kind: Kind, segs: []const Seg, real: u64, stored_extra: u64) ![]u8 {
    return buildEx(gpa, kind, segs, real, stored_extra, &.{});
}

/// `build` plus extra `GNU.sparse.*` records appended to the pax header (the last
/// of a repeated key wins), or, for the GNU form, a `realsize` extra written as
/// a base-256 field.
fn buildEx(gpa: std.mem.Allocator, kind: Kind, segs: []const Seg, real: u64, stored_extra: u64, extras: []const [2][]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);
    for (segs) |s| {
        var i: u64 = 0;
        while (i < s.len) : (i += 1) try data.append(gpa, pattern(s.off +% i));
    }
    try data.appendNTimes(gpa, 0xEE, @intCast(stored_extra));
    switch (kind) {
        .gnu => {
            var h = header("g.bin", 'S', data.items.len);
            var ext: std.ArrayList(u8) = .empty;
            defer ext.deinit(gpa);
            for (segs, 0..) |s, i| {
                if (i < 4) {
                    _ = std.fmt.bufPrint(h[386 + i * 24 ..][0..12], "{o:0>11}", .{s.off}) catch unreachable;
                    _ = std.fmt.bufPrint(h[386 + i * 24 + 12 ..][0..12], "{o:0>11}", .{s.len}) catch unreachable;
                } else {
                    const j = i - 4;
                    if (j % 21 == 0) {
                        try pad(&ext, gpa);
                        try ext.appendNTimes(gpa, 0, 512);
                    }
                    const base = ext.items.len - 512 + (j % 21) * 24;
                    _ = std.fmt.bufPrint(ext.items[base..][0..12], "{o:0>11}", .{s.off}) catch unreachable;
                    _ = std.fmt.bufPrint(ext.items[base + 12 ..][0..12], "{o:0>11}", .{s.len}) catch unreachable;
                }
            }
            _ = std.fmt.bufPrint(h[483..495], "{o:0>11}", .{real}) catch unreachable;
            for (extras) |x| if (std.mem.eql(u8, x[0], "GNU.sparse.realsize")) {
                @memset(h[483..495], 0);
                h[483] = 0x80;
                std.mem.writeInt(u64, h[487..495], std.fmt.parseInt(u64, x[1], 10) catch 0, .big);
            };
            if (segs.len > 4) h[482] = 1;
            var k: usize = 0;
            while (k * 512 < ext.items.len) : (k += 1) {
                ext.items[k * 512 + 504] = if ((k + 1) * 512 < ext.items.len) 1 else 0;
            }
            stamp(&h);
            try out.appendSlice(gpa, &h);
            try out.appendSlice(gpa, ext.items);
            try out.appendSlice(gpa, data.items);
        },
        .v00, .v01, .v10 => {
            var px: std.ArrayList(u8) = .empty;
            defer px.deinit(gpa);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(gpa);
            var num: [32]u8 = undefined;
            switch (kind) {
                .v10 => {
                    try record(&px, gpa, "GNU.sparse.major", "1");
                    try record(&px, gpa, "GNU.sparse.minor", "0");
                    try record(&px, gpa, "GNU.sparse.name", "p.bin");
                    try record(&px, gpa, "GNU.sparse.realsize", try std.fmt.bufPrint(&num, "{d}", .{real}));
                    try body.print(gpa, "{d}\n", .{segs.len});
                    for (segs) |s| try body.print(gpa, "{d}\n{d}\n", .{ s.off, s.len });
                    try pad(&body, gpa);
                },
                .v01 => {
                    try record(&px, gpa, "GNU.sparse.major", "0");
                    try record(&px, gpa, "GNU.sparse.minor", "1");
                    try record(&px, gpa, "GNU.sparse.size", try std.fmt.bufPrint(&num, "{d}", .{real}));
                    var map: std.ArrayList(u8) = .empty;
                    defer map.deinit(gpa);
                    for (segs, 0..) |s, i| try map.print(gpa, "{s}{d},{d}", .{ if (i == 0) "" else ",", s.off, s.len });
                    try record(&px, gpa, "GNU.sparse.map", map.items);
                },
                else => {
                    try record(&px, gpa, "GNU.sparse.size", try std.fmt.bufPrint(&num, "{d}", .{real}));
                    try record(&px, gpa, "GNU.sparse.numblocks", try std.fmt.bufPrint(&num, "{d}", .{segs.len}));
                    for (segs) |s| {
                        var n1: [24]u8 = undefined;
                        var n2: [24]u8 = undefined;
                        try record(&px, gpa, "GNU.sparse.offset", try std.fmt.bufPrint(&n1, "{d}", .{s.off}));
                        try record(&px, gpa, "GNU.sparse.numbytes", try std.fmt.bufPrint(&n2, "{d}", .{s.len}));
                    }
                },
            }
            for (extras) |x| try record(&px, gpa, x[0], x[1]);
            var xh = header("././@PaxHeader", 'x', px.items.len);
            stamp(&xh);
            try out.appendSlice(gpa, &xh);
            try out.appendSlice(gpa, px.items);
            try pad(&out, gpa);
            var h = header("GNUSparseFile.0/p.bin", '0', body.items.len + data.items.len);
            stamp(&h);
            try out.appendSlice(gpa, &h);
            try out.appendSlice(gpa, body.items);
            try out.appendSlice(gpa, data.items);
        },
    }
    try pad(&out, gpa);
    var t = header("tail", '0', 4);
    stamp(&t);
    try out.appendSlice(gpa, &t);
    try out.appendSlice(gpa, "tail");
    try pad(&out, gpa);
    try out.appendNTimes(gpa, 0, 1024);
    return out.toOwnedSlice(gpa);
}

const Walk = struct { sparse_parsed: bool = false, first_size: u64 = 0, content_ok: bool = true, saw_tail: bool = false, err: ?tar.ReadError = null };

/// Walk `bytes`, checking the first entry's content against `pattern` over
/// `segs` (zeros elsewhere) and that "tail" follows.
fn walk(gpa: std.mem.Allocator, bytes: []const u8, segs: []const Seg) Walk {
    var w: Walk = .{};
    var src: std.Io.Reader = .fixed(bytes);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    var first = true;
    while (true) {
        const e = (tr.next() catch |err| {
            w.err = err;
            return w;
        }) orelse return w;
        if (!first) {
            w.saw_tail = std.mem.eql(u8, e.path, "tail");
            return w;
        }
        first = false;
        w.first_size = e.size;
        w.sparse_parsed = tr.is_sparse;
        var buf: [333]u8 = undefined;
        var pos: u64 = 0;
        while (true) {
            const n = tr.read(&buf) catch |err| {
                w.err = err;
                return w;
            };
            if (n == 0) break;
            for (buf[0..n], 0..) |b, i| {
                var want: u8 = 0;
                for (segs) |s| if (pos + i >= s.off and pos + i < s.off + s.len) {
                    want = pattern(pos + i);
                };
                if (b != want) w.content_ok = false;
            }
            pos += n;
            if (pos > (1 << 20)) return w; // a quota, as a consumer would apply to a declared size
        }
        if (pos != e.size) w.content_ok = false;
    }
}

const good_segs = [_]Seg{ .{ .off = 100, .len = 600 }, .{ .off = 1000, .len = 1 }, .{ .off = 5000, .len = 1500 } };

test "sparse: every generation round-trips a hand-built map, with a member after it" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    for ([_]Kind{ .gnu, .v00, .v01, .v10 }) |k| {
        const a = try build(testing.allocator, k, &good_segs, 9000, 0);
        defer testing.allocator.free(a);
        const w = walk(testing.allocator, a, &good_segs);
        try testing.expectEqual(@as(?tar.ReadError, null), w.err);
        try testing.expectEqual(@as(u64, 9000), w.first_size);
        try testing.expect(w.content_ok);
        try testing.expect(w.saw_tail);
    }
}

test "sparse: GNU extension blocks (more than four segments), and a map with none" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    var segs: [60]Seg = undefined;
    for (&segs, 0..) |*s, i| s.* = .{ .off = i * 100, .len = 1 + i % 50 };
    const a = try build(testing.allocator, .gnu, &segs, 6100, 0);
    defer testing.allocator.free(a);
    const w = walk(testing.allocator, a, &segs);
    try testing.expectEqual(@as(?tar.ReadError, null), w.err);
    try testing.expect(w.content_ok and w.saw_tail);
    // A file that is all hole.
    for ([_]Kind{ .gnu, .v00, .v01, .v10 }) |k| {
        const h = try build(testing.allocator, k, &.{}, 5000, 0);
        defer testing.allocator.free(h);
        const wh = walk(testing.allocator, h, &.{});
        try testing.expectEqual(@as(?tar.ReadError, null), wh.err);
        try testing.expectEqual(@as(u64, 5000), wh.first_size);
        try testing.expect(wh.content_ok and wh.saw_tail);
    }
}

test "sparse: stored bytes the map does not use are BadHeader (Go: errUnrefData; GNU tar reads a header in them)" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    for ([_]Kind{ .gnu, .v00, .v01, .v10 }) |k| {
        const a = try build(testing.allocator, k, &good_segs, 9000, 700);
        defer testing.allocator.free(a);
        const w = walk(testing.allocator, a, &good_segs);
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), w.err);
    }
}

/// 'S' with one all-NUL extension block, size 1024, map empty, then one zero
/// block and a member: GNU tar 1.35 counts the extension block in `size` when the
/// map disagrees, and so lists and extracts `evil-file`.
fn smuggleArchive(gpa: std.mem.Allocator) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var h = header("s", 'S', 1024);
    _ = std.fmt.bufPrint(h[483..495], "{o:0>11}", .{@as(u64, 100)}) catch unreachable;
    h[482] = 1;
    stamp(&h);
    try out.appendSlice(gpa, &h);
    try out.appendNTimes(gpa, 0, 1024);
    var e = header("evil-file", '0', 0);
    stamp(&e);
    try out.appendSlice(gpa, &e);
    try out.appendNTimes(gpa, 0, 1024);
    return out.toOwnedSlice(gpa);
}

test "sparse: a member GNU tar would extract behind a lying 'S' cannot pass checkArchive (delta audit F1)" {
    const a = try smuggleArchive(testing.allocator);
    defer testing.allocator.free(a);
    var src: std.Io.Reader = .fixed(a);
    try testing.expectError(error.BadHeader, tar.checkArchive(testing.allocator, &src, .{ .allow_special = true }));
}

test "sparse: major without minor is BadHeader, not read as x.0 (delta audit F5)" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try paxBlock(&out, gpa, &.{ .{ "GNU.sparse.major", "1" }, .{ "GNU.sparse.realsize", "0" } });
    var h = header("f", '0', 512);
    stamp(&h);
    try out.appendSlice(gpa, &h);
    try out.appendSlice(gpa, "0\n");
    try out.appendNTimes(gpa, 0, 510);
    try out.appendNTimes(gpa, 0, 1024);
    var src: std.Io.Reader = .fixed(out.items);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    try testing.expectError(error.BadHeader, tr.next());
}

test "tar-sparse=false: a sparse member is BadHeader, never misread; records on a link are ignored (delta audit F3)" {
    if (tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    for ([_]Kind{ .gnu, .v00, .v01, .v10 }) |k| {
        const a = try build(gpa, k, &good_segs, 9000, 0);
        defer gpa.free(a);
        var src: std.Io.Reader = .fixed(a);
        try testing.expectError(error.BadHeader, tar.checkArchive(gpa, &src, .{ .allow_special = true }));
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try paxBlock(&out, gpa, &.{.{ "GNU.sparse.major", "1" }});
    var l = header("l", '2', 0);
    @memcpy(l[157..][0..1], "t");
    stamp(&l);
    try out.appendSlice(gpa, &l);
    try out.appendNTimes(gpa, 0, 1024);
    var src: std.Io.Reader = .fixed(out.items);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    try testing.expectEqual(tar.Kind.symlink, (try tr.next()).?.kind);
    try testing.expect((try tr.next()) == null);
}

test "checkEntry: a trailing slash or dot does not add a level for a symlink (delta audit F2)" {
    const escaping = [_][]const u8{ "a/b/", "a/b//", "a/b/.", "a/b/./", "a/b/./." };
    for (escaping) |p| {
        try testing.expectError(error.LinkEscape, tar.checkEntry(.{ .path = p, .kind = .symlink, .link_target = "../.." }, .{}));
        try tar.checkEntry(.{ .path = p, .kind = .symlink, .link_target = ".." }, .{});
    }
    try testing.expectError(error.LinkEscape, tar.checkEntry(.{ .path = "x/", .kind = .symlink, .link_target = ".." }, .{}));
    try tar.checkEntry(.{ .path = "x/", .kind = .symlink, .link_target = "y" }, .{});
}

test "sparse: a hostile map is BadHeader, never a panic or a misread" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const cases = [_]struct { segs: []const Seg, real: u64 }{
        .{ .segs = &.{ .{ .off = 500, .len = 100 }, .{ .off = 100, .len = 10 } }, .real = 9000 }, // out of order
        .{ .segs = &.{ .{ .off = 100, .len = 100 }, .{ .off = 150, .len = 10 } }, .real = 9000 }, // overlap
        .{ .segs = &.{.{ .off = 8990, .len = 100 }}, .real = 9000 }, // past the logical size
        .{ .segs = &.{.{ .off = std.math.maxInt(u64) - 5, .len = 100 }}, .real = 9000 }, // wraps
        .{ .segs = &.{.{ .off = 0, .len = 10 }}, .real = (1 << 40) + 1 }, // over max_sparse_size
    };
    for ([_]Kind{ .gnu, .v00, .v01, .v10 }) |k| for (cases) |c| {
        // The octal fields of the GNU form cannot spell a wrapping offset; skip it there.
        if (k == .gnu and (c.segs[0].off > (1 << 33) or c.real > (1 << 33))) continue;
        const a = try build(testing.allocator, k, c.segs, c.real, 0);
        defer testing.allocator.free(a);
        const w = walk(testing.allocator, a, c.segs);
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), w.err);
    };
}

test "sparse: a map that wants more data than is stored is BadHeader" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const a = try build(testing.allocator, .v01, &.{.{ .off = 0, .len = 600 }}, 9000, 0);
    defer testing.allocator.free(a);
    // "0,600" -> "0,610": the map now needs 610 stored bytes, 600 are stored.
    const at = std.mem.find(u8, a, "0,600").?;
    a[at + 3] = '1';
    a[at + 4] = '0';
    const w = walk(testing.allocator, a, &.{});
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), w.err);
}

test "sparse: malformed pax sparse records and maps are BadHeader" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const bad = [_][]const u8{
        "GNU.sparse.major=2\nGNU.sparse.minor=0\nGNU.sparse.realsize=100",
        "GNU.sparse.size=abc",
        "GNU.sparse.size=100\nGNU.sparse.numbytes=5", // numbytes without offset
        "GNU.sparse.size=100\nGNU.sparse.offset=5", // offset left open
        "GNU.sparse.size=100\nGNU.sparse.map=1,2,3", // odd map
        "GNU.sparse.size=100\nGNU.sparse.map=a,b",
        "GNU.sparse.major=0\nGNU.sparse.minor=1\nGNU.sparse.map=0,1", // no size
    };
    for (bad) |recs| {
        var px: std.ArrayList(u8) = .empty;
        defer px.deinit(testing.allocator);
        var it = std.mem.splitScalar(u8, recs, '\n');
        while (it.next()) |r| {
            const eq = std.mem.findScalar(u8, r, '=').?;
            try record(&px, testing.allocator, r[0..eq], r[eq + 1 ..]);
        }
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(testing.allocator);
        var xh = header("x", 'x', px.items.len);
        stamp(&xh);
        try out.appendSlice(testing.allocator, &xh);
        try out.appendSlice(testing.allocator, px.items);
        try pad(&out, testing.allocator);
        var h = header("f", '0', 1);
        stamp(&h);
        try out.appendSlice(testing.allocator, &h);
        try out.appendSlice(testing.allocator, "z");
        try pad(&out, testing.allocator);
        try out.appendNTimes(testing.allocator, 0, 1024);
        const w = walk(testing.allocator, out.items, &.{});
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), w.err);
    }
}

test "sparse: a 1.0 map longer than the member, or with a run of digits, is BadHeader" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    for ([_][]const u8{ "5\n1\n", "99999999999999999999999\n", "1\n0\n99999999999999999999\n", "x\n", "\n" }) |map| {
        var px: std.ArrayList(u8) = .empty;
        defer px.deinit(testing.allocator);
        try record(&px, testing.allocator, "GNU.sparse.major", "1");
        try record(&px, testing.allocator, "GNU.sparse.minor", "0");
        try record(&px, testing.allocator, "GNU.sparse.realsize", "100");
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(testing.allocator);
        var xh = header("x", 'x', px.items.len);
        stamp(&xh);
        try out.appendSlice(testing.allocator, &xh);
        try out.appendSlice(testing.allocator, px.items);
        try pad(&out, testing.allocator);
        var h = header("f", '0', map.len);
        stamp(&h);
        try out.appendSlice(testing.allocator, &h);
        try out.appendSlice(testing.allocator, map);
        try pad(&out, testing.allocator);
        try out.appendNTimes(testing.allocator, 0, 1024);
        const w = walk(testing.allocator, out.items, &.{});
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), w.err);
    }
}

test "sparse: a cut stream is TruncatedArchive, an endless extension chain is bounded" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const a = try build(testing.allocator, .v10, &good_segs, 9000, 0);
    defer testing.allocator.free(a);
    const w = walk(testing.allocator, a[0 .. 512 + 512 + 512 + 600], &good_segs);
    try testing.expectEqual(@as(?tar.ReadError, error.TruncatedArchive), w.err);
    // GNU 'S' whose every extension block says "another follows".
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    var h = header("s", 'S', 0);
    h[482] = 1;
    _ = std.fmt.bufPrint(h[483..495], "{o:0>11}", .{@as(u32, 100)}) catch unreachable;
    stamp(&h);
    try out.appendSlice(testing.allocator, &h);
    var blk: [512]u8 = @splat(0);
    blk[504] = 1;
    for (0..4000) |_| try out.appendSlice(testing.allocator, &blk);
    const w2 = walk(testing.allocator, out.items, &.{});
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), w2.err);
}

test "sparse: max_sparse_size is configurable" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const a = try build(testing.allocator, .v00, &.{.{ .off = 0, .len = 4 }}, 5000, 0);
    defer testing.allocator.free(a);
    var src: std.Io.Reader = .fixed(a);
    var tr = tar.Reader.init(testing.allocator, &src);
    defer tr.deinit();
    tr.max_sparse_size = 4999;
    try testing.expectError(error.BadHeader, tr.next());
}

// ── fuzz harness ────────────────────────────────────────────────────────────

const edge_keys = [_][]const u8{ "GNU.sparse.major", "GNU.sparse.minor", "GNU.sparse.realsize", "GNU.sparse.size", "GNU.sparse.numblocks", "GNU.sparse.offset", "GNU.sparse.numbytes" };
const edge_values = [_][]const u8{ "0", "1", "2", "9", "10", "18446744073709551615", "18446744073709551614", "18446744073709551616", "1844674407370955162", "1844674407370955161", "9223372036854775808", "1099511627776", "268435457", "4294967296" };

/// Independent statement of "this map is invalid": unordered, overlapping or past `real`.
fn mapInvalid(segs: []const Seg, real: u64) bool {
    var prev_end: u64 = 0;
    for (segs) |s| {
        if (s.off < prev_end) return true;
        prev_end = s.off + s.len;
        if (prev_end > real) return true;
    }
    return false;
}

/// A random sparse member (any generation) followed by "tail". Honest maps must
/// read back exactly and reach "tail"; a map damaged on purpose must be refused
/// (`BadHeader`) where the damage makes it invalid, and a numeric record at or
/// over the u64 edges (major, minor, realsize, numblocks, offset, numbytes) must
/// end in an error or in whatever it says, never a panic or a hang.
pub fn sparseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    if (!tar.sparse_enabled) return;
    const kind: Kind = @fromBackingInt(@intCast(src.valueRangeAtMost(u8, 0, 3)));
    var segs: [24]Seg = undefined;
    const n = src.valueRangeAtMost(u8, 0, if (kind == .gnu) 24 else 6);
    var at: u64 = 0;
    for (0..n) |i| {
        at += src.valueRangeAtMost(u16, 0, 1200);
        const len: u64 = src.valueRangeAtMost(u16, 1, 700);
        segs[i] = .{ .off = at, .len = len };
        at += len;
    }
    var real: u64 = at + src.valueRangeAtMost(u16, 0, 900);
    const damage = src.valueRangeAtMost(u8, 0, 9);
    switch (damage) {
        0 => if (n >= 2) {
            segs[1].off = segs[0].off;
        },
        1 => real = real / 2,
        2 => if (n > 0) {
            segs[n - 1].len += src.valueRangeAtMost(u16, 1, 4000);
        },
        else => {},
    }
    const extra: u64 = if (damage == 3) src.valueRangeAtMost(u16, 1, 600) else 0;
    var extras_buf: [2][2][]const u8 = undefined;
    var extras: [][2][]const u8 = extras_buf[0..0];
    if (damage == 6 or damage == 7) {
        extras_buf[0] = .{ edge_keys[src.index(edge_keys.len)], edge_values[src.index(edge_values.len)] };
        extras = extras_buf[0..1];
        if (damage == 7) {
            extras_buf[1] = .{ edge_keys[src.index(edge_keys.len)], edge_values[src.index(edge_values.len)] };
            extras = extras_buf[0..2];
        }
    }
    const a = buildEx(gpa, kind, segs[0..n], real, extra, extras) catch return;
    defer gpa.free(a);
    var cut: usize = a.len;
    if (damage == 4) cut -= src.index(a.len);
    if (damage == 5) {
        const flips = src.valueRangeAtMost(u8, 1, 4);
        const m = gpa.dupe(u8, a) catch return;
        defer gpa.free(m);
        for (0..flips) |_| m[src.index(m.len)] ^= src.value(u8);
        const w = walk(gpa, m, segs[0..n]);
        if (w.sparse_parsed) fz.mark(.sparse_entry);
        return;
    }
    const w = walk(gpa, a[0..cut], segs[0..n]);
    if (w.sparse_parsed) fz.mark(.sparse_entry);
    if (w.saw_tail) fz.mark(.after_sparse);
    if (damage >= 4) return;
    const invalid = mapInvalid(segs[0..n], real) or extra != 0;
    if (invalid) {
        if (w.err == null or w.err.? != error.BadHeader) {
            std.debug.print("sparse harness: invalid map accepted: kind={t} n={d} damage={d} err={any}\n", .{ kind, n, damage, w.err });
            return error.InvalidSparseMapAccepted;
        }
    } else if (w.err != null or !w.content_ok or !w.saw_tail or w.first_size != real) {
        std.debug.print("sparse harness: honest map failed: kind={t} n={d} damage={d} err={any} content_ok={} tail={}\n", .{ kind, n, damage, w.err, w.content_ok, w.saw_tail });
        return error.HonestSparseMapRejected;
    }
}

// ── fix round 2026-11-04 (independent review) ───────────────────────────────

fn paxBlock(out: *std.ArrayList(u8), gpa: std.mem.Allocator, recs: []const [2][]const u8) !void {
    var px: std.ArrayList(u8) = .empty;
    defer px.deinit(gpa);
    for (recs) |r| try record(&px, gpa, r[0], r[1]);
    var xh = header("././@PaxHeader", 'x', px.items.len);
    stamp(&xh);
    try out.appendSlice(gpa, &xh);
    try out.appendSlice(gpa, px.items);
    try pad(out, gpa);
}

fn plainMember(out: *std.ArrayList(u8), gpa: std.mem.Allocator, name: []const u8, data: []const u8) !void {
    var h = header(name, '0', data.len);
    stamp(&h);
    try out.appendSlice(gpa, &h);
    try out.appendSlice(gpa, data);
    try pad(out, gpa);
}

fn linkMember(out: *std.ArrayList(u8), gpa: std.mem.Allocator, name: []const u8, target: []const u8) !void {
    var h = header(name, '2', 0);
    @memcpy(h[157..][0..target.len], target);
    stamp(&h);
    try out.appendSlice(gpa, &h);
}

fn firstError(bytes: []const u8) ?tar.ReadError {
    var src: std.Io.Reader = .fixed(bytes);
    var tr = tar.Reader.init(testing.allocator, &src);
    defer tr.deinit();
    while (true) {
        const e = tr.next() catch |err| return err;
        if (e == null) return null;
    }
}

test "sparse: numeric pax records at the u64 edges are refused, never an overflow" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const cases = [_][]const [2][]const u8{
        &.{ .{ "GNU.sparse.major", "1844674407370955162" }, .{ "GNU.sparse.minor", "0" }, .{ "GNU.sparse.size", "100" } },
        &.{ .{ "GNU.sparse.major", "18446744073709551615" }, .{ "GNU.sparse.size", "100" } },
        &.{ .{ "GNU.sparse.major", "1" }, .{ "GNU.sparse.minor", "18446744073709551615" }, .{ "GNU.sparse.size", "100" } },
        &.{ .{ "GNU.sparse.major", "0" }, .{ "GNU.sparse.minor", "18446744073709551615" }, .{ "GNU.sparse.size", "100" } },
        &.{ .{ "GNU.sparse.major", "2" }, .{ "GNU.sparse.minor", "0" }, .{ "GNU.sparse.size", "100" } },
        &.{ .{ "GNU.sparse.major", "18446744073709551616" }, .{ "GNU.sparse.size", "100" } },
        &.{.{ "GNU.sparse.size", "18446744073709551616" }},
        &.{ .{ "GNU.sparse.size", "100" }, .{ "GNU.sparse.numblocks", "18446744073709551616" } },
    };
    for (cases) |recs| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(testing.allocator);
        try paxBlock(&out, testing.allocator, recs);
        try plainMember(&out, testing.allocator, "f", "z");
        try out.appendNTimes(testing.allocator, 0, 1024);
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(out.items));
    }
}

test "sparse: the default max_sparse_size is 256 MiB, a larger one is an option" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const a = try build(testing.allocator, .v00, &.{.{ .off = 0, .len = 4 }}, 300 << 20, 0);
    defer testing.allocator.free(a);
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(a));
    var src: std.Io.Reader = .fixed(a);
    var tr = tar.Reader.init(testing.allocator, &src);
    defer tr.deinit();
    tr.max_sparse_size = 512 << 20;
    const e = (try tr.next()).?;
    try testing.expectEqual(@as(u64, 300 << 20), e.size);
}

test "reader: after an error next() and read() keep failing, they never produce another entry" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    // A pax 1.0 member whose map is garbage, then a good member.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try paxBlock(&out, gpa, &.{ .{ "GNU.sparse.major", "1" }, .{ "GNU.sparse.minor", "0" }, .{ "GNU.sparse.realsize", "100" } });
    try plainMember(&out, gpa, "bad", "x\n");
    try plainMember(&out, gpa, "tail", "tail");
    try out.appendNTimes(gpa, 0, 1024);
    var src: std.Io.Reader = .fixed(out.items);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    try testing.expectError(error.BadHeader, tr.next());
    try testing.expectError(error.BadHeader, tr.next());
    var b: [16]u8 = undefined;
    try testing.expectError(error.BadHeader, tr.read(&b));

    // A garbage block between two good members.
    var out2: std.ArrayList(u8) = .empty;
    defer out2.deinit(gpa);
    try plainMember(&out2, gpa, "a", "a");
    try out2.appendNTimes(gpa, 0xFF, 512);
    try plainMember(&out2, gpa, "tail", "tail");
    try out2.appendNTimes(gpa, 0, 1024);
    var src2: std.Io.Reader = .fixed(out2.items);
    var tr2 = tar.Reader.init(gpa, &src2);
    defer tr2.deinit();
    _ = (try tr2.next()).?;
    try testing.expectError(error.BadHeader, tr2.next());
    try testing.expectError(error.BadHeader, tr2.next());
    try testing.expectError(error.BadHeader, tr2.next());
}

test "pax GNU.sparse.name applies to a pax sparse member only (Go: same), in any record order" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    const sparse10 = [_][2][]const u8{ .{ "GNU.sparse.major", "1" }, .{ "GNU.sparse.minor", "0" }, .{ "GNU.sparse.realsize", "100" } };
    var map: [512]u8 = @splat(0);
    map[0] = '0';
    map[1] = '\n';
    const Case = struct { recs: []const [2][]const u8, sparse: bool, want: []const u8 };
    const cases = [_]Case{
        .{ .recs = &.{.{ "GNU.sparse.name", "evil/../x" }}, .sparse = false, .want = "GNUSparseFile.0/f" },
        .{ .recs = &.{ .{ "GNU.sparse.name", "S" }, .{ "path", "P" } }, .sparse = false, .want = "P" },
        .{ .recs = &.{ .{ "path", "P" }, .{ "GNU.sparse.name", "S" } }, .sparse = false, .want = "P" },
        .{ .recs = &(sparse10 ++ [_][2][]const u8{ .{ "GNU.sparse.name", "S" }, .{ "path", "P" } }), .sparse = true, .want = "S" },
        .{ .recs = &([_][2][]const u8{ .{ "path", "P" }, .{ "GNU.sparse.name", "S" } } ++ sparse10), .sparse = true, .want = "S" },
    };
    for (cases) |c| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try paxBlock(&out, gpa, c.recs);
        try plainMember(&out, gpa, "GNUSparseFile.0/f", if (c.sparse) map[0..] else "data");
        try out.appendNTimes(gpa, 0, 1024);
        var src: std.Io.Reader = .fixed(out.items);
        var tr = tar.Reader.init(gpa, &src);
        defer tr.deinit();
        const e = (try tr.next()).?;
        try testing.expectEqualStrings(c.want, e.path);
        // What next() returns is what the check sees.
        var src2: std.Io.Reader = .fixed(out.items);
        if (std.mem.eql(u8, c.want, "GNUSparseFile.0/f") or std.mem.eql(u8, c.want, "P") or std.mem.eql(u8, c.want, "S")) {
            try testing.expectEqual(@as(u64, 1), try tar.checkArchive(gpa, &src2, .{}));
        }
    }
    // An escaping sparse name is what checkArchive refuses.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try paxBlock(&out, gpa, &(sparse10 ++ [_][2][]const u8{.{ "GNU.sparse.name", "../../etc/x" }}));
    try plainMember(&out, gpa, "GNUSparseFile.0/f", map[0..]);
    try out.appendNTimes(gpa, 0, 1024);
    var src: std.Io.Reader = .fixed(out.items);
    try testing.expectError(error.ParentEscape, tar.checkArchive(gpa, &src, .{}));
}

test "reader: a lone zero block ends the archive only before EOF or a second zero block (Go: same)" {
    const gpa = testing.allocator;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    try plainMember(&a, gpa, "a", "a");
    const z: [512]u8 = @splat(0);

    var eof = try a.clone(gpa);
    defer eof.deinit(gpa);
    try eof.appendSlice(gpa, &z);
    try testing.expectEqual(@as(?tar.ReadError, null), firstError(eof.items));

    var zz = try a.clone(gpa);
    defer zz.deinit(gpa);
    try zz.appendSlice(gpa, &(z ++ z));
    try testing.expectEqual(@as(?tar.ReadError, null), firstError(zz.items));

    // zero block, then a member: an error, and the member behind it is never reported.
    var zm = try a.clone(gpa);
    defer zm.deinit(gpa);
    try zm.appendSlice(gpa, &z);
    try plainMember(&zm, gpa, "../../hidden", "x");
    try zm.appendSlice(gpa, &(z ++ z));
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(zm.items));
    var src: std.Io.Reader = .fixed(zm.items);
    try testing.expectError(error.BadHeader, tar.checkArchive(gpa, &src, .{}));

    // zero block, then a partial block: truncated.
    var zp = try a.clone(gpa);
    defer zp.deinit(gpa);
    try zp.appendSlice(gpa, &z);
    try zp.appendNTimes(gpa, 'x', 100);
    try testing.expectEqual(@as(?tar.ReadError, error.TruncatedArchive), firstError(zp.items));
}

test "checkArchive: symlink chains through `..` after a name are refused" {
    const gpa = testing.allocator;
    const Chain = struct { l1: [2][]const u8, l2: [2][]const u8 };
    const chains = [_]Chain{
        .{ .l1 = .{ "x/l1", ".." }, .l2 = .{ "l2", "x/l1/.." } },
        .{ .l1 = .{ "l1", "." }, .l2 = .{ "l2", "x/l1/../.." } },
        .{ .l1 = .{ "a/b/l1", "../.." }, .l2 = .{ "l2", "a/b/l1/../.." } },
        .{ .l1 = .{ "l1", "d" }, .l2 = .{ "l2", "l1/../.." } },
    };
    for (chains) |c| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try linkMember(&out, gpa, c.l1[0], c.l1[1]);
        try linkMember(&out, gpa, c.l2[0], c.l2[1]);
        try out.appendNTimes(gpa, 0, 1024);
        var src: std.Io.Reader = .fixed(out.items);
        try testing.expectError(error.LinkEscape, tar.checkArchive(gpa, &src, .{}));
    }
}

// ── delta audit 2026-11-04: tests for the guards the first mutant set missed ──

/// A source over `data` whose first read at offset `fail_at` fails with
/// `ReadFailed`; every later read works. A reader that is not sticky would go on.
const Flaky = struct {
    data: []const u8,
    pos: usize = 0,
    fail_at: usize,
    failed: bool = false,
    rd: std.Io.Reader,

    fn init(buf: []u8, data: []const u8, fail_at: usize) Flaky {
        return .{ .data = data, .fail_at = fail_at, .rd = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 } };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Flaky = @fieldParentPtr("rd", r);
        if (!self.failed and self.pos == self.fail_at) {
            self.failed = true;
            return error.ReadFailed;
        }
        if (self.pos >= self.data.len) return error.EndOfStream;
        var end = self.data.len;
        if (!self.failed and self.fail_at > self.pos) end = @min(end, self.fail_at);
        const n = try w.write(self.data[self.pos..][0..limit.minInt(end - self.pos)]);
        self.pos += n;
        return n;
    }
};

fn rawMember(out: *std.ArrayList(u8), gpa: std.mem.Allocator, name: []const u8, typeflag: u8, body: []const u8) !void {
    var h = header(name, typeflag, body.len);
    stamp(&h);
    try out.appendSlice(gpa, &h);
    try out.appendSlice(gpa, body);
    try pad(out, gpa);
}

const sparse10_recs = [_][2][]const u8{ .{ "GNU.sparse.major", "1" }, .{ "GNU.sparse.minor", "0" }, .{ "GNU.sparse.realsize", "100" } };

/// A pax 1.0 member with the given `realsize` record, whose map text is `map`
/// (NUL-padded to a block) followed by `data`, and the trailer.
fn v10Raw(gpa: std.mem.Allocator, real: []const u8, map: []const u8, data: []const u8) !std.ArrayList(u8) {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var recs = sparse10_recs;
    recs[2][1] = real;
    try paxBlock(&out, gpa, &recs);
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.appendSlice(gpa, map);
    try pad(&body, gpa);
    try body.appendSlice(gpa, data);
    try rawMember(&out, gpa, "f", '0', body.items);
    try out.appendNTimes(gpa, 0, 1024);
    return out;
}

fn readAll(gpa: std.mem.Allocator, tr: *tar.Reader) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var b: [97]u8 = undefined;
    while (true) {
        const n = try tr.read(&b);
        if (n == 0) break;
        try out.appendSlice(gpa, b[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

fn expectedFor(gpa: std.mem.Allocator, segs: []const Seg, real: u64) ![]u8 {
    const out = try gpa.alloc(u8, @intCast(real));
    @memset(out, 0);
    for (segs) |s| for (0..@intCast(s.len)) |i| {
        out[@intCast(s.off + i)] = pattern(s.off + i);
    };
    return out;
}

/// One sparse member (GNU 'S' with at most four pairs, or pax 1.0), no tail.
fn sparseMember(out: *std.ArrayList(u8), gpa: std.mem.Allocator, kind: Kind, name: []const u8, segs: []const Seg, real: u64) !void {
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);
    for (segs) |s| for (0..@intCast(s.len)) |i| try data.append(gpa, pattern(s.off + i));
    switch (kind) {
        .gnu => {
            var h = header(name, 'S', data.items.len);
            for (segs, 0..) |s, i| {
                _ = std.fmt.bufPrint(h[386 + i * 24 ..][0..12], "{o:0>11}", .{s.off}) catch unreachable;
                _ = std.fmt.bufPrint(h[386 + i * 24 + 12 ..][0..12], "{o:0>11}", .{s.len}) catch unreachable;
            }
            _ = std.fmt.bufPrint(h[483..495], "{o:0>11}", .{real}) catch unreachable;
            stamp(&h);
            try out.appendSlice(gpa, &h);
            try out.appendSlice(gpa, data.items);
            try pad(out, gpa);
        },
        .v10 => {
            var num: [24]u8 = undefined;
            var recs = sparse10_recs;
            recs[2][1] = try std.fmt.bufPrint(&num, "{d}", .{real});
            try paxBlock(out, gpa, &recs);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(gpa);
            try body.print(gpa, "{d}\n", .{segs.len});
            for (segs) |s| try body.print(gpa, "{d}\n{d}\n", .{ s.off, s.len });
            try pad(&body, gpa);
            try body.appendSlice(gpa, data.items);
            try rawMember(out, gpa, name, '0', body.items);
        },
        else => unreachable,
    }
}

test "reader: a failing source is sticky in read() as in next(), and a read error is not a clean end" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    const a = try build(gpa, .v10, &good_segs, 9000, 0);
    defer gpa.free(a);
    const d = a.len - 4608; // start of the stored data: tail header, tail block, trailer follow its padded 2560
    try testing.expectEqual(pattern(100), a[d]);
    var buf: [512]u8 = undefined;
    var fl = Flaky.init(&buf, a, d + 300);
    var tr = tar.Reader.init(gpa, &fl.rd);
    defer tr.deinit();
    _ = (try tr.next()).?;
    var rb: [4093]u8 = undefined;
    try testing.expectEqual(@as(usize, 100), try tr.read(&rb)); // the hole before the first segment
    try testing.expectError(error.ReadFailed, tr.read(&rb));
    try testing.expectError(error.ReadFailed, tr.read(&rb));
    try testing.expectError(error.ReadFailed, tr.next());
}

test "reader: a read error right after a zero block is an error, not the end of the archive" {
    const gpa = testing.allocator;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    try plainMember(&a, gpa, "a", "a");
    try a.appendNTimes(gpa, 0, 1024);
    var buf: [512]u8 = undefined;
    var fl = Flaky.init(&buf, a.items, 1024 + 512);
    var tr = tar.Reader.init(gpa, &fl.rd);
    defer tr.deinit();
    _ = (try tr.next()).?;
    try testing.expectError(error.ReadFailed, tr.next());
    try testing.expectError(error.ReadFailed, tr.next());
}

test "sparse: a stream cut inside a data segment is TruncatedArchive from read() itself" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    const a = try build(gpa, .v10, &good_segs, 9000, 0);
    defer gpa.free(a);
    const d = a.len - 4608;
    var src: std.Io.Reader = .fixed(a[0 .. d + 300]);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    _ = (try tr.next()).?;
    var rb: [4093]u8 = undefined;
    var got: usize = 0;
    const err = while (true) {
        const n = tr.read(&rb) catch |e| break e;
        if (n == 0) break error.CleanEnd;
        got += n;
    };
    try testing.expectEqual(error.TruncatedArchive, err);
}

test "sparse: max_sparse_size is inclusive, in every generation" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    for ([_]Kind{ .gnu, .v00, .v01, .v10 }) |k| for ([_]u64{ 5000, 5001 }) |real| {
        const a = try build(gpa, k, &.{.{ .off = 0, .len = 4 }}, real, 0);
        defer gpa.free(a);
        var src: std.Io.Reader = .fixed(a);
        var tr = tar.Reader.init(gpa, &src);
        defer tr.deinit();
        tr.max_sparse_size = 5000;
        if (real == 5000) {
            try testing.expectEqual(real, (try tr.next()).?.size);
        } else {
            try testing.expectError(error.BadHeader, tr.next());
        }
    };
}

test "sparse: a pax 1.0 member without a realsize is BadHeader, not an empty file" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try paxBlock(&out, gpa, &.{ .{ "GNU.sparse.major", "1" }, .{ "GNU.sparse.minor", "0" } });
    var map: [512]u8 = @splat(0);
    map[0] = '0';
    map[1] = '\n';
    try rawMember(&out, gpa, "f", '0', &map);
    try out.appendNTimes(gpa, 0, 1024);
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(out.items));
}

test "sparse: a GNU 'S' extension block cut short is TruncatedArchive" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var h = header("s", 'S', 0);
    h[482] = 1;
    _ = std.fmt.bufPrint(h[483..495], "{o:0>11}", .{@as(u32, 100)}) catch unreachable;
    stamp(&h);
    try out.appendSlice(gpa, &h);
    try out.appendNTimes(gpa, 0, 100);
    try testing.expectEqual(@as(?tar.ReadError, error.TruncatedArchive), firstError(out.items));
}

test "sparse: an all-NUL offset ends the GNU map, pairs behind it are not read" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var h = header("s", 'S', 10);
    _ = std.fmt.bufPrint(h[386..][0..12], "{o:0>11}", .{@as(u32, 0)}) catch unreachable;
    _ = std.fmt.bufPrint(h[386 + 12 ..][0..12], "{o:0>11}", .{@as(u32, 10)}) catch unreachable;
    // pair 1 stays all NUL; pair 2 behind it claims 5 more bytes that are not stored
    _ = std.fmt.bufPrint(h[386 + 48 ..][0..12], "{o:0>11}", .{@as(u32, 20)}) catch unreachable;
    _ = std.fmt.bufPrint(h[386 + 60 ..][0..12], "{o:0>11}", .{@as(u32, 5)}) catch unreachable;
    _ = std.fmt.bufPrint(h[483..495], "{o:0>11}", .{@as(u32, 100)}) catch unreachable;
    stamp(&h);
    try out.appendSlice(gpa, &h);
    for (0..10) |i| try out.append(gpa, pattern(i));
    try pad(&out, gpa);
    try plainMember(&out, gpa, "tail", "tail");
    try out.appendNTimes(gpa, 0, 1024);
    const w = walk(gpa, out.items, &.{.{ .off = 0, .len = 10 }});
    try testing.expectEqual(@as(?tar.ReadError, null), w.err);
    try testing.expectEqual(@as(u64, 100), w.first_size);
    try testing.expect(w.content_ok and w.saw_tail);
}

test "sparse: the segment cap is 65,536 in every map form that can carry that many" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    for ([_]Kind{ .gnu, .v01, .v10 }) |k| for ([_]usize{ 65536, 65537 }) |n| {
        const segs = try gpa.alloc(Seg, n);
        defer gpa.free(segs);
        for (segs, 0..) |*s, i| s.* = .{ .off = 2 * i, .len = 1 };
        const a = try build(gpa, k, segs, 2 * n, 0);
        defer gpa.free(a);
        const want: ?tar.ReadError = if (n == 65536) null else error.BadHeader;
        try testing.expectEqual(want, firstError(a));
    };
}

test "sparse: unknown GNU.sparse versions are BadHeader even with a valid 1.0 map" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    for ([_][2][]const u8{ .{ "2", "0" }, .{ "1", "1" }, .{ "0", "2" }, .{ "0", "10" }, .{ "10", "0" }, .{ "1", "2" } }) |v| {
        const a = try buildEx(gpa, .v10, &good_segs, 9000, 0, &.{ .{ "GNU.sparse.major", v[0] }, .{ "GNU.sparse.minor", v[1] } });
        defer gpa.free(a);
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(a));
    }
}

test "sparse: an odd entry count in a 0.1 map, a doubled offset and a numbytes alone are BadHeader" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    const a = try buildEx(gpa, .v01, &good_segs, 9000, 0, &.{.{ "GNU.sparse.map", "100,600,1000,1,5000,1500,7" }});
    defer gpa.free(a);
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(a));
    const b = try buildEx(gpa, .v00, &.{}, 20000, 5, &.{ .{ "GNU.sparse.offset", "10000" }, .{ "GNU.sparse.offset", "10001" }, .{ "GNU.sparse.numbytes", "5" } });
    defer gpa.free(b);
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(b));
    const c = try buildEx(gpa, .v00, &.{}, 100, 5, &.{.{ "GNU.sparse.numbytes", "5" }});
    defer gpa.free(c);
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(c));
}

test "sparse: a 1.0 map that cannot fit its own padding in the member is BadHeader" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var recs = sparse10_recs;
    try paxBlock(&out, gpa, &recs);
    try rawMember(&out, gpa, "f", '0', "0\n"); // the member is 2 bytes, the map's padding would need 510 more
    try out.appendNTimes(gpa, 0, 1024);
    try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(out.items));
}

test "sparse: 1.0 map numbers that wrap u64, are padded past 20 digits, empty or not digits are BadHeader" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    const Case = struct { map: []const u8, data: []const u8 };
    const cases = [_]Case{
        .{ .map = "1\n0\n18446744073709551621\n", .data = "AAAAA" }, // the multiply wraps, to 5
        .{ .map = "1\n0\n18446744073709551617\n", .data = "A" }, // the add wraps, to 1
        .{ .map = "1\n0\n0000000000000000000005\n", .data = "AAAAA" }, // 22 digits
        .{ .map = "\n", .data = "" }, // an empty line is not a number
        .{ .map = "1\n0\n:\n", .data = "AAAAAAAAAA" }, // ':' follows '9'
        .{ .map = "4294967297\n", .data = "" }, // a count over u32 (32-bit: the @intCast) and over the cap
    };
    for (cases) |c| {
        var a = try v10Raw(gpa, "100", c.map, c.data);
        defer a.deinit(gpa);
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(a.items));
    }
    // a stream that ends inside the map is truncated, not malformed
    var a = try v10Raw(gpa, "100", "1\n0\n5\n", "AAAAA");
    defer a.deinit(gpa);
    const at = std.mem.find(u8, a.items, "1\n0\n5\n").?;
    try testing.expectEqual(@as(?tar.ReadError, error.TruncatedArchive), firstError(a.items[0 .. at + 3]));
}

test "sparse: a segment that ends exactly at the logical size is valid, in every generation" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    for ([_]Kind{ .gnu, .v00, .v01, .v10 }) |k| {
        const a = try build(testing.allocator, k, &good_segs, 6500, 0);
        defer testing.allocator.free(a);
        const w = walk(testing.allocator, a, &good_segs);
        try testing.expectEqual(@as(?tar.ReadError, null), w.err);
        try testing.expectEqual(@as(u64, 6500), w.first_size);
        try testing.expect(w.content_ok and w.saw_tail);
    }
}

test "sparse: consecutive sparse members, and a plain file after one, read independently" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    const sa = [_]Seg{.{ .off = 10, .len = 20 }};
    const sb = [_]Seg{ .{ .off = 0, .len = 5 }, .{ .off = 50, .len = 10 } };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try sparseMember(&out, gpa, .v10, "A", &sa, 100);
    try sparseMember(&out, gpa, .gnu, "B", &sb, 70);
    try sparseMember(&out, gpa, .v10, "C", &sb, 70);
    try plainMember(&out, gpa, "P", "plain-content");
    try out.appendNTimes(gpa, 0, 1024);
    var src: std.Io.Reader = .fixed(out.items);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    const Want = struct { segs: []const Seg, real: u64 };
    for ([_]Want{ .{ .segs = &sa, .real = 100 }, .{ .segs = &sb, .real = 70 }, .{ .segs = &sb, .real = 70 } }) |w| {
        const e = (try tr.next()).?;
        try testing.expectEqual(w.real, e.size);
        const got = try readAll(gpa, &tr);
        defer gpa.free(got);
        const want = try expectedFor(gpa, w.segs, w.real);
        defer gpa.free(want);
        try testing.expectEqualSlices(u8, want, got);
    }
    const e = (try tr.next()).?;
    try testing.expectEqualStrings("P", e.path);
    const got = try readAll(gpa, &tr);
    defer gpa.free(got);
    try testing.expectEqualStrings("plain-content", got);
    try testing.expect((try tr.next()) == null);
}

test "sparse: GNU.sparse.name with a NUL or over 64 KiB, and numbers with a sign, are BadHeader" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    const long = try gpa.alloc(u8, tar.max_name_len + 1);
    defer gpa.free(long);
    @memset(long, 'a');
    for ([_][]const u8{ "a\x00b", long }) |nm| {
        var recs: [4][2][]const u8 = undefined;
        @memcpy(recs[0..3], &sparse10_recs);
        recs[3] = .{ "GNU.sparse.name", nm };
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try paxBlock(&out, gpa, &recs);
        var map: [512]u8 = @splat(0);
        map[0] = '0';
        map[1] = '\n';
        try rawMember(&out, gpa, "f", '0', &map); // a valid, empty 1.0 map: only the name is wrong
        try out.appendNTimes(gpa, 0, 1024);
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(out.items));
    }
    for ([_][]const u8{ "+100", "-0", " 100", "1_0", "" }) |v| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try paxBlock(&out, gpa, &.{.{ "GNU.sparse.size", v }});
        try plainMember(&out, gpa, "f", "z");
        try out.appendNTimes(gpa, 0, 1024);
        try testing.expectEqual(@as(?tar.ReadError, error.BadHeader), firstError(out.items));
    }
}

test "sparse: GNU.sparse.name never renames a symlink, and sparse records on a non-file change nothing" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try paxBlock(&out, gpa, &(sparse10_recs ++ [_][2][]const u8{.{ "GNU.sparse.name", "S" }}));
    try linkMember(&out, gpa, "L", "target");
    try paxBlock(&out, gpa, &sparse10_recs);
    var body: [600]u8 = @splat('x');
    try rawMember(&out, gpa, "V1", 'V', &body);
    try out.appendNTimes(gpa, 0, 1024);
    var src: std.Io.Reader = .fixed(out.items);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    const l = (try tr.next()).?;
    try testing.expectEqualStrings("L", l.path);
    try testing.expectEqual(tar.Kind.symlink, l.kind);
    const v = (try tr.next()).?;
    try testing.expectEqual(tar.Kind.other, v.kind);
    try testing.expectEqual(@as(u64, 600), v.size);
    const got = try readAll(gpa, &tr);
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, &body, got);
}

fn namedMember(out: *std.ArrayList(u8), gpa: std.mem.Allocator, name: []const u8, uname: []const u8, gname: []const u8, magic: bool) !void {
    var h = header(name, '0', 0);
    @memcpy(h[265..][0..uname.len], uname);
    @memcpy(h[297..][0..gname.len], gname);
    if (!magic) @memset(h[257..265], 0);
    stamp(&h);
    try out.appendSlice(gpa, &h);
}

test "reader: uname/gname come from the pax record for one entry only, and only from a ustar header" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try paxBlock(&out, gpa, &.{ .{ "uname", "alice" }, .{ "gname", "staff" } });
    try namedMember(&out, gpa, "m1", "bob", "wheel", true);
    try namedMember(&out, gpa, "m2", "carol", "wheel2", true);
    try paxBlock(&out, gpa, &.{ .{ "uname", "a\x00b" }, .{ "gname", "x" } }); // a NUL leaves the ustar field
    try namedMember(&out, gpa, "m3", "dave", "g3", true);
    try namedMember(&out, gpa, "m4", "evil", "evilg", false); // no magic: those bytes are not names
    try out.appendNTimes(gpa, 0, 1024);
    var src: std.Io.Reader = .fixed(out.items);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    const want = [_][2][]const u8{ .{ "alice", "staff" }, .{ "carol", "wheel2" }, .{ "dave", "x" }, .{ "", "" } };
    for (want) |w| {
        const e = (try tr.next()).?;
        try testing.expectEqualStrings(w[0], e.uname);
        try testing.expectEqualStrings(w[1], e.gname);
    }
    try testing.expect((try tr.next()) == null);
}

test "checkEntry: a NUL in a symlink target is LinkEscape" {
    try testing.expectError(error.LinkEscape, tar.checkEntry(.{ .path = "l", .kind = .symlink, .link_target = "a\x00b" }, .{}));
}

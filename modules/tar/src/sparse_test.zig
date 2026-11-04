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
    try checkFixture(@embedFile("testdata/read_sparse_gnu_old.tar"));
}
test "sparse: pax 1.0 (map in the data) reads back as the whole file" {
    try checkFixture(@embedFile("testdata/read_sparse_pax_10.tar"));
}
test "sparse: pax 0.1 (GNU.sparse.map) reads back as the whole file" {
    try checkFixture(@embedFile("testdata/read_sparse_pax_01.tar"));
}
test "sparse: pax 0.0 (repeated offset/numbytes) reads back as the whole file" {
    try checkFixture(@embedFile("testdata/read_sparse_pax_00.tar"));
}

test "sparse: unread content is skipped, the next entry is found" {
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

const Walk = struct { first_size: u64 = 0, content_ok: bool = true, saw_tail: bool = false, err: ?tar.ReadError = null };

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

test "sparse: stored bytes the map does not use are skipped, the stream stays in sync" {
    for ([_]Kind{ .gnu, .v00, .v01, .v10 }) |k| {
        const a = try build(testing.allocator, k, &good_segs, 9000, 700);
        defer testing.allocator.free(a);
        const w = walk(testing.allocator, a, &good_segs);
        try testing.expectEqual(@as(?tar.ReadError, null), w.err);
        try testing.expect(w.content_ok and w.saw_tail);
    }
}

test "sparse: a hostile map is BadHeader, never a panic or a misread" {
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
    const a = try build(testing.allocator, .v00, &.{.{ .off = 0, .len = 4 }}, 5000, 0);
    defer testing.allocator.free(a);
    var src: std.Io.Reader = .fixed(a);
    var tr = tar.Reader.init(testing.allocator, &src);
    defer tr.deinit();
    tr.max_sparse_size = 4999;
    try testing.expectError(error.BadHeader, tr.next());
}

// ── fuzz harness ────────────────────────────────────────────────────────────

/// A random sparse member (any generation) followed by "tail". Honest maps must
/// read back exactly and reach "tail"; a map damaged on purpose must end in an
/// error or in whatever it says, never a panic or a hang.
pub fn sparseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const kind: Kind = @fromBackingInt(@intCast(src.valueRangeAtMost(u8, 0, 3)));
    var segs: [24]Seg = undefined;
    const n = src.valueRangeAtMost(u8, 0, if (kind == .gnu) 24 else 6);
    var at: u64 = 0;
    var stored: u64 = 0;
    for (0..n) |i| {
        at += src.valueRangeAtMost(u16, 0, 1200);
        const len: u64 = src.valueRangeAtMost(u16, 1, 700);
        segs[i] = .{ .off = at, .len = len };
        at += len;
        stored += len;
    }
    var real: u64 = at + src.valueRangeAtMost(u16, 0, 900);
    const damage = src.valueRangeAtMost(u8, 0, 9);
    var honest = true;
    switch (damage) {
        0 => if (n >= 2) {
            segs[1].off = segs[0].off;
            honest = false;
        },
        1 => {
            real = real / 2;
            honest = real >= at;
        },
        2 => {
            if (n > 0) segs[n - 1].len += src.valueRangeAtMost(u16, 1, 4000);
            honest = n == 0;
        },
        else => {},
    }
    const extra: u64 = if (damage == 3) src.valueRangeAtMost(u16, 1, 600) else 0;
    const a = build(gpa, kind, segs[0..n], real, extra) catch return;
    defer gpa.free(a);
    var cut: usize = a.len;
    if (damage == 4) cut -= src.index(a.len);
    if (damage == 5) {
        const flips = src.valueRangeAtMost(u8, 1, 4);
        const m = gpa.dupe(u8, a) catch return;
        defer gpa.free(m);
        for (0..flips) |_| m[src.index(m.len)] ^= src.value(u8);
        const w = walk(gpa, m, segs[0..n]);
        if (w.err == null) fz.mark(.sparse_entry);
        return;
    }
    honest = honest and damage != 4;
    const w = walk(gpa, a[0..cut], segs[0..n]);
    if (w.first_size != 0 or w.err == null) fz.mark(.sparse_entry);
    if (w.saw_tail) fz.mark(.after_sparse);
    if (honest and (damage < 3 or damage == 3)) {
        if (w.err != null or !w.content_ok or !w.saw_tail or w.first_size != real) {
            std.debug.print("sparse harness: honest map failed: kind={t} n={d} err={any} content_ok={} tail={}\n", .{ kind, n, w.err, w.content_ok, w.saw_tail });
            return error.HonestSparseMapRejected;
        }
    }
}

test "sparse: the segment cap is exact, 65536 read and 65537 are BadHeader" {
    const gpa = testing.allocator;
    const segs = try gpa.alloc(Seg, tar.max_sparse_segments + 1);
    defer gpa.free(segs);
    for (segs, 0..) |*s, i| s.* = .{ .off = i * 2, .len = 1 };
    for ([_]usize{ tar.max_sparse_segments, tar.max_sparse_segments + 1 }) |n| {
        const a = try build(gpa, .v01, segs[0..n], n * 2, 0);
        defer gpa.free(a);
        var src: std.Io.Reader = .fixed(a);
        var tr = tar.Reader.init(gpa, &src);
        defer tr.deinit();
        if (n > tar.max_sparse_segments) {
            try testing.expectError(error.BadHeader, tr.next());
            continue;
        }
        const e = (try tr.next()).?;
        try testing.expectEqual(@as(u64, n * 2), e.size);
        var buf: [8192]u8 = undefined;
        var total: u64 = 0;
        while (true) {
            const got = try tr.read(&buf);
            if (got == 0) break;
            total += got;
        }
        try testing.expectEqual(@as(u64, n * 2), total);
    }
}

test "sparse: max_sparse_size also bounds the GNU 'S' size field" {
    const a = try build(testing.allocator, .gnu, &.{.{ .off = 0, .len = 4 }}, 5000, 0);
    defer testing.allocator.free(a);
    var src: std.Io.Reader = .fixed(a);
    var tr = tar.Reader.init(testing.allocator, &src);
    defer tr.deinit();
    tr.max_sparse_size = 4999;
    try testing.expectError(error.BadHeader, tr.next());
}

// SPDX-License-Identifier: MIT
//! UTS #46 conformance: Unicode's own IdnaTestV2.txt (18.0.0, comments stripped by
//! `tools/ucd_gen/idna_gen.py`) replayed against `idna.toUnicode` and `idna.toAscii`
//! (non-transitional and transitional) with the strict flags the file was generated with.
//! A line expects either no error and an exact string, or some error (the individual
//! status codes are not compared, as the file's own header allows).

const std = @import("std");
const idna = @import("idna.zig");
const testing = std.testing;

const vectors = @embedFile("testdata/idna_test.txt");

/// `\uXXXX` and `\x{XXXX}` escapes to UTF-8; `""` is the empty string.
fn unescape(a: std.mem.Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    if (std.mem.eql(u8, s, "\"\"")) return out.toOwnedSlice(a);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '\\' and i + 1 < s.len and s[i + 1] == 'u') {
            const cp = try std.fmt.parseInt(u21, s[i + 2 ..][0..4], 16);
            var buf: [4]u8 = undefined;
            const n = try std.unicode.utf8Encode(cp, &buf);
            try out.appendSlice(a, buf[0..n]);
            i += 6;
        } else if (s[i] == '\\' and i + 1 < s.len and s[i + 1] == 'x') {
            const close = std.mem.indexOfScalarPos(u8, s, i, '}').?;
            const cp = try std.fmt.parseInt(u21, s[i + 3 .. close], 16);
            var buf: [4]u8 = undefined;
            const n = try std.unicode.utf8Encode(cp, &buf);
            try out.appendSlice(a, buf[0..n]);
            i = close + 1;
        } else {
            try out.append(a, s[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(a);
}

fn failing(status: []const u8) bool {
    return status.len > 2; // "[]" is none
}

test "IdnaTestV2.txt: toUnicode, toAsciiN and toAsciiT agree with Unicode's expectations" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const o = idna.Options.std3();
    var lines = std.mem.splitScalar(u8, vectors, '\n');
    var n: usize = 0;
    var bad: usize = 0;
    var skipped: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var f: [7][]const u8 = undefined;
        var it = std.mem.splitScalar(u8, line, ';');
        for (&f) |*x| x.* = std.mem.trim(u8, it.next() orelse "", " \t");
        // Lines holding a lone surrogate are ill-formed strings, which the file lets UTF-8 implementations skip.
        const src = unescape(a, f[0]) catch |err| switch (err) {
            error.Utf8CannotEncodeSurrogateHalf => {
                skipped += 1;
                continue;
            },
            else => return err,
        };
        const uni = if (f[1].len == 0) src else unescape(a, f[1]) catch continue;
        const uni_status = f[2];
        const asc_n = if (f[3].len == 0) uni else unescape(a, f[3]) catch continue;
        const n_status = if (f[4].len == 0) uni_status else f[4];
        const asc_t = if (f[5].len == 0) asc_n else unescape(a, f[5]) catch continue;
        const t_status = if (f[6].len == 0) n_status else f[6];
        n += 1;

        var r = try idna.toUnicode(testing.allocator, src, o);
        defer r.deinit(testing.allocator);
        const ok_u = r.valid == !failing(uni_status) and (!r.valid or std.mem.eql(u8, r.text, uni));

        const gn = idna.toAscii(testing.allocator, src, o);
        const ok_n = if (gn) |g| blk: {
            defer testing.allocator.free(g);
            break :blk !failing(n_status) and std.mem.eql(u8, g, asc_n);
        } else |_| failing(n_status);

        var ot = o;
        ot.transitional = true;
        const gt = idna.toAscii(testing.allocator, src, ot);
        const ok_t = if (gt) |g| blk: {
            defer testing.allocator.free(g);
            break :blk !failing(t_status) and std.mem.eql(u8, g, asc_t);
        } else |_| failing(t_status);

        if (!(ok_u and ok_n and ok_t)) {
            bad += 1;
            if (bad <= 10) std.debug.print("line: {s}\n  toUnicode ok={} N ok={} T ok={}\n", .{ line, ok_u, ok_n, ok_t });
        }
    }
    try testing.expect(n > 6000);
    try testing.expect(skipped < 40);
    try testing.expectEqual(@as(usize, 0), bad);
}

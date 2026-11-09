// SPDX-License-Identifier: MIT

//! Conformance replays of frozen vector files (see README DATA and SPEC Anchoring):
//!
//!   testdata/normalization_test.txt  Unicode's NormalizationTest.txt (17.0.0), all five parts
//!   testdata/cpython_vectors.txt     CPython 3.14.4 (unicodedata 16.0.0) on every code point
//!                                    whose UCD data are identical in 16.0.0 and 17.0.0, plus
//!                                    2000 seeded strings (tools/py_oracle.py)
//!   testdata/rust_vectors.txt        Rust 1.93 (Unicode 17.0.0) to_lowercase / to_uppercase on
//!                                    EVERY scalar value and on the same strings (tools/rust_case.rs)

const std = @import("std");
const ut = @import("root.zig");
const ucd = @import("ucd.zig");
const testing = std.testing;

const normalization_test = @embedFile("testdata/normalization_test.txt");
const cpython_vectors = @embedFile("testdata/cpython_vectors.txt");
const rust_vectors = @embedFile("testdata/rust_vectors.txt");

/// `hex hex hex` -> UTF-8 appended to `out`.
fn fromHex(out: *std.ArrayList(u8), a: std.mem.Allocator, field: []const u8) !void {
    var it = std.mem.tokenizeScalar(u8, field, ' ');
    while (it.next()) |tok| {
        const cp = try std.fmt.parseInt(u21, tok, 16);
        var b: [4]u8 = undefined;
        const n = try std.unicode.utf8Encode(cp, &b);
        try out.appendSlice(a, b[0..n]);
    }
}

fn eqStr(label: []const u8, line: []const u8, want: []const u8, got: []const u8) !void {
    if (!std.mem.eql(u8, want, got)) {
        std.debug.print("MISMATCH {s}\n  line: {s}\n  want: {any}\n  got:  {any}\n", .{ label, line, want, got });
        return error.VectorMismatch;
    }
}

// ── NormalizationTest.txt ───────────────────────────────────────────────────

fn norm(a: std.mem.Allocator, s: []const u8, f: ut.Form) ![]u8 {
    return ut.normalize(a, s, f, .{});
}

fn expectNorm(a: std.mem.Allocator, line: []const u8, f: ut.Form, in: []const u8, want: []const u8, label: []const u8) !void {
    const got = try norm(a, in, f);
    defer a.free(got);
    try eqStr(label, line, want, got);
}

test "NormalizationTest.txt: the five invariants of every line (Parts 0-5)" {
    const a = testing.allocator;
    var it = std.mem.splitScalar(u8, normalization_test, '\n');
    var cols: [5]std.ArrayList(u8) = @splat(.empty);
    defer for (&cols) |*c| c.deinit(a);
    var lines: usize = 0;
    var part: usize = 0;
    var seen_single = try a.alloc(bool, 0x110000);
    defer a.free(seen_single);
    @memset(seen_single, false);
    while (it.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        if (line[0] == '@') {
            part = line[5] - '0';
            continue;
        }
        var f = std.mem.splitScalar(u8, line, ';');
        for (&cols) |*c| {
            c.clearRetainingCapacity();
            try fromHex(c, a, f.next() orelse return error.BadLine);
        }
        const c1 = cols[0].items;
        const c2 = cols[1].items;
        const c3 = cols[2].items;
        const c4 = cols[3].items;
        const c5 = cols[4].items;
        for ([_][]const u8{ c1, c2, c3 }) |x| try expectNorm(a, line, .nfc, x, c2, "nfc c2");
        for ([_][]const u8{ c4, c5 }) |x| try expectNorm(a, line, .nfc, x, c4, "nfc c4");
        for ([_][]const u8{ c1, c2, c3 }) |x| try expectNorm(a, line, .nfd, x, c3, "nfd c3");
        for ([_][]const u8{ c4, c5 }) |x| try expectNorm(a, line, .nfd, x, c5, "nfd c5");
        for ([_][]const u8{ c1, c2, c3, c4, c5 }) |x| try expectNorm(a, line, .nfkc, x, c4, "nfkc c4");
        for ([_][]const u8{ c1, c2, c3, c4, c5 }) |x| try expectNorm(a, line, .nfkd, x, c5, "nfkd c5");
        // the writer form and the is-normalized test agree
        try testing.expect(try ut.isNormalized(a, c2, .nfc, .{}));
        try testing.expect(try ut.isNormalized(a, c3, .nfd, .{}));
        try testing.expect(try ut.isNormalized(a, c4, .nfkc, .{}));
        try testing.expect(try ut.isNormalized(a, c5, .nfkd, .{}));
        try testing.expectEqual(std.mem.eql(u8, c1, c2), try ut.isNormalized(a, c1, .nfc, .{}));
        try testing.expectEqual(std.mem.eql(u8, c1, c3), try ut.isNormalized(a, c1, .nfd, .{}));
        try testing.expectEqual(std.mem.eql(u8, c1, c4), try ut.isNormalized(a, c1, .nfkc, .{}));
        try testing.expectEqual(std.mem.eql(u8, c1, c5), try ut.isNormalized(a, c1, .nfkd, .{}));
        if (part == 1) {
            const cp = try std.unicode.utf8Decode(c1);
            seen_single[cp] = true;
        }
        lines += 1;
    }
    try testing.expect(lines > 19000);
    // "all code points not listed in Part 1 are invariant under all four forms" (the file's own
    // statement), except the Hangul syllables, which are algorithmic.
    var cp: u21 = 0;
    var checked: usize = 0;
    while (cp <= 0x10FFFF) : (cp += 1) {
        if ((cp >= 0xD800 and cp < 0xE000) or seen_single[cp] or ucd.hangul.isSyllable(cp)) continue;
        var b: [4]u8 = undefined;
        const n = try std.unicode.utf8Encode(cp, &b);
        for ([_]ut.Form{ .nfc, .nfd, .nfkc, .nfkd }) |form| {
            if (!try ut.isNormalized(a, b[0..n], form, .{})) {
                std.debug.print("U+{X} is not invariant under {t}\n", .{ cp, form });
                return error.NotInvariant;
            }
        }
        checked += 1;
    }
    try testing.expect(checked > 1_000_000);
}

test "Hangul syllables: NFD is the L V T arithmetic and NFC restores every one" {
    const a = testing.allocator;
    var cp: u21 = 0xAC00;
    while (cp < 0xAC00 + 11172) : (cp += 1) {
        const si = cp - 0xAC00;
        var want: [12]u8 = undefined;
        var n: usize = 0;
        n += try std.unicode.utf8Encode(@intCast(0x1100 + si / 588), want[n..]);
        n += try std.unicode.utf8Encode(@intCast(0x1161 + (si % 588) / 28), want[n..]);
        if (si % 28 != 0) n += try std.unicode.utf8Encode(@intCast(0x11A7 + si % 28), want[n..]);
        var b: [4]u8 = undefined;
        const m = try std.unicode.utf8Encode(cp, &b);
        const d = try ut.normalize(a, b[0..m], .nfd, .{});
        defer a.free(d);
        try testing.expectEqualSlices(u8, want[0..n], d);
        const c = try ut.normalize(a, d, .nfc, .{});
        defer a.free(c);
        try testing.expectEqualSlices(u8, b[0..m], c);
    }
}

// ── CPython ─────────────────────────────────────────────────────────────────

const pred_names = [_][]const u8{ "isalpha", "isdecimal", "isdigit", "isnumeric", "isalnum", "isspace", "isupper", "islower", "istitle", "isprintable", "isascii" };

fn predsOfString(s: []const u8) ![11]u8 {
    const o: ut.Options = .{};
    var r: [11]u8 = undefined;
    const v = [11]bool{
        try ut.isAlpha(s, o), try ut.isDecimal(s, o),   try ut.isDigit(s, o), try ut.isNumeric(s, o),
        try ut.isAlnum(s, o), try ut.isSpace(s, o),     try ut.isUpper(s, o), try ut.isLower(s, o),
        try ut.isTitle(s, o), try ut.isPrintable(s, o), ut.isAscii(s),
    };
    for (v, 0..) |x, i| r[i] = if (x) '1' else '0';
    return r;
}

fn isnOfString(a: std.mem.Allocator, s: []const u8) ![4]u8 {
    var r: [4]u8 = undefined;
    for ([_]ut.Form{ .nfc, .nfd, .nfkc, .nfkd }, 0..) |f, i| r[i] = if (try ut.isNormalized(a, s, f, .{})) '1' else '0';
    return r;
}

/// `want` is a field: empty = the string itself, else hex code points.
fn expectField(a: std.mem.Allocator, label: []const u8, line: []const u8, field: []const u8, self: []const u8, got: []const u8) !void {
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(a);
    if (field.len == 0) try want.appendSlice(a, self) else try fromHex(&want, a, field);
    try eqStr(label, line, want.items, got);
}

const MapFn = *const fn (std.mem.Allocator, []const u8, ut.Options) ut.Error![]u8;

fn checkMaps(a: std.mem.Allocator, line: []const u8, s: []const u8, fields: []const []const u8, labels: []const []const u8, fns: []const MapFn) !void {
    for (fields, labels, fns) |f, l, func| {
        const got = try func(a, s, .{});
        defer a.free(got);
        try expectField(a, l, line, f, s, got);
    }
}

fn normFn(comptime f: ut.Form) MapFn {
    return struct {
        fn go(a: std.mem.Allocator, s: []const u8, o: ut.Options) ut.Error![]u8 {
            return ut.normalize(a, s, f, o);
        }
    }.go;
}

test "CPython vectors: every code point of the 16.0.0/17.0.0 intersection and 2000 strings" {
    const a = testing.allocator;
    var it = std.mem.splitScalar(u8, cpython_vectors, '\n');
    var cps: usize = 0;
    var strs: usize = 0;
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(a);
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const nfns = [_]MapFn{ normFn(.nfc), normFn(.nfd), normFn(.nfkc), normFn(.nfkd) };
    const nlabels = [_][]const u8{ "nfc", "nfd", "nfkc", "nfkd" };
    while (it.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields_buf: [18][]const u8 = undefined;
        var nf: usize = 0;
        var f = std.mem.splitScalar(u8, line, ';');
        while (f.next()) |x| : (nf += 1) fields_buf[nf] = x;
        const fields = fields_buf[0..nf];
        if (line[0] == 'S' and line[1] == ';') {
            if (nf != 14) return error.BadLine;
            strs += 1;
            tmp.clearRetainingCapacity();
            try fromHex(&tmp, a, fields[1]);
            const s = tmp.items;
            try eqStr("flags", line, fields[2], &(try predsOfString(s)));
            try eqStr("isnormalized", line, fields[3], &(try isnOfString(a, s)));
            const fns = [_]MapFn{ ut.lower, ut.upper, ut.title, ut.capitalize, ut.swapcase, ut.casefold } ++ nfns;
            const labels = [_][]const u8{ "lower", "upper", "title", "capitalize", "swapcase", "casefold" } ++ nlabels;
            // the string itself is never a stand-in here: every field is spelled out
            for (fields[4..14], labels, fns) |fld, l, func| {
                const got = try func(a, s, .{});
                defer a.free(got);
                var want: std.ArrayList(u8) = .empty;
                defer want.deinit(a);
                try fromHex(&want, a, fld);
                try eqStr(l, line, want.items, got);
            }
            continue;
        }
        if (nf != 17) return error.BadLine;
        var lo: u21 = undefined;
        var hi: u21 = undefined;
        if (std.mem.indexOfScalar(u8, fields[0], '-')) |dash| {
            lo = try std.fmt.parseInt(u21, fields[0][0..dash], 16);
            hi = try std.fmt.parseInt(u21, fields[0][dash + 1 ..], 16);
        } else {
            lo = try std.fmt.parseInt(u21, fields[0], 16);
            hi = lo;
        }
        const want_ccc = try std.fmt.parseInt(u8, fields[2], 10);
        var cp = lo;
        while (cp <= hi) : (cp += 1) {
            cps += 1;
            if (ut.generalCategory(cp) != std.meta.stringToEnum(ut.GeneralCategory, fields[1]).?) {
                std.debug.print("gc of U+{X}: want {s} got {t}\n", .{ cp, fields[1], ut.generalCategory(cp) });
                return error.VectorMismatch;
            }
            if (ucd.ccc(cp) != want_ccc) {
                std.debug.print("ccc of U+{X}: want {d} got {d}\n", .{ cp, want_ccc, ucd.ccc(cp) });
                return error.VectorMismatch;
            }
            var b: [4]u8 = undefined;
            const n = try std.unicode.utf8Encode(cp, &b);
            const s = b[0..n];
            try eqStr("flags", line, fields[3], &(try predsOfString(s)));
            // Mapping and normalization checks: every code point of a single line, a thinned
            // sample of the long identity ranges (Rust's file covers lower/upper of all of them).
            const sample = hi == lo or (cp - lo) < 8 or (cp - lo) % 61 == 0 or cp == hi;
            if (!sample) continue;
            _ = arena_state.reset(.retain_capacity);
            try eqStr("isnormalized", line, fields[4], &(try isnOfString(arena, s)));
            const fns = [_]MapFn{ ut.lower, ut.upper, ut.title, ut.casefold } ++ nfns;
            const labels = [_][]const u8{ "lower", "upper", "title", "casefold" } ++ nlabels;
            try checkMaps(arena, line, s, fields[5..13], &labels, &fns);
            // simple mappings
            const simple = [_]struct { f: u21, i: usize }{
                .{ .f = ut.toLowerCp(cp), .i = 13 },
                .{ .f = ut.toUpperCp(cp), .i = 14 },
                .{ .f = ut.toTitleCp(cp), .i = 15 },
                .{ .f = ut.foldCp(cp), .i = 16 },
            };
            for (simple) |sm| {
                const want: u21 = if (fields[sm.i].len == 0) cp else try std.fmt.parseInt(u21, fields[sm.i], 16);
                if (sm.f != want) {
                    std.debug.print("simple mapping #{d} of U+{X}: want U+{X} got U+{X}\n", .{ sm.i, cp, want, sm.f });
                    return error.VectorMismatch;
                }
            }
        }
    }
    try testing.expect(cps > 1_000_000);
    try testing.expectEqual(@as(usize, 2000), strs);
}

// ── Rust ────────────────────────────────────────────────────────────────────

test "Rust vectors: to_lowercase / to_uppercase of every scalar value and of the strings" {
    const a = testing.allocator;
    var it = std.mem.splitScalar(u8, rust_vectors, '\n');
    var want_lower: std.ArrayList(u8) = .empty;
    defer want_lower.deinit(a);
    var want_upper: std.ArrayList(u8) = .empty;
    defer want_upper.deinit(a);
    var cp: u21 = 0;
    var changed: usize = 0;
    var strs: usize = 0;
    var lbuf: [64]u8 = undefined;
    var ubuf: [64]u8 = undefined;
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    while (it.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.splitScalar(u8, line, ';');
        const kind = f.next().?;
        const key = f.next().?;
        const lo_f = f.next().?;
        const up_f = f.next().?;
        want_lower.clearRetainingCapacity();
        want_upper.clearRetainingCapacity();
        try fromHex(&want_lower, a, lo_f);
        try fromHex(&want_upper, a, up_f);
        if (kind[0] == 'C') {
            const target = try std.fmt.parseInt(u21, key, 16);
            // everything before `target` that Rust did not list maps to itself
            while (cp < target) : (cp += 1) try expectIdentity(cp, &lbuf, &ubuf);
            changed += 1;
            var b: [4]u8 = undefined;
            const n = try std.unicode.utf8Encode(target, &b);
            try expectCase(line, b[0..n], want_lower.items, want_upper.items, &lbuf, &ubuf);
            cp = target + 1;
        } else {
            while (cp <= 0x10FFFF) : (cp += 1) try expectIdentity(cp, &lbuf, &ubuf);
            strs += 1;
            src.clearRetainingCapacity();
            try fromHex(&src, a, key);
            const l = try ut.lower(a, src.items, .{});
            defer a.free(l);
            const u = try ut.upper(a, src.items, .{});
            defer a.free(u);
            try eqStr("lower", line, want_lower.items, l);
            try eqStr("upper", line, want_upper.items, u);
        }
    }
    try testing.expect(changed > 3000 and strs == 2000);
}

fn expectIdentity(cp: u21, lbuf: []u8, ubuf: []u8) !void {
    if (cp >= 0xD800 and cp < 0xE000) return;
    var b: [4]u8 = undefined;
    const n = try std.unicode.utf8Encode(cp, &b);
    try expectCase("identity", b[0..n], b[0..n], b[0..n], lbuf, ubuf);
}

fn expectCase(label: []const u8, s: []const u8, lower: []const u8, upper: []const u8, lbuf: []u8, ubuf: []u8) !void {
    var lw = std.Io.Writer.fixed(lbuf);
    try ut.lowerTo(&lw, s, .{});
    var uw = std.Io.Writer.fixed(ubuf);
    try ut.upperTo(&uw, s, .{});
    if (!std.mem.eql(u8, lw.buffered(), lower) or !std.mem.eql(u8, uw.buffered(), upper)) {
        std.debug.print("MISMATCH {s} for {any}: lower want {any} got {any}; upper want {any} got {any}\n", .{ label, s, lower, lw.buffered(), upper, uw.buffered() });
        return error.VectorMismatch;
    }
}

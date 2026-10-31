// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over json5's two existing `testing.fuzz`
//! harnesses (`preprocess`, `preprocessAnnotated`; added 2026-10-09). The
//! bodies live here, generic over their source of choices
//! (`fn(comptime S, *S, gpa)`); `root.zig`'s `testing.fuzz` tests feed them
//! through the cursor adapter below, the driver feeds them a PRNG.
//!
//! Driver: `JSON5_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const json5 = @import("root.zig");

pub const Label = enum { accepted, changed, compared, direct, declined_valid };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    /// What `Smith.slice` would have returned for this script: up to
    /// `buf.len` of the remaining script bytes, and their count.
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

pub fn jsonParses(alloc: std.mem.Allocator, text: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, text, .{
        .duplicate_field_behavior = .use_last,
    }) catch return false;
    parsed.deinit();
    return true;
}

/// `preprocess` must never panic or leak on arbitrary bytes.
pub fn preprocessHarness(comptime S: type, src: *S, alloc: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = src.slice(&buf);
    const out = json5.preprocess(alloc, buf[0..len]) catch return; // `refused` is not reachable from random bytes (400 seeds: 0 hits)
    defer alloc.free(out);
    mark(.accepted);
    if (!std.mem.eql(u8, out, buf[0..len])) mark(.changed);
}

/// `preprocessAnnotated` never panics, and agrees with `preprocess` on whether
/// the result parses as JSON (turning diagnostics on must not change that).
pub fn annotatedHarness(comptime S: type, src: *S, alloc: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = src.slice(&buf);
    const input = buf[0..len];
    const r = json5.preprocessAnnotated(alloc, input) catch return;
    defer alloc.free(r.out);
    const plain = json5.preprocess(alloc, input) catch return;
    defer alloc.free(plain);
    const ann_ok = jsonParses(alloc, r.out);
    const plain_ok = jsonParses(alloc, plain);
    // (`ann_ok` itself is not a label: random bytes are almost never JSON.)
    mark(.compared);
    if (ann_ok != plain_ok) {
        std.debug.print(
            "\nentry points disagree on {f}\n  preprocess ({}): {f}\n  annotated  ({}): {f}\n",
            .{
                std.ascii.hexEscape(input, .lower),
                plain_ok,
                std.ascii.hexEscape(plain, .lower),
                ann_ok,
                std.ascii.hexEscape(r.out, .lower),
            },
        );
        return error.EntryPointsDisagree;
    }
}

/// Choices for `genDocument`, read from a byte script; past its end every
/// choice is 0 (the shortest production), so every script ends.
const Choices = struct {
    bytes: []const u8,
    at: usize = 0,

    fn next(c: *Choices, n: usize) usize {
        if (c.at >= c.bytes.len) return 0;
        defer c.at += 1;
        return c.bytes[c.at] % n;
    }
};

const ws_pieces = [_][]const u8{
    " ",         "\n",      "\t",   "\r\n", "\x0b", "\x0c", "\xc2\xa0", "\xef\xbb\xbf", "\xe2\x80\xa8",
    "// note\n", "/* c */", "//\r", "/**/", "",
};
const key_pieces = [_][]const u8{
    "a",        "b",       "$x_1", "\\u0061", "\xc3\xa9", "\"a\"",  "'b'", "\"\\u0062\"",
    "a\\u0062", "\\u+041", "1a",   "a b",     "\"\"",     "'k\"q'", "_",   "\\uD800",
};
const string_pieces = [_][]const u8{
    "x",        "\"",           "'",     "\\n",          "\\t",            "\\v",            "\\0",     "\\01",
    "\\1",      "\\x41",        "\\xe9", "\\xG1",        "\\u00e9",        "\\ud83d\\ude00", "\\uD800", "\\uDC00x",
    "\\q",      "\\\xc3\xa9",   "\\\n",  "\\\r\n",       "\\\xe2\x80\xa8", "\t",             "\x01",    "\x7f",
    "\xc3\xa9", "\xe2\x80\xa8", "\xff",  "\xed\xa0\x80", "\\/",            "\\\\",           "\\u12",   "\n",
};
const number_pieces = [_][]const u8{
    "0",                    "123",   "-7",       "+1",    "1.5", ".5", "5.",    "-.5e3",
    "1e5",                  "1E-3",  "0x1F",     "-0xff", "0X0", "01", "1.2.3", "9223372036854775808",
    "-9223372036854775809", "1e400", "Infinity", "-NaN",  "-",   "0x", "5.e2",  "1e",
};
const literal_pieces = [_][]const u8{ "true", "false", "null", "tru", "nulll", "foo" };

fn genWs(c: *Choices, out: *std.ArrayList(u8), gpa: std.mem.Allocator) !void {
    for (0..c.next(3)) |_| try out.appendSlice(gpa, ws_pieces[c.next(ws_pieces.len)]);
}

fn genValue(c: *Choices, out: *std.ArrayList(u8), gpa: std.mem.Allocator, depth: usize) !void {
    try genWs(c, out, gpa);
    switch (c.next(if (depth < 4) 7 else 4)) {
        0 => try out.appendSlice(gpa, literal_pieces[c.next(literal_pieces.len)]),
        1 => try out.appendSlice(gpa, number_pieces[c.next(number_pieces.len)]),
        2, 3 => {
            const q: u8 = if (c.next(2) == 0) '"' else '\'';
            try out.append(gpa, q);
            for (0..c.next(5)) |_| try out.appendSlice(gpa, string_pieces[c.next(string_pieces.len)]);
            if (c.next(16) != 0) try out.append(gpa, q);
        },
        4, 5 => {
            const obj = c.next(2) == 0;
            try out.append(gpa, if (obj) '{' else '[');
            const n = c.next(4);
            for (0..n) |k| {
                try genWs(c, out, gpa);
                if (obj) {
                    try out.appendSlice(gpa, key_pieces[c.next(key_pieces.len)]);
                    try genWs(c, out, gpa);
                    if (c.next(16) != 0) try out.append(gpa, ':');
                }
                try genValue(c, out, gpa, depth + 1);
                try genWs(c, out, gpa);
                if (k + 1 < n or c.next(3) == 0) try out.append(gpa, ',');
            }
            try genWs(c, out, gpa);
            if (c.next(16) != 0) try out.append(gpa, if (obj) '}' else ']');
        },
        else => try out.appendSlice(gpa, number_pieces[c.next(4)]),
    }
    try genWs(c, out, gpa);
}

/// A JSON5-shaped document from the script, then up to two byte mutations.
fn genDocument(c: *Choices, out: *std.ArrayList(u8), gpa: std.mem.Allocator) !void {
    try genValue(c, out, gpa, 0);
    for (0..c.next(4) / 2) |_| {
        if (out.items.len == 0) break;
        const at = c.next(256) * out.items.len / 256;
        switch (c.next(3)) {
            0 => _ = out.orderedRemove(at),
            1 => try out.insert(gpa, at, @intCast(c.next(256))),
            else => try out.insert(gpa, at, out.items[at]),
        }
    }
}

pub fn valueEql(a: std.json.Value, b: std.json.Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => |x| x == b.bool,
        .integer => |x| x == b.integer,
        .float => |x| @as(u64, @bitCast(x)) == @as(u64, @bitCast(b.float)),
        .number_string => |x| std.mem.eql(u8, x, b.number_string),
        .string => |x| std.mem.eql(u8, x, b.string),
        .array => |x| x.items.len == b.array.items.len and for (x.items, b.array.items) |p, q| {
            if (!valueEql(p, q)) break false;
        } else true,
        .object => |x| x.count() == b.object.count() and for (x.keys(), x.values(), b.object.keys(), b.object.values()) |ka, va, kb, vb| {
            if (!std.mem.eql(u8, ka, kb) or !valueEql(va, vb)) break false;
        } else true,
    };
}

/// `parseFromSlice(std.json.Value, ...)` gives the same value, or the same
/// error, whether or not the single-pass reader takes the document: a
/// `diagnostic` always sends it down the two-stage path, which is the oracle.
pub fn checkDirect(gpa: std.mem.Allocator, text: []const u8, opts: json5.ParseOptions) !void {
    const before = json5.directTaken();
    const got = json5.parseFromSlice(std.json.Value, gpa, text, opts);
    const took = json5.directTaken() != before;
    defer if (got) |p| p.deinit() else |_| {};
    var d: json5.Diagnostic = .{};
    var slow_opts = opts;
    slow_opts.diagnostic = &d;
    const want = json5.parseFromSlice(std.json.Value, gpa, text, slow_opts);
    defer if (want) |p| p.deinit() else |_| {};
    const same = if (got) |g| (if (want) |w| valueEql(g.value, w.value) else |_| false) else |ge| (if (want) |_| false else |we| ge == we);
    if (took) mark(.direct) else if (want) |_| mark(.declined_valid) else |_| {}
    if (!same) {
        std.debug.print("\nsingle-pass reader disagrees (took it: {}) on {f}\n  options: {any}\n", .{ took, std.ascii.hexEscape(text, .lower), opts });
        return error.DirectReaderDisagrees;
    }
}

/// The single-pass `std.json.Value` reader agrees with the two-stage path on
/// JSON5-shaped documents, mutated, under varied options.
pub fn directHarness(comptime S: type, src: *S, alloc: std.mem.Allocator) anyerror!void {
    var script: [256]u8 = undefined;
    const len: usize = src.slice(&script);
    var c: Choices = .{ .bytes = script[0..len] };
    var opts: json5.ParseOptions = .{};
    opts.json.duplicate_field_behavior = switch (c.next(3)) {
        0 => .@"error",
        1 => .use_first,
        else => .use_last,
    };
    opts.json.parse_numbers = c.next(4) != 0;
    if (c.next(8) == 0) opts.json.max_value_len = c.next(8);
    if (c.next(4) == 0) opts.json5.non_finite = .quoted;
    var doc: std.ArrayList(u8) = .empty;
    defer doc.deinit(alloc);
    try genDocument(&c, &doc, alloc);
    try checkDirect(alloc, doc.items, opts);
}

test "fuzz driver: JSON5_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ preprocessHarness, .{ .prefix = "JSON5_FUZZ", .name = "json5-preprocess" } },
        .{ annotatedHarness, .{ .prefix = "JSON5_FUZZ", .name = "json5-annotated" } },
        .{ directHarness, .{ .prefix = "JSON5_FUZZ", .name = "json5-direct" } },
    });
}

test "single-pass Value reader: every corpus document agrees with the two-stage path" {
    const ref = @import("ref_oracle_vectors.zig");
    const fixtures = @import("json5_tests_vectors.zig");
    reach = @splat(0);
    for (ref.cases) |case| try checkDirect(testing.allocator, case.src, .{});
    for (fixtures.vectors) |v| try checkDirect(testing.allocator, v.content, .{});
    for (fixtures.vectors) |v| try checkDirect(testing.allocator, v.content, .{ .json5 = .{ .non_finite = .quoted } });
    // 1153 taken on 2026-10-24 (of 2660 oracle cases + 3 x 112 fixtures, many
    // of them must-reject); the valid ones it declines are key recovery,
    // `Infinity`/`NaN` and surrogate escapes, all left to the two-stage path.
    try testing.expect(reach[@backingInt(Label.direct)] > ref.cases.len / 3);
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        preprocessHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("json5 preprocess seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        annotatedHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("json5 annotated seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        directHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("json5 direct seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

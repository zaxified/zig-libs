// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over the JSONPath parser and evaluator. The harness
//! draws one script of bytes, generic over its source (`testing.fuzz` feeds it
//! through `root.zig`'s test, the driver through a PRNG), and reads every choice
//! from it: a small document, then a path from a grammar, sometimes damaged by a
//! byte, sometimes raw script bytes.
//!
//! Driver: `JSONSHAPE_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).
//!
//! What must hold, beyond no panic, no leak and no hang: the three query entry
//! points agree; every Normalized Path compiles again and selects exactly its own
//! node; a smaller work budget changes the outcome only into `WorkLimit`;
//! `shape`'s lenient parser agrees with `compile` on a path both accept; and two
//! independent models: a slice against RFC 9535's definition by membership (not
//! the §2.3.4.2.2 loop the module uses), and a pattern without metacharacters
//! under `match`/`search` against equality/containment.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const js = @import("root.zig");

const J = std.json.Value;

pub const Label = enum {
    raw_path,
    compile_refused,
    compile_ok,
    query_limit,
    nodes_found,
    normalized_round_trip,
    work_limit,
    shape_agrees,
    slice_model,
    regex_model,
};
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// The budget of most runs: an ordinary query over a document of this size stays
/// inside it, and so do a few compiles of a pattern read from the document.
const fuzz_work: usize = 200_000;
/// The budget of the rest: an ordinary query may run out of it.
const fuzz_work_tight: usize = 24;

/// The bytes of one draw, read as small choices; zeros past the end.
pub const Choices = struct {
    bytes: []const u8,
    at: usize = 0,
    fn pick(c: *Choices, n: usize) usize {
        if (c.at >= c.bytes.len) return 0;
        c.at += 1;
        return c.bytes[c.at - 1] % n;
    }
    fn one(c: *Choices, comptime list: []const []const u8) []const u8 {
        return list[c.pick(list.len)];
    }
};

/// `testing.fuzz`'s source: what `Smith.slice` would give for one saved script.
pub const ScriptSource = struct {
    bytes: []const u8,
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const n = @min(buf.len, self.bytes.len);
        @memcpy(buf[0..n], self.bytes[0..n]);
        return @intCast(n);
    }
};

pub fn pathHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = src.slice(&buf);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var c: Choices = .{ .bytes = buf[0..len] };

    var text: std.ArrayList(u8) = .empty;
    try genValue(&c, a, &text, 0);
    const root = try js.parseDocument(a, text.items, .{ .duplicate_keys = .last });

    switch (c.pick(8)) {
        0 => try sliceModel(&c, a),
        1 => try regexModel(&c, a),
        else => {},
    }

    var path: std.ArrayList(u8) = .empty;
    try path.append(a, '$');
    if (c.pick(5) == 0) {
        // Raw bytes: the parsers see text no grammar made.
        mark(.raw_path);
        path.clearRetainingCapacity();
        try path.appendSlice(a, c.bytes[@min(c.at, c.bytes.len)..]);
        c.at = c.bytes.len;
    } else {
        for (0..c.pick(5)) |_| try genSegment(&c, a, &path, 0);
        if (c.pick(3) == 0 and path.items.len > 1) {
            // One damaged byte.
            const at = c.pick(path.items.len);
            path.items[at] = "$@.[]()?*,:'\"!=<>&|-0a \\"[c.pick(24)];
        }
    }
    const work = if (c.pick(4) == 1) fuzz_work_tight else fuzz_work;
    try checkPath(a, root, text.items, path.items, work);
}

fn checkPath(a: std.mem.Allocator, root: J, doc: []const u8, text: []const u8, work: usize) !void {
    // Whatever the text: no panic, and only a declared error.
    const lenient = js.shape(a, doc, .{
        .path = text,
        .columns = &.{.{ .name = "v", .type = .text }},
        .max_work = work,
        .duplicate_keys = .last,
    });
    const path = js.compile(a, text, null) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.InvalidPath => {
            mark(.compile_refused);
            return;
        },
    };
    mark(.compile_ok);

    const opts: js.QueryOptions = .{ .max_work = work };
    const nodes = js.query(a, root, path, opts) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.WorkLimit, error.DepthLimit, error.TooManyMatches, error.BadJson => {
            mark(.query_limit);
            return;
        },
    };
    // `normalized` is charged too, so only a limit may separate the two.
    const located = js.queryLocated(a, root, path, opts) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return,
    };
    if (located.len != nodes.len) return error.LocatedDisagrees;
    for (located, nodes) |l, n| if (!same(l.value, n)) return error.LocatedDisagrees;

    const first = try js.queryFirst(a, root, path, opts);
    if ((first != null) != (nodes.len > 0)) return error.FirstDisagrees;
    if (first) |f| if (!same(f, nodes[0])) return error.FirstDisagrees;

    if (nodes.len > 0) mark(.nodes_found);

    // A Normalized Path is a singular query for exactly that node.
    for (located[0..@min(located.len, 16)]) |l| {
        const again = js.compile(a, l.path, null) catch return error.NormalizedPathRefused;
        const back = try js.query(a, root, again, opts);
        if (back.len != 1 or !same(back[0], l.value)) return error.NormalizedPathElsewhere;
        mark(.normalized_round_trip);
    }

    // Less budget: the same answer, or a refusal, never another answer.
    if (js.query(a, root, path, .{ .max_work = 64 })) |small| {
        if (small.len != nodes.len) return error.BudgetChangedAnswer;
    } else |e| switch (e) {
        error.OutOfMemory => return e,
        error.WorkLimit => mark(.work_limit),
        else => return error.BudgetChangedError,
    }

    // `shape` reads a path both parsers accept the same way. Blanks are where
    // the two grammars differ on purpose (a top-level name may hold them there).
    if (std.mem.indexOfAny(u8, text, " \t\r\n-") == null) {
        const d = lenient catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => return,
        };
        var rows: usize = 0;
        for (nodes) |n| rows += if (n == .array) n.array.items.len else 1;
        if (d.len != rows) return error.ShapeDisagrees;
        mark(.shape_agrees);
    }
}

/// The same node of one tree: containers by identity, scalars by value.
fn same(x: J, y: J) bool {
    return switch (x) {
        .null => y == .null,
        .bool => |v| y == .bool and y.bool == v,
        .integer => |v| y == .integer and y.integer == v,
        .float => |v| y == .float and y.float == v,
        .string, .number_string => |v| (y == .string or y == .number_string) and std.mem.eql(u8, v, if (y == .string) y.string else y.number_string),
        .array => |v| y == .array and v.items.ptr == y.array.items.ptr and v.items.len == y.array.items.len,
        .object => |v| y == .object and v.count() == y.object.count() and v.keys().ptr == y.object.keys().ptr,
    };
}

// ── generators ──────────────────────────────────────────────────────────────

fn genValue(c: *Choices, a: std.mem.Allocator, out: *std.ArrayList(u8), depth: u32) !void {
    const kinds: usize = if (depth >= 4) 6 else 9;
    switch (c.pick(kinds)) {
        0 => try out.appendSlice(a, c.one(&.{ "0", "1", "-1", "2", "7", "1.5", "1e3", "9007199254740993" })),
        1 => try out.appendSlice(a, c.one(&.{ "\"\"", "\"a\"", "\"ab\"", "\"é∂\"", "\"a\\nb\"", "\"[ab]\"", "\"a.*\"" })),
        2 => try out.appendSlice(a, "null"),
        3 => try out.appendSlice(a, "true"),
        4 => try out.appendSlice(a, "false"),
        5 => try out.appendSlice(a, c.one(&.{ "\"(\"", "\"\\\\d\"", "\"a{1000}\"", "\"^a$\"" })),
        6 => {
            try out.append(a, '[');
            for (0..c.pick(5)) |i| {
                if (i > 0) try out.append(a, ',');
                try genValue(c, a, out, depth + 1);
            }
            try out.append(a, ']');
        },
        else => {
            try out.append(a, '{');
            for (0..c.pick(5)) |i| {
                if (i > 0) try out.append(a, ',');
                try out.appendSlice(a, c.one(&.{ "\"a\"", "\"b\"", "\"p\"", "\"c d\"", "\"it's\"", "\"\\u0001\"", "\"\\\\\"", "\"é\"" }));
                try out.append(a, ':');
                try genValue(c, a, out, depth + 1);
            }
            try out.append(a, '}');
        },
    }
}

fn genSegment(c: *Choices, a: std.mem.Allocator, out: *std.ArrayList(u8), depth: u32) std.mem.Allocator.Error!void {
    switch (c.pick(12)) {
        0 => try out.appendSlice(a, c.one(&.{ ".a", ".b", ".p", ".é", "._x1" })),
        1 => try out.appendSlice(a, c.one(&.{ "['a']", "[\"b\"]", "['c d']", "['it\\'s']", "['\\u0001']", "['\\\\']" })),
        2 => try out.appendSlice(a, c.one(&.{ "..a", "..b", "..*", "..[0]", "..['a',0]" })),
        3 => try out.appendSlice(a, c.one(&.{ ".*", "[*]", "[*,*]" })),
        4 => try out.print(a, "[{d}]", .{@as(i32, @intCast(c.pick(9))) - 4}),
        5 => try out.appendSlice(a, c.one(&.{ "[1:3]", "[::-1]", "[::2]", "[-2:]", "[:2]", "[3:0:-1]", "[0:5:0]", "[ 1 : 2 ]" })),
        6 => try out.appendSlice(a, c.one(&.{ "[0,'a']", "[1,0]", "['a','b']", "[0:1,'a',*]" })),
        7 => try out.appendSlice(a, c.one(&.{ " .a", "\t[0]", "\n.*" })),
        8 => {
            try out.append(a, '[');
            try out.append(a, '?');
            try genExpr(c, a, out, depth);
            try out.append(a, ']');
        },
        9 => {
            try out.appendSlice(a, "..[?");
            try genExpr(c, a, out, depth);
            try out.append(a, ']');
        },
        else => try out.appendSlice(a, ".a"),
    }
}

fn genOperand(c: *Choices, a: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    try out.appendSlice(a, c.one(&.{ "@", "@.a", "@.b", "@[0]", "$.a", "$[0]", "1", "-1", "1.5", "'a'", "\"ab\"", "true", "null", "length(@)", "length(@.a)", "count(@.*)", "count($..a)", "value(@..a)", "value(@.b)" }));
}

fn genExpr(c: *Choices, a: std.mem.Allocator, out: *std.ArrayList(u8), depth: u32) std.mem.Allocator.Error!void {
    if (depth >= 3) return out.appendSlice(a, "@.a");
    switch (c.pick(9)) {
        0 => try out.appendSlice(a, c.one(&.{ "@.a", "@", "$.b", "@[0]", "@.*", "@..a" })),
        1, 2 => {
            try genOperand(c, a, out);
            try out.appendSlice(a, c.one(&.{ "==", "!=", "<", "<=", ">", ">=", " == " }));
            try genOperand(c, a, out);
        },
        3 => {
            try out.append(a, '!');
            try out.append(a, '(');
            try genExpr(c, a, out, depth + 1);
            try out.append(a, ')');
        },
        4 => {
            try genExpr(c, a, out, depth + 1);
            try out.appendSlice(a, c.one(&.{ "&&", "||", " && " }));
            try genExpr(c, a, out, depth + 1);
        },
        5 => {
            try out.append(a, '(');
            try genExpr(c, a, out, depth + 1);
            try out.append(a, ')');
        },
        6 => {
            // A filter query holding a filter of its own.
            try out.append(a, '@');
            try genSegment(c, a, out, depth + 1);
        },
        else => {
            try out.appendSlice(a, c.one(&.{ "match(", "search(", "!match(", "!search(" }));
            try genOperand(c, a, out);
            try out.append(a, ',');
            try out.appendSlice(a, c.one(&.{ "'a.*'", "'[ab]'", "'^a$'", "'(a|b)+'", "'\\\\d'", "'(?i)a'", "'('", "'a{2,1}'", "'\\\\p{Lu}'", "@.p", "$.p", "@", "1" }));
            try out.append(a, ')');
        },
    }
}

// ── models ──────────────────────────────────────────────────────────────────

/// Which indices `[start:end:step]` selects, by RFC 9535's membership wording,
/// then ordered by the step: not by the loop `selectSlice` runs.
fn sliceModel(c: *Choices, a: std.mem.Allocator) !void {
    const len: i64 = @intCast(c.pick(9));
    const start: ?i64 = if (c.pick(4) == 0) null else @as(i64, @intCast(c.pick(21))) - 10;
    const end: ?i64 = if (c.pick(4) == 0) null else @as(i64, @intCast(c.pick(21))) - 10;
    const step: i64 = @as(i64, @intCast(c.pick(9))) - 4;

    var doc: std.ArrayList(u8) = .empty;
    try doc.append(a, '[');
    for (0..@intCast(len)) |i| {
        if (i > 0) try doc.append(a, ',');
        try doc.print(a, "{d}", .{i});
    }
    try doc.append(a, ']');
    const root = try js.parseDocument(a, doc.items, .{});

    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(a, "$[");
    if (start) |s| try text.print(a, "{d}", .{s});
    try text.append(a, ':');
    if (end) |e| try text.print(a, "{d}", .{e});
    try text.print(a, ":{d}]", .{step});
    const got = try js.query(a, root, try js.compile(a, text.items, null), .{});

    var want: std.ArrayList(i64) = .empty;
    if (step != 0) {
        const norm = struct {
            fn f(v: i64, l: i64) i64 {
                return if (v >= 0) v else l + v;
            }
            fn clamp(v: i64, lo: i64, hi: i64) i64 {
                return @max(lo, @min(v, hi));
            }
        };
        if (step > 0) {
            const lower = norm.clamp(norm.f(start orelse 0, len), 0, len);
            const upper = norm.clamp(norm.f(end orelse len, len), 0, len);
            var i: i64 = 0;
            while (i < len) : (i += 1) {
                if (lower <= i and i < upper and @mod(i - lower, step) == 0) try want.append(a, i);
            }
        } else {
            const upper = norm.clamp(norm.f(start orelse len - 1, len), -1, len - 1);
            const lower = norm.clamp(if (end) |e| norm.f(e, len) else -1, -1, len - 1);
            var i: i64 = len - 1;
            while (i >= 0) : (i -= 1) {
                if (lower < i and i <= upper and @mod(upper - i, -step) == 0) try want.append(a, i);
            }
        }
    }
    if (got.len != want.items.len) return error.SliceModelDisagrees;
    for (got, want.items) |g, w| if (g.integer != w) return error.SliceModelDisagrees;
    mark(.slice_model);
}

/// A pattern of plain letters: `match` is equality, `search` containment.
fn regexModel(c: *Choices, a: std.mem.Allocator) !void {
    var pattern: [3]u8 = undefined;
    const plen = c.pick(4);
    for (pattern[0..plen]) |*b| b.* = "abc"[c.pick(3)];
    const pat = pattern[0..plen];

    var subjects: [6][]const u8 = undefined;
    var doc: std.ArrayList(u8) = .empty;
    try doc.append(a, '[');
    for (&subjects, 0..) |*s, i| {
        const b = try a.alloc(u8, c.pick(5));
        for (b) |*x| x.* = "abc"[c.pick(3)];
        s.* = b;
        if (i > 0) try doc.append(a, ',');
        try doc.print(a, "\"{s}\"", .{b});
    }
    try doc.append(a, ']');
    const root = try js.parseDocument(a, doc.items, .{});

    const full = try js.query(a, root, try js.compile(a, try a.print("$[?match(@,'{s}')]", .{pat}), null), .{});
    const part = try js.query(a, root, try js.compile(a, try a.print("$[?search(@,'{s}')]", .{pat}), null), .{});
    var want_full: usize = 0;
    var want_part: usize = 0;
    for (subjects) |s| {
        if (std.mem.eql(u8, s, pat)) want_full += 1;
        if (std.mem.find(u8, s, pat) != null) want_part += 1;
    }
    if (full.len != want_full or part.len != want_part) return error.RegexModelDisagrees;
    mark(.regex_model);
}

test "fuzz driver: JSONSHAPE_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ pathHarness, .{ .prefix = "JSONSHAPE_FUZZ", .name = "jsonshape-path" } },
    });
}

test "fuzz harness: 2000 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..2000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        pathHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("jsonshape seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

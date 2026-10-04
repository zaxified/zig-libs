// SPDX-License-Identifier: MIT
//! Tests for the 2026-10-04 additions: the emitter and the typed mapping
//! (merge keys are checked against PyYAML in `suite_test.zig`). Expected
//! text is derived by hand from YAML 1.2 (§7.3 quoted scalars, §8 block
//! collections, §10.2 core schema), as each test says.

const std = @import("std");
const testing = std.testing;
const yaml = @import("root.zig");
const Value = yaml.Value;
const Pair = yaml.Pair;

fn roundTrip(v: Value) !void {
    const a = testing.allocator;
    const text = try yaml.stringify(a, v);
    defer a.free(text);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const docs = yaml.composeAllLeaky(arena.allocator(), text, .{}) catch |e| {
        std.debug.print("does not compose ({t}):\n{s}\n", .{ e, text });
        return e;
    };
    try testing.expectEqual(@as(usize, 1), docs.len);
    if (!yaml.valueEql(v, docs[0])) {
        std.debug.print("composes differently:\n{s}\n", .{text});
        return error.TestUnexpectedResult;
    }
}

test "emit: block layout, quoting, numbers (text derived by hand)" {
    const a = testing.allocator;
    const inner = [_]Pair{
        .{ .key = .{ .string = "x" }, .value = .{ .int = -1 } },
        .{ .key = .{ .string = "y" }, .value = .{ .float = 1e300 } },
    };
    const seq = [_]Value{ .{ .string = "plain word" }, .{ .string = "yes" }, .{ .string = "1.5" }, .{ .mapping = &inner }, .{ .sequence = &.{} } };
    const top = [_]Pair{
        .{ .key = .{ .string = "name" }, .value = .{ .string = "a\"b\\c\n\t\u{85}\u{feff}" } },
        .{ .key = .{ .string = "on" }, .value = .null },
        .{ .key = .{ .int = 7 }, .value = .{ .bool = false } },
        .{ .key = .{ .string = "list" }, .value = .{ .sequence = &seq } },
        .{ .key = .{ .string = "nums" }, .value = .{ .sequence = &.{ .{ .float = 0.5 }, .{ .float = -0.0 }, .{ .float = std.math.inf(f64) }, .{ .float = std.math.nan(f64) }, .{ .float = 100.0 } } } },
        .{ .key = .{ .sequence = &.{ .{ .int = 1 }, .{ .string = "k" } } }, .value = .{ .mapping = &.{} } },
    };
    const v: Value = .{ .mapping = &top };
    const text = try yaml.stringify(a, v);
    defer a.free(text);
    // "on"/"yes"/"y" would be booleans to a 1.1 reader and "1.5" a float
    // to both: quoted. A collection key takes the explicit `? ` form.
    try testing.expectEqualStrings(
        \\name: "a\"b\\c\n\t\N\uFEFF"
        \\"on": null
        \\7: false
        \\list:
        \\  - plain word
        \\  - "yes"
        \\  - "1.5"
        \\  -
        \\    x: -1
        \\    "y": 1.0e+300
        \\  - []
        \\nums:
        \\  - 0.5
        \\  - -0.0
        \\  - .inf
        \\  - .nan
        \\  - 100.0
        \\? [1, k]
        \\: {}
        \\
    , text);
    // NaN never equals itself, so the round trip is checked without it.
    var no_nan = top;
    no_nan[4] = .{ .key = .{ .string = "nums" }, .value = .{ .sequence = &.{ .{ .float = 0.5 }, .{ .float = -0.0 }, .{ .float = -std.math.inf(f64) } } } };
    try roundTrip(.{ .mapping = &no_nan });
}

test "emit: scalars that must be quoted, and ones that need not be" {
    const quoted = [_][]const u8{ "", " lead", "trail ", "null", "NULL", "~", "true", "False", "yes", "No", "ON", "off", "y", "N", "0777", "1:30", "2001-12-14", "-dash", "? q", "a: b", "a #c", "[x]", "{x}", "*ref", "&anc", "!tag", "%dir", "@at", "`bt", "'s'", "\"d\"", "<<", "=", ".inf", "+1", "x\ny", "\u{e9}t\u{e9}", "tab\there", "a,b" };
    for (quoted) |s| {
        try testing.expect(!yaml.emit.isSafePlain(s));
        try roundTrip(.{ .string = s });
    }
    const plain = [_][]const u8{ "a", "hello world", "_x", "/usr/bin", "v1.2-rc3", "CamelCase" };
    for (plain) |s| {
        try testing.expect(yaml.emit.isSafePlain(s));
        try roundTrip(.{ .string = s });
    }
    // Control characters, the BOM and line separators escape (§5.7).
    try roundTrip(.{ .string = "\x00\x01\x07\x1b\x7f\u{2028}\u{2029}\u{fffe}" });
    // Integer extremes and floats that need every layout branch.
    for ([_]i64{ std.math.minInt(i64), -1, 0, std.math.maxInt(i64) }) |i| try roundTrip(.{ .int = i });
    for ([_]f64{ 5e-324, 1e-7, 1e-6, 0.1, 1.0, 1e20, 1e21, 123456789.125, std.math.floatMax(f64) }) |f| try roundTrip(.{ .float = f });
}

test "emit: a shared node is written once, anchored, and aliased after" {
    const a = testing.allocator;
    // A 20-level billion-laughs DAG: 2^20 leaves when walked as a tree.
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(a);
    try src.appendSlice(a, "l0: &l0 [lol, lol]\n");
    for (1..20) |i| try src.print(a, "l{d}: &l{d} [*l{d}, *l{d}]\n", .{ i, i, i - 1, i - 1 });
    const docs = try yaml.composeAllLeaky(arena.allocator(), src.items, .{});
    const text = try yaml.stringify(a, docs[0]);
    defer a.free(text);
    // Linear, not 2^20: every level is written once and aliased once more.
    try testing.expect(text.len < 2 * src.items.len + 400);
    try testing.expect(std.mem.indexOf(u8, text, "*a") != null);
    const back = try yaml.composeAllLeaky(arena.allocator(), text, .{});
    try testing.expect(yaml.valueEql(docs[0], back[0]));
    // writeAll: a stream of two documents.
    var aw: std.Io.Writer.Allocating = .init(a);
    defer aw.deinit();
    try yaml.writeAll(a, &aw.writer, &.{ .{ .int = 1 }, .{ .string = "two" } });
    try testing.expectEqualStrings("---\n1\n---\ntwo\n", aw.written());
}

// ── typed mapping ──────────────────────────────────────────────────────────

const Level = enum { debug, info, warn };
const Target = union(enum) {
    stdout,
    file: []const u8,
    tcp: struct { host: []const u8, port: u16 },
};
const Config = struct {
    name: []const u8,
    max_conn: u32 = 100,
    ratio: f64 = 1.0,
    level: Level = .info,
    tags: []const []const u8 = &.{},
    limits: [2]i16 = .{ 0, 0 },
    owner: ?[]const u8 = null,
    target: Target = .stdout,
    pub const yaml_keys = .{ .max_conn = "max-connections" };
};

test "typed: a config document onto a struct" {
    const a = testing.allocator;
    const doc =
        \\name: api
        \\max-connections: 250
        \\ratio: 2
        \\level: warn
        \\tags: [a, "b"]
        \\limits: [-1, 300]
        \\target:
        \\  tcp: {host: localhost, port: 8125}
        \\
    ;
    const p = try yaml.typed.parse(Config, a, doc, .{});
    defer p.deinit();
    const c = p.value;
    try testing.expectEqualStrings("api", c.name);
    try testing.expectEqual(@as(u32, 250), c.max_conn);
    try testing.expectEqual(@as(f64, 2.0), c.ratio); // an int the float holds exactly
    try testing.expectEqual(Level.warn, c.level);
    try testing.expectEqualStrings("b", c.tags[1]);
    try testing.expectEqual([2]i16{ -1, 300 }, c.limits);
    try testing.expectEqual(@as(?[]const u8, null), c.owner);
    try testing.expectEqual(@as(u16, 8125), c.target.tcp.port);
    // A void variant may be the bare name.
    const p2 = try yaml.typed.parse(Config, a, "name: x\ntarget: stdout\n", .{});
    defer p2.deinit();
    try testing.expect(p2.value.target == .stdout);
    // And back: stringify, parse again, same struct.
    const text = try yaml.typed.stringify(a, c);
    defer a.free(text);
    const p3 = try yaml.typed.parse(Config, a, text, .{});
    defer p3.deinit();
    try testing.expectEqualStrings("localhost", p3.value.target.tcp.host);
    try testing.expectEqual(@as(u32, 250), p3.value.max_conn);
    try testing.expect(std.mem.indexOf(u8, text, "max-connections: 250\n") != null);
}

test "typed: every refusal, each derived from the type and the document" {
    const a = testing.allocator;
    const T = yaml.typed;
    try testing.expectError(error.MissingField, T.parse(Config, a, "ratio: 1.5\n", .{}));
    // `version: 1.10` is the float 1.1 under the core schema: not a string.
    const V = struct { version: []const u8 };
    try testing.expectError(error.WrongType, T.parse(V, a, "version: 1.10\n", .{}));
    const ok = try T.parse(V, a, "version: \"1.10\"\n", .{});
    ok.deinit();
    try testing.expectError(error.Overflow, T.parse(struct { n: u8 }, a, "n: 256\n", .{}));
    try testing.expectError(error.Overflow, T.parse(struct { n: u8 }, a, "n: -1\n", .{}));
    // 2^53 + 1 is not exactly a double.
    try testing.expectError(error.Overflow, T.parse(struct { f: f64 }, a, "f: 9007199254740993\n", .{}));
    try testing.expectError(error.Overflow, T.parse(struct { f: f32 }, a, "f: 0.1\n", .{}));
    try testing.expectError(error.InvalidEnum, T.parse(Config, a, "name: x\nlevel: loud\n", .{}));
    try testing.expectError(error.LengthMismatch, T.parse(Config, a, "name: x\nlimits: [1]\n", .{}));
    try testing.expectError(error.UnknownField, T.parse(V, a, "version: a\nextra: 1\n", .{ .ignore_unknown_fields = false }));
    const lax = try T.parse(V, a, "version: a\nextra: 1\n", .{});
    lax.deinit();
    try testing.expectError(error.DuplicateField, T.parse(V, a, "version: a\nversion: b\n", .{ .compose = .{ .reject_duplicate_keys = false } }));
    try testing.expectError(error.DuplicateKey, T.parse(V, a, "version: a\nversion: b\n", .{}));
    try testing.expectError(error.WrongType, T.parse(Config, a, "name: x\ntarget: [1]\n", .{}));
    try testing.expectError(error.InvalidEnum, T.parse(Config, a, "name: x\ntarget: {udp: 1}\n", .{}));
    try testing.expectError(error.ExpectedSingleDocument, T.parse(V, a, "version: a\n---\nversion: b\n", .{}));
    // The allocation cap: 100 empty mappings into a 4 KiB struct each.
    const Fat = struct { pad: [4096]u8 = @splat(0) };
    var buf: [400]u8 = undefined;
    var n: usize = 0;
    buf[0] = '[';
    n = 1;
    for (0..100) |i| {
        if (i != 0) {
            buf[n] = ',';
            n += 1;
        }
        buf[n] = '{';
        buf[n + 1] = '}';
        n += 2;
    }
    buf[n] = ']';
    n += 1;
    try testing.expectError(error.TooLarge, T.parse([]const Fat, a, buf[0..n], .{ .max_alloc_bytes = 100_000 }));
    const fat = try T.parse([]const Fat, a, buf[0..n], .{});
    fat.deinit();
}

test "typed: no leak on any allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn f(a: std.mem.Allocator) !void {
            const p = try yaml.typed.parse(Config, a, "name: n\ntags: [x, y]\ntarget: {file: /tmp/x}\n", .{});
            p.deinit();
            const t = try yaml.typed.stringify(a, Config{ .name = "q" });
            a.free(t);
        }
    }.f, .{});
}

// ── tests asked for by the 2026-10-04 mutation run ─────────────────────────

test "emit: a node shared exactly twice is anchored once and aliased once" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const docs = try yaml.composeAllLeaky(arena.allocator(), "a: &x [1, 2]\nb: *x\n", .{});
    const text = try yaml.stringify(a, docs[0]);
    defer a.free(text);
    try testing.expectEqualStrings("a: &a1\n  - 1\n  - 2\nb: *a1\n", text);
}

test "emit: a long key takes the explicit form (implicit keys stop at 1024 characters)" {
    const a = testing.allocator;
    // 150 control characters escape to 600 characters plus quotes: fine as
    // an implicit key on its own, but the emitter's bound (100 source bytes,
    // so even 10-character escapes stay under 1024) sends it to `? `.
    const key = "\x01" ** 150;
    const pairs = [_]Pair{.{ .key = .{ .string = key }, .value = .{ .int = 1 } }};
    const text = try yaml.stringify(a, .{ .mapping = &pairs });
    defer a.free(text);
    try testing.expect(std.mem.startsWith(u8, text, "? \"\\x01"));
    try testing.expect(std.mem.endsWith(u8, text, "\"\n: 1\n"));
}

test "typed: a key with no value is a struct of defaults; u64 beyond i64 is a string; null optionals are left out" {
    const a = testing.allocator;
    const Outer = struct { inner: struct { n: u8 = 7 } };
    const p = try yaml.typed.parse(Outer, a, "inner:\n", .{});
    defer p.deinit();
    try testing.expectEqual(@as(u8, 7), p.value.inner.n);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const big = try yaml.typed.toValue(arena.allocator(), @as(u64, std.math.maxInt(u64)));
    try testing.expectEqualStrings("18446744073709551615", big.string);
    const text = try yaml.typed.stringify(a, Config{ .name = "q" });
    defer a.free(text);
    try testing.expectEqualStrings(
        \\name: q
        \\max-connections: 100
        \\ratio: 1.0
        \\level: info
        \\tags: []
        \\limits:
        \\  - 0
        \\  - 0
        \\target: stdout
        \\
    , text);
}

test "emit: an aliased KEY keeps a space before ':' (an alias name may contain ':')" {
    // Found by self-review: `*a1:` reads as the alias named "a1:".
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const long = "k" ** 40; // 32+ bytes: shared strings are anchored too
    const src = "a: {&k " ++ long ++ ": 1}\nb: {*k : 2}\nc: [{? {*k : 3} : 4}]\n";
    const docs = try yaml.composeAllLeaky(arena.allocator(), src, .{});
    const text = try yaml.stringify(a, docs[0]);
    defer a.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "*a1 :") != null);
    const back = try yaml.composeAllLeaky(arena.allocator(), text, .{});
    try testing.expect(yaml.valueEql(docs[0], back[0]));
}

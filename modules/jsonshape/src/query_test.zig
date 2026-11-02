// SPDX-License-Identifier: MIT
//! The query API beyond what the compliance suite (`cts_test.zig`) asks for:
//! the I-Regexp boundary as RFC 9535 sees it, Normalized Paths, the diagnostic,
//! duplicate keys, exact integers and the agreement with `shape`.

const std = @import("std");
const testing = std.testing;
const js = @import("root.zig");

const Env = struct {
    arena: std.heap.ArenaAllocator,

    fn init() Env {
        return .{ .arena = std.heap.ArenaAllocator.init(testing.allocator) };
    }
    fn deinit(e: *Env) void {
        e.arena.deinit();
    }
    fn count(e: *Env, doc: []const u8, path: []const u8) !usize {
        const a = e.arena.allocator();
        const root = try js.parseDocument(a, doc, .{});
        return (try js.query(a, root, try js.compile(a, path, null), .{})).len;
    }
};

test "match is anchored at both ends, search is not" {
    var e = Env.init();
    defer e.deinit();
    const doc = "[\"ab\",\"xab\",\"abx\",\"a\"]";
    try testing.expectEqual(1, try e.count(doc, "$[?match(@,'ab')]"));
    try testing.expectEqual(3, try e.count(doc, "$[?search(@,'ab')]"));
    // The anchoring holds around an alternative that would match a prefix.
    try testing.expectEqual(2, try e.count(doc, "$[?match(@,'a|ab')]"));
    try testing.expectEqual(2, try e.count(doc, "$[?match(@,'(a|ab)')]"));
    // Negated, and combined, as a test.
    try testing.expectEqual(3, try e.count(doc, "$[?!match(@,'ab')]"));
    try testing.expectEqual(1, try e.count(doc, "$[?search(@,'x')&&match(@,'.*x')]"));
}

test "`.` is not \\n or \\r: RFC 9485 §5.3, where the engine would take \\r" {
    var e = Env.init();
    defer e.deinit();
    try testing.expectEqual(0, try e.count("[\"\\n\",\"\\r\"]", "$[?match(@,'.')]"));
    try testing.expectEqual(1, try e.count("[\"\\u2028\"]", "$[?match(@,'.')]"));
    // Whereas a class says what it says.
    try testing.expectEqual(2, try e.count("[\"\\n\",\"\\r\"]", "$[?match(@,'[^a]')]"));
}

test "the engine's wider syntax makes the function false, it does not apply" {
    var e = Env.init();
    defer e.deinit();
    const doc = "[\"1\",\"A\",\"a\",\"aa\",\"(\"]";
    for ([_][]const u8{
        "\\\\d",         "\\\\w", "\\\\s",    "\\\\x31", "(?i)a",       "(?:a)",   "(?P<n>a)",
        "a*?",           "a+?",   "(a)\\\\1", "\\\\b",   "[[:digit:]]", "[\\\\d]", "\\\\p{Greek}",
        "\\\\p{Letter}", "(",     ")",        "[",       "a{1001}",     "a{2,1}",  "[z-a]",
    }) |pattern| {
        var buf: [64]u8 = undefined;
        for ([_][]const u8{ "match", "search" }) |f| {
            const path = try std.fmt.bufPrint(&buf, "$[?{s}(@,'{s}')]", .{ f, pattern });
            testing.expectEqual(0, try e.count(doc, path)) catch |err| {
                std.debug.print("selected something: {s}\n", .{path});
                return err;
            };
        }
    }
}

test "I-Regexp's own syntax reaches the engine intact" {
    var e = Env.init();
    defer e.deinit();
    try testing.expectEqual(2, try e.count("[\"é\",\"Z\",\"1\"]", "$[?match(@,'\\\\p{L}')]"));
    try testing.expectEqual(1, try e.count("[\"é\",\"Z\",\"1\"]", "$[?match(@,'\\\\P{L}')]"));
    try testing.expectEqual(1, try e.count("[\"Z\",\"z\"]", "$[?match(@,'[\\\\p{Lu}]')]"));
    try testing.expectEqual(1, try e.count("[\"a-b\",\"a\"]", "$[?match(@,'a\\\\-b')]"));
    try testing.expectEqual(1, try e.count("[\"^\",\"a\"]", "$[?match(@,'[\\\\^]')]"));
    try testing.expectEqual(1, try e.count("[\"^\",\"a\"]", "$[?match(@,'[x^]')]"));
    try testing.expectEqual(1, try e.count("[\"&\",\"a\"]", "$[?match(@,'[x&&y]')]"));
    try testing.expectEqual(1, try e.count("[\"aaa\",\"aa\"]", "$[?match(@,'a{03}')]"));
}

test "match and search: an argument of the wrong kind is false, a shape of the wrong kind refused" {
    var e = Env.init();
    defer e.deinit();
    const doc = "[{\"a\":1,\"p\":\"a\"},{\"a\":\"a\",\"p\":2},{\"a\":\"a\",\"p\":\"a\"},{\"a\":\"a\"}]";
    try testing.expectEqual(1, try e.count(doc, "$[?match(@.a,@.p)]"));
    try testing.expectEqual(0, try e.count(doc, "$[?match(@.a,1)]"));
    try testing.expectEqual(0, try e.count(doc, "$[?match(@.nope,'a')]"));
    try testing.expectEqual(3, try e.count(doc, "$[?search(@.a,$[2].p)]"));

    const a = e.arena.allocator();
    for ([_][]const u8{
        "$[?match(@.a)]",           "$[?match(@.a,'a','b')]",  "$[?match(@.*,'a')]",
        "$[?match(@.a,'a')==true]", "$[?count(match(@,'a'))]", "$[?length(match(@,'a'))==1]",
        "$[?match (@,'a')]",        "$[?MATCH(@,'a')]",
    }) |path| {
        testing.expectError(error.InvalidPath, js.compile(a, path, null)) catch |err| {
            std.debug.print("accepted: {s}\n", .{path});
            return err;
        };
    }
}

test "compile: the offset of the failure" {
    var e = Env.init();
    defer e.deinit();
    const a = e.arena.allocator();
    var d: js.Diagnostic = .{};
    try testing.expectError(error.InvalidPath, js.compile(a, "$.a.1", &d));
    try testing.expectEqual(4, d.offset);
    try testing.expectError(error.InvalidPath, js.compile(a, "a.b", &d));
    try testing.expectEqual(0, d.offset);
    try testing.expectError(error.InvalidPath, js.compile(a, "$.a\xff", &d));
    try testing.expectEqual(0, d.offset);
    d.offset = 99;
    _ = try js.compile(a, "$.a", &d);
    try testing.expectEqual(99, d.offset);
}

test "Normalized Paths: RFC 9535 §2.7 escapes, and they select their node" {
    var e = Env.init();
    defer e.deinit();
    const a = e.arena.allocator();
    const doc =
        \\{"a'b":{"c\\d":[10,{"\u0001\u001f\b\t\n\f\r":1,"é/\"":2}]}}
    ;
    const root = try js.parseDocument(a, doc, .{});
    const got = try js.queryLocated(a, root, try js.compile(a, "$.*.*[1].*", null), .{});
    try testing.expectEqual(2, got.len);
    try testing.expectEqualStrings("$['a\\'b']['c\\\\d'][1]['\\u0001\\u001f\\b\\t\\n\\f\\r']", got[0].path);
    try testing.expectEqualStrings("$['a\\'b']['c\\\\d'][1]['é/\"']", got[1].path);
    try testing.expectEqual(1, got[0].value.integer);
    for (got) |g| {
        const back = try js.query(a, root, try js.compile(a, g.path, null), .{});
        try testing.expectEqual(1, back.len);
        try testing.expectEqual(g.value.integer, back[0].integer);
    }
    // Negative indices and slices come back as the position in the array.
    const arr = try js.parseDocument(a, "[1,2,3]", .{});
    const neg = try js.queryLocated(a, arr, try js.compile(a, "$[-1,::-2,?@==2]", null), .{});
    const want = [_][]const u8{ "$[2]", "$[2]", "$[0]", "$[1]" };
    try testing.expectEqual(want.len, neg.len);
    for (want, neg) |w, n| try testing.expectEqualStrings(w, n.path);
}

test "queryFirst stops at the first node, past which a query would run out of budget" {
    var e = Env.init();
    defer e.deinit();
    const a = e.arena.allocator();
    const root = try js.parseDocument(a, "[1,2,3,4,5,6,7,8]", .{});
    const path = try js.compile(a, "$[*]", null);
    try testing.expectError(error.WorkLimit, js.query(a, root, path, .{ .max_work = 5 }));
    try testing.expectEqual(1, (try js.queryFirst(a, root, path, .{ .max_work = 5 })).?.integer);
    try testing.expectEqual(null, try js.queryFirst(a, root, try js.compile(a, "$.a", null), .{}));
    try testing.expectError(error.TooManyMatches, js.query(a, root, path, .{ .max_matches = 7 }));
    try testing.expectEqual(8, (try js.query(a, root, path, .{ .max_matches = 8 })).len);
}

test "a filter's integer literal compares exactly, past f64's 2^53" {
    var e = Env.init();
    defer e.deinit();
    const doc = "[9007199254740993,9007199254740992]";
    try testing.expectEqual(1, try e.count(doc, "$[?@==9007199254740993]"));
    try testing.expectEqual(1, try e.count(doc, "$[?@>9007199254740992]"));
    try testing.expectEqual(1, try e.count("[1,2]", "$[?@==1.0]"));
}

test "duplicate keys: refused by default, the last one on request" {
    var e = Env.init();
    defer e.deinit();
    const a = e.arena.allocator();
    const doc = "{\"a\":1,\"a\":2}";
    try testing.expectError(error.BadJson, js.parseDocument(a, doc, .{}));
    const root = try js.parseDocument(a, doc, .{ .duplicate_keys = .last });
    try testing.expectEqual(2, root.object.get("a").?.integer);

    const col = [_]js.JsonCol{.{ .name = "a", .key = "a", .type = .int }};
    const wrapped = "[{\"a\":1,\"a\":2}]";
    try testing.expectError(error.BadJson, js.shape(a, wrapped, .{ .columns = &col }));
    const d = try js.shape(a, wrapped, .{ .columns = &col, .duplicate_keys = .last });
    try testing.expectEqual(2, d.rows[0][0].int);
}

test "shape takes match and search, and keeps its permissive path" {
    var e = Env.init();
    defer e.deinit();
    const a = e.arena.allocator();
    const col = [_]js.JsonCol{.{ .name = "n", .key = "n", .type = .text }};
    const doc = "{\"list\":[{\"n\":\"ab\"},{\"n\":\"xab\"}],\"a-b c\":[{\"n\":\"z\"}]}";
    const m = try js.shape(a, doc, .{ .path = "list[?match(@.n,'a.*')]", .columns = &col });
    try testing.expectEqual(1, m.rows.len);
    const s = try js.shape(a, doc, .{ .path = "$.list[?search(@.n,'a')]", .columns = &col });
    try testing.expectEqual(2, s.rows.len);
    const bad = try js.shape(a, doc, .{ .path = "$.list[?match(@.n,'\\\\d')]", .columns = &col });
    try testing.expectEqual(0, bad.rows.len);
    // Not RFC 9535, accepted since v1: `compile` refuses what `shape` still takes.
    const loose = try js.shape(a, doc, .{ .path = "$.a-b c", .columns = &col });
    try testing.expectEqual(1, loose.rows.len);
    try testing.expectError(error.InvalidPath, js.compile(a, "$.a-b c", null));
}

test "review: `^` anchors only as a branch's first atom, `$` only as its last (MED-5)" {
    var e = Env.init();
    defer e.deinit();
    // Anchors, where the suite needs them.
    try testing.expectEqual(1, try e.count("[\"ab\",\"xab\"]", "$[?search(@,'^ab')]"));
    try testing.expectEqual(1, try e.count("[\"ab\",\"abx\"]", "$[?search(@,'ab$')]"));
    try testing.expectEqual(1, try e.count("[\"\",\"a\"]", "$[?match(@,'^$')]"));
    // In each branch, also inside a group.
    try testing.expectEqual(2, try e.count("[\"x\",\"y\",\"zy\"]", "$[?match(@,'x|^y')]"));
    try testing.expectEqual(1, try e.count("[\"y\",\"zy\"]", "$[?search(@,'(x|^y)')]"));
    // Elsewhere they are characters: these could never match as anchors.
    try testing.expectEqual(1, try e.count("[\"a$b\",\"ab\"]", "$[?match(@,'a$b')]"));
    try testing.expectEqual(1, try e.count("[\"a^b\",\"ab\"]", "$[?match(@,'a^b')]"));
    try testing.expectEqual(1, try e.count("[\"$a\",\"a\"]", "$[?match(@,'$a')]"));
    try testing.expectEqual(1, try e.count("[\"^^a\",\"^a\",\"a\"]", "$[?match(@,'^^a')]"));
    try testing.expectEqual(1, try e.count("[\"a$\",\"a\"]", "$[?match(@,'a$$')]"));
    // A quantified one is an atom with a count, so a character.
    try testing.expectEqual(1, try e.count("[\"$$\",\"\"]", "$[?match(@,'$+')]"));
    try testing.expectEqual(1, try e.count("[\"^^\",\"\"]", "$[?match(@,'^{2}')]"));
}

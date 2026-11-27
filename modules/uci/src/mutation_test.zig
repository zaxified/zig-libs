// SPDX-License-Identifier: MIT
//! Killing tests of the 2026-11-27 whole-module mutation run (uci): one test
//! per survivor group of the schemata run. Every expected value comes from the
//! documented grammar, the module's SPEC.md or the doc comments of the code
//! under test, never from running the pristine code and copying its output.

const std = @import("std");
const testing = std.testing;
const uci = @import("root.zig");
const edit = @import("edit.zig");
const store_mod = @import("store.zig");

const max_line = uci.max_line_len;
const max_input = uci.max_input_len;

fn repeat(a: std.mem.Allocator, buf: *std.ArrayList(u8), s: []const u8, n: usize) !void {
    for (0..n) |_| try buf.appendSlice(a, s);
}

// ── model: accessors and equality ───────────────────────────────────────────

test "mutation 2026-11-27: get and getInt on an option without values and on an empty list entry" {
    const opts = [_]uci.Option{
        .{ .key = "e", .kind = .list, .values = &.{} },
        .{ .key = "z", .kind = .list, .values = &.{""} },
    };
    const s: uci.Section = .{ .type = "t", .name = null, .anonymous = true, .options = &opts };
    try testing.expect(s.get("e") == null);
    try testing.expectEqual(@as(usize, 0), s.getList("e").len);
    try testing.expectEqual(@as(?i64, null), s.getInt("z"));
    try testing.expectEqual(@as(?bool, null), s.getBool("z"));
}

test "mutation 2026-11-27: Option, Section and Package equality see every single difference" {
    const v_a = [_][]const u8{"a"};
    const v_b = [_][]const u8{"b"};
    const v_aa = [_][]const u8{ "a", "a" };
    const base: uci.Option = .{ .key = "k", .kind = .single, .values = &v_a };
    try testing.expect(base.eql(&base));
    const o_key: uci.Option = .{ .key = "j", .kind = .single, .values = &v_a };
    const o_kind: uci.Option = .{ .key = "k", .kind = .list, .values = &v_a };
    const o_len: uci.Option = .{ .key = "k", .kind = .single, .values = &v_aa };
    const o_val: uci.Option = .{ .key = "k", .kind = .single, .values = &v_b };
    try testing.expect(!base.eql(&o_key));
    try testing.expect(!base.eql(&o_kind));
    try testing.expect(!base.eql(&o_len));
    try testing.expect(!base.eql(&o_val));

    const opts = [_]uci.Option{base};
    const opts2 = [_]uci.Option{ base, o_key };
    const opts_val = [_]uci.Option{o_val};
    const s: uci.Section = .{ .type = "t", .name = "n", .anonymous = false, .options = &opts };
    try testing.expect(s.eql(&s));
    const s_type: uci.Section = .{ .type = "u", .name = "n", .anonymous = false, .options = &opts };
    const s_name: uci.Section = .{ .type = "t", .name = "m", .anonymous = false, .options = &opts };
    const s_none: uci.Section = .{ .type = "t", .name = null, .anonymous = false, .options = &opts };
    const s_anon: uci.Section = .{ .type = "t", .name = "n", .anonymous = true, .options = &opts };
    const s_cnt: uci.Section = .{ .type = "t", .name = "n", .anonymous = false, .options = &opts2 };
    const s_opt: uci.Section = .{ .type = "t", .name = "n", .anonymous = false, .options = &opts_val };
    try testing.expect(!s.eql(&s_type));
    try testing.expect(!s.eql(&s_name));
    try testing.expect(!s.eql(&s_none)); // a name against none
    try testing.expect(!s_none.eql(&s)); // none against a name
    try testing.expect(!s.eql(&s_anon));
    try testing.expect(!s.eql(&s_cnt));
    try testing.expect(!s.eql(&s_opt));

    const secs = [_]uci.Section{s};
    const secs2 = [_]uci.Section{ s, s };
    const secs_diff = [_]uci.Section{s_type};
    const p: uci.Package = .{ .name = "p", .sections = &secs };
    try testing.expect(p.eql(&p));
    const p_name: uci.Package = .{ .name = "q", .sections = &secs };
    const p_null: uci.Package = .{ .name = null, .sections = &secs };
    const p_cnt: uci.Package = .{ .name = "p", .sections = &secs2 };
    const p_sec: uci.Package = .{ .name = "p", .sections = &secs_diff };
    try testing.expect(!p.eql(&p_name));
    try testing.expect(!p.eql(&p_null));
    try testing.expect(!p_null.eql(&p));
    try testing.expect(!p.eql(&p_cnt));
    try testing.expect(!p.eql(&p_sec));
    try testing.expect(p_null.eql(&p_null)); // no name equals no name
}

test "mutation 2026-11-27: resolveSection needs the closing bracket" {
    const gpa = testing.allocator;
    var pkg = try uci.parse(gpa, "config t\n\toption a '1'\n");
    defer pkg.deinit(gpa);
    try testing.expect(pkg.resolveSection("@t[0]") != null);
    try testing.expect(pkg.resolveSection("@t[0x") == null);
    try testing.expect(pkg.resolveSection("@t[0") == null);
}

test "mutation 2026-11-27: validTypeChars accepts 33 and 126, refuses 32 and 127" {
    try testing.expect(uci.validTypeChars("!~"));
    try testing.expect(!uci.validTypeChars(" "));
    try testing.expect(!uci.validTypeChars("\x7f"));
    try testing.expect(!uci.validTypeChars("a\x80"));
}

// ── parser: limits and their boundaries ─────────────────────────────────────

fn commentBlock(a: std.mem.Allocator, total: usize) ![]u8 {
    // whole lines of max_line_len bytes ('#', 16382 x, LF); the last one short
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(a);
    var left = total;
    while (left > 0) {
        const n = @min(left, max_line);
        try buf.append(a, '#');
        if (n >= 2) {
            try buf.appendNTimes(a, 'x', n - 2);
            try buf.append(a, '\n');
        }
        left -= n;
    }
    return buf.toOwnedSlice(a);
}

test "mutation 2026-11-27: input of exactly max_input_len is accepted, one byte more is InputTooLarge (parse and parseScript)" {
    const gpa = testing.allocator;
    const exact = try commentBlock(gpa, max_input);
    defer gpa.free(exact);
    try testing.expectEqual(max_input, exact.len);
    var pkg = try uci.parse(gpa, exact);
    pkg.deinit(gpa);
    var sc = try uci.parseScript(gpa, exact, null);
    sc.deinit(gpa);

    const over = try gpa.alloc(u8, max_input + 1);
    defer gpa.free(over);
    @memcpy(over[0..max_input], exact);
    over[max_input] = '\n';
    var diag: uci.Diagnostics = .{ .line = 7 };
    try testing.expectError(error.InputTooLarge, uci.parseDiag(gpa, over, &diag));
    try testing.expectEqual(@as(usize, 0), diag.line);
    diag.line = 7;
    try testing.expectError(error.InputTooLarge, uci.parseScript(gpa, over, &diag));
    try testing.expectEqual(@as(usize, 0), diag.line);
}

test "mutation 2026-11-27: a CR before LF is not counted into max_line_len, on the first line and on a later one" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    // first physical line: exactly max_line_len bytes, then CRLF
    try buf.append(gpa, '#');
    try buf.appendNTimes(gpa, 'x', max_line - 1);
    try buf.appendSlice(gpa, "\r\nconfig t\r\n");
    var pkg = try uci.parse(gpa, buf.items);
    try testing.expectEqual(@as(usize, 1), pkg.sections.len);
    pkg.deinit(gpa);
    // a later line
    buf.clearRetainingCapacity();
    try buf.appendSlice(gpa, "config t\r\n#");
    try buf.appendNTimes(gpa, 'x', max_line - 1);
    try buf.appendSlice(gpa, "\r\n");
    var pkg2 = try uci.parse(gpa, buf.items);
    try testing.expectEqual(@as(usize, 1), pkg2.sections.len);
    pkg2.deinit(gpa);
    // one byte more is too long either way
    buf.clearRetainingCapacity();
    try buf.appendSlice(gpa, "config t\r\n#");
    try buf.appendNTimes(gpa, 'x', max_line);
    try buf.appendSlice(gpa, "\r\n");
    try testing.expectError(error.LineTooLong, uci.parse(gpa, buf.items));
}

test "mutation 2026-11-27: every physical line of a multi-line quote is bounded" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, "config t\n\toption k 'a\n");
    try buf.appendNTimes(gpa, 'y', max_line + 1);
    try buf.appendSlice(gpa, "'\n");
    try testing.expectError(error.LineTooLong, uci.parse(gpa, buf.items));
}

test "mutation 2026-11-27: a lone CR as the last byte ends the line" {
    const gpa = testing.allocator;
    var pkg = try uci.parse(gpa, "config t\r");
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), pkg.sections.len);
    try testing.expectEqualStrings("t", pkg.sections[0].type);
}

test "mutation 2026-11-27: a final LF does not start a phantom line in a diagnostic" {
    const gpa = testing.allocator;
    var diag: uci.Diagnostics = .{};
    // after a backslash-LF at the very end of the input
    try testing.expectError(error.MixedOptionList, uci.parseDiag(gpa, "config t\n\toption a 'x'\n\tlist a \\\n", &diag));
    try testing.expectEqual(@as(usize, 3), diag.line);
    // a quote left open at the last LF
    try testing.expectError(error.UnterminatedQuote, uci.parseDiag(gpa, "config t\n\toption a 'x\n", &diag));
    try testing.expectEqual(@as(usize, 2), diag.line);
}

test "mutation 2026-11-27: a backslash at the very end of a double quote is an unterminated quote" {
    const gpa = testing.allocator;
    try testing.expectError(error.UnterminatedQuote, uci.parse(gpa, "config t\n\toption a \"x\\"));
    try testing.expectError(error.UnterminatedQuote, uci.parse(gpa, "config t\n\toption a \"x\\\r"));
}

test "mutation 2026-11-27: a comment where a required argument would start is MissingArgument" {
    const gpa = testing.allocator;
    try testing.expectError(error.MissingArgument, uci.parse(gpa, "config # nothing\n"));
    try testing.expectError(error.MissingArgument, uci.parse(gpa, "config t\n\toption # nothing\n"));
}

test "mutation 2026-11-27: a tab separates words" {
    const gpa = testing.allocator;
    var pkg = try uci.parse(gpa, "config\tt\t'n'\n\toption\tk\t'v'\n\tlist\tl\tw\n");
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), pkg.sections.len);
    const s = &pkg.sections[0];
    try testing.expectEqualStrings("t", s.type);
    try testing.expectEqualStrings("n", s.name.?);
    try testing.expectEqualStrings("v", s.get("k").?);
    try testing.expectEqualStrings("w", s.get("l").?);
}

fn itemsText(a: std.mem.Allocator, extra_lists: usize) ![]u8 {
    // 2 sections (2 items) + 149998 single options (299996) + one list (2) = 300000 items;
    // every extra list entry is one more
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(a);
    try buf.appendSlice(a, "config a\nconfig b\n");
    for (0..149_998) |i| try buf.print(a, "\toption k{d} 'v'\n", .{i});
    try buf.appendSlice(a, "\tlist l 'a'\n");
    try repeat(a, &buf, "\tlist l 'b'\n", extra_lists);
    return buf.toOwnedSlice(a);
}

test "mutation 2026-11-27: max_total_items is exact, counting sections, options and list entries" {
    const gpa = testing.allocator;
    const at_cap = try itemsText(gpa, 0);
    defer gpa.free(at_cap);
    var pkg = try uci.parse(gpa, at_cap);
    pkg.deinit(gpa);
    const over = try itemsText(gpa, 1);
    defer gpa.free(over);
    try testing.expectError(error.MemoryLimitExceeded, uci.parse(gpa, over));
}

test "mutation 2026-11-27: the item cap also stops a file of sections only, and one of list entries only" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try repeat(gpa, &buf, "config t\n", uci.max_total_items);
    var pkg = try uci.parse(gpa, buf.items);
    try testing.expectEqual(uci.max_total_items, pkg.sections.len);
    pkg.deinit(gpa);
    try buf.appendSlice(gpa, "config t\n");
    try testing.expectError(error.MemoryLimitExceeded, uci.parse(gpa, buf.items));

    // 1 section + the first entry (2) + 299997 more = 300000; one more is over
    buf.clearRetainingCapacity();
    try buf.appendSlice(gpa, "config t\nlist l 'a'\n");
    try repeat(gpa, &buf, "list l 'a'\n", uci.max_total_items - 3);
    var pkg2 = try uci.parse(gpa, buf.items);
    pkg2.deinit(gpa);
    try buf.appendSlice(gpa, "list l 'a'\n");
    try testing.expectError(error.MemoryLimitExceeded, uci.parse(gpa, buf.items));
}

test "mutation 2026-11-27: a script is charged one item per command and one per word" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try repeat(gpa, &buf, "a\n", uci.max_total_items / 2); // 2 items each: exactly the cap
    var sc = try uci.parseScript(gpa, buf.items, null);
    try testing.expectEqual(uci.max_total_items / 2, sc.commands.len);
    sc.deinit(gpa);
    try buf.appendSlice(gpa, "a\n");
    var diag: uci.Diagnostics = .{};
    try testing.expectError(error.MemoryLimitExceeded, uci.parseScript(gpa, buf.items, &diag));
    try testing.expectEqual(uci.max_total_items / 2 + 1, diag.line);
}

test "mutation 2026-11-27: parseScript skips comment and separator lines, cuts a command at # and at ;, takes at most 8 words" {
    const gpa = testing.allocator;
    var sc = try uci.parseScript(gpa, "# only a comment\n; whatever\nset a.b.c=1 # note\nset a.b.d=2; set a.b.e=3\n", null);
    defer sc.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), sc.commands.len);
    try testing.expectEqual(@as(usize, 2), sc.commands[0].len);
    try testing.expectEqualStrings("set", sc.commands[0][0]);
    try testing.expectEqualStrings("a.b.c=1", sc.commands[0][1]);
    try testing.expectEqual(@as(usize, 2), sc.commands[1].len);
    try testing.expectEqualStrings("a.b.d=2", sc.commands[1][1]);

    var eight = try uci.parseScript(gpa, "a b c d e f g h\n", null);
    try testing.expectEqual(@as(usize, 8), eight.commands[0].len);
    eight.deinit(gpa);
    var diag: uci.Diagnostics = .{};
    try testing.expectError(error.TooManyArguments, uci.parseScript(gpa, "a\na b c d e f g h i\n", &diag));
    try testing.expectEqual(@as(usize, 2), diag.line);
}

// ── serializer ──────────────────────────────────────────────────────────────

test "mutation 2026-11-27: serialize is exact at max_input_len and refuses one byte more" {
    const gpa = testing.allocator;
    // 1029 options with distinct keys and 16300-byte values (a line of 16317
    // bytes); the last value is trimmed so that the text is exactly
    // max_input_len bytes
    const n = 1029;
    var keys: [n][8]u8 = undefined;
    var opts: [n]uci.Option = undefined;
    const filler = try gpa.alloc(u8, 16_400);
    defer gpa.free(filler);
    @memset(filler, 'v');
    var vals: [n][1][]const u8 = undefined;
    for (0..n) |i| {
        const k = std.fmt.bufPrint(&keys[i], "k{d:0>5}", .{i}) catch unreachable;
        vals[i] = .{filler[0..16_300]};
        opts[i] = .{ .key = k, .kind = .single, .values = &vals[i] };
    }
    const secs = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts }};
    var pkg: uci.Package = .{ .sections = &secs };
    const probe = try uci.serializeUnchecked(gpa, &pkg);
    const base_len = probe.len;
    gpa.free(probe);
    // adjust the last value by the difference to max_input_len (grows or shrinks)
    const want: i64 = @as(i64, @intCast(max_input)) - @as(i64, @intCast(base_len)) + 16_300;
    try testing.expect(want > 0 and want <= filler.len);
    vals[n - 1] = .{filler[0..@intCast(want)]};
    const text = try uci.serialize(gpa, &pkg);
    try testing.expectEqual(max_input, text.len);
    gpa.free(text);
    vals[n - 1] = .{filler[0..@intCast(want + 1)]};
    try testing.expectError(error.OutputTooLarge, uci.serialize(gpa, &pkg));
}

test "mutation 2026-11-27: a CR before LF inside a value is not counted into max_line_len when serializing" {
    const gpa = testing.allocator;
    const head = "\toption k '".len;
    const first = try gpa.alloc(u8, max_line - head + 2);
    defer gpa.free(first);
    @memset(first, 'a');
    // physical line 1 = "\toption k '" + (max_line - head) bytes of 'a', then CR (not counted) and LF
    first[max_line - head] = '\r';
    first[max_line - head + 1] = '\n';
    const value = try std.mem.concat(gpa, u8, &.{ first, "z" });
    defer gpa.free(value);
    const opts = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{value} }};
    const secs = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts }};
    const pkg: uci.Package = .{ .sections = &secs };
    const text = try uci.serialize(gpa, &pkg);
    defer gpa.free(text);
    // and the text reads back as the same value (a CR inside quotes is kept)
    var back = try uci.parse(gpa, text);
    defer back.deinit(gpa);
    try testing.expectEqualStrings(value, back.sections[0].get("k").?);
    // one 'a' more makes the line too long
    const longer = try std.mem.concat(gpa, u8, &.{ "a", first, "z" });
    defer gpa.free(longer);
    const opts2 = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{longer} }};
    const secs2 = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts2 }};
    const pkg2: uci.Package = .{ .sections = &secs2 };
    try testing.expectError(error.OutputTooLarge, uci.serialize(gpa, &pkg2));
}

test "mutation 2026-11-27: serialize refuses a type with a space or DEL, an empty name and a name with a dash" {
    const mk = struct {
        fn run(ty: []const u8, name: ?[]const u8) !void {
            const secs = [_]uci.Section{.{ .type = ty, .name = name, .anonymous = name == null, .options = &.{} }};
            const pkg: uci.Package = .{ .sections = &secs };
            const text = try uci.serialize(testing.allocator, &pkg);
            testing.allocator.free(text);
        }
    }.run;
    try testing.expectError(error.InvalidName, mk("a b", null));
    try testing.expectError(error.InvalidName, mk("a\x7f", null));
    try testing.expectError(error.InvalidName, mk("t", ""));
    try testing.expectError(error.InvalidName, mk("t", "a-b"));
    try mk("t", "a_b");
}

test "mutation 2026-11-27: a type with a dash is written bare; an empty package name is written as ''" {
    const gpa = testing.allocator;
    const secs = [_]uci.Section{.{ .type = "wifi-iface", .name = null, .anonymous = true, .options = &.{} }};
    const pkg: uci.Package = .{ .sections = &secs };
    const text = try uci.serialize(gpa, &pkg);
    defer gpa.free(text);
    try testing.expectEqualStrings("config wifi-iface\n", text);

    const named: uci.Package = .{ .name = "", .sections = &secs };
    const t2 = try uci.serialize(gpa, &named);
    defer gpa.free(t2);
    try testing.expect(std.mem.startsWith(u8, t2, "package ''\n"));
    var back = try uci.parse(gpa, t2); // the header must read back
    back.deinit(gpa);
}

// ── editor ──────────────────────────────────────────────────────────────────

fn editorOf(gpa: std.mem.Allocator, text: []const u8) !uci.Editor {
    var pkg = try uci.parse(gpa, text);
    defer pkg.deinit(gpa);
    return uci.Editor.init(gpa, &pkg);
}

test "mutation 2026-11-27: the editor keeps the package name; an empty or unterminated reference names nothing" {
    const gpa = testing.allocator;
    var pkg = try uci.parse(gpa, "config t 'a'\n");
    defer pkg.deinit(gpa);
    pkg.name = "pk";
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    var out = try ed.toPackage(gpa);
    defer out.deinit(gpa);
    try testing.expectEqualStrings("pk", out.name.?);

    try testing.expect(ed.find("") == null);
    try testing.expect(ed.find("@t[0x") == null);
    try testing.expectEqual(@as(?usize, 0), ed.find("@t[0]"));
    try testing.expectError(error.NoSuchSection, ed.set("", "k", "v"));
}

test "mutation 2026-11-27: a replayed add checks its type and its id; addList and renameOption check the key" {
    const gpa = testing.allocator;
    var ed = try editorOf(gpa, "config t 'a'\n\toption k 'v'\n");
    defer ed.deinit();
    var diag: uci.Diagnostics = .{};
    try testing.expectError(error.InvalidName, ed.applyDelta("p", "+p.x1='a b'\n", &diag));
    try testing.expectError(error.InvalidName, ed.applyDelta("p", "+p.a-b='t'\n", &diag));
    try testing.expectError(error.InvalidName, ed.addList("a", "bad-key", "v"));
    try testing.expectError(error.InvalidName, ed.renameOption("a", "k", "bad-key"));
}

test "mutation 2026-11-27: deleting the list entry one past the end is a no-op" {
    const gpa = testing.allocator;
    var ed = try editorOf(gpa, "config t 'a'\n\tlist l 'x'\n\tlist l 'y'\n");
    defer ed.deinit();
    try ed.deleteListItem("a", "l", 2);
    var out = try ed.toPackage(gpa);
    defer out.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), out.sections[0].getList("l").len);
    try ed.deleteListItem("a", "l", 1);
    var out2 = try ed.toPackage(gpa);
    defer out2.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), out2.sections[0].getList("l").len);
}

test "mutation 2026-11-27: renaming a section or an option to its own name makes no duplicate" {
    const gpa = testing.allocator;
    var ed = try editorOf(gpa, "config t 'x'\nconfig t 'y'\n\toption k '1'\n");
    defer ed.deinit();
    try ed.rename("x", "x");
    try testing.expect(!ed.dups);
    try ed.renameOption("y", "k", "k");
    try testing.expect(!ed.dups);
    try ed.rename("y", "x"); // a real clash of one type: `uci` holds both
    try testing.expect(ed.dups);
}

test "mutation 2026-11-27: a delta of exactly max_input_len bytes is replayed, one byte more is BadDelta at line 0" {
    const gpa = testing.allocator;
    var ed = try editorOf(gpa, "config t 'a'\n");
    defer ed.deinit();
    const big = try gpa.alloc(u8, max_input + 1);
    defer gpa.free(big);
    @memset(big, '\n');
    try ed.applyDelta("p", big[0..max_input], null);
    var diag: uci.Diagnostics = .{ .line = 9 };
    try testing.expectError(error.BadDelta, ed.applyDelta("p", big, &diag));
    try testing.expectEqual(@as(usize, 0), diag.line);
}

test "mutation 2026-11-27: the last delta record needs no trailing newline" {
    const gpa = testing.allocator;
    var ed = try editorOf(gpa, "config t 'a'\nconfig t 'b'\n");
    defer ed.deinit();
    try ed.applyDelta("p", "p.a.k='v'", null); // a set, value quoted, input ends there
    try ed.applyDelta("p", "-p.b", null); // a delete, input ends in the path
    try ed.applyDelta("p", "p.a.j=w", null); // an unquoted value up to the end
    var out = try ed.toPackage(gpa);
    defer out.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), out.sections.len);
    try testing.expectEqualStrings("v", out.sections[0].get("k").?);
    try testing.expectEqualStrings("w", out.sections[0].get("j").?);
}

fn emptySections(gpa: std.mem.Allocator, n: usize) ![]uci.Section {
    const secs = try gpa.alloc(uci.Section, n);
    @memset(secs, .{ .type = "t", .name = null, .anonymous = true, .options = &.{} });
    return secs;
}

test "mutation 2026-11-27: toPackage counts sections, options and values against max_total_items, on both paths" {
    const gpa = testing.allocator;
    const secs = try emptySections(gpa, uci.max_total_items + 1);
    defer gpa.free(secs);
    inline for (.{ false, true }) |merged| {
        // exactly the cap: fine
        const at_cap: uci.Package = .{ .sections = secs[0..uci.max_total_items] };
        var ed = try uci.Editor.init(gpa, &at_cap);
        ed.dups = merged;
        var ok = try ed.toPackage(gpa);
        try testing.expectEqual(uci.max_total_items, ok.sections.len);
        ok.deinit(gpa);
        ed.deinit();
        // one more: refused
        const over: uci.Package = .{ .sections = secs };
        var ed2 = try uci.Editor.init(gpa, &over);
        defer ed2.deinit();
        ed2.dups = merged;
        try testing.expectError(error.MemoryLimitExceeded, ed2.toPackage(gpa));
    }
}

test "mutation 2026-11-27: toPackage counts the values of a list against max_total_items, on both paths" {
    const gpa = testing.allocator;
    // 1 section + 1 option + (cap - 2) values = cap items; one more value is over
    const vals = try gpa.alloc([]const u8, uci.max_total_items - 1);
    defer gpa.free(vals);
    @memset(vals, "v");
    inline for (.{ false, true }) |merged| {
        const opt_at = [_]uci.Option{.{ .key = "l", .kind = .list, .values = vals[0 .. uci.max_total_items - 2] }};
        const sec_at = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opt_at }};
        const at_cap: uci.Package = .{ .sections = &sec_at };
        var ed = try uci.Editor.init(gpa, &at_cap);
        ed.dups = merged;
        var ok = try ed.toPackage(gpa);
        try testing.expectEqual(uci.max_total_items - 2, ok.sections[0].getList("l").len);
        ok.deinit(gpa);
        ed.deinit();
        const opt_over = [_]uci.Option{.{ .key = "l", .kind = .list, .values = vals }};
        const sec_over = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opt_over }};
        const over: uci.Package = .{ .sections = &sec_over };
        var ed2 = try uci.Editor.init(gpa, &over);
        defer ed2.deinit();
        ed2.dups = merged;
        try testing.expectError(error.MemoryLimitExceeded, ed2.toPackage(gpa));
    }
}

test "mutation 2026-11-27: after a rename clash, one key of two kinds is DuplicateOption; an anonymous section stays anonymous" {
    const gpa = testing.allocator;
    var ed = try editorOf(gpa, "config t 'x'\n\toption k '1'\nconfig t 'y'\n\tlist k 'a'\n");
    defer ed.deinit();
    try ed.rename("y", "x");
    try testing.expectError(error.DuplicateOption, ed.toPackage(gpa));

    var ed2 = try editorOf(gpa, "config t 'x'\n\toption k '1'\nconfig t 'y'\n\toption k '2'\nconfig t\n\toption z '3'\n");
    defer ed2.deinit();
    try ed2.rename("y", "x");
    var out = try ed2.toPackage(gpa);
    defer out.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), out.sections.len);
    try testing.expectEqualStrings("x", out.sections[0].name.?);
    try testing.expectEqualStrings("2", out.sections[0].get("k").?); // a later single value replaces the earlier
    try testing.expect(out.sections[1].name == null);
    try testing.expect(out.sections[1].anonymous);
    try testing.expect(!out.sections[0].anonymous);
}

test "mutation 2026-11-27: a package name with DEL cannot be a delta record's package part" {
    try testing.expect(!@import("diff.zig").deltaNameOk("a\x7fb"));
    try testing.expect(@import("diff.zig").deltaNameOk("a_b-c"));
}

// ── file layer ──────────────────────────────────────────────────────────────

const base_conf = "config iface 'lan'\n\toption proto 'static'\n\tlist dns '1.1.1.1'\n\tlist dns '8.8.8.8'\n\n" ++
    "config rule\n\toption name 'r0'\n";

const Fx = struct {
    tmp: std.testing.TmpDir,
    conf: std.Io.Dir,
    save: std.Io.Dir,

    fn init() !Fx {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        try tmp.dir.createDir(testing.io, "conf", .default_dir);
        try tmp.dir.createDir(testing.io, "save", .default_dir);
        return .{
            .tmp = tmp,
            .conf = try tmp.dir.openDir(testing.io, "conf", .{ .iterate = true }),
            .save = try tmp.dir.openDir(testing.io, "save", .{ .iterate = true }),
        };
    }
    fn deinit(self: *Fx) void {
        self.conf.close(testing.io);
        self.save.close(testing.io);
        self.tmp.cleanup();
    }
    fn store(self: *const Fx) uci.Store {
        return .{ .io = testing.io, .conf = self.conf, .save = self.save };
    }
    fn put(self: *const Fx, dir: std.Io.Dir, name: []const u8, data: []const u8) !void {
        _ = self;
        try dir.writeFile(testing.io, .{ .sub_path = name, .data = data });
    }
    fn read(self: *const Fx, dir: std.Io.Dir, name: []const u8) ![]u8 {
        _ = self;
        return dir.readFileAlloc(testing.io, name, testing.allocator, .limited(1 << 22));
    }
    /// Entries of `dir` whose name starts with `prefix`.
    fn count(self: *const Fx, dir: std.Io.Dir, prefix: []const u8) !usize {
        _ = self;
        var d = try dir.openDir(testing.io, ".", .{ .iterate = true });
        defer d.close(testing.io);
        var it = d.iterate();
        var n: usize = 0;
        while (try it.next(testing.io)) |e| {
            if (std.mem.startsWith(u8, e.name, prefix)) n += 1;
        }
        return n;
    }
};

test "mutation 2026-11-27: a file of exactly max_bytes loads, one byte more is FileTooLarge" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    var st = fx.store();
    st.options.max_bytes = 100;
    var ok: [100]u8 = @splat('x');
    ok[0] = '#';
    ok[99] = '\n';
    try fx.put(fx.conf, "net", &ok);
    var pkg = try st.load(gpa, "net", null);
    pkg.deinit(gpa);
    var big: [101]u8 = @splat('x');
    big[0] = '#';
    big[100] = '\n';
    try fx.put(fx.conf, "big", &big);
    try testing.expectError(error.FileTooLarge, st.load(gpa, "big", null));
}

test "mutation 2026-11-27: stagedPackages lists the regular files with a valid name and a non-empty delta, sorted" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    const st = fx.store();
    try fx.put(fx.save, "c", "c.x.y='1'\n");
    try fx.put(fx.save, "a", "a.x.y='1'\n");
    try fx.put(fx.save, "b", "b.x.y='1'\n");
    try fx.put(fx.save, "empty", "");
    try fx.put(fx.save, "bad name", "x.y.z='1'\n");
    try fx.save.createDir(testing.io, "dirpkg", .default_dir);
    const names = try st.stagedPackages(gpa);
    defer {
        for (names) |n| gpa.free(n);
        gpa.free(names);
    }
    try testing.expectEqual(@as(usize, 3), names.len);
    try testing.expectEqualStrings("a", names[0]);
    try testing.expectEqualStrings("b", names[1]);
    try testing.expectEqualStrings("c", names[2]);
}

test "mutation 2026-11-27: loadView refuses an invalid name even when the override directory has a file of that name" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    var st = fx.store();
    st.override = fx.save;
    try fx.put(fx.save, "a b", base_conf);
    try testing.expectError(error.InvalidPackageName, st.loadView(gpa, "a b", null));
}

test "mutation 2026-11-27: a bad name is refused before the file or the text is looked at" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    const st = fx.store();
    // a directory of that name would otherwise be NotRegularFile
    try fx.conf.createDir(testing.io, "a b", .default_dir);
    var pkg = try uci.parse(gpa, base_conf);
    defer pkg.deinit(gpa);
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    try testing.expectError(error.InvalidPackageName, st.commitEditor(gpa, "a b", &ed, null));
    try testing.expectError(error.InvalidPackageName, st.commitStaged(gpa, "a b", null));
    try testing.expectError(error.InvalidPackageName, st.replace(gpa, "a b", &pkg));
    try testing.expectError(error.InvalidPackageName, st.saveEditor(gpa, "a b", &ed));
    // and before the text is parsed
    try testing.expectError(error.InvalidPackageName, st.importText(gpa, "a b", "config 'unterminated", null));
}

test "mutation 2026-11-27: an existing package's commit reaps its stale temps on every entry point; a new package's does not" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    const st = fx.store();
    var pkg = try uci.parse(gpa, base_conf);
    defer pkg.deinit(gpa);
    var ed = try uci.Editor.init(gpa, &pkg);
    defer ed.deinit();
    try fx.put(fx.conf, "net", base_conf);
    const temp = ".net.uci-tmp-0123456789abcdef";

    try fx.put(fx.conf, temp, "stale");
    try st.commitEditor(gpa, "net", &ed, try st.stamp("net"));
    try testing.expectEqual(@as(usize, 0), try fx.count(fx.conf, ".net."));

    try fx.put(fx.conf, temp, "stale");
    try st.replace(gpa, "net", &pkg);
    try testing.expectEqual(@as(usize, 0), try fx.count(fx.conf, ".net."));

    try fx.put(fx.conf, temp, "stale");
    try fx.put(fx.save, "net", "net.lan.proto='dhcp'\n");
    try st.commitStaged(gpa, "net", null);
    try testing.expectEqual(@as(usize, 0), try fx.count(fx.conf, ".net."));

    // a package with no file yet has no lock: a temp there may be another creator's live one
    try fx.put(fx.conf, ".newa.uci-tmp-0123456789abcdef", "live");
    try st.commitEditor(gpa, "newa", &ed, null);
    try testing.expectEqual(@as(usize, 1), try fx.count(fx.conf, ".newa."));
    try fx.put(fx.conf, ".newb.uci-tmp-0123456789abcdef", "live");
    try st.replace(gpa, "newb", &pkg);
    try testing.expectEqual(@as(usize, 1), try fx.count(fx.conf, ".newb."));
}

test "mutation 2026-11-27: a delta of exactly max_bytes is saved, one byte under it is FileTooLarge" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    const st = fx.store();
    const big: [400]u8 = @splat('x');
    var script: [512]u8 = undefined;
    const set_big = try std.fmt.bufPrint(&script, "set net.lan.big={s}\n", .{big});
    var s = uci.Session.init(gpa, st);
    defer s.deinit();
    try s.run(set_big, .{}, null, null);
    try s.save("net");
    const delta = (try st.staged(gpa, "net")).?;
    const delta_len = delta.len;
    gpa.free(delta);
    try testing.expect(delta_len > base_conf.len); // so a cap of that size still reads the config
    try fx.save.deleteFile(testing.io, "net");

    var tight = st;
    tight.options.max_bytes = delta_len;
    var s2 = uci.Session.init(gpa, tight);
    defer s2.deinit();
    try s2.run(set_big, .{}, null, null);
    try s2.save("net"); // exactly the cap
    try fx.save.deleteFile(testing.io, "net");

    tight.options.max_bytes = delta_len - 1;
    var s3 = uci.Session.init(gpa, tight);
    defer s3.deinit();
    try s3.run(set_big, .{}, null, null);
    try testing.expectError(error.FileTooLarge, s3.save("net"));
}

test "mutation 2026-11-27: a new delta file is created 0644" {
    var fx = try Fx.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    var s = uci.Session.init(testing.allocator, fx.store());
    defer s.deinit();
    try s.run("set net.lan.a=1\n", .{}, null, null);
    try s.save("net");
    const sst = try fx.save.statFile(testing.io, "net", .{});
    try testing.expectEqual(@as(u32, 0o644), @as(u32, @intCast(@backingInt(sst.permissions))) & 0o777);
}

test "mutation 2026-11-27: a commit accepts a physical line of exactly max_line_len" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    const st = fx.store();
    // "\toption k '" is 11 bytes and the closing quote one more
    const v = try gpa.alloc(u8, max_line - 12);
    defer gpa.free(v);
    @memset(v, 'v');
    const opts = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{v} }};
    const secs = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts }};
    const pkg: uci.Package = .{ .sections = &secs };
    try st.replace(gpa, "net", &pkg);
    var back = try st.load(gpa, "net", null);
    defer back.deinit(gpa);
    try testing.expectEqual(v.len, back.sections[0].get("k").?.len);
    // one byte more cannot be read back
    const v2 = try gpa.alloc(u8, max_line - 11);
    defer gpa.free(v2);
    @memset(v2, 'v');
    const opts2 = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{v2} }};
    const secs2 = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts2 }};
    const pkg2: uci.Package = .{ .sections = &secs2 };
    try testing.expectError(error.WouldNotReload, st.replace(gpa, "net2", &pkg2));
}

// ── session ─────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: commit <pkg> writes that package only" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    try fx.put(fx.conf, "a", base_conf);
    try fx.put(fx.conf, "b", base_conf);
    var s = uci.Session.init(gpa, fx.store());
    defer s.deinit();
    try s.run("set a.lan.x=1\nset b.lan.x=1\ncommit a\n", .{}, null, null);
    const fa = try fx.read(fx.conf, "a");
    defer gpa.free(fa);
    const fb = try fx.read(fx.conf, "b");
    defer gpa.free(fb);
    try testing.expect(std.mem.indexOf(u8, fa, "option x") != null);
    try testing.expect(std.mem.indexOf(u8, fb, "option x") == null);
}

test "mutation 2026-11-27: the work budget: spent beyond the cap ends a run after a free command; spent at the cap does not stop a charged one before it runs" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    try fx.put(fx.conf, "a", base_conf);
    var s = uci.Session.init(gpa, fx.store());
    defer s.deinit();
    var rep: uci.RunReport = .{};
    s.spent = edit.max_delta_work + 1;
    try testing.expectError(error.WorkLimitExceeded, s.run("add a iface\n", .{ .keep_going = true }, &rep, null));
    try testing.expectEqual(@as(usize, 1), rep.executed); // it ran, then the budget ended the run
    s.resetBudget();
    s.spent = edit.max_delta_work;
    var rep2: uci.RunReport = .{};
    try testing.expectError(error.WorkLimitExceeded, s.run("set a.lan.x=1\n", .{}, &rep2, null));
    try testing.expectEqual(@as(usize, 1), rep2.executed); // "more than" the cap is needed to refuse it up front
}

test "mutation 2026-11-27: an allocation failure is never counted as a failing line, even with keep_going" {
    var fx = try Fx.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    const st = fx.store();
    var i: usize = 0;
    while (i < 600) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        var s = uci.Session.init(fa.allocator(), st);
        defer s.deinit();
        var rep: uci.RunReport = .{};
        if (s.run("set net.lan.a=1\nset net.lan.b=2\nadd net rule\n", .{ .keep_going = true }, &rep, null)) |_| {
            try testing.expectEqual(@as(usize, 0), rep.failed);
            if (!fa.has_induced_failure) break;
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
    }
    try testing.expect(i < 600);
}

fn sectionFile(gpa: std.mem.Allocator, n: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    try repeat(gpa, &buf, "config t\n", n);
    return buf.toOwnedSlice(gpa);
}

test "mutation 2026-11-27: a session may hold exactly max_session_items, not one more" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    const text = try sectionFile(gpa, uci.max_total_items);
    defer gpa.free(text);
    try fx.put(fx.conf, "a", text);
    try fx.put(fx.conf, "b", text);
    try fx.put(fx.conf, "c", "config t\n");
    var s = uci.Session.init(gpa, fx.store());
    defer s.deinit();
    _ = try s.editor("a");
    _ = try s.editor("b"); // 2 * 300000 = the session cap, not over it
    try testing.expectError(error.MemoryLimitExceeded, s.editor("c"));
}

test "mutation 2026-11-27: merge checks every name, key and the item cap before it changes anything" {
    const gpa = testing.allocator;
    var ed = try editorOf(gpa, "config t 'n0'\n");
    defer ed.deinit();
    const bad_name = [_]uci.Section{
        .{ .type = "t", .name = "n1", .anonymous = false, .options = &.{} },
        .{ .type = "t", .name = "", .anonymous = false, .options = &.{} },
    };
    try testing.expectError(error.InvalidName, uci.merge(&ed, &.{ .sections = &bad_name }));
    try testing.expect(ed.find("n1") == null);
    const bad_opts = [_]uci.Option{.{ .key = "", .kind = .single, .values = &.{"v"} }};
    const bad_key = [_]uci.Section{.{ .type = "t", .name = "n2", .anonymous = false, .options = &bad_opts }};
    try testing.expectError(error.InvalidName, uci.merge(&ed, &.{ .sections = &bad_key }));
    try testing.expect(ed.find("n2") == null);
}

test "mutation 2026-11-27: merge counts one item for every option, so the cap is exact and a refusal changes nothing" {
    const gpa = testing.allocator;
    const vals = try gpa.alloc([]const u8, uci.max_total_items - 1);
    defer gpa.free(vals);
    @memset(vals, "v");
    // 1 section + 1 option + (cap - 2) values = cap items: fits an empty editor
    var ed = try editorOf(gpa, "");
    defer ed.deinit();
    const opt_ok = [_]uci.Option{.{ .key = "l", .kind = .list, .values = vals[0 .. uci.max_total_items - 2] }};
    const sec_ok = [_]uci.Section{.{ .type = "t", .name = "s", .anonymous = false, .options = &opt_ok }};
    try uci.merge(&ed, &.{ .sections = &sec_ok });
    try testing.expect(ed.find("s") != null);
    // one value more does not, and "s" must not be there afterwards
    var ed2 = try editorOf(gpa, "");
    defer ed2.deinit();
    const opt_over = [_]uci.Option{.{ .key = "l", .kind = .list, .values = vals }};
    const sec_over = [_]uci.Section{.{ .type = "t", .name = "s", .anonymous = false, .options = &opt_over }};
    try testing.expectError(error.MemoryLimitExceeded, uci.merge(&ed2, &.{ .sections = &sec_over }));
    try testing.expect(ed2.find("s") == null);
}

// ── file layer: names and links with allow_paths ────────────────────────────

test "mutation 2026-11-27: allow_paths accepts a name of 255 bytes; an absolute link target is refused" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    var st = fx.store();
    st.options.allow_paths = true;
    const long_buf: [255]u8 = @splat('a');
    try testing.expectError(error.PackageNotFound, st.load(gpa, &long_buf, null));
    // a link to an absolute path leaves the directory, with allow_paths too (a relative one is followed)
    try fx.conf.symLink(testing.io, "/etc/passwd", "abs", .{});
    try testing.expectError(error.NotRegularFile, st.load(gpa, "abs", null));
}

test "mutation 2026-11-27: a relative link with a directory part is resolved against the link's directory" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    var st = fx.store();
    st.options.allow_paths = true;
    try fx.conf.createDir(testing.io, "sub", .default_dir);
    try fx.conf.createDir(testing.io, "sub/d", .default_dir);
    try fx.put(fx.conf, "sub/d/f", base_conf);
    try fx.conf.symLink(testing.io, "d/f", "sub/lnk", .{});
    var pkg = try st.load(gpa, "sub/lnk", null);
    defer pkg.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), pkg.sections.len);
}

// ── session and merge ───────────────────────────────────────────────────────

test "mutation 2026-11-27: a command without = is BadCommand before any package is opened; the work cap is 'more than'" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    try fx.put(fx.conf, "a", base_conf);
    var s = uci.Session.init(gpa, fx.store());
    defer s.deinit();
    try testing.expectError(error.BadCommand, s.run("set nopkg.sec\n", .{}, null, null));
    try testing.expectError(error.BadCommand, s.run("add_list nopkg.sec.key\n", .{}, null, null));
    try testing.expectError(error.BadCommand, s.run("rename nopkg.sec\n", .{}, null, null));
    // exactly at the cap a free command is fine
    s.spent = edit.max_delta_work;
    try s.run("add a iface\n", .{}, null, null);
}

test "mutation 2026-11-27: merge refuses an empty section type before it changes anything" {
    const gpa = testing.allocator;
    var ed = try editorOf(gpa, "config t 'n0'\n");
    defer ed.deinit();
    const secs = [_]uci.Section{
        .{ .type = "t", .name = "n1", .anonymous = false, .options = &.{} },
        .{ .type = "", .name = "n3", .anonymous = false, .options = &.{} },
    };
    try testing.expectError(error.InvalidName, uci.merge(&ed, &.{ .sections = &secs }));
    try testing.expect(ed.find("n1") == null);
}

test "mutation 2026-11-27: save of a list emptied by del_list works, and the reload sees no such option" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    try fx.put(fx.conf, "net", base_conf);
    const st = fx.store();
    var s = uci.Session.init(gpa, st);
    defer s.deinit();
    try s.run("del_list net.lan.dns=1.1.1.1\ndel_list net.lan.dns=8.8.8.8\n", .{}, null, null);
    try s.save("net");
    var s2 = uci.Session.init(gpa, st);
    defer s2.deinit();
    const ed = try s2.editor("net");
    var out = try ed.toPackage(gpa);
    defer out.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), out.sections[0].getList("dns").len);
}

// ── diffRecords ─────────────────────────────────────────────────────────────

fn diffText(gpa: std.mem.Allocator, from_text: []const u8, to: *const uci.Editor, from: *const uci.Editor) ![]u8 {
    _ = from_text;
    return uci.diffRecords(gpa, from, to, "p", null);
}

test "mutation 2026-11-27: a change of kind with the same values is a record; an emptied list is deleted once; the first of two equal keys is the one compared" {
    const gpa = testing.allocator;
    // list -> single, same value
    var from = try editorOf(gpa, "config t 'x'\n\tlist l 'a'\n");
    defer from.deinit();
    var to = try editorOf(gpa, "config t 'x'\n\tlist l 'a'\n");
    defer to.deinit();
    try to.set("x", "l", "a");
    const r1 = try diffText(gpa, "", &to, &from);
    defer gpa.free(r1);
    try testing.expectEqualStrings("p.x.l='a'\n", r1);

    // a list emptied by del_list: one delete record
    var to2 = try editorOf(gpa, "config t 'x'\n\tlist l 'a'\n");
    defer to2.deinit();
    try to2.delList("x", "l", "a");
    const r2 = try diffText(gpa, "", &to2, &from);
    defer gpa.free(r2);
    try testing.expectEqualStrings("-p.x.l\n", r2);

    // two options of one key (a rename clash): the first one is the one the lookups answer
    var dup = try editorOf(gpa, "config t 'x'\n\toption a '1'\n\toption b '2'\n");
    defer dup.deinit();
    try dup.renameOption("x", "b", "a");
    var one = try editorOf(gpa, "config t 'x'\n\toption a '1'\n");
    defer one.deinit();
    const r3 = try diffText(gpa, "", &one, &dup);
    defer gpa.free(r3);
    try testing.expectEqualStrings("", r3);
}

test "mutation 2026-11-27: a named section called like an anonymous one's id: replaying the diff gives the target order" {
    const gpa = testing.allocator;
    var from = try editorOf(gpa, "config t\nconfig u 'b'\n");
    defer from.deinit();
    const id = from.sections.items[0].id;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    try text.print(gpa, "config t '{s}'\nconfig u 'b'\n", .{id});
    var to = try editorOf(gpa, text.items);
    defer to.deinit();
    // make the order differ as well: the named one goes last
    try to.reorder(id, 5);
    const recs = try uci.diffRecords(gpa, &from, &to, "p", null);
    defer gpa.free(recs);
    // the created section lands last by itself: no reorder record is needed
    try testing.expect(std.mem.indexOfScalar(u8, recs, '^') == null);
    try from.applyDelta("p", recs, null);
    var got = try from.toPackage(gpa);
    defer got.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), got.sections.len);
    try testing.expectEqualStrings("b", got.sections[0].name.?);
    try testing.expectEqualStrings(id, got.sections[1].name.?);
}

test "mutation 2026-11-27: deltaNameOk refuses the empty name and a control byte" {
    const d = @import("diff.zig");
    try testing.expect(!d.deltaNameOk(""));
    try testing.expect(!d.deltaNameOk("a\x01b"));
    try testing.expect(!d.deltaNameOk("a\nb"));
}

test "mutation 2026-11-27: commit(null) reloads an open package it committed from its staged delta" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    try fx.put(fx.conf, "a", base_conf);
    try fx.put(fx.save, "a", "a.lan.x='1'\n");
    var s = uci.Session.init(gpa, fx.store());
    defer s.deinit();
    _ = try s.editor("a"); // loaded with the delta, not dirty
    try s.commit(null); // writes the staged delta of a, empties it
    // the editor must have followed the file: its stamp is the new file's, so this commit is not ChangedOnDisk
    try s.run("set a.lan.y=2\ncommit a\n", .{}, null, null);
    const f = try fx.read(fx.conf, "a");
    defer gpa.free(f);
    try testing.expect(std.mem.indexOf(u8, f, "option y") != null);
    try testing.expect(std.mem.indexOf(u8, f, "option x") != null);
}

test "Store.replace applies parse's line rule: a CR before LF is not counted, one byte more is WouldNotReload (FIX 2026-11-27)" {
    const gpa = testing.allocator;
    var fx = try Fx.init();
    defer fx.deinit();
    const st = fx.store();
    try fx.put(fx.conf, "p", "");
    const head = "\toption k '".len;
    const first = try gpa.alloc(u8, max_line - head + 2);
    defer gpa.free(first);
    @memset(first, 'a');
    first[max_line - head] = '\r';
    first[max_line - head + 1] = '\n';
    // At the limit: serialize and parse accept it, so replace must too (it refused before the fix).
    const value = try std.mem.concat(gpa, u8, &.{ first, "z" });
    defer gpa.free(value);
    const opts = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{value} }};
    const secs = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts }};
    const pkg: uci.Package = .{ .sections = &secs };
    try st.replace(gpa, "p", &pkg);
    var back = try st.load(gpa, "p", null);
    defer back.deinit(gpa);
    try testing.expectEqualStrings(value, back.sections[0].get("k").?);
    // One byte over: the reload check refuses it and the file is unchanged.
    const longer = try std.mem.concat(gpa, u8, &.{ "a", first, "z" });
    defer gpa.free(longer);
    const opts2 = [_]uci.Option{.{ .key = "k", .kind = .single, .values = &.{longer} }};
    const secs2 = [_]uci.Section{.{ .type = "t", .name = null, .anonymous = true, .options = &opts2 }};
    const pkg2: uci.Package = .{ .sections = &secs2 };
    try testing.expectError(error.WouldNotReload, st.replace(gpa, "p", &pkg2));
    const kept = try fx.read(fx.conf, "p");
    defer gpa.free(kept);
    try testing.expect(std.mem.indexOf(u8, kept, value) != null);
}

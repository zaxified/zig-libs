// SPDX-License-Identifier: MIT

//! Hand-written expectations for what `parse` is not: Editor, Document.write,
//! the pull readers, typed getters, lists, interpolation, struct mapping. The
//! foreign anchors for the same features are in `oracle_ext_test.zig`.

const std = @import("std");
const ini = @import("root.zig");
const testing = std.testing;
const gpa = testing.allocator;

fn expectEdited(ed: *const ini.Editor, want: []const u8) !void {
    const got = try ed.toOwnedSlice(gpa);
    defer gpa.free(got);
    try testing.expectEqualStrings(want, got);
}

fn expectUnchanged(text: []const u8, opts: ini.Options) !void {
    var ed = try ini.Editor.init(gpa, text, opts);
    defer ed.deinit();
    try expectEdited(&ed, text);
}

test "Editor unedited: every byte of the input comes back" {
    const texts = [_][]const u8{
        "",
        "\n",
        "\n\n",
        "[a]",
        "[a]\n",
        "[a]\r\nk = v\r\n",
        "\xEF\xBB\xBF[a]\nk=v",
        "# top\n\n  [a]  ; note\n   k   =  v   # c\n\n; end\n",
        "[a]\nk=v\n  more\n\tmore2  \n# c\n",
        "k=v\r\n[a]\n  x:y\n",
    };
    for (texts) |t| {
        try expectUnchanged(t, .{ .strict = false, .continuation_lines = true, .separators = "=:" });
    }
    try expectUnchanged("[a]\njunk\n=x\nk=v\n", .{ .strict = false });
    try expectUnchanged("[a]\nk=v\n\n# c\n  more\n\n", .configparser);
}

test "Editor: strict refuses what parse refuses, and says where" {
    var info: ini.ErrorInfo = .{};
    try testing.expectError(error.MissingSeparator, ini.Editor.initDiag(gpa, "[a]\nk=v\njunk\n", .{}, &info));
    try testing.expectEqual(@as(usize, 3), info.line);
}

test "Editor.set on an existing key keeps indentation, spacing, inline comment, line end" {
    var ed = try ini.Editor.init(gpa, "# top\n[a]\n   key   =   old   ; why\r\nother=1\n", .{ .inline_comments = true });
    defer ed.deinit();
    try ed.set("a", "key", "new");
    try expectEdited(&ed, "# top\n[a]\n   key   =   new   ; why\r\nother=1\n");
    try testing.expectEqualStrings("new", ed.get("a", "key").?);
}

test "Editor.set changes the occurrence get reads" {
    var ed = try ini.Editor.init(gpa, "[a]\nk=1\n[b]\nk=x\n[a]\nk=2\n", .{});
    defer ed.deinit();
    try ed.set("a", "k", "3");
    try expectEdited(&ed, "[a]\nk=1\n[b]\nk=x\n[a]\nk=3\n");
}

test "Editor.set of a new key follows the section's last entry and copies its look" {
    var ed = try ini.Editor.init(gpa, "[a]\n  x : 1\n\n# about b\n[b]\ny=2", .{ .separators = "=:" });
    defer ed.deinit();
    try ed.set("a", "z", "9");
    try ed.set("b", "w", "8");
    try expectEdited(&ed, "[a]\n  x : 1\n  z : 9\n\n# about b\n[b]\ny=2\nw=8\n");
}

test "Editor.set of a new section goes at the end, a blank line before it" {
    var ed = try ini.Editor.init(gpa, "[a]\nx=1", .{});
    defer ed.deinit();
    try ed.set("b", "k", "v");
    try expectEdited(&ed, "[a]\nx=1\n\n[b]\nk = v\n");

    var fresh = try ini.Editor.init(gpa, "", .desktop);
    defer fresh.deinit();
    try fresh.set("Desktop Entry", "Name", "x");
    try expectEdited(&fresh, "[Desktop Entry]\nName=x\n");
}

test "Editor: a CRLF file gets CRLF lines" {
    var ed = try ini.Editor.init(gpa, "[a]\r\nx=1\r\n", .python);
    defer ed.deinit();
    try ed.set("a", "m", "l1\nl2");
    try ed.set("b", "k", "v");
    try expectEdited(&ed, "[a]\r\nx=1\r\nm=l1\r\n\tl2\r\n\r\n[b]\r\nk = v\r\n");
    var doc = try ed.document(gpa);
    defer doc.deinit();
    try testing.expectEqualStrings("l1\nl2", doc.get("a", "m").?);
}

test "Editor: global entries go before the first header, after the preamble" {
    var ed = try ini.Editor.init(gpa, "# top\n[a]\nk=1\n", .{});
    defer ed.deinit();
    try ed.set("", "g", "1");
    try ed.set("", "h", "2");
    try expectEdited(&ed, "# top\ng = 1\nh = 2\n[a]\nk=1\n");
    try testing.expectEqualStrings("2", ed.get("", "h").?);
    try testing.expectEqual(@as(usize, 1), try ed.remove("", "g"));

    var strict_sections = try ini.Editor.init(gpa, "[a]\n", .python);
    defer strict_sections.deinit();
    try testing.expectError(error.NotRepresentable, strict_sections.set("", "g", "1"));
    try expectEdited(&strict_sections, "[a]\n");
}

test "Editor refuses what the dialect cannot say, and changes nothing" {
    const text = "[a]\nk=v\n";
    var ed = try ini.Editor.init(gpa, text, .{ .inline_comments = true });
    defer ed.deinit();
    const bad_values = [_][]const u8{ " lead", "trail ", "two\nlines", "x ; y", "cr\r" };
    for (bad_values) |v| {
        try testing.expectError(error.NotRepresentable, ed.set("a", "k", v));
        try testing.expectError(error.NotRepresentable, ed.set("a", "new", v));
        try testing.expectError(error.NotRepresentable, ed.set("new", "new", v));
    }
    const bad_keys = [_][]const u8{ "", " x", "x ", "a=b", "#c", ";c", "two\nlines" };
    for (bad_keys) |k| {
        try testing.expectError(error.NotRepresentable, ed.set("a", k, "v"));
        try testing.expectError(error.NotRepresentable, ed.set("new", k, "v"));
    }
    var py = try ini.Editor.init(gpa, "[a]\n", .python);
    defer py.deinit();
    try testing.expectError(error.NotRepresentable, py.set("a", "[h]", "v")); // reads as a header there
    try testing.expectError(error.NotRepresentable, ed.addSection("a\nb"));
    try testing.expectError(error.NotRepresentable, ed.addSection("a]"));
    try testing.expect(!ed.hasSection("new"));
    try expectEdited(&ed, text);
}

test "Editor.remove takes every occurrence; the next key's line is untouched" {
    var ed = try ini.Editor.init(gpa, "[a]\nk=1\nj=2\n[b]\n[a]\nk=3\n", .{});
    defer ed.deinit();
    try testing.expectEqual(@as(usize, 2), try ed.remove("a", "k"));
    try testing.expectEqual(@as(usize, 0), try ed.remove("a", "k"));
    try testing.expectEqual(@as(usize, 0), try ed.remove("zz", "k"));
    try testing.expect(ed.get("a", "k") == null);
    try ed.set("a", "m", "9"); // the anchor moved back to the last instance's header
    try expectEdited(&ed, "[a]\nj=2\n[b]\n[a]\nm = 9\n");
}

test "Editor.removeSection takes every instance and what they hold" {
    var ed = try ini.Editor.init(gpa, "[a]\nk=1\n# c\n\n[b]\nj=2\n[a]\nm=3\n", .{});
    defer ed.deinit();
    try testing.expect(try ed.removeSection("a"));
    try testing.expect(!try ed.removeSection("a"));
    try testing.expect(ed.get("a", "k") == null);
    try expectEdited(&ed, "[b]\nj=2\n");
    try ed.set("a", "k", "new"); // a new section of the old name has no old keys
    try expectEdited(&ed, "[b]\nj=2\n\n[a]\nk = new\n");
}

test "Editor keeps an indented line from turning into a continuation" {
    // `  [c]` is a header only because a header precedes it.
    var ed = try ini.Editor.init(gpa, "[a]\nk=v\n[b]\n  [c]\nz=1\n", .python);
    defer ed.deinit();
    try testing.expect(try ed.removeSection("b"));
    var doc = try ed.document(gpa);
    defer doc.deinit();
    try testing.expectEqualStrings("v", doc.get("a", "k").?);
    try testing.expectEqualStrings("1", doc.get("c", "z").?);
    // A comment was keeping these two apart.
    var e2 = try ini.Editor.init(gpa, "[a]\nk=v\n# c\n  j=w\n", .python);
    defer e2.deinit();
    try e2.setComment("a", "j", "");
    try expectEdited(&e2, "[a]\nk=v\nj=w\n");
    try testing.expectEqualStrings("w", e2.get("a", "j").?);
}

test "Editor: continued values" {
    var ed = try ini.Editor.init(gpa, "[a]\n  k = one\n      two  \nj=1\n", .python);
    defer ed.deinit();
    try testing.expectEqualStrings("one\ntwo", ed.get("a", "k").?);
    try ed.set("a", "k", "x\ny\nz");
    try expectEdited(&ed, "[a]\n  k = x\n  \ty\n  \tz  \nj=1\n");
    try ed.set("a", "k", "single");
    try expectEdited(&ed, "[a]\n  k = single  \nj=1\n");
    try testing.expectError(error.NotRepresentable, ed.set("a", "k", "a\n\nb")); // blank ends a value here
    try testing.expectError(error.NotRepresentable, ed.set("a", "k", "a\n# no"));
    try testing.expectError(error.NotRepresentable, ed.set("a", "k", "a\n"));

    var cp = try ini.Editor.init(gpa, "[a]\nk = x\n\n  y\n# c\n  z\nj=1\n", .configparser);
    defer cp.deinit();
    try testing.expectEqualStrings("x\n\ny\nz", cp.get("a", "k").?);
    try ini.Editor.set(&cp, "a", "j", "p\n\nq");
    try expectEdited(&cp, "[a]\nk = x\n\n  y\n# c\n  z\nj=p\n\t\n\tq\n");
}

test "Editor: comments above a key or a section" {
    var ed = try ini.Editor.init(gpa, "# about a\n; second\n[a]\n# about k\nk=1\n\n# detached\n\nj=2\n", .{});
    defer ed.deinit();
    const sec = (try ed.getComment(gpa, "a", null)).?;
    defer gpa.free(sec);
    try testing.expectEqualStrings("# about a\n; second", sec);
    const k = (try ed.getComment(gpa, "a", "k")).?;
    defer gpa.free(k);
    try testing.expectEqualStrings("# about k", k);
    const j = (try ed.getComment(gpa, "a", "j")).?;
    defer gpa.free(j);
    try testing.expectEqualStrings("", j);
    try testing.expect((try ed.getComment(gpa, "a", "absent")) == null);
    try testing.expect((try ed.getComment(gpa, "zz", null)) == null);

    try ed.setComment("a", "k", "new text\n; kept marker");
    try ed.setComment("a", null, "");
    try ed.setComment("a", "j", "#x");
    try testing.expectError(error.NotRepresentable, ed.setComment("a", "absent", "x"));
    try testing.expectError(error.NotRepresentable, ed.setComment("a", "j", "bad\r"));
    try expectEdited(&ed, "[a]\n# new text\n; kept marker\nk=1\n\n# detached\n\n#x\nj=2\n");
}

test "Editor: bare keys" {
    var ed = try ini.Editor.init(gpa, "[mysqld]\nskip-bdb\nport = 1\n", .{ .no_value_keys = true, .global_entries = false });
    defer ed.deinit();
    try testing.expectEqualStrings("", ed.get("mysqld", "skip-bdb").?);
    try ed.setNoValue("mysqld", "quick");
    try ed.setNoValue("mysqld", "port");
    try ed.set("mysqld", "skip-bdb", "1");
    try expectEdited(&ed, "[mysqld]\nskip-bdb = 1\nport\nquick\n");

    var no = try ini.Editor.init(gpa, "[a]\n", .{});
    defer no.deinit();
    try testing.expectError(error.NotRepresentable, no.setNoValue("a", "x"));
}

test "Editor: case-insensitive names and [DEFAULT]" {
    var ed = try ini.Editor.init(gpa, "[DEFAULT]\nd=1\n[A]\nKey=2\n", .{ .case_insensitive_sections = true, .case_insensitive_keys = true, .default_section = "default" });
    defer ed.deinit();
    try testing.expectEqualStrings("2", ed.get("a", "KEY").?);
    try testing.expectEqualStrings("1", ed.get("a", "D").?);
    try ed.set("a", "key", "3");
    try expectEdited(&ed, "[DEFAULT]\nd=1\n[A]\nKey=3\n");
    try testing.expectEqual(@as(usize, 0), try ed.remove("a", "d"));
}

test "Editor: every allocation of an edit session can fail without a leak" {
    const session = struct {
        fn run(a: std.mem.Allocator) !void {
            var ed = try ini.Editor.init(a, "# c\n[a]\nk=v\n  w\nj=1\n[b]\n", .python);
            defer ed.deinit();
            try ed.set("a", "k", "x\ny");
            try ed.set("a", "n", "1");
            try ed.set("c", "n", "1");
            _ = try ed.remove("a", "j");
            _ = try ed.removeSection("b");
            try ed.setComment("a", "k", "hello");
            const c = try ed.getComment(a, "a", "k");
            if (c) |x| a.free(x);
            const out = try ed.toOwnedSlice(a);
            a.free(out);
            var d = try ed.document(a);
            d.deinit();
        }
    };
    var counter = testing.FailingAllocator.init(gpa, .{});
    try session.run(counter.allocator());
    var i: usize = 0;
    while (i <= counter.alloc_index) : (i += 1) {
        var fa = testing.FailingAllocator.init(gpa, .{ .fail_index = i });
        session.run(fa.allocator()) catch |e| try testing.expectEqual(error.OutOfMemory, e);
    }
}

// ── Document.write ───────────────────────────────────────────────────────────

fn written(doc: *const ini.Document, o: ini.WriteOptions) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try doc.write(gpa, &out.writer, o);
    return out.toOwnedSlice();
}

test "Document.write: file order, or merged like configparser.write" {
    const text = "[a]\nk=1\nk=2\n[DEFAULT]\nd=x\n[a]\nm=l1\n  l2\n";
    var doc = try ini.parse(gpa, text, .configparser);
    defer doc.deinit();
    const all = try written(&doc, .{ .options = .configparser, .blank_after_section = false });
    defer gpa.free(all);
    try testing.expectEqualStrings("[a]\nk = 1\nk = 2\n[DEFAULT]\nd = x\n[a]\nm = l1\n\tl2\n", all);
    const merged = try written(&doc, .{ .options = .configparser, .merged = true });
    defer gpa.free(merged);
    try testing.expectEqualStrings("[DEFAULT]\nd = x\n\n[a]\nk = 2\nm = l1\n\tl2\n\n", merged);
}

test "Document.write: global entries have no header; a desktop file has no spaces" {
    var doc = try ini.parse(gpa, "top=1\n[a]\nk=v  \n", .{ .trim_values = false });
    defer doc.deinit();
    const out = try written(&doc, .{ .options = .{ .trim_values = false }, .blank_after_section = false, .eol = "\r\n" });
    defer gpa.free(out);
    try testing.expectEqualStrings("top=1\r\n[a]\r\nk=v  \r\n", out);
}

test "Document.write refuses what the target dialect would read differently" {
    var doc = try ini.parse(gpa, "[a]\nk=v ; c\n", .{});
    defer doc.deinit();
    var sink: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&sink);
    try testing.expectError(error.NotRepresentable, doc.write(gpa, &w, .{ .options = .{ .inline_comments = true } }));
    var cont = try ini.parse(gpa, "[a]\nk=x\n  y\n", .python);
    defer cont.deinit();
    w = .fixed(&sink);
    try testing.expectError(error.NotRepresentable, cont.write(gpa, &w, .{ .options = .{} }));
    var small: [2]u8 = undefined;
    w = .fixed(&small);
    try testing.expectError(error.WriteFailed, cont.write(gpa, &w, .{ .options = .python }));
}

// ── pull readers ─────────────────────────────────────────────────────────────

test "Scanner: events in file order, nothing allocated" {
    var sc = ini.Scanner.init("\xEF\xBB\xBF# c\n[s]\nk = v\n  more\n\nbad\n", .python);
    const got = [_]std.meta.Tag(ini.Event){ .comment, .section, .entry, .continuation, .blank, .invalid };
    for (got, 1..) |tag, line| {
        const ev = sc.next().?;
        try testing.expectEqual(tag, std.meta.activeTag(ev));
        const at = switch (ev) {
            .blank => |x| x.line,
            .comment => |x| x.line,
            .section => |x| x.line,
            .entry => |x| x.line,
            .continuation => |x| x.line,
            .invalid => |x| x.line,
        };
        try testing.expectEqual(line, at);
    }
    try testing.expect(sc.next() == null);
    try testing.expect(sc.next() == null);
    var empty = ini.Scanner.init("", .{});
    try testing.expect(empty.next() == null);
}

test "StreamScanner reads what Scanner reads; a line over the buffer is an error" {
    const text = "\xEF\xBB\xBF[s]\r\nk = v\n  more\n[t]\nlast=1";
    var r: std.Io.Reader = .fixed(text);
    var st = ini.StreamScanner.init(&r, .python);
    var sc = ini.Scanner.init(text, .python);
    while (try st.next()) |a| {
        const b = sc.next().?;
        try testing.expectEqual(std.meta.activeTag(b), std.meta.activeTag(a));
        switch (a) {
            .entry => |e| {
                try testing.expectEqualStrings(b.entry.key, e.key);
                try testing.expectEqualStrings(b.entry.value, e.value);
            },
            .section => |h| try testing.expectEqualStrings(b.section.name, h.name),
            else => {},
        }
    }
    try testing.expect(sc.next() == null);

    // A reader whose buffer is smaller than the line.
    var src: std.Io.Reader = .fixed("[s]\nkey=value\n");
    var small: [4]u8 = undefined;
    var limited = src.limited(.unlimited, &small);
    var lt = ini.StreamScanner.init(&limited.interface, .{});
    try testing.expect((try lt.next()).? == .section);
    try testing.expectError(error.LineTooLong, lt.next());
}

// ── typed readings ───────────────────────────────────────────────────────────

test "getInt, getFloat: absent is null, wrong is an error" {
    var doc = try ini.parse(gpa, "[a]\ni=42\nn=-7\nbig=99999999999\nf=1.5\nx=abc\n", .{});
    defer doc.deinit();
    try testing.expectEqual(@as(?i32, 42), try doc.getInt(i32, "a", "i"));
    try testing.expectEqual(@as(?i32, -7), try doc.getInt(i32, "a", "n"));
    try testing.expectEqual(@as(?i32, null), try doc.getInt(i32, "a", "absent"));
    try testing.expectError(error.Overflow, doc.getInt(i32, "a", "big"));
    try testing.expectError(error.Overflow, doc.getInt(u32, "a", "n"));
    try testing.expectError(error.NotAnInt, doc.getInt(i32, "a", "f"));
    try testing.expectEqual(@as(?f64, 1.5), try doc.getFloat(f64, "a", "f"));
    try testing.expectEqual(@as(?f64, null), try doc.getFloat(f64, "a", "absent"));
    try testing.expectError(error.NotAFloat, doc.getFloat(f64, "a", "x"));
}

test "mapSection: fields by name, defaults stay, errors surface" {
    const Color = enum { red, green };
    const Cfg = struct {
        name: []const u8 = "none",
        port: u16 = 80,
        ratio: f32 = 0.5,
        on: bool = false,
        color: Color = .red,
        opt: ?i8 = null,
        untouched: u8 = 9,
    };
    var doc = try ini.parse(gpa, "[s]\nname=x\nport=8080\nratio=2.5\non=yes\ncolor=green\nopt=-3\n[bad]\nport=70000\n[bad2]\ncolor=blue\n", .{});
    defer doc.deinit();
    const c = try doc.mapSection(Cfg, "s");
    try testing.expectEqualStrings("x", c.name);
    try testing.expectEqual(@as(u16, 8080), c.port);
    try testing.expectEqual(@as(f32, 2.5), c.ratio);
    try testing.expect(c.on);
    try testing.expectEqual(Color.green, c.color);
    try testing.expectEqual(@as(?i8, -3), c.opt);
    try testing.expectEqual(@as(u8, 9), c.untouched);
    const d = try doc.mapSection(Cfg, "absent");
    try testing.expectEqual(@as(u16, 80), d.port);
    try testing.expectError(error.Overflow, doc.mapSection(Cfg, "bad"));
    try testing.expectError(error.NotAnEnumTag, doc.mapSection(Cfg, "bad2"));
}

test "getInherited walks up the dotted name" {
    var doc = try ini.parse(gpa, "[a]\nk=top\n[a.b]\nj=mid\n[a.b.c]\ni=low\n", .{});
    defer doc.deinit();
    try testing.expectEqualStrings("top", doc.getInherited("a.b.c", "k", '.').?);
    try testing.expectEqualStrings("mid", doc.getInherited("a.b.c", "j", '.').?);
    try testing.expectEqualStrings("low", doc.getInherited("a.b.c", "i", '.').?);
    try testing.expect(doc.getInherited("a.b.c", "z", '.') == null);
    try testing.expectEqualStrings("top", doc.getInherited("a.x.y", "k", '.').?); // a missing level is walked over
}

fn expectList(raw: []const u8, opts: ini.ListOptions, want: []const []const u8) !void {
    var l = try ini.parseList(gpa, raw, opts);
    defer l.deinit(gpa);
    try testing.expectEqual(want.len, l.items.len);
    for (want, l.items) |w, g| try testing.expectEqualStrings(w, g);
}

test "parseList: go-ini's and GKeyFile's rules, by option" {
    try expectList("a, b ,,c,", .{}, &.{ "a", "b", "c" });
    try expectList("a\\,b,c", .{}, &.{ "a,b", "c" });
    try expectList("a\\qb", .{}, &.{"a\\qb"});
    try expectList("", .{}, &.{});
    try expectList("a\\,b", .{ .escapes = .none }, &.{ "a\\", "b" });
    try expectList("a;;b;", .desktop, &.{ "a", "", "b" });
    try expectList(" a\\s;b\\;c\\n", .desktop, &.{ " a ", "b;c\n" });
    try testing.expectError(error.InvalidEscape, ini.parseList(gpa, "a\\q", .desktop));
    try testing.expectError(error.InvalidEscape, ini.parseList(gpa, "a\\", .desktop));
    var doc = try ini.parse(gpa, "[a]\nl=x,y\n", .{});
    defer doc.deinit();
    var l = (try doc.getList(gpa, "a", "l", .{})).?;
    defer l.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), l.items.len);
    try testing.expect((try doc.getList(gpa, "a", "none", .{})) == null);
}

test "quote and escapeDesktop invert unquote and unescapeDesktop" {
    const samples = [_][]const u8{ "", "plain", " lead", "tail ", "a\"b\\c\nd\te\rf", "'single'", "\\s", "  " };
    for (samples) |s| {
        const q = try ini.quote(gpa, s);
        defer gpa.free(q);
        const uq = try ini.unquote(gpa, q);
        defer gpa.free(uq);
        try testing.expectEqualStrings(s, uq);
        const e = try ini.escapeDesktop(gpa, s);
        defer gpa.free(e);
        const ue = try ini.unescapeDesktop(gpa, e);
        defer gpa.free(ue);
        try testing.expectEqualStrings(s, ue);
    }
}

// ── [DEFAULT], merged, duplicates ────────────────────────────────────────────

test "default_section: get falls back, raw access does not, an absent section stays absent" {
    var doc = try ini.parse(gpa, "[DEFAULT]\nd=1\nk=def\n[a]\nk=own\n[b]\n", .configparser);
    defer doc.deinit();
    try testing.expectEqualStrings("1", doc.get("a", "d").?);
    try testing.expectEqualStrings("own", doc.get("a", "k").?);
    try testing.expectEqualStrings("def", doc.get("b", "k").?);
    try testing.expect(doc.get("absent", "d") == null);
    try testing.expectEqualStrings("1", doc.get("DEFAULT", "d").?);
    var raw = doc.entries("b");
    try testing.expect(raw.next() == null);
    var names = doc.sectionNames();
    try testing.expectEqualStrings("a", names.next().?);
    try testing.expectEqualStrings("b", names.next().?);
    try testing.expect(names.next() == null);
    var m = doc.merged("a");
    try testing.expectEqualStrings("k", m.next().?.key);
    const e = m.next().?;
    try testing.expectEqualStrings("d", e.key);
    try testing.expectEqualStrings("1", e.value);
    try testing.expect(m.next() == null);
    var absent = doc.merged("zz");
    try testing.expect(absent.next() == null);
    // Without the option `[DEFAULT]` is a section like another.
    var plain = try ini.parse(gpa, "[DEFAULT]\nd=1\n[a]\n", .python);
    defer plain.deinit();
    try testing.expect(plain.get("a", "d") == null);
}

test "merged: first-appearance order, last value, across repeated sections" {
    var doc = try ini.parse(gpa, "[a]\nx=1\ny=2\n[b]\n[a]\nx=3\nz=4\n", .{});
    defer doc.deinit();
    var m = doc.merged("a");
    const want = [_][2][]const u8{ .{ "x", "3" }, .{ "y", "2" }, .{ "z", "4" } };
    for (want) |w| {
        const e = m.next().?;
        try testing.expectEqualStrings(w[0], e.key);
        try testing.expectEqualStrings(w[1], e.value);
    }
    try testing.expect(m.next() == null);
}

test "firstDuplicate finds what configparser strict=True refuses" {
    var clean = try ini.parse(gpa, "[a]\nk=1\n[b]\nk=2\n", .{});
    defer clean.deinit();
    try testing.expect(clean.firstDuplicate() == null);
    var dk = try ini.parse(gpa, "[a]\nk=1\nj=2\nk=3\n", .{});
    defer dk.deinit();
    const d1 = dk.firstDuplicate().?;
    try testing.expectEqual(.key, d1.kind);
    try testing.expectEqualStrings("k", d1.name);
    try testing.expectEqual(@as(usize, 4), d1.line);
    var ds = try ini.parse(gpa, "[a]\n[b]\n[A]\n", .{ .case_insensitive_sections = true });
    defer ds.deinit();
    const d2 = ds.firstDuplicate().?;
    try testing.expectEqual(.section, d2.kind);
    try testing.expectEqual(@as(usize, 3), d2.line);
}

// ── interpolation ────────────────────────────────────────────────────────────

fn expectInterp(doc: *const ini.Document, section: []const u8, key: []const u8, opts: ini.InterpolateOptions, want: []const u8) !void {
    const got = (try doc.interpolated(gpa, section, key, opts)).?;
    defer gpa.free(got);
    try testing.expectEqualStrings(want, got);
}

test "interpolation: basic and extended, refusals, limits" {
    var doc = try ini.parse(gpa,
        \\[DEFAULT]
        \\home = /h
        \\[a]
        \\p = %(home)s/x
        \\q = %(p)s/y
        \\pc = 100%%
        \\bad1 = 5%
        \\bad2 = %(open
        \\bad3 = %x
        \\bad4 = %()s
        \\miss = %(nope)s
        \\self = %(self)s
        \\e = ${home}/z
        \\c = ${b:v}!
        \\d = $$5
        \\e1 = ${open
        \\e2 = ${a:b:c}
        \\e3 = ${nosec:v}
        \\e4 = $x
        \\[b]
        \\v = ${w}
        \\w = deep
    , .configparser);
    defer doc.deinit();
    try expectInterp(&doc, "a", "p", .{}, "/h/x");
    try expectInterp(&doc, "a", "q", .{}, "/h/x/y");
    try expectInterp(&doc, "a", "pc", .{}, "100%");
    try testing.expect((try doc.interpolated(gpa, "a", "absent", .{})) == null);
    for ([_][]const u8{ "bad1", "bad2", "bad3", "bad4" }) |k|
        try testing.expectError(error.InterpolationSyntax, doc.interpolated(gpa, "a", k, .{}));
    try testing.expectError(error.InterpolationMissing, doc.interpolated(gpa, "a", "miss", .{}));
    try testing.expectError(error.InterpolationDepth, doc.interpolated(gpa, "a", "self", .{}));

    const ext: ini.InterpolateOptions = .{ .style = .extended };
    try expectInterp(&doc, "a", "e", ext, "/h/z");
    try expectInterp(&doc, "a", "c", ext, "deep!"); // the reference resolves in [b]
    try expectInterp(&doc, "a", "d", ext, "$5");
    for ([_][]const u8{ "e1", "e2", "e4" }) |k|
        try testing.expectError(error.InterpolationSyntax, doc.interpolated(gpa, "a", k, ext));
    try testing.expectError(error.InterpolationMissing, doc.interpolated(gpa, "a", "e3", ext));
}

test "interpolation: a billion laughs stops at the limits, cheaply and cleanly" {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    try text.appendSlice(gpa, "[a]\nv0=xxxxxxxxxxxxxxxx\nz0=\n");
    for (1..10) |i| {
        var b: [200]u8 = undefined;
        const line = try std.mem.print(&b, "v{d}=%(v{d})s%(v{d})s%(v{d})s%(v{d})s%(v{d})s%(v{d})s%(v{d})s%(v{d})s\nz{d}=%(z{d})s%(z{d})s%(z{d})s%(z{d})s%(z{d})s%(z{d})s%(z{d})s%(z{d})s\n", .{ i, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1, i - 1 });
        try text.appendSlice(gpa, line);
    }
    var doc = try ini.parse(gpa, text.items, .python);
    defer doc.deinit();
    try testing.expectError(error.InterpolationTooLarge, doc.interpolated(gpa, "a", "v9", .{}));
    try testing.expectError(error.InterpolationTooLarge, doc.interpolated(gpa, "a", "z9", .{}));
    try testing.expectError(error.InterpolationTooLarge, doc.interpolated(gpa, "a", "v2", .{ .max_bytes = 8 }));
    try testing.expectError(error.InterpolationDepth, doc.interpolated(gpa, "a", "v3", .{ .max_depth = 1 }));
    // A depth above the honoured 64 is 64: a cycle still ends.
    var cyc = try ini.parse(gpa, "[a]\nk=%(k)s\n", .python);
    defer cyc.deinit();
    try testing.expectError(error.InterpolationDepth, cyc.interpolated(gpa, "a", "k", .{ .max_depth = 255 }));
}

// ── options ─────────────────────────────────────────────────────────────────

test "inline comments are cut from every kind of line" {
    const o: ini.Options = .{ .inline_comments = true, .continuation_lines = true };
    try testing.expectError(error.MissingSeparator, ini.parse(gpa, "[a]\nx ; y = z\n", o));
    var doc = try ini.parse(gpa, "[a] ; note\nk = v ; c\n  more # c\n", o);
    defer doc.deinit();
    try testing.expectEqualStrings("v\nmore", doc.get("a", "k").?);
}

test "empty_lines_in_values keeps inner blanks and drops trailing ones" {
    var doc = try ini.parse(gpa, "[a]\nk=x\n\n\n  y\n# c\n  z\n\n\nj=1\n", .configparser);
    defer doc.deinit();
    try testing.expectEqualStrings("x\n\n\ny\nz", doc.get("a", "k").?);
    try testing.expectEqualStrings("1", doc.get("a", "j").?);
}

test "no_value_keys: bare keys, has_value false, not continuable" {
    const o: ini.Options = .{ .no_value_keys = true, .continuation_lines = true };
    var doc = try ini.parse(gpa, "[a]\nbare\nk=v\n", o);
    defer doc.deinit();
    try testing.expectEqualStrings("", doc.get("a", "bare").?);
    try testing.expect(!doc.sections[0].entries[0].has_value);
    try testing.expect(doc.sections[0].entries[1].has_value);
    try testing.expectError(error.MissingSeparator, ini.parse(gpa, "[a]\nbare\n  more\n", o));
}

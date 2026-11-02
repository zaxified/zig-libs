// SPDX-License-Identifier: MIT

//! Findings of the independent review of 2026-11-02, each pinned, and the
//! sweep behind the Editor's promise that a failed edit changes nothing.

const std = @import("std");
const ini = @import("root.zig");
const testing = std.testing;
const gpa = testing.allocator;

fn expectEdited(ed: *const ini.Editor, want: []const u8) !void {
    const got = try ed.toOwnedSlice(gpa);
    defer gpa.free(got);
    try testing.expectEqualStrings(want, got);
}

// ── H1 ───────────────────────────────────────────────────────────────────────

test "setComment copies its text: the caller may free it at once" {
    var ed = try ini.Editor.init(gpa, "[a]\nk=1\n", .{});
    defer ed.deinit();
    const text = try gpa.dupe(u8, "# marked already\n; and this");
    try ed.setComment("a", "k", text);
    @memset(text, 'X'); // what a freed block may hold
    gpa.free(text);
    try expectEdited(&ed, "[a]\n# marked already\n; and this\nk=1\n");
    const c = (try ed.getComment(gpa, "a", "k")).?;
    defer gpa.free(c);
    try testing.expectEqualStrings("# marked already\n; and this", c);
}

// ── M1 ───────────────────────────────────────────────────────────────────────

test "merged write: the headerless section goes first, or it reads back under [DEFAULT]" {
    const opts: ini.Options = .{ .default_section = "DEFAULT" };
    var doc = try ini.parse(gpa, "g=1\n[DEFAULT]\nd=2\n[s]\nx=3\n", opts);
    defer doc.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try doc.write(gpa, &out.writer, .{ .options = opts, .merged = true });
    try testing.expectEqualStrings("g = 1\n\n[DEFAULT]\nd = 2\n\n[s]\nx = 3\n\n", out.written());
    var back = try ini.parse(gpa, out.written(), opts);
    defer back.deinit();
    try testing.expectEqualStrings("1", back.get("", "g").?);
    var in_default = back.entries("DEFAULT");
    try testing.expectEqualStrings("d", in_default.next().?.key);
    try testing.expect(in_default.next() == null);
}

test "merged write: the document's own [DEFAULT] is written whatever the target options say" {
    var doc = try ini.parse(gpa, "[s]\nx=1\n[DEFAULT]\nd=2\n", .{ .default_section = "DEFAULT" });
    defer doc.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try doc.write(gpa, &out.writer, .{ .options = .{}, .merged = true });
    try testing.expectEqualStrings("[DEFAULT]\nd = 2\n\n[s]\nx = 1\n\n", out.written());
}

// ── L1, L2 ───────────────────────────────────────────────────────────────────

test "a line skipped for continuing a bare key is not absorbed by giving the key a value" {
    const opts: ini.Options = .{ .no_value_keys = true, .continuation_lines = true, .strict = false };
    const text = "[s]\nk\n  x\nj=1\n";
    var ed = try ini.Editor.init(gpa, text, opts);
    defer ed.deinit();
    try testing.expectEqualSlices(usize, &.{3}, ed.skipped);
    // Neither absorbing it nor promoting it to a key of its own is what was
    // asked, so the edit is refused and the file stays.
    try testing.expectError(error.NotRepresentable, ed.set("s", "k", "v"));
    try expectEdited(&ed, text);
    try ed.setNoValue("s", "k"); // already bare
    try expectEdited(&ed, text);
    // A new key after it does not turn the skipped line into a key.
    try ed.set("t", "n", "1");
    try ed.set("s", "n", "2");
    var doc = try ed.document(gpa);
    defer doc.deinit();
    try testing.expect(doc.get("s", "x") == null);
    // Removing the key takes the line that was trying to continue it.
    try testing.expectEqual(@as(usize, 1), try ed.remove("s", "k"));
    try expectEdited(&ed, "[s]\nj=1\nn=2\n\n[t]\nn = 1\n");
}

test "setNoValue keeps the line's own ending in a mixed file, and is a no-op on a bare key" {
    var ed = try ini.Editor.init(gpa, "[s]\nk=v\r\nj=1 ; note\nm\n", .{ .no_value_keys = true });
    defer ed.deinit();
    try ed.setNoValue("s", "k"); // CRLF line in an LF file
    try ed.setNoValue("s", "j"); // the value and what followed it on the line go
    try ed.setNoValue("s", "m");
    try expectEdited(&ed, "[s]\nk\r\nj\nm\n");

    var crlf = try ini.Editor.init(gpa, "[s]\r\nk=v\nj=w\r\n", .{ .no_value_keys = true });
    defer crlf.deinit();
    try crlf.setNoValue("s", "k"); // LF line in a CRLF file stays LF
    try crlf.setNoValue("s", "j");
    try expectEdited(&crlf, "[s]\r\nk\nj\r\n");
}

// ── L5, L6 ───────────────────────────────────────────────────────────────────

test "StreamScanner: the newline must fit the reader's buffer too" {
    var buf: [4]u8 = undefined;
    var fits: std.Io.Reader = .fixed("k=v\n");
    var a = fits.limited(.unlimited, &buf);
    var sa = ini.StreamScanner.init(&a.interface, .{});
    try testing.expect((try sa.next()).? == .entry); // 3 bytes + newline = capacity

    var over: std.Io.Reader = .fixed("k=vv\n");
    var b = over.limited(.unlimited, &buf);
    var sb = ini.StreamScanner.init(&b.interface, .{});
    try testing.expectError(error.LineTooLong, sb.next()); // 4 bytes + newline
}

test "WriteOptions.eol: only a line ending is one" {
    var doc = try ini.parse(gpa, "[a]\nk=1\nj=2\n", .{});
    defer doc.deinit();
    for ([_][]const u8{ "", "\r", "x", "\n\n", "\n\r", " \n" }) |eol| {
        var sink: [64]u8 = undefined;
        var w: std.Io.Writer = .fixed(&sink);
        try testing.expectError(error.NotRepresentable, doc.write(gpa, &w, .{ .eol = eol }));
        try testing.expectEqual(@as(usize, 0), w.buffered().len);
    }
}

// ── M2: a failed edit changes nothing ────────────────────────────────────────

const names = [_][]const u8{ "", "a", "b", "new", "DEFAULT", "A" };
const keys = [_][]const u8{ "k", "j", "x", "n", "top", "bare", "K" };

fn expectConsistent(ed: *const ini.Editor) !void {
    var doc = try ed.document(gpa);
    defer doc.deinit();
    for (names) |s| {
        try testing.expectEqual(doc.hasSection(s), ed.hasSection(s));
        for (keys) |k| {
            const x = doc.get(s, k);
            const y = ed.get(s, k);
            try testing.expectEqual(x == null, y == null);
            if (x) |v| try testing.expectEqualStrings(v, y.?);
        }
    }
}

const Op = struct {
    fn setExisting(ed: *ini.Editor) anyerror!void {
        try ed.set("a", "k", "a much longer value than the one that was there before it");
    }
    fn setMultiline(ed: *ini.Editor) anyerror!void {
        try ed.set("a", "k", "first line\nsecond line\nthird line");
    }
    fn setNewKey(ed: *ini.Editor) anyerror!void {
        try ed.set("a", "n", "new value");
    }
    fn setNewSection(ed: *ini.Editor) anyerror!void {
        try ed.set("new", "n", "new value");
    }
    fn setGlobal(ed: *ini.Editor) anyerror!void {
        try ed.set("", "n", "new value");
    }
    fn noValueExisting(ed: *ini.Editor) anyerror!void {
        try ed.setNoValue("a", "k");
    }
    fn noValueNew(ed: *ini.Editor) anyerror!void {
        try ed.setNoValue("a", "n");
    }
    fn noValueNewSection(ed: *ini.Editor) anyerror!void {
        try ed.setNoValue("new", "n");
    }
    fn addSection(ed: *ini.Editor) anyerror!void {
        try ed.addSection("new");
    }
    fn commentKey(ed: *ini.Editor) anyerror!void {
        try ed.setComment("a", "k", "first comment line\n# second\n; third, and rather longer than the others");
    }
    fn commentSection(ed: *ini.Editor) anyerror!void {
        try ed.setComment("a", null, "section comment");
    }
    fn commentRemove(ed: *ini.Editor) anyerror!void {
        try ed.setComment("a", "k", "");
    }
    fn remove(ed: *ini.Editor) anyerror!void {
        _ = try ed.remove("a", "k");
    }
    fn removeSection(ed: *ini.Editor) anyerror!void {
        _ = try ed.removeSection("a");
    }
};

const ops = [_]*const fn (*ini.Editor) anyerror!void{
    Op.setExisting,     Op.setMultiline,  Op.setNewKey,         Op.setNewSection, Op.setGlobal,
    Op.noValueExisting, Op.noValueNew,    Op.noValueNewSection, Op.addSection,    Op.commentKey,
    Op.commentSection,  Op.commentRemove, Op.remove,            Op.removeSection,
};

const documents = [_]struct { text: []const u8, opts: ini.Options }{
    .{ .text = "# top\n[a]\n# about k\nk=v\n  w\nj=1\n[b]\n# c\nx=2\n[a]\nk=3\n", .opts = .python },
    .{ .text = "[a]\r\nk = v\r\n\r\n[b]\r\nx = 2", .opts = .{ .no_value_keys = true, .continuation_lines = true } },
    .{ .text = "top=1\n[a]\nk=1\n", .opts = .{ .no_value_keys = true } },
    .{ .text = "[DEFAULT]\nd=1\n[a]\nk=x\n\n  y\n# c\n  z\n", .opts = .configparser },
    .{ .text = "", .opts = .{ .no_value_keys = true } },
    .{ .text = "[A]\nK=1\njunk\n", .opts = .{ .strict = false, .case_insensitive_sections = true, .case_insensitive_keys = true } },
    .{ .text = "[a]\nbare\n  x\nk=1\n", .opts = .{ .no_value_keys = true, .continuation_lines = true, .strict = false } },
};

const never = std.math.maxInt(usize);

/// One edit, with the `fail`-th allocation from here on failing, on an arena
/// `burn` bytes further along. Over an arena most allocations never reach the
/// child, so the position in the chunk is what decides which `try` sees the
/// failure. Whether a failure was induced.
fn oneFailure(text: []const u8, opts: ini.Options, op: *const fn (*ini.Editor) anyerror!void, burn: usize, fail: usize, induced_oom: *usize) !bool {
    var fa = testing.FailingAllocator.init(gpa, .{});
    var ed = try ini.Editor.init(fa.allocator(), text, opts);
    defer ed.deinit();
    if (burn != 0) _ = try ed.arena.allocator().alloc(u8, burn);
    const before = try ed.toOwnedSlice(gpa);
    defer gpa.free(before);

    fa.fail_index = fa.alloc_index + fail;
    fa.resize_fail_index = fa.resize_index + fail;
    const result = op(&ed);
    const induced = fa.has_induced_failure;
    fa.fail_index = never;
    fa.resize_fail_index = never;

    result catch |e| switch (e) {
        error.OutOfMemory => {
            induced_oom.* += 1;
            const after = try ed.toOwnedSlice(gpa);
            defer gpa.free(after);
            try testing.expectEqualStrings(before, after);
            try expectConsistent(&ed);
            // The editor still works: the same edit now goes through or is refused.
            op(&ed) catch |e2| try testing.expectEqual(error.NotRepresentable, e2);
        },
        error.NotRepresentable => {
            const after = try ed.toOwnedSlice(gpa);
            defer gpa.free(after);
            try testing.expectEqualStrings(before, after);
        },
        else => return e,
    };
    try expectConsistent(&ed);
    return induced;
}

test "a failed edit changes nothing: every allocation of every edit on several documents" {
    var ooms: usize = 0;
    for (documents) |d| {
        for (ops) |op| {
            var burn: usize = 0;
            while (burn < 8192) : (burn += 96) {
                var fail: usize = 0;
                while (fail < 32) : (fail += 1) {
                    if (!try oneFailure(d.text, d.opts, op, burn, fail, &ooms)) break;
                }
            }
        }
    }
    // The sweep reached the failure paths, which is what it is for.
    try testing.expect(ooms > 100);
}

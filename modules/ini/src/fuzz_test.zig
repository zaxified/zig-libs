// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over ini's existing `testing.fuzz` harness
//! (added 2026-10-09). The harness body lives here, generic over its source of
//! choices (`fn(comptime S, *S, gpa)`); `root.zig`'s `testing.fuzz` test feeds
//! it through the cursor adapter below, the driver feeds it a PRNG.
//!
//! Driver: `INI_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const ini = @import("root.zig");

pub const Label = enum {
    strict_rejected,
    strict_parsed,
    lenient_skipped,
    write_ok,
    write_refused,
    merged_ok,
    edit_applied,
    edit_refused,
    edit_after_continuation,
    interpolated_ok,
    interpolated_refused,
};
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

pub fn parseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [1024]u8 = undefined;
    const len: usize = src.slice(&buf);
    _ = try checkAllPresets(gpa, buf[0..len]);
}

/// Parse `text` with every preset, strict and lenient, and check what must
/// hold whatever the input: lenient never fails (short of memory); when
/// strict succeeds, lenient produced the same document and skipped nothing;
/// every line number is inside the text. Returns how many strict parses
/// succeeded.
pub fn checkAllPresets(gpa: std.mem.Allocator, text: []const u8) !usize {
    const line_count = std.mem.count(u8, text, "\n") + 1;
    var ok: usize = 0;
    for ([_]ini.Options{ .{}, .python, .desktop, .{ .inline_comments = true } }) |base| {
        var lax_opts = base;
        lax_opts.strict = false;
        var lax = try ini.parse(gpa, text, lax_opts);
        defer lax.deinit();
        if (lax.skipped.len != 0) mark(.lenient_skipped);
        for (lax.skipped) |l| try testing.expect(l >= 1 and l <= line_count);
        for (lax.sections) |s| {
            try testing.expect(s.line <= line_count);
            for (s.entries) |e| {
                try testing.expect(e.line >= 1 and e.line <= line_count);
                try testing.expect(e.key.len > 0);
            }
        }
        var strict = ini.parse(gpa, text, base) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => {
                mark(.strict_rejected);
                continue;
            },
        };
        defer strict.deinit();
        mark(.strict_parsed);
        ok += 1;
        try testing.expectEqual(@as(usize, 0), lax.skipped.len);
        try testing.expectEqual(lax.sections.len, strict.sections.len);
        for (lax.sections, strict.sections) |x, y| {
            try testing.expectEqualStrings(x.name, y.name);
            try testing.expectEqual(x.entries.len, y.entries.len);
            for (x.entries, y.entries) |ex, ey| {
                try testing.expectEqualStrings(ex.key, ey.key);
                try testing.expectEqualStrings(ex.value, ey.value);
            }
        }
    }
    return ok;
}

// ── the readers agree; the writers round-trip; an edit does what it says ─────

const presets = [_]ini.Options{
    .{ .strict = false },
    .{ .strict = false, .separators = "=:", .continuation_lines = true, .global_entries = false, .header_trailing_text = true },
    .{ .strict = false, .comment_chars = "#", .trim_values = false, .global_entries = false, .locale_keys = true },
    .{ .strict = false, .separators = "=:", .continuation_lines = true, .empty_lines_in_values = true, .global_entries = false, .header_trailing_text = true, .default_section = "DEFAULT" },
    .{ .no_value_keys = true, .continuation_lines = true }, // strict: the refusal path of `editHarness`
    .{ .strict = false, .no_value_keys = true, .continuation_lines = true },
    .{ .strict = false, .default_section = "DEFAULT" }, // `[DEFAULT]` with entries before any header
    .{ .strict = false, .inline_comments = true, .continuation_lines = true },
    .{ .strict = false, .case_insensitive_sections = true, .case_insensitive_keys = true },
};

const line_shapes = [_][]const u8{
    "[a]",      "[b]",  "[DEFAULT]",  "  [b]",   "[a] ; c", "k=v",      "k = w  ", "j: x",  "K=V",     "j=a b",   "k=v ; c",
    "  k = i",  "bare", "  bare",     "x ; y=z", "=v",      "",         "   ",     "# c",   "; c",     "  # c",   "  more",
    "    deep", "\tt",  "  more ; c", "junk]",   "k=%(j)s", "j=${b:k}", "n=42",    "f=1.5", "l=a,b;c", "N[cs]=A",
};

const name_alphabet = [_][]const u8{ "a", "b", "", "DEFAULT", "A" };
const key_alphabet = [_][]const u8{ "k", "j", "K", "new", "bare" };
const value_alphabet = [_][]const u8{
    "v", "", "two words", "l1\nl2", "l1\n\nl2", " lead", "trail ", "c ; d", "#x", "tail\n", "\nx", "a\n#b", "cr\r", "%(k)s", "\n",
};
const comment_alphabet = [_][]const u8{ "", "hello", "# marked", "two\nlines", "bad\r" };

/// The bytes of one `slice` draw, read as small choices; zeros past the end.
const Choices = struct {
    bytes: []const u8,
    at: usize = 0,
    fn pick(c: *Choices, n: usize) usize {
        if (c.at >= c.bytes.len) return 0;
        c.at += 1;
        return c.bytes[c.at - 1] % n;
    }
};

/// A text of shape lines, drawn from `c`, into `out`.
fn shapedText(c: *Choices, out: *std.ArrayList(u8), gpa: std.mem.Allocator) !void {
    const lines = c.pick(14);
    for (0..lines) |_| {
        try out.appendSlice(gpa, line_shapes[c.pick(line_shapes.len)]);
        try out.appendSlice(gpa, switch (c.pick(16)) {
            0 => "\r\n",
            else => "\n",
        });
    }
    if (c.pick(5) == 0 and out.items.len != 0) out.items.len -= 1; // no final newline
}

fn sameDocument(x: *const ini.Document, y: *const ini.Document) !void {
    try testing.expectEqual(x.sections.len, y.sections.len);
    for (x.sections, y.sections) |a, b| {
        try testing.expectEqualStrings(a.name, b.name);
        try testing.expectEqual(a.entries.len, b.entries.len);
        for (a.entries, b.entries) |ea, eb| {
            try testing.expectEqualStrings(ea.key, eb.key);
            try testing.expectEqualStrings(ea.value, eb.value);
            try testing.expectEqual(ea.has_value, eb.has_value);
        }
    }
}

/// The last value of `key` in `section` itself, inheriting nothing.
fn ownValue(doc: *const ini.Document, section: []const u8, key: []const u8) ?[]const u8 {
    var it = doc.merged(section);
    while (it.next()) |e| {
        if (it.in_default) return null;
        if (std.mem.eql(u8, e.key, key)) return e.value;
    }
    return null;
}

/// Section for section, both ways. The per-line proof sees one line at a time, so
/// only this notices a line that landed under the wrong header.
fn sameBySection(x: *const ini.Document, y: *const ini.Document) !void {
    for ([2]*const ini.Document{ x, y }, [2]*const ini.Document{ y, x }) |p, q| {
        for (p.sections) |s| {
            var it = p.merged(s.name);
            while (it.next()) |e| {
                if (it.in_default) break;
                if (!optEql(e.value, ownValue(q, s.name, e.key))) {
                    std.debug.print("[{s}] {s}: {s}, on the other side {?s}\n", .{ s.name, e.key, e.value, ownValue(q, s.name, e.key) });
                    return error.SectionContextDiffers;
                }
            }
        }
    }
}

fn optEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

/// Every reader, every writer, every getter over a shaped text, then a random
/// edit session against the only model that matters: reading the output back.
pub fn editHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [256]u8 = undefined;
    const len: usize = src.slice(&buf);
    var c: Choices = .{ .bytes = buf[0..len] };
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    try shapedText(&c, &text, gpa);
    const opts = presets[c.pick(presets.len)];

    var doc = ini.parse(gpa, text.items, opts) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {
            // Strict only: the Editor must refuse the same text.
            if (ini.Editor.init(gpa, text.items, opts)) |ed_const| {
                var ed = ed_const;
                ed.deinit();
                return error.EditorAcceptsWhatParseRefuses;
            } else |_| return;
        },
    };
    defer doc.deinit();

    try checkScanners(gpa, text.items, opts, &doc);
    try checkGetters(gpa, &doc);

    // Document.write reads back as the same document.
    var written: std.Io.Writer.Allocating = .init(gpa);
    defer written.deinit();
    const wopts: ini.WriteOptions = .{ .options = opts, .eol = if (c.pick(4) == 0) "\r\n" else "\n", .separator = if (c.pick(4) == 0) "=" else null };
    if (doc.write(gpa, &written.writer, wopts)) {
        mark(.write_ok);
        var back = try ini.parse(gpa, written.written(), opts);
        defer back.deinit();
        try sameDocument(&doc, &back);
    } else |e| switch (e) {
        error.NotRepresentable => mark(.write_refused),
        else => return e,
    }

    // Merged: each section still holds what it held.
    var merged: std.Io.Writer.Allocating = .init(gpa);
    defer merged.deinit();
    if (doc.write(gpa, &merged.writer, .{ .options = opts, .merged = true })) {
        mark(.merged_ok);
        var back = try ini.parse(gpa, merged.written(), opts);
        defer back.deinit();
        try sameBySection(&doc, &back);
    } else |e| switch (e) {
        error.NotRepresentable => mark(.write_refused),
        else => return e,
    }

    // Whatever dialect accepts the document reads it back the same.
    const other = presets[c.pick(presets.len)];
    var cross: std.Io.Writer.Allocating = .init(gpa);
    defer cross.deinit();
    if (doc.write(gpa, &cross.writer, .{ .options = other })) {
        var back = try ini.parse(gpa, cross.written(), other);
        defer back.deinit();
        try sameDocument(&doc, &back);
    } else |e| switch (e) {
        error.NotRepresentable => mark(.write_refused),
        else => return e,
    }

    // The Editor, unedited, is the input byte for byte and reads the same.
    var ed = try ini.Editor.init(gpa, text.items, opts);
    defer ed.deinit();
    const same = try ed.toOwnedSlice(gpa);
    defer gpa.free(same);
    try testing.expectEqualStrings(text.items, same);
    try testing.expectEqualSlices(usize, doc.skipped, ed.skipped);
    try checkEditorView(gpa, &ed, opts);

    for (0..c.pick(7)) |_| try oneEdit(gpa, &ed, &c, opts);
}

fn checkScanners(gpa: std.mem.Allocator, text: []const u8, opts: ini.Options, doc: *const ini.Document) !void {
    // The pull readers see what `parse` built, in order, line for line.
    var r: std.Io.Reader = .fixed(text);
    var st = ini.StreamScanner.init(&r, opts);
    var sc = ini.Scanner.init(text, opts);
    var si: usize = if (doc.sections.len != 0 and doc.sections[0].line == 0) 0 else std.math.maxInt(usize);
    var ei: usize = 0;
    while (sc.next()) |ev| {
        const ev2 = (try st.next()).?;
        try testing.expectEqual(std.meta.activeTag(ev), std.meta.activeTag(ev2));
        switch (ev) {
            .section => |h| {
                si +%= 1;
                ei = 0;
                try testing.expectEqualStrings(doc.sections[si].name, h.name);
                try testing.expectEqual(doc.sections[si].line, h.line);
                try testing.expectEqualStrings(h.name, ev2.section.name);
            },
            .entry => |e| {
                try testing.expectEqualStrings(doc.sections[si].entries[ei].key, e.key);
                try testing.expectEqual(doc.sections[si].entries[ei].line, e.line);
                try testing.expectEqualStrings(e.value, ev2.entry.value);
                ei += 1;
            },
            else => {},
        }
    }
    // A text ending in a bare BOM line is the one place the stream sees a line more.
    _ = st.next() catch {};
    _ = gpa;
}

fn checkGetters(gpa: std.mem.Allocator, doc: *const ini.Document) !void {
    const Mapped = struct { k: []const u8 = "", n: i32 = 0, f: f64 = 0, j: ?bool = null };
    for (name_alphabet) |s| {
        _ = doc.hasSection(s);
        _ = doc.mapSection(Mapped, s) catch {};
        var m = doc.merged(s);
        while (m.next()) |e| try testing.expectEqualStrings(doc.get(s, e.key).?, e.value);
        for (key_alphabet ++ [_][]const u8{ "n", "f", "l", "N" }) |k| {
            _ = doc.getInt(i16, s, k) catch {};
            _ = doc.getInt(u64, s, k) catch {};
            _ = doc.getFloat(f32, s, k) catch {};
            _ = doc.getBool(s, k) catch {};
            _ = doc.getLocale(s, k, "cs_CZ.UTF-8@x");
            _ = doc.getInherited(s, k, '.');
            for ([_]ini.ListOptions{ .{}, .desktop }) |lo| {
                var l = (doc.getList(gpa, s, k, lo) catch |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => null,
                }) orelse continue;
                l.deinit(gpa);
            }
            for ([_]ini.InterpolateOptions{ .{}, .{ .style = .extended } }) |io| {
                if (doc.interpolated(gpa, s, k, io)) |v| {
                    mark(.interpolated_ok);
                    if (v) |x| gpa.free(x);
                } else |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => mark(.interpolated_refused),
                }
            }
        }
    }
    _ = doc.firstDuplicate();
    var names = doc.sectionNames();
    while (names.next()) |n| try testing.expect(doc.hasSection(n));
}

/// The Editor's view of every name equals a fresh parse of its own output.
fn checkEditorView(gpa: std.mem.Allocator, ed: *const ini.Editor, opts: ini.Options) !void {
    const out = try ed.toOwnedSlice(gpa);
    defer gpa.free(out);
    var back = ini.parse(gpa, out, opts) catch |e| {
        std.debug.print("edited text does not parse ({t}):\n{s}\n", .{ e, out });
        return e;
    };
    defer back.deinit();
    for (name_alphabet) |s| {
        if (back.hasSection(s) != ed.hasSection(s)) {
            std.debug.print("[{s}]: editor has it = {}, its text:\n{f}\n", .{ s, ed.hasSection(s), std.ascii.hexEscape(out, .lower) });
            return error.EditorViewDiffers;
        }
        for (key_alphabet) |k| {
            if (!optEql(back.get(s, k), ed.get(s, k))) {
                std.debug.print("[{s}] {s}: editor {f}, its text {f}:\n{f}\n", .{ s, k, std.ascii.hexEscape(ed.get(s, k) orelse "<absent>", .lower), std.ascii.hexEscape(back.get(s, k) orelse "<absent>", .lower), std.ascii.hexEscape(out, .lower) });
                return error.EditorViewDiffers;
            }
        }
    }
}

fn oneEdit(gpa: std.mem.Allocator, ed: *ini.Editor, c: *Choices, opts: ini.Options) !void {
    const s = name_alphabet[c.pick(name_alphabet.len)];
    const k = key_alphabet[c.pick(key_alphabet.len)];
    const before = try ed.toOwnedSlice(gpa);
    defer gpa.free(before);
    var refused = false;
    switch (c.pick(6)) {
        0, 1 => {
            const v = value_alphabet[c.pick(value_alphabet.len)];
            if (ed.set(s, k, v)) {
                try testing.expectEqualStrings(v, ed.get(s, k).?);
            } else |e| switch (e) {
                error.NotRepresentable => refused = true,
                else => return e,
            }
        },
        2 => {
            _ = try ed.remove(s, k);
            if (opts.default_section == null) try testing.expect(ed.get(s, k) == null);
        },
        3 => {
            _ = try ed.removeSection(s);
            try testing.expect(!ed.hasSection(s));
        },
        4 => {
            const t = comment_alphabet[c.pick(comment_alphabet.len)];
            // A copy freed at once: the Editor must not keep the caller's text.
            const owned = try gpa.dupe(u8, t);
            ed.setComment(s, if (c.pick(2) == 0) k else null, owned) catch |e| switch (e) {
                error.NotRepresentable => refused = true,
                else => {
                    gpa.free(owned);
                    return e;
                },
            };
            gpa.free(owned);
            const got = try ed.getComment(gpa, s, k);
            if (got) |g| gpa.free(g);
        },
        else => {
            ed.setNoValue(s, k) catch |e| switch (e) {
                error.NotRepresentable => refused = true,
                else => return e,
            };
        },
    }
    if (refused) {
        mark(.edit_refused);
        const after = try ed.toOwnedSlice(gpa);
        defer gpa.free(after);
        try testing.expectEqualStrings(before, after);
    } else {
        mark(.edit_applied);
        if (opts.continuation_lines) mark(.edit_after_continuation);
    }
    try checkEditorView(gpa, ed, opts);
}

test "fuzz driver: INI_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ parseHarness, .{ .prefix = "INI_FUZZ", .name = "ini-parse" } },
        .{ editHarness, .{ .prefix = "INI_FUZZ", .name = "ini-edit" } },
    });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        parseHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("ini seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        var prng2 = std.Random.DefaultPrng.init(seed);
        var rng2: fuzz_driver.Rng = .{ .r = prng2.random() };
        editHarness(fuzz_driver.Rng, &rng2, testing.allocator) catch |err| {
            std.debug.print("ini edit seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

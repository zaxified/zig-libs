// SPDX-License-Identifier: MIT

//! The external anchor for the opt-in features: CPython's configparser and
//! GLib's GKeyFile on the same inputs (`testdata/goldens_ext.zig`, captured by
//! `tools/gen_goldens_ext.py`). Plus the live half: `INI_WRITER_DUMP=<file>`
//! dumps what our writers made of the golden corpus, for
//! `tools/writer_oracle.py` to read back with the foreign implementations.

const std = @import("std");
const ini = @import("root.zig");
const goldens = @import("testdata/goldens.zig");
const ext = @import("testdata/goldens_ext.zig");

const testing = std.testing;
const gpa = testing.allocator;

/// The view `gen_goldens_ext.py`'s `view` prints.
fn render(doc: *const ini.Document) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    var names = doc.sectionNames();
    while (names.next()) |name| {
        try w.print("[{s}]\n", .{name});
        var it = doc.merged(name);
        while (it.next()) |e| {
            try w.print("{s}=", .{e.key});
            if (!e.has_value) try w.writeAll("<none>");
            for (e.value) |c| switch (c) {
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                else => try w.writeByte(c),
            };
            try w.writeByte('\n');
        }
    }
    return out.toOwnedSlice();
}

fn checkView(text: []const u8, opts: ini.Options, want: ?[]const u8, label: []const u8) !bool {
    var doc = ini.parse(gpa, text, opts) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {
            if (want == null) return true;
            std.debug.print("{s}: refused {f}, reference read:\n{s}\n", .{ label, std.ascii.hexEscape(text, .lower), want.? });
            return false;
        },
    };
    defer doc.deinit();
    const got = try render(&doc);
    defer gpa.free(got);
    if (want) |w| if (std.mem.eql(u8, w, got)) return true;
    std.debug.print("{s}: {f}\n  ours:\n{s}  reference:\n{?s}\n", .{ label, std.ascii.hexEscape(text, .lower), got, want });
    return false;
}

test "inline_comments agrees with configparser's inline_comment_prefixes" {
    var opts = ini.Options.python;
    opts.inline_comments = true;
    var bad: usize = 0;
    var refused: usize = 0;
    for (ext.inline_cases) |c| {
        if (!try checkView(c.text, opts, c.view, "inline")) bad += 1;
        if (c.view == null) refused += 1;
    }
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expect(refused > 20 and refused < ext.inline_cases.len - 20);
}

test "Options.configparser agrees with ConfigParser: [DEFAULT], blank lines in values, strict, write" {
    var bad: usize = 0;
    var refused: usize = 0;
    var dups: usize = 0;
    var wrote: usize = 0;
    for (ext.default_cases) |c| {
        if (!try checkView(c.text, .configparser, c.view, "configparser")) bad += 1;
        if (c.view == null) {
            refused += 1;
            continue;
        }
        var doc = try ini.parse(gpa, c.text, .configparser);
        defer doc.deinit();
        if ((doc.firstDuplicate() != null) != c.strict_refuses) {
            std.debug.print("firstDuplicate on {f}: reference strict refuses = {}\n", .{ std.ascii.hexEscape(c.text, .lower), c.strict_refuses });
            bad += 1;
        }
        if (c.strict_refuses) dups += 1;
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try doc.write(gpa, &out.writer, .{ .options = .configparser, .merged = true });
        if (!std.mem.eql(u8, out.written(), c.write.?)) {
            std.debug.print("write on {f}:\n  ours:\n{s}  reference:\n{s}\n", .{ std.ascii.hexEscape(c.text, .lower), out.written(), c.write.? });
            bad += 1;
        }
        wrote += 1;
    }
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expect(refused > 20 and dups > 20 and wrote > 100);
}

test "no_value_keys agrees with allow_no_value=True" {
    var opts = ini.Options.python;
    opts.no_value_keys = true;
    var bad: usize = 0;
    for (ext.no_value_cases) |c| {
        if (!try checkView(c.text, opts, c.view, "no_value")) bad += 1;
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "interpolated agrees with Basic and Extended interpolation" {
    var bad: usize = 0;
    var seen: [4]usize = @splat(0);
    for (ext.interp_cases) |c| {
        var doc = try ini.parse(gpa, c.text, .configparser);
        defer doc.deinit();
        var got_buf: [64]u8 = undefined;
        var owned: ?[]u8 = null;
        defer if (owned) |o| gpa.free(o);
        const got: []const u8 = blk: {
            const r = doc.interpolated(gpa, "a", c.key, .{ .style = if (c.extended) .extended else .basic }) catch |e| switch (e) {
                error.InterpolationSyntax => {
                    seen[1] += 1;
                    break :blk "err:syntax";
                },
                error.InterpolationMissing => {
                    seen[2] += 1;
                    break :blk "err:missing";
                },
                error.InterpolationDepth => {
                    seen[3] += 1;
                    break :blk "err:depth";
                },
                else => return e,
            };
            seen[0] += 1;
            owned = r.?;
            break :blk try std.fmt.bufPrint(&got_buf, "ok:{s}", .{owned.?});
        };
        if (!std.mem.eql(u8, got, c.result)) {
            std.debug.print("interp extended={}: {s}\n  ours {s}\n  reference {s}\n", .{ c.extended, c.text, got, c.result });
            bad += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
    for (seen) |n| try testing.expect(n > 0);
}

test "intValue, floatValue, boolValue agree with int(), float(), getboolean()" {
    var bad: usize = 0;
    for (ext.int_cases) |c| {
        var buf: [32]u8 = undefined;
        const got: ?[]const u8 = if (ini.intValue(i64, c.raw)) |n| try std.fmt.bufPrint(&buf, "{d}", .{n}) else |e| switch (e) {
            error.Overflow => "overflow",
            error.NotAnInt => null,
        };
        if (!optEql(got, c.result) and !isDeliberate(c.raw)) {
            std.debug.print("int '{s}': ours {?s} reference {?s}\n", .{ c.raw, got, c.result });
            bad += 1;
        }
    }
    for (ext.float_cases) |c| {
        const want: ?f64 = if (c.result) |r| try std.fmt.parseFloat(f64, r) else null;
        const got: ?f64 = ini.floatValue(f64, c.raw) catch null;
        const same = if (got != null and want != null)
            (got.? == want.? or (std.math.isNan(got.?) and std.math.isNan(want.?)))
        else
            got == null and want == null;
        if (!same and !isDeliberate(c.raw)) {
            std.debug.print("float '{s}': ours {?} reference {?}\n", .{ c.raw, got, want });
            bad += 1;
        }
    }
    for (ext.bool_cases) |c| {
        const got: ?[]const u8 = if (ini.boolValue(c.raw)) |b| (if (b) "true" else "false") else |_| null;
        if (!optEql(got, c.result)) {
            std.debug.print("bool '{s}': ours {?s} reference {?s}\n", .{ c.raw, got, c.result });
            bad += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

/// Non-ASCII digits: Python's `int` and `float` read them. Deliberately not
/// here (SPEC, § Deliberate divergences).
fn isDeliberate(raw: []const u8) bool {
    for (raw) |c| if (c >= 0x80) return true;
    return false;
}

fn optEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

/// What a key-file line holding `text` as its value reads as.
fn desktopValue(text: []const u8) ![]u8 {
    const line = try std.mem.concat(gpa, u8, &.{ "[g]\nk=", text, "\n" });
    defer gpa.free(line);
    var doc = try ini.parse(gpa, line, .desktop);
    defer doc.deinit();
    return gpa.dupe(u8, doc.get("g", "k").?);
}

test "ListOptions.desktop, getLocale, unescapeDesktop, escapeDesktop agree with GKeyFile" {
    var bad: usize = 0;
    for (ext.list_cases) |c| {
        var joined: std.ArrayList(u8) = .empty;
        defer joined.deinit(gpa);
        var got: ?[]const u8 = null;
        const raw = try desktopValue(c.raw);
        defer gpa.free(raw);
        if (ini.parseList(gpa, raw, .desktop)) |l_const| {
            var l = l_const;
            defer l.deinit(gpa);
            for (l.items) |it| {
                try joined.appendSlice(gpa, it);
                try joined.append(gpa, 0x1f);
            }
            got = joined.items;
        } else |e| switch (e) {
            error.InvalidEscape => {},
            else => return e,
        }
        if (!optEql(got, c.result)) {
            std.debug.print("list '{s}': ours {?s} reference {?s}\n", .{ c.raw, got, c.result });
            bad += 1;
        }
    }
    var doc = try ini.parse(gpa, ext.locale_doc, .desktop);
    defer doc.deinit();
    for (ext.locale_cases) |c| {
        const got = doc.getLocale("g", c.key, c.locale);
        if (!optEql(got, c.result)) {
            std.debug.print("locale {s} '{s}': ours {?s} reference {?s}\n", .{ c.key, c.locale, got, c.result });
            bad += 1;
        }
    }
    for (ext.unescape_cases) |c| {
        const raw = try desktopValue(c.raw);
        defer gpa.free(raw);
        var got: ?[]u8 = ini.unescapeDesktop(gpa, raw) catch |e| switch (e) {
            error.InvalidEscape => null,
            else => return e,
        };
        defer if (got) |g| gpa.free(g);
        if (!optEql(got, c.result)) {
            std.debug.print("unescape '{s}': ours {?s} reference {?s}\n", .{ c.raw, got, c.result });
            bad += 1;
        }
        _ = &got;
    }
    for (ext.escape_cases) |c| {
        const got = try ini.escapeDesktop(gpa, c.raw);
        defer gpa.free(got);
        if (!std.mem.eql(u8, got, c.result.?)) {
            std.debug.print("escape '{s}': ours {s} reference {s}\n", .{ c.raw, got, c.result.? });
            bad += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

// ── the live half ────────────────────────────────────────────────────────────

fn hexField(w: *std.Io.Writer, s: []const u8) !void {
    try w.print("{x}\t", .{s});
}

fn dumpOne(w: *std.Io.Writer, dialect: []const u8, text: []const u8, opts: ini.Options) !void {
    var doc = ini.parse(gpa, text, opts) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return, // The reference refuses too: the anchor test checks that.
    };
    defer doc.deinit();

    var plain: std.Io.Writer.Allocating = .init(gpa);
    defer plain.deinit();
    doc.write(gpa, &plain.writer, .{ .options = opts }) catch |e| switch (e) {
        error.NotRepresentable => return,
        else => return e,
    };

    var ed = try ini.Editor.init(gpa, text, opts);
    defer ed.deinit();
    const same = try ed.toOwnedSlice(gpa);
    defer gpa.free(same);
    // The edits a user makes: change a key that exists, add one, add a section,
    // remove one. The script applies the same to the reference's view.
    var changed: []const u8 = "";
    var removed: []const u8 = "";
    if (doc.sections.len != 0) {
        const s = &doc.sections[doc.sections.len - 1];
        if (s.entries.len != 0) {
            changed = s.entries[s.entries.len - 1].key;
            try ed.set(s.name, changed, "edited value");
        }
        try ed.set(s.name, "oracle_new", "new value");
    }
    try ed.set("oracle section", "oracle_key", "v1\tv2");
    if (doc.sections.len != 0) {
        const s = &doc.sections[0];
        if (s.entries.len != 0 and !std.mem.eql(u8, s.name, doc.sections[doc.sections.len - 1].name)) {
            removed = s.entries[0].key;
            _ = try ed.remove(s.name, removed);
        }
    }
    const edited = try ed.toOwnedSlice(gpa);
    defer gpa.free(edited);

    try w.print("{s}\t", .{dialect});
    try hexField(w, text);
    try hexField(w, plain.written());
    try hexField(w, same);
    try hexField(w, edited);
    try hexField(w, changed);
    try hexField(w, removed);
    try hexField(w, if (doc.sections.len != 0) doc.sections[doc.sections.len - 1].name else "");
    try w.print("{x}\n", .{if (doc.sections.len != 0) doc.sections[0].name else ""});
}

test "writer oracle: INI_WRITER_DUMP" {
    const path = testing.environ.getPosix("INI_WRITER_DUMP") orelse return error.SkipZigTest;
    const io = testing.io;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    for (goldens.cases) |c| {
        try dumpOne(&out.writer, "python", c.text, .python);
        try dumpOne(&out.writer, "desktop", c.text, .desktop);
    }
    for (ext.default_cases) |c| try dumpOne(&out.writer, "configparser", c.text, .configparser);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = out.written() });
}

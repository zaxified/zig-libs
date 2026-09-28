// SPDX-License-Identifier: MIT

//! The external anchor: `Options.python` and `Options.desktop` against what
//! Python's configparser and GLib's GKeyFile made of the same texts
//! (`testdata/goldens.zig`, captured by `tools/gen_goldens.py`: the probes
//! behind every rule in SPEC.md plus 600 seeded random INI-shaped texts).
//! A golden is the reference's merged view -- sections in first-appearance
//! order, each key once, in first-appearance order, with its last value --
//! or null where the reference refused the text; a strict parse must then
//! fail too.

const std = @import("std");
const ini = @import("root.zig");
const goldens = @import("testdata/goldens.zig");

const testing = std.testing;

/// The merged view, in the generator's `dump` format.
fn render(gpa: std.mem.Allocator, doc: *const ini.Document) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    for (doc.sections, 0..) |s, si| {
        if (firstSection(doc, s.name) != si) continue;
        try w.print("[{s}]\n", .{s.name});
        var keys: std.ArrayList([]const u8) = .empty;
        defer keys.deinit(gpa);
        var it = doc.entries(s.name);
        while (it.next()) |e| {
            for (keys.items) |k| {
                if (std.mem.eql(u8, k, e.key)) break;
            } else try keys.append(gpa, e.key);
        }
        for (keys.items) |k| {
            try w.print("{s}=", .{k});
            for (doc.get(s.name, k).?) |c| switch (c) {
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                else => try w.writeByte(c),
            };
            try w.writeByte('\n');
        }
    }
    return out.toOwnedSlice();
}

fn firstSection(doc: *const ini.Document, name: []const u8) usize {
    for (doc.sections, 0..) |s, i| if (std.mem.eql(u8, s.name, name)) return i;
    unreachable;
}

fn check(text: []const u8, opts: ini.Options, want: ?[]const u8, label: []const u8) !bool {
    var doc = ini.parse(testing.allocator, text, opts) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {
            if (want == null) return true;
            std.debug.print("{s}: refused {x}, reference read:\n{s}\n", .{ label, text, want.? });
            return false;
        },
    };
    defer doc.deinit();
    const got = try render(testing.allocator, &doc);
    defer testing.allocator.free(got);
    if (want) |w| if (std.mem.eql(u8, w, got)) return true;
    std.debug.print("{s}: {x}\n  ours:\n{s}  reference:\n{?s}\n", .{ label, text, got, want });
    return false;
}

test "external anchor: Options.python agrees with configparser, Options.desktop with GKeyFile" {
    var bad: usize = 0;
    var refused = [2]usize{ 0, 0 };
    for (goldens.cases) |c| {
        if (!try check(c.text, .python, c.python, "python")) bad += 1;
        if (!try check(c.text, .desktop, c.desktop, "desktop")) bad += 1;
        if (c.python == null) refused[0] += 1;
        if (c.desktop == null) refused[1] += 1;
    }
    try testing.expectEqual(@as(usize, 0), bad);
    // Both halves of the corpus are exercised -- texts each reference accepts
    // and texts it refuses -- so neither "we accept everything" nor "we refuse
    // everything" could pass. Pinned, so a regenerated corpus that loses one
    // half shows here.
    try testing.expectEqual(@as(usize, 905), goldens.cases.len);
    try testing.expectEqual([2]usize{ 293, 377 }, refused);
}

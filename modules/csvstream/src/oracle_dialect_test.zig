// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for the dialect options (S2, 2026-10-20):
//! Go `encoding/csv` (`Comment`, `TrimLeadingSpace`, `LazyQuotes = false`)
//! and Python `csv` (`skipinitialspace`, `escapechar` + `doublequote=False`,
//! `QUOTE_ALL`) as black boxes over this module's own inputs
//! (`tools/oracle.py --dialect`, answers frozen in `oracle_dialect_vectors.zig`).
//!
//! Each input is read in span mode (both other readers span quoted
//! newlines) with the matching option and split with the matching
//! `SplitOptions`; the records must equal every reference that answered,
//! except in the classes listed at each `continue` below.

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const csv = @import("root.zig");
const vectors = @import("oracle_dialect_vectors.zig");

const Records = []const []const []const u8;

const Ours = struct { records: ?Records, unbalanced: bool };

fn readAll(arena: mem.Allocator, c: vectors.ReadCase) !Ours {
    var cfg: csv.SpanConfig = .{};
    var split: csv.SplitOptions = .{};
    switch (c.dialect) {
        .comment => cfg.comment = '#',
        .trim => {
            cfg.trim = .leading;
            split.trim = .leading;
        },
        .strict => split.strict = true,
        .escape => {
            cfg.escape = '\\';
            cfg.double_quote = false;
            split.escape = '\\';
            split.double_quote = false;
        },
    }
    var it = csv.LineIterator.initSpan(c.text, '"', 0, cfg);
    var recs: std.ArrayList([]const []const u8) = .empty;
    var unbalanced = false;
    while (it.next()) |ls| {
        unbalanced = unbalanced or ls.unbalanced_quote;
        const buf = try arena.alloc([]const u8, 64);
        const fields = csv.splitFieldsOpts(ls.bytes, buf, ',', '"', arena, split) catch |err| switch (err) {
            error.BareQuote, error.ExtraneousQuote, error.UnterminatedQuote => return .{ .records = null, .unbalanced = unbalanced },
            else => return err,
        };
        try recs.append(arena, try arena.dupe([]const u8, fields));
    }
    return .{ .records = recs.items, .unbalanced = unbalanced };
}

fn eqlRecords(a: ?Records, b: ?Records) bool {
    if (a == null or b == null) return a == null and b == null;
    if (a.?.len != b.?.len) return false;
    for (a.?, b.?) |ra, rb| {
        if (ra.len != rb.len) return false;
        for (ra, rb) |fa, fb| if (!mem.eql(u8, fa, fb)) return false;
    }
    return true;
}

/// Does `ours` match the reference answer? `.none` = not asked.
fn matches(ours: ?Records, ref: vectors.Answer) ?bool {
    return switch (ref) {
        .none => null,
        .err => ours == null,
        .ok => |r| eqlRecords(ours, r),
    };
}

fn printAnswer(label: []const u8, r: ?Records) void {
    std.debug.print("   {s}:", .{label});
    const recs = r orelse return std.debug.print(" ERR\n", .{});
    for (recs) |rec| {
        std.debug.print(" [", .{});
        for (rec, 0..) |f, i| std.debug.print("{s}{f}", .{ if (i == 0) "" else ",", std.zig.fmtString(f) });
        std.debug.print("]", .{});
    }
    std.debug.print("\n", .{});
}

fn refRecords(a: vectors.Answer) ?Records {
    return switch (a) {
        .ok => |r| r,
        else => null,
    };
}

test "oracle: dialect options read as Go and Python read them" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var agree: [4]usize = @splat(0);
    var bad: usize = 0;
    var unbalanced: usize = 0;
    var like_one: usize = 0;
    for (vectors.reads) |c| {
        const ours = try readAll(arena, c);
        // Python yields an empty record for a blank line; Go skips it, and
        // so does `LineIterator` (the class `oracle_test.zig` lists too).
        const py: vectors.Answer = switch (c.py) {
            .ok => |recs| blk: {
                var kept: std.ArrayList([]const []const u8) = .empty;
                for (recs) |r| if (r.len != 0) try kept.append(arena, r);
                break :blk .{ .ok = kept.items };
            },
            else => c.py,
        };
        const m_py = matches(ours.records, py);
        const m_go = matches(ours.records, c.go);
        if ((m_py orelse true) and (m_go orelse true)) {
            agree[@backingInt(c.dialect)] += 1;
            continue;
        }
        // Python and Go disagree with each other (lazy quote handling, e.g.
        // `""a"`): we must give one of their answers.
        if ((m_py orelse false) or (m_go orelse false)) {
            like_one += 1;
            continue;
        }
        // A quote left open to the end of input: Python and Go take every
        // byte after it into the field; span mode ends that record at its
        // first line break and flags it -- the documented bound, a stray
        // quote costs one record. (Under `strict` we refuse it, as Go does.)
        if (ours.unbalanced) {
            unbalanced += 1;
            continue;
        }
        bad += 1;
        if (bad <= 40) {
            std.debug.print("{t} {f}\n", .{ c.dialect, std.zig.fmtString(c.text) });
            if (c.py != .none) printAnswer("py  ", refRecords(c.py));
            if (c.go != .none) printAnswer("go  ", refRecords(c.go));
            printAnswer("ours", ours.records);
        }
    }
    if (bad != 0) std.debug.print("dialect reads: agree comment {d} trim {d} strict {d} escape {d}; {d} like one of them, {d} unbalanced, {d} bad\n", .{ agree[0], agree[1], agree[2], agree[3], like_one, unbalanced, bad });
    try testing.expectEqual(@as(usize, 0), bad);
    // 2026-10-20: comment 1463, trim 1407, strict 1571, escape 300 agree with
    // every reference; 3 like one of them, 269 unbalanced. Mostly agreement.
    try testing.expect(agree[0] >= 1400 and agree[1] >= 1350 and agree[2] >= 1500 and agree[3] >= 290);
}

test "oracle: QUOTE_ALL and escape-dialect writes are Python's bytes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var bad: usize = 0;
    for (vectors.writes) |c| {
        var a: std.Io.Writer.Allocating = .init(arena);
        try csv.writeRecord(&a.writer, c.fields, .{ .quote_style = .always, .line_terminator = .lf });
        var e: std.Io.Writer.Allocating = .init(arena);
        try csv.writeRecord(&e.writer, c.fields, .{ .quote_style = .always, .line_terminator = .lf, .escape = '\\' });
        if (mem.eql(u8, a.written(), c.all) and mem.eql(u8, e.written(), c.all_escaped)) continue;
        bad += 1;
        if (bad <= 30) std.debug.print("fields {any}: py {f} / {f}; ours {f} / {f}\n", .{
            c.fields, std.zig.fmtString(c.all), std.zig.fmtString(c.all_escaped), std.zig.fmtString(a.written()), std.zig.fmtString(e.written()),
        });
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: the reference JSON5 implementation (the
//! `json5` package of the JSON5 project, run under bun as a black box) on
//! documents generated from the JSON5 grammar plus single-character
//! mutations of them (`tools/ref_oracle.js`). Its answers -- the value each
//! document parses to, or a refusal -- are in `ref_oracle_vectors.zig` in a
//! canonical text (see the script's header) that this file reproduces from
//! `preprocess` + `std.json`. No bun at test time.
//!
//! Run with `non_finite = .quoted`, so Infinity/NaN compare as the strings
//! both sides write them as. Three outcomes are checked:
//!  - the reference parses `src`: `preprocess` + `std.json` must give the
//!    same value -- numbers as IEEE-754 doubles (sign of zero included),
//!    strings as UTF-16 code units, objects by key with the last duplicate
//!    winning;
//!  - the reference refuses `src` and so do we: agreement;
//!  - the reference refuses `src` and we produce JSON: allowed ONLY when the
//!    output carries this module's own recovery marker (`$err_trace_`), the
//!    documented design for malformed config input. Valid-looking JSON from
//!    a document the reference refuses is a finding.
//! Every other difference must be listed in `divergences`.

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const json5 = @import("root.zig");
const vectors = @import("ref_oracle_vectors.zig");

const Divergence = struct { src: []const u8, why: []const u8 };

const divergences = [_]Divergence{};

/// The one class of difference left, by its content rather than one entry
/// per document: the reference's value holds an UNPAIRED surrogate code unit
/// (`'\uD800'`, `"\uDC00"`), which a JS string can hold and UTF-8 cannot.
/// `preprocess` passes the escape through unchanged -- it is JSON syntax --
/// and `std.json` refuses it (pinned by the test below), so the document is
/// refused. Not this module's choice to make: rewriting it to U+FFFD would
/// change the value silently.
fn holdsLoneSurrogate(canon_text: []const u8) bool {
    var i: usize = 0;
    while (mem.indexOfScalarPos(u8, canon_text, i, 's')) |at| {
        var j = at + 1;
        var prev_high = false;
        while (j + 4 <= canon_text.len and canon_text[j] != ';') : (j += 4) {
            const u = std.fmt.parseInt(u16, canon_text[j..][0..4], 16) catch return false;
            const high = u >= 0xD800 and u <= 0xDBFF;
            const low = u >= 0xDC00 and u <= 0xDFFF;
            if (prev_high and !low) return true;
            if (low and !prev_high) return true;
            prev_high = high;
        }
        if (prev_high) return true;
        i = j + 1;
    }
    return false;
}

test "ref oracle: std.json refuses an unpaired surrogate escape (why holdsLoneSurrogate is a divergence)" {
    for ([_][]const u8{ "\"\\ud800\"", "\"\\udc00\"", "\"a\\ud800b\"" }) |doc| {
        try testing.expect(std.json.parseFromSlice(std.json.Value, testing.allocator, doc, .{}) == error.SyntaxError or
            std.meta.isError(std.json.parseFromSlice(std.json.Value, testing.allocator, doc, .{})));
    }
}

fn writeUnits(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('s');
    var it = std.unicode.Wtf8View.initUnchecked(s).iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp >= 0x10000) {
            const v = cp - 0x10000;
            try w.print("{x:0>4}{x:0>4}", .{ 0xD800 + (v >> 10), 0xDC00 + (v & 0x3ff) });
        } else try w.print("{x:0>4}", .{cp});
    }
    try w.writeByte(';');
}

fn writeNumber(w: *std.Io.Writer, text: []const u8) !void {
    const f = std.fmt.parseFloat(f64, text) catch return error.BadNumber;
    if (std.math.isNan(f)) return writeUnits(w, "NaN");
    if (std.math.isInf(f)) return writeUnits(w, if (f > 0) "Infinity" else "-Infinity");
    try w.print("n{x:0>16}", .{@as(u64, @bitCast(f))});
}

fn keyLess(_: void, a: []const u8, b: []const u8) bool {
    return mem.order(u8, a, b) == .lt;
}

fn canon(gpa: mem.Allocator, w: *std.Io.Writer, v: std.json.Value) !void {
    switch (v) {
        .null => try w.writeByte('z'),
        .bool => |b| try w.writeByte(if (b) 't' else 'f'),
        .number_string => |t| try writeNumber(w, t),
        .integer, .float => unreachable, // parse_numbers = false
        .string => |s| try writeUnits(w, s),
        .array => |a| {
            try w.writeByte('[');
            for (a.items, 0..) |x, i| {
                if (i != 0) try w.writeByte(',');
                try canon(gpa, w, x);
            }
            try w.writeByte(']');
        },
        .object => |o| {
            // Sort by the key's code units: the hex digits of each unit are
            // fixed-width, so ordering the hex text orders the units, and a
            // proper prefix sorts first as it does in the generator.
            const Member = struct { hex: []const u8, value: std.json.Value };
            var members: std.ArrayList(Member) = .empty;
            defer {
                for (members.items) |m| gpa.free(m.hex);
                members.deinit(gpa);
            }
            var it = o.iterator();
            while (it.next()) |e| {
                var kw: std.Io.Writer.Allocating = .init(gpa);
                try writeUnits(&kw.writer, e.key_ptr.*);
                const full = try kw.toOwnedSlice();
                try members.append(gpa, .{ .hex = full, .value = e.value_ptr.* });
            }
            mem.sort(Member, members.items, {}, struct {
                fn less(_: void, a: Member, b: Member) bool {
                    return keyLess({}, a.hex[1 .. a.hex.len - 1], b.hex[1 .. b.hex.len - 1]);
                }
            }.less);
            try w.writeByte('{');
            for (members.items, 0..) |m, i| {
                if (i != 0) try w.writeByte(',');
                try w.writeAll(m.hex);
                try w.writeByte('=');
                try canon(gpa, w, m.value);
            }
            try w.writeByte('}');
        },
    }
}

const Ours = union(enum) { refused, recovered, value: []u8 };

fn ours(gpa: mem.Allocator, src: []const u8) !Ours {
    const out = json5.preprocessWithOptions(gpa, src, .{ .non_finite = .quoted }) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return .refused,
    };
    defer gpa.free(out);
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, out, .{
        .duplicate_field_behavior = .use_last,
        .parse_numbers = false,
    }) catch return .refused;
    defer parsed.deinit();
    if (mem.indexOf(u8, out, "$err_trace_") != null) return .recovered;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    try canon(gpa, &aw.writer, parsed.value);
    return .{ .value = try aw.toOwnedSlice() };
}

test "ref oracle: preprocess + std.json read every document as the reference JSON5 does" {
    const gpa = testing.allocator;
    var seen = [_]bool{false} ** divergences.len;
    var bad: usize = 0;
    var agreed_values: usize = 0;
    var recovered: usize = 0;
    var lone_surrogates: usize = 0;
    for (vectors.cases) |c| {
        const got = try ours(gpa, c.src);
        defer if (got == .value) gpa.free(got.value);
        const agree = if (c.ref) |r| switch (got) {
            .value => |v| mem.eql(u8, v, r),
            .refused, .recovered => false,
        } else switch (got) {
            .refused => true,
            .recovered => blk: {
                recovered += 1;
                break :blk true;
            },
            .value => false,
        };
        if (agree) {
            if (c.ref != null) agreed_values += 1;
            continue;
        }
        if (got == .refused and c.ref != null and holdsLoneSurrogate(c.ref.?)) {
            lone_surrogates += 1;
            continue;
        }
        var listed = false;
        for (divergences, 0..) |d, i| if (mem.eql(u8, d.src, c.src)) {
            seen[i] = true;
            listed = true;
        };
        if (listed) continue;
        bad += 1;
        if (bad <= 60) std.debug.print("src {f}: ref {?s}, ours {s}\n", .{
            std.zig.fmtString(c.src), c.ref,
            switch (got) {
                .refused => "refused",
                .recovered => "recovered ($err_trace_)",
                .value => |v| v,
            },
        });
    }
    for (divergences, seen) |d, s| if (!s) {
        std.debug.print("divergence {f} agrees now: delete it\n", .{std.zig.fmtString(d.src)});
        bad += 1;
    };
    if (bad != 0) std.debug.print("{d} differ; {d} values agree, {d} refusals met by recovery\n", .{ bad, agreed_values, recovered });
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expect(lone_surrogates > 0); // the class is still exercised
    // 2026-10-05: 1106 values agree (of 1204 the reference accepts), the rest
    // hold a lone surrogate; most of the evidence is agreement.
    try testing.expect(agreed_values >= 1000);
}

/// The first `line N` an `$err` message of `out` names.
fn firstReportedLine(out: []const u8) ?u32 {
    var i: usize = 0;
    while (mem.indexOfPos(u8, out, i, "line ")) |at| {
        var j = at + 5;
        while (j < out.len and std.ascii.isDigit(out[j])) j += 1;
        if (j > at + 5) return std.fmt.parseInt(u32, out[at + 5 .. j], 10) catch null;
        i = at + 5;
    }
    return null;
}

test "ref oracle: the editor mode never turns a refused document into valid JSON, and reports where the reference stops" {
    // Every document the reference refuses, through `preprocessAnnotated`:
    // the output must be refused by `std.json` too, or carry `$err` entries
    // -- and then the first one names the line the reference's SyntaxError
    // names. One class: TOKEN_START -- the reference reports the position
    // just PAST the line terminator that broke a key or an escape (column
    // 0 or 1 of the next line), this module the line the broken token
    // starts on.
    //
    // ⛔ 56 documents came out valid with no `$err` at all (2026-10-06): a
    // bad bare word or a single-quoted string broken by a newline, outside
    // an object, was recovered with nowhere to report it -- `nul` became
    // `"nul"`, `[tru]` became `["tru"]`.
    const gpa = testing.allocator;
    var refused: usize = 0;
    var same_line: usize = 0;
    var token_start: usize = 0;
    var bad: usize = 0;
    for (vectors.cases) |c| {
        if (c.ref != null) continue;
        const r = try json5.preprocessAnnotated(gpa, c.src);
        defer gpa.free(r.out);
        const parsed = std.json.parseFromSlice(std.json.Value, gpa, r.out, .{}) catch {
            refused += 1;
            continue;
        };
        parsed.deinit();
        const line = if (r.next_id > 1) firstReportedLine(r.out) else null;
        if (line) |l| {
            if (l == c.line) {
                same_line += 1;
                continue;
            }
            if (l + 1 == c.line and c.column <= 1) {
                token_start += 1;
                continue;
            }
        }
        bad += 1;
        std.debug.print("refused by the reference at {d}:{d}, annotated gives {?d}: src={f}\n    out={s}\n", .{ c.line, c.column, line, std.json.fmt(c.src, .{}), r.out });
    }
    try testing.expectEqual(@as(usize, 0), bad);
    // Pinned so a regenerated corpus that stopped reaching either branch shows.
    try testing.expect(same_line >= 50);
    try testing.expect(token_start >= 1);
    try testing.expect(refused >= 1000);
}

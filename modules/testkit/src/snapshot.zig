// SPDX-License-Identifier: MIT
//! Inline snapshots with an update workflow (insta / ohsnap style).
//!
//! ```zig
//! try testkit.expectSnapshot(@src(), "old text", actual);
//! try testkit.expectSnapshot(@src(),
//!     \\line one
//!     \\line two
//! , actual);
//! try testkit.expectSnapshotHex(@src(), "deadbeef", bytes);
//! ```
//!
//! The expected value is a literal at the call site, directly after `@src()`.
//! A mismatch fails with a diff (`golden.zig`'s first-difference offset and
//! window for bytes, the first differing line for text) and the one-line
//! command that accepts the new value. Run with `TESTKIT_SNAPSHOT=update` and
//! the mismatch instead REWRITES that literal in the source file, in place and
//! atomically (temp file + rename), choosing `"..."` or the `\\` multiline
//! form; the next run is green and a second update changes nothing.
//!
//! ## How the literal is found
//!
//! `@src()` yields file, line and column of the `@src()` token. The file is
//! relative to the *module root directory* (the directory of the module's root
//! source file), which a test binary does not know; measured 2026-11-15, in a
//! build-system test run `@src().file` was `probe.zig` for
//! `modules/testkit/src/probe.zig` and the cwd was the repository root.
//! So the path is resolved by search from the repository root (the nearest
//! ancestor of the cwd holding a `build.zig`): `<root>/<file>`,
//! `<root>/src/<file>` and `modules/<m>/{src,.,tools,example}/<file>` for every
//! module, and a candidate counts only when the text at line:column really is
//! `@src()` followed by a literal that decodes to exactly the `expected`
//! argument. Exactly one such candidate is used; none is
//! `error.SnapshotSourceNotFound`, several `error.SnapshotAmbiguous`
//! (`TESTKIT_SNAPSHOT_ROOT=<dir relative to the repo root>` names the module's
//! source directory and ends the search). Nothing outside the repository root
//! is ever opened for writing: the file name and the override must be relative
//! and free of `..`.
//!
//! Several snapshots in one file are updated in one run: the first touch of a
//! file keeps its original text, line and column are looked up in THAT text and
//! shifted by the edits already made before them. The same snapshot location
//! reached twice with different values (a helper called in a loop) is
//! `error.SnapshotConflict`, never a silent last-write-wins.
//!
//! Bounds: a source file up to `max_source` (4 MiB), an actual value up to
//! `max_actual` (1 MiB) in update mode; more is an error, not a panic.
//!
//! Not done: a review mode with a `.snap.new` side file. The update rewrite is
//! reviewed with `git diff`, which is the review tool the repository already
//! has.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const golden = @import("golden.zig");
const hex = @import("hex.zig");

/// Environment variable: unset or empty compares; `update` rewrites.
pub const env_name = "TESTKIT_SNAPSHOT";
/// Environment variable naming the module source directory, relative to the
/// repository root (ends the candidate search).
pub const root_env_name = "TESTKIT_SNAPSHOT_ROOT";
/// Largest source file read for an update.
pub const max_source: usize = 4 << 20;
/// Largest actual value an update writes.
pub const max_actual: usize = 1 << 20;
/// Bytes of a text line shown in a failure message.
pub const excerpt_len: usize = 200;
/// Bytes of hex per line in a rewritten multiline hex snapshot.
pub const hex_line_bytes: usize = 32;

pub const Error = error{
    TestExpectedEqual,
    SnapshotModeUnknown,
    SnapshotSourceNotFound,
    SnapshotAmbiguous,
    SnapshotSourceChanged,
    SnapshotNotLiteral,
    SnapshotLiteralMismatch,
    SnapshotTooLarge,
    SnapshotConflict,
    SnapshotBadPath,
    SnapshotIo,
    OutOfMemory,
    InvalidCharacter,
    InvalidLength,
};

pub const Kind = enum { text, hex };
pub const Mode = enum { compare, update };

/// The decision, split from the environment read (like `verboseEnabled`).
/// An unrecognised value is an error: a typo must not mean "compare".
pub fn modeOf(raw: ?[]const u8) error{SnapshotModeUnknown}!Mode {
    const v = raw orelse return .compare;
    if (v.len == 0) return .compare;
    if (std.mem.eql(u8, v, "update")) return .update;
    return error.SnapshotModeUnknown;
}

// ── public API ───────────────────────────────────────────────────────────

/// Compare `actual` against the text literal following `@src()`.
pub fn expectSnapshot(src: std.builtin.SourceLocation, expected: []const u8, actual: []const u8) Error!void {
    return check(.text, src, expected, actual);
}

/// Compare `actual` bytes against the hex literal following `@src()`. The
/// literal may be split over lines (whitespace is ignored when decoding).
pub fn expectSnapshotHex(src: std.builtin.SourceLocation, expected_hex: []const u8, actual: []const u8) Error!void {
    return check(.hex, src, expected_hex, actual);
}

fn check(kind: Kind, src: std.builtin.SourceLocation, expected: []const u8, actual: []const u8) Error!void {
    const mode = modeOf(envGet(env_name)) catch |e| {
        std.debug.print("\n{s} must be unset or `update`\n", .{env_name});
        return e;
    };
    const same = matches(std.heap.page_allocator, kind, expected, actual) catch |e| switch (e) { // global-alloc-ok: called only from `test` blocks via expectSnapshot*; the compare holds no state past the call
        // A malformed or missing hex literal is repaired by an update; compared, it is an error.
        error.InvalidCharacter, error.InvalidLength => blk: {
            if (mode == .compare) {
                std.debug.print("\nsnapshot at {s}:{d}:{d}: the hex literal is not valid hex ({t})\n", .{ src.file, src.line, src.column, e });
                return e;
            }
            break :blk false;
        },
        else => return e,
    };
    if (same) return;
    switch (mode) {
        .compare => {
            var buf: [4096]u8 = undefined;
            var w: Io.Writer = .fixed(&buf);
            writeReport(&w, kind, src.file, src.line, src.column, expected, actual) catch {};
            std.debug.print("{s}", .{w.buffered()});
            return error.TestExpectedEqual;
        },
        .update => {
            updateSource(kind, src, expected, actual) catch |e| {
                std.debug.print("\n{s}=update: cannot rewrite the snapshot at {s}:{d}:{d} ({t})\n", .{ env_name, src.file, src.line, src.column, e });
                return e;
            };
            std.debug.print("\n{s}=update: rewrote the snapshot at {s}:{d}\n", .{ env_name, src.file, src.line });
        },
    }
}

/// The silent verdict: whether `actual` equals what the literal says.
/// For hex, the literal is decoded first.
pub fn matches(gpa: std.mem.Allocator, kind: Kind, expected: []const u8, actual: []const u8) Error!bool {
    switch (kind) {
        .text => return std.mem.eql(u8, expected, actual),
        .hex => {
            const bytes = try hexBytes(gpa, expected);
            defer gpa.free(bytes);
            return std.mem.eql(u8, bytes, actual);
        },
    }
}

/// Decode a hex literal, ignoring ASCII whitespace (multiline literals).
pub fn hexBytes(gpa: std.mem.Allocator, s: []const u8) Error![]u8 {
    var digits = try gpa.alloc(u8, s.len);
    defer gpa.free(digits);
    var n: usize = 0;
    for (s) |c| {
        if (isWs(c)) continue;
        digits[n] = c;
        n += 1;
    }
    if (n % 2 != 0) return error.InvalidLength;
    const out = try gpa.alloc(u8, n / 2);
    errdefer gpa.free(out);
    _ = std.fmt.hexToBytes(out, digits[0..n]) catch |e| switch (e) {
        error.InvalidCharacter => return error.InvalidCharacter,
        else => return error.InvalidLength,
    };
    return out;
}

// ── failure message ──────────────────────────────────────────────────────

/// Everything printed when a snapshot does not match. A pure function over a
/// writer, so the format is tested without writing to stderr.
pub fn writeReport(
    w: *Io.Writer,
    kind: Kind,
    file: []const u8,
    line: u32,
    column: u32,
    expected: []const u8,
    actual: []const u8,
) Io.Writer.Error!void {
    try w.print("\nsnapshot mismatch at {s}:{d}:{d}\n", .{ file, line, column });
    switch (kind) {
        .text => try writeTextDiff(w, expected, actual),
        .hex => try writeHexDiff(w, expected, actual),
    }
    try w.print("  update: {s}=update <the command that ran this test> (e.g. {s}=update scripts/modtest <module>)\n", .{ env_name, env_name });
}

fn writeTextDiff(w: *Io.Writer, expected: []const u8, actual: []const u8) Io.Writer.Error!void {
    // The first differing byte, not `golden.diff`'s verdict: for text a length
    // difference may hide an earlier changed byte, and the line is what matters.
    const at = std.mem.findDiff(u8, expected, actual) orelse return;
    // Both sides agree up to `at`, so the line number and the line start are shared.
    const prefix = expected[0..at];
    const line_no = std.mem.count(u8, prefix, "\n") + 1;
    const ls = if (std.mem.findLast(u8, prefix, "\n")) |p| p + 1 else 0;
    try w.print("  first difference: line {d}, byte offset {d} (expected {d} bytes, got {d} bytes)\n", .{ line_no, at, expected.len, actual.len });
    if (at == expected.len) {
        try w.writeAll("  expected ends here; actual continues: ");
        try writeExcerpt(w, actual[at..]);
    } else if (at == actual.len) {
        try w.writeAll("  actual ends here; expected continues: ");
        try writeExcerpt(w, expected[at..]);
    } else {
        try w.writeAll("  expected: ");
        try writeExcerpt(w, lineFrom(expected, ls));
        try w.writeAll("\n  actual:   ");
        try writeExcerpt(w, lineFrom(actual, ls));
    }
    try w.writeByte('\n');
}

fn lineFrom(s: []const u8, start: usize) []const u8 {
    const rest = s[@min(start, s.len)..];
    return rest[0 .. std.mem.findScalar(u8, rest, '\n') orelse rest.len];
}

fn writeExcerpt(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    const cut = s.len > excerpt_len;
    try w.writeByte('"');
    try writeEscaped(w, s[0..@min(s.len, excerpt_len)]);
    try w.writeByte('"');
    if (cut) try w.writeAll("...");
}

fn writeHexDiff(w: *Io.Writer, expected_hex: []const u8, actual: []const u8) Io.Writer.Error!void {
    // The decode already succeeded in `check`; a failure here (a hand-built
    // call of this function) is shown rather than hidden.
    const expected = hexBytes(std.heap.page_allocator, expected_hex) catch |e| { // global-alloc-ok: failure-report path of expectSnapshotHex, called only from `test` blocks
        return w.print("  the hex literal does not decode ({t})\n", .{e});
    };
    defer std.heap.page_allocator.free(expected); // global-alloc-ok: frees the line-244 decode
    const m = golden.diff(expected, actual) orelse return;
    const at = switch (m) {
        .length => |l| @min(l.expected, l.actual),
        .byte => |b| b,
    };
    switch (m) {
        .length => |l| try w.print("  length mismatch: expected {d} bytes, got {d}\n", .{ l.expected, l.actual }),
        .byte => try w.print("  first difference at offset {d} (0x{x}): expected 0x{x:0>2}, got 0x{x:0>2}\n", .{ at, at, expected[at], actual[at] }),
    }
    var eb: [16 * golden.window]u8 = undefined;
    var ab: [16 * golden.window]u8 = undefined;
    try w.print("  offset {d}..\n", .{at -| golden.window});
    try w.print("  expected: {s}\n", .{golden.render(&eb, expected, at)});
    try w.print("  actual:   {s}\n", .{golden.render(&ab, actual, at)});
}

// ── literal generation ───────────────────────────────────────────────────

/// Write `s` as the body of a Zig string literal (no quotes). Valid UTF-8 stays
/// as it is; a value that is not valid UTF-8 escapes every byte >= 0x80.
fn writeEscaped(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    const utf8 = std.unicode.utf8ValidateSlice(s);
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0...8, 11, 12, 14...31, 127 => try w.print("\\x{x:0>2}", .{c}),
        128...255 => if (utf8) try w.writeByte(c) else try w.print("\\x{x:0>2}", .{c}),
        else => try w.writeByte(c),
    };
}

/// Whether `s` can be written as `\\` lines and read back unchanged: it has a
/// newline, is valid UTF-8, and holds no control byte but the newline (a tab or
/// a carriage return in a multiline literal is at the tokenizer's mercy).
fn multilineSafe(s: []const u8) bool {
    if (std.mem.findScalar(u8, s, '\n') == null) return false;
    if (!std.unicode.utf8ValidateSlice(s)) return false;
    for (s) |c| {
        if (c == '\n') continue;
        if (c < 32 or c == 127) return false;
    }
    return true;
}

/// The text that goes between the comma after `@src()` and the comma after the
/// literal. `indent` is the indentation of the line holding `@src()`.
fn renderRegion(gpa: std.mem.Allocator, kind: Kind, actual: []const u8, indent: []const u8, eol: []const u8) Error![]u8 {
    var aw: Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    renderInto(&aw.writer, kind, actual, indent, eol) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

fn renderInto(w: *Io.Writer, kind: Kind, actual: []const u8, indent: []const u8, eol: []const u8) Io.Writer.Error!void {
    switch (kind) {
        .text => if (multilineSafe(actual)) {
            var it = std.mem.splitScalar(u8, actual, '\n');
            while (it.next()) |l| {
                try w.writeAll(eol);
                try w.print("{s}    \\\\{s}", .{ indent, l });
            }
            try w.print("{s}{s}", .{ eol, indent });
        } else {
            try w.writeAll(" \"");
            try writeEscaped(w, actual);
            try w.writeByte('"');
        },
        .hex => if (actual.len <= hex_line_bytes) {
            try w.writeAll(" \"");
            for (actual) |c| try w.print("{x:0>2}", .{c});
            try w.writeByte('"');
        } else {
            var i: usize = 0;
            while (i < actual.len) : (i += hex_line_bytes) {
                try w.writeAll(eol);
                try w.print("{s}    \\\\", .{indent});
                for (actual[i..@min(actual.len, i + hex_line_bytes)]) |c| try w.print("{x:0>2}", .{c});
            }
            try w.print("{s}{s}", .{ eol, indent });
        },
    }
}

// ── locating the literal in the source ───────────────────────────────────

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

fn skipWs(text: []const u8, from: usize) usize {
    var i = from;
    while (i < text.len and isWs(text[i])) i += 1;
    return i;
}

const Located = struct {
    /// Offset of the `@` of `@src()`.
    at: usize,
    /// Offset just after the comma that follows `@src()`.
    region_start: usize,
    /// Offset of the comma that follows the literal.
    region_end: usize,
    lit_start: usize,
    /// Exclusive; for a multiline literal the end of the last line's content.
    lit_end: usize,
    multiline: bool,
};

/// Offset of 1-based `line`, `column` (in bytes), or null when outside `text`.
fn offsetOf(text: []const u8, line: u32, column: u32) ?usize {
    if (line == 0 or column == 0) return null;
    var start: usize = 0;
    var l: u32 = 1;
    while (l < line) : (l += 1) {
        const nl = std.mem.findScalar(u8, text[start..], '\n') orelse return null;
        start += nl + 1;
    }
    const off = start + (column - 1);
    return if (off < text.len) off else null;
}

const call = "@src()";

fn locate(text: []const u8, line: u32, column: u32) error{ SnapshotSourceChanged, SnapshotNotLiteral }!Located {
    const at = offsetOf(text, line, column) orelse return error.SnapshotSourceChanged;
    return locateAt(text, at);
}

fn locateAt(text: []const u8, at: usize) error{ SnapshotSourceChanged, SnapshotNotLiteral }!Located {
    if (at >= text.len) return error.SnapshotSourceChanged;
    if (!std.mem.startsWith(u8, text[at..], call)) return error.SnapshotSourceChanged;
    var i = skipWs(text, at + call.len);
    if (i >= text.len or text[i] != ',') return error.SnapshotNotLiteral;
    const region_start = i + 1;
    i = skipWs(text, region_start);
    const lit_start = i;
    if (i >= text.len) return error.SnapshotNotLiteral;
    var multiline = false;
    var lit_end: usize = undefined;
    if (text[i] == '"') {
        i += 1;
        while (true) {
            if (i >= text.len) return error.SnapshotNotLiteral;
            const c = text[i];
            if (c == '\n') return error.SnapshotNotLiteral;
            if (c == '\\') {
                if (i + 1 >= text.len or text[i + 1] == '\n') return error.SnapshotNotLiteral;
                i += 2;
                continue;
            }
            i += 1;
            if (c == '"') break;
        }
        lit_end = i;
    } else if (std.mem.startsWith(u8, text[i..], "\\\\")) {
        multiline = true;
        while (true) {
            const nl = std.mem.findScalar(u8, text[i..], '\n');
            const line_end = if (nl) |n| i + n else text.len;
            lit_end = if (line_end > i and text[line_end - 1] == '\r') line_end - 1 else line_end;
            if (nl == null) break;
            var j = line_end + 1;
            while (j < text.len and (text[j] == ' ' or text[j] == '\t')) j += 1;
            if (!std.mem.startsWith(u8, text[j..], "\\\\")) break;
            i = j;
        }
    } else return error.SnapshotNotLiteral;
    const k = skipWs(text, lit_end);
    if (k >= text.len or text[k] != ',') return error.SnapshotNotLiteral;
    return .{ .at = at, .region_start = region_start, .region_end = k, .lit_start = lit_start, .lit_end = lit_end, .multiline = multiline };
}

/// The value the located literal denotes.
fn decode(gpa: std.mem.Allocator, text: []const u8, loc: Located) Error![]u8 {
    if (!loc.multiline) {
        return std.zig.string_literal.parseAlloc(gpa, text[loc.lit_start..loc.lit_end]) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.SnapshotNotLiteral,
        };
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var p = loc.lit_start;
    var first = true;
    while (true) {
        if (!first) try out.append(gpa, '\n');
        first = false;
        var e = p + 2;
        while (e < loc.lit_end and text[e] != '\n') e += 1;
        const content_end = if (e > p + 2 and text[e - 1] == '\r' and e < loc.lit_end) e - 1 else e;
        try out.appendSlice(gpa, text[p + 2 .. content_end]);
        if (e >= loc.lit_end) break;
        p = e + 1;
        while (text[p] == ' ' or text[p] == '\t') p += 1;
    }
    return out.toOwnedSlice(gpa);
}

// ── rewriting the file ───────────────────────────────────────────────────

const Edit = struct {
    orig_start: usize,
    orig_end: usize,
    new_len: usize,
    /// The value written, to tell a repeat from a conflict.
    value: []u8,
};

const FileState = struct {
    path: []u8,
    orig: []u8,
    edits: std.ArrayList(Edit) = .empty,
};

/// What this process already rewrote, per file. Tests use their own; the
/// public functions use the process-wide one.
pub const Registry = struct {
    files: std.ArrayList(FileState) = .empty,

    pub fn deinit(r: *Registry, gpa: std.mem.Allocator) void {
        for (r.files.items) |*f| {
            for (f.edits.items) |e| gpa.free(e.value);
            f.edits.deinit(gpa);
            gpa.free(f.orig);
            gpa.free(f.path);
        }
        r.files.deinit(gpa);
        r.* = .{};
    }

    fn find(r: *Registry, path: []const u8) ?*FileState {
        for (r.files.items) |*f| if (std.mem.eql(u8, f.path, path)) return f;
        return null;
    }
};

var global_registry: Registry = .{};
var global_mutex: Io.Mutex = .init;

fn readSource(gpa: std.mem.Allocator, io: Io, root: Dir, path: []const u8) Error![]u8 {
    return root.readFileAlloc(io, path, gpa, .limited(max_source)) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.SnapshotTooLarge,
        error.FileNotFound => error.SnapshotSourceNotFound,
        else => error.SnapshotIo,
    };
}

/// Rewrite the literal at `line`:`column` of `path` (relative to `root`) so it
/// denotes `actual`. `expected` is the literal's current value and is checked
/// against the source before anything is written.
pub fn rewrite(
    reg: *Registry,
    gpa: std.mem.Allocator,
    io: Io,
    root: Dir,
    path: []const u8,
    line: u32,
    column: u32,
    kind: Kind,
    expected: []const u8,
    actual: []const u8,
) Error!void {
    if (actual.len > max_actual) return error.SnapshotTooLarge;

    if (reg.find(path) == null) {
        const orig = try readSource(gpa, io, root, path);
        errdefer gpa.free(orig);
        const path_copy = try gpa.dupe(u8, path);
        errdefer gpa.free(path_copy);
        try reg.files.append(gpa, .{ .path = path_copy, .orig = orig });
    }
    const fs = reg.find(path).?;

    const loc0 = try locate(fs.orig, line, column);
    {
        const value = try decode(gpa, fs.orig, loc0);
        defer gpa.free(value);
        if (!std.mem.eql(u8, value, expected)) return error.SnapshotLiteralMismatch;
    }
    for (fs.edits.items) |e| {
        if (e.orig_start != loc0.region_start) continue;
        if (std.mem.eql(u8, e.value, actual)) return;
        return error.SnapshotConflict;
    }

    const cur = try readSource(gpa, io, root, path);
    defer gpa.free(cur);
    var shift: isize = 0;
    for (fs.edits.items) |e| {
        if (e.orig_end <= loc0.region_start)
            shift += @as(isize, @intCast(e.new_len)) - @as(isize, @intCast(e.orig_end - e.orig_start));
    }
    const at = shifted(loc0.at, shift) orelse return error.SnapshotSourceChanged;
    const loc = try locateAt(cur, at);
    if (loc.region_start != shifted(loc0.region_start, shift)) return error.SnapshotSourceChanged;

    const ls = if (std.mem.findLast(u8, cur[0..at], "\n")) |p| p + 1 else 0;
    var ind_end = ls;
    while (ind_end < at and (cur[ind_end] == ' ' or cur[ind_end] == '\t')) ind_end += 1;
    const line_end = std.mem.findScalar(u8, cur[at..], '\n') orelse cur.len - at;
    const eol: []const u8 = if (at + line_end > 0 and cur[at + line_end - 1] == '\r') "\r\n" else "\n";
    const region = try renderRegion(gpa, kind, actual, cur[ls..ind_end], eol);
    defer gpa.free(region);

    const old_region = cur[loc.region_start..loc.region_end];
    const new_len = cur.len - old_region.len + region.len;
    if (new_len > max_source) return error.SnapshotTooLarge;
    const out = try gpa.alloc(u8, new_len);
    defer gpa.free(out);
    @memcpy(out[0..loc.region_start], cur[0..loc.region_start]);
    @memcpy(out[loc.region_start..][0..region.len], region);
    @memcpy(out[loc.region_start + region.len ..], cur[loc.region_end..]);

    // Everything that can run out of memory happens before the write: the
    // file is either untouched or complete, and the record never lags it.
    const value = try gpa.dupe(u8, actual);
    errdefer gpa.free(value);
    try fs.edits.ensureUnusedCapacity(gpa, 1);
    try writeAtomic(io, root, path, out);

    fs.edits.appendAssumeCapacity(.{
        .orig_start = loc0.region_start,
        .orig_end = loc0.region_end,
        .new_len = region.len,
        .value = value,
    });
}

fn shifted(off: usize, shift: isize) ?usize {
    const v = @as(isize, @intCast(off)) + shift;
    return if (v < 0) null else @intCast(v);
}

fn writeAtomic(io: Io, root: Dir, path: []const u8, data: []const u8) Error!void {
    const st = root.statFile(io, path, .{}) catch return error.SnapshotIo;
    var af = root.createFileAtomic(io, path, .{ .permissions = st.permissions, .replace = true }) catch return error.SnapshotIo;
    defer af.deinit(io);
    af.file.writeStreamingAll(io, data) catch return error.SnapshotIo;
    af.replace(io) catch return error.SnapshotIo;
}

// ── finding the file ─────────────────────────────────────────────────────

/// A relative path with no `..`, no absolute start, no backslash, no NUL.
fn validRel(p: []const u8) bool {
    if (p.len == 0 or p.len > 512 or p[0] == '/') return false;
    if (std.mem.findAny(u8, p, "\\\x00") != null) return false;
    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |c| if (std.mem.eql(u8, c, "..")) return false;
    return true;
}

/// Whether `path` holds, at `line`:`column`, `@src()` and a literal denoting
/// `expected`. The text is the one the test binary was built from: the original
/// kept by `reg` for a file already rewritten in this process (its line numbers
/// moved on disk), else the file as it is.
fn candidateMatches(reg: *Registry, gpa: std.mem.Allocator, io: Io, root: Dir, path: []const u8, line: u32, column: u32, expected: []const u8) bool {
    const kept = reg.find(path);
    const text = if (kept) |f| f.orig else readSource(gpa, io, root, path) catch return false;
    defer if (kept == null) gpa.free(text);
    const loc = locate(text, line, column) catch return false;
    const value = decode(gpa, text, loc) catch return false;
    defer gpa.free(value);
    return std.mem.eql(u8, value, expected);
}

const Search = struct {
    reg: *Registry,
    gpa: std.mem.Allocator,
    io: Io,
    root: Dir,
    file: []const u8,
    line: u32,
    column: u32,
    expected: []const u8,
    found: ?[]u8 = null,
    count: usize = 0,

    fn consider(s: *Search, dir: []const u8) Error!void {
        const path = if (dir.len == 0)
            try s.gpa.dupe(u8, s.file)
        else
            try s.gpa.print("{s}/{s}", .{ dir, s.file });
        if (candidateMatches(s.reg, s.gpa, s.io, s.root, path, s.line, s.column, s.expected)) {
            s.count += 1;
            if (s.found) |old| s.gpa.free(old);
            s.found = path;
        } else s.gpa.free(path);
    }
};

/// The one source file under `root` whose text at `line`:`column` is `@src()`
/// followed by a literal denoting `expected`. Caller frees.
pub fn resolve(
    reg: *Registry,
    gpa: std.mem.Allocator,
    io: Io,
    root: Dir,
    override: ?[]const u8,
    file: []const u8,
    line: u32,
    column: u32,
    expected: []const u8,
) Error![]u8 {
    if (!validRel(file) or !std.mem.endsWith(u8, file, ".zig")) return error.SnapshotBadPath;
    var s: Search = .{ .reg = reg, .gpa = gpa, .io = io, .root = root, .file = file, .line = line, .column = column, .expected = expected };
    errdefer if (s.found) |f| gpa.free(f);

    if (override) |o| {
        if (!validRel(o)) return error.SnapshotBadPath;
        try s.consider(o);
    } else {
        try s.consider("");
        try s.consider("src");
        if (root.openDir(io, "modules", .{ .iterate = true })) |opened| {
            var mods = opened;
            defer mods.close(io);
            var it = mods.iterate();
            while (it.next(io) catch return error.SnapshotIo) |ent| {
                if (ent.kind != .directory) continue;
                for ([_][]const u8{ "src", "", "tools", "example" }) |sub| {
                    const d = if (sub.len == 0)
                        try gpa.print("modules/{s}", .{ent.name})
                    else
                        try gpa.print("modules/{s}/{s}", .{ ent.name, sub });
                    defer gpa.free(d);
                    try s.consider(d);
                }
            }
        } else |e| switch (e) {
            error.FileNotFound, error.NotDir => {},
            else => return error.SnapshotIo,
        }
    }
    if (s.count > 1) return error.SnapshotAmbiguous;
    return s.found orelse error.SnapshotSourceNotFound;
}

/// Find the repository root: the nearest ancestor of the cwd holding a
/// `build.zig`. Returns the number of `..` steps.
fn rootDepth(io: Io) ?usize {
    var buf: [64]u8 = undefined;
    var depth: usize = 0;
    while (depth <= 8) : (depth += 1) {
        var n: usize = 0;
        for (0..depth) |_| {
            @memcpy(buf[n..][0..3], "../");
            n += 3;
        }
        @memcpy(buf[n..][0.."build.zig".len], "build.zig");
        n += "build.zig".len;
        if (Dir.cwd().access(io, buf[0..n], .{})) |_| return depth else |_| {}
    }
    return null;
}

fn envGet(name: []const u8) ?[]const u8 {
    if (@import("builtin").target.os.tag == .windows) return null;
    return std.process.Environ.getPosix(std.testing.environ, name);
}

/// The update path of `check`: find the repository root and the file, rewrite
/// the literal. Needs the real cwd and a real test runner, so the tests drive
/// its parts (`resolve`, `rewrite`); the whole is proved by a run with the
/// variable set.
fn updateSource(kind: Kind, src: std.builtin.SourceLocation, expected: []const u8, actual: []const u8) Error!void {
    const io = std.testing.io;
    const gpa = std.heap.page_allocator; // global-alloc-ok: the update registry lives for the whole test process (one per run), no caller to take one from
    const depth = rootDepth(io) orelse return error.SnapshotSourceNotFound;
    var up: [64]u8 = undefined;
    var n: usize = 0;
    for (0..depth) |_| {
        @memcpy(up[n..][0..3], "../");
        n += 3;
    }
    const root_path = if (depth == 0) "." else up[0 .. n - 1];
    var root = Dir.cwd().openDir(io, root_path, .{}) catch return error.SnapshotIo;
    defer root.close(io);

    global_mutex.lockUncancelable(io);
    defer global_mutex.unlock(io);
    const path = try resolve(&global_registry, gpa, io, root, envGet(root_env_name), src.file, src.line, src.column, expected);
    defer gpa.free(path);
    return rewrite(&global_registry, gpa, io, root, path, src.line, src.column, kind, expected, actual);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// `n` characters alternating `x` and `y` (n is at most 64).
fn rep64(comptime n: usize, x: u8, y: u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, 0..) |*c, i| c.* = if (i % 2 == 0) x else y;
    return out;
}

/// The 1-based line and column of the `nth` (0-based) `@src()` in `text`.
fn pos(text: []const u8, nth: usize) struct { line: u32, column: u32 } {
    var at: usize = 0;
    var seen: usize = 0;
    while (std.mem.find(u8, text[at..], call)) |p| {
        at += p;
        if (seen == nth) break;
        seen += 1;
        at += call.len;
    }
    const line: u32 = @intCast(std.mem.count(u8, text[0..at], "\n") + 1);
    const ls = if (std.mem.findLast(u8, text[0..at], "\n")) |p| p + 1 else 0;
    return .{ .line = line, .column = @intCast(at - ls + 1) };
}

fn put(dir: Dir, path: []const u8, data: []const u8) !void {
    try dir.writeFile(testing.io, .{ .sub_path = path, .data = data });
}

fn slurp(dir: Dir, path: []const u8) ![]u8 {
    // A fixture may be as large as `max_source` (the cap tests build one).
    return dir.readFileAlloc(testing.io, path, testing.allocator, .limited(max_source + 1));
}

/// One rewrite of the `nth` `@src()` of fixture `path` (already written).
fn rewriteNth(reg: *Registry, dir: Dir, path: []const u8, nth: usize, kind: Kind, expected: []const u8, actual: []const u8) Error!void {
    const text = slurp(dir, path) catch return error.SnapshotIo;
    defer testing.allocator.free(text);
    // Positions refer to the ORIGINAL text: a test passes the nth of the original.
    const p = pos(reg_orig(reg, path) orelse text, nth);
    return rewrite(reg, testing.allocator, testing.io, dir, path, p.line, p.column, kind, expected, actual);
}

fn reg_orig(reg: *Registry, path: []const u8) ?[]const u8 {
    return if (reg.find(path)) |f| f.orig else null;
}

test "modeOf: unset and empty compare, update updates, anything else is refused" {
    try testing.expectEqual(Mode.compare, try modeOf(null));
    try testing.expectEqual(Mode.compare, try modeOf(""));
    try testing.expectEqual(Mode.update, try modeOf("update"));
    try testing.expectError(error.SnapshotModeUnknown, modeOf("1"));
    try testing.expectError(error.SnapshotModeUnknown, modeOf("Update"));
    try testing.expectError(error.SnapshotModeUnknown, modeOf("updat"));
    try testing.expectError(error.SnapshotModeUnknown, modeOf("update "));
}

test "matches: text is byte equality, hex decodes first (whitespace ignored)" {
    const a = testing.allocator;
    try testing.expect(try matches(a, .text, "abc", "abc"));
    try testing.expect(!try matches(a, .text, "abc", "abd"));
    try testing.expect(!try matches(a, .text, "abc", "ab"));
    try testing.expect(try matches(a, .text, "", ""));
    try testing.expect(try matches(a, .hex, "deadbeef", &.{ 0xde, 0xad, 0xbe, 0xef }));
    try testing.expect(try matches(a, .hex, "dead\n  beef\r\n", &.{ 0xde, 0xad, 0xbe, 0xef }));
    try testing.expect(try matches(a, .hex, "", ""));
    try testing.expect(!try matches(a, .hex, "deadbeef", &.{ 0xde, 0xad, 0xbe, 0xee }));
    try testing.expect(!try matches(a, .hex, "deadbe", &.{ 0xde, 0xad, 0xbe, 0xef }));
    try testing.expectError(error.InvalidLength, matches(a, .hex, "abc", "x"));
    try testing.expectError(error.InvalidLength, matches(a, .hex, "ab c", "x"));
    try testing.expectError(error.InvalidCharacter, matches(a, .hex, "zz", "x"));
    try testing.expectError(error.InvalidCharacter, matches(a, .hex, "0g", "x"));
}

test "hexBytes accepts upper case and rejects an odd digit count split by whitespace" {
    const a = testing.allocator;
    const b = try hexBytes(a, "AB\tcd");
    defer a.free(b);
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd }, b);
    try testing.expectError(error.InvalidLength, hexBytes(a, "a b c"));
}

test "locate: single-line, multiline and the extents of each" {
    const src =
        "try e(@src(), \"abc\", x);\n" ++
        "try e(@src(),\n" ++
        "    \\\\l1\n" ++
        "    \\\\l2\n" ++
        ", x);\n";
    const p0 = pos(src, 0);
    const l0 = try locate(src, p0.line, p0.column);
    try testing.expect(!l0.multiline);
    try testing.expectEqualStrings("\"abc\"", src[l0.lit_start..l0.lit_end]);
    try testing.expectEqualStrings(" \"abc\"", src[l0.region_start..l0.region_end]);
    try testing.expectEqual(@as(u8, ','), src[l0.region_end]);
    try testing.expectEqual(@as(u8, '@'), src[l0.at]);

    const p1 = pos(src, 1);
    const l1 = try locate(src, p1.line, p1.column);
    try testing.expect(l1.multiline);
    try testing.expectEqualStrings("\\\\l1\n    \\\\l2", src[l1.lit_start..l1.lit_end]);
    try testing.expectEqualStrings("\n    \\\\l1\n    \\\\l2\n", src[l1.region_start..l1.region_end]);
    const v = try decode(testing.allocator, src, l1);
    defer testing.allocator.free(v);
    try testing.expectEqualStrings("l1\nl2", v);
}

test "locate refuses a location that is not @src() or not followed by a plain literal" {
    const t = "try e(@src(), name, x);\ntry e(@src(), \"a\" ++ \"b\", x);\ntry e(@src() , \"a\"\n);\ntry e(@src(), \"unterminated\n, x);\ntry e(@src(), \"a";
    try testing.expectError(error.SnapshotNotLiteral, locate(t, 1, 7)); // an identifier
    try testing.expectError(error.SnapshotNotLiteral, locate(t, 2, 7)); // concatenation
    try testing.expectError(error.SnapshotNotLiteral, locate(t, 3, 7)); // the literal is the last argument
    try testing.expectError(error.SnapshotNotLiteral, locate(t, 5, 7)); // string runs past the line
    try testing.expectError(error.SnapshotNotLiteral, locate(t, 7, 7)); // end of file inside the string
    try testing.expectError(error.SnapshotSourceChanged, locate(t, 1, 8)); // not at an @src()
    try testing.expectError(error.SnapshotSourceChanged, locate(t, 1, 0));
    try testing.expectError(error.SnapshotSourceChanged, locate(t, 0, 7));
    try testing.expectError(error.SnapshotSourceChanged, locate(t, 99, 7));
    try testing.expectError(error.SnapshotSourceChanged, locate(t, 1, 99));
    // `@src()` with nothing after it, and a comma with nothing after it.
    try testing.expectError(error.SnapshotNotLiteral, locate("@src()", 1, 1));
    try testing.expectError(error.SnapshotNotLiteral, locate("@src(),", 1, 1));
    try testing.expectError(error.SnapshotNotLiteral, locate("@src(), ", 1, 1));
}

test "decode: escapes, CRLF multiline, empty lines" {
    const a = testing.allocator;
    const s = "@src(), \"a\\n\\x41\\\\\\\"\\u{e9}\", x";
    const ls = try locate(s, 1, 1);
    const vs = try decode(a, s, ls);
    defer a.free(vs);
    try testing.expectEqualStrings("a\nA\\\"\u{e9}", vs);

    const m = "@src(),\r\n    \\\\one\r\n    \\\\\r\n\t\\\\three\r\n, x";
    const lm = try locate(m, 1, 1);
    try testing.expect(lm.multiline);
    const vm = try decode(a, m, lm);
    defer a.free(vm);
    try testing.expectEqualStrings("one\n\nthree", vm);
    // The literal ends at the content, not at the CR before the newline.
    try testing.expectEqual(@as(u8, 'e'), m[lm.lit_end - 1]);

    const bad = "@src(), \"\\q\", x";
    const lb = try locate(bad, 1, 1);
    try testing.expectError(error.SnapshotNotLiteral, decode(a, bad, lb));
}

test "renderRegion: single-line escapes, multiline lines, hex split" {
    const a = testing.allocator;
    const r1 = try renderRegion(a, .text, "he said \"hi\"\\\t\x01", "  ", "\n");
    defer a.free(r1);
    try testing.expectEqualStrings(" \"he said \\\"hi\\\"\\\\\\t\\x01\"", r1);

    const r2 = try renderRegion(a, .text, "a\nb\n", "  ", "\n");
    defer a.free(r2);
    try testing.expectEqualStrings("\n      \\\\a\n      \\\\b\n      \\\\\n  ", r2);

    const r3 = try renderRegion(a, .text, "a\nb", "", "\r\n");
    defer a.free(r3);
    try testing.expectEqualStrings("\r\n    \\\\a\r\n    \\\\b\r\n", r3);

    // A newline plus a tab, CR or invalid UTF-8 stays an escaped single line.
    const r4 = try renderRegion(a, .text, "a\n\tb", "", "\n");
    defer a.free(r4);
    try testing.expectEqualStrings(" \"a\\n\\tb\"", r4);
    const r5 = try renderRegion(a, .text, "a\r\nb", "", "\n");
    defer a.free(r5);
    try testing.expectEqualStrings(" \"a\\r\\nb\"", r5);
    const r6 = try renderRegion(a, .text, "a\n\xff", "", "\n");
    defer a.free(r6);
    try testing.expectEqualStrings(" \"a\\n\\xff\"", r6);
    const r7 = try renderRegion(a, .text, "a\n\x7f", "", "\n");
    defer a.free(r7);
    try testing.expectEqualStrings(" \"a\\n\\x7f\"", r7);
    // Valid UTF-8 stays raw; a lone high byte is escaped.
    const r8 = try renderRegion(a, .text, "caf\u{e9}", "", "\n");
    defer a.free(r8);
    try testing.expectEqualStrings(" \"caf\u{e9}\"", r8);
    const r9 = try renderRegion(a, .text, "", "", "\n");
    defer a.free(r9);
    try testing.expectEqualStrings(" \"\"", r9);
    const r10 = try renderRegion(a, .text, "\n", "", "\n");
    defer a.free(r10);
    try testing.expectEqualStrings("\n    \\\\\n    \\\\\n", r10);

    const h1 = try renderRegion(a, .hex, &.{ 0xde, 0xad }, "", "\n");
    defer a.free(h1);
    try testing.expectEqualStrings(" \"dead\"", h1);
    const h0 = try renderRegion(a, .hex, "", "", "\n");
    defer a.free(h0);
    try testing.expectEqualStrings(" \"\"", h0);

    var big: [hex_line_bytes + 3]u8 = undefined;
    @memset(&big, 0xab);
    const h2 = try renderRegion(a, .hex, &big, "  ", "\n");
    defer a.free(h2);
    const want = try std.mem.concat(a, u8, &.{ "\n      \\\\", &rep64(hex_line_bytes * 2, 'a', 'b'), "\n      \\\\ababab\n  " });
    defer a.free(want);
    try testing.expectEqualStrings(want, h2);
    // exactly one full line stays single-line
    var edge: [hex_line_bytes]u8 = undefined;
    @memset(&edge, 0x01);
    const h3 = try renderRegion(a, .hex, &edge, "", "\n");
    defer a.free(h3);
    try testing.expectEqual(@as(u8, '"'), h3[1]);
}

test "rewrite: a single-line literal becomes the new value, the rest of the file is untouched" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const before = "const x = 1;\n    try testkit.expectSnapshot(@src(), \"old\", got);\nconst y = 2;\n";
    try put(tmp.dir, "t.zig", before);
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "old", "new value");
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("const x = 1;\n    try testkit.expectSnapshot(@src(), \"new value\", got);\nconst y = 2;\n", after);
}

test "rewrite: single-line to multiline and back, indentation of the call line" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "fn f() !void {\n    try e(@src(), \"old\", got);\n}\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "old", "l1\nl2");
    const a1 = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(a1);
    try testing.expectEqualStrings("fn f() !void {\n    try e(@src(),\n        \\\\l1\n        \\\\l2\n    , got);\n}\n", a1);
    // Parses back to what was written.
    const p = pos(a1, 0);
    const loc = try locate(a1, p.line, p.column);
    const v = try decode(testing.allocator, a1, loc);
    defer testing.allocator.free(v);
    try testing.expectEqualStrings("l1\nl2", v);

    // A fresh session turns the multiline literal into a single line again.
    var reg2: Registry = .{};
    defer reg2.deinit(testing.allocator);
    try rewriteNth(&reg2, tmp.dir, "t.zig", 0, .text, "l1\nl2", "short");
    const a2 = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(a2);
    try testing.expectEqualStrings("fn f() !void {\n    try e(@src(), \"short\", got);\n}\n", a2);
}

test "rewrite: CRLF files keep CRLF" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "    try e(@src(), \"old\", got);\r\nconst z = 0;\r\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "old", "a\nb");
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("    try e(@src(),\r\n        \\\\a\r\n        \\\\b\r\n    , got);\r\nconst z = 0;\r\n", after);
}

test "rewrite: the file's permissions survive and no temporary file is left" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "t.zig",
        .data = "e(@src(), \"a\", x);\n",
        .flags = .{ .permissions = .fromMode(0o640) },
    });
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "b");
    const st = try tmp.dir.statFile(testing.io, "t.zig", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o640), st.permissions.toMode() & 0o777);
    var it = tmp.dir.iterate();
    var n: usize = 0;
    while (try it.next(testing.io)) |_| n += 1;
    try testing.expectEqual(@as(usize, 1), n);
}

test "rewrite: several snapshots in one file, rewritten in any order, line shifts included" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const before =
        "e(@src(), \"a\", x);\n" ++
        "e(@src(), \"b\", x); e(@src(), \"c\", y);\n" ++
        "e(@src(),\n    \\\\d1\n    \\\\d2\n, x);\n" ++
        "e(@src(), \"e\", x);\n";
    try put(tmp.dir, "t.zig", before);
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    // Last first, then the middle ones, then the first: every earlier edit
    // moves the lines and columns of the later `@src()`s of the ORIGINAL file.
    try rewriteNth(&reg, tmp.dir, "t.zig", 4, .text, "e", "E1\nE2");
    try rewriteNth(&reg, tmp.dir, "t.zig", 3, .text, "d1\nd2", "D");
    try rewriteNth(&reg, tmp.dir, "t.zig", 1, .text, "b", "B1\nB2\nB3");
    try rewriteNth(&reg, tmp.dir, "t.zig", 2, .text, "c", "C");
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "A");
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    const want =
        "e(@src(), \"A\", x);\n" ++
        "e(@src(),\n    \\\\B1\n    \\\\B2\n    \\\\B3\n, x); e(@src(), \"C\", y);\n" ++
        "e(@src(), \"D\", x);\n" ++
        "e(@src(),\n    \\\\E1\n    \\\\E2\n, x);\n";
    try testing.expectEqualStrings(want, after);
}

test "rewrite: two snapshots on one line are told apart by column" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "e(@src(), \"one\", x); e(@src(), \"two\", y);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "one", "1111");
    try rewriteNth(&reg, tmp.dir, "t.zig", 1, .text, "two", "2");
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("e(@src(), \"1111\", x); e(@src(), \"2\", y);\n", after);
}

test "rewrite: the same location twice is a repeat when equal and a conflict when not" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "e(@src(), \"a\", x);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "b");
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "b");
    try testing.expectError(error.SnapshotConflict, rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "c"));
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("e(@src(), \"b\", x);\n", after);
}

test "rewrite: update is idempotent (the rewritten literal compares equal, a second update has nothing to do)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "    e(@src(), \"old\", x);\n    e(@src(), \"\", y);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    const values = [_][]const u8{ "multi\nline\n", "" };
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "old", values[0]);
    try rewriteNth(&reg, tmp.dir, "t.zig", 1, .text, "", "x\ty\n");
    const once = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(once);

    // A new process reads the file: every literal now equals its value, so
    // `check` would never reach `rewrite` again. Prove that by decoding.
    var p = pos(once, 0);
    var loc = try locate(once, p.line, p.column);
    var v = try decode(testing.allocator, once, loc);
    try testing.expectEqualStrings("multi\nline\n", v);
    testing.allocator.free(v);
    p = pos(once, 1);
    loc = try locate(once, p.line, p.column);
    v = try decode(testing.allocator, once, loc);
    try testing.expectEqualStrings("x\ty\n", v);
    testing.allocator.free(v);

    // And if it is called anyway with the same value, the bytes are the same.
    var reg2: Registry = .{};
    defer reg2.deinit(testing.allocator);
    try rewriteNth(&reg2, tmp.dir, "t.zig", 0, .text, "multi\nline\n", "multi\nline\n");
    try rewriteNth(&reg2, tmp.dir, "t.zig", 1, .text, "x\ty\n", "x\ty\n");
    const twice = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(twice);
    try testing.expectEqualStrings(once, twice);
}

test "rewrite: hex snapshots, one line and split over lines" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "e(@src(), \"\", x);\ne(@src(), \"00\", y);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    var big: [hex_line_bytes + 1]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @intCast(i);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .hex, "", &.{ 0xca, 0xfe });
    try rewriteNth(&reg, tmp.dir, "t.zig", 1, .hex, "00", &big);
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    const want = "e(@src(), \"cafe\", x);\ne(@src(),\n    \\\\000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n    \\\\20\n, y);\n";
    try testing.expectEqualStrings(want, after);
    // The split literal decodes back to the bytes through `matches`.
    const p = pos(after, 1);
    const loc = try locate(after, p.line, p.column);
    const v = try decode(testing.allocator, after, loc);
    defer testing.allocator.free(v);
    try testing.expect(try matches(testing.allocator, .hex, v, &big));
}

test "rewrite refuses instead of guessing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "e(@src(), \"a\", x);\ne(@src(), name, x);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    // The literal at that location is not the value the caller passed.
    try testing.expectError(error.SnapshotLiteralMismatch, rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "other", "b"));
    // Not a literal.
    try testing.expectError(error.SnapshotNotLiteral, rewriteNth(&reg, tmp.dir, "t.zig", 1, .text, "", "b"));
    // No such file.
    try testing.expectError(error.SnapshotSourceNotFound, rewrite(&reg, testing.allocator, testing.io, tmp.dir, "nope.zig", 1, 3, .text, "a", "b"));
    // A location that is not an @src().
    try testing.expectError(error.SnapshotSourceChanged, rewrite(&reg, testing.allocator, testing.io, tmp.dir, "t.zig", 1, 1, .text, "a", "b"));
    // Nothing was written by any of the refusals.
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("e(@src(), \"a\", x);\ne(@src(), name, x);\n", after);
}

test "rewrite: a file edited since the build is refused, not corrupted" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "e(@src(), \"a\", x);\ne(@src(), \"b\", x);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "A");
    // Someone inserts a line behind our back: the original text the second
    // snapshot's position refers to is no longer what is at that offset.
    const cur = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(cur);
    const edited = try std.mem.concat(testing.allocator, u8, &.{ "// pad\n", cur });
    defer testing.allocator.free(edited);
    try put(tmp.dir, "t.zig", edited);
    try testing.expectError(error.SnapshotSourceChanged, rewriteNth(&reg, tmp.dir, "t.zig", 1, .text, "b", "B"));
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    try testing.expectEqualStrings(edited, after);

    // A fresh session whose location no longer holds an @src() refuses too.
    var other: Registry = .{};
    defer other.deinit(testing.allocator);
    try testing.expectError(error.SnapshotSourceChanged, rewrite(&other, testing.allocator, testing.io, tmp.dir, "t.zig", 1, 3, .text, "A", "c"));
}

test "rewrite: an oversized actual is refused" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "e(@src(), \"a\", x);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    const big = try testing.allocator.alloc(u8, max_actual + 1);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    try testing.expectError(error.SnapshotTooLarge, rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", big));
    // The limit itself is allowed.
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", big[0..max_actual]);
}

test "rewrite: a source file over the cap is refused" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const big = try testing.allocator.alloc(u8, max_source + 1);
    defer testing.allocator.free(big);
    @memset(big, '/');
    try put(tmp.dir, "t.zig", big);
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try testing.expectError(error.SnapshotTooLarge, rewrite(&reg, testing.allocator, testing.io, tmp.dir, "t.zig", 1, 1, .text, "", "x"));
}

test "rewrite: out-of-memory at every allocation is an error, never a partial file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const before = "e(@src(), \"a\", x);\n";
    try put(tmp.dir, "t.zig", before);
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        var reg: Registry = .{};
        defer reg.deinit(fa.allocator());
        rewrite(&reg, fa.allocator(), testing.io, tmp.dir, "t.zig", 1, 3, .text, "a", "b\nc") catch |e| {
            try testing.expectEqual(error.OutOfMemory, e);
            const now = try slurp(tmp.dir, "t.zig");
            defer testing.allocator.free(now);
            try testing.expectEqualStrings(before, now);
            continue;
        };
        break;
    }
    try testing.expect(i > 3 and i < 40);
}

test "locate: whitespace before the comma, a missing comma, a string over a newline, a multiline at EOF" {
    const l = try locate("@src() , \"a\", x", 1, 1);
    try testing.expectEqualStrings("\"a\"", ("@src() , \"a\", x")[l.lit_start..l.lit_end]);
    try testing.expectError(error.SnapshotNotLiteral, locate("@src() \"a\", x", 1, 1));
    try testing.expectError(error.SnapshotNotLiteral, locate("@src(), \"abc\n\", x", 1, 1));
    try testing.expectError(error.SnapshotNotLiteral, locate("@src(), \"abc\\\n\", x", 1, 1));
    try testing.expectError(error.SnapshotNotLiteral, locate("@src(),\n  \\\\l1", 1, 1));
    try testing.expectError(error.SnapshotNotLiteral, locate("@src(), \"a\"", 1, 1));
    // `@src()` at the very end of the text and an `at` past it.
    try testing.expectError(error.SnapshotNotLiteral, locate("@src()", 1, 1));
    try testing.expectError(error.SnapshotSourceChanged, locateAt("@src(), \"a\", x", 99));
    // A backslash as the last byte of the file.
    try testing.expectError(error.SnapshotNotLiteral, locate("@src(), \"a\\", 1, 1));
}

test "decode: a lone carriage return inside a line is content, not a line ending" {
    const m = "@src(),\r\n    \\\\x\r\r\n, y";
    const loc = try locate(m, 1, 1);
    const v = try decode(testing.allocator, m, loc);
    defer testing.allocator.free(v);
    try testing.expectEqualStrings("x\r", v);
}

test "the single-line form round-trips every byte value, alone and together" {
    const a = testing.allocator;
    var all: [256]u8 = undefined;
    for (&all, 0..) |*c, i| c.* = @intCast(i);
    var one: [1]u8 = undefined;
    var i: usize = 0;
    while (i <= 256) : (i += 1) {
        const value: []const u8 = if (i == 256) &all else blk: {
            one[0] = @intCast(i);
            break :blk &one;
        };
        const region = try renderRegion(a, .text, value, "", "\n");
        defer a.free(region);
        const src = try std.mem.concat(a, u8, &.{ "@src(),", region, ", x" });
        defer a.free(src);
        const loc = try locate(src, 1, 1);
        const back = try decode(a, src, loc);
        defer a.free(back);
        try testing.expectEqualSlices(u8, value, back);
        // A control byte never appears raw in the single-line form.
        if (i != 256 and i != 10 and (value[0] < 32 or value[0] == 127)) {
            for (region) |c| try testing.expect(c >= 32 and c != 127);
        }
    }
}

test "the multiline form round-trips text with spaces, symbols and non-ASCII" {
    const a = testing.allocator;
    const values = [_][]const u8{ "a b\n c\n", " lead\ntrail \n", "x = \"q\" \\ y\n!~\n", "caf\u{e9}\n\u{1F600}\n", "\n\n", "a\n\nb" };
    for (values) |v| {
        try testing.expect(multilineSafe(v));
        const region = try renderRegion(a, .text, v, "  ", "\n");
        defer a.free(region);
        try testing.expect(region[0] == '\n');
        const src = try std.mem.concat(a, u8, &.{ "@src(),", region, ", x" });
        defer a.free(src);
        const loc = try locate(src, 1, 1);
        try testing.expect(loc.multiline);
        const back = try decode(a, src, loc);
        defer a.free(back);
        try testing.expectEqualStrings(v, back);
    }
    try testing.expect(!multilineSafe("no newline"));
    try testing.expect(!multilineSafe("a\nb\x1f"));
    try testing.expect(!multilineSafe("a\nb\x7f"));
    try testing.expect(multilineSafe("a\nb "));
}

test "rewrite: tab indentation of the call line is kept" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "\t\te(@src(), \"a\", x);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "p\nq");
    const after = try slurp(tmp.dir, "t.zig");
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("\t\te(@src(),\n\t\t    \\\\p\n\t\t    \\\\q\n\t\t, x);\n", after);
}

test "rewrite: two files in one registry stay apart" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "a.zig", "e(@src(), \"a\", x);\n");
    try put(tmp.dir, "b.zig", "e(@src(), \"b\", x);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "a.zig", 0, .text, "a", "A");
    try rewriteNth(&reg, tmp.dir, "b.zig", 0, .text, "b", "B");
    const a = try slurp(tmp.dir, "a.zig");
    defer testing.allocator.free(a);
    const b = try slurp(tmp.dir, "b.zig");
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("e(@src(), \"A\", x);\n", a);
    try testing.expectEqualStrings("e(@src(), \"B\", x);\n", b);
    try testing.expectEqual(@as(usize, 2), reg.files.items.len);
}

test "rewrite: a file whose call was edited since the build is refused" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try put(tmp.dir, "t.zig", "e(@src(), \"a\", x);\ne(@src(), \"b\", x);\n");
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "A");
    // The second call gets a space before its comma: same `@src()`, other region.
    try put(tmp.dir, "t.zig", "e(@src(), \"A\", x);\ne(@src() , \"b\", x);\n");
    try testing.expectError(error.SnapshotSourceChanged, rewriteNth(&reg, tmp.dir, "t.zig", 1, .text, "b", "B"));
    // The file shrank under us: the shifted offset is past its end.
    try put(tmp.dir, "t.zig", "x\n");
    try testing.expectError(error.SnapshotSourceChanged, rewriteNth(&reg, tmp.dir, "t.zig", 1, .text, "b", "B"));
}

test "rewrite: growing a file past the source cap is refused" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const head = "e(@src(), \"a\", x);\n";
    const pad = try testing.allocator.alloc(u8, max_source - head.len - 4);
    defer testing.allocator.free(pad);
    @memset(pad, '/');
    const body = try std.mem.concat(testing.allocator, u8, &.{ head, pad });
    defer testing.allocator.free(body);
    try put(tmp.dir, "t.zig", body);
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try testing.expectError(error.SnapshotTooLarge, rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "0123456789"));
    // The same file with a value that still fits is fine.
    try rewriteNth(&reg, tmp.dir, "t.zig", 0, .text, "a", "b");
}

test "validRel: relative paths without .. only" {
    try testing.expect(validRel("a.zig"));
    try testing.expect(validRel("sub/a.zig"));
    try testing.expect(validRel("modules/x/src"));
    try testing.expect(!validRel(""));
    try testing.expect(!validRel("/etc/passwd"));
    try testing.expect(!validRel("../a.zig"));
    try testing.expect(!validRel("a/../b.zig"));
    try testing.expect(!validRel("a/.."));
    try testing.expect(!validRel("a\\b.zig"));
    try testing.expect(!validRel("a\x00b"));
    try testing.expect(validRel("a/..b/c"));
    var long: [513]u8 = undefined;
    @memset(&long, 'a');
    try testing.expect(!validRel(&long));
    try testing.expect(validRel(long[0..512]));
}

fn tree(tmp: *testing.TmpDir) !void {
    try tmp.dir.createDirPath(testing.io, "modules/m1/src");
    try tmp.dir.createDirPath(testing.io, "modules/m2/src");
    try tmp.dir.createDirPath(testing.io, "modules/m2/example");
}

test "resolve: finds the one module whose file has the literal at that location" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try tree(&tmp);
    const a = testing.allocator;
    try put(tmp.dir, "modules/m1/src/t.zig", "e(@src(), \"one\", x);\n");
    try put(tmp.dir, "modules/m2/src/t.zig", "e(@src(), \"two\", x);\n");
    const p = try resolve(&reg, a, testing.io, tmp.dir, null, "t.zig", 1, 3, "two");
    defer a.free(p);
    try testing.expectEqualStrings("modules/m2/src/t.zig", p);
    // The same name with different literals: neither is picked for a third value.
    try testing.expectError(error.SnapshotSourceNotFound, resolve(&reg, a, testing.io, tmp.dir, null, "t.zig", 1, 3, "three"));
    // A wrong location is not found either.
    try testing.expectError(error.SnapshotSourceNotFound, resolve(&reg, a, testing.io, tmp.dir, null, "t.zig", 2, 3, "two"));
}

test "resolve: the other candidate directories (root, src, module root, tools, example)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try tree(&tmp);
    try tmp.dir.createDirPath(testing.io, "src");
    try tmp.dir.createDirPath(testing.io, "modules/m1/tools");
    const a = testing.allocator;
    const Case = struct { path: []const u8, name: []const u8 };
    const cases = [_]Case{
        .{ .path = "r.zig", .name = "r.zig" },
        .{ .path = "src/s.zig", .name = "s.zig" },
        .{ .path = "modules/m1/mr.zig", .name = "mr.zig" },
        .{ .path = "modules/m1/tools/tl.zig", .name = "tl.zig" },
        .{ .path = "modules/m2/example/ex.zig", .name = "ex.zig" },
        .{ .path = "modules/m2/src/deep/d.zig", .name = "deep/d.zig" },
    };
    try tmp.dir.createDirPath(testing.io, "modules/m2/src/deep");
    for (cases) |c| try put(tmp.dir, c.path, "e(@src(), \"v\", x);\n");
    for (cases) |c| {
        const p = try resolve(&reg, a, testing.io, tmp.dir, null, c.name, 1, 3, "v");
        defer a.free(p);
        try testing.expectEqualStrings(c.path, p);
    }
}

test "resolve: ambiguity is an error and the override ends it" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try tree(&tmp);
    const a = testing.allocator;
    try put(tmp.dir, "modules/m1/src/t.zig", "e(@src(), \"same\", x);\n");
    try put(tmp.dir, "modules/m2/src/t.zig", "e(@src(), \"same\", x);\n");
    try testing.expectError(error.SnapshotAmbiguous, resolve(&reg, a, testing.io, tmp.dir, null, "t.zig", 1, 3, "same"));
    const p = try resolve(&reg, a, testing.io, tmp.dir, "modules/m1/src", "t.zig", 1, 3, "same");
    defer a.free(p);
    try testing.expectEqualStrings("modules/m1/src/t.zig", p);
    // The override does not look anywhere else.
    try testing.expectError(error.SnapshotSourceNotFound, resolve(&reg, a, testing.io, tmp.dir, "modules/m1/example", "t.zig", 1, 3, "same"));
}

test "resolve: a file rewritten earlier in this process is matched against its original text" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "modules/m/src");
    const a = testing.allocator;
    try put(tmp.dir, "modules/m/src/t.zig", "e(@src(), \"one\", x);\ne(@src(), \"two\", y);\n");
    var reg: Registry = .{};
    defer reg.deinit(a);
    const p0 = try resolve(&reg, a, testing.io, tmp.dir, null, "t.zig", 1, 3, "one");
    defer a.free(p0);
    try rewrite(&reg, a, testing.io, tmp.dir, p0, 1, 3, .text, "one", "1\n2\n3");
    // On disk "two" is now on line 6; the binary still says line 2.
    const p1 = try resolve(&reg, a, testing.io, tmp.dir, null, "t.zig", 2, 3, "two");
    defer a.free(p1);
    try testing.expectEqualStrings("modules/m/src/t.zig", p1);
    // A fresh registry sees only the disk, where line 2 is a literal line.
    var fresh: Registry = .{};
    defer fresh.deinit(a);
    try testing.expectError(error.SnapshotSourceNotFound, resolve(&fresh, a, testing.io, tmp.dir, null, "t.zig", 2, 3, "two"));
}

test "resolve refuses a path that could leave the repository" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    const a = testing.allocator;
    try testing.expectError(error.SnapshotBadPath, resolve(&reg, a, testing.io, tmp.dir, null, "../t.zig", 1, 3, "x"));
    try testing.expectError(error.SnapshotBadPath, resolve(&reg, a, testing.io, tmp.dir, null, "/etc/t.zig", 1, 3, "x"));
    try testing.expectError(error.SnapshotBadPath, resolve(&reg, a, testing.io, tmp.dir, null, "t.txt", 1, 3, "x"));
    try testing.expectError(error.SnapshotBadPath, resolve(&reg, a, testing.io, tmp.dir, null, "", 1, 3, "x"));
    try testing.expectError(error.SnapshotBadPath, resolve(&reg, a, testing.io, tmp.dir, "../x", "t.zig", 1, 3, "x"));
    try testing.expectError(error.SnapshotBadPath, resolve(&reg, a, testing.io, tmp.dir, "/tmp", "t.zig", 1, 3, "x"));
}

test "resolve without a modules directory is just not found" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var reg: Registry = .{};
    defer reg.deinit(testing.allocator);
    try testing.expectError(error.SnapshotSourceNotFound, resolve(&reg, testing.allocator, testing.io, tmp.dir, null, "t.zig", 1, 3, "x"));
}

test "failure message: text names the first differing line and both versions" {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeReport(&w, .text, "t.zig", 7, 12, "alpha\nbeta\ngamma", "alpha\nbeXa\ngamma");
    const out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "snapshot mismatch at t.zig:7:12\n") != null);
    try testing.expect(std.mem.find(u8, out, "first difference: line 2, byte offset 8 (expected 16 bytes, got 16 bytes)\n") != null);
    try testing.expect(std.mem.find(u8, out, "  expected: \"beta\"\n") != null);
    try testing.expect(std.mem.find(u8, out, "  actual:   \"beXa\"\n") != null);
    try testing.expect(std.mem.find(u8, out, "TESTKIT_SNAPSHOT=update") != null);
}

test "failure message: a length difference, a missing last line, escapes and a long line" {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeReport(&w, .text, "t.zig", 1, 1, "a\nb", "a\nb\nc");
    var out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "first difference: line 2, byte offset 3 (expected 3 bytes, got 5 bytes)\n") != null);
    try testing.expect(std.mem.find(u8, out, "  expected ends here; actual continues: \"\\nc\"\n") != null);
    w = .fixed(&buf);
    try writeReport(&w, .text, "t.zig", 1, 1, "a\nb\nc", "a\nb");
    out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "  actual ends here; expected continues: \"\\nc\"\n") != null);
    // A length difference does not hide an earlier changed byte.
    w = .fixed(&buf);
    try writeReport(&w, .text, "t.zig", 1, 1, "abc", "xbcd");
    out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "line 1, byte offset 0 (expected 3 bytes, got 4 bytes)") != null);
    try testing.expect(std.mem.find(u8, out, "  expected: \"abc\"\n  actual:   \"xbcd\"\n") != null);

    w = .fixed(&buf);
    try writeReport(&w, .text, "t.zig", 1, 1, "tab\there", "tab\tHere");
    out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "\"tab\\there\"") != null);
    try testing.expect(std.mem.find(u8, out, "\"tab\\tHere\"") != null);

    var long: [excerpt_len + 50]u8 = undefined;
    @memset(&long, 'x');
    var long2 = long;
    long2[0] = 'y';
    var big: [4096]u8 = undefined;
    w = .fixed(&big);
    try writeReport(&w, .text, "t.zig", 1, 1, &long, &long2);
    out = w.buffered();
    var xs: [excerpt_len + 4]u8 = undefined;
    @memset(xs[0..excerpt_len], 'x');
    @memcpy(xs[excerpt_len..], "\"...");
    try testing.expect(std.mem.find(u8, out, &xs) != null);
    // An excerpt at exactly the limit has no ellipsis.
    w = .fixed(&big);
    try writeReport(&w, .text, "t.zig", 1, 1, long[0..excerpt_len], long2[0..excerpt_len]);
    out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "...") == null);
}

test "failure message: hex reuses the golden offset and window" {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeReport(&w, .hex, "t.zig", 3, 4, "00010203 04050607", &.{ 0, 1, 2, 3, 4, 0x55, 6, 7 });
    var out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "snapshot mismatch at t.zig:3:4\n") != null);
    try testing.expect(std.mem.find(u8, out, "first difference at offset 5 (0x5): expected 0x05, got 0x55\n") != null);
    try testing.expect(std.mem.find(u8, out, "  offset 0..\n") != null);
    try testing.expect(std.mem.find(u8, out, "[05]") != null);
    try testing.expect(std.mem.find(u8, out, "[55]") != null);

    w = .fixed(&buf);
    try writeReport(&w, .hex, "t.zig", 1, 1, "0001", &.{ 0, 1, 2 });
    out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "length mismatch: expected 2 bytes, got 3\n") != null);

    w = .fixed(&buf);
    try writeReport(&w, .hex, "t.zig", 1, 1, "zz", &.{});
    out = w.buffered();
    try testing.expect(std.mem.find(u8, out, "does not decode (InvalidCharacter)") != null);
}

test "writeReport prints nothing for equal values" {
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeReport(&w, .text, "t.zig", 1, 1, "same", "same");
    try testing.expect(std.mem.find(u8, w.buffered(), "first difference") == null);
    w = .fixed(&buf);
    try writeReport(&w, .hex, "t.zig", 1, 1, "0102", &.{ 1, 2 });
    try testing.expect(std.mem.find(u8, w.buffered(), "offset") == null);
}

test "expectSnapshot passes on equal values (the passing path writes nothing)" {
    // `check` reads the real environment; in compare mode an equal value returns first.
    if ((modeOf(envGet(env_name)) catch return) == .update) return;
    try expectSnapshot(@src(), "equal", "equal");
    try expectSnapshot(@src(),
        \\two
        \\lines
    , "two\nlines");
    try expectSnapshotHex(@src(), "cafe", &.{ 0xca, 0xfe });
    try expectSnapshotHex(@src(),
        \\ca
        \\fe
    , &.{ 0xca, 0xfe });
}

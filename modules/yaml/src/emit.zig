// SPDX-License-Identifier: MIT
//! Emitter: a composed `Value` (or several) back to YAML text that composes
//! to the same `Value` — under this module's YAML 1.2 core schema AND under
//! a YAML 1.1 reader such as PyYAML / libyaml.
//!
//! **Scalars.** A string is written plain only when it is a "simple word" —
//! ASCII letters, digits, `_ . / -` and inner spaces, starting with a letter,
//! `_` or `/`, and not one of the words a 1.1 or 1.2 resolver reads as
//! something else (`null`, `true`, `yes`, `on`, `y`, … in any case).
//! Everything else is double-quoted, with every character outside YAML's
//! printable set escaped (`\n`, `\t`, `\x7F`, `\N`, ` `, `﻿`, …), so
//! the output is a single line per scalar and never depends on indentation
//! or folding rules. Integers are decimal. Floats are the shortest decimal
//! that reads back to the same bits, always with a `.` and a signed exponent
//! when there is one (`1.0e+300`) — the form both YAML 1.1 (which needs the
//! dot) and 1.2 resolve as a float — plus `.inf`, `-.inf`, `.nan`.
//!
//! **Collections** are block style, two-space indent; empty ones are `[]` /
//! `{}`. A key that is a collection (or a string too long for an implicit
//! key) uses the explicit `? key` / `: value` form with the key in flow style.
//!
//! **Shared nodes stay shared.** The composer shares an aliased node instead
//! of copying it (that is its billion-laughs defence), so a naive tree walk
//! would write 2^n nodes for an n-level bomb. The emitter first counts how
//! often each collection (and each string of 32+ bytes) is reached, by slice
//! identity, without descending into one twice; a node reached more than
//! once is written once with an anchor (`&a1`) and then as an alias (`*a1`).
//! Output is therefore linear in the composed size, not the expanded one.
//!
//! Recursion follows the `Value`'s depth — bounded by `ComposeOptions.
//! max_depth` for a composed tree; a hand-built one is the caller's.

const std = @import("std");
const compose = @import("compose.zig");
const Value = compose.Value;
const Pair = compose.Pair;
const Io = std.Io;

pub const Error = Io.Writer.Error || std.mem.Allocator.Error || error{
    /// A string that is not valid UTF-8 (only a hand-built `Value` can hold one).
    InvalidUtf8,
};

const NodeKey = struct { ptr: usize, len: usize };
const NodeState = struct { count: u32 = 0, anchor: u32 = 0, written: bool = false };

const Emitter = struct {
    w: *Io.Writer,
    gpa: std.mem.Allocator,
    nodes: std.AutoHashMapUnmanaged(NodeKey, NodeState) = .empty,
    next_anchor: u32 = 0,

    fn deinit(self: *Emitter) void {
        self.nodes.deinit(self.gpa);
    }

    fn keyOf(v: Value) ?NodeKey {
        return switch (v) {
            .sequence => |s| if (s.len == 0) null else .{ .ptr = @intFromPtr(s.ptr), .len = s.len },
            .mapping => |m| if (m.len == 0) null else .{ .ptr = @intFromPtr(m.ptr), .len = m.len },
            .string => |s| if (s.len < 32) null else .{ .ptr = @intFromPtr(s.ptr), .len = s.len },
            else => null,
        };
    }

    /// First pass: how often is each shareable node reached?
    fn count(self: *Emitter, v: Value) Error!void {
        const k = keyOf(v) orelse return;
        const gop = try self.nodes.getOrPut(self.gpa, k);
        if (gop.found_existing) {
            gop.value_ptr.count += 1;
            return;
        }
        gop.value_ptr.* = .{ .count = 1 };
        switch (v) {
            .sequence => |s| for (s) |x| try self.count(x),
            .mapping => |m| for (m) |p| {
                try self.count(p.key);
                try self.count(p.value);
            },
            else => {},
        }
    }

    /// Writes `&aN ` / `*aN` as needed. Returns true if an alias was written
    /// (the node itself must then not be).
    fn prefix(self: *Emitter, v: Value, sep: []const u8) Error!bool {
        const k = keyOf(v) orelse return false;
        const st = self.nodes.getPtr(k) orelse return false;
        if (st.count < 2) return false;
        if (st.written) {
            try self.w.print("*a{d}", .{st.anchor});
            return true;
        }
        self.next_anchor += 1;
        st.anchor = self.next_anchor;
        st.written = true;
        try self.w.print("&a{d}{s}", .{ st.anchor, sep });
        return false;
    }

    fn indent(self: *Emitter, n: usize) Error!void {
        try self.w.splatByteAll(' ', n);
    }

    fn isBlock(v: Value) bool {
        return switch (v) {
            .sequence => |s| s.len != 0,
            .mapping => |m| m.len != 0,
            else => false,
        };
    }

    /// A value that follows `- ` or `key:` (or starts a document): a scalar
    /// or an empty collection on the same line; a block collection on the
    /// lines after, at `ind`.
    fn valueAfter(self: *Emitter, v: Value, ind: usize, after_key: bool) Error!void {
        if (!isBlock(v)) {
            if (after_key) try self.w.writeByte(' ');
            if (!try self.prefix(v, " ")) try self.scalarOrFlow(v);
            try self.w.writeByte('\n');
            return;
        }
        // An anchor or alias goes on this line; a plain block starts on the next.
        if (self.shared(v)) {
            if (after_key) try self.w.writeByte(' ');
            if (try self.prefix(v, "")) {
                try self.w.writeByte('\n');
                return;
            }
        }
        try self.w.writeByte('\n');
        try self.block(v, ind);
    }

    fn shared(self: *Emitter, v: Value) bool {
        const k = keyOf(v) orelse return false;
        const st = self.nodes.get(k) orelse return false;
        return st.count >= 2;
    }

    fn block(self: *Emitter, v: Value, ind: usize) Error!void {
        switch (v) {
            .sequence => |items| for (items) |it| {
                try self.indent(ind);
                try self.w.writeByte('-');
                try self.valueAfter(it, ind + 2, true);
            },
            .mapping => |pairs| for (pairs) |p| {
                try self.indent(ind);
                if (simpleKey(p.key)) {
                    // `:` may be part of an alias name (`*a1:` is the alias
                    // "a1:"), so an aliased key is followed by a space.
                    if (try self.prefix(p.key, " ")) try self.w.writeByte(' ') else try self.scalarOrFlow(p.key);
                    try self.w.writeByte(':');
                    try self.valueAfter(p.value, ind + 2, true);
                } else {
                    try self.w.writeAll("? ");
                    if (!try self.prefix(p.key, " ")) try self.flow(p.key);
                    try self.w.writeByte('\n');
                    try self.indent(ind);
                    try self.w.writeByte(':');
                    try self.valueAfter(p.value, ind + 2, true);
                }
            },
            else => unreachable,
        }
    }

    fn simpleKey(k: Value) bool {
        return switch (k) {
            .sequence, .mapping => false,
            // An implicit key is limited to 1024 characters; escaping can
            // grow a character to 10, so only short strings stay implicit.
            .string => |s| s.len <= 100,
            else => true,
        };
    }

    fn scalarOrFlow(self: *Emitter, v: Value) Error!void {
        switch (v) {
            .sequence, .mapping => try self.flow(v),
            else => try scalar(self.w, v),
        }
    }

    /// Flow style, for collection keys: `[a, "b"]`, `{k: v}`.
    fn flow(self: *Emitter, v: Value) Error!void {
        switch (v) {
            .sequence => |items| {
                try self.w.writeByte('[');
                for (items, 0..) |it, i| {
                    if (i != 0) try self.w.writeAll(", ");
                    if (!try self.prefix(it, " ")) try self.flow(it);
                }
                try self.w.writeByte(']');
            },
            .mapping => |pairs| {
                try self.w.writeByte('{');
                for (pairs, 0..) |p, i| {
                    if (i != 0) try self.w.writeAll(", ");
                    // `? ` keeps any key — even a collection — legal in flow.
                    try self.w.writeAll("? ");
                    if (try self.prefix(p.key, " ")) try self.w.writeByte(' ') else try self.flow(p.key);
                    try self.w.writeAll(": ");
                    if (!try self.prefix(p.value, " ")) try self.flow(p.value);
                }
                try self.w.writeByte('}');
            },
            else => try scalar(self.w, v),
        }
    }
};

/// Write one document (`v` and a final newline).
pub fn writeValue(gpa: std.mem.Allocator, w: *Io.Writer, v: Value) Error!void {
    var e: Emitter = .{ .w = w, .gpa = gpa };
    defer e.deinit();
    try e.count(v);
    if (Emitter.isBlock(v)) {
        // A shared root cannot exist (no cycles), so no anchor is needed here.
        try e.block(v, 0);
    } else {
        if (!try e.prefix(v, " ")) try e.scalarOrFlow(v);
        try w.writeByte('\n');
    }
}

/// Write a stream: each document after a `---` line.
pub fn writeAll(gpa: std.mem.Allocator, w: *Io.Writer, docs: []const Value) Error!void {
    for (docs) |d| {
        try w.writeAll("---\n");
        try writeValue(gpa, w, d);
    }
}

/// `writeValue` into a new `gpa`-owned slice.
pub fn stringify(gpa: std.mem.Allocator, v: Value) Error![]u8 {
    var aw: Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    // The allocating writer fails only when its allocator does.
    writeValue(gpa, &aw.writer, v) catch |e| return switch (e) {
        error.WriteFailed => error.OutOfMemory,
        else => e,
    };
    return aw.toOwnedSlice();
}

// ── scalars ────────────────────────────────────────────────────────────────

fn scalar(w: *Io.Writer, v: Value) Error!void {
    switch (v) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .int => |i| try w.print("{d}", .{i}),
        .float => |f| try writeFloat(w, f),
        .string => |s| if (isSafePlain(s)) try w.writeAll(s) else try doubleQuoted(w, s),
        .sequence, .mapping => unreachable,
    }
}

/// Words a YAML 1.1 or 1.2 resolver reads as null / bool (compared
/// case-insensitively, which covers every spelling either version accepts).
const reserved = [_][]const u8{ "null", "true", "false", "yes", "no", "on", "off", "y", "n" };

/// A string that every YAML 1.1 and 1.2 reader takes, written plain, as the
/// same string.
pub fn isSafePlain(s: []const u8) bool {
    if (s.len == 0 or s.len > 512) return false;
    const c0 = s[0];
    if (!(std.ascii.isAlphabetic(c0) or c0 == '_' or c0 == '/')) return false;
    if (s[s.len - 1] == ' ') return false;
    for (s) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '.' or c == '/' or c == '-' or c == ' ')) return false;
    }
    for (reserved) |r| if (std.ascii.eqlIgnoreCase(s, r)) return false;
    return true;
}

/// YAML's c-printable: what may appear unescaped in a double-quoted scalar.
fn printable(cp: u21) bool {
    return cp == 0x9 or cp == 0xA or cp == 0xD or (cp >= 0x20 and cp <= 0x7E) or cp == 0x85 or
        (cp >= 0xA0 and cp <= 0xD7FF) or (cp >= 0xE000 and cp <= 0xFFFD) or cp >= 0x10000;
}

fn doubleQuoted(w: *Io.Writer, s: []const u8) Error!void {
    var view = std.unicode.Utf8View.init(s) catch return error.InvalidUtf8;
    var it = view.iterator();
    try w.writeByte('"');
    while (it.nextCodepointSlice()) |seq| {
        const cp = std.unicode.utf8Decode(seq) catch return error.InvalidUtf8;
        switch (cp) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            0 => try w.writeAll("\\0"),
            0x07 => try w.writeAll("\\a"),
            0x08 => try w.writeAll("\\b"),
            '\t' => try w.writeAll("\\t"),
            '\n' => try w.writeAll("\\n"),
            0x0B => try w.writeAll("\\v"),
            0x0C => try w.writeAll("\\f"),
            '\r' => try w.writeAll("\\r"),
            0x1B => try w.writeAll("\\e"),
            0x85 => try w.writeAll("\\N"),
            0x2028 => try w.writeAll("\\L"),
            0x2029 => try w.writeAll("\\P"),
            else => if (cp == 0xFEFF or !printable(cp)) {
                if (cp <= 0xFF) {
                    try w.print("\\x{X:0>2}", .{cp});
                } else if (cp <= 0xFFFF) {
                    try w.print("\\u{X:0>4}", .{cp});
                } else {
                    try w.print("\\U{X:0>8}", .{cp});
                }
            } else try w.writeAll(seq),
        }
    }
    try w.writeByte('"');
}

fn writeFloat(w: *Io.Writer, x: f64) Error!void {
    if (std.math.isNan(x)) return w.writeAll(".nan");
    if (std.math.isInf(x)) return w.writeAll(if (x > 0) ".inf" else "-.inf");
    if (std.math.signbit(x)) try w.writeByte('-');
    const a = @abs(x);
    // Shortest round-trip digits and exponent from `{e}`: x = 0.d0d1... * 10^n.
    var sbuf: [64]u8 = undefined;
    const sci = std.fmt.bufPrint(&sbuf, "{e}", .{a}) catch unreachable;
    const e_at = std.mem.indexOfScalar(u8, sci, 'e').?;
    var digits_buf: [32]u8 = undefined;
    var k: usize = 0;
    for (sci[0..e_at]) |c| if (c != '.') {
        digits_buf[k] = c;
        k += 1;
    };
    while (k > 1 and digits_buf[k - 1] == '0') k -= 1;
    const digits = digits_buf[0..k];
    const n: i32 = (std.fmt.parseInt(i32, sci[e_at + 1 ..], 10) catch unreachable) + 1;
    const ki: i32 = @intCast(k);
    if (ki <= n and n <= 21) {
        try w.writeAll(digits);
        try w.splatByteAll('0', @intCast(n - ki));
        try w.writeAll(".0");
    } else if (0 < n and n <= 21) {
        try w.writeAll(digits[0..@intCast(n)]);
        try w.writeByte('.');
        try w.writeAll(digits[@intCast(n)..]);
    } else if (-6 < n and n <= 0) {
        try w.writeAll("0.");
        try w.splatByteAll('0', @intCast(-n));
        try w.writeAll(digits);
    } else {
        try w.writeByte(digits[0]);
        try w.writeByte('.');
        if (k > 1) try w.writeAll(digits[1..]) else try w.writeByte('0');
        const e = n - 1;
        try w.print("e{c}{d}", .{ @as(u8, if (e < 0) '-' else '+'), @abs(e) });
    }
}

// SPDX-License-Identifier: MIT
//! The `pprint` filter: Python's `pprint.pformat(obj)` (width 80, indent 1,
//! sorted dict keys, not compact), as Jinja2's `pformat` calls it, over this
//! module's value model. `str`, `list`, `tuple` and `dict` are wrapped the way
//! `PrettyPrinter` wraps them; every other value is its `repr`.

const std = @import("std");
const value = @import("value.zig");

const Value = value.Value;
pub const Error = value.Error;

const width: usize = 80;

fn leafRepr(arena: std.mem.Allocator, v: Value) Error![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    try value.reprTo(&aw.writer, v);
    return aw.written();
}

fn cpLen(s: []const u8) usize {
    var n: usize = 0;
    for (s) |c| {
        if (c & 0xc0 != 0x80) n += 1;
    }
    return n;
}

fn typeName(v: Value) []const u8 {
    return switch (v) {
        .boolean => "bool",
        .float => "float",
        .integer => "int",
        .none => "NoneType",
        .string => "str",
        .tuple => "tuple",
        .list => "list",
        .map => "dict",
        else => "object",
    };
}

fn numOf(v: Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .boolean => |b| if (b) 1.0 else 0.0,
        else => null,
    };
}

/// `_safe_key.__lt__`: the natural order where the types compare, the type
/// names otherwise.
fn keyLess(a: Value, b: Value) bool {
    if (a == .string and b == .string) return std.mem.lessThan(u8, a.string.bytes, b.string.bytes);
    if (numOf(a)) |x| if (numOf(b)) |y| return x < y;
    if (a == .tuple and b == .tuple) {
        for (a.tuple, 0..) |e, i| {
            if (i >= b.tuple.len) return false;
            if (keyLess(e, b.tuple[i])) return true;
            if (keyLess(b.tuple[i], e)) return false;
        }
        return a.tuple.len < b.tuple.len;
    }
    return std.mem.lessThan(u8, typeName(a), typeName(b));
}

fn sortedPairs(arena: std.mem.Allocator, pairs: []const value.Pair) Error![]value.Pair {
    const out = try arena.dupe(value.Pair, pairs);
    std.mem.sort(value.Pair, out, {}, struct {
        fn lt(_: void, a: value.Pair, b: value.Pair) bool {
            return keyLess(a.key, b.key);
        }
    }.lt);
    return out;
}

/// `PrettyPrinter._safe_repr` with `sort_dicts`.
fn srepr(arena: std.mem.Allocator, v: Value, depth: usize) Error![]const u8 {
    if (depth > 64) return error.OutOfRange;
    switch (v) {
        .list, .tuple => |items| {
            var out: std.ArrayList(u8) = .empty;
            try out.append(arena, if (v == .list) '[' else '(');
            for (items, 0..) |e, i| {
                if (i != 0) try out.appendSlice(arena, ", ");
                try out.appendSlice(arena, try srepr(arena, e, depth + 1));
            }
            if (v == .tuple and items.len == 1) try out.append(arena, ',');
            try out.append(arena, if (v == .list) ']' else ')');
            return out.items;
        },
        .map => |m| {
            var out: std.ArrayList(u8) = .empty;
            try out.append(arena, '{');
            for (try sortedPairs(arena, m.pairs), 0..) |p, i| {
                if (i != 0) try out.appendSlice(arena, ", ");
                try out.appendSlice(arena, try srepr(arena, p.key, depth + 1));
                try out.appendSlice(arena, ": ");
                try out.appendSlice(arena, try srepr(arena, p.value, depth + 1));
            }
            try out.append(arena, '}');
            return out.items;
        },
        else => return leafRepr(arena, v),
    }
}

const P = struct {
    arena: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,

    fn w(self: *P, s: []const u8) Error!void {
        try self.out.appendSlice(self.arena, s);
    }

    fn spaces(self: *P, n: usize) Error!void {
        try self.out.appendNTimes(self.arena, ' ', n);
    }

    fn format(self: *P, v: Value, indent: usize, allowance: usize, level: usize) Error!void {
        const rep = try srepr(self.arena, v, 0);
        const max_width: i64 = @as(i64, @intCast(width)) - @as(i64, @intCast(indent)) - @as(i64, @intCast(allowance));
        if (@as(i64, @intCast(cpLen(rep))) > max_width) {
            switch (v) {
                .map => |m| return self.dict(m.pairs, indent, allowance, level + 1),
                .list => |xs| {
                    try self.w("[");
                    try self.items(xs, indent, allowance + 1, level + 1);
                    return self.w("]");
                },
                .tuple => |xs| {
                    try self.w("(");
                    const end: []const u8 = if (xs.len == 1) ",)" else ")";
                    try self.items(xs, indent, allowance + end.len, level + 1);
                    return self.w(end);
                },
                .string => |s| return self.str(s.bytes, indent, allowance, level + 1),
                else => {},
            }
        }
        try self.w(rep);
    }

    fn items(self: *P, xs: []const Value, indent_in: usize, allowance: usize, level: usize) Error!void {
        const indent = indent_in + 1;
        for (xs, 0..) |e, i| {
            if (i != 0) {
                try self.w(",\n");
                try self.spaces(indent);
            }
            const last = i + 1 == xs.len;
            try self.format(e, indent, if (last) allowance else 1, level);
        }
    }

    fn dict(self: *P, pairs: []const value.Pair, indent_in: usize, allowance: usize, level: usize) Error!void {
        try self.w("{");
        if (pairs.len != 0) {
            const sorted = try sortedPairs(self.arena, pairs);
            const indent = indent_in + 1;
            for (sorted, 0..) |p, i| {
                const last = i + 1 == sorted.len;
                const rep = try srepr(self.arena, p.key, 0);
                try self.w(rep);
                try self.w(": ");
                try self.format(p.value, indent + cpLen(rep) + 2, if (last) allowance + 1 else 1, level);
                if (!last) {
                    try self.w(",\n");
                    try self.spaces(indent);
                }
            }
        }
        try self.w("}");
    }

    fn str(self: *P, s: []const u8, indent_in: usize, allowance_in: usize, level: usize) Error!void {
        if (s.len == 0) return self.w(try leafRepr(self.arena, Value.str(s)));
        var indent = indent_in;
        var allowance = allowance_in;
        if (level == 1) {
            indent += 1;
            allowance += 1;
        }
        const max_width: i64 = @as(i64, @intCast(width)) - @as(i64, @intCast(indent));
        var max_width1 = max_width;
        var chunks: std.ArrayList([]const u8) = .empty;
        // `str.splitlines(True)`
        var lines: std.ArrayList([]const u8) = .empty;
        var st: usize = 0;
        var i: usize = 0;
        while (i < s.len) {
            const c = s[i];
            var brk: usize = 0;
            if (c == '\r' and i + 1 < s.len and s[i + 1] == '\n') {
                brk = 2;
            } else if (c == '\n' or c == '\r' or c == 0x0b or c == 0x0c or (c >= 0x1c and c <= 0x1e)) {
                brk = 1;
            } else if (c == 0xc2 and i + 1 < s.len and s[i + 1] == 0x85) {
                // U+0085 NEL; with U+2028/U+2029 below, Python's
                // `str.splitlines` breaks on them too (2026-11-27).
                brk = 2;
            } else if (c == 0xe2 and i + 2 < s.len and s[i + 1] == 0x80 and (s[i + 2] == 0xa8 or s[i + 2] == 0xa9)) {
                brk = 3;
            }
            if (brk != 0) {
                try lines.append(self.arena, s[st .. i + brk]);
                i += brk;
                st = i;
            } else i += 1;
        }
        if (st < s.len) try lines.append(self.arena, s[st..]);
        var last_rep: []const u8 = "";
        for (lines.items, 0..) |line, li| {
            const rep = try leafRepr(self.arena, Value.str(line));
            last_rep = rep;
            const is_last_line = li + 1 == lines.items.len;
            if (is_last_line) max_width1 -= @intCast(allowance);
            if (@as(i64, @intCast(cpLen(rep))) <= max_width1) {
                try chunks.append(self.arena, rep);
                continue;
            }
            // `re.findall(r'\S*\s*', line)` without its empty last match.
            var parts: std.ArrayList([]const u8) = .empty;
            var p: usize = 0;
            while (p < line.len) {
                var q = p;
                while (q < line.len and !isSpace(line[q])) q += 1;
                while (q < line.len and isSpace(line[q])) q += 1;
                try parts.append(self.arena, line[p..q]);
                p = q;
            }
            var max_width2 = max_width;
            var current: []const u8 = "";
            for (parts.items, 0..) |part, j| {
                const cand = try std.mem.concat(self.arena, u8, &.{ current, part });
                if (j + 1 == parts.items.len and is_last_line) max_width2 -= @intCast(allowance);
                if (@as(i64, @intCast(cpLen(try leafRepr(self.arena, Value.str(cand))))) > max_width2) {
                    if (current.len != 0) try chunks.append(self.arena, try leafRepr(self.arena, Value.str(current)));
                    current = part;
                } else current = cand;
            }
            if (current.len != 0) try chunks.append(self.arena, try leafRepr(self.arena, Value.str(current)));
        }
        if (chunks.items.len == 1) return self.w(last_rep);
        if (level == 1) try self.w("(");
        for (chunks.items, 0..) |c, ci| {
            if (ci > 0) {
                try self.w("\n");
                try self.spaces(indent);
            }
            try self.w(c);
        }
        if (level == 1) try self.w(")");
    }
};

fn isSpace(c: u8) bool {
    return c == ' ' or (c >= 0x09 and c <= 0x0d) or (c >= 0x1c and c <= 0x1f);
}

/// `pprint.pformat(v)`.
pub fn pformat(arena: std.mem.Allocator, v: Value) Error![]const u8 {
    var p: P = .{ .arena = arena };
    try p.format(v, 0, 0, 0);
    return p.out.items;
}

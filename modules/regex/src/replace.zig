// SPDX-License-Identifier: MIT

//! What Go's `regexp` builds on top of a search: template expansion
//! (`Expand`), replacing every match (`ReplaceAll*`), splitting by matches
//! (`Split`), quoting text into a pattern (`QuoteMeta`) and the literal text
//! every match starts with (`LiteralPrefix`). Everything writes to a
//! `std.Io.Writer` or yields slices of the input; the allocating forms are
//! thin wrappers in `root.zig`.

const std = @import("std");
const root = @import("root.zig");
const syntax = @import("syntax.zig");

const Writer = std.Io.Writer;
const Regex = root.Regex;
const Matcher = root.Matcher;
const Span = root.Span;

/// Append `template` to `w` with its variables replaced from a match:
/// `$1`/`${1}` is group 1's text, `$name`/`${name}` the group of that name,
/// `$$` a literal `$` (Go's `Expand`). A name is letters, digits and `_` —
/// Unicode ones, as Go — and `$name` takes as many as it can (`$1x` is
/// `${1x}`). Only ASCII digits without a leading zero make a group number. An
/// out-of-range number, an unknown name, or a group that took no part writes
/// nothing; a `$` that starts no variable is written as it is.
pub fn expand(re: *const Regex, w: *Writer, template: []const u8, input: []const u8, groups: []const ?Span) Writer.Error!void {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, template, i, '$')) |d| {
        try w.writeAll(template[i..d]);
        if (d + 1 < template.len and template[d + 1] == '$') {
            try w.writeByte('$');
            i = d + 2;
            continue;
        }
        const ref = variable(template, d + 1) orelse {
            try w.writeByte('$');
            i = d + 1;
            continue;
        };
        i = ref.end;
        const g = groupOf(re, ref.name) orelse continue;
        if (g < groups.len) if (groups[g]) |s| try w.writeAll(s.slice(input));
    }
    try w.writeAll(template[i..]);
}

const Ref = struct { name: []const u8, end: usize };

/// The variable after a `$` at `t[j..]`: `{name}` or a bare name.
fn variable(t: []const u8, j: usize) ?Ref {
    if (j < t.len and t[j] == '{') {
        const end = nameEnd(t, j + 1);
        if (end == j + 1 or end >= t.len or t[end] != '}') return null;
        return .{ .name = t[j + 1 .. end], .end = end + 1 };
    }
    const end = nameEnd(t, j);
    if (end == j) return null;
    return .{ .name = t[j..end], .end = end };
}

/// The end of the run of name characters at `t[j..]`.
fn nameEnd(t: []const u8, j: usize) usize {
    var i = j;
    while (i < t.len) {
        const c = t[i];
        if (c < 0x80) {
            if (!(std.ascii.isAlphanumeric(c) or c == '_')) break;
            i += 1;
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(c) catch break;
        if (i + len > t.len) break;
        const cp = std.unicode.utf8Decode(t[i..][0..len]) catch break;
        if (!(syntax.unicodeClassContains("l", cp) or syntax.unicodeClassContains("nd", cp))) break;
        i += len;
    }
    return i;
}

/// The group a variable names: a number (ASCII digits, no leading zero), or
/// the first group with that name.
fn groupOf(re: *const Regex, name: []const u8) ?usize {
    for (name) |c| if (!std.ascii.isDigit(c)) return re.groupIndex(name);
    if (name.len > 1 and name[0] == '0') return null;
    return std.fmt.parseInt(usize, name, 10) catch null;
}

/// Write `input` with every match (as the iterator finds them) replaced by
/// `template` expanded for it (Go's `ReplaceAllString`).
pub fn replaceAll(m: *Matcher, w: *Writer, input: []const u8, template: []const u8) Writer.Error!void {
    var groups: [root.max_groups]?Span = undefined;
    const g = groups[0..m.re.names.len];
    var it = m.iterator(input);
    var last: usize = 0;
    while (it.nextCaptures(g)) |s| {
        try w.writeAll(input[last..s.start]);
        try expand(m.re, w, template, input, g);
        last = s.end;
    }
    try w.writeAll(input[last..]);
}

/// `replaceAll` with `replacement` written as it is, no `$` expansion
/// (Go's `ReplaceAllLiteralString`).
pub fn replaceAllLiteral(m: *Matcher, w: *Writer, input: []const u8, replacement: []const u8) Writer.Error!void {
    var it = m.iterator(input);
    var last: usize = 0;
    while (it.next()) |s| {
        try w.writeAll(input[last..s.start]);
        try w.writeAll(replacement);
        last = s.end;
    }
    try w.writeAll(input[last..]);
}

/// `replaceAll` with each match replaced by what `f(context, w, match)`
/// writes (Go's `ReplaceAllStringFunc`).
pub fn replaceAllFunc(
    m: *Matcher,
    w: *Writer,
    input: []const u8,
    context: anytype,
    comptime f: fn (@TypeOf(context), *Writer, []const u8) Writer.Error!void,
) Writer.Error!void {
    var it = m.iterator(input);
    var last: usize = 0;
    while (it.next()) |s| {
        try w.writeAll(input[last..s.start]);
        try f(context, w, s.slice(input));
        last = s.end;
    }
    try w.writeAll(input[last..]);
}

/// The text between matches (Go's `Split`), as slices of the input: at most
/// `limit` pieces, the last one the unsplit rest (null: all of them; 0: none).
/// An empty match at the very start splits nothing off, and no empty piece
/// follows a match at the very end; an empty input is one empty piece, unless
/// the pattern itself is empty — Go's rules.
pub const SplitIterator = struct {
    it: Matcher.Iterator,
    input: []const u8,
    limit: ?usize,
    /// Start of the next piece.
    beg: usize = 0,
    /// Start of the last match taken.
    end: usize = 0,
    pieces: usize = 0,
    matches: usize = 0,
    state: enum { matches, rest, done },

    pub fn init(m: *Matcher, input: []const u8, limit: ?usize) SplitIterator {
        var s: SplitIterator = .{ .it = m.iterator(input), .input = input, .limit = limit, .state = .matches };
        if (limit != null and limit.? == 0) {
            s.state = .done;
        } else if (input.len == 0 and m.re.source.len != 0) {
            // Go: an empty input is one empty piece — unless the pattern is empty.
            s.state = .rest;
            s.end = 1;
        }
        return s;
    }

    pub fn next(s: *SplitIterator) ?[]const u8 {
        while (s.state == .matches) {
            if (s.limit) |n| if (s.pieces == n - 1 or s.matches == n) {
                s.state = .rest;
                break;
            };
            const match = s.it.next() orelse {
                s.state = .rest;
                break;
            };
            s.matches += 1;
            s.end = match.start;
            const piece_start = s.beg;
            s.beg = match.end;
            if (match.end != 0) {
                s.pieces += 1;
                return s.input[piece_start..match.start];
            }
        }
        if (s.state == .rest) {
            s.state = .done;
            if (s.end != s.input.len) {
                s.pieces += 1;
                return s.input[@min(s.beg, s.input.len)..];
            }
        }
        return null;
    }
};

/// Write `text` with every metacharacter escaped, so the result is a pattern
/// matching exactly `text` (Go's `QuoteMeta`: `\.+*?()|[]{}^$`).
pub fn quoteMeta(w: *Writer, text: []const u8) Writer.Error!void {
    var last: usize = 0;
    for (text, 0..) |c, i| {
        if (std.mem.indexOfScalar(u8, "\\.+*?()|[]{}^$", c) == null) continue;
        try w.writeAll(text[last..i]);
        try w.writeByte('\\');
        last = i;
    }
    try w.writeAll(text[last..]);
}

/// Write the literal text every match begins with; return whether that text
/// is the whole pattern — the only string it matches (Go's `LiteralPrefix`).
/// Followed from the program's start: the prefix grows while every live path
/// consumes the same one code point (case folding makes it a set, which ends
/// it). A `\A` (`^`) at the very start is passed but makes the prefix
/// incomplete; any other assertion, a place where a match may end, or a choice
/// of code points ends it. Complete when, after the prefix, the match is all
/// that is left.
pub fn literalPrefix(re: *const Regex, w: *Writer) Writer.Error!bool {
    const Sink = struct {
        w: *Writer,
        fn put(s: @This(), bytes: []const u8) Writer.Error!bool {
            try s.w.writeAll(bytes);
            return true;
        }
    };
    return walkPrefix(re.insts, re.ranges, Sink{ .w = w });
}

/// The first `buf.len` bytes (at most) of the literal prefix, for the
/// prefilter; its length. Also at comptime.
pub fn prefixInto(insts: []const syntax.Inst, ranges: []const syntax.Range, buf: []u8) usize {
    const Sink = struct {
        buf: []u8,
        n: *usize,
        fn put(s: @This(), bytes: []const u8) error{}!bool {
            if (s.n.* + bytes.len > s.buf.len) return false; // full: stop here
            // U+FFFD also matches an invalid byte, which these bytes would miss.
            if (std.mem.eql(u8, bytes, "\u{fffd}")) return false;
            @memcpy(s.buf[s.n.*..][0..bytes.len], bytes);
            s.n.* += bytes.len;
            return true;
        }
    };
    var n: usize = 0;
    _ = walkPrefix(insts, ranges, Sink{ .buf = buf, .n = &n }) catch unreachable;
    return n;
}

/// `literalPrefix` over a program, writing through `sink.put` (false: stop).
fn walkPrefix(insts: []const syntax.Inst, ranges: []const syntax.Range, sink: anytype) !bool {
    var cur: std.StaticBitSet(root.max_insts) = .initEmpty();
    var nxt: std.StaticBitSet(root.max_insts) = .initEmpty();
    var complete = true;
    var stopped = false;
    // At the start: `\A` may be passed.
    reach(insts, &cur, 0, true, &complete, &stopped);
    var steps: usize = 0;
    while (!stopped and steps <= root.max_insts) : (steps += 1) {
        var single: ?u21 = null;
        var ended = false;
        var it = cur.iterator(.{});
        while (it.next()) |pc| switch (insts[pc]) {
            .match => ended = true,
            .rune => |r| {
                const rs = ranges[r.start..][0..r.len];
                if (rs.len != 1 or rs[0].lo != rs[0].hi or (single != null and single.? != rs[0].lo)) {
                    ended = true;
                } else single = rs[0].lo;
            },
            else => ended = true, // any, any_not_nl
        };
        if (ended or single == null) {
            // Complete only when nothing but the match is left.
            if (complete) {
                var only_match = cur.count() == 1;
                var it2 = cur.iterator(.{});
                while (it2.next()) |pc| if (insts[pc] != .match) {
                    only_match = false;
                };
                complete = only_match;
            }
            return complete and !stopped;
        }
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(single.?, &buf) catch unreachable;
        if (!try sink.put(buf[0..n])) return false;
        nxt = .initEmpty();
        var it3 = cur.iterator(.{});
        while (it3.next()) |pc| reach(insts, &nxt, @intCast(pc + 1), false, &complete, &stopped);
        std.mem.swap(std.StaticBitSet(root.max_insts), &cur, &nxt);
    }
    return false;
}

/// Add to `set` the consuming states and the match reachable from `pc0`
/// without consuming. An assertion stops the prefix (`stopped`), except `\A`
/// at the start, which only makes it incomplete.
fn reach(insts: []const syntax.Inst, set: *std.StaticBitSet(root.max_insts), pc0: u16, at_start: bool, complete: *bool, stopped: *bool) void {
    var seen: std.StaticBitSet(root.max_insts) = .initEmpty();
    var stack: [2 * root.max_insts]u16 = undefined;
    var sp: usize = 1;
    stack[0] = pc0;
    while (sp != 0) {
        sp -= 1;
        const pc = stack[sp];
        if (seen.isSet(pc)) continue;
        seen.set(pc);
        switch (insts[pc]) {
            .jmp => |t| {
                stack[sp] = t;
                sp += 1;
            },
            .split => |s| {
                stack[sp] = s.y;
                stack[sp + 1] = s.x;
                sp += 2;
            },
            .save => {
                stack[sp] = pc + 1;
                sp += 1;
            },
            .assert => |a| {
                complete.* = false;
                if (at_start and a == .begin_text) {
                    stack[sp] = pc + 1;
                    sp += 1;
                } else stopped.* = true;
            },
            .rune, .any, .any_not_nl, .match => set.set(pc),
        }
    }
}

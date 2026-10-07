// SPDX-License-Identifier: MIT

//! Pattern → program: the RE2 / Go `regexp/syntax` grammar parsed into a small
//! AST, then compiled by Thompson's construction into the instruction list
//! the Pike VM in `root.zig` runs.
//!
//! No allocator: the `Builder` holds every table at a fixed capacity, so the
//! same code compiles a pattern at run time (the builder on the heap) and at
//! compile time (`comptime` — what `router.Static` needs). Capacities are the
//! module's documented limits; a pattern past one is `error.PatternTooLarge`,
//! never a truncated program.

const std = @import("std");

/// Instructions in one program — also what bounds the VM's own scratch.
pub const max_insts = 1024;
/// Character-class ranges, all classes of one pattern together.
pub const max_ranges = 4096;
/// AST nodes.
pub const max_nodes = 2048;
/// Capture groups, group 0 (the whole match) included.
pub const max_groups = 64;
/// `{n,m}`: n, m ≤ 1000 (Go's documented limit).
pub const max_repeat = 1000;
/// Nesting of groups and repetitions. Go goes deeper; 250 keeps the
/// recursive parser and compiler within a 512 KiB thread stack even in a
/// Debug build (a compile of untrusted patterns runs on whatever thread the
/// caller has), and no real pattern nests this far.
pub const max_depth = 250;

pub const Error = error{
    /// A `\` escape this grammar does not define (`\8`, `\y`, a backreference).
    InvalidEscape,
    /// A `\` at the very end of the pattern.
    TrailingBackslash,
    /// `[` with no closing `]`.
    MissingBracket,
    /// A range whose ends are out of order (`[z-a]`) or not single characters.
    InvalidCharRange,
    /// `[[:foo:]]` with an unknown class name.
    InvalidCharClass,
    /// `(` with no `)`.
    MissingParen,
    /// `)` with no `(`.
    UnexpectedParen,
    /// A repetition with nothing before it (`*a`, `(+)`, `a|*`).
    MissingRepeatArgument,
    /// A repetition of a repetition (`a**`, `a{2}{3}`).
    InvalidNestedRepeat,
    /// `{n,m}` with n or m above 1000, or m < n.
    InvalidRepeatSize,
    /// `(?` followed by something that is not a flag group or a named capture.
    InvalidPerlOp,
    /// `(?P<name>` with an empty or non-word name.
    InvalidNamedCapture,
    /// The pattern is not valid UTF-8.
    InvalidUtf8,
    /// Groups or repetitions nested deeper than `max_depth`.
    NestingDepth,
    /// Past `max_insts`, `max_ranges`, `max_nodes` or `max_groups`.
    PatternTooLarge,
    /// `\pL`, `\p{Greek}` — Unicode property classes need tables this module
    /// does not carry yet (SPEC Backlog).
    UnsupportedUnicodeClass,
};

/// An inclusive range of code points.
pub const Range = struct { lo: u21, hi: u21 };

pub const Assert = enum(u8) {
    begin_text, // \A, ^ without (?m)
    end_text, // \z, $ without (?m)
    begin_line, // ^ with (?m)
    end_line, // $ with (?m)
    word_boundary, // \b (ASCII word characters, as RE2)
    not_word_boundary, // \B
};

pub const Inst = union(enum) {
    /// Consume one code point inside `ranges[start..][0..len]` (sorted, merged).
    rune: struct { start: u16, len: u16 },
    /// Consume any code point.
    any,
    /// Consume any code point but `\n`.
    any_not_nl,
    /// Continue at `x` (preferred) and at `y`.
    split: struct { x: u16, y: u16 },
    jmp: u16,
    /// Record the position into capture slot `n` (group n/2, start or end).
    save: u16,
    assert: Assert,
    match,
};

const none: u16 = std.math.maxInt(u16);

const Kind = enum(u8) { empty, literal, class, any, any_not_nl, assert, capture, concat, alternate, repeat };

const Node = struct {
    kind: Kind,
    /// literal: the code point. class: first range. assert: the `Assert`.
    /// capture: the group index. repeat: min.
    a: u32 = 0,
    /// class: range count. repeat: max (`inf` = unbounded).
    b: u32 = 0,
    /// literal: fold case. repeat: greedy.
    flag: bool = false,
    /// repeat: written `{n}`, `{n,}` or `{n,m}` (counts toward the nested
    /// repetition limit; `*`, `+` and `?` do not).
    counted: bool = false,
    /// capture/repeat: the operand; concat/alternate: the first operand.
    child: u16 = none,
    /// The next operand of the enclosing concat/alternate.
    next: u16 = none,
};

const inf: u32 = std.math.maxInt(u32);

const Flags = struct {
    fold: bool = false, // i
    multi_line: bool = false, // m
    dot_nl: bool = false, // s
    ungreedy: bool = false, // U
};

/// Every table of one compilation, at fixed capacity.
pub const Builder = struct {
    insts: [max_insts]Inst = undefined,
    ninsts: u16 = 0,
    ranges: [max_ranges]Range = undefined,
    nranges: u16 = 0,
    nodes: [max_nodes]Node = undefined,
    nnodes: u16 = 0,
    /// Group names, `""` for an unnamed group; [0] is the whole match.
    names: [max_groups][]const u8 = undefined,
    ngroups: u16 = 1,

    // ── parser state ──
    src: []const u8 = "",
    pos: usize = 0,

    pub fn compile(b: *Builder, pattern: []const u8) Error!void {
        b.* = .{};
        b.names[0] = "";
        if (!std.unicode.utf8ValidateSlice(pattern)) return error.InvalidUtf8;
        b.src = pattern;
        var flags: Flags = .{};
        const root = try b.parseAlternate(&flags, 0);
        if (b.pos < b.src.len) return error.UnexpectedParen; // a `)` ended it
        // save 0; root; save 1; match
        try b.emit(.{ .save = 0 });
        try b.emitNode(root);
        try b.emit(.{ .save = 1 });
        try b.emit(.match);
    }

    // ── parsing ──────────────────────────────────────────────────────────

    fn node(b: *Builder, n: Node) Error!u16 {
        if (b.nnodes == max_nodes) return error.PatternTooLarge;
        b.nodes[b.nnodes] = n;
        b.nnodes += 1;
        return b.nnodes - 1;
    }

    fn eof(b: *const Builder) bool {
        return b.pos >= b.src.len;
    }

    fn peek(b: *const Builder) u8 {
        return b.src[b.pos];
    }

    /// The next code point of the pattern (validated UTF-8).
    fn nextRune(b: *Builder) u21 {
        const len = std.unicode.utf8ByteSequenceLength(b.src[b.pos]) catch unreachable;
        const cp = std.unicode.utf8Decode(b.src[b.pos..][0..len]) catch unreachable;
        b.pos += len;
        return cp;
    }

    /// `a|b|...` up to a `)` or the end. `flags` is the enclosing group's:
    /// a `(?i)` inside one alternative holds for the rest of the group,
    /// later alternatives included.
    fn parseAlternate(b: *Builder, flags: *Flags, depth: u32) Error!u16 {
        if (depth > max_depth) return error.NestingDepth;
        const first = try b.parseConcat(flags, depth);
        if (b.eof() or b.peek() != '|') return first;
        const alt = try b.node(.{ .kind = .alternate, .child = first });
        var last = first;
        while (!b.eof() and b.peek() == '|') {
            b.pos += 1;
            const n = try b.parseConcat(flags, depth);
            b.nodes[last].next = n;
            last = n;
        }
        return alt;
    }

    fn parseConcat(b: *Builder, flags: *Flags, depth: u32) Error!u16 {
        const cat = try b.node(.{ .kind = .concat });
        var last: u16 = none;
        // The last operand, which a repetition applies to, and whether it
        // already is one (`a**` is an error, as in RE2).
        var operand: u16 = none;
        var repeated = false;
        while (!b.eof()) {
            const c = b.peek();
            if (c == '|' or c == ')') break;
            if (c == '*' or c == '+' or c == '?' or c == '{') {
                const rep = try b.parseRepeatOp(flags.*) orelse {
                    // A `{` that is not a repetition is a literal.
                    b.pos += 1;
                    operand = try b.literal('{', flags.*);
                    repeated = false;
                    last = b.append(cat, last, operand);
                    continue;
                };
                if (operand == none) return error.MissingRepeatArgument;
                if (repeated) return error.InvalidNestedRepeat;
                if (depth + 1 > max_depth) return error.NestingDepth;
                // Wrap the operand in place: it keeps its link in the list.
                const inner = try b.node(b.nodes[operand]);
                b.nodes[inner].next = none;
                b.nodes[operand] = .{ .kind = .repeat, .a = rep.min, .b = rep.max, .flag = rep.greedy, .counted = rep.counted, .child = inner, .next = b.nodes[operand].next };
                // Nested counted repetitions multiply: Go refuses a product
                // past 1000, and that also bounds the compiler's work (an
                // empty body emits nothing, so no capacity would stop it).
                if (rep.counted and b.repeatSize(operand) > max_repeat) return error.InvalidRepeatSize;
                repeated = true;
                continue;
            }
            // A flag group `(?i)` is transparent: `a(?i)*` repeats `a` (Go).
            const n = try b.parseAtom(flags, depth) orelse continue;
            repeated = false;
            if (b.nodes[n].kind == .concat and b.nodes[n].flag) {
                // `\Q...\E`: its literals join this concat one by one, so a
                // repetition after it takes the last one only.
                var lit = b.nodes[n].child;
                while (lit != none) {
                    const nx = b.nodes[lit].next;
                    b.nodes[lit].next = none;
                    last = b.append(cat, last, lit);
                    operand = lit;
                    lit = nx;
                }
                continue;
            }
            operand = n;
            last = b.append(cat, last, n);
        }
        return cat;
    }

    /// The repetition size Go limits: a counted repetition multiplies its
    /// operand's size by its count (the max, or the min when unbounded; at
    /// least 1); anything else is the largest size among its operands.
    fn repeatSize(b: *const Builder, n: u16) u64 {
        const nd = b.nodes[n];
        var inner: u64 = 1;
        switch (nd.kind) {
            .capture, .repeat => inner = b.repeatSize(nd.child),
            .concat, .alternate => {
                var c = nd.child;
                while (c != none) : (c = b.nodes[c].next) inner = @max(inner, b.repeatSize(c));
            },
            else => {},
        }
        if (nd.kind == .repeat and nd.counted) {
            const count: u64 = if (nd.b == inf) nd.a else nd.b;
            return @max(count, 1) * inner;
        }
        return inner;
    }

    fn append(b: *Builder, cat: u16, last: u16, n: u16) u16 {
        if (last == none) b.nodes[cat].child = n else b.nodes[last].next = n;
        return n;
    }

    const Rep = struct { min: u32, max: u32, greedy: bool, counted: bool = false };

    /// A repetition operator at `pos`, consumed; null (nothing consumed) for a
    /// `{` that does not start a valid `{n}`, `{n,}` or `{n,m}`.
    fn parseRepeatOp(b: *Builder, flags: Flags) Error!?Rep {
        var r: Rep = .{ .min = 0, .max = 0, .greedy = true };
        switch (b.peek()) {
            '*' => {
                r = .{ .min = 0, .max = inf, .greedy = true };
                b.pos += 1;
            },
            '+' => {
                r = .{ .min = 1, .max = inf, .greedy = true };
                b.pos += 1;
            },
            '?' => {
                r = .{ .min = 0, .max = 1, .greedy = true };
                b.pos += 1;
            },
            '{' => {
                var p = b.pos + 1;
                const lo = parseInt(b.src, &p) orelse return null;
                var hi: ?u32 = lo;
                if (p < b.src.len and b.src[p] == ',') {
                    p += 1;
                    if (p < b.src.len and b.src[p] == '}') hi = null else hi = parseInt(b.src, &p) orelse return null;
                }
                if (p >= b.src.len or b.src[p] != '}') return null;
                b.pos = p + 1;
                if (lo > max_repeat or (hi != null and (hi.? > max_repeat or hi.? < lo))) return error.InvalidRepeatSize;
                r = .{ .min = lo, .max = hi orelse inf, .greedy = true, .counted = true };
            },
            else => unreachable,
        }
        if (!b.eof() and b.peek() == '?') {
            b.pos += 1;
            r.greedy = false;
        }
        if (flags.ungreedy) r.greedy = !r.greedy;
        return r;
    }

    /// Decimal digits at `p.*` (advanced past them), or null for none. Values
    /// past `max_repeat` saturate just above it, so the caller reports the
    /// size, not an overflow.
    fn parseInt(s: []const u8, p: *usize) ?u32 {
        const start = p.*;
        var v: u32 = 0;
        while (p.* < s.len and std.ascii.isDigit(s[p.*])) : (p.* += 1) {
            v = @min(v * 10 + (s[p.*] - '0'), max_repeat + 1);
        }
        if (p.* == start) return null;
        return v;
    }

    fn literal(b: *Builder, cp: u21, flags: Flags) Error!u16 {
        return b.node(.{ .kind = .literal, .a = cp, .flag = flags.fold and hasFold(cp) });
    }

    /// One operand; null when the "atom" was a bare flag group `(?i)`.
    fn parseAtom(b: *Builder, flags: *Flags, depth: u32) Error!?u16 {
        const c = b.peek();
        switch (c) {
            '(' => return b.parseGroup(flags, depth),
            '[' => return try b.parseClass(flags.*),
            '.' => {
                b.pos += 1;
                return try b.node(.{ .kind = if (flags.dot_nl) .any else .any_not_nl });
            },
            '^' => {
                b.pos += 1;
                return try b.node(.{ .kind = .assert, .a = @intFromEnum(if (flags.multi_line) Assert.begin_line else Assert.begin_text) });
            },
            '$' => {
                b.pos += 1;
                return try b.node(.{ .kind = .assert, .a = @intFromEnum(if (flags.multi_line) Assert.end_line else Assert.end_text) });
            },
            '\\' => return try b.parseEscape(flags.*),
            else => return try b.literal(b.nextRune(), flags.*),
        }
    }

    fn parseGroup(b: *Builder, flags: *Flags, depth: u32) Error!?u16 {
        b.pos += 1; // (
        var name: ?[]const u8 = null;
        var inner = flags.*;
        if (std.mem.startsWith(u8, b.src[b.pos..], "?P<") or std.mem.startsWith(u8, b.src[b.pos..], "?<")) {
            b.pos += if (b.src[b.pos + 1] == 'P') 3 else 2;
            const end = std.mem.indexOfScalarPos(u8, b.src, b.pos, '>') orelse return error.InvalidNamedCapture;
            const n = b.src[b.pos..end];
            if (n.len == 0) return error.InvalidNamedCapture;
            for (n) |ch| if (!(std.ascii.isAlphanumeric(ch) or ch == '_')) return error.InvalidNamedCapture;
            name = n;
            b.pos = end + 1;
        } else if (!b.eof() and b.peek() == '?') {
            // (?flags) or (?flags:re)
            b.pos += 1;
            var negate = false;
            var any = false;
            while (true) {
                if (b.eof()) return error.MissingParen;
                const f = b.peek();
                b.pos += 1;
                switch (f) {
                    'i' => inner.fold = !negate,
                    'm' => inner.multi_line = !negate,
                    's' => inner.dot_nl = !negate,
                    'U' => inner.ungreedy = !negate,
                    '-' => {
                        if (negate) return error.InvalidPerlOp;
                        negate = true;
                        any = false;
                        continue;
                    },
                    ')' => {
                        // `(?)` is an empty flag group (Go takes it); `(?i-)`
                        // and `(?-)` clear nothing and are refused.
                        if (negate and !any) return error.InvalidPerlOp;
                        flags.* = inner;
                        return null;
                    },
                    ':' => {
                        if (negate and !any) return error.InvalidPerlOp;
                        break;
                    },
                    else => return error.InvalidPerlOp,
                }
                any = true;
            }
            const body = try b.parseAlternate(&inner, depth + 1);
            if (b.eof() or b.peek() != ')') return error.MissingParen;
            b.pos += 1;
            return body;
        }
        if (b.ngroups == max_groups) return error.PatternTooLarge;
        const index = b.ngroups;
        b.names[index] = name orelse "";
        b.ngroups += 1;
        const body = try b.parseAlternate(&inner, depth + 1);
        if (b.eof() or b.peek() != ')') return error.MissingParen;
        b.pos += 1;
        return try b.node(.{ .kind = .capture, .a = index, .child = body });
    }

    // ── escapes and classes ──────────────────────────────────────────────

    const Escape = union(enum) {
        rune: u21,
        /// \d \s \w and their negations: ranges appended at `start`.
        class: struct { start: u16, len: u16 },
        assert: Assert,
        /// `\Q...\E`: literal text.
        quoted: []const u8,
    };

    fn parseEscape(b: *Builder, flags: Flags) Error!u16 {
        switch (try b.escape(false, flags.fold)) {
            .rune => |cp| return b.literal(cp, flags),
            .class => |cl| return b.node(.{ .kind = .class, .a = cl.start, .b = cl.len }),
            .assert => |a| return b.node(.{ .kind = .assert, .a = @intFromEnum(a) }),
            .quoted => |text| {
                // A concat of literals (the enclosing concat takes it as one operand).
                const cat = try b.node(.{ .kind = .concat, .flag = true }); // flag: spliced by parseConcat
                var last: u16 = none;
                var i: usize = 0;
                while (i < text.len) {
                    const len = std.unicode.utf8ByteSequenceLength(text[i]) catch unreachable;
                    const cp = std.unicode.utf8Decode(text[i..][0..len]) catch unreachable;
                    i += len;
                    last = b.append(cat, last, try b.literal(cp, flags));
                }
                return cat;
            },
        }
    }

    /// One escape after `\` (at `pos`). `in_class`: inside `[...]`, where
    /// assertions and `\Q` mean nothing. `fold`: a class escape is folded
    /// before it is negated, as Go does — `(?i)\W` excludes U+017F and
    /// U+212A, which fold to `s` and `k`.
    fn escape(b: *Builder, in_class: bool, fold: bool) Error!Escape {
        b.pos += 1; // backslash
        if (b.eof()) return error.TrailingBackslash;
        const c = b.peek();
        if (c >= 0x80) return error.InvalidEscape;
        b.pos += 1;
        switch (c) {
            'a' => return .{ .rune = 0x07 },
            'f' => return .{ .rune = 0x0c },
            't' => return .{ .rune = '\t' },
            'n' => return .{ .rune = '\n' },
            'r' => return .{ .rune = '\r' },
            'v' => return .{ .rune = 0x0b },
            '0'...'7' => {
                // Octal, up to three digits. A lone 1-7 would be a
                // backreference, which RE2 does not have.
                var v: u21 = c - '0';
                var n: usize = 1;
                while (n < 3 and !b.eof() and b.peek() >= '0' and b.peek() <= '7') : (n += 1) {
                    v = v * 8 + (b.peek() - '0');
                    b.pos += 1;
                }
                if (c != '0' and n == 1) return error.InvalidEscape;
                return .{ .rune = v };
            },
            'x' => {
                if (b.eof()) return error.InvalidEscape;
                if (b.peek() == '{') {
                    // Any number of hex digits (leading zeros too), at most U+10FFFF.
                    const end = std.mem.indexOfScalarPos(u8, b.src, b.pos, '}') orelse return error.InvalidEscape;
                    const digits = b.src[b.pos + 1 .. end];
                    if (digits.len == 0) return error.InvalidEscape;
                    var v: u32 = 0;
                    for (digits) |d| {
                        v = v * 16 + (hexDigit(d) orelse return error.InvalidEscape);
                        if (v > 0x10ffff) return error.InvalidEscape;
                    }
                    b.pos = end + 1;
                    return .{ .rune = @intCast(v) };
                }
                if (b.pos + 2 > b.src.len) return error.InvalidEscape;
                const hi = hexDigit(b.src[b.pos]) orelse return error.InvalidEscape;
                const lo = hexDigit(b.src[b.pos + 1]) orelse return error.InvalidEscape;
                b.pos += 2;
                return .{ .rune = @intCast(hi * 16 + lo) };
            },
            'd', 'D', 's', 'S', 'w', 'W' => {
                const start = b.nranges;
                const set: []const Range = switch (std.ascii.toLower(c)) {
                    'd' => &.{.{ .lo = '0', .hi = '9' }},
                    's' => &.{ .{ .lo = '\t', .hi = '\n' }, .{ .lo = 0x0c, .hi = '\r' }, .{ .lo = ' ', .hi = ' ' } },
                    else => &word_ranges,
                };
                for (set) |r| try b.addRange(r);
                if (fold) try b.foldFrom(start);
                b.normalizeFrom(start);
                if (std.ascii.isUpper(c)) try b.negateFrom(start);
                return .{ .class = .{ .start = start, .len = b.nranges - start } };
            },
            'p', 'P' => return error.UnsupportedUnicodeClass,
            'A', 'z', 'b', 'B' => {
                if (in_class) return error.InvalidEscape;
                return .{ .assert = switch (c) {
                    'A' => .begin_text,
                    'z' => .end_text,
                    'b' => .word_boundary,
                    else => .not_word_boundary,
                } };
            },
            'Q' => {
                if (in_class) return error.InvalidEscape;
                const end = std.mem.indexOfPos(u8, b.src, b.pos, "\\E") orelse b.src.len;
                const text = b.src[b.pos..end];
                b.pos = @min(end + 2, b.src.len);
                return .{ .quoted = text };
            },
            else => {
                // Any ASCII byte that is not a letter or digit escapes itself
                // (punctuation, space, control characters — as Go).
                if (c < 0x80 and !std.ascii.isAlphanumeric(c)) return .{ .rune = c };
                return error.InvalidEscape;
            },
        }
    }

    fn addRange(b: *Builder, r: Range) Error!void {
        if (b.nranges == max_ranges) return error.PatternTooLarge;
        b.ranges[b.nranges] = r;
        b.nranges += 1;
    }

    /// `[...]`: ranges appended, folded, sorted, merged, negated.
    fn parseClass(b: *Builder, flags: Flags) Error!u16 {
        b.pos += 1; // [
        const start = b.nranges;
        var negated = false;
        if (!b.eof() and b.peek() == '^') {
            negated = true;
            b.pos += 1;
        }
        var first = true;
        while (true) {
            if (b.eof()) return error.MissingBracket;
            const c = b.peek();
            if (c == ']' and !first) {
                b.pos += 1;
                break;
            }
            first = false;
            // Each member is folded on its own, before any negation of its own
            // (`[\W]`, `[[:^alpha:]]`); the class's `^` comes last.
            if (c == '[' and std.mem.startsWith(u8, b.src[b.pos..], "[:")) {
                if (try b.posixClass(flags.fold)) continue;
            }
            const item = b.nranges;
            const lo = try b.classChar(flags.fold) orelse continue; // a \d-style set was added
            // A range `lo-hi`, unless the `-` is last (`[a-]`).
            if (b.pos + 1 < b.src.len and b.peek() == '-' and b.src[b.pos + 1] != ']') {
                b.pos += 1;
                const hi = try b.classChar(flags.fold) orelse return error.InvalidCharRange;
                if (hi < lo) return error.InvalidCharRange;
                try b.addRange(.{ .lo = lo, .hi = hi });
            } else try b.addRange(.{ .lo = lo, .hi = lo });
            if (flags.fold) try b.foldFrom(item);
        }
        b.normalizeFrom(start);
        if (negated) try b.negateFrom(start);
        return b.node(.{ .kind = .class, .a = start, .b = b.nranges - start });
    }

    /// One class member: a code point, or null after appending an escape's set.
    fn classChar(b: *Builder, fold: bool) Error!?u21 {
        if (b.peek() == '\\') {
            return switch (try b.escape(true, fold)) {
                .rune => |cp| cp,
                .class => null,
                else => error.InvalidEscape,
            };
        }
        return b.nextRune();
    }

    /// `[:name:]` / `[:^name:]` at `pos`; false (nothing consumed) when the
    /// text is not one, so `[[:]` stays a literal `[` and `:`.
    fn posixClass(b: *Builder, fold: bool) Error!bool {
        const end = std.mem.indexOfPos(u8, b.src, b.pos + 2, ":]") orelse return false;
        var name = b.src[b.pos + 2 .. end];
        const negated = name.len != 0 and name[0] == '^';
        if (negated) name = name[1..];
        const set: []const Range = posix_classes.get(name) orelse return error.InvalidCharClass;
        b.pos = end + 2;
        const start = b.nranges;
        for (set) |r| try b.addRange(r);
        if (fold) try b.foldFrom(start);
        if (negated) try b.negateFrom(start);
        return true;
    }

    /// Sort and merge `ranges[start..]` in place.
    fn normalizeFrom(b: *Builder, start: u16) void {
        const rs = b.ranges[start..b.nranges];
        std.sort.insertion(Range, rs, {}, struct {
            fn lt(_: void, x: Range, y: Range) bool {
                return x.lo < y.lo;
            }
        }.lt);
        var out: usize = 0;
        for (rs) |r| {
            if (out != 0 and @as(u32, r.lo) <= @as(u32, rs[out - 1].hi) + 1) {
                rs[out - 1].hi = @max(rs[out - 1].hi, r.hi);
            } else {
                rs[out] = r;
                out += 1;
            }
        }
        b.nranges = start + @as(u16, @intCast(out));
    }

    /// Replace `ranges[start..]` by its complement over all code points.
    fn negateFrom(b: *Builder, start: u16) Error!void {
        b.normalizeFrom(start);
        const n = b.nranges - start;
        // Complement into the space after, then move it down.
        const out_start = b.nranges;
        var next: u32 = 0;
        for (b.ranges[start..][0..n]) |r| {
            if (r.lo > next) try b.addRange(.{ .lo = @intCast(next), .hi = r.lo - 1 });
            next = @as(u32, r.hi) + 1;
        }
        if (next <= 0x10ffff) try b.addRange(.{ .lo = @intCast(next), .hi = 0x10ffff });
        const m = b.nranges - out_start;
        std.mem.copyForwards(Range, b.ranges[start..][0..m], b.ranges[out_start..][0..m]);
        b.nranges = start + m;
    }

    /// Add the case variants of `ranges[start..]` (ASCII letters, plus the two
    /// non-ASCII code points that fold to ASCII ones: K ↔ U+212A KELVIN SIGN,
    /// S ↔ U+017F LATIN SMALL LETTER LONG S). Other Unicode case folding is
    /// SPEC Backlog.
    fn foldFrom(b: *Builder, start: u16) Error!void {
        const end = b.nranges;
        var i = start;
        while (i < end) : (i += 1) {
            const r = b.ranges[i];
            // a-z → A-Z, A-Z → a-z
            if (overlap(r, 'a', 'z')) |o| try b.addRange(.{ .lo = o.lo - 32, .hi = o.hi - 32 });
            if (overlap(r, 'A', 'Z')) |o| try b.addRange(.{ .lo = o.lo + 32, .hi = o.hi + 32 });
            if (contains(r, 'k') or contains(r, 'K')) try b.addRange(.{ .lo = 0x212a, .hi = 0x212a });
            if (contains(r, 's') or contains(r, 'S')) try b.addRange(.{ .lo = 0x17f, .hi = 0x17f });
            if (contains(r, 0x212a)) {
                try b.addRange(.{ .lo = 'k', .hi = 'k' });
                try b.addRange(.{ .lo = 'K', .hi = 'K' });
            }
            if (contains(r, 0x17f)) {
                try b.addRange(.{ .lo = 's', .hi = 's' });
                try b.addRange(.{ .lo = 'S', .hi = 'S' });
            }
        }
    }

    // ── compiling ────────────────────────────────────────────────────────

    fn emit(b: *Builder, inst: Inst) Error!void {
        if (b.ninsts == max_insts) return error.PatternTooLarge;
        b.insts[b.ninsts] = inst;
        b.ninsts += 1;
    }

    fn here(b: *const Builder) u16 {
        return b.ninsts;
    }

    fn emitNode(b: *Builder, n: u16) Error!void {
        const nd = b.nodes[n];
        switch (nd.kind) {
            .empty => {},
            .literal => {
                const cp: u21 = @intCast(nd.a);
                const start = b.nranges;
                try b.addRange(.{ .lo = cp, .hi = cp });
                if (nd.flag) {
                    try b.foldFrom(start);
                    b.normalizeFrom(start);
                }
                try b.emit(.{ .rune = .{ .start = start, .len = b.nranges - start } });
            },
            .class => try b.emit(.{ .rune = .{ .start = @intCast(nd.a), .len = @intCast(nd.b) } }),
            .any => try b.emit(.any),
            .any_not_nl => try b.emit(.any_not_nl),
            .assert => try b.emit(.{ .assert = @enumFromInt(nd.a) }),
            .capture => {
                try b.emit(.{ .save = @intCast(nd.a * 2) });
                try b.emitNode(nd.child);
                try b.emit(.{ .save = @intCast(nd.a * 2 + 1) });
            },
            .concat => {
                var c = nd.child;
                while (c != none) : (c = b.nodes[c].next) try b.emitNode(c);
            },
            .alternate => {
                // split L1, next; L1: a; jmp end; next: split L2, next2; ...
                // The pending `jmp end`s are chained through their own target
                // field (no array in this recursive frame).
                var chain: u16 = none;
                var c = nd.child;
                while (c != none) : (c = b.nodes[c].next) {
                    if (b.nodes[c].next == none) {
                        try b.emitNode(c);
                        break;
                    }
                    const split = b.here();
                    try b.emit(.{ .split = .{ .x = split + 1, .y = none } });
                    try b.emitNode(c);
                    const j = b.here();
                    try b.emit(.{ .jmp = chain });
                    chain = j;
                    b.insts[split].split.y = b.here();
                }
                while (chain != none) {
                    const prev = b.insts[chain].jmp;
                    b.insts[chain] = .{ .jmp = b.here() };
                    chain = prev;
                }
            },
            .repeat => try b.emitRepeat(nd),
        }
    }

    /// Whether node `n` can match the empty string.
    fn canBeEmpty(b: *const Builder, n: u16) bool {
        const nd = b.nodes[n];
        return switch (nd.kind) {
            .empty, .assert => true,
            .literal, .class, .any, .any_not_nl => false,
            .capture => b.canBeEmpty(nd.child),
            .repeat => nd.a == 0 or b.canBeEmpty(nd.child),
            .concat => blk: {
                var c = nd.child;
                while (c != none) : (c = b.nodes[c].next) if (!b.canBeEmpty(c)) break :blk false;
                break :blk true;
            },
            .alternate => blk: {
                var c = nd.child;
                while (c != none) : (c = b.nodes[c].next) if (b.canBeEmpty(c)) break :blk true;
                break :blk false;
            },
        };
    }

    fn emitRepeat(b: *Builder, nd: Node) Error!void {
        const min = nd.a;
        const max = nd.b;
        const greedy = nd.flag;
        // The mandatory copies; with an unbounded max the last one loops.
        var i: u32 = 0;
        while (i < min) : (i += 1) {
            if (max == inf and i + 1 == min) {
                const top = b.here();
                try b.emitNode(nd.child);
                const after = b.here() + 1;
                try b.emit(.{ .split = if (greedy) .{ .x = top, .y = after } else .{ .x = after, .y = top } });
                return;
            }
            try b.emitNode(nd.child);
        }
        if (max == inf and b.canBeEmpty(nd.child)) {
            // x* where x can match empty is (x+)?: one empty pass through x
            // counts (its groups take part), as in Go — the plain loop below
            // would drop that pass when it revisits its own split.
            const skip = b.here();
            try b.emit(.{ .split = .{ .x = none, .y = none } });
            const top = b.here();
            try b.emitNode(nd.child);
            const after = b.here() + 1;
            try b.emit(.{ .split = if (greedy) .{ .x = top, .y = after } else .{ .x = after, .y = top } });
            const out = b.here();
            b.insts[skip] = .{ .split = if (greedy) .{ .x = top, .y = out } else .{ .x = out, .y = top } };
            return;
        }
        if (max == inf) {
            // x*: L: split body, out; body; jmp L
            const top = b.here();
            try b.emit(.{ .split = .{ .x = none, .y = none } });
            try b.emitNode(nd.child);
            try b.emit(.{ .jmp = top });
            const out = b.here();
            b.insts[top] = .{ .split = if (greedy) .{ .x = top + 1, .y = out } else .{ .x = out, .y = top + 1 } };
            return;
        }
        // (max - min) optional copies, each skipping to the end: x{2,4} = xx(x(x)?)?
        // The pending splits are chained through their `y` (no array in this
        // recursive frame).
        var chain: u16 = none;
        i = min;
        while (i < max) : (i += 1) {
            const sp = b.here();
            try b.emit(.{ .split = .{ .x = none, .y = chain } });
            chain = sp;
            try b.emitNode(nd.child);
        }
        const out = b.here();
        while (chain != none) {
            const prev = b.insts[chain].split.y;
            b.insts[chain] = .{ .split = if (greedy) .{ .x = chain + 1, .y = out } else .{ .x = out, .y = chain + 1 } };
            chain = prev;
        }
    }
};

fn hexDigit(c: u8) ?u32 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn overlap(r: Range, lo: u21, hi: u21) ?Range {
    const a = @max(r.lo, lo);
    const z = @min(r.hi, hi);
    return if (a <= z) .{ .lo = a, .hi = z } else null;
}

fn contains(r: Range, cp: u21) bool {
    return r.lo <= cp and cp <= r.hi;
}

/// Whether case-insensitive matching changes what `cp` matches.
fn hasFold(cp: u21) bool {
    return std.ascii.isAlphabetic(@truncate(cp)) and cp < 0x80 or cp == 0x212a or cp == 0x17f;
}

const word_ranges = [_]Range{ .{ .lo = '0', .hi = '9' }, .{ .lo = 'A', .hi = 'Z' }, .{ .lo = '_', .hi = '_' }, .{ .lo = 'a', .hi = 'z' } };

const posix_classes = std.StaticStringMap([]const Range).initComptime(.{
    .{ "alnum", &[_]Range{ .{ .lo = '0', .hi = '9' }, .{ .lo = 'A', .hi = 'Z' }, .{ .lo = 'a', .hi = 'z' } } },
    .{ "alpha", &[_]Range{ .{ .lo = 'A', .hi = 'Z' }, .{ .lo = 'a', .hi = 'z' } } },
    .{ "ascii", &[_]Range{.{ .lo = 0, .hi = 0x7f }} },
    .{ "blank", &[_]Range{ .{ .lo = '\t', .hi = '\t' }, .{ .lo = ' ', .hi = ' ' } } },
    .{ "cntrl", &[_]Range{ .{ .lo = 0, .hi = 0x1f }, .{ .lo = 0x7f, .hi = 0x7f } } },
    .{ "digit", &[_]Range{.{ .lo = '0', .hi = '9' }} },
    .{ "graph", &[_]Range{.{ .lo = '!', .hi = '~' }} },
    .{ "lower", &[_]Range{.{ .lo = 'a', .hi = 'z' }} },
    .{ "print", &[_]Range{.{ .lo = ' ', .hi = '~' }} },
    .{ "punct", &[_]Range{ .{ .lo = '!', .hi = '/' }, .{ .lo = ':', .hi = '@' }, .{ .lo = '[', .hi = '`' }, .{ .lo = '{', .hi = '~' } } },
    .{ "space", &[_]Range{ .{ .lo = '\t', .hi = '\r' }, .{ .lo = ' ', .hi = ' ' } } },
    .{ "upper", &[_]Range{.{ .lo = 'A', .hi = 'Z' }} },
    .{ "word", &word_ranges },
    .{ "xdigit", &[_]Range{ .{ .lo = '0', .hi = '9' }, .{ .lo = 'A', .hi = 'F' }, .{ .lo = 'a', .hi = 'f' } } },
});

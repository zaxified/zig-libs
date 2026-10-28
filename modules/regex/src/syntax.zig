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
const casefold = @import("casefold.zig");
const tables = @import("unicode_tables.zig");

/// Where bytes-mode instructions keep a raw byte past ASCII: `byte_base + b`,
/// past every code point (a range is all bytes or all code points).
pub const byte_base: u21 = 0x110000;

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
/// The Rust grammar's bound on a count and on nested counts' product: the
/// crate has none but its compiled size; this keeps the work of compiling an
/// empty body bounded (a body that emits code meets `large_capacity` first).
pub const max_repeat_rust = 100_000;
/// The capacities of the largest builder (on the heap): a program of up to
/// `4 * max_insts` instructions — what every matching entry point still runs
/// in stack scratch, so no compiled pattern can make one fail later; the
/// range and node tables to their `u16` indices.
pub const large_capacity: Capacity = .{ .insts = 4 * max_insts, .ranges = 65535, .nodes = 65535 };
/// `emitNode` calls in one compile: far past any program the builders hold
/// (Go's nested-count rule caps it at ~2M), short of a compile that runs for
/// seconds on empty repeated bodies (~16M steps, tens of milliseconds).
pub const max_emit_work = 1 << 24;
/// Nesting of groups and repetitions. Go goes deeper; 250 keeps the
/// recursive parser and compiler within a 512 KiB thread stack even in a
/// Debug build (a compile of untrusted patterns runs on whatever thread the
/// caller has), and no real pattern nests this far.
pub const max_depth = 250;
/// Repetitions of a repetition (POSIX `a**`, `a{2}{3}`) in one pattern.
pub const max_stacked = 64;

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
    /// `\p{Name}` with a name that is not a Unicode general category, its
    /// alias, a script or `Any`; or a `\p{` with no `}`.
    InvalidUnicodeClass,
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
    // `Syntax.rust` only:
    begin_line_crlf, // ^ with (?mR): after `\n`, or after `\r` not followed by `\n`
    end_line_crlf, // $ with (?mR): before `\r`, or before `\n` not preceded by `\r`
    word_boundary_unicode, // \b (Unicode `\w`)
    not_word_boundary_unicode, // \B (Unicode `\w`)
    word_start, // \b{start}, \< with (?-u)
    word_end, // \b{end}, \> with (?-u)
    word_start_half, // \b{start-half} with (?-u)
    word_end_half, // \b{end-half} with (?-u)
    word_start_unicode, // \b{start}, \<
    word_end_unicode, // \b{end}, \>
    word_start_half_unicode, // \b{start-half}
    word_end_half_unicode, // \b{end-half}
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
    // `Syntax.rust` only:
    crlf: bool = false, // R
    unicode: bool = false, // u (on from the start in the Rust grammar)
    verbose: bool = false, // x
};

/// Which grammar a pattern is read in.
pub const Syntax = enum {
    /// Go's `regexp.Compile` (RE2's Perl-like syntax): everything in the
    /// module doc.
    perl,
    /// Go's `regexp.CompilePOSIX` (POSIX ERE, egrep): no `\d \s \w \b \A \z
    /// \Q \p` and no `(?…)`; `^`/`$` match at line breaks; a negated class
    /// never matches `\n`; a repetition may repeat a repetition (`a**`,
    /// `a{2}{3}`; `a*?` is `(a*)?`, not lazy).
    posix,
    /// Rust's `regex` 1.13 (`regex-syntax` 0.8): flags `i m s R U u x`, with
    /// `u` (Unicode `\d \s \w \b`, Unicode case folding) on by default;
    /// `(?x)` whitespace and `#` comments; class set operations `&& -- ~~`
    /// and nested classes; `\<`, `\>`, `\b{start}`, `\b{end}`,
    /// `\b{start-half}`, `\b{end-half}`; `\u`/`\U` escapes; property queries
    /// `\p{name=value}`. No octal, no `\Q…\E`; `{` always starts a repetition;
    /// group names are Unicode and may not repeat.
    rust,
};

/// Table capacities of a `BuilderOf`. The defaults are the module's
/// documented limits; a smaller builder refuses a larger pattern with
/// `error.PatternTooLarge` (what `Regex.compile` retries with the full one).
pub const Capacity = struct {
    insts: u16 = max_insts,
    ranges: u16 = max_ranges,
    nodes: u16 = max_nodes,
};

/// The builder at the module's documented limits (~80 KiB).
pub const Builder = BuilderOf(.{});

/// Every table of one compilation, at fixed capacity.
pub fn BuilderOf(comptime cap: Capacity) type {
    return struct {
        const Self = @This();

        insts: [cap.insts]Inst = undefined,
        ninsts: u16 = 0,
        ranges: [cap.ranges]Range = undefined,
        nranges: u16 = 0,
        nodes: [cap.nodes]Node = undefined,
        nnodes: u16 = 0,
        /// Group names, `""` for an unnamed group; [0] is the whole match.
        names: [max_groups][]const u8 = undefined,
        ngroups: u16 = 1,

        // ── parser state ──
        src: []const u8 = "",
        pos: usize = 0,
        posix: bool = false,
        rust: bool = false,
        /// Rust grammar on bytes (`regex::bytes`): `(?-u)` may match any byte.
        bytes: bool = false,
        /// Rust grammar: the nesting height of what the last parse function
        /// read, as regex-syntax's `NestLimiter` counts it (groups,
        /// repetitions, classes and their unions and set operations, and
        /// every concatenation or alternation of two or more).
        rheight: u32 = 0,
        /// Repetitions applied to an operand that already was one (POSIX only:
        /// `a**`, `a{2}{3}`) in this pattern. Each adds a level to the tree
        /// without adding group depth, so they are budgeted (`max_stacked`).
        stacked: u16 = 0,
        /// `emitNode` calls of this compile, against `max_emit_work`.
        work: u32 = 0,

        pub fn compile(b: *Self, pattern: []const u8) Error!void {
            return b.compileSyntax(pattern, .perl);
        }

        pub fn compileSyntax(b: *Self, pattern: []const u8, syntax: Syntax) Error!void {
            return b.compileSyntaxBytes(pattern, syntax, false);
        }

        /// `compileSyntax`; `bytes` (Rust grammar only): for a haystack that
        /// need not be UTF-8, where `(?-u)` classes, `.` and `\xNN` match raw
        /// bytes. Such a byte past ASCII is stored as `byte_base + b`.
        pub fn compileSyntaxBytes(b: *Self, pattern: []const u8, syntax: Syntax, bytes: bool) Error!void {
            b.bytes = bytes and syntax == .rust;
            // Reset the counters only: `b.* = .{}` would write all ~80 KiB of
            // tables on every compile (measured: most of a short pattern's cost).
            b.ninsts = 0;
            b.nranges = 0;
            b.nnodes = 0;
            b.ngroups = 1;
            b.pos = 0;
            b.posix = syntax == .posix;
            b.rust = syntax == .rust;
            b.stacked = 0;
            b.work = 0;
            b.names[0] = "";
            if (!std.unicode.utf8ValidateSlice(pattern)) return error.InvalidUtf8;
            b.src = pattern;
            var flags: Flags = .{ .unicode = b.rust };
            const root = try b.parseAlternate(&flags, 0);
            if (b.pos < b.src.len) return error.UnexpectedParen; // a `)` ended it
            if (b.rust and b.rheight > max_depth) return error.NestingDepth;
            // save 0; root; save 1; match
            try b.emit(.{ .save = 0 });
            try b.emitNode(root);
            try b.emit(.{ .save = 1 });
            try b.emit(.match);
            if (b.rust) b.dropVanishedGroups();
        }

        /// Rust drops what `x{0}` holds, groups included: those past the last
        /// group left go, those before it stay as unnamed placeholders that
        /// never take part (regex-automata fills the gaps).
        fn dropVanishedGroups(b: *Self) void {
            var seen: [max_groups]bool = @splat(false);
            for (b.insts[0..b.ninsts]) |inst| {
                if (inst == .save) seen[inst.save / 2] = true;
            }
            var n: u16 = 1;
            for (1..b.ngroups) |g| {
                if (seen[g]) n = @intCast(g + 1) else b.names[g] = "";
            }
            b.ngroups = n;
        }

        // ── parsing ──────────────────────────────────────────────────────────

        fn node(b: *Self, n: Node) Error!u16 {
            if (b.nnodes == cap.nodes) return error.PatternTooLarge;
            b.nodes[b.nnodes] = n;
            b.nnodes += 1;
            return b.nnodes - 1;
        }

        fn eof(b: *const Self) bool {
            return b.pos >= b.src.len;
        }

        fn peek(b: *const Self) u8 {
            return b.src[b.pos];
        }

        /// The next code point of the pattern (validated UTF-8).
        fn nextRune(b: *Self) u21 {
            const len = std.unicode.utf8ByteSequenceLength(b.src[b.pos]) catch unreachable;
            const cp = std.unicode.utf8Decode(b.src[b.pos..][0..len]) catch unreachable;
            b.pos += len;
            return cp;
        }

        /// `a|b|...` up to a `)` or the end. `flags` is the enclosing group's:
        /// a `(?i)` inside one alternative holds for the rest of the group,
        /// later alternatives included.
        fn parseAlternate(b: *Self, flags: *Flags, depth: u32) Error!u16 {
            if (depth > max_depth) return error.NestingDepth;
            const first = if (b.rust) try b.rustConcat(flags, depth) else try b.parseConcat(flags, depth);
            if (b.eof() or b.peek() != '|') return first;
            const alt = try b.node(.{ .kind = .alternate, .child = first });
            var last = first;
            var height = b.rheight;
            while (!b.eof() and b.peek() == '|') {
                b.pos += 1;
                const n = if (b.rust) try b.rustConcat(flags, depth) else try b.parseConcat(flags, depth);
                height = @max(height, b.rheight);
                b.nodes[last].next = n;
                last = n;
            }
            b.rheight = height + 1;
            return alt;
        }

        fn parseConcat(b: *Self, flags: *Flags, depth: u32) Error!u16 {
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
                    if (repeated and !b.posix) return error.InvalidNestedRepeat;
                    if (depth + 1 > max_depth) return error.NestingDepth;
                    if (repeated) {
                        // Only POSIX gets here. A chain `a{1}{1}{1}…` adds no
                        // instructions (nor group depth), yet the recursive
                        // compiler would follow ~2000 levels of it and overflow
                        // a small thread stack.
                        if (b.stacked == max_stacked) return error.NestingDepth;
                        b.stacked += 1;
                    }
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
        fn repeatSize(b: *const Self, n: u16) u64 {
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

        fn append(b: *Self, cat: u16, last: u16, n: u16) u16 {
            if (last == none) b.nodes[cat].child = n else b.nodes[last].next = n;
            return n;
        }

        const Rep = struct { min: u32, max: u32, greedy: bool, counted: bool = false };

        /// A repetition operator at `pos`, consumed; null (nothing consumed) for a
        /// `{` that does not start a valid `{n}`, `{n,}` or `{n,m}`.
        fn parseRepeatOp(b: *Self, flags: Flags) Error!?Rep {
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
            // POSIX has no lazy marker: a `?` after a repetition repeats it.
            if (!b.posix and !b.eof() and b.peek() == '?') {
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

        fn literal(b: *Self, cp: u21, flags: Flags) Error!u16 {
            return b.node(.{ .kind = .literal, .a = cp, .flag = flags.fold and hasFold(cp) });
        }

        /// One operand; null when the "atom" was a bare flag group `(?i)`.
        fn parseAtom(b: *Self, flags: *Flags, depth: u32) Error!?u16 {
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
                    return try b.node(.{ .kind = .assert, .a = @backingInt(if (flags.multi_line or b.posix) Assert.begin_line else Assert.begin_text) });
                },
                '$' => {
                    b.pos += 1;
                    return try b.node(.{ .kind = .assert, .a = @backingInt(if (flags.multi_line or b.posix) Assert.end_line else Assert.end_text) });
                },
                '\\' => return try b.parseEscape(flags.*),
                else => return try b.literal(b.nextRune(), flags.*),
            }
        }

        fn parseGroup(b: *Self, flags: *Flags, depth: u32) Error!?u16 {
            b.pos += 1; // (
            var name: ?[]const u8 = null;
            var inner = flags.*;
            if (b.posix) {
                // No `(?…)`: the `?` is a repetition with nothing before it.
            } else if (std.mem.startsWith(u8, b.src[b.pos..], "?P<") or std.mem.startsWith(u8, b.src[b.pos..], "?<")) {
                b.pos += if (b.src[b.pos + 1] == 'P') 3 else 2;
                const end = std.mem.findScalarPos(u8, b.src, b.pos, '>') orelse return error.InvalidNamedCapture;
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
            /// Rust grammar, bytes mode: `(?-u:\xNN)`, one raw byte.
            byte: u8,
        };

        fn parseEscape(b: *Self, flags: Flags) Error!u16 {
            switch (try b.escape(false, flags.fold)) {
                .rune => |cp| return b.literal(cp, flags),
                .class => |cl| return b.classNode(cl.start),
                .assert => |a| return b.node(.{ .kind = .assert, .a = @backingInt(a) }),
                .byte => unreachable, // the Rust grammar only
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
        fn escape(b: *Self, in_class: bool, fold: bool) Error!Escape {
            b.pos += 1; // backslash
            if (b.eof()) return error.TrailingBackslash;
            const c = b.peek();
            if (c >= 0x80) return error.InvalidEscape;
            // POSIX: none of the Perl and Unicode class escapes, assertions or `\Q`.
            if (b.posix and std.mem.findScalar(u8, "dDsSwWpPAzbBQ", c) != null) return error.InvalidEscape;
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
                        const end = std.mem.findScalarPos(u8, b.src, b.pos, '}') orelse return error.InvalidEscape;
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
                'p', 'P' => {
                    // `\pL` (one letter), `\p{Name}`, `\p{^Name}` (negated).
                    if (b.eof()) return error.InvalidUnicodeClass;
                    var name: []const u8 = undefined;
                    if (b.peek() == '{') {
                        const end = std.mem.findScalarPos(u8, b.src, b.pos, '}') orelse return error.InvalidUnicodeClass;
                        name = b.src[b.pos + 1 .. end];
                        b.pos = end + 1;
                    } else {
                        const s = b.pos;
                        _ = b.nextRune();
                        name = b.src[s..b.pos];
                    }
                    var negated = c == 'P';
                    if (name.len != 0 and name[0] == '^') {
                        negated = !negated;
                        name = name[1..];
                    }
                    const start = b.nranges;
                    try b.addUnicodeClass(name);
                    if (fold) try b.foldFrom(start);
                    b.normalizeFrom(start);
                    if (negated) try b.negateFrom(start);
                    return .{ .class = .{ .start = start, .len = b.nranges - start } };
                },
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
                    const end = std.mem.findPos(u8, b.src, b.pos, "\\E") orelse b.src.len;
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

        /// Append the ranges of the Unicode class `name` (Go grammar), matched
        /// loosely (Unicode TR18: ASCII case ignored, spaces, `_` and `-`
        /// dropped — what Go 1.25+ documents): a name Go lists (`Any`,
        /// `ASCII`, `Assigned`, the general categories and their aliases, the
        /// scripts), with its class from `unicode_tables.zig` (Unicode 17.0).
        fn addUnicodeClass(b: *Self, name: []const u8) Error!void {
            var buf: [max_class_name]u8 = undefined;
            const key = looseName(name, &buf) orelse return error.InvalidUnicodeClass;
            // Rust's tables have no surrogates (a `char` is never one); Go
            // lists them. The same in every Unicode version.
            if (std.mem.eql(u8, key, "cs") or std.mem.eql(u8, key, "surrogate")) return b.addRange(.{ .lo = 0xd800, .hi = 0xdfff });
            const entry = findEntry(key) orelse return error.InvalidUnicodeClass;
            if (!entry.go) return error.InvalidUnicodeClass;
            try b.addBase(entry.base);
        }

        fn addRange(b: *Self, r: Range) Error!void {
            if (b.nranges == cap.ranges) return error.PatternTooLarge;
            b.ranges[b.nranges] = r;
            b.nranges += 1;
        }

        /// `[...]`: ranges appended, folded, sorted, merged, negated.
        fn parseClass(b: *Self, flags: Flags) Error!u16 {
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
                // POSIX: a `-` is a member only first or last (`[a-c-e]`,
                // `[[:alpha:]-z]` are refused); Perl takes it anywhere.
                if (b.posix and c == '-' and !first and !(b.pos + 1 < b.src.len and b.src[b.pos + 1] == ']'))
                    return error.InvalidCharRange;
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
            // POSIX: a negated class never matches a newline (Go without ClassNL).
            if (negated and b.posix) try b.addRange(.{ .lo = '\n', .hi = '\n' });
            b.normalizeFrom(start);
            if (negated) try b.negateFrom(start);
            return b.classNode(start);
        }

        /// A class node for `ranges[start..]`. When an earlier class holds the
        /// same ranges, the node points at those and the copy is dropped —
        /// `\p{L}` is ~700 ranges, and a pattern that names it a few times
        /// would otherwise run out of `max_ranges` where Go compiles it.
        fn classNode(b: *Self, start: u16) Error!u16 {
            const len = b.nranges - start;
            const mine = b.ranges[start..b.nranges];
            for (b.nodes[0..b.nnodes]) |nd| {
                if (nd.kind != .class or nd.b != len or nd.a + nd.b > start) continue;
                if (sameRanges(b.ranges[nd.a..][0..nd.b], mine)) {
                    b.nranges = start;
                    return b.node(.{ .kind = .class, .a = nd.a, .b = len });
                }
            }
            return b.node(.{ .kind = .class, .a = start, .b = len });
        }

        /// One class member: a code point, or null after appending an escape's set.
        fn classChar(b: *Self, fold: bool) Error!?u21 {
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
        fn posixClass(b: *Self, fold: bool) Error!bool {
            const end = std.mem.findPos(u8, b.src, b.pos + 2, ":]") orelse return false;
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
        fn normalizeFrom(b: *Self, start: u16) void {
            const rs = b.ranges[start..b.nranges];
            sortRanges(rs);
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
        fn negateFrom(b: *Self, start: u16) Error!void {
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

        /// Add the case variants of `ranges[start..]`: every code point of each
        /// one's simple case-folding orbit (`casefold.zig`, Unicode's
        /// CaseFolding.txt as Go walks it), so `(?i)é` takes `É` and `(?i)k`
        /// takes U+212A KELVIN SIGN. An orbit has at most `max_orbit` members, so
        /// taking the successors of what was added `max_orbit - 1` times reaches
        /// all of them — run by run, never code point by code point (a class over
        /// all of Unicode costs as much as `[a-z]`, also at comptime).
        fn foldFrom(b: *Self, start: u16) Error!void {
            return b.foldFromWith(casefold, start);
        }

        /// `foldFrom` over the orbits of table `cf`.
        fn foldFromWith(b: *Self, comptime cf: type, start: u16) Error!void {
            var lo = start;
            var hi = b.nranges;
            var step: usize = 1;
            while (step < cf.max_orbit and lo < hi) : (step += 1) {
                const added = b.nranges;
                var i = lo;
                while (i < hi) : (i += 1) try b.addFoldImage(cf, b.ranges[i]);
                b.normalizeFrom(added);
                lo = added;
                hi = b.nranges;
            }
        }

        /// Append the orbit successors of the code points in `r` (for an
        /// alternating run, the whole pairs `r` touches — a superset by `r`
        /// itself, which the class holds anyway).
        fn addFoldImage(b: *Self, comptime cf: type, r: Range) Error!void {
            // Every code point with a fold, and so every successor, is already in `r`.
            if (r.lo <= cf.min_fold and r.hi >= cf.max_fold) return;
            const runs = &cf.runs;
            var i = firstRunIn(cf, r.lo);
            while (i < runs.len and runs[i].lo <= r.hi) : (i += 1) {
                const run = runs[i];
                const a = @max(run.lo, r.lo);
                const z = @min(run.hi, r.hi);
                if (run.alt) {
                    try b.addRange(.{ .lo = a - ((a - run.lo) & 1), .hi = z + (1 - ((z - run.lo) & 1)) });
                } else {
                    try b.addRange(.{ .lo = @intCast(@as(i32, a) + run.delta), .hi = @intCast(@as(i32, z) + run.delta) });
                }
            }
        }

        // ── the Rust grammar (`Syntax.rust`) ─────────────────────────────────
        //
        // regex-syntax 0.8's parser and translator as `regex` 1.13 runs them
        // on a `&str` haystack: `(?-u)` may not make a class that can match a
        // byte past ASCII. The same nodes as the Go grammar come out, so the
        // engines are shared.

        /// With `(?x)`: skip whitespace (Unicode White_Space) and `#` comments.
        fn rustSpace(b: *Self, flags: Flags) void {
            if (!flags.verbose) return;
            while (!b.eof()) {
                if (b.peek() == '#') {
                    while (!b.eof()) {
                        const ch = b.peek();
                        b.pos += 1;
                        if (ch == '\n') break;
                    }
                    continue;
                }
                const save = b.pos;
                if (!isRustSpace(b.nextRune())) {
                    b.pos = save;
                    return;
                }
            }
        }

        /// Past the code point at `pos` and any `(?x)` space after it; false
        /// at the end of the pattern (regex-syntax's `bump_and_bump_space`).
        fn rustBump(b: *Self, flags: Flags) bool {
            _ = b.nextRune();
            b.rustSpace(flags);
            return !b.eof();
        }

        /// The code point after the one at `pos`, `(?x)` space skipped, or
        /// null at the end (`peek_space`). `pos` is unchanged.
        fn rustPeekSpace(b: *Self, flags: Flags) ?u8 {
            const save = b.pos;
            defer b.pos = save;
            _ = b.nextRune();
            b.rustSpace(flags);
            return if (b.eof()) null else b.peek();
        }

        fn rustConcat(b: *Self, flags: *Flags, depth: u32) Error!u16 {
            const cat = try b.node(.{ .kind = .concat });
            var last: u16 = none;
            // The operand a repetition applies to; none after a flag group
            // (`(?i)*` is an error in Rust, `a(?i)*` too).
            var operand: u16 = none;
            var repeated = false;
            // Heights: of the last item (a repetition wraps it), of all.
            var items: u32 = 0;
            var last_h: u32 = 0;
            var max_h: u32 = 0;
            while (true) {
                b.rustSpace(flags.*);
                if (b.eof()) break;
                const c = b.peek();
                if (c == '|' or c == ')') break;
                if (c == '*' or c == '+' or c == '?' or c == '{') {
                    if (operand == none) return error.MissingRepeatArgument;
                    const rep = try b.rustRepeatOp(flags.*);
                    if (depth + 1 > max_depth) return error.NestingDepth;
                    if (repeated) {
                        // Rust repeats a repetition (`a**`); budgeted as POSIX's.
                        if (b.stacked == max_stacked) return error.NestingDepth;
                        b.stacked += 1;
                    }
                    const inner = try b.node(b.nodes[operand]);
                    b.nodes[inner].next = none;
                    b.nodes[operand] = .{ .kind = .repeat, .a = rep.min, .b = rep.max, .flag = rep.greedy, .counted = rep.counted, .child = inner, .next = b.nodes[operand].next };
                    if (rep.counted and b.repeatSize(operand) > max_repeat_rust) return error.InvalidRepeatSize;
                    repeated = true;
                    last_h += 1;
                    max_h = @max(max_h, last_h);
                    continue;
                }
                b.rheight = 0;
                const got = try b.rustAtom(flags, depth);
                items += 1; // a flag group is an item of Rust's concatenation too
                last_h = b.rheight;
                max_h = @max(max_h, last_h);
                const n = got orelse {
                    operand = none;
                    repeated = false;
                    continue;
                };
                repeated = false;
                operand = n;
                last = b.append(cat, last, n);
            }
            b.rheight = max_h + @intFromBool(items >= 2);
            return cat;
        }

        /// `*`, `+`, `?` or `{…}` at `pos`, consumed. A `{` that is not a valid
        /// counted repetition is an error (Rust has no literal `{` there).
        fn rustRepeatOp(b: *Self, flags: Flags) Error!Rep {
            var r: Rep = .{ .min = 0, .max = inf, .greedy = true };
            const c = b.peek();
            if (c != '{') {
                if (c == '+') r.min = 1;
                if (c == '?') r.max = 1;
                b.pos += 1;
                // No space skipped before the lazy marker here (Rust's `bump`).
                if (!b.eof() and b.peek() == '?') {
                    b.pos += 1;
                    r.greedy = false;
                }
            } else {
                r.counted = true;
                if (!b.rustBump(flags)) return error.InvalidRepeatSize;
                const lo = b.rustDecimal(flags);
                if (b.eof()) return error.InvalidRepeatSize;
                var hi: ?u32 = lo;
                if (b.peek() == ',') {
                    if (!b.rustBump(flags)) return error.InvalidRepeatSize;
                    hi = if (b.peek() == '}') null else b.rustDecimal(flags) orelse return error.InvalidRepeatSize;
                }
                const min = lo orelse return error.InvalidRepeatSize;
                if (b.eof() or b.peek() != '}') return error.InvalidRepeatSize;
                b.pos += 1;
                b.rustSpace(flags);
                if (!b.eof() and b.peek() == '?') {
                    b.pos += 1;
                    r.greedy = false;
                }
                if (hi != null and hi.? < min) return error.InvalidRepeatSize;
                if (min > max_repeat_rust or (hi != null and hi.? > max_repeat_rust)) return error.InvalidRepeatSize;
                r.min = min;
                r.max = hi orelse inf;
            }
            if (flags.ungreedy) r.greedy = !r.greedy;
            return r;
        }

        /// Decimal digits with whitespace around them (always, as regex-syntax's
        /// `parse_decimal`; between the digits only with `(?x)`). Null for none;
        /// values saturate past `max_repeat_rust`.
        fn rustDecimal(b: *Self, flags: Flags) ?u32 {
            while (!b.eof() and isRustSpaceAt(b.src, b.pos)) _ = b.nextRune();
            var v: u32 = 0;
            var any = false;
            while (!b.eof() and std.ascii.isDigit(b.peek())) {
                v = @min(v * 10 + (b.peek() - '0'), max_repeat_rust + 1);
                any = true;
                _ = b.rustBump(flags);
            }
            while (!b.eof() and isRustSpaceAt(b.src, b.pos)) _ = b.rustBump(flags);
            return if (any) v else null;
        }

        fn rustAtom(b: *Self, flags: *Flags, depth: u32) Error!?u16 {
            const f = flags.*;
            switch (b.peek()) {
                '(' => return b.rustGroup(flags, depth),
                '[' => {
                    const start = b.nranges;
                    try b.rustClass(f, depth + 1);
                    if (!f.unicode) try b.mapBytes(start);
                    return try b.classNode(start);
                },
                '.' => {
                    b.pos += 1;
                    if (!f.unicode) {
                        // Any byte: not on `&str`.
                        if (!b.bytes) return error.InvalidUtf8;
                        const start = b.nranges;
                        if (f.dot_nl) {
                            try b.addRange(.{ .lo = 0, .hi = 0xff });
                        } else {
                            try b.addRange(.{ .lo = '\n', .hi = '\n' });
                            if (f.crlf) try b.addRange(.{ .lo = '\r', .hi = '\r' });
                            try b.negateBytesFrom(start);
                        }
                        try b.mapBytes(start);
                        return try b.classNode(start);
                    }
                    if (f.dot_nl) return try b.node(.{ .kind = .any });
                    if (!f.crlf) return try b.node(.{ .kind = .any_not_nl });
                    const start = b.nranges;
                    try b.addRange(.{ .lo = 0, .hi = '\n' - 1 });
                    try b.addRange(.{ .lo = '\n' + 1, .hi = '\r' - 1 });
                    try b.addRange(.{ .lo = '\r' + 1, .hi = 0x10ffff });
                    return try b.classNode(start);
                },
                '^' => {
                    b.pos += 1;
                    const a: Assert = if (!f.multi_line) .begin_text else if (f.crlf) .begin_line_crlf else .begin_line;
                    return try b.node(.{ .kind = .assert, .a = @backingInt(a) });
                },
                '$' => {
                    b.pos += 1;
                    const a: Assert = if (!f.multi_line) .end_text else if (f.crlf) .end_line_crlf else .end_line;
                    return try b.node(.{ .kind = .assert, .a = @backingInt(a) });
                },
                '\\' => switch (try b.rustEscape(f, false)) {
                    .rune => |cp| return try b.rustLiteral(cp, f),
                    .byte => |c| return try b.rustLiteral(if (c < 0x80) c else byte_base + @as(u21, c), f),
                    .class => |cl| {
                        if (!f.unicode) try b.mapBytes(cl.start);
                        return try b.classNode(cl.start);
                    },
                    .assert => |a| return try b.node(.{ .kind = .assert, .a = @backingInt(a) }),
                    .quoted => unreachable,
                },
                else => return try b.rustLiteral(b.nextRune(), f),
            }
        }

        /// A literal; with `(?i)` its simple case-folding orbit, or with
        /// `(?-u)` only the other case of an ASCII letter.
        fn rustLiteral(b: *Self, cp: u21, flags: Flags) Error!u16 {
            if (!flags.fold) return b.literal(cp, flags);
            if (flags.unicode) return b.literal(cp, flags);
            if (cp >= 0x80 or !std.ascii.isAlphabetic(@intCast(cp))) return b.literal(cp, .{});
            const start = b.nranges;
            const c: u8 = @intCast(cp);
            try b.addRange(.{ .lo = std.ascii.toUpper(c), .hi = std.ascii.toUpper(c) });
            try b.addRange(.{ .lo = std.ascii.toLower(c), .hi = std.ascii.toLower(c) });
            return b.classNode(start);
        }

        fn rustGroup(b: *Self, flags: *Flags, depth: u32) Error!?u16 {
            b.pos += 1; // (
            b.rustSpace(flags.*);
            const rest = b.src[b.pos..];
            for ([_][]const u8{ "?=", "?!", "?<=", "?<!" }) |p| {
                if (std.mem.startsWith(u8, rest, p)) return error.InvalidPerlOp;
            }
            var inner = flags.*;
            var name: ?[]const u8 = null;
            if (std.mem.startsWith(u8, rest, "?P<") or std.mem.startsWith(u8, rest, "?<")) {
                b.pos += if (rest[1] == 'P') 3 else 2;
                name = try b.rustCaptureName();
            } else if (std.mem.startsWith(u8, rest, "?")) {
                b.pos += 1;
                if (b.eof()) return error.MissingParen;
                const any = try b.rustFlags(&inner);
                const end = b.peek();
                b.pos += 1;
                if (end == ')') {
                    // `(?)`: Rust reads it as a repetition with no operand.
                    if (!any) return error.MissingRepeatArgument;
                    flags.* = inner;
                    return null;
                }
                const body = try b.parseAlternate(&inner, depth + 1);
                if (b.eof() or b.peek() != ')') return error.MissingParen;
                b.pos += 1;
                b.rheight += 1;
                return body;
            }
            if (b.ngroups == max_groups) return error.PatternTooLarge;
            const index = b.ngroups;
            b.names[index] = name orelse "";
            b.ngroups += 1;
            const body = try b.parseAlternate(&inner, depth + 1);
            if (b.eof() or b.peek() != ')') return error.MissingParen;
            b.pos += 1;
            b.rheight += 1;
            return try b.node(.{ .kind = .capture, .a = index, .child = body });
        }

        /// A group name up to `>`, consumed with it: an `_` or Alphabetic code
        /// point first, then `_ . [ ]` or alphanumeric ones; unique.
        fn rustCaptureName(b: *Self) Error![]const u8 {
            const start = b.pos;
            while (true) {
                if (b.eof()) return error.InvalidNamedCapture;
                if (b.peek() == '>') break;
                const first = b.pos == start;
                const cp = b.nextRune();
                const ok = cp == '_' or isRustAlphabetic(cp) or
                    (!first and (cp == '.' or cp == '[' or cp == ']' or isRustNumeric(cp)));
                if (!ok) return error.InvalidNamedCapture;
            }
            const n = b.src[start..b.pos];
            b.pos += 1; // >
            if (n.len == 0) return error.InvalidNamedCapture;
            for (b.names[1..b.ngroups]) |prev| {
                if (std.mem.eql(u8, prev, n)) return error.InvalidNamedCapture;
            }
            return n;
        }

        /// Flags up to `:` or `)` (left at `pos`) into `inner`; whether any
        /// flag was named. A flag named twice, a second `-` or a trailing `-`
        /// is an error.
        fn rustFlags(b: *Self, inner: *Flags) Error!bool {
            var seen: u8 = 0;
            var negate = false;
            var last_negation = false;
            var any = false;
            while (b.peek() != ':' and b.peek() != ')') {
                const c = b.peek();
                if (c == '-') {
                    if (negate) return error.InvalidPerlOp;
                    negate = true;
                    last_negation = true;
                } else {
                    last_negation = false;
                    const bit: u8 = switch (c) {
                        'i' => 1,
                        'm' => 2,
                        's' => 4,
                        'U' => 8,
                        'u' => 16,
                        'R' => 32,
                        'x' => 64,
                        else => return error.InvalidPerlOp,
                    };
                    if (seen & bit != 0) return error.InvalidPerlOp;
                    seen |= bit;
                    any = true;
                    const v = !negate;
                    switch (c) {
                        'i' => inner.fold = v,
                        'm' => inner.multi_line = v,
                        's' => inner.dot_nl = v,
                        'U' => inner.ungreedy = v,
                        'u' => inner.unicode = v,
                        'R' => inner.crlf = v,
                        else => inner.verbose = v,
                    }
                }
                b.pos += 1;
                if (b.eof()) return error.MissingParen;
            }
            if (last_negation) return error.InvalidPerlOp;
            return any or negate;
        }

        /// One escape after `\` (at `pos`), as regex-syntax's `parse_escape`
        /// and its translation. `in_class`: inside `[...]`, where an
        /// assertion is an error.
        fn rustEscape(b: *Self, flags: Flags, in_class: bool) Error!Escape {
            b.pos += 1; // backslash
            if (b.eof()) return error.TrailingBackslash;
            const c = b.peek();
            switch (c) {
                // Octal is off in `regex`; a digit would be a backreference.
                '0'...'9' => return error.InvalidEscape,
                'x', 'u', 'U' => {
                    const h = try b.rustHex(flags);
                    // `(?-u:\xFF)` is the byte 0xFF: not on `&str`.
                    if (!flags.unicode and h.byte and h.cp > 0x7f) {
                        if (!b.bytes) return error.InvalidUtf8;
                        return .{ .byte = @intCast(h.cp) };
                    }
                    return .{ .rune = h.cp };
                },
                'p', 'P' => return b.rustUnicodeEscape(flags),
                'd', 's', 'w', 'D', 'S', 'W' => {
                    b.pos += 1;
                    return b.rustPerl(c, flags);
                },
                else => {},
            }
            if (c >= 0x80) return error.InvalidEscape;
            b.pos += 1;
            switch (c) {
                'a' => return .{ .rune = 0x07 },
                'f' => return .{ .rune = 0x0c },
                't' => return .{ .rune = '\t' },
                'n' => return .{ .rune = '\n' },
                'r' => return .{ .rune = '\r' },
                'v' => return .{ .rune = 0x0b },
                'A', 'z', 'B', '<', '>' => {
                    if (in_class) return error.InvalidEscape;
                    const u = flags.unicode;
                    return .{ .assert = switch (c) {
                        'A' => .begin_text,
                        'z' => .end_text,
                        'B' => if (u) .not_word_boundary_unicode else .not_word_boundary,
                        '<' => if (u) .word_start_unicode else .word_start,
                        else => if (u) .word_end_unicode else .word_end,
                    } };
                },
                'b' => {
                    if (in_class) return error.InvalidEscape;
                    return .{ .assert = try b.rustWordBoundary(flags) };
                },
                else => {
                    // Any other ASCII byte that is not a letter or digit
                    // escapes itself (`<` and `>` are assertions above).
                    if (!std.ascii.isAlphanumeric(c)) return .{ .rune = c };
                    return error.InvalidEscape;
                },
            }
        }

        /// After `\b`: `{start}`, `{end}`, `{start-half}`, `{end-half}`, or a
        /// plain boundary (a `{` that is not one of those is left for a
        /// counted repetition of `\b`).
        fn rustWordBoundary(b: *Self, flags: Flags) Error!Assert {
            const u = flags.unicode;
            const plain: Assert = if (u) .word_boundary_unicode else .word_boundary;
            if (b.eof() or b.peek() != '{') return plain;
            const start = b.pos;
            if (!b.rustBump(flags)) return error.InvalidEscape;
            if (!isWordBoundaryNameChar(b.peek())) {
                b.pos = start;
                return plain;
            }
            var buf: [16]u8 = undefined;
            var n: usize = 0;
            while (!b.eof() and isWordBoundaryNameChar(b.peek())) {
                if (n < buf.len) buf[n] = b.peek();
                n += 1;
                _ = b.rustBump(flags);
            }
            if (b.eof() or b.peek() != '}') return error.InvalidEscape;
            b.pos += 1;
            const name = buf[0..@min(n, buf.len)];
            if (n > buf.len) return error.InvalidEscape;
            if (std.mem.eql(u8, name, "start")) return if (u) .word_start_unicode else .word_start;
            if (std.mem.eql(u8, name, "end")) return if (u) .word_end_unicode else .word_end;
            if (std.mem.eql(u8, name, "start-half")) return if (u) .word_start_half_unicode else .word_start_half;
            if (std.mem.eql(u8, name, "end-half")) return if (u) .word_end_half_unicode else .word_end_half;
            return error.InvalidEscape;
        }

        /// `\x`, `\u`, `\U` at `pos` (the letter): two, four or eight hex
        /// digits, or any number in braces; `(?x)` space allowed between them.
        /// `byte`: the two-digit `\xNN` form, which `(?-u)` reads as a byte.
        fn rustHex(b: *Self, flags: Flags) Error!struct { cp: u21, byte: bool } {
            const kind = b.peek();
            if (!b.rustBump(flags)) return error.InvalidEscape;
            var v: u32 = 0;
            const braced = b.peek() == '{';
            if (braced) {
                var any = false;
                while (b.rustBump(flags) and b.peek() != '}') {
                    const d = hexDigit(b.peek()) orelse return error.InvalidEscape;
                    v = @min(v * 16 + d, 0x110000);
                    any = true;
                }
                if (b.eof()) return error.InvalidEscape;
                b.pos += 1; // }
                b.rustSpace(flags);
                if (!any) return error.InvalidEscape;
            } else {
                const digits: usize = switch (kind) {
                    'x' => 2,
                    'u' => 4,
                    else => 8,
                };
                for (0..digits) |i| {
                    if (i > 0 and !b.rustBump(flags)) return error.InvalidEscape;
                    const d = hexDigit(b.peek()) orelse return error.InvalidEscape;
                    v = @min(v * 16 + d, 0x110000);
                }
                _ = b.rustBump(flags);
            }
            // A Rust `char`: no surrogates, nothing past U+10FFFF.
            if (v > 0x10ffff or (v >= 0xd800 and v <= 0xdfff)) return error.InvalidEscape;
            return .{ .cp = @intCast(v), .byte = kind == 'x' and !braced };
        }

        /// `\d \s \w` and their negations (letter consumed): Unicode with
        /// `u`, else ASCII — whose negation could match a byte past ASCII,
        /// an error on `&str`. Not case-folded on their own (Rust).
        fn rustPerl(b: *Self, c: u8, flags: Flags) Error!Escape {
            const negated = std.ascii.isUpper(c);
            const start = b.nranges;
            if (flags.unicode) {
                switch (std.ascii.toLower(c)) {
                    'd' => try b.addBase(tables.perl_digit),
                    's' => try b.addBase(tables.perl_space),
                    else => try b.addBase(tables.perl_word),
                }
            } else {
                if (negated and !b.bytes) return error.InvalidUtf8;
                const set: []const Range = switch (std.ascii.toLower(c)) {
                    'd' => &.{.{ .lo = '0', .hi = '9' }},
                    's' => &.{ .{ .lo = '\t', .hi = '\r' }, .{ .lo = ' ', .hi = ' ' } },
                    else => &word_ranges,
                };
                for (set) |r| try b.addRange(r);
                // Over bytes (bytes mode): the caller maps past ASCII.
                b.normalizeFrom(start);
                if (negated) try b.negateBytesFrom(start);
                return .{ .class = .{ .start = start, .len = b.nranges - start } };
            }
            b.normalizeFrom(start);
            if (negated) try b.negateFrom(start);
            return .{ .class = .{ .start = start, .len = b.nranges - start } };
        }

        /// `\p…`/`\P…` at `pos` (the letter): one letter, or a query in braces
        /// (`Name`, `name=value`, `name:value`, `name!=value`). Case-folded
        /// with `(?i)`, then negated. Refused under `(?-u)`.
        fn rustUnicodeEscape(b: *Self, flags: Flags) Error!Escape {
            var negated = b.peek() == 'P';
            if (!b.rustBump(flags)) return error.InvalidUnicodeClass;
            var buf: [max_class_name]u8 = undefined;
            var n: usize = 0;
            if (b.peek() == '{') {
                while (b.rustBump(flags) and b.peek() != '}') {
                    const s = b.pos;
                    _ = b.nextRune();
                    const ch = b.src[s..b.pos];
                    if (n + ch.len > buf.len) return error.InvalidUnicodeClass;
                    @memcpy(buf[n..][0..ch.len], ch);
                    n += ch.len;
                    b.pos = s;
                }
                if (b.eof()) return error.InvalidUnicodeClass;
                b.pos += 1; // }
            } else {
                if (b.peek() == '\\') return error.InvalidUnicodeClass;
                const s = b.pos;
                _ = b.rustBump(flags);
                // The one letter only (spaces after it were skipped).
                const len = std.unicode.utf8ByteSequenceLength(b.src[s]) catch unreachable;
                @memcpy(buf[0..len], b.src[s..][0..len]);
                n = len;
            }
            if (!flags.unicode) return error.InvalidUnicodeClass;
            const query = buf[0..n];
            const start = b.nranges;
            if (std.mem.find(u8, query, "!=")) |i| {
                negated = !negated;
                try b.addRustProperty(query[0..i], query[i + 2 ..]);
            } else if (std.mem.findScalar(u8, query, ':')) |i| {
                try b.addRustProperty(query[0..i], query[i + 1 ..]);
            } else if (std.mem.findScalar(u8, query, '=')) |i| {
                try b.addRustProperty(query[0..i], query[i + 1 ..]);
            } else {
                var key: [max_class_name]u8 = undefined;
                try b.addBase(findName(rustNormalize(query, &key)) orelse return error.InvalidUnicodeClass);
            }
            if (flags.fold) try b.foldFromWith(casefold, start);
            b.normalizeFrom(start);
            if (negated) try b.negateFrom(start);
            return .{ .class = .{ .start = start, .len = b.nranges - start } };
        }

        /// `name=value`: a property of `tables.props` (general category,
        /// script, script extensions, age, the break properties) and one of
        /// its values, both normalized as regex-syntax does.
        fn addRustProperty(b: *Self, name: []const u8, value: []const u8) Error!void {
            var nbuf: [max_class_name]u8 = undefined;
            const prop = rustNormalize(name, &nbuf);
            const id = for (tables.props) |p| {
                if (std.mem.eql(u8, p.name, prop)) break p.id;
            } else return error.InvalidUnicodeClass;
            var vbuf: [max_class_name]u8 = undefined;
            const v = rustNormalize(value, &vbuf);
            var kbuf: [2 * max_class_name]u8 = undefined;
            if (id.len + 1 + v.len > kbuf.len) return error.InvalidUnicodeClass;
            @memcpy(kbuf[0..id.len], id);
            kbuf[id.len] = '=';
            @memcpy(kbuf[id.len + 1 ..][0..v.len], v);
            const key = kbuf[0 .. id.len + 1 + v.len];
            try b.addBase(findName(key) orelse return error.InvalidUnicodeClass);
        }

        /// Append the ranges of `tables.bases[base]`.
        fn addBase(b: *Self, base: u16) Error!void {
            var it: TableRanges = .init(base);
            while (it.next()) |r| try b.addRange(r);
        }

        /// `[...]` at `pos`: its ranges appended at the old `nranges`, sorted
        /// and merged. Rust's order: union binds tighter than `&& -- ~~`
        /// (left to right, each side case-folded first), then the whole
        /// class is folded, then negated.
        fn rustClass(b: *Self, flags: Flags, depth: u32) Error!void {
            if (depth > max_depth) return error.NestingDepth;
            const start = b.nranges;
            if (!b.rustBump(flags)) return error.MissingBracket;
            var negated = false;
            if (b.peek() == '^') {
                negated = true;
                if (!b.rustBump(flags)) return error.MissingBracket;
            }
            // Leading `-`s are members; so is a first `]` (not after a `-`).
            // Heights (`rheight`): the union being read has `items` members,
            // the tallest `union_h`; `lhs_h` is the set-operation chain's.
            var items: u32 = 0;
            var union_h: u32 = 0;
            var lhs_h: u32 = 0;
            var dashes = false;
            while (b.peek() == '-') {
                try b.addRange(.{ .lo = '-', .hi = '-' });
                dashes = true;
                items += 1;
                if (!b.rustBump(flags)) return error.MissingBracket;
            }
            if (!dashes and b.peek() == ']') {
                try b.addRange(.{ .lo = ']', .hi = ']' });
                items += 1;
                if (!b.rustBump(flags)) return error.MissingBracket;
            }
            // ranges[start..operand] is the result so far, ranges[operand..]
            // the union being read; `op` is the operator between them.
            var operand = start;
            var op: u8 = 0;
            while (true) {
                b.rustSpace(flags);
                if (b.eof()) return error.MissingBracket;
                const c = b.peek();
                if (c == ']') {
                    b.pos += 1;
                    break;
                }
                if ((c == '&' or c == '-' or c == '~') and b.pos + 1 < b.src.len and b.src[b.pos + 1] == c) {
                    b.pos += 2;
                    try b.rustClassOp(flags, start, &operand, op);
                    const u = union_h + @intFromBool(items >= 2);
                    lhs_h = if (op == 0) u else 1 + @max(lhs_h, u);
                    items = 0;
                    union_h = 0;
                    op = c;
                    continue;
                }
                b.rheight = 0;
                try b.rustClassItem(flags, depth);
                items += 1;
                union_h = @max(union_h, b.rheight);
            }
            try b.rustClassOp(flags, start, &operand, op);
            const u = union_h + @intFromBool(items >= 2);
            b.rheight = 1 + if (op == 0) u else 1 + @max(lhs_h, u);
            if (flags.fold) try b.rustFold(flags, start);
            b.normalizeFrom(start);
            if (negated) {
                if (flags.unicode) return b.negateFrom(start);
                // Over bytes, a negation reaches past ASCII: not on `&str`.
                if (!b.bytes) return error.InvalidUtf8;
                try b.negateBytesFrom(start);
            }
        }

        /// Close the operand at `operand.*`: with no operator it joins the
        /// result; else result `op` operand replaces both.
        fn rustClassOp(b: *Self, flags: Flags, start: u16, operand: *u16, op: u8) Error!void {
            if (op == 0) {
                b.normalizeFrom(start);
                operand.* = b.nranges;
                return;
            }
            if (flags.fold) {
                try b.rustFold(flags, operand.*);
                // Folding the result appends after the operand: fold a copy
                // of the result past both, then make it the result again.
                const lhs_len = operand.* - start;
                const rhs_start = operand.*;
                const rhs_len = b.nranges - rhs_start;
                const copy = b.nranges;
                for (0..lhs_len) |i| try b.addRange(b.ranges[start + i]);
                try b.rustFold(flags, copy);
                const folded_len = b.nranges - copy;
                // Layout now: lhs | rhs | folded lhs. Rebuild lhs' | rhs, lhs'
                // sorted and merged again: the fold appended its orbits after
                // it (`[a-c]` → `a-c A-C`), and `appendSetOp` sweeps both
                // sides in order (fuzz 2026-10-28: `(?i)[a-c~~b-d]` lost
                // `A-C` and came out as the union).
                const tmp = b.nranges;
                for (0..rhs_len) |i| try b.addRange(b.ranges[rhs_start + i]);
                std.mem.copyForwards(Range, b.ranges[start..][0..folded_len], b.ranges[copy..][0..folded_len]);
                b.nranges = start + folded_len;
                b.normalizeFrom(start);
                const lhs_end = b.nranges;
                std.mem.copyForwards(Range, b.ranges[lhs_end..][0..rhs_len], b.ranges[tmp..][0..rhs_len]);
                b.nranges = lhs_end + rhs_len;
                operand.* = lhs_end;
            }
            b.normalizeFrom(operand.*);
            const lhs = b.ranges[start..operand.*];
            const rhs = b.ranges[operand.*..b.nranges];
            const out = b.nranges;
            try b.appendSetOp(lhs, rhs, op);
            const m = b.nranges - out;
            std.mem.copyForwards(Range, b.ranges[start..][0..m], b.ranges[out..][0..m]);
            b.nranges = start + m;
            b.normalizeFrom(start);
            operand.* = b.nranges;
        }

        /// Append `x op y` (`&` intersection, `-` difference, `~` symmetric
        /// difference) of two sorted, merged range lists.
        fn appendSetOp(b: *Self, x: []const Range, y: []const Range, op: u8) Error!void {
            var i: usize = 0;
            var j: usize = 0;
            var p: u32 = 0;
            while (p <= 0x10ffff) {
                while (i < x.len and x[i].hi < p) i += 1;
                while (j < y.len and y[j].hi < p) j += 1;
                const in_x = i < x.len and x[i].lo <= p;
                const in_y = j < y.len and y[j].lo <= p;
                var end: u32 = 0x10ffff;
                if (i < x.len) end = @min(end, if (in_x) @as(u32, x[i].hi) else @as(u32, x[i].lo) - 1);
                if (j < y.len) end = @min(end, if (in_y) @as(u32, y[j].hi) else @as(u32, y[j].lo) - 1);
                const keep = switch (op) {
                    '&' => in_x and in_y,
                    '-' => in_x and !in_y,
                    else => in_x != in_y,
                };
                if (keep) try b.addRange(.{ .lo = @intCast(p), .hi = @intCast(end) });
                p = end + 1;
            }
        }

        /// Case-fold `ranges[start..]`: Unicode orbits, or with `(?-u)` the
        /// ASCII letters' other case.
        fn rustFold(b: *Self, flags: Flags, start: u16) Error!void {
            if (flags.unicode) return b.foldFromWith(casefold, start);
            const end = b.nranges;
            for (start..end) |i| {
                const r = b.ranges[i];
                const pairs = [_][2]u21{ .{ 'a', 'A' }, .{ 'A', 'a' } };
                for (pairs) |p| {
                    const lo = @max(r.lo, p[0]);
                    const hi = @min(r.hi, p[0] + 25);
                    if (lo <= hi) try b.addRange(.{ .lo = lo - p[0] + p[1], .hi = hi - p[0] + p[1] });
                }
            }
        }

        /// One class member: a nested class, `[:name:]`, an escape, or a
        /// code point — and with `-` after it a range.
        fn rustClassItem(b: *Self, flags: Flags, depth: u32) Error!void {
            if (b.peek() == '[') {
                if (try b.rustAsciiClass(flags)) return;
                return b.rustClass(flags, depth + 1);
            }
            const lo = try b.rustClassPrim(flags);
            b.rustSpace(flags);
            if (b.eof()) return error.MissingBracket;
            const range = b.peek() == '-' and blk: {
                const nx = b.rustPeekSpace(flags);
                break :blk nx != ']' and nx != '-';
            };
            if (!range) {
                if (lo) |cp| try b.addRange(.{ .lo = cp, .hi = cp });
                return;
            }
            // A set (`\d`) cannot start a range.
            const first = lo orelse return error.InvalidCharRange;
            if (!b.rustBump(flags)) return error.MissingBracket;
            const hi = try b.rustClassPrim(flags) orelse return error.InvalidCharRange;
            if (hi < first) return error.InvalidCharRange;
            try b.addRange(.{ .lo = first, .hi = hi });
        }

        /// A code point (null after appending an escape's set). Under `(?-u)`
        /// only ASCII: a class member is a byte there.
        fn rustClassPrim(b: *Self, flags: Flags) Error!?u21 {
            const cp: u21 = if (b.peek() == '\\') switch (try b.rustEscape(flags, true)) {
                .rune => |r| r,
                .byte => |c| return c, // a byte class member (bytes mode)
                .class => return null,
                else => return error.InvalidEscape,
            } else b.nextRune();
            if (!flags.unicode and cp > 0x7f) return error.InvalidUtf8;
            return cp;
        }

        /// `[:name:]` / `[:^name:]` at `pos` inside a class; false (nothing
        /// consumed) when it is not one — then `[` opens a nested class.
        fn rustAsciiClass(b: *Self, flags: Flags) Error!bool {
            if (!std.mem.startsWith(u8, b.src[b.pos..], "[:")) return false;
            const end = std.mem.findPos(u8, b.src, b.pos + 2, ":") orelse return false;
            if (!std.mem.startsWith(u8, b.src[end..], ":]")) return false;
            var name = b.src[b.pos + 2 .. end];
            const negated = name.len != 0 and name[0] == '^';
            if (negated) name = name[1..];
            const set: []const Range = posix_classes.get(name) orelse return false;
            b.pos = end + 2;
            const start = b.nranges;
            for (set) |r| try b.addRange(r);
            // Folded before it is negated (`(?i)[[:^upper:]]` takes no letter).
            if (flags.fold) try b.rustFold(flags, start);
            if (negated) {
                if (flags.unicode) {
                    try b.negateFrom(start);
                } else {
                    if (!b.bytes) return error.InvalidUtf8;
                    try b.negateBytesFrom(start);
                }
            }
            return true;
        }

        /// Complement `ranges[start..]` over the bytes 0..255 (a `(?-u)`
        /// class in bytes mode, before `mapBytes`).
        fn negateBytesFrom(b: *Self, start: u16) Error!void {
            b.normalizeFrom(start);
            try b.negateFrom(start);
            // Cut the complement at 0xff.
            var out = start;
            for (start..b.nranges) |i| {
                const r = b.ranges[i];
                if (r.lo > 0xff) continue;
                b.ranges[out] = .{ .lo = r.lo, .hi = @min(r.hi, 0xff) };
                out += 1;
            }
            b.nranges = out;
        }

        /// A byte class's ranges (0..255) as instruction ranges: ASCII as is,
        /// the bytes past it at `byte_base + b` — never a code point.
        fn mapBytes(b: *Self, start: u16) Error!void {
            var i = start;
            const end = b.nranges;
            while (i < end) : (i += 1) {
                const r = b.ranges[i];
                if (r.lo >= 0x80) {
                    b.ranges[i] = .{ .lo = byte_base + r.lo, .hi = byte_base + r.hi };
                } else if (r.hi >= 0x80) {
                    b.ranges[i].hi = 0x7f;
                    // Split; `normalizeFrom` sorts the new part in.
                    try b.addRange(.{ .lo = byte_base + 0x80, .hi = byte_base + r.hi });
                }
            }
            b.normalizeFrom(start);
        }

        // ── compiling ────────────────────────────────────────────────────────

        fn emit(b: *Self, inst: Inst) Error!void {
            if (b.ninsts == cap.insts) return error.PatternTooLarge;
            b.insts[b.ninsts] = inst;
            b.ninsts += 1;
        }

        fn here(b: *const Self) u16 {
            return b.ninsts;
        }

        fn emitNode(b: *Self, n: u16) Error!void {
            // Copies of a body that emits nothing (`(?:(?:)(?:)…){100000}`)
            // meet no instruction capacity: the walk itself is budgeted, so a
            // compile's time is bounded whatever the pattern (audit
            // 2026-10-28).
            b.work += 1;
            if (b.work > max_emit_work) return error.PatternTooLarge;
            const nd = b.nodes[n];
            switch (nd.kind) {
                .empty => {},
                .literal => {
                    const cp: u21 = @intCast(nd.a);
                    const start = b.nranges;
                    try b.addRange(.{ .lo = cp, .hi = cp });
                    if (nd.flag) {
                        // The orbit, successor by successor (a literal is one
                        // code point: no ranges to fold).
                        var c = foldNext(cp);
                        while (c != cp) : (c = foldNext(c)) try b.addRange(.{ .lo = c, .hi = c });
                        b.normalizeFrom(start);
                    }
                    try b.emit(.{ .rune = .{ .start = start, .len = b.nranges - start } });
                },
                .class => try b.emit(.{ .rune = .{ .start = @intCast(nd.a), .len = @intCast(nd.b) } }),
                .any => try b.emit(.any),
                .any_not_nl => try b.emit(.any_not_nl),
                .assert => try b.emit(.{ .assert = @fromBackingInt(@intCast(nd.a)) }),
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
        fn canBeEmpty(b: *const Self, n: u16) bool {
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

        fn emitRepeat(b: *Self, nd: Node) Error!void {
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
}

/// Unicode White_Space (Rust's `char::is_whitespace`, the `(?x)` space and
/// the Unicode `\s`); unchanged since Unicode 6.
const rust_white_space = [_]Range{
    .{ .lo = '\t', .hi = '\r' },     .{ .lo = ' ', .hi = ' ' },
    .{ .lo = 0x85, .hi = 0x85 },     .{ .lo = 0xa0, .hi = 0xa0 },
    .{ .lo = 0x1680, .hi = 0x1680 }, .{ .lo = 0x2000, .hi = 0x200a },
    .{ .lo = 0x2028, .hi = 0x2029 }, .{ .lo = 0x202f, .hi = 0x202f },
    .{ .lo = 0x205f, .hi = 0x205f }, .{ .lo = 0x3000, .hi = 0x3000 },
};

fn isRustSpace(cp: u21) bool {
    for (rust_white_space) |r| if (cp >= r.lo and cp <= r.hi) return true;
    return false;
}

/// Whether the code point at `s[i]` (valid UTF-8) is White_Space.
fn isRustSpaceAt(s: []const u8, i: usize) bool {
    const len = std.unicode.utf8ByteSequenceLength(s[i]) catch unreachable;
    return isRustSpace(std.unicode.utf8Decode(s[i..][0..len]) catch unreachable);
}

/// Rust's `char::is_alphabetic` (the Alphabetic property; Rust's own
/// Unicode version may differ from the tables' 17.0 — not seen in names).
fn isRustAlphabetic(cp: u21) bool {
    if (cp < 0x80) return std.ascii.isAlphabetic(@intCast(cp));
    return inTable(comptime findName("alphabetic").?, cp);
}

/// Rust's `char::is_numeric` (general category N).
fn isRustNumeric(cp: u21) bool {
    if (cp < 0x80) return std.ascii.isDigit(@intCast(cp));
    return inTable(comptime findName("n").?, cp);
}

/// The ranges of one `tables` table, decoded from its varints.
const TableRanges = struct {
    bytes: []const u8,
    left: u16,
    i: usize = 0,
    next_lo: u32 = 0,

    fn init(base: u16) TableRanges {
        const t = tables.bases[base];
        return .{ .bytes = tables.data[t.offset..][0..t.size], .left = t.count };
    }

    fn next(it: *TableRanges) ?Range {
        if (it.left == 0) return null;
        it.left -= 1;
        const lo = it.next_lo + readVarint(it.bytes, &it.i);
        const hi = lo + readVarint(it.bytes, &it.i);
        it.next_lo = hi + 1;
        return .{ .lo = @intCast(lo), .hi = @intCast(hi) };
    }
};

/// Whether `cp` is in `tables.bases[base]` (a walk over its ranges).
fn inTable(base: u16, cp: u21) bool {
    var it: TableRanges = .init(base);
    while (it.next()) |r| {
        if (cp < r.lo) return false;
        if (cp <= r.hi) return true;
    }
    return false;
}

/// Unicode `\w` (`perl_word`), decoded at compile time.
const perl_word_ranges = blk: {
    @setEvalBranchQuota(100_000);
    var out: [tables.bases[tables.perl_word].count]Range = undefined;
    var it: TableRanges = .init(tables.perl_word);
    for (&out) |*r| r.* = it.next().?;
    break :blk out;
};

/// Whether `cp` is a word character of the Unicode word boundaries.
pub fn isPerlWord(cp: u21) bool {
    const rs = &perl_word_ranges;
    var lo: usize = 0;
    var hi: usize = rs.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (cp < rs[mid].lo) hi = mid else if (cp > rs[mid].hi) lo = mid + 1 else return true;
    }
    return false;
}

/// The table of a `tables` key.
fn findName(key: []const u8) ?u16 {
    return if (findEntry(key)) |e| e.base else null;
}

/// The entry of a `tables` key, by binary search.
fn findEntry(key: []const u8) ?tables.Name {
    const names = &tables.names;
    var lo: usize = 0;
    var hi: usize = names.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        switch (std.mem.order(u8, names[mid].name, key)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return names[mid],
        }
    }
    return null;
}

/// regex-syntax's `symbolic_name_normalize`: an `is` prefix (any case)
/// dropped, ASCII lower-cased, ` `, `_`, `-` and non-ASCII bytes dropped;
/// `isc` (ISO_Comment) kept. Truncated to `buf` (longer than any key).
fn rustNormalize(name: []const u8, buf: *[max_class_name]u8) []const u8 {
    const is = name.len >= 2 and std.ascii.eqlIgnoreCase(name[0..2], "is");
    var n: usize = 0;
    for (name[if (is) 2 else 0..]) |c| {
        if (c == ' ' or c == '_' or c == '-' or c >= 0x80) continue;
        if (n == buf.len) break;
        buf[n] = std.ascii.toLower(c);
        n += 1;
    }
    if (is and n == 1 and buf[0] == 'c') {
        @memcpy(buf[0..3], "isc");
        n = 3;
    }
    return buf[0..n];
}

fn isWordBoundaryNameChar(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '-';
}

/// Longer than any Unicode class name in its loose form.
const max_class_name = 48;

/// `name` in its loose form into `buf`: ASCII letters lower-cased, spaces,
/// underscores and hyphens dropped. Null when nothing is left or it does not fit.
fn looseName(name: []const u8, buf: *[max_class_name]u8) ?[]const u8 {
    var n: usize = 0;
    for (name) |c| {
        if (c == ' ' or c == '_' or c == '-') continue;
        if (n == buf.len) return null;
        buf[n] = std.ascii.toLower(c);
        n += 1;
    }
    return if (n == 0) null else buf[0..n];
}

/// Whether `cp` is in the Unicode class of key `key` (one of
/// `unicode_tables.names`) — a walk over its stored ranges.
pub fn unicodeClassContains(comptime key: []const u8, cp: u21) bool {
    return inTable(comptime findName(key).?, cp);
}

/// One LEB128 varint at `bytes[i.*..]` (the generator writes at most three bytes).
fn readVarint(bytes: []const u8, i: *usize) u32 {
    var v: u32 = 0;
    var shift: u5 = 0;
    while (true) {
        const c = bytes[i.*];
        i.* += 1;
        v |= @as(u32, c & 0x7f) << shift;
        if (c < 0x80) return v;
        shift += 7;
    }
}

fn sameRanges(x: []const Range, y: []const Range) bool {
    for (x, y) |p, q| if (p.lo != q.lo or p.hi != q.hi) return false;
    return true;
}

fn hexDigit(c: u8) ?u32 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Whether case-insensitive matching changes what `cp` matches.
fn hasFold(cp: u21) bool {
    const i = firstRunEndingAtOrAfter(cp);
    return i < casefold.runs.len and casefold.runs[i].lo <= cp;
}

/// Sort ranges by their low end: insertion for the usual handful, pdq for a
/// big folded class.
fn sortRanges(rs: []Range) void {
    const lt = struct {
        fn lt(_: void, x: Range, y: Range) bool {
            return x.lo < y.lo;
        }
    }.lt;
    if (rs.len <= 16) std.sort.insertion(Range, rs, {}, lt) else std.sort.pdq(Range, rs, {}, lt);
}

/// The successor of `cp` in its case-folding orbit (`cp` itself: none).
fn foldNext(cp: u21) u21 {
    const i = firstRunEndingAtOrAfter(cp);
    if (i == casefold.runs.len or casefold.runs[i].lo > cp) return cp;
    const run = casefold.runs[i];
    if (run.alt) return if ((cp - run.lo) & 1 == 0) cp + 1 else cp - 1;
    return @intCast(@as(i32, cp) + run.delta);
}

/// The index of the first fold run whose `hi` is at least `cp` (binary search).
fn firstRunEndingAtOrAfter(cp: u21) usize {
    return firstRunIn(casefold, cp);
}

fn firstRunIn(comptime cf: type, cp: u21) usize {
    const runs = &cf.runs;
    var lo: usize = 0;
    var hi: usize = runs.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (runs[mid].hi < cp) lo = mid + 1 else hi = mid;
    }
    return lo;
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

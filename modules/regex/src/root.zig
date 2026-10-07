// SPDX-License-Identifier: MIT

//! regex — RE2-syntax regular expressions in linear time.
//!
//! The grammar of Go's `regexp/syntax` (RE2): literals, `.`, classes
//! (`[a-z]`, `[^…]`, `\d\s\w`, `[[:alpha:]]`), groups (capturing, named
//! `(?P<n>…)`/`(?<n>…)`, non-capturing `(?:…)`), alternation, greedy and lazy
//! repetition up to `{1000}`, the flags `i m s U`, and the empty-width
//! assertions `^ $ \A \z \b \B`. Matching is a Pike VM over a Thompson NFA:
//! time linear in pattern × input, no backtracking, so no pattern can make it
//! explode (no backreferences or lookaround — RE2 leaves them out for that
//! reason). Leftmost-first semantics, as Go's `regexp` and Perl.
//!
//! Compiling needs no allocator: `comptimeCompile` builds the program at
//! compile time (a bad pattern is a compile error), `compile` at run time.
//! `isMatch` and `fullMatch` run in fixed stack scratch, with no allocator;
//! submatch positions (`Matcher`) take scratch sized by the program, once.
//!
//! Input is UTF-8 and matched per code point; an invalid byte reads as
//! U+FFFD, one byte wide (as Go). `(?i)` folds by Unicode's simple case
//! folding (`(?i)é` matches `É`). Not yet: Unicode property classes
//! (`\pL`, `\p{Greek}`) (SPEC Backlog).

const std = @import("std");
const syntax = @import("syntax.zig");
const replace = @import("replace.zig");

pub const meta = .{
    .doc = "RE2-syntax regular expressions — Pike VM, linear time, comptime compile, alloc-free match",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // A compiled Regex is immutable; matching uses caller/stack scratch.
    .concurrency = .reentrant,
    .model_after = "Go regexp / RE2 (syntax and leftmost-first semantics)",
    .deps = .{},
};

pub const Error = syntax.Error;
pub const Syntax = syntax.Syntax;

/// How `compileOptions` reads a pattern and which match it reports.
pub const Options = struct {
    syntax: Syntax = .perl,
    /// Leftmost-longest instead of leftmost-first (Go's `Longest()`): among
    /// the matches that start leftmost, the longest; among those, the one
    /// leftmost-first would find first. Null: what the syntax implies — off
    /// for `.perl`, on for `.posix` (Go's `CompilePOSIX`).
    longest: ?bool = null,

    fn isLongest(o: Options) bool {
        return o.longest orelse (o.syntax == .posix);
    }
};
pub const max_insts = syntax.max_insts;
pub const max_groups = syntax.max_groups;
pub const max_repeat = syntax.max_repeat;
pub const max_depth = syntax.max_depth;

const Inst = syntax.Inst;
const Range = syntax.Range;
const Assert = syntax.Assert;

/// A match: `input[start..end]`.
pub const Span = struct {
    start: usize,
    end: usize,

    pub fn slice(s: Span, input: []const u8) []const u8 {
        return input[s.start..s.end];
    }
};

/// A compiled pattern. Immutable; safe to share across threads.
pub const Regex = struct {
    insts: []const Inst,
    ranges: []const Range,
    /// Group names; [0] is the whole match, `""` an unnamed group.
    names: []const []const u8,
    /// Set by `compile`: the slices above are owned (free with `deinit`).
    owned: bool = false,
    /// What the search may skip, from `analyze` (the defaults skip nothing).
    prefilter: Prefilter = .{},
    /// Leftmost-longest matching (Go's `Longest()`; see `Options.longest`).
    /// May be set after compiling, before the `Regex` is shared.
    longest: bool = false,
    /// The pattern it was compiled from (Go's `String()`); owned like the tables.
    source: []const u8 = "",

    /// Compile at run time. The result owns its tables; `deinit` frees them.
    /// A pattern that fits `small_capacity` compiles in ~9 KiB of stack
    /// scratch; a larger one in a full `Builder` from `gpa`.
    pub fn compile(gpa: std.mem.Allocator, pattern: []const u8) (Error || std.mem.Allocator.Error)!Regex {
        return compileOptions(gpa, pattern, .{});
    }

    /// `compile` in POSIX ERE syntax with leftmost-longest matching (Go's
    /// `CompilePOSIX`).
    pub fn compilePosix(gpa: std.mem.Allocator, pattern: []const u8) (Error || std.mem.Allocator.Error)!Regex {
        return compileOptions(gpa, pattern, .{ .syntax = .posix });
    }

    /// `compile` with a choice of syntax and match semantics.
    pub fn compileOptions(gpa: std.mem.Allocator, pattern: []const u8, opts: Options) (Error || std.mem.Allocator.Error)!Regex {
        var small: syntax.BuilderOf(small_capacity) = undefined;
        if (compileWith(gpa, &small, pattern, opts)) |re| return re else |e| if (e != error.PatternTooLarge) return e;
        const b = try gpa.create(syntax.Builder);
        defer gpa.destroy(b);
        return compileWith(gpa, b, pattern, opts);
    }

    /// `compile` with the caller's `Builder` (~80 KiB of compile scratch, any
    /// lifetime) — for compiling many patterns, or into an arena that should
    /// not hold the scratch.
    pub fn compileUsing(gpa: std.mem.Allocator, b: *Builder, pattern: []const u8) (Error || std.mem.Allocator.Error)!Regex {
        return compileWith(gpa, b, pattern, .{});
    }

    /// `compileUsing` with a choice of syntax and match semantics.
    pub fn compileUsingOptions(gpa: std.mem.Allocator, b: *Builder, pattern: []const u8, opts: Options) (Error || std.mem.Allocator.Error)!Regex {
        return compileWith(gpa, b, pattern, opts);
    }

    fn compileWith(gpa: std.mem.Allocator, b: anytype, pattern: []const u8, opts: Options) (Error || std.mem.Allocator.Error)!Regex {
        try b.compileSyntax(pattern, opts.syntax);
        const insts = try gpa.dupe(Inst, b.insts[0..b.ninsts]);
        errdefer gpa.free(insts);
        const ranges = try gpa.dupe(Range, b.ranges[0..b.nranges]);
        errdefer gpa.free(ranges);
        const names = try gpa.alloc([]const u8, b.ngroups);
        var done: usize = 0;
        errdefer {
            for (names[0..done]) |n| gpa.free(n);
            gpa.free(names);
        }
        for (names, b.names[0..b.ngroups]) |*slot, n| {
            slot.* = try gpa.dupe(u8, n);
            done += 1;
        }
        const source = try gpa.dupe(u8, pattern);
        return .{ .insts = insts, .ranges = ranges, .names = names, .owned = true, .prefilter = analyze(insts, ranges), .longest = opts.isLongest(), .source = source };
    }

    pub fn deinit(re: *Regex, gpa: std.mem.Allocator) void {
        if (re.owned) {
            gpa.free(re.insts);
            gpa.free(re.ranges);
            for (re.names) |n| gpa.free(n);
            gpa.free(re.names);
            gpa.free(re.source);
        }
        re.* = undefined;
    }

    /// Number of capture groups (group 0, the whole match, not counted).
    pub fn groupCount(re: *const Regex) usize {
        return re.names.len - 1;
    }

    /// Index of the first group named `name`, or null (Go lets two groups
    /// share a name).
    pub fn groupIndex(re: *const Regex, name: []const u8) ?usize {
        for (re.names[1..], 1..) |n, i| if (n.len != 0 and std.mem.eql(u8, n, name)) return i;
        return null;
    }

    /// Does the pattern match anywhere in `input`? (Go's `MatchString`.)
    /// No allocator; scratch on the stack, bounded by `max_insts`.
    pub fn isMatch(re: *const Regex, input: []const u8) bool {
        return re.runSet(input, false);
    }

    /// Does the pattern match all of `input`? (Go: `^(?:re)$` without `(?m)`.)
    /// Any way through the pattern counts, not only the leftmost-first one.
    pub fn fullMatch(re: *const Regex, input: []const u8) bool {
        return re.runSet(input, true);
    }

    /// Go's `Expand`: `template` with `$1`, `${name}`, `$$` replaced from a
    /// match's `groups` (as `Matcher.captures` fills them) in `input`.
    pub fn expand(re: *const Regex, w: *std.Io.Writer, template: []const u8, input: []const u8, groups: []const ?Span) std.Io.Writer.Error!void {
        return replace.expand(re, w, template, input, groups);
    }

    /// Go's `LiteralPrefix`: writes the literal text every match begins with;
    /// true when that text is the whole pattern.
    pub fn literalPrefix(re: *const Regex, w: *std.Io.Writer) std.Io.Writer.Error!bool {
        return replace.literalPrefix(re, w);
    }

    /// Go's `ReplaceAllString`, into a new allocation (see
    /// `Matcher.replaceAll`). Allocates the VM scratch for this one call.
    pub fn replaceAll(re: *const Regex, gpa: std.mem.Allocator, input: []const u8, template: []const u8) std.mem.Allocator.Error![]u8 {
        var m = try Matcher.init(gpa, re);
        defer m.deinit();
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        m.replaceAll(&out.writer, input, template) catch return error.OutOfMemory;
        return out.toOwnedSlice();
    }

    /// Go's `ReplaceAllLiteralString`, into a new allocation.
    pub fn replaceAllLiteral(re: *const Regex, gpa: std.mem.Allocator, input: []const u8, replacement: []const u8) std.mem.Allocator.Error![]u8 {
        var m = try Matcher.init(gpa, re);
        defer m.deinit();
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        m.replaceAllLiteral(&out.writer, input, replacement) catch return error.OutOfMemory;
        return out.toOwnedSlice();
    }

    /// Go's `Split`: the pieces between matches, as slices of `input` in a new
    /// allocation (see `SplitIterator` for `limit`).
    pub fn split(re: *const Regex, gpa: std.mem.Allocator, input: []const u8, limit: ?usize) std.mem.Allocator.Error![][]const u8 {
        var m = try Matcher.init(gpa, re);
        defer m.deinit();
        var pieces: std.ArrayList([]const u8) = .empty;
        errdefer pieces.deinit(gpa);
        var it = m.split(input, limit);
        while (it.next()) |p| try pieces.append(gpa, p);
        return pieces.toOwnedSlice(gpa);
    }

    /// Leftmost-first match, or null. Allocates the VM scratch for this one
    /// call; repeated matching should keep a `Matcher`.
    pub fn find(re: *const Regex, gpa: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error!?Span {
        var m = try Matcher.init(gpa, re);
        defer m.deinit();
        return m.find(input, 0);
    }

    /// Go's `MatchReader`: does the pattern match anywhere in what `r`
    /// yields? Reads code point by code point, no further than it must (at
    /// most three code points past the end of a match); no allocator,
    /// constant memory. `r`'s buffer must hold at least 4 bytes (one UTF-8 sequence).
    pub fn isMatchReader(re: *const Regex, r: *std.Io.Reader) error{ReadFailed}!bool {
        var t: ReaderText = .init(r);
        const found = re.runSetOn(&t, false);
        if (t.failed) return error.ReadFailed;
        return found;
    }

    fn runSet(re: *const Regex, input: []const u8, full: bool) bool {
        var t: SliceText = .{ .input = input };
        return re.runSetOn(&t, full);
    }

    /// `noinline`: its ~6 KiB of stack scratch is paid only while it runs,
    /// never by a caller's frame that inlined it.
    noinline fn runSetOn(re: *const Regex, text: anytype, full: bool) bool {
        // `undefined`, not `.{}`: a default-initialised StateSet is written
        // whole (~2 KiB each) on every call — measured as 85 % of `isMatch`.
        var lists: [2]StateSet = undefined;
        const words = (re.insts.len + 63) / 64;
        var stack: [2 * max_insts]u16 = undefined;
        var cur: *StateSet = &lists[0];
        var nxt: *StateSet = &lists[1];
        var pos: usize = 0;
        var prev: ?u21 = null;
        cur.clear(words);
        const pf = re.prefilter;
        while (true) {
            if (!full and cur.n == 0) {
                // No thread alive: a match can only start where the prefilter allows.
                if (pf.anchored and pos != 0) return false;
                if (@TypeOf(text.*).can_skip and pf.first != null) {
                    pos = text.skip(pf, pos) orelse return false;
                    prev = text.before(pos);
                }
            }
            const here = text.at(pos);
            if ((!full and (!pf.anchored or pos == 0)) or pos == 0) re.closureSet(cur, 0, prev, here.cp, &stack);
            // No thread left: anchored, nothing can start later; unanchored,
            // the next position starts a new one.
            if (cur.n == 0 and (full or here.cp == null)) return false;
            nxt.clear(words);
            const after = if (here.cp != null) text.at(pos + here.w) else here;
            for (cur.pcs[0..cur.n]) |pc| {
                switch (re.insts[pc]) {
                    .match => if (!full or here.cp == null) return true,
                    else => if (here.cp) |cp| if (re.consumes(pc, cp))
                        re.closureSet(nxt, pc + 1, cp, after.cp, &stack),
                }
            }
            if (here.cp == null) return false;
            pos += here.w;
            prev = here.cp;
            std.mem.swap(*StateSet, &cur, &nxt);
        }
    }

    /// Add `pc0` and every state reachable from it without consuming input,
    /// at a position between `prev` and `next`.
    fn closureSet(re: *const Regex, set: *StateSet, pc0: u16, prev: ?u21, next: ?u21, stack: *[2 * max_insts]u16) void {
        var sp: usize = 0;
        stack[sp] = pc0;
        sp += 1;
        while (sp != 0) {
            sp -= 1;
            const pc = stack[sp];
            if (set.seen.isSet(pc)) continue;
            set.seen.set(pc);
            switch (re.insts[pc]) {
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
                .assert => |a| if (assertHolds(a, prev, next)) {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .rune, .any, .any_not_nl, .match => {
                    set.pcs[set.n] = pc;
                    set.n += 1;
                },
            }
        }
    }

    fn consumes(re: *const Regex, pc: u16, cp: u21) bool {
        return switch (re.insts[pc]) {
            .any => true,
            .any_not_nl => cp != '\n',
            .rune => |r| inRanges(re.ranges[r.start..][0..r.len], cp),
            else => false,
        };
    }
};

/// Compile `pattern` at compile time; a bad pattern is a compile error.
pub fn comptimeCompile(comptime pattern: []const u8) Regex {
    return comptimeCompileOptions(pattern, .{});
}

/// `comptimeCompile` with a choice of syntax and match semantics.
pub fn comptimeCompileOptions(comptime pattern: []const u8, comptime opts: Options) Regex {
    comptime {
        @setEvalBranchQuota(2_000_000);
        var b: syntax.Builder = .{};
        b.compileSyntax(pattern, opts.syntax) catch |e| @compileError("regex: \"" ++ pattern ++ "\": " ++ @errorName(e));
        const insts = b.insts[0..b.ninsts].*;
        const ranges = b.ranges[0..b.nranges].*;
        var names: [b.ngroups][]const u8 = undefined;
        for (&names, b.names[0..b.ngroups]) |*slot, n| slot.* = n;
        const final_names = names;
        return .{ .insts = &insts, .ranges = &ranges, .names = &final_names, .prefilter = analyze(&insts, &ranges), .longest = opts.isLongest(), .source = pattern };
    }
}

/// Check `pattern` without keeping a program (what `router` does at `add`).
pub fn validate(pattern: []const u8, scratch: *syntax.Builder) Error!void {
    return scratch.compile(pattern);
}

/// Check `pattern` in the given syntax without keeping a program.
pub fn validateSyntax(pattern: []const u8, syntax_: Syntax, scratch: *syntax.Builder) Error!void {
    return scratch.compileSyntax(pattern, syntax_);
}

pub const Builder = syntax.Builder;
pub const SplitIterator = replace.SplitIterator;

/// Go's `QuoteMeta`: `text` with `\.+*?()|[]{}^$` escaped — a pattern
/// matching exactly `text`.
pub const quoteMeta = replace.quoteMeta;

/// `quoteMeta` into a new allocation.
pub fn quoteMetaAlloc(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    replace.quoteMeta(&out.writer, text) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

/// Go's `MatchString`: compile `pattern` and look for it in `input` once.
pub fn matches(gpa: std.mem.Allocator, pattern: []const u8, input: []const u8) (Error || std.mem.Allocator.Error)!bool {
    var re = try Regex.compile(gpa, pattern);
    defer re.deinit(gpa);
    return re.isMatch(input);
}

const StateSet = struct {
    pcs: [max_insts]u16,
    n: u16,
    seen: std.StaticBitSet(max_insts),

    /// Empty the set; only the first `words` of `seen` (the program's
    /// length) are ever looked at.
    fn clear(s: *StateSet, words: usize) void {
        s.n = 0;
        @memset(s.seen.masks[0..words], 0);
    }
};

/// Table capacities `Regex.compile` tries first, on the stack: every pattern
/// short of a large counted repetition or a big case-folded class fits.
const small_capacity: syntax.Capacity = .{ .insts = 256, .ranges = 256, .nodes = 256 };

/// Where a match can start, worked out from the program once at compile time
/// so the search skips positions where no thread could begin. Only consulted
/// while no thread is alive, so it never changes which match is found.
pub const Prefilter = struct {
    /// Every match starts at the start of the text (each path passes `\A`).
    anchored: bool = false,
    /// The first byte of every match is in this set (bit b of word b/64);
    /// null when a match can be empty, or start with any byte.
    first: ?[4]u64 = null,
    /// The set's only member, when it has one.
    single: ?u8 = null,

    /// The first position at or after `pos` whose byte may start a match.
    fn next(pf: Prefilter, input: []const u8, pos: usize) ?usize {
        if (pf.single) |c| return std.mem.indexOfScalarPos(u8, input, pos, c);
        const set = pf.first.?;
        var i = pos;
        while (i < input.len) : (i += 1) {
            const c = input[i];
            if (set[c >> 6] & (@as(u64, 1) << @truncate(c)) != 0) return i;
        }
        return null;
    }
};

/// Work out `Prefilter` from a program: follow the empty transitions from the
/// start. `anchored` when a `\A` stands before every consuming state and the
/// match; `first` from the UTF-8 lead bytes of every class reachable there.
/// Byte positions the set skips are never the start of a code point the VM
/// would decode differently: a lead or ASCII byte always starts one, and a set
/// that could need a continuation byte (U+FFFD, what an invalid byte reads
/// as) is given up.
fn analyze(insts: []const Inst, ranges: []const Range) Prefilter {
    var pf: Prefilter = .{};
    var seen: std.StaticBitSet(max_insts) = .initEmpty();
    var stack: [2 * max_insts]u16 = undefined;
    var set: [4]u64 = .{ 0, 0, 0, 0 };
    var any_first = false; // a `.`, an empty match, or U+FFFD: no byte set
    var unanchored = false; // a consuming state or the match before any `\A`
    // Two walks: with `\A` as a wall (anchoring), and through it (first bytes).
    for ([_]bool{ true, false }) |wall| {
        seen = .initEmpty();
        var sp: usize = 1;
        stack[0] = 0;
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
                .split => |sx| {
                    stack[sp] = sx.y;
                    stack[sp + 1] = sx.x;
                    sp += 2;
                },
                .save => {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .assert => |a| if (!(wall and a == .begin_text)) {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .match, .any, .any_not_nl => if (wall) {
                    unanchored = true;
                } else {
                    any_first = true;
                },
                .rune => |r| if (wall) {
                    unanchored = true;
                } else for (ranges[r.start..][0..r.len]) |rg| {
                    if (rg.lo <= 0xfffd and 0xfffd <= rg.hi) any_first = true;
                    addLeadBytes(&set, rg);
                },
            }
        }
    }
    pf.anchored = !unanchored;
    if (!any_first) {
        pf.first = set;
        var count: usize = 0;
        for (set) |w| count += @popCount(w);
        if (count == 1) {
            for (set, 0..) |w, i| if (w != 0) {
                pf.single = @intCast(i * 64 + @ctz(w));
            };
        }
    }
    return pf;
}

/// Add the first bytes of the UTF-8 encodings of `r` to `set`.
fn addLeadBytes(set: *[4]u64, r: Range) void {
    const Band = struct { lo: u21, hi: u21, shift: u5, tag: u8 };
    const bands = [_]Band{
        .{ .lo = 0, .hi = 0x7f, .shift = 0, .tag = 0 },
        .{ .lo = 0x80, .hi = 0x7ff, .shift = 6, .tag = 0xc0 },
        .{ .lo = 0x800, .hi = 0xffff, .shift = 12, .tag = 0xe0 },
        .{ .lo = 0x10000, .hi = 0x10ffff, .shift = 18, .tag = 0xf0 },
    };
    for (bands) |band| {
        const lo: u32 = @max(r.lo, band.lo);
        const hi: u32 = @min(r.hi, band.hi);
        if (lo > hi) continue;
        var c: u32 = band.tag | (lo >> band.shift);
        const last: u32 = band.tag | (hi >> band.shift);
        while (c <= last) : (c += 1) set[c >> 6] |= @as(u64, 1) << @truncate(c);
    }
}

// ── submatches ──────────────────────────────────────────────────────────────

const nil = std.math.maxInt(usize);

/// VM scratch for one `Regex`, sized once by its program: leftmost-first
/// `find`, `captures`, and a non-overlapping iterator. Not thread-safe — one
/// per thread; the `Regex` itself is shared.
pub const Matcher = struct {
    gpa: std.mem.Allocator,
    re: *const Regex,
    /// Capture slots per thread: two per group.
    k: usize,
    /// The one allocation the slices below live in.
    block: []usize,
    lists: [2]List,
    stack: []Entry,
    tmp: []usize,
    best: []usize,

    const List = struct {
        pcs: []u16,
        caps: []usize,
        seen: []u32,
        gen: u32 = 0,
        n: usize = 0,

        fn clear(l: *List) void {
            l.n = 0;
            l.gen +%= 1;
            if (l.gen == 0) {
                @memset(l.seen, 0);
                l.gen = 1;
            }
        }
    };

    const Entry = union(enum) { explore: u16, restore: struct { slot: u16, val: usize } };

    /// One allocation, carved into the tables below (measured: five
    /// separate ones were most of a short pattern's per-call `Matcher` cost).
    pub fn init(gpa: std.mem.Allocator, re: *const Regex) std.mem.Allocator.Error!Matcher {
        const n = re.insts.len;
        const k = re.names.len * 2;
        const words = 2 * (wordsFor(usize, n * k) + wordsFor(u16, n) + wordsFor(u32, n)) +
            wordsFor(Entry, 3 * n) + 2 * wordsFor(usize, k);
        const block = try gpa.alloc(usize, words);
        var rest = block;
        var m: Matcher = .{ .gpa = gpa, .re = re, .k = k, .block = block, .lists = undefined, .stack = undefined, .tmp = undefined, .best = undefined };
        for (&m.lists) |*l| {
            l.* = .{ .caps = take(usize, &rest, n * k), .pcs = take(u16, &rest, n), .seen = take(u32, &rest, n) };
            @memset(l.seen, 0);
        }
        m.stack = take(Entry, &rest, 3 * n);
        m.tmp = take(usize, &rest, k);
        m.best = take(usize, &rest, k);
        return m;
    }

    fn wordsFor(comptime T: type, count: usize) usize {
        return (count * @sizeOf(T) + @sizeOf(usize) - 1) / @sizeOf(usize);
    }

    /// The next `count` items of type `T` from the block (every `T` here is
    /// aligned no stricter than `usize`).
    fn take(comptime T: type, rest: *[]usize, count: usize) []T {
        comptime std.debug.assert(@alignOf(T) <= @alignOf(usize));
        const out: [*]T = @ptrCast(rest.*.ptr);
        rest.* = rest.*[wordsFor(T, count)..];
        return out[0..count];
    }

    pub fn deinit(m: *Matcher) void {
        m.gpa.free(m.block);
        m.* = undefined;
    }

    /// Leftmost-first match starting the search at `from` (the text before
    /// `from` still counts for `^`/`\b`), or null.
    pub fn find(m: *Matcher, input: []const u8, from: usize) ?Span {
        if (from > input.len or !m.run(input, from, false)) return null;
        return .{ .start = m.best[0], .end = m.best[1] };
    }

    /// Like `find`, filling `out[i]` with group i's span (null: the group
    /// took no part); `out` may be shorter or longer than the group count.
    pub fn captures(m: *Matcher, input: []const u8, from: usize, out: []?Span) bool {
        if (from > input.len or !m.run(input, from, false)) return false;
        m.fillCaptures(out);
        return true;
    }

    fn fillCaptures(m: *const Matcher, out: []?Span) void {
        for (out, 0..) |*slot, i| {
            slot.* = if (2 * i + 1 < m.k and m.best[2 * i] != nil and m.best[2 * i + 1] != nil)
                .{ .start = m.best[2 * i], .end = m.best[2 * i + 1] }
            else
                null;
        }
    }

    /// Successive non-overlapping matches (Go's `FindAll`: an empty match
    /// right where the previous match ended is skipped).
    pub fn iterator(m: *Matcher, input: []const u8) Iterator {
        return .{ .m = m, .input = input };
    }

    /// Go's `ReplaceAllString`: `input` with every match replaced by
    /// `template` expanded for it (`Regex.expand`), written to `w`.
    pub const replaceAll = replace.replaceAll;
    /// Go's `ReplaceAllLiteralString`: every match replaced by `replacement`
    /// as it is.
    pub const replaceAllLiteral = replace.replaceAllLiteral;
    /// Go's `ReplaceAllStringFunc`: every match replaced by what
    /// `f(context, w, match)` writes.
    pub const replaceAllFunc = replace.replaceAllFunc;

    /// Go's `Split`: the pieces of `input` between matches; at most `limit`
    /// of them, the last the unsplit rest (null: all; 0: none).
    pub fn split(m: *Matcher, input: []const u8, limit: ?usize) SplitIterator {
        return .init(m, input, limit);
    }

    pub const Iterator = struct {
        m: *Matcher,
        input: []const u8,
        pos: usize = 0,
        prev_end: ?usize = null,

        pub fn next(it: *Iterator) ?Span {
            return it.advance(null);
        }

        /// `next` that also fills `out` as `Matcher.captures` does (Go's
        /// `FindAllSubmatchIndex`).
        pub fn nextCaptures(it: *Iterator, out: []?Span) ?Span {
            return it.advance(out);
        }

        fn advance(it: *Iterator, out: ?[]?Span) ?Span {
            while (it.pos <= it.input.len) {
                const found = if (out) |o| it.m.captures(it.input, it.pos, o) else it.m.find(it.input, it.pos) != null;
                if (!found) {
                    it.pos = it.input.len + 1;
                    return null;
                }
                const s: Span = .{ .start = it.m.best[0], .end = it.m.best[1] };
                var accept = true;
                if (s.start == s.end) {
                    if (it.prev_end != null and s.start == it.prev_end.?) accept = false;
                    it.pos = if (s.end < it.input.len) s.end + decode(it.input, s.end).w else it.input.len + 1;
                } else it.pos = s.end;
                it.prev_end = s.end;
                if (accept) return s;
            }
            return null;
        }
    };

    /// The Pike VM. Threads in a list are in priority order, those that
    /// started earlier first. Leftmost-first: a match cuts every
    /// lower-priority thread of the same step. Leftmost-longest: a match cuts
    /// nothing; later threads of the same start may still find a longer one,
    /// and threads that started later are dropped.
    fn run(m: *Matcher, input: []const u8, from: usize, full: bool) bool {
        var t: SliceText = .{ .input = input };
        return m.runOn(&t, from, full);
    }

    /// Go's `FindReaderIndex`: the leftmost match in what `r` yields, as byte
    /// offsets from where `r` stood. Reads no further than it must (at most
    /// three code points past the match's end); constant memory. `r`'s buffer must
    /// hold at least 4 bytes.
    pub fn findReader(m: *Matcher, r: *std.Io.Reader) error{ReadFailed}!?Span {
        var t: ReaderText = .init(r);
        const found = m.runOn(&t, 0, false);
        if (t.failed) return error.ReadFailed;
        if (!found) return null;
        return .{ .start = m.best[0], .end = m.best[1] };
    }

    /// Go's `FindReaderSubmatchIndex`: `findReader` that also fills `out` as
    /// `captures` does.
    pub fn capturesReader(m: *Matcher, r: *std.Io.Reader, out: []?Span) error{ReadFailed}!bool {
        var t: ReaderText = .init(r);
        const found = m.runOn(&t, 0, false);
        if (t.failed) return error.ReadFailed;
        if (!found) return false;
        m.fillCaptures(out);
        return true;
    }

    fn runOn(m: *Matcher, text: anytype, from: usize, full: bool) bool {
        const re = m.re;
        var cur = &m.lists[0];
        var nxt = &m.lists[1];
        cur.clear();
        var matched = false;
        var pos = from;
        var prev = text.before(from);
        const pf = re.prefilter;
        while (true) {
            if (!matched and cur.n == 0 and !full) {
                // No thread alive: a match can only start where the prefilter allows.
                if (pf.anchored and pos != from) break;
                if (@TypeOf(text.*).can_skip and pf.first != null) {
                    pos = text.skip(pf, pos) orelse break;
                    prev = text.before(pos);
                }
            }
            const here = text.at(pos);
            if (!matched and (!pf.anchored or pos == from)) {
                @memset(m.tmp, nil);
                m.addThread(cur, 0, pos, prev, here.cp);
            }
            if (cur.n == 0 and (matched or here.cp == null)) break;
            nxt.clear();
            const after = if (here.cp != null) text.at(pos + here.w) else here;
            var i: usize = 0;
            while (i < cur.n) : (i += 1) {
                const pc = cur.pcs[i];
                const caps = cur.caps[i * m.k ..][0..m.k];
                if (re.longest and matched and caps[0] > m.best[0]) continue; // started later
                switch (re.insts[pc]) {
                    .match => {
                        if (full and here.cp != null) continue;
                        if (re.longest) {
                            // The first thread to end here is the leftmost-first
                            // among equals; a later step is longer.
                            if (matched and m.best[1] == pos) continue;
                            @memcpy(m.best, caps);
                            m.best[1] = pos;
                            matched = true;
                            continue;
                        }
                        @memcpy(m.best, caps);
                        m.best[1] = pos;
                        matched = true;
                        break; // cut the lower-priority threads
                    },
                    else => if (here.cp) |cp| if (re.consumes(pc, cp)) {
                        @memcpy(m.tmp, caps);
                        m.addThread(nxt, pc + 1, pos + here.w, cp, after.cp);
                    },
                }
            }
            if (here.cp == null) break;
            pos += here.w;
            prev = here.cp;
            std.mem.swap(*List, &cur, &nxt);
        }
        return matched;
    }

    /// Follow every empty transition from `pc0` at `pos`, in priority
    /// order, adding each consuming or matching state with the captures of
    /// the path that reached it first. `m.tmp` holds the thread's captures
    /// and is restored on the way back out.
    fn addThread(m: *Matcher, list: *List, pc0: u16, pos: usize, prev: ?u21, next: ?u21) void {
        const re = m.re;
        var sp: usize = 0;
        m.stack[sp] = .{ .explore = pc0 };
        sp += 1;
        while (sp != 0) {
            sp -= 1;
            switch (m.stack[sp]) {
                .restore => |r| m.tmp[r.slot] = r.val,
                .explore => |pc| {
                    if (list.seen[pc] == list.gen) continue;
                    list.seen[pc] = list.gen;
                    switch (re.insts[pc]) {
                        .jmp => |t| {
                            m.stack[sp] = .{ .explore = t };
                            sp += 1;
                        },
                        .split => |s| {
                            m.stack[sp] = .{ .explore = s.y };
                            m.stack[sp + 1] = .{ .explore = s.x };
                            sp += 2;
                        },
                        .save => |slot| {
                            if (slot < m.k) {
                                m.stack[sp] = .{ .restore = .{ .slot = slot, .val = m.tmp[slot] } };
                                sp += 1;
                                m.tmp[slot] = pos;
                            }
                            m.stack[sp] = .{ .explore = pc + 1 };
                            sp += 1;
                        },
                        .assert => |a| if (assertHolds(a, prev, next)) {
                            m.stack[sp] = .{ .explore = pc + 1 };
                            sp += 1;
                        },
                        .rune, .any, .any_not_nl, .match => {
                            list.pcs[list.n] = pc;
                            @memcpy(list.caps[list.n * m.k ..][0..m.k], m.tmp);
                            list.n += 1;
                        },
                    }
                },
            }
        }
    }
};

// ── text ────────────────────────────────────────────────────────────────────

/// The VMs read text through one of these. `at(pos)` is the code point at
/// `pos`; the VMs only ever ask for the current position and the one after it.
const SliceText = struct {
    input: []const u8,

    const can_skip = true;

    fn at(t: *const SliceText, pos: usize) Decoded {
        return decode(t.input, pos);
    }

    fn before(t: *const SliceText, pos: usize) ?u21 {
        return runeBefore(t.input, pos);
    }

    fn skip(t: *const SliceText, pf: Prefilter, pos: usize) ?usize {
        return pf.next(t.input, pos);
    }
};

/// A `std.Io.Reader` decoded as `decode` reads a slice, in a window of two
/// code points: `win[0]` at byte offset `base`, `win[1]` right after it. Asking
/// for a later position slides the window; nothing before it is kept.
const ReaderText = struct {
    r: *std.Io.Reader,
    base: usize = 0,
    win: [2]Decoded = undefined,
    /// The reader failed; the VM saw the end of the text there.
    failed: bool = false,

    /// No skipping ahead: the bytes between would have to be read anyway.
    const can_skip = false;

    fn init(r: *std.Io.Reader) ReaderText {
        var t: ReaderText = .{ .r = r };
        t.win[0] = t.read();
        t.win[1] = if (t.win[0].cp != null) t.read() else t.win[0];
        return t;
    }

    fn at(t: *ReaderText, pos: usize) Decoded {
        while (pos > t.base and t.win[0].cp != null) {
            t.base += t.win[0].w;
            t.win[0] = t.win[1];
            t.win[1] = if (t.win[0].cp != null) t.read() else t.win[0];
        }
        std.debug.assert(pos == t.base);
        return t.win[0];
    }

    fn before(_: *const ReaderText, pos: usize) ?u21 {
        std.debug.assert(pos == 0);
        return null;
    }

    fn skip(_: *const ReaderText, _: Prefilter, pos: usize) ?usize {
        return pos;
    }

    /// The next code point; an invalid sequence is U+FFFD, one byte, and the
    /// bytes after its first stay unread.
    fn read(t: *ReaderText) Decoded {
        const bad: Decoded = .{ .cp = 0xfffd, .w = 1 };
        const c = t.r.takeByte() catch |e| {
            if (e == error.ReadFailed) t.failed = true;
            return .{ .cp = null, .w = 0 };
        };
        if (c < 0x80) return .{ .cp = c, .w = 1 };
        const len = std.unicode.utf8ByteSequenceLength(c) catch return bad;
        const rest = t.r.peek(len - 1) catch |e| {
            if (e == error.ReadFailed) t.failed = true;
            return bad;
        };
        var buf: [4]u8 = undefined;
        buf[0] = c;
        @memcpy(buf[1..len], rest);
        const cp = std.unicode.utf8Decode(buf[0..len]) catch return bad;
        t.r.toss(len - 1);
        return .{ .cp = cp, .w = len };
    }
};

const Decoded = struct { cp: ?u21, w: usize };

/// The code point at `i` (null at the end); an invalid sequence is U+FFFD,
/// one byte wide.
fn decode(input: []const u8, i: usize) Decoded {
    if (i >= input.len) return .{ .cp = null, .w = 0 };
    const c = input[i];
    if (c < 0x80) return .{ .cp = c, .w = 1 };
    const len = std.unicode.utf8ByteSequenceLength(c) catch return .{ .cp = 0xfffd, .w = 1 };
    if (i + len > input.len) return .{ .cp = 0xfffd, .w = 1 };
    const cp = std.unicode.utf8Decode(input[i..][0..len]) catch return .{ .cp = 0xfffd, .w = 1 };
    return .{ .cp = cp, .w = len };
}

/// What the assertions need of the text just before `i`: null at the start,
/// the byte when it is ASCII, and U+FFFD for any non-ASCII code point — the
/// assertions look only at ASCII (`\n` for `(?m)^`, ASCII word characters
/// for `\b`, as RE2), so which non-ASCII code point it was never matters.
fn runeBefore(input: []const u8, i: usize) ?u21 {
    if (i == 0) return null;
    const c = input[i - 1];
    return if (c < 0x80) c else 0xfffd;
}

fn isWord(cp: ?u21) bool {
    const c = cp orelse return false;
    return c < 0x80 and (std.ascii.isAlphanumeric(@intCast(c)) or c == '_');
}

fn assertHolds(a: Assert, prev: ?u21, next: ?u21) bool {
    return switch (a) {
        .begin_text => prev == null,
        .end_text => next == null,
        .begin_line => prev == null or prev.? == '\n',
        .end_line => next == null or next.? == '\n',
        .word_boundary => isWord(prev) != isWord(next),
        .not_word_boundary => isWord(prev) == isWord(next),
    };
}

fn inRanges(ranges: []const Range, cp: u21) bool {
    var lo: usize = 0;
    var hi: usize = ranges.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (cp < ranges[mid].lo) hi = mid else if (cp > ranges[mid].hi) lo = mid + 1 else return true;
    }
    return false;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectFind(pattern: []const u8, input: []const u8, want: ?[]const u8) !void {
    var re = try Regex.compile(testing.allocator, pattern);
    defer re.deinit(testing.allocator);
    const got = try re.find(testing.allocator, input);
    errdefer std.debug.print("/{s}/ on \"{s}\": got {?any}\n", .{ pattern, input, got });
    if (want) |w| {
        try testing.expect(got != null);
        try testing.expectEqualStrings(w, got.?.slice(input));
    } else try testing.expectEqual(@as(?Span, null), got);
    try testing.expectEqual(want != null, re.isMatch(input));
}

test "literals, classes, dot, anchors" {
    try expectFind("abc", "xxabcxx", "abc");
    try expectFind("a.c", "abc", "abc");
    try expectFind("a.c", "a\nc", null);
    try expectFind("(?s)a.c", "a\nc", "a\nc");
    try expectFind("[a-c]+", "xxbcay", "bca");
    try expectFind("[^a-c]+", "abxyc", "xy");
    try expectFind("\\d+", "ab123c", "123");
    try expectFind("\\w+", "  foo_1 ", "foo_1");
    try expectFind("[[:alpha:]]+", "12ab3", "ab");
    try expectFind("^ab", "ab", "ab");
    try expectFind("^ab", "cab", null);
    try expectFind("b$", "ab", "b");
    try expectFind("b$", "ab\n", null); // RE2: $ is end of text without (?m)
    try expectFind("(?m)b$", "ab\nc", "b");
    try expectFind("\\bfoo\\b", "a foo b", "foo");
    try expectFind("\\bfoo\\b", "afoob", null);
    try expectFind("é+", "aééb", "éé");
    try expectFind("(?i)HeLLo", "say hello", "hello");
    try expectFind("(?i)k", "\u{212a}", "\u{212a}");
    try expectFind("\\Qa.b\\E+", "a.bbb", "a.bbb");
    try expectFind("\\x41\\x{263a}", "A\u{263a}", "A\u{263a}");
}

test "(?i) folds by Unicode simple case folding" {
    try expectFind("(?i)é", "xÉy", "É");
    try expectFind("(?i)[á-ž]+", "xčÉŠx", "čÉŠ");
    try expectFind("(?i)ǅ", "ǆ", "ǆ"); // an orbit of three: Ǆ ǅ ǆ
    try expectFind("(?i)θ", "ϴ", "ϴ"); // an orbit of four: θ ϑ Θ ϴ
    try expectFind("(?i)ß", "ẞ", "ẞ");
    try expectFind("(?i)𐐀", "𐐨", "𐐨");
    try expectFind("(?i)[^é]", "É", null); // folded before negated
    try expectFind("é", "É", null);
    // A class over all of Unicode folds run by run, also at comptime.
    const all = comptime comptimeCompile("(?i)[^\\x{0}-\\x{40}]+");
    try testing.expect(all.fullMatch("aÁ𐐀"));
    const cz = comptime comptimeCompile("(?i)příliš žluťoučký");
    try testing.expect(cz.fullMatch("PŘÍLIŠ ŽLUŤOUČKÝ"));
}

test "Unicode classes: categories, scripts, aliases, loose names, negation, folding" {
    try expectFind("\\pL+", "12žluť3", "žluť");
    try expectFind("\\p{Lu}\\p{Ll}+", "x Ωmega", "Ωmega");
    try expectFind("\\p{Greek}+", "abc αβγ", "αβγ");
    try expectFind("\\p{Han}+", "x中文y", "中文");
    try expectFind("\\PL+", "ab12cd", "12");
    try expectFind("\\p{^L}+", "ab12cd", "12");
    try expectFind("\\P{^N}+", "ab٣3cd", "٣3"); // double negation
    try expectFind("[\\p{Greek}\\d]+", "xα1β", "α1β");
    try expectFind("[^\\p{L}\\s]+", "ab, cd", ",");
    try expectFind("\\p{lowercase letter}+", "ABcdE", "cd"); // loose: case, space, _ and - ignored
    try expectFind("\\p{old_persian}", "\u{103a0}", "\u{103a0}"); // Go 1.26 refuses it (GO_DEFECT)
    try expectFind("\\p{ASCII}+", "éabcé", "abc");
    try expectFind("\\p{Assigned}", "\u{378}a", "a");
    try expectFind("\\p{Any}", "\u{378}", "\u{378}");
    try expectFind("(?i)\\p{Lu}+", "abcD1", "abcD"); // folded like any class
    try expectFind("(?i)\\P{Lu}", "aB1", "1"); // folded, then negated
    // The tables also compile at comptime; a class named twice is stored once.
    const ident = comptime comptimeCompile("\\p{L}[\\p{L}\\p{N}_]*");
    try testing.expect(ident.fullMatch("π_2ž"));
    try testing.expect(!ident.fullMatch("2π"));
    var many = try Regex.compile(testing.allocator, "\\p{L}" ** 12);
    defer many.deinit(testing.allocator);
    try testing.expect(many.ranges.len < 2 * 1000);
}

test "leftmost-first, greedy and lazy" {
    try expectFind("a|ab", "ab", "a");
    try expectFind("ab|a", "ab", "ab");
    try expectFind("a+", "baaa", "aaa");
    try expectFind("a+?", "baaa", "a");
    try expectFind("a{2,3}", "aaaa", "aaa");
    try expectFind("a{2,3}?", "aaaa", "aa");
    try expectFind("(?U)a+", "aaa", "a");
    try expectFind("x*", "aaa", "");
    try expectFind("(a*)*b", "aaab", "aaab");
}

test "leftmost-longest (Go's Longest) and POSIX ERE syntax (Go's CompilePOSIX)" {
    var re = try Regex.compile(testing.allocator, "a|ab|abc");
    defer re.deinit(testing.allocator);
    try testing.expectEqualStrings("a", (try re.find(testing.allocator, "abcd")).?.slice("abcd"));
    re.longest = true;
    try testing.expectEqualStrings("abc", (try re.find(testing.allocator, "abcd")).?.slice("abcd"));
    // Among the longest, the one leftmost-first finds first: (a)(bcd), not (ab)(cd).
    var ll = try Regex.compileOptions(testing.allocator, "(a|ab)(c|bcd)(d*)", .{ .longest = true });
    defer ll.deinit(testing.allocator);
    var m = try Matcher.init(testing.allocator, &ll);
    defer m.deinit();
    var out: [4]?Span = undefined;
    try testing.expect(m.captures("abcd", 0, &out));
    try testing.expectEqual(Span{ .start = 0, .end = 4 }, out[0].?);
    try testing.expectEqual(Span{ .start = 0, .end = 1 }, out[1].?);
    // POSIX: no Perl escapes or (?…); ^/$ at line breaks; a negated class
    // skips newlines; `a*?` is (a*)?; leftmost-longest by default.
    try testing.expectError(error.InvalidEscape, Regex.compilePosix(testing.allocator, "\\d"));
    try testing.expectError(error.MissingRepeatArgument, Regex.compilePosix(testing.allocator, "(?i)a"));
    try testing.expectError(error.InvalidCharRange, Regex.compilePosix(testing.allocator, "[a-c-e]"));
    var px = try Regex.compilePosix(testing.allocator, "^b[^a]*$");
    defer px.deinit(testing.allocator);
    try testing.expect(px.longest);
    try testing.expectEqualStrings("bc", (try px.find(testing.allocator, "a\nbc\nd")).?.slice("a\nbc\nd"));
    const cpx = comptime comptimeCompileOptions("a**|b{2}{2}", .{ .syntax = .posix });
    try testing.expect(cpx.fullMatch("bbbb"));
}

test "replace, expand, split, quoteMeta, literalPrefix, source (Go's API on top of a search)" {
    const gpa = testing.allocator;
    var re = try Regex.compile(gpa, "(?P<y>\\d{4})-(\\d{2})");
    defer re.deinit(gpa);
    try testing.expectEqualStrings("(?P<y>\\d{4})-(\\d{2})", re.source);
    const swapped = try re.replaceAll(gpa, "from 2026-10 to 2027-01.", "$2/${y} ($$)");
    defer gpa.free(swapped);
    try testing.expectEqualStrings("from 10/2026 ($) to 01/2027 ($).", swapped);
    // `$2x` names group "2x" (none): nothing; `$01` is not a group number.
    const odd = try re.replaceAll(gpa, "2026-10", "[$2x|${2}x|$01|$]");
    defer gpa.free(odd);
    try testing.expectEqualStrings("[|10x||$]", odd);
    const lit = try re.replaceAllLiteral(gpa, "2026-10!", "$1");
    defer gpa.free(lit);
    try testing.expectEqualStrings("$1!", lit);

    var m = try Matcher.init(gpa, &re);
    defer m.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try m.replaceAllFunc(&out.writer, "a 2026-10 b", @as(usize, 7), struct {
        fn f(n: usize, w: *std.Io.Writer, match: []const u8) std.Io.Writer.Error!void {
            try w.print("<{d}:{d}>", .{ n, match.len });
        }
    }.f);
    try testing.expectEqualStrings("a <7:7> b", out.written());

    var star = try Regex.compile(gpa, "a*");
    defer star.deinit(gpa);
    const pieces = try star.split(gpa, "abaabaccadaaae", 5);
    defer gpa.free(pieces);
    const want = [_][]const u8{ "", "b", "b", "c", "cadaaae" }; // Go's doc example
    try testing.expectEqual(want.len, pieces.len);
    for (want, pieces) |w, p| try testing.expectEqualStrings(w, p);
    const none = try star.split(gpa, "abc", 0);
    defer gpa.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);

    const q = try quoteMetaAlloc(gpa, "1.5*[x]");
    defer gpa.free(q);
    try testing.expectEqualStrings("1\\.5\\*\\[x\\]", q);
    try testing.expect(try matches(gpa, q, "is 1.5*[x]"));

    out.clearRetainingCapacity();
    try testing.expect(!try re.literalPrefix(&out.writer));
    try testing.expectEqualStrings("", out.written());
    var lp = try Regex.compile(gpa, "foo(bar)");
    defer lp.deinit(gpa);
    out.clearRetainingCapacity();
    try testing.expect(try lp.literalPrefix(&out.writer));
    try testing.expectEqualStrings("foobar", out.written());

    // All matches with their groups (Go's FindAllSubmatchIndex).
    var it = m.iterator("2026-10 2027-01");
    var groups: [3]?Span = undefined;
    var years: usize = 0;
    while (it.nextCaptures(&groups)) |_| years += 1;
    try testing.expectEqual(@as(usize, 2), years);
    try testing.expectEqual(Span{ .start = 8, .end = 12 }, groups[1].?);
}

test "reader front end (Go's MatchReader, FindReaderIndex): constant memory, reads no further than it must" {
    var re = try Regex.compile(testing.allocator, "(\\p{L}+)=(\\d+)");
    defer re.deinit(testing.allocator);
    var m = try Matcher.init(testing.allocator, &re);
    defer m.deinit();
    const text = "-- žluť=42; rest of a long stream";
    var buf: [4]u8 = undefined;
    var tr: std.testing.Reader = .init(&buf, &.{.{ .buffer = text }});
    tr.artificial_limit = .limited(1);
    var out: [3]?Span = undefined;
    try testing.expect(try m.capturesReader(&tr.interface, &out));
    try testing.expectEqualStrings("žluť=42", out[0].?.slice(text));
    try testing.expectEqualStrings("42", out[2].?.slice(text));
    // The match ends at the `;`: the reader stopped within three bytes of it.
    var left: usize = 0;
    while (tr.interface.takeByte()) |_| left += 1 else |_| {}
    errdefer std.debug.print("left {d} of {d} after the match\n", .{ left, text.len - out[0].?.end });
    try testing.expect(left + 3 >= text.len - out[0].?.end);

    var fixed: std.Io.Reader = .fixed("no match here");
    try testing.expectEqual(@as(?Span, null), try m.findReader(&fixed));
    var any: std.Io.Reader = .fixed("x=1");
    try testing.expect(try re.isMatchReader(&any));

    // A failing reader is an error, not a silent "no match".
    const Failing = struct {
        fn stream(_: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
            return error.ReadFailed;
        }
    };
    var fbuf: [8]u8 = undefined;
    var failing: std.Io.Reader = .{ .vtable = &.{ .stream = Failing.stream }, .buffer = &fbuf, .seek = 0, .end = 0 };
    try testing.expectError(error.ReadFailed, re.isMatchReader(&failing));
}

test "captures and names" {
    var re = try Regex.compile(testing.allocator, "(?P<y>\\d{4})-(\\d{2})(?:-(?<d>\\d{2}))?");
    defer re.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), re.groupCount());
    try testing.expectEqual(@as(?usize, 1), re.groupIndex("y"));
    try testing.expectEqual(@as(?usize, 3), re.groupIndex("d"));
    var m = try Matcher.init(testing.allocator, &re);
    defer m.deinit();
    var out: [4]?Span = undefined;
    const input = "on 2026-10 and";
    try testing.expect(m.captures(input, 0, &out));
    try testing.expectEqualStrings("2026-10", out[0].?.slice(input));
    try testing.expectEqualStrings("2026", out[1].?.slice(input));
    try testing.expectEqualStrings("10", out[2].?.slice(input));
    try testing.expectEqual(@as(?Span, null), out[3]);
}

test "iterator: non-overlapping, an empty match next to the previous is skipped" {
    var re = try Regex.compile(testing.allocator, "a*");
    defer re.deinit(testing.allocator);
    var m = try Matcher.init(testing.allocator, &re);
    defer m.deinit();
    var it = m.iterator("baaac");
    var got: [8]Span = undefined;
    var n: usize = 0;
    while (it.next()) |s| : (n += 1) got[n] = s;
    // Go: FindAllStringIndex("a*", "baaac") = [[0 0] [1 4] [5 5]]
    try testing.expectEqualSlices(Span, &.{ .{ .start = 0, .end = 0 }, .{ .start = 1, .end = 4 }, .{ .start = 5, .end = 5 } }, got[0..n]);
}

test "fullMatch takes any way through, comptimeCompile matches compile" {
    const re = comptime comptimeCompile("[0-9]+|[0-9]+x");
    try testing.expect(re.fullMatch("123x"));
    try testing.expect(re.fullMatch("123"));
    try testing.expect(!re.fullMatch("123y"));
    try testing.expect(!re.fullMatch(""));
    var rt = try Regex.compile(testing.allocator, "[0-9]+|[0-9]+x");
    defer rt.deinit(testing.allocator);
    try testing.expectEqualSlices(Inst, rt.insts, re.insts);
    try testing.expectEqualSlices(Range, rt.ranges, re.ranges);
}

test "syntax errors" {
    const bad = .{
        .{ "a**", error.InvalidNestedRepeat },
        .{ "*a", error.MissingRepeatArgument },
        .{ "a{1001}", error.InvalidRepeatSize },
        .{ "a{3,2}", error.InvalidRepeatSize },
        .{ "(a", error.MissingParen },
        .{ "a)", error.UnexpectedParen },
        .{ "[a", error.MissingBracket },
        .{ "[z-a]", error.InvalidCharRange },
        .{ "[[:foo:]]", error.InvalidCharClass },
        .{ "a\\", error.TrailingBackslash },
        .{ "\\1", error.InvalidEscape },
        .{ "\\y", error.InvalidEscape },
        .{ "(?P<>a)", error.InvalidNamedCapture },
        .{ "(?z)", error.InvalidPerlOp },
        .{ "\\p{Klingon}", error.InvalidUnicodeClass },
        .{ "\xff", error.InvalidUtf8 },
    };
    inline for (bad) |c| {
        errdefer std.debug.print("pattern {s}\n", .{c[0]});
        try testing.expectError(c[1], Regex.compile(testing.allocator, c[0]));
    }
    // A `{` that is not a repetition is a literal.
    try expectFind("a{,2}", "a{,2}", "a{,2}");
    try expectFind("a{", "a{", "a{");
}

test "linear time: the classic exponential backtracking case is instant" {
    var re = try Regex.compile(testing.allocator, "(a+)+$");
    defer re.deinit(testing.allocator);
    const input = "a" ** 5000 ++ "b";
    try testing.expect(!re.isMatch(input));
    try testing.expect((try re.find(testing.allocator, input)) == null);
}

test "invalid UTF-8 in the input reads as U+FFFD, one byte" {
    try expectFind("a.b", "a\xffb", "a\xffb");
    try expectFind("\\x{fffd}", "x\xfey", "\xfe");
}

test {
    _ = syntax;
    _ = @import("go_oracle_test.zig");
    _ = @import("fuzz_test.zig");
}

test "robustness: random patterns and inputs compile or refuse, and match, without a trap" {
    // A deterministic driver (seeded PRNG): metacharacter-dense byte strings,
    // invalid UTF-8 included. Every outcome is fine but a safety trap.
    const alphabet = "ab()[]{}|*+?.^$\\-,:<>=!PQEdDwWsSbBAzx0179iUms_\xc3\xa9\xff";
    var prng: std.Random.DefaultPrng = .init(0x7265676578);
    const rng = prng.random();
    var pat: [24]u8 = undefined;
    var input: [16]u8 = undefined;
    var compiled: usize = 0;
    for (0..20_000) |_| {
        const pl = rng.uintLessThan(usize, pat.len);
        for (pat[0..pl]) |*c| c.* = alphabet[rng.uintLessThan(usize, alphabet.len)];
        var re = Regex.compile(testing.allocator, pat[0..pl]) catch continue;
        defer re.deinit(testing.allocator);
        compiled += 1;
        var m = try Matcher.init(testing.allocator, &re);
        defer m.deinit();
        for (0..4) |_| {
            const il = rng.uintLessThan(usize, input.len);
            for (input[0..il]) |*c| c.* = "ab\n é\xff1_"[rng.uintLessThan(usize, 9)];
            const in = input[0..il];
            const any = re.isMatch(in);
            const s = m.find(in, 0);
            // The three entry points agree with one another.
            try testing.expectEqual(any, s != null);
            if (re.fullMatch(in)) try testing.expect(any);
            var it = m.iterator(in);
            var n: usize = 0;
            while (it.next()) |_| n += 1;
            try testing.expect(n <= in.len + 1);
            // The prefilter only skips: the same program without it agrees.
            var bare = re;
            bare.prefilter = .{};
            var bm = try Matcher.init(testing.allocator, &bare);
            defer bm.deinit();
            try testing.expectEqual(any, bare.isMatch(in));
            try testing.expectEqual(s, bm.find(in, 0));
            for (0..in.len + 1) |from| try testing.expectEqual(bm.find(in, from), m.find(in, from));
        }
    }
    try testing.expect(compiled > 2_000); // the driver reaches the matcher
}

test "prefilter: anchoring and first bytes worked out from the program" {
    const Case = struct { p: []const u8, anchored: bool, single: ?u8, first: bool };
    const cases = [_]Case{
        .{ .p = "^abc", .anchored = true, .single = 'a', .first = true },
        .{ .p = "\\Aa|\\Ab", .anchored = true, .single = null, .first = true },
        .{ .p = "^a|b", .anchored = false, .single = null, .first = true },
        .{ .p = "(?m)^a", .anchored = false, .single = 'a', .first = true },
        .{ .p = "#([0-9]+)", .anchored = false, .single = '#', .first = true },
        .{ .p = "\\bfoo", .anchored = false, .single = 'f', .first = true },
        .{ .p = "é", .anchored = false, .single = 0xc3, .first = true },
        .{ .p = "a*", .anchored = false, .single = null, .first = false }, // can be empty
        .{ .p = ".b", .anchored = false, .single = null, .first = false },
        .{ .p = "[^a]", .anchored = false, .single = null, .first = false }, // holds U+FFFD
    };
    for (cases) |c| {
        errdefer std.debug.print("/{s}/\n", .{c.p});
        var re = try Regex.compile(testing.allocator, c.p);
        defer re.deinit(testing.allocator);
        try testing.expectEqual(c.anchored, re.prefilter.anchored);
        try testing.expectEqual(c.single, re.prefilter.single);
        try testing.expectEqual(c.first, re.prefilter.first != null);
    }
    // An invalid byte before the candidate is skipped without desynchronising.
    try expectFind("é", "\xc3\xc3\xa9", "é");
    try expectFind("#([0-9]+)", "a#b#12", "#12");
    try expectFind("^a", "ba", null);
}

test "compile: a pattern past the stack builder's capacity takes the full one" {
    var re = try Regex.compile(testing.allocator, "a{600}");
    defer re.deinit(testing.allocator);
    try testing.expect(re.insts.len > small_capacity.insts);
    try testing.expect(re.fullMatch("a" ** 600));
    try testing.expectError(error.PatternTooLarge, Regex.compile(testing.allocator, "a{1000}b{1000}"));
}

test "deep nesting compiles (or is refused) on a 512 KiB thread stack" {
    const Run = struct {
        fn go(out: *[2]?anyerror) void {
            const deep = "(?:" ** (max_depth - 1) ++ "a*" ++ ")" ** (max_depth - 1);
            const deeper = "(?:" ** (max_depth + 1) ++ "a" ++ ")" ** (max_depth + 1);
            var b = std.heap.page_allocator.create(Builder) catch unreachable;
            defer std.heap.page_allocator.destroy(b);
            out[0] = if (b.compile(deep)) |_| null else |e| e;
            out[1] = if (b.compile(deeper)) |_| null else |e| e;
        }
    };
    var out: [2]?anyerror = .{ null, null };
    const t = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, Run.go, .{&out});
    t.join();
    try testing.expectEqual(@as(?anyerror, null), out[0]);
    try testing.expectEqual(@as(?anyerror, error.NestingDepth), out[1]);
}

test "nested counted repetitions multiply, as Go limits them — no compile-time blow-up" {
    try testing.expectError(error.InvalidRepeatSize, Regex.compile(testing.allocator, "(?:(?:(?:a{0}){1000}){1000}){1000}"));
    try testing.expectError(error.InvalidRepeatSize, Regex.compile(testing.allocator, "(?:a{2}|b{600}){2}"));
    var ok = try Regex.compile(testing.allocator, "(?:(?:a{0}){100}){10}");
    ok.deinit(testing.allocator);
}

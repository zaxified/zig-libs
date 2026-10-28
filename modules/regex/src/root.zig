// SPDX-License-Identifier: MIT

//! regex — RE2-syntax regular expressions in linear time, at parity with
//! Go's `regexp`.
//!
//! The grammar of Go's `regexp/syntax` (RE2): literals, `.`, classes
//! (`[a-z]`, `[^…]`, `\d\s\w`, `[[:alpha:]]`, Unicode `\pL`/`\p{Greek}`),
//! groups (capturing, named `(?P<n>…)`/`(?<n>…)`, non-capturing `(?:…)`),
//! alternation, greedy and lazy repetition up to `{1000}`, the flags
//! `i m s U`, and the empty-width assertions `^ $ \A \z \b \B`; or its POSIX
//! ERE grammar (`compilePosix`). Matching is a Pike VM over a Thompson NFA,
//! and for short texts a bit-state backtracker: each visits a (position,
//! instruction) at most once, so time is linear in pattern × input and no
//! pattern can make it explode (no backreferences or lookaround — RE2 leaves
//! them out for that reason). Leftmost-first semantics, as Go's `regexp` and
//! Perl, or leftmost-longest (`Regex.longest`, POSIX).
//!
//! Compiling needs no allocator: `comptimeCompile` builds the program at
//! compile time (a bad pattern is a compile error), `compile` at run time.
//! `isMatch` and `fullMatch` run in fixed stack scratch, with no allocator;
//! submatch positions (`Matcher`) take scratch sized by the program, once.
//! On top of a search: replace (`$1`, `${name}`), split, quote, literal
//! prefix, and matching from a `std.Io.Reader` in constant memory.
//!
//! Input is UTF-8 and matched per code point; an invalid byte reads as
//! U+FFFD, one byte wide (as Go). `(?i)` folds by Unicode's simple case
//! folding (`(?i)é` matches `É`).

const std = @import("std");
const syntax = @import("syntax.zig");
const replace = @import("replace.zig");
const teddy = @import("teddy.zig");

pub const meta = .{
    .doc = "RE2-syntax regular expressions at parity with Go regexp — linear time, comptime compile, alloc-free match",
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
    /// Rust grammar only: false reads the haystack as bytes that need not be
    /// UTF-8, as Rust's `regex::bytes::Regex` — `(?-u)` classes, `(?-u).`
    /// and `(?-u:\xNN)` match raw bytes, a Unicode class never matches an
    /// invalid byte, and an empty match may fall inside a code point. Such a
    /// `Regex` runs on the VMs only, and not through the `Reader` functions.
    utf8: bool = true,

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
    /// The program has an assertion: the DFAs tell positions apart by the
    /// code point before (`Dfa.Ctx`) only then. Not a prefilter: it changes
    /// what a state is, not what the search may skip.
    asserts: bool = true,
    /// The program has an assertion only the Rust grammar writes (CRLF lines,
    /// Unicode or start/end word boundaries): the lazy DFAs and the one-pass
    /// engine, whose contexts know ASCII only, step aside for the VMs.
    vm_only: bool = false,
    /// Compiled with `Options.utf8 = false` (bytes mode).
    bytes: bool = false,

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
        {
            const b = try gpa.create(syntax.Builder);
            defer gpa.destroy(b);
            if (compileWith(gpa, b, pattern, opts)) |re| return re else |e| if (e != error.PatternTooLarge) return e;
        }
        // Past `max_insts` (or the other documented tables): a program of up
        // to 65,534 instructions, compiled in ~2 MiB of heap scratch. Its
        // `isMatch` keeps to the stack up to `4 * max_insts`; past that the
        // `*Alloc` variants. The DFAs and the prefilter step aside.
        const big = try gpa.create(syntax.BuilderOf(syntax.big_capacity));
        defer gpa.destroy(big);
        return compileWith(gpa, big, pattern, opts);
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
        try b.compileSyntaxBytes(pattern, opts.syntax, !opts.utf8);
        const bytes = b.bytes;
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
        errdefer gpa.free(source);
        // Bytes mode: no prefilter (its sets are of code points' bytes); a
        // program past `max_insts`: none either (the analysis's scratch is
        // sized for that).
        const plain = !bytes and insts.len <= max_insts;
        var pf: Prefilter = if (plain) analyze(insts, ranges) else .{};
        if (plain) if (buildTeddy(&pf, insts, ranges)) |t| {
            const tp = try gpa.create(teddy.Teddy);
            tp.* = t;
            pf.teddy = tp;
        };
        return .{ .insts = insts, .ranges = ranges, .names = names, .owned = true, .prefilter = pf, .longest = opts.isLongest(), .source = source, .asserts = hasAsserts(insts), .vm_only = bytes or hasRustAsserts(insts), .bytes = bytes };
    }

    pub fn deinit(re: *Regex, gpa: std.mem.Allocator) void {
        if (re.owned) {
            gpa.free(re.insts);
            gpa.free(re.ranges);
            for (re.names) |n| gpa.free(n);
            gpa.free(re.names);
            gpa.free(re.source);
            if (re.prefilter.teddy) |t| gpa.destroy(@constCast(t));
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
    /// No allocator; scratch on the stack: a program of up to `max_insts`
    /// instructions as always, up to `4 * max_insts` in ~33 KiB of it (bytes
    /// mode: `max_insts`). A larger program (a pattern past `max_insts`,
    /// compiled on the heap) panics here: use `isMatchAlloc`.
    pub fn isMatch(re: *const Regex, input: []const u8) bool {
        return re.runSet(input, false);
    }

    /// Does the pattern match all of `input`? (Go: `^(?:re)$` without `(?m)`.)
    /// Any way through the pattern counts, not only the leftmost-first one.
    /// Scratch as `isMatch`.
    pub fn fullMatch(re: *const Regex, input: []const u8) bool {
        return re.runSet(input, true);
    }

    /// Where the first match to be found ends — the earliest end of any
    /// match, not the leftmost-first one's (Rust's `shortest_match`); null
    /// when nothing matches. Cheaper than a search with positions: no start
    /// is worked out. Runs on the set VM; scratch as `isMatch`.
    pub fn shortestMatch(re: *const Regex, input: []const u8) ?usize {
        if (re.bytes) return re.runSetBytesEnd(input, false);
        var t: SliceText = .{ .input = input };
        return re.runSetEnd(&t, false);
    }

    /// `isMatch` for a program of any size: scratch from `gpa` when it is
    /// past what `isMatch` keeps on the stack.
    pub fn isMatchAlloc(re: *const Regex, gpa: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error!bool {
        return (try re.endAlloc(gpa, input, false)) != null;
    }

    /// `fullMatch` for a program of any size (see `isMatchAlloc`).
    pub fn fullMatchAlloc(re: *const Regex, gpa: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error!bool {
        return (try re.endAlloc(gpa, input, true)) != null;
    }

    /// `shortestMatch` for a program of any size (see `isMatchAlloc`).
    pub fn shortestMatchAlloc(re: *const Regex, gpa: std.mem.Allocator, input: []const u8) std.mem.Allocator.Error!?usize {
        return re.endAlloc(gpa, input, false);
    }

    fn endAlloc(re: *const Regex, gpa: std.mem.Allocator, input: []const u8, full: bool) std.mem.Allocator.Error!?usize {
        const fits = re.insts.len <= @as(usize, if (re.bytes) max_insts else 4 * max_insts);
        if (fits) {
            if (full) return if (re.runSet(input, true)) input.len else null;
            return re.shortestMatch(input);
        }
        const n = re.insts.len;
        if (re.bytes) {
            var sets: [2]ByteSet = undefined;
            const block = try ByteSet.alloc(gpa, &sets, n);
            defer gpa.free(block);
            const stack = try gpa.alloc(u16, 2 * n);
            defer gpa.free(stack);
            return re.bytesLoop(input, full, &sets[0], &sets[1], stack);
        }
        var sets: [2]HeapSet = undefined;
        const block = try HeapSet.alloc(gpa, &sets, n);
        defer gpa.free(block);
        const stack = try gpa.alloc(u16, 2 * n);
        defer gpa.free(stack);
        var t: SliceText = .{ .input = input };
        return re.setLoop(&t, full, &sets[0], &sets[1], stack);
    }

    /// Go's `Expand`: `template` with `$1`, `${name}`, `$$` replaced from a
    /// match's `groups` (as `Matcher.captures` fills them) in `input`.
    pub fn expand(re: *const Regex, w: *std.Io.Writer, template: []const u8, input: []const u8, groups: []const ?Span) std.Io.Writer.Error!void {
        return replace.expand(re, w, template, input, groups);
    }

    /// Go's `LiteralPrefix`: writes the literal text every match begins with;
    /// true when that text is the whole pattern.
    pub fn literalPrefix(re: *const Regex, w: *std.Io.Writer) std.Io.Writer.Error!bool {
        // Bytes mode: its byte classes are no text; a program past
        // `4 * max_insts`: past the walk's scratch. The empty prefix holds.
        if (re.bytes or re.insts.len > 4 * max_insts) return false;
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
    /// Its scratch is on the stack, as `isMatch`'s: a program past
    /// `4 * max_insts` (compiled on the heap) panics here.
    pub fn isMatchReader(re: *const Regex, r: *std.Io.Reader) error{ReadFailed}!bool {
        std.debug.assert(!re.bytes); // bytes mode: slices only
        var t: ReaderText = .init(r);
        const found = re.runSetOn(&t, false);
        // A failure after the answer was settled does not change it.
        if (t.failed and !found) return error.ReadFailed;
        return found;
    }

    fn runSet(re: *const Regex, input: []const u8, full: bool) bool {
        if (re.bytes) return re.runSetBytes(input, full);
        if (re.vm_only) {
            var t: SliceText = .{ .input = input };
            return re.runSetOn(&t, full);
        }
        if (!full and re.prefilter.end_anchored) {
            if (re.prefilter.last) |set| {
                if (input.len == 0) return false;
                const c = input[input.len - 1];
                if (set[c >> 6] & (@as(u64, 1) << @truncate(c)) == 0) return false;
            }
            const pf = &re.prefilter;
            if (input.len < pf.tail_len) return false;
            for (pf.tail[0..pf.tail_len], 1..) |pair, i| {
                const c = input[input.len - i];
                if (c != pair[0] and c != pair[1]) return false;
            }
            if (re.runRevDfa(input, RevDfa.max_states)) |found| return found;
        }
        if (re.runDfa(input, full)) |found| return found;
        var t: SliceText = .{ .input = input };
        return re.runSetOn(&t, full);
    }

    /// `runSet` as a lazy DFA (`Dfa`) — null for a program too large for it.
    /// Each state is the set of instructions to follow from a position, and
    /// what the code point before it was, as far as an assertion can tell;
    /// a transition on an ASCII byte is worked out once and then looked up.
    /// `noinline`: its stack scratch is never live with `runSetOn`'s.
    noinline fn runDfa(re: *const Regex, input: []const u8, full: bool) ?bool {
        if (re.insts.len > Dfa.max_insts) return null;
        var d: Dfa = undefined;
        d.n = 0;
        const pf = &re.prefilter;
        // A thread may start at every position, not only the first.
        const restart = !full and !pf.anchored;
        const skip = restart and pf.first != null;
        const start: Dfa.Set = .{ 1, 0 };
        var s = d.intern(start, .ofIf(re.asserts, null), restart);
        var pos: usize = 0;
        while (true) {
            if (skip and d.idle[s]) {
                // No thread alive: jump to where a match can start.
                pos = pf.next(input, pos) orelse return false;
                s = d.intern(start, .ofIf(re.asserts, runeBefore(input, pos)), restart);
            }
            if (pos == input.len) return re.dfaAccepts(d.keys[s], d.ctxs[s]);
            const c = input[pos];
            if (c < 0x80) {
                const t = d.trans[s][c];
                if (t >= 2) {
                    s = t - 2;
                    pos += 1;
                    continue;
                }
                if (t == 1) return true;
            }
            const here = decode(input, pos);
            const next = re.dfaStep(d.keys[s], d.ctxs[s], here.cp.?, restart, full) orelse {
                if (c < 0x80) d.trans[s][c] = 1;
                return true;
            };
            if (next[0] == 0 and next[1] == 0) return false; // no thread left
            const ctx: Dfa.Ctx = .ofIf(re.asserts, here.cp);
            var cache = c < 0x80;
            const ns = d.find(next, ctx) orelse blk: {
                if (d.n == Dfa.max_states) {
                    // Full: start over; the current state is not needed again.
                    d.n = 0;
                    cache = false;
                }
                break :blk d.add(next, ctx, restart);
            };
            if (cache) d.trans[s][c] = ns + 2;
            pos += here.w;
            s = ns;
        }
    }

    /// `isMatch` for a pattern every match of which ends at the end of the
    /// text (`Prefilter.end_anchored`): a lazy DFA run backwards from the end,
    /// so a text whose tail cannot end a match is rejected without reading
    /// the rest (RE2's and Rust's reverse anchored search). A state is the
    /// set of consuming instructions from which the text after the position
    /// can be read to the match, and what the code point after the position
    /// is, as far as an assertion can tell. The search succeeds at the first
    /// position (going back) where the start reaches a member of that set.
    /// Null for a program too large for the DFA. `limit`: the states kept
    /// before the table is emptied (`RevDfa.max_states`; tests: fewer).
    noinline fn runRevDfa(re: *const Regex, input: []const u8, comptime limit: u8) ?bool {
        comptime std.debug.assert(limit >= 1 and limit <= RevDfa.max_states);
        if (re.insts.len > Dfa.max_insts) return null;
        var d: RevDfa = undefined;
        d.n = 0;
        var end: Dfa.Set = .{ 0, 0 };
        for (re.insts, 0..) |inst, pc| if (inst == .match) {
            end[pc >> 6] |= @as(u64, 1) << @truncate(pc);
        };
        const asserts = re.asserts;
        var s = d.add(end, .ofIf(asserts, null));
        var pos = input.len;
        while (true) {
            if (re.revAccepts(&d, s, if (asserts) runeBefore(input, pos) else ' ')) return true;
            if (pos == 0) return false;
            const here = decodeBefore(input, pos);
            const c = input[pos - 1];
            const ascii = here.w == 1 and c < 0x80;
            if (ascii) {
                const t = d.trans[s][c];
                if (t != 0) {
                    if (t == 1) return false; // no set member left
                    s = t - 2;
                    pos -= 1;
                    continue;
                }
            }
            const prev = re.revStep(d.keys[s], d.ctxs[s], here.cp.?);
            var cache = ascii;
            if (prev[0] == 0 and prev[1] == 0) {
                if (cache) d.trans[s][c] = 1;
                return false;
            }
            const ctx: Dfa.Ctx = .ofIf(asserts, here.cp);
            const ps = d.find(prev, ctx) orelse blk: {
                if (d.n == limit) {
                    // Full: start over; the current state is not needed again.
                    d.n = 0;
                    cache = false;
                }
                break :blk d.add(prev, ctx);
            };
            if (cache) d.trans[s][c] = ps + 2;
            pos -= here.w;
            s = ps;
        }
    }

    /// One backward step from set `k` (`ctx`: the code point after the
    /// position) over `cp`, the code point before it: the consuming
    /// instructions that take `cp` to a state reaching a member of `k`.
    fn revStep(re: *const Regex, k: Dfa.Set, ctx: Dfa.Ctx, cp: u21) Dfa.Set {
        var out: Dfa.Set = .{ 0, 0 };
        for (re.insts, 0..) |_, i| {
            const pc: u16 = @intCast(i);
            if (!re.consumes(pc, cp)) continue;
            var one: Dfa.Set = .{ 0, 0 };
            one[(pc + 1) >> 6] |= @as(u64, 1) << @truncate(pc + 1);
            var matched: bool = undefined;
            const cl = re.dfaClosure(one, cp, ctx.rep(), &matched);
            if (cl[0] & k[0] != 0 or cl[1] & k[1] != 0) out[pc >> 6] |= @as(u64, 1) << @truncate(pc);
        }
        return out;
    }

    /// Does the start, at a position after `prev`, reach a member of state
    /// `s`'s set? Cached per state and class of `prev`.
    fn revAccepts(re: *const Regex, d: *RevDfa, s: u8, prev: ?u21) bool {
        const pc = Dfa.Ctx.of(prev);
        const slot = &d.accepts[s][@backingInt(pc)];
        if (slot.* == .unknown) slot.* = if (re.revReaches(d.keys[s], d.ctxs[s], pc)) .yes else .no;
        return slot.* == .yes;
    }

    /// Does the start, at a position after a code point of class `prev`,
    /// reach a member of set `k` (`ctx`: the class of the code point after)?
    fn revReaches(re: *const Regex, k: Dfa.Set, ctx: Dfa.Ctx, prev: Dfa.Ctx) bool {
        var matched: bool = undefined;
        const cl = re.dfaClosure(.{ 1, 0 }, prev.rep(), ctx.rep(), &matched);
        return cl[0] & k[0] != 0 or cl[1] & k[1] != 0;
    }

    /// `noinline`: its ~6 KiB of stack scratch is paid only while it runs,
    /// never by a caller's frame that inlined it.
    inline fn runSetOn(re: *const Regex, text: anytype, full: bool) bool {
        return re.runSetEnd(text, full) != null;
    }

    /// `runSetOn`, giving where the first match to be seen ends (the
    /// earliest end of any match), or null.
    noinline fn runSetEnd(re: *const Regex, text: anytype, full: bool) ?usize {
        if (re.insts.len > max_insts) return re.runSetEndWide(text, full);
        // `undefined`, not `.{}`: a default-initialised StateSet is written
        // whole (~2 KiB each) on every call — measured as 85 % of `isMatch`.
        var lists: [2]StateSet = undefined;
        var stack: [2 * max_insts]u16 = undefined;
        return re.setLoop(text, full, &lists[0], &lists[1], &stack);
    }

    /// `runSetEnd` for a program past `max_insts`: up to `4 * max_insts` on
    /// the stack, else a panic (the caller should have used `isMatchAlloc`).
    noinline fn runSetEndWide(re: *const Regex, text: anytype, full: bool) ?usize {
        if (re.insts.len > 4 * max_insts) @panic("regex: a program this large needs isMatchAlloc / fullMatchAlloc / shortestMatchAlloc");
        var lists: [2]StateSetOf(4 * max_insts) = undefined;
        var stack: [8 * max_insts]u16 = undefined;
        return re.setLoop(text, full, &lists[0], &lists[1], &stack);
    }

    /// The set VM's loop over sets `cur0`/`nxt0` (fixed or heap).
    inline fn setLoop(re: *const Regex, text: anytype, full: bool, cur0: anytype, nxt0: @TypeOf(cur0), stack: []u16) ?usize {
        const words = (re.insts.len + 63) / 64;
        var cur = cur0;
        var nxt = nxt0;
        var pos: usize = 0;
        var prev: ?u21 = null;
        cur.clear(words);
        const pf = &re.prefilter;
        while (true) {
            if (!full and cur.n == 0) {
                // No thread alive: a match can only start where the prefilter allows.
                if (pf.anchored and pos != 0) return null;
                if (@TypeOf(text.*).can_skip and pf.first != null) {
                    pos = text.skip(pf, pos) orelse return null;
                    prev = text.before(pos);
                    // `seen` still holds the closure walked where the threads
                    // died (an assertion that failed there, say): stale here.
                    cur.clear(words);
                }
            }
            const here = text.at(pos);
            if ((!full and (!pf.anchored or pos == 0)) or pos == 0) re.closureSet(cur, 0, prev, here.cp, stack);
            // No thread left: anchored, nothing can start later; unanchored,
            // the next position starts a new one.
            if (cur.n == 0 and (full or here.cp == null)) return null;
            nxt.clear(words);
            const after = if (here.cp != null) text.at(pos + here.w) else here;
            for (cur.pcs[0..cur.n]) |pc| {
                switch (re.insts[pc]) {
                    .match => if (!full or here.cp == null) return pos,
                    else => if (here.cp) |cp| if (re.consumes(pc, cp))
                        re.closureSet(nxt, pc + 1, cp, after.cp, stack),
                }
            }
            if (here.cp == null) return null;
            pos += here.w;
            prev = here.cp;
            std.mem.swap(@TypeOf(cur), &cur, &nxt);
        }
    }

    /// The instructions a DFA state's set reaches without consuming input,
    /// at a position between `prev` and `next`: the consuming ones and the
    /// match. `matched`: the match is among them.
    fn dfaClosure(re: *const Regex, k: Dfa.Set, prev: ?u21, next: ?u21, matched: *bool) Dfa.Set {
        var seen: Dfa.Set = .{ 0, 0 };
        var out: Dfa.Set = .{ 0, 0 };
        var stack: [3 * Dfa.max_insts]u16 = undefined;
        var sp: usize = 0;
        for (k, 0..) |word, wi| {
            var w = word;
            while (w != 0) : (w &= w - 1) {
                stack[sp] = @intCast(wi * 64 + @ctz(w));
                sp += 1;
            }
        }
        matched.* = false;
        while (sp != 0) {
            sp -= 1;
            const pc = stack[sp];
            const bit = @as(u64, 1) << @truncate(pc);
            if (seen[pc >> 6] & bit != 0) continue;
            seen[pc >> 6] |= bit;
            switch (re.insts[pc]) {
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
                .assert => |a| if (assertHolds(a, prev, next)) {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .match => {
                    matched.* = true;
                    out[pc >> 6] |= bit;
                },
                .rune, .any, .any_not_nl => out[pc >> 6] |= bit,
            }
        }
        return out;
    }

    /// One DFA step from set `k` after `ctx`, over code point `cp`: the set
    /// for the position after it, or null when a match ends before `cp`
    /// (never in a full match, which must end at the end of the text).
    fn dfaStep(re: *const Regex, k: Dfa.Set, ctx: Dfa.Ctx, cp: u21, restart: bool, full: bool) ?Dfa.Set {
        var matched: bool = undefined;
        const cl = re.dfaClosure(k, ctx.rep(), cp, &matched);
        if (matched and !full) return null;
        var nk: Dfa.Set = .{ @intFromBool(restart), 0 };
        for (cl, 0..) |word, wi| {
            var w = word;
            while (w != 0) : (w &= w - 1) {
                const pc: u16 = @intCast(wi * 64 + @ctz(w));
                if (re.consumes(pc, cp)) {
                    // A consuming instruction is never last (the program ends in `match`).
                    std.debug.assert(pc + 1 < re.insts.len);
                    nk[(pc + 1) >> 6] |= @as(u64, 1) << @truncate(pc + 1);
                }
            }
        }
        return nk;
    }

    /// Does set `k` after `ctx` reach the match at the end of the text?
    fn dfaAccepts(re: *const Regex, k: Dfa.Set, ctx: Dfa.Ctx) bool {
        var matched: bool = undefined;
        _ = re.dfaClosure(k, ctx.rep(), null, &matched);
        return matched;
    }

    /// Add `pc0` and every state reachable from it without consuming input,
    /// at a position between `prev` and `next`.
    fn closureSet(re: *const Regex, set: anytype, pc0: u16, prev: ?u21, next: ?u21, stack: []u16) void {
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
                    if (@hasField(@TypeOf(set.*), "rem")) set.rem[set.n] = 0;
                    set.n += 1;
                },
            }
        }
    }

    /// Bytes mode: how many bytes instruction `pc` takes at `pos`, or null.
    /// A byte class (one with a range past `byte_base`) takes one raw byte;
    /// anything else one valid UTF-8 sequence (never an invalid byte).
    fn consumeBytes(re: *const Regex, pc: u16, input: []const u8, pos: usize) ?usize {
        if (pos >= input.len) return null;
        const c = input[pos];
        if (re.insts[pc] == .rune) {
            const r = re.insts[pc].rune;
            const rs = re.ranges[r.start..][0..r.len];
            if (rs.len != 0 and rs[rs.len - 1].hi >= syntax.byte_base) {
                const key: u21 = if (c < 0x80) c else syntax.byte_base + @as(u21, c);
                return if (inRanges(rs, key)) 1 else null;
            }
        }
        const d = decode(input, pos);
        if (d.w == 1 and c >= 0x80) return null; // invalid UTF-8
        return if (re.consumes(pc, d.cp.?)) d.w else null;
    }

    /// `runSet` in bytes mode: one step per byte; a thread that took a
    /// sequence of `w` bytes waits `w - 1` steps (`rem`) before its closure,
    /// as the states inside a UTF-8 automaton would.
    fn runSetBytes(re: *const Regex, input: []const u8, full: bool) bool {
        return re.runSetBytesEnd(input, full) != null;
    }

    noinline fn runSetBytesEnd(re: *const Regex, input: []const u8, full: bool) ?usize {
        if (re.insts.len > max_insts) @panic("regex: a bytes-mode program this large needs isMatchAlloc / fullMatchAlloc / shortestMatchAlloc");
        var storage: ByteSet.Fixed = undefined;
        var sets = storage.sets();
        var stack: [2 * max_insts]u16 = undefined;
        return re.bytesLoop(input, full, &sets[0], &sets[1], &stack);
    }

    fn bytesLoop(re: *const Regex, input: []const u8, full: bool, cur0: *ByteSet, nxt0: *ByteSet, stack: []u16) ?usize {
        var cur = cur0;
        var nxt = nxt0;
        cur.clear();
        var pos: usize = 0;
        while (true) {
            const at_end = pos >= input.len;
            if (!full or pos == 0) re.closureSet(cur, 0, bytesBefore(input, pos), bytesAt(input, pos), stack);
            if (cur.n == 0 and (full or at_end)) return null;
            nxt.clear();
            const q = pos + 1;
            for (cur.pcs[0..cur.n], cur.rem[0..cur.n]) |pc, rem| {
                if (rem != 0) {
                    if (rem == 1) re.closureSet(nxt, pc, bytesBefore(input, q), bytesAt(input, q), stack) else nxt.pending(pc, rem - 1);
                    continue;
                }
                if (re.insts[pc] == .match) {
                    if (!full or at_end) return pos;
                    continue;
                }
                const w = re.consumeBytes(pc, input, pos) orelse continue;
                if (w == 1) re.closureSet(nxt, pc + 1, bytesBefore(input, q), bytesAt(input, q), stack) else nxt.pending(pc + 1, @intCast(w - 1));
            }
            if (at_end) return null;
            pos = q;
            std.mem.swap(*ByteSet, &cur, &nxt);
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

/// Many patterns, one pass over the text: which of them match, each on its
/// own and anywhere (Rust's `RegexSet`, RE2's `RE2::Set`). The patterns are
/// compiled one by one and joined into one program — a chain of splits, one
/// branch per pattern, each keeping its own `match` — which a set of threads
/// runs once over the text, unanchored. No positions: ask a `Regex` for
/// those. The joined program is bounded by `4 * max_insts` (bytes mode:
/// `max_insts`): its scratch is on the stack.
pub const RegexSet = struct {
    insts: []const Inst,
    ranges: []const Range,
    /// The `match` instruction of each pattern, ascending.
    ends: []const u16,
    /// Compiled with `Options.utf8 = false`.
    bytes: bool,

    /// Compile `patterns` with `opts` (one bad pattern fails the set, with
    /// its error). The set owns its tables; `deinit` frees them.
    pub fn compile(gpa: std.mem.Allocator, patterns: []const []const u8, opts: Options) (Error || std.mem.Allocator.Error)!RegexSet {
        const res = try gpa.alloc(Regex, patterns.len);
        defer gpa.free(res);
        var done: usize = 0;
        defer for (res[0..done]) |*re| re.deinit(gpa);
        var n_insts: usize = patterns.len -| 1; // the splits
        var n_ranges: usize = 0;
        // Its runs keep their scratch on the stack (as `Regex.isMatch`):
        // refused as soon as the patterns so far are past it, not after
        // compiling every one (review 2026-10-28).
        const bytes = !opts.utf8 and opts.syntax == .rust;
        const cap: usize = if (bytes) max_insts else 4 * max_insts;
        for (patterns, res) |pat, *re| {
            re.* = try Regex.compileOptions(gpa, pat, opts);
            done += 1;
            n_insts += re.insts.len;
            n_ranges += re.ranges.len;
            if (n_insts > cap) return error.PatternTooLarge;
        }
        // A `rune` instruction indexes the joined range table with a u16:
        // a hundred `\pL` patterns are past it.
        if (n_ranges > std.math.maxInt(u16)) return error.PatternTooLarge;
        const insts = try gpa.alloc(Inst, n_insts);
        errdefer gpa.free(insts);
        const ranges = try gpa.alloc(Range, n_ranges);
        errdefer gpa.free(ranges);
        const ends = try gpa.alloc(u16, patterns.len);
        errdefer gpa.free(ends);
        var at: u16 = @intCast(patterns.len -| 1);
        var rat: u16 = 0;
        for (res, 0..) |*re, i| {
            if (i + 1 < res.len) {
                // Split i: pattern i, else the next split (or the last pattern).
                const next: u16 = if (i + 2 < res.len) @intCast(i + 1) else at + @as(u16, @intCast(re.insts.len));
                insts[i] = .{ .split = .{ .x = at, .y = next } };
            }
            for (re.insts, 0..) |inst, pc| {
                insts[at + pc] = switch (inst) {
                    .jmp => |t| .{ .jmp = t + at },
                    .split => |sp| .{ .split = .{ .x = sp.x + at, .y = sp.y + at } },
                    .rune => |r| .{ .rune = .{ .start = r.start + rat, .len = r.len } },
                    .match => blk: {
                        ends[i] = at + @as(u16, @intCast(pc));
                        break :blk .match;
                    },
                    else => inst,
                };
            }
            @memcpy(ranges[rat..][0..re.ranges.len], re.ranges);
            at += @intCast(re.insts.len);
            rat += @intCast(re.ranges.len);
        }
        return .{ .insts = insts, .ranges = ranges, .ends = ends, .bytes = bytes };
    }

    pub fn deinit(set: *RegexSet, gpa: std.mem.Allocator) void {
        gpa.free(set.insts);
        gpa.free(set.ranges);
        gpa.free(set.ends);
        set.* = undefined;
    }

    /// Does any pattern match `input`?
    pub fn isMatch(set: *const RegexSet, input: []const u8) bool {
        return set.run(input, null);
    }

    /// Which patterns match `input`: `out[i]` for pattern `i` (`out.len` is
    /// the pattern count). Whether any did.
    pub fn matches(set: *const RegexSet, input: []const u8, out: []bool) bool {
        std.debug.assert(out.len == set.ends.len);
        @memset(out, false);
        return set.run(input, out);
    }

    /// The joined program as a `Regex`, for its thread machinery.
    fn view(set: *const RegexSet) Regex {
        return .{ .insts = set.insts, .ranges = set.ranges, .names = &.{}, .bytes = set.bytes, .vm_only = true };
    }

    /// Which pattern `pc` (a `match`) ends.
    fn patternOf(set: *const RegexSet, pc: u16) usize {
        return std.sort.lowerBound(u16, set.ends, pc, struct {
            fn order(a: u16, b: u16) std.math.Order {
                return std.math.order(a, b);
            }
        }.order);
    }

    /// Mark the pattern that `pc` ends; true when the run can stop (any
    /// match will do, or every pattern has matched).
    fn hit(set: *const RegexSet, out: ?[]bool, found: *usize, pc: u16) bool {
        const o = out orelse return true;
        const p = set.patternOf(pc);
        if (!o[p]) {
            o[p] = true;
            found.* += 1;
        }
        return found.* == o.len;
    }

    fn run(set: *const RegexSet, input: []const u8, out: ?[]bool) bool {
        if (set.ends.len == 0) return false;
        const re = set.view();
        var found: usize = 0;
        if (set.bytes) return set.runBytes(&re, input, out, &found) or found != 0;
        if (re.insts.len > max_insts) {
            var wide: [2]StateSetOf(4 * max_insts) = undefined;
            var stack: [8 * max_insts]u16 = undefined;
            return set.runLoop(&re, input, out, &found, &wide[0], &wide[1], &stack);
        }
        var lists: [2]StateSet = undefined;
        var stack: [2 * max_insts]u16 = undefined;
        return set.runLoop(&re, input, out, &found, &lists[0], &lists[1], &stack);
    }

    inline fn runLoop(set: *const RegexSet, re: *const Regex, input: []const u8, out: ?[]bool, found: *usize, cur0: anytype, nxt0: @TypeOf(cur0), stack: []u16) bool {
        const words = (re.insts.len + 63) / 64;
        var cur = cur0;
        var nxt = nxt0;
        cur.clear(words);
        var pos: usize = 0;
        var prev: ?u21 = null;
        while (true) {
            const here = decode(input, pos);
            re.closureSet(cur, 0, prev, here.cp, stack);
            nxt.clear(words);
            const after = if (here.cp != null) decode(input, pos + here.w) else here;
            for (cur.pcs[0..cur.n]) |pc| {
                switch (re.insts[pc]) {
                    .match => if (set.hit(out, found, pc)) return true,
                    else => if (here.cp) |cp| if (re.consumes(pc, cp))
                        re.closureSet(nxt, pc + 1, cp, after.cp, stack),
                }
            }
            if (here.cp == null) return found.* != 0;
            pos += here.w;
            prev = here.cp;
            std.mem.swap(@TypeOf(cur), &cur, &nxt);
        }
    }

    /// `run` in bytes mode, as `Regex.runSetBytes`.
    noinline fn runBytes(set: *const RegexSet, re: *const Regex, input: []const u8, out: ?[]bool, found: *usize) bool {
        var storage: ByteSet.Fixed = undefined;
        var lists = storage.sets();
        var stack: [2 * max_insts]u16 = undefined;
        var cur: *ByteSet = &lists[0];
        var nxt: *ByteSet = &lists[1];
        cur.clear();
        var pos: usize = 0;
        while (true) {
            const at_end = pos >= input.len;
            re.closureSet(cur, 0, bytesBefore(input, pos), bytesAt(input, pos), &stack);
            nxt.clear();
            const q = pos + 1;
            for (cur.pcs[0..cur.n], cur.rem[0..cur.n]) |pc, rem| {
                if (rem != 0) {
                    if (rem == 1) re.closureSet(nxt, pc, bytesBefore(input, q), bytesAt(input, q), &stack) else nxt.pending(pc, rem - 1);
                    continue;
                }
                if (re.insts[pc] == .match) {
                    if (set.hit(out, found, pc)) return true;
                    continue;
                }
                const w = re.consumeBytes(pc, input, pos) orelse continue;
                if (w == 1) re.closureSet(nxt, pc + 1, bytesBefore(input, q), bytesAt(input, q), &stack) else nxt.pending(pc + 1, @intCast(w - 1));
            }
            if (at_end) return false;
            pos = q;
            std.mem.swap(*ByteSet, &cur, &nxt);
        }
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
        b.compileSyntaxBytes(pattern, opts.syntax, !opts.utf8) catch |e| @compileError("regex: \"" ++ pattern ++ "\": " ++ @errorName(e));
        const bytes = b.bytes;
        const insts = b.insts[0..b.ninsts].*;
        const ranges = b.ranges[0..b.nranges].*;
        var names: [b.ngroups][]const u8 = undefined;
        for (&names, b.names[0..b.ngroups]) |*slot, n| slot.* = n;
        const final_names = names;
        var pf: Prefilter = if (bytes) .{} else analyze(&insts, &ranges);
        if (!bytes) if (buildTeddy(&pf, &insts, &ranges)) |t| {
            const final_teddy = t;
            pf.teddy = &final_teddy;
        };
        const final_pf = pf;
        return .{ .insts = &insts, .ranges = &ranges, .names = &final_names, .prefilter = final_pf, .longest = opts.isLongest(), .source = pattern, .asserts = hasAsserts(&insts), .vm_only = bytes or hasRustAsserts(&insts), .bytes = bytes };
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
    // Any size: a pattern past `4 * max_insts` compiles (heap tier), and
    // `isMatch` would panic on it (review 2026-10-28).
    return re.isMatchAlloc(gpa, input);
}

/// A bit set over slices of words (the heap sets').
const SliceBits = struct {
    masks: []u64,

    fn isSet(b: SliceBits, i: usize) bool {
        return b.masks[i >> 6] & (@as(u64, 1) << @truncate(i)) != 0;
    }

    fn set(b: SliceBits, i: usize) void {
        b.masks[i >> 6] |= @as(u64, 1) << @truncate(i);
    }
};

/// The set VM's threads in bytes mode: also those inside a UTF-8 sequence,
/// `rem` bytes from its end (1..3), each (instruction, rem) once. Slices,
/// over `Fixed` (a program of up to `max_insts`, on the stack) or the heap.
const ByteSet = struct {
    pcs: []u16,
    rem: []u8,
    n: u32 = 0,
    seen: SliceBits,
    /// Instructions per `rem` row of `seen`.
    stride: usize,

    const Fixed = struct {
        pcs: [2][4 * max_insts]u16,
        rem: [2][4 * max_insts]u8,
        masks: [2][4 * max_insts / 64]u64,

        fn sets(f: *Fixed) [2]ByteSet {
            var out: [2]ByteSet = undefined;
            for (&out, 0..) |*b, i| b.* = .{ .pcs = &f.pcs[i], .rem = &f.rem[i], .seen = .{ .masks = &f.masks[i] }, .stride = max_insts };
            return out;
        }
    };

    /// Two sets for a program of `n` instructions, in one allocation (returned
    /// for the caller to free).
    fn alloc(gpa: std.mem.Allocator, out: *[2]ByteSet, n: usize) std.mem.Allocator.Error![]u64 {
        const words_seen = (4 * n + 63) / 64;
        const words_pcs = (4 * n * 2 + 7) / 8;
        const words_rem = (4 * n + 7) / 8;
        const per = words_seen + words_pcs + words_rem;
        const block = try gpa.alloc(u64, 2 * per);
        for (out, 0..) |*b, i| {
            const part = block[i * per ..][0..per];
            b.* = .{
                .seen = .{ .masks = part[0..words_seen] },
                .pcs = @as([*]u16, @ptrCast(part[words_seen..].ptr))[0 .. 4 * n],
                .rem = @as([*]u8, @ptrCast(part[words_seen + words_pcs ..].ptr))[0 .. 4 * n],
                .stride = n,
            };
        }
        return block;
    }

    fn clear(s: *ByteSet) void {
        s.n = 0;
        @memset(s.seen.masks, 0);
    }

    fn pending(s: *ByteSet, pc: u16, rem: u8) void {
        const key = @as(usize, rem) * s.stride + pc;
        if (s.seen.isSet(key)) return;
        s.seen.set(key);
        s.pcs[s.n] = pc;
        s.rem[s.n] = rem;
        s.n += 1;
    }
};

const StateSet = StateSetOf(max_insts);

fn StateSetOf(comptime cap: usize) type {
    return struct {
        pcs: [cap]u16,
        n: u16,
        seen: std.StaticBitSet(cap),

        /// Empty the set; only the first `words` of `seen` (the program's
        /// length) are ever looked at.
        fn clear(s: *@This(), words: usize) void {
            s.n = 0;
            @memset(s.seen.masks[0..words], 0);
        }
    };
}

/// `StateSet` on the heap, for a program of any size (`isMatchAlloc`).
const HeapSet = struct {
    pcs: []u16,
    n: u16 = 0,
    seen: SliceBits,

    fn alloc(gpa: std.mem.Allocator, out: *[2]HeapSet, n: usize) std.mem.Allocator.Error![]u64 {
        const words_seen = (n + 63) / 64;
        const words_pcs = (2 * n + 7) / 8;
        const per = words_seen + words_pcs;
        const block = try gpa.alloc(u64, 2 * per);
        for (out, 0..) |*h, i| {
            const part = block[i * per ..][0..per];
            h.* = .{ .seen = .{ .masks = part[0..words_seen] }, .pcs = @as([*]u16, @ptrCast(part[words_seen..].ptr))[0..n] };
        }
        return block;
    }

    fn clear(s: *HeapSet, words: usize) void {
        s.n = 0;
        @memset(s.seen.masks[0..words], 0);
    }
};

/// `Regex.runDfa`'s scratch, on the stack (~4.7 KiB): up to `max_states`
/// states of a program of up to `max_insts` instructions, and their
/// transitions on ASCII bytes. A full table is emptied and refilled.
const Dfa = struct {
    const max_insts = 128;
    const max_states = 32;
    /// One bit per instruction.
    const Set = [2]u64;

    /// What an assertion can tell of the code point before a position.
    const Ctx = enum(u8) {
        start,
        newline,
        word,
        other,

        fn of(cp: ?u21) Ctx {
            const c = cp orelse return .start;
            if (c == '\n') return .newline;
            return if (isWord(c)) .word else .other;
        }

        /// `of`, for a program with assertions; without, every position is
        /// one context (one state where there would be four).
        fn ofIf(asserts: bool, cp: ?u21) Ctx {
            return if (asserts) .of(cp) else .other;
        }

        /// A code point of this class, as `assertHolds` sees it.
        fn rep(ctx: Ctx) ?u21 {
            return switch (ctx) {
                .start => null,
                .newline => '\n',
                .word => 'a',
                .other => ' ',
            };
        }
    };

    keys: [max_states]Set,
    ctxs: [max_states]Ctx,
    /// The state's set is the start alone: no thread is alive.
    idle: [max_states]bool,
    n: u8,
    /// `trans[s][c]`: 0 not worked out yet, 1 a match ends before `c`,
    /// otherwise the next state + 2.
    trans: [max_states][128]u8,

    fn find(d: *const Dfa, k: Set, ctx: Ctx) ?u8 {
        for (d.keys[0..d.n], d.ctxs[0..d.n], 0..) |key, c, i| {
            if (key[0] == k[0] and key[1] == k[1] and c == ctx) return @intCast(i);
        }
        return null;
    }

    /// Add a state (the table has room).
    fn add(d: *Dfa, k: Set, ctx: Ctx, restart: bool) u8 {
        const i = d.n;
        d.keys[i] = k;
        d.ctxs[i] = ctx;
        d.idle[i] = restart and k[0] == 1 and k[1] == 0;
        @memset(&d.trans[i], 0);
        d.n += 1;
        return i;
    }

    fn intern(d: *Dfa, k: Set, ctx: Ctx, restart: bool) u8 {
        if (d.find(k, ctx)) |i| return i;
        if (d.n == max_states) d.n = 0;
        return d.add(k, ctx, restart);
    }
};

/// `Regex.runRevDfa`'s scratch, on the stack (~4.7 KiB): `Dfa`'s table, a
/// state's context being the code point AFTER its position, plus whether the
/// start reaches the state's set, per class of the code point before.
const RevDfa = struct {
    const max_states = Dfa.max_states;
    const Accept = enum(u8) { unknown, no, yes };

    keys: [max_states]Dfa.Set,
    ctxs: [max_states]Dfa.Ctx,
    accepts: [max_states][4]Accept,
    n: u8,
    /// `trans[s][c]`: 0 not worked out yet, 1 the set is empty, otherwise
    /// the state before `c` + 2.
    trans: [max_states][128]u8,

    fn find(d: *const RevDfa, k: Dfa.Set, ctx: Dfa.Ctx) ?u8 {
        for (d.keys[0..d.n], d.ctxs[0..d.n], 0..) |key, c, i| {
            if (key[0] == k[0] and key[1] == k[1] and c == ctx) return @intCast(i);
        }
        return null;
    }

    /// Add a state (the table has room).
    fn add(d: *RevDfa, k: Dfa.Set, ctx: Dfa.Ctx) u8 {
        const i = d.n;
        d.keys[i] = k;
        d.ctxs[i] = ctx;
        d.accepts[i] = @splat(.unknown);
        @memset(&d.trans[i], 0);
        d.n += 1;
        return i;
    }
};

/// `Matcher.find`'s lazy DFAs: the end of the leftmost-first match, without
/// captures, then (unless the program is anchored) its start by `rev`, run
/// backwards from the end (Rust's `regex` and RE2 search the same way). A
/// forward state is the
/// ordered list of instructions to follow from a position (threads in
/// priority order, as the Pike VM keeps them), what the code point before it
/// was as far as an assertion can tell, and whether a thread may still start
/// there. A step follows the empty transitions in the Pike VM's order, and a
/// match among them cuts every later thread: the leftmost-first cut. Kept in
/// the `Matcher` across calls, so a transition on an ASCII byte is worked out
/// once per `Matcher`; a full table is emptied and refilled.
const FindDfa = struct {
    /// Rows are premultiplied by 256 in a `u16` (`trans`).
    const max_states = 255;
    /// The low byte of a `trans` (and `Back.trans`) entry: bit 0 a match
    /// (forwards: a match ends before the byte; backwards: the start reaches
    /// the state's set), and the rare ones, tested together.
    const stop: u16 = 2;
    /// No thread left and none can start (forwards: the search is over);
    /// backwards, no way left. Always with `stop`.
    const dead_bit: u16 = 4;
    const dead: u16 = dead_bit | stop;
    const unknown: u16 = 8;
    /// Forwards (`Track`): a thread begins at the byte (`begin`), at the
    /// byte before it (`begin_in_seq`, out of a mid-sequence state: the code
    /// point began at its lead byte), or a thread that began here joins
    /// older ones (`join`).
    const begin: u16 = 16;
    const begin_in_seq: u16 = 32;
    const join: u16 = 64;
    const rare: u16 = stop | unknown | begin | begin_in_seq | join;
    const scan_give_up = 32;
    const Accept = enum(u8) { unknown, no, yes };
    /// `mid`: 0, or (for a state inside a two-byte UTF-8 sequence, see
    /// `midAfter`) the state before its lead byte + 1.
    const State = struct { off: u32, len: u16, ctx: Dfa.Ctx, restart: bool, eoi: Accept = .unknown, mid: u16 = 0 };
    /// The outcome of one step: the next state's list and whether a match
    /// ends before the code point.
    const Step = struct {
        n: usize,
        matched: bool,
        /// From a state with no thread, one begins at the code point.
        began: bool = false,
        /// From a state with threads, the start adds one (or matches).
        joined: bool = false,
    };

    /// Where the match `run` found began, read off its forward pass: the
    /// position of the last `begin`, as long as no thread that began later
    /// joined (`clean`). Every live thread then descends from that one start,
    /// so the leftmost-first match starts there — no backward pass (`start`).
    const Track = struct { origin: usize = no_end, clean: bool = true };
    const wide_slots = 1024;
    /// As `trans`, direct-mapped by state and code point (a collision only
    /// costs the step again); `rev` as `rev.trans` encodes them.
    const WideCaches = struct {
        fwd: [wide_slots]Wide = @splat(.empty),
        rev: [wide_slots]Wide = @splat(.empty),
    };
    /// `key`: (state + 1) << 21 | code point, 0 empty.
    const Wide = struct {
        key: u32,
        val: u16,
        const empty: Wide = .{ .key = 0, .val = 0 };

        fn keyOf(s: u16, cp: u21) u32 {
            return (@as(u32, s) + 1) << 21 | cp;
        }

        fn slot(key: u32) usize {
            return (key *% 0x9e3779b1) >> comptime (32 - std.math.log2_int(usize, wide_slots));
        }
    };

    gpa: std.mem.Allocator,
    /// The program has assertions: without, every context is one state.
    asserts: bool,
    /// With no thread alive, jump ahead with the prefilter: only when it is
    /// a fast scan (a literal, one byte, Teddy). A byte set is scanned byte
    /// by byte, slower than the DFA's own cached transitions over the gap
    /// (measured: 12 % of `\b\w+\b` over Czech text).
    skip_idle: bool,
    states: std.ArrayList(State) = .empty,
    /// `trans[s + 1][c]` (row 0 unused): 0 not worked out yet, otherwise
    /// (next state + 1) << 8 — the offset of its row, so the next lookup
    /// needs no multiply (Rust's premultiplied ids) — bit 1 set when that
    /// state has no thread, bit 2 when no thread can start there either
    /// (the search is over), bit 0 when a match ends before `c`. Over every
    /// byte: a two-byte UTF-8 sequence (Latin, Greek, Cyrillic) is two
    /// lookups through a mid-sequence state (`midAfter`), never a decode.
    trans: std.ArrayList([256]u16) = .empty,
    /// The states' lists, one after another.
    pcs: std.ArrayList(u16) = .empty,
    /// Open addressing (a power of two, over twice `max_states`): state + 1, 0 empty.
    table: [512]u16 = @splat(0),
    /// `idleAt`'s states per context, + 1 (0 not made yet).
    idle: [4]u16 = @splat(0),
    /// `anchoredAt`'s, the same way.
    anchored: [4]u16 = @splat(0),
    /// Transitions on code points of three and four bytes and on invalid
    /// bytes (`Wide`), made on the first such code point: a `Matcher` for
    /// one ASCII search does not pay for them (measured: 3× a short
    /// compile-and-match).
    wide: ?*WideCaches = null,
    /// `rev`'s first state (the match) per context after the end, + 1.
    rev_start: [4]u16 = @splat(0),
    /// Times the table was emptied (tests).
    flushes: usize = 0,
    /// Scans past an idle code point beyond ASCII that moved a block or
    /// more, minus those that did not; at `-scan_give_up` they stop.
    scan_score: i32 = 0,
    /// `span` reads the start off the forward pass (`Track`), and the
    /// transitions carry the bits for it; `joins` and `tracked` count
    /// against each other (`note`).
    track: bool = true,
    joins: usize = 0,
    tracked: usize = 0,
    flush_pending: bool = false,
    /// The backward DFA for the start (`start`), kept across calls too.
    rev: Back = .{},
    /// The states kept before the table is emptied (tests: fewer), and
    /// `rev`'s.
    limit: u16 = max_states,
    rev_limit: u16 = Back.max_states,
    /// The match instructions: `rev`'s first set.
    match_set: Dfa.Set,

    /// `start`'s backward DFA: `RevDfa`'s states (the set of consuming
    /// instructions from which the text after the position reads to the
    /// match), with `trans` rows over every byte as the forward one has,
    /// and mid-sequence states the same way — reading backwards, the one
    /// after a continuation byte (`midAfter`).
    const Back = struct {
        const max_states = 255;
        keys: std.ArrayList(Dfa.Set) = .empty,
        ctxs: std.ArrayList(Dfa.Ctx) = .empty,
        accepts: std.ArrayList([4]Accept) = .empty,
        /// As `State.mid`.
        mids: std.ArrayList(u16) = .empty,
        /// `trans[s + 1][c]` (row 0 unused), `c` the byte before the
        /// position: 0 not worked out yet, otherwise (state before `c` + 1)
        /// << 8, bit 1 set when no way is left (no state), bit 0 when the
        /// start reaches this state's set at the position.
        trans: std.ArrayList([256]u16) = .empty,

        fn len(r: *const Back) usize {
            return r.keys.items.len;
        }

        fn find(r: *const Back, k: Dfa.Set, ctx: Dfa.Ctx) ?u16 {
            for (r.keys.items, r.ctxs.items, r.mids.items, 0..) |key, c, mid, i| {
                if (mid == 0 and key[0] == k[0] and key[1] == k[1] and c == ctx) return @intCast(i);
            }
            return null;
        }

        /// Add a state (the caller checked the room).
        fn add(r: *Back, gpa: std.mem.Allocator, k: Dfa.Set, ctx: Dfa.Ctx, mid: u16) std.mem.Allocator.Error!u16 {
            try r.keys.ensureUnusedCapacity(gpa, 1);
            try r.ctxs.ensureUnusedCapacity(gpa, 1);
            try r.accepts.ensureUnusedCapacity(gpa, 1);
            try r.mids.ensureUnusedCapacity(gpa, 1);
            try r.trans.ensureUnusedCapacity(gpa, 2);
            const id: u16 = @intCast(r.keys.items.len);
            r.keys.appendAssumeCapacity(k);
            r.ctxs.appendAssumeCapacity(ctx);
            r.accepts.appendAssumeCapacity(@splat(.unknown));
            r.mids.appendAssumeCapacity(mid);
            if (r.trans.items.len == 0) r.trans.appendAssumeCapacity(@splat(unknown)); // row 0
            r.trans.appendAssumeCapacity(@splat(unknown));
            return id;
        }

        fn clear(r: *Back) void {
            r.keys.clearRetainingCapacity();
            r.ctxs.clearRetainingCapacity();
            r.accepts.clearRetainingCapacity();
            r.mids.clearRetainingCapacity();
            r.trans.clearRetainingCapacity();
        }

        fn deinit(r: *Back, gpa: std.mem.Allocator) void {
            r.keys.deinit(gpa);
            r.ctxs.deinit(gpa);
            r.accepts.deinit(gpa);
            r.mids.deinit(gpa);
            r.trans.deinit(gpa);
        }
    };

    fn init(gpa: std.mem.Allocator, re: *const Regex) FindDfa {
        var match_set: Dfa.Set = .{ 0, 0 };
        for (re.insts, 0..) |inst, pc| if (inst == .match) {
            match_set[pc >> 6] |= @as(u64, 1) << @truncate(pc);
        };
        const pf = &re.prefilter;
        const skip_idle = pf.first != null and (pf.lit_len >= 2 or pf.teddy != null or pf.single != null);
        return .{ .gpa = gpa, .asserts = re.asserts, .skip_idle = skip_idle, .match_set = match_set };
    }

    /// The start of the leftmost-first match from `from` that ends at
    /// `end`: the leftmost position from which some way through the program
    /// reads exactly to `end` (no match begins further left, so that is the
    /// one). Read backwards from `end` until no way is left.
    fn start(d: *FindDfa, re: *const Regex, input: []const u8, from: usize, end: usize) std.mem.Allocator.Error!usize {
        const r = &d.rev;
        // The class of the code point after `end` from its first byte, no
        // decode: past ASCII every one is U+FFFD's (`byte_ctx`).
        const end_ctx: Dfa.Ctx = if (!d.asserts) .other else if (end == input.len) .start else byte_ctx[input[end]];
        const first = &d.rev_start[@backingInt(end_ctx)];
        if (first.* == 0) {
            if (r.len() == d.rev_limit) d.revFlush();
            first.* = try r.add(d.gpa, d.match_set, end_ctx, 0) + 1;
        }
        var s = first.* - 1;
        var pos = end;
        var best = end;
        while (true) {
            // Cached transitions over the byte before `pos` until one is not.
            const flat: [*]const u16 = @ptrCast(r.trans.items.ptr);
            var row = (@as(usize, s) + 1) << 8;
            while (pos > from) {
                const t = flat[row + input[pos - 1]];
                // One test for the rare entries (Rust's tagged ids): fewer
                // branches in the loop, so less padding where the Intel JCC
                // erratum is mitigated.
                if (t & (dead | unknown) != 0) {
                    if (t & unknown != 0) break;
                    if (t & 1 != 0) best = pos;
                    return best; // no way left
                }
                if (t & 1 != 0) best = pos;
                row = t & ~@as(u16, 0xff);
                pos -= 1;
            }
            s = @intCast((row >> 8) - 1);
            const mid = r.mids.items[s];
            if (mid != 0) {
                // Read a continuation byte, and the one before it is no lead
                // worked out yet: back to the code point's end.
                s = mid - 1;
                pos += 1;
            }
            if (pos == from) {
                if (d.revAccepts(re, s, d.ctxBefore(input, pos))) best = pos;
                return best;
            }
            // The code point before `pos`: what the start would see before
            // it, and what the step reads.
            const c = input[pos - 1];
            const here: Decoded = if (c < 0x80) .{ .cp = c, .w = 1 } else decodeBefore(input, pos);
            const key = Wide.keyOf(s, here.cp.?);
            const wide = c >= 0x80 and here.w != 2;
            if (wide) wide: {
                const caches = d.wideCaches() catch break :wide;
                const w = caches.rev[Wide.slot(key)];
                if (w.key == key) {
                    if (w.val & 1 != 0) best = pos;
                    if (w.val & dead != 0) return best;
                    s = (w.val >> 8) - 1;
                    pos -= here.w;
                    continue;
                }
            }
            const ctx = d.ctxOf(here.cp);
            const acc = d.revAccepts(re, s, ctx);
            if (acc) best = pos;
            const acc_bit: u16 = @intFromBool(acc);
            const prev = re.revStep(r.keys.items[s], r.ctxs.items[s], here.cp.?);
            if (prev[0] == 0 and prev[1] == 0) {
                try d.revCache(s, input, pos, here, key, dead | acc_bit);
                return best;
            }
            var cache = true;
            const ps = r.find(prev, ctx) orelse blk: {
                if (r.len() == d.rev_limit) {
                    d.revFlush();
                    cache = false;
                }
                break :blk try r.add(d.gpa, prev, ctx, 0);
            };
            if (cache) try d.revCache(s, input, pos, here, key, (ps + 1) << 8 | acc_bit);
            pos -= here.w;
            s = ps;
        }
    }

    /// Remember `rev`'s transition `t` from `s` over `here`, the code point
    /// before `pos` (`key`: its `Wide` key): one entry for ASCII, two for a
    /// two-byte sequence (into the mid-sequence state, which takes the
    /// accept bit, then out of it over the lead byte), `Wide` otherwise.
    fn revCache(d: *FindDfa, s: u16, input: []const u8, pos: usize, here: Decoded, key: u32, t: u16) std.mem.Allocator.Error!void {
        const r = &d.rev;
        const c = input[pos - 1];
        if (c < 0x80) {
            r.trans.items[s + 1][c] = t;
        } else if (here.w == 2) {
            var into = r.trans.items[s + 1][c];
            if (into & unknown != 0) {
                if (r.len() == d.rev_limit) return; // no room: not cached
                const mid = try r.add(d.gpa, .{ 0, 0 }, .other, s + 1);
                into = (mid + 1) << 8 | (t & 1);
                r.trans.items[s + 1][c] = into;
            }
            r.trans.items[into >> 8][input[pos - 2]] = t & ~@as(u16, 1);
        } else if (d.wide) |w| w.rev[Wide.slot(key)] = .{ .key = key, .val = t };
    }

    /// `rev` is full: empty it, and what remembers its states.
    fn revFlush(d: *FindDfa) void {
        d.rev.clear();
        if (d.wide) |w| w.rev = @splat(.empty);
        d.rev_start = @splat(0);
    }

    /// `Regex.revReaches` for `rev`'s state `s`, cached, and the class of the
    /// code point before the position already worked out.
    inline fn revAccepts(d: *FindDfa, re: *const Regex, s: u16, ctx: Dfa.Ctx) bool {
        const a = &d.rev.accepts.items[s][@backingInt(ctx)];
        if (a.* == .unknown) a.* = if (re.revReaches(d.rev.keys.items[s], d.rev.ctxs.items[s], ctx)) .yes else .no;
        return a.* == .yes;
    }

    fn deinit(d: *FindDfa) void {
        if (d.wide) |w| d.gpa.destroy(w);
        d.rev.deinit(d.gpa);
        d.states.deinit(d.gpa);
        d.trans.deinit(d.gpa);
        d.pcs.deinit(d.gpa);
    }

    /// The end of the leftmost-first match from `from`, which is 0 for an
    /// anchored program (`anchored`: no thread starts later).
    /// `reach`: where the search stopped reading.
    const no_end = std.math.maxInt(usize);

    fn run(d: *FindDfa, re: *const Regex, input: []const u8, from: usize, anchored: bool, reach: *usize, track: *Track) std.mem.Allocator.Error!?usize {
        if (d.flush_pending) {
            d.flush();
            d.flush_pending = false;
        }
        // The first state, remembered per context: the idle one, or a
        // thread at the start alone.
        var s = if (anchored) try d.anchoredAt(input, from) else try d.idleAt(input, from);
        // `no_end` for none: an optional costs a flag register and a
        // second cmov per byte in the loop.
        var end: usize = no_end;
        var pos = from;
        defer reach.* = pos;
        const pf = &re.prefilter;
        while (true) {
            const st = d.states.items[s];
            if (st.len == 0) {
                if (!st.restart) return if (end == no_end) null else end; // no thread left
                if (d.skip_idle) {
                    // No thread alive, none matched yet: jump to where one can start.
                    pos = pf.next(input, pos) orelse return null;
                    s = try d.idleAt(input, pos);
                }
            }
            // Cached transitions until one leads to a state the loop above
            // must see (bit 1: no thread left, or idle with `skip_idle`).
            const flat: [*]const u16 = @ptrCast(d.trans.items.ptr);
            var row = (@as(usize, s) + 1) << 8;
            const stopped = while (pos < input.len) {
                const t = flat[row + input[pos]];
                if (t & 1 != 0) end = pos;
                // One test for the rare entries, as in `start`.
                if (t & rare != 0) {
                    if (t & unknown != 0) break false;
                    if (t & (begin | begin_in_seq | join) != 0) d.note(track, t, pos);
                    row = t & ~@as(u16, 0xff);
                    pos += 1;
                    if (t & stop == 0) continue;
                    if (t & dead_bit != 0) return if (end == no_end) null else end; // no thread left
                    break true;
                }
                row = t & ~@as(u16, 0xff);
                pos += 1;
            } else blk: {
                const last: u16 = @intCast((row >> 8) - 1);
                if (d.states.items[last].mid == 0) {
                    if (d.accepts(re, last)) {
                        end = pos;
                        track.clean = false; // the start's empty match, maybe
                    }
                    return if (end == no_end) null else end;
                }
                break :blk false; // a lead byte last: U+FFFD, below
            };
            s = @intCast((row >> 8) - 1);
            if (stopped) continue;
            const mid = d.states.items[s].mid;
            if (mid != 0) {
                // Read a lead byte, and the byte after it is not worked out
                // yet (or ends no sequence): back to the code point's start.
                s = mid - 1;
                pos -= 1;
            }
            const c = input[pos];
            const idle = d.states.items[s].len == 0 and d.states.items[s].restart;
            const no_start = if (pf.first) |set| set[c >> 6] & (@as(u64, 1) << @truncate(c)) == 0 else false;
            if (c >= 0x80 and idle and no_start and d.scan_score > -scan_give_up) {
                // Idle at a code point past ASCII that cannot start a match:
                // the scan for a first byte moves past `pos`, over long gaps
                // faster than the cached steps (Czech text between `[0-9]+`
                // matches: 0.8 against 1.6 ms). Over short ones the call is
                // the cost (`\b\w+\b`, where each accented letter ends a
                // match): once most scans moved less than a block, the
                // steps over the bytes are cached instead (`midAfter`).
                const to = pf.next(input, pos) orelse return null;
                d.scan_score += if (to - pos >= 32) 1 else -1;
                pos = to;
                s = try d.idleAt(input, pos);
                continue;
            }
            const here = decode(input, pos);
            const key = Wide.keyOf(s, here.cp.?);
            if (c >= 0x80 and here.w != 2) {
                const w = (try d.wideCaches()).fwd[Wide.slot(key)];
                if (w.key == key) {
                    if (w.val & 1 != 0) end = pos;
                    if (w.val & (begin | join) != 0) d.note(track, w.val, pos);
                    s = (w.val >> 8) - 1;
                    pos += here.w;
                    continue;
                }
            }
            const restart = d.states.items[s].restart;
            var next: [Dfa.max_insts]u16 = undefined;
            const r = d.step(re, s, here.cp.?, &next);
            if (r.matched) end = pos;
            const tracked: u16 = if (!d.track) 0 else if (r.began) begin else if (r.joined) join else 0;
            if (tracked != 0) d.note(track, tracked, pos);
            const ns_restart = restart and !r.matched;
            const ns = try d.intern(next[0..r.n], d.ctxOf(here.cp), ns_restart);
            if (!ns.flushed) {
                // Bit `stop`: no thread left, and none starts here either
                // (`dead`) or `skip_idle` jumps ahead.
                const flags: u16 = if (r.n != 0) 0 else if (!ns_restart) dead else if (d.skip_idle) stop else 0;
                const t = (@as(u16, ns.id) + 1) << 8 | flags | tracked | @intFromBool(r.matched);
                if (c < 0x80) {
                    d.trans.items[s + 1][c] = t;
                } else if (here.w == 2) {
                    // The match bit on the lead byte: whether a match ends
                    // before a code point past ASCII does not depend on which
                    // (the assertions see each as U+FFFD, `runeBefore`); a
                    // begin read out of the mid-sequence state is a byte late.
                    const out = (t & ~(@as(u16, 1) | begin)) | (if (t & begin != 0) begin_in_seq else 0);
                    if (try d.midAfter(s, c, r.matched)) |m| d.trans.items[m + 1][input[pos + 1]] = out;
                } else d.wide.?.fwd[Wide.slot(key)] = .{ .key = key, .val = t };
            }
            s = ns.id;
            pos += here.w;
        }
    }

    /// The mid-sequence state that `s` reaches over the lead byte `c` of a
    /// two-byte sequence, made if new; null when the table has no room (it
    /// is emptied only by `intern`, which would lose `s`). Its row holds
    /// the transitions over the continuation bytes, worked out as they come;
    /// any other byte, or the end of the text, finds 0 there and `run` reads
    /// the code point again from `s` (an invalid sequence: U+FFFD).
    fn midAfter(d: *FindDfa, s: u16, c: u8, matched: bool) std.mem.Allocator.Error!?u16 {
        const into = d.trans.items[s + 1][c];
        if (into & unknown == 0) return (into >> 8) - 1;
        if (d.states.items.len == d.limit) return null;
        try d.states.ensureUnusedCapacity(d.gpa, 1);
        try d.trans.ensureUnusedCapacity(d.gpa, 1);
        const id: u16 = @intCast(d.states.items.len);
        d.states.appendAssumeCapacity(.{ .off = 0, .len = 0, .ctx = .other, .restart = false, .mid = s + 1 });
        d.trans.appendAssumeCapacity(@splat(unknown));
        d.trans.items[s + 1][c] = (id + 1) << 8 | @intFromBool(matched);
        return id;
    }

    /// The leftmost-first match from `from` of an unanchored program: `run`
    /// and `start` in one frame (a find-all over short matches pays their
    /// calls once per match).
    noinline fn span(d: *FindDfa, re: *const Regex, input: []const u8, from: usize) std.mem.Allocator.Error!?Span {
        var reach: usize = undefined;
        var track: Track = .{};
        const end = (try @call(.always_inline, run, .{ d, re, input, from, false, &reach, &track })) orelse return null;
        if (d.track and track.clean and track.origin != no_end) {
            std.debug.assert(track.origin <= end);
            d.tracked += 1;
            return .{ .start = track.origin, .end = end };
        }
        return .{ .start = try @call(.always_inline, start, .{ d, re, input, from, end }), .end = end };
    }

    /// `run` read a transition with `begin`, `begin_in_seq` or `join` at
    /// `pos`. Joins that outnumber the matches tracked (and 32 of them) end
    /// the tracking: their transitions leave the loop every time, so the
    /// table is emptied and made again without the bits.
    fn note(d: *FindDfa, track: *Track, t: u16, pos: usize) void {
        if (t & (begin | begin_in_seq) != 0) {
            // From a state with no thread: every older one is dead.
            track.origin = if (t & begin != 0) pos else pos - 1;
            track.clean = true;
        }
        if (t & join != 0) {
            track.clean = false;
            d.joins += 1;
            if (d.track and d.joins > 32 and d.joins > d.tracked) {
                // Emptied at the next `run`: here the loop still reads it.
                d.track = false;
                d.flush_pending = true;
            }
        }
    }

    /// The state with no thread and a start pending at `pos`, one per
    /// context, remembered (the prefilter lands there once per match).
    fn idleAt(d: *FindDfa, input: []const u8, pos: usize) std.mem.Allocator.Error!u16 {
        const ctx = d.ctxBefore(input, pos);
        const slot = &d.idle[@backingInt(ctx)];
        if (slot.* == 0) slot.* = (try d.intern(&.{}, ctx, true)).id + 1;
        return slot.* - 1;
    }

    fn wideCaches(d: *FindDfa) std.mem.Allocator.Error!*WideCaches {
        if (d.wide) |w| return w;
        const w = try d.gpa.create(WideCaches);
        w.* = .{};
        d.wide = w;
        return w;
    }

    /// The state with a thread at the start alone at `pos`, per context.
    fn anchoredAt(d: *FindDfa, input: []const u8, pos: usize) std.mem.Allocator.Error!u16 {
        const ctx = d.ctxBefore(input, pos);
        const slot = &d.anchored[@backingInt(ctx)];
        if (slot.* == 0) slot.* = (try d.intern(&.{0}, ctx, false)).id + 1;
        return slot.* - 1;
    }

    /// `ctxOf` the code point before `pos`, decoded only when it matters.
    fn ctxBefore(d: *const FindDfa, input: []const u8, pos: usize) Dfa.Ctx {
        if (!d.asserts) return .other;
        return if (pos == 0) .start else byte_ctx[input[pos - 1]];
    }

    /// `Dfa.Ctx.of` the code point a byte ends (past ASCII: not a word
    /// character, as `runeBefore` reads it), without branches.
    const byte_ctx: [256]Dfa.Ctx = blk: {
        var t: [256]Dfa.Ctx = undefined;
        for (&t, 0..) |*x, c| x.* = .of(if (c < 0x80) c else 0xfffd);
        break :blk t;
    };

    fn ctxOf(d: *const FindDfa, cp: ?u21) Dfa.Ctx {
        return if (d.asserts) .of(cp) else .other;
    }

    /// One step from state `s` over `cp` (see the type's comment); the next
    /// list goes to `out`.
    fn step(d: *const FindDfa, re: *const Regex, s: u16, cp: u21, out: *[Dfa.max_insts]u16) Step {
        const st = d.states.items[s];
        var seen: Dfa.Set = .{ 0, 0 };
        var n: usize = 0;
        const list = d.pcs.items[st.off..][0..st.len];
        for (0..list.len + @intFromBool(st.restart)) |i| {
            const pc0: u16 = if (i < list.len) list[i] else 0; // a thread starting here comes last
            const before = n;
            const hit = closure(re, &seen, pc0, st.ctx.rep(), cp, cp, out, &n);
            // The start's own threads, the ones not merged into older ones;
            // an empty match from no thread counts as a join (its start is
            // the position, not a `begin`).
            const joined = i == list.len and (n > before or hit);
            if (hit) return .{ .n = n, .matched = true, .joined = joined };
            if (joined) return .{ .n = n, .matched = false, .began = list.len == 0, .joined = list.len != 0 };
        }
        return .{ .n = n, .matched = false };
    }

    /// Does state `s` reach the match at the end of the text?
    fn accepts(d: *FindDfa, re: *const Regex, s: u16) bool {
        const st = &d.states.items[s];
        if (st.eoi == .unknown) {
            var seen: Dfa.Set = .{ 0, 0 };
            var n: usize = 0;
            var out: [Dfa.max_insts]u16 = undefined;
            var found = false;
            const list = d.pcs.items[st.off..][0..st.len];
            for (0..list.len + @intFromBool(st.restart)) |i| {
                const pc0: u16 = if (i < list.len) list[i] else 0;
                if (closure(re, &seen, pc0, st.ctx.rep(), null, 0, &out, &n)) {
                    found = true;
                    break;
                }
            }
            st.eoi = if (found) .yes else .no;
        }
        return st.eoi == .yes;
    }

    /// Follow the empty transitions from `pc0` at a position between `prev`
    /// and `next`, in `Matcher.addThread`'s order, skipping what `seen`
    /// holds: a consuming instruction that takes `cp` (none when `next` is
    /// null) appends the one after it to `out`; true at the match.
    fn closure(re: *const Regex, seen: *Dfa.Set, pc0: u16, prev: ?u21, next: ?u21, cp: u21, out: *[Dfa.max_insts]u16, n: *usize) bool {
        var stack: [2 * Dfa.max_insts + 1]u16 = undefined;
        stack[0] = pc0;
        var sp: usize = 1;
        while (sp != 0) {
            sp -= 1;
            const pc = stack[sp];
            const bit = @as(u64, 1) << @truncate(pc);
            if (seen[pc >> 6] & bit != 0) continue;
            seen[pc >> 6] |= bit;
            switch (re.insts[pc]) {
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
                .assert => |a| if (assertHolds(a, prev, next)) {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .match => return true,
                .rune, .any, .any_not_nl => if (next != null and re.consumes(pc, cp)) {
                    out[n.*] = pc + 1;
                    n.* += 1;
                },
            }
        }
        return false;
    }

    fn hash(list: []const u16, ctx: Dfa.Ctx, restart: bool) u32 {
        var h: u32 = 0x811c9dc5 ^ (@as(u32, @backingInt(ctx)) << 1 | @intFromBool(restart));
        for (list) |pc| h = (h ^ pc) *% 0x01000193;
        return h ^ (h >> 15);
    }

    /// Empty the forward table and what remembers its states.
    fn flush(d: *FindDfa) void {
        d.states.clearRetainingCapacity();
        d.trans.clearRetainingCapacity();
        d.pcs.clearRetainingCapacity();
        d.table = @splat(0);
        d.idle = @splat(0);
        d.anchored = @splat(0);
        if (d.wide) |w| w.fwd = @splat(.empty);
        d.flushes += 1;
    }

    /// The state for (`list`, `ctx`, `restart`), added if new; `flushed`:
    /// the table was full and emptied first, every earlier id is gone.
    fn intern(d: *FindDfa, list: []const u16, ctx: Dfa.Ctx, restart: bool) std.mem.Allocator.Error!struct { id: u16, flushed: bool } {
        const mask = d.table.len - 1;
        var i = hash(list, ctx, restart) & mask;
        while (d.table[i] != 0) : (i = (i + 1) & mask) {
            const id = d.table[i] - 1;
            const st = d.states.items[id];
            if (st.ctx == ctx and st.restart == restart and std.mem.eql(u16, d.pcs.items[st.off..][0..st.len], list)) return .{ .id = id, .flushed = false };
        }
        var flushed = false;
        if (d.states.items.len == d.limit) {
            d.flush();
            flushed = true;
            i = hash(list, ctx, restart) & mask;
        }
        const id: u16 = @intCast(d.states.items.len);
        comptime std.debug.assert(max_states << 8 <= std.math.maxInt(u16));
        comptime std.debug.assert(std.math.isPowerOfTwo(d.table.len) and d.table.len > 2 * max_states);
        try d.states.ensureUnusedCapacity(d.gpa, 1);
        try d.trans.ensureUnusedCapacity(d.gpa, 2);
        try d.pcs.appendSlice(d.gpa, list);
        d.states.appendAssumeCapacity(.{ .off = @intCast(d.pcs.items.len - list.len), .len = @intCast(list.len), .ctx = ctx, .restart = restart });
        if (d.trans.items.len == 0) d.trans.appendAssumeCapacity(@splat(unknown)); // row 0
        d.trans.appendAssumeCapacity(@splat(unknown));
        d.table[i] = id + 1;
        return .{ .id = id, .flushed = flushed };
    }
};

/// `captures` for a one-pass program (RE2's and Rust's one-pass engine):
/// one where, read anchored, the next code point always picks at most one
/// way on. Then the search is one thread whose captures are written in
/// place — no per-thread copies (Pike VM), no visited bits or pending
/// branches (backtracker). A root is where the thread stands before reading
/// (instruction 0, or just after a consuming one); its closure, in priority
/// order, gives the ways out (`Edge`: the consuming instruction, the slots
/// set and the assertions passed on the way) and the match, if one is on the
/// way. One-pass: the ways out of each root consume disjoint sets. A way
/// below the match is cut (leftmost-first); a match below a way is pending —
/// the thread goes on, and the last match passed is the answer when it dies.
const OnePass = struct {
    /// Slots the engine carries (16 groups): a step's fit one word.
    const max_slots = 32;
    const match_bit = 56;
    /// A way out, as `step` packs it: the root it leads to as the offset of
    /// its `trans` row (bits 0–15, root × 128: the next lookup takes no
    /// shift or multiply, the loop's dependency chain is the load alone;
    /// never 0, no edge leads back to the start), the slots set on the way
    /// (16–47), the assertions passed (48–53, by `Assert` value), and bit
    /// `match_bit` when a match is on the way from that root (the loop reads
    /// the root only then). 0: none.
    const Edge = struct { slots: u32, next: u16, pc: u16, asserts: u8, step: u64 = 0 };
    const Root = struct {
        /// Its edges: `edges[first..][0..len]`.
        first: u16,
        len: u16,
        /// A match is on the way: the slots and assertions on the way to it.
        has_match: bool,
        match_asserts: u8,
        match_slots: u32,
    };
    const Match = struct { slots: u32, asserts: u8 };

    gpa: std.mem.Allocator,
    roots: std.ArrayList(Root),
    /// Per root, per ASCII byte: the step that reads it (one load per byte:
    /// the step is the whole transition, as Rust's one-pass table).
    trans: std.ArrayList([128]u64),
    edges: std.ArrayList(Edge),

    /// The engine for `re`, or null: not one-pass, or no memory.
    fn make(gpa: std.mem.Allocator, re: *const Regex) ?*OnePass {
        const n = re.insts.len;
        const k = re.names.len * 2;
        if (n > Dfa.max_insts or k > max_slots) return null;
        var roots: std.ArrayList(Root) = .empty;
        var edges: std.ArrayList(Edge) = .empty;
        var trans: std.ArrayList([128]u64) = .empty;
        var root_pcs: [Dfa.max_insts + 1]u16 = undefined;
        // pc → its root + 1 (0: none yet).
        var root_of: [Dfa.max_insts + 1]u16 = @splat(0);
        const ok = blk: {
            root_pcs[0] = 0;
            root_of[0] = 1;
            var nroots: usize = 1;
            var r: usize = 0;
            while (r < nroots) : (r += 1) {
                const first = edges.items.len;
                const match = closure(re, root_pcs[r], k, gpa, &edges) catch break :blk false;
                const out = edges.items[first..];
                for (out, 0..) |*e, i| {
                    for (out[0..i]) |o| if (overlap(re, o.pc, e.pc)) break :blk false;
                    const next = e.pc + 1;
                    if (root_of[next] == 0) {
                        root_pcs[nroots] = next;
                        nroots += 1;
                        root_of[next] = @intCast(nroots);
                    }
                    e.next = root_of[next] - 1;
                }
                const mt: Match = match orelse .{ .slots = 0, .asserts = 0 };
                roots.append(gpa, .{
                    .first = @intCast(first),
                    .len = @intCast(out.len),
                    .has_match = match != null,
                    .match_asserts = mt.asserts,
                    .match_slots = mt.slots,
                }) catch break :blk false;
            }
            // The steps, once every root's match is known.
            for (edges.items) |*e| {
                const m: u64 = @intFromBool(roots.items[e.next].has_match);
                e.step = m << match_bit | @as(u64, e.asserts) << 48 | @as(u64, e.slots) << 16 | @as(u64, e.next) << 7;
            }
            trans.ensureTotalCapacityPrecise(gpa, roots.items.len) catch break :blk false;
            for (roots.items) |root| {
                const row = trans.addOneAssumeCapacity();
                row.* = @splat(0);
                for (row, 0..) |*slot, c| for (edges.items[root.first..][0..root.len]) |e| {
                    if (re.consumes(e.pc, @intCast(c))) slot.* = e.step;
                };
            }
            break :blk true;
        };
        const op: ?*OnePass = if (ok) gpa.create(OnePass) catch null else null;
        const p = op orelse {
            roots.deinit(gpa);
            edges.deinit(gpa);
            trans.deinit(gpa);
            return null;
        };
        p.* = .{ .gpa = gpa, .roots = roots, .trans = trans, .edges = edges };
        return p;
    }

    const NotOnePass = error{NotOnePass} || std.mem.Allocator.Error;

    /// Append the edges out of `pc0` to `edges`, in priority order (the Pike
    /// VM's `addThread` walk); return the match, when one is on the way. A
    /// state first reached past an assertion, then again, is not one-pass:
    /// whether the first way gets there depends on the text, and when it
    /// does not, the second way does. So is a way below a match past an
    /// assertion: whether the match cuts it depends on the text.
    fn closure(re: *const Regex, pc0: u16, k: usize, gpa: std.mem.Allocator, edges: *std.ArrayList(Edge)) NotOnePass!?Match {
        const Item = struct { pc: u16, slots: u32, asserts: u8 };
        // 0 unseen, 1 seen, 2 seen past an assertion.
        var seen: [Dfa.max_insts]u8 = @splat(0);
        var stack: [2 * Dfa.max_insts]Item = undefined;
        var sp: usize = 1;
        stack[0] = .{ .pc = pc0, .slots = 0, .asserts = 0 };
        var match: ?Match = null;
        while (sp != 0) {
            sp -= 1;
            var it = stack[sp];
            if (seen[it.pc] != 0) {
                if (seen[it.pc] == 2) return error.NotOnePass;
                continue;
            }
            seen[it.pc] = if (it.asserts != 0) 2 else 1;
            switch (re.insts[it.pc]) {
                .jmp => |t| {
                    it.pc = t;
                    stack[sp] = it;
                    sp += 1;
                },
                .split => |s| {
                    stack[sp] = .{ .pc = s.y, .slots = it.slots, .asserts = it.asserts };
                    stack[sp + 1] = .{ .pc = s.x, .slots = it.slots, .asserts = it.asserts };
                    sp += 2;
                },
                .save => |slot| {
                    if (slot < k) it.slots |= @as(u32, 1) << @intCast(slot);
                    it.pc += 1;
                    stack[sp] = it;
                    sp += 1;
                },
                .assert => |a| {
                    it.asserts |= @as(u8, 1) << @intCast(@backingInt(a));
                    it.pc += 1;
                    stack[sp] = it;
                    sp += 1;
                },
                .match => match = .{ .slots = it.slots, .asserts = it.asserts },
                .rune, .any, .any_not_nl => if (match) |mt| {
                    if (mt.asserts != 0) return error.NotOnePass;
                } else {
                    try edges.append(gpa, .{ .slots = it.slots, .next = undefined, .pc = it.pc, .asserts = it.asserts });
                },
            }
        }
        return match;
    }

    /// Whether some code point is read by both `a` and `b`.
    fn overlap(re: *const Regex, a: u16, b: u16) bool {
        const ra = re.insts[a];
        const rb = re.insts[b];
        if (ra == .any or rb == .any) return true;
        if (ra == .any_not_nl and rb == .any_not_nl) return true;
        if (ra == .any_not_nl) return !onlyNewline(re, rb.rune);
        if (rb == .any_not_nl) return !onlyNewline(re, ra.rune);
        const x = re.ranges[ra.rune.start..][0..ra.rune.len];
        const y = re.ranges[rb.rune.start..][0..rb.rune.len];
        var i: usize = 0;
        var j: usize = 0;
        while (i < x.len and j < y.len) {
            if (x[i].hi < y[j].lo) {
                i += 1;
            } else if (y[j].hi < x[i].lo) {
                j += 1;
            } else return true;
        }
        return false;
    }

    fn onlyNewline(re: *const Regex, r: @FieldType(Inst, "rune")) bool {
        const rs = re.ranges[r.start..][0..r.len];
        return rs.len == 1 and rs[0].lo == '\n' and rs[0].hi == '\n';
    }

    fn deinit(op: *OnePass) void {
        op.roots.deinit(op.gpa);
        op.trans.deinit(op.gpa);
        op.edges.deinit(op.gpa);
    }

    /// The leftmost-first match starting at `at`, its slots into `best`
    /// (`caps` scratch); `reach` set to where the reading stopped.
    noinline fn run(op: *const OnePass, re: *const Regex, input: []const u8, at: usize, caps: []usize, best: []usize, reach: *usize) bool {
        // The slots written in `caps`, and in `best` by the last match: no
        // clearing and copying of the whole slices (with a length known only
        // at run time, each a `compiler_rt` call).
        var set: u32 = 0;
        var best_set: u32 = 0;
        const roots = op.roots.items;
        const trans: [*]const u64 = @ptrCast(op.trans.items.ptr);
        // The root's `trans` row offset (root × 128).
        var r: usize = 0;
        var pos = at;
        var matched = false;
        var has_match = roots[0].has_match;
        // Few values live across the loop (measured: with the code point
        // before kept in one, the loop spilled to the stack): what an
        // assertion needs is read from the text when one is passed.
        while (true) {
            if (has_match) {
                const root = roots[r >> 7];
                if (root.match_asserts == 0 or holdAt(root.match_asserts, input, pos)) {
                    var cs = set;
                    while (cs != 0) : (cs &= cs - 1) best[@ctz(cs)] = caps[@ctz(cs)];
                    setSlots(best, root.match_slots, pos);
                    best_set = set | root.match_slots;
                    matched = true;
                    if (root.len == 0) break;
                }
            }
            // Steps that only move to the next root (no slot, assertion or
            // match: nothing above 16 bits), in a loop of few live values;
            // the step that ends it is read again below.
            while (pos < input.len) {
                const c = input[pos];
                if (c >= 0x80) break;
                const step = trans[r + c];
                if (step == 0 or step >> 16 != 0) break;
                r = @as(u16, @truncate(step));
                pos += 1;
            }
            if (pos >= input.len) break;
            const c = input[pos];
            var w: usize = 1;
            var step: u64 = undefined;
            if (c < 0x80) {
                step = trans[r + c];
                if (step == 0) break;
            } else {
                const ws = op.wideStep(re, input, pos, r);
                if (ws.step == 0) break;
                step = ws.step;
                w = ws.w;
            }
            const asserts: u8 = @truncate(step >> 48);
            if (asserts != 0 and !holdAt(asserts, input, pos)) break;
            const slots: u32 = @truncate(step >> 16);
            setSlots(caps, slots, pos);
            set |= slots;
            pos += w;
            r = @as(u16, @truncate(step));
            has_match = step >> match_bit != 0;
        }
        reach.* = pos;
        if (matched) {
            var unset = ~best_set & ((@as(u64, 1) << @intCast(best.len)) - 1);
            while (unset != 0) : (unset &= unset - 1) best[@ctz(unset)] = nil;
        }
        return matched;
    }

    inline fn setSlots(caps: []usize, slots: u32, pos: usize) void {
        var s = slots;
        while (s != 0) : (s &= s - 1) caps[@ctz(s)] = pos;
    }

    /// The step from root row `r` over the code point past ASCII at `pos`
    /// (0: none takes it) and its width. Out of line, as `holdAt`: inlined,
    /// the decode and the edge walk kept the loop's pointers on the stack
    /// (measured: 40 instructions per ASCII byte).
    noinline fn wideStep(op: *const OnePass, re: *const Regex, input: []const u8, pos: usize, r: usize) struct { step: u64, w: usize } {
        const d = decode(input, pos);
        const root = op.roots.items[r >> 7];
        for (op.edges.items[root.first..][0..root.len]) |edge| {
            if (re.consumes(edge.pc, d.cp.?)) return .{ .step = edge.step, .w = d.w };
        }
        return .{ .step = 0, .w = d.w };
    }

    /// Do `asserts` hold at `pos`?
    noinline fn holdAt(asserts: u8, input: []const u8, pos: usize) bool {
        return holdAll(asserts, runeBefore(input, pos), decode(input, pos).cp);
    }

    fn holdAll(asserts: u8, prev: ?u21, next: ?u21) bool {
        var s = asserts;
        while (s != 0) : (s &= s - 1) {
            if (!assertHolds(@fromBackingInt(@intCast(@ctz(s))), prev, next)) return false;
        }
        return true;
    }
};

fn hasRustAsserts(insts: []const Inst) bool {
    for (insts) |inst| {
        if (inst == .assert and @backingInt(inst.assert) > @backingInt(Assert.not_word_boundary)) return true;
    }
    return false;
}

fn hasAsserts(insts: []const Inst) bool {
    for (insts) |inst| {
        if (inst == .assert) return true;
    }
    return false;
}

/// Table capacities `Regex.compile` tries first, on the stack: every pattern
/// short of a large counted repetition or a big case-folded class fits.
const small_capacity: syntax.Capacity = .{ .insts = 256, .ranges = 256, .nodes = 256 };

/// Where a match can start, worked out from the program once at compile time
/// so the search skips positions where no thread could begin. Only consulted
/// while no thread is alive, so it never changes which match is found.
pub const Prefilter = struct {
    /// Every match starts at the start of the text (each path passes `\A`).
    anchored: bool = false,
    /// Every match ends at the end of the text (each path to the match
    /// passes `\z`), and not every one starts at its start: `isMatch` reads
    /// the text backwards from its end (`Regex.runRevDfa`).
    end_anchored: bool = false,
    /// With `end_anchored`: the last byte of every match is in this set (as
    /// `first`); null when a match can be empty, or end with any byte.
    last: ?[4]u64 = null,
    /// With `end_anchored`: every match ends with `tail_len` ASCII code
    /// points, the i-th from the end one of the two bytes `tail[i]` (the same
    /// byte twice for a literal; `(?i)` gives the two cases).
    tail: [16][2]u8 = undefined,
    tail_len: u8 = 0,
    /// The first byte of every match is in this set (bit b of word b/64);
    /// null when a match can be empty, or start with any byte.
    first: ?[4]u64 = null,
    /// The set's only member, when it has one.
    single: ?u8 = null,
    /// The first bytes of the literal text every match begins with
    /// (`Regex.literalPrefix`), up to 16; used from two bytes on.
    lit: [16]u8 = undefined,
    lit_len: u8 = 0,
    /// Without such a literal: the literal prefixes every match begins with
    /// (two bytes or more, at most `teddy.max_pats`), searched for together.
    /// Out of line (~400 B, most patterns have none): owned like the tables.
    teddy: ?*const teddy.Teddy = null,
    /// `first` as a SIMD scan, when it fits one (`teddy.ByteSet`).
    bytes: ?teddy.ByteSet = null,

    /// The first position at or after `pos` whose byte may start a match.
    fn next(pf: *const Prefilter, input: []const u8, pos: usize) ?usize {
        if (pf.lit_len >= 2) return findLiteral(input, pos, pf.lit[0..pf.lit_len]);
        if (pf.teddy) |t| return t.find(input, pos);
        if (pf.single) |c| return std.mem.findScalarPos(u8, input, pos, c);
        if (pf.bytes) |*b| return b.find(input, pos);
        const set = pf.first.?;
        var i = pos;
        while (i < input.len) : (i += 1) {
            const c = input[i];
            if (set[c >> 6] & (@as(u64, 1) << @truncate(c)) != 0) return i;
        }
        return null;
    }
};

/// The first occurrence of `lit` (two bytes or more) at or after `pos`:
/// 32 positions at a time, those whose first AND last byte match are checked
/// in full ("packed pair"; `std.mem.findPos` compares byte by byte for a
/// short needle).
fn findLiteral(input: []const u8, pos: usize, lit: []const u8) ?usize {
    const V = @Vector(32, u8);
    const last = lit.len - 1;
    const first_v: V = @splat(lit[0]);
    const last_v: V = @splat(lit[last]);
    var i = pos;
    // Two blocks per test: a candidate is rare, the loop is the cost.
    while (i + last + 64 <= input.len) : (i += 64) {
        const a0: V = input[i..][0..32].*;
        const b0: V = input[i + last ..][0..32].*;
        const a1: V = input[i + 32 ..][0..32].*;
        const b1: V = input[i + 32 + last ..][0..32].*;
        const m0 = @as(u32, @bitCast(a0 == first_v)) & @as(u32, @bitCast(b0 == last_v));
        const m1 = @as(u32, @bitCast(a1 == first_v)) & @as(u32, @bitCast(b1 == last_v));
        var mask = @as(u64, m1) << 32 | m0;
        while (mask != 0) : (mask &= mask - 1) {
            const at = i + @ctz(mask);
            if (std.mem.eql(u8, input[at + 1 ..][0 .. last - 1], lit[1..last])) return at;
        }
    }
    while (i + last + 32 <= input.len) : (i += 32) {
        const a: V = input[i..][0..32].*;
        const b: V = input[i + last ..][0..32].*;
        const m1: u32 = @bitCast(a == first_v);
        const m2: u32 = @bitCast(b == last_v);
        var mask = m1 & m2;
        while (mask != 0) : (mask &= mask - 1) {
            const at = i + @ctz(mask);
            if (std.mem.eql(u8, input[at + 1 ..][0 .. last - 1], lit[1..last])) return at;
        }
    }
    while (i + lit.len <= input.len) : (i += 1) {
        if (input[i] == lit[0] and std.mem.eql(u8, input[i..][0..lit.len], lit)) return i;
    }
    return null;
}

/// Work out `Prefilter` from a program: follow the empty transitions from the
/// start. `anchored` when a `\A` stands before every consuming state and the
/// match; `first` from the UTF-8 lead bytes of every class reachable there.
/// Byte positions the set skips are never the start of a code point the VM
/// would decode differently: a lead or ASCII byte always starts one, and a set
/// that could need a continuation byte (U+FFFD, what an invalid byte reads
/// as) is given up.
fn analyze(insts: []const Inst, ranges: []const Range) Prefilter {
    var pf: Prefilter = .{};
    var seen: std.StaticBitSet(max_insts) = .empty;
    var stack: [2 * max_insts]u16 = undefined;
    var set: [4]u64 = .{ 0, 0, 0, 0 };
    var any_first = false; // a `.`, an empty match, or U+FFFD: no byte set
    var unanchored = false; // a consuming state or the match before any `\A`
    // Two walks: with `\A` as a wall (anchoring), and through it (first bytes).
    for ([_]bool{ true, false }) |wall| {
        seen = .empty;
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
    pf.end_anchored = !pf.anchored and endAnchored(insts);
    if (pf.end_anchored) {
        pf.last = lastBytes(insts, ranges);
        if (pf.last != null) pf.tail_len = tailBytes(insts, ranges, &pf.tail);
    }
    pf.lit_len = @intCast(replace.prefixInto(insts, ranges, &pf.lit));
    if (!any_first) {
        pf.first = set;
        pf.bytes = teddy.ByteSet.build(set);
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

/// The `Prefilter.teddy` for a program `analyze` gave `pf`, or null: only
/// where a match can start anywhere and no literal prefix is searched for.
fn buildTeddy(pf: *const Prefilter, insts: []const Inst, ranges: []const Range) ?teddy.Teddy {
    if (pf.anchored or pf.first == null or pf.lit_len >= 2) return null;
    return .build(insts, ranges);
}

/// Does every path to the match pass a `\z`? Follows the empty transitions
/// from the start and from after every consuming instruction, with `\z` as a
/// wall and every other assertion passable.
fn endAnchored(insts: []const Inst) bool {
    var seen: std.StaticBitSet(max_insts) = .empty;
    // The start and every consuming instruction, then two per instruction walked.
    var stack: [3 * max_insts + 1]u16 = undefined;
    var sp: usize = 1;
    stack[0] = 0;
    for (insts, 0..) |inst, pc| switch (inst) {
        .rune, .any, .any_not_nl => {
            stack[sp] = @intCast(pc + 1);
            sp += 1;
        },
        else => {},
    };
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
            .assert => |a| if (a != .end_text) {
                stack[sp] = pc + 1;
                sp += 1;
            },
            .match => return false,
            .rune, .any, .any_not_nl => {},
        }
    }
    return true;
}

/// Does the match follow `pc0` without consuming input (every assertion
/// passable)?
fn reachesMatch(insts: []const Inst, pc0: u16) bool {
    var seen: std.StaticBitSet(max_insts) = .empty;
    var stack: [2 * max_insts]u16 = undefined;
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
            .split => |sx| {
                stack[sp] = sx.y;
                stack[sp + 1] = sx.x;
                sp += 2;
            },
            .save, .assert => {
                stack[sp] = pc + 1;
                sp += 1;
            },
            .match => return true,
            .rune, .any, .any_not_nl => {},
        }
    }
    return false;
}

/// The bytes a match can end with: the last byte of the UTF-8 encoding of
/// every code point a consuming instruction followed by the match takes —
/// a continuation byte for any past ASCII, and any byte from 0x80 when
/// U+FFFD is among them (an invalid byte reads as it). Null when a match can
/// be empty or end with any byte.
fn lastBytes(insts: []const Inst, ranges: []const Range) ?[4]u64 {
    if (reachesMatch(insts, 0)) return null;
    var set: [4]u64 = .{ 0, 0, 0, 0 };
    for (insts, 0..) |inst, pc| {
        switch (inst) {
            .rune, .any, .any_not_nl => {},
            else => continue,
        }
        if (!reachesMatch(insts, @intCast(pc + 1))) continue;
        switch (inst) {
            .rune => |r| for (ranges[r.start..][0..r.len]) |rg| {
                var c: u32 = rg.lo;
                while (c <= @min(rg.hi, 0x7f)) : (c += 1) set[c >> 6] |= @as(u64, 1) << @truncate(c);
                if (rg.hi >= 0x80) set[2] = ~@as(u64, 0); // 0x80..0xbf
                if (rg.lo <= 0xfffd and 0xfffd <= rg.hi) set[3] = ~@as(u64, 0);
            },
            else => return null,
        }
    }
    return set;
}

/// Fill `tail` (see `Prefilter.tail`) and return its length, for a program
/// with no empty match whose matches all end at the end of the text. Level k
/// holds the consuming instructions that can take the k-th code point from
/// the end of a match: level 1 those followed by the match, level k+1 those
/// followed by a member of level k (every assertion passable). It stops at
/// a level with a non-ASCII member or more than two bytes, and after a level
/// the start reaches (a match may be that short).
fn tailBytes(insts: []const Inst, ranges: []const Range, tail: *[16][2]u8) u8 {
    if (insts.len > Dfa.max_insts) return 0;
    // What follows each consuming instruction without consuming input: the
    // consuming instructions and the match (pc 0's own entry: the start).
    var follow: [Dfa.max_insts]Dfa.Set = undefined;
    for (insts, 0..) |inst, pc| {
        follow[pc] = switch (inst) {
            .rune, .any, .any_not_nl => closureOf(insts, @intCast(pc + 1)),
            else => .{ 0, 0 },
        };
    }
    const start = closureOf(insts, 0);
    var level: Dfa.Set = .{ 0, 0 };
    for (insts, 0..) |inst, pc| if (inst == .match) {
        level[pc >> 6] |= @as(u64, 1) << @truncate(pc);
    };
    var n: u8 = 0;
    while (n < tail.len) {
        var next: Dfa.Set = .{ 0, 0 };
        for (insts, 0..) |_, pc| {
            if (follow[pc][0] & level[0] != 0 or follow[pc][1] & level[1] != 0) next[pc >> 6] |= @as(u64, 1) << @truncate(pc);
        }
        level = next;
        var bytes: [2]u8 = undefined;
        var nb: usize = 0;
        for (insts, 0..) |inst, pc| {
            if (level[pc >> 6] & (@as(u64, 1) << @truncate(pc)) == 0) continue;
            const r = switch (inst) {
                .rune => |r| r,
                else => return n,
            };
            for (ranges[r.start..][0..r.len]) |rg| {
                if (rg.hi >= 0x80) return n;
                var c: u32 = rg.lo;
                while (c <= rg.hi) : (c += 1) {
                    const b: u8 = @intCast(c);
                    if (std.mem.findScalar(u8, bytes[0..nb], b) != null) continue;
                    if (nb == 2) return n;
                    bytes[nb] = b;
                    nb += 1;
                }
            }
        }
        if (nb == 0) return n;
        tail[n] = .{ bytes[0], bytes[nb - 1] };
        n += 1;
        if (start[0] & level[0] != 0 or start[1] & level[1] != 0) return n;
    }
    return n;
}

/// The consuming instructions and the match that follow `pc0` without
/// consuming input (every assertion passable), as a `Dfa.Set`.
fn closureOf(insts: []const Inst, pc0: u16) Dfa.Set {
    var seen: Dfa.Set = .{ 0, 0 };
    var out: Dfa.Set = .{ 0, 0 };
    var stack: [2 * Dfa.max_insts + 1]u16 = undefined;
    var sp: usize = 1;
    stack[0] = pc0;
    while (sp != 0) {
        sp -= 1;
        const pc = stack[sp];
        const bit = @as(u64, 1) << @truncate(pc);
        if (seen[pc >> 6] & bit != 0) continue;
        seen[pc >> 6] |= bit;
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
            .save, .assert => {
                stack[sp] = pc + 1;
                sp += 1;
            },
            .match, .rune, .any, .any_not_nl => out[pc >> 6] |= bit,
        }
    }
    return out;
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
    /// The backtracker's scratch, grown on first use: one bit per
    /// (position, instruction) visited, all zero between searches; and its
    /// stack of pending branches and capture restores.
    bt_visited: std.ArrayList(u64) = .empty,
    bt_jobs: std.ArrayList(Job) = .empty,
    /// Positions the backtracker's bit budget covers for this program
    /// (worked out once: the division was 4 % of a short search).
    bt_width: usize,
    /// `find`'s DFA, made once `vm_read` reaches `dfa_after`.
    dfa: ?*FindDfa = null,
    /// Bytes of text `find` handed to the VMs before the DFA was made.
    vm_read: usize = 0,
    /// Tests only: always the Pike VM, to compare the two engines.
    pike_only: bool = false,
    /// Tests only: the DFA from the first `find`, however short the text.
    dfa_eager: bool = false,
    /// Tests only: the DFA's tables a few states large, so they fill.
    dfa_small: bool = false,
    /// `captures`' one-pass engine, made with the DFA (when the program is
    /// one-pass); `onepass_tried` once that was worked out.
    onepass: ?*OnePass = null,
    onepass_tried: bool = false,
    /// Tests only: `captures` never by the one-pass engine (to test the
    /// backtracker on long texts).
    onepass_off: bool = false,
    /// Set for the call by `findAnchored`/`capturesAnchored`: a match must
    /// start at `from`.
    anchor: bool = false,

    /// Explore `pc` at `pos`, or (`restore`) put `pos` back into capture
    /// slot `pc`. A plain struct, not a tagged union: a union built on the
    /// stack wrote its tag as a byte and copied it out as a word, a failed
    /// store forward on every push (measured: 19 % of a short search).
    const Job = struct { pos: usize, pc: u16, restore: bool };

    /// The backtracker runs when (positions × instructions) fits this many
    /// bits (Go's limit too): a short text, where it beats the Pike VM's
    /// per-thread capture copies.
    const max_backtrack_bits = 256 * 1024;
    /// Pending branches and restores the backtracker may hold (~400 KiB);
    /// past it the search is handed to the Pike VM.
    const max_backtrack_jobs = 16 * 1024;

    const List = struct {
        pcs: []u16,
        caps: []usize,
        seen: []u32,
        /// Bytes mode: bytes left of the sequence the thread is inside (0: at
        /// a boundary); 1..3 entries are keyed in `seen` past the first `n`.
        rem: []u8,
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
        // Bytes mode: also the threads inside a sequence, (pc, 1..3).
        const cap = if (re.bytes) 4 * n else n;
        const words = 2 * (wordsFor(usize, cap * k) + wordsFor(u16, cap) + wordsFor(u32, cap) + wordsFor(u8, cap)) +
            wordsFor(Entry, 3 * n) + 2 * wordsFor(usize, k);
        const block = try gpa.alloc(usize, words);
        var rest = block;
        var m: Matcher = .{ .gpa = gpa, .re = re, .k = k, .block = block, .lists = undefined, .stack = undefined, .tmp = undefined, .best = undefined, .bt_width = max_backtrack_bits / n };
        for (&m.lists) |*l| {
            l.* = .{ .caps = take(usize, &rest, cap * k), .pcs = take(u16, &rest, cap), .seen = take(u32, &rest, cap), .rem = take(u8, &rest, cap) };
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
        if (m.dfa) |d| {
            d.deinit();
            m.gpa.destroy(d);
        }
        if (m.onepass) |op| {
            op.deinit();
            m.gpa.destroy(op);
        }
        m.bt_visited.deinit(m.gpa);
        m.bt_jobs.deinit(m.gpa);
        m.gpa.free(m.block);
        m.* = undefined;
    }

    /// Leftmost-first match starting the search at `from` (the text before
    /// `from` still counts for `^`/`\b`), or null.
    pub fn find(m: *Matcher, input: []const u8, from: usize) ?Span {
        if (from > input.len) return null;
        if (m.findDfa(input, from)) |found| {
            const span = found orelse return null;
            m.best[0] = span.start;
            m.best[1] = span.end;
            return span;
        }
        if (!m.run(input, from, false)) return null;
        return .{ .start = m.best[0], .end = m.best[1] };
    }

    const dfa_after = 1024;

    /// `find` by the DFAs (`FindDfa`): the match, none, or null when the
    /// DFA does not apply or cannot get its memory.
    fn findDfa(m: *Matcher, input: []const u8, from: usize) ??Span {
        const re = m.re;
        if (m.pike_only or m.anchor or re.vm_only or re.longest or re.insts.len > Dfa.max_insts) return null;
        const anchored = re.prefilter.anchored;
        if (anchored and from != 0) return @as(?Span, null); // `\A` holds at 0 only
        // Inside a UTF-8 sequence the VMs read from `from` on, byte by byte;
        // `start`, reading backwards, would read the whole sequence.
        if (!anchored and from < input.len and input[from] & 0xc0 == 0x80) return null;
        const d = m.dfa orelse blk: {
            // A fresh DFA works out every transition it takes; over a short
            // text that costs more than the backtracker (measured: a
            // compile-and-find of 37 bytes 1.0 → 1.8 µs). Made once the
            // `Matcher` has been handed enough text for it to pay off.
            if (!m.warm(input, from)) return null;
            break :blk m.makeDfa() orelse return null;
        };
        var reach: usize = undefined;
        var untracked: FindDfa.Track = .{};
        if (!anchored and d.skip_idle) {
            // Every match starts where the (fast) prefilter points: the
            // first such place with a match, read forwards from there, is
            // the leftmost-first match, and no backward pass is needed
            // (RE2's search from a literal prefix). The failed tries may
            // read no more than twice the text they moved past, with slack
            // (`A[^Z]*Z` over `AAAA…` would be quadratic); past that, one
            // unanchored pass.
            var pos = from;
            var spent: usize = 0;
            while (spent <= 2 * (pos - from) + 256) {
                const p = re.prefilter.next(input, pos) orelse return @as(?Span, null);
                if (d.run(re, input, p, true, &reach, &untracked) catch return null) |e| return .{ .start = p, .end = e };
                spent += reach - p;
                pos = p + 1;
            }
        }
        if (anchored) {
            const end = (d.run(re, input, from, true, &reach, &untracked) catch return null) orelse return @as(?Span, null);
            return .{ .start = from, .end = end };
        }
        return d.span(re, input, from) catch return null;
    }

    /// Whether the `Matcher` has been handed enough text for the DFA (and
    /// the one-pass engine) to pay off, counting this search's.
    fn warm(m: *Matcher, input: []const u8, from: usize) bool {
        m.vm_read +|= input.len - from;
        return m.vm_read >= dfa_after or m.dfa_eager;
    }

    fn makeDfa(m: *Matcher) ?*FindDfa {
        const d = m.gpa.create(FindDfa) catch return null;
        d.* = .init(m.gpa, m.re);
        if (m.dfa_small) {
            d.limit = 12;
            d.rev_limit = 6;
        }
        m.dfa = d;
        return d;
    }

    /// `find` for a match that starts at `from` exactly, or null — RE2's
    /// `ANCHOR_START`, regex-automata's `Input::anchored` (a search, unlike
    /// `^`, that leaves the pattern alone and the text before `from` in
    /// view of the assertions). Among the matches starting there, the one
    /// `find` would report.
    pub fn findAnchored(m: *Matcher, input: []const u8, from: usize) ?Span {
        m.anchor = true;
        defer m.anchor = false;
        return m.find(input, from);
    }

    /// `captures` for a match that starts at `from` exactly (see
    /// `findAnchored`).
    pub fn capturesAnchored(m: *Matcher, input: []const u8, from: usize, out: []?Span) bool {
        m.anchor = true;
        defer m.anchor = false;
        return m.captures(input, from, out);
    }

    /// Like `find`, filling `out[i]` with group i's span (null: the group
    /// took no part); `out` may be shorter or longer than the group count.
    pub fn captures(m: *Matcher, input: []const u8, from: usize, out: []?Span) bool {
        if (from > input.len) return false;
        const found = m.capturesOnePass(input, from) orelse m.run(input, from, false);
        if (!found) return false;
        m.fillCaptures(out);
        return true;
    }

    /// `captures` by the one-pass engine (`OnePass`), the match's slots in
    /// `best`: whether there is one, or null when the engine does not apply.
    /// The start comes as `findDfa` finds it: from each candidate of a fast
    /// prefilter, read anchored (the engine does it in the same pass as the
    /// captures); otherwise by the DFAs, then the engine from that start.
    fn capturesOnePass(m: *Matcher, input: []const u8, from: usize) ?bool {
        const re = m.re;
        if (m.pike_only or m.onepass_off or re.vm_only or re.longest or re.insts.len > Dfa.max_insts) return null;
        const anchored = re.prefilter.anchored;
        if (anchored and from != 0) return false;
        // As in `findDfa`: `start` would read a whole UTF-8 sequence backwards.
        if (!anchored and from < input.len and input[from] & 0xc0 == 0x80) return null;
        const op = m.onepass orelse blk: {
            if (m.onepass_tried) return null;
            if (m.dfa == null and !m.warm(input, from)) return null;
            m.onepass_tried = true;
            m.onepass = OnePass.make(m.gpa, re);
            break :blk m.onepass orelse return null;
        };
        var reach: usize = undefined;
        var track: FindDfa.Track = .{};
        if (anchored) return op.run(re, input, 0, m.tmp, m.best, &reach);
        if (m.anchor) return op.run(re, input, from, m.tmp, m.best, &reach);
        const d = m.dfa orelse m.makeDfa() orelse return null;
        if (d.skip_idle) {
            // `findDfa`'s search from each candidate, with its budget.
            var pos = from;
            var spent: usize = 0;
            while (spent <= 2 * (pos - from) + 256) {
                const p = re.prefilter.next(input, pos) orelse return false;
                if (op.run(re, input, p, m.tmp, m.best, &reach)) return true;
                spent += reach - p;
                pos = p + 1;
            }
        }
        const end = (d.run(re, input, from, false, &reach, &track) catch return null) orelse return false;
        const tracked = d.track and track.clean and track.origin != FindDfa.no_end;
        if (tracked) d.tracked += 1; // weighed against the joins, as in `span`
        const start = if (tracked) track.origin else d.start(re, input, from, end) catch return null;
        const found = op.run(re, input, start, m.tmp, m.best, &reach);
        std.debug.assert(found and m.best[1] == end);
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
                    const w = if (it.m.re.bytes) 1 else decode(it.input, s.end).w;
                    it.pos = if (s.end < it.input.len) s.end + w else it.input.len + 1;
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
        // Every match starts where `\A` holds, at 0 only: an iterator's call
        // after the first match is settled here, not by a search.
        if (m.re.prefilter.anchored and from != 0) return false;
        var start = from;
        if (!full and !m.pike_only and !m.re.longest) switch (m.backtrack(input, from)) {
            .found => return true,
            .none => return false,
            .pike => |at| start = at,
        };
        if (m.re.bytes) return m.runOnBytes(input, start, full);
        var t: SliceText = .{ .input = input };
        return m.runOn(&t, start, full);
    }

    /// `runOn` in bytes mode: one step per byte; a thread that took a
    /// sequence of `w` bytes keeps its place in the list for `w - 1` steps
    /// (`List.rem`) before its closure — the states inside a UTF-8
    /// automaton, so priorities stay as Rust's byte NFA has them.
    fn runOnBytes(m: *Matcher, input: []const u8, from: usize, full: bool) bool {
        const re = m.re;
        var cur = &m.lists[0];
        var nxt = &m.lists[1];
        cur.clear();
        var matched = false;
        var pos = from;
        while (true) {
            const at_end = pos >= input.len;
            if (!matched and ((!full and !m.anchor) or pos == from)) {
                @memset(m.tmp, nil);
                m.addThread(cur, 0, pos, bytesBefore(input, pos), bytesAt(input, pos));
            }
            if (cur.n == 0 and (matched or at_end or full or m.anchor)) break;
            nxt.clear();
            const q = pos + 1;
            var i: usize = 0;
            while (i < cur.n) : (i += 1) {
                const pc = cur.pcs[i];
                const rem = cur.rem[i];
                const caps = cur.caps[i * m.k ..][0..m.k];
                if (re.longest and matched and caps[0] > m.best[0]) continue; // started later
                if (rem != 0) {
                    @memcpy(m.tmp, caps);
                    if (rem == 1) m.addThread(nxt, pc, q, bytesBefore(input, q), bytesAt(input, q)) else m.addPending(nxt, pc, rem - 1);
                    continue;
                }
                if (re.insts[pc] == .match) {
                    if (full and !at_end) continue;
                    @memcpy(m.best, caps);
                    m.best[1] = pos;
                    matched = true;
                    if (re.longest) continue;
                    break; // cut the lower-priority threads
                }
                const w = re.consumeBytes(pc, input, pos) orelse continue;
                @memcpy(m.tmp, caps);
                if (w == 1) m.addThread(nxt, pc + 1, q, bytesBefore(input, q), bytesAt(input, q)) else m.addPending(nxt, pc + 1, @intCast(w - 1));
            }
            if (at_end) break;
            pos = q;
            std.mem.swap(*List, &cur, &nxt);
        }
        return matched;
    }

    /// A thread `rem` bytes before the end of a sequence, with `m.tmp`'s captures.
    fn addPending(m: *Matcher, list: *List, pc: u16, rem: u8) void {
        const key = @as(usize, rem) * m.re.insts.len + pc;
        if (list.seen[key] == list.gen) return;
        list.seen[key] = list.gen;
        list.pcs[list.n] = pc;
        list.rem[list.n] = rem;
        @memcpy(list.caps[list.n * m.k ..][0..m.k], m.tmp);
        list.n += 1;
    }

    /// What `backtrack` settled: a match, none, or no answer — the Pike VM
    /// takes over from `start` (no match begins before it).
    const Backtracked = union(enum) { found, none, pike: usize };

    /// Leftmost-first search by backtracking with a visited bit per
    /// (position, instruction) — each state is explored once, so the time is
    /// linear in their number, as the Pike VM's. A depth-first walk taking
    /// the preferred branch first finds the leftmost-first match first, and
    /// carries one set of captures instead of one per thread. A state that
    /// failed once fails again from any start, so the bits are kept across
    /// start positions. The bits cover a window of positions from `base`
    /// (the bit budget's worth), not the whole text: a search whose match is
    /// short backtracks however long the text is. Once a start lies past
    /// every position visited, the window moves there (no later start
    /// revisits an earlier position). When the exploration runs off the
    /// window's end, or the scratch cannot grow, the Pike VM takes over.
    fn backtrack(m: *Matcher, input: []const u8, from: usize) Backtracked {
        const re = m.re;
        const n = re.insts.len;
        const width = @min(input.len - from + 1, m.bt_width);
        if (width < 2) return .{ .pike = from };
        const words = (width * n + 63) / 64;
        if (m.bt_visited.items.len < words) {
            const old = m.bt_visited.items.len;
            m.bt_visited.resize(m.gpa, words) catch return .{ .pike = from };
            @memset(m.bt_visited.items[old..], 0);
        }
        var win: Window = .{ .base = from, .width = width, .hi = from };
        defer {
            win.clear(m.bt_visited.items, n);
            m.bt_jobs.clearRetainingCapacity();
        }
        const pf = &re.prefilter;
        var start = from;
        const anchor = pf.anchored or m.anchor;
        while (true) {
            if (anchor and start != from) return .none;
            if (pf.first != null) start = pf.next(input, start) orelse return .none;
            if (m.anchor and start != from) return .none;
            if (start > win.hi) {
                win.clear(m.bt_visited.items, n);
                win = .{ .base = start, .width = width, .hi = start };
            }
            switch (m.backtrackAt(input, start, &win)) {
                .found => return .found,
                .pike => return .{ .pike = start },
                .none => {},
            }
            if (start >= input.len) return .none;
            start += if (re.bytes) 1 else decode(input, start).w;
        }
    }

    /// The positions `backtrack`'s bits stand for: `base` up to, not
    /// including, `base + width`; `hi` the furthest one visited.
    const Window = struct {
        base: usize,
        width: usize,
        hi: usize,

        /// Zero the bits that were used, leaving the scratch all zero.
        fn clear(w: *const Window, visited: []u64, n: usize) void {
            @memset(visited[0 .. ((w.hi - w.base + 1) * n + 63) / 64], 0);
        }
    };

    fn backtrackAt(m: *Matcher, input: []const u8, start: usize, win: *Window) enum { found, none, pike } {
        const re = m.re;
        const n = re.insts.len;
        const visited = m.bt_visited.items;
        @memset(m.tmp, nil);
        m.pushJob(0, start, false) catch return .pike;
        const limit = max_backtrack_jobs;
        while (m.bt_jobs.pop()) |job| {
            if (job.restore) {
                m.tmp[job.pc] = job.pos;
                continue;
            }
            var pc = job.pc;
            var pos = job.pos;
            while (true) {
                if (pos - win.base >= win.width) return .pike;
                const bit = (pos - win.base) * n + pc;
                const mask = @as(u64, 1) << @truncate(bit);
                if (visited[bit >> 6] & mask != 0) break;
                visited[bit >> 6] |= mask;
                win.hi = @max(win.hi, pos);
                switch (re.insts[pc]) {
                    .match => {
                        @memcpy(m.best, m.tmp);
                        m.best[1] = pos;
                        return .found;
                    },
                    .rune, .any, .any_not_nl => {
                        if (re.bytes) {
                            pos += re.consumeBytes(pc, input, pos) orelse break;
                        } else {
                            const d = decode(input, pos);
                            const cp = d.cp orelse break;
                            if (!re.consumes(pc, cp)) break;
                            pos += d.w;
                        }
                        pc += 1;
                    },
                    .split => |sp| {
                        if (m.bt_jobs.items.len >= limit) return .pike;
                        m.pushJob(sp.y, pos, false) catch return .pike;
                        pc = sp.x;
                    },
                    .jmp => |t| pc = t,
                    .save => |slot| {
                        if (slot < m.k) {
                            if (m.bt_jobs.items.len >= limit) return .pike;
                            m.pushJob(slot, m.tmp[slot], true) catch return .pike;
                            m.tmp[slot] = pos;
                        }
                        pc += 1;
                    },
                    .assert => |a| {
                        const holds = if (re.bytes) assertHolds(a, bytesBefore(input, pos), bytesAt(input, pos)) else assertHolds(a, runeBefore(input, pos), decode(input, pos).cp);
                        if (!holds) break;
                        pc += 1;
                    },
                }
            }
        }
        return .none;
    }

    /// `bt_jobs.append` with the common case inline: the job fits the
    /// capacity already there (measured: the out-of-line `append` was 28 % of
    /// a short anchored search).
    inline fn pushJob(m: *Matcher, pc: u16, pos: usize, restore: bool) std.mem.Allocator.Error!void {
        if (m.bt_jobs.items.len == m.bt_jobs.capacity) try m.growJobs();
        const j = m.bt_jobs.addOneAssumeCapacity();
        j.pos = pos;
        j.pc = pc;
        j.restore = restore;
    }

    noinline fn growJobs(m: *Matcher) std.mem.Allocator.Error!void {
        try m.bt_jobs.ensureUnusedCapacity(m.gpa, 1);
    }

    /// Go's `FindReaderIndex`: the leftmost match in what `r` yields, as byte
    /// offsets from where `r` stood. Reads no further than it must (at most
    /// three code points past the match's end); constant memory. `r`'s buffer must
    /// hold at least 4 bytes.
    pub fn findReader(m: *Matcher, r: *std.Io.Reader) error{ReadFailed}!?Span {
        std.debug.assert(!m.re.bytes); // bytes mode: slices only
        var t: ReaderText = .init(r);
        const found = m.runOn(&t, 0, false);
        if (t.failed and !found) return error.ReadFailed;
        if (!found) return null;
        return .{ .start = m.best[0], .end = m.best[1] };
    }

    /// Go's `FindReaderSubmatchIndex`: `findReader` that also fills `out` as
    /// `captures` does.
    pub fn capturesReader(m: *Matcher, r: *std.Io.Reader, out: []?Span) error{ReadFailed}!bool {
        std.debug.assert(!m.re.bytes); // bytes mode: slices only
        var t: ReaderText = .init(r);
        const found = m.runOn(&t, 0, false);
        if (t.failed and !found) return error.ReadFailed;
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
        // Started inside a UTF-8 sequence: its tail is read byte by byte
        // (U+FFFD each), but an assertion after one of those bytes sees the
        // text before it — as the backtracker and bytes mode do — up to the
        // sequence's end, where the two first differ (`\b` after `é`).
        const sync = if (@TypeOf(text.*).can_skip) seqEnd(text.input, from) else from;
        const pf = &re.prefilter;
        while (true) {
            if (!matched and cur.n == 0 and !full) {
                // No thread alive: a match can only start where the prefilter allows.
                if ((pf.anchored or m.anchor) and pos != from) break;
                if (@TypeOf(text.*).can_skip and pf.first != null) {
                    pos = text.skip(pf, pos) orelse break;
                    prev = text.before(pos);
                    // As in `runSetOn`: `seen` is from where the threads died.
                    cur.clear();
                }
            }
            const here = text.at(pos);
            if (!matched and (!(pf.anchored or m.anchor) or pos == from)) {
                @memset(m.tmp, nil);
                m.addThread(cur, 0, pos, prev, here.cp);
            }
            if (cur.n == 0 and (matched or here.cp == null)) break;
            nxt.clear();
            const after = if (here.cp != null) text.at(pos + here.w) else here;
            const next_prev = if (pos + here.w <= sync) text.before(pos + here.w) else here.cp;
            var i: usize = 0;
            while (i < cur.n) : (i += 1) {
                const pc = cur.pcs[i];
                const caps = cur.caps[i * m.k ..][0..m.k];
                if (re.longest and matched and caps[0] > m.best[0]) continue; // started later
                switch (re.insts[pc]) {
                    .match => {
                        if (full and here.cp != null) continue;
                        if (re.longest) {
                            // The match state is one thread per step, so this is
                            // the leftmost-first among the matches ending here; a
                            // later step's is longer.
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
                        m.addThread(nxt, pc + 1, pos + here.w, next_prev, after.cp);
                    },
                }
            }
            if (here.cp == null) break;
            pos += here.w;
            prev = next_prev;
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
                            list.rem[list.n] = 0;
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

    fn skip(t: *const SliceText, pf: *const Prefilter, pos: usize) ?usize {
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

    fn skip(_: *const ReaderText, _: *const Prefilter, pos: usize) ?usize {
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
    // Two bytes (Latin, Greek, Cyrillic, …) inline: `utf8Decode` is a call,
    // a quarter of a find-all over Czech text. C2..DF: no overlong form.
    if (c >= 0xc2 and c <= 0xdf and i + 1 < input.len and input[i + 1] & 0xc0 == 0x80)
        return .{ .cp = @as(u21, c & 0x1f) << 6 | (input[i + 1] & 0x3f), .w = 2 };
    const len = std.unicode.utf8ByteSequenceLength(c) catch return .{ .cp = 0xfffd, .w = 1 };
    if (i + len > input.len) return .{ .cp = 0xfffd, .w = 1 };
    const cp = std.unicode.utf8Decode(input[i..][0..len]) catch return .{ .cp = 0xfffd, .w = 1 };
    return .{ .cp = cp, .w = len };
}

/// The code point that ends at `i` (`i > 0`), as `decode` reads the text
/// from the start: a valid sequence is one code point wherever it stands (a
/// lead byte is never inside another), anything else is U+FFFD, one byte.
fn decodeBefore(input: []const u8, i: usize) Decoded {
    const c = input[i - 1];
    if (c < 0x80) return .{ .cp = c, .w = 1 };
    // Two bytes inline, as `decode`.
    if (c & 0xc0 == 0x80 and i >= 2 and input[i - 2] >= 0xc2 and input[i - 2] <= 0xdf)
        return .{ .cp = @as(u21, input[i - 2] & 0x1f) << 6 | (c & 0x3f), .w = 2 };
    var back: usize = 2;
    while (back <= @min(4, i)) : (back += 1) {
        const d = decode(input[0..i], i - back);
        if (d.w == back) return d;
    }
    return .{ .cp = 0xfffd, .w = 1 };
}

/// What the assertions need of the text just before `i`: null at the start,
/// else the code point that ends there (U+FFFD for an invalid sequence).
/// The Go grammar's assertions look at ASCII only; the Rust grammar's
/// Unicode word boundaries need the whole code point.
/// Past the continuation bytes at `i` (at most three): where the UTF-8
/// sequence `i` lies inside ends; `i` itself on a boundary.
fn seqEnd(input: []const u8, i: usize) usize {
    var e = i;
    while (e < input.len and e < i + 3 and input[e] & 0xc0 == 0x80) e += 1;
    return e;
}

fn runeBefore(input: []const u8, i: usize) ?u21 {
    if (i == 0) return null;
    const c = input[i - 1];
    if (c < 0x80) return c;
    return runeBeforeWide(input, i);
}

noinline fn runeBeforeWide(input: []const u8, i: usize) u21 {
    return decodeBefore(input, i).cp.?;
}

fn isWord(cp: ?u21) bool {
    const c = cp orelse return false;
    return c < 0x80 and (std.ascii.isAlphanumeric(@intCast(c)) or c == '_');
}

/// Bytes mode: what the assertions see before `i`, as regex-automata's
/// `utf8::decode_last`: back over at most three continuation bytes, then
/// decode from there — a code point that ends before `i` counts
/// (`"σ\x80"` reads σ, a word character, before its end). `invalid` when
/// that decode fails.
fn bytesBefore(input: []const u8, i: usize) ?u21 {
    if (i == 0) return null;
    var start = i - 1;
    const limit = i -| 4;
    while (start > limit and input[start] & 0xc0 == 0x80) start -= 1;
    const d = decode(input[0..i], start);
    if (d.w == 1 and input[start] >= 0x80) return invalid;
    // The ASCII assertions read the byte at `i - 1` itself: past ASCII, no
    // word byte — though `decode_last` may have read an ASCII one before it.
    const cp = d.cp.?;
    if (cp < 0x80 and input[i - 1] >= 0x80) return ascii_shadow + cp;
    return cp;
}

/// `ascii_shadow + c`: the Unicode assertions see ASCII `c`, the ASCII ones
/// a byte past ASCII (bytes mode, `bytesBefore`).
const ascii_shadow: u21 = syntax.byte_base + 0x100;

/// Bytes mode: the code point at `i` for the assertions (`invalid` for an
/// invalid byte), null at the end.
fn bytesAt(input: []const u8, i: usize) ?u21 {
    const d = decode(input, i);
    const cp = d.cp orelse return null;
    return if (d.w == 1 and input[i] >= 0x80) invalid else cp;
}

/// An invalid byte next to a position (bytes mode): no word character, and
/// Rust's `\B` and half boundaries do not hold beside it.
const invalid: u21 = syntax.byte_base;

fn isUnicodeWord(cp: ?u21) bool {
    const c = cp orelse return false;
    if (c < 0x80) return isWord(c);
    if (c >= ascii_shadow and c < ascii_shadow + 0x80) return isWord(c - ascii_shadow);
    return syntax.isPerlWord(c);
}

fn assertHolds(a: Assert, prev: ?u21, next: ?u21) bool {
    return switch (a) {
        .begin_text => prev == null,
        .end_text => next == null,
        .begin_line => prev == null or prev.? == '\n',
        .end_line => next == null or next.? == '\n',
        .word_boundary => isWord(prev) != isWord(next),
        .not_word_boundary => isWord(prev) == isWord(next),
        .begin_line_crlf => prev == null or prev.? == '\n' or (prev.? == '\r' and next != '\n'),
        .end_line_crlf => next == null or next.? == '\r' or (next.? == '\n' and prev != '\r'),
        .word_boundary_unicode => isUnicodeWord(prev) != isUnicodeWord(next),
        .not_word_boundary_unicode => prev != invalid and next != invalid and isUnicodeWord(prev) == isUnicodeWord(next),
        .word_start => !isWord(prev) and isWord(next),
        .word_end => isWord(prev) and !isWord(next),
        .word_start_half => !isWord(prev),
        .word_end_half => !isWord(next),
        .word_start_unicode => !isUnicodeWord(prev) and isUnicodeWord(next),
        .word_end_unicode => isUnicodeWord(prev) and !isUnicodeWord(next),
        .word_start_half_unicode => prev != invalid and !isUnicodeWord(prev),
        .word_end_half_unicode => next != invalid and !isUnicodeWord(next),
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
    try expectFind("\\p{ASCII}+", "é\x00abc\x7fé", "\x00abc\x7f");
    try expectFind("\\p{Assigned}", "\u{378}a", "a");
    try expectFind("\\p{Any}", "\u{378}", "\u{378}");
    try expectFind("(?i)\\p{Lu}+", "abcD1", "abcD"); // folded like any class
    try expectFind("(?i)\\P{Lu}", "aB1", "1"); // folded, then negated
    // The tables also compile at comptime; a class named twice is stored once.
    const ident = comptime comptimeCompile("\\p{L}[\\p{L}\\p{N}_]*");
    try testing.expect(ident.fullMatch("π_2ž"));
    try testing.expect(!ident.fullMatch("2π"));
    var many = try Regex.compile(testing.allocator, strRepeat("\\p{L}", 12));
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

test "find's DFA (anchored programs) agrees with the Pike VM, across calls and past a full table" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x6466);
    const rng = prng.random();
    const patterns = [_][]const u8{
        "^[a-z]+",         "^(a|ab)(c|bcd)(d*)", "^a*?b",  "^(?:ab|a)(?:c|bcd)?", "\\Aab|\\Ab\\b",
        "^\\w+\\b",
        "^é+[^a]",
        "^$",              "^x*",                "^.*\\z", "^(a|b)*a(a|b){8}",    "^(?s).+?d",
        "^[^\\n]*\\n",     "^a{2,5}?b?",
        "^(?i)ÉA+",
        "^(?:a\\B|b\\b)+",
    };
    var buf: [600]u8 = undefined;
    for (patterns) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        try testing.expect(re.prefilter.anchored);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        // Short texts and long ones; every prefix of the short ones. One
        // Matcher throughout: the cached transitions carry over.
        for (0..300) |round| {
            const len = if (round % 10 == 0) 200 + rng.uintLessThan(usize, 400) else rng.uintLessThan(usize, 12);
            var n: usize = 0;
            while (n < len) {
                const piece = ([_][]const u8{ "a", "b", "c", "d", " ", "\n", "é", "É", "_" })[rng.uintLessThan(usize, 9)];
                if (n + piece.len > len) break;
                @memcpy(buf[n..][0..piece.len], piece);
                n += piece.len;
            }
            const text = buf[0..n];
            var cut = if (n > 12) n else 0;
            while (cut <= n) : (cut += 1) {
                const t = text[0..cut];
                errdefer std.debug.print("/{s}/ on \"{f}\"\n", .{ p, std.zig.fmtString(t) });
                try testing.expectEqual(pm.find(t, 0), m.find(t, 0));
                if (t.len != 0) try testing.expectEqual(pm.find(t, 1), m.find(t, 1));
            }
        }
        try testing.expect(m.dfa != null);
        // 2^9 subsets of the last nine letters: more states than the table holds.
        if (std.mem.eql(u8, p, "^(a|b)*a(a|b){8}")) {
            var long: [4000]u8 = undefined;
            for (&long) |*c| c.* = "ab"[rng.uintLessThan(usize, 2)];
            try testing.expectEqual(pm.find(&long, 0), m.find(&long, 0));
            try testing.expect(m.dfa.?.flushes > 0);
        }
    }
}

test "find makes its DFA only once the Matcher was handed enough text" {
    var re = try Regex.compile(testing.allocator, "[a-z]+");
    defer re.deinit(testing.allocator);
    var m = try Matcher.init(testing.allocator, &re);
    defer m.deinit();
    try testing.expectEqual(Span{ .start = 4, .end = 7 }, m.find("12, abc", 0).?);
    try testing.expect(m.dfa == null); // a short one-shot search stays on the VMs
    const long = strRepeat("1 ", 600) ++ "xyz";
    try testing.expectEqual(Span{ .start = 1200, .end = 1203 }, m.find(long, 0).?);
    try testing.expect(m.dfa != null);
    try testing.expectEqual(Span{ .start = 4, .end = 7 }, m.find("12, abc", 0).?);
}

test "captures by the one-pass engine agree with the Pike VM" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x6f70);
    const rng = prng.random();
    // The pattern, and whether it is one-pass (null: either).
    const cases = [_]struct { []const u8, ?bool }{
        .{ "INV-([0-9]{4}-[0-9]{4})", true },
        .{ "(a+)(b*)c", true },
        .{ "(\\w+)@(\\w+)\\.com", true },
        .{ "\\b(\\w+)\\b", true },
        .{ "^(\\d+)-(\\d+)$", true },
        .{ "(?m)^(\\w+)$", true },
        .{ "x*", true },
        .{ "(é+)(ž|a)", true },
        .{ "(?i)(žluť)ou", true },
        .{ "(a)|b", true },
        .{ "(?s)(.)(.)", true },
        .{ "([^ ]+) (.*)", true },
        .{ "(\\d+)?x", true },
        // A way below the match is cut: over "b", the empty match.
        .{ "(a?)|(b)", true },
        // The match past `$` holds only at the end: "1-2x" has none.
        .{ "(\\d+)-(\\d+)$", true },
        // From each candidate of the prefilter: `\b` decides, not the DFA.
        .{ "\\bab(c)", true },
        .{ "(a|ab)(c|bcd)", false },
        .{ "a*a", false },
        .{ "a|(ab)", false },
        .{ "(a?)(a)", false },
        .{ "a$|ab", false },
        // `a` is reached past `\b`, then again: where `\b` fails, the second way.
        .{ "(\\b|)(a)", false },
        // Whether the match past `$` cuts `b` depends on the text.
        .{ "(a)(?:$|b)", false },
        .{ "(a*)*b", null },
        .{ "a\\B(b)", null },
        .{ "(?:(a)|b)*?c", null },
        .{ "(\\b|x)(a)", null },
    };
    const pieces = [_][]const u8{ "a", "b", "c", "d", " ", "\n", "é", "ž", "Ž", "_", "x", "-", "1", "2", "@", ".com", "INV-", "ou", "\xff", "\xc3" };
    // Texts each case meets for sure, besides the random ones.
    const fixed = [_][]const u8{ "1-2", "1-2x", "12-345\n", "ab", "b", "a b", "_a", "xa", " a", "INV-1234-5678", "x@y.com", "žluťou", "ééž", "xabc abc" };
    var text: [3000]u8 = undefined;
    var ga: [8]?Span = undefined;
    var gb: [8]?Span = undefined;
    for (cases) |cs| {
        const p = cs[0];
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        const ng = re.names.len;
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        for (0..60 + fixed.len) |round| {
            var n: usize = 0;
            if (round >= 60) {
                const f = fixed[round - 60];
                @memcpy(text[0..f.len], f);
                n = f.len;
            } else {
                const len = if (round % 6 == 0) text.len - 8 else rng.uintLessThan(usize, 30);
                while (n < len) {
                    const piece = pieces[rng.uintLessThan(usize, pieces.len)];
                    @memcpy(text[n..][0..piece.len], piece);
                    n += piece.len;
                }
            }
            const t = text[0..n];
            errdefer std.debug.print("/{s}/ on \"{f}\"\n", .{ p, std.zig.fmtString(t) });
            var it = m.iterator(t);
            var pit = pm.iterator(t);
            while (true) {
                const s1 = it.nextCaptures(ga[0..ng]);
                try testing.expectEqual(pit.nextCaptures(gb[0..ng]), s1);
                if (s1 == null) break;
                try testing.expectEqualSlices(?Span, gb[0..ng], ga[0..ng]);
            }
            var from: usize = 0;
            while (from <= t.len) : (from += if (t.len > 64) 7 else 1) {
                errdefer std.debug.print("from {d}\n", .{from});
                const f1 = m.captures(t, from, ga[0..ng]);
                try testing.expectEqual(pm.captures(t, from, gb[0..ng]), f1);
                if (f1) try testing.expectEqualSlices(?Span, gb[0..ng], ga[0..ng]);
            }
        }
        errdefer std.debug.print("/{s}/ one-pass: {}\n", .{ p, m.onepass != null });
        try testing.expect(m.onepass_tried);
        if (cs[1]) |want| try testing.expectEqual(want, m.onepass != null);
    }
}

test "find's DFAs (unanchored: forward for the end, backward for the start) agree with the Pike VM" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x7266);
    const rng = prng.random();
    const patterns = [_][]const u8{
        "[a-z]+",            "\\p{L}+",   "\\b\\w+\\b",
        "(?i)éa\\w*",
        "a(b|bc)d?",         "c|ab|b",    "(a|b)*a(a|b){6}",
        "[ab]{2,9}?c",
        "\\B.é",
        "(?m)^\\w+$",        "x*",        ".",
        "é+|a+",
        "(?:ab|a)(?:c|bcd)", "[^ \\n]+ ", "d\\z",
        "(?s).{3}\\n",
        "a(?s:.)*Ω\\z",
    };
    const text = try gpa.alloc(u8, 3000);
    defer gpa.free(text);
    for (patterns) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        try testing.expect(!re.prefilter.anchored);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        for (0..20) |round| {
            var n: usize = 0;
            const len = if (round % 4 == 0) text.len - 4 else rng.uintLessThan(usize, 40);
            while (n < len) {
                const piece = ([_][]const u8{ "a", "b", "c", "d", " ", "\n", "é", "É", "_", "Ω" })[rng.uintLessThan(usize, 10)];
                @memcpy(text[n..][0..piece.len], piece);
                n += piece.len;
            }
            const t = text[0..n];
            errdefer std.debug.print("/{s}/ on \"{f}\"\n", .{ p, std.zig.fmtString(t) });
            var it = m.iterator(t);
            var pit = pm.iterator(t);
            while (true) {
                const a = it.next();
                try testing.expectEqual(pit.next(), a);
                if (a == null) break;
            }
            var from: usize = 0;
            while (from <= t.len) : (from += if (t.len > 64) 7 else 1) {
                try testing.expectEqual(pm.find(t, from), m.find(t, from));
            }
        }
        try testing.expect(m.dfa != null);
    }
}

test "the DFAs past the backward table, many contexts and the candidate budget; Teddy and one-pass edge cases" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x7276);
    const rng = prng.random();
    // Backward sets (an `a` at each offset up to six back) past
    // `RevDfa.max_states`, over ASCII and past it: `start` and `runRevDfa`
    // empty their table while reading.
    const patterns = [_][]const u8{
        "[a-dé]{6}a[a-dé]*",
        // `start` must begin each read at the match's own set: a stale
        // first state from before a flush need not read the `_`.
        "[a-dé]{6}a[a-dé]*_",
        "_[a-dé]{6}a[a-dé]*\\z",
        "\\b[a-d]{1,3}\\b(?:[ _][a-d]{1,3}\\b){1,5}",
    };
    const pieces = [_][]const u8{ "a", "b", "c", "d", "é", "a", "b", "c", "d", "é", " ", "_", "z" };
    const text = try gpa.alloc(u8, 4000);
    defer gpa.free(text);
    for (patterns) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        for (0..30) |round| {
            var n: usize = 0;
            const len = if (round % 3 == 0) text.len - 4 else rng.uintLessThan(usize, 200);
            // Separators rarely in odd rounds: long runs for the backward reads.
            const np: usize = if (round % 2 == 1) pieces.len - 3 else pieces.len;
            const sep_odds: usize = if (round % 2 == 1) 400 else 40;
            while (n < len) {
                const piece = pieces[if (rng.uintLessThan(usize, sep_odds) == 0) pieces.len - 1 - rng.uintLessThan(usize, 3) else rng.uintLessThan(usize, np)];
                @memcpy(text[n..][0..piece.len], piece);
                n += piece.len;
            }
            const t = text[0..n];
            errdefer std.debug.print("/{s}/ on \"{f}\"\n", .{ p, std.zig.fmtString(t) });
            try testing.expectEqual(pm.find(t, 0) != null, re.isMatch(t));
            var it = m.iterator(t);
            var pit = pm.iterator(t);
            while (true) {
                const a = it.next();
                try testing.expectEqual(pit.next(), a);
                if (a == null) break;
            }
            var from: usize = 0;
            while (from <= t.len) : (from += 13) {
                try testing.expectEqual(pm.find(t, from), m.find(t, from));
            }
        }
    }

    // Each case through the DFAs and the one-pass engine (`dfa_eager`),
    // and the Pike VM: the same match and groups.
    const Case = struct { []const u8, []const u8, ?Span };
    var long: [400]u8 = undefined;
    // The first candidate reads 300 bytes and fails: past the candidate
    // budget, one unanchored pass, whose skip to "AB" lands after `x` —
    // `\b` must see the `x`, not the `!` the threads died at.
    const lead_len = 2 + 300 + 1;
    @memset(long[0..lead_len], 'c');
    long[0..2].* = "AB".*;
    long[lead_len - 1] = '!';
    long[lead_len..][0..6].* = "xABccZ".*;
    const cases = [_]Case{
        .{ "\\bAB[^Z!]*Z", long[0 .. lead_len + 6], null },
        // Candidate "xy" at 0 reads to 3 and fails; candidate "9x" at 2,
        // before where that read stopped, matches.
        .{ "xy([0-9]+)c|(9x)yd", "xy9xyd", .{ .start = 2, .end = 6 } },
        // A branch starts with a class too large for Teddy: no Teddy at all.
        .{ "[c-z]x|ab", "zx", .{ .start = 0, .end = 2 } },
        .{ "[c-z]x|ab", "-ab", .{ .start = 1, .end = 3 } },
    };
    var ga: [4]?Span = undefined;
    var gb: [4]?Span = undefined;
    for (cases) |cs| {
        const p, const t, const want = cs;
        errdefer std.debug.print("/{s}/ on \"{f}\"\n", .{ p, std.zig.fmtString(t) });
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        const ng = re.names.len;
        try testing.expectEqual(want != null, re.isMatch(t));
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        try testing.expectEqual(want, m.find(t, 0));
        try testing.expectEqual(want, pm.find(t, 0));
        try testing.expectEqual(want != null, m.captures(t, 0, ga[0..ng]));
        try testing.expectEqual(want != null, pm.captures(t, 0, gb[0..ng]));
        if (want != null) try testing.expectEqualSlices(?Span, gb[0..ng], ga[0..ng]);
    }
}

test "FindDfa over bytes: two-byte sequences through mid-sequence states, the rest and invalid UTF-8 as before" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x7574_6638);
    const rng = prng.random();
    // A lone lead, a lone continuation byte, a cut three-byte sequence and
    // a lead before ASCII make U+FFFD, one byte wide; a two-byte sequence
    // whose lead the forward table knows meets an unknown continuation, and
    // the backward one a continuation byte after a non-lead (`€`, `😀`).
    const pieces = [_][]const u8{ "a", "b", "c", "7", " ", "_", "é", "É", "ž", "ť", "\xc3", "\xa9", "\xe2\x82", "€", "😀", "\xdf" };
    const patterns = [_][]const u8{
        "\\p{L}+",
        "\\b\\w+\\b",
        "[0-9]+",
        "(?i)žluť\\w*",
        ".",
        "[^a]+",
        "é+",
        "\\PL+",
        "(?i)é[a-c]*",
        "[é€]+",
        "\\x{FFFD}+",
        "a\\b",
        "[a-cé]{3}a[a-cé]*",
        "\\Bé|b\\b",
        "[\\x{80}-\\x{7ff}]+$",
        // The forward pass's start (`FindDfa.Track`): a later start that
        // joins live threads, or matches empty beside them, while they die.
        " ab|\\b",
        "é[ab]c|\\B",
        "a[bc]*a|b",
        "(?:ab|b)c",
        "ab|ba|a",
        "_?a|_b",
    };
    const text = try gpa.alloc(u8, 3000);
    defer gpa.free(text);
    var fills: usize = 0;
    for (patterns) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        // Full-size tables, and tables that fill and empty while reading.
        for ([_]bool{ false, true }) |small| {
            var m = try Matcher.init(gpa, &re);
            defer m.deinit();
            m.dfa_eager = true;
            m.dfa_small = small;
            for (0..24) |round| {
                const len = if (round % 4 == 0) text.len - 4 else rng.uintLessThan(usize, 120);
                // Odd rounds: mostly two-byte letters, rarely the rest.
                const np: usize = if (round % 2 == 1) 10 else pieces.len;
                var n: usize = 0;
                while (n < len) {
                    const piece = pieces[if (round % 2 == 1 and rng.uintLessThan(usize, 50) == 0) rng.uintLessThan(usize, pieces.len) else rng.uintLessThan(usize, np)];
                    @memcpy(text[n..][0..piece.len], piece);
                    n += piece.len;
                }
                const t = text[0..n];
                errdefer std.debug.print("/{s}/ small={} on \"{f}\"\n", .{ p, small, std.zig.fmtString(t) });
                var it = m.iterator(t);
                var pit = pm.iterator(t);
                while (true) {
                    const a = it.next();
                    try testing.expectEqual(pit.next(), a);
                    if (a == null) break;
                }
                var from: usize = 0;
                while (from <= t.len) : (from += 7) try testing.expectEqual(pm.find(t, from), m.find(t, from));
            }
            if (small) {
                const d = m.dfa.?;
                fills += @intFromBool(d.flushes > 0 or d.states.items.len == d.limit);
            }
        }
    }
    try testing.expect(fills >= 8);
    // `\b\w+\b` over accented words: each accented letter ends a match and
    // the scan past it moves a byte or two — it gives up, and the steps over
    // the two-byte letters are cached instead.
    var re = try Regex.compile(gpa, "\\b\\w+\\b");
    defer re.deinit(gpa);
    var m = try Matcher.init(gpa, &re);
    defer m.deinit();
    m.dfa_eager = true;
    var n: usize = 0;
    while (n + 8 <= text.len) : (n += 8) text[n..][0..8].* = "ab\xc3\xa9cd\xc5\xbe".*;
    var it = m.iterator(text[0..n]);
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    try testing.expectEqual(2 * n / 8, count);
    try testing.expect(m.dfa.?.scan_score <= -FindDfa.scan_give_up);
    for (m.dfa.?.states.items) |st| {
        if (st.mid != 0) break;
    } else return error.TestExpectedMidState;
}

test "FindDfa: the start read off the forward pass, and where it must not be" {
    const gpa = testing.allocator;
    const Case = struct { []const u8, []const u8, ?Span };
    const cases = [_]Case{
        // The empty match at the boundary is the only one: the thread that
        // began at 0 dies at `c`.
        .{ " ab|\\b", " ac", .{ .start = 1, .end = 1 } },
        // A later start joins (`b` at 1) while `ab` lives, and wins.
        .{ "abd|bc", "abc", .{ .start = 1, .end = 3 } },
        // Begun in a two-byte sequence: the start is its lead byte.
        .{ "é+", "xxéé", .{ .start = 2, .end = 6 } },
        .{ "[éa]b", "ééb", .{ .start = 2, .end = 5 } },
    };
    for (cases) |c| {
        var re = try Regex.compile(gpa, c[0]);
        defer re.deinit(gpa);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.dfa_eager = true;
        errdefer std.debug.print("/{s}/ on \"{s}\"\n", .{ c[0], c[1] });
        try testing.expectEqual(c[2], m.find(c[1], 0));
        try testing.expect(m.dfa != null);
    }
}

test "FindDfa.intern: one state per (list, context, restart), wherever their probes meet" {
    const gpa = testing.allocator;
    var re = try Regex.compile(gpa, "\\ba");
    defer re.deinit(gpa);
    var d: FindDfa = .init(gpa, &re);
    defer d.deinit();
    // 60 lists × 4 contexts = 240 states in a 512-slot table: probes of
    // states that differ in their context alone cross for sure.
    const ctxs = [_]Dfa.Ctx{ .start, .newline, .word, .other };
    var ids: [60][4]u16 = undefined;
    for (0..60) |i| {
        const list = [_]u16{ @intCast(i), @intCast(i * 7 % 13) };
        for (ctxs, 0..) |ctx, j| {
            const r = try d.intern(&list, ctx, false);
            try testing.expect(!r.flushed);
            ids[i][j] = r.id;
        }
    }
    try testing.expectEqual(@as(usize, 240), d.states.items.len);
    for (0..60) |i| {
        const list = [_]u16{ @intCast(i), @intCast(i * 7 % 13) };
        for (ctxs, 0..) |ctx, j| try testing.expectEqual(ids[i][j], (try d.intern(&list, ctx, false)).id);
    }
}

test "the backtracker and the Pike VM agree on long texts, past the bit budget and the job cap" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x6274);
    const rng = prng.random();
    const text = try gpa.alloc(u8, 40_000);
    defer gpa.free(text);
    for (text) |*c| c.* = "abcAB -1\n"[rng.uintLessThan(usize, 9)];
    const patterns = [_][]const u8{ "(a+)(b*)c", "AB-1", "(?:a|b)*?c(A)", "((a)|b)+?B", "x*", "[ab]{3,}(c|\\n)", "(a*)*(b*)*c?$", "AB-1(a|b)\\n", "1\\n([ab]{2}) c", "(?:b|[ab]{40})A{2}" };
    var ga: [8]?Span = undefined;
    var gb: [8]?Span = undefined;
    for (patterns) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        m.onepass_off = true;
        var pm = try Matcher.init(gpa, &re);
        defer pm.deinit();
        pm.pike_only = true;
        const ng = re.names.len;
        // Every match over the whole text: for the larger programs the
        // backtracker's window (budget / instructions) is shorter than the
        // text, so it moves from one sparse match to the next, or runs off
        // its end into the Pike VM.
        var it = m.iterator(text);
        var pit = pm.iterator(text);
        while (true) {
            const s1 = it.nextCaptures(ga[0..ng]);
            const s2 = pit.nextCaptures(gb[0..ng]);
            errdefer std.debug.print("/{s}/ find-all at {any}\n", .{ p, s2 });
            try testing.expectEqual(s2, s1);
            if (s1 == null) break;
            try testing.expectEqualSlices(?Span, gb[0..ng], ga[0..ng]);
        }
        // Starts from far (Pike) to near the end (backtracker), each window length.
        for ([_]usize{ 0, 100, 20_000, 39_000, 39_900, 39_990, 40_000 }) |from| {
            for ([_]usize{ 40, 300, 5_000, 40_000 }) |len| {
                const in = text[0..@min(from + len, text.len)];
                if (from > in.len) continue;
                const f1 = m.captures(in, from, ga[0..ng]);
                const f2 = pm.captures(in, from, gb[0..ng]);
                errdefer std.debug.print("/{s}/ from {d} len {d}\n", .{ p, from, in.len });
                try testing.expectEqual(f2, f1);
                if (f1) try testing.expectEqualSlices(?Span, gb[0..ng], ga[0..ng]);
            }
        }
    }
    // A program that needs more pending branches than the cap: the search is
    // handed to the Pike VM and still answers.
    var deep = try Regex.compile(gpa, "((?:a|b))*c");
    defer deep.deinit(gpa);
    const long = strRepeat("a", 20_000) ++ "c";
    try testing.expect(deep.insts.len * long.len < Matcher.max_backtrack_bits); // the bits fit,
    var dm = try Matcher.init(gpa, &deep);
    defer dm.deinit();
    dm.onepass_off = true;
    var dg: [2]?Span = undefined;
    try testing.expect(dm.captures(long, 0, &dg));
    try testing.expect(dm.bt_jobs.capacity >= Matcher.max_backtrack_jobs); // the jobs did not
    try testing.expectEqual(Span{ .start = 0, .end = long.len }, dg[0].?);
    try testing.expectEqual(Span{ .start = long.len - 2, .end = long.len - 1 }, dg[1].?);
}

test "isMatch past the DFA's size: a prefilter skip starts with a fresh closure" {
    // bxp 2026-10-19 (differential driver vs Go): 129 instructions, so `runSetOn`
    // answers. The threads die after `a` with `\b` visited (it fails between
    // `a` and `1`); the skip to ` ` reused that `seen` and never walked `\b`
    // again, where it holds. Go: MatchString true, FindIndex [2 3].
    const gpa = testing.allocator;
    var re = try Regex.compile(gpa, "a?\\b+(  *((xxxxa+)xx|()+){2}){1,3}");
    defer re.deinit(gpa);
    try testing.expect(re.insts.len > Dfa.max_insts);
    try testing.expect(re.prefilter.first != null);
    try testing.expect(re.isMatch("a1 "));
    const s = (try re.find(gpa, "a1 ")).?;
    try testing.expectEqual(@as(usize, 2), s.start);
    try testing.expectEqual(@as(usize, 3), s.end);
}

test "Pike VM: a prefilter skip starts with a fresh closure" {
    // The same stale `seen` in `runOn` (found by the fuzz harness once it drew
    // `a?^`-shaped starts): the threads die after the ` ` before `a`, with `^`
    // visited and failing there; after the skip to `a` past the newline it
    // was never walked again. Go (CompilePOSIX, ^ = line start): [4 6].
    const gpa = testing.allocator;
    const in = " a \nabÉ";
    var re = try Regex.compilePosix(gpa, "(a?^[a-][^a])");
    defer re.deinit(gpa);
    const s = (try re.find(gpa, in)).?;
    try testing.expectEqual(@as(usize, 4), s.start);
    try testing.expectEqual(@as(usize, 6), s.end);
    // Leftmost-first reaches `runOn` when the backtracker hands over.
    var re2 = try Regex.compile(gpa, "(?m)(a?^[a-][^a])");
    defer re2.deinit(gpa);
    var pm = try Matcher.init(gpa, &re2);
    defer pm.deinit();
    pm.pike_only = true;
    const s2 = pm.find(in, 0).?;
    try testing.expectEqual(@as(usize, 4), s2.start);
    try testing.expectEqual(@as(usize, 6), s2.end);
}

test "end-anchored patterns: which ones, and the backward DFA agrees with the NFA" {
    const gpa = testing.allocator;
    // Which programs read backwards: every path to the match through `\z`,
    // and not anchored at the start too.
    for ([_]struct { []const u8, bool }{
        .{ "a$", true },     .{ "a\\z", true },     .{ "(?:a|bc)+$", true }, .{ "(a$)", true },
        .{ "a$|b$", true },  .{ "a*$", true },      .{ "a$b", false },       .{ "a$|b", false },
        .{ "^a$", false },   .{ "\\Aa$|b$", true }, .{ "(?m)a$", false },    .{ "a", false },
        .{ "a\\zb", false }, .{ "(?:a$)?", false }, .{ "\\bx\\b$", true },
    }) |case| {
        var re = try Regex.compile(gpa, case[0]);
        defer re.deinit(gpa);
        errdefer std.debug.print("/{s}/\n", .{case[0]});
        try testing.expectEqual(case[1], re.prefilter.end_anchored);
    }
    // The last-byte set: none when a match can be empty or end anywhere.
    for ([_]struct { []const u8, ?[4]u64 }{
        .{ "ab$", .{ 0, @as(u64, 1) << ('b' - 64), 0, 0 } },
        .{ "(?i)z$", .{ 0, (@as(u64, 1) << ('z' - 64)) | (@as(u64, 1) << ('Z' - 64)), 0, 0 } },
        .{ "č$", .{ 0, 0, ~@as(u64, 0), 0 } },
        .{ "[^a]$", .{ ~@as(u64, 0), ~(@as(u64, 1) << ('a' - 64)), ~@as(u64, 0), ~@as(u64, 0) } },
        .{ "a*$", null },
        .{ "a.$", null },
        .{ "\\x{FFFD}$", .{ 0, 0, ~@as(u64, 0), ~@as(u64, 0) } },
    }) |case| {
        var re = try Regex.compile(gpa, case[0]);
        defer re.deinit(gpa);
        errdefer std.debug.print("/{s}/\n", .{case[0]});
        try testing.expectEqual(case[1], re.prefilter.last);
    }
    // The tail: each level from the end, its one or two bytes.
    for ([_]struct { []const u8, []const u8 }{
        .{ "ABCZ$", "ZZCCBBAA" },     .{ "(?i)ab$", "BbAa" },    .{ "x[ab]$", "abxx" },
        .{ "[abc]$", "" },            .{ "a+$", "aa" },
        .{ "č$", "" },
        .{ "\\d{3}$", "" },           .{ "(?:ab|cb)$", "bbac" }, .{ "a\\bb$", "bbaa" },
        .{ "Q[ -~]*XYZ$", "ZZYYXX" },
    }) |case| {
        var re = try Regex.compile(gpa, case[0]);
        defer re.deinit(gpa);
        errdefer std.debug.print("/{s}/\n", .{case[0]});
        const pf = &re.prefilter;
        try testing.expectEqualSlices(u8, case[1], std.mem.sliceAsBytes(pf.tail[0..pf.tail_len]));
    }

    var prng: std.Random.DefaultPrng = .init(0x726576);
    const rng = prng.random();
    // `[ab]{5}a(a|b)*$` needs 2^6 states backwards, twice the table. The
    // pieces include a truncated `€`, a lone continuation and a lone lead
    // byte: the backward decoder must cut the text as the forward one does.
    const patterns = [_][]const u8{
        "[ab]{5}a(?:a|b)*$", "ab$",             "(?:a|b)*$",    "\\ba[ab]*\\b$",
        "\\B[ab]č$",
        "(?i)[áa]b$",
        "[^ab\\n]a{2}$",
        "(?:a|€|č)+$",
        "\\pL$",             "(?:\\n|^)b$",     "(?m)^a[ab]*$", ".$",
        "(?s).{3}$",         "a$|b$",           "\\Aab|ba$",    "\\x{FFFD}$",
        "[^a]$",             "(?:ab|a)(?:b)?$", "a$b",          "\\b$",
    };
    const pieces = [_][]const u8{ "a", "a", "b", "b", "\n", "č", "€", "\xe2\x82", "\x82", "\xc3", " ", "Á", "\xff" };
    for (patterns) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        try testing.expect(re.insts.len <= Dfa.max_insts);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        for (0..400) |round| {
            var text: [600]u8 = undefined;
            var len: usize = 0;
            const n = rng.uintLessThan(usize, if (round < 200) 16 else 400);
            while (len < n) {
                const piece = pieces[rng.uintLessThan(usize, pieces.len)];
                @memcpy(text[len..][0..piece.len], piece);
                len += piece.len;
            }
            const in = text[0..len];
            var r: std.Io.Reader = .fixed(in);
            const nfa = try re.isMatchReader(&r);
            errdefer std.debug.print("/{s}/ on \"{f}\"\n", .{ p, std.zig.fmtString(in) });
            try testing.expectEqual(nfa, m.find(in, 0) != null);
            try testing.expectEqual(nfa, re.isMatch(in));
            if (re.prefilter.end_anchored) {
                try testing.expectEqual(nfa, re.runRevDfa(in, RevDfa.max_states).?);
                // A table of two: emptied at nearly every step, in either state.
                try testing.expectEqual(nfa, re.runRevDfa(in, 2).?);
            }
        }
    }
    // Long reads back that only a `_` ends: with a table of two, the flush
    // also comes in state 0, whose row it refills first.
    {
        var re = try Regex.compile(gpa, "_[ab]{3}a[ab]*$");
        defer re.deinit(gpa);
        for (0..2000) |_| {
            var text: [60]u8 = undefined;
            const n = 1 + rng.uintLessThan(usize, text.len);
            text[0] = '_';
            for (text[1..n]) |*c| c.* = "ab_"[rng.uintLessThan(usize, if (rng.uintLessThan(u8, 8) == 0) 3 else 2)];
            const in = text[0..n];
            var r: std.Io.Reader = .fixed(in);
            const nfa = try re.isMatchReader(&r);
            errdefer std.debug.print("\"{s}\"\n", .{in});
            try testing.expectEqual(nfa, re.runRevDfa(in, 2).?);
            try testing.expectEqual(nfa, re.isMatch(in));
        }
    }
    // The backward decoder cuts every text as the forward one does.
    for (0..2000) |_| {
        var text: [40]u8 = undefined;
        for (&text) |*c| c.* = ([_]u8{ 'a', 0x82, 0xac, 0xe2, 0xc3, 0xa1, 0xf0, 0x9f, 0x98, 0x80, 0xff, 0xed, 0xa0 })[rng.uintLessThan(u8, 13)];
        var cuts: [41]usize = undefined;
        var nc: usize = 0;
        var i: usize = 0;
        while (i < text.len) : (i += decode(&text, i).w) {
            cuts[nc] = i;
            nc += 1;
        }
        var e: usize = text.len;
        while (e > 0) {
            const d = decodeBefore(&text, e);
            e -= d.w;
            nc -= 1;
            try testing.expectEqual(cuts[nc], e);
            try testing.expectEqual(decode(&text, e).cp, d.cp);
        }
        try testing.expectEqual(0, nc);
    }
}

test "the lazy DFA agrees with the NFA: more states than its table, assertions, non-ASCII" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x646661);
    const rng = prng.random();
    // `(a|b)*a(a|b){6}` needs 2^7 states, four times the table: it is
    // emptied and refilled many times over one text.
    const patterns = [_][]const u8{
        "(a|b)*a(a|b){6}$",   "(a|b)*a(a|b){6}c", "\\ba[ab]{5}\\b", "(?m)^b[ab]*a$",
        "(?m)^(?:ab|ba)+\\n",
        "\\B[ab]{3}č",
        "(?i)[áa]{2}[bB]{2}",
        "[^ab\\n]a{3}",
        "(?:a|b|č)*ač{2}",
        "\\Aa(?:b|a)*\\z",    "a{0,3}$",
    };
    for (patterns) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        try testing.expect(re.insts.len <= Dfa.max_insts);
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        for (0..300) |round| {
            var text: [600]u8 = undefined;
            var len: usize = 0;
            const n = rng.uintLessThan(usize, if (round < 100) 24 else 400);
            while (len < n) {
                const piece: []const u8 = switch (rng.uintLessThan(u8, 12)) {
                    0...4 => "a",
                    5...8 => "b",
                    9 => "\n",
                    10 => "č",
                    else => " ",
                };
                @memcpy(text[len..][0..piece.len], piece);
                len += piece.len;
            }
            const in = text[0..len];
            // The NFA: through a reader (`runSetOn`), and the Matcher's find.
            var r: std.Io.Reader = .fixed(in);
            const nfa = try re.isMatchReader(&r);
            errdefer std.debug.print("/{s}/ on \"{f}\"\n", .{ p, std.zig.fmtString(in) });
            try testing.expectEqual(nfa, re.isMatch(in));
            try testing.expectEqual(m.find(in, 0) != null, re.isMatch(in));
            var t: SliceText = .{ .input = in };
            try testing.expectEqual(re.runSetOn(&t, true), re.fullMatch(in));
        }
    }
    // Long texts: the tables are emptied hundreds of times per text, some of
    // them while the DFA stands in the state about to be renumbered 0. The
    // anchored pattern's states carry the parity of the position, so one
    // wrong transition shows in the answer however far from the end it was.
    var long: [20_000]u8 = undefined;
    for ([_][]const u8{ "(a|b)*a(a|b){6}c", "(?:a|b)*b(?:a|b){5}(?:\\b|a)c", "\\A(?:[ab][ab])*a[ab]{12}c" }) |p| {
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        for (0..24) |_| {
            for (&long) |*c| c.* = "ab"[rng.uintLessThan(u8, 2)];
            long[long.len - 1] = 'c';
            var r: std.Io.Reader = .fixed(&long);
            errdefer std.debug.print("/{s}/ on a long text\n", .{p});
            try testing.expectEqual(try re.isMatchReader(&r), re.isMatch(&long));
            for ([_]usize{ 200, 3_000, 19_999 }) |cut| {
                var r2: std.Io.Reader = .fixed(long[0..cut]);
                try testing.expectEqual(try re.isMatchReader(&r2), re.isMatch(long[0..cut]));
            }
        }
    }
}

test "the backtracker's window: an exploration that reaches its very end is handed over" {
    // A program whose window (budget / instructions) is a whole number of
    // 64-bit words, on a text longer than the window that `[ab]*` runs
    // through to the end: the walk reaches the first position past the window.
    const gpa = testing.allocator;
    var src: [80]u8 = undefined;
    var found = false;
    for (1..60) |k| {
        const p = try std.mem.print(&src, "a[ab]*{s}", .{(strRepeat("c", 60))[0..k]});
        var re = try Regex.compile(gpa, p);
        defer re.deinit(gpa);
        const n = re.insts.len;
        const width = Matcher.max_backtrack_bits / n;
        if (width * n % 64 != 0) continue;
        found = true;
        const text = try gpa.alloc(u8, width + 50);
        defer gpa.free(text);
        for (text, 0..) |*c, i| c.* = "ab"[i % 2];
        var m = try Matcher.init(gpa, &re);
        defer m.deinit();
        try testing.expectEqual(@as(?Span, null), m.find(text, 0));
        // Followed by a match: found, by the Pike VM, from where the walk stopped.
        @memcpy(text[text.len - k ..], (strRepeat("c", 60))[0..k]);
        try testing.expectEqual(@as(?Span, .{ .start = 0, .end = text.len }), m.find(text, 0));
    }
    try testing.expect(found);
}

test "surrogates compile and match nothing; Expand takes the first group of a name that took part" {
    const gpa = testing.allocator;
    var s = try Regex.compile(gpa, "a\\x{D800}");
    defer s.deinit(gpa);
    try testing.expect(!s.isMatch("a\xed\xa0\x80"));
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try testing.expect(try s.literalPrefix(&out.writer)); // Go: "a\u{fffd}", complete
    try testing.expectEqualStrings("a\u{fffd}", out.written());
    const cs = comptime comptimeCompile("[\\x{D800}]");
    try testing.expect(!cs.isMatch("\u{fffd}"));

    var d = try Regex.compile(gpa, "(?P<n>a)|(?P<n>b)");
    defer d.deinit(gpa);
    const r = try d.replaceAll(gpa, "xaby", "[$n|${n}|${a b}|${1 }]");
    defer gpa.free(r);
    try testing.expectEqualStrings("x[a|a|${a b}|${1 }][b|b|${a b}|${1 }]y", r);
}

test "a reader that fails after the answer is settled does not turn it into an error" {
    const Half = struct {
        r: std.Io.Reader,
        left: []const u8,
        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const self: *@This() = @fieldParentPtr("r", r);
            if (self.left.len == 0) return error.ReadFailed;
            const n = limit.minInt(self.left.len);
            try w.writeAll(self.left[0..n]);
            self.left = self.left[n..];
            return n;
        }
    };
    var re = try Regex.compile(testing.allocator, "ab");
    defer re.deinit(testing.allocator);
    var buf: [8]u8 = undefined;
    var h: Half = .{ .r = .{ .vtable = &.{ .stream = Half.stream }, .buffer = &buf, .seek = 0, .end = 0 }, .left = "xab" };
    try testing.expect(try re.isMatchReader(&h.r)); // fails right after "ab"
    var buf2: [8]u8 = undefined;
    var h2: Half = .{ .r = .{ .vtable = &.{ .stream = Half.stream }, .buffer = &buf2, .seek = 0, .end = 0 }, .left = "xa" };
    try testing.expectError(error.ReadFailed, re.isMatchReader(&h2.r));
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
    const input = strRepeat("a", 5000) ++ "b";
    try testing.expect(!re.isMatch(input));
    try testing.expect((try re.find(testing.allocator, input)) == null);
}

test "invalid UTF-8 in the input reads as U+FFFD, one byte" {
    try expectFind("a.b", "a\xffb", "a\xffb");
    try expectFind("\\x{fffd}", "x\xfey", "\xfe");
}

test {
    _ = syntax;
    _ = teddy;
    _ = @import("go_oracle_test.zig");
    _ = @import("rust_oracle_test.zig");
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
            // The backtracker and the Pike VM find the same match and groups.
            var pm = try Matcher.init(testing.allocator, &re);
            defer pm.deinit();
            pm.pike_only = true;
            var g1: [max_groups]?Span = undefined;
            var g2: [max_groups]?Span = undefined;
            const ng = re.names.len;
            for (0..in.len + 1) |from| {
                const f1 = m.captures(in, from, g1[0..ng]);
                const f2 = pm.captures(in, from, g2[0..ng]);
                try testing.expectEqual(f2, f1);
                if (f1) try testing.expectEqualSlices(?Span, g2[0..ng], g1[0..ng]);
            }
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
    // The literal prefix, from two bytes on, is searched for whole.
    const Lit = struct { p: []const u8, lit: []const u8 };
    for ([_]Lit{
        .{ .p = "id=([0-9]+)", .lit = "id=" },
        .{ .p = "INV-\\d|INV-x", .lit = "INV-" },
        .{ .p = "(?i)abc", .lit = "" },
        .{ .p = "a\\x{fffd}b", .lit = "a" }, // U+FFFD also matches an invalid byte
        .{ .p = strRepeat("x", 40), .lit = strRepeat("x", 16) },
    }) |c| {
        var re = try Regex.compile(testing.allocator, c.p);
        defer re.deinit(testing.allocator);
        try testing.expectEqualStrings(c.lit, re.prefilter.lit[0..re.prefilter.lit_len]);
    }
    try expectFind("a\\x{fffd}b", "xa\xffb", "a\xffb");
    try expectFind("id=([0-9]+)", "i id id=7", "id=7");
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

test "prefilter: the literal prefixes of every match, searched for together (Teddy)" {
    const Case = struct { p: []const u8, n: ?u8, masks: u8 = 0 };
    for ([_]Case{
        .{ .p = "ABCD|CDEF|EFGH|GHIJ|IJKL|KLMN|MNOP|OPQR|QRST|STUV|UVWX|WXYZ", .n = 12, .masks = 3 },
        .{ .p = "(?i)abc", .n = 8, .masks = 3 },
        .{ .p = "(?i)abcdefghij", .n = 16, .masks = 3 }, // 2^8 at eight bytes: cut to four
        .{ .p = "[ab][cd][ef][gh][ij][kl]", .n = 16, .masks = 3 },
        .{ .p = "foo\\d|bar\\d", .n = 2, .masks = 3 },
        .{ .p = "é|ü", .n = 2, .masks = 2 },
        .{ .p = "ab|abcd|cd", .n = 2, .masks = 2 }, // `abcd` is covered by `ab`
        .{ .p = "(ab|cd)(?m:^)x|\\bef", .n = 3, .masks = 2 }, // assertions passed
        .{ .p = "a|bc", .n = null }, // one byte
        .{ .p = "ab|c\\d", .n = null }, // `c`, then a class of ten
        .{ .p = "x*y|zz", .n = null }, // `y`
        .{ .p = "ab|.c", .n = null },
        .{ .p = "ab|cd|", .n = null }, // can be empty
        .{ .p = "ab|c\\x{fffd}", .n = null }, // U+FFFD also reads an invalid byte
        .{ .p = "abc|abd", .n = null }, // the literal `ab` instead
        .{ .p = "^ab|^cd", .n = null }, // anchored
    }) |c| {
        errdefer std.debug.print("/{s}/\n", .{c.p});
        var re = try Regex.compile(testing.allocator, c.p);
        defer re.deinit(testing.allocator);
        if (c.n) |n| {
            const t = re.prefilter.teddy orelse return error.NoTeddy;
            try testing.expectEqual(n, t.n);
            try testing.expectEqual(c.masks, t.masks);
        } else try testing.expect(re.prefilter.teddy == null);
    }
    // A surrogate is never read, an invalid sequence reads as U+FFFD.
    try expectFind("[\\x{D7FF}\\x{D800}]x|yz", "\xed\xa0\x80x", null);
    try expectFind("[\\x{D7FF}\\x{D800}]x|yz", "a\u{d7ff}x", "\u{d7ff}x");
    // A walk past its budget at eight bytes fits when cut shorter.
    {
        var re = try Regex.compile(testing.allocator, "(?i)[ab][cd][ef][gh][ij][kl][mn][op]|zz");
        defer re.deinit(testing.allocator);
        try testing.expect(re.prefilter.teddy != null);
    }
    // Also at compile time.
    const ct = comptime comptimeCompile("ABCD|CDEF|EFGH");
    try testing.expectEqual(@as(u8, 3), ct.prefilter.teddy.?.n);
}

test "Teddy.find agrees with a scan for the first prefix, over and past the 32-byte lanes" {
    var prng: std.Random.DefaultPrng = .init(0x7465_6464_79);
    const rng = prng.random();
    const alpha = "abcdAB\xc3\xa9";
    var pat_buf: [256]u8 = undefined;
    var hay: [200]u8 = undefined;
    var built: usize = 0;
    for (0..3000) |_| {
        // An alternation of literals over a small alphabet, `(?i)` now and then.
        var w: std.Io.Writer = .fixed(&pat_buf);
        if (rng.uintLessThan(u8, 4) == 0) try w.writeAll("(?i)");
        const alts = rng.intRangeAtMost(usize, 1, 14);
        for (0..alts) |k| {
            if (k != 0) try w.writeByte('|');
            for (0..rng.intRangeAtMost(usize, 2, 5)) |_| try w.writeByte("abcdAB"[rng.uintLessThan(usize, 6)]);
        }
        var re = try Regex.compile(testing.allocator, w.buffered());
        defer re.deinit(testing.allocator);
        const t = re.prefilter.teddy orelse continue;
        built += 1;
        const hl = rng.uintLessThan(usize, hay.len + 1);
        for (hay[0..hl]) |*b| b.* = alpha[rng.uintLessThan(usize, alpha.len)];
        const in = hay[0..hl];
        const from = rng.uintLessThan(usize, hl + 1);
        const want: ?usize = for (from..in.len) |i| {
            const hit = for (t.pats[0..t.n], t.lens[0..t.n]) |*p, l| {
                if (std.mem.startsWith(u8, in[i..], p[0..l])) break true;
            } else false;
            if (hit) break i;
        } else null;
        errdefer std.debug.print("/{s}/ from {d} in \"{f}\"\n", .{ w.buffered(), from, std.zig.fmtString(in) });
        try testing.expectEqual(want, t.find(in, from));
        // The prefilter only skips: the same program without it agrees.
        var bare = re;
        bare.prefilter = .{};
        try testing.expectEqual(bare.isMatch(in), re.isMatch(in));
        var m = try Matcher.init(testing.allocator, &re);
        defer m.deinit();
        var bm = try Matcher.init(testing.allocator, &bare);
        defer bm.deinit();
        try testing.expectEqual(bm.find(in, from), m.find(in, from));
        var it = m.iterator(in);
        var bit = bm.iterator(in);
        while (bit.next()) |s| try testing.expectEqual(s, it.next().?);
        try testing.expect(it.next() == null);
    }
    try testing.expect(built > 2000); // one alternative or a common literal: no Teddy
}

test "findLiteral agrees with std.mem.findPos" {
    var prng: std.Random.DefaultPrng = .init(0x6c6974);
    const rng = prng.random();
    var hay: [300]u8 = undefined;
    var needle: [6]u8 = undefined;
    for (0..5000) |_| {
        const hl = rng.uintLessThan(usize, hay.len);
        for (hay[0..hl]) |*c| c.* = "abAB"[rng.uintLessThan(usize, 4)];
        const nl = 2 + rng.uintLessThan(usize, needle.len - 1);
        for (needle[0..nl]) |*c| c.* = "abAB"[rng.uintLessThan(usize, 4)];
        const pos = rng.uintLessThan(usize, hl + 1);
        try testing.expectEqual(std.mem.findPos(u8, hay[0..hl], pos, needle[0..nl]), findLiteral(hay[0..hl], pos, needle[0..nl]));
    }
}

test "compile: a pattern past the stack builder's capacity takes the full one" {
    var re = try Regex.compile(testing.allocator, "a{600}");
    defer re.deinit(testing.allocator);
    try testing.expect(re.insts.len > small_capacity.insts);
    try testing.expect(re.fullMatch(strRepeat("a", 600)));
}

test "compile: a pattern past max_insts compiles on the heap and matches" {
    var re = try Regex.compile(testing.allocator, "a{1000}b{1000}");
    defer re.deinit(testing.allocator);
    try testing.expect(re.insts.len > max_insts);
    const text = strRepeat("a", 1000) ++ strRepeat("b", 1000);
    // Up to 4 * max_insts: the stack variants; any size: the `*Alloc` ones.
    try testing.expect(re.fullMatch(text));
    try testing.expect(!re.isMatch(text[1..]));
    try testing.expect(try re.fullMatchAlloc(testing.allocator, text));
    try testing.expectEqual(@as(?usize, 2001), try re.shortestMatchAlloc(testing.allocator, "x" ++ text));
    try testing.expectEqual(@as(?usize, null), try re.shortestMatchAlloc(testing.allocator, "x" ++ text[1..]));
    var m = try Matcher.init(testing.allocator, &re);
    defer m.deinit();
    try testing.expectEqual(@as(?Span, .{ .start = 1, .end = 2001 }), m.find("x" ++ text, 0));
    // Past what `isMatch` keeps on the stack: only `isMatchAlloc`.
    var huge = try Regex.compile(testing.allocator, "a{1000}b{1000}c{1000}d{1000}e{1000}");
    defer huge.deinit(testing.allocator);
    try testing.expect(huge.insts.len > 4 * max_insts);
    const all = strRepeat("a", 1000) ++ strRepeat("b", 1000) ++ strRepeat("c", 1000) ++ strRepeat("d", 1000) ++ strRepeat("e", 1000);
    try testing.expect(try huge.isMatchAlloc(testing.allocator, "x" ++ all));
    try testing.expect(!try huge.isMatchAlloc(testing.allocator, all[1..]));
    try testing.expect(try huge.fullMatchAlloc(testing.allocator, all));
    // `matches` compiles and matches any size (it panicked: review 2026-10-28).
    try testing.expect(!try matches(testing.allocator, "a{1000}b{1000}c{1000}d{1000}e{1000}", "x"));
}

test "RegexSet: a joined range table past a u16 is refused, not wrapped" {
    // Fuzz 2026-10-28: 160 × `\pL` summed the range offsets in a u16 — a
    // panic in safe builds, rune instructions reading the wrong ranges in
    // ReleaseFast.
    const pats: [160][]const u8 = @splat("\\pL");
    try testing.expectError(error.PatternTooLarge, RegexSet.compile(testing.allocator, &pats, .{}));
    var set = try RegexSet.compile(testing.allocator, pats[0..60], .{});
    defer set.deinit(testing.allocator);
    var out: [60]bool = undefined;
    try testing.expect(set.matches("1é", &out));
    try testing.expect(!set.isMatch("1 2"));
}

test "findAnchored / capturesAnchored: a match that starts at from, in every engine" {
    const gpa = testing.allocator;
    const Case = struct { []const u8, Options, []const u8, usize, ?Span };
    for ([_]Case{
        .{ "b+", .{}, "abbb", 0, null },
        .{ "b+", .{}, "abbb", 1, .{ .start = 1, .end = 4 } },
        .{ "b+", .{}, "abbb", 2, .{ .start = 2, .end = 4 } },
        .{ "b+|a", .{}, "xab", 0, null }, // `find` would report 1..2
        // The text before `from` stays in view: no word boundary inside "bb".
        .{ "\\bb", .{}, "abb", 2, null },
        .{ "\\bb", .{}, "a b", 2, .{ .start = 2, .end = 3 } },
        .{ "(?i)ab|a", .{ .longest = true }, "xAB", 1, .{ .start = 1, .end = 3 } },
        .{ "\\b{start}\\w+", .{ .syntax = .rust }, "é žluť", 3, .{ .start = 3, .end = 9 } },
        .{ "(?-u:\\xff)a", .{ .syntax = .rust, .utf8 = false }, "a\xffa\xffa", 1, .{ .start = 1, .end = 3 } },
        .{ "(?-u:\\xff)a", .{ .syntax = .rust, .utf8 = false }, "a\xffa\xffa", 2, null },
        .{ "a{1000}b{1000}|x", .{}, "yx", 1, .{ .start = 1, .end = 2 } }, // heap tier
    }) |c| {
        var re = try Regex.compileOptions(gpa, c[0], c[1]);
        defer re.deinit(gpa);
        for ([_]bool{ false, true }) |pike| {
            var m = try Matcher.init(gpa, &re);
            defer m.deinit();
            m.pike_only = pike;
            m.dfa_eager = true;
            errdefer std.debug.print("/{s}/ from {d} pike {}\n", .{ c[0], c[3], pike });
            try testing.expectEqual(c[4], m.findAnchored(c[2], c[3]));
            var out: [2]?Span = undefined;
            try testing.expectEqual(c[4] != null, m.capturesAnchored(c[2], c[3], &out));
            if (c[4]) |want| try testing.expectEqual(want, out[0].?);
            // The anchor is for the call only.
            try testing.expectEqual(re.isMatch(c[2]), m.find(c[2], 0) != null);
        }
    }
    // A one-pass program: `capturesAnchored` runs the one-pass engine at `from`.
    var op = try Regex.compile(gpa, "([a-z]+)-([0-9]+)");
    defer op.deinit(gpa);
    var m = try Matcher.init(gpa, &op);
    defer m.deinit();
    m.dfa_eager = true;
    var g: [3]?Span = undefined;
    try testing.expect(m.capturesAnchored("ab-12 cd-34", 1, &g));
    try testing.expectEqual(Span{ .start = 1, .end = 5 }, g[0].?);
    try testing.expect(m.capturesAnchored("ab-12 cd-34", 6, &g));
    try testing.expectEqual(Span{ .start = 9, .end = 11 }, g[2].?);
    try testing.expect(!m.capturesAnchored("ab-12 cd-34", 5, &g));
}

test "Rust nest height counts a concatenation; bytes-mode classes reach raw bytes" {
    // Mutation 2026-10-28: both survived the oracle replays.
    const gpa = testing.allocator;
    const open = strRepeat("(?:", 250);
    const close = strRepeat(")", 250);
    var one = try Regex.compileOptions(gpa, open ++ "a" ++ close, .{ .syntax = .rust });
    one.deinit(gpa);
    try testing.expectError(error.NestingDepth, Regex.compileOptions(gpa, open ++ "ab" ++ close, .{ .syntax = .rust }));

    var hi = try Regex.compileOptions(gpa, "(?-u)[\\x80-\\xff]{2}", .{ .syntax = .rust, .utf8 = false });
    defer hi.deinit(gpa);
    try testing.expect(hi.fullMatch("\xff\x80"));
    try testing.expect(hi.fullMatch("é")); // its two bytes, not the code point
    try testing.expect(!hi.fullMatch("\xffa"));

    // `(?-u)`: CRLF mode keeps `\r` out of a byte `.`; `(?i)` folds ASCII
    // letters only (no Kelvin sign for `k`).
    var dot = try Regex.compileOptions(gpa, "(?R-u:.)", .{ .syntax = .rust, .utf8 = false });
    defer dot.deinit(gpa);
    try testing.expect(dot.fullMatch("\xff"));
    try testing.expect(!dot.fullMatch("\r"));
    var k = try Regex.compileOptions(gpa, "(?i-u)k", .{ .syntax = .rust });
    defer k.deinit(gpa);
    try testing.expect(k.fullMatch("K"));
    try testing.expect(!k.fullMatch("\u{212a}"));
}

test "Rust class set operations under (?i) fold both sides first" {
    // Fuzz 2026-10-28: the folded left side was left unsorted, and the
    // symmetric difference came out as the union.
    const Case = struct { []const u8, []const u8, []const u8 };
    for ([_]Case{
        .{ "(?i)[a-c~~b-d]", "aAdD", "bBcC" },
        .{ "(?i)[a-c&&b-d]", "bBcC", "aAdD" },
        .{ "(?i)[a-c--b]", "aAcC", "bBdD" },
        .{ "(?i)[[:alpha:]--[a-c]]", "dDzZ\u{212a}", "aAcC1" },
    }) |c| {
        var re = try Regex.compileOptions(testing.allocator, c[0], .{ .syntax = .rust });
        defer re.deinit(testing.allocator);
        var it = std.unicode.Utf8View.initUnchecked(c[1]).iterator();
        while (it.nextCodepointSlice()) |s| try testing.expect(re.fullMatch(s));
        it = std.unicode.Utf8View.initUnchecked(c[2]).iterator();
        while (it.nextCodepointSlice()) |s| try testing.expect(!re.fullMatch(s));
    }
}

test "find from inside a code point: a Unicode assertion sees the text, in every engine" {
    // Fuzz 2026-10-28: the Pike VM took the U+FFFD it read for the byte at
    // 1 as the code point before 2; the backtracker reads `é` there.
    var re = try Regex.compileOptions(testing.allocator, "a|.\\b", .{ .syntax = .rust });
    defer re.deinit(testing.allocator);
    for ([_]bool{ false, true }) |pike| {
        var m = try Matcher.init(testing.allocator, &re);
        defer m.deinit();
        m.pike_only = pike;
        try testing.expectEqual(@as(?Span, .{ .start = 2, .end = 4 }), m.find("éé", 1));
        try testing.expectEqual(@as(?Span, .{ .start = 3, .end = 4 }), m.find("éé", 3));
        try testing.expectEqual(@as(?Span, .{ .start = 4, .end = 6 }), m.find("ééé", 1));
    }
}

test "deep nesting compiles (or is refused) on a 512 KiB thread stack" {
    const Run = struct {
        fn go(out: *[2]?anyerror) void {
            const deep = strRepeat("(?:", max_depth - 1) ++ "a*" ++ strRepeat(")", max_depth - 1);
            const deeper = strRepeat("(?:", max_depth + 1) ++ "a" ++ strRepeat(")", max_depth + 1);
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

test "POSIX stacked repetitions (a{1}{1}…, a**…, a??…) compile or are refused on a 512 KiB thread stack" {
    // POSIX lets a repetition repeat a repetition, and such a chain adds no
    // group depth: the tree is as deep as the node table allows, and the
    // recursive compiler follows it.
    const Run = struct {
        fn go(out: *[3]?anyerror) void {
            const counted = "a" ++ strRepeat("{1}", 2000);
            const star = "a" ++ strRepeat("*", 2000);
            const quest = "a" ++ strRepeat("?", 2000);
            var b = std.heap.page_allocator.create(Builder) catch unreachable;
            defer std.heap.page_allocator.destroy(b);
            out[0] = if (b.compileSyntax(counted, .posix)) |_| null else |e| e;
            out[1] = if (b.compileSyntax(star, .posix)) |_| null else |e| e;
            out[2] = if (b.compileSyntax(quest, .posix)) |_| null else |e| e;
        }
    };
    var out: [3]?anyerror = .{ null, null, null };
    const t = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, Run.go, .{&out});
    t.join();
    for (out) |e| try testing.expectEqual(@as(?anyerror, error.NestingDepth), e);
    // A few stacked repetitions stay valid.
    var ok = try Regex.compilePosix(testing.allocator, "a" ++ strRepeat("{1}", 60));
    ok.deinit(testing.allocator);
}

test "nested counted repetitions multiply, as Go limits them — no compile-time blow-up" {
    try testing.expectError(error.InvalidRepeatSize, Regex.compile(testing.allocator, "(?:(?:(?:a{0}){1000}){1000}){1000}"));
    try testing.expectError(error.InvalidRepeatSize, Regex.compile(testing.allocator, "(?:a{2}|b{600}){2}"));
    var ok = try Regex.compile(testing.allocator, "(?:(?:a{0}){100}){10}");
    ok.deinit(testing.allocator);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

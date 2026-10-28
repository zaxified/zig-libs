// SPDX-License-Identifier: MIT
//! Structure-aware harness over the whole module: a pattern drawn from the
//! grammar (literals, classes, Perl and POSIX classes, assertions, groups,
//! flags, every quantifier form, alternation) or that same text damaged
//! byte-wise, and an input over a small alphabet with invalid UTF-8.
//! Oracles:
//!
//!   - no crash, no hang, no leak (compile is `compile`-or-error; the
//!     driver's DebugAllocator sees the Matcher and the Regex freed);
//!   - `isMatch` ⇔ `Matcher.find` finds a match; `fullMatch` ⇒ `isMatch`;
//!   - with a literal prefix set (`Prefilter.teddy`): `isMatch` and `find`
//!     from every position as without the prefilter;
//!   - `captures` group 0 is `find`'s span; every group span lies inside it
//!     and inside the input, start ≤ end;
//!   - the iterator yields non-overlapping spans in increasing order, its
//!     first span is `find`'s, no empty span right after the previous one,
//!     no span splitting a code point, and it ends;
//!   - a literal-only pattern (no metacharacter drawn) matches exactly where
//!     `std.mem.find` finds it — a reference that shares no code;
//!   - the engines agree: the backtracker (short texts) and the Pike VM
//!     (`pike_only`) give the same match and groups; `find`'s DFA gives the
//!     Pike VM's span for every pattern's anchored twin `^(?:…)`;
//!   - the reader front end agrees with the slice one (one byte per read);
//!   - leftmost-longest starts where leftmost-first does and ends no earlier;
//!   - `replaceAll(.., "$0")` gives the input back; `replaceAllLiteral(.., "")`
//!     removes exactly the iterator's spans; split pieces are disjoint from
//!     the matches; every match begins with `literalPrefix`, and a complete
//!     prefix is matched in full; `quoteMeta(input)` matches the input exactly;
//!   - `findAnchored`/`capturesAnchored` from every start: `find`'s match
//!     when it starts there, else none (the Pike VM alike);
//!   - `shortestMatch` is null exactly when nothing matches, lies inside
//!     `find`'s span, and — for patterns without assertions — is the
//!     earliest end of any substring `fullMatch` takes; the `*Alloc`
//!     variants answer as the stack ones.
//!
//! A third of the patterns is drawn from a POSIX ERE grammar of its own
//! (bracket expressions with `[:class:]`, intervals, stacked repetitions
//! `a**` that only POSIX takes, now and then a Perl-only form for the
//! refusal path) and compiled with `compilePosix`. For leftmost-longest —
//! POSIX, and every pattern's `Longest` twin — a reference that shares no
//! engine with it: the leftmost start from which some substring matches in
//! full, and the longest such substring, by `fullMatch` (the DFA) over every
//! pair of code-point boundaries. Only for patterns without assertions, whose
//! meaning does not depend on the text around a substring.
//!
//! The Rust grammar (`Options.syntax = .rust`) and bytes mode (`utf8 =
//! false`) are drawn too, and every atom is written in both grammars with
//! the same meaning (Go's `\d` is Rust's `[0-9]`, Rust's `[a-c&&b-d]` is
//! Go's `[b-c]`, `(?x: a b )` is `(?:ab)`): while no atom only one grammar
//! can say was drawn, the `.perl` and `.rust` programs must give the same
//! matches and groups from every position. A bytes-mode pattern that
//! `&str` also takes gives, on valid UTF-8, `&str`'s match — or an earlier
//! empty one inside a code point, which only bytes mode may report. A third
//! of the drawn patterns also runs in a `RegexSet` with up to three others
//! (now and then with a hundred large classes, past what a set's range
//! table holds): a set reports exactly the patterns whose own `isMatch`
//! holds, and refuses exactly when one of them, or its size, is refused. A
//! share is padded past `max_insts` (compiled on the heap) and past
//! `4 * max_insts` (the `*Alloc` entry points only).
//!
//! The Go oracle (`go_oracle_test.zig`) is what holds the answers to Go's;
//! this holds the engine to itself over far more shapes. Planted mutants
//! (2026-10-07): the harness fails on a broken unanchored restart, a missing
//! leftmost-first cut, a broken range search, a lost capture restore, a
//! byte-wise iterator advance and a kept empty-adjacent match; it does NOT see
//! `_` dropped from `\w` or a swapped split priority — pure semantics with no
//! reference here, both killed by the Go oracle.
//! 2026-10-07 night: a leftmost-longest that stops at its first match passes
//! the old "starts where first does, ends no earlier" check; the substring
//! reference fails it.
//!
//! Driver: `REGEX_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT` as documented there). 500 seeds also run in every
//! ordinary test run.

const std = @import("std");
const testing = std.testing;
const regex = @import("root.zig");
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

/// Reach labels: the driver's `hit` (printed by `REGEX_FUZZ` runs) and a
/// local count the in-suite test checks.
const Label = enum { refused, compiled, full, matched, group, literal, posix, posix_refused, longest_ref, big, end_anchored, end_anchored_match, teddy, teddy_long, teddy_match, dfa_find, dfa_find_match, onepass, onepass_match, rust, rust_vm_only, bytes, twin, twin_match, bytes_twin, bytes_twin_match, set, set_match, set_big, set_too_large, heap, too_large, shortest, shortest_ref, anchored_match };

/// `Dfa.max_insts` in root.zig: a longer program is matched by `runSetOn`.
const dfa_max_insts = 128;
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn hit(comptime l: Label) void {
    fuzz_driver.hit(@tagName(l));
    reach[@backingInt(l)] += 1;
}

const Mode = enum { perl, posix, rust, bytes };

fn optionsFor(mode: Mode) regex.Options {
    return switch (mode) {
        .perl => .{},
        .posix => .{ .syntax = .posix },
        .rust => .{ .syntax = .rust },
        .bytes => .{ .syntax = .rust, .utf8 = false },
    };
}

/// One atom in both grammars: Go's (`.perl`) text and Rust's, saying the
/// same; null where that grammar cannot say it.
const Pair = struct { ?[]const u8, ?[]const u8 };

const literals = [_][]const u8{ "a", "b", "c", "é", "1", " ", "-", "\u{212a}", "ſ" };
const classes = [_][]const u8{ "[ab]", "[^a]", "[a-c]", "[é1-2]", "[]a]", "[a-]", "[[:alpha:]]", "[^[:digit:]\\n]", "\\pL", "\\p{Greek}", "\\PN", "[\\p{Lu}a]", "(?i)\\p{Ll}" };
/// Go's Perl classes are ASCII and case-folded under `(?i)`; Rust's are
/// Unicode and never folded — a bracket class says Go's in Rust.
const perl_classes = [_]Pair{
    .{ "\\d", "[0-9]" },         .{ "\\w", "[0-9A-Za-z_]" },  .{ "\\s", "[\\t\\n\\f\\r ]" },
    .{ "\\D", "[^0-9]" },        .{ "\\W", "[^0-9A-Za-z_]" }, .{ "\\S", "[^\\t\\n\\f\\r ]" },
    .{ "\\.", "\\." },           .{ "\\x{e9}", "\\x{e9}" },   .{ "\\Qa.\\E", "a\\." },
    .{ "[\\d]", "[[:digit:]]" },
};
const assertions = [_]Pair{
    .{ "^", "^" }, .{ "$", "$" }, .{ "\\b", "(?-u:\\b)" }, .{ "\\B", "(?-u:\\B)" }, .{ "\\A", "\\A" }, .{ "\\z", "\\z" },
};
const flag_groups = [_][]const u8{ "(?i)", "(?m)", "(?s)", "(?U)", "(?-i)" };
/// Rust syntax: with Go's twin where Go can say it.
const rust_atoms = [_]Pair{
    .{ "[b-c]", "[a-c&&b-d]" },   .{ "[ac]", "[a-c--b]" },                  .{ "[ad]", "[a-c~~b-d]" },
    .{ "\\p{Nd}", "[\\w&&\\d]" }, .{ "[d-zD-Z]", "[[:alpha:]--[a-cA-C]]" },
    .{ "é", "\\u{e9}" },
    .{ "é", "\\u00E9" },
    .{ "\\p{Lu}", "\\p{gc=Lu}" }, .{ "\\p{Greek}", "\\p{sc:Greek}" },       .{ "\\P{Greek}", "\\p{sc!=Greek}" },
    .{ "(?:ab)", "(?x: a b )" },  .{ "(?:a b)", "(?x:a\\ b)" },             .{ "(?:ab)", "(?x:a#c\nb)" },
    .{ "[ab]", "[a[b]]" },        .{ "[^ab]", "[^a[b]]" },                  .{ null, "\\d" },
    .{ null, "\\w" },             .{ null, "\\s" },                         .{ null, "\\W" },
    .{ null, "\\p{scx=Greek}" },  .{ null, "\\p{Alphabetic}" },             .{ null, "[\\p{Greek}&&\\p{Ll}]" },
    .{ null, "[\\w--a]" },        .{ null, "(?R:.)" },                      .{ null, "(?-u:\\w)" },
    .{ null, "\\p{Emoji}" },
};
const rust_assertions = [_][]const u8{ "\\b", "\\B", "\\<", "\\>", "\\b{start}", "\\b{end}", "\\b{start-half}", "\\b{end-half}", "(?-u:\\<)", "(?-u:\\b{end-half})", "(?Rm:^)", "(?Rm:$)" };
const rust_flags = [_][]const u8{ "(?R)", "(?x)", "(?-u)", "(?u)", "(?ix)", "(?i-u)", "(?mR)" };
/// Bytes mode only: `&str` refuses each.
const byte_atoms = [_][]const u8{ "(?-u:\\xff)", "(?-u:.)", "(?-u)[\\x80-\\xff]", "(?-u:\\W)", "(?s-u:.)", "(?-u:[^a])", "(?-u:\\xC3)" };
const quantifiers = [_]Pair{
    .{ "*", "*" },       .{ "+", "+" },   .{ "?", "?" },   .{ "{2}", "{ 2 }" },     .{ "{0,2}", "{0,2}" },
    .{ "{1,}", "{1,}" }, .{ "*?", "*?" }, .{ "+?", "+?" }, .{ "{1,3}?", "{1,3}?" },
};

const Gen = struct {
    /// Go's text (and POSIX's), Rust's text: they say the same while
    /// `perl_ok` and `rust_ok` hold.
    buf: [512]u8 = undefined,
    len: usize = 0,
    rbuf: [512]u8 = undefined,
    rlen: usize = 0,
    perl_ok: bool = true,
    rust_ok: bool = true,
    /// A construct `&str` refuses was drawn (or the text was damaged).
    bytes_only: bool = false,
    literal_only: bool = true,
    /// An assertion (`^ $ \b …`) was drawn: no substring reference.
    asserts: bool = false,
    groups: usize = 0,

    fn append(buf: []u8, len: *usize, s: []const u8) bool {
        if (len.* + s.len > buf.len) return false;
        @memcpy(buf[len.*..][0..s.len], s);
        len.* += s.len;
        return true;
    }

    fn put2(g: *Gen, perl: ?[]const u8, rust: ?[]const u8) void {
        if (perl) |s| {
            if (!append(&g.buf, &g.len, s)) g.perl_ok = false;
        } else g.perl_ok = false;
        if (rust) |s| {
            if (!append(&g.rbuf, &g.rlen, s)) g.rust_ok = false;
        } else g.rust_ok = false;
    }

    fn put(g: *Gen, s: []const u8) void {
        g.put2(s, s);
    }

    fn meta(g: *Gen, s: []const u8) void {
        g.literal_only = false;
        g.put(s);
    }

    fn meta2(g: *Gen, perl: ?[]const u8, rust: ?[]const u8) void {
        g.literal_only = false;
        g.put2(perl, rust);
    }

    fn primary(g: *Gen, mode: Mode) []u8 {
        return switch (mode) {
            .perl, .posix => g.buf[0..g.len],
            .rust, .bytes => g.rbuf[0..g.rlen],
        };
    }

    /// `open ++ what was drawn ++ close`, in both texts.
    fn wrap(g: *Gen, open: []const u8, ropen: []const u8, close: []const u8) void {
        var body: [512]u8 = undefined;
        var rbody: [512]u8 = undefined;
        const n = g.len;
        const rn = g.rlen;
        @memcpy(body[0..n], g.buf[0..n]);
        @memcpy(rbody[0..rn], g.rbuf[0..rn]);
        g.len = 0;
        g.rlen = 0;
        g.meta2(open, ropen);
        if (!append(&g.buf, &g.len, body[0..n])) g.perl_ok = false;
        if (!append(&g.rbuf, &g.rlen, rbody[0..rn])) g.rust_ok = false;
        g.put(close);
    }
};

fn pick(comptime S: type, src: *S, comptime T: type, table: []const T) T {
    return table[src.index(table.len)];
}

fn genAtom(comptime S: type, src: *S, g: *Gen, depth: u32, mode: Mode) void {
    const rust = mode == .rust or mode == .bytes;
    switch (src.valueRangeAtMost(u8, 0, if (depth < 2) 15 else 11)) {
        0, 1, 2 => g.put(pick(S, src, []const u8, &literals)),
        3 => g.meta("."),
        4 => g.meta(pick(S, src, []const u8, &classes)),
        5 => {
            const p = pick(S, src, Pair, &perl_classes);
            g.meta2(p[0], p[1]);
        },
        6 => {
            g.asserts = true;
            const p = pick(S, src, Pair, &assertions);
            g.meta2(p[0], p[1]);
        },
        7 => {
            // A flag group takes no repetition of its own.
            g.meta(pick(S, src, []const u8, &flag_groups));
            return;
        },
        8, 9 => if (rust) {
            const p = pick(S, src, Pair, &rust_atoms);
            g.meta2(p[0], p[1]);
        } else g.put(pick(S, src, []const u8, &literals)),
        10 => if (rust) {
            if (src.value(bool)) {
                g.asserts = true;
                g.meta2(null, pick(S, src, []const u8, &rust_assertions));
            } else {
                g.meta2(null, pick(S, src, []const u8, &rust_flags));
                return;
            }
        } else g.meta("."),
        11 => if (mode == .bytes) {
            g.bytes_only = true;
            g.meta2(null, pick(S, src, []const u8, &byte_atoms));
        } else g.meta(pick(S, src, []const u8, &classes)),
        else => {
            const k = src.index(4);
            if (k == 3) {
                // Names stay unique: Rust refuses a repeated one.
                var pn: [16]u8 = undefined;
                var rn: [16]u8 = undefined;
                const perl = std.fmt.bufPrint(&pn, "(?P<n{d}>", .{g.groups}) catch unreachable;
                const r = std.fmt.bufPrint(&rn, "{s}<n{d}>", .{ if (src.value(bool)) "(?P" else "(?", g.groups }) catch unreachable;
                g.meta2(perl, r);
            } else g.meta(([_][]const u8{ "(", "(?:", "(?i:" })[k]);
            g.groups += 1;
            genAlt(S, src, g, depth + 1, mode);
            g.put(")");
        },
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) {
        const q = pick(S, src, Pair, &quantifiers);
        g.meta2(q[0], q[1]);
        // Rust repeats a repetition (`a*+`); Go refuses it.
        if (rust and src.valueRangeAtMost(u8, 0, 7) == 0) g.meta2(null, pick(S, src, []const u8, &.{ "+", "{2}", "*" }));
    }
}

/// An atom of POSIX ERE (Go's `CompilePOSIX`): no Perl classes, flags,
/// non-capturing groups or lazy repetitions — `*?` is `*` repeated by `?`.
fn genAtomPosix(comptime S: type, src: *S, g: *Gen, depth: u32) void {
    switch (src.valueRangeAtMost(u8, 0, if (depth < 2) 11 else 7)) {
        0, 1, 2 => g.put(([_][]const u8{ "a", "b", "c", "é", "1", " ", "-" })[src.index(7)]),
        3 => g.meta("."),
        4, 5 => g.meta(([_][]const u8{ "[ab]", "[^a]", "[a-c]", "[é1-2]", "[]a]", "[a-]", "[^]b]", "[[:alpha:]]", "[[:digit:]a]", "[^[:space:]]", "[[:upper:][:lower:]]", "[[:punct:]é]", "[-a]", "[a-a]" })[src.index(14)]),
        6 => g.meta(([_][]const u8{ "\\.", "\\*", "\\[", "\\\\", "\\(", "\\-" })[src.index(6)]),
        7 => {
            if (src.valueRangeAtMost(u8, 0, 3) == 0) {
                // Perl only: refused here.
                g.meta(([_][]const u8{ "\\d", "(?:a)", "(?i)a", "\\b", "\\pL", "\\Qa\\E", "[[:foo:]]" })[src.index(7)]);
            } else {
                g.asserts = true;
                g.meta(([_][]const u8{ "^", "$" })[src.index(2)]);
            }
        },
        else => {
            g.meta("(");
            g.groups += 1;
            genAltPosix(S, src, g, depth + 1);
            g.put(")");
        },
    }
    // Repetitions, stacked now and then (`a+*`, `a{2}?`).
    for (0..src.valueRangeAtMost(u8, 0, 2)) |_| {
        if (src.valueRangeAtMost(u8, 0, 2) != 0) break;
        g.meta(([_][]const u8{ "*", "+", "?", "{2}", "{0,2}", "{1,}", "{0}", "{1,3}" })[src.index(8)]);
    }
}

fn genAltPosix(comptime S: type, src: *S, g: *Gen, depth: u32) void {
    for (0..src.valueRangeAtMost(u8, 1, 3), 0..) |_, i| {
        if (i != 0) g.meta("|");
        for (0..src.valueRangeAtMost(u8, 1, 3)) |_| genAtomPosix(S, src, g, depth);
    }
}

/// One to three alternatives of one to four atoms. A loop, not recursion:
/// a source that keeps answering the minimum (Smith outside `--fuzz`) must
/// still end.
fn genAlt(comptime S: type, src: *S, g: *Gen, depth: u32, mode: Mode) void {
    for (0..src.valueRangeAtMost(u8, 1, 3), 0..) |_, i| {
        if (i != 0) g.meta("|");
        for (0..src.valueRangeAtMost(u8, 1, 3)) |_| genAtom(S, src, g, depth, mode);
    }
}

/// What `compile` may make: every entry point runs it in stack scratch.
fn withinStack(re: *const regex.Regex) bool {
    return re.insts.len <= @as(usize, if (re.bytes) regex.max_insts else 4 * regex.max_insts);
}

fn isMatchOf(_: std.mem.Allocator, re: *const regex.Regex, input: []const u8) !bool {
    return re.isMatch(input);
}

fn fullMatchOf(_: std.mem.Allocator, re: *const regex.Regex, input: []const u8) !bool {
    return re.fullMatch(input);
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var g: Gen = .{};
    const mode: Mode = switch (src.valueRangeAtMost(u8, 0, 8)) {
        0, 1 => .posix,
        2, 3, 4 => .perl,
        5, 6 => .rust,
        else => .bytes,
    };
    const posix = mode == .posix;
    if (posix) genAltPosix(S, src, &g, 0) else genAlt(S, src, &g, 0, mode);
    // A share padded past the lazy DFA's size with a dead alternative (`q` is
    // not in the input alphabet): the same language, but `isMatch` runs the
    // NFA set simulation (bxp 2026-10-19: a stale closure after a prefilter
    // skip lived only there; repeating the whole pattern instead hid it —
    // 0 of 200 000 seeds). Half of them start with an assertion reachable
    // both from the start and after a consumed code point (`a?\b`): when the
    // threads die there it has been visited, failing — the shape of that
    // bug, about one in 10^6 of the plain grammar (0 of 200 000 padded seeds).
    if (src.valueRangeAtMost(u8, 0, 3) == 0 and g.primary(mode).len != 0) {
        if (src.value(bool)) {
            g.asserts = true;
            if (posix) {
                const p = pick(S, src, []const u8, &.{ "(a?^", "(a*$", "([a1]*^" });
                g.wrap(p, p, ")|q{130}");
            } else {
                const p = pick(S, src, Pair, &.{
                    .{ "(?:a?\\b", "(?:a?(?-u:\\b)" },       .{ "(?:a*\\b", "(?:a*(?-u:\\b)" },
                    .{ "(?:[a1]?\\B", "(?:[a1]?(?-u:\\B)" }, .{ "(?:\\w*\\b", "(?:[0-9A-Za-z_]*(?-u:\\b)" },
                    .{ "(?:(?m:a?^)", "(?:(?m:a?^)" },       .{ "(?:a*$", "(?:a*$" },
                });
                g.wrap(p[0].?, p[1].?, ")|q{130}");
            }
        } else g.wrap(if (posix) "(" else "(?:", "(?:", ")|q{130}");
    }
    // A share behind a set of literal prefixes: `Prefilter.teddy` (the plain
    // grammar draws one about once in 40 patterns).
    if (!posix and src.valueRangeAtMost(u8, 0, 7) == 0) {
        const p = pick(S, src, []const u8, &.{ "(?:ab|ca)", "(?:ab|ba|c1)", "(?:é|ab|-)", "(?:a|b)", "(?:1a|1b|1c|é1)" });
        g.wrap(p, p, "");
    }
    // A share past `max_insts` (compiled on the heap), some of it past
    // `4 * max_insts` (refused: `error.PatternTooLarge`, never a panic later).
    if (!posix and src.valueRangeAtMost(u8, 0, 15) == 0 and g.primary(mode).len != 0) {
        g.wrap("(?:", "(?:", pick(S, src, []const u8, &.{ ")|q{1000}q{100}", ")|q{1000}q{1000}", ")|q{1000}q{1000}q{1000}", ")|q{1000}q{1000}q{1000}q{1000}q{500}" }));
    }
    // A share anchored at the end: `isMatch` reads those backwards from the
    // end of the text (`runRevDfa`), the grammar alone rarely gets there.
    if (src.valueRangeAtMost(u8, 0, 3) == 0 and g.primary(mode).len != 0) {
        g.asserts = true;
        g.wrap(if (posix) "(" else "(?:", "(?:", ")$");
    }
    // A share of the patterns is damaged byte-wise: the parser's error paths.
    if (src.valueRangeAtMost(u8, 0, 4) == 0 and g.primary(mode).len != 0) {
        g.literal_only = false;
        g.asserts = true; // `ab` damaged to `\b`: whatever it now says
        g.perl_ok = false;
        g.rust_ok = false;
        g.bytes_only = true;
        const text = g.primary(mode);
        for (0..src.valueRangeAtMost(u8, 1, 3)) |_| {
            text[src.index(text.len)] = ([_]u8{ '(', ')', '[', ']', '{', '}', '\\', '*', '|', 0xff, ':', '?' })[src.index(12)];
        }
    }
    const pattern = g.primary(mode);

    var input_buf: [24]u8 = undefined;
    var il: usize = 0;
    for (0..src.valueRangeAtMost(u8, 0, 10)) |_| {
        const piece = ([_][]const u8{ "a", "b", "c", "1", " ", "\n", "é", "É", "-", "_", "\xff", "ab", "Ω", "ω", "\r", "\u{212a}", "ſ" })[src.index(17)];
        if (il + piece.len > input_buf.len) break;
        @memcpy(input_buf[il..][0..piece.len], piece);
        il += piece.len;
    }
    // Now and then the input repeated to a few hundred bytes: the
    // prefilter's 32-byte scan and the backtracker's budget edge.
    var long_buf: [400]u8 = undefined;
    var input: []const u8 = input_buf[0..il];
    if (il != 0 and src.valueRangeAtMost(u8, 0, 7) == 0) {
        var ll: usize = 0;
        while (ll + il <= long_buf.len) : (ll += il) @memcpy(long_buf[ll..][0..il], input);
        input = long_buf[0..ll];
    }

    // Printed only when a check fails, for the replay.
    errdefer std.debug.print("regex fuzz: {t} \"{f}\" on \"{f}\"\n", .{ mode, std.zig.fmtString(pattern), std.zig.fmtString(input) });
    if (!posix and src.valueRangeAtMost(u8, 0, 2) == 0) try setCheck(S, src, gpa, mode, pattern, input);

    const opts = optionsFor(mode);
    var re = regex.Regex.compileOptions(gpa, pattern, opts) catch |e| {
        if (e == error.OutOfMemory) return e;
        hit(.refused);
        if (posix) hit(.posix_refused);
        if (e == error.PatternTooLarge) hit(.too_large);
        try refusedTwins(gpa, &g, mode, e);
        return;
    };
    defer re.deinit(gpa);
    hit(.compiled);
    switch (mode) {
        .rust => {
            hit(.rust);
            if (re.vm_only) hit(.rust_vm_only);
        },
        .bytes => hit(.bytes),
        else => {},
    }
    if (re.insts.len > dfa_max_insts) hit(.big);
    // A heap program (up to 65,534 instructions, `(…){1000}`) on the VMs is
    // O(text × program) per start: the short input only.
    if (re.insts.len > regex.max_insts) input = input[0..@min(input.len, il)];
    if (re.insts.len > regex.max_insts) hit(.heap);
    if (!withinStack(&re)) return error.CompiledPastTheStack;
    var m = try regex.Matcher.init(gpa, &re);
    defer m.deinit();
    m.dfa_eager = true; // short inputs: the DFA would not be made yet

    const any = try isMatchOf(gpa, &re, input);
    const found = m.find(input, 0);
    if (any != (found != null)) return error.IsMatchDisagreesWithFind;
    if (re.prefilter.end_anchored and re.insts.len <= dfa_max_insts) {
        hit(.end_anchored);
        if (any) hit(.end_anchored_match);
    }
    if (re.prefilter.teddy != null) {
        // A prefix set that misses a match skips it in every entry point
        // alike: only the program without the prefilter tells.
        hit(.teddy);
        if (input.len >= 34) hit(.teddy_long);
        if (any) hit(.teddy_match);
        var bare = re;
        bare.prefilter = .{};
        if (bare.isMatch(input) != any) return error.TeddySkippedAMatch;
        var bm = try regex.Matcher.init(gpa, &bare);
        defer bm.deinit();
        for (0..input.len + 1) |from| {
            if (!std.meta.eql(bm.find(input, from), m.find(input, from))) return error.TeddySkippedAMatch;
        }
    }
    if (try fullMatchOf(gpa, &re, input)) {
        hit(.full);
        if (!any) return error.FullMatchWithoutMatch;
    }
    if (found) |s| {
        hit(.matched);
        if (s.start > s.end or s.end > input.len) return error.SpanOutOfInput;
        var out: [regex.max_groups]?regex.Span = undefined;
        const groups = out[0..re.names.len];
        if (!m.captures(input, 0, groups)) return error.CapturesDisagreeWithFind;
        if (groups[0] == null or groups[0].?.start != s.start or groups[0].?.end != s.end) return error.GroupZeroIsNotTheMatch;
        for (groups[1..]) |gs| if (gs) |x| {
            hit(.group);
            if (x.start > x.end or x.start < s.start or x.end > s.end) return error.GroupOutsideMatch;
        };
    }
    var it = m.iterator(input);
    var prev_end: usize = 0;
    var n: usize = 0;
    while (it.next()) |s| : (n += 1) {
        if (n == 0 and (found == null or s.start != found.?.start or s.end != found.?.end)) return error.IteratorFirstIsNotFind;
        if (s.start < prev_end or s.end < s.start) return error.IteratorOverlaps;
        // Go's FindAll: an empty match right where the previous one ended is
        // skipped.
        if (n != 0 and s.start == s.end and s.start == prev_end) return error.IteratorEmptyNextToPrevious;
        if (!onBoundary(input, s.start, re.bytes) or !onBoundary(input, s.end, re.bytes)) return error.SpanSplitsACodePoint;
        prev_end = s.end;
        if (n > input.len + 1) return error.IteratorDoesNotEnd;
    }
    if ((n == 0) != (found == null)) return error.IteratorDisagreesWithFind;

    try crossChecks(gpa, &re, &m, input, found);
    try shortestChecks(gpa, &re, input, found, g.asserts);
    try anchoredTwin(gpa, pattern, mode, input);
    if (posix) hit(.posix);
    if (!g.asserts and input.len <= input_buf.len and re.insts.len <= regex.max_insts) try longestReference(gpa, &re, input);

    if (g.literal_only and !posix) {
        hit(.literal);
        const want = std.mem.find(u8, input, pattern);
        if ((want != null) != any) return error.LiteralReferenceDisagrees;
        if (want) |w| if (found.?.start != w or found.?.end != w + pattern.len) return error.LiteralReferenceSpan;
    }

    switch (mode) {
        .perl => if (g.rust_ok) try syntaxTwin(gpa, &re, g.rbuf[0..g.rlen], .{ .syntax = .rust }, input),
        .rust => if (g.perl_ok) try syntaxTwin(gpa, &re, g.buf[0..g.len], .{}, input),
        .bytes => if (!g.bytes_only and std.unicode.utf8ValidateSlice(input)) try bytesTwin(gpa, &re, pattern, input),
        .posix => {},
    }
}

/// Limits the two grammars count differently (Rust's nest height counts
/// concatenations): a twin refused for one of these says nothing.
fn isLimit(e: anyerror) bool {
    return e == error.NestingDepth or e == error.PatternTooLarge;
}

/// The drawn pattern was refused: its twin must be refused too.
fn refusedTwins(gpa: std.mem.Allocator, g: *Gen, mode: Mode, e: anyerror) anyerror!void {
    if (isLimit(e)) return;
    const ok = switch (mode) {
        .perl => g.rust_ok,
        .rust => g.perl_ok,
        .bytes => !g.bytes_only,
        .posix => false,
    };
    if (!ok) return;
    const twin = if (mode == .rust) g.buf[0..g.len] else g.rbuf[0..g.rlen];
    const opts: regex.Options = if (mode == .rust) .{} else .{ .syntax = .rust };
    var tw = regex.Regex.compileOptions(gpa, twin, opts) catch |te| {
        if (te == error.OutOfMemory) return te;
        return;
    };
    tw.deinit(gpa);
    std.debug.print("regex fuzz: refused with {t}, twin \"{f}\" compiles\n", .{ e, std.zig.fmtString(twin) });
    return error.TwinTakesWhatIsRefused;
}

/// The same pattern in the other grammar: the same answers everywhere.
fn syntaxTwin(gpa: std.mem.Allocator, re: *const regex.Regex, twin: []const u8, opts: regex.Options, input: []const u8) anyerror!void {
    errdefer std.debug.print("regex fuzz: twin {t} \"{f}\"\n", .{ opts.syntax, std.zig.fmtString(twin) });
    var tw = regex.Regex.compileOptions(gpa, twin, opts) catch |e| {
        if (e == error.OutOfMemory) return e;
        if (isLimit(e)) return;
        return error.TwinRefused;
    };
    defer tw.deinit(gpa);
    hit(.twin);
    if (tw.names.len != re.names.len) return error.TwinGroupCount;
    if (try isMatchOf(gpa, &tw, input) != try isMatchOf(gpa, re, input)) return error.TwinIsMatch;
    if (try fullMatchOf(gpa, &tw, input) != try fullMatchOf(gpa, re, input)) return error.TwinFullMatch;
    var a = try regex.Matcher.init(gpa, re);
    defer a.deinit();
    var b = try regex.Matcher.init(gpa, &tw);
    defer b.deinit();
    const ng = re.names.len;
    var g1: [regex.max_groups]?regex.Span = undefined;
    var g2: [regex.max_groups]?regex.Span = undefined;
    const stride: usize = if (input.len > 32) 37 else 1;
    var from: usize = 0;
    while (from <= input.len) : (from += stride) {
        if (!onBoundary(input, from, false)) continue;
        const f1 = a.captures(input, from, g1[0..ng]);
        if (f1 != b.captures(input, from, g2[0..ng])) return error.TwinFind;
        if (f1) {
            hit(.twin_match);
            for (g1[0..ng], g2[0..ng]) |x, y| if (!std.meta.eql(x, y)) return error.TwinGroups;
        }
    }
    var ia = a.iterator(input);
    var ib = b.iterator(input);
    while (true) {
        const x = ia.next();
        if (!std.meta.eql(x, ib.next())) return error.TwinIterator;
        if (x == null) break;
    }
}

/// A bytes-mode pattern that `&str` takes too, on valid UTF-8: `&str`'s
/// match, or an earlier empty one inside a code point.
fn bytesTwin(gpa: std.mem.Allocator, re: *const regex.Regex, pattern: []const u8, input: []const u8) anyerror!void {
    var sre = regex.Regex.compileOptions(gpa, pattern, .{ .syntax = .rust }) catch |e| {
        if (e == error.OutOfMemory) return e;
        // `(?-u)` then `.`: only bytes mode can say it.
        if (e == error.InvalidUtf8 or isLimit(e)) return;
        return error.StrRefusesWhatBytesTakes;
    };
    defer sre.deinit(gpa);
    hit(.bytes_twin);
    if (try fullMatchOf(gpa, &sre, input) != try fullMatchOf(gpa, re, input)) return error.BytesFullMatch;
    var bm = try regex.Matcher.init(gpa, re);
    defer bm.deinit();
    var sm = try regex.Matcher.init(gpa, &sre);
    defer sm.deinit();
    const stride: usize = if (input.len > 32) 37 else 1;
    var from: usize = 0;
    while (from <= input.len) : (from += stride) {
        if (!onBoundary(input, from, false)) continue;
        const b = bm.find(input, from);
        const s = sm.find(input, from);
        errdefer std.debug.print("regex fuzz: bytes {any} str {any} from {d}\n", .{ b, s, from });
        if (b) |x| {
            hit(.bytes_twin_match);
            if (!onBoundary(input, x.start, false) or !onBoundary(input, x.end, false)) {
                if (x.start != x.end) return error.BytesSplitsACodePoint;
                if (s) |y| if (y.start <= x.start) return error.BytesEmptyNotEarlier;
            } else if (!std.meta.eql(b, s)) return error.BytesDisagreesWithStr;
        } else if (s != null) return error.BytesMissesStrMatch;
    }
}

/// The drawn pattern among up to three others (or a hundred large classes)
/// in a `RegexSet`: each pattern's own `isMatch`, refused as its parts are.
fn setCheck(comptime S: type, src: *S, gpa: std.mem.Allocator, mode: Mode, main: []const u8, input: []const u8) anyerror!void {
    const opts = optionsFor(mode);
    var gens: [3]Gen = undefined;
    var pats: [161][]const u8 = undefined;
    var n: usize = 0;
    if (src.valueRangeAtMost(u8, 0, 15) == 0) {
        // Each class some hundreds of ranges: the set's table past a u16.
        hit(.set_big);
        const c = pick(S, src, []const u8, &.{ "\\pL", "[\\pL\\pN]", "\\PL", "\\p{L}\\p{N}" });
        for (0..src.valueRangeAtMost(u8, 60, 159)) |_| {
            pats[n] = c;
            n += 1;
        }
        pats[n] = main;
        n += 1;
    } else {
        const at = src.valueRangeAtMost(u8, 0, 3);
        var drawn: usize = 0;
        for (0..4) |i| {
            if (i == at) {
                pats[n] = main;
            } else if (src.value(bool)) {
                gens[drawn] = .{};
                genAlt(S, src, &gens[drawn], 0, mode);
                pats[n] = gens[drawn].primary(mode);
                drawn += 1;
            } else continue;
            n += 1;
        }
    }
    errdefer for (pats[0..@min(n, 5)]) |p| std.debug.print("regex fuzz: set pattern \"{f}\"\n", .{std.zig.fmtString(p)});
    var res: [161]regex.Regex = undefined;
    var done: usize = 0;
    defer for (res[0..done]) |*r| r.deinit(gpa);
    var bad: ?anyerror = null;
    var insts: usize = n - 1;
    var ranges: usize = 0;
    for (pats[0..n]) |p| {
        res[done] = regex.Regex.compileOptions(gpa, p, opts) catch |e| {
            if (e == error.OutOfMemory) return e;
            bad = e;
            break;
        };
        insts += res[done].insts.len;
        ranges += res[done].ranges.len;
        done += 1;
    }
    const cap: usize = if (mode == .bytes) regex.max_insts else 4 * regex.max_insts;
    const too_large = insts > cap or ranges > std.math.maxInt(u16);
    var set = regex.RegexSet.compile(gpa, pats[0..n], opts) catch |e| {
        if (e == error.OutOfMemory) return e;
        // Refused as soon as the patterns before a bad one are too large.
        if (e == error.PatternTooLarge and too_large) {
            hit(.set_too_large);
            return;
        }
        if (bad) |b| {
            if (b != e) return error.SetErrorIsNotItsPatterns;
            return;
        }
        return error.SetRefusedItsPatterns;
    };
    defer set.deinit(gpa);
    if (bad != null) return error.SetTookABadPattern;
    if (too_large) return error.SetPastItsTables;
    hit(.set);
    var out: [163]bool = undefined;
    // `out` shorter or longer than the set now and then: as many as it holds.
    const olen = switch (src.valueRangeAtMost(u8, 0, 5)) {
        0 => n - 1,
        1 => n + 2,
        else => n,
    };
    const any = set.matches(input, out[0..olen]);
    if (olen > n) for (out[n..olen]) |o| if (o) return error.SetReportsPastItsPatterns;
    var want_any = false;
    for (res[0..n], 0..) |*r, i| {
        const want = try isMatchOf(gpa, r, input);
        if (i < olen and want != out[i]) return error.SetDisagreesWithPattern;
        want_any = want_any or want;
    }
    if (any != want_any or set.isMatch(input) != want_any) return error.SetAnyDisagrees;
    if (any) hit(.set_match);
}

/// The engine-against-engine and API invariants (see the file comment).
fn crossChecks(gpa: std.mem.Allocator, re: *const regex.Regex, m: *regex.Matcher, input: []const u8, found: ?regex.Span) anyerror!void {
    const ng = re.names.len;
    var g1: [regex.max_groups]?regex.Span = undefined;
    var g2: [regex.max_groups]?regex.Span = undefined;
    var pm = try regex.Matcher.init(gpa, re);
    defer pm.deinit();
    pm.pike_only = true;
    // Every start on a short input; on a long one (the repeated inputs) a
    // stride, so the checks stay linear in the input.
    const stride: usize = if (input.len > 32) 37 else 1;
    var from: usize = 0;
    while (from <= input.len) : (from += stride) {
        if (!std.meta.eql(m.find(input, from), pm.find(input, from))) return error.FindDisagreesWithPike;
        const f1 = m.captures(input, from, g1[0..ng]);
        const f2 = pm.captures(input, from, g2[0..ng]);
        if (f1 != f2) return error.EnginesDisagree;
        if (f1) for (g1[0..ng], g2[0..ng]) |a, b| {
            if ((a == null) != (b == null)) return error.EnginesDisagreeOnGroups;
            if (a) |x| if (x.start != b.?.start or x.end != b.?.end) return error.EnginesDisagreeOnGroups;
        };
    }
    // An anchored search: `find`'s match when it starts at `from`, else none;
    // the same in the Pike VM, and `capturesAnchored` with `captures`' groups.
    from = 0;
    while (from <= input.len) : (from += stride) {
        const f = m.find(input, from);
        const want: ?regex.Span = if (f != null and f.?.start == from) f else null;
        const got = m.findAnchored(input, from);
        errdefer std.debug.print("regex fuzz: anchored from {d}: {any}, want {any}\n", .{ from, got, want });
        if (!std.meta.eql(got, want)) return error.AnchoredDisagreesWithFind;
        if (!std.meta.eql(pm.findAnchored(input, from), want)) return error.AnchoredPikeDisagrees;
        if (want != null) {
            hit(.anchored_match);
            if (!m.capturesAnchored(input, from, g1[0..ng]) or !m.captures(input, from, g2[0..ng])) return error.AnchoredCapturesMissing;
            for (g1[0..ng], g2[0..ng]) |x, y| if (!std.meta.eql(x, y)) return error.AnchoredCapturesDisagree;
        } else if (m.capturesAnchored(input, from, g1[0..ng])) return error.AnchoredCapturesFound;
    }

    // `m` is `dfa_eager`: its `captures` went by the one-pass engine when the
    // program is one-pass.
    if (m.onepass != null) {
        hit(.onepass);
        if (found != null) hit(.onepass_match);
    }

    // The reader front end, through a 4-byte buffer (peeked sequences) and a
    // 1-byte one (held bytes); bytes mode: refused with an error.
    for ([_]usize{ 4, 1 }) |bl| {
        var rbuf: [4]u8 = undefined;
        var tr: std.testing.Reader = .init(rbuf[0..bl], &.{.{ .buffer = input }});
        tr.artificial_limit = .limited(1);
        if (re.bytes) {
            if (m.capturesReader(&tr.interface, g1[0..ng])) |_| return error.BytesReaderAccepted else |e| if (e != error.BytesMode) return e;
            break;
        }
        const rf = try m.capturesReader(&tr.interface, g1[0..ng]);
        if (rf != (found != null)) return error.ReaderDisagrees;
        if (rf and (g1[0].?.start != found.?.start or g1[0].?.end != found.?.end)) return error.ReaderDisagreesOnSpan;
        var rbuf2: [4]u8 = undefined;
        var tr2: std.testing.Reader = .init(rbuf2[0..bl], &.{.{ .buffer = input }});
        tr2.artificial_limit = .limited(1);
        if (try re.isMatchReader(&tr2.interface) != (found != null)) return error.ReaderMatchDisagrees;
    }

    if (!re.longest) {
        var lre = re.*;
        lre.longest = true;
        var lm = try regex.Matcher.init(gpa, &lre);
        defer lm.deinit();
        const l = lm.find(input, 0);
        if ((l == null) != (found == null)) return error.LongestDisagreesOnMatch;
        if (l) |x| if (x.start != found.?.start or x.end < found.?.end) return error.LongestNotLongest;
    }

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try m.replaceAll(&out.writer, input, "$0");
    if (!std.mem.eql(u8, out.written(), input)) return error.ReplaceIdentity;
    out.clearRetainingCapacity();
    try m.replaceAllLiteral(&out.writer, input, "");
    var removed: usize = 0;
    var it = m.iterator(input);
    while (it.next()) |x| removed += x.end - x.start;
    if (out.written().len + removed != input.len) return error.ReplaceRemovesOtherThanMatches;

    // The matches once, then each piece against them (both in order).
    var spans: [512]regex.Span = undefined;
    var ns: usize = 0;
    var it2 = m.iterator(input);
    while (it2.next()) |x| : (ns += 1) {
        if (ns == spans.len) return error.TooManyMatches;
        spans[ns] = x;
    }
    var sp = m.split(input, null);
    var pieces: usize = 0;
    var k: usize = 0;
    while (sp.next()) |piece| : (pieces += 1) {
        const at = @intFromPtr(piece.ptr) - @intFromPtr(input.ptr);
        if (input.len != 0 and at + piece.len > input.len) return error.SplitOutsideInput;
        while (k < ns and spans[k].end <= at) k += 1;
        var j = k;
        while (j < ns and spans[j].start < at + piece.len) : (j += 1) {
            if (spans[j].end > spans[j].start and at < spans[j].end) return error.SplitOverlapsMatch;
        }
    }
    if (pieces > input.len + 2) return error.SplitTooMany;

    out.clearRetainingCapacity();
    const complete = try re.literalPrefix(&out.writer);
    const prefix = out.written();
    for (spans[0..ns]) |x| if (!std.mem.startsWith(u8, input[x.start..], prefix)) return error.MatchWithoutLiteralPrefix;
    if (complete and !try fullMatchOf(gpa, re, prefix)) return error.CompletePrefixNotMatched;

    if (std.unicode.utf8ValidateSlice(input)) {
        const q = try regex.quoteMetaAlloc(gpa, input);
        defer gpa.free(q);
        var qre = try regex.Regex.compile(gpa, q);
        defer qre.deinit(gpa);
        if (!qre.fullMatch(input)) return error.QuoteMetaDoesNotMatch;
    }
}

/// `shortestMatch` (see the file comment).
fn shortestChecks(gpa: std.mem.Allocator, re: *const regex.Regex, input: []const u8, found: ?regex.Span, asserts: bool) anyerror!void {
    _ = gpa;
    const end = re.shortestMatch(input);
    if ((end == null) != (found == null)) return error.ShortestDisagreesWithFind;
    const e = end orelse return;
    hit(.shortest);
    if (e < found.?.start or e > found.?.end) return error.ShortestOutsideFind;
    if (asserts or input.len > 24 or re.insts.len > regex.max_insts) return;
    hit(.shortest_ref);
    var want: ?usize = null;
    ends: for (0..input.len + 1) |to| {
        if (!onBoundary(input, to, re.bytes)) continue;
        for (0..to + 1) |s| {
            if (!onBoundary(input, s, re.bytes)) continue;
            if (re.fullMatch(input[s..to])) {
                want = to;
                break :ends;
            }
        }
    }
    if (want != e) {
        std.debug.print("regex fuzz: shortest {d}, earliest end {?d}\n", .{ e, want });
        return error.ShortestReference;
    }
}

/// The pattern anchored at the start, `^(?:…)`: `Matcher.find` runs such a
/// program on its DFA (`FindDfa`), against the Pike VM from every start. A
/// twin, not a share of the drawn patterns: the grammar alone rarely draws an
/// anchored pattern that matches, and a new draw would move every seed.
fn anchoredTwin(gpa: std.mem.Allocator, pattern: []const u8, mode: Mode, input: []const u8) anyerror!void {
    var buf: [600]u8 = undefined;
    const twin = std.fmt.bufPrint(&buf, "{s}{s})", .{ if (mode == .posix) "^(" else "^(?:", pattern }) catch return;
    var re = regex.Regex.compileOptions(gpa, twin, optionsFor(mode)) catch |e| {
        if (e == error.OutOfMemory) return e;
        return; // `a)(b` and the like: the twin does not parse
    };
    defer re.deinit(gpa);
    if (!re.prefilter.anchored or re.longest or re.insts.len > dfa_max_insts) return;
    hit(.dfa_find);
    var m = try regex.Matcher.init(gpa, &re);
    defer m.deinit();
    m.dfa_eager = true;
    var pm = try regex.Matcher.init(gpa, &re);
    defer pm.deinit();
    pm.pike_only = true;
    const stride: usize = if (input.len > 32) 37 else 1;
    var from: usize = 0;
    while (from <= input.len) : (from += stride) {
        const got = m.find(input, from);
        errdefer std.debug.print("regex fuzz: anchored twin \"{f}\" from {d}\n", .{ std.zig.fmtString(twin), from });
        if (!std.meta.eql(got, pm.find(input, from))) return error.DfaFindDisagreesWithPike;
        if (got != null) hit(.dfa_find_match);
    }
}

/// Leftmost-longest (`re` itself in POSIX syntax, its `Longest` twin
/// otherwise) against the substring reference (see the file comment).
fn longestReference(gpa: std.mem.Allocator, re: *const regex.Regex, input: []const u8) anyerror!void {
    var lre = re.*;
    lre.longest = true;
    var lm = try regex.Matcher.init(gpa, &lre);
    defer lm.deinit();
    const got = lm.find(input, 0);
    var want: ?regex.Span = null;
    var s: usize = 0;
    while (s <= input.len and want == null) : (s += 1) {
        if (!onBoundary(input, s, re.bytes)) continue;
        var e = input.len + 1;
        while (e > s) {
            e -= 1;
            if (!onBoundary(input, e, re.bytes)) continue;
            if (re.fullMatch(input[s..e])) {
                want = .{ .start = s, .end = e };
                break;
            }
        }
    }
    hit(.longest_ref);
    if ((got == null) != (want == null)) return error.LongestReferenceDisagrees;
    if (got) |x| if (x.start != want.?.start or x.end != want.?.end) return error.LongestReferenceSpan;
}

/// Not inside a UTF-8 sequence (bytes mode: every position is one). The
/// inputs hold valid UTF-8 and a lone 0xff, so a continuation byte is always
/// the middle of a sequence.
fn onBoundary(input: []const u8, i: usize, bytes: bool) bool {
    return bytes or i == input.len or input[i] & 0xc0 != 0x80;
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor — so each seed is its own input
/// (a ranged draw first would collapse every seed to one, `check-fuzz-reach`).
const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        comptime std.debug.assert(T == bool);
        return self.cur.byte() & 1 == 1;
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
};

fn fuzzOne(_: void, smith: *testing.Smith) anyerror!void {
    var script: [1024]u8 = undefined;
    const n = smith.slice(&script);
    var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return harness(ScriptSource, &src, testing.allocator);
}

test "fuzz: compile and match never trap, and the entry points agree" {
    try testing.fuzz({}, fuzzOne, .{});
}

test "fuzz driver: REGEX_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "REGEX_FUZZ", .name = "regex" });
}

test "fuzz harness: 500 seeds in every test run, and it gets everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
    // Reach before verdict: every oracle had something to judge.
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("unreached: {t}\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.Unreached;
    };
}

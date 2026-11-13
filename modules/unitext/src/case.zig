// SPDX-License-Identifier: MIT

//! Full Unicode case mapping of UTF-8 strings: lower, upper, title, capitalize,
//! swapcase, casefold, and the simple per-code-point mappings.
//!
//! Behaviour is CPython's `str` methods (3.14, Unicode 16 there, 18 here): the
//! mappings are UnicodeData's simple ones overridden by the **unconditional** entries
//! of SpecialCasing.txt (ß -> SS, ŉ -> ʼN, İ -> i̇, ligatures, Greek iota subscript),
//! lowercase applies the Final_Sigma rule, and no language-tailored rule is applied
//! (Turkish/Azeri dotted and dotless i, Lithuanian dot retention: SpecialCasing's
//! conditional entries; Python and Rust do not apply them either). Rust's
//! `str::to_lowercase` / `to_uppercase` give the same results; Go's
//! `strings.ToLower` / `ToUpper` use SIMPLE mappings (no ß -> SS), so they differ.

const std = @import("std");
const ucd = @import("ucd.zig");
const utf8 = @import("utf8.zig");
const t = @import("tables.zig");
const common = @import("common.zig");

pub const Options = common.Options;
pub const Error = common.Error;
pub const WriteError = common.WriteError;
const Emitter = common.Emitter;

pub const Mode = enum { lower, upper, title, capitalize, swapcase, casefold };

const Kind = enum { lower, upper, title, fold };

fn findSpecial(comptime list: anytype, cp: u21) ?t.Special {
    var lo: usize = 0;
    var hi: usize = list.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const e = list[mid];
        if (e.cp == cp) return e;
        if (e.cp < cp) lo = mid + 1 else hi = mid;
    }
    return null;
}

inline fn table(comptime kind: Kind) type {
    return switch (kind) {
        .lower => t.lower,
        .upper => t.upper,
        .title => t.title,
        .fold => t.fold,
    };
}

/// The simple mapping of `cp` (identity if none).
fn simple(comptime kind: Kind, cp: u21) u21 {
    const v: i32 = ucd.look(table(kind), cp);
    const d = v >> 1;
    if (d == 0) return cp;
    const r: i32 = @as(i32, cp) + d;
    return @intCast(r); // in 0..0x10FFFF by construction of the table
}

/// Emit the full mapping of `cp` (up to three code points).
fn emitFull(comptime kind: Kind, em: anytype, cp: u21) !void {
    const v: i32 = ucd.look(table(kind), cp);
    if (v & 1 != 0) {
        const sp = findSpecial(switch (kind) {
            .lower => t.special_lower,
            .upper => t.special_upper,
            .title => t.special_title,
            .fold => t.special_fold,
        }, cp);
        if (sp) |e| {
            for (e.m[0..e.len]) |m| try em.cp(@intCast(m));
            return;
        }
    }
    try em.cp(simple(kind, cp));
}

/// True if, skipping Case_Ignorable code points from `i`, the next one is Cased.
fn followedByCased(s: []const u8, start: usize) bool {
    var i = start;
    while (i < s.len) {
        const st = utf8.step(s, i);
        const fl = ucd.flags(st.cp);
        if (fl & ucd.f_ignorable == 0) return fl & ucd.f_cased != 0;
        i += st.len;
    }
    return false;
}

fn emitLower(em: anytype, s: []const u8, next: usize, cp: u21, ctx_cased: bool) !void {
    if (cp == 0x03A3) {
        // Final_Sigma (Unicode §3.13 table 3-17): preceded by a cased letter (skipping
        // case-ignorables) and not followed by one.
        const final = ctx_cased and !followedByCased(s, next);
        return em.cp(if (final) 0x03C2 else 0x03C3);
    }
    return emitFull(.lower, em, cp);
}

/// Map `s` with `mode` into `out` (a `common` sink).
pub fn mapTo(comptime mode: Mode, out: anytype, s: []const u8, policy: utf8.InvalidUtf8) !void {
    const Out = @typeInfo(@TypeOf(out)).pointer.child;
    var em: Emitter(Out) = .{ .out = out };
    var i: usize = 0;
    var ctx_cased = false; // the last non-case-ignorable code point was Cased (Final_Sigma context)
    var prev_cased = false; // Python title(): the previous code point was Cased
    var first = true;
    while (i < s.len) {
        const u = try utf8.unit(s, i, policy);
        const next = i + u.len;
        if (u.raw) {
            try em.bytes(s[i..next]);
            ctx_cased = false;
            prev_cased = false;
            first = false;
            i = next;
            continue;
        }
        const c = u.cp;
        const fl = ucd.flags(c);
        switch (mode) {
            .lower => try emitLower(&em, s, next, c, ctx_cased),
            .upper => try emitFull(.upper, &em, c),
            .casefold => try emitFull(.fold, &em, c),
            .title => if (prev_cased) try emitLower(&em, s, next, c, ctx_cased) else try emitFull(.title, &em, c),
            .capitalize => if (first) try emitFull(.title, &em, c) else try emitLower(&em, s, next, c, ctx_cased),
            .swapcase => if (fl & ucd.f_upper != 0)
                try emitLower(&em, s, next, c, ctx_cased)
            else if (fl & ucd.f_lower != 0)
                try emitFull(.upper, &em, c)
            else
                try em.cp(c),
        }
        if (fl & ucd.f_ignorable == 0) ctx_cased = fl & ucd.f_cased != 0;
        prev_cased = fl & ucd.f_cased != 0;
        first = false;
        i = next;
    }
    try em.flush();
}

fn toWriter(comptime mode: Mode, w: *std.Io.Writer, s: []const u8, opts: Options) WriteError!void {
    var o: common.WriterOut = .{ .w = w };
    return mapTo(mode, &o, s, opts.invalid_utf8);
}

fn toOwned(comptime mode: Mode, a: std.mem.Allocator, s: []const u8, opts: Options) Error![]u8 {
    var o: common.ListOut = .{ .a = a, .cap = opts.max_output };
    errdefer o.deinit();
    try o.list.ensureTotalCapacity(a, @min(s.len, opts.max_output));
    try mapTo(mode, &o, s, opts.invalid_utf8);
    return o.toOwned();
}

// ── public API ──────────────────────────────────────────────────────────────

/// Python `str.lower()` / Rust `str::to_lowercase()`: full lowercase mapping with the
/// Final_Sigma rule (Σ -> ς at the end of a word, else σ); İ -> i̇ (two code points).
pub fn lower(a: std.mem.Allocator, s: []const u8, opts: Options) Error![]u8 {
    return toOwned(.lower, a, s, opts);
}
/// Writer form of `lower`; allocates nothing.
pub fn lowerTo(w: *std.Io.Writer, s: []const u8, opts: Options) WriteError!void {
    return toWriter(.lower, w, s, opts);
}

/// Python `str.upper()` / Rust `str::to_uppercase()`: full uppercase mapping (ß -> SS,
/// ŉ -> ʼN, ǰ -> J̌, ligatures and the Greek iota-subscript forms expand).
pub fn upper(a: std.mem.Allocator, s: []const u8, opts: Options) Error![]u8 {
    return toOwned(.upper, a, s, opts);
}
/// Writer form of `upper`; allocates nothing.
pub fn upperTo(w: *std.Io.Writer, s: []const u8, opts: Options) WriteError!void {
    return toWriter(.upper, w, s, opts);
}

/// Python `str.title()`: the first Cased code point of each run of Cased code points
/// gets its full titlecase mapping, the rest their lowercase one (with Final_Sigma).
/// "Run" is Python's: any non-Cased code point (a digit, an apostrophe, a hyphen) ends
/// it, so `"they're"` becomes `"They'Re"`. polars `str.to_titlecase` and ICU's word
/// breaking differ (see SPEC.md, Backlog).
pub fn title(a: std.mem.Allocator, s: []const u8, opts: Options) Error![]u8 {
    return toOwned(.title, a, s, opts);
}
/// Writer form of `title`; allocates nothing.
pub fn titleTo(w: *std.Io.Writer, s: []const u8, opts: Options) WriteError!void {
    return toWriter(.title, w, s, opts);
}

/// Python `str.capitalize()` (3.8+): the first code point titlecased (`ǆ` -> `ǅ`, `ß` ->
/// `Ss`), the rest lowercased. pandas `Series.str.capitalize` is this; Rust has no
/// equivalent.
pub fn capitalize(a: std.mem.Allocator, s: []const u8, opts: Options) Error![]u8 {
    return toOwned(.capitalize, a, s, opts);
}
/// Writer form of `capitalize`; allocates nothing.
pub fn capitalizeTo(w: *std.Io.Writer, s: []const u8, opts: Options) WriteError!void {
    return toWriter(.capitalize, w, s, opts);
}

/// Python `str.swapcase()`: Uppercase code points lowercased (full, with Final_Sigma),
/// Lowercase ones uppercased (full); everything else (titlecase `ǅ`, uncased) unchanged.
/// Note that `s.swapcase().swapcase() == s` does not always hold (ß -> SS -> ss).
pub fn swapcase(a: std.mem.Allocator, s: []const u8, opts: Options) Error![]u8 {
    return toOwned(.swapcase, a, s, opts);
}
/// Writer form of `swapcase`; allocates nothing.
pub fn swapcaseTo(w: *std.Io.Writer, s: []const u8, opts: Options) WriteError!void {
    return toWriter(.swapcase, w, s, opts);
}

/// Python `str.casefold()`: full case folding (CaseFolding.txt status C and F): ß -> ss,
/// ﬁ -> fi, ς -> σ. For caseless matching, not display. Rust's std has no casefold.
pub fn casefold(a: std.mem.Allocator, s: []const u8, opts: Options) Error![]u8 {
    return toOwned(.casefold, a, s, opts);
}
/// Writer form of `casefold`; allocates nothing.
pub fn casefoldTo(w: *std.Io.Writer, s: []const u8, opts: Options) WriteError!void {
    return toWriter(.casefold, w, s, opts);
}

/// Simple lowercase mapping of one code point (UnicodeData field 13; Rust's `char::to_lowercase`
/// is the full mapping; Go's `unicode.ToLower` is this). Identity above U+10FFFF.
pub fn toLowerCp(cp: u21) u21 {
    return simple(.lower, cp);
}
/// Simple uppercase mapping (UnicodeData field 12; Go's `unicode.ToUpper`). `ß` maps to itself.
pub fn toUpperCp(cp: u21) u21 {
    return simple(.upper, cp);
}
/// Simple titlecase mapping (UnicodeData field 14; Go's `unicode.ToTitle`).
pub fn toTitleCp(cp: u21) u21 {
    return simple(.title, cp);
}
/// Simple case folding (CaseFolding.txt status C and S; Go's `unicode.SimpleFold` is an
/// orbit step, not this; Python has no per-character equivalent).
pub fn foldCp(cp: u21) u21 {
    return simple(.fold, cp);
}

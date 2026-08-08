// SPDX-License-Identifier: MIT
//! The built-in filters, tests and value methods.
//!
//! Every name here is resolved at **compile time** by the parser, so a template
//! that mentions a filter this table does not have fails when it is compiled,
//! never mid-render. README.md carries the full table of what is present and
//! SPEC.md the table of what is deliberately absent; nothing is silently
//! approximated.

const std = @import("std");
const value = @import("value.zig");

const Value = value.Value;

pub const Error = value.Error;

pub const Kwarg = struct {
    name: []const u8,
    value: Value,
};

pub const Args = struct {
    pos: []const Value = &.{},
    kw: []const Kwarg = &.{},

    /// The `i`-th positional argument, or the keyword of that name.
    pub fn get(self: Args, i: usize, name: []const u8) ?Value {
        if (i < self.pos.len) return self.pos[i];
        for (self.kw) |k| if (std.mem.eql(u8, k.name, name)) return k.value;
        return null;
    }

    pub fn byName(self: Args, name: []const u8) ?Value {
        for (self.kw) |k| if (std.mem.eql(u8, k.name, name)) return k.value;
        return null;
    }
};

pub const Ctx = struct {
    arena: std.mem.Allocator,
    autoescape: bool,
    /// Under the strict policy a filter must refuse an undefined input rather
    /// than quietly turning it into `""`.
    strict: bool,
    user: *const anyopaque,
    callFilter: *const fn (ctx: *Ctx, name: []const u8, input: Value, args: Args) Error!Value,
    callTest: *const fn (ctx: *Ctx, name: []const u8, input: Value, args: Args) Error!bool,

    /// `str(v)`, refusing undefined when the policy is strict. This is the one
    /// place the undefined policy reaches the filter library.
    pub fn toStr(self: *Ctx, v: Value) Error![]const u8 {
        if (v == .undef and self.strict) return error.UndefinedValue;
        return value.strAlloc(self.arena, v);
    }
};

pub const Fn = *const fn (ctx: *Ctx, input: Value, args: Args) Error!Value;
pub const TestFn = *const fn (ctx: *Ctx, input: Value, args: Args) Error!bool;

pub const Entry = struct { name: []const u8, func: Fn };
pub const TestEntry = struct { name: []const u8, func: TestFn };

// ── helpers ─────────────────────────────────────────────────────────────────

/// A float in a position that needs an integer. The reference refuses one
/// outright here (`range(1e300)` → `TypeError`); this module is deliberately
/// more permissive and truncates, but a magnitude `i64` cannot hold is a named
/// error rather than a `@intFromFloat` that traps in ReleaseSafe and produces a
/// junk integer in ReleaseFast.
pub fn intFromFloatChecked(f: f64) Error!i64 {
    if (!std.math.isFinite(f)) return error.BadArgument;
    const t = @trunc(f);
    // Both bounds are exactly representable: -2^63 and +2^63.
    if (t < -9223372036854775808.0 or t >= 9223372036854775808.0) return error.OutOfRange;
    return @intFromFloat(t);
}

fn intArg(v: Value, dflt: i64) Error!i64 {
    return switch (v) {
        .integer => |i| i,
        .boolean => |b| @intFromBool(b),
        .float => |f| intFromFloatChecked(f),
        .none, .undef => dflt,
        else => error.BadArgument,
    };
}

fn boolArg(args: Args, i: usize, name: []const u8, dflt: bool) bool {
    const v = args.get(i, name) orelse return dflt;
    return v.truthy();
}

fn strArg(ctx: *Ctx, args: Args, i: usize, name: []const u8, dflt: []const u8) Error![]const u8 {
    const v = args.get(i, name) orelse return dflt;
    return ctx.toStr(v);
}

/// The markup bit of a filter whose result is built **only out of the input's
/// own bytes** — a case fold, a trim, a reversal, a prefix removal. markupsafe
/// does exactly this (`Markup.upper()`, `Markup.strip()`, `Markup.removeprefix()`
/// all return `Markup` without escaping anything).
///
/// **Never use this for a result that splices a caller-supplied ARGUMENT in.**
/// The argument is ordinary data — attacker-reachable in every documented use —
/// and re-marking the result as markup emits it unescaped, which is an
/// autoescape bypass reachable without any `|safe` in the template, because a
/// `{% filter %}`/`{% set %}` block body is markup by construction
/// (`render.zig:310`, `:324`). The rule markupsafe actually holds to is: a
/// markup result may only be assembled from operands that are *themselves*
/// markup or have been escaped. `fReplace`, `fJoin` and `binary(.add)` do that;
/// this helper cannot, because it never sees the argument.
fn markupAware(ctx: *Ctx, input: Value, bytes: []const u8) Value {
    const safe = ctx.autoescape and input == .string and input.string.safe;
    return .{ .string = .{ .bytes = bytes, .safe = safe } };
}

fn isMarkup(v: Value) bool {
    return v == .string and v.string.safe;
}

/// The elements a sequence filter works on.
fn seq(ctx: *Ctx, v: Value) Error![]const Value {
    // Matches the reference: its default `Undefined` is an empty iterable, so
    // `missing|list` is `[]`; `StrictUndefined` refuses.
    if (v == .undef) return if (ctx.strict) error.UndefinedValue else &.{};
    return value.iterate(ctx.arena, v);
}

/// `attribute=` support, shared by sort/min/max/sum/unique/map/groupby-likes.
/// A dotted path (`a.b`) and an integer index both work, as in the reference.
fn attrOf(ctx: *Ctx, item: Value, spec: Value) Error!Value {
    switch (spec) {
        .integer => |i| {
            const items = value.iterate(ctx.arena, item) catch return .{ .undef = .{ .name = "index" } };
            if (i < 0 or i >= items.len) return .{ .undef = .{ .name = "index" } };
            return items[@intCast(i)];
        },
        .string => |s| {
            var cur = item;
            var it = std.mem.splitScalar(u8, s.bytes, '.');
            while (it.next()) |part| {
                if (std.fmt.parseInt(i64, part, 10) catch null) |idx| {
                    const items = value.iterate(ctx.arena, cur) catch return .{ .undef = .{ .name = part } };
                    if (idx < 0 or idx >= items.len) return .{ .undef = .{ .name = part } };
                    cur = items[@intCast(idx)];
                    continue;
                }
                cur = switch (cur) {
                    .map => |m| m.get(part) orelse return .{ .undef = .{ .name = part } },
                    .namespace => |ns| ns.get(part) orelse return .{ .undef = .{ .name = part } },
                    else => return .{ .undef = .{ .name = part } },
                };
            }
            return cur;
        },
        else => return error.BadArgument,
    }
}

// ── string filters ──────────────────────────────────────────────────────────

fn fUpper(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const s = try ctx.toStr(input);
    const out = try ctx.arena.dupe(u8, s);
    for (out) |*c| c.* = std.ascii.toUpper(c.*);
    return markupAware(ctx, input, out);
}

fn fLower(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const s = try ctx.toStr(input);
    const out = try ctx.arena.dupe(u8, s);
    for (out) |*c| c.* = std.ascii.toLower(c.*);
    return markupAware(ctx, input, out);
}

// W2-A1/A2-jinja-F6: `do_capitalize` is `soft_str(s).capitalize()`, and
// `soft_str` returns a `Markup` argument unchanged (it only wraps non-`str`
// values). `str.capitalize()` on a `Markup` receiver returns a `Markup`
// result — verified live: `Markup('<b>x</b>').capitalize()` is
// `<class 'markupsafe.Markup'>`, not `str`. So the reference PRESERVES
// markup through `capitalize`, unlike `chars()`'s per-character loss above.
// `SPEC.md`'s "case-changing filters preserve markup" claim was accurate for
// this filter; only `fCapitalize`'s own code didn't act on it.
fn fCapitalize(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const s = try ctx.toStr(input);
    const out = try ctx.arena.dupe(u8, s);
    for (out, 0..) |*c, i| c.* = if (i == 0) std.ascii.toUpper(c.*) else std.ascii.toLower(c.*);
    return markupAware(ctx, input, out);
}

/// W2-A1-jinja-F7: the boundary set Jinja2's `do_title` actually splits on
/// (`jinja2/filters.py`'s `_word_beginning_split_re`, verified live:
/// `re.compile(r"([-\s({\[<]+)").pattern`) — a run of `-`, whitespace, `(`,
/// `{`, `[` or `<`. Anything else (`/`, `.`, `:`, `>`, `)`, `}`, `]`, digits,
/// `'`) is an ordinary mid-word byte and does not start a new titlecased
/// word — unlike the "any non-alphabetic byte" rule this replaced, which
/// diverged on ordinary configuration data (paths, FQDNs, interface names).
fn isTitleBoundary(c: u8) bool {
    return switch (c) {
        '-', ' ', '\t', '\r', '\n', 0x0b, 0x0c, '(', '{', '[', '<' => true,
        else => false,
    };
}

// W2-A1/A2-jinja-F6/F7: `do_title` (the `|title` FILTER) runs
// `_word_beginning_split_re.split(...)` (a capturing split, so the boundary
// runs themselves are also items) and applies
// `item[0].upper() + item[1:].lower()` to every non-empty item —
// equivalently, "at every point where byte membership in the boundary set
// changes (including position 0), uppercase; everywhere else, lowercase".
// Boundary characters have no case, so applying that rule to a boundary
// character or a text character is uniformly correct byte-for-byte.
//
// **Unlike `capitalize`, this does NOT preserve markup** — audit F6's claim
// that "title" belongs on the markup-preserving list does not survive a live
// check: `(s|safe)|title` renders fully escaped in Jinja2 3.1.6/markupsafe
// 3.0.3 (`&lt;B&gt;x&lt;/b&gt;` for `s = "<b>x</b>"`). The reason is
// `do_title` rebuilds the result with a **plain** `"".join(...)` (`str`'s
// `join`, not `Markup`'s), which discards every item's markup bit regardless
// of the receiver's — the opposite of `capitalize`/`center`, which call the
// receiver's own `.capitalize()`/`.center()` method directly and inherit
// whatever type `soft_str(s)` was. See `titleMethod` below for `.title()` as
// a *method* call, which goes through the real method and does preserve it.
fn fTitle(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const s = try ctx.toStr(input);
    const out = try ctx.arena.dupe(u8, s);
    var prev_boundary = false;
    for (out, 0..) |*c, i| {
        const boundary = isTitleBoundary(c.*);
        const transition = i == 0 or boundary != prev_boundary;
        c.* = if (transition) std.ascii.toUpper(c.*) else std.ascii.toLower(c.*);
        prev_boundary = boundary;
    }
    return Value.str(out);
}

// `.title()` as a METHOD call is a different function from the filter above:
// it goes through `str.title()`/`Markup.title()` directly, which (a) uses
// the built-in Unicode title-casing boundary rule — ANY non-alphabetic byte,
// not the filter's `[-\s({[<]+` set (verified live: `"it's ok".title()` is
// `"It'S Ok"` — the apostrophe *is* a boundary here, unlike the filter's
// set) — and (b) DOES preserve markup on a `Markup` receiver (verified live:
// `(s|safe).title()` stays unescaped), because it is the real method, not a
// plain-`str`-reconstructing filter.
fn titleMethod(ctx: *Ctx, input: Value) Error!Value {
    const s = try ctx.toStr(input);
    const out = try ctx.arena.dupe(u8, s);
    var at_start = true;
    for (out) |*c| {
        const alpha = std.ascii.isAlphabetic(c.*);
        c.* = if (at_start) std.ascii.toUpper(c.*) else std.ascii.toLower(c.*);
        at_start = !alpha;
    }
    return markupAware(ctx, input, out);
}

fn fTrim(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const s = try ctx.toStr(input);
    const cut = try strArg(ctx, args, 0, "chars", " \t\r\n\x0b\x0c");
    return markupAware(ctx, input, std.mem.trim(u8, s, cut));
}

/// `|replace` — Jinja2's `do_replace`, escaping included.
///
/// MATCH THE REFERENCE, and here the reference is also where the security
/// property lives. `do_replace` (jinja2/filters.py, 3.1.6) under autoescape is
///
///     if hasattr(old, "__html__") or hasattr(new, "__html__") and not hasattr(s, "__html__"):
///         s = escape(s)
///     else:
///         s = soft_str(s)
///     return s.replace(soft_str(old), soft_str(new), count)
///
/// and `Markup.replace` (markupsafe 3.0.3) is
/// `self.__class__(super().replace(old, self.escape(new), count))` — **`new` is
/// escaped, `old` is not**: `old` is matched against the raw markup bytes.
/// Composing the two gives one rule, which is the rule for every markup-valued
/// operation: *the result is markup iff some operand is markup, and every
/// operand that is not already markup is escaped on the way in.*
///
/// Splicing `new` in raw while re-marking the result as markup — what
/// `markupAware` did here — is an autoescape bypass that needs no `|safe`
/// anywhere in the template, because `{% filter replace('x', data) %}` and
/// `{% set b %}…{% endset %}{{ b|replace('x', data) }}` both have a markup
/// body by construction. Verified case for case against Jinja2 3.1.6 +
/// markupsafe 3.0.3 on this host, both autoescape settings; the corpus pins
/// the whole matrix (`escape_replace_*`).
fn fReplace(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const old_v = args.get(0, "old") orelse Value.empty_string;
    const new_v = args.get(1, "new") orelse Value.empty_string;
    // `escape(s)` when either argument is markup, `soft_str(s)` otherwise —
    // which is markup exactly when one of the three operands already was.
    const markup = ctx.autoescape and (isMarkup(input) or isMarkup(old_v) or isMarkup(new_v));
    const s = if (markup) try escapedBytes(ctx, input) else try ctx.toStr(input);
    const old = try ctx.toStr(old_v);
    const new = if (markup) try escapedBytes(ctx, new_v) else try ctx.toStr(new_v);
    return replaceCore(ctx, s, old, new, args.get(2, "count"), markup);
}

/// The splice itself, shared by the filter and the `.replace()` method, which
/// differ only in how they decide what to escape.
fn replaceCore(ctx: *Ctx, s: []const u8, old: []const u8, new: []const u8, count_v: ?Value, markup: bool) Error!Value {
    // MATCH THE REFERENCE. `str.replace(old, new, count)` treats *any* negative
    // count as "every occurrence", and `{{ x|replace('a','b',-1) }}` is an
    // ordinary Jinja2 spelling: 3.1.6 renders `'aaa'|replace('a','b',-1)` and
    // `…,-5)` both as `bbb`, and `…,0)` as `aaa`.
    const limit: usize = if (count_v == null or count_v.? == .none)
        std.math.maxInt(usize)
    else blk: {
        const c = try intArg(count_v.?, 0);
        break :blk if (c < 0) std.math.maxInt(usize) else @intCast(c);
    };
    // MATCH THE REFERENCE. An empty `old` is not "nothing to do": Python's
    // `str.replace` treats it as a match at every gap, so `'abc'.replace('','X')`
    // is `'XaXbXcX'`, `''.replace('','X')` is `'X'`, and `count` clips from the
    // left (`'abc'.replace('','X',2)` is `'XaXbc'`). Jinja2 3.1.6 inherits all of
    // it verbatim, in both autoescape settings — checked on this host. Returning
    // the input unchanged (what this did) is a silent no-op in a filter whose
    // arguments routinely come from context data, so the divergence is not
    // reachable only from template text (audit BD-06).
    //
    // The gaps are between CODEPOINTS, not bytes: Python replaces over
    // characters, so `'áb'.replace('','X')` is `'XáXbX'` — three insertions, not
    // four — and splicing between the bytes of a multi-byte sequence would also
    // emit invalid UTF-8.
    var out: std.ArrayList(u8) = .empty;
    if (old.len == 0) {
        var i: usize = 0;
        var done: usize = 0;
        while (i < s.len) {
            if (done < limit) {
                try out.appendSlice(ctx.arena, new);
                done += 1;
            }
            const n = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
            const end = @min(i + n, s.len);
            try out.appendSlice(ctx.arena, s[i..end]);
            i = end;
        }
        if (done < limit) try out.appendSlice(ctx.arena, new);
        return .{ .string = .{ .bytes = out.items, .safe = markup } };
    }

    var i: usize = 0;
    var done: usize = 0;
    while (i < s.len) {
        if (done < limit and std.mem.startsWith(u8, s[i..], old)) {
            try out.appendSlice(ctx.arena, new);
            i += old.len;
            done += 1;
        } else {
            try out.append(ctx.arena, s[i]);
            i += 1;
        }
    }
    return .{ .string = .{ .bytes = out.items, .safe = markup } };
}

/// `.replace()` as a **method**, which is not the same function as the filter:
/// the method is markupsafe's `Markup.replace` when the receiver is markup and
/// plain `str.replace` when it is not. `do_replace`'s "escape `s` when an
/// argument is markup" rule belongs to the filter alone, and the method's
/// escaping of `new` is driven by the receiver, not by `autoescape` — with
/// autoescape off, Jinja2 3.1.6 renders `{{ (s|safe).replace('x', evil) }}`
/// with the entities visible, and `{{ s.replace('x', evil) }}` raw.
fn replaceMethod(ctx: *Ctx, s: value.Str, args: Args) Error!Value {
    const new_v = args.get(1, "new") orelse Value.empty_string;
    const old = try strArg(ctx, args, 0, "old", "");
    const new = if (s.safe) try escapedBytes(ctx, new_v) else try ctx.toStr(new_v);
    return replaceCore(ctx, s.bytes, old, new, args.get(2, "count"), s.safe);
}

fn fIndent(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const s = try ctx.toStr(input);
    const width_v = args.get(0, "width") orelse Value{ .integer = 4 };
    const indention: []const u8 = switch (width_v) {
        // MATCH THE REFERENCE, INCLUDING ITS SHARP EDGE. `do_indent` does
        // `indention = Markup(indention)` when the input is markup, and
        // `Markup(x)` marks x safe *without* escaping it — so a string `width`
        // is spliced raw into a markup result. Jinja2 3.1.6 renders
        // `{% filter indent(data, true) %}q{% endfilter %}` under autoescape
        // with `data` unescaped, and so do we (corpus:
        // `escape_indent_string_width_splices_raw`). This is the one remaining
        // route from context data to unescaped output that does not spell
        // `|safe`, and it is the reference's, not ours; diverging here would
        // cost byte-exactness against the only oracle this module has.
        .string => |x| x.bytes,
        else => blk: {
            // MATCH THE REFERENCE. `do_indent` builds `" " * width`, and in
            // Python that is `""` for any negative width: Jinja2 3.1.6 renders
            // `'a\nb'|indent(-1, true)` as `a\nb`, unchanged.
            const w = try intArg(width_v, 4);
            const n: usize = if (w < 0) 0 else @intCast(w);
            if (n > value.max_alloc) return error.OutOfRange;
            const buf = try ctx.arena.alloc(u8, n);
            @memset(buf, ' ');
            break :blk buf;
        },
    };
    const first = boolArg(args, 1, "first", false);
    const blank = boolArg(args, 2, "blank", false);

    var out: std.ArrayList(u8) = .empty;
    if (first) try out.appendSlice(ctx.arena, indention);
    var it = std.mem.splitScalar(u8, s, '\n');
    var idx: usize = 0;
    while (it.next()) |line| : (idx += 1) {
        if (idx != 0) {
            try out.append(ctx.arena, '\n');
            if (line.len != 0 or blank) try out.appendSlice(ctx.arena, indention);
        }
        try out.appendSlice(ctx.arena, line);
    }
    return markupAware(ctx, input, out.items);
}

fn fCenter(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const s = try ctx.toStr(input);
    // MATCH THE REFERENCE. `str.center(w)` returns the string unchanged for
    // every `w <= len`, negatives included: Jinja2 3.1.6 renders
    // `'ab'|center(-1)` and `'ab'|center(0)` both as `ab`. Folding a negative
    // width to 0 reproduces that exactly, because the `len >= width` branch
    // below is the same early return.
    const width_i = try intArg(args.get(0, "width") orelse Value{ .integer = 80 }, 80);
    const width: usize = if (width_i < 0) 0 else @intCast(width_i);
    const len = std.unicode.utf8CountCodepoints(s) catch s.len;
    // W2-A1/A2-jinja-F6: `do_center` is `soft_str(value).center(width)`, and
    // `str.center()` on a `Markup` receiver returns `Markup` (verified live:
    // `Markup('<b>x</b>').center(12)` is `<class 'markupsafe.Markup'>`) —
    // both the early return and the padded result must preserve it.
    if (len >= width) return markupAware(ctx, input, s);
    const total = width - len;
    if (total > value.max_alloc) return error.OutOfRange;
    // CPython's exact rule (`Objects/stringlib/transmute.h`): the odd space
    // goes LEFT when both the margin and the width are odd.
    const left = total / 2 + (total & width & 1);
    const right = total - left;
    var out: std.ArrayList(u8) = .empty;
    try out.appendNTimes(ctx.arena, ' ', left);
    try out.appendSlice(ctx.arena, s);
    try out.appendNTimes(ctx.arena, ' ', right);
    return markupAware(ctx, input, out.items);
}

fn fTruncate(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const s = try ctx.toStr(input);
    const length_i = try intArg(args.get(0, "length") orelse Value{ .integer = 255 }, 255);
    const killwords = boolArg(args, 1, "killwords", false);
    const end_v = args.get(2, "end") orelse Value.str("...");
    const end_raw = try ctx.toStr(end_v);
    const leeway_i = try intArg(args.get(3, "leeway") orelse Value{ .integer = 5 }, 5);
    // TYPED ERROR. `do_truncate` opens with `assert length >= len(end)` and
    // `assert leeway >= 0`, so a negative either way raises in the reference
    // (Jinja2 3.1.6: `'abcdefghijklmnop'|truncate(-1)` → AssertionError,
    // `…|truncate(5, true, '...', -1)` → AssertionError). There is no defined
    // output to match, so it is a named error here.
    if (length_i < 0 or leeway_i < 0) return error.BadArgument;
    const length: usize = @intCast(length_i);
    const leeway: usize = @intCast(leeway_i);
    // W2-A1/A2-jinja-F6: `do_truncate` returns `s` itself untouched when it's
    // short enough, and otherwise builds `s[:n] + end`. `str.__add__` on a
    // `Markup` receiver (`str.center`'s sibling rule) escapes a non-markup
    // right operand and returns `Markup` — the same splice rule `fReplace`
    // already applies to its own argument. A non-markup receiver stays
    // unmarked either way, so the whole result (including `end`) is escaped
    // on render, matching the reference.
    if (s.len <= length +| leeway) return markupAware(ctx, input, s);
    if (length < end_raw.len) return error.BadArgument;
    const markup = ctx.autoescape and isMarkup(input);
    const end = if (markup) try escapedBytes(ctx, end_v) else end_raw;
    const keep = length - end_raw.len;
    var cut = s[0..keep];
    if (!killwords) {
        if (std.mem.lastIndexOfScalar(u8, cut, ' ')) |sp| {
            cut = cut[0..sp];
        } else {
            cut = cut[0..0];
        }
    }
    return .{ .string = .{ .bytes = try std.mem.concat(ctx.arena, u8, &.{ cut, end }), .safe = markup } };
}

fn fWordcount(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const s = try ctx.toStr(input);
    var n: i64 = 0;
    var it = std.mem.tokenizeAny(u8, s, " \t\r\n\x0b\x0c");
    while (it.next()) |_| n += 1;
    return .{ .integer = n };
}

fn fStriptags(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const s = try ctx.toStr(input);
    var stripped: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '<') {
            const close = std.mem.indexOfScalarPos(u8, s, i, '>') orelse break;
            i = close + 1;
            continue;
        }
        try stripped.append(ctx.arena, s[i]);
        i += 1;
    }
    const unescaped = try unescapeEntities(ctx.arena, stripped.items);
    // Collapse runs of whitespace, then strip.
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, unescaped, " \t\r\n\x0b\x0c");
    var first = true;
    while (it.next()) |w| {
        if (!first) try out.append(ctx.arena, ' ');
        try out.appendSlice(ctx.arena, w);
        first = false;
    }
    return Value.str(out.items);
}

fn unescapeEntities(arena: std.mem.Allocator, s: []const u8) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '&') {
            const table = .{
                .{ "&amp;", "&" },   .{ "&lt;", "<" },   .{ "&gt;", ">" },
                .{ "&quot;", "\"" }, .{ "&#34;", "\"" }, .{ "&#39;", "'" },
                .{ "&apos;", "'" },
            };
            var matched = false;
            inline for (table) |e| {
                if (!matched and std.mem.startsWith(u8, s[i..], e[0])) {
                    try out.appendSlice(arena, e[1]);
                    i += e[0].len;
                    matched = true;
                }
            }
            if (matched) continue;
        }
        try out.append(arena, s[i]);
        i += 1;
    }
    return out.items;
}

fn fEscape(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    if (input == .string and input.string.safe) return input;
    if (input == .undef and ctx.strict) return error.UndefinedValue;
    const s = try value.strAlloc(ctx.arena, input);
    return .{ .string = .{ .bytes = try value.escapeAlloc(ctx.arena, s), .safe = true } };
}

fn fForceEscape(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    if (input == .undef and ctx.strict) return error.UndefinedValue;
    const s = try value.strAlloc(ctx.arena, input);
    return .{ .string = .{ .bytes = try value.escapeAlloc(ctx.arena, s), .safe = true } };
}

fn fSafe(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    if (input == .undef and ctx.strict) return error.UndefinedValue;
    const s = try value.strAlloc(ctx.arena, input);
    return .{ .string = .{ .bytes = s, .safe = true } };
}

fn fString(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    if (input == .string) return input;
    const s = try ctx.toStr(input);
    return Value.str(s);
}

fn fUrlencode(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    switch (input) {
        .map, .namespace => {
            const pairs: []const value.Pair = switch (input) {
                .map => |m| m.pairs,
                .namespace => |ns| ns.pairs.items,
                else => unreachable,
            };
            var out: std.ArrayList(u8) = .empty;
            for (pairs, 0..) |p, i| {
                if (i != 0) try out.append(ctx.arena, '&');
                try quoteInto(ctx, &out, try ctx.toStr(p.key), "");
                try out.append(ctx.arena, '=');
                try quoteInto(ctx, &out, try ctx.toStr(p.value), "");
            }
            return Value.str(out.items);
        },
        else => {
            const s = try ctx.toStr(input);
            var out: std.ArrayList(u8) = .empty;
            try quoteInto(ctx, &out, s, "/");
            return Value.str(out.items);
        },
    }
}

fn quoteInto(ctx: *Ctx, out: *std.ArrayList(u8), s: []const u8, extra_safe: []const u8) Error!void {
    for (s) |c| {
        const unreserved = std.ascii.isAlphanumeric(c) or c == '_' or c == '.' or c == '-' or c == '~' or
            std.mem.indexOfScalar(u8, extra_safe, c) != null;
        if (unreserved) {
            try out.append(ctx.arena, c);
        } else {
            var buf: [3]u8 = undefined;
            const hex = std.fmt.bufPrint(&buf, "%{X:0>2}", .{c}) catch unreachable;
            try out.appendSlice(ctx.arena, hex);
        }
    }
}

fn fXmlattr(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const autospace = boolArg(args, 0, "autospace", true);
    const pairs: []const value.Pair = switch (input) {
        .map => |m| m.pairs,
        .namespace => |ns| ns.pairs.items,
        else => return error.TypeMismatch,
    };
    var out: std.ArrayList(u8) = .empty;
    var first = true;
    for (pairs) |p| {
        if (p.value == .none or p.value == .undef) continue;
        if (!first or autospace) try out.append(ctx.arena, ' ');
        first = false;
        var aw: std.Io.Writer.Allocating = .init(ctx.arena);
        try value.escapeTo(&aw.writer, try ctx.toStr(p.key));
        try out.appendSlice(ctx.arena, aw.written());
        try out.appendSlice(ctx.arena, "=\"");
        var vw: std.Io.Writer.Allocating = .init(ctx.arena);
        try value.escapeTo(&vw.writer, try ctx.toStr(p.value));
        try out.appendSlice(ctx.arena, vw.written());
        try out.append(ctx.arena, '"');
    }
    return .{ .string = .{ .bytes = out.items, .safe = true } };
}

// ── numeric filters ─────────────────────────────────────────────────────────

fn fAbs(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = ctx;
    _ = args;
    return switch (input) {
        .integer => |i| .{ .integer = if (i < 0) (std.math.negate(i) catch return error.OutOfRange) else i },
        .float => |f| .{ .float = @abs(f) },
        .boolean => |b| .{ .integer = @intFromBool(b) },
        .undef => error.UndefinedValue,
        else => error.TypeMismatch,
    };
}

fn fInt(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const dflt = args.get(0, "default") orelse Value{ .integer = 0 };
    // MATCH THE REFERENCE. `int(s, base)` accepts only 0 and 2..36; any other
    // base raises there, and `do_int` catches it and falls through to its
    // `int(float(value))` branch — Jinja2 3.1.6 renders `'10'|int(0,-1)` and
    // `'10'|int(0,99999999999)` both as `10`. So an out-of-range base is not an
    // error, it is a base no integer parse will accept.
    const base_i = try intArg(args.get(1, "base") orelse Value{ .integer = 10 }, 10);
    const base: ?u8 = if (base_i == 0 or (base_i >= 2 and base_i <= 36)) @intCast(base_i) else null;
    _ = ctx;
    return switch (input) {
        .integer => input,
        .boolean => |b| .{ .integer = @intFromBool(b) },
        // TYPED ERROR on magnitude: the reference answers `1e300|int` with an
        // arbitrary-precision integer this module has no type for, and
        // returning `default` instead would be a wrong answer rather than a
        // refusal.
        .float => |f| if (std.math.isNan(f) or std.math.isInf(f)) dflt else .{ .integer = try intFromFloatChecked(f) },
        .string => |s| blk: {
            const t = std.mem.trim(u8, s.bytes, " \t\r\n");
            if (base) |b| {
                const stripped = if (b != 10 and t.len > 2 and t[0] == '0' and !std.ascii.isDigit(t[1])) t[2..] else t;
                if (std.fmt.parseInt(i64, stripped, b)) |v| break :blk .{ .integer = v } else |_| {}
            }
            if (base == null or base.? == 10) {
                if (std.fmt.parseFloat(f64, t)) |f| break :blk .{ .integer = try intFromFloatChecked(f) } else |_| {}
            }
            break :blk dflt;
        },
        else => dflt,
    };
}

fn fFloat(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = ctx;
    const dflt = args.get(0, "default") orelse Value{ .float = 0.0 };
    return switch (input) {
        .float => input,
        .integer => |i| .{ .float = @floatFromInt(i) },
        .boolean => |b| .{ .float = if (b) 1.0 else 0.0 },
        .string => |s| blk: {
            const t = std.mem.trim(u8, s.bytes, " \t\r\n");
            if (std.fmt.parseFloat(f64, t)) |f| break :blk .{ .float = f } else |_| {}
            break :blk dflt;
        },
        else => dflt,
    };
}

fn fRound(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = ctx;
    // MATCH THE REFERENCE, by a clamp that is value-preserving rather than a
    // guess: for `f64` every precision past ±400 decimal places gives the same
    // answer as ±400 (17 significant digits, magnitudes 5e-324 … 1.8e308), and
    // that answer is the reference's — Jinja2 3.1.6 renders
    // `1.5|round(10000000000)` as `1.5` and `1.5|round(-10000000000)` as `0.0`.
    // `roundHalfEven`/`roundIntHalfEven` handle the two saturated ends exactly.
    const precision: i32 = @intCast(std.math.clamp(try intArg(args.get(0, "precision") orelse Value{ .integer = 0 }, 0), -400, 400));
    const method_v = args.get(1, "method");
    const method: []const u8 = if (method_v) |m| switch (m) {
        .string => |s| s.bytes,
        else => return error.BadArgument,
    } else "common";

    const x: f64 = switch (input) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        .boolean => |b| if (b) 1.0 else 0.0,
        .undef => return error.UndefinedValue,
        else => return error.TypeMismatch,
    };
    if (std.mem.eql(u8, method, "common")) {
        // Python's `round(int, p)` stays an int; `round(float, p)` stays a
        // float. Both reach templates, and the two render differently.
        if (input == .integer or input == .boolean) {
            const iv: i64 = if (input == .boolean) @intFromBool(input.boolean) else input.integer;
            return .{ .integer = try roundIntHalfEven(iv, precision) };
        }
        return .{ .float = roundHalfEven(x, precision) };
    }
    // `ceil`/`floor` are what the reference does verbatim: scale, apply the
    // math function, scale back.
    const scale = powTen(precision);
    // `math.ceil(value * 10**precision)` is what the reference computes, and it
    // raises (`OverflowError`) once `10**precision` leaves `f64` — there is no
    // defined output to match, and an unguarded `inf`/`0` scale here would
    // silently produce NaN.
    if (!std.math.isFinite(scale) or scale == 0) return error.OutOfRange;
    const scaled = x * scale;
    const r: f64 = if (std.mem.eql(u8, method, "ceil"))
        @ceil(scaled)
    else if (std.mem.eql(u8, method, "floor"))
        @floor(scaled)
    else
        return error.BadArgument;
    return .{ .float = r / scale };
}

/// `round(int, p)`. A non-negative precision leaves an integer alone; a
/// negative one rounds to a multiple of `10^-p`, ties to even.
fn roundIntHalfEven(x: i64, p: i32) Error!i64 {
    if (p >= 0) return x;
    // `|i64| < 5e19`, so rounding to a multiple of `10^20` or coarser is 0 for
    // every input — which is what the reference gives (`round(15, -400)` → 0).
    if (p <= -20) return 0;
    const d: i128 = @intCast(mulPow10(1, @intCast(-p)) orelse return error.OutOfRange);
    const neg = x < 0;
    const a: i128 = if (neg) -@as(i128, x) else @as(i128, x);
    const q = @divTrunc(a, d);
    const r = @rem(a, d);
    var res = q;
    if (r * 2 > d) {
        res += 1;
    } else if (r * 2 == d and @rem(q, 2) != 0) {
        res += 1;
    }
    res *= d;
    const signed = if (neg) -res else res;
    return std.math.cast(i64, signed) orelse error.OutOfRange;
}

/// An exact power of ten. `std.math.pow(10, 2)` can come back as
/// 100.00000000000001, which is enough to move a rounding decision.
fn powTen(p: i32) f64 {
    var acc: f64 = 1.0;
    var n = @abs(p);
    while (n > 0) : (n -= 1) acc *= 10.0;
    return if (p < 0) 1.0 / acc else acc;
}

/// Python's `round(x, p)`: banker's rounding of the value's **exact** binary
/// magnitude, not of its printed form.
///
/// The obvious `@round(x * 10^p) / 10^p` is wrong in a way that shows: `2.675`
/// is really 2.67499999999999982…, so the exact answer at two places is 2.67,
/// yet `2.675 * 100` rounds *up* to exactly 267.5 in f64 and any tie rule then
/// says 2.68. Formatting to 25 digits does not help either — Zig pads the
/// shortest round-trip form with zeros, reproducing "2.6750000…".
///
/// So the comparison is done on integers. Every finite f64 is exactly
/// `m · 2^e`; the question "which side of the midpoint is `m · 2^e · 10^p`"
/// is then a shift and a remainder, with no rounding anywhere until the final
/// decimal string is parsed back (once, correctly rounded). Inputs that would
/// overflow `u128` fall back to the scaled form — they are past the precision
/// f64 can express anyway.
fn roundHalfEven(x: f64, p: i32) f64 {
    if (x == 0 or std.math.isNan(x) or std.math.isInf(x)) return x;
    const neg = x < 0;
    // Saturated precision. At 400 decimal places the correction is below half
    // an ulp for every finite `f64`, so the value is unchanged; at -400 every
    // finite `f64` is below half of `10^400`, so the answer is zero. Both agree
    // with the reference, and both keep the exact path below out of the
    // `mulPow10` overflow fallback, which degenerates to NaN at this scale.
    if (p >= 400) return x;
    if (p <= -400) return if (neg) -0.0 else 0.0;
    const mag = @abs(x);

    const bits: u64 = @bitCast(mag);
    const raw_exp: u32 = @truncate((bits >> 52) & 0x7ff);
    var m: u128 = bits & ((@as(u64, 1) << 52) - 1);
    var e: i32 = undefined;
    if (raw_exp == 0) {
        e = -1074;
    } else {
        m |= @as(u128, 1) << 52;
        e = @as(i32, @intCast(raw_exp)) - 1075;
    }

    const n = scaledRoundHalfEven(m, e, p) orelse {
        const scale = powTen(p);
        const scaled = mag * scale;
        const f = @floor(scaled);
        const diff = scaled - f;
        const r = if (diff > 0.5) f + 1 else if (diff < 0.5) f else (if (@mod(f, 2.0) == 0.0) f else f + 1);
        return if (neg) -(r / scale) else r / scale;
    };

    var buf: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}e{d}", .{ n, -p }) catch return x;
    const out = std.fmt.parseFloat(f64, text) catch return x;
    return if (neg) -out else out;
}

/// `round_half_even(m · 2^e · 10^p)` as an exact integer, or null when it does
/// not fit in `u128`.
fn scaledRoundHalfEven(m: u128, e: i32, p: i32) ?u128 {
    // numerator / denominator, both exact.
    var num: u128 = m;
    var den: u128 = 1;
    if (p >= 0) {
        num = mulPow10(num, @intCast(p)) orelse return null;
    } else {
        den = mulPow10(1, @intCast(-p)) orelse return null;
    }
    if (e >= 0) {
        if (e >= 127) return null;
        num = std.math.shlExact(u128, num, @intCast(e)) catch return null;
    } else {
        const k: u32 = @intCast(-e);
        // Denominator beyond u128: the magnitude is far below half a unit in
        // the last place asked for, so the answer is 0 either way.
        if (k >= 127) return 0;
        den = std.math.shlExact(u128, den, @intCast(k)) catch return 0;
    }
    const q = num / den;
    const r = num % den;
    const twice = std.math.mul(u128, r, 2) catch return if (r > den / 2) q + 1 else q;
    if (twice > den) return q + 1;
    if (twice < den) return q;
    return if (q % 2 == 0) q else q + 1;
}

fn mulPow10(v: u128, p: u32) ?u128 {
    var acc = v;
    var i: u32 = 0;
    while (i < p) : (i += 1) acc = std.math.mul(u128, acc, 10) catch return null;
    return acc;
}

fn fSum(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const items = try seq(ctx, input);
    const attribute = args.get(0, "attribute");
    var acc: Value = args.get(1, "start") orelse Value{ .integer = 0 };
    for (items) |it| {
        const v = if (attribute != null and attribute.? != .none) try attrOf(ctx, it, attribute.?) else it;
        acc = try value.binary(ctx.arena, .add, acc, v);
    }
    return acc;
}

// ── sequence filters ────────────────────────────────────────────────────────

fn fLength(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = ctx;
    _ = args;
    return .{ .integer = @intCast(try value.length(input)) };
}

fn fList(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    return .{ .list = try seq(ctx, input) };
}

fn fFirst(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const items = try seq(ctx, input);
    return if (items.len == 0) .{ .undef = .{ .name = "first" } } else items[0];
}

fn fLast(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const items = try seq(ctx, input);
    if (items.len == 0) return .{ .undef = .{ .name = "last" } };
    const last = items[items.len - 1];
    // W2-A1/A2-jinja-F6: `do_last` is `next(iter(reversed(seq)))`. `str`
    // (and `Markup`) define no `__reversed__`, so `reversed()` falls back to
    // the index-based sequence protocol (`seq[len-1]`, `seq[len-2]`, ...),
    // which — unlike `__iter__` (see `value.chars()`'s doc comment) —
    // *does* preserve `Markup` on a single-character result: verified live,
    // `list(reversed(Markup('<b>x</b>')))[0]` is `Markup`, not `str`.
    // `first` (`next(iter(seq))`) goes through `__iter__` and has no such
    // fallback, so it stays plain — the two filters genuinely disagree.
    if (input == .string and last == .string) return markupAware(ctx, input, last.string.bytes);
    return last;
}

fn fReverse(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    if (input == .string) {
        // Reversed by codepoint, like Python's `s[::-1]`.
        const cs = try value.chars(ctx.arena, input.string);
        var out: std.ArrayList(u8) = .empty;
        var i = cs.len;
        while (i > 0) {
            i -= 1;
            try out.appendSlice(ctx.arena, cs[i].string.bytes);
        }
        return markupAware(ctx, input, out.items);
    }
    const items = try seq(ctx, input);
    const out = try ctx.arena.alloc(Value, items.len);
    for (items, 0..) |it, i| out[items.len - 1 - i] = it;
    return .{ .list = out };
}

fn fJoin(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const items = try seq(ctx, input);
    const sep_val = args.get(0, "d") orelse Value.empty_string;
    const attribute = args.byName("attribute");

    var parts: std.ArrayList(Value) = .empty;
    for (items) |it| {
        const v = if (attribute != null and attribute.? != .none) try attrOf(ctx, it, attribute.?) else it;
        try parts.append(ctx.arena, v);
    }
    if (!ctx.autoescape) {
        var out: std.ArrayList(u8) = .empty;
        const sep = try ctx.toStr(sep_val);
        for (parts.items, 0..) |p, i| {
            if (i != 0) try out.appendSlice(ctx.arena, sep);
            try out.appendSlice(ctx.arena, try ctx.toStr(p));
        }
        return Value.str(out.items);
    }
    // Autoescaping: every non-markup part is escaped and the result is markup.
    var out: std.ArrayList(u8) = .empty;
    const sep_esc = try escapedBytes(ctx, sep_val);
    for (parts.items, 0..) |p, i| {
        if (i != 0) try out.appendSlice(ctx.arena, sep_esc);
        try out.appendSlice(ctx.arena, try escapedBytes(ctx, p));
    }
    return .{ .string = .{ .bytes = out.items, .safe = true } };
}

fn escapedBytes(ctx: *Ctx, v: Value) Error![]const u8 {
    if (v == .string and v.string.safe) return v.string.bytes;
    return value.escapeAlloc(ctx.arena, try ctx.toStr(v));
}

fn fBatch(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const items = try seq(ctx, input);
    const n_i = try intArg(args.get(0, "linecount") orelse return error.BadArgument, 1);
    if (n_i == 0) return error.BadArgument;
    // MATCH THE REFERENCE. `do_batch`'s `if len(tmp) == linecount` can never
    // fire for a negative count, so every item lands in a single batch and
    // `fill_with` never applies: Jinja2 3.1.6 renders `[1,2,3]|batch(-1)` and
    // `[1,2,3]|batch(-1,'x')` both as `[[1, 2, 3]]`, and `[]|batch(-1)` as `[]`.
    if (n_i < 0) {
        if (items.len == 0) return .{ .list = &.{} };
        const rows = try ctx.arena.alloc(Value, 1);
        rows[0] = .{ .list = try ctx.arena.dupe(Value, items) };
        return .{ .list = rows };
    }
    const n: usize = @intCast(n_i);
    // A `fill_with` row is padded up to `n`, so `n` is an allocation size.
    if (n > value.max_items) return error.OutOfRange;
    const fill = args.get(1, "fill_with");
    var rows: std.ArrayList(Value) = .empty;
    var i: usize = 0;
    while (i < items.len) : (i += n) {
        const end = @min(i + n, items.len);
        var row: std.ArrayList(Value) = .empty;
        try row.appendSlice(ctx.arena, items[i..end]);
        if (fill != null and fill.? != .none) {
            while (row.items.len < n) try row.append(ctx.arena, fill.?);
        }
        try rows.append(ctx.arena, .{ .list = row.items });
    }
    return .{ .list = rows.items };
}

fn fSlice(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const items = try seq(ctx, input);
    const n_i = try intArg(args.get(0, "slices") orelse return error.BadArgument, 1);
    if (n_i == 0) return error.BadArgument;
    // MATCH THE REFERENCE. `do_slice` iterates `range(slices)`, which is empty
    // for a negative count: Jinja2 3.1.6 renders `[1,2,3]|slice(-1)` and
    // `[1,2,3]|slice(-2,'x')` both as `[]`.
    if (n_i < 0) return .{ .list = &.{} };
    const n: usize = @intCast(n_i);
    // `n` is the row count, so it is an allocation size.
    if (n > value.max_items) return error.OutOfRange;
    const fill = args.get(1, "fill_with");
    const per = items.len / n;
    const extra = items.len % n;
    var rows: std.ArrayList(Value) = .empty;
    var idx: usize = 0;
    while (idx < n) : (idx += 1) {
        const start = idx * per + @min(idx, extra);
        var end = start + per;
        if (idx < extra) end += 1;
        var row: std.ArrayList(Value) = .empty;
        try row.appendSlice(ctx.arena, items[start..@min(end, items.len)]);
        if (fill != null and fill.? != .none and idx >= extra and extra != 0)
            try row.append(ctx.arena, fill.?);
        try rows.append(ctx.arena, .{ .list = row.items });
    }
    return .{ .list = rows.items };
}

const SortKey = struct {
    idx: usize,
    num: f64 = 0,
    text: []const u8 = "",
};

fn lessNum(_: void, a: SortKey, b: SortKey) bool {
    return a.num < b.num;
}

fn lessText(_: void, a: SortKey, b: SortKey) bool {
    return std.mem.order(u8, a.text, b.text) == .lt;
}

/// Build the comparison keys for sort/min/max/unique. Returns null when the
/// values are not uniformly numeric or uniformly textual — the reference would
/// raise a `TypeError` there and so do we.
fn sortKeys(ctx: *Ctx, items: []const Value, attribute: ?Value, case_sensitive: bool) Error!struct {
    keys: []SortKey,
    numeric: bool,
} {
    const keys = try ctx.arena.alloc(SortKey, items.len);
    var numeric = true;
    var textual = true;
    for (items, 0..) |it, i| {
        const v = if (attribute != null and attribute.? != .none) try attrOf(ctx, it, attribute.?) else it;
        keys[i] = .{ .idx = i };
        switch (v) {
            .integer => |n| keys[i].num = @floatFromInt(n),
            .float => |f| keys[i].num = f,
            .boolean => |b| keys[i].num = if (b) 1 else 0,
            else => numeric = false,
        }
        switch (v) {
            .string => |s| {
                if (case_sensitive) {
                    keys[i].text = s.bytes;
                } else {
                    const low = try ctx.arena.dupe(u8, s.bytes);
                    for (low) |*c| c.* = std.ascii.toLower(c.*);
                    keys[i].text = low;
                }
            },
            else => textual = false,
        }
    }
    if (!numeric and !textual) return error.TypeMismatch;
    return .{ .keys = keys, .numeric = numeric };
}

fn fSort(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const items = try seq(ctx, input);
    const reverse = boolArg(args, 0, "reverse", false);
    const case_sensitive = boolArg(args, 1, "case_sensitive", false);
    const attribute = args.get(2, "attribute");
    const k = try sortKeys(ctx, items, attribute, case_sensitive);
    if (k.numeric) std.sort.block(SortKey, k.keys, {}, lessNum) else std.sort.block(SortKey, k.keys, {}, lessText);
    const out = try ctx.arena.alloc(Value, items.len);
    for (k.keys, 0..) |key, i| out[if (reverse) items.len - 1 - i else i] = items[key.idx];
    return .{ .list = out };
}

fn extremum(ctx: *Ctx, input: Value, args: Args, want_max: bool) Error!Value {
    const items = try seq(ctx, input);
    if (items.len == 0) return .{ .undef = .{ .name = if (want_max) "max" else "min" } };
    const case_sensitive = boolArg(args, 0, "case_sensitive", false);
    const attribute = args.get(1, "attribute");
    const k = try sortKeys(ctx, items, attribute, case_sensitive);
    var best: usize = 0;
    for (k.keys[1..]) |key| {
        const better = if (k.numeric)
            (if (want_max) key.num > k.keys[best].num else key.num < k.keys[best].num)
        else
            (if (want_max)
                std.mem.order(u8, key.text, k.keys[best].text) == .gt
            else
                std.mem.order(u8, key.text, k.keys[best].text) == .lt);
        if (better) best = key.idx;
    }
    return items[k.keys[best].idx];
}

fn fMin(ctx: *Ctx, input: Value, args: Args) Error!Value {
    return extremum(ctx, input, args, false);
}

fn fMax(ctx: *Ctx, input: Value, args: Args) Error!Value {
    return extremum(ctx, input, args, true);
}

fn fUnique(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const items = try seq(ctx, input);
    const case_sensitive = boolArg(args, 0, "case_sensitive", false);
    const attribute = args.get(1, "attribute");
    var out: std.ArrayList(Value) = .empty;
    var seen: std.ArrayList(Value) = .empty;
    for (items) |it| {
        var key = if (attribute != null and attribute.? != .none) try attrOf(ctx, it, attribute.?) else it;
        if (!case_sensitive and key == .string) {
            const low = try ctx.arena.dupe(u8, key.string.bytes);
            for (low) |*c| c.* = std.ascii.toLower(c.*);
            key = Value.str(low);
        }
        var dup = false;
        for (seen.items) |s| if (value.valueEql(s, key)) {
            dup = true;
            break;
        };
        if (dup) continue;
        try seen.append(ctx.arena, key);
        try out.append(ctx.arena, it);
    }
    return .{ .list = out.items };
}

fn fItems(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = args;
    const pairs: []const value.Pair = switch (input) {
        .map => |m| m.pairs,
        .namespace => |ns| ns.pairs.items,
        .undef => return error.UndefinedValue,
        else => return error.TypeMismatch,
    };
    return pairsToList(ctx, pairs);
}

fn pairsToList(ctx: *Ctx, pairs: []const value.Pair) Error!Value {
    const out = try ctx.arena.alloc(Value, pairs.len);
    for (pairs, 0..) |p, i| {
        const two = try ctx.arena.alloc(Value, 2);
        two[0] = p.key;
        two[1] = p.value;
        out[i] = .{ .tuple = two };
    }
    return .{ .list = out };
}

fn fDictsort(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const pairs: []const value.Pair = switch (input) {
        .map => |m| m.pairs,
        .namespace => |ns| ns.pairs.items,
        .undef => return error.UndefinedValue,
        else => return error.TypeMismatch,
    };
    const case_sensitive = boolArg(args, 0, "case_sensitive", false);
    const by = try strArg(ctx, args, 1, "by", "key");
    const reverse = boolArg(args, 2, "reverse", false);
    const use_value = std.mem.eql(u8, by, "value");
    if (!use_value and !std.mem.eql(u8, by, "key")) return error.BadArgument;

    const picked = try ctx.arena.alloc(Value, pairs.len);
    for (pairs, 0..) |p, i| picked[i] = if (use_value) p.value else p.key;
    const k = try sortKeys(ctx, picked, null, case_sensitive);
    if (k.numeric) std.sort.block(SortKey, k.keys, {}, lessNum) else std.sort.block(SortKey, k.keys, {}, lessText);

    const ordered = try ctx.arena.alloc(value.Pair, pairs.len);
    for (k.keys, 0..) |key, i| ordered[if (reverse) pairs.len - 1 - i else i] = pairs[key.idx];
    return pairsToList(ctx, ordered);
}

fn fDefault(ctx: *Ctx, input: Value, args: Args) Error!Value {
    _ = ctx;
    const dflt = args.get(0, "default_value") orelse Value.empty_string;
    const boolean = boolArg(args, 1, "boolean", false);
    if (input == .undef) return dflt;
    if (boolean and !input.truthy()) return dflt;
    return input;
}

fn fMap(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const items = try seq(ctx, input);
    const out = try ctx.arena.alloc(Value, items.len);
    if (args.byName("attribute")) |attribute| {
        const dflt = args.byName("default");
        for (items, 0..) |it, i| {
            const v = try attrOf(ctx, it, attribute);
            out[i] = if (v == .undef and dflt != null) dflt.? else v;
        }
        return .{ .list = out };
    }
    if (args.pos.len == 0) return error.BadArgument;
    const name = switch (args.pos[0]) {
        .string => |s| s.bytes,
        else => return error.BadArgument,
    };
    const rest: Args = .{ .pos = args.pos[1..], .kw = args.kw };
    for (items, 0..) |it, i| out[i] = try ctx.callFilter(ctx, name, it, rest);
    return .{ .list = out };
}

fn selectLike(ctx: *Ctx, input: Value, args: Args, keep: bool, by_attr: bool) Error!Value {
    const items = try seq(ctx, input);
    var out: std.ArrayList(Value) = .empty;
    var attribute: ?Value = null;
    var pos = args.pos;
    if (by_attr) {
        if (pos.len == 0) return error.BadArgument;
        attribute = pos[0];
        pos = pos[1..];
    }
    const test_name: ?[]const u8 = if (pos.len == 0) null else switch (pos[0]) {
        .string => |s| s.bytes,
        else => return error.BadArgument,
    };
    const rest: Args = .{ .pos = if (pos.len == 0) &.{} else pos[1..], .kw = args.kw };

    for (items) |it| {
        const subject = if (attribute) |a| try attrOf(ctx, it, a) else it;
        const ok = if (test_name) |n| try ctx.callTest(ctx, n, subject, rest) else subject.truthy();
        if (ok == keep) try out.append(ctx.arena, it);
    }
    return .{ .list = out.items };
}

fn fSelect(ctx: *Ctx, input: Value, args: Args) Error!Value {
    return selectLike(ctx, input, args, true, false);
}
fn fReject(ctx: *Ctx, input: Value, args: Args) Error!Value {
    return selectLike(ctx, input, args, false, false);
}
fn fSelectattr(ctx: *Ctx, input: Value, args: Args) Error!Value {
    return selectLike(ctx, input, args, true, true);
}
fn fRejectattr(ctx: *Ctx, input: Value, args: Args) Error!Value {
    return selectLike(ctx, input, args, false, true);
}

// ── tojson ──────────────────────────────────────────────────────────────────

fn fTojson(ctx: *Ctx, input: Value, args: Args) Error!Value {
    const indent_v = args.get(0, "indent");
    // MATCH THE REFERENCE. `json.dumps(indent=n)` spells the pad as `' ' * n`,
    // so a negative indent still switches on the newlines but emits no spaces:
    // Jinja2 3.1.6 renders `{'a':1,'b':2}|tojson(-1)` identically to
    // `…|tojson(0)`, as `{\n"a": 1,\n"b": 2\n}`.
    const indent: ?usize = if (indent_v == null or indent_v.? == .none)
        null
    else blk: {
        const n = try intArg(indent_v.?, 0);
        if (n > value.max_alloc) return error.OutOfRange;
        break :blk if (n < 0) 0 else @as(usize, @intCast(n));
    };
    var aw: std.Io.Writer.Allocating = .init(ctx.arena);
    try jsonWrite(ctx, &aw.writer, input, indent, 0);
    // Jinja escapes the four characters that could break out of a <script> or
    // an attribute, then marks the result safe.
    var out: std.ArrayList(u8) = .empty;
    for (aw.written()) |c| switch (c) {
        '<' => try out.appendSlice(ctx.arena, "\\u003c"),
        '>' => try out.appendSlice(ctx.arena, "\\u003e"),
        '&' => try out.appendSlice(ctx.arena, "\\u0026"),
        '\'' => try out.appendSlice(ctx.arena, "\\u0027"),
        else => try out.append(ctx.arena, c),
    };
    return .{ .string = .{ .bytes = out.items, .safe = true } };
}

fn jsonWrite(ctx: *Ctx, w: *std.Io.Writer, v: Value, indent: ?usize, depth: usize) Error!void {
    switch (v) {
        .undef => return error.UndefinedValue,
        .none => w.writeAll("null") catch return error.OutOfMemory,
        .boolean => |b| w.writeAll(if (b) "true" else "false") catch return error.OutOfMemory,
        .integer => |i| w.print("{d}", .{i}) catch return error.OutOfMemory,
        .float => |f| {
            if (std.math.isNan(f) or std.math.isInf(f)) return error.BadArgument;
            try value.floatTo(w, f);
        },
        .string => |s| try jsonString(w, s.bytes),
        .list, .tuple => |items| {
            w.writeAll("[") catch return error.OutOfMemory;
            for (items, 0..) |e, i| {
                if (i != 0) w.writeAll(",") catch return error.OutOfMemory;
                try jsonSep(w, indent, depth + 1, i != 0);
                try jsonWrite(ctx, w, e, indent, depth + 1);
            }
            if (items.len != 0 and indent != null) try jsonSep(w, indent, depth, true);
            w.writeAll("]") catch return error.OutOfMemory;
        },
        .map, .namespace => {
            const pairs: []const value.Pair = switch (v) {
                .map => |m| m.pairs,
                .namespace => |ns| ns.pairs.items,
                else => unreachable,
            };
            // The reference's default policy sorts object keys.
            const order = try ctx.arena.alloc(SortKey, pairs.len);
            for (pairs, 0..) |p, i| {
                order[i] = .{ .idx = i, .text = switch (p.key) {
                    .string => |s| s.bytes,
                    else => return error.BadArgument,
                } };
            }
            std.sort.block(SortKey, order, {}, lessText);
            w.writeAll("{") catch return error.OutOfMemory;
            for (order, 0..) |o, i| {
                if (i != 0) w.writeAll(",") catch return error.OutOfMemory;
                try jsonSep(w, indent, depth + 1, i != 0);
                try jsonString(w, pairs[o.idx].key.string.bytes);
                w.writeAll(": ") catch return error.OutOfMemory;
                try jsonWrite(ctx, w, pairs[o.idx].value, indent, depth + 1);
            }
            if (pairs.len != 0 and indent != null) try jsonSep(w, indent, depth, true);
            w.writeAll("}") catch return error.OutOfMemory;
        },
        .loop, .macro => return error.BadArgument,
    }
}

fn jsonSep(w: *std.Io.Writer, indent: ?usize, depth: usize, comma: bool) Error!void {
    if (indent) |n| {
        w.writeAll("\n") catch return error.OutOfMemory;
        w.splatByteAll(' ', n * depth) catch return error.OutOfMemory;
    } else if (comma) {
        w.writeAll(" ") catch return error.OutOfMemory;
    }
}

fn jsonString(w: *std.Io.Writer, s: []const u8) Error!void {
    w.writeAll("\"") catch return error.OutOfMemory;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c < 0x80) {
            switch (c) {
                '"' => w.writeAll("\\\"") catch return error.OutOfMemory,
                '\\' => w.writeAll("\\\\") catch return error.OutOfMemory,
                '\n' => w.writeAll("\\n") catch return error.OutOfMemory,
                '\r' => w.writeAll("\\r") catch return error.OutOfMemory,
                '\t' => w.writeAll("\\t") catch return error.OutOfMemory,
                0x08 => w.writeAll("\\b") catch return error.OutOfMemory,
                0x0c => w.writeAll("\\f") catch return error.OutOfMemory,
                else => if (c < 0x20)
                    w.print("\\u{x:0>4}", .{c}) catch return error.OutOfMemory
                else
                    w.writeByte(c) catch return error.OutOfMemory,
            }
            i += 1;
            continue;
        }
        // `ensure_ascii=True` is the reference's default: non-ASCII becomes
        // \uXXXX, with surrogate pairs above the BMP.
        const n = std.unicode.utf8ByteSequenceLength(s[i]) catch {
            w.print("\\u{x:0>4}", .{s[i]}) catch return error.OutOfMemory;
            i += 1;
            continue;
        };
        if (i + n > s.len) return error.BadArgument;
        const cp = std.unicode.utf8Decode(s[i .. i + n]) catch return error.BadArgument;
        if (cp < 0x10000) {
            w.print("\\u{x:0>4}", .{cp}) catch return error.OutOfMemory;
        } else {
            const v2 = cp - 0x10000;
            const hi = 0xD800 + (v2 >> 10);
            const lo = 0xDC00 + (v2 & 0x3FF);
            w.print("\\u{x:0>4}\\u{x:0>4}", .{ hi, lo }) catch return error.OutOfMemory;
        }
        i += n;
    }
    w.writeAll("\"") catch return error.OutOfMemory;
}

// ── registry ────────────────────────────────────────────────────────────────

pub const builtin_filters = [_]Entry{
    .{ .name = "abs", .func = fAbs },
    .{ .name = "batch", .func = fBatch },
    .{ .name = "capitalize", .func = fCapitalize },
    .{ .name = "center", .func = fCenter },
    .{ .name = "count", .func = fLength },
    .{ .name = "d", .func = fDefault },
    .{ .name = "default", .func = fDefault },
    .{ .name = "dictsort", .func = fDictsort },
    .{ .name = "e", .func = fEscape },
    .{ .name = "escape", .func = fEscape },
    .{ .name = "first", .func = fFirst },
    .{ .name = "float", .func = fFloat },
    .{ .name = "forceescape", .func = fForceEscape },
    .{ .name = "indent", .func = fIndent },
    .{ .name = "int", .func = fInt },
    .{ .name = "items", .func = fItems },
    .{ .name = "join", .func = fJoin },
    .{ .name = "last", .func = fLast },
    .{ .name = "length", .func = fLength },
    .{ .name = "list", .func = fList },
    .{ .name = "lower", .func = fLower },
    .{ .name = "map", .func = fMap },
    .{ .name = "max", .func = fMax },
    .{ .name = "min", .func = fMin },
    .{ .name = "reject", .func = fReject },
    .{ .name = "rejectattr", .func = fRejectattr },
    .{ .name = "replace", .func = fReplace },
    .{ .name = "reverse", .func = fReverse },
    .{ .name = "round", .func = fRound },
    .{ .name = "safe", .func = fSafe },
    .{ .name = "select", .func = fSelect },
    .{ .name = "selectattr", .func = fSelectattr },
    .{ .name = "slice", .func = fSlice },
    .{ .name = "sort", .func = fSort },
    .{ .name = "string", .func = fString },
    .{ .name = "striptags", .func = fStriptags },
    .{ .name = "sum", .func = fSum },
    .{ .name = "title", .func = fTitle },
    .{ .name = "tojson", .func = fTojson },
    .{ .name = "trim", .func = fTrim },
    .{ .name = "truncate", .func = fTruncate },
    .{ .name = "unique", .func = fUnique },
    .{ .name = "upper", .func = fUpper },
    .{ .name = "urlencode", .func = fUrlencode },
    .{ .name = "wordcount", .func = fWordcount },
    .{ .name = "xmlattr", .func = fXmlattr },
};

// ── tests ───────────────────────────────────────────────────────────────────

fn tDefined(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input != .undef;
}
fn tUndefined(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .undef;
}
fn tNone(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .none;
}
fn tBoolean(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .boolean;
}
fn tTrue(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .boolean and input.boolean;
}
fn tFalse(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .boolean and !input.boolean;
}
fn tInteger(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .integer;
}
fn tFloatTest(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .float;
}
fn tNumber(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .integer or input == .float or input == .boolean;
}
fn tString(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .string;
}
fn tMapping(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .map or input == .namespace;
}
fn tSequence(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return switch (input) {
        .list, .string, .map, .namespace => true,
        else => false,
    };
}
fn tIterable(ctx: *Ctx, input: Value, args: Args) Error!bool {
    return tSequence(ctx, input, args);
}
fn tEscaped(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    return input == .string and input.string.safe;
}
fn tEven(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    if (input != .integer) return error.TypeMismatch;
    return @mod(input.integer, 2) == 0;
}
fn tOdd(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = args;
    if (input != .integer) return error.TypeMismatch;
    return @mod(input.integer, 2) != 0;
}
fn tDivisibleby(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    const by = args.get(0, "num") orelse return error.BadArgument;
    if (input != .integer or by != .integer) return error.TypeMismatch;
    if (by.integer == 0) return error.DivisionByZero;
    return @mod(input.integer, by.integer) == 0;
}
fn tUpperTest(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = args;
    const s = try ctx.toStr(input);
    var has_alpha = false;
    for (s) |c| {
        if (std.ascii.isAlphabetic(c)) has_alpha = true;
        if (std.ascii.isLower(c)) return false;
    }
    return has_alpha;
}
fn tLowerTest(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = args;
    const s = try ctx.toStr(input);
    var has_alpha = false;
    for (s) |c| {
        if (std.ascii.isAlphabetic(c)) has_alpha = true;
        if (std.ascii.isUpper(c)) return false;
    }
    return has_alpha;
}

fn cmpTest(comptime op: value.CmpOp) TestFn {
    return struct {
        fn f(ctx: *Ctx, input: Value, args: Args) Error!bool {
            _ = ctx;
            const other = args.get(0, "other") orelse return error.BadArgument;
            return value.compare(op, input, other);
        }
    }.f;
}

fn tIn(ctx: *Ctx, input: Value, args: Args) Error!bool {
    _ = ctx;
    const container = args.get(0, "seq") orelse return error.BadArgument;
    return value.contains(container, input);
}

pub const builtin_tests = [_]TestEntry{
    .{ .name = "boolean", .func = tBoolean },
    .{ .name = "defined", .func = tDefined },
    .{ .name = "divisibleby", .func = tDivisibleby },
    .{ .name = "eq", .func = cmpTest(.eq) },
    .{ .name = "equalto", .func = cmpTest(.eq) },
    .{ .name = "escaped", .func = tEscaped },
    .{ .name = "even", .func = tEven },
    .{ .name = "false", .func = tFalse },
    .{ .name = "float", .func = tFloatTest },
    .{ .name = "ge", .func = cmpTest(.ge) },
    .{ .name = "greaterthan", .func = cmpTest(.gt) },
    .{ .name = "gt", .func = cmpTest(.gt) },
    .{ .name = "in", .func = tIn },
    .{ .name = "integer", .func = tInteger },
    .{ .name = "iterable", .func = tIterable },
    .{ .name = "le", .func = cmpTest(.le) },
    .{ .name = "lessthan", .func = cmpTest(.lt) },
    .{ .name = "lower", .func = tLowerTest },
    .{ .name = "lt", .func = cmpTest(.lt) },
    .{ .name = "mapping", .func = tMapping },
    .{ .name = "ne", .func = cmpTest(.ne) },
    .{ .name = "none", .func = tNone },
    .{ .name = "number", .func = tNumber },
    .{ .name = "odd", .func = tOdd },
    .{ .name = "sequence", .func = tSequence },
    .{ .name = "string", .func = tString },
    .{ .name = "true", .func = tTrue },
    .{ .name = "undefined", .func = tUndefined },
    .{ .name = "upper", .func = tUpperTest },
};

// ── value methods (`s.upper()`, `d.items()`, …) ─────────────────────────────

/// `error.Unsupported` means "no such method on this type", which the renderer
/// turns into a message naming both.
pub fn callMethod(
    arena: std.mem.Allocator,
    obj: Value,
    name: []const u8,
    args: Args,
    autoescape: bool,
) Error!Value {
    var ctx: Ctx = .{
        .arena = arena,
        .autoescape = autoescape,
        .strict = true,
        .user = undefined,
        .callFilter = unavailableFilter,
        .callTest = unavailableTest,
    };
    switch (obj) {
        .undef => return error.UndefinedValue,
        .string => |s| return stringMethod(&ctx, s, name, args),
        .map, .namespace => {
            const pairs: []const value.Pair = switch (obj) {
                .map => |m| m.pairs,
                .namespace => |ns| ns.pairs.items,
                else => unreachable,
            };
            if (std.mem.eql(u8, name, "items")) return pairsToList(&ctx, pairs);
            if (std.mem.eql(u8, name, "keys")) {
                const out = try arena.alloc(Value, pairs.len);
                for (pairs, 0..) |p, i| out[i] = p.key;
                return .{ .list = out };
            }
            if (std.mem.eql(u8, name, "values")) {
                const out = try arena.alloc(Value, pairs.len);
                for (pairs, 0..) |p, i| out[i] = p.value;
                return .{ .list = out };
            }
            if (std.mem.eql(u8, name, "get")) {
                const key = args.get(0, "key") orelse return error.BadArgument;
                for (pairs) |p| if (value.valueEql(p.key, key)) return p.value;
                return args.get(1, "default") orelse .none;
            }
            return error.Unsupported;
        },
        .list, .tuple => |items| {
            if (std.mem.eql(u8, name, "count")) {
                const needle = args.get(0, "value") orelse return error.BadArgument;
                var n: i64 = 0;
                for (items) |e| if (value.valueEql(e, needle)) {
                    n += 1;
                };
                return .{ .integer = n };
            }
            if (std.mem.eql(u8, name, "index")) {
                const needle = args.get(0, "value") orelse return error.BadArgument;
                for (items, 0..) |e, i| if (value.valueEql(e, needle)) return .{ .integer = @intCast(i) };
                return error.BadArgument;
            }
            return error.Unsupported;
        },
        else => return error.Unsupported,
    }
}

fn unavailableFilter(ctx: *Ctx, name: []const u8, input: Value, args: Args) Error!Value {
    _ = ctx;
    _ = name;
    _ = input;
    _ = args;
    return error.Unsupported;
}

fn unavailableTest(ctx: *Ctx, name: []const u8, input: Value, args: Args) Error!bool {
    _ = ctx;
    _ = name;
    _ = input;
    _ = args;
    return error.Unsupported;
}

fn stringMethod(ctx: *Ctx, s: value.Str, name: []const u8, args: Args) Error!Value {
    const input: Value = .{ .string = s };
    if (std.mem.eql(u8, name, "upper")) return fUpper(ctx, input, args);
    if (std.mem.eql(u8, name, "lower")) return fLower(ctx, input, args);
    if (std.mem.eql(u8, name, "title")) return titleMethod(ctx, input);
    if (std.mem.eql(u8, name, "capitalize")) return fCapitalize(ctx, input, args);
    if (std.mem.eql(u8, name, "strip")) return fTrim(ctx, input, args);
    if (std.mem.eql(u8, name, "replace")) return replaceMethod(ctx, s, args);
    if (std.mem.eql(u8, name, "lstrip")) {
        const cut = try strArg(ctx, args, 0, "chars", " \t\r\n\x0b\x0c");
        return markupAware(ctx, input, std.mem.trimStart(u8, s.bytes, cut));
    }
    if (std.mem.eql(u8, name, "rstrip")) {
        const cut = try strArg(ctx, args, 0, "chars", " \t\r\n\x0b\x0c");
        return markupAware(ctx, input, std.mem.trimEnd(u8, s.bytes, cut));
    }
    if (std.mem.eql(u8, name, "startswith")) {
        const p = try strArg(ctx, args, 0, "prefix", "");
        return .{ .boolean = std.mem.startsWith(u8, s.bytes, p) };
    }
    if (std.mem.eql(u8, name, "endswith")) {
        const p = try strArg(ctx, args, 0, "suffix", "");
        return .{ .boolean = std.mem.endsWith(u8, s.bytes, p) };
    }
    if (std.mem.eql(u8, name, "count")) {
        const p = try strArg(ctx, args, 0, "sub", "");
        if (p.len == 0) return error.BadArgument;
        var n: i64 = 0;
        var i: usize = 0;
        while (std.mem.indexOfPos(u8, s.bytes, i, p)) |at| : (i = at + p.len) n += 1;
        return .{ .integer = n };
    }
    if (std.mem.eql(u8, name, "find")) {
        const p = try strArg(ctx, args, 0, "sub", "");
        const at = std.mem.indexOf(u8, s.bytes, p) orelse return .{ .integer = -1 };
        return .{ .integer = @intCast(at) };
    }
    // W2-A1/A2-jinja-F6: `str.split()`/`str.splitlines()` on a `Markup`
    // receiver return `Markup` parts (verified live: `Markup('<b>x</b>')
    // .split('x')` is `[Markup('<b>'), Markup('</b>')]`) — the opposite of
    // `value.chars()`'s per-character iteration, which loses the mark (see
    // its doc comment). Two different reference behaviours for two
    // different ways of breaking a markup string apart.
    if (std.mem.eql(u8, name, "split")) {
        const sep_v = args.get(0, "sep");
        var out: std.ArrayList(Value) = .empty;
        if (sep_v == null or sep_v.? == .none) {
            var it = std.mem.tokenizeAny(u8, s.bytes, " \t\r\n\x0b\x0c");
            while (it.next()) |part| try out.append(ctx.arena, markupAware(ctx, input, part));
        } else {
            const sep = try ctx.toStr(sep_v.?);
            if (sep.len == 0) return error.BadArgument;
            var it = std.mem.splitSequence(u8, s.bytes, sep);
            while (it.next()) |part| try out.append(ctx.arena, markupAware(ctx, input, part));
        }
        return .{ .list = out.items };
    }
    if (std.mem.eql(u8, name, "splitlines")) {
        var out: std.ArrayList(Value) = .empty;
        var it = std.mem.splitScalar(u8, s.bytes, '\n');
        var pending: ?[]const u8 = null;
        while (it.next()) |part| {
            if (pending) |pv| try out.append(ctx.arena, markupAware(ctx, input, pv));
            pending = std.mem.trimEnd(u8, part, "\r");
        }
        if (pending) |pv| if (pv.len != 0) try out.append(ctx.arena, markupAware(ctx, input, pv));
        return .{ .list = out.items };
    }
    if (std.mem.eql(u8, name, "join")) {
        const items = args.get(0, "iterable") orelse return error.BadArgument;
        return fJoin(ctx, items, .{ .pos = &.{input} });
    }
    if (std.mem.eql(u8, name, "isdigit")) {
        if (s.bytes.len == 0) return .{ .boolean = false };
        for (s.bytes) |c| if (!std.ascii.isDigit(c)) return .{ .boolean = false };
        return .{ .boolean = true };
    }
    if (std.mem.eql(u8, name, "isalpha")) {
        if (s.bytes.len == 0) return .{ .boolean = false };
        for (s.bytes) |c| if (!std.ascii.isAlphabetic(c)) return .{ .boolean = false };
        return .{ .boolean = true };
    }
    if (std.mem.eql(u8, name, "removeprefix")) {
        const p = try strArg(ctx, args, 0, "prefix", "");
        if (std.mem.startsWith(u8, s.bytes, p)) return markupAware(ctx, input, s.bytes[p.len..]);
        return input;
    }
    if (std.mem.eql(u8, name, "removesuffix")) {
        const p = try strArg(ctx, args, 0, "suffix", "");
        if (p.len != 0 and std.mem.endsWith(u8, s.bytes, p))
            return markupAware(ctx, input, s.bytes[0 .. s.bytes.len - p.len]);
        return input;
    }
    return error.Unsupported;
}

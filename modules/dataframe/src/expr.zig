// SPDX-License-Identifier: MIT
//! Expressions over a `Frame`'s columns: `mutate` (dplyr `mutate`, pandas `assign`,
//! polars `with_columns`), `where` (filter by a nested predicate) and `cast` (the
//! coercion rules in one place). An `Expr` tree is compiled once to a flat stack
//! program that reads the columns it names, so a row costs no name lookup and no
//! recursion; compiling is where a cyclic or too deep tree is refused. Taken from
//! `tabular`'s `expr` (the same authors, MIT), whose row verbs are the oracle here.
//!
//! Semantics, each with its reason:
//! - **Missing** = null or NaN. Arithmetic and comparison with a missing operand give
//!   null. `and`/`or` are three-valued (Kleene): `false and null` is false, `true or
//!   null` is true; `where` keeps only true. This is SQL and polars; pandas' NaN
//!   comparisons give false instead, labelled in the oracle's vectors.
//! - **Kinds**: int op int stays int (`add`/`sub`/`mul`/`floordiv`/`mod`); overflow is
//!   null, never a wrapped number (a wrapped total is a confident wrong number; pandas
//!   and polars wrap). `div` and `pow` give float. decimal +/- decimal (or int) stays
//!   exact in i128, any other decimal arithmetic goes through f64. Text or bool in
//!   arithmetic is null. Float division by zero follows IEEE (inf, NaN); integer
//!   `floordiv`/`mod` by zero is null. `floordiv`/`mod` take the divisor's sign (Python).
//! - **Comparison** across kinds other than number/number is null; number with number
//!   is exact (`Value.order`), so an i64 above 2^53 is not rounded.
//! - **Text** verbs are bytewise; `lower`/`upper` touch ASCII only and `length` counts
//!   code points (bytes where the text is not valid UTF-8). Unicode case mapping would
//!   need its tables: rejected for this module (see SPEC).

const std = @import("std");
const ds = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const core = @import("core.zig");
const verbs = @import("verbs.zig");
const fnx = @import("exprfn.zig");
const dtf = @import("dtfn.zig");
pub const DtPart = dtf.DtPart;
pub const ParseTo = dtf.ParseTo;
pub const RoundMode = fnx.RoundMode;
pub const PadSide = fnx.PadSide;
pub const StripSide = fnx.StripSide;
const Frame = fm.Frame;
const ColumnData = fm.ColumnData;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

const Error = ExprError;

pub const ExprError = error{
    NoSuchColumn,
    OutOfMemory,
    /// The tree is deeper than `max_depth` (or cyclic), or wider than `max_nodes`.
    ExprTooLarge,
    /// A `.binary`/`.unary` given where the operator wants the other arity, or a
    /// result column name given twice.
    BadExpr,
    /// `where` over a frame of 2^32 - 1 rows or more (row indexes are `u32`), or a
    /// selection whose text does not fit the address space.
    TooLarge,
};

/// Deepest tree `compile` accepts: it recurses, and an `Expr` is caller data.
pub const max_depth: usize = 256;
/// Most nodes in one expression: bounds the program and the row stack.
pub const max_nodes: usize = 1 << 16;

pub const Unary = enum {
    neg,
    abs,
    sqrt,
    floor,
    ceil,
    /// Half to even (numpy, pandas; polars' default is half away from zero).
    round,
    exp,
    /// Natural log; of 0 is -inf, of a negative number NaN (IEEE).
    log,
    log10,
    sign,
    not,
    is_null,
    not_null,
    lower,
    upper,
    strip,
    length,
    // ── added after the move (survey rows 36-38, 92) ──
    sin,
    cos,
    tan,
    /// 1 / tan.
    cot,
    asin,
    acos,
    atan,
    sinh,
    cosh,
    tanh,
    asinh,
    acosh,
    atanh,
    cbrt,
    log1p,
    expm1,
    log2,
    erf,
    degrees,
    radians,
    /// A NaN float (polars `is_nan`): a number that is not NaN is false, null is null.
    is_nan,
    is_not_nan,
    /// Not NaN and not infinite; an int or decimal is finite.
    is_finite,
    is_infinite,
    /// Bits of an int's two's complement (polars `bitwise_count_ones` …); not an int: null.
    count_ones,
    count_zeros,
    leading_zeros,
    trailing_zeros,
    leading_ones,
    trailing_ones,
    /// `~x` of an int.
    bit_not,
    /// ASCII case (see `exprfn`): Python's `capitalize`, `title`, `swapcase`.
    capitalize,
    title,
    swapcase,
    /// The characters in reverse order (code points).
    reverse,
    /// Bytes of the text (polars `len_bytes`); `length` counts characters.
    len_bytes,
    /// Python's `isalpha` … `istitle` over ASCII (pandas `str.isalpha` …).
    is_alpha,
    is_digit,
    is_alnum,
    is_space,
    is_lower,
    is_upper,
    is_title,
    /// Whitespace off the start / the end only (pandas `lstrip`/`rstrip`).
    lstrip,
    rstrip,
};

pub const Binary = enum {
    add,
    sub,
    mul,
    div,
    floordiv,
    mod,
    pow,
    min,
    max,
    eq,
    ne,
    lt,
    le,
    gt,
    ge,
    @"and",
    @"or",
    contains,
    starts_with,
    ends_with,
    concat,
    // ── added after the move (survey rows 36, 37, 39, 92) ──
    /// int & int (polars `and_` on ints, pandas `&`); not two ints: null.
    bit_and,
    bit_or,
    bit_xor,
    /// `log(l) / log(r)`: the log of `l` to base `r` (polars `log(base)`).
    log_base,
    /// `atan2(l, r)`: the angle of the point (r, l).
    atan2,
    /// Equality where two missing cells are equal and never null (polars `eq_missing`).
    eq_missing,
    ne_missing,
    /// `l`, or `r` where `l` is a NaN float (polars `fill_nan`); a null stays null.
    fill_nan,
    /// The text without a leading / trailing `r` (pandas `removeprefix`, polars
    /// `strip_prefix`).
    strip_prefix,
    strip_suffix,
    /// The byte offset of the first / last `r` in `l`, null when absent (polars `find`;
    /// pandas' `find` gives -1 and counts characters).
    find,
    rfind,
    /// Non-overlapping occurrences of the literal `r` (Python's `count`).
    count_matches,
    /// `l` repeated `r` times (an int; `r <= 0` is empty).
    repeat,
    /// The first / last `r` characters (polars `str.head`/`str.tail`; a negative `r`
    /// all but the last / first `-r`).
    head,
    tail,
    /// `l` zero-filled to `r` characters after a sign (pandas and polars `zfill`).
    zfill,
    /// The character at position `r`, negative from the end; out of range null (pandas
    /// `str.get`).
    char_at,
};

pub const Expr = union(enum) {
    col: []const u8,
    lit: Value,
    unary: struct { op: Unary, x: *const Expr },
    binary: struct { op: Binary, l: *const Expr, r: *const Expr },
    /// `x` is one of `values` (SQL `IN`, pandas `isin`, polars `is_in`). A missing
    /// `x` gives null; `values` entries compare by key equality.
    is_in: struct { x: *const Expr, values: []const Value },
    /// null condition counts as false: gives `otherwise` (pandas' `where`, SQL's CASE).
    if_else: struct { cond: *const Expr, then: *const Expr, otherwise: *const Expr },
    /// The first non-missing, null when none.
    coalesce: []const Expr,
    /// `cast` with a failed conversion as null.
    cast: struct { x: *const Expr, to: ColumnType },
    /// Literal text replacement, all occurrences.
    replace: struct { x: *const Expr, from: []const u8, to: []const u8 },
    // ── added after the move ──
    /// pandas `round(decimals)`, polars `round(decimals, mode)`; see `exprfn.round`.
    round: struct { x: *const Expr, decimals: i32 = 0, mode: fnx.RoundMode = .half_even },
    /// polars `round_sig_figs`; `digits` of 0 is `error.BadExpr`.
    round_sig_figs: struct { x: *const Expr, digits: u32 },
    /// polars `is_close`; a negative or NaN tolerance is `error.BadExpr`.
    is_close: struct { l: *const Expr, r: *const Expr, rel_tol: f64 = 1e-9, abs_tol: f64 = 0, nans_equal: bool = false },
    /// pandas `pad`/`ljust`/`rjust`/`center`, polars `pad_start`/`pad_end`.
    pad: struct { x: *const Expr, width: usize, side: fnx.PadSide = .left, fill: u21 = ' ' },
    /// polars `str.slice(offset, length)` in characters.
    slice: struct { x: *const Expr, offset: i64, length: ?usize = null },
    /// pandas `strip(chars)`, polars `strip_chars(_start/_end)`; null chars = whitespace.
    strip_chars: struct { x: *const Expr, chars: ?[]const u8 = null, side: fnx.StripSide = .both },
    /// pandas `str.translate`: `from[i]` becomes `to[i]` (same character count, else
    /// `error.BadExpr`), the characters of `delete` go.
    translate: struct { x: *const Expr, from: []const u8, to: []const u8, delete: []const u8 = "" },
    /// polars `str.to_integer(base)`; a base outside 2..36 is `error.BadExpr`.
    to_integer: struct { x: *const Expr, base: u8 = 10 },
    /// polars `str.contains_any`.
    contains_any: struct { x: *const Expr, patterns: []const []const u8, ascii_case_insensitive: bool = false },
    /// polars `str.replace_many`: `with` one entry per pattern or one for all, no empty
    /// pattern (else `error.BadExpr`).
    replace_many: struct { x: *const Expr, patterns: []const []const u8, with: []const []const u8, ascii_case_insensitive: bool = false },
    /// One calendar component (pandas `dt.<part>`, polars `dt.<part>()`); see `dtfn`
    /// for the three temporal cell shapes.
    dt: struct { x: *const Expr, part: dtf.DtPart },
    /// Text to a date or a timestamp by a `%` format (pandas `to_datetime(format=)`,
    /// polars `str.strptime`); a format `dtfn.translateFormat` refuses is `error.BadExpr`.
    strptime: struct { x: *const Expr, format: []const u8, to: dtf.ParseTo = .date },
    /// A temporal cell as text by a `%` format (pandas and polars `dt.strftime`).
    strftime: struct { x: *const Expr, format: []const u8 },
    /// polars `dt.offset_by("1mo2d")`; a duration `dtfn.parseDuration` refuses is
    /// `error.BadExpr`.
    offset_by: struct { x: *const Expr, by: []const u8 },
    /// polars `dt.truncate("1h")`, pandas `dt.floor`; `every` positive, months or a
    /// fixed part but not both, else `error.BadExpr`.
    truncate: struct { x: *const Expr, every: []const u8 },
    /// polars `dt.add_business_days(n, roll="forward")`; see `dtfn.addBusinessDays`.
    add_business_days: struct { x: *const Expr, n: i64 },
};

const Inst = union(enum) {
    col: usize,
    lit: Value,
    unary: Unary,
    binary: Binary,
    is_in: []const u8, // index into Program.sets, as a pointer-sized handle (below)
    if_else,
    coalesce: u32,
    cast: ColumnType,
    replace: struct { from: []const u8, to: []const u8 },
    round: struct { decimals: i32, mode: fnx.RoundMode },
    round_sig_figs: u32,
    is_close: struct { rel_tol: f64, abs_tol: f64, nans_equal: bool },
    pad: struct { width: usize, side: fnx.PadSide, fill: u21 },
    slice: struct { offset: i64, length: ?usize },
    strip_chars: struct { chars: ?[]const u8, side: fnx.StripSide },
    translate: struct { from: []const u8, to: []const u8, delete: []const u8 },
    to_integer: u8,
    contains_any: struct { patterns: []const []const u8, fold: bool },
    replace_many: struct { patterns: []const []const u8, with: []const []const u8, fold: bool },
    dt: dtf.DtPart,
    strptime: struct { layout: []const u8, to: dtf.ParseTo },
    strftime: []const u8,
    offset_by: dtf.Duration,
    truncate: dtf.Duration,
    add_business_days: i64,
};

const Program = struct {
    code: []const Inst,
    stack: usize,
};

const Compiler = struct {
    a: std.mem.Allocator,
    f: Frame,
    code: std.ArrayList(Inst) = .empty,
    max: usize = 0,
    cur: usize = 0,

    fn push(c: *Compiler, inst: Inst, pops: usize) Error!void {
        if (c.code.items.len >= max_nodes) return error.ExprTooLarge;
        try c.code.append(c.a, inst);
        c.cur = c.cur - pops + 1;
        c.max = @max(c.max, c.cur);
    }

    fn go(c: *Compiler, e: *const Expr, depth: usize) Error!void {
        if (depth >= max_depth) return error.ExprTooLarge;
        switch (e.*) {
            .col => |name| try c.push(.{ .col = c.f.columnIndex(name) orelse return error.NoSuchColumn }, 0),
            .lit => |v| try c.push(.{ .lit = v }, 0),
            .unary => |u| {
                try c.go(u.x, depth + 1);
                try c.push(.{ .unary = u.op }, 1);
            },
            .binary => |b| {
                try c.go(b.l, depth + 1);
                try c.go(b.r, depth + 1);
                try c.push(.{ .binary = b.op }, 2);
            },
            .is_in => |s| {
                try c.go(s.x, depth + 1);
                // The set as sorted canonical keys, joined: membership by bsearch of
                // a length-prefixed block would be tighter, a hash set is simpler.
                try c.push(.{ .is_in = try encodeSet(c.a, s.values) }, 1);
            },
            .if_else => |f| {
                try c.go(f.cond, depth + 1);
                try c.go(f.then, depth + 1);
                try c.go(f.otherwise, depth + 1);
                try c.push(.if_else, 3);
            },
            .coalesce => |xs| {
                if (xs.len == 0) return error.BadExpr;
                if (xs.len > max_nodes) return error.ExprTooLarge;
                for (xs) |*x| try c.go(x, depth + 1);
                try c.push(.{ .coalesce = @intCast(xs.len) }, xs.len);
            },
            .cast => |k| {
                try c.go(k.x, depth + 1);
                try c.push(.{ .cast = k.to }, 1);
            },
            .replace => |r| {
                if (r.from.len == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .replace = .{ .from = r.from, .to = r.to } }, 1);
            },
            .round => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .round = .{ .decimals = r.decimals, .mode = r.mode } }, 1);
            },
            .round_sig_figs => |r| {
                if (r.digits == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .round_sig_figs = r.digits }, 1);
            },
            .is_close => |r| {
                if (!(r.rel_tol >= 0) or !(r.abs_tol >= 0)) return error.BadExpr;
                try c.go(r.l, depth + 1);
                try c.go(r.r, depth + 1);
                try c.push(.{ .is_close = .{ .rel_tol = r.rel_tol, .abs_tol = r.abs_tol, .nans_equal = r.nans_equal } }, 2);
            },
            .pad => |r| {
                if (r.fill > 0x10FFFF or (r.fill >= 0xD800 and r.fill <= 0xDFFF)) return error.BadExpr;
                if (r.width > fnx.max_text_result) return error.TooLarge;
                try c.go(r.x, depth + 1);
                try c.push(.{ .pad = .{ .width = r.width, .side = r.side, .fill = r.fill } }, 1);
            },
            .slice => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .slice = .{ .offset = r.offset, .length = r.length } }, 1);
            },
            .strip_chars => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .strip_chars = .{ .chars = r.chars, .side = r.side } }, 1);
            },
            .translate => |r| {
                if (fnx.charCountOf(r.from) != fnx.charCountOf(r.to)) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .translate = .{ .from = r.from, .to = r.to, .delete = r.delete } }, 1);
            },
            .to_integer => |r| {
                if (r.base < 2 or r.base > 36) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .to_integer = r.base }, 1);
            },
            .contains_any => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .contains_any = .{ .patterns = r.patterns, .fold = r.ascii_case_insensitive } }, 1);
            },
            .replace_many => |r| {
                for (r.patterns) |pat| if (pat.len == 0) return error.BadExpr;
                if (!(r.with.len == 1 or r.with.len == r.patterns.len)) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .replace_many = .{ .patterns = r.patterns, .with = r.with, .fold = r.ascii_case_insensitive } }, 1);
            },
            .dt => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .dt = r.part }, 1);
            },
            .strptime => |r| {
                const layout = dtf.translateFormat(c.a, r.format) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .strptime = .{ .layout = layout, .to = r.to } }, 1);
            },
            .strftime => |r| {
                const layout = dtf.translateFormat(c.a, r.format) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .strftime = layout }, 1);
            },
            .offset_by => |r| {
                const d = dtf.parseDuration(r.by) orelse return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .offset_by = d }, 1);
            },
            .truncate => |r| {
                const d = dtf.parseDuration(r.every) orelse return error.BadExpr;
                const ok = (d.months > 0 and d.us == 0) or (d.months == 0 and d.us > 0);
                if (!ok) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .truncate = d }, 1);
            },
            .add_business_days => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .add_business_days = r.n }, 1);
            },
        }
    }
};

fn compile(a: std.mem.Allocator, f: Frame, e: *const Expr) Error!Program {
    var c: Compiler = .{ .a = a, .f = f };
    try c.go(e, 0);
    return .{ .code = c.code.items, .stack = c.max };
}

/// The value set of `is_in`: each canonical key, u32 length prefixed. A short scan
/// per row; sets are spec data of a handful of entries.
fn encodeSet(a: std.mem.Allocator, values: []const Value) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var one: std.ArrayList(u8) = .empty;
    defer one.deinit(a);
    for (values) |v| {
        if (keys.isMissing(v)) continue; // missing is in no set
        one.clearRetainingCapacity();
        try keys.encode(a, &one, v, .as_null);
        const n: u32 = @intCast(one.items.len);
        try out.appendSlice(a, std.mem.asBytes(&n));
        try out.appendSlice(a, one.items);
    }
    return out.toOwnedSlice(a);
}

fn inSet(set: []const u8, key: []const u8) bool {
    var i: usize = 0;
    while (i + 4 <= set.len) {
        const n = std.mem.readInt(u32, set[i..][0..4], .native);
        i += 4;
        if (std.mem.eql(u8, set[i..][0..n], key)) return true;
        i += n;
    }
    return false;
}

const num_of = Value.asFloat;

fn roundHalfEven(x: f64) f64 {
    const r = @round(x); // half away from zero
    if (@abs(x - @trunc(x)) != 0.5) return r;
    return 2 * @round(x / 2);
}

fn evalUnary(a: std.mem.Allocator, op: Unary, v: Value) Error!Value {
    switch (op) {
        .is_null => return .{ .bool = keys.isMissing(v) },
        .not_null => return .{ .bool = !keys.isMissing(v) },
        .is_nan, .is_not_nan, .is_finite, .is_infinite => {
            const x: f64 = switch (v) {
                .float => |f| f,
                .int, .decimal => 0,
                else => return .null,
            };
            return .{ .bool = switch (op) {
                .is_nan => std.math.isNan(x),
                .is_not_nan => !std.math.isNan(x),
                .is_finite => std.math.isFinite(x),
                else => std.math.isInf(x),
            } };
        },
        else => {},
    }
    if (keys.isMissing(v)) return .null;
    switch (op) {
        .count_ones, .count_zeros, .leading_zeros, .trailing_zeros, .leading_ones, .trailing_ones, .bit_not => {
            if (v != .int) return .null;
            const u: u64 = @bitCast(v.int);
            return .{ .int = switch (op) {
                .count_ones => @popCount(u),
                .count_zeros => @popCount(~u),
                .leading_zeros => @clz(u),
                .trailing_zeros => @ctz(u),
                .leading_ones => @clz(~u),
                .trailing_ones => @ctz(~u),
                else => ~v.int,
            } };
        },
        .capitalize, .title, .swapcase, .reverse, .len_bytes, .is_alpha, .is_digit, .is_alnum, .is_space, .is_lower, .is_upper, .is_title, .lstrip, .rstrip => {
            if (v != .text) return .null;
            const t = v.text;
            return switch (op) {
                .capitalize => .{ .text = try fnx.capitalize(a, t) },
                .title => .{ .text = try fnx.title(a, t) },
                .swapcase => .{ .text = try fnx.swapcase(a, t) },
                .reverse => .{ .text = try fnx.reverse(a, t) },
                .len_bytes => .{ .int = @intCast(t.len) },
                .is_alpha => .{ .bool = fnx.isClass(t, .alpha) },
                .is_digit => .{ .bool = fnx.isClass(t, .digit) },
                .is_alnum => .{ .bool = fnx.isClass(t, .alnum) },
                .is_space => .{ .bool = fnx.isClass(t, .space) },
                .is_lower => .{ .bool = fnx.isClass(t, .lower) },
                .is_upper => .{ .bool = fnx.isClass(t, .upper) },
                .is_title => .{ .bool = fnx.isClass(t, .title) },
                .lstrip => .{ .text = fnx.stripChars(t, null, .start) },
                else => .{ .text = fnx.stripChars(t, null, .end) },
            };
        },
        else => {},
    }
    switch (op) {
        .not => return if (v == .bool) .{ .bool = !v.bool } else .null,
        .lower, .upper, .strip, .length => {
            if (v != .text) return .null;
            const t = v.text;
            return switch (op) {
                .lower => .{ .text = try std.ascii.allocLowerString(a, t) },
                .upper => .{ .text = try std.ascii.allocUpperString(a, t) },
                .strip => .{ .text = std.mem.trim(u8, t, " \t\r\n\x0b\x0c") },
                else => .{ .int = @intCast(std.unicode.utf8CountCodepoints(t) catch t.len) },
            };
        },
        .neg, .abs => switch (v) {
            .int => |i| {
                if (op == .neg) return .{ .int = std.math.negate(i) catch return .null };
                if (i == std.math.minInt(i64)) return .null;
                return .{ .int = if (i < 0) -i else i };
            },
            .decimal => |r| {
                if (r == std.math.minInt(i128)) return .null;
                return .{ .decimal = if (op == .neg or r < 0) -r else r };
            },
            .float => |f| return .{ .float = if (op == .neg) -f else @abs(f) },
            else => return .null,
        },
        else => {},
    }
    const x = v.asFloat() orelse return .null;
    return switch (op) {
        .sqrt => .{ .float = @sqrt(x) }, // NaN below 0, IEEE
        .floor => .{ .float = @floor(x) },
        .ceil => .{ .float = @ceil(x) },
        .round => .{ .float = roundHalfEven(x) },
        .exp => .{ .float = @exp(x) },
        .log => .{ .float = @log(x) },
        .log10 => .{ .float = std.math.log10(x) },
        .sign => .{ .float = if (x > 0) 1 else if (x < 0) -1 else 0 },
        .sin => .{ .float = @sin(x) },
        .cos => .{ .float = @cos(x) },
        .tan => .{ .float = @tan(x) },
        .cot => .{ .float = 1 / @tan(x) },
        .asin => .{ .float = std.math.asin(x) },
        .acos => .{ .float = std.math.acos(x) },
        .atan => .{ .float = std.math.atan(x) },
        .sinh => .{ .float = std.math.sinh(x) },
        .cosh => .{ .float = std.math.cosh(x) },
        .tanh => .{ .float = std.math.tanh(x) },
        .asinh => .{ .float = std.math.asinh(x) },
        .acosh => .{ .float = std.math.acosh(x) },
        .atanh => .{ .float = std.math.atanh(x) },
        .cbrt => .{ .float = std.math.cbrt(x) },
        .log1p => .{ .float = std.math.log1p(x) },
        .expm1 => .{ .float = std.math.expm1(x) },
        .log2 => .{ .float = std.math.log2(x) },
        .erf => .{ .float = fnx.erf(x) },
        .degrees => .{ .float = x * (180.0 / std.math.pi) },
        .radians => .{ .float = x * (std.math.pi / 180.0) },
        else => unreachable, // handled above
    };
}

fn evalBinary(a: std.mem.Allocator, op: Binary, l: Value, r: Value) Error!Value {
    switch (op) {
        .@"and", .@"or" => {
            const lb: ?bool = if (l == .bool) l.bool else null;
            const rb: ?bool = if (r == .bool) r.bool else null;
            const absorbing = op == .@"or";
            if (lb == absorbing or rb == absorbing) return .{ .bool = absorbing };
            if (lb == null or rb == null) return .null;
            return .{ .bool = !absorbing };
        },
        .eq_missing => return .{ .bool = fnx.eqMissing(l, r) },
        .ne_missing => return .{ .bool = !fnx.eqMissing(l, r) },
        .fill_nan => return if (l == .float and std.math.isNan(l.float)) r else l,
        else => {},
    }
    if (keys.isMissing(l) or keys.isMissing(r)) return .null;
    switch (op) {
        .bit_and, .bit_or, .bit_xor => {
            if (l != .int or r != .int) return .null;
            return .{ .int = switch (op) {
                .bit_and => l.int & r.int,
                .bit_or => l.int | r.int,
                else => l.int ^ r.int,
            } };
        },
        .log_base, .atan2 => {
            const x = l.asFloat() orelse return .null;
            const y = r.asFloat() orelse return .null;
            return .{ .float = if (op == .atan2) std.math.atan2(x, y) else @log(x) / @log(y) };
        },
        .strip_prefix, .strip_suffix, .find, .rfind, .count_matches => {
            if (l != .text or r != .text) return .null;
            const t = l.text;
            const p = r.text;
            return switch (op) {
                .strip_prefix => .{ .text = if (std.mem.startsWith(u8, t, p)) t[p.len..] else t },
                .strip_suffix => .{ .text = if (std.mem.endsWith(u8, t, p)) t[0 .. t.len - p.len] else t },
                .find => if (std.mem.find(u8, t, p)) |i| .{ .int = @intCast(i) } else .null,
                .rfind => if (std.mem.findLast(u8, t, p)) |i| .{ .int = @intCast(i) } else .null,
                else => .{ .int = @intCast(fnx.countMatches(t, p)) },
            };
        },
        .repeat, .head, .tail, .zfill, .char_at => {
            if (l != .text or r != .int) return .null;
            const t = l.text;
            const n = r.int;
            return switch (op) {
                .repeat => .{ .text = try fnx.repeat(a, t, n) },
                .head => .{ .text = try fnx.head(a, t, n) },
                .tail => .{ .text = try fnx.tail(a, t, n) },
                .zfill => .{ .text = try fnx.zfill(a, t, n) },
                else => if (try fnx.charAt(a, t, n)) |c| .{ .text = c } else .null,
            };
        },
        else => {},
    }
    switch (op) {
        .eq, .ne, .lt, .le, .gt, .ge => {
            const same = switch (l) {
                .int, .float, .decimal => r == .int or r == .float or r == .decimal,
                .text => r == .text,
                .bool => r == .bool,
                .null => false,
            };
            if (!same) return .null;
            const o = l.order(r);
            return .{ .bool = switch (op) {
                .eq => o == .eq,
                .ne => o != .eq,
                .lt => o == .lt,
                .le => o != .gt,
                .gt => o == .gt,
                else => o != .lt,
            } };
        },
        .contains, .starts_with, .ends_with, .concat => {
            if (l != .text or r != .text) return .null;
            return switch (op) {
                .contains => .{ .bool = std.mem.find(u8, l.text, r.text) != null },
                .starts_with => .{ .bool = std.mem.startsWith(u8, l.text, r.text) },
                .ends_with => .{ .bool = std.mem.endsWith(u8, l.text, r.text) },
                else => .{ .text = try std.mem.concat(a, u8, &.{ l.text, r.text }) },
            };
        },
        .min, .max => {
            if (l.asFloat() == null or r.asFloat() == null) return .null;
            const o = l.order(r);
            return if (op == .min) (if (o == .gt) r else l) else (if (o == .lt) r else l);
        },
        else => {},
    }
    if (l == .int and r == .int) {
        const x = l.int;
        const y = r.int;
        switch (op) {
            .add => return .{ .int = std.math.add(i64, x, y) catch return .null },
            .sub => return .{ .int = std.math.sub(i64, x, y) catch return .null },
            .mul => return .{ .int = std.math.mul(i64, x, y) catch return .null },
            .floordiv => {
                if (y == 0 or (x == std.math.minInt(i64) and y == -1)) return .null;
                return .{ .int = @divFloor(x, y) };
            },
            .mod => {
                if (y == 0) return .null;
                if (y == -1) return .{ .int = 0 };
                // Not `@mod`: its denominator must be positive. In i128: the product
                // can leave i64 (maxInt mod -2), the result cannot, |r| < |y|.
                const wx: i128 = x;
                const wy: i128 = y;
                return .{ .int = @intCast(wx - @divFloor(wx, wy) * wy) };
            },
            else => {},
        }
    }
    if ((l == .decimal or r == .decimal) and (op == .add or op == .sub)) exact: {
        const x: i128 = switch (l) {
            .decimal => |d| d,
            .int => |i| @as(i128, i) * ds.decimal_scale,
            else => break :exact,
        };
        const y: i128 = switch (r) {
            .decimal => |d| d,
            .int => |i| @as(i128, i) * ds.decimal_scale,
            else => break :exact,
        };
        const s = if (op == .add) std.math.add(i128, x, y) else std.math.sub(i128, x, y);
        return .{ .decimal = s catch return .null };
    }
    const x = l.asFloat() orelse return .null;
    const y = r.asFloat() orelse return .null;
    return .{
        .float = switch (op) {
            .add => x + y,
            .sub => x - y,
            .mul => x * y,
            .div => x / y,
            .floordiv => @floor(x / y),
            // Python's: the result takes the divisor's sign; x % inf and x % 0 per IEEE.
            .mod => blk: {
                if (y == 0 or !std.math.isFinite(x)) break :blk std.math.nan(f64);
                if (std.math.isInf(y)) break :blk if ((x >= 0) == (y > 0) or x == 0) x else y;
                const m = @rem(x, y);
                break :blk if (m != 0 and ((m < 0) != (y < 0))) m + y else m;
            },
            .pow => std.math.pow(f64, x, y),
            else => unreachable, // the switches above took every other operator
        },
    };
}

/// One binary operator on two cells, `Expr`'s rule (for the frame-wide arithmetic).
pub fn binaryValue(a: std.mem.Allocator, op: Binary, l: Value, r: Value) Error!Value {
    return evalBinary(a, op, l, r);
}

/// A decimal float, or "nan"/"inf"/"infinity" in any case, as pandas and polars read
/// them. `parseFloat`'s hex floats and digit separators are refused: both engines read
/// "0x10" and "1_000" as not a number, and a typo must not become 16.
/// A decimal's exact digits: no f64 on the way, trailing fraction zeros trimmed.
fn decimalText(a: std.mem.Allocator, raw: i128) Error![]const u8 {
    const scale: u128 = @intCast(ds.decimal_scale);
    const m: u128 = @abs(raw);
    const sign: []const u8 = if (raw < 0) "-" else "";
    const q = m / scale;
    const r = m % scale;
    if (r == 0) return a.print("{s}{d}", .{ sign, q });
    var fb: [12]u8 = undefined;
    _ = std.mem.print(&fb, "{d:0>12}", .{r}) catch unreachable; // r < 10^12: 12 digits
    var end: usize = fb.len;
    while (fb[end - 1] == '0') end -= 1;
    return a.print("{s}{d}.{s}", .{ sign, q, fb[0..end] });
}

pub fn parseNumber(s: []const u8) ?f64 {
    if (std.mem.findAny(u8, s, "_xXpP") != null) return null;
    return std.fmt.parseFloat(f64, s) catch null;
}

/// The one cast rule, for `Expr.cast` and the `cast` verb. Null when it cannot be
/// converted; a missing cell stays null. Beyond `Value.cast`: text parses to int,
/// float and bool ("true"/"false", any case; see `parseNumber`; to int only a whole
/// number, "12.9" is null), anything prints to text (`{d}`, bool as "true"/"false"),
/// bool counts as 0/1. Text to `.decimal` is null here: parsing
/// money is `numparse`'s, with its locale rules, and this module does not pull it in.
pub fn castValue(a: std.mem.Allocator, v: Value, to: ColumnType) Error!Value {
    if (keys.isMissing(v)) return .null;
    switch (to) {
        .text, .date => switch (v) {
            .text => return v,
            .int => |i| return .{ .text = try a.print("{d}", .{i}) },
            .float => |f| return .{ .text = try a.print("{d}", .{f}) },
            .bool => |b| return .{ .text = if (b) "true" else "false" },
            .decimal => |r| return .{ .text = try decimalText(a, r) },
            .null => return .null,
        },
        .int => switch (v) {
            .bool => |b| return .{ .int = @intFromBool(b) },
            .text => |t| {
                const s = std.mem.trim(u8, t, " \t");
                if (std.mem.findAny(u8, s, "_xX") != null) return .null;
                if (std.fmt.parseInt(i64, s, 10)) |i| return .{ .int = i } else |_| {}
                const f = parseNumber(s) orelse return .null;
                // Whole only ("1e2"): "12.9" is not an int, say so rather than truncate.
                const i = Value.floatToInt(i64, f) orelse return .null;
                return if (@as(f64, @floatFromInt(i)) == f) .{ .int = i } else .null;
            },
            else => {},
        },
        .float => switch (v) {
            .bool => |b| return .{ .float = @floatFromInt(@intFromBool(b)) },
            .text => |t| return .{ .float = parseNumber(std.mem.trim(u8, t, " \t")) orelse return .null },
            else => {},
        },
        .bool => if (v == .text) {
            if (std.ascii.eqlIgnoreCase(v.text, "true")) return .{ .bool = true };
            if (std.ascii.eqlIgnoreCase(v.text, "false")) return .{ .bool = false };
            return .null;
        },
        else => {},
    }
    return v.cast(to) orelse .null;
}

/// Run the program on row `ri` of `f`. `stack` has `Program.stack` slots; `one` is a
/// reusable key buffer.
fn eval(a: std.mem.Allocator, p: Program, f: Frame, ri: usize, stack: []Value, one: *std.ArrayList(u8)) Error!Value {
    var sp: usize = 0;
    for (p.code) |inst| {
        switch (inst) {
            .col => |ci| {
                stack[sp] = f.columnAt(ci).get(ri);
                sp += 1;
            },
            .lit => |v| {
                stack[sp] = v;
                sp += 1;
            },
            .unary => |op| stack[sp - 1] = try evalUnary(a, op, stack[sp - 1]),
            .binary => |op| {
                stack[sp - 2] = try evalBinary(a, op, stack[sp - 2], stack[sp - 1]);
                sp -= 1;
            },
            .is_in => |set| {
                const v = stack[sp - 1];
                if (keys.isMissing(v)) {
                    stack[sp - 1] = .null;
                } else {
                    one.clearRetainingCapacity();
                    try keys.encode(a, one, v, .as_null);
                    stack[sp - 1] = .{ .bool = inSet(set, one.items) };
                }
            },
            .if_else => {
                const c = stack[sp - 3];
                stack[sp - 3] = if (c == .bool and c.bool) stack[sp - 2] else stack[sp - 1];
                sp -= 2;
            },
            .coalesce => |n| {
                const base = sp - n;
                var res: Value = .null;
                for (stack[base..sp]) |v| {
                    if (!keys.isMissing(v)) {
                        res = v;
                        break;
                    }
                }
                stack[base] = res;
                sp = base + 1;
            },
            .cast => |to| stack[sp - 1] = try castValue(a, stack[sp - 1], to),
            .replace => |r| {
                const v = stack[sp - 1];
                stack[sp - 1] = if (v == .text)
                    .{ .text = try std.mem.replaceOwned(u8, a, v.text, r.from, r.to) }
                else
                    .null;
            },
            .round => |r| stack[sp - 1] = if (keys.isMissing(stack[sp - 1])) .null else fnx.round(stack[sp - 1], r.decimals, r.mode),
            .round_sig_figs => |d| stack[sp - 1] = if (keys.isMissing(stack[sp - 1])) .null else fnx.roundSigFigs(stack[sp - 1], d),
            .is_close => |r| {
                stack[sp - 2] = fnx.isClose(stack[sp - 2], stack[sp - 1], r.rel_tol, r.abs_tol, r.nans_equal);
                sp -= 1;
            },
            .pad, .slice, .strip_chars, .translate, .to_integer, .contains_any, .replace_many => {
                const v = stack[sp - 1];
                if (v != .text) {
                    stack[sp - 1] = .null;
                    continue;
                }
                const t = v.text;
                stack[sp - 1] = switch (inst) {
                    .pad => |r| .{ .text = try fnx.pad(a, t, r.width, r.side, r.fill) },
                    .slice => |r| .{ .text = try fnx.slice(a, t, r.offset, r.length) },
                    .strip_chars => |r| .{ .text = fnx.stripChars(t, r.chars, r.side) },
                    .translate => |r| .{ .text = try fnx.translate(a, t, r.from, r.to, r.delete) },
                    .to_integer => |base| fnx.toInteger(t, base),
                    .contains_any => |r| .{ .bool = fnx.containsAny(t, r.patterns, r.fold) },
                    .replace_many => |r| .{ .text = try fnx.replaceMany(a, t, r.patterns, r.with, r.fold) },
                    else => unreachable, // the prong names these seven
                };
            },
            .dt, .strptime, .strftime, .offset_by, .truncate, .add_business_days => {
                const v = stack[sp - 1];
                stack[sp - 1] = if (keys.isMissing(v)) .null else switch (inst) {
                    .dt => |part| try dtf.part(a, v, part),
                    .strptime => |r| try dtf.strptime(a, v, r.layout, r.to),
                    .strftime => |layout| try dtf.strftime(a, v, layout),
                    .offset_by => |d| try dtf.offsetBy(a, v, d),
                    .truncate => |d| try dtf.truncate(a, v, d),
                    .add_business_days => |n| try dtf.addBusinessDays(a, v, n),
                    else => unreachable, // the prong names these six
                };
            },
        }
    }
    return stack[0];
}

pub const Assign = struct {
    out: []const u8,
    expr: Expr,
    /// The output column's type; every cell is cast to it. null infers it from all
    /// the results: one kind is that kind, numbers of different kinds promote (any float:
    /// all float; decimal and int: decimal), no results is `.float`, and text or bool
    /// among other kinds is `error.BadExpr`, since no type holds them.
    type: ?ColumnType = null,
};

fn typeOf(v: Value) ColumnType {
    return switch (v) {
        .int => .int,
        .text => .text,
        .bool => .bool,
        .decimal => .decimal,
        .float, .null => .float,
    };
}

/// Add or replace columns, in order: a later assignment sees the earlier ones
/// (pandas' `assign`, dplyr's `mutate`; polars' `with_columns` evaluates against the
/// input, a one-assignment-per-call there). Replacing keeps the column's position;
/// every other column is shared.
pub fn mutate(a: std.mem.Allocator, f: Frame, assigns: []const Assign) Error!Frame {
    var cur = f;
    for (assigns) |as| cur = try mutateOne(a, cur, as, true);
    return cur;
}

/// For the differential tests only: `mutate` with every cell through the boxed evaluator.
pub const test_hooks = struct {
    pub const containsShort = expr_containsShort;
    /// How many `mutate` assignments the text predicate kernel answered.
    pub var text_kernel_hits: usize = 0;
    pub fn mutateCells(a: std.mem.Allocator, f: Frame, assigns: []const Assign) Error!Frame {
        var cur = f;
        for (assigns) |as| cur = try mutateOne(a, cur, as, false);
        return cur;
    }
};

const expr_containsShort = containsShort;

/// The result of a typed kernel: the column's data and the type `mutateOne` would infer.
const Typed = struct { data: ColumnData, ty: ColumnType };

/// `std.mem.find(u8, h, p) != null` for the short haystacks and needles of text cells:
/// a scan for the first byte, then the rest compared in place (the library's search
/// pays a call per candidate position).
fn containsShort(h: []const u8, p: []const u8) bool {
    if (p.len == 0) return std.mem.find(u8, h, p) != null;
    if (p.len > h.len) return false;
    const first = p[0];
    const rest = p[1..];
    var i: usize = 0;
    const last = h.len - p.len;
    while (i <= last) : (i += 1) {
        if (h[i] != first) continue;
        var k: usize = 0;
        while (k < rest.len and h[i + 1 + k] == rest[k]) k += 1;
        if (k == rest.len) return true;
    }
    return false;
}

/// `col <contains | starts_with | ends_with> "literal"` over a plain text column: the
/// program is exactly column, literal, operator. A null cell gives null (the boxed
/// evaluator: a missing operand), and the rest a bool, so the column is `.bool`, or
/// `.nulls` typed `.float` when every cell is null, as the cell path infers it.
fn textPredicate(a: std.mem.Allocator, f: Frame, p: Program) Error!?Typed {
    if (p.code.len != 3) return null;
    if (p.code[0] != .col or p.code[1] != .lit or p.code[2] != .binary) return null;
    const op = p.code[2].binary;
    if (op != .contains and op != .starts_with and op != .ends_with) return null;
    if (p.code[1].lit != .text) return null;
    const pat = p.code[1].lit.text;
    const tc = switch (f.columnAt(p.code[0].col)) {
        .text => |t| t,
        else => return null,
    };
    if (@import("builtin").is_test) test_hooks.text_kernel_hits += 1;
    const out = try a.alloc(bool, f.len);
    const valid = try a.alloc(u64, f.len / 64 + 1);
    @memset(valid, 0);
    var nonnull: usize = 0;
    for (out, 0..) |*o, ri| {
        const t = tc.at(ri) orelse {
            o.* = false;
            continue;
        };
        o.* = switch (op) {
            .contains => containsShort(t, pat),
            .starts_with => std.mem.startsWith(u8, t, pat),
            else => std.mem.endsWith(u8, t, pat),
        };
        valid[ri / 64] |= @as(u64, 1) << @intCast(ri % 64);
        nonnull += 1;
    }
    if (nonnull == 0) return .{ .data = .nulls, .ty = .float };
    return .{ .data = .{ .bool = .{ .values = out, .valid = if (nonnull == f.len) null else valid } }, .ty = .bool };
}

fn mutateOne(a: std.mem.Allocator, f: Frame, as: Assign, typed: bool) Error!Frame {
    const p = try compile(a, f, &as.expr);
    const existing = f.columnIndex(as.out);
    const width = if (existing == null) f.columns.len + 1 else f.columns.len;
    const at = existing orelse f.columns.len;
    const cols = try a.alloc(Column, width);
    @memcpy(cols[0..f.columns.len], f.columns);
    if (typed and as.type == null) if (try textPredicate(a, f, p)) |res| {
        cols[at] = .{ .name = as.out, .type = res.ty };
        const data = try a.alloc(ColumnData, width);
        for (data[0..f.columns.len], 0..) |*d, ci| d.* = f.columnAt(ci);
        data[at] = res.data;
        return .{ .columns = cols, .data = data, .len = f.len };
    };
    const vals = try a.alloc(Value, f.len);
    defer a.free(vals);
    const stack = try a.alloc(Value, p.stack);
    defer a.free(stack);
    var one: std.ArrayList(u8) = .empty;
    defer one.deinit(a);
    var any_int = false;
    var any_float = false;
    var any_decimal = false;
    var any_text = false;
    var any_bool = false;
    for (vals, 0..) |*o, ri| {
        var v = try eval(a, p, f, ri, stack, &one);
        if (as.type) |ty| {
            if (!keys.isMissing(v)) v = try castValue(a, v, ty);
        } else switch (v) {
            .int => any_int = true,
            .float => |x| any_float = any_float or !std.math.isNan(x),
            .decimal => any_decimal = true,
            .text => any_text = true,
            .bool => any_bool = true,
            .null => {},
        }
        o.* = v;
    }
    const kinds = @as(u8, @intFromBool(any_int)) + @intFromBool(any_float) + @intFromBool(any_decimal) + @intFromBool(any_text) + @intFromBool(any_bool);
    if (kinds > 1 and (any_text or any_bool)) return error.BadExpr;
    const ty: ColumnType = as.type orelse if (any_text) .text else if (any_bool) .bool else if (any_float) .float else if (any_decimal) .decimal else if (any_int) .int else .float;
    if (as.type == null and kinds > 1) {
        for (vals) |*c| {
            if (keys.isMissing(c.*)) continue;
            const promoted: Value = c.cast(ty) orelse .null;
            c.* = promoted;
        }
    }
    cols[at] = .{ .name = as.out, .type = ty };
    const data = try a.alloc(ColumnData, width);
    for (data[0..f.columns.len], 0..) |*d, ci| d.* = f.columnAt(ci);
    data[at] = try fm.columnFromCells(a, vals);
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// Keep the rows where `e` is true: nested AND/OR/NOT, column against column,
/// anything `Expr` can say. A null condition drops the row.
pub fn where(a: std.mem.Allocator, f: Frame, e: *const Expr) Error!Frame {
    try core.checkRowsU32(f.len);
    const p = try compile(a, f, e);
    const stack = try a.alloc(Value, p.stack);
    defer a.free(stack);
    var one: std.ArrayList(u8) = .empty;
    defer one.deinit(a);
    const kept = try a.alloc(u32, f.len);
    var n: usize = 0;
    for (0..f.len) |ri| {
        const v = try eval(a, p, f, ri, stack, &one);
        kept[n] = @intCast(ri);
        n += @intFromBool(v == .bool and v.bool);
    }
    return verbs.takeRows(a, f, kept[0..n]);
}

pub const CastSpec = struct {
    col: []const u8,
    to: ColumnType,
    /// `.null`: an unconvertible cell becomes null (pandas' `errors="coerce"`,
    /// polars' `strict=False`). `.fail`: `error.CastFailed` (their strict default).
    on_error: enum { null, fail } = .null,
};

pub const CastError = Error || error{CastFailed};

/// Convert one column by `castValue`'s rule, the declared type following.
pub fn cast(a: std.mem.Allocator, f: Frame, spec: CastSpec) CastError!Frame {
    const ci = f.columnIndex(spec.col) orelse return error.NoSuchColumn;
    const cols = try a.dupe(Column, f.columns);
    cols[ci].type = spec.to;
    const vals = try a.alloc(Value, f.len);
    defer a.free(vals);
    const col = f.columnAt(ci);
    for (vals, 0..) |*o, ri| {
        const src = col.get(ri);
        const v = try castValue(a, src, spec.to);
        if (spec.on_error == .fail and v == .null and !keys.isMissing(src)) return error.CastFailed;
        o.* = v;
    }
    const data = try a.alloc(ColumnData, cols.len);
    for (data, 0..) |*d, i| d.* = f.columnAt(i);
    data[ci] = try fm.columnFromCells(a, vals);
    return .{ .columns = cols, .data = data, .len = f.len };
}

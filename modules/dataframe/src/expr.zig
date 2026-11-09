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
//! - **Text** verbs are bytewise; case mapping and the `is*` classes are Unicode (`unitext`) and
//!   `length` counts code points (bytes where the text is not valid UTF-8, which the
//!   case functions then treat as bytes too; see SPEC, "Unicode text").

const std = @import("std");
const ds = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const core = @import("core.zig");
const verbs = @import("verbs.zig");
const fnx = @import("exprfn.zig");
const dtf = @import("dtfn.zig");
const jsonio = @import("jsonio.zig");
const regex = @import("regex");
const tz = @import("tz");
const lf = @import("listfn.zig");
const sf = @import("strfn.zig");
const nv = @import("nestverbs.zig");
const catfn = @import("catfn.zig");
pub const ListOp = lf.ListOp;
pub const SetOp = lf.SetOp;
pub const StructOp = lf.StructOp;
pub const NameMap = lf.NameMap;
pub const DtPart = dtf.DtPart;
pub const ParseTo = dtf.ParseTo;
pub const DateMode = dtf.DateMode;
pub const Encoding = sf.Encoding;
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
    /// A regex function's pattern that `regex` (Rust syntax) refuses, or one past its
    /// compile limits.
    BadPattern,
};

/// Deepest tree `compile` accepts: it recurses, and an `Expr` is caller data.
pub const max_depth: usize = 256;
/// Most nodes in one expression: bounds the program and the row stack.
pub const max_nodes: usize = 1 << 16;
/// Most bytes the cells of one `mutate` assignment or one `where` may allocate while they
/// are evaluated, in all (a result text, a `repeat` or `pad` of every row): past it the
/// call is `error.TooLarge`. `max_text_result` bounds one cell, this bounds the column.
pub const max_eval_bytes: usize = 1 << 30;
/// Most bytes one `mutate` assignment or one `where` may allocate in all, freed ones
/// included: the work bound. A row's intermediate results are freed after the row (so
/// `max_eval_bytes` counts what is kept), and without this a `where` over `repeat` of
/// millions of rows would fill 16 MiB a row for hours (sweep S2-4). 16 GiB, a few seconds
/// of filling memory; past it `error.TooLarge`.
pub const max_eval_work: usize = 16 << 30;

/// Counts the bytes live through it and the bytes ever allocated, and refuses (null, `hit`
/// set) past `limit` or `work_limit`, so the evaluator stops at `max_eval_bytes` live and
/// `max_eval_work` in all instead of at the machine or the clock.
const Budget = struct {
    child: std.mem.Allocator,
    limit: usize,
    work_limit: usize,
    used: usize = 0,
    work: usize = 0,
    hit: bool = false,

    fn init(child: std.mem.Allocator) Budget {
        const is_test = @import("builtin").is_test;
        const limit = if (is_test) test_hooks.eval_limit orelse max_eval_bytes else max_eval_bytes;
        const work_limit = if (is_test) test_hooks.eval_work_limit orelse max_eval_work else max_eval_work;
        return .{ .child = child, .limit = limit, .work_limit = work_limit };
    }

    /// Whether `n` more bytes fit both bounds; counts them as work when they do.
    fn take(b: *Budget, n: usize) bool {
        if (n > b.limit -| b.used or n > b.work_limit -| b.work) {
            b.hit = true;
            return false;
        }
        b.work += n;
        return true;
    }

    /// Whether `n` more bytes of work fit, counted when they do (the scratch's requests,
    /// which its arena may serve from memory already counted as live).
    fn takeWork(b: *Budget, n: usize) bool {
        if (n > b.work_limit -| b.work) {
            b.hit = true;
            return false;
        }
        b.work += n;
        return true;
    }

    fn allocator(b: *Budget) std.mem.Allocator {
        return .{ .ptr = b, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{ .alloc = balloc, .resize = bresize, .remap = bremap, .free = bfree };

    fn of(ctx: *anyopaque) *Budget {
        return @ptrCast(@alignCast(ctx));
    }

    fn balloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const b = of(ctx);
        if (!b.take(len)) return null;
        const p = b.child.rawAlloc(len, alignment, ra) orelse return null;
        b.used += len;
        return p;
    }

    fn bresize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const b = of(ctx);
        if (new_len > memory.len and !b.take(new_len - memory.len)) return false;
        if (!b.child.rawResize(memory, alignment, new_len, ra)) return false;
        b.used = b.used -| memory.len +| new_len;
        return true;
    }

    fn bremap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const b = of(ctx);
        if (new_len > memory.len and !b.take(new_len - memory.len)) return null;
        const p = b.child.rawRemap(memory, alignment, new_len, ra) orelse return null;
        b.used = b.used -| memory.len +| new_len;
        return p;
    }

    fn bfree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const b = of(ctx);
        b.child.rawFree(memory, alignment, ra);
        b.used -|= memory.len;
    }
};

/// Scratch for one row's intermediate results (review R2 M1): every instruction but the
/// last allocates here, the last in the budget, and the scratch is reset after a row that
/// used it, so a value an instruction consumed is not kept for the rest of the column (a
/// `list.len(split(...))` kept every row's list and reached `max_eval_bytes` at ~4M rows).
/// A result read out of the scratch (a slice or a view of an intermediate) is copied out
/// before the reset; a program of one allocating instruction never touches the scratch.
const RowScratch = struct {
    arena: std.heap.ArenaAllocator,
    /// Every request counts as work here: the arena reuses its memory after a reset, so
    /// the budget below it would not see a row's churn again (its growth counts twice,
    /// which only makes the bound stricter).
    bud: *Budget,
    used: bool = false,

    fn init(bud: *Budget) RowScratch {
        return .{ .arena = .init(bud.allocator()), .bud = bud };
    }

    fn deinit(r: *RowScratch) void {
        r.arena.deinit();
    }

    fn allocator(r: *RowScratch) std.mem.Allocator {
        return .{ .ptr = r, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{ .alloc = salloc, .resize = sresize, .remap = sremap, .free = sfree };

    fn of(ctx: *anyopaque) *RowScratch {
        return @ptrCast(@alignCast(ctx));
    }

    fn salloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const r = of(ctx);
        r.used = true;
        if (!r.bud.takeWork(len)) return null;
        return r.arena.allocator().rawAlloc(len, alignment, ra);
    }

    fn sresize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const r = of(ctx);
        r.used = true;
        if (new_len > memory.len and !r.bud.takeWork(new_len - memory.len)) return false;
        return r.arena.allocator().rawResize(memory, alignment, new_len, ra);
    }

    fn sremap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const r = of(ctx);
        r.used = true;
        if (new_len > memory.len and !r.bud.takeWork(new_len - memory.len)) return null;
        return r.arena.allocator().rawRemap(memory, alignment, new_len, ra);
    }

    fn sfree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        of(ctx).arena.allocator().rawFree(memory, alignment, ra);
    }

    /// After a row: the scratch emptied if the row used it.
    fn endRow(r: *RowScratch) void {
        if (!r.used) return;
        _ = r.arena.reset(.retain_capacity);
        r.used = false;
    }
};

/// `eval` through a `Budget`, intermediates in `row`: an allocation the budget refused is
/// `error.TooLarge`, not out of memory. Call `keepRow` on a result that outlives the row.
fn evalBudget(b: *Budget, row: *RowScratch, p: Program, f: Frame, ri: usize, stack: []Value, one: *std.ArrayList(u8)) Error!Value {
    return eval(row.allocator(), b.allocator(), b.allocator(), p, f, ri, stack, one) catch |e| if (e == error.OutOfMemory and b.hit) error.TooLarge else e;
}

/// `v` copied out of `row`'s scratch when the row used it (it may be a slice or a view of an
/// intermediate there), then the scratch emptied.
fn keepRow(b: *Budget, row: *RowScratch, v: Value) Error!Value {
    defer row.endRow();
    if (!row.used) return v;
    return fm.copyValue(b.allocator(), v, 0) catch |e| if (b.hit) error.TooLarge else e;
}

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
    /// Unicode case (see `exprfn`): Python's `capitalize`, `title`, `swapcase`.
    capitalize,
    title,
    swapcase,
    /// The characters in reverse order (code points).
    reverse,
    /// Bytes of the text (polars `len_bytes`); `length` counts characters.
    len_bytes,
    /// Python's `isalpha` … `istitle`, Unicode (pandas `str.isalpha` …); see `exprfn.isClass`.
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
    // ── added in dataframe S2 wave W3 ──
    /// `1 - erf x` without the cancellation in the tail (scipy `erfc`).
    erfc,
    /// The text with every regex metacharacter backslash-escaped, so it matches itself as
    /// a pattern (polars `escape_regex`; Rust `regex::escape`: `\ . + * ? ( ) | [ ] { } ^ $ # & - ~`).
    /// Python's `re.escape` also escapes whitespace.
    escape_regex,
    // ── added in dataframe S2 wave W4 ──
    /// Python's `isascii` (pandas `str.isascii`): every byte below 0x80 (the empty text too).
    is_ascii,
    // ── added in dataframe S2 wave W8 (Unicode text, `unitext`) ──
    /// Python's `casefold` (pandas `str.casefold`): full case folding for caseless matching.
    casefold,
    /// Accent folding (`unitext.unaccent`); see `exprfn.unaccent` for how it differs from
    /// the pandas `normalize("NFKD")` recipe. Neither engine has it built in.
    unaccent,
    /// Python's `isdecimal` / `isnumeric` (pandas `str.isdecimal`, `str.isnumeric`).
    is_decimal,
    is_numeric,
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
    /// Division truncated toward zero (C, Rust and numpy `trunc(a / b)`; `floordiv`
    /// rounds toward minus infinity). Int by int stays int (zero divisor, `minInt / -1`:
    /// null); any other number gives a float.
    truncdiv,
};

/// Which ends of an interval belong to it (polars `is_between(closed=)`, pandas
/// `Series.between(inclusive=)`, `cut(closed)`, `date_range(closed=)`).
pub const Closed = enum { both, left, right, none };

/// polars `from_epoch(time_unit=)` / pandas `to_datetime(unit=)`; see `dtfn.fromEpoch`.
pub const EpochUnit = dtf.EpochUnit;

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
    /// `cast` with a failed conversion as null. With `zone` (valid for `to = .timestamp` only,
    /// else `error.BadExpr`; an unknown zone too) the result is a zoned timestamp, polars
    /// `cast(Datetime("us", time_zone=zone))`: the cells are the same UTC instants, only the
    /// column's zone changes (a naive column is read as UTC, as polars does; pandas' `astype`
    /// refuses a naive-to-aware cast and asks for `tz_localize`, which is `replace_time_zone`).
    cast: struct { x: *const Expr, to: ColumnType, zone: ?[]const u8 = null },
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
    /// polars `dt.truncate("1h")`, pandas `dt.floor`; with `mode` pandas `dt.ceil` and
    /// polars `dt.round` (`dtfn.RoundTo`). `every` positive, months or a fixed part but
    /// not both, else `error.BadExpr`.
    truncate: struct { x: *const Expr, every: []const u8, mode: dtf.RoundTo = .floor },
    /// polars `dt.add_business_days(n, roll="forward")`; see `dtfn.addBusinessDays`.
    /// With `week_mask` (Monday first), `holidays` (any order, duplicates fine) and `roll`
    /// (polars `roll="forward"|"backward"`; polars' default `"raise"` is not done: the start is
    /// rolled) it follows polars' full signature; see `dtfn.addBizDaysGeneral`. The defaults
    /// keep the original behaviour exactly.
    add_business_days: struct { x: *const Expr, n: i64, week_mask: [7]bool = dtf.monday_to_friday, holidays: []const ds.Date = &.{}, roll: dtf.Roll = .forward },
    /// polars `str.contains(pattern)` (pandas `str.contains(regex=True)`): the pattern
    /// matches somewhere in the text. Patterns are the `regex` module's Rust grammar,
    /// polars' own (Rust's `regex` crate); linear time whatever the pattern or text.
    contains_regex: struct { x: *const Expr, pattern: []const u8 },
    /// polars `str.extract(pattern, group_index)`, pandas `str.extract` of one group:
    /// the group's text in the first match; null when nothing matches or the group took
    /// no part. Group 0 is the whole match; a group past the pattern's is `error.BadExpr`.
    extract: struct { x: *const Expr, pattern: []const u8, group: usize = 1 },
    /// polars `str.count_matches(pattern)`, pandas `str.count`: non-overlapping matches.
    count_regex: struct { x: *const Expr, pattern: []const u8 },
    /// polars `str.replace(pattern, value, n=1)` and `str.replace_all` (`all`), pandas
    /// `str.replace(regex=True)`: `with` is a template (`$1`, `${name}`, `$$`) unless
    /// `literal`. `n` (pandas `n=`; zero is `error.BadExpr`) replaces the first `n` matches
    /// and wins over `all`.
    replace_regex: struct { x: *const Expr, pattern: []const u8, with: []const u8, all: bool = true, literal: bool = false, n: ?usize = null },
    /// A UTC instant as the wall clock of the IANA `zone` (`"Europe/Prague"`) shows it:
    /// polars `convert_time_zone` then the wall clock, pandas `tz_convert`. See
    /// `dtfn.toLocal`; an unknown zone is `error.BadExpr`.
    to_local: struct { x: *const Expr, zone: []const u8 },
    /// A wall-clock time read in `zone` as the UTC instant it names: polars
    /// `replace_time_zone`, pandas `tz_localize`. See `dtfn.fromLocal`.
    from_local: struct { x: *const Expr, zone: []const u8, policy: dtf.TzPolicy = .compatible },
    // ── time zone carried by the column (dataframe S2 wave W7) ──
    /// The same instants shown in another zone: polars `dt.convert_time_zone(zone)`, pandas
    /// `tz_convert(zone)`. Metadata only, the cells do not change. `zone = null` drops the zone
    /// and keeps the UTC instants (pandas `tz_convert(None)`; polars `convert_time_zone` takes a
    /// name only). A naive column is read as UTC, which is what polars does (pandas raises
    /// "Cannot convert tz-naive timestamps": followed here is polars, since a naive column of
    /// this module IS a column of UTC instants). A date or duration, or an unknown zone, is
    /// `error.BadExpr`.
    convert_time_zone: struct { x: *const Expr, zone: ?[]const u8 },
    /// The same wall clock in another zone, so other instants: polars
    /// `dt.replace_time_zone(zone, ambiguous, non_existent)`, pandas `tz_localize(zone, ambiguous,
    /// nonexistent)`. A naive column is read as wall-clock time in `zone`; a zoned one first
    /// shows its own wall clock (polars; pandas' `tz_localize` refuses an aware column).
    /// `zone = null` drops the zone and keeps the WALL CLOCK (polars `replace_time_zone(None)`,
    /// pandas `tz_localize(None)`), unlike `convert_time_zone(null)`. `policy` settles folds and
    /// gaps as `from_local` does (one setting for polars' `ambiguous` and `non_existent`; there
    /// is no raising mode, a cell has no error channel).
    replace_time_zone: struct { x: *const Expr, zone: ?[]const u8, policy: dtf.TzPolicy = .compatible },
    // ── list and struct (S3 step 3) ──
    /// A `list.*` function of a list cell (`listfn.ListOp`); not a list: null.
    list: struct { x: *const Expr, op: lf.ListOp },
    /// polars `concat_list`: the parts' elements in order, a non-list part one element,
    /// a null part a null result. No parts is `error.BadExpr`.
    concat_list: []const Expr,
    /// polars `struct.field(name)`: a record's field, null where the cell has none. Over a
    /// column whose declared fields lack `name`: `error.BadExpr` (polars'
    /// `StructFieldNotFoundError`).
    field: struct { x: *const Expr, name: []const u8 },
    /// polars `pl.struct(...)`: one record per row, a field per entry. No entries or a
    /// name given twice is `error.BadExpr`.
    struct_of: []const NamedExpr,
    /// polars `str.split(by, inclusive)`, pandas `str.split(pat, n)` (`listfn.splitLiteral`):
    /// a list of the pieces. `limit` 0 is `error.BadExpr`.
    split: struct { x: *const Expr, by: []const u8, inclusive: bool = false, limit: ?usize = null },
    /// pandas `str.split(pat, n, regex=True)`: the pieces between the matches, at most
    /// `limit`, the last the rest. Captured groups are not spliced into the result (Rust's
    /// `Regex::split`; Python's `re.split` does splice them).
    split_regex: struct { x: *const Expr, pattern: []const u8, limit: ?usize = null },
    /// polars `str.extract_all(pattern)` (every match, `group` 0), pandas `str.findall`
    /// (with `group` 1 for a pattern of one group): a list of the texts, empty when nothing
    /// matches; a match where the group took no part gives a null element.
    extract_all: struct { x: *const Expr, pattern: []const u8, group: usize = 0 },
    /// polars `str.extract_groups(pattern)`, pandas `str.extract(expand=True)`: a record of
    /// the first match's groups, named by the group's name or else its number ("1", "2",
    /// polars' names); no match: every field null. A pattern with no group is
    /// `error.BadExpr`.
    extract_groups: struct { x: *const Expr, pattern: []const u8 },
    // ── added in dataframe S2 wave W3 ──
    /// polars `is_between(lower, upper, closed)`, pandas `between(inclusive=)`: `x` between
    /// the bounds (each an expression), as the Kleene `and` of the two comparisons, so a
    /// missing `x` or bound is null unless the other side already decides it.
    is_between: struct { x: *const Expr, lower: *const Expr, upper: *const Expr, closed: Closed = .both },
    /// polars `concat_str(exprs, separator, ignore_nulls)`, pandas `str.cat(others, sep,
    /// na_rep)`: the parts as text joined by `separator`. A number or bool is written as
    /// `cast(text)` does. A missing part is `na_rep` when given (pandas); else it skips
    /// with `ignore_nulls` (polars; all missing gives ""); else the row is null (both
    /// engines' default). No parts is `error.BadExpr`.
    concat_str: struct { parts: []const Expr, separator: []const u8 = "", ignore_nulls: bool = false, na_rep: ?[]const u8 = null },
    /// polars `pl.fold(acc, function, exprs)` and `pl.reduce(function, exprs)` for a
    /// `function` that is one of the binary operators: `op(op(op(acc, p0), p1), p2)`; with
    /// no `acc` the first part starts (`reduce`). No parts, or neither acc nor parts, is
    /// `error.BadExpr`. A function of the caller's own is `fold.foldColumns` (a callback verb).
    fold: struct { op: Binary, parts: []const Expr, acc: ?*const Expr = null },
    /// polars `business_day_count(start, end, week_mask, holidays)`: the business days of
    /// `[start, end)` (a date or timestamp each; the time of day is dropped); negative when
    /// `end` is before `start`. `week_mask` is Monday first. Holidays are dates.
    business_day_count: struct { start: *const Expr, end: *const Expr, week_mask: [7]bool = dtf.monday_to_friday, holidays: []const ds.Date = &.{} },
    /// polars `pl.date(year, month, day)`: a date; a day that does not exist is null. The
    /// parts are int expressions (a non-int is null).
    make_date: struct { year: *const Expr, month: *const Expr, day: *const Expr },
    /// polars `pl.datetime(year, month, day, hour, minute, second, microsecond)`: a
    /// timestamp (UTC); the time parts default to 0, an out-of-range part is null.
    make_datetime: struct {
        year: *const Expr,
        month: *const Expr,
        day: *const Expr,
        hour: ?*const Expr = null,
        minute: ?*const Expr = null,
        second: ?*const Expr = null,
        microsecond: ?*const Expr = null,
    },
    /// polars `pl.duration(weeks, days, hours, minutes, seconds, milliseconds,
    /// microseconds)`: the sum as a duration; the parts default to 0.
    make_duration: struct {
        weeks: ?*const Expr = null,
        days: ?*const Expr = null,
        hours: ?*const Expr = null,
        minutes: ?*const Expr = null,
        seconds: ?*const Expr = null,
        milliseconds: ?*const Expr = null,
        microseconds: ?*const Expr = null,
    },
    /// polars `from_epoch(x, time_unit)`, pandas `to_datetime(x, unit=)`: an int count since
    /// 1970-01-01 as a timestamp, or a date for `.day`. A non-int is null.
    from_epoch: struct { x: *const Expr, unit: EpochUnit = .s },
    // ── added in dataframe S2 wave W4 ──
    /// Python's `split()` with no separator (pandas `str.split()` default): runs of whitespace
    /// separate, no empty pieces; `limit` pieces at most, the last the rest. `limit` 0 is
    /// `error.BadExpr`. See `strfn.splitWhitespace`.
    split_ws: struct { x: *const Expr, limit: ?usize = null },
    /// pandas `str.rsplit(pat, n)`: `split` from the right, at most `limit` pieces, the first
    /// the rest. An empty `by` or a zero `limit` is `error.BadExpr` (Python refuses both).
    rsplit: struct { x: *const Expr, by: []const u8, limit: ?usize = null },
    /// pandas `str.partition(sep)` (`last`: `rpartition`): a record `{"0","1","2"}` of the text
    /// before, the separator and the text after (pandas' three columns; `unnest` them).
    /// An empty `sep` is `error.BadExpr`.
    partition: struct { x: *const Expr, sep: []const u8, last: bool = false },
    /// polars `str.split_exact(by, n)` (`rest` false): a record of `n + 1` fields `field_0` ...
    /// (polars' names), null where the text has fewer pieces, the pieces past the n+1st
    /// dropped; with `rest`, polars `str.splitn(by, n)`: `n` fields whose last is the rest
    /// of the text (`n` 0 is then `error.BadExpr`). An empty `by` is `error.BadExpr`.
    /// `strfn.splitColumns` is the pandas `expand=True` form (as many columns as pieces).
    split_fields: struct { x: *const Expr, by: []const u8, n: usize, rest: bool = false },
    /// pandas `str.wrap(width, break_long_words=, break_on_hyphens=)` = Python's
    /// `textwrap.wrap` joined by "\n"; see `strfn.wrap` for the supported options. A zero
    /// `width` is `error.BadExpr`.
    wrap: struct { x: *const Expr, width: usize, break_long_words: bool = true, break_on_hyphens: bool = true },
    /// pandas `str.slice_replace(start, stop, repl)`; see `strfn.sliceReplace`.
    slice_replace: struct { x: *const Expr, start: ?i64 = null, stop: ?i64 = null, with: []const u8 = "" },
    /// polars `str.encode("hex" | "base64")` of the text's bytes.
    encode: struct { x: *const Expr, how: Encoding },
    /// polars `str.decode("hex" | "base64", strict=False)`: text, null for invalid input or
    /// bytes that are not UTF-8; see `strfn.decode`.
    decode: struct { x: *const Expr, how: Encoding },
    /// Python's `startswith(tuple)` / `endswith(tuple)` (pandas `str.startswith(("a", "b"))`):
    /// any of `patterns`; none: false.
    affix_any: struct { x: *const Expr, patterns: []const []const u8, end: bool = false },
    /// pandas `str.replace(from, to, n=n, regex=False)`: the first `n` occurrences (`n` >= 1;
    /// 0 is `error.BadExpr`; `replace` is the all-occurrences form).
    replace_n: struct { x: *const Expr, from: []const u8, to: []const u8, n: usize },
    /// pandas `str.match(pattern)` (anchored at the start) and, `full`, `str.fullmatch`
    /// (anchored at both ends). Patterns are the `regex` module's Rust grammar as in
    /// `contains_regex`; the whole pattern is anchored, so `a|b` is `(?:a|b)` there.
    match_regex: struct { x: *const Expr, pattern: []const u8, full: bool = false },
    /// Text to a date or a timestamp with no format: polars `str.strptime` without `format`,
    /// pandas `to_datetime` default (`.infer`), `format="ISO8601"` or `"mixed"`; see
    /// `dtfn.DateMode` and `dtfn.inferFormats`. `dayfirst` puts day-first before month-first
    /// for an ambiguous `01/02/2024` (pandas `dayfirst`; polars has none and reads day
    /// first). A cell that does not parse is null; for `.infer` an expression that is not a
    /// column, or a first non-null cell that no pattern reads, is `error.BadExpr`.
    to_datetime: struct { x: *const Expr, mode: DateMode = .infer, dayfirst: bool = false, to: ParseTo = .timestamp },
    /// pandas `Series.dt.components` (`Timedelta.components`) of a duration: a record
    /// `{days, hours, minutes, seconds, milliseconds, microseconds, nanoseconds}`; see
    /// `dtfn.components`. A non-int cell is null.
    td_components: struct { x: *const Expr },
    /// polars `dt.combine(time)`: date of `date` plus a time of day `time` (a duration since
    /// midnight in microseconds, or the text `HH:MM[:SS[.f]]`) as a timestamp.
    dt_combine: struct { date: *const Expr, time: *const Expr },
    /// polars `dt.replace(year=, month=, ...)`: each given part (an int expression, null
    /// gives null) replaces that field of `x`; a result that does not exist is null.
    dt_replace: struct {
        x: *const Expr,
        year: ?*const Expr = null,
        month: ?*const Expr = null,
        day: ?*const Expr = null,
        hour: ?*const Expr = null,
        minute: ?*const Expr = null,
        second: ?*const Expr = null,
        microsecond: ?*const Expr = null,
    },
    /// polars `dt.base_utc_offset()` / `dt.dst_offset()` and pandas `utcoffset()` of the UTC
    /// instant `x` in the IANA `zone`: a duration; see `dtfn.zoneOffset`. An unknown zone is
    /// `error.BadExpr`.
    tz_offset: struct { x: *const Expr, zone: []const u8, kind: dtf.OffsetKind = .total },
    /// polars `is_business_day(week_mask, holidays)`; the `dt` part `is_business_day` is this
    /// with Monday to Friday and no holidays.
    is_business_day: struct { x: *const Expr, week_mask: [7]bool = dtf.monday_to_friday, holidays: []const ds.Date = &.{} },
    // ── added in dataframe S2 wave W8 ──
    /// pandas `str.normalize(form)` (Python `unicodedata.normalize`): the Unicode normal form
    /// of a text cell; see `exprfn.normalize`.
    normalize: struct { x: *const Expr, form: NormalForm = .nfc },
    // ── added in dataframe S2 wave W6 ──
    /// polars `list.set_union` / `set_intersection` / `set_difference` / `set_symmetric_difference`
    /// (`x.list.set_*(y)`); see `listfn.setCell` for the order and the nulls.
    list_set: struct { x: *const Expr, y: *const Expr, op: lf.SetOp },
    /// polars `list.gather(indices, null_on_oob)`: `idx` evaluates to a list of ints (or one
    /// int); see `listfn.gatherCell`. polars' `list.concat(other)` is `concat_list`.
    list_gather: struct { x: *const Expr, idx: *const Expr, null_on_oob: bool = true },
    /// polars `Expr.repeat_by(by)`: a list of `x` repeated `by` times; see `listfn.repeatBy`.
    repeat_by: struct { x: *const Expr, by: *const Expr },
    /// polars `list.to_struct(fields)`: a record of the list's first `names.len` elements. No
    /// names, or a name twice, is `error.BadExpr`.
    list_to_struct: struct { x: *const Expr, names: []const []const u8 },
    /// polars `list.sample(n | fraction, with_replacement, shuffle, seed)`; see
    /// `listfn.sampleCell`. `n` and `fraction` together, or a negative or NaN `fraction`, is
    /// `error.BadExpr`. The generator is seeded by `seed` once per program, so the cells of a
    /// column are drawn from one stream in row order.
    list_sample: struct { x: *const Expr, n: ?usize = null, fraction: ?f64 = null, with_replacement: bool = false, shuffle: bool = false, seed: u64 = 0 },
    /// polars `list.eval(expr)`: `body` evaluated for every element of each list cell, with
    /// `.element` (polars `pl.element()`) standing for the element; the results are a list
    /// of the same length. `body` is row-wise: polars' aggregating bodies (`pl.element().sum()`,
    /// `.rank()`, `.cum_sum()`) are not here, but `list.agg` is this followed by a `list`
    /// reduction (`.list = .{ .op = .sum, .x = list_eval }`). A cell that is not a list is null.
    list_eval: struct { x: *const Expr, body: *const Expr },
    /// polars `list.filter(predicate)`: the elements for which `pred` (over `.element`) is
    /// true; false and null drop the element.
    list_filter: struct { x: *const Expr, pred: *const Expr },
    /// polars `pl.element()`: the current element, only inside `list_eval` / `list_filter`
    /// (else `error.BadExpr`). Its schema is the list column's declared element, if any.
    element,
    /// polars `struct.rename_fields`, `name.map_fields` / `prefix_fields` / `suffix_fields`
    /// and the field drop; see `listfn.StructOp`. Not a record: null.
    struct_op: struct { x: *const Expr, op: lf.StructOp },
    /// polars `struct.with_fields(...)` (`keep` true: the record's fields, the named ones
    /// replaced in place and new names appended) and `struct.eval(...)` (`keep` false: a
    /// record of just these fields). Each `fields` entry is evaluated over the record's own
    /// fields as columns, so `.col = "a"` is polars' `pl.field("a")`. `x` must name a struct
    /// column (`error.BadExpr` otherwise: the field names are read from its storage), a name
    /// twice among `fields` is `error.BadExpr`.
    struct_fields: struct { x: *const Expr, fields: []const NamedExpr, keep: bool = true },
};

/// Unicode normalization form of `Expr.normalize`: NFC, NFD, NFKC, NFKD.
pub const NormalForm = fnx.NormalForm;

/// One field of `Expr.struct_of`.
pub const NamedExpr = struct { name: []const u8, x: Expr };

pub const RegexOp = enum { contains, extract, count, replace, extract_all, split, extract_groups };

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
    /// `strftime` of a zoned instant: the zone's wall clock with its offset (`%z`) and, with
    /// `layout` null (the format has `%Z`), its abbreviation, translated per cell.
    strftime_tz: struct { fmt: []const u8, layout: ?[]const u8, zone: *const tz.Zone },
    offset_by: dtf.Duration,
    truncate: struct { d: dtf.Duration, mode: dtf.RoundTo },
    truncate_zoned: struct { d: dtf.Duration, mode: dtf.RoundTo, zone: *const tz.Zone },
    add_business_days: struct { n: i64, mask: [7]bool, holidays: []const i64, roll: dtf.Roll, plain: bool },
    regex: RegexInst,
    to_local: *const tz.Zone,
    from_local: struct { zone: *const tz.Zone, policy: dtf.TzPolicy },
    list: lf.ListOp,
    concat_list: u32,
    field: []const u8,
    /// The field names; pops one value per name.
    struct_of: []const []const u8,
    split: struct { by: []const u8, inclusive: bool, limit: ?usize },
    concat_str: struct { n: u32, separator: []const u8, ignore_nulls: bool, na_rep: ?[]const u8 },
    business_day_count: struct { mask: [7]bool, holidays: []const i64 },
    make_date,
    make_datetime,
    make_duration,
    from_epoch: dtf.EpochUnit,
    // ── dataframe S2 wave W4 ──
    split_ws: ?usize,
    rsplit: struct { by: []const u8, limit: ?usize },
    partition: struct { sep: []const u8, last: bool },
    split_fields: struct { by: []const u8, names: []const []const u8, rest: bool },
    wrap: struct { width: usize, long: bool, hyphens: bool },
    slice_replace: struct { start: ?i64, stop: ?i64, with: []const u8 },
    encode: sf.Encoding,
    decode: sf.Encoding,
    affix_any: struct { patterns: []const []const u8, end: bool },
    replace_n: struct { from: []const u8, to: []const u8, n: usize },
    /// ISO 8601 (`layouts` empty) or `parseMixed`.
    to_datetime: struct { to: dtf.ParseTo, layouts: []const []const u8, iso_only: bool },
    td_components,
    dt_combine,
    /// `mask` bit k: field k is an operand (in `dtfn.replace_fields` order, under `x`).
    dt_replace: u8,
    tz_offset: struct { zone: *const tz.Zone, kind: dtf.OffsetKind },
    is_business_day: struct { mask: [7]bool, holidays: []const i64 },
    normalize: fnx.NormalForm,
    // ── dataframe S2 wave W6 ──
    list_set: lf.SetOp,
    list_gather: bool,
    repeat_by,
    list_to_struct: []const []const u8,
    list_sample: *lf.Sampler,
    list_map: ListMap,
    struct_op: lf.StructOp,
    struct_fields: StructFields,
    /// The code of column `n`'s categorical cell as an int (null where the cell is null).
    cat_code: usize,
};

/// `list_eval` / `list_filter`: `body` over the elements, in a one-column scope `elem`.
const ListMap = struct { body: Program, filter: bool, elem: Column };

/// Where an output field of `struct_fields` comes from: field `pass` of the record, or the
/// result of program `prog`.
const FieldSrc = union(enum) { pass: usize, prog: usize };

/// `struct_fields`: the output layout and the programs, over the record's own fields as `cols`.
const StructFields = struct { names: []const []const u8, src: []const FieldSrc, progs: []const Program, cols: []const Column };

const RegexInst = struct {
    op: RegexOp,
    /// The compiled pattern's scratch, made once per program (a program runs on one
    /// thread, row after row).
    m: *regex.Matcher,
    /// `extract`'s capture slots, sized by the pattern.
    groups: []?regex.Span,
    group: usize = 0,
    with: []const u8 = "",
    all: bool = true,
    literal: bool = false,
    /// `split`'s most pieces.
    limit: ?usize = null,
    /// `extract_groups`' field names, one per group.
    names: []const []const u8 = &.{},
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
    /// Inside `list_eval` / `list_filter`: `.element` is column 0 of `f`.
    element_scope: bool = false,

    fn push(c: *Compiler, inst: Inst, pops: usize) Error!void {
        if (c.code.items.len >= max_nodes) return error.ExprTooLarge;
        try c.code.append(c.a, inst);
        c.cur = c.cur - pops + 1;
        c.max = @max(c.max, c.cur);
    }

    /// A compiled pattern and its scratch, in the program's allocator (the call's arena,
    /// as every other compiled constant here).
    fn matcher(c: *Compiler, pattern: []const u8) Error!*regex.Matcher {
        const re = try c.a.create(regex.Regex);
        re.* = regex.Regex.compileOptions(c.a, pattern, .{ .syntax = .rust }) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadPattern,
        };
        const m = try c.a.create(regex.Matcher);
        m.* = try regex.Matcher.init(c.a, re);
        return m;
    }

    /// `e`, or the literal 0 where a part is left out.
    fn goOrZero(c: *Compiler, e: ?*const Expr, depth: usize) Error!void {
        if (e) |x| return c.go(x, depth + 1);
        try c.push(.{ .lit = .{ .int = 0 } }, 0);
    }

    /// The ordered categorical column `e` names, if it is a plain column reference to one.
    fn orderedCat(c: *Compiler, e: *const Expr) ?struct { ci: usize, cat: fm.CatColumn } {
        if (e.* != .col) return null;
        const ci = c.f.columnIndex(e.col) orelse return null;
        return switch (c.f.columnAt(ci)) {
            .categorical => |cc| if (cc.ordered) .{ .ci = ci, .cat = cc } else null,
            else => null,
        };
    }

    /// `<`, `<=`, `>`, `>=` with an ordered categorical column on a side: compiled as a
    /// comparison of codes (polars `Enum`, pandas `ordered=True`). The other side is a text
    /// literal (its position among the categories; a text that is no category is
    /// `error.BadExpr`, polars `InvalidOperationError`, pandas `TypeError`), a null literal
    /// (the comparison is null) or another ordered column with the same categories in the same
    /// order; anything else is `error.BadExpr`. Returns whether it compiled the comparison.
    fn orderedCompare(c: *Compiler, op: Binary, l: *const Expr, r: *const Expr, depth: usize) Error!bool {
        switch (op) {
            .lt, .le, .gt, .ge => {},
            else => return false,
        }
        const lc = c.orderedCat(l);
        const rc = c.orderedCat(r);
        if (lc == null and rc == null) return false;
        const dict = (lc orelse rc.?).cat.dict;
        if (lc != null and rc != null and !catfn.sameDict(lc.?.cat.dict, rc.?.cat.dict)) return error.BadExpr;
        if (depth + 1 >= max_depth) return error.ExprTooLarge;
        for ([2]*const Expr{ l, r }) |side| {
            if (c.orderedCat(side)) |oc| {
                try c.push(.{ .cat_code = oc.ci }, 0);
                continue;
            }
            if (side.* != .lit) return error.BadExpr;
            switch (side.lit) {
                .null => try c.push(.{ .lit = .null }, 0),
                .text => |t| {
                    const k = catfn.rankOf(dict, t) orelse return error.BadExpr;
                    try c.push(.{ .lit = .{ .int = k } }, 0);
                },
                else => return error.BadExpr,
            }
        }
        try c.push(.{ .binary = op }, 2);
        return true;
    }

    /// `struct_fields`: the record's own fields are the columns of the scope its `fields` are
    /// compiled in (names read from the column's storage).
    fn structFields(c: *Compiler, x: *const Expr, fields: []const NamedExpr, keep: bool, depth: usize) Error!void {
        if (!keep and fields.len == 0) return error.BadExpr;
        if (fields.len > nv.max_unnest_fields) return error.TooLarge;
        if (x.* != .col) return error.BadExpr;
        const ci = c.f.columnIndex(x.col) orelse return error.NoSuchColumn;
        const sc = switch (c.f.columnAt(ci)) {
            .@"struct" => |p| p,
            else => return error.BadExpr,
        };
        const decl = c.f.columns[ci];
        const cols = try c.a.alloc(Column, sc.names.len);
        for (cols, sc.names, 0..) |*o, nm, i| {
            const d = decl.innerAt(i, nm);
            o.* = d orelse .{ .name = nm, .type = nv.storageType(if (i < sc.children.len) sc.children[i] else .nulls) };
        }
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        defer seen.deinit(c.a);
        const progs = try c.a.alloc(Program, fields.len);
        for (fields, progs) |*nf, *pr| {
            if ((try seen.getOrPut(c.a, nf.name)).found_existing) return error.BadExpr;
            var sub: Compiler = .{ .a = c.a, .f = .{ .columns = cols, .data = sc.children, .len = sc.len } };
            try sub.go(&nf.x, depth + 1);
            pr.* = .{ .code = sub.code.items, .stack = sub.max };
        }
        var names: std.ArrayList([]const u8) = .empty;
        var src: std.ArrayList(FieldSrc) = .empty;
        if (keep) for (sc.names, 0..) |nm, i| {
            try names.append(c.a, nm);
            try src.append(c.a, .{ .pass = i });
        };
        for (fields, 0..) |nf, j| {
            const at = for (names.items, 0..) |nm, k| {
                if (std.mem.eql(u8, nm, nf.name)) break k;
            } else null;
            if (at) |k| {
                src.items[k] = .{ .prog = j };
            } else {
                try names.append(c.a, nf.name);
                try src.append(c.a, .{ .prog = j });
            }
        }
        if (names.items.len > nv.max_unnest_fields) return error.TooLarge;
        try c.go(x, depth + 1);
        try c.push(.{ .struct_fields = .{ .names = names.items, .src = src.items, .progs = progs, .cols = cols } }, 1);
    }

    /// `l op r` as `go(.binary)` compiles it: an ordered categorical comparison by codes,
    /// else both operands and the operator. `depth` is the depth of the node holding it.
    fn binary(c: *Compiler, op: Binary, l: *const Expr, r: *const Expr, depth: usize) Error!void {
        if (try c.orderedCompare(op, l, r, depth)) return;
        try c.go(l, depth + 1);
        try c.go(r, depth + 1);
        try c.push(.{ .binary = op }, 2);
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
                try c.binary(b.op, b.l, b.r, depth);
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
                if (k.zone) |zn| if (k.to != .timestamp or tz.find(zn) == null) return error.BadExpr;
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
            .contains_regex => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .regex = .{ .op = .contains, .m = try c.matcher(r.pattern), .groups = &.{} } }, 1);
            },
            .count_regex => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .regex = .{ .op = .count, .m = try c.matcher(r.pattern), .groups = &.{} } }, 1);
            },
            .extract => |r| {
                const m = try c.matcher(r.pattern);
                const n = m.re.groupCount();
                if (r.group > n) return error.BadExpr;
                const groups = try c.a.alloc(?regex.Span, n + 1);
                try c.go(r.x, depth + 1);
                try c.push(.{ .regex = .{ .op = .extract, .m = m, .groups = groups, .group = r.group } }, 1);
            },
            .replace_regex => |r| {
                if (r.n != null and r.n.? == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .regex = .{ .op = .replace, .m = try c.matcher(r.pattern), .groups = &.{}, .with = r.with, .all = r.all, .literal = r.literal, .limit = r.n } }, 1);
            },
            .to_local => |r| {
                const zone = tz.find(r.zone) orelse return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .to_local = zone }, 1);
            },
            .from_local => |r| {
                const zone = tz.find(r.zone) orelse return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .from_local = .{ .zone = zone, .policy = r.policy } }, 1);
            },
            .convert_time_zone => |r| {
                if (r.zone) |zn| if (tz.find(zn) == null) return error.BadExpr;
                try c.go(r.x, depth + 1); // metadata only: the instants stay
                // After `go`: the static helpers walk only an operand `go` has bounded.
                if (temporalType(c.f, r.x)) |t| if (t != .timestamp) return error.BadExpr;
            },
            .replace_time_zone => |r| {
                const to: ?*const tz.Zone = if (r.zone) |zn| (tz.find(zn) orelse return error.BadExpr) else null;
                try c.go(r.x, depth + 1);
                if (temporalType(c.f, r.x)) |t| if (t != .timestamp) return error.BadExpr;
                if (zoneOf(c.f, r.x)) |old| try c.push(.{ .to_local = tz.find(old) orelse return error.BadExpr }, 1);
                if (to) |z| try c.push(.{ .from_local = .{ .zone = z, .policy = r.policy } }, 1);
            },
            .dt => |r| {
                try c.go(r.x, depth + 1);
                // A zoned column shows its zone's wall clock (polars and pandas); the epoch and
                // duration parts are the instant's own. `month_start`/`month_end` are instants
                // again: cut on the wall clock, read back in the zone.
                const zone = if (zoneOf(c.f, r.x)) |zn| (tz.find(zn) orelse return error.BadExpr) else null;
                if (zone) |z| if (localPart(r.part)) try c.push(.{ .to_local = z }, 1);
                try c.push(.{ .dt = r.part }, 1);
                if (zone) |z| if (r.part == .month_start or r.part == .month_end) try c.push(.{ .from_local = .{ .zone = z, .policy = .compatible } }, 1);
            },
            .strptime => |r| {
                const layout = dtf.translateFormat(c.a, r.format) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .strptime = .{ .layout = layout, .to = r.to } }, 1);
            },
            .strftime => |r| {
                try c.go(r.x, depth + 1); // first: `zoneOf` walks only an operand `go` has bounded
                if (zoneOf(c.f, r.x)) |zn| {
                    const zone = tz.find(zn) orelse return error.BadExpr;
                    // `%Z` (the abbreviation) changes with the cell, so its format is translated per cell.
                    const per_cell = std.mem.find(u8, r.format, "%Z") != null;
                    if (per_cell) dtf.checkZonedFormat(c.a, r.format) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.BadExpr;
                    const layout: ?[]const u8 = if (per_cell) null else (dtf.translateFormat(c.a, r.format) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.BadExpr);
                    try c.push(.{ .strftime_tz = .{ .fmt = r.format, .layout = layout, .zone = zone } }, 1);
                    return;
                }
                const layout = dtf.translateFormat(c.a, r.format) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.BadExpr;
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
                // A zoned column cuts on its wall clock, whatever the step (see `dtfn.roundToZoned`).
                if (zoneOf(c.f, r.x)) |zn| {
                    const z = tz.find(zn) orelse return error.BadExpr;
                    try c.push(.{ .truncate_zoned = .{ .d = d, .mode = r.mode, .zone = z } }, 1);
                    return;
                }
                try c.push(.{ .truncate = .{ .d = d, .mode = r.mode } }, 1);
            },
            .add_business_days => |r| {
                const plain = std.mem.eql(bool, &r.week_mask, &dtf.monday_to_friday) and r.holidays.len == 0 and r.roll == .forward;
                try c.go(r.x, depth + 1);
                try c.push(.{ .add_business_days = .{ .n = r.n, .mask = r.week_mask, .holidays = try holidayDays(c.a, r.holidays), .roll = r.roll, .plain = plain } }, 1);
            },
            .list => |r| {
                if (r.op == .gather_every and r.op.gather_every.n == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .list = r.op }, 1);
            },
            .concat_list => |xs| {
                if (xs.len == 0) return error.BadExpr;
                if (xs.len > max_nodes) return error.ExprTooLarge;
                for (xs) |*x| try c.go(x, depth + 1);
                try c.push(.{ .concat_list = @intCast(xs.len) }, xs.len);
            },
            .field => |r| {
                // A column that declares its fields and lacks this one: the name is wrong.
                if (r.x.* == .col) if (c.f.columnIndex(r.x.col)) |ci| {
                    const col = c.f.columns[ci];
                    if (col.type == .@"struct" and col.inner.len > 0 and col.innerAt(0, r.name) == null) return error.BadExpr;
                };
                try c.go(r.x, depth + 1);
                try c.push(.{ .field = r.name }, 1);
            },
            .struct_of => |fs| {
                if (fs.len == 0) return error.BadExpr;
                if (fs.len > max_nodes) return error.ExprTooLarge;
                const names = try c.a.alloc([]const u8, fs.len);
                var seen: std.StringHashMapUnmanaged(void) = .empty;
                defer seen.deinit(c.a);
                for (fs, names) |*nf, *n| {
                    if ((try seen.getOrPut(c.a, nf.name)).found_existing) return error.BadExpr;
                    n.* = nf.name;
                    try c.go(&nf.x, depth + 1);
                }
                try c.push(.{ .struct_of = names }, fs.len);
            },
            .split => |r| {
                if (r.limit == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .split = .{ .by = r.by, .inclusive = r.inclusive, .limit = r.limit } }, 1);
            },
            .split_regex => |r| {
                if (r.limit == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .regex = .{ .op = .split, .m = try c.matcher(r.pattern), .groups = &.{}, .limit = r.limit } }, 1);
            },
            .extract_all => |r| {
                const m = try c.matcher(r.pattern);
                const n = m.re.groupCount();
                if (r.group > n) return error.BadExpr;
                const groups = try c.a.alloc(?regex.Span, n + 1);
                try c.go(r.x, depth + 1);
                try c.push(.{ .regex = .{ .op = .extract_all, .m = m, .groups = groups, .group = r.group } }, 1);
            },
            .is_between => |r| {
                try c.binary(if (r.closed == .both or r.closed == .left) .ge else .gt, r.x, r.lower, depth);
                try c.binary(if (r.closed == .both or r.closed == .right) .le else .lt, r.x, r.upper, depth);
                try c.push(.{ .binary = .@"and" }, 2);
            },
            .concat_str => |r| {
                if (r.parts.len == 0) return error.BadExpr;
                if (r.parts.len > max_nodes) return error.ExprTooLarge;
                for (r.parts) |*x| try c.go(x, depth + 1);
                try c.push(.{ .concat_str = .{ .n = @intCast(r.parts.len), .separator = r.separator, .ignore_nulls = r.ignore_nulls, .na_rep = r.na_rep } }, r.parts.len);
            },
            .fold => |r| {
                if (r.parts.len > max_nodes) return error.ExprTooLarge;
                var rest: []const Expr = r.parts;
                var left: *const Expr = undefined;
                if (r.acc) |acc| {
                    left = acc;
                } else {
                    if (rest.len == 0) return error.BadExpr;
                    left = &rest[0];
                    rest = rest[1..];
                }
                // The first step compares the two expressions (an ordered categorical there); the
                // later ones fold the running value, which is no column.
                var first = true;
                for (rest) |*x| {
                    if (first) {
                        try c.binary(r.op, left, x, depth);
                        first = false;
                    } else {
                        try c.go(x, depth + 1);
                        try c.push(.{ .binary = r.op }, 2);
                    }
                }
                if (first) try c.go(left, depth + 1);
            },
            .business_day_count => |r| {
                const days = try c.a.alloc(i64, r.holidays.len);
                for (days, r.holidays) |*d, h| d.* = h.ordinal();
                std.mem.sort(i64, days, {}, std.sort.asc(i64));
                var k: usize = 0;
                for (days) |d| {
                    if (k > 0 and days[k - 1] == d) continue;
                    days[k] = d;
                    k += 1;
                }
                // Each operand counts by its own local day when it is zoned.
                for ([2]*const Expr{ r.start, r.end }) |side| {
                    try c.go(side, depth + 1);
                    if (zoneOf(c.f, side)) |zn| try c.push(.{ .to_local = tz.find(zn) orelse return error.BadExpr }, 1);
                }
                try c.push(.{ .business_day_count = .{ .mask = r.week_mask, .holidays = days[0..k] } }, 2);
            },
            .make_date => |r| {
                try c.go(r.year, depth + 1);
                try c.go(r.month, depth + 1);
                try c.go(r.day, depth + 1);
                try c.push(.make_date, 3);
            },
            .make_datetime => |r| {
                try c.go(r.year, depth + 1);
                try c.go(r.month, depth + 1);
                try c.go(r.day, depth + 1);
                try c.goOrZero(r.hour, depth);
                try c.goOrZero(r.minute, depth);
                try c.goOrZero(r.second, depth);
                try c.goOrZero(r.microsecond, depth);
                try c.push(.make_datetime, 7);
            },
            .make_duration => |r| {
                try c.goOrZero(r.weeks, depth);
                try c.goOrZero(r.days, depth);
                try c.goOrZero(r.hours, depth);
                try c.goOrZero(r.minutes, depth);
                try c.goOrZero(r.seconds, depth);
                try c.goOrZero(r.milliseconds, depth);
                try c.goOrZero(r.microseconds, depth);
                try c.push(.make_duration, 7);
            },
            .from_epoch => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .from_epoch = r.unit }, 1);
            },
            .split_ws => |r| {
                if (r.limit != null and r.limit.? == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .split_ws = r.limit }, 1);
            },
            .rsplit => |r| {
                if (r.by.len == 0 or (r.limit != null and r.limit.? == 0)) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .rsplit = .{ .by = r.by, .limit = r.limit } }, 1);
            },
            .partition => |r| {
                if (r.sep.len == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .partition = .{ .sep = r.sep, .last = r.last } }, 1);
            },
            .split_fields => |r| {
                if (r.by.len == 0 or (r.rest and r.n == 0)) return error.BadExpr;
                const count = if (r.rest) r.n else r.n +| 1;
                if (count > sf.max_str_columns) return error.TooLarge;
                const names = try c.a.alloc([]const u8, count);
                for (names, 0..) |*nm, i| nm.* = try c.a.print("field_{d}", .{i});
                try c.go(r.x, depth + 1);
                try c.push(.{ .split_fields = .{ .by = r.by, .names = names, .rest = r.rest } }, 1);
            },
            .wrap => |r| {
                if (r.width == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .wrap = .{ .width = r.width, .long = r.break_long_words, .hyphens = r.break_on_hyphens } }, 1);
            },
            .slice_replace => |r| {
                if (r.with.len > fnx.max_text_result) return error.TooLarge;
                try c.go(r.x, depth + 1);
                try c.push(.{ .slice_replace = .{ .start = r.start, .stop = r.stop, .with = r.with } }, 1);
            },
            .encode => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .encode = r.how }, 1);
            },
            .decode => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .decode = r.how }, 1);
            },
            .affix_any => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .affix_any = .{ .patterns = r.patterns, .end = r.end } }, 1);
            },
            .replace_n => |r| {
                if (r.from.len == 0 or r.n == 0) return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .replace_n = .{ .from = r.from, .to = r.to, .n = r.n } }, 1);
            },
            .match_regex => |r| {
                _ = try c.matcher(r.pattern); // the user's pattern alone must be valid
                const anchored = try c.a.print("\\A(?:{s}){s}", .{ r.pattern, if (r.full) "\\z" else "" });
                try c.go(r.x, depth + 1);
                try c.push(.{ .regex = .{ .op = .contains, .m = try c.matcher(anchored), .groups = &.{} } }, 1);
            },
            .to_datetime => |r| {
                var layouts: std.ArrayList([]const u8) = .empty;
                for (dtf.inferFormats(r.dayfirst)) |fmt| {
                    layouts.append(c.a, dtf.translateInfer(c.a, fmt) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.BadExpr) catch return error.OutOfMemory;
                }
                switch (r.mode) {
                    .iso8601 => {
                        try c.go(r.x, depth + 1);
                        try c.push(.{ .to_datetime = .{ .to = r.to, .layouts = &.{}, .iso_only = true } }, 1);
                    },
                    .mixed => {
                        try c.go(r.x, depth + 1);
                        try c.push(.{ .to_datetime = .{ .to = r.to, .layouts = layouts.items, .iso_only = false } }, 1);
                    },
                    .infer => {
                        if (r.x.* != .col) return error.BadExpr;
                        const ci = c.f.columnIndex(r.x.col) orelse return error.NoSuchColumn;
                        const colv = c.f.columnAt(ci);
                        var first: ?Value = null;
                        for (0..c.f.len) |ri| {
                            const v = colv.get(ri);
                            if (!keys.isMissing(v)) {
                                first = v;
                                break;
                            }
                        }
                        try c.go(r.x, depth + 1);
                        const v = first orelse {
                            try c.push(.{ .to_datetime = .{ .to = r.to, .layouts = &.{}, .iso_only = true } }, 1);
                            return;
                        };
                        if ((try dtf.parseIso(c.a, v, r.to)) != .null) {
                            try c.push(.{ .to_datetime = .{ .to = r.to, .layouts = &.{}, .iso_only = true } }, 1);
                            return;
                        }
                        for (layouts.items) |l| {
                            if ((try dtf.strptime(c.a, v, l, r.to)) != .null) {
                                try c.push(.{ .strptime = .{ .layout = l, .to = r.to } }, 1);
                                return;
                            }
                        }
                        return error.BadExpr;
                    },
                }
            },
            .td_components => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.td_components, 1);
            },
            .dt_combine => |r| {
                try c.go(r.date, depth + 1);
                try c.go(r.time, depth + 1);
                try c.push(.dt_combine, 2);
            },
            .dt_replace => |r| {
                try c.go(r.x, depth + 1);
                // A zoned column replaces fields of its wall clock and reads the result back in its zone.
                const zone = if (zoneOf(c.f, r.x)) |zn| (tz.find(zn) orelse return error.BadExpr) else null;
                if (zone) |z| try c.push(.{ .to_local = z }, 1);
                const given = [7]?*const Expr{ r.year, r.month, r.day, r.hour, r.minute, r.second, r.microsecond };
                var mask: u8 = 0;
                var pops: usize = 1;
                for (given, 0..) |g, k| if (g) |e2| {
                    try c.go(e2, depth + 1);
                    mask |= @as(u8, 1) << @intCast(k);
                    pops += 1;
                };
                try c.push(.{ .dt_replace = mask }, pops);
                if (zone) |z| try c.push(.{ .from_local = .{ .zone = z, .policy = .compatible } }, 1);
            },
            .tz_offset => |r| {
                const zone = tz.find(r.zone) orelse return error.BadExpr;
                try c.go(r.x, depth + 1);
                try c.push(.{ .tz_offset = .{ .zone = zone, .kind = r.kind } }, 1);
            },
            .is_business_day => |r| {
                try c.go(r.x, depth + 1);
                // A zoned column's business day is its local day (as the `dt` part reads it).
                if (zoneOf(c.f, r.x)) |zn| try c.push(.{ .to_local = tz.find(zn) orelse return error.BadExpr }, 1);
                try c.push(.{ .is_business_day = .{ .mask = r.week_mask, .holidays = try holidayDays(c.a, r.holidays) } }, 1);
            },
            .normalize => |r| {
                try c.go(r.x, depth + 1);
                try c.push(.{ .normalize = r.form }, 1);
            },
            // ── dataframe S2 wave W6 ──
            .list_set => |r| {
                try c.go(r.x, depth + 1);
                try c.go(r.y, depth + 1);
                try c.push(.{ .list_set = r.op }, 2);
            },
            .list_gather => |r| {
                try c.go(r.x, depth + 1);
                try c.go(r.idx, depth + 1);
                try c.push(.{ .list_gather = r.null_on_oob }, 2);
            },
            .repeat_by => |r| {
                try c.go(r.x, depth + 1);
                try c.go(r.by, depth + 1);
                try c.push(.repeat_by, 2);
            },
            .list_to_struct => |r| {
                if (r.names.len == 0) return error.BadExpr;
                if (r.names.len > nv.max_unnest_fields) return error.TooLarge;
                try noDuplicateNames(c.a, r.names);
                try c.go(r.x, depth + 1);
                try c.push(.{ .list_to_struct = r.names }, 1);
            },
            .list_sample => |r| {
                if (r.n != null and r.fraction != null) return error.BadExpr;
                // NaN, negative and infinite are refused: `len * inf` is NaN for an empty list.
                if (r.fraction) |fr| if (!(fr >= 0 and std.math.isFinite(fr))) return error.BadExpr;
                const st = try c.a.create(lf.Sampler);
                st.* = .{ .prng = std.Random.DefaultPrng.init(r.seed), .n = r.n, .fraction = r.fraction, .with_replacement = r.with_replacement, .shuffle = r.shuffle };
                try c.go(r.x, depth + 1);
                try c.push(.{ .list_sample = st }, 1);
            },
            .list_eval, .list_filter => {
                const r: struct { x: *const Expr, body: *const Expr } = switch (e.*) {
                    .list_eval => |q| .{ .x = q.x, .body = q.body },
                    .list_filter => |q| .{ .x = q.x, .body = q.pred },
                    else => unreachable, // the prong names these two
                };
                try c.go(r.x, depth + 1);
                const decl = elementColumn(c.f, r.x);
                const elem: Column = .{ .name = "", .type = if (decl) |d| d.type else .float, .inner = if (decl) |d| d.inner else &.{}, .time_zone = if (decl) |d| d.time_zone else null };
                const cols = try c.a.alloc(Column, 1);
                cols[0] = elem;
                const data = try c.a.alloc(ColumnData, 1);
                data[0] = .nulls;
                if (r.x.* == .col) if (c.f.columnIndex(r.x.col)) |ci| switch (c.f.columnAt(ci)) {
                    .list => |lc| data[0] = lc.items.*,
                    else => {},
                };
                var sub: Compiler = .{ .a = c.a, .f = .{ .columns = cols, .data = data, .len = 0 }, .element_scope = true };
                try sub.go(r.body, depth + 1);
                try c.push(.{ .list_map = .{ .body = .{ .code = sub.code.items, .stack = sub.max }, .filter = e.* == .list_filter, .elem = elem } }, 1);
            },
            .element => {
                if (!c.element_scope) return error.BadExpr;
                try c.push(.{ .col = 0 }, 0);
            },
            .struct_op => |r| {
                switch (r.op) {
                    .rename_fields => |names| {
                        if (names.len == 0) return error.BadExpr;
                        try noDuplicateNames(c.a, names);
                    },
                    .map_fields => |m| switch (m) {
                        .replace => |q| if (q.from.len == 0) return error.BadExpr,
                        else => {},
                    },
                    .drop => {},
                }
                try c.go(r.x, depth + 1);
                try c.push(.{ .struct_op = r.op }, 1);
            },
            .struct_fields => |r| try c.structFields(r.x, r.fields, r.keep, depth),
            .extract_groups => |r| {
                const m = try c.matcher(r.pattern);
                const n = m.re.groupCount();
                if (n == 0) return error.BadExpr;
                const groups = try c.a.alloc(?regex.Span, n + 1);
                const names = try c.a.alloc([]const u8, n);
                for (names, 1..) |*nm, gi| {
                    const given = m.re.names[gi];
                    nm.* = if (given.len != 0) given else try c.a.print("{d}", .{gi});
                }
                try c.go(r.x, depth + 1);
                try c.push(.{ .regex = .{ .op = .extract_groups, .m = m, .groups = groups, .names = names } }, 1);
            },
        }
    }
};

/// `error.BadExpr` when a name appears twice.
fn noDuplicateNames(a: std.mem.Allocator, names: []const []const u8) Error!void {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (names) |n| if ((try seen.getOrPut(a, n)).found_existing) return error.BadExpr;
}

/// Holidays as sorted, distinct epoch days (the form `dtfn.businessDayCount` wants).
fn holidayDays(a: std.mem.Allocator, hs: []const ds.Date) Error![]const i64 {
    const days = try a.alloc(i64, hs.len);
    for (days, hs) |*d, h| d.* = h.ordinal();
    std.mem.sort(i64, days, {}, std.sort.asc(i64));
    var k: usize = 0;
    for (days) |d| {
        if (k > 0 and days[k - 1] == d) continue;
        days[k] = d;
        k += 1;
    }
    return days[0..k];
}

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
        const n = try keyLen(one.items.len);
        try out.appendSlice(a, std.mem.asBytes(&n));
        try out.appendSlice(a, one.items);
    }
    return out.toOwnedSlice(a);
}

/// A canonical key's length as the set's u32 prefix; a key of 4 GiB or more is refused
/// (a text value that long is caller data, sweep S2-7).
fn keyLen(n: usize) Error!u32 {
    return std.math.cast(u32, n) orelse error.TooLarge;
}

/// `concat_str` of one row: see `Expr.concat_str`.
fn concatStr(a: std.mem.Allocator, parts: []const Value, sep: []const u8, ignore_nulls: bool, na_rep: ?[]const u8) Error!Value {
    var out: std.ArrayList(u8) = .empty;
    var first = true;
    for (parts) |p| {
        var piece: []const u8 = undefined;
        if (keys.isMissing(p)) {
            if (na_rep) |r| {
                piece = r;
            } else if (ignore_nulls) {
                continue;
            } else {
                out.deinit(a);
                return .null;
            }
        } else piece = (try castValue(a, p, .text)).text;
        const add = piece.len + if (first) 0 else sep.len;
        if (add > fnx.max_text_result -| out.items.len) {
            out.deinit(a);
            return error.TooLarge;
        }
        if (!first) try out.appendSlice(a, sep);
        try out.appendSlice(a, piece);
        first = false;
    }
    return .{ .text = try out.toOwnedSlice(a) };
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
        .is_ascii, .escape_regex, .capitalize, .title, .swapcase, .reverse, .len_bytes, .is_alpha, .is_digit, .is_alnum, .is_space, .is_lower, .is_upper, .is_title, .lstrip, .rstrip, .casefold, .unaccent, .is_decimal, .is_numeric => {
            if (v != .text) return .null;
            const t = v.text;
            return switch (op) {
                .is_ascii => .{ .bool = for (t) |ch| {
                    if (ch >= 0x80) break false;
                } else true },
                .escape_regex => .{ .text = try fnx.escapeRegex(a, t) },
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
                .is_decimal => .{ .bool = fnx.isClass(t, .decimal) },
                .is_numeric => .{ .bool = fnx.isClass(t, .numeric) },
                .casefold => .{ .text = try fnx.casefold(a, t) },
                .unaccent => .{ .text = try fnx.unaccent(a, t) },
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
                .lower => .{ .text = try fnx.lower(a, t) },
                .upper => .{ .text = try fnx.upper(a, t) },
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
        .erfc => .{ .float = fnx.erfc(x) },
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
                .find => if (try fnx.findIn(a, t, p)) |i| .{ .int = @intCast(i) } else .null,
                .rfind => if (try fnx.findLastIn(a, t, p)) |i| .{ .int = @intCast(i) } else .null,
                else => .{ .int = @intCast(try fnx.countMatchesIn(a, t, p)) },
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
                // Lists and records compare as polars compares them (`Value.order`).
                .list => r == .list,
                .record => r == .record,
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
                .contains => .{ .bool = (try fnx.findIn(a, l.text, r.text)) != null },
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
            .truncdiv => {
                if (y == 0 or (x == std.math.minInt(i64) and y == -1)) return .null;
                return .{ .int = @divTrunc(x, y) };
            },
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
            .truncdiv => @trunc(x / y),
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
        .text, .date, .categorical => switch (v) {
            .text => return v,
            .int => |i| return .{ .text = try a.print("{d}", .{i}) },
            .float => |f| return .{ .text = try a.print("{d}", .{f}) },
            .bool => |b| return .{ .text = if (b) "true" else "false" },
            .decimal => |r| return .{ .text = try decimalText(a, r) },
            .null => return .null,
            // A nested cell as text is its JSON (polars' `cast(String)` refuses a list;
            // its JSON is what `writeCsv` writes for it).
            .list, .record => {
                var out: std.Io.Writer.Allocating = .init(a);
                defer out.deinit();
                jsonio.writeValue(&out.writer, v, null, 0) catch return error.OutOfMemory; // an Allocating writer fails only so
                return .{ .text = try out.toOwnedSlice() };
            },
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
fn regexCell(a: std.mem.Allocator, r: RegexInst, t: []const u8) Error!Value {
    switch (r.op) {
        .contains => return .{ .bool = r.m.find(t, 0) != null },
        .count => {
            var it = r.m.iterator(t);
            var n: i64 = 0;
            while (it.next()) |_| n += 1; // at most len + 1 matches: no overflow
            return .{ .int = n };
        },
        .extract => {
            if (!r.m.captures(t, 0, r.groups)) return .null;
            const span = r.groups[r.group] orelse return .null;
            return .{ .text = span.slice(t) };
        },
        .replace => {
            var out: std.Io.Writer.Allocating = .init(a);
            defer out.deinit();
            const limit: ?usize = r.limit orelse if (r.all) null else 1;
            const res = if (r.literal) r.m.replaceNLiteral(&out.writer, t, r.with, limit) else r.m.replaceN(&out.writer, t, r.with, limit);
            res catch return error.OutOfMemory; // the only way an Allocating writer fails
            if (out.written().len > fnx.max_text_result) return error.TooLarge;
            return .{ .text = try out.toOwnedSlice() };
        },
        .extract_all => {
            var pieces: std.ArrayList(Value) = .empty;
            defer pieces.deinit(a);
            var it = r.m.iterator(t);
            while (it.nextCaptures(r.groups)) |_| {
                // At most len + 1 matches; each element a slice of `t`, copied by `makeList`.
                try pieces.append(a, if (r.groups[r.group]) |s| .{ .text = s.slice(t) } else .null);
            }
            return lf.makeList(a, pieces.items);
        },
        .split => {
            var pieces: std.ArrayList(Value) = .empty;
            defer pieces.deinit(a);
            var it = r.m.split(t, r.limit);
            while (it.next()) |piece| try pieces.append(a, .{ .text = piece });
            return lf.makeList(a, pieces.items);
        },
        .extract_groups => {
            const vals = try a.alloc(Value, r.names.len);
            defer a.free(vals);
            const hit = r.m.captures(t, 0, r.groups);
            for (vals, 1..) |*v, gi| v.* = if (!hit) .null else if (r.groups[gi]) |s| .{ .text = s.slice(t) } else .null;
            return lf.makeRecord(a, r.names, vals);
        },
    }
}

/// One row of `p`. Every instruction but the last allocates in `tmp`, the last in `last`
/// (see `RowScratch`); `one` (the `is_in` key scratch, kept across rows) grows in `one_a`.
fn eval(tmp: std.mem.Allocator, last: std.mem.Allocator, one_a: std.mem.Allocator, p: Program, f: Frame, ri: usize, stack: []Value, one: *std.ArrayList(u8)) Error!Value {
    var sp: usize = 0;
    for (p.code, 0..) |inst, ii| {
        const a = if (ii + 1 == p.code.len) last else tmp;
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
                    try keys.encode(one_a, one, v, .as_null);
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
            .regex => |r| {
                const v = stack[sp - 1];
                if (v != .text) {
                    stack[sp - 1] = .null;
                    continue;
                }
                stack[sp - 1] = try regexCell(a, r, v.text);
            },
            .truncate_zoned => |r| {
                const v = stack[sp - 1];
                stack[sp - 1] = if (keys.isMissing(v)) .null else try dtf.roundToZoned(a, v, r.d, r.mode, r.zone);
            },
            .strftime_tz => |r| {
                const v = stack[sp - 1];
                stack[sp - 1] = if (keys.isMissing(v)) .null else try dtf.strftimeZoned(a, v, r.fmt, r.layout, r.zone);
            },
            .to_local => |zone| stack[sp - 1] = try dtf.toLocal(a, stack[sp - 1], zone),
            .from_local => |r| stack[sp - 1] = try dtf.fromLocal(a, stack[sp - 1], r.zone, r.policy),
            .add_business_days => |r| {
                const v = stack[sp - 1];
                stack[sp - 1] = if (keys.isMissing(v)) .null else if (r.plain) try dtf.addBusinessDays(a, v, r.n) else try dtf.addBusinessDaysMask(a, v, r.n, r.mask, r.holidays, r.roll);
            },
            .dt, .strptime, .strftime, .offset_by, .truncate => {
                const v = stack[sp - 1];
                stack[sp - 1] = if (keys.isMissing(v)) .null else switch (inst) {
                    .dt => |part| try dtf.part(a, v, part),
                    .strptime => |r| try dtf.strptime(a, v, r.layout, r.to),
                    .strftime => |layout| try dtf.strftime(a, v, layout),
                    .offset_by => |d| try dtf.offsetBy(a, v, d),
                    .truncate => |r| try dtf.roundTo(a, v, r.d, r.mode),
                    else => unreachable, // the prong names these five
                };
            },
            .list => |op| stack[sp - 1] = try lf.listCell(a, stack[sp - 1], op),
            .concat_list => |n| {
                const base = sp - n;
                stack[base] = try lf.concatList(a, stack[base..sp]);
                sp = base + 1;
            },
            .field => |name| stack[sp - 1] = lf.field(stack[sp - 1], name),
            .struct_of => |names| {
                const base = sp - names.len;
                stack[base] = try lf.makeRecord(a, names, stack[base..sp]);
                sp = base + 1;
            },
            .split => |r| {
                const v = stack[sp - 1];
                stack[sp - 1] = if (v == .text) try lf.splitLiteral(a, v.text, r.by, r.inclusive, r.limit) else .null;
            },
            .concat_str => |r| {
                const base = sp - r.n;
                stack[base] = try concatStr(a, stack[base..sp], r.separator, r.ignore_nulls, r.na_rep);
                sp = base + 1;
            },
            .business_day_count => |r| {
                const s = dtf.dayOf(stack[sp - 2]);
                const e = dtf.dayOf(stack[sp - 1]);
                stack[sp - 2] = if (s != null and e != null) .{ .int = dtf.businessDayCount(s.?, e.?, r.mask, r.holidays) } else .null;
                sp -= 1;
            },
            .make_date => {
                const ps = stack[sp - 3 .. sp];
                stack[sp - 3] = if (ps[0] == .int and ps[1] == .int and ps[2] == .int) try dtf.makeDate(a, ps[0].int, ps[1].int, ps[2].int) else .null;
                sp -= 2;
            },
            .make_datetime, .make_duration => {
                const ps = stack[sp - 7 .. sp];
                var n: [7]i64 = undefined;
                var ok = true;
                for (&n, ps) |*o, v| {
                    if (v == .int) o.* = v.int else ok = false;
                }
                stack[sp - 7] = if (!ok) .null else if (inst == .make_datetime)
                    dtf.makeDatetime(n[0], n[1], n[2], n[3], n[4], n[5], n[6])
                else
                    dtf.makeDuration(n);
                sp -= 6;
            },
            .from_epoch => |unit| stack[sp - 1] = try dtf.fromEpoch(a, stack[sp - 1], unit),
            .split_ws, .rsplit, .partition, .split_fields, .wrap, .slice_replace, .encode, .decode, .affix_any, .replace_n => {
                const v = stack[sp - 1];
                if (v != .text) {
                    stack[sp - 1] = .null;
                    continue;
                }
                const t = v.text;
                stack[sp - 1] = switch (inst) {
                    .split_ws => |lim| try sf.splitWhitespace(a, t, lim),
                    .rsplit => |r| try sf.rsplitLiteral(a, t, r.by, r.limit),
                    .partition => |r| try sf.partition(a, t, r.sep, r.last),
                    .split_fields => |r| try sf.splitFields(a, t, r.by, r.names, r.rest),
                    .wrap => |r| .{ .text = try sf.wrap(a, t, r.width, r.long, r.hyphens) },
                    .slice_replace => |r| .{ .text = try sf.sliceReplace(a, t, r.start, r.stop, r.with) },
                    .encode => |how| .{ .text = try sf.encode(a, t, how) },
                    .decode => |how| if (try sf.decode(a, t, how)) |d| Value{ .text = d } else .null,
                    .affix_any => |r| .{ .bool = sf.hasAnyAffix(t, r.patterns, r.end) },
                    .replace_n => |r| .{ .text = try sf.replaceFirstN(a, t, r.from, r.to, r.n) },
                    else => unreachable, // the prong names these ten
                };
            },
            .to_datetime => |r| {
                const v = stack[sp - 1];
                stack[sp - 1] = if (r.iso_only) try dtf.parseIso(a, v, r.to) else try dtf.parseMixed(a, v, r.to, r.layouts);
            },
            .td_components => {
                const v = stack[sp - 1];
                if (v != .int) {
                    stack[sp - 1] = .null;
                    continue;
                }
                const comp = dtf.components(v.int);
                var vals: [7]Value = undefined;
                for (&vals, comp) |*o, x| o.* = .{ .int = x };
                stack[sp - 1] = try lf.makeRecord(a, &dtf.component_names, &vals);
            },
            .dt_combine => {
                stack[sp - 2] = dtf.combine(stack[sp - 2], stack[sp - 1]);
                sp -= 1;
            },
            .dt_replace => |mask| {
                const n_ops: usize = @popCount(mask);
                const base = sp - 1 - n_ops;
                var set: [7]?i64 = @splat(null);
                var ok = true;
                var at = base + 1;
                for (0..7) |k| {
                    if (mask & (@as(u8, 1) << @intCast(k)) == 0) continue;
                    if (stack[at] == .int) set[k] = stack[at].int else ok = false;
                    at += 1;
                }
                const x = stack[base];
                stack[base] = if (!ok or keys.isMissing(x)) .null else try dtf.replaceParts(a, x, set);
                sp = base + 1;
            },
            .tz_offset => |r| stack[sp - 1] = dtf.zoneOffset(stack[sp - 1], r.zone, r.kind),
            .is_business_day => |r| stack[sp - 1] = dtf.isBusinessDay(stack[sp - 1], r.mask, r.holidays),
            .normalize => |form| stack[sp - 1] = if (stack[sp - 1] == .text) .{ .text = try fnx.normalize(a, stack[sp - 1].text, form) } else .null,
            .list_set => |op| {
                stack[sp - 2] = try lf.setCell(a, stack[sp - 2], stack[sp - 1], op);
                sp -= 1;
            },
            .list_gather => |null_on_oob| {
                stack[sp - 2] = try lf.gatherCell(a, stack[sp - 2], stack[sp - 1], null_on_oob);
                sp -= 1;
            },
            .repeat_by => {
                stack[sp - 2] = try lf.repeatBy(a, stack[sp - 2], stack[sp - 1]);
                sp -= 1;
            },
            .list_to_struct => |names| stack[sp - 1] = try lf.toStruct(a, stack[sp - 1], names),
            .list_sample => |st| stack[sp - 1] = try lf.sampleCell(a, stack[sp - 1], st),
            .list_map => |m| {
                const v = stack[sp - 1];
                stack[sp - 1] = if (v == .list) try listMap(a, m, v.list, one_a, one) else .null;
            },
            .cat_code => |ci| {
                stack[sp] = switch (f.columnAt(ci)) {
                    .categorical => |cc| if (cc.codes.isValid(ri)) Value{ .int = cc.codes.values[ri] } else .null,
                    else => .null,
                };
                sp += 1;
            },
            .struct_op => |op| stack[sp - 1] = try lf.structCell(a, stack[sp - 1], op),
            .struct_fields => |m| {
                const v = stack[sp - 1];
                stack[sp - 1] = if (v == .record) try structFields(a, m, v.record, one_a, one) else .null;
            },
        }
    }
    return stack[0];
}

/// `list_eval` / `list_filter` for one list cell: `m.body` for every element, the elements
/// as column 0 of a one-column scope (row = the element's position in the list's storage).
/// The body's intermediates live in an arena that goes with the call, so a list of `n`
/// elements costs `n` bodies of the evaluator's budget (`max_eval_bytes`, `max_eval_work`,
/// which `a` counts) and holds nothing after it returns.
fn listMap(a: std.mem.Allocator, m: ListMap, l: ds.ListView, one_a: std.mem.Allocator, one: *std.ArrayList(u8)) Error!Value {
    const n = l.len();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ia = arena.allocator();
    const cols = [1]Column{m.elem};
    const data = [1]ColumnData{l.items.*};
    const scope: Frame = .{ .columns = &cols, .data = &data, .len = 0 };
    const stack = try ia.alloc(Value, m.body.stack);
    const out = try a.alloc(Value, n);
    defer a.free(out);
    var k: usize = 0;
    for (0..n) |i| {
        const r = try eval(ia, ia, one_a, m.body, scope, @as(usize, l.start) + i, stack, one);
        if (m.filter) {
            if (r == .bool and r.bool) {
                out[k] = l.get(i);
                k += 1;
            }
        } else {
            out[k] = r;
            k += 1;
        }
    }
    return lf.makeList(a, out[0..k]);
}

/// `struct_fields` for one record: the programs over the record's fields as columns (the
/// record's row), the output fields in `m.src` order.
fn structFields(a: std.mem.Allocator, m: StructFields, r: ds.RecordView, one_a: std.mem.Allocator, one: *std.ArrayList(u8)) Error!Value {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ia = arena.allocator();
    const scope: Frame = .{ .columns = m.cols, .data = r.fields.children, .len = r.fields.len };
    const vals = try a.alloc(Value, m.src.len);
    defer a.free(vals);
    for (vals, m.src) |*o, s| switch (s) {
        .pass => |i| o.* = r.get(i),
        .prog => |j| {
            const pr = m.progs[j];
            const stack = try ia.alloc(Value, pr.stack);
            o.* = try eval(ia, ia, one_a, pr, scope, r.row, stack, one);
        },
    };
    return lf.makeRecord(a, m.names, vals);
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

/// The temporal type `e` keeps, read from the column types it names, or null: the
/// cells of a timestamp, a duration and an int are all `.int`, so only the expression
/// tells them apart (polars' rules): `ts - ts` is a duration, `ts ± dur` and `dur + ts`
/// a timestamp, `dur ± dur`, `-dur`, `abs(dur)`, `dur * k`, `k * dur`, `dur / k` and
/// `dur // k` a duration; the `dt` functions that move an instant keep the input's
/// type; `strptime` gives what it parses to; `cast` its target; `if_else` and
/// `coalesce` a type all their branches share.
/// The inner columns a nested result declares: the source column's when the expression
/// is that column (or a cast or branch of it), else none (read by the storage alone).
fn nestedInner(f: Frame, e: *const Expr) []const Column {
    return switch (e.*) {
        .col => |name| if (f.columnIndex(name)) |ci| f.columns[ci].inner else &.{},
        .cast => |c| nestedInner(f, c.x),
        .if_else => |b| blk: {
            const t = nestedInner(f, b.then);
            break :blk if (t.len > 0) t else nestedInner(f, b.otherwise);
        },
        .list => |l| switch (l.op) {
            // A list of the same elements.
            .reverse, .sort, .unique, .drop_nulls, .slice, .head, .tail, .gather_every, .shift => nestedInner(f, l.x),
            // One element: a nested element declares its own inner columns.
            .get, .first, .last, .min, .max, .item => if (elementColumn(f, l.x)) |c| c.inner else &.{},
            else => &.{},
        },
        .list_set => |r| nestedInner(f, r.x),
        .list_gather => |r| nestedInner(f, r.x),
        .list_sample => |r| nestedInner(f, r.x),
        .list_filter => |r| nestedInner(f, r.x),
        .field => |r| if (fieldColumn(f, r.x, r.name)) |c| c.inner else &.{},
        .concat_list => |xs| for (xs) |*x| {
            const t = nestedInner(f, x);
            if (t.len > 0) break t;
        } else &.{},
        .split, .split_regex, .extract_all, .split_ws, .rsplit => &text_items,
        else => &.{},
    };
}

/// The element column of a list of text (the text functions' list results).
const text_items = [_]Column{.{ .name = "", .type = .text }};

/// The declared element column of the list `e` evaluates to, when its schema says.
fn elementColumn(f: Frame, e: *const Expr) ?Column {
    const inner = nestedInner(f, e);
    return if (inner.len == 1 and listTyped(f, e)) inner[0] else null;
}

/// Whether `e` is known to give a list (so `nestedInner(e)` names its element).
fn listTyped(f: Frame, e: *const Expr) bool {
    return switch (e.*) {
        .col => |name| f.columnType(name) == .list,
        .cast => |c| c.to == .list,
        .list => |l| switch (l.op) {
            .reverse, .sort, .unique, .drop_nulls, .slice, .head, .tail, .gather_every, .shift => listTyped(f, l.x),
            .get, .first, .last, .min, .max, .item => if (elementColumn(f, l.x)) |c| c.type == .list else false,
            else => false,
        },
        .list_set => |r| listTyped(f, r.x),
        .list_gather => |r| listTyped(f, r.x),
        .list_sample => |r| listTyped(f, r.x),
        .list_filter => |r| listTyped(f, r.x),
        .repeat_by, .list_eval => true,
        .field => |r| if (fieldColumn(f, r.x, r.name)) |c| c.type == .list else false,
        .split, .split_regex, .extract_all, .concat_list, .split_ws, .rsplit => true,
        else => false,
    };
}

/// The declared column of field `name` of the struct `e` evaluates to, when its schema says.
fn fieldColumn(f: Frame, e: *const Expr, name: []const u8) ?Column {
    const struct_typed = switch (e.*) {
        .col => |n| f.columnType(n) == .@"struct",
        else => false,
    };
    if (!struct_typed) return null;
    for (nestedInner(f, e)) |c| if (std.mem.eql(u8, c.name, name)) return c;
    return null;
}

/// Whether a `dt` part reads the wall clock (so a zoned column converts first); the epoch and
/// duration parts are the instant's own.
fn localPart(p: dtf.DtPart) bool {
    return switch (p) {
        .epoch_days, .epoch_seconds, .epoch_ms, .epoch_us, .total_days, .total_hours, .total_minutes, .total_seconds, .total_milliseconds, .total_microseconds, .total_seconds_f64, .td_days, .td_seconds, .td_microseconds, .td_nanoseconds => false,
        else => true,
    };
}

/// The time zone the timestamp `e` evaluates to carries (the same instants shown in a zone),
/// or null for a naive one or one that is not a timestamp. Statically known, like
/// `temporalType`: a column's `time_zone`, the target of `convert_time_zone`,
/// `replace_time_zone` or a zoned `cast`, and the operand's zone through the arithmetic and
/// selection that keep an instant an instant. `to_local`/`from_local` give naive wall clocks
/// and instants of no zone.
fn zoneOf(f: Frame, e: *const Expr) ?[]const u8 {
    return switch (e.*) {
        .col => |name| blk: {
            const i = f.columnIndex(name) orelse break :blk null;
            break :blk if (f.columns[i].type == .timestamp) f.columns[i].time_zone else null;
        },
        // The element of a `list_eval` body is column 0 of its one-column scope (outside one,
        // `go` has already refused `.element`).
        .element => if (f.columns.len == 1 and f.columns[0].type == .timestamp) f.columns[0].time_zone else null,
        .cast => |c| if (c.to == .timestamp) c.zone else null,
        .convert_time_zone => |r| r.zone,
        .replace_time_zone => |r| r.zone,
        .offset_by => |r| zoneOf(f, r.x),
        .truncate => |r| zoneOf(f, r.x),
        .add_business_days => |r| zoneOf(f, r.x),
        .dt_replace => |r| zoneOf(f, r.x),
        .binary => |b| switch (b.op) {
            .add => if (temporalType(f, b.l) == .timestamp) zoneOf(f, b.l) else zoneOf(f, b.r),
            .sub => if (temporalType(f, b.l) == .timestamp and temporalType(f, b.r) == .duration) zoneOf(f, b.l) else null,
            .min, .max => zoneOf(f, b.l) orelse zoneOf(f, b.r),
            else => null,
        },
        .if_else => |c| zoneOf(f, c.then) orelse zoneOf(f, c.otherwise),
        .coalesce => |xs| blk: {
            for (xs) |*x| if (zoneOf(f, x)) |z| break :blk z;
            break :blk null;
        },
        else => null,
    };
}

fn temporalType(f: Frame, e: *const Expr) ?ColumnType {
    return switch (e.*) {
        .col => |name| switch (f.columnType(name) orelse return null) {
            .timestamp, .duration, .date => |t| t,
            else => null,
        },
        .cast => |c| switch (c.to) {
            .timestamp, .duration, .date => c.to,
            else => null,
        },
        .strptime => |r| switch (r.to) {
            .date => .date,
            .timestamp => .timestamp,
        },
        .offset_by => |r| temporalType(f, r.x),
        .truncate => |r| temporalType(f, r.x),
        .add_business_days => |r| temporalType(f, r.x),
        .make_date => .date,
        .make_datetime => .timestamp,
        .make_duration => .duration,
        .from_epoch => |r| if (r.unit == .day) .date else .timestamp,
        .to_datetime => |r| if (r.to == .date) .date else .timestamp,
        .dt_combine => .timestamp,
        .dt_replace => |r| temporalType(f, r.x),
        .tz_offset => .duration,
        .to_local => |r| temporalType(f, r.x),
        .from_local => |r| temporalType(f, r.x),
        .convert_time_zone => |r| temporalType(f, r.x),
        .replace_time_zone => |r| temporalType(f, r.x),
        // An element or a field keeps the temporal type its schema declares.
        .list => |l| switch (l.op) {
            .get, .first, .last, .min, .max, .item => if (elementColumn(f, l.x)) |c| temporalOf(c.type) else null,
            else => null,
        },
        .field => |r| if (fieldColumn(f, r.x, r.name)) |c| temporalOf(c.type) else null,
        .unary => |u| switch (u.op) {
            .neg, .abs => if (temporalType(f, u.x) == .duration) .duration else null,
            else => null,
        },
        .binary => |b| blk: {
            const l = temporalType(f, b.l);
            const r = temporalType(f, b.r);
            break :blk switch (b.op) {
                .sub => if (l == .timestamp and r == .timestamp)
                    .duration
                else if (l == .timestamp and r == .duration)
                    .timestamp
                else if (l == .duration and r == .duration) .duration else null,
                .add => if ((l == .timestamp and r == .duration) or (l == .duration and r == .timestamp))
                    .timestamp
                else if (l == .duration and r == .duration) .duration else null,
                .mul => if ((l == .duration and r == null) or (l == null and r == .duration)) .duration else null,
                .div, .floordiv => if (l == .duration and r == null) .duration else null,
                .min, .max => if (l != null and l == r) l else null,
                else => null,
            };
        },
        .if_else => |c| blk: {
            const t = temporalType(f, c.then) orelse break :blk null;
            break :blk if (temporalType(f, c.otherwise) == t) t else null;
        },
        .coalesce => |xs| blk: {
            if (xs.len == 0) break :blk null;
            const t = temporalType(f, &xs[0]) orelse break :blk null;
            for (xs[1..]) |*x| if (temporalType(f, x) != t) break :blk null;
            break :blk t;
        },
        else => null,
    };
}

fn temporalOf(t: ColumnType) ?ColumnType {
    return switch (t) {
        .timestamp, .duration, .date => t,
        else => null,
    };
}

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
    /// Tests only: replaces `max_eval_bytes`.
    pub var eval_limit: ?usize = null;
    /// Tests only: replaces `max_eval_work`.
    pub var eval_work_limit: ?usize = null;
    pub const keyLen = expr_keyLen;
    pub fn mutateCells(a: std.mem.Allocator, f: Frame, assigns: []const Assign) Error!Frame {
        var cur = f;
        for (assigns) |as| cur = try mutateOne(a, cur, as, false);
        return cur;
    }
};

const expr_containsShort = containsShort;
const expr_keyLen = keyLen;

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
    var any_list = false;
    var any_record = false;
    var bud = Budget.init(a);
    var row = RowScratch.init(&bud);
    defer row.deinit();
    for (vals, 0..) |*o, ri| {
        var v = try keepRow(&bud, &row, try evalBudget(&bud, &row, p, f, ri, stack, &one));
        if (as.type) |ty| {
            if (!keys.isMissing(v)) v = castValue(bud.allocator(), v, ty) catch |e| return if (e == error.OutOfMemory and bud.hit) error.TooLarge else e;
        } else switch (v) {
            .int => any_int = true,
            .float => |x| any_float = any_float or !std.math.isNan(x),
            .decimal => any_decimal = true,
            .text => any_text = true,
            .bool => any_bool = true,
            .list => any_list = true,
            .record => any_record = true,
            .null => {},
        }
        o.* = v;
    }
    const kinds = @as(u8, @intFromBool(any_int)) + @intFromBool(any_float) + @intFromBool(any_decimal) + @intFromBool(any_text) + @intFromBool(any_bool) + @intFromBool(any_list) + @intFromBool(any_record);
    if (kinds > 1 and (any_text or any_bool or any_list or any_record)) return error.BadExpr;
    if (any_list or any_record or (as.type != null and (as.type.? == .list or as.type.? == .@"struct"))) {
        // Nested cells, carried over (a column, a branch of `if_else`): the column is
        // their kind, its declared inner columns the source's where the expression names one.
        cols[at] = .{ .name = as.out, .type = as.type orelse if (any_list) .list else .@"struct", .inner = nestedInner(f, &as.expr) };
        const data = try a.alloc(ColumnData, width);
        for (data[0..f.columns.len], 0..) |*d, ci| d.* = f.columnAt(ci);
        data[at] = try fm.columnFromCells(a, vals);
        return .{ .columns = cols, .data = data, .len = f.len };
    }
    var ty: ColumnType = as.type orelse if (any_text) .text else if (any_bool) .bool else if (any_float) .float else if (any_decimal) .decimal else if (any_int) .int else .float;
    // An instant or a length of time kept by the expression (its cells are ints or
    // ISO text like any other): the column says so, as polars' does.
    if (as.type == null) if (temporalType(f, &as.expr)) |t| {
        const fits = if (t == .date) !(any_int or any_float or any_decimal or any_bool) else !(any_text or any_bool or any_decimal);
        if (fits) {
            ty = t;
            // `dur / 2` evaluates to a float: whole microseconds, as polars truncates.
            if (t != .date and any_float) for (vals) |*c| {
                c.* = if (keys.isMissing(c.*)) .null else c.cast(t) orelse .null;
            };
            cols[at] = .{ .name = as.out, .type = ty, .time_zone = if (ty == .timestamp) zoneOf(f, &as.expr) else null };
            const data = try a.alloc(ColumnData, width);
            for (data[0..f.columns.len], 0..) |*d, ci| d.* = f.columnAt(ci);
            data[at] = try fm.columnFromCells(a, vals);
            return .{ .columns = cols, .data = data, .len = f.len };
        }
    };
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
    if (ty == .categorical) data[at] = try fm.encodeCategorical(a, data[at], f.len);
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
    var bud = Budget.init(a);
    var row = RowScratch.init(&bud);
    defer row.deinit();
    for (0..f.len) |ri| {
        const v = try evalBudget(&bud, &row, p, f, ri, stack, &one);
        row.endRow(); // the condition is a bool: nothing of the row is kept
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
    /// With `to = .timestamp`: the zone the result carries, polars
    /// `cast(Datetime("us", time_zone=...))`: the cells stay the same UTC instants (see
    /// `Expr.cast`). Null gives a naive column, also from a zoned one, again the same
    /// instants (polars strips the zone and keeps UTC). Another `to` with a zone, or an
    /// unknown zone, is `error.BadExpr`.
    zone: ?[]const u8 = null,
    /// With `to = .categorical`: the category list, in order (polars `Enum(categories)`,
    /// pandas `CategoricalDtype(categories)`). The dictionary is this list, not the observed
    /// values: it keeps categories no row uses, and the order is the list's. A cell that is
    /// no category is null with `on_error = .null` (polars `strict=False`, pandas `astype`)
    /// and `error.CastFailed` with `.fail` (polars' strict `cast`, which raises). A name
    /// twice, or a list with `to` not `.categorical`, is `error.BadExpr`.
    categories: ?[]const []const u8 = null,
    /// With `to = .categorical`: pandas `ordered=True`, polars `Enum` (always ordered).
    /// Without `categories` the dictionary is the observed values, lexically ordered.
    ordered: bool = false,
};

pub const CastError = Error || error{CastFailed};

/// Convert one column by `castValue`'s rule, the declared type following.
pub fn cast(a: std.mem.Allocator, f: Frame, spec: CastSpec) CastError!Frame {
    const ci = f.columnIndex(spec.col) orelse return error.NoSuchColumn;
    const cols = try a.dupe(Column, f.columns);
    cols[ci].type = spec.to;
    if (spec.to != f.columns[ci].type) cols[ci].inner = &.{};
    // A zone names the column's instants: a cast to a timestamp sets it (null: naive), any
    // other target has none.
    if (spec.zone) |zn| if (spec.to != .timestamp or tz.find(zn) == null) return error.BadExpr;
    if (spec.ordered and spec.to != .categorical) return error.BadExpr;
    cols[ci].time_zone = spec.zone;
    const vals = try a.alloc(Value, f.len);
    defer a.free(vals);
    const col = f.columnAt(ci);
    const from = f.columns[ci].type;
    // An instant or a length of time to text is its ISO form, not its microseconds.
    const iso_text = (from == .timestamp or from == .duration) and (spec.to == .text or spec.to == .categorical);
    for (vals, 0..) |*o, ri| {
        const src = col.get(ri);
        const v = if (iso_text and src == .int) blk: {
            var buf: [@max(ds.max_iso_timestamp_len, ds.max_duration_len)]u8 = undefined;
            const t = if (from == .timestamp) ds.formatIsoTimestamp(buf[0..ds.max_iso_timestamp_len], src.int) else ds.formatIsoDuration(buf[0..ds.max_duration_len], src.int);
            break :blk Value{ .text = try a.dupe(u8, t) };
        } else if (src.isNested() and (spec.to == .text or spec.to == .categorical)) blk: {
            // Its JSON, written with the column's schema (an instant inside stays RFC 3339).
            var out: std.Io.Writer.Allocating = .init(a);
            defer out.deinit();
            jsonio.writeValue(&out.writer, src, f.columns[ci], 0) catch return error.OutOfMemory; // an Allocating writer fails only so
            break :blk Value{ .text = try out.toOwnedSlice() };
        } else try castValue(a, src, spec.to);
        if (spec.on_error == .fail and v == .null and !keys.isMissing(src)) return error.CastFailed;
        o.* = v;
    }
    const data = try a.alloc(ColumnData, cols.len);
    for (data, 0..) |*d, i| d.* = f.columnAt(i);
    data[ci] = try fm.columnFromCells(a, vals);
    if (spec.to == .categorical) {
        if (spec.categories) |cats| {
            const enc = catfn.encodeWith(a, data[ci], f.len, cats, spec.ordered) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.TooLarge => error.TooLarge,
                else => error.BadExpr, // a category twice
            };
            if (enc.lost and spec.on_error == .fail) return error.CastFailed;
            data[ci] = enc.data;
        } else {
            data[ci] = try fm.encodeCategorical(a, data[ci], f.len);
            if (spec.ordered) switch (data[ci]) {
                .categorical => |*c| c.ordered = true,
                else => {},
            };
        }
    } else if (spec.categories != null) return error.BadExpr;
    return .{ .columns = cols, .data = data, .len = f.len };
}

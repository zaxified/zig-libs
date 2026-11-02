// SPDX-License-Identifier: MIT
//! Row expressions: `mutate` (dplyr `mutate`, pandas `assign`, polars
//! `with_columns`), `where` (filter by a nested predicate) and `cast` (the coercion
//! rules in one place). An `Expr` tree is compiled once to a flat stack program, so
//! a row costs no name lookup and no recursion; compiling is where a cyclic or too
//! deep tree is refused.
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
const ds = @import("dataset");
const keys = @import("keys.zig");
const Dataset = ds.Dataset;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

pub const Error = error{
    NoSuchColumn,
    OutOfMemory,
    /// The tree is deeper than `max_depth` (or cyclic), or wider than `max_nodes`.
    ExprTooLarge,
    /// A `.binary`/`.unary` given where the operator wants the other arity, or a
    /// result column name given twice.
    BadExpr,
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
};

const Program = struct {
    code: []const Inst,
    stack: usize,
};

const Compiler = struct {
    a: std.mem.Allocator,
    d: Dataset,
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
            .col => |name| try c.push(.{ .col = c.d.columnIndex(name) orelse return error.NoSuchColumn }, 0),
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
        }
    }
};

fn compile(a: std.mem.Allocator, d: Dataset, e: *const Expr) Error!Program {
    var c: Compiler = .{ .a = a, .d = d };
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
        else => {},
    }
    if (keys.isMissing(v)) return .null;
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
        else => {},
    }
    if (keys.isMissing(l) or keys.isMissing(r)) return .null;
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
                .contains => .{ .bool = std.mem.indexOf(u8, l.text, r.text) != null },
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
                return .{ .int = @mod(x, y) };
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

/// The one cast rule, for `Expr.cast` and the `cast` verb. Null when it cannot be
/// converted; a missing cell stays null. Beyond `Value.cast`: text parses to int,
/// float and bool ("true"/"false", any case), anything prints to text (`{d}`, bool
/// as "true"/"false"), bool counts as 0/1. Text to `.decimal` is null here: parsing
/// money is `numparse`'s, with its locale rules, and this module does not pull it in.
pub fn castValue(a: std.mem.Allocator, v: Value, to: ColumnType) Error!Value {
    if (keys.isMissing(v)) return .null;
    switch (to) {
        .text, .date => switch (v) {
            .text => return v,
            .int => |i| return .{ .text = try a.print("{d}", .{i}) },
            .float => |f| return .{ .text = try a.print("{d}", .{f}) },
            .bool => |b| return .{ .text = if (b) "true" else "false" },
            .decimal => return .{ .text = try a.print("{d}", .{v.asFloat().?}) },
            .null => return .null,
        },
        .int => switch (v) {
            .bool => |b| return .{ .int = @intFromBool(b) },
            .text => |t| {
                const s = std.mem.trim(u8, t, " \t");
                if (std.fmt.parseInt(i64, s, 10)) |i| return .{ .int = i } else |_| {}
                const f = std.fmt.parseFloat(f64, s) catch return .null;
                return if (Value.floatToInt(i64, f)) |i| .{ .int = i } else .null;
            },
            else => {},
        },
        .float => switch (v) {
            .bool => |b| return .{ .float = @floatFromInt(@intFromBool(b)) },
            .text => |t| return .{ .float = std.fmt.parseFloat(f64, std.mem.trim(u8, t, " \t")) catch return .null },
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

/// Run the program on one row. `stack` has `Program.stack` slots; `one` is a reusable
/// key buffer.
fn eval(a: std.mem.Allocator, p: Program, row: []const Value, stack: []Value, one: *std.ArrayList(u8)) Error!Value {
    var sp: usize = 0;
    for (p.code) |inst| {
        switch (inst) {
            .col => |ci| {
                stack[sp] = row[ci];
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
        }
    }
    return stack[0];
}

pub const Assign = struct {
    out: []const u8,
    expr: Expr,
    /// The output column's declared type; null infers it from the first non-missing
    /// result (`.float` when there is none).
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
/// input, a one-assignment-per-call there). Replacing keeps the column's position.
pub fn mutate(a: std.mem.Allocator, d: Dataset, assigns: []const Assign) Error!Dataset {
    var cur = d;
    for (assigns) |as| cur = try mutateOne(a, cur, as);
    return cur;
}

fn mutateOne(a: std.mem.Allocator, d: Dataset, as: Assign) Error!Dataset {
    const p = try compile(a, d, &as.expr);
    const existing = d.columnIndex(as.out);
    const width = if (existing == null) d.columns.len + 1 else d.columns.len;
    const at = existing orelse d.columns.len;
    const cols = try a.alloc(Column, width);
    @memcpy(cols[0..d.columns.len], d.columns);
    const rows = try a.alloc([]const Value, d.rows.len);
    const cells = try a.alloc(Value, d.rows.len * width);
    const stack = try a.alloc(Value, p.stack);
    defer a.free(stack);
    var one: std.ArrayList(u8) = .empty;
    defer one.deinit(a);
    var inferred: ?ColumnType = as.type;
    for (d.rows, 0..) |r, ri| {
        const nr = cells[ri * width ..][0..width];
        const v = try eval(a, p, r, stack, &one);
        @memcpy(nr[0..d.columns.len], r);
        nr[at] = v;
        if (inferred == null and !keys.isMissing(v)) inferred = typeOf(v);
        rows[ri] = nr;
    }
    cols[at] = .{ .name = as.out, .type = inferred orelse .float };
    return .{ .columns = cols, .rows = rows };
}

/// Keep the rows where `e` is true: nested AND/OR/NOT, column against column,
/// anything `Expr` can say. A null condition drops the row. Rows are borrowed.
pub fn where(a: std.mem.Allocator, d: Dataset, e: *const Expr) Error!Dataset {
    const p = try compile(a, d, e);
    const stack = try a.alloc(Value, p.stack);
    defer a.free(stack);
    var one: std.ArrayList(u8) = .empty;
    defer one.deinit(a);
    var kept: std.ArrayList([]const Value) = .empty;
    try kept.ensureTotalCapacityPrecise(a, d.rows.len);
    for (d.rows) |r| {
        const v = try eval(a, p, r, stack, &one);
        if (v == .bool and v.bool) kept.appendAssumeCapacity(r);
    }
    return .{ .columns = d.columns, .rows = try kept.toOwnedSlice(a) };
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
pub fn cast(a: std.mem.Allocator, d: Dataset, spec: CastSpec) CastError!Dataset {
    const ci = d.columnIndex(spec.col) orelse return error.NoSuchColumn;
    const cols = try a.dupe(Column, d.columns);
    cols[ci].type = spec.to;
    const rows = try a.alloc([]const Value, d.rows.len);
    const cells = try a.alloc(Value, d.rows.len * cols.len);
    for (d.rows, 0..) |r, ri| {
        const nr = cells[ri * cols.len ..][0..cols.len];
        @memcpy(nr, r);
        const v = try castValue(a, r[ci], spec.to);
        if (spec.on_error == .fail and v == .null and !keys.isMissing(r[ci])) return error.CastFailed;
        nr[ci] = v;
        rows[ri] = nr;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

fn col(n: []const u8) Expr {
    return .{ .col = n };
}

test "mutate: int stays int, overflow is null, div is float, later sees earlier" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "x", .type = .int }, .{ .name = "y", .type = .int } };
    const rows = [_][]const Value{
        &.{ .{ .int = 7 }, .{ .int = 2 } },
        &.{ .{ .int = std.math.maxInt(i64) }, .{ .int = 1 } },
        &.{ .null, .{ .int = 1 } },
    };
    const x = col("x");
    const y = col("y");
    const sum: Expr = .{ .binary = .{ .op = .add, .l = &x, .r = &y } };
    const quot: Expr = .{ .binary = .{ .op = .div, .l = &x, .r = &y } };
    const s = col("s");
    const dbl: Expr = .{ .binary = .{ .op = .mul, .l = &s, .r = &.{ .lit = .{ .int = 2 } } } };
    const o = try mutate(a, .{ .columns = &cols, .rows = &rows }, &.{
        .{ .out = "s", .expr = sum },
        .{ .out = "q", .expr = quot },
        .{ .out = "d", .expr = dbl },
    });
    try testing.expectEqual(@as(i64, 9), o.rows[0][2].int);
    try testing.expectEqual(ColumnType.int, o.columns[2].type);
    try testing.expectEqual(@as(f64, 3.5), o.rows[0][3].float);
    try testing.expectEqual(@as(i64, 18), o.rows[0][4].int);
    try testing.expect(o.rows[1][2] == .null); // not a wrapped negative
    try testing.expect(o.rows[2][2] == .null);
    try testing.expect(o.rows[2][3] == .null);
}

test "where: Kleene logic, column vs column, is_in, nested not" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "x", .type = .float }, .{ .name = "y", .type = .float }, .{ .name = "t", .type = .text } };
    const rows = [_][]const Value{
        &.{ .{ .float = 1 }, .{ .float = 2 }, .{ .text = "a" } },
        &.{ .{ .float = 3 }, .{ .float = 2 }, .{ .text = "b" } },
        &.{ .null, .{ .float = 2 }, .{ .text = "a" } },
        &.{ .{ .float = std.math.nan(f64) }, .{ .float = 2 }, .{ .text = "c" } },
    };
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    const x = col("x");
    const y = col("y");
    const t = col("t");
    const lt: Expr = .{ .binary = .{ .op = .lt, .l = &x, .r = &y } };
    const in_a: Expr = .{ .is_in = .{ .x = &t, .values = &.{.{ .text = "a" }} } };
    // null < 2 is unknown; unknown OR true is true, unknown AND true is unknown.
    const orr: Expr = .{ .binary = .{ .op = .@"or", .l = &lt, .r = &in_a } };
    try testing.expectEqual(@as(usize, 2), (try where(a, d, &orr)).rows.len);
    const andd: Expr = .{ .binary = .{ .op = .@"and", .l = &lt, .r = &in_a } };
    try testing.expectEqual(@as(usize, 1), (try where(a, d, &andd)).rows.len);
    const notlt: Expr = .{ .unary = .{ .op = .not, .x = &lt } };
    try testing.expectEqual(@as(usize, 1), (try where(a, d, &notlt)).rows.len); // only x=3
}

test "compile: a cyclic or too deep tree is an error, not a stack overflow" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "x", .type = .int }};
    const rows = [_][]const Value{&.{.{ .int = 1 }}};
    const d: Dataset = .{ .columns = &cols, .rows = &rows };
    var cyc: Expr = undefined;
    cyc = .{ .unary = .{ .op = .neg, .x = &cyc } };
    try testing.expectError(error.ExprTooLarge, mutate(a, d, &.{.{ .out = "o", .expr = cyc }}));
    try testing.expectError(error.NoSuchColumn, where(a, d, &.{ .col = "zz" }));
    try testing.expectError(error.BadExpr, where(a, d, &.{ .coalesce = &.{} }));
}

test "cast: the rule table" {
    const a = testing.allocator;
    try testing.expectEqual(@as(i64, 12), (try castValue(a, .{ .text = " 12 " }, .int)).int);
    try testing.expectEqual(@as(i64, 12), (try castValue(a, .{ .text = "12.9" }, .int)).int);
    try testing.expectEqual(@as(f64, 1.5), (try castValue(a, .{ .text = "1.5" }, .float)).float);
    try testing.expect((try castValue(a, .{ .text = "x" }, .float)) == .null);
    try testing.expect((try castValue(a, .{ .float = 1e300 }, .int)) == .null);
    try testing.expect((try castValue(a, .{ .float = std.math.nan(f64) }, .int)) == .null);
    try testing.expectEqual(true, (try castValue(a, .{ .text = "TRUE" }, .bool)).bool);
    try testing.expectEqual(@as(i64, 1), (try castValue(a, .{ .bool = true }, .int)).int);
    try testing.expectEqualStrings("false", (try castValue(a, .{ .bool = false }, .text)).text);
    const s = try castValue(a, .{ .int = 42 }, .text);
    defer a.free(s.text);
    try testing.expectEqualStrings("42", s.text);
}

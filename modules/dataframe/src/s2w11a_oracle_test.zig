// SPDX-License-Identifier: MIT
//! Replays `oracle2j_vectors.json` (dataframe S2 wave W11, real dtype widths) for the kinds the
//! computing half of the wave owns: `supertype` (arithmetic of two typed columns), `overflow`,
//! `weak_literal`, `unary`, `aggregate`, `group_agg`, `combine` and `supertype_concat`. The vectors
//! are what polars 2.1 answered (`tools/oracle2j.py` asked the engine; no line of this module is
//! consulted there); the pandas cases are not replayed (the module follows polars). Every difference
//! is a `known` entry with its reason: by case (`known`), by type (`typeKnown`) or by cell
//! (`cellKnown`: an overflow that polars wraps, a NaN that is missing here, the f32 ulp).
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const dtype = @import("dtype.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const Expr = df.Expr;
const J = std.json.Value;

const vectors = @embedFile("oracle2j_vectors.json");

/// Deliberate differences from what polars answered, by case: id substring and why.
const Known = struct { id: []const u8, why: []const u8 };
const known = [_]Known{
    .{ .id = "ag-mode-", .why = "polars' `mode` returns every value tied for the most frequent; `aggregate` `mode` one of them (the first seen), its rule before W11" },
    .{ .id = "ag-first-", .why = "polars' `first` keeps a leading null; the module's `first` skips missing cells under `skip_na`, its rule before W11" },
    .{ .id = "ag-last-", .why = "polars' `last` keeps a trailing null; the module's `last` skips missing cells under `skip_na`, its rule before W11" },
};

/// A type of ours that is not the type polars answered, by case.
fn typeKnown(id: []const u8, op: []const u8, want: []const u8, got: ColumnType) ?[]const u8 {
    if (std.mem.eql(u8, want, "f64") and got == .int and std.mem.find(u8, id, "concat-i64-f64") != null)
        return "`concatByName` of Int64 with Float64 pieces declares the first frame's type, its rule before W11 (`mut_mb_test`, `structure_test`); only a width piece meets the other in the supertype";
    if (std.mem.eql(u8, want, "i128")) return if (got == .float) "polars' Int128 (Int64 or a narrower signed type with UInt64) has no equivalent here: Float64 (D5)" else null;
    if (std.mem.eql(u8, want, "u32") and got == .int) return "`n_unique` is Int64 here (polars UInt32), its type before W11";
    if (std.mem.eql(u8, want, "i64") and got == .float) {
        if (std.mem.eql(u8, op, "mod0") or std.mem.eql(u8, op, "floordiv0")) return "an Int64 column modulo or divided by 0 is all null here, a column the cells type as Float64: unchanged since before W11";
        if (std.mem.find(u8, id, "-u64-") != null or std.mem.find(u8, id, "u64-pl") != null) return "polars casts a UInt64 with a negative literal to Int64 (lossy); here Float64, the supertype of Int64 and UInt64 (D5, D6)";
        if (std.mem.eql(u8, op, "sum") or std.mem.eql(u8, op, "product")) return "`aggregate` sum / prod of an Int64 column is Float64 in this module since before W11 (SPEC backlog: int sum stays int); the narrow widths follow polars";
        if (std.mem.eql(u8, op, "sign") or std.mem.eql(u8, op, "pow2")) return "`sign` and `pow` of an Int64 column are Float64 in this module since before W11; the narrow widths keep their type";
        if (std.mem.eql(u8, op, "cum_sum") or std.mem.eql(u8, op, "cum_prod") or std.mem.eql(u8, op, "diff")) return "a window verb over an Int64 column is Int64 when every cell is an int: unchanged";
    }
    if (std.mem.eql(u8, want, "f32") and got == .float and std.mem.eql(u8, op, "rank")) return null;
    return null;
}

/// A single cell of ours that is not polars': the reason, or null.
fn cellKnown(c: J, row: usize, id: []const u8, op: []const u8, dout: []const u8, want: J, got: Value, ty: ColumnType, exact_fits: ?bool) ?[]const u8 {
    if (want == .string and std.mem.eql(u8, want.string, "nan") and got == .null) return "NaN is missing here, the module's one rule";
    if (got == .null and want != .null and dtype.isInteger(ty) and exact_fits != null and !exact_fits.?)
        return "an integer outside the type's range is null here, where polars wraps (D5)";
    if (std.mem.eql(u8, op, "n_unique") and std.mem.find(u8, id, "-null-") != null)
        return "polars counts a null as one more distinct value; `aggregate` skips missing cells under `skip_na`";
    if ((std.mem.eql(u8, op, "std") or std.mem.eql(u8, op, "var")) and want == .string and std.mem.eql(u8, want.string, "nan") and got == .float and std.math.isInf(got.float))
        return "a variance past the f64 range is infinity here (Welford), NaN in polars";
    if ((std.mem.eql(u8, op, "sign") or std.mem.eql(u8, op, "pow0.5")) and want == .float and want.float == 0 and got.asFloat() != null and got.asFloat().? == 0)
        return "the sign of a negative zero: `sign(-0.0)` and `pow(-0.0, 0.5)` give +0.0 here (IEEE `pow`), -0.0 in polars";
    if (std.mem.eql(u8, op, "mod") and (std.mem.eql(u8, dout, "f32") or std.mem.eql(u8, dout, "f64"))) {
        const col = c.object.get("in").?.object.get("a").?;
        const x = col.object.get("values").?.array.items[row];
        const mag: f64 = switch (x) {
            .float => |f| @abs(f),
            .integer => |i| @abs(@as(f64, @floatFromInt(i))),
            else => 0,
        };
        if (mag >= 1e30) return "polars' float `%` is `a - floor(a / b) * b`: for a quotient this large it overflows to inf or loses every digit (0); here the exact remainder with the divisor's sign";
    }
    if (std.mem.eql(u8, op, "diff") and std.mem.eql(u8, dout, "i64") and want == .null and got != .null)
        return "polars casts a UInt64 to Int64 before `diff` (null above maxInt(i64)); here the exact difference";
    return null;
}

fn typeOf(name: []const u8) ?ColumnType {
    const map = [_]struct { []const u8, ColumnType }{
        .{ "i8", .int8 },     .{ "i16", .int16 },  .{ "i32", .int32 },  .{ "i64", .int },
        .{ "u8", .uint8 },    .{ "u16", .uint16 }, .{ "u32", .uint32 }, .{ "u64", .uint64 },
        .{ "f32", .float32 }, .{ "f64", .float },  .{ "bool", .bool },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], name)) return m[1];
    return null;
}

/// What a polars dtype name is here: its type, Int128 as Float64 (the supertype's stand-in).
fn wantType(name: []const u8) ?ColumnType {
    if (std.mem.eql(u8, name, "i128")) return .float;
    return typeOf(name);
}

fn strOf(o: J, k: []const u8) []const u8 {
    return o.object.get(k).?.string;
}

fn jcell(j: J, ty: ColumnType) Value {
    return switch (j) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| if (dtype.isFloat(ty)) .{ .float = @floatFromInt(i) } else .{ .int = i },
        .float => |x| .{ .float = x },
        .number_string => |s| dtype.intValue(std.fmt.parseInt(i128, s, 10) catch unreachable).?, // the oracle writes only integers so
        .string => |s| if (dtype.isFloat(ty)) .{ .float = std.fmt.parseFloat(f64, s) catch unreachable } else .{ .text = s },
        else => unreachable, // the oracle writes no other cell
    };
}

fn cellText(a: std.mem.Allocator, j: J) []const u8 {
    return switch (j) {
        .string => |s| s,
        .integer => |i| a.print("{d}", .{i}) catch "?",
        .float => |x| a.print("{d}", .{x}) catch "?",
        .number_string => |s| s,
        .bool => |b| if (b) "true" else "false",
        .null => "null",
        else => "?",
    };
}

fn exactOf(j: J) ?i128 {
    return switch (j) {
        .integer => |i| i,
        .number_string => |s| std.fmt.parseInt(i128, s, 10) catch null,
        else => null,
    };
}

const Tally = struct {
    run: usize = 0,
    cells: usize = 0,
    known_cells: usize = 0,
    known_cases: usize = 0,
    bad: usize = 0,
    out: std.Io.Writer.Allocating,

    fn miss(t: *Tally, comptime fmt: []const u8, args: anytype) void {
        t.bad += 1;
        if (t.bad <= 300) t.out.writer.print(fmt ++ "\n", args) catch {};
    }
};

fn knownCase(id: []const u8) bool {
    for (known) |k| if (std.mem.find(u8, id, k.id) != null) return true;
    return false;
}

fn column(a: std.mem.Allocator, name: []const u8, ty: ColumnType, vals: []const J) !struct { Column, []const Value } {
    const cells = try a.alloc(Value, vals.len);
    for (cells, vals) |*c, j| c.* = jcell(j, ty);
    return .{ .{ .name = name, .type = ty }, cells };
}

/// A frame of the named input columns of a case (`a`, `b`, `k`).
fn frameOfCase(a: std.mem.Allocator, input: J, with_cond: bool) !?Frame {
    var names: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "k", "a", "b" }) |n| if (input.object.get(n) != null) try names.append(a, n);
    const cols = try a.alloc(Column, names.items.len + @intFromBool(with_cond));
    const cells = try a.alloc([]const Value, cols.len);
    var rows: usize = 0;
    for (names.items, cols[0..names.items.len], cells[0..names.items.len]) |n, *c, *cs| {
        const col = input.object.get(n).?;
        const ty = typeOf(strOf(col, "dtype")) orelse return null;
        const r = try column(a, n, ty, col.object.get("values").?.array.items);
        c.* = r[0];
        cs.* = r[1];
        rows = r[1].len;
    }
    if (with_cond) {
        // The oracle's condition: True, False, True, False.
        const cond = try a.alloc(Value, rows);
        for (cond, 0..) |*x, i| x.* = .{ .bool = i % 2 == 0 };
        cols[cols.len - 1] = .{ .name = "c", .type = .bool };
        cells[cells.len - 1] = cond;
    }
    var b = try fm.FrameBuilder.init(a, cols, rows);
    const row = try a.alloc(Value, cols.len);
    for (0..rows) |ri| {
        for (cells, row) |cs, *o| o.* = cs[ri];
        try b.appendRow(row);
    }
    return try b.toOwned();
}

fn bx(a: std.mem.Allocator, e: Expr) !*const Expr {
    const p = try a.create(Expr);
    p.* = e;
    return p;
}

fn colX(a: std.mem.Allocator, name: []const u8) !*const Expr {
    return bx(a, .{ .col = name });
}

const Out = struct { type: ColumnType, cells: []const Value, std_ok: bool };

fn column0(a: std.mem.Allocator, g: Frame, name: []const u8) !Out {
    const ci = g.columnIndex(name).?;
    const cells = try a.alloc(Value, g.len);
    for (cells, 0..) |*c, i| c.* = g.columnAt(ci).get(i);
    return .{ .type = g.columns[ci].type, .cells = cells, .std_ok = fm.widthsConform(g) };
}

fn mutated(a: std.mem.Allocator, f: Frame, e: Expr) !Out {
    const g = try df.mutate(a, f, &.{.{ .out = "r", .expr = e }});
    return column0(a, g, "r");
}

const Bin = @FieldType(@FieldType(Expr, "binary"), "op");

fn opOf(name: []const u8) ?Bin {
    const map = [_]struct { []const u8, Bin }{
        .{ "add", .add },     .{ "sub", .sub },           .{ "mul", .mul },
        .{ "truediv", .div }, .{ "floordiv", .floordiv }, .{ "mod", .mod },
        .{ "eq", .eq },       .{ "lt", .lt },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], name)) return m[1];
    return null;
}

/// The result an `i128` computation of `op` on two cells, null when the operator has no exact form here.
fn exactBin(op: []const u8, x: i128, y: i128) ?i128 {
    if (std.mem.eql(u8, op, "add")) return x + y;
    if (std.mem.eql(u8, op, "sub")) return x - y;
    if (std.mem.eql(u8, op, "mul")) return std.math.mul(i128, x, y) catch std.math.maxInt(i128); // past every width
    if (std.mem.eql(u8, op, "floordiv")) return if (y == 0) null else @divFloor(x, y);
    if (std.mem.eql(u8, op, "mod")) return if (y == 0) null else x - @divFloor(x, y) * y;
    return null;
}

const Cmp = struct {
    /// F32 results compare by bits within this many units in the last place.
    ulp: u32 = 0,
    /// F64 results within this relative difference (an algorithm's last digits: Welford's variance).
    rel: f64 = 0,
};

/// Whether `got` is the cell polars answered, `want`, of a column of type `ty`.
fn sameCell(want: J, got: Value, ty: ColumnType, bits: ?[]const u8, cmp: Cmp) bool {
    if (want == .null) return got == .null;
    if (got == .null) return false;
    if (ty == .bool) return want == .bool and got == .bool and want.bool == got.bool;
    if (dtype.isFloat(ty)) {
        const g = got.asFloat() orelse return false;
        if (want == .string) {
            const w = jcell(want, .float).asFloat().?;
            if (std.math.isNan(w)) return std.math.isNan(g);
            return g == w;
        }
        if (bits) |b| {
            const w = std.fmt.parseInt(u32, b[2..], 16) catch return false;
            const gf: f32 = @floatCast(g);
            const gb: u32 = @bitCast(gf);
            if (gb == w) return true;
            const wf: f32 = @bitCast(w);
            if (std.math.isNan(gf) and std.math.isNan(wf)) return true;
            if (cmp.ulp == 0 or std.math.isNan(gf) or std.math.isNan(wf)) return false;
            const d = if (gb > w) gb - w else w - gb;
            return (gb >> 31) == (w >> 31) and d <= cmp.ulp;
        }
        const w = jcell(want, .float).asFloat() orelse return false;
        if (std.math.isNan(w)) return std.math.isNan(g);
        if (cmp.ulp > 0) return @abs(g - w) <= @abs(w) * 4e-16;
        if (cmp.rel > 0) return @abs(g - w) <= @abs(w) * cmp.rel;
        return @as(u64, @bitCast(w)) == @as(u64, @bitCast(g));
    }
    const w = jcell(want, ty);
    return w.eql(got);
}

fn wantCells(c: J) []const J {
    return c.object.get("expect").?.array.items;
}

fn bitsOf(c: J, i: usize) ?[]const u8 {
    const b = c.object.get("bits") orelse return null;
    if (i >= b.array.items.len or b.array.items[i] != .string) return null;
    return b.array.items[i].string;
}

/// Compare the result cells with polars' and tally. `exact` gives, per row, the exact integer result
/// (null: unknown), for the overflow rule. A result type of ours that is a `typeKnown` difference
/// makes the cells known too (the values then follow the other type's arithmetic).
fn compare(a: std.mem.Allocator, c: J, out: Out, t: *Tally, ulp: u32, exact: ?[]const ?i128) void {
    const id = strOf(c, "id");
    const op = strOf(c, "op");
    const want = wantCells(c);
    const dout = if (c.object.get("dtype_out").? == .string) strOf(c, "dtype_out") else "";
    const wt = wantType(dout) orelse return;
    var type_known = false;
    if (out.type != wt) {
        if (typeKnown(id, op, dout, out.type)) |_| {
            t.known_cases += 1;
            type_known = true;
        } else {
            t.miss("{s}: type {s}, polars {s}", .{ id, @tagName(out.type), dout });
        }
    }
    if (!out.std_ok) t.miss("{s}: storage does not conform to the declared width", .{id});
    if (std.mem.eql(u8, dout, "i128")) {
        t.known_cases += 1;
        return;
    }
    if (out.cells.len != want.len) {
        t.miss("{s}: {d} rows, polars {d}", .{ id, out.cells.len, want.len });
        return;
    }
    // After an overflow of a running total no later row is right (`cum_*`): polars may wrap back in range.
    var dead = false;
    const running = std.mem.eql(u8, op, "cum_sum") or std.mem.eql(u8, op, "cum_prod");
    const rel: f64 = if (std.mem.eql(u8, op, "std") or std.mem.eql(u8, op, "var")) 1e-12 else 0;
    for (want, out.cells, 0..) |w, g, i| {
        t.cells += 1;
        var fits: ?bool = if (exact) |ex| (if (ex[i]) |x| dtype.fits(x, wt) else null) else null;
        if (running and fits != null) {
            if (!fits.?) dead = true;
            if (dead) fits = false;
        }
        if (sameCell(w, g, wt, bitsOf(c, i), .{ .ulp = ulp, .rel = rel })) continue;
        if (type_known) {
            t.known_cells += 1;
            continue;
        }
        if (cellKnown(c, i, id, op, dout, w, g, wt, fits)) |_| {
            t.known_cells += 1;
            continue;
        }
        t.miss("{s} [row {d}]: polars {s}, got {any}", .{ id, i, cellText(a, w), g });
    }
}

fn inputExact(c: J, name: []const u8, i: usize) ?i128 {
    const col = c.object.get("in").?.object.get(name) orelse return null;
    return exactOf(col.object.get("values").?.array.items[i]);
}

// ── kinds ───────────────────────────────────────────────────────────────────

fn replayBinary(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const opn = strOf(c, "op");
    const op = opOf(opn) orelse return;
    if (std.mem.eql(u8, opn, "eq") or std.mem.eql(u8, opn, "lt")) return;
    const f = (try frameOfCase(a, c.object.get("in").?, false)) orelse return;
    t.run += 1;
    const e: Expr = .{ .binary = .{ .op = op, .l = try colX(a, "a"), .r = try colX(a, "b") } };
    const out = mutated(a, f, e) catch |err| {
        if (!knownCase(id)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    const ex = try a.alloc(?i128, out.cells.len);
    for (ex, 0..) |*x, i| x.* = blk: {
        const l = inputExact(c, "a", i) orelse break :blk null;
        const r = inputExact(c, "b", i) orelse break :blk null;
        break :blk exactBin(opn, l, r);
    };
    compare(a, c, out, t, 0, ex);
}

const LitOp = struct { op: []const u8, lit: Value };

fn overflowOp(name: []const u8) ?LitOp {
    const map = [_]struct { []const u8, []const u8, Value }{
        .{ "add1", "add", .{ .int = 1 } },               .{ "sub1", "sub", .{ .int = 1 } },
        .{ "mul2", "mul", .{ .int = 2 } },               .{ "mulneg1", "mul", .{ .int = -1 } },
        .{ "floordivneg1", "floordiv", .{ .int = -1 } }, .{ "mod0", "mod", .{ .int = 0 } },
        .{ "floordiv0", "floordiv", .{ .int = 0 } },     .{ "modneg1", "mod", .{ .int = -1 } },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], name)) return .{ .op = m[1], .lit = m[2] };
    return null;
}

fn replayOverflow(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const lo = overflowOp(strOf(c, "op")) orelse return;
    const f = (try frameOfCase(a, c.object.get("in").?, false)) orelse return;
    t.run += 1;
    const e: Expr = .{ .binary = .{ .op = opOf(lo.op).?, .l = try colX(a, "a"), .r = try bx(a, .{ .lit = lo.lit }) } };
    const polars_error = c.object.get("error").?.bool;
    const out = mutated(a, f, e) catch |err| {
        if (!polars_error and !knownCase(id)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    if (polars_error) {
        // polars refuses a negative literal with an unsigned column; the weak literal here widens (D6).
        t.known_cases += 1;
        return;
    }
    const ex = try a.alloc(?i128, out.cells.len);
    for (ex, 0..) |*x, i| x.* = blk: {
        const l = inputExact(c, "a", i) orelse break :blk null;
        break :blk exactBin(lo.op, l, lo.lit.int);
    };
    compare(a, c, out, t, 0, ex);
}

fn replayWeak(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const opn = strOf(c, "op");
    const f = (try frameOfCase(a, c.object.get("in").?, false)) orelse return;
    const lj = c.object.get("lit").?;
    const lit: Value = if (lj == .float) .{ .float = lj.float } else jcell(lj, .int);
    t.run += 1;
    const l = try colX(a, "a");
    const r = try bx(a, .{ .lit = lit });
    const e: Expr = if (std.mem.eql(u8, opn, "fill_null"))
        .{ .coalesce = try a.dupe(Expr, &.{ l.*, r.* }) }
    else
        .{ .binary = .{ .op = opOf(opn) orelse return, .l = l, .r = r } };
    const polars_error = c.object.get("error").?.bool;
    const out = mutated(a, f, e) catch |err| {
        if (!polars_error and !knownCase(id)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    if (polars_error) {
        t.known_cases += 1;
        return;
    }
    const ex = try a.alloc(?i128, out.cells.len);
    for (ex, 0..) |*x, i| x.* = blk: {
        const l0 = inputExact(c, "a", i) orelse break :blk null;
        const lv = dtype.exactI128(lit) orelse break :blk null;
        break :blk exactBin(opn, l0, lv);
    };
    compare(a, c, out, t, 0, ex);
}

fn replayUnary(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const opn = strOf(c, "op");
    const f = (try frameOfCase(a, c.object.get("in").?, false)) orelse return;
    t.run += 1;
    const x = try colX(a, "a");
    const e: Expr = if (std.mem.eql(u8, opn, "neg")) .{ .unary = .{ .op = .neg, .x = x } } else if (std.mem.eql(u8, opn, "abs")) .{ .unary = .{ .op = .abs, .x = x } } else if (std.mem.eql(u8, opn, "sign")) .{ .unary = .{ .op = .sign, .x = x } } else if (std.mem.eql(u8, opn, "sqrt")) .{ .unary = .{ .op = .sqrt, .x = x } } else if (std.mem.eql(u8, opn, "is_nan")) .{ .unary = .{ .op = .is_nan, .x = x } } else if (std.mem.eql(u8, opn, "pow2")) .{ .binary = .{ .op = .pow, .l = x, .r = try bx(a, .{ .lit = .{ .int = 2 } }) } } else if (std.mem.eql(u8, opn, "pow0.5")) .{ .binary = .{ .op = .pow, .l = x, .r = try bx(a, .{ .lit = .{ .float = 0.5 } }) } } else if (std.mem.eql(u8, opn, "round1")) .{ .round = .{ .x = x, .decimals = 1, .mode = .half_even } } else return;
    const polars_error = c.object.get("error").?.bool;
    const out = mutated(a, f, e) catch |err| {
        if (polars_error and err == error.BadExpr) return; // both refuse a negation of an unsigned column
        if (!knownCase(id)) t.miss("{s}: {s} (polars error {any})", .{ id, @errorName(err), polars_error });
        return;
    };
    if (polars_error) {
        t.miss("{s}: polars refuses, got a column", .{id});
        return;
    }
    const ex = try a.alloc(?i128, out.cells.len);
    for (ex, 0..) |*xx, i| xx.* = blk: {
        const v = inputExact(c, "a", i) orelse break :blk null;
        if (std.mem.eql(u8, opn, "neg")) break :blk -v;
        if (std.mem.eql(u8, opn, "abs")) break :blk if (v < 0) -v else v;
        if (std.mem.eql(u8, opn, "pow2")) break :blk std.math.mul(i128, v, v) catch std.math.maxInt(i128);
        break :blk null;
    };
    compare(a, c, out, t, 0, ex);
}

const AggFn = df.AggFn;

fn aggOf(name: []const u8) ?AggFn {
    const map = [_]struct { []const u8, AggFn }{
        .{ "sum", .sum },      .{ "mean", .mean },        .{ "median", .median }, .{ "min", .min },
        .{ "max", .max },      .{ "std", .std },          .{ "var", .@"var" },    .{ "quantile", .quantile },
        .{ "product", .prod }, .{ "n_unique", .nunique }, .{ "first", .first },   .{ "last", .last },
        .{ "mode", .mode },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], name)) return m[1];
    return null;
}

fn windowOf(name: []const u8) ?df.WindowOp {
    if (std.mem.eql(u8, name, "cum_sum")) return .cum_sum;
    if (std.mem.eql(u8, name, "cum_prod")) return .cum_prod;
    if (std.mem.eql(u8, name, "cum_min")) return .cum_min;
    if (std.mem.eql(u8, name, "cum_max")) return .cum_max;
    if (std.mem.eql(u8, name, "diff")) return .{ .diff = 1 };
    if (std.mem.eql(u8, name, "pct_change")) return .{ .pct_change = 1 };
    if (std.mem.eql(u8, name, "rank")) return .{ .rank = .{} };
    return null;
}

/// The exact `sum`/`product`/running results of the input, for the overflow rule.
fn aggExact(a: std.mem.Allocator, c: J, opn: []const u8, n_out: usize) !?[]?i128 {
    const col = c.object.get("in").?.object.get("a") orelse return null;
    const vals = col.object.get("values").?.array.items;
    const out = try a.alloc(?i128, n_out);
    @memset(out, null);
    const cum = std.mem.startsWith(u8, opn, "cum_");
    const scalar = std.mem.eql(u8, opn, "sum") or std.mem.eql(u8, opn, "product");
    if (!cum and !scalar and !std.mem.eql(u8, opn, "diff")) return null;
    var acc: ?i128 = null;
    var prev: ?i128 = null;
    for (vals, 0..) |v, i| {
        const x = exactOf(v);
        if (std.mem.eql(u8, opn, "diff")) {
            if (i < out.len) out[i] = if (x != null and prev != null) x.? - prev.? else null;
            prev = x;
            continue;
        }
        const xv = x orelse {
            if (cum and i < out.len) out[i] = null;
            continue;
        };
        const is_prod = std.mem.eql(u8, opn, "product") or std.mem.eql(u8, opn, "cum_prod");
        acc = if (acc) |s| (if (is_prod) std.math.mul(i128, s, xv) catch std.math.maxInt(i128) else s + xv) else xv; // saturated: past every width
        if (cum and i < out.len) out[i] = acc;
    }
    if (scalar and out.len > 0) out[0] = acc orelse (if (std.mem.eql(u8, opn, "sum")) @as(?i128, 0) else 1);
    return out;
}

fn replayAggregate(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const opn = strOf(c, "op");
    if (knownCase(id)) {
        t.known_cases += 1;
        return;
    }
    const f = (try frameOfCase(a, c.object.get("in").?, false)) orelse return;
    t.run += 1;
    var out: Out = undefined;
    if (aggOf(opn)) |func| {
        const g = df.aggregate(a, f, .{
            .group_by = &.{},
            .aggs = &.{.{ .src = "a", .out = "r", .func = func, .q = 0.5, .interpolation = .nearest }},
            .skip_na = true,
        }) catch |err| {
            t.miss("{s}: {s}", .{ id, @errorName(err) });
            return;
        };
        out = try column0(a, g, "r");
    } else if (windowOf(opn)) |op| {
        const g = df.window(a, f, .{ .value_col = "a", .out = "r", .op = op }) catch |err| {
            t.miss("{s}: {s}", .{ id, @errorName(err) });
            return;
        };
        out = try column0(a, g, "r");
    } else return;
    const ex = try aggExact(a, c, opn, out.cells.len);
    const ulp: u32 = if (dtype.isFloat(typeOf(strOf(c.object.get("in").?.object.get("a").?, "dtype")) orelse .int)) 1 else 0;
    compare(a, c, out, t, ulp, ex);
}

fn replayGroupAgg(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const opn = strOf(c, "op");
    const func = aggOf(opn) orelse return;
    const f = (try frameOfCase(a, c.object.get("in").?, false)) orelse return;
    t.run += 1;
    const g = df.aggregate(a, f, .{
        .group_by = &.{"k"},
        .aggs = &.{.{ .src = "a", .out = "r", .func = func }},
        .skip_na = true,
    }) catch |err| {
        t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    const out = try column0(a, g, "r");
    // The exact group sums: the keys are first seen in order.
    const ks = c.object.get("in").?.object.get("k").?.object.get("values").?.array.items;
    const vs = c.object.get("in").?.object.get("a").?.object.get("values").?.array.items;
    const ex = try a.alloc(?i128, out.cells.len);
    @memset(ex, null);
    if (std.mem.eql(u8, opn, "sum")) {
        var seen: std.ArrayList(i128) = .empty;
        for (ks, vs) |k, v| {
            const kk = exactOf(k) orelse continue;
            const slot = for (seen.items, 0..) |s, i| {
                if (s == kk) break i;
            } else blk: {
                try seen.append(a, kk);
                break :blk seen.items.len - 1;
            };
            if (slot < ex.len) ex[slot] = (ex[slot] orelse 0) + (exactOf(v) orelse 0);
        }
    }
    const ulp: u32 = if (dtype.isFloat(typeOf(strOf(c.object.get("in").?.object.get("a").?, "dtype")) orelse .int)) 1 else 0;
    compare(a, c, out, t, ulp, ex);
}

fn replayCombine(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const opn = strOf(c, "op");
    const f = (try frameOfCase(a, c.object.get("in").?, true)) orelse return;
    t.run += 1;
    const ca = try colX(a, "a");
    const cb = try colX(a, "b");
    const e: Expr = if (std.mem.eql(u8, opn, "when_then_otherwise"))
        .{ .if_else = .{ .cond = try colX(a, "c"), .then = ca, .otherwise = cb } }
    else
        .{ .coalesce = try a.dupe(Expr, &.{ ca.*, cb.* }) };
    const out = mutated(a, f, e) catch |err| {
        t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    compare(a, c, out, t, 0, null);
}

fn replayConcat(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const input = c.object.get("in").?.object;
    var frames: [2]Frame = undefined;
    for ([_][]const u8{ "a", "b" }, &frames) |n, *fr| {
        const col = input.get(n).?;
        const ty = typeOf(strOf(col, "dtype")) orelse return;
        const r = try column(a, "x", ty, col.object.get("values").?.array.items);
        var b = try fm.FrameBuilder.init(a, try a.dupe(Column, &.{r[0]}), r[1].len);
        for (r[1]) |v| try b.appendRow(&.{v});
        fr.* = try b.toOwned();
    }
    t.run += 1;
    const g = df.concatByName(a, &frames) catch |err| {
        t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    compare(a, c, try column0(a, g, "x"), t, 0, null);
}

test "W11 oracle: polars arithmetic, literals, aggregates and combining of the width types" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    var t: Tally = .{ .out = .init(a) };
    for (doc.array.items) |c| {
        if (!std.mem.eql(u8, strOf(c, "engine"), "pl")) continue;
        const kind = strOf(c, "kind");
        if (std.mem.eql(u8, kind, "supertype")) try replayBinary(a, c, &t);
        if (std.mem.eql(u8, kind, "overflow")) try replayOverflow(a, c, &t);
        if (std.mem.eql(u8, kind, "weak_literal")) try replayWeak(a, c, &t);
        if (std.mem.eql(u8, kind, "unary")) try replayUnary(a, c, &t);
        if (std.mem.eql(u8, kind, "aggregate")) try replayAggregate(a, c, &t);
        if (std.mem.eql(u8, kind, "group_agg")) try replayGroupAgg(a, c, &t);
        if (std.mem.eql(u8, kind, "combine")) try replayCombine(a, c, &t);
        if (std.mem.eql(u8, kind, "supertype_concat")) try replayConcat(a, c, &t);
    }
    if (t.bad != 0) {
        std.debug.print("W11a oracle: {d} problems in {d} cases ({d} cells, {d} cells and {d} cases known):\n{s}", .{ t.bad, t.run, t.cells, t.known_cells, t.known_cases, t.out.written() });
        return error.TestUnexpectedResult;
    }
    try testing.expect(t.run > 2000);
}

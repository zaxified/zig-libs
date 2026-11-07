// SPDX-License-Identifier: MIT
//! Replays `oracle2_vectors.json`: what pandas and polars answered for the verbs added in
//! D2 (`tools/oracle2.py` asked the engines; no line of this module is consulted there).
//! Scalar cases run one cell function over a list of cells, frame cases one verb over a
//! small table. The expected values are the engines' alone, so a failure here is a
//! difference from them, never a restatement of this module. Where the engines disagree
//! the vector carries a `label` and the engine followed (`engine`); the other engine's
//! answer is kept in `other`, and a mismatch that equals it is reported as such.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const verbs = @import("verbs.zig");
const sp = @import("spec.zig");
const ex = @import("expr.zig");
const ef = @import("exprfn.zig");
const dtf = @import("dtfn.zig");
const an = @import("analysis.zig");
const st = @import("structure.zig");
const rs = @import("reshape.zig");
const sf = @import("seriesfn.zig");
const fo = @import("frameops.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const J = std.json.Value;

const vectors = @embedFile("oracle2_vectors.json");

/// Deliberate differences from what the engines answered: id substring, and why. An
/// entry with `always` must still DIFFER, or it is stale and the test fails.
const known = [_]struct { id: []const u8, why: []const u8, always: bool = true }{
    // datefmt parses numeric fields at their full width; both engines also take one digit
    .{ .id = "strptime-ymd", .why = "`datefmt` needs two-digit month and day; the engines take 2021-3-4 (outside this module: `datefmt`)" },
    .{ .id = "strptime-dmy", .why = "one-digit day and month, as strptime-ymd" },
    .{ .id = "strptime-compact", .why = "`%Y%m%d` over 7 digits: the engines read 2021 03 4" },
    .{ .id = "strptime-dt", .why = "one-digit hour" },
    .{ .id = "strptime-frac", .why = "a fraction of fewer than six digits" },
    .{ .id = "strptime-mon", .why = "one-digit day after a month name" },
    .{ .id = "strptime-month", .why = "one-digit day after a month name" },
    .{ .id = "strptime-doy", .why = "`%j` of fewer than three digits" },
    .{ .id = "strptime-ampm", .why = "one-digit hour with `%I`" },
    .{ .id = "strptime-tz", .why = "an offset of `+hh` only" },
    .{ .id = "strptime-FT", .why = "one-digit hour" },
    .{ .id = "strptime-hm", .why = "one-digit hour and minute" },
    .{ .id = "strptime-dots", .why = "one-digit day, month and hour" },
    // case and character classes are ASCII (SPEC Backlog: Unicode tables)
    .{ .id = "str-swapcase", .why = "the case of non-ASCII letters (SPEC Backlog: Unicode tables)" },
    .{ .id = "str-uni-", .why = "the case of non-ASCII letters (SPEC Backlog: Unicode tables)", .always = false },
    .{ .id = "str-title", .why = "a non-ASCII letter at the start of a word is not capitalised", .always = false },
    .{ .id = "str-is-", .why = "non-ASCII letters are no letters here; a missing text is null here, False in pandas' str dtype" },
    // typed sums
    .{ .id = "pivot_many-sum", .why = "the `sum` of an int column is a float column (as `aggregate`'s, SPEC D2 note); both engines int" },
    // skew and kurtosis without spread
    .{ .id = "agg-skew-small", .why = "a group of equal values: both engines NaN, here (and in `tabular`, the twin) 0" },
    .{ .id = "agg-kurt-small", .why = "as agg-skew-small" },
    // polars' peak_max / peak_min
    .{ .id = "peaks-asc-min", .why = "polars 2.1 compares an END cell with 0 (data-dependent at the ends); here a missing neighbour is left out" },
    .{ .id = "peaks-desc-min", .why = "as peaks-asc-min" },
    .{ .id = "peaks-plateau-min", .why = "as peaks-asc-min" },
    .{ .id = "peaks-zigzag-min", .why = "as peaks-asc-min" },
    .{ .id = "peaks-one-max", .why = "a single cell: polars True for max, False for min; here never a peak" },
    .{ .id = "peaks-two-min", .why = "as peaks-asc-min" },
    .{ .id = "peaks-neg-max", .why = "as peaks-asc-min: the end -1 is above its neighbour but not above 0" },
    .{ .id = "peaks-inf-max", .why = "as peaks-asc-min: the end 0 is above -inf but not above 0" },
    .{ .id = "peaks-inf-min", .why = "as peaks-asc-min" },
    .{ .id = "peaks-int-min", .why = "as peaks-asc-min" },
    .{ .id = "peaks-null_mid-min", .why = "as peaks-asc-min, at the first cell" },
    .{ .id = "peaks-nan-", .why = "polars counts NaN as the greatest number, this module as missing (SPEC)" },
};

// ── json helpers ────────────────────────────────────────────────────────────

fn jstr(o: J, k: []const u8) []const u8 {
    return o.object.get(k).?.string;
}

fn jopt(o: J, k: []const u8) ?J {
    const v = o.object.get(k) orelse return null;
    return if (v == .null) null else v;
}

fn jbool(o: J, k: []const u8, d: bool) bool {
    return if (jopt(o, k)) |v| v.bool else d;
}

fn jnum(v: J) f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .string => |s| special(s),
        else => unreachable, // the vectors put a number here
    };
}

fn special(s: []const u8) f64 {
    if (std.mem.eql(u8, s, "NaN")) return std.math.nan(f64);
    if (std.mem.eql(u8, s, "inf")) return std.math.inf(f64);
    if (std.mem.eql(u8, s, "-inf")) return -std.math.inf(f64);
    unreachable; // only these three strings stand for a float in the vectors
}

fn strs(a: std.mem.Allocator, v: ?J) ![]const []const u8 {
    const xs = (v orelse return &.{}).array.items;
    const out = try a.alloc([]const u8, xs.len);
    for (out, xs) |*o, x| o.* = x.string;
    return out;
}

fn optStr(o: J, k: []const u8) ?[]const u8 {
    return if (jopt(o, k)) |v| v.string else null;
}

/// A table cell: NaN, inf as the strings the generator writes.
fn cellOf(v: J) Value {
    return switch (v) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .int = i },
        .float => |f| .{ .float = f },
        .string => |s| if (std.mem.eql(u8, s, "NaN")) .{ .float = std.math.nan(f64) } else .{ .text = s },
        else => unreachable, // no other cell in the vectors
    };
}

fn loadTable(a: std.mem.Allocator, tj: J) !Frame {
    const cj = tj.object.get("columns").?.array.items;
    const cols = try a.alloc(Column, cj.len);
    for (cols, cj) |*c, x| c.* = .{ .name = jstr(x, "name"), .type = std.meta.stringToEnum(ColumnType, jstr(x, "type")).? };
    const rj = tj.object.get("rows").?.array.items;
    var b = try fm.FrameBuilder.init(a, cols, rj.len);
    const row = try a.alloc(Value, cols.len);
    for (rj) |x| {
        for (row, x.array.items, cols) |*n, v, c| {
            n.* = cellOf(v);
            if (c.type == .float and n.* == .int) n.* = .{ .float = @floatFromInt(n.int) };
            // "inf" and "-inf" in a float column are the numbers
            if (c.type == .float and n.* == .text) {
                const t = n.text;
                n.* = .{ .float = special(t) };
            }
        }
        try b.appendRow(row);
    }
    return b.toOwned();
}

// ── scalar cases ────────────────────────────────────────────────────────────

fn kindIs(kind: []const u8, k: []const u8) bool {
    return std.mem.eql(u8, kind, k);
}

/// A cell of a scalar case, read as `kind` (`float`, `int`, `ts`, `text`, `bool`).
fn cellK(v: J, kind: []const u8) Value {
    return switch (v) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| if (kindIs(kind, "float")) .{ .float = @floatFromInt(i) } else .{ .int = i },
        .float => |f| .{ .float = f },
        .string => |s| if (kindIs(kind, "float")) .{ .float = special(s) } else .{ .text = s },
        else => unreachable, // no other cell in the vectors
    };
}

fn missing(v: Value) bool {
    return v == .null or (v == .float and std.math.isNan(v.float));
}

fn nearFloat(x: f64, y: f64) bool {
    if (std.math.isInf(x) or std.math.isInf(y)) return x == y;
    return @abs(x - y) <= 1e-9 * @max(1.0, @max(@abs(x), @abs(y)));
}

fn matchK(want: Value, got: Value, kind: []const u8) bool {
    if (missing(want) or missing(got)) return missing(want) and missing(got);
    if (kindIs(kind, "text")) return want == .text and got == .text and std.mem.eql(u8, want.text, got.text);
    if (kindIs(kind, "bool")) return want == .bool and got == .bool and want.bool == got.bool;
    if (kindIs(kind, "int") or kindIs(kind, "ts")) return want == .int and got == .int and want.int == got.int;
    const w = want.asFloat() orelse return false;
    const g = got.asFloat() orelse return false;
    return nearFloat(w, g);
}

fn shape(a: std.mem.Allocator, v: Value) ![]const u8 {
    return switch (v) {
        .text => |t| try a.print("\"{s}\"", .{t}),
        else => try a.print("{any}", .{v}),
    };
}

const BadFormat = error{BadFormat};

fn strVal(t: []const u8) Value {
    return .{ .text = t };
}

fn patterns(a: std.mem.Allocator, args: J, k: []const u8) ![]const []const u8 {
    return strs(a, args.object.get(k));
}

fn enumOf(comptime E: type, s: []const u8) E {
    return std.meta.stringToEnum(E, s).?; // the generator writes our own enum names
}

/// One cell through the function a scalar case names.
fn applyScalar(a: std.mem.Allocator, fn_name: []const u8, args: J, cell: J, in_kind: []const u8, layout: ?[]const u8) !Value {
    const eq = std.mem.eql;
    if (eq(u8, fn_name, "is_close")) {
        const xs = cell.array.items;
        return ef.isClose(cellK(xs[0], "float"), cellK(xs[1], "float"), jnum(args.object.get("rel_tol").?), jnum(args.object.get("abs_tol").?), jbool(args, "nans_equal", false));
    }
    const v = cellK(cell, in_kind);
    if (eq(u8, fn_name, "round")) {
        const d: i32 = @intCast(args.object.get("decimals").?.integer);
        return ef.round(v, d, enumOf(ef.RoundMode, jstr(args, "mode")));
    }
    if (eq(u8, fn_name, "round_sig_figs")) return ef.roundSigFigs(v, @intCast(args.object.get("digits").?.integer));
    if (eq(u8, fn_name, "dt_part")) return dtf.part(a, v, enumOf(dtf.DtPart, jstr(args, "part")));
    if (eq(u8, fn_name, "strptime")) return dtf.strptime(a, v, layout.?, .timestamp);
    if (eq(u8, fn_name, "strftime")) return dtf.strftime(a, v, layout.?);
    if (eq(u8, fn_name, "offset_by")) return dtf.offsetBy(a, v, dtf.parseDuration(jstr(args, "every")) orelse return .null);
    if (eq(u8, fn_name, "truncate")) return dtf.truncate(a, v, dtf.parseDuration(jstr(args, "every")) orelse return .null);
    if (eq(u8, fn_name, "add_business_days")) return dtf.addBusinessDays(a, v, args.object.get("n").?.integer);
    // Text functions: a missing text is missing.
    if (v != .text) return .null;
    const t = v.text;
    if (eq(u8, fn_name, "slice")) {
        const len: ?usize = if (jopt(args, "length")) |l| @intCast(l.integer) else null;
        return strVal(try ef.slice(a, t, args.object.get("offset").?.integer, len));
    }
    if (eq(u8, fn_name, "head")) return strVal(try ef.head(a, t, args.object.get("n").?.integer));
    if (eq(u8, fn_name, "tail")) return strVal(try ef.tail(a, t, args.object.get("n").?.integer));
    if (eq(u8, fn_name, "char_at")) return if (try ef.charAt(a, t, args.object.get("i").?.integer)) |c| strVal(c) else .null;
    if (eq(u8, fn_name, "reverse")) return strVal(try ef.reverse(a, t));
    if (eq(u8, fn_name, "pad")) {
        const fill = try std.unicode.utf8Decode(jstr(args, "fill"));
        return strVal(try ef.pad(a, t, @intCast(args.object.get("width").?.integer), enumOf(ef.PadSide, jstr(args, "side")), fill));
    }
    if (eq(u8, fn_name, "zfill")) return strVal(try ef.zfill(a, t, args.object.get("width").?.integer));
    if (eq(u8, fn_name, "repeat")) return strVal(try ef.repeat(a, t, args.object.get("n").?.integer));
    if (eq(u8, fn_name, "strip")) return strVal(ef.stripChars(t, optStr(args, "chars"), enumOf(ef.StripSide, jstr(args, "side"))));
    if (eq(u8, fn_name, "translate")) return strVal(try ef.translate(a, t, jstr(args, "from"), jstr(args, "to"), jstr(args, "delete")));
    if (eq(u8, fn_name, "to_integer")) return ef.toInteger(t, @intCast(args.object.get("base").?.integer));
    if (eq(u8, fn_name, "capitalize")) return strVal(try ef.capitalize(a, t));
    if (eq(u8, fn_name, "title")) return strVal(try ef.title(a, t));
    if (eq(u8, fn_name, "swapcase")) return strVal(try ef.swapcase(a, t));
    if (eq(u8, fn_name, "is_class")) return .{ .bool = ef.isClass(t, enumOf(ef.CharClass, jstr(args, "class"))) };
    if (eq(u8, fn_name, "contains_any")) return .{ .bool = ef.containsAny(t, try patterns(a, args, "patterns"), jbool(args, "fold", false)) };
    if (eq(u8, fn_name, "replace_many")) return strVal(try ef.replaceMany(a, t, try patterns(a, args, "patterns"), try patterns(a, args, "with"), jbool(args, "fold", false)));
    if (eq(u8, fn_name, "count_matches")) return .{ .int = @intCast(ef.countMatches(t, jstr(args, "p"))) };
    return error.NotCovered;
}

/// null = same, else what differs (first cell only).
fn runScalarList(a: std.mem.Allocator, c: J, want: []const J) !?[]const u8 {
    const fn_name = jstr(c, "fn");
    const args = c.object.get("args").?;
    const in = c.object.get("in").?.array.items;
    const in_kind = jstr(c, "in_kind");
    const out_kind = jstr(c, "out_kind");
    var layout: ?[]const u8 = null;
    if (std.mem.eql(u8, fn_name, "strptime") or std.mem.eql(u8, fn_name, "strftime")) {
        layout = dtf.translateFormat(a, jstr(args, "fmt")) catch |e| switch (e) {
            error.BadFormat => return try a.print("format {s} refused", .{jstr(args, "fmt")}),
            else => return e,
        };
    }
    var diffs: usize = 0;
    var first: ?[]const u8 = null;
    for (in, want, 0..) |x, w, i| {
        const got = try applyScalar(a, fn_name, args, x, in_kind, layout);
        if (!matchK(cellK(w, out_kind), got, out_kind)) {
            diffs += 1;
            if (first == null) first = try a.print("cell {d} (in {s}): engines {s}, ours {s}", .{ i, try jsonText(a, x), try jsonText(a, w), try shape(a, got) });
        }
    }
    if (first) |f| return try a.print("{d} of {d} cells differ; {s}", .{ diffs, in.len, f });
    return null;
}

fn jsonText(a: std.mem.Allocator, v: J) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, v, .{});
}

// ── frame cases ─────────────────────────────────────────────────────────────

fn aggCols(a: std.mem.Allocator, aj: []const J) ![]sp.AggCol {
    const aggs = try a.alloc(sp.AggCol, aj.len);
    for (aggs, aj) |*g, x| g.* = .{
        .src = jstr(x, "src"),
        .out = jstr(x, "out"),
        .func = enumOf(sp.AggFn, jstr(x, "func")),
        .q = if (jopt(x, "q")) |q| jnum(q) else 0.5,
        .interpolation = if (optStr(x, "interp")) |s| enumOf(sp.Interpolation, s) else .linear,
        .ddof = if (jopt(x, "ddof")) |d| @intCast(d.integer) else 1,
    };
    return aggs;
}

fn onePlain(a: std.mem.Allocator, name: []const u8, ty: ColumnType, v: Value) !Frame {
    const cols = try a.dupe(Column, &.{.{ .name = name, .type = ty }});
    var b = try fm.FrameBuilder.init(a, cols, 1);
    try b.appendRow(&.{v});
    return b.toOwned();
}

fn runFrame(a: std.mem.Allocator, c: J) !Frame {
    const verb = jstr(c, "verb");
    const s = c.object.get("spec").?;
    const d = try loadTable(a, c.object.get("table").?);
    const right: ?Frame = if (c.object.get("right")) |r| try loadTable(a, r) else null;
    const eq = std.mem.eql;

    if (eq(u8, verb, "fill_null")) return an.fillNull(a, d, .{
        .subset = try strs(a, s.object.get("subset")),
        .strategy = enumOf(an.FillStrategy, jstr(s, "strategy")),
        .limit = if (jopt(s, "limit")) |l| @intCast(l.integer) else null,
    });
    if (eq(u8, verb, "qcut")) {
        const pj = if (jopt(s, "probs")) |p| p.array.items else &[_]J{};
        const probs = try a.alloc(f64, pj.len);
        for (probs, pj) |*p, x| p.* = jnum(x);
        return an.qcut(a, d, .{
            .col = jstr(s, "col"),
            .out = jstr(s, "out"),
            .bins = if (jopt(s, "bins")) |b| @intCast(b.integer) else 4,
            .probs = probs,
            .labels = try strs(a, s.object.get("labels")),
            .duplicates = enumOf(@FieldType(an.QcutSpec, "duplicates"), jstr(s, "duplicates")),
        });
    }
    if (eq(u8, verb, "factorize")) {
        const r = try an.factorize(a, d, .{
            .cols = try strs(a, s.object.get("cols")),
            .out = jstr(s, "out"),
            .sort = jbool(s, "sort", false),
            .missing = enumOf(@FieldType(an.FactorizeSpec, "missing"), jstr(s, "missing")),
        });
        return r.frame;
    }
    if (eq(u8, verb, "interpolate")) return fo.interpolate(a, d, .{
        .col = jstr(s, "col"),
        .method = enumOf(@FieldType(fo.InterpolateSpec, "method"), jstr(s, "method")),
        .by = optStr(s, "by"),
    });
    if (eq(u8, verb, "group_by_dynamic")) return fo.groupByDynamic(a, d, .{
        .index = jstr(s, "index"),
        .every = jstr(s, "every"),
        .by = try strs(a, s.object.get("by")),
        .aggs = try aggCols(a, s.object.get("aggs").?.array.items),
    });
    if (eq(u8, verb, "pivot_many")) return rs.pivotMany(a, d, .{
        .row_key = jstr(s, "row_key"),
        .col_key = jstr(s, "col_key"),
        .values = try strs(a, s.object.get("values")),
        .agg = enumOf(sp.AggFn, jstr(s, "agg")),
        .skip_na = jbool(s, "skip_na", false),
    });
    if (eq(u8, verb, "dummies")) return rs.dummies(a, d, .{
        .cols = try strs(a, s.object.get("cols")),
        .separator = jstr(s, "separator"),
        .drop_first = jbool(s, "drop_first", false),
        .dummy_na = jbool(s, "dummy_na", false),
    });
    if (eq(u8, verb, "join_where")) {
        const pj = s.object.get("preds").?.array.items;
        const preds = try a.alloc(rs.JoinPredicate, pj.len);
        for (preds, pj) |*p, x| p.* = .{ .left = x.array.items[0].string, .op = enumOf(sp.CmpOp, x.array.items[1].string), .right = x.array.items[2].string };
        return rs.joinWhere(a, d, right.?, preds, jstr(s, "suffix"));
    }
    if (eq(u8, verb, "merge_ordered")) return rs.mergeOrdered(a, d, right.?, .{
        .on = try strs(a, s.object.get("on")),
        .fill_forward = jbool(s, "fill_forward", false),
        .suffix = jstr(s, "suffix"),
    });
    if (eq(u8, verb, "transpose")) return st.transpose(a, d, .{ .header_name = optStr(s, "header_name"), .names_from = optStr(s, "names_from") });
    if (eq(u8, verb, "peaks")) return sf.peaks(a, d, jstr(s, "col"), enumOf(sf.Peak, jstr(s, "which")), jstr(s, "out"));
    if (eq(u8, verb, "aggregate")) return verbs.aggregate(a, d, .{
        .group_by = try strs(a, s.object.get("by")),
        .aggs = try aggCols(a, s.object.get("aggs").?.array.items),
        .skip_na = jbool(s, "skip_na", false),
    });
    if (eq(u8, verb, "horizontal")) return an.horizontal(a, d, .{
        .cols = try strs(a, s.object.get("cols")),
        .func = enumOf(an.HorizontalFn, jstr(s, "func")),
        .out = jstr(s, "out"),
        .skip_na = jbool(s, "skip_na", true),
    });
    if (eq(u8, verb, "duplicate_mask")) return an.duplicateMask(a, d, .{
        .keys = try strs(a, s.object.get("keys")),
        .mask = enumOf(an.DupMask, jstr(s, "mask")),
        .out = jstr(s, "out"),
    });
    if (eq(u8, verb, "top_k")) return an.topK(a, d, .{
        .by = try strs(a, s.object.get("by")),
        .n = @intCast(s.object.get("n").?.integer),
        .largest = jbool(s, "largest", true),
        .keep = enumOf(@FieldType(an.TopKSpec, "keep"), jstr(s, "keep")),
    });
    if (eq(u8, verb, "rle_id")) return sf.rleId(a, d, jstr(s, "col"), jstr(s, "out"));
    if (eq(u8, verb, "rle")) return sf.rle(a, d.series(jstr(s, "col")).?);
    if (eq(u8, verb, "arith_scalar")) return fo.arithScalar(a, d, enumOf(ex.Binary, jstr(s, "op")), .{ .float = jnum(s.object.get("value").?) }, .{});
    if (eq(u8, verb, "n_unique")) {
        const n = try sf.nUnique(a, d, jstr(s, "col"), jbool(s, "count_missing", true));
        return onePlain(a, "o", .int, .{ .int = @intCast(n) });
    }
    return error.NotCovered;
}

fn rankOf(v: Value) u8 {
    return switch (v) {
        .null => 0,
        .bool => 1,
        .int, .float, .decimal => 2,
        .text => 3,
    };
}

fn rounded(x: f64) f64 {
    return @round(x * 1e9) / 1e9;
}

const RowCtx = struct {
    fn lt(_: void, l: []const Value, m: []const Value) bool {
        for (l, m) |x, y| {
            const rx = rankOf(x);
            const ry = rankOf(y);
            if (rx != ry) return rx < ry;
            switch (x) {
                .bool => if (x.bool != y.bool) return !x.bool,
                .int, .float, .decimal => {
                    if (x == .int and y == .int) {
                        if (x.int != y.int) return x.int < y.int;
                        continue;
                    }
                    const p = rounded(x.asFloat().?);
                    const q = rounded(y.asFloat().?);
                    if (p != q) return p < q;
                },
                .text => {
                    const o = std.mem.order(u8, x.text, y.text);
                    if (o != .eq) return o == .lt;
                },
                .null => {},
            }
        }
        return false;
    }
};

fn normCell(v: Value) Value {
    return if (missing(v)) .null else v;
}

fn nearCell(want: Value, got: Value) bool {
    const w = normCell(want);
    const g = normCell(got);
    if (w == .null or g == .null) return w == .null and g == .null;
    if (w == .text and std.mem.eql(u8, w.text, "inf")) return g == .float and g.float == std.math.inf(f64);
    if (w == .text and std.mem.eql(u8, w.text, "-inf")) return g == .float and g.float == -std.math.inf(f64);
    if (w == .text or g == .text) return w == .text and g == .text and std.mem.eql(u8, w.text, g.text);
    if (w == .bool or g == .bool) {
        const x: f64 = if (w == .bool) @floatFromInt(@intFromBool(w.bool)) else w.asFloat().?;
        const y: f64 = if (g == .bool) @floatFromInt(@intFromBool(g.bool)) else g.asFloat().?;
        return x == y;
    }
    if (w == .int) return w.order(g) == .eq or (@abs(w.int) < (1 << 53) and nearFloat(w.asFloat().?, g.asFloat().?));
    return nearFloat(w.asFloat().?, g.asFloat().?);
}

/// null = same, else what differs. `exp` is `{columns, rows}`; `full`: the width counts;
/// `positional`: columns compare by position, not name (a transpose names its own).
fn compare(a: std.mem.Allocator, c: J, exp: J, got: Frame) !?[]const u8 {
    const names = try strs(a, exp.object.get("columns"));
    const full = jbool(c, "full", false);
    const positional = jbool(c, "positional", false);
    if (full and got.columns.len != names.len) return try a.print("width {d}, engines {d}", .{ got.columns.len, names.len });
    const idx = try a.alloc(usize, names.len);
    for (idx, names, 0..) |*ix, n, k| {
        if (positional) {
            if (k >= got.columns.len) return try a.print("no column {d}", .{k});
            ix.* = k;
        } else ix.* = got.columnIndex(n) orelse return try a.print("no column {s}", .{n});
    }
    const rj = exp.object.get("rows").?.array.items;
    if (got.len != rj.len) return try a.print("{d} rows, engines {d}", .{ got.len, rj.len });
    const want = try a.alloc([]const Value, rj.len);
    const have = try a.alloc([]const Value, rj.len);
    for (want, have, rj, 0..) |*w, *h, x, ri| {
        const nw = try a.alloc(Value, names.len);
        const nh = try a.alloc(Value, names.len);
        for (nw, nh, x.array.items, idx) |*p, *q, v, ci| {
            p.* = normCell(cellOf(v));
            q.* = normCell(got.columnAt(ci).get(ri));
        }
        w.* = nw;
        h.* = nh;
    }
    if (std.mem.eql(u8, jstr(c, "order"), "any")) {
        std.mem.sort([]const Value, want, {}, RowCtx.lt);
        std.mem.sort([]const Value, have, {}, RowCtx.lt);
    }
    for (want, have, 0..) |w, h, ri| {
        for (w, h, names) |x, y, n| {
            if (!nearCell(x, y)) return try a.print("row {d} col {s}: engines {any}, ours {any}", .{ ri, n, x, y });
        }
    }
    return null;
}

fn kindName(ty: ColumnType) []const u8 {
    return switch (ty) {
        .int, .timestamp => "int",
        .float => "float",
        .text, .date => "text",
        .bool => "bool",
        .decimal => "decimal",
    };
}

/// null = every expected column has a kind one of the engines gave it.
fn compareTypes(a: std.mem.Allocator, c: J, got: Frame) !?[]const u8 {
    if (jbool(c, "positional", false)) return null;
    const names = try strs(a, c.object.get("expect").?.object.get("columns"));
    const pt = jopt(c, "ptypes");
    const qt = jopt(c, "qtypes");
    for (names) |n| {
        const ci = got.columnIndex(n) orelse continue;
        const kind = kindName(got.columns[ci].type);
        var ok = false;
        for ([_]?J{ pt, qt }) |ts| {
            const k = (ts orelse continue).object.get(n) orelse continue;
            if (std.mem.eql(u8, k.string, kind) or std.mem.eql(u8, k.string, "null")) ok = true;
        }
        if (!ok) return try a.print("column {s} is {s}", .{ n, kind });
    }
    return null;
}

// ── the replay ──────────────────────────────────────────────────────────────

fn listed(id: []const u8) ?usize {
    for (known, 0..) |k, i| {
        // an id ending in `-` names a family
        if (std.mem.eql(u8, id, k.id) or (k.id[k.id.len - 1] == '-' and std.mem.startsWith(u8, id, k.id))) return i;
    }
    return null;
}

const Tally = struct {
    ran: usize = 0,
    failed: usize = 0,
    known_hit: usize = 0,
    shown: usize = 0,
    flip: usize = 0,

    fn report(t: *Tally, id: []const u8, why: []const u8, c: J, other_ok: bool) void {
        t.failed += 1;
        if (other_ok) t.flip += 1;
        if (t.shown < 120) {
            t.shown += 1;
            std.debug.print("ORACLE2 {s}{s}: {s}\n", .{ id, if (other_ok) " [matches the OTHER engine]" else "", why });
            if (other_ok) std.debug.print("   label: {s}\n", .{jstr(c, "label")});
        }
    }
};

test "oracle2: the comparison sees a wrong cell, a wrong count and a wrong width" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try std.json.parseFromSliceLeaky(J, a,
        \\{"order":"exact","full":true,"expect":{"columns":["o"],"rows":[[1.5],[null]]}}
    , .{});
    const exp = c.object.get("expect").?;
    const cols = [_]Column{.{ .name = "o", .type = .float }};
    const good = [_]fm.ColumnData{.{ .float = .{ .values = &.{ 1.5, std.math.nan(f64) } } }};
    const off = [_]fm.ColumnData{.{ .float = .{ .values = &.{ 1.5000001, 0 }, .valid = &.{1} } }};
    const short = [_]fm.ColumnData{.{ .float = .{ .values = &.{1.5} } }};
    try testing.expect((try compare(a, c, exp, .{ .columns = &cols, .data = &good, .len = 2 })) == null);
    try testing.expect((try compare(a, c, exp, .{ .columns = &cols, .data = &off, .len = 2 })) != null);
    try testing.expect((try compare(a, c, exp, .{ .columns = &cols, .data = &short, .len = 1 })) != null);
    const wide = [_]Column{ cols[0], .{ .name = "z", .type = .float } };
    try testing.expect((try compare(a, c, exp, .{ .columns = &wide, .data = &.{}, .len = 0 })) != null);
    // the scalar comparison: missing meets missing, a text is exact, an int is not a float
    try testing.expect(matchK(.null, .{ .float = std.math.nan(f64) }, "float"));
    try testing.expect(!matchK(.{ .text = "a" }, .{ .text = "b" }, "text"));
    try testing.expect(!matchK(.{ .int = 1 }, .{ .float = 1 }, "int"));
    try testing.expect(matchK(.{ .float = 1 }, .{ .int = 1 }, "float"));
}

test "oracle2: pandas and polars vectors for the D2 verbs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    const sc = root.object.get("scalar").?.array.items;
    const fr = root.object.get("frames").?.array.items;
    try testing.expect(sc.len > 250 and fr.len > 250);
    var t: Tally = .{};

    for (sc) |c| {
        var case_arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer case_arena.deinit();
        const ca = case_arena.allocator();
        const id = jstr(c, "id");
        const engine = jstr(c, "engine");
        const fn_name = jstr(c, "fn");
        if (std.mem.eql(u8, engine, "none")) continue; // no engine had it: nothing to compare
        t.ran += 1;
        if (std.mem.eql(u8, engine, "gap")) {
            // A directive refused on purpose: the refusal itself is the contract.
            const args = c.object.get("args").?;
            if (dtf.translateFormat(ca, jstr(args, "fmt"))) |_| {
                t.failed += 1;
                std.debug.print("ORACLE2 {s}: format {s} is now accepted; move it out of the gap list\n", .{ id, jstr(args, "fmt") });
            } else |_| {}
            continue;
        }
        const want = c.object.get("expect").?.array.items;
        const why: ?[]const u8 = runScalarList(ca, c, want) catch |e| try ca.print("error {s}", .{@errorName(e)});
        const k = listed(id);
        if (why) |w| {
            if (k == null) {
                var other_ok = false;
                if (c.object.get("other")) |o| other_ok = (try runScalarList(ca, c, o.array.items)) == null;
                t.report(id, w, c, other_ok);
            } else t.known_hit += 1;
        } else if (k) |i| {
            if (known[i].always) {
                t.failed += 1;
                std.debug.print("ORACLE2 stale known-difference entry: {s} ({s})\n", .{ id, fn_name });
            }
        }
    }

    for (fr) |c| {
        var case_arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer case_arena.deinit();
        const ca = case_arena.allocator();
        const id = jstr(c, "id");
        const engine = jstr(c, "engine");
        if (std.mem.eql(u8, engine, "none") and !jbool(c, "expect_error", false)) continue;
        t.ran += 1;
        const k = listed(id);
        var why: ?[]const u8 = null;
        var type_why: ?[]const u8 = null;
        var other_ok = false;
        if (runFrame(ca, c)) |got| {
            if (jbool(c, "expect_error", false)) {
                why = "engines refuse, ours answers";
            } else {
                why = try compare(ca, c, c.object.get("expect").?, got);
                if (why == null) type_why = try compareTypes(ca, c, got);
                if (why != null) {
                    if (c.object.get("other")) |o| other_ok = (try compare(ca, c, o, got)) == null;
                }
            }
        } else |e| {
            if (e == error.NotCovered) {
                t.failed += 1;
                std.debug.print("ORACLE2 {s}: verb {s} is not wired in the replay\n", .{ id, jstr(c, "verb") });
                continue;
            }
            if (!jbool(c, "expect_error", false)) why = try ca.print("error {s}", .{@errorName(e)});
        }
        if (why == null) why = type_why;
        if (why) |w| {
            if (k == null) t.report(id, w, c, other_ok) else t.known_hit += 1;
        } else if (k) |i| {
            if (known[i].always) {
                t.failed += 1;
                std.debug.print("ORACLE2 stale known-difference entry: {s}\n", .{id});
            }
        }
    }
    if (t.failed != 0) {
        std.debug.print("ORACLE2 {d} of {d} cases differ ({d} match the other engine, {d} listed as known)\n", .{ t.failed, t.ran, t.flip, t.known_hit });
        return error.OracleMismatch;
    }
}

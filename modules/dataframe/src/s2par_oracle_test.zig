// SPDX-License-Identifier: MIT
//! Replays `oracle2k_vectors.json` (dataframe parity additions of 2026-11-10): what polars 2.1 and
//! pandas 3.1 answered for `str.extract_many` / `str.find_many`, `read_fwf`, `date_ranges` /
//! `datetime_ranges` / `linear_spaces`, `to_latex(index=False)`, `str.json_decode` and the
//! time-of-day (`pl.Time`) core (`tools/oracle2k.py` asked the engines; no line of this module is
//! consulted there). Every difference that is kept on purpose is in `known` with its reason; a
//! difference not listed there fails the test.
const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const fm = @import("frame.zig");
const vm = @import("value.zig");
const Frame = fm.Frame;
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const Expr = df.Expr;
const J = std.json.Value;

const vectors = @embedFile("oracle2k_vectors.json");

/// Deliberate differences from what the engine answered: a case id substring, the input cell
/// (null: the whole case) and why.
const Known = struct { id: []const u8, cell: ?[]const u8 = null, why: []const u8 };
const known = [_]Known{
    .{ .id = "extract_many-emptylist", .why = "polars refuses an empty pattern list (`str.extract_many` not supported for dtypes `str` and `list[null]`); an empty list matches nothing here, so every row is an empty list (a superset)" },
    .{ .id = "find_many-emptylist", .why = "as extract_many-emptylist" },
    .{ .id = "time-cast-str-lax", .why = "polars' `cast(pl.Time)` refuses every String (`str.to_time` is its route, replayed by time-str-to-time); `cast` here parses the text as `str.to_time(strict=False)` does (a superset)" },
    .{ .id = "time-cast-str-strict", .why = "as time-cast-str-lax: `cast` parses the text (strict: an unparsable text is `error.CastFailed`)" },
    .{ .id = "time-cast-str-from-time", .why = "polars' `cast(pl.String)` of a Time drops the fraction (`00:00:00.120` becomes `00:00:00`, a polars quirk: display, JSON and CSV keep it); the text here keeps it, so it reads back" },
    .{ .id = "time-cast-dur", .why = "polars counts a Time in nanoseconds, this module in microseconds (the unit of `.timestamp`/`.duration`): the Int64 and Duration counts are the polars ones divided by 1000" },
    .{ .id = "time-write-csv", .why = "polars writes a Time to CSV with nine fraction digits (`01:02:03.000000000`); this module writes the shortest form (`01:02:03`, groups of three digits), the form its JSON and display use and its reader reads back (open question to the coordinator)" },
    .{ .id = "time-repr-dtype", .why = "polars names the dtype `Time`; the dtype name of this module is the column type tag (`time`), checked by the display test" },
    .{ .id = "time-repr-series", .why = "the Series repr is not provided (frames only)" },
    .{ .id = "emptypat", .why = "polars matches an empty pattern at every byte offset (`find_many` lists 0..len, mid-character offsets of non-ASCII text included) and `extract_many` panics there (`start byte index is not a char boundary`); an empty pattern is `error.BadExpr` here, as for `replace_many`" },
    .{ .id = "emptyutf8", .why = "as emptypat: polars' empty pattern is degenerate (a panic on non-ASCII text); refused here" },
    .{ .id = "fwf-docs-noheader-nonames", .cell = "names", .why = "pandas names a header-less file's columns 0, 1, 2...; `readCsv` names them column_0... (polars), the module's one rule" },
    .{ .id = "fwf-overlap", .cell = "names", .why = "as fwf-docs-noheader-nonames" },
    .{ .id = "fwf-past-end", .cell = "names", .why = "as fwf-docs-noheader-nonames" },
    .{ .id = "fwf-reversed", .cell = "names", .why = "as fwf-docs-noheader-nonames" },
    .{ .id = "fwf-zero-width", .cell = "names", .why = "as fwf-docs-noheader-nonames" },
    .{ .id = "fwf-blank-short", .cell = "dtype", .why = "an int column with a missing cell stays Int64 with a null here; pandas' default numpy backend turns it into float64 NaN (the cells equal numerically)" },
    .{ .id = "fwf-cjk", .cell = "dtype", .why = "as fwf-blank-short: a short line leaves a null in an int column" },
    .{ .id = "fwf-na-default", .cell = "dtype", .why = "as fwf-blank-short: `NA` is a null in an int column" },
    .{ .id = "fwf-na-values", .cell = "dtype", .why = "as fwf-blank-short: a `na_values` cell is a null in an int column" },
    .{ .id = "fwf-past-end", .cell = "dtype", .why = "a column of nothing but empty cells is text here (`readCsv`'s rule for an all-null column); pandas types it float64 NaN" },
    .{ .id = "fwf-reversed", .cell = "dtype", .why = "as fwf-past-end: an all-empty column" },
    .{ .id = "fwf-zero-width", .cell = "dtype", .why = "as fwf-past-end: an all-empty column" },
    .{ .id = "jd-arrays-empty-only", .cell = "dtype", .why = "no Null type here: the element of lists that are all empty is text (polars `List(Null)`)" },
    .{ .id = "jd-empty-input", .cell = "dtype", .why = "no Null type here: a column of nothing decodes as text (polars `Null`)" },
    .{ .id = "jd-null-text", .cell = "dtype", .why = "as jd-empty-input: only JSON `null`s" },
    .{ .id = "jd-only-none", .cell = "dtype", .why = "as jd-empty-input: only nulls" },
    .{ .id = "jd-objects-null-field", .cell = "dtype", .why = "as jd-empty-input: a struct field that is always null is text" },
    .{ .id = "jd-bad-lone-surrogate", .why = "polars decodes the JSON text `\"\\ud800\"` to a NUL character (an engine defect); a lone surrogate cannot be UTF-8, so it is `error.BadJson` here" },
    .{ .id = "jd-dtype-i64-float", .why = "polars' `json_decode(Int64)` truncates `1.5` to 1; a declared integer type is read as `readCsv` reads the text here: `error.BadValue`" },
    .{ .id = "jd-dtype-i8-big", .why = "polars' `json_decode(Int8)` turns an out-of-range 300 into null; here it is `error.BadValue` (documented: out of range is refused)" },
    .{ .id = "jd-dtype-struct", .why = "polars' `json_decode(Struct({'a': Int64}))` keeps only the declared field; here the fields of a declared struct are inferred, never imposed (`JsonDecodeSpec.type`)" },
    .{ .id = "jd-dtype-str-obj", .why = "polars refuses a nested value under `dtype=String`; here a nested value under a text type is its source text (documented)" },
    .{ .id = "jd-mix-arr-obj", .why = "polars refuses cells of different JSON kinds that it cannot unify; a mix is text in its source form here (documented, a superset)" },
    .{ .id = "jd-mix-num-obj", .why = "as jd-mix-arr-obj" },
    .{ .id = "jd-mix-arr-int", .why = "polars wraps a scalar in a list to meet an array (`2` becomes `[2]`); a mix of kinds is text in its source form here" },
    .{ .id = "jd-mix-int-bool", .why = "polars reads `true` as the integer 1 beside an integer; a mix of kinds is text here" },
    .{ .id = "jd-scalars-u64", .cell = "dtype", .why = "polars widens an integer above Int64 to Int128; there is no Int128 here, the number stays text in its source form (as for 2^63, which polars reads as a string too)" },
    .{ .id = "jd-scalars-u64", .cell = "cells", .why = "as the dtype: the text of the number" },
    .{ .id = "time-csv-try-parse-blank", .why = "a blank line is a skipped line to `readCsv`, in a one-column file too (D1's rule; polars keeps it as a null row)" },
    .{ .id = "time-csv-try-parse-hm", .why = "polars refuses a column that mixes HH:MM:SS with HH:MM; here both shapes read as Time (a superset)" },
    .{ .id = "time-csv-schema-t-hm", .why = "as time-csv-try-parse-hm: a declared Time reads both HH:MM:SS and HH:MM here (a superset)" },
    .{ .id = "time-csv-probe-schema-trail-space", .why = "polars refuses a trailing blank under a Time schema; `readCsv` trims blanks around a cell before reading it (D1's rule)" },
    .{ .id = "time-repr-pl", .why = "the display of `format` is a plain aligned table, not polars' box; the Time cells read the same (checked cell by cell by the display tests)" },
};

fn knownCell(id: []const u8, cell: ?[]const u8) bool {
    for (known) |k| {
        if (std.mem.find(u8, id, k.id) == null) continue;
        if (k.cell == null) return true;
        if (cell) |c| if (std.mem.eql(u8, c, k.cell.?)) return true;
    }
    return false;
}

const Tally = struct {
    run: usize = 0,
    bad: usize = 0,
    out: std.Io.Writer.Allocating,

    fn miss(t: *Tally, comptime fmt: []const u8, args: anytype) void {
        t.bad += 1;
        if (t.bad <= 300) t.out.writer.print(fmt ++ "\n", args) catch {};
    }
};

fn get(o: J, k: []const u8) ?J {
    return o.object.get(k);
}

fn strOf(o: J, k: []const u8) []const u8 {
    return o.object.get(k).?.string;
}

fn isErrCell(j: J) bool {
    return j == .object and j.object.get("error") != null;
}

fn jnum(j: J) ?f64 {
    return switch (j) {
        .integer => |i| @floatFromInt(i),
        .float => |x| x,
        .string => |s| if (std.mem.eql(u8, s, "nan")) std.math.nan(f64) else if (std.mem.eql(u8, s, "inf")) std.math.inf(f64) else if (std.mem.eql(u8, s, "-inf")) -std.math.inf(f64) else null,
        else => null,
    };
}

fn jint(j: J) ?i64 {
    return switch (j) {
        .integer => |i| i,
        else => null,
    };
}

/// A short text of a cell for a failure line.
fn jtext(a: std.mem.Allocator, j: J) []const u8 {
    return std.json.Stringify.valueAlloc(a, j, .{}) catch "?";
}

fn vtext(a: std.mem.Allocator, v: Value) []const u8 {
    return switch (v) {
        .null => "null",
        .int => |i| a.print("{d}", .{i}) catch "?",
        .uint => |i| a.print("{d}", .{i}) catch "?",
        .float => |x| a.print("{d}", .{x}) catch "?",
        .text => |s| a.print("\"{s}\"", .{s}) catch "?",
        .bool => |b| if (b) "true" else "false",
        .list => |l| blk: {
            var o: std.ArrayList(u8) = .empty;
            o.append(a, '[') catch {};
            for (0..l.len()) |i| {
                if (i > 0) o.append(a, ',') catch {};
                o.appendSlice(a, vtext(a, l.get(i))) catch {};
            }
            o.append(a, ']') catch {};
            break :blk o.items;
        },
        .record => |r| blk: {
            var o: std.ArrayList(u8) = .empty;
            o.append(a, '{') catch {};
            for (0..r.len()) |i| {
                if (i > 0) o.append(a, ',') catch {};
                o.print(a, "{s}:{s}", .{ r.name(i), vtext(a, r.get(i)) }) catch {};
            }
            o.append(a, '}') catch {};
            break :blk o.items;
        },
        .decimal => "decimal",
    };
}

/// A cell of the vectors as the cell of a column of `col`'s type: exact, a NaN equal to a NaN.
fn cellEq(want: J, got: Value, col: Column) bool {
    if (want == .null) return got == .null;
    if (got == .null) return false;
    switch (col.type) {
        .list => {
            if (want != .array or got != .list) return false;
            if (want.array.items.len != got.list.len()) return false;
            for (want.array.items, 0..) |w, i| if (!cellEq(w, got.list.get(i), col.inner[0])) return false;
            return true;
        },
        .@"struct" => {
            if (want != .object or got != .record) return false;
            if (want.object.count() != got.record.len()) return false;
            for (col.inner) |f| {
                const w = want.object.get(f.name) orelse return false;
                const g = got.record.field(f.name) orelse return false;
                if (!cellEq(w, g, f)) return false;
            }
            return true;
        },
        .float, .float32 => {
            const g = got.asFloat() orelse return false;
            const w = jnum(want) orelse return false;
            if (std.math.isNan(w)) return std.math.isNan(g);
            return @as(u64, @bitCast(w)) == @as(u64, @bitCast(g));
        },
        .text, .date => return want == .string and got == .text and std.mem.eql(u8, want.string, got.text),
        .bool => return want == .bool and got == .bool and want.bool == got.bool,
        else => {
            const w = jint(want) orelse return false;
            return got == .int and got.int == w;
        },
    }
}

fn columnOf(name: []const u8, ty: ColumnType) Column {
    return .{ .name = name, .type = ty };
}

fn textFrame(a: std.mem.Allocator, name: []const u8, vals: []const J) !Frame {
    const cols = try a.alloc(Column, 1);
    cols[0] = columnOf(name, .text);
    var b = try fm.FrameBuilder.init(a, cols, vals.len);
    for (vals) |j| try b.appendRow(&.{if (j == .string) Value{ .text = j.string } else .null});
    return b.toOwned();
}

// ── a) extract_many / find_many ────────────────────────────────────────────────

const X: Expr = .{ .col = "x" };

fn replayMany(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const offsets = std.mem.eql(u8, strOf(c, "kind"), "find_many");
    const input = get(c, "in").?;
    const texts = get(input, "text").?.array.items;
    const pj = get(input, "patterns").?.array.items;
    const pats = try a.alloc([]const u8, pj.len);
    for (pj, pats) |j, *p| p.* = j.string;
    const fold = get(input, "ascii_case_insensitive").?.bool;
    const ov = get(input, "overlapping").?.bool;
    const lm = get(input, "leftmost").?.bool;
    const e: Expr = if (offsets)
        .{ .find_many = .{ .x = &X, .patterns = pats, .ascii_case_insensitive = fold, .overlapping = ov, .leftmost = lm } }
    else
        .{ .extract_many = .{ .x = &X, .patterns = pats, .ascii_case_insensitive = fold, .overlapping = ov, .leftmost = lm } };
    t.run += 1;
    const f = try textFrame(a, "x", texts);
    const r = df.mutate(a, f, &.{.{ .out = "out", .expr = e }});
    if (get(c, "error").?.bool) {
        if (r) |_| {
            if (!knownCell(id, null)) t.miss("{s}: the engine refused ({s}), got a result", .{ id, strOf(c, "msg") });
        } else |_| {}
        return;
    }
    const g = r catch |err| {
        if (!knownCell(id, null)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    const want = get(c, "expect").?.array.items;
    const elem: Column = columnOf("", if (offsets) .int else .text);
    const col: Column = .{ .name = "out", .type = .list, .inner = &.{elem} };
    for (want, 0..) |w, i| {
        const got = g.cell(i, "out").?;
        if (!cellEq(w, got, col) and !knownCell(id, null))
            t.miss("{s} [{s}] patterns {s} fold={} ov={} lm={}: want {s}, got {s}", .{ id, jtext(a, texts[i]), jtext(a, get(input, "patterns").?), fold, ov, lm, jtext(a, w), vtext(a, got) });
    }
}

// ── b) read_fwf ────────────────────────────────────────────────────────────────

fn typeOfName(n: []const u8) ?ColumnType {
    const map = [_]struct { []const u8, ColumnType }{
        .{ "i64", .int },    .{ "f64", .float },   .{ "str", .text },     .{ "bool", .bool },    .{ "date", .date },  .{ "time", .time },
        .{ "i8", .int8 },    .{ "i16", .int16 },   .{ "i32", .int32 },    .{ "u8", .uint8 },     .{ "u16", .uint16 }, .{ "u32", .uint32 },
        .{ "u64", .uint64 }, .{ "f32", .float32 }, .{ "ts", .timestamp }, .{ "dur", .duration },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], n)) return m[1];
    return null;
}

fn replayFwf(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const input = get(c, "in").?;
    const text = strOf(input, "text");
    const o = get(input, "opts").?;
    var opts: df.FwfReadOptions = .{};
    if (get(o, "widths")) |w| {
        const ws = try a.alloc(usize, w.array.items.len);
        for (w.array.items, ws) |j, *x| x.* = @intCast(j.integer);
        opts.spec = .{ .widths = ws };
    } else if (get(o, "colspecs")) |cs| {
        if (cs == .array) {
            const specs = try a.alloc(df.Colspec, cs.array.items.len);
            for (cs.array.items, specs) |j, *x| x.* = .{ .start = @intCast(j.array.items[0].integer), .end = @intCast(j.array.items[1].integer) };
            opts.spec = .{ .colspecs = specs };
        } else opts.spec = .infer;
    }
    if (get(o, "infer_nrows")) |n| opts.infer_nrows = @intCast(n.integer);
    if (get(o, "delimiter")) |d| opts.delimiter = d.string;
    var names: ?[]const []const u8 = null;
    if (get(o, "names")) |ns| {
        const arr = try a.alloc([]const u8, ns.array.items.len);
        for (ns.array.items, arr) |j, *x| x.* = j.string;
        names = arr;
    }
    opts.csv.names = names;
    // pandas: `header` absent means 0 without `names` and None with them.
    opts.csv.has_header = if (get(o, "header")) |h| h != .null else names == null;
    if (get(o, "skiprows")) |n| opts.csv.skip_rows = @intCast(n.integer);
    if (get(o, "nrows")) |n| opts.csv.n_rows = @intCast(n.integer);
    if (get(o, "dtype")) |d| {
        const ov = try a.alloc(df.TypeOverride, d.object.count());
        var it = d.object.iterator();
        var i: usize = 0;
        while (it.next()) |en| : (i += 1) ov[i] = .{ .name = en.key_ptr.*, .type = typeOfName(en.value_ptr.string).? };
        opts.csv.types = ov;
    }
    if (get(o, "na_values")) |nv| {
        var list: std.ArrayList([]const u8) = .empty;
        try list.appendSlice(a, &df.pandas_na_values);
        for (nv.array.items) |j| try list.append(a, j.string);
        opts.csv.null_values = list.items;
    }
    t.run += 1;
    const r = df.readFwf(a, text, opts);
    if (get(c, "error").?.bool) {
        if (r) |_| {
            if (!knownCell(id, null)) t.miss("{s}: pandas refused ({s}), got a frame", .{ id, strOf(c, "msg") });
        } else |_| {}
        return;
    }
    const g = r catch |err| {
        if (!knownCell(id, null)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    const want = get(c, "expect").?;
    const wcols = get(want, "columns").?.array.items;
    const wtypes = get(want, "dtypes").?.array.items;
    const rows = get(want, "rows").?.array.items;
    if (g.columns.len != wcols.len) {
        t.miss("{s}: {d} columns, pandas {d}", .{ id, g.columns.len, wcols.len });
        return;
    }
    for (g.columns, wcols, wtypes) |col, wn, wt| {
        if (!std.mem.eql(u8, col.name, wn.string) and !knownCell(id, "names")) t.miss("{s}: column named {s}, pandas {s}", .{ id, col.name, wn.string });
        if (col.type != typeOfName(wt.string).? and !knownCell(id, "dtype")) t.miss("{s}: column {s} is {s}, pandas {s}", .{ id, col.name, @tagName(col.type), wt.string });
    }
    if (g.len != rows.len) {
        t.miss("{s}: {d} rows, pandas {d}", .{ id, g.len, rows.len });
        return;
    }
    for (rows, 0..) |row, ri| for (row.array.items, 0..) |w, ci| {
        const got = g.cell(ri, g.columns[ci].name).?;
        // A text column of a numeric-looking cell is compared as the text it holds.
        const numeric = w == .float and got == .int and knownCell(id, "dtype") and w.float == @as(f64, @floatFromInt(got.int));
        if (!cellEq(w, got, g.columns[ci]) and !numeric and !knownCell(id, null)) t.miss("{s} [{d},{d}]: want {s}, got {s}", .{ id, ri, ci, jtext(a, w), vtext(a, got) });
    };
}

// ── c) ranges ──────────────────────────────────────────────────────────────────

fn closedOf(s: []const u8) df.Closed {
    if (std.mem.eql(u8, s, "left")) return .left;
    if (std.mem.eql(u8, s, "right")) return .right;
    if (std.mem.eql(u8, s, "none")) return .none;
    return .both;
}

fn parseDate(j: J) ?df.Date {
    if (j != .string) return null;
    const s = j.string;
    return .{
        .y = std.fmt.parseInt(i32, s[0..4], 10) catch unreachable,
        .m = std.fmt.parseInt(u8, s[5..7], 10) catch unreachable,
        .d = std.fmt.parseInt(u8, s[8..10], 10) catch unreachable,
    };
}

fn replayRanges(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const kind = strOf(c, "kind");
    const input = get(c, "in").?;
    const sj = get(input, "starts").?.array.items;
    const ej = get(input, "ends").?.array.items;
    const closed = closedOf(strOf(input, "closed"));
    t.run += 1;
    var inner_ty: ColumnType = .float;
    const r: anyerror!Frame = blk: {
        if (std.mem.eql(u8, kind, "date_ranges")) {
            inner_ty = .date;
            const ss = try a.alloc(?df.Date, sj.len);
            for (sj, ss) |j, *x| x.* = parseDate(j);
            const es = try a.alloc(?df.Date, ej.len);
            for (ej, es) |j, *x| x.* = parseDate(j);
            break :blk df.dateRanges(a, "r", ss, es, .{ .interval = strOf(input, "interval"), .closed = closed });
        } else if (std.mem.eql(u8, kind, "datetime_ranges")) {
            inner_ty = .timestamp;
            const ss = try a.alloc(?i64, sj.len);
            for (sj, ss) |j, *x| x.* = jint(j);
            const es = try a.alloc(?i64, ej.len);
            for (ej, es) |j, *x| x.* = jint(j);
            break :blk df.datetimeRanges(a, "r", ss, es, .{ .interval = strOf(input, "interval"), .closed = closed });
        } else {
            const ss = try a.alloc(?f64, sj.len);
            for (sj, ss) |j, *x| x.* = if (j == .null) null else jnum(j);
            const es = try a.alloc(?f64, ej.len);
            for (ej, es) |j, *x| x.* = if (j == .null) null else jnum(j);
            const nj = get(input, "num_samples").?.array.items;
            const ns = try a.alloc(?usize, nj.len);
            for (nj, ns) |j, *x| {
                const n = if (j == .null) null else jint(j).?;
                if (n != null and n.? < 0) return; // a usize cannot hold it; polars refuses it
                x.* = if (n) |v| @intCast(v) else null;
            }
            break :blk df.linearSpaces(a, "r", ss, es, ns, closed);
        }
    };
    if (get(c, "error").?.bool) {
        if (r) |_| {
            if (!knownCell(id, null)) t.miss("{s}: the engine refused ({s}), got a frame", .{ id, strOf(c, "msg") });
        } else |_| {}
        return;
    }
    const g = r catch |err| {
        if (!knownCell(id, null)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    const want = get(c, "expect").?.array.items;
    if (g.len != want.len) {
        if (!knownCell(id, null)) t.miss("{s}: {d} rows, engine {d}", .{ id, g.len, want.len });
        return;
    }
    const elem = columnOf("", inner_ty);
    const col: Column = .{ .name = "r", .type = .list, .inner = &.{elem} };
    for (want, 0..) |w, i| {
        const got = g.cell(i, "r").?;
        if (!cellEq(w, got, col) and !knownCell(id, null)) t.miss("{s} row {d}: want {s}, got {s}", .{ id, i, jtext(a, w), vtext(a, got) });
    }
}

// ── d) to_latex ────────────────────────────────────────────────────────────────

fn replayLatex(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const input = get(c, "in").?;
    const cj = get(input, "columns").?.array.items;
    const cols = try a.alloc(Column, cj.len);
    var n: usize = 0;
    for (cj, cols) |j, *col| {
        col.* = columnOf(strOf(j, "name"), typeOfName(if (std.mem.eql(u8, strOf(j, "dtype"), "Int64")) "i64" else if (std.mem.eql(u8, strOf(j, "dtype"), "boolean")) "bool" else strOf(j, "dtype")).?);
        n = get(j, "values").?.array.items.len;
    }
    var b = try fm.FrameBuilder.init(a, cols, n);
    for (0..n) |ri| {
        const row = try a.alloc(Value, cols.len);
        for (cj, cols, row) |j, col, *cell| {
            const w = get(j, "values").?.array.items[ri];
            cell.* = switch (w) {
                .null => .null,
                .bool => |x| .{ .bool = x },
                .integer => |x| if (col.type == .float) .{ .float = @floatFromInt(x) } else .{ .int = x },
                .float => |x| .{ .float = x },
                .string => |s| if (col.type == .float) .{ .float = jnum(w).? } else .{ .text = s },
                else => unreachable,
            };
        }
        try b.appendRow(row);
    }
    const f = try b.toOwned();
    const o = get(input, "opts").?;
    var opts: df.LatexOptions = .{};
    if (get(o, "escape")) |x| opts.escape = x.bool;
    if (get(o, "na_rep")) |x| opts.null_text = x.string;
    if (get(o, "caption")) |x| opts.caption = x.string;
    if (get(o, "label")) |x| opts.label = x.string;
    if (get(o, "header")) |x| opts.header = x.bool;
    t.run += 1;
    const got = df.toLatex(a, f, opts) catch |err| {
        if (!knownCell(id, null)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    const want = get(c, "expect").?.array.items[0].string;
    if (!std.mem.eql(u8, want, got) and !knownCell(id, null)) t.miss("{s}:\n want {f}\n  got {f}", .{ id, std.zig.fmtString(want), std.zig.fmtString(got) });
}

// ── e) json_decode ─────────────────────────────────────────────────────────────

fn treeOk(want: J, col: Column) bool {
    const tn = strOf(want, "t");
    if (std.mem.eql(u8, tn, "list")) return col.type == .list and col.inner.len == 1 and treeOk(get(want, "inner").?, col.inner[0]);
    if (std.mem.eql(u8, tn, "struct")) {
        const fs = get(want, "fields").?.array.items;
        if (col.type != .@"struct" or col.inner.len != fs.len) return false;
        for (fs, col.inner) |f, ic| if (!std.mem.eql(u8, strOf(f, "name"), ic.name) or !treeOk(f, ic)) return false;
        return true;
    }
    const ty = typeOfName(tn) orelse return false;
    return col.type == ty;
}

fn treeName(a: std.mem.Allocator, col: Column) []const u8 {
    if (col.type == .list and col.inner.len == 1) return a.print("list[{s}]", .{treeName(a, col.inner[0])}) catch "?";
    if (col.type == .@"struct") {
        var o: std.ArrayList(u8) = .empty;
        o.appendSlice(a, "struct{") catch {};
        for (col.inner, 0..) |f, i| o.print(a, "{s}{s}:{s}", .{ if (i > 0) "," else "", f.name, treeName(a, f) }) catch {};
        o.append(a, '}') catch {};
        return o.items;
    }
    return @tagName(col.type);
}

fn dtypeArg(s: []const u8) ?ColumnType {
    const map = [_]struct { []const u8, ColumnType }{
        .{ "Int8", .int8 }, .{ "String", .text }, .{ "Float64", .float }, .{ "Int64", .int }, .{ "Boolean", .bool }, .{ "Date", .date },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], s)) return m[1];
    if (std.mem.startsWith(u8, s, "List")) return .list;
    if (std.mem.startsWith(u8, s, "Struct")) return .@"struct";
    return null;
}

fn replayJson(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const input = get(c, "in").?;
    const vals = get(input, "values").?.array.items;
    var spec: df.JsonDecodeSpec = .{ .column = "j" };
    if (get(input, "dtype")) |d| spec.type = dtypeArg(d.string).?;
    t.run += 1;
    const f = try textFrame(a, "j", vals);
    const r = df.jsonDecode(a, f, spec);
    if (get(c, "error").?.bool) {
        if (r) |_| {
            if (!knownCell(id, null)) t.miss("{s}: polars refused ({s}), got a frame", .{ id, strOf(c, "msg") });
        } else |_| {}
        return;
    }
    const g = r catch |err| {
        if (!knownCell(id, null)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    const want = get(c, "expect").?;
    const col = g.columns[0];
    if (!treeOk(get(want, "dtype").?, col) and !knownCell(id, "dtype")) t.miss("{s}: dtype {s}, polars {s}", .{ id, treeName(a, col), jtext(a, get(want, "dtype").?) });
    const cells = get(want, "cells").?.array.items;
    if (g.len != cells.len) {
        t.miss("{s}: {d} rows, polars {d}", .{ id, g.len, cells.len });
        return;
    }
    for (cells, 0..) |w, i| {
        const got = g.cell(i, "j").?;
        if (!cellEq(w, got, col) and !knownCell(id, "cells")) t.miss("{s} row {d}: want {s}, got {s}", .{ id, i, jtext(a, w), vtext(a, got) });
    }
}

// ── f) the time core ───────────────────────────────────────────────────────────

/// Microseconds of a polars nanosecond count (the module's unit; digits past the sixth dropped).
fn usOfNs(ns: i64) i64 {
    return @divFloor(ns, 1000);
}

fn timeFrame(a: std.mem.Allocator, ns: []const J, withN: bool) !Frame {
    const cols = try a.dupe(Column, &.{ columnOf("t", .time), columnOf("n", .int) });
    const use = if (withN) cols else cols[0..1];
    var b = try fm.FrameBuilder.init(a, use, ns.len);
    for (ns, 0..) |j, i| {
        const tv: Value = if (j == .null) .null else .{ .int = usOfNs(j.integer) };
        if (withN) try b.appendRow(&.{ tv, .{ .int = @intCast(i + 1) } }) else try b.appendRow(&.{tv});
    }
    return b.toOwned();
}

fn replayTimeCast(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const kind = strOf(c, "kind");
    const op = strOf(c, "op");
    const input = get(c, "in").?;
    const from_text = std.mem.eql(u8, kind, "time_cast_str");
    const vals = get(input, if (from_text) "values" else "ns").?.array.items;
    const want = get(c, "expect").?.array.items;
    if (from_text and (std.mem.eql(u8, op, "strict") or std.mem.eql(u8, op, "lax"))) {
        // polars refuses every cell (known); replayed so a cell it would accept is noticed.
        for (vals, want) |v, w| {
            t.run += 1;
            if (!isErrCell(w) and !knownCell(id, null)) t.miss("{s} [{s}]: polars answered {s}", .{ id, jtext(a, v), jtext(a, w) });
        }
        return;
    }
    const strict = std.mem.eql(u8, op, "strict");
    for (vals, want) |v, w| {
        t.run += 1;
        const cell_txt = jtext(a, v);
        const f = if (from_text) try textFrame(a, "a", &.{v}) else blk: {
            const cols = try a.dupe(Column, &.{columnOf("a", .int)});
            var b = try fm.FrameBuilder.init(a, cols, 1);
            try b.appendRow(&.{.{ .int = usOfNs(v.integer) }});
            break :blk try b.toOwned();
        };
        const r = df.cast(a, f, .{ .col = "a", .to = .time, .on_error = if (strict) .fail else .null });
        const got: Value = if (r) |g| g.cell(0, "a").? else |_| .{ .text = "<error>" };
        const ok = if (isErrCell(w) or w == .null)
            (got == .null or (got == .text and std.mem.eql(u8, got.text, "<error>")))
        else
            got == .int and got.int == usOfNs(w.integer);
        if (!ok and !knownCell(id, cell_txt)) t.miss("{s} [{s}]: want {s}, got {s}", .{ id, cell_txt, jtext(a, w), vtext(a, got) });
    }
}

fn replayTimeToStr(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const ns = get(get(c, "in").?, "ns").?.array.items;
    const want = get(c, "expect").?.array.items;
    const f = try timeFrame(a, ns, false);
    t.run += 1;
    const g = try df.cast(a, f, .{ .col = "t", .to = .text });
    for (want, 0..) |w, i| {
        const got = g.cell(i, "t").?;
        if (!cellEq(w, got, g.columns[0]) and !knownCell(id, null)) t.miss("{s} row {d}: want {s}, got {s}", .{ id, i, jtext(a, w), vtext(a, got) });
    }
}

fn replayTimeOut(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const ns = get(get(c, "in").?, "ns").?.array.items;
    const want = get(c, "expect").?;
    const f = try timeFrame(a, ns, false);
    t.run += 1;
    const d = try df.cast(a, f, .{ .col = "t", .to = .duration });
    const i = try df.cast(a, f, .{ .col = "t", .to = .int });
    const wd = get(want, "dur_us").?.array.items;
    const wi = get(want, "i64").?.array.items;
    for (wd, wi, 0..) |x, y, k| {
        if (!cellEq(x, d.cell(k, "t").?, columnOf("t", .duration)) and !knownCell(id, null)) t.miss("{s} duration row {d}: want {s}, got {s}", .{ id, k, jtext(a, x), vtext(a, d.cell(k, "t").?) });
        if (!cellEq(y, i.cell(k, "t").?, columnOf("t", .int)) and !knownCell(id, null)) t.miss("{s} int row {d}: want {s}, got {s}", .{ id, k, jtext(a, y), vtext(a, i.cell(k, "t").?) });
    }
}

fn replayTimeCsv(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const input = get(c, "in").?;
    const text = strOf(input, "text");
    const o = get(input, "opts").?;
    var opts: df.CsvReadOptions = .{};
    if (get(o, "try_parse_dates")) |x| opts.parse_dates = x.bool;
    if (get(o, "schema_overrides")) |so| {
        const ov = try a.alloc(df.TypeOverride, so.object.count());
        var it = so.object.iterator();
        var i: usize = 0;
        while (it.next()) |en| : (i += 1) ov[i] = .{ .name = en.key_ptr.*, .type = .time };
        opts.types = ov;
    }
    t.run += 1;
    const r = df.readCsv(a, text, opts);
    if (get(c, "error").?.bool) {
        if (r) |_| {
            if (!knownCell(id, null)) t.miss("{s}: polars refused ({s}), got a frame", .{ id, strOf(c, "msg") });
        } else |_| {}
        return;
    }
    const g = r catch |err| {
        if (!knownCell(id, null)) t.miss("{s}: {s}", .{ id, @errorName(err) });
        return;
    };
    const want = get(c, "expect").?;
    const wcols = get(want, "columns").?.array.items;
    const wt = get(want, "dtypes").?.array.items;
    const rows = get(want, "rows").?.array.items;
    if (g.columns.len != wcols.len or g.len != rows.len) {
        if (!knownCell(id, null)) t.miss("{s}: shape {d}x{d}, polars {d}x{d}", .{ id, g.len, g.columns.len, rows.len, wcols.len });
        return;
    }
    for (g.columns, wt) |col, d| if (!treeOk(d, col) and !knownCell(id, "dtype")) t.miss("{s}: column {s} is {s}, polars {s}", .{ id, col.name, @tagName(col.type), jtext(a, d) });
    for (rows, 0..) |row, ri| for (row.array.items, 0..) |w, ci| {
        const col = g.columns[ci];
        const got = g.cell(ri, col.name).?;
        const ok = if (col.type == .time and w != .null) got == .int and got.int == usOfNs(w.integer) else cellEq(w, got, col);
        if (!ok and !knownCell(id, null)) t.miss("{s} [{d},{d}]: want {s}, got {s}", .{ id, ri, ci, jtext(a, w), vtext(a, got) });
    };
}

fn replayTimeWrite(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const op = strOf(c, "op");
    const input = get(c, "in").?;
    const ns = get(input, "ns").?.array.items;
    const one = std.mem.eql(u8, op, "write_json_col");
    const f = try timeFrame(a, ns, !one);
    var out: std.Io.Writer.Allocating = .init(a);
    t.run += 1;
    if (std.mem.eql(u8, op, "write_csv")) {
        try df.writeCsv(a, &out.writer, f, .{});
    } else if (std.mem.eql(u8, op, "write_ndjson")) {
        try df.writeNdjson(&out.writer, f);
    } else try df.writeJson(&out.writer, f, .records);
    const want = get(c, "expect").?.array.items[0].string;
    if (!std.mem.eql(u8, want, out.written()) and !knownCell(id, null)) t.miss("{s}:\n want {f}\n  got {f}", .{ id, std.zig.fmtString(want), std.zig.fmtString(out.written()) });
}

fn replayTimeRepr(a: std.mem.Allocator, c: J, t: *Tally) !void {
    const id = strOf(c, "id");
    const op = strOf(c, "op");
    if (!std.mem.eql(u8, op, "str_frame")) {
        t.run += 1;
        if (!knownCell(id, null)) t.miss("{s}: not replayed and not known", .{id});
        return;
    }
    const ns = get(get(c, "in").?, "ns").?.array.items;
    const f = try timeFrame(a, ns, true);
    t.run += 1;
    const got = try df.format(a, f, .{});
    const want = get(c, "expect").?.array.items[0].string;
    if (!std.mem.eql(u8, want, got) and !knownCell(id, null)) t.miss("{s}:\n want {f}\n  got {f}", .{ id, std.zig.fmtString(want), std.zig.fmtString(got) });
}

test "parity oracle: polars and pandas on the 2026-11-10 additions" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try std.json.parseFromSliceLeaky(J, a, vectors, .{});
    var t: Tally = .{ .out = .init(a) };
    for (doc.array.items) |c| {
        const kind = strOf(c, "kind");
        if (std.mem.eql(u8, kind, "extract_many") or std.mem.eql(u8, kind, "find_many")) try replayMany(a, c, &t) else if (std.mem.eql(u8, kind, "read_fwf")) try replayFwf(a, c, &t) else if (std.mem.eql(u8, kind, "date_ranges") or std.mem.eql(u8, kind, "datetime_ranges") or std.mem.eql(u8, kind, "linear_spaces")) try replayRanges(a, c, &t) else if (std.mem.eql(u8, kind, "to_latex")) try replayLatex(a, c, &t) else if (std.mem.eql(u8, kind, "json_decode")) try replayJson(a, c, &t) else if (std.mem.eql(u8, kind, "time_cast_str") or std.mem.eql(u8, kind, "time_cast_int")) try replayTimeCast(a, c, &t) else if (std.mem.eql(u8, kind, "time_to_str")) try replayTimeToStr(a, c, &t) else if (std.mem.eql(u8, kind, "time_cast_out")) try replayTimeOut(a, c, &t) else if (std.mem.eql(u8, kind, "time_read_csv")) try replayTimeCsv(a, c, &t) else if (std.mem.eql(u8, kind, "time_write")) try replayTimeWrite(a, c, &t) else if (std.mem.eql(u8, kind, "time_repr")) try replayTimeRepr(a, c, &t) else {
            t.miss("{s}: kind {s} has no replay", .{ strOf(c, "id"), kind });
        }
    }
    if (t.bad != 0) {
        std.debug.print("parity oracle: {d} of {d} cases or cells differ:\n{s}", .{ t.bad, t.run, t.out.written() });
        return error.TestUnexpectedResult;
    }
    try testing.expect(t.run > 500);
}

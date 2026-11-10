// SPDX-License-Identifier: MIT
//! A `Frame` as text for people: `format` (pandas `to_string(index=False)` with polars'
//! way of cutting a big frame: the first and last rows around a `…` row, the first and
//! last columns around a `…` column) and `toMarkdown` (a pipe table, pandas
//! `to_markdown(index=False)`). Widths count code points, not terminal cells: wide
//! characters misalign, as in pandas.

const std = @import("std");
const value = @import("value.zig");
const frame_mod = @import("frame.zig");
const textio = @import("textio.zig");
const dtype = @import("dtype.zig");
const jsonio = @import("jsonio.zig");
const bf = @import("binfn.zig");

const Frame = frame_mod.Frame;
const Value = value.Value;
const ColumnType = value.ColumnType;

pub const FormatOptions = struct {
    /// Rows shown: the first `ceil(max_rows / 2)` and the last `floor(max_rows / 2)`,
    /// a `…` row between when rows were left out.
    max_rows: usize = 10,
    /// Columns shown, cut the same way.
    max_cols: usize = 12,
    /// A cell longer than this (in code points) ends in `…` (polars `fmt_str_lengths`).
    max_cell_chars: usize = 32,
    /// What a null cell shows (polars `null`; pandas `<NA>`/`NaN`).
    null_text: []const u8 = "null",
    /// A row of column types under the header (polars shows `i64`, `str`...).
    show_dtypes: bool = false,
    /// A first line `shape: (rows, columns)` (polars).
    show_shape: bool = false,
};

pub const MarkdownOptions = struct {
    null_text: []const u8 = "null",
};

pub const RenderError = std.mem.Allocator.Error || std.Io.Writer.Error;

fn cpLen(s: []const u8) usize {
    return std.unicode.utf8CountCodepoints(s) catch s.len;
}

/// Byte length of the first `n` code points of `s` (all of it if it has fewer, or is not UTF-8).
fn prefixBytes(s: []const u8, n: usize) usize {
    var i: usize = 0;
    var k: usize = 0;
    while (i < s.len and k < n) : (k += 1) {
        // Not UTF-8 from here on: count the rest in bytes, after the code points so far.
        const l = std.unicode.utf8ByteSequenceLength(s[i]) catch return @min(i +| (n - k), s.len);
        i += l;
    }
    return @min(i, s.len);
}

/// The text of a cell, with control characters written as escapes and a long text cut.
fn cellText(a: std.mem.Allocator, v: Value, col: value.Column, null_text: []const u8, max_chars: usize, md: bool) std.mem.Allocator.Error![]const u8 {
    const ty = col.type;
    var nb: [textio.max_float_len + 8]u8 = undefined;
    var sb: [textio.max_stamp_len]u8 = undefined;
    var db: [textio.max_decimal_len]u8 = undefined;
    var ub: [value.max_duration_len]u8 = undefined;
    const s: []const u8 = switch (v) {
        .null => return null_text,
        .bool => |b| if (b) "True" else "False",
        .int => |i| if (ty == .timestamp)
            textio.formatStampZoned(&sb, i, if (textio.hasFraction(i)) 6 else 0, textio.zoneOf(col.time_zone))
        else if (ty == .duration)
            value.formatDuration(&ub, i)
        else if (ty == .time)
            value.formatTimeOfDay(ub[0..value.max_time_len], i) orelse "null"
        else
            std.fmt.bufPrint(&nb, "{d}", .{i}) catch unreachable,
        .float => |x| if (std.math.isNan(x)) "NaN" else if (std.math.isInf(x)) (if (x > 0) "inf" else "-inf") else if (ty == .float32) textio.formatFloat32(nb[0..textio.max_float_len], @floatCast(x)) else textio.formatFloat(nb[0..textio.max_float_len], x),
        .uint => |u| std.fmt.bufPrint(&nb, "{d}", .{u}) catch unreachable, // 20 digits fit
        .decimal => |r| textio.formatDecimal(&db, r),
        // polars' `b"\x00ab"` form: printable ASCII as is, every other byte `\xNN`.
        .text => |t| if (ty == .binary) try bf.displayInto(a, t) else t,
        // A nested cell shows as its JSON (polars prints `[1, 2]` and `{1,"a"}`; the JSON
        // names the fields), cut like any long cell.
        .list, .record => blk: {
            var out: std.Io.Writer.Allocating = .init(a);
            jsonio.writeValue(&out.writer, v, col, 0) catch return error.OutOfMemory; // an Allocating writer fails only so
            break :blk out.written();
        },
    };
    var needs = cpLen(s) > max_chars;
    for (s) |c| if (c < 0x20 or c == 0x7f or (md and c == '|')) {
        needs = true;
        break;
    };
    if (!needs) return try a.dupe(u8, s);
    var out: std.ArrayList(u8) = .empty;
    // At most `max_chars` in all, the `…` included.
    const cut = if (cpLen(s) > max_chars) prefixBytes(s, max_chars -| 1) else s.len;
    for (s[0..cut]) |c| switch (c) {
        '\n' => try out.appendSlice(a, "\\n"),
        '\r' => try out.appendSlice(a, "\\r"),
        '\t' => try out.appendSlice(a, "\\t"),
        '|' => if (md) try out.appendSlice(a, "\\|") else try out.append(a, c),
        0...8, 11, 12, 14...31, 0x7f => try out.print(a, "\\x{x:0>2}", .{c}),
        else => try out.append(a, c),
    };
    if (cut < s.len) try out.appendSlice(a, "…");
    return out.items;
}

fn isNumeric(ty: ColumnType) bool {
    return dtype.isNumeric(ty) or ty == .decimal;
}

/// The dtype line's name of a column type: polars' short name for a width (`i8` … `u64`,
/// `f32`), the tag name for every other type (Int64 and Float64 keep `int` and `float`).
fn typeLabel(ty: ColumnType) []const u8 {
    return if (dtype.isWidth(ty)) dtype.name(ty) else @tagName(ty);
}

/// polars' element label inside `array[..., n]`: its short dtype names (`i64`, `f64`,
/// `str`, and the widths'), this module's tag name for the rest (the dtype line itself says
/// `int` for Int64).
fn elementLabel(ty: ColumnType) []const u8 {
    return switch (ty) {
        .text => "str",
        .array, .list => "list",
        else => dtype.name(ty),
    };
}

/// `array[i64, 3]` (polars' repr) of an `.array` column, `typeLabel` of any other.
fn columnLabel(a: std.mem.Allocator, c: value.Column) std.mem.Allocator.Error![]const u8 {
    if (c.type != .array) return typeLabel(c.type);
    const el: []const u8 = if (c.inner.len > 0) elementLabel(c.inner[0].type) else "?";
    return std.fmt.allocPrint(a, "array[{s}, {d}]", .{ el, c.array_width });
}

fn pad(w: *std.Io.Writer, n: usize) std.Io.Writer.Error!void {
    for (0..n) |_| try w.writeByte(' ');
}

const marker = "…";
const text_col: value.Column = .{ .name = "", .type = .text };

/// `f` as aligned text, every column right-aligned and one space between columns.
pub fn formatTo(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, opts: FormatOptions) RenderError!void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();
    if (opts.show_shape) try w.print("shape: ({d}, {d})\n", .{ f.len, f.columns.len });
    if (f.columns.len == 0) return;

    // The visible columns (null = the `…` column) and rows.
    // ceil(n / 2) without `n + 1`, which overflows for `maxInt(usize)`.
    const head_c = opts.max_cols / 2 + opts.max_cols % 2;
    const tail_c = opts.max_cols / 2;
    var cols: std.ArrayList(?usize) = .empty;
    if (f.columns.len <= opts.max_cols) {
        for (0..f.columns.len) |i| try cols.append(al, i);
    } else {
        for (0..head_c) |i| try cols.append(al, i);
        try cols.append(al, null);
        for (f.columns.len - tail_c..f.columns.len) |i| try cols.append(al, i);
    }
    const head_r = opts.max_rows / 2 + opts.max_rows % 2;
    const tail_r = opts.max_rows / 2;
    var rows: std.ArrayList(?usize) = .empty;
    if (f.len <= opts.max_rows) {
        for (0..f.len) |i| try rows.append(al, i);
    } else {
        for (0..head_r) |i| try rows.append(al, i);
        try rows.append(al, null);
        for (f.len - tail_r..f.len) |i| try rows.append(al, i);
    }

    const nc = cols.items.len;
    const extra: usize = 1 + @as(usize, @intFromBool(opts.show_dtypes));
    const grid = try al.alloc([]const u8, (rows.items.len + extra) * nc);
    const widths = try al.alloc(usize, nc);
    @memset(widths, 0);
    for (cols.items, 0..) |maybe, j| {
        grid[j] = if (maybe) |ci| try cellText(al, .{ .text = f.columns[ci].name }, text_col, "", opts.max_cell_chars, false) else marker;
        if (opts.show_dtypes) grid[nc + j] = if (maybe) |ci| try columnLabel(al, f.columns[ci]) else marker;
        for (rows.items, 0..) |mr, i| {
            const idx = (i + extra) * nc + j;
            grid[idx] = if (maybe == null or mr == null) marker else blk: {
                const ci = maybe.?;
                break :blk try cellText(al, f.columnAt(ci).get(mr.?), f.columns[ci], opts.null_text, opts.max_cell_chars, false);
            };
        }
        for (0..rows.items.len + extra) |i| widths[j] = @max(widths[j], cpLen(grid[i * nc + j]));
    }
    for (0..rows.items.len + extra) |i| {
        for (0..nc) |j| {
            if (j != 0) try w.writeByte(' ');
            const s = grid[i * nc + j];
            try pad(w, widths[j] - cpLen(s));
            try w.writeAll(s);
        }
        try w.writeByte('\n');
    }
}

/// `formatTo`, as an owned string.
pub fn format(a: std.mem.Allocator, f: Frame, opts: FormatOptions) RenderError![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    try formatTo(a, &aw.writer, f, opts);
    return aw.toOwnedSlice();
}

/// `f` as a Markdown pipe table: numbers (int, float, decimal) right-aligned, the rest
/// left, every column at least two wider than its header, as `tabulate` lays it out for
/// pandas. Not done: `tabulate` aligns floats on the decimal point. A `|` in a cell is
/// written `\|` and a newline `\n`, which `tabulate` does not do.
pub fn markdownTo(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, opts: MarkdownOptions) RenderError!void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();
    const nc = f.columns.len;
    if (nc == 0) return;
    // A hand-built frame may claim any `len`: a grid that cannot be sized is out of memory.
    const lines = std.math.add(usize, f.len, 1) catch return error.OutOfMemory;
    const grid = try al.alloc([]const u8, std.math.mul(usize, lines, nc) catch return error.OutOfMemory);
    const widths = try al.alloc(usize, nc);
    for (f.columns, 0..) |c, j| {
        grid[j] = try cellText(al, .{ .text = c.name }, text_col, "", std.math.maxInt(usize), true);
        widths[j] = cpLen(grid[j]) + 2;
        const col = f.columnAt(j);
        for (0..f.len) |i| {
            const s = try cellText(al, col.get(i), c, opts.null_text, std.math.maxInt(usize), true);
            grid[(i + 1) * nc + j] = s;
            widths[j] = @max(widths[j], cpLen(s));
        }
    }
    for (0..lines) |i| {
        try w.writeByte('|');
        for (0..nc) |j| {
            const s = grid[i * nc + j];
            try w.writeByte(' ');
            if (isNumeric(f.columns[j].type)) {
                try pad(w, widths[j] - cpLen(s));
                try w.writeAll(s);
            } else {
                try w.writeAll(s);
                try pad(w, widths[j] - cpLen(s));
            }
            try w.writeAll(" |");
        }
        try w.writeByte('\n');
        if (i == 0) {
            try w.writeByte('|');
            for (0..nc) |j| {
                if (isNumeric(f.columns[j].type)) {
                    for (0..widths[j] + 1) |_| try w.writeByte('-');
                    try w.writeAll(":|");
                } else {
                    try w.writeByte(':');
                    for (0..widths[j] + 1) |_| try w.writeByte('-');
                    try w.writeByte('|');
                }
            }
            try w.writeByte('\n');
        }
    }
}

/// `markdownTo`, as an owned string.
pub fn toMarkdown(a: std.mem.Allocator, f: Frame, opts: MarkdownOptions) RenderError![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    try markdownTo(a, &aw.writer, f, opts);
    return aw.toOwnedSlice();
}

// ── toHtml and glimpse ──────────────────────────────────────────────────────

pub const HtmlOptions = struct {
    /// What a null cell and a NaN show (pandas `na_rep`, default `NaN`).
    null_text: []const u8 = "NaN",
    /// Floats with this many fixed decimals (pandas `float_format="%.Nf"`); `null`: the
    /// shortest digits that read back (pandas pads a column to one common number of digits).
    float_precision: ?u8 = null,
    /// The `border` attribute (pandas `border`, default 1); `null` or `0` leaves it out, as pandas does.
    border: ?u8 = 1,
    /// Classes after `dataframe`, which is always there (pandas `classes`).
    classes: []const u8 = "",
    /// Write the `<thead>` (pandas `header`).
    header: bool = true,
    /// Escape `& < > "` in cells and names (pandas `escape=True`, which leaves out the quote).
    escape: bool = true,
    /// A cell longer than this (in code points) ends in `…`.
    max_cell_chars: usize = 1 << 20,
};

fn htmlText(w: *std.Io.Writer, s: []const u8, escape: bool) std.Io.Writer.Error!void {
    if (!escape) return w.writeAll(s);
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        else => try w.writeByte(c),
    };
}

/// `f` as an HTML table in pandas' `to_html(index=False)` layout (2-space indent, a
/// `<thead>` row with `style="text-align: right;"`, one `<td>` per cell). A frame here
/// has no index, so there is no index column; numbers are not aligned by CSS.
pub fn htmlTo(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, opts: HtmlOptions) RenderError!void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();
    try w.writeAll("<table");
    if (opts.border) |b| if (b != 0) try w.print(" border=\"{d}\"", .{b});
    try w.writeAll(" class=\"dataframe");
    if (opts.classes.len != 0) {
        try w.writeByte(' ');
        try htmlText(w, opts.classes, true);
    }
    try w.writeAll("\">\n");
    if (opts.header) {
        try w.writeAll("  <thead>\n    <tr style=\"text-align: right;\">\n");
        for (f.columns) |c| {
            try w.writeAll("      <th>");
            try htmlText(w, c.name, opts.escape);
            try w.writeAll("</th>\n");
        }
        try w.writeAll("    </tr>\n  </thead>\n");
    }
    try w.writeAll("  <tbody>\n");
    var fb: [400]u8 = undefined;
    for (0..f.len) |ri| {
        _ = arena.reset(.retain_capacity);
        try w.writeAll("    <tr>\n");
        for (f.columns, 0..) |c, ci| {
            const v = f.columnAt(ci).get(ri);
            const s: []const u8 = if (v == .float and std.math.isFinite(v.float) and opts.float_precision != null)
                textio.formatFloatFixed(&fb, v.float, @min(opts.float_precision.?, 22))
            else
                try cellText(al, v, c, opts.null_text, opts.max_cell_chars, false);
            try w.writeAll("      <td>");
            try htmlText(w, if (v == .float and std.math.isNan(v.float)) opts.null_text else s, opts.escape);
            try w.writeAll("</td>\n");
        }
        try w.writeAll("    </tr>\n");
    }
    try w.writeAll("  </tbody>\n</table>\n");
}

/// `htmlTo`, as an owned string.
pub fn toHtml(a: std.mem.Allocator, f: Frame, opts: HtmlOptions) RenderError![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    try htmlTo(a, &aw.writer, f, opts);
    return aw.toOwnedSlice();
}

// ── toLatex ─────────────────────────────────────────────────────────────────

pub const LatexOptions = struct {
    /// What a null cell and a NaN show (pandas `na_rep`, default `NaN`).
    null_text: []const u8 = "NaN",
    /// Escape the LaTeX specials in cells and names (pandas `escape`; its default is `False`
    /// since 2.0, so it is here).
    escape: bool = false,
    /// `\caption{...}` inside a `table` environment (pandas `caption`); the text is not escaped, as pandas.
    caption: ?[]const u8 = null,
    /// `\label{...}` (pandas `label`); needs a `table` environment, so it wraps the table as `caption` does.
    label: ?[]const u8 = null,
    /// Write the header row and the rule under it (pandas `header`).
    header: bool = true,
    /// The `tabular` / `longtable` column spec as written, replacing the computed `l` / `r`
    /// letters (pandas `column_format`; not checked against the column count, as pandas).
    column_format: ?[]const u8 = null,
    /// The `longtable` environment with its `\endfirsthead` / `\endhead` / `\endfoot` /
    /// `\endlastfoot` blocks (pandas `longtable`); `caption` and `label` go inside it, there
    /// is no `table` wrapper.
    longtable: bool = false,
    /// The `[h]` after `\begin{table}` / `\begin{longtable}` (pandas `position`, trimmed of
    /// blanks); a non-empty one also wraps a `tabular` in `table`. Empty = none.
    position: ?[]const u8 = null,
};

/// `%.6f` of a finite float, as Python prints it: the exact binary value rounded half to even
/// at the sixth decimal. `{d:.6}` rounds the shortest digits instead (`0.0000005` gives
/// `0.000001`, Python `0.000000`) and pads with zeros past 2^53, so the digits come from integer
/// arithmetic: the value is `mant * 2^e`.
fn fixed6(al: std.mem.Allocator, w: *std.Io.Writer, x: f64) error{ OutOfMemory, WriteFailed }!void {
    const bits: u64 = @bitCast(x);
    const bexp: i32 = @intCast((bits >> 52) & 0x7ff);
    const frac = bits & ((1 << 52) - 1);
    const mant: u64 = if (bexp == 0) frac else frac | (1 << 52);
    const e: i32 = (if (bexp == 0) 1 else bexp) - 1075;
    if (bits >> 63 != 0) try w.writeByte('-');
    if (e >= 0) {
        var m = try std.math.big.int.Managed.init(al);
        try m.set(mant);
        try m.shiftLeft(&m, @intCast(e));
        const digits = m.toString(al, 10, .lower) catch return error.OutOfMemory; // base 10 is valid
        return w.print("{s}.000000", .{digits});
    }
    const shift: u32 = @intCast(-e);
    const n: u128 = @as(u128, mant) * 1_000_000; // 73 bits
    var q: u128 = 0;
    if (shift < 128) {
        q = n >> @intCast(shift);
        const rem = n & ((@as(u128, 1) << @intCast(shift)) - 1);
        const half = @as(u128, 1) << @intCast(shift - 1);
        if (rem > half or (rem == half and q & 1 == 1)) q += 1;
    }
    try w.print("{d}.{d:0>6}", .{ q / 1_000_000, q % 1_000_000 });
}

fn latexText(w: *std.Io.Writer, s: []const u8, escape: bool) std.Io.Writer.Error!void {
    if (!escape) return w.writeAll(s);
    for (s) |c| switch (c) {
        '&', '%', '$', '#', '_', '{', '}' => {
            try w.writeByte('\\');
            try w.writeByte(c);
        },
        // pandas 3.1 writes these three with a trailing blank, not `{}` (oracle2k `lat-specials-esc`).
        '~' => try w.writeAll("\\textasciitilde "),
        '^' => try w.writeAll("\\textasciicircum "),
        '\\' => try w.writeAll("\\textbackslash "),
        else => try w.writeByte(c),
    };
}

/// `f` as a LaTeX table in pandas' `to_latex(index=False)` layout (booktabs rules): `\begin{tabular}{lrr}`,
/// a column format letter `r` for a number or bool column (int, float, decimal) and `l` for the rest, a
/// header row, `\midrule` (written without a header too), one row per line, `\bottomrule`. A `caption`
/// or `label` wraps it in `\begin{table}`. A float is written with six decimals (pandas' Styler
/// precision, `1.500000`, `1e-07` as `0.000000`). Text and names go out byte for byte, a tab or
/// newline included (pandas does not touch them), `null_text` is never escaped. `column_format`,
/// `longtable` and `position` are pandas'. Not done: `multicolumn`, `formatters`, `float_format`.
pub fn latexTo(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, opts: LatexOptions) RenderError!void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();
    // pandas takes an empty caption / label / position as not given.
    const caption = nonEmpty(opts.caption);
    const label = nonEmpty(opts.label);
    const pos = nonEmpty(opts.position);
    const env: []const u8 = if (opts.longtable) "longtable" else "tabular";
    const wrap = !opts.longtable and (caption != null or label != null or pos != null);
    const rows = if (f.columns.len == 0) 0 else f.len;
    if (wrap) {
        try w.writeAll("\\begin{table}");
        if (pos) |p| try w.print("[{s}]", .{std.mem.trim(u8, p, " \t\r\n")});
        try w.writeByte('\n');
        if (caption) |c| try w.print("\\caption{{{s}}}\n", .{c});
        if (label) |l| try w.print("\\label{{{s}}}\n", .{l});
    }
    try w.print("\\begin{{{s}}}", .{env});
    if (opts.longtable) if (pos) |p| try w.print("[{s}]", .{std.mem.trim(u8, p, " \t\r\n")});
    try w.writeByte('{');
    if (opts.column_format) |cf| {
        try w.writeAll(cf);
    } else for (f.columns) |c| try w.writeByte(if (isNumeric(c.type) or c.type == .bool) 'r' else 'l');
    try w.writeAll("}\n");
    if (opts.longtable and (caption != null or label != null)) {
        if (caption) |c| try w.print("\\caption{{{s}}}", .{c});
        if (caption != null and label != null) try w.writeByte(' ');
        if (label) |l| try w.print("\\label{{{s}}}", .{l});
        try w.writeAll(" \\\\\n");
    }
    try latexHead(w, f, opts);
    if (opts.longtable) {
        try w.writeAll("\\endfirsthead\n");
        if (caption) |c| try w.print("\\caption[]{{{s}}} \\\\\n", .{c});
        try latexHead(w, f, opts);
        // pandas counts the columns of the first row: none without rows.
        try w.print("\\endhead\n\\midrule\n\\multicolumn{{{d}}}{{r}}{{Continued on next page}} \\\\\n\\midrule\n\\endfoot\n\\bottomrule\n\\endlastfoot\n", .{if (rows == 0) 0 else f.columns.len});
    }
    for (0..rows) |ri| {
        for (f.columns, 0..) |c, ci| {
            if (ci != 0) try w.writeAll(" & ");
            _ = arena.reset(.retain_capacity);
            const v = f.columnAt(ci).get(ri);
            if (v == .null or (v == .float and std.math.isNan(v.float))) {
                try w.writeAll(opts.null_text);
            } else switch (v) {
                .text => |t| try latexText(w, t, opts.escape),
                .float => |x| if (std.math.isInf(x)) try w.writeAll(if (x > 0) "inf" else "-inf") else {
                    try fixed6(al, w, x);
                },
                else => try latexText(w, try cellText(al, v, c, opts.null_text, std.math.maxInt(usize), false), opts.escape),
            }
        }
        try w.writeAll(" \\\\\n");
    }
    if (opts.longtable) {
        try w.writeAll("\\end{longtable}\n");
    } else {
        try w.writeAll("\\bottomrule\n\\end{tabular}\n");
        if (wrap) try w.writeAll("\\end{table}\n");
    }
}

fn nonEmpty(s: ?[]const u8) ?[]const u8 {
    const v = s orelse return null;
    return if (v.len == 0) null else v;
}

/// `\toprule`, the header row (with `header`) and `\midrule`.
fn latexHead(w: *std.Io.Writer, f: Frame, opts: LatexOptions) std.Io.Writer.Error!void {
    try w.writeAll("\\toprule\n");
    // pandas writes no header line for a frame without columns.
    if (opts.header and f.columns.len != 0) {
        for (f.columns, 0..) |c, ci| {
            if (ci != 0) try w.writeAll(" & ");
            try latexText(w, c.name, opts.escape);
        }
        try w.writeAll(" \\\\\n");
    }
    try w.writeAll("\\midrule\n");
}

/// `latexTo`, as an owned string.
pub fn toLatex(a: std.mem.Allocator, f: Frame, opts: LatexOptions) RenderError![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    try latexTo(a, &aw.writer, f, opts);
    return aw.toOwnedSlice();
}

pub const GlimpseOptions = struct {
    /// Values shown per column (polars `max_items_per_column`, default 10).
    max_items: usize = 10,
    /// A column name longer than this (code points) is cut with `…` (polars `max_colname_length`, 50).
    max_name_chars: usize = 50,
    /// Cut a line to this many code points, ending in `…`. polars never cuts a line, so `null`.
    max_width: ?usize = null,
    /// A text value longer than this ends in `…` (polars shows it whole).
    max_cell_chars: usize = std.math.maxInt(usize),
};

fn glimpseType(a: std.mem.Allocator, t: value.Column) std.mem.Allocator.Error![]const u8 {
    return switch (t.type) {
        .int => "<i64>",
        .float => "<f64>",
        .text => "<str>",
        .bool => "<bool>",
        .date => "<date>",
        .decimal => "<decimal>",
        .timestamp => "<datetime[μs]>",
        .categorical => "<cat>",
        .duration => "<duration[μs]>",
        .time => "<time>",
        .binary => "<binary>",
        .list => "<list>",
        .array => try std.fmt.allocPrint(a, "<{s}>", .{try columnLabel(a, t)}),
        .@"struct" => "<struct>",
        .int8 => "<i8>",
        .int16 => "<i16>",
        .int32 => "<i32>",
        .uint8 => "<u8>",
        .uint16 => "<u16>",
        .uint32 => "<u32>",
        .uint64 => "<u64>",
        .float32 => "<f32>",
    };
}

/// polars `DataFrame.glimpse()` (as its string form prints it): `Rows: n`, `Columns: m`, then
/// one line per column, `$ name <type> v1, v2, ...`: names padded to the longest, the `<type>`
/// right-aligned to the longest, at most `max_items` values, text in single quotes (not
/// escaped), nulls `null`, bools `True`/`False`. Dates and timestamps are unquoted.
pub fn glimpseTo(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, opts: GlimpseOptions) RenderError!void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();
    try w.print("Rows: {d}\nColumns: {d}\n", .{ f.len, f.columns.len });
    var name_w: usize = 0;
    var type_w: usize = 0;
    const names = try al.alloc([]const u8, f.columns.len);
    for (f.columns, names) |c, *n| {
        n.* = try cellText(al, .{ .text = c.name }, text_col, "", opts.max_name_chars, false);
        name_w = @max(name_w, cpLen(n.*));
        type_w = @max(type_w, cpLen(try glimpseType(al, c)));
    }
    for (f.columns, names, 0..) |c, n, ci| {
        var line: std.ArrayList(u8) = .empty;
        try line.appendSlice(al, "$ ");
        try line.appendSlice(al, n);
        for (0..name_w - cpLen(n)) |_| try line.append(al, ' ');
        try line.append(al, ' ');
        const ty = try glimpseType(al, c);
        for (0..type_w - cpLen(ty)) |_| try line.append(al, ' ');
        try line.appendSlice(al, ty);
        try line.append(al, ' ');
        const col = f.columnAt(ci);
        const shown = @min(f.len, opts.max_items);
        for (0..shown) |ri| {
            if (ri != 0) try line.appendSlice(al, ", ");
            const v = col.get(ri);
            // polars' glimpse prints a binary cell as Python's `repr(bytes)`, unquoted here.
            const t = if (v == .text and c.type == .binary) try bf.reprInto(al, v.text) else try cellText(al, v, c, "null", opts.max_cell_chars, false);
            if (v == .text and c.type != .date and c.type != .binary) {
                try line.append(al, '\'');
                try line.appendSlice(al, t);
                try line.append(al, '\'');
            } else try line.appendSlice(al, t);
        }
        if (opts.max_width) |mw| if (cpLen(line.items) > mw) {
            const keep = prefixBytes(line.items, mw -| 1);
            try w.writeAll(line.items[0..keep]);
            try w.writeAll("…\n");
            continue;
        };
        try w.writeAll(line.items);
        try w.writeByte('\n');
    }
}

/// `glimpseTo`, as an owned string.
pub fn glimpse(a: std.mem.Allocator, f: Frame, opts: GlimpseOptions) RenderError![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    try glimpseTo(a, &aw.writer, f, opts);
    return aw.toOwnedSlice();
}

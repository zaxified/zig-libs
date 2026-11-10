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
const jsonio = @import("jsonio.zig");

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
        else
            std.fmt.bufPrint(&nb, "{d}", .{i}) catch unreachable,
        .float => |x| if (std.math.isNan(x)) "NaN" else if (std.math.isInf(x)) (if (x > 0) "inf" else "-inf") else if (ty == .float32) textio.formatFloat32(nb[0..textio.max_float_len], @floatCast(x)) else textio.formatFloat(nb[0..textio.max_float_len], x),
        .uint => |u| std.fmt.bufPrint(&nb, "{d}", .{u}) catch unreachable, // 20 digits fit
        .decimal => |r| textio.formatDecimal(&db, r),
        .text => |t| t,
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
    return ty == .int or ty == .float or ty == .decimal;
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
        if (opts.show_dtypes) grid[nc + j] = if (maybe) |ci| @tagName(f.columns[ci].type) else marker;
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

fn glimpseType(t: value.Column) []const u8 {
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
        .list => "<list>",
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
        type_w = @max(type_w, cpLen(glimpseType(c)));
    }
    for (f.columns, names, 0..) |c, n, ci| {
        var line: std.ArrayList(u8) = .empty;
        try line.appendSlice(al, "$ ");
        try line.appendSlice(al, n);
        for (0..name_w - cpLen(n)) |_| try line.append(al, ' ');
        try line.append(al, ' ');
        const ty = glimpseType(c);
        for (0..type_w - cpLen(ty)) |_| try line.append(al, ' ');
        try line.appendSlice(al, ty);
        try line.append(al, ' ');
        const col = f.columnAt(ci);
        const shown = @min(f.len, opts.max_items);
        for (0..shown) |ri| {
            if (ri != 0) try line.appendSlice(al, ", ");
            const v = col.get(ri);
            const t = try cellText(al, v, c, "null", opts.max_cell_chars, false);
            if (v == .text and c.type != .date) {
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

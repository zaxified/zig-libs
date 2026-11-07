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
        const l = std.unicode.utf8ByteSequenceLength(s[i]) catch return @min(n, s.len);
        i += l;
    }
    return @min(i, s.len);
}

/// The text of a cell, with control characters written as escapes and a long text cut.
fn cellText(a: std.mem.Allocator, v: Value, ty: ColumnType, null_text: []const u8, max_chars: usize, md: bool) std.mem.Allocator.Error![]const u8 {
    var nb: [textio.max_float_len + 8]u8 = undefined;
    var sb: [textio.max_stamp_len]u8 = undefined;
    var db: [textio.max_decimal_len]u8 = undefined;
    const s: []const u8 = switch (v) {
        .null => return null_text,
        .bool => |b| if (b) "True" else "False",
        .int => |i| if (ty == .timestamp) textio.formatStampSpace(&sb, i, if (textio.hasFraction(i)) 6 else 0) else std.fmt.bufPrint(&nb, "{d}", .{i}) catch unreachable,
        .float => |x| if (std.math.isNan(x)) "NaN" else if (std.math.isInf(x)) (if (x > 0) "inf" else "-inf") else textio.formatFloat(nb[0..textio.max_float_len], x),
        .decimal => |r| textio.formatDecimal(&db, r),
        .text => |t| t,
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

/// `f` as aligned text, every column right-aligned and one space between columns.
pub fn formatTo(a: std.mem.Allocator, w: *std.Io.Writer, f: Frame, opts: FormatOptions) RenderError!void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();
    if (opts.show_shape) try w.print("shape: ({d}, {d})\n", .{ f.len, f.columns.len });
    if (f.columns.len == 0) return;

    // The visible columns (null = the `…` column) and rows.
    const head_c = (opts.max_cols + 1) / 2;
    const tail_c = opts.max_cols / 2;
    var cols: std.ArrayList(?usize) = .empty;
    if (f.columns.len <= opts.max_cols) {
        for (0..f.columns.len) |i| try cols.append(al, i);
    } else {
        for (0..head_c) |i| try cols.append(al, i);
        try cols.append(al, null);
        for (f.columns.len - tail_c..f.columns.len) |i| try cols.append(al, i);
    }
    const head_r = (opts.max_rows + 1) / 2;
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
        grid[j] = if (maybe) |ci| try cellText(al, .{ .text = f.columns[ci].name }, .text, "", opts.max_cell_chars, false) else marker;
        if (opts.show_dtypes) grid[nc + j] = if (maybe) |ci| @tagName(f.columns[ci].type) else marker;
        for (rows.items, 0..) |mr, i| {
            const idx = (i + extra) * nc + j;
            grid[idx] = if (maybe == null or mr == null) marker else blk: {
                const ci = maybe.?;
                break :blk try cellText(al, f.columnAt(ci).get(mr.?), f.columns[ci].type, opts.null_text, opts.max_cell_chars, false);
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
    const grid = try al.alloc([]const u8, (f.len + 1) * nc);
    const widths = try al.alloc(usize, nc);
    for (f.columns, 0..) |c, j| {
        grid[j] = try cellText(al, .{ .text = c.name }, .text, "", std.math.maxInt(usize), true);
        widths[j] = cpLen(grid[j]) + 2;
        const col = f.columnAt(j);
        for (0..f.len) |i| {
            const s = try cellText(al, col.get(i), c.type, opts.null_text, std.math.maxInt(usize), true);
            grid[(i + 1) * nc + j] = s;
            widths[j] = @max(widths[j], cpLen(s));
        }
    }
    for (0..f.len + 1) |i| {
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

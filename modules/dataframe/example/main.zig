// SPDX-License-Identifier: MIT
//! A small pipeline over `dataframe`: build a frame, clean it, join a lookup table,
//! aggregate per group, pivot, and print the result.

const std = @import("std");
const df = @import("dataframe");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var arena = std.heap.ArenaAllocator.init(df.big_block_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cols = [_]df.Column{
        .{ .name = "city", .type = .text },
        .{ .name = "month", .type = .int },
        .{ .name = "sales", .type = .float },
    };
    var b = try df.FrameBuilder.init(a, &cols, 8);
    const rows = [_][3]df.Value{
        .{ .{ .text = "Brno" }, .{ .int = 1 }, .{ .float = 120 } },
        .{ .{ .text = "Praha" }, .{ .int = 1 }, .{ .float = 300 } },
        .{ .{ .text = "Brno" }, .{ .int = 2 }, .null },
        .{ .{ .text = "Ostrava" }, .{ .int = 2 }, .{ .float = 80 } },
        .{ .{ .text = "Praha" }, .{ .int = 2 }, .{ .float = 310 } },
        .{ .{ .text = "Brno" }, .{ .int = 2 }, .{ .float = 140 } },
    };
    for (rows) |r| try b.appendRow(&r);
    const sales = try b.toOwned();

    const rcols = [_]df.Column{ .{ .name = "city", .type = .text }, .{ .name = "region", .type = .text } };
    var rb = try df.FrameBuilder.init(a, &rcols, 3);
    try rb.appendRow(&.{ .{ .text = "Brno" }, .{ .text = "south" } });
    try rb.appendRow(&.{ .{ .text = "Praha" }, .{ .text = "centre" } });
    try rb.appendRow(&.{ .{ .text = "Ostrava" }, .{ .text = "north" } });
    const regions = try rb.toOwned();

    const clean = try df.dropna(a, sales, .{ .subset = &.{"sales"} });
    const joined = try df.join(a, clean, regions, .{ .on = "city", .how = .left });
    const per_region = try df.aggregate(a, joined, .{
        .group_by = &.{"region"},
        .aggs = &.{
            .{ .src = "sales", .out = "total", .func = .sum },
            .{ .src = "sales", .out = "rows", .func = .count },
        },
        .sort_groups = true,
    });
    const ranked = try df.sort(a, per_region, .{ .key = "total", .dir = .desc });
    const wide = try df.pivot(a, clean, .{ .row_key = "city", .col_key = "month", .value_col = "sales", .fill_value = 0 });

    // Text into columns (pandas `str.split(expand=True)`): one column per piece.
    const tcols = [_]df.Column{.{ .name = "tags", .type = .text }};
    var tb = try df.FrameBuilder.init(a, &tcols, 2);
    try tb.appendRow(&.{.{ .text = "red,round,small" }});
    try tb.appendRow(&.{.{ .text = "blue" }});
    const tagged = try df.splitColumns(a, try tb.toOwned(), .{ .col = "tags", .by = ",", .prefix = "tag_" });
    // Time windows: a Hann-weighted rolling mean, and 2-hour windows that overlap by an hour.
    const wcols = [_]df.Column{ .{ .name = "t", .type = .int }, .{ .name = "x", .type = .float } };
    var wb = try df.FrameBuilder.init(a, &wcols, 5);
    const xs = [_]f64{ 1, 3, 2, 5, 4 };
    for (xs, 0..) |x, i| try wb.appendRow(&.{ .{ .int = @as(i64, @intCast(i)) * 40 * 60_000_000 }, .{ .float = x } });
    const series = try wb.toOwned();
    const smooth = try df.window(a, series, .{ .value_col = "x", .out = "smooth", .op = .{ .rolling = .{ .window = 3, .min_periods = 1, .win_type = .hann } } });
    const overlapping = try df.groupByDynamic(a, series, .{
        .index = "t",
        .every = "1h",
        .period = "2h",
        .label = .right,
        .aggs = &.{.{ .src = "x", .out = "sum", .func = .sum }},
    });

    var buf: [1024]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;
    try printFrame(out, ranked);
    try out.writeAll("\n");
    try printFrame(out, wide);
    try out.writeAll("\n");
    try printFrame(out, tagged);
    try out.writeAll("\n");
    try printFrame(out, smooth);
    try out.writeAll("\n");
    try printFrame(out, overlapping);

    // A CSV stream three rows at a time (pandas `chunksize`, polars `read_csv_batched`): the
    // types come from the first chunk and stay, memory is one chunk, whatever the stream's size.
    // A fixed reader stands in for a file here; any `std.Io.Reader` works.
    const csv_text = "id,score\n1,0.5\n2,1.5\n3,2\n4,\"3.5\"\n5,4\n";
    var csv_reader: std.Io.Reader = .fixed(csv_text);
    var chunks = try df.CsvChunkReader.init(init.gpa, &csv_reader, .{}, .{});
    defer chunks.deinit();
    while (true) {
        var chunk_arena = std.heap.ArenaAllocator.init(init.gpa);
        defer chunk_arena.deinit();
        const chunk = (try chunks.next(chunk_arena.allocator(), 3)) orelse break;
        try out.writeAll("\nchunk\n");
        try printFrame(out, chunk);
    }
    // The same for newline-delimited JSON; each chunk is typed on its own, as in pandas.
    var nd_reader: std.Io.Reader = .fixed("{\"k\":1}\n{\"k\":2}\n{\"k\":3}\n");
    var nd_chunks = df.NdjsonChunkReader.init(init.gpa, &nd_reader, .{});
    defer nd_chunks.deinit();
    while (true) {
        var chunk_arena = std.heap.ArenaAllocator.init(init.gpa);
        defer chunk_arena.deinit();
        const chunk = (try nd_chunks.next(chunk_arena.allocator(), 2)) orelse break;
        try out.writeAll("\nndjson chunk\n");
        try printFrame(out, chunk);
    }
    try out.flush();
}

fn printFrame(out: *std.Io.Writer, f: df.Frame) !void {
    for (f.columns, 0..) |c, ci| try out.print("{s}{s}", .{ if (ci > 0) "\t" else "", c.name });
    try out.writeAll("\n");
    for (0..f.len) |ri| {
        for (0..f.columns.len) |ci| {
            if (ci > 0) try out.writeAll("\t");
            switch (f.columnAt(ci).get(ri)) {
                .null => try out.writeAll("null"),
                .int => |x| try out.print("{d}", .{x}),
                .float => |x| try out.print("{d}", .{x}),
                .text => |x| try out.writeAll(x),
                .bool => |x| try out.writeAll(if (x) "true" else "false"),
                .decimal => |x| try out.print("{d}e-12", .{x}),
                .list => |l| try out.print("[{d} items]", .{l.len()}),
                .record => |r| try out.print("{{{d} fields}}", .{r.len()}),
            }
        }
        try out.writeAll("\n");
    }
}

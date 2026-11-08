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

    var buf: [1024]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;
    try printFrame(out, ranked);
    try out.writeAll("\n");
    try printFrame(out, wide);
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

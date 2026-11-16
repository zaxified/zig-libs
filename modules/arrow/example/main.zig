// SPDX-License-Identifier: MIT
//! A small frame to an Arrow IPC file (zstd-compressed) on disk and back, then one
//! record batch read on its own: the file a pyarrow `pa.ipc.open_file` or a polars
//! `pl.read_ipc` opens. The file is removed again before the program ends.

const std = @import("std");
const df = @import("dataframe");
const arrow = @import("arrow");

const path = "example-arrow.arrow";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const cols = [_]df.Column{
        .{ .name = "city", .type = .categorical },
        .{ .name = "day", .type = .date },
        .{ .name = "at", .type = .timestamp, .time_zone = "Europe/Prague" },
        .{ .name = "kwh", .type = .float },
        .{ .name = "price", .type = .decimal },
    };
    var b = try df.FrameBuilder.init(a, &cols, 4);
    const rows = [_][5]df.Value{
        .{ .{ .text = "Brno" }, .{ .text = "2026-11-16" }, .{ .int = 1_763_280_000_000_000 }, .{ .float = 12.5 }, .{ .decimal = 4_120_000_000_000 } },
        .{ .{ .text = "Praha" }, .{ .text = "2026-11-16" }, .{ .int = 1_763_283_600_000_000 }, .null, .{ .decimal = 3_990_000_000_000 } },
        .{ .{ .text = "Brno" }, .{ .text = "2026-11-17" }, .{ .int = 1_763_366_400_000_000 }, .{ .float = 9.75 }, .null },
        .{ .null, .{ .text = "2026-11-17" }, .{ .int = 1_763_370_000_000_000 }, .{ .float = 0 }, .{ .decimal = 4_000_000_000_000 } },
    };
    for (rows) |r| try b.appendRow(&r);
    const frame = try b.toOwned();

    const bytes = try arrow.writeFile(gpa, frame, .{ .rows_per_batch = 2, .compression = .zstd });
    defer gpa.free(bytes);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
    defer std.Io.Dir.cwd().deleteFile(io, path) catch |err| {
        std.debug.print("example-arrow: could not remove {s}: {t}\n", .{ path, err });
    };

    const on_disk = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
    defer gpa.free(on_disk);
    const back = try arrow.readFile(a, on_disk, .{});
    if (back.len != frame.len or back.columns.len != frame.columns.len) return error.RoundTripDiffers;
    for (frame.columns, 0..) |c, ci| {
        if (back.columns[ci].type != c.type) return error.RoundTripDiffers;
        for (0..frame.len) |r| {
            const x = frame.columnAt(ci).get(r);
            const y = back.columnAt(ci).get(r);
            if (std.meta.activeTag(x) != std.meta.activeTag(y) or (x != .null and !x.eql(y))) return error.RoundTripDiffers;
        }
    }

    // Random access: the second record batch alone.
    var file = try arrow.openFile(a, on_disk, .{});
    const second = try file.readBatch(1);

    var buf: [512]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;
    try out.print("{s}: {d} bytes, {d} rows in {d} batches, read back equal\n", .{ path, bytes.len, back.len, file.batchCount() });
    try out.print("batch 1 ({d} rows):\n", .{second.len});
    for (0..second.len) |r| {
        try out.print("  city={any} day={s} kwh={any}\n", .{ second.cell(r, "city").?, second.cell(r, "day").?.text, second.cell(r, "kwh").? });
    }
    try out.flush();
}

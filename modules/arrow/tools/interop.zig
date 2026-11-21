// SPDX-License-Identifier: MIT
//! A foreign reader over OUR bytes: writes one sample frame (every column type
//! the mapping covers, with nulls) with this module's writer as streams and
//! files, uncompressed, ZSTD and LZ4_FRAME, in one record batch and in several,
//! then has pyarrow (`tools/check_ours.py`) read every file and compare each
//! column's Arrow type and values. Exit 0 = pyarrow agrees on every file.
//!
//!     zig build interop-arrow
//!
//! Needs python3 with pyarrow: `python3 -m venv tools/arrow-venv &&
//! tools/arrow-venv/bin/pip install pyarrow` (picked up when present;
//! `ARROW_PYTHON` names another interpreter). Run from the repository root.

const std = @import("std");
const df = @import("dataframe");
const arrow = @import("arrow");

const Allocator = std.mem.Allocator;
const Column = df.Column;
const ColumnData = df.ColumnData;

const scale: i128 = df.decimal_scale;
const out_dir = ".zig-cache/tmp/arrow-interop";
const venv_python = "tools/arrow-venv/bin/python";
const checker = "modules/arrow/tools/check_ours.py";

fn validBits(a: Allocator, n: usize, nulls: []const usize) ![]u64 {
    const w = try a.alloc(u64, (n + 63) / 64);
    @memset(w, ~@as(u64, 0));
    for (nulls) |i| w[i / 64] &= ~(@as(u64, 1) << @as(u6, @truncate(i)));
    return w;
}

fn textCol(a: Allocator, cells: []const ?[]const u8) !df.TextColumn {
    const offs = try a.alloc(usize, cells.len + 1);
    var bytes: std.ArrayList(u8) = .empty;
    var nulls: std.ArrayList(usize) = .empty;
    offs[0] = 0;
    for (cells, 0..) |c, i| {
        if (c) |t| try bytes.appendSlice(a, t) else try nulls.append(a, i);
        offs[i + 1] = bytes.items.len;
    }
    return .{ .offsets = offs, .bytes = bytes.items, .valid = if (nulls.items.len > 0) try validBits(a, cells.len, nulls.items) else null };
}

fn sampleFrame(a: Allocator) !df.Frame {
    const n = 5;
    const ints: ColumnData = .{ .int = .{ .values = &.{ 1, -2, 0, 4, std.math.maxInt(i64) }, .valid = try validBits(a, n, &.{2}) } };
    const items = try a.create(ColumnData);
    items.* = .{ .int = .{ .values = &.{ 10, 11, 12, 13, 14, 15 }, .valid = try validBits(a, 6, &.{3}) } };
    const arr_items = try a.create(ColumnData);
    arr_items.* = .{ .float = .{ .values = &.{ 0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5 } } };
    const cat_items = try a.create(ColumnData);
    cat_items.* = .{ .categorical = .{ .codes = .{ .values = &.{ 1, 0, 1 } }, .dict = try textCol(a, &.{ "p", "q" }) } };
    const sc = try a.create(df.StructColumn);
    sc.* = .{
        .names = &.{ "a", "b" },
        .children = try a.dupe(ColumnData, &.{
            .{ .int = .{ .values = &.{ 1, 2, 3, 4, 5 }, .valid = try validBits(a, n, &.{4}) } },
            .{ .text = try textCol(a, &.{ "x", null, "", "yy", "z" }) },
        }),
        .len = n,
        .valid = try validBits(a, n, &.{1}),
    };
    const int_inner = [_]Column{.{ .name = "item", .type = .int }};
    const float_inner = [_]Column{.{ .name = "item", .type = .float }};
    const cat_inner = [_]Column{.{ .name = "item", .type = .categorical }};
    const st_inner = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text } };
    const columns = [_]Column{
        .{ .name = "i64", .type = .int },
        .{ .name = "f64", .type = .float },
        .{ .name = "b", .type = .bool },
        .{ .name = "dec", .type = .decimal },
        .{ .name = "s", .type = .text },
        .{ .name = "bin", .type = .binary },
        .{ .name = "d", .type = .date },
        .{ .name = "ts", .type = .timestamp, .time_zone = "Europe/Prague" },
        .{ .name = "ts_naive", .type = .timestamp },
        .{ .name = "dur", .type = .duration },
        .{ .name = "tm", .type = .time },
        .{ .name = "cat", .type = .categorical },
        .{ .name = "ord", .type = .categorical },
        .{ .name = "i8", .type = .int8 },
        .{ .name = "i16", .type = .int16 },
        .{ .name = "i32", .type = .int32 },
        .{ .name = "u8", .type = .uint8 },
        .{ .name = "u16", .type = .uint16 },
        .{ .name = "u32", .type = .uint32 },
        .{ .name = "u64", .type = .uint64 },
        .{ .name = "f32", .type = .float32 },
        .{ .name = "l", .type = .list, .inner = &int_inner },
        .{ .name = "arr", .type = .array, .array_width = 2, .inner = &float_inner },
        .{ .name = "st", .type = .@"struct", .inner = &st_inner },
        .{ .name = "lcat", .type = .list, .inner = &cat_inner },
        .{ .name = "nul", .type = .text },
    };
    const data = [_]ColumnData{
        ints,
        .{ .float = .{ .values = &.{ 1.5, 0, -2.25, 1e300, 0 }, .valid = try validBits(a, n, &.{ 1, 4 }) } },
        .{ .bool = .{ .values = &.{ true, false, false, true, true }, .valid = try validBits(a, n, &.{2}) } },
        .{ .decimal = .{ .values = &.{ 12_345 * scale / 100, -1, 0, std.math.maxInt(i64) * scale, 7 }, .valid = try validBits(a, n, &.{2}) } },
        .{ .text = try textCol(a, &.{ "a", "", "h\xc3\xa9llo", null, "z" }) },
        .{ .text = try textCol(a, &.{ "\x00\xff", null, "", "bytes", "\x80" }) },
        .{ .text = try textCol(a, &.{ "2024-02-29", "1970-01-01", null, "0001-01-01", "9999-12-31" }) },
        .{ .int = .{ .values = &.{ 0, 1_700_000_000_000_000, -1, 0, 86_400_000_000 }, .valid = try validBits(a, n, &.{3}) } },
        .{ .int = .{ .values = &.{ 5, 6, 7, 8, 9 } } },
        .{ .int = .{ .values = &.{ -1_000_000, 0, 3_600_000_000, 0, 1 }, .valid = try validBits(a, n, &.{3}) } },
        .{ .int = .{ .values = &.{ 0, 86_399_999_999, 12 * 3_600_000_000, 0, 1 }, .valid = try validBits(a, n, &.{3}) } },
        .{ .categorical = .{ .codes = .{ .values = &.{ 2, 0, 1, 0, 2 }, .valid = try validBits(a, n, &.{3}) }, .dict = try textCol(a, &.{ "a", "b", "c" }) } },
        .{ .categorical = .{ .codes = .{ .values = &.{ 0, 2, 1, 1, 0 } }, .dict = try textCol(a, &.{ "lo", "mid", "hi", "unused" }), .ordered = true } },
        .{ .int8 = .{ .values = &.{ -128, 127, 0, 1, -1 }, .valid = try validBits(a, n, &.{2}) } },
        .{ .int16 = .{ .values = &.{ -32768, 32767, 0, 1, -1 } } },
        .{ .int32 = .{ .values = &.{ std.math.minInt(i32), std.math.maxInt(i32), 0, 1, -1 } } },
        .{ .uint8 = .{ .values = &.{ 0, 255, 1, 2, 3 }, .valid = try validBits(a, n, &.{0}) } },
        .{ .uint16 = .{ .values = &.{ 0, 65535, 1, 2, 3 } } },
        .{ .uint32 = .{ .values = &.{ 0, std.math.maxInt(u32), 1, 2, 3 } } },
        .{ .uint64 = .{ .values = &.{ 0, std.math.maxInt(u64), 1 << 63, 2, 3 }, .valid = try validBits(a, n, &.{4}) } },
        .{ .float32 = .{ .values = &.{ 0.25, -1.5, 3.0e38, 0, 1 } } },
        .{ .list = .{ .offsets = &.{ 0, 2, 2, 2, 5, 6 }, .items = items, .valid = try validBits(a, n, &.{1}) } },
        .{ .list = .{ .offsets = &.{ 0, 2, 4, 4, 6, 8 }, .items = arr_items, .valid = try validBits(a, n, &.{2}) } },
        .{ .@"struct" = sc },
        .{ .list = .{ .offsets = &.{ 0, 1, 1, 3, 3, 3 }, .items = cat_items, .valid = try validBits(a, n, &.{4}) } },
        .nulls,
    };
    return .{ .columns = try a.dupe(Column, &columns), .data = try a.dupe(ColumnData, &data), .len = n };
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const frame = try sampleFrame(a);

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, out_dir);
    var written: usize = 0;
    inline for (.{ "stream", "file" }) |kind| {
        inline for (.{ arrow.Compression.none, .zstd, .lz4 }) |comp| {
            for ([_]usize{ 0, 2 }) |rows| {
                const opts: arrow.WriteOptions = .{ .rows_per_batch = rows, .compression = comp };
                const bytes = if (comptime std.mem.eql(u8, kind, "stream")) try arrow.writeStream(gpa, frame, opts) else try arrow.writeFile(gpa, frame, opts);
                defer gpa.free(bytes);
                const name = try std.fmt.allocPrint(a, "{s}/{s}-{s}-{d}.arrow", .{ out_dir, kind, @tagName(comp), rows });
                try cwd.writeFile(io, .{ .sub_path = name, .data = bytes });
                written += 1;
            }
        }
    }
    std.debug.print("interop-arrow: wrote {d} files to {s}\n", .{ written, out_dir });

    const python: []const u8 = if (init.environ_map.get("ARROW_PYTHON")) |p| p else blk: {
        cwd.access(io, venv_python, .{}) catch break :blk "python3";
        break :blk venv_python;
    };
    var child = std.process.spawn(io, .{
        .argv = &.{ python, checker, out_dir },
        .stdin = .close,
    }) catch |e| {
        std.debug.print("cannot run `{s} {s}`: {t}\nThis program needs python3 with pyarrow (see the header).\n", .{ python, checker, e });
        return 2;
    };
    switch (try child.wait(io)) {
        .exited => |code| return code,
        else => return 2,
    }
}

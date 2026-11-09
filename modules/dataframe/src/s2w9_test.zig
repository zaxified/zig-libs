// SPDX-License-Identifier: MIT
//! Tests of dataframe S2 wave W9: `CsvChunkReader`. The main oracle is a differential: for
//! generated inputs (quotes, embedded newlines, CRLF, BOM, comments, bad lines, nulls) and
//! every chunk size, the chunks read through a stream that hands out 1..7 bytes per call must,
//! put end to end, equal `readCsv` of the whole input cell by cell. The engines' answers for the
//! parts that are theirs (pandas per-chunk types, polars' fixed schema and `ignore_errors`) are
//! replayed in `s2w9_oracle_test.zig`.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const cio = @import("csvio.zig");
const cc = @import("csvchunk.zig");
const Frame = fm.Frame;
const Value = vm.Value;

/// A reader that returns 1..7 bytes per call, so every chunk boundary falls somewhere.
pub const Slow = struct {
    interface: std.Io.Reader,
    data: []const u8,
    pos: usize = 0,
    step: usize = 0,
    /// 0: cycle 1..7; else always this many.
    fixed: usize = 0,
    buf: [8]u8 = undefined,

    pub fn init(s: *Slow, data: []const u8, fixed: usize) void {
        s.* = .{
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = &s.buf, .seek = 0, .end = 0 },
            .data = data,
            .fixed = fixed,
        };
        s.interface.buffer = &s.buf;
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const s: *Slow = @alignCast(@fieldParentPtr("interface", r));
        if (s.pos >= s.data.len) return error.EndOfStream;
        s.step = if (s.fixed != 0) s.fixed else s.step % 7 + 1;
        const n = limit.minInt(@min(s.step, s.data.len - s.pos));
        try w.writeAll(s.data[s.pos..][0..n]);
        s.pos += n;
        return n;
    }
};

fn valueEq(x: Value, y: Value) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .null => true,
        .bool => |b| b == y.bool,
        .int => |i| i == y.int,
        .float => |f| (std.math.isNan(f) and std.math.isNan(y.float)) or f == y.float,
        .text => |t| std.mem.eql(u8, t, y.text),
        .decimal => |d| d == y.decimal,
        else => false,
    };
}

/// Collects the cells of every chunk of `bytes` read `n` rows at a time, through a slow stream.
fn chunked(a: std.mem.Allocator, bytes: []const u8, opts: cio.CsvReadOptions, copts: cc.ChunkOptions, n: usize, step: usize, out: *std.ArrayList([]const Value), widths: *usize) !void {
    var slow: Slow = undefined;
    slow.init(bytes, step);
    var rd = try cc.CsvChunkReader.init(testing.allocator, &slow.interface, opts, copts);
    defer rd.deinit();
    while (true) {
        var ar = std.heap.ArenaAllocator.init(testing.allocator);
        defer ar.deinit();
        const f = (try rd.next(ar.allocator(), n)) orelse break;
        try testing.expect(f.len <= n);
        try testing.expect(f.len > 0);
        widths.* = f.columns.len;
        for (0..f.len) |ri| {
            const row = try a.alloc(Value, f.columns.len);
            for (row, 0..) |*c, ci| {
                const v = f.columnAt(ci).get(ri);
                c.* = if (v == .text) .{ .text = try a.dupe(u8, v.text) } else v;
            }
            try out.append(a, row);
        }
    }
}

fn expectSame(input: []const u8, opts: cio.CsvReadOptions, ks: []const usize) !void {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const whole = cio.readCsv(a, input, opts);
    for (ks) |n| for ([_]usize{ 0, 1, 3 }) |step| {
        var rows: std.ArrayList([]const Value) = .empty;
        var width: usize = 0;
        if (whole) |w| {
            try chunked(a, input, opts, .{}, n, step, &rows, &width);
            try testing.expectEqual(w.len, rows.items.len);
            if (w.len != 0) try testing.expectEqual(w.columns.len, width);
            for (rows.items, 0..) |row, ri| for (row, 0..) |c, ci| {
                const want = w.columnAt(ci).get(ri);
                if (!valueEq(want, c)) {
                    std.debug.print("n={d} step={d} row {d} col {d}: want {any} got {any}\ninput: {f}\n", .{ n, step, ri, ci, want, c, std.zig.fmtString(input) });
                    return error.TestExpectedEqual;
                }
            };
        } else |we| {
            // The whole read refuses: so does the stream, at some chunk (the same error,
            // or the stream's own cap error for what a stream cannot see whole).
            const r = chunked(a, input, opts, .{}, n, step, &rows, &width);
            try testing.expectError(we, r);
        }
    };
}

const all_types = [_]cio.TypeOverride{
    .{ .name = "a", .type = .int },
    .{ .name = "b", .type = .text },
    .{ .name = "c", .type = .float },
};

test "w9 differential: hand-written inputs, every chunk size, 1..7 bytes per read" {
    const inputs = [_][]const u8{
        "a,b,c\n1,x,1.5\n2,y,2.5\n3,z,\n",
        "a,b,c\r\n1,\"x,y\",1.5\r\n2,\"line\nbreak\",2.5\r\n3,\"q\"\"uote\",\r\n",
        "\xEF\xBB\xBFa,b,c\n1,x,1\n2,y,2",
        "a,b,c\n\n1,x,1\n\n\n2,y,2\n\n",
        "# comment\na,b,c\n1,x,1\n# another\n2,\"# not a comment\",2\n",
        "a,b,c\n1,x,1\n2,y\n3,z,3,extra\n4,w,4\n",
        "a,b,c\n1,\"multi\r\nline\r\nfield\",1\n2,\"\",\n3,,3\n",
        "a,b,c\n",
        "a,b,c\n1,\"unterminated,1\n2,y,2\n",
        "a,b,c\n1,x,notafloat\n",
        "a,b,c\n1,\"a\nb\nc\nd\ne\nf\",1\n2,\"g\",2\n",
    };
    const variants = [_]cio.CsvReadOptions{
        .{ .types = &all_types },
        .{ .types = &all_types, .comment = '#' },
        .{ .types = &all_types, .truncate_ragged = true },
        .{ .types = &all_types, .on_bad_lines = .skip },
        .{ .types = &all_types, .strict_quotes = false },
        .{ .types = &all_types, .n_rows = 2 },
        .{ .types = &all_types, .skip_rows_after_header = 1 },
        .{ .types = &all_types, .row_index_name = "idx", .row_index_offset = 100 },
        .{ .types = &all_types, .columns = &.{ "a", "c" } },
        .{ .types = &all_types, .null_values = &cio.polars_na_values },
        .{ .types = &all_types, .max_quoted_lines = 3 },
    };
    for (inputs) |inp| for (variants) |v| try expectSame(inp, v, &.{ 1, 2, 3, 5, 100 });
}

test "w9 differential: no header, skip_rows, quote off, tab delimiter, other options" {
    const hl = [_]cio.TypeOverride{ .{ .name = "column_0", .type = .int }, .{ .name = "column_1", .type = .text } };
    try expectSame("1,x\n2,y\n3,\"z\nw\"\n", .{ .has_header = false, .types = &hl }, &.{ 1, 2, 4 });
    try expectSame("1,x\n2,y\n3,z\n", .{ .has_header = false, .names = &.{ "p", "q" }, .types = &.{.{ .name = "p", .type = .int }} }, &.{ 1, 2 });
    try expectSame("junk\nmore junk\na\tb\n1\tx\n2\ty\n", .{ .skip_rows = 2, .delimiter = '\t' }, &.{ 1, 2 });
    try expectSame("a,b\n1,\"x\n2,y\n", .{ .quote = 0, .types = &.{.{ .name = "a", .type = .int }} }, &.{ 1, 2 });
    try expectSame("a;b\n1,5;x\n2,5;y\n", .{ .delimiter = ';', .decimal = ',', .types = &.{.{ .name = "a", .type = .float }} }, &.{ 1, 2 });
    try expectSame("a\n1,000\n2,000\n", .{ .thousands = ',', .types = &.{.{ .name = "a", .type = .int }} }, &.{ 1, 2 });
    try expectSame("a,b\n1,2\n", .{ .names = &.{ "p", "p" } }, &.{1});
    try expectSame("", .{}, &.{1});
}

test "w9 differential: generated inputs" {
    var prng = std.Random.DefaultPrng.init(0x9a11);
    const rnd = prng.random();
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const pieces = [_][]const u8{ "1", "-7", "2.5", "", "x", "\"q,r\"", "\"a\nb\"", "\"he said \"\"hi\"\"\"", "NA", "# c", "\"\"", " 4 " };
    for (0..300) |_| {
        var text: std.ArrayList(u8) = .empty;
        if (rnd.boolean()) try text.appendSlice(a, "\xEF\xBB\xBF");
        try text.appendSlice(a, "a,b,c\n");
        const rows = rnd.uintLessThan(usize, 12);
        const eol: []const u8 = if (rnd.boolean()) "\n" else "\r\n";
        for (0..rows) |_| {
            if (rnd.uintLessThan(u8, 12) == 0) try text.appendSlice(a, eol);
            if (rnd.uintLessThan(u8, 15) == 0) try text.appendSlice(a, "# note\n");
            const w = 3 - @as(usize, if (rnd.uintLessThan(u8, 12) == 0) 1 else 0) + @as(usize, if (rnd.uintLessThan(u8, 12) == 0) 1 else 0);
            for (0..w) |j| {
                if (j != 0) try text.append(a, ',');
                try text.appendSlice(a, pieces[rnd.uintLessThan(usize, pieces.len)]);
            }
            try text.appendSlice(a, eol);
        }
        if (rnd.boolean() and text.items.len > 0) _ = text.pop();
        // Types are left to be fixed as text so no cell can fail: this is about record cutting.
        const opts: cio.CsvReadOptions = .{
            .infer_types = false,
            .comment = if (rnd.boolean()) '#' else 0,
            .on_bad_lines = if (rnd.boolean()) .skip else .@"error",
            .truncate_ragged = rnd.uintLessThan(u8, 4) == 0,
            .strict_quotes = rnd.uintLessThan(u8, 4) != 0,
        };
        try expectSame(text.items, opts, &.{ 1, 2, 3, 7, 1000 });
    }
}

// ── the reader's own behaviour ───────────────────────────────────────────────

fn open(slow: *Slow, bytes: []const u8, opts: cio.CsvReadOptions, copts: cc.ChunkOptions) !cc.CsvChunkReader {
    slow.init(bytes, 0);
    return cc.CsvChunkReader.init(testing.allocator, &slow.interface, opts, copts);
}

fn colTypes(f: Frame) [8]vm.ColumnType {
    var out: [8]vm.ColumnType = @splat(.text);
    for (f.columns, 0..) |c, i| out[i] = c.type;
    return out;
}

test "w9 schema: first chunk fixes the types, a later bad cell is BadValue with its line" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var slow: Slow = undefined;
    var rd = try open(&slow, "a,b\n1,x\n2,y\n3.5,z\n4,w\n", .{}, .{});
    defer rd.deinit();
    const f1 = (try rd.next(a, 2)).?;
    try testing.expectEqual(vm.ColumnType.int, f1.columns[0].type);
    try testing.expectEqual(@as(usize, 2), f1.len);
    try testing.expectError(error.BadValue, rd.next(a, 2));
    try testing.expectEqual(@as(u64, 4), rd.error_line);
}

test "w9 schema: infer_rows reads ahead and fixes float; per_chunk is pandas" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const text = "a,b\n1,x\n2,y\n3.5,z\n4,w\n";
    {
        var slow: Slow = undefined;
        var rd = try open(&slow, text, .{}, .{ .infer_rows = 4 });
        defer rd.deinit();
        const f1 = (try rd.next(a, 2)).?;
        try testing.expectEqual(vm.ColumnType.float, f1.columns[0].type);
        try testing.expectEqual(@as(f64, 2), f1.columnAt(0).get(1).float);
        const f2 = (try rd.next(a, 2)).?;
        try testing.expectEqual(vm.ColumnType.float, f2.columns[0].type);
        try testing.expectEqual(@as(f64, 3.5), f2.columnAt(0).get(0).float);
        try testing.expect((try rd.next(a, 2)) == null);
    }
    {
        var slow: Slow = undefined;
        var rd = try open(&slow, text, .{}, .{ .schema = .per_chunk });
        defer rd.deinit();
        try testing.expectEqual(vm.ColumnType.int, (try rd.next(a, 2)).?.columns[0].type);
        try testing.expectEqual(vm.ColumnType.float, (try rd.next(a, 2)).?.columns[0].type);
    }
}

test "w9 ignore_errors nulls the bad cell; it needs a null marker" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const text = "a,b\n1,x\n2,y\nzz,\"q,r\"\n4,w\n";
    var slow: Slow = undefined;
    var rd = try open(&slow, text, .{}, .{ .ignore_errors = true });
    defer rd.deinit();
    _ = (try rd.next(a, 2)).?;
    const f2 = (try rd.next(a, 2)).?;
    try testing.expectEqual(@as(usize, 2), f2.len);
    try testing.expect(f2.columnAt(0).get(0) == .null);
    try testing.expectEqual(@as(i64, 4), f2.columnAt(0).get(1).int);
    try testing.expectEqualStrings("q,r", f2.columnAt(1).get(0).text);
    // No marker at all: the error stays.
    var slow2: Slow = undefined;
    var rd2 = try open(&slow2, text, .{ .null_values = &.{} }, .{ .ignore_errors = true });
    defer rd2.deinit();
    _ = (try rd2.next(a, 2)).?;
    try testing.expectError(error.BadValue, rd2.next(a, 2));
    try testing.expectEqual(@as(u64, 4), rd2.error_line);
}

test "w9 counters run across chunks: n_rows, row index, bad lines" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var slow: Slow = undefined;
    var bad: usize = 99;
    var rd = try open(&slow, "a\n1\n2,9\n3\n4\n5,9\n6\n7\n", .{ .row_index_name = "i", .row_index_offset = 10, .on_bad_lines = .skip, .bad_lines_skipped = &bad, .n_rows = 5 }, .{});
    defer rd.deinit();
    const f1 = (try rd.next(a, 2)).?;
    try testing.expectEqual(@as(i64, 10), f1.columnAt(0).get(0).int);
    try testing.expectEqual(@as(i64, 3), f1.columnAt(1).get(1).int);
    const f2 = (try rd.next(a, 2)).?;
    try testing.expectEqual(@as(i64, 12), f2.columnAt(0).get(0).int);
    try testing.expectEqual(@as(i64, 4), f2.columnAt(1).get(0).int);
    const f3 = (try rd.next(a, 2)).?;
    try testing.expectEqual(@as(usize, 1), f3.len);
    try testing.expectEqual(@as(i64, 14), f3.columnAt(0).get(0).int);
    try testing.expect((try rd.next(a, 2)) == null);
    try testing.expectEqual(@as(usize, 2), bad);
}

test "w9 options: skipfooter refused, n of 0, header only, empty input" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var slow: Slow = undefined;
    slow.init("a\n1\n", 0);
    try testing.expectError(error.UnsupportedOption, cc.CsvChunkReader.init(testing.allocator, &slow.interface, .{ .skipfooter = 1 }, .{}));
    try testing.expectError(error.BadOptions, cc.CsvChunkReader.init(testing.allocator, &slow.interface, .{ .delimiter = '\n' }, .{}));
    var rd = try open(&slow, "a,b\n", .{}, .{});
    defer rd.deinit();
    try testing.expectError(error.BadOptions, rd.next(a, 0));
    try testing.expect((try rd.next(a, 5)) == null);
    var slow2: Slow = undefined;
    var rd2 = try open(&slow2, "", .{}, .{});
    defer rd2.deinit();
    try testing.expectError(error.EmptyInput, rd2.next(a, 5));
}

test "w9 limits: a record or a chunk past the cap is an error, memory stays at the chunk" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var slow: Slow = undefined;
    var rd = try open(&slow, "a\n1\n2222222222222222222222222222222\n3\n", .{ .max_record_bytes = 16 }, .{});
    defer rd.deinit();
    try testing.expectError(error.RecordTooLarge, rd.next(a, 5));
    var slow2: Slow = undefined;
    var rd2 = try open(&slow2, "a\n1\n2\n3\n4\n5\n", .{ .max_bytes = 8 }, .{});
    defer rd2.deinit();
    try testing.expectError(error.InputTooLarge, rd2.next(a, 5));
    // A stream much larger than a chunk: the reader's buffers do not follow it.
    var big: std.ArrayList(u8) = .empty;
    defer big.deinit(testing.allocator);
    try big.appendSlice(testing.allocator, "a,b\n");
    for (0..20000) |i| try big.print(testing.allocator, "{d},\"text {d}\"\n", .{ i, i });
    var slow3: Slow = undefined;
    slow3.init(big.items, 5);
    var rd3 = try cc.CsvChunkReader.init(testing.allocator, &slow3.interface, .{}, .{});
    defer rd3.deinit();
    var rows: usize = 0;
    while (true) {
        var chunk_arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer chunk_arena.deinit();
        const f = (try rd3.next(chunk_arena.allocator(), 10)) orelse break;
        rows += f.len;
    }
    try testing.expectEqual(@as(usize, 20000), rows);
    try testing.expect(rd3.buf.capacity < 4096);
    try testing.expect(rd3.win.capacity < 4096);
}

test "w9 headerless first chunk and enums keep the whole-read meaning" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var slow: Slow = undefined;
    var rd = try open(&slow, "1,x\n2,y\n3,x\n", .{ .has_header = false, .skip_rows_after_header = 1 }, .{});
    defer rd.deinit();
    const f1 = (try rd.next(a, 1)).?;
    try testing.expectEqualStrings("column_0", f1.columns[0].name);
    try testing.expectEqual(@as(i64, 2), f1.columnAt(0).get(0).int);
    const f2 = (try rd.next(a, 1)).?;
    try testing.expectEqual(@as(i64, 3), f2.columnAt(0).get(0).int);
    const decl = [_]@import("catfn.zig").EnumDecl{.{ .name = "b", .categories = &.{ "x", "y" } }};
    var slow2: Slow = undefined;
    var rd2 = try open(&slow2, "a,b\n1,x\n2,y\n3,z\n", .{ .enums = &decl }, .{});
    defer rd2.deinit();
    _ = (try rd2.next(a, 2)).?;
    try testing.expectError(error.BadValue, rd2.next(a, 2));
}

// ── ndjson ──────────────────────────────────────────────────────────────────

const nd = @import("ndjsonchunk.zig");
const jr = @import("jsonread.zig");

test "w9 ndjson: chunks put end to end equal the whole read, through a slow stream" {
    const text = "{\"a\":1,\"b\":\"x\"}\r\n\n{\"a\":2,\"b\":\"y\\nz\"}\n  \n{\"a\":null,\"b\":\"w\"}\n{\"a\":4,\"b\":null}";
    const opts: jr.JsonReadOptions = .{ .types = &.{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .text } } };
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const whole = try jr.readNdjson(a, text, opts);
    for ([_]usize{ 1, 2, 3, 100 }) |n| for ([_]usize{ 0, 1, 4 }) |step| {
        var slow: Slow = undefined;
        slow.init(text, step);
        var rd = nd.NdjsonChunkReader.init(testing.allocator, &slow.interface, opts);
        defer rd.deinit();
        var row: usize = 0;
        while (true) {
            var ca = std.heap.ArenaAllocator.init(testing.allocator);
            defer ca.deinit();
            const f = (try rd.next(ca.allocator(), n)) orelse break;
            try testing.expect(f.len <= n);
            for (0..f.len) |ri| {
                for (0..2) |ci| try testing.expect(valueEq(whole.columnAt(ci).get(row), f.columnAt(ci).get(ri)));
                row += 1;
            }
        }
        try testing.expectEqual(whole.len, row);
    };
}

test "w9 ndjson: n_rows is the stream's, a long line is an error, n of 0 is refused" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var slow: Slow = undefined;
    slow.init("{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n", 0);
    var rd = nd.NdjsonChunkReader.init(testing.allocator, &slow.interface, .{ .n_rows = 3 });
    defer rd.deinit();
    try testing.expectError(error.BadShape, rd.next(a, 0));
    try testing.expectEqual(@as(usize, 2), (try rd.next(a, 2)).?.len);
    try testing.expectEqual(@as(usize, 1), (try rd.next(a, 2)).?.len);
    try testing.expect((try rd.next(a, 2)) == null);
    var slow2: Slow = undefined;
    slow2.init("{\"a\":\"0123456789012345678901234567890123456789\"}\n", 0);
    var rd2 = nd.NdjsonChunkReader.init(testing.allocator, &slow2.interface, .{ .max_bytes = 16 });
    defer rd2.deinit();
    try testing.expectError(error.InputTooLarge, rd2.next(a, 2));
}

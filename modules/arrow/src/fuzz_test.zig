// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for the readers (wave A6): `readStream`, and
//! `openFile` + `File.readBatch` / `readAll`, over hostile input.
//!
//! The harness is generic over its source of choices (testkit's fuzz driver
//! hands it `fuzz.Rng`, `std.testing.fuzz` a `Smith`). Under the driver, an
//! input is a VALID stream or file — an apache/arrow-testing golden file, or a
//! frame this module wrote (plain and zstd-compressed, one batch and many) —
//! damaged where it matters: a framing length, a FlatBuffers offset or vtable
//! field, a node length or null count, a buffer location, a compressed buffer's
//! length prefix, the file footer and its blocks, or plain bytes, then maybe
//! truncated. Every input must end in an error or a frame, never a panic or a
//! hang. The oracle on a frame: the writer writes it, and that reads back equal
//! cell by cell (a frame the reader makes is one the writer takes).
//!
//! Inputs are also read with one column projected (`ReadOptions.columns`) and with the
//! key/value metadata asked for; the golden inputs for Decimal32/256, RunEndEncoded,
//! the view types, Map, custom metadata, nested and shared dictionaries carry a reach
//! label each, as does a stream that replaces its dictionary between two batches.
//!
//! Driver: `ARROW_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). Harness name: `read`.

const std = @import("std");
const df = @import("dataframe");
const testkit = @import("testkit");
const stream = @import("stream.zig");
const st = @import("stream_test.zig");
const ipc = @import("ipc.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;
const fuzz_driver = testkit.fuzz.driver;

const golden = [_][]const u8{
    @embedFile("testdata/1.0.0-littleendian/generated_primitive.stream"),
    @embedFile("testdata/1.0.0-littleendian/generated_nested.arrow_file"),
    @embedFile("testdata/1.0.0-littleendian/generated_dictionary.stream"),
    @embedFile("testdata/1.0.0-littleendian/generated_recursive_nested.arrow_file"),
    @embedFile("testdata/1.0.0-littleendian/generated_datetime.stream"),
    @embedFile("testdata/1.0.0-littleendian/generated_nested_large_offsets.stream"),
    @embedFile("testdata/1.0.0-littleendian/generated_extension.arrow_file"),
    @embedFile("testdata/1.0.0-littleendian/generated_null.stream"),
    @embedFile("testdata/2.0.0-compression/generated_zstd.stream"),
    @embedFile("testdata/2.0.0-compression/generated_zstd.arrow_file"),
    @embedFile("testdata/2.0.0-compression/generated_uncompressible_zstd.stream"),
    @embedFile("testdata/1.0.0-littleendian/generated_custom_metadata.arrow_file"),
    @embedFile("testdata/cpp-21.0.0/generated_decimal32.stream"),
    @embedFile("testdata/cpp-21.0.0/generated_decimal256.stream"),
    @embedFile("testdata/cpp-21.0.0/generated_run_end_encoded.arrow_file"),
    @embedFile("testdata/cpp-21.0.0/generated_binary_view.stream"),
    @embedFile("testdata/cpp-21.0.0/generated_list_view.stream"),
    @embedFile("testdata/1.0.0-littleendian/generated_map.arrow_file"),
    @embedFile("testdata/1.0.0-littleendian/generated_nested_dictionary.stream"),
    @embedFile("testdata/4.0.0-shareddict/generated_shared_dict.arrow_file"),
};

/// Reach labels for the golden inputs that exercise one decoder each (a frame read from
/// one, damaged or not, reached that decoder).
const golden_label = [golden.len]?[]const u8{ null, null, null, null, null, null, null, null, null, null, null, "key/value metadata", "Decimal32", "Decimal256", "RunEndEncoded", "BinaryView/Utf8View", "ListView/LargeListView", "Map", "nested dictionary", "shared dictionary" };

fn hitSource(pick: usize) void {
    inline for (golden_label, 0..) |l, i| {
        if (l) |name| {
            if (pick == i) fuzz_driver.hit("frame from the " ++ name ++ " golden");
        }
    }
    if (pick == golden.len) fuzz_driver.hit("frame from the dictionary replacement stream");
}

/// The inputs damage starts from: the golden files above and what this module writes
/// of `sample` (built once, kept for the process).
var corpus_buf: [golden.len + 9][]const u8 = undefined;
var corpus: []const []const u8 = &.{};

fn buildCorpus() ![]const []const u8 {
    if (corpus.len > 0) return corpus;
    const keep = std.heap.page_allocator; // global-alloc-ok: process-lifetime fixtures of a test-only harness
    var arena = std.heap.ArenaAllocator.init(keep);
    const a = arena.allocator();
    const f = try st.sampleFrame(a);
    var n: usize = 0;
    for (golden) |g| {
        corpus_buf[n] = g;
        n += 1;
    }
    corpus_buf[n] = try replacementStream(a);
    n += 1;
    for ([_]stream.WriteOptions{
        .{},
        .{ .rows_per_batch = 2 },
        .{ .compression = .zstd },
        .{ .compression = .zstd, .rows_per_batch = 2 },
    }) |o| {
        corpus_buf[n] = try stream.writeStream(a, f, o);
        corpus_buf[n + 1] = try stream.writeFile(a, f, o);
        n += 2;
    }
    corpus = corpus_buf[0..n];
    return corpus;
}

/// A stream whose dictionary is replaced between its two record batches: the schema,
/// dictionary and batch of one written stream, then the dictionary and batch of another
/// with the same schema and other categories.
fn replacementStream(a: Allocator) ![]const u8 {
    var parts: [2][]const u8 = undefined;
    for (&parts, [_][]const ?[]const u8{ &.{ "p", "q" }, &.{ "r", "q", "s" } }) |*p, cats| {
        const f: df.Frame = .{
            .columns = &.{.{ .name = "c", .type = .categorical }},
            .data = try a.dupe(df.ColumnData, &.{.{ .categorical = .{ .codes = .{ .values = &.{ 1, 0 } }, .dict = try st.textCol(a, cats) } }}),
            .len = 2,
        };
        p.* = try stream.writeStream(a, f, .{});
    }
    var pos: usize = 0;
    _ = try ipc.readMessage(parts[1], &pos); // the second stream's schema
    const tail = parts[1][pos..];
    const eos = 8;
    const out = try a.alloc(u8, parts[0].len - eos + tail.len);
    @memcpy(out[0 .. parts[0].len - eos], parts[0][0 .. parts[0].len - eos]);
    @memcpy(out[parts[0].len - eos ..], tail);
    return out;
}

/// Where the damage goes: structure first, since random offsets almost never hit the
/// bytes that matter.
const Damage = enum { byte, int32, int64, tail, near_marker, splice };

fn damage(comptime S: type, src: *S, buf: []u8, base: []const u8) usize {
    var n = @min(base.len, buf.len);
    @memcpy(buf[0..n], base[0..n]);
    const k = src.valueRangeAtMost(u8, 1, 4);
    for (0..k) |_| {
        if (n < 8) break;
        switch (src.valueRangeAtMost(u8, 0, @typeInfo(Damage).@"enum".field_names.len - 1)) {
            // A random byte anywhere.
            0 => buf[src.index(n)] = src.value(u8),
            // An aligned 4-byte field (metadata lengths, vtable offsets, i32 offsets,
            // list sizes) set to an edge value.
            1 => {
                const at = src.index(n / 4) * 4;
                if (at + 4 <= n) std.mem.writeInt(i32, buf[at..][0..4], edge32(src), .little);
            },
            // An aligned 8-byte field (node lengths, null counts, buffer locations,
            // compressed lengths, footer block offsets).
            2 => {
                const at = src.index(n / 8) * 8;
                if (at + 8 <= n) std.mem.writeInt(i64, buf[at..][0..8], edge64(src), .little);
            },
            // The last 256 bytes: a file's footer, its length, the trailing mark.
            3 => {
                const span = @min(n, 256);
                buf[n - span + src.index(span)] = src.value(u8);
            },
            // Just after a continuation marker: a message's metadata length and table.
            4 => {
                var at = src.index(n);
                while (at + 4 <= n and !std.mem.eql(u8, buf[at..][0..4], "\xff\xff\xff\xff")) at += 1;
                const off = at + 4 + src.index(32);
                if (off < n) buf[off] = src.value(u8);
            },
            // A run of bytes copied from elsewhere in the input.
            5 => {
                const from = src.index(n);
                const to = src.index(n);
                const len = @min(src.valueRangeAtMost(usize, 1, 64), n - from, n - to);
                std.mem.copyForwards(u8, buf[to..][0..len], buf[from..][0..len]);
            },
            else => unreachable,
        }
    }
    if (src.valueRangeAtMost(u8, 0, 7) == 0) n = src.index(n + 1);
    return n;
}

fn edge32(src: anytype) i32 {
    const e = [_]i32{ 0, 1, -1, 2, 7, 8, 64, 255, 1 << 16, std.math.maxInt(i32), std.math.minInt(i32), -8 };
    return if (src.value(bool)) e[src.index(e.len)] else src.value(i32);
}

fn edge64(src: anytype) i64 {
    const e = [_]i64{ 0, 1, -1, 2, 8, 1 << 20, 1 << 31, 1 << 40, std.math.maxInt(i64), std.math.minInt(i64) };
    return if (src.value(bool)) e[src.index(e.len)] else src.value(i64);
}

/// Cell equality that a NaN (which `Value.eql` never equals) does not fail.
fn sameCell(x: df.Value, y: df.Value, depth: usize) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    if (depth > 70) return true;
    return switch (x) {
        .null => true,
        .float => |a| a == y.float or (std.math.isNan(a) and std.math.isNan(y.float)),
        .list => |l| blk: {
            if (l.len() != y.list.len()) break :blk false;
            for (0..l.len()) |i| if (!sameCell(l.get(i), y.list.get(i), depth + 1)) break :blk false;
            break :blk true;
        },
        .record => |r| blk: {
            if (r.len() != y.record.len()) break :blk false;
            for (0..r.len()) |i| if (!sameCell(r.get(i), y.record.get(i), depth + 1)) break :blk false;
            break :blk true;
        },
        else => x.eql(y),
    };
}

/// The oracle on a frame the reader made: written and read back, cell for cell.
fn rewrites(gpa: Allocator, a: Allocator, f: df.Frame, compress: bool) !void {
    const bytes = stream.writeStream(gpa, f, .{ .rows_per_batch = 3, .compression = if (compress) .zstd else .none }) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => {
            std.debug.print("rewrite refused: {t}\n", .{e});
            return error.RewriteRefused;
        },
    };
    defer gpa.free(bytes);
    const back = try stream.readStream(a, bytes, .{});
    if (back.len != f.len or back.columns.len != f.columns.len) return error.RewriteDiffers;
    for (0..f.columns.len) |ci| {
        if (back.columns[ci].type != f.columns[ci].type) return error.RewriteDiffers;
        for (0..f.len) |r| {
            if (!sameCell(f.columnAt(ci).get(r), back.columnAt(ci).get(r), 0)) {
                std.debug.print("rewrite: column {d} row {d}: {any} vs {any}\n", .{ ci, r, f.columnAt(ci).get(r), back.columnAt(ci).get(r) });
                return error.RewriteDiffers;
            }
        }
    }
}

fn harness(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    var buf: [32 << 10]u8 = undefined;
    var n: usize = undefined;
    var compressed = false;
    var pick: usize = std.math.maxInt(usize);
    if (S == fuzz_driver.Rng) {
        const c = try buildCorpus();
        pick = src.index(c.len);
        compressed = isCompressed(pick);
        n = damage(S, src, &buf, c[pick]);
    } else n = src.slice(&buf);
    const input = buf[0..n];
    // Sometimes one column projected (an index past the last is `UnknownColumn`), sometimes
    // the key/value metadata asked for.
    var md: stream.Metadata = .{};
    const col = src.valueRangeAtMost(u8, 0, 11);
    const one_col = [_]stream.ColumnRef{.{ .index = col }};
    const opts: stream.ReadOptions = .{
        .max_rows = 1 << 14,
        .max_body_bytes = 1 << 22,
        .lossy = src.value(bool),
        .columns = if (col < 4) &one_col else null,
        .metadata = if (src.value(bool)) &md else null,
    };

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const is_file = n >= 6 and std.mem.eql(u8, input[0..6], "ARROW1");
    const frame: ?df.Frame = if (is_file) blk: {
        var file = stream.openFile(a, input, opts) catch |e| break :blk outcome(e);
        fuzz_driver.hit("file opened");
        if (file.batchCount() > 0) {
            if (file.readBatch(src.index(file.batchCount()))) |_| fuzz_driver.hit("file batch") else |e| _ = outcome(e);
        }
        break :blk file.readAll() catch |e| outcome(e);
    } else stream.readStream(a, input, opts) catch |e| outcome(e);
    const f = frame orelse return;
    fuzz_driver.hit("frame");
    if (compressed) fuzz_driver.hit("frame from a compressed input");
    if (f.len > 0) fuzz_driver.hit("frame with rows");
    if (opts.columns != null) fuzz_driver.hit("projected frame");
    if (md.schema.len > 0 or (md.fields.len > 0 and md.fields[0].metadata.len > 0)) fuzz_driver.hit("metadata read");
    hitSource(pick);
    try rewrites(gpa, a, f, src.value(bool));
}

/// Corpus entries whose bodies are zstd-compressed: three golden files and the last
/// four this module wrote.
fn isCompressed(i: usize) bool {
    return (i >= 8 and i < 11) or i >= golden.len + 4;
}

fn outcome(e: stream.Error) ?df.Frame {
    switch (e) {
        error.Malformed => fuzz_driver.hit("Malformed"),
        error.Unsupported => fuzz_driver.hit("Unsupported"),
        error.LimitExceeded => fuzz_driver.hit("LimitExceeded"),
        error.OutOfMemory => fuzz_driver.hit("OutOfMemory"),
        error.InvalidUtf8 => fuzz_driver.hit("InvalidUtf8"),
        error.UnknownColumn => fuzz_driver.hit("UnknownColumn"),
    }
    return null;
}

test "fuzz: the readers (exploration, optional)" {
    try testing.fuzz({}, struct {
        fn f(_: void, s: *testing.Smith) anyerror!void {
            return harness(testing.Smith, s, testing.allocator);
        }
    }.f, .{});
}

test "fuzz driver: the readers" {
    try fuzz_driver.run(harness, .{ .prefix = "ARROW_FUZZ", .name = "read" });
}

test "fuzz harness: every corpus entry reads and rewrites undamaged" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (try buildCorpus()) |c| {
        const f = if (std.mem.eql(u8, c[0..6], "ARROW1"))
            try stream.readFile(a, c, .{ .lossy = true })
        else
            try stream.readStream(a, c, .{ .lossy = true });
        try rewrites(testing.allocator, a, f, true);
    }
}

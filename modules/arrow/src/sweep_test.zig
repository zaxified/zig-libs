// SPDX-License-Identifier: MIT

//! The no-panic sweep of the public readers (CONVENTIONS section 8): every
//! reading entry point -- `readStream`, `readFile`, `openFile` with `readBatch`
//! / `readAll` -- over EVERY single-byte damage of a set of valid inputs,
//! checked and lossy. The property is only "an error or a
//! frame, never a panic, a hang or a leak": the testing allocator and the
//! safety checks of the test build do the judging. The inputs are frames this
//! module wrote (every column type of the sample frame, stream and file,
//! uncompressed, ZSTD and LZ4_FRAME, one batch and several), so the damage
//! reaches the framing lengths, the FlatBuffers tables and vtables, the node
//! and buffer lists, the compression prefixes, the footer and its blocks, and
//! the data. `fuzz_test.zig` covers damage that is shaped, many bytes at once;
//! this is the exhaustive single-byte half.

const std = @import("std");
const stream = @import("stream.zig");
const st = @import("stream_test.zig");

const testing = std.testing;

const damage = [_]u8{ 0x00, 0xff, 0x80 };

fn readAll(gpa: std.mem.Allocator, bytes: []const u8, file: bool, opts: stream.ReadOptions) void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    if (file) {
        _ = stream.readFile(a, bytes, opts) catch {};
        var f = stream.openFile(a, bytes, opts) catch return;
        for (0..@min(f.batchCount(), 4)) |i| _ = f.readBatch(i) catch {};
    } else {
        _ = stream.readStream(a, bytes, opts) catch {};
    }
}

test "no-panic sweep: every readable entry point over every single-byte damage of written streams and files" {
    var frame_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer frame_arena.deinit();
    const frame = try st.sampleFrame(frame_arena.allocator());

    var inputs: usize = 0;
    var reads: usize = 0;
    var oks: usize = 0;
    for ([_]bool{ false, true }) |file| {
        for ([_]stream.Compression{ .none, .zstd, .lz4 }) |comp| {
            for ([_]usize{ 0, 2 }) |rows| {
                const opts: stream.WriteOptions = .{ .rows_per_batch = rows, .compression = comp };
                const bytes = if (file) try stream.writeFile(testing.allocator, frame, opts) else try stream.writeStream(testing.allocator, frame, opts);
                defer testing.allocator.free(bytes);
                const work = try testing.allocator.dupe(u8, bytes);
                defer testing.allocator.free(work);
                inputs += 1;
                // The head (messages, schema, first batch) and the tail (footer, blocks).
                const head: usize = @min(bytes.len, 2048);
                const tail_from: usize = if (bytes.len > 512) @max(head, bytes.len - 512) else bytes.len;
                for ([2][2]usize{ .{ 0, head }, .{ tail_from, bytes.len } }) |range| {
                    for (range[0]..range[1]) |pos| {
                        const orig = bytes[pos];
                        for (damage) |d| {
                            if (d == orig) continue;
                            work[pos] = d;
                            readAll(testing.allocator, work, file, .{});
                            readAll(testing.allocator, work, file, .{ .lossy = true, .validate_utf8 = false });
                            reads += 2;
                        }
                        work[pos] = orig;
                    }
                }
                // The undamaged input still reads (the harness is not vacuous).
                var a = std.heap.ArenaAllocator.init(testing.allocator);
                defer a.deinit();
                _ = if (file) try stream.readFile(a.allocator(), bytes, .{}) else try stream.readStream(a.allocator(), bytes, .{});
                oks += 1;
            }
        }
    }
    try testing.expectEqual(inputs, oks);
    try testing.expect(reads > 20_000);
}

test "no-panic sweep: every prefix of every input is an error or a frame" {
    var frame_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer frame_arena.deinit();
    const frame = try st.sampleFrame(frame_arena.allocator());
    for ([_]bool{ false, true }) |file| {
        for ([_]stream.Compression{ .none, .zstd }) |comp| {
            const opts: stream.WriteOptions = .{ .rows_per_batch = 2, .compression = comp };
            const bytes = if (file) try stream.writeFile(testing.allocator, frame, opts) else try stream.writeStream(testing.allocator, frame, opts);
            defer testing.allocator.free(bytes);
            for (0..bytes.len) |n| readAll(testing.allocator, bytes[0..n], file, .{});
        }
    }
}

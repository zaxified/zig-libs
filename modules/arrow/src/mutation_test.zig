// SPDX-License-Identifier: MIT

//! Tests the delta mutation audit of 2026-11-25 asked for: the checked contract
//! panics of `fb.Builder` and `ipc.writeMessage` (observed in a forked child, as a
//! panic cannot be caught in-process), the 32-bit size edges, and the saturating
//! sums of the reader over lengths no real stream could back with bytes.

const std = @import("std");
const testkit = @import("testkit");
const fb = @import("fb.zig");
const ipc = @import("ipc.zig");
const schema = @import("schema.zig");
const stream = @import("stream.zig");
const st = @import("stream_test.zig");

const testing = std.testing;

const Violation = enum {
    string_in_table,
    vector_in_table,
    struct_vector_in_table,
    struct_vector_ragged,
    offset_vector_in_table,
    nested_start_table,
    field_outside_table,
    end_without_start,
    finish_in_table,
    write_message_ragged_body,
};

/// Does one contract violation and returns 0 if it survived (it must not).
fn violate(v: Violation) u8 {
    const gpa = std.heap.page_allocator; // global-alloc-ok: runs in a forked child that must panic; no leak check applies
    var b = fb.Builder.init(gpa);
    switch (v) {
        .string_in_table => {
            b.startTable();
            _ = b.createString("x") catch {};
        },
        .vector_in_table => {
            b.startTable();
            _ = b.createVector(u8, "x") catch {};
        },
        .struct_vector_in_table => {
            b.startTable();
            _ = b.createStructVector("ab", 2, 1) catch {};
        },
        .struct_vector_ragged => _ = b.createStructVector("abc", 2, 1) catch {},
        .offset_vector_in_table => {
            b.startTable();
            _ = b.createOffsetVector(&.{}) catch {};
        },
        .nested_start_table => {
            b.startTable();
            b.startTable();
        },
        .field_outside_table => b.addScalarForce(0, u8, 1) catch {},
        .end_without_start => _ = b.endTable() catch {},
        .finish_in_table => {
            b.startTable();
            _ = b.finish(0) catch {};
        },
        .write_message_ragged_body => {
            var out: std.ArrayList(u8) = .empty;
            ipc.writeMessage(gpa, &out, "meta", "short") catch {};
        },
    }
    return 0;
}

test "mutation 2026-11-25: every builder and writeMessage contract violation is a panic in every mode" {
    if (!testkit.child.supported) return error.SkipZigTest;
    inline for (comptime std.enums.values(Violation)) |v| {
        const out = try testkit.child.run(violate, .{v}, .{ .limit_ms = 5000 });
        testing.expect(out == .signaled) catch |e| {
            std.debug.print("contract violation {s}: {any}\n", .{ @tagName(v), out });
            return e;
        };
    }
}

test "mutation 2026-11-25: a builder buffer at the u32 limit: the last offset that fits, and the first that does not" {
    // A buffer whose size is 2^32 - 4 bytes (front room for one offset). Only its last 4 bytes
    // are real memory; `finish` pads nothing and writes one offset there.
    var real: [16]u8 = @splat(0);
    const fake = @as([*]u8, &real)[0 .. 1 << 32];
    var ok: fb.Builder = .{ .gpa = testing.allocator, .buf = fake, .head = 4 };
    // dist = size + 4 - target = 2^32 - 1: exactly representable.
    _ = try ok.finish(1);
    var over: fb.Builder = .{ .gpa = testing.allocator, .buf = fake, .head = 4 };
    // dist = 2^32: not a wrap to 0, an error.
    try testing.expectError(error.OutOfMemory, over.finish(0));
}

test "mutation 2026-11-25: writeMessage refuses a metadata length past the 32-bit prefix before touching memory" {
    var one: [1]u8 = .{0};
    const fake: []const u8 = @as([*]const u8, &one)[0 .. 1 << 32];
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var out: std.ArrayList(u8) = .empty;
    try testing.expectError(error.OutOfMemory, ipc.writeMessage(fa.allocator(), &out, fake, ""));
    // The error is the length check's: no allocation was even tried.
    try testing.expect(!fa.has_induced_failure);
}

const huge: i64 = std.math.maxInt(i64);

test "mutation 2026-11-25: dictionary lengths no projected column reads saturate, they do not wrap" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{
        .{ .name = "x", .type = .{ .int = .{ .bits = 32, .signed = true } } },
        .{ .name = "c", .type = .utf8, .dictionary = .{ .id = 0 } },
    };
    const dict_node: ipc.FieldNode = .{ .length = huge, .null_count = 0 };
    const one: ipc.FieldNode = .{ .length = 1, .null_count = 0 };
    // Three batches of 2^63 - 1 entries of a dictionary the read never touches: 3 * (2^63 - 1) passes 2^64.
    const bytes = try st.hand(gpa, &fields, &.{
        .{ .length = huge, .dict_id = 0, .nodes = &.{dict_node}, .bufs = &.{ "", "", "" } },
        .{ .length = huge, .dict_id = 0, .delta = true, .nodes = &.{dict_node}, .bufs = &.{ "", "", "" } },
        .{ .length = huge, .dict_id = 0, .delta = true, .nodes = &.{dict_node}, .bufs = &.{ "", "", "" } },
        .{ .length = 1, .nodes = &.{ one, one }, .bufs = &.{ "", st.bytesOf(i32, &.{7}), "", st.bytesOf(i32, &.{0}) } },
    });
    defer gpa.free(bytes);
    const f = try stream.readStream(a, bytes, .{ .max_rows = 1 << 63, .max_cells = std.math.maxInt(u64), .columns = &.{.{ .name = "x" }} });
    try testing.expectEqual(@as(usize, 1), f.len);
    try testing.expectEqual(@as(i64, 7), f.cell(0, "x").?.int);
}

test "mutation 2026-11-25: the rows of many batches saturate, so a huge max_rows cannot wrap the sum" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fields = [_]schema.Field{.{ .name = "n", .type = .null }};
    const node: ipc.FieldNode = .{ .length = huge, .null_count = huge };
    // Each batch is within max_rows = 2^63 - 1; their sum, 3 * (2^63 - 1), is not (and passes 2^64).
    const batch: st.HandBatch = .{ .length = huge, .nodes = &.{node}, .bufs = &.{} };
    const bytes = try st.hand(gpa, &fields, &.{ batch, batch, batch });
    defer gpa.free(bytes);
    try testing.expectError(error.LimitExceeded, stream.readStream(a, bytes, .{ .max_rows = huge, .max_cells = std.math.maxInt(u64) }));
}

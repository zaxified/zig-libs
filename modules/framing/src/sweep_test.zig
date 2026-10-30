// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GS), findings FR-1, FR-2, FR-3, REV-FR-1, round 2.
const std = @import("std");
const testing = std.testing;
const framing = @import("root.zig");

// ── FR-1: readFrameAlloc believed the announced length up front ────────────

test "readFrameAlloc: a peer that announces max_frame and stalls costs one chunk, not max_frame (sweep FR-1)" {
    // 1 MiB announced (the default cap), 10 bytes delivered. The allocator has
    // 64 KiB: allocating the announced length up front is OutOfMemory, reading
    // as the bytes arrive is the stream's own short-read error.
    var scratch: [64 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const wire = [_]u8{ 0x00, 0x00, 0x10, 0x00 } ++ "0123456789".*;
    var r: std.Io.Reader = .fixed(&wire);
    try testing.expectError(error.EndOfStream, framing.readFrameAlloc(&r, fba.allocator(), .{}));
}

test "readFrameAlloc: a large frame arrives intact and the result frees as exactly its length (sweep FR-1)" {
    const gpa = testing.allocator;
    const n = 100_000; // several doublings past the first chunk
    const wire = try gpa.alloc(u8, 4 + n);
    defer gpa.free(wire);
    std.mem.writeInt(u32, wire[0..4], n, .little);
    for (wire[4..], 0..) |*b, i| b.* = @truncate(i *% 31);
    var r: std.Io.Reader = .fixed(wire);
    const got = try framing.readFrameAlloc(&r, gpa, .{});
    defer gpa.free(got); // the testing allocator checks the freed length
    try testing.expectEqual(@as(usize, n), got.len);
    try testing.expectEqualSlices(u8, wire[4..], got);
}

test "readFrameAlloc: an allocation failure at any step is OutOfMemory and leaks nothing (sweep FR-1)" {
    const n = 70_000;
    var wire: [4 + n]u8 = undefined;
    std.mem.writeInt(u32, wire[0..4], n, .little);
    @memset(wire[4..], 0xab);
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var r: std.Io.Reader = .fixed(&wire);
        if (framing.readFrameAlloc(&r, fa.allocator(), .{})) |got| {
            testing.allocator.free(got);
            break; // no allocation failed any more: every earlier index was exercised
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
        try testing.expect(fail_index < 64);
    }
    try testing.expect(fail_index >= 1);
}

// ── FR-2: Decoder.feed limit arithmetic ─────────────────────────────────────

test "Decoder.feed: max_frame = maxInt(u32) does not overflow the limit (sweep FR-2)" {
    // On a 32-bit target `max_frame + max_prefix_len` overflowed usize; on a
    // 64-bit one this cannot be provoked (see the report), so this pins only
    // that the limit stays a limit and a small feed is accepted.
    const gpa = testing.allocator;
    var d: framing.Decoder = .init(.{ .max_frame = std.math.maxInt(u32) });
    defer d.deinit(gpa);
    try d.feed(gpa, &.{ 2, 0, 0, 0, 'h', 'i' });
    try testing.expectEqualStrings("hi", (try d.next()).?);
    try d.feed(gpa, &.{ 1, 0 });
    try testing.expect((try d.next()) == null);
}

// ── FR-3 (clean): hostile envelopes are errors ──────────────────────────────

const Env = union(enum) {
    ping: struct { seq: u8 },
    note: struct { text: []const u8 },
    raw: std.json.Value,
};
const EnvCodec = framing.EnvelopeCodec(Env);

test "envelope: hostile JSON bodies are errors, never a panic (sweep FR-3)" {
    const gpa = testing.allocator;
    const bad = [_][]const u8{
        "",
        "{}",
        "[]",
        "null",
        "{\"ping\":{\"seq\":256}}",
        "{\"ping\":{\"seq\":-1}}",
        "{\"ping\":{\"seq\":1.5}}",
        "{\"ping\":{\"seq\":99999999999999999999999999999999999999}}",
        "{\"ping\":{\"seq\":1e999}}",
        "{\"ping\":{\"seq\":1},\"ping\":{\"seq\":2}}",
        "{\"ping\":{\"seq\":1},\"note\":{\"text\":\"x\"}}",
        "{\"nope\":{}}",
        "{\"ping\":{\"seq\":1,\"seq\":2}}",
        "{\"ping\":[1]}",
        "{\"note\":{\"text\":\"\\ud800\"}}",
        "{\"note\":{\"text\":\"\\u00\"}}",
        "{\"ping\":{\"seq\":1}",
        "\x00\xff\xfe",
    };
    for (bad) |b| {
        if (EnvCodec.parse(gpa, b)) |p| {
            p.deinit();
            return error.TestUnexpectedSuccess;
        } else |_| {}
    }
    // depth: exactly at the cap parses, one past is refused before std.json
    var buf: [200]u8 = undefined;
    const open = "{\"raw\":";
    var n: usize = 0;
    @memcpy(buf[0..open.len], open);
    n += open.len;
    for (0..63) |_| {
        buf[n] = '[';
        n += 1;
    }
    for (0..63) |_| {
        buf[n] = ']';
        n += 1;
    }
    buf[n] = '}';
    n += 1;
    const ok = try EnvCodec.parse(gpa, buf[0..n]); // depth 64 = the cap
    ok.deinit();
    var deep: [200]u8 = undefined;
    @memcpy(deep[0..open.len], open);
    var m: usize = open.len;
    for (0..64) |_| {
        deep[m] = '[';
        m += 1;
    }
    for (0..64) |_| {
        deep[m] = ']';
        m += 1;
    }
    deep[m] = '}';
    m += 1;
    try testing.expectError(error.JsonNestingTooDeep, EnvCodec.parse(gpa, deep[0..m]));
}

test "Decoder: a hostile stream fed one byte at a time stays within max_frame + prefix (sweep FR-3)" {
    const gpa = testing.allocator;
    var d: framing.Decoder = .init(.{ .max_frame = 64, .prefix = .{ .width = .varint } });
    defer d.deinit(gpa);
    // a 1-byte-per-feed stream announcing a frame bigger than the cap: refused at the prefix
    try d.feed(gpa, &.{0x81});
    try testing.expect((try d.next()) == null);
    try d.feed(gpa, &.{0x01}); // 129 > 64
    try testing.expectError(error.FrameTooLarge, d.next());
    try testing.expectError(error.FrameTooLarge, d.next()); // sticky
    try testing.expect(d.buffered() <= 64 + framing.max_prefix_len);
}

// ── REV-FR-1: parsed strings must not alias the input frame ────────────────

test "EnvelopeCodec.parse: the result does not alias the input buffer (sweep REV-FR-1)" {
    const gpa = testing.allocator;
    var frame = "{\"note\":{\"text\":\"hello world\"}}".*;
    const parsed = try EnvCodec.parse(gpa, &frame);
    defer parsed.deinit();
    @memset(&frame, 'X'); // the frame buffer is reused / freed by the caller
    try testing.expectEqualStrings("hello world", parsed.value.note.text);
}

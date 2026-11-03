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

test "readFrameAlloc: a frame of exactly 16 KiB is one exact allocation, never resized (sweep audit GS-FR-1)" {
    const n = 16 * 1024;
    var wire: [4 + n]u8 = undefined;
    std.mem.writeInt(u32, wire[0..4], n, .little);
    @memset(wire[4..], 0x5a);
    var fa = testing.FailingAllocator.init(testing.allocator, .{});
    var r: std.Io.Reader = .fixed(&wire);
    const got = try framing.readFrameAlloc(&r, fa.allocator(), .{});
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, n), got.len);
    try testing.expectEqual(@as(usize, 1), fa.alloc_index);
    try testing.expectEqual(@as(usize, 0), fa.resize_index);
    try testing.expectEqual(@as(usize, n), fa.allocated_bytes);
}

// ── general prefix (2026-11-03): hostile configurations and streams ─────────

test "general prefix: extreme offset/adjustment/skip over hostile streams never panic (sweep)" {
    const widths = [_]framing.Width{ .u8, .u16, .u24, .u32, .u40, .u48, .u56, .u64, .varint };
    const adjs = [_]i32{ std.math.minInt(i32), -1, 0, 1, std.math.maxInt(i32) };
    var prng = std.Random.DefaultPrng.init(0x5eed_f00d);
    const r = prng.random();
    var rb: [300]u8 = undefined;
    for (widths) |wd| for (adjs) |adj| for ([_]bool{ false, true }) |inc| for ([_]u8{ 0, 7, 255 }) |off| for ([_]?u8{ null, 0, 3, 255 }) |skip| {
        const lim: framing.Limits = .{ .max_frame = 64, .prefix = .{ .width = wd, .endian = if (r.boolean()) .big else .little, .includes_prefix = inc, .offset = off, .adjustment = adj, .skip = skip } };
        var stream: [300]u8 = undefined;
        for (0..4) |_| {
            r.bytes(&stream);
            var rd: std.Io.Reader = .fixed(stream[0..r.uintAtMost(usize, stream.len)]);
            _ = framing.readFrame(&rd, &rb, lim) catch {};
            var rd2: std.Io.Reader = .fixed(stream[0..r.uintAtMost(usize, stream.len)]);
            if (framing.readFrameAlloc(&rd2, testing.allocator, lim)) |f| testing.allocator.free(f) else |_| {}
            var d: framing.Decoder = .init(lim);
            defer d.deinit(testing.allocator);
            try d.feed(testing.allocator, &stream);
            while (d.next() catch null) |_| {}
        }
        // The writer: every payload length, header right and wrong.
        var out: [1200]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        const hdr: [255]u8 = @splat(0);
        framing.writeFrameWithHeader(&w, hdr[0..off], "payload", lim) catch {};
        framing.writeFrameWithHeader(&w, hdr[0..1], "p", lim) catch {};
        framing.writeFrame(&w, "p", lim) catch {};
    };
}

// ── review 2026-11-03: hostile u64 fields (Zig #37131), skip, NotDrained ────

test "hostile length fields are FrameTooLarge in every optimize mode (#37131 guard)" {
    // A field in the upper half of u64 (and of the narrower widths), with and
    // without an adjustment, goes through i128 arithmetic: a signed-to-narrower-
    // unsigned cast there would be poison in ReleaseSafe/ReleaseFast.
    const gpa = testing.allocator;
    const Case = struct { prefix: framing.Prefix, bytes: []const u8 };
    const cases = [_]Case{
        .{ .prefix = .{ .width = .u64, .endian = .big }, .bytes = "\x80\x00\x00\x00\x00\x00\x00\x00abcdefgh" },
        .{ .prefix = .{ .width = .u64, .endian = .big }, .bytes = "\xff\xff\xff\xff\xff\xff\xff\xffabcdefgh" },
        .{ .prefix = .{ .width = .u64, .endian = .big, .adjustment = std.math.minInt(i32) }, .bytes = "\xff\xff\xff\xff\xff\xff\xff\xffabcdefgh" },
        .{ .prefix = .{ .width = .u64, .endian = .big, .adjustment = std.math.maxInt(i32) }, .bytes = "\xff\xff\xff\xff\xff\xff\xff\xffabcdefgh" },
        .{ .prefix = .{ .width = .u56, .endian = .big, .adjustment = std.math.maxInt(i32) }, .bytes = "\xff\xff\xff\xff\xff\xff\xffabcdefgh" },
        .{ .prefix = .{ .width = .u48, .endian = .little, .adjustment = std.math.maxInt(i32), .includes_prefix = true }, .bytes = "\xff\xff\xff\xff\xff\xffabcdefgh" },
        .{ .prefix = .{ .width = .u32, .endian = .big, .adjustment = std.math.maxInt(i32) }, .bytes = "\xff\xff\xff\xffabcdefgh" },
        .{ .prefix = .{ .width = .varint }, .bytes = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01abcdefgh" },
    };
    for (cases) |c| {
        const lim: framing.Limits = .{ .prefix = c.prefix };
        var d: framing.Decoder = .init(lim);
        defer d.deinit(gpa);
        try d.feed(gpa, c.bytes);
        try testing.expectError(error.FrameTooLarge, d.next());
        var r: std.Io.Reader = .fixed(c.bytes);
        var rb: [16]u8 = undefined;
        try testing.expectError(error.FrameTooLarge, framing.readFrame(&r, &rb, lim));
        var r2: std.Io.Reader = .fixed(c.bytes);
        try testing.expectError(error.FrameTooLarge, framing.readFrameAlloc(&r2, gpa, lim));
    }
}

test "accepted frames at extreme adjustment are decoded exactly (sweep)" {
    var out: [32]u8 = undefined;
    // field = n - adjustment = 3 + 2^31.
    const lim: framing.Limits = .{ .prefix = .{ .width = .u64, .endian = .big, .adjustment = std.math.minInt(i32) } };
    var w: std.Io.Writer = .fixed(&out);
    try framing.writeFrame(&w, "abc", lim);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x80\x00\x00\x03abc", w.buffered());
    var r: std.Io.Reader = .fixed(w.buffered());
    var rb: [8]u8 = undefined;
    try testing.expectEqualStrings("abc", try framing.readFrame(&r, &rb, lim));
    // The largest payload a u8 field can announce through a negative adjustment.
    const lim2: framing.Limits = .{ .prefix = .{ .width = .u8, .adjustment = -200 } };
    var w2: std.Io.Writer = .fixed(&out);
    try framing.writeFrame(&w2, "xy", lim2);
    try testing.expectEqualSlices(u8, "\xcaxy", w2.buffered());
    try testing.expectError(error.FrameTooLarge, framing.writeFrame(&w2, "", .{ .prefix = .{ .width = .u8, .adjustment = -256 } }));
}

test "writers refuse a skip that would not read back (SkipNotWritable)" {
    var out: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const bad: framing.Limits = .{ .prefix = .{ .width = .u16, .endian = .big, .offset = 2, .skip = 2 } };
    try testing.expectError(error.SkipNotWritable, framing.writeFrameWithHeader(&w, "ab", "xyz", bad));
    try testing.expectEqual(@as(usize, 0), w.end); // nothing written
    var good = bad;
    good.prefix.skip = 4; // the whole head: the default
    try framing.writeFrameWithHeader(&w, "ab", "xyz", good);
    try testing.expectEqualSlices(u8, "ab\x00\x03xyz", w.buffered());
    good.prefix.skip = 5; // past the head: not writable either
    try testing.expectError(error.SkipNotWritable, framing.writeFrameWithHeader(&w, "ab", "xyz", good));
}

test "Decoder: max_frame = maxInt(u32) and NotDrained with an offset (sweep)" {
    const gpa = testing.allocator;
    var d: framing.Decoder = .init(.{ .max_frame = std.math.maxInt(u32), .prefix = .{ .width = .u16, .offset = 3 } });
    defer d.deinit(gpa);
    try d.feed(gpa, "abc\x02\x00hi");
    try testing.expectEqualStrings("hi", (try d.next()).?);
    // Threshold: buffered > max_frame + 10 + offset.
    var e: framing.Decoder = .init(.{ .max_frame = 8, .prefix = .{ .width = .u8, .offset = 5 } });
    defer e.deinit(gpa);
    const x23: [23]u8 = @splat(0xff); // an incomplete (oversize) head would fail next(); only feed
    try e.feed(gpa, &x23); // 0 buffered before
    try e.feed(gpa, "z"); // 23 <= 23 before: allowed -> 24
    try testing.expectError(error.NotDrained, e.feed(gpa, "z"));
}

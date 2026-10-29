// SPDX-License-Identifier: MIT
//! Faults a fuzz harness draws from its source, like any other choice.
//!
//! A harness that hands its code under test a `Reader.fixed(input)` and a
//! growing `Writer.Allocating` tests the one transport that never happens:
//! everything at once, and never an error. mqtt 2026-10-17: a double free on
//! a transport that fails halfway through a session was invisible to a
//! session fuzzer whose transport could not fail. These put the transport's
//! behaviour into the input — where the chunks break, at which byte it
//! fails, which allocation fails — so the driver explores it, a failing seed
//! replays it, and the shrinker reduces it like any other draw (a fault at
//! byte 0 and one-byte chunks are the "small" end).
//!
//!     var plan = testkit.fuzz.FaultPlan.draw(src, input.len);
//!     var rbuf: [64]u8 = undefined;
//!     var r = testkit.fuzz.ChunkedReader.init(input, plan, &rbuf);
//!     var fa = testkit.fuzz.failingAllocator(src, gpa, 32);
//!     decodeStream(fa.allocator(), &r.interface) catch |e| switch (e) {
//!         error.ReadFailed, error.OutOfMemory => return, // injected
//!         else => return e,
//!     };
//!
//! Only the drawing methods every source has are used (`valueRangeAtMost`,
//! `value`), so the same harness runs under `std.testing.Smith`.

const std = @import("std");
const Io = std.Io;

/// Where a stream breaks into chunks, and where it fails.
pub const FaultPlan = struct {
    /// Chunk sizes, used in turn and then again from the first.
    chunks: [8]u16 = @splat(1),
    n_chunks: u8 = 1,
    /// The stream fails once this many bytes went through (`null`: never).
    fail_at: ?usize = null,

    /// No chunking worth the name, no failure: `Reader.fixed` behaviour.
    pub const whole: FaultPlan = .{ .chunks = @splat(std.math.maxInt(u16)), .n_chunks = 1 };

    /// One to eight chunk sizes (a third of them one byte, the rest up to
    /// 1 KiB) and, one draw in four, a failure at a byte in `0..len`.
    pub fn draw(src: anytype, len: usize) FaultPlan {
        var p: FaultPlan = .{ .n_chunks = src.valueRangeAtMost(u8, 1, 8) };
        for (p.chunks[0..p.n_chunks]) |*c| {
            c.* = switch (src.valueRangeAtMost(u8, 0, 2)) {
                0 => 1,
                1 => src.valueRangeAtMost(u16, 1, 16),
                else => src.valueRangeAtMost(u16, 1, 1024),
            };
        }
        if (src.valueRangeAtMost(u8, 0, 3) == 0) p.fail_at = @as(usize, @intCast(src.valueRangeAtMost(u64, 0, len)));
        return p;
    }

    /// Total for any plan a caller writes by hand: `n_chunks` outside 1..8 is
    /// clamped into it and a zero-size chunk is one byte (a zero-size chunk
    /// makes no progress, so the stream would spin forever).
    fn chunk(p: *const FaultPlan, k: usize) usize {
        const n = std.math.clamp(@as(usize, p.n_chunks), 1, p.chunks.len);
        return @max(1, p.chunks[k % n]);
    }
};

/// A `std.Io.Reader` over `data` that delivers it in the plan's chunks and
/// fails with `error.ReadFailed` at the plan's byte.
pub const ChunkedReader = struct {
    interface: Io.Reader,
    data: []const u8,
    plan: FaultPlan,
    pos: usize = 0,
    calls: usize = 0,

    pub fn init(data: []const u8, plan: FaultPlan, buffer: []u8) ChunkedReader {
        return .{
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .data = data,
            .plan = plan,
        };
    }

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const r: *ChunkedReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (r.plan.fail_at) |f| if (r.pos >= f) return error.ReadFailed;
        if (r.pos == r.data.len) return error.EndOfStream;
        var n = @min(r.plan.chunk(r.calls), r.data.len - r.pos);
        if (r.plan.fail_at) |f| n = @min(n, f - r.pos);
        const written = try w.write(limit.sliceConst(r.data[r.pos..][0..n]));
        r.pos += written;
        r.calls += 1;
        return written;
    }
};

/// A `std.Io.Writer` into `out` that takes at most one chunk of the plan per
/// `drain` (a short write each time) and fails with `error.WriteFailed` when
/// a write would go past the plan's byte, or when `out` is full (`full` is
/// then set). A failure at exactly the last byte is therefore no failure for
/// a writer — nothing more is written — while a reader asked for more there
/// does fail (a reset after the last byte, rather than a clean end).
pub const ChunkedWriter = struct {
    interface: Io.Writer,
    out: []u8,
    plan: FaultPlan,
    len: usize = 0,
    calls: usize = 0,
    full: bool = false,

    pub fn init(out: []u8, plan: FaultPlan, buffer: []u8) ChunkedWriter {
        return .{
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
            .out = out,
            .plan = plan,
        };
    }

    /// What reached the sink (not what is still in `interface`'s buffer).
    pub fn written(w: *const ChunkedWriter) []const u8 {
        return w.out[0..w.len];
    }

    fn accept(w: *ChunkedWriter, bytes: []const u8) Io.Writer.Error!usize {
        if (w.plan.fail_at) |f| if (w.len >= f) return error.WriteFailed;
        var n = @min(bytes.len, w.plan.chunk(w.calls));
        if (w.plan.fail_at) |f| n = @min(n, f - w.len);
        if (n > w.out.len - w.len) {
            w.full = true;
            return error.WriteFailed;
        }
        @memcpy(w.out[w.len..][0..n], bytes[0..n]);
        w.len += n;
        w.calls += 1;
        return n;
    }

    fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const w: *ChunkedWriter = @alignCast(@fieldParentPtr("interface", io_w));
        const buffered = io_w.buffered();
        if (buffered.len != 0) return io_w.consume(try w.accept(buffered));
        for (data[0 .. data.len - 1]) |bytes| {
            if (bytes.len != 0) return w.accept(bytes);
        }
        const pattern = data[data.len - 1];
        if (splat == 0 or pattern.len == 0) return 0;
        return w.accept(pattern);
    }
};

/// `std.testing.FailingAllocator` over `backing` that, half the time, fails
/// from its allocation number `0..max_index` (drawn) on — that one and every
/// later one, which is std's semantics (its index stops at the failure) —
/// else never.
pub fn failingAllocator(src: anytype, backing: std.mem.Allocator, max_index: usize) std.testing.FailingAllocator {
    const fail = src.value(bool);
    return .init(backing, .{ .fail_index = if (fail) @as(usize, @intCast(src.valueRangeAtMost(u64, 0, max_index))) else std.math.maxInt(usize) });
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const Rng = @import("fuzz_driver.zig").Rng;

fn rngFor(prng: *std.Random.DefaultPrng) Rng {
    return .{ .r = prng.random() };
}

test "ChunkedReader: the whole input in chunks no larger than planned, or the failure at its byte" {
    var data: [3000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var src = rngFor(&prng);
        const len = @as(usize, @intCast(src.valueRangeAtMost(u64, 0, data.len)));
        const plan = FaultPlan.draw(&src, len);
        var rbuf: [64]u8 = undefined;
        var r = ChunkedReader.init(data[0..len], plan, &rbuf);
        var got: std.Io.Writer.Allocating = .init(testing.allocator);
        defer got.deinit();
        const res = r.interface.streamRemaining(&got.writer);
        if (plan.fail_at) |f| {
            try testing.expectError(error.ReadFailed, res);
            try testing.expectEqual(f, r.pos);
            // Everything before the failure was delivered, nothing after.
            try testing.expectEqualSlices(u8, data[0..f], got.written());
        } else {
            _ = try res;
            try testing.expectEqualSlices(u8, data[0..len], got.written());
        }
        var max_chunk: usize = 0;
        for (plan.chunks[0..plan.n_chunks]) |c| max_chunk = @max(max_chunk, c);
        // At least ceil(pos / largest chunk) calls: no call delivered more.
        try testing.expect(r.calls * max_chunk >= r.pos);
    }
}

test "ChunkedWriter: short writes add up to the whole, or stop at the failing byte" {
    var msg: [2000]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 13 +% 1);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var src = rngFor(&prng);
        const len = @as(usize, @intCast(src.valueRangeAtMost(u64, 0, msg.len)));
        const plan = FaultPlan.draw(&src, len);
        var out: [2000]u8 = undefined;
        var wbuf: [32]u8 = undefined;
        var w = ChunkedWriter.init(&out, plan, &wbuf);
        // Mixed shapes: a slice, a splat, a byte at a time.
        const third = len / 3;
        const res = blk: {
            w.interface.writeAll(msg[0..third]) catch |e| break :blk e;
            for (msg[third .. 2 * third]) |b| w.interface.writeByte(b) catch |e| break :blk e;
            w.interface.writeAll(msg[2 * third .. len]) catch |e| break :blk e;
            w.interface.flush() catch |e| break :blk e;
        };
        if (plan.fail_at != null and plan.fail_at.? < len) {
            const f = plan.fail_at.?;
            try testing.expectError(error.WriteFailed, res);
            try testing.expectEqual(f, w.len);
            try testing.expectEqualSlices(u8, msg[0..f], w.written());
        } else {
            try res;
            try testing.expectEqualSlices(u8, msg[0..len], w.written());
        }
    }
}

test "ChunkedWriter: a splat goes through whole, and a full sink is reported" {
    var out: [10]u8 = undefined;
    var wbuf: [4]u8 = undefined;
    var w = ChunkedWriter.init(&out, .{ .chunks = .{ 3, 1, 1, 1, 1, 1, 1, 1 }, .n_chunks = 2 }, &wbuf);
    try w.interface.splatByteAll('z', 7);
    try w.interface.flush();
    try testing.expectEqualStrings("zzzzzzz", w.written());
    try testing.expectError(error.WriteFailed, w.interface.writeAll("abcdef"));
    try testing.expect(w.full);
}

test "FaultPlan.whole: the input in one piece, never failing" {
    var rbuf: [16]u8 = undefined;
    var r = ChunkedReader.init("hello, world", .whole, &rbuf);
    var got: [32]u8 = undefined;
    var gw: std.Io.Writer = .fixed(&got);
    _ = try r.interface.streamRemaining(&gw);
    try testing.expectEqualStrings("hello, world", gw.buffered());
}

test "failingAllocator: fails the drawn allocation, or none" {
    var failed: usize = 0;
    for (0..200) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var src = rngFor(&prng);
        var fa = failingAllocator(&src, testing.allocator, 4);
        const a = fa.allocator();
        var got: [6]?[]u8 = @splat(null);
        for (&got) |*g| g.* = a.alloc(u8, 3) catch null;
        defer for (got) |g| if (g) |x| a.free(x);
        // Nothing, or a failure from some index <= 4 to the end.
        const first = for (got, 0..) |g, i| {
            if (g == null) break i;
        } else got.len;
        if (first < got.len) {
            failed += 1;
            try testing.expect(first <= 4);
            for (got[first..]) |g| try testing.expect(g == null);
        }
    }
    // About half the seeds inject one.
    try testing.expect(failed > 60 and failed < 140);
}

test "a hand-written plan with n_chunks 0, 9 or a zero chunk still makes progress (sweep TK-7)" {
    const plans = [_]FaultPlan{
        .{ .n_chunks = 0 },
        .{ .n_chunks = 200, .chunks = .{ 2, 2, 2, 2, 2, 2, 2, 2 } },
        .{ .n_chunks = 2, .chunks = .{ 0, 0, 0, 0, 0, 0, 0, 0 } },
    };
    for (plans) |plan| {
        var rbuf: [8]u8 = undefined;
        var r = ChunkedReader.init("hello, world", plan, &rbuf);
        var got: [32]u8 = undefined;
        var gw: std.Io.Writer = .fixed(&got);
        _ = try r.interface.streamRemaining(&gw);
        try testing.expectEqualStrings("hello, world", gw.buffered());

        var out: [32]u8 = undefined;
        var wbuf: [8]u8 = undefined;
        var w = ChunkedWriter.init(&out, plan, &wbuf);
        try w.interface.writeAll("hello, world");
        try w.interface.flush();
        try testing.expectEqualStrings("hello, world", w.written());
    }
}

test "FaultPlan.chunk: an index past a hand-written n_chunks of 200 stays in bounds (audit TK-18)" {
    const plan: FaultPlan = .{ .n_chunks = 200, .chunks = .{ 5, 4, 3, 2, 1, 6, 7, 8 } };
    // n_chunks is clamped to the 8 slots, so the sizes cycle through them.
    for (0..600) |k| try testing.expectEqual(@as(usize, plan.chunks[k % 8]), plan.chunk(k));
    // And over a long stream through a reader: it finishes, in order.
    var data: [1000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);
    var rbuf: [8]u8 = undefined;
    var r = ChunkedReader.init(&data, plan, &rbuf);
    var got: [1000]u8 = undefined;
    var gw: std.Io.Writer = .fixed(&got);
    _ = try r.interface.streamRemaining(&gw);
    try testing.expectEqualSlices(u8, &data, gw.buffered());
}

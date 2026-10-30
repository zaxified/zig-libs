// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GU, findings BZ-1 .. BZ-4); see
//! ~/CML/20261029-panic-sweep/bzip2-sweep.report.md.

const std = @import("std");
const testing = std.testing;
const bz = @import("root.zig");

const plain = "hello, sweep: the quick brown fox jumps over the lazy dog";

test "Decoder.read with an empty dest returns 0 and makes no progress (sweep BZ-1)" {
    const gpa = testing.allocator;
    const z = try bz.compress(gpa, plain, .{ .level = 1 });
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var d = try bz.Decoder.init(gpa, &in, .{});
    defer d.deinit();
    var none: [0]u8 = undefined;
    for (0..3) |_| try testing.expectEqual(@as(usize, 0), try d.read(&none));
    // The stream is still all there.
    var out: [128]u8 = undefined;
    const n = try d.read(&out);
    try testing.expectEqualSlices(u8, plain, out[0..n]);
    try testing.expectEqual(@as(usize, 0), try d.read(&out));
    try testing.expectEqual(@as(usize, 0), try d.read(&none));
}

test "a stream count at the u32 limit saturates instead of wrapping (sweep BZ-2)" {
    const gpa = testing.allocator;
    const z = try bz.compress(gpa, plain, .{ .level = 1 });
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var d = try bz.Decoder.init(gpa, &in, .{});
    defer d.deinit();
    d.streams = std.math.maxInt(u32);
    var out: [128]u8 = undefined;
    const n = try d.read(&out);
    try testing.expectEqualSlices(u8, plain, out[0..n]);
    // The clean end of input after the stream (not BadMagic, which a wrapped
    // counter of 0 would give).
    try testing.expectEqual(@as(usize, 0), try d.read(&out));
}

test "compressBound saturates for sizes no slice has (sweep BZ-3)" {
    try testing.expectEqual(@as(usize, 1000 + 10 + 700), bz.compressBound(1000));
    try testing.expectEqual(std.math.maxInt(usize), bz.compressBound(std.math.maxInt(usize)));
    try testing.expectEqual(std.math.maxInt(usize), bz.compressBound(std.math.maxInt(usize) - 5));
}

test "an input reader with no buffer at all decodes, and a cut stream is TruncatedInput (sweep BZ-4)" {
    const gpa = testing.allocator;
    const z = try bz.compress(gpa, plain, .{ .level = 1 });
    defer gpa.free(z);
    for ([_]usize{ 1, 3, 4096 }) |piece| {
        var calls: [1]std.testing.Reader.Call = .{.{ .buffer = z }};
        var tr: std.testing.Reader = .init(&.{}, &calls);
        tr.artificial_limit = .limited(piece);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        _ = try bz.decompressStream(gpa, &tr.interface, &out.writer, .{});
        try testing.expectEqualSlices(u8, plain, out.written());
    }
    var calls: [1]std.testing.Reader.Call = .{.{ .buffer = z[0 .. z.len - 3] }};
    var tr: std.testing.Reader = .init(&.{}, &calls);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try testing.expectError(error.TruncatedInput, bz.decompressStream(gpa, &tr.interface, &out.writer, .{}));
    // And an empty unbuffered input is the plain "no stream" refusal.
    var none: [0]std.testing.Reader.Call = .{};
    var tr0: std.testing.Reader = .init(&.{}, &none);
    var out0: std.Io.Writer.Allocating = .init(gpa);
    defer out0.deinit();
    try testing.expectError(error.TruncatedInput, bz.decompressStream(gpa, &tr0.interface, &out0.writer, .{}));
}

test "StreamWriter.finish is idempotent and a write after it fails cleanly (sweep REV-bzip2-1)" {
    const gpa = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [64]u8 = undefined;
    var sw = try bz.StreamWriter.init(gpa, &out.writer, &buf, .{ .level = 1 });
    defer sw.deinit();
    try sw.writer.writeAll(plain);
    try sw.finish();
    const len = out.written().len;
    // Before the fix the second call died in `@errorCast` (AlreadyFinished is
    // not in `err`'s set).
    try sw.finish();
    try sw.finish();
    try testing.expectEqual(len, out.written().len);
    try testing.expectError(error.WriteFailed, sw.writer.writeAll("more"));
    try testing.expectEqual(len, out.written().len);
    const back = try bz.decompress(gpa, out.written(), .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, plain, back);
}

/// A writer whose first `drain` fails and every later one succeeds.
const FlakyWriter = struct {
    w: std.Io.Writer = .{ .vtable = &vtable, .buffer = &.{} },
    calls: usize = 0,

    const vtable: std.Io.Writer.VTable = .{ .drain = drain };

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const s: *FlakyWriter = @alignCast(@fieldParentPtr("w", w));
        s.calls += 1;
        if (s.calls == 1) return error.WriteFailed;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| n += d.len;
        return n + data[data.len - 1].len * splat;
    }
};

test "Encoder.write latches the first error and never re-enters a half-written block (sweep REV-bzip2-2)" {
    const gpa = testing.allocator;
    var fw: FlakyWriter = .{};
    var enc = try bz.Encoder.init(gpa, &fw.w, .{ .level = 1 });
    defer enc.deinit();
    var prng = std.Random.DefaultPrng.init(2);
    const data = try gpa.alloc(u8, 120_000);
    defer gpa.free(data);
    prng.random().bytes(data);
    // The first block closes and its bytes hit the flaky output.
    try testing.expectError(error.WriteFailed, enc.write(data));
    try testing.expectEqual(@as(usize, 1), fw.calls);
    // A retry would succeed on the (now working) output and re-emit the block.
    try testing.expectError(error.WriteFailed, enc.write("x"));
    try testing.expectError(error.WriteFailed, enc.finish());
    try testing.expectEqual(@as(usize, 1), fw.calls);
    // `reset` clears the latch.
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    enc.reset(&out.writer);
    try enc.write(plain);
    try enc.finish();
    const back = try bz.decompress(gpa, out.written(), .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, plain, back);
}

test "Encoder.finish latches a failure of the trailer's flush (sweep REV-bzip2-2)" {
    const gpa = testing.allocator;
    var fw: FlakyWriter = .{};
    var enc = try bz.Encoder.init(gpa, &fw.w, .{ .level = 1 });
    defer enc.deinit();
    try enc.write(plain);
    try testing.expectError(error.WriteFailed, enc.finish());
    // Without the latch this is AlreadyFinished, and a "successful" retry
    // would claim a stream whose bytes never left.
    try testing.expectError(error.WriteFailed, enc.finish());
    try testing.expectError(error.WriteFailed, enc.write("x"));
    try testing.expectEqual(@as(usize, 1), fw.calls);
}

test "the default max_output is a 256 MiB bomb guard; null is the opt-out (sweep REV-bzip2-3)" {
    try testing.expectEqual(@as(u64, 256 << 20), bz.decoder_default_max_output);
    const o: bz.DecodeOptions = .{};
    try testing.expectEqual(@as(?u64, 256 << 20), o.max_output);
    const unbounded: bz.DecodeOptions = .{ .max_output = null };
    try testing.expectEqual(@as(?u64, null), unbounded.max_output);
}

const zero_vtable: std.Io.Reader.VTable = .{ .stream = zeroStream, .readVec = zeroReadVec };

fn zeroStream(_: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
    return 0;
}

fn zeroReadVec(_: *std.Io.Reader, _: [][]u8) std.Io.Reader.Error!usize {
    return 0;
}

test "an unbuffered reader that never makes progress is ReadFailed, not a spin (sweep REV-bzip2-4)" {
    const gpa = testing.allocator;
    var in: std.Io.Reader = .{ .vtable = &zero_vtable, .buffer = &.{}, .seek = 0, .end = 0 };
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try testing.expectError(error.ReadFailed, bz.decompressStream(gpa, &in, &out.writer, .{}));
}

test "StreamWriter.fail never casts an error outside its set into err (sweep REV-bzip2-1b)" {
    const gpa = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [16]u8 = undefined;
    var sw = try bz.StreamWriter.init(gpa, &out.writer, &buf, .{ .level = 1 });
    defer sw.deinit();
    // End the stream behind the writer's back: its next flush meets
    // `error.AlreadyFinished`, which is not an allocation failure.
    try sw.enc.write(plain);
    try sw.enc.finish();
    try testing.expectError(error.WriteFailed, sw.writer.writeAll("more bytes than the 16-byte buffer holds"));
    try testing.expectEqual(@as(?std.mem.Allocator.Error, null), sw.err);
}

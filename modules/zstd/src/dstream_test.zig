// SPDX-License-Identifier: MIT
//! Streaming decompression: `DecompressStream` and `DecompressReader`
//! against the one-shot decoder and the inputs, under hostile call
//! patterns (1-byte input and output, random chunks, stable output), plus
//! the stream's own refusals. Every expectation about which frame is
//! refused was checked against libzstd 1.5.7's `ZSTD_decompressStream`
//! (`tools/zdec.c` mode 1).

const std = @import("std");
const zstd = @import("root.zig");
const corpus = @import("testdata/corpus.zig");

const gpa = std.testing.allocator;

const Plan = struct { in_max: usize, out_max: usize, stable: bool = false };

/// Decode `z` through a stream fed by `plan` (chunk sizes drawn up to the
/// maxima). Returns the output, or the stream's error.
fn streamDecode(z: []const u8, plan: Plan, seed: u64, options: zstd.DecompressStreamOptions) ![]u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    const rnd = prng.random();
    var o = options;
    o.stable_output = plan.stable;
    var s = try zstd.DecompressStream.init(gpa, o);
    defer s.deinit();
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const stable = if (plan.stable) try gpa.alloc(u8, @intCast(try zstd.decompressBound(z))) else &[_]u8{};
    defer if (plan.stable) gpa.free(stable);
    var sout: zstd.OutBuffer = .{ .dst = @constCast(stable) };
    var obuf: [4096]u8 = undefined;
    var ip: usize = 0;
    var hint: usize = 1;
    var idle: usize = 0;
    while (true) {
        var in: zstd.InBuffer = .{ .src = z[0..@min(z.len, ip + 1 + rnd.uintLessThan(usize, plan.in_max))], .pos = ip };
        var o_small: zstd.OutBuffer = .{ .dst = obuf[0 .. 1 + rnd.uintLessThan(usize, plan.out_max)] };
        const op = if (plan.stable) &sout else &o_small;
        const before = op.pos;
        hint = try s.decompressStream(op, &in);
        if (!plan.stable) try out.appendSlice(gpa, o_small.dst[0..o_small.pos]);
        const progressed = in.pos != ip or op.pos != before;
        ip = in.pos;
        if (ip == z.len and hint == 0) break;
        if (!progressed) {
            idle += 1;
            if (idle > 2) return error.Truncated;
        } else idle = 0;
    }
    if (plan.stable) try out.appendSlice(gpa, sout.dst[0..sout.pos]);
    return out.toOwnedSlice(gpa);
}

fn corpusInput(name: []const u8) ![]u8 {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) {
        const src = try gpa.alloc(u8, c.len);
        corpus.generate(c, src);
        return src;
    };
    unreachable;
}

test "streamed decoding equals the input under every call pattern" {
    const plans = [_]Plan{
        .{ .in_max = 1, .out_max = 1 },
        .{ .in_max = 7, .out_max = 4096 },
        .{ .in_max = 4096, .out_max = 3 },
        .{ .in_max = 1 << 20, .out_max = 4096 },
        .{ .in_max = 100, .out_max = 1, .stable = true },
    };
    for ([_][]const u8{ "csv-131073", "far-repeat", "zeros-300000" }) |name| {
        const src = try corpusInput(name);
        defer gpa.free(src);
        for ([_]i32{ -1, 3, 12, 19 }) |level| {
            const z = try zstd.compressAlloc(gpa, src, .{ .level = level, .checksum = level == 3 });
            defer gpa.free(z);
            for (plans, 0..) |plan, pi| {
                if (plan.in_max == 1 and src.len > 140_000) continue; // byte-at-a-time only on the smaller inputs
                const back = try streamDecode(z, plan, pi, .{});
                defer gpa.free(back);
                try std.testing.expectEqualSlices(u8, src, back);
            }
        }
    }
}

test "a window-sized ring: a stream without content size, window smaller than the input" {
    // window 1 KB so the ring wraps many times and matches cross it
    const src = try corpusInput("far-repeat");
    defer gpa.free(src);
    var s = try zstd.Stream.init(gpa, .{ .level = 5 });
    defer s.deinit();
    s.window_log = 10;
    const cap = zstd.compressBound(src.len) + 1024;
    const z = try gpa.alloc(u8, cap);
    defer gpa.free(z);
    var o: zstd.OutBuffer = .{ .dst = z };
    var i: zstd.InBuffer = .{ .src = src };
    _ = try s.compressStream2(&o, &i, .@"continue");
    var none: zstd.InBuffer = .{ .src = "" };
    while (try s.compressStream2(&o, &none, .end) != 0) {}
    try std.testing.expectEqual(@as(?u64, null), try zstd.getFrameContentSize(z[0..o.pos]));
    for (0..3) |seed| {
        const back = try streamDecode(z[0..o.pos], .{ .in_max = 3000, .out_max = 700 }, seed, .{});
        defer gpa.free(back);
        try std.testing.expectEqualSlices(u8, src, back);
    }
}

test "concatenated and skippable frames stream one after another" {
    const a = try zstd.compressAlloc(gpa, "first " ** 300, .{});
    defer gpa.free(a);
    const b = try zstd.compressAlloc(gpa, "second " ** 300, .{ .level = 9, .checksum = true });
    defer gpa.free(b);
    const skip = [_]u8{ 0x5f, 0x2a, 0x4d, 0x18, 0x03, 0x00, 0x00, 0x00, 1, 2, 3 };
    const z = try std.mem.concat(gpa, u8, &.{ &skip, a, &skip, b, &skip });
    defer gpa.free(z);
    for (0..4) |seed| {
        const back = try streamDecode(z, .{ .in_max = 5, .out_max = 50 }, seed, .{});
        defer gpa.free(back);
        try std.testing.expectEqualStrings("first " ** 300 ++ "second " ** 300, back);
    }
}

test "the window limit: refused above it, taken when raised" {
    // a frame asking for a 2^28 window (window byte (28-10)<<3), empty
    // raw last block
    const f = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 18 << 3, 0x01, 0x00, 0x00 };
    try std.testing.expectError(error.FrameParameterWindowTooLarge, streamDecode(&f, .{ .in_max = 100, .out_max = 100 }, 0, .{}));
    try std.testing.expectError(error.FrameParameterWindowTooLarge, streamDecode(&f, .{ .in_max = 100, .out_max = 100 }, 0, .{ .window_log_max = 27 }));
    const back = try streamDecode(&f, .{ .in_max = 100, .out_max = 100 }, 0, .{ .window_log_max = 28 });
    defer gpa.free(back);
    try std.testing.expectEqual(@as(usize, 0), back.len);
    // exactly 2^27 passes the default (2^27 + 1)
    const g = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 17 << 3, 0x01, 0x00, 0x00 };
    const back2 = try streamDecode(&g, .{ .in_max = 100, .out_max = 100 }, 0, .{});
    gpa.free(back2);
}

test "stable output: straight into the caller's buffer, which must not move" {
    const src = "stable output " ** 500;
    const z = try zstd.compressAlloc(gpa, src, .{ .level = 3 });
    defer gpa.free(z);
    var s = try zstd.DecompressStream.init(gpa, .{ .stable_output = true });
    defer s.deinit();
    var buf: [src.len]u8 = undefined;
    var o: zstd.OutBuffer = .{ .dst = &buf };
    var in: zstd.InBuffer = .{ .src = z[0..10] };
    _ = try s.decompressStream(&o, &in);
    // a different buffer mid-frame
    var other: [src.len]u8 = undefined;
    var o2: zstd.OutBuffer = .{ .dst = &other };
    in.src = z;
    try std.testing.expectError(error.DstBufferWrong, s.decompressStream(&o2, &in));
    // a known content size larger than the buffer is refused up front
    s.reset();
    var small: [100]u8 = undefined;
    var o3: zstd.OutBuffer = .{ .dst = &small };
    var in3: zstd.InBuffer = .{ .src = z[0..20] };
    try std.testing.expectError(error.DstSizeTooSmall, s.decompressStream(&o3, &in3));
}

test "a truncated frame leaves a nonzero hint; no progress is an error after 16 calls" {
    const z = try zstd.compressAlloc(gpa, "truncated stream " ** 100, .{ .checksum = true });
    defer gpa.free(z);
    var s = try zstd.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var buf: [4096]u8 = undefined;
    var o: zstd.OutBuffer = .{ .dst = &buf };
    var in: zstd.InBuffer = .{ .src = z[0 .. z.len - 2] };
    try std.testing.expect(try s.decompressStream(&o, &in) != 0);
    var n: usize = 0;
    const e = while (n < 20) : (n += 1) {
        _ = s.decompressStream(&o, &in) catch |err| break err;
    } else error.NoErrorRaised;
    try std.testing.expectEqual(error.NoForwardProgressInputEmpty, e);
    try std.testing.expectEqual(@as(usize, 15), n);
}

test "a corrupt frame is refused by the stream as by the one-shot decoder" {
    const z = try zstd.compressAlloc(gpa, "checksummed " ** 200, .{ .checksum = true });
    defer gpa.free(z);
    z[z.len - 2] ^= 0x10;
    try std.testing.expectError(error.ChecksumWrong, streamDecode(z, .{ .in_max = 9, .out_max = 30 }, 1, .{}));
    try std.testing.expectError(error.PrefixUnknown, streamDecode("definitely not zstd", .{ .in_max = 3, .out_max = 30 }, 1, .{}));
}

test "DecompressReader reads every frame of another reader" {
    const src = try corpusInput("csv-131073");
    defer gpa.free(src);
    const z = try zstd.compressAlloc(gpa, src, .{ .level = 7, .checksum = true });
    defer gpa.free(z);
    const both = try std.mem.concat(gpa, u8, &.{ z, z });
    defer gpa.free(both);
    var fr: std.Io.Reader = .fixed(both);
    var r = try zstd.DecompressReader.init(gpa, &fr, &.{}, .{});
    defer r.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    _ = try r.interface.streamRemaining(&out.writer);
    try std.testing.expectEqual(2 * src.len, out.written().len);
    try std.testing.expectEqualSlices(u8, src, out.written()[0..src.len]);
    try std.testing.expectEqualSlices(u8, src, out.written()[src.len..]);

    // with a buffer of its own, and an input cut short
    var fr2: std.Io.Reader = .fixed(z[0 .. z.len - 1]);
    var rbuf: [1000]u8 = undefined;
    var r2 = try zstd.DecompressReader.init(gpa, &fr2, &rbuf, .{});
    defer r2.deinit();
    var out2: std.Io.Writer.Allocating = .init(gpa);
    defer out2.deinit();
    try std.testing.expectError(error.ReadFailed, r2.interface.streamRemaining(&out2.writer));
    try std.testing.expectEqual(@as(?zstd.DecompressStreamError, error.SrcSizeWrong), r2.err);
}

test "decompressContinue decodes a frame piece by piece" {
    const src = "piece by piece " ** 200;
    const z = try zstd.compressAlloc(gpa, src, .{ .level = 2, .checksum = true });
    defer gpa.free(z);
    var d = try zstd.Decompressor.init(gpa, .{});
    defer d.deinit();
    d.begin();
    var out: [src.len]u8 = undefined;
    var op: usize = 0;
    var ip: usize = 0;
    while (d.nextSrcSizeToDecompress() != 0) {
        const n = d.nextSrcSizeToDecompress();
        op += try d.decompressContinue(out[op..], z[ip..][0..n]);
        ip += n;
    }
    try std.testing.expectEqual(z.len, ip);
    try std.testing.expectEqualStrings(src, out[0..op]);
}

// The call-by-call behaviour below (return hints, what is consumed, the
// hostage byte, the refusals) is libzstd 1.5.7's, recorded from
// `ZSTD_decompressStream` on the same frames (the encoder is byte-identical,
// so the frames are the same too).

const Step = struct { cut: usize, out: usize, hint: usize, in_pos: usize, out_pos: usize };

fn expectSteps(z: []const u8, steps: []const Step, empty_after_first: bool) !void {
    var s = try zstd.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var buf: [4096]u8 = undefined;
    var in: zstd.InBuffer = .{ .src = z[0..steps[0].cut] };
    for (steps, 0..) |st, k| {
        if (empty_after_first and k > 0) {
            if (k == 1) in = .{ .src = z[0..0] };
        } else in.src = z[0..st.cut];
        var o: zstd.OutBuffer = .{ .dst = buf[0..st.out] };
        const hint = try s.decompressStream(&o, &in);
        try std.testing.expectEqual(st.hint, hint);
        try std.testing.expectEqual(st.in_pos, in.pos);
        try std.testing.expectEqual(st.out_pos, o.pos);
    }
}

test "stream hints, input consumption and the hostage byte, as libzstd" {
    const text = "hint " ** 600;
    const z = try zstd.compressAlloc(gpa, text, .{ .level = 3, .checksum = true });
    defer gpa.free(z);
    try std.testing.expectEqual(@as(usize, 26), z.len);
    // header in pieces, block header, then the block (output 64 at a time)
    try expectSteps(z, &.{
        .{ .cut = 2, .out = 64, .hint = 7, .in_pos = 2, .out_pos = 0 },
        .{ .cut = 5, .out = 64, .hint = 5, .in_pos = 5, .out_pos = 0 },
        .{ .cut = 6, .out = 64, .hint = 4, .in_pos = 6, .out_pos = 0 },
        .{ .cut = 9, .out = 64, .hint = 1, .in_pos = 9, .out_pos = 0 },
        .{ .cut = 22, .out = 64, .hint = 4, .in_pos = 22, .out_pos = 64 },
        .{ .cut = 25, .out = 64, .hint = 4, .in_pos = 22, .out_pos = 64 },
    }, false);
    // a checksum is read only once the output is flushed
    try expectSteps(z, &.{
        .{ .cut = 26, .out = 1000, .hint = 4, .in_pos = 22, .out_pos = 1000 },
        .{ .cut = 26, .out = 1000, .hint = 4, .in_pos = 22, .out_pos = 1000 },
        .{ .cut = 26, .out = 1000, .hint = 0, .in_pos = 26, .out_pos = 1000 },
    }, false);

    // without a checksum the frame ends while output is still buffered:
    // one input byte is held back until it is flushed
    const zn = try zstd.compressAlloc(gpa, text, .{ .level = 3 });
    defer gpa.free(zn);
    try std.testing.expectEqual(@as(usize, 22), zn.len);
    try expectSteps(zn, &.{
        .{ .cut = 22, .out = 1000, .hint = 1, .in_pos = 21, .out_pos = 1000 },
        .{ .cut = 22, .out = 1000, .hint = 1, .in_pos = 21, .out_pos = 1000 },
        .{ .cut = 22, .out = 1000, .hint = 0, .in_pos = 22, .out_pos = 1000 },
    }, false);
    // ... and with an empty input next, nothing can be given back yet
    try expectSteps(zn, &.{
        .{ .cut = 22, .out = 1000, .hint = 1, .in_pos = 21, .out_pos = 1000 },
        .{ .cut = 0, .out = 1000, .hint = 1, .in_pos = 0, .out_pos = 1000 },
        .{ .cut = 0, .out = 1000, .hint = 1, .in_pos = 0, .out_pos = 1000 },
        .{ .cut = 0, .out = 1000, .hint = 1, .in_pos = 0, .out_pos = 0 },
    }, true);
}

test "the single-pass shortcut needs room for exactly the content" {
    // window 1 KB, content size 1025, one raw block of 1025 bytes: over the
    // block maximum, so only the one-shot shortcut takes it
    var f: [11 + 1025]u8 = undefined;
    @memcpy(f[0..4], &[_]u8{ 0x28, 0xb5, 0x2f, 0xfd });
    f[4] = 0x40;
    f[5] = 0x00;
    std.mem.writeInt(u16, f[6..8], 1025 - 256, .little);
    const h: u32 = (1025 << 3) | 1;
    f[8] = @truncate(h);
    f[9] = @truncate(h >> 8);
    f[10] = @truncate(h >> 16);
    @memset(f[11..], 'q');
    var buf: [1025]u8 = undefined;
    for ([_]usize{ 1024, 1025 }) |cap| {
        var s = try zstd.DecompressStream.init(gpa, .{});
        defer s.deinit();
        var o: zstd.OutBuffer = .{ .dst = buf[0..cap] };
        var in: zstd.InBuffer = .{ .src = &f };
        if (cap == 1024) {
            try std.testing.expectError(error.CorruptionDetected, s.decompressStream(&o, &in));
        } else {
            try std.testing.expectEqual(@as(usize, 0), try s.decompressStream(&o, &in));
            try std.testing.expectEqual(@as(usize, 1025), o.pos);
        }
    }
}

test "an RLE block over the block maximum: one-shot takes it, the stream does not" {
    const f = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, @truncate((1025 << 3) | 3), @truncate(((1025 << 3) | 3) >> 8), @truncate(((1025 << 3) | 3) >> 16), 'r' };
    var out: [4096]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1025), try zstd.decompress(gpa, &out, &f));
    var s = try zstd.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var o: zstd.OutBuffer = .{ .dst = &out };
    var in: zstd.InBuffer = .{ .src = f[0..0] };
    var k: usize = 1;
    const e = while (k <= f.len) : (k += 1) {
        in.src = f[0..k];
        _ = s.decompressStream(&o, &in) catch |err| break err;
    } else error.NoErrorRaised;
    try std.testing.expectEqual(error.CorruptionDetected, e);
    try std.testing.expectEqual(@as(usize, 9), in.pos);
}

test "the window limit counts a single-segment frame's content size" {
    var out: [16]u8 = undefined;
    // content size 1025 in one segment: window 1025 > 2^10
    const f = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x60, (1025 - 256) & 0xff, (1025 - 256) >> 8 };
    {
        var s = try zstd.DecompressStream.init(gpa, .{ .window_log_max = 10 });
        defer s.deinit();
        var o: zstd.OutBuffer = .{ .dst = &out };
        var in: zstd.InBuffer = .{ .src = &f };
        try std.testing.expectError(error.FrameParameterWindowTooLarge, s.decompressStream(&o, &in));
    }
    // the default limit is 2^27 + 1 bytes
    for ([_]u32{ (1 << 27) + 1, (1 << 27) + 2 }) |fcs| {
        var g = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0xA0, 0, 0, 0, 0 };
        std.mem.writeInt(u32, g[5..9], fcs, .little);
        var s = try zstd.DecompressStream.init(gpa, .{});
        defer s.deinit();
        var o: zstd.OutBuffer = .{ .dst = &out };
        var in: zstd.InBuffer = .{ .src = &g };
        if (fcs == (1 << 27) + 1) {
            try std.testing.expectEqual(@as(usize, 3), try s.decompressStream(&o, &in));
        } else {
            try std.testing.expectError(error.FrameParameterWindowTooLarge, s.decompressStream(&o, &in));
        }
    }
}

test "a two-byte checksummed frame fed one byte at a time" {
    // block maximum 2: the 4-byte checksum still fits the input buffer
    const z = try zstd.compressAlloc(gpa, "ab", .{ .level = 3, .checksum = true });
    defer gpa.free(z);
    try std.testing.expectEqual(@as(usize, 15), z.len);
    const back = try streamDecode(z, .{ .in_max = 1, .out_max = 16 }, 0, .{});
    defer gpa.free(back);
    try std.testing.expectEqualStrings("ab", back);
}

test "buffers 3x too large for 128 frames in a row are shrunk" {
    // one frame with a 1 MB window, then small frames of unknown size
    // (no single-pass shortcut, so each one sizes the buffers)
    var s = try zstd.DecompressStream.init(gpa, .{});
    defer s.deinit();
    var out: [4096]u8 = undefined;
    const big = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 10 << 3, 0x01, 0x00, 0x00 };
    const small = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x01, 0x00, 0x00 };
    var o: zstd.OutBuffer = .{ .dst = &out };
    var in: zstd.InBuffer = .{ .src = &big };
    try std.testing.expectEqual(@as(usize, 0), try s.decompressStream(&o, &in));
    const large = s.buf.len;
    for (1..129) |n| {
        in = .{ .src = &small };
        try std.testing.expectEqual(@as(usize, 0), try s.decompressStream(&o, &in));
        if (n < 128) try std.testing.expectEqual(large, s.buf.len) else try std.testing.expect(s.buf.len < large);
    }
}

test "a stream with a 128 KB window through a small output buffer" {
    // the ring holds the window plus two blocks; matches reach back across
    // its wrap while the caller drains 700 bytes at a time
    const src = try corpusInput("far-repeat");
    defer gpa.free(src);
    var st = try zstd.Stream.init(gpa, .{ .level = 3 });
    defer st.deinit();
    st.window_log = 17;
    const z = try gpa.alloc(u8, zstd.compressBound(src.len) + 1024);
    defer gpa.free(z);
    var o: zstd.OutBuffer = .{ .dst = z };
    var i: zstd.InBuffer = .{ .src = src };
    _ = try st.compressStream2(&o, &i, .@"continue");
    var none: zstd.InBuffer = .{ .src = "" };
    while (try st.compressStream2(&o, &none, .end) != 0) {}
    const back = try streamDecode(z[0..o.pos], .{ .in_max = 50_000, .out_max = 700 }, 3, .{});
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, src, back);
}

test "the hint counts the next block header; a raw block streams in pieces" {
    // multi-block frame (libzstd: frame 120 832 bytes, first block
    // 52 775 bytes, not the last)
    const big = try gpa.alloc(u8, 300_000);
    defer gpa.free(big);
    var x: u32 = 7;
    for (big) |*b| {
        x = x *% 1103515245 +% 12345;
        b.* = "abcdefgh "[(x >> 16) % 9];
    }
    const z = try zstd.compressAlloc(gpa, big, .{ .level = 1 });
    defer gpa.free(z);
    try std.testing.expectEqual(@as(usize, 120_832), z.len);
    try expectSteps(z, &.{.{ .cut = 12, .out = 64, .hint = 52_778, .in_pos = 12, .out_pos = 0 }}, false);

    // a raw block of 1000 bytes fed in halves: its first half comes out
    // before the rest arrives
    var f: [9 + 1000]u8 = undefined;
    @memcpy(f[0..6], &[_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00 });
    const h: u32 = (1000 << 3) | 1;
    f[6] = @truncate(h);
    f[7] = @truncate(h >> 8);
    f[8] = @truncate(h >> 16);
    for (f[9..], 0..) |*b, i| b.* = @intCast('a' + i % 26);
    try expectSteps(&f, &.{
        .{ .cut = 509, .out = 4096, .hint = 500, .in_pos = 509, .out_pos = 500 },
    }, false);
}

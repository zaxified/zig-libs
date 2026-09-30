// SPDX-License-Identifier: MIT
//! Tests for `decompressStream`. The oracle is the one-shot `decompress`
//! (itself anchored on google/brotli's streams, `interop_replay_test.zig`):
//! for every stream in the committed corpus the streaming decoder must write
//! the same bytes — fed whole, and fed in slivers of 1..7 bytes — and for every
//! truncation of a small stream it must fail exactly where `decompress` fails.
//! On top of that, the properties only streaming has: output larger than the
//! window (the ring wraps), memory bounded by the window rather than the
//! output, and the two ends' own failures reported as themselves.

const std = @import("std");
const testing = std.testing;
const brotli = @import("root.zig");
const corpus = @import("interop_corpus.zig");

/// Decode `stream` through `decompressStream`, the input served in pieces of
/// at most `piece` bytes (0 = all at once) through a reader with a small
/// buffer. Caller frees the result.
fn streamDecode(gpa: std.mem.Allocator, stream: []const u8, piece: usize, options: brotli.Options) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    if (piece == 0) {
        var in: std.Io.Reader = .fixed(stream);
        const n = try brotli.decompressStream(gpa, &in, &out.writer, options);
        try testing.expectEqual(@as(u64, out.written().len), n);
    } else {
        var calls: [1]std.testing.Reader.Call = .{.{ .buffer = stream }};
        var buf: [16]u8 = undefined;
        var tr: std.testing.Reader = .init(&buf, &calls);
        tr.artificial_limit = .limited(piece);
        const n = try brotli.decompressStream(gpa, &tr.interface, &out.writer, options);
        try testing.expectEqual(@as(u64, out.written().len), n);
    }
    return out.toOwnedSlice();
}

fn expectStreamsTo(plain: []const u8, stream: []const u8, options: brotli.Options) !void {
    // Slivers on the small streams, where every chunk boundary lands on a
    // different decoder state; a large stream only adds time at 1 byte a call.
    const pieces: []const usize = if (stream.len <= 4096) &.{ 0, 1, 3, 7 } else &.{0};
    for (pieces) |piece| {
        const got = try streamDecode(testing.allocator, stream, piece, options);
        defer testing.allocator.free(got);
        testing.expectEqualSlices(u8, plain, got) catch |e| {
            std.debug.print("piece size {d}\n", .{piece});
            return e;
        };
    }
}

const small_vectors = [_][]const u8{
    "empty",             "x",          "xyzzy",          "10x10y",             "64x",         "quickfox",
    "quickfox_repeated", "zeros",      "ukkonooa",       "zerosukkanooa",      "monkey",      "backward65536",
    "compressed_file",   "cp852-utf8", "cp1251-utf16le", "random_org_10k.bin", "alice29.txt",
};

test "stream: every committed vector decodes to its plaintext, whole and in slivers" {
    inline for (small_vectors) |name| {
        const plain = @embedFile("testdata/" ++ name);
        const comp = @embedFile("testdata/" ++ name ++ ".compressed");
        expectStreamsTo(plain, comp, .{}) catch |e| {
            std.debug.print("vector {s}\n", .{name});
            return e;
        };
    }
}

test "stream: google/brotli's own streams, including 1 KiB and 64 KiB windows the ring wraps many times" {
    inline for (corpus.ref_streams) |r| {
        const plain = @embedFile("testdata/" ++ r.input);
        const stream = @embedFile("testdata/ref/" ++ r.file);
        // Once each, in 61-byte pieces (chunk boundaries anywhere in the
        // stream); slivers over 24 streams would dominate the suite's time,
        // and the small vectors above take 1/3/7.
        for ([_]usize{61}) |piece| {
            const got = streamDecode(testing.allocator, stream, piece, .{ .max_output = 1 << 24 }) catch |e| {
                std.debug.print("{s}: {s}\n", .{ r.file, @errorName(e) });
                return e;
            };
            defer testing.allocator.free(got);
            testing.expectEqualSlices(u8, plain, got) catch |e| {
                std.debug.print("{s} piece {d}\n", .{ r.file, piece });
                return e;
            };
        }
    }
}

test "stream: our encoder's output round-trips (stored and compressed blocks, both windows, block edges)" {
    const gpa = testing.allocator;
    // The shapes whose streams differ in kind; compressing all 45 again would
    // double what the interop replay already spends on them.
    const wanted = [_][]const u8{ "mixed_random_first", "mixed_text_first", "block_plus_one", "random_70000", "run_22595", "alice_65519", "alice_65521" };
    inline for (corpus.shapes) |shape| {
        const keep = comptime for (wanted) |w| {
            if (std.mem.eql(u8, w, shape.name)) break true;
        } else false;
        if (!keep) continue;
        const input = try corpus.build(gpa, shape);
        defer gpa.free(input);
        const comp = try brotli.compress(gpa, input);
        defer gpa.free(comp);
        const got = try streamDecode(gpa, comp, 0, .{});
        defer gpa.free(got);
        testing.expectEqualSlices(u8, input, got) catch |e| {
            std.debug.print("shape {s}\n", .{shape.name});
            return e;
        };
    }
}

test "stream: every truncation fails as the one-shot decoder fails (never a panic, never a different verdict)" {
    const vectors = [_][]const u8{
        @embedFile("testdata/quickfox.compressed"),
        @embedFile("testdata/10x10y.compressed"),
        @embedFile("testdata/ukkonooa.compressed"),
        @embedFile("testdata/monkey.compressed"),
    };
    for (vectors) |full| {
        for (0..full.len) |cut| {
            const prefix = full[0..cut];
            const want = brotli.decompress(testing.allocator, prefix, .{});
            if (want) |bytes| {
                // A prefix can itself be a complete stream only if the rest
                // was trailing bytes; then the stream decoder agrees.
                defer testing.allocator.free(bytes);
                const got = try streamDecode(testing.allocator, prefix, 1, .{});
                defer testing.allocator.free(got);
                try testing.expectEqualSlices(u8, bytes, got);
            } else |want_err| {
                for ([_]usize{ 0, 1 }) |piece| {
                    if (streamDecode(testing.allocator, prefix, piece, .{})) |got| {
                        testing.allocator.free(got);
                        std.debug.print("cut {d}: stream succeeded, one-shot said {s}\n", .{ cut, @errorName(want_err) });
                        return error.TestUnexpectedResult;
                    } else |got_err| {
                        testing.expectEqual(@as(anyerror, want_err), @as(anyerror, got_err)) catch |e| {
                            std.debug.print("cut {d} piece {d}\n", .{ cut, piece });
                            return e;
                        };
                    }
                }
            }
        }
    }
}

/// An allocator that records the peak of live bytes.
const PeakAllocator = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,

    fn allocator(self: *PeakAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn note(self: *PeakAllocator, grow: usize, shrink: usize) void {
        self.live = self.live + grow - shrink;
        self.peak = @max(self.peak, self.live);
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *PeakAllocator = @ptrCast(@alignCast(ctx));
        const p = self.child.rawAlloc(len, a, ra) orelse return null;
        self.note(len, 0);
        return p;
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *PeakAllocator = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(m, a, new_len, ra)) return false;
        self.note(new_len, m.len);
        return true;
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *PeakAllocator = @ptrCast(@alignCast(ctx));
        const p = self.child.rawRemap(m, a, new_len, ra) orelse return null;
        self.note(new_len, m.len);
        return p;
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *PeakAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(m, a, ra);
        self.note(0, m.len);
    }
};

test "stream: memory is the window, not the output (4 MiB out through a 2 MiB window)" {
    const gpa = testing.allocator;
    // alice29.txt cycled to 4 MiB: our encoder picks WBITS 21 (2 MiB) for
    // it, so the ring wraps and the output outgrows it.
    const len = 4 << 20;
    const input = try gpa.alloc(u8, len);
    defer gpa.free(input);
    for (input, 0..) |*b, i| b.* = corpus.alice[i % corpus.alice.len];
    const comp = try brotli.compress(gpa, input);
    defer gpa.free(comp);

    var peak: PeakAllocator = .{ .child = gpa };
    const got = try streamDecode(peak.allocator(), comp, 0, .{});
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, input, got);
    // The ring grown to the window (2 MiB; its last doubling briefly holds
    // the 1 MiB it grew from) plus the decoding tables — below the output.
    try testing.expect(peak.peak >= 2 << 20);
    try testing.expect(peak.peak < (13 << 20) / 4);
    try testing.expectEqual(@as(usize, 0), peak.live);

    // The one-shot decoder, for contrast, holds the whole output.
    var peak1: PeakAllocator = .{ .child = gpa };
    const one = try brotli.decompress(peak1.allocator(), comp, .{});
    defer peak1.allocator().free(one);
    try testing.expect(peak1.peak >= len);
}

test "stream: tables do not pile up across meta-blocks (1024 meta-blocks)" {
    // 2 MiB of text in 2 KiB meta-blocks, each with its own prefix codes.
    // Without the per-meta-block reset the tables of all 1024 stay live until
    // the end (measured: peak 2.98 MB); with it, one meta-block's worth
    // (2.11 MB, of which 2 MiB is the ring).
    const gpa = testing.allocator;
    const len = 2 << 20;
    const input = try gpa.alloc(u8, len);
    defer gpa.free(input);
    for (input, 0..) |*b, i| b.* = corpus.alice[(i * 7) % corpus.alice.len];
    const comp = try brotli.compressWith(gpa, input, .{ .block_size = 2048 });
    defer gpa.free(comp);

    var peak: PeakAllocator = .{ .child = gpa };
    const got = try streamDecode(peak.allocator(), comp, 0, .{});
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, input, got);
    // The ring (2 MiB window) plus one meta-block's tables.
    try testing.expect(peak.peak < (2 << 20) + (256 << 10));
}

test "stream: stored meta-blocks larger than the ratio floor are not mistaken for a bomb" {
    const gpa = testing.allocator;
    // Incompressible input: the encoder stores it, 1.25 MiB in stored blocks,
    // past `min_output_floor` (1 MiB) while little input is consumed.
    const input = try gpa.alloc(u8, (5 << 20) / 4);
    defer gpa.free(input);
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    prng.random().bytes(input);
    const comp = try brotli.compress(gpa, input);
    defer gpa.free(comp);
    const got = try streamDecode(gpa, comp, 0, .{});
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, input, got);
}

test "stream: a small body costs a small ring; the output cap holds and bounds the ring" {
    // quickfox.compressed declares a 4 MiB window for 43 bytes of output.
    {
        var peak: PeakAllocator = .{ .child = testing.allocator };
        const got = try streamDecode(peak.allocator(), @embedFile("testdata/quickfox.compressed"), 0, .{});
        defer testing.allocator.free(got);
        try testing.expect(peak.peak < 256 << 10);
    }
    const plain = @embedFile("testdata/alice29.txt");
    const stream = @embedFile("testdata/ref/alice29.txt.q11.w22.br");
    // Exactly the output: accepted, with a 256 KiB ring instead of 4 MiB.
    var peak: PeakAllocator = .{ .child = testing.allocator };
    const got = try streamDecode(peak.allocator(), stream, 0, .{ .max_output = plain.len });
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, plain, got);
    try testing.expect(peak.peak < 1 << 20);
    // One byte less: refused.
    try testing.expectError(error.OutputTooLarge, streamDecode(testing.allocator, stream, 0, .{ .max_output = plain.len - 1 }));
    // The ratio bound: 13 bytes of zeros.compressed expand 20000x but stay
    // under the floor; lower the floor and the stream is refused.
    const zeros = @embedFile("testdata/zeros.compressed");
    try testing.expectError(error.OutputTooLarge, streamDecode(testing.allocator, zeros, 0, .{ .min_output_floor = 4096 }));
}

/// A reader that serves `good` and then fails.
const FailingReader = struct {
    good: []const u8,
    pos: usize = 0,
    interface: std.Io.Reader,

    fn init(good: []const u8, buf: []u8) FailingReader {
        return .{ .good = good, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 } };
    }
    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *FailingReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.pos == self.good.len) return error.ReadFailed;
        const n = try w.write(limit.sliceConst(self.good[self.pos..]));
        self.pos += n;
        return n;
    }
};

test "stream: a failing reader is ReadFailed, a failing writer WriteFailed — not a format error" {
    const comp = @embedFile("testdata/alice29.txt.compressed");
    var buf: [64]u8 = undefined;
    var fr: FailingReader = .init(comp[0 .. comp.len / 2], &buf);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.ReadFailed, brotli.decompressStream(testing.allocator, &fr.interface, &out.writer, .{}));

    var in: std.Io.Reader = .fixed(comp);
    var small: [1000]u8 = undefined;
    var fw: std.Io.Writer = .fixed(&small);
    try testing.expectError(error.WriteFailed, brotli.decompressStream(testing.allocator, &in, &fw, .{}));
}

test "stream: the reader is left just past what the decoder consumed" {
    // A complete stream from a fixed reader: everything is consumed (the
    // bit reader's read-ahead stops at the end of the input).
    const comp = @embedFile("testdata/quickfox.compressed");
    var in: std.Io.Reader = .fixed(comp);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    _ = try brotli.decompressStream(testing.allocator, &in, &out.writer, .{});
    try testing.expectEqual(@as(usize, 0), in.bufferedLen());
}

// ── deterministic fuzz driver (differential: stream vs one-shot) ────────────
//
//     BROTLI_FUZZ=<runs>[,<first seed>]  (testkit's driver: _MS, _SEEDFILE, …)
//
// Each input is a valid stream (google/brotli's, or our encoder's) damaged
// where it matters — a share of the flips land in the first bytes (window and
// meta-block headers, prefix-code descriptions) — sometimes truncated or
// spliced, and fed to both decoders, the streaming one in random piece sizes.
// The verdicts must agree: the same bytes, or the same error. The reach line
// counts how many decoded and how each of the rest failed.

const fuzz_driver = @import("testkit").fuzz.driver;

const fz_bases = [_][]const u8{
    @embedFile("testdata/quickfox.compressed"),
    @embedFile("testdata/10x10y.compressed"),
    @embedFile("testdata/ukkonooa.compressed"),
    @embedFile("testdata/monkey.compressed"),
    @embedFile("testdata/zerosukkanooa.compressed"),
    @embedFile("testdata/cp852-utf8.compressed"),
    @embedFile("testdata/ref/monkey.q11.w22.br"),
    @embedFile("testdata/ref/ukkonooa.q11.w22.br"),
    @embedFile("testdata/ref/cp852-utf8.q11.w22.br"),
    @embedFile("testdata/ref/quickfox_repeated.q11.w10.br"),
    @embedFile("testdata/ref/x.q1.w22.br"),
};

fn streamDiffHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [16 << 10]u8 = undefined;
    const base = fz_bases[src.index(fz_bases.len)];
    var len: usize = @min(base.len, buf.len);
    @memcpy(buf[0..len], base[0..len]);

    const damages = src.valueRangeAtMost(u8, 0, 4);
    for (0..damages) |_| {
        if (len == 0) break;
        switch (src.valueRangeAtMost(u8, 0, 4)) {
            // A bit in the headers: window bits, meta-block length, the first
            // prefix codes.
            0, 1 => buf[src.index(@min(len, 48))] ^= @as(u8, 1) << src.value(u3),
            2 => buf[src.index(len)] ^= @as(u8, 1) << src.value(u3),
            3 => len = src.index(len + 1),
            // Splice: repeat a slice of the stream at another place.
            else => {
                const from = src.index(len);
                const n = @min(@as(usize, src.valueRangeAtMost(u8, 0, 32)), len - from, buf.len - len);
                const to = src.index(len + 1);
                std.mem.copyBackwards(u8, buf[to + n .. len + n], buf[to..len]);
                // The source may overlap the gap it is copied into.
                const at = if (from >= to) from + n else from;
                var tmp: [32]u8 = undefined;
                @memcpy(tmp[0..n], buf[at..][0..n]);
                @memcpy(buf[to..][0..n], tmp[0..n]);
                len += n;
            },
        }
    }
    const input = buf[0..len];
    const opts: brotli.Options = .{ .max_output = 1 << 20 };

    const want = brotli.decompress(gpa, input, opts);
    defer if (want) |w| gpa.free(w) else |_| {};

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const piece: usize = if (src.value(bool)) 0 else src.valueRangeAtMost(u8, 1, 64);
    const got = if (piece == 0) blk: {
        var in: std.Io.Reader = .fixed(input);
        break :blk brotli.decompressStream(gpa, &in, &out.writer, opts);
    } else blk: {
        var calls: [1]std.testing.Reader.Call = .{.{ .buffer = input }};
        var rbuf: [64]u8 = undefined;
        var tr: std.testing.Reader = .init(&rbuf, &calls);
        tr.artificial_limit = .limited(piece);
        break :blk brotli.decompressStream(gpa, &tr.interface, &out.writer, opts);
    };

    if (want) |w| {
        _ = got catch |e| {
            std.debug.print("one-shot decoded {d} bytes, stream said {t}\n", .{ w.len, e });
            return error.Disagree;
        };
        if (!std.mem.eql(u8, w, out.written())) return error.Disagree;
        fuzz_driver.hit("decoded");
    } else |we| {
        if (got) |_| {
            std.debug.print("one-shot said {t}, stream decoded {d} bytes\n", .{ we, out.written().len });
            return error.Disagree;
        } else |ge| {
            if (we != ge) {
                std.debug.print("one-shot said {t}, stream said {t}\n", .{ we, ge });
                return error.Disagree;
            }
            switch (we) {
                error.TruncatedInput => fuzz_driver.hit("truncated"),
                error.OutputTooLarge => fuzz_driver.hit("too_large"),
                error.InvalidDistance => fuzz_driver.hit("bad_distance"),
                error.InvalidDictionary => fuzz_driver.hit("bad_dictionary"),
                error.InvalidHuffman, error.DuplicateSimpleSymbol => fuzz_driver.hit("bad_prefix_code"),
                else => fuzz_driver.hit("other_format_error"),
            }
        }
    }
}

test "fuzz driver: stream and one-shot agree on damaged streams (BROTLI_FUZZ)" {
    try fuzz_driver.run(streamDiffHarness, .{ .prefix = "BROTLI_FUZZ", .name = "stream-diff" });
}

test "fuzz: stream and one-shot agree on damaged streams (coverage-guided exploration)" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) !void {
            try streamDiffHarness(std.testing.Smith, smith, testing.allocator);
        }
    }.one, .{});
}

// SPDX-License-Identifier: MIT
//! Compression contexts: reuse, sizing, and caller-provided workspaces.
//!
//! That a reused context gives libzstd's bytes is pinned by the golden
//! tests, which run every frame through one context. Here: the workspace
//! policy (kept, replaced when too small or long too big, indexing
//! restarted near the index limit -- each still giving a fresh context's
//! bytes), and the estimates, which are exact.

const std = @import("std");
const zstd = @import("root.zig");
const frame = @import("frame.zig");
const params = @import("params.zig");
const corpus = @import("testdata/corpus.zig");

fn input(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) {
        const buf = try gpa.alloc(u8, c.len);
        corpus.generate(c, buf);
        return buf;
    };
    unreachable;
}

fn expectFresh(gpa: std.mem.Allocator, got: []const u8, src: []const u8, opts: zstd.Options) !void {
    const want = try zstd.compressAlloc(gpa, src, opts);
    defer gpa.free(want);
    try std.testing.expectEqualSlices(u8, want, got);
}

const levels = [_]i32{ -5, 1, 3, 5, 9, 11, 12, 16, 19, 22 };
const advanced = [_]zstd.Advanced{
    .{},
    .{ .window_log = 12 },
    .{ .row_match_finder = .enable, .hash_log = 20 },
    .{ .max_block_size = 5000 },
    // Tiny tables: at level 11 an input of 16 KB (`btopt`, with the optimal
    // parser's scratch) then needs more than any larger one (`btlazy2`), so
    // the largest need is at a size-class bound.
    .{ .window_log = 10, .hash_log = 6, .chain_log = 6 },
};

test "a compressor allocates exactly its estimate, and no size needs more than the estimate for any" {
    const gpa = std.testing.allocator;
    const src = try input(gpa, "csv-600000");
    defer gpa.free(src);
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(dst);
    for (levels) |level| for (advanced) |adv| {
        const opts: zstd.Options = .{ .level = level, .advanced = adv };
        const any = try zstd.estimateCompressorSize(null, opts);
        for ([_]usize{ 0, 1, 100, 16384, 16385, 131072, 131073, 262144, 262145, 600000 }) |n| {
            var c: zstd.Compressor = .init(gpa);
            defer c.deinit();
            _ = try c.compress(dst, src[0..n], opts);
            try std.testing.expectEqual(try zstd.estimateCompressorSize(n, opts), c.workspaceSize());
            try std.testing.expect(c.workspaceSize() <= any);
        }
        // sizes the compressions above would take too long for
        var prng: std.Random.DefaultPrng = .init(@bitCast(@as(i64, level)));
        var reached = false;
        for (0..300) |_| {
            const n = prng.random().uintLessThan(u64, @as(u64, 1) << prng.random().uintLessThan(u6, 34));
            const e = try zstd.estimateCompressorSize(n, opts);
            try std.testing.expect(e <= any);
            reached = reached or e == any;
        }
        for (params.size_class_bounds ++ [_]u64{1 << 40}) |n| reached = reached or try zstd.estimateCompressorSize(n, opts) == any;
        try std.testing.expect(reached);
    };
}

test "a stream allocates exactly its estimate; without a size, no frame needs more" {
    const gpa = std.testing.allocator;
    const src = try input(gpa, "csv-600000");
    defer gpa.free(src);
    var obuf: [1 << 16]u8 = undefined;
    const big = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(big);
    for (levels) |level| for (advanced) |adv| {
        const any_opts: zstd.StreamOptions = .{ .level = level, .advanced = adv };
        const any = try zstd.estimateStreamSize(any_opts);
        for ([_]?u64{ null, 5000, 200000 }) |pledged| for ([_]?u32{ null, 70000 }) |hint| {
            const opts: zstd.StreamOptions = .{ .level = level, .advanced = adv, .pledged_size = pledged, .src_size_hint = hint };
            var s = try zstd.Stream.init(gpa, opts);
            defer s.deinit();
            const n: usize = @intCast(pledged orelse 150000);
            var in: zstd.InBuffer = .{ .src = src[0..n] };
            while (true) {
                var o: zstd.OutBuffer = .{ .dst = &obuf };
                if (try s.compressStream2(&o, &in, .@"continue") == 0 and in.pos == in.src.len) break;
            }
            if (pledged != null or hint != null) try std.testing.expectEqual(try zstd.estimateStreamSize(opts), s.workspaceSize());
            try std.testing.expect(s.workspaceSize() <= any);
            while (true) {
                var o: zstd.OutBuffer = .{ .dst = &obuf };
                if (try s.compressStream2(&o, &in, .end) == 0) break;
            }
        };
        // a frame ended in its first call is sized for its input
        for ([_]usize{ 0, 16384, 131073, 262144, 600000 }) |n| {
            var s = try zstd.Stream.init(gpa, any_opts);
            defer s.deinit();
            var in: zstd.InBuffer = .{ .src = src[0..n] };
            var o: zstd.OutBuffer = .{ .dst = big };
            try std.testing.expectEqual(@as(usize, 0), try s.compressStream2(&o, &in, .end));
            try std.testing.expect(s.workspaceSize() <= any);
        }
    };
}

test "a static workspace of the estimate is enough, a byte less is not, and it is never replaced" {
    const gpa = std.testing.allocator;
    const src = try input(gpa, "csv-200000-0");
    defer gpa.free(src);
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(dst);
    for ([_]i32{ 1, 6, 17 }) |level| {
        const opts: zstd.Options = .{ .level = level, .checksum = true };
        const size = try zstd.estimateCompressorSize(src.len, opts);
        const ws = try gpa.alignedAlloc(u8, .fromByteUnits(zstd.workspace_alignment), size);
        defer gpa.free(ws);
        var short: zstd.Compressor = .initStatic(ws[0 .. size - 1]);
        try std.testing.expectError(error.OutOfMemory, short.compress(dst, src, opts));
        var c: zstd.Compressor = .initStatic(ws);
        for (0..3) |_| {
            const n = try c.compress(dst, src, opts);
            try expectFresh(gpa, dst[0..n], src, opts);
            // a smaller frame fits in what is there
            const m = try c.compress(dst, src[0..5000], opts);
            try expectFresh(gpa, dst[0..m], src[0..5000], opts);
        }
        try std.testing.expectEqual(size, c.workspaceSize());

        const sopts: zstd.StreamOptions = .{ .level = level, .pledged_size = src.len };
        const ssize = try zstd.estimateStreamSize(sopts);
        const sws = try gpa.alignedAlloc(u8, .fromByteUnits(zstd.workspace_alignment), ssize);
        defer gpa.free(sws);
        var obuf: [1 << 12]u8 = undefined;
        var s = try zstd.Stream.initStatic(sws, sopts);
        var in: zstd.InBuffer = .{ .src = src };
        var o: zstd.OutBuffer = .{ .dst = &obuf };
        _ = try s.compressStream2(&o, &in, .@"continue");
        var s_short = try zstd.Stream.initStatic(sws[0 .. ssize - 1], sopts);
        in.pos = 0;
        try std.testing.expectError(error.OutOfMemory, s_short.compressStream2(&o, &in, .@"continue"));
    }
}

test "a workspace three times too big is replaced after 128 frames, as libzstd does" {
    const gpa = std.testing.allocator;
    const src = try input(gpa, "csv-600000");
    defer gpa.free(src);
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(dst);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    _ = try c.compress(dst, src, .{ .level = 12 });
    const big = c.workspaceSize();
    // the first small frame finds the big one's layout in place (nothing
    // free), each one after counts as oversized
    for (0..129) |i| {
        const n = try c.compress(dst, src[i * 100 ..][0..3000], .{ .level = 1 });
        if (i % 32 == 0) try expectFresh(gpa, dst[0..n], src[i * 100 ..][0..3000], .{ .level = 1 });
    }
    try std.testing.expectEqual(big, c.workspaceSize());
    try std.testing.expectEqual(@as(u32, 1), c.ctx.n_workspace_allocs);
    const n = try c.compress(dst, src[0..3000], .{ .level = 1 });
    try expectFresh(gpa, dst[0..n], src[0..3000], .{ .level = 1 });
    try std.testing.expectEqual(@as(u32, 2), c.ctx.n_workspace_allocs);
    try std.testing.expect(c.workspaceSize() * 3 <= big);
}

test "indexing restarts near the index limit, with the same bytes" {
    const gpa = std.testing.allocator;
    const src = try input(gpa, "csv-600000");
    defer gpa.free(src);
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(dst);
    for ([_]i32{ 2, 7, 16 }) |level| {
        var c: zstd.Compressor = .init(gpa);
        defer c.deinit();
        // (seam) the limit 400 KB in instead of 3484 MB
        c.ctx.index_too_close = 400_000;
        var frames: u32 = 0;
        var at: usize = 0;
        while (at + 150000 <= src.len) : (at += 90000) {
            const piece = src[at..][0..150000];
            const n = try c.compress(dst, piece, .{ .level = level });
            try expectFresh(gpa, dst[0..n], piece, .{ .level = level });
            frames += 1;
        }
        // the first frame and one in every three or so after (150 KB each
        // over a 400 KB limit)
        try std.testing.expect(c.ctx.n_index_resets > 1 and c.ctx.n_index_resets < frames);
        try std.testing.expectEqual(@as(u32, 1), c.ctx.n_workspace_allocs);
    }
}

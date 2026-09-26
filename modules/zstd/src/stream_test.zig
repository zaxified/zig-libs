// SPDX-License-Identifier: MIT
//! Streaming byte-exactness against libzstd 1.5.7.
//!
//! Every `corpus.stream_cases` entry is compressed through `Stream` by the
//! same call schedule `tools/zstream.c` gave `ZSTD_compressStream2`; the
//! concatenated output must have the length and SHA-256 recorded in
//! `testdata/stream_goldens.zig`. The schedule decides the bytes (where
//! chunks end, when the input buffer wraps, whether the end is compressed
//! straight from the caller's buffer), so both sides parse the same string.
//! A schedule starting with the token `x` is compared against libzstd built
//! to correct index overflow frequently (`tools/gen-goldens.sh` picks it).

const std = @import("std");
const stream = @import("stream.zig");
const zstd = @import("root.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/stream_goldens.zig");
const param_test = @import("param_test.zig");

pub const Run = struct {
    out: []u8,
    /// Blocks compressed with the window in two segments.
    ext_dict_blocks: u32,
    /// Of the match state and, with LDM, its window.
    overflow_corrections: u32,
    /// LDM chunks searched over two segments.
    ldm_ext_dict_chunks: u32,
};

/// Drive a stream over `src` as `tools/zstream.c` does for `schedule`.
fn run(gpa: std.mem.Allocator, src: []const u8, level: i32, checksum: bool, schedule: []const u8) !Run {
    return runOn(gpa, null, src, level, checksum, schedule, .none);
}

/// `run`, on `reused` (reset to the schedule's options) rather than on a
/// fresh stream when it is given.
pub fn runOn(gpa: std.mem.Allocator, reused: ?*stream.Stream, src: []const u8, level: i32, checksum: bool, schedule: []const u8, dictionary: zstd.Dictionary) !Run {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var pledged: ?u64 = null;
    var window_log: ?u32 = null;
    var ocap: usize = 1 << 24;
    var fed: usize = 0;
    var own: ?stream.Stream = null;
    defer if (own) |*st| st.deinit();
    var s: ?*stream.Stream = null;
    var ocf = false;
    var advanced: zstd.Advanced = .{};
    var src_size_hint: ?u32 = null;
    var ext_dict_blocks: u32 = 0;
    var overflow_corrections: u32 = 0;
    var ldm_ext_dict_chunks: u32 = 0;
    var sin: stream.InBuffer = .{ .src = src[0..0] };
    var sout: ?stream.OutBuffer = null;
    defer if (sout) |so| gpa.free(so.dst);
    var written: usize = 0;
    var it = std.mem.tokenizeScalar(u8, schedule, ',');
    while (it.next()) |tok| {
        if (std.mem.eql(u8, tok, "x")) {
            ocf = true;
            continue;
        }
        if (std.mem.eql(u8, tok, "l")) {
            advanced.long_distance_matching = .enable;
            continue;
        }
        if (try param_test.applyParam(&advanced, &src_size_hint, tok)) continue;
        const num: usize = if (tok[1] == '*') src.len - fed else try std.fmt.parseInt(usize, tok[1..], 10);
        const dir: stream.EndDirective = switch (tok[0]) {
            'p' => {
                pledged = num;
                continue;
            },
            'w' => {
                window_log = @intCast(num);
                continue;
            },
            'o' => {
                ocap = num;
                continue;
            },
            'c' => .@"continue",
            'f' => .flush,
            'e' => .end,
            else => return error.BadSchedule,
        };
        if (s == null) {
            if (window_log) |w| advanced.window_log = w;
            const opts: stream.Options = .{ .level = level, .checksum = checksum, .pledged_size = pledged, .src_size_hint = src_size_hint, .advanced = advanced, .dictionary = dictionary };
            if (reused) |r| {
                try r.reset(opts);
                s = r;
            } else {
                own = try stream.Stream.init(gpa, opts);
                s = &own.?;
            }
            s.?.overflow_correct_frequently = ocf;
        }
        // stable input: one buffer, grown by each token, pos kept; stable
        // output: one buffer for the whole schedule, never drained
        if (advanced.stable_out_buffer and sout == null) sout = .{ .dst = try gpa.alloc(u8, ocap) };
        const obuf = try gpa.alloc(u8, ocap);
        defer gpa.free(obuf);
        var in: stream.InBuffer = .{ .src = src[fed..][0..num] };
        const inp = if (advanced.stable_in_buffer) &sin else &in;
        if (advanced.stable_in_buffer) sin.src = src[0 .. fed + num];
        while (true) {
            var o: stream.OutBuffer = .{ .dst = obuf };
            const outp = if (sout) |*so| so else &o;
            const remaining = try s.?.compressStream2(outp, inp, dir);
            if (sout) |so| {
                try out.appendSlice(gpa, so.dst[written..so.pos]);
                written = so.pos;
                if (if (dir == .@"continue") inp.pos == inp.src.len else remaining == 0) break;
                if (so.pos == so.dst.len) return error.StableOutputFull;
                continue;
            }
            try out.appendSlice(gpa, obuf[0..o.pos]);
            if (if (dir == .@"continue") inp.pos == inp.src.len else remaining == 0) break;
        }
        fed += num;
        if (dir == .end) {
            ext_dict_blocks = s.?.comp.c.ms.n_ext_dict_blocks;
            overflow_corrections = s.?.comp.c.ms.n_overflow_corrections;
            if (s.?.comp.c.ldm) |ls| {
                ldm_ext_dict_chunks = ls.n_ext_dict_chunks;
                overflow_corrections += ls.n_overflow_corrections;
            }
            break;
        }
    }
    return .{ .out = try out.toOwnedSlice(gpa), .ext_dict_blocks = ext_dict_blocks, .overflow_corrections = overflow_corrections, .ldm_ext_dict_chunks = ldm_ext_dict_chunks };
}

fn findCase(name: []const u8) corpus.Case {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    unreachable;
}

fn find(sc: corpus.StreamCase, level: i32, checksum: bool) ?goldens.Golden {
    for (goldens.rows) |g| {
        if (g.level == level and g.checksum == checksum and std.mem.eql(u8, g.case, sc.case) and std.mem.eql(u8, g.schedule, sc.schedule)) return g;
    }
    return null;
}

test "every streaming case has a golden row, and nothing else does" {
    var n: usize = 0;
    for (corpus.stream_cases) |sc| for (sc.levels) |level| for ([_]bool{ false, true }) |ck| {
        n += 1;
        if (find(sc, level, ck) == null) {
            std.debug.print("no golden row for {s} {s} level {d} checksum {}\n", .{ sc.case, sc.schedule, level, ck });
            return error.MissingGolden;
        }
    };
    try std.testing.expectEqual(n, goldens.rows.len);
}

test "streaming output is byte-identical to libzstd 1.5.7's ZSTD_compressStream2" {
    const gpa = std.testing.allocator;
    var mismatches: usize = 0;
    var dec_zstd1 = try zstd.Decompressor.init(gpa, .{});
    defer dec_zstd1.deinit();
    var dec_magicless = try zstd.Decompressor.init(gpa, .{ .format = .magicless });
    defer dec_magicless.deinit();
    // one stream for every frame, reset to each schedule's options (see
    // golden_test.zig)
    var reused = try stream.Stream.init(gpa, .{});
    defer reused.deinit();
    var frames: u32 = 0;
    for (corpus.stream_cases) |sc| {
        const dec = if (std.mem.indexOf(u8, sc.schedule, "format=1") != null) &dec_magicless else &dec_zstd1;
        const case = findCase(sc.case);
        const src = try gpa.alloc(u8, case.len);
        defer gpa.free(src);
        corpus.generate(case, src);
        // one byte more than the input: a frame decoding too long is caught
        const back = try gpa.alloc(u8, src.len + 1);
        defer gpa.free(back);
        for (sc.levels) |level| for ([_]bool{ false, true }) |ck| {
            const g = find(sc, level, ck).?;
            const r = try runOn(gpa, &reused, src, level, ck, sc.schedule, .none);
            defer gpa.free(r.out);
            frames += 1;
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(r.out, &digest, .{});
            const hex = std.fmt.bytesToHex(digest, .lower);
            if (r.out.len != g.len or !std.mem.eql(u8, &hex, g.sha256)) {
                std.debug.print("MISMATCH {s} {s} level {d} checksum {}: len {d} (libzstd {d})\n", .{ sc.case, sc.schedule, level, ck, r.out.len, g.len });
                mismatches += 1;
            }
            const got = dec.decompress(back, r.out) catch |e| {
                std.debug.print("DECODE ERROR {s} {s} level {d} checksum {}: {s}\n", .{ sc.case, sc.schedule, level, ck, @errorName(e) });
                mismatches += 1;
                continue;
            };
            if (got != src.len or !std.mem.eql(u8, back[0..got], src)) {
                std.debug.print("DECODE MISMATCH {s} {s} level {d} checksum {}\n", .{ sc.case, sc.schedule, level, ck });
                mismatches += 1;
            }
            // The extDict path leaves no mark in the output; that it ran
            // is checked here.
            if (std.mem.indexOfScalar(i32, sc.ext_dict, level) != null and r.ext_dict_blocks == 0) {
                std.debug.print("NO EXTDICT BLOCK {s} {s} level {d}\n", .{ sc.case, sc.schedule, level });
                mismatches += 1;
            }
            // ... and, with LDM on by hand (token l), by LDM too.
            if (std.mem.startsWith(u8, sc.schedule, "l,") and std.mem.indexOfScalar(i32, sc.ext_dict, level) != null and r.ldm_ext_dict_chunks == 0) {
                std.debug.print("NO LDM EXTDICT CHUNK {s} {s} level {d}\n", .{ sc.case, sc.schedule, level });
                mismatches += 1;
            }
            // Likewise a correction for index overflow (token x).
            if (std.mem.startsWith(u8, sc.schedule, "x,") and sc.corrects and std.mem.indexOfScalar(i32, sc.ext_dict, level) != null and r.overflow_corrections == 0) {
                std.debug.print("NO CORRECTION {s} {s} level {d}\n", .{ sc.case, sc.schedule, level });
                mismatches += 1;
            }
        };
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
    const ctx = &reused.comp;
    try std.testing.expect(ctx.n_index_resets > 1 and ctx.n_index_resets < frames / 2);
    try std.testing.expect(ctx.n_workspace_allocs > 1 and ctx.n_workspace_allocs < frames / 2);
}

test "a stream ended in its first call is the one-shot frame" {
    const gpa = std.testing.allocator;
    const case = findCase("csv-131073");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    for ([_]i32{ -1, 1, 3 }) |level| {
        const one = try zstd.compressAlloc(gpa, src, .{ .level = level, .checksum = true });
        defer gpa.free(one);
        const r = try run(gpa, src, level, true, "e*");
        defer gpa.free(r.out);
        try std.testing.expectEqualSlices(u8, one, r.out);
    }
}

test "a pledged size is enforced both ways" {
    const gpa = std.testing.allocator;
    const src = "0123456789" ** 10;
    // more than pledged
    try std.testing.expectError(error.SrcSizeWrong, run(gpa, src, 1, false, "p50,c*,e0"));
    // less than pledged, at the end
    try std.testing.expectError(error.SrcSizeWrong, run(gpa, src, 1, false, "p150,c*,e0"));
    const r = try run(gpa, src, 1, false, "p100,c*,e0");
    gpa.free(r.out);
}

test "levels above the streaming maximum are refused" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.LevelUnsupported, stream.Stream.init(gpa, .{ .level = stream.max_level + 1 }));
    var s = try stream.Stream.init(gpa, .{});
    defer s.deinit();
    try std.testing.expectError(error.LevelUnsupported, s.reset(.{ .level = stream.max_level + 1 }));
}

/// Feed `src` to `s` as schedule "c<half>,c*,e0" does: one frame.
fn feedFrame(gpa: std.mem.Allocator, s: *stream.Stream, src: []const u8, out: *std.ArrayList(u8)) !void {
    var obuf: [4096]u8 = undefined;
    const half = src.len / 2;
    for ([_][]const u8{ src[0..half], src[half..], "" }, [_]stream.EndDirective{ .@"continue", .@"continue", .end }) |piece, dir| {
        var in: stream.InBuffer = .{ .src = piece };
        while (true) {
            var o: stream.OutBuffer = .{ .dst = &obuf };
            const remaining = try s.compressStream2(&o, &in, dir);
            try out.appendSlice(gpa, obuf[0..o.pos]);
            if (if (dir == .@"continue") in.pos == in.src.len else remaining == 0) break;
        }
    }
}

test "after its end a stream goes on with a new frame of unknown size, as libzstd" {
    // libzstd resets the session at the end of a frame
    // (`ZSTD_CCtx_reset(ZSTD_reset_session_only)`): the pledged size is
    // forgotten, the options stay, and the context is reused.
    const gpa = std.testing.allocator;
    const case = findCase("far-repeat");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    const a = src[0 .. src.len / 3];
    const b = src[src.len / 3 ..];
    var sched_buf: [3][64]u8 = undefined;
    // One level, not three, on 32-bit MIPS: this loop's handful of
    // `Stream.init`/`deinit` and one-shot `run` contexts is a fraction of
    // `context_test.zig`'s churn, yet still reliably hits `qemu-mips`'s
    // `page_find_range_empty` assertion there (confirmed absent under
    // `qemu-i386`, unmodified -- SPEC.md Z12, *Portability*); one level
    // still exercises the reused-context "goes on with a new frame of
    // unknown size" path this test is about.
    const test_levels = if (@import("builtin").cpu.arch.isMIPS32()) &[_]i32{5} else &[_]i32{ 1, 5, 12 };
    for (test_levels) |level| {
        var s = try stream.Stream.init(gpa, .{ .level = level, .checksum = true, .pledged_size = a.len });
        defer s.deinit();
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try feedFrame(gpa, &s, a, &out);
        const first_len = out.items.len;
        try feedFrame(gpa, &s, b, &out);
        try feedFrame(gpa, &s, a, &out);
        const want_a = try run(gpa, a, level, true, try std.fmt.bufPrint(&sched_buf[0], "p{d},c{d},c*,e0", .{ a.len, a.len / 2 }));
        defer gpa.free(want_a.out);
        const want_b = try run(gpa, b, level, true, try std.fmt.bufPrint(&sched_buf[1], "c{d},c*,e0", .{b.len / 2}));
        defer gpa.free(want_b.out);
        const want_a2 = try run(gpa, a, level, true, try std.fmt.bufPrint(&sched_buf[2], "c{d},c*,e0", .{a.len / 2}));
        defer gpa.free(want_a2.out);
        try std.testing.expectEqualSlices(u8, want_a.out, out.items[0..first_len]);
        try std.testing.expectEqualSlices(u8, want_b.out, out.items[first_len..][0..want_b.out.len]);
        try std.testing.expectEqualSlices(u8, want_a2.out, out.items[first_len + want_b.out.len ..]);
        // the pledged first frame needs less than the two of unknown size,
        // the third reuses the second's workspace
        try std.testing.expectEqual(@as(u32, 2), s.comp.n_workspace_allocs);
    }
}

test "reset abandons a frame and starts over with new options" {
    const gpa = std.testing.allocator;
    const case = findCase("csv-131073");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    var s = try stream.Stream.init(gpa, .{ .level = 7 });
    defer s.deinit();
    var obuf: [1 << 18]u8 = undefined;
    var o: stream.OutBuffer = .{ .dst = &obuf };
    var in: stream.InBuffer = .{ .src = src[0..70000] };
    _ = try s.compressStream2(&o, &in, .flush); // half a frame, dropped
    try s.reset(.{ .level = 3, .pledged_size = src.len });
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try feedFrame(gpa, &s, src, &out);
    var sched_buf: [1][64]u8 = undefined;
    const want = try run(gpa, src, 3, false, try std.fmt.bufPrint(&sched_buf[0], "p{d},c{d},c*,e0", .{ src.len, src.len / 2 }));
    defer gpa.free(want.out);
    try std.testing.expectEqualSlices(u8, want.out, out.items);
}

test "streams round-trip through std's decoder" {
    const gpa = std.testing.allocator;
    const case = findCase("far-repeat");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    for ([_][]const u8{ "c*,e0", "w10,o77,c1000,f0,c*,e0", "w12,c300000,f0,c*,e0" }) |sched| {
        const r = try run(gpa, src, 1, false, sched);
        defer gpa.free(r.out);
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var in: std.Io.Reader = .fixed(r.out);
        var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{ .verify_checksum = false });
        _ = try d.reader.streamRemaining(&out.writer);
        try std.testing.expectEqualSlices(u8, src, out.written());
    }
}

test "stable input: calls under one block wait, pretending to consume; the contract is checked" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 300_000);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 7 }, src);
    var out: [1 << 17]u8 = undefined;
    inline for (.{ params_zstd1, params_magicless }) |p| {
        var s: stream.Stream = try .init(gpa, .{ .advanced = p.adv });
        defer s.deinit();
        var in: stream.InBuffer = .{ .src = src[0..1000] };
        var o: stream.OutBuffer = .{ .dst = &out };
        // ZSTD_FRAMEHEADERSIZE_MIN: nothing written, all "consumed"
        try std.testing.expectEqual(@as(usize, p.hint), try s.compressStream2(&o, &in, .@"continue"));
        try std.testing.expectEqual(@as(usize, 1000), in.pos);
        try std.testing.expectEqual(@as(usize, 0), o.pos);
        // the same buffer, grown: fine; moved or with pos changed: refused
        in.src = src[0..2000];
        _ = try s.compressStream2(&o, &in, .@"continue");
        var moved: stream.InBuffer = .{ .src = src[1..3001], .pos = 2000 };
        try std.testing.expectError(error.StabilityConditionNotRespected, s.compressStream2(&o, &moved, .@"continue"));
        var rewound: stream.InBuffer = .{ .src = src[0..3000], .pos = 1000 };
        try std.testing.expectError(error.StabilityConditionNotRespected, s.compressStream2(&o, &rewound, .@"continue"));
        // past one block the frame starts; after that, too
        in.src = src[0..200_000];
        _ = try s.compressStream2(&o, &in, .@"continue");
        try std.testing.expect(o.pos > 0);
        var moved2: stream.InBuffer = .{ .src = src[1..250_000], .pos = in.pos };
        try std.testing.expectError(error.StabilityConditionNotRespected, s.compressStream2(&o, &moved2, .@"continue"));
        var rewound2: stream.InBuffer = .{ .src = src[0..250_000], .pos = in.pos - 1 };
        try std.testing.expectError(error.StabilityConditionNotRespected, s.compressStream2(&o, &rewound2, .@"continue"));
    }
    // exactly one block in the first call: the frame starts there
    {
        var s: stream.Stream = try .init(gpa, .{ .advanced = .{ .stable_in_buffer = true } });
        defer s.deinit();
        var in: stream.InBuffer = .{ .src = src[0 .. 128 * 1024] };
        var o: stream.OutBuffer = .{ .dst = &out };
        _ = try s.compressStream2(&o, &in, .@"continue");
        try std.testing.expect(o.pos > 6);
    }
    // a reset drops what a waiting frame held back: the next frame, from
    // another buffer, is a fresh stream's
    {
        var s: stream.Stream = try .init(gpa, .{ .advanced = .{ .stable_in_buffer = true } });
        defer s.deinit();
        var in: stream.InBuffer = .{ .src = src[0..1000] };
        var o: stream.OutBuffer = .{ .dst = &out };
        _ = try s.compressStream2(&o, &in, .@"continue");
        try s.reset(.{ .advanced = .{ .stable_in_buffer = true } });
        var in2: stream.InBuffer = .{ .src = src[5000..9000] };
        var o2: stream.OutBuffer = .{ .dst = &out };
        _ = try s.compressStream2(&o2, &in2, .end);
        const one = try zstd.compressAlloc(gpa, src[5000..9000], .{});
        defer gpa.free(one);
        try std.testing.expectEqualSlices(u8, one, out[0..o2.pos]);
    }
}

const params_zstd1 = .{ .adv = zstd.Advanced{ .stable_in_buffer = true }, .hint = 6 };
const params_magicless = .{ .adv = zstd.Advanced{ .stable_in_buffer = true, .format = .magicless }, .hint = 2 };

test "stable output: the room left is checked; blocks go into whatever room there is" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 200_000);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 8 }, src);
    var out: [1 << 18]u8 = undefined;
    {
        var s: stream.Stream = try .init(gpa, .{ .advanced = .{ .stable_out_buffer = true } });
        defer s.deinit();
        var in: stream.InBuffer = .{ .src = src[0..150_000] };
        var o: stream.OutBuffer = .{ .dst = &out };
        _ = try s.compressStream2(&o, &in, .@"continue");
        var other: stream.OutBuffer = .{ .dst = out[0 .. out.len - 1], .pos = o.pos };
        try std.testing.expectError(error.StabilityConditionNotRespected, s.compressStream2(&other, &in, .flush));
        // (moving the buffer with the same room left is allowed, as in libzstd)
        var moved: stream.OutBuffer = .{ .dst = out[1..], .pos = o.pos - 1 };
        _ = try s.compressStream2(&moved, &in, .flush);
    }
    {
        // 1000 bytes of room for a 128 KB block: neither its compressed
        // form nor a raw block fits
        var s: stream.Stream = try .init(gpa, .{ .advanced = .{ .stable_out_buffer = true } });
        defer s.deinit();
        var in: stream.InBuffer = .{ .src = src };
        var o: stream.OutBuffer = .{ .dst = out[0..1000] };
        try std.testing.expectError(error.DstSizeTooSmall, s.compressStream2(&o, &in, .end));
    }
    {
        // a full block through `continue`, the same
        var s: stream.Stream = try .init(gpa, .{ .advanced = .{ .stable_out_buffer = true } });
        defer s.deinit();
        var in: stream.InBuffer = .{ .src = src };
        var o: stream.OutBuffer = .{ .dst = out[0..1000] };
        try std.testing.expectError(error.DstSizeTooSmall, s.compressStream2(&o, &in, .@"continue"));
    }
    {
        // less room than compressBound, but enough for what it compresses
        // to: the one-pass end succeeds, as libzstd's (the goldens pin the
        // bytes)
        var s: stream.Stream = try .init(gpa, .{ .advanced = .{ .stable_out_buffer = true } });
        defer s.deinit();
        var in: stream.InBuffer = .{ .src = src };
        var o: stream.OutBuffer = .{ .dst = out[0..150_000] };
        try std.testing.expectEqual(@as(usize, 0), try s.compressStream2(&o, &in, .end));
        var d = try zstd.Decompressor.init(gpa, .{});
        defer d.deinit();
        const back = try gpa.alloc(u8, src.len);
        defer gpa.free(back);
        try std.testing.expectEqualSlices(u8, src, back[0..try d.decompress(back, out[0..o.pos])]);
    }
}

test "stable buffers leave the stream's own out of the workspace, as estimated" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 300_000);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 9 }, src);
    var sizes: [4]usize = undefined;
    for ([_]zstd.Advanced{ .{}, .{ .stable_in_buffer = true }, .{ .stable_out_buffer = true }, .{ .stable_in_buffer = true, .stable_out_buffer = true } }, 0..) |adv, i| {
        const opts: stream.Options = .{ .level = 3, .pledged_size = src.len, .advanced = adv };
        var s: stream.Stream = try .init(gpa, opts);
        defer s.deinit();
        var out: [1 << 19]u8 = undefined;
        var in: stream.InBuffer = .{ .src = src };
        var o: stream.OutBuffer = .{ .dst = &out };
        _ = try s.compressStream2(&o, &in, .flush);
        sizes[i] = s.workspaceSize();
        try std.testing.expectEqual(try zstd.estimateStreamSize(opts), sizes[i]);
    }
    // the input buffer holds the window (the pledged 300 000 bytes) and a
    // block; the output buffer a compressed block
    try std.testing.expect(sizes[0] - sizes[1] >= 300_000 + (1 << 17));
    try std.testing.expect(sizes[0] - sizes[2] >= 1 << 17);
    try std.testing.expect(sizes[3] < sizes[1] and sizes[3] < sizes[2]);
}

test "stable output: one byte less than the least room libzstd succeeds in is refused, as by libzstd" {
    // the golden rows at that least room (`stableOutBuffer=1,o<min>,...`
    // in `corpus.stream_cases`) pin the bytes; here the room one byte short
    const gpa = std.testing.allocator;
    var n: usize = 0;
    for (corpus.stream_cases) |sc| {
        if (!std.mem.startsWith(u8, sc.schedule, "stableOutBuffer=1,o")) continue;
        const rest = sc.schedule["stableOutBuffer=1,o".len..];
        const room = try std.fmt.parseInt(usize, rest[0..std.mem.indexOfScalar(u8, rest, ',').?], 10);
        var short: std.ArrayList(u8) = .empty;
        defer short.deinit(gpa);
        try short.print(gpa, "stableOutBuffer=1,o{d}{s}", .{ room - 1, rest[std.mem.indexOfScalar(u8, rest, ',').?..] });
        const src = try gpa.alloc(u8, findCase(sc.case).len);
        defer gpa.free(src);
        corpus.generate(findCase(sc.case), src);
        try std.testing.expectError(error.DstSizeTooSmall, run(gpa, src, sc.levels[0], true, short.items));
        // without the checksum: the least room libzstd succeeds in there
        // (zstream), where the last block's own check decides
        const no_checksum = [_]struct { []const u8, []const u8, usize }{
            .{ "zeros-300000", "c*,e0", 43 },
            .{ "seven", "c*,e0", 18 },
            .{ "empty", "c*,e0", 18 },
            .{ "words-16385", "c*,f0,e0", 3604 },
            .{ "csv-600000", "c*,e0", 207433 },
            .{ "mix-300000-9", "c*,e0", 84494 },
        };
        for (no_checksum) |nc| {
            if (!std.mem.eql(u8, sc.case, nc[0]) or !std.mem.endsWith(u8, sc.schedule, nc[1]) or std.mem.indexOf(u8, sc.schedule, "Size") != null) continue;
            if (std.mem.eql(u8, sc.case, "csv-600000") and sc.levels[0] != 1) continue;
            var at: std.ArrayList(u8) = .empty;
            defer at.deinit(gpa);
            try at.print(gpa, "stableOutBuffer=1,o{d},{s}", .{ nc[2], nc[1] });
            const ok = try run(gpa, src, sc.levels[0], false, at.items);
            gpa.free(ok.out);
            at.clearRetainingCapacity();
            try at.print(gpa, "stableOutBuffer=1,o{d},{s}", .{ nc[2] - 1, nc[1] });
            try std.testing.expectError(error.DstSizeTooSmall, run(gpa, src, sc.levels[0], false, at.items));
        }
        n += 1;
    }
    try std.testing.expectEqual(@as(usize, 13), n);
}

test "stable output: every room below the least libzstd succeeds in is refused (block splitter)" {
    // with the post-block splitter a block goes out as partitions, each
    // checked for its header's room where it lands; libzstd refuses each of
    // these 32 rooms (zstream, 2026-09-26)
    const gpa = std.testing.allocator;
    const c = findCase("mix-300000-9");
    const src = try gpa.alloc(u8, c.len);
    defer gpa.free(src);
    corpus.generate(c, src);
    var buf: [64]u8 = undefined;
    for (84494 - 32..84494) |room| {
        const sched = try std.fmt.bufPrint(&buf, "stableOutBuffer=1,o{d},c*,e0", .{room});
        try std.testing.expectError(error.DstSizeTooSmall, run(gpa, src, 19, true, sched));
    }
}

test "stable output: where libzstd would write past the end, the block is refused" {
    // libzstd's sub-blocks (targetCBlockSize) copy the Huffman table
    // description and the FSE tables unchecked: with this little room
    // AddressSanitizer reports libzstd writing past the output buffer
    // (zstream built with -fsanitize=address, 2026-09-26). This port
    // stops there, and the raw block does not fit either.
    const gpa = std.testing.allocator;
    for ([_][2][]const u8{
        .{ "mix-9000-5", "stableOutBuffer=1,targetCBlockSize=1340,o24,c*,e0" }, // the literals' table description
        .{ "two-symbols-16000-1", "stableOutBuffer=1,targetCBlockSize=1340,o47,c*,e0" }, // the sequences' FSE tables
    }) |cs| {
        const c = findCase(cs[0]);
        const src = try gpa.alloc(u8, c.len);
        defer gpa.free(src);
        corpus.generate(c, src);
        try std.testing.expectError(error.DstSizeTooSmall, run(gpa, src, 3, false, cs[1]));
    }
}

test "stable output: a raw block exactly the room left after its header" {
    // random-5000 without the checksum: 5009 bytes of room leave the one
    // block exactly its own size after the frame and block headers; its
    // compressed form runs out of room and it goes out raw, as libzstd's
    // (zstream: 5009 succeeds with the o5013 golden's bytes, 5008 fails)
    const gpa = std.testing.allocator;
    const c = findCase("random-5000");
    const src = try gpa.alloc(u8, c.len);
    defer gpa.free(src);
    corpus.generate(c, src);
    const ample = try run(gpa, src, 3, false, "stableOutBuffer=1,c*,e0");
    defer gpa.free(ample.out);
    const exact = try run(gpa, src, 3, false, "stableOutBuffer=1,o5009,c*,e0");
    defer gpa.free(exact.out);
    try std.testing.expectEqualSlices(u8, ample.out, exact.out);
    try std.testing.expectError(error.DstSizeTooSmall, run(gpa, src, 3, false, "stableOutBuffer=1,o5008,c*,e0"));
}

test "stable output: six bytes asked before each block, whatever the block needs" {
    // "seven" as 6 bytes flushed, then the last byte: the 1-byte block goes
    // out raw in 4 bytes, but libzstd asks 6 before trying any block (the
    // header, a least block, one byte) -- 21 bytes of room succeed with
    // exactly 6 left there, 20 fail at that check (zstream)
    const gpa = std.testing.allocator;
    const c = findCase("seven");
    const src = try gpa.alloc(u8, c.len);
    defer gpa.free(src);
    corpus.generate(c, src);
    const ample = try run(gpa, src, 3, false, "stableOutBuffer=1,c6,f0,e*");
    defer gpa.free(ample.out);
    const exact = try run(gpa, src, 3, false, "stableOutBuffer=1,o21,c6,f0,e*");
    defer gpa.free(exact.out);
    try std.testing.expectEqualSlices(u8, ample.out, exact.out);
    try std.testing.expectError(error.DstSizeTooSmall, run(gpa, src, 3, false, "stableOutBuffer=1,o20,c6,f0,e*"));
}

test "stable output: the epilogue's empty last block and checksum ask their own room" {
    // random-5000 flushed as one raw block, then ended: the empty last
    // block (3 bytes) and the checksum (4) come after it and fail on their
    // own checks one byte short (zstream: 5012 / 5016 succeed, 5011 fails
    // at "no room for epilogue", 5015 at "no room for checksum")
    const gpa = std.testing.allocator;
    const c = findCase("random-5000");
    const src = try gpa.alloc(u8, c.len);
    defer gpa.free(src);
    corpus.generate(c, src);
    for ([_]struct { bool, usize }{ .{ false, 5012 }, .{ true, 5016 } }) |cr| {
        const ample = try run(gpa, src, 3, cr[0], "stableOutBuffer=1,c*,f0,e0");
        defer gpa.free(ample.out);
        var buf: [64]u8 = undefined;
        const exact = try run(gpa, src, 3, cr[0], try std.fmt.bufPrint(&buf, "stableOutBuffer=1,o{d},c*,f0,e0", .{cr[1]}));
        defer gpa.free(exact.out);
        try std.testing.expectEqualSlices(u8, ample.out, exact.out);
        try std.testing.expectError(error.DstSizeTooSmall, run(gpa, src, 3, cr[0], try std.fmt.bufPrint(&buf, "stableOutBuffer=1,o{d},c*,f0,e0", .{cr[1] - 1})));
    }
}

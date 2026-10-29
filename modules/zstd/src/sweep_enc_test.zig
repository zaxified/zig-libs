// SPDX-License-Identifier: MIT
//! No-panic sweep of the encoder and dictionary side (wave GL, findings ZE-n):
//! caller-supplied sequences, stream buffers, dictionaries and low-level
//! trainer calls must end in an error (or a result), never a panic, whatever
//! the values. The `(sweep ZE-n)` tests pin one finding each; the `probe`
//! tests drive the same entry points with seeded random garbage.

const std = @import("std");
const zstd = @import("root.zig");
const dict_builder = @import("dict_builder.zig");
const stream = @import("stream.zig");

const gpa = std.testing.allocator;

fn text(buf: []u8, seed: u64) void {
    var prng: std.Random.DefaultPrng = .init(seed);
    const words = [_][]const u8{ "alpha ", "beta ", "gamma ", "delta,", "42;", "\n", "zstd " };
    var i: usize = 0;
    while (i < buf.len) {
        const w = words[prng.random().uintLessThan(usize, words.len)];
        const n = @min(w.len, buf.len - i);
        @memcpy(buf[i..][0..n], w[0..n]);
        i += n;
    }
}

// ---------------------------------------------------------------------------
// ZE-1: an offset of 2^32 - 3 wraps to offBase 0 in `finalizeOffBase`, and
// `updateRep` indexed the repeat offsets with `0 - 1`.

test "an offset that wraps to offBase 0 is refused, with repcode resolution (sweep ZE-1)" {
    var src: [40]u8 = undefined;
    text(&src, 1);
    var dst: [512]u8 = undefined;
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const explicit: zstd.Options = .{ .advanced = .{ .block_delimiters = .explicit, .repcode_resolution = .enable } };
    for ([_]u32{ 0xFFFF_FFFD, 0xFFFF_FFFC }) |off| for ([_]u32{ 0, 1 }) |ll| {
        // the first sequence has `ll` literals; the rest go into the delimiter
        const seqs = [_]zstd.Sequence{
            .{ .offset = off, .lit_length = ll, .match_length = 4 },
            .{ .offset = 0, .lit_length = @intCast(src.len - 4 - ll), .match_length = 0 },
        };
        const r = c.compressSequences(&dst, &seqs, &src, explicit);
        if (off == 0xFFFF_FFFD) {
            try std.testing.expectError(error.ExternalSequencesInvalid, r);
        } else if (r) |_| {} else |_| {}
        // no delimiters: the repeat offsets are always resolved
        const none: zstd.Options = .{ .advanced = .{ .block_delimiters = .none } };
        const flat = [_]zstd.Sequence{.{ .offset = off, .lit_length = ll, .match_length = 4 }};
        const r2 = c.compressSequences(&dst, &flat, &src, none);
        if (off == 0xFFFF_FFFD) {
            try std.testing.expectError(error.ExternalSequencesInvalid, r2);
        } else if (r2) |_| {} else |_| {}
    };
}

// ---------------------------------------------------------------------------
// ZE-2: `stable_in_buffer`, input reported consumed and later taken back:
// `input.pos -= stable_in_not_consumed` wrapped when the caller's `pos` was
// below it.

test "stable_in_buffer: a pos below the input held back is refused (sweep ZE-2)" {
    var data: [64]u8 = undefined;
    text(&data, 2);
    var out: [4096]u8 = undefined;
    for ([_]stream.EndDirective{ .end, .flush, .@"continue" }) |op| {
        var s: stream.Stream = try .init(gpa, .{ .advanced = .{ .stable_in_buffer = true } });
        defer s.deinit();
        var o: stream.OutBuffer = .{ .dst = &out };
        var in: stream.InBuffer = .{ .src = data[0..10] };
        _ = try s.compressStream2(&o, &in, .@"continue"); // held back, reported consumed
        try std.testing.expectEqual(@as(usize, 10), in.pos);
        // the same buffer, but not where the last call left it
        var again: stream.InBuffer = .{ .src = data[0..10], .pos = 3 };
        try std.testing.expectError(error.StabilityConditionNotRespected, s.compressStream2(&o, &again, op));
        // the stream is untouched: the contract-keeping call still works
        var ok: stream.InBuffer = .{ .src = data[0..20], .pos = 10 };
        var left = try s.compressStream2(&o, &ok, .end);
        while (left != 0) left = try s.compressStream2(&o, &ok, .end);
        const n = o.pos;
        var back: [64]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 20), try zstd.decompress(gpa, &back, out[0..n]));
        try std.testing.expectEqualSlices(u8, data[0..20], back[0..20]);
    }
}

// ---------------------------------------------------------------------------
// ZE-3: low-level trainer pieces, public, divided or indexed by their
// arguments.

test "computeEpochs and the d-mer map are total (sweep ZE-3)" {
    const db = dict_builder;
    // k = 0, passes = 0, no d-mers at all: libzstd divides by zero
    for ([_][4]u32{ .{ 1000, 0, 8, 1 }, .{ 1000, 100, 0, 1 }, .{ 1000, 100, 8, 0 }, .{ 0, 100, 8, 4 }, .{ 1000, 100, std.math.maxInt(u32), 1 }, .{ 1000, 0, 0, 0 } }) |a| {
        const e = db.computeEpochs(a[0], a[1], a[2], a[3]);
        try std.testing.expect(e.num >= 1);
        try std.testing.expect(@as(u64, e.size) * e.num <= a[1]);
    }
    // the sizes the maps are made for, and the one they are not
    try std.testing.expectEqual(@as(?u64, null), db.ActiveDmers.slots(0));
    try std.testing.expectError(error.ParameterOutOfBound, db.ActiveDmers.init(gpa, 0));
    try std.testing.expect(db.ActiveDmers.slots(1) != null);
}

test "selectDict refuses arguments that do not fit its samples (sweep ZE-3)" {
    var buf: [4096]u8 = undefined;
    text(&buf, 3);
    const sizes = [_]usize{ 1000, 1000, 1000, 1000, 96 };
    const offsets = [_]usize{ 0, 1000, 2000, 3000, 4000, 4096 };
    const samples: dict_builder.Samples = .{ .buffer = &buf, .sizes = &sizes };
    const p: dict_builder.SelectParams = .{};
    // content longer than the buffer it is the tail of
    try std.testing.expectError(error.DstSizeTooSmall, dict_builder.selectDict(gpa, buf[0..300], 301, samples, &offsets, 5, 5, 1.0, p));
    // more samples than there are
    try std.testing.expectError(error.SrcSizeWrong, dict_builder.selectDict(gpa, buf[0..300], 200, samples, &offsets, 6, 5, 1.0, p));
    try std.testing.expectError(error.SrcSizeWrong, dict_builder.selectDict(gpa, buf[0..300], 200, samples, &offsets, 5, 6, 0.75, p));
    // offsets that are not the samples' (too few; past the buffer)
    try std.testing.expectError(error.SrcSizeWrong, dict_builder.selectDict(gpa, buf[0..300], 200, samples, offsets[0..5], 5, 5, 1.0, p));
    const bad = [_]usize{ 0, 1000, 2000, 3000, 4001, 4097 };
    try std.testing.expectError(error.SrcSizeWrong, dict_builder.selectDict(gpa, buf[0..300], 200, samples, &bad, 5, 5, 1.0, p));
    // and the well-formed call still selects
    if (try dict_builder.selectDict(gpa, buf[0..600], 300, samples, &offsets, 5, 5, 1.0, p)) |sel| dict_builder.freeSelection(gpa, sel);
}

// ---------------------------------------------------------------------------
// ZE-4: a `Compressor` copied onto itself.

test "copyFrom of the context itself is refused (sweep ZE-4)" {
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    try c.begin(.{ .level = .{ .level = 3 } });
    try std.testing.expectError(error.StageWrong, c.copyFrom(&c, 100));
}

// ---------------------------------------------------------------------------
// ZE-5: a `StreamWriter` with no buffer of its own is an unbuffered writer, and
// so is a `FrameWriter` (it makes its own buffer).

test "StreamWriter and FrameWriter: an empty buffer works (sweep ZE-5)" {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var empty: [0]u8 = .{};
    var scratch: [256]u8 = undefined;
    var sw: zstd.StreamWriter = try .initScratch(gpa, &out.writer, &empty, &scratch, .{});
    defer sw.deinit();
    var src: [3000]u8 = undefined;
    text(&src, 5);
    try sw.writer.writeAll(&src);
    try sw.writer.writeAll(src[0..17]);
    try sw.finish();
    var back: [4000]u8 = undefined;
    const n = try zstd.decompress(gpa, &back, out.written());
    try std.testing.expectEqual(@as(usize, 3017), n);
    try std.testing.expectEqualSlices(u8, &src, back[0..3000]);
}

// ---------------------------------------------------------------------------
// probes: seeded garbage through the public entry points

fn randLen(r: std.Random) u32 {
    return switch (r.uintLessThan(u8, 9)) {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => r.uintLessThan(u32, 40),
        4 => r.uintLessThan(u32, 600),
        5 => 0xFFFF_FFFF,
        6 => 0xFFFF_FFF0 +% r.uintLessThan(u32, 16),
        7 => 65536 + r.uintLessThan(u32, 4),
        else => 131072 + r.uintLessThan(u32, 4),
    };
}

fn randOff(r: std.Random) u32 {
    return switch (r.uintLessThan(u8, 10)) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => r.uintLessThan(u32, 3000),
        6 => 0xFFFF_FFFD,
        7 => 0xFFFF_FFFE,
        8 => 0xFFFF_FFFF,
        else => r.int(u32),
    };
}

test "probe: random sequences never crash the sequence API (sweep ZE-1)" {
    var src: [3000]u8 = undefined;
    text(&src, 7);
    var dst: [8192]u8 = undefined;
    var lits: [4096]u8 = undefined;
    text(&lits, 8);
    var seqs: [40]zstd.Sequence = undefined;
    var prng: std.Random.DefaultPrng = .init(0x5eed0001);
    const r = prng.random();
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const modes = [_]zstd.Advanced{
        .{ .block_delimiters = .explicit },
        .{ .block_delimiters = .explicit, .repcode_resolution = .enable },
        .{ .block_delimiters = .explicit, .validate_sequences = true, .repcode_resolution = .enable },
        .{ .block_delimiters = .none },
        .{ .block_delimiters = .none, .validate_sequences = true, .max_block_size = 1024 },
        .{ .block_delimiters = .none, .min_match = 5, .max_block_size = 1024 },
    };
    for (0..6000) |it| {
        const adv = modes[it % modes.len];
        const level: i32 = switch (it % 3) {
            0 => 1,
            1 => 12,
            else => 19,
        };
        const n = r.uintLessThan(usize, seqs.len);
        const well_formed = r.boolean();
        var total: usize = 0;
        for (seqs[0..n]) |*s| {
            if (well_formed) {
                const ll: u32 = r.uintLessThan(u32, 60);
                const ml: u32 = 3 + r.uintLessThan(u32, 80);
                s.* = .{ .offset = randOff(r), .lit_length = ll, .match_length = ml };
                total += ll + ml;
                if (total > src.len) {
                    s.* = .{ .offset = 0, .lit_length = 0, .match_length = 0 };
                }
            } else {
                s.* = .{ .offset = randOff(r), .lit_length = randLen(r), .match_length = randLen(r) };
                if (r.uintLessThan(u8, 6) == 0) s.offset = 0;
                if (r.uintLessThan(u8, 8) == 0) s.match_length = 0;
            }
            if (adv.block_delimiters == .explicit and well_formed and r.uintLessThan(u8, 5) == 0) s.* = .{ .offset = 0, .lit_length = r.uintLessThan(u32, 50), .match_length = 0 };
        }
        // a closing delimiter most of the time
        const m: usize = if (n < seqs.len and r.uintLessThan(u8, 4) != 0) blk: {
            seqs[n] = .{ .offset = 0, .lit_length = if (well_formed) @intCast(src.len -| total) else randLen(r), .match_length = 0 };
            break :blk n + 1;
        } else n;
        const room: usize = switch (r.uintLessThan(u8, 4)) {
            0 => r.uintLessThan(usize, 40),
            1 => r.uintLessThan(usize, 600),
            else => dst.len,
        };
        const opts: zstd.Options = .{ .level = level, .advanced = adv };
        _ = c.compressSequences(dst[0..room], seqs[0..m], src[0 .. 1 + r.uintLessThan(usize, src.len)], opts) catch {};
        var eadv = adv;
        eadv.block_delimiters = .explicit;
        const lit_n = r.uintLessThan(usize, lits.len);
        _ = c.compressSequencesAndLiterals(dst[0..room], seqs[0..m], lits[0..lit_n], r.uintLessThan(usize, 5000), .{ .level = level, .advanced = eadv }) catch {};
    }
}

test "probe: random Stream calls never crash, stable buffers included (sweep ZE-2)" {
    var data: [30000]u8 = undefined;
    text(&data, 9);
    var obuf: [40000]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0x5eed0002);
    const r = prng.random();
    for (0..1500) |it| {
        const stable_in = it % 3 == 0;
        const stable_out = it % 5 == 0;
        const level: i32 = switch (it % 4) {
            0 => 1,
            1 => 3,
            2 => 9,
            else => 19,
        };
        const pledged: ?u64 = if (it % 7 == 0) r.uintLessThan(u64, 40000) else null;
        var s: stream.Stream = stream.Stream.init(gpa, .{ .level = level, .pledged_size = pledged, .checksum = it % 2 == 0, .advanced = .{ .stable_in_buffer = stable_in, .stable_out_buffer = stable_out } }) catch continue;
        defer s.deinit();
        var src_len: usize = r.uintLessThan(usize, 200);
        var pos: usize = 0;
        const base: usize = if (r.uintLessThan(u8, 8) == 0) r.uintLessThan(usize, 100) else 0;
        for (0..14) |_| {
            const op: stream.EndDirective = switch (r.uintLessThan(u8, 4)) {
                0 => .flush,
                1 => .end,
                else => .@"continue",
            };
            // mostly the contract: the same start, only longer, pos where it was left
            if (r.uintLessThan(u8, 5) != 0) src_len = @min(data.len - base, src_len + r.uintLessThan(usize, 9000));
            var in: stream.InBuffer = .{ .src = data[base .. base + src_len], .pos = pos };
            if (r.uintLessThan(u8, 6) == 0) in.pos = r.uintLessThan(usize, src_len + 2);
            if (r.uintLessThan(u8, 9) == 0) in.src = data[0..r.uintLessThan(usize, data.len)];
            if (in.pos > in.src.len and r.uintLessThan(u8, 3) != 0) in.pos = in.src.len;
            var out: stream.OutBuffer = .{ .dst = obuf[0..r.uintLessThan(usize, obuf.len)] };
            if (r.uintLessThan(u8, 8) == 0) out.pos = r.uintLessThan(usize, out.dst.len + 2);
            const left = s.compressStream2(&out, &in, op) catch break;
            pos = in.pos;
            if (op == .end and left == 0) break;
        }
    }
}

fn randCParams(r: std.Random) zstd.CParams {
    return .{
        .window_log = 8 + r.uintLessThan(u32, 14),
        .chain_log = 5 + r.uintLessThan(u32, 14),
        .hash_log = 5 + r.uintLessThan(u32, 14),
        .search_log = r.uintLessThan(u32, 8),
        .min_match = 2 + r.uintLessThan(u32, 7),
        .target_length = r.uintLessThan(u32, 400),
        .strategy = @fromBackingInt(@intCast(1 + r.uintLessThan(u32, 9))),
    };
}

test "probe: random buffer-less call orders never crash (sweep ZE-4)" {
    var data: [60000]u8 = undefined;
    text(&data, 11);
    var dict_src: [3000]u8 = undefined;
    text(&dict_src, 12);
    var cd = try zstd.CDict.init(gpa, &dict_src, 5);
    defer cd.deinit();
    var dst: [70000]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0x5eed0003);
    const r = prng.random();
    var a: zstd.Compressor = .init(gpa);
    defer a.deinit();
    var b: zstd.Compressor = .init(gpa);
    defer b.deinit();
    for (0..2500) |_| {
        const c = if (r.boolean()) &a else &b;
        var at: usize = 0;
        for (0..6) |_| {
            switch (r.uintLessThan(u8, 8)) {
                0 => c.begin(.{ .level = .{ .level = r.intRangeAtMost(i32, -3, 22), .dict = if (r.boolean()) dict_src[0..r.uintLessThan(usize, dict_src.len)] else &.{} } }) catch {},
                1 => c.begin(.{ .advanced = .{ .cparams = randCParams(r), .dict = if (r.boolean()) dict_src[0..r.uintLessThan(usize, 600)] else &.{}, .pledged_size = if (r.boolean()) r.uintLessThan(u64, 70000) else null } }) catch {},
                2 => c.begin(.{ .cdict = .{ .cdict = &cd, .pledged_size = if (r.boolean()) r.uintLessThan(u64, 70000) else null } }) catch {},
                3 => c.copyFrom(if (r.boolean()) &a else &b, if (r.boolean()) r.uintLessThan(u64, 70000) else null) catch {},
                4, 5 => {
                    const n = @min(r.uintLessThan(usize, 12000), data.len - at);
                    _ = c.compressContinue(dst[0..r.uintLessThan(usize, dst.len)], data[at..][0..n]) catch {};
                    at += n;
                },
                6 => {
                    const n = @min(r.uintLessThan(usize, 12000), data.len - at);
                    _ = c.compressEnd(dst[0..r.uintLessThan(usize, dst.len)], data[at..][0..n]) catch {};
                    at += n;
                },
                else => _ = c.compressUsingDict(dst[0..r.uintLessThan(usize, dst.len)], data[0..r.uintLessThan(usize, 5000)], dict_src[0..r.uintLessThan(usize, 1000)], r.intRangeAtMost(i32, -3, 22)) catch {},
            }
        }
    }
}

test "probe: corrupted full dictionaries never crash the compressor (sweep ZE-6)" {
    var buf: [60000]u8 = undefined;
    text(&buf, 13);
    var sizes: [100]usize = undefined;
    for (&sizes, 0..) |*s, i| s.* = 400 + (i * 37) % 300;
    var dict_buf: [4096]u8 = undefined;
    const dn = try dict_builder.train(gpa, &dict_buf, .{ .buffer = &buf, .sizes = &sizes });
    try std.testing.expect(dn >= 256);
    var input: [3000]u8 = undefined;
    text(&input, 14);
    var dst: [8192]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0x5eed0004);
    const r = prng.random();
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    for (0..600) |it| {
        var d: [4096]u8 = undefined;
        @memcpy(d[0..dn], dict_buf[0..dn]);
        var len = dn;
        for (0..1 + r.uintLessThan(usize, 4)) |_| {
            const at = r.uintLessThan(usize, @min(len, 420));
            d[at] = switch (r.uintLessThan(u8, 4)) {
                0 => 0,
                1 => 0xFF,
                2 => d[at] +% 1,
                else => r.int(u8),
            };
        }
        if (r.uintLessThan(u8, 4) == 0) len = r.uintLessThan(usize, dn);
        const level: i32 = switch (it % 3) {
            0 => 1,
            1 => 9,
            else => 19,
        };
        const kind: zstd.DictContentType = if (it % 2 == 0) .full else .auto;
        if (zstd.CDict.initAdvanced(gpa, d[0..len], .{ .level = level, .content_type = kind })) |made| {
            var cd = made;
            defer cd.deinit();
            _ = c.compressUsingCDict(&dst, input[0 .. 1 + r.uintLessThan(usize, input.len)], &cd, .{}) catch {};
        } else |_| {}
        _ = zstd.compress(gpa, &dst, input[0 .. 1 + r.uintLessThan(usize, input.len)], .{ .level = level, .dictionary = .{ .raw = .{ .bytes = d[0..len], .content_type = kind } } }) catch {};
        _ = c.compressUsingDict(&dst, input[0..500], d[0..len], level) catch {};
    }
}

test "probe: the trainers take degenerate samples (sweep ZE-3)" {
    var buf: [20000]u8 = undefined;
    text(&buf, 15);
    var dict: [1024]u8 = undefined;
    const cases = [_][]const usize{
        &.{}, // none
        &.{ 0, 0, 0, 0, 0, 0 }, // all empty
        &.{ 100, 0, 100, 0, 100, 0, 100, 0, 100, 0 },
        &.{ 19000, 1, 1, 1, 1, 1 },
        &.{ 4, 4, 4, 4, 4, 4, 4, 4 },
        &.{ 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000 },
    };
    for (cases) |sizes| {
        const samples: dict_builder.Samples = .{ .buffer = &buf, .sizes = sizes };
        _ = dict_builder.train(gpa, &dict, samples) catch {};
        for ([_]u32{ 8, 50, 1000, 1024 }) |k| {
            _ = dict_builder.trainCover(gpa, &dict, samples, .{ .k = k, .d = 8 }) catch {};
            _ = dict_builder.trainFastCover(gpa, &dict, samples, .{ .k = k, .d = 6 }) catch {};
        }
        _ = dict_builder.optimizeCover(gpa, &dict, samples, .{ .steps = 2 }) catch {};
        _ = dict_builder.optimizeFastCover(gpa, &dict, samples, .{ .steps = 2, .nb_threads = 3 }) catch {};
    }
    // sizes past the buffer, and parameters at their edges
    _ = dict_builder.train(gpa, &dict, .{ .buffer = buf[0..100], .sizes = &.{ 5000, 5000, 5000, 5000, 5000 } }) catch {};
    _ = dict_builder.trainCover(gpa, &dict, .{ .buffer = &buf, .sizes = &.{ 4000, 4000, 4000, 4000, 4000 } }, .{ .k = std.math.maxInt(u32), .d = 8 }) catch {};
    _ = dict_builder.optimizeCover(gpa, &dict, .{ .buffer = &buf, .sizes = &.{ 4000, 4000, 4000, 4000, 4000 } }, .{ .k = std.math.maxInt(u32), .d = std.math.maxInt(u32) }) catch {};
    _ = dict_builder.optimizeFastCover(gpa, &dict, .{ .buffer = &buf, .sizes = &.{ 4000, 4000, 4000, 4000, 4000 } }, .{ .steps = std.math.maxInt(u32), .nb_threads = 2, .split_point = 0.5, .k = 100, .d = 8 }) catch {};
}

test "FrameWriter with an empty buffer makes its own (sweep ZE-5)" {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var empty: [0]u8 = .{};
    var fw: zstd.FrameWriter = try .init(gpa, &out.writer, &empty, .{});
    defer fw.deinit();
    var src: [5000]u8 = undefined;
    text(&src, 6);
    try fw.writer.writeAll(&src);
    try fw.finish();
    var back: [5000]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5000), try zstd.decompress(gpa, &back, out.written()));
    try std.testing.expectEqualSlices(u8, &src, &back);
}

test "optimizer threads are capped; the dictionary offset codes are computed wide; huge literal runs are refused (sweep ZE-7)" {
    const db = dict_builder;
    try std.testing.expectEqual(@as(usize, 1), db.workerThreads(0, 1951));
    try std.testing.expectEqual(@as(usize, 3), db.workerThreads(3, 1951));
    try std.testing.expectEqual(@as(usize, 2), db.workerThreads(100, 2));
    try std.testing.expectEqual(@as(usize, db.max_threads), db.workerThreads(std.math.maxInt(u32), 1951));
    // the same dictionary, whatever the count asked for
    var buf: [20000]u8 = undefined;
    text(&buf, 16);
    const sizes = [_]usize{ 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000 };
    var d1: [512]u8 = undefined;
    var d2: [512]u8 = undefined;
    const a = try db.optimizeFastCover(gpa, &d1, .{ .buffer = &buf, .sizes = &sizes }, .{ .steps = 2, .nb_threads = 1 });
    const b = try db.optimizeFastCover(gpa, &d2, .{ .buffer = &buf, .sizes = &sizes }, .{ .steps = 2, .nb_threads = std.math.maxInt(u32) });
    try std.testing.expectEqualSlices(u8, d1[0..a.size], d2[0..b.size]);

    const zd = dict_builder.zdict;
    try std.testing.expectEqual(@as(?u32, 17), zd.offcodeMaxFor(1000));
    try std.testing.expectEqual(@as(?u32, 30), zd.offcodeMaxFor((1 << 31) - (128 << 10) - 1));
    try std.testing.expectEqual(@as(?u32, null), zd.offcodeMaxFor((1 << 31) - (128 << 10)));
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(?u32, null), zd.offcodeMaxFor(1 << 32));
        try std.testing.expectEqual(@as(?u32, null), zd.offcodeMaxFor((1 << 32) - (128 << 10)));
    }

    // 200 000 literals in one block, into a dst too small for them
    const lits = try gpa.alloc(u8, 200_000);
    defer gpa.free(lits);
    text(lits, 17);
    const seqs = [_]zstd.Sequence{.{ .offset = 0, .lit_length = 200_000, .match_length = 0 }};
    var dst: [100]u8 = undefined;
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    try std.testing.expectError(error.CannotProduceUncompressedBlock, c.compressSequencesAndLiterals(&dst, &seqs, lits, lits.len, .{ .advanced = .{ .block_delimiters = .explicit } }));
}

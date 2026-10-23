// SPDX-License-Identifier: MIT

//! Fuzz harnesses, generic over their source of choices (`fn(comptime S, *S,
//! gpa)`): `testing.fuzz` feeds them a `Smith`, the deterministic driver
//! (`BZIP2_FUZZ=<runs>[,<first seed>]`, testkit's fuzz driver) a PRNG.
//!
//!   decode     arbitrary bytes, valid streams mutated (anywhere / past the
//!              block header), synthetic blocks with random but well-formed
//!              tables, streams glued to junk; read whole and through a
//!              chunked, failing reader with a failing allocator. Invariants:
//!              no panic, no leak, no hang; the whole-buffer and reader
//!              verdicts agree; an accepted stream re-encodes and decodes to
//!              the same bytes.
//!   roundtrip  random structured input, every level, work factors, randomised
//!              blocks, odd write sizes, failing sinks: decode(encode(x)) == x
//!              and every write pattern gives the same bytes.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const bz = @import("root.zig");
const huffman = @import("huffman.zig");

var reach: [reach_labels.len]usize = @splat(0);

fn labelIndex(comptime label: []const u8) ?usize {
    for (reach_labels, 0..) |l, i| if (std.mem.eql(u8, l, label)) return i;
    return null;
}

fn mark(comptime label: []const u8) void {
    fuzz_driver.hit(label);
    if (comptime labelIndex(label)) |i| reach[i] += 1;
}

fn markError(e: anyerror) void {
    inline for (@typeInfo(bz.DecodeError).error_set.error_names.?) |n| {
        if (std.mem.eql(u8, n, @errorName(e))) {
            mark("err_" ++ n);
            return;
        }
    }
}

// ── bit-level stream builder ──────────────────────────────────────────────

const Bits = struct {
    list: std.ArrayList(u8) = .empty,
    acc: u32 = 0,
    n: u5 = 0,

    fn put(b: *Bits, gpa: std.mem.Allocator, bits: u6, v: u32) !void {
        var i: u6 = bits;
        while (i > 0) {
            i -= 1;
            b.acc = (b.acc << 1) | ((v >> @intCast(i)) & 1);
            b.n += 1;
            if (b.n == 8) {
                try b.list.append(gpa, @truncate(b.acc));
                b.acc = 0;
                b.n = 0;
            }
        }
    }

    fn flush(b: *Bits, gpa: std.mem.Allocator) !void {
        while (b.n != 0) try b.put(gpa, 1, 0);
    }
};

fn rangeU32(src: anytype, lo: u32, hi: u32) u32 {
    return src.valueRangeAtMost(u32, lo, hi);
}

/// A block-shaped stream: valid framing and well-formed (prefix-complete)
/// tables with random content, then random payload bits, so the decoder
/// walks the Huffman, MTF and run machinery on input a mutation would
/// almost never reach.
fn synthStream(comptime S: type, src: *S, gpa: std.mem.Allocator, b: *Bits) !void {
    try b.put(gpa, 8, 'B');
    try b.put(gpa, 8, 'Z');
    try b.put(gpa, 8, 'h');
    try b.put(gpa, 8, '0' + rangeU32(src, if (src.valueRangeAtMost(u8, 0, 31) == 0) 0 else 1, 9));
    try b.put(gpa, 24, 0x314159);
    try b.put(gpa, 24, 0x265359);
    try b.put(gpa, 32, src.value(u32));
    try b.put(gpa, 1, @intFromBool(src.valueRangeAtMost(u8, 0, 7) == 0));
    try b.put(gpa, 24, if (src.valueRangeAtMost(u8, 0, 15) == 0) src.value(u24) else rangeU32(src, 0, 60));

    // The symbol map.
    var in16: u32 = if (src.valueRangeAtMost(u8, 0, 31) == 0) 0 else rangeU32(src, 1, 0xffff);
    if (src.valueRangeAtMost(u8, 0, 3) != 0) in16 &= rangeU32(src, 1, 0xffff) | 1;
    try b.put(gpa, 16, in16);
    var n_in_use: usize = 0;
    for (0..16) |i| {
        if ((in16 >> @intCast(15 - i)) & 1 == 0) continue;
        const m: u32 = if (src.valueRangeAtMost(u8, 0, 1) == 0) rangeU32(src, 1, 0xffff) else (@as(u32, 1) << @intCast(src.valueRangeAtMost(u8, 0, 15)));
        try b.put(gpa, 16, m);
        n_in_use += @popCount(m);
    }
    const alpha: usize = @max(n_in_use, 1) + 2;

    // Selectors.
    var n_groups: u32 = rangeU32(src, 2, 6);
    if (src.valueRangeAtMost(u8, 0, 31) == 0) n_groups = src.valueRangeAtMost(u8, 0, 7);
    try b.put(gpa, 3, n_groups);
    const n_sel: u32 = if (src.valueRangeAtMost(u8, 0, 63) == 0) src.value(u15) else rangeU32(src, 1, 24);
    try b.put(gpa, 15, n_sel);
    for (0..@min(n_sel, 64)) |_| {
        var j = if (n_groups > 0) rangeU32(src, 0, n_groups - 1) else 0;
        if (src.valueRangeAtMost(u8, 0, 63) == 0) j += 3;
        for (0..j) |_| try b.put(gpa, 1, 1);
        try b.put(gpa, 1, 0);
    }

    // Tables from random frequencies, EOB and the run symbols favoured.
    var len: [huffman.max_alpha_size]u8 = undefined;
    var freq: [huffman.max_alpha_size]u32 = undefined;
    for (0..@max(n_groups, 1)) |_| {
        for (freq[0..alpha], 0..) |*f, i| {
            f.* = if (i == alpha - 1 or i < 2) rangeU32(src, 1, 400) else src.valueRangeAtMost(u16, 0, 60);
        }
        huffman.makeCodeLengths(&len, &freq, alpha, 17);
        if (src.valueRangeAtMost(u8, 0, 31) == 0) len[src.valueRangeAtMost(u16, 0, @intCast(alpha - 1))] = src.valueRangeAtMost(u8, 0, 24);
        var curr: u32 = len[0];
        try b.put(gpa, 5, curr);
        for (len[0..alpha]) |target| {
            while (curr < target) : (curr += 1) try b.put(gpa, 2, 2);
            while (curr > target) : (curr -= 1) try b.put(gpa, 2, 3);
            try b.put(gpa, 1, 0);
        }
    }

    // Payload.
    var pay: [160]u8 = undefined;
    const k = src.slice(&pay);
    for (pay[0..k]) |x| try b.put(gpa, 8, x);
    try b.flush(gpa);
}

fn drawStructured(comptime S: type, src: *S, buf: []u8) usize {
    const n = buf.len;
    switch (src.valueRangeAtMost(u8, 0, 6)) {
        0 => {
            const len = src.slice(buf);
            return len;
        },
        1 => {
            // runs
            var i: usize = 0;
            while (i < n) {
                const r = @min(src.valueRangeAtMost(u16, 1, 300), n - i);
                @memset(buf[i..][0..r], src.value(u8));
                i += r;
            }
            return n;
        },
        2 => {
            // small alphabet
            const k = src.valueRangeAtMost(u8, 1, 4);
            for (buf) |*c| c.* = 'a' + src.valueRangeAtMost(u8, 0, k);
            return n;
        },
        3 => {
            const p = src.valueRangeAtMost(u8, 1, 12);
            var seed: [12]u8 = undefined;
            src.bytes(&seed);
            for (buf, 0..) |*c, i| c.* = seed[i % p];
            return n;
        },
        4 => {
            @memset(buf, src.value(u8));
            return n;
        },
        else => {
            const words = [_][]const u8{ "bzip2 ", "block ", "sort ", "the ", "of ", "\n", "zero " };
            var i: usize = 0;
            while (i < n) {
                const w = words[src.valueRangeAtMost(u8, 0, words.len - 1)];
                const k = @min(w.len, n - i);
                @memcpy(buf[i..][0..k], w[0..k]);
                i += k;
            }
            return n;
        },
    }
}

// ── decode harness ────────────────────────────────────────────────────────

const cap: u64 = 4 << 20;

fn decodeStream(comptime S: type, src: *S, gpa: std.mem.Allocator, stream: []const u8) !void {
    const opts: bz.DecodeOptions = .{
        .max_output = cap,
        .multi_stream = src.valueRangeAtMost(u8, 0, 7) != 0,
        .ignore_trailing_garbage = src.valueRangeAtMost(u8, 0, 3) == 0,
    };
    const whole = bz.decompress(gpa, stream, opts);

    // The same stream through a reader that breaks it into chunks and may
    // fail, with an allocator that may fail.
    var plan = testkit.fuzz.FaultPlan.draw(src, stream.len);
    if (src.valueRangeAtMost(u8, 0, 1) == 0) plan.fail_at = null;
    var rbuf: [16]u8 = undefined;
    var cr = testkit.fuzz.ChunkedReader.init(stream, plan, &rbuf);
    var fa = testkit.fuzz.failingAllocator(src, gpa, 24);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const piece = piece: {
        var dr = bz.DecompressReader.init(fa.allocator(), &cr.interface, &.{}, opts) catch |e| {
            std.debug.assert(e == error.OutOfMemory);
            mark("oom_init");
            break :piece @as(?anyerror, e);
        };
        defer dr.deinit();
        _ = dr.reader.streamRemaining(&out.writer) catch |e| {
            if (e == error.WriteFailed) break :piece @as(?anyerror, error.OutOfMemory);
            break :piece @as(?anyerror, dr.err orelse return error.ReadFailedWithoutCause);
        };
        break :piece null;
    };

    if (piece) |pe| {
        if (pe == error.OutOfMemory) mark("fault_oom");
        if (pe == error.ReadFailed) mark("fault_read");
    }
    if (whole) |w| {
        defer gpa.free(w);
        if (w.len == 0) mark("ok_empty") else mark("ok_data");
        if (piece) |e| {
            // Only an injected fault may make the reader differ.
            if (e != error.ReadFailed and e != error.OutOfMemory) return error.ReaderDisagrees;
            if (plan.fail_at == null and fa.fail_index == std.math.maxInt(usize)) return error.ReaderDisagrees;
            mark("fault_on_good");
        } else try testing.expectEqualSlices(u8, w, out.written());
        // An accepted stream's output re-encodes and decodes to itself.
        if (w.len != 0 and w.len <= 6000) {
            const z = try bz.compress(gpa, w, .{ .level = 1 });
            defer gpa.free(z);
            const back = try bz.decompress(gpa, z, .{});
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, w, back);
            mark("reencoded");
        }
    } else |e| {
        markError(e);
        if (piece) |pe| {
            if (pe != e and pe != error.ReadFailed and pe != error.OutOfMemory) {
                std.debug.print("whole: {t}, reader: {t}\n", .{ e, pe });
                return error.ReaderDisagrees;
            }
        } else return error.ReaderAcceptedWhatWholeRefused;
    }
}

pub fn decodeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var data: [3000]u8 = undefined;
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);

    // First draw from a full-range u64: a ranged first draw returns its minimum for
    // almost every --fuzz seed (check-fuzz-reach R1), pinning the mode to 0.
    const mode: u8 = @intCast(src.value(u64) % 6);
    switch (mode) {
        0 => {
            mark("mode_raw");
            var raw: [300]u8 = undefined;
            const raw_len = src.slice(&raw);
            if (raw_len >= 4 and src.valueRangeAtMost(u8, 0, 1) == 0) @memcpy(raw[0..3], "BZh");
            try stream.appendSlice(gpa, raw[0..raw_len]);
        },
        1, 2, 5 => {
            const n = drawStructured(S, src, data[0..@as(usize, src.valueRangeAtMost(u16, 0, 3000))]);
            const z = try bz.compress(gpa, data[0..n], .{ .level = if (src.valueRangeAtMost(u8, 0, 7) == 0) src.valueRangeAtMost(u4, 1, 9) else 1 });
            defer gpa.free(z);
            try stream.appendSlice(gpa, z);
            if (mode == 5) {
                mark("mode_glued");
                switch (src.valueRangeAtMost(u8, 0, 4)) {
                    0 => try stream.appendSlice(gpa, z),
                    1 => try stream.appendSlice(gpa, "junk"),
                    2 => try stream.appendSlice(gpa, "BZh9"),
                    3 => try stream.appendSlice(gpa, z[0..@min(z.len, @as(usize, src.valueRangeAtMost(u8, 0, 30)))]),
                    else => try stream.appendNTimes(gpa, 0, 8),
                }
            } else {
                const deep = mode == 2;
                if (deep) mark("mode_deep") else mark("mode_mutated");
                const first: usize = if (deep) @min(14, stream.items.len) else 0;
                for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
                    if (stream.items.len <= first) break;
                    const room = stream.items.len - first;
                    const at = first + @as(usize, @intCast(src.value(u64) % room));
                    switch (src.valueRangeAtMost(u8, 0, 3)) {
                        0 => stream.items[at] ^= @as(u8, 1) << src.valueRangeAtMost(u3, 0, 7),
                        1 => stream.items[at] = src.value(u8),
                        2 => stream.shrinkRetainingCapacity(at),
                        else => try stream.insert(gpa, at, src.value(u8)),
                    }
                }
            }
        },
        3, 4 => {
            mark("mode_synth");
            var b: Bits = .{};
            defer b.list.deinit(gpa);
            try synthStream(S, src, gpa, &b);
            // Sometimes the trailer, so the stream can end.
            if (src.valueRangeAtMost(u8, 0, 3) == 0) {
                for ([_]u8{ 0x17, 0x72, 0x45, 0x38, 0x50, 0x90 }) |x| try b.put(gpa, 8, x);
                try b.put(gpa, 32, 0);
                try b.flush(gpa);
            }
            try stream.appendSlice(gpa, b.list.items);
        },
        else => unreachable,
    }
    try decodeStream(S, src, gpa, stream.items);
}

// ── round-trip harness ────────────────────────────────────────────────────

pub fn roundtripHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var data: [30_000]u8 = undefined;
    // Full-range first draw, see decodeHarness (check-fuzz-reach R1).
    const want_len: usize = switch (src.value(u64) % 8) {
        0 => 0,
        1...5 => src.valueRangeAtMost(u16, 1, 2000),
        6 => src.valueRangeAtMost(u16, 9990, 10_010),
        else => src.valueRangeAtMost(u16, 10_000, 30_000),
    };
    const n = drawStructured(S, src, data[0..want_len]);
    const input = data[0..n];
    if (n == 0) mark("rt_empty");
    if (n >= 10_000) mark("rt_mainsort");

    const level: u4 = if (src.valueRangeAtMost(u8, 0, 7) == 0) src.valueRangeAtMost(u4, 1, 9) else 1;
    const wf: u8 = switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => 1,
        1 => 100,
        2 => 0,
        else => 30,
    };
    const opts: bz.EncodeOptions = .{ .level = level, .work_factor = wf };
    const z = try bz.compress(gpa, input, opts);
    defer gpa.free(z);
    const back = try bz.decompress(gpa, z, .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, input, back);
    mark("rt_ok");

    // Another write pattern: the same bytes.
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var buf: [64]u8 = undefined;
        var sw = try bz.StreamWriter.init(gpa, &out.writer, buf[0..src.valueRangeAtMost(u8, 0, 64)], opts);
        defer sw.deinit();
        var at: usize = 0;
        while (at < n) {
            const k = @min(@as(usize, src.valueRangeAtMost(u16, 1, 5000)), n - at);
            try sw.writer.writeAll(input[at..][0..k]);
            at += k;
        }
        try sw.finish();
        try testing.expectEqualSlices(u8, z, out.written());
        mark("rt_pieces");
    }

    // Randomised blocks read back.
    if (src.valueRangeAtMost(u8, 0, 3) == 0) {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var enc = try bz.Encoder.init(gpa, &out.writer, opts);
        defer enc.deinit();
        enc.randomise = true;
        try enc.write(input);
        try enc.finish();
        const rb = try bz.decompress(gpa, out.written(), .{});
        defer gpa.free(rb);
        try testing.expectEqualSlices(u8, input, rb);
        mark("rt_randomised");
    }

    // A sink that fails: an error, never a panic, never a leak.
    {
        var plan = testkit.fuzz.FaultPlan.draw(src, z.len);
        plan.fail_at = @as(usize, src.valueRangeAtMost(u32, 0, @intCast(z.len)));
        var sink: [40_000]u8 = undefined;
        var cw = testkit.fuzz.ChunkedWriter.init(&sink, plan, &.{});
        var enc = try bz.Encoder.init(gpa, &cw.interface, opts);
        defer enc.deinit();
        var failed = false;
        enc.write(input) catch |e| {
            try testing.expect(e == error.WriteFailed);
            failed = true;
        };
        if (!failed) enc.finish() catch |e| {
            try testing.expect(e == error.WriteFailed);
            failed = true;
        };
        if (failed) mark("rt_sink_failed");
    }
}

// ── drivers ──────────────────────────────────────────────────────────────

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    try decodeHarness(std.testing.Smith, smith, testing.allocator);
}

fn fuzzRoundtrip(_: void, smith: *std.testing.Smith) !void {
    try roundtripHarness(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: the decoder never panics, leaks or hangs on arbitrary and mutated streams" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

test "fuzz: encode then decode is the identity for every level and write pattern" {
    try std.testing.fuzz({}, fuzzRoundtrip, .{});
}

test "fuzz driver: BZIP2_FUZZ, decoder" {
    try fuzz_driver.run(decodeHarness, .{ .prefix = "BZIP2_FUZZ", .name = "bzip2-decode" });
}

test "fuzz driver: BZIP2_FUZZ, round trip" {
    try fuzz_driver.run(roundtripHarness, .{ .prefix = "BZIP2_FUZZ", .name = "bzip2-roundtrip", .scale = 6 });
}

const reach_labels = [_][]const u8{
    "mode_raw",           "mode_mutated",     "mode_deep",        "mode_synth",           "mode_glued",
    "ok_data",            "ok_empty",         "reencoded",        "err_BadMagic",         "err_BadBlockHeader",
    "err_BadTrailer",     "err_BadOrigPtr",   "err_BadSymbolMap", "err_BadTables",        "err_BadCode",
    "err_BlockOverflow",  "err_BadRun",       "err_BadBlockData", "err_BlockCrcMismatch", "err_StreamCrcMismatch",
    "err_TruncatedInput", "err_TrailingData", "fault_oom",        "fault_read",           "rt_empty",
    "rt_mainsort",        "rt_ok",            "rt_pieces",        "rt_randomised",        "rt_sink_failed",
};

test "fuzz harnesses: 4000 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..4000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        decodeHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("bzip2 decode seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        if (seed % 8 == 0) roundtripHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("bzip2 roundtrip seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    var missing = false;
    for (reach_labels, reach) |l, n| {
        if (n == 0) {
            std.debug.print("reach: label {s} never hit in 4000 seeds\n", .{l});
            missing = true;
        }
    }
    if (missing) return error.HarnessDoesNotReach;
}

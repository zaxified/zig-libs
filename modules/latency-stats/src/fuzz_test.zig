// SPDX-License-Identifier: MIT

//! Fuzz harness for `wire.decode` (added 2026-11-02): the one parser of
//! untrusted bytes in this module.
//!
//! Each input builds a small histogram from drawn values, encodes it (plain or
//! compressed), and checks the oracle on the undamaged bytes: it decodes and
//! the counts are the original's. Then the bytes are damaged — flips aimed at
//! the header and the tail, a truncation, or a header field forged outright —
//! and decoded under a small `max_counts`: any result but a crash or a hang
//! is fine, and an accepted histogram must satisfy its own invariants (counts
//! add to `total_count`, queries do not trap).
//!
//! Driver: `LATENCY_STATS_FUZZ=<runs>[,<first seed>]`; harness name
//! `latency-stats-wire`.

const std = @import("std");
const testing = std.testing;
const fuzz_driver = @import("testkit").fuzz.driver;
const root = @import("root.zig");
const wire = root.wire;
const Histogram = root.Histogram;

const Label = enum { roundtrip_plain, roundtrip_compressed, damaged_accepted, damaged_refused, too_large, header_forged, truncated };
var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    counts[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const small: wire.DecodeOptions = .{ .max_counts = 1 << 14 };

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const highs = [_]u64{ 1000, 1_000_000, 3_600_000_000 };
    var h = try Histogram.init(gpa, .{
        .highest = highs[src.index(highs.len)],
        .sigfigs = src.valueRangeAtMost(u8, 1, 3),
    });
    defer h.deinit();
    for (0..src.index(40)) |_| {
        const v = src.valueRangeAtMost(u64, 0, h.highest + 10);
        if (src.value(bool)) h.record(v) else h.recordCount(v, src.valueRangeAtMost(u64, 1, 1 << 20));
    }

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const compressed = src.value(bool);
    if (compressed) try wire.encodeCompressed(&h, gpa, &aw.writer) else try wire.encode(&h, &aw.writer);

    {
        var d = try wire.decode(gpa, aw.written(), .{});
        defer d.deinit();
        if (!std.mem.eql(u64, d.counts, h.counts) or d.total_count != h.total_count) return error.RoundtripMismatch;
        if (compressed) mark(.roundtrip_compressed) else mark(.roundtrip_plain);
    }

    const bytes = try gpa.dupe(u8, aw.written());
    defer gpa.free(bytes);
    var len = bytes.len;
    const kind = src.index(4);
    switch (kind) {
        0 => for (0..1 + src.index(3)) |_| { // flips anywhere
            bytes[src.index(len)] ^= @as(u8, 1) << @intCast(src.index(8));
        },
        1 => for (0..1 + src.index(3)) |_| { // flips in the header / its compressed twin
            bytes[src.index(@min(len, 48))] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        2 => { // forged header field (plain only meaningfully; harmless on compressed)
            mark(.header_forged);
            const at = src.index(@min(len, 36)) & ~@as(usize, 3);
            if (at + 4 <= len) src.bytes(bytes[at..][0..4]);
        },
        3 => { // truncated
            mark(.truncated);
            len = src.index(len + 1);
        },
        else => unreachable,
    }
    if (decodeChecked(gpa, bytes[0..len])) |_| mark(.damaged_accepted) else |e| {
        if (e == error.TooLarge) mark(.too_large);
        mark(.damaged_refused);
    }
}

fn decodeChecked(gpa: std.mem.Allocator, bytes: []const u8) wire.DecodeError!void {
    var d = try wire.decode(gpa, bytes, small);
    defer d.deinit();
    var sum: u64 = 0;
    for (d.counts) |c| sum = std.math.add(u64, sum, c) catch @panic("counts overflow in an accepted histogram");
    if (sum != d.total_count) @panic("accepted histogram: counts do not add to total_count");
    _ = d.valueAtPercentile(50);
    _ = d.valueAtPercentile(100);
    _ = d.percentileSnapshot();
    _ = d.mean();
    _ = d.stdDev();
    var it = d.recorded();
    while (it.next()) |_| {}
}

test "fuzz driver: LATENCY_STATS_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "LATENCY_STATS_FUZZ", .name = "latency-stats-wire" });
}

test "fuzz harness: 600 seeds in every test run, and it gets everywhere" {
    counts = @splat(0);
    for (0..600) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
    for (counts, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 600 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

// SPDX-License-Identifier: MIT

//! Fuzz harnesses (added 2026-11-02), three of them, run by testkit's driver:
//!
//!  - `latency-stats-wire`: `wire.decode`, the one parser of untrusted bytes.
//!    A histogram (any `lowest`, huge counts too, so 5-9 byte varints occur) is
//!    encoded plain or compressed and must decode to the same counts. Then the
//!    bytes are damaged (flips anywhere / in the header, a forged header field,
//!    a truncation) or built to hit one specific refusal (a payload longer
//!    than its array, a total past u64, a count past i64), and decoded under a
//!    small `max_counts`: any outcome but a crash or a hang is fine, and an
//!    accepted histogram must satisfy its invariants and survive every query
//!    and iterator.
//!  - `latency-stats-corrected`: `recordCorrectedCount` against the one-by-one
//!    definition (counts, total, min, max), with `lowest` not a power of two
//!    and a total that sometimes runs out mid-run.
//!  - `latency-stats-add`: `add` (copy into empty, vector add, saturating
//!    add) leaves `min`/`max` in non-empty slots and the total equal to the
//!    saturating sum.
//!
//! Driver: `LATENCY_STATS_FUZZ=<runs>[,<first seed>]` (`_ONLY` selects).

const std = @import("std");
const testing = std.testing;
const fuzz_driver = @import("testkit").fuzz.driver;
const root = @import("root.zig");
const wire = root.wire;
const Histogram = root.Histogram;

const maxU = std.math.maxInt(u64);

const Label = enum {
    roundtrip_plain,
    roundtrip_compressed,
    big_varint,
    damaged_accepted,
    damaged_refused,
    too_large,
    header_forged,
    truncated,
    refused_payload_past_array,
    refused_total_overflow,
    refused_count_past_i64,
    iterated_hostile,
    corrected_checked,
    corrected_room_ran_out,
    corrected_odd_lowest,
    add_copy,
    add_plain,
    add_saturated,
};
var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    counts[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const small: wire.DecodeOptions = .{ .max_counts = 1 << 14 };
const lowests = [_]u64{ 1, 3, 1000 };

// ── wire.decode ─────────────────────────────────────────────────────────────

fn harnessWire(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const highs = [_]u64{ 2000, 1_000_000, 100_000_000 };
    var h = try Histogram.init(gpa, .{
        .lowest = lowests[src.index(lowests.len)],
        .highest = highs[src.index(highs.len)],
        .sigfigs = src.valueRangeAtMost(u8, 1, 3),
    });
    defer h.deinit();
    for (0..src.index(40)) |_| {
        const v = src.valueRangeAtMost(u64, 0, h.highest + 10);
        switch (src.index(4)) {
            0 => h.record(v),
            1 => h.recordCount(v, src.valueRangeAtMost(u64, 1, 1 << 20)),
            2 => { // a count that needs 5-9 varint bytes
                h.recordCount(v, src.valueRangeAtMost(u64, 1 << 30, 1 << 56));
                mark(.big_varint);
            },
            else => h.recordCorrected(v, src.valueRangeAtMost(u64, 1, 5000)),
        }
    }

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const compressed = src.value(bool);
    if (compressed) try wire.encodeCompressed(&h, gpa, &aw.writer) else try wire.encode(&h, &aw.writer);

    {
        var d = try wire.decode(gpa, aw.written(), .{});
        defer d.deinit();
        if (!std.mem.eql(u64, d.counts, h.counts) or d.total_count != h.total_count) return error.RoundtripMismatch;
        // min/max are slot bounds after decode, never outside the slot of the exact value
        if (h.total_count != 0 and (d.min() > h.min() or d.max() < h.max() or d.lowestEquivalent(d.min()) != d.lowestEquivalent(h.min()))) return error.ExtremesOutsideSlot;
        if (compressed) mark(.roundtrip_compressed) else mark(.roundtrip_plain);
    }

    const bytes = try gpa.dupe(u8, aw.written());
    defer gpa.free(bytes);
    var len = bytes.len;
    var specific: ?Label = null;
    const plain_form = !compressed;
    switch (src.index(7)) {
        0 => for (0..1 + src.index(3)) |_| { // flips anywhere
            bytes[src.index(len)] ^= @as(u8, 1) << @intCast(src.index(8));
        },
        1 => for (0..1 + src.index(3)) |_| { // flips in the header / its compressed twin
            bytes[src.index(@min(len, 48))] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        2 => { // forged header field
            mark(.header_forged);
            const at = src.index(@min(len, 36)) & ~@as(usize, 3);
            if (at + 4 <= len) src.bytes(bytes[at..][0..4]);
        },
        3 => { // truncated
            mark(.truncated);
            len = src.index(len + 1);
        },
        4 => if (plain_form and len > 40) { // highest forged down: the payload outruns its array
            std.mem.writeInt(u64, bytes[24..32], 2000, .big);
            std.mem.writeInt(u64, bytes[16..24], 1, .big);
            specific = .refused_payload_past_array;
        },
        5 => { // counts that add past u64: three slots of maxInt(i64) in a fresh histogram
            var t = try Histogram.init(gpa, .{ .highest = 2000, .sigfigs = 2 });
            defer t.deinit();
            for (t.counts[0..3]) |*c| c.* = std.math.maxInt(i64);
            var tw: std.Io.Writer.Allocating = .init(gpa);
            defer tw.deinit();
            try wire.encode(&t, &tw.writer);
            if (decodeChecked(gpa, tw.written())) |_| return error.TotalOverflowAccepted else |e| {
                if (e != error.BadFormat) return error.WrongRefusal;
                mark(.refused_total_overflow);
            }
        },
        6 => { // a count past i64 cannot be encoded: refused, not wrapped
            var t = try Histogram.init(gpa, .{ .highest = 2000, .sigfigs = 2 });
            defer t.deinit();
            t.counts[src.index(t.counts.len)] = src.valueRangeAtMost(u64, @as(u64, std.math.maxInt(i64)) + 1, maxU);
            var tw: std.Io.Writer.Allocating = .init(gpa);
            defer tw.deinit();
            if (wire.encode(&t, &tw.writer)) |_| return error.CountPastI64Encoded else |e| {
                if (e != error.CountTooLarge) return error.WrongRefusal;
                mark(.refused_count_past_i64);
            }
        },
        else => unreachable,
    }
    if (decodeChecked(gpa, bytes[0..len])) |_| mark(.damaged_accepted) else |e| {
        if (e == error.TooLarge) mark(.too_large);
        mark(.damaged_refused);
        if (specific) |l| switch (l) {
            .refused_payload_past_array => mark(.refused_payload_past_array),
            else => {},
        };
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
    var r = d.recorded();
    while (r.next()) |_| {}
    // The iterators are lazy; a caller bounds them, so do the same here.
    var lin = d.linear(1 + d.max() / 50);
    var k: usize = 0;
    while (lin.next()) |_| : (k += 1) if (k > 200) break;
    var lg = d.logarithmic(2, 1.5);
    k = 0;
    while (lg.next()) |_| : (k += 1) if (k > 200) break;
    var pc = d.percentiles(4);
    k = 0;
    while (pc.next()) |_| : (k += 1) if (k > 2000) break;
    mark(.iterated_hostile);
}

// ── recordCorrectedCount ────────────────────────────────────────────────────

fn harnessCorrected(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const lows = [_]u64{ 1, 3, 50, 1000 };
    const highs = [_]u64{ 5000, 1_000_000 };
    const cfg: root.HistogramOptions = .{
        .lowest = lows[src.index(lows.len)],
        .highest = highs[src.index(highs.len)],
        .sigfigs = src.valueRangeAtMost(u8, 1, 3),
    };
    var a = try Histogram.init(gpa, cfg);
    defer a.deinit();
    var b = try Histogram.init(gpa, cfg);
    defer b.deinit();
    if (cfg.lowest & (cfg.lowest - 1) != 0) mark(.corrected_odd_lowest);
    if (src.index(3) == 0) { // the total nearly full: it runs out inside a run
        const left = src.valueRangeAtMost(u64, 1, 60);
        const at = src.valueRangeAtMost(u64, cfg.lowest, cfg.highest);
        a.recordCount(at, maxU - left);
        b.recordCount(at, maxU - left);
        mark(.corrected_room_ran_out);
    }
    const v = src.valueRangeAtMost(u64, 0, cfg.highest + 5);
    // keep the one-by-one reference to a few thousand steps
    const steps = src.valueRangeAtMost(u64, 1, 4000);
    const iv = if (src.index(8) == 0) 0 else @max(1, @min(v, cfg.highest) / steps + src.valueRangeAtMost(u64, 0, 3));
    const n: u64 = switch (src.index(3)) {
        0 => 1,
        1 => src.valueRangeAtMost(u64, 2, 9),
        else => src.valueRangeAtMost(u64, 1 << 20, maxU),
    };
    a.recordCorrectedCount(v, n, iv);
    b.recordCount(v, n);
    const c = std.math.clamp(v, cfg.lowest, cfg.highest);
    if (iv != 0 and c > iv) {
        var m = c - iv;
        while (m >= iv) : (m -= iv) b.recordCount(m, n);
    }
    if (!std.mem.eql(u64, a.counts, b.counts)) return error.CountsDiffer;
    if (a.total_count != b.total_count or a.min() != b.min() or a.max() != b.max()) return error.ExtremesDiffer;
    mark(.corrected_checked);
}

// ── add ─────────────────────────────────────────────────────────────────────

fn harnessAdd(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const cfg: root.HistogramOptions = .{
        .lowest = lowests[src.index(lowests.len)],
        .highest = 1_000_000,
        .sigfigs = src.valueRangeAtMost(u8, 1, 3),
    };
    var a = try Histogram.init(gpa, cfg);
    defer a.deinit();
    var b = try Histogram.init(gpa, cfg);
    defer b.deinit();
    const saturate = src.index(3) == 0;
    const empty_dst = src.index(4) == 0;
    inline for (.{ &a, &b }, 0..) |h, which| {
        if (which == 0 and empty_dst) {} else {
            for (0..1 + src.index(12)) |_| h.recordCount(src.valueRangeAtMost(u64, 0, cfg.highest + 3), src.valueRangeAtMost(u64, 1, 1000));
            if (saturate) h.recordCount(src.valueRangeAtMost(u64, 0, cfg.highest), maxU / 2 + src.valueRangeAtMost(u64, 0, 1 << 20));
        }
    }
    const before = a.total_count;
    try a.add(&b);
    const expect_total = if (std.math.add(u64, before, b.total_count)) |t| t else |_| maxU;
    if (a.total_count != expect_total) return error.TotalNotTheSaturatingSum;
    var sum: u64 = 0;
    for (a.counts) |c| sum = std.math.add(u64, sum, c) catch return error.CountsOverflow;
    if (sum != a.total_count) return error.CountsDisagreeWithTotal;
    if (a.total_count != 0) {
        // min and max lie in non-empty slots, and nothing non-empty lies outside them
        if (a.countAtValue(a.min()) == 0 or a.countAtValue(a.max()) == 0) return error.ExtremeInEmptySlot;
        if (a.valueAtPercentile(100) != a.highestEquivalent(a.max())) return error.NonEmptySlotAboveMax;
        if (a.valueAtPercentile(0) != a.highestEquivalent(a.min())) return error.NonEmptySlotBelowMin;
    }
    if (a.total_count == maxU) mark(.add_saturated) else if (before == 0) mark(.add_copy) else mark(.add_plain);
}

// ── driver and in-suite reach ───────────────────────────────────────────────

test "fuzz driver: LATENCY_STATS_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ harnessWire, .{ .prefix = "LATENCY_STATS_FUZZ", .name = "latency-stats-wire" } },
        .{ harnessCorrected, .{ .prefix = "LATENCY_STATS_FUZZ", .name = "latency-stats-corrected" } },
        .{ harnessAdd, .{ .prefix = "LATENCY_STATS_FUZZ", .name = "latency-stats-add" } },
    });
}

test "fuzz harnesses: 800 seeds in every test run, and they get everywhere" {
    counts = @splat(0);
    inline for (.{ harnessWire, harnessCorrected, harnessAdd }, .{ "wire", "corrected", "add" }) |hn, name| {
        for (0..800) |seed| {
            var prng = std.Random.DefaultPrng.init(seed);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            hn(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
                std.debug.print("{s} seed {d}: {t}\n", .{ name, seed, e });
                return e;
            };
        }
    }
    for (counts, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 800 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

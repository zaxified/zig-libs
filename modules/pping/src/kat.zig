// SPDX-License-Identifier: MIT

//! kat — known-answer scenarios for `Estimator.observe`, i.e. for the
//! whole pping pipeline including the Fable-stub core (`match.matchEcho`).
//! Every test here drives `Estimator` through a hand-built sequence of
//! `Observation`s with a KNOWN expected sequence of `RttSample`s, including
//! the adversarial cases the module doc / `match.matchEcho`'s doc contract
//! call out by name: duplicate TSecr (first-echo-only), a TSval flood
//! (bounded memory, no crash), out-of-order arrivals, an unmatched TSecr,
//! and one clean single RTT.
//!
//! Every test in this file calls `Estimator.observe`, which calls into
//! `match.matchEcho` — the Fable stub. Each test therefore starts with a
//! gate check (`if (!root.fable_core_implemented) return error.SkipZigTest;`)
//! so `zig build test-pping` reports these as SKIP, not PASS, until a Fable
//! pass fills in `matchEcho` (see `gate.zig`). The scenarios themselves are
//! written and reviewable NOW — only the assertions against the real
//! algorithm's output wait on the core.

const std = @import("std");
const root = @import("root.zig");
const Estimator = root.Estimator;
const Direction = root.Direction;
const testing = std.testing;

test "KAT (a): duplicate TSecr — only the FIRST match yields a sample" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);

    // a_to_b sends TSval=100 at t=0.
    try testing.expectEqual(@as(?root.RttSample, null), est.observe(.{
        .dir = .a_to_b,
        .tsval = 100,
        .tsecr = 0,
        .now = 0,
    }));

    // b_to_a echoes TSecr=100 at t=50 -> a real 50-tick RTT sample.
    const first = est.observe(.{ .dir = .b_to_a, .tsval = 500, .tsecr = 100, .now = 50 });
    try testing.expect(first != null);
    try testing.expectEqual(@as(u64, 50), first.?.rtt);
    try testing.expectEqual(@as(u32, 100), first.?.tsval);

    // A delayed/duplicate ACK re-echoes the SAME TSecr=100 later — must NOT
    // produce a second sample; the entry was consumed by the first match.
    const second = est.observe(.{ .dir = .b_to_a, .tsval = 501, .tsecr = 100, .now = 90 });
    try testing.expectEqual(@as(?root.RttSample, null), second);
}

test "KAT (b): TSval flood — memory stays bounded, no crash, no spurious samples" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    var est = try Estimator.init(testing.allocator, .{ .capacity = 16 });
    defer est.deinit(testing.allocator);

    var i: u32 = 0;
    while (i < 10_000) : (i += 1) {
        // A flood of distinct, never-echoed TSvals in one direction — the
        // adversarial case for "does the table stay bounded".
        const sample = est.observe(.{
            .dir = .a_to_b,
            .tsval = i,
            .tsecr = 0, // never matches anything real
            .now = i,
        });
        try testing.expectEqual(@as(?root.RttSample, null), sample);
        try testing.expect(est.tableCount(.a_to_b) <= 16);
    }
    try testing.expectEqual(@as(usize, 16), est.tables[@intFromEnum(Direction.a_to_b)].capacity());
}

test "KAT (c): out-of-order arrivals still match correctly" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);

    // Two TSvals go out a_to_b, seen out of the order they were generated
    // (e.g. reordering upstream of the observation point): TSval=200 is
    // observed before TSval=100, but both are still "first seen" at their
    // own observation time.
    _ = est.observe(.{ .dir = .a_to_b, .tsval = 200, .tsecr = 0, .now = 10 });
    _ = est.observe(.{ .dir = .a_to_b, .tsval = 100, .tsecr = 0, .now = 20 });

    // Echoes also arrive out of order relative to generation, but each must
    // still match its own TSval's own first-seen time.
    const echo_200 = est.observe(.{ .dir = .b_to_a, .tsval = 900, .tsecr = 200, .now = 35 });
    try testing.expect(echo_200 != null);
    try testing.expectEqual(@as(u64, 25), echo_200.?.rtt); // 35 - 10
    try testing.expectEqual(@as(u32, 200), echo_200.?.tsval);

    const echo_100 = est.observe(.{ .dir = .b_to_a, .tsval = 901, .tsecr = 100, .now = 40 });
    try testing.expect(echo_100 != null);
    try testing.expectEqual(@as(u64, 20), echo_100.?.rtt); // 40 - 20
    try testing.expectEqual(@as(u32, 100), echo_100.?.tsval);
}

test "KAT (d): TSecr with no matching stored TSval produces no sample" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);

    // Nothing has ever been sent a_to_b, so a b_to_a echo of TSecr=42
    // (perhaps this flow's very first segment, or TSval=42 was never
    // actually sent) must find nothing.
    const sample = est.observe(.{ .dir = .b_to_a, .tsval = 1, .tsecr = 42, .now = 100 });
    try testing.expectEqual(@as(?root.RttSample, null), sample);
    try testing.expectEqual(@as(u64, 0), est.samples_emitted);
}

test "KAT (e): a clean single RTT, the base case" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);

    _ = est.observe(.{ .dir = .a_to_b, .tsval = 7, .tsecr = 0, .now = 1000 });
    const sample = est.observe(.{ .dir = .b_to_a, .tsval = 8, .tsecr = 7, .now = 1042 });
    try testing.expect(sample != null);
    try testing.expectEqual(@as(u64, 42), sample.?.rtt);
    try testing.expectEqual(@as(u32, 7), sample.?.tsval);
    try testing.expectEqual(@as(u64, 1042), sample.?.at);
    try testing.expectEqual(@as(u64, 1), est.samples_emitted);
}

test "KAT: an aged-out TSval no longer matches once max_age has elapsed" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    var est = try Estimator.init(testing.allocator, .{ .max_age = 100 });
    defer est.deinit(testing.allocator);

    _ = est.observe(.{ .dir = .a_to_b, .tsval = 1, .tsecr = 0, .now = 0 });
    // An echo arriving well past max_age must not match a long-forgotten entry.
    const sample = est.observe(.{ .dir = .b_to_a, .tsval = 2, .tsecr = 1, .now = 5_000 });
    try testing.expectEqual(@as(?root.RttSample, null), sample);
}

test "KAT: retransmission of the same TSval does not reset its first-seen time" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);

    // TSval=55 sent at t=0, then retransmitted (same TSval — TCP does not
    // advance TSval on retransmit) at t=30.
    _ = est.observe(.{ .dir = .a_to_b, .tsval = 55, .tsecr = 0, .now = 0 });
    _ = est.observe(.{ .dir = .a_to_b, .tsval = 55, .tsecr = 0, .now = 30 });

    // The eventual echo's RTT must be measured from the FIRST time (t=0),
    // not the retransmission (t=30).
    const sample = est.observe(.{ .dir = .b_to_a, .tsval = 999, .tsecr = 55, .now = 40 });
    try testing.expect(sample != null);
    try testing.expectEqual(@as(u64, 40), sample.?.rtt); // 40 - 0, not 40 - 30
}

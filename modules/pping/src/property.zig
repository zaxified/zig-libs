// SPDX-License-Identifier: MIT

//! property — structural properties `Estimator` must hold over long/
//! adversarial streams, independent of any single hand-picked scenario
//! (contrast `kat.zig`'s fixed known-answer cases). Three properties, per
//! the module's scaffolding brief:
//!
//!   1. **Bounded memory.** Table occupancy per direction never exceeds
//!      `Config.capacity`, no matter how long the observed stream runs.
//!      Gated — exercised through `Estimator.observe`, which calls the
//!      Fable-stub core.
//!   2. **No RTT without a real echo.** A TSecr value that was never sent
//!      as a TSval in the opposite direction must never produce a sample.
//!      Gated, same reason.
//!   3. **Monotonic-time robustness.** A caller-supplied clock that is not
//!      perfectly monotonic (regresses, or repeats a value) must never
//!      corrupt bounded state (crash, over-evict, under-evict into
//!      unbounded growth) — this is a property of the mechanical `TsTable`
//!      layer alone (see `TsTable.evictOlderThan`'s saturating-age
//!      construction in `table.zig`), so it is checked WITHOUT calling
//!      `Estimator.observe` / the Fable stub, and is therefore **not**
//!      gated — it holds today.

const std = @import("std");
const root = @import("root.zig");
const Estimator = root.Estimator;
const Direction = root.Direction;
const testing = std.testing;

/// Deterministic 64-bit LCG (Knuth MMIX constants) — same construction used
/// throughout this module's scaffold (`table.zig`, `parse.zig`) and in
/// `latency-stats`, for reproducible property-test streams without
/// depending on `std.crypto.random` (removed in 0.16).
fn lcg(state: *u64) u64 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return state.* >> 11;
}

test "property (gated): bounded memory — table occupancy never exceeds capacity over a long, adversarial observation stream" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    const capacity = 32;
    var est = try Estimator.init(testing.allocator, .{ .capacity = capacity, .max_age = 500 });
    defer est.deinit(testing.allocator);

    var state: u64 = 0xA02BDBF7BB3C0A7;
    var i: u64 = 0;
    while (i < 50_000) : (i += 1) {
        const dir: Direction = if (lcg(&state) & 1 == 0) .a_to_b else .b_to_a;
        const tsval: u32 = @truncate(lcg(&state) % 200); // small range: forces churn/eviction
        const tsecr: u32 = @truncate(lcg(&state) % 200);
        _ = est.observe(.{ .dir = dir, .tsval = tsval, .tsecr = tsecr, .now = i });

        try testing.expect(est.tableCount(.a_to_b) <= capacity);
        try testing.expect(est.tableCount(.b_to_a) <= capacity);
    }
    // The backing allocation itself must never have grown past capacity.
    try testing.expectEqual(@as(usize, capacity), est.tables[0].capacity());
    try testing.expectEqual(@as(usize, capacity), est.tables[1].capacity());
}

test "property (gated): no RTT sample without a real echo — TSecr values never sent as a TSval never match" {
    if (!root.fable_core_implemented) return error.SkipZigTest;
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);

    // Populate a_to_b with TSvals 0..99.
    var v: u32 = 0;
    while (v < 100) : (v += 1) {
        _ = est.observe(.{ .dir = .a_to_b, .tsval = v, .tsecr = 0, .now = v });
    }

    // Every b_to_a echo in the DISJOINT range 1000..1099 was never sent as
    // a TSval by a_to_b — none of them may ever produce a sample.
    var state: u64 = 0x243F6A8885A308D3;
    var i: u64 = 0;
    while (i < 5_000) : (i += 1) {
        const tsecr: u32 = 1000 + @as(u32, @truncate(lcg(&state) % 100));
        const sample = est.observe(.{ .dir = .b_to_a, .tsval = 0, .tsecr = tsecr, .now = 100 + i });
        try testing.expectEqual(@as(?root.RttSample, null), sample);
    }
    try testing.expectEqual(@as(u64, 0), est.samples_emitted);
}

test "property (ungated): monotonic-time robustness — a regressing/repeating clock never corrupts bounded table state" {
    // Deliberately drives `Estimator.tables` directly via the mechanical
    // TsTable API (insert/evictOlderThan) — NOT through `observe`, so no
    // Fable-stub call happens and this test needs no gate.
    var est = try Estimator.init(testing.allocator, .{ .capacity = 16, .max_age = 50 });
    defer est.deinit(testing.allocator);
    const tbl = &est.tables[@intFromEnum(Direction.a_to_b)];

    var state: u64 = 0x1BD11BDAA9FC1A22;
    var now: u64 = 1_000_000; // start large so a naive unsaturated subtraction could underflow
    var tsval: u32 = 0;
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        // A hostile/misbehaving clock: usually advances, but sometimes
        // jumps backward — `TsTable.evictOlderThan`'s saturating age must
        // tolerate this without panicking or leaking unbounded entries.
        const step = lcg(&state) % 20;
        if (lcg(&state) % 10 == 0 and now > step) {
            now -= step; // regress
        } else {
            now +%= step; // advance (wrapping, in case `now` is ever near maxInt)
        }

        if (tbl.indexOf(tsval) == null) {
            if (tbl.isFull()) {
                tbl.removeAt(tbl.oldestIndex().?);
            }
            try tbl.insert(tsval, now);
        }
        _ = tbl.evictOlderThan(now, 50);
        tsval +%= 1;

        try testing.expect(tbl.count() <= tbl.capacity());
    }
    try testing.expectEqual(@as(usize, 16), tbl.entries.len); // allocation never grew
}

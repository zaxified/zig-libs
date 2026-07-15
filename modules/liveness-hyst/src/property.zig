// SPDX-License-Identifier: MIT
//! Property tests for the Estimator: monotonicity (a strictly-worse probe
//! stream never yields a strictly-more-"up" verdict) and bounded memory (fixed
//! state regardless of stream length). These are properties of the Estimator
//! itself, not of any particular network scenario, so they drive
//! `Estimator.onProbeReply` / `onProbeTimeout` directly with synthetic probe
//! streams — no netsim needed.
//!
//! NOTE: the monotonicity test and the runtime bounded-memory test both call
//! into the Fable-core `decide()` stub (via the Estimator), so until that lands
//! they panic at the first probe — expected, see root.zig / core.zig. The
//! structural bounded-memory test does NOT call `decide` and passes today.

const std = @import("std");
const root = @import("root.zig");
const Estimator = root.Estimator;
const Time = root.Time;

const testing = std.testing;

// ── monotonicity ──────────────────────────────────────────────────────────────

const ProbeEvent = union(enum) {
    reply: Time, // rtt
    timeout,
};

/// A "strictly worse" transform of a single probe event: a reply either stays a
/// reply with an RTT that is never lower, or degrades all the way to a timeout;
/// a timeout stays a timeout. Never improves any single probe.
fn worsen(rng: std.Random, ev: ProbeEvent) ProbeEvent {
    return switch (ev) {
        .timeout => .timeout,
        .reply => |rtt| if (rng.boolean())
            .timeout
        else
            .{ .reply = rtt + rng.uintLessThan(Time, 50) },
    };
}

fn feed(est: *Estimator, now: Time, ev: ProbeEvent) void {
    switch (ev) {
        .reply => |rtt| est.onProbeReply(now, rtt),
        .timeout => est.onProbeTimeout(now),
    }
}

test "property: a strictly-worse probe stream never yields a strictly-more-up verdict" {
    var prng = std.Random.DefaultPrng.init(0xA11CE);
    const rng = prng.random();

    var a = Estimator.init(.{});
    var b = Estimator.init(.{});

    const n = 500;
    var now: Time = 0;
    const interval: Time = 200;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        now += interval;
        // Baseline stream A: mostly clean replies, occasional timeout.
        const ev_a: ProbeEvent = if (rng.uintLessThan(u32, 20) == 0)
            .timeout
        else
            .{ .reply = 10 + rng.uintLessThan(Time, 40) };
        const ev_b = worsen(rng, ev_a);

        feed(&a, now, ev_a);
        feed(&b, now, ev_b);

        try testing.expect(b.state().rank() <= a.state().rank());
    }
}

// ── bounded memory ────────────────────────────────────────────────────────────

test "property: bounded memory — Estimator holds no pointer/slice field" {
    // Structural proof, independent of the Fable core: the type has no
    // allocator and no dynamically-growing collection (a raw pointer or slice
    // field would be the tell), so its footprint cannot depend on how many
    // probes it has processed. Compares against `history`, which is a fixed
    // `[history_capacity]Probe` array (not a pointer), by construction.
    comptime {
        const info = @typeInfo(Estimator).@"struct";
        for (info.fields) |f| {
            if (@typeInfo(f.type) == .pointer) {
                @compileError("Estimator must not hold a pointer/slice field (unbounded-memory risk): " ++ f.name);
            }
        }
    }
}

test "property: bounded memory — recent-probe history saturates instead of growing" {
    var est = Estimator.init(.{});
    var now: Time = 0;
    const n = root.history_capacity * 10; // far more probes than the window holds
    var i: usize = 0;
    while (i < n) : (i += 1) {
        now += 100;
        if (i % 7 == 0) est.onProbeTimeout(now) else est.onProbeReply(now, 20);
        try testing.expect(est.history_len <= root.history_capacity);
    }
    try testing.expectEqual(root.history_capacity, est.history_len);
}

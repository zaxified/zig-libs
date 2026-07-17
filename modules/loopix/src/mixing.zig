// SPDX-License-Identifier: MIT

//! mixing — THE GATED FABLE CORE. The three functions this module exists to
//! prove are `@panic("TODO(fable/core): ...")` stubs today; everything that
//! measures whether they are CORRECT (the anonymity invariant + adversary in
//! `adversary.zig`, the FIFO positive control in `protocol.zig`) is already
//! real and has teeth. Flip `gate.fable_core_implemented` once these are
//! filled in — see `gate.zig`.
//!
//! **What is irreducible here, and why it is the anonymity-load-bearing part.**
//! A Loopix mix is a *continuous-time (stop-and-go) mix*: on each arrival it
//! draws an INDEPENDENT exponential hold and releases the packet when that hold
//! elapses. The exponential's memorylessness is not an implementation detail —
//! it is the entire security argument. Because P(release in the next dt | still
//! held) is constant regardless of how long the packet has waited, the time a
//! packet LEAVES a mix is statistically independent of when it ARRIVED, so a
//! global passive adversary watching every link cannot correlate a mix's
//! outputs back to its inputs by timing. Any non-memoryless hold (constant,
//! FIFO, threshold, uniform-bounded) leaks that correlation — which is exactly
//! what the `FifoMix` positive control demonstrates and the harness flags.
//!
//! **The discrete-time subtlety a filler-in MUST get right** (flagged here
//! because it is the one place a strong non-Fable pass could quietly go wrong):
//! netsim time is INTEGER ticks. A rounded/floored continuous exponential
//! (`@intFromFloat(-mean*@log(u))`) is NOT memoryless — flooring destroys the
//! constant-hazard property near zero. The correct discrete memoryless law is
//! the GEOMETRIC distribution (the discrete analogue of the exponential):
//! `k = floor( ln(u) / ln(1 - 1/mean) )`. Whether the difference is large
//! enough to move the anonymity metric is exactly what the (gated) real-mix
//! test will decide — but a filler-in that reaches for a floored exponential
//! without noticing the distinction is the mistake this comment exists to
//! prevent.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");

const Time = netsim.Time;
const LoopixConfig = types.LoopixConfig;
const MsgKind = types.MsgKind;

// ── seeded PRNG (splitmix64, public domain — same generator netsim uses) ─────
//
// The mixing core is randomized (exponential holds, Poisson cover). To keep
// runs a pure function of their seed, that randomness comes from THIS seeded
// stream, never from the OS / a wall clock — identical to netsim's own rule.

pub const Prng = struct {
    state: u64,

    pub fn init(seed: u64) Prng {
        var p = Prng{ .state = seed };
        _ = p.next(); // decorrelate low-entropy seeds
        return p;
    }

    pub fn next(p: *Prng) u64 {
        p.state +%= 0x9e3779b97f4a7c15;
        var z = p.state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    /// Uniform in the OPEN interval (0, 1) — open so `@log` never sees 0.
    pub fn unit(p: *Prng) f64 {
        // 53-bit mantissa draw in [0, 1), shifted off the endpoints.
        const bits: u64 = p.next() >> 11; // 53 bits
        const x = (@as(f64, @floatFromInt(bits)) + 0.5) * (1.0 / 9007199254740992.0);
        return x;
    }
};

// ── the Poisson cover-traffic process (GATED) ────────────────────────────────

/// One scheduled emission of the Poisson cover process: WHEN (relative delay,
/// ticks) to send the next chaff packet and WHICH KIND it is.
pub const CoverEvent = struct {
    delay: Time,
    kind: MsgKind,
};

/// TODO(fable/core): the node's Poisson cover-traffic process. Draw the delay
/// to the next chaff emission as an integer exponential with mean
/// `cfg.cover_mean_interval` (see the discrete-memorylessness note at the top
/// of this file — a Poisson process has geometric inter-arrivals in discrete
/// time), and pick `loop_cover` vs `drop_cover` from `prng`. Called once per
/// emission by every node (mixes AND clients) to self-clock its chaff stream;
/// the caller re-arms a timer for `delay` and re-invokes. Cover volume is the
/// only thing keeping every mix's anonymity set above `AnonymityBound.
/// min_effective_set` — this is the function the `no-cover` failure mode
/// disables.
pub fn nextCover(prng: *Prng, cfg: LoopixConfig) CoverEvent {
    _ = prng;
    _ = cfg;
    @panic("TODO(fable/core): Poisson cover-traffic process (exponential inter-arrival + loop/drop choice)");
}

// ── the Poisson mix hold/release decision (GATED) ────────────────────────────

/// TODO(fable/core): the memoryless per-hop delay primitive. Return an integer
/// exponential draw with mean `mean` ticks — the discrete-time memoryless
/// (geometric) law, NOT a floored continuous exponential (see the file-top
/// note). This is the single primitive both the mix hold (`scheduleRelease`)
/// and the cover process (`nextCover`) are built on; getting its distribution
/// right is what makes output timing independent of input timing.
pub fn sampleExpDelay(prng: *Prng, mean: Time) Time {
    _ = prng;
    _ = mean;
    @panic("TODO(fable/core): memoryless integer exponential (geometric) delay sample");
}

/// TODO(fable/core): the mix pool's hold/release decision for one arriving
/// packet. Given the packet arrived at `arrival`, return the ABSOLUTE sim time
/// at which the mix must release (forward) it — i.e. `arrival +
/// sampleExpDelay(prng, cfg.mean_delay)`. The caller (`protocol.zig`'s
/// `Loopix.onMessage`) stashes the packet and `setTimer`s exactly this
/// release time; on the timer it forwards to the next hop and logs the
/// completed `(arrival, departure)` transit for the adversary. The whole
/// anonymity guarantee rests on this hold being an INDEPENDENT exponential per
/// arrival — a constant offset here reduces the mix to the `FifoMix` control
/// the harness already flags.
pub fn scheduleRelease(prng: *Prng, cfg: LoopixConfig, arrival: Time) Time {
    _ = prng;
    _ = cfg;
    _ = arrival;
    @panic("TODO(fable/core): Poisson mix hold/release (arrival + independent exponential hold)");
}

// ── tests: the PRNG is real and seeded; the gated core is only type-checked ──

const testing = std.testing;

test "Prng: identical seed reproduces the identical unit stream" {
    var a = Prng.init(123);
    var b = Prng.init(123);
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try testing.expectEqual(a.next(), b.next());
    }
    var c = Prng.init(7);
    var seen_low = false;
    var seen_high = false;
    i = 0;
    while (i < 1000) : (i += 1) {
        const u = c.unit();
        try testing.expect(u > 0.0 and u < 1.0); // open interval — @log-safe
        if (u < 0.25) seen_low = true;
        if (u > 0.75) seen_high = true;
    }
    try testing.expect(seen_low and seen_high); // spans the range
}

test "gated core: the three stubs compile with their real signatures (no call)" {
    // Referencing without calling proves the signatures type-check against the
    // config/PRNG the real implementation will use — a call would @panic and
    // abort the whole test binary (which is why the protocol tests that reach
    // them are gate-skipped, not just expected-to-fail).
    const F0 = @TypeOf(nextCover);
    const F1 = @TypeOf(sampleExpDelay);
    const F2 = @TypeOf(scheduleRelease);
    try testing.expect(@typeInfo(F0) == .@"fn");
    try testing.expect(@typeInfo(F1) == .@"fn");
    try testing.expect(@typeInfo(F2) == .@"fn");
}

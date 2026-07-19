// SPDX-License-Identifier: MIT

//! mixing — THE (formerly gated) CORE. The three functions this module exists
//! to prove — `sampleExpDelay` / `scheduleRelease` / `nextCover` — are now
//! IMPLEMENTED (`gate.fable_core_implemented = true`), and the real `Loopix`
//! Poisson mix satisfies the retuned `AnonymityBound` across a seed sweep while
//! the FIFO + no-cover controls fail it (see `protocol.zig`). Everything that
//! measures whether they are CORRECT (the anonymity invariant + adversary in
//! `adversary.zig`, the FIFO positive control in `protocol.zig`) is real and
//! has teeth — see `gate.zig`.
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
    // Inter-arrival of the Poisson cover process = the same memoryless integer
    // draw the mix hold uses (a Poisson process has geometric gaps in discrete
    // time). Clamp to >= 1: the caller re-arms a COVER_TIMER for exactly this
    // delay and re-invokes, so a 0-tick gap would self-schedule another cover
    // emission at the SAME tick forever (a within-tick livelock). The mix hold
    // has no such clamp because its release timer is one-shot, not self-arming.
    const gap: Time = @max(1, sampleExpDelay(prng, cfg.cover_mean_interval));
    // Loop vs drop chaff — both bit-indistinguishable to the GPA, so an even
    // split is fine; a fresh PRNG draw keeps the choice a pure function of seed.
    const kind: MsgKind = if (prng.next() & 1 == 0) .loop_cover else .drop_cover;
    return .{ .delay = gap, .kind = kind };
}

// ── the Poisson mix hold/release decision (GATED) ────────────────────────────

/// TODO(fable/core): the memoryless per-hop delay primitive. Return an integer
/// exponential draw with mean `mean` ticks — the discrete-time memoryless
/// (geometric) law, NOT a floored continuous exponential (see the file-top
/// note). This is the single primitive both the mix hold (`scheduleRelease`)
/// and the cover process (`nextCover`) are built on; getting its distribution
/// right is what makes output timing independent of input timing.
pub fn sampleExpDelay(prng: *Prng, mean: Time) Time {
    if (mean <= 1) return 0; // degenerate: a per-tick hazard of ~1 ⇒ release now
    // Geometric inverse-CDF. With per-tick success (release) probability
    // p = 1/mean, the survival is P(hold ≥ k) = (1−p)^k, so
    //     hold = ⌊ ln(u) / ln(1 − p) ⌋ ,  u ~ U(0,1),
    // yields P(hold = k) = (1−p)^k · p on support {0,1,2,…}. This is the
    // DISCRETE-time memoryless law: the per-tick release hazard
    // P(hold = k | hold ≥ k) = p is CONSTANT for every k, which is exactly the
    // "output timing independent of input timing" property the anonymity
    // argument rests on (a packet held for a while is no more/less likely to
    // leave next tick than a fresh one). The survival ratio (1 − 1/mean) also
    // matches the adversary's exp(−1/mean) kernel to O(1/mean²), so the mix's
    // own hold pmf is ∝ the adversary's likelihood — no departure stands out.
    const u = prng.unit(); // (0,1) open ⇒ ln(u) finite and < 0
    const survive = 1.0 - 1.0 / @as(f64, @floatFromInt(mean)); // (0,1) ⇒ ln < 0
    const k = @log(u) / @log(survive); // (neg)/(neg) ⇒ ≥ 0
    return @intFromFloat(k); // ⌊·⌋ (k ≥ 0, so truncation == floor)
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
    // One INDEPENDENT memoryless hold per arrival (Poisson mix, not a batch or
    // threshold): the release time is this packet's own draw added to when it
    // arrived. Independence across arrivals is what decorrelates the departure
    // multiset from the arrival multiset.
    //
    // ADJUDICATION ANCHOR (audit F1). The property this function must provide,
    // stated as a checkable observable: for two packets co-resident in a mix
    // (the second arrived while the first was still held), memorylessness makes
    // the first packet's RESIDUAL hold distributed like a fresh draw, so the
    // later arrival departs first with probability ~1/2. Any order-preserving
    // hold (constant, FIFO, threshold-batch) scores exactly 0. This is enforced
    // end-to-end by the reorder property test in `protocol.zig` (statistic:
    // `adversary.reorderStats`, band [0.35, 0.65], measured ~0.49-0.53 over
    // ~6-7.5k pairs/seed). Two independent ways to lose the property, both
    // caught by that test: (1) this draw ceasing to be i.i.d. geometric
    // (constant-hold injection here => fraction 0 => RED); (2) the CALLER
    // re-assigning drawn release times to packets in arrival order — the
    // release path must forward the packet whose OWN timer fired, see
    // `protocol.zig`'s `Relay.release` (a real caught defect: front-first
    // release made the shipped mix order-preserving, fraction 0, while the
    // departure timeline still looked exponential).
    return arrival + sampleExpDelay(prng, cfg.mean_delay);
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

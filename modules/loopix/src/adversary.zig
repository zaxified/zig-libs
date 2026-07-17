// SPDX-License-Identifier: MIT

//! adversary — the anonymity invariant and the global-passive-adversary that
//! measures it. This is the module's real intellectual content: the mixing
//! core (`mixing.zig`) is a few lines of exponential sampling; deciding *what
//! "anonymous" means as a number a deterministic harness can check*, and
//! building an adversary with enough teeth that a broken mix fails it hard and
//! a correct one passes robustly, is the hard part.
//!
//! ── Threat model ─────────────────────────────────────────────────────────
//!
//! A **global passive adversary (GPA)** — the standard Loopix/Nym adversary —
//! observes the timing of every packet on every link, but:
//!   - CANNOT read packet contents (Sphinx layer-encryption makes each hop's
//!     bytes unlinkable to the next — provided by the `sphinx` module; the
//!     adversary is therefore never handed a transit's `id`), and
//!   - CANNOT tell a real packet from cover (loop/drop chaff is
//!     bit-indistinguishable and constant-length — so the adversary is never
//!     handed a transit's `kind` either).
//! What it CAN do is watch, at each mix, the multiset of arrival times and the
//! multiset of departure times, and try to match them up. That matching — "did
//! output `d` carry the same packet as input `a`?" — is the anonymity game.
//!
//! ── The metric ───────────────────────────────────────────────────────────
//!
//! The adversary knows the mix's strategy (Kerckhoffs), so it links using the
//! strategy's own delay law. For a target that arrived at a mix at time `a*`,
//! it assigns each departure `d` a likelihood `kernel(d − a*)` and normalizes
//! to a posterior over "which departure is my target". From that posterior we
//! measure two independent things (see `AnonymityResult`):
//!
//!  1. **effective anonymity set** `2^H`, H = −Σ pⱼ·log₂ pⱼ  (the
//!     Serjantov–Danezis metric) — the effective number of departures the
//!     target could equally be. Large = the target is lost in a crowd. This
//!     is what COVER TRAFFIC protects: no chaff ⇒ empty pool ⇒ the crowd
//!     shrinks to 1.
//!  2. **linking probability** `p(d*)` — the posterior mass on the target's
//!     TRUE departure (`d*` is ground truth the harness knows and the
//!     adversary does not). Low = even inside the crowd the adversary cannot
//!     concentrate on the real match. This is what the memoryless POISSON HOLD
//!     protects: a deterministic/FIFO hold makes `p(d*) = 1`.
//!
//! The invariant (`AnonymityBound`) requires BOTH the WORST-case effective set
//! (min over all targets) to stay large AND the WORST-case linking probability
//! (max over all targets) to stay low. A single pinned message fails it.
//!
//! ── Why it separates robustly and is not flaky ───────────────────────────
//!
//! The metric is a pure function of a concrete transit transcript, which is a
//! pure function of the netsim seed — so it is deterministic per seed, and a
//! seed sweep just averages many independent draws (law of large numbers). The
//! separation is not a marginal statistical gap: a FIFO mix, scored with its
//! own (spike) delay law, puts the ENTIRE posterior on the true departure on
//! EVERY target — `p(d*) = 1`, effective set `= 1` — deterministically, on
//! every seed, with no partition or fault required. The correct Poisson mix's
//! smooth law spreads the posterior across the whole in-flight pool. There is
//! no seed on which FIFO "accidentally mixes", so no threshold tuning can make
//! the teeth flaky — the gap is 1.0 vs ~1/pool, not 0.6 vs 0.4.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");

const Time = netsim.Time;
const NodeId = netsim.NodeId;
const Allocator = std.mem.Allocator;
const MsgKind = types.MsgKind;
const AnonymityBound = types.AnonymityBound;

/// One completed pass of a packet through one mix, as recorded by the protocol
/// under test. The harness sees all fields (it is the oracle); the adversary
/// is handed only the projection in `measure` (arrival/departure/mix — never
/// `id` or `kind`, per the threat model).
pub const Transit = struct {
    mix: NodeId,
    arrival: Time,
    departure: Time,
    kind: MsgKind,
    /// Ground-truth packet identity. The adversary NEVER sees this — it is how
    /// the harness scores whether the adversary's guess was right.
    id: u64,
};

/// The delay law the adversary links with. It knows the mix's strategy, so it
/// uses that strategy's own hold distribution as its likelihood kernel.
pub const DelayModel = union(enum) {
    /// A Poisson mix: hold ~ Exp(1/mean). Likelihood of a hold `δ` is
    /// `exp(−δ/mean)` (the normalizing μ cancels in the posterior). Smooth, so
    /// many candidate departures get comparable weight ⇒ large effective set.
    exponential: f64, // mean hold, ticks
    /// A constant/FIFO mix: hold is exactly `delta` (± `tol` for jitter).
    /// A spike likelihood — only the departure whose hold matches gets weight,
    /// so the posterior collapses onto the true match ⇒ effective set 1.
    constant: struct { delta: Time, tol: Time },

    fn kernel(self: DelayModel, hold: i128) f64 {
        if (hold < 0) return 0.0; // causal: a packet cannot depart before it arrived
        const d: f64 = @floatFromInt(hold);
        return switch (self) {
            .exponential => |mean| std.math.exp(-d / mean),
            .constant => |c| blk: {
                const target: f64 = @floatFromInt(c.delta);
                const tol: f64 = @floatFromInt(c.tol);
                break :blk if (@abs(d - target) <= tol) 1.0 else 0.0;
            },
        };
    }
};

/// Aggregate anonymity measured over every real target × every mix it
/// transited. The `min_effective_set` / `max_link_prob` fields are the
/// safety-relevant extremes (a single bad target fails the invariant); the
/// means are for reporting/tuning.
pub const AnonymityResult = struct {
    targets: usize = 0,
    mean_effective_set: f64 = 0,
    min_effective_set: f64 = std.math.inf(f64),
    mean_link_prob: f64 = 0,
    max_link_prob: f64 = 0,

    /// Does this measurement satisfy the declared anonymity bound?
    pub fn holds(self: AnonymityResult, bound: AnonymityBound) bool {
        if (self.targets == 0) return true; // vacuous — no traffic to link
        return self.min_effective_set >= bound.min_effective_set and
            self.max_link_prob <= bound.max_link_prob;
    }
};

/// Measure the GPA's anonymity against a transit transcript, linking with
/// `model` (the mix's own delay law). For each REAL transit `T` (arrival `a*`,
/// true departure `d*`, mix `M`), the adversary builds a posterior over the
/// departures observed at `M` and we score the effective set + true-match
/// probability. Cover transits are NOT scored as targets (anonymity is only
/// defined for real traffic) but they DO swell each mix's departure pool — so
/// disabling cover shrinks every real target's crowd, exactly as in Loopix.
///
/// Deterministic and allocation-light: one pass to index departures per mix,
/// then one posterior per target. `O(targets × pool)`; the exponential kernel
/// self-windows (far departures weigh ~0) so a whole-run pool is fine.
pub fn measure(
    gpa: Allocator,
    transits: []const Transit,
    model: DelayModel,
) Allocator.Error!AnonymityResult {
    // Index every departure time by mix, so each target can scan just its own
    // mix's outputs. (Departures include cover — the adversary can't tell it
    // apart, which is the point.)
    var by_mix: std.AutoHashMapUnmanaged(NodeId, std.ArrayListUnmanaged(Time)) = .empty;
    defer {
        var it = by_mix.valueIterator();
        while (it.next()) |list| list.deinit(gpa);
        by_mix.deinit(gpa);
    }
    for (transits) |t| {
        const gop = try by_mix.getOrPut(gpa, t.mix);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(gpa, t.departure);
    }

    var res = AnonymityResult{};
    var sum_eff: f64 = 0;
    var sum_link: f64 = 0;

    for (transits) |t| {
        if (t.kind != .real) continue; // only real traffic is a linking target
        const deps = by_mix.get(t.mix).?.items;

        // Build the (unnormalized) posterior over this mix's departures for a
        // packet that arrived at t.arrival, and locate the true departure's
        // weight. The true departure is t.departure (ground truth); when
        // several departures coincide in time we still credit exactly one
        // share to the true match (posterior mass at that timestamp / count).
        var total: f64 = 0;
        var true_weight: f64 = 0;
        var true_coincident: f64 = 0; // departures sharing the true timestamp
        for (deps) |d| {
            const hold: i128 = @as(i128, @intCast(d)) - @as(i128, @intCast(t.arrival));
            const w = model.kernel(hold);
            total += w;
            if (d == t.departure) {
                true_weight = w;
                true_coincident += 1;
            }
        }

        // Effective anonymity set = 2^H over the normalized posterior.
        var link_prob: f64 = 0;
        var eff_set: f64 = 1;
        if (total > 0) {
            var h: f64 = 0;
            for (deps) |d| {
                const hold: i128 = @as(i128, @intCast(d)) - @as(i128, @intCast(t.arrival));
                const w = model.kernel(hold);
                if (w <= 0) continue;
                const p = w / total;
                h -= p * std.math.log2(p);
            }
            eff_set = std.math.exp2(h);
            // Posterior mass on the true match — split evenly if several
            // departures share its exact timestamp (adversary can't break the
            // tie, so the true one gets its fair share of the coincident mass).
            link_prob = (true_weight / total) / true_coincident;
        }

        res.targets += 1;
        sum_eff += eff_set;
        sum_link += link_prob;
        res.min_effective_set = @min(res.min_effective_set, eff_set);
        res.max_link_prob = @max(res.max_link_prob, link_prob);
    }

    if (res.targets > 0) {
        const n: f64 = @floatFromInt(res.targets);
        res.mean_effective_set = sum_eff / n;
        res.mean_link_prob = sum_link / n;
    } else {
        res.min_effective_set = 0;
    }
    return res;
}

// ── tests: the harness has teeth on hand-built transcripts (no core needed) ──
//
// These are the anonymity analogue of df-elect's synthetic `worstBadDfWindow`
// tests: they prove `measure` separates a well-mixed transcript from the two
// failure modes (order-preserving FIFO, and cover-starved thin pools) WITHOUT
// running any protocol — so the checker is proven to have teeth before the
// mixing core exists.

const testing = std.testing;

const R = MsgKind.real;

fn tr(mix: NodeId, arr: Time, dep: Time, id: u64) Transit {
    return .{ .mix = mix, .arrival = arr, .departure = dep, .kind = R, .id = id };
}

test "measure: a FIFO transcript (order preserved) collapses anonymity — spike posterior" {
    // 8 packets arrive 0,10,20,… at ONE mix and depart in the SAME order a
    // constant 40 later. Scored with the FIFO mix's own (constant) delay law,
    // each target's posterior is a spike on its true departure.
    const gpa = testing.allocator;
    var list: std.ArrayListUnmanaged(Transit) = .empty;
    defer list.deinit(gpa);
    var i: u64 = 0;
    while (i < 8) : (i += 1) {
        try list.append(gpa, tr(0, i * 10, i * 10 + 40, i));
    }
    const r = try measure(gpa, list.items, .{ .constant = .{ .delta = 40, .tol = 0 } });
    try testing.expectEqual(@as(usize, 8), r.targets);
    // Every target is pinned: effective set 1, linking probability 1.
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.max_link_prob, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.min_effective_set, 1e-9);
    const bound = AnonymityBound{};
    try testing.expect(!r.holds(bound)); // FIFO FAILS the invariant, hard
}

test "measure: a well-mixed transcript (exponential holds, full pool) preserves anonymity" {
    // 12 packets all arrive within a tight window at one mix and depart at
    // exponentially-spread times that interleave — the memoryless-hold picture.
    // Scored with the exponential law, the posterior spreads across the pool.
    const gpa = testing.allocator;
    var list: std.ArrayListUnmanaged(Transit) = .empty;
    defer list.deinit(gpa);
    // Arrivals clustered 0..11; departures deliberately re-ordered vs arrival
    // and spread over ~a few mean-delays so several are plausible for each.
    const deps = [_]Time{ 55, 30, 80, 42, 12, 95, 61, 25, 70, 38, 105, 48 };
    var i: u64 = 0;
    while (i < deps.len) : (i += 1) {
        try list.append(gpa, tr(0, i, deps[i], i));
    }
    const r = try measure(gpa, list.items, .{ .exponential = 40.0 });
    try testing.expectEqual(@as(usize, deps.len), r.targets);
    const bound = AnonymityBound{ .min_effective_set = 2.0, .max_link_prob = 0.5 };
    // A real crowd: no target is pinned and the effective set stays plural.
    try testing.expect(r.max_link_prob <= bound.max_link_prob);
    try testing.expect(r.min_effective_set >= bound.min_effective_set);
    try testing.expect(r.holds(bound));
}

test "measure: a cover-starved transcript (one packet per mix) collapses the set" {
    // The no-cover failure mode: each mix sees a single real packet in
    // isolation, so there is no crowd to hide in even with a smooth kernel.
    const gpa = testing.allocator;
    const transits = [_]Transit{
        tr(0, 0, 41, 100),
        tr(1, 60, 98, 101),
        tr(2, 120, 165, 102),
    };
    const r = try measure(gpa, &transits, .{ .exponential = 40.0 });
    try testing.expectEqual(@as(usize, 3), r.targets);
    // Alone in its pool, every target is fully exposed.
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.min_effective_set, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.max_link_prob, 1e-9);
    try testing.expect(!r.holds(AnonymityBound{}));
}

test "measure: cover transits enlarge a real target's crowd without being scored" {
    // Same real packet, but now three COVER departures share its mix and time
    // window. It is not counted as a target (targets stays 1) yet it swells the
    // pool the real target hides in — effective set climbs above 1, and the
    // real packet is no longer pinned.
    const gpa = testing.allocator;
    const c = MsgKind.drop_cover;
    const transits = [_]Transit{
        tr(0, 10, 50, 1), // the lone real target
        .{ .mix = 0, .arrival = 8, .departure = 46, .kind = c, .id = 900 },
        .{ .mix = 0, .arrival = 12, .departure = 55, .kind = c, .id = 901 },
        .{ .mix = 0, .arrival = 9, .departure = 60, .kind = c, .id = 902 },
    };
    const r = try measure(gpa, &transits, .{ .exponential = 40.0 });
    try testing.expectEqual(@as(usize, 1), r.targets); // cover is never a target
    try testing.expect(r.min_effective_set > 1.5); // real target now has a crowd
    try testing.expect(r.max_link_prob < 1.0); // …and is no longer pinned
}

test "measure: no real traffic is vacuously anonymous" {
    const gpa = testing.allocator;
    const r = try measure(gpa, &.{}, .{ .exponential = 40.0 });
    try testing.expectEqual(@as(usize, 0), r.targets);
    try testing.expect(r.holds(AnonymityBound{}));
}

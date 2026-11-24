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
    /// Which mix hop of its route this pass was (0 = first layer). With `id`,
    /// it is how `measureEndToEnd` finds the pass BEFORE this one — which the
    /// adversary sees as "this arrival came over that link from that
    /// departure" (see there).
    hop: u8 = 0,
    /// Where the packet went on leaving the mix (the link it took: a next mix,
    /// a provider or a client). The adversary watches every link, so this is
    /// observable; `measureReceiver` reads the last hop's.
    to: NodeId = 0,
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
    /// A batch-and-reorder mix (threshold or timed): everything it holds is
    /// released at ONE instant, in random order. The adversary sees the
    /// release instants (departure times shared by a burst); a packet that
    /// arrived at `a` leaves in the first release at or after `a`, and is
    /// equally likely to be any packet of that burst. So its anonymity set is
    /// the batch, and the linking probability `1/batch`.
    batch,

    /// The likelihood of a departure at `departure` for an arrival at
    /// `arrival`; `flush` is the first release instant at or after `arrival`
    /// (only read by `.batch`).
    fn weight(self: DelayModel, arrival: Time, departure: Time, flush: Time) f64 {
        if (self == .batch) return if (departure == flush) 1.0 else 0.0;
        return self.kernel(@as(i128, @intCast(departure)) - @as(i128, @intCast(arrival)));
    }

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
            .batch => unreachable, // `weight` answers for it
        };
    }
};

/// The first departure at or after `arrival` (`maxInt` if none): the release
/// instant a batch mix lets an arrival leave in.
fn firstFlush(deps: []const Time, arrival: Time) Time {
    var f: Time = std.math.maxInt(Time);
    for (deps) |d| {
        if (d >= arrival and d < f) f = d;
    }
    return f;
}

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
        const flush = if (model == .batch) firstFlush(deps, t.arrival) else 0;
        var total: f64 = 0;
        var true_weight: f64 = 0;
        var true_coincident: f64 = 0; // departures sharing the true timestamp
        for (deps) |d| {
            const w = model.weight(t.arrival, d, flush);
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
                const w = model.weight(t.arrival, d, flush);
                if (w <= 0) continue;
                const p = w / total;
                h -= p * std.math.log2(p);
            }
            eff_set = std.math.exp2(h);
            // Posterior mass on the true match. Departures sharing its exact
            // timestamp are indistinguishable, so the true one gets its fair
            // share of their combined mass: (k·w / total) / k = w / total.
            // (Review, L-01: this used to divide by k a second
            // time — 1/k² — so a batch mix releasing k at once scored as if
            // it hid each packet among k² departures.)
            std.debug.assert(true_coincident >= 1);
            link_prob = true_weight / total;
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

// ── end-to-end: which CLIENT sent this packet? ──────────────────────────────
//
// `measure` scores one mix at a time. Loopix's guarantee is end to end: a
// packet leaving the last layer must not be traceable to its sender through
// ALL the layers. The adversary composes the per-mix inference backward:
//
//   - at the first layer every arrival came over a client's link, so its
//     sender distribution is a point mass on that client (the GPA sees which
//     client transmitted; it cannot see what);
//   - a departure from mix M at time d is, to the adversary, one of the
//     packets that arrived at M before d, weighted by the mix's own hold law
//     `kernel(d − a)` — exactly `measure`'s posterior, run backward — so its
//     sender distribution is the weighted mix of those arrivals' distributions;
//   - an arrival at the next layer is the departure that crossed that link (the
//     GPA watches every link; matching a link's transmissions to its deliveries
//     is observation, not inference). The harness finds that departure by
//     `(id, hop − 1)`, which is the oracle's shortcut for the same fact.
//
// Scored on REAL packets at their last mix: the effective number of possible
// senders `2^H` (at most the number of clients) and the posterior mass on the
// true one. Cover packets are senders' traffic too — they carry their sender's
// point mass and blur everyone else's, which is the point of cover.
//
// Like `measure`, the posterior treats each departure independently (a
// relaxation of the true one-to-one matching), which can only make the
// adversary weaker in the tails it double-counts — the positive controls below
// show it is still strong enough to pin a FIFO or cover-starved network.

/// A packet's ground truth as injected: who sent it and, for application
/// traffic, whom it is for.
pub const Origin = struct {
    id: u64,
    /// The sending client (meaningless when `from_mix`).
    client: u8,
    /// The receiving client, when the packet is addressed to one.
    recipient: ?u8 = null,
    /// A loop a MIX sent to itself: no client sent it, so it carries no
    /// sender mass at all (it blurs other packets' posteriors, which is what
    /// mix-originated cover is for, but names nobody).
    from_mix: bool = false,
};

pub const SenderResult = struct {
    targets: usize = 0,
    /// Distributions the adversary could not derive and fell back to uniform
    /// on: a first-layer packet with no recorded origin, a later arrival with
    /// no recorded previous pass, a departure no arrival could explain. Each
    /// one ADDS anonymity the transcript did not earn, so a complete
    /// transcript must report 0 (the tests require it).
    fallbacks: usize = 0,
    mean_sender_set: f64 = 0,
    min_sender_set: f64 = std.math.inf(f64),
    mean_link_prob: f64 = 0,
    max_link_prob: f64 = 0,
    /// Third-party sender–receiver unlinkability (Piotrowska 2021, after the
    /// Loopix paper): for every real packet, the leakage
    /// `ε = ln(Pr[true sender] / Pr[S2])` against every other client `S2` the
    /// adversary has not ruled out (`Pr` floored at `1e-12`, so a sender the
    /// adversary pins gives ≈ 27.6 nats), averaged over those pairs and over
    /// packets. 0 = the adversary cannot tell the true sender from anyone
    /// else; the worst packet is `max_epsilon`.
    mean_epsilon: f64 = 0,
    max_epsilon: f64 = 0,

    pub fn holds(self: SenderResult, bound: types.SenderBound) bool {
        if (self.targets == 0) return true;
        return self.min_sender_set >= bound.min_sender_set and self.max_link_prob <= bound.max_link_prob;
    }

    /// Does the leakage stay below `bound.max_mean_epsilon`?
    pub fn unlinkable(self: SenderResult, bound: types.UnlinkBound) bool {
        return self.targets == 0 or self.mean_epsilon <= bound.max_mean_epsilon;
    }
};

const eps_floor = 1e-12;

fn groupKey(t: Transit) u64 {
    return (@as(u64, t.mix) << 8) | t.hop;
}

/// What both end-to-end measures index: the passes of each (mix, hop) group,
/// the pass of an id at a hop (the link observation) and, for a batch mix,
/// each arrival's release instant. Grouping by hop as well as mix credits the
/// adversary with knowing a pass's position in its route — which a layered
/// topology gives away for free, and a free route does not (there it is a
/// STRONGER adversary than the real one, so its anonymity is understated).
const Index = struct {
    const Key = struct { id: u64, hop: u8 };
    at: std.AutoHashMapUnmanaged(Key, usize) = .empty,
    groups: std.AutoHashMapUnmanaged(u64, std.ArrayListUnmanaged(usize)) = .empty,
    flush: []Time = &.{},

    fn init(gpa: Allocator, transits: []const Transit, model: DelayModel) Allocator.Error!Index {
        var ix = Index{};
        errdefer ix.deinit(gpa);
        for (transits, 0..) |t, i| {
            try ix.at.put(gpa, .{ .id = t.id, .hop = t.hop }, i);
            const gop = try ix.groups.getOrPut(gpa, groupKey(t));
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(gpa, i);
        }
        ix.flush = try gpa.alloc(Time, transits.len);
        @memset(ix.flush, 0);
        if (model == .batch) {
            var it = ix.groups.valueIterator();
            while (it.next()) |list| {
                for (list.items) |u| {
                    var f: Time = std.math.maxInt(Time);
                    for (list.items) |i| {
                        const d = transits[i].departure;
                        if (d >= transits[u].arrival and d < f) f = d;
                    }
                    ix.flush[u] = f;
                }
            }
        }
        return ix;
    }

    fn deinit(self: *Index, gpa: Allocator) void {
        self.at.deinit(gpa);
        var it = self.groups.valueIterator();
        while (it.next()) |l| l.deinit(gpa);
        self.groups.deinit(gpa);
        gpa.free(self.flush);
    }
};

/// Sender anonymity of every real packet that completed hop `last_hop`, given
/// the transcript, every packet's origin, the number of clients and the mixes'
/// hold law. `O(Σ_mix pool² × clients)`.
pub fn measureEndToEnd(
    gpa: Allocator,
    transits: []const Transit,
    origins: []const Origin,
    clients: u8,
    last_hop: u8,
    model: DelayModel,
) Allocator.Error!SenderResult {
    const c: usize = clients;
    const n = transits.len;
    var origin_of: std.AutoHashMapUnmanaged(u64, Origin) = .empty;
    defer origin_of.deinit(gpa);
    for (origins) |o| try origin_of.put(gpa, o.id, o);

    var ix = try Index.init(gpa, transits, model);
    defer ix.deinit(gpa);

    const uniform = 1.0 / @as(f64, @floatFromInt(c));
    const dist_in = try gpa.alloc(f64, n * c);
    defer gpa.free(dist_in);
    @memset(dist_in, uniform);
    const dist_out = try gpa.alloc(f64, n * c);
    defer gpa.free(dist_out);
    @memset(dist_out, uniform);
    var fallbacks: usize = 0;

    for (0..@as(usize, last_hop) + 1) |hop_usize| {
        const hop: u8 = @intCast(hop_usize);
        // What each arrival at this layer could be, as a sender distribution.
        for (transits, 0..) |t, i| {
            if (t.hop != hop) continue;
            const row = dist_in[i * c ..][0..c];
            if (hop == 0) {
                @memset(row, 0);
                if (origin_of.get(t.id)) |o| {
                    if (!o.from_mix) row[o.client] = 1;
                } else {
                    @memset(row, uniform);
                    fallbacks += 1;
                }
            } else if (ix.at.get(.{ .id = t.id, .hop = hop - 1 })) |prev| {
                @memcpy(row, dist_out[prev * c ..][0..c]);
            } else {
                @memset(row, uniform);
                fallbacks += 1;
            }
        }
        // What each departure from a mix of this layer could be.
        var it = ix.groups.valueIterator();
        while (it.next()) |list| {
            if (transits[list.items[0]].hop != hop) continue;
            for (list.items) |i| {
                const row = dist_out[i * c ..][0..c];
                @memset(row, 0);
                var total: f64 = 0;
                for (list.items) |u| {
                    const w = model.weight(transits[u].arrival, transits[i].departure, ix.flush[u]);
                    if (w <= 0) continue;
                    total += w;
                    for (row, dist_in[u * c ..][0..c]) |*r, d| r.* += w * d;
                }
                if (total > 0) {
                    for (row) |*r| r.* /= total;
                } else {
                    @memset(row, uniform);
                    fallbacks += 1;
                }
            }
        }
    }

    var res = SenderResult{ .fallbacks = fallbacks };
    var sum_set: f64 = 0;
    var sum_link: f64 = 0;
    var sum_eps: f64 = 0;
    for (transits, 0..) |t, i| {
        if (t.kind != .real or t.hop != last_hop) continue;
        const o = origin_of.get(t.id) orelse continue;
        if (o.from_mix) continue;
        const src = o.client;
        // The sender is a client (the packet is real), so condition on that:
        // mass the adversary put on "a mix sent it" is not a client's.
        const row = dist_out[i * c ..][0..c];
        var mass: f64 = 0;
        for (row) |p| mass += p;
        if (mass <= 0) continue;
        var h: f64 = 0;
        var eps: f64 = 0;
        const p_true = @max(row[src] / mass, eps_floor);
        for (row, 0..) |p, k| {
            const q = p / mass;
            if (q > 0) h -= q * std.math.log2(q);
            if (k != src and c > 1) eps += @log(p_true / @max(q, eps_floor));
        }
        if (c > 1) eps /= @as(f64, @floatFromInt(c - 1));
        const set = std.math.exp2(h);
        const link = row[src] / mass;
        res.targets += 1;
        sum_set += set;
        sum_link += link;
        sum_eps += eps;
        res.min_sender_set = @min(res.min_sender_set, set);
        res.max_link_prob = @max(res.max_link_prob, link);
        res.max_epsilon = @max(res.max_epsilon, eps);
    }
    if (res.targets > 0) {
        const k: f64 = @floatFromInt(res.targets);
        res.mean_sender_set = sum_set / k;
        res.mean_link_prob = sum_link / k;
        res.mean_epsilon = sum_eps / k;
    } else res.min_sender_set = 0;
    return res;
}

pub const ReceiverResult = struct {
    targets: usize = 0,
    /// As in `SenderResult`: distributions that fell back to uniform.
    fallbacks: usize = 0,
    mean_receiver_set: f64 = 0,
    min_receiver_set: f64 = std.math.inf(f64),
    mean_link_prob: f64 = 0,
    max_link_prob: f64 = 0,

    pub fn holds(self: ReceiverResult, bound: types.ReceiverBound) bool {
        if (self.targets == 0) return true;
        return self.min_receiver_set >= bound.min_receiver_set and self.max_link_prob <= bound.max_link_prob;
    }
};

/// RECEIVER anonymity of every real packet (sender known to the adversary:
/// it sees which client transmitted): the posterior over which client it is
/// for, composed FORWARD through every layer. At a mix, an arrival becomes
/// departure `i` with probability `∝ weight(i)` (the mix's own hold law);
/// a departure's link is observed, so the next layer's arrival is that same
/// packet; a last-hop departure's link names the receiver — a client, or with
/// providers every client of the provider uniformly (`exit_rows`, from
/// `LoopixConfig.exitRows`: row `node * clients ..`). Scored per real
/// packet: effective set `2^H` over the clients and the mass on the true
/// recipient (`Origin.recipient`). `O(Σ_mix pool² × clients)`.
pub fn measureReceiver(
    gpa: Allocator,
    transits: []const Transit,
    origins: []const Origin,
    exit_rows: []const f64,
    clients: u8,
    last_hop: u8,
    model: DelayModel,
) Allocator.Error!ReceiverResult {
    const c: usize = clients;
    const n = transits.len;
    var origin_of: std.AutoHashMapUnmanaged(u64, Origin) = .empty;
    defer origin_of.deinit(gpa);
    for (origins) |o| try origin_of.put(gpa, o.id, o);

    var ix = try Index.init(gpa, transits, model);
    defer ix.deinit(gpa);

    const uniform = 1.0 / @as(f64, @floatFromInt(c));
    const r_in = try gpa.alloc(f64, n * c);
    defer gpa.free(r_in);
    @memset(r_in, uniform);
    const r_out = try gpa.alloc(f64, n * c);
    defer gpa.free(r_out);
    @memset(r_out, uniform);
    var fallbacks: usize = 0;

    var hop_i: usize = @as(usize, last_hop) + 1;
    while (hop_i > 0) {
        hop_i -= 1;
        const hop: u8 = @intCast(hop_i);
        // Where each departure of this layer ends up.
        for (transits, 0..) |t, i| {
            if (t.hop != hop) continue;
            const row = r_out[i * c ..][0..c];
            if (hop == last_hop) {
                if ((@as(usize, t.to) + 1) * c <= exit_rows.len) {
                    @memcpy(row, exit_rows[@as(usize, t.to) * c ..][0..c]);
                } else {
                    @memset(row, uniform);
                    fallbacks += 1;
                }
            } else if (ix.at.get(.{ .id = t.id, .hop = hop + 1 })) |next| {
                @memcpy(row, r_in[next * c ..][0..c]);
            } else {
                @memset(row, uniform);
                fallbacks += 1;
            }
        }
        // What each arrival of this layer becomes.
        var it = ix.groups.valueIterator();
        while (it.next()) |list| {
            if (transits[list.items[0]].hop != hop) continue;
            for (list.items) |u| {
                const row = r_in[u * c ..][0..c];
                @memset(row, 0);
                var total: f64 = 0;
                for (list.items) |i| {
                    const w = model.weight(transits[u].arrival, transits[i].departure, ix.flush[u]);
                    if (w <= 0) continue;
                    total += w;
                    for (row, r_out[i * c ..][0..c]) |*r, d| r.* += w * d;
                }
                if (total > 0) {
                    for (row) |*r| r.* /= total;
                } else {
                    @memset(row, uniform);
                    fallbacks += 1;
                }
            }
        }
    }

    var res = ReceiverResult{ .fallbacks = fallbacks };
    var sum_set: f64 = 0;
    var sum_link: f64 = 0;
    for (transits, 0..) |t, i| {
        if (t.kind != .real or t.hop != 0) continue;
        const o = origin_of.get(t.id) orelse continue;
        const dst = o.recipient orelse continue;
        const row = r_in[i * c ..][0..c];
        var mass: f64 = 0;
        for (row) |p| mass += p;
        if (mass <= 0) continue;
        var h: f64 = 0;
        for (row) |p| {
            const q = p / mass;
            if (q > 0) h -= q * std.math.log2(q);
        }
        const set = std.math.exp2(h);
        const link = row[dst] / mass;
        res.targets += 1;
        sum_set += set;
        sum_link += link;
        res.min_receiver_set = @min(res.min_receiver_set, set);
        res.max_link_prob = @max(res.max_link_prob, link);
    }
    if (res.targets > 0) {
        const k: f64 = @floatFromInt(res.targets);
        res.mean_receiver_set = sum_set / k;
        res.mean_link_prob = sum_link / k;
    } else res.min_receiver_set = 0;
    return res;
}

// ── the memoryless-vs-order-preserving distinguisher ─────────────────────────

/// Reordering statistic over a transit transcript: among every pair of packets
/// that were held by the SAME mix at the same time (the second arrived while
/// the first was still in the pool — "co-resident"), how often did the LATER
/// arrival depart FIRST ("an inversion")?
///
/// This is the deterministic, checkable consequence of memorylessness:
///  - **Correct memoryless (geometric/exponential) mix:** at the moment the
///    second packet arrives, the first packet's REMAINING hold is distributed
///    exactly like a fresh draw (that is what memoryless means), so the two
///    race as i.i.d. holds and the later arrival wins just under 1/2 of the
///    time (slightly under, because exact ties count as non-inversions).
///    Expected fraction ≈ 0.5 − O(1/mean).
///  - **Constant-hold mix:** departure = arrival + c, so a later arrival can
///    NEVER depart first. Fraction = 0.
///  - **FIFO release discipline (any hold law):** identities leave in arrival
///    order by construction. Fraction = 0.
/// The gap is 0.5 vs 0.0 — categorical, not statistical — so a mid threshold
/// (e.g. ≥ 0.35 over hundreds of pairs) can never flake on the correct mix nor
/// pass an order-preserving one.
pub const ReorderStats = struct {
    /// Co-resident pairs examined (same mix, overlapping hold intervals,
    /// distinct arrival ticks).
    pairs: usize = 0,
    /// Pairs where the later arrival departed strictly first.
    inversions: usize = 0,

    pub fn fraction(self: ReorderStats) f64 {
        if (self.pairs == 0) return 0;
        return @as(f64, @floatFromInt(self.inversions)) / @as(f64, @floatFromInt(self.pairs));
    }
};

/// Compute `ReorderStats` over a transcript. All kinds count (real and cover
/// are held under the same law — the statistic is about the mix, not the
/// traffic class). Pairs arriving on the same tick are skipped (no defined
/// arrival order to invert). O(n²) over the transcript — fine at sim scale.
pub fn reorderStats(transits: []const Transit) ReorderStats {
    var st = ReorderStats{};
    for (transits, 0..) |a, i| {
        for (transits[i + 1 ..]) |b| {
            if (a.mix != b.mix) continue;
            if (a.arrival == b.arrival) continue; // simultaneous: order undefined
            const first = if (a.arrival < b.arrival) a else b;
            const second = if (a.arrival < b.arrival) b else a;
            if (second.arrival >= first.departure) continue; // never co-resident
            st.pairs += 1;
            if (second.departure < first.departure) st.inversions += 1;
        }
    }
    return st;
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
    // `usize`, not `u64`: this loop indexes the fixed test array `deps[i]`,
    // and every other use of `i` here (`tr`'s `arr: Time`/`id: u64` params)
    // widens implicitly from `usize` — there was no actual need for `u64`.
    var i: usize = 0;
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

test "reorderStats: order-preserving transcripts score exactly zero" {
    const gpa = testing.allocator;
    // Constant hold: 8 packets, arrivals 0,10,…, departures arrival+40 — the
    // FifoMix picture. Later arrival can never depart first.
    var list: std.ArrayListUnmanaged(Transit) = .empty;
    defer list.deinit(gpa);
    // `usize`, not `u64`: reused below to index `deps_sorted[i]`, and neither
    // loop needs `u64` range — `tr`'s `arr`/`dep: Time` and `id: u64` params
    // all widen implicitly from `usize`.
    var i: usize = 0;
    while (i < 8) : (i += 1) try list.append(gpa, tr(0, i * 10, i * 10 + 40, i));
    const st = reorderStats(list.items);
    try testing.expect(st.pairs >= 10); // plenty of co-resident pairs examined
    try testing.expectEqual(@as(usize, 0), st.inversions);

    // FIFO discipline with SPREAD departure times (exponential timer multiset,
    // identities released front-first): timing looks memoryless, identity order
    // is still arrival order — the statistic must still score zero.
    var fifo_ids: std.ArrayListUnmanaged(Transit) = .empty;
    defer fifo_ids.deinit(gpa);
    const deps_sorted = [_]Time{ 12, 25, 30, 38, 42, 48, 55, 61 }; // sorted = FIFO pairing
    i = 0;
    while (i < deps_sorted.len) : (i += 1) try fifo_ids.append(gpa, tr(0, i, deps_sorted[i], i));
    const st2 = reorderStats(fifo_ids.items);
    try testing.expect(st2.pairs >= 10);
    try testing.expectEqual(@as(usize, 0), st2.inversions);
}

test "reorderStats: an interleaved (memoryless-looking) transcript scores near 1/2" {
    const gpa = testing.allocator;
    var list: std.ArrayListUnmanaged(Transit) = .empty;
    defer list.deinit(gpa);
    // The well-mixed synthetic from the `measure` test: clustered arrivals,
    // departures genuinely re-ordered vs arrival.
    const deps = [_]Time{ 55, 30, 80, 42, 12, 95, 61, 25, 70, 38, 105, 48 };
    // `usize`, not `u64`: same reasoning as the sibling "well-mixed
    // transcript" test above — this loop indexes the fixed test array
    // `deps[i]`, and `tr`'s `arr: Time`/`id: u64` params both widen
    // implicitly from `usize`, so there was no actual need for `u64`.
    var i: usize = 0;
    while (i < deps.len) : (i += 1) try list.append(gpa, tr(0, i, deps[i], i));
    const st = reorderStats(list.items);
    try testing.expect(st.pairs >= 30);
    const f = st.fraction();
    try testing.expect(f > 0.3 and f < 0.7); // a real shuffle, not order-preserving
}

fn trh(mix: NodeId, arr: Time, dep: Time, id: u64, hop: u8, kind: MsgKind) Transit {
    return .{ .mix = mix, .arrival = arr, .departure = dep, .kind = kind, .id = id, .hop = hop };
}

test "measureEndToEnd: an order-preserving two-layer path pins the sender" {
    const gpa = testing.allocator;
    // Two clients, one mix per layer, holds of exactly 10: each departure
    // matches exactly one arrival under the constant law.
    const ts = [_]Transit{
        trh(0, 0, 10, 1, 0, .real),  trh(0, 3, 13, 2, 0, .real),
        trh(1, 15, 25, 1, 1, .real), trh(1, 18, 28, 2, 1, .real),
    };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 } };
    const r = try measureEndToEnd(gpa, &ts, &os, 2, 1, .{ .constant = .{ .delta = 10, .tol = 0 } });
    try testing.expectEqual(@as(usize, 2), r.targets);
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.min_sender_set, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.max_link_prob, 1e-9);
}

test "measureEndToEnd: two layers of mixing compose — the second layer blurs what the first left" {
    const gpa = testing.allocator;
    // Layer 0 is a pure FIFO (constant kernel would pin), but scored with an
    // exponential law the two co-resident packets are mixed at EACH layer, and
    // composing two such layers brings the sender posterior closer to uniform
    // than one layer does.
    const ts = [_]Transit{
        trh(0, 0, 20, 1, 0, .real),        trh(0, 2, 18, 2, 0, .drop_cover),
        trh(1, 22, 41, 2, 1, .drop_cover), trh(1, 24, 44, 1, 1, .real),
    };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 } };
    const model = DelayModel{ .exponential = 20 };
    const one = try measureEndToEnd(gpa, &ts, &os, 2, 0, model);
    const two = try measureEndToEnd(gpa, &ts, &os, 2, 1, model);
    try testing.expectEqual(@as(usize, 1), one.targets);
    try testing.expectEqual(@as(usize, 1), two.targets);
    try testing.expect(one.min_sender_set > 1.2); // mixed already
    try testing.expect(two.min_sender_set >= one.min_sender_set - 1e-9);
    try testing.expect(two.max_link_prob < 0.75);
}

test "measure: departures tied with the true one share its mass — 1/k, not 1/k²" {
    const gpa = testing.allocator;
    // Two packets in at t=0 and t=0, both out at t=10 (a batch of two): the
    // adversary cannot tell which is which, so each is 1/2 linkable.
    const ts = [_]Transit{ tr(0, 0, 10, 1), tr(0, 0, 10, 2) };
    const r = try measure(gpa, &ts, .{ .constant = .{ .delta = 10, .tol = 0 } });
    try testing.expectApproxEqAbs(@as(f64, 0.5), r.max_link_prob, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 2.0), r.min_effective_set, 1e-9);
}

test "measureEndToEnd: a transcript the adversary cannot follow is COUNTED, not silently uniform" {
    const gpa = testing.allocator;
    // Hop 1 with no hop-0 pass for its id, and no origin for it either.
    const ts = [_]Transit{trh(1, 15, 25, 9, 1, .real)};
    const r = try measureEndToEnd(gpa, &ts, &.{.{ .id = 9, .client = 0 }}, 2, 1, .{ .exponential = 10 });
    try testing.expect(r.fallbacks > 0);
}

test "measureEndToEnd: no real traffic is vacuously anonymous" {
    const gpa = testing.allocator;
    const r = try measureEndToEnd(gpa, &.{}, &.{}, 3, 2, .{ .exponential = 10 });
    try testing.expectEqual(@as(usize, 0), r.targets);
    try testing.expect(r.holds(.{}));
}

test "measure: no real traffic is vacuously anonymous" {
    const gpa = testing.allocator;
    const r = try measure(gpa, &.{}, .{ .exponential = 40.0 });
    try testing.expectEqual(@as(usize, 0), r.targets);
    try testing.expect(r.holds(AnonymityBound{}));
}

test "measure: a batch mix hides a packet among its batch, 1/k each; a lone packet in a round is pinned" {
    const gpa = testing.allocator;
    // Round at t=50: four packets (arrivals 3..30) leave together. Round at t=90:
    // one packet alone.
    const ts = [_]Transit{ tr(0, 3, 50, 1), tr(0, 10, 50, 2), tr(0, 22, 50, 3), tr(0, 30, 50, 4), tr(0, 60, 90, 5) };
    const r = try measure(gpa, &ts, .batch);
    try testing.expectEqual(@as(usize, 5), r.targets);
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.min_effective_set, 1e-9); // the lone one
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.max_link_prob, 1e-9);
    // Without it, the batch of four is a uniform crowd.
    const r4 = try measure(gpa, ts[0..4], .batch);
    try testing.expectApproxEqAbs(@as(f64, 4.0), r4.min_effective_set, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 0.25), r4.max_link_prob, 1e-9);
}

test "measureEndToEnd: batch law, and a pinned sender leaks the floor ε, a uniform one none" {
    const gpa = testing.allocator;
    // Two clients, one mix: both packets in one batch ⇒ sender 50/50, ε = 0.
    const ts = [_]Transit{ trh(0, 0, 20, 1, 0, .real), trh(0, 5, 20, 2, 0, .real) };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 } };
    const mixed = try measureEndToEnd(gpa, &ts, &os, 2, 0, .batch);
    try testing.expectApproxEqAbs(@as(f64, 2.0), mixed.min_sender_set, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 0.0), mixed.max_epsilon, 1e-9);
    try testing.expect(mixed.unlinkable(.{ .max_mean_epsilon = 0.01 }));
    // Two rounds of one packet each: pinned, ε = ln(1 / 1e-12).
    const alone = [_]Transit{ trh(0, 0, 20, 1, 0, .real), trh(0, 25, 40, 2, 0, .real) };
    const pinned = try measureEndToEnd(gpa, &alone, &os, 2, 0, .batch);
    try testing.expectApproxEqAbs(@log(1.0 / eps_floor), pinned.mean_epsilon, 1e-6);
    try testing.expect(!pinned.unlinkable(.{}));
}

test "measureEndToEnd: a mix's own loop carries no sender mass and is not scored" {
    const gpa = testing.allocator;
    // A client packet and a mix loop share one batch: the packet's sender is
    // the client with certainty (the loop names nobody), and the loop is no target.
    const ts = [_]Transit{ trh(0, 0, 20, 1, 0, .real), trh(0, 5, 20, 2, 0, .loop_cover) };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 0, .from_mix = true } };
    const r = try measureEndToEnd(gpa, &ts, &os, 2, 0, .batch);
    try testing.expectEqual(@as(usize, 1), r.targets);
    try testing.expectEqual(@as(usize, 0), r.fallbacks);
    try testing.expectApproxEqAbs(@as(f64, 1.0), r.max_link_prob, 1e-9);
}

fn trTo(mix: NodeId, arr: Time, dep: Time, id: u64, hop: u8, to: NodeId) Transit {
    return .{ .mix = mix, .arrival = arr, .departure = dep, .kind = .real, .id = id, .hop = hop, .to = to };
}

test "measureReceiver: an order-preserving mix pins the receiver; mixing and a shared provider spread it" {
    const gpa = testing.allocator;
    // Nodes 5 and 6 are the exits; 2 clients. Row of node n at n*2.
    var rows: [7 * 2]f64 = @splat(0);
    rows[5 * 2 + 0] = 1; // exit 5 = client 0
    rows[6 * 2 + 1] = 1; // exit 6 = client 1
    const os = [_]Origin{ .{ .id = 1, .client = 0, .recipient = 0 }, .{ .id = 2, .client = 1, .recipient = 1 } };
    const fifo = [_]Transit{ trTo(0, 0, 10, 1, 0, 5), trTo(0, 3, 13, 2, 0, 6) };
    const pinned = try measureReceiver(gpa, &fifo, &os, &rows, 2, 0, .{ .constant = .{ .delta = 10, .tol = 0 } });
    try testing.expectEqual(@as(usize, 2), pinned.targets);
    try testing.expectApproxEqAbs(@as(f64, 1.0), pinned.min_receiver_set, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 1.0), pinned.max_link_prob, 1e-9);
    try testing.expect(!pinned.holds(.{}));
    // One batch, two exits: each packet is for either client with equal odds.
    const batch = [_]Transit{ trTo(0, 0, 10, 1, 0, 5), trTo(0, 3, 10, 2, 0, 6) };
    const mixed = try measureReceiver(gpa, &batch, &os, &rows, 2, 0, .batch);
    try testing.expectApproxEqAbs(@as(f64, 2.0), mixed.min_receiver_set, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 0.5), mixed.max_link_prob, 1e-9);
    try testing.expect(mixed.holds(.{ .min_receiver_set = 2.0, .max_link_prob = 0.5 }));
    // A shared provider (row uniform over both clients) hides it even from a FIFO mix.
    rows[5 * 2 + 0] = 0.5;
    rows[5 * 2 + 1] = 0.5;
    rows[6 * 2 + 0] = 0.5;
    rows[6 * 2 + 1] = 0.5;
    const provider = try measureReceiver(gpa, &fifo, &os, &rows, 2, 0, .{ .constant = .{ .delta = 10, .tol = 0 } });
    try testing.expectApproxEqAbs(@as(f64, 2.0), provider.min_receiver_set, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 0.5), provider.max_link_prob, 1e-9);
}

test "measureReceiver: composes forward over two layers; an unobserved next hop is counted" {
    const gpa = testing.allocator;
    var rows: [8 * 2]f64 = @splat(0);
    rows[6 * 2 + 0] = 1;
    rows[7 * 2 + 1] = 1;
    const os = [_]Origin{ .{ .id = 1, .client = 0, .recipient = 0 }, .{ .id = 2, .client = 1, .recipient = 1 } };
    // Layer 0 batches both packets (mix 0, at 10); layer 1 is a FIFO (constant 5) that
    // would pin them, but the batch already blurred which is which.
    const ts = [_]Transit{
        trTo(0, 0, 10, 1, 0, 3),  trTo(0, 4, 10, 2, 0, 4),
        trTo(3, 12, 17, 1, 1, 6), trTo(4, 13, 18, 2, 1, 7),
    };
    // Different layer-1 mixes: layer 1 sees one packet each and pins its own
    // packet's exit, so the layer-0 batch is the only blur: 50/50 between the two.
    const r = try measureReceiver(gpa, &ts, &os, &rows, 2, 1, .{ .exponential = 5 });
    try testing.expectEqual(@as(usize, 2), r.targets);
    try testing.expectEqual(@as(usize, 0), r.fallbacks);
    try testing.expect(r.min_receiver_set > 1.5);
    // Drop the second-layer pass of packet 2: packet 1's chain is intact, but
    // the departure that was packet 2 now has no observed continuation.
    const cut = [_]Transit{ ts[0], ts[1], ts[2] };
    const c = try measureReceiver(gpa, &cut, &os, &rows, 2, 1, .{ .exponential = 5 });
    try testing.expect(c.fallbacks > 0);
}

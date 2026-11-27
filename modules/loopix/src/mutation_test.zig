// SPDX-License-Identifier: MIT

//! mutation_test — tests added by the 2026-11-27 whole-module mutation audit
//! (each one kills mutants the earlier suite let live). Expected values are
//! derived from the documented definitions (Serjantov–Danezis `2^H`, the
//! hold-law posterior of `adversary.zig`, splitmix64), not copied from a run of
//! the code: the adversary numbers come from an independent re-implementation
//! of the documented algorithm, the PRNG ones from the module's own
//! known-answer test.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");
const mixing = @import("mixing.zig");
const adversary = @import("adversary.zig");
const routing = @import("routing.zig");
const protocol = @import("protocol.zig");

const testing = std.testing;
const gpa = testing.allocator;
const Time = netsim.Time;
const NodeId = netsim.NodeId;
const MsgKind = types.MsgKind;
const Transit = adversary.Transit;
const Origin = adversary.Origin;
const LoopixConfig = types.LoopixConfig;

fn tp(mix: NodeId, arr: Time, dep: Time, id: u64, hop: u8, kind: MsgKind, to: NodeId) Transit {
    return .{ .mix = mix, .arrival = arr, .departure = dep, .kind = kind, .id = id, .hop = hop, .to = to };
}

fn near(want: f64, got: f64) !void {
    try testing.expectApproxEqAbs(want, got, 1e-9);
}

// ── mixing ───────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: Prng.init takes one step (decorrelates the seed); unit() is open at the all-zero draw" {
    // The known-answer test of mixing.zig: state 0 yields e220a8397b1dcdaf then
    // 6e789e6aa1b965f4, advancing the state by the splitmix gamma per draw. So
    // `init(0)` (one discarded draw) holds state gamma and its first draw is the
    // second known answer.
    var p = mixing.Prng.init(0);
    try testing.expectEqual(@as(u64, 0x9e3779b97f4a7c15), p.state);
    try testing.expectEqual(@as(u64, 0x6e789e6aa1b965f4), p.next());
    // splitmix64: next() = finalizer(state + gamma); the finalizer maps 0 to 0,
    // so the state -gamma draws exactly 0 — and unit() must still be inside the
    // OPEN interval (0, 1), because @log(0) would poison the exponential draw.
    var z: mixing.Prng = .{ .state = @as(u64, 0) -% 0x9e3779b97f4a7c15 };
    const u = z.unit();
    try testing.expect(u > 0.0 and u < 1.0);
}

test "mutation 2026-11-27: nextCover / nextMixLoop clamp the gap to one tick, and cover draws both kinds" {
    // mean 1: the exponential draw is 0 ticks, the clamp makes it exactly 1
    // (a 0-tick gap would re-arm the cover timer on the same tick forever).
    const cover1 = LoopixConfig{ .cover_mean_interval = 1, .mix_loop_interval = 50 };
    var p = mixing.Prng.init(5);
    var loops: usize = 0;
    var drops: usize = 0;
    for (0..400) |_| {
        const ev = mixing.nextCover(&p, cover1);
        try testing.expectEqual(@as(Time, 1), ev.delay);
        if (ev.kind == .loop_cover) loops += 1 else drops += 1;
    }
    // both chaff kinds occur, roughly evenly
    try testing.expect(loops > 100 and drops > 100);
    // the mix's own loop uses ITS interval (1), not the cover interval (50)
    const loop1 = LoopixConfig{ .cover_mean_interval = 50, .mix_loop_interval = 1 };
    for (0..200) |_| try testing.expectEqual(@as(Time, 1), mixing.nextMixLoop(&p, loop1));
}

test "mutation 2026-11-27: sampleExpDelay is geometric — P(0) = 1/mean, P(1) = (1 - 1/mean)/mean" {
    // The documented law is P(hold = k) = (1-p)^k p with p = 1/mean on {0,1,..};
    // rounding the continuous draw instead of flooring it halves P(0).
    var p = mixing.Prng.init(11);
    const n = 40_000;
    var c0: usize = 0;
    var c1: usize = 0;
    for (0..n) |_| switch (mixing.sampleExpDelay(&p, 4)) {
        0 => c0 += 1,
        1 => c1 += 1,
        else => {},
    };
    const f0 = @as(f64, @floatFromInt(c0)) / n;
    const f1 = @as(f64, @floatFromInt(c1)) / n;
    try testing.expectApproxEqAbs(@as(f64, 0.25), f0, 0.02);
    try testing.expectApproxEqAbs(@as(f64, 0.1875), f1, 0.02);
}

test "mutation 2026-11-27: scheduleRelease is arrival + a mean_delay draw" {
    var p = mixing.Prng.init(3);
    const cfg = LoopixConfig{}; // mean_delay 40, cover_mean_interval 15
    var sum: u64 = 0;
    const n = 20_000;
    for (0..n) |_| {
        const r = mixing.scheduleRelease(&p, cfg, 1000);
        try testing.expect(r >= 1000);
        sum += r - 1000;
    }
    // geometric mean (1-p)/p = 39 for mean_delay 40 (and 14 for the cover interval)
    const avg = @as(f64, @floatFromInt(sum)) / n;
    try testing.expect(avg > 36.0 and avg < 42.0);
}

// ── types ────────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: validate() refuses each out-of-range field and accepts the boundary values" {
    const bad = [_]LoopixConfig{
        .{ .width = 0 },
        .{ .clients = 0 },
        .{ .fetch_period = 0 },
        .{ .real_period = 0 },
        .{ .cover_mean_interval = 0 },
        .{ .mix_loop_alarm_lost = 0 },
        .{ .topology = .cascade, .width = 2 },
        .{ .threshold = 0 },
        .{ .batch_period = 0 },
        .{ .batch_period = (1 << 20) + 1 },
        .{ .layers = 5, .width = 50, .clients = 5, .providers = 1 }, // 256 nodes
        .{ .layers = types.max_layers + 1 },
        .{ .fetch_batch = 17 },
        .{ .mean_delay = (1 << 20) + 1 },
        .{ .providers = 4, .clients = 3 },
    };
    for (bad) |cfg| try testing.expectError(error.InvalidConfig, cfg.validate());
    const ok = [_]LoopixConfig{
        .{ .layers = types.max_layers },
        .{ .layers = 1 },
        .{ .fetch_batch = 16 },
        .{ .fetch_batch = 1 },
        .{ .mean_delay = 1 << 20 },
        .{ .providers = 3, .clients = 3 },
        .{ .batch_period = 1 << 20 },
        .{ .layers = 5, .width = 50, .clients = 5 }, // exactly 255 nodes
        .{ .topology = .cascade, .width = 1 },
        .{ .topology = .free_route, .layers = 3, .width = 1 },
    };
    for (ok) |cfg| try cfg.validate();
}

test "mutation 2026-11-27: node classification at the boundaries of mixes, clients and providers" {
    const cfg = LoopixConfig{ .layers = 3, .width = 3, .clients = 3, .providers = 2 };
    const mixes: NodeId = 9;
    try testing.expect(cfg.isMix(mixes - 1));
    try testing.expect(!cfg.isMix(mixes));
    try testing.expect(cfg.isClient(mixes));
    try testing.expect(cfg.isClient(mixes + 2));
    try testing.expect(!cfg.isClient(mixes + 3));
    try testing.expect(!cfg.isClient(mixes - 1));
    try testing.expect(cfg.isProvider(mixes + 3));
    try testing.expect(cfg.isProvider(mixes + 4));
    try testing.expect(!cfg.isProvider(mixes + 5)); // nodeCount()
    try testing.expect(!cfg.isProvider(mixes + 2));
    try testing.expectEqual(@as(NodeId, mixes + 3 + 1), cfg.providerNode(1));
    try testing.expectEqual(@as(NodeId, mixes + 1), cfg.clientNode(1));
    try testing.expectEqual(@as(u8, 2), cfg.clientIndex(mixes + 2));
    try testing.expectEqual(@as(NodeId, mixes + 3 + 1), cfg.providerOf(3)); // c % providers
    try testing.expectEqual(@as(?u8, 1), cfg.layerOf(3));
    try testing.expectEqual(@as(?u8, null), cfg.layerOf(mixes));
    try testing.expectEqual(@as(NodeId, 7), cfg.mixNode(2, 1));
    // not square: width != layers
    const wide = LoopixConfig{ .layers = 2, .width = 4 };
    try testing.expectEqual(@as(NodeId, 6), wide.mixNode(1, 2));
    try testing.expectEqual(@as(usize, 8), wide.mixCount());
    try testing.expectEqual(@as(usize, 8 + 3), wide.nodeCount());
}

test "mutation 2026-11-27: isExitMix — the last layer of a layered net, any mix of a free route, never a client" {
    const strat = LoopixConfig{ .layers = 3, .width = 2, .clients = 2 };
    try testing.expect(!strat.isExitMix(strat.mixNode(0, 0)));
    try testing.expect(!strat.isExitMix(strat.mixNode(1, 1)));
    try testing.expect(strat.isExitMix(strat.mixNode(2, 0)));
    try testing.expect(strat.isExitMix(strat.mixNode(2, 1)));
    try testing.expect(!strat.isExitMix(strat.clientNode(0)));
    const free = LoopixConfig{ .layers = 3, .width = 2, .clients = 2, .topology = .free_route };
    try testing.expect(free.isExitMix(free.mixNode(0, 0)));
    try testing.expect(free.isExitMix(free.mixNode(1, 1)));
    try testing.expect(!free.isExitMix(free.clientNode(0)));
    try testing.expect(!free.isExitMix(free.clientNode(1)));
}

test "mutation 2026-11-27: exitRows — a client is its own receiver, a provider every client it serves uniformly, all else 0" {
    const direct = LoopixConfig{ .layers = 2, .width = 2, .clients = 3 };
    const dr = try direct.exitRows(gpa);
    defer gpa.free(dr);
    try testing.expectEqual(direct.nodeCount() * 3, dr.len);
    for (0..direct.nodeCount()) |node| for (0..3) |i| {
        const want: f64 = if (node == direct.clientNode(@intCast(i))) 1.0 else 0.0;
        try testing.expectEqual(want, dr[node * 3 + i]);
    };
    // 5 clients behind 2 providers: provider 0 serves clients 0, 2, 4; provider 1 serves 1, 3
    const prov = LoopixConfig{ .layers = 2, .width = 2, .clients = 5, .providers = 2 };
    const pr = try prov.exitRows(gpa);
    defer gpa.free(pr);
    for (0..prov.nodeCount()) |node| for (0..5) |i| {
        var want: f64 = 0.0;
        for (0..2) |q| {
            if (node == prov.providerNode(@intCast(q)) and i % 2 == q) want = if (q == 0) 1.0 / 3.0 else 1.0 / 2.0;
        }
        try near(want, pr[node * 5 + i]);
    };
}

test "mutation 2026-11-27: a header of each message kind round-trips, and an unknown kind or flag byte is refused" {
    var h = MixHeader{ .kind = .drop_cover, .id = 0x0102030405060708, .hop = 2, .n_hops = 3, .route = .{ 1, 2, 3, 4, 5, 6, 7 }, .has_delays = true, .recipient = 77 };
    h.delays = .{ 10, 20, 30, 40, 50, 60, 70 };
    for ([_]MsgKind{ .real, .loop_cover, .drop_cover }) |k| {
        h.kind = k;
        const b = hdrBytes(h);
        try testing.expectEqual(h, try MixHeader.decode(&b));
    }
    var b = hdrBytes(h);
    b[0] = 3; // no such kind
    try testing.expectError(error.MalformedMixHeader, MixHeader.decode(&b));
    b = hdrBytes(h);
    b[11 + 7 * 4] = 2; // the has_delays flag is 0 or 1
    try testing.expectError(error.MalformedMixHeader, MixHeader.decode(&b));
    b = hdrBytes(h);
    try testing.expectError(error.MalformedMixHeader, MixHeader.decode(b[0 .. MixHeader.wire_len - 1]));
    // hop may equal n_hops (delivered) but not exceed it; n_hops may be max_layers but not more
    h.hop = 3;
    b = hdrBytes(h);
    _ = try MixHeader.decode(&b);
    h.hop = 4;
    b = hdrBytes(h);
    try testing.expectError(error.MalformedMixHeader, MixHeader.decode(&b));
    h.hop = 6;
    h.n_hops = 6;
    b = hdrBytes(h);
    _ = try MixHeader.decode(&b);
    h.n_hops = 7;
    h.hop = 0;
    b = hdrBytes(h);
    try testing.expectError(error.MalformedMixHeader, MixHeader.decode(&b));
    // navigation
    h.n_hops = 3;
    h.hop = 1;
    try testing.expectEqual(@as(NodeId, 2), h.currentMix());
    try testing.expectEqual(@as(NodeId, 3), h.nextHop());
    try testing.expect(!h.atLastMix());
    h.hop = 2;
    try testing.expect(h.atLastMix());
}

// ── routing ──────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: mix64 is the splitmix64 finalizer (the std generator is the oracle)" {
    for ([_]u64{ 0, 1, 2, 0xdeadbeef, 0x9e3779b97f4a7c15, std.math.maxInt(u64) }) |x| {
        var sm = std.Random.SplitMix64.init(x);
        try testing.expectEqual(sm.next(), routing.mix64(x));
    }
}

test "mutation 2026-11-27: a stratified route reaches every mix of a layer; a free route fits width 1" {
    const cfg = LoopixConfig{ .layers = 3, .width = 3, .clients = 3 };
    var seen: [3][3]bool = @splat(@splat(false));
    var h: types.MixHeader = undefined;
    for (0..200) |k| {
        routing.pickRoute(cfg, k * 7919 + 1, cfg.clientNode(1), &h);
        for (0..3) |layer| seen[layer][@as(usize, h.route[layer]) - layer * 3] = true;
    }
    for (seen) |row| for (row) |s| try testing.expect(s);
    // a free route of `layers` out of exactly `layers` mixes is a permutation
    const free = LoopixConfig{ .layers = 3, .width = 1, .clients = 2, .topology = .free_route };
    try free.validate();
    for (0..50) |k| {
        routing.pickRoute(free, k + 1, free.clientNode(0), &h);
        var mask: u8 = 0;
        for (h.route[0..3]) |m| mask |= @as(u8, 1) << @intCast(m);
        try testing.expectEqual(@as(u8, 0b111), mask);
    }
}

// ── adversary: measure ───────────────────────────────────────────────────────

test "mutation 2026-11-27: measure weighs holds — zero hold counts, a departure before arrival never, shorter beats longer" {
    // zero hold: a lone packet leaving on its arrival tick is fully linkable
    const z = [_]Transit{tp(0, 10, 10, 1, 0, .real, 0)};
    try near(1.0, (try adversary.measure(gpa, &z, .{ .exponential = 40.0 })).max_link_prob);
    // causal: a departure before the target arrived carries no weight at all
    const c = [_]Transit{ tp(0, 10, 20, 1, 0, .real, 0), tp(0, 0, 5, 2, 0, .drop_cover, 0) };
    const rc = try adversary.measure(gpa, &c, .{ .exponential = 40.0 });
    try near(1.0, rc.max_link_prob);
    try near(1.0, rc.min_effective_set);
    // decay: own departure holds 0 (weight 1), the other holds 40 = mean (weight e^-1)
    const d = [_]Transit{ tp(0, 10, 10, 1, 0, .real, 0), tp(0, 0, 50, 2, 0, .drop_cover, 0) };
    try near(1.0 / (1.0 + @exp(@as(f64, -1.0))), (try adversary.measure(gpa, &d, .{ .exponential = 40.0 })).max_link_prob);
}

test "mutation 2026-11-27: a batch mix's release instant is the first departure AT or after the arrival" {
    // packet 2 arrives on the very tick packet 1 leaves (and leaves then itself)
    const ts = [_]Transit{ tp(0, 0, 10, 1, 0, .real, 0), tp(0, 10, 10, 2, 0, .real, 0) };
    const r = try adversary.measure(gpa, &ts, .batch);
    try testing.expectEqual(@as(usize, 2), r.targets);
    try near(2.0, r.min_effective_set);
    try near(0.5, r.max_link_prob);
    // end to end: both senders share that batch, 50/50
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 } };
    const e = [_]Transit{ tp(0, 0, 10, 1, 0, .real, 0), tp(0, 10, 10, 2, 0, .real, 0) };
    const re = try adversary.measureEndToEnd(gpa, &e, &os, 2, 0, .batch);
    try near(2.0, re.min_sender_set);
    try near(0.5, re.max_link_prob);
}

test "mutation 2026-11-27: measure — a target no departure explains is not NaN; means, and the empty transcript" {
    // constant law 10, actual hold 5: every weight is 0, so the posterior is empty
    const ts = [_]Transit{tp(0, 0, 5, 1, 0, .real, 0)};
    const r = try adversary.measure(gpa, &ts, .{ .constant = .{ .delta = 10, .tol = 0 } });
    try testing.expectEqual(@as(usize, 1), r.targets);
    try near(0.0, r.mean_link_prob);
    try near(0.0, r.max_link_prob);
    try near(1.0, r.mean_effective_set);
    // a batch of four: every target hides among 4, each 1/4 linkable (means over n = 4)
    const b = [_]Transit{ tp(0, 3, 50, 1, 0, .real, 0), tp(0, 10, 50, 2, 0, .real, 0), tp(0, 22, 50, 3, 0, .real, 0), tp(0, 30, 50, 4, 0, .real, 0) };
    const rb = try adversary.measure(gpa, &b, .batch);
    try near(4.0, rb.mean_effective_set);
    try near(0.25, rb.mean_link_prob);
    // nothing to score: the means and the minimum are 0, not NaN / infinity
    const none = try adversary.measure(gpa, &.{}, .{ .exponential = 40.0 });
    try testing.expectEqual(@as(f64, 0.0), none.mean_effective_set);
    try testing.expectEqual(@as(f64, 0.0), none.mean_link_prob);
    try testing.expectEqual(@as(f64, 0.0), none.min_effective_set);
}

// ── adversary: bounds ────────────────────────────────────────────────────────

test "mutation 2026-11-27: holds() is inclusive on both bounds, needs both clauses, is vacuous without targets" {
    const b = types.AnonymityBound{ .min_effective_set = 2.0, .max_link_prob = 0.5 };
    const R = adversary.AnonymityResult;
    try testing.expect((R{ .targets = 1, .min_effective_set = 2.0, .max_link_prob = 0.5 }).holds(b));
    try testing.expect(!(R{ .targets = 1, .min_effective_set = 1.9, .max_link_prob = 0.5 }).holds(b));
    try testing.expect(!(R{ .targets = 1, .min_effective_set = 2.0, .max_link_prob = 0.6 }).holds(b));
    try testing.expect((R{ .targets = 0, .min_effective_set = 0, .max_link_prob = 1 }).holds(b));

    const sb = types.SenderBound{ .min_sender_set = 4.0, .max_link_prob = 0.5 };
    const S = adversary.SenderResult;
    try testing.expect((S{ .targets = 1, .min_sender_set = 4.0, .max_link_prob = 0.5 }).holds(sb));
    try testing.expect(!(S{ .targets = 1, .min_sender_set = 3.9, .max_link_prob = 0.5 }).holds(sb));
    try testing.expect(!(S{ .targets = 1, .min_sender_set = 4.0, .max_link_prob = 0.6 }).holds(sb));
    try testing.expect((S{ .targets = 0, .min_sender_set = 0, .max_link_prob = 1 }).holds(sb));
    const ub = types.UnlinkBound{ .max_mean_epsilon = 1.0 };
    try testing.expect((S{ .targets = 1, .mean_epsilon = 1.0 }).unlinkable(ub));
    try testing.expect(!(S{ .targets = 1, .mean_epsilon = 1.1 }).unlinkable(ub));
    try testing.expect((S{ .targets = 0, .mean_epsilon = 5.0 }).unlinkable(ub));

    const rb = types.ReceiverBound{ .min_receiver_set = 2.0, .max_link_prob = 0.5 };
    const Rc = adversary.ReceiverResult;
    try testing.expect((Rc{ .targets = 1, .min_receiver_set = 2.0, .max_link_prob = 0.5 }).holds(rb));
    try testing.expect(!(Rc{ .targets = 1, .min_receiver_set = 1.9, .max_link_prob = 0.5 }).holds(rb));
    try testing.expect(!(Rc{ .targets = 1, .min_receiver_set = 2.0, .max_link_prob = 0.6 }).holds(rb));
    try testing.expect((Rc{ .targets = 0, .min_receiver_set = 0, .max_link_prob = 1 }).holds(rb));
}

// ── adversary: end to end ────────────────────────────────────────────────────

const big = [_]Transit{
    tp(0, 0, 20, 1, 0, .real, 1),  tp(0, 2, 18, 2, 0, .real, 1),  tp(0, 10, 12, 3, 0, .drop_cover, 1),
    tp(1, 22, 41, 2, 1, .real, 5), tp(1, 24, 44, 1, 1, .real, 5), tp(1, 30, 33, 3, 1, .drop_cover, 5),
};
const big_origins = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 }, .{ .id = 3, .client = 1 } };

test "mutation 2026-11-27: measureEndToEnd composes two exponential layers (weights, normalisation, every mean)" {
    const m: adversary.DelayModel = .{ .exponential = 20.0 };
    const r = try adversary.measureEndToEnd(gpa, &big, &big_origins, 2, 1, m);
    try testing.expectEqual(@as(usize, 2), r.targets);
    try testing.expectEqual(@as(usize, 0), r.fallbacks);
    try near(1.785387141078, r.min_sender_set);
    try near(1.785387141078, r.mean_sender_set);
    try near(0.733609824227, r.max_link_prob);
    try near(0.5, r.mean_link_prob);
    try near(1.0130152524, r.max_epsilon);
    try near(0.0, r.mean_epsilon);
    // the first layer alone, scored at its own last hop
    const r0 = try adversary.measureEndToEnd(gpa, &big, &big_origins, 2, 0, m);
    try testing.expectEqual(@as(usize, 2), r0.targets);
    try near(1.785387141078, r0.mean_sender_set);
}

test "mutation 2026-11-27: measureEndToEnd, four targets on one layer" {
    const ts = [_]Transit{
        tp(0, 0, 10, 1, 0, .real, 0), tp(0, 3, 13, 2, 0, .real, 0),
        tp(0, 6, 40, 5, 0, .real, 0), tp(0, 7, 60, 6, 0, .real, 0),
    };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 }, .{ .id = 5, .client = 0 }, .{ .id = 6, .client = 1 } };
    const r = try adversary.measureEndToEnd(gpa, &ts, &os, 2, 0, .{ .exponential = 20.0 });
    try testing.expectEqual(@as(usize, 4), r.targets);
    try near(1.997804778649, r.min_sender_set);
    try near(1.997804778649, r.mean_sender_set);
    try near(0.523428736714, r.max_link_prob);
    try near(0.5, r.mean_link_prob);
    try near(0.093783624913, r.max_epsilon);
}

test "mutation 2026-11-27: the leakage floors the true sender's probability at 1e-12 (a sender the adversary excluded)" {
    // constant law 10. Packet 2 (client 1) really held 7, but a cover loop that arrived
    // 10 ticks before it left explains its departure: the adversary puts all mass on
    // client 0, so Pr[true sender] = 0 floors at 1e-12 and ε = ln(1e-12).
    const ts = [_]Transit{ tp(0, 5, 12, 2, 0, .real, 0), tp(0, 2, 40, 9, 0, .drop_cover, 0) };
    const os = [_]Origin{ .{ .id = 2, .client = 1 }, .{ .id = 9, .client = 0 } };
    const r = try adversary.measureEndToEnd(gpa, &ts, &os, 2, 0, .{ .constant = .{ .delta = 10, .tol = 0 } });
    try testing.expectEqual(@as(usize, 1), r.targets);
    try near(@log(1e-12), r.mean_epsilon);
    try near(0.0, r.max_link_prob);
    // and a pinned sender: ε = ln(1 / 1e-12) for the packet beside it
    const ts2 = [_]Transit{ ts[0], ts[1], tp(0, 3, 13, 8, 0, .real, 0) };
    const os2 = [_]Origin{ os[0], os[1], .{ .id = 8, .client = 0 } };
    const r2 = try adversary.measureEndToEnd(gpa, &ts2, &os2, 2, 0, .{ .constant = .{ .delta = 10, .tol = 0 } });
    try near(-@log(1e-12), r2.max_epsilon);
}

test "mutation 2026-11-27: measureEndToEnd with ONE client has no other sender to leak to (ε = 0, not NaN)" {
    const ts = [_]Transit{ tp(0, 0, 10, 1, 0, .real, 0), tp(0, 3, 15, 2, 0, .real, 0) };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 0 } };
    const r = try adversary.measureEndToEnd(gpa, &ts, &os, 1, 0, .{ .exponential = 10.0 });
    try testing.expectEqual(@as(usize, 2), r.targets);
    try testing.expectEqual(@as(f64, 0.0), r.mean_epsilon);
    try testing.expectEqual(@as(f64, 0.0), r.max_epsilon);
    try near(1.0, r.mean_link_prob);
}

test "mutation 2026-11-27: measureEndToEnd counts each fallback to a uniform exactly once" {
    const model: adversary.DelayModel = .{ .constant = .{ .delta = 10, .tol = 0 } };
    // (1) a departure no arrival explains: uniform over the 2 clients, one fallback
    const a = [_]Transit{tp(0, 0, 5, 1, 0, .real, 0)};
    const ra = try adversary.measureEndToEnd(gpa, &a, &.{.{ .id = 1, .client = 0 }}, 2, 0, model);
    try testing.expectEqual(@as(usize, 1), ra.fallbacks);
    try near(2.0, ra.min_sender_set);
    try near(0.5, ra.max_link_prob);
    // (2) the same at the SECOND layer (the first one is fine)
    const b = [_]Transit{ tp(0, 0, 10, 1, 0, .real, 0), tp(1, 12, 30, 1, 1, .real, 0) };
    const rb = try adversary.measureEndToEnd(gpa, &b, &.{.{ .id = 1, .client = 0 }}, 2, 1, model);
    try testing.expectEqual(@as(usize, 1), rb.fallbacks);
    try near(2.0, rb.min_sender_set);
    // (3) a first-layer packet with no recorded origin
    const c = [_]Transit{tp(0, 0, 10, 5, 0, .real, 0)};
    const rc = try adversary.measureEndToEnd(gpa, &c, &.{}, 2, 0, model);
    try testing.expectEqual(@as(usize, 1), rc.fallbacks);
    // (4) a later arrival with no recorded previous pass (and no origin either)
    const d = [_]Transit{tp(1, 15, 25, 9, 1, .real, 0)};
    const rd = try adversary.measureEndToEnd(gpa, &d, &.{}, 2, 1, .{ .exponential = 10.0 });
    try testing.expectEqual(@as(usize, 1), rd.fallbacks);
    try testing.expectEqual(@as(usize, 0), rd.targets);
}

test "mutation 2026-11-27: a mix's loop is no target even if labelled real; a packet carrying no client mass is not scored" {
    const model: adversary.DelayModel = .{ .constant = .{ .delta = 10, .tol = 0 } };
    // origin says `from_mix`: nobody sent it, whatever its kind — it is no target even though the
    // client packet before it puts mass on its departure
    const exp: adversary.DelayModel = .{ .exponential = 10.0 };
    const m = [_]Transit{ tp(0, 0, 10, 1, 0, .real, 0), tp(0, 5, 15, 2, 0, .real, 0) };
    const rm = try adversary.measureEndToEnd(gpa, &m, &.{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 0, .from_mix = true } }, 2, 0, exp);
    try testing.expectEqual(@as(usize, 1), rm.targets);
    // packet 1 (hold 20) is explained only by the mix loop that arrived at 10, which carries no
    // client mass: the posterior over clients is empty, so the packet is skipped, not scored
    const z = [_]Transit{ tp(0, 0, 20, 1, 0, .real, 0), tp(0, 10, 20, 2, 0, .loop_cover, 0) };
    const rz = try adversary.measureEndToEnd(gpa, &z, &.{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 0, .from_mix = true } }, 2, 0, model);
    try testing.expectEqual(@as(usize, 0), rz.targets);
}

test "mutation 2026-11-27: measureEndToEnd keeps a mix's passes at different hops apart (free route)" {
    // mix 0 is hop 0 of packet 1 and hop 1 of packet 2, over the same ticks. Packet 2 is
    // alone in its (mix 0, hop 1) pool, so its sender (client 1) is pinned.
    const ts = [_]Transit{ tp(1, 0, 5, 2, 0, .real, 0), tp(0, 20, 30, 1, 0, .real, 0), tp(0, 20, 30, 2, 1, .real, 0) };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 } };
    const r = try adversary.measureEndToEnd(gpa, &ts, &os, 2, 1, .{ .exponential = 10.0 });
    try testing.expectEqual(@as(usize, 1), r.targets);
    try near(1.0, r.max_link_prob);
    try near(1.0, r.min_sender_set);
}

test "mutation 2026-11-27: pool identity is the (mix, hop) pair for every u8 hop, not a packed approximation of it" {
    // (mix 1, hop 0) and (mix 0, hop 128) are different pools. Packet 2's hop-128 pass has no
    // recorded predecessor, so its sender is the uniform fallback (one fallback, 1/2 each) -
    // it must not be blended with packet 1, who left mix 1 on the same ticks.
    const ts = [_]Transit{ tp(1, 0, 10, 1, 0, .real, 0), tp(0, 0, 10, 2, 128, .real, 0) };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 } };
    const r = try adversary.measureEndToEnd(gpa, &ts, &os, 2, 128, .{ .exponential = 10.0 });
    try testing.expectEqual(@as(usize, 1), r.targets);
    try testing.expectEqual(@as(usize, 1), r.fallbacks);
    try near(0.5, r.max_link_prob);
    try near(2.0, r.min_sender_set);
}

test "mutation 2026-11-27: measureEndToEnd, three clients through two layers (the posterior is renormalised per layer)" {
    const ts = [_]Transit{
        tp(0, 1, 5, 1, 0, .real, 0),  tp(0, 7, 9, 2, 0, .real, 0),   tp(0, 9, 31, 3, 0, .real, 0),
        tp(1, 6, 16, 1, 1, .real, 0), tp(1, 12, 17, 2, 1, .real, 0), tp(1, 32, 43, 3, 1, .real, 0),
    };
    const os = [_]Origin{ .{ .id = 1, .client = 0 }, .{ .id = 2, .client = 1 }, .{ .id = 3, .client = 2 } };
    const r = try adversary.measureEndToEnd(gpa, &ts, &os, 3, 1, .{ .exponential = 15.0 });
    try testing.expectEqual(@as(usize, 3), r.targets);
    try testing.expectEqual(@as(usize, 0), r.fallbacks);
    try near(2.7301403435212106, r.min_sender_set);
    try near(2.818607252342258, r.mean_sender_set);
    try near(0.5439783017795872, r.max_link_prob);
    try near(0.37106053748136253, r.mean_link_prob);
    try near(0.8717367260667945, r.max_epsilon);
    try near(0.14611341572777536, r.mean_epsilon);
}

test "mutation 2026-11-27: nothing to score — end-to-end and receiver means and minima are 0, not NaN or infinity" {
    const e = try adversary.measureEndToEnd(gpa, &.{}, &.{}, 3, 2, .{ .exponential = 10.0 });
    try testing.expectEqual(@as(f64, 0.0), e.mean_sender_set);
    try testing.expectEqual(@as(f64, 0.0), e.mean_link_prob);
    try testing.expectEqual(@as(f64, 0.0), e.mean_epsilon);
    try testing.expectEqual(@as(f64, 0.0), e.min_sender_set);
    const rows = exitRows();
    const r = try adversary.measureReceiver(gpa, &.{}, &.{}, &rows, 2, 1, .{ .exponential = 10.0 });
    try testing.expectEqual(@as(f64, 0.0), r.mean_receiver_set);
    try testing.expectEqual(@as(f64, 0.0), r.mean_link_prob);
    try testing.expectEqual(@as(f64, 0.0), r.min_receiver_set);
}

// ── adversary: receiver ──────────────────────────────────────────────────────

fn exitRows() [8 * 2]f64 {
    var rows: [8 * 2]f64 = @splat(0);
    rows[5 * 2 + 0] = 0.75;
    rows[5 * 2 + 1] = 0.25;
    rows[6 * 2 + 0] = 0.1; // a row that does not sum to 1: the posterior is conditioned on its mass
    rows[6 * 2 + 1] = 0.3;
    return rows;
}

test "mutation 2026-11-27: measureReceiver composes forward over two layers (cover is no target)" {
    const rows = exitRows();
    const ts = [_]Transit{
        tp(0, 0, 10, 1, 0, .real, 1),  tp(0, 3, 12, 2, 0, .real, 2),        tp(0, 5, 20, 3, 0, .drop_cover, 1),
        tp(1, 13, 25, 1, 1, .real, 5), tp(1, 22, 30, 3, 1, .drop_cover, 5), tp(2, 15, 27, 2, 1, .real, 6),
    };
    const os = [_]Origin{ .{ .id = 1, .client = 0, .recipient = 0 }, .{ .id = 2, .client = 1, .recipient = 1 }, .{ .id = 3, .client = 1, .recipient = 1 } };
    const r = try adversary.measureReceiver(gpa, &ts, &os, &rows, 2, 1, .{ .exponential = 15.0 });
    try testing.expectEqual(@as(usize, 2), r.targets);
    try testing.expectEqual(@as(usize, 0), r.fallbacks);
    try near(1.903333774398, r.min_receiver_set);
    try near(1.903333774398, r.mean_receiver_set);
    try near(0.656071404961, r.max_link_prob);
    try near(0.5, r.mean_link_prob);
}

test "mutation 2026-11-27: measureReceiver — an all-zero exit row skips the packet; fallbacks are counted once, at the right layer" {
    const rows = exitRows();
    const os = [_]Origin{.{ .id = 1, .client = 0, .recipient = 0 }};
    const exp: adversary.DelayModel = .{ .exponential = 15.0 };
    // node 7's row is all zeros: nothing observed about the receiver, no score
    const z = [_]Transit{tp(0, 0, 10, 1, 0, .real, 7)};
    try testing.expectEqual(@as(usize, 0), (try adversary.measureReceiver(gpa, &z, &os, &rows, 2, 0, exp)).targets);
    // a first-layer pass whose `to` is outside the rows is no exit: no fallback
    const f0 = [_]Transit{ tp(0, 0, 10, 1, 0, .real, 99), tp(1, 13, 25, 1, 1, .real, 5) };
    const r0 = try adversary.measureReceiver(gpa, &f0, &os, &rows, 2, 1, exp);
    try testing.expectEqual(@as(usize, 0), r0.fallbacks);
    try near(1.754765350603, r0.min_receiver_set);
    try near(0.75, r0.max_link_prob);
    // a last-layer exit outside the rows IS unobserved: one fallback, uniform
    const f1 = [_]Transit{ tp(0, 0, 10, 1, 0, .real, 99), tp(1, 13, 25, 1, 1, .real, 99) };
    const r1 = try adversary.measureReceiver(gpa, &f1, &os, &rows, 2, 1, exp);
    try testing.expectEqual(@as(usize, 1), r1.fallbacks);
    try near(2.0, r1.min_receiver_set);
    try near(0.5, r1.max_link_prob);
    // a first-layer pool no departure explains: one fallback (not one per pass over the layers)
    const f2 = [_]Transit{ tp(0, 0, 18, 1, 0, .real, 1), tp(1, 20, 30, 1, 1, .real, 5) };
    const r2 = try adversary.measureReceiver(gpa, &f2, &os, &rows, 2, 1, .{ .constant = .{ .delta = 10, .tol = 0 } });
    try testing.expectEqual(@as(usize, 1), r2.fallbacks);
    try near(2.0, r2.min_receiver_set);
}

// ── adversary: reorder statistic ─────────────────────────────────────────────

test "mutation 2026-11-27: reorderStats — same mix only, distinct arrival ticks, strictly co-resident, ties are no inversion" {
    try testing.expectEqual(@as(f64, 0.0), (adversary.ReorderStats{}).fraction());
    // different mixes never pair
    const x = [_]Transit{ tp(0, 0, 20, 1, 0, .real, 0), tp(1, 5, 10, 2, 0, .real, 0) };
    try testing.expectEqual(@as(usize, 0), adversary.reorderStats(&x).pairs);
    // the same arrival tick has no order to invert
    const s = [_]Transit{ tp(0, 5, 20, 1, 0, .real, 0), tp(0, 5, 10, 2, 0, .real, 0) };
    try testing.expectEqual(@as(usize, 0), adversary.reorderStats(&s).pairs);
    // the second arrives the very tick the first leaves: not co-resident
    const e = [_]Transit{ tp(0, 0, 10, 1, 0, .real, 0), tp(0, 10, 15, 2, 0, .real, 0) };
    try testing.expectEqual(@as(usize, 0), adversary.reorderStats(&e).pairs);
    // a later arrival that leaves first is an inversion; leaving on the same tick is not
    const i = adversary.reorderStats(&.{ tp(0, 0, 20, 1, 0, .real, 0), tp(0, 5, 10, 2, 0, .real, 0) });
    try testing.expectEqual(@as(usize, 1), i.pairs);
    try testing.expectEqual(@as(usize, 1), i.inversions);
    const t = adversary.reorderStats(&.{ tp(0, 0, 20, 1, 0, .real, 0), tp(0, 5, 20, 2, 0, .real, 0) });
    try testing.expectEqual(@as(usize, 1), t.pairs);
    try testing.expectEqual(@as(usize, 0), t.inversions);
}

// ── protocol: wiring, reset, provider and client handlers ────────────────────

const MixHeader = types.MixHeader;
const P = protocol.PROVIDER_CFG;

fn noDuplicateLinks(comptime cfg: LoopixConfig) !void {
    var fifo = try protocol.FifoMix.init(gpa, cfg);
    defer fifo.deinit(gpa);
    const topo = try netsim.snapshotTopo(gpa, .{ .seed = 0, .scenario = protocol.scenarioFor(cfg), .protocol = fifo.protocol(), .until = 100 });
    defer gpa.free(topo.links);
    for (topo.links, 0..) |a, i| {
        for (topo.links[i + 1 ..]) |b| try testing.expect(a.a != b.a or a.b != b.b);
    }
}

test "mutation 2026-11-27: every directed link is added exactly once, whichever wiring rule asks for it" {
    // one layer: the first-layer links and the last-layer links are the same links
    try noDuplicateLinks(.{ .layers = 1, .width = 2, .clients = 2 });
    try noDuplicateLinks(.{ .layers = 1, .width = 2, .clients = 2, .providers = 1 });
    // mix loops: a mix's overlay legs duplicate layered links unless they are filtered
    try noDuplicateLinks(.{ .layers = 2, .width = 2, .clients = 2, .mix_loop_interval = 50 });
    try noDuplicateLinks(.{ .layers = 3, .width = 1, .clients = 2, .topology = .cascade, .mix_loop_interval = 50 });
    // one layer, 2 clients x 2 mixes, both directions: exactly 8 links
    var fifo = try protocol.FifoMix.init(gpa, .{ .layers = 1, .width = 2, .clients = 2 });
    defer fifo.deinit(gpa);
    const topo = try netsim.snapshotTopo(gpa, .{ .seed = 0, .scenario = protocol.scenarioFor(.{ .layers = 1, .width = 2, .clients = 2 }), .protocol = fifo.protocol(), .until = 100 });
    defer gpa.free(topo.links);
    try testing.expectEqual(@as(usize, 8), topo.links.len);
}

const reset_cfg = blk: {
    var c = protocol.PROVIDER_CFG;
    c.mix_loop_interval = 60;
    break :blk c;
};
const reset_attack = protocol.Attack{ .mix = reset_cfg.mixNode(1, 0), .start = 700, .stop = 1400 };

fn runReset(mix: *protocol.Loopix, seed: u64) !void {
    mix.attack = reset_attack;
    _ = try netsim.replay(gpa, .{ .seed = seed, .scenario = protocol.scenarioFor(reset_cfg), .protocol = mix.protocol(), .until = 2000 }, &.{}, null);
}

test "mutation 2026-11-27: a reused Loopix (reset by the next run) behaves exactly like a fresh one" {
    var fresh = try protocol.Loopix.init(gpa, reset_cfg, 7);
    defer fresh.deinit(gpa);
    try runReset(&fresh, 7);

    var used = try protocol.Loopix.init(gpa, reset_cfg, 7);
    defer used.deinit(gpa);
    try runReset(&used, 99); // a first, different run leaves state of every kind behind
    // ... and so does anything a previous owner left in the counters and queues
    const r = &used.relay;
    r.malformed = 5;
    r.misdelivered = 4;
    r.link_bytes = 99;
    r.fetch_bytes = 98;
    r.next_id = 500;
    r.real_seq = 77;
    r.cover_seq = 66;
    r.mix_loop_seq = 55;
    used.attack_dropped = 44;
    used.attack_last_drop = 33;
    used.loops_watched = 22;
    used.loops_returned = 21;
    used.mix_loops_watched = 20;
    used.mix_loops_returned = 19;
    used.lost[0] = 9;
    used.mix_lost[0] = 8;
    try used.alarms.append(gpa, .{ .client = 0, .at = 1 });
    try used.mix_alarms.append(gpa, .{ .mix = 0, .at = 1 });
    const stale = MixHeader{ .kind = .real, .id = 9999, .hop = 0, .n_hops = 3, .route = .{ 0, 3, 6, 9, 0, 0, 0 } };
    var t: Time = 50;
    while (t < 1000) : (t += 1) try r.queues[0].append(gpa, .{ .arrival = 1, .release_at = t, .hdr = stale });
    try r.mailboxes[0].append(gpa, stale);
    try used.loops.put(gpa, 12345, .{ .client = 0, .deadline = 1 });
    try used.mix_loops.put(gpa, 12346, .{ .mix = 0, .deadline = 1 });
    try r.sent.put(gpa, 9999, .{ .client = 0, .at = 0, .kind = .real, .recipient = P.clientNode(0) });
    try r.delivered.put(gpa, 9999, 0);
    try r.mix_returned.put(gpa, 9999, 0);
    try r.mix_sent.put(gpa, 9999, .{ .mix = 0, .at = 0 });
    try r.fetch_lens.append(gpa, 1);
    try r.deliveries.append(gpa, .{ .id = 9999, .kind = .real, .sender = 0, .recipient = 0, .sent = 0, .delivered = 0 });
    try r.origins.append(gpa, .{ .id = 9999, .client = 0 });
    try r.transcript.append(gpa, .{ .mix = 0, .arrival = 0, .departure = 0, .kind = .real, .id = 9999 });
    try runReset(&used, 7);

    const a = &fresh;
    const b = &used;
    try testing.expectEqualSlices(Transit, a.transcript(), b.transcript());
    try testing.expectEqualSlices(Origin, a.origins(), b.origins());
    try testing.expectEqual(a.deliveries().len, b.deliveries().len);
    for (a.deliveries(), b.deliveries()) |x, y| try testing.expectEqual(x, y);
    try testing.expectEqual(a.stats(), b.stats());
    try testing.expectEqual(a.relay.malformed, b.relay.malformed);
    try testing.expectEqual(a.relay.misdelivered, b.relay.misdelivered);
    try testing.expectEqual(a.relay.link_bytes, b.relay.link_bytes);
    try testing.expectEqual(a.relay.fetch_bytes, b.relay.fetch_bytes);
    try testing.expectEqual(a.relay.next_id, b.relay.next_id);
    try testing.expectEqual(a.relay.real_seq, b.relay.real_seq);
    try testing.expectEqual(a.relay.cover_seq, b.relay.cover_seq);
    try testing.expectEqual(a.relay.mix_loop_seq, b.relay.mix_loop_seq);
    try testing.expectEqualSlices(usize, a.relay.fetch_lens.items, b.relay.fetch_lens.items);
    try testing.expectEqual(a.relay.sent.count(), b.relay.sent.count());
    try testing.expectEqual(a.relay.delivered.count(), b.relay.delivered.count());
    try testing.expectEqual(a.relay.mix_sent.count(), b.relay.mix_sent.count());
    try testing.expectEqual(a.relay.mix_returned.count(), b.relay.mix_returned.count());
    for (a.relay.queues, b.relay.queues) |x, y| try testing.expectEqual(x.items.len, y.items.len);
    for (a.relay.mailboxes, b.relay.mailboxes) |x, y| try testing.expectEqual(x.items.len, y.items.len);
    try testing.expectEqual(a.attack_dropped, b.attack_dropped);
    try testing.expectEqual(a.attack_last_drop, b.attack_last_drop);
    try testing.expectEqual(a.loops_watched, b.loops_watched);
    try testing.expectEqual(a.loops_returned, b.loops_returned);
    try testing.expectEqual(a.mix_loops_watched, b.mix_loops_watched);
    try testing.expectEqual(a.mix_loops_returned, b.mix_loops_returned);
    try testing.expectEqual(a.loops.count(), b.loops.count());
    try testing.expectEqual(a.mix_loops.count(), b.mix_loops.count());
    try testing.expectEqualSlices(u32, a.lost, b.lost);
    try testing.expectEqualSlices(u32, a.mix_lost, b.mix_lost);
    try testing.expectEqual(a.alarms.items.len, b.alarms.items.len);
    try testing.expectEqual(a.mix_alarms.items.len, b.mix_alarms.items.len);
    // the run really exercised what is compared (the attack bit, the mixes' loops flew)
    try testing.expect(a.attack_dropped > 0 and a.mix_loops_watched > 0 and a.loops_watched > 0);
    // every watched loop is exactly one of: home, given up on, still pending
    var lost_sum: u64 = 0;
    for (a.lost) |l| lost_sum += l;
    var mix_lost_sum: u64 = 0;
    for (a.mix_lost) |l| mix_lost_sum += l;
    try testing.expect(lost_sum > 0 and mix_lost_sum > 0);
    try testing.expectEqual(a.loops_watched, a.loops_returned + lost_sum + a.loops.count());
    try testing.expectEqual(a.mix_loops_watched, a.mix_loops_returned + mix_lost_sum + a.mix_loops.count());
    // a run that never meets the attacker does not inherit the last one's drop count or time
    used.attack_last_drop = 33;
    used.attack_dropped = 44;
    used.attack = null;
    _ = try netsim.replay(gpa, .{ .seed = 7, .scenario = protocol.scenarioFor(reset_cfg), .protocol = used.protocol(), .until = 2000 }, &.{}, null);
    try testing.expectEqual(@as(u64, 0), used.attack_dropped);
    try testing.expectEqual(@as(Time, 0), used.attack_last_drop);
}

fn hdrBytes(h: MixHeader) [MixHeader.wire_len]u8 {
    var b: [MixHeader.wire_len]u8 = undefined;
    h.encode(&b);
    return b;
}

test "mutation 2026-11-27: a provider answers only the exact one-byte fetch, with exactly fetch_batch slots" {
    var mix = try protocol.Loopix.init(gpa, P, 1);
    defer mix.deinit(gpa);
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, mix.protocol(), &log, 2000, 10_000);
    defer sim.deinit();
    try protocol.providerScenario(&sim);
    const p = mix.protocol();
    const prov = P.providerOf(0);
    const c0 = P.clientNode(0);

    try p.onMessageFn(p.ctx, &sim, prov, c0, &.{0xF0});
    try testing.expectEqual(@as(usize, 1), mix.relay.fetch_lens.items.len);
    // tag byte, count byte, then exactly `fetch_batch` padded slots
    const want: usize = 2 + @as(usize, P.fetch_batch) * MixHeader.wire_len;
    try testing.expectEqual(want, mix.relay.fetch_lens.items[0]);
    try testing.expectEqual(@as(u64, want), mix.relay.fetch_bytes);
    // a longer payload that merely starts with the tag, and a one-byte payload with another tag
    try p.onMessageFn(p.ctx, &sim, prov, c0, &.{ 0xF0, 0x01 });
    try p.onMessageFn(p.ctx, &sim, prov, c0, &.{0x7F});
    try testing.expectEqual(@as(u64, 2), mix.relay.malformed);
    try testing.expectEqual(@as(usize, 1), mix.relay.fetch_lens.items.len);
}

test "mutation 2026-11-27: a provider forwards only a fresh packet of its own client, and stores only what the last layer addressed to it" {
    var mix = try protocol.Loopix.init(gpa, P, 1);
    defer mix.deinit(gpa);
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, mix.protocol(), &log, 2000, 10_000);
    defer sim.deinit();
    try protocol.providerScenario(&sim);
    const p = mix.protocol();
    const prov0 = P.providerOf(0);
    const c0 = P.clientNode(0);
    const c1 = P.clientNode(1); // served by the OTHER provider
    const exit_mix = P.mixNode(2, 1);

    // ingress: positive control — a fresh packet of its own client is forwarded to the first mix
    const fresh = hdrBytes(.{ .kind = .real, .id = 1, .hop = 0, .n_hops = 3, .route = .{ P.mixNode(0, 0), P.mixNode(1, 0), P.mixNode(2, 0), 0, 0, 0, 0 } });
    try p.onMessageFn(p.ctx, &sim, prov0, c0, &fresh);
    try testing.expectEqual(@as(u64, MixHeader.wire_len), mix.relay.link_bytes);
    try testing.expectEqual(@as(u64, 0), mix.relay.malformed);
    // ... the same packet from a client of another provider is refused, not forwarded
    try p.onMessageFn(p.ctx, &sim, prov0, c1, &fresh);
    try testing.expectEqual(@as(u64, 1), mix.relay.malformed);
    try testing.expectEqual(@as(u64, MixHeader.wire_len), mix.relay.link_bytes);
    // ... and a packet with no mix hops at all (the all-zero header) is no packet
    const zero: [MixHeader.wire_len]u8 = @splat(0);
    try p.onMessageFn(p.ctx, &sim, prov0, c0, &zero);
    try testing.expectEqual(@as(u64, 2), mix.relay.malformed);
    try testing.expectEqual(@as(u64, MixHeader.wire_len), mix.relay.link_bytes);

    // egress: positive control — out of the last layer, addressed to this provider, for its client
    const route_ok: [7]NodeId = .{ P.mixNode(0, 0), P.mixNode(1, 0), P.mixNode(2, 1), prov0, 0, 0, 0 };
    const ok = hdrBytes(.{ .kind = .real, .id = 2, .hop = 3, .n_hops = 3, .route = route_ok, .recipient = c0 });
    try p.onMessageFn(p.ctx, &sim, prov0, exit_mix, &ok);
    try testing.expectEqual(@as(usize, 1), mix.relay.mailboxes[0].items.len);
    try testing.expectEqual(@as(u64, 2), mix.relay.malformed);
    // refused: no hops, a hop that is not the end, a route that ends at another node
    var no_hops = MixHeader{ .kind = .real, .id = 3, .hop = 0, .n_hops = 0, .route = route_ok, .recipient = c0 };
    no_hops.route[0] = prov0;
    var mid = MixHeader{ .kind = .real, .id = 4, .hop = 2, .n_hops = 3, .route = route_ok, .recipient = c0 };
    mid.route[3] = prov0;
    var elsewhere = MixHeader{ .kind = .real, .id = 5, .hop = 3, .n_hops = 3, .route = route_ok, .recipient = c0 };
    elsewhere.route[3] = P.providerOf(1);
    // recipient is a client of the OTHER provider
    var other_client = MixHeader{ .kind = .real, .id = 6, .hop = 3, .n_hops = 3, .route = route_ok, .recipient = c1 };
    other_client.route[3] = prov0;
    var n: u64 = 2;
    for ([_]MixHeader{ no_hops, mid, elsewhere, other_client }) |h| {
        const b = hdrBytes(h);
        try p.onMessageFn(p.ctx, &sim, prov0, exit_mix, &b);
        n += 1;
        try testing.expectEqual(n, mix.relay.malformed);
        try testing.expectEqual(@as(usize, 1), mix.relay.mailboxes[0].items.len);
    }
}

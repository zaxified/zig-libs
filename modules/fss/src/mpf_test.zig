// SPDX-License-Identifier: MIT

//! mpf_test — the multi-point FSS harness.
//!
//! Labels, kept in the same vocabulary the rest of the repo uses:
//!
//!   EXTERNAL — a vector produced outside this repo. There IS one here, and it
//!              is inherited rather than newly generated: an `Mpf` key is the
//!              concatenation of `dpf` keys, and `dpf`'s keys are pinned
//!              byte-exact by `kat_vectors.zig` (an independent Python
//!              re-derivation of BGI16 Fig. 1). Composing two recorded vectors
//!              into one `Mpf` key and asserting the serialized bytes reproduce
//!              both, at the right offsets, anchors this module's Gen and its
//!              encoding against something this implementation did not compute.
//!              **No vector in this file was computed by this implementation
//!              and then presented as an anchor.**
//!   DERIVED  — computed a second, structurally different way and required to
//!              agree (e.g. the summed `eval` against the plaintext multi-point
//!              function; the `k=1` path against `dpf` directly).
//!   SELF     — a round-trip or property of this module against itself.
//!   LEAK     — an executable demonstration of a real leak, run as a negative
//!              control so the corresponding non-leak claim has teeth.
//!
//! What is NOT claimed anywhere here: that the summed multi-point *evaluation*
//! has an external anchor. It does not — there is no published vector for
//! "sum of k BGI DPFs" in this module's PRG. The components are externally
//! anchored; their sum is checked by re-derivation only, and that distinction
//! is kept visible rather than blurred into the word "KAT".

const std = @import("std");
const dpf_mod = @import("dpf.zig");
const mpf_mod = @import("mpf.zig");
const kat_vectors = @import("kat_vectors.zig");
const prg_mod = @import("prg.zig");

const testing = std.testing;
const Mpf = mpf_mod.Mpf;
const Dpf = dpf_mod.Dpf;

/// Deterministic, mutually distinct seeds, so every failure here is permanent
/// rather than a flake. NOT a production pattern: `genWithSeeds` requires
/// independent CSPRNG seeds.
fn detSeed(tag: u64) prg_mod.Seed {
    var h: [32]u8 = undefined;
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, tag, .little);
    std.crypto.hash.sha2.Sha256.hash(&buf, &h, .{});
    return h[0..16].*;
}

fn detSeeds(comptime k: usize, tag: u64) [2][k]prg_mod.Seed {
    var s0: [k]prg_mod.Seed = undefined;
    var s1: [k]prg_mod.Seed = undefined;
    for (0..k) |j| {
        s0[j] = detSeed(tag *% 1_000_003 +% @as(u64, j) *% 2 +% 0);
        s1[j] = detSeed(tag *% 1_000_003 +% @as(u64, j) *% 2 +% 1);
    }
    return .{ s0, s1 };
}

// ── correctness across awkward geometries ─────────────────────────────────

test "SELF: full-domain reconstruction for k=1..domain_size, incl. k == domain_size" {
    // The geometries the brief calls awkward, each run exhaustively over the
    // whole domain rather than at sampled points.
    const cases = .{
        .{ .n = 1, .k = 1 }, // smallest domain, one point
        .{ .n = 1, .k = 2 }, // k == domain_size: every point is a point
        .{ .n = 2, .k = 4 }, // k == domain_size again, larger
        .{ .n = 3, .k = 2 },
        .{ .n = 3, .k = 7 }, // k one below the domain size
        .{ .n = 3, .k = 8 }, // k == domain_size
        .{ .n = 4, .k = 3 },
        .{ .n = 5, .k = 5 },
        .{ .n = 6, .k = 1 }, // the single-point case, through the multi path
    };
    inline for (cases) |c| {
        const M = Mpf(c.n, 4, c.k);
        // Points spread over the domain, values distinct and non-trivial.
        var alphas: [c.k]M.Index = undefined;
        var betas: [c.k]M.Elem = undefined;
        for (0..c.k) |j| {
            alphas[j] = @intCast((j * 7 + 1) % M.domain_size);
            betas[j] = @intCast(j * 0x01010101 + 1);
        }
        const seeds = detSeeds(c.k, c.n * 31 + c.k);
        const keys = try M.genWithSeeds(alphas, betas, seeds[0], seeds[1]);

        var e0: [M.domain_size]M.Elem = undefined;
        var e1: [M.domain_size]M.Elem = undefined;
        M.evalAll(0, keys[0], &e0);
        M.evalAll(1, keys[1], &e1);
        try testing.expectEqual(@as(?usize, null), M.firstMismatch(&e0, &e1, alphas, betas));
    }
}

test "SELF: repeated indices sum, and that is the shared function's definition" {
    // Two instances on the SAME point: the multi-point function takes the sum
    // of their values there. Asserted directly against a hand-written expected
    // vector rather than only through `firstMismatch`, so the semantic is
    // pinned independently of the checker that encodes it.
    const M = Mpf(3, 4, 3);
    const alphas: [3]M.Index = .{ 5, 5, 2 }; // 5 twice
    const betas: [3]M.Elem = .{ 10, 32, 7 };
    const seeds = detSeeds(3, 777);
    const keys = try M.genWithSeeds(alphas, betas, seeds[0], seeds[1]);

    var e0: [8]M.Elem = undefined;
    var e1: [8]M.Elem = undefined;
    M.evalAll(0, keys[0], &e0);
    M.evalAll(1, keys[1], &e1);

    const want = [8]M.Elem{ 0, 0, 7, 0, 0, 42, 0, 0 }; // 10+32 at index 5
    for (want, 0..) |w, x| try testing.expectEqual(w, e0[x] +% e1[x]);
    try testing.expectEqual(@as(?usize, null), M.firstMismatch(&e0, &e1, alphas, betas));

    // All three points on ONE index: the extreme of the same rule.
    const M1 = Mpf(2, 4, 3);
    const a1: [3]M1.Index = .{ 3, 3, 3 };
    const b1: [3]M1.Elem = .{ 1, 2, 4 };
    const s1 = detSeeds(3, 778);
    const k1 = try M1.genWithSeeds(a1, b1, s1[0], s1[1]);
    var f0: [4]M1.Elem = undefined;
    var f1: [4]M1.Elem = undefined;
    M1.evalAll(0, k1[0], &f0);
    M1.evalAll(1, k1[1], &f1);
    try testing.expectEqual(@as(M1.Elem, 7), f0[3] +% f1[3]);
    try testing.expectEqual(@as(M1.Elem, 0), f0[0] +% f1[0]);
}

test "SELF: k=0 is a total no-op — zero-byte key, all-zero function" {
    // A boundary case, not a use case: asserted because a zero-length key and
    // an empty instance loop are exactly where an off-by-one or a division by
    // `k` would surface.
    const M = Mpf(4, 4, 0);
    try testing.expectEqual(@as(usize, 0), M.Key.serialized_len);
    const alphas: [0]M.Index = .{};
    const betas: [0]M.Elem = .{};
    const s0: [0]prg_mod.Seed = .{};
    const s1: [0]prg_mod.Seed = .{};
    const keys = try M.genWithSeeds(alphas, betas, s0, s1);

    var e0: [16]M.Elem = undefined;
    var e1: [16]M.Elem = undefined;
    M.evalAll(0, keys[0], &e0);
    M.evalAll(1, keys[1], &e1);
    for (0..16) |x| {
        try testing.expectEqual(@as(M.Elem, 0), e0[x]);
        try testing.expectEqual(@as(M.Elem, 0), e1[x]);
    }
    try testing.expectEqual(@as(?usize, null), M.firstMismatch(&e0, &e1, alphas, betas));

    // The zero-byte key still round-trips through the codec.
    var buf: [0]u8 = undefined;
    keys[0].toBytes(&buf);
    _ = M.Key.fromBytes(&buf);
}

test "DERIVED: k=1 is byte-for-byte the existing single-point path" {
    // The strongest possible statement of "k=1 must equal the DPF": not "it
    // retrieves the same value" but "it is the same key material and the same
    // evaluations", compared through the serialized bytes a peer would see.
    const D = Dpf(6, 8);
    const M = Mpf(6, 8, 1);
    const alpha: D.Index = 37;
    const beta: D.Elem = 0x0BADF00DDEADBEEF;
    const s0 = detSeed(4001);
    const s1 = detSeed(4002);

    const single = D.genWithSeeds(alpha, beta, s0, s1);
    const multi = try M.genWithSeeds(.{alpha}, .{beta}, .{s0}, .{s1});

    try testing.expectEqual(@as(usize, D.Key.serialized_len), M.Key.serialized_len);
    inline for (0..2) |b| {
        var a: [D.Key.serialized_len]u8 = undefined;
        var c: [M.Key.serialized_len]u8 = undefined;
        single[b].toBytes(&a);
        multi[b].toBytes(&c);
        try testing.expectEqualSlices(u8, &a, &c);
    }
    // …and the evaluations agree at every point, both summed and per-instance.
    for (0..D.domain_size) |x| {
        const xi: D.Index = @intCast(x);
        var each: [1]M.Elem = undefined;
        M.evalEach(0, multi[0], xi, &each);
        try testing.expectEqual(D.eval(0, single[0], xi), M.eval(0, multi[0], xi));
        try testing.expectEqual(D.eval(0, single[0], xi), each[0]);
        try testing.expectEqual(D.eval(1, single[1], xi), M.eval(1, multi[1], xi));
    }
}

test "DERIVED: evalEach's components sum to eval, and each component is its own DPF" {
    const M = Mpf(5, 4, 4);
    const alphas: [4]M.Index = .{ 0, 17, 31, 8 };
    const betas: [4]M.Elem = .{ 1, 2, 3, 4 };
    const seeds = detSeeds(4, 909);
    const keys = try M.genWithSeeds(alphas, betas, seeds[0], seeds[1]);

    for (0..M.domain_size) |x| {
        const xi: M.Index = @intCast(x);
        inline for (0..2) |b| {
            var each: [4]M.Elem = undefined;
            M.evalEach(b, keys[b], xi, &each);
            var sum: M.Elem = 0;
            for (each) |e| sum +%= e;
            try testing.expectEqual(M.eval(b, keys[b], xi), sum);
        }
        // Component j, taken alone across both parties, IS the point function
        // f_{α_j, β_j} — the property `pir`'s k-record retrieval depends on.
        var each0: [4]M.Elem = undefined;
        var each1: [4]M.Elem = undefined;
        M.evalEach(0, keys[0], xi, &each0);
        M.evalEach(1, keys[1], xi, &each1);
        for (0..4) |j| {
            const want: M.Elem = if (x == @as(usize, alphas[j])) betas[j] else 0;
            try testing.expectEqual(want, each0[j] +% each1[j]);
        }
    }
}

// ── EXTERNAL: the inherited anchor ────────────────────────────────────────

test "EXTERNAL: an Mpf key reproduces two independently-derived DPF KAT vectors" {
    // The anchor question, answered by composition rather than by generating
    // new vectors: `kat_vectors.v0` and `.v3` were produced by an INDEPENDENT
    // Python re-derivation of BGI16 Fig. 1 (see SPEC.md). Both are n=4, L=4, so
    // they can be the two instances of one `Mpf(4,4,2)` key. If this module's
    // Gen or its encoding deviated at all — a reordered instance, a stray
    // header, a shared seed, a different offset — these bytes would not match.
    const v0 = kat_vectors.v0;
    const v3 = kat_vectors.v3;
    const M = Mpf(4, 4, 2);

    const alphas: [2]M.Index = .{ @intCast(v0.alpha), @intCast(v3.alpha) };
    const betas: [2]M.Elem = .{ @intCast(v0.beta), @intCast(v3.beta) };
    const keys = try M.genWithSeeds(
        alphas,
        betas,
        .{ v0.seed0, v3.seed0 },
        .{ v0.seed1, v3.seed1 },
    );

    // Gen anchor: each sub-key's correction-word portion must be the recorded
    // bytes, for BOTH parties (they share correction words).
    inline for (0..2) |party| {
        var cw_a: [M.Dpf.Key.cw_serialized_len]u8 = undefined;
        var cw_b: [M.Dpf.Key.cw_serialized_len]u8 = undefined;
        keys[party].keys[0].serializeCw(&cw_a);
        keys[party].keys[1].serializeCw(&cw_b);
        try testing.expectEqualSlices(u8, v0.cw, &cw_a);
        try testing.expectEqualSlices(u8, v3.cw, &cw_b);
    }

    // Encoding anchor: the recorded bytes must appear in the SERIALIZED multi
    // key at the offsets the layout predicts — seed, then CWs, per instance,
    // with nothing in between.
    var wire: [M.Key.serialized_len]u8 = undefined;
    keys[0].toBytes(&wire);
    const sub = M.Key.sub_serialized_len;
    try testing.expectEqualSlices(u8, &v0.seed0, wire[0..16]);
    try testing.expectEqualSlices(u8, v0.cw, wire[16..sub]);
    try testing.expectEqualSlices(u8, &v3.seed0, wire[sub..][0..16]);
    try testing.expectEqualSlices(u8, v3.cw, wire[sub + 16 ..][0 .. sub - 16]);

    // Eval anchor: the per-instance evaluations must be the recorded
    // full-domain values. The SUM is not externally anchored — no published
    // vector exists for it — so it is only checked as a re-derivation.
    for (0..M.domain_size) |x| {
        const xi: M.Index = @intCast(x);
        var each0: [2]M.Elem = undefined;
        var each1: [2]M.Elem = undefined;
        M.evalEach(0, keys[0], xi, &each0);
        M.evalEach(1, keys[1], xi, &each1);
        try testing.expectEqual(v0.eval0[x], @as(u64, each0[0]));
        try testing.expectEqual(v3.eval0[x], @as(u64, each0[1]));
        try testing.expectEqual(v0.eval1[x], @as(u64, each1[0]));
        try testing.expectEqual(v3.eval1[x], @as(u64, each1[1]));
        // DERIVED: the summed eval is the sum of the anchored components.
        try testing.expectEqual(
            @as(M.Elem, @truncate(v0.eval0[x])) +% @as(M.Elem, @truncate(v3.eval0[x])),
            M.eval(0, keys[0], xi),
        );
    }
}

// ── the encoding: no length field, by construction ────────────────────────

test "SELF: the key encoding is a compile-time constant with no count field" {
    // `k` is comptime, so `serialized_len` is comptime and `fromBytes` takes a
    // fixed-size array pointer. There is no count in the bytes to trust — the
    // property `pir` depends on, preserved from `dpf` and asserted rather than
    // assumed.
    inline for (.{ 0, 1, 2, 7 }) |k| {
        const M = Mpf(8, 4, k);
        const D = Dpf(8, 4);
        try testing.expectEqual(k * D.Key.serialized_len, M.Key.serialized_len);
        // The decoder's parameter type is a pointer to an array of exactly
        // that length: a compile-time fact, so a mismatched length cannot even
        // be expressed at the call site.
        const Param = @typeInfo(@TypeOf(M.Key.fromBytes)).@"fn".params[0].type.?;
        try testing.expectEqual(
            @as(type, *const [M.Key.serialized_len]u8),
            Param,
        );
    }
}

test "SELF: key round-trips through the codec for arbitrary key material" {
    const M = Mpf(5, 8, 3);
    var key: M.Key = undefined;
    for (&key.keys, 0..) |*sub, j| {
        for (&sub.seed, 0..) |*b, i| b.* = @truncate(j * 41 + i * 7 + 1);
        for (&sub.cw, 0..) |*c, i| {
            for (&c.s_cw, 0..) |*b, q| b.* = @truncate(j * 13 + i * 5 + q);
            c.t_cw_l = @truncate(i + j);
            c.t_cw_r = @truncate(i + j + 1);
        }
        sub.cw_final = @as(u64, j) *% 0x0123456789ABCDEF +% 7;
    }
    var buf: [M.Key.serialized_len]u8 = undefined;
    key.toBytes(&buf);
    const back = M.Key.fromBytes(&buf);
    var buf2: [M.Key.serialized_len]u8 = undefined;
    back.toBytes(&buf2);
    try testing.expectEqualSlices(u8, &buf, &buf2);
    for (key.keys, back.keys) |a, b| {
        try testing.expectEqualSlices(u8, &a.seed, &b.seed);
        try testing.expectEqual(a.cw_final, b.cw_final);
    }
}

// ── seed independence: the guard, and the leak it guards against ──────────

test "SELF: genWithSeeds rejects byte-identical seeds anywhere among the 2k" {
    const M = Mpf(4, 4, 3);
    const alphas: [3]M.Index = .{ 1, 2, 3 };
    const betas: [3]M.Elem = .{ 1, 1, 1 };
    const good = detSeeds(3, 12345);
    _ = try M.genWithSeeds(alphas, betas, good[0], good[1]);

    // the same pair handed to two instances — the plumbing bug this catches
    var s0 = good[0];
    s0[2] = s0[0];
    var s1 = good[1];
    s1[2] = s1[0];
    try testing.expectError(error.SeedReuse, M.genWithSeeds(alphas, betas, s0, s1));

    // a single duplicate on one side only
    var s0b = good[0];
    s0b[1] = s0b[0];
    try testing.expectError(error.SeedReuse, M.genWithSeeds(alphas, betas, s0b, good[1]));

    // a party-0 seed equal to a party-1 seed (the within-pair reuse `dpf`
    // already forbids, checked here because the bundle is where it gets lost)
    var s1c = good[1];
    s1c[0] = good[0][0];
    try testing.expectError(error.SeedReuse, M.genWithSeeds(alphas, betas, good[0], s1c));
}

test "LEAK: with seeds REUSED across instances, the shared index prefix is readable" {
    // The negative control for the guard above, and the answer to "does the
    // relationship between the indices leak?" for the construction WITHOUT the
    // guard. Built with `dpf` directly so it demonstrates the mechanism rather
    // than testing around the rejection.
    //
    // Gen's state at level i depends on the seeds and on α's bits 1..i-1, and
    // cw[i-1] additionally on α_i. So under identical seeds, two indices
    // agreeing on their top p bits produce byte-identical correction words for
    // exactly the first p levels — a server reads the common-prefix length
    // straight out of the bytes it was sent.
    const D = Dpf(8, 4);
    const s0 = detSeed(555);
    const s1 = detSeed(556);
    const a: D.Index = 0b10110000;
    const b: D.Index = 0b10110010; // agrees with `a` on the top 6 bits
    const common_prefix = 6;

    const ka = D.genWithSeeds(a, 1, s0, s1);
    const kb = D.genWithSeeds(b, 1, s0, s1);

    var equal_levels: usize = 0;
    for (ka[0].cw, kb[0].cw) |ca, cb| {
        const same = std.mem.eql(u8, &ca.s_cw, &cb.s_cw) and
            ca.t_cw_l == cb.t_cw_l and ca.t_cw_r == cb.t_cw_r;
        if (!same) break;
        equal_levels += 1;
    }
    // Exactly the prefix length — not "at least", so the measurement is a
    // statement about the mechanism rather than a threshold.
    try testing.expectEqual(@as(usize, common_prefix), equal_levels);
}

test "SELF: with INDEPENDENT seeds, a shared index prefix leaves no matching bytes" {
    // The claim the guard buys: same two indices, same shared 6-bit prefix,
    // but one independent seed pair per instance — and now not even the first
    // correction word matches. Structural: instance j's key is a function of
    // instance j's seeds alone, so the bundle's joint distribution factorises
    // and no cross-instance relationship survives into the bytes.
    const M = Mpf(8, 4, 2);
    const alphas: [2]M.Index = .{ 0b10110000, 0b10110010 };
    const betas: [2]M.Elem = .{ 1, 1 };
    const seeds = detSeeds(2, 6161);
    const keys = try M.genWithSeeds(alphas, betas, seeds[0], seeds[1]);

    var any_equal_level = false;
    for (keys[0].keys[0].cw, keys[0].keys[1].cw) |ca, cb| {
        if (std.mem.eql(u8, &ca.s_cw, &cb.s_cw)) any_equal_level = true;
    }
    try testing.expect(!any_equal_level);

    // And the same for a pair of indices that are outright EQUAL — the case
    // where a seed-sharing construction would be at its most obvious.
    const M2 = Mpf(8, 4, 2);
    const same: [2]M2.Index = .{ 99, 99 };
    const s2 = detSeeds(2, 6262);
    const k2 = try M2.genWithSeeds(same, betas, s2[0], s2[1]);
    var cw_a: [M2.Dpf.Key.cw_serialized_len]u8 = undefined;
    var cw_b: [M2.Dpf.Key.cw_serialized_len]u8 = undefined;
    k2[0].keys[0].serializeCw(&cw_a);
    k2[0].keys[1].serializeCw(&cw_b);
    try testing.expect(!std.mem.eql(u8, &cw_a, &cw_b));
}

// ── harness teeth ─────────────────────────────────────────────────────────

test "positive control: firstMismatch rejects broken multi-point sharings" {
    // Core-independent teeth for the oracle every correctness test above uses,
    // in the same shape as `kat_test.zig`'s brokenAllBeta/brokenAllZero.
    const M = Mpf(3, 4, 2);
    const alphas: [2]M.Index = .{ 1, 6 };
    const betas: [2]M.Elem = .{ 5, 9 };

    // all-zero: misses both spikes
    const zero: [8]M.Elem = @splat(0);
    try testing.expect(M.firstMismatch(&zero, &zero, alphas, betas) != null);

    // a correct hand-built sharing passes …
    var e0: [8]M.Elem = undefined;
    var e1: [8]M.Elem = undefined;
    for (0..8) |x| {
        e0[x] = @truncate(x *% 2654435761 +% 13);
        var want: M.Elem = 0;
        for (alphas, betas) |a, b| {
            if (@as(usize, a) == x) want +%= b;
        }
        e1[x] = want -% e0[x];
    }
    try testing.expectEqual(@as(?usize, null), M.firstMismatch(&e0, &e1, alphas, betas));

    // … and one perturbed point is caught, at exactly that point.
    e1[4] +%= 1;
    try testing.expectEqual(@as(?usize, 4), M.firstMismatch(&e0, &e1, alphas, betas));

    // A sharing that puts only ONE of the two spikes in place must be rejected:
    // the check must not be satisfied by a subset of the points.
    for (0..8) |x| {
        const want: M.Elem = if (x == 1) 5 else 0; // β at α_0 only
        e1[x] = want -% e0[x];
    }
    try testing.expectEqual(@as(?usize, 6), M.firstMismatch(&e0, &e1, alphas, betas));
}

test "SELF: a single key's evaluations do not spike at the shared points (heuristic)" {
    // The multi-point analogue of `kat_test.zig`'s smell test, and just as
    // heuristic: one party's full-domain evaluation must look pseudorandom —
    // in particular the k shared points must not stand out from the rest. Not
    // a proof of anything; a smoke alarm for a catastrophically broken Gen.
    const M = Mpf(8, 4, 5);
    var alphas: [5]M.Index = undefined;
    var betas: [5]M.Elem = undefined;
    for (0..5) |j| {
        alphas[j] = @intCast(j * 50 + 3);
        betas[j] = 1;
    }
    const seeds = detSeeds(5, 24680);
    const keys = try M.genWithSeeds(alphas, betas, seeds[0], seeds[1]);
    var e0: [256]M.Elem = undefined;
    M.evalAll(0, keys[0], &e0);

    var distinct: usize = 0;
    for (0..256) |i| {
        var seen = false;
        for (0..i) |j| {
            if (e0[i] == e0[j]) {
                seen = true;
                break;
            }
        }
        if (!seen) distinct += 1;
    }
    try testing.expect(distinct > 128);
    // None of the shared points is zero or otherwise obviously marked.
    for (alphas) |a| try testing.expect(e0[@as(usize, a)] != 0);
}

// ── fuzz: arbitrary key material through decode + evaluate ────────────────

const FuzzMpf = Mpf(8, 4, 3);

fn fuzzKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    // `fromBytes` takes a fixed-size array pointer, so there is no length for
    // an attacker to lie about — which is precisely why the interesting fuzz
    // target is the CONTENT: arbitrary bytes decoded as a key and then
    // evaluated, both summed and per-instance, over a domain walk.
    var buf: [FuzzMpf.Key.serialized_len]u8 = undefined;
    smith.bytes(&buf);
    const key = FuzzMpf.Key.fromBytes(&buf);

    const party: u1 = @truncate(smith.valueRangeAtMost(u8, 0, 1));
    var each: [3]FuzzMpf.Elem = undefined;
    var acc: FuzzMpf.Elem = 0;
    var x: usize = 0;
    while (x < FuzzMpf.domain_size) : (x += 1) {
        const xi: FuzzMpf.Index = @intCast(x);
        FuzzMpf.evalEach(party, key, xi, &each);
        var sum: FuzzMpf.Elem = 0;
        for (each) |e| sum +%= e;
        try std.testing.expectEqual(FuzzMpf.eval(party, key, xi), sum);
        acc +%= sum;
    }
    std.mem.doNotOptimizeAway(acc);

    // Re-encoding is NOT the identity on arbitrary bytes, and asserting that it
    // is was a real mistake this fuzzer caught (see SPEC.md §"The encoding is
    // not injective"): `serializeCw` writes each control-bit CW as a whole byte
    // valued 0/1, while `fromBytes` truncates that byte to its low bit — so the
    // other seven bits are DROPPED. What must hold is the weaker, true
    // property: re-encoding produces the canonical form, and decoding that form
    // again is a fixed point.
    var out: [FuzzMpf.Key.serialized_len]u8 = undefined;
    key.toBytes(&out);
    const again = FuzzMpf.Key.fromBytes(&out);
    var out2: [FuzzMpf.Key.serialized_len]u8 = undefined;
    again.toBytes(&out2);
    try std.testing.expectEqualSlices(u8, &out, &out2);
    // …and the canonical form differs from the input in exactly the ignored
    // bits, nowhere else.
    for (buf, out, 0..) |in_byte, out_byte, i| {
        const off = i % FuzzMpf.Key.sub_serialized_len;
        const in_cw = off >= 16 and off < 16 + FuzzMpf.n * 18;
        const q = if (in_cw) (off - 16) % 18 else 0;
        if (in_cw and (q == 16 or q == 17)) {
            try std.testing.expectEqual(in_byte & 1, out_byte);
        } else {
            try std.testing.expectEqual(in_byte, out_byte);
        }
    }
}
test "fuzz Mpf key decode + evaluate never panics" {
    try std.testing.fuzz({}, fuzzKeyFromBytes, .{});
}

fn fuzzGenSeeds(_: void, smith: *std.testing.Smith) !void {
    // Arbitrary attacker-influenced seeds and points through Gen: the
    // distinctness guard must be total (never panic, never miss a duplicate it
    // then divides by), and Gen must survive whatever it accepts.
    const K = 4;
    const M = Mpf(6, 4, K);
    var s0: [K]prg_mod.Seed = undefined;
    var s1: [K]prg_mod.Seed = undefined;
    for (&s0) |*s| smith.bytes(s);
    for (&s1) |*s| smith.bytes(s);
    var alphas: [K]M.Index = undefined;
    var betas: [K]M.Elem = undefined;
    for (&alphas) |*a| a.* = @truncate(smith.value(u8));
    for (&betas) |*b| b.* = smith.value(u32);

    const keys = M.genWithSeeds(alphas, betas, s0, s1) catch return;
    // Whatever Gen accepted must still reconstruct: the guard rejects, it does
    // not silently degrade.
    var e0: [M.domain_size]M.Elem = undefined;
    var e1: [M.domain_size]M.Elem = undefined;
    M.evalAll(0, keys[0], &e0);
    M.evalAll(1, keys[1], &e1);
    try std.testing.expectEqual(@as(?usize, null), M.firstMismatch(&e0, &e1, alphas, betas));
}
test "fuzz Mpf gen over arbitrary seeds never panics" {
    try std.testing.fuzz({}, fuzzGenSeeds, .{});
}

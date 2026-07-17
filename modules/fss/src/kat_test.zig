// SPDX-License-Identifier: MIT

//! kat_test — the DPF verification harness.
//!
//! Verification here is **DETERMINISTIC** (unlike a randomized/soundness
//! harness): given fixed seeds, Gen is a pure function and full-domain
//! reconstruction is exhaustive, so every check below is exact — no
//! probabilistic slack.
//!
//! ## What runs TODAY (ungated — proves the harness has teeth)
//!   - The two DELIBERATELY-BROKEN positive controls
//!     (`brokenAllBeta`/`brokenAllZero`) built WITHOUT the real core, fed to
//!     the pure `firstMismatch` full-domain checker: they MUST be rejected,
//!     proving the checker catches both a spurious-nonzero-off-target sharing
//!     and a missing-β-on-target sharing before Gen/Eval even exist.
//!   - (PRG, group, and key-codec unit tests live in their own files.)
//!
//! ## What is GATED behind `gate.core_implemented` (SKIP until Fable flips it)
//!   - Full-domain exhaustive correctness for several (α,β).
//!   - Byte-exact KAT vs the independent-reference vectors in
//!     `kat_vectors.zig` (the anti-self-consistency anchor).
//!   - The security smell test (a single key's EvalAll is ~uniform, no spike
//!     at α) — heuristic, NOT a proof.
//!   - The STRONGER CW-perturbation positive control (flip one control-bit CW
//!     in a real key → the same `firstMismatch` catches it) — needs the real
//!     Gen, so it is gated; the two broken controls above are its
//!     core-independent stand-ins that run today.

const std = @import("std");
const fss = @import("root.zig");
const gate = fss.gate;
const Dpf = fss.Dpf;
const kat_vectors = fss.kat_vectors;

// ── Positive controls that run TODAY (no core) ────────────────────────────

test "positive control: firstMismatch rejects an all-β (constant) sharing" {
    const D = Dpf(4, 4); // domain 16
    const alpha: D.Index = 5;
    const beta: D.Elem = 287454020;
    // brokenAllBeta: reconstructs β at EVERY x (party0 all-zero, party1 all-β).
    // A real DPF must be 0 off-target, so this must be rejected at some x≠α.
    var e0: [D.domain_size]D.Elem = [_]D.Elem{0} ** D.domain_size;
    var e1: [D.domain_size]D.Elem = [_]D.Elem{beta} ** D.domain_size;
    const bad = D.firstMismatch(&e0, &e1, alpha, beta);
    try std.testing.expect(bad != null);
    try std.testing.expect(bad.? != @as(usize, alpha)); // wrong at an off-target point
}

test "positive control: firstMismatch rejects an all-zero sharing (misses β at α)" {
    const D = Dpf(4, 4);
    const alpha: D.Index = 5;
    const beta: D.Elem = 287454020;
    const e0: [D.domain_size]D.Elem = [_]D.Elem{0} ** D.domain_size;
    const e1: [D.domain_size]D.Elem = [_]D.Elem{0} ** D.domain_size;
    // reconstructs 0 everywhere → the α point is wrong (should be β).
    try std.testing.expectEqual(@as(?usize, @as(usize, alpha)), D.firstMismatch(&e0, &e1, alpha, beta));
}

// ── Core-dependent tests (GATED → SKIP until gate.core_implemented) ────────

test "full-domain correctness: Gen+EvalAll reconstruct f_{α,β} exhaustively" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const D = Dpf(8, 4); // domain 256
    // several (α,β), independent fixed seeds per case
    const cases = [_]struct { a: D.Index, b: D.Elem }{
        .{ .a = 0, .b = 1 },
        .{ .a = 200, .b = 0xDEADBEEF },
        .{ .a = 255, .b = 0 },
        .{ .a = 128, .b = 7 },
    };
    for (cases, 0..) |c, i| {
        var s0: [16]u8 = undefined;
        var s1: [16]u8 = undefined;
        for (&s0, &s1, 0..) |*p0, *p1, j| {
            p0.* = @truncate(i * 31 + j * 3 + 1);
            p1.* = @truncate(i * 17 + j * 5 + 200);
        }
        const keys = D.genWithSeeds(c.a, c.b, s0, s1);
        var b0: [D.domain_size]D.Elem = undefined;
        var b1: [D.domain_size]D.Elem = undefined;
        D.evalAll(0, keys[0], &b0);
        D.evalAll(1, keys[1], &b1);
        try std.testing.expectEqual(@as(?usize, null), D.firstMismatch(&b0, &b1, c.a, c.b));
    }
}

test "byte-exact KAT vs independent reference vectors (anti-self-consistency)" {
    if (!gate.core_implemented) return error.SkipZigTest;
    inline for (kat_vectors.all) |v| {
        const D = Dpf(v.n, v.out_bytes);
        const alpha: D.Index = @intCast(v.alpha);
        const beta: D.Elem = @intCast(v.beta);
        const keys = D.genWithSeeds(alpha, beta, v.seed0, v.seed1);
        // Gen anchor: serialized CW portion must match byte-exact.
        var cw_buf: [D.Key.cw_serialized_len]u8 = undefined;
        keys[0].serializeCw(&cw_buf);
        try std.testing.expectEqualSlices(u8, v.cw, &cw_buf);
        // k1 shares the same CW portion.
        var cw_buf1: [D.Key.cw_serialized_len]u8 = undefined;
        keys[1].serializeCw(&cw_buf1);
        try std.testing.expectEqualSlices(u8, v.cw, &cw_buf1);
        // Root seeds are the inputs, echoed into the keys.
        try std.testing.expectEqualSlices(u8, &v.seed0, &keys[0].seed);
        try std.testing.expectEqualSlices(u8, &v.seed1, &keys[1].seed);

        // Eval anchor.
        if (v.eval0.len != 0) {
            var b0: [D.domain_size]D.Elem = undefined;
            var b1: [D.domain_size]D.Elem = undefined;
            D.evalAll(0, keys[0], &b0);
            D.evalAll(1, keys[1], &b1);
            for (0..D.domain_size) |x| {
                try std.testing.expectEqual(v.eval0[x], @as(u64, b0[x]));
                try std.testing.expectEqual(v.eval1[x], @as(u64, b1[x]));
            }
        } else {
            for (v.spot) |sp| {
                const x: D.Index = @intCast(sp[0]);
                try std.testing.expectEqual(sp[1], @as(u64, D.eval(0, keys[0], x)));
                try std.testing.expectEqual(sp[2], @as(u64, D.eval(1, keys[1], x)));
            }
        }
    }
}

test "security smell test: a single key's EvalAll is ~uniform (heuristic)" {
    if (!gate.core_implemented) return error.SkipZigTest;
    // HEURISTIC, not a proof: one party's full-domain shares should look
    // pseudorandom — in particular they must NOT collapse to a constant and
    // must NOT expose α as an obvious spike (e.g. the sole distinct value).
    const D = Dpf(8, 4);
    const alpha: D.Index = 123;
    const beta: D.Elem = 0x01020304;
    const s0 = [_]u8{0x5A} ** 16;
    const s1 = [_]u8{0xA5} ** 16;
    const keys = D.genWithSeeds(alpha, beta, s0, s1);
    var b0: [D.domain_size]D.Elem = undefined;
    D.evalAll(0, keys[0], &b0);
    // count distinct values — a pseudorandom share vector over 256 points
    // should be nearly all-distinct; certainly far more than 2 distinct.
    var distinct: usize = 0;
    for (0..D.domain_size) |i| {
        var seen = false;
        for (0..i) |j| {
            if (b0[i] == b0[j]) {
                seen = true;
                break;
            }
        }
        if (!seen) distinct += 1;
    }
    try std.testing.expect(distinct > D.domain_size / 2);
}

test "positive control (stronger, GATED): flipping one CW bit breaks reconstruction" {
    if (!gate.core_implemented) return error.SkipZigTest;
    // Once the real Gen exists, a one-bit corruption of a correction word must
    // be caught by the SAME full-domain checker — proving the byte-exact CW
    // anchor and the reconstruction check are both load-bearing.
    const D = Dpf(6, 4);
    const alpha: D.Index = 21;
    const beta: D.Elem = 0x0BADF00D;
    const s0 = [_]u8{0x11} ** 16;
    const s1 = [_]u8{0x22} ** 16;
    var keys = D.genWithSeeds(alpha, beta, s0, s1);
    // sanity: unperturbed keys reconstruct
    var b0: [D.domain_size]D.Elem = undefined;
    var b1: [D.domain_size]D.Elem = undefined;
    D.evalAll(0, keys[0], &b0);
    D.evalAll(1, keys[1], &b1);
    try std.testing.expectEqual(@as(?usize, null), D.firstMismatch(&b0, &b1, alpha, beta));
    // flip one control-bit CW at the first level in BOTH keys (they share CWs)
    keys[0].cw[0].t_cw_l ^= 1;
    keys[1].cw[0].t_cw_l ^= 1;
    D.evalAll(0, keys[0], &b0);
    D.evalAll(1, keys[1], &b1);
    try std.testing.expect(D.firstMismatch(&b0, &b1, alpha, beta) != null);
}

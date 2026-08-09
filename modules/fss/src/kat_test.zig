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

/// The KAT vectors were re-derived over the **SHA-256** PRG, so they are
/// stated over that instantiation and not over the (now default) fixed-key-AES
/// one. This is deliberate and is what let the default PRG change without
/// costing the module its anchor: `DpfWith` shares ONE body of
/// correction-word code across instantiations, so reproducing the recorded
/// `cw` bytes still pins that code. What it no longer pins is the PRG itself —
/// for the AES PRG that job belongs to `prg.zig`'s FIPS-197 MMO test.
fn KatDpf(comptime n: usize, comptime L: usize) type {
    return fss.DpfWith(fss.prg.Sha256Prg, n, L);
}

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
        const D = KatDpf(v.n, v.out_bytes);
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

// ── evalFull: tree-reuse prefix evaluator vs the naive oracle ──────────────
//
// `evalFull` must produce EXACTLY what the per-point `eval` path produces —
// bit-for-bit, no tolerance — because `pir` swaps one for the other inside its
// server loop and the swap must be invisible. `evalAll` is the structurally
// independent oracle here: it is a plain loop over `eval` and shares nothing
// with the tree-reuse walk except `eval` itself.

/// deterministic seed pair, distinct per tag
fn efSeeds(tag: u8) [2][16]u8 {
    var s0: [16]u8 = undefined;
    var s1: [16]u8 = undefined;
    for (&s0, &s1, 0..) |*p0, *p1, j| {
        p0.* = @truncate(tag *% 31 +% j *% 3 +% 1);
        p1.* = @truncate(tag *% 17 +% j *% 5 +% 200);
    }
    return .{ s0, s1 };
}

test "evalFull == evalAll element-for-element over the FULL domain (both parties)" {
    if (!gate.core_implemented) return error.SkipZigTest;
    // Small domain fully, and a medium domain fully. α at both edges and in
    // the middle; β including 0 (the all-zero point function's edge).
    inline for (.{ Dpf(4, 4), Dpf(10, 8) }) |D| {
        const alphas = [_]D.Index{ 0, D.domain_size / 2, @intCast(D.domain_size - 1) };
        const betas = [_]D.Elem{ 1, 0xDEADBEEF, 0 };
        for (alphas, betas, 0..) |alpha, beta, i| {
            const seeds = efSeeds(@intCast(i * 7 + D.n));
            const keys = D.genWithSeeds(alpha, beta, seeds[0], seeds[1]);
            inline for (.{ 0, 1 }) |b| {
                var naive: [D.domain_size]D.Elem = undefined;
                var fast: [D.domain_size]D.Elem = undefined;
                D.evalAll(b, keys[b], &naive);
                D.evalFull(b, keys[b], &fast);
                try std.testing.expectEqualSlices(D.Elem, &naive, &fast);
            }
        }
    }
}

test "evalFull over a PREFIX matches eval point-for-point (out.len far below 2^n)" {
    if (!gate.core_implemented) return error.SkipZigTest;
    // The contract pir depends on: a 2^16 domain of which only a few hundred
    // leading points are evaluated. α inside the prefix, exactly at its last
    // point, just past it, and at the far end of the domain — the spike being
    // outside the prefix must simply never be seen.
    const D = Dpf(16, 4);
    const prefix_len = 300;
    const alphas = [_]D.Index{ 0, 150, prefix_len - 1, prefix_len, 65535 };
    var fast: [prefix_len]D.Elem = undefined;
    for (alphas, 0..) |alpha, i| {
        const seeds = efSeeds(@intCast(100 + i));
        const keys = D.genWithSeeds(alpha, 0xC0FFEE, seeds[0], seeds[1]);
        inline for (.{ 0, 1 }) |b| {
            D.evalFull(b, keys[b], &fast);
            for (0..prefix_len) |x| {
                try std.testing.expectEqual(D.eval(b, keys[b], @intCast(x)), fast[x]);
            }
        }
    }
    // Both parties' prefix evaluations reconstruct f_{α,β} on the prefix:
    // β where α is inside it, 0 everywhere else.
    {
        const seeds = efSeeds(200);
        const alpha: D.Index = 150;
        const keys = D.genWithSeeds(alpha, 42, seeds[0], seeds[1]);
        var f0: [prefix_len]D.Elem = undefined;
        var f1: [prefix_len]D.Elem = undefined;
        D.evalFull(0, keys[0], &f0);
        D.evalFull(1, keys[1], &f1);
        for (0..prefix_len) |x| {
            const want: D.Elem = if (x == alpha) 42 else 0;
            try std.testing.expectEqual(want, D.G.add(f0[x], f1[x]));
        }
    }
}

test "evalFull prefix boundary cases: len 0, len 1, and a non-power-of-two straddle" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const D = Dpf(10, 4);
    const seeds = efSeeds(50);
    const keys = D.genWithSeeds(700, 9, seeds[0], seeds[1]);
    inline for (.{ 0, 1 }) |b| {
        // len 0: a defined no-op.
        var empty: [0]D.Elem = undefined;
        D.evalFull(b, keys[b], &empty);
        // len 1: only the leftmost path.
        var one: [1]D.Elem = undefined;
        D.evalFull(b, keys[b], &one);
        try std.testing.expectEqual(D.eval(b, keys[b], 0), one[0]);
        // 257 = 2^8 + 1 leaves: a full subtree plus a lone straddling leaf.
        var odd: [257]D.Elem = undefined;
        D.evalFull(b, keys[b], &odd);
        for (0..odd.len) |x| {
            try std.testing.expectEqual(D.eval(b, keys[b], @intCast(x)), odd[x]);
        }
    }
}

test "evalFullWith streams the same values, each index exactly once, in order" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const D = Dpf(8, 4);
    const seeds = efSeeds(77);
    const keys = D.genWithSeeds(33, 0xABCD, seeds[0], seeds[1]);
    const count = 100;
    const Ctx = struct {
        vals: *[count]D.Elem,
        next: *usize,
        fn emit(ctx: @This(), x: usize, v: D.Elem) void {
            // ascending order, no skip, no repeat — pir's access-pattern
            // requirement rides on this.
            std.debug.assert(x == ctx.next.*);
            ctx.next.* += 1;
            ctx.vals[x] = v;
        }
    };
    inline for (.{ 0, 1 }) |b| {
        var vals: [count]D.Elem = undefined;
        var next: usize = 0;
        D.evalFullWith(b, keys[b], count, Ctx{ .vals = &vals, .next = &next }, Ctx.emit);
        try std.testing.expectEqual(@as(usize, count), next);
        var buf: [count]D.Elem = undefined;
        D.evalFull(b, keys[b], &buf);
        try std.testing.expectEqualSlices(D.Elem, &buf, &vals);
    }
}

// ── evalRangeWith: the sharding entry point (F4) ────────────────────────────
//
// `evalRangeWith(b, key, lo, hi, ...)` is `evalFullWith`'s prefix pruning made
// symmetric on the left edge, so it can seed a walk at any [lo, hi) window
// instead of only [0, hi). The oracle for all of this is `evalFull` — the
// UNCHANGED tree-reuse full-prefix walk, itself already anchored against the
// structurally-independent `evalAll` above. Bit-identical, not "close".

test "evalRangeWith(0, hi) reproduces evalFullWith(hi) — the lo=0 case is not a second implementation" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const D = Dpf(9, 4);
    const seeds = efSeeds(61);
    const keys = D.genWithSeeds(200, 0x1357, seeds[0], seeds[1]);
    const count = 300;
    inline for (.{ 0, 1 }) |b| {
        var full: [count]D.Elem = undefined;
        D.evalFull(b, keys[b], &full);

        var ranged: [count]D.Elem = undefined;
        const Ctx = struct {
            out: *[count]D.Elem,
            fn emit(ctx: @This(), x: usize, v: D.Elem) void {
                ctx.out[x] = v;
            }
        };
        D.evalRangeWith(b, keys[b], 0, count, Ctx{ .out = &ranged }, Ctx.emit);
        try std.testing.expectEqualSlices(D.Elem, &full, &ranged);
    }
}

test "evalRangeWith: disjoint shards sum to evalFull, over several shard counts incl. ones that don't divide the domain, incl. len-0 and len-1 shards" {
    if (!gate.core_implemented) return error.SkipZigTest;
    // 200 leaves: deliberately not a power of two, so shard counts that
    // don't divide it evenly are the common case, not a special one.
    const D = Dpf(10, 4);
    const seeds = efSeeds(88);
    const keys = D.genWithSeeds(137, 0xF00D, seeds[0], seeds[1]);
    const n = 200;

    var want: [n]D.Elem = undefined;
    D.evalFull(0, keys[0], &want);

    // shard_counts includes 1 (degenerate: one shard, the whole range),
    // 2 and 3 (2 divides 200 evenly, 3 does not — 200/3 leaves a remainder
    // shard), and a count deliberately larger than n so most shards are
    // len-0 or len-1 at the tail.
    const shard_counts = [_]usize{ 1, 2, 3, 7, 251 };
    const Ctx = struct {
        out: *[n]D.Elem,
        fn emit(ctx: @This(), x: usize, v: D.Elem) void {
            ctx.out[x] = v;
        }
    };
    for (shard_counts) |shards| {
        var got: [n]D.Elem = @splat(0);
        var saw: [n]bool = @splat(false);
        var lo: usize = 0;
        var shard_idx: usize = 0;
        while (shard_idx < shards) : (shard_idx += 1) {
            // ceil-divide the remaining range across the remaining shards so
            // every leaf lands in exactly one shard, including the len-0
            // shards once `lo == n` (shards > n).
            const remaining_shards = shards - shard_idx;
            const remaining = n - lo;
            const len = (remaining + remaining_shards - 1) / remaining_shards;
            const hi = @min(lo + len, n);
            D.evalRangeWith(0, keys[0], lo, hi, Ctx{ .out = &got }, Ctx.emit);
            for (lo..hi) |x| {
                try std.testing.expect(!saw[x]); // each leaf touched by exactly one shard
                saw[x] = true;
            }
            lo = hi;
        }
        try std.testing.expectEqual(n, lo);
        for (0..n) |x| try std.testing.expect(saw[x]);
        try std.testing.expectEqualSlices(D.Elem, &want, &got);
    }
}

test "evalRangeWith: explicit len-0 and len-1 shards at the domain start, middle, and end" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const D = Dpf(8, 4);
    const seeds = efSeeds(99);
    const keys = D.genWithSeeds(0, 5, seeds[0], seeds[1]); // α at the very first index
    const Ctx = struct {
        calls: *usize,
        last_x: *usize,
        fn emit(ctx: @This(), x: usize, v: D.Elem) void {
            _ = v;
            ctx.calls.* += 1;
            ctx.last_x.* = x;
        }
    };
    inline for (.{ 0, 1 }) |b| {
        // len 0 at the start: no emits at all.
        {
            var calls: usize = 0;
            var last_x: usize = 0;
            D.evalRangeWith(b, keys[b], 0, 0, Ctx{ .calls = &calls, .last_x = &last_x }, Ctx.emit);
            try std.testing.expectEqual(@as(usize, 0), calls);
        }
        // len 0 in the middle (lo == hi, both nonzero): no emits.
        {
            var calls: usize = 0;
            var last_x: usize = 0;
            D.evalRangeWith(b, keys[b], 40, 40, Ctx{ .calls = &calls, .last_x = &last_x }, Ctx.emit);
            try std.testing.expectEqual(@as(usize, 0), calls);
        }
        // len 0 at the domain end: no emits.
        {
            var calls: usize = 0;
            var last_x: usize = 0;
            D.evalRangeWith(b, keys[b], D.domain_size, D.domain_size, Ctx{ .calls = &calls, .last_x = &last_x }, Ctx.emit);
            try std.testing.expectEqual(@as(usize, 0), calls);
        }
        // len 1 exactly on α (index 0): the on-path single-leaf shard.
        {
            var calls: usize = 0;
            var last_x: usize = 0;
            D.evalRangeWith(b, keys[b], 0, 1, Ctx{ .calls = &calls, .last_x = &last_x }, Ctx.emit);
            try std.testing.expectEqual(@as(usize, 1), calls);
            try std.testing.expectEqual(@as(usize, 0), last_x);
        }
        // len 1 well off-path, at the last index.
        {
            var calls: usize = 0;
            var last_x: usize = 0;
            D.evalRangeWith(b, keys[b], D.domain_size - 1, D.domain_size, Ctx{ .calls = &calls, .last_x = &last_x }, Ctx.emit);
            try std.testing.expectEqual(@as(usize, 1), calls);
            try std.testing.expectEqual(D.domain_size - 1, last_x);
        }
    }
    // Reconstruct from three shards touching α at index 0, plus a len-1 and
    // a len-0 shard elsewhere, and check the sum still lands on β at α and
    // 0 everywhere else queried — the off-by-one risk at a shard boundary
    // is exactly what this pins.
    {
        var a0_on: D.Elem = undefined;
        var a1_on: D.Elem = undefined;
        const OnCtx = struct {
            out: *D.Elem,
            fn emit(ctx: @This(), x: usize, v: D.Elem) void {
                _ = x;
                ctx.out.* = v;
            }
        };
        D.evalRangeWith(0, keys[0], 0, 1, OnCtx{ .out = &a0_on }, OnCtx.emit);
        D.evalRangeWith(1, keys[1], 0, 1, OnCtx{ .out = &a1_on }, OnCtx.emit);
        try std.testing.expectEqual(@as(D.Elem, 5), D.G.add(a0_on, a1_on));

        var a0_off: D.Elem = undefined;
        var a1_off: D.Elem = undefined;
        D.evalRangeWith(0, keys[0], 1, 2, OnCtx{ .out = &a0_off }, OnCtx.emit);
        D.evalRangeWith(1, keys[1], 1, 2, OnCtx{ .out = &a1_off }, OnCtx.emit);
        try std.testing.expectEqual(@as(D.Elem, 0), D.G.add(a0_off, a1_off));
    }
}

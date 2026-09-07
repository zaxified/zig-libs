// SPDX-License-Identifier: MIT
//! Fuzz harnesses.
//!
//! Poseidon has no parser and no wire format, so there is no decoder to
//! fuzz — every input is already a field element. What is left is worth
//! fuzzing anyway, because it is a *structural* property that the known-answer
//! tests cannot state: the permutation must be a **permutation**, i.e.
//! injective. A wrong MDS matrix, a state element overwritten mid-round, or an
//! S-box applied to the wrong slot can all collapse two distinct states onto
//! one output while every fixed vector still passes.
//!
//! Run with:
//!
//! ```sh
//! zig build test-poseidon --fuzz --release=safe
//! ```
//!
//! `--release=safe` is not optional: a plain `--fuzz` in Debug does not
//! actually fuzz in this toolchain.

const std = @import("std");
const bn = @import("bn254_poseidon.zig");
const bls = @import("bls12_381_poseidon.zig");

/// An arbitrary field element from fuzz bytes. `reduceWide` rather than
/// `fromBytes` so no draw is ever rejected — the fuzzer should spend its
/// budget on the permutation, not on retrying out-of-range 32-byte strings.
fn arbitraryFr(comptime Fr: type, smith: *std.testing.Smith) Fr {
    var be: [32]u8 = undefined;
    smith.bytes(&be);
    return Fr.reduceWide(&be);
}

fn fuzzInjective(P: bn.Perm(3), smith: *std.testing.Smith) !void {
    var a: [3]bn.Fr = undefined;
    for (&a) |*x| x.* = arbitraryFr(bn.Fr, smith);

    // Perturb exactly one slot by a non-zero delta, so the two inputs are
    // guaranteed distinct and the outputs therefore must be too.
    const slot = smith.value(u8) % 3;
    var delta = arbitraryFr(bn.Fr, smith);
    if (delta.isZero()) delta = bn.fromU64(1);

    var b = a;
    b[slot] = b[slot].add(delta);

    const oa = P.permute(a);
    const ob = P.permute(b);

    var same = true;
    for (oa, ob) |x, y| {
        if (!x.eql(y)) same = false;
    }
    try std.testing.expect(!same);
}

/// A 32-octet big-endian field-element frame, the way `arbitraryFr` reads one.
fn be32(comptime v: u256) [32]u8 {
    return std.mem.toBytes(std.mem.nativeToBig(u256, v));
}

/// ⚠ These harnesses draw with `smith.bytes`, so a corpus entry is read RAW —
/// there is no `u32` length header, unlike a `smith.slice` harness. One
/// `fuzzInjective` round on the wire is: three 32-octet big-endian elements
/// (`arbitraryFr` -> `Fr.reduceWide`), then the eight-octet little-endian word
/// `smith.value(u8)` reads for `slot`, then a fourth element for `delta`.
///
/// ⛔ Why the corpus exists at all: `std.testing.fuzz` with no corpus replays
/// exactly ONE input, the empty one. `smith.bytes` memsets an exhausted input
/// to zero and a scalar draw returns its range minimum, so both injectivity
/// targets ran `a = (0, 0, 0)`, `slot = 0`, `delta = 0` (rewritten to 1) on
/// every run for ever — one state pair, and slots 1 and 2 never perturbed at
/// all. Those are exactly the slots a wrong MDS row or an S-box applied to the
/// wrong element would show up in, which is the defect class this file's
/// module comment says the target exists for.
fn injSeed(
    comptime a0: u256,
    comptime a1: u256,
    comptime a2: u256,
    comptime slot: u64,
    comptime delta: u256,
) []const u8 {
    return &struct {
        const bytes = be32(a0) ++ be32(a1) ++ be32(a2) ++
            std.mem.toBytes(slot) ++ be32(delta);
    }.bytes;
}

/// Shared by both injectivity targets: the two fields read the same 32-octet
/// big-endian frames and both permutations are `t = 3`, so one corpus drives
/// both and a seed that is interesting on one field is interesting on the other.
const inj_seeds = [_][]const u8{
    // The input both targets used to run for ever, spelled out.
    injSeed(0, 0, 0, 0, 0),
    // Each of the three slots perturbed, over a state that is not all-zero.
    injSeed(1, 2, 3, 0, 1),
    injSeed(1, 2, 3, 1, 1),
    injSeed(1, 2, 3, 2, 1),
    // `slot` is `value(u8) % 3`, so a word above 2 still selects: 7 % 3 == 1.
    injSeed(1, 2, 3, 7, 0x1234_5678_9abc_def0),
    // A state whose elements need reducing: all-0xff is far above either
    // field's modulus, so `reduceWide` has to fold it.
    injSeed(
        std.math.maxInt(u256),
        std.math.maxInt(u256),
        std.math.maxInt(u256),
        2,
        std.math.maxInt(u256),
    ),
    // Two slots equal and one different, with a large delta: the shape that
    // catches a permutation collapsing two coordinates onto one.
    injSeed(5, 5, 0, 1, std.math.maxInt(u256) - 1),
    // A drawn delta that reduces to ZERO on both fields (the modulus itself is
    // not expressible in 32 octets for either, but 0 is): the `isZero`
    // fallback to 1, reached deliberately rather than by exhaustion.
    injSeed(9, 8, 7, 2, 0),
};

test "corpus: the injectivity seeds drive slot and delta, and the counts are pinned" {
    // Measured 2026-09-08. ⛔ Not "the property held" — that was already true
    // over the single all-zero input and said nothing. These three numbers are
    // the ones the collapsed input could not move: distinct slots perturbed
    // (it was 1), seeds whose DRAWN delta was already non-zero so the `isZero`
    // fallback did not fire (it was 0), and distinct permutation outputs (1).
    const P = bn.Perm(3).init();
    const Q = bls.Perm(3).init();
    var slots: [3]bool = @splat(false);
    var drawn_delta: usize = 0;
    var seen: [8][3]bn.Fr = undefined;
    var distinct: usize = 0;
    for (inj_seeds) |sd| {
        // The harnesses themselves, over the real `Smith`, on both fields.
        var sm_bn: std.testing.Smith = .{ .in = sd };
        try fuzzInjective(P, &sm_bn);
        var sm_bls: std.testing.Smith = .{ .in = sd };
        try fuzzBlsInjective(Q, &sm_bls);

        // …and the same draw sequence again, to count what it produced.
        var smith: std.testing.Smith = .{ .in = sd };
        var a: [3]bn.Fr = undefined;
        for (&a) |*x| x.* = arbitraryFr(bn.Fr, &smith);
        const slot = smith.value(u8) % 3;
        slots[slot] = true;
        if (!arbitraryFr(bn.Fr, &smith).isZero()) drawn_delta += 1;
        const out = P.permute(a);
        var already = false;
        for (seen[0..distinct]) |prev| {
            var same = true;
            for (prev, out) |x, y| {
                if (!x.eql(y)) same = false;
            }
            if (same) already = true;
        }
        if (!already) {
            seen[distinct] = out;
            distinct += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 3), countTrue(&slots));
    try std.testing.expectEqual(@as(usize, 6), drawn_delta); // 8 seeds, 2 deltas reduce to 0
    try std.testing.expectEqual(@as(usize, 5), distinct); // 5 distinct states among the 8
}

fn countTrue(flags: []const bool) usize {
    var n: usize = 0;
    for (flags) |f| {
        if (f) n += 1;
    }
    return n;
}

test "fuzz: the BN254 t=3 permutation is injective" {
    // `Perm(3).init()` re-derives the round constants (Grain LFSR) and MDS
    // matrix — real work, ~2ms — so it is computed ONCE here and passed as
    // the fuzz context, not inside `fuzzInjective` where it would otherwise
    // re-run on every single fuzzed iteration and burn most of the budget on
    // constant re-derivation instead of the property under test.
    try std.testing.fuzz(bn.Perm(3).init(), fuzzInjective, .{ .corpus = &inj_seeds });
}

fn fuzzFramingAgrees(P: bn.Perm(5), smith: *std.testing.Smith) !void {
    // `hash` is `hashN(1, zero, …)`; `hashN(k, …)` must be a prefix of the
    // permutation output for any k. Cheap, total, and it pins the framing
    // against a "helpful" future change that starts squeezing or padding.
    var in: [4]bn.Fr = undefined;
    for (&in) |*x| x.* = arbitraryFr(bn.Fr, smith);
    const init_state = arbitraryFr(bn.Fr, smith);

    var state: [5]bn.Fr = undefined;
    state[0] = init_state;
    @memcpy(state[1..], &in);
    const full = P.permute(state);

    const k4 = P.hashN(4, init_state, in);
    for (0..4) |i| try std.testing.expect(full[i].eql(k4[i]));

    if (init_state.isZero()) {
        try std.testing.expect(P.hash(in).eql(full[0]));
    }
}

test "fuzz: hash framing is a prefix of the permutation" {
    try std.testing.fuzz(bn.Perm(5).init(), fuzzFramingAgrees, .{});
}

fn fuzzBlsInjective(P: bls.Perm(3), smith: *std.testing.Smith) !void {
    // Same property on the other field — different prime, different Grain
    // seed width, entirely separate constant tables.
    var a: [3]bls.Fr = undefined;
    for (&a) |*x| x.* = arbitraryFr(bls.Fr, smith);
    const slot = smith.value(u8) % 3;
    var delta = arbitraryFr(bls.Fr, smith);
    if (delta.isZero()) delta = bls.fromU64(1);
    var b = a;
    b[slot] = b[slot].add(delta);

    const oa = P.permute(a);
    const ob = P.permute(b);
    var same = true;
    for (oa, ob) |x, y| {
        if (!x.eql(y)) same = false;
    }
    try std.testing.expect(!same);
}

test "fuzz: the BLS12-381 t=3 permutation is injective" {
    try std.testing.fuzz(bls.Perm(3).init(), fuzzBlsInjective, .{ .corpus = &inj_seeds });
}

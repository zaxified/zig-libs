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

fn fuzzInjective(_: void, smith: *std.testing.Smith) !void {
    const P = bn.Perm(3).init();

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

test "fuzz: the BN254 t=3 permutation is injective" {
    try std.testing.fuzz({}, fuzzInjective, .{});
}

fn fuzzFramingAgrees(_: void, smith: *std.testing.Smith) !void {
    // `hash` is `hashN(1, zero, …)`; `hashN(k, …)` must be a prefix of the
    // permutation output for any k. Cheap, total, and it pins the framing
    // against a "helpful" future change that starts squeezing or padding.
    const P = bn.Perm(5).init();
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
    try std.testing.fuzz({}, fuzzFramingAgrees, .{});
}

fn fuzzBlsInjective(_: void, smith: *std.testing.Smith) !void {
    // Same property on the other field — different prime, different Grain
    // seed width, entirely separate constant tables.
    const P = bls.Perm(3).init();
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
    try std.testing.fuzz({}, fuzzBlsInjective, .{});
}

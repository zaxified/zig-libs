// SPDX-License-Identifier: MIT

//! aggregate_test — aggregated range proofs (`proveMultiple`/
//! `verifyMultiple`, paper §4.3): completeness over m = 1..8, the single
//! proof as its m = 1 case, refusal of malformed batches, and soundness
//! against the forgeries aggregation adds (reordered, swapped, dropped or
//! extra commitments). The byte-exact half — dalek's `prove_multiple`
//! proofs verified here and ours by dalek's `verify_multiple` — is in
//! `interop_test.zig`.

const std = @import("std");
const bp = @import("root.zig");
const Generators = bp.Generators;
const Transcript = bp.Transcript;
const Ristretto255 = bp.Ristretto255;
const scalar = Ristretto255.scalar;

const talloc = std.testing.allocator;

/// A deterministic, distinct, nonzero blinding per index.
fn gammaFor(j: usize) [32]u8 {
    var g = [_]u8{0} ** 32;
    std.mem.writeInt(u64, g[0..8], 0x9e37_79b9_7f4a_7c15 *% (@as(u64, j) + 1), .little);
    return scalar.reduce(g);
}

fn commitU64(gens: Generators, v: u64, gamma: [32]u8) Ristretto255 {
    var v_bytes = [_]u8{0} ** 32;
    std.mem.writeInt(u64, v_bytes[0..8], v, .little);
    return bp.commit(gens, v_bytes, gamma);
}

const Batch = struct {
    proof: bp.RangeProof,
    commitments: []Ristretto255,

    fn deinit(self: Batch) void {
        self.proof.deinit(talloc);
        talloc.free(self.commitments);
    }
};

fn proveBatch(gens: Generators, values: []const u64) !Batch {
    const gammas = try talloc.alloc([32]u8, values.len);
    defer talloc.free(gammas);
    const commitments = try talloc.alloc(Ristretto255, values.len);
    errdefer talloc.free(commitments);
    for (values, gammas, commitments, 0..) |v, *g, *c, j| {
        g.* = gammaFor(j);
        c.* = commitU64(gens, v, g.*);
    }
    var t = Transcript.init(bp.rangeproof_domain);
    const proof = try bp.proveMultiple(talloc, gens, &t, values, gammas);
    return .{ .proof = proof, .commitments = commitments };
}

fn verifyBatch(gens: Generators, commitments: []const Ristretto255, proof: bp.RangeProof) bool {
    var t = Transcript.init(bp.rangeproof_domain);
    return bp.verifyMultiple(gens, &t, commitments, proof);
}

test "completeness: m = 1, 2, 4, 8 values at n = 8, boundary values included" {
    const gens = try Generators.initParties(talloc, 8, 8);
    defer gens.deinit(talloc);
    const values = [_]u64{ 0, 255, 1, 128, 77, 254, 3, 200 };
    for ([_]usize{ 1, 2, 4, 8 }) |m| {
        const batch = try proveBatch(gens, values[0..m]);
        defer batch.deinit();
        try std.testing.expect(verifyBatch(gens, batch.commitments, batch.proof));
        // log2(n*m) IPA rounds.
        try std.testing.expectEqual(std.math.log2_int(usize, 8 * m), batch.proof.ipa.l_vec.len);
    }
}

test "completeness: m = 2 at n = 64 with 0 and 2^64 - 1" {
    const gens = try Generators.initParties(talloc, 64, 2);
    defer gens.deinit(talloc);
    const batch = try proveBatch(gens, &.{ std.math.maxInt(u64), 0 });
    defer batch.deinit();
    try std.testing.expect(verifyBatch(gens, batch.commitments, batch.proof));
}

test "m = 1: an aggregated proof of one value is the single proof, both ways" {
    const gens = try Generators.init(talloc, 16);
    defer gens.deinit(talloc);
    const gamma = gammaFor(0);
    const v: u64 = 40_000;
    const commitment = commitU64(gens, v, gamma);

    const batch = try proveBatch(gens, &.{v});
    defer batch.deinit();
    var t1 = Transcript.init(bp.rangeproof_domain);
    try std.testing.expect(bp.verify(gens, &t1, commitment, batch.proof));

    var pt = Transcript.init(bp.rangeproof_domain);
    const single = try bp.prove(talloc, gens, &pt, &v, gamma);
    defer single.deinit(talloc);
    try std.testing.expect(verifyBatch(gens, &.{commitment}, single));
}

test "a single proof verifies over a wider party set (party 0 is the same)" {
    const wide = try Generators.initParties(talloc, 8, 4);
    defer wide.deinit(talloc);
    const narrow = try Generators.init(talloc, 8);
    defer narrow.deinit(talloc);
    const v: u64 = 9;
    const gamma = gammaFor(5);
    var pt = Transcript.init(bp.rangeproof_domain);
    const proof = try bp.prove(talloc, narrow, &pt, &v, gamma);
    defer proof.deinit(talloc);
    var vt = Transcript.init(bp.rangeproof_domain);
    try std.testing.expect(bp.verify(wide, &vt, commitU64(wide, v, gamma), proof));
}

test "proveMultiple refuses malformed batches and out-of-range values" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    const g4 = [_][32]u8{ gammaFor(0), gammaFor(1), gammaFor(2), gammaFor(3) };
    var t = Transcript.init(bp.rangeproof_domain);

    // Empty, not a power of two, gammas of another length.
    try std.testing.expectError(error.InvalidAggregation, bp.proveMultiple(talloc, gens, &t, &.{}, &.{}));
    try std.testing.expectError(error.InvalidAggregation, bp.proveMultiple(talloc, gens, &t, &.{ 1, 2, 3 }, g4[0..3]));
    try std.testing.expectError(error.InvalidAggregation, bp.proveMultiple(talloc, gens, &t, &.{ 1, 2 }, g4[0..1]));
    // More values than the generator set has parties.
    const g8 = g4 ++ g4;
    try std.testing.expectError(error.InvalidAggregation, bp.proveMultiple(talloc, gens, &t, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &g8));
    // Any one value out of range refuses the whole batch, whatever its slot.
    for (0..4) |j| {
        var values = [_]u64{ 1, 2, 3, 4 };
        values[j] = 256;
        try std.testing.expectError(error.ValueOutOfRange, bp.proveMultiple(talloc, gens, &t, &values, &g4));
    }
}

test "soundness: reordered, swapped, dropped or extra commitments are rejected" {
    const gens = try Generators.initParties(talloc, 8, 8);
    defer gens.deinit(talloc);
    const values = [_]u64{ 10, 20, 30, 40 };
    const batch = try proveBatch(gens, &values);
    defer batch.deinit();
    const c = batch.commitments;
    try std.testing.expect(verifyBatch(gens, c, batch.proof));

    // Two commitments swapped: same set, other order.
    try std.testing.expect(!verifyBatch(gens, &.{ c[1], c[0], c[2], c[3] }, batch.proof));
    try std.testing.expect(!verifyBatch(gens, &.{ c[0], c[1], c[3], c[2] }, batch.proof));
    // One commitment to another value (same blinding).
    for (0..4) |j| {
        var forged: [4]Ristretto255 = c[0..4].*;
        forged[j] = commitU64(gens, values[j] + 1, gammaFor(j));
        try std.testing.expect(!verifyBatch(gens, &forged, batch.proof));
    }
    // A prefix, and the batch padded with a fresh commitment.
    try std.testing.expect(!verifyBatch(gens, c[0..2], batch.proof));
    try std.testing.expect(!verifyBatch(gens, &.{ c[0], c[1], c[2], c[3], c[0], c[1], c[2], c[3] }, batch.proof));
    // Three commitments: m must be a power of two.
    try std.testing.expect(!verifyBatch(gens, c[0..3], batch.proof));
    // No commitments at all.
    try std.testing.expect(!verifyBatch(gens, &.{}, batch.proof));
}

test "soundness: fewer parties in the verifier's set, or another width, is rejected" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    const batch = try proveBatch(gens, &.{ 1, 2, 3, 4 });
    defer batch.deinit();

    const two = try Generators.initParties(talloc, 8, 2);
    defer two.deinit(talloc);
    try std.testing.expect(!verifyBatch(two, batch.commitments, batch.proof));

    // n = 16 with m = 2 has the same n*m = 32 and the same round count, but
    // other generators and another domain separator.
    const wide = try Generators.initParties(talloc, 16, 4);
    defer wide.deinit(talloc);
    try std.testing.expect(!verifyBatch(wide, batch.commitments[0..2], batch.proof));
}

test "soundness: one flipped bit in any 32-byte element of an aggregated proof is rejected" {
    const gens = try Generators.initParties(talloc, 8, 2);
    defer gens.deinit(talloc);
    const batch = try proveBatch(gens, &.{ 5, 250 });
    defer batch.deinit();
    const bytes = try batch.proof.toBytesAlloc(talloc);
    defer talloc.free(bytes);

    var off: usize = 0;
    var elements: usize = 0;
    while (off < bytes.len) : (off += 32) {
        const work = try talloc.dupe(u8, bytes);
        defer talloc.free(work);
        work[off + 1] ^= 0x01;
        elements += 1;
        const forged = bp.RangeProof.fromBytesAlloc(talloc, work) catch continue;
        defer forged.deinit(talloc);
        try std.testing.expect(!verifyBatch(gens, batch.commitments, forged));
    }
    // 4 points + 3 scalars + 2*log2(16) IPA points + a, b.
    try std.testing.expectEqual(@as(usize, 4 + 3 + 8 + 2), elements);
}

test "deltaYZMultiple: n = 2, m = 2 against the formula expanded by hand" {
    // delta = (z - z^2)(1 + y + y^2 + y^3) - z^3 * (2^2 - 1) * (1 + z)
    // y = 3, z = 5: (5 - 25) * 40 - 125 * 3 * 6 = -800 - 2250 = -3050.
    const y = [_]u8{3} ++ [_]u8{0} ** 31;
    const z = [_]u8{5} ++ [_]u8{0} ** 31;
    const got = try bp.deltaYZMultiple(talloc, y, z, 2, 2);
    // 3050 = 0x0BEA, little-endian, negated.
    const want = scalar.neg([_]u8{ 0xEA, 0x0B } ++ [_]u8{0} ** 30);
    try std.testing.expectEqualSlices(u8, &want, &got);

    // m = 1 is deltaYZ.
    try std.testing.expectEqualSlices(
        u8,
        &(try bp.deltaYZ(talloc, y, z, 8)),
        &(try bp.deltaYZMultiple(talloc, y, z, 8, 1)),
    );
}

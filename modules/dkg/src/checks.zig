// SPDX-License-Identifier: MIT

//! checks — the DKG correctness invariants, as REAL (ungated) predicates
//! the harness asserts. These are the teeth: they discriminate a correct
//! DKG output from a subtly-wrong one WITHOUT any gated code on the path,
//! which is exactly what lets the `BrokenDkg` positive control in
//! `protocol.zig` prove the harness works before the core exists.
//!
//! The strongest teeth are `reconstructsToQ` (Lagrange-reconstruct the
//! group secret from `t` shares and check `x·G == Q`) and the end-to-end
//! anchor in `root.zig` (feed the shares to the REAL
//! `threshold_ecdsa.signWithShares` and verify under `Q` with std ECDSA) —
//! a "self-consistent but nonstandard" DKG cannot pass either.

const std = @import("std");
const tecdsa = @import("threshold_ecdsa");
const types = @import("types.zig");

pub const Secp256k1 = tecdsa.Secp256k1;
pub const Scalar = tecdsa.Scalar;
pub const Element = tecdsa.Element;
pub const DkgShareOutput = types.DkgShareOutput;

/// Every honest party must have emitted the SAME group public key `Q`.
pub fn allSameQ(outputs: []const DkgShareOutput) bool {
    if (outputs.len == 0) return true;
    const q0 = outputs[0].group_public_key.toBytes();
    for (outputs[1..]) |o| {
        if (!std.mem.eql(u8, &o.group_public_key.toBytes(), &q0)) return false;
    }
    return true;
}

/// A single party's `verifying_share` must equal `secret_share · G`.
pub fn verifyingShareConsistent(o: DkgShareOutput) bool {
    const p = Secp256k1.basePoint.mul(o.secret_share.toBytes(.big), .big) catch return false;
    const expect = (Element.fromPoint(p) catch return false).toBytes();
    return std.mem.eql(u8, &expect, &o.verifying_share.toBytes());
}

/// **The decisive off-line teeth.** Lagrange-reconstruct the group secret
/// `x` from `shares` (any `t` DKG outputs with distinct indices, via the
/// REAL `threshold_ecdsa.reconstructSecret`), then check `x·G == Q`. A
/// correct DKG satisfies this for every `t`-subset; a DKG that accepted a
/// Byzantine bad share (so some party's `x_j != F(j)`) fails it whenever
/// the reconstruction subset includes the corrupted party. Returns
/// `error`/`false` distinctly: a genuine reconstruction failure is `false`
/// (the teeth firing), not a thrown error.
pub fn reconstructsToQ(allocator: std.mem.Allocator, shares: []const DkgShareOutput) !bool {
    if (shares.len == 0) return false;
    const ss = try allocator.alloc(tecdsa.ShamirShare, shares.len);
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(ss));
        allocator.free(ss);
    }
    for (ss, shares) |*dst, src| dst.* = .{ .index = src.index, .scalar = src.secret_share };

    const x = tecdsa.reconstructSecret(ss) catch return false;
    const p = Secp256k1.basePoint.mul(x.toBytes(.big), .big) catch return false;
    const xg = (Element.fromPoint(p) catch return false).toBytes();
    return std.mem.eql(u8, &xg, &shares[0].group_public_key.toBytes());
}

test "reconstructsToQ / allSameQ discriminate a correct sharing from a corrupted one" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Build a correct (2,3) sharing directly (no DKG core needed): pick a
    // secret x and a degree-1 poly F(z) = x + a1·z; X_j = F(j).
    const x = commitScalar(42);
    const a1 = commitScalar(17);
    const Q = try pointOf(x);

    var outs: [3]DkgShareOutput = undefined;
    for (0..3) |k| {
        const j: u32 = @intCast(k + 1);
        const fj = x.add(a1.mul(commitScalar(j)));
        outs[k] = .{
            .index = j,
            .secret_share = fj,
            .group_public_key = Q,
            .verifying_share = try pointOf(fj),
        };
    }

    try testing.expect(allSameQ(&outs));
    try testing.expect(verifyingShareConsistent(outs[0]));
    // Any 2 of 3 reconstruct to Q.
    try testing.expect(try reconstructsToQ(allocator, outs[0..2]));
    try testing.expect(try reconstructsToQ(allocator, &.{ outs[0], outs[2] }));

    // Corrupt party 2's share (as if a bad dealer's share was accepted):
    var bad = outs;
    bad[1].secret_share = bad[1].secret_share.add(commitScalar(1));
    // A subset INCLUDING the corrupted party no longer reconstructs to Q.
    try testing.expect(!(try reconstructsToQ(allocator, bad[0..2])));
    // verifying_share no longer matches its (unchanged) recorded value.
    try testing.expect(!verifyingShareConsistent(bad[1]));
    // Q agreement is unaffected (only the secret was corrupted).
    try testing.expect(allSameQ(&bad));
}

fn commitScalar(v: u32) Scalar {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u32, buf[28..32], v, .big);
    return Scalar.fromBytes(buf, .big) catch unreachable;
}

fn pointOf(s: Scalar) !Element {
    return Element.fromPoint(try Secp256k1.basePoint.mul(s.toBytes(.big), .big));
}

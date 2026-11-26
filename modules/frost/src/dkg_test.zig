// SPDX-License-Identifier: MIT
//! Tests of `dkg.zig` (frost-core's DKG for FROST(secp256k1, SHA-256)).
//!
//!   - frost-core's published DKG vector (`frost-secp256k1/tests/helpers/
//!     vectors_dkg.json`, frost-core v3.0.0; MIT OR Apache-2.0, test data,
//!     transcribed below): from each participant's polynomial, `part1`
//!     reproduces its published commitment; `part2` accepts the other two
//!     participants' published proofs of knowledge (made by frost-core, so
//!     this pins the `HDKG` challenge: DST, preimage order and encoding)
//!     and sends the published shares; `part3` on the published received
//!     shares reproduces the signing share, verifying share, group key and
//!     every verifying share. An RFC model in Python checked the vector
//!     (proofs, commitments, shares) before this file was written.
//!   - Properties: n-of-n reconstruction of the group secret, t-of-n signing
//!     with the DKG output (`round1Commit` → `round2Sign` → `aggregate` →
//!     `verify`), a bent proof and a bent share rejected with the culprit
//!     named, and every count/identifier check of frost-core.

const std = @import("std");
const builtin = @import("builtin");
const frost = @import("root.zig");
const dkg = frost.dkg;

const testing = std.testing;
const Scalar = frost.Scalar;
const Identifier = frost.Identifier;

const VectorShare = struct { from: u16, share: []const u8 };
const VectorParticipant = struct {
    identifier: u16,
    signing_key: []const u8,
    coefficient: []const u8,
    vss_commitments: [2][]const u8,
    proof_of_knowledge: []const u8,
    received_shares: [2]VectorShare,
    verifying_share: []const u8,
    signing_share: []const u8,
};

const vector_verifying_key = "037b5b0c4b6c91a16fb78499e8a74cc792f9ea79cb94860fcb90f801472930de47";
const vector_participants = [_]VectorParticipant{
    .{
        .identifier = 1,
        .signing_key = "e7a3cf1fdb1e17d4c3e8a7f663803ef305d03bdfdc930b824b0664c6b853156d",
        .coefficient = "819adb51466d687c3944f8dad799a09551af9c083c918a50d9a24a883ae86e2a",
        .vss_commitments = .{ "02dd81b7019efd1d38352b8df26a47d8e6bcb4ce7db71b2f9739b01031105294e2", "03cad1d1bc9d75de15ed0b4cb49dbde670d70988aa96d7982a25ee5484c97d3efc" },
        .proof_of_knowledge = "0304df6af7f67b0d5f49ea2116f2d561a0a535c184836779f0f0677ff0838740ce20a0cb076384312f8817e030ca20379bab9247ee56fc3576b0b092f01c005691",
        .received_shares = .{ .{ .from = 2, .share = "3c4ae6fe69d55280cb06a0551f8563e526ee6f133a99433addcbb722a4c6f438" }, .{ .from = 3, .share = "e2454ec522749fc08388fed9c120b6ada8e1fd1e00026624c95b273f94dbf8a8" } },
        .verifying_share = "02b2597e19a037ba2eef224402a50652be93c1ab5bbd6195fc07ae6f6ecfa1304d",
        .signing_share = "87cee034add572924bbd40001bbffa1db1f28a4bf52efebb4c2ad0978c71edf5",
    },
    .{
        .identifier = 2,
        .signing_key = "ea163e297661aadf460b3de39a7550bd9b8fb2d07f1e1db5af098720156591a5",
        .coefficient = "5234a8d4f373a7a184fb627185101326460d99296ac3c5c0ee948e8f5f97a3d4",
        .vss_commitments = .{ "0280709e1bc38ca14a42f04dde31b33308d5a7ed7ef79a87c0cc14200783b519ac", "03490b38389a84ea57fde7b369962a92c53b367c221d5cd4728a7c6dfddb337c51" },
        .proof_of_knowledge = "02afffa1f80fd46f2bac01bf7967649014a3a5236a62f32f98ce11fec20ee7229072c534d89a6b7b4c16129780404e172c3bdb527a77d40d760b80cc6538bcd4c4",
        .received_shares = .{ .{ .from = 1, .share = "ead985c267f8e8cd367299ac12b3801eee809709a66d7fe83e789b4a5dedb080" }, .{ .from = 3, .share = "39ee690094ac23a2373b35714ae7d3dc0e07e380bf547bf71758903d291a3e0b" } },
        .verifying_share = "03037adc4e0f796b96fc639ac194c1e167ccc5dd57505c813b0533b2bcd6d6ddaa",
        .signing_share = "b3477e9659ee0691bdafd1e40230cb07aed5a5e05bd6649f625f12acbb304556",
    },
    .{
        .identifier = 3,
        .signing_key = "8a9c3489b03d1bdecfd6c84237599980890d39d49167b016bb8b5fb530677204",
        .coefficient = "57a91a3b723783e1b3b2369789c71d2d1fd4c3496e9ab60e0dcfc78a647486a4",
        .vss_commitments = .{ "03f26b76678fe0174196430bb94e4e688044ae7bae2ccd7fef21c354429eb8bd61", "020d7a0d25b4ebed5157daf56aba2b89c3e0522f3bc293cc5e138f10e9c5efa465" },
        .proof_of_knowledge = "02ad586ef180cda6bae1d2144ee090d277c77b789c8261349a247073626373cd8723b0ea6a62e8bc37372567ab4ef221d5e0a6c46d57d3746f6e5fde863298a542",
        .received_shares = .{ .{ .from = 1, .share = "6c746113ae6651496fb79286ea4d20b58581562b33b669fd58488745c89fdd69" }, .{ .from = 2, .share = "e0b438a850bca1c3d4fd653829a58a31b309a1661020cebcbaf4d44163f63be0" } },
        .verifying_share = "02f2198ff3f1e1de2249cdc59eb4ec926936892fa39fc1582861ad2e84681624b3",
        .signing_share = "dec01cf806069a912fa263c7e8a19bf1abb8c174c27dca83789354c1e9ee9cb7",
    },
};

fn hexArray(comptime n: usize, s: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

fn scalarHex(s: []const u8) !Scalar {
    return Scalar.fromBytes(try hexArray(32, s), .big);
}

fn elementHex(s: []const u8) !frost.Element {
    return frost.Element.fromBytes(try hexArray(33, s));
}

fn vectorRound1(v: VectorParticipant) !dkg.Round1Received {
    return .{
        .sender = try Identifier.fromU16(v.identifier),
        .package = .{
            .commitment = &.{},
            .proof_of_knowledge = try frost.Signature.fromBytes(try hexArray(65, v.proof_of_knowledge)),
        },
    };
}

/// Deterministic test scalar (never zero in practice): `hdkg("dkg-test" || tag || i)`.
fn testScalar(tag: u8, i: u32) Scalar {
    var buf: [13]u8 = undefined;
    buf[0..8].* = "dkg-test".*;
    buf[8] = tag;
    std.mem.writeInt(u32, buf[9..13], i, .big);
    return frost.hdkg(&buf);
}

test "dkg: frost-core's published DKG vector (secp256k1, 2-of-3)" {
    const gpa = testing.allocator;
    var commitments: [3][2]frost.Element = undefined;
    for (vector_participants, 0..) |v, i| {
        commitments[i] = .{ try elementHex(v.vss_commitments[0]), try elementHex(v.vss_commitments[1]) };
    }
    const vk = try elementHex(vector_verifying_key);

    for (vector_participants, 0..) |me, mi| {
        const id = try Identifier.fromU16(me.identifier);
        const coeffs = [_]Scalar{ try scalarHex(me.signing_key), try scalarHex(me.coefficient) };
        const nonce = testScalar('k', @intCast(mi));

        var secret1: dkg.Round1SecretPackage = undefined;
        var pkg = try dkg.part1(gpa, &secret1, id, 3, 2, &coeffs, &nonce);
        defer pkg.deinit(gpa);
        defer secret1.deinit(gpa);
        // part1 reproduces the published commitment; its own proof verifies.
        try testing.expectEqualSlices(u8, &commitments[mi][0].bytes, &pkg.commitment[0].bytes);
        try testing.expectEqualSlices(u8, &commitments[mi][1].bytes, &pkg.commitment[1].bytes);
        try testing.expect(dkg.verifyProofOfKnowledge(id, pkg));

        // The other two participants' published round-1 packages.
        var r1: [2]dkg.Round1Received = undefined;
        var r2: [2]dkg.Round2Received = undefined;
        var n: usize = 0;
        for (vector_participants, 0..) |other, oi| {
            if (oi == mi) continue;
            r1[n] = try vectorRound1(other);
            r1[n].package.commitment = &commitments[oi];
            n += 1;
        }
        for (me.received_shares, 0..) |rs, k| {
            r2[k] = .{ .sender = try Identifier.fromU16(rs.from), .signing_share = try frost.SigningShare.fromBytes(try hexArray(32, rs.share)) };
        }

        var secret2: dkg.Round2SecretPackage = undefined;
        const sent = try dkg.part2(gpa, &secret2, &secret1, &r1, null);
        defer dkg.freeRound2Packages(gpa, sent);
        defer secret2.deinit(gpa);
        // What we send to each other participant is what it published as received from us.
        for (sent) |s| {
            const to = vector_participants[s.recipient.bytes[31] - 1];
            for (to.received_shares) |rs| {
                if (rs.from == me.identifier) try testing.expectEqualSlices(u8, &(try hexArray(32, rs.share)), &s.signing_share.bytes);
            }
        }

        var key: dkg.KeyPackage = undefined;
        var pubkeys = try dkg.part3(gpa, &key, &secret2, &r1, &r2, null);
        defer pubkeys.deinit(gpa);
        defer key.deinit();
        try testing.expectEqualSlices(u8, &(try hexArray(32, me.signing_share)), &key.signing_share.bytes);
        try testing.expectEqualSlices(u8, &(try hexArray(33, me.verifying_share)), &key.verifying_share.bytes);
        try testing.expectEqualSlices(u8, &vk.bytes, &key.verifying_key.bytes);
        try testing.expectEqualSlices(u8, &vk.bytes, &pubkeys.verifying_key.bytes);
        try testing.expectEqual(@as(u16, 2), key.min_signers);
        try testing.expectEqual(@as(usize, 3), pubkeys.verifying_shares.len);
        for (pubkeys.verifying_shares, vector_participants) |e, p| {
            try testing.expectEqual(p.identifier, std.mem.readInt(u16, e.identifier.bytes[30..32], .big));
            try testing.expectEqualSlices(u8, &(try hexArray(33, p.verifying_share)), &e.verifying_share.bytes);
        }
    }
}

test "dkg: frost-core's published proofs of knowledge are bound to sender, commitment and R" {
    var commitments: [3][2]frost.Element = undefined;
    for (vector_participants, 0..) |v, i| {
        commitments[i] = .{ try elementHex(v.vss_commitments[0]), try elementHex(v.vss_commitments[1]) };
    }
    for (vector_participants, 0..) |v, i| {
        var r = try vectorRound1(v);
        r.package.commitment = &commitments[i];
        try testing.expect(dkg.verifyProofOfKnowledge(r.sender, r.package));
        // Another sender, another commitment, a bent mu: refused.
        try testing.expect(!dkg.verifyProofOfKnowledge(try Identifier.fromU16(v.identifier % 3 + 1), r.package));
        var other = r.package;
        other.commitment = &commitments[(i + 1) % 3];
        try testing.expect(!dkg.verifyProofOfKnowledge(r.sender, other));
        var bent = r.package;
        bent.proof_of_knowledge.z[31] ^= 1;
        try testing.expect(!dkg.verifyProofOfKnowledge(r.sender, bent));
        try testing.expect(!dkg.verifyProofOfKnowledge(r.sender, .{ .commitment = &.{}, .proof_of_knowledge = r.package.proof_of_knowledge }));
    }
}

/// A full in-memory DKG run among `n` participants with threshold `t`;
/// participant `i` (0-based) has identifier `i + 1`.
const Run = struct {
    n: u16,
    t: u16,
    secrets1: []dkg.Round1SecretPackage,
    packages: []dkg.Round1Package,
    secrets2: []dkg.Round2SecretPackage,
    sent: [][]dkg.Round2Package,
    keys: []dkg.KeyPackage,
    pubs: []dkg.PublicKeyPackage,

    fn deinit(self: *Run, gpa: std.mem.Allocator) void {
        for (self.secrets1) |*s| s.deinit(gpa);
        for (self.packages) |*p| p.deinit(gpa);
        for (self.secrets2) |*s| s.deinit(gpa);
        for (self.sent) |s| dkg.freeRound2Packages(gpa, s);
        for (self.keys) |*k| k.deinit();
        for (self.pubs) |*p| p.deinit(gpa);
        gpa.free(self.secrets1);
        gpa.free(self.packages);
        gpa.free(self.secrets2);
        gpa.free(self.sent);
        gpa.free(self.keys);
        gpa.free(self.pubs);
    }
};

fn round1For(gpa: std.mem.Allocator, packages: []const dkg.Round1Package, me: usize) ![]dkg.Round1Received {
    const out = try gpa.alloc(dkg.Round1Received, packages.len - 1);
    var k: usize = 0;
    for (packages, 0..) |p, i| {
        if (i == me) continue;
        out[k] = .{ .sender = try Identifier.fromU16(@intCast(i + 1)), .package = p };
        k += 1;
    }
    return out;
}

fn round2For(gpa: std.mem.Allocator, sent: []const []dkg.Round2Package, me: usize) ![]dkg.Round2Received {
    const out = try gpa.alloc(dkg.Round2Received, sent.len - 1);
    const my_id = try Identifier.fromU16(@intCast(me + 1));
    var k: usize = 0;
    for (sent, 0..) |list, i| {
        if (i == me) continue;
        for (list) |s| {
            if (std.mem.eql(u8, &s.recipient.bytes, &my_id.bytes)) {
                out[k] = .{ .sender = try Identifier.fromU16(@intCast(i + 1)), .signing_share = s.signing_share };
                k += 1;
            }
        }
    }
    std.debug.assert(k == out.len);
    return out;
}

fn runDkg(gpa: std.mem.Allocator, n: u16, t: u16, seed: u32) !Run {
    var run: Run = .{
        .n = n,
        .t = t,
        .secrets1 = try gpa.alloc(dkg.Round1SecretPackage, n),
        .packages = try gpa.alloc(dkg.Round1Package, n),
        .secrets2 = try gpa.alloc(dkg.Round2SecretPackage, n),
        .sent = try gpa.alloc([]dkg.Round2Package, n),
        .keys = try gpa.alloc(dkg.KeyPackage, n),
        .pubs = try gpa.alloc(dkg.PublicKeyPackage, n),
    };
    const coeffs = try gpa.alloc(Scalar, t);
    defer gpa.free(coeffs);
    for (0..n) |i| {
        for (coeffs, 0..) |*c, j| c.* = testScalar('a', seed *% 1000 + @as(u32, @intCast(i * 64 + j)));
        const nonce = testScalar('k', seed *% 1000 + @as(u32, @intCast(i)));
        run.packages[i] = try dkg.part1(gpa, &run.secrets1[i], try Identifier.fromU16(@intCast(i + 1)), n, t, coeffs, &nonce);
    }
    for (0..n) |i| {
        const r1 = try round1For(gpa, run.packages, i);
        defer gpa.free(r1);
        run.sent[i] = try dkg.part2(gpa, &run.secrets2[i], &run.secrets1[i], r1, null);
    }
    for (0..n) |i| {
        const r1 = try round1For(gpa, run.packages, i);
        defer gpa.free(r1);
        const r2 = try round2For(gpa, run.sent, i);
        defer gpa.free(r2);
        run.pubs[i] = try dkg.part3(gpa, &run.keys[i], &run.secrets2[i], r1, r2, null);
    }
    return run;
}

test "dkg: 3-of-5 run — every participant agrees; t shares reconstruct the sum of the a_i0; t-of-n signing verifies" {
    const gpa = testing.allocator;
    var run = try runDkg(gpa, 5, 3, 1);
    defer run.deinit(gpa);

    // Every participant computed the same public key package, and each
    // participant's own verifying share is in it.
    for (run.pubs[1..]) |p| {
        try testing.expectEqualSlices(u8, &run.pubs[0].verifying_key.bytes, &p.verifying_key.bytes);
        for (p.verifying_shares, run.pubs[0].verifying_shares) |a, b| try testing.expectEqual(a, b);
    }
    for (run.keys) |k| {
        try testing.expectEqual(k.verifying_share, run.pubs[0].verifyingShare(k.identifier).?);
        try testing.expectEqual(k.verifying_key, run.pubs[0].verifying_key);
    }

    // The group secret is Σ a_i0 (no one holds it); any 3 shares give it.
    var group_secret = Scalar.zero;
    for (run.secrets1) |s| group_secret = group_secret.add(s.coefficients[0]);
    const gpk = try frost.Element.fromPoint(try frost.Secp256k1.combMulBase(group_secret.toBytes(.big), .big));
    try testing.expectEqual(gpk, run.pubs[0].verifying_key);
    const subsets = [_][3]usize{ .{ 0, 1, 2 }, .{ 0, 2, 4 }, .{ 1, 3, 4 } };
    for (subsets) |sub| {
        var shares: [3]frost.ParticipantShare = undefined;
        for (sub, 0..) |i, k| shares[k] = .{ .identifier = run.keys[i].identifier, .signing_share = run.keys[i].signing_share };
        try testing.expect((try frost.secretShareCombine(&shares)).equivalent(group_secret));
    }
    // All five (n-of-n) too; two shares give a different value.
    var all: [5]frost.ParticipantShare = undefined;
    for (run.keys, 0..) |k, i| all[i] = .{ .identifier = k.identifier, .signing_share = k.signing_share };
    try testing.expect((try frost.secretShareCombine(&all)).equivalent(group_secret));
    try testing.expect(!(try frost.secretShareCombine(all[0..2])).equivalent(group_secret));

    // Sign with participants 2, 4, 5 under the DKG key.
    const signers = [_]usize{ 1, 3, 4 };
    var nonces: [3]frost.SigningNonces = undefined;
    var list: [3]frost.SigningCommitments = undefined;
    for (signers, 0..) |i, k| {
        var hr: [32]u8 = undefined;
        var br: [32]u8 = undefined;
        hr = testScalar('h', @intCast(i)).toBytes(.big);
        br = testScalar('b', @intCast(i)).toBytes(.big);
        frost.generateNonces(&nonces[k], &run.keys[i].signing_share, hr, br);
        const c = try frost.round1Commit(&nonces[k]);
        list[k] = .{ .identifier = run.keys[i].identifier, .hiding = c.hiding, .binding = c.binding };
    }
    const msg = "signed under a DKG key";
    var sig_shares: [3]frost.SignatureShare = undefined;
    var vshares: [3]frost.VerifyingShare = undefined;
    for (signers, 0..) |i, k| {
        const key = run.keys[i];
        sig_shares[k] = try frost.round2Sign(gpa, key.identifier, &key.signing_share, key.verifying_key, &nonces[k], msg, &list);
        vshares[k] = key.verifying_share;
    }
    const sig = try frost.aggregateVerified(gpa, &list, msg, run.pubs[0].verifying_key, &sig_shares, &vshares, null);
    try testing.expect(frost.verify(msg, sig, run.pubs[0].verifying_key));
    for (&nonces) |*nn| nn.deinit();
}

test "dkg: a bent proof of knowledge is refused in part2, the sender named" {
    const gpa = testing.allocator;
    var run = try runDkg(gpa, 3, 2, 2);
    defer run.deinit(gpa);
    const r1 = try round1For(gpa, run.packages, 0);
    defer gpa.free(r1);
    r1[1].package.proof_of_knowledge.z[31] ^= 1; // participant 3's proof
    var culprit: Identifier = undefined;
    var s2: dkg.Round2SecretPackage = undefined;
    try testing.expectError(error.InvalidProofOfKnowledge, dkg.part2(gpa, &s2, &run.secrets1[0], r1, &culprit));
    try testing.expectEqual(try Identifier.fromU16(3), culprit);
    // A commitment swapped under a valid proof: refused too.
    const r1b = try round1For(gpa, run.packages, 0);
    defer gpa.free(r1b);
    r1b[0].package.commitment = run.packages[2].commitment;
    try testing.expectError(error.InvalidProofOfKnowledge, dkg.part2(gpa, &s2, &run.secrets1[0], r1b, &culprit));
    try testing.expectEqual(try Identifier.fromU16(2), culprit);
}

test "dkg: a bent secret share is refused in part3, the sender named" {
    const gpa = testing.allocator;
    var run = try runDkg(gpa, 4, 3, 3);
    defer run.deinit(gpa);
    const r1 = try round1For(gpa, run.packages, 1);
    defer gpa.free(r1);
    const r2 = try round2For(gpa, run.sent, 1);
    defer gpa.free(r2);
    r2[2].signing_share = frost.SigningShare.fromScalar(r2[2].signing_share.scalar().add(Scalar.one)); // from participant 4
    var culprit: Identifier = undefined;
    var key: dkg.KeyPackage = undefined;
    try testing.expectError(error.InvalidSecretShare, dkg.part3(gpa, &key, &run.secrets2[1], r1, r2, &culprit));
    try testing.expectEqual(try Identifier.fromU16(4), culprit);
}

test "dkg: frost-core's parameter, count and identifier checks" {
    const gpa = testing.allocator;
    const id1 = try Identifier.fromU16(1);
    const c3 = [_]Scalar{ testScalar('a', 1), testScalar('a', 2), testScalar('a', 3) };
    const nonce = testScalar('k', 1);
    var s1: dkg.Round1SecretPackage = undefined;
    try testing.expectError(error.InvalidParameters, dkg.part1(gpa, &s1, id1, 3, 1, c3[0..1], &nonce)); // t < 2
    try testing.expectError(error.InvalidParameters, dkg.part1(gpa, &s1, id1, 2, 3, &c3, &nonce)); // n < t
    try testing.expectError(error.InvalidParameters, dkg.part1(gpa, &s1, id1, 3, 2, &c3, &nonce)); // t + 1 coefficients
    const with_zero = [_]Scalar{ testScalar('a', 1), Scalar.zero };
    try testing.expectError(error.InvalidParameters, dkg.part1(gpa, &s1, id1, 3, 2, &with_zero, &nonce));
    try testing.expectError(error.InvalidParameters, dkg.part1(gpa, &s1, id1, 3, 2, c3[0..2], &Scalar.zero));

    var run = try runDkg(gpa, 3, 2, 4);
    defer run.deinit(gpa);
    var s2: dkg.Round2SecretPackage = undefined;
    var key: dkg.KeyPackage = undefined;
    const r1 = try round1For(gpa, run.packages, 0);
    defer gpa.free(r1);
    const r2 = try round2For(gpa, run.sent, 0);
    defer gpa.free(r2);

    // part2: count, own identifier, duplicate, commitment length.
    try testing.expectError(error.IncorrectNumberOfPackages, dkg.part2(gpa, &s2, &run.secrets1[0], r1[0..1], null));
    var own = r1[0..2].*;
    own[0].sender = id1;
    try testing.expectError(error.UnknownIdentifier, dkg.part2(gpa, &s2, &run.secrets1[0], &own, null));
    var dup = r1[0..2].*;
    dup[1].sender = dup[0].sender;
    try testing.expectError(error.DuplicatedIdentifier, dkg.part2(gpa, &s2, &run.secrets1[0], &dup, null));
    var short = r1[0..2].*;
    short[1].package.commitment = short[1].package.commitment[0..1];
    try testing.expectError(error.IncorrectNumberOfCommitments, dkg.part2(gpa, &s2, &run.secrets1[0], &short, null));

    // part3: counts, own identifier, a round-1 sender without a share.
    try testing.expectError(error.IncorrectNumberOfPackages, dkg.part3(gpa, &key, &run.secrets2[0], r1[0..1], r2, null));
    try testing.expectError(error.IncorrectNumberOfPackages, dkg.part3(gpa, &key, &run.secrets2[0], r1, r2[0..1], null));
    var own2 = r2[0..2].*;
    own2[0].sender = id1;
    try testing.expectError(error.UnknownIdentifier, dkg.part3(gpa, &key, &run.secrets2[0], r1, &own2, null));
    var other = r2[0..2].*;
    other[0].sender = try Identifier.fromU16(9);
    try testing.expectError(error.IncorrectPackage, dkg.part3(gpa, &key, &run.secrets2[0], r1, &other, null));
    var dup2 = r2[0..2].*;
    dup2[1].sender = dup2[0].sender;
    try testing.expectError(error.DuplicatedIdentifier, dkg.part3(gpa, &key, &run.secrets2[0], r1, &dup2, null));
}

test "dkg: an allocation failure in any part leaks nothing" {
    const gpa = testing.allocator;
    var run = try runDkg(gpa, 3, 2, 5);
    defer run.deinit(gpa);
    const r1 = try round1For(gpa, run.packages, 0);
    defer gpa.free(r1);
    const r2 = try round2For(gpa, run.sent, 0);
    defer gpa.free(r2);
    const coeffs = [_]Scalar{ testScalar('a', 7), testScalar('a', 8) };
    const nonce = testScalar('k', 7);
    var fail_index: usize = 0;
    while (fail_index < 4) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = fail_index });
        const fa = failing.allocator();
        var s1: dkg.Round1SecretPackage = undefined;
        if (dkg.part1(fa, &s1, try Identifier.fromU16(1), 3, 2, &coeffs, &nonce)) |p| {
            var pp = p;
            pp.deinit(fa);
            s1.deinit(fa);
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
        var s2: dkg.Round2SecretPackage = undefined;
        if (dkg.part2(fa, &s2, &run.secrets1[0], r1, null)) |sent| {
            dkg.freeRound2Packages(fa, sent);
            s2.deinit(fa);
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
        var key: dkg.KeyPackage = undefined;
        if (dkg.part3(fa, &key, &run.secrets2[0], r1, r2, null)) |pk| {
            var p = pk;
            p.deinit(fa);
            key.deinit();
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
    }
}

// ── delta mutation run 2026-11-25 ───────────────────────────────────────────

test "mutation 2026-11-25: part1 accepts max_signers == min_signers" {
    const gpa = testing.allocator;
    const coeffs = [_]Scalar{ testScalar('a', 31), testScalar('a', 32) };
    const nonce = testScalar('k', 31);
    var s1: dkg.Round1SecretPackage = undefined;
    var pkg = try dkg.part1(gpa, &s1, try Identifier.fromU16(1), 2, 2, &coeffs, &nonce);
    defer pkg.deinit(gpa);
    defer s1.deinit(gpa);
    try testing.expectEqual(@as(u16, 2), s1.max_signers);
    try testing.expectEqual(@as(u16, 2), s1.min_signers);
}

test "mutation 2026-11-25: verifyProofOfKnowledge refuses a malformed commitment, R, or scalar, and a zero scalar" {
    const gpa = testing.allocator;
    var run = try runDkg(gpa, 3, 2, 11);
    defer run.deinit(gpa);
    const sender = try Identifier.fromU16(2);
    const good = run.packages[1];
    try testing.expect(dkg.verifyProofOfKnowledge(sender, good));
    const junk: frost.Element = .{ .bytes = @splat(0) };

    var bad_commit = [2]frost.Element{ junk, good.commitment[1] };
    try testing.expect(!dkg.verifyProofOfKnowledge(sender, .{ .commitment = &bad_commit, .proof_of_knowledge = good.proof_of_knowledge }));
    var bad_r = good;
    bad_r.proof_of_knowledge.r = junk;
    try testing.expect(!dkg.verifyProofOfKnowledge(sender, bad_r));
    var big_z = good;
    big_z.proof_of_knowledge.z = @splat(0xff); // >= the group order
    try testing.expect(!dkg.verifyProofOfKnowledge(sender, big_z));
    var zero_z = good;
    zero_z.proof_of_knowledge.z = @splat(0);
    try testing.expect(!dkg.verifyProofOfKnowledge(sender, zero_z));
    try testing.expect(!dkg.verifyProofOfKnowledge(sender, .{ .commitment = &.{}, .proof_of_knowledge = good.proof_of_knowledge }));
}

test "mutation 2026-11-25: part2 and part3 refuse too many packages and over-long commitments" {
    const gpa = testing.allocator;
    var run = try runDkg(gpa, 3, 2, 12);
    defer run.deinit(gpa);
    const id4 = try Identifier.fromU16(4);
    const r1 = try round1For(gpa, run.packages, 0);
    defer gpa.free(r1);
    const r2 = try round2For(gpa, run.sent, 0);
    defer gpa.free(r2);
    var s2: dkg.Round2SecretPackage = undefined;
    var key: dkg.KeyPackage = undefined;

    // One package too many (a third sender).
    var extra1 = [3]dkg.Round1Received{ r1[0], r1[1], .{ .sender = id4, .package = r1[0].package } };
    try testing.expectError(error.IncorrectNumberOfPackages, dkg.part2(gpa, &s2, &run.secrets1[0], &extra1, null));
    try testing.expectError(error.IncorrectNumberOfPackages, dkg.part3(gpa, &key, &run.secrets2[0], &extra1, &[3]dkg.Round2Received{ r2[0], r2[1], .{ .sender = id4, .signing_share = r2[0].signing_share } }, null));
    // Consistently too few in both lists.
    try testing.expectError(error.IncorrectNumberOfPackages, dkg.part3(gpa, &key, &run.secrets2[0], r1[0..1], r2[0..1], null));

    // A commitment with an extra element (the proof only reads element 0).
    const c = r1[0].package.commitment;
    var long = [3]frost.Element{ c[0], c[1], c[1] };
    var longer = [2]dkg.Round1Received{ r1[0], r1[1] };
    longer[0].package.commitment = &long;
    try testing.expectError(error.IncorrectNumberOfCommitments, dkg.part2(gpa, &s2, &run.secrets1[0], &longer, null));
    try testing.expectError(error.IncorrectNumberOfCommitments, dkg.part3(gpa, &key, &run.secrets2[0], &longer, r2, null));

    // part3: a duplicate sender among the round-1 packages (round 2 is fine).
    var dup1 = [2]dkg.Round1Received{ r1[0], r1[1] };
    dup1[1].sender = dup1[0].sender;
    try testing.expectError(error.DuplicatedIdentifier, dkg.part3(gpa, &key, &run.secrets2[0], &dup1, r2, null));
    // part3: the participant's own identifier among the round-1 senders.
    var own1 = [2]dkg.Round1Received{ r1[0], r1[1] };
    own1[0].sender = try Identifier.fromU16(1);
    try testing.expectError(error.UnknownIdentifier, dkg.part3(gpa, &key, &run.secrets2[0], &own1, r2, null));
}

fn allZero(p: [*]const volatile u8, n: usize) bool {
    for (0..n) |i| if (p[i] != 0) return false;
    return true;
}

test "mutation 2026-11-25: every dkg secret container is wiped by its deinit (ReleaseFast: the safe builds poison on free)" {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
    const gpa = testing.allocator;
    var run = try runDkg(gpa, 3, 2, 21);
    defer run.deinit(gpa);
    var buf: [16384]u8 align(16) = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();

    // Round1SecretPackage.deinit: the coefficients.
    const coefs = [_]Scalar{ testScalar('a', 91), testScalar('a', 92) };
    const nonce = testScalar('k', 91);
    var s1: dkg.Round1SecretPackage = undefined;
    var pkg = try dkg.part1(a, &s1, try Identifier.fromU16(1), 3, 2, &coefs, &nonce);
    const cp: [*]const volatile u8 = @ptrCast(s1.coefficients.ptr);
    const clen = s1.coefficients.len * @sizeOf(Scalar);
    try testing.expect(!allZero(cp, clen));
    pkg.deinit(a);
    s1.deinit(a);
    try testing.expect(allZero(cp, clen));

    // freeRound2Packages and Round2SecretPackage.deinit (the kept share).
    const r1 = try round1For(gpa, run.packages, 0);
    defer gpa.free(r1);
    var sec2: dkg.Round2SecretPackage = undefined;
    const sent = try dkg.part2(a, &sec2, &run.secrets1[0], r1, null);
    const sp: [*]const volatile u8 = @ptrCast(sent.ptr);
    const slen = sent.len * @sizeOf(dkg.Round2Package);
    try testing.expect(!allZero(sp, slen));
    dkg.freeRound2Packages(a, sent);
    try testing.expect(allZero(sp, slen));
    const kp: [*]const volatile u8 = @ptrCast(&sec2.secret_share.bytes);
    try testing.expect(!allZero(kp, 32));
    const r2 = try round2For(gpa, run.sent, 0);
    defer gpa.free(r2);
    var key: dkg.KeyPackage = undefined;
    var pubs = try dkg.part3(a, &key, &sec2, r1, r2, null);
    defer pubs.deinit(a);
    sec2.deinit(a);
    try testing.expect(allZero(kp, 32));

    // KeyPackage.deinit: the signing share.
    const sk: [*]const volatile u8 = @ptrCast(&key.signing_share.bytes);
    try testing.expect(!allZero(sk, 32));
    key.deinit();
    try testing.expect(allZero(sk, 32));
}

// SPDX-License-Identifier: MIT

//! neptune (Filecoin) compatibility: the known answers neptune's own test suite
//! pins (`src/poseidon.rs`, `hash_values`), the round-number table and the
//! constants of its `parameters/` directory.
//!
//! Provenance. Source: github.com/lurk-lab/neptune (the repository moved from
//! filecoin-project/neptune; today argumentcomputer/neptune), `LICENSE-MIT` /
//! `LICENSE-APACHE`, commit b06f03c (2025-03-10), read as source text; nothing
//! was executed to produce these values. The digests are the `scalar_from_u64s`
//! limbs (little-endian, lowest first) of `expected` (inputs `0..arity`, Merkle
//! tag) and `expected_constant` (`ConstantLength(4)` over inputs `0..4`; only the
//! arities `>= 4` reduce to one permutation, arity 2 needs neptune's sponge) in
//! `hash_values_aux`, rewritten as big-endian hex. `round_numbers` is the `RP`
//! column of `parameters/round_numbers.txt` (`calc_round_numbers.py` output,
//! `2 <= t <= 125`, `R_F = 8` throughout). The constants digest is SHA-256 over
//! the 585 big-endian 32-byte values of the single data line of
//! `parameters/round_constants-1-1-255-9-8-57-<r>.txt` (the authors' sage script
//! output for arity 8, standard strength).

const std = @import("std");
const testing = std.testing;
const neptune = @import("neptune.zig");

const Fr = neptune.Fr;

fn fr(comptime hex: []const u8) Fr {
    var be: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&be, hex) catch unreachable;
    return Fr.fromBytes(be) catch unreachable;
}

fn small(v: u64) Fr {
    var be: [32]u8 = @splat(0);
    std.mem.writeInt(u64, be[24..32], v, .big);
    return Fr.fromBytes(be) catch unreachable;
}

const Known = struct { arity: usize, digest: []const u8 };

const merkle_standard = [_]Known{
    .{ .arity = 2, .digest = "396508d75e76a56b739e0fd902efe161a6fba9339d05a69d2e203c369a02e7ff" },
    .{ .arity = 4, .digest = "58a54b10a9e5848a00db3c6579229399fb6b4605bf1327ec019814ff6662075d" },
    .{ .arity = 8, .digest = "2394611da3a5de5512010042116770774b682e9d9cc4aed92a9934f56d38a5e6" },
    .{ .arity = 11, .digest = "0c0fc1b2e5227f286ca537e232ebe87a09f3dcd8ccb08fc1cee3bbc32b693163" },
    .{ .arity = 16, .digest = "2d3ae2663381ae8ac1c2fb5a6f871e635b8dbc6d30680a6f1291c74060266d37" },
    .{ .arity = 24, .digest = "63beb8831f11ae15066f39bf783f3d9fc3e779f6468815b1d7ef3569f585b321" },
    .{ .arity = 36, .digest = "699303082a6e5d5f540a30e03c10bbaa75cd368df8a8ac3c4473606dfa4e8140" },
};

const merkle_strengthened = [_]Known{
    .{ .arity = 2, .digest = "33d28a753baee41bc48b36ecc4cab7485278ecbf17040ea6793dbaf54552cd69" },
    .{ .arity = 4, .digest = "09d8207c51ca3f4354013bdaf68ba4c2e5113a254d6f5c7e4650ee190212aa9a" },
    .{ .arity = 8, .digest = "69e61465981ae17ed69aae8fe1cb63e8e843d4cfba662df19f0c3c93c3fc894e" },
    .{ .arity = 11, .digest = "28bb83ff439753c007abbcf9b406e8d8c94fe2ca3f46d433778af344d8f9e8b7" },
    .{ .arity = 16, .digest = "68d7856395aa217e43ba5f418c6ef01dd7431eaaa5e431893cc2664c5fd6ae07" },
    .{ .arity = 24, .digest = "086e4e81a35bfd92222eb82c6666be3d0566756b7b80fb101df1da58827cb39d" },
    .{ .arity = 36, .digest = "609f8c6fe45cc05464d73b2ddc03d43b8f69e35a702ed188636401e9371dc311" },
};

const const4_standard = [_]Known{
    .{ .arity = 4, .digest = "3a21a6ae86754a2939443980077d75934984de08542c99778935b00a07909d45" },
    .{ .arity = 8, .digest = "5c6de4b69de9d792cad8b9f8aeb1578f203e3c7c4a85c1f9370a94532f818897" },
    .{ .arity = 11, .digest = "02550c3a2113c7caef841b6bf51a5a397d2807d793af9582e9b0cb7d6496f73b" },
    .{ .arity = 16, .digest = "30ec6fa0fec08504275a6eb04a0ecb376b4493d5d40be9d36a1e563d359c1bdd" },
    .{ .arity = 24, .digest = "327bdee6fa2b22b615ed0a6b8faba5aae2e556352af20f97c540772c5968a299" },
    .{ .arity = 36, .digest = "626bdae6cad79307fe52151f29c50f9902ae71d3d04f0b327d89cddb70217dcd" },
};

const const4_strengthened = [_]Known{
    .{ .arity = 4, .digest = "466e7819bb809c44dff9a095d1d40420b5be830aae89db0da31d9dc66a42f972" },
    .{ .arity = 8, .digest = "0bb12009ab1fb62abf626c21fd6cb051adb6da339b87e5906f2c393786312ee2" },
    .{ .arity = 11, .digest = "5ee31c86cd42e810f199e67d4e6e4bc796e16aa48efc68a96d14b130d0fc1ed5" },
    .{ .arity = 16, .digest = "4611720250274a295bc3390694ee8251eb53bd55f5095e4e7dbe8ac03eb7fb25" },
    .{ .arity = 24, .digest = "1075afe1e62be162aa5f37dd1685188e2400a67b915b45fae2ed71355cbe9268" },
    .{ .arity = 36, .digest = "4ed7c0e22446987f4fc92a1baa0ee777d3cd55eeec46751a8d6f2e5faf077152" },
};

const round_numbers_rp = [_]u8{ 55, 55, 56, 56, 56, 56, 57, 57, 57, 57, 57, 57, 57, 57, 59, 59, 59, 59, 59, 59, 59, 59, 59, 59, 59, 59, 59, 59, 59, 59, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 62 }; // t = 2..125

const constants_digest = "53d16e2f1c0141cbfd5d8bfa4cb69abcbbd056d13a523f929a93e981434ee9f7";
const first_constant = "6ce90d12c4045fe08c3caddb776dd84ac52b4ae7e48cd49443984154f2f4c2f9";
const last_constant = "3b3a75eb91b0f723bcc4ab7e449e4a011b8960063efe74670c05e545519d9a8c";

fn inputs(comptime n: usize) [n]Fr {
    var a: [n]Fr = undefined;
    for (&a, 0..) |*e, i| e.* = small(i);
    return a;
}

fn expectKnown(comptime strength: neptune.Strength, comptime table: []const Known, comptime ht: neptune.HashType) !void {
    inline for (table) |k| {
        const H = neptune.Hasher(k.arity, strength);
        const h = H.init();
        const n = switch (ht) {
            .constant_length => |len| len,
            else => k.arity,
        };
        const pre = inputs(n);
        const got = try h.hash(ht, &pre);
        try testing.expectEqual(fr(k.digest), got);
    }
}

test "neptune: Merkle-tag digests of inputs 0..arity match neptune's hash_values vectors, standard strength" {
    try expectKnown(.standard, &merkle_standard, .merkle_tree);
}

test "neptune: Merkle-tag digests of inputs 0..arity match neptune's hash_values vectors, strengthened" {
    try expectKnown(.strengthened, &merkle_strengthened, .merkle_tree);
}

test "neptune: ConstantLength(4) digests (arity >= 4, one permutation) match neptune's vectors" {
    try expectKnown(.standard, &const4_standard, .{ .constant_length = 4 });
    try expectKnown(.strengthened, &const4_strengthened, .{ .constant_length = 4 });
}

test "neptune: roundNumbers reproduces calc_round_numbers.py for every width 2..125" {
    for (round_numbers_rp, 2..) |rp, t| {
        const r = neptune.roundNumbers(t);
        try testing.expectEqual(@as(u10, 8), r.r_f);
        try testing.expectEqual(@as(u10, rp), r.r_p);
    }
}

test "neptune: strengthened R_P is ceil(1.25 R_P), neptune's own table" {
    const cases = [_][2]usize{
        .{ 1, 69 }, .{ 2, 69 },  .{ 3, 70 },  .{ 4, 70 },  .{ 5, 70 },  .{ 6, 70 },  .{ 7, 72 },  .{ 8, 72 },
        .{ 9, 72 }, .{ 10, 72 }, .{ 11, 72 }, .{ 16, 74 }, .{ 24, 74 }, .{ 36, 75 }, .{ 64, 77 },
    };
    for (cases) |c| try testing.expectEqual(@as(u10, @intCast(c[1])), neptune.partialRounds(c[0], .strengthened));
    try testing.expectEqual(@as(u10, 55), neptune.partialRounds(1, .standard));
    try testing.expectEqual(@as(u10, 57), neptune.partialRounds(8, .standard));
}

test "neptune: the arity-8 constants are the authors' script output shipped in neptune's parameters directory" {
    const H = neptune.Hasher(8, .standard);
    const h = H.init();
    const cs = h.permutation.round_constants;
    try testing.expectEqual(@as(usize, 585), cs.len);
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    for (cs) |c| sha.update(&c.toBytes());
    var d: [32]u8 = undefined;
    sha.final(&d);
    try testing.expectEqualStrings(constants_digest, &std.fmt.bytesToHex(d, .lower));
    try testing.expectEqual(fr(first_constant), cs[0]);
    try testing.expectEqual(fr(last_constant), cs[584]);
}

test "neptune: the MDS matrix is the symmetric Cauchy matrix 1/(i + t + j)" {
    const H = neptune.Hasher(4, .standard);
    const h = H.init();
    const t = 5;
    for (0..t) |i| for (0..t) |j| {
        try testing.expect(h.permutation.mds[i][j].eql(h.permutation.mds[j][i]));
        const back = h.permutation.mds[i][j].mul(small(i + t + j));
        try testing.expect(back.eql(Fr.one));
    };
}

test "neptune: domain tags" {
    const H = neptune.Hasher(8, .standard);
    try testing.expectEqual(small(0xff), try H.domainTag(.merkle_tree));
    try testing.expectEqual(fr("0000000000000000000000000000000000000000000000000000000100000000"), try H.domainTag(.encryption));
    try testing.expectEqual(fr("0000000000000000000000000000000000000000000000040000000000000000"), try H.domainTag(.{ .constant_length = 4 }));
    try testing.expectEqual(fr("0000000000000000000000000000000000000000000000000000010000000000"), try H.domainTag(.{ .custom = 1 }));
    try testing.expectEqual(fr("0000000000000000000000000000000000000000000000000001000000000000"), try H.domainTag(.{ .custom = 256 }));
    try testing.expectEqual(fr("0000000000000000000000000000000000000000000000000000000000000000"), try H.domainTag(.{ .constant_length = 0 }));
    try testing.expectError(error.UnsupportedHashType, H.domainTag(.{ .custom = 0 }));
    try testing.expectError(error.UnsupportedHashType, H.domainTag(.{ .custom = 257 }));
    try testing.expectError(error.UnsupportedHashType, H.domainTag(.{ .constant_length = 9 }));
}

test "neptune: preimage lengths are checked, tags separate the hash types" {
    const H = neptune.Hasher(2, .standard);
    const h = H.init();
    const pre = inputs(2);
    try testing.expectError(error.InvalidPreimageLength, h.hash(.merkle_tree, pre[0..1]));
    try testing.expectError(error.InvalidPreimageLength, h.hash(.encryption, pre[0..1]));
    try testing.expectError(error.InvalidPreimageLength, h.hash(.{ .constant_length = 1 }, &pre));
    const a = try h.hash(.merkle_tree, &pre);
    const b = try h.hash(.encryption, &pre);
    const c = try h.hash(.{ .custom = 7 }, &pre);
    const d = try h.hash(.{ .constant_length = 2 }, &pre);
    try testing.expect(!a.eql(b) and !a.eql(c) and !a.eql(d) and !b.eql(c) and !b.eql(d) and !c.eql(d));
    try testing.expectEqual(a, h.merkle(pre));
    // the digest is state element 1 of the permutation, not element 0
    const st = h.permutation.permute(.{ try H.domainTag(.merkle_tree), pre[0], pre[1] });
    try testing.expectEqual(st[1], a);
}

const live_vectors = @embedFile("testdata/neptune_vectors.txt");

fn parseHashType(name: []const u8) !neptune.HashType {
    if (std.mem.eql(u8, name, "merkle")) return .merkle_tree;
    if (std.mem.eql(u8, name, "encryption")) return .encryption;
    if (std.mem.startsWith(u8, name, "custom")) return .{ .custom = try std.fmt.parseInt(u16, name[6..], 10) };
    if (std.mem.startsWith(u8, name, "const")) return .{ .constant_length = try std.fmt.parseInt(usize, name[5..], 10) };
    return error.UnknownHashType;
}

fn frHex(hex: []const u8) !Fr {
    var be: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&be, hex);
    return Fr.fromBytes(be);
}

test "neptune: every line of the frozen live-run transcript (all hash types, both strengths, 9 arities) reproduces" {
    const arities = [_]usize{ 1, 2, 3, 4, 8, 11, 16, 24, 36 };
    var seen: usize = 0;
    inline for (arities) |arity| inline for (.{ neptune.Strength.standard, neptune.Strength.strengthened }) |strength| {
        const h = neptune.Hasher(arity, strength).init();
        var lines = std.mem.tokenizeScalar(u8, live_vectors, '\n');
        while (lines.next()) |line| {
            if (line[0] == '#') continue;
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const a = try std.fmt.parseInt(usize, f.next().?, 10);
            const st = f.next().?;
            if (a != arity or !std.mem.eql(u8, st, @tagName(strength))) continue;
            const ht = try parseHashType(f.next().?);
            const len = try std.fmt.parseInt(usize, f.next().?, 10);
            var pre: [arity]Fr = undefined;
            var ins = std.mem.splitScalar(u8, f.next().?, ',');
            for (0..len) |i| pre[i] = try frHex(ins.next().?);
            const want = try frHex(f.next().?);
            const got = try h.hash(ht, pre[0..len]);
            try testing.expectEqual(want, got);
            seen += 1;
        }
    };
    try testing.expectEqual(@as(usize, 426), seen);
}

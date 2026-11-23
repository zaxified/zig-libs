// SPDX-License-Identifier: MIT
//! ECVRF-P256-SHA256-TAI / -SSWU against RFC 9381 Appendix B.1 (Examples
//! 10-12) and B.2 (Examples 13-15): `PK`, `H`, `pi` (which carries `Gamma`,
//! `c`, `s`), `beta`, and for SSWU the published `u`; `k`, `U = k*B` and
//! `V = k*H` are checked through the RFC 6979 nonce the module uses.

const std = @import("std");
const testing = std.testing;
const vrf = @import("p256vrf.zig");
const p256 = @import("p256");

const V = struct {
    sk: []const u8,
    pk: []const u8,
    alpha: []const u8,
    h: []const u8,
    k: []const u8,
    u: []const u8,
    v: []const u8,
    pi: []const u8,
    beta: []const u8,
    sswu_u: []const u8 = "",
};

const sk_a = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const pk_a = "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const sk_b = "2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8";
const pk_b = "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d";
const alpha_b = "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005";

const tai_vectors = [_]V{
    .{ .sk = sk_a, .pk = pk_a, .alpha = "sample", .h = "0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4", .k = "0d90591273453d2dc67312d39914e3a93e194ab47a58cd598886897076986f77", .u = "02bb6a034f67643c6183c10f8b41dc4babf88bff154b674e377d90bde009c21672", .v = "02893ebee7af9a0faa6da810da8a91f9d50e1dc071240c9706726820ff919e8394", .pi = "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f", .beta = "a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e" },
    .{ .sk = sk_a, .pk = pk_a, .alpha = "test", .h = "02173119b4fff5e6f8afed4868a29fe8920f1b54c2cf89cc7b301d0d473de6b974", .k = "5852353a868bdce26938cde1826723e58bf8cb06dd2fed475213ea6f3b12e961", .u = "022779a2cafcb65414c4a04a4b4d2adf4c50395f57995e89e6de823250d91bc48e", .v = "033b4a14731672e82339f03b45ff6b5b13dee7ada38c9bf1d6f8f61e2ce5921119", .pi = "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56c19e067b15a8a8174905b13617804534214f935b94c2287f797e393eb0816969d864f37625b443f30f1a5a33f2b3c854", .beta = "a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d" },
    .{ .sk = sk_b, .pk = pk_b, .alpha = alpha_b, .h = "0258055c26c4b01d01c00fb57567955f7d39cd6f6e85fd37c58f696cc6b7aa761d", .k = "5689e2e08e1110b4dda293ac21667eac6db5de4a46a519c73d533f69be2f4da3", .u = "020f465cd0ec74d2e23af0abde4c07e866ae4e5138bded5dd1196b8843f380db84", .v = "036cb6f811428fc4904370b86c488f60c280fa5b496d2f34ff8772f60ed24b2d1d", .pi = "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667d091c00b0f5c3619d10ecea44363b5a599cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1", .beta = "90871e06da5caa39a3c61578ebb844de8635e27ac0b13e829997d0d95dd98c19" },
};

const sswu_vectors = [_]V{
    .{ .sk = sk_a, .pk = pk_a, .alpha = "sample", .sswu_u = "df565615a2372e8b31b8771f7503bafc144e48b05688b97958cc27ce29a8d810", .h = "02b31973e872d4a097e2cfae9f37af9f9d73428fde74ac537dda93b5f18dbc5842", .k = "e92820035a0a8afe132826c6312662b6ea733fc1a0d33737945016de54d02dd8", .u = "031490f49d0355ffcdf66e40df788bee93861917ee713acff79be40d20cc91a30a", .v = "03701df0228138fa3d16612c0d720389326b3265151bc7ac696ea4d0591cd053e3", .pi = "0331d984ca8fece9cbb9a144c0d53df3c4c7a33080c1e02ddb1a96a365394c7888782fffde7b842c38c20c08de6ec6c2e7027a97000f2c9fa4425d5c03e639fb48fde58114d755985498d7eb234cf4aed9", .beta = "21e66dc9747430f17ed9efeda054cf4a264b097b9e8956a1787526ed00dc664b" },
    .{ .sk = sk_a, .pk = pk_a, .alpha = "test", .sswu_u = "d8b0107f7e7aa36390240d834852f8703a6dc407019d6196bda5861b8fc00181", .h = "03ccc747fa7318b9486ce4044adbbecaa084c27be6eda88eb7b7f3d688fd0968c7", .k = "febc3451ea7639fde2cf41ffd03f463124ecb3b5a79913db1ed069147c8a7dea", .u = "031200f9900e96f811d1247d353573f47e0d9da601fc992566234fc1a5b37749ae", .v = "02d3715dcfee136c7ae50e95ffca76f4ca6c29ddfb92a39c31a0d48e75c6605cd1", .pi = "03f814c0455d32dbc75ad3aea08c7e2db31748e12802db23640203aebf1fa8db2743aad348a3006dc1caad7da28687320740bf7dd78fe13c298867321ce3b36b79ec3093b7083ac5e4daf3465f9f43c627", .beta = "8e7185d2b420e4f4681f44ce313a26d05613323837da09a69f00491a83ad25dd" },
    .{ .sk = sk_b, .pk = pk_b, .alpha = alpha_b, .sswu_u = "e43c98c2ae06d13839fedb0303e5ee815896beda39be83fb11325b97976efdce", .h = "022dd5150e5a2a24c66feab2f68532be1486e28e07f1b9a055cf38ccc16f6595ff", .k = "8e29221f33564f3f66f858ba2b0c14766e1057adbd422c3e7d0d99d5e142b613", .u = "03a8823ff9fd16bf879261c740b9c7792b77fee0830f21314117e441784667958d", .v = "02d48fbb45921c755b73b25be2f23379e3ce69294f6cee9279815f57f4b422659d", .pi = "039f8d9cdc162c89be2871cbcb1435144739431db7fab437ab7bc4e2651a9e99d5488405a11a6c7fc8defddd9e1573a563b7333aab4effe73ae9803274174c659269fd39b53e133dcd9e0d24f01288de9a", .beta = "4fbadf33b42a5f42f23a6f89952d2e634a6e3810f15878b46ef1bb85a04fe95a" },
};

fn hex(comptime n: usize, h: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    if (h.len != 2 * n) return error.BadVector;
    _ = try std.fmt.hexToBytes(&out, h);
    return out;
}

fn check(comptime S: type, v: V) !void {
    const sk = try hex(32, v.sk);
    var kp: S.KeyPair = undefined;
    try S.KeyPair.init(&kp, &sk);
    try testing.expectEqualSlices(u8, &try hex(33, v.pk), &kp.pk);
    const h = S.encodeToCurve(&kp.pk, v.alpha);
    try testing.expectEqualSlices(u8, &try hex(33, v.h), &h);

    // k (RFC 6979 over h_string) and U = k*B, V = k*H.
    var hm: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&h, &hm, .{});
    const k = p256.sign.rfc6979Nonce(sk, hm).toBytes(.big);
    try testing.expectEqualSlices(u8, &try hex(32, v.k), &k);
    const u = try p256.P256.basePoint.mul(k, .big);
    try testing.expectEqualSlices(u8, &try hex(33, v.u), &u.toCompressedSec1());
    const vv = try (try p256.P256.fromSec1(&h)).mul(k, .big);
    try testing.expectEqualSlices(u8, &try hex(33, v.v), &vv.toCompressedSec1());

    const pi = kp.prove(v.alpha);
    try testing.expectEqualSlices(u8, &try hex(vrf.proof_len, v.pi), &pi);
    const beta = try S.proofToHash(&pi);
    try testing.expectEqualSlices(u8, &try hex(32, v.beta), &beta);
    try testing.expectEqualSlices(u8, &beta, &try S.verify(&kp.pk, v.alpha, &pi));
}

test "ECVRF-P256-SHA256-TAI: RFC 9381 B.1 Examples 10-12, every published value" {
    for (tai_vectors) |v| try check(vrf.tai, v);
}

test "ECVRF-P256-SHA256-SSWU: RFC 9381 B.2 Examples 13-15, every published value (u included)" {
    for (sswu_vectors) |v| {
        try check(vrf.sswu, v);
        const pk = try hex(33, v.pk);
        const u = vrf.sswu.hash_to_curve.hashToField(1, &.{ &pk, v.alpha }, vrf.sswu.dst);
        try testing.expectEqualSlices(u8, &try hex(32, v.sswu_u), &u[0].toBytes(.big));
    }
}

test "P-256 suites: tamper, wrong key, wrong alpha and cross-suite proofs are refused" {
    const sk = try hex(32, sk_a);
    inline for (.{ vrf.tai, vrf.sswu }, .{ vrf.sswu, vrf.tai }) |S, Other| {
        var kp: S.KeyPair = undefined;
        try S.KeyPair.init(&kp, &sk);
        const pi = kp.prove("alpha");
        _ = try S.verify(&kp.pk, "alpha", &pi);
        try testing.expectError(error.InvalidProof, S.verify(&kp.pk, "alphb", &pi));
        try testing.expectError(error.InvalidProof, Other.verify(&kp.pk, "alpha", &pi));
        var other: S.KeyPair = undefined;
        try S.KeyPair.init(&other, &try hex(32, sk_b));
        try testing.expectError(error.InvalidProof, S.verify(&other.pk, "alpha", &pi));
        for (0..vrf.proof_len) |i| {
            var bad = pi;
            bad[i] ^= 0x01;
            if (S.verify(&kp.pk, "alpha", &bad)) |_| return error.TamperAccepted else |_| {}
        }
        // s >= q, Gamma not on the curve, a public key with a bad prefix.
        var bad = pi;
        @memset(bad[vrf.pt_len + vrf.c_len ..], 0xff);
        try testing.expectError(error.InvalidProof, S.verify(&kp.pk, "alpha", &bad));
        try testing.expectError(error.InvalidProof, S.proofToHash(&bad));
        var pk_bad = kp.pk;
        pk_bad[0] = 0x04;
        try testing.expectError(error.InvalidPublicKey, S.verify(&pk_bad, "alpha", &pi));
    }
}

test "P-256 suites: SK outside [1, q-1] is InvalidSecretKey" {
    var kp: vrf.tai.KeyPair = .{ .sk = @splat(0x5a), .pk = @splat(0xa5) };
    const zero: [32]u8 = @splat(0);
    try testing.expectError(error.InvalidSecretKey, vrf.tai.KeyPair.init(&kp, &zero));
    try testing.expectEqual(@as(u8, 0x5a), kp.sk[0]); // a refused key leaves `out` untouched
    try testing.expectEqual(@as(u8, 0xa5), kp.pk[0]);
    const big: [32]u8 = @splat(0xff);
    var kp2: vrf.sswu.KeyPair = undefined;
    try testing.expectError(error.InvalidSecretKey, vrf.sswu.KeyPair.init(&kp2, &big));
    var one: [32]u8 = @splat(0);
    one[31] = 1;
    try vrf.tai.KeyPair.init(&kp, &one);
    try testing.expectEqualSlices(u8, &p256.P256.basePoint.toCompressedSec1(), &kp.pk);
}

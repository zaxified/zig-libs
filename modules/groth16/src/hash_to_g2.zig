// SPDX-License-Identifier: MIT
//! RFC 9380 `hash_to_curve` onto BN254's G2 with the Shallue–van de
//! Woestijne map: the suite `BN254G2_XMD:SHA-256_SVDW_RO_` that gnark-crypto
//! ships as `bn254.HashToG2(msg, dst)` (RFC 9380 defines the construction,
//! not a BN254 suite; gnark-crypto's is the one in use).
//!
//!   1. `hash_to_field(msg, 2)` — `expand_message_xmd` with SHA-256 (§5.3.1),
//!      `L = 48` bytes per `Fp` coordinate, two `Fp2` elements `u0`, `u1`.
//!   2. `Q_i = map_to_curve_svdw(u_i)` (§6.6.1, straight-line form F.1) on the
//!      twist `E': y² = x³ + b'`, `b' = 3/(9+u)`, with `Z = 1` (the first
//!      value `find_z_svdw`, §H.1, accepts — re-derived by the tests below)
//!      and `sgn0` of §4.1 for `m = 2`.
//!   3. `clear_cofactor(Q0 + Q1)`: the endomorphism form of Fuentes-Castañeda,
//!      Knapp and Rodríguez-Henríquez ("Faster hashing to G2", SAC 2011, §6.1)
//!      gnark-crypto uses, `[x]Q + ψ([3x]Q) + ψ²([x]Q) + ψ³(Q)`, `x` the BN
//!      seed. It lands in the order-r subgroup; a plain `[2p − r]Q` would too,
//!      but would give a different point than every other implementation of
//!      the suite.
//!
//! Every input is public (a hash input), so nothing here is constant-time
//! by requirement; the map is straight-line anyway.
//!
//! Anchored by gnark-crypto's published vectors (`u0`, `u1`, `Q0`, `Q1` and
//! the output for five messages, below) and by an RFC 9380 model in Python
//! that reproduced them before this file was written.

const std = @import("std");
const bn254 = @import("bn254");

const Fp = bn254.Fp;
const Fp2 = bn254.Fp2;
const G2 = bn254.G2;
const Sha256 = std.crypto.hash.sha2.Sha256;

const p_int: u384 = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

/// Bytes per `Fp` coordinate in `hash_to_field`: `ceil((ceil(log2 p) + k) / 8)`
/// with `k = 128` (RFC 9380 §5).
const field_l = 48;

/// The BN seed `x` (`bn254`'s `pairing.bn_x`), big-endian.
const seed_be: [8]u8 = blk: {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, 4965661367192848881, .big);
    break :blk b;
};

/// `H(msg)`: a point of the order-r subgroup of G2 (RFC 9380 `hash_to_curve`,
/// random-oracle variant). `dst` is the domain separation tag, 1..255 bytes.
pub fn hashToG2(msg: []const u8, comptime dst: []const u8) G2.Affine {
    const u = hashToField(msg, dst);
    const q0 = G2.Jacobian.fromAffine(mapToCurve(u[0]));
    const q1 = G2.Jacobian.fromAffine(mapToCurve(u[1]));
    return clearCofactor(q0.add(q1)).toAffine();
}

/// RFC 9380 §5.2 `hash_to_field(msg, 2)` over `Fp2` (`m = 2`, `L = 48`).
fn hashToField(msg: []const u8, comptime dst: []const u8) [2]Fp2 {
    const uniform = expandMessageXmd(2 * 2 * field_l, msg, dst);
    var out: [2]Fp2 = undefined;
    for (&out, 0..) |*e, i| {
        e.* = .{
            .c0 = fpFromWide(uniform[(2 * i) * field_l ..][0..field_l]),
            .c1 = fpFromWide(uniform[(2 * i + 1) * field_l ..][0..field_l]),
        };
    }
    return out;
}

fn fpFromWide(bytes: *const [field_l]u8) Fp {
    const v: u256 = @intCast(std.mem.readInt(u384, bytes, .big) % p_int);
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, v, .big);
    return Fp.fromBytes(b) catch unreachable; // v < p
}

/// RFC 9380 §5.3.1 `expand_message_xmd` with SHA-256.
fn expandMessageXmd(comptime len: usize, msg: []const u8, comptime dst: []const u8) [len]u8 {
    const b_len = Sha256.digest_length;
    const ell = (len + b_len - 1) / b_len;
    comptime {
        if (len == 0 or len > 65535 or ell > 255) @compileError("expand_message_xmd: length out of range");
        if (dst.len == 0 or dst.len > 255) @compileError("expand_message_xmd: DST must be 1..255 bytes");
    }
    const dst_prime = dst ++ [1]u8{dst.len};
    var h0 = Sha256.init(.{});
    h0.update(&@as([Sha256.block_length]u8, @splat(0)));
    h0.update(msg);
    h0.update(&[3]u8{ len >> 8, len & 0xff, 0 });
    h0.update(dst_prime);
    var b0: [b_len]u8 = undefined;
    h0.final(&b0);

    var out: [ell * b_len]u8 = undefined;
    var prev: [b_len]u8 = b0;
    for (0..ell) |i| {
        var x: [b_len]u8 = undefined;
        for (&x, b0, prev) |*o, a, b| o.* = if (i == 0) a else a ^ b;
        var h = Sha256.init(.{});
        h.update(&x);
        h.update(&[1]u8{@intCast(i + 1)});
        h.update(dst_prime);
        h.final(&prev);
        out[i * b_len ..][0..b_len].* = prev;
    }
    return out[0..len].*;
}

// ── the SVDW map (RFC 9380 §6.6.1, constants of §F.1 for A = 0, Z = 1) ──────

fn fp2Hex(comptime c0: *const [64]u8, comptime c1: *const [64]u8) Fp2 {
    @setEvalBranchQuota(100_000);
    return .{ .c0 = fpHex(c0), .c1 = fpHex(c1) };
}

fn fpHex(comptime h: *const [64]u8) Fp {
    var b: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, h) catch unreachable;
    return Fp.fromBytes(b) catch unreachable;
}

/// `Z = 1`.
const svdw_z: Fp2 = Fp2.one;
/// `c1 = g(Z)`.
const svdw_c1 = fp2Hex("2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e6", "009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2");
/// `c2 = −Z/2`.
const svdw_c2 = fp2Hex("183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3", "0000000000000000000000000000000000000000000000000000000000000000");
/// `c3 = sqrt(−g(Z)·(3Z² + 4A))` with `sgn0(c3) = 0`.
const svdw_c3 = fp2Hex("29fd332ab7260112b801fa95b21af64e2e6da55f90a3e510fcbe57377b5ca1ec", "303d1eff1426764bf8408aee24ba0b865e76f77b1267a846b1e9154d01565034");
/// `c4 = −4·g(Z) / (3Z² + 4A)`.
const svdw_c4 = fp2Hex("17365bbe63b1d2078632fe0eb2ac5a41b4e6a9c08b98676721010b008d4eaf99", "0f57ffe5fc79e19cd689d7aa4209cad8fe164d7f4694786b388732a995d03755");

/// `(p − 1)/2`: Euler's criterion in `Fp`.
const legendre_exp: [32]u8 = bn254.fp.pExponentBytes(-1, 2);

/// `a` is a square in `Fp2` iff its norm `c0² + c1²` is a square in `Fp`.
fn isSquare(a: Fp2) bool {
    const norm = a.c0.square().add(a.c1.square());
    return norm.isZero() or norm.pow(legendre_exp).eql(Fp.one);
}

/// RFC 9380 §4.1 `sgn0` for `m = 2`.
fn sgn0(a: Fp2) u1 {
    const sign0: u1 = @truncate(a.c0.toBytes()[31]);
    const zero0: u1 = @intFromBool(a.c0.isZero());
    const sign1: u1 = @truncate(a.c1.toBytes()[31]);
    return sign0 | (zero0 & sign1);
}

/// `g(x) = x³ + b'`.
fn curveRhs(x: Fp2, b: Fp2) Fp2 {
    return x.square().mul(x).add(b);
}

/// `map_to_curve_svdw(u)`: a point of the twist `E'` (not yet in G2).
fn mapToCurve(u: Fp2) G2.Affine {
    const b = bn254.g2.twistB();
    var tv1 = u.square().mul(svdw_c1);
    const tv2 = Fp2.one.add(tv1);
    tv1 = Fp2.one.sub(tv1);
    const tv3 = tv1.mul(tv2).inv0();
    const tv4 = u.mul(tv1).mul(tv3).mul(svdw_c3);
    const x1 = svdw_c2.sub(tv4);
    const e1 = isSquare(curveRhs(x1, b));
    const x2 = svdw_c2.add(tv4);
    const e2 = isSquare(curveRhs(x2, b)) and !e1;
    const x3 = tv2.square().mul(tv3).square().mul(svdw_c4).add(svdw_z);
    var x = Fp2.ctSelect(e1, x1, x3);
    x = Fp2.ctSelect(e2, x2, x);
    // One of g(x1), g(x2), g(x3) is a square (the point of SVDW).
    var y = curveRhs(x, b).sqrt() orelse unreachable;
    if (sgn0(u) != sgn0(y)) y = y.neg();
    return .{ .x = x, .y = y, .infinity = false };
}

// ── cofactor clearing ───────────────────────────────────────────────────────

/// `ψ(X, Y, Z) = (X̄·γx, Ȳ·γy, Z̄)`, the twist Frobenius (`bn254`'s `psi_gamma_*`).
fn psi(p: G2.Jacobian) G2.Jacobian {
    return .{
        .x = p.x.frobenius().mul(bn254.g2.psi_gamma_x),
        .y = p.y.frobenius().mul(bn254.g2.psi_gamma_y),
        .z = p.z.frobenius(),
    };
}

/// `[x]Q + ψ([3x]Q) + ψ²([x]Q) + ψ³(Q)` (SAC 2011, §6.1; gnark-crypto's
/// `G2Jac.ClearCofactor`): a point of the order-r subgroup for every `Q` on `E'`.
fn clearCofactor(q: G2.Jacobian) G2.Jacobian {
    const xq = q.scalarMulBytes(&seed_be);
    const t1 = psi(xq.double().add(xq));
    const t2 = psi(psi(xq));
    const t3 = psi(psi(psi(q)));
    return xq.add(t1).add(t2).add(t3);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn fpFromHex(s: []const u8) !Fp {
    const v = try std.fmt.parseInt(u256, s, 0);
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, v, .big);
    return Fp.fromBytes(b);
}

/// `"0x<c0>,0x<c1>"`, gnark-crypto's `Fp2` notation.
fn fp2FromHex(s: []const u8) !Fp2 {
    var it = std.mem.splitScalar(u8, s, ',');
    const c0 = try fpFromHex(it.next().?);
    const c1 = try fpFromHex(it.next().?);
    return .{ .c0 = c0, .c1 = c1 };
}

fn expectPoint(got: G2.Affine, x: []const u8, y: []const u8) !void {
    try testing.expect(!got.infinity);
    try testing.expect(got.x.eql(try fp2FromHex(x)));
    try testing.expect(got.y.eql(try fp2FromHex(y)));
}

const Vector = struct { msg: []const u8, u0: []const u8, u1: []const u8, q0: [2][]const u8, q1: [2][]const u8, p: [2][]const u8 };

const quux_dst = "QUUX-V01-CS02-with-BN254G2_XMD:SHA-256_SVDW_RO_";

/// gnark-crypto v0.19.2, `ecc/bn254/hash_vectors_test.go`, `hashToG2Vector`
/// (Apache-2.0; test data, transcribed). The same values came out of an
/// independent RFC 9380 model in Python before this file existed.
const vectors = [_]Vector{
    .{
        .msg = "",
        .u0 = "0x2c85988ecf26034a6d6c495c467150aeaead51fceb623aa99b0433275c8952c7,0x182126b31e6df7cf33844bf16a92f42072ee47f80539dace68dbfc3380d1fcbd",
        .u1 = "0x1c3035901eab4768d522b3d0eb7e58b05c130603c8f43587345dc51745fa3533,0x23597b1c4f238038ba6579d203e7fcb7d427c63d4e0d037185453168718203bb",
        .q0 = .{ "0x71e460ff150e978d833ef69fdf228f0d2c0807e3dce076b17dccdaa64bf6b25,0xab3b378f44776bd951140bfc354e68554ca76a4369a6b20d0da39e18e31fa38", "0x2c6cdc66602f181b70022028cd584f9d021eb409af5bfcef716a180383140aaf,0x113b1e8168192dc9a8048152b61aab936ce3654bf5f67d3d63f53d4eee72e011" },
        .q1 = .{ "0x39f9c639d9261f6d96487bae68e2336ba7ed68af727960c371caa330f0f3c05,0x1bf10eb5452db5be04eb3469440f9008017f1c632252b13069a3a9aa6c7467ec", "0x229827ca645e88cccdf70f001f3051f4148bcbc1165796f8550ef055a211d685,0x4ffb54e9e9f23b1c84d262f273518f14a8873f4589d2227575d5c65141da706" },
        .p = .{ "0x1192005a0f121921a6d5629946199e4b27ff8ee4d6dd4f9581dc550ade851300,0x1747d950a6f23c16156e2171bce95d1189b04148ad12628869ed21c96a8c9335", "0x498f6bb5ac309a07d9a8b88e6ff4b8de0d5f27a075830e1eb0e68ea318201d8,0x2c9755350ca363ef2cf541005437221c5740086c2e909b71d075152484e845f4" },
    },
    .{
        .msg = "abc",
        .u0 = "0x234b244ed36d5acbb96a4f5fb67094945a0bb4ecf33d55bcc218ce834dc82c63,0x4ca11f51d0cf7e7393a0e6d7be3d0e6b07652d5ba308554a72dafe502dd59cc",
        .u1 = "0x1c31ec87881353ec57fc87c27e31099a0705390c52dbfc8c047d14260658df71,0x2daa8e05eb3367285b5de508d248b3153207498f3e9e51cbe6183ff7dae286a6",
        .q0 = .{ "0x254d44345e73654a4a41adc0b17f39b397c352693513b3439afe5596cba3c6b2,0x2d489087e8025d60a201c109bd6be0aac5e8b04593c1127e4f8cf9e654dd1f82", "0xf1b1989fb5b87287ba1eee6b04426b1b3afb72c0aa8e981e392e740c0b2045,0x20d48c7925d6e00cf89487c737f49a0b5946158ca515fcc12516aefd33f9a45b" },
        .q1 = .{ "0x1af57e1f34420bf4fc5d2d880fd69f8c58b0ff2647b9d8b3d98f03fe45300ae8,0x164ff536dd42039dbd2f6351f445cd76cb1a346ea1347cfd98500ec62996c94d", "0x304eeaafb7429b8fe754a567cf23c0d04be055baeb0e9a3a6d34e433f3aa8027,0x168b97f3e2a1bbe114931e35f3abd3614f99a58abb4ae0adda944c09d1bdc0e6" },
        .p = .{ "0x16c88b54eec9af86a41569608cd0f60aab43464e52ce7e6e298bf584b94fccd2,0xb5db3ca7e8ef5edf3a33dfc3242357fbccead98099c3eb564b3d9d13cba4efd", "0x1c42ba524cb74db8e2c680449746c028f7bea923f245e69f89256af2d6c5f3ac,0x22d02d2da7f288545ff8789e789902245ab08c6b1d253561eec789ec2c1bd630" },
    },
    .{
        .msg = "abcdef0123456789",
        .u0 = "0x29c7f821157ab18e589d1e7d7bd393d20aff69af2ac4deadc7950998d594d201,0x860010a5c2ae9289f0d4f7099ff0d5904ded06f99d5960f734de36b82ff983c",
        .u1 = "0x1f3c50c3ccfbaad8e81f8a765c5465a034b55fb873be48fd60dc21fb2cca98b8,0x2fa095cba1059ef5e2d5ea1c976a87f4530225aa7759b5b9510bb76d7b1d4f3",
        .q0 = .{ "0x100476fddb9ea779a6fb6d42e56309214d17e9f977e55817d90d174c25da1da,0x119928ea6db28a02b97ffd78ca301352f59bf218283c4636ffd8630424d715f2", "0x1f8b75179bb45ec7dce4e80a6e5ff343354405fb37e0f00f05b6bd4576fe7325,0x217dc1c62afca9b764d6aad37652d2ceca98082e8a91278665fc69aa1086f42c" },
        .q1 = .{ "0x2eea8de62a9fe65f771b334f09895a941513447befc908c9bd92e379413f705,0x2116b794a45df430772983535769ee30a6b16383f402a45bfd061091423771c4", "0x1a236124a4be9b04860439e8ca5ff9c2b7309473b2235193befcd61c9e911b88,0x2abc966940a34cdd457e0505ea3884e90a804cee8b01b510f319fb5f5447c90c" },
        .p = .{ "0x1435fd84aa43c699230e371f6fea3545ce7e053cbbb06a320296a2b81efddc70,0x2a8a360585b6b05996ef69c3c09b2c6fb17afe2b1e944f07559c53178eabf171", "0x2820188dcdc13ffdca31694942418afa1d6dfaaf259d012fab4da52b0f592e38,0x142f08e2441ec431defc24621b73cfe0252d19b243cb55b84bdeb85de039207a" },
    },
    .{
        .msg = "q128_" ++ @as([128]u8, @splat('q')),
        .u0 = "0x859e4f9b60f7ce13f81da9da46435c8827ed53f553b4e1804a395af1354b2c7,0x368bfd8f29d990293171aee9be3bc4ad623c54d0db776d0fe87cfd579059a86",
        .u1 = "0x103aa84a49f14d0ca1dfda47fa93a43cece0c267ae8799123d63ccd027772f71,0x9ebcb7d529f69c5e7ab096ff1a727ec8bc6c5214ed1784cd7f9e325e121640c",
        .q0 = .{ "0xc18ed8f507c46c91c3cd68bbe67d84fedddf54aa36a0b724d8993c0e89d3473,0x216fd51ee739a5ea4bea5e0d02e3217399e001a1b1192494cad83778b265bf51", "0x86feb20cd348a7f6b10395367f6a94a7c0b6be76673ab847914302cfbef4c8d,0x184f467bdb87df3cf3616b88a2dfd4eb512627a8e7cb00ac4c0f0c256948693d" },
        .q1 = .{ "0x2ab06564fee17a6d71b4cb24b73798d44711fdd101f6368fdc53e34fb2a3e411,0x1924dbd030b8093ac48e7363505d25c53cb0a21f96d5d2e6c534b8e541c2f332", "0x89c25648c64971fc868a1c5ca178e336147f26d2984221ed1df72b2c1b49b1,0xaf10b749194f436828978b2428c7944d46f8fb8bc34461794bc1bc1d636003a" },
        .p = .{ "0x2cffc213fb63d00d923cb22cda5a2904837bb93a2fe6e875c532c51744388341,0x2718ef38d1bc4347f0266c774c8ef4ee5fa7056cc27a4bd7ecf7a888efb95b26", "0x232553f728341afa64ce66d00535764557a052e38657594e10074ad28728c584,0x2206ec0a9288f31ed78531c37295df3b56c42a1284443ee9893adb1521779001" },
    },
    .{
        .msg = "a512_" ++ @as([512]u8, @splat('a')),
        .u0 = "0xf0a229a329e3df7fe4feea02aac7dad3a01d345f65efe512544699439aacd83,0x15b85241a3f8790e550026f37fd861babd3dba9e2bce0deced2df56f7440bbb4",
        .u1 = "0xfa59525a85744763ea88a78ca612cb8db4d6e08f3d192568749b90ef16c36b6,0x1c32e85696693c537a91a4283353fba8c24f4107278b82990cc0c595a4d4f6cc",
        .q0 = .{ "0x14909a7cf12c368a1ecf7dde981bee058f657b6c47aa2d8bbd0528afac6dbd7b,0x3691ff7c610402d3acc2494c72a2a8eb7b34f40f54953201ce87f6c1b0f4bee", "0x1b4f9ced14ace59a4469280f4ad25c2727cca98c74729f4491bbcd9e3c4ec65f,0x26616d464461190482f9583225c483a6df9a7c9bf76bef2c0f02f7b08913cda5" },
        .q1 = .{ "0x21641581efa27adfd51aa8605a6e5763c563d929e8157508387bb76239446dbc,0x2edc55e80aa268be53526cb82df2eea5aba8595c258b0da6b91e3798d1b901c5", "0x2e3312775b7af85c4acb0a67fcf5e0a7ea163dd6dae35021d97851dfa9778af4,0xe8d867d428e160f1597b1096f9c492519d9d5e663a4af02f20f272d589804cc" },
        .p = .{ "0x242a0a159f36f87065e7c5170426012087023165ce47a486e53d6e2845ca625a,0x17f9f6292998cf18ccc155903c1fe6b6465d40c794a3e1ed644a4182ad639f4a", "0x2dc5b7b65c9c79e6ef4afab8fbe3083c66d4ce31c78f6621ece17ecc892cf4b3,0x18ef4886c818f01fdf309bc9a46dd904273917f85e74ecd0de62460a68122037" },
    },
};

test "hashToG2: gnark-crypto's BN254G2_XMD:SHA-256_SVDW_RO_ vectors (u0, u1, Q0, Q1, P)" {
    for (vectors) |v| {
        const u = hashToField(v.msg, quux_dst);
        try testing.expect(u[0].eql(try fp2FromHex(v.u0)));
        try testing.expect(u[1].eql(try fp2FromHex(v.u1)));
        try expectPoint(mapToCurve(u[0]), v.q0[0], v.q0[1]);
        try expectPoint(mapToCurve(u[1]), v.q1[0], v.q1[1]);
        const p = hashToG2(v.msg, quux_dst);
        try expectPoint(p, v.p[0], v.p[1]);
        try testing.expect(G2.Jacobian.fromAffine(p).subgroupCheck());
    }
}

test "SVDW constants: re-derived from their RFC 9380 definitions (A = 0, Z = 1)" {
    const b = bn254.g2.twistB();
    const gz = curveRhs(svdw_z, b);
    const three: Fp2 = .{ .c0 = try Fp.fromInt(u8, 3), .c1 = Fp.zero };
    const two: Fp2 = .{ .c0 = try Fp.fromInt(u8, 2), .c1 = Fp.zero };
    const four: Fp2 = .{ .c0 = try Fp.fromInt(u8, 4), .c1 = Fp.zero };
    try testing.expect(svdw_c1.eql(gz));
    try testing.expect(svdw_c2.mul(two).eql(svdw_z.neg()));
    const t = gz.neg().mul(three); // −g(Z)·3Z², Z = 1
    try testing.expect(svdw_c3.square().eql(t));
    try testing.expectEqual(@as(u1, 0), sgn0(svdw_c3));
    try testing.expect(svdw_c4.mul(three).eql(four.mul(gz).neg()));
    // find_z_svdw (RFC 9380 §H.1) tries 1 first; it qualifies: g(Z) ≠ 0,
    // −(3Z² + 4A)/(4·g(Z)) is a nonzero square, and g(Z) is a square.
    try testing.expect(!gz.isZero());
    const h = three.neg().mul(four.mul(gz).inv0());
    try testing.expect(!h.isZero() and isSquare(h));
    try testing.expect(isSquare(gz));
}

test "isSquare agrees with Fp2.sqrt; sgn0 follows RFC 9380 §4.1" {
    var a: Fp2 = .{ .c0 = try Fp.fromInt(u8, 5), .c1 = try Fp.fromInt(u8, 7) };
    for (0..32) |_| {
        try testing.expectEqual(a.sqrt() != null, isSquare(a));
        a = a.mul(a).add(Fp2.one).add(.{ .c0 = Fp.zero, .c1 = Fp.one });
    }
    try testing.expect(isSquare(Fp2.zero));
    try testing.expectEqual(@as(u1, 1), sgn0(.{ .c0 = Fp.one, .c1 = Fp.zero }));
    try testing.expectEqual(@as(u1, 0), sgn0(.{ .c0 = try Fp.fromInt(u8, 2), .c1 = Fp.one }));
    try testing.expectEqual(@as(u1, 1), sgn0(.{ .c0 = Fp.zero, .c1 = Fp.one }));
    try testing.expectEqual(@as(u1, 0), sgn0(Fp2.zero));
}

test "map_to_curve: the exceptional inputs (tv1·tv2 = 0) still land on the twist" {
    const b = bn254.g2.twistB();
    // u = 0, and every u with c1·u² = ±1, where `inv0` returns 0.
    var inputs: [5]Fp2 = @splat(Fp2.zero);
    var n: usize = 1;
    const inv_c1 = svdw_c1.inv0();
    for ([_]Fp2{ inv_c1, inv_c1.neg() }) |t| {
        if (t.sqrt()) |r| {
            inputs[n] = r;
            inputs[n + 1] = r.neg();
            n += 2;
        }
    }
    try testing.expect(n > 1);
    for (inputs[0..n]) |u| {
        const q = mapToCurve(u);
        try testing.expect(q.y.square().eql(curveRhs(q.x, b)));
    }
}

test "clearCofactor: the raw SVDW point is outside G2, the cleared one inside" {
    const q = mapToCurve(hashToField("cofactor", quux_dst)[0]);
    const j = G2.Jacobian.fromAffine(q);
    try testing.expect(j.isOnCurve());
    try testing.expect(!j.subgroupCheck());
    const c = clearCofactor(j);
    try testing.expect(!c.isIdentity());
    try testing.expect(c.subgroupCheck());
}

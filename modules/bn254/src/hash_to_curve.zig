// SPDX-License-Identifier: MIT
//! RFC 9380 hash-to-curve onto BN254's G1 and G2 with the Shallue–van de
//! Woestijne map: the suites `BN254G1_XMD:SHA-256_SVDW_RO_` / `_NU_`
//! (`hashToCurveG1` / `encodeToCurveG1`) and `BN254G2_XMD:SHA-256_SVDW_RO_`
//! / `_NU_` (`hashToCurveG2` / `encodeToCurveG2`) that gnark-crypto ships as
//! `HashToG1` / `EncodeToG1` / `HashToG2` / `EncodeToG2` in its `bn254`
//! package (RFC 9380 defines the construction, not a BN254 suite;
//! gnark-crypto's are the ones in use).
//!
//! G1 (`y² = x³ + 3` over `Fp`, cofactor 1): `hash_to_field` over `Fp`
//! (`L = 48`), the same SVDW map with `Z = 1` (gnark-crypto's constant,
//! re-derived by the tests below), no cofactor clearing (every point of the
//! curve is in G1). The G2 steps:
//!
//!   1. `hash_to_field(msg, count)` — `expand_message_xmd` with SHA-256
//!      (§5.3.1, `sha2.expandMessageXmd`), `L = 48` bytes per `Fp`
//!      coordinate, `count` `Fp2` elements (2 for `_RO_`, 1 for `_NU_`).
//!   2. `Q_i = map_to_curve_svdw(u_i)` (§6.6.1, straight-line form F.1) on the
//!      twist `E': y² = x³ + b'`, `b' = 3/(9+u)`, with `Z = 1` (the first
//!      value `find_z_svdw`, §H.1, accepts — re-derived by the tests below)
//!      and `sgn0` of §4.1 for `m = 2`.
//!   3. `clear_cofactor`: the endomorphism form of Fuentes-Castañeda,
//!      Knapp and Rodríguez-Henríquez ("Faster hashing to G2", SAC 2011, §6.1)
//!      gnark-crypto uses, `[x]Q + ψ([3x]Q) + ψ²([x]Q) + ψ³(Q)`, `x` the BN
//!      seed. It lands in the order-r subgroup; a plain `[2p − r]Q` would too,
//!      but would give a different point than every other implementation of
//!      the suite.
//!
//! The DST may have any length (one over 255 bytes is reduced per RFC 9380
//! §5.3.3). Not constant-time by requirement (a hash input is public in
//! every use here); the map is straight-line apart from `sqrt`.
//!
//! Anchored by gnark-crypto's published vectors (`u`, `Q` and the output for
//! five messages per suite, all four suites, below) and by an RFC 9380 model
//! in Python that reproduced them (G2 `_RO_` and both G1 suites) before the
//! code was written.

const std = @import("std");
const sha2 = @import("sha2");
const fp = @import("fp.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");

const Fp = fp.Fp;
const Fp2 = g2.Fp2;
const G1 = g1;
const G2 = g2;
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

/// `hash_to_curve(msg)` (RFC 9380 §3, random-oracle variant), suite
/// `BN254G2_XMD:SHA-256_SVDW_RO_` under the caller's `dst`: a point of the
/// order-r subgroup of G2. gnark-crypto's `HashToG2(msg, dst)`.
pub fn hashToCurveG2(msg: []const u8, dst: []const u8) G2.Affine {
    const u = hashToFieldFp2(2, msg, dst);
    const q0 = G2.Jacobian.fromAffine(mapToCurveG2(u[0]));
    const q1 = G2.Jacobian.fromAffine(mapToCurveG2(u[1]));
    return clearCofactorG2(q0.add(q1)).toAffine();
}

/// `encode_to_curve(msg)` (RFC 9380 §3, nonuniform variant), suite
/// `BN254G2_XMD:SHA-256_SVDW_NU_`: one field element, one map, the
/// cofactor cleared. Cheaper than `hashToCurveG2`, but its output is not
/// uniform (RFC 9380 §10.4: use `hashToCurveG2` unless the protocol says
/// otherwise). gnark-crypto's `EncodeToG2(msg, dst)`.
pub fn encodeToCurveG2(msg: []const u8, dst: []const u8) G2.Affine {
    const u = hashToFieldFp2(1, msg, dst);
    return clearCofactorG2(G2.Jacobian.fromAffine(mapToCurveG2(u[0]))).toAffine();
}

/// RFC 9380 §5.2 `hash_to_field(msg, count)` over `Fp2` (`m = 2`, `L = 48`).
pub fn hashToFieldFp2(comptime count: usize, msg: []const u8, dst: []const u8) [count]Fp2 {
    const uniform = sha2.expandMessageXmd(Sha256, count * 2 * field_l, &.{msg}, dst);
    var out: [count]Fp2 = undefined;
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
const legendre_exp: [32]u8 = fp.pExponentBytes(-1, 2);

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

/// `map_to_curve_svdw(u)` (RFC 9380 §6.6.1): a point of the twist `E'`, not
/// yet in G2 (`clearCofactorG2` takes it there).
pub fn mapToCurveG2(u: Fp2) G2.Affine {
    const b = g2.twistB();
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

/// `ψ(X, Y, Z) = (X̄·γx, Ȳ·γy, Z̄)`, the twist Frobenius (`g2.psi_gamma_*`).
fn psi(p: G2.Jacobian) G2.Jacobian {
    return .{
        .x = p.x.frobenius().mul(g2.psi_gamma_x),
        .y = p.y.frobenius().mul(g2.psi_gamma_y),
        .z = p.z.frobenius(),
    };
}

/// RFC 9380 `clear_cofactor` for this suite: `[x]Q + ψ([3x]Q) + ψ²([x]Q) +
/// ψ³(Q)` (SAC 2011, §6.1; gnark-crypto's `G2Jac.ClearCofactor`): a point of
/// the order-r subgroup for every `Q` on `E'`.
pub fn clearCofactorG2(q: G2.Jacobian) G2.Jacobian {
    const xq = q.scalarMulBytes(&seed_be);
    const t1 = psi(xq.double().add(xq));
    const t2 = psi(psi(xq));
    const t3 = psi(psi(psi(q)));
    return xq.add(t1).add(t2).add(t3);
}

// ── G1 ──────────────────────────────────────────────────────────────────────

/// `hash_to_curve(msg)` (RFC 9380 §3, random-oracle variant), suite
/// `BN254G1_XMD:SHA-256_SVDW_RO_` under the caller's `dst`: a point of G1
/// (the curve's whole group; cofactor 1). gnark-crypto's `HashToG1(msg, dst)`.
pub fn hashToCurveG1(msg: []const u8, dst: []const u8) G1.Affine {
    const u = hashToFieldFp(2, msg, dst);
    const q0 = G1.Jacobian.fromAffine(mapToCurveG1(u[0]));
    const q1 = G1.Jacobian.fromAffine(mapToCurveG1(u[1]));
    return q0.add(q1).toAffine();
}

/// `encode_to_curve(msg)` (RFC 9380 §3, nonuniform variant), suite
/// `BN254G1_XMD:SHA-256_SVDW_NU_`: one field element, one map. Not uniform
/// (RFC 9380 §10.4: use `hashToCurveG1` unless the protocol says otherwise).
/// gnark-crypto's `EncodeToG1(msg, dst)`.
pub fn encodeToCurveG1(msg: []const u8, dst: []const u8) G1.Affine {
    return mapToCurveG1(hashToFieldFp(1, msg, dst)[0]);
}

/// RFC 9380 §5.2 `hash_to_field(msg, count)` over `Fp` (`m = 1`, `L = 48`);
/// gnark-crypto's `fp.Hash(msg, dst, count)`.
pub fn hashToFieldFp(comptime count: usize, msg: []const u8, dst: []const u8) [count]Fp {
    const uniform = sha2.expandMessageXmd(Sha256, count * field_l, &.{msg}, dst);
    var out: [count]Fp = undefined;
    for (&out, 0..) |*e, i| e.* = fpFromWide(uniform[i * field_l ..][0..field_l]);
    return out;
}

/// `Z = 1` (the first value `find_z_svdw`, §H.1, accepts for `A = 0, B = 3`).
const svdw1_z: Fp = Fp.one;
/// `c1 = g(Z) = 4`.
const svdw1_c1 = fpHex("0000000000000000000000000000000000000000000000000000000000000004");
/// `c2 = −Z/2`.
const svdw1_c2 = fpHex("183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3");
/// `c3 = sqrt(−g(Z)·(3Z² + 4A))` with `sgn0(c3) = 0`.
const svdw1_c3 = fpHex("00000000000000016789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa");
/// `c4 = −4·g(Z) / (3Z² + 4A)`.
const svdw1_c4 = fpHex("10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd");

fn isSquareFp(a: Fp) bool {
    return a.isZero() or a.pow(legendre_exp).eql(Fp.one);
}

/// RFC 9380 §4.1 `sgn0` for `m = 1`: the parity of the canonical value.
fn sgn0Fp(a: Fp) u1 {
    return @truncate(a.toBytes()[31]);
}

/// `g(x) = x³ + 3` (G1's curve).
fn curveRhsG1(x: Fp) Fp {
    return x.square().mul(x).add(G1.b);
}

/// `map_to_curve_svdw(u)` (RFC 9380 §6.6.1) onto `y² = x³ + 3`: a point of
/// G1 (cofactor 1, so no clearing). gnark-crypto's `MapToCurve1` / `MapToG1`.
pub fn mapToCurveG1(u: Fp) G1.Affine {
    var tv1 = u.square().mul(svdw1_c1);
    const tv2 = Fp.one.add(tv1);
    tv1 = Fp.one.sub(tv1);
    const tv3 = tv1.mul(tv2).inv0();
    const tv4 = u.mul(tv1).mul(tv3).mul(svdw1_c3);
    const x1 = svdw1_c2.sub(tv4);
    const e1 = isSquareFp(curveRhsG1(x1));
    const x2 = svdw1_c2.add(tv4);
    const e2 = isSquareFp(curveRhsG1(x2)) and !e1;
    const x3 = tv2.square().mul(tv3).square().mul(svdw1_c4).add(svdw1_z);
    var x = Fp.ctSelect(e1, x1, x3);
    x = Fp.ctSelect(e2, x2, x);
    // One of g(x1), g(x2), g(x3) is a square (the point of SVDW).
    var y = curveRhsG1(x).sqrt() orelse unreachable;
    if (sgn0Fp(u) != sgn0Fp(y)) y = y.neg();
    return .{ .x = x, .y = y, .infinity = false };
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

test "hashToCurveG2: gnark-crypto's BN254G2_XMD:SHA-256_SVDW_RO_ vectors (u0, u1, Q0, Q1, P)" {
    for (vectors) |v| {
        const u = hashToFieldFp2(2, v.msg, quux_dst);
        try testing.expect(u[0].eql(try fp2FromHex(v.u0)));
        try testing.expect(u[1].eql(try fp2FromHex(v.u1)));
        try expectPoint(mapToCurveG2(u[0]), v.q0[0], v.q0[1]);
        try expectPoint(mapToCurveG2(u[1]), v.q1[0], v.q1[1]);
        const p = hashToCurveG2(v.msg, quux_dst);
        try expectPoint(p, v.p[0], v.p[1]);
        try testing.expect(G2.Jacobian.fromAffine(p).subgroupCheck());
    }
}

const NuVector = struct { msg: []const u8, u: []const u8, q: [2][]const u8, p: [2][]const u8 };

const quux_nu_dst = "QUUX-V01-CS02-with-BN254G2_XMD:SHA-256_SVDW_NU_";

/// gnark-crypto v0.19.2, `ecc/bn254/hash_vectors_test.go`, `encodeToG2Vector`
/// (Apache-2.0; test data, transcribed).
const nu_vectors = [_]NuVector{
    .{
        .msg = "",
        .u = "0x5952a51e848675c06172da425edc1c471c11db4bc51cfb84c097bdbcf22b6b5,0x4f8c1f037b231d08ea68f3e23b8e3c708d3993a1577d1bcfc92c2392a82c47e",
        .q = .{ "0x1aff45b8bec4d8c0b48638acd6aa6886d9c0202c8f415061673ec4a1eb520af6,0x19abe65fd87b71da2f78347494f28418dee2f1b75956f0dddc4efb98837e325d", "0x1f01deb60bef6c08b36bb2cb465efdd20b597532e05a27c45034a729f8fe8f59,0x2e76aede179fdb62bdba78c6f28566f68aa721f3220a853b65c79f135e427ef7" },
        .p = .{ "0x4e9ea7f5807198397a99e234e91d4b9e6cadf0135ebedd97fd75cffed6e994d,0x70077acfda8443392fb30222ba96b63f4b734e678494bf4ed0e07074b440a7b", "0x2d3653bf41ec170ce2d48774d02393c8d5f60fee5690b4f8cbc8531e269227f9,0xa7cf5d0d356f0c4d163570209e5f8f749bf91dc2a7d9ba58199a95ce02242b4" },
    },
    .{
        .msg = "abc",
        .u = "0x25f701986d04721d21b118002eeaad1b8ecc8de722d4d8e7ad5f060518ea5c7c,0xf05f22acfb3bf7abb1f8f1b80e0de029a20a2b96c6eefa2f371431bbfca04a3",
        .q = .{ "0x2216ec5165748117d5aecf12f1eff5f6380367163e351d591f5de9aebfe5f82e,0x2dc39518b60217999eadc27840962dd62ffb38e7d7e6c72a208206e6b2c07028", "0xb424f1cc74e01e0d61084ecfb3785bc8a66443d99be786c387a4d5e1ad91832,0xbb538ea60a53b3c933726e61a57e753a8919a75d8c600f8f6af6bbf460a57ee" },
        .p = .{ "0x101e2f3d9fa22cb435ecb67d5284dc27c247856d6de4e420e1812e0bcea5afd8,0x29226a3ca7415a541599274bf9e805050c82d443fd953481b17236325be3b6b7", "0x290bf12841dd276211effe86af369c11a2cb364c443981d0faf347cfb7b68715,0x2e7c8a61fe36735852597ac564966560afe0ef8221918d5534e57f3096f7047d" },
    },
    .{
        .msg = "abcdef0123456789",
        .u = "0xeb05b113763043309faadf3c004ac0eb40f948faed5d83d4d1f0571112ca09c,0x1730924259ae2e94ae7ee719c1eeb5d6328b6963819ee4065541dfdefb5e7a07",
        .q = .{ "0x1f3620223ed7115c479ed1150b509886c8ecf7411e004e943f544829ed3fc56f,0x3063a2d037058a1ff49edba42f2f78d3fdd03e592bd3df415d04176ba269c7c7", "0x1d1a9b20266ba09a594e299ca4c9e27564218986669d1fa90566764f5a8ac63a,0x7f48bbaf8c038ad3a2167a9e43e583a73d6a88795e574c4e26834fbcf2bb44b" },
        .p = .{ "0xfcda542dd52f0e527bf828e63fe2a1f63a05c9a5c7a28865cfef247c6e1e8a6,0x2d0bb492bb59847c106af8285fae5be0b5f96b6dcad56b3a0c7ddc364ae55a3a", "0x172d50b483e9bb9aa230e7cb82fbd522af1b73c1643bbd022614533311071780,0xafb68b6e28f44f49d6ab4c3014e73f7e07fd4d0b13a9519b798e9f1927a47b9" },
    },
    .{
        .msg = "q128_" ++ @as([128]u8, @splat('q')),
        .u = "0x47b36a3ec43c92ae9070ef71f85016bd5a08c1bd0ca487672f176061ca09159,0x248076a8b63f52e5f3c7228411637e04cbd0cb36940ee3a257f60ce49e75fe86",
        .q = .{ "0x1db4c6c448341a408bd60ebf8d19bfc149927dbd5af0af598d4c6d2f1629bd8a,0x2d61dff76daa91b0044f83074f4c841e0bbf3711f5b8a7ac8e0618b29fce6d92", "0x1dedea44e27ea061f38fd062e2b1c6d93db96a32cf5a214da49f39eeeb803791,0x113a4cf8a33642670164f11b2ef257f6653ae8045ac58fc172f022f3f8107c4a" },
        .p = .{ "0x1d050758368c65df07014cab4752d8244ddf21691ab6418a3493bcc2a946b38d,0x2596aa6bcb29439a9cdc7cfe0b9d247a890a4295dc17d053c293c7e40c27387f", "0x2f84eec5eaa87952d0d81c93c3f470c1e1a00d0ba307d8fda78b76841aca8e82,0x27aef639d6eb4157c6f076e9fdae2f9eb15042dea92304fc54ebd5f69c5c3443" },
    },
    .{
        .msg = "a512_" ++ @as([512]u8, @splat('a')),
        .u = "0x2f3b24a712fbb1272e51db197d666cdad2cc94c2a6e7b77d99e97d8a705a8a50,0x253bcb542b718219fe2f6de276c6d86965d610b3e66bd0448576db18e1e9ab3f",
        .q = .{ "0x2376cb494d599bbe8523817d9702f0da6e6e0ba7f321dcccb720cd5696f57de7,0x2228f04e096f6802387d0d40b3b575afd66281de5d734b33da09fbb86cef5a1a", "0x17332e7ce9faf26d7f5c5cf247ea51f48594238faeb0be338462895016da6738,0xcbd6f12f78c47d3f46238782e5d297ab15a1b8f5c065a8ba52620c16d555fa0" },
        .p = .{ "0x13729abbd4fbe2a13bc742960afa9053a4e6be06ea712b0d18153a9ec3854a7,0x261e8ebaff3438064599465bb52880e8e8a663b27cfb6d794d90ac60437819a9", "0x132285a30dc36cc14da2d145390a6328e574155ebaece32856fb890d1f7ba16e,0x6bd9197b3c0c1cc4d17695042dcbaf0168329a113d358c3b17885f71a394986" },
    },
};

test "encodeToCurveG2: gnark-crypto's BN254G2_XMD:SHA-256_SVDW_NU_ vectors (u, Q, P)" {
    for (nu_vectors) |v| {
        const u = hashToFieldFp2(1, v.msg, quux_nu_dst);
        try testing.expect(u[0].eql(try fp2FromHex(v.u)));
        try expectPoint(mapToCurveG2(u[0]), v.q[0], v.q[1]);
        const p = encodeToCurveG2(v.msg, quux_nu_dst);
        try expectPoint(p, v.p[0], v.p[1]);
        try testing.expect(G2.Jacobian.fromAffine(p).subgroupCheck());
    }
}

test "SVDW constants: re-derived from their RFC 9380 definitions (A = 0, Z = 1)" {
    const b = g2.twistB();
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
    const b = g2.twistB();
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
        const q = mapToCurveG2(u);
        try testing.expect(q.y.square().eql(curveRhs(q.x, b)));
    }
}

test "clearCofactorG2: the raw SVDW point is outside G2, the cleared one inside" {
    const q = mapToCurveG2(hashToFieldFp2(1, "cofactor", quux_dst)[0]);
    const j = G2.Jacobian.fromAffine(q);
    try testing.expect(j.isOnCurve());
    try testing.expect(!j.subgroupCheck());
    const c = clearCofactorG2(j);
    try testing.expect(!c.isIdentity());
    try testing.expect(c.subgroupCheck());
}

// ── G1 tests ────────────────────────────────────────────────────────────────

const G1Vector = struct { msg: []const u8, u0: []const u8, u1: []const u8, q0: [2][]const u8, q1: [2][]const u8, p: [2][]const u8 };
const G1NuVector = struct { msg: []const u8, u: []const u8, q: [2][]const u8, p: [2][]const u8 };

const quux_g1_dst = "QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_";
const quux_g1_nu_dst = "QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_NU_";

// gnark-crypto v0.19.2, `ecc/bn254/hash_vectors_test.go`, `hashToG1Vector`
// and `encodeToG1Vector` (Apache-2.0; test data, transcribed). An RFC 9380
// model in Python reproduced every value (and gnark-crypto's Montgomery-form
// SVDW constants) before the code below was written.
const g1_vectors = [_]G1Vector{
    .{ .msg = "", .u0 = "0x2f87b81d9d6ef05ad4d249737498cc27e1bd485dca804487844feb3c67c1a9b5", .u1 = "0x6de2d0d7c0d9c7a5a6c0b74675e7543f5b98186b5dbf831067449000b2b1f8e", .q0 = .{ "0xe449b959abbd0e5ab4c873eaeb1ccd887f1d9ad6cd671fd72cb8d77fb651892", "0x29ff1e36867c60374695ee0c298fcbef2af16f8f97ed356fa75e61a797ebb265" }, .q1 = .{ "0x19388d9112a306fba595c3a8c63daa8f04205ad9581f7cf105c63c442d7c6511", "0x182da356478aa7776d1de8377a18b41e933036d0b71ab03f17114e4e673ad6e4" }, .p = .{ "0xa976ab906170db1f9638d376514dbf8c42aef256a54bbd48521f20749e59e86", "0x2925ead66b9e68bfc309b014398640ab55f6619ab59bc1fab2210ad4c4d53d5" } },
    .{ .msg = "abc", .u0 = "0x11945105b5e3d3b9392b5a2318409cbc28b7246aa47fa30da5739907737799a9", .u1 = "0x1255fc9ad5a6e0fb440916f091229bda611c41be2f2283c3d8f98c596be4c8c9", .q0 = .{ "0x1452c8cc24f8dedc25b24d89b87b64e25488191cecc78464fea84077dd156f8d", "0x209c3633505ba956f5ce4d974a868db972b8f1b69d63c218d360996bcec1ad41" }, .q1 = .{ "0x4e8357c98524e6208ae2b771e370f0c449e839003988c2e4ce1eaf8d632559f", "0x4396ec43dd8ec8f2b4a705090b5892219759da30154c39490fc4d59d51bb817" }, .p = .{ "0x23f717bee89b1003957139f193e6be7da1df5f1374b26a4643b0378b5baf53d1", "0x4142f826b71ee574452dbc47e05bc3e1a647478403a7ba38b7b93948f4e151d" } },
    .{ .msg = "abcdef0123456789", .u0 = "0x2f7993a6b43a8dbb37060e790011a888157f456b895b925c3568690685f4983d", .u1 = "0x2677d0532b47a4cead2488845e7df7ebc16c0b8a2cd8a6b7f4ce99f51659794e", .q0 = .{ "0x28d01790d2a1cc4832296774438acd46c2ce162d03099926478cf52319daba8d", "0x10227ab2707fd65fb45e87f0a48cfe3556f04113d27b1da9a7ae1709007355e1" }, .q1 = .{ "0x7dc256c7aadac1b4e1d23b3b2bbb5e2ffd9c753b9073d8d952ead8f812ce1b3", "0x2589008b2e15dcb3d16cdc1fed2634778001b1b28f0ab433f4f5ec6635c55e1e" }, .p = .{ "0x187dbf1c3c89aceceef254d6548d7163fdfa43084145f92c4c91c85c21442d4a", "0xabd99d5b0000910b56058f9cc3b0ab0a22d47cf27615f588924fac1e5c63b4d" } },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .u0 = "0x2a50be15282ee276b76db1dab761f75401cdc8bd9fff81fcf4d428db16092a7b", .u1 = "0x23b41953676183c30aca54b5c8bd3ffe3535a6238c39f6b15487a5467d5d20eb", .q0 = .{ "0x1c53b05f2fce15ba0b9100650c0fb46de1fb62f1d0968b69151151bd25dfefa4", "0x1fe783faf4bdbd79b717784dc59619106e4acccfe3b5d9750799729d855e7b81" }, .q1 = .{ "0x214a4e6e97adda47558f80088460eabd71ed35bc8ceafb99a493dd6f4e2b3f0a", "0xfaaeb29cc23f9d09b187a99741613aed84443e7c35736258f57982d336d13bd" }, .p = .{ "0xfe2b0743575324fc452d590d217390ad48e5a16cf051bee5c40a2eba233f5c", "0x794211e0cc72d3cbbdf8e4e5cd6e7d7e78d101ff94862caae8acbe63e9fdc78" } },
    .{ .msg = "a512_" ++ @as([512]u8, @splat('a')), .u0 = "0x48527470f534978bae262c0f3ba8380d7f560916af58af9ad7dcb6a4238e633", .u1 = "0x19a6d8be25702820b9b11eada2d42f425343889637a01ecd7672fbcf590d9ffe", .q0 = .{ "0x2298ba379768da62495af6bb390ffca9156fde1dc167235b89c6dd008d2f2f3b", "0x660564cf6fce5cdea4780f5976dd0932559336fd072b4ddd83ec37f00fc7699" }, .q1 = .{ "0x2811dea430f7a1f6c8c941ecdf0e1e725b8ad1801ad15e832654bd8f10b62f16", "0x253390ed4fb39e58c30ca43892ab0428684cfb30b9df05fc239ab532eaa02444" }, .p = .{ "0x1b05dc540bd79fd0fea4fbb07de08e94fc2e7bd171fe025c479dc212a2173ce", "0x1bf028afc00c0f843d113758968f580640541728cfc6d32ced9779aa613cd9b0" } },
};

const g1_nu_vectors = [_]G1NuVector{
    .{ .msg = "", .u = "0xcb81538a98a2e3580076eed495256611813f6dae9e16d3d4f8de7af0e9833e1", .q = .{ "0x1bb8810e2ceaf04786d4efd216fc2820ddd9363712efc736ada11049d8af5925", "0x1efbf8d54c60d865cce08437668ea30f5bf90d287dbd9b5af31da852915e8f11" }, .p = .{ "0x1bb8810e2ceaf04786d4efd216fc2820ddd9363712efc736ada11049d8af5925", "0x1efbf8d54c60d865cce08437668ea30f5bf90d287dbd9b5af31da852915e8f11" } },
    .{ .msg = "abc", .u = "0xba35e127276e9000b33011860904ddee28f1d48ddd3577e2a797ef4a5e62319", .q = .{ "0xda4a96147df1f35b0f820bd35c6fac3b80e8e320de7c536b1e054667b22c332", "0x189bd3fbffe4c8740d6543754d95c790e44cd2d162858e3b733d2b8387983bb7" }, .p = .{ "0xda4a96147df1f35b0f820bd35c6fac3b80e8e320de7c536b1e054667b22c332", "0x189bd3fbffe4c8740d6543754d95c790e44cd2d162858e3b733d2b8387983bb7" } },
    .{ .msg = "abcdef0123456789", .u = "0x11852286660cd970e9d7f46f99c7cca2b75554245e91b9b19d537aa6147c28fc", .q = .{ "0x2ff727cfaaadb3acab713fa22d91f5fddab3ed77948f3ef6233d7ea9b03f4da1", "0x304080768fd2f87a852155b727f97db84b191e41970506f0326ed4046d1141aa" }, .p = .{ "0x2ff727cfaaadb3acab713fa22d91f5fddab3ed77948f3ef6233d7ea9b03f4da1", "0x304080768fd2f87a852155b727f97db84b191e41970506f0326ed4046d1141aa" } },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .u = "0x174d1c85d8a690a876cc1deba0166d30569fafdb49cb3ed28405bd1c5357a1cc", .q = .{ "0x11a2eaa8e3e89de056d1b3a288a7f733c8a1282efa41d28e71af065ab245df9b", "0x60f37c447ac29fd97b9bb83be98ddccf15e34831a9cdf5493b7fede0777ae06" }, .p = .{ "0x11a2eaa8e3e89de056d1b3a288a7f733c8a1282efa41d28e71af065ab245df9b", "0x60f37c447ac29fd97b9bb83be98ddccf15e34831a9cdf5493b7fede0777ae06" } },
    .{ .msg = "a512_" ++ @as([512]u8, @splat('a')), .u = "0x73b81432b4cf3a8a9076201500d1b94159539f052a6e0928db7f2df74bff672", .q = .{ "0x27409dccc6ee4ce90e24744fda8d72c0bc64e79766f778da0c1c0ef1c186ea84", "0x1ac201a542feca15e77f30370da183514dc99d8a0b2c136d64ede35cd0b51dc0" }, .p = .{ "0x27409dccc6ee4ce90e24744fda8d72c0bc64e79766f778da0c1c0ef1c186ea84", "0x1ac201a542feca15e77f30370da183514dc99d8a0b2c136d64ede35cd0b51dc0" } },
};

fn expectPointG1(got: G1.Affine, x: []const u8, y: []const u8) !void {
    try testing.expect(!got.infinity);
    try testing.expect(got.x.eql(try fpFromHex(x)));
    try testing.expect(got.y.eql(try fpFromHex(y)));
}

test "hashToCurveG1: gnark-crypto's BN254G1_XMD:SHA-256_SVDW_RO_ vectors (u0, u1, Q0, Q1, P)" {
    for (g1_vectors) |v| {
        const u = hashToFieldFp(2, v.msg, quux_g1_dst);
        try testing.expect(u[0].eql(try fpFromHex(v.u0)));
        try testing.expect(u[1].eql(try fpFromHex(v.u1)));
        try expectPointG1(mapToCurveG1(u[0]), v.q0[0], v.q0[1]);
        try expectPointG1(mapToCurveG1(u[1]), v.q1[0], v.q1[1]);
        const p = hashToCurveG1(v.msg, quux_g1_dst);
        try expectPointG1(p, v.p[0], v.p[1]);
        try testing.expect(G1.Jacobian.fromAffine(p).isOnCurve());
    }
}

test "encodeToCurveG1: gnark-crypto's BN254G1_XMD:SHA-256_SVDW_NU_ vectors (u, Q, P)" {
    for (g1_nu_vectors) |v| {
        const u = hashToFieldFp(1, v.msg, quux_g1_nu_dst);
        try testing.expect(u[0].eql(try fpFromHex(v.u)));
        try expectPointG1(mapToCurveG1(u[0]), v.q[0], v.q[1]);
        try expectPointG1(encodeToCurveG1(v.msg, quux_g1_nu_dst), v.p[0], v.p[1]);
    }
}

test "G1 SVDW constants: re-derived from their RFC 9380 definitions (A = 0, B = 3, Z = 1)" {
    const gz = curveRhsG1(svdw1_z);
    const two = try Fp.fromInt(u8, 2);
    const three = try Fp.fromInt(u8, 3);
    const four = try Fp.fromInt(u8, 4);
    try testing.expect(svdw1_c1.eql(gz));
    try testing.expect(svdw1_c2.mul(two).eql(svdw1_z.neg()));
    try testing.expect(svdw1_c3.square().eql(gz.neg().mul(three)));
    try testing.expectEqual(@as(u1, 0), sgn0Fp(svdw1_c3));
    try testing.expect(svdw1_c4.mul(three).eql(four.mul(gz).neg()));
    // find_z_svdw (§H.1) tries 1 first; it qualifies.
    try testing.expect(!gz.isZero());
    const h = three.neg().mul(four.mul(gz).inv0());
    try testing.expect(!h.isZero() and isSquareFp(h));
    try testing.expect(isSquareFp(gz));
}

test "mapToCurveG1: the exceptional inputs (tv1·tv2 = 0) still land on the curve" {
    var inputs: [5]Fp = @splat(Fp.zero);
    var n: usize = 1;
    const inv_c1 = svdw1_c1.inv0();
    for ([_]Fp{ inv_c1, inv_c1.neg() }) |t| {
        if (t.sqrt()) |r| {
            inputs[n] = r;
            inputs[n + 1] = r.neg();
            n += 2;
        }
    }
    try testing.expect(n > 1);
    for (inputs[0..n]) |u| {
        const q = mapToCurveG1(u);
        try testing.expect(q.y.square().eql(curveRhsG1(q.x)));
    }
}

test "hashToCurveG1: a DST over 255 bytes is accepted (RFC 9380 §5.3.3) and separates" {
    const long: [300]u8 = @splat('D');
    const a = hashToCurveG1("m", &long);
    const b = hashToCurveG1("m", long[0..299]);
    try testing.expect(G1.Jacobian.fromAffine(a).isOnCurve());
    try testing.expect(!a.x.eql(b.x));
}

test "mutation 2026-11-25: isSquareFp: zero and one are squares, -1 is not (p = 3 mod 4)" {
    try testing.expect(isSquareFp(Fp.zero));
    try testing.expect(isSquareFp(Fp.one));
    try testing.expect(!isSquareFp(Fp.one.neg()));
}

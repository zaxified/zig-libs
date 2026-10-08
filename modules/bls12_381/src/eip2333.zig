// SPDX-License-Identifier: MIT
//! EIP-2333 BLS12-381 hierarchical key derivation (`derive_master_SK`,
//! `derive_child_SK`) plus an EIP-2334-style path helper
//! (`m/12381/3600/i/0/0`).
//!
//! NOT the same algorithm as `bls_sig.keyGen` (draft-irtf-cfrg-bls-
//! signature-05 KeyGen): EIP-2333's `HKDF_mod_r` hashes the salt BEFORE
//! the first iteration (`salt = SHA256("BLS-SIG-KEYGEN-SALT-")`, then
//! loops), while the draft's `keyGen` uses the raw ASCII string on the
//! first iteration and hashes only on retry. The two give different keys
//! for the same input; do not mix them.
//!
//! Not constant-time beyond what HKDF-SHA256 / SHA-256 give: the retry
//! loop of `HKDF_mod_r` branches on `SK == 0` (probability ~2^-255). The
//! Lamport chunk buffers (secret) are zeroed before every return.
//!
//! Spec: https://eips.ethereum.org/EIPS/eip-2333 (CC0).

const std = @import("std");
const scalarmod = @import("scalar.zig");
const bls_sig = @import("bls_sig.zig");
const burn = @import("burn.zig");

const Fr = scalarmod.Fr;
const SecretKey = bls_sig.SecretKey;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Eip2333Error = error{SeedTooShort};
pub const PathError = error{ InvalidPath, PathTooDeep };

/// `K` — Lamport chunk size (SHA-256 output).
const lamport_k = 32;
/// Number of chunks per Lamport secret key.
const lamport_chunks = 255;
/// `L` — HKDF_mod_r output length (ceil(3 * 255 / 16)).
const l_bytes = 48;
const hkdf_salt = "BLS-SIG-KEYGEN-SALT-";

/// EIP-2333 `HKDF_mod_r(IKM, key_info = "")`: salt is hashed first on
/// every iteration (see the module doc).
fn hkdfModR(ikm: []const u8) Fr {
    var salt: [32]u8 = undefined;
    var salt_in: []const u8 = hkdf_salt;
    while (true) {
        Sha256.hash(salt_in, &salt, .{});
        salt_in = &salt;

        var st = Hkdf.extractInit(&salt);
        st.update(ikm);
        st.update(&[_]u8{0}); // I2OSP(0, 1)
        var prk: [Hkdf.prk_length]u8 = undefined;
        st.final(&prk);
        defer std.crypto.secureZero(u8, &prk);

        var info: [2]u8 = undefined;
        std.mem.writeInt(u16, &info, l_bytes, .big); // key_info || I2OSP(L, 2)
        var okm: [l_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &okm);
        Hkdf.expand(&okm, &info, prk);

        const sk = Fr.reduceWide(&okm);
        if (!sk.isZero()) return sk;
    }
}

/// `IKM_to_lamport_SK`: 255 chunks of 32 bytes (HKDF-Expand with empty info).
fn ikmToLamportSk(out: *[lamport_chunks * lamport_k]u8, ikm: *const [32]u8, salt: *const [4]u8) void {
    const prk = Hkdf.extract(salt, ikm);
    Hkdf.expand(out, "", prk);
}

/// `parent_SK_to_lamport_PK`: compressed Lamport public key (32 bytes).
fn parentSkToLamportPk(out: *[32]u8, parent: *const Fr, index: u32) void {
    var salt: [4]u8 = undefined;
    std.mem.writeInt(u32, &salt, index, .big);

    var ikm = parent.toBytes(); // I2OSP(parent_SK, 32)
    var not_ikm: [32]u8 = undefined;
    for (&not_ikm, ikm) |*o, b| o.* = ~b;

    var lamport_0: [lamport_chunks * lamport_k]u8 = undefined;
    var lamport_1: [lamport_chunks * lamport_k]u8 = undefined;
    var pk: [2 * lamport_chunks * lamport_k]u8 = undefined;
    defer {
        std.crypto.secureZero(u8, &ikm);
        std.crypto.secureZero(u8, &not_ikm);
        std.crypto.secureZero(u8, &lamport_0);
        std.crypto.secureZero(u8, &lamport_1);
        std.crypto.secureZero(u8, &pk); // hashes of secrets; cheap to wipe
    }
    ikmToLamportSk(&lamport_0, &ikm, &salt);
    ikmToLamportSk(&lamport_1, &not_ikm, &salt);

    for (0..lamport_chunks) |i| {
        Sha256.hash(lamport_0[i * lamport_k ..][0..lamport_k], pk[i * lamport_k ..][0..lamport_k], .{});
        Sha256.hash(lamport_1[i * lamport_k ..][0..lamport_k], pk[(lamport_chunks + i) * lamport_k ..][0..lamport_k], .{});
    }
    Sha256.hash(&pk, out, .{});
}

/// EIP-2333 `derive_master_SK(seed)`. `seed` MUST be at least 32 bytes.
/// Every derivation below writes its key to `out` (zeroed on error), runs
/// one frame down and zeroes the stack it dirtied (`burn.zig`).
pub fn deriveMasterSk(out: *SecretKey, seed: []const u8) Eip2333Error!void {
    if (seed.len < 32) {
        out.deinit();
        return error.SeedTooShort;
    }
    burn.run(burn.derive_burn, void, deriveMasterBody, .{ out, seed });
}

fn deriveMasterBody(out: *SecretKey, seed: []const u8) void {
    out.scalar = hkdfModR(seed);
}

/// EIP-2333 `derive_child_SK(parent_SK, index)`; `index` is the full u32
/// (EIP-2333 does not distinguish hardened indices). `out` may alias
/// `parent`.
pub fn deriveChildSk(out: *SecretKey, parent: *const SecretKey, index: u32) void {
    burn.run(burn.derive_burn, void, deriveChildBody, .{ out, parent, index });
}

fn deriveChildBody(out: *SecretKey, parent: *const SecretKey, index: u32) void {
    var lpk: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &lpk);
    parentSkToLamportPk(&lpk, &parent.scalar, index);
    out.scalar = hkdfModR(&lpk);
}

/// Derive along `path` from the master key of `seed` (empty path = master).
pub fn derivePath(out: *SecretKey, seed: []const u8, path: []const u32) Eip2333Error!void {
    if (seed.len < 32) {
        out.deinit();
        return error.SeedTooShort;
    }
    burn.run(burn.derive_burn, void, derivePathBody, .{ out, seed, path });
}

fn derivePathBody(out: *SecretKey, seed: []const u8, path: []const u32) void {
    // Every intermediate key lives only in `out`, overwritten in place.
    deriveMasterBody(out, seed);
    for (path) |idx| deriveChildBody(out, out, idx);
}

/// Maximum number of components `parsePath` accepts.
pub const max_path_depth = 32;

/// A parsed derivation path (components after the leading `m`).
pub const Path = struct {
    components: [max_path_depth]u32 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Path) []const u32 {
        return self.components[0..self.len];
    }
};

/// Parse `"m/12381/3600/0/0/0"`. `"m"` alone is the empty path. Rejects a
/// missing leading `m`, empty components (incl. trailing `/`), non-digit
/// characters (no signs, no `'`) and values above `u32` max.
pub fn parsePath(text: []const u8) PathError!Path {
    var it = std.mem.splitScalar(u8, text, '/');
    const first = it.next().?;
    if (!std.mem.eql(u8, first, "m")) return error.InvalidPath;
    var p: Path = .{};
    while (it.next()) |part| {
        if (part.len == 0) return error.InvalidPath;
        for (part) |c| if (c < '0' or c > '9') return error.InvalidPath;
        const v = std.fmt.parseInt(u32, part, 10) catch return error.InvalidPath;
        if (p.len == max_path_depth) return error.PathTooDeep;
        p.components[p.len] = v;
        p.len += 1;
    }
    return p;
}

// ── tests ───────────────────────────────────────────────────────────

const testing = std.testing;

fn decBytes(comptime dec: []const u8) [32]u8 {
    @setEvalBranchQuota(100_000);
    const v = comptime std.fmt.parseInt(u256, dec, 10) catch unreachable;
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, v, .big);
    return out;
}

fn hexAlloc(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// Vectors: EIP-2333 test cases, https://eips.ethereum.org/EIPS/eip-2333
// (fetched 2026-10-06). Decimal values transcribed verbatim.
const Vec = struct {
    seed: []const u8,
    master: [32]u8,
    index: u32,
    child: [32]u8,
};

const vectors = [_]Vec{
    .{
        .seed = &hexAlloc("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
        .master = decBytes("6083874454709270928345386274498605044986640685124978867557563392430687146096"),
        .index = 0,
        .child = decBytes("20397789859736650942317412262472558107875392172444076792671091975210932703118"),
    },
    .{
        .seed = &hexAlloc("3141592653589793238462643383279502884197169399375105820974944592"),
        .master = decBytes("29757020647961307431480504535336562678282505419141012933316116377660817309383"),
        .index = 3141592653,
        .child = decBytes("25457201688850691947727629385191704516744796114925897962676248250929345014287"),
    },
    .{
        .seed = &hexAlloc("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00"),
        .master = decBytes("27580842291869792442942448775674722299803720648445448686099262467207037398656"),
        .index = 4294967295,
        .child = decBytes("29358610794459428860402234341874281240803786294062035874021252734817515685787"),
    },
    .{
        .seed = &hexAlloc("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
        .master = decBytes("19022158461524446591288038168518313374041767046816487870552872741050760015818"),
        .index = 42,
        .child = decBytes("31372231650479070279774297061823572166496564838472787488249775572789064611981"),
    },
};

test "eip2333: EIP master_SK vectors" {
    for (vectors) |v| {
        var sk: bls_sig.SecretKey = undefined;
        try deriveMasterSk(&sk, v.seed);
        try testing.expectEqualSlices(u8, &v.master, &sk.scalar.toBytes());
    }
}

test "eip2333: EIP child_SK vectors" {
    for (vectors) |v| {
        const master = try Fr.fromBytes(v.master);
        const parent: SecretKey = .{ .scalar = master };
        var child: SecretKey = undefined;
        deriveChildSk(&child, &parent, v.index);
        try testing.expectEqualSlices(u8, &v.child, &child.scalar.toBytes());
    }
}

test "eip2333: compressed_lamport_PK intermediate from the EIP" {
    const master = try Fr.fromBytes(vectors[0].master);
    var lpk: [32]u8 = undefined;
    parentSkToLamportPk(&lpk, &master, 0);
    const expected = hexAlloc("dd635d27d1d52b9a49df9e5c0c622360a4dd17cba7db4e89bce3cb048fb721a5");
    try testing.expectEqualSlices(u8, &expected, &lpk);
}

test "eip2333: negative control, flipped seed byte does not match" {
    var seed: [64]u8 = undefined;
    @memcpy(&seed, vectors[0].seed);
    seed[10] ^= 1;
    var sk: bls_sig.SecretKey = undefined;
    try deriveMasterSk(&sk, &seed);
    try testing.expect(!std.mem.eql(u8, &vectors[0].master, &sk.scalar.toBytes()));
}

test "eip2333: seed shorter than 32 bytes is rejected" {
    var seed: [31]u8 = @splat(7);
    var sk: SecretKey = undefined;
    try testing.expectError(error.SeedTooShort, deriveMasterSk(&sk, &seed));
    try testing.expectError(error.SeedTooShort, derivePath(&sk, &seed, &.{}));
    var ok: [32]u8 = @splat(7);
    try deriveMasterSk(&sk, &ok);
}

test "eip2333: derivePath equals chained deriveChildSk" {
    const seed = vectors[3].seed;
    const p = try parsePath("m/12381/3600/0/0/0");
    try testing.expectEqualSlices(u32, &.{ 12381, 3600, 0, 0, 0 }, p.slice());
    var sk: bls_sig.SecretKey = undefined;
    try deriveMasterSk(&sk, seed);
    for ([_]u32{ 12381, 3600, 0, 0, 0 }) |i| deriveChildSk(&sk, &sk, i);
    var via: bls_sig.SecretKey = undefined;
    try derivePath(&via, seed, p.slice());
    try testing.expectEqualSlices(u8, &sk.scalar.toBytes(), &via.scalar.toBytes());
    var master: bls_sig.SecretKey = undefined;
    try derivePath(&master, seed, &.{});
    try testing.expectEqualSlices(u8, &vectors[3].master, &master.scalar.toBytes());
}

test "eip2333: parsePath rejections" {
    try testing.expectEqual(@as(usize, 0), (try parsePath("m")).len);
    try testing.expectError(error.InvalidPath, parsePath(""));
    try testing.expectError(error.InvalidPath, parsePath("12381/3600"));
    try testing.expectError(error.InvalidPath, parsePath("M/1"));
    try testing.expectError(error.InvalidPath, parsePath("m/"));
    try testing.expectError(error.InvalidPath, parsePath("m//1"));
    try testing.expectError(error.InvalidPath, parsePath("m/1/"));
    try testing.expectError(error.InvalidPath, parsePath("m/1a"));
    try testing.expectError(error.InvalidPath, parsePath("m/-1"));
    try testing.expectError(error.InvalidPath, parsePath("m/+1"));
    try testing.expectError(error.InvalidPath, parsePath("m/1'"));
    try testing.expectError(error.InvalidPath, parsePath("m/4294967296"));
    try testing.expectEqual(@as(u32, 4294967295), (try parsePath("m/4294967295")).components[0]);
    const deep = "m" ++ "/1" ** (max_path_depth + 1);
    try testing.expectError(error.PathTooDeep, parsePath(deep));
}

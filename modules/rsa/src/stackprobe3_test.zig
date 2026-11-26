// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of the private-key entry points
//! `stackprobe_test.zig` does not call: the prehashed / digest / blinded / H
//! signing variants, `decryptOaepH`, the secret-key serializers (plain and
//! PBES2-encrypted), the encrypted loaders, `fromPrimesWith` and `generateWith`.
//! Residue rule below each burn, plus needles: the key's primes (both byte
//! orders) and every output buffer that holds secret bytes (DER/PEM of the
//! private key). ReleaseFast/ReleaseSmall only (`skipUnlessOptimized`, a
//! runtime skip, so the body is type-checked in every mode). Coverage sweep
//! 2026-11-26 (public secret-touching entry points no probe called).

const std = @import("std");
const rsa = @import("root.zig");
const sp = @import("testkit").stackprobe;
const Sha256 = std.crypto.hash.sha2.Sha256;

const P = sp.Probe(.{ .window = 512 * 1024, .max_windows = 1 << 17 });

/// The module's own 2048-bit KAT key (public in this repository, as in `stackprobe_test.zig`).
const kat_p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");
const kat_e = [_]u8{ 0x01, 0x00, 0x01 };

fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    var b: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

var sk: rsa.SecretKey = undefined;
var p_le: [128]u8 = undefined;
var q_le: [128]u8 = undefined;
var digest: [32]u8 = undefined;
var out: [512]u8 = undefined;
var der: [4096]u8 = undefined;
var enc_der: [4096]u8 = undefined;
var enc_der_len: usize = 0;
var enc_pem: [8192]u8 = undefined;
var enc_pem_len: usize = 0;
var ct: [256]u8 = undefined;
var prng: std.Random.DefaultPrng = .init(11);
var loaded: rsa.SecretKey = undefined;
var kp: rsa.KeyPair = undefined;
const password = "rsa probe password 2026-11-26";
const msg = "rsa dead-stack probe message (coverage sweep)";
const fast_pbes2: rsa.Pbes2Options = .{ .iterations = 16 };

var d_be: [256]u8 = undefined;
var dp_be: [128]u8 = undefined;
var dq_be: [128]u8 = undefined;
var qinv_be: [128]u8 = undefined;

/// Every image of the key's secret parts: primes in both byte orders, the
/// CRT exponents and `d` big-endian, and the in-memory images of the `ff`
/// and montint carriers (their limb layouts differ from the byte strings).
fn keyNeedles() [14][]const u8 {
    return .{
        &kat_p,                      &kat_q,                      &p_le,                   &q_le,
        &d_be,                       &dp_be,                      &dq_be,                  &qinv_be,
        std.mem.asBytes(&sk.d),      std.mem.asBytes(&sk.dp),     std.mem.asBytes(&sk.dq), std.mem.asBytes(&sk.qinv),
        std.mem.asBytes(&sk.p_mont), std.mem.asBytes(&sk.q_mont),
    };
}

var failures: usize = 0;

/// `P.run`, but a failing entry point is counted and the next one still runs,
/// so one build reports every entry point.
fn probe(comptime label: []const u8, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f)), secrets: []const []const u8) void {
    _ = P.run(label, f, args, secrets, .{}) catch |e| {
        failures += 1;
        std.debug.print("STACKPROBE rsa sweep: {s} -> {t}\n", .{ label, e });
    };
}

// Wrappers: the engine takes a concrete function; each forwards pointers only.
fn signPkcs1Pre(k: *const rsa.SecretKey, d: *const [32]u8, o: []u8) ![]u8 {
    return rsa.signPkcs1v15Prehashed(k, Sha256, d, o);
}
fn signPkcs1Blinded(k: *const rsa.SecretKey, o: []u8) ![]u8 {
    return rsa.signPkcs1v15Blinded(k, Sha256, .{ .csprng = prng.random() }, msg, o);
}
fn signPkcs1Dig(k: *const rsa.SecretKey, d: *const [32]u8, o: []u8) ![]u8 {
    return rsa.signPkcs1v15Digest(k, .sha256, d, o);
}
fn signPssPre(k: *const rsa.SecretKey, d: *const [32]u8, o: []u8) ![]u8 {
    return rsa.signPssPrehashed(k, Sha256, prng.random(), d, 32, o);
}
fn signPssBlind(k: *const rsa.SecretKey, o: []u8) ![]u8 {
    return rsa.signPssBlinded(k, Sha256, prng.random(), .{ .csprng = prng.random() }, msg, 32, o);
}
fn signPssHh(k: *const rsa.SecretKey, o: []u8) ![]u8 {
    return rsa.signPssH(k, Sha256, Sha256, prng.random(), msg, 32, o);
}
fn signPssDig(k: *const rsa.SecretKey, d: *const [32]u8, o: []u8) ![]u8 {
    return rsa.signPssDigest(k, .sha256, prng.random(), d, 32, o);
}
fn decOaepH(k: *const rsa.SecretKey, o: []u8) ![]u8 {
    return rsa.decryptOaepH(k, Sha256, Sha256, &ct, "", o);
}
fn toPkcs8Enc(k: *const rsa.SecretKey, o: []u8) ![]u8 {
    return k.toPkcs8Encrypted(password, prng.random(), fast_pbes2, o);
}
fn toPemEnc(k: *const rsa.SecretKey, o: []u8) ![]u8 {
    return k.toPemEncrypted(password, prng.random(), fast_pbes2, o);
}
fn fromPemEnc(o: *rsa.SecretKey) !void {
    return rsa.SecretKey.fromPemEncrypted(o, enc_pem[0..enc_pem_len], password);
}
fn fromPemEncLimited(o: *rsa.SecretKey) !void {
    return rsa.SecretKey.fromPemEncryptedLimited(o, enc_pem[0..enc_pem_len], password, .{});
}
fn fromP8Enc(o: *rsa.SecretKey) !void {
    return rsa.fromPkcs8Encrypted(o, enc_der[0..enc_der_len], password);
}
fn fromP8EncLimited(o: *rsa.SecretKey) !void {
    return rsa.fromPkcs8EncryptedLimited(o, enc_der[0..enc_der_len], password, .{});
}
var plain_der: [4096]u8 = undefined;
var plain_der_s: []const u8 = &.{};
var p8_der: [4096]u8 = undefined;
var p8_der_s: []const u8 = &.{};
var plain_pem: [8192]u8 = undefined;
var plain_pem_len: usize = 0;
fn fromDerW(o: *rsa.SecretKey) !void {
    return rsa.SecretKey.fromDer(o, plain_der_s);
}
fn fromP8W(o: *rsa.SecretKey) !void {
    return rsa.fromPkcs8(o, p8_der_s);
}
fn fromPemW(o: *rsa.SecretKey) !void {
    return rsa.SecretKey.fromPem(o, plain_pem[0..plain_pem_len]);
}
fn fromPemEncPlain(o: *rsa.SecretKey) !void {
    return rsa.SecretKey.fromPemEncrypted(o, plain_pem[0..plain_pem_len], password);
}
fn fromPrimesW(o: *rsa.SecretKey) !void {
    return rsa.SecretKey.fromPrimesWith(o, &kat_p, &kat_q, &kat_e, .{});
}
fn genWith(o: *rsa.KeyPair) !void {
    return rsa.generateWith(o, prng.random(), 2048, 65537, .{});
}

test "STACKPROBE: signing variants, decryptOaepH and key (de)serializers leave no prime or key bytes on the dead stack" {
    try sp.skipUnlessOptimized();
    try rsa.SecretKey.fromPrimes(&sk, &kat_p, &kat_q, &kat_e);
    defer sk.deinit();
    p_le = kat_p;
    std.mem.reverse(u8, &p_le);
    q_le = kat_q;
    std.mem.reverse(u8, &q_le);
    Sha256.hash(msg, &digest, .{});
    try sk.d.toBytes(&d_be, .big);
    try sk.dp.toBytes(&dp_be, .big);
    try sk.dq.toBytes(&dq_be, .big);
    try sk.qinv.toBytes(&qinv_be, .big);
    const kn = keyNeedles();
    const pw = [_][]const u8{password};
    const knp = kn ++ pw;
    const k: *const rsa.SecretKey = &sk;

    probe("signPkcs1v15Prehashed", signPkcs1Pre, .{ k, &digest, &out }, &kn);
    probe("signPkcs1v15Blinded", signPkcs1Blinded, .{ k, &out }, &kn);
    probe("signPkcs1v15Digest", signPkcs1Dig, .{ k, &digest, &out }, &kn);
    probe("signPssPrehashed", signPssPre, .{ k, &digest, &out }, &kn);
    probe("signPssBlinded", signPssBlind, .{ k, &out }, &kn);
    probe("signPssH", signPssHh, .{ k, &out }, &kn);
    probe("signPssDigest", signPssDig, .{ k, &digest, &out }, &kn);

    const pk = try rsa.PublicKey.fromBytes(&kat_n, &kat_e);
    ct = (try rsa.encryptOaep(pk, Sha256, prng.random(), "secret plaintext", "", &out))[0..256].*;
    probe("decryptOaepH", decOaepH, .{ k, &out }, &(kn ++ [_][]const u8{out[0..16]}));

    // Serializers: the output IS the secret key (DER/PEM), so it is a needle too.
    probe("SecretKey.toPkcs1Der", rsa.SecretKey.toPkcs1Der, .{ k, &der }, &kn);
    probe("SecretKey.toPkcs8Der", rsa.SecretKey.toPkcs8Der, .{ k, &der }, &kn);
    probe("SecretKey.toPem", rsa.SecretKey.toPem, .{ k, .pkcs8, &der }, &kn);
    probe("SecretKey.toPkcs8Encrypted", toPkcs8Enc, .{ k, &enc_der }, &knp);
    probe("SecretKey.toPemEncrypted", toPemEnc, .{ k, &enc_pem }, &knp);

    enc_der_len = (try k.toPkcs8Encrypted(password, prng.random(), fast_pbes2, &enc_der)).len;
    enc_pem_len = (try k.toPemEncrypted(password, prng.random(), fast_pbes2, &enc_pem)).len;
    probe("SecretKey.fromPemEncrypted", fromPemEnc, .{&loaded}, &knp);
    loaded.deinit();
    probe("SecretKey.fromPemEncryptedLimited", fromPemEncLimited, .{&loaded}, &knp);
    loaded.deinit();
    probe("fromPkcs8Encrypted", fromP8Enc, .{&loaded}, &knp);
    loaded.deinit();
    probe("fromPkcs8EncryptedLimited", fromP8EncLimited, .{&loaded}, &knp);
    loaded.deinit();
    // Plain loaders (no probe called them by name; they route through fromPrimes).
    plain_der_s = try k.toPkcs1Der(&plain_der);
    p8_der_s = try k.toPkcs8Der(&p8_der);
    plain_pem_len = (try k.toPem(.pkcs1, &plain_pem)).len;
    probe("SecretKey.fromDer", fromDerW, .{&loaded}, &kn);
    loaded.deinit();
    probe("fromPkcs8", fromP8W, .{&loaded}, &kn);
    loaded.deinit();
    probe("SecretKey.fromPem", fromPemW, .{&loaded}, &kn);
    loaded.deinit();
    probe("SecretKey.fromPemEncrypted (unencrypted PEM)", fromPemEncPlain, .{&loaded}, &kn);
    loaded.deinit();
    probe("SecretKey.fromPrimesWith", fromPrimesW, .{&loaded}, &kn);
    loaded.deinit();
    try std.testing.expectEqual(@as(usize, 0), failures);
}

test "STACKPROBE: generateWith leaves no residue below its burn" {
    try sp.skipUnlessOptimized();
    // The primes exist only inside the call, so the residue rule is the check here.
    _ = try P.run("generateWith", genWith, .{&kp}, &.{}, .{});
    kp.secret_key.deinit();
}

// ── second pass: the raw primitives, the blinded OAEP decryptors, generate ──

var c256: [256]u8 = undefined;

fn rsadpW(k: *const rsa.SecretKey) ![256]u8 {
    return rsa.rsadp(256, c256, k);
}
fn rsadpCrtBlindedW(k: *const rsa.SecretKey) ![256]u8 {
    return rsa.rsadpCrtBlinded(256, c256, k, .{ .csprng = prng.random() });
}
fn rsasp1W(k: *const rsa.SecretKey) ![256]u8 {
    return rsa.rsasp1(256, c256, k);
}
fn decOaepBlindedW(k: *const rsa.SecretKey, o: []u8) ![]u8 {
    return rsa.decryptOaepBlinded(k, Sha256, .{ .csprng = prng.random() }, &ct, "", o);
}
fn decOaepHBlindedW(k: *const rsa.SecretKey, o: []u8) ![]u8 {
    return rsa.decryptOaepHBlinded(k, Sha256, Sha256, .{ .csprng = prng.random() }, &ct, "", o);
}
fn genW(o: *rsa.KeyPair) !void {
    return rsa.generate(o, prng.random(), 2048, 65537);
}

test "STACKPROBE: rsadp / rsadpCrtBlinded / rsasp1, the blinded OAEP decryptors and generate leave no key on the dead stack" {
    try sp.skipUnlessOptimized();
    try rsa.SecretKey.fromPrimes(&sk, &kat_p, &kat_q, &kat_e);
    defer sk.deinit();
    p_le = kat_p;
    std.mem.reverse(u8, &p_le);
    q_le = kat_q;
    std.mem.reverse(u8, &q_le);
    try sk.d.toBytes(&d_be, .big);
    try sk.dp.toBytes(&dp_be, .big);
    try sk.dq.toBytes(&dq_be, .big);
    try sk.qinv.toBytes(&qinv_be, .big);
    const kn = keyNeedles();
    const k: *const rsa.SecretKey = &sk;
    const pk = try rsa.PublicKey.fromBytes(&kat_n, &kat_e);
    // A value below n: the modulus with its top byte cleared.
    c256 = kat_n;
    c256[0] = 0;
    failures = 0;

    // By-value results land in the probe's call frame by shape: key needles only.
    probe("rsadp", rsadpW, .{k}, &kn);
    probe("rsadpCrtBlinded", rsadpCrtBlindedW, .{k}, &kn);
    probe("rsasp1", rsasp1W, .{k}, &kn);
    ct = (try rsa.encryptOaep(pk, Sha256, prng.random(), "secret plaintext", "", &out))[0..256].*;
    probe("decryptOaepBlinded", decOaepBlindedW, .{ k, @as([]u8, &out) }, &(kn ++ [_][]const u8{out[0..16]}));
    probe("decryptOaepHBlinded", decOaepHBlindedW, .{ k, @as([]u8, &out) }, &(kn ++ [_][]const u8{out[0..16]}));
    try std.testing.expectEqual(@as(usize, 0), failures);
    _ = try P.run("generate", genW, .{&kp}, &.{}, .{});
    kp.secret_key.deinit();
}

// SPDX-License-Identifier: MIT

//! Dead-stack probe for `kex`'s entry points (`testkit.stackprobe`): residue
//! below each per-group burn, and the ephemeral secret / shared secret as
//! needles in any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime
//! skip, so the body is type-checked in every mode). `keyschedule` and
//! `certverify.sign` are probed by `dtls`'s `stackprobe_test.zig` through its
//! shim and re-export.

const std = @import("std");
const kex = @import("kex.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 384 * 1024 }); // must exceed kex_mlkem1024_burn (256 KiB) plus the burn top

var csprng: std.Random.DefaultCsprng = undefined;
var client: kex.KeyPair = undefined;
var ex: kex.ServerExchange = undefined;
var shared: kex.SharedSecret = undefined;

fn probeGroup(comptime label: []const u8, group: u16) !void {
    csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5c)));
    const rnd = csprng.random();
    // Only the group's own prefix of `secret` is written (the curves use 32
    // or 48 of its 96 bytes); the rest must not become a needle.
    const n = kex.scalarLen(group);

    _ = try P.run(label ++ " generate", kex.generate, .{ group, rnd, &client }, &[_][]const u8{client.secret[0..n]}, .{});
    _ = try P.run(label ++ " serverExchange", kex.serverExchange, .{ group, client.public[0..client.public_len], rnd, &ex }, &[_][]const u8{ex.shared.slice()}, .{});
    _ = try P.run(label ++ " sharedSecret", kex.sharedSecret, .{ group, client.secret[0..n], ex.public[0..ex.public_len], &shared }, &[_][]const u8{ client.secret[0..n], shared.slice() }, .{});
    if (!std.mem.eql(u8, shared.slice(), ex.shared.slice())) return error.ProbeExchangeDisagrees;
}

test "STACKPROBE: no ephemeral or shared secret residue after any kex entry point" {
    try sp.skipUnlessOptimized();
    try probeGroup("x25519", kex.x25519_group);
    try probeGroup("secp256r1", kex.secp256r1_group);
    try probeGroup("secp384r1", kex.secp384r1_group);
    try probeGroup("x25519mlkem768", kex.x25519_mlkem768_group);
    try probeGroup("mlkem1024", kex.mlkem1024_group);
}

// ── certverify: P-521 and ML-DSA (their burns are this module's own) ─────

const certverify = @import("certverify.zig");
const mldsa = std.crypto.sign.mldsa;
const EcdsaP521 = @import("p521").EcdsaP521Sha512;

/// Past the deepest `burn.mldsa_verify_burn` (448 KiB) and the burn's own frame.
const PSig = sp.Probe(.{ .window = 640 * 1024 });

var sig_buf: [certverify.max_signature_len]u8 = undefined;
var sig_len: usize = 0;
const probe_th: [48]u8 = @splat(0x6b);

fn signInto(scheme: certverify.SignatureScheme, sk: certverify.SecretKey) !void {
    var rnd = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x17)));
    sig_len = (try certverify.sign(scheme, sk, .server, &probe_th, rnd.random(), &sig_buf)).len;
}

fn verifyIt(scheme: certverify.SignatureScheme, pk: certverify.PublicKey) !void {
    try certverify.verify(scheme, pk, .server, &probe_th, sig_buf[0..sig_len]);
}

fn probeMlDsa(comptime label: []const u8, comptime M: type, comptime scheme: certverify.SignatureScheme) !void {
    const kp = try std.heap.page_allocator.create(M.KeyPair); // global-alloc-ok: probe fixture, freed below
    defer std.heap.page_allocator.destroy(kp); // global-alloc-ok: the fixture above
    kp.* = try M.KeyPair.generateDeterministic(@splat(0x3d));
    const sk = @unionInit(certverify.SecretKey, @tagName(scheme), &kp.secret_key);
    _ = try PSig.run(label ++ " sign", signInto, .{ scheme, sk }, &[_][]const u8{&kp.secret_key.key}, .{});
    const pk_bytes = kp.public_key.toBytes();
    _ = try PSig.run(label ++ " verify", verifyIt, .{ scheme, @unionInit(certverify.PublicKey, @tagName(scheme), &pk_bytes) }, &[_][]const u8{&kp.secret_key.key}, .{});
}

test "STACKPROBE: no key residue after certverify sign/verify, P-521 and ML-DSA" {
    try sp.skipUnlessOptimized();
    const sk = try EcdsaP521.SecretKey.fromBytes(@splat(0x11));
    _ = try PSig.run("p521 sign", signInto, .{ .ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = &sk } }, &[_][]const u8{&sk.bytes}, .{});
    try probeMlDsa("mldsa44", mldsa.MLDSA44, .mldsa44);
    try probeMlDsa("mldsa65", mldsa.MLDSA65, .mldsa65);
    try probeMlDsa("mldsa87", mldsa.MLDSA87, .mldsa87);
}

// ── keyschedule: the exporter (its own burned entry point, not `dtls`'s) ──

const ks = @import("keyschedule.zig").tls13;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Hkdf384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

const PKs = sp.Probe(.{ .window = 64 * 1024 });

var exporter_secret: [48]u8 = @splat(0x2f);
var exported: [100]u8 = undefined;

fn exportIt() void {
    ks.exportKeyingMaterial(Sha384, Hkdf384, &exported, &exporter_secret, "EXPERIMENTAL-probe", "ctx");
}

test "STACKPROBE: no exporter secret residue after exportKeyingMaterial" {
    try sp.skipUnlessOptimized();
    // The label's own secret, Derive-Secret(exporter_master_secret, label,
    // ""), lives only inside the call.
    var empty_hash: [48]u8 = undefined;
    Sha384.hash("", &empty_hash, .{});
    var inner: [48]u8 = undefined;
    ks.deriveSecret(Hkdf384, &inner, &exporter_secret, "EXPERIMENTAL-probe", &empty_hash);
    _ = try PKs.run("exportKeyingMaterial", exportIt, .{}, &[_][]const u8{ &exporter_secret, &inner }, .{});
}

// ── certverify: ECDSA P-256 / P-384 (`burn.ecdsa_burn`) ──────────────────

const Ecdsa = std.crypto.sign.ecdsa;

test "STACKPROBE: no key residue after certverify sign, ECDSA P-256 and P-384" {
    try sp.skipUnlessOptimized();
    const sk256 = try Ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(@splat(0x21));
    _ = try PSig.run("p256 sign", signInto, .{ .ecdsa_secp256r1_sha256, .{ .ecdsa_p256 = &sk256 } }, &[_][]const u8{&sk256.bytes}, .{});
    const sk384 = try Ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(@splat(0x23));
    _ = try PSig.run("p384 sign", signInto, .{ .ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = &sk384 } }, &[_][]const u8{&sk384.bytes}, .{});
}

// ── keyschedule: the steps a handshake runs (`burn.ks_burn`) ──────────────

var ks_secret: [48]u8 = @splat(0x4d);
var ks_out: [3][48]u8 = undefined;
var ks_key: [32]u8 = undefined;
var ks_iv: [12]u8 = undefined;
const ks_th: [48]u8 = @splat(0x15);
const ks_dhe: [32]u8 = @splat(0x52);

fn ksHandshakeTraffic() void {
    ks.deriveHandshakeTrafficSecrets(Hkdf384, &ks_out[0], &ks_out[1], &ks_secret, &ks_th);
}
fn ksApplication() void {
    ks.deriveApplicationSecrets(Hkdf384, &ks_out[0], &ks_out[1], &ks_out[2], &ks_secret, &ks_th);
}
fn ksKeyIv() void {
    ks.deriveTrafficKeyIv(Hkdf384, 32, 12, &ks_key, &ks_iv, &ks_secret);
}
fn ksNoPsk() void {
    ks.deriveHandshakeSecretNoPsk(Hkdf384, &ks_out[0], &ks_dhe);
}
fn ksMaster() void {
    ks.deriveMasterSecret(Hkdf384, &ks_out[0], &ks_secret, @import("keyschedule.zig").emptyTranscriptHash(Sha384));
}
fn ksFinished() void {
    @import("keyschedule.zig").computeFinishedVerifyData(std.crypto.auth.hmac.sha2.HmacSha384, &ks_out[0], &ks_secret, &ks_th);
}

test "STACKPROBE: no secret residue after the keyschedule steps of a handshake" {
    try sp.skipUnlessOptimized();
    const outs = [_][]const u8{ &ks_secret, &ks_out[0], &ks_out[1], &ks_out[2] };
    _ = try PKs.run("deriveHandshakeTrafficSecrets", ksHandshakeTraffic, .{}, &outs, .{});
    _ = try PKs.run("deriveApplicationSecrets", ksApplication, .{}, &outs, .{});
    _ = try PKs.run("deriveTrafficKeyIv", ksKeyIv, .{}, &[_][]const u8{ &ks_secret, &ks_key, &ks_iv }, .{});
    _ = try PKs.run("deriveHandshakeSecretNoPsk", ksNoPsk, .{}, &[_][]const u8{ &ks_dhe, &ks_out[0] }, .{});
    _ = try PKs.run("deriveMasterSecret", ksMaster, .{}, &outs, .{});
    _ = try PKs.run("computeFinishedVerifyData", ksFinished, .{}, &outs, .{});
}

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

    // The expanded-key entry points: the expanded decapsulation key itself
    // (~7.8 / ~12.4 KB of secret) is a needle too, wherever a copy of it lands.
    var exp: kex.Expanded = .none;
    defer exp.wipe();
    _ = try P.run(label ++ " generateExpanded", kex.generateExpanded, .{ group, rnd, &client, &exp }, &[_][]const u8{ client.secret[0..n], expandedBytes(&exp) }, .{});
    _ = try P.run(label ++ " serverExchange(2)", kex.serverExchange, .{ group, client.public[0..client.public_len], rnd, &ex }, &[_][]const u8{ex.shared.slice()}, .{});
    _ = try P.run(label ++ " sharedSecretExpanded", kex.sharedSecretExpanded, .{ group, client.secret[0..n], &exp, ex.public[0..ex.public_len], &shared }, &[_][]const u8{ client.secret[0..n], shared.slice(), expandedBytes(&exp) }, .{});
    if (!std.mem.eql(u8, shared.slice(), ex.shared.slice())) return error.ProbeExchangeDisagrees;
    if (exp == .none) return; // classical group: `expand` is a no-op, nothing to burn
    var exp2: kex.Expanded = .none;
    defer exp2.wipe();
    _ = try P.run(label ++ " expand", kex.expand, .{ group, client.secret[0..n], &exp2 }, &[_][]const u8{ client.secret[0..n], expandedBytes(&exp) }, .{});
}

/// The bytes of the active ML-KEM secret key (empty for `.none`), the needle.
fn expandedBytes(e: *const kex.Expanded) []const u8 {
    return switch (e.*) {
        .none => &.{},
        .mlkem512 => |*sk| std.mem.asBytes(sk),
        .mlkem768 => |*sk| std.mem.asBytes(sk),
        .mlkem1024 => |*sk| std.mem.asBytes(sk),
    };
}

test "STACKPROBE: no ephemeral or shared secret residue after any kex entry point" {
    try sp.skipUnlessOptimized();
    try probeGroup("x25519", kex.x25519_group);
    try probeGroup("secp256r1", kex.secp256r1_group);
    try probeGroup("secp384r1", kex.secp384r1_group);
    try probeGroup("secp521r1", kex.secp521r1_group);
    try probeGroup("mlkem512", kex.mlkem512_group);
    try probeGroup("mlkem768", kex.mlkem768_group);
    try probeGroup("x25519mlkem768", kex.x25519_mlkem768_group);
    try probeGroup("mlkem1024", kex.mlkem1024_group);
    try probeGroup("secp256r1mlkem768", kex.secp256r1_mlkem768_group);
    try probeGroup("secp384r1mlkem1024", kex.secp384r1_mlkem1024_group);
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

/// A non-uniform `n`-byte pattern: a uniform secret is invisible to the needle
/// windows (the probe warns), so every secret below is built with this.
fn pattern(comptime n: usize, comptime seed: u8) [n]u8 {
    var b: [n]u8 = undefined;
    for (&b, 0..) |*x, i| x.* = @truncate(i *% 37 +% seed);
    return b;
}

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
    const sk = try EcdsaP521.SecretKey.fromBytes(pattern(66, 0x11));
    _ = try PSig.run("p521 sign", signInto, .{ .ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = &sk } }, &[_][]const u8{&sk.bytes}, .{});
    try probeMlDsa("mldsa44", mldsa.MLDSA44, .mldsa44);
    try probeMlDsa("mldsa65", mldsa.MLDSA65, .mldsa65);
    try probeMlDsa("mldsa87", mldsa.MLDSA87, .mldsa87);
}

// ── certverify: Ed25519 (`burn.ed25519_burn`) ────────────────────────────

var ed_signer: certverify.Ed25519Signer = undefined;

fn edSignerSign() !void {
    sig_len = (try ed_signer.sign(.server, &probe_th, null, &sig_buf)).len;
}

test "STACKPROBE: no key residue after certverify Ed25519 sign (per-call key and prepared signer)" {
    try sp.skipUnlessOptimized();
    const Sha512 = std.crypto.hash.sha2.Sha512;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11); // non-uniform: a uniform seed is invisible to the needle windows
    const sk = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var h: [64]u8 = undefined;
    Sha512.hash(&sk.secret_key.seed(), &h, .{});
    var a: [32]u8 = h[0..32].*;
    std.crypto.ecc.Edwards25519.scalar.clamp(&a);
    const needles = &[_][]const u8{ &sk.secret_key.seed(), &a, h[32..64] };
    _ = try PSig.run("ed25519 sign", signInto, .{ .ed25519, .{ .ed25519 = &sk.secret_key } }, needles, .{});
    ed_signer = try certverify.Ed25519Signer.init(&sk.secret_key);
    _ = try PSig.run("ed25519 prepared sign", edSignerSign, .{}, needles, .{});
}

// ── keyschedule: the exporter (its own burned entry point, not `dtls`'s) ──

const ks = @import("keyschedule.zig").tls13;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Hkdf384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

const PKs = sp.Probe(.{ .window = 64 * 1024 });

var exporter_secret: [48]u8 = pattern(48, 0x2f);
var exported: [100]u8 = undefined;

fn exportIt() ks.ExportError!void {
    try ks.exportKeyingMaterial(Sha384, Hkdf384, &exported, &exporter_secret, "EXPERIMENTAL-probe", "ctx");
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
    const sk256 = try Ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(pattern(32, 0x21));
    _ = try PSig.run("p256 sign", signInto, .{ .ecdsa_secp256r1_sha256, .{ .ecdsa_p256 = &sk256 } }, &[_][]const u8{&sk256.bytes}, .{});
    const sk384 = try Ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(pattern(48, 0x23));
    _ = try PSig.run("p384 sign", signInto, .{ .ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = &sk384 } }, &[_][]const u8{&sk384.bytes}, .{});
}

// ── keyschedule: the steps a handshake runs (`burn.ks_burn`) ──────────────

var ks_secret: [48]u8 = pattern(48, 0x4d);
var ks_out: [3][48]u8 = undefined;
var ks_key: [32]u8 = undefined;
var ks_iv: [12]u8 = undefined;
const ks_th: [48]u8 = @splat(0x15);
const ks_dhe: [32]u8 = pattern(32, 0x52);

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
    // Only probe-able secrets: an output still zero at the call (and the
    // 12-byte IV, shorter than a needle window) would make the probe warn.
    const outs2 = [_][]const u8{ &ks_secret, &ks_out[0], &ks_out[1] };
    const outs = [_][]const u8{ &ks_secret, &ks_out[0], &ks_out[1], &ks_out[2] };
    _ = try PKs.run("deriveHandshakeTrafficSecrets", ksHandshakeTraffic, .{}, &outs2, .{});
    _ = try PKs.run("deriveApplicationSecrets", ksApplication, .{}, &outs, .{});
    _ = try PKs.run("deriveTrafficKeyIv", ksKeyIv, .{}, &[_][]const u8{ &ks_secret, &ks_key }, .{});
    _ = try PKs.run("deriveHandshakeSecretNoPsk", ksNoPsk, .{}, &[_][]const u8{ &ks_dhe, &ks_out[0] }, .{});
    _ = try PKs.run("deriveMasterSecret", ksMaster, .{}, &outs, .{});
    _ = try PKs.run("computeFinishedVerifyData", ksFinished, .{}, &outs, .{});
}

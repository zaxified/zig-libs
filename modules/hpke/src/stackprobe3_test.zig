// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`, residue rule + input/output needles)
//! for the secret-touching entry points `stackprobe_test.zig` and
//! `stackprobe2_test.zig` never call (whole-module mutation run 2026-11-25: a
//! skipped burn or wipe at each of these survived): `keyPairFromSecret` of
//! every DHKEM, the DHKEM(P-521) entry points, DHKEM(P-384) auth mode, the
//! entropy-drawing wrappers (`encap`, `generateKeyPair`, `setup*S`, `seal*`,
//! the pq / hybrid `generateKeyPair` and `encap`, `agile.sealBase` /
//! `openBase`), `keySchedule` itself and `Context.open`.
//!
//! The wrappers that draw their ephemeral from an `std.Io` run on a test
//! double of it (`entropy.fill` accepts one that copies the threaded vtable
//! and swaps `randomSecure`): its stream is a fixed SHA-512 expansion, the same
//! on every call, so the ephemeral secret the wrapper holds in its own frame
//! (neither an input nor an output) is known to the probe and is a needle.
//! ReleaseFast/ReleaseSmall only.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const suite = @import("suite.zig");
const schedule = @import("schedule.zig");
const aesgcm = @import("aesgcm");
const sp = @import("testkit").stackprobe;

const Pr = sp.Probe(.{});

const X = root.X25519Kem;
const X4 = root.X448Kem;
const P256 = root.P256Kem;
const Q = root.P384Kem;
const R = root.P521Kem;
const Aes = aesgcm.Aes128Gcm;
const info = "hpke probe3 info";

// ── the entropy double ──────────────────────────────────────────────────────

fn detFill(buf: []u8) void {
    var off: usize = 0;
    var ctr: u8 = 0;
    while (off < buf.len) : (ctr += 1) {
        var h: [64]u8 = undefined;
        var s = std.crypto.hash.sha2.Sha512.init(.{});
        s.update("hpke stackprobe3 rng");
        s.update(&[1]u8{ctr});
        s.final(&h);
        const n = @min(h.len, buf.len - off);
        @memcpy(buf[off..][0..n], h[0..n]);
        off += n;
    }
}

fn detRandomSecure(_: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
    detFill(buf);
}

var det_vtable: std.Io.VTable = undefined;
var det_io: std.Io = undefined;

fn setupIo(threaded: *std.Io.Threaded) void {
    const base = threaded.io();
    det_vtable = base.vtable.*;
    det_vtable.randomSecure = detRandomSecure;
    det_io = .{ .userdata = base.userdata, .vtable = &det_vtable };
}

/// `DH(sk, pk)` of a DHKEM, the bytes `ExtractAndExpand` takes (the x
/// coordinate for the NIST curves, the u coordinate for X25519 / X448).
fn dhOf(comptime K: type, sk: *const [K.Nsk]u8, pk: *const K.PublicKey) [K.Nsk]u8 {
    var out: [K.Nsk]u8 = undefined;
    if (K == X) {
        out = std.crypto.dh.X25519.scalarmult(sk.*, pk.*) catch unreachable;
    } else if (K == X4) {
        @import("ed448").x448.scalarmult(&out, sk, pk.*) catch unreachable;
    } else if (K == R) {
        @import("p521").ecdhInto(&out, sk, pk) catch unreachable;
    } else {
        const Curve = if (K == P256) @import("p256").P256 else @import("p384").P384;
        const p = (Curve.fromSec1(pk) catch unreachable).mul(sk.*, .big) catch unreachable;
        out = p.affineCoordinates().x.toBytes(.big);
    }
    return out;
}

// ── one DHKEM ───────────────────────────────────────────────────────────────

fn probeKem(comptime K: type, comptime label: []const u8) !void {
    var ikm: [K.Nsk]u8 = undefined;
    detFill(&ikm);
    var eph: K.KeyPair = undefined;
    K.deriveKeyPair(&eph, &ikm);
    var r: K.KeyPair = undefined;
    K.deriveKeyPair(&r, "recipient ikm");
    var s: K.KeyPair = undefined;
    K.deriveKeyPair(&s, "sender ikm");
    var kp: K.KeyPair = undefined;
    var enc: K.Encapped = undefined;
    var ss: [K.Nsecret]u8 = undefined;
    const dh_e = dhOf(K, &eph.secret_key, &r.public_key); // DH(skE, pkR) = DH(skR, pkE)
    const dh_s = dhOf(K, &s.secret_key, &r.public_key); // DH(skS, pkR) = DH(skR, pkS)

    _ = try Pr.run(label ++ " keyPairFromSecret", K.keyPairFromSecret, .{ &kp, &r.secret_key }, &.{ &r.secret_key, &kp.secret_key }, .{});
    _ = try Pr.run(label ++ " deriveKeyPair", K.deriveKeyPair, .{ &kp, &ikm }, &.{ &ikm, &kp.secret_key }, .{});
    _ = try Pr.run(label ++ " generateKeyPair(io)", K.generateKeyPair, .{ &kp, det_io }, &.{ &ikm, &kp.secret_key }, .{});
    _ = try Pr.run(label ++ " encap(io)", K.encap, .{ &enc, r.public_key, det_io }, &.{ &ikm, &eph.secret_key, &dh_e, &enc.shared_secret }, .{});
    _ = try Pr.run(label ++ " encapDeterministic", K.encapDeterministic, .{ &enc, r.public_key, &eph }, &.{ &eph.secret_key, &dh_e, &enc.shared_secret }, .{});
    _ = try Pr.run(label ++ " decap", K.decap, .{ &ss, eph.public_key, &r }, &.{ &r.secret_key, &dh_e, &ss }, .{});
    _ = try Pr.run(label ++ " authEncapDeterministic", K.authEncapDeterministic, .{ &enc, r.public_key, &s, &eph }, &.{ &s.secret_key, &eph.secret_key, &dh_e, &dh_s, &enc.shared_secret }, .{});
    _ = try Pr.run(label ++ " authDecap", K.authDecap, .{ &ss, eph.public_key, &r, s.public_key }, &.{ &r.secret_key, &dh_e, &dh_s, &ss }, .{});
}

test "mutation 2026-11-25: STACKPROBE: every DHKEM's keyPairFromSecret, encap(io), generateKeyPair(io) and the P-521 / P-384 auth entry points leave nothing on the dead stack" {
    try sp.skipUnlessOptimized();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    setupIo(&threaded);
    try probeKem(X, "X25519");
    try probeKem(X4, "X448");
    try probeKem(P256, "P-256");
    try probeKem(Q, "P-384");
    try probeKem(R, "P-521");
}

// ── the key schedule and the context ────────────────────────────────────────

const AesCtx = root.Context(Aes, 32);

fn ksW(out: *AesCtx, sid: *const [10]u8, ss: *const [32]u8) !void {
    return root.keySchedule(Aes, 32, out, .base, sid, ss, info, "", "");
}

fn openW(ctx: *AesCtx, ct: *const [10 + 16]u8, out: *[10]u8) !void {
    ctx.seq = 0;
    return ctx.open("aad", ct, out);
}

fn sealW(ctx: *AesCtx, out: *[10 + 16]u8) !void {
    ctx.seq = 0;
    return ctx.seal("aad", "0123456789", out);
}

test "mutation 2026-11-25: STACKPROBE: keySchedule, Context.seal and Context.open leave no key on the dead stack" {
    try sp.skipUnlessOptimized();
    var ss: [32]u8 = undefined;
    detFill(&ss);
    const sid = suite.suiteId(X.kem_id, 1, 1);
    var ctx: AesCtx = undefined;
    _ = try Pr.run("keySchedule (AES-128-GCM)", ksW, .{ &ctx, &sid, &ss }, &.{ &ss, &ctx.key, &ctx.exporter_secret }, .{});
    var ct: [10 + 16]u8 = undefined;
    ctx.seq = 0;
    try ctx.seal("aad", "0123456789", &ct);
    var sealed_out: [10 + 16]u8 = undefined;
    _ = try Pr.run("Context.seal (AES-128-GCM)", sealW, .{ &ctx, &sealed_out }, &.{ &ctx.key, &ctx.exporter_secret }, .{});
    var back: [10]u8 = undefined;
    _ = try Pr.run("Context.open (AES-128-GCM)", openW, .{ &ctx, &ct, &back }, &.{ &ctx.key, &ctx.exporter_secret }, .{});
}

// ── the schedule's entropy-drawing wrappers (X25519, AES-128-GCM) ───────────

const Setup = schedule.Setup(X, Aes, 32);
const psk = "0123456789abcdef0123456789abcdef";

fn setupBaseSW(out: *Setup, pkR: X.PublicKey, io: std.Io) !void {
    return schedule.setupBaseS(X, Aes, 32, out, pkR, io, info);
}
fn setupPskSW(out: *Setup, pkR: X.PublicKey, io: std.Io) !void {
    return schedule.setupPskS(X, Aes, 32, out, pkR, io, info, psk, "id");
}
fn setupAuthSW(out: *Setup, pkR: X.PublicKey, skS: *const X.KeyPair, io: std.Io) !void {
    return schedule.setupAuthS(X, Aes, 32, out, pkR, skS, io, info);
}
fn setupAuthPskSW(out: *Setup, pkR: X.PublicKey, skS: *const X.KeyPair, io: std.Io) !void {
    return schedule.setupAuthPskS(X, Aes, 32, out, pkR, skS, io, info, psk, "id");
}
fn sealBaseW(pkR: X.PublicKey, io: std.Io, out: *[10 + 16]u8) !void {
    _ = try schedule.sealBase(X, Aes, 32, pkR, io, info, "aad", "0123456789", out);
}
fn sealPskW(pkR: X.PublicKey, io: std.Io, out: *[10 + 16]u8) !void {
    _ = try schedule.sealPsk(X, Aes, 32, pkR, io, info, psk, "id", "aad", "0123456789", out);
}
fn sealAuthW(pkR: X.PublicKey, skS: *const X.KeyPair, io: std.Io, out: *[10 + 16]u8) !void {
    _ = try schedule.sealAuth(X, Aes, 32, pkR, skS, io, info, "aad", "0123456789", out);
}
fn sealAuthPskW(pkR: X.PublicKey, skS: *const X.KeyPair, io: std.Io, out: *[10 + 16]u8) !void {
    _ = try schedule.sealAuthPsk(X, Aes, 32, pkR, skS, io, info, psk, "id", "aad", "0123456789", out);
}

test "mutation 2026-11-25: STACKPROBE: the setup*S and seal* wrappers that draw their ephemeral leave nothing on the dead stack" {
    try sp.skipUnlessOptimized();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    setupIo(&threaded);
    var ikm: [X.Nsk]u8 = undefined;
    detFill(&ikm);
    var eph: X.KeyPair = undefined;
    X.deriveKeyPair(&eph, &ikm);
    var r: X.KeyPair = undefined;
    X.deriveKeyPair(&r, "recipient ikm");
    var s: X.KeyPair = undefined;
    X.deriveKeyPair(&s, "sender ikm");
    var ss: [X.Nsecret]u8 = undefined;
    try X.decap(&ss, eph.public_key, &r);
    var ss_auth: [X.Nsecret]u8 = undefined;
    try X.authDecap(&ss_auth, eph.public_key, &r, s.public_key);
    var st: Setup = undefined;
    var ct: [10 + 16]u8 = undefined;

    _ = try Pr.run("setupBaseS(io)", setupBaseSW, .{ &st, r.public_key, det_io }, &.{ &ikm, &eph.secret_key, &ss, &st.context.key, &st.context.exporter_secret }, .{});
    _ = try Pr.run("setupPskS(io)", setupPskSW, .{ &st, r.public_key, det_io }, &.{ &ikm, &eph.secret_key, &ss, &st.context.key, &st.context.exporter_secret }, .{});
    _ = try Pr.run("setupAuthS(io)", setupAuthSW, .{ &st, r.public_key, &s, det_io }, &.{ &ikm, &eph.secret_key, &s.secret_key, &ss_auth, &st.context.key, &st.context.exporter_secret }, .{});
    _ = try Pr.run("setupAuthPskS(io)", setupAuthPskSW, .{ &st, r.public_key, &s, det_io }, &.{ &ikm, &eph.secret_key, &s.secret_key, &ss_auth, &st.context.key, &st.context.exporter_secret }, .{});
    _ = try Pr.run("sealBase(io)", sealBaseW, .{ r.public_key, det_io, &ct }, &.{ &ikm, &eph.secret_key, &ss }, .{});
    _ = try Pr.run("sealPsk(io)", sealPskW, .{ r.public_key, det_io, &ct }, &.{ &ikm, &eph.secret_key, &ss }, .{});
    _ = try Pr.run("sealAuth(io)", sealAuthW, .{ r.public_key, &s, det_io, &ct }, &.{ &ikm, &eph.secret_key, &s.secret_key, &ss_auth }, .{});
    _ = try Pr.run("sealAuthPsk(io)", sealAuthPskW, .{ r.public_key, &s, det_io, &ct }, &.{ &ikm, &eph.secret_key, &s.secret_key, &ss_auth }, .{});
}

// ── the pq / hybrid KEMs' entropy-drawing wrappers ──────────────────────────

fn probePq(comptime K: type, comptime label: []const u8) !void {
    var seed: [K.Nsk]u8 = undefined;
    detFill(&seed);
    var eph: K.Ephemeral = undefined;
    detFill(&eph);
    var kp: K.KeyPair = undefined;
    K.fromSeed(&kp, &@as([K.Nsk]u8, @splat(0x5a)));
    var kp2: K.KeyPair = undefined;
    var enc: K.Encapped = undefined;
    _ = try Pr.run(label ++ " generateKeyPair(io)", K.generateKeyPair, .{ &kp2, det_io }, &.{ &seed, &kp2.seed }, .{});
    _ = try Pr.run(label ++ " encap(io)", K.encap, .{ &enc, kp.public_key, det_io }, &.{ &eph, &enc.shared_secret }, .{});
    _ = try Pr.run(label ++ " encapDeterministic", K.encapDeterministic, .{ &enc, kp.public_key, &eph }, &.{ &eph, &enc.shared_secret }, .{});
}

test "mutation 2026-11-25: STACKPROBE: the pq KEMs' generateKeyPair(io), encap(io) and encapDeterministic leave nothing on the dead stack" {
    try sp.skipUnlessOptimized();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    setupIo(&threaded);
    try probePq(root.MlKem768Kem, "ML-KEM-768");
    try probePq(root.MlKem1024Kem, "ML-KEM-1024");
    try probePq(root.MlKem768X25519Kem, "X-Wing");
    try probePq(root.MlKem768P256Kem, "MLKEM768-P256");
    try probePq(root.MlKem1024P384Kem, "MLKEM1024-P384");
}

// ── agile single-shot ───────────────────────────────────────────────────────

fn agSeal(s: root.agile.Suite, pk: *const root.agile.PublicKey, io: std.Io, out: *[32 + 10 + 16]u8) !void {
    return root.agile.sealBase(s, pk, io, info, "aad", "0123456789", out);
}
fn agOpen(s: root.agile.Suite, sk: *const root.agile.KeyPair, sealed: *const [32 + 10 + 16]u8, out: *[10]u8) !void {
    return root.agile.openBase(s, sk, info, "aad", sealed, out);
}

test "mutation 2026-11-25: STACKPROBE: agile sealBase / openBase leave nothing on the dead stack" {
    try sp.skipUnlessOptimized();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    setupIo(&threaded);
    const s = try root.agile.Suite.init(X.kem_id, 1, 1);
    var ikm: [X.Nsk]u8 = undefined;
    detFill(&ikm);
    var eph: X.KeyPair = undefined;
    X.deriveKeyPair(&eph, &ikm);
    var kp: root.agile.KeyPair = undefined;
    try root.agile.deriveKeyPair(&kp, .dhkem_x25519_hkdf_sha256, "agile recipient");
    const pk = kp.publicKey();
    var ss: [X.Nsecret]u8 = undefined;
    try X.decap(&ss, eph.public_key, &kp.dhkem_x25519_hkdf_sha256);
    // The context the single-shot call builds in its own frame: key and exporter secret.
    var ref: root.agile.Setup = undefined;
    try root.agile.setupSDeterministic(&ref, s, .base, &pk, null, &ikm, info, "", "");
    const ctx_key = ref.context.msg.aes128gcm.key;
    const ctx_exp = ref.context.exporter_secret[0..32].*;
    const dh = dhOf(X, &eph.secret_key, &kp.dhkem_x25519_hkdf_sha256.public_key);
    var sealed: [32 + 10 + 16]u8 = undefined;
    _ = try Pr.run("agile sealBase", agSeal, .{ s, &pk, det_io, &sealed }, &.{ &ikm, &eph.secret_key, &dh, &ss, &ctx_key, &ctx_exp }, .{});
    var back: [10]u8 = undefined;
    _ = try Pr.run("agile openBase", agOpen, .{ s, &kp, &sealed, &back }, &.{ &kp.dhkem_x25519_hkdf_sha256.secret_key, &dh, &ss, &ctx_key, &ctx_exp }, .{});
}

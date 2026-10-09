// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for every secret-touching entry
//! point: the resumption-PSK chain (`psk.zig`), the 0-RTT early-data keys
//! (`earlydata.zig`), the STEK ticket seal/open (`stek.zig`) and the server
//! selection loop (`select.selectPsk`). ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in
//! every mode). Generic entry points go through non-generic wrappers that
//! fix the suite (SHA-256); the wrappers hold no secret by value.

const std = @import("std");
const sp = @import("testkit").stackprobe;
const psk = @import("psk.zig");
const earlydata = @import("earlydata.zig");
const stek = @import("stek.zig");
const select = @import("select.zig");
const replay = @import("replay.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Ctx = earlydata.EarlyDataContext(Hkdf, 16);
const Ring = stek.StekRing(3);
const Sel = select.Selection(32);

const P = sp.Probe(.{ .window = 64 * 1024 });

var rms: [32]u8 = undefined;
var secret: [32]u8 = undefined;
var out: [32]u8 = undefined;
var out_psk: [32]u8 = undefined;
var th: [32]u8 = undefined;
var eh: [32]u8 = undefined;
var stek_key: [32]u8 = undefined;
var ctx: Ctx = undefined;
var key_iv: earlydata.TrafficKeyIv(16) = undefined;
var ring: Ring = undefined;
var sel: Sel = undefined;
var blob: [160]u8 = undefined;
var opened: [160]u8 = undefined;
var scratch: [160]u8 = undefined;
var plain: [64]u8 = undefined;
var ticket_len: usize = 0;
var binder: [32]u8 = undefined;
var nonce: [2]u8 = .{ 0, 1 };

fn pskWrap(o: *[32]u8, r: *const [32]u8) void {
    psk.derivePsk(Hkdf, 32, o, r, &nonce);
}
fn earlyWrap(o: *[32]u8, p: []const u8) void {
    psk.earlySecret(Hkdf, o, p);
}
fn binderKeyWrap(o: *[32]u8, es: *const [32]u8) void {
    psk.binderKey(Hkdf, o, es, &eh);
}
fn computeBinderWrap(o: *[32]u8, bk: *const [32]u8) void {
    psk.computeBinder(Hkdf, Hmac, o, bk, &th);
}
fn verifyBinderWrap(bk: *const [32]u8, b: [32]u8) bool {
    return psk.verifyBinder(Hkdf, Hmac, bk, &th, b);
}
fn cetsWrap(o: *[32]u8, es: *const [32]u8) void {
    earlydata.clientEarlyTrafficSecret(Hkdf, o, es, &th);
}
fn eemsWrap(o: *[32]u8, es: *const [32]u8) void {
    earlydata.earlyExporterMasterSecret(Hkdf, o, es, &th);
}
fn keyIvWrap(o: *earlydata.TrafficKeyIv(16), s: *const [32]u8) void {
    earlydata.earlyTrafficKeyIv(Hkdf, 16, o, s);
}
fn ctxWrap(o: *Ctx, p: []const u8) void {
    Ctx.derive(o, p, &th);
}
fn rotateWrap(r: *Ring, k: *const [32]u8) void {
    r.rotate(1, k, 0);
}
fn sealWrap(r: *const Ring, p: []const u8, n: [12]u8, o: []u8) ![]u8 {
    return r.seal(p, n, o);
}
fn openWrap(r: *const Ring, b: []const u8, o: []u8) ![]u8 {
    return r.open(b, o);
}
fn selectWrap(o: *Sel, r: *const Ring, id: []const select.OfferedIdentity, b: []const [32]u8) !void {
    return select.selectPsk(Hkdf, Hmac, Ring, o, r, id, b, &eh, &th, 5_000, 10_000, null, &scratch);
}

fn fill() void {
    std.crypto.hash.sha2.Sha256.hash("tlsresume probe rms", &rms, .{});
    std.crypto.hash.sha2.Sha256.hash("tlsresume probe secret", &secret, .{});
    std.crypto.hash.sha2.Sha256.hash("tlsresume probe transcript", &th, .{});
    std.crypto.hash.sha2.Sha256.hash("", &eh, .{});
    std.crypto.hash.sha2.Sha256.hash("tlsresume probe stek key", &stek_key, .{});
}

test "STACKPROBE: resumption PSK chain and early-data keys leave no secret residue" {
    try sp.skipUnlessOptimized();
    fill();

    _ = try P.run("derivePsk", pskWrap, .{ &out, &rms }, &.{ &rms, &out }, .{});
    _ = try P.run("earlySecret", earlyWrap, .{ &out, &secret }, &.{ &secret, &out }, .{});
    _ = try P.run("binderKey", binderKeyWrap, .{ &out, &secret }, &.{ &secret, &out }, .{});
    _ = try P.run("computeBinder", computeBinderWrap, .{ &out, &secret }, &.{ &secret, &out }, .{});
    computeBinderWrap(&binder, &secret);
    _ = try P.run("verifyBinder", verifyBinderWrap, .{ &secret, binder }, &.{&secret}, .{});
    _ = try P.run("clientEarlyTrafficSecret", cetsWrap, .{ &out, &secret }, &.{ &secret, &out }, .{});
    _ = try P.run("earlyExporterMasterSecret", eemsWrap, .{ &out, &secret }, &.{ &secret, &out }, .{});
    _ = try P.run("earlyTrafficKeyIv", keyIvWrap, .{ &key_iv, &secret }, &.{ &secret, std.mem.asBytes(&key_iv) }, .{});
    _ = try P.run("EarlyDataContext.derive", ctxWrap, .{ &ctx, &rms }, &.{ &rms, std.mem.asBytes(&ctx) }, .{});
}

test "STACKPROBE: STEK ring and PSK selection leave no key residue" {
    try sp.skipUnlessOptimized();
    fill();

    ring = Ring.init();
    // rotate only stores the key (no crypto): needles only, no burn to look for.
    _ = try P.run("StekRing.rotate", rotateWrap, .{ &ring, &stek_key }, &.{&stek_key}, .{ .burn = false });

    @memset(&plain, 0);
    const state: select.SessionState(32) = .{
        .resumption_master_secret = rms,
        .ticket_nonce = &nonce,
        .issued_at_ms = 0,
        .ticket_age_add = 7,
    };
    const wire = try state.serialize(&plain);
    const n12 = [_]u8{0x01} ** stek.nonce_length;
    _ = try P.run("StekRing.seal", sealWrap, .{ &ring, wire, n12, &blob }, &.{&stek_key}, .{});
    const ticket = try ring.seal(wire, n12, &blob);
    ticket_len = ticket.len;
    _ = try P.run("StekRing.open", openWrap, .{ &ring, ticket, &opened }, &.{ &stek_key, &rms }, .{});

    var client_psk: [32]u8 = undefined;
    var es: [32]u8 = undefined;
    var bk: [32]u8 = undefined;
    psk.derivePsk(Hkdf, 32, &client_psk, &rms, &nonce);
    psk.earlySecret(Hkdf, &es, &client_psk);
    psk.binderKey(Hkdf, &bk, &es, &eh);
    psk.computeBinder(Hkdf, Hmac, &binder, &bk, &th);
    const ids = [_]select.OfferedIdentity{.{ .ticket = ticket, .obfuscated_ticket_age = replay.obfuscateAge(5_000, 7) }};
    const binders = [_][32]u8{binder};
    _ = try P.run("selectPsk", selectWrap, .{ &sel, &ring, &ids, &binders }, &.{ &stek_key, &rms, &client_psk, &bk, std.mem.asBytes(&sel) }, .{});
    try std.testing.expectEqualSlices(u8, &client_psk, &sel.psk);
}

// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the PUBLIC building blocks:
//! `keyschedule.*` and the record-protection / sequence-number helpers of
//! `aead.zig`. The handshake-level sweep lives in `stackprobe_test.zig`
//! (older engine, untouched). ReleaseFast only (`skipUnlessOptimized`, a
//! runtime skip, so the body is type-checked in every mode).
//!
//! Generic entry points are probed through non-generic wrappers that fix the
//! suite (SHA-256 / AES-128-GCM / ChaCha20-Poly1305); the wrappers hold no
//! secret by value.

const std = @import("std");
const sp = @import("testkit").stackprobe;
const keyschedule = @import("keyschedule.zig");
const aead = @import("aead.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const P = sp.Probe(.{ .window = 64 * 1024 });

var secret: [32]u8 = undefined;
var secret2: [32]u8 = undefined;
var psk: [40]u8 = undefined;
var out: [32]u8 = undefined;
var out2: [32]u8 = undefined;
var out16: [16]u8 = undefined;
var out12: [12]u8 = undefined;
var th: [32]u8 = undefined;
var dhe: [32]u8 = undefined;
var key16: [16]u8 = undefined;
var key32: [32]u8 = undefined;
var iv: [12]u8 = undefined;
var seq: [2]u8 = undefined;
var sample: [16]u8 = undefined;
var pt: [200]u8 = undefined;
var ct: [200 + 16]u8 = undefined;
var back: [200]u8 = undefined;

fn fill() void {
    std.crypto.hash.sha2.Sha256.hash("dtls probe secret", &secret, .{});
    std.crypto.hash.sha2.Sha256.hash("dtls probe secret 2", &secret2, .{});
    std.crypto.hash.sha2.Sha256.hash("dtls probe transcript", &th, .{});
    std.crypto.hash.sha2.Sha256.hash("dtls probe dhe", &dhe, .{});
    std.crypto.hash.sha2.Sha256.hash("dtls probe key", &key32, .{});
    @memcpy(&key16, key32[0..16]);
    @memcpy(&iv, secret2[0..12]);
    @memcpy(psk[0..32], &secret2);
    @memcpy(psk[32..], "probepsk");
    @memcpy(&sample, secret[0..16]);
    seq = .{ 0x12, 0x34 };
    @memset(&pt, 0x5a);
}

fn expandWrap(o: *[32]u8, s: *const [32]u8, th_: []const u8) void {
    keyschedule.expandLabel(Hkdf, keyschedule.tls13_prefix, 32, o, s, "derived", th_);
}
fn hkdfWrap(o: *[16]u8, s: *const [32]u8) void {
    keyschedule.hkdfExpandLabel(Hkdf, 16, o, s, "key", "");
}
fn deriveSecretWrap(o: *[32]u8, s: *const [32]u8, th_: []const u8) void {
    keyschedule.deriveSecret(Hkdf, o, s, "c ap traffic", th_);
}
fn earlyWrap(o: *[32]u8, p: []const u8) void {
    keyschedule.earlySecret(Hkdf, o, p);
}
fn binderKeyWrap(o: *[32]u8, es: *const [32]u8, th_: []const u8) void {
    keyschedule.binderKey(Hkdf, o, es, th_);
}
fn binderWrap(o: *[32]u8, bk: *const [32]u8, th_: []const u8) void {
    keyschedule.pskBinder(Hkdf, Hmac, o, bk, th_);
}
fn hsWrap(o: *[32]u8, es: *const [32]u8, th_: []const u8, d: ?[]const u8) void {
    keyschedule.deriveHandshakeSecret(Hkdf, o, es, th_, d);
}
fn hsTrafficWrap(c: *[32]u8, s: *[32]u8, hs: *const [32]u8, th_: []const u8) void {
    keyschedule.deriveHandshakeTrafficSecrets(Hkdf, c, s, hs, th_);
}
fn masterWrap(o: *[32]u8, hs: *const [32]u8, th_: []const u8) void {
    keyschedule.deriveMasterSecret(Hkdf, o, hs, th_);
}
fn apTrafficWrap(c: *[32]u8, s: *[32]u8, ms: *const [32]u8, th_: []const u8) void {
    keyschedule.deriveApplicationTrafficSecrets(Hkdf, c, s, ms, th_);
}
fn finishedKeyWrap(o: *[32]u8, ts: *const [32]u8) void {
    keyschedule.deriveFinishedKey(Hkdf, 32, o, ts);
}
fn verifyDataWrap(o: *[32]u8, fk: *const [32]u8, th_: []const u8) void {
    keyschedule.computeFinishedVerifyData(Hmac, o, fk, th_);
}
fn keyIvWrap(k: *[16]u8, i: *[12]u8, ts: *const [32]u8) void {
    keyschedule.deriveTrafficKeyIv(Hkdf, 16, 12, k, i, ts);
}
fn snKeyWrap(o: *[16]u8, ts: *const [32]u8) void {
    keyschedule.deriveSequenceNumberKey(Hkdf, 16, o, ts);
}

const Gcm = aead.Protection(@import("aesgcm").Aes128Gcm);
const Chacha = aead.Protection(std.crypto.aead.chacha_poly.ChaCha20Poly1305);

fn gcmSeal(k: *const [16]u8, n: [12]u8, p: []const u8, o: []u8) !usize {
    return Gcm.protect(k, n, 2, 7, p, "hdr", o);
}
fn gcmOpen(k: *const [16]u8, n: [12]u8, c: []const u8, o: []u8) !usize {
    return Gcm.unprotect(k, n, 2, 7, c, "hdr", o);
}
fn chachaSeal(k: *const [32]u8, n: [12]u8, p: []const u8, o: []u8) !usize {
    return Chacha.protect(k, n, 2, 7, p, "hdr", o);
}
fn chachaOpen(k: *const [32]u8, n: [12]u8, c: []const u8, o: []u8) !usize {
    return Chacha.unprotect(k, n, 2, 7, c, "hdr", o);
}

test "STACKPROBE: keyschedule building blocks leave no secret residue" {
    try sp.skipUnlessOptimized();
    fill();

    _ = try P.run("expandLabel", expandWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("hkdfExpandLabel", hkdfWrap, .{ &out16, &secret }, &.{ &secret, &out16 }, .{});
    _ = try P.run("deriveSecret", deriveSecretWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("earlySecret", earlyWrap, .{ &out, &psk }, &.{ &psk, &out }, .{});
    _ = try P.run("binderKey", binderKeyWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("pskBinder", binderWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("deriveHandshakeSecret psk_ke", hsWrap, .{ &out, &secret, &th, null }, &.{ &secret, &out }, .{});
    _ = try P.run("deriveHandshakeSecret psk_dhe_ke", hsWrap, .{ &out, &secret, &th, @as(?[]const u8, &dhe) }, &.{ &secret, &dhe, &out }, .{});
    _ = try P.run("deriveHandshakeTrafficSecrets", hsTrafficWrap, .{ &out, &out2, &secret, &th }, &.{ &secret, &out, &out2 }, .{});
    _ = try P.run("deriveMasterSecret", masterWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("deriveApplicationTrafficSecrets", apTrafficWrap, .{ &out, &out2, &secret, &th }, &.{ &secret, &out, &out2 }, .{});
    _ = try P.run("deriveFinishedKey", finishedKeyWrap, .{ &out, &secret }, &.{ &secret, &out }, .{});
    _ = try P.run("computeFinishedVerifyData", verifyDataWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    // `out12` (the 12-byte IV) is shorter than a 16-byte needle window and so
    // cannot be a needle; it is left out of the secrets rather than warned about.
    _ = try P.run("deriveTrafficKeyIv", keyIvWrap, .{ &out16, &out12, &secret }, &.{ &secret, &out16 }, .{});
    _ = try P.run("deriveSequenceNumberKey", snKeyWrap, .{ &out16, &secret }, &.{ &secret, &out16 }, .{});
}

test "STACKPROBE: record protection and sequence-number masks leave no key residue" {
    try sp.skipUnlessOptimized();
    fill();

    _ = try P.run("Protection(Aes128Gcm).protect", gcmSeal, .{ &key16, iv, &pt, &ct }, &.{&key16}, .{});
    const sealed = try gcmSeal(&key16, iv, &pt, &ct);
    _ = try P.run("Protection(Aes128Gcm).unprotect", gcmOpen, .{ &key16, iv, ct[0..sealed], &back }, &.{&key16}, .{});
    _ = try P.run("Protection(ChaCha20Poly1305).protect", chachaSeal, .{ &key32, iv, &pt, &ct }, &.{&key32}, .{});
    const sealed2 = try chachaSeal(&key32, iv, &pt, &ct);
    _ = try P.run("Protection(ChaCha20Poly1305).unprotect", chachaOpen, .{ &key32, iv, ct[0..sealed2], &back }, &.{&key32}, .{});

    _ = try P.run("encryptSequenceNumberAes 128", aead.encryptSequenceNumberAes, .{ @as([]const u8, &key16), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key16}, .{});
    _ = try P.run("encryptSequenceNumberAes 256", aead.encryptSequenceNumberAes, .{ @as([]const u8, &key32), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key32}, .{});
    _ = try P.run("encryptSequenceNumberChaCha20", aead.encryptSequenceNumberChaCha20, .{ @as([]const u8, &key32), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key32}, .{});
    _ = try P.run("decryptSequenceNumberAes", aead.decryptSequenceNumberAes, .{ @as([]const u8, &key16), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key16}, .{});
    _ = try P.run("decryptSequenceNumberChaCha20", aead.decryptSequenceNumberChaCha20, .{ @as([]const u8, &key32), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key32}, .{});
}

const aesgcm = @import("aesgcm");
const record = @import("record.zig");
const record12 = @import("record12.zig");
const Aes128GcmT = aesgcm.Aes128Gcm;
const Aes256GcmT = aesgcm.Aes256Gcm;
var gcm_ctx128: Aes128GcmT.Context = undefined;
var gcm_ctx256: Aes256GcmT.Context = undefined;
var rk128: record12.DirKeys = .{ .bulk = .aes_128_gcm };
var rk256: record12.DirKeys = .{ .bulk = .aes_256_gcm };
var rback: [256]u8 = undefined; // a CID record opens 1 byte (the content type) more than the plaintext
const probe_cid = [_]u8{ 9, 8, 7 };

fn ctxSeal(comptime A: type, c: *const A.Context, n: [12]u8, p: []const u8, o: []u8) !usize {
    return aead.Protection(A).protectCtx(c, n, 2, 7, p, "hdr", o);
}
fn ctxOpen(comptime A: type, c: *const A.Context, n: [12]u8, ct_: []const u8, o: []u8) !usize {
    return aead.Protection(A).unprotectCtx(c, n, 2, 7, ct_, "hdr", o);
}
fn ctxSeal128(c: *const Aes128GcmT.Context, n: [12]u8, p: []const u8, o: []u8) !usize {
    return ctxSeal(Aes128GcmT, c, n, p, o);
}
fn ctxOpen128(c: *const Aes128GcmT.Context, n: [12]u8, ct_: []const u8, o: []u8) !usize {
    return ctxOpen(Aes128GcmT, c, n, ct_, o);
}
fn ctxSeal256(c: *const Aes256GcmT.Context, n: [12]u8, p: []const u8, o: []u8) !usize {
    return ctxSeal(Aes256GcmT, c, n, p, o);
}
fn ctxOpen256(c: *const Aes256GcmT.Context, n: [12]u8, ct_: []const u8, o: []u8) !usize {
    return ctxOpen(Aes256GcmT, c, n, ct_, o);
}
fn r12Seal(k: *const record12.DirKeys, p: []const u8, o: []u8) !usize {
    return (try record12.seal(k, 1, 2, 23, p, o)).len;
}
fn r12Open(k: *const record12.DirKeys, sealed: []const u8, o: []u8) !usize {
    const hdr = try record.decodePlaintext(sealed);
    return (try record12.open(k, hdr, sealed[record.plaintext_header_len..], o)).len;
}
fn r12SealCid(k: *const record12.DirKeys, p: []const u8, o: []u8) !usize {
    return (try record12.sealCid(k, 1, 2, 23, p, &probe_cid, o)).len;
}
fn r12OpenCid(k: *const record12.DirKeys, sealed: []const u8, o: []u8) !usize {
    const ch = try record12.decodeCidHeader(sealed, probe_cid.len);
    const r = try record12.openCid(k, ch, sealed[record12.CidHeader.len(probe_cid.len)..][0..ch.length], o);
    return r.plaintext.len;
}

/// One unprobed pass over every per-epoch-context path with a THROWAWAY key. Measured 2026-11-26: the first
/// `Protection(Aes128Gcm).protectCtx` call of a fresh process leaves 45 B of non-zero, non-paint, no-needle residue
/// a fixed ~76 B below the end of its burn (burn 4 KiB: to 4383 B; burn 5 KiB: to 5407 B), only when this test
/// runs nearly alone (MUT_TESTS=stackprobe2); in the full suite earlier probes have already run the path. A bigger
/// burn does not move it, so it is a first-call effect below the burn frame, not a depth the burn misses. Warming
/// the paths up with another key makes the probed calls independent of the test order.
fn warmUp() !void {
    var wk: [32]u8 = undefined;
    @memset(&wk, 0x3c);
    var c128: Aes128GcmT.Context = undefined;
    var c256: Aes256GcmT.Context = undefined;
    Aes128GcmT.Context.initInto(&c128, wk[0..16]);
    Aes256GcmT.Context.initInto(&c256, &wk);
    var w: [200 + 64]u8 = undefined;
    var b: [200]u8 = undefined;
    const n1 = try ctxSeal128(&c128, iv, &pt, &w);
    _ = try ctxOpen128(&c128, iv, w[0..n1], &b);
    const n2 = try ctxSeal256(&c256, iv, &pt, &w);
    _ = try ctxOpen256(&c256, iv, w[0..n2], &b);
    inline for (.{ record12.Bulk.aes_128_gcm, record12.Bulk.aes_256_gcm }) |bulk| {
        var k: record12.DirKeys = .{ .bulk = bulk };
        k.key = wk;
        k.iv = iv;
        k.prepare();
        const a1 = try r12Seal(&k, &pt, &w);
        _ = try r12Open(&k, w[0..a1], &rback);
        const a2 = try r12SealCid(&k, &pt, &w);
        _ = try r12OpenCid(&k, w[0..a2], &rback);
        k.wipe();
    }
    std.crypto.secureZero(u8, std.mem.asBytes(&c128));
    std.crypto.secureZero(u8, std.mem.asBytes(&c256));
    std.crypto.secureZero(u8, &wk);
}

test "mutation 2026-11-25: STACKPROBE: the per-epoch AES-GCM context entry points (aead protectCtx/unprotectCtx, prepared record12 seal/open/sealCid/openCid) leave no key residue" {
    try sp.skipUnlessOptimized();
    fill();
    try warmUp();
    Aes128GcmT.Context.initInto(&gcm_ctx128, &key16);
    Aes256GcmT.Context.initInto(&gcm_ctx256, &key32);
    _ = try P.run("Protection(Aes128Gcm).protectCtx", ctxSeal128, .{ &gcm_ctx128, iv, &pt, &ct }, &.{&key16}, .{});
    const s128 = try ctxSeal128(&gcm_ctx128, iv, &pt, &ct);
    _ = try P.run("Protection(Aes128Gcm).unprotectCtx", ctxOpen128, .{ &gcm_ctx128, iv, ct[0..s128], &back }, &.{&key16}, .{});
    _ = try P.run("Protection(Aes256Gcm).protectCtx", ctxSeal256, .{ &gcm_ctx256, iv, &pt, &ct }, &.{&key32}, .{});
    const s256 = try ctxSeal256(&gcm_ctx256, iv, &pt, &ct);
    _ = try P.run("Protection(Aes256Gcm).unprotectCtx", ctxOpen256, .{ &gcm_ctx256, iv, ct[0..s256], &back }, &.{&key32}, .{});
    std.crypto.secureZero(u8, std.mem.asBytes(&gcm_ctx128));
    std.crypto.secureZero(u8, std.mem.asBytes(&gcm_ctx256));

    // record12 with prepared keys (the cached schedule on both the plain and the CID records).
    @memcpy(&rk128.key, &key32);
    @memcpy(&rk256.key, &key32);
    rk128.iv = iv;
    rk256.iv = iv;
    rk128.prepare();
    rk256.prepare();
    var wire: [200 + 64]u8 = undefined;
    inline for (.{ .{ "128", &rk128, key32[0..16] }, .{ "256", &rk256, key32[0..32] } }) |c| {
        const k: *const record12.DirKeys = c[1];
        _ = try P.run("record12.seal prepared " ++ c[0], r12Seal, .{ k, &pt, &wire }, &.{c[2]}, .{});
        const n1 = try r12Seal(k, &pt, &wire);
        _ = try P.run("record12.open prepared " ++ c[0], r12Open, .{ k, wire[0..n1], &rback }, &.{c[2]}, .{});
        _ = try P.run("record12.sealCid prepared " ++ c[0], r12SealCid, .{ k, &pt, &wire }, &.{c[2]}, .{});
        const n2 = try r12SealCid(k, &pt, &wire);
        _ = try P.run("record12.openCid prepared " ++ c[0], r12OpenCid, .{ k, wire[0..n2], &rback }, &.{c[2]}, .{});
    }
    rk128.wipe();
    rk256.wipe();
}

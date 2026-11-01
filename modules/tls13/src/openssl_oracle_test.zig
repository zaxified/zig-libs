// SPDX-License-Identifier: MIT

//! Hermetic replay of the live OpenSSL oracle (`tools/interop.zig`): the values
//! OpenSSL 3.5's libcrypto produced, frozen in `openssl_oracle_vectors.zig`, and
//! this module's answer to each. The TAKING of the transcript (`zig build
//! interop-tls13 -- --write`) needs OpenSSL and a C compiler; this replay needs
//! neither, so the anchor's value runs in `test-tls13` on every host.
//!
//!   - key schedule: every secret, key and IV of RFC 8446 section 7 over the frozen
//!     inputs equals the one OpenSSL derived;
//!   - key exchange: our client reaches the shared secret of OpenSSL's server, our
//!     server (seeded as when the row was taken) reaches the one OpenSSL's client
//!     derived from our answer;
//!   - malformed peers: the verdict we gave when the row was taken, which is the
//!     one OpenSSL gave;
//!   - CertificateVerify: we verify what OpenSSL signed, under the context string
//!     it was signed for, and refuse it with a bit flipped or under the other one.

const std = @import("std");
const rsa = @import("rsa");
const p521 = @import("p521");
const v = @import("openssl_oracle_vectors.zig");
const keyschedule = @import("keyschedule.zig");
const kex = @import("kex.zig");
const cv = @import("certverify.zig");

const testing = std.testing;
const Ecdsa = std.crypto.sign.ecdsa;
const Ed25519 = std.crypto.sign.Ed25519;

fn unhex(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len == 1 and s[0] == '-') return arena.alloc(u8, 0);
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

// ---- key schedule ----

const KsIn = struct {
    sha384: bool,
    psk: ?[]const u8,
    dhe: ?[]const u8,
    th: [4][]const u8,
    nonce: []const u8,
    label: []const u8,
    ctx: []const u8,
    exp_len: usize,
    key_len: usize,
};

/// Our side of the schedule, the fields in the C side's order.
fn ksOurs(comptime Hash: type, comptime Hkdf: type, comptime Hmac: type, arena: std.mem.Allocator, in: KsIn) ![]const []u8 {
    const L = Hkdf.prk_length;
    const S = keyschedule.tls13;
    const empty = keyschedule.emptyTranscriptHash(Hash);
    const zeros: [L]u8 = @splat(0);
    var f: std.ArrayList([]u8) = .empty;

    var early: [L]u8 = undefined;
    const psk: []const u8 = in.psk orelse &zeros;
    S.earlySecret(Hkdf, &early, psk);
    try f.append(arena, try arena.dupe(u8, &early));
    var ext: [L]u8 = undefined;
    S.binderKey(Hkdf, &ext, &early, empty);
    try f.append(arena, try arena.dupe(u8, &ext));
    var resb: [L]u8 = undefined;
    S.resumptionBinderKey(Hkdf, &resb, &early, empty);
    try f.append(arena, try arena.dupe(u8, &resb));
    var binder: [L]u8 = undefined;
    S.pskBinder(Hkdf, Hmac, &binder, &ext, in.th[0]);
    try f.append(arena, try arena.dupe(u8, &binder));
    var ce: [L]u8 = undefined;
    S.deriveSecret(Hkdf, &ce, &early, "c e traffic", in.th[0]);
    try f.append(arena, try arena.dupe(u8, &ce));
    var ee: [L]u8 = undefined;
    S.deriveSecret(Hkdf, &ee, &early, "e exp master", in.th[0]);
    try f.append(arena, try arena.dupe(u8, &ee));

    var hs: [L]u8 = undefined;
    S.deriveHandshakeSecret(Hkdf, &hs, &early, empty, in.dhe);
    try f.append(arena, try arena.dupe(u8, &hs));
    var c_hs: [L]u8 = undefined;
    var s_hs: [L]u8 = undefined;
    S.deriveHandshakeTrafficSecrets(Hkdf, &c_hs, &s_hs, &hs, in.th[1]);
    try f.append(arena, try arena.dupe(u8, &c_hs));
    try f.append(arena, try arena.dupe(u8, &s_hs));
    var ms: [L]u8 = undefined;
    S.deriveMasterSecret(Hkdf, &ms, &hs, empty);
    try f.append(arena, try arena.dupe(u8, &ms));
    var c_ap: [L]u8 = undefined;
    var s_ap: [L]u8 = undefined;
    var exp: [L]u8 = undefined;
    S.deriveApplicationSecrets(Hkdf, &c_ap, &s_ap, &exp, &ms, in.th[2]);
    try f.append(arena, try arena.dupe(u8, &c_ap));
    try f.append(arena, try arena.dupe(u8, &s_ap));
    try f.append(arena, try arena.dupe(u8, &exp));
    var res: [L]u8 = undefined;
    S.deriveResumptionMasterSecret(Hkdf, &res, &ms, in.th[3]);
    try f.append(arena, try arena.dupe(u8, &res));
    var rpsk: [L]u8 = undefined;
    S.deriveResumptionPsk(Hkdf, &rpsk, &res, in.nonce);
    try f.append(arena, try arena.dupe(u8, &rpsk));

    var fc: [L]u8 = undefined;
    var fs: [L]u8 = undefined;
    S.deriveFinishedKey(Hkdf, L, &fc, &c_hs);
    S.deriveFinishedKey(Hkdf, L, &fs, &s_hs);
    try f.append(arena, try arena.dupe(u8, &fc));
    try f.append(arena, try arena.dupe(u8, &fs));
    var vd: [L]u8 = undefined;
    keyschedule.computeFinishedVerifyData(Hmac, &vd, &fs, in.th[2]);
    try f.append(arena, try arena.dupe(u8, &vd));

    const traffic = [_]*const [L]u8{ &c_hs, &s_hs, &c_ap, &s_ap };
    for (traffic) |t| {
        switch (in.key_len) {
            inline 16, 32 => |kl| {
                var key: [kl]u8 = undefined;
                var iv: [12]u8 = undefined;
                S.deriveTrafficKeyIv(Hkdf, kl, 12, &key, &iv, t);
                try f.append(arena, try arena.dupe(u8, &key));
                try f.append(arena, try arena.dupe(u8, &iv));
            },
            else => unreachable,
        }
    }
    var n1: [L]u8 = undefined;
    var n2: [L]u8 = undefined;
    S.nextApplicationTrafficSecret(Hkdf, &n1, &c_ap);
    S.nextApplicationTrafficSecret(Hkdf, &n2, &s_ap);
    try f.append(arena, try arena.dupe(u8, &n1));
    try f.append(arena, try arena.dupe(u8, &n2));
    const exported = try arena.alloc(u8, in.exp_len);
    try S.exportKeyingMaterial(Hash, Hkdf, exported, &exp, in.label, in.ctx);
    try f.append(arena, exported);
    return f.items;
}

test "openssl oracle: key schedule secrets equal OpenSSL's" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (v.ks, 0..) |row, n| {
        const in: KsIn = .{
            .sha384 = row.sha384,
            .psk = if (row.psk) |p| try unhex(arena, p) else null,
            .dhe = if (row.dhe) |p| try unhex(arena, p) else null,
            .th = .{ try unhex(arena, row.th[0]), try unhex(arena, row.th[1]), try unhex(arena, row.th[2]), try unhex(arena, row.th[3]) },
            .nonce = try unhex(arena, row.nonce),
            .label = try unhex(arena, row.label),
            .ctx = try unhex(arena, row.ctx),
            .exp_len = row.exp_len,
            .key_len = row.key_len,
        };
        const ours = if (row.sha384)
            try ksOurs(std.crypto.hash.sha2.Sha384, std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384), std.crypto.auth.hmac.sha2.HmacSha384, arena, in)
        else
            try ksOurs(std.crypto.hash.sha2.Sha256, std.crypto.kdf.hkdf.HkdfSha256, std.crypto.auth.hmac.sha2.HmacSha256, arena, in);
        try testing.expectEqual(v.ks_names.len, ours.len);
        for (ours, row.fields, v.ks_names) |a, theirs, name| {
            testing.expectEqualSlices(u8, try unhex(arena, theirs), a) catch |e| {
                std.debug.print("row {d} ({s}): {s}\n", .{ n, if (row.sha384) "SHA-384" else "SHA-256", name });
                return e;
            };
        }
    }
}

// ---- key exchange ----

test "openssl oracle: our client reaches the shared secret of OpenSSL's server" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(v.kex_server.len >= 7);
    for (v.kex_server) |row| {
        const secret = try unhex(arena, row.secret);
        const cshare = try unhex(arena, row.cshare);
        try testing.expectEqual(kex.scalarLen(row.group), secret.len);
        try testing.expectEqual(kex.expectedShareLen(row.group), cshare.len);
        var ss: kex.SharedSecret = undefined;
        try kex.sharedSecret(row.group, secret, try unhex(arena, row.sshare), &ss);
        try testing.expectEqualSlices(u8, try unhex(arena, row.ss), ss.slice());
    }
}

test "openssl oracle: our server reaches the shared secret of OpenSSL's client" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(v.kex_client.len >= 7);
    for (v.kex_client) |row| {
        var prng = std.Random.DefaultPrng.init(row.seed);
        var x: kex.ServerExchange = undefined;
        try kex.serverExchange(row.group, try unhex(arena, row.cshare), prng.random(), &x);
        try testing.expectEqualSlices(u8, try unhex(arena, row.ss), x.shared.slice());
    }
}

test "openssl oracle: malformed peer shares get the verdict OpenSSL gave" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var accepted: usize = 0;
    var refused: usize = 0;
    for (v.neg) |row| {
        const share = try unhex(arena, row.share);
        const ours = if (row.client_dir) blk: {
            var ss: kex.SharedSecret = undefined;
            break :blk if (kex.sharedSecret(row.group, try unhex(arena, row.secret), share, &ss)) true else |_| false;
        } else blk: {
            var prng = std.Random.DefaultPrng.init(1);
            var x: kex.ServerExchange = undefined;
            break :blk if (kex.serverExchange(row.group, share, prng.random(), &x)) true else |_| false;
        };
        testing.expectEqual(row.ours, ours) catch |e| {
            std.debug.print("group 0x{x:0>4} {s} {s}\n", .{ row.group, if (row.client_dir) "client" else "server", row.kind });
            return e;
        };
        // No row is frozen with a verdict where we are stricter than OpenSSL (that needs an
        // RFC sentence in the oracle's `stricter` and a case here).
        try testing.expectEqual(row.ossl, row.ours);
        if (ours) accepted += 1 else refused += 1;
    }
    try testing.expect(refused > 0 and accepted > 0);
}

// ---- CertificateVerify ----

fn publicKey(scheme: cv.SignatureScheme, pk: []const u8, pk2: []const u8) !cv.PublicKey {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => .{ .ecdsa_p256 = try Ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(pk) },
        .ecdsa_secp384r1_sha384 => .{ .ecdsa_p384 = try Ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(pk) },
        .ecdsa_secp521r1_sha512 => .{ .ecdsa_p521 = try p521.EcdsaP521Sha512.PublicKey.fromSec1(pk) },
        .ed25519 => .{ .ed25519 = try Ed25519.PublicKey.fromBytes(pk[0..32].*) },
        .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => .{ .rsa = try rsa.PublicKey.fromBytes(pk, pk2) },
        .mldsa44 => .{ .mldsa44 = pk },
        .mldsa65 => .{ .mldsa65 = pk },
        .mldsa87 => .{ .mldsa87 = pk },
        else => error.UnsupportedScheme,
    };
}

test "openssl oracle: we verify what OpenSSL signed, and refuse it damaged or under the other context" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(v.sigs.len >= 10);
    var seen: [16]u16 = undefined;
    var nseen: usize = 0;
    for (v.sigs) |row| {
        const scheme: cv.SignatureScheme = @fromBackingInt(@intCast(row.scheme));
        if (std.mem.indexOfScalar(u16, seen[0..nseen], row.scheme) == null) {
            seen[nseen] = row.scheme;
            nseen += 1;
        }
        const pk = try publicKey(scheme, try unhex(arena, row.pk), try unhex(arena, row.pk2));
        const side: cv.Side = if (row.client) .client else .server;
        const other: cv.Side = if (row.client) .server else .client;
        const th = try unhex(arena, row.th);
        const sig = try unhex(arena, row.sig);
        cv.verify(scheme, pk, side, th, sig) catch |e| {
            std.debug.print("{s}: {t}\n", .{ @tagName(scheme), e });
            return e;
        };
        const bad = try arena.dupe(u8, sig);
        bad[bad.len / 2] ^= 0x10;
        try testing.expect(std.meta.isError(cv.verify(scheme, pk, side, th, bad)));
        try testing.expect(std.meta.isError(cv.verify(scheme, pk, other, th, sig)));
    }
    // Every scheme certverify has, signed by OpenSSL.
    try testing.expectEqual(@as(usize, 10), nseen);
}

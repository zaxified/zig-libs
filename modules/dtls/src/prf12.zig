// SPDX-License-Identifier: MIT

//! dtls.prf12 — the TLS 1.2 key derivation DTLS 1.2 (RFC 6347 §4.1.2) uses
//! unchanged: the RFC 5246 §5 PRF (`P_SHA256` / `P_SHA384`), the master
//! secret (RFC 5246 §8.1) and its extended form (RFC 7627 §4), the key block
//! (RFC 5246 §6.3), the Finished `verify_data` (RFC 5246 §7.4.9) and the
//! RFC 5705 §4 exporter.
//!
//! The PRF hash is the cipher suite's: SHA-256 for every suite here except
//! the `_SHA384` ones (RFC 5288 §3, RFC 5289 §3.2). Every function takes it
//! as a runtime `HashAlg` and dispatches to a comptime-typed body.

const std = @import("std");
const suitehash = @import("suitehash.zig");

pub const HashAlg = suitehash.HashAlg;

/// RFC 5246 §8.1: the master secret is always 48 bytes.
pub const master_secret_len = 48;
/// RFC 5246 §7.4.9: `verify_data_length` defaults to 12 and no suite here
/// overrides it.
pub const verify_data_len = 12;

fn HmacOf(comptime alg: HashAlg) type {
    return std.crypto.auth.hmac.Hmac(suitehash.Types(alg).Hash);
}

fn pHashT(comptime alg: HashAlg, secret: []const u8, seed: []const []const u8, out: []u8) void {
    const Hmac = HmacOf(alg);
    // A(1) = HMAC(secret, seed); A(i) = HMAC(secret, A(i-1)).
    var a: [Hmac.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &a);
    {
        var h = Hmac.init(secret);
        for (seed) |part| h.update(part);
        h.final(&a);
    }
    var off: usize = 0;
    while (off < out.len) {
        var block: [Hmac.mac_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &block);
        var h = Hmac.init(secret);
        h.update(&a);
        for (seed) |part| h.update(part);
        h.final(&block);
        const k = @min(block.len, out.len - off);
        @memcpy(out[off..][0..k], block[0..k]);
        off += k;
        Hmac.create(&a, &a, secret);
    }
}

/// RFC 5246 §5: `PRF(secret, label, seed) = P_<hash>(secret, label + seed)`,
/// with `label + seed` given as parts (`label` first) so no caller has to
/// concatenate secrets into a scratch buffer. Fills all of `out`.
pub fn prf(alg: HashAlg, secret: []const u8, label: []const u8, seed: []const []const u8, out: []u8) void {
    var parts: [6][]const u8 = undefined;
    std.debug.assert(seed.len < parts.len); // internal callers only, at most 4 seed parts
    parts[0] = label;
    for (seed, 0..) |s, i| parts[i + 1] = s;
    switch (alg) {
        inline else => |a| pHashT(a, secret, parts[0 .. seed.len + 1], out),
    }
}

/// RFC 5246 §8.1 (`extended == false`) or RFC 7627 §4 (`extended == true`):
/// `seed` is `ClientHello.random + ServerHello.random` for the former and
/// the `session_hash` (the transcript hash through ClientKeyExchange) for
/// the latter.
pub fn masterSecret(
    alg: HashAlg,
    pre_master_secret: []const u8,
    extended: bool,
    client_random: *const [32]u8,
    server_random: *const [32]u8,
    session_hash: []const u8,
    out: *[master_secret_len]u8,
) void {
    if (extended) {
        prf(alg, pre_master_secret, "extended master secret", &.{session_hash}, out);
    } else {
        prf(alg, pre_master_secret, "master secret", &.{ client_random, server_random }, out);
    }
}

/// RFC 5246 §6.3: `key_block = PRF(master, "key expansion", server_random +
/// client_random)` — note the order, server first, the reverse of the master
/// secret's seed.
pub fn keyBlock(alg: HashAlg, master: *const [master_secret_len]u8, client_random: *const [32]u8, server_random: *const [32]u8, out: []u8) void {
    prf(alg, master, "key expansion", &.{ server_random, client_random }, out);
}

/// RFC 5246 §7.4.9: `PRF(master, finished_label, Hash(handshake_messages))
/// [0..11]`, `finished_label` "client finished" or "server finished".
pub fn finishedVerifyData(alg: HashAlg, master: *const [master_secret_len]u8, from_client: bool, transcript_hash: []const u8) [verify_data_len]u8 {
    var out: [verify_data_len]u8 = undefined;
    prf(alg, master, if (from_client) "client finished" else "server finished", &.{transcript_hash}, &out);
    return out;
}

/// RFC 5705 §4 labels the exporter must not accept: the PRF labels TLS 1.2
/// itself uses (§4: "labels ... MUST NOT collide with existing PRF labels").
const reserved_labels = [_][]const u8{ "client finished", "server finished", "master secret", "key expansion", "extended master secret" };

pub const ExportError = error{ ReservedLabel, ContextTooLong };

/// RFC 5705 §4: `PRF(master, label, client_random + server_random [+
/// context_length(u16) + context])`. A null `context` and an empty one are
/// DIFFERENT exports in TLS 1.2 (the length field is present or not).
pub fn exportKeyingMaterial(
    alg: HashAlg,
    master: *const [master_secret_len]u8,
    client_random: *const [32]u8,
    server_random: *const [32]u8,
    label: []const u8,
    context: ?[]const u8,
    out: []u8,
) ExportError!void {
    for (reserved_labels) |r| if (std.mem.eql(u8, label, r)) return error.ReservedLabel;
    if (context) |ctx| {
        if (ctx.len > 0xffff) return error.ContextTooLong;
        var ctx_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &ctx_len, @intCast(ctx.len), .big);
        prf(alg, master, label, &.{ client_random, server_random, &ctx_len, ctx }, out);
    } else {
        prf(alg, master, label, &.{ client_random, server_random }, out);
    }
}

// ── tests ────────────────────────────────────────────────────────────────
//
// Goldens computed with Python 3's `hmac`/`hashlib` (an implementation
// independent of this file) from the RFC 5246 §5 definition of P_hash, plus
// a cross-check against std's own `std.crypto.tls.hmacExpandLabel`, which
// is std's TLS 1.2 PRF.

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const test_seed = blk: {
    var s: [16]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = 0x20 + i;
    break :blk s;
};

test "prf12: P_SHA256 (RFC 5246 §5) against an independent HMAC golden, 100 bytes" {
    var secret: [16]u8 = undefined;
    for (&secret, 0..) |*b, i| b.* = @intCast(i);
    var out: [100]u8 = undefined;
    prf(.sha256, &secret, "test label", &.{&test_seed}, &out);
    try testing.expectEqualSlices(u8, &hex("143428c1a9c2cee225e97eac4aca2db88bd90b18e23d12a84612b056220804be5313ff6982a0728fa9a78fc533fc71c67ded4f9390d365be7926727e3ebbf1c8a31b89cb4427676f4a218ce612cd16375e8ed71d442efac6294a02f9176fecf2d7130869"), &out);
    // std's TLS 1.2 PRF agrees.
    const std_out = std.crypto.tls.hmacExpandLabel(std.crypto.auth.hmac.sha2.HmacSha256, &secret, &.{ "test label", &test_seed }, 100);
    try testing.expectEqualSlices(u8, &std_out, &out);
}

test "prf12: P_SHA384 (RFC 5246 §5, RFC 5288 §3) against an independent HMAC golden, 148 bytes" {
    var secret: [48]u8 = undefined;
    for (&secret, 0..) |*b, i| b.* = @intCast(i);
    var out: [148]u8 = undefined;
    prf(.sha384, &secret, "test label", &.{&test_seed}, &out);
    try testing.expectEqualSlices(u8, &hex("80052404a675dcfa99cf1d6a0fa2209d1d75397dcf784d7d75cc2603497251f34177897f126c92915383c5cf93b991bfedfedd7799e89324cc7ee62eebb056037b78817adfa0d850ae13b64fb3bf7dace6d48626cce28f8de9188f09083df0d6ffffc879e4c90ade1e27077f84280b1437bf4beb689e68fe50ec00827bb4cdcef09906afeb8323d4eee78d7ff71e34a04894e82b"), &out);
    const std_out = std.crypto.tls.hmacExpandLabel(std.crypto.auth.hmac.sha2.HmacSha384, &secret, &.{ "test label", &test_seed }, 148);
    try testing.expectEqualSlices(u8, &std_out, &out);
}

const kat_pms: [32]u8 = @splat(0x11);
const kat_cr = blk: {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = i;
    break :blk s;
};
const kat_sr = blk: {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = 32 + i;
    break :blk s;
};

test "prf12: master secret (RFC 5246 §8.1), extended master secret (RFC 7627 §4), key block (§6.3), Finished (§7.4.9), exporter (RFC 5705 §4)" {
    var sh: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("handshake", &sh, .{});
    var ms: [48]u8 = undefined;
    masterSecret(.sha256, &kat_pms, false, &kat_cr, &kat_sr, &sh, &ms);
    try testing.expectEqualSlices(u8, &hex("4573d7d22a22e5a04c57b3060f5d673db21b90cf1d4184b19e7a3ddab84ec1bf2ef3d5c7f6c2ccd511cac03e0aaf6b3d"), &ms);
    var ems: [48]u8 = undefined;
    masterSecret(.sha256, &kat_pms, true, &kat_cr, &kat_sr, &sh, &ems);
    try testing.expectEqualSlices(u8, &hex("ca9f95cba66c4281dc1a564fba01a9dd1d9f3693429407f6801826a59d262072d2319ed096389a7f0b467725c9f9d511"), &ems);
    var kb: [40]u8 = undefined;
    keyBlock(.sha256, &ems, &kat_cr, &kat_sr, &kb);
    try testing.expectEqualSlices(u8, &hex("20994b090afd35212e42c1a185ca80abff722a0c5662d014a897e39807e3439d41a35f91beb19822"), &kb);
    try testing.expectEqualSlices(u8, &hex("53c2d78c7e59ee5c1de6119c"), &finishedVerifyData(.sha256, &ems, true, &sh));
    var exp: [20]u8 = undefined;
    try exportKeyingMaterial(.sha256, &ems, &kat_cr, &kat_sr, "EXPORTER-test", "ctx", &exp);
    try testing.expectEqualSlices(u8, &hex("20c85825ef93880d9df85504e9c898255637d42c"), &exp);
    try exportKeyingMaterial(.sha256, &ems, &kat_cr, &kat_sr, "EXPORTER-test", null, &exp);
    try testing.expectEqualSlices(u8, &hex("37e8b6fea7aadbaccd2f294c87545dd70fa9abaf"), &exp);
    try testing.expectError(error.ReservedLabel, exportKeyingMaterial(.sha256, &ems, &kat_cr, &kat_sr, "key expansion", null, &exp));
}

test "prf12: SHA-384 extended master secret and server Finished (RFC 7627 §4, RFC 5288 §3)" {
    var sh: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash("handshake", &sh, .{});
    var ems: [48]u8 = undefined;
    masterSecret(.sha384, &kat_pms, true, &kat_cr, &kat_sr, &sh, &ems);
    try testing.expectEqualSlices(u8, &hex("faa551b1f57e356ade37d571f1a8e367364b731d6f393d854dd69df706dff783dca45d6382476802f73e8bf9f76c5131"), &ems);
    try testing.expectEqualSlices(u8, &hex("aae1fdaa988a6c68b33508f7"), &finishedVerifyData(.sha384, &ems, false, &sh));
}

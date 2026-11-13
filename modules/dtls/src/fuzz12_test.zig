// SPDX-License-Identifier: MIT

//! Deterministic fuzz harnesses for the DTLS 1.2 engine (added 2026-11-13),
//! in the shape of `fuzz_test.zig` and run by the same driver
//! (`DTLS_FUZZ=<runs>[,<first seed>]`, `_ONLY=<name>`):
//! - `dtls12-handshake`: a whole `Connection12` handshake (PSK, ECDHE_PSK,
//!   PSK behind a HelloVerifyRequest, ECDHE_ECDSA with a certificate) where
//!   ONE datagram on the way is damaged, replaced by random bytes, dropped
//!   or duplicated. Undamaged (or duplicated): both sides connect. Damaged:
//!   never a panic, and a pair that does connect agrees on its keys and
//!   moves a record both ways.
//! - `dtls12-wire`: the 1.2 message decoders (`messages12`: ClientHello,
//!   HelloVerifyRequest, ServerHello, Certificate, ServerECDHParams, the
//!   PSK opaque fields, digitally-signed, CertificateRequest, the point
//!   formats) on damaged genuine messages and on random bytes.

const std = @import("std");
const testing = std.testing;
const fz = @import("fuzz_test.zig");
const fuzz_driver = fz.fuzz_driver;
const conn13 = @import("Connection.zig");
const c12 = @import("Connection12.zig");
const m12 = @import("messages12.zig");
const suite12 = @import("suite12.zig");
const cert_kat = @import("certauth_kat_vectors.zig");
const certverify = @import("tls13").certverify;

const Config = conn13.Config;
const Connection12 = c12.Connection12;

const v12 = [_]conn13.ProtocolVersion{.dtls12};
const Mode = enum { psk, ecdhe_psk, psk_hvr, ecdsa };

var server_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;

fn configs(mode: Mode) [2]Config {
    const id = "fuzz-device";
    const key = "fuzz pre-shared key";
    return switch (mode) {
        .psk, .psk_hvr => .{
            .{ .role = .client, .versions = &v12, .psk_identity = id, .psk = key, .cipher_suites12 = &.{.psk_with_aes_128_gcm_sha256} },
            .{
                .role = .server,
                .versions = &v12,
                .psk_identity = id,
                .psk = key,
                .cipher_suites12 = &.{.psk_with_aes_128_gcm_sha256},
                .hello_retry = if (mode == .psk_hvr) .{ .cookie_secret = "fuzz cookie key", .peer_binding = "192.0.2.1:5684" } else null,
            },
        },
        .ecdhe_psk => .{
            .{ .role = .client, .versions = &v12, .psk_identity = id, .psk = key, .cipher_suites12 = &.{.ecdhe_psk_with_chacha20_poly1305_sha256} },
            .{ .role = .server, .versions = &v12, .psk_identity = id, .psk = key, .cipher_suites12 = &.{.ecdhe_psk_with_chacha20_poly1305_sha256} },
        },
        .ecdsa => blk: {
            server_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable;
            break :blk .{
                .{ .role = .client, .versions = &v12, .key_exchange = .cert_dhe, .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der }, .now_sec = cert_kat.valid_now_sec, .cipher_suites12 = &.{.ecdhe_ecdsa_with_aes_128_gcm_sha256} },
                .{ .role = .server, .versions = &v12, .key_exchange = .cert_dhe, .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = .{ .ecdsa_p256 = &server_sk } }, .cipher_suites12 = &.{.ecdhe_ecdsa_with_aes_128_gcm_sha256} },
            };
        },
    };
}

fn expectEstablished(client: *Connection12, server: *Connection12) !void {
    if (!std.mem.eql(u8, &client.write_keys.key, &server.read_keys.key) or !std.mem.eql(u8, &client.read_keys.key, &server.write_keys.key)) return error.KeysDisagree;
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const r1 = try client.send("client to server", &wire);
    if (!std.mem.eql(u8, "client to server", try server.recv(r1, &plain))) return error.RecordLost;
    const r2 = try server.send("server to client", &wire);
    if (!std.mem.eql(u8, "server to client", try client.recv(r2, &plain))) return error.RecordLost;
}

const HsMark = fz.Marker(enum { connected, refused, stalled, after_damage_connected, hvr, ecdsa });

pub fn fuzzHandshake12(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const mode: Mode = if (S == fuzz_driver.Rng) @fromBackingInt(@intCast(src.valueRangeAtMost(u8, 0, 3))) else .psk;
    const cfg = configs(mode);
    var client = try Connection12.clientInit(cfg[0]);
    var server = try Connection12.serverInit(cfg[1]);
    var seed: [32]u8 = undefined;
    src.bytes(&seed);
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };

    const Kind = enum { none, damage, random, drop, duplicate };
    var kind: Kind = .random;
    var at: usize = 0;
    if (S == fuzz_driver.Rng) {
        kind = switch (src.valueRangeAtMost(u8, 0, 9)) {
            0, 1, 2 => .none,
            3, 4, 5, 6 => .damage,
            7 => .random,
            8 => .drop,
            else => .duplicate,
        };
        at = src.valueRangeAtMost(u8, 0, 4);
    }
    var bufs: [2][8192]u8 = undefined;
    var raw: [2048]u8 = undefined;
    var cur: []const u8 = client.startHandshake(rnd, 0, &bufs[0]) catch return;
    var to_server = true;
    var err_seen = false;
    var changed = false;
    var step: usize = 0;
    while (step < 8) : (step += 1) {
        var msg: []const u8 = cur;
        var scratch: [8192]u8 = undefined;
        if (step == at) switch (kind) {
            .damage => {
                const n = fz.damage(src, &scratch, cur);
                msg = scratch[0..n];
                changed = n != cur.len or !std.mem.eql(u8, msg, cur);
            },
            .random => {
                const n = src.slice(&raw);
                msg = raw[0..n];
                changed = true;
            },
            .drop => break,
            else => {},
        };
        const peer: *Connection12 = if (to_server) &server else &client;
        const out = &bufs[(step + 1) % 2];
        const res = peer.handleFlight(msg, rnd, 0, out) catch {
            err_seen = true;
            break;
        };
        if (step == at and kind == .duplicate) {
            var dup: [8192]u8 = undefined;
            _ = peer.handleFlight(msg, rnd, 0, &dup) catch {};
        }
        if (client.isConnected() and server.isConnected()) break;
        if (res.out.len == 0) break;
        cur = res.out;
        to_server = !to_server;
    }
    if (client.isConnected() and server.isConnected()) {
        try expectEstablished(&client, &server);
        if (changed) HsMark.mark(.after_damage_connected) else HsMark.mark(.connected);
        if (mode == .psk_hvr and !changed) HsMark.mark(.hvr);
        if (mode == .ecdsa and !changed) HsMark.mark(.ecdsa);
    } else {
        if ((kind == .none or kind == .duplicate) and S == fuzz_driver.Rng) {
            std.debug.print("dtls12-handshake: an undamaged handshake did not connect (mode {t}, kind {t}, client {t}, server {t})\n", .{ mode, kind, client.state, server.state });
            return error.GenuineHandshakeFailed;
        }
        if (err_seen) HsMark.mark(.refused) else HsMark.mark(.stalled);
    }
}

fn fuzzHandshake12Smith(_: void, smith: *std.testing.Smith) !void {
    try fuzzHandshake12(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: a DTLS 1.2 handshake with one datagram damaged never panics" {
    try testing.fuzz({}, fuzzHandshake12Smith, .{});
}

test "fuzz driver: DTLS_FUZZ (dtls12-handshake)" {
    try fuzz_driver.run(fuzzHandshake12, .{ .prefix = "DTLS_FUZZ", .name = "dtls12-handshake" });
}

test "fuzz harness: dtls12-handshake, 160 seeds, reaches every outcome" {
    try HsMark.reach(fuzzHandshake12, "dtls12-handshake", 160);
}

// ── dtls12-wire ─────────────────────────────────────────────────────────

const WireMark = fz.Marker(enum { client_hello_ok, server_hello_ok, certificate_ok, ske_ok, cr_ok, rejected });

/// Genuine bodies of each 1.2 message, built once.
fn genuine(which: u8, buf: []u8) ![]const u8 {
    const exts = [_]m12.Extension{
        .{ .ext_type = m12.ext_extended_master_secret, .data = &.{} },
        .{ .ext_type = m12.ext_renegotiation_info, .data = &m12.renegotiation_info_initial },
    };
    return switch (which) {
        0 => m12.encodeClientHello(.{ .random = @splat(1), .cookie = "c00kie", .cipher_suites = &.{ 0xc02b, 0x00a8 }, .extensions = &exts }, buf),
        1 => m12.encodeServerHello(.{ .random = @splat(2), .cipher_suite = 0xc02b, .extensions = &exts }, buf),
        2 => m12.encodeCertificate(&.{ &cert_kat.server_cert_der, &cert_kat.anchor_cert_der }, buf),
        3 => blk: {
            const p = try m12.encodeEcdhParams(0x1d, &@as([32]u8, @splat(9)), buf);
            const s = try m12.encodeSigned(0x0403, &@as([70]u8, @splat(3)), buf[p.len..]);
            break :blk buf[0 .. p.len + s.len];
        },
        4 => m12.encodeCertificateRequest(&.{ 0x0403, 0x0804, 0x0401 }, buf),
        else => m12.encodeHelloVerifyRequest("c00kie", buf),
    };
}

pub fn fuzzWire12(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var gbuf: [2048]u8 = undefined;
    var buf: [2048]u8 = undefined;
    const which: u8 = if (S == fuzz_driver.Rng) src.valueRangeAtMost(u8, 0, 5) else 0;
    var input: []const u8 = undefined;
    if (S == fuzz_driver.Rng and src.valueRangeAtMost(u8, 0, 3) != 0) {
        const g = try genuine(which, &gbuf);
        input = buf[0..fz.damage(src, &buf, g)];
    } else input = buf[0..src.slice(&buf)];

    var ext: [24]m12.Extension = undefined;
    var ok = false;
    switch (which) {
        0 => if (m12.decodeClientHello(input, &ext)) |d| {
            ok = true;
            _ = m12.offersSuite(d.cipher_suites_raw, 0x00ff);
            if (d.cookie_offset >= input.len) return error.CookieOffsetOutOfRange;
            WireMark.mark(.client_hello_ok);
        } else |_| {},
        1 => if (m12.decodeServerHello(input, &ext)) |d| {
            ok = true;
            if (m12.findExtension(d.extensions, m12.ext_ec_point_formats)) |pf| _ = m12.pointFormatsIncludeUncompressed(pf);
            WireMark.mark(.server_hello_ok);
        } else |_| {},
        2 => if (m12.decodeCertificateLeaf(input)) |leaf| {
            ok = true;
            if (leaf) |l| if (l.len > input.len) return error.LeafOutOfRange;
            WireMark.mark(.certificate_ok);
        } else |_| {},
        3 => {
            if (m12.decodeEcdhParams(input)) |d| {
                if (m12.decodeSigned(d.rest)) |_| {
                    ok = true;
                    WireMark.mark(.ske_ok);
                } else |_| {}
            } else |_| {}
            if (m12.decodeOpaque16(input)) |h| _ = m12.decodeEcdhParams(h.rest) catch {} else |_| {}
            _ = m12.decodePoint(input) catch {};
        },
        4 => if (m12.decodeCertificateRequest(input)) |_| {
            ok = true;
            WireMark.mark(.cr_ok);
        } else |_| {},
        else => if (m12.decodeHelloVerifyRequest(input)) |_| {
            ok = true;
        } else |_| {},
    }
    if (!ok) WireMark.mark(.rejected);
}

fn fuzzWire12Smith(_: void, smith: *std.testing.Smith) !void {
    try fuzzWire12(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: the DTLS 1.2 message decoders never panic" {
    try testing.fuzz({}, fuzzWire12Smith, .{});
}

test "fuzz driver: DTLS_FUZZ (dtls12-wire)" {
    try fuzz_driver.run(fuzzWire12, .{ .prefix = "DTLS_FUZZ", .name = "dtls12-wire" });
}

test "fuzz harness: dtls12-wire, 400 seeds, reaches every outcome" {
    try WireMark.reach(fuzzWire12, "dtls12-wire", 400);
}

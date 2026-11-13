// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh dtls`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-dtls`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `hs` — a full in-memory PSK handshake (`Connection` client and server,
//!    AES-128-GCM-SHA256, then AES-256-GCM-SHA384 with a SHA-384 PSK, the
//!    module's own loopback flow) with the pre-shared key
//!    tainted on both sides: PSK binder (compute + verify), the whole key
//!    schedule, the handshake record protection, both Finished MACs and
//!    their verification, and `installApplicationKeys`. Randoms are public.
//!  * `app` — after an UNTAINTED handshake, both directions' record keys
//!    (AEAD key, static IV, sequence-number mask key) tainted, then
//!    `send`/`recv` both ways under AES-128-GCM, ChaCha20-Poly1305 and
//!    AES-256-GCM (2026-11-13): record
//!    protection, sequence-number masking, and the receiver's DTLSInnerPlaintext
//!    handling of the decrypted (secret) content.
//!
//!  * `ku` (2026-11-13) — after an UNTAINTED handshake, both sides'
//!    application traffic secrets and exporter master secret tainted, then a
//!    KeyUpdate in each direction (RFC 9147 §8: the `update_requested`
//!    exchange, ACKs, `"traffic upd"` derivation, the new record keys used
//!    both ways) and an RFC 8446 §7.5 export, under AES-128-GCM,
//!    ChaCha20-Poly1305 and AES-256-GCM-SHA384 (48-byte secrets).
//!
//!  * `hs12` (2026-11-13) — DTLS 1.2 (`Connection12`) handshakes: PSK
//!    AES-128-GCM and ECDHE_PSK ChaCha20-Poly1305 with the pre-shared key
//!    tainted on both sides (premaster, RFC 7627 master secret, key block,
//!    both Finished MACs and their verification), and ECDHE_ECDSA
//!    AES-256-GCM-SHA384 with the SERVER's ephemeral ECDHE private key
//!    tainted once its flight is out (the shared secret, the SHA-384 PRF,
//!    the key block, the encrypted Finished both ways).
//!  * `app12` (2026-11-13) — after UNTAINTED 1.2 handshakes, both
//!    directions' record keys (AEAD key, implicit IV / salt) tainted, then
//!    `send`/`recv` both ways under AES-128-GCM, ChaCha20-Poly1305 and
//!    AES-256-GCM (RFC 5288 / RFC 7905 nonces).
//!
//! The in-file pattern is this module's own files.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const dtls = @import("root.zig");

const Connection = dtls.Connection;
const Target = enum { hs, app, ku, hs12, app12 };
const Connection12 = dtls.Connection12;
const cert_kat = @import("certauth_kat_vectors.zig");
var ecdsa_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;

const Mode12 = enum { psk, ecdhe_psk, ecdsa };

fn configs12(mode: Mode12, psk: []const u8) [2]dtls.Config {
    const v12 = &[_]dtls.ProtocolVersion{.dtls12};
    const id = "device-042";
    return switch (mode) {
        .psk => .{
            .{ .role = .client, .versions = v12, .psk_identity = id, .psk = psk, .cipher_suites12 = &.{.psk_with_aes_128_gcm_sha256} },
            .{ .role = .server, .versions = v12, .psk_identity = id, .psk = psk, .cipher_suites12 = &.{.psk_with_aes_128_gcm_sha256} },
        },
        .ecdhe_psk => .{
            .{ .role = .client, .versions = v12, .psk_identity = id, .psk = psk, .cipher_suites12 = &.{.ecdhe_psk_with_chacha20_poly1305_sha256} },
            .{ .role = .server, .versions = v12, .psk_identity = id, .psk = psk, .cipher_suites12 = &.{.ecdhe_psk_with_chacha20_poly1305_sha256} },
        },
        .ecdsa => blk: {
            ecdsa_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable;
            break :blk .{
                .{ .role = .client, .versions = v12, .key_exchange = .cert_dhe_insecure_unauthenticated, .cipher_suites12 = &.{.ecdhe_ecdsa_with_aes_256_gcm_sha384} },
                .{ .role = .server, .versions = v12, .key_exchange = .cert_dhe_insecure_unauthenticated, .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = .{ .ecdsa_p256 = &ecdsa_sk } }, .cipher_suites12 = &.{.ecdhe_ecdsa_with_aes_256_gcm_sha384} },
            };
        },
    };
}

/// A full 1.2 handshake; `taint_ecdhe` taints the server's ephemeral ECDHE
/// private key between its flight 4 and the client's ClientKeyExchange.
fn handshake12(mode: Mode12, psk: []const u8, taint_ecdhe: bool, client: *Connection12, server: *Connection12) !void {
    const cfg = configs12(mode, psk);
    client.* = try Connection12.clientInit(cfg[0]);
    server.* = try Connection12.serverInit(cfg[1]);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x12)));
    const rnd: dtls.Entropy = .{ .seeded_for_test = csprng.random() };
    var buf1: [4096]u8 = undefined;
    var buf2: [4096]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const f4 = try server.handleFlight(ch, rnd, 0, &buf2);
    if (taint_ecdhe) std.valgrind.memcheck.makeMemUndefined(&server.ecdhe_secret);
    const f5 = try client.handleFlight(f4.out, rnd, 0, &buf1);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &buf2);
    const fin = try client.handleFlight(f6.out, rnd, 0, &buf1);
    if (!f6.done or !fin.done) return error.HandshakeIncomplete;
}

fn exchange12(client: *Connection12, server: *Connection12) !void {
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec1 = try client.send("hello from client, dtls 1.2", &wire);
    std.debug.print("ctgrind_result={x}\n", .{try server.recv(rec1, &plain)});
    const rec2 = try server.send("hello from server, dtls 1.2", &wire);
    std.debug.print("ctgrind_result={x}\n", .{try client.recv(rec2, &plain)});
}

fn taintKeys12(c: *Connection12) void {
    inline for (.{ &c.write_keys, &c.read_keys }) |k| {
        std.valgrind.memcheck.makeMemUndefined(&k.key);
        std.valgrind.memcheck.makeMemUndefined(&k.iv);
    }
}
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn handshake(suite: dtls.CipherSuite, psk: []const u8, client: *Connection, server: *Connection) !void {
    const id = "device-042";
    const suites = [_]dtls.CipherSuite{suite};
    client.* = try Connection.clientInit(.{ .role = .client, .psk_identity = id, .psk = psk, .psk_hash = suite.hash(), .cipher_suites = &suites });
    server.* = try Connection.serverInit(.{ .role = .server, .psk_identity = id, .psk = psk, .psk_hash = suite.hash(), .cipher_suites = &suites });
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x10)));
    const rnd: dtls.Entropy = .{ .seeded_for_test = csprng.random() };
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &buf1);
    const f2 = try server.handleFlight(ch, rnd, 0, &buf2);
    const cf = try client.handleFlight(f2.out, rnd, 0, &buf1);
    const sr = try server.handleFlight(cf.out, rnd, 0, &buf2);
    if (!cf.done or !sr.done) return error.HandshakeIncomplete;
}

fn exchange(client: *Connection, server: *Connection) !void {
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec1 = try client.send("hello from client, post-handshake", &wire);
    std.debug.print("ctgrind_result={x}\n", .{try server.recv(rec1, &plain)});
    const rec2 = try server.send("hello from server, post-handshake", &wire);
    std.debug.print("ctgrind_result={x}\n", .{try client.recv(rec2, &plain)});
}

fn taintKeys(c: *Connection) void {
    inline for (.{ &c.write_keys, &c.read_keys }) |k| {
        std.valgrind.memcheck.makeMemUndefined(&k.key);
        std.valgrind.memcheck.makeMemUndefined(&k.iv);
        std.valgrind.memcheck.makeMemUndefined(&k.sn_key);
    }
}

fn taintSecrets(c: *Connection) void {
    std.valgrind.memcheck.makeMemUndefined(&c.ap_write_secret);
    std.valgrind.memcheck.makeMemUndefined(&c.ap_read_secret);
    std.valgrind.memcheck.makeMemUndefined(&c.exporter_master);
}

/// Moves `from`'s next `poll` record to `to`; `to.recv` must report it as
/// the control record `want`.
fn relay(from: *Connection, to: *Connection, want: anyerror) !void {
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const rec = (try from.poll(0, &wire)) orelse return error.NothingToSend;
    if (to.recv(rec, &plain)) |_| return error.UnexpectedData else |err| if (err != want) return err;
}

fn keyUpdate(client: *Connection, server: *Connection) !void {
    try client.requestKeyUpdate(true);
    try relay(client, server, error.ReceivedKeyUpdate); // client KeyUpdate(update_requested)
    try relay(server, client, error.ReceivedAck); // its ACK: client write key moves
    try relay(server, client, error.ReceivedKeyUpdate); // server's own KeyUpdate
    try relay(client, server, error.ReceivedAck); // its ACK: server write key moves
    if (client.write_epoch != 4 or server.write_epoch != 4) return error.KeyUpdateIncomplete;
    try exchange(client, server);
    var ekm: [32]u8 = undefined;
    try client.exportKeyingMaterial("EXTRACTOR-dtls_srtp", null, &ekm);
    std.debug.print("ctgrind_result={x}\n", .{ekm});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var client: Connection = undefined;
    var server: Connection = undefined;
    switch (target) {
        .hs => {
            for ([_]dtls.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 }) |suite| {
                var psk = secretBytes(32, "ctgrind-dtls-psk-v1");
                if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&psk);
                try handshake(suite, &psk, &client, &server);
                std.debug.print("ctgrind_result={x}\n", .{client.write_keys.key[0..client.write_keys.key_len]});
            }
        },
        .app => {
            const psk = secretBytes(32, "ctgrind-dtls-psk-v1");
            for ([_]dtls.CipherSuite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 }) |suite| {
                try handshake(suite, &psk, &client, &server);
                if (taint == .yes) {
                    taintKeys(&client);
                    taintKeys(&server);
                }
                try exchange(&client, &server);
            }
        },
        .ku => {
            const psk = secretBytes(32, "ctgrind-dtls-psk-v1");
            for ([_]dtls.CipherSuite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 }) |suite| {
                try handshake(suite, &psk, &client, &server);
                var plain: [64]u8 = undefined;
                // The server's final-flight ACK, so the KeyUpdate ACKs are
                // the only ones in flight.
                if (try server.poll(0, &plain)) |_| return error.UnexpectedControlRecord;
                if (taint == .yes) {
                    taintSecrets(&client);
                    taintSecrets(&server);
                }
                try keyUpdate(&client, &server);
            }
        },
        .hs12 => {
            var c12: Connection12 = undefined;
            var s12: Connection12 = undefined;
            for ([_]Mode12{ .psk, .ecdhe_psk, .ecdsa }) |mode| {
                var psk = secretBytes(32, "ctgrind-dtls12-psk-v1");
                if (taint == .yes and mode != .ecdsa) std.valgrind.memcheck.makeMemUndefined(&psk);
                try handshake12(mode, &psk, taint == .yes and mode == .ecdsa, &c12, &s12);
                std.debug.print("ctgrind_result={x}\n", .{c12.write_keys.key});
            }
        },
        .app12 => {
            var c12: Connection12 = undefined;
            var s12: Connection12 = undefined;
            const psk = secretBytes(32, "ctgrind-dtls12-psk-v1");
            for ([_]Mode12{ .psk, .ecdhe_psk, .ecdsa }) |mode| {
                try handshake12(mode, &psk, false, &c12, &s12);
                if (taint == .yes) {
                    taintKeys12(&c12);
                    taintKeys12(&s12);
                }
                try exchange12(&c12, &s12);
            }
        },
    }
}

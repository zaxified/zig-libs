// SPDX-License-Identifier: MIT

//! DTLS 1.2 (`Connection12`) and version-negotiation (`Endpoint`) tests:
//! in-memory client <-> server self-interop for every wired suite, the
//! RFC 6347 §4.2.1 HelloVerifyRequest cookie exchange, retransmission under
//! loss (RFC 6347 §4.2.4), version negotiation both ways with the RFC 8446
//! §4.1.3 downgrade sentinel, and the RFC 7627 / RFC 5746 refusals.

const std = @import("std");
const testing = std.testing;
const conn13 = @import("Connection.zig");
const c12 = @import("Connection12.zig");
const ep = @import("Endpoint.zig");
const m12 = @import("messages12.zig");
const record = @import("record.zig");
const handshake = @import("handshake.zig");
const suite12 = @import("suite12.zig");
const cert_kat = @import("certauth_kat_vectors.zig");
const certverify = @import("tls13").certverify;
const rsa = @import("rsa");

const Config = conn13.Config;
const Connection12 = c12.Connection12;
const Endpoint = ep.Endpoint;
const Entropy = conn13.Entropy;
const CipherSuite12 = suite12.CipherSuite12;

fn seeded(csprng: *std.Random.DefaultCsprng) Entropy {
    return .{ .seeded_for_test = csprng.random() };
}

/// After both RSA (2026-11-13) and the ECDSA (2026-07-21) fixtures' notBefore.
const now_sec: i64 = 1798761600; // 2027-01-01

var server_ecdsa_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var client_ecdsa_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var rsa_sk: rsa.SecretKey = undefined;

fn serverEcdsa() certverify.SecretKey {
    server_ecdsa_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable;
    return .{ .ecdsa_p256 = &server_ecdsa_sk };
}
fn clientEcdsa() certverify.SecretKey {
    client_ecdsa_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.client_secret_key_bytes) catch unreachable;
    return .{ .ecdsa_p256 = &client_ecdsa_sk };
}
fn rsaKey() certverify.SecretKey {
    rsa.SecretKey.fromDer(&rsa_sk, &cert_kat.rsa12_key_der) catch unreachable;
    return .{ .rsa = &rsa_sk };
}

const v12 = [_]conn13.ProtocolVersion{.dtls12};
const v_both = [_]conn13.ProtocolVersion{ .dtls13, .dtls12 };

fn pskConfig(role: conn13.Role, suites: []const CipherSuite12) Config {
    return .{ .role = role, .versions = &v12, .psk_identity = "device-12", .psk = "a 1.2 pre-shared key", .cipher_suites12 = suites };
}

fn ecdsaServerConfig(suites: []const CipherSuite12) Config {
    return .{
        .role = .server,
        .versions = &v12,
        .key_exchange = .cert_dhe,
        .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = serverEcdsa() },
        .cipher_suites12 = suites,
        .now_sec = now_sec,
    };
}

fn ecdsaClientConfig(suites: []const CipherSuite12) Config {
    return .{
        .role = .client,
        .versions = &v12,
        .key_exchange = .cert_dhe,
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .expected_peer_name = "dtls-test-server",
        .cipher_suites12 = suites,
        .now_sec = now_sec,
    };
}

fn rsaServerConfig(suites: []const CipherSuite12) Config {
    return .{
        .role = .server,
        .versions = &v12,
        .key_exchange = .cert_dhe,
        .cert = .{ .chain = &.{&cert_kat.rsa12_cert_der}, .private_key = rsaKey() },
        .cipher_suites12 = suites,
        .now_sec = now_sec,
    };
}

fn rsaClientConfig(suites: []const CipherSuite12) Config {
    return .{
        .role = .client,
        .versions = &v12,
        .key_exchange = .cert_dhe,
        .peer_verify = .{ .trust_anchor = &cert_kat.rsa12_cert_der },
        .cipher_suites12 = suites,
        .now_sec = now_sec,
    };
}

const Bufs = struct {
    a: [8192]u8 = undefined,
    b: [8192]u8 = undefined,
};

/// Drives a full handshake with no loss.
fn drive(client: anytype, server: anytype, rnd: Entropy, bufs: *Bufs) !void {
    var to_server: []const u8 = try client.startHandshake(rnd, 0, &bufs.a);
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        const s = try server.handleFlight(to_server, rnd, 0, &bufs.b);
        if (client.isConnected() and server.isConnected()) return;
        const c = try client.handleFlight(s.out, rnd, 0, &bufs.a);
        if (client.isConnected() and server.isConnected()) return;
        to_server = c.out;
    }
    return error.TestHandshakeDidNotComplete;
}

fn exchangeData(client: anytype, server: anytype) !void {
    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    const rec = try client.send("ping over dtls 1.2", &b1);
    try testing.expectEqualStrings("ping over dtls 1.2", try server.recv(rec, &b2));
    const rec2 = try server.send("pong", &b1);
    try testing.expectEqualStrings("pong", try client.recv(rec2, &b2));
    // A replayed record is refused after its tag verified.
    try testing.expectError(error.ReplayedRecord, client.recv(rec2, &b2));
    var e1: [32]u8 = undefined;
    var e2: [32]u8 = undefined;
    try client.exportKeyingMaterial("EXTRACTOR-dtls_srtp", null, &e1);
    try server.exportKeyingMaterial("EXTRACTOR-dtls_srtp", null, &e2);
    try testing.expectEqualSlices(u8, &e1, &e2);
}

fn roundTrip(ccfg: Config, scfg: Config, want: CipherSuite12) !void {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x12)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ccfg);
    defer client.deinit();
    var server = try Connection12.serverInit(scfg);
    defer server.deinit();
    var bufs: Bufs = .{};
    try drive(&client, &server, rnd, &bufs);
    try testing.expectEqual(want, client.negotiatedSuite().?);
    try testing.expectEqual(want, server.negotiatedSuite().?);
    try testing.expect(client.ems and server.ems);
    try exchangeData(&client, &server);
}

test "dtls12: self-interop for every ECDHE_ECDSA suite (RFC 8422, RFC 5289, RFC 7905)" {
    for ([_]CipherSuite12{ .ecdhe_ecdsa_with_aes_128_gcm_sha256, .ecdhe_ecdsa_with_aes_256_gcm_sha384, .ecdhe_ecdsa_with_chacha20_poly1305_sha256 }) |s| {
        try roundTrip(ecdsaClientConfig(&.{s}), ecdsaServerConfig(&.{s}), s);
    }
}

test "dtls12: self-interop for every ECDHE_RSA suite, RSA-PSS preferred over PKCS#1 v1.5" {
    for ([_]CipherSuite12{ .ecdhe_rsa_with_aes_128_gcm_sha256, .ecdhe_rsa_with_aes_256_gcm_sha384, .ecdhe_rsa_with_chacha20_poly1305_sha256 }) |s| {
        try roundTrip(rsaClientConfig(&.{s}), rsaServerConfig(&.{s}), s);
    }
}

test "dtls12: ECDHE_RSA with a peer that offers only PKCS#1 v1.5 (rsa_pkcs1_sha256)" {
    // A client whose `signature_algorithms` holds nothing but ECDSA: its
    // 1.2 advertisement is then {ecdsa_secp256r1_sha256, rsa_pkcs1_sha256,
    // rsa_pkcs1_sha384}, so the RSA server must sign with PKCS#1 v1.5.
    var ccfg = rsaClientConfig(&.{.ecdhe_rsa_with_aes_128_gcm_sha256});
    ccfg.signature_algorithms = &.{.ecdsa_secp256r1_sha256};
    try roundTrip(ccfg, rsaServerConfig(&.{.ecdhe_rsa_with_aes_128_gcm_sha256}), .ecdhe_rsa_with_aes_128_gcm_sha256);
}

test "dtls12: PSK (RFC 4279/5487) and ECDHE_PSK (RFC 5489/7905) self-interop, with and without a hint" {
    try roundTrip(pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256}), pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256}), .psk_with_aes_128_gcm_sha256);
    try roundTrip(pskConfig(.client, &.{.ecdhe_psk_with_chacha20_poly1305_sha256}), pskConfig(.server, &.{.ecdhe_psk_with_chacha20_poly1305_sha256}), .ecdhe_psk_with_chacha20_poly1305_sha256);
    var s = pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256});
    s.psk_identity_hint = "hint";
    try roundTrip(pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256}), s, .psk_with_aes_128_gcm_sha256);
}

test "dtls12: the server picks ITS preference among the client's suites" {
    const client_suites = [_]CipherSuite12{ .ecdhe_ecdsa_with_chacha20_poly1305_sha256, .ecdhe_ecdsa_with_aes_128_gcm_sha256 };
    const server_suites = [_]CipherSuite12{ .ecdhe_ecdsa_with_aes_256_gcm_sha384, .ecdhe_ecdsa_with_aes_128_gcm_sha256, .ecdhe_ecdsa_with_chacha20_poly1305_sha256 };
    try roundTrip(ecdsaClientConfig(&client_suites), ecdsaServerConfig(&server_suites), .ecdhe_ecdsa_with_aes_128_gcm_sha256);
}

test "dtls12: mutual authentication (RFC 5246 §7.4.4 CertificateRequest, §7.4.8 CertificateVerify)" {
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.request_client_cert = true;
    s.require_peer_cert = true;
    s.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
    var c = ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    c.cert = .{ .chain = &.{&cert_kat.client_cert_der}, .private_key = clientEcdsa() };
    try roundTrip(c, s, .ecdhe_ecdsa_with_aes_128_gcm_sha256);

    // The same server against a client with no certificate.
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(3)));
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    var server = try Connection12.serverInit(s);
    var bufs: Bufs = .{};
    try testing.expectError(error.PeerCertificateRequired, drive(&client, &server, seeded(&csprng), &bufs));
}

test "dtls12: an untrusted server certificate and a wrong expected name are rejected" {
    var c = ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    c.peer_verify = .{ .trust_anchor = &cert_kat.evil_anchor_cert_der };
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(4)));
    {
        var client = try Connection12.clientInit(c);
        var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
        var bufs: Bufs = .{};
        try testing.expectError(error.CertificateRejected, drive(&client, &server, seeded(&csprng), &bufs));
        // Rolled back: the client still waits for a ServerHello flight.
        try testing.expectEqual(c12.State.wait_server_hello, client.state);
    }
    c = ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    c.expected_peer_name = "someone-else";
    {
        var client = try Connection12.clientInit(c);
        var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
        var bufs: Bufs = .{};
        try testing.expectError(error.CertificateRejected, drive(&client, &server, seeded(&csprng), &bufs));
    }
}

test "dtls12: a wrong PSK fails at the server's Finished record (it cannot even open it), a wrong identity at ClientKeyExchange" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(5)));
    var c = pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256});
    c.psk = "not the key";
    {
        var client = try Connection12.clientInit(c);
        var server = try Connection12.serverInit(pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256}));
        var bufs: Bufs = .{};
        try testing.expectError(error.DecryptionFailed, drive(&client, &server, seeded(&csprng), &bufs));
    }
    c = pskConfig(.client, &.{.ecdhe_psk_with_chacha20_poly1305_sha256});
    c.psk_identity = "intruder";
    {
        var client = try Connection12.clientInit(c);
        var server = try Connection12.serverInit(pskConfig(.server, &.{.ecdhe_psk_with_chacha20_poly1305_sha256}));
        var bufs: Bufs = .{};
        try testing.expectError(error.NoMatchingPskIdentity, drive(&client, &server, seeded(&csprng), &bufs));
    }
}

test "dtls12: RFC 6347 §4.2.1 HelloVerifyRequest — stateless server, cookie bound to the peer" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(6)));
    const rnd = seeded(&csprng);
    var s = pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256});
    s.hello_retry = .{ .cookie_secret = "cookie secret", .peer_binding = "198.51.100.7:5684" };
    var client = try Connection12.clientInit(pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256}));
    var server = try Connection12.serverInit(s);
    var bufs: Bufs = .{};
    const ch1 = try client.startHandshake(rnd, 0, &bufs.a);
    const hvr = try server.handleFlight(ch1, rnd, 0, &bufs.b);
    // HVR in DTLS 1.0 framing, message_seq 0, the ClientHello's record seq.
    const hh = try handshake.decodeHeader(hvr.out[record.plaintext_header_len..]);
    try testing.expectEqual(m12.HandshakeType.hello_verify_request, hh.msg_type);
    try testing.expectEqual(c12.State.start, server.state); // kept nothing
    try testing.expectEqual(@as(usize, 0), server.transcript_len);
    const ch1_seq = (try record.decodePlaintext(ch1)).sequence_number;
    try testing.expectEqual(ch1_seq, (try record.decodePlaintext(hvr.out)).sequence_number);

    // The cookie does not verify for another peer: a second server bound to
    // a different address answers ClientHello2 with a fresh HVR.
    const r2 = try client.handleFlight(hvr.out, rnd, 0, &bufs.a);
    var ch2_copy: [2048]u8 = undefined;
    @memcpy(ch2_copy[0..r2.out.len], r2.out);
    const ch2 = ch2_copy[0..r2.out.len];
    var other_cfg = s;
    other_cfg.hello_retry = .{ .cookie_secret = "cookie secret", .peer_binding = "203.0.113.9:5684" };
    var other = try Connection12.serverInit(other_cfg);
    const again = try other.handleFlight(ch2, rnd, 0, &bufs.b);
    try testing.expectEqual(m12.HandshakeType.hello_verify_request, (try handshake.decodeHeader(again.out[record.plaintext_header_len..])).msg_type);

    // The right server accepts it: ServerHello carries message_seq 1.
    const f4 = try server.handleFlight(ch2, rnd, 0, &bufs.b);
    try testing.expectEqual(@as(u16, 1), (try handshake.decodeHeader(f4.out[record.plaintext_header_len..])).message_seq);
    const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect(f6.done);
    const fin = try client.handleFlight(f6.out, rnd, 0, &bufs.a);
    try testing.expect(fin.done);
    try exchangeData(&client, &server);
}

test "dtls12: retransmission under loss (RFC 6347 §4.2.4) — lost flight 4, lost flight 6" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(7)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    var bufs: Bufs = .{};
    var tmp: [8192]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    _ = try server.handleFlight(ch, rnd, 0, &bufs.b); // flight 4 LOST
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(500, &tmp));
    const ch_again = (try client.poll(1000, &tmp)).?;
    // The ClientHello is resent in a NEW record (fresh sequence number).
    try testing.expect((try record.decodePlaintext(ch_again)).sequence_number != (try record.decodePlaintext(ch)).sequence_number);
    // The server sees a duplicate ClientHello and resends flight 4.
    const f4 = try server.handleFlight(ch_again, rnd, 1000, &bufs.b);
    try testing.expect(f4.out.len > 0);
    const f5 = try client.handleFlight(f4.out, rnd, 1000, &bufs.a);
    var f5_copy: [8192]u8 = undefined;
    @memcpy(f5_copy[0..f5.out.len], f5.out);
    const f6 = try server.handleFlight(f5_copy[0..f5.out.len], rnd, 1000, &bufs.b);
    try testing.expect(f6.done and server.isConnected()); // flight 6 LOST
    try testing.expect(!client.isConnected());
    // The client times out and retransmits flight 5; the connected server
    // reports it from `recv` and answers from `poll`.
    const f5_again = (try client.poll(3000, &tmp)).?;
    var b: [256]u8 = undefined;
    try testing.expectError(error.ReceivedPostHandshakeMessage, server.recv(f5_again, &b));
    const f6_again = (try server.poll(3000, &bufs.b)).?;
    try testing.expectEqual(@as(?[]const u8, null), try server.poll(3000, &tmp));
    const done = try client.handleFlight(f6_again, rnd, 3000, &bufs.a);
    try testing.expect(done.done);
    try exchangeData(&client, &server);
}

test "dtls12: a tampered epoch-1 Finished fails and leaves the connection as it was" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(8)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256}));
    var server = try Connection12.serverInit(pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256}));
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
    var bad: [8192]u8 = undefined;
    @memcpy(bad[0..f5.out.len], f5.out);
    bad[f5.out.len - 1] ^= 1; // the Finished record's tag
    try testing.expectError(error.DecryptionFailed, server.handleFlight(bad[0..f5.out.len], rnd, 0, &bufs.b));
    try testing.expectEqual(c12.State.wait_client_flight, server.state);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect(f6.done);
}

// ── refusals on hand-built hellos ───────────────────────────────────────

fn buildRecord(t: u8, seq: u16, body: []const u8, out: []u8) []const u8 {
    var hh: [handshake.header_len]u8 = undefined;
    handshake.encodeHeader(.{ .msg_type = t, .length = @intCast(body.len), .message_seq = seq, .fragment_offset = 0, .fragment_length = @intCast(body.len) }, &hh);
    _ = record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = 0, .length = @intCast(body.len + 12) }, out) catch unreachable;
    @memcpy(out[13..25], &hh);
    @memcpy(out[25..][0..body.len], body);
    return out[0 .. 25 + body.len];
}

fn serverSeesHello(exts: []const m12.Extension, suites: []const u16) anyerror!void {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(9)));
    var server = try Connection12.serverInit(pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256}));
    var body_buf: [512]u8 = undefined;
    const body = try m12.encodeClientHello(.{ .random = @splat(1), .cipher_suites = suites, .extensions = exts }, &body_buf);
    var rec: [600]u8 = undefined;
    var out: [4096]u8 = undefined;
    _ = try server.handleFlight(buildRecord(1, 0, body, &rec), seeded(&csprng), 0, &out);
}

const ems_ext = m12.Extension{ .ext_type = m12.ext_extended_master_secret, .data = &.{} };
const ri_ext = m12.Extension{ .ext_type = m12.ext_renegotiation_info, .data = &m12.renegotiation_info_initial };

test "dtls12 server: RFC 7627 required, RFC 5746 required, renegotiation refused, SCSV accepted" {
    const psk_suite = [_]u16{0x00a8};
    try testing.expectError(error.ExtendedMasterSecretRequired, serverSeesHello(&.{ri_ext}, &psk_suite));
    try testing.expectError(error.SecureRenegotiationRequired, serverSeesHello(&.{ems_ext}, &psk_suite));
    const reneg = m12.Extension{ .ext_type = m12.ext_renegotiation_info, .data = &.{ 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 } };
    try testing.expectError(error.SecureRenegotiationRequired, serverSeesHello(&.{ ems_ext, reneg }, &psk_suite));
    // RFC 5746 §3.3: the SCSV stands in for the empty extension.
    try serverSeesHello(&.{ems_ext}, &.{ 0x00a8, m12.empty_renegotiation_info_scsv });
    try testing.expectError(error.NoCipherSuiteOverlap, serverSeesHello(&.{ ems_ext, ri_ext }, &.{0x002f}));
}

fn clientSeesServerHello(cfg: Config, random: [32]u8, exts: []const m12.Extension) anyerror!void {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(10)));
    var client = try Connection12.clientInit(cfg);
    var out: [4096]u8 = undefined;
    _ = try client.startHandshake(seeded(&csprng), 0, &out);
    var body_buf: [256]u8 = undefined;
    const body = try m12.encodeServerHello(.{ .random = random, .cipher_suite = 0x00a8, .extensions = exts }, &body_buf);
    var rec: [400]u8 = undefined;
    _ = try client.handleFlight(buildRecord(2, 0, body, &rec), seeded(&csprng), 0, &out);
}

test "dtls12 client: RFC 7627 / RFC 5746 refusals and the RFC 8446 §4.1.3 downgrade sentinel" {
    const cfg = pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256});
    try testing.expectError(error.ExtendedMasterSecretRequired, clientSeesServerHello(cfg, @splat(2), &.{ri_ext}));
    try testing.expectError(error.SecureRenegotiationRequired, clientSeesServerHello(cfg, @splat(2), &.{ems_ext}));
    // An extension the client never offered.
    try testing.expectError(error.Malformed, clientSeesServerHello(cfg, @splat(2), &.{ ems_ext, ri_ext, .{ .ext_type = 35, .data = &.{} } }));
    var sentinel_random: [32]u8 = @splat(2);
    sentinel_random[24..32].* = m12.downgrade_sentinel_12;
    // A 1.2-only client ignores the sentinel ...
    try clientSeesServerHello(cfg, sentinel_random, &.{ ems_ext, ri_ext });
    // ... a 1.3-capable one refuses it.
    var dual = cfg;
    dual.versions = &v_both;
    try testing.expectError(error.DowngradeDetected, clientSeesServerHello(dual, sentinel_random, &.{ ems_ext, ri_ext }));
    // EMS off by config: the same ServerHello without EMS is accepted.
    var lax = cfg;
    lax.require_extended_master_secret = false;
    try clientSeesServerHello(lax, @splat(2), &.{ri_ext});
}

// ── version negotiation (Endpoint) ──────────────────────────────────────

fn driveEndpoints(ccfg: Config, scfg: Config) !struct { conn13.ProtocolVersion, conn13.ProtocolVersion } {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(11)));
    var client = try Endpoint.clientInit(ccfg);
    defer client.deinit();
    var server = try Endpoint.serverInit(scfg);
    defer server.deinit();
    var bufs: Bufs = .{};
    try drive(&client, &server, seeded(&csprng), &bufs);
    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    const rec = try client.send("negotiated", &b1);
    try testing.expectEqualStrings("negotiated", try server.recv(rec, &b2));
    return .{ client.version(), server.version() };
}

test "Endpoint: dual client x {1.2-only, dual, 1.3-only} server; 1.2-only client x dual server" {
    const ps = [_]CipherSuite12{.psk_with_aes_128_gcm_sha256};
    var c_dual = pskConfig(.client, &ps);
    c_dual.versions = &v_both;
    var s_dual = pskConfig(.server, &ps);
    s_dual.versions = &v_both;
    const s12 = pskConfig(.server, &ps);
    const c12cfg = pskConfig(.client, &ps);
    var s13 = pskConfig(.server, &ps);
    s13.versions = &.{.dtls13};

    var r = try driveEndpoints(c_dual, s12);
    try testing.expectEqual(conn13.ProtocolVersion.dtls12, r[0]);
    try testing.expectEqual(conn13.ProtocolVersion.dtls12, r[1]);
    r = try driveEndpoints(c_dual, s_dual);
    try testing.expectEqual(conn13.ProtocolVersion.dtls13, r[0]);
    try testing.expectEqual(conn13.ProtocolVersion.dtls13, r[1]);
    r = try driveEndpoints(c_dual, s13);
    try testing.expectEqual(conn13.ProtocolVersion.dtls13, r[0]);
    // A 1.2-only client reaches a dual server's 1.2 engine (which marks its
    // random with the sentinel; this client cannot speak 1.3 so it does not
    // object).
    r = try driveEndpoints(c12cfg, s_dual);
    try testing.expectEqual(conn13.ProtocolVersion.dtls12, r[0]);
    try testing.expectEqual(conn13.ProtocolVersion.dtls12, r[1]);
}

test "Endpoint: certificate mode negotiates 1.2 against a 1.2-only server, through a HelloVerifyRequest" {
    var c = ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    c.versions = &v_both;
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.hello_retry = .{ .cookie_secret = "k", .peer_binding = "peer" };
    const r = try driveEndpoints(c, s);
    try testing.expectEqual(conn13.ProtocolVersion.dtls12, r[0]);
}

test "Endpoint: a dual client refuses a 1.2 answer from a server that could speak 1.3 (downgrade)" {
    // A man in the middle strips 1.3 from the client's hello; the server's
    // 1.2 engine, configured for both, marks its random. Simulated by
    // feeding the dual hello straight to that 1.2 engine.
    const ps = [_]CipherSuite12{.psk_with_aes_128_gcm_sha256};
    var c_dual = pskConfig(.client, &ps);
    c_dual.versions = &v_both;
    var s_dual = pskConfig(.server, &ps);
    s_dual.versions = &v_both;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(12)));
    const rnd = seeded(&csprng);
    var client = try Endpoint.clientInit(c_dual);
    var server = try Connection12.serverInit(s_dual);
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    try testing.expectError(error.DowngradeDetected, client.handleFlight(f4.out, rnd, 0, &bufs.a));
}

test "Config.validate: versions and 1.2 suites" {
    var c = pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256});
    c.versions = &.{};
    try testing.expectError(error.InvalidVersions, c.validate());
    c.versions = &.{ .dtls12, .dtls12 };
    try testing.expectError(error.InvalidVersions, c.validate());
    c.versions = &v12;
    c.cipher_suites12 = &.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}; // no PSK suite in .psk mode
    try testing.expectError(error.NoCipherSuites12, c.validate());
    c.cipher_suites12 = &.{@fromBackingInt(0x002f)};
    try testing.expectError(error.NoCipherSuites12, c.validate());
    // A 1.3-only config is untouched by the 1.2 fields.
    const c13 = Config{ .role = .client, .psk_identity = "id", .psk = "secret", .cipher_suites12 = &.{} };
    try c13.validate();
    try testing.expectError(error.InvalidVersions, Connection12.clientInit(c13));
}

/// Re-frames `flight` so the handshake message of type `split_type` travels
/// as two fragments in two datagrams (RFC 6347 §4.2.3), as a peer with a
/// small MTU sends a certificate chain.
fn splitFlight(flight: []const u8, split_type: u8, d1: []u8, d2: []u8) !struct { []const u8, []const u8 } {
    var n1: usize = 0;
    var n2: usize = 0;
    var second = false;
    var pos: usize = 0;
    while (pos < flight.len) {
        const hdr = try record.decodePlaintext(flight[pos..]);
        const rec = flight[pos..][0 .. record.plaintext_header_len + hdr.length];
        pos += rec.len;
        const frag = rec[record.plaintext_header_len..];
        if (hdr.content_type == 22 and hdr.epoch == 0 and frag[0] == split_type) {
            const hh = try handshake.decodeHeader(frag);
            const body = frag[handshake.header_len..];
            const half = body.len / 2;
            inline for (.{ 0, 1 }) |k| {
                const off: usize = if (k == 0) 0 else half;
                const part = if (k == 0) body[0..half] else body[half..];
                const dst = if (k == 0) d1[n1..] else d2[n2..];
                _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = hdr.sequence_number + k, .length = @intCast(handshake.header_len + part.len) }, dst);
                var h: [handshake.header_len]u8 = undefined;
                handshake.encodeHeader(.{ .msg_type = hh.msg_type, .length = hh.length, .message_seq = hh.message_seq, .fragment_offset = @intCast(off), .fragment_length = @intCast(part.len) }, &h);
                @memcpy(dst[13..25], &h);
                @memcpy(dst[25..][0..part.len], part);
                if (k == 0) n1 += 25 + part.len else n2 += 25 + part.len;
            }
            second = true;
            continue;
        }
        if (second) {
            // Every later record moves up by one: the second fragment took
            // the next record number (epoch-0 records are unauthenticated,
            // so renumbering them is what a fragmenting sender does anyway).
            @memcpy(d2[n2..][0..rec.len], rec);
            var renum = hdr;
            renum.sequence_number += 1;
            _ = try record.encodePlaintext(renum, d2[n2..]);
            n2 += rec.len;
        } else {
            @memcpy(d1[n1..][0..rec.len], rec);
            n1 += rec.len;
        }
    }
    return .{ d1[0..n1], d2[0..n2] };
}

test "dtls12: a Certificate fragmented across two datagrams is reassembled (RFC 6347 §4.2.3)" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(13)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    var d1: [4096]u8 = undefined;
    var d2: [4096]u8 = undefined;
    const parts = try splitFlight(f4.out, m12.HandshakeType.certificate, &d1, &d2);
    // The fragmenting sender used one more epoch-0 record number.
    server.send_seq[0] += 1;
    const r1 = try client.handleFlight(parts[0], rnd, 0, &bufs.a);
    try testing.expect(r1.need_more_data);
    try testing.expectEqual(c12.State.wait_server_hello_done, client.state);
    // The SAME first datagram again (a duplicate) changes nothing.
    _ = try client.handleFlight(parts[0], rnd, 0, &bufs.a);
    const f5 = try client.handleFlight(parts[1], rnd, 0, &bufs.a);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect(f6.done);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
    try exchangeData(&client, &server);
}

test "dtls12: a peer alert is error.ReceivedAlert, during and after the handshake" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(14)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256}));
    var server = try Connection12.serverInit(pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256}));
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    // A plaintext fatal handshake_failure(40) in epoch 0.
    var alert: [15]u8 = undefined;
    _ = try record.encodePlaintext(.{ .content_type = 21, .epoch = 0, .sequence_number = 0, .length = 2 }, &alert);
    alert[13] = 2;
    alert[14] = 40;
    try testing.expectError(error.ReceivedAlert, client.handleFlight(&alert, rnd, 0, &bufs.b));
    try testing.expectEqual(c12.State.wait_server_hello, client.state); // rolled back
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
    // After the handshake, an encrypted close_notify(0).
    var rec_buf: [64]u8 = undefined;
    const close = try @import("record12.zig").seal(&server.write_keys, 1, server.send_seq[1], 21, &.{ 1, 0 }, &rec_buf);
    var out: [64]u8 = undefined;
    try testing.expectError(error.ReceivedAlert, client.recv(close, &out));
    try testing.expectEqual([2]u8{ 1, 0 }, client.peer_alert.?);
}

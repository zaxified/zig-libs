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

/// After both RSA and the ECDSA fixtures' notBefore.
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

test "dtls12: the RFC 6655 / RFC 7251 AES-128-CCM and CCM_8 suites (RFC 7925's profile), PSK and ECDHE_ECDSA" {
    for ([_]CipherSuite12{ .psk_with_aes_128_ccm, .psk_with_aes_128_ccm_8 }) |s| {
        try roundTrip(pskConfig(.client, &.{s}), pskConfig(.server, &.{s}), s);
    }
    for ([_]CipherSuite12{ .ecdhe_ecdsa_with_aes_128_ccm, .ecdhe_ecdsa_with_aes_128_ccm_8 }) |s| {
        try roundTrip(ecdsaClientConfig(&.{s}), ecdsaServerConfig(&.{ .ecdhe_ecdsa_with_aes_128_gcm_sha256, s }), s);
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

test "CertConfig.rsa_blinding: the per-key cache serves every RSA signature (1.2 PSS and PKCS#1 v1.5 ServerKeyExchange, 1.3 CertificateVerify)" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5b)));
    var cache = rsa.BlindingCache.init(csprng.random());
    defer cache.deinit();

    // 1.2, RSA-PSS ServerKeyExchange: one op drawn from the cache.
    var scfg = rsaServerConfig(&.{.ecdhe_rsa_with_aes_128_gcm_sha256});
    scfg.cert.?.rsa_blinding = &cache;
    try roundTrip(rsaClientConfig(&.{.ecdhe_rsa_with_aes_128_gcm_sha256}), scfg, .ecdhe_rsa_with_aes_128_gcm_sha256);
    try testing.expectEqual(rsa.BlindingCache.refresh_every - 1, cache.left);

    // 1.2, PKCS#1 v1.5 (a client offering no PSS): the same pair, squared.
    var ccfg = rsaClientConfig(&.{.ecdhe_rsa_with_aes_128_gcm_sha256});
    ccfg.signature_algorithms = &.{.ecdsa_secp256r1_sha256};
    try roundTrip(ccfg, scfg, .ecdhe_rsa_with_aes_128_gcm_sha256);
    try testing.expectEqual(rsa.BlindingCache.refresh_every - 2, cache.left);

    // 1.3 CertificateVerify (RSA-PSS).
    const v13 = [_]conn13.ProtocolVersion{.dtls13};
    var s13 = scfg;
    s13.versions = &v13;
    var c13 = rsaClientConfig(scfg.cipher_suites12);
    c13.versions = &v13;
    var client = try conn13.Connection.clientInit(c13);
    defer client.deinit();
    var server = try conn13.Connection.serverInit(s13);
    defer server.deinit();
    var hs_csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5c)));
    const rnd = seeded(&hs_csprng);
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f2 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    const fin = try client.handleFlight(f2.out, rnd, 0, &bufs.a);
    try testing.expect(fin.done);
    try testing.expect((try server.handleFlight(fin.out, rnd, 0, &bufs.b)).done);
    try testing.expectEqual(rsa.BlindingCache.refresh_every - 3, cache.left);
    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    const rec = try client.send("rsa over 1.3", &b1);
    try testing.expectEqualStrings("rsa over 1.3", try server.recv(rec, &b2));
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

/// The extension types of the ServerHello a server answers `exts` with.
fn serverHelloExtensions(exts: []const m12.Extension, suites: []const u16, types: []u16) ![]const u16 {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(9)));
    var server = try Connection12.serverInit(pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256}));
    var body_buf: [512]u8 = undefined;
    const body = try m12.encodeClientHello(.{ .random = @splat(1), .cipher_suites = suites, .extensions = exts }, &body_buf);
    var rec: [600]u8 = undefined;
    var out: [4096]u8 = undefined;
    const r = try server.handleFlight(buildRecord(1, 0, body, &rec), seeded(&csprng), 0, &out);
    // The first record is the ServerHello.
    const sh = r.out[record.plaintext_header_len + handshake.header_len ..];
    var ext: [16]m12.Extension = undefined;
    const dec = try m12.decodeServerHello(sh[0 .. std.mem.readInt(u16, r.out[11..13], .big) - handshake.header_len], &ext);
    for (dec.extensions, 0..) |e, i| types[i] = e.ext_type;
    return types[0..dec.extensions.len];
}

test "dtls12 server: RFC 7627 required, renegotiation refused, RFC 5746 answered only when signalled" {
    const psk_suite = [_]u16{0x00a8};
    try testing.expectError(error.ExtendedMasterSecretRequired, serverSeesHello(&.{ri_ext}, &psk_suite));
    // RFC 5746 §4.3: a server that never renegotiates serves a client that
    // signals neither the extension nor the SCSV (OpenSSL, wolfSSL and
    // mbedTLS servers do; Debian's wolfSSL 1.2 client is one, found live) —
    // and then must not send the extension itself (RFC 5246 §7.4.1.4).
    try serverSeesHello(&.{ems_ext}, &psk_suite);
    var types: [16]u16 = undefined;
    const without = try serverHelloExtensions(&.{ems_ext}, &psk_suite, &types);
    try testing.expect(std.mem.indexOfScalar(u16, without, m12.ext_renegotiation_info) == null);
    const with_ext = try serverHelloExtensions(&.{ ems_ext, ri_ext }, &psk_suite, &types);
    try testing.expect(std.mem.indexOfScalar(u16, with_ext, m12.ext_renegotiation_info) != null);
    const with_scsv = try serverHelloExtensions(&.{ems_ext}, &.{ 0x00a8, m12.empty_renegotiation_info_scsv }, &types);
    try testing.expect(std.mem.indexOfScalar(u16, with_scsv, m12.ext_renegotiation_info) != null);
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

// ── send-side fragmentation and the receive queue (RFC 6347 §4.2.2/§4.2.3) ─

/// Cuts `blob` into datagrams the way a caller must (`record.nextDatagram`),
/// checking every datagram AND every record against `limit`.
fn datagramsOf(blob: []const u8, limit: usize, out: [][]const u8) ![]const []const u8 {
    var n: usize = 0;
    var rest = blob;
    while (rest.len > 0) {
        const s = record.nextDatagram(rest, limit);
        try testing.expect(s.datagram.len <= limit);
        out[n] = s.datagram;
        n += 1;
        rest = s.rest;
    }
    return out[0..n];
}

/// Feeds `dgs` to `conn` in reverse order, each twice (a duplicate right
/// after the original), and returns the first answer that came back, copied.
fn feedReversedTwice(conn: *Connection12, dgs: []const []const u8, rnd: Entropy, reply: []u8) ![]const u8 {
    var out: [8192]u8 = undefined;
    var reply_len: usize = 0;
    var i = dgs.len;
    while (i > 0) {
        i -= 1;
        for (0..2) |_| {
            const r = try conn.handleFlight(dgs[i], rnd, 0, &out);
            if (r.out.len == 0) continue;
            if (reply_len == 0) {
                @memcpy(reply[0..r.out.len], r.out);
                reply_len = r.out.len;
            } else {
                // A duplicate of an already-consumed datagram after the
                // answer went out: RFC 6347 §4.2.4 resends that answer.
                try testing.expectEqual(reply_len, r.out.len);
            }
        }
    }
    return reply[0..reply_len];
}

test "dtls12: Config.max_datagram_len fragments every large message; flights delivered reversed and duplicated still complete in one pass" {
    const limit = 200;
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.request_client_cert = true;
    s.require_peer_cert = true;
    s.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
    s.max_datagram_len = limit;
    var c = ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    c.cert = .{ .chain = &.{&cert_kat.client_cert_der}, .private_key = clientEcdsa() };
    c.max_datagram_len = limit;

    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(21)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(c);
    defer client.deinit();
    var server = try Connection12.serverInit(s);
    defer server.deinit();
    var bufs: Bufs = .{};
    var dg_buf: [64][]const u8 = undefined;
    var reply: [8192]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const ch_dgs = try datagramsOf(ch, limit, &dg_buf);
    var f4_copy: [8192]u8 = undefined;
    var f4: []const u8 = &.{};
    for (ch_dgs) |d| {
        const r = try server.handleFlight(d, rnd, 0, &bufs.b);
        if (r.out.len > 0) {
            @memcpy(f4_copy[0..r.out.len], r.out);
            f4 = f4_copy[0..r.out.len];
        }
    }
    // The server flight (Certificate ~0.5 KB) needs several datagrams.
    const f4_dgs = try datagramsOf(f4, limit, &dg_buf);
    try testing.expect(f4_dgs.len >= 3);
    const f5 = try feedReversedTwice(&client, f4_dgs, rnd, &reply);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    // Every queued copy was consumed or, once stale, discarded.
    try testing.expectEqual(@as(usize, 0), client.rx_future_len);
    // The client's final flight (its own Certificate) is fragmented too;
    // delivered in order, each datagram twice.
    var f5_copy: [8192]u8 = undefined;
    @memcpy(f5_copy[0..f5.len], f5);
    var dg5: [64][]const u8 = undefined;
    const f5_dgs = try datagramsOf(f5_copy[0..f5.len], limit, &dg5);
    try testing.expect(f5_dgs.len >= 3);
    var f6: []const u8 = &.{};
    var f6_copy: [1024]u8 = undefined;
    for (f5_dgs) |d| {
        for (0..2) |_| {
            const r = try server.handleFlight(d, rnd, 0, &bufs.b);
            if (r.done) {
                @memcpy(f6_copy[0..r.out.len], r.out);
                f6 = f6_copy[0..r.out.len];
            }
        }
    }
    try testing.expect(server.isConnected());
    try testing.expect((try client.handleFlight(f6, rnd, 0, &bufs.a)).done);
    try testing.expect(server.client_cert_presented);
    try exchangeData(&client, &server);
}

test "dtls12: a fragmented flight's retransmission (poll) is fragmented the same way" {
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.max_datagram_len = 160;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(22)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var server = try Connection12.serverInit(s);
    defer server.deinit();
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const first = try server.handleFlight(ch, rnd, 0, &bufs.b);
    var dg_buf: [64][]const u8 = undefined;
    const n_first = (try datagramsOf(first.out, 160, &dg_buf)).len;
    // Lost: the timer fires, the same messages go out again as fragments
    // under fresh record numbers.
    var again_buf: [8192]u8 = undefined;
    const again = (try server.poll(60_000, &again_buf)).?;
    try testing.expectEqual(first.out.len, again.len);
    try testing.expectEqual(n_first, (try datagramsOf(again, 160, &dg_buf)).len);
    var dg2: [64][]const u8 = undefined;
    for (try datagramsOf(again, 160, &dg2)) |d| _ = try client.handleFlight(d, rnd, 0, &bufs.a);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
}

test "dtls12: whole messages arriving in reverse order inside one datagram are queued, not dropped" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(23)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer server.deinit();
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    // ServerHello, Certificate, ServerKeyExchange, ServerHelloDone: one
    // record each. Re-pack them last-first into one datagram.
    var recs: [8][]const u8 = undefined;
    var n: usize = 0;
    var rest = f4.out;
    while (rest.len > 0) {
        const one = record.nextDatagram(rest, 1); // one record at a time
        recs[n] = one.datagram;
        n += 1;
        rest = one.rest;
    }
    try testing.expectEqual(@as(usize, 4), n);
    var rev: [8192]u8 = undefined;
    var len: usize = 0;
    var i = n;
    while (i > 0) {
        i -= 1;
        @memcpy(rev[len..][0..recs[i].len], recs[i]);
        len += recs[i].len;
    }
    // Two early copies of the ServerKeyExchange first: queued; the first
    // completes it, the second is then stale and must be discarded.
    // (The second copy under another record number, or the replay window
    // would drop it before the handshake layer sees it.)
    _ = try client.handleFlight(recs[2], rnd, 0, &bufs.a);
    var copy: [1024]u8 = undefined;
    @memcpy(copy[0..recs[2].len], recs[2]);
    copy[10] +%= 40;
    _ = try client.handleFlight(copy[0..recs[2].len], rnd, 0, &bufs.a);
    try testing.expectEqual(2 * (recs[2].len - record.plaintext_header_len + 1), client.rx_future_len);
    const f5 = try client.handleFlight(rev[0..len], rnd, 0, &bufs.a);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    try testing.expectEqual(@as(usize, 0), client.rx_future_len);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
    try exchangeData(&client, &server);
}

/// One epoch-0 handshake record carrying one fragment, `body_len` bytes of
/// `fill` at offset 0 of a message of `total` bytes.
fn forgedFragment(seq: u48, msg_type: u8, message_seq: u16, total: u24, body_len: u16, fill: u8, out: []u8) []const u8 {
    const len = handshake.header_len + body_len;
    _ = record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = seq, .length = @intCast(len) }, out) catch unreachable;
    handshake.encodeHeader(.{ .msg_type = msg_type, .length = total, .message_seq = message_seq, .fragment_offset = 0, .fragment_length = body_len }, out[record.plaintext_header_len..][0..handshake.header_len]);
    @memset(out[record.plaintext_header_len + handshake.header_len ..][0..body_len], fill);
    return out[0 .. record.plaintext_header_len + len];
}

test "dtls12: a flood of forged later-message fragments stays inside the queue bound and cannot wedge the genuine flight" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(24)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer server.deinit();
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);

    // 4000 forged fragments: message_seq 1..8 (inside the queue window)
    // over and over, each with different content, plus every tenth one far
    // ahead — far more than the queue holds. A forged message that is
    // COMPLETE (seq 2, 40 of 40 bytes) is in there too.
    var rec_buf: [512]u8 = undefined;
    var seq: u48 = 1000;
    var k: u16 = 0;
    while (k < 4000) : (k += 1) {
        const ms: u16 = if (k % 10 == 9) 9 + k else 1 + k % 8;
        const d = if (ms == 2)
            forgedFragment(seq, m12.HandshakeType.certificate, ms, 40, 40, @truncate(k), &rec_buf)
        else
            forgedFragment(seq, m12.HandshakeType.certificate, ms, 900, 300, @truncate(k), &rec_buf);
        seq += 1;
        const r = try client.handleFlight(d, rnd, 0, &bufs.a);
        try testing.expectEqual(@as(usize, 0), r.out.len);
        try testing.expect(client.rx_future_len <= client.rx_future.len);
    }
    try testing.expect(client.rx_future_len > client.rx_future.len - 400); // it did fill up
    try testing.expectEqual(c12.State.wait_server_hello, client.state);

    // The genuine flight still completes: the queued forgeries make the
    // first pass fail, and the datagram is retried from live bytes alone.
    // Its record numbers (from 0) are far below the forged ones (from
    // 1000): queued forgeries are not recorded in the epoch-0 window.
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
    try exchangeData(&client, &server);

    // Only the window is queued: far-ahead fragments are not.
    var c2 = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer c2.deinit();
    _ = try c2.startHandshake(rnd, 0, &bufs.a);
    _ = try c2.handleFlight(forgedFragment(7, m12.HandshakeType.certificate, 9, 40, 40, 1, &rec_buf), rnd, 0, &bufs.a);
    try testing.expectEqual(@as(usize, 0), c2.rx_future_len);
    _ = try c2.handleFlight(forgedFragment(8, m12.HandshakeType.certificate, 8, 40, 40, 1, &rec_buf), rnd, 0, &bufs.a);
    try testing.expectEqual(@as(usize, 13 + 40), c2.rx_future_len);

    // A stateless server at `.start` keeps nothing at all.
    var s2 = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer s2.deinit();
    _ = try s2.handleFlight(forgedFragment(5, m12.HandshakeType.client_key_exchange, 3, 40, 40, 1, &rec_buf), rnd, 0, &bufs.b);
    try testing.expectEqual(@as(usize, 0), s2.rx_future_len);
}

test "dtls12: an injected epoch-0 record with a huge record number does not make the genuine flights stale" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(25)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer server.deinit();
    var bufs: Bufs = .{};
    var rec_buf: [512]u8 = undefined;
    const huge: u48 = std.math.maxInt(u48);
    const ccs = [_]u8{ 20, 0xfe, 0xfd, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 1 };

    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    // Off-path: a later message's fragment and a stray ChangeCipherSpec,
    // both at the top of the sequence space, ahead of the server's flight.
    _ = try client.handleFlight(forgedFragment(huge, m12.HandshakeType.certificate, 3, 900, 300, 1, &rec_buf), rnd, 0, &bufs.a);
    _ = try client.handleFlight(&ccs, rnd, 0, &bufs.a);
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    // The same against the server, ahead of the client's second flight.
    _ = try server.handleFlight(forgedFragment(huge, m12.HandshakeType.finished, 9, 12, 12, 1, &rec_buf), rnd, 0, &bufs.b);
    _ = try server.handleFlight(&ccs, rnd, 0, &bufs.b);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
    try exchangeData(&client, &server);
}

test "dtls12: one forged 1-byte hello fragment with a huge record number does not wedge the handshake (review F1)" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(26)));
    const rnd = seeded(&csprng);
    const huge: u48 = std.math.maxInt(u48);
    var rec_buf: [512]u8 = undefined;
    // Client side: a ServerHello fragment (type 2, length 500, message_seq 0,
    // one byte 0xfe) ahead of the genuine flight. It is taken into the
    // reassembler; it must neither shadow the genuine records in the window
    // nor wedge the reassembly.
    {
        var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
        defer client.deinit();
        var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
        defer server.deinit();
        var bufs: Bufs = .{};
        const ch = try client.startHandshake(rnd, 0, &bufs.a);
        _ = try client.handleFlight(forgedFragment(huge, m12.HandshakeType.server_hello, 0, 500, 1, 0xfe, &rec_buf), rnd, 0, &bufs.a);
        try testing.expect(!client.recv_win[0].seen_any);
        const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
        const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
        try testing.expectEqual(c12.State.wait_server_finished, client.state);
        const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
        try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
        try exchangeData(&client, &server);
    }
    // Server side: a ClientHello fragment, under the genuine message_seq and
    // under another one.
    for ([_]u16{ 0, 5 }) |ms| {
        var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
        defer client.deinit();
        var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
        defer server.deinit();
        var bufs: Bufs = .{};
        const ch = try client.startHandshake(rnd, 0, &bufs.a);
        _ = try server.handleFlight(forgedFragment(huge, m12.HandshakeType.client_hello, ms, 500, 1, 0xfe, &rec_buf), rnd, 0, &bufs.b);
        try testing.expect(!server.recv_win[0].seen_any);
        const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
        try testing.expect(f4.out.len > 0);
        const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
        const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
        try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
        try exchangeData(&client, &server);
    }
}

test "dtls12: a forged early ChangeCipherSpec with a huge record number is taken but not recorded (review F1)" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(27)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer server.deinit();
    var bufs: Bufs = .{};
    const ccs = [_]u8{ 20, 0xfe, 0xfd, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 1 };
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
    const high = client.recv_win[0].high;
    // The client now expects the server's CCS: the forged one is accepted
    // (epoch 0 cannot tell), but its record number goes nowhere.
    _ = try client.handleFlight(&ccs, rnd, 0, &bufs.a);
    try testing.expectEqual(@as(u16, 1), client.read_epoch);
    try testing.expectEqual(high, client.recv_win[0].high);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
    try exchangeData(&client, &server);
}

test "dtls12: a fragmented flight whose record numbers jumped far ahead (lost retransmissions) still completes" {
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.max_datagram_len = 160;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(28)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var server = try Connection12.serverInit(s);
    defer server.deinit();
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const first = try server.handleFlight(ch, rnd, 0, &bufs.b);
    var dg_buf: [64][]const u8 = undefined;
    // Only the first datagram arrives; then many copies are lost and the
    // next one carries record numbers far past the window.
    const firsts = try datagramsOf(first.out, 160, &dg_buf);
    _ = try client.handleFlight(firsts[0], rnd, 0, &bufs.a);
    server.send_seq[0] += 10_000;
    var again_buf: [8192]u8 = undefined;
    const again = (try server.poll(60_000, &again_buf)).?;
    var dg2: [64][]const u8 = undefined;
    var last: c12.HandshakeResult = undefined;
    for (try datagramsOf(again, 160, &dg2)) |d| last = try client.handleFlight(d, rnd, 0, &bufs.a);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    const f6 = try server.handleFlight(last.out, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
    try exchangeData(&client, &server);
}

test "Config.validate: max_datagram_len below the floor" {
    var c = pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256});
    c.max_datagram_len = conn13.min_max_datagram_len - 1;
    try testing.expectError(error.MaxDatagramLenTooSmall, c.validate());
    c.max_datagram_len = conn13.min_max_datagram_len;
    try c.validate();
    c.max_datagram_len = 0;
    try c.validate();
}

/// Records in `bytes` (each one, not datagrams).
fn countRecords(bytes: []const u8) usize {
    var n: usize = 0;
    var rest = bytes;
    while (rest.len > 0) : (n += 1) rest = record.nextDatagram(rest, 1).rest;
    return n;
}

/// The largest record in `bytes`.
fn largestRecord(bytes: []const u8) usize {
    var m: usize = 0;
    var rest = bytes;
    while (rest.len > 0) {
        const d = record.nextDatagram(rest, 1);
        m = @max(m, d.datagram.len);
        rest = d.rest;
    }
    return m;
}

fn serverFlight4(limit: u16, out: []u8) ![]const u8 {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(25)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.max_datagram_len = limit;
    var server = try Connection12.serverInit(s);
    defer server.deinit();
    var ch_buf: [2048]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &ch_buf);
    return (try server.handleFlight(ch, rnd, 0, out)).out;
}

test "dtls12: a record of exactly max_datagram_len is not fragmented, one byte over is; a short output buffer is BufferTooShort" {
    var b0: [8192]u8 = undefined;
    const whole = try serverFlight4(0, &b0);
    const biggest = largestRecord(whole); // the Certificate's record
    try testing.expect(biggest > 300);
    var b1: [8192]u8 = undefined;
    const at = try serverFlight4(@intCast(biggest), &b1);
    try testing.expectEqual(countRecords(whole), countRecords(at));
    try testing.expectEqualSlices(u8, whole, at);
    var b2: [8192]u8 = undefined;
    const under = try serverFlight4(@intCast(biggest - 1), &b2);
    try testing.expectEqual(countRecords(whole) + 1, countRecords(under));
    try testing.expectEqual(biggest - 1, largestRecord(under));
    // The fragment loop checks its room before writing: too small an
    // output buffer is a typed error, not a write past it.
    var small: [400]u8 = undefined;
    try testing.expectError(error.BufferTooShort, serverFlight4(200, &small));
}

test "dtls12: a forged queued fragment latched by an EARLIER call is dropped when the genuine message conflicts" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(26)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer server.deinit();
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    server.send_seq[0] = 100;
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    // A forged partial Certificate (message_seq 1), queued ahead.
    var rec_buf: [512]u8 = undefined;
    _ = try client.handleFlight(forgedFragment(5, m12.HandshakeType.certificate, 1, 900, 300, 0xee, &rec_buf), rnd, 0, &bufs.a);
    try testing.expect(client.rx_future_len > 0);
    // The genuine ServerHello alone: it completes, the queue is drained into
    // the reassembler — the forged bytes are now the message in progress.
    const sh = record.nextDatagram(f4.out, 1);
    _ = try client.handleFlight(sh.datagram, rnd, 0, &bufs.a);
    try testing.expect(client.rx_active);
    // The genuine rest of the flight conflicts with them; the retry without
    // the queue must also forget the message in progress.
    const f5 = try client.handleFlight(sh.rest, rnd, 0, &bufs.a);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
}

test "dtls12: fragmenting at the end of the epoch-0 sequence space is SequenceNumberExhausted" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(27)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.max_datagram_len = 200;
    var server = try Connection12.serverInit(s);
    defer server.deinit();
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    // ServerHello takes max-2, the first Certificate fragment max-1, the
    // second would need max: refused, never wrapped.
    server.send_seq[0] = std.math.maxInt(u48) - 2;
    try testing.expectError(error.SequenceNumberExhausted, server.handleFlight(ch, rnd, 0, &bufs.b));
}

/// The records of `bytes`, one slice each.
fn recordsOf(bytes: []const u8, out: [][]const u8) []const []const u8 {
    var n: usize = 0;
    var rest = bytes;
    while (rest.len > 0) : (n += 1) {
        const d = record.nextDatagram(rest, 1);
        out[n] = d.datagram;
        rest = d.rest;
    }
    return out[0..n];
}

/// `message_seq` / `msg_type` of an epoch-0 handshake record.
fn recMsgSeq(rec: []const u8) u16 {
    return std.mem.readInt(u16, rec[record.plaintext_header_len + 4 ..][0..2], .big);
}

test "dtls12: a retry after a queued message failed sends ONE answer, not the failed pass's output plus the retry's" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(28)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var server = try Connection12.serverInit(ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer server.deinit();
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    // A complete forged message 4, right after ServerHelloDone (3). The
    // first pass writes the final flight, then fails on it.
    var rec_buf: [128]u8 = undefined;
    _ = try client.handleFlight(forgedFragment(50, m12.HandshakeType.certificate, 4, 40, 40, 7, &rec_buf), rnd, 0, &bufs.a);
    const f5 = try client.handleFlight(f4.out, rnd, 0, &bufs.a);
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    try testing.expectEqual(@as(usize, 3), countRecords(f5.out)); // ClientKeyExchange, CCS, Finished
    const f6 = try server.handleFlight(f5.out, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
}

test "dtls12: once a message completed from the queue, a forged fragment cannot evict a genuine partial message" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(29)));
    const rnd = seeded(&csprng);
    var client = try Connection12.clientInit(ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256}));
    defer client.deinit();
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.max_datagram_len = conn13.min_max_datagram_len; // the ServerKeyExchange is fragmented too
    var server = try Connection12.serverInit(s);
    defer server.deinit();
    var bufs: Bufs = .{};
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f4 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    var rbuf: [64][]const u8 = undefined;
    const recs = recordsOf(f4.out, &rbuf);
    var ske_first: ?usize = null;
    // Every Certificate fragment (message 1) first: all queued.
    for (recs, 0..) |r, i| switch (recMsgSeq(r)) {
        1 => _ = try client.handleFlight(r, rnd, 0, &bufs.a),
        2 => if (ske_first == null) {
            ske_first = i;
        },
        else => {},
    };
    // The ServerHello: it completes, and the Certificate completes from the queue.
    _ = try client.handleFlight(recs[0], rnd, 0, &bufs.a);
    try testing.expectEqual(@as(u16, 2), client.next_recv_seq);
    // The first half of the ServerKeyExchange, live.
    _ = try client.handleFlight(recs[ske_first.?], rnd, 0, &bufs.a);
    try testing.expect(client.rx_active);
    const filled = client.rx_filled;
    // A forged fragment of it with another length: refused, nothing moves.
    var rec_buf: [128]u8 = undefined;
    try testing.expectError(error.InconsistentLength, client.handleFlight(forgedFragment(60, m12.HandshakeType.server_key_exchange, 2, 999, 10, 1, &rec_buf), rnd, 0, &bufs.a));
    try testing.expectEqual(filled, client.rx_filled);
    // The rest, in order: the handshake completes on the genuine bytes.
    var f5: []const u8 = &.{};
    for (recs[ske_first.? + 1 ..]) |r| {
        const res = try client.handleFlight(r, rnd, 0, &bufs.a);
        if (res.out.len > 0) f5 = res.out;
    }
    try testing.expectEqual(c12.State.wait_server_finished, client.state);
    const f6 = try server.handleFlight(f5, rnd, 0, &bufs.b);
    try testing.expect((try client.handleFlight(f6.out, rnd, 0, &bufs.a)).done);
}

test "dtls12: use_srtp (RFC 5764) in the hellos, server preference, same SRTP keying material" {
    var c = pskConfig(.client, &.{.psk_with_aes_128_gcm_sha256});
    c.srtp_profiles = &.{ 0x0001, 0x0007 };
    var s = pskConfig(.server, &.{.psk_with_aes_128_gcm_sha256});
    s.srtp_profiles = &.{ 0x0007, 0x0001 };
    var client = try Connection12.clientInit(c);
    defer client.deinit();
    var server = try Connection12.serverInit(s);
    defer server.deinit();
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x82)));
    var bufs: Bufs = undefined;
    try drive(&client, &server, seeded(&csprng), &bufs);
    try testing.expectEqual(@as(?u16, 0x0007), client.negotiatedSrtpProfile());
    try testing.expectEqual(@as(?u16, 0x0007), server.negotiatedSrtpProfile());
    var kc: [60]u8 = undefined;
    var ks: [60]u8 = undefined;
    try client.exportKeyingMaterial("EXTRACTOR-dtls_srtp", null, &kc);
    try server.exportKeyingMaterial("EXTRACTOR-dtls_srtp", null, &ks);
    try testing.expectEqualSlices(u8, &kc, &ks);
}

test "dtls12: PeerVerify.chain builds the path through the intermediate (and refuses without it)" {
    const sk = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.chain_leaf_secret_key_bytes);
    const roots = [_][]const u8{&cert_kat.chain_root_cert_der};
    var c = ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    c.peer_verify = .{ .chain = .{ .trust_anchors = &roots, .required_eku = .server_auth } };
    c.expected_peer_name = "dtls-chain.test";
    var s = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    s.cert = .{ .chain = &.{ &cert_kat.chain_leaf_cert_der, &cert_kat.chain_inter_cert_der }, .private_key = .{ .ecdsa_p256 = &sk } };
    try roundTrip(c, s, .ecdhe_ecdsa_with_aes_128_gcm_sha256);
    s.cert = .{ .chain = &.{&cert_kat.chain_leaf_cert_der}, .private_key = .{ .ecdsa_p256 = &sk } };
    var client = try Connection12.clientInit(c);
    defer client.deinit();
    var server = try Connection12.serverInit(s);
    defer server.deinit();
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x84)));
    var bufs: Bufs = undefined;
    try testing.expectError(error.CertificateRejected, drive(&client, &server, seeded(&csprng), &bufs));
}

// ── connection ID (RFC 9146) ─────────────────────────────────────────────

fn cidPair(c_cid: ?[]const u8, s_cid: ?[]const u8, suite: CipherSuite12, client: *Connection12, server: *Connection12) !void {
    var ccfg = pskConfig(.client, &.{suite});
    ccfg.connection_id = c_cid;
    var scfg = pskConfig(.server, &.{suite});
    scfg.connection_id = s_cid;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x91)));
    client.* = try Connection12.clientInit(ccfg);
    server.* = try Connection12.serverInit(scfg);
    var bufs: Bufs = .{};
    try drive(client, server, seeded(&csprng), &bufs);
}

test "dtls12 CID (RFC 9146): both sides ask for one, every epoch-1 record is tls12_cid with the receiver's CID" {
    for ([_]CipherSuite12{ .psk_with_aes_128_gcm_sha256, .ecdhe_psk_with_chacha20_poly1305_sha256, .psk_with_aes_128_ccm_8 }) |suite| {
        var client: Connection12 = undefined;
        var server: Connection12 = undefined;
        try cidPair("cli", "a-server-cid-1234", suite, &client, &server);
        defer client.deinit();
        defer server.deinit();
        try testing.expectEqualStrings("a-server-cid-1234", client.peerConnectionId().?);
        try testing.expectEqualStrings("cli", server.peerConnectionId().?);
        var b1: [256]u8 = undefined;
        var b2: [256]u8 = undefined;
        const rec = try client.send("over a cid", &b1);
        try testing.expectEqual(@as(u8, 25), rec[0]);
        try testing.expectEqualStrings("a-server-cid-1234", rec[11..][0..17]);
        try testing.expectEqualStrings("over a cid", try server.recv(rec, &b2));
        const back = try server.send("back", &b1);
        try testing.expectEqualStrings("cli", back[11..][0..3]);
        try testing.expectEqualStrings("back", try client.recv(back, &b2));
        // Another CID, or none, is invalid (RFC 9146 §3).
        const rec2 = try client.send("x", &b1);
        var wrong: [256]u8 = undefined;
        @memcpy(wrong[0..rec2.len], rec2);
        wrong[11] ^= 1;
        try testing.expectError(error.Malformed, server.recv(wrong[0..rec2.len], &b2));
        try testing.expectEqualStrings("x", try server.recv(rec2, &b2));
    }
}

test "dtls12 CID: an empty CID means the peer sends none; a server without one does not negotiate" {
    {
        var client: Connection12 = undefined;
        var server: Connection12 = undefined;
        try cidPair("", "srv-cid", .psk_with_aes_128_gcm_sha256, &client, &server);
        defer client.deinit();
        defer server.deinit();
        try testing.expectEqualStrings("srv-cid", client.peerConnectionId().?);
        try testing.expect(server.peerConnectionId() == null);
        var b1: [256]u8 = undefined;
        var b2: [256]u8 = undefined;
        const up = try client.send("up", &b1);
        try testing.expectEqual(@as(u8, 25), up[0]);
        try testing.expectEqualStrings("up", try server.recv(up, &b2));
        const down = try server.send("down", &b1);
        try testing.expectEqual(@as(u8, 23), down[0]); // plain RFC 6347 record
        try testing.expectEqualStrings("down", try client.recv(down, &b2));
        // The server expects its CID: a plain record from the client is refused.
        var plain12 = client;
        plain12.cid_peer_len = 0;
        const bare = try plain12.send("bare", &b1);
        try testing.expectError(error.Malformed, server.recv(bare, &b2));
    }
    {
        var client: Connection12 = undefined;
        var server: Connection12 = undefined;
        try cidPair("cli", null, .psk_with_aes_128_gcm_sha256, &client, &server);
        defer client.deinit();
        defer server.deinit();
        try testing.expect(!client.cid_negotiated and !server.cid_negotiated);
        try exchangeData(&client, &server);
    }
}

test "dtls12 CID: fragmented flights cut with nextDatagramCid, certificate mode" {
    var ccfg = ecdsaClientConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    ccfg.connection_id = "c1";
    ccfg.max_datagram_len = 200;
    var scfg = ecdsaServerConfig(&.{.ecdhe_ecdsa_with_aes_128_gcm_sha256});
    scfg.connection_id = "s-22";
    scfg.max_datagram_len = 200;
    var client = try Connection12.clientInit(ccfg);
    defer client.deinit();
    var server = try Connection12.serverInit(scfg);
    defer server.deinit();
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x92)));
    const rnd = seeded(&csprng);
    var a: [8192]u8 = undefined;
    var b: [8192]u8 = undefined;
    var to_server: []const u8 = try client.startHandshake(rnd, 0, &a);
    var rounds: usize = 0;
    while (!(client.isConnected() and server.isConnected())) : (rounds += 1) {
        if (rounds > 8) return error.TestHandshakeDidNotComplete;
        var rest = to_server;
        var s_out: []const u8 = &.{};
        while (rest.len > 0) {
            const sp = record.nextDatagramCid(rest, 200, if (client.peerConnectionId()) |c| c.len else 0);
            try testing.expect(sp.datagram.len <= 200);
            const r = try server.handleFlight(sp.datagram, rnd, 0, &b);
            if (r.out.len > 0) s_out = r.out;
            rest = sp.rest;
        }
        if (client.isConnected() and server.isConnected()) break;
        rest = s_out;
        var c_out: []const u8 = &.{};
        while (rest.len > 0) {
            const sp = record.nextDatagramCid(rest, 200, if (server.peerConnectionId()) |c| c.len else 0);
            try testing.expect(sp.datagram.len <= 200);
            const r = try client.handleFlight(sp.datagram, rnd, 0, &a);
            if (r.out.len > 0) c_out = r.out;
            rest = sp.rest;
        }
        to_server = c_out;
    }
    try testing.expectEqualStrings("s-22", client.peerConnectionId().?);
    try exchangeData(&client, &server);
}

// ── RFC 5077 session tickets, abbreviated handshake (RFC 5246 §7.3) ───────

const tlsresume = @import("tlsresume");
const TestTicketer12 = conn13.StekTicketer(tlsresume.stek.DefaultRing);

fn ticketRing12() tlsresume.stek.DefaultRing {
    var ring: tlsresume.stek.DefaultRing = .init();
    ring.rotate(7, &@as([32]u8, @splat(0x24)), now_sec);
    return ring;
}

/// A full handshake whose client asks for a ticket; returns it.
fn ticket12(ccfg: Config, scfg: Config, seed: u8) !conn13.SessionTicket12 {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(seed)));
    const rnd = seeded(&csprng);
    var cc = ccfg;
    cc.session_tickets12 = true;
    var client = try Connection12.clientInit(cc);
    defer client.deinit();
    var server = try Connection12.serverInit(scfg);
    defer server.deinit();
    var bufs: Bufs = .{};
    try drive(&client, &server, rnd, &bufs);
    try testing.expect(!client.resumed() and !server.resumed());
    try exchangeData(&client, &server);
    return (client.sessionTicket() orelse return error.TestNoTicket).*;
}

fn resume12(ccfg: Config, scfg: Config, t: *const conn13.SessionTicket12, seed: u8, want_resumed: bool) !void {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(seed)));
    const rnd = seeded(&csprng);
    var cc = ccfg;
    cc.resumption12 = t;
    var client = try Connection12.clientInit(cc);
    defer client.deinit();
    var server = try Connection12.serverInit(scfg);
    defer server.deinit();
    var bufs: Bufs = .{};
    try drive(&client, &server, rnd, &bufs);
    try testing.expectEqual(want_resumed, client.resumed());
    try testing.expectEqual(want_resumed, server.resumed());
    try exchangeData(&client, &server);
    if (want_resumed) {
        // A ticket was asked for again (the extension carried the old one):
        // a fresh one came with the abbreviated flight.
        const fresh = client.sessionTicket() orelse return error.TestNoTicket;
        try testing.expect(!std.mem.eql(u8, fresh.identity(), t.identity()));
    }
}

test "dtls12: RFC 5077 ticket from a full handshake resumes with an abbreviated one (ECDHE_ECDSA, PSK, ECDHE_PSK)" {
    var ring = ticketRing12();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    const Pair = struct { c: Config, s: Config };
    const ecdsa = [_]CipherSuite12{.ecdhe_ecdsa_with_aes_128_gcm_sha256};
    const psk = [_]CipherSuite12{.psk_with_aes_128_gcm_sha256};
    const epsk = [_]CipherSuite12{.ecdhe_psk_with_chacha20_poly1305_sha256};
    var pairs = [_]Pair{
        .{ .c = ecdsaClientConfig(&ecdsa), .s = ecdsaServerConfig(&ecdsa) },
        .{ .c = pskConfig(.client, &psk), .s = pskConfig(.server, &psk) },
        .{ .c = pskConfig(.client, &epsk), .s = pskConfig(.server, &epsk) },
    };
    for (&pairs, 0..) |*p, i| {
        p.s.tickets = .{ .ticketer = tkr.ticketer() };
        p.s.now_sec = now_sec;
        p.c.now_sec = now_sec;
        var t = try ticket12(p.c, p.s, @intCast(0x30 + i));
        defer t.wipe();
        try testing.expect(t.ems);
        try testing.expectEqual(@as(u32, 12 * 3600), t.lifetime_hint_s);
        try resume12(p.c, p.s, &t, @intCast(0x40 + i), true);
    }
}

test "dtls12: an unusable ticket, or a server without tickets, runs the full handshake" {
    var ring = ticketRing12();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    const ecdsa = [_]CipherSuite12{.ecdhe_ecdsa_with_aes_128_gcm_sha256};
    var scfg = ecdsaServerConfig(&ecdsa);
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var t = try ticket12(ecdsaClientConfig(&ecdsa), scfg, 0x50);
    defer t.wipe();

    // No tickets on the server: the extension is ignored, no ticket issued.
    var plain = ecdsaServerConfig(&ecdsa);
    plain.now_sec = now_sec;
    try resume12(ecdsaClientConfig(&ecdsa), plain, &t, 0x51, false);
    // A corrupted ticket, an expired one: full handshakes.
    var bad = t;
    bad.ticket[5] ^= 1;
    try resume12(ecdsaClientConfig(&ecdsa), scfg, &bad, 0x52, false);
    var late = scfg;
    late.now_sec = now_sec + 12 * 3600 + 1;
    try resume12(ecdsaClientConfig(&ecdsa), late, &t, 0x53, false);
    // A suite the client no longer offers: full handshake in another suite.
    const other = [_]CipherSuite12{.ecdhe_ecdsa_with_aes_256_gcm_sha384};
    var scfg2 = ecdsaServerConfig(&.{ .ecdhe_ecdsa_with_aes_128_gcm_sha256, .ecdhe_ecdsa_with_aes_256_gcm_sha384 });
    scfg2.tickets = scfg.tickets;
    try resume12(ecdsaClientConfig(&other), scfg2, &t, 0x54, false);
}

test "dtls12: abbreviated handshake under loss — the client's final flight lost, resent on the server's retransmission" {
    var ring = ticketRing12();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    const ecdsa = [_]CipherSuite12{.ecdhe_ecdsa_with_aes_128_gcm_sha256};
    var scfg = ecdsaServerConfig(&ecdsa);
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var t = try ticket12(ecdsaClientConfig(&ecdsa), scfg, 0x60);
    defer t.wipe();

    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x61)));
    const rnd = seeded(&csprng);
    var cc = ecdsaClientConfig(&ecdsa);
    cc.resumption12 = &t;
    var client = try Connection12.clientInit(cc);
    defer client.deinit();
    var server = try Connection12.serverInit(scfg);
    defer server.deinit();
    var bufs: Bufs = .{};
    var tmp: [8192]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &bufs.a);
    const f2 = try server.handleFlight(ch, rnd, 0, &bufs.b);
    try testing.expect(!server.isConnected());
    const f3 = try client.handleFlight(f2.out, rnd, 0, &bufs.a);
    try testing.expect(f3.done and client.isConnected() and client.resumed()); // f3 LOST
    // The server times out and resends its flight; the connected client
    // reports it from `recv` and answers from `poll`.
    const f2_again = (try server.poll(1000, &tmp)).?;
    var b: [256]u8 = undefined;
    var rest = f2_again;
    var saw = false;
    while (rest.len > 0) {
        const h = try record.decodePlaintext(rest);
        const n = record.plaintext_header_len + h.length;
        if (client.recv(rest[0..n], &b)) |_| return error.TestUnexpectedData else |e| switch (e) {
            error.ReceivedPostHandshakeMessage => saw = true,
            else => return e,
        }
        rest = rest[n..];
    }
    try testing.expect(saw);
    const f3_again = (try client.poll(1000, &tmp)).?;
    const done = try server.handleFlight(f3_again, rnd, 1000, &bufs.b);
    try testing.expect(done.done and server.isConnected() and server.resumed());
    try exchangeData(&client, &server);
}

test "dtls12: OCSP staple (CertificateStatus, RFC 6066 §8) and SCT list (ServerHello, RFC 6962 §3.3.1) when asked for" {
    const staple = "\x30\x03\x0a\x01\x00";
    const scts = "\x00\x06\x00\x04\x05\x06\x07\x08";
    const ecdsa = [_]CipherSuite12{.ecdhe_ecdsa_with_aes_128_gcm_sha256};
    for ([_]bool{ true, false }) |ask| {
        var scfg = ecdsaServerConfig(&ecdsa);
        scfg.cert.?.ocsp_response = staple;
        scfg.cert.?.sct_list = scts;
        var ccfg = ecdsaClientConfig(&ecdsa);
        ccfg.request_ocsp = ask;
        ccfg.request_scts = ask;
        var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x70)));
        const rnd = seeded(&csprng);
        var client = try Connection12.clientInit(ccfg);
        defer client.deinit();
        var server = try Connection12.serverInit(scfg);
        defer server.deinit();
        var bufs: Bufs = .{};
        try drive(&client, &server, rnd, &bufs);
        if (ask) {
            try testing.expectEqualSlices(u8, staple, client.peerOcspResponse().?);
            try testing.expectEqualSlices(u8, scts, client.peerSctList().?);
        } else try testing.expect(client.peerOcspResponse() == null and client.peerSctList() == null);
        try exchangeData(&client, &server);
    }
}

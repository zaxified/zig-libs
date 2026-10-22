// SPDX-License-Identifier: MIT

//! End-to-end handshakes in one thread: Zig std's `crypto.tls.Client` and
//! the collection's `tlsclient` (std's client with RFC 5280 chain checks,
//! grown to Go's client options — it verifies Ed25519 and RSA-PSS, and
//! reports the negotiated group and ALPN) against `Server`, joined by
//! in-memory pipes. The client's input `Reader` drives the server whenever the client
//! wants more octets: it hands the server what the client wrote, feeds it,
//! and returns what the server queued — so the blocking client runs to
//! completion without threads or sockets.

const std = @import("std");
const testing = std.testing;
const tls13 = @import("tls13");
const record = @import("record.zig");
const inbound = @import("inbound.zig");
const server_mod = @import("server.zig");
const certs = @import("test_certs.zig");
const rsa = @import("rsa");
const tlsresume = @import("tlsresume");

const Server = server_mod.Server;
const StdClient = std.crypto.tls.Client;
const ZlClient = @import("tlsclient").Client;
// Both clients share std's buffer and entropy sizes, so one pipe fits both.
const Client = StdClient;
comptime {
    std.debug.assert(ZlClient.min_buffer_len == StdClient.min_buffer_len);
    std.debug.assert(ZlClient.Options.entropy_len == StdClient.Options.entropy_len);
}

/// The server end of the pipes, behind the client's input `Reader`.
const Pipe = struct {
    reader: std.Io.Reader,
    reader_buf: [Client.min_buffer_len]u8 = undefined,
    /// What the client writes (its output `Writer` is fixed over this).
    client_out_buf: [32 * 1024]u8 = undefined,
    client_out: std.Io.Writer = undefined,
    /// Flip the last octet of the client's first flight (a ClientHello's
    /// last octet is its last PSK binder's).
    corrupt_first: bool = false,
    /// Received by the server and not yet consumed.
    server_in: [64 * 1024]u8 = undefined,
    server_in_len: usize = 0,
    server: *Server,
    handshake_done: bool = false,
    /// Application data the server received.
    received: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    failure: ?server_mod.Error = null,
    /// The key an offloaded certificate signs with, here at once
    /// (`signature_needed`), and how many signatures it made.
    offload_key: ?tls13.certverify.SecretKey = null,
    signed: usize = 0,

    fn init(p: *Pipe, server: *Server, gpa: std.mem.Allocator) void {
        p.* = .{ .reader = undefined, .server = server, .gpa = gpa };
        p.reader = .{ .vtable = &.{ .stream = stream }, .buffer = &p.reader_buf, .seek = 0, .end = 0 };
        p.client_out = .fixed(&p.client_out_buf);
    }

    fn deinit(p: *Pipe) void {
        p.received.deinit(p.gpa);
    }

    /// Move the client's output into the server, run it to `need_more`.
    fn pump(p: *Pipe) !void {
        const w = p.client_out.buffered();
        if (p.corrupt_first and w.len != 0) {
            w[w.len - 1] ^= 1;
            p.corrupt_first = false;
        }
        @memcpy(p.server_in[p.server_in_len..][0..w.len], w);
        p.server_in_len += w.len;
        p.client_out.end = 0;
        while (true) {
            const r = p.server.feed(p.server_in[0..p.server_in_len]) catch |err| {
                p.failure = err;
                return;
            };
            switch (r.event) {
                .need_more => {},
                .handshake_done => p.handshake_done = true,
                .app_data => |d| try p.received.appendSlice(p.gpa, d),
                // tlsclient sends no early data.
                .early_data_accepted, .early_data => return error.UnexpectedEarlyData,
                .peer_closed => {},
                .signature_needed => {
                    const key = p.offload_key orelse return error.UnexpectedSignatureRequest;
                    // The flight so far is queued: the Certificate is its last message.
                    const out = p.server.pendingOutput();
                    if (out.len == 0) return error.FlightNotQueued;
                    const req = p.server.signatureRequest().?;
                    var prng = std.Random.DefaultPrng.init(p.signed);
                    var buf: [tls13.certverify.max_signature_len]u8 = undefined;
                    const sig = try tls13.certverify.signContent(@fromBackingInt(req.scheme), key, req.message, prng.random(), &buf);
                    p.server.provideSignature(sig) catch |err| {
                        p.failure = err;
                        return;
                    };
                    p.signed += 1;
                },
            }
            std.mem.copyForwards(u8, p.server_in[0 .. p.server_in_len - r.consumed], p.server_in[r.consumed..p.server_in_len]);
            p.server_in_len -= r.consumed;
            if (r.event == .need_more) return;
        }
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const p: *Pipe = @fieldParentPtr("reader", r);
        p.pump() catch return error.ReadFailed;
        const out = p.server.pendingOutput();
        if (out.len == 0) return error.EndOfStream;
        const n = limit.minInt(out.len);
        const dst = w.writableSliceGreedy(1) catch return error.WriteFailed;
        const m = @min(n, dst.len);
        @memcpy(dst[0..m], out[0..m]);
        w.advance(m);
        p.server.discardOutput(m);
        return m;
    }
};

const Fixture = struct {
    p256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
    p384: std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey,
    ed25519: std.crypto.sign.Ed25519.SecretKey,
    rsa2048: rsa.SecretKey,

    fn init(fx: *Fixture) !void {
        fx.p256 = try .fromBytes(certs.p256_scalar);
        fx.p384 = try .fromBytes(certs.p384_scalar);
        fx.ed25519 = try .fromBytes(certs.ed25519_secret);
        try rsa.SecretKey.fromDer(&fx.rsa2048, &certs.rsa2048_pkcs1);
    }
};

const Outcome = struct {
    suite: record.CipherSuite,
    group: u16,
    alpn: ?[]const u8,
    resumed: bool,
    retried: bool,
    age_skew_s: ?i64,
    echoed: []u8,
    /// `Server.peerCertificate` (owned, like `echoed`).
    peer: ?[]u8 = null,
    /// Offloaded signatures made.
    signed: usize = 0,

    fn deinit(o: Outcome, gpa: std.mem.Allocator) void {
        gpa.free(o.echoed);
        if (o.peer) |p| gpa.free(p);
    }
};

/// What `tlsclient` offers beyond std's defaults (ignored for std's client).
const ClientOffer = struct {
    groups: ?[]const std.crypto.tls.NamedGroup = null,
    key_share_groups: ?[]const std.crypto.tls.NamedGroup = null,
    alpn: []const []const u8 = &.{},
    /// Filled by `tlsclient` (Go's ConnectionState).
    info: ?*ZlClient.ConnectionInfo = null,
    session_cache: ?*ZlClient.SessionCache = null,
    corrupt_client_hello: bool = false,
    client_auth: ?ZlClient.ClientAuth = null,
    client_auth_select: ?ZlClient.ClientAuthSelect = null,
    request_ocsp: bool = true,
    request_scts: bool = true,
    /// The client's wall clock, ms past 2030-03-17 (`tlsclient` only).
    clock_ms: i64 = 0,
};

const ServerSide = struct {
    suites: []const record.CipherSuite = &server_mod.default_cipher_suites,
    groups: []const u16 = &server_mod.default_groups,
    alpn: []const []const u8 = &.{},
    tickets: ?*const server_mod.Tickets = null,
    client_auth: ?*const server_mod.ClientAuth = null,
    /// Signs for a certificate whose key is offloaded.
    offload_key: ?tls13.certverify.SecretKey = null,
};

/// One handshake of client type `C` against the server, then a request, a
/// response, and close_notify.
fn handshake(comptime C: type, gpa: std.mem.Allocator, ck: *const server_mod.CertifiedKey, srv: ServerSide, offer: ClientOffer) !Outcome {
    var prng = std.Random.DefaultPrng.init(0x7e57);
    const config: server_mod.Config = .{
        .certificate = .{ .fixed = ck },
        .cipher_suites = srv.suites,
        .groups = srv.groups,
        .alpn_protocols = srv.alpn,
        .random = prng.random(),
        .tickets = srv.tickets,
        .client_auth = srv.client_auth,
    };
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, server_mod.minOutputLen(&config, ck) + 64 * 1024);
    defer gpa.free(out);
    // Without client authentication a short buffer must be ignored (tickets
    // are then built on the stack), not written past.
    const peer = try gpa.alloc(u8, if (srv.client_auth) |ca| server_mod.peerBufferLen(ca.max_leaf_len) else 16);
    defer gpa.free(peer);
    var server: Server = .init(&config, joiner, out);
    server.setPeerBuffer(peer);
    defer server.deinit();

    const pipe = try gpa.create(Pipe);
    defer gpa.destroy(pipe);
    pipe.init(&server, gpa);
    defer pipe.deinit();
    pipe.corrupt_first = offer.corrupt_client_hello;
    pipe.offload_key = srv.offload_key;

    var entropy: [Client.Options.entropy_len]u8 = undefined;
    prng.random().bytes(&entropy);
    var read_buf: [Client.min_buffer_len]u8 = undefined;
    var write_buf: [Client.min_buffer_len]u8 = undefined;
    const now: std.Io.Timestamp = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s + @as(i96, offer.clock_ms) * std.time.ns_per_ms); // 2030
    var client = (if (C == ZlClient) ZlClient.init(&pipe.reader, &pipe.client_out, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = now,
        .min_version = .tls_1_3,
        .groups = offer.groups orelse &ZlClient.default_groups,
        .key_share_groups = offer.key_share_groups orelse &ZlClient.default_key_share_groups,
        .alpn_protocols = offer.alpn,
        .connection_info = offer.info,
        .session_cache = offer.session_cache,
        .client_auth = offer.client_auth,
        .client_auth_select = offer.client_auth_select,
        .request_ocsp = offer.request_ocsp,
        .request_scts = offer.request_scts,
    }) else StdClient.init(&pipe.reader, &pipe.client_out, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = now,
    })) catch |err| {
        if (pipe.failure) |f| return f;
        std.debug.print("client: {t}\n", .{err});
        return err;
    };
    // The server learns the handshake is done from the client's Finished,
    // which the client sends with its first write.
    var exported: [100]u8 = undefined;
    try testing.expectError(error.HandshakeNotComplete, server.exportKeyingMaterial(&exported, "EXPERIMENTAL-tlsserver", "ctx"));
    try client.writer.writeAll("GET / HTTP/1.1\r\n\r\n");
    try client.writer.flush();
    try pipe.pump();
    if (pipe.failure) |f| return f;
    try testing.expect(pipe.handshake_done);
    try testing.expect(server.isConnected());
    try testing.expectEqualStrings("localhost", server.serverName().?);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", pipe.received.items);

    // The exporter: the client's (tlsclient's own RFC 8446 §7.5 code) over
    // more than one HKDF block, with and without a context.
    if (C == ZlClient) {
        for ([_][]const u8{ "ctx", "" }) |context| {
            try server.exportKeyingMaterial(&exported, "EXPERIMENTAL-tlsserver", context);
            var theirs: [100]u8 = undefined;
            try client.exportKeyingMaterial("EXPERIMENTAL-tlsserver", context, &theirs);
            try testing.expectEqualSlices(u8, &theirs, &exported);
        }
        try testing.expectError(error.LabelTooLong, server.exportKeyingMaterial(&exported, &@as([Server.max_exporter_label_len + 1]u8, @splat('a')), ""));
        const big = try gpa.alloc(u8, Server.maxExporterLen(server.cipherSuite().?) + 1);
        defer gpa.free(big);
        try testing.expectError(error.OutputTooLong, server.exportKeyingMaterial(big, "EXPERIMENTAL-tlsserver", ""));
        // The longest output, all 255 HKDF blocks.
        const theirs_big = try gpa.alloc(u8, big.len - 1);
        defer gpa.free(theirs_big);
        try server.exportKeyingMaterial(big[1..], "EXPERIMENTAL-tlsserver", "");
        try client.exportKeyingMaterial("EXPERIMENTAL-tlsserver", "", theirs_big);
        try testing.expectEqualSlices(u8, theirs_big, big[1..]);
    }

    // Server → client, then close_notify both ways.
    try testing.expectEqual(@as(usize, 11), try server.write("hello there"));
    try server.close();
    var got: [64]u8 = undefined;
    var n: usize = 0;
    while (true) {
        const k = client.reader.readSliceShort(got[n..]) catch break;
        if (k == 0) break;
        n += k;
    }
    return .{
        .suite = server.cipherSuite().?,
        .group = server.negotiatedGroup().?,
        .alpn = server.alpnProtocol(),
        .resumed = server.isResumed(),
        .retried = server.usedHelloRetryRequest(),
        .age_skew_s = server.ticketAgeSkew(),
        .echoed = try gpa.dupe(u8, got[0..n]),
        .peer = if (server.peerCertificate()) |p| try gpa.dupe(u8, p) else null,
        .signed = pipe.signed,
    };
}

const p256_chain = [_][]const u8{&certs.p256_cert};

test "std client ↔ Server: ECDSA P-256, every suite, the hybrid group" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        const o = try handshake(StdClient, testing.allocator, &ck, .{ .suites = &.{suite} }, .{});
        defer testing.allocator.free(o.echoed);
        try testing.expectEqual(suite, o.suite);
        try testing.expectEqualStrings("hello there", o.echoed);
    }
}

test "std client ↔ Server: the x25519 and secp256r1 groups" {
    // ECDSA P-256 again: std's client advertises ed25519 in
    // signature_algorithms but cannot verify it (Client.zig
    // `verifySignature` has no ed25519 arm: TlsBadSignatureScheme), so
    // Ed25519 and RSA certificates are exercised by the OpenSSL and Go
    // interop instead.
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    for ([_]u16{ tls13.kex.x25519_group, tls13.kex.secp256r1_group }) |g| {
        const o = try handshake(StdClient, testing.allocator, &ck, .{ .groups = &.{g} }, .{});
        try testing.expectEqual(g, o.group);
        defer testing.allocator.free(o.echoed);
        try testing.expectEqualStrings("hello there", o.echoed);
    }
}

test "std client ↔ Server: chains and keys loaded from openssl's PEM forms (`keys`)" {
    const key_vectors = @import("key_vectors.zig");
    const CertKeyPair = @import("keys.zig").CertKeyPair;
    for (key_vectors.cases) |c| {
        // ECDSA only: std's client checks neither Ed25519 nor (here) RSA-PSS
        // certificates; the loader's other forms are pinned in `keys.zig`.
        if (c.kind != .ecdsa_p256 and c.kind != .ecdsa_p384) continue;
        errdefer std.debug.print("case {s}\n", .{c.name});
        var pair: CertKeyPair = undefined;
        try CertKeyPair.fromPem(&pair, testing.allocator, c.cert_pem, c.key_pem);
        defer pair.deinit(testing.allocator);
        const ck = pair.certifiedKey();
        const o = try handshake(StdClient, testing.allocator, &ck, .{}, .{});
        defer testing.allocator.free(o.echoed);
        try testing.expectEqualStrings("hello there", o.echoed);
    }
}

const NamedGroup = std.crypto.tls.NamedGroup;

test "tlsclient ↔ Server: every certificate kind, chain verified by x509" {
    var fx: Fixture = undefined;
    try fx.init();
    const chains = [_][1][]const u8{ .{&certs.p256_cert}, .{&certs.p384_cert}, .{&certs.ed25519_cert}, .{&certs.rsa2048_cert} };
    const keys = [_]server_mod.CertifiedKey{
        .{ .chain = &chains[0], .key = .{ .ecdsa_p256 = &fx.p256 } },
        .{ .chain = &chains[1], .key = .{ .ecdsa_p384 = &fx.p384 } },
        .{ .chain = &chains[2], .key = .{ .ed25519 = &fx.ed25519 } },
        .{ .chain = &chains[3], .key = .{ .rsa = &fx.rsa2048 } },
    };
    for (&keys, chains) |*ck, chain| {
        var storage: [16 * 1024]u8 = undefined;
        var info: ZlClient.ConnectionInfo = .init(&storage);
        const o = try handshake(ZlClient, testing.allocator, ck, .{}, .{ .info = &info });
        defer testing.allocator.free(o.echoed);
        try testing.expectEqualStrings("hello there", o.echoed);
        // The client's view agrees with the server's.
        try testing.expectEqual(@backingInt(o.suite), @backingInt(info.cipher_suite));
        try testing.expectEqual(o.group, @backingInt(info.negotiated_group.?));
        try testing.expectEqual(@as(usize, 1), info.peerCertificates().len);
        try testing.expectEqualSlices(u8, chain[0], info.peerCertificates()[0]);
        try testing.expect(!info.hello_retry_request and !info.did_resume);
    }
}

test "tlsclient ↔ Server: every group with a lone key share, every suite" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const groups = [_]NamedGroup{ .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1 };
    for (groups) |g| {
        for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
            var storage: [16 * 1024]u8 = undefined;
            var info: ZlClient.ConnectionInfo = .init(&storage);
            const o = try handshake(ZlClient, testing.allocator, &ck, .{ .suites = &.{suite} }, .{ .groups = &.{g}, .key_share_groups = &.{g}, .info = &info });
            defer testing.allocator.free(o.echoed);
            try testing.expectEqual(@backingInt(g), o.group);
            try testing.expectEqual(suite, o.suite);
            try testing.expectEqual(g, info.negotiated_group.?);
            try testing.expectEqualStrings("hello there", o.echoed);
        }
    }
}

test "tlsclient ↔ Server: the client's first group with a share; ALPN" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    // tlsclient's defaults (Go's): shares for X25519MLKEM768 and X25519; a
    // server without the hybrid takes the X25519 share, no retry.
    var storage: [16 * 1024]u8 = undefined;
    var info: ZlClient.ConnectionInfo = .init(&storage);
    const o = try handshake(ZlClient, testing.allocator, &ck, .{
        .groups = &.{ tls13.kex.secp256r1_group, tls13.kex.x25519_group },
        .alpn = &.{ "h2", "http/1.1" },
    }, .{ .alpn = &.{ "http/1.1", "h2" }, .info = &info });
    defer testing.allocator.free(o.echoed);
    try testing.expectEqual(tls13.kex.x25519_group, o.group);
    try testing.expectEqualStrings("h2", o.alpn.?);
    try testing.expectEqualStrings("h2", info.alpn_protocol.?);
}

test "tlsclient ↔ Server: the OCSP staple and the SCT list on the leaf, each only when asked for" {
    var fx: Fixture = undefined;
    try fx.init();
    const ocsp = "\x30\x03\x0a\x01\x01"; // OCSPResponse malformedRequest(1)
    const scts = "\x00\x10" ++ "\x00\x07SCT-one" ++ "\x00\x05SCT-2";
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 }, .ocsp_response = ocsp, .sct_list = scts };
    try ck.check();
    for ([_][2]bool{ .{ true, true }, .{ true, false }, .{ false, true }, .{ false, false } }) |ask| {
        var storage: [16 * 1024]u8 = undefined;
        var info: ZlClient.ConnectionInfo = .init(&storage);
        const o = try handshake(ZlClient, testing.allocator, &ck, .{}, .{ .info = &info, .request_ocsp = ask[0], .request_scts = ask[1] });
        defer testing.allocator.free(o.echoed);
        try testing.expectEqualStrings(if (ask[0]) ocsp else "", info.ocsp_response);
        const got = info.signedCertificateTimestamps();
        if (ask[1]) {
            try testing.expectEqual(@as(usize, 2), got.len);
            try testing.expectEqualStrings("SCT-one", got[0]);
            try testing.expectEqualStrings("SCT-2", got[1]);
        } else try testing.expectEqual(@as(usize, 0), got.len);
        try testing.expectEqual(@as(usize, 1), info.peerCertificates().len);
    }
    // Empty counts as none (rustls).
    const empty: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 }, .ocsp_response = "", .sct_list = "" };
    var storage: [16 * 1024]u8 = undefined;
    var info: ZlClient.ConnectionInfo = .init(&storage);
    const o = try handshake(ZlClient, testing.allocator, &empty, .{}, .{ .info = &info });
    defer testing.allocator.free(o.echoed);
    try testing.expectEqualStrings("", info.ocsp_response);
    try testing.expectEqual(@as(usize, 0), info.signedCertificateTimestamps().len);
}

test "tlsclient ↔ Server: HelloRetryRequest for a group the client has no share for, every suite" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    // tlsclient's default shares are X25519MLKEM768 and X25519; a server
    // with neither asks for its group on the second ClientHello. The suite
    // decides the hash of `message_hash` (RFC 8446 §4.4.1).
    for ([_]u16{ tls13.kex.secp256r1_group, tls13.kex.secp384r1_group }) |g| {
        for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
            var storage: [16 * 1024]u8 = undefined;
            var info: ZlClient.ConnectionInfo = .init(&storage);
            const o = try handshake(ZlClient, testing.allocator, &ck, .{ .suites = &.{suite}, .groups = &.{g} }, .{ .info = &info });
            defer testing.allocator.free(o.echoed);
            try testing.expect(info.hello_retry_request);
            try testing.expect(o.retried);
            try testing.expectEqual(g, o.group);
            try testing.expectEqual(g, @backingInt(info.negotiated_group.?));
            try testing.expectEqual(suite, o.suite);
            try testing.expectEqualStrings("hello there", o.echoed);
        }
    }
}

test "tlsclient ↔ Server: KeyUpdate both ways, every suite" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const gpa = testing.allocator;
    for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        errdefer std.debug.print("suite {t}\n", .{suite});
        var prng = std.Random.DefaultPrng.init(0x7e57);
        const config: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .cipher_suites = &.{suite}, .random = prng.random() };
        const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
        defer gpa.free(joiner);
        const out = try gpa.alloc(u8, server_mod.minOutputLen(&config, &ck) + 64 * 1024);
        defer gpa.free(out);
        var server: Server = .init(&config, joiner, out);
        defer server.deinit();
        const pipe = try gpa.create(Pipe);
        defer gpa.destroy(pipe);
        pipe.init(&server, gpa);
        defer pipe.deinit();

        var entropy: [Client.Options.entropy_len]u8 = undefined;
        prng.random().bytes(&entropy);
        var read_buf: [Client.min_buffer_len]u8 = undefined;
        var write_buf: [Client.min_buffer_len]u8 = undefined;
        var client = try ZlClient.init(&pipe.reader, &pipe.client_out, .{
            .host = .{ .explicit = "localhost" },
            .ca = .self_signed,
            .read_buffer = &read_buf,
            .write_buffer = &write_buf,
            .entropy = &entropy,
            .realtime_now = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s),
            .min_version = .tls_1_3,
        });
        try client.writer.writeAll("hi");
        try client.writer.flush();
        try pipe.pump();
        try testing.expect(pipe.handshake_done);

        var got: [16]u8 = undefined;
        for (0..3) |i| {
            // The server asks; the client answers before its next record.
            try server.keyUpdate(.update_requested);
            var msg: [8]u8 = undefined;
            const m = try std.fmt.bufPrint(&msg, "srv{d}", .{i});
            _ = try server.write(m);
            try client.reader.readSliceAll(got[0..m.len]);
            try testing.expectEqualStrings(m, got[0..m.len]);
            try testing.expect(client.key_update_pending);
            const c = try std.fmt.bufPrint(&msg, "cli{d}", .{i});
            try client.writer.writeAll(c);
            try client.writer.flush();
            try testing.expect(!client.key_update_pending);
            pipe.received.clearRetainingCapacity();
            try pipe.pump();
            if (pipe.failure) |f| return f;
            try testing.expectEqualStrings(c, pipe.received.items);
        }
        // The client turns its key over unasked: nothing comes back.
        client.key_update_pending = true;
        try client.writer.writeAll("last");
        try client.writer.flush();
        pipe.received.clearRetainingCapacity();
        try pipe.pump();
        if (pipe.failure) |f| return f;
        try testing.expectEqualStrings("last", pipe.received.items);
        try testing.expectEqual(@as(?server_mod.KeyUpdateRequest, null), server.tx_update);
        try testing.expectEqual(@as(usize, 0), server.pendingOutput().len);
    }
}

test "tlsclient ↔ Server: write sends whole records, not ones cut to fit behind pending output" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7e58);
    const config: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, @max(server_mod.minOutputLen(&config, &ck), server_mod.full_record_output_len) + 1000);
    defer gpa.free(out);
    var server: Server = .init(&config, joiner, out);
    defer server.deinit();
    const pipe = try gpa.create(Pipe);
    defer gpa.destroy(pipe);
    pipe.init(&server, gpa);
    defer pipe.deinit();

    var entropy: [Client.Options.entropy_len]u8 = undefined;
    prng.random().bytes(&entropy);
    var read_buf: [Client.min_buffer_len]u8 = undefined;
    var write_buf: [Client.min_buffer_len]u8 = undefined;
    var client = try ZlClient.init(&pipe.reader, &pipe.client_out, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s),
        .min_version = .tls_1_3,
    });
    try client.writer.writeAll("hi");
    try client.writer.flush();
    try pipe.pump();
    try testing.expect(pipe.handshake_done);
    try testing.expectEqual(@as(usize, 0), server.pendingOutput().len);

    const data: [10_000]u8 = @splat('d');
    const sealed = record.header_len + data.len + 1 + record.tag_len;
    try testing.expectEqual(data.len, try server.write(&data));
    try testing.expectEqual(sealed, server.pendingOutput().len);
    // The rest of the buffer holds a part only: nothing is taken.
    try testing.expectError(error.OutputFull, server.write(&data));
    server.discardOutput(sealed);
    try testing.expectEqual(data.len, try server.write(&data));
    try testing.expectEqual(sealed, server.pendingOutput().len);
}

test "tlsclient ↔ Server: dynamic record sizing — one segment, growing, full after boost_after; small again after idling" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7e59);
    const Clock = struct {
        var now: i64 = 1_900_000_000_000;
        fn ms(_: ?*anyopaque) i64 {
            return now;
        }
    };
    const dyn: server_mod.DynamicRecords = .{ .clock = .{ .now_ms = Clock.ms } };
    const config: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random(), .dynamic_records = dyn };
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, @max(server_mod.minOutputLen(&config, &ck), server_mod.full_record_output_len) + 1000);
    defer gpa.free(out);
    var server: Server = .init(&config, joiner, out);
    defer server.deinit();
    const pipe = try gpa.create(Pipe);
    defer gpa.destroy(pipe);
    pipe.init(&server, gpa);
    defer pipe.deinit();
    var entropy: [Client.Options.entropy_len]u8 = undefined;
    prng.random().bytes(&entropy);
    var read_buf: [Client.min_buffer_len]u8 = undefined;
    var write_buf: [Client.min_buffer_len]u8 = undefined;
    var client = try ZlClient.init(&pipe.reader, &pipe.client_out, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s),
        .min_version = .tls_1_3,
    });
    try client.writer.writeAll("hi");
    try client.writer.flush();
    try pipe.pump();
    try testing.expect(pipe.handshake_done);

    const data = try gpa.alloc(u8, 200_000);
    defer gpa.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
    const got = try gpa.alloc(u8, data.len);
    defer gpa.free(got);
    // Every record's content length, in order, and the client reads it all.
    var lens: std.ArrayList(usize) = .empty;
    defer lens.deinit(gpa);
    var done: usize = 0;
    var read: usize = 0;
    while (done < data.len) {
        done += try server.write(data[done..]);
        const p = server.pendingOutput();
        var at: usize = 0;
        while (at < p.len) {
            const n = std.mem.readInt(u16, p[at + 3 ..][0..2], .big);
            try lens.append(gpa, n - 1 - record.tag_len);
            at += 5 + n;
        }
        try client.reader.readSliceAll(got[read..done]);
        read = done;
    }
    try testing.expectEqualSlices(u8, data, got);
    var sent: usize = 0;
    for (lens.items, 0..) |n, k| {
        const want = if (sent >= dyn.boost_after) 16384 else @min(16384, @as(usize, dyn.segment_len) * (k + 1));
        try testing.expectEqual(@min(want, data.len - sent), n);
        sent += n;
    }
    try testing.expectEqual(@as(usize, 1186), lens.items[0]);
    // Idle for the reset time: one segment again; just under it: not.
    Clock.now += 999;
    var n = try server.write(data[0..20_000]);
    try testing.expectEqual(@as(usize, 16384), std.mem.readInt(u16, server.pendingOutput()[3..5], .big) - 1 - record.tag_len);
    try client.reader.readSliceAll(got[0..n]);
    Clock.now += 1000;
    n = try server.write(data[0..20_000]);
    try testing.expectEqual(@as(usize, 1186), std.mem.readInt(u16, server.pendingOutput()[3..5], .big) - 1 - record.tag_len);
    try client.reader.readSliceAll(got[0..n]);
}

test "tlsclient ↔ Server: a connection serialized, sealed, resumed in a new Server — data both ways, KeyUpdate, exporter, client certificate" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const gpa = testing.allocator;
    var ca: ClientAuthFixture = undefined;
    ca.init(true);
    var ckeys: ClientKeys = undefined;
    try ckeys.init();
    for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        errdefer std.debug.print("suite {t}\n", .{suite});
        var prng = std.Random.DefaultPrng.init(0x5e7);
        const config: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random(), .cipher_suites = &.{suite}, .alpn_protocols = &.{ "h2", "http/1.1" }, .client_auth = &ca.auth, .enable_secret_extraction = true };
        const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
        defer gpa.free(joiner);
        const out = try gpa.alloc(u8, @max(server_mod.minOutputLen(&config, &ck), server_mod.full_record_output_len) + 1000);
        defer gpa.free(out);
        const peer = try gpa.alloc(u8, server_mod.peerBufferLen(ca.auth.max_leaf_len));
        defer gpa.free(peer);
        var server: Server = .init(&config, joiner, out);
        server.setPeerBuffer(peer);
        defer server.deinit();
        const pipe = try gpa.create(Pipe);
        defer gpa.destroy(pipe);
        pipe.init(&server, gpa);
        defer pipe.deinit();
        var entropy: [Client.Options.entropy_len]u8 = undefined;
        prng.random().bytes(&entropy);
        var read_buf: [Client.min_buffer_len]u8 = undefined;
        var write_buf: [Client.min_buffer_len]u8 = undefined;
        var cchain: [1][]const u8 = undefined;
        var client = try ZlClient.init(&pipe.reader, &pipe.client_out, .{
            .host = .{ .explicit = "localhost" },
            .ca = .self_signed,
            .read_buffer = &read_buf,
            .write_buffer = &write_buf,
            .entropy = &entropy,
            .realtime_now = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s),
            .min_version = .tls_1_3,
            .alpn_protocols = &.{"h2"},
            .client_auth = clientCert(&client_certs.p256_cert, &ckeys.p256, &cchain),
        });
        try client.writer.writeAll("before");
        try client.writer.flush();
        try pipe.pump();
        try testing.expect(pipe.handshake_done);
        try testing.expectEqualStrings("before", pipe.received.items);
        _ = try server.write("one");
        var got: [64]u8 = undefined;
        try client.reader.readSliceAll(got[0..3]);
        var exported: [32]u8 = undefined;
        try server.exportKeyingMaterial(&exported, "EXPERIMENTAL-migrate", "");

        // Sealed, the old server finished; a wrong key, a flipped octet refused.
        const key: [32]u8 = @splat(0x7a);
        var blob_buf: [4096]u8 = undefined;
        try testing.expectError(error.BufferTooSmall, server.serialize(blob_buf[0 .. server.blobLen() - 1], &key, "conn-1/gen-1"));
        // Not without `enable_secret_extraction` (checked first).
        var cfg_off = config;
        cfg_off.enable_secret_extraction = false;
        var no_extract: Server = .init(&cfg_off, joiner, out);
        try testing.expectError(error.SecretExtractionDisabled, no_extract.serialize(&blob_buf, &key, ""));
        const blob = try server.serialize(&blob_buf, &key, "conn-1/gen-1");
        try testing.expectError(error.Closed, server.feed(&.{}));
        try testing.expectEqual(null, server.peerCertificate());
        try testing.expect(std.mem.indexOf(u8, blob, &client_certs.p256_cert) == null);
        const joiner2 = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
        defer gpa.free(joiner2);
        const out2 = try gpa.alloc(u8, out.len);
        defer gpa.free(out2);
        const peer2 = try gpa.alloc(u8, peer.len);
        defer gpa.free(peer2);
        var copy: [4096]u8 = undefined;
        var scratch: Server = undefined;
        for ([_]usize{ 0, 1, 20, blob.len - 1 }) |at| {
            @memcpy(copy[0..blob.len], blob);
            copy[at] ^= 1;
            try testing.expectError(error.BadBlob, Server.deserialize(&scratch, &config, joiner2, out2, peer2, copy[0..blob.len], &key, "conn-1/gen-1"));
        }
        @memcpy(copy[0..blob.len], blob);
        try testing.expectError(error.BadBlob, Server.deserialize(&scratch, &config, joiner2, out2, peer2, copy[0..blob.len], &@as([32]u8, @splat(0x7b)), "conn-1/gen-1"));
        @memcpy(copy[0..blob.len], blob);
        const no_alpn: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random(), .alpn_protocols = &.{"http/1.1"} };
        try testing.expectError(error.ConfigMismatch, Server.deserialize(&scratch, &no_alpn, joiner2, out2, peer2, copy[0..blob.len], &key, "conn-1/gen-1"));
        @memcpy(copy[0..blob.len], blob);
        var moved: Server = undefined;
        // Another connection's (or generation's) context.
        try testing.expectError(error.BadBlob, Server.deserialize(&scratch, &config, joiner2, out2, peer2, copy[0..blob.len], &key, "conn-1/gen-2"));
        @memcpy(copy[0..blob.len], blob);
        try Server.deserialize(&moved, &config, joiner2, out2, peer2, copy[0..blob.len], &key, "conn-1/gen-1");
        defer moved.deinit();
        pipe.server = &moved;

        // The same client, unaware.
        try testing.expect(moved.isConnected());
        try testing.expectEqual(suite, moved.cipherSuite().?);
        try testing.expectEqualStrings("h2", moved.alpnProtocol().?);
        try testing.expectEqualStrings("localhost", moved.serverName().?);
        try testing.expectEqualSlices(u8, &client_certs.p256_cert, moved.peerCertificate().?);
        var again: [32]u8 = undefined;
        try moved.exportKeyingMaterial(&again, "EXPERIMENTAL-migrate", "");
        try testing.expectEqualSlices(u8, &exported, &again);
        _ = try moved.write("two");
        try client.reader.readSliceAll(got[0..3]);
        try testing.expectEqualStrings("two", got[0..3]);
        try client.writer.writeAll("after");
        try client.writer.flush();
        try pipe.pump();
        try testing.expectEqualStrings("beforeafter", pipe.received.items);
        // KeyUpdate both ways from the new process.
        try moved.keyUpdate(.update_requested);
        _ = try moved.write("three");
        try client.reader.readSliceAll(got[0..5]);
        try client.writer.writeAll("!");
        try client.writer.flush();
        try pipe.pump();
        try testing.expectEqualStrings("beforeafter!", pipe.received.items);
        try moved.close();
        while (true) {
            const k = client.reader.readSliceShort(&got) catch break;
            if (k == 0) break;
        }
    }
}

/// A STEK ring with one key, a clock the test moves (2030, as the
/// client's), and the ticket settings over them.
const TicketFixture = struct {
    ring: tlsresume.stek.DefaultRing,
    stek: server_mod.StekTicketer(tlsresume.stek.DefaultRing),
    now_ms: i64,
    tickets: server_mod.Tickets,

    fn init(fx: *TicketFixture) void {
        fx.ring = .init();
        fx.ring.rotate(1, &@as([32]u8, @splat(0x3c)), 1_900_000_000);
        fx.stek = .{ .ring = &fx.ring };
        fx.now_ms = 1_900_000_000_000 + 5_000;
        fx.tickets = .{ .ticketer = fx.stek.ticketer(), .clock = .{ .ctx = fx, .now_ms = now } };
    }

    fn now(ctx: ?*anyopaque) i64 {
        const fx: *TicketFixture = @ptrCast(@alignCast(ctx.?));
        return fx.now_ms;
    }
};

test "tlsclient ↔ Server: tickets, then resumed handshakes, every suite" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    var tf: TicketFixture = undefined;
    tf.init();
    for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        errdefer std.debug.print("suite {t}\n", .{suite});
        const entries = try testing.allocator.alloc(ZlClient.ClientSession, 2);
        defer testing.allocator.free(entries);
        var cache: ZlClient.SessionCache = .init(entries, null);
        defer cache.deinit();
        const srv: ServerSide = .{ .suites = &.{suite}, .tickets = &tf.tickets, .alpn = &.{"h2"} };
        for (0..3) |round| {
            var storage: [16 * 1024]u8 = undefined;
            var info: ZlClient.ConnectionInfo = .init(&storage);
            const o = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &cache, .info = &info, .alpn = &.{"h2"} });
            defer testing.allocator.free(o.echoed);
            try testing.expectEqualStrings("hello there", o.echoed);
            try testing.expectEqual(round != 0, o.resumed);
            try testing.expectEqual(round != 0, info.did_resume);
            try testing.expectEqualStrings("h2", info.alpn_protocol.?);
            // The client shows the chain it kept with the ticket.
            try testing.expectEqualSlices(u8, &certs.p256_cert, info.peerCertificates()[0]);
        }
    }
}

test "tlsclient ↔ Server: a stateful ticket resumes once, a STEK ticket again" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const Cache = server_mod.SessionCache(0);
    for ([_]bool{ true, false }) |stateful| {
        errdefer std.debug.print("stateful {}\n", .{stateful});
        var tf: TicketFixture = undefined;
        tf.init();
        var cache: Cache = try .init(testing.allocator, 4, 3600);
        defer cache.deinit();
        var prng = std.Random.DefaultPrng.init(9);
        const ct: server_mod.CacheTicketer(Cache) = .{ .cache = &cache, .clock = tf.tickets.clock, .random = prng.random() };
        if (stateful) tf.tickets.ticketer = ct.ticketer();
        tf.tickets.count = 1;
        const entries = try testing.allocator.alloc(ZlClient.ClientSession, 1);
        defer testing.allocator.free(entries);
        var client_cache: ZlClient.SessionCache = .init(entries, null);
        defer client_cache.deinit();
        const srv: ServerSide = .{ .tickets = &tf.tickets };
        for (0..3) |round| {
            // No ticket after the first: the client offers the same one
            // again after resuming with it.
            if (round == 1) tf.tickets.count = 0;
            const o = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &client_cache });
            defer testing.allocator.free(o.echoed);
            try testing.expectEqualStrings("hello there", o.echoed);
            try testing.expectEqual(round == 1 or (round == 2 and !stateful), o.resumed);
        }
        try testing.expectEqual(@as(usize, 0), cache.count());
    }
}

test "tlsclient ↔ Server: a stateful ticket offered with a bad binder is spent" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const Cache = server_mod.SessionCache(0);
    var tf: TicketFixture = undefined;
    tf.init();
    var cache: Cache = try .init(testing.allocator, 4, 3600);
    defer cache.deinit();
    var prng = std.Random.DefaultPrng.init(9);
    const ct: server_mod.CacheTicketer(Cache) = .{ .cache = &cache, .clock = tf.tickets.clock, .random = prng.random() };
    tf.tickets.ticketer = ct.ticketer();
    tf.tickets.count = 1;
    const entries = try testing.allocator.alloc(ZlClient.ClientSession, 1);
    defer testing.allocator.free(entries);
    var client_cache: ZlClient.SessionCache = .init(entries, null);
    defer client_cache.deinit();
    const srv: ServerSide = .{ .tickets = &tf.tickets };
    const first = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &client_cache });
    testing.allocator.free(first.echoed);
    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expectError(error.DecryptError, handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &client_cache, .corrupt_client_hello = true }));
    try testing.expectEqual(@as(usize, 0), cache.count());
    const o = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &client_cache });
    defer testing.allocator.free(o.echoed);
    try testing.expect(!o.resumed);
}

test "tlsclient ↔ Server: a ticket for another suite, a retired key or past its lifetime gets a full handshake" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const Case = enum { other_suite, retired_key, too_old, at_lifetime };
    for ([_]Case{ .other_suite, .retired_key, .too_old, .at_lifetime }) |case| {
        errdefer std.debug.print("case {t}\n", .{case});
        var tf: TicketFixture = undefined;
        tf.init();
        tf.tickets.lifetime_s = 3600;
        const entries = try testing.allocator.alloc(ZlClient.ClientSession, 2);
        defer testing.allocator.free(entries);
        var cache: ZlClient.SessionCache = .init(entries, null);
        defer cache.deinit();
        const first = try handshake(ZlClient, testing.allocator, &ck, .{ .suites = &.{.aes_128_gcm_sha256}, .tickets = &tf.tickets }, .{ .session_cache = &cache });
        testing.allocator.free(first.echoed);
        var suites: []const record.CipherSuite = &.{.aes_128_gcm_sha256};
        switch (case) {
            // Same hash, another suite: rustls `can_resume` wants the same.
            .other_suite => suites = &.{.chacha20_poly1305_sha256},
            .retired_key => {
                tf.ring = .init();
                tf.ring.rotate(2, &@as([32]u8, @splat(0x4d)), 1_900_000_000);
            },
            .too_old => tf.now_ms += 3600 * 1000 + 1,
            .at_lifetime => tf.now_ms += 3600 * 1000,
        }
        // The client's clock stays put, so its reported age is off by the
        // hour: the server does not check it (no early data).
        const o = try handshake(ZlClient, testing.allocator, &ck, .{ .suites = suites, .tickets = &tf.tickets }, .{ .session_cache = &cache });
        defer testing.allocator.free(o.echoed);
        try testing.expectEqual(case == .at_lifetime, o.resumed);
        try testing.expectEqualStrings("hello there", o.echoed);
    }
}

test "tlsclient ↔ Server: ticketAgeSkew is the client's age less the server's, in seconds" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    // How far each clock moves between the two handshakes; each age is
    // truncated to seconds before the difference.
    const cases = [_]struct { client_ms: i64, server_ms: i64, skew: i64 }{
        .{ .client_ms = 15_800, .server_ms = 10_900, .skew = 5 },
        .{ .client_ms = 0, .server_ms = 21_700, .skew = -21 },
    };
    for (cases) |c| {
        var tf: TicketFixture = undefined;
        tf.init();
        const entries = try testing.allocator.alloc(ZlClient.ClientSession, 2);
        defer testing.allocator.free(entries);
        var cache: ZlClient.SessionCache = .init(entries, null);
        defer cache.deinit();
        const srv: ServerSide = .{ .tickets = &tf.tickets };
        const first = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &cache });
        testing.allocator.free(first.echoed);
        try testing.expectEqual(@as(?i64, null), first.age_skew_s);
        tf.now_ms += c.server_ms;
        const o = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &cache, .clock_ms = c.client_ms });
        defer testing.allocator.free(o.echoed);
        try testing.expect(o.resumed);
        try testing.expectEqual(@as(?i64, c.skew), o.age_skew_s);
    }
}

test "tlsclient ↔ Server: a resumption ClientHello with a bad binder is decrypt_error" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    var tf: TicketFixture = undefined;
    tf.init();
    const entries = try testing.allocator.alloc(ZlClient.ClientSession, 2);
    defer testing.allocator.free(entries);
    var cache: ZlClient.SessionCache = .init(entries, null);
    defer cache.deinit();
    const srv: ServerSide = .{ .tickets = &tf.tickets };
    const first = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &cache });
    testing.allocator.free(first.echoed);
    try testing.expectError(error.DecryptError, handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &cache, .corrupt_client_hello = true }));
    // Without tickets configured the binder is never looked at: the server
    // answers with a full flight, which the client cannot open (the two
    // transcripts differ in that octet).
    try testing.expectError(error.TlsBadRecordMac, handshake(ZlClient, testing.allocator, &ck, .{}, .{ .session_cache = &cache, .corrupt_client_hello = true }));
}

test "Server: the NewSessionTickets after the client's Finished, one record, each its own" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    const gpa = testing.allocator;
    var tf: TicketFixture = undefined;
    tf.init();
    tf.tickets.count = 3;
    tf.tickets.lifetime_s = 8 * 24 * 3600; // capped at 7 days
    var prng = std.Random.DefaultPrng.init(0x7e57);
    const config: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .cipher_suites = &.{.aes_256_gcm_sha384}, .random = prng.random(), .tickets = &tf.tickets };
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, server_mod.minOutputLen(&config, &ck) + 64 * 1024);
    defer gpa.free(out);
    var server: Server = .init(&config, joiner, out);
    defer server.deinit();
    const pipe = try gpa.create(Pipe);
    defer gpa.destroy(pipe);
    pipe.init(&server, gpa);
    defer pipe.deinit();
    var entropy: [Client.Options.entropy_len]u8 = undefined;
    prng.random().bytes(&entropy);
    var read_buf: [Client.min_buffer_len]u8 = undefined;
    var write_buf: [Client.min_buffer_len]u8 = undefined;
    _ = try ZlClient.init(&pipe.reader, &pipe.client_out, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s),
        .min_version = .tls_1_3,
    });
    // The client's Finished is in its output; nothing of the server's is
    // left unread.
    try testing.expectEqual(@as(usize, 0), server.pendingOutput().len);
    try pipe.pump();
    try testing.expect(pipe.handshake_done);
    // Issued: the master secret is gone (review 2026-10-20 LOW-2).
    try testing.expect(std.mem.allEqual(u8, &server.master_secret, 0));

    const p = try gpa.dupe(u8, server.pendingOutput());
    defer gpa.free(p);
    var rx: record.Protection = undefined;
    try rx.init(.aes_256_gcm_sha384, &server.server_application_secret);
    defer rx.wipe();
    const h = record.parseHeader(p[0..5]);
    try testing.expectEqual(p.len, 5 + h.length); // one record
    const o = try rx.open(p);
    try testing.expectEqual(record.ContentType.handshake, o.content_type);
    var nonces: [3][]const u8 = undefined;
    var tickets: [3][]const u8 = undefined;
    var age_adds: [3]u32 = undefined;
    var at: usize = 0;
    var n: usize = 0;
    while (at < o.content.len) : (n += 1) {
        try testing.expectEqual(@as(u8, 4), o.content[at]);
        const len = std.mem.readInt(u24, o.content[at + 1 ..][0..3], .big);
        var exts: [4]tlsresume.ticket.Extension = undefined;
        const t = try tlsresume.ticket.NewSessionTicket.decode(o.content[at + 4 ..][0..len], &exts);
        try testing.expectEqual(server_mod.max_ticket_lifetime_s, t.ticket_lifetime);
        try testing.expectEqual(@as(usize, 1), t.extensions.len);
        const g = t.extensions[0].ext_type;
        try testing.expect(g & 0x0f0f == 0x0a0a and g >> 8 == g & 0xff); // RFC 8701 GREASE
        nonces[n] = t.ticket_nonce;
        tickets[n] = t.ticket;
        age_adds[n] = t.ticket_age_add;
        at += 4 + len;
    }
    try testing.expectEqual(@as(usize, 3), n);
    for (0..3) |i| for (i + 1..3) |j| {
        try testing.expect(!std.mem.eql(u8, nonces[i], nonces[j]));
        try testing.expect(!std.mem.eql(u8, tickets[i], tickets[j]));
        try testing.expect(age_adds[i] != age_adds[j]);
    };
}

// ── client certificates ──────────────────────────────────────────────────

const client_certs = @import("client_certs.zig");
const clientauth = @import("clientauth.zig");

/// A client CA trusted through `x509`, at the test clock (2030).
const ClientAuthFixture = struct {
    verifier: clientauth.X509Verifier,
    auth: server_mod.ClientAuth,

    fn init(fx: *ClientAuthFixture, mandatory: bool) void {
        fx.verifier = .{ .gpa = testing.allocator, .anchors = &.{&client_certs.ca_cert} };
        fx.auth = .{ .verifier = fx.verifier.verifier(), .mandatory = mandatory, .clock = .{ .now_ms = clock2030 } };
    }

    fn clock2030(_: ?*anyopaque) i64 {
        return 1_900_000_000_000;
    }
};

const ClientKeys = struct {
    p256: ZlClient.ClientAuth.PrivateKey,
    ed25519: ZlClient.ClientAuth.PrivateKey,
    rsa: ZlClient.ClientAuth.PrivateKey,
    rsa_kp: rsa.KeyPair,
    server_only: ZlClient.ClientAuth.PrivateKey,
    expired: ZlClient.ClientAuth.PrivateKey,
    stranger: ZlClient.ClientAuth.PrivateKey,

    fn init(k: *ClientKeys) !void {
        k.p256 = .{ .ecdsa_secp256r1_sha256 = client_certs.p256_scalar };
        k.ed25519 = .{ .ed25519 = client_certs.ed25519_secret[0..32].* };
        try rsa.SecretKey.fromDer(&k.rsa_kp.secret_key, &client_certs.rsa2048_pkcs1);
        k.rsa = .{ .rsa = &k.rsa_kp };
        k.server_only = .{ .ecdsa_secp256r1_sha256 = client_certs.server_only_scalar };
        k.expired = .{ .ecdsa_secp256r1_sha256 = client_certs.expired_scalar };
        k.stranger = .{ .ecdsa_secp256r1_sha256 = client_certs.stranger_scalar };
    }
};

fn clientCert(der: []const u8, key: *const ZlClient.ClientAuth.PrivateKey, chain: *[1][]const u8) ZlClient.ClientAuth {
    chain[0] = der;
    return .{ .certificate_chain = chain, .key = key };
}

test "tlsclient ↔ Server: client certificates of every kind, verified by x509, every suite" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    var ca: ClientAuthFixture = undefined;
    ca.init(true);
    var keys: ClientKeys = undefined;
    try keys.init();
    const cases = [_]struct { []const u8, *const ZlClient.ClientAuth.PrivateKey }{
        .{ &client_certs.p256_cert, &keys.p256 },
        .{ &client_certs.ed25519_cert, &keys.ed25519 },
        .{ &client_certs.rsa2048_cert, &keys.rsa },
    };
    for (cases) |c| for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        errdefer std.debug.print("suite {t}, client key {t}\n", .{ suite, c[1].* });
        var chain: [1][]const u8 = undefined;
        const o = try handshake(ZlClient, testing.allocator, &ck, .{ .suites = &.{suite}, .client_auth = &ca.auth }, .{ .client_auth = clientCert(c[0], c[1], &chain) });
        defer o.deinit(testing.allocator);
        try testing.expectEqualStrings("hello there", o.echoed);
        try testing.expectEqualSlices(u8, c[0], o.peer.?);
    };
}

/// The schemes a key can make, as `Offload.schemes` lists them.
fn schemesOf(key: tls13.certverify.SecretKey, buf: *[4]u16) []const u16 {
    const c = tls13.certverify.candidateSchemes(key);
    for (c, 0..) |s, i| buf[i] = @backingInt(s);
    return buf[0..c.len];
}

test "tlsclient ↔ Server: an offloaded key signs between feeds — every key kind, every suite, after a HelloRetryRequest, with a client certificate" {
    var fx: Fixture = undefined;
    try fx.init();
    const chains = [_][1][]const u8{ .{&certs.p256_cert}, .{&certs.p384_cert}, .{&certs.ed25519_cert}, .{&certs.rsa2048_cert} };
    const keys = [_]tls13.certverify.SecretKey{ .{ .ecdsa_p256 = &fx.p256 }, .{ .ecdsa_p384 = &fx.p384 }, .{ .ed25519 = &fx.ed25519 }, .{ .rsa = &fx.rsa2048 } };
    var ca: ClientAuthFixture = undefined;
    ca.init(true);
    var ckeys: ClientKeys = undefined;
    try ckeys.init();
    for (keys, &chains) |key, *chain| for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        errdefer std.debug.print("suite {t}, key {t}\n", .{ suite, key });
        var sb: [4]u16 = undefined;
        for ([_]bool{ false, true }) |verify| {
            const ck: server_mod.CertifiedKey = .{ .chain = chain, .key = null, .offload = .{ .schemes = schemesOf(key, &sb), .verify = verify } };
            try ck.check();
            var storage: [16 * 1024]u8 = undefined;
            var info: ZlClient.ConnectionInfo = .init(&storage);
            const o = try handshake(ZlClient, testing.allocator, &ck, .{ .suites = &.{suite}, .offload_key = key }, .{ .info = &info });
            defer o.deinit(testing.allocator);
            try testing.expectEqualStrings("hello there", o.echoed);
            try testing.expectEqual(@as(usize, 1), o.signed);
            try testing.expectEqualSlices(u8, chain[0], info.peerCertificates()[0]);
        }
        // A HelloRetryRequest first (the server's group has no share), and a
        // client certificate after the signature.
        const ck: server_mod.CertifiedKey = .{ .chain = chain, .key = null, .offload = .{ .schemes = schemesOf(key, &sb) } };
        var cchain: [1][]const u8 = undefined;
        const o = try handshake(ZlClient, testing.allocator, &ck, .{
            .suites = &.{suite},
            .groups = &.{tls13.kex.secp256r1_group},
            .client_auth = &ca.auth,
            .offload_key = key,
        }, .{ .client_auth = clientCert(&client_certs.p256_cert, &ckeys.p256, &cchain) });
        defer o.deinit(testing.allocator);
        try testing.expect(o.retried);
        try testing.expectEqual(@as(usize, 1), o.signed);
        try testing.expectEqualSlices(u8, &client_certs.p256_cert, o.peer.?);
    };
}

test "tlsclient ↔ Server: a resumption with an offloaded key asks for no signature" {
    var fx: Fixture = undefined;
    try fx.init();
    const key: tls13.certverify.SecretKey = .{ .ecdsa_p256 = &fx.p256 };
    var sb: [4]u16 = undefined;
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = null, .offload = .{ .schemes = schemesOf(key, &sb) } };
    var tf: TicketFixture = undefined;
    tf.init();
    const entries = try testing.allocator.alloc(ZlClient.ClientSession, 2);
    defer testing.allocator.free(entries);
    var cache: ZlClient.SessionCache = .init(entries, null);
    defer cache.deinit();
    const first = try handshake(ZlClient, testing.allocator, &ck, .{ .tickets = &tf.tickets, .offload_key = key }, .{ .session_cache = &cache });
    defer first.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), first.signed);
    const again = try handshake(ZlClient, testing.allocator, &ck, .{ .tickets = &tf.tickets, .offload_key = key }, .{ .session_cache = &cache });
    defer again.deinit(testing.allocator);
    try testing.expect(again.resumed);
    try testing.expectEqual(@as(usize, 0), again.signed);
}

/// `ClientAuthSelect` that sends no certificate, and records the request.
const NoCert = struct {
    authorities: usize = 0,
    first_authority: [64]u8 = undefined,
    first_len: usize = 0,
    schemes: usize = 0,

    fn select(ctx: ?*anyopaque, info: *const ZlClient.CertificateRequestInfo) ?ZlClient.ClientAuth {
        const self: *NoCert = @ptrCast(@alignCast(ctx.?));
        self.authorities = info.certificate_authorities.len;
        self.schemes = info.signature_schemes.len;
        if (info.certificate_authorities.len != 0) {
            const a = info.certificate_authorities[0];
            @memcpy(self.first_authority[0..a.len], a);
            self.first_len = a.len;
        }
        return null;
    }
};

test "tlsclient ↔ Server: no client certificate — certificate_required, or on unauthenticated" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    var ca: ClientAuthFixture = undefined;
    ca.init(true);
    ca.auth.authorities = &.{&client_certs.ca_name};
    var nc: NoCert = .{};
    try testing.expectError(error.CertificateRequired, handshake(ZlClient, testing.allocator, &ck, .{ .client_auth = &ca.auth }, .{ .client_auth_select = .{ .context = &nc, .select = NoCert.select } }));
    // The request named the CA and the default schemes.
    try testing.expectEqual(@as(usize, 1), nc.authorities);
    try testing.expectEqualSlices(u8, &client_certs.ca_name, nc.first_authority[0..nc.first_len]);
    try testing.expectEqual(server_mod.default_client_auth_schemes.len, nc.schemes);

    ca.auth.mandatory = false;
    const o = try handshake(ZlClient, testing.allocator, &ck, .{ .client_auth = &ca.auth }, .{ .client_auth_select = .{ .context = &nc, .select = NoCert.select } });
    defer o.deinit(testing.allocator);
    try testing.expectEqualStrings("hello there", o.echoed);
    try testing.expectEqual(null, o.peer);
}

test "tlsclient ↔ Server: a client certificate the verifier refuses gets its alert" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    var ca: ClientAuthFixture = undefined;
    ca.init(false);
    var keys: ClientKeys = undefined;
    try keys.init();
    const cases = [_]struct { []const u8, *const ZlClient.ClientAuth.PrivateKey, server_mod.Error }{
        .{ &client_certs.server_only_cert, &keys.server_only, error.UnsupportedCertificate },
        .{ &client_certs.expired_cert, &keys.expired, error.CertificateExpired },
        .{ &client_certs.stranger_cert, &keys.stranger, error.UnknownCa },
    };
    for (cases) |c| {
        var chain: [1][]const u8 = undefined;
        try testing.expectError(c[2], handshake(ZlClient, testing.allocator, &ck, .{ .client_auth = &ca.auth }, .{ .client_auth = clientCert(c[0], c[1], &chain) }));
    }
    // A key that does not match the certificate: the CertificateVerify fails.
    var chain: [1][]const u8 = undefined;
    try testing.expectError(error.DecryptError, handshake(ZlClient, testing.allocator, &ck, .{ .client_auth = &ca.auth }, .{ .client_auth = clientCert(&client_certs.p256_cert, &keys.stranger, &chain) }));
}

test "tlsclient ↔ Server: a resumption keeps the client certificate; a mandatory one needs a ticket with it" {
    var fx: Fixture = undefined;
    try fx.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    var ca: ClientAuthFixture = undefined;
    ca.init(true);
    var keys: ClientKeys = undefined;
    try keys.init();
    var tf: TicketFixture = undefined;
    tf.init();
    for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 }) |suite| {
        errdefer std.debug.print("suite {t}\n", .{suite});
        const entries = try testing.allocator.alloc(ZlClient.ClientSession, 2);
        defer testing.allocator.free(entries);
        var cache: ZlClient.SessionCache = .init(entries, null);
        defer cache.deinit();
        const srv: ServerSide = .{ .suites = &.{suite}, .tickets = &tf.tickets, .client_auth = &ca.auth };
        for (0..3) |round| {
            var chain: [1][]const u8 = undefined;
            const o = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &cache, .client_auth = clientCert(&client_certs.rsa2048_cert, &keys.rsa, &chain) });
            defer o.deinit(testing.allocator);
            try testing.expectEqual(round != 0, o.resumed);
            try testing.expectEqualSlices(u8, &client_certs.rsa2048_cert, o.peer.?);
        }
    }

    // Re-issued tickets do not extend the certificate: past the lifetime
    // from the full handshake that proved it, a full handshake again
    // (each resumption's own ticket is younger than the lifetime).
    {
        var tf2: TicketFixture = undefined;
        tf2.init();
        tf2.tickets.lifetime_s = 3600;
        const entries = try testing.allocator.alloc(ZlClient.ClientSession, 2);
        defer testing.allocator.free(entries);
        var cache: ZlClient.SessionCache = .init(entries, null);
        defer cache.deinit();
        const srv: ServerSide = .{ .tickets = &tf2.tickets, .client_auth = &ca.auth };
        for ([_]bool{ false, true, true, false }) |want_resumed| {
            var chain: [1][]const u8 = undefined;
            const o = try handshake(ZlClient, testing.allocator, &ck, srv, .{ .session_cache = &cache, .client_auth = clientCert(&client_certs.p256_cert, &keys.p256, &chain) });
            defer o.deinit(testing.allocator);
            try testing.expectEqual(want_resumed, o.resumed);
            tf2.now_ms += 1500 * 1000;
        }
    }

    // A ticket from an unauthenticated session (an optional certificate,
    // none sent): resumed while the certificate stays optional, not once it
    // is mandatory — that handshake asks for one.
    const entries = try testing.allocator.alloc(ZlClient.ClientSession, 2);
    defer testing.allocator.free(entries);
    var cache: ZlClient.SessionCache = .init(entries, null);
    defer cache.deinit();
    ca.auth.mandatory = false;
    var nc: NoCert = .{};
    const srv: ServerSide = .{ .tickets = &tf.tickets, .client_auth = &ca.auth };
    const anon: ClientOffer = .{ .session_cache = &cache, .client_auth_select = .{ .context = &nc, .select = NoCert.select } };
    const first = try handshake(ZlClient, testing.allocator, &ck, srv, anon);
    first.deinit(testing.allocator);
    const again = try handshake(ZlClient, testing.allocator, &ck, srv, anon);
    defer again.deinit(testing.allocator);
    try testing.expect(again.resumed and again.peer == null);
    ca.auth.mandatory = true;
    try testing.expectError(error.CertificateRequired, handshake(ZlClient, testing.allocator, &ck, srv, anon));
}

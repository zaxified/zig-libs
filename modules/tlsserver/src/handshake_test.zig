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
    try client.writer.writeAll("GET / HTTP/1.1\r\n\r\n");
    try client.writer.flush();
    try pipe.pump();
    if (pipe.failure) |f| return f;
    try testing.expect(pipe.handshake_done);
    try testing.expect(server.isConnected());
    try testing.expectEqualStrings("localhost", server.serverName().?);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", pipe.received.items);

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

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
    echoed: []u8,
};

/// What `tlsclient` offers beyond std's defaults (ignored for std's client).
const ClientOffer = struct {
    groups: ?[]const std.crypto.tls.NamedGroup = null,
    key_share_groups: ?[]const std.crypto.tls.NamedGroup = null,
    alpn: []const []const u8 = &.{},
    /// Filled by `tlsclient` (Go's ConnectionState).
    info: ?*ZlClient.ConnectionInfo = null,
};

const ServerSide = struct {
    suites: []const record.CipherSuite = &server_mod.default_cipher_suites,
    groups: []const u16 = &server_mod.default_groups,
    alpn: []const []const u8 = &.{},
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
    };
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, server_mod.minOutputLen(ck) + 64 * 1024);
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
    const now: std.Io.Timestamp = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s); // 2030
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
    }) else StdClient.init(&pipe.reader, &pipe.client_out, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = now,
    })) catch |err| {
        std.debug.print("client: {t}; server: {?t}\n", .{ err, pipe.failure });
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
        .echoed = try gpa.dupe(u8, got[0..n]),
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

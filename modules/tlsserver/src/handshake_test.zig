// SPDX-License-Identifier: MIT

//! End-to-end handshakes in one thread: Zig std's `crypto.tls.Client` (an
//! independent TLS 1.3 client) against `Server`, joined by in-memory
//! pipes. The client's input `Reader` drives the server whenever the client
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

const Server = server_mod.Server;
const Client = std.crypto.tls.Client;

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
    ed25519: std.crypto.sign.Ed25519.SecretKey,

    fn init() !Fixture {
        return .{
            .p256 = try .fromBytes(certs.p256_scalar),
            .ed25519 = try .fromBytes(certs.ed25519_secret),
        };
    }
};

const Outcome = struct {
    suite: record.CipherSuite,
    echoed: []u8,
};

/// One handshake against the server enabling only `server_suites` and
/// `server_groups`, then a request, a response, and close_notify.
fn handshake(gpa: std.mem.Allocator, ck: *const server_mod.CertifiedKey, server_suites: []const record.CipherSuite, server_groups: []const u16) !Outcome {
    var prng = std.Random.DefaultPrng.init(0x7e57);
    const config: server_mod.Config = .{
        .certificate = .{ .fixed = ck },
        .cipher_suites = server_suites,
        .groups = server_groups,
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
    var client = Client.init(&pipe.reader, &pipe.client_out, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s), // 2030
    }) catch |err| {
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
    return .{ .suite = server.cipherSuite().?, .echoed = try gpa.dupe(u8, got[0..n]) };
}

const p256_chain = [_][]const u8{&certs.p256_cert};

test "std client ↔ Server: ECDSA P-256, every suite, the hybrid group" {
    var fx = try Fixture.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    for ([_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        const o = try handshake(testing.allocator, &ck, &.{suite}, &server_mod.default_groups);
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
    var fx = try Fixture.init();
    const ck: server_mod.CertifiedKey = .{ .chain = &p256_chain, .key = .{ .ecdsa_p256 = &fx.p256 } };
    for ([_]u16{ tls13.kex.x25519_group, tls13.kex.secp256r1_group }) |g| {
        const o = try handshake(testing.allocator, &ck, &server_mod.default_cipher_suites, &.{g});
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
        const o = try handshake(testing.allocator, &ck, &server_mod.default_cipher_suites, &server_mod.default_groups);
        defer testing.allocator.free(o.echoed);
        try testing.expectEqualStrings("hello there", o.echoed);
    }
}

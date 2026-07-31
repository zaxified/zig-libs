// SPDX-License-Identifier: MIT

//! RFC 6455 §1.3/§4 opening handshake: server-side request validation +
//! response, and client-side request generation + response verification.
//! Built on `http.h1.RequestHead` / `http.h1.ResponseHead` — this module
//! parses the *WebSocket-specific* headers out of an already-parsed HTTP
//! head; the HTTP framing itself (`readHead`, `RequestHead.parse`,
//! `ResponseHead.parse`) is `http`'s job.

const std = @import("std");
const http = @import("http");
const h1 = http.h1;

/// RFC 6455 §1.3: fixed GUID concatenated onto the client's key before
/// hashing. Not a secret — it exists only to make the accept value
/// unguessable by anything that didn't see the opening handshake (e.g. a
/// naive HTTP cache).
pub const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const HandshakeError = error{
    /// The request method was not GET (§4.1 point 1).
    NotGet,
    /// The request was HTTP/1.0; the handshake requires HTTP/1.1 or
    /// greater (§4.1 point 1).
    UnsupportedHttpVersion,
    /// No `Upgrade` header, or it does not contain the `websocket` token
    /// (§4.1 point 3 / §4.2.1 point 3).
    MissingUpgrade,
    /// No `Connection` header, or it does not contain the `Upgrade` token
    /// (§4.1 point 4 / §4.2.1 point 4).
    MissingConnection,
    /// `Sec-WebSocket-Version` missing or not `"13"` (§4.2.1 point 6). This
    /// module implements only version 13 (the final RFC version).
    UnsupportedVersion,
    /// `Sec-WebSocket-Key` header missing (§4.2.1 point 5).
    MissingKey,
    /// `Sec-WebSocket-Key` present but not a well-formed 16-byte
    /// base64-encoded nonce (§4.2.1 point 5) — always exactly 24 base64
    /// characters for 16 bytes.
    InvalidKey,
    /// (Client side) the response status was not 101.
    UnexpectedStatus,
    /// (Client side) the response advertised a `Sec-WebSocket-Protocol`
    /// the client never offered (§4.1 point 10 forbids this).
    UnexpectedSubprotocol,
    /// (Client side) `Sec-WebSocket-Accept` is missing or does not match
    /// the value computed from the key the client sent (§4.1 point 9) —
    /// the core anti-cache-poisoning / anti-cross-protocol check.
    AcceptMismatch,
};

/// SHA-1(key ++ guid), base64-encoded — RFC 6455 §1.3/§4.2.2 point 5.4.
/// `key` is the raw header value (already OWS-trimmed by the HTTP header
/// parser), not base64-decoded — the spec hashes the *encoded* nonce
/// string, not its decoded bytes.
///
/// Verified against the RFC §1.3 worked example:
/// `computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==")` ==
/// `"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="`.
pub fn computeAcceptKey(key: []const u8) [28]u8 {
    var sha: std.crypto.hash.Sha1 = .init(.{});
    sha.update(key);
    sha.update(guid);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha.final(&digest);

    var out: [28]u8 = undefined;
    const written = std.base64.standard.Encoder.encode(&out, &digest);
    std.debug.assert(written.len == 28);
    return out;
}

/// §4.2.1 point 5: the key, base64-decoded, MUST be exactly 16 bytes.
/// Standard padded base64 of exactly 16 bytes is always exactly 24
/// characters (no other length can decode to 16 bytes under the padded
/// alphabet), so the length check alone is a correct and cheap first gate;
/// the decode call then rejects anything that merely *looks* like 24
/// base64-alphabet characters without actually being valid.
fn validateKey(key: []const u8) HandshakeError!void {
    if (key.len != 24) return error.InvalidKey;
    var decoded: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&decoded, key) catch return error.InvalidKey;
}

// ── server side ─────────────────────────────────────────────────────────

pub const ServerAcceptOptions = struct {
    /// Subprotocols this server is willing to speak, in the server's
    /// preference order. `acceptHandshake` selects the first one the
    /// client also offered in its `Sec-WebSocket-Protocol` list (client
    /// preference order, server-supported set) — empty means no
    /// subprotocol negotiation happens and `ServerAccept.protocol` is
    /// always null.
    protocols: []const []const u8 = &.{},
};

pub const ServerAccept = struct {
    /// The value for the response's `Sec-WebSocket-Accept` header.
    accept_key: [28]u8,
    /// The negotiated subprotocol (borrows `options.protocols`), or null.
    protocol: ?[]const u8,
};

/// Validate a client's upgrade request (§4.2.1) and compute the response
/// fields. Does not write anything — pass the result to `writeResponse`.
/// Rejects with a typed `HandshakeError` on any malformed or non-conformant
/// request; never panics on attacker-controlled header values.
pub fn acceptHandshake(head: h1.RequestHead, options: ServerAcceptOptions) HandshakeError!ServerAccept {
    if (!std.ascii.eqlIgnoreCase(head.method, "GET")) return error.NotGet;
    if (head.http1_0) return error.UnsupportedHttpVersion;

    const upgrade = head.header("upgrade") orelse return error.MissingUpgrade;
    if (!h1.tokenListContains(upgrade, "websocket")) return error.MissingUpgrade;

    const connection = head.header("connection") orelse return error.MissingConnection;
    if (!h1.tokenListContains(connection, "upgrade")) return error.MissingConnection;

    const version = head.header("sec-websocket-version") orelse return error.UnsupportedVersion;
    if (!std.mem.eql(u8, version, "13")) return error.UnsupportedVersion;

    const key = head.header("sec-websocket-key") orelse return error.MissingKey;
    try validateKey(key);

    var protocol: ?[]const u8 = null;
    if (options.protocols.len > 0) {
        if (head.header("sec-websocket-protocol")) |offered| {
            protocol = selectProtocol(offered, options.protocols);
        }
    }

    return .{ .accept_key = computeAcceptKey(key), .protocol = protocol };
}

/// First token in the comma-separated `offered` list (client preference
/// order) that case-insensitively matches an entry in `allowed`
/// (server-supported set). Returns a slice of `allowed` (stable regardless
/// of the client buffer's lifetime).
fn selectProtocol(offered: []const u8, allowed: []const []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, offered, ',');
    while (it.next()) |raw| {
        const tok = std.mem.trim(u8, raw, " \t");
        for (allowed) |a| {
            if (std.ascii.eqlIgnoreCase(tok, a)) return a;
        }
    }
    return null;
}

/// Write the `101 Switching Protocols` response (§4.2.2) for a validated
/// `ServerAccept`.
pub fn writeResponse(w: *std.Io.Writer, accept: ServerAccept) std.Io.Writer.Error!void {
    try w.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
    try w.writeAll("Upgrade: websocket\r\n");
    try w.writeAll("Connection: Upgrade\r\n");
    try w.writeAll("Sec-WebSocket-Accept: ");
    try w.writeAll(&accept.accept_key);
    try w.writeAll("\r\n");
    if (accept.protocol) |p| {
        try w.writeAll("Sec-WebSocket-Protocol: ");
        try w.writeAll(p);
        try w.writeAll("\r\n");
    }
    try w.writeAll("\r\n");
}

// ── client side ─────────────────────────────────────────────────────────

/// Generate a fresh `Sec-WebSocket-Key` (§4.1 point 7): 16 random bytes,
/// base64-encoded to 24 characters. `random` is caller-supplied — this
/// module never reaches for `std.crypto.random` itself, so the caller
/// controls the CSPRNG (and can substitute a deterministic one in tests).
pub fn generateKey(random: std.Random) [24]u8 {
    var raw: [16]u8 = undefined;
    random.bytes(&raw);
    var out: [24]u8 = undefined;
    const written = std.base64.standard.Encoder.encode(&out, &raw);
    std.debug.assert(written.len == 24);
    return out;
}

pub const ClientRequestOptions = struct {
    /// `Host` header value (`host` or `host:port`).
    host: []const u8,
    /// Request target, e.g. `"/chat"`. Defaults to `"/"`.
    target: []const u8 = "/",
    /// The key from `generateKey` — keep it to pass to `verifyResponse`.
    key: []const u8,
    /// Subprotocols to offer, in preference order. Empty = no
    /// `Sec-WebSocket-Protocol` header sent.
    protocols: []const []const u8 = &.{},
    /// Additional headers to send verbatim (e.g. `Origin`, cookies,
    /// bearer auth) after the required WebSocket headers.
    extra_headers: []const http.Header = &.{},
};

/// Write the client's upgrade request (§4.1).
pub fn writeRequest(w: *std.Io.Writer, options: ClientRequestOptions) std.Io.Writer.Error!void {
    try w.print("GET {s} HTTP/1.1\r\n", .{options.target});
    try w.print("Host: {s}\r\n", .{options.host});
    try w.writeAll("Upgrade: websocket\r\n");
    try w.writeAll("Connection: Upgrade\r\n");
    try w.print("Sec-WebSocket-Key: {s}\r\n", .{options.key});
    try w.writeAll("Sec-WebSocket-Version: 13\r\n");
    if (options.protocols.len > 0) {
        try w.writeAll("Sec-WebSocket-Protocol: ");
        for (options.protocols, 0..) |p, i| {
            if (i > 0) try w.writeAll(", ");
            try w.writeAll(p);
        }
        try w.writeAll("\r\n");
    }
    for (options.extra_headers) |h| {
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try w.writeAll("\r\n");
}

pub const ClientVerifyResult = struct {
    /// The subprotocol the server selected, or null.
    protocol: ?[]const u8,
};

/// Verify a server's `101` response against the `key` the client sent and
/// the `offered_protocols` it advertised (§4.1 points 8-10). Rejects on
/// any mismatch — in particular an accept-value mismatch, which is the
/// handshake's core integrity check (a transparent proxy or cache that
/// mangled/replayed the response is caught here).
pub fn verifyResponse(head: h1.ResponseHead, key: []const u8, offered_protocols: []const []const u8) HandshakeError!ClientVerifyResult {
    if (head.status != 101) return error.UnexpectedStatus;

    const upgrade = head.header("upgrade") orelse return error.MissingUpgrade;
    if (!h1.tokenListContains(upgrade, "websocket")) return error.MissingUpgrade;

    const connection = head.header("connection") orelse return error.MissingConnection;
    if (!h1.tokenListContains(connection, "upgrade")) return error.MissingConnection;

    const accept = head.header("sec-websocket-accept") orelse return error.AcceptMismatch;
    const expected = computeAcceptKey(key);
    if (!std.mem.eql(u8, accept, &expected)) return error.AcceptMismatch;

    var protocol: ?[]const u8 = null;
    if (head.header("sec-websocket-protocol")) |p| {
        var matched = false;
        for (offered_protocols) |o| {
            if (std.ascii.eqlIgnoreCase(o, p)) {
                matched = true;
                break;
            }
        }
        if (!matched) return error.UnexpectedSubprotocol;
        protocol = p;
    }
    return .{ .protocol = protocol };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// RFC 6455 §1.3 worked example, byte-exact.
test "computeAcceptKey: RFC 1.3 worked example" {
    const accept = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

// RFC 6455 §1.3 example request, verbatim.
test "acceptHandshake: RFC 1.3 example request" {
    const req =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Origin: http://example.com\r\n" ++
        "Sec-WebSocket-Protocol: chat, superchat\r\n" ++
        "Sec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    const accept = try acceptHandshake(head, .{ .protocols = &.{"chat"} });
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept.accept_key);
    try testing.expectEqualStrings("chat", accept.protocol.?);

    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try writeResponse(&out, accept);
    const resp = out.buffered();
    try testing.expect(std.mem.indexOf(u8, resp, "101 Switching Protocols") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "Sec-WebSocket-Protocol: chat") != null);
}

test "acceptHandshake: rejects non-GET" {
    const req = "POST /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.NotGet, acceptHandshake(head, .{}));
}

test "acceptHandshake: rejects missing Upgrade" {
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.MissingUpgrade, acceptHandshake(head, .{}));
}

test "acceptHandshake: rejects missing Connection: Upgrade" {
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.MissingConnection, acceptHandshake(head, .{}));
}

test "acceptHandshake: rejects wrong version" {
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.UnsupportedVersion, acceptHandshake(head, .{}));
}

test "acceptHandshake: rejects missing key" {
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.MissingKey, acceptHandshake(head, .{}));
}

test "acceptHandshake: rejects malformed key (wrong decoded length)" {
    // "dGVzdA==" decodes to 4 bytes, not 16.
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.InvalidKey, acceptHandshake(head, .{}));
}

test "acceptHandshake: rejects key with invalid base64 characters" {
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: !!!!not-b64!!!!!!!!!!!!!\r\nSec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.InvalidKey, acceptHandshake(head, .{}));
}

test "acceptHandshake: client's first-choice protocol unsupported, second choice matches" {
    // Client offers "superchat, chat" (its own preference order); the server
    // only supports "chat". This must still find "chat" further down the
    // offered list, not just check the first token.
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: superchat, chat\r\nSec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    const accept = try acceptHandshake(head, .{ .protocols = &.{"chat"} });
    try testing.expectEqualStrings("chat", accept.protocol.?);
}

test "acceptHandshake: no protocols offered -> no negotiation, always null" {
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    const accept = try acceptHandshake(head, .{});
    try testing.expectEqual(@as(?[]const u8, null), accept.protocol);
}

test "client round trip: generateKey + writeRequest + verifyResponse" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const key = generateKey(prng.random());

    var req_buf: [512]u8 = undefined;
    var req_out: std.Io.Writer = .fixed(&req_buf);
    try writeRequest(&req_out, .{ .host = "example.com", .target = "/ws", .key = &key, .protocols = &.{"chat"} });
    const req = req_out.buffered();
    try testing.expect(std.mem.indexOf(u8, req, "GET /ws HTTP/1.1") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Protocol: chat") != null);

    // Server side computes the accept for the same key.
    const accept_key = computeAcceptKey(&key);
    var resp_buf: [256]u8 = undefined;
    var resp_out: std.Io.Writer = .fixed(&resp_buf);
    try writeResponse(&resp_out, .{ .accept_key = accept_key, .protocol = "chat" });

    const resp_head = try h1.ResponseHead.parse(resp_out.buffered());
    const result = try verifyResponse(resp_head, &key, &.{"chat"});
    try testing.expectEqualStrings("chat", result.protocol.?);
}

test "verifyResponse: rejects accept mismatch" {
    var prng = std.Random.DefaultPrng.init(1);
    const key = generateKey(prng.random());
    const resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: bm90dGhlcmlnaHR2YWx1ZSE=\r\n\r\n";
    const head = try h1.ResponseHead.parse(resp);
    try testing.expectError(error.AcceptMismatch, verifyResponse(head, &key, &.{}));
}

test "verifyResponse: rejects non-101 status" {
    const resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
    const head = try h1.ResponseHead.parse(resp);
    try testing.expectError(error.UnexpectedStatus, verifyResponse(head, "dGhlIHNhbXBsZSBub25jZQ==", &.{}));
}

test "verifyResponse: rejects an unoffered subprotocol" {
    const accept = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    var resp_buf: [256]u8 = undefined;
    var resp_out: std.Io.Writer = .fixed(&resp_buf);
    try writeResponse(&resp_out, .{ .accept_key = accept, .protocol = "sneaky" });
    const head = try h1.ResponseHead.parse(resp_out.buffered());
    try testing.expectError(error.UnexpectedSubprotocol, verifyResponse(head, "dGhlIHNhbXBsZSBub25jZQ==", &.{"chat"}));
}

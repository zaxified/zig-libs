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
    /// `Upgrade`, `Connection`, `Sec-WebSocket-Version` or
    /// `Sec-WebSocket-Key` appeared more than once (server-side request), or
    /// `Upgrade`, `Connection`, `Sec-WebSocket-Accept` or
    /// `Sec-WebSocket-Protocol` appeared more than once (client-side
    /// response). RFC 6455 §4.1/§4.2.1 say nothing about a duplicated
    /// instance of any of these header fields — fetched and read 2026-08-07
    /// (https://www.rfc-editor.org/rfc/rfc6455.html): the opening-handshake
    /// sections defer silently to general HTTP header processing (RFC 2616)
    /// for anything they do not spell out themselves, and that generic
    /// fallback does not resolve a duplicate either. `h1.RequestHead.header`
    /// / `h1.ResponseHead.header` return only the first occurrence, so a
    /// duplicate used to be silently first-wins — an intermediary in front
    /// of (or behind) this endpoint that combines the values or picks the
    /// last would derive a different accept key, or a different
    /// upgrade/protocol decision, from the same bytes. Undefined + silently
    /// resolved is the dangerous combination, so this is rejected rather
    /// than left to chance.
    DuplicateHeader,
    /// (Client side) the response status was not 101.
    UnexpectedStatus,
    /// (Client side) the response advertised a `Sec-WebSocket-Protocol`
    /// the client never offered (§4.1 point 10 forbids this).
    UnexpectedSubprotocol,
    /// (Client side) the response carried a `Sec-WebSocket-Extensions`
    /// header naming an extension the client never offered (§4.1 point 5:
    /// "the client MUST _Fail the WebSocket Connection_"). This module
    /// never offers any extension (see SPEC.md — no `Sec-WebSocket-
    /// Extensions` is ever sent by `writeRequest`), so *any* value in the
    /// response's `Sec-WebSocket-Extensions` header is by definition one
    /// the client did not ask for.
    UnexpectedExtension,
    /// (Client side) `Sec-WebSocket-Accept` is missing or does not match
    /// the value computed from the key the client sent (§4.1 point 9) —
    /// the core anti-cache-poisoning / anti-cross-protocol check.
    AcceptMismatch,
    /// (Client side, `writeRequest`) `host`, `target`, `key`, a
    /// `protocols` entry, or an `extra_headers` name/value contained a
    /// byte (CR, LF, NUL, or — for `host`/`target` — another control or
    /// disallowed character) that would let the caller's input inject
    /// extra header lines or split the request. Every field is written
    /// verbatim onto the wire, so this is the module's only line of
    /// defense against a caller that forwards attacker-controlled values
    /// (e.g. `extra_headers` built from a cookie or bearer token).
    InvalidRequestField,
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

    // W3-websocket-F10: `sec-websocket-protocol` was the one handshake
    // header `countHeader` didn't cover — `acceptHandshake` negotiates by
    // taking the *first* occurrence (`selectProtocol` below), same as every
    // other header here, so a duplicate silently negotiated whichever value
    // came first while an intermediary reading the last would believe a
    // different subprotocol won. Same class as the other four, closed the
    // same way.
    inline for (.{ "upgrade", "connection", "sec-websocket-version", "sec-websocket-key", "sec-websocket-protocol" }) |name| {
        if (countHeader(head, name) > 1) return error.DuplicateHeader;
    }

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

/// How many header fields named `name` (case-insensitive) appear in `head`.
/// `head.header(name)` only ever returns the first, so this is the only way
/// to notice a duplicate at all.
fn countHeader(head: h1.RequestHead, name: []const u8) usize {
    var n: usize = 0;
    var it = head.iterate();
    while (it.next()) |e| {
        if (std.ascii.eqlIgnoreCase(e.name, name)) n += 1;
    }
    return n;
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

/// W3-websocket-F2: every `ClientRequestOptions` field used to go onto the
/// wire byte-for-byte, with no check at all — `target`, `host`, `key`, each
/// `protocols` entry, and each `extra_headers` name/value. A CR/LF in any of
/// them splits the request line or injects extra header lines (request
/// smuggling); a bare LF alone is enough against a lenient parser. Reuses
/// `http`'s own field-syntax predicates (`h1.isValidHost`,
/// `h1.isValidRequestTarget`, `h1.isToken`, `h1.isValidFieldValue`) — the
/// same ones `http.Server`'s `setHeader` holds outbound response headers to
/// (`Server.zig:2282`), so the client side of this module is now held to the
/// class of check the server side of the sibling module already has.
/// Checked before anything is written, so a rejected call never puts a
/// partially-built request on the wire.
fn validRequestFields(options: ClientRequestOptions) bool {
    if (!h1.isValidHost(options.host)) return false;
    if (!h1.isValidRequestTarget(options.target)) return false;
    if (!h1.isValidFieldValue(options.key)) return false;
    for (options.protocols) |p| if (!h1.isToken(p)) return false;
    for (options.extra_headers) |h| {
        if (!h1.isToken(h.name)) return false;
        if (!h1.isValidFieldValue(h.value)) return false;
    }
    return true;
}

/// Write the client's upgrade request (§4.1). Returns
/// `error.InvalidRequestField` if any field would inject bytes into the
/// header block or split the request line — see `validRequestFields`.
pub fn writeRequest(w: *std.Io.Writer, options: ClientRequestOptions) (std.Io.Writer.Error || error{InvalidRequestField})!void {
    if (!validRequestFields(options)) return error.InvalidRequestField;
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

    // W3-websocket-F3: `verifyResponse` had no duplicate-header check at
    // all, though the server side (`acceptHandshake`) has one and explains
    // at length why (`DuplicateHeader`'s doc comment) — an intermediary that
    // combines or picks-last from a duplicated `Sec-WebSocket-Accept` would
    // derive a different accept key than the one checked below; a
    // duplicated `Upgrade`/`Connection` is the same ambiguity on the
    // negotiation decision itself; a duplicated `Sec-WebSocket-Protocol` is
    // the client-side twin of F10.
    inline for (.{ "upgrade", "connection", "sec-websocket-accept", "sec-websocket-protocol" }) |name| {
        if (countResponseHeader(head, name) > 1) return error.DuplicateHeader;
    }

    const upgrade = head.header("upgrade") orelse return error.MissingUpgrade;
    if (!h1.tokenListContains(upgrade, "websocket")) return error.MissingUpgrade;

    const connection = head.header("connection") orelse return error.MissingConnection;
    if (!h1.tokenListContains(connection, "upgrade")) return error.MissingConnection;

    const accept = head.header("sec-websocket-accept") orelse return error.AcceptMismatch;
    const expected = computeAcceptKey(key);
    if (!std.mem.eql(u8, accept, &expected)) return error.AcceptMismatch;

    // W3-websocket-F1: RFC 6455 §4.1 point 5 (the item right before point 6,
    // which `UnexpectedSubprotocol` below already implements) requires
    // failing the connection if the response names an extension the client
    // never offered. This module never offers one (SPEC.md: "no extension
    // negotiation of any kind is implemented"), so any value here is
    // unrequested by construction.
    if (head.header("sec-websocket-extensions") != null) return error.UnexpectedExtension;

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

/// How many header fields named `name` (case-insensitive) appear in `head`.
/// Client-side twin of `countHeader` above, for `verifyResponse` (F3).
fn countResponseHeader(head: h1.ResponseHead, name: []const u8) usize {
    var n: usize = 0;
    var it = head.iterate();
    while (it.next()) |e| {
        if (std.ascii.eqlIgnoreCase(e.name, name)) n += 1;
    }
    return n;
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

test "acceptHandshake: rejects a duplicated Sec-WebSocket-Key" {
    // Two different keys under the same header name. `head.header()` only
    // ever returns the first, so this used to silently accept and hash the
    // first key — a proxy that combined or preferred the last key would
    // compute a different Sec-WebSocket-Accept from the same request.
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.DuplicateHeader, acceptHandshake(head, .{}));
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

// W3-websocket-F1: RFC 6455 §4.1 point 5 — a response naming an extension
// the client never offered MUST fail the connection. This module never
// offers any extension, so any value here is unrequested by construction.
test "verifyResponse: rejects a Sec-WebSocket-Extensions the client never offered" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = computeAcceptKey(key);
    const resp = try std.fmt.allocPrint(testing.allocator, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n", .{accept});
    defer testing.allocator.free(resp);
    const head = try h1.ResponseHead.parse(resp);
    try testing.expectError(error.UnexpectedExtension, verifyResponse(head, key, &.{}));
}

// Positive control: the same response with no Sec-WebSocket-Extensions
// header at all (what a conforming server sends, since this module never
// offers one) must still be accepted.
test "verifyResponse: positive control, no Sec-WebSocket-Extensions header is fine" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = computeAcceptKey(key);
    var resp_buf: [256]u8 = undefined;
    var resp_out: std.Io.Writer = .fixed(&resp_buf);
    try writeResponse(&resp_out, .{ .accept_key = accept, .protocol = null });
    const head = try h1.ResponseHead.parse(resp_out.buffered());
    _ = try verifyResponse(head, key, &.{});
}

// W3-websocket-F3: duplicate handshake-critical response headers used to go
// unchecked on the client side, though the server side (`acceptHandshake`)
// rejects the same shape via `DuplicateHeader`.
test "verifyResponse: rejects duplicate Sec-WebSocket-Accept" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = computeAcceptKey(key);
    const resp = try std.fmt.allocPrint(testing.allocator, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n", .{accept});
    defer testing.allocator.free(resp);
    const head = try h1.ResponseHead.parse(resp);
    try testing.expectError(error.DuplicateHeader, verifyResponse(head, key, &.{}));
}

test "verifyResponse: rejects duplicate Upgrade" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = computeAcceptKey(key);
    const resp = try std.fmt.allocPrint(testing.allocator, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{accept});
    defer testing.allocator.free(resp);
    const head = try h1.ResponseHead.parse(resp);
    try testing.expectError(error.DuplicateHeader, verifyResponse(head, key, &.{}));
}

test "verifyResponse: rejects duplicate Sec-WebSocket-Protocol" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = computeAcceptKey(key);
    const resp = try std.fmt.allocPrint(testing.allocator, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: superchat\r\n\r\n", .{accept});
    defer testing.allocator.free(resp);
    const head = try h1.ResponseHead.parse(resp);
    try testing.expectError(error.DuplicateHeader, verifyResponse(head, key, &.{ "chat", "superchat" }));
}

// W3-websocket-F10: server-side twin — `sec-websocket-protocol` was the one
// handshake header `countHeader` didn't cover.
test "acceptHandshake: rejects a duplicated Sec-WebSocket-Protocol" {
    const req = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Protocol: chat\r\n" ++
        "Sec-WebSocket-Protocol: admin\r\n" ++
        "Sec-WebSocket-Version: 13\r\n";
    const head = try h1.RequestHead.parse(req);
    try testing.expectError(error.DuplicateHeader, acceptHandshake(head, .{ .protocols = &.{ "admin", "chat" } }));
}

// W3-websocket-F2: every `ClientRequestOptions` field used to go onto the
// wire byte-for-byte with no check — CR/LF/NUL injection via any of them.
// Naming each vector the way the audit measured it (8 of 8).
test "writeRequest: rejects CR/LF/NUL injection in every field" {
    var buf: [512]u8 = undefined;

    // target: splits the request line into a second request.
    {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidRequestField, writeRequest(&w, .{ .host = "h", .target = "/ws\r\nGET /admin HTTP/1.1\r\nX: 1", .key = "k" }));
    }
    // host: RFC 9110-illegal Host bytes, including a CRLF-smuggled second header.
    {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidRequestField, writeRequest(&w, .{ .host = "h\r\nX-Injected: yes", .target = "/", .key = "k" }));
    }
    // key: base64 field, but still checked — a NUL must not sail through.
    {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidRequestField, writeRequest(&w, .{ .host = "h", .target = "/", .key = "abc\x00def" }));
    }
    // protocols: a comma is legal syntax elsewhere but not inside one token.
    {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidRequestField, writeRequest(&w, .{ .host = "h", .target = "/", .key = "k", .protocols = &.{"chat\r\nX-Injected: yes"} }));
    }
    // extra_headers name.
    {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidRequestField, writeRequest(&w, .{ .host = "h", .target = "/", .key = "k", .extra_headers = &.{.{ .name = "Cookie\r\nX-Injected", .value = "1" }} }));
    }
    // extra_headers value: the exact attack from the audit report.
    {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidRequestField, writeRequest(&w, .{ .host = "h", .target = "/", .key = "k", .extra_headers = &.{.{ .name = "Cookie", .value = "sid=abc\r\nAuthorization: Bearer attacker-token\r\nX-Smuggled: 1" }} }));
    }
    // a bare LF alone (no CR) is enough against a lenient parser.
    {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidRequestField, writeRequest(&w, .{ .host = "h", .target = "/x\nX-Injected: yes", .key = "k" }));
    }
    // NUL alone.
    {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.InvalidRequestField, writeRequest(&w, .{ .host = "h\x00x", .target = "/", .key = "k" }));
    }
}

// Positive control: ordinary fields (including a legitimate extra header)
// still write the exact request they always did.
test "writeRequest: positive control, ordinary fields still write correctly" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequest(&w, .{
        .host = "example.com:8080",
        .target = "/chat?x=1",
        .key = "dGhlIHNhbXBsZSBub25jZQ==",
        .protocols = &.{ "chat", "superchat" },
        .extra_headers = &.{.{ .name = "Origin", .value = "https://example.com" }},
    });
    const req = w.buffered();
    try testing.expect(std.mem.indexOf(u8, req, "GET /chat?x=1 HTTP/1.1\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Host: example.com:8080\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Protocol: chat, superchat\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Origin: https://example.com\r\n") != null);
}

// ── fuzz: verifyResponse off the wire, client role, never panics ───────────
//
// A1/websocket.md F5's "second half": `handshake.zig` had ZERO fuzz
// harnesses, on either side. `verifyResponse` is the client's ONLY defense
// against a malicious or compromised server response — including the
// accept-key check that RFC 6455 §4.1 point 9 calls the anti-cache-poisoning
// / anti-cross-protocol check — so this is the higher-value direction of the
// two (a server usually sits behind infrastructure that validates its own
// inbound requests; a client dials whatever address it was given).
//
// Genuinely attacker-controlled input is the raw response BYTES, not just
// the already-parsed `h1.ResponseHead` — so the harness fuzzes
// `h1.ResponseHead.parse` and `verifyResponse` together, exactly the two
// calls a real client makes back to back (see "client round trip" above).
// `key`/`offered_protocols` are the CLIENT's own values, not attacker input,
// so they stay fixed.

const fuzz = @import("testkit").fuzz;

/// Response blocks a **client** receives from its server, in the format
/// `Smith.slice` reads (one call, never `smith.bytes` + a ranged length —
/// see `frame.zig`'s fuzz harnesses for the measured reason that collapses
/// outside `--fuzz`). `fixed_key`/`fixed_offered` below are the values the
/// harness verifies every seed against — RFC 6455 §1.3's own worked example
/// key, so `computeAcceptKey(fixed_key)` is a literal anyone can check
/// against the spec rather than a value only this file knows.
const response_seeds = [_][]const u8{
    fuzz.seed("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"), // valid, no subprotocol
    fuzz.seed("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat\r\n\r\n"), // valid, offered subprotocol selected
    fuzz.seed("HTTP/1.1 400 Bad Request\r\n\r\n"), // UnexpectedStatus
    fuzz.seed("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"), // MissingUpgrade
    fuzz.seed("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"), // MissingConnection
    fuzz.seed("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n"), // AcceptMismatch -- the anti-cache-poisoning check itself
    fuzz.seed("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"), // DuplicateHeader
    fuzz.seed("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"), // UnexpectedExtension
    fuzz.seed("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: sneaky\r\n\r\n"), // UnexpectedSubprotocol
    fuzz.seed("not even close to an http response\r\n\r\n"), // rejected by h1.ResponseHead.parse itself, verifyResponse never runs
    fuzz.seed(""), // the empty body, deliberately -- also an h1 parse rejection
};

const fixed_key = "dGhlIHNhbXBsZSBub25jZQ==";
const fixed_offered = [_][]const u8{"chat"};

test "fuzz: verifyResponse never panics, client role (h1.ResponseHead.parse + verifyResponse together)" {
    try testing.fuzz({}, fuzzVerifyResponseClient, .{ .corpus = &response_seeds });
}

fn fuzzVerifyResponseClient(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const head = h1.ResponseHead.parse(buf[0..len]) catch return;
    _ = verifyResponse(head, fixed_key, &fixed_offered) catch return;
}

// ── fuzz: acceptHandshake off the wire, server role, never panics ──────────
//
// The other direction of the same gap: a server's FIRST look at a client is
// an untrusted upgrade request. Smaller corpus than the client side above —
// `acceptHandshake`'s checks are more numerous but each is a single `orelse`
// off a header lookup, not a multi-field integrity computation like
// `verifyResponse`'s accept-key check — but every named error variant still
// gets its own seed, same discipline.

/// Request blocks a **server** receives from a client, in the format
/// `Smith.slice` reads.
const request_seeds = [_][]const u8{
    fuzz.seed("GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"), // valid, no subprotocol
    fuzz.seed("GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n"), // valid, subprotocol negotiated
    fuzz.seed("POST /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"), // NotGet
    fuzz.seed("GET /chat HTTP/1.0\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"), // UnsupportedHttpVersion
    fuzz.seed("GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"), // MissingUpgrade
    fuzz.seed("GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"), // MissingConnection
    fuzz.seed("GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 12\r\n\r\n"), // UnsupportedVersion
    fuzz.seed("GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"), // MissingKey
    fuzz.seed("GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: tooshort\r\nSec-WebSocket-Version: 13\r\n\r\n"), // InvalidKey
    fuzz.seed("GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"), // DuplicateHeader
    fuzz.seed("not even close to an http request\r\n\r\n"), // rejected by h1.RequestHead.parse itself
    fuzz.seed(""), // the empty body, deliberately
};

test "fuzz: acceptHandshake never panics, server role (h1.RequestHead.parse + acceptHandshake together)" {
    try testing.fuzz({}, fuzzAcceptHandshakeServer, .{ .corpus = &request_seeds });
}

fn fuzzAcceptHandshakeServer(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const head = h1.RequestHead.parse(buf[0..len]) catch return;
    _ = acceptHandshake(head, .{ .protocols = &fixed_offered }) catch return;
}

test "corpus: every request seed reaches h1.RequestHead.parse, and acceptHandshake's own checks all fire" {
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var accepted_ok: usize = 0;
    var not_get: usize = 0;
    var unsupported_http_version: usize = 0;
    var missing_upgrade: usize = 0;
    var missing_connection: usize = 0;
    var unsupported_version: usize = 0;
    var missing_key: usize = 0;
    var invalid_key: usize = 0;
    var duplicate_header: usize = 0;

    for (request_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;

        const head = h1.RequestHead.parse(buf[0..len]) catch continue;
        parsed += 1;
        const result = acceptHandshake(head, .{ .protocols = &fixed_offered }) catch |e| {
            switch (e) {
                error.NotGet => not_get += 1,
                error.UnsupportedHttpVersion => unsupported_http_version += 1,
                error.MissingUpgrade => missing_upgrade += 1,
                error.MissingConnection => missing_connection += 1,
                error.UnsupportedVersion => unsupported_version += 1,
                error.MissingKey => missing_key += 1,
                error.InvalidKey => invalid_key += 1,
                error.DuplicateHeader => duplicate_header += 1,
                else => {},
            }
            continue;
        };
        _ = result;
        accepted_ok += 1;
    }

    try testing.expectEqual(request_seeds.len - 1, nonempty); // the empty body is a seed on purpose
    try testing.expectEqual(@as(usize, 10), parsed); // all but the two malformed-input seeds
    try testing.expectEqual(@as(usize, 2), accepted_ok); // seeds 0, 1
    try testing.expectEqual(@as(usize, 1), not_get);
    try testing.expectEqual(@as(usize, 1), unsupported_http_version);
    try testing.expectEqual(@as(usize, 1), missing_upgrade);
    try testing.expectEqual(@as(usize, 1), missing_connection);
    try testing.expectEqual(@as(usize, 1), unsupported_version);
    try testing.expectEqual(@as(usize, 1), missing_key);
    try testing.expectEqual(@as(usize, 1), invalid_key);
    try testing.expectEqual(@as(usize, 1), duplicate_header);
}

test "corpus: every response seed reaches h1.ResponseHead.parse, and verifyResponse's own checks all fire" {
    // ⭐ Executable measurement, not an asserted comment — `frame.zig`'s reach
    // tests are the precedent. `nonempty` catches a seed grown past the
    // 512-octet buffer; `parsed` catches a seed that never got past
    // `h1.ResponseHead.parse` at all (this harness's two malformed-input
    // seeds are DELIBERATELY in that bucket, so `parsed < nonempty` here is
    // the claim, not a bug); the per-error counters are the claim that
    // `verifyResponse`'s OWN checks -- not just the HTTP layer beneath it --
    // are what is being reached.
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var verified_ok: usize = 0;
    var unexpected_status: usize = 0;
    var missing_upgrade: usize = 0;
    var missing_connection: usize = 0;
    var accept_mismatch: usize = 0;
    var duplicate_header: usize = 0;
    var unexpected_extension: usize = 0;
    var unexpected_subprotocol: usize = 0;

    for (response_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;

        const head = h1.ResponseHead.parse(buf[0..len]) catch continue;
        parsed += 1;
        const result = verifyResponse(head, fixed_key, &fixed_offered) catch |e| {
            switch (e) {
                error.UnexpectedStatus => unexpected_status += 1,
                error.MissingUpgrade => missing_upgrade += 1,
                error.MissingConnection => missing_connection += 1,
                error.AcceptMismatch => accept_mismatch += 1,
                error.DuplicateHeader => duplicate_header += 1,
                error.UnexpectedExtension => unexpected_extension += 1,
                error.UnexpectedSubprotocol => unexpected_subprotocol += 1,
                else => {},
            }
            continue;
        };
        _ = result;
        verified_ok += 1;
    }

    // One short of the corpus length: the empty body is a seed on purpose
    // (same convention as `frame.zig`'s `close_seeds`).
    try testing.expectEqual(response_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 9), parsed); // all but the two malformed-input seeds
    try testing.expectEqual(@as(usize, 2), verified_ok); // seeds 0, 1
    try testing.expectEqual(@as(usize, 1), unexpected_status);
    try testing.expectEqual(@as(usize, 1), missing_upgrade);
    try testing.expectEqual(@as(usize, 1), missing_connection);
    try testing.expectEqual(@as(usize, 1), accept_mismatch);
    try testing.expectEqual(@as(usize, 1), duplicate_header);
    try testing.expectEqual(@as(usize, 1), unexpected_extension);
    try testing.expectEqual(@as(usize, 1), unexpected_subprotocol);
}

// SPDX-License-Identifier: MIT

//! coap server (C5) — the request-dispatch + response-building half of a CoAP
//! endpoint. Transport-agnostic: the caller receives datagrams on its own UDP
//! socket, parses them (C1), deduplicates by message id (`reliability.Dedup`,
//! C3), routes by `Uri-Path` (C2 `options.uriPath`), and builds a response with
//! the helpers here — either **piggybacked** in the ACK (the common case) or a
//! **separate** message when the answer isn't ready in time.
//!
//! ```zig
//! const req = try coap.parse(dgram, &opts);
//! if (!coap.server.isRequest(req)) return; // ACK/RST/empty → not for routing
//! if (dedup.check(req.message_id, now_ms) == .duplicate) return; // already handled
//! var it = coap.options.uriPath(req);
//! const resp = if (routeMatches(&it)) coap.server.piggyback(req, .content, &out_opts, body)
//!              else coap.server.piggyback(req, .not_found, &.{}, "");
//! const n = try coap.serialize(resp, &out);
//! send(out[0..n]);
//! ```

const std = @import("std");
const coap = @import("root.zig");

/// Whether `msg` is a request to route: a Confirmable or Non-confirmable
/// message carrying a request-class code (0.01..0.31, not the Empty message).
/// ACKs, RSTs and empty messages return false.
pub fn isRequest(msg: coap.Message) bool {
    return (msg.type == .confirmable or msg.type == .non_confirmable) and msg.code.isRequest();
}

/// Build a **piggybacked** response — an Acknowledgement carrying the response
/// (RFC 7252 §5.2.1). Echoes the request's message id and token; sets the
/// response `code` and any `options`/`payload`. Use this for a Confirmable
/// request answered immediately; for a Non-confirmable request, or a response
/// that isn't ready in time, use `Server.separate`.
pub fn piggyback(
    request: coap.Message,
    code: coap.Code,
    options: []const coap.Option,
    payload: []const u8,
) coap.Message {
    return .{
        .type = .ack,
        .code = code,
        .message_id = request.message_id,
        .token = request.token,
        .options = options,
        .payload = payload,
    };
}

/// Acknowledge a Confirmable request without a response yet (RFC 7252 §5.2.2) —
/// an empty ACK; the answer follows later via `Server.separate`.
pub fn ackOnly(request: coap.Message) coap.Message {
    return .{ .type = .ack, .code = .empty, .message_id = request.message_id };
}

/// A CoAP responding endpoint — just the message-id counter used for separate
/// (non-piggybacked) responses. Piggybacked responses reuse the request's id
/// and need no state, so they are the free `piggyback` above.
pub const Server = struct {
    next_mid: u16,

    pub fn init(seed_mid: u16) Server {
        return .{ .next_mid = seed_mid };
    }

    /// Build a **separate** response (RFC 7252 §5.2.2): a fresh Confirmable or
    /// Non-confirmable message that echoes the request's token but carries a
    /// new message id (consumed from the counter). Use after `ackOnly` when the
    /// answer wasn't ready in time, or to answer a Non-confirmable request.
    pub fn separate(
        self: *Server,
        request: coap.Message,
        code: coap.Code,
        options: []const coap.Option,
        payload: []const u8,
        confirmable: bool,
    ) coap.Message {
        const mid = self.next_mid;
        self.next_mid +%= 1;
        return .{
            .type = if (confirmable) .confirmable else .non_confirmable,
            .code = code,
            .message_id = mid,
            .token = request.token,
            .options = options,
            .payload = payload,
        };
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "isRequest: CON/NON request codes yes; ACK/RST/empty no" {
    try testing.expect(isRequest(.{ .type = .confirmable, .code = .get, .message_id = 1 }));
    try testing.expect(isRequest(.{ .type = .non_confirmable, .code = .post, .message_id = 1 }));
    // A response code on a CON is not a request.
    try testing.expect(!isRequest(.{ .type = .confirmable, .code = .content, .message_id = 1 }));
    // ACK / RST / empty are never requests.
    try testing.expect(!isRequest(.{ .type = .ack, .code = .get, .message_id = 1 }));
    try testing.expect(!isRequest(.{ .type = .reset, .code = .empty, .message_id = 1 }));
    try testing.expect(!isRequest(.{ .type = .confirmable, .code = .empty, .message_id = 1 }));
}

test "piggyback: ACK echoes the request id + token, carries the response" {
    const req: coap.Message = .{
        .type = .confirmable,
        .code = .get,
        .message_id = 0x2345,
        .token = &.{ 0xaa, 0xbb },
    };
    const body = "24.5";
    const resp = piggyback(req, .content, &.{}, body);
    try testing.expectEqual(coap.Type.ack, resp.type);
    try testing.expectEqual(coap.Code.content, resp.code);
    try testing.expectEqual(@as(u16, 0x2345), resp.message_id);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, resp.token);
    try testing.expectEqualStrings(body, resp.payload);

    // It serializes and round-trips.
    var out: [64]u8 = undefined;
    const n = try coap.serialize(resp, &out);
    var opts: [4]coap.Option = undefined;
    const back = try coap.parse(out[0..n], &opts);
    try testing.expectEqual(coap.Type.ack, back.type);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, back.token);
    try testing.expectEqualStrings(body, back.payload);
}

test "ackOnly + Server.separate: empty ACK then a fresh-id response with the token" {
    const req: coap.Message = .{
        .type = .confirmable,
        .code = .get,
        .message_id = 7,
        .token = &.{ 1, 2, 3, 4 },
    };
    const ack = ackOnly(req);
    try testing.expectEqual(coap.Type.ack, ack.type);
    try testing.expectEqual(coap.Code.empty, ack.code);
    try testing.expectEqual(@as(u16, 7), ack.message_id);
    try testing.expectEqual(@as(usize, 0), ack.token.len);

    var srv = Server.init(0x8000);
    const resp = srv.separate(req, .content, &.{}, "later", true);
    try testing.expectEqual(coap.Type.confirmable, resp.type);
    try testing.expectEqual(@as(u16, 0x8000), resp.message_id); // fresh id
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, resp.token); // echoes the token
    try testing.expectEqualStrings("later", resp.payload);
    try testing.expectEqual(@as(u16, 0x8001), srv.next_mid); // counter advanced

    // A NON separate response is typed NON.
    const non = srv.separate(req, .content, &.{}, "x", false);
    try testing.expectEqual(coap.Type.non_confirmable, non.type);
}

test "end-to-end: client request → server routes by Uri-Path → piggybacked reply" {
    const client = @import("client.zig");
    const optmod = coap.options;

    var c = client.Client.init(100, 0x10);
    var copts: [8]coap.Option = undefined;
    var cscratch: [64]u8 = undefined;
    var cout: [128]u8 = undefined;
    const req = try c.buildRequest(.get, "coap://h/temp", .{}, &copts, &cscratch, &cout);

    // Server parses the datagram, confirms it's a request, routes /temp.
    var sopts: [8]coap.Option = undefined;
    const rmsg = try coap.parse(req.datagram, &sopts);
    try testing.expect(isRequest(rmsg));
    var path = optmod.uriPath(rmsg);
    try testing.expectEqualStrings("temp", path.next().?);
    try testing.expect(path.next() == null);

    const resp = piggyback(rmsg, .content, &.{}, "21.0");
    var sout: [64]u8 = undefined;
    const n = try coap.serialize(resp, &sout);

    // Client correlates the reply to its exchange.
    var ropts: [8]coap.Option = undefined;
    const back = try coap.parse(sout[0..n], &ropts);
    try testing.expectEqual(client.Match.piggybacked, req.exchange.match(back));
    try testing.expectEqualStrings("21.0", back.payload);
}

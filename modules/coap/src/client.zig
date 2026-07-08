// SPDX-License-Identifier: MIT

//! coap client (C4) — the request-building + response-correlation half of a
//! CoAP endpoint, joining the codec (C1), the option/URI layer (C2) and the
//! reliability layer (C3). Transport-agnostic: `buildRequest` produces the
//! datagram bytes and an `Exchange` handle; the caller sends the bytes over its
//! own UDP socket and (for a Confirmable request) drives a
//! `reliability.Retransmit` with the returned message id, then hands each
//! received datagram to `Exchange.match` to correlate it.
//!
//! ```zig
//! var c = coap.Client.init(seed_mid, seed_token);
//! const req = try c.buildRequest(.get, "coap://sensor.local/temp", .{}, &opts, &scratch, &out);
//! send(req.datagram);
//! var rt = coap.reliability.Retransmit.init(.{}, now_ms, jitter);
//! // …on each received datagram:
//! const msg = try coap.parse(dgram, &in_opts);
//! switch (req.exchange.match(msg)) {
//!     .piggybacked, .separate => { rt.ack(); handle(msg); },
//!     .empty_ack => rt.ack(), // response will follow separately
//!     .reset => { rt.onReset(); fail(); },
//!     .unrelated => {},
//! }
//! ```

const std = @import("std");
const coap = @import("root.zig");
const opt = coap.options;

/// A pending request's identity, used to correlate incoming datagrams. Owns a
/// copy of the token, so it outlives the request buffer.
pub const Exchange = struct {
    token_buf: [coap.max_token_len]u8 = undefined,
    token_len: u8 = 0,
    message_id: u16,
    confirmable: bool,

    pub fn token(ex: *const Exchange) []const u8 {
        return ex.token_buf[0..ex.token_len];
    }

    /// How an incoming message relates to this exchange (RFC 7252 §5.3.2).
    pub fn match(ex: *const Exchange, msg: coap.Message) Match {
        const tok_eq = std.mem.eql(u8, ex.token(), msg.token);
        switch (msg.type) {
            // ACK / RST are correlated by message id.
            .ack => {
                if (msg.message_id != ex.message_id) return .unrelated;
                if (msg.code == .empty) return .empty_ack;
                return if (tok_eq) .piggybacked else .unrelated;
            },
            .reset => return if (msg.message_id == ex.message_id) .reset else .unrelated,
            // A separate response is correlated by token, not message id.
            .confirmable, .non_confirmable => return if (tok_eq and msg.code != .empty) .separate else .unrelated,
        }
    }
};

/// The relationship of an incoming datagram to a pending `Exchange`.
pub const Match = enum {
    /// An ACK carrying the response (piggybacked; same message id + token).
    piggybacked,
    /// A separate response (CON/NON) matched by token.
    separate,
    /// An empty ACK — the request was received; the response will follow
    /// separately.
    empty_ack,
    /// A Reset — the peer rejected the request.
    reset,
    /// Not for this exchange.
    unrelated,
};

pub const BuildError = opt.UriError || coap.SerializeError;

/// Per-request knobs.
pub const RequestOptions = struct {
    /// Confirmable (retransmitted) vs Non-confirmable (fire-and-forget).
    confirmable: bool = true,
    /// Request payload (empty ⇒ no payload).
    payload: []const u8 = "",
    /// `Content-Format` (option 12) describing `payload`, if any.
    content_format: ?u16 = null,
    /// `Accept` (option 17) — the response format the client prefers.
    accept: ?u16 = null,
    /// Token length to use (0..8). A shorter token is a smaller datagram; 4 is
    /// a common default that still makes cross-request collisions unlikely.
    token_len: u8 = 4,
};

/// A built request: the wire bytes to send + the handle to correlate replies.
pub const Request = struct {
    datagram: []const u8,
    exchange: Exchange,
};

/// A CoAP requesting endpoint — just the two monotonic counters (message id +
/// token) that keep requests distinguishable. Stateless otherwise; the
/// caller owns the socket and the retransmission timers.
pub const Client = struct {
    next_mid: u16,
    next_token: u64,

    pub fn init(seed_mid: u16, seed_token: u64) Client {
        return .{ .next_mid = seed_mid, .next_token = seed_token };
    }

    /// Build a request to `uri` with `method` (a request `Code`). URI-derived
    /// options (Uri-Host/Port/Path/Query) plus any `content_format`/`accept`
    /// are emitted in ascending order and serialized into `out`. `options_buf`
    /// holds the parsed options; `scratch` backs percent-decoded URI segments.
    /// Returns the datagram (a prefix of `out`) and the correlation `Exchange`.
    pub fn buildRequest(
        self: *Client,
        method: coap.Code,
        uri: []const u8,
        options: RequestOptions,
        options_buf: []coap.Option,
        scratch: []u8,
        out: []u8,
    ) BuildError!Request {
        // URI → options (host/port/path/query, already ascending).
        const uri_opts = try opt.optionsFromUri(uri, options_buf, scratch);
        var n = uri_opts.len;

        // Append content_format (12) / accept (17); a shared tail of `scratch`
        // holds their encoded uint bytes.
        var used = usedScratch(scratch, uri_opts);
        if (options.content_format) |cf| {
            n = try appendUint(options_buf, n, opt.number.content_format, cf, scratch, &used);
        }
        if (options.accept) |ac| {
            n = try appendUint(options_buf, n, opt.number.accept, ac, scratch, &used);
        }
        // Keep options ascending by number (stable — Uri-Path/Query order
        // within an equal number is preserved).
        std.sort.insertion(coap.Option, options_buf[0..n], {}, lessByNumber);

        // Fresh token + message id.
        var ex: Exchange = .{
            .message_id = self.next_mid,
            .confirmable = options.confirmable,
        };
        ex.token_len = @min(options.token_len, coap.max_token_len);
        writeToken(ex.token_buf[0..ex.token_len], self.next_token);
        self.next_mid +%= 1;
        self.next_token +%= 1;

        const msg: coap.Message = .{
            .type = if (options.confirmable) .confirmable else .non_confirmable,
            .code = method,
            .message_id = ex.message_id,
            .token = ex.token(),
            .options = options_buf[0..n],
            .payload = options.payload,
        };
        const len = try coap.serialize(msg, out);
        return .{ .datagram = out[0..len], .exchange = ex };
    }
};

fn lessByNumber(_: void, a: coap.Option, b: coap.Option) bool {
    return a.number < b.number;
}

/// Bytes of `scratch` already consumed by `optionsFromUri` (its option values
/// that borrow scratch end at the furthest such slice).
fn usedScratch(scratch: []const u8, options: []const coap.Option) usize {
    var end: usize = 0;
    const base = @intFromPtr(scratch.ptr);
    for (options) |o| {
        const p = @intFromPtr(o.value.ptr);
        if (p >= base and p < base + scratch.len) {
            const tail = (p - base) + o.value.len;
            if (tail > end) end = tail;
        }
    }
    return end;
}

fn appendUint(
    options_buf: []coap.Option,
    n: usize,
    number: u16,
    value: u16,
    scratch: []u8,
    used: *usize,
) opt.UriError!usize {
    if (n == options_buf.len) return error.TooManyOptions;
    var buf: [8]u8 = undefined;
    const enc = opt.encodeUint(value, &buf);
    if (scratch.len - used.* < enc.len) return error.ScratchTooSmall;
    const dst = scratch[used.* .. used.* + enc.len];
    @memcpy(dst, enc);
    used.* += enc.len;
    options_buf[n] = .{ .number = number, .value = dst };
    return n + 1;
}

/// Minimal big-endian token bytes from a counter (like a CoAP uint, but into a
/// fixed-width `dst` — a short token still stays unique across a counter run).
fn writeToken(dst: []u8, counter: u64) void {
    // Fill dst right-to-left with the low bytes of `counter`.
    var v = counter;
    var i: usize = dst.len;
    while (i > 0) {
        i -= 1;
        dst[i] = @truncate(v);
        v >>= 8;
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn findOption(msg: coap.Message, n: u16) ?[]const u8 {
    for (msg.options) |o| if (o.number == n) return o.value;
    return null;
}

test "buildRequest: URI + content-format + accept → a parseable request" {
    var c = Client.init(0x1000, 0x40);
    var opts: [16]coap.Option = undefined;
    var scratch: [128]u8 = undefined;
    var out: [256]u8 = undefined;

    const req = try c.buildRequest(.post, "coap://sensor.local/a/b?x=1", .{
        .payload = "42",
        .content_format = opt.content_format.text_plain,
        .accept = opt.content_format.json,
        .token_len = 4,
    }, &opts, &scratch, &out);

    // Parse it back and check everything landed in ascending option order.
    var in_opts: [16]coap.Option = undefined;
    const msg = try coap.parse(req.datagram, &in_opts);
    try testing.expectEqual(coap.Type.confirmable, msg.type);
    try testing.expectEqual(coap.Code.post, msg.code);
    try testing.expectEqual(@as(u16, 0x1000), msg.message_id);
    try testing.expectEqual(@as(usize, 4), msg.token.len);
    try testing.expectEqualStrings("42", msg.payload);

    try testing.expectEqualStrings("sensor.local", findOption(msg, opt.number.uri_host).?);
    try testing.expectEqual(@as(?u16, opt.content_format.text_plain), opt.contentFormat(msg));
    try testing.expectEqual(@as(?u16, opt.content_format.json), opt.accept(msg));
    var path = opt.uriPath(msg);
    try testing.expectEqualStrings("a", path.next().?);
    try testing.expectEqualStrings("b", path.next().?);
    try testing.expect(path.next() == null);
    var q = opt.uriQuery(msg);
    try testing.expectEqualStrings("x=1", q.next().?);

    // The counters advanced.
    try testing.expectEqual(@as(u16, 0x1001), c.next_mid);
    try testing.expectEqual(@as(u64, 0x41), c.next_token);
}

test "Exchange.match: piggybacked / separate / empty-ack / reset / unrelated" {
    var c = Client.init(5, 0x99);
    var opts: [8]coap.Option = undefined;
    var scratch: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const req = try c.buildRequest(.get, "coap://h/x", .{}, &opts, &scratch, &out);
    const ex = req.exchange;

    // Piggybacked response: ACK, same mid + token, a response code.
    try testing.expectEqual(Match.piggybacked, ex.match(.{
        .type = .ack,
        .code = .content,
        .message_id = 5,
        .token = ex.token(),
    }));
    // Empty ACK: same mid, empty code.
    try testing.expectEqual(Match.empty_ack, ex.match(.{
        .type = .ack,
        .code = .empty,
        .message_id = 5,
    }));
    // Separate response: CON with the same token, different mid.
    try testing.expectEqual(Match.separate, ex.match(.{
        .type = .confirmable,
        .code = .content,
        .message_id = 999,
        .token = ex.token(),
    }));
    // Reset for our mid.
    try testing.expectEqual(Match.reset, ex.match(.{
        .type = .reset,
        .code = .empty,
        .message_id = 5,
    }));
    // Wrong mid / wrong token → unrelated.
    try testing.expectEqual(Match.unrelated, ex.match(.{
        .type = .ack,
        .code = .content,
        .message_id = 6,
        .token = ex.token(),
    }));
    try testing.expectEqual(Match.unrelated, ex.match(.{
        .type = .confirmable,
        .code = .content,
        .message_id = 999,
        .token = "zzzz",
    }));
}

test "non-confirmable request is typed NON" {
    var c = Client.init(1, 1);
    var opts: [8]coap.Option = undefined;
    var scratch: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const req = try c.buildRequest(.get, "coap://h/p", .{ .confirmable = false }, &opts, &scratch, &out);
    try testing.expect(!req.exchange.confirmable);
    var in_opts: [8]coap.Option = undefined;
    const msg = try coap.parse(req.datagram, &in_opts);
    try testing.expectEqual(coap.Type.non_confirmable, msg.type);
}

// SPDX-License-Identifier: MIT

//! coap options (C2) — the typed CoAP option layer on top of the message codec:
//! the RFC 7252 §5.10 option-number registry + class bits (§5.4.6), the CoAP
//! variable-length uint value format (§3.2), typed accessors over a parsed
//! message (Content-Format / Accept / Max-Age / Uri-Path / Uri-Query), and the
//! §6 URI ↔ options mapping (`optionsFromUri` / `uriFromOptions`).
//!
//! The message codec (`coap.parse`/`serialize`) is value-agnostic; this layer
//! gives the options their meaning. Still zero-allocation — accessors borrow
//! the parsed message; the URI helpers use caller-provided buffers.

const std = @import("std");
const coap = @import("root.zig");
const Option = coap.Option;

// ── option-number registry (RFC 7252 §5.10 + §12.2) ─────────────────────────

/// Standard CoAP option numbers.
pub const number = struct {
    pub const if_match: u16 = 1;
    pub const uri_host: u16 = 3;
    pub const etag: u16 = 4;
    pub const if_none_match: u16 = 5;
    /// Observe (RFC 7641 §2).
    pub const observe: u16 = 6;
    pub const uri_port: u16 = 7;
    pub const location_path: u16 = 8;
    pub const uri_path: u16 = 11;
    pub const content_format: u16 = 12;
    pub const max_age: u16 = 14;
    pub const uri_query: u16 = 15;
    pub const accept: u16 = 17;
    pub const location_query: u16 = 20;
    /// Block2 — block-wise transfer of a response body (RFC 7959 §2.1).
    pub const block2: u16 = 23;
    /// Block1 — block-wise transfer of a request body (RFC 7959 §2.1).
    pub const block1: u16 = 27;
    /// Size2 — the size of the Block2 body, when known (RFC 7959 §4).
    pub const size2: u16 = 28;
    pub const proxy_uri: u16 = 35;
    pub const proxy_scheme: u16 = 39;
    pub const size1: u16 = 60;
};

/// Common Content-Format identifiers (RFC 7252 §12.3 + the CoAP Content-Formats
/// registry) for use with `content_format` / `accept` options.
pub const content_format = struct {
    pub const text_plain: u16 = 0;
    pub const link_format: u16 = 40;
    pub const xml: u16 = 41;
    pub const octet_stream: u16 = 42;
    pub const exi: u16 = 47;
    pub const json: u16 = 50;
    pub const cbor: u16 = 60;
};

/// The default `Max-Age` when the option is absent (RFC 7252 §5.10.5): 60 s.
pub const default_max_age: u64 = 60;

// ── option class bits (RFC 7252 §5.4.6) ─────────────────────────────────────
// The properties are encoded in the option number itself.

/// Critical (else Elective): an unrecognized critical option must be rejected
/// (4.02 for a request; the response is dropped) — an odd option number.
pub fn isCritical(n: u16) bool {
    return n & 1 == 1;
}

/// Unsafe to forward (a proxy that does not understand it must not forward).
pub fn isUnsafe(n: u16) bool {
    return n & 2 == 2;
}

/// NoCacheKey — excluded from the cache key when the pattern `0b11100` matches
/// (and the option is safe-to-forward).
pub fn noCacheKey(n: u16) bool {
    return n & 0x1e == 0x1c;
}

// ── CoAP uint value format (RFC 7252 §3.2) ──────────────────────────────────

/// Decode a CoAP option "uint": a variable-length (0..8 byte) big-endian
/// unsigned integer with no leading zero bytes; an empty value is 0.
pub fn decodeUint(bytes: []const u8) u64 {
    // Defensively fold only the last 8 bytes (registered uint options never
    // exceed 8; anything longer would overflow the shift).
    const tail = if (bytes.len > 8) bytes[bytes.len - 8 ..] else bytes;
    var result: u64 = 0;
    for (tail) |b| result = (result << 8) | b;
    return result;
}

/// Encode `value` as a minimal CoAP uint (big-endian, no leading zero bytes;
/// 0 → empty) into `buf`, returning the used prefix.
pub fn encodeUint(value: u64, buf: *[8]u8) []const u8 {
    std.mem.writeInt(u64, buf, value, .big);
    var start: usize = 0;
    while (start < buf.len and buf[start] == 0) start += 1;
    return buf[start..];
}

// ── typed accessors over a parsed message ───────────────────────────────────

/// First value of option `n` in `options` (which parse keeps sorted), or null.
fn firstOption(options: []const Option, n: u16) ?[]const u8 {
    for (options) |o| {
        if (o.number == n) return o.value;
        if (o.number > n) break; // sorted: no later match possible
    }
    return null;
}

/// The request/response `Content-Format` (option 12) as its identifier, or null
/// when absent.
pub fn contentFormat(msg: coap.Message) ?u16 {
    const v = firstOption(msg.options, number.content_format) orelse return null;
    return @truncate(decodeUint(v));
}

/// The `Accept` (option 17) content-format the client prefers, or null.
pub fn accept(msg: coap.Message) ?u16 {
    const v = firstOption(msg.options, number.accept) orelse return null;
    return @truncate(decodeUint(v));
}

/// The `Max-Age` (option 14) in seconds, or the §5.10.5 default (60) when
/// absent.
pub fn maxAge(msg: coap.Message) u64 {
    const v = firstOption(msg.options, number.max_age) orelse return default_max_age;
    return decodeUint(v);
}

/// Iterates the `Uri-Path` (option 11) segments in order — the request path,
/// one segment per option. Each `next()` is a path segment (already the decoded
/// bytes as they arrived on the wire).
pub const PathIterator = struct {
    options: []const Option,
    i: usize = 0,

    pub fn next(it: *PathIterator) ?[]const u8 {
        while (it.i < it.options.len) {
            const o = it.options[it.i];
            it.i += 1;
            if (o.number == number.uri_path) return o.value;
        }
        return null;
    }
};

pub fn uriPath(msg: coap.Message) PathIterator {
    return .{ .options = msg.options };
}

/// Iterates the `Uri-Query` (option 15) parameters in order — each a raw
/// `key=value` (or bare `key`) string as it arrived.
pub const QueryIterator = struct {
    options: []const Option,
    i: usize = 0,

    pub fn next(it: *QueryIterator) ?[]const u8 {
        while (it.i < it.options.len) {
            const o = it.options[it.i];
            it.i += 1;
            if (o.number == number.uri_query) return o.value;
        }
        return null;
    }
};

pub fn uriQuery(msg: coap.Message) QueryIterator {
    return .{ .options = msg.options };
}

// ── URI ↔ options mapping (RFC 7252 §6) ─────────────────────────────────────

pub const UriError = error{
    /// Scheme is not `coap`/`coaps`, or the URI is malformed.
    BadUri,
    /// More options than `out` can hold.
    TooManyOptions,
    /// `scratch` (for percent-decoded segments) is too small.
    ScratchTooSmall,
    /// `out` byte buffer too small (`uriFromOptions`).
    BufferTooSmall,
};

/// Default UDP ports: `coap` = 5683, `coaps` = 5684 (RFC 7252 §6.1/§6.2). A
/// port equal to the scheme default is omitted from the options.
pub const default_port: u16 = 5683;
pub const default_secure_port: u16 = 5684;

/// Decompose a CoAP URI into options (RFC 7252 §6.4): `Uri-Host` (option 3),
/// `Uri-Port` (7, only when non-default), one `Uri-Path` (11) per path segment,
/// one `Uri-Query` (15) per query parameter — emitted in ascending option
/// order so the result feeds `coap.serialize` directly. Percent-decoded
/// segments are written into `scratch`; option values borrow `scratch` (or the
/// input `uri`). Returns the filled option slice.
pub fn optionsFromUri(uri: []const u8, out: []Option, scratch: []u8) UriError![]Option {
    // 1. Scheme (case-insensitive): "coap://" or "coaps://".
    var secure = false;
    var rest: []const u8 = undefined;
    if (std.ascii.startsWithIgnoreCase(uri, "coap://")) {
        rest = uri["coap://".len..];
    } else if (std.ascii.startsWithIgnoreCase(uri, "coaps://")) {
        secure = true;
        rest = uri["coaps://".len..];
    } else return error.BadUri;

    var n: usize = 0;
    var scratch_used: usize = 0;

    // 2. Authority: up to the next '/', '?', or end.
    const authority_end = std.mem.indexOfAny(u8, rest, "/?") orelse rest.len;
    const authority = rest[0..authority_end];
    rest = rest[authority_end..];

    var host: []const u8 = undefined;
    var port_str: []const u8 = &.{};
    if (authority.len > 0 and authority[0] == '[') {
        // Bracketed IPv6 literal: strip the brackets.
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.BadUri;
        host = authority[1..close];
        const after = authority[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return error.BadUri;
            port_str = after[1..];
        }
    } else if (std.mem.indexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port_str = authority[colon + 1 ..];
    } else {
        host = authority;
    }
    if (host.len == 0) return error.BadUri;

    // Uri-Host (3): lower-cased (borrow the input when already lowercase).
    const host_lower = blk: {
        var has_upper = false;
        for (host) |c| {
            if (std.ascii.isUpper(c)) {
                has_upper = true;
                break;
            }
        }
        if (!has_upper) break :blk host;
        if (scratch.len - scratch_used < host.len) return error.ScratchTooSmall;
        const dst = scratch[scratch_used .. scratch_used + host.len];
        for (host, dst) |c, *d| d.* = std.ascii.toLower(c);
        scratch_used += host.len;
        break :blk dst;
    };
    if (n == out.len) return error.TooManyOptions;
    out[n] = .{ .number = number.uri_host, .value = host_lower };
    n += 1;

    // Uri-Port (7): only when present and non-default.
    if (port_str.len > 0) {
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.BadUri;
        const default: u16 = if (secure) default_secure_port else default_port;
        if (port != default) {
            if (scratch.len - scratch_used < 8) return error.ScratchTooSmall;
            var port_buf: [8]u8 = undefined;
            const encoded = encodeUint(port, &port_buf);
            const dst = scratch[scratch_used .. scratch_used + encoded.len];
            @memcpy(dst, encoded);
            scratch_used += encoded.len;
            if (n == out.len) return error.TooManyOptions;
            out[n] = .{ .number = number.uri_port, .value = dst };
            n += 1;
        }
    }

    // 3. Path: non-empty '/'-separated segments up to '?'.
    const query_start = std.mem.indexOfScalar(u8, rest, '?');
    const path = if (query_start) |q| rest[0..q] else rest;
    var seg_it = std.mem.splitScalar(u8, path, '/');
    while (seg_it.next()) |seg| {
        if (seg.len == 0) continue;
        const decoded = try decodeInto(seg, scratch, &scratch_used);
        if (n == out.len) return error.TooManyOptions;
        out[n] = .{ .number = number.uri_path, .value = decoded };
        n += 1;
    }

    // 4. Query: '&'-separated params after '?'.
    if (query_start) |q| {
        var param_it = std.mem.splitScalar(u8, rest[q + 1 ..], '&');
        while (param_it.next()) |param| {
            if (param.len == 0) continue;
            const decoded = try decodeInto(param, scratch, &scratch_used);
            if (n == out.len) return error.TooManyOptions;
            out[n] = .{ .number = number.uri_query, .value = decoded };
            n += 1;
        }
    }

    return out[0..n];
}

/// Percent-decode `src` into the unused tail of `scratch` (advancing
/// `scratch_used`), or borrow `src` verbatim when it has no escapes.
fn decodeInto(src: []const u8, scratch: []u8, scratch_used: *usize) UriError![]const u8 {
    if (std.mem.indexOfScalar(u8, src, '%') == null) return src;
    if (scratch.len - scratch_used.* < src.len) return error.ScratchTooSmall;
    const window = scratch[scratch_used.* .. scratch_used.* + src.len];
    const decoded = std.Uri.percentDecodeBackwards(window, src);
    scratch_used.* += src.len;
    return decoded;
}

/// Reconstruct an absolute CoAP URI (RFC 7252 §6.5) from options into `out`,
/// returning the used length. `secure` picks the `coap`/`coaps` scheme and the
/// default port; `Uri-Host`/`Uri-Port`/`Uri-Path`/`Uri-Query` options supply
/// the rest (a missing `Uri-Host` uses `fallback_host`). Path/query segments
/// are percent-encoded as needed.
pub fn uriFromOptions(
    options: []const Option,
    secure: bool,
    fallback_host: []const u8,
    out: []u8,
) UriError!usize {
    var w: std.Io.Writer = .fixed(out);
    write(&w, options, secure, fallback_host) catch return error.BufferTooSmall;
    return w.buffered().len;
}

fn write(
    w: *std.Io.Writer,
    options: []const Option,
    secure: bool,
    fallback_host: []const u8,
) std.Io.Writer.Error!void {
    try w.writeAll(if (secure) "coaps://" else "coap://");
    try w.writeAll(firstOption(options, number.uri_host) orelse fallback_host);

    if (firstOption(options, number.uri_port)) |port_bytes| {
        const port = decodeUint(port_bytes);
        const default: u16 = if (secure) default_secure_port else default_port;
        if (port != default) try w.print(":{d}", .{port});
    }

    var wrote_path = false;
    var path_it = PathIterator{ .options = options };
    while (path_it.next()) |seg| {
        try w.writeByte('/');
        try std.Uri.Component.percentEncode(w, seg, isPathSegmentChar);
        wrote_path = true;
    }
    if (!wrote_path) try w.writeByte('/');

    var first_param = true;
    var query_it = QueryIterator{ .options = options };
    while (query_it.next()) |param| {
        try w.writeByte(if (first_param) '?' else '&');
        try std.Uri.Component.percentEncode(w, param, isQueryParamChar);
        first_param = false;
    }
}

/// RFC 3986 `unreserved`.
fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '-', '.', '_', '~' => true,
        else => false,
    };
}

/// A char that may appear literally in a URI path segment (RFC 3986 `pchar`).
fn isPathSegmentChar(c: u8) bool {
    return isUnreserved(c) or switch (c) {
        // sub-delims + ':' '@'
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@' => true,
        else => false,
    };
}

/// A char that may appear literally in one Uri-Query param: `query` chars
/// minus '&' (the parameter separator must be escaped inside a param).
fn isQueryParamChar(c: u8) bool {
    return c != '&' and (isPathSegmentChar(c) or c == '/' or c == '?');
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "class bits" {
    try testing.expect(isCritical(number.uri_path)); // 11 odd → critical
    try testing.expect(!isCritical(number.content_format)); // 12 even → elective
    try testing.expect(isCritical(number.uri_host));
    try testing.expect(isUnsafe(number.proxy_uri)); // 35: unsafe to forward
    try testing.expect(isUnsafe(number.uri_path)); // 11 = 0b1011 → critical AND unsafe (RFC 7252 Table 4)
    try testing.expect(!isUnsafe(number.content_format)); // 12 = 0b1100 → safe to forward
    try testing.expect(noCacheKey(28)); // 0b11100 pattern
    try testing.expect(!noCacheKey(number.uri_path));
    try testing.expect(!noCacheKey(number.max_age));
}

test "decodeUint" {
    try testing.expectEqual(@as(u64, 0), decodeUint(&.{}));
    try testing.expectEqual(@as(u64, 60), decodeUint(&.{60}));
    try testing.expectEqual(@as(u64, 300), decodeUint(&.{ 0x01, 0x2c }));
    try testing.expectEqual(@as(u64, 0x0102030405060708), decodeUint(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }));
    // Defensive: over 8 bytes, only the last 8 are folded.
    try testing.expectEqual(@as(u64, 0x0102), decodeUint(&.{ 0xff, 0, 0, 0, 0, 0, 0, 1, 2 }));
}

test "encodeUint minimal big-endian" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{}, encodeUint(0, &buf));
    try testing.expectEqualSlices(u8, &.{60}, encodeUint(60, &buf));
    try testing.expectEqualSlices(u8, &.{255}, encodeUint(255, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, encodeUint(256, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x2c }, encodeUint(300, &buf));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, encodeUint(std.math.maxInt(u64), &buf));
}

test "uint round-trip has no leading zeros" {
    const cases = [_]u64{ 0, 1, 60, 255, 256, 300, 5683, 65535, 65536, 1 << 32, std.math.maxInt(u64) };
    for (cases) |v| {
        var buf: [8]u8 = undefined;
        const enc = encodeUint(v, &buf);
        if (enc.len > 0) try testing.expect(enc[0] != 0);
        try testing.expectEqual(v, decodeUint(enc));
    }
}

test "typed accessors over a hand-built message" {
    const opts = [_]Option{
        .{ .number = number.uri_path, .value = "sensors" },
        .{ .number = number.uri_path, .value = "temp" },
        .{ .number = number.content_format, .value = &.{50} }, // json
        .{ .number = number.max_age, .value = &.{ 0x01, 0x2c } }, // 300 s
        .{ .number = number.uri_query, .value = "unit=c" },
        .{ .number = number.uri_query, .value = "raw" },
        .{ .number = number.accept, .value = &.{} }, // 0 = text/plain
    };
    const msg = coap.Message{
        .type = .confirmable,
        .code = .get,
        .message_id = 0x1234,
        .options = &opts,
    };

    try testing.expectEqual(@as(?u16, content_format.json), contentFormat(msg));
    try testing.expectEqual(@as(?u16, content_format.text_plain), accept(msg));
    try testing.expectEqual(@as(u64, 300), maxAge(msg));

    var path = uriPath(msg);
    try testing.expectEqualStrings("sensors", path.next().?);
    try testing.expectEqualStrings("temp", path.next().?);
    try testing.expectEqual(@as(?[]const u8, null), path.next());

    var query = uriQuery(msg);
    try testing.expectEqualStrings("unit=c", query.next().?);
    try testing.expectEqualStrings("raw", query.next().?);
    try testing.expectEqual(@as(?[]const u8, null), query.next());
}

test "typed accessors absent options" {
    const msg = coap.Message{ .type = .confirmable, .code = .get, .message_id = 1 };
    try testing.expectEqual(@as(?u16, null), contentFormat(msg));
    try testing.expectEqual(@as(?u16, null), accept(msg));
    try testing.expectEqual(default_max_age, maxAge(msg));
    var path = uriPath(msg);
    try testing.expectEqual(@as(?[]const u8, null), path.next());
    var query = uriQuery(msg);
    try testing.expectEqual(@as(?[]const u8, null), query.next());
}

test "optionsFromUri: host, default port, path and query" {
    var out: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    const opts = try optionsFromUri("coap://example.com/a/b?x=1&y", &out, &scratch);

    try testing.expectEqual(@as(usize, 5), opts.len);
    try testing.expectEqual(number.uri_host, opts[0].number);
    try testing.expectEqualStrings("example.com", opts[0].value);
    try testing.expectEqual(number.uri_path, opts[1].number);
    try testing.expectEqualStrings("a", opts[1].value);
    try testing.expectEqual(number.uri_path, opts[2].number);
    try testing.expectEqualStrings("b", opts[2].value);
    try testing.expectEqual(number.uri_query, opts[3].number);
    try testing.expectEqualStrings("x=1", opts[3].value);
    try testing.expectEqual(number.uri_query, opts[4].number);
    try testing.expectEqualStrings("y", opts[4].value);

    // Ascending option numbers — ready for coap.serialize.
    for (opts[1..], opts[0 .. opts.len - 1]) |b, a| {
        try testing.expect(a.number <= b.number);
    }
}

test "optionsFromUri: non-default port becomes a Uri-Port uint" {
    var out: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    const opts = try optionsFromUri("coap://h:9999/p", &out, &scratch);

    try testing.expectEqual(@as(usize, 3), opts.len);
    try testing.expectEqual(number.uri_host, opts[0].number);
    try testing.expectEqualStrings("h", opts[0].value);
    try testing.expectEqual(number.uri_port, opts[1].number);
    try testing.expectEqual(@as(u64, 9999), decodeUint(opts[1].value));
    try testing.expectEqual(number.uri_path, opts[2].number);
    try testing.expectEqualStrings("p", opts[2].value);
}

test "optionsFromUri: default port is omitted, host lower-cased" {
    var out: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    const opts = try optionsFromUri("coap://Example.COM:5683/", &out, &scratch);
    try testing.expectEqual(@as(usize, 1), opts.len);
    try testing.expectEqual(number.uri_host, opts[0].number);
    try testing.expectEqualStrings("example.com", opts[0].value);
}

test "optionsFromUri: percent-decoded segment" {
    var out: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    const opts = try optionsFromUri("coap://h/a%20b", &out, &scratch);
    try testing.expectEqual(@as(usize, 2), opts.len);
    try testing.expectEqual(number.uri_path, opts[1].number);
    try testing.expectEqualStrings("a b", opts[1].value);
}

test "optionsFromUri: coaps scheme and its default port" {
    var out: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    // 5684 is coaps' default → omitted.
    const opts = try optionsFromUri("coaps://secure.example:5684/s", &out, &scratch);
    try testing.expectEqual(@as(usize, 2), opts.len);
    try testing.expectEqualStrings("secure.example", opts[0].value);
    try testing.expectEqualStrings("s", opts[1].value);

    // 5683 is NOT the coaps default → emitted.
    const opts2 = try optionsFromUri("coaps://secure.example:5683/s", &out, &scratch);
    try testing.expectEqual(@as(usize, 3), opts2.len);
    try testing.expectEqual(number.uri_port, opts2[1].number);
    try testing.expectEqual(@as(u64, 5683), decodeUint(opts2[1].value));
}

test "optionsFromUri: bracketed IPv6 host" {
    var out: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    const opts = try optionsFromUri("coap://[2001:db8::1]:9999/p", &out, &scratch);
    try testing.expectEqualStrings("2001:db8::1", opts[0].value);
    try testing.expectEqual(number.uri_port, opts[1].number);
    try testing.expectEqual(@as(u64, 9999), decodeUint(opts[1].value));
}

test "optionsFromUri: errors" {
    var out: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    try testing.expectError(error.BadUri, optionsFromUri("http://example.com/", &out, &scratch));
    try testing.expectError(error.BadUri, optionsFromUri("coap://", &out, &scratch));
    try testing.expectError(error.BadUri, optionsFromUri("coap://h:notaport/", &out, &scratch));

    var tiny_out: [1]Option = undefined;
    try testing.expectError(error.TooManyOptions, optionsFromUri("coap://h/a/b", &tiny_out, &scratch));

    var tiny_scratch: [2]u8 = undefined;
    try testing.expectError(error.ScratchTooSmall, optionsFromUri("coap://h/a%20b%20c", &out, &tiny_scratch));
}

test "uriFromOptions: representative option set" {
    var port_buf: [8]u8 = undefined;
    const opts = [_]Option{
        .{ .number = number.uri_host, .value = "example.com" },
        .{ .number = number.uri_port, .value = encodeUint(9999, &port_buf) },
        .{ .number = number.uri_path, .value = "a" },
        .{ .number = number.uri_path, .value = "b" },
        .{ .number = number.uri_query, .value = "x=1" },
        .{ .number = number.uri_query, .value = "y" },
    };
    var out: [128]u8 = undefined;
    const len = try uriFromOptions(&opts, false, "fallback", &out);
    try testing.expectEqualStrings("coap://example.com:9999/a/b?x=1&y", out[0..len]);
}

test "uriFromOptions: defaults — fallback host, default port, bare path" {
    var port_buf: [8]u8 = undefined;
    const opts = [_]Option{
        .{ .number = number.uri_port, .value = encodeUint(default_port, &port_buf) },
    };
    var out: [64]u8 = undefined;
    const len = try uriFromOptions(&opts, false, "fallback.host", &out);
    try testing.expectEqualStrings("coap://fallback.host/", out[0..len]);

    const none = [_]Option{};
    const len2 = try uriFromOptions(&none, true, "s.example", &out);
    try testing.expectEqualStrings("coaps://s.example/", out[0..len2]);
}

test "uriFromOptions: segment needing encoding is re-encoded" {
    const opts = [_]Option{
        .{ .number = number.uri_host, .value = "h" },
        .{ .number = number.uri_path, .value = "a b/c" },
        .{ .number = number.uri_query, .value = "k=a&b" },
    };
    var out: [64]u8 = undefined;
    const len = try uriFromOptions(&opts, false, "", &out);
    try testing.expectEqualStrings("coap://h/a%20b%2Fc?k=a%26b", out[0..len]);
}

test "uriFromOptions: BufferTooSmall" {
    const opts = [_]Option{
        .{ .number = number.uri_host, .value = "example.com" },
    };
    var out: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, uriFromOptions(&opts, false, "", &out));
}

test "URI round-trip preserves host, path and query" {
    var out_opts: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    const original = "coap://example.com:9999/a%20b/c?x=1&y";
    const opts = try optionsFromUri(original, &out_opts, &scratch);

    var uri_buf: [128]u8 = undefined;
    const len = try uriFromOptions(opts, false, "", &uri_buf);

    var out_opts2: [8]Option = undefined;
    var scratch2: [64]u8 = undefined;
    const opts2 = try optionsFromUri(uri_buf[0..len], &out_opts2, &scratch2);

    try testing.expectEqual(opts.len, opts2.len);
    for (opts, opts2) |a, b| {
        try testing.expectEqual(a.number, b.number);
        try testing.expectEqualSlices(u8, a.value, b.value);
    }
}

test "optionsFromUri feeds coap.serialize / coap.parse round-trip" {
    var out_opts: [8]Option = undefined;
    var scratch: [64]u8 = undefined;
    const opts = try optionsFromUri("coap://example.com:9999/sensors/temp?unit=c", &out_opts, &scratch);

    const msg = coap.Message{
        .type = .confirmable,
        .code = .get,
        .message_id = 0xbeef,
        .token = "\x01\x02",
        .options = opts,
    };
    var wire: [128]u8 = undefined;
    const wire_len = try coap.serialize(msg, &wire);

    var parsed_opts: [8]Option = undefined;
    const parsed = try coap.parse(wire[0..wire_len], &parsed_opts);
    try testing.expectEqual(msg.options.len, parsed.options.len);

    var path = uriPath(parsed);
    try testing.expectEqualStrings("sensors", path.next().?);
    try testing.expectEqualStrings("temp", path.next().?);
    try testing.expectEqual(@as(?[]const u8, null), path.next());
    var query = uriQuery(parsed);
    try testing.expectEqualStrings("unit=c", query.next().?);

    var uri_buf: [128]u8 = undefined;
    const len = try uriFromOptions(parsed.options, false, "", &uri_buf);
    try testing.expectEqualStrings("coap://example.com:9999/sensors/temp?unit=c", uri_buf[0..len]);
}

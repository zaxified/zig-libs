// SPDX-License-Identifier: MIT

//! accesslog — structured HTTP access-log formatter.
//!
//! One record (`Entry`) per request, emitted to a `std.Io.Writer` in any of
//! three formats: **JSON Lines** (one JSON object per line — the modern
//! structured default), **logfmt** (`key=value`, Heroku/Go
//! `kr/logfmt`-style), and the ubiquitous Apache/NGINX **Combined Log
//! Format** (`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`,
//! modeled after `mod_log_config`'s escaping — `ap_escape_logitem`).
//!
//! `Entry` is a plain struct: it carries no reference to a live HTTP
//! request, so it is usable standalone (tests, non-`http` transports,
//! replaying archived data). `entryFromRequest` is the convenience bridge
//! that pulls method/target/protocol/status/headers/peer out of an
//! `http.Server.Request` + `http.Server.ResponseWriter` for the common
//! case of logging one just-served request.
//!
//! ## Log-injection safety (the primary requirement)
//!
//! Every string field may originate from untrusted request data (path,
//! User-Agent, Referer, even the method on a hand-built `Entry`). Each
//! format's writer escapes rigorously so such a field can never: break out
//! of its JSON string / logfmt value / combined quoted field, inject a
//! newline that forges a second record, or emit a raw control byte. See
//! `writeJsonLines` / `writeLogfmt` / `writeCombined` for the per-format
//! escaping rule and the module tests for the adversarial vectors this was
//! verified against.
//!
//! ## Time contract — no system clock
//!
//! This module never reads the clock. `Entry.timestamp_ns` is a caller-
//! supplied nanosecond Unix timestamp, used verbatim (JSON/logfmt) or as a
//! numeric fallback for Combined's `[%t]` bracket. Combined's real shape
//! (`10/Oct/2000:13:55:36 -0700`) additionally needs a timezone-aware
//! calendar conversion that this module deliberately does not perform
//! (that is a formatting concern, not a logging one, and pulling it in
//! would mean guessing at a timezone policy) — a caller that wants the
//! spec-shaped bracket formats the string itself (e.g. with the `datefmt`
//! module) and passes it as `Entry.time_formatted`.
//!
//! Relationship to `metrics.AccessLog`: the `metrics` module ships a small
//! built-in access-log writer (JSON/Combined, driven off its narrower
//! `AccessEntry` — method/path/status/duration/bytes only, no host/UA/
//! referer/time/request-id). This module is the standalone, fuller-fielded
//! formatter for when those extra fields matter; the two are independent
//! and neither depends on the other.

const std = @import("std");
const http = @import("http");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    // Pure functions over caller-supplied data / a caller-supplied Writer;
    // no shared or internal state.
    .concurrency = .reentrant,
    .model_after = "Apache mod_log_config (Combined Log Format + ap_escape_logitem escaping) + Heroku/kr logfmt + the common JSON-Lines access-log convention (Caddy/nginx json access log)",
    .deps = .{"http"},
};

// ── the record ───────────────────────────────────────────────────────────

/// One access-log record. Plain data — no allocation, no borrowed
/// lifetimes beyond "valid until you're done formatting it". Optional
/// fields render per format: JSON emits an explicit `null`; logfmt omits
/// the key; Combined uses the `-` placeholder (its own convention).
pub const Entry = struct {
    /// Caller-supplied timestamp, nanoseconds since the Unix epoch. This
    /// module never reads the system clock — see the module doc's "Time
    /// contract".
    timestamp_ns: i64,
    /// Preformatted time string for Combined's `[%t]` bracket (e.g.
    /// `"22/Jul/2026:10:00:00 +0000"`). Null falls back to writing the raw
    /// `timestamp_ns` inside the brackets — still one well-formed field,
    /// just not calendar-shaped. Ignored by JSON/logfmt (they use
    /// `timestamp_ns` directly, no ambiguity to resolve).
    time_formatted: ?[]const u8 = null,
    /// Client address (and port, when the caller includes one), e.g.
    /// `"192.0.2.1:54321"`. Null when unknown (no live connection, e.g. a
    /// trusted-proxy deployment with no forwarded-for signal parsed yet).
    remote_addr: ?[]const u8 = null,
    /// Request method token, e.g. `"GET"`.
    method: []const u8,
    /// Raw request-target as sent, e.g. `"/path?q=1"` or `"*"`.
    target: []const u8,
    /// Protocol version string, e.g. `"HTTP/1.1"`.
    protocol: []const u8 = "HTTP/1.1",
    /// Response status code.
    status: u16,
    /// Request body byte count, when known (e.g. the declared
    /// `Content-Length`; null for chunked/unknown).
    request_bytes: ?u64 = null,
    /// Response body byte count, when known (null for streamed responses
    /// with no running total — see `entryFromRequest`'s helper for the
    /// exact contract against `http.Server.ResponseWriter`).
    response_bytes: ?u64 = null,
    /// Request→response latency in nanoseconds, when the caller timed it.
    latency_ns: ?u64 = null,
    /// `User-Agent` header value, if present.
    user_agent: ?[]const u8 = null,
    /// `Referer` header value, if present.
    referer: ?[]const u8 = null,
    /// Correlation / request id (e.g. from the `requestid` module), if any.
    request_id: ?[]const u8 = null,
};

/// Selects which `write*` function `write` dispatches to. Each format is
/// also directly callable (`writeJsonLines`/`writeLogfmt`/`writeCombined`)
/// when the caller already knows which one it wants.
pub const Format = enum { json_lines, logfmt, combined };

/// Emit `entry` in `format` to `w`. See `writeJsonLines`/`writeLogfmt`/
/// `writeCombined` for the exact shape of each.
pub fn write(entry: Entry, format: Format, w: *std.Io.Writer) std.Io.Writer.Error!void {
    switch (format) {
        .json_lines => try writeJsonLines(entry, w),
        .logfmt => try writeLogfmt(entry, w),
        .combined => try writeCombined(entry, w),
    }
}

// ── JSON Lines ───────────────────────────────────────────────────────────

/// One JSON object per line (LF-terminated), fixed key order, every field
/// present (absent optionals as JSON `null`).
///
/// Escaping: every string field goes through `writeJsonString` — RFC 8259
/// `"`/`\`/control-byte escaping (the same rule `std.json` itself expects
/// on the way back in). A crafted value can therefore never close its
/// string early, inject a sibling key, or emit a raw newline: the whole
/// record — no matter what a field contains — stays exactly one line and
/// one JSON object, provably so by round-tripping it through
/// `std.json.parseFromSlice` (see the tests).
pub fn writeJsonLines(entry: Entry, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("{{\"ts\":{d},\"remote_addr\":", .{entry.timestamp_ns});
    try writeJsonOptString(w, entry.remote_addr);
    try w.writeAll(",\"method\":");
    try writeJsonString(w, entry.method);
    try w.writeAll(",\"target\":");
    try writeJsonString(w, entry.target);
    try w.writeAll(",\"protocol\":");
    try writeJsonString(w, entry.protocol);
    try w.print(",\"status\":{d},\"request_bytes\":", .{entry.status});
    try writeJsonOptU64(w, entry.request_bytes);
    try w.writeAll(",\"response_bytes\":");
    try writeJsonOptU64(w, entry.response_bytes);
    try w.writeAll(",\"latency_ns\":");
    try writeJsonOptU64(w, entry.latency_ns);
    try w.writeAll(",\"user_agent\":");
    try writeJsonOptString(w, entry.user_agent);
    try w.writeAll(",\"referer\":");
    try writeJsonOptString(w, entry.referer);
    try w.writeAll(",\"request_id\":");
    try writeJsonOptString(w, entry.request_id);
    try w.writeAll("}\n");
}

/// Write `s` as a double-quoted JSON string (RFC 8259 §7): `"` and `\`
/// backslash-escaped, the named short escapes for `\b\t\n\f\r`, every other
/// control byte as `\u00XX`. Bytes ≥ 0x20 (including any non-ASCII/invalid
/// UTF-8 byte) pass through verbatim — this module deliberately does not
/// validate UTF-8, so a malformed byte can never trigger a decode panic;
/// it only ever affects display, never the string's structural validity.
fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0x08 => try w.writeAll("\\b"),
        0x09 => try w.writeAll("\\t"),
        0x0A => try w.writeAll("\\n"),
        0x0C => try w.writeAll("\\f"),
        0x0D => try w.writeAll("\\r"),
        0x00...0x07, 0x0B, 0x0E...0x1F => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

fn writeJsonOptString(w: *std.Io.Writer, s: ?[]const u8) std.Io.Writer.Error!void {
    if (s) |v| try writeJsonString(w, v) else try w.writeAll("null");
}

fn writeJsonOptU64(w: *std.Io.Writer, v: ?u64) std.Io.Writer.Error!void {
    if (v) |x| try w.print("{d}", .{x}) else try w.writeAll("null");
}

// ── logfmt ───────────────────────────────────────────────────────────────

/// `key=value` pairs, space-separated, LF-terminated. Fixed key order
/// matching `writeJsonLines`; absent optionals **omit** the key entirely
/// (the logfmt convention — there is no `null`).
///
/// Escaping: a value is quoted only when it needs to be — it contains a
/// space, tab, `"`, `=`, backslash, a control byte, or is empty
/// (`logfmtNeedsQuote`). When quoted, `"`/`\` are backslash-escaped, `\n`/
/// `\r`/`\t` get their short escapes, and any other control byte becomes
/// `\xHH`. Because *every* character that would ever need escaping is also
/// exactly the trigger set for quoting, an unquoted value is guaranteed
/// escape-free passthrough (a benign `GET`, a plain path) while anything
/// containing a quote, an `=` (which could otherwise read as a second
/// key=value pair), or a raw newline (which would otherwise forge a
/// second log line) is always wrapped and neutralized.
pub fn writeLogfmt(entry: Entry, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("ts={d}", .{entry.timestamp_ns});
    if (entry.remote_addr) |v| {
        try w.writeAll(" remote_addr=");
        try writeLogfmtValue(w, v);
    }
    try w.writeAll(" method=");
    try writeLogfmtValue(w, entry.method);
    try w.writeAll(" target=");
    try writeLogfmtValue(w, entry.target);
    try w.writeAll(" protocol=");
    try writeLogfmtValue(w, entry.protocol);
    try w.print(" status={d}", .{entry.status});
    if (entry.request_bytes) |v| try w.print(" request_bytes={d}", .{v});
    if (entry.response_bytes) |v| try w.print(" response_bytes={d}", .{v});
    if (entry.latency_ns) |v| try w.print(" latency_ns={d}", .{v});
    if (entry.user_agent) |v| {
        try w.writeAll(" user_agent=");
        try writeLogfmtValue(w, v);
    }
    if (entry.referer) |v| {
        try w.writeAll(" referer=");
        try writeLogfmtValue(w, v);
    }
    if (entry.request_id) |v| {
        try w.writeAll(" request_id=");
        try writeLogfmtValue(w, v);
    }
    try w.writeByte('\n');
}

/// True when `s` must be quoted in a logfmt value: empty, or contains a
/// byte from the trigger set (space/tab/`"`/`=`/backslash/any control
/// byte). Kept in exact lockstep with the escape set in `writeLogfmtValue`
/// — see that function's doc.
fn logfmtNeedsQuote(s: []const u8) bool {
    if (s.len == 0) return true;
    for (s) |c| switch (c) {
        ' ', '"', '=', '\\', 0x00...0x1F, 0x7F => return true,
        else => {},
    };
    return false;
}

fn writeLogfmtValue(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    if (!logfmtNeedsQuote(s)) {
        // No byte in `s` needs escaping (that's exactly what
        // `logfmtNeedsQuote` just proved) — verbatim passthrough.
        return w.writeAll(s);
    }
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F, 0x7F => try w.print("\\x{x:0>2}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

// ── Apache/NGINX Combined Log Format ────────────────────────────────────

/// `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"\n`.
///
/// `%l` (identity) and `%u` (authenticated user) are always `-` — this
/// module tracks neither. `%b` is `-` when `response_bytes` is null, the
/// decimal count otherwise (0 prints as `0`, matching real servers).
/// Referer/User-Agent print the literal `"-"` when absent, matching
/// `mod_log_config`'s own behavior for a missing header on a quoted field.
///
/// Escaping (`ap_escape_logitem` rule, applied to every field — not just
/// the quoted ones, so even `%h`/`%t` can't inject a raw control byte):
/// `"` and `\` are backslash-escaped, every other control byte (0x00–0x1F,
/// 0x7F — this includes `\n`/`\r`) becomes `\xHH`. A quote can therefore
/// never close a quoted field early, and a newline can never start a
/// second line — the record stays exactly one line no matter what the
/// caller's method/target/protocol/referer/user-agent/remote_addr contain.
pub fn writeCombined(entry: Entry, w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (entry.remote_addr) |a| try writeClfEscaped(w, a) else try w.writeByte('-');
    try w.writeAll(" - - [");
    if (entry.time_formatted) |t| try writeClfEscaped(w, t) else try w.print("{d}", .{entry.timestamp_ns});
    try w.writeAll("] \"");
    try writeClfEscaped(w, entry.method);
    try w.writeByte(' ');
    try writeClfEscaped(w, entry.target);
    try w.writeByte(' ');
    try writeClfEscaped(w, entry.protocol);
    try w.print("\" {d} ", .{entry.status});
    if (entry.response_bytes) |b| try w.print("{d}", .{b}) else try w.writeByte('-');
    try w.writeAll(" \"");
    if (entry.referer) |r| try writeClfEscaped(w, r) else try w.writeByte('-');
    try w.writeAll("\" \"");
    if (entry.user_agent) |u| try writeClfEscaped(w, u) else try w.writeByte('-');
    try w.writeAll("\"\n");
}

fn writeClfEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0x00...0x1F, 0x7F => try w.print("\\x{x:0>2}", .{c}),
        else => try w.writeByte(c),
    };
}

// ── http request/response → Entry helper ────────────────────────────────

/// Options for `entryFromRequest` — everything the live `http.Server`
/// types cannot supply themselves (time, latency, correlation id) or that
/// the caller may want to override.
pub const FromRequestOptions = struct {
    /// Caller-supplied timestamp, ns since the Unix epoch — see the
    /// module doc's "Time contract". Required: this module never reads
    /// the clock.
    timestamp_ns: i64,
    /// Preformatted time string for Combined's `[%t]` — see
    /// `Entry.time_formatted`.
    time_formatted: ?[]const u8 = null,
    /// Request→response latency, if the caller timed it.
    latency_ns: ?u64 = null,
    /// Override for the request body byte count. Defaults to the
    /// request's declared `Content-Length` (null when chunked/absent —
    /// this module never drains the body to count it).
    request_bytes: ?u64 = null,
    /// Correlation / request id, e.g. from the `requestid` module.
    request_id: ?[]const u8 = null,
};

/// Build an `Entry` from a served request + its response writer, pulling
/// method/target/protocol/status/User-Agent/Referer/peer address
/// automatically. Zero allocation: `addr_buf` is caller-supplied scratch
/// the peer address is formatted into (the returned `Entry.remote_addr`
/// borrows it) — 64 bytes comfortably covers the longest `IpAddress`
/// textual form (`"[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:65535"`, 47
/// bytes). `addr_buf` must outlive the returned `Entry`.
///
/// `response_bytes` uses the same best-effort contract as
/// `metrics.AccessEntry.bytes`: exact for a buffered or declared-length
/// body, `0` for HEAD/204/304 (`.discard`), `null` for chunked/
/// until-close/compressed streaming responses (no running total is kept).
pub fn entryFromRequest(
    req: *const http.Server.Request,
    res: *const http.Server.ResponseWriter,
    addr_buf: []u8,
    opts: FromRequestOptions,
) Entry {
    var entry: Entry = .{
        .timestamp_ns = opts.timestamp_ns,
        .time_formatted = opts.time_formatted,
        .method = req.method.token(),
        .target = req.target,
        .protocol = if (req.head.http1_0) "HTTP/1.0" else "HTTP/1.1",
        .status = res.status,
        .request_bytes = opts.request_bytes orelse req.head.content_length,
        .response_bytes = responseBytesOf(res),
        .latency_ns = opts.latency_ns,
        .user_agent = req.header("User-Agent"),
        .referer = req.header("Referer"),
        .request_id = opts.request_id,
    };
    if (req.peerAddress()) |p| {
        var w: std.Io.Writer = .fixed(addr_buf);
        w.print("{f}", .{p}) catch {
            // addr_buf too small: leave remote_addr null rather than a
            // truncated/garbage address.
            return entry;
        };
        entry.remote_addr = w.buffered();
    }
    return entry;
}

/// See `entryFromRequest`'s doc for the exact contract.
fn responseBytesOf(res: *const http.Server.ResponseWriter) ?u64 {
    return switch (res.body) {
        .buffering => res.declared_len orelse res.interface.end,
        .identity => res.declared_len.?,
        .discard => 0,
        .chunked, .until_close, .gzip => null,
    };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn sampleEntry() Entry {
    return .{
        .timestamp_ns = 1734000000000000000,
        .time_formatted = "22/Jul/2026:10:00:00 +0000",
        .remote_addr = "192.0.2.1:54321",
        .method = "GET",
        .target = "/status?x=1",
        .protocol = "HTTP/1.1",
        .status = 200,
        .request_bytes = 0,
        .response_bytes = 512,
        .latency_ns = 1500000,
        .user_agent = "curl/8.0",
        .referer = "https://example.org/",
        .request_id = "req-abc-123",
    };
}

test "writeJsonLines: byte-exact golden for a representative entry" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeJsonLines(sampleEntry(), &w);
    try testing.expectEqualStrings(
        "{\"ts\":1734000000000000000,\"remote_addr\":\"192.0.2.1:54321\"," ++
            "\"method\":\"GET\",\"target\":\"/status?x=1\",\"protocol\":\"HTTP/1.1\"," ++
            "\"status\":200,\"request_bytes\":0,\"response_bytes\":512," ++
            "\"latency_ns\":1500000,\"user_agent\":\"curl/8.0\"," ++
            "\"referer\":\"https://example.org/\",\"request_id\":\"req-abc-123\"}\n",
        w.buffered(),
    );
}

test "writeLogfmt: byte-exact golden for a representative entry" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmt(sampleEntry(), &w);
    try testing.expectEqualStrings(
        "ts=1734000000000000000 remote_addr=192.0.2.1:54321 method=GET " ++
            "target=\"/status?x=1\" protocol=HTTP/1.1 status=200 request_bytes=0 " ++
            "response_bytes=512 latency_ns=1500000 user_agent=curl/8.0 " ++
            "referer=https://example.org/ request_id=req-abc-123\n",
        w.buffered(),
    );
}

test "writeCombined: byte-exact golden for a representative entry" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeCombined(sampleEntry(), &w);
    try testing.expectEqualStrings(
        "192.0.2.1:54321 - - [22/Jul/2026:10:00:00 +0000] \"GET /status?x=1 HTTP/1.1\" " ++
            "200 512 \"https://example.org/\" \"curl/8.0\"\n",
        w.buffered(),
    );
}

test "writeCombined: null timestamp fallback prints raw ns inside the brackets" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.time_formatted = null;
    try writeCombined(entry, &w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "[1734000000000000000]") != null);
}

test "combined: response_bytes of exactly 0 prints the digit '0', not the '-' absent-marker" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.response_bytes = 0;
    try writeCombined(entry, &w);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "\" 200 0 \"") != null);
}

test "write: enum dispatch matches the dedicated per-format functions" {
    inline for ([_]Format{ .json_lines, .logfmt, .combined }) |fmt| {
        var direct_buf: [512]u8 = undefined;
        var dispatch_buf: [512]u8 = undefined;
        var direct: std.Io.Writer = .fixed(&direct_buf);
        var dispatch: std.Io.Writer = .fixed(&dispatch_buf);
        switch (fmt) {
            .json_lines => try writeJsonLines(sampleEntry(), &direct),
            .logfmt => try writeLogfmt(sampleEntry(), &direct),
            .combined => try writeCombined(sampleEntry(), &direct),
        }
        try write(sampleEntry(), fmt, &dispatch);
        try testing.expectEqualStrings(direct.buffered(), dispatch.buffered());
    }
}

test "missing optional fields: JSON emits null, logfmt omits the key, combined uses '-'" {
    const entry: Entry = .{
        .timestamp_ns = 1,
        .method = "GET",
        .target = "/",
        .status = 204,
        // remote_addr, request_bytes, response_bytes, latency_ns,
        // user_agent, referer, request_id all left null.
    };

    var jbuf: [512]u8 = undefined;
    var jw: std.Io.Writer = .fixed(&jbuf);
    try writeJsonLines(entry, &jw);
    try testing.expectEqualStrings(
        "{\"ts\":1,\"remote_addr\":null,\"method\":\"GET\",\"target\":\"/\"," ++
            "\"protocol\":\"HTTP/1.1\",\"status\":204,\"request_bytes\":null," ++
            "\"response_bytes\":null,\"latency_ns\":null,\"user_agent\":null," ++
            "\"referer\":null,\"request_id\":null}\n",
        jw.buffered(),
    );

    var lbuf: [256]u8 = undefined;
    var lw: std.Io.Writer = .fixed(&lbuf);
    try writeLogfmt(entry, &lw);
    try testing.expectEqualStrings("ts=1 method=GET target=/ protocol=HTTP/1.1 status=204\n", lw.buffered());

    var cbuf: [256]u8 = undefined;
    var cw: std.Io.Writer = .fixed(&cbuf);
    try writeCombined(entry, &cw);
    try testing.expectEqualStrings("- - - [1] \"GET / HTTP/1.1\" 204 - \"-\" \"-\"\n", cw.buffered());
}

// ── log-injection teeth ──────────────────────────────────────────────────
//
// One shared adversarial payload exercised as method/target/user_agent/
// referer across every format: a quote (breakout attempt), CR+LF (line-
// forge attempt), braces (JSON-structure-confusion attempt), a fake
// `logfmt` key=value pair, and a spread of control bytes including DEL.

const evil_payload = "evil\"\r\n{fake}=1 status=200\x01\x1f\x7f";

test "JSON: injection payload stays one record, round-trips byte-exact through std.json" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.user_agent = evil_payload;
    entry.target = evil_payload;
    entry.method = evil_payload;
    try writeJsonLines(entry, &w);
    const out = w.buffered();

    // Exactly one newline: the record terminator. No forged second line.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    // No raw control byte reached the wire. (0x7F/DEL is not a JSON
    // "control character" per RFC 8259 §7 — 0x00-0x1F only — so it is
    // legitimately allowed to pass through unescaped; it cannot break the
    // string or the line either way.)
    for ([_]u8{ 0x00, 0x01, 0x0D, 0x1F }) |b| {
        try testing.expect(std.mem.indexOfScalar(u8, out, b) == null);
    }

    // Structural validity + exact field round-trip via std.json.
    const without_nl = out[0 .. out.len - 1];
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, without_nl, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqualStrings(evil_payload, obj.get("user_agent").?.string);
    try testing.expectEqualStrings(evil_payload, obj.get("target").?.string);
    try testing.expectEqualStrings(evil_payload, obj.get("method").?.string);
}

test "JSON: benign field passes through unchanged (positive control)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.user_agent = "Mozilla/5.0 (X11; Linux x86_64)";
    try writeJsonLines(entry, &w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\"user_agent\":\"Mozilla/5.0 (X11; Linux x86_64)\"") != null);
}

test "logfmt: injection payload is quoted+escaped, one record, no fake pair, no raw control bytes" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.user_agent = evil_payload;
    entry.referer = evil_payload;
    try writeLogfmt(entry, &w);
    const out = w.buffered();

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    try testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
    for ([_]u8{ 0x01, 0x1F, 0x7F }) |b| {
        try testing.expect(std.mem.indexOfScalar(u8, out, b) == null);
    }
    // The embedded quote is backslash-escaped (`\"`, not a bare `"`), so it
    // can never close the quoted value early and let `{fake}=1` or
    // `status=200` read as a sibling top-level key=value pair.
    try testing.expect(std.mem.indexOf(u8, out, "user_agent=\"evil\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "referer=\"evil\\\"") != null);
}

test "logfmt: benign field is unquoted verbatim (positive control)" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.user_agent = "curl/8.0";
    try writeLogfmt(entry, &w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), " user_agent=curl/8.0 ") != null);
}

test "logfmt: a value containing only '=' is quoted (no ambiguous bare key=value split)" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmtValue(&w, "a=b");
    try testing.expectEqualStrings("\"a=b\"", w.buffered());
}

test "logfmt: an empty value is quoted (an unquoted empty value would vanish, misreading as an absent key)" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmtValue(&w, "");
    try testing.expectEqualStrings("\"\"", w.buffered());
}

test "logfmt: control bytes escape to their own exact \\xHH value, not just 'something'" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmtValue(&w, "\x01\x1f\x7f");
    try testing.expectEqualStrings("\"\\x01\\x1f\\x7f\"", w.buffered());
}

test "combined: injection payload cannot forge a second line or break the quoted fields" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    // A payload aiming to close the quoted user-agent field, inject a
    // newline, and prepend what looks like a whole forged combined line.
    const forge = "Mozilla\" \r\n127.0.0.1 - - [x] \"GET / HTTP/1.1\" 200 1 \"-\" \"-";
    entry.user_agent = forge;
    entry.referer = forge;
    entry.method = evil_payload;
    entry.target = evil_payload;
    try writeCombined(entry, &w);
    const out = w.buffered();

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    try testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
    for ([_]u8{ 0x01, 0x1F, 0x7F }) |b| {
        try testing.expect(std.mem.indexOfScalar(u8, out, b) == null);
    }
    // The line still ends with the real closing `"\n` for user-agent, i.e.
    // it is still exactly the shape %h ... "referer" "user-agent"\n — the
    // embedded quote+newline never closed the field early.
    try testing.expect(std.mem.endsWith(u8, out, "\"\n"));
}

test "combined: benign fields render verbatim (positive control)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeCombined(sampleEntry(), &w);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "\"https://example.org/\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"curl/8.0\"") != null);
    try testing.expect(std.mem.startsWith(u8, out, "192.0.2.1:54321 - - ["));
}

// ── entryFromRequest ─────────────────────────────────────────────────────

fn testRequest(head_block: []const u8, target: []const u8, http1_0: bool, body: *http.Server.RequestBody, peer: ?std.Io.net.IpAddress) http.Server.Request {
    return .{
        .method = .get,
        .target = target,
        .path = target,
        .query = "",
        .head = .{
            .method = "GET",
            .target = target,
            .http1_0 = http1_0,
            .header_block = head_block,
            .content_length = 42,
            .has_content_length = true,
        },
        .body = body,
        .context = null,
        .peer = peer,
    };
}

test "entryFromRequest: pulls method/target/protocol/status/UA/referer/peer/content-length" {
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const peer = try std.Io.net.IpAddress.parse("192.0.2.9", 5555);
    const req = testRequest(
        "User-Agent: curl/8.0\r\nReferer: https://example.org/\r\n",
        "/status?x=1",
        false,
        &body,
        peer,
    );

    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [256]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(201);
    try res.writeAll("hi");

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{
        .timestamp_ns = 99,
        .latency_ns = 12345,
        .request_id = "corr-1",
    });

    try testing.expectEqualStrings("GET", entry.method);
    try testing.expectEqualStrings("/status?x=1", entry.target);
    try testing.expectEqualStrings("HTTP/1.1", entry.protocol);
    try testing.expectEqual(@as(u16, 201), entry.status);
    try testing.expectEqualStrings("curl/8.0", entry.user_agent.?);
    try testing.expectEqualStrings("https://example.org/", entry.referer.?);
    try testing.expectEqualStrings("192.0.2.9:5555", entry.remote_addr.?);
    try testing.expectEqual(@as(?u64, 42), entry.request_bytes);
    try testing.expectEqual(@as(u64, 2), entry.response_bytes.?);
    try testing.expectEqual(@as(i64, 99), entry.timestamp_ns);
    try testing.expectEqual(@as(?u64, 12345), entry.latency_ns);
    try testing.expectEqualStrings("corr-1", entry.request_id.?);
}

test "entryFromRequest: HTTP/1.0 protocol, no peer, no UA/referer, request_bytes override" {
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const req = testRequest("", "/", true, &body, null);

    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(404);

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{
        .timestamp_ns = 1,
        .request_bytes = 7,
    });

    try testing.expectEqualStrings("HTTP/1.0", entry.protocol);
    try testing.expectEqual(@as(?[]const u8, null), entry.remote_addr);
    try testing.expectEqual(@as(?[]const u8, null), entry.user_agent);
    try testing.expectEqual(@as(?[]const u8, null), entry.referer);
    try testing.expectEqual(@as(?u64, 7), entry.request_bytes); // override wins over content_length
}

test "entryFromRequest: addr_buf too small to hold the peer address leaves remote_addr null" {
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const peer = try std.Io.net.IpAddress.parse("192.0.2.9", 5555);
    const req = testRequest("", "/", false, &body, peer);

    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(200);

    // "192.0.2.9:5555" is 14 bytes; 1 byte is nowhere near enough, forcing
    // the write-failure path instead of the happy path.
    var addr_buf: [1]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{ .timestamp_ns = 1 });

    try testing.expectEqual(@as(?[]const u8, null), entry.remote_addr);
}

test "entryFromRequest output feeds straight into writeCombined without extra glue" {
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const peer = try std.Io.net.IpAddress.parse("203.0.113.5", 443);
    const req = testRequest("User-Agent: probe\r\n", "/health", false, &body, peer);

    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(200);

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{ .timestamp_ns = 5 });

    var line_buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&line_buf);
    try writeCombined(entry, &w);
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "203.0.113.5:443 - - "));
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\"GET /health HTTP/1.1\" 200") != null);
}

test "entryFromRequest: 204 response streamed through .discard maps response_bytes to 0, not null" {
    // `responseBytesOf` has a 5-way switch over `res.body`; every other
    // test in this file only ever exercises the `.buffering` arm (the
    // default until the body is actually streamed). Force a `.discard`
    // body (HEAD/204/304, per `noBody()`) by flushing before `end()`, and
    // confirm the mapping is the documented `0` — not `null` (that would
    // read as "unknown", which is wrong: a discarded body's length is
    // exactly known to be zero) and not some other constant.
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const req = testRequest("", "/", false, &body, null);

    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(204);
    try res.writeAll("ignored-per-noBody");
    try res.flush();

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{ .timestamp_ns = 1 });
    try testing.expectEqual(@as(?u64, 0), entry.response_bytes);
}

test "entryFromRequest: identity-framed response maps response_bytes to the declared Content-Length" {
    // The `.identity` arm reads `res.declared_len.?` — the original
    // declared total, not the shrinking remaining-bytes counter in
    // `res.body.identity`. Confirm it reports the full declared length
    // after the whole body has been written (remaining counter at 0).
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const req = testRequest("", "/", false, &body, null);

    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(200);
    try res.setHeader("Content-Length", "2");
    try res.writeAll("hi");
    try res.flush();

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{ .timestamp_ns = 1 });
    try testing.expectEqual(@as(?u64, 2), entry.response_bytes);
}

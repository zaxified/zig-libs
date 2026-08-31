// SPDX-License-Identifier: MIT

//! h1 — pure HTTP/1.1 wire framing. No sockets, no allocation: everything
//! operates on `std.Io.Reader`/`std.Io.Writer` interfaces and caller buffers,
//! so it is fully testable offline and shared by the client and the server.
//!
//! Contents: message-head reader, response-head parser (`ResponseHead`,
//! client side), request-head parser (`RequestHead`, server side), chunked
//! transfer-coding decoder (`ChunkedReader`) and encoder (`ChunkedWriter`),
//! and a Content-Length bounded body reader that detects truncation
//! (`ContentLengthReader`).

const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;

// ── head reading ────────────────────────────────────────────────────────────

pub const ReadHeadError = error{
    /// Transport failed mid-head; see the underlying reader for diagnostics.
    ReadFailed,
    /// Peer closed the connection before completing the head.
    ConnectionClosed,
    /// The head (or a single line of it) exceeds the provided buffer.
    HeadTooLarge,
};

/// One line as `takeLineInto` produced it.
const Line = struct {
    /// The line with its original `\r\n`, as far as it fit the destination.
    bytes: []u8,
    /// The line was longer than the destination; the excess was consumed off
    /// the wire and dropped, so the reader is still positioned on the next
    /// line either way.
    overflow: bool,
    /// The line is the empty one — nothing but its terminator. Reported
    /// separately from `bytes` because a caller may pass no destination at
    /// all and still need to recognise the end of a header section.
    blank: bool,
};

/// Read one `\n`-terminated line into `dest`, scanning what has arrived and
/// consuming it as it goes.
///
/// ⭐ The contiguity this asks of `r` is **one byte**, not one line. That is
/// the whole difference from `Reader.takeDelimiterInclusive`, which needs the
/// line whole in the reader's buffer and reports `StreamTooLong` when it
/// cannot have it. A reader whose buffer is a frame or a record — one that
/// hands out whatever arrived and cannot join two of them — therefore serves
/// this, and the line length stops being bounded by the reader's buffer and
/// starts being bounded by `dest`, which is the caller's to size.
///
/// The copy is not new work: every caller here was already copying the line
/// out of the reader's buffer into a buffer of its own.
fn takeLineInto(r: *Reader, dest: []u8) error{ ReadFailed, EndOfStream }!Line {
    var len: usize = 0;
    var overflow = false;
    var blank = true;
    while (true) {
        const avail = r.peekGreedy(1) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => return error.EndOfStream,
        };
        const nl = std.mem.indexOfScalar(u8, avail, '\n');
        const take = if (nl) |i| i + 1 else avail.len;
        // Only worth scanning while it could still be blank, which is only
        // ever the terminator line and the first byte settles it.
        if (blank) for (avail[0..take]) |b| {
            if (b != '\r' and b != '\n') {
                blank = false;
                break;
            }
        };
        const n = @min(take, dest.len - len);
        @memcpy(dest[len..][0..n], avail[0..n]);
        len += n;
        if (n < take) overflow = true;
        r.toss(take);
        if (nl != null) return .{ .bytes = dest[0..len], .overflow = overflow, .blank = blank };
    }
}

/// Read one HTTP/1.x message head (status/request line + header lines) off
/// `r` into `buf`, consuming the terminating blank line. Returns the raw head
/// block — lines with their original `\r\n` endings, blank terminator
/// excluded.
///
/// A line is bounded by `buf` and by nothing else: this reads incrementally,
/// so `r` is never asked for more contiguous bytes than it has. That is what
/// lets a server run h1 over a reader that hands out one TLS record or one
/// frame at a time.
pub fn readHead(r: *Reader, buf: []u8) ReadHeadError![]const u8 {
    var len: usize = 0;
    while (true) {
        const line = takeLineInto(r, buf[len..]) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => return error.ConnectionClosed,
        };
        // Before `overflow`, not after: the terminator is two bytes that are
        // never kept, so a head whose lines fill `buf` exactly still ends
        // successfully -- which is what the previous implementation did, and
        // the difference would otherwise be an off-by-two in the head limit.
        if (line.blank) return buf[0..len];
        if (line.overflow) return error.HeadTooLarge;
        len += line.bytes.len;
    }
}

fn trimLineEnd(line: []const u8) []const u8 {
    return std.mem.trimEnd(u8, line, "\r\n");
}

// ── header fields (shared by request + response heads) ─────────────────────

pub const HeadParseError = error{
    /// Not a syntactically valid HTTP/1.x message head.
    MalformedHead,
    /// An HTTP version this module does not speak (e.g. HTTP/2 on the wire).
    UnsupportedVersion,
};

pub const HeaderEntry = struct { name: []const u8, value: []const u8 };

/// Strict line unwrap for a CRLF-framed head: `raw` is one segment of the
/// block split on `\n`, and must carry the preceding `\r`. RFC 9112 §2.2
/// permits (does not require) a recipient to recognize a bare LF as a line
/// terminator ("a recipient MAY recognize a single LF as a line terminator
/// and ignore any preceding CR") — this module deliberately does NOT take
/// that leniency: accepting a bare LF opens a request-smuggling desync where
/// a front-end and back-end disagree on message framing (confirmed
/// divergent from `h11`, an independent HTTP/1.1 state machine that DOES
/// exercise the RFC's leniency — see `h11_interop.zig`). Returns the line
/// with its trailing CR removed, or `error.MalformedHead` if the CR is
/// missing (a bare-LF terminator). Callers must skip the trailing empty
/// split (the segment after the final CRLF) before calling this.
fn stripCrlf(raw: []const u8) HeadParseError![]const u8 {
    if (raw.len == 0 or raw[raw.len - 1] != '\r') return error.MalformedHead;
    return raw[0 .. raw.len - 1];
}

// Byte-class tables for the head parser's hot loops: a 256-entry table
// turns each RFC character-class test into one load and one branch. The
// switch-form predicate (`isTchar`) stays the readable definition and the
// table is derived from it at comptime, so the two cannot drift.
const tchar_table: [256]bool = blk: {
    var t: [256]bool = @splat(false);
    for (0..256) |c| t[c] = isTchar(c);
    break :blk t;
};
// field-value = *(field-vchar / SP / HTAB), field-vchar = VCHAR / obs-text
// (RFC 9110 §5.5): a control byte -- NUL, a bare CR, anything below 0x20
// but HTAB, or DEL -- cannot appear in a value, and is the classic vehicle
// for header injection. Bytes >= 0x80 are obs-text and stay legal.
const value_char_table: [256]bool = blk: {
    var t: [256]bool = @splat(false);
    for (0..256) |c| t[c] = !((c < 0x20 and c != '\t') or c == 0x7f);
    break :blk t;
};

/// Strict header-line split (no obs-fold, no whitespace around the name);
/// the value is trimmed of optional whitespace. `line` must be non-empty and
/// already stripped of its line ending.
fn parseHeaderLine(line: []const u8) HeadParseError!HeaderEntry {
    // field-name = token (RFC 9110 §5.1): a name that is not a token is not
    // a header, and a server that stores it under whatever bytes it got has
    // let "Bad[Name", "Transfer\x00Encoding" and every non-ASCII spelling
    // through as headers nobody will ever match. One table-driven pass both
    // finds the colon and validates the name: the scan stops at the first
    // non-tchar, which must BE the colon — and that subsumes the old
    // explicit checks (obs-fold: ' '/'\t' is not a tchar, so a folded line
    // stops at 0; empty name: ':' first stops at 0 too).
    var i: usize = 0;
    while (i < line.len and tchar_table[line[i]]) i += 1;
    if (i == 0 or i >= line.len or line[i] != ':') return error.MalformedHead;
    const name = line[0..i];
    const value = std.mem.trim(u8, line[i + 1 ..], " \t");
    for (value) |c| if (!value_char_table[c]) return error.MalformedHead;
    return .{ .name = name, .value = value };
}

/// `Host = uri-host [ ":" port ]` (RFC 9112 §3.2): the characters a reg-name,
/// an IP-literal or a port can be made of, and nothing else. What it turns
/// away: an empty value on an origin-form request, a path ("h/x"), userinfo
/// ("u@h"), a second host after a comma, whitespace. Each of those is either
/// a smuggling vector against a front proxy that reads Host differently, or
/// a request no client sends. A server MUST answer such a request 400
/// (§3.2, last paragraph).
pub fn isValidHost(v: []const u8) bool {
    if (v.len == 0) return false;
    for (v) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => {},
        '-', '.', '_', '~', '%', ':', '[', ']', '!', '$', '&', '\'', '(', ')', '*', '+', ';', '=' => {},
        else => return false,
    };
    return true;
}

/// Lenient wire-order iterator over a raw header block (lines that fail to
/// split are skipped — parse validated them already).
pub const HeaderIterator = struct {
    lines: std.mem.SplitIterator(u8, .scalar),

    pub fn next(it: *HeaderIterator) ?HeaderEntry {
        while (it.lines.next()) |raw| {
            const line = trimLineEnd(raw);
            if (line.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            return .{
                .name = line[0..colon],
                .value = std.mem.trim(u8, line[colon + 1 ..], " \t"),
            };
        }
        return null;
    }
};

fn iterateHeaderBlock(block: []const u8) HeaderIterator {
    return .{ .lines = std.mem.splitScalar(u8, block, '\n') };
}

fn findHeader(block: []const u8, name: []const u8) ?[]const u8 {
    // The block was already validated by parse (names are tokens, so no
    // name contains ':'), which licenses a cheap shape probe per line: the
    // header can match only if the byte AT `name.len` is the colon. Almost
    // every non-matching line fails that one-byte test, so the per-line
    // cost of a lookup is a split and a load -- the full case-insensitive
    // compare and the value trim run only on a length-matching candidate.
    // (A shorter real name puts its ':' or the SP after it inside the
    // compared window, where `name` -- a token -- can never match it.)
    var lines = std.mem.splitScalar(u8, block, '\n');
    while (lines.next()) |raw| {
        if (raw.len <= name.len or raw[name.len] != ':') continue;
        if (!std.ascii.eqlIgnoreCase(raw[0..name.len], name)) continue;
        return std.mem.trim(u8, trimLineEnd(raw)[name.len + 1 ..], " \t");
    }
    return null;
}

/// First value of field `name` (case-insensitive) in a raw CRLF header/
/// trailer block, or null — for callers holding a block directly (e.g. a
/// request's captured chunked trailers).
pub fn blockHeader(block: []const u8, name: []const u8) ?[]const u8 {
    return findHeader(block, name);
}

/// Iterate a raw CRLF header/trailer block's fields in wire order.
pub fn blockIterator(block: []const u8) HeaderIterator {
    return iterateHeaderBlock(block);
}

/// Strictly parse a Content-Length value per RFC 9110 §8.6 grammar
/// (`Content-Length = 1*DIGIT`, ASCII `0`-`9` only). `std.fmt.parseInt`
/// is deliberately not used here: it accepts a leading `+` sign, `_`
/// digit-group separators, and `-0`, none of which are valid DIGIT
/// sequences — e.g. `+5`, `1_0`, `-0` would silently parse to `5`, `10`,
/// `0`. A fronting CDN/LB that forwards those raw bytes and disagrees
/// with our lenient parse is a request-smuggling desync risk, so any
/// non-digit byte (or an empty value) is rejected.
fn parseContentLengthStrict(value: []const u8) HeadParseError!u64 {
    if (value.len == 0) return error.MalformedHead;
    var n: u64 = 0;
    for (value) |c| {
        if (c < '0' or c > '9') return error.MalformedHead;
        n = std.math.mul(u64, n, 10) catch return error.MalformedHead;
        n = std.math.add(u64, n, c - '0') catch return error.MalformedHead;
    }
    return n;
}

/// Latch a Content-Length value; duplicates must agree (RFC 7230 §3.3.2).
fn latchContentLength(current: *?u64, value: []const u8) HeadParseError!void {
    const n = try parseContentLengthStrict(value);
    if (current.*) |prev| {
        if (prev != n) return error.MalformedHead; // conflicting lengths
    } else current.* = n;
}

// ── response head parsing ───────────────────────────────────────────────────

/// A parsed response head. All slices point into the head block passed to
/// `parse` — keep that buffer alive as long as the head is used.
pub const ResponseHead = struct {
    status: u16,
    reason: []const u8,
    /// True for `HTTP/1.0` (implies connection close unless keep-alive).
    http1_0: bool,
    /// Raw header lines (status line excluded), for `header`/`iterate`.
    header_block: []const u8,
    /// Parsed `Content-Length`, null if absent or overridden by chunked.
    content_length: ?u64 = null,
    /// `Transfer-Encoding` includes `chunked`.
    chunked: bool = false,
    /// `Connection: close` was sent.
    connection_close: bool = false,
    /// `Connection: keep-alive` was sent. Only relevant for an `HTTP/1.0`
    /// response (`http1_0`) — 1.0 defaults to closing unless the server
    /// opts into persistence; an `HTTP/1.1` response is persistent by
    /// default regardless of this flag (`connection_close` is what matters
    /// there).
    connection_keep_alive: bool = false,

    /// Parse a raw head block as produced by `readHead` (lenient about bare
    /// `\n` line endings; strict about header syntax — no obs-fold, no
    /// whitespace before the colon, no conflicting Content-Length).
    pub fn parse(block: []const u8) HeadParseError!ResponseHead {
        var lines = std.mem.splitScalar(u8, block, '\n');
        const status_line = trimLineEnd(lines.next() orelse return error.MalformedHead);

        // "HTTP/1.x <3-digit> [reason]"
        if (status_line.len < 12) return error.MalformedHead;
        if (!std.mem.startsWith(u8, status_line, "HTTP/")) return error.MalformedHead;
        if (status_line[5] != '1' or status_line[6] != '.') return error.UnsupportedVersion;
        const minor = status_line[7];
        if (minor != '0' and minor != '1') return error.UnsupportedVersion;
        if (status_line[8] != ' ') return error.MalformedHead;
        var status: u16 = 0;
        for (status_line[9..12]) |c| {
            if (c < '0' or c > '9') return error.MalformedHead;
            status = status * 10 + (c - '0');
        }
        var reason: []const u8 = "";
        if (status_line.len > 12) {
            if (status_line[12] != ' ') return error.MalformedHead;
            reason = status_line[13..];
        }

        var head: ResponseHead = .{
            .status = status,
            .reason = reason,
            .http1_0 = minor == '0',
            .header_block = block[@min(block.len, lines.index orelse block.len)..],
        };

        while (lines.next()) |raw| {
            const line = trimLineEnd(raw);
            if (line.len == 0) continue; // tolerate a trailing empty split
            const entry = try parseHeaderLine(line);

            if (std.ascii.eqlIgnoreCase(entry.name, "content-length")) {
                try latchContentLength(&head.content_length, entry.value);
            } else if (std.ascii.eqlIgnoreCase(entry.name, "transfer-encoding")) {
                if (tokenListContains(entry.value, "chunked")) head.chunked = true;
            } else if (std.ascii.eqlIgnoreCase(entry.name, "connection")) {
                if (tokenListContains(entry.value, "close")) head.connection_close = true;
                if (tokenListContains(entry.value, "keep-alive")) head.connection_keep_alive = true;
            }
        }

        // Chunked wins over Content-Length (RFC 7230 §3.3.3).
        if (head.chunked) head.content_length = null;
        return head;
    }

    /// First value of header `name` (case-insensitive), or null.
    pub fn header(h: *const ResponseHead, name: []const u8) ?[]const u8 {
        return findHeader(h.header_block, name);
    }

    pub const Iterator = HeaderIterator;

    /// Iterate all header name/value pairs in wire order.
    pub fn iterate(h: *const ResponseHead) HeaderIterator {
        return iterateHeaderBlock(h.header_block);
    }
};

/// True when the comma-separated `list` contains `token` (case-insensitive,
/// optional whitespace) — e.g. `Connection: keep-alive, close`.
pub fn tokenListContains(list: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |t| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, t, " \t"), token)) return true;
    }
    return false;
}

// ── request head parsing ────────────────────────────────────────────────────

/// A parsed request head (server side). All slices point into the head block
/// passed to `parse` — keep that buffer alive as long as the head is used.
/// Purely syntactic: semantic rejections (missing Host on 1.1, unsupported
/// Transfer-Encoding, unknown method) are the server's call.
pub const RequestHead = struct {
    /// The method token as sent, e.g. "GET" (validated: non-empty, tchars).
    method: []const u8,
    /// The raw request-target, e.g. "/path?q=1" (validated: non-empty, no
    /// whitespace/control bytes; form not interpreted here).
    target: []const u8,
    /// True for `HTTP/1.0` (no persistent connection unless keep-alive).
    http1_0: bool,
    /// Raw header lines (request line excluded), for `header`/`iterate`.
    header_block: []const u8,
    /// The `Host` header value; null if absent (required by HTTP/1.1).
    host: ?[]const u8 = null,
    /// Parsed `Content-Length`, null if absent or overridden by chunked.
    content_length: ?u64 = null,
    /// A `Content-Length` header was present at all (kept even when
    /// `chunked` nulls `content_length`, so the server can reject a message
    /// carrying both framings — the classic CL.TE smuggling vector).
    has_content_length: bool = false,
    /// `Transfer-Encoding` includes `chunked`.
    chunked: bool = false,
    /// A `Transfer-Encoding` header is present at all. When set without
    /// `chunked` the body cannot be framed — reject the request.
    has_transfer_encoding: bool = false,
    /// `Connection: close` was sent.
    connection_close: bool = false,
    /// `Connection: keep-alive` was sent (HTTP/1.0 opt-in).
    connection_keep_alive: bool = false,
    /// `Expect: 100-continue` was sent.
    expect_continue: bool = false,

    /// Parse a raw head block as produced by `readHead`. Strict about line
    /// endings: every line MUST be CRLF-terminated — a bare LF is rejected as
    /// `error.MalformedHead` (RFC 9112 §2.2, request-smuggling hardening; see
    /// `stripCrlf`). Strict about syntax too — same header rules as
    /// `ResponseHead.parse`, plus: single Host only, method must be a token.
    pub fn parse(block: []const u8) HeadParseError!RequestHead {
        var lines = std.mem.splitScalar(u8, block, '\n');
        const request_line = try stripCrlf(lines.next() orelse return error.MalformedHead);

        // "METHOD SP request-target SP HTTP/1.x"
        const sp1 = std.mem.indexOfScalar(u8, request_line, ' ') orelse return error.MalformedHead;
        const sp2 = std.mem.lastIndexOfScalar(u8, request_line, ' ').?;
        if (sp2 <= sp1) return error.MalformedHead; // fewer than two spaces
        const method = request_line[0..sp1];
        const target = request_line[sp1 + 1 .. sp2];
        const version = request_line[sp2 + 1 ..];

        if (method.len == 0) return error.MalformedHead;
        for (method) |c| if (!isTchar(c)) return error.MalformedHead;
        if (target.len == 0) return error.MalformedHead;
        // A request-target is a URI reference, and a URI is ASCII (RFC 3986
        // §2): a raw byte >= 0x80 in it is a client that did not
        // percent-encode, and routing on it would route on the bytes of
        // whichever encoding it happened to use.
        for (target) |c| if (c <= ' ' or c >= 0x7f) return error.MalformedHead;
        if (version.len != 8 or !std.mem.startsWith(u8, version, "HTTP/"))
            return error.MalformedHead;
        if (version[5] != '1' or version[6] != '.') return error.UnsupportedVersion;
        const minor = version[7];
        if (minor != '0' and minor != '1') return error.UnsupportedVersion;

        var head: RequestHead = .{
            .method = method,
            .target = target,
            .http1_0 = minor == '0',
            .header_block = block[@min(block.len, lines.index orelse block.len)..],
        };

        while (lines.next()) |raw| {
            if (raw.len == 0) continue; // trailing empty split after the final CRLF
            const line = try stripCrlf(raw); // bare-LF terminator → MalformedHead
            if (line.len == 0) continue; // tolerate a stray blank CRLF line
            const entry = try parseHeaderLine(line);

            // Length first: every framing-relevant name has a distinct
            // length, so the typical uninteresting header pays one integer
            // compare here instead of five case-insensitive scans.
            switch (entry.name.len) {
                "content-length".len => if (std.ascii.eqlIgnoreCase(entry.name, "content-length")) {
                    head.has_content_length = true;
                    try latchContentLength(&head.content_length, entry.value);
                },
                "transfer-encoding".len => if (std.ascii.eqlIgnoreCase(entry.name, "transfer-encoding")) {
                    head.has_transfer_encoding = true;
                    // RFC 9112 §6.1: when `chunked` is present it MUST be the
                    // final transfer-coding; this server supports no other
                    // coding, so the only accepted value is the single token
                    // "chunked". Merely *containing* chunked (e.g.
                    // "chunked, gzip", or the "chunked, chunked" double-chunk
                    // vector) is a TE.TE request-smuggling primitive — leaving
                    // `chunked` false here routes it through the
                    // `has_transfer_encoding and !chunked` → 400 gate below.
                    if (std.ascii.eqlIgnoreCase(entry.value, "chunked")) head.chunked = true;
                },
                "connection".len => if (std.ascii.eqlIgnoreCase(entry.name, "connection")) {
                    if (tokenListContains(entry.value, "close")) head.connection_close = true;
                    if (tokenListContains(entry.value, "keep-alive")) head.connection_keep_alive = true;
                },
                "host".len => if (std.ascii.eqlIgnoreCase(entry.name, "host")) {
                    if (head.host != null) return error.MalformedHead; // request smuggling
                    if (!isValidHost(entry.value)) return error.MalformedHead;
                    head.host = entry.value;
                },
                "expect".len => if (std.ascii.eqlIgnoreCase(entry.name, "expect")) {
                    if (std.ascii.eqlIgnoreCase(entry.value, "100-continue")) head.expect_continue = true;
                },
                else => {},
            }
        }

        // Chunked wins over Content-Length (RFC 7230 §3.3.3).
        if (head.chunked) head.content_length = null;
        return head;
    }

    /// First value of header `name` (case-insensitive), or null.
    pub fn header(h: *const RequestHead, name: []const u8) ?[]const u8 {
        return findHeader(h.header_block, name);
    }

    /// Iterate all header name/value pairs in wire order.
    pub fn iterate(h: *const RequestHead) HeaderIterator {
        return iterateHeaderBlock(h.header_block);
    }
};

/// RFC 7230 token characters (method names, header names).
pub fn isTchar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

// ── chunked transfer-coding decoder ─────────────────────────────────────────

/// Streaming decoder for `Transfer-Encoding: chunked` response bodies,
/// exposed as a `std.Io.Reader` (`.reader`). On protocol violation or a
/// truncated stream it returns `error.ReadFailed` and records the cause in
/// `fail_reason`.
///
/// Trailer fields (RFC 7230 §4.1.2) are consumed and — by default —
/// discarded. Construct with `initCapturingTrailers` to instead capture the
/// trailer section into a caller buffer, readable via `trailers` / `trailer`
/// / `iterateTrailers` once the reader has reached end-of-stream (the whole
/// body has been consumed). A trailer section larger than the buffer is
/// truncated (the overflow is still drained off the wire), flagged by
/// `trailers_overflow`.
///
/// Not movable after `reader` has been handed out (the interface points back
/// into this struct).
pub const ChunkedReader = struct {
    in: *Reader,
    reader: Reader,
    state: State,
    fail_reason: ?FailReason = null,
    /// Optional trailer-capture buffer; empty (the default) discards
    /// trailers as before. Holds trailer lines as a raw header block
    /// (CRLF-terminated, `HeaderIterator`-parseable).
    trailer_buf: []u8 = &.{},
    trailer_len: usize = 0,
    /// The trailer section did not fit `trailer_buf`; excess lines were
    /// dropped (still consumed off the wire).
    trailers_overflow: bool = false,
    /// Scratch for the chunk-header line, which is the only line this decoder
    /// has to read the bytes of. Sized past the longest one that can be
    /// meaningful: a chunk size is at most 16 hex digits, so everything the
    /// parse depends on is in the first 17 bytes.
    line_buf: [32]u8 = undefined,

    pub const FailReason = enum { malformed_chunk, truncated_body };

    const State = union(enum) {
        chunk_header,
        body: u64,
        body_crlf,
        trailers,
        done,
    };

    pub fn init(in: *Reader, buffer: []u8) ChunkedReader {
        return .{
            .in = in,
            .state = .chunk_header,
            .reader = .{
                .vtable = &.{ .stream = streamFn },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    /// Like `init`, but capture the incoming trailer section into
    /// `trailer_buf` instead of discarding it (see the type doc). Pass an
    /// empty `trailer_buf` to disable capture (equivalent to `init`).
    pub fn initCapturingTrailers(in: *Reader, buffer: []u8, trailer_buf: []u8) ChunkedReader {
        var cr = init(in, buffer);
        cr.trailer_buf = trailer_buf;
        return cr;
    }

    /// The captured trailer section as a raw header block (empty unless
    /// constructed with `initCapturingTrailers` and the body was fully
    /// read). Parse with `iterateTrailers`/`trailer`.
    pub fn trailers(c: *const ChunkedReader) []const u8 {
        return c.trailer_buf[0..c.trailer_len];
    }

    /// First captured trailer field `name` (case-insensitive), or null.
    pub fn trailer(c: *const ChunkedReader, name: []const u8) ?[]const u8 {
        return findHeader(c.trailers(), name);
    }

    /// Iterate the captured trailer fields in wire order.
    pub fn iterateTrailers(c: *const ChunkedReader) HeaderIterator {
        return iterateHeaderBlock(c.trailers());
    }

    fn streamFn(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        const c: *ChunkedReader = @alignCast(@fieldParentPtr("reader", r));
        while (true) {
            switch (c.state) {
                .done => return error.EndOfStream,
                .chunk_header => {
                    // ⭐ Truncation at `line_buf` cannot change the verdict.
                    // A chunk size is at most 16 hex digits, so a ';' that
                    // ends a valid size sits at index 16 or less -- well
                    // inside the buffer. A line long enough to be cut here
                    // therefore either carries its ';' in the kept prefix,
                    // and parses to the same size, or carries none, and is
                    // rejected for a size text over 16 digits. Both are what
                    // the whole line would have produced.
                    const line = trimLineEnd((try c.takeLineRaw(&c.line_buf)).bytes);
                    // "<hex-size>[;extensions]"
                    const size_text = if (std.mem.indexOfScalar(u8, line, ';')) |i| line[0..i] else line;
                    if (size_text.len == 0 or size_text.len > 16) return c.fail(.malformed_chunk);
                    var size: u64 = 0;
                    for (size_text) |ch| {
                        const d = std.fmt.charToDigit(ch, 16) catch return c.fail(.malformed_chunk);
                        size = (size << 4) | d;
                    }
                    c.state = if (size == 0) .trailers else .{ .body = size };
                },
                .body => |remaining| {
                    const n = c.in.stream(w, limit.min(.limited64(remaining))) catch |err| switch (err) {
                        error.EndOfStream => return c.fail(.truncated_body),
                        error.ReadFailed, error.WriteFailed => |e| return e,
                    };
                    const left = remaining - n;
                    c.state = if (left == 0) .body_crlf else .{ .body = left };
                    if (n != 0) return n;
                },
                .body_crlf => {
                    // Nothing is wanted of this line but that it be empty, so
                    // it is read into no buffer at all.
                    if (!(try c.takeLineRaw(c.line_buf[0..0])).blank) return c.fail(.malformed_chunk);
                    c.state = .chunk_header;
                },
                .trailers => {
                    // Consume trailer fields up to the blank line; capture
                    // them (with their CRLF, so the block parses like a head)
                    // when a buffer was provided, else just discard. Read
                    // straight into the capture buffer rather than into a
                    // line buffer and out again -- which also means a trailer
                    // line is bounded by the space left in it and not by the
                    // reader's buffer.
                    const line = try c.takeLineRaw(c.trailer_buf[c.trailer_len..]);
                    if (line.blank) {
                        c.state = .done;
                    } else if (c.trailer_buf.len != 0) {
                        // Excess lines are dropped whole, as before: the
                        // partial bytes are simply not committed.
                        if (line.overflow) c.trailers_overflow = true else c.trailer_len += line.bytes.len;
                    }
                },
            }
        }
    }

    /// One line into `dest`, with this decoder's failure vocabulary.
    fn takeLineRaw(c: *ChunkedReader, dest: []u8) Reader.StreamError!Line {
        return takeLineInto(c.in, dest) catch |err| switch (err) {
            error.ReadFailed => error.ReadFailed,
            error.EndOfStream => c.fail(.truncated_body),
        };
    }

    fn fail(c: *ChunkedReader, reason: FailReason) error{ReadFailed} {
        c.fail_reason = reason;
        return error.ReadFailed;
    }
};

// ── Content-Length bounded reader ───────────────────────────────────────────

/// Body reader for a `Content-Length: n` response: yields exactly `n` bytes
/// then end-of-stream. If the peer closes early, returns `error.ReadFailed`
/// with `truncated` set (a plain `Reader.Limited` cannot detect truncation).
///
/// Not movable after `reader` has been handed out.
pub const ContentLengthReader = struct {
    in: *Reader,
    remaining: u64,
    reader: Reader,
    truncated: bool = false,

    pub fn init(in: *Reader, content_length: u64, buffer: []u8) ContentLengthReader {
        return .{
            .in = in,
            .remaining = content_length,
            .reader = .{
                .vtable = &.{ .stream = streamFn },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamFn(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        const c: *ContentLengthReader = @alignCast(@fieldParentPtr("reader", r));
        if (c.remaining == 0) return error.EndOfStream;
        const n = c.in.stream(w, limit.min(.limited64(c.remaining))) catch |err| switch (err) {
            error.EndOfStream => {
                c.truncated = true;
                return error.ReadFailed;
            },
            error.ReadFailed, error.WriteFailed => |e| return e,
        };
        c.remaining -= n;
        return n;
    }
};

// ── chunked transfer-coding encoder ─────────────────────────────────────────

/// Streaming encoder for `Transfer-Encoding: chunked` request bodies,
/// exposed as a `std.Io.Writer` (`.writer`). Each drain of the internal
/// buffer emits one chunk; call `finish` to write the terminating 0-chunk
/// (the underlying writer still needs a flush afterwards).
///
/// Not movable after `writer` has been handed out.
pub const ChunkedWriter = struct {
    out: *Writer,
    writer: Writer,

    pub fn init(out: *Writer, buffer: []u8) ChunkedWriter {
        std.debug.assert(buffer.len > 0);
        return .{
            .out = out,
            .writer = .{
                .vtable = &.{ .drain = drainFn },
                .buffer = buffer,
            },
        };
    }

    fn drainFn(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const c: *ChunkedWriter = @alignCast(@fieldParentPtr("writer", w));
        var total: u64 = w.end;
        for (data[0 .. data.len - 1]) |d| total += d.len;
        total += data[data.len - 1].len * splat;
        // Never emit an empty chunk: "0\r\n" would terminate the body.
        if (total == 0) return 0;

        try c.out.print("{x}\r\n", .{total});
        try c.out.writeAll(w.buffer[0..w.end]);
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try c.out.writeAll(d);
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try c.out.writeAll(last);
        consumed += last.len * splat;
        try c.out.writeAll("\r\n");
        w.end = 0;
        return consumed;
    }

    /// Flush pending data as a final chunk and write the 0-chunk terminator
    /// (no trailers). The underlying writer is not flushed.
    pub fn finish(c: *ChunkedWriter) Writer.Error!void {
        return c.finishWithTrailers(&.{});
    }

    /// `finish` plus a **trailer section** (RFC 9112 §7.1.2). Wire order is
    /// load-bearing and is the whole point of this function: the last-chunk
    /// line `0\r\n` comes FIRST, then the trailer fields as ordinary
    /// `name: value` CRLF lines, then the blank line that ends the message.
    ///
    ///     0⏎ X-Checksum: deadbeef⏎ X-Rows: 3⏎ ⏎
    ///
    /// Emitting the fields before the `0` line instead turns each of them
    /// into a chunk-size line, which is a hard parse error on every
    /// conformant client (curl fails the transfer with exit 56) — an
    /// ordering mistake here is not a cosmetic one.
    ///
    /// Field names/values are written verbatim; the caller is responsible
    /// for validating them (see `Server.ResponseWriter.setTrailer`, which
    /// rejects both malformed and RFC 9110 §6.5.1-forbidden fields). With
    /// an empty `trailers` the bytes are exactly `finish`'s `0\r\n\r\n`.
    /// The underlying writer is not flushed.
    pub fn finishWithTrailers(c: *ChunkedWriter, trailers: []const HeaderEntry) Writer.Error!void {
        try c.writer.flush();
        try c.out.writeAll("0\r\n");
        for (trailers) |t| try c.out.print("{s}: {s}\r\n", .{ t.name, t.value });
        try c.out.writeAll("\r\n");
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Test reader that hands out its source one byte per stream call —
/// exercises the decoders' split-read handling.
const Trickle = struct {
    src: []const u8,
    pos: usize = 0,
    reader: Reader,

    fn init(src: []const u8, buffer: []u8) Trickle {
        return .{ .src = src, .reader = .{
            .vtable = &.{ .stream = streamFn },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        } };
    }

    fn streamFn(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        const t: *Trickle = @alignCast(@fieldParentPtr("reader", r));
        if (t.pos == t.src.len) return error.EndOfStream;
        const n = limit.minInt(1);
        if (n == 0) return 0;
        try w.writeAll(t.src[t.pos..][0..1]);
        t.pos += 1;
        return 1;
    }
};

/// A reader that hands out its input a record at a time and **cannot join two
/// of them** — the shape of a TLS record reader or a frame reader, where the
/// buffer is not storage the reader owns but an alias onto whatever arrived.
///
/// This is the reader the incremental line reading exists for, and it is
/// written to refuse rather than to be slow: a caller asking for more
/// contiguous bytes than the current record holds gets `ReadFailed`, exactly
/// as the real one does.
const RecordSource = struct {
    data: []const u8,
    chunk: usize,
    pos: usize = 0,
    reader: Reader,

    fn init(data: []const u8, chunk: usize) RecordSource {
        return .{
            .data = data,
            .chunk = chunk,
            .reader = .{
                .vtable = &.{ .stream = streamFn, .readVec = readVec, .rebase = rebase },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn pull(s: *RecordSource, r: *Reader) Reader.Error!void {
        if (s.pos == s.data.len) return error.EndOfStream;
        const n = @min(s.chunk, s.data.len - s.pos);
        r.buffer = @constCast(s.data[s.pos..][0..n]);
        r.seek = 0;
        r.end = n;
        s.pos += n;
    }

    fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize {
        const s: *RecordSource = @alignCast(@fieldParentPtr("reader", r));
        if (r.seek != r.end) return error.ReadFailed; // asked to span two records
        _ = data;
        try s.pull(r);
        return 0;
    }

    fn rebase(r: *Reader, capacity: usize) Reader.RebaseError!void {
        _ = capacity;
        if (r.seek == r.end) {
            r.buffer = r.buffer[0..0];
            r.seek = 0;
            r.end = 0;
            return;
        }
        return error.ReadFailed; // asked to span two records
    }

    fn streamFn(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        const s: *RecordSource = @alignCast(@fieldParentPtr("reader", r));
        if (r.seek == r.end) try s.pull(r);
        const available = r.buffer[r.seek..r.end];
        const n = limit.minInt(available.len);
        if (n == 0) return 0;
        try w.writeAll(available[0..n]);
        r.seek += n;
        return n;
    }
};

const split_request =
    "GET /suggest?q=abcde HTTP/1.1\r\n" ++
    "Host: api.example.com\r\n" ++
    "User-Agent: something-long-enough-to-straddle\r\n" ++
    "Accept: */*\r\n" ++
    "\r\nBODY";

test "readHead reads a head no record of which holds a whole line" {
    // Three bytes a record: every line of the request above spans several,
    // and the blank terminator can land split across two.
    var src: RecordSource = .init(split_request, 3);
    var buf: [256]u8 = undefined;
    const head = try readHead(&src.reader, &buf);
    try testing.expectEqualStrings(split_request[0 .. split_request.len - "\r\nBODY".len], head);
    // The body is still there, and still readable a record at a time.
    var out: [4]u8 = undefined;
    var w: Writer = .fixed(&out);
    var got: usize = 0;
    while (got < 4) got += try src.reader.stream(&w, .limited(4 - got));
    try testing.expectEqualStrings("BODY", &out);
}

test "the reader this is for really cannot serve takeDelimiterInclusive" {
    // Without this the test above proves nothing about the mechanism: a
    // reader that quietly joined records would pass it too. `readHead` used
    // to be exactly this call.
    //
    // ⚠ And note *which* error, because it is the whole reason this was worth
    // changing rather than documenting. `peekDelimiterInclusive` gives up as
    // soon as `buffer.len - content_len == 0`, which for a buffer that *is*
    // the record is immediately -- so the answer is `StreamTooLong`, which
    // `readHead` mapped to `HeadTooLarge`. A valid request would have been
    // refused for being too large: a wrong answer, not a slow one.
    var src: RecordSource = .init(split_request, 3);
    try testing.expectError(error.StreamTooLong, src.reader.takeDelimiterInclusive('\n'));
}

test "a head line longer than the buffer is still HeadTooLarge across records" {
    var src: RecordSource = .init(split_request, 3);
    var small: [40]u8 = undefined; // the first line alone is longer
    try testing.expectError(error.HeadTooLarge, readHead(&src.reader, &small));
}

test "a head whose lines exactly fill the buffer still ends" {
    // The blank terminator is two bytes that are never kept, so it must not
    // be charged against `buf`. Pins the `blank`-before-`overflow` order in
    // `readHead`; reverse them and this is HeadTooLarge.
    const lines = "GET / HTTP/1.1\r\nA: 1\r\n";
    var r: Reader = .fixed(lines ++ "\r\n");
    var exact: [lines.len]u8 = undefined;
    try testing.expectEqualStrings(lines, try readHead(&r, &exact));
}

test "a chunked body arrives over records that split every framing line" {
    const wire = "4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: v\r\n\r\n";
    var src: RecordSource = .init(wire, 3);
    var body: [64]u8 = undefined;
    var tbuf: [64]u8 = undefined;
    var cr: ChunkedReader = .initCapturingTrailers(&src.reader, &body, &tbuf);
    var out: [64]u8 = undefined;
    var w: Writer = .fixed(&out);
    var n: usize = 0;
    while (cr.reader.stream(&w, .limited(64 - n))) |k| {
        n += k;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    }
    try testing.expectEqualStrings("Wikipedia", out[0..n]);
    try testing.expectEqualStrings("X-T: v\r\n", cr.trailers());
}

test "readHead consumes the blank line and preserves raw lines" {
    var r: Reader = .fixed("HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\n\r\nBODY");
    var buf: [256]u8 = undefined;
    const head = try readHead(&r, &buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\n", head);
    // Body must remain unread on the stream.
    try testing.expectEqualStrings("BODY", try r.take(4));
}

test "readHead errors" {
    var buf: [256]u8 = undefined;

    var eof: Reader = .fixed("HTTP/1.1 200 OK\r\nA: 1\r\n"); // never terminated
    try testing.expectError(error.ConnectionClosed, readHead(&eof, &buf));

    var small_buf: [8]u8 = undefined;
    var big: Reader = .fixed("HTTP/1.1 200 OK\r\n\r\n");
    try testing.expectError(error.HeadTooLarge, readHead(&big, &small_buf));
}

test "ResponseHead.parse: status line variants" {
    const ok = try ResponseHead.parse("HTTP/1.1 200 OK\r\n");
    try testing.expectEqual(@as(u16, 200), ok.status);
    try testing.expectEqualStrings("OK", ok.reason);
    try testing.expect(!ok.http1_0);

    const nored = try ResponseHead.parse("HTTP/1.1 204\r\n"); // no reason phrase
    try testing.expectEqual(@as(u16, 204), nored.status);
    try testing.expectEqualStrings("", nored.reason);

    const old = try ResponseHead.parse("HTTP/1.0 302 Found\r\n");
    try testing.expect(old.http1_0);

    const multiword = try ResponseHead.parse("HTTP/1.1 404 Not Found\r\n");
    try testing.expectEqualStrings("Not Found", multiword.reason);
}

test "ResponseHead.parse: malformed heads never panic" {
    const malformed = [_][]const u8{
        "",
        "\r\n",
        "HTTP/1.1\r\n",
        "HTTP/1.1 20 OK\r\n",
        "HTTP/1.1 2000\r\n", // no space before reason
        "HTTP/1.1 abc\r\n",
        "ICY 200 OK\r\n",
        "HTTP/1.1 200 OK\r\nNoColonHere\r\n",
        "HTTP/1.1 200 OK\r\n: empty-name\r\n",
        "HTTP/1.1 200 OK\r\nBad Name: x\r\n",
        "HTTP/1.1 200 OK\r\nA: 1\r\n folded\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 12x\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n",
        // Content-Length is `1*DIGIT` only (RFC 9110 §8.6) — std.fmt.parseInt
        // would otherwise accept a leading `+`, `_` digit separators, and a
        // signed `-0`.
        "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -0\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: \r\n",
    };
    for (malformed) |m| try testing.expectError(error.MalformedHead, ResponseHead.parse(m));

    try testing.expectError(error.UnsupportedVersion, ResponseHead.parse("HTTP/2.0 200 OK\r\n"));
    try testing.expectError(error.UnsupportedVersion, ResponseHead.parse("HTTP/1.9 200 OK\r\n"));
}

test "ResponseHead.parse: framing headers" {
    const cl = try ResponseHead.parse("HTTP/1.1 200 OK\r\nContent-Length: 42\r\nServer: x\r\n");
    try testing.expectEqual(@as(?u64, 42), cl.content_length);
    try testing.expect(!cl.chunked);

    // Duplicate identical Content-Length is tolerated (RFC 7230 §3.3.2).
    const dup = try ResponseHead.parse("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Length: 7\r\n");
    try testing.expectEqual(@as(?u64, 7), dup.content_length);

    // Chunked overrides Content-Length; token match is case-insensitive.
    const te = try ResponseHead.parse("HTTP/1.1 200 OK\r\nContent-Length: 42\r\nTransfer-Encoding: gzip, Chunked\r\n");
    try testing.expect(te.chunked);
    try testing.expectEqual(@as(?u64, null), te.content_length);

    const cc = try ResponseHead.parse("HTTP/1.1 200 OK\r\nConnection: keep-alive, Close\r\n");
    try testing.expect(cc.connection_close);
    try testing.expect(cc.connection_keep_alive);

    // HTTP/1.0 default-closes unless it opts into persistence.
    const old_default = try ResponseHead.parse("HTTP/1.0 200 OK\r\n");
    try testing.expect(!old_default.connection_keep_alive);
    const old_ka = try ResponseHead.parse("HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\n");
    try testing.expect(old_ka.connection_keep_alive);
    try testing.expect(!old_ka.connection_close);
}

test "RequestHead.parse: happy paths" {
    const get = try RequestHead.parse("GET /x/y?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n");
    try testing.expectEqualStrings("GET", get.method);
    try testing.expectEqualStrings("/x/y?q=1", get.target);
    try testing.expect(!get.http1_0);
    try testing.expectEqualStrings("example.com", get.host.?);
    try testing.expectEqualStrings("*/*", get.header("accept").?);
    try testing.expectEqual(@as(?u64, null), get.content_length);
    try testing.expect(!get.chunked and !get.connection_close);

    const post = try RequestHead.parse("POST /submit HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n");
    try testing.expectEqualStrings("POST", post.method);
    try testing.expectEqual(@as(?u64, 11), post.content_length);

    const chunked = try RequestHead.parse("PUT /up HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n");
    try testing.expect(chunked.chunked);
    try testing.expect(chunked.has_transfer_encoding);
    try testing.expectEqual(@as(?u64, null), chunked.content_length); // chunked wins

    const old = try RequestHead.parse("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n");
    try testing.expect(old.http1_0);
    try testing.expect(old.connection_keep_alive);
    try testing.expect(old.host == null);

    const star = try RequestHead.parse("OPTIONS * HTTP/1.1\r\nHost: h\r\n");
    try testing.expectEqualStrings("*", star.target);

    const expect_hdr = try RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nExpect: 100-Continue\r\nContent-Length: 1\r\n");
    try testing.expect(expect_hdr.expect_continue);

    const closing = try RequestHead.parse("DELETE /d HTTP/1.1\r\nHost: h\r\nConnection: close\r\n");
    try testing.expect(closing.connection_close);
}

test "RequestHead.parse: malformed heads never panic" {
    const malformed = [_][]const u8{
        "",
        "\r\n",
        "GET\r\n",
        "GET /\r\n", // missing version
        "GET  HTTP/1.1\r\n", // empty target
        " / HTTP/1.1\r\n", // empty method
        "GET / HTTP/1.1 extra\r\n", // junk after version
        "G@T / HTTP/1.1\r\n", // non-token method byte
        "GET / http/1.1\r\n", // lowercase version
        "GET / HTTP/11\r\n", // version too short
        "GET / XTTP/1.1\r\n",
        "GET / HTTP/1.11\r\n", // version too long
        "GET / HTTP/1.1\r\nNoColonHere\r\n",
        "GET / HTTP/1.1\r\n: empty-name\r\n",
        "GET / HTTP/1.1\r\nBad Name: x\r\n",
        "GET / HTTP/1.1\r\nBad[Name: x\r\n", // name is not a token
        "GET / HTTP/1.1\r\nB\xc3\xa4d: x\r\n", // non-ASCII name
        "GET / HTTP/1.1\r\nX: va\x00lue\r\n", // NUL in a value
        "GET / HTTP/1.1\r\nX: va\rlue\r\n", // bare CR in a value
        "GET / HTTP/1.1\r\nX: va\x7flue\r\n", // DEL in a value
        "GET /caf\xc3\xa9 HTTP/1.1\r\n", // non-ASCII target
        "GET / HTTP/1.1\r\nHost: a/b\r\n", // Host with a path
        "GET / HTTP/1.1\r\nHost: u@h\r\n", // Host with userinfo
        "GET / HTTP/1.1\r\nHost: a, b\r\n", // two hosts in one field
        "GET / HTTP/1.1\r\nHost:\r\n", // empty Host on an origin-form request
        "GET / HTTP/1.1\r\nA: 1\r\n folded\r\n",
        "GET / HTTP/1.1\r\nContent-Length: 12x\r\n",
        "GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n",
        // Content-Length is `1*DIGIT` only (RFC 9110 §8.6) — std.fmt.parseInt
        // would otherwise accept a leading `+`, `_` digit separators, and a
        // signed `-0`.
        "GET / HTTP/1.1\r\nContent-Length: +5\r\n",
        "GET / HTTP/1.1\r\nContent-Length: 1_0\r\n",
        "GET / HTTP/1.1\r\nContent-Length: -0\r\n",
        "GET / HTTP/1.1\r\nContent-Length: \r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n", // duplicate Host
        "GET / HTTP/1.1\nHost: h\r\n", // bare-LF after the request line
        "GET / HTTP/1.1\r\nHost: h\nAccept: x\r\n", // bare-LF between headers
        "GET / HTTP/1.1\r\nHost: h\n", // bare-LF terminating the last header
    };
    for (malformed) |m| try testing.expectError(error.MalformedHead, RequestHead.parse(m));

    try testing.expectError(error.UnsupportedVersion, RequestHead.parse("GET / HTTP/2.0\r\n"));
    try testing.expectError(error.UnsupportedVersion, RequestHead.parse("GET / HTTP/1.9\r\n"));
    try testing.expectError(error.UnsupportedVersion, RequestHead.parse("PRI * HTTP/2.0\r\n"));
}

test "RequestHead.parse: Content-Length is strict 1*DIGIT (RFC 9110 §8.6)" {
    // A plain digit string still works.
    const plain = try RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n");
    try testing.expectEqual(@as(?u64, 5), plain.content_length);

    // Leading `+`, `_` digit-group separators, and a signed `-0` are all
    // rejected — std.fmt.parseInt would otherwise silently accept them
    // (`+5`→5, `1_0`→10, `-0`→0), diverging from a fronting CDN/LB that
    // forwards the raw bytes strictly.
    try testing.expectError(error.MalformedHead, RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n"));
    try testing.expectError(error.MalformedHead, RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 1_0\r\n"));
    try testing.expectError(error.MalformedHead, RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: -0\r\n"));
    try testing.expectError(error.MalformedHead, RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: \r\n"));
}

test "RequestHead.parse: Transfer-Encoding must be exactly the single 'chunked' token (RFC 9112 §6.1, TE.TE smuggling)" {
    // Chunked present but not the sole/final coding — "chunked, gzip"
    // (chunked not final), the reversed "gzip, chunked", and the
    // "chunked, chunked" double-chunk smuggling vector — must not be
    // framed as chunked. `parse` stays purely syntactic (no error here);
    // it leaves `chunked` false with `has_transfer_encoding` true, which
    // routes the request through the server's existing
    // `has_transfer_encoding and !chunked` → 400 gate (Server.zig).
    const not_final = try RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n");
    try testing.expect(not_final.has_transfer_encoding);
    try testing.expect(!not_final.chunked);

    const double_chunk = try RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, chunked\r\n");
    try testing.expect(double_chunk.has_transfer_encoding);
    try testing.expect(!double_chunk.chunked);

    const reversed = try RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n");
    try testing.expect(reversed.has_transfer_encoding);
    try testing.expect(!reversed.chunked);

    // The sole token — case-insensitively — still works.
    const sole = try RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n");
    try testing.expect(sole.chunked);
    const sole_case = try RequestHead.parse("POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: CHUNKED\r\n");
    try testing.expect(sole_case.chunked);
}

test "RequestHead.parse: bare-LF line endings are rejected (RFC 9112 §2.2)" {
    // A bare LF anywhere in the head is a request-smuggling vector (a
    // front-end and back-end can disagree on line framing), so it must be a
    // hard MalformedHead — the serving loop maps that to 400.
    try testing.expectError(error.MalformedHead, RequestHead.parse("GET / HTTP/1.1\nHost: h\r\n"));
    try testing.expectError(error.MalformedHead, RequestHead.parse("GET / HTTP/1.1\r\nHost: h\nAccept: */*\r\n"));
    try testing.expectError(error.MalformedHead, RequestHead.parse("GET / HTTP/1.1\r\nHost: h\n"));
    // A well-formed all-CRLF request is unaffected.
    const ok = try RequestHead.parse("GET / HTTP/1.1\r\nHost: h\r\nAccept: */*\r\n");
    try testing.expectEqualStrings("h", ok.host.?);
    try testing.expectEqualStrings("*/*", ok.header("accept").?);
}

test "RequestHead: duplicate identical Content-Length tolerated" {
    const dup = try RequestHead.parse("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 7\r\nContent-Length: 7\r\n");
    try testing.expectEqual(@as(?u64, 7), dup.content_length);
}

test "RequestHead.iterate walks wire order" {
    const h = try RequestHead.parse("GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nX-B: 2\r\n");
    var it = h.iterate();
    try testing.expectEqualStrings("Host", it.next().?.name);
    try testing.expectEqualStrings("X-A", it.next().?.name);
    try testing.expectEqualStrings("2", it.next().?.value);
    try testing.expect(it.next() == null);
}

test "ResponseHead.header lookup and iteration" {
    const h = try ResponseHead.parse("HTTP/1.1 301 Moved\r\nLocation: /new\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n");
    try testing.expectEqualStrings("/new", h.header("location").?);
    try testing.expectEqualStrings("/new", h.header("LOCATION").?);
    try testing.expectEqualStrings("a=1", h.header("set-cookie").?); // first wins
    try testing.expect(h.header("x-missing") == null);

    var it = h.iterate();
    var count: usize = 0;
    while (it.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 3), count);
}

fn expectChunkedDecode(wire: []const u8, expected: []const u8) !void {
    // Once from a fully buffered source…
    {
        var src: Reader = .fixed(wire);
        var cbuf: [64]u8 = undefined;
        var cr: ChunkedReader = .init(&src, &cbuf);
        var out: [256]u8 = undefined;
        var w: Writer = .fixed(&out);
        _ = try cr.reader.streamRemaining(&w);
        try testing.expectEqualStrings(expected, w.buffered());
    }
    // …and once with pathological 1-byte reads.
    {
        var tbuf: [64]u8 = undefined;
        var trickle: Trickle = .init(wire, &tbuf);
        var cbuf: [8]u8 = undefined;
        var cr: ChunkedReader = .init(&trickle.reader, &cbuf);
        var out: [256]u8 = undefined;
        var w: Writer = .fixed(&out);
        _ = try cr.reader.streamRemaining(&w);
        try testing.expectEqualStrings(expected, w.buffered());
    }
}

test "ChunkedReader decodes bodies" {
    try expectChunkedDecode("4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n", "Wikipedia in\r\n\r\nchunks.");
    try expectChunkedDecode("0\r\n\r\n", ""); // empty body
    try expectChunkedDecode("a\r\n0123456789\r\n0\r\n\r\n", "0123456789"); // lowercase hex
    try expectChunkedDecode("A\r\n0123456789\r\n0\r\n\r\n", "0123456789"); // uppercase hex
    try expectChunkedDecode("3;ext=1;q=\"x\"\r\nabc\r\n0\r\n\r\n", "abc"); // extensions ignored
    try expectChunkedDecode("3\r\nabc\r\n0\r\nX-Trailer: v\r\nX-More: w\r\n\r\n", "abc"); // trailers discarded
}

test "ChunkedReader rejects malformed and truncated input" {
    const cases = [_]struct { wire: []const u8, reason: ChunkedReader.FailReason }{
        .{ .wire = "zz\r\nab\r\n0\r\n\r\n", .reason = .malformed_chunk }, // bad hex
        .{ .wire = "\r\nab\r\n0\r\n\r\n", .reason = .malformed_chunk }, // empty size
        .{ .wire = "3\r\nabcX\r\n0\r\n\r\n", .reason = .malformed_chunk }, // missing chunk CRLF
        .{ .wire = "5\r\nab", .reason = .truncated_body }, // stream ends mid-chunk
        .{ .wire = "3\r\nabc\r\n", .reason = .truncated_body }, // stream ends before 0-chunk
        .{ .wire = "3\r\nabc\r\n0\r\n", .reason = .truncated_body }, // stream ends before trailer end
    };
    for (cases) |case| {
        var src: Reader = .fixed(case.wire);
        var cbuf: [64]u8 = undefined;
        var cr: ChunkedReader = .init(&src, &cbuf);
        var out: [256]u8 = undefined;
        var w: Writer = .fixed(&out);
        try testing.expectError(error.ReadFailed, cr.reader.streamRemaining(&w));
        try testing.expectEqual(case.reason, cr.fail_reason.?);
    }
}

test "ChunkedReader captures trailers when a buffer is provided" {
    // Body decodes as before; the trailer fields are now readable.
    var src: Reader = .fixed("3\r\nabc\r\n0\r\nX-Checksum: deadbeef\r\nX-Rows: 3\r\n\r\n");
    var cbuf: [64]u8 = undefined;
    var tbuf: [128]u8 = undefined;
    var cr: ChunkedReader = .initCapturingTrailers(&src, &cbuf, &tbuf);
    var out: [64]u8 = undefined;
    var w: Writer = .fixed(&out);
    _ = try cr.reader.streamRemaining(&w);
    try testing.expectEqualStrings("abc", w.buffered());
    // Trailers are available once the body is fully consumed.
    try testing.expectEqualStrings("deadbeef", cr.trailer("x-checksum").?); // case-insensitive
    try testing.expectEqualStrings("3", cr.trailer("X-Rows").?);
    try testing.expect(cr.trailer("x-missing") == null);
    try testing.expect(!cr.trailers_overflow);
    var it = cr.iterateTrailers();
    try testing.expectEqualStrings("X-Checksum", it.next().?.name);
    try testing.expectEqualStrings("X-Rows", it.next().?.name);
    try testing.expect(it.next() == null);
}

test "ChunkedReader: trailer capture overflow is flagged, body still decodes" {
    var src: Reader = .fixed("3\r\nabc\r\n0\r\nX-Big: " ++ ("z" ** 200) ++ "\r\n\r\n");
    var cbuf: [64]u8 = undefined;
    var tbuf: [16]u8 = undefined; // too small for the trailer line
    var cr: ChunkedReader = .initCapturingTrailers(&src, &cbuf, &tbuf);
    var out: [64]u8 = undefined;
    var w: Writer = .fixed(&out);
    _ = try cr.reader.streamRemaining(&w); // body unaffected, overflow drained
    try testing.expectEqualStrings("abc", w.buffered());
    try testing.expect(cr.trailers_overflow);
    try testing.expect(cr.trailer("x-big") == null); // dropped, not truncated-in
}

test "ContentLengthReader yields exactly n bytes" {
    var src: Reader = .fixed("hello, worldEXTRA");
    var buf: [8]u8 = undefined;
    var clr: ContentLengthReader = .init(&src, 12, &buf);
    var out: [64]u8 = undefined;
    var w: Writer = .fixed(&out);
    const n = try clr.reader.streamRemaining(&w);
    try testing.expectEqual(@as(usize, 12), n);
    try testing.expectEqualStrings("hello, world", w.buffered());
    // The excess stays on the underlying stream.
    try testing.expectEqualStrings("EXTRA", try src.take(5));
}

test "ContentLengthReader detects truncation" {
    var src: Reader = .fixed("shrt");
    var buf: [8]u8 = undefined;
    var clr: ContentLengthReader = .init(&src, 10, &buf);
    var out: [64]u8 = undefined;
    var w: Writer = .fixed(&out);
    try testing.expectError(error.ReadFailed, clr.reader.streamRemaining(&w));
    try testing.expect(clr.truncated);
}

test "ChunkedWriter emits parseable chunked bodies" {
    var out: [256]u8 = undefined;
    var sink: Writer = .fixed(&out);
    var cbuf: [8]u8 = undefined; // small on purpose: forces multiple chunks
    var cw: ChunkedWriter = .init(&sink, &cbuf);

    try cw.writer.writeAll("Hello, chunked world!");
    try cw.writer.print(" n={d}", .{42});
    try cw.finish();

    // Exact wire format is chunk-size dependent; verify by round-trip decode.
    var src: Reader = .fixed(sink.buffered());
    var dbuf: [16]u8 = undefined;
    var cr: ChunkedReader = .init(&src, &dbuf);
    var plain: [128]u8 = undefined;
    var w: Writer = .fixed(&plain);
    _ = try cr.reader.streamRemaining(&w);
    try testing.expectEqualStrings("Hello, chunked world! n=42", w.buffered());
}

test "ChunkedWriter: empty body is just the terminator" {
    var out: [16]u8 = undefined;
    var sink: Writer = .fixed(&out);
    var cbuf: [8]u8 = undefined;
    var cw: ChunkedWriter = .init(&sink, &cbuf);
    try cw.finish();
    try testing.expectEqualStrings("0\r\n\r\n", sink.buffered());
}

test "ChunkedWriter: single small write is one exact chunk" {
    var out: [64]u8 = undefined;
    var sink: Writer = .fixed(&out);
    var cbuf: [32]u8 = undefined;
    var cw: ChunkedWriter = .init(&sink, &cbuf);
    try cw.writer.writeAll("abc");
    try cw.finish();
    try testing.expectEqualStrings("3\r\nabc\r\n0\r\n\r\n", sink.buffered());
}

// ── fuzz: wire-facing parsers, never panic on arbitrary bytes ──────────────
//
// `RequestHead.parse`/`ResponseHead.parse` and `ChunkedReader` are the three
// HTTP/1.x parsers that see raw, attacker-controlled bytes directly off the
// wire (the request/status line + header block, and the chunked
// transfer-coding framing of a body) before any higher layer gets to look
// at them — exactly the "never panic on any input" contract HD1 exists for.

test "fuzz: RequestHead.parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzRequestHeadParse, .{});
}

fn fuzzRequestHeadParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = RequestHead.parse(buf[0..len]) catch return;
}

test "fuzz: ResponseHead.parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzResponseHeadParse, .{});
}

fn fuzzResponseHeadParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = ResponseHead.parse(buf[0..len]) catch return;
}

test "fuzz: ChunkedReader never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzChunkedReader, .{});
}

fn fuzzChunkedReader(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var src: Reader = .fixed(buf[0..len]);
    var cbuf: [64]u8 = undefined;
    var trailer_buf: [64]u8 = undefined;
    var cr: ChunkedReader = .initCapturingTrailers(&src, &cbuf, &trailer_buf);
    var out: [512]u8 = undefined;
    var w: Writer = .fixed(&out);
    // A malformed/truncated chunked stream surfaces as `error.ReadFailed`
    // (see `ChunkedReader.fail_reason`), never a panic or an infinite loop
    // (the fixed output buffer bounds `streamRemaining`'s work even if it
    // did loop).
    _ = cr.reader.streamRemaining(&w) catch {};
}

test "RequestHead: a head packed with minimal headers is bounded by bytes, not by a count" {
    // The backlog carried "max-header-count cap" as an open hardening item.
    // There is no per-header allocation to cap: the head is one borrowed byte
    // block bounded by the server's `max_header_bytes` (16 KiB by default),
    // and lookups scan it. This pins what that bound actually buys — a head
    // filled with the smallest legal headers, which is the worst case for a
    // linear scan, still parses and still answers lookups correctly.
    //
    // 16 KiB of `a0:\r\n`-shaped lines is ~2700 headers; ten lookups over that
    // is a few hundred thousand byte comparisons, which is not a denial of
    // service. A separate count cap would bound the same thing twice.
    const allocator = testing.allocator;
    var head: std.ArrayList(u8) = .empty;
    defer head.deinit(allocator);
    try head.appendSlice(allocator, "GET / HTTP/1.1\r\nHost: h\r\n");
    var i: usize = 0;
    while (head.items.len < 16 * 1024 - 32) : (i += 1) {
        var line_buf: [32]u8 = undefined;
        try head.appendSlice(allocator, try std.fmt.bufPrint(&line_buf, "h{d}: v\r\n", .{i}));
    }
    // The header we look for is LAST, so the scan cannot short-circuit early.
    try head.appendSlice(allocator, "x-needle: found\r\n");

    const parsed = try RequestHead.parse(head.items);
    try testing.expectEqualStrings("h", parsed.host.?);
    try testing.expectEqualStrings("found", parsed.header("x-needle").?);
    try testing.expectEqual(@as(?[]const u8, null), parsed.header("x-absent"));
    try testing.expect(i > 1000); // the head really is densely packed

    // Every line still iterates in wire order.
    var seen: usize = 0;
    var it = parsed.iterate();
    while (it.next()) |_| seen += 1;
    try testing.expectEqual(i + 2, seen); // Host + the h<N> lines + x-needle
}

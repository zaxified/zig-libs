//! h1 — pure HTTP/1.1 wire framing. No sockets, no allocation: everything
//! operates on `std.Io.Reader`/`std.Io.Writer` interfaces and caller buffers,
//! so it is fully testable offline and reusable by the Phase 2 server codec.
//!
//! Contents: response-head reader + parser, chunked transfer-coding decoder
//! (`ChunkedReader`) and encoder (`ChunkedWriter`), and a Content-Length
//! bounded body reader that detects truncation (`ContentLengthReader`).

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

/// Read one HTTP/1.x message head (status/request line + header lines) off
/// `r` into `buf`, consuming the terminating blank line. Returns the raw head
/// block — lines with their original `\r\n` endings, blank terminator
/// excluded. Line length is additionally bounded by `r`'s buffer capacity.
pub fn readHead(r: *Reader, buf: []u8) ReadHeadError![]const u8 {
    var len: usize = 0;
    while (true) {
        const line = r.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => return error.ConnectionClosed,
            error.StreamTooLong => return error.HeadTooLarge,
        };
        if (trimLineEnd(line).len == 0) return buf[0..len];
        if (buf.len - len < line.len) return error.HeadTooLarge;
        @memcpy(buf[len..][0..line.len], line);
        len += line.len;
    }
}

fn trimLineEnd(line: []const u8) []const u8 {
    return std.mem.trimEnd(u8, line, "\r\n");
}

// ── response head parsing ───────────────────────────────────────────────────

pub const HeadParseError = error{
    /// Not a syntactically valid HTTP/1.x response head.
    MalformedHead,
    /// An HTTP version this module does not speak (e.g. HTTP/2 on the wire).
    UnsupportedVersion,
};

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
            if (line[0] == ' ' or line[0] == '\t') return error.MalformedHead; // obs-fold
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHead;
            const name = line[0..colon];
            if (name.len == 0 or std.mem.indexOfAny(u8, name, " \t") != null)
                return error.MalformedHead;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                const n = std.fmt.parseInt(u64, value, 10) catch return error.MalformedHead;
                if (head.content_length) |prev| {
                    if (prev != n) return error.MalformedHead; // conflicting lengths
                } else head.content_length = n;
            } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                if (tokenListContains(value, "chunked")) head.chunked = true;
            } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
                if (tokenListContains(value, "close")) head.connection_close = true;
            }
        }

        // Chunked wins over Content-Length (RFC 7230 §3.3.3).
        if (head.chunked) head.content_length = null;
        return head;
    }

    /// First value of header `name` (case-insensitive), or null.
    pub fn header(h: *const ResponseHead, name: []const u8) ?[]const u8 {
        var it = h.iterate();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry.value;
        }
        return null;
    }

    pub const HeaderEntry = struct { name: []const u8, value: []const u8 };

    pub const Iterator = struct {
        lines: std.mem.SplitIterator(u8, .scalar),

        pub fn next(it: *Iterator) ?HeaderEntry {
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

    /// Iterate all header name/value pairs in wire order.
    pub fn iterate(h: *const ResponseHead) Iterator {
        return .{ .lines = std.mem.splitScalar(u8, h.header_block, '\n') };
    }
};

fn tokenListContains(list: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |t| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, t, " \t"), token)) return true;
    }
    return false;
}

// ── chunked transfer-coding decoder ─────────────────────────────────────────

/// Streaming decoder for `Transfer-Encoding: chunked` response bodies,
/// exposed as a `std.Io.Reader` (`.reader`). Trailer fields are consumed and
/// discarded. On protocol violation or a truncated stream it returns
/// `error.ReadFailed` and records the cause in `fail_reason`.
///
/// Not movable after `reader` has been handed out (the interface points back
/// into this struct).
pub const ChunkedReader = struct {
    in: *Reader,
    reader: Reader,
    state: State,
    fail_reason: ?FailReason = null,

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

    fn streamFn(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        const c: *ChunkedReader = @alignCast(@fieldParentPtr("reader", r));
        while (true) {
            switch (c.state) {
                .done => return error.EndOfStream,
                .chunk_header => {
                    const line = trimLineEnd(try c.takeLine());
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
                    if (trimLineEnd(try c.takeLine()).len != 0) return c.fail(.malformed_chunk);
                    c.state = .chunk_header;
                },
                .trailers => {
                    // Consume (and discard) trailer fields up to the blank line.
                    if (trimLineEnd(try c.takeLine()).len == 0) c.state = .done;
                },
            }
        }
    }

    fn takeLine(c: *ChunkedReader) Reader.StreamError![]const u8 {
        return c.in.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.ReadFailed => error.ReadFailed,
            error.EndOfStream => c.fail(.truncated_body),
            error.StreamTooLong => c.fail(.malformed_chunk),
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
        try c.writer.flush();
        try c.out.writeAll("0\r\n\r\n");
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

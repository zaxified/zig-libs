// SPDX-License-Identifier: MIT

//! `multipart/form-data` body parser (RFC 7578 + the RFC 2046 §5.1 multipart
//! grammar it builds on): the standard way an HTTP client uploads files and
//! mixed form fields. Given the body already read into a caller-owned buffer
//! (bound its size with an upstream request-body limit — this is the DoS
//! ceiling), iterate the parts; each yields its form-field `name`, optional
//! `filename`, `Content-Type`, and body bytes (a slice into the source, so
//! binary content passes through verbatim and zero-copy).
//!
//! Two shapes over one grammar. `parse` takes the whole body in memory: no
//! cross-read boundary-spanning to get wrong, the part bodies are plain
//! slices, and the size bound is simply "how big a buffer did you read into"
//! — the hard-to-misuse shape for the bounded form posts most APIs accept.
//! `Reader` streams from a `*std.Io.Reader` for uploads too large to hold:
//! each part's body is itself a reader that ends at the next delimiter, and
//! memory is one part's header block plus the underlying reader's buffer.
//! Both accept and refuse the same bodies and yield the same parts (a test
//! below drives them side by side over arbitrary bytes and read sizes).
//!
//! ## Usage
//!
//! ```zig
//! const ct = http.body.ContentType.parse(req.header("content-type") orelse "") orelse return;
//! if (!ct.isType("multipart/form-data")) return;
//! const boundary = ct.param("boundary") orelse return error.BadRequest; // RFC 2046 §5.1.1
//! // read the (size-limited) body into `buf` via req.reader() … then:
//! var it = http.multipart.parse(buf, boundary, .{});
//! while (try it.next()) |part| {
//!     if (part.filename) |fname| {
//!         // a file upload: part.value is the raw file bytes.
//!         // SECURITY: never use `fname` as a path directly — it is
//!         // attacker-controlled and may be "../../etc/passwd" or absolute.
//!         // Sanitize (basename only, allow-list charset) before touching disk.
//!     } else if (part.name) |field| {
//!         // an ordinary form field: part.value is its (text) value.
//!     }
//! }
//! ```
//!
//! ## Boundary handling (RFC 2046 §5.1.1)
//!
//! On the wire the delimiter is `CRLF "--" boundary`; the first part's opening
//! delimiter (`"--" boundary`) may omit the leading CRLF (it can start the
//! body), and the whole thing ends at the closing delimiter `"--" boundary
//! "--"`. Text before the first delimiter (the "preamble") and after the
//! closing one (the "epilogue") are ignored. `boundary` here is the value from
//! the Content-Type parameter WITHOUT the leading `--`.

const std = @import("std");
const body = @import("body.zig");
const h1 = @import("h1.zig");

/// Resource bounds. The overall body size is bounded by the caller's buffer;
/// these cap the per-body part count and per-part header size so a small body
/// full of tiny parts / a giant header block cannot blow up work or memory.
pub const Limits = struct {
    /// Maximum number of parts before `next` returns `error.TooManyParts`.
    max_parts: usize = 1000,
    /// Maximum bytes in one part's header block (up to the blank line) before
    /// `error.HeadersTooLarge`.
    max_header_bytes: usize = 16 * 1024,
};

pub const Error = error{
    /// The body does not conform to the multipart grammar (no opening
    /// delimiter, a part with no blank line terminating its headers, a
    /// delimiter that is neither followed by CRLF nor the closing `--`, …).
    MalformedBody,
    /// More than `Limits.max_parts` parts.
    TooManyParts,
    /// A part's header block exceeds `Limits.max_header_bytes`.
    HeadersTooLarge,
};

/// One parsed part. All slices point into the source buffer, which must
/// outlive the part.
pub const Part = struct {
    /// The Content-Disposition `name` parameter (the form-field name). Null
    /// only for a malformed part missing it (RFC 7578 §4.2 requires it).
    name: ?[]const u8,
    /// The Content-Disposition `filename` parameter — present ⇒ this part is a
    /// file upload. ATTACKER-CONTROLLED: never use as a filesystem path
    /// without sanitizing (basename, charset allow-list).
    filename: ?[]const u8,
    /// The part's own `Content-Type` (e.g. `application/pdf`); null ⇒ the
    /// RFC 7578 default `text/plain` applies.
    content_type: ?[]const u8,
    /// The part's raw header block (the `Name: value` lines, no trailing blank
    /// line), for looking up headers beyond the three surfaced above.
    headers_raw: []const u8,
    /// The part's body bytes, verbatim (binary-safe), a slice of the source.
    value: []const u8,

    /// First value of header `name` (case-insensitive) in this part's header
    /// block, or null.
    pub fn header(p: Part, name: []const u8) ?[]const u8 {
        return findHeader(p.headers_raw, name);
    }
};

/// First value of header `name` (case-insensitive) in a raw header block.
fn findHeader(headers_raw: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, headers_raw, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

/// The three headers a part surfaces, read out of its raw header block.
const Meta = struct {
    name: ?[]const u8 = null,
    filename: ?[]const u8 = null,
    content_type: ?[]const u8 = null,

    fn of(headers_raw: []const u8) Meta {
        var m: Meta = .{ .content_type = findHeader(headers_raw, "content-type") };
        if (findHeader(headers_raw, "content-disposition")) |cd_raw| {
            if (body.ContentType.parse(cd_raw)) |cd| {
                m.name = cd.param("name");
                m.filename = cd.param("filename");
            }
        }
        return m;
    }
};

/// Iterator over the parts of a multipart body.
pub const Iterator = struct {
    /// Not-yet-consumed tail of the source, positioned just after the previous
    /// part's closing CRLF (or, initially, at the very start).
    rest: []const u8,
    /// The delimiter line content WITHOUT the leading "--" (the raw boundary).
    boundary: []const u8,
    limits: Limits,
    parts_seen: usize = 0,
    /// Set once the closing delimiter (`--boundary--`) has been consumed.
    done: bool = false,

    /// Advance to the next part. Returns null at the closing delimiter (or
    /// clean end), or a typed error on a malformed body / exceeded limit.
    pub fn next(it: *Iterator) Error!?Part {
        if (it.done) return null;

        if (it.parts_seen == 0) {
            // Skip the preamble: find the opening dash-boundary, which must
            // be at rest[0] or immediately preceded by CRLF.
            if (std.mem.startsWith(u8, it.rest, "--") and
                std.mem.startsWith(u8, it.rest[2..], it.boundary))
            {
                it.rest = it.rest[2 + it.boundary.len ..];
            } else if (indexOfDelimiter(it.rest, it.boundary)) |p| {
                it.rest = it.rest[p + 4 + it.boundary.len ..];
            } else {
                return error.MalformedBody;
            }
        }

        // At a delimiter, positioned just past the dash_boundary bytes.
        if (std.mem.startsWith(u8, it.rest, "--")) {
            // Closing delimiter; transport-padding / epilogue after it is
            // ignored, not validated.
            it.done = true;
            return null;
        }
        // Tolerate transport-padding (SP / HTAB), then require CRLF.
        var pad: usize = 0;
        while (pad < it.rest.len and (it.rest[pad] == ' ' or it.rest[pad] == '\t')) : (pad += 1) {}
        if (!std.mem.startsWith(u8, it.rest[pad..], "\r\n")) return error.MalformedBody;
        it.rest = it.rest[pad + 2 ..];

        if (it.parts_seen == it.limits.max_parts) return error.TooManyParts;

        // Header block: up to the blank line terminating the headers. An
        // immediate CRLF means an empty header block (the "\r\n\r\n" search
        // would wrongly consume the body's first CRLF there).
        const hdr: struct { raw: []const u8, body_off: usize } = blk: {
            if (std.mem.startsWith(u8, it.rest, "\r\n"))
                break :blk .{ .raw = "", .body_off = 2 };
            const end = std.mem.indexOf(u8, it.rest, "\r\n\r\n") orelse
                return error.MalformedBody;
            break :blk .{ .raw = it.rest[0..end], .body_off = end + 4 };
        };
        if (hdr.raw.len > it.limits.max_header_bytes) return error.HeadersTooLarge;
        if (!wellFormedHeaders(hdr.raw)) return error.MalformedBody;

        // Body: up to the next "\r\n--boundary"; that CRLF is framing, not
        // body. Position rest just past the dash_boundary for the next call.
        const tail = it.rest[hdr.body_off..];
        const delim = indexOfDelimiter(tail, it.boundary) orelse
            return error.MalformedBody;
        it.rest = tail[delim + 4 + it.boundary.len ..];
        it.parts_seen += 1;

        const meta = Meta.of(hdr.raw);
        return .{
            .name = meta.name,
            .filename = meta.filename,
            .content_type = meta.content_type,
            .headers_raw = hdr.raw,
            .value = tail[0..delim],
        };
    }
};

/// Whether every line of a part's header block is `token ":" value`. A line
/// without a colon, or one that starts with whitespace (a folded
/// continuation), used to be skipped by the header lookup: a folded
/// `Content-Disposition` lost its `name`, and `--b CRLF --b` read the second
/// delimiter as an ignorable header line (Go oracle, 2026-10-05). Neither is
/// what a browser sends; refusing beats guessing.
fn wellFormedHeaders(raw: []const u8) bool {
    if (raw.len == 0) return true;
    var lines = std.mem.splitSequence(u8, raw, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return false;
        if (colon == 0) return false;
        for (line[0..colon]) |c| if (!h1.isTchar(c)) return false;
    }
    return true;
}

/// Index in `hay` of the first full delimiter `"\r\n--" ++ boundary`, or null.
fn indexOfDelimiter(hay: []const u8, boundary: []const u8) ?usize {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, hay, from, "\r\n--")) |p| : (from = p + 1) {
        if (std.mem.startsWith(u8, hay[p + 4 ..], boundary)) return p;
    }
    return null;
}

/// Parse a `multipart/form-data` body already read into `source`. `boundary`
/// is the Content-Type `boundary` parameter, WITHOUT the leading `--`
/// (`http.body.ContentType.param("boundary")` gives exactly this). Nothing is
/// parsed until you call `next`.
pub fn parse(source: []const u8, boundary: []const u8, limits: Limits) Iterator {
    return .{ .rest = source, .boundary = boundary, .limits = limits };
}

// ── streaming ────────────────────────────────────────────────────────────

/// What the streaming `Reader` can fail with: the buffered parser's errors,
/// plus `ReadFailed` when the underlying reader failed (its own diagnostics
/// say why — a transport error, or an upstream body cap).
pub const StreamError = Error || error{ReadFailed};

/// One part from the streaming `Reader`. The header slices point into the
/// reader's `header_buf` and stay valid until the next `nextPart`.
pub const StreamPart = struct {
    /// As `Part.name`.
    name: ?[]const u8,
    /// As `Part.filename` — ATTACKER-CONTROLLED, never a path as is.
    filename: ?[]const u8,
    /// As `Part.content_type`.
    content_type: ?[]const u8,
    /// As `Part.headers_raw`.
    headers_raw: []const u8,
    /// The part's body bytes, verbatim, as they arrive; `error.EndOfStream`
    /// at the delimiter that closes the part. The reader has no buffer of its
    /// own: read it with `stream`, `streamRemaining`, `readSliceShort`,
    /// `allocRemaining` or `discardRemaining`, not `peek`/`take`. A body that
    /// breaks the grammar fails the read with `error.ReadFailed` and sets
    /// `Reader.err`.
    body: *std.Io.Reader,

    /// First value of header `name` (case-insensitive), or null.
    pub fn header(p: StreamPart, name: []const u8) ?[]const u8 {
        return findHeader(p.headers_raw, name);
    }
};

/// Streaming `multipart/form-data` parser: the same grammar, limits and
/// errors as `parse`, over a `*std.Io.Reader` instead of a whole body in
/// memory, so an upload of any size costs one part's header block plus the
/// underlying reader's buffer. Go's `mime/multipart.Reader` shape: `nextPart`
/// yields a part whose `body` reads up to the next delimiter; calling
/// `nextPart` again skips whatever of the current body was left unread.
///
/// ```zig
/// var hdr: [http.multipart.header_buf_len]u8 = undefined;
/// var mr = try http.multipart.Reader.init(req_body, boundary, &hdr, .{});
/// while (try mr.nextPart()) |part| {
///     _ = part.body.streamRemaining(&file_writer.interface) catch |e| switch (e) {
///         error.ReadFailed => return mr.err orelse error.ReadFailed,
///         error.WriteFailed => return error.WriteFailed,
///     };
/// }
/// ```
///
/// The underlying reader must buffer at least `boundary.len + 4` bytes (a
/// whole delimiter, `CRLF "--" boundary`); `init` refuses a boundary it
/// cannot hold rather than asserting on a length the peer chose. Its buffer is
/// also the unit of work: body bytes are handed on as soon as they cannot be
/// the start of a delimiter, and at most one delimiter's worth is held back.
///
/// A failure is sticky: after any error every call returns it again.
pub const Reader = struct {
    in: *std.Io.Reader,
    /// The delimiter line content WITHOUT the leading "--" (the raw boundary).
    boundary: []const u8,
    /// Storage for the current part's header block.
    header_buf: []u8,
    limits: Limits,
    parts_seen: usize = 0,
    state: State = .start,
    /// Octets at the front of `in.buffered()` already known to be body — the
    /// scan result kept across calls, so a reader drained in small reads does
    /// not rescan the same buffered bytes for a delimiter each time.
    known_body: usize = 0,
    /// Why the last call failed; null until something did.
    err: ?StreamError = null,
    /// The current part's body, handed out as `StreamPart.body`.
    body_reader: std.Io.Reader,

    const State = enum {
        /// Nothing read yet: the preamble comes first.
        start,
        /// Just past a delimiter's boundary, before its `--` or CRLF.
        after_delimiter,
        /// Inside a part body.
        in_body,
        /// The closing delimiter has been read.
        done,
        /// A call failed; `err` says why.
        failed,
    };

    /// `header_buf` holds one part's header block and its terminating blank
    /// line: give it `limits.max_header_bytes + 4` bytes (`header_buf_len` for
    /// the default limits); a shorter one lowers the cap. `error.MalformedBody`
    /// when `boundary` is empty, longer than the 70 characters RFC 2046
    /// §5.1.1 allows, or longer than `in` can buffer as a delimiter.
    pub fn init(in: *std.Io.Reader, boundary: []const u8, header_buf: []u8, limits: Limits) error{MalformedBody}!Reader {
        if (boundary.len == 0 or boundary.len > 70 or boundary.len + 4 > in.buffer.len)
            return error.MalformedBody;
        return .{
            .in = in,
            .boundary = boundary,
            .header_buf = header_buf,
            .limits = limits,
            .body_reader = .{
                .vtable = &.{ .stream = bodyStream, .discard = bodyDiscard },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    /// Advance to the next part, skipping what is left of the current one.
    /// Null at the closing delimiter; the epilogue after it is not read.
    pub fn nextPart(r: *Reader) StreamError!?StreamPart {
        return r.advance() catch |e| {
            r.fail(e);
            return e;
        };
    }

    fn fail(r: *Reader, e: StreamError) void {
        r.state = .failed;
        r.err = e;
    }

    fn advance(r: *Reader) StreamError!?StreamPart {
        switch (r.state) {
            .failed => return r.err.?,
            .done => return null,
            .start => try r.skipPreamble(),
            .in_body => while (try r.bodyBytes()) |bytes| r.consume(bytes.len),
            .after_delimiter => {},
        }
        r.state = .after_delimiter;

        const next = r.in.peek(2) catch |e| return eof(e);
        if (std.mem.eql(u8, next, "--")) {
            // Closing delimiter; the epilogue after it is ignored, not read.
            r.state = .done;
            return null;
        }
        // Tolerate transport-padding (SP / HTAB), then require CRLF.
        while (true) {
            const c = r.in.peekByte() catch |e| return eof(e);
            if (c != ' ' and c != '\t') break;
            r.in.toss(1);
        }
        const crlf_ = r.in.peek(2) catch |e| return eof(e);
        if (!std.mem.eql(u8, crlf_, "\r\n")) return error.MalformedBody;
        r.in.toss(2);

        if (r.parts_seen == r.limits.max_parts) return error.TooManyParts;
        const raw = try r.readHeaders();
        if (!wellFormedHeaders(raw)) return error.MalformedBody;
        r.parts_seen += 1;
        r.state = .in_body;
        r.known_body = 0;

        const meta = Meta.of(raw);
        return .{
            .name = meta.name,
            .filename = meta.filename,
            .content_type = meta.content_type,
            .headers_raw = raw,
            .body = &r.body_reader,
        };
    }

    /// Consume up to and including the opening delimiter: `"--" boundary` at
    /// the very start, or else the first `CRLF "--" boundary`.
    fn skipPreamble(r: *Reader) StreamError!void {
        const head = r.in.peek(2 + r.boundary.len) catch |e| return eof(e);
        if (std.mem.startsWith(u8, head, "--") and std.mem.endsWith(u8, head, r.boundary)) {
            r.in.toss(head.len);
            return;
        }
        while (try r.bodyBytes()) |bytes| r.consume(bytes.len);
    }

    /// Read the header block up to its terminating blank line into
    /// `header_buf`; returns it without that blank line. The CRLF that ended
    /// the delimiter line counts as the first half of the terminator, so a
    /// part that opens with a bare CRLF has an empty header block (as in
    /// `parse`: a plain "\r\n\r\n" search would eat the body's first CRLF).
    fn readHeaders(r: *Reader) StreamError![]const u8 {
        const terminator = "\r\n\r\n";
        var matched: usize = 2;
        var n: usize = 0;
        while (matched < terminator.len) {
            if (n == r.header_buf.len or n == r.limits.max_header_bytes +| terminator.len)
                return error.HeadersTooLarge;
            const c = r.in.takeByte() catch |e| return eof(e);
            r.header_buf[n] = c;
            n += 1;
            matched = if (c == terminator[matched]) matched + 1 else if (c == '\r') 1 else 0;
        }
        // n == 2 only for the bare-CRLF case, where nothing precedes the terminator.
        const raw = r.header_buf[0..n -| terminator.len];
        if (raw.len > r.limits.max_header_bytes) return error.HeadersTooLarge;
        return raw;
    }

    /// The next body bytes at the front of `in` that cannot be part of a
    /// delimiter — not consumed; `consume` what you use. Null once the
    /// delimiter ending the body has been consumed.
    fn bodyBytes(r: *Reader) StreamError!?[]const u8 {
        if (r.known_body > 0) return r.in.buffered()[0..r.known_body];
        const delimiter_len = 4 + r.boundary.len;
        while (true) {
            const buf = r.in.buffered();
            if (indexOfDelimiter(buf, r.boundary)) |p| {
                if (p == 0) {
                    r.in.toss(delimiter_len);
                    return null;
                }
                r.known_body = p;
                return buf[0..p];
            }
            const held = partialDelimiterSuffix(buf, r.boundary);
            if (held < buf.len) {
                r.known_body = buf.len - held;
                return buf[0..r.known_body];
            }
            // All of what is buffered could still become a delimiter: read
            // more (`init` made sure a whole delimiter fits).
            r.in.fillMore() catch |e| return eof(e);
        }
    }

    fn consume(r: *Reader, n: usize) void {
        r.in.toss(n);
        r.known_body -= n;
    }

    /// The body bytes for `body_reader`: null at the end of the part.
    fn bodyChunk(r: *Reader) std.Io.Reader.Error!?[]const u8 {
        switch (r.state) {
            .in_body => {},
            .failed => return error.ReadFailed,
            else => return null,
        }
        const bytes = r.bodyBytes() catch |e| {
            r.fail(e);
            return error.ReadFailed;
        };
        if (bytes == null) r.state = .after_delimiter;
        return bytes;
    }

    fn bodyStream(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const r: *Reader = @alignCast(@fieldParentPtr("body_reader", io_r));
        const bytes = (try r.bodyChunk()) orelse return error.EndOfStream;
        // An unbuffered writer (`Discarding.init(&.{})`, a raw file) has no
        // slice to fill: hand the bytes to its `drain`, which says how many it
        // took. A buffered one is filled in place — `write` on a full fixed
        // writer would copy part and then fail, losing the count.
        const n = if (w.buffer.len == 0) try w.write(limit.sliceConst(bytes)) else n: {
            const dest = limit.slice(try w.writableSliceGreedy(1));
            const n = @min(dest.len, bytes.len);
            @memcpy(dest[0..n], bytes[0..n]);
            w.advance(n);
            break :n n;
        };
        r.consume(n);
        return n;
    }

    fn bodyDiscard(io_r: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        const r: *Reader = @alignCast(@fieldParentPtr("body_reader", io_r));
        const bytes = (try r.bodyChunk()) orelse return error.EndOfStream;
        const n = limit.minInt(bytes.len);
        r.consume(n);
        return n;
    }
};

/// `header_buf` length for the default `Limits`: the header block cap plus
/// its terminating blank line.
pub const header_buf_len = (Limits{}).max_header_bytes + 4;

/// The body ran out where the grammar needs more: malformed, unless the
/// underlying reader itself failed.
fn eof(e: std.Io.Reader.Error) StreamError {
    return switch (e) {
        error.EndOfStream => error.MalformedBody,
        error.ReadFailed => error.ReadFailed,
    };
}

/// Length of the longest suffix of `buf` that is a proper prefix of the
/// delimiter `"\r\n--" ++ boundary` — the bytes a scan must hold back
/// because the next read could complete them into a delimiter.
fn partialDelimiterSuffix(buf: []const u8, boundary: []const u8) usize {
    const delimiter_len = 4 + boundary.len;
    var k = @min(buf.len, delimiter_len - 1);
    while (k > 0) : (k -= 1) {
        const tail = buf[buf.len - k ..];
        if (tail[0] != '\r') continue;
        const lead = @min(k, 4);
        if (std.mem.eql(u8, tail[0..lead], "\r\n--"[0..lead]) and
            std.mem.eql(u8, tail[lead..], boundary[0 .. k - lead])) return k;
    }
    return 0;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

const test_boundary = "----WebKitFormBoundaryABC123";
/// dash-boundary: the delimiter line prefix as it appears on the wire.
const db = "--" ++ test_boundary;
const crlf = "\r\n";

test "happy path: text field + file part; closing delimiter ends iteration" {
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"title\"" ++ crlf ++
        crlf ++
        "Hello, world" ++ crlf ++
        db ++ crlf ++
        "Content-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"" ++ crlf ++
        "Content-Type: application/pdf" ++ crlf ++
        crlf ++
        "%PDF-1.7 fake" ++ crlf ++
        db ++ "--" ++ crlf;

    var it = parse(src, test_boundary, .{});

    // Plain text field: no filename, no Content-Type (⇒ text/plain default).
    const p1 = (try it.next()).?;
    try testing.expectEqualStrings("title", p1.name.?);
    try testing.expect(p1.filename == null);
    try testing.expect(p1.content_type == null);
    try testing.expectEqualStrings("Hello, world", p1.value);

    // File upload: filename + its own Content-Type.
    const p2 = (try it.next()).?;
    try testing.expectEqualStrings("file", p2.name.?);
    try testing.expectEqualStrings("report.pdf", p2.filename.?);
    try testing.expectEqualStrings("application/pdf", p2.content_type.?);
    try testing.expectEqualStrings("%PDF-1.7 fake", p2.value);

    try testing.expect((try it.next()) == null);
    try testing.expect((try it.next()) == null); // stays done
}

test "binary-safe: CRLF and boundary-like bytes inside a part body" {
    // Contains a raw CRLF, the bare boundary text, "--boundary" NOT preceded
    // by CRLF, and non-ASCII bytes — none of these may split the part.
    const payload = "line1\r\nline2 " ++ test_boundary ++ " zz" ++ db ++ "\x00\xff tail";
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"blob\"" ++ crlf ++
        crlf ++
        payload ++ crlf ++
        db ++ "--" ++ crlf;

    var it = parse(src, test_boundary, .{});
    const p = (try it.next()).?;
    try testing.expectEqualStrings("blob", p.name.?);
    try testing.expectEqualSlices(u8, payload, p.value);
    try testing.expect((try it.next()) == null);
}

test "preamble, epilogue and delimiter transport-padding are ignored" {
    const src = "This preamble is ignored (RFC 2046)." ++ crlf ++
        db ++ " \t" ++ crlf ++ // transport-padding before the CRLF
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++
        crlf ++
        "1" ++ crlf ++
        db ++ "--" ++ crlf ++
        "Epilogue junk, also ignored.";

    var it = parse(src, test_boundary, .{});
    const p = (try it.next()).?;
    try testing.expectEqualStrings("a", p.name.?);
    try testing.expectEqualStrings("1", p.value);
    try testing.expect((try it.next()) == null);
}

test "quoted filename with special characters" {
    // ';' and spaces inside the quoted filename must not split parameters
    // (body.ContentType parameter splitting is quoted-string aware).
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"up\"; filename=\"we;ird name(1).txt\"" ++ crlf ++
        crlf ++
        "data" ++ crlf ++
        db ++ "--" ++ crlf;

    var it = parse(src, test_boundary, .{});
    const p = (try it.next()).?;
    try testing.expectEqualStrings("up", p.name.?);
    try testing.expectEqualStrings("we;ird name(1).txt", p.filename.?);
    try testing.expectEqualStrings("data", p.value);
}

test "empty header block: blank line immediately after the delimiter" {
    const src = db ++ crlf ++
        crlf ++
        "raw" ++ crlf ++
        db ++ "--" ++ crlf;

    var it = parse(src, test_boundary, .{});
    const p = (try it.next()).?;
    try testing.expect(p.name == null);
    try testing.expect(p.filename == null);
    try testing.expect(p.content_type == null);
    try testing.expectEqualStrings("", p.headers_raw);
    try testing.expectEqualStrings("raw", p.value);
    try testing.expect((try it.next()) == null);
}

test "Part.header: case-insensitive lookup, OWS trimming, first match" {
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"x\"" ++ crlf ++
        "X-Custom-Meta: \t tagged value \t" ++ crlf ++
        "X-Custom-Meta: second (ignored)" ++ crlf ++
        crlf ++
        "v" ++ crlf ++
        db ++ "--" ++ crlf;

    var it = parse(src, test_boundary, .{});
    const p = (try it.next()).?;
    try testing.expectEqualStrings("tagged value", p.header("x-custom-meta").?);
    try testing.expectEqualStrings("tagged value", p.header("X-CUSTOM-META").?);
    try testing.expect(p.header("missing") == null);
}

test "limits: max_parts → TooManyParts; header block → HeadersTooLarge" {
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++
        crlf ++
        "1" ++ crlf ++
        db ++ crlf ++
        "Content-Disposition: form-data; name=\"b\"" ++ crlf ++
        crlf ++
        "2" ++ crlf ++
        db ++ "--" ++ crlf;

    var it = parse(src, test_boundary, .{ .max_parts = 1 });
    try testing.expectEqualStrings("a", (try it.next()).?.name.?);
    try testing.expectError(error.TooManyParts, it.next());

    var it2 = parse(src, test_boundary, .{ .max_header_bytes = 8 });
    try testing.expectError(error.HeadersTooLarge, it2.next());
}

test "Limits defaults are pinned (G8) — the mechanism above was tested, not the shipped values" {
    // A1 audit G8 (2026-09-04): mutating these two DEFAULT literals up by
    // 5-8 orders of magnitude (max_parts 1000 -> 100_000_000, max_header_bytes
    // 16 KiB -> 1 TiB) left the whole suite green, because every test above
    // passes an explicit override instead of exercising `Limits{}`. `G6`'s
    // amplification (a `Range` header that multiplies the represented body)
    // and this module's own DoS surface both lean on these two numbers being
    // what SPEC.md says they are.
    try testing.expectEqual(@as(usize, 1000), (Limits{}).max_parts);
    try testing.expectEqual(@as(usize, 16 * 1024), (Limits{}).max_header_bytes);
}

test "malformed bodies → MalformedBody" {
    // No opening delimiter at all.
    var it1 = parse("no delimiter here", test_boundary, .{});
    try testing.expectError(error.MalformedBody, it1.next());

    // Dash-boundary present but neither at offset 0 nor after a CRLF.
    var it2 = parse("xx" ++ db ++ crlf, test_boundary, .{});
    try testing.expectError(error.MalformedBody, it2.next());

    // A part with no blank line terminating its headers.
    const no_blank = db ++ crlf ++
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++
        db ++ "--" ++ crlf;
    var it3 = parse(no_blank, test_boundary, .{});
    try testing.expectError(error.MalformedBody, it3.next());

    // Unterminated final part (no closing delimiter).
    const unterminated = db ++ crlf ++
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++
        crlf ++
        "body with no end";
    var it4 = parse(unterminated, test_boundary, .{});
    try testing.expectError(error.MalformedBody, it4.next());

    // Delimiter line followed by garbage instead of CRLF or "--".
    const bad_line = db ++ "junk" ++ crlf;
    var it5 = parse(bad_line, test_boundary, .{});
    try testing.expectError(error.MalformedBody, it5.next());
}

// ── fuzz: multipart body parse, never panic on arbitrary bytes ─────────────
//
// `source` is a `multipart/form-data` request body already read into
// memory — fully attacker-controlled bytes, bounded only by the caller's
// upstream body-size limit. `it.rest` strictly shrinks on every successful
// `next()` (each branch reslices past what it just consumed), so a
// malformed/adversarial body always terminates in a typed error rather
// than looping — this harness exercises that termination directly, not
// just via an iteration cap.

// ⚠ This used to open with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain — so `len` was 0 on every
// input a corpus can carry and the parser was handed an EMPTY body, which
// refuses at the first `indexOf` without walking a single part. The whole
// "`it.rest` strictly shrinks" argument above was therefore never exercised.
// One `slice` draw reads the corpus entry's own length header instead.
//
// The 512-octet buffer is checked against the module's own largest fixture:
// the two-part happy-path body below is 276 octets, and every other body this
// module owns is shorter.

/// `testkit.fuzz.seed`, aliased so the corpus below reads as the request bodies
/// it is. A corpus entry is not the frame: the length draw reads a
/// little-endian `u32` first, so a raw body would arrive minus its own first
/// four octets. `testkit/src/fuzz.zig` carries the other two hazards.
const seed = @import("testkit").fuzz.seed;

/// `multipart/form-data` bodies against `test_boundary`, in the format the
/// length draw reads. Undirected bytes cannot produce a delimiter line — the
/// dash-boundary alone is 30 octets — so without these the harness never got
/// past the first `MalformedBody` and none of the header, limit or
/// binary-safety paths below ran at all.
const multipart_seeds = [_][]const u8{
    seed(db ++ crlf ++ // the two-part happy path: a text field and a file upload
        "Content-Disposition: form-data; name=\"title\"" ++ crlf ++ crlf ++
        "Hello, world" ++ crlf ++
        db ++ crlf ++
        "Content-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"" ++ crlf ++
        "Content-Type: application/pdf" ++ crlf ++ crlf ++
        "%PDF-1.7 fake" ++ crlf ++
        db ++ "--" ++ crlf),
    seed(db ++ crlf ++ // a body carrying CRLF, the bare boundary text and NUL/high bytes
        "Content-Disposition: form-data; name=\"blob\"" ++ crlf ++ crlf ++
        "line1\r\nline2 " ++ test_boundary ++ " zz" ++ db ++ "\x00\xff tail" ++ crlf ++
        db ++ "--" ++ crlf),
    seed("This preamble is ignored (RFC 2046)." ++ crlf ++ // preamble, transport-padding, epilogue
        db ++ " \t" ++ crlf ++
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ crlf ++
        "1" ++ crlf ++
        db ++ "--" ++ crlf ++
        "Epilogue junk, also ignored."),
    seed(db ++ crlf ++ // a ';' and spaces inside the quoted filename
        "Content-Disposition: form-data; name=\"up\"; filename=\"we;ird name(1).txt\"" ++ crlf ++ crlf ++
        "data" ++ crlf ++
        db ++ "--" ++ crlf),
    seed(db ++ crlf ++ crlf ++ "raw" ++ crlf ++ db ++ "--" ++ crlf), // no part headers at all
    seed(db ++ crlf ++ // a repeated custom header with OWS around its value
        "Content-Disposition: form-data; name=\"x\"" ++ crlf ++
        "X-Custom-Meta: \t tagged value \t" ++ crlf ++
        "X-Custom-Meta: second (ignored)" ++ crlf ++ crlf ++
        "v" ++ crlf ++
        db ++ "--" ++ crlf),
    seed(db ++ crlf ++ // two parts, which is what `max_parts` counts
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ crlf ++ "1" ++ crlf ++
        db ++ crlf ++
        "Content-Disposition: form-data; name=\"b\"" ++ crlf ++ crlf ++ "2" ++ crlf ++
        db ++ "--" ++ crlf),
    seed(db ++ crlf ++ // an empty part body between two delimiters
        "Content-Disposition: form-data; name=\"e\"" ++ crlf ++ crlf ++ crlf ++
        db ++ "--" ++ crlf),
    seed("no delimiter here"), // no opening delimiter at all
    seed("xx" ++ db ++ crlf), // a dash-boundary neither at offset 0 nor after a CRLF
    seed(db ++ crlf ++ // headers never terminated by a blank line
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++
        db ++ "--" ++ crlf),
    seed(db ++ crlf ++ // no closing delimiter: the body runs off the end
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ crlf ++
        "body with no end"),
    seed(db ++ "junk" ++ crlf), // a delimiter line followed by neither CRLF nor "--"
    seed(db), // the dash-boundary and nothing after it
    seed(db ++ "--"), // the closing delimiter with no trailing CRLF
};

test "fuzz: multipart parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzMultipartParse, .{ .corpus = &multipart_seeds });
}

fn fuzzMultipartParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);

    var it = parse(buf[0..len], test_boundary, .{});
    while (it.next() catch return) |_| {}
}

test "corpus: every multipart seed reaches the parser, and the parts walked are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, drawing
    // exactly the way the harness does.
    //
    // Parts walked is the second number and it is the one with teeth: an empty
    // body is refused, so "some seeds errored" was true of the collapsed draw
    // as well — it was true of EVERY input it ever ran. A part yielded, and
    // the octets of body it carried, are things no empty input can produce.
    var nonempty: usize = 0;
    var parts: usize = 0;
    var body_octets: usize = 0;
    var named: usize = 0;
    var refused: usize = 0;
    for (multipart_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;

        var it = parse(buf[0..len], test_boundary, .{});
        while (true) {
            const p = it.next() catch {
                refused += 1;
                break;
            } orelse break;
            parts += 1;
            body_octets += p.value.len;
            if (p.name != null) named += 1;
        }
    }
    try testing.expectEqual(multipart_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 15 seeds non-empty, 0 parts walked, 0 body
    // octets, 0 named parts and 15 refusals before the draw was fixed (every
    // input the harness ever ran was the same empty body); 15 / 10 / 117 /
    // 9 / 6 after.
    try testing.expectEqual(@as(usize, 10), parts);
    try testing.expectEqual(@as(usize, 117), body_octets);
    try testing.expectEqual(@as(usize, 9), named);
    try testing.expectEqual(@as(usize, 6), refused);
}

// ── streaming: tests ──────────────────────────────────────────────────────

/// Hands `src` out at most `step` octets per read through `buffer`, and fails
/// with `ReadFailed` once `fail_at` octets are out — the shapes a socket, a
/// small codec buffer and a dropped connection give the streaming `Reader`.
const ChunkedReader = struct {
    src: []const u8,
    step: usize,
    fail_at: ?usize = null,
    pos: usize = 0,
    interface: std.Io.Reader,

    fn init(src: []const u8, step: usize, buffer: []u8) ChunkedReader {
        return .{
            .src = src,
            .step = step,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    fn stream(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const c: *ChunkedReader = @alignCast(@fieldParentPtr("interface", io_r));
        const end = if (c.fail_at) |f| @min(f, c.src.len) else c.src.len;
        if (c.pos == end) return if (end < c.src.len) error.ReadFailed else error.EndOfStream;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = @min(dest.len, c.step, end - c.pos);
        @memcpy(dest[0..n], c.src[c.pos..][0..n]);
        w.advance(n);
        c.pos += n;
        return n;
    }
};

/// Whether the streaming reader's refusal `got` matches the buffered
/// parser's `want`. One pair differs by design: a header block over the cap
/// that never ends is `HeadersTooLarge` to the reader, which stops at the cap,
/// and `MalformedBody` to `parse`, which looks for the blank line first.
fn sameRefusal(want: Error, got: StreamError) bool {
    return got == want or (want == error.MalformedBody and got == error.HeadersTooLarge);
}

/// Drive `parse` and the streaming `Reader` side by side over `src`, the
/// latter reading `step` octets at a time through a `buf_len`-octet buffer,
/// and require the same parts (every header and every body octet) and the
/// same end: the closing delimiter, or a matching refusal.
fn expectSameAsParse(src: []const u8, boundary: []const u8, limits: Limits, step: usize, buf_len: usize) !void {
    const gpa = testing.allocator;
    const in_buf = try gpa.alloc(u8, buf_len);
    defer gpa.free(in_buf);
    const out = try gpa.alloc(u8, src.len);
    defer gpa.free(out);
    var hdr: [header_buf_len]u8 = undefined;

    var chunked: ChunkedReader = .init(src, step, in_buf);
    var mr = try Reader.init(&chunked.interface, boundary, &hdr, limits);
    var it = parse(src, boundary, limits);
    while (true) {
        const want = it.next() catch |we| {
            // `parse` refused here: the reader refuses at this `nextPart`,
            // or while reading the body of the part it yields.
            const ge: StreamError = if (mr.nextPart()) |maybe| blk: {
                const sp = maybe orelse return error.TestExpectedRefusal;
                var w: std.Io.Writer = .fixed(out);
                if (sp.body.streamRemaining(&w)) |_| return error.TestExpectedRefusal else |_| {}
                break :blk mr.err.?;
            } else |e| e;
            if (!sameRefusal(we, ge)) {
                std.debug.print("parse refused {t}, Reader {t}\n", .{ we, ge });
                return error.TestRefusalDiffers;
            }
            try testing.expectEqual(ge, mr.nextPart()); // sticky
            return;
        };
        const got = try mr.nextPart();
        const p = want orelse return testing.expect(got == null);
        const sp = got orelse return error.TestPartMissing;
        try testing.expectEqualStrings(p.headers_raw, sp.headers_raw);
        try expectEqualOpt(p.name, sp.name);
        try expectEqualOpt(p.filename, sp.filename);
        try expectEqualOpt(p.content_type, sp.content_type);
        var w: std.Io.Writer = .fixed(out);
        _ = try sp.body.streamRemaining(&w);
        try testing.expectEqualSlices(u8, p.value, w.buffered());
    }
}

fn expectEqualOpt(want: ?[]const u8, got: ?[]const u8) !void {
    if (want) |x| return testing.expectEqualStrings(x, got orelse return error.TestExpectedValue);
    try testing.expect(got == null);
}

/// Read sizes and buffer lengths, smallest first: one octet at a time through
/// a buffer that holds exactly one delimiter is where a split is likeliest.
const steps = [_]usize{ 1, 2, 3, 5, 7, 31, 64, 4096 };
const extra_buf = [_]usize{ 0, 1, 2, 33, 4096 };

fn expectSameAsParseEverywhere(src: []const u8, limits: Limits) !void {
    for (steps) |step| for (extra_buf) |extra| {
        expectSameAsParse(src, test_boundary, limits, step, test_boundary.len + 4 + extra) catch |e| {
            std.debug.print("step {d}, buffer {d}\n", .{ step, test_boundary.len + 4 + extra });
            return e;
        };
    };
}

test "Reader: every seed body gives what parse gives, at every read size and buffer length" {
    // The seeds are the buffered parser's fuzz corpus — every accepted and
    // refused shape that module owns — with the length frame stripped.
    for (multipart_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        try expectSameAsParseEverywhere(buf[0..len], .{});
        try expectSameAsParseEverywhere(buf[0..len], .{ .max_parts = 1 });
        try expectSameAsParseEverywhere(buf[0..len], .{ .max_header_bytes = 8 });
    }
}

test "Reader: a megabyte of near-delimiters streams byte-identical to parse" {
    // Random bodies salted with every proper prefix of the delimiter (and a
    // CR run before one), so held-back tails are completed, broken and
    // re-started across read boundaries all through the stream.
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x6d756c7469706172);
    const rand = prng.random();
    const delimiter = "\r\n--" ++ test_boundary;

    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    try src.appendSlice(gpa, "preamble\r\n--" ++ test_boundary[0..9] ++ "\r\n");
    for (0..24) |i| {
        try src.appendSlice(gpa, if (i == 0) db else delimiter);
        try src.print(gpa, "\r\nContent-Disposition: form-data; name=\"f{d}\"\r\n\r\n", .{i});
        const target = src.items.len + rand.intRangeAtMost(usize, 0, 80 * 1024);
        while (src.items.len < target) switch (rand.uintLessThan(u8, 4)) {
            0 => try src.appendSlice(gpa, delimiter[0..rand.uintLessThan(usize, delimiter.len)]),
            1 => try src.appendSlice(gpa, "\r\r\n\r\n-"),
            else => {
                var chunk: [97]u8 = undefined;
                rand.bytes(&chunk);
                try src.appendSlice(gpa, &chunk);
            },
        };
    }
    try src.appendSlice(gpa, delimiter ++ "--\r\nepilogue");

    for ([_][2]usize{ .{ 1, 0 }, .{ 3, 1 }, .{ 4096, 0 }, .{ 1500, 7 }, .{ 65536, 65536 } }) |c|
        try expectSameAsParse(src.items, test_boundary, .{}, c[0], delimiter.len + c[1]);
}

test "Reader: fuzz — same parts and the same end as parse, over any read size" {
    try testing.fuzz({}, fuzzStreamMatchesParse, .{ .corpus = &multipart_seeds });
}

fn fuzzStreamMatchesParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const step = smith.valueRangeAtMost(u8, 1, 64);
    const extra = smith.valueRangeAtMost(u8, 0, 64);
    try expectSameAsParse(buf[0..len], test_boundary, .{}, step, test_boundary.len + 4 + extra);
}

test "Reader: nextPart skips an unread body, and a half-read one" {
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ crlf ++
        "first body, never read" ++ crlf ++
        db ++ crlf ++
        "Content-Disposition: form-data; name=\"b\"" ++ crlf ++ crlf ++
        "second body, half read" ++ crlf ++
        db ++ crlf ++
        "Content-Disposition: form-data; name=\"c\"" ++ crlf ++ crlf ++
        "third" ++ crlf ++
        db ++ "--" ++ crlf;
    var in_buf: [test_boundary.len + 4]u8 = undefined;
    var chunked: ChunkedReader = .init(src, 1, &in_buf);
    var hdr: [header_buf_len]u8 = undefined;
    var mr = try Reader.init(&chunked.interface, test_boundary, &hdr, .{});

    try testing.expectEqualStrings("a", (try mr.nextPart()).?.name.?);
    const b = (try mr.nextPart()).?;
    try testing.expectEqualStrings("b", b.name.?);
    var half: [6]u8 = undefined;
    try testing.expectEqual(@as(usize, 6), try b.body.readSliceShort(&half));
    try testing.expectEqualStrings("second", &half);
    const c = (try mr.nextPart()).?;
    try testing.expectEqualStrings("c", c.name.?);
    try testing.expectEqual(@as(usize, 5), try c.body.discardRemaining());
    try testing.expect((try mr.nextPart()) == null);
    try testing.expect((try mr.nextPart()) == null); // stays done
    // A finished part's body keeps saying so.
    var one: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try c.body.readSliceShort(&one));
}

test "Reader: a failed underlying read is ReadFailed, sticky, and not a malformed body" {
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"up\"" ++ crlf ++ crlf ++
        "0123456789abcdef" ++ crlf ++
        db ++ "--" ++ crlf;
    var in_buf: [64]u8 = undefined;
    var hdr: [header_buf_len]u8 = undefined;

    // Mid-body: the body read fails, `err` says the transport did it.
    var chunked: ChunkedReader = .init(src, 3, &in_buf);
    chunked.fail_at = src.len - 20;
    var mr = try Reader.init(&chunked.interface, test_boundary, &hdr, .{});
    const p = (try mr.nextPart()).?;
    var w: std.Io.Writer.Discarding = .init(&.{});
    try testing.expectError(error.ReadFailed, p.body.streamRemaining(&w.writer));
    try testing.expectEqual(@as(?StreamError, error.ReadFailed), mr.err);
    try testing.expectError(error.ReadFailed, mr.nextPart());
    try testing.expectError(error.ReadFailed, p.body.discardRemaining());

    // In the headers: `nextPart` itself fails.
    var chunked2: ChunkedReader = .init(src, 3, &in_buf);
    chunked2.fail_at = db.len + 10;
    var mr2 = try Reader.init(&chunked2.interface, test_boundary, &hdr, .{});
    try testing.expectError(error.ReadFailed, mr2.nextPart());
    try testing.expectError(error.ReadFailed, mr2.nextPart());
}

test "Reader: a body that ends inside a part fails the body read with MalformedBody" {
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ crlf ++
        "body with no end\r\n--" ++ test_boundary[0..5];
    var in_buf: [64]u8 = undefined;
    var chunked: ChunkedReader = .init(src, 4, &in_buf);
    var hdr: [header_buf_len]u8 = undefined;
    var mr = try Reader.init(&chunked.interface, test_boundary, &hdr, .{});
    const p = (try mr.nextPart()).?;
    var got: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&got);
    try testing.expectError(error.ReadFailed, p.body.streamRemaining(&w));
    // Every octet that could not start the delimiter was handed on; the
    // held-back "\r\n--" + 5 never was.
    try testing.expectEqualStrings("body with no end", w.buffered());
    try testing.expectEqual(@as(?StreamError, error.MalformedBody), mr.err);
    try testing.expectError(error.MalformedBody, mr.nextPart());
}

test "Reader.init refuses a boundary RFC 2046 forbids or the buffer cannot hold" {
    var in_buf: [80]u8 = undefined;
    var chunked: ChunkedReader = .init("", 1, &in_buf);
    var hdr: [header_buf_len]u8 = undefined;
    const b70 = "b" ** 70;
    try testing.expectError(error.MalformedBody, Reader.init(&chunked.interface, "", &hdr, .{}));
    try testing.expectError(error.MalformedBody, Reader.init(&chunked.interface, b70 ++ "b", &hdr, .{}));
    _ = try Reader.init(&chunked.interface, b70, &hdr, .{});
    // 70 + "\r\n--" needs 74 octets of buffer.
    var small: ChunkedReader = .init("", 1, in_buf[0..73]);
    try testing.expectError(error.MalformedBody, Reader.init(&small.interface, b70, &hdr, .{}));
    var exact: ChunkedReader = .init("", 1, in_buf[0..74]);
    _ = try Reader.init(&exact.interface, b70, &hdr, .{});
}

test "Reader: header cap — max_header_bytes exactly fits, one more does not, a short header_buf lowers it" {
    const name_line = "Content-Disposition: form-data; name=\"a\"";
    const src = db ++ crlf ++ name_line ++ crlf ++ crlf ++ "v" ++ crlf ++ db ++ "--" ++ crlf;
    var in_buf: [64]u8 = undefined;
    var hdr: [header_buf_len]u8 = undefined;

    var c1: ChunkedReader = .init(src, 5, &in_buf);
    var fits = try Reader.init(&c1.interface, test_boundary, &hdr, .{ .max_header_bytes = name_line.len });
    try testing.expectEqualStrings(name_line, (try fits.nextPart()).?.headers_raw);

    var c2: ChunkedReader = .init(src, 5, &in_buf);
    var over = try Reader.init(&c2.interface, test_boundary, &hdr, .{ .max_header_bytes = name_line.len - 1 });
    try testing.expectError(error.HeadersTooLarge, over.nextPart());

    var c3: ChunkedReader = .init(src, 5, &in_buf);
    var short = try Reader.init(&c3.interface, test_boundary, hdr[0 .. name_line.len + 3], .{});
    try testing.expectError(error.HeadersTooLarge, short.nextPart());
    var c4: ChunkedReader = .init(src, 5, &in_buf);
    var enough = try Reader.init(&c4.interface, test_boundary, hdr[0 .. name_line.len + 4], .{});
    try testing.expectEqualStrings("a", (try enough.nextPart()).?.name.?);
}

test "header_buf_len is the default cap plus the blank line" {
    try testing.expectEqual(@as(usize, 16 * 1024 + 4), header_buf_len);
}

test "Reader: an endless header block stops at max_header_bytes, not at the end of header_buf" {
    // `parse` would call this malformed once the body ran out; the reader
    // must stop reading at the cap, however much storage it was lent.
    const src = db ++ crlf ++ "X-Long: " ++ "a" ** 200;
    var in_buf: [64]u8 = undefined;
    var chunked: ChunkedReader = .init(src, 7, &in_buf);
    var hdr: [256]u8 = undefined;
    var mr = try Reader.init(&chunked.interface, test_boundary, &hdr, .{ .max_header_bytes = 16 });
    try testing.expectError(error.HeadersTooLarge, mr.nextPart());
    try testing.expect(chunked.pos < src.len); // never read to the end
}

test "a part header line must be `token: value`: no colon, a fold or a second delimiter refuse the body" {
    const bad = [_][]const u8{
        // A line with no colon.
        db ++ crlf ++ "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ "NoColon" ++ crlf ++ crlf ++ "v" ++ crlf ++ db ++ "--" ++ crlf,
        // A folded continuation: skipping it lost `name`.
        db ++ crlf ++ "Content-Disposition: form-data;" ++ crlf ++ " name=\"a\"" ++ crlf ++ crlf ++ "v" ++ crlf ++ db ++ "--" ++ crlf,
        // A second delimiter read as a header line.
        db ++ crlf ++ db ++ crlf ++ "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ crlf ++ "v" ++ crlf ++ db ++ "--" ++ crlf,
        // Whitespace before the colon, and an empty name.
        db ++ crlf ++ "Content-Disposition : form-data; name=\"a\"" ++ crlf ++ crlf ++ "v" ++ crlf ++ db ++ "--" ++ crlf,
        db ++ crlf ++ ": x" ++ crlf ++ crlf ++ "v" ++ crlf ++ db ++ "--" ++ crlf,
    };
    for (bad) |src| {
        var it = parse(src, test_boundary, .{});
        try testing.expectError(error.MalformedBody, it.next());
        try expectSameAsParseEverywhere(src, .{});
    }
    // The refusal is per part: an earlier good part is still yielded.
    const second_bad = db ++ crlf ++ "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ crlf ++ "1" ++ crlf ++
        db ++ crlf ++ "Oops" ++ crlf ++ crlf ++ "2" ++ crlf ++ db ++ "--" ++ crlf;
    var it = parse(second_bad, test_boundary, .{});
    try testing.expectEqualStrings("1", (try it.next()).?.value);
    try testing.expectError(error.MalformedBody, it.next());
    try expectSameAsParseEverywhere(second_bad, .{});
}

test "Reader: a bare CR right before the blank line ends the header block where parse does" {
    // "\r\r\n\r\n": the first CR breaks the match, the second one starts it
    // again -- a scan that restarts from nothing runs on into the body.
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"a\"\r" ++ crlf ++ crlf ++
        "v\r\n\r\nw" ++ crlf ++
        db ++ "--" ++ crlf;
    try expectSameAsParseEverywhere(src, .{});
    var it = parse(src, test_boundary, .{});
    try testing.expectEqualStrings("v\r\n\r\nw", (try it.next()).?.value);
}

test "Reader: a bounded discard skips exactly that many body octets" {
    const src = db ++ crlf ++
        "Content-Disposition: form-data; name=\"a\"" ++ crlf ++ crlf ++
        "0123456789" ++ crlf ++
        db ++ "--" ++ crlf;
    var in_buf: [64]u8 = undefined;
    var chunked: ChunkedReader = .init(src, 64, &in_buf);
    var hdr: [header_buf_len]u8 = undefined;
    var mr = try Reader.init(&chunked.interface, test_boundary, &hdr, .{});
    const p = (try mr.nextPart()).?;
    try testing.expectEqual(@as(usize, 3), try p.body.discard(.limited(3)));
    var rest: [16]u8 = undefined;
    const n = try p.body.readSliceShort(&rest);
    try testing.expectEqualStrings("3456789", rest[0..n]);
}

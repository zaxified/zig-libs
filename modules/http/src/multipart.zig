// SPDX-License-Identifier: MIT

//! `multipart/form-data` body parser (RFC 7578 + the RFC 2046 §5.1 multipart
//! grammar it builds on): the standard way an HTTP client uploads files and
//! mixed form fields. Given the body already read into a caller-owned buffer
//! (bound its size with an upstream request-body limit — this is the DoS
//! ceiling), iterate the parts; each yields its form-field `name`, optional
//! `filename`, `Content-Type`, and body bytes (a slice into the source, so
//! binary content passes through verbatim and zero-copy).
//!
//! Buffer-based (not streaming) on purpose: the whole body is in memory, so
//! there is no cross-read boundary-spanning to get wrong, the part bodies are
//! plain slices, and the size bound is simply "how big a buffer did you read
//! into". For very large uploads a streaming variant could come later; for the
//! bounded form posts an internet-facing API actually accepts, this is the
//! correct, hard-to-misuse shape.
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
        var lines = std.mem.splitSequence(u8, p.headers_raw, "\r\n");
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
        return null;
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

        // Body: up to the next "\r\n--boundary"; that CRLF is framing, not
        // body. Position rest just past the dash_boundary for the next call.
        const tail = it.rest[hdr.body_off..];
        const delim = indexOfDelimiter(tail, it.boundary) orelse
            return error.MalformedBody;
        it.rest = tail[delim + 4 + it.boundary.len ..];
        it.parts_seen += 1;

        var part: Part = .{
            .name = null,
            .filename = null,
            .content_type = null,
            .headers_raw = hdr.raw,
            .value = tail[0..delim],
        };
        part.content_type = part.header("content-type");
        if (part.header("content-disposition")) |cd_raw| {
            if (body.ContentType.parse(cd_raw)) |cd| {
                part.name = cd.param("name");
                part.filename = cd.param("filename");
            }
        }
        return part;
    }
};

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

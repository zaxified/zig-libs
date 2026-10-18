// SPDX-License-Identifier: MIT

//! Request forms in one call — Go's `Request.ParseForm` +
//! `ParseMultipartForm` and the `FormValue` / `PostFormValue` / `FormFile`
//! lookups over their result — plus the client-side encoder
//! (`url.Values.Encode` / `QueryEscape`, what `Client.PostForm` sends).
//!
//! ```zig
//! var arena_state: std.heap.ArenaAllocator = .init(gpa);
//! defer arena_state.deinit();
//! const f = http.form.Form.parse(arena_state.allocator(), req, .{}) catch |e| switch (e) {
//!     error.BodyTooLarge, error.TooManyFields => return rw.writeError(413, "form too large"),
//!     error.MalformedForm => return rw.writeError(400, "malformed form"),
//!     error.ReadFailed, error.OutOfMemory => return e,
//! };
//! if (f.malformed) return rw.writeError(400, "malformed form"); // or read what decoded
//! const name = f.value("name") orelse "";
//! if (f.file("avatar")) |up| { … up.filename, up.data … }
//! ```
//!
//! Everything is copied or decoded once into the arena; the `Form` and every
//! slice it hands out live as long as the arena, independent of the request.
//!
//! ## What is read (Go's rules, pinned by the Go oracle, area `form`)
//!
//! * The query string, always. The body as
//!   `application/x-www-form-urlencoded` only for POST, PUT and PATCH; as
//!   `multipart/form-data` for any method (Go's `multipartReader` does not
//!   look at the method). Any other `Content-Type` leaves the body unread.
//! * Precedence (`value`): urlencoded body, then query, then multipart body —
//!   Go's documented `FormValue` order. `values` walks the same order.
//! * Pairs decode strictly (`url.decodeComponent`, Go's `ParseQuery`): a pair
//!   with a malformed escape is dropped and `malformed` is set — Go keeps the
//!   rest and returns the error from `ParseForm`. A query or body with more
//!   than `Limits.max_params` pairs is dropped whole, `malformed` set (Go's
//!   `urlmaxqueryparams`). A `;` is an ordinary byte (as in `url`; Go refuses
//!   the pair: judged divergence `body-semicolon`).
//! * A body-carrying request whose `Content-Type` Go's `mime.ParseMediaType`
//!   refuses sets `malformed` (`body.checkMediaType`); a type Go still
//!   returns (only a parameter is bad) is read under it, a refused one is not.
//! * Multipart: parts whose `Content-Disposition` is not cleanly `form-data`
//!   with a non-empty `name` are skipped. A part with a non-empty `filename`
//!   is a file, its name passed through Go's `filepath.Base`
//!   (`../../etc/passwd` → `passwd`, but `..` stays `..`: still sanitize
//!   before touching disk); every other part is a value.
//!
//! ## Where it differs from Go, deliberately
//!
//! * Hard failures are errors, not a half-filled form: a body over its cap
//!   (Go: `ParseForm` error "http: POST too large" with the query still
//!   read), a malformed multipart body, a missing boundary. Map them to
//!   400/413 (example above); Go's `FormValue` would ignore them and answer
//!   from the query.
//! * No temporary files. Go keeps 32 MiB of file data in memory and spills
//!   the rest to disk; here the whole multipart body must fit
//!   `Limits.max_multipart_bytes`, else `error.BodyTooLarge`. Uploads too big
//!   to hold go through the streaming `multipart.Reader` directly.
//! * `Content-Transfer-Encoding: quoted-printable` parts are not decoded
//!   (Go's `NextPart` does; RFC 7578 §4.7 deprecates the header and no
//!   browser sends it).

const std = @import("std");
const http = @import("root.zig");
const Server = @import("Server.zig");
const body = @import("body.zig");
const url = @import("url.zig");
const multipart = @import("multipart.zig");

const Allocator = std.mem.Allocator;

/// The media types this module reads.
pub const urlencoded_type = "application/x-www-form-urlencoded";
pub const multipart_type = "multipart/form-data";

pub const Limits = struct {
    /// Cap on an urlencoded body (Go's `maxFormSize`, 10 MiB).
    max_urlencoded_bytes: usize = 10 << 20,
    /// Cap on a whole multipart body, held in memory (Go's
    /// `defaultMaxMemory`, 32 MiB — there for file data, before spilling).
    max_multipart_bytes: usize = 32 << 20,
    /// Pairs in one query string or urlencoded body (Go's
    /// `urlmaxqueryparams`, 10000); past it the whole string is dropped.
    max_params: usize = 10_000,
    /// Part count and per-part header size of a multipart body.
    multipart: multipart.Limits = .{},
};

pub const ParseError = error{
    /// A body over its cap (`Limits`), declared or read; a multipart part
    /// header over `multipart.max_header_bytes`. 413.
    BodyTooLarge,
    /// More multipart parts than `multipart.max_parts`. 413.
    TooManyFields,
    /// A multipart body that breaks the grammar, or a multipart
    /// `Content-Type` without a (non-empty) boundary. 400.
    MalformedForm,
    /// The body could not be read: transport, framing, the server's own
    /// body cap, a `Server.BodyLimit` the handler installed.
    ReadFailed,
    OutOfMemory,
};

/// One decoded `name=value` pair.
pub const Pair = body.FormPair;

/// One uploaded file, held in memory (Go's `multipart.FileHeader`).
pub const File = struct {
    /// The form field name.
    name: []const u8,
    /// The client's file name after Go's `filepath.Base`. Never empty, but
    /// can be `.`, `..` or `/`: ATTACKER-CONTROLLED, sanitize before use.
    filename: []const u8,
    /// The part's own `Content-Type`, or null (RFC 7578 default
    /// `text/plain`; Go reports the header as absent too).
    content_type: ?[]const u8,
    /// The part's raw header block (see `multipart.Part.headers_raw`).
    headers_raw: []const u8,
    /// The file contents, verbatim.
    data: []const u8,
};

pub const Form = struct {
    /// Go's `Request.Form`: every value, a name's values in `value` order
    /// (urlencoded body, query, multipart body).
    all: []const Pair,
    /// Go's `Request.PostForm`: the body's values only.
    post: []const Pair,
    /// Go's `MultipartForm.File`, in body order.
    files: []const File,
    /// Go's `ParseForm` would have returned an error: a pair failed to
    /// decode (dropped), a query or body had too many pairs (dropped whole),
    /// a body-carrying request had a `Content-Type` Go refuses. What did
    /// decode is still here, as in Go.
    malformed: bool,

    pub const empty: Form = .{ .all = &.{}, .post = &.{}, .files = &.{}, .malformed = false };

    /// Read `req`'s form (see the module doc). Asks for the body only when
    /// it is going to read it — that is what sends a pending
    /// `100 Continue` — and refuses a declared `Content-Length` over the
    /// cap before that.
    pub fn parse(arena: Allocator, req: *Server.Request, limits: Limits) ParseError!Form {
        return parseSource(arena, .{
            .method = req.method,
            .content_type = req.header("content-type") orelse "",
            .query = req.query,
            .body = .{ .request = req },
            // The declared length frames the wire body; a transparently
            // decoded (gunzipped) one has a length of its own.
            .content_length = if (req.decoded == null) req.head.content_length else null,
        }, limits);
    }

    /// Go's `FormValue`: the first value of `name`, or null.
    pub fn value(f: *const Form, name: []const u8) ?[]const u8 {
        return first(f.all, name);
    }

    /// Go's `PostFormValue`: the first body value of `name`, or null.
    pub fn postValue(f: *const Form, name: []const u8) ?[]const u8 {
        return first(f.post, name);
    }

    /// Go's `Form[name]`: every value of `name`, in `value` order.
    pub fn values(f: *const Form, name: []const u8) Values {
        return .{ .pairs = f.all, .name = name };
    }

    /// Go's `FormFile`: the first file uploaded as `name`, or null.
    pub fn file(f: *const Form, name: []const u8) ?*const File {
        for (f.files) |*x| if (std.mem.eql(u8, x.name, name)) return x;
        return null;
    }

    fn first(pairs: []const Pair, name: []const u8) ?[]const u8 {
        for (pairs) |p| if (std.mem.eql(u8, p.name, name)) return p.value;
        return null;
    }
};

pub const Values = struct {
    pairs: []const Pair,
    name: []const u8,
    i: usize = 0,

    pub fn next(v: *Values) ?[]const u8 {
        while (v.i < v.pairs.len) {
            const p = v.pairs[v.i];
            v.i += 1;
            if (std.mem.eql(u8, p.name, v.name)) return p.value;
        }
        return null;
    }
};

/// What `parseSource` reads a form from: `Form.parse` fills it from a
/// request; tests and the fuzz harness fill it directly.
pub const Source = struct {
    method: http.Method,
    /// The `Content-Type` value, "" when absent.
    content_type: []const u8,
    /// The raw query (after the `?`), still encoded.
    query: []const u8,
    body: Body,
    /// The declared body length, when the body reader yields exactly that
    /// many octets.
    content_length: ?u64 = null,

    pub const Body = union(enum) {
        request: *Server.Request,
        reader: *std.Io.Reader,

        fn get(b: Body) *std.Io.Reader {
            return switch (b) {
                .request => |r| r.reader(),
                .reader => |r| r,
            };
        }
    };
};

pub fn parseSource(arena: Allocator, src: Source, limits: Limits) ParseError!Form {
    var malformed = false;
    var post: std.ArrayList(Pair) = .empty;
    var query: std.ArrayList(Pair) = .empty;
    var files: std.ArrayList(File) = .empty;

    // An absent type is `application/octet-stream` to Go: nothing to read,
    // nothing wrong.
    const ct: body.MediaTypeCheck = if (src.content_type.len == 0)
        .{ .media_type = "", .clean = true }
    else
        body.checkMediaType(src.content_type);
    const body_method = switch (src.method) {
        .post, .put, .patch => true,
        else => false,
    };
    if (body_method and !ct.clean) malformed = true;

    const is_multipart = ct.clean and std.ascii.eqlIgnoreCase(ct.media_type, multipart_type);
    if (body_method and std.ascii.eqlIgnoreCase(ct.media_type, urlencoded_type)) {
        const raw = try readBody(arena, src, limits.max_urlencoded_bytes);
        try decodePairs(arena, raw, limits.max_params, &post, &malformed);
    } else if (is_multipart) {
        try readMultipart(arena, src, limits, &post, &files);
    }
    try decodePairs(arena, src.query, limits.max_params, &query, &malformed);

    const all = try arena.alloc(Pair, post.items.len + query.items.len);
    // Go appends multipart values to a Form the query already filled.
    const before, const after = if (is_multipart) .{ query.items, post.items } else .{ post.items, query.items };
    @memcpy(all[0..before.len], before);
    @memcpy(all[before.len..], after);
    return .{ .all = all, .post = post.items, .files = files.items, .malformed = malformed };
}

/// The whole body into the arena, at most `cap` octets.
fn readBody(arena: Allocator, src: Source, cap: usize) ParseError![]u8 {
    if (src.content_length) |n| {
        if (n > cap) return error.BodyTooLarge;
        const buf = try arena.alloc(u8, @intCast(n));
        src.body.get().readSliceAll(buf) catch return error.ReadFailed;
        return buf;
    }
    // Zig 0.17: `allocRemaining` allows exactly `limit` bytes (0.16 failed at
    // `limit`, hence the former `cap +| 1`).
    return src.body.get().allocRemaining(arena, .limited(cap)) catch |e| switch (e) {
        error.StreamTooLong => error.BodyTooLarge,
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// Go's `url.ParseQuery` into `list`: pairs that do not decode are dropped,
/// a string with more than `max_params` pairs is dropped whole.
fn decodePairs(arena: Allocator, raw: []const u8, max_params: usize, list: *std.ArrayList(Pair), malformed: *bool) Allocator.Error!void {
    const n = std.mem.count(u8, raw, "&") + 1;
    if (n > max_params) {
        malformed.* = true;
        return;
    }
    if (raw.len == 0) return;
    try list.ensureUnusedCapacity(arena, n);
    // Decoding never grows a component, so the encoded length holds them all.
    const text = try arena.alloc(u8, raw.len);
    var used: usize = 0;
    var it = url.QueryIterator.init(raw);
    while (it.next()) |p| {
        const k = url.decodeComponent(text[used..], p.key) catch {
            malformed.* = true;
            continue;
        };
        const v = url.decodeComponent(text[used + k.len ..], p.value) catch {
            malformed.* = true;
            continue;
        };
        used += k.len + v.len;
        list.appendAssumeCapacity(.{ .name = k, .value = v });
    }
}

fn readMultipart(arena: Allocator, src: Source, limits: Limits, post: *std.ArrayList(Pair), files: *std.ArrayList(File)) ParseError!void {
    const ct = body.ContentType.parse(src.content_type) orelse return error.MalformedForm;
    const bbuf = try arena.alloc(u8, src.content_type.len);
    const boundary = (ct.paramUnescaped("boundary", bbuf) catch unreachable) orelse
        return error.MalformedForm; // Go's ErrMissingBoundary
    if (boundary.len == 0) return error.MalformedForm;

    const raw = try readBody(arena, src, limits.max_multipart_bytes);
    var it = multipart.parse(raw, boundary, limits.multipart);
    while (it.next() catch |e| return switch (e) {
        error.MalformedBody => error.MalformedForm,
        error.TooManyParts => error.TooManyFields,
        error.HeadersTooLarge => error.BodyTooLarge,
    }) |part| {
        // `name` is set only for a disposition Go parses cleanly; Go's
        // `FormName` also wants the type to be `form-data`.
        const name = part.name orelse continue;
        if (name.len == 0) continue;
        const cd = body.ContentType.parse(part.header("content-disposition").?).?;
        if (!cd.isType("form-data")) continue;
        const filename = part.filename orelse "";
        if (filename.len == 0) {
            try post.append(arena, .{ .name = name, .value = part.value });
        } else {
            try files.append(arena, .{
                .name = name,
                .filename = baseName(filename),
                .content_type = part.content_type,
                .headers_raw = part.headers_raw,
                .data = part.value,
            });
        }
    }
}

/// Go's `filepath.Base` on a non-empty path (Unix): the last element,
/// trailing slashes ignored; all slashes is `/`.
fn baseName(path: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, path, "/");
    if (trimmed.len == 0) return "/";
    const slash = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse return trimmed;
    return trimmed[slash + 1 ..];
}

// ── client side ─────────────────────────────────────────────────────────

/// Write `pairs` as an `application/x-www-form-urlencoded` body, in the
/// order given (Go's `Values.Encode` sorts by name; pass them sorted for
/// the same bytes). Send with `Content-Type: application/x-www-form-urlencoded`
/// (`urlencoded_type`) — Go's `Client.PostForm`.
pub fn encode(w: *std.Io.Writer, pairs: []const Pair) std.Io.Writer.Error!void {
    for (pairs, 0..) |p, i| {
        if (i != 0) try w.writeByte('&');
        try escape(w, p.name);
        try w.writeByte('=');
        try escape(w, p.value);
    }
}

/// `encode` into a new allocation owned by the caller.
pub fn encodeAlloc(gpa: Allocator, pairs: []const Pair) Allocator.Error![]u8 {
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    encode(&a.writer, pairs) catch return error.OutOfMemory;
    return a.toOwnedSlice();
}

/// Go's `url.QueryEscape`: letters, digits and `-_.~` as is, a space as
/// `+`, every other octet `%XX` (uppercase hex).
pub fn escape(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.', '~' => try w.writeByte(c),
        ' ' => try w.writeByte('+'),
        else => try w.print("%{X:0>2}", .{c}),
    };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn testParse(arena: Allocator, method: http.Method, content_type: []const u8, query: []const u8, body_bytes: []const u8, limits: Limits) ParseError!Form {
    var r: std.Io.Reader = .fixed(body_bytes);
    return parseSource(arena, .{
        .method = method,
        .content_type = content_type,
        .query = query,
        .body = .{ .reader = &r },
    }, limits);
}

test "Form: urlencoded body before the query, PostForm the body only" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const f = try testParse(arena.allocator(), .post, urlencoded_type, "a=q&c=3", "a=b&d=x+y%21", .{});
    try testing.expectEqualStrings("b", f.value("a").?);
    try testing.expectEqualStrings("3", f.value("c").?);
    try testing.expectEqualStrings("x y!", f.postValue("d").?);
    try testing.expectEqual(@as(?[]const u8, null), f.postValue("c"));
    try testing.expectEqual(@as(?[]const u8, null), f.value("missing"));
    var it = f.values("a");
    try testing.expectEqualStrings("b", it.next().?);
    try testing.expectEqualStrings("q", it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());
    try testing.expect(!f.malformed);
}

test "Form: only POST, PUT and PATCH read an urlencoded body" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for ([_]http.Method{ .get, .head, .delete, .options }) |m| {
        const f = try testParse(arena.allocator(), m, urlencoded_type, "q=1", "a=b", .{});
        try testing.expectEqual(@as(usize, 0), f.post.len);
        try testing.expectEqualStrings("1", f.value("q").?);
    }
    for ([_]http.Method{ .post, .put, .patch }) |m| {
        const f = try testParse(arena.allocator(), m, urlencoded_type, "", "a=b", .{});
        try testing.expectEqualStrings("b", f.postValue("a").?);
    }
}

test "Form: malformed pairs dropped and flagged, the rest kept" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const f = try testParse(arena.allocator(), .post, urlencoded_type, "x=%zz&y=1", "a=%4&b=2", .{});
    try testing.expect(f.malformed);
    try testing.expectEqual(@as(usize, 2), f.all.len);
    try testing.expectEqualStrings("2", f.value("b").?);
    try testing.expectEqualStrings("1", f.value("y").?);
}

test "Form: a Content-Type Go refuses flags body-carrying requests only" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect((try testParse(a, .post, "; x=1", "", "a=1", .{})).malformed);
    try testing.expect(!(try testParse(a, .get, "; x=1", "", "a=1", .{})).malformed);
    // A bad parameter keeps the type: the body is still read, and flagged.
    const f = try testParse(a, .post, urlencoded_type ++ "; charset", "", "a=1", .{});
    try testing.expect(f.malformed);
    try testing.expectEqualStrings("1", f.value("a").?);
    // Absent: nothing read, nothing wrong.
    const g = try testParse(a, .post, "", "", "a=1", .{});
    try testing.expect(!g.malformed);
    try testing.expectEqual(@as(usize, 0), g.all.len);
}

test "Form: the parameter cap drops a whole string at max_params + 1, keeps it at max_params" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const at = try testParse(a, .post, urlencoded_type, "q=1", "a=1&b=2&c=3", .{ .max_params = 3 });
    try testing.expectEqual(@as(usize, 4), at.all.len);
    try testing.expect(!at.malformed);
    const over = try testParse(a, .post, urlencoded_type, "q=1", "a=1&b=2&c=3&", .{ .max_params = 3 });
    try testing.expectEqual(@as(usize, 1), over.all.len); // the query survives
    try testing.expect(over.malformed);
}

test "Form: body caps, read and declared" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    _ = try testParse(a, .post, urlencoded_type, "", "a=12", .{ .max_urlencoded_bytes = 4 });
    try testing.expectError(error.BodyTooLarge, testParse(a, .post, urlencoded_type, "", "a=123", .{ .max_urlencoded_bytes = 4 }));
    var r: std.Io.Reader = .fixed("a=1");
    try testing.expectError(error.BodyTooLarge, parseSource(a, .{
        .method = .post,
        .content_type = urlencoded_type,
        .query = "",
        .body = .{ .reader = &r },
        .content_length = 5,
    }, .{ .max_urlencoded_bytes = 4 }));
    try testing.expectEqual(@as(usize, 0), r.seek); // refused before a byte was read
    // A declared length the body falls short of is a read failure.
    var short: std.Io.Reader = .fixed("a=1");
    try testing.expectError(error.ReadFailed, parseSource(a, .{
        .method = .post,
        .content_type = urlencoded_type,
        .query = "",
        .body = .{ .reader = &short },
        .content_length = 4,
    }, .{}));
    const mp = "multipart/form-data; boundary=B";
    const mp_body = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--B--\r\n";
    _ = try testParse(a, .post, mp, "", mp_body, .{ .max_multipart_bytes = mp_body.len });
    try testing.expectError(error.BodyTooLarge, testParse(a, .post, mp, "", mp_body, .{ .max_multipart_bytes = mp_body.len - 1 }));
}

test "Form: multipart values after the query, files apart, Go's FormName and filepath.Base" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const mp_body = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nm\r\n" ++
        "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"../x/y.txt\"\r\nContent-Type: text/plain\r\n\r\nfile\r\n" ++
        "--B\r\nContent-Disposition: attachment; name=\"skip\"\r\n\r\n1\r\n" ++
        "--B\r\nContent-Disposition: form-data; name=\"\"\r\n\r\n1\r\n" ++
        "--B\r\nContent-Disposition: form-data; name=\"e\"; filename=\"\"\r\n\r\nvalue\r\n--B--\r\n";
    const f = try testParse(arena.allocator(), .get, "multipart/form-data; boundary=\"B\"", "a=q", mp_body, .{});
    try testing.expectEqualStrings("q", f.value("a").?); // query first for multipart
    try testing.expectEqualStrings("m", f.postValue("a").?);
    try testing.expectEqualStrings("value", f.value("e").?); // empty filename: a value
    try testing.expectEqual(@as(?[]const u8, null), f.value("skip"));
    try testing.expectEqual(@as(usize, 2), f.post.len);
    const up = f.file("f").?;
    try testing.expectEqualStrings("y.txt", up.filename);
    try testing.expectEqualStrings("text/plain", up.content_type.?);
    try testing.expectEqualStrings("file", up.data);
    try testing.expectEqual(@as(?*const File, null), f.file("a"));
}

test "Form: multipart failures are errors" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const part = "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n";
    try testing.expectError(error.MalformedForm, testParse(a, .post, "multipart/form-data", "", part ++ "--B--\r\n", .{}));
    try testing.expectError(error.MalformedForm, testParse(a, .post, "multipart/form-data; boundary=\"\"", "", part ++ "--B--\r\n", .{}));
    try testing.expectError(error.MalformedForm, testParse(a, .post, "multipart/form-data; boundary=B", "", part, .{}));
    try testing.expectError(error.TooManyFields, testParse(a, .post, "multipart/form-data; boundary=B", "", part ++ part ++ "--B--\r\n", .{ .multipart = .{ .max_parts = 1 } }));
    try testing.expectError(error.BodyTooLarge, testParse(a, .post, "multipart/form-data; boundary=B", "", part ++ "--B--\r\n", .{ .multipart = .{ .max_header_bytes = 8 } }));
    // A multipart type Go refuses is not multipart at all: no error, nothing read.
    const f = try testParse(a, .post, "multipart/form-data; boundary=B; boundary=C", "q=1", part ++ "--B--\r\n", .{});
    try testing.expect(f.malformed);
    try testing.expectEqual(@as(usize, 1), f.all.len);
}

test "baseName: Go's filepath.Base on Unix" {
    const cases = [_][2][]const u8{
        .{ "a.txt", "a.txt" }, .{ "/tmp/a.txt", "a.txt" },  .{ "../../etc/passwd", "passwd" },
        .{ "a/b/", "b" },      .{ "///", "/" },             .{ ".", "." },
        .{ "..", ".." },       .{ "C:\\d\\a", "C:\\d\\a" },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], baseName(c[0]));
}

test "encode: QueryEscape per component, pairs in the order given" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try encode(&w, &.{ .{ .name = "q", .value = "a b+c" }, .{ .name = "č", .value = "" }, .{ .name = "-_.~", .value = "&=" } });
    try testing.expectEqualStrings("q=a+b%2Bc&%C4%8D=&-_.~=%26%3D", w.buffered());
    const owned = try encodeAlloc(testing.allocator, &.{.{ .name = "a", .value = "1" }});
    defer testing.allocator.free(owned);
    try testing.expectEqualStrings("a=1", owned);
    // Round trip through the decoder.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const f = try testParse(arena.allocator(), .post, urlencoded_type, "", w.buffered(), .{});
    try testing.expectEqualStrings("a b+c", f.value("q").?);
    try testing.expectEqualStrings("", f.value("č").?);
    try testing.expectEqualStrings("&=", f.value("-_.~").?);
}

// ── fuzz: a whole form over arbitrary method, type, query and body ────────

const seed = @import("testkit").fuzz.seed;
const fz = @import("fuzz_test.zig");
const Mark = fz.Marker(enum { refused, query_only, urlencoded, multipart, files, malformed });

/// A form request, flattened for the length draw: one selector octet (method
/// in the low two bits, content type in the next two), then `query`, a
/// `\x00`, then the body.
const form_seeds = [_][]const u8{
    seed("\x00a=1&b=2&a=3\x00"), // GET, no type
    seed("\x05a=q\x00a=b&d=x+y%21"), // POST, urlencoded
    seed("\x05\x00a=%zz&b=1&c=%4"), // malformed escapes
    seed("\x05x=1\x00&&a=1&&=&%2B=%2B"), // empty pairs, empty name
    seed("\x09a=q\x00--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nm\r\n--B--\r\n"), // POST, multipart
    seed("\x08\x00--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"../a\"\r\nContent-Type: x/y\r\n\r\nF\r\n--B--\r\n"), // GET, multipart file
    seed("\x09\x00--B\r\nContent-Disposition: attachment; name=\"a\"\r\n\r\n1\r\n--B\r\nContent-Disposition: form-data; name=\"\"\r\n\r\n2\r\n--B--\r\n"), // skipped parts
    seed("\x09\x00--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv"), // truncated
    seed("\x0d\x00a=1"), // POST, a type Go refuses
    seed("\x06q=1\x00a=1"), // PUT, urlencoded
};

const fuzz_types = [_][]const u8{ "", urlencoded_type, "multipart/form-data; boundary=B", "multipart/form-data; boundary=B; boundary=C" };
const fuzz_methods = [_]http.Method{ .get, .post, .put, .delete };

test "fuzz: Form.parse never panics on arbitrary requests" {
    try testing.fuzz({}, fuzzFormSmith, .{ .corpus = &form_seeds });
}

test "fuzz driver: HTTP_FUZZ (form)" {
    try fz.fuzz_driver.run(fuzzForm, .{ .prefix = "HTTP_FUZZ", .name = "http-form" });
}

test "fuzz harness: form, 300 seeds, reaches every outcome" {
    try Mark.reach(fuzzForm, "http-form", 300);
}

fn fuzzFormSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzForm, smith, script[0..n]);
}

fn fuzzForm(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &form_seeds);
    if (len == 0) return Mark.mark(.refused);
    const sel = buf[0];
    const rest = buf[1..len];
    const split = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
    const query = rest[0..split];
    const body_bytes = rest[@min(split + 1, rest.len)..];

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const f = testParse(arena.allocator(), fuzz_methods[sel & 3], fuzz_types[(sel >> 2) & 3], query, body_bytes, .{
        .max_params = 16,
        .multipart = .{ .max_parts = 8, .max_header_bytes = 256 },
    }) catch |e| switch (e) {
        error.BodyTooLarge, error.TooManyFields, error.MalformedForm => return Mark.mark(.refused),
        error.ReadFailed, error.OutOfMemory => return e,
    };
    // The body's values are in `all` too, and every pair decoded inside it.
    if (f.all.len < f.post.len) return error.PostNotInForm;
    for (f.files) |x| if (x.filename.len == 0 or x.name.len == 0) return error.EmptyFileName;
    if (f.malformed) Mark.mark(.malformed);
    if (f.files.len != 0) Mark.mark(.files);
    if (f.post.len == 0) Mark.mark(.query_only) else if ((sel >> 2) & 3 == 1) Mark.mark(.urlencoded) else Mark.mark(.multipart);
}

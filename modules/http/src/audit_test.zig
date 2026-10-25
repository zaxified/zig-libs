// SPDX-License-Identifier: MIT

//! Tests added by the 2026-10-25 grade-1 audit (axis A1) of `http`, one per
//! mutant the existing suite let survive (see the audit report). They use the
//! public surface plus the fields of `h2.Connection` (a struct has no private
//! fields) and stand on their own: no test here depends on another.

const std = @import("std");
const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const testkit = @import("testkit");

const http = @import("root.zig");
const h1 = @import("h1.zig");
const h2 = @import("h2.zig");
const hpack = @import("hpack.zig");
const body = @import("body.zig");
const conditional = @import("conditional.zig");
const range = @import("range.zig");
const gzip = @import("gzip.zig");
const multipart = @import("multipart.zig");
const proxy = @import("proxy.zig");
const httptest = @import("httptest.zig");
const Server = @import("Server.zig");
const Client = @import("Client.zig");

// ── h1 ──────────────────────────────────────────────────────────────────────

test "audit h1: DEL is not a request-target byte, a trailing tab is not part of a field value" {
    try testing.expect(!h1.isValidRequestTarget("/a\x7fb"));
    try testing.expect(h1.isValidRequestTarget("/a~b"));

    const head = try h1.RequestHead.parse("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\t\r\n");
    try testing.expectEqual(@as(?u64, 5), head.content_length);
    try testing.expectEqualStrings("5", head.header("content-length").?);
}

test "audit h1: findHeader sees a header line that starts inside a 4..7 byte tail window" {
    // 71 bytes: the last 64-byte window is 7 bytes wide and its '\n' is at
    // offset 4, with the one-letter header `A:` right behind it.
    var buf: [71]u8 = undefined;
    @memset(&buf, 'x');
    buf[0] = 'P';
    buf[1] = ':';
    buf[2] = ' ';
    buf[67] = '\r';
    buf[68] = '\n';
    buf[69] = 'A';
    buf[70] = ':';
    try testing.expectEqualStrings("", h1.blockHeader(&buf, "A").?);
}

test "audit h1: Content-Length is 1*DIGIT and exactly u64" {
    try testing.expectError(error.MalformedHead, h1.parseContentLengthStrict("1:"));
    try testing.expectError(error.MalformedHead, h1.parseContentLengthStrict("18446744073709551616"));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), try h1.parseContentLengthStrict("18446744073709551615"));
}

test "audit h1: response status line shape" {
    try testing.expectError(error.MalformedHead, h1.ResponseHead.parse("HTTP/1.1 20\r\n\r\n"));
    try testing.expectError(error.MalformedHead, h1.ResponseHead.parse("HTTP/1.1x200 OK\r\n\r\n"));
    const ok = try h1.ResponseHead.parse("HTTP/1.1 200\r\n\r\n");
    try testing.expectEqual(@as(u16, 200), ok.status);
}

fn decodeChunked(wire: []const u8, out: []u8) ![]const u8 {
    var src: Reader = .fixed(wire);
    var cbuf: [64]u8 = undefined;
    var cr: h1.ChunkedReader = .init(&src, &cbuf);
    var w: Writer = .fixed(out);
    _ = try cr.reader.streamRemaining(&w);
    return w.buffered();
}

test "audit h1: a zero-limit read of a chunked body returns 0 instead of spinning (L1)" {
    var src: Reader = .fixed("5\r\nhello\r\n0\r\n\r\n");
    var cbuf: [64]u8 = undefined;
    var cr: h1.ChunkedReader = .init(&src, &cbuf);
    var out: [16]u8 = undefined;
    var w: Writer = .fixed(&out);
    // Before the fix this call never returned (the test run's cap killed it).
    try testing.expectEqual(@as(usize, 0), try cr.reader.stream(&w, .nothing));
    _ = try cr.reader.streamRemaining(&w);
    try testing.expectEqualStrings("hello", w.buffered());
}

test "audit h1: a bare-LF chunk-size line is refused whatever its length" {
    var out: [32]u8 = undefined;
    // "55\n" used to decode as the size line "5" once the CR test was gone.
    try testing.expectError(error.ReadFailed, decodeChunked("55\nhello\r\n0\r\n\r\n", &out));
    // An unterminated quoted extension ending in a backslash.
    try testing.expectError(error.ReadFailed, decodeChunked("5;a=\"\\\r\nhello\r\n0\r\n\r\n", &out));
}

test "audit h1: the trailer cap is inclusive and a discarded trailer is not an overflow" {
    const wire = "0\r\nA: b\r\n\r\n"; // trailer section: 6 + 2 = 8 bytes
    {
        var src: Reader = .fixed(wire);
        var cbuf: [16]u8 = undefined;
        var cr: h1.ChunkedReader = .init(&src, &cbuf);
        cr.max_trailer_bytes = 8;
        var out: [8]u8 = undefined;
        var w: Writer = .fixed(&out);
        _ = try cr.reader.streamRemaining(&w);
        try testing.expect(!cr.trailers_overflow);
    }
    {
        var src: Reader = .fixed(wire);
        var cbuf: [16]u8 = undefined;
        var cr: h1.ChunkedReader = .init(&src, &cbuf);
        cr.max_trailer_bytes = 7;
        var out: [8]u8 = undefined;
        var w: Writer = .fixed(&out);
        try testing.expectError(error.ReadFailed, cr.reader.streamRemaining(&w));
        try testing.expectEqual(h1.ChunkedReader.FailReason.trailer_too_large, cr.fail_reason.?);
    }
}

test "audit h1: ChunkedWriter frames what the drain receives, splat included" {
    var sink: [256]u8 = undefined;
    var out: Writer = .fixed(&sink);
    var cbuf: [4]u8 = undefined;
    var cw: h1.ChunkedWriter = .init(&out, &cbuf);
    try cw.writer.writeAll("0123456789abcdef"); // bigger than the buffer: straight to drain
    try cw.writer.splatByteAll('x', 10);
    var parts = [_][]const u8{ "0123456789", "abcdefghij" };
    try cw.writer.writeVecAll(&parts);
    try cw.finish();
    var dec: [128]u8 = undefined;
    try testing.expectEqualStrings("0123456789abcdefxxxxxxxxxx0123456789abcdefghij", try decodeChunked(out.buffered(), &dec));
}

// ── Server ──────────────────────────────────────────────────────────────────

fn echoHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    try rw.writer().print("{s}", .{req.path});
}

fn statusOf(opts: Server.StreamOptions, wire: []const u8) !u16 {
    var rec = try httptest.record(testing.allocator, opts, wire, .{});
    defer rec.deinit();
    return (try rec.only()).status;
}

test "audit Server: request-line cap is inclusive; absolute-form targets are validated" {
    var o: Server.StreamOptions = .{ .handler = echoHandler, .server_name = null };
    o.max_request_line_bytes = 16; // "GET /ab HTTP/1.1" is 16 bytes
    try testing.expectEqual(@as(u16, 200), try statusOf(o, "GET /ab HTTP/1.1\r\nHost: t\r\n\r\n"));
    o.max_request_line_bytes = 15;
    try testing.expectEqual(@as(u16, 414), try statusOf(o, "GET /ab HTTP/1.1\r\nHost: t\r\n\r\n"));

    const q: Server.StreamOptions = .{ .handler = echoHandler, .server_name = null };
    try testing.expectEqual(@as(u16, 400), try statusOf(q, "GET ftp://h/x HTTP/1.1\r\nHost: h\r\n\r\n"));
    try testing.expectEqual(@as(u16, 200), try statusOf(q, "GET HTTP://h/x HTTP/1.1\r\nHost: h\r\n\r\n"));
    // HTTP/1.0 needs no Host, so only the authority check can refuse userinfo.
    try testing.expectEqual(@as(u16, 400), try statusOf(q, "GET http://u@h/x HTTP/1.0\r\n\r\n"));
}

test "audit Server: checkOriginPath refuses NUL and %00 anywhere" {
    try testing.expectError(error.PathForbidden, Server.checkOriginPath("/a\x00b"));
    try testing.expectError(error.PathForbidden, Server.checkOriginPath("/a%00"));
    try Server.checkOriginPath("/a%2fb");
}

// ── hpack ───────────────────────────────────────────────────────────────────

fn decodeOk(dec: *hpack.Decoder, block: []const u8) !void {
    var hl = try dec.decodeBlock(block);
    hl.deinit(testing.allocator);
}

test "audit hpack: an entry exactly as big as the table is inserted; entry 0 and the last static entry" {
    var dec = hpack.Decoder.init(testing.allocator, .{ .max_table_size = 36 });
    defer dec.deinit();
    try decodeOk(&dec, &.{ 0x40, 0x02, 'a', 'b', 0x02, 'c', 'd' }); // 2 + 2 + 32
    try testing.expectEqual(@as(usize, 1), dec.dynamicTableCount());
    try testing.expect(dec.dynamicTableEntry(0) == null);
    try testing.expect(dec.dynamicTableEntry(1) != null);

    var hl = try dec.decodeBlock(&.{0xBD}); // static 61
    defer hl.deinit(testing.allocator);
    try testing.expectEqualStrings("www-authenticate", hl.fields[0].name);
}

test "audit hpack: a size update after a literal field is refused" {
    var d1 = hpack.Decoder.init(testing.allocator, .{});
    defer d1.deinit();
    try testing.expectError(error.InvalidHpack, d1.decodeBlock(&.{ 0x40, 1, 'a', 1, 'b', 0x20 }));
    var d2 = hpack.Decoder.init(testing.allocator, .{});
    defer d2.deinit();
    try testing.expectError(error.InvalidHpack, d2.decodeBlock(&.{ 0x00, 1, 'a', 1, 'b', 0x20 }));
}

test "audit hpack: header-list accounting counts the 32-byte overhead, cumulatively, for every field kind" {
    const lit = [_]u8{ 0x00, 1, 'a', 1, 'b' }; // 1 + 1 + 32 = 34
    {
        var d = hpack.Decoder.init(testing.allocator, .{ .max_header_list_size = 34 });
        defer d.deinit();
        try decodeOk(&d, &lit); // exactly at the cap
    }
    {
        var d = hpack.Decoder.init(testing.allocator, .{ .max_header_list_size = 33 });
        defer d.deinit();
        try testing.expectError(error.HeaderListTooLarge, d.decodeBlock(&lit));
    }
    {
        var d = hpack.Decoder.init(testing.allocator, .{ .max_header_list_size = 40 });
        defer d.deinit();
        try testing.expectError(error.HeaderListTooLarge, d.decodeBlock(&(lit ++ lit)));
    }
    {
        var d = hpack.Decoder.init(testing.allocator, .{ .max_header_list_size = 40 });
        defer d.deinit();
        // `:method: GET` is 7 + 3 + 32 = 42.
        try testing.expectError(error.HeaderListTooLarge, d.decodeBlock(&.{0x82}));
    }
}

// ── body ────────────────────────────────────────────────────────────────────

test "audit body: ContentType parse/param details" {
    const ct = body.ContentType.parse("a/b; x=1").?;
    try testing.expectEqualStrings(" x=1", ct.params_section);

    var out3: [3]u8 = undefined;
    const ct3 = body.ContentType.parse("a/b; x=abc").?;
    try testing.expectEqualStrings("abc", (try ct3.paramUnescaped("x", &out3)).?);

    // An unquoted value is never unescaped.
    var out: [8]u8 = undefined;
    const bs = body.ContentType.parse("a/b; x=a\\\\b").?;
    try testing.expectEqualStrings("a\\\\b", (try bs.paramUnescaped("x", &out)).?);
    try testing.expect(!body.isQuotedValue("abc", "abc"));
    try testing.expect(!body.isQuotedValue("x=1", "x=1"[2..]));

    // A lone opening quote is not a quoted-string.
    try testing.expectEqualStrings("\"abc", body.ContentType.parse("a/b; x=\"abc").?.param("x").?);
}

test "audit body: checkMediaType verdicts" {
    try testing.expectEqualStrings("", body.checkMediaType("a\x7f/b").media_type);
    const tabbed = body.checkMediaType("\ttext/plain\t; a=b");
    try testing.expectEqualStrings("text/plain", tabbed.media_type);
    try testing.expect(tabbed.clean);
    try testing.expectEqualStrings("", body.checkMediaType("a b").media_type);
    try testing.expect(!body.checkMediaType("text/plain; a=b xc=d").clean);
    try testing.expect(!body.checkMediaType("text/plain; =x").clean);
    try testing.expect(!body.checkMediaType("text/plain; a bc").clean);
    try testing.expect(!body.checkMediaType("text/plain; a=\"x\\\ry\"").clean);
    // Same name, one value a prefix of the other: two different values.
    try testing.expectEqualStrings("", body.checkMediaType("text/plain; a=x; a=xy").media_type);
    try testing.expect(body.checkMediaType("text/plain; a=x; a=x").clean);
}

// ── conditional ─────────────────────────────────────────────────────────────

fn evalWith(method: http.Method, header_block: []const u8, v: conditional.Validators) conditional.Outcome {
    var b: Server.RequestBody = .{ .none = .fixed("") };
    const req: Server.Request = .{
        .method = method,
        .target = "/",
        .path = "/",
        .query = "",
        .head = .{
            .method = method.token(),
            .target = "/",
            .http1_0 = false,
            .header_block = header_block,
        },
        .body = &b,
        .context = null,
    };
    return conditional.evaluate(method, &req, v);
}

fn ifRange(header_block: []const u8, v: conditional.Validators) bool {
    var b: Server.RequestBody = .{ .none = .fixed("") };
    const req: Server.Request = .{
        .method = .get,
        .target = "/",
        .path = "/",
        .query = "",
        .head = .{
            .method = "GET",
            .target = "/",
            .http1_0 = false,
            .header_block = header_block,
        },
        .body = &b,
        .context = null,
    };
    return conditional.ifRangeAllows(&req, v);
}

test "audit conditional: `*`, duplicate If-Match, tag-list edges" {
    // `*` is satisfied by an ETag alone.
    try testing.expectEqual(conditional.Outcome.proceed, evalWith(.put, "If-Match: *\r\n", .{ .etag = "\"v1\"" }));
    // The first If-Match line wins.
    try testing.expectEqual(
        conditional.Outcome.precondition_failed,
        evalWith(.put, "If-Match: \"a\"\r\nIf-Match: \"v1\"\r\n", .{ .etag = "\"v1\"" }),
    );
    // A dangling `W/` is a malformed element, not an out-of-range read.
    try testing.expectEqual(conditional.Outcome.proceed, evalWith(.get, "If-None-Match: W/\r\n", .{ .etag = "\"v1\"" }));
    // OWS before the comma may be a tab.
    try testing.expectEqual(
        conditional.Outcome.not_modified,
        evalWith(.get, "If-None-Match: \"v1\"\t, \"x\"\r\n", .{ .etag = "\"v1\"" }),
    );
}

test "audit conditional: If-Range with an empty value never allows" {
    try testing.expect(!ifRange("If-Range: \r\n", .{ .etag = "\"v1\"" }));
    try testing.expect(ifRange("If-Range: \"v1\"\r\n", .{ .etag = "\"v1\"" }));
}

test "audit conditional: HTTP-date delimiters, widths and field ranges" {
    const imf_ok = "Sun, 06 Nov 1994 08:49:37 GMT";
    try testing.expect(conditional.parseHttpDate(imf_ok) != null);
    const imf_bad = [_][]const u8{
        "Sun,x06 Nov 1994 08:49:37 GMT", // s[4]
        "Sun, 06xNov 1994 08:49:37 GMT", // s[7]
        "Sun, 06 Novx1994 08:49:37 GMT", // s[11]
        "Sun, 06 Nov 1994x08:49:37 GMT", // s[16]
        "Sun, 06 Nov 1994 08:49x37 GMT", // tod[5]
        "Sun, 06 Nov 1994 08x49:37 GMT", // tod[2]
        "Sun, 0: Nov 1994 08:49:37 GMT", // ':' is not a digit
        "Sun,  6 Nov 1994 08:49:37 GMT", // a space is not a digit
    };
    for (imf_bad) |s| try testing.expectEqual(@as(?i64, null), conditional.parseHttpDate(s));

    // The last second of the day is valid.
    try testing.expect(conditional.parseHttpDate("Sun, 06 Nov 1994 23:59:59 GMT") != null);

    const r850_ok = "Sunday, 06-Nov-94 08:49:37 GMT";
    try testing.expect(conditional.parseHttpDate(r850_ok) != null);
    try testing.expectEqual(@as(?i64, null), conditional.parseHttpDate("Sunday,x06-Nov-94 08:49:37 GMT"));
    try testing.expectEqual(@as(?i64, null), conditional.parseHttpDate("Sunday, 06-Nov-94 08:49:37 UTC"));
    try testing.expectEqual(@as(?i64, null), conditional.parseHttpDate("Sunday, 06-Nov-94 08:49:37 GMTx"));

    const asc_ok = "Sun Nov  6 08:49:37 1994";
    try testing.expect(conditional.parseHttpDate(asc_ok) != null);
    try testing.expectEqual(@as(?i64, null), conditional.parseHttpDate("Sun Nov  6 08:49:37 1994x"));
    try testing.expectEqual(@as(?i64, null), conditional.parseHttpDate("Sun Nov  6x08:49:37 1994"));
    try testing.expectEqual(@as(?i64, null), conditional.parseHttpDate("Sun Nov  6 08:49:37x1994"));
}

// ── range ───────────────────────────────────────────────────────────────────

test "audit range: tab is OWS, resolve is bounded by out, writeBody preflight is inclusive" {
    var buf: [4]range.ByteRangeSpec = undefined;
    try testing.expectEqual(@as(usize, 2), (try range.parse("bytes=0-1,\t,2-3", &buf)).len);
    try testing.expectEqual(@as(usize, 2), (try range.parse("bytes=0-1\t,2-3", &buf)).len);

    const specs = [_]range.ByteRangeSpec{ .{ .from = 0 }, .{ .from = 1 }, .{ .from = 2 } };
    var out2: [2]range.ResolvedRange = undefined;
    try testing.expectEqual(@as(usize, 2), range.resolve(&specs, 10, &out2).len);

    var sink: [128]u8 = undefined;
    var w: Writer = .fixed(&sink);
    const mp: range.MultipartRanges = .{ .boundary = "B", .content_type = "t/p" };
    const rr = [_]range.ResolvedRange{.{ .start = 0, .end = 3, .total = 4 }};
    try testing.expectError(error.RangeOutOfBounds, mp.writeBody(&w, &rr, "abc"));
}

const long_boundary: [71]u8 = blk: {
    var b: [71]u8 = undefined;
    @memset(&b, 'a');
    break :blk b;
};

fn longBoundaryHandler(_: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    const mp: range.MultipartRanges = .{ .boundary = &long_boundary, .content_type = "t/p" };
    mp.setContentType(rw) catch |e| {
        if (e == error.BoundaryTooLong) rw.setStatus(418);
        return;
    };
}

test "audit range: a boundary over 70 characters is refused by setContentType" {
    try testing.expectEqual(
        @as(u16, 418),
        try statusOf(.{ .handler = longBoundaryHandler, .server_name = null }, "GET / HTTP/1.1\r\nHost: t\r\n\r\n"),
    );
}

test "audit multipart: the header-size cap is inclusive" {
    const hdr = "Content-Disposition: form-data; name=\"a\"";
    const wire = "--B\r\n" ++ hdr ++ "\r\n\r\nxyz\r\n--B--\r\n";
    var buf: [wire.len]u8 = undefined;
    @memcpy(&buf, wire);
    var it = multipart.parse(&buf, "B", .{ .max_header_bytes = hdr.len });
    const part = (try it.next()).?;
    try testing.expectEqualStrings("a", part.name.?);
    @memcpy(&buf, wire);
    var it2 = multipart.parse(&buf, "B", .{ .max_header_bytes = hdr.len - 1 });
    try testing.expectError(error.HeadersTooLarge, it2.next());
}

// ── root / gzip / proxy helpers ─────────────────────────────────────────────

fn dots(comptime in: []const u8) []const u8 {
    const S = struct {
        var buf: [64]u8 = undefined;
    };
    @memcpy(S.buf[0..in.len], in);
    return S.buf[0..http.removeDotSegments(S.buf[0..in.len])];
}

test "audit root: removeDotSegments leading dot forms (RFC 3986 5.2.4 steps A and D)" {
    try testing.expectEqualStrings("a", dots("../a"));
    try testing.expectEqualStrings("a", dots("./a"));
    try testing.expectEqualStrings("", dots("."));
    try testing.expectEqualStrings("", dots(".."));
}

test "audit gzip/proxy: q-value edges, empty allowlist entry, Trailers is hop-by-hop" {
    try testing.expect(gzip.acceptsGzip("gzip;q"));
    try testing.expect(gzip.acceptsGzip("gzip;q="));
    // `qx0` is not a q-value parameter: it must not be read as `q=0`.
    try testing.expect(gzip.acceptsGzip("gzip;qx0"));
    try testing.expect(!gzip.contentTypeCompressible("text/plain", &.{""}));
    try testing.expect(proxy.isHopByHop("Trailers", null));
}

// ── proxy, end to end ───────────────────────────────────────────────────────

fn reflectAll(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    var it = req.iterateHeaders();
    while (it.next()) |h| try rw.writer().print("{s}: {s}\n", .{ h.name, h.value });
}

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

fn occurrences(hay: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var at: usize = 0;
    while (std.mem.findPos(u8, hay, at, needle)) |i| : (at = i + needle.len) n += 1;
    return n;
}

test "audit proxy: Content-Length and Via are not copied, a non-Connection header names nothing, upgrade needs an upgradable server" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var origin = Server.init(io, testing.allocator, .{ .handler = reflectAll });
    defer origin.deinit();
    origin.bind() catch |err| return testkit.loopbackSkip("origin bind failed ({t})", .{err});
    const origin_thread = try std.Thread.spawn(.{}, serveWrap, .{&origin});
    defer origin_thread.join();
    defer origin.shutdown();
    const origin_port = origin.boundAddress().getPort();

    var proxy_client = Client.init(io, testing.allocator, .{});
    defer proxy_client.deinit();
    var ph = proxy.ProxyHandler.init(.{
        .client = &proxy_client,
        .backend = .{ .host = "127.0.0.1", .port = origin_port },
    });
    var front = Server.init(io, testing.allocator, .{ .handler = proxy.ProxyHandler.handler, .context = &ph });
    defer front.deinit();
    front.bind() catch |err| return testkit.loopbackSkip("proxy bind failed ({t})", .{err});
    const front_thread = try std.Thread.spawn(.{}, serveWrap, .{&front});
    defer front_thread.join();
    defer front.shutdown();
    const front_port = front.boundAddress().getPort();

    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/x", .{front_port});

    var res = try client.request(.post, url, .{
        .body = "abc",
        .headers = &.{
            .{ .name = "Via", .value = "1.0 evil" },
            .{ .name = "X-Hint", .value = "Bar-Hdr" },
            .{ .name = "Bar-Hdr", .value = "v" },
        },
    });
    defer res.deinit();
    try testing.expectEqual(@as(u16, 200), res.status);
    const raw = try res.readAllAlloc(testing.allocator, 4096);
    defer testing.allocator.free(raw);
    const seen = try std.ascii.allocLowerString(testing.allocator, raw);
    defer testing.allocator.free(seen);

    try testing.expectEqual(@as(usize, 1), occurrences(seen, "content-length: "));
    try testing.expectEqual(@as(usize, 1), occurrences(seen, "via: "));
    try testing.expect(std.mem.find(u8, seen, "1.0 evil") != null);
    try testing.expect(std.mem.find(u8, seen, "bar-hdr: v") != null);

    // A socket-free serve: no connection control, so no upgrade is possible
    // and `Connection: Upgrade` must just be stripped.
    const opts: Server.StreamOptions = .{ .handler = proxy.ProxyHandler.handler, .context = &ph, .server_name = null };
    var rec = try httptest.record(
        testing.allocator,
        opts,
        "GET /x HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        .{},
    );
    defer rec.deinit();
    const up_res = try rec.only();
    try testing.expectEqual(@as(u16, 200), up_res.status);
    const seen_up = try std.ascii.allocLowerString(testing.allocator, up_res.body);
    defer testing.allocator.free(seen_up);
    try testing.expect(std.mem.find(u8, seen_up, "upgrade:") == null);
}

// ── h2 ──────────────────────────────────────────────────────────────────────

fn pf(t: h2.FrameType, flags: u8, sid: u31, payload: []const u8) h2.ParseError!h2.Frame {
    return h2.parseFrame(.{ .length = @intCast(payload.len), .frame_type = t, .flags = flags, .stream_id = sid }, payload);
}

test "audit h2: parseFrame length, stream-id, reserved-bit and padding rules" {
    try testing.expectError(error.FrameSizeError, pf(.priority, 0, 1, "\x00\x00\x00\x00\x00\x00"));
    try testing.expectError(error.FrameSizeError, pf(.rst_stream, 0, 1, "\x00\x00\x00\x00\x00"));
    try testing.expectError(error.FrameSizeError, pf(.ping, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x00\x00"));
    try testing.expectError(error.FrameSizeError, pf(.window_update, 0, 1, "\x00\x00\x00\x01\x00"));
    try testing.expectError(error.FrameSizeError, pf(.goaway, 0, 0, "\x00\x00\x00\x01\x00\x00\x00"));

    try testing.expectError(error.ProtocolError, pf(.push_promise, 0x04, 0, "\x00\x00\x00\x02"));
    try testing.expectError(error.ProtocolError, pf(.push_promise, 0x04, 1, "\x00\x00\x00\x00"));
    const pp = try pf(.push_promise, 0x04, 1, "\x80\x00\x00\x02");
    try testing.expectEqual(@as(u31, 2), pp.push_promise.promised_id);
    const ga = try pf(.goaway, 0, 0, "\x80\x00\x00\x05\x00\x00\x00\x00");
    try testing.expectEqual(@as(u31, 5), ga.goaway.last_stream_id);

    // pad == remaining bytes is a legal empty DATA; one more is not.
    const d0 = try pf(.data, 0x08, 1, "\x03abc");
    try testing.expectEqual(@as(usize, 0), d0.data.data.len);
    try testing.expectError(error.ProtocolError, pf(.data, 0x08, 1, "\x04abc"));
    // PRIORITY flag with fewer than 5 bytes behind the pad length.
    try testing.expectError(error.ProtocolError, pf(.headers, 0x08 | 0x20 | 0x04, 1, "\x00\x01\x02\x03"));
}

const get_block = "\x82\x86\x84";

const Sess = struct {
    c: h2.Connection,
    out: std.ArrayList(u8) = .empty,
    events: std.ArrayList(h2.Event) = .empty,

    fn init(role: h2.Role, opts: h2.Connection.Options) Sess {
        return .{ .c = .init(testing.allocator, role, opts) };
    }

    fn deinit(s: *Sess) void {
        s.clearEvents();
        s.events.deinit(testing.allocator);
        s.out.deinit(testing.allocator);
        s.c.deinit();
    }

    fn clearEvents(s: *Sess) void {
        for (s.events.items) |*ev| ev.deinit(testing.allocator);
        s.events.clearRetainingCapacity();
    }

    fn feed(s: *Sess, bytes: []const u8) !void {
        s.clearEvents();
        try s.c.recv(bytes, &s.out, &s.events);
    }

    fn frame(s: *Sess, t: h2.FrameType, flags: u8, sid: u31, payload: []const u8) !void {
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(testing.allocator);
        const hdr: h2.FrameHeader = .{ .length = @intCast(payload.len), .frame_type = t, .flags = flags, .stream_id = sid };
        try b.appendSlice(testing.allocator, &hdr.encode());
        try b.appendSlice(testing.allocator, payload);
        try s.feed(b.items);
    }

    /// Server side: preface + the peer's empty SETTINGS, then stream 1 opened
    /// by a HEADERS without END_STREAM.
    fn serverUp(s: *Sess, open_stream_1: bool) !void {
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(testing.allocator);
        try b.appendSlice(testing.allocator, h2.preface);
        const hdr: h2.FrameHeader = .{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 0 };
        try b.appendSlice(testing.allocator, &hdr.encode());
        try s.feed(b.items);
        if (open_stream_1) try s.frame(.headers, h2.Flags.end_headers, 1, get_block);
    }

    /// Client side: our preface, then the peer's SETTINGS (with `payload`).
    fn clientUp(s: *Sess, settings_payload: []const u8) !void {
        try s.c.sendPreface(&s.out);
        try s.frame(.settings, 0, 0, settings_payload);
    }
};

const ok_status = [_]u8{0x88}; // :status 200

test "audit h2: stream() knows only what existed" {
    var s = Sess.init(.server, .{});
    defer s.deinit();
    try s.serverUp(true);
    try testing.expect(s.c.stream(0) == null);
    try testing.expect(s.c.stream(2) == null); // our next id, not yet used
    try testing.expect(s.c.stream(1) != null);

    var cl = Sess.init(.client, .{});
    defer cl.deinit();
    try cl.clientUp("");
    const id = try cl.c.startStream(&cl.out, &.{.{ .name = ":method", .value = "GET" }}, false);
    try testing.expectEqual(@as(u31, 1), id);
    try testing.expect(cl.c.stream(3) == null);
}

test "audit h2: DATA for a retired stream is charged to the connection window exactly, an empty one credits nothing" {
    // Empty DATA on a stream that finished: no WINDOW_UPDATE(0, 0).
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("");
        const id = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "GET" }}, true);
        try s.frame(.headers, h2.Flags.end_headers | h2.Flags.end_stream, id, &ok_status);
        try testing.expectEqual(@as(usize, 0), s.c.streams.count());
        const before = s.out.items.len;
        try testing.expectError(error.StreamClosed, s.frame(.data, 0, id, ""));
        try testing.expectEqual(before, s.out.items.len);
    }
    // The boundary: connection window left = 16383.
    inline for (.{ .{ 16383, error.StreamClosed }, .{ 16384, error.FlowControlError } }) |case| {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        const chunk = try testing.allocator.alloc(u8, 16384);
        defer testing.allocator.free(chunk);
        @memset(chunk, 'x');
        for (0..3) |_| try s.frame(.data, 0, 1, chunk);
        try s.frame(.data, h2.Flags.end_stream, 1, "");
        try s.c.sendHeaders(&s.out, 1, &.{.{ .name = ":status", .value = "200" }}, true);
        try testing.expectEqual(@as(usize, 0), s.c.streams.count());
        try testing.expectError(case[1], s.frame(.data, 0, 1, chunk[0..case[0]]));
    }
}

test "audit h2: sendData checks the connection window as well as the stream's" {
    var s = Sess.init(.client, .{});
    defer s.deinit();
    try s.clientUp("\x00\x04\x00\x10\x00\x00"); // peer initial_window_size = 1 MiB
    const id = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "POST" }}, false);
    const big = try testing.allocator.alloc(u8, 70_000);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    try testing.expectError(error.WindowExhausted, s.c.sendData(&s.out, id, big, false));
}

test "audit h2: CONTINUATION rules" {
    // Wrong stream while assembling.
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(false);
        try s.frame(.headers, 0, 1, get_block[0..1]);
        try testing.expectError(error.ProtocolError, s.frame(.continuation, h2.Flags.end_headers, 3, get_block[1..]));
    }
    // Any other frame type while assembling, even on the same stream.
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(false);
        try s.frame(.headers, 0, 1, get_block[0..1]);
        try testing.expectError(error.ProtocolError, s.frame(.data, 0, 1, "x"));
    }
    // Frame-count cap is inclusive.
    {
        var s = Sess.init(.server, .{ .max_continuation_frames = 2 });
        defer s.deinit();
        try s.serverUp(false);
        try s.frame(.headers, 0, 1, get_block[0..1]);
        try s.frame(.continuation, 0, 1, "");
        try s.frame(.continuation, 0, 1, "");
        try testing.expectError(error.EnhanceYourCalm, s.frame(.continuation, 0, 1, ""));
    }
    // Reassembled-size cap is inclusive.
    {
        var s = Sess.init(.server, .{ .max_header_block = 4 });
        defer s.deinit();
        try s.serverUp(false);
        try s.frame(.headers, 0, 1, "\x82");
        try s.frame(.continuation, 0, 1, "\x86\x84\x82"); // 1 + 3 = 4
        try testing.expectError(error.EnhanceYourCalm, s.frame(.continuation, 0, 1, "\x82"));
    }
    // First-fragment cap is inclusive.
    {
        var s = Sess.init(.server, .{ .max_header_block = 4 });
        defer s.deinit();
        try s.serverUp(false);
        try s.frame(.headers, 0, 1, "\x82\x86\x84\x82");
    }
    {
        var s = Sess.init(.server, .{ .max_header_block = 4 });
        defer s.deinit();
        try s.serverUp(false);
        try testing.expectError(error.EnhanceYourCalm, s.frame(.headers, 0, 1, "\x82\x86\x84\x82\x82"));
    }
}

test "audit h2: the first frame, and the scope of a bad WINDOW_UPDATE" {
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.c.sendPreface(&s.out);
        try testing.expectError(error.ProtocolError, s.frame(.settings, h2.Flags.ack, 0, ""));
    }
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        try testing.expectError(error.FrameSizeError, s.frame(.window_update, 0, 1, "\x00\x00\x00\x01\x00"));
        try testing.expect(s.c.violation.?.scope == .connection);
    }
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        try testing.expectError(error.ProtocolError, s.frame(.window_update, 0, 0, "\x00\x00\x00\x00"));
        try testing.expect(s.c.violation.?.scope == .connection);
    }
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        try testing.expectError(error.ProtocolError, s.frame(.window_update, 0, 1, "\x00\x00\x00\x00"));
        try testing.expect(s.c.violation.?.scope == .stream);
    }
    {
        // A WINDOW_UPDATE for a stream that never existed.
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        try testing.expectError(error.ProtocolError, s.frame(.window_update, 0, 7, "\x00\x00\x00\x01"));
    }
}

test "audit h2: flood accounting by frame class" {
    // DATA with payload resets the counter; empty DATA+END_STREAM does not count.
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        s.c.unproductive_frames = 7;
        try s.frame(.data, 0, 1, "abc");
        try testing.expectEqual(@as(u32, 0), s.c.unproductive_frames);
        s.c.unproductive_frames = 7;
        try s.frame(.data, h2.Flags.end_stream, 1, "");
        try testing.expectEqual(@as(u32, 0), s.c.unproductive_frames);
        // More DATA on a half-closed stream: stream error, and the bytes are credited back.
        const before = s.out.items.len;
        try testing.expectError(error.StreamClosed, s.frame(.data, 0, 1, "hello"));
        try testing.expect(s.out.items.len > before);
    }
    // A trailer HEADERS is no progress.
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        s.c.unproductive_frames = 0;
        try s.frame(.headers, h2.Flags.end_headers | h2.Flags.end_stream, 1, get_block);
        try testing.expectEqual(@as(u32, 1), s.c.unproductive_frames);
    }
    // PRIORITY is no progress; a self-dependency is a stream error.
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        s.c.unproductive_frames = 0;
        try s.frame(.priority, 0, 1, "\x00\x00\x00\x03\x10");
        try testing.expectEqual(@as(u32, 1), s.c.unproductive_frames);
        try testing.expectError(error.ProtocolError, s.frame(.priority, 0, 1, "\x00\x00\x00\x01\x10"));
        try testing.expect(s.c.violation.?.scope == .stream);
    }
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(false);
        try testing.expectError(
            error.ProtocolError,
            s.frame(.headers, h2.Flags.end_headers | h2.Flags.priority, 1, "\x00\x00\x00\x01\x10" ++ get_block),
        );
    }
    // RST_STREAM retires the stream; a second one is no progress.
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        try s.frame(.rst_stream, 0, 1, "\x00\x00\x00\x08");
        try testing.expectEqual(@as(usize, 0), s.c.streams.count());
        s.c.unproductive_frames = 0;
        try s.frame(.rst_stream, 0, 1, "\x00\x00\x00\x08");
        try testing.expectEqual(@as(u32, 1), s.c.unproductive_frames);
    }
    // A stream-level WINDOW_UPDATE that replenishes nothing we sent is no progress.
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        s.c.unproductive_frames = 0;
        try s.frame(.window_update, 0, 1, "\x00\x00\x00\x01");
        try testing.expectEqual(@as(u32, 1), s.c.unproductive_frames);
    }
}

test "audit h2: a stream that closes by END_STREAM is retired, on either side" {
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        try s.c.sendHeaders(&s.out, 1, &.{.{ .name = ":status", .value = "200" }}, true);
        try s.frame(.data, h2.Flags.end_stream, 1, "");
        try testing.expectEqual(@as(usize, 0), s.c.streams.count());
    }
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("");
        const id = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "GET" }}, true);
        try s.frame(.headers, h2.Flags.end_headers | h2.Flags.end_stream, id, &ok_status);
        try testing.expectEqual(@as(usize, 0), s.c.streams.count());
    }
}

test "audit h2: the last 32 streams we reset are remembered" {
    var s = Sess.init(.client, .{});
    defer s.deinit();
    try s.clientUp("");
    const a = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "GET" }}, false);
    const b = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "GET" }}, false);
    try s.c.sendRstStream(&s.out, a, .cancel);
    try s.c.sendRstStream(&s.out, b, .cancel);
    // In flight before the peer saw the reset: ignored, not an error.
    try s.frame(.data, 0, a, "x");
    try s.frame(.data, 0, b, "x");
}

test "audit h2: who may open or push a stream" {
    // A client receiving HEADERS on a stream it never opened.
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("");
        try testing.expectError(error.ProtocolError, s.frame(.headers, h2.Flags.end_headers, 5, &ok_status));
    }
    // A server receiving PUSH_PROMISE on an open stream.
    {
        var s = Sess.init(.server, .{});
        defer s.deinit();
        try s.serverUp(true);
        try testing.expectError(error.ProtocolError, s.frame(.push_promise, h2.Flags.end_headers, 1, "\x00\x00\x00\x02" ++ get_block));
    }
    // A client that disabled push.
    {
        var s = Sess.init(.client, .{ .settings = .{ .enable_push = false } });
        defer s.deinit();
        try s.clientUp("");
        _ = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "GET" }}, false);
        try testing.expectError(error.ProtocolError, s.frame(.push_promise, h2.Flags.end_headers, 1, "\x00\x00\x00\x02" ++ get_block));
    }
    // Odd promised id.
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("");
        _ = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "GET" }}, false);
        try testing.expectError(error.ProtocolError, s.frame(.push_promise, h2.Flags.end_headers, 1, "\x00\x00\x00\x03" ++ get_block));
    }
    // A promised id that does not rise.
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("");
        _ = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "GET" }}, false);
        try s.frame(.push_promise, h2.Flags.end_headers, 1, "\x00\x00\x00\x02" ++ get_block);
        try testing.expectError(error.ProtocolError, s.frame(.push_promise, h2.Flags.end_headers, 1, "\x00\x00\x00\x02" ++ get_block));
    }
}

test "audit h2: window ceilings are inclusive; SETTINGS ranges" {
    // Connection window exactly 2^31 - 1.
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("");
        try s.frame(.window_update, 0, 0, "\x7f\xff\x00\x00");
        try testing.expectEqual(@as(i64, 0x7fffffff), s.c.conn_send_window);
    }
    // Stream window exactly 2^31 - 1, then a SETTINGS delta pushes it over.
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("");
        const id = try s.c.startStream(&s.out, &.{.{ .name = ":method", .value = "GET" }}, false);
        try s.frame(.window_update, 0, id, "\x7f\xff\x00\x00");
        try testing.expectError(error.FlowControlError, s.frame(.settings, 0, 0, "\x00\x04\x00\x01\x00\x00"));
    }
    // initial_window_size 2^31 - 1 is the largest legal value.
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("\x00\x04\x7f\xff\xff\xff");
    }
    // max_frame_size 2^24 - 1 is legal, 2^24 is not.
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("\x00\x05\x00\xff\xff\xff");
    }
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.c.sendPreface(&s.out);
        try testing.expectError(error.ProtocolError, s.frame(.settings, 0, 0, "\x00\x05\x01\x00\x00\x00"));
    }
    // A huge header_table_size from the peer never raises our encoder's table past the default.
    {
        var s = Sess.init(.client, .{});
        defer s.deinit();
        try s.clientUp("\x00\x01\x00\x10\x00\x00");
        try testing.expectEqual(hpack.default_max_table_size, s.c.hpack_enc.table.max_size);
    }
}

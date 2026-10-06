// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: Go's standard library (go1.26, BSD-3-Clause)
//! as an independent implementation of what this module does. The cases are
//! ours (`tools/go_oracle/*.go`); Go's answers to them were captured by that
//! program into `go_oracle_vectors.zig`, and the tests here replay the same
//! bytes through THIS module and compare. No Go at test time. Exempt from a
//! NOTICE entry under §0's black-box-oracle carve-out: only Go's observable
//! verdicts were recorded, no Go source was read or ported.
//!
//! Go is an oracle, not an authority. Every place we answer differently is
//! listed in a `divergences` table with the RFC rule and the judgement; a
//! case that diverges without an entry fails, and so does an entry whose case
//! has started to agree (the table can only describe the present).

const std = @import("std");
const testing = std.testing;
const Server = @import("Server.zig");
const vectors = @import("go_oracle_vectors.zig");

fn find(comptime T: type, table: []const T, id: []const u8) ?T {
    for (table) |d| if (std.mem.eql(u8, d.id, id)) return d;
    return null;
}

// ── h1: what reaches the handler, and what the server refuses itself ─────

const max_calls = 8;

const Call = struct {
    method: []const u8,
    target: []const u8,
    body: ?[]const u8,
};

/// What one wire did to the handler. Storage is per-replay; the handler is
/// a plain function, so the record lives in a file-scope variable.
const H1Run = struct {
    calls: [max_calls]Call = undefined,
    n: usize = 0,
    text: [4096]u8 = undefined,
    text_len: usize = 0,

    fn keep(r: *H1Run, s: []const u8) []const u8 {
        const dst = r.text[r.text_len..][0..s.len];
        @memcpy(dst, s);
        r.text_len += s.len;
        return dst;
    }
};

var h1_run: H1Run = .{};

/// The same handler the Go side ran: read the whole body, record the call,
/// answer 200 "ok" whether or not the body read.
fn h1Handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    var body_buf: [256]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&body_buf);
    const r = req.reader();
    const ok = while (true) {
        _ = r.stream(&sink, .unlimited) catch |err| switch (err) {
            error.EndOfStream => break true,
            else => break false,
        };
    };
    const run = &h1_run;
    if (run.n < max_calls) {
        run.calls[run.n] = .{
            .method = run.keep(req.head.method),
            .target = run.keep(req.target),
            .body = if (ok) run.keep(sink.buffered()) else null,
        };
        run.n += 1;
    }
    try rw.writeAll("ok");
}

const H1Outcome = struct { calls: []const Call, reject: u16 };

fn replayH1(wire: []const u8, out_buf: []u8) H1Outcome {
    h1_run = .{};
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    Server.serveStream(.{ .handler = h1Handler, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return .{ .calls = h1_run.calls[0..h1_run.n], .reject = firstReject(out.buffered()) };
}

/// The first status line in `resp` that is not the handler's 200. The
/// handler's body is "ok", so a status-line pattern cannot come from a body.
fn firstReject(resp: []const u8) u16 {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, resp, i, "HTTP/1.")) |at| : (i = at + 1) {
        if (at + 12 > resp.len) break;
        if (resp[at + 8] != ' ') continue;
        const code = std.fmt.parseInt(u16, resp[at + 9 .. at + 12], 10) catch continue;
        if (code != 200) return code;
    }
    return 0;
}

fn callsEqual(a: []const Call, b: []const vectors.H1Call) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x.method, y.method)) return false;
        if (!std.mem.eql(u8, x.target, y.target)) return false;
        if ((x.body == null) != (y.body == null)) return false;
        if (x.body) |xb| if (!std.mem.eql(u8, xb, y.body.?)) return false;
    }
    return true;
}

/// Agreement = the same handler calls, and both refused (any error status)
/// or neither did. The exact error code is not compared: 400 vs 501 for an
/// unsupported transfer coding is a choice, not a framing disagreement.
fn h1Agrees(ours: H1Outcome, go: vectors.H1Case) bool {
    return callsEqual(ours.calls, go.calls) and (ours.reject == 0) == (go.reject == 0);
}

/// Where we answer differently from Go's server, what we answer instead
/// (`reject`: our status, 0 = none; `calls`: handler calls), and why.
const H1Divergence = struct { id: []const u8, reject: u16, calls: usize, why: []const u8 };

const h1_divergences = [_]H1Divergence{
    // ── we are stricter, deliberately; the RFC allows it ──
    .{ .id = "lf-only-lines", .reject = 400, .calls = 0, .why = "RFC 9112 §2.2 MAY accept a bare LF; refused as a smuggling guard (A1 http F4)" },
    .{ .id = "obs-fold", .reject = 400, .calls = 0, .why = "RFC 9112 §5.2: MUST reject with 400 or replace with SP; we reject" },
    .{ .id = "te-and-cl", .reject = 400, .calls = 0, .why = "RFC 9112 §6.3: MAY reject CL + TE; Go lets TE win" },
    .{ .id = "cl-and-te", .reject = 400, .calls = 0, .why = "same as te-and-cl, fields reversed" },
    .{ .id = "chunk-smuggle-te-cl", .reject = 400, .calls = 0, .why = "same as te-and-cl: the CL.TE desync shape" },
    .{ .id = "get-asterisk", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2.4: asterisk-form is for OPTIONS only; Go dispatches GET *" },
    .{ .id = "target-high-byte", .reject = 400, .calls = 0, .why = "a raw byte >= 0x80 is not a URI (RFC 3986 §2); Go passes it to the handler" },
    .{ .id = "get-host-empty", .reject = 400, .calls = 0, .why = "h1.isValidHost refuses an empty Host on an origin-form request: an http(s) target always has an authority (RFC 9112 §3.2)" },
    .{ .id = "chunk-size-trailing-space", .reject = 0, .calls = 1, .why = "RFC 9112 §7.1: whitespace after chunk-size is only BWS before ';'; Go skips it, we fail the body" },
    // ── a different, legal choice ──
    .{ .id = "http10-keepalive-pipeline", .reject = 0, .calls = 1, .why = "HTTP/1.0 keep-alive is not honoured; a server may always close (RFC 9112 §9.3)" },
    .{ .id = "lowercase-method", .reject = 501, .calls = 0, .why = "methods are case-sensitive, so `get` is an unknown method: 501 (RFC 9110 §9.1)" },
    .{ .id = "extension-method", .reject = 501, .calls = 0, .why = "only the shared Method vocabulary is dispatched; others get 501 (RFC 9110 §9.1)" },
    .{ .id = "connect-authority", .reject = 501, .calls = 0, .why = "CONNECT is not implemented (a proxy's job): 501" },
    .{ .id = "version-1.2", .reject = 505, .calls = 0, .why = "RFC 9110 §2.5 SHOULD treat 1.2 as 1.1; no HTTP/1.2 exists, refused on purpose (pinned in h1.zig)" },
    .{ .id = "options-asterisk", .reject = 0, .calls = 1, .why = "Go answers OPTIONS * itself; here the handler decides" },
    // ── Go is the one off the RFC ──
    .{ .id = "te-chunked-http10", .reject = 400, .calls = 0, .why = "RFC 9112 §6.1: HTTP/1.0 + Transfer-Encoding MUST be faulty framing (400 + close); Go ignores TE. We used to decode chunked: fixed 2026-10-05" },
    .{ .id = "te-chunked-http10-cl", .reject = 400, .calls = 0, .why = "as te-chunked-http10, even with a Content-Length (§6.1 says so); Go frames by CL" },
};

test "go oracle h1: every wire reaches the handler as Go's server does, or the difference is judged" {
    var out_buf: [8192]u8 = undefined;
    var bad: usize = 0;
    for (vectors.h1) |c| {
        const ours = replayH1(c.wire, &out_buf);
        const agrees = h1Agrees(ours, c);
        const listed = find(H1Divergence, &h1_divergences, c.id);
        const verdict: ?[]const u8 = if (listed) |d|
            (if (agrees)
                "agrees now, drop its divergence entry"
            else if (ours.reject != d.reject or ours.calls.len != d.calls)
                "diverges, but not the way its entry says"
            else
                null)
        else if (agrees) null else "diverges";
        const v = verdict orelse continue;
        bad += 1;
        std.debug.print("h1 {s}: {s}\n  go:   reject={d} calls={d}", .{ c.id, v, c.reject, c.calls.len });
        for (c.calls) |call| std.debug.print(" [{s} {s} body={?s}]", .{ call.method, call.target, call.body });
        std.debug.print("\n  ours: reject={d} calls={d}", .{ ours.reject, ours.calls.len });
        for (ours.calls) |call| std.debug.print(" [{s} {s} body={?s}]", .{ call.method, call.target, call.body });
        std.debug.print("\n", .{});
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

// ── serve: preconditions + byte ranges, as a handler composes them ───────

const conditional = @import("conditional.zig");
const range = @import("range.zig");

/// The case being replayed and what `range.apply` resolved for it.
var serve_case: *const vectors.ServeCase = undefined;
var serve_ranges: [16]range.ResolvedRange = undefined;
var serve_n: usize = 0;

/// The composition a file server writes (and `ServeContent` does inside):
/// preconditions first, then If-Range, then the Range itself.
fn serveHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    const v: conditional.Validators = .{ .etag = serve_case.etag, .last_modified = serve_case.last_modified };
    if (try conditional.apply(req, rw, v)) return;
    if (!conditional.ifRangeAllows(req, v)) return;
    const applied = try range.apply(req, rw, vectors.serve_size, &serve_ranges);
    if (applied.outcome == .multiple) serve_n = applied.ranges.len;
}

const ServeOutcome = struct { status: u16, content_range: []const u8, parts: []const range.ResolvedRange };

fn replayServe(c: *const vectors.ServeCase, wire_buf: []u8, out_buf: []u8) !ServeOutcome {
    serve_case = c;
    serve_n = 0;
    const wire = try std.fmt.bufPrint(wire_buf, "{s} /r HTTP/1.1\r\nHost: t\r\n{s}Connection: close\r\n\r\n", .{ c.method, c.headers });
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    Server.serveStream(.{ .handler = serveHandler, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    const resp = out.buffered();
    const status = if (resp.len >= 12) std.fmt.parseInt(u16, resp[9..12], 10) catch 0 else 0;
    return .{ .status = status, .content_range = responseHeader(resp, "Content-Range") orelse "", .parts = serve_ranges[0..serve_n] };
}

fn responseHeader(resp: []const u8, name: []const u8) ?[]const u8 {
    const head_end = std.mem.indexOf(u8, resp, "\r\n\r\n") orelse resp.len;
    var lines = std.mem.splitSequence(u8, resp[0..head_end], "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

fn serveAgrees(ours: ServeOutcome, go: vectors.ServeCase) bool {
    if (ours.status != go.status) return false;
    if (!std.mem.eql(u8, ours.content_range, go.content_range)) return false;
    if (ours.parts.len != go.parts.len) return false;
    for (ours.parts, go.parts) |o, g| if (o.start != g[0] or o.end != g[1]) return false;
    return true;
}

/// Where we answer differently from `ServeContent`: our status, and why.
const ServeDivergence = struct { id: []const u8, status: u16, why: []const u8 };

const serve_divergences = [_]ServeDivergence{
    // ── Go is the one off the RFC ──
    .{ .id = "range-06", .status = 416, .why = "`-0` selects nothing: 416 (RFC 9110 §14.1.3); Go answers 206 with the impossible `bytes 100-99/100`" },
    .{ .id = "range-15", .status = 206, .why = "range units are case-insensitive (RFC 9110 §14.1); Go answers `Bytes=` with 416" },
    .{ .id = "range-16", .status = 206, .why = "as range-15, `BYTES=`" },
    .{ .id = "range-25", .status = 200, .why = "positions are 1*DIGIT (RFC 9110 §14.1.2), so `+1` makes the header invalid and it is ignored; Go's integer parse takes the sign" },
    .{ .id = "range-26", .status = 200, .why = "as range-25, `1-+9`" },
    .{ .id = "range-27", .status = 200, .why = "an unknown range unit MUST be ignored (RFC 9110 §14.2); Go answers 416" },
    .{ .id = "range-post", .status = 200, .why = "Range is defined for GET only and MUST be ignored otherwise (RFC 9110 §14.2); Go serves 206 to POST" },
    .{ .id = "range-38", .status = 416, .why = "2^64-1 is a valid position past the end: 416 with `bytes */100`; Go overflows int64 and refuses the syntax without Content-Range" },
    // ── an invalid Range: we ignore it (200), Go rejects it (416); RFC 9110 §14.2 allows both ──
    .{ .id = "range-08", .status = 200, .why = "`5-4`: last < first makes the set invalid" },
    .{ .id = "range-21", .status = 200, .why = "`-`: no digits" },
    .{ .id = "range-22", .status = 200, .why = "`--1`: not a spec" },
    .{ .id = "range-23", .status = 200, .why = "`a-b`: not digits" },
    .{ .id = "range-24", .status = 200, .why = "`0x0-9`: not digits" },
    .{ .id = "range-36", .status = 200, .why = "first-pos overflows u64" },
    .{ .id = "range-37", .status = 200, .why = "last-pos overflows u64" },
    .{ .id = "range-39", .status = 200, .why = "suffix-length overflows u64" },
    .{ .id = "range-42", .status = 200, .why = "`;x` after a spec" },
    .{ .id = "range-46", .status = 200, .why = "a second `bytes=` inside the set" },
    // ── whitespace: we take OWS around `=`, nothing inside a spec ──
    .{ .id = "range-14", .status = 206, .why = "`bytes = 0-9`: OWS around `=` is tolerated (range.zig, Validity); Go answers 416" },
    .{ .id = "range-19", .status = 200, .why = "`0 -9`: no whitespace inside a byte-range-spec, the header is ignored; Go trims it" },
    .{ .id = "range-20", .status = 200, .why = "`0- 9`: as range-19" },
    // ── a different, legal choice ──
    .{ .id = "range-30", .status = 206, .why = "`range.apply` bounds the count, not the bytes (`applyBounded` does both); Go ignores a set whose sum exceeds the representation" },
    .{ .id = "im-empty", .status = 412, .why = "an empty If-Match lists no tag, so none matches: 412 (RFC 9110 §13.1.1); Go treats it as absent" },
    .{ .id = "ims-leap-second", .status = 304, .why = "second 60 is accepted as a leap second; Go's time.Parse refuses it and ignores the header" },
    .{ .id = "ims-rfc850-yy69", .status = 304, .why = "RFC 9110 §5.6.7: a 2-digit year is the past only when it is more than 50 years ahead, so `69` is 2069 today; Go reads 1969" },
};

test "go oracle serve: preconditions and ranges answer as Go's ServeContent, or the difference is judged" {
    var wire_buf: [1024]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var bad: usize = 0;
    for (&vectors.serve) |*c| {
        const ours = try replayServe(c, &wire_buf, &out_buf);
        const agrees = serveAgrees(ours, c.*);
        const listed = find(ServeDivergence, &serve_divergences, c.id);
        const verdict: ?[]const u8 = if (listed) |d|
            (if (agrees)
                "agrees now, drop its divergence entry"
            else if (ours.status != d.status)
                "diverges, but not the way its entry says"
            else
                null)
        else if (agrees) null else "diverges";
        const v = verdict orelse continue;
        bad += 1;
        std.debug.print("serve {s} [{s}]: {s}\n  go:   {d} '{s}' parts={d}\n  ours: {d} '{s}' parts={d}\n", .{
            c.id, c.headers, v, c.status, c.content_range, c.parts.len, ours.status, ours.content_range, ours.parts.len,
        });
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

// ── url: query strings, query components, paths ─────────────────────────

const url = @import("url.zig");

const KV = [2][]const u8;

/// What `url.ParseQuery` computes, from this module's parts: every pair of
/// `QueryIterator`, both halves through `decodeComponent`; a pair that does
/// not decode is dropped and marks the query as erroneous, as Go does.
fn ourQuery(raw: []const u8, text: []u8, pairs: []KV) struct { err: bool, pairs: []KV } {
    var used: usize = 0;
    var n: usize = 0;
    var err = false;
    var it = url.QueryIterator.init(raw);
    while (it.next()) |p| {
        const k = url.decodeComponent(text[used..], p.key) catch {
            err = true;
            continue;
        };
        used += k.len;
        const v = url.decodeComponent(text[used..], p.value) catch {
            used -= k.len;
            err = true;
            continue;
        };
        used += v.len;
        pairs[n] = .{ k, v };
        n += 1;
    }
    // Go's order: keys sorted, values of one key in query order (stable).
    std.sort.insertion(KV, pairs[0..n], {}, struct {
        fn lt(_: void, a: KV, b: KV) bool {
            return std.mem.lessThan(u8, a[0], b[0]);
        }
    }.lt);
    return .{ .err = err, .pairs = pairs[0..n] };
}

/// Where we answer differently from net/url, and why. `ours_err` pins the
/// side we take.
const UrlDivergence = struct { id: []const u8, ours_err: bool, why: []const u8 };

const query_divergences = [_]UrlDivergence{
    .{ .id = "a=1;b=2", .ours_err = false, .why = "`;` is a literal byte, not a separator (WHATWG URL, and RFC 3986 gives it no meaning in a query); Go 1.17+ refuses it to stop parameter cloaking behind proxies that split on it" },
    .{ .id = ";", .ours_err = false, .why = "as `a=1;b=2`" },
    .{ .id = "a;b=1", .ours_err = false, .why = "as `a=1;b=2`" },
};
const component_divergences = [_]UrlDivergence{};
const path_divergences = [_]UrlDivergence{
    .{ .id = "/a%2Fb", .ours_err = true, .why = "a decoded `/` is refused, not decoded: `/a%2Fb` and `/a/b` must not reach the same handler (url.zig header)" },
    .{ .id = "/a%2fb", .ours_err = true, .why = "as `/a%2Fb`, lowercase hex" },
    .{ .id = "/..%2F", .ours_err = true, .why = "as `/a%2Fb`: an encoded separator after `..`" },
    .{ .id = "/a%00", .ours_err = true, .why = "a decoded NUL is refused (url.zig header); Go decodes it" },
};

fn checkUrlDivergence(
    table: []const UrlDivergence,
    area: []const u8,
    id: []const u8,
    agrees: bool,
    ours_err: bool,
) bool {
    const listed = find(UrlDivergence, table, id);
    const verdict: ?[]const u8 = if (listed) |d|
        (if (agrees)
            "agrees now, drop its divergence entry"
        else if (ours_err != d.ours_err)
            "diverges, but not the way its entry says"
        else
            null)
    else if (agrees) null else "diverges";
    const v = verdict orelse return true;
    std.debug.print("{s} \"{f}\": {s}\n", .{ area, std.zig.fmtString(id), v });
    return false;
}

test "go oracle url: query strings decode as url.ParseQuery does, or the difference is judged" {
    var bad: usize = 0;
    for (vectors.query) |c| {
        var text: [256]u8 = undefined;
        var pairs: [16]KV = undefined;
        const ours = ourQuery(c.query, &text, &pairs);
        var agrees = ours.err == c.err and ours.pairs.len == c.pairs.len;
        if (agrees) for (ours.pairs, c.pairs) |o, g| {
            if (!std.mem.eql(u8, o[0], g[0]) or !std.mem.eql(u8, o[1], g[1])) agrees = false;
        };
        if (!checkUrlDivergence(&query_divergences, "query", c.query, agrees, ours.err)) {
            bad += 1;
            std.debug.print("  go:   err={} pairs={d}", .{ c.err, c.pairs.len });
            for (c.pairs) |p| std.debug.print(" [{s}={s}]", .{ p[0], p[1] });
            std.debug.print("\n  ours: err={} pairs={d}", .{ ours.err, ours.pairs.len });
            for (ours.pairs) |p| std.debug.print(" [{s}={s}]", .{ p[0], p[1] });
            std.debug.print("\n", .{});
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

fn checkUnescape(
    comptime area: []const u8,
    cases: []const vectors.UnescapeCase,
    table: []const UrlDivergence,
    decode: fn ([]u8, []const u8) url.DecodeError![]const u8,
) !void {
    var bad: usize = 0;
    for (cases) |c| {
        var buf: [256]u8 = undefined;
        const ours: ?[]const u8 = decode(&buf, c.input) catch null;
        const agrees = if (ours) |o| (c.out != null and std.mem.eql(u8, o, c.out.?)) else c.out == null;
        if (!checkUrlDivergence(table, area, c.input, agrees, ours == null)) {
            bad += 1;
            std.debug.print("  go:   {f}\n  ours: {f}\n", .{
                std.zig.fmtString(c.out orelse "<error>"), std.zig.fmtString(ours orelse "<error>"),
            });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "go oracle url: query components unescape as url.QueryUnescape does, or the difference is judged" {
    try checkUnescape("component", &vectors.component, &component_divergences, url.decodeComponent);
}

test "go oracle url: paths unescape as url.PathUnescape does, or the difference is judged" {
    try checkUnescape("path", &vectors.path, &path_divergences, url.decodePath);
}

// ── multipart: form-data bodies ──────────────────────────────────────────

const multipart = @import("multipart.zig");

fn optEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

const MultipartOutcome = struct { parts: [8]multipart.Part = undefined, n: usize = 0, err: bool = false };

fn ourMultipart(body: []const u8) MultipartOutcome {
    var o: MultipartOutcome = .{};
    var it = multipart.parse(body, vectors.multipart_boundary, .{});
    while (true) {
        const part = it.next() catch {
            o.err = true;
            return o;
        } orelse return o;
        if (o.n == o.parts.len) return o;
        o.parts[o.n] = part;
        o.n += 1;
    }
}

/// Parts agree when name, filename, content type and body are equal. A Go
/// part whose body failed to read (`value == null`) is the error that ended
/// the stream, so ours has to end in an error there too.
fn multipartAgrees(ours: *const MultipartOutcome, go: vectors.MultipartCase) bool {
    var go_parts = go.parts;
    var go_err = go.err;
    if (go_parts.len > 0 and go_parts[go_parts.len - 1].value == null) {
        go_parts = go_parts[0 .. go_parts.len - 1];
        go_err = true;
    }
    if (ours.err != go_err or ours.n != go_parts.len) return false;
    for (ours.parts[0..ours.n], go_parts) |o, g| {
        if (!optEql(o.name, g.name) or !optEql(o.filename, g.filename)) return false;
        if (!optEql(o.content_type, g.content_type) or !optEql(o.value, g.value)) return false;
    }
    return true;
}

const MultipartDivergence = struct { id: []const u8, ours_err: bool, ours_parts: usize, why: []const u8 };

const multipart_divergences = [_]MultipartDivergence{
    // ── we refuse what Go reads somehow; a cut or ambiguous upload must not look whole ──
    .{ .id = "truncated-in-headers", .ours_err = true, .ours_parts = 0, .why = "a header block with no blank line is refused; Go reports a clean end with no parts" },
    .{ .id = "lf-only", .ours_err = true, .ours_parts = 0, .why = "RFC 2046 §5.1.1 delimiters are CRLF-framed; Go takes a bare LF too" },
    .{ .id = "delim-then-junk", .ours_err = true, .ours_parts = 1, .why = "`--XyZjunk` at a line start is neither a delimiter nor legal body (the boundary must not occur inside a part, RFC 2046 §5.1.1); Go keeps it as body text" },
    .{ .id = "first-delim-junk", .ours_err = true, .ours_parts = 0, .why = "as delim-then-junk, on the opening delimiter" },
    .{ .id = "boundary-prefix-in-body", .ours_err = true, .ours_parts = 1, .why = "as delim-then-junk: `--XyZz`" },
    .{ .id = "boundary-dash-in-body", .ours_err = true, .ours_parts = 1, .why = "as delim-then-junk: `--XyZ-y`" },
    .{ .id = "header-folded", .ours_err = true, .ours_parts = 0, .why = "a folded part header is refused (until 2026-10-05 it silently lost `name`); Go unfolds it" },
    .{ .id = "header-space-before-colon", .ours_err = true, .ours_parts = 0, .why = "a header name with whitespace before the colon is not a token: refused; Go keeps the part without its disposition" },
    // ── a different, legal choice ──
    .{ .id = "closing-junk", .ours_err = false, .ours_parts = 1, .why = "whatever follows the closing delimiter is epilogue and ignored; Go wants a CRLF first" },
    .{ .id = "name-escaped-quote", .ours_err = false, .ours_parts = 1, .why = "a quoted parameter comes back zero-copy with its quoted-pairs NOT unescaped (body.ContentType.param); Go unescapes. Browsers percent-encode `\"` in names (WHATWG), so they never send this" },
    .{ .id = "name-escaped-backslash", .ours_err = false, .ours_parts = 1, .why = "as name-escaped-quote" },
    .{ .id = "name-duplicate-param", .ours_err = false, .ours_parts = 1, .why = "the first `name` wins; Go's ParseMediaType refuses a duplicate parameter and drops the whole disposition" },
    .{ .id = "filename-star", .ours_err = false, .ours_parts = 1, .why = "RFC 7578 §4.2: `filename*` MUST NOT be used; it is ignored here, Go decodes it" },
    .{ .id = "filename-and-star", .ours_err = false, .ours_parts = 1, .why = "as filename-star: `filename` is the one that counts" },
};

test "go oracle multipart: bodies split into the parts mime/multipart finds, or the difference is judged" {
    var bad: usize = 0;
    for (vectors.multipart) |c| {
        const ours = ourMultipart(c.body);
        const agrees = multipartAgrees(&ours, c);
        const listed = find(MultipartDivergence, &multipart_divergences, c.id);
        const verdict: ?[]const u8 = if (listed) |d|
            (if (agrees)
                "agrees now, drop its divergence entry"
            else if (ours.err != d.ours_err or ours.n != d.ours_parts)
                "diverges, but not the way its entry says"
            else
                null)
        else if (agrees) null else "diverges";
        const v = verdict orelse continue;
        bad += 1;
        std.debug.print("multipart {s}: {s}\n  go:   err={} parts={d}", .{ c.id, v, c.err, c.parts.len });
        for (c.parts) |p| std.debug.print(" [name={f} file={f} ct={f} value={f}]", .{
            std.zig.fmtString(p.name orelse "<null>"),         std.zig.fmtString(p.filename orelse "<null>"),
            std.zig.fmtString(p.content_type orelse "<null>"), std.zig.fmtString(p.value orelse "<error>"),
        });
        std.debug.print("\n  ours: err={} parts={d}", .{ ours.err, ours.n });
        for (ours.parts[0..ours.n]) |p| std.debug.print(" [name={f} file={f} ct={f} value={f}]", .{
            std.zig.fmtString(p.name orelse "<null>"),         std.zig.fmtString(p.filename orelse "<null>"),
            std.zig.fmtString(p.content_type orelse "<null>"), std.zig.fmtString(p.value),
        });
        std.debug.print("\n", .{});
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

// ── client: how a response is framed ─────────────────────────────────────

const Client = @import("Client.zig");
const testkit = @import("testkit");
const net = std.Io.net;

/// Answers exactly one connection: reads the request head, writes
/// `response`, closes.
const OneShotPeer = struct {
    io: std.Io,
    listener: *net.Server,
    response: []const u8,

    fn run(p: *OneShotPeer) void {
        const s = p.listener.accept(p.io) catch return;
        defer s.close(p.io);
        var rbuf: [1024]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        while (true) {
            const line = sr.interface.takeDelimiterInclusive('\n') catch return;
            if (std.mem.eql(u8, line, "\r\n")) break;
        }
        var wbuf: [256]u8 = undefined;
        var sw = s.writer(p.io, &wbuf);
        sw.interface.writeAll(p.response) catch return;
        sw.interface.flush() catch return;
    }
};

const ClientOutcome = struct { status: u16, body: ?[]u8 };

fn ourClient(io: std.Io, gpa: std.mem.Allocator, c: vectors.ClientCase) !ClientOutcome {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("go oracle client: listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    var peer: OneShotPeer = .{ .io = io, .listener = &listener, .response = c.response };
    const thread = try std.Thread.spawn(.{}, OneShotPeer.run, .{&peer});
    defer thread.join();

    var client = Client.init(io, gpa, .{ .pool = .{ .enabled = false } });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url_text = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{listener.socket.address.getPort()});
    const method: http_root.Method = if (std.mem.eql(u8, c.method, "HEAD")) .head else .get;
    var res = client.requestPlain(method, url_text, .{ .follow_redirects = false }) catch
        return .{ .status = 0, .body = null };
    defer res.deinit();
    const body = res.readAllAlloc(gpa, 4096) catch null;
    return .{ .status = res.status, .body = body };
}

const http_root = @import("root.zig");

/// Where our client reads a response differently from Go's Transport: what
/// we return (status 0 = the request failed; `body_ok` = the body read
/// cleanly), and why.
const ClientDivergence = struct { id: []const u8, status: u16, body_ok: bool, why: []const u8 };

const client_divergences = [_]ClientDivergence{
    // ── Go is the one off the RFC ──
    .{ .id = "te-http10-chunked", .status = 0, .body_ok = false, .why = "RFC 9112 §6.1: an HTTP/1.0 message with Transfer-Encoding has faulty framing, which a user agent discards (§6.3); Go hands over the raw chunked bytes as the body. We used to decode it as chunked: fixed 2026-10-05" },
    .{ .id = "version-2.0", .status = 0, .body_ok = false, .why = "`HTTP/2.0` is not an HTTP/1.x status line; Go's Transport reads it as one" },
    // ── we are stricter, deliberately (as the server side is) ──
    .{ .id = "version-1.2", .status = 0, .body_ok = false, .why = "RFC 9110 §2.5 SHOULD treat 1.2 as 1.1; no HTTP/1.2 exists, refused on purpose (pinned in h1.zig)" },
    .{ .id = "double-space", .status = 0, .body_ok = false, .why = "status-line = HTTP-version SP status-code SP reason (RFC 9112 §4): one SP; Go skips extra spaces" },
    .{ .id = "lf-only-head", .status = 0, .body_ok = false, .why = "RFC 9112 §2.2 MAY accept a bare LF; refused on both sides as a framing-desync guard (h1.readHead)" },
    .{ .id = "space-before-colon", .status = 0, .body_ok = false, .why = "whitespace between a field name and the colon is invalid (RFC 9112 §5.1); Go keeps the field" },
    .{ .id = "space-before-colon-cl", .status = 0, .body_ok = false, .why = "as space-before-colon, on Content-Length: a recipient that strips the space frames by it, one that does not reads until close" },
};

test "go oracle client: responses frame as Go's Transport frames them, or the difference is judged" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bad: usize = 0;
    for (vectors.client) |c| {
        const ours = try ourClient(io, gpa, c);
        defer if (ours.body) |b| gpa.free(b);
        const agrees = ours.status == c.status and optEql(ours.body, c.body);
        const listed = find(ClientDivergence, &client_divergences, c.id);
        const verdict: ?[]const u8 = if (listed) |d|
            (if (agrees)
                "agrees now, drop its divergence entry"
            else if (ours.status != d.status or (ours.body != null) != d.body_ok)
                "diverges, but not the way its entry says"
            else
                null)
        else if (agrees) null else "diverges";
        const v = verdict orelse continue;
        bad += 1;
        std.debug.print("client {s}: {s}\n  go:   {d} {f}\n  ours: {d} {f}\n", .{
            c.id,        v,
            c.status,    std.zig.fmtString(c.body orelse "<error>"),
            ours.status, std.zig.fmtString(ours.body orelse "<error>"),
        });
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

// ── proxy: which proxy a URL goes through ────────────────────────────────

const client_proxy = @import("client_proxy.zig");

/// Our answer in the generator's notation: `direct`, `error`, or
/// `proxy http <host> <port> <user|-> <password|->` (decoded credentials).
fn ourProxy(c: vectors.ProxyCase, buf: []u8) ![]const u8 {
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    for (c.env) |line| {
        const eq = std.mem.indexOfScalar(u8, line, '=').?;
        try env.put(line[0..eq], line[eq + 1 ..]);
    }
    const target = try http_root.Url.parse(c.target);
    const ep = client_proxy.Proxy.fromEnviron(&env).forUrl(target) catch return "error";
    const e = ep orelse return "direct";
    var user: []const u8 = "-";
    var pass: []const u8 = "-";
    var cred: [1024]u8 = undefined;
    if (e.userinfo) |ui| {
        const colon = std.mem.indexOfScalar(u8, ui, ':');
        user = try percentDecode(ui[0 .. colon orelse ui.len], cred[0..512]);
        if (colon) |at| pass = try percentDecode(ui[at + 1 ..], cred[512..]);
    }
    return std.fmt.bufPrint(buf, "proxy http {s} {d} {s} {s}", .{ e.host, e.port, user, pass });
}

fn percentDecode(in: []const u8, out: []u8) ![]const u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < in.len) : (o += 1) {
        if (in[i] == '%') {
            out[o] = try std.fmt.parseInt(u8, in[i + 1 .. i + 3], 16);
            i += 3;
        } else {
            out[o] = in[i];
            i += 1;
        }
    }
    return out[0..o];
}

/// Where our proxy choice differs from Go's: what we answer, and why.
const ProxyDivergence = struct { id: []const u8, ours: []const u8, why: []const u8 };

const proxy_divergences = [_]ProxyDivergence{
    .{ .id = "proxy-https-scheme", .ours = "error", .why = "only http:// proxies are supported (TLS to the proxy is not); BadProxy rather than a silent direct connection" },
    .{ .id = "proxy-socks5", .ours = "error", .why = "SOCKS is not supported; BadProxy as for https://" },
    .{ .id = "proxy-bad-port", .ours = "error", .why = "a port over 65535 is refused when the setting is read; Go accepts the text and fails at the dial" },
    .{ .id = "proxy-space", .ours = "error", .why = "a proxy setting that does not parse is BadProxy; Go ignores it and connects DIRECTLY -- the request the operator meant to route through a proxy leaks past it" },
};

test "go oracle proxy: the proxy a URL goes through is Go's ProxyFromEnvironment choice, or the difference is judged" {
    var bad: usize = 0;
    for (vectors.proxy) |c| {
        var buf: [256]u8 = undefined;
        const ours = try ourProxy(c, &buf);
        const agrees = std.mem.eql(u8, ours, c.go);
        const listed = find(ProxyDivergence, &proxy_divergences, c.id);
        const verdict: ?[]const u8 = if (listed) |d|
            (if (agrees)
                "agrees now, drop its divergence entry"
            else if (!std.mem.eql(u8, ours, d.ours))
                "diverges, but not the way its entry says"
            else
                null)
        else if (agrees) null else "diverges";
        const v = verdict orelse continue;
        bad += 1;
        std.debug.print("proxy {s}: {s}\n  go:   {s}\n  ours: {s}\n", .{ c.id, v, c.go, ours });
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

// ── rproxy: what a reverse proxy passes on, both ways ────────────────────

const proxy_mod = @import("proxy.zig");

/// A raw backend: answers `n` connections one at a time, each by recording
/// the request head and body it received and writing `response` (read from
/// `current` when the connection arrives).
const RawBackend = struct {
    io: std.Io,
    listener: *net.Server,
    n: usize,
    current: *const vectors.RProxyCase,
    head: [4096]u8 = undefined,
    head_len: usize = 0,
    body: [256]u8 = undefined,
    body_len: usize = 0,

    fn run(b: *RawBackend) void {
        for (0..b.n) |_| b.one() catch {};
    }

    fn one(b: *RawBackend) !void {
        const s = try b.listener.accept(b.io);
        defer s.close(b.io);
        var rbuf: [4096]u8 = undefined;
        var sr = s.reader(b.io, &rbuf);
        const msg = try readMessage(&sr.interface, &b.head, &b.body);
        b.head_len = msg.head;
        b.body_len = msg.body;
        var wbuf: [512]u8 = undefined;
        var sw = s.writer(b.io, &wbuf);
        try sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n");
        try sw.interface.writeAll(b.current.resp_extra);
        try sw.interface.writeAll("\r\nok");
        try sw.interface.flush();
    }
};

/// Read one HTTP/1.1 message: the head into `head`, the body (by
/// Content-Length, or chunked and decoded) into `body`.
fn readMessage(r: *std.Io.Reader, head: []u8, body_out: []u8) !struct { head: usize, body: usize } {
    var hl: usize = 0;
    while (true) {
        const line = try r.takeDelimiterInclusive('\n');
        @memcpy(head[hl..][0..line.len], line);
        hl += line.len;
        if (std.mem.eql(u8, line, "\r\n")) break;
    }
    const h = head[0..hl];
    var bl: usize = 0;
    if (headerValue(h, "content-length")) |v| {
        const n = try std.fmt.parseInt(usize, v, 10);
        try r.readSliceAll(body_out[0..n]);
        bl = n;
    } else if (headerValue(h, "transfer-encoding")) |v| if (std.ascii.eqlIgnoreCase(v, "chunked")) {
        while (true) {
            const size_line = try r.takeDelimiterInclusive('\n');
            const size_text = std.mem.trim(u8, size_line[0 .. std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len], " \t\r\n");
            const n = try std.fmt.parseInt(usize, size_text, 16);
            if (n == 0) {
                while (!std.mem.eql(u8, try r.takeDelimiterInclusive('\n'), "\r\n")) {}
                break;
            }
            try r.readSliceAll(body_out[bl..][0..n]);
            bl += n;
            _ = try r.takeDelimiterInclusive('\n');
        }
    };
    return .{ .head = hl, .body = bl };
}

fn headerValue(head: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, head, "\r\n");
    _ = it.next();
    while (it.next()) |l| {
        const colon = std.mem.indexOfScalar(u8, l, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(l[0..colon], name)) return std.mem.trim(u8, l[colon + 1 ..], " \t");
    }
    return null;
}

const up_ignore = [_][]const u8{ "connection", "content-length", "transfer-encoding", "via", "x-forwarded-proto", "x-forwarded-host", "user-agent" };
const down_ignore = [_][]const u8{ "connection", "content-length", "transfer-encoding", "via", "date", "server" };

/// The generator's normalisation: field names lower-cased, values trimmed,
/// `ignore`d names dropped, lines stably sorted by name. Returns the first
/// line; the field lines go to `out`.
fn normHead(head: []const u8, ignore: []const []const u8, text: []u8, out: [][]const u8) !struct { first: []const u8, lines: [][]const u8 } {
    var it = std.mem.splitSequence(u8, std.mem.trimEnd(u8, head, "\r\n"), "\r\n");
    const first = it.next().?;
    var n: usize = 0;
    var used: usize = 0;
    lines: while (it.next()) |l| {
        const colon = std.mem.indexOfScalar(u8, l, ':') orelse continue;
        for (ignore) |ig| if (std.ascii.eqlIgnoreCase(l[0..colon], ig)) continue :lines;
        var w: std.Io.Writer = .fixed(text[used..]);
        try w.print("{s}: {s}", .{ l[0..colon], std.mem.trim(u8, l[colon + 1 ..], " \t") });
        const s = text[used..][0..w.buffered().len];
        for (s[0..colon]) |*ch| ch.* = std.ascii.toLower(ch.*);
        used += s.len;
        out[n] = s;
        n += 1;
    }
    const byName = struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            const an = a[0..std.mem.indexOfScalar(u8, a, ':').?];
            const bn = b[0..std.mem.indexOfScalar(u8, b, ':').?];
            return std.mem.order(u8, an, bn) == .lt;
        }
    };
    std.sort.insertion([]const u8, out[0..n], {}, byName.lt);
    return .{ .first = first, .lines = out[0..n] };
}

fn sameLines(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

/// Where our proxy passes on something different from Go's ReverseProxy, and
/// why. `side` is which record differs ("up" = what the backend received,
/// "down" = what the client received).
const RProxyDivergence = struct { id: []const u8, side: []const u8, why: []const u8 };

const rproxy_divergences = [_]RProxyDivergence{
    .{ .id = "conn-lists-te", .side = "up", .why = "TE is hop-by-hop (RFC 9110 §7.6.1); Go re-sends `TE: trailers` upstream, which promises the backend a trailer section reaches the client -- this proxy relays none (h1 streams the body only, h2 does not surface trailers), so it does not make the promise" },
    .{ .id = "te-trailers", .side = "up", .why = "TE is hop-by-hop (RFC 9110 §7.6.1); Go re-sends `TE: trailers` upstream, which promises the backend a trailer section reaches the client -- this proxy relays none (h1 streams the body only, h2 does not surface trailers), so it does not make the promise" },
    .{ .id = "te-gzip-trailers", .side = "up", .why = "TE is hop-by-hop (RFC 9110 §7.6.1); Go re-sends `TE: trailers` upstream, which promises the backend a trailer section reaches the client -- this proxy relays none (h1 streams the body only, h2 does not surface trailers), so it does not make the promise" },
    .{ .id = "proxy-other", .side = "up", .why = "every `Proxy-*` field is dropped (module doc): a proxy credential under any name never leaks to the origin; Go drops only Proxy-Authorization/-Authenticate/-Connection" },
    .{ .id = "resp-proxy-other", .side = "down", .why = "as proxy-other, on the response" },
};

test "go oracle rproxy: the proxy passes on what Go's ReverseProxy passes on, or the difference is judged" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("go oracle rproxy: listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    var current: *const vectors.RProxyCase = &vectors.rproxy[0];
    var backend: RawBackend = .{ .io = io, .listener = &listener, .n = vectors.rproxy.len, .current = current };
    const backend_thread = try std.Thread.spawn(.{}, RawBackend.run, .{&backend});
    defer backend_thread.join();

    var proxy_client = Client.init(io, gpa, .{ .pool = .{ .enabled = false } });
    defer proxy_client.deinit();
    var ph = proxy_mod.ProxyHandler.init(.{
        .client = &proxy_client,
        .backend = .{ .host = "127.0.0.1", .port = listener.socket.address.getPort() },
        .rewrite_host = false,
    });
    var front = Server.init(io, gpa, .{ .handler = proxy_mod.ProxyHandler.handler, .context = &ph });
    defer front.deinit();
    front.bind() catch |err| return testkit.loopbackSkip("go oracle rproxy: bind failed ({t})", .{err});
    const front_thread = try std.Thread.spawn(.{}, rproxyServe, .{&front});
    defer front_thread.join();
    defer front.shutdown();
    const front_addr = try net.IpAddress.parse("127.0.0.1", front.boundAddress().getPort());

    var bad: usize = 0;
    for (&vectors.rproxy) |*c| {
        current = c;
        backend.current = c;
        backend.head_len = 0;
        backend.body_len = 0;
        const s = try front_addr.connect(io, .{ .mode = .stream });
        var wbuf: [1024]u8 = undefined;
        var sw = s.writer(io, &wbuf);
        try sw.interface.writeAll(c.wire);
        try sw.interface.flush();
        var rbuf: [4096]u8 = undefined;
        var sr = s.reader(io, &rbuf);
        var down_head: [4096]u8 = undefined;
        var down_body: [256]u8 = undefined;
        const msg = readMessage(&sr.interface, &down_head, &down_body) catch {
            s.close(io);
            std.debug.print("rproxy {s}: no response from our proxy\n", .{c.id});
            bad += 1;
            continue;
        };
        s.close(io);

        var t1: [4096]u8 = undefined;
        var l1: [64][]const u8 = undefined;
        const up = try normHead(backend.head[0..backend.head_len], &up_ignore, &t1, &l1);
        var t2: [4096]u8 = undefined;
        var l2: [64][]const u8 = undefined;
        const down = try normHead(down_head[0..msg.head], &down_ignore, &t2, &l2);
        const up_line = if (std.mem.lastIndexOf(u8, up.first, " HTTP/")) |i| up.first[0..i] else up.first;
        const status = std.fmt.parseInt(u16, down.first[9..12], 10) catch 0;

        const up_ok = std.mem.eql(u8, up_line, c.up_line) and sameLines(up.lines, c.up) and
            std.mem.eql(u8, backend.body[0..backend.body_len], c.up_body);
        const down_ok = status == c.status and sameLines(down.lines, c.down);
        for ([_]struct { side: []const u8, ok: bool }{ .{ .side = "up", .ok = up_ok }, .{ .side = "down", .ok = down_ok } }) |r| {
            var listed = false;
            for (rproxy_divergences) |d| {
                if (std.mem.eql(u8, d.id, c.id) and std.mem.eql(u8, d.side, r.side)) listed = true;
            }
            if (r.ok == !listed) continue;
            bad += 1;
            std.debug.print("rproxy {s} ({s}): {s}\n", .{ c.id, r.side, if (r.ok) "agrees now, drop its divergence entry" else "diverges" });
            if (!r.ok) {
                const go_lines, const our_lines = if (std.mem.eql(u8, r.side, "up")) .{ c.up, up.lines } else .{ c.down, down.lines };
                std.debug.print("  go:  ", .{});
                for (go_lines) |l| std.debug.print(" [{s}]", .{l});
                std.debug.print("\n  ours:", .{});
                for (our_lines) |l| std.debug.print(" [{s}]", .{l});
                std.debug.print("\n", .{});
            }
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

fn rproxyServe(s: *Server) void {
    s.serve() catch {};
}

// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: hyper 1.11 (Rust's HTTP/1.1 server connection)
//! and llhttp 9.4 (the parser of Node.js and uvicorn, through `httptools`) as
//! independent implementations of the request framing `Server` does. The wires
//! are the Go oracle's plus smuggling-shaped ones (`tools/h1parsers.zig`); the
//! two parsers' verdicts were captured by that program into
//! `h1_parsers_vectors.zig`, and the test here replays the same bytes through
//! THIS module's server and compares. No Rust and no Python at test time.
//! Exempt from a NOTICE entry under §0's black-box-oracle carve-out: only the
//! observable verdicts were recorded, no source was read or ported.
//!
//! Neither is an authority. A case on which we answer differently is listed in
//! a divergence table with the RFC 9112 rule and the judgement (spec-MANDATORY
//! first, then what the majority does); a case that diverges without an entry
//! fails, and so does an entry whose case has started to agree.
//!
//! llhttp is a parser: it has no handler, no Host rule and no limits of its
//! own, so its rows differ from a server's wherever the rule is a server's
//! (RFC 9112 §3.2 Host, §3 head size). Those are listed too, once, with the
//! reason, rather than hidden.

const std = @import("std");
const testing = std.testing;
const go_oracle = @import("go_oracle.zig");
const vectors = @import("h1_parsers_vectors.zig");

fn callsEqual(a: []const go_oracle.Call, b: []const vectors.Call) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!std.mem.eql(u8, x.method, y.method)) return false;
        if (!std.mem.eql(u8, x.target, y.target)) return false;
        if ((x.body == null) != (y.body == null)) return false;
        if (x.body) |xb| if (!std.mem.eql(u8, xb, y.body.?)) return false;
    }
    return true;
}

/// Agreement = the same handler calls, and both refused (any status) or
/// neither did.
fn agrees(ours: go_oracle.H1Outcome, v: vectors.Verdict) bool {
    return callsEqual(ours.calls, v.calls) and (ours.reject == 0) == (v.reject == 0);
}

/// Where we answer differently from a parser, what we answer instead
/// (`reject`: our status, 0 = none; `calls`: handler calls), and why.
const Divergence = struct { id: []const u8, reject: u16, calls: usize, why: []const u8 };

const hyper_divergences = [_]Divergence{
    .{ .id = "get-no-host-1.1", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2: a server MUST answer an HTTP/1.1 request that lacks Host, has several or an invalid one with 400; hyper leaves Host to the application" },
    .{ .id = "get-two-host", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2: a server MUST answer an HTTP/1.1 request that lacks Host, has several or an invalid one with 400; hyper leaves Host to the application" },
    .{ .id = "get-host-empty", .reject = 400, .calls = 0, .why = "an http(s) target always has an authority, so an empty Host on an origin-form request is invalid (RFC 9112 §3.2); a parser or a hyper app does not check" },
    .{ .id = "get-host-bad-char", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2: a server MUST answer an HTTP/1.1 request that lacks Host, has several or an invalid one with 400; hyper leaves Host to the application" },
    .{ .id = "get-host-userinfo", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2: a server MUST answer an HTTP/1.1 request that lacks Host, has several or an invalid one with 400; hyper leaves Host to the application" },
    .{ .id = "lf-only-lines", .reject = 400, .calls = 0, .why = "RFC 9112 §2.2 MAY accept a bare LF; refused as a smuggling guard (A1 http F4); llhttp refuses it too, hyper and Go accept" },
    .{ .id = "get-asterisk", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2.4: asterisk-form is for OPTIONS only; hyper and llhttp pass any method on" },
    .{ .id = "connect-asterisk", .reject = 400, .calls = 0, .why = "as get-asterisk: a CONNECT names an authority, never *" },
    .{ .id = "connect-authority-userinfo", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2.3: no userinfo in authority-form" },
    .{ .id = "connect-then-get", .reject = 0, .calls = 2, .why = "after a CONNECT the connection is a tunnel: the bytes behind it are not a second request (RFC 9112 §9.3.6); a parser's upgrade stop and hyper's connection both go on to read them as one" },
    .{ .id = "get-authority-form", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2.3: authority-form is for CONNECT only" },
    .{ .id = "extension-asterisk", .reject = 400, .calls = 0, .why = "as get-asterisk, for an extension method" },
    .{ .id = "target-no-slash", .reject = 400, .calls = 0, .why = "`a` is neither origin-, absolute-, authority- nor asterisk-form (RFC 9112 §3.2); hyper takes it as an authority" },
    .{ .id = "target-with-fragment", .reject = 0, .calls = 1, .why = "a fragment is no part of a request-target (RFC 9112 §3.2); hyper's URI type cuts it off, Go, llhttp and this module pass it on in the target" },
    .{ .id = "target-high-byte", .reject = 400, .calls = 0, .why = "a raw byte >= 0x80 is not a URI (RFC 3986 §2); hyper and Go pass it to the handler" },
    .{ .id = "te-chunked-twice-list", .reject = 400, .calls = 0, .why = "RFC 9112 §6.1: chunked MUST NOT be applied more than once; hyper decodes it" },
    .{ .id = "te-chunked-two-fields", .reject = 400, .calls = 0, .why = "as te-chunked-twice-list, in two fields" },
    .{ .id = "te-gzip-chunked", .reject = 400, .calls = 0, .why = "RFC 9112 §6.1: a coding this server does not implement is 501 (it cannot undo gzip); hyper hands the still-gzipped body over as the content" },
    .{ .id = "te-two-fields-gzip-chunked", .reject = 400, .calls = 0, .why = "as te-gzip-chunked, in two fields" },
    .{ .id = "te-two-fields-empty-chunked", .reject = 400, .calls = 0, .why = "RFC 9110 §5.6.1.2: a recipient MUST parse and ignore a reasonable number of empty list elements, so an empty Transfer-Encoding line before `chunked` is a legal list; this module takes only the sole token `chunked` (TE.TE smuggling guard, `RequestHead.parse`) and refuses it -- a deliberate departure; hyper accepts, Go and llhttp refuse" },
    .{ .id = "te-and-cl", .reject = 400, .calls = 0, .why = "RFC 9112 §6.3: a server MAY reject a request with both Content-Length and Transfer-Encoding; refused as the CL.TE smuggling guard; hyper lets Transfer-Encoding win, llhttp refuses" },
    .{ .id = "cl-and-te", .reject = 400, .calls = 0, .why = "same as te-and-cl, fields reversed" },
    .{ .id = "chunk-size-trailing-space", .reject = 0, .calls = 1, .why = "RFC 9112 §7.1.1: BWS belongs before a ';' of an extension, not after the size alone; hyper and Go skip it, this module fails the body" },
    .{ .id = "chunk-smuggle-te-cl", .reject = 400, .calls = 0, .why = "same as te-and-cl: the CL.TE desync shape" },
    .{ .id = "te-lowercase-names-cl", .reject = 400, .calls = 0, .why = "same as te-and-cl (field names are case-insensitive)" },
    .{ .id = "te-chunked-cl-zero", .reject = 400, .calls = 0, .why = "same as te-and-cl, with Content-Length: 0" },
    .{ .id = "te-identity-then-chunked", .reject = 400, .calls = 0, .why = "`identity` is not a transfer coding any more (RFC 9112 §12.2); this server does not know it: 501/400 (§6.1); hyper and Go accept it, llhttp refuses" },
    .{ .id = "te-cl-hidden-request", .reject = 400, .calls = 0, .why = "same as te-and-cl, the request hidden in the body is the point of the shape" },
    .{ .id = "cl-te-hidden-request", .reject = 400, .calls = 0, .why = "same as te-and-cl, Content-Length first" },
    .{ .id = "lf-after-request-line-only", .reject = 400, .calls = 0, .why = "as lf-only-lines, on the request line" },
    .{ .id = "lf-after-host-only", .reject = 400, .calls = 0, .why = "as lf-only-lines, on one field line" },
    .{ .id = "lf-ends-head", .reject = 400, .calls = 0, .why = "as lf-only-lines, on the blank line that ends the head" },
    .{ .id = "chunk-ext-no-name", .reject = 0, .calls = 1, .why = "RFC 9112 §7.1.1: chunk-ext-name is a token (1*tchar); `5;` has none; hyper accepts it, llhttp refuses" },
    .{ .id = "header-value-20k", .reject = 431, .calls = 0, .why = "limit policy: a head over `max_header_bytes` (16 KiB default) is 431 (RFC 9112 §3 leaves the limit to the server); hyper's is 400 KiB, llhttp has none" },
    .{ .id = "header-name-20k", .reject = 431, .calls = 0, .why = "as header-value-20k" },
    .{ .id = "target-20k", .reject = 431, .calls = 0, .why = "as header-value-20k (a request line over `max_request_line_bytes` is 414, past the head budget 431)" },
    .{ .id = "target-9k", .reject = 414, .calls = 0, .why = "RFC 9112 §3 asks for request lines of at least 8000 octets; `max_request_line_bytes` is 8 KiB by default (414 above it); hyper and llhttp have no such bound" },
    .{ .id = "method-20k", .reject = 431, .calls = 0, .why = "as header-value-20k" },
    .{ .id = "headers-300", .reject = 0, .calls = 1, .why = "limit policy: this module counts bytes (`max_header_bytes`), not fields; hyper refuses more than 100 fields (431)" },
    .{ .id = "head-70k-in-20-headers", .reject = 431, .calls = 0, .why = "as header-value-20k" },
};

const llhttp_divergences = [_]Divergence{
    .{ .id = "get-no-host-1.1", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2: a server MUST answer an HTTP/1.1 request that lacks Host, has several or an invalid one with 400; hyper leaves Host to the application" },
    .{ .id = "get-two-host", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2: a server MUST answer an HTTP/1.1 request that lacks Host, has several or an invalid one with 400; hyper leaves Host to the application" },
    .{ .id = "get-host-empty", .reject = 400, .calls = 0, .why = "an http(s) target always has an authority, so an empty Host on an origin-form request is invalid (RFC 9112 §3.2); a parser or a hyper app does not check" },
    .{ .id = "get-host-bad-char", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2: a server MUST answer an HTTP/1.1 request that lacks Host, has several or an invalid one with 400; hyper leaves Host to the application" },
    .{ .id = "get-host-userinfo", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2: a server MUST answer an HTTP/1.1 request that lacks Host, has several or an invalid one with 400; hyper leaves Host to the application" },
    .{ .id = "double-space-request-line", .reject = 400, .calls = 0, .why = "RFC 9112 §3: the request-line is method SP target SP version; a recipient MAY parse on whitespace boundaries but this one refuses (smuggling guard, as Go); llhttp tolerates it" },
    .{ .id = "lowercase-method", .reject = 0, .calls = 1, .why = "methods are case-sensitive tokens (RFC 9110 §9.1) and an unknown one is the handler's to answer (501); llhttp's fixed method table refuses it" },
    .{ .id = "version-2.0", .reject = 505, .calls = 0, .why = "RFC 9112 §2.3: another major version is refused (505) rather than parsed as 1.x; llhttp reads HTTP/2.0 as a 1.x message" },
    .{ .id = "version-0.9", .reject = 400, .calls = 0, .why = "a request without a version (HTTP/0.9) is refused 400; llhttp accepts the simple request" },
    .{ .id = "get-asterisk", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2.4: asterisk-form is for OPTIONS only; hyper and llhttp pass any method on" },
    .{ .id = "connect-asterisk", .reject = 400, .calls = 0, .why = "as get-asterisk: a CONNECT names an authority, never *" },
    .{ .id = "connect-authority-path", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2.3: authority-form is uri-host \":\" port, no path" },
    .{ .id = "connect-authority-userinfo", .reject = 400, .calls = 0, .why = "RFC 9112 §3.2.3: no userinfo in authority-form" },
    .{ .id = "connect-then-get", .reject = 0, .calls = 2, .why = "after a CONNECT the connection is a tunnel: the bytes behind it are not a second request (RFC 9112 §9.3.6); a parser's upgrade stop and hyper's connection both go on to read them as one" },
    .{ .id = "extension-asterisk", .reject = 400, .calls = 0, .why = "as get-asterisk, for an extension method" },
    .{ .id = "extension-long-method", .reject = 0, .calls = 1, .why = "as lowercase-method: an extension token" },
    .{ .id = "mixed-case-method", .reject = 0, .calls = 1, .why = "as lowercase-method" },
    .{ .id = "cl-dup-same", .reject = 0, .calls = 1, .why = "RFC 9110 §8.6: a repeated Content-Length with one value may be combined; accepted (Go does), llhttp refuses any repeat" },
    .{ .id = "te-gzip-chunked", .reject = 400, .calls = 0, .why = "RFC 9112 §6.1: a coding this server does not implement is 501 (it cannot undo gzip); hyper hands the still-gzipped body over as the content" },
    .{ .id = "te-two-fields-gzip-chunked", .reject = 400, .calls = 0, .why = "as te-gzip-chunked, in two fields" },
    .{ .id = "te-chunked-http10", .reject = 400, .calls = 0, .why = "RFC 9112 §6.1: Transfer-Encoding in an HTTP/1.0 request MUST be treated as faulty framing (400 and close); llhttp frames by it" },
    .{ .id = "chunk-ext-ws", .reject = 0, .calls = 1, .why = "RFC 9112 §7.1.1 (June 2022) allows BWS around ';', '=' in chunk-ext: accepted since 2026-11-24; Go and llhttp still read RFC 7230's grammar, which had none" },
    .{ .id = "te-identity-then-chunked", .reject = 400, .calls = 0, .why = "`identity` is not a transfer coding any more (RFC 9112 §12.2); this server does not know it: 501/400 (§6.1); hyper and Go accept it, llhttp refuses" },
    .{ .id = "chunk-trailer-content-length", .reject = 0, .calls = 2, .why = "a Content-Length in the trailer section is a trailer, never framing (RFC 9112 §6.5): the body ends at the blank line and what follows is the next request; llhttp merges trailers into the header handling and fails" },
    .{ .id = "header-value-20k", .reject = 431, .calls = 0, .why = "limit policy: a head over `max_header_bytes` (16 KiB default) is 431 (RFC 9112 §3 leaves the limit to the server); hyper's is 400 KiB, llhttp has none" },
    .{ .id = "header-name-20k", .reject = 431, .calls = 0, .why = "as header-value-20k" },
    .{ .id = "target-20k", .reject = 431, .calls = 0, .why = "as header-value-20k (a request line over `max_request_line_bytes` is 414, past the head budget 431)" },
    .{ .id = "target-9k", .reject = 414, .calls = 0, .why = "RFC 9112 §3 asks for request lines of at least 8000 octets; `max_request_line_bytes` is 8 KiB by default (414 above it); hyper and llhttp have no such bound" },
    .{ .id = "head-70k-in-20-headers", .reject = 431, .calls = 0, .why = "as header-value-20k" },
};

fn find(table: []const Divergence, id: []const u8) ?Divergence {
    for (table) |d| if (std.mem.eql(u8, d.id, id)) return d;
    return null;
}

fn dump(label: []const u8, calls: anytype, reject: u16) void {
    std.debug.print("  {s}: reject={d} calls={d}", .{ label, reject, calls.len });
    for (calls) |c| std.debug.print(" [{s} {s} body={?s}]", .{ c.method, if (c.target.len > 60) c.target[0..60] else c.target, if (c.body) |b| (if (b.len > 40) b[0..40] else b) else null });
    std.debug.print("\n", .{});
}

fn replayAll(comptime which: enum { hyper, llhttp }, table: []const Divergence) !void {
    var out_buf: [8192]u8 = undefined;
    var head_buf: [16 * 1024]u8 = undefined;
    var bad: usize = 0;
    for (vectors.cases) |c| {
        const v = if (which == .hyper) c.hyper else c.llhttp;
        const ours = go_oracle.replayH1Head(c.wire, &out_buf, &head_buf);
        const ok = agrees(ours, v);
        const listed = find(table, c.id);
        const verdict: ?[]const u8 = if (listed) |d|
            (if (ok)
                "agrees now, drop its divergence entry"
            else if (ours.reject != d.reject or ours.calls.len != d.calls)
                "diverges, but not the way its entry says"
            else
                null)
        else if (ok) null else "diverges";
        const msg = verdict orelse continue;
        bad += 1;
        std.debug.print("{s} {s}: {s}\n", .{ @tagName(which), c.id, msg });
        dump(@tagName(which), v.calls, v.reject);
        dump("ours", ours.calls, ours.reject);
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "hyper oracle h1: every wire reaches the handler as hyper's server does, or the difference is judged" {
    try replayAll(.hyper, &hyper_divergences);
}

test "llhttp oracle h1: every wire parses as llhttp does, or the difference is judged" {
    try replayAll(.llhttp, &llhttp_divergences);
}

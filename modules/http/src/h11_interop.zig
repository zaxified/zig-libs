// SPDX-License-Identifier: MIT

//! OFFLINE external anchor: `h11` 0.16.0 (an independent, deliberately strict
//! Python HTTP/1.1 state machine — https://h11.readthedocs.io) as a black-box
//! oracle for this module's HTTP/1.1 wire framing (`h1.zig`). Exempt from a
//! root `NOTICE` entry under §0's black-box-oracle carve-out: only h11's
//! observable accept/reject verdict on hand-crafted bytes was consulted, no
//! h11 source was read or ported (confirmed via `check-catalog`).
//!
//! Unlike `curl_interop.zig` (a LIVE peer over a real loopback socket, used
//! there for response trailers), this file is fully OFFLINE: h11's verdicts
//! were captured ONCE via a throwaway Python script
//! (`~/.cache/zig-libs-misc/bin/python`, h11 0.16.0) driving `h11.Connection`
//! directly over hand-crafted byte strings — no socket even at capture time.
//! The verdicts are transcribed below as comments next to the bytes that
//! produced them; the tests assert OUR OWN parser's behavior on those exact
//! bytes, offline, with no Python invoked at test time.
//!
//! h11 is a "sans-io" state machine: it validates wire framing but leaves
//! policy decisions (e.g. "reject a message carrying both Content-Length and
//! Transfer-Encoding") to its caller. Where h11 itself enforces something,
//! that is load-bearing; where h11 is permissive and OUR module's *server*
//! (`Server.zig`) adds a stricter policy on top of a permissive `h1.zig`
//! parse, that is noted as an intentional, additional safety margin — not
//! reconciled away.
//!
//! Every divergence between h11 and this module is reported here with an
//! RFC citation and a judgement, per campaign policy: a mature independent
//! implementation is an oracle, not an authority, and golden values are
//! never adjusted to match it.

const std = @import("std");
const testing = std.testing;
const h1 = @import("h1.zig");

// ── agreements ────────────────────────────────────────────────────────────

test "h11 agrees: chunked request decodes to the expected body" {
    // Captured: h11.Connection(SERVER).receive_data(...) on
    //   POST /t HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n
    //   5\r\nhello\r\n0\r\n\r\n
    // yields Request(...) then Data(b'hello') then EndOfMessage — a clean
    // parse and a fully-decoded 5-byte body, no different from ours.
    const block = "POST /t HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
    const head = try h1.RequestHead.parse(block);
    try testing.expect(head.chunked);
    try testing.expect(!head.has_content_length);

    var in: std.Io.Reader = .fixed("5\r\nhello\r\n0\r\n\r\n");
    var buf: [16]u8 = undefined;
    var cr = h1.ChunkedReader.init(&in, &buf);
    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const n = try cr.reader.stream(&w, .limited(16));
    try testing.expectEqualStrings("hello", out[0..n]);
}

test "h11 agrees: Content-Length + Transfer-Encoding both present parses cleanly at the wire-framing layer (chunked wins) -- but see the Server.zig policy note below" {
    // Captured: h11.Connection(SERVER) on
    //   POST /t HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n
    // raised NO error: Request(...) with BOTH headers present, then
    // EndOfMessage -- h11 (a bare sans-io state machine) does not itself
    // reject the CL+TE combination; RFC 9112 §6.1 says TE overrides CL and
    // leaves outright rejection to the application ("ought to be handled as
    // an error" -- MAY, not MUST). `h1.zig`'s pure parse-layer agrees
    // exactly: it does not reject either, it lets TE win.
    const block = "POST /t HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
    const head = try h1.RequestHead.parse(block);
    try testing.expect(head.chunked);
    try testing.expect(head.has_content_length); // kept for the policy layer
    try testing.expectEqual(@as(?u64, null), head.content_length); // TE wins

    // The POLICY decision to reject this outright as a smuggling vector is
    // made one layer up, in `Server.zig` (`has_transfer_encoding and
    // has_content_length` → 400; see "serveStream: Content-Length +
    // Transfer-Encoding together → 400 (CL.TE smuggling guard)" in
    // Server.zig) -- stricter than h11's own default (h11 leaves this
    // entirely to its caller), which is a deliberate extra margin, not a
    // gap: a fronting proxy that trusts Content-Length while we trust
    // Transfer-Encoding is exactly the CL.TE desync RFC 9112 §6.1 warns
    // about, so we refuse the whole message rather than merely picking a
    // winner.
}

test "h11 agrees: TE.TE double-chunk and chunked+other-coding are both refused (h11 hard-errors; our parser routes them through the has_transfer_encoding-but-not-chunked 400 gate)" {
    // Captured: h11 raised RemoteProtocolError("Only Transfer-Encoding:
    // chunked is supported") for BOTH
    //   Transfer-Encoding: chunked, chunked
    // and
    //   Transfer-Encoding: chunked, gzip
    // h1.zig's exact-match check (`eqlIgnoreCase(entry.value, "chunked")`)
    // does not set `chunked` for either value (neither is the bare single
    // token "chunked"), so both leave `has_transfer_encoding = true,
    // chunked = false` -- which `Server.zig` maps to 400 (see
    // "serveStream: protocol rejections" in Server.zig, which exercises
    // exactly these two byte strings). Same refused OUTCOME as h11, via a
    // deferred-to-server-policy mechanism rather than a hard parse error.
    inline for (.{ "chunked, chunked", "chunked, gzip" }) |te| {
        const block = "POST /t HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: " ++ te ++ "\r\n\r\n";
        const head = try h1.RequestHead.parse(block);
        try testing.expect(head.has_transfer_encoding);
        try testing.expect(!head.chunked);
    }
}

test "h11 agrees: duplicate IDENTICAL Content-Length is tolerated, CONFLICTING is rejected (RFC 7230 §3.3.2)" {
    // Captured: h11 on "Content-Length: 4\r\nContent-Length: 4\r\n\r\nabcd"
    // merges into a single Request(headers=[('content-length', '4')]) and
    // parses the body -- no error. On "Content-Length: 4\r\nContent-Length:
    // 5\r\n\r\nabcde" it raises RemoteProtocolError("conflicting
    // Content-Length headers"). Ours: `latchContentLength` agrees on both.
    const same = try h1.RequestHead.parse("POST /t HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n");
    try testing.expectEqual(@as(?u64, 4), same.content_length);

    try testing.expectError(error.MalformedHead, h1.RequestHead.parse(
        "POST /t HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n",
    ));
}

test "h11 agrees: Content-Length with a leading '+' is rejected; a leading zero is accepted" {
    // Captured: h11 raises RemoteProtocolError("bad Content-Length") for
    // "Content-Length: +4", but ACCEPTS "Content-Length: 04" (parses as a
    // Request with content-length '04', then decodes a 4-byte body) --
    // RFC 9110 §8.6's `1*DIGIT` grammar has no leading-zero restriction.
    // `parseContentLengthStrict`'s digit-only loop agrees exactly on both.
    try testing.expectError(error.MalformedHead, h1.RequestHead.parse(
        "POST /t HTTP/1.1\r\nHost: x\r\nContent-Length: +4\r\n\r\n",
    ));
    const lz = try h1.RequestHead.parse("POST /t HTTP/1.1\r\nHost: x\r\nContent-Length: 04\r\n\r\n");
    try testing.expectEqual(@as(?u64, 4), lz.content_length);
}

test "h11 agrees: whitespace between a header name and its colon is rejected (RFC 9112 §5.1)" {
    // Captured: h11 raises RemoteProtocolError("illegal header line") for
    // "X-Foo : bar" (space before the colon). `parseHeaderLine` agrees: the
    // colon search includes the space in `name`, and the
    // `indexOfAny(name, " \t")` check rejects it.
    try testing.expectError(error.MalformedHead, h1.RequestHead.parse(
        "GET /t HTTP/1.1\r\nHost: x\r\nX-Foo : bar\r\n\r\n",
    ));
}

test "h11 agrees: chunked trailer fields are captured after the body, not folded into it" {
    // Captured: h11 on a chunked request with a trailing "X-Checksum:
    // deadbeef" after the 0-chunk produces EndOfMessage(headers=[('x-checksum',
    // 'deadbeef')]) -- a distinct trailer section, not extra body bytes.
    // `ChunkedReader.initCapturingTrailers` agrees.
    var in: std.Io.Reader = .fixed("5\r\nhello\r\n0\r\nX-Checksum: deadbeef\r\n\r\n");
    var buf: [16]u8 = undefined;
    var tbuf: [64]u8 = undefined;
    var cr = h1.ChunkedReader.initCapturingTrailers(&in, &buf, &tbuf);
    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var total: usize = 0;
    while (true) {
        const n = cr.reader.stream(&w, .limited(16)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        total += n;
    }
    try testing.expectEqualStrings("hello", out[0..total]);
    try testing.expectEqualStrings("deadbeef", cr.trailer("X-Checksum").?);
}

test "h11 agrees: a response with both Content-Length and Transfer-Encoding parses cleanly (chunked wins) at the wire-framing layer" {
    // Captured: h11.Connection(CLIENT) on
    //   HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n
    // parses without error (Response with both headers, then EndOfMessage).
    // `ResponseHead.parse` agrees: chunked nulls content_length, no rejection
    // at the parse layer (this module's client-side response handling has no
    // equivalent of Server.zig's request-side CL+TE policy gate, since a
    // response is not attacker-controlled the way a request is).
    const head = try h1.ResponseHead.parse("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n");
    try testing.expect(head.chunked);
    try testing.expectEqual(@as(?u64, null), head.content_length);
}

// ── divergences (documented, NOT reconciled) ────────────────────────────────

test "h11 DIVERGES: obs-fold continuation lines are leniently unfolded by h11; we hard-reject the whole message (RFC 9112 §5.2 permits either)" {
    // Captured: h11 on
    //   GET /t HTTP/1.1\r\nHost: x\r\nX-Foo: bar\r\n baz\r\n\r\n
    // produces Request(headers=[('host','x'),('x-foo','bar baz')]) -- it
    // UNFOLDS the continuation line into the previous field's value (joined
    // with a space). RFC 9112 §5.2: "A server that receives an obs-fold in a
    // request message... MUST either reject the message... or replace each
    // received obs-fold with one or more SP octets" -- both are spec-legal;
    // h11 takes the replace option, we take the reject option.
    //
    // Judgement: rejecting is the safer choice for a server sitting behind
    // another HTTP implementation (the classic desync is a front-end that
    // treats " baz" as a continuation while a back-end treats it as a
    // malformed/ignored line, or vice versa) -- multiple request-smuggling
    // writeups single out obs-fold leniency as a hardening target. Not
    // adopting h11's unfold; `parseHeaderLine`'s `line[0]==' '/'\t' →
    // MalformedHead` stays as-is.
    try testing.expectError(error.MalformedHead, h1.RequestHead.parse(
        "GET /t HTTP/1.1\r\nHost: x\r\nX-Foo: bar\r\n baz\r\n\r\n",
    ));
}

test "h11 DIVERGES: bare LF is a valid line terminator for h11 (RFC 9112 §2.2 MAY); we reject it (deliberate, not exercising the MAY)" {
    // Captured: h11 on "GET /t HTTP/1.1\nHost: x\r\n\r\n" (bare LF ending the
    // request line) and on "GET /t HTTP/1.1\r\nHost: x\nX-Foo: bar\r\n\r\n"
    // (bare LF between headers) both parse CLEANLY -- Request(...) then
    // EndOfMessage, no error either time. RFC 9112 §2.2 verbatim: "a
    // recipient MAY recognize a single LF as a line terminator and ignore
    // any preceding CR" -- h11 exercises that MAY; nothing in the RFC
    // requires it to.
    //
    // Judgement: this module deliberately does NOT exercise the MAY (see
    // `h1.zig`'s `stripCrlf`, whose doc comment previously misquoted this
    // as a "MUST NOT" -- corrected during this audit to cite the RFC
    // accurately: it is discretionary, and we choose the strict option) for
    // the same smuggling-hardening reason as obs-fold: a bare LF is only
    // dangerous when one HTTP implementation in a chain accepts it as a
    // terminator and another does not. Confirmed already enforced at the
    // server level too (`Server.zig`: "serveStream: bare-LF in the request
    // head → 400"). Not adopting h11's leniency.
    try testing.expectError(error.MalformedHead, h1.RequestHead.parse("GET /t HTTP/1.1\nHost: x\r\n\r\n"));
    try testing.expectError(error.MalformedHead, h1.RequestHead.parse("GET /t HTTP/1.1\r\nHost: x\nX-Foo: bar\r\n\r\n"));
}

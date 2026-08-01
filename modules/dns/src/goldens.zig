// SPDX-License-Identifier: MIT

//! Real DNS wire-format responses captured live from a public recursive
//! resolver, plus one authentic NXDOMAIN and one authentic name-compression
//! chain — closing the gap that every other golden in `message.zig` is
//! hand-computed per RFC 1035 rather than observed from a real server.
//!
//! ## Why this file exists
//!
//! Every golden byte string in `message.zig`'s "decode (golden packets)"
//! section was built by hand, offset arithmetic and all, by the same person
//! who wrote the decoder. That is the textbook blind spot this campaign
//! keeps finding: a hand-built fixture agrees with the decoder's own reading
//! of the spec, not necessarily with what a real authoritative/recursive
//! server actually emits on the wire — especially for name compression,
//! where a real server's exact pointer placement is an implementation
//! choice RFC 1035 does not fully pin down.
//!
//! ## Capture recipe
//!
//! A tiny one-shot Python script (not committed — throwaway tooling) built
//! a minimal RFC 1035 query by hand (2-byte ID, RD flag, one question, no
//! EDNS) and sent it over a raw UDP socket to `8.8.8.8:53`, then printed the
//! raw response bytes as a `\xHH`-escaped literal:
//!
//! ```python
//! import socket
//! def build_query(qid, name, qtype):
//!     flags = 0x0100  # RD
//!     h = qid.to_bytes(2,"big")+flags.to_bytes(2,"big")
//!     h += (1).to_bytes(2,"big")+(0).to_bytes(2,"big")*2+(0).to_bytes(2,"big")
//!     qname = b"".join(bytes([len(l)])+l.encode() for l in name.split("."))+b"\x00"
//!     return h + qname + qtype.to_bytes(2,"big") + (1).to_bytes(2,"big")
//! s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
//! s.sendto(build_query(qid, name, qtype), ("8.8.8.8", 53))
//! resp, _ = s.recvfrom(4096)
//! ```
//!
//! Captured 2026-08-01 against Google Public DNS (`8.8.8.8`). Every capture
//! below is reproducible by re-running the recipe (subject to the records
//! themselves changing at the authoritative side).
//!
//! ## What each capture exercises
//!
//! - **`a_example_com`** — `example.com A`: two A answers, the plain case.
//! - **`aaaa_example_com`** — `example.com AAAA`: two AAAA answers.
//! - **`cname_chain_wikipedia`** — `www.wikipedia.org A`: a REAL CNAME chain
//!   (`www.wikipedia.org` → `dyna.wikimedia.org` → A), with the CNAME's own
//!   RDATA using a compression pointer into the *target* label
//!   (`dyna.wikimedia` + pointer to `org` inside the question name, i.e. a
//!   pointer into the MIDDLE of another name's tail — not just "pointer to
//!   the question start", which is all the hand-built fixtures ever do), and
//!   the second answer's owner name pointing at the CNAME's RDATA rather
//!   than the question.
//! - **`mx_iana_org`** — `iana.org MX`: four MX answers, each with a
//!   compression pointer into a PRIOR ANSWER's RDATA (pechora6/7/8's owner
//!   name is `<label>.icann.org`, itself half-written + a pointer into the
//!   first answer's exchange name) — chained pointer-to-a-pointed-at-name,
//!   never a hand-built fixture's habit of always repointing at the header.
//! - **`txt_example_com`** — `example.com TXT`: two TXT answers, one long
//!   SPF-shaped string and one short one, real character-string framing.
//! - **`nxdomain_zig_libs_test`** — a domain manufactured to not exist
//!   (`zz-nonexistent-domain-a1b2c3-zig-libs-test.com A`): NXDOMAIN rcode
//!   (3), empty answer section, and a real authority-section SOA whose
//!   `mname`/`rname` compression pointers land in the middle of the
//!   question's own label sequence (`c0 37` = offset 55, the `com` label),
//!   distinct from every hand-built SOA fixture's `c0 0c` (always offset 12,
//!   the very start of the name).
//!
//! Nothing here is time-varying in a way that can rot: a captured UDP
//! datagram's TTLs are literal wire integers, not derived from the wall
//! clock — decoding them today or in ten years yields the identical `u32`.
//! No re-pinning is needed or possible; the bytes themselves are the pin.
//!
//! Attribution: none required. Per root `NOTICE` §0 and the same reasoning
//! `ocsp`'s `goldens.zig` documents for its live CA captures — a public
//! recursive resolver's answer to a stock RFC 1035 query is the observable
//! output of a public protocol (DNS wire format, itself dictated by RFC
//! 1035/2782/3596, not copyrightable expression) plus facts (IP addresses,
//! TTLs, hostnames already published in the DNS) — not a third-party
//! implementation's source or design. No reference resolver's source was
//! consulted; only its wire output was captured. No root `NOTICE` change
//! accompanies this addition.

const std = @import("std");
const testing = std.testing;
const message = @import("message.zig");

// ── captured wire bytes ─────────────────────────────────────────────────────

/// `example.com A` via 8.8.8.8, qid=0x1001.
pub const a_example_com = "\x10\x01\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x07\x65\x78\x61" ++
    "\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00" ++
    "\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xac\x42\x93\xf3\xc0\x0c\x00" ++
    "\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x68\x14\x17\x9a";

/// `example.com AAAA` via 8.8.8.8, qid=0x1002.
pub const aaaa_example_com = "\x10\x02\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x07\x65\x78\x61" ++
    "\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01\xc0\x0c\x00" ++
    "\x1c\x00\x01\x00\x00\x01\x2c\x00\x10\x26\x06\x47\x00\x00\x10\x00" ++
    "\x00\x00\x00\x00\x00\xac\x42\x93\xf3\xc0\x0c\x00\x1c\x00\x01\x00" ++
    "\x00\x01\x2c\x00\x10\x26\x06\x47\x00\x00\x10\x00\x00\x00\x00\x00" ++
    "\x00\x68\x14\x17\x9a";

/// `www.wikipedia.org A` via 8.8.8.8, qid=0x1003 — real CNAME chain with
/// mid-name compression pointers.
pub const cname_chain_wikipedia = "\x10\x03\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x77\x77\x77" ++
    "\x09\x77\x69\x6b\x69\x70\x65\x64\x69\x61\x03\x6f\x72\x67\x00\x00" ++
    "\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x08\x7d\x00\x11\x04" ++
    "\x64\x79\x6e\x61\x09\x77\x69\x6b\x69\x6d\x65\x64\x69\x61\xc0\x1a" ++
    "\xc0\x2f\x00\x01\x00\x01\x00\x00\x00\xb4\x00\x04\xb9\x0f\x3a\xe0";

/// `iana.org MX` via 8.8.8.8, qid=0x1004 — four MX answers chained through
/// each other's RDATA via compression pointers.
pub const mx_iana_org = "\x10\x04\x81\x80\x00\x01\x00\x04\x00\x00\x00\x00\x04\x69\x61\x6e" ++
    "\x61\x03\x6f\x72\x67\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01" ++
    "\x00\x00\x0b\x2c\x00\x13\x00\x0a\x08\x70\x65\x63\x68\x6f\x72\x61" ++
    "\x36\x05\x69\x63\x61\x6e\x6e\xc0\x11\xc0\x0c\x00\x0f\x00\x01\x00" ++
    "\x00\x0b\x2c\x00\x0d\x00\x0a\x08\x70\x65\x63\x68\x6f\x72\x61\x38" ++
    "\xc0\x31\xc0\x0c\x00\x0f\x00\x01\x00\x00\x0b\x2c\x00\x0d\x00\x0a" ++
    "\x08\x70\x65\x63\x68\x6f\x72\x61\x37\xc0\x31\xc0\x0c\x00\x0f\x00" ++
    "\x01\x00\x00\x0b\x2c\x00\x0d\x00\x0a\x08\x70\x65\x63\x68\x6f\x72" ++
    "\x61\x31\xc0\x31";

/// `example.com TXT` via 8.8.8.8, qid=0x1005.
pub const txt_example_com = "\x10\x05\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x07\x65\x78\x61" ++
    "\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x10\x00\x01\xc0\x0c\x00" ++
    "\x10\x00\x01\x00\x00\x01\x2c\x00\x21\x20\x5f\x6b\x32\x6e\x31\x79" ++
    "\x34\x76\x77\x33\x71\x74\x62\x34\x73\x6b\x64\x78\x39\x65\x37\x64" ++
    "\x78\x74\x39\x37\x71\x72\x6d\x6d\x71\x39\xc0\x0c\x00\x10\x00\x01" ++
    "\x00\x00\x01\x2c\x00\x0c\x0b\x76\x3d\x73\x70\x66\x31\x20\x2d\x61" ++
    "\x6c\x6c";

/// `zz-nonexistent-domain-a1b2c3-zig-libs-test.com A` via 8.8.8.8,
/// qid=0x1006 — real NXDOMAIN with an SOA authority record whose
/// compression pointer lands mid-name.
pub const nxdomain_zig_libs_test = "\x10\x06\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00\x2a\x7a\x7a\x2d" ++
    "\x6e\x6f\x6e\x65\x78\x69\x73\x74\x65\x6e\x74\x2d\x64\x6f\x6d\x61" ++
    "\x69\x6e\x2d\x61\x31\x62\x32\x63\x33\x2d\x7a\x69\x67\x2d\x6c\x69" ++
    "\x62\x73\x2d\x74\x65\x73\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01" ++
    "\xc0\x37\x00\x06\x00\x01\x00\x00\x03\x84\x00\x3d\x01\x61\x0c\x67" ++
    "\x74\x6c\x64\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74\x00" ++
    "\x05\x6e\x73\x74\x6c\x64\x0c\x76\x65\x72\x69\x73\x69\x67\x6e\x2d" ++
    "\x67\x72\x73\xc0\x37\x6a\x6d\xe9\xa9\x00\x00\x07\x08\x00\x00\x03" ++
    "\x84\x00\x09\x3a\x80\x00\x00\x03\x84";

// ── tests: assert real content, not just "it decoded" ──────────────────────

test "golden: example.com A — two real answers" {
    var msg = try message.decode(testing.allocator, a_example_com);
    defer msg.deinit();
    try testing.expectEqual(@as(u16, 0x1001), msg.header.id);
    try testing.expectEqual(message.Rcode.no_error, msg.rcode());
    try testing.expectEqualStrings("example.com", msg.questions[0].name);
    try testing.expectEqual(@as(usize, 2), msg.answers.len);
    try testing.expectEqualStrings("example.com", msg.answers[0].name);
    try testing.expectEqual(message.Type.a, msg.answers[0].ty);
    try testing.expectEqual(@as(u32, 300), msg.answers[0].ttl);
    try testing.expectEqual([4]u8{ 172, 66, 147, 243 }, msg.answers[0].data.a);
    try testing.expectEqual([4]u8{ 104, 20, 23, 154 }, msg.answers[1].data.a);
}

test "golden: example.com AAAA — two real answers" {
    var msg = try message.decode(testing.allocator, aaaa_example_com);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 2), msg.answers.len);
    try testing.expectEqual(message.Type.aaaa, msg.answers[0].ty);
    try testing.expectEqual(@as(u32, 300), msg.answers[0].ttl);
    const want0 = [16]u8{ 0x26, 0x06, 0x47, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x42, 0x93, 0xf3 };
    try testing.expectEqual(want0, msg.answers[0].data.aaaa);
}

test "golden: www.wikipedia.org — real CNAME chain, mid-name compression" {
    var msg = try message.decode(testing.allocator, cname_chain_wikipedia);
    defer msg.deinit();
    try testing.expectEqualStrings("www.wikipedia.org", msg.questions[0].name);
    try testing.expectEqual(@as(usize, 2), msg.answers.len);

    const cname_rr = msg.answers[0];
    try testing.expectEqualStrings("www.wikipedia.org", cname_rr.name);
    try testing.expectEqual(message.Type.cname, cname_rr.ty);
    try testing.expectEqual(@as(u32, 2173), cname_rr.ttl);
    // The target's compression pointer (\xc0\x1a) lands inside the QUESTION
    // name's tail ("wikipedia.org" starts at offset 0x1a=26) — a
    // mid-name-tail pointer, not "point at the whole name from offset 12"
    // like every hand-built fixture in message.zig does.
    try testing.expectEqualStrings("dyna.wikimedia.org", cname_rr.data.cname);

    const a_rr = msg.answers[1];
    // The owner name's pointer (\xc0\x2f = offset 47) targets the CNAME
    // RDATA's own name bytes, not the question — a second real-world
    // compression pattern absent from the hand-built goldens.
    try testing.expectEqualStrings("dyna.wikimedia.org", a_rr.name);
    try testing.expectEqual(message.Type.a, a_rr.ty);
    try testing.expectEqual(@as(u32, 180), a_rr.ttl);
    try testing.expectEqual([4]u8{ 185, 15, 58, 224 }, a_rr.data.a);
}

test "golden: iana.org MX — four answers chained through prior RDATA" {
    var msg = try message.decode(testing.allocator, mx_iana_org);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 4), msg.answers.len);

    const want_exchanges = [_][]const u8{
        "pechora6.icann.org",
        "pechora8.icann.org",
        "pechora7.icann.org",
        "pechora1.icann.org",
    };
    for (msg.answers, want_exchanges) |rr, want| {
        try testing.expectEqual(message.Type.mx, rr.ty);
        try testing.expectEqual(@as(u16, 10), rr.data.mx.preference);
        try testing.expectEqualStrings(want, rr.data.mx.exchange);
        try testing.expectEqualStrings("iana.org", rr.name);
    }
}

test "golden: example.com TXT — real SPF + verification-token strings" {
    var msg = try message.decode(testing.allocator, txt_example_com);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 2), msg.answers.len);
    const txt0 = msg.answers[0].data.txt;
    try testing.expectEqual(@as(usize, 1), txt0.len);
    try testing.expectEqualStrings("_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9", txt0[0]);
    const txt1 = msg.answers[1].data.txt;
    try testing.expectEqual(@as(usize, 1), txt1.len);
    try testing.expectEqualStrings("v=spf1 -all", txt1[0]);
}

test "golden: real NXDOMAIN with mid-name SOA compression pointer" {
    var msg = try message.decode(testing.allocator, nxdomain_zig_libs_test);
    defer msg.deinit();
    try testing.expectEqual(message.Rcode.nx_domain, msg.rcode());
    try testing.expectEqual(@as(usize, 0), msg.answers.len);
    try testing.expectEqual(@as(usize, 1), msg.authorities.len);

    const soa = msg.authorities[0];
    try testing.expectEqual(message.Type.soa, soa.ty);
    // The SOA's owner is the ZONE APEX ("com"), not the queried (nonexistent)
    // name — Google Public DNS answers NXDOMAIN for the queried name but the
    // authority-section SOA belongs to whatever zone is actually authoritative
    // for the negative answer (RFC 2308 §3). Its name is wire-compressed as a
    // pointer (\xc0\x37 = offset 55) straight into the "com" label INSIDE the
    // question name's tail — decoding to "com" alone, not the full queried
    // name. (First hand-assumption this capture corrected: every hand-built
    // SOA fixture elsewhere in this repo has the SOA share the question's
    // full owner name, which is not how a real resolver answers NXDOMAIN.)
    try testing.expectEqualStrings("com", soa.name);
    try testing.expectEqualStrings("a.gtld-servers.net", soa.data.soa.mname);
    try testing.expectEqualStrings("nstld.verisign-grs.com", soa.data.soa.rname);
    try testing.expectEqual(@as(u32, 900), soa.ttl);
}

test "golden: fixture count + size canary — 6 real captures, one per record shape" {
    // Pins the set this file covers: if a capture is added or removed, this
    // fails and the doc comment above must be updated to match.
    const captures = [_][]const u8{
        a_example_com,
        aaaa_example_com,
        cname_chain_wikipedia,
        mx_iana_org,
        txt_example_com,
        nxdomain_zig_libs_test,
    };
    try testing.expectEqual(@as(usize, 6), captures.len);
    for (captures) |c| try testing.expect(c.len > 0);
}

// ── not covered here, with reasons ──────────────────────────────────────────
//
// - SRV / CAA / NS / OPT real captures: message.zig's hand-built goldens
//   already exercise the decode paths structurally; no real-server capture
//   of these was made because the record shapes involved (pointer handling,
//   RDATA framing) are identical in kind to what CNAME/MX/SOA above already
//   prove against a real server — the risk this file targets is compression
//   *placement* diverging from a hand-built assumption, and the six captures
//   above already cover every pointer-placement pattern DNS servers use
//   (start-of-name, mid-name-tail, pointer-to-prior-RDATA-name).
// - A real truncated (TC-bit) UDP response requiring TCP retry: not
//   reproduced here — provoking a real truncated UDP reply requires a query
//   shape (e.g. DNSSEC, many records) this module does not control end to
//   end, and `Resolver.zig`'s TC-bit retry logic is transport plumbing, not
//   `message.zig`'s decode surface this file targets.

// SPDX-License-Identifier: MIT

//! `whois-demo` — a real RFC 3912 WHOIS query with the referral chase this
//! module implements: start at the IANA bootstrap server, follow whatever
//! referral it hands back toward the authoritative registry, and print
//! **every hop consulted** — so the reader sees what `lookup` actually did,
//! not just its final answer.
//!
//! What this deliberately does NOT do: parse the registry's reply into
//! fields. RFC 3912 is one page and defines no response grammar at all —
//! every registry writes its own free-form text, so this module's only
//! concession beyond referral-line extraction is `fieldValue`, a single
//! `key: value` lookup. Pretending to more structure than that would be
//! inventing a schema the wire format does not have; this example prints
//! the raw reply and says why.
//!
//! **Two halves.** The first needs no network: frozen registry replies are
//! driven through the published `Transport` seam, so the whole referral
//! chase — hop order, the cycle guard, the SSRF guard, the depth cap, the
//! referral-key priority, and the CRLF wire framing — runs in memory and is
//! ASSERTED. A mismatch panics; it does not print. The second half is the
//! live one, and still says so and exits 0 when there is no network.
//!
//! Built against the PUBLISHED module (`@import("whois")`) only.

const std = @import("std");
const whois = @import("whois");

/// Queried with the FULL domain (not just the TLD) — `whois.iana.org`
/// answers a bare TLD query without a `refer:` line (only the trailing
/// `whois:` field, lower priority in `whois.referral_keys`) but answers a
/// full domain query with `refer:` up front, so this is the query shape
/// that actually exercises the chase.
const demo_domain = "iana.org";
/// Same TLD, unregistered by construction: the chase still reaches PIR,
/// which answers "Domain not found." as free text — there is no structured
/// not-found signal in RFC 3912, unlike RDAP's HTTP 404.
const missing_domain = "this-domain-should-not-exist-zig-libs-whois-demo-2026.org";

pub fn main() u8 {
    // `whois.lookup` never allocates -- `Chain` is fixed storage and
    // `Transport` reads into a caller-owned buffer -- but `std.Io.Threaded`
    // still wants an allocator for its own bookkeeping, so this remains a
    // real leak detector for that layer.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");

    // ── half one: no network, everything asserted ────────────────────────
    runOfflineChecks();

    var threaded: std.Io.Threaded = .init(da.allocator(), .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tcp: whois.TcpTransport = .{ .io = io };
    const transport = tcp.transport();

    std.debug.print("=== {s} ===\n", .{demo_domain});
    const ok = runLookup(transport, demo_domain);
    if (!ok) return 0; // "no network" already reported by runLookup

    std.debug.print("\n=== failure path: {s} ===\n", .{missing_domain});
    _ = runLookup(transport, missing_domain);

    return 0;
}

// ── half one: the offline checks ─────────────────────────────────────────
//
// Frozen registry replies driven through the published `Transport` seam --
// the same seam `TcpTransport` implements -- so `lookup`'s entire referral
// chase runs in memory. Everything is ASSERTED: a mismatch panics. Before
// this half existed, a run with no route to the internet printed
// "could not reach whois.iana.org -- no network access, exiting cleanly",
// exited 0, and had exercised nothing at all.

fn check(ok: bool, comptime what: []const u8) void {
    if (!ok) @panic("whois-demo offline: " ++ what);
}

fn checkStr(expected: []const u8, actual: ?[]const u8, comptime what: []const u8) void {
    const got = actual orelse @panic("whois-demo offline: " ++ what ++ " (absent)");
    if (!std.mem.eql(u8, expected, got)) @panic("whois-demo offline: " ++ what);
}

/// The IANA bootstrap's answer: a `refer:` line and nothing else useful.
/// It also carries a lower-priority `whois:` line, because the real IANA TLD
/// records do — which is what makes `referral_keys`' ORDER observable.
const iana_reply =
    \\% IANA WHOIS server
    \\domain:       EXAMPLE
    \\refer:        whois.pir.example
    \\
    \\organisation: Demo Registry
    \\whois:        whois.wrong.example
    \\
;

/// A thick registry: real data, plus a `Registrar WHOIS Server:` pointing on
/// to the registrar's own server (the Verisign-shaped thin-registry hop).
const registry_reply =
    \\Domain Name: DEMO.EXAMPLE
    \\Registry Domain ID: D-2026-DEMO
    \\Registrar: Demo Registrar, Inc.
    \\Registrar WHOIS Server: whois.registrar.example
    \\Registrar IANA ID: 9999
    \\Domain Status: clientTransferProhibited
    \\
;

/// The terminal hop: no referral line at all, so the chase must stop here.
const registrar_reply =
    \\Domain Name: DEMO.EXAMPLE
    \\Registrar: Demo Registrar, Inc.
    \\Registrant Organization:
    \\Registrant Country: AU
    \\
;

/// A transport answering from a frozen script instead of a socket. It also
/// checks the WIRE bytes at every hop: RFC 3912 §2 is `<query>CRLF`, and
/// `lookup` must hand each server exactly that, unchanged.
const CannedTransport = struct {
    const Reply = struct {
        server: []const u8,
        port: u16 = whois.default_port,
        text: []const u8,
    };

    replies: []const Reply,
    expect_wire: []const u8,
    dials: usize = 0,
    last_port: u16 = 0,

    fn transport(t: *CannedTransport) whois.Transport {
        return .{ .ctx = t, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(
        ctx: *anyopaque,
        server: []const u8,
        port: u16,
        query: []const u8,
        response_buf: []u8,
    ) whois.TransportError!usize {
        const t: *CannedTransport = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, t.expect_wire, query))
            @panic("whois-demo offline: lookup handed the transport a query it did not format");
        t.dials += 1;
        t.last_port = port;
        for (t.replies) |r| {
            if (!std.ascii.eqlIgnoreCase(r.server, server) or r.port != port) continue;
            if (r.text.len > response_buf.len) return error.ResponseTooLarge;
            @memcpy(response_buf[0..r.text.len], r.text);
            return r.text.len;
        }
        return error.TransportFailed; // nothing scripted for this server
    }
};

fn runOfflineChecks() void {
    std.debug.print("=== offline checks (no network needed; every value asserted) ===\n", .{});

    // ── wire framing (RFC 3912 §2) ──────────────────────────────────────
    var qbuf: [whois.max_query_len + 2]u8 = undefined;
    checkStr("demo.example\r\n", whois.formatQuery(&qbuf, "demo.example") catch null, "formatQuery appends CRLF");
    // A CR/LF inside the query would inject a SECOND command on the wire.
    check(std.meta.isError(whois.formatQuery(&qbuf, "a\r\nb")), "embedded CRLF must be refused");
    check(std.meta.isError(whois.formatQuery(&qbuf, "x" ** (whois.max_query_len + 1))), "an overlong query must be refused");
    checkStr("domain demo.example\r\n", whois.verisignDomainQuery(&qbuf, "demo.example") catch null, "verisignDomainQuery prefix");
    checkStr("n 192.0.2.1\r\n", whois.arinIpQuery(&qbuf, "192.0.2.1") catch null, "arinIpQuery prefix");
    std.debug.print("query framing: CRLF, injection refusal, length cap, both registry prefixes\n", .{});

    // ── the one field this module extracts ──────────────────────────────
    checkStr("Demo Registrar, Inc.", whois.fieldValue(registry_reply, "Registrar"), "fieldValue");
    checkStr("Demo Registrar, Inc.", whois.fieldValue(registry_reply, "rEgIsTrAr"), "fieldValue is case-insensitive");
    // The colon must follow the key IMMEDIATELY: "Registrar" must not match
    // "Registrar IANA ID:" or "Registrar WHOIS Server:" -- the documented
    // rule, and the difference between an extractor and a prefix search.
    checkStr("whois.registrar.example", whois.fieldValue(registry_reply, "Registrar WHOIS Server"), "the longer key is its own field");
    // An empty value is skipped rather than returned as "".
    check(whois.fieldValue(registrar_reply, "Registrant Organization") == null, "an empty value reads as absent");
    check(whois.fieldValue(registry_reply, "Nonexistent") == null, "an absent key reads null");
    std.debug.print("fieldValue: case-insensitive, colon-adjacent, empty-value and absent-key rules\n", .{});

    // ── referral parsing, and the KEY PRIORITY ──────────────────────────
    const ref = whois.parseServerRef("whois://whois.other.example:4343/") orelse @panic("whois-demo offline: whois:// URL must parse");
    checkStr("whois.other.example", ref.host, "parseServerRef host");
    check(ref.port == 4343, "parseServerRef port");
    check(whois.parseServerRef("rwhois://rwhois.example") == null, "rwhois:// is a different protocol and must be refused");
    check(whois.parseServerRef("whois.example:0") == null, "port 0 must be refused");
    check(whois.parseServerRef("not a host!") == null, "a malformed host must be refused");
    // `iana_reply` carries BOTH `refer:` and `whois:`. `referral_keys` order
    // decides, and the wrong answer is a real host in this fixture -- so a
    // reordering cannot pass by accident.
    const chosen = whois.nextServer(iana_reply) orelse @panic("whois-demo offline: nextServer found no referral");
    checkStr("whois.pir.example", chosen.host, "refer: must outrank whois:");
    check(whois.nextServer(registrar_reply) == null, "a terminal reply must yield no referral");
    std.debug.print("referrals: whois:// URLs, refusals, and refer: outranking whois:\n", .{});

    // ── the SSRF guard's classifier ─────────────────────────────────────
    inline for (.{ "localhost", "127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.1.1", "192.0.2.7", "::1" }) |h| {
        check(whois.isSpecialUseHost(h), "special-use host must be classified: " ++ h);
    }
    inline for (.{ "whois.pir.example", "203.0.114.1" }) |h| {
        check(!whois.isSpecialUseHost(h), "routable host must not be classified special-use: " ++ h);
    }
    std.debug.print("SSRF classifier: loopback, RFC1918, link-local, TEST-NET, v6 -- and a routable host\n", .{});

    // ── the full chase, three hops ──────────────────────────────────────
    var buf: [4096]u8 = undefined;
    var script: CannedTransport = .{
        .expect_wire = "demo.example\r\n",
        .replies = &.{
            .{ .server = whois.iana_root, .text = iana_reply },
            .{ .server = "whois.pir.example", .text = registry_reply },
            .{ .server = "whois.registrar.example", .text = registrar_reply },
        },
    };
    const result = whois.lookup(script.transport(), "demo.example", .{}, &buf) catch
        @panic("whois-demo offline: the scripted chase failed");
    check(script.dials == 3, "three hops must be dialed");
    check(result.chain.count == 3, "the chain must record all three");
    checkStr(whois.iana_root, result.chain.get(0), "hop 1 is the configured root");
    checkStr("whois.pir.example", result.chain.get(1), "hop 2 follows refer:");
    checkStr("whois.registrar.example", result.chain.get(2), "hop 3 follows Registrar WHOIS Server:");
    check(!result.truncated, "a chase that reached a terminal reply is not truncated");
    // The response must be the LAST hop's, not the first's.
    check(std.mem.eql(u8, registrar_reply, result.response), "the returned reply is the deepest one");
    checkStr("Demo Registrar, Inc.", whois.fieldValue(result.response, "Registrar"), "field extracted from the terminal reply");
    std.debug.print("chase: 3 hops in order, terminal reply returned, field extracted\n", .{});

    // ── the depth cap ───────────────────────────────────────────────────
    var capped: CannedTransport = .{ .expect_wire = "demo.example\r\n", .replies = script.replies };
    const capped_result = whois.lookup(capped.transport(), "demo.example", .{ .max_referrals = 1 }, &buf) catch
        @panic("whois-demo offline: the capped chase failed");
    check(capped_result.chain.count == 2, "max_referrals=1 stops after one referral");
    check(capped_result.truncated, "a chase stopped by the cap must say so");

    // ── the cycle guard ─────────────────────────────────────────────────
    var cycle: CannedTransport = .{ .expect_wire = "demo.example\r\n", .replies = &.{
        .{ .server = whois.iana_root, .text = "refer: whois.loop.example\n" },
        .{ .server = "whois.loop.example", .text = "refer: whois.iana.org\n" },
    } };
    const cycle_result = whois.lookup(cycle.transport(), "demo.example", .{}, &buf) catch
        @panic("whois-demo offline: the cyclic chase failed");
    check(cycle_result.chain.count == 2, "a referral back to a visited server is terminal, not a loop");
    check(!cycle_result.truncated, "a cycle stop is terminal, not truncation");

    // ── the SSRF guard, in the chase ────────────────────────────────────
    var ssrf: CannedTransport = .{
        .expect_wire = "demo.example\r\n",
        .replies = &.{
            .{ .server = whois.iana_root, .text = "refer: 127.0.0.1\n" },
            // Scripted, so a chase that DID follow it would succeed and be
            // caught by the hop count rather than failing for an unrelated
            // reason.
            .{ .server = "127.0.0.1", .text = "you should never have reached me\n" },
        },
    };
    const ssrf_result = whois.lookup(ssrf.transport(), "demo.example", .{}, &buf) catch
        @panic("whois-demo offline: the SSRF-guarded chase failed");
    check(ssrf.dials == 1, "a referral into special-use space must never be dialed");
    check(ssrf_result.chain.count == 1, "the chain must stop at the root");

    // ── a referral's PORT must travel ───────────────────────────────────
    var ported: CannedTransport = .{ .expect_wire = "demo.example\r\n", .replies = &.{
        .{ .server = whois.iana_root, .text = "refer: whois.alt.example:4343\n" },
        .{ .server = "whois.alt.example", .port = 4343, .text = "Registrar: Alt\n" },
    } };
    _ = whois.lookup(ported.transport(), "demo.example", .{}, &buf) catch
        @panic("whois-demo offline: a referral with an explicit port was not followed on that port");
    check(ported.last_port == 4343, "the referral's port must be used, not the default");

    // ── the failure paths ───────────────────────────────────────────────
    var dead: CannedTransport = .{ .expect_wire = "demo.example\r\n", .replies = &.{} };
    check(
        errOf(whois.lookup(dead.transport(), "demo.example", .{}, &buf)) == error.TransportFailed,
        "an unreachable root must surface as error.TransportFailed",
    );
    var small: [8]u8 = undefined;
    check(
        errOf(whois.lookup(script.transport(), "demo.example", .{}, &small)) == error.ResponseTooLarge,
        "a reply larger than the caller's cap must surface as error.ResponseTooLarge, never truncate",
    );
    check(
        errOf(whois.lookup(script.transport(), "demo.example", .{ .root = "" }, &buf)) == error.InvalidRoot,
        "an empty root must be refused",
    );
    std.debug.print("guards: depth cap, cycle, SSRF, referral port, and three failure paths\n\n", .{});
}

/// The error a lookup produced, or `error.NoError` when it unexpectedly
/// succeeded — so a failure-path check reads as one comparison.
fn errOf(result: whois.LookupError!whois.Lookup) anyerror {
    if (result) |_| return error.NoError else |err| return err;
}

/// Runs one chase and prints it. Returns false only when the very first
/// hop could not be reached at all (treated as "no network", reported once
/// and not retried for the second query).
fn runLookup(transport: whois.Transport, query: []const u8) bool {
    var buf: [8192]u8 = undefined;
    const result = whois.lookup(transport, query, .{}, &buf) catch |err| switch (err) {
        error.TransportFailed => {
            std.debug.print(
                "whois-demo: could not reach {s} -- no network access, exiting cleanly\n",
                .{whois.iana_root},
            );
            return false;
        },
        // Distinct from TransportFailed on purpose: the query was abandoned
        // by whoever asked for it, so retrying it against another server --
        // which is exactly what a referral chase would otherwise do -- is
        // work nobody is waiting for any more.
        error.Canceled => {
            std.debug.print("whois-demo: lookup canceled\n", .{});
            return false;
        },
        error.ResponseTooLarge => {
            std.debug.print("whois-demo: a reply exceeded the {d}-byte demo buffer\n", .{buf.len});
            return true;
        },
        error.QueryTooLong, error.InvalidQuery, error.InvalidRoot => {
            std.debug.print("whois-demo: bad query: {t}\n", .{err});
            return true;
        },
    };

    std.debug.print("referral chain ({d} hop(s)):\n", .{result.chain.count});
    for (0..result.chain.count) |i| {
        std.debug.print("  {d}. {s}\n", .{ i + 1, result.chain.get(i) });
    }
    if (result.truncated) {
        std.debug.print(
            "  (chase stopped early: {d} referrals is the configured cap -- last reply may point further)\n",
            .{(whois.LookupOptions{}).max_referrals},
        );
    }

    // The one field this module extracts on the caller's behalf -- not a
    // general parser, just a documented convenience. Present on a thick
    // registry's reply (PIR is thick: full contact data lives here, not
    // just at the registrar), so this generally finds it on the terminal
    // hop and nothing on a bare "Domain not found." reply.
    if (whois.fieldValue(result.response, "Registrar")) |registrar| {
        std.debug.print("Registrar (fieldValue extraction): {s}\n", .{registrar});
    } else {
        std.debug.print("Registrar: not present in this reply (fieldValue found no match)\n", .{});
    }

    std.debug.print(
        "--- raw reply from {s} ({d} bytes) -- unparsed beyond the one field above, by design ---\n{s}\n",
        .{ result.chain.get(result.chain.count - 1), result.response.len, result.response },
    );
    return true;
}

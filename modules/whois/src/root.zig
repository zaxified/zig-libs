// SPDX-License-Identifier: MIT

//! whois — RFC 3912 WHOIS client: query formatting, referral chasing, and a
//! tiny key/value field extractor.
//!
//! RFC 3912 is one page: connect to TCP port 43, send `<query>\r\n`, read the
//! free-form text reply until the server closes. The value this module adds on
//! top of that is the **referral chain**: the bootstrap server
//! (`whois.iana.org`) and the registries answer with a pointer to the next,
//! more authoritative server (`refer:`, `ReferralServer:`,
//! `Registrar WHOIS Server:`, `whois:`), and `lookup` follows that chain —
//! depth-capped and cycle-guarded — to the terminal response.
//!
//! I/O goes through a caller-provided `Transport` seam ("send this query to
//! this server, give me the whole reply"), so everything here is offline
//! testable from canned buffers. An optional blocking `TcpTransport` over
//! `std.Io.net` is provided for real use; nothing else touches the network.
//!
//! WHOIS replies are deliberately NOT parsed beyond the referral keys —
//! every registry has its own freeform format; `fieldValue` is the only
//! (small) concession.
//!
//! Provenance: clean-room from RFC 3912 plus the documented IANA/registry
//! referral line conventions (IANA `refer:`, ARIN `ReferralServer:`, Verisign
//! `Registrar WHOIS Server:`). No third-party whois implementation was
//! consulted or copied.

const std = @import("std");

pub const meta = .{
    .status = .gap,
    .platform = .any, // codec/logic; the optional TcpTransport helper is posix
    .role = .client,
    .concurrency = .reentrant, // no shared state anywhere
    .model_after = "RFC 3912 whois; IANA/registry referral chain",
    .deps = .{}, // std only
};

// ── constants ───────────────────────────────────────────────────────────────

/// IANA WHOIS port (RFC 3912 §2).
pub const default_port: u16 = 43;

/// The IANA bootstrap server — knows the authoritative server for every
/// TLD, IP block and ASN, and answers with a `refer:` line.
pub const iana_root = "whois.iana.org";

/// Upper bound on a referral host name (DNS limit).
pub const max_host_len = 255;

/// Upper bound on the query text (before the trailing CRLF). Real WHOIS
/// queries are a domain / IP / ASN / handle — a few dozen bytes.
pub const max_query_len = 512;

// ── query formatting (RFC 3912 §2: "<query> CRLF") ─────────────────────────

pub const QueryError = error{
    /// Query exceeds `max_query_len` or the destination buffer.
    QueryTooLong,
    /// Query contains CR or LF (would inject a second WHOIS command).
    InvalidQuery,
};

/// Format `query` as an RFC 3912 wire query: `<query>\r\n`.
/// Returns a slice of `buf`. Rejects embedded CR/LF.
pub fn formatQuery(buf: []u8, query: []const u8) QueryError![]const u8 {
    if (query.len > max_query_len or query.len + 2 > buf.len) return error.QueryTooLong;
    for (query) |c| if (c == '\r' or c == '\n') return error.InvalidQuery;
    @memcpy(buf[0..query.len], query);
    buf[query.len] = '\r';
    buf[query.len + 1] = '\n';
    return buf[0 .. query.len + 2];
}

/// Documented ARIN convenience: `n <ip>` restricts the match to network
/// objects (plain `<ip>` also works but can return multiple records).
pub fn arinIpQuery(buf: []u8, ip_text: []const u8) QueryError![]const u8 {
    return prefixedQuery(buf, "n ", ip_text);
}

/// Documented Verisign convenience: `domain <name>` restricts the match to
/// domain records (a bare name can fuzzy-match nameserver/registrar objects).
pub fn verisignDomainQuery(buf: []u8, domain: []const u8) QueryError![]const u8 {
    return prefixedQuery(buf, "domain ", domain);
}

fn prefixedQuery(buf: []u8, prefix: []const u8, rest: []const u8) QueryError![]const u8 {
    if (rest.len > max_query_len - prefix.len) return error.QueryTooLong;
    if (buf.len < prefix.len) return error.QueryTooLong;
    @memcpy(buf[0..prefix.len], prefix);
    const tail = try formatQuery(buf[prefix.len..], rest);
    return buf[0 .. prefix.len + tail.len];
}

// ── transport seam ──────────────────────────────────────────────────────────

pub const TransportError = error{
    /// Connect / send / receive failed.
    TransportFailed,
    /// The reply did not fit the caller's response buffer (byte cap).
    ResponseTooLarge,
};

/// The one I/O operation WHOIS needs: connect to `server:port`, send the
/// already-formatted `query` bytes, read the whole text reply until the
/// server closes, return its length in `response_buf`. Implementations MUST
/// return `error.ResponseTooLarge` instead of truncating silently.
pub const Transport = struct {
    ctx: *anyopaque,
    exchangeFn: *const fn (
        ctx: *anyopaque,
        server: []const u8,
        port: u16,
        query: []const u8,
        response_buf: []u8,
    ) TransportError!usize,

    pub fn exchange(
        t: Transport,
        server: []const u8,
        port: u16,
        query: []const u8,
        response_buf: []u8,
    ) TransportError![]const u8 {
        const n = try t.exchangeFn(t.ctx, server, port, query, response_buf);
        if (n > response_buf.len) return error.TransportFailed;
        return response_buf[0..n];
    }
};

// ── field extraction ────────────────────────────────────────────────────────

/// First occurrence of `key: value` in a WHOIS reply, with a **non-empty**
/// value; the value is returned trimmed. Key match is at line start (leading
/// whitespace ignored), ASCII case-insensitive, and requires the colon
/// immediately after the key — `fieldValue(r, "whois")` matches `whois:` but
/// not `Whois Server:`. Returns null if absent. This is deliberately the
/// entire extent of response parsing.
pub fn fieldValue(response: []const u8, key: []const u8) ?[]const u8 {
    if (key.len == 0) return null;
    var lines = std.mem.splitScalar(u8, response, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len <= key.len) continue;
        if (!std.ascii.startsWithIgnoreCase(line, key)) continue;
        if (line[key.len] != ':') continue;
        const value = std.mem.trim(u8, line[key.len + 1 ..], " \t");
        if (value.len == 0) continue;
        return value;
    }
    return null;
}

// ── referral extraction ─────────────────────────────────────────────────────

/// The next server to ask, as extracted from a referral line.
pub const Referral = struct {
    host: []const u8, // slice into the response / input text
    port: u16 = default_port,
};

/// Parse a referral server reference as the registries write it:
/// `whois://host[:port][/]`, `host[:port]`, or `host`. Anything with another
/// scheme (`rwhois://…` is a different protocol) or a malformed host/port is
/// rejected with null.
pub fn parseServerRef(text: []const u8) ?Referral {
    var s = std.mem.trim(u8, text, " \t\r");
    if (std.ascii.startsWithIgnoreCase(s, "whois://")) {
        s = s["whois://".len..];
    } else if (std.mem.indexOf(u8, s, "://") != null) {
        return null; // rwhois://, http://, … — not RFC 3912
    }
    if (std.mem.indexOfScalar(u8, s, '/')) |i| s = s[0..i]; // trailing "/" or path
    var host = s;
    var port: u16 = default_port;
    if (std.mem.indexOfScalar(u8, s, ':')) |i| {
        host = s[0..i];
        port = std.fmt.parseInt(u16, s[i + 1 ..], 10) catch return null;
        if (port == 0) return null;
    }
    if (host.len == 0 or host.len > max_host_len) return null;
    for (host) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '-' or c == '_')) return null;
    }
    return .{ .host = host, .port = port };
}

/// Referral line keys the ecosystem actually emits, in lookup priority:
/// `refer:` (IANA bootstrap), `ReferralServer:` (ARIN), `Registrar WHOIS
/// Server:` (Verisign thin registry), `whois:` (IANA TLD records).
pub const referral_keys = [_][]const u8{
    "refer",
    "ReferralServer",
    "Registrar WHOIS Server",
    "whois",
};

/// Scan a raw WHOIS reply for a referral to a more authoritative server.
/// Returns null for a terminal reply (no usable referral). Never errors on
/// malformed/empty/garbage input.
pub fn nextServer(response: []const u8) ?Referral {
    for (referral_keys) |key| {
        const value = fieldValue(response, key) orelse continue;
        if (parseServerRef(value)) |ref| return ref;
    }
    return null;
}

// ── lookup: referral chasing ────────────────────────────────────────────────

pub const LookupOptions = struct {
    /// Server to start at. The IANA bootstrap resolves any TLD/IP/ASN;
    /// point it directly at a registry if you already know it.
    root: []const u8 = iana_root,
    /// Port for the root server (referral-specified ports override later hops).
    port: u16 = default_port,
    /// Maximum referrals to follow after the root (clamped to
    /// `Chain.capacity - 1`).
    max_referrals: u8 = 5,
};

/// The servers consulted, in order, root first. Fixed storage — host names
/// are copied so they survive response-buffer reuse across hops.
pub const Chain = struct {
    pub const capacity = 8;

    hosts: [capacity][max_host_len]u8 = undefined,
    lens: [capacity]usize = @splat(0),
    count: usize = 0,

    pub fn get(c: *const Chain, i: usize) []const u8 {
        return c.hosts[i][0..c.lens[i]];
    }

    /// ASCII case-insensitive membership — the cycle guard.
    pub fn contains(c: *const Chain, host: []const u8) bool {
        for (0..c.count) |i| {
            if (std.ascii.eqlIgnoreCase(c.get(i), host)) return true;
        }
        return false;
    }

    fn append(c: *Chain, host: []const u8) bool {
        if (c.count >= capacity or host.len > max_host_len) return false;
        @memcpy(c.hosts[c.count][0..host.len], host);
        c.lens[c.count] = host.len;
        c.count += 1;
        return true;
    }
};

pub const Lookup = struct {
    /// Final (most authoritative) response text; a slice of the caller's
    /// `response_buf`.
    response: []const u8,
    /// Every server consulted, in order (root first).
    chain: Chain,
    /// True if a further referral existed but the depth cap stopped the
    /// chase; `response` is then the deepest reply obtained.
    truncated: bool,
};

pub const LookupError = QueryError || TransportError || error{
    /// `LookupOptions.root` is empty or longer than `max_host_len`.
    InvalidRoot,
};

/// WHOIS lookup with referral chasing: query `opts.root` (default the IANA
/// bootstrap), follow `refer:` / `ReferralServer:` / `Registrar WHOIS
/// Server:` referrals up to `opts.max_referrals` hops, stop on a terminal
/// reply, a self-referral, or any cycle. `response_buf` is reused per hop —
/// its length is the per-response byte cap (the transport must return
/// `error.ResponseTooLarge` rather than truncate).
pub fn lookup(
    transport: Transport,
    query: []const u8,
    opts: LookupOptions,
    response_buf: []u8,
) LookupError!Lookup {
    var query_buf: [max_query_len + 2]u8 = undefined;
    const wire = try formatQuery(&query_buf, query);

    var chain: Chain = .{};
    if (opts.root.len == 0 or !chain.append(opts.root)) return error.InvalidRoot;
    const max_servers: usize = @min(@as(usize, opts.max_referrals) + 1, Chain.capacity);

    var port = opts.port;
    while (true) {
        const server = chain.get(chain.count - 1);
        const response = try transport.exchange(server, port, wire, response_buf);

        const ref = nextServer(response) orelse
            return .{ .response = response, .chain = chain, .truncated = false };
        if (chain.contains(ref.host)) // self-referral / cycle: this is terminal
            return .{ .response = response, .chain = chain, .truncated = false };
        if (chain.count >= max_servers or !chain.append(ref.host))
            return .{ .response = response, .chain = chain, .truncated = true };
        port = ref.port;
    }
}

// ── optional real transport: TCP over std.Io.net ────────────────────────────
// Convenience only — nothing in the logic or tests needs it, and no test
// below ever touches the network.

/// Blocking RFC 3912 transport over `std.Io.net`: resolve + connect to
/// `server:port`, send the query, read the reply to EOF.
pub const TcpTransport = struct {
    io: std.Io,

    pub fn transport(t: *TcpTransport) Transport {
        return .{ .ctx = t, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(
        ctx: *anyopaque,
        server: []const u8,
        port: u16,
        query: []const u8,
        response_buf: []u8,
    ) TransportError!usize {
        const t: *TcpTransport = @ptrCast(@alignCast(ctx));

        const host = std.Io.net.HostName.init(server) catch return error.TransportFailed;
        const stream = host.connect(t.io, port, .{ .mode = .stream }) catch
            return error.TransportFailed;
        defer stream.close(t.io);

        var wbuf: [max_query_len + 2]u8 = undefined;
        var sw = stream.writer(t.io, &wbuf);
        sw.interface.writeAll(query) catch return error.TransportFailed;
        sw.interface.flush() catch return error.TransportFailed;

        var rbuf: [4096]u8 = undefined;
        var sr = stream.reader(t.io, &rbuf);
        const n = sr.interface.readSliceShort(response_buf) catch
            return error.TransportFailed;
        if (n == response_buf.len) {
            // Buffer exactly full — distinguish "fit exactly" from "more coming".
            var extra: [1]u8 = undefined;
            const m = sr.interface.readSliceShort(&extra) catch
                return error.TransportFailed;
            if (m != 0) return error.ResponseTooLarge;
        }
        return n;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// Scripted transport: canned server→response map, plus a call log, so every
// lookup test runs offline. Behaves like a real transport: bounded copy into
// response_buf, ResponseTooLarge on overflow, TransportFailed for unknown
// servers.
const ScriptedTransport = struct {
    entries: []const Entry,
    calls: [Chain.capacity]Call = undefined,
    call_count: usize = 0,

    const Entry = struct { server: []const u8, response: []const u8 };
    const Call = struct {
        server: [max_host_len]u8,
        server_len: usize,
        port: u16,
        query: [64]u8,
        query_len: usize,

        fn serverName(c: *const Call) []const u8 {
            return c.server[0..c.server_len];
        }

        fn queryText(c: *const Call) []const u8 {
            return c.query[0..c.query_len];
        }
    };

    fn transport(s: *ScriptedTransport) Transport {
        return .{ .ctx = s, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(
        ctx: *anyopaque,
        server: []const u8,
        port: u16,
        query: []const u8,
        response_buf: []u8,
    ) TransportError!usize {
        const s: *ScriptedTransport = @ptrCast(@alignCast(ctx));
        if (s.call_count < s.calls.len and
            server.len <= max_host_len and query.len <= 64)
        {
            const c = &s.calls[s.call_count];
            @memcpy(c.server[0..server.len], server);
            c.server_len = server.len;
            c.port = port;
            @memcpy(c.query[0..query.len], query);
            c.query_len = query.len;
            s.call_count += 1;
        }
        for (s.entries) |e| {
            if (!std.ascii.eqlIgnoreCase(e.server, server)) continue;
            if (e.response.len > response_buf.len) return error.ResponseTooLarge;
            @memcpy(response_buf[0..e.response.len], e.response);
            return e.response.len;
        }
        return error.TransportFailed;
    }
};

// Canned replies modeled on the real line conventions (texts abridged).
const iana_reply =
    "% IANA WHOIS server\n" ++
    "% for more information on IANA, visit http://www.iana.org\n" ++
    "\n" ++
    "refer:        whois.verisign-grs.com\n" ++
    "\n" ++
    "domain:       COM\n" ++
    "organisation: VeriSign Global Registry Services\n";

const verisign_reply =
    "   Domain Name: EXAMPLE.COM\n" ++
    "   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\n" ++
    "   Registrar WHOIS Server: whois.markmonitor.com\n" ++
    "   Registrar URL: http://www.markmonitor.com\n";

const terminal_reply =
    "Domain Name: example.com\n" ++
    "Registrant Organization: Internet Assigned Numbers Authority\n" ++
    "DNSSEC: signedDelegation\n";

test "formatQuery round-trips per RFC 3912" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("example.com\r\n", try formatQuery(&buf, "example.com"));
    try testing.expectEqualStrings("\r\n", try formatQuery(&buf, "")); // legal: empty query
}

test "formatQuery enforces length and rejects CRLF injection" {
    var buf: [600]u8 = undefined;
    const long = "x" ** (max_query_len + 1);
    try testing.expectError(error.QueryTooLong, formatQuery(&buf, long));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.QueryTooLong, formatQuery(&tiny, "toolongforbuf"));
    try testing.expectError(error.InvalidQuery, formatQuery(&buf, "a.com\r\nb.com"));
}

test "documented query conveniences" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("n 192.0.2.1\r\n", try arinIpQuery(&buf, "192.0.2.1"));
    try testing.expectEqualStrings(
        "domain example.com\r\n",
        try verisignDomainQuery(&buf, "example.com"),
    );
    try testing.expectError(error.QueryTooLong, arinIpQuery(&buf, "x" ** max_query_len));
}

test "fieldValue: case-insensitive key, trimmed value, skips empty" {
    const r = "  Registrar WHOIS Server:   \n" ++ // empty value — skipped
        "  registrar whois server:  whois.markmonitor.com \r\n" ++
        "Refer: keep.out\n";
    try testing.expectEqualStrings(
        "whois.markmonitor.com",
        fieldValue(r, "Registrar WHOIS Server").?,
    );
    // colon must follow the key directly: "whois" must not match "Whois Server:"
    try testing.expect(fieldValue("Whois Server: x.example\n", "whois") == null);
    try testing.expect(fieldValue(r, "missing") == null);
    try testing.expect(fieldValue("", "refer") == null);
    try testing.expect(fieldValue(r, "") == null);
}

test "parseServerRef: whois:// URL form, ports, rejects other schemes/garbage" {
    const a = parseServerRef("whois://whois.example.net:43").?;
    try testing.expectEqualStrings("whois.example.net", a.host);
    try testing.expectEqual(@as(u16, 43), a.port);

    const b = parseServerRef(" whois://whois.example.net:4343/ ").?;
    try testing.expectEqual(@as(u16, 4343), b.port);

    const c = parseServerRef("whois.iana.org").?;
    try testing.expectEqualStrings("whois.iana.org", c.host);
    try testing.expectEqual(default_port, c.port);

    try testing.expect(parseServerRef("rwhois://rwhois.example.net:4321/") == null);
    try testing.expect(parseServerRef("http://example.com") == null);
    try testing.expect(parseServerRef("host:0") == null);
    try testing.expect(parseServerRef("host:notaport") == null);
    try testing.expect(parseServerRef("no spaces allowed") == null);
    try testing.expect(parseServerRef("") == null);
    try testing.expect(parseServerRef("x" ** (max_host_len + 1)) == null);
}

test "nextServer: known-answer referral extraction" {
    try testing.expectEqualStrings("whois.verisign-grs.com", nextServer(iana_reply).?.host);
    try testing.expectEqualStrings("whois.markmonitor.com", nextServer(verisign_reply).?.host);
    const arin = "ReferralServer: whois://whois.ripe.net\n";
    try testing.expectEqualStrings("whois.ripe.net", nextServer(arin).?.host);
    try testing.expect(nextServer(terminal_reply) == null);
    try testing.expect(nextServer("") == null);
    try testing.expect(nextServer("\x00\xff garbage \r\r\n::!") == null);
}

test "lookup: follows the IANA → Verisign → registrar chain" {
    var scripted: ScriptedTransport = .{ .entries = &.{
        .{ .server = "whois.iana.org", .response = iana_reply },
        .{ .server = "whois.verisign-grs.com", .response = verisign_reply },
        .{ .server = "whois.markmonitor.com", .response = terminal_reply },
    } };
    var buf: [1024]u8 = undefined;
    const result = try lookup(scripted.transport(), "example.com", .{}, &buf);

    try testing.expectEqualStrings(terminal_reply, result.response);
    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 3), result.chain.count);
    try testing.expectEqualStrings("whois.iana.org", result.chain.get(0));
    try testing.expectEqualStrings("whois.verisign-grs.com", result.chain.get(1));
    try testing.expectEqualStrings("whois.markmonitor.com", result.chain.get(2));
    // Wire format on every hop: "<query>\r\n" at port 43.
    for (scripted.calls[0..scripted.call_count]) |*c| {
        try testing.expectEqualStrings("example.com\r\n", c.queryText());
        try testing.expectEqual(default_port, c.port);
    }
}

test "lookup: self-referral stops cleanly" {
    // Registrar reply names itself as the WHOIS server — the common terminal case.
    const self_ref =
        "Registrar WHOIS Server: whois.markmonitor.com\n" ++
        "Domain Name: example.com\n";
    var scripted: ScriptedTransport = .{ .entries = &.{
        .{ .server = "whois.markmonitor.com", .response = self_ref },
    } };
    var buf: [512]u8 = undefined;
    const result = try lookup(
        scripted.transport(),
        "example.com",
        .{ .root = "whois.markmonitor.com" },
        &buf,
    );
    try testing.expectEqual(@as(usize, 1), result.chain.count);
    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 1), scripted.call_count);
}

test "lookup: two-server cycle stops at the guard (case-insensitive)" {
    var scripted: ScriptedTransport = .{ .entries = &.{
        .{ .server = "a.example", .response = "refer: b.example\n" },
        .{ .server = "b.example", .response = "refer: A.EXAMPLE\n" },
    } };
    var buf: [256]u8 = undefined;
    const result = try lookup(scripted.transport(), "q", .{ .root = "a.example" }, &buf);
    try testing.expectEqual(@as(usize, 2), result.chain.count);
    try testing.expect(!result.truncated); // cycle = terminal, not a cap hit
    try testing.expectEqualStrings("refer: A.EXAMPLE\n", result.response);
}

test "lookup: depth cap honored and reported as truncated" {
    var scripted: ScriptedTransport = .{ .entries = &.{
        .{ .server = "s0.example", .response = "refer: s1.example\n" },
        .{ .server = "s1.example", .response = "refer: s2.example\n" },
        .{ .server = "s2.example", .response = "refer: s3.example\n" },
        .{ .server = "s3.example", .response = "refer: s4.example\n" },
    } };
    var buf: [256]u8 = undefined;
    const result = try lookup(
        scripted.transport(),
        "q",
        .{ .root = "s0.example", .max_referrals = 2 },
        &buf,
    );
    try testing.expect(result.truncated);
    try testing.expectEqual(@as(usize, 3), result.chain.count); // root + 2 referrals
    try testing.expectEqual(@as(usize, 3), scripted.call_count);
    try testing.expectEqualStrings("refer: s3.example\n", result.response);
}

test "lookup: max_referrals clamped to chain capacity" {
    var scripted: ScriptedTransport = .{ .entries = &.{
        .{ .server = "s0.example", .response = "refer: s1.example\n" },
        .{ .server = "s1.example", .response = "refer: s2.example\n" },
        .{ .server = "s2.example", .response = "refer: s3.example\n" },
        .{ .server = "s3.example", .response = "refer: s4.example\n" },
        .{ .server = "s4.example", .response = "refer: s5.example\n" },
        .{ .server = "s5.example", .response = "refer: s6.example\n" },
        .{ .server = "s6.example", .response = "refer: s7.example\n" },
        .{ .server = "s7.example", .response = "refer: s8.example\n" },
    } };
    var buf: [256]u8 = undefined;
    const result = try lookup(
        scripted.transport(),
        "q",
        .{ .root = "s0.example", .max_referrals = 255 },
        &buf,
    );
    try testing.expect(result.truncated);
    try testing.expectEqual(Chain.capacity, result.chain.count);
}

test "lookup: empty and garbage responses are clean terminals" {
    var scripted: ScriptedTransport = .{ .entries = &.{
        .{ .server = "empty.example", .response = "" },
    } };
    var buf: [256]u8 = undefined;
    const r1 = try lookup(scripted.transport(), "q", .{ .root = "empty.example" }, &buf);
    try testing.expectEqualStrings("", r1.response);
    try testing.expectEqual(@as(usize, 1), r1.chain.count);

    var garbage: ScriptedTransport = .{ .entries = &.{
        .{ .server = "junk.example", .response = "\x00\x01\xfe\xffrefer\n:::\r\r" },
    } };
    const r2 = try lookup(garbage.transport(), "q", .{ .root = "junk.example" }, &buf);
    try testing.expect(!r2.truncated);
    try testing.expectEqual(@as(usize, 1), r2.chain.count);
}

test "lookup: byte cap — oversized response surfaces ResponseTooLarge" {
    var scripted: ScriptedTransport = .{ .entries = &.{
        .{ .server = "big.example", .response = "x" ** 128 },
    } };
    var small: [64]u8 = undefined;
    try testing.expectError(
        error.ResponseTooLarge,
        lookup(scripted.transport(), "q", .{ .root = "big.example" }, &small),
    );
}

test "lookup: referral port from whois:// URL is used on the next hop" {
    var scripted: ScriptedTransport = .{ .entries = &.{
        .{ .server = "root.example", .response = "refer: whois://next.example:4343\n" },
        .{ .server = "next.example", .response = terminal_reply },
    } };
    var buf: [512]u8 = undefined;
    const result = try lookup(scripted.transport(), "q", .{ .root = "root.example" }, &buf);
    try testing.expectEqual(@as(usize, 2), result.chain.count);
    try testing.expectEqual(@as(u16, 4343), scripted.calls[1].port);
    try testing.expectEqual(default_port, scripted.calls[0].port);
}

test "lookup: invalid root and oversized query rejected up front" {
    var scripted: ScriptedTransport = .{ .entries = &.{} };
    var buf: [64]u8 = undefined;
    try testing.expectError(
        error.InvalidRoot,
        lookup(scripted.transport(), "q", .{ .root = "" }, &buf),
    );
    try testing.expectError(
        error.InvalidRoot,
        lookup(scripted.transport(), "q", .{ .root = "x" ** (max_host_len + 1) }, &buf),
    );
    try testing.expectError(
        error.QueryTooLong,
        lookup(scripted.transport(), "x" ** (max_query_len + 1), .{}, &buf),
    );
    try testing.expectEqual(@as(usize, 0), scripted.call_count); // never hit the wire
}

test "lookup: transport failure propagates" {
    var scripted: ScriptedTransport = .{ .entries = &.{} }; // knows no servers
    var buf: [64]u8 = undefined;
    try testing.expectError(
        error.TransportFailed,
        lookup(scripted.transport(), "example.com", .{}, &buf),
    );
}

test "TcpTransport compiles (never dialed in tests)" {
    // Reference the optional real transport so it is semantically checked
    // without any network activity.
    _ = TcpTransport.exchangeFn;
    _ = TcpTransport.transport;
}

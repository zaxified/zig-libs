// SPDX-License-Identifier: MIT

//! `rdap-demo` — what a real RDAP consumer does with this module: bootstrap
//! through the IANA registry (RFC 9224), query the authoritative RDAP
//! server for a domain, and print the registration the way a person reads
//! it — handle, status, the events that matter, nameservers, and (the
//! reason anyone actually runs an RDAP query) the registrar's **abuse
//! contact**. That contact is reached two levels deep —
//! `o.entityWithRole("registrar").?.entityWithRole("abuse")` — through the
//! registrar entity's own nested `entities[]` (RFC 9083 §5.1); commit
//! `68303af` is what made that nesting reachable from outside the module at
//! all. This example also shows the two things `68303af` added alongside
//! it: the HTTP status out-pointer (`Client.query`'s `status_out`), which
//! turns a bare failure into "the registry is rate-limiting you (429)"
//! instead of an opaque error; and the `redacted` array (RFC 9537), which
//! says a field was **withheld under GDPR** rather than just leaving it
//! absent — those are different things, and a good tool says which.
//!
//! Layers exercised, in order: raw JSON fetch + `parseBootstrap` (RFC
//! 9224) to find the right server — the bootstrap file is plain JSON, not
//! RDAP, so it goes straight through `http.Client`, not through
//! `rdap.Client`; `Bootstrap.lookupDomain`/`.lookupIp` (longest-match) to
//! pick a base URL; `Client.query` (build URL → fetch → parse) to reach
//! it; the typed `Object` model to read the result. `rdap.HttpFetcher`
//! wraps the same `http.Client` for the RDAP hop, so only one connection
//! pool exists for the whole run.
//!
//! **Two halves.** The first needs no network at all: frozen bootstrap and
//! RDAP bodies are driven through `parseBootstrap` / `buildUrl` /
//! `Client.query` (over a canned `Fetcher`) / the typed `Object` model, and
//! every interesting value is ASSERTED — a mismatch panics, it does not
//! print. That half runs identically on a machine with no route to the
//! internet, which is what makes this example a check rather than a
//! demonstration. The second half is the live one: it says so and exits 0
//! when there is no network, rather than propagating a raw connect error.
//!
//! Built against the PUBLISHED module (`@import("rdap")`) only.

const std = @import("std");
const rdap = @import("rdap");
const http = @import("http");

/// A domain `src/goldens.zig` already captured a real, live PIR response
/// for (GDPR-redacted handle, nested entities, publicIds, nameserver glue
/// addresses) — so this run's shape can be sanity-checked against that
/// fixture's shape.
const demo_domain = "iana.org";
/// Same TLD, unregistered by construction: the 404 -> `error.NotFound` path.
const missing_domain = "this-domain-should-not-exist-zig-libs-rdap-demo-2026.org";
/// A stable, well-known IPv4 address (Cloudflare public DNS) — the second
/// query type this module's URL/bootstrap layers support alongside domains.
const demo_ip = "1.1.1.1";

const iana_dns_bootstrap_url = "https://data.iana.org/rdap/dns.json";
const iana_ipv4_bootstrap_url = "https://data.iana.org/rdap/ipv4.json";

/// The largest of the IANA bootstrap files (`dns.json`) runs under 100 KiB
/// today; this covers it with generous room to spare.
const bootstrap_max_len = 4 << 20;
/// Per-response byte cap for the RDAP hop itself (`Client.query`'s
/// `body_buf`) — real RDAP objects run tens of KiB even with several
/// nested entities.
const body_buf_len = 256 * 1024;

pub fn main() u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── half one: no network, everything asserted ────────────────────────
    runOfflineChecks(gpa);

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client: http.Client = .init(io, gpa, .{
        .connect_timeout_ms = 5000,
        .total_timeout_ms = 15000,
    });
    defer client.deinit();

    // ── bootstrap: find the right server for the TLD (RFC 9224) ─────────
    const dns_bootstrap_json = client.getAlloc(gpa, iana_dns_bootstrap_url, bootstrap_max_len) catch |err|
        return reportBootstrapFailure("dns", err);
    defer gpa.free(dns_bootstrap_json);

    var dns_bootstrap = rdap.parseBootstrap(gpa, dns_bootstrap_json) catch |err| {
        std.debug.print("rdap-demo: IANA dns.json did not parse: {t}\n", .{err});
        return 1;
    };
    defer dns_bootstrap.deinit();

    var fetcher_impl = rdap.HttpFetcher{ .client = &client };
    var rdap_client: rdap.Client = .{ .fetcher = fetcher_impl.fetcher(), .gpa = gpa };

    std.debug.print("=== domain lookup: {s} ===\n", .{demo_domain});
    runDomainLookup(&rdap_client, &dns_bootstrap, demo_domain);

    std.debug.print("\n=== failure path: {s} (expect RDAP 404 -> NotFound) ===\n", .{missing_domain});
    runDomainLookup(&rdap_client, &dns_bootstrap, missing_domain);

    // ── a second query type: IP, its own bootstrap file ──────────────────
    const ipv4_bootstrap_json = client.getAlloc(gpa, iana_ipv4_bootstrap_url, bootstrap_max_len) catch |err| {
        std.debug.print(
            "\nrdap-demo: could not fetch the IPv4 bootstrap file ({t}) -- skipping the IP lookup\n",
            .{err},
        );
        return 0;
    };
    defer gpa.free(ipv4_bootstrap_json);

    var ipv4_bootstrap = rdap.parseBootstrap(gpa, ipv4_bootstrap_json) catch |err| {
        std.debug.print("rdap-demo: IANA ipv4.json did not parse: {t}\n", .{err});
        return 1;
    };
    defer ipv4_bootstrap.deinit();

    std.debug.print("\n=== ip lookup: {s} ===\n", .{demo_ip});
    runIpLookup(&rdap_client, &ipv4_bootstrap, demo_ip);

    return 0;
}

// ── half one: the offline checks ─────────────────────────────────────────
//
// Frozen bodies driven through the same published entry points the live half
// uses -- `parseBootstrap`, `Bootstrap.lookupDomain`/`.lookupIp`, `buildUrl`,
// `Client.query` over a canned `Fetcher`, `parseResponse`, and the typed
// `Object` model. Everything is ASSERTED: a mismatch panics. That is the
// point. Before this half existed, a run on a machine with no route to the
// internet printed "no network access ... exiting cleanly", exited 0, and had
// exercised nothing at all -- a green row in the repository's example gate
// that proved only that the program starts.

fn check(ok: bool, comptime what: []const u8) void {
    if (!ok) @panic("rdap-demo offline: " ++ what);
}

fn checkStr(expected: []const u8, actual: ?[]const u8, comptime what: []const u8) void {
    const got = actual orelse @panic("rdap-demo offline: " ++ what ++ " (absent)");
    if (!std.mem.eql(u8, expected, got)) @panic("rdap-demo offline: " ++ what);
}

/// The first URL of a bootstrap hit, or null if the lookup missed — so a
/// miss reads as "absent" through `checkStr` rather than needing an unwrap
/// at every call site.
fn firstUrl(urls: ?[]const []const u8) ?[]const u8 {
    const u = urls orelse return null;
    return if (u.len == 0) null else u[0];
}

/// A scripted query that MUST fail, and must fail with exactly `expected`.
/// Written out rather than inlined because an unexpected success returns a
/// `Parsed` that has to be freed before the panic — a demo that leaks on its
/// own failure path is not much of a leak detector.
fn expectQueryError(
    client: *rdap.Client,
    value: []const u8,
    body_buf: []u8,
    status: *u16,
    expected: anyerror,
    comptime what: []const u8,
) void {
    if (client.query("https://rdap.thin.example/", .domain, value, .{}, body_buf, status)) |p| {
        var owned = p;
        owned.deinit();
        @panic("rdap-demo offline: " ++ what ++ " (the query unexpectedly succeeded)");
    } else |err| {
        if (err != expected) {
            std.debug.print("rdap-demo offline: got {t}\n", .{err});
            @panic("rdap-demo offline: " ++ what);
        }
    }
}

/// An IANA-shaped DNS bootstrap file (RFC 9224 §4), trimmed to three
/// services. `example.org` is deliberately a TWO-label key: the registry's
/// keys are domain names and need not be TLDs, which is exactly why the
/// module's match rule is longest-suffix rather than "the final label".
const canned_dns_bootstrap =
    \\{
    \\  "version": "1.0",
    \\  "publication": "2026-01-01T00:00:00Z",
    \\  "services": [
    \\    [ ["org"],           ["https://rdap.pir.example/rdap/"] ],
    \\    [ ["com", "net"],    ["https://rdap.verisign.example/v1/"] ],
    \\    [ ["example.org"],   ["https://rdap.deeper.example/"] ]
    \\  ]
    \\}
;

/// An IANA-shaped IPv4 bootstrap file: two overlapping CIDRs, so the
/// longest-prefix rule has something to decide.
const canned_ipv4_bootstrap =
    \\{
    \\  "version": "1.0",
    \\  "services": [
    \\    [ ["1.0.0.0/8"],   ["https://rdap.apnic.example/"] ],
    \\    [ ["1.1.1.0/24"],  ["https://rdap.narrower.example/"] ]
    \\  ]
    \\}
;

/// A thin registry's answer: almost nothing except the `rel:"related"` link
/// pointing at the registrar's own RDAP server. This is the shape that makes
/// `QueryOptions.follow_related` necessary.
const canned_thin_response =
    \\{
    \\  "objectClassName": "domain",
    \\  "handle": "THIN-HANDLE",
    \\  "ldhName": "demo.example",
    \\  "links": [
    \\    { "rel": "self",    "href": "https://rdap.thin.example/domain/demo.example" },
    \\    { "rel": "related", "href": "https://rdap.registrar.example/domain/demo.example" }
    \\  ]
    \\}
;

/// The registrar's fuller answer: the nested `registrar` -> `abuse` entity
/// chain (RFC 9083 §5.1), events, nameserver glue, and an RFC 9537
/// `redacted[]` disclosure. Every one of those is read back below.
const canned_registrar_response =
    \\{
    \\  "rdapConformance": ["rdap_level_0", "redacted"],
    \\  "objectClassName": "domain",
    \\  "handle": "D-2026-DEMO",
    \\  "ldhName": "demo.example",
    \\  "status": ["client transfer prohibited", "server delete prohibited"],
    \\  "events": [
    \\    { "eventAction": "registration", "eventDate": "1995-01-01T05:00:00Z" },
    \\    { "eventAction": "expiration",   "eventDate": "2027-01-01T05:00:00Z" },
    \\    { "eventAction": "last changed", "eventDate": "2026-06-30T12:00:00Z" }
    \\  ],
    \\  "nameservers": [
    \\    { "objectClassName": "nameserver", "ldhName": "ns1.demo.example",
    \\      "ipAddresses": { "v4": ["192.0.2.53"], "v6": ["2001:db8::53"] } },
    \\    { "objectClassName": "nameserver", "ldhName": "ns2.demo.example" }
    \\  ],
    \\  "entities": [
    \\    {
    \\      "objectClassName": "entity",
    \\      "handle": "9999",
    \\      "roles": ["registrar"],
    \\      "publicIds": [ { "type": "IANA Registrar ID", "identifier": "9999" } ],
    \\      "vcardArray": ["vcard", [
    \\        ["version", {}, "text", "4.0"],
    \\        ["fn", {}, "text", "Demo Registrar, Inc."]
    \\      ]],
    \\      "entities": [
    \\        {
    \\          "objectClassName": "entity",
    \\          "roles": ["abuse"],
    \\          "vcardArray": ["vcard", [
    \\            ["version", {}, "text", "4.0"],
    \\            ["fn", {}, "text", "Demo Registrar Abuse Desk"],
    \\            ["email", {}, "text", "abuse@registrar.example"]
    \\          ]]
    \\        }
    \\      ]
    \\    }
    \\  ],
    \\  "redacted": [
    \\    { "name": { "type": "Registrant Name" }, "prePath": "$.entities[?(@.roles[0]=='registrant')]",
    \\      "pathLang": "jsonpath", "method": "removal" }
    \\  ]
    \\}
;

/// An RFC 7480 §5.3 error body — the machine-readable form a registry uses
/// for "no such object", as opposed to a bare HTTP status.
const canned_rdap_error =
    \\{ "errorCode": 404, "title": "Domain not found",
    \\  "description": ["The domain you are looking for is not registered."] }
;

/// A `Fetcher` answering from a frozen script instead of the network. The
/// match is on the FULL url, so an unscripted URL is a miss -- which means
/// this also pins the URL `Client.query` built via `buildUrl`, not just the
/// body it parsed.
const CannedFetcher = struct {
    const Reply = struct { url: []const u8, status: u16, body: []const u8 };

    replies: []const Reply,
    hits: usize = 0,

    fn fetcher(f: *CannedFetcher) rdap.Fetcher {
        return .{ .ctx = f, .fetchFn = fetchFn };
    }

    fn fetchFn(ctx: *anyopaque, url: []const u8, body_buf: []u8) rdap.FetchError!rdap.Fetcher.Result {
        const f: *CannedFetcher = @ptrCast(@alignCast(ctx));
        for (f.replies) |r| {
            if (!std.mem.eql(u8, r.url, url)) continue;
            if (r.body.len > body_buf.len) return error.ResponseTooLarge;
            @memcpy(body_buf[0..r.body.len], r.body);
            f.hits += 1;
            return .{ .status = r.status, .body_len = r.body.len };
        }
        std.debug.print("rdap-demo offline: unscripted URL fetched: {s}\n", .{url});
        @panic("rdap-demo offline: Client.query built a URL the script does not answer");
    }
};

fn runOfflineChecks(gpa: std.mem.Allocator) void {
    std.debug.print("=== offline checks (no network needed; every value asserted) ===\n", .{});

    // ── bootstrap parsing + the two match rules ─────────────────────────
    var dns = rdap.parseBootstrap(gpa, canned_dns_bootstrap) catch @panic("rdap-demo offline: canned dns.json did not parse");
    defer dns.deinit();

    checkStr("https://rdap.pir.example/rdap/", firstUrl(dns.lookupDomain("iana.org")), "org -> PIR");
    // Longest-suffix, not last-label: `example.org` must beat `org`.
    checkStr("https://rdap.deeper.example/", firstUrl(dns.lookupDomain("sub.example.org")), "longest-suffix match");
    // A trailing root dot is ignored (RFC 9224 §4).
    checkStr("https://rdap.pir.example/rdap/", firstUrl(dns.lookupDomain("iana.org.")), "trailing root dot");
    // A partial LABEL must not match: "notorg" does not end in the label "org".
    check(dns.lookupDomain("example.notorg") == null, "partial-label match must not count");
    check(dns.lookupDomain("example.museum") == null, "unknown TLD must miss");
    std.debug.print("bootstrap (DNS): longest-suffix, root dot, label boundary, miss -- all as specified\n", .{});

    var ipv4 = rdap.parseBootstrap(gpa, canned_ipv4_bootstrap) catch @panic("rdap-demo offline: canned ipv4.json did not parse");
    defer ipv4.deinit();

    // Longest PREFIX wins: 1.1.1.1 is inside both 1.0.0.0/8 and 1.1.1.0/24.
    checkStr("https://rdap.narrower.example/", firstUrl(ipv4.lookupIp("1.1.1.1")), "longest-prefix match");
    checkStr("https://rdap.apnic.example/", firstUrl(ipv4.lookupIp("1.2.3.4")), "/8 match");
    check(ipv4.lookupIp("8.8.8.8") == null, "address outside every range must miss");
    check(ipv4.lookupIp("not-an-address") == null, "unparseable address must miss, not crash");
    std.debug.print("bootstrap (IPv4): longest-prefix, miss, malformed input -- all as specified\n", .{});

    // ── URL construction, including the escaping ────────────────────────
    var url_buf: [rdap.max_url_len]u8 = undefined;
    checkStr(
        "https://rdap.example/domain/demo.example",
        rdap.buildUrl(&url_buf, "https://rdap.example/", .domain, "demo.example") catch null,
        "buildUrl: base with trailing slash",
    );
    checkStr(
        "https://rdap.example/domain/demo.example",
        rdap.buildUrl(&url_buf, "https://rdap.example", .domain, "demo.example") catch null,
        "buildUrl: base without trailing slash gets one",
    );
    // The `/` of a CIDR is percent-encoded -- it is data, not a path
    // separator, and a server handed the raw slash would see a different
    // resource entirely.
    checkStr(
        "https://rdap.example/ip/192.0.2.0%2F24",
        rdap.buildUrl(&url_buf, "https://rdap.example/", .ip, "192.0.2.0/24") catch null,
        "buildUrl: CIDR slash is escaped",
    );
    check(std.meta.isError(rdap.buildUrl(&url_buf, "", .domain, "x")), "empty base must be rejected");
    check(std.meta.isError(rdap.buildUrl(&url_buf, "https://x/", .domain, "")), "empty query must be rejected");
    std.debug.print("buildUrl: slash-joining, percent-encoding, and both refusals -- as specified\n", .{});

    // ── the whole query path, over a frozen script ──────────────────────
    var script: CannedFetcher = .{ .replies = &.{
        .{ .url = "https://rdap.thin.example/domain/demo.example", .status = 200, .body = canned_thin_response },
        .{ .url = "https://rdap.registrar.example/domain/demo.example", .status = 200, .body = canned_registrar_response },
        .{ .url = "https://rdap.thin.example/domain/gone.example", .status = 404, .body = canned_rdap_error },
        .{ .url = "https://rdap.thin.example/domain/busy.example", .status = 429, .body = "<html>too many requests</html>" },
    } };
    var client: rdap.Client = .{ .fetcher = script.fetcher(), .gpa = gpa };
    // Deliberately smaller than the live half's `body_buf_len`: the scripted
    // bodies are small, and a fetcher that would overrun the caller's cap has
    // to say `error.ResponseTooLarge` rather than truncate.
    var body_buf: [16 * 1024]u8 = undefined;
    var status: u16 = 0;

    // `follow_related`: the thin registry's answer must be REPLACED by the
    // registrar's, not merged with it and not kept.
    var parsed = client.query("https://rdap.thin.example/", .domain, "demo.example", .{ .follow_related = true }, &body_buf, &status) catch
        @panic("rdap-demo offline: the scripted domain query failed");
    defer parsed.deinit();
    check(script.hits == 2, "follow_related must make exactly two fetches");

    const o = switch (parsed.document) {
        .object => |obj| obj,
        .rdap_error => @panic("rdap-demo offline: expected an object, got an RDAP error"),
    };
    checkStr("D-2026-DEMO", o.handle, "the FOLLOWED document's handle (not the thin one's)");
    checkStr("demo.example", o.ldh_name, "ldhName");
    check(o.object_class == .domain, "objectClassName -> .domain");
    check(o.status.len == 2, "status count");
    checkStr("client transfer prohibited", o.status[0], "first status");
    checkStr("1995-01-01T05:00:00Z", o.eventDate("registration"), "registration event");
    checkStr("2027-01-01T05:00:00Z", o.eventDate("EXPIRATION"), "eventDate is case-insensitive");
    check(o.eventDate("deletion") == null, "an absent event reads null");
    check(o.nameservers.len == 2, "nameserver count");
    checkStr("ns1.demo.example", o.nameservers[0].ldh_name, "first nameserver");
    check(o.nameservers[0].ipv4_addresses.len == 1 and o.nameservers[0].ipv6_addresses.len == 1, "glue addresses");
    check(o.nameservers[1].ipv4_addresses.len == 0, "a nameserver with no glue reads empty, not absent");

    // The two-level chain this whole example exists to show.
    const registrar = o.entityWithRole("registrar") orelse @panic("rdap-demo offline: no registrar entity");
    checkStr("Demo Registrar, Inc.", registrar.full_name, "registrar jCard fn");
    checkStr("9999", registrar.handle, "registrar handle");
    check(registrar.public_ids.len == 1, "registrar publicIds");
    checkStr("IANA Registrar ID", registrar.public_ids[0].id_type, "publicId type");
    const abuse = registrar.entityWithRole("abuse") orelse @panic("rdap-demo offline: no nested abuse entity");
    checkStr("abuse@registrar.example", abuse.email, "abuse jCard email");
    // …and the nesting is real: `abuse` is NOT a top-level entity.
    check(o.entityWithRole("abuse") == null, "abuse must be nested under the registrar, not top-level");

    // RFC 9537: withheld is not the same as absent.
    check(o.redacted.len == 1, "redacted count");
    checkStr("Registrant Name", o.redacted[0].name, "redacted name");
    checkStr("removal", o.redacted[0].method, "redaction method");
    std.debug.print("query+parse: followed the related link, and read back handle, status, events,\n", .{});
    std.debug.print("  nameserver glue, registrar -> abuse nesting, publicIds and RFC 9537 redaction\n", .{});

    // ── the failure paths, which is where a demo usually lies ───────────
    expectQueryError(
        &client,
        "gone.example",
        &body_buf,
        &status,
        error.NotFound,
        "HTTP 404 must surface as error.NotFound",
    );
    var rl_status: u16 = 0;
    expectQueryError(
        &client,
        "busy.example",
        &body_buf,
        &rl_status,
        error.HttpStatus,
        "a non-2xx with an unparseable body must surface as error.HttpStatus",
    );
    check(rl_status == 429, "status_out must carry the 429 the error itself cannot");

    // A 404 whose body IS a valid RDAP error document still takes the
    // status-derived path -- `NotFound` is decided before parsing.
    var err_doc = rdap.parseResponse(gpa, canned_rdap_error) catch @panic("rdap-demo offline: canned RDAP error body did not parse");
    defer err_doc.deinit();
    switch (err_doc.document) {
        .rdap_error => |e| {
            check(e.error_code == 404, "errorCode selects the rdap_error arm");
            checkStr("Domain not found", e.title, "RDAP error title");
        },
        .object => @panic("rdap-demo offline: a body with errorCode must parse as an RDAP error"),
    }

    // Tolerant parsing is a documented promise, so it is asserted rather
    // than assumed: sparse, extra and wrong-typed members must not fail.
    var odd = rdap.parseResponse(gpa, "{\"objectClassName\":42,\"handle\":[1,2],\"unheard_of\":{}}") catch
        @panic("rdap-demo offline: tolerant parsing must not reject well-formed but surprising JSON");
    defer odd.deinit();
    check(std.meta.isError(rdap.parseResponse(gpa, "{ not json")), "malformed JSON must be rejected");
    std.debug.print("failure paths: 404, 429+status_out, RDAP error body, tolerant parse -- all as specified\n\n", .{});
}

/// `http.Client.getAlloc`'s error set is the full transport error set (not
/// collapsed the way `rdap.FetchError` collapses it) — precise enough to
/// tell "no network" apart from a real bug, which is the whole reason this
/// helper fetches the bootstrap file itself rather than through
/// `rdap.Fetcher`.
fn reportBootstrapFailure(which: []const u8, err: http.Client.Error) u8 {
    return switch (err) {
        error.ConnectFailed,
        error.TlsFailed,
        error.UnknownHostName,
        error.Timeout,
        error.CertificateBundleLoadFailure,
        error.EntropyUnavailable,
        error.Canceled,
        => blk: {
            std.debug.print("rdap-demo: no network access ({t} fetching {s}.json) -- exiting cleanly\n", .{ err, which });
            break :blk 0;
        },
        else => blk: {
            std.debug.print("rdap-demo: unexpected error fetching IANA {s}.json: {t}\n", .{ which, err });
            break :blk 1;
        },
    };
}

fn runDomainLookup(client: *rdap.Client, bootstrap: *const rdap.Bootstrap, domain: []const u8) void {
    const urls = bootstrap.lookupDomain(domain) orelse {
        std.debug.print("{s}: no RDAP server known for this TLD\n", .{domain});
        return;
    };
    const base_url = urls[0];
    std.debug.print("bootstrap: {s} -> {s}\n", .{ domain, base_url });

    var body_buf: [body_buf_len]u8 = undefined;
    var status: u16 = 0;
    // `follow_related = true`: a thin registry (Verisign for .com/.net) answers
    // with only a `rel:"related"` link to the registrar's own RDAP server,
    // which is where the fuller entity data (and the abuse contact) usually
    // lives; a thick registry like PIR (.org) already has it and the follow
    // is a harmless no-op (no "related" link to find).
    var parsed = client.query(base_url, .domain, domain, .{ .follow_related = true }, &body_buf, &status) catch |err| {
        switch (err) {
            error.NotFound => std.debug.print("{s}: not registered (RDAP 404)\n", .{domain}),
            error.HttpStatus => if (status == 429)
                std.debug.print("{s}: the registry is rate-limiting you (HTTP 429)\n", .{domain})
            else
                std.debug.print("{s}: registry returned HTTP {d} with no parseable RDAP error body\n", .{ domain, status }),
            else => std.debug.print("{s}: lookup failed: {t}\n", .{ domain, err }),
        }
        return;
    };
    defer parsed.deinit();

    switch (parsed.document) {
        .object => |o| printObject(&o),
        .rdap_error => |e| std.debug.print("{s}: RDAP error {d} {?s}\n", .{ domain, e.error_code, e.title }),
    }
}

fn runIpLookup(client: *rdap.Client, bootstrap: *const rdap.Bootstrap, addr: []const u8) void {
    const urls = bootstrap.lookupIp(addr) orelse {
        std.debug.print("{s}: no RDAP server known for this address range\n", .{addr});
        return;
    };
    const base_url = urls[0];
    std.debug.print("bootstrap: {s} -> {s}\n", .{ addr, base_url });

    var body_buf: [body_buf_len]u8 = undefined;
    var status: u16 = 0;
    var parsed = client.query(base_url, .ip, addr, .{ .follow_related = true }, &body_buf, &status) catch |err| {
        switch (err) {
            error.NotFound => std.debug.print("{s}: no RDAP record (RDAP 404)\n", .{addr}),
            error.HttpStatus => std.debug.print("{s}: registry returned HTTP {d}\n", .{ addr, status }),
            else => std.debug.print("{s}: lookup failed: {t}\n", .{ addr, err }),
        }
        return;
    };
    defer parsed.deinit();

    switch (parsed.document) {
        .object => |o| {
            std.debug.print("handle: {?s}", .{o.handle});
            if (o.name) |n| std.debug.print("  name: {s}", .{n});
            if (o.country) |c| std.debug.print("  country: {s}", .{c});
            std.debug.print("\n", .{});
            if (o.entityWithRole("abuse")) |abuse| {
                std.debug.print("abuse contact:", .{});
                if (abuse.full_name) |n| std.debug.print(" {s}", .{n});
                if (abuse.email) |e| std.debug.print(" <{s}>", .{e});
                std.debug.print("\n", .{});
            } else {
                std.debug.print("no direct abuse entity in this response\n", .{});
            }
        },
        .rdap_error => |e| std.debug.print("{s}: RDAP error {d} {?s}\n", .{ addr, e.error_code, e.title }),
    }
}

/// The full read-out for a domain object: everything a person actually
/// wants out of an RDAP query.
fn printObject(o: *const rdap.Object) void {
    std.debug.print("handle: {?s}\n", .{o.handle});
    if (o.ldh_name) |n| std.debug.print("name: {s}\n", .{n});

    std.debug.print("status:", .{});
    for (o.status) |s| std.debug.print(" {s}", .{s});
    std.debug.print("\n", .{});

    inline for (.{ "registration", "expiration", "last changed" }) |action| {
        if (o.eventDate(action)) |date| std.debug.print("{s}: {s}\n", .{ action, date });
    }

    if (o.nameservers.len > 0) {
        std.debug.print("nameservers:", .{});
        for (o.nameservers) |ns| if (ns.ldh_name) |n| std.debug.print(" {s}", .{n});
        std.debug.print("\n", .{});
    }

    // The point of the whole tool: the registrar's OWN nested entities[]
    // (RFC 9083 §5.1) — commonly its abuse desk. Unreachable before
    // 68303af flattened `Entity.entities` into the published model.
    if (o.entityWithRole("registrar")) |registrar| {
        std.debug.print("registrar:", .{});
        if (registrar.full_name) |n| std.debug.print(" {s}", .{n});
        if (registrar.handle) |h| std.debug.print(" (handle {s})", .{h});
        std.debug.print("\n", .{});

        if (registrar.entityWithRole("abuse")) |abuse| {
            std.debug.print("  abuse contact:", .{});
            if (abuse.full_name) |n| std.debug.print(" {s}", .{n});
            if (abuse.email) |e| std.debug.print(" <{s}>", .{e});
            std.debug.print("\n", .{});
        } else {
            std.debug.print("  no nested abuse entity under the registrar in this response\n", .{});
        }
    } else {
        std.debug.print("no registrar entity in this response\n", .{});
    }

    // `redacted` (RFC 9537): a field withheld under a privacy policy is a
    // different thing from a field the registry never had -- say which.
    if (o.redacted.len == 0) {
        std.debug.print("redacted fields: none disclosed\n", .{});
    } else {
        std.debug.print("redacted fields (RFC 9537 -- withheld under a privacy policy, not absent):\n", .{});
        for (o.redacted) |r| {
            std.debug.print("  {?s}", .{r.name});
            if (r.method) |m| std.debug.print(" (method: {s})", .{m});
            std.debug.print("\n", .{});
        }
    }
}

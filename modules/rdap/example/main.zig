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
//! Handles having no network the same way a well-behaved CLI does: says so
//! and exits 0, rather than propagating a raw connect error.
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

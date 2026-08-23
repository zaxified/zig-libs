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

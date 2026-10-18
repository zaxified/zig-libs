// SPDX-License-Identifier: MIT

//! acmedns — ACME DNS-01 beyond the provider call: a `Dns01Solver` for
//! `acme.Client` that follows the `_acme-challenge` CNAME delegation, finds
//! the zone by its SOA, publishes through a `Publisher` and waits until every
//! authoritative server answers; plus four generic publishers —
//! `Rfc2136` (dynamic update + TSIG: BIND, Knot, PowerDNS, Windows DNS),
//! `AcmeDns` (joohoi/acme-dns), `HttpReq` (lego's "POST to your URL") and
//! `Exec` (lego's "run your program").
//!
//! A sibling of `acme`, not part of it: DNS-01 needs a resolver (`dns`) and,
//! for the publishers, `procrun`; an `acme` consumer that solves HTTP-01 or
//! TLS-ALPN-01 should not carry either. The same split as certmagic +
//! libdns, or lego's core + its providers.
//!
//! ```zig
//! const key: dns.tsig.Key = .{ .name = "acme.", .secret = secret };
//! var rfc2136 = acmedns.Rfc2136.init(io, gpa, .{ .server = primary_ip, .key = &key });
//! var solver = acmedns.Dns01Solver.init(io, gpa, .{ .publisher = rfc2136.publisher() });
//! defer solver.deinit();
//! var client = try acme.Client.init(io, gpa, .{
//!     .challenge_type = .dns_01,
//!     .solvers = &.{solver.solver()},
//!     // ...
//! });
//! ```

const std = @import("std");

pub const meta = .{
    .doc = "ACME DNS-01: CNAME delegation, SOA zone walk, propagation check; RFC 2136+TSIG, acme-dns, httpreq, exec publishers",
    .platform_note = "linux (exec publisher: posix process spawn)",
    .targets = .{.linux64},
    .platform = .posix,
    .role = .client,
    .concurrency = .single_owner, // one solver per acme.Client, like the client
    .model_after = "lego (challenge/dns01 + providers rfc2136, acmedns, httpreq, exec) / certmagic DNS01Solver",
    .deps = .{ "acme", "dns", "http", "netaddr", "procrun", "b64ct" }, // dns: resolver + RFC 2136/TSIG; http: acme-dns, httpreq; procrun: exec; also uses std.json
};

/// The `acme.Client.Solver` for DNS-01.
pub const Dns01Solver = @import("Dns01Solver.zig");

/// CNAME walk, SOA zone discovery, NS lookup, the per-server TXT check.
pub const zone = @import("zone.zig");

const publishers = @import("publishers.zig");
/// RFC 2136 dynamic update, optionally TSIG-signed.
pub const Rfc2136 = publishers.Rfc2136;
/// joohoi/acme-dns: one authenticated POST per value.
pub const AcmeDns = publishers.AcmeDns;
/// lego's `httpreq`: POST `<endpoint>/present` and `/cleanup`.
pub const HttpReq = publishers.HttpReq;
/// lego's `exec`: run `<program> present|cleanup <fqdn> <value>`.
pub const Exec = publishers.Exec;

/// What a publisher must put in DNS (or take out again).
pub const Record = struct {
    /// The authorization's identifier (the base name for a wildcard).
    domain: []const u8,
    /// Where the TXT record goes: `_acme-challenge.<domain>`, or the end of
    /// its CNAME chain (no trailing dot).
    fqdn: []const u8,
    /// The zone `fqdn` is in (no trailing dot).
    zone: []const u8,
    /// The TXT value: base64url(SHA-256(key authorization)), 43 characters.
    value: []const u8,
    /// The challenge token and key authorization, for a publisher that
    /// hands the raw challenge to someone else (lego's RAW modes).
    token: []const u8,
    key_authorization: []const u8,
};

pub const PublishError = error{ OutOfMemory, PublishFailed };

/// A DNS provider seam: lego's `challenge.Provider`, libdns's
/// `RecordAppender`/`RecordDeleter`. `present` must ADD the value (a
/// wildcard and its base name validate at the same name at once) and may
/// return before the record is visible — `Dns01Solver` waits for it.
pub const Publisher = struct {
    ctx: ?*anyopaque = null,
    present: *const fn (ctx: ?*anyopaque, rec: *const Record) PublishError!void,
    /// Remove exactly that value. Best effort: nothing is reported back.
    cleanup: *const fn (ctx: ?*anyopaque, rec: *const Record) void,
};

test {
    _ = zone;
    _ = Dns01Solver;
    _ = publishers;
    _ = @import("solver_test.zig");
    _ = @import("zone_test.zig");
    _ = @import("fuzz_test.zig");
}

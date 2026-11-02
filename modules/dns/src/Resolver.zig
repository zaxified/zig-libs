// SPDX-License-Identifier: MIT

//! DNS resolver — UDP (with TC-bit → TCP retry), TCP (RFC 1035 §4.2.2
//! two-byte length prefix), DoT (RFC 7858, the same framing inside TLS) and
//! DoH (RFC 8484, `application/dns-message` over
//! the sibling `http` module; plus the common `application/dns-json` variant
//! via `std.json`).
//!
//! Modeled after Go's built-in resolver (`net/dnsclient_unix.go`): servers
//! and search list come from /etc/resolv.conf (explicit `Options.servers`
//! override), `lookupIp`/`reverse` consult /etc/hosts first, search-list
//! expansion follows Go's `conf.nameList`. One `Resolver` is owned by one
//! thread (`.single_owner`); every call blocks until an answer or timeout.
//!
//! Timeout model: `timeout_ms` bounds each UDP attempt natively
//! (`Socket.receiveTimeout`) and each TCP attempt — connect, write AND the
//! two reads — by running the exchange on its own task and canceling it at
//! the deadline (`runBounded`, the same shape `http.Client` uses, because std
//! 0.16.0 has no per-read deadline on a stream). DoH attempts are bounded by
//! `http.Client`'s `total_timeout_ms`, set from the same `timeout_ms`. What
//! the budget is NOT is a bound on a whole `lookupIp`/`resolve` call — see
//! `Error.Timeout`.
//!
//! What a response must prove before it is believed (RFC 5452 §9.1): it came
//! from the server we sent to (UDP: address AND port), carries our transaction
//! id, has the QR bit set, and echoes exactly our question — name
//! (case-insensitive), type and class. `lookupIp`/`reverse` additionally
//! take only answer records whose owner is the queried name or a CNAME target
//! reachable from it inside the same answer section, so an unrelated record a
//! server slips into the answer section is ignored, not returned.

const std = @import("std");
const testkit = @import("testkit");
const builtin = @import("builtin");
const netaddr = @import("netaddr");
const http = @import("http");
const dns = @import("root.zig");
const message = @import("message.zig");
const config = @import("config.zig");
const net = std.Io.net;

const Resolver = @This();
const zl_options = @import("zl_options");

/// Whether DoH is compiled in: `-Ddns-doh` (CONVENTIONS §4.2), default
/// `true`, `false` under `-Dprofile=small`. Without it the `http` module and
/// the TLS stack behind it are not in the binary at all, and a `Resolver`
/// given `Options.doh_url` refuses every query with `error.NoDohEndpoint`
/// rather than fall back to plain DNS.
pub const doh_enabled: bool = zl_options.dns_doh orelse switch (zl_options.profile) {
    .default => true,
    .small => false,
};
const HttpClient = if (doh_enabled) http.Client else void;

/// Whether DoT is compiled in: `-Ddns-dot`, default `true`, `false` under
/// `-Dprofile=small`. Without it `tlsclient` is not in the binary at all and
/// a `Resolver` with `Options.transport = .tls` refuses every query with
/// `error.NoDotSupport` rather than fall back to plain DNS.
pub const dot_enabled: bool = zl_options.dns_dot orelse switch (zl_options.profile) {
    .default => true,
    .small => false,
};
const tlsclient = if (dot_enabled) @import("tlsclient") else void;
/// The system CA store for DoT's strict verification, loaded on first use.
const DotCa = if (dot_enabled) http.Client.CaBundle else void;

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
/// Present iff `options.doh_url` is set (and `doh_enabled`).
http_client: ?HttpClient,
/// DoT's CA bundle, loaded on the first strict `.tls` exchange.
dot_ca: DotCa = if (dot_enabled) .{} else {},
/// resolv.conf, loaded lazily on first use (do not copy the Resolver after).
conf: ?config.ResolvConf,
conf_text: ?[]u8,
/// Servers that refused an EDNS query (FORMERR without OPT, or BADVERS) and
/// are asked without OPT from then on (RFC 6891 §7). Bounded: the oldest
/// entry is replaced when full; dropped with the Resolver.
no_edns: [max_no_edns]?netaddr.Ip = @splat(null),
no_edns_next: u8 = 0,
/// `rotate`: index of the server the next query starts at.
rotate_next: usize = 0,
/// End of the current public call's `call_timeout_ms` budget; set by the
/// OUTERMOST public call only (`beginCall`), so nested calls share it.
call_deadline: ?std.Io.Clock.Timestamp = null,

const max_no_edns = 8;

pub const Family = enum { any, v4, v6 };

pub const Transport = enum {
    /// UDP first; retry over TCP when the response has the TC bit set.
    auto,
    /// TCP only.
    tcp,
    /// DNS over TLS (RFC 7858): TCP to `Options.dot_port`, a TLS handshake,
    /// then the RFC 1035 §4.2.2 two-byte framing inside the session. One
    /// connection per exchange. Authenticated by default (`dot_tls`,
    /// `tls_server_name`); a failed handshake is `error.TlsFailed`, never a
    /// plain-DNS retry. Needs a build with `dot_enabled`, else `NoDotSupport`.
    /// `doh_url`, when set, still wins over every transport.
    tls,
};

pub const DohMethod = enum {
    /// RFC 8484 POST — the request body is the binary DNS message.
    post,
    /// RFC 8484 GET — the message travels base64url-encoded in `?dns=`.
    get,
};

/// `Options.timeout_ms`'s own struct default (audit F10): when the caller
/// leaves `timeout_ms` at exactly this value AND resolv.conf is in play (no
/// explicit `Options.servers`), `effectiveTimeoutMs` honors resolv.conf's
/// `options timeout:` instead. Named so the struct default and that
/// comparison can never drift apart into two unverifiable copies of the same
/// number ([[feedback_n_copies_of_one_invariant_is_one_unverifiable_guard]]).
pub const default_timeout_ms: u32 = 5000;
/// `Options.attempts`'s own struct default; see `default_timeout_ms`.
pub const default_attempts: u8 = 2;

pub const Options = struct {
    /// Explicit DNS servers; empty = read /etc/resolv.conf (falling back to
    /// localhost like Go when that is missing/empty).
    servers: []const netaddr.Ip = &.{},
    port: u16 = 53,
    /// DoH endpoint (e.g. "https://dns.google/dns-query"). When set, ALL
    /// queries go over HTTPS and `servers`/`transport` are ignored.
    doh_url: ?[]const u8 = null,
    doh_method: DohMethod = .post,
    /// TLS verification for DoH.
    doh_tls: http.Client.TlsOptions = .{},
    transport: Transport = .auto,
    /// Port of `transport = .tls` (RFC 7858 §3.1: 853). `port` keeps meaning
    /// the plain UDP/TCP port.
    dot_port: u16 = 853,
    /// `transport = .tls`: the name sent as SNI and the name the server's
    /// certificate must carry (RFC 7858 §4.2 strict privacy, "authentication
    /// domain name"). Null: the certificate is verified against the server's
    /// IP address (an IP SAN) and no SNI is sent.
    tls_server_name: ?[]const u8 = null,
    /// `transport = .tls`: `.strict` (default) verifies the chain against the
    /// system CA bundle and the name; `.insecure_no_verify` is RFC 7858
    /// opportunistic privacy -- encrypted against a passive observer only.
    dot_tls: http.Client.TlsOptions = .{},
    /// Which address families `lookupIp`/`lookupIpTtl` ask for (Go's
    /// "ip4"/"ip6" networks, hickory's `ip_strategy`). `.v4` sends no AAAA
    /// query at all; literals and /etc/hosts entries of the other family are
    /// left out. At `.any`, resolv.conf `options no-aaaa` (when resolv.conf is
    /// read) means `.v4`.
    family: Family = .any,
    /// Ask A and AAAA at the same time in `lookupIp`/`lookupIpTtl`, as Go,
    /// glibc and c-ares do: a server that drops AAAA then costs one timeout,
    /// not timeout + the A query. false = one after the other (glibc
    /// `single-request`); left true, resolv.conf `options single-request`
    /// (when read) also means one after the other. Falls back to sequential
    /// when the `Io` offers no concurrency. CONSUMER-VISIBLE since 2026-11-02:
    /// both queries leave together. Each side may run its TCP/DoT exchange on
    /// one more concurrent task (`runBounded`), so a lookup can hold three; an
    /// `Io` near its concurrency limit then sees `NetworkFailed` on TCP/DoT
    /// where sequential lookups would not — set this false there.
    parallel_families: bool = true,
    /// Start each query at the next server in turn instead of always the
    /// first (resolv.conf `options rotate`, also honoured when read); every
    /// attempt still walks all servers.
    rotate: bool = false,
    /// Per-attempt budget; 0 = no timeout. Enforced natively on UDP receive;
    /// see the module comment for the TCP/DoH connect caveat. Left at its
    /// struct default (`default_timeout_ms`), this is overridden by
    /// resolv.conf's `options timeout:` when resolv.conf is in play (audit
    /// F10) — see `effectiveTimeoutMs`. An explicit non-default value here
    /// always wins, on the classic UDP/TCP path; DoH's `total_timeout_ms` is
    /// set once at `init` from this field and never revisited.
    timeout_ms: u32 = default_timeout_ms,
    /// Budget for ONE public call (`resolve`, `query`, `lookupIp`,
    /// `lookupIpTtl`, `reverse`, `exchange`, `queryJson`): every attempt,
    /// server, search-list candidate and family together — Go's `ctx`
    /// deadline. When it runs out the call ends with `error.Timeout` (a reply
    /// already in hand is still returned). Each attempt waits for the earlier
    /// of `timeout_ms` and what is left of this. 0 = no call budget (the
    /// per-attempt bounds only, as before). Not applied to DoH (`doh_url`),
    /// whose one request is bounded by `timeout_ms`.
    call_timeout_ms: u32 = 0,
    /// UDP retry rounds over the server list (min 1). Same resolv.conf
    /// fallback as `timeout_ms`, via `options attempts:` (audit F10).
    attempts: u8 = default_attempts,
    /// Consult /etc/hosts in `lookupIp`/`reverse` before querying.
    use_hosts: bool = true,
    /// Apply the resolv.conf search list / ndots in `resolve`/`lookupIp`.
    use_search: bool = true,
    /// EDNS(0) advertised UDP payload size; null disables the OPT record.
    edns_udp_size: ?u16 = 1232,
    /// The RD bit on queries. Clear it to ask an AUTHORITATIVE server about
    /// its own zone (a DNS-01 propagation check, `dig +norec`): an
    /// authoritative-only server may refuse a recursive query.
    recursion_desired: bool = true,
    /// DO bit (RFC 3225) on every query: ask for RRSIGs (for the `dnssec`
    /// module). Needs `edns_udp_size`; else every query is `InvalidOptions`.
    dnssec_ok: bool = false,
    /// AD bit on queries AND trust in the reply's AD bit (glibc `trust-ad`,
    /// RFC 6840 §5.7): when false, a reply's `header.authentic_data` is
    /// cleared before the caller sees it — only trust AD from a validating
    /// resolver on a path you trust (loopback, or DoT/DoH).
    authentic_data: bool = false,
    /// CD bit on queries (RFC 4035 §3.2.2): the server should not validate.
    checking_disabled: bool = false,
    /// EDNS options sent with every query (cookie, NSID, padding …), at most
    /// `message.max_edns_options_len` bytes; else `InvalidOptions`.
    edns_options: []const message.EdnsOption = &.{},
    hosts_path: []const u8 = "/etc/hosts",
    resolv_conf_path: []const u8 = "/etc/resolv.conf",
};

pub const Error = error{
    /// From the codec: name over 253 chars / bad label (see message.zig).
    NameTooLong,
    BadName,
    /// No response within the budget. `timeout_ms` is PER ATTEMPT PER
    /// SERVER: one `query` can take up to `timeout_ms × attempts × servers`
    /// (every server is tried in every round), and `lookupIp` runs a query
    /// per (search-list candidate × {A, AAAA}) on top of that — with the
    /// defaults (5 s, 2 attempts, a 3-server resolv.conf, 6 search domains)
    /// that is 7 minutes for a name that resolves nowhere. Callers that need
    /// a bound on the CALL set `timeout_ms`/`attempts` small, or pass a name
    /// with a trailing dot (no search-list expansion), or shorten `servers`.
    /// ⚠ An administrator who tightens `options timeout:`/`attempts:` in
    /// resolv.conf specifically to bound this IS honored (audit F10, when
    /// `Options` is left at its own struct defaults and no explicit
    /// `Options.servers` bypasses resolv.conf) — the "5 s, 2 attempts" above
    /// is the fallback, not a promise resolv.conf can't shorten.
    /// `lookupIp`/`lookupIpTtl` only: every server answered with a failure
    /// rcode (SERVFAIL, REFUSED, NOTIMP — `serverFailed`) and nothing else
    /// answered. Go's "server misbehaving": an outage, not "no such host".
    ServerFailed,
    Timeout,
    /// Socket-level failure (bind/send/connect/read).
    NetworkFailed,
    /// The response did not decode, or its id/QR did not match the query.
    MalformedResponse,
    /// DoH transport failed (HTTP error, non-200 status, oversized body).
    DohFailed,
    /// DoT: the TLS handshake failed (certificate or name not accepted, alert,
    /// protocol error) or the session broke after it. Never retried in plain.
    TlsFailed,
    /// `Options.transport = .tls` in a build without DoT (`dot_enabled`,
    /// `-Ddns-dot=false`, the default under `-Dprofile=small`).
    NoDotSupport,
    /// A DoH operation was requested without `Options.doh_url`, or with it
    /// in a build without DoH (`doh_enabled`, `-Ddns-doh=false`).
    NoDohEndpoint,
    /// The message given to `exchange` exceeds the 65 535 bytes a DNS TCP
    /// message can carry; nothing was sent.
    RequestTooLarge,
    /// `Options.dnssec_ok`/`edns_options` with `edns_udp_size = null`, or
    /// `edns_options` over `message.max_edns_options_len` bytes: no query
    /// can be built from these options.
    InvalidOptions,
    OutOfMemory,
    Canceled,
};

/// `io` must support net + async operations (e.g. `std.Io.Threaded`).
pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Resolver {
    return .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .http_client = if (doh_enabled and options.doh_url != null)
            http.Client.init(io, gpa, .{
                .tls = options.doh_tls,
                .total_timeout_ms = options.timeout_ms,
            })
        else
            null,
        .conf = null,
        .conf_text = null,
    };
}

pub fn deinit(r: *Resolver) void {
    if (dot_enabled) r.dot_ca.deinit(r.gpa);
    if (doh_enabled) if (r.http_client) |*c| c.deinit();
    if (r.conf_text) |t| r.gpa.free(t);
    r.* = undefined;
}

// ── high-level API ──────────────────────────────────────────────────────────

/// Resolve `name`/`ty` applying the search list (Go `conf.nameList` order,
/// unless `use_search` is off or the name is rooted). Returns the first
/// response with rcode NOERROR and at least one answer; otherwise the last
/// response (so the caller can inspect the rcode — NXDOMAIN is a valid
/// answer, not an error). Does NOT consult /etc/hosts — use `lookupIp` for
/// getaddrinfo-like behavior. Caller owns the message (`Message.deinit`).
pub fn resolve(r: *Resolver, name: []const u8, ty: message.Type) Error!message.Message {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    // RFC 7686 / 6761: `.onion` and `.invalid` never leave the host (a Tor
    // name leaked to the resolver). `query`, the raw primitive, does not
    // filter.
    if (config.isDnsAvoided(name)) return error.BadName;
    var search: []const []const u8 = &.{};
    var ndots: u8 = 1;
    if (r.options.use_search) {
        try r.ensureConfig();
        search = r.conf.?.search();
        ndots = r.conf.?.ndots;
    }

    var candidate_buf: [message.max_name_text_len]u8 = undefined;
    var it = config.NameIterator.init(name, search, ndots);
    var last: ?message.Message = null;
    errdefer if (last) |*m| m.deinit();
    // A search-list entry that makes a bad name (`search a..b`, a 64-byte
    // label) is skipped like `lookupIp` does, not fatal to every unqualified
    // lookup (sweep REV-dns-3); it is the answer only when nothing else is.
    var bad_name: ?Error = null;
    while (it.next(&candidate_buf)) |candidate| {
        const msg = r.query(candidate, ty) catch |err| switch (err) {
            error.BadName, error.NameTooLong => {
                if (bad_name == null) bad_name = err;
                continue;
            },
            else => |e| return e,
        };
        if (msg.rcode() == .no_error and msg.answers.len > 0) {
            if (last) |*m| m.deinit();
            return msg;
        }
        if (last) |*m| m.deinit();
        last = msg;
    }
    if (last) |m| return m;
    return bad_name orelse error.BadName; // only an empty/over-long name yields no candidate
}

/// All IPv4 + IPv6 addresses for `name`: IP literals pass through, /etc/hosts
/// is consulted first (when enabled), then A and AAAA queries per search-list
/// candidate. On Linux the result is ordered by RFC 6724 destination rules
/// (netaddr) like getaddrinfo. Returns an empty slice when the servers
/// answered but nothing resolves (NXDOMAIN, no records). When no address was
/// found and a query failed (timeout, network, malformed answer), returns the
/// last such error, as Go does — an outage is not "no such host". One family
/// failing while the other answers is tolerated. Caller frees with `gpa.free`.
pub fn lookupIp(r: *Resolver, name: []const u8) Error![]netaddr.Ip {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    return (try r.lookupIpTtl(name)).ips;
}

/// `lookupIpTtl`'s answer. Free `ips` with `gpa.free`.
pub const IpLookup = struct {
    ips: []netaddr.Ip,
    /// How long the answer may be cached, in seconds: the smallest TTL of the
    /// records it was built from (the CNAME chain included, RFC 1035 §3.2.1);
    /// for an empty answer the negative-caching TTL, the smaller of the SOA
    /// record's TTL and its MINIMUM (RFC 2308 §5). Null when there is none to
    /// go by: an IP literal, an /etc/hosts entry, an empty answer without SOA.
    ttl_s: ?u32,
    /// One address family's query failed (a timeout, a server failure) while
    /// the other answered: `ips` holds that family only. A caller keeping an
    /// address of the missing family should not take this as its replacement.
    partial: bool = false,
};

/// `lookupIp`, and how long its answer may be cached (`IpLookup.ttl_s`) —
/// what a caller that keeps addresses between lookups needs (a monitor that
/// re-resolves its targets only when the answer expires). Only the answers
/// of the search-list candidate that produced the addresses count; an empty
/// result takes the smallest negative TTL over every candidate asked.
pub fn lookupIpTtl(r: *Resolver, name: []const u8) Error!IpLookup {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    var list: std.ArrayList(netaddr.Ip) = .empty;
    errdefer list.deinit(r.gpa);

    if (netaddr.parseIp(name)) |ip| {
        // A literal of the other family than `Options.family` asks for: none.
        if (familyAllows(r.options.family, ip)) try list.append(r.gpa, ip);
        return .{ .ips = try list.toOwnedSlice(r.gpa), .ttl_s = null };
    }

    if (r.options.use_hosts) hosts: {
        const content = r.readHosts() orelse break :hosts;
        defer r.gpa.free(content);
        var ips: [16]netaddr.Ip = undefined;
        const n = config.hostsIpsForName(content, name, &ips);
        // /etc/hosts filtered to `Options.family` (resolv.conf `no-aaaa`
        // limits the DNS queries only, as in glibc).
        for (ips[0..n]) |ip| if (familyAllows(r.options.family, ip)) try list.append(r.gpa, ip);
        if (list.items.len > 0) {
            sortIps(list.items);
            return .{ .ips = try list.toOwnedSlice(r.gpa), .ttl_s = null };
        }
    }

    // RFC 7686 / 6761: after /etc/hosts, `.onion` and `.invalid` are not
    // asked of DNS; nothing resolves (Go's `avoidDNS`, `errNoSuchHost`).
    if (config.isDnsAvoided(name)) return .{ .ips = try list.toOwnedSlice(r.gpa), .ttl_s = null };

    var search: []const []const u8 = &.{};
    var ndots: u8 = 1;
    if (r.options.use_search) {
        try r.ensureConfig();
        search = r.conf.?.search();
        ndots = r.conf.?.ndots;
    }

    // Lazily loaded, owned state must exist BEFORE the parallel path copies
    // the Resolver: otherwise each side loads its own (resolv.conf text, the
    // DoT CA bundle) and the copy's is never freed (review X, 2026-11-02).
    // This also lets `no-aaaa`/`single-request` count on the first lookup.
    if (r.options.servers.len == 0) try r.ensureConfig();
    if (dot_enabled and r.options.doh_url == null and r.options.transport == .tls and r.options.dot_tls.verify == .strict)
        r.dot_ca.load(r.gpa, r.io) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            else => return error.TlsFailed,
        };

    var candidate_buf: [message.max_name_text_len]u8 = undefined;
    var it = config.NameIterator.init(name, search, ndots);
    var last_err: ?Error = null;
    // The winning candidate's TTL, or the smallest negative one so far.
    var ttl: ?u32 = null;
    var partial = false;
    while (it.next(&candidate_buf)) |candidate| {
        var candidate_ttl: ?u32 = null;
        partial = false;
        families: {
            const fam = r.effectiveFamily();
            if (fam == .any and r.parallelFamilies() and r.options.doh_url == null) parallel: {
                // A and AAAA at once. The AAAA query runs on a copy of the
                // Resolver (its learned no-EDNS servers are merged back); both
                // allocate through one lock, because `gpa` need not be
                // thread-safe (an arena, a single-threaded DebugAllocator).
                var locked: LockedAllocator = .{ .child = r.gpa };
                const saved_gpa = r.gpa;
                r.gpa = locked.allocator();
                defer r.gpa = saved_gpa;
                var r6 = r.*;
                // `rotate`: AAAA starts one server after A, and the next query
                // after both.
                r6.rotate_next = r.rotate_next +% 1;
                var res6: Error!message.Message = error.Timeout;
                var fut = r.io.concurrent(queryInto, .{ &r6, candidate, message.Type.aaaa, &res6 }) catch {
                    r.gpa = saved_gpa;
                    break :parallel; // no concurrency: sequential below
                };
                var res4 = r.query(candidate, .a);
                fut.await(r.io);
                for (r6.no_edns) |e| if (e) |ip| r.rememberNoEdns(ip);
                r.rotate_next = r6.rotate_next;
                defer if (res4) |*m| m.deinit() else |_| {};
                defer if (res6) |*m| m.deinit() else |_| {};
                try r.takeFamily(&list, candidate, &res4, &candidate_ttl, &last_err, &partial);
                try r.takeFamily(&list, candidate, &res6, &candidate_ttl, &last_err, &partial);
                break :families;
            }
            const types: []const message.Type = switch (fam) {
                .any => &.{ .a, .aaaa },
                .v4 => &.{.a},
                .v6 => &.{.aaaa},
            };
            for (types) |ty| {
                var res = r.query(candidate, ty);
                defer if (res) |*m| m.deinit() else |_| {};
                try r.takeFamily(&list, candidate, &res, &candidate_ttl, &last_err, &partial);
            }
            break :families;
        }
        if (list.items.len > 0) { // first useful candidate wins
            ttl = candidate_ttl;
            break;
        }
        ttl = minTtl(ttl, candidate_ttl);
    }

    // Found by simio's dns pilot (2026-10-01): with the server down, both
    // queries timed out and this returned an empty list — indistinguishable
    // from a name that has no addresses.
    if (list.items.len == 0) if (last_err) |err| return err;
    sortIps(list.items);
    return .{ .ips = try list.toOwnedSlice(r.gpa), .ttl_s = ttl, .partial = partial };
}

fn minTtl(a: ?u32, b: ?u32) ?u32 {
    const x = a orelse return b;
    const y = b orelse return a;
    return @min(x, y);
}

/// The TTL one response contributes to `lookupIpTtl`: with addresses taken
/// from it (`found`), the smallest TTL of the address and CNAME records on
/// `qname`'s chain — the records `collectAddresses` used; without, the
/// negative TTL from the authority section's SOA (RFC 2308 §5), bounded by
/// any CNAME the chain did follow.
fn answerTtl(answers: []const message.Record, authorities: []const message.Record, qname: []const u8, found: bool) ?u32 {
    var chain: OwnerChain = .init(qname);
    chain.follow(answers);
    var ttl: ?u32 = null;
    for (answers) |rec| {
        if (rec.class != .in or !chain.contains(rec.name)) continue;
        if (rec.data == .cname or dns.recordIp(rec) != null) ttl = minTtl(ttl, rec.ttl);
    }
    if (found) return ttl;
    for (authorities) |rec| if (rec.data == .soa) return minTtl(ttl, @min(rec.ttl, rec.data.soa.minimum));
    return ttl;
}

test "answerTtl: smallest TTL on the chain; negative answers from the SOA" {
    const a = message.Record{ .name = "www.example.com", .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, 1 } } };
    const cname = message.Record{ .name = "example.com", .ty = .cname, .class = .in, .ttl = 120, .data = .{ .cname = "www.example.com" } };
    const stray = message.Record{ .name = "other.example", .ty = .a, .class = .in, .ttl = 5, .data = .{ .a = .{ 203, 0, 113, 66 } } };
    const soa = message.Record{ .name = "example.com", .ty = .soa, .class = .in, .ttl = 3600, .data = .{ .soa = .{
        .mname = "ns.example.com",
        .rname = "admin.example.com",
        .serial = 1,
        .refresh = 0,
        .retry = 0,
        .expire = 0,
        .minimum = 900,
    } } };
    // The CNAME bounds the address behind it; a record off the chain does not count.
    try testing.expectEqual(@as(?u32, 120), answerTtl(&.{ cname, a, stray }, &.{}, "example.com", true));
    try testing.expectEqual(@as(?u32, 300), answerTtl(&.{ a, stray }, &.{}, "www.example.com", true));
    // Nothing found: min(SOA TTL, MINIMUM), bounded by a followed CNAME; no SOA, no TTL.
    try testing.expectEqual(@as(?u32, 900), answerTtl(&.{}, &.{soa}, "nx.example.com", false));
    try testing.expectEqual(@as(?u32, 120), answerTtl(&.{cname}, &.{soa}, "example.com", false));
    try testing.expectEqual(@as(?u32, null), answerTtl(&.{}, &.{}, "nx.example.com", false));
    try testing.expectEqual(@as(?u32, 7), minTtl(7, null));
    try testing.expectEqual(@as(?u32, 3), minTtl(7, 3));
}

/// PTR lookup: /etc/hosts first (when enabled), then a reverse query for the
/// `in-addr.arpa`/`ip6.arpa` name built via netaddr. Returns the host names
/// (possibly empty); free with `freeNames`.
pub fn reverse(r: *Resolver, ip: netaddr.Ip) Error![]const []const u8 {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    var names: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (names.items) |n| r.gpa.free(n);
        names.deinit(r.gpa);
    }

    if (r.options.use_hosts) hosts: {
        const content = r.readHosts() orelse break :hosts;
        defer r.gpa.free(content);
        var name_buf: [message.max_name_text_len]u8 = undefined;
        if (config.hostsNameForIp(content, ip, &name_buf)) |name| {
            try names.append(r.gpa, try r.gpa.dupe(u8, name));
            return names.toOwnedSlice(r.gpa);
        }
    }

    var rev_buf: [dns.max_reverse_name_len]u8 = undefined;
    // rev_buf is sized to exactly max_reverse_name_len: reverseName cannot
    // fail here.
    const rev = dns.reverseName(ip, &rev_buf) catch unreachable;
    var msg = try r.query(rev, .ptr);
    defer msg.deinit();
    try collectPtrNames(r.gpa, &names, &msg, rev);
    return names.toOwnedSlice(r.gpa);
}

// ── typed lookups (R5 / G2): MX, NS, TXT, CNAME, SRV ─────────────────────────

/// One MX record (RFC 1035 §3.3.9): lower `preference` is tried first.
pub const Mx = struct { preference: u16, host: []const u8 };

/// One SRV record (RFC 2782). `target` "" or "." is "decidedly not available".
pub const Srv = struct { priority: u16, weight: u16, port: u16, target: []const u8 };

/// One result set of a typed lookup; every string lives in `arena` (free the
/// whole set with `deinit`).
pub fn Lookup(comptime T: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        items: []const T,
        /// The smallest TTL of the records used (the CNAME chain they were
        /// reached through included); for an empty set the negative-caching
        /// TTL from the SOA (RFC 2308 §5), null when there is none to go by.
        ttl_s: ?u32,

        pub fn deinit(l: *@This()) void {
            const gpa = l.arena.child_allocator;
            l.arena.deinit();
            gpa.destroy(l.arena);
            l.* = undefined;
        }
    };
}

/// `resolve`'s answer plus the search-list candidate that produced it (`qname`
/// points into the caller's buffer or at the caller's `name`).
const Answered = struct {
    msg: message.Message,
    qname: []const u8,
};

/// `resolve` that also reports WHICH candidate answered — the typed lookups
/// accept only records whose owner is in that candidate's `OwnerChain`. A
/// failure rcode (SERVFAIL, REFUSED, NOTIMP) from every candidate that
/// produced no answer is `error.ServerFailed` (an outage, not "no such
/// name"), as in `lookupIpTtl`. NXDOMAIN / NODATA return the last reply.
fn resolveNamed(r: *Resolver, name: []const u8, ty: message.Type, buf: *[message.max_name_text_len]u8) Error!Answered {
    if (config.isDnsAvoided(name)) return error.BadName;
    var search: []const []const u8 = &.{};
    var ndots: u8 = 1;
    if (r.options.use_search) {
        try r.ensureConfig();
        search = r.conf.?.search();
        ndots = r.conf.?.ndots;
    }
    var it = config.NameIterator.init(name, search, ndots);
    var last: ?Answered = null;
    errdefer if (last) |*a| a.msg.deinit();
    var bad_name: ?Error = null;
    var failed = false;
    while (it.next(buf)) |candidate| {
        const msg = r.query(candidate, ty) catch |err| switch (err) {
            error.BadName, error.NameTooLong => {
                if (bad_name == null) bad_name = err;
                continue;
            },
            else => |e| return e,
        };
        if (serverFailed(msg.rcode())) failed = true;
        if (msg.rcode() == .no_error and msg.answers.len > 0) {
            if (last) |*a| a.msg.deinit();
            last = null;
            return .{ .msg = msg, .qname = candidate };
        }
        if (last) |*a| a.msg.deinit();
        last = .{ .msg = msg, .qname = candidate };
    }
    if (failed) return error.ServerFailed;
    if (last) |a| return a;
    return bad_name orelse error.BadName;
}

fn newLookup(comptime T: type, gpa: std.mem.Allocator) error{OutOfMemory}!Lookup(T) {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = .init(gpa);
    return .{ .arena = arena, .items = &.{}, .ttl_s = null };
}

/// The TTL of a typed answer: `used` (the smallest TTL of the records taken)
/// bounded by the CNAMEs on the chain; with nothing found, the SOA's negative
/// TTL (RFC 2308 §5).
fn typedTtl(msg: *const message.Message, chain: *const OwnerChain, used: ?u32, found: bool) ?u32 {
    var ttl = used;
    for (msg.answers) |rec| {
        if (rec.class == .in and rec.data == .cname and chain.contains(rec.name)) ttl = minTtl(ttl, rec.ttl);
    }
    if (found) return ttl;
    for (msg.authorities) |rec| if (rec.data == .soa) return minTtl(ttl, @min(rec.ttl, rec.data.soa.minimum));
    return ttl;
}

/// Builds the result set from the records of `ans` that `convert` accepts
/// (null = not this type) and whose owner is in the answering candidate's
/// chain, class IN.
fn collectTyped(
    comptime T: type,
    r: *Resolver,
    ans: *const Answered,
    comptime convert: fn (std.mem.Allocator, *const message.Record) error{OutOfMemory}!?T,
) error{OutOfMemory}!Lookup(T) {
    var lk = try newLookup(T, r.gpa);
    errdefer lk.deinit();
    const a = lk.arena.allocator();
    var chain: OwnerChain = .init(ans.qname);
    chain.follow(ans.msg.answers);
    var list: std.ArrayList(T) = .empty;
    var used: ?u32 = null;
    for (ans.msg.answers) |*rec| {
        if (rec.class != .in or !chain.contains(rec.name)) continue;
        const item = (try convert(a, rec)) orelse continue;
        try list.append(a, item);
        used = minTtl(used, rec.ttl);
    }
    lk.items = list.items;
    lk.ttl_s = typedTtl(&ans.msg, &chain, used, list.items.len > 0);
    return lk;
}

fn mxItem(a: std.mem.Allocator, rec: *const message.Record) error{OutOfMemory}!?Mx {
    const mx = switch (rec.data) {
        .mx => |m| m,
        else => return null,
    };
    // RFC 7505 null MX (exchange "."): the domain accepts no mail — not a
    // host to connect to, so it is no item (as a "." SRV target is not).
    if (mx.exchange.len == 0 or std.mem.eql(u8, mx.exchange, ".")) return null;
    return .{ .preference = mx.preference, .host = try a.dupe(u8, mx.exchange) };
}

fn nsItem(a: std.mem.Allocator, rec: *const message.Record) error{OutOfMemory}!?[]const u8 {
    return switch (rec.data) {
        .ns => |n| try a.dupe(u8, n),
        else => null,
    };
}

fn txtItem(a: std.mem.Allocator, rec: *const message.Record) error{OutOfMemory}!?[]const u8 {
    return switch (rec.data) {
        .txt => |strings| try std.mem.concat(a, u8, strings),
        else => null,
    };
}

fn isRootName(n: []const u8) bool {
    return n.len == 0 or std.mem.eql(u8, n, ".");
}

fn srvItem(a: std.mem.Allocator, rec: *const message.Record) error{OutOfMemory}!?Srv {
    const s = switch (rec.data) {
        .srv => |s| s,
        else => return null,
    };
    // RFC 2782 (Target): "." = the service is decidedly not available at this
    // domain. A single such record means "none"; next to real targets it is
    // not something to connect to either, so it never enters the set.
    if (isRootName(s.target)) return null;
    return .{ .priority = s.priority, .weight = s.weight, .port = s.port, .target = try a.dupe(u8, s.target) };
}

/// Uniform draw from `r.io.random` for the ordering helpers below.
const IoRng = struct {
    io: std.Io,

    /// Uniform in [0, n); `n` 0 or 1 give 0. Bounded rejection sampling, so an
    /// `Io` whose `random` is degenerate cannot hang the caller.
    fn below(self: IoRng, n: u64) u64 {
        if (n <= 1) return 0;
        const threshold = (0 -% n) % n;
        var x: u64 = 0;
        for (0..8) |_| {
            var b: [8]u8 = undefined;
            self.io.random(&b);
            x = std.mem.readInt(u64, &b, .little);
            if (x >= threshold) break;
        }
        return x % n;
    }
};

fn mxLess(_: void, a: Mx, b: Mx) bool {
    return a.preference < b.preference;
}

/// MX order (RFC 5321 §5.1): ascending preference, equal preferences in a
/// random order (shuffle, then a stable sort). `rng.below(n: u64) u64` is
/// uniform in [0, n).
pub fn orderMx(items: []Mx, rng: anytype) void {
    var i = items.len;
    while (i > 1) : (i -= 1) {
        const j: usize = @intCast(rng.below(i));
        std.mem.swap(Mx, &items[i - 1], &items[j]);
    }
    std.mem.sort(Mx, items, {}, mxLess);
}

fn srvLess(_: void, a: Srv, b: Srv) bool {
    if (a.priority != b.priority) return a.priority < b.priority;
    return a.weight == 0 and b.weight != 0; // weight 0 first within a priority (RFC 2782)
}

/// SRV order (RFC 2782): ascending priority; within one priority the records
/// are drawn one by one, a record's chance proportional to its weight — the
/// RFC's running-sum selection over a random number in [0, sum] with weight-0
/// records listed first, so they keep "a very small chance". `rng.below(n:
/// u64) u64` is uniform in [0, n).
pub fn orderSrv(items: []Srv, rng: anytype) void {
    std.mem.sort(Srv, items, {}, srvLess);
    var start: usize = 0;
    while (start < items.len) {
        var end = start + 1;
        while (end < items.len and items[end].priority == items[start].priority) end += 1;
        var i = start;
        while (i < end) : (i += 1) {
            var total: u64 = 0;
            for (items[i..end]) |s| total += s.weight;
            const pick = rng.below(total + 1);
            var run: u64 = 0;
            var j = i;
            while (j < end - 1) : (j += 1) {
                run += items[j].weight;
                if (run >= pick) break;
            }
            // Move the chosen record to the front of the remainder, keeping
            // the others in order (weight-0 records stay first).
            std.mem.rotate(Srv, items[i .. j + 1], j - i);
        }
        start = end;
    }
}

/// MX records of `name`, sorted by preference; equal preferences in random
/// order (RFC 5321 §5.1). Only records owned by the name that answered (or by
/// a CNAME target chained from it) count. An empty set for NXDOMAIN / NODATA;
/// `error.ServerFailed` when the servers failed. Free with `Lookup.deinit`.
pub fn lookupMx(r: *Resolver, name: []const u8) Error!Lookup(Mx) {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    var buf: [message.max_name_text_len]u8 = undefined;
    var ans = try r.resolveNamed(name, .mx, &buf);
    defer ans.msg.deinit();
    const lk = try collectTyped(Mx, r, &ans, mxItem);
    const items: []Mx = @constCast(lk.items);
    orderMx(items, IoRng{ .io = r.io });
    return lk;
}

/// NS records of `name` (answer order). Same rules as `lookupMx`.
pub fn lookupNs(r: *Resolver, name: []const u8) Error!Lookup([]const u8) {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    var buf: [message.max_name_text_len]u8 = undefined;
    var ans = try r.resolveNamed(name, .ns, &buf);
    defer ans.msg.deinit();
    return collectTyped([]const u8, r, &ans, nsItem);
}

/// TXT records of `name`, one string per record: the record's
/// character-strings joined in wire order (what SPF / verification tokens
/// expect). Same rules as `lookupMx`.
pub fn lookupTxt(r: *Resolver, name: []const u8) Error!Lookup([]const u8) {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    var buf: [message.max_name_text_len]u8 = undefined;
    var ans = try r.resolveNamed(name, .txt, &buf);
    defer ans.msg.deinit();
    return collectTyped([]const u8, r, &ans, txtItem);
}

/// The canonical name of `name`: the end of its CNAME chain (at most
/// `OwnerChain.max_cname_chain` hops), or `name` itself when it has no CNAME
/// (or nothing resolves). The chain is read from an A answer — a recursive
/// resolver returns the whole chain there — so a name with only AAAA records
/// and a CNAME still reports its CNAME. Caller frees with `gpa.free`.
pub fn lookupCname(r: *Resolver, name: []const u8) Error![]u8 {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    var buf: [message.max_name_text_len]u8 = undefined;
    var ans = try r.resolveNamed(name, .a, &buf);
    defer ans.msg.deinit();
    var cur = ans.qname;
    var hops: usize = 0;
    walk: while (hops < OwnerChain.max_cname_chain) : (hops += 1) {
        for (ans.msg.answers) |rec| {
            if (rec.class != .in or rec.data != .cname or !namesEqual(rec.name, cur)) continue;
            cur = rec.data.cname;
            continue :walk;
        }
        break;
    }
    return r.gpa.dupe(u8, if (hops == 0) name else cur);
}

/// SRV targets of `_service._proto.name` (RFC 2782) in connection order:
/// ascending priority, weighted-random within a priority (`orderSrv`). Empty
/// `service` and `proto` query `name` as given (Go semantics). A "." target =
/// service not available = empty set. `error.NameTooLong` when the built name
/// does not fit. Same rules as `lookupMx` otherwise.
pub fn lookupSrv(r: *Resolver, service: []const u8, proto: []const u8, name: []const u8) Error!Lookup(Srv) {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    var name_buf: [message.max_name_text_len]u8 = undefined;
    const full = if (service.len == 0 and proto.len == 0)
        name
    else
        std.fmt.bufPrint(&name_buf, "_{s}._{s}.{s}", .{ service, proto, name }) catch return error.NameTooLong;
    var buf: [message.max_name_text_len]u8 = undefined;
    var ans = try r.resolveNamed(full, .srv, &buf);
    defer ans.msg.deinit();
    const lk = try collectTyped(Srv, r, &ans, srvItem);
    const items: []Srv = @constCast(lk.items);
    orderSrv(items, IoRng{ .io = r.io });
    return lk;
}

/// Appends (gpa-duped) the PTR targets in `msg.answers` that answer `rev` —
/// owner equal to the reverse name or to a CNAME target chained from it
/// (RFC 2317 classless in-addr.arpa delegation is exactly such a chain),
/// class IN. A PTR for some other owner is not this answer. Pure over the
/// decoded message; the `reverse` counterpart of `collectAddresses`.
fn collectPtrNames(gpa: std.mem.Allocator, names: *std.ArrayList([]const u8), msg: *const message.Message, rev: []const u8) error{OutOfMemory}!void {
    var chain: OwnerChain = .init(rev);
    chain.follow(msg.answers);
    for (msg.answers) |rec| switch (rec.data) {
        .ptr => |name| if (rec.class == .in and chain.contains(rec.name)) try names.append(gpa, try gpa.dupe(u8, name)),
        else => {},
    };
}

/// Case-insensitive DNS name equality on the codec's text form; one trailing
/// root dot on either side is ignored (`writeName` accepts it, the decoder
/// never emits it). Labels are raw bytes, so this is ASCII case folding only
/// (RFC 4343) — the same rule every resolver applies to owner names.
fn namesEqual(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(stripRootDot(a), stripRootDot(b));
}

fn stripRootDot(name: []const u8) []const u8 {
    return if (name.len > 1 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

/// The owner names an answer record may carry and still be an answer to
/// `qname`: the question name itself plus every CNAME target reachable from
/// it through CNAME records IN THE SAME answer section (RFC 1034 §3.6.2's
/// alias chain, as a recursive resolver returns it). Anything else in the
/// answer section — an A record for `victim.test` in a reply to
/// `example.com` — is out of bailiwick for the question and is not
/// something `lookupIp` may hand to a caller that will connect to it.
/// Bounded: a chain longer than `max_cname_chain` hops is cut there (glibc
/// and Go stop at a small constant too); a CNAME loop cannot extend it,
/// because a name already in the chain is never added twice.
const OwnerChain = struct {
    names: [max_cname_chain + 1][]const u8,
    len: usize,

    const max_cname_chain = 8;

    fn init(qname: []const u8) OwnerChain {
        var c: OwnerChain = .{ .names = undefined, .len = 1 };
        c.names[0] = qname;
        return c;
    }

    fn contains(c: *const OwnerChain, name: []const u8) bool {
        for (c.names[0..c.len]) |n| if (namesEqual(n, name)) return true;
        return false;
    }

    /// Adds CNAME targets until a full pass adds nothing (records may arrive
    /// in any order) or the chain is full.
    fn follow(c: *OwnerChain, answers: []const message.Record) void {
        var progressed = true;
        while (progressed and c.len < c.names.len) {
            progressed = false;
            for (answers) |rec| {
                if (rec.class != .in or rec.data != .cname) continue;
                if (!c.contains(rec.name) or c.contains(rec.data.cname)) continue;
                c.names[c.len] = rec.data.cname;
                c.len += 1;
                progressed = true;
                if (c.len == c.names.len) break;
            }
        }
    }
};

/// Appends the A/AAAA addresses in `msg.answers` that answer `qname` — owner
/// equal to `qname` or to a CNAME target chained from it (see `OwnerChain`),
/// class IN. Pure over the decoded message, so it is testable offline.
fn collectAddresses(gpa: std.mem.Allocator, list: *std.ArrayList(netaddr.Ip), msg: *const message.Message, qname: []const u8) error{OutOfMemory}!void {
    var chain: OwnerChain = .init(qname);
    chain.follow(msg.answers);
    for (msg.answers) |rec| {
        if (rec.class != .in or !chain.contains(rec.name)) continue;
        if (dns.recordIp(rec)) |ip| try list.append(gpa, ip);
    }
}

/// Free a slice returned by `reverse`.
pub fn freeNames(r: *Resolver, names: []const []const u8) void {
    for (names) |n| r.gpa.free(n);
    r.gpa.free(names);
}

/// One-shot query for exactly `name` (no search list, no hosts file) over
/// the configured transport. Caller owns the returned message.
///
/// A reply whose rcode says the SERVER failed (`serverFailed`: SERVFAIL,
/// NOTIMP, REFUSED) is not the answer: the next server is asked, round after
/// round, as glibc does (`testdata/config_oracle.zig` `rcodes`). If every
/// server fails that way, the last such reply is returned, so the caller can
/// still read its rcode. Any other rcode, NXDOMAIN included, is final.
pub fn query(r: *Resolver, name: []const u8, ty: message.Type) Error!message.Message {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    var qbuf: [message.max_query_len]u8 = undefined;

    if (r.options.doh_url != null) {
        // Built without DoH: refuse, never quietly ask plain DNS instead.
        if (!doh_enabled) return error.NoDohEndpoint;
        // RFC 8484 §4.1: use id 0 so DoH caches can be effective.
        const packet = try r.encodeChecked(&qbuf, name, ty, 0);
        const raw = try r.dohExchange(packet);
        defer r.gpa.free(raw);
        return r.decodeResponse(raw, 0, name, ty);
    }

    // Built without DoT: refuse, never quietly ask plain DNS instead.
    if (r.options.transport == .tls and !dot_enabled) return error.NoDotSupport;

    // Validate the name before touching the network (the per-attempt encode
    // below cannot fail differently).
    _ = try r.encodeChecked(&qbuf, name, ty, 0);

    const servers = try r.serverList();
    const rbuf = try r.gpa.alloc(u8, @max(512, r.options.edns_udp_size orelse 0));
    defer r.gpa.free(rbuf);

    var last_err: ?Error = null;
    // The last reply from a server that failed (`serverFailed`), kept in case
    // every server does.
    var failed: ?message.Message = null;
    errdefer if (failed) |*m| m.deinit();
    var attempt: u8 = 0;
    rounds: while (attempt < @max(1, r.effectiveAttempts())) : (attempt += 1) {
        const first = r.rotateStart(servers.len);
        for (0..servers.len) |k| {
            const server = servers[(first + k) % servers.len];
            // `call_timeout_ms` spent: no new attempt (a failed server's
            // reply already in hand is still returned below).
            if (r.callExpired()) {
                last_err = error.Timeout;
                break :rounds;
            }
            const edns = r.options.edns_udp_size != null and !r.refusedEdns(server);
            var msg = (try r.askServer(server, name, ty, &qbuf, rbuf, edns, &last_err)) orelse continue;
            // RFC 6891 §7: a server that answers an EDNS query with FORMERR
            // (and no OPT of its own) or BADVERS does not speak EDNS; ask it
            // once more in plain RFC 1035 form, and from now on only so. Not
            // on SERVFAIL (DNS flag day 2020). The retry is checked like any
            // reply (id, question), so a spoofed FORMERR can only cost this
            // server its EDNS, never inject an answer.
            if (edns and refusesEdns(&msg)) {
                msg.deinit();
                r.rememberNoEdns(server);
                msg = (try r.askServer(server, name, ty, &qbuf, rbuf, false, &last_err)) orelse continue;
            }
            return settle(&failed, msg) orelse continue;
        }
    }
    if (failed) |msg| return msg;
    return last_err orelse error.Timeout;
}

/// One attempt at one server: a fresh id, UDP (TCP on truncation, or
/// `transport = .tcp`), the reply decoded and checked against the question.
/// Null after a transport failure (recorded in `last_err`): try the next.
fn askServer(r: *Resolver, server: netaddr.Ip, name: []const u8, ty: message.Type, qbuf: []u8, rbuf: []u8, edns: bool, last_err: *?Error) Error!?message.Message {
    // A fresh transaction id for EVERY datagram sent. One id per `query`
    // meant a retry re-used an id an off-path attacker may already have seen
    // or guessed on the previous attempt, so every round was another shot at
    // a half-known target.
    var id_bytes: [2]u8 = undefined;
    r.io.random(&id_bytes);
    const id = std.mem.readInt(u16, &id_bytes, .big);
    const packet = try r.encodeFor(qbuf, name, ty, id, edns);

    if (r.useTcp()) {
        const raw = r.streamExchange(server, packet) catch |err| switch (err) {
            error.Canceled, error.OutOfMemory => |e| return e,
            else => {
                last_err.* = err;
                return null;
            },
        };
        defer r.gpa.free(raw);
        return try r.decodeResponse(raw, id, name, ty);
    }

    const udp = r.udpExchange(server, packet, id, rbuf, .{ .name = name, .ty = ty }) catch |err| switch (err) {
        error.Canceled, error.OutOfMemory => |e| return e,
        else => {
            last_err.* = err;
            return null;
        },
    };
    const raw = udp.data;
    // Retry over TCP when either says the UDP reply is not the whole answer:
    // the TC bit the server itself set, or the kernel's own truncation flag
    // for a datagram the server sent oversized without setting TC (audit
    // F13). The truncated bytes are never decoded -- a header whose counts no
    // longer match its body is exactly the malformed input this resolver
    // already treats as untrustworthy, so there is nothing to gain from
    // trying first.
    if (udp.truncated or (raw.len >= 3 and raw[2] & 0x02 != 0)) {
        const traw = r.streamExchange(server, packet) catch |err| switch (err) {
            error.Canceled, error.OutOfMemory => |e| return e,
            else => {
                last_err.* = err;
                return null;
            },
        };
        defer r.gpa.free(traw);
        return try r.decodeResponse(traw, id, name, ty);
    }
    return try r.decodeResponse(raw, id, name, ty);
}

/// FORMERR with no OPT in the reply, or BADVERS: the server refused the
/// EDNS form of the query (RFC 6891 §7, §6.1.3).
fn refusesEdns(msg: *const message.Message) bool {
    const rc = msg.rcode();
    if (rc == .bad_vers) return true;
    if (rc != .form_err) return false;
    for (msg.additionals) |a| if (a.data == .opt) return false;
    return true;
}

fn refusedEdns(r: *const Resolver, server: netaddr.Ip) bool {
    for (r.no_edns) |e| if (e) |ip| if (ip.eql(server)) return true;
    return false;
}

fn rememberNoEdns(r: *Resolver, server: netaddr.Ip) void {
    if (r.refusedEdns(server)) return;
    r.no_edns[r.no_edns_next] = server;
    r.no_edns_next = (r.no_edns_next + 1) % max_no_edns;
}

/// Send a message the caller built — an RFC 2136 UPDATE (`update.send`), a
/// NOTIFY, a TSIG-signed query — to `server` and return the raw reply
/// (gpa-owned). UDP, retried over TCP when the reply is truncated; TCP from
/// the start for `transport = .tcp` or a message over 512 bytes (no EDNS
/// negotiation is assumed). `Options.port`, `timeout_ms` and `attempts`
/// apply; `doh_url`, the search list and /etc/hosts do not. The reply must
/// come from `server`, carry the message's id and have QR set; anything else
/// about it — question echo, rcode, a TSIG — is the caller's to check. A
/// `packet` shorter than a DNS header is refused with `MalformedResponse`, one
/// longer than the 65 535 bytes the TCP length prefix can announce with
/// `RequestTooLarge`, both before anything is sent (sweep DN-1: the long one
/// used to trap in `@intCast`).
pub fn exchange(r: *Resolver, server: netaddr.Ip, packet: []const u8) Error![]u8 {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    if (packet.len < message.header_len) return error.MalformedResponse;
    if (packet.len > std.math.maxInt(u16)) return error.RequestTooLarge;
    if (r.options.transport == .tls and !dot_enabled) return error.NoDotSupport;
    const id = std.mem.readInt(u16, packet[0..2], .big);
    const tcp_only = r.useTcp() or packet.len > 512;
    var no_rbuf: [0]u8 = .{};
    const rbuf: []u8 = if (tcp_only) &no_rbuf else try r.gpa.alloc(u8, 4096);
    defer r.gpa.free(rbuf);

    var last_err: Error = error.Timeout;
    var attempt: u8 = 0;
    while (attempt < @max(1, r.effectiveAttempts())) : (attempt += 1) {
        if (r.callExpired()) return error.Timeout;
        const raw = r.exchangeOnce(server, packet, id, tcp_only, rbuf) catch |err| switch (err) {
            error.Canceled, error.OutOfMemory, error.MalformedResponse => |e| return e,
            else => {
                last_err = err;
                continue;
            },
        };
        return raw;
    }
    return last_err;
}

fn exchangeOnce(r: *Resolver, server: netaddr.Ip, packet: []const u8, id: u16, tcp_only: bool, rbuf: []u8) Error![]u8 {
    const raw = if (tcp_only) try r.streamExchange(server, packet) else udp: {
        const udp = try r.udpExchange(server, packet, id, rbuf, null);
        if (udp.truncated or (udp.data.len >= 3 and udp.data[2] & 0x02 != 0)) break :udp try r.streamExchange(server, packet);
        break :udp try r.gpa.dupe(u8, udp.data);
    };
    errdefer r.gpa.free(raw);
    if (raw.len < message.header_len or raw[2] & 0x80 == 0 or std.mem.readInt(u16, raw[0..2], .big) != id) return error.MalformedResponse;
    return raw;
}

/// Does `rcode` say the server failed, rather than answer? Then the next
/// server is asked. Observed of glibc 2.43 (`testdata/config_oracle.zig`
/// `rcodes`): SERVFAIL, NOTIMP and REFUSED send it on through every server
/// and attempt; FORMERR and NXDOMAIN end the lookup at the first server.
/// NOERROR is an answer, even an empty one.
pub fn serverFailed(rcode: message.Rcode) bool {
    return switch (rcode) {
        .serv_fail, .not_imp, .refused => true,
        else => false,
    };
}

/// `msg` when it is the answer, after freeing any failed reply kept before
/// it; null when `msg` is itself a failed server's reply, which then replaces
/// the one in `failed`.
fn settle(failed: *?message.Message, msg: message.Message) ?message.Message {
    if (failed.*) |*m| m.deinit();
    failed.* = null;
    if (!serverFailed(msg.rcode())) return msg;
    failed.* = msg;
    return null;
}

fn encodeChecked(r: *const Resolver, buf: []u8, name: []const u8, ty: message.Type, id: u16) Error![]u8 {
    return r.encodeFor(buf, name, ty, id, true);
}

/// `edns = false`: the plain RFC 1035 form for a server that refused EDNS —
/// no OPT record, so no DO bit and no options either.
fn encodeFor(r: *const Resolver, buf: []u8, name: []const u8, ty: message.Type, id: u16, edns: bool) Error![]u8 {
    // `edns = true` passes the options as configured, so a DO bit or options
    // without `edns_udp_size` is still refused (`InvalidOptions`); only the
    // fallback strips the OPT-borne fields on purpose.
    return message.encodeQuery(buf, name, ty, .{
        .id = id,
        .edns_udp_size = if (edns) r.options.edns_udp_size else null,
        .recursion_desired = r.options.recursion_desired,
        .dnssec_ok = edns and r.options.dnssec_ok,
        .authentic_data = r.options.authentic_data,
        .checking_disabled = r.options.checking_disabled,
        .edns_options = if (edns) r.options.edns_options else &.{},
    }) catch |err| switch (err) {
        error.BufferTooSmall => unreachable, // max_query_len always fits
        error.NameTooLong => error.NameTooLong,
        error.BadName => error.BadName,
        error.EdnsRequired, error.TooManyOptions => error.InvalidOptions,
    };
}

/// Decode `raw` and accept it only as a response to the query
/// `(id, name, ty)`: QR set, id equal, and — RFC 5452 §9.1 — exactly one
/// question that echoes our name (case-insensitive), type and class IN.
/// Before the question check an off-path attacker needed only the 16-bit id
/// and the source port; a reply whose question section named some other
/// name, or had no question section at all, was taken as the answer to ours.
fn decodeResponse(r: *Resolver, raw: []const u8, id: u16, name: []const u8, ty: message.Type) Error!message.Message {
    var msg = message.decode(r.gpa, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    errdefer msg.deinit();
    if (!msg.header.response or msg.header.id != id) return error.MalformedResponse;
    if (msg.questions.len != 1) return error.MalformedResponse;
    const q = msg.questions[0];
    if (q.ty != ty or q.class != .in or !namesEqual(q.name, name)) return error.MalformedResponse;
    // RFC 6840 §5.7 / glibc `trust-ad`: AD passes only when asked for.
    if (!r.options.authentic_data) msg.header.authentic_data = false;
    return msg;
}

// ── configuration plumbing ──────────────────────────────────────────────────

/// Go's fallback when resolv.conf is missing or names no servers.
const default_servers = [_]netaddr.Ip{
    .{ .v4 = .{ 127, 0, 0, 1 } },
    .{ .v6 = @as([15]u8, @splat(0)) ++ [_]u8{1} },
};

/// One family's query result folded into `lookupIpTtl`'s state: addresses
/// collected (owner-chain checked), TTL, and failures remembered — a failed
/// family is tolerated (Go aggregates too) but marks the result `partial`.
fn takeFamily(r: *Resolver, list: *std.ArrayList(netaddr.Ip), candidate: []const u8, res: *Error!message.Message, candidate_ttl: *?u32, last_err: *?Error, partial: *bool) Error!void {
    const msg = res.* catch |err| switch (err) {
        error.Canceled, error.OutOfMemory => |e| return e,
        else => {
            last_err.* = err;
            partial.* = true;
            return;
        },
    };
    // A failure rcode is the server's outage, not an empty answer (`query`
    // returns it once every server failed that way).
    if (serverFailed(msg.rcode())) {
        last_err.* = error.ServerFailed;
        partial.* = true;
        return;
    }
    const before = list.items.len;
    try collectAddresses(r.gpa, list, &msg, candidate);
    candidate_ttl.* = minTtl(candidate_ttl.*, answerTtl(msg.answers, msg.authorities, candidate, list.items.len > before));
}

fn queryInto(r: *Resolver, name: []const u8, ty: message.Type, out: *(Error!message.Message)) void {
    out.* = r.query(name, ty);
}

fn familyAllows(f: Family, ip: netaddr.Ip) bool {
    return switch (f) {
        .any => true,
        .v4 => ip == .v4,
        .v6 => ip == .v6,
    };
}

/// `gpa` behind a spin lock, for the two concurrent family queries: the
/// caller's allocator need not be thread-safe. Held only for the allocator
/// call itself.
const LockedAllocator = struct {
    child: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,

    fn allocator(l: *LockedAllocator) std.mem.Allocator {
        return .{ .ptr = l, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn lock(l: *LockedAllocator) void {
        while (!l.mutex.tryLock()) std.atomic.spinLoopHint();
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const l: *LockedAllocator = @ptrCast(@alignCast(ctx));
        l.lock();
        defer l.mutex.unlock();
        return l.child.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const l: *LockedAllocator = @ptrCast(@alignCast(ctx));
        l.lock();
        defer l.mutex.unlock();
        return l.child.rawResize(m, a, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const l: *LockedAllocator = @ptrCast(@alignCast(ctx));
        l.lock();
        defer l.mutex.unlock();
        return l.child.rawRemap(m, a, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const l: *LockedAllocator = @ptrCast(@alignCast(ctx));
        l.lock();
        defer l.mutex.unlock();
        l.child.rawFree(m, a, ra);
    }
};

/// A stream for every query: `transport = .tcp` or `.tls`, or resolv.conf
/// `use-vc` (when read) with `transport` left `.auto`.
fn useTcp(r: *const Resolver) bool {
    if (r.options.transport != .auto) return true;
    return if (r.conf) |c| c.use_vc else false;
}

/// The family `lookupIpTtl` asks for: `Options.family`, or `.v4` for
/// resolv.conf `no-aaaa` when the option was left `.any`.
fn effectiveFamily(r: *const Resolver) Family {
    if (r.options.family != .any) return r.options.family;
    if (r.conf) |c| if (c.no_aaaa) return .v4;
    return .any;
}

fn parallelFamilies(r: *const Resolver) bool {
    if (!r.options.parallel_families) return false;
    return if (r.conf) |c| !c.single_request else true;
}

/// First server index for this query: 0, or the next in turn with `rotate`.
fn rotateStart(r: *Resolver, n: usize) usize {
    const on = r.options.rotate or (if (r.conf) |c| c.rotate else false);
    if (!on or n == 0) return 0;
    const i = r.rotate_next % n;
    r.rotate_next = i + 1;
    return i;
}

fn serverList(r: *Resolver) Error![]const netaddr.Ip {
    if (r.options.servers.len > 0) return r.options.servers;
    try r.ensureConfig();
    const from_conf = r.conf.?.servers();
    return if (from_conf.len > 0) from_conf else &default_servers;
}

fn ensureConfig(r: *Resolver) Error!void {
    if (r.conf != null) return;
    const text = std.Io.Dir.cwd().readFileAlloc(
        r.io,
        r.options.resolv_conf_path,
        r.gpa,
        .limited(64 * 1024),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => try r.gpa.alloc(u8, 0), // unreadable → glibc-style defaults
    };
    r.conf_text = text;
    r.conf = config.parseResolvConf(text);
}

fn readHosts(r: *Resolver) ?[]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        r.io,
        r.options.hosts_path,
        r.gpa,
        .limited(1 << 20),
    ) catch null;
}

fn sortIps(ips: []netaddr.Ip) void {
    if (comptime builtin.os.tag != .linux) return; // systemSource is Linux-only
    // The candidate bound lives in `netaddr` and is enforced there; an answer
    // set larger than it is left in the order it arrived rather than being
    // sorted in part. This used to re-check the length here too, which meant
    // the rule was written twice and the one that mattered was an assert.
    netaddr.sortDestinations(ips, netaddr.systemSource) catch {};
}

// ── transports ──────────────────────────────────────────────────────────────

fn toNetAddress(ip: netaddr.Ip, port: u16) net.IpAddress {
    return switch (ip) {
        .v4 => |b| .{ .ip4 = .{ .bytes = b, .port = port } },
        .v6 => |b| .{ .ip6 = .{ .bytes = b, .port = port } },
    };
}

fn attemptDeadline(r: *Resolver) std.Io.Timeout {
    const ms = r.effectiveTimeoutMs();
    const per: std.Io.Timeout = if (ms == 0) .none else blk: {
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
        break :blk t.toDeadline(r.io);
    };
    const call = r.call_deadline orelse return per;
    return switch (per) {
        .deadline => |d| if (d.compare(.lte, call)) per else .{ .deadline = call },
        else => .{ .deadline = call },
    };
}

/// Start the `call_timeout_ms` budget if no outer call already did; returns
/// whether this call owns it (pass to `endCall`).
fn beginCall(r: *Resolver) bool {
    if (r.call_deadline != null or r.options.call_timeout_ms == 0) return false;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(r.options.call_timeout_ms), .clock = .awake } };
    r.call_deadline = t.toTimestamp(r.io);
    return true;
}

fn endCall(r: *Resolver, owns: bool) void {
    if (owns) r.call_deadline = null;
}

/// The call budget is spent: no further attempt may start.
fn callExpired(r: *Resolver) bool {
    const d = r.call_deadline orelse return false;
    return std.Io.Clock.Timestamp.now(r.io, .awake).compare(.gte, d);
}

// F10 (audit): `config.ResolvConf.timeout_s`/`.attempts` used to be parsed,
// capped and tested (`parseResolvConf: glibc option caps`) and then simply
// never read anywhere outside `config.zig` -- `Options.timeout_ms`/
// `.attempts` always won, silently, even when an administrator had set
// `options timeout:1 attempts:1` specifically to bound the F5 amplification
// (7 minutes at the shipped defaults). Q8 (round 2, 2026-09-11): a "safe
// default plus an escape hatch" choice between two equally-valid semantics,
// decided here rather than left to the user, because it is a design
// preference with no norm behind it, not a security defect with one right
// answer. Chosen: HONOR resolv.conf when the caller left `Options` at its
// own struct default -- an administrator's explicit, deliberately tightened
// resolv.conf value is the shorter of "silently ignored" and "silently
// obeyed", and obeying it is what glibc and Go (the two resolvers this
// module already claims to mirror) both do. The escape hatch is any
// explicit `Options.timeout_ms`/`.attempts` value: it always wins, on the
// classic UDP/TCP path (DoH's timeout is set once at `init`, from the same
// field, before resolv.conf is ever read -- untouched by this). The
// documented cost, unchanged from the original finding: a caller who
// explicitly writes `.timeout_ms = 5000` (the struct default's own value)
// is indistinguishable from one who left it unset, so that one caller's
// explicit choice is what yields to resolv.conf instead of overriding it --
// no `Options` field can tell "left alone" apart from "chosen to match the
// default" without becoming `?u32`, itself a breaking type change.
fn effectiveTimeoutMs(r: *Resolver) u32 {
    if (r.options.timeout_ms == default_timeout_ms) {
        if (r.conf) |c| return @as(u32, c.timeout_s) * 1000;
    }
    return r.options.timeout_ms;
}

fn effectiveAttempts(r: *Resolver) u8 {
    if (r.options.attempts == default_attempts) {
        if (r.conf) |c| return c.attempts;
    }
    return r.options.attempts;
}

/// `attemptDeadline` as the absolute timestamp `runBounded` takes; null when
/// `timeout_ms == 0` (no bound, by the caller's choice).
fn attemptTimestamp(r: *Resolver) ?std.Io.Clock.Timestamp {
    return r.attemptDeadline().toTimestamp(r.io);
}

fn BoundedResult(comptime func: anytype) type {
    const eu = @typeInfo(@typeInfo(@TypeOf(func)).@"fn".return_type.?).error_union;
    return (eu.error_set || error{ConcurrencyUnavailable})!eu.payload;
}

/// Run `func(args)` on its own concurrent task and give it until `deadline`
/// (null = no bound). The same construction as `http.Client.runBounded`
/// (module-private there, hence a copy): std 0.16.0 offers no per-read
/// deadline on a `net.Stream` — the read/write/connect syscalls take no
/// timeout and there is no `SO_RCVTIMEO` seam — but `Io.Threaded` implements
/// `Future.cancel` by signalling the task's thread until the blocked syscall
/// returns `EINTR`, so "run it over there, then cancel it at the deadline"
/// is the one way to bound a blocking TCP exchange. That only works for a
/// task the `Io` owns: a syscall on the caller's own thread has no
/// cancelation state, which is why this spawns rather than sleeps.
///
/// Contract: finished in time → `func`'s own result; deadline hit → the task
/// is canceled and JOINED (its frame borrows this stack), then
/// `error.Timeout` — unless it completed inside the cancelation window, in
/// which case its value is returned (a response the task already allocated
/// must not be dropped); this task canceled while waiting → the same unwind,
/// then `error.Canceled`; no unit of concurrency → `error.ConcurrencyUnavailable`,
/// never a silent unbounded run.
fn runBounded(
    io: std.Io,
    deadline: ?std.Io.Clock.Timestamp,
    comptime func: anytype,
    args: std.meta.ArgsTuple(@TypeOf(func)),
) BoundedResult(func) {
    const Result = @typeInfo(@TypeOf(func)).@"fn".return_type.?;
    const Ctx = struct {
        io: std.Io,
        args: std.meta.ArgsTuple(@TypeOf(func)),
        result: Result = undefined,
        /// 0 while the task runs, 1 once `result` is published; doubles as
        /// the futex word the waiter parks on.
        state: std.atomic.Value(u32) = .init(0),

        fn run(ctx: *@This()) void {
            ctx.result = @call(.auto, func, ctx.args);
            ctx.state.store(1, .release);
            ctx.io.futexWake(u32, &ctx.state.raw, 1);
        }
    };

    var ctx: Ctx = .{ .io = io, .args = args };
    var future = try io.concurrent(Ctx.run, .{&ctx});

    var canceled = false;
    var expired = false;
    while (ctx.state.load(.acquire) == 0) {
        const timeout: std.Io.Timeout = if (deadline) |d| t: {
            if (d.durationFromNow(io).raw.nanoseconds <= 0) {
                expired = true;
                break;
            }
            break :t .{ .deadline = d };
        } else .none;
        // Spurious wakeups are allowed here; the loop re-reads `state`.
        io.futexWaitTimeout(u32, &ctx.state.raw, 0, timeout) catch {
            canceled = true;
            break;
        };
    }
    if (!expired and !canceled) {
        future.await(io);
        return ctx.result;
    }
    future.cancel(io);
    // `cancel` joined the task, so `result` is written either way. A success
    // that landed in the cancelation window is still a success.
    if (ctx.result) |value| return value else |_| {}
    return if (expired) error.Timeout else error.Canceled;
}

/// Result of one UDP round-trip: `data` points into the caller's `rbuf`, and
/// `truncated` is the kernel's own verdict (`MSG_TRUNC`) on whether the full
/// datagram fit — independent of whatever the TC bit inside `data` says,
/// because a server that sends an oversized reply without setting TC (a bug,
/// or indifference to what it advertised) still gets its delivery truncated
/// by the socket layer (audit F13).
const UdpResult = struct {
    data: []u8,
    truncated: bool,
};

/// What `query` asked, for `udpExchange` to recognise its answer by.
const Expect = struct { name: []const u8, ty: message.Type };

/// One UDP round-trip. Datagrams from the wrong peer, with the wrong id, that
/// are no response or (with `expect`) no answer to the question are ignored
/// (anti-spoofing, same as Go/c-ares) until the deadline.
/// The returned slice points into `rbuf`.
fn udpExchange(r: *Resolver, server: netaddr.Ip, packet: []const u8, id: u16, rbuf: []u8, expect: ?Expect) Error!UdpResult {
    const io = r.io;
    const dest = toNetAddress(server, r.options.port);
    const bind_addr: net.IpAddress = switch (server) {
        .v4 => .{ .ip4 = .unspecified(0) },
        .v6 => .{ .ip6 = .unspecified(0) },
    };
    const sock = bind_addr.bind(io, .{ .mode = .dgram }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.NetworkFailed,
    };
    defer sock.close(io);
    sock.send(io, &dest, packet) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.NetworkFailed,
    };

    const deadline = r.attemptDeadline();
    while (true) {
        const incoming = sock.receiveTimeout(io, rbuf, deadline) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Canceled,
            else => return error.NetworkFailed,
        };
        if (!incoming.from.eql(&dest)) continue;
        if (incoming.data.len < message.header_len) continue;
        if (std.mem.readInt(u16, incoming.data[0..2], .big) != id) continue;
        // A datagram that has our id but is not a response (QR clear), or --
        // for `query` -- does not decode or does not echo our question, is
        // not the answer either (RFC 5452 §9.1): drop it and keep waiting to
        // the same deadline instead of failing the whole query (sweep
        // REV-dns-4: the id is only 16 bits, an off-path forger sending a
        // junk datagram with a guessed id and port used to end the query).
        // A truncated reply is not decoded here, it goes to TCP.
        if (incoming.data[2] & 0x80 == 0) continue;
        if (expect) |e| if (!incoming.flags.trunc and incoming.data[2] & 0x02 == 0) {
            var m = r.decodeResponse(incoming.data, id, e.name, e.ty) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue,
            };
            m.deinit();
        };
        return .{ .data = incoming.data, .truncated = incoming.flags.trunc };
    }
}

/// Distinguish a canceled wait from a genuine read/write failure using the
/// concrete `Stream.Reader`/`Stream.Writer`'s out-of-band `err` field —
/// `Io.Reader.Error`/`Io.Writer.Error` cannot carry `Canceled` themselves.
/// `tcpExchange` is the only place in this file that owns a TCP fd directly
/// (`udpExchange` gets `Io.Cancelable` intact from `Socket.Send`/
/// `ReceiveTimeoutError` already, nothing to recover there).
fn readFailure(sr: *const net.Stream.Reader) Error {
    if (sr.err) |e| if (e == error.Canceled) return error.Canceled;
    return error.NetworkFailed;
}

fn writeFailure(sw: *const net.Stream.Writer) Error {
    if (sw.err) |e| if (e == error.Canceled) return error.Canceled;
    return error.NetworkFailed;
}

/// One TCP round-trip: 2-byte big-endian length prefix both ways
/// (RFC 1035 §4.2.2). Returns a gpa-owned response. The WHOLE exchange —
/// connect, write, the length read and the body read — runs under
/// `attemptDeadline` via `runBounded`. Before that, `timeout_ms` bounded the
/// UDP path only: a server that accepted the TCP connection and never
/// answered (or announced a 65 535-byte length and trickled it) held the
/// caller until the OS gave up, and reaching this path needed no
/// `transport = .tcp` — one UDP datagram with the TC bit set was enough.
/// `timeout_ms == 0` runs unbounded, as documented. An `Io` without a unit
/// of concurrency to spare cannot be bounded and fails this attempt with
/// `error.NetworkFailed` rather than run it without a deadline.
fn tcpExchange(r: *Resolver, server: netaddr.Ip, packet: []const u8) Error![]u8 {
    const deadline = r.attemptTimestamp() orelse return tcpExchangeInner(r, server, packet);
    return runBounded(r.io, deadline, tcpExchangeInner, .{ r, server, packet }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.NetworkFailed,
        else => |e| return e,
    };
}

fn tcpExchangeInner(r: *Resolver, server: netaddr.Ip, packet: []const u8) Error![]u8 {
    const io = r.io;
    const dest = toNetAddress(server, r.options.port);
    // No native connect timeout in std 0.16.0 Io.Threaded (same TODO as
    // http.Client); the deadline is enforced from outside by `runBounded`.
    const stream = dest.connect(io, .{ .mode = .stream }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout => return error.Timeout,
        else => return error.NetworkFailed,
    };
    defer stream.close(io);

    var wbuf: [message.max_query_len + 2]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    const w = &sw.interface;
    // `packet.len` fits: `query` sends at most `max_query_len` bytes and
    // `exchange` refuses anything over 65 535 before it gets here.
    w.writeInt(u16, @intCast(packet.len), .big) catch return writeFailure(&sw);
    w.writeAll(packet) catch return writeFailure(&sw);
    w.flush() catch return writeFailure(&sw);

    var tbuf: [4096]u8 = undefined;
    var sr = stream.reader(io, &tbuf);
    const len = sr.interface.takeInt(u16, .big) catch |e| switch (e) {
        error.EndOfStream => return error.NetworkFailed,
        error.ReadFailed => return readFailure(&sr),
    };
    const out = try r.gpa.alloc(u8, len);
    errdefer r.gpa.free(out);
    sr.interface.readSliceAll(out) catch |e| switch (e) {
        error.EndOfStream => return error.NetworkFailed,
        error.ReadFailed => return readFailure(&sr),
    };
    return out;
}

/// The framed exchange of the chosen stream transport: TLS for `.tls`, plain
/// TCP otherwise. Both return a gpa-owned response.
fn streamExchange(r: *Resolver, server: netaddr.Ip, packet: []const u8) Error![]u8 {
    if (r.options.transport == .tls) return r.tlsExchange(server, packet);
    return r.tcpExchange(server, packet);
}

/// One DoT round-trip (RFC 7858): `tcpExchange`'s shape with a TLS session
/// between the socket and the framing, one connection per exchange. The whole
/// thing -- connect, handshake, write, both reads -- runs under
/// `attemptDeadline` via `runBounded`.
fn tlsExchange(r: *Resolver, server: netaddr.Ip, packet: []const u8) Error![]u8 {
    if (!dot_enabled) return error.NoDotSupport;
    const deadline = r.attemptTimestamp() orelse return tlsExchangeInner(r, server, packet);
    return runBounded(r.io, deadline, tlsExchangeInner, .{ r, server, packet }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.NetworkFailed,
        else => |e| return e,
    };
}

fn tlsExchangeInner(r: *Resolver, server: netaddr.Ip, packet: []const u8) Error![]u8 {
    if (!dot_enabled) return error.NoDotSupport;
    const io = r.io;
    const gpa = r.gpa;
    const strict = r.options.dot_tls.verify == .strict;
    if (strict) r.dot_ca.load(gpa, io) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        else => return error.TlsFailed, // no trust anchors: nothing can be authenticated
    };

    // Socket-facing buffers hold a whole ciphertext record; the plaintext
    // side one record plus the 2-byte length. Heap, not stack: the handshake
    // is deep enough already.
    const record_len = tlsclient.Client.min_buffer_len;
    const slab = try gpa.alloc(u8, 3 * record_len + 512);
    defer {
        std.crypto.secureZero(u8, slab);
        gpa.free(slab);
    }
    const sock_r = slab[0..record_len];
    const sock_w = slab[record_len..][0..record_len];
    const tls_r = slab[2 * record_len ..][0..record_len];
    const tls_w = slab[3 * record_len ..][0..512];

    const dest = toNetAddress(server, r.options.dot_port);
    const stream = dest.connect(io, .{ .mode = .stream }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout => return error.Timeout,
        else => return error.NetworkFailed,
    };
    defer stream.close(io);
    var sr = stream.reader(io, sock_r);
    var sw = stream.writer(io, sock_w);

    var name_buf: [netaddr.max_ip_text_len]u8 = undefined;
    const host = r.options.tls_server_name orelse netaddr.formatIp(server, &name_buf);
    var entropy: [tlsclient.Client.Options.entropy_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &entropy);
    // Key material: fail closed instead of `io.random`'s fallback.
    io.randomSecure(&entropy) catch return error.TlsFailed;
    var tc: tlsclient.Client = undefined;
    tlsclient.Client.initInto(&tc, &sr.interface, &sw.interface, .{
        .host = if (strict) .{ .explicit = host } else .no_verification,
        .ca = if (strict) .{ .bundle = .{
            .gpa = gpa,
            .io = io,
            .lock = &r.dot_ca.lock,
            .bundle = &r.dot_ca.bundle,
        } } else .no_verification,
        .read_buffer = tls_r,
        .write_buffer = tls_w,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
    }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.ReadFailed => return readFailure(&sr),
        error.WriteFailed => return writeFailure(&sw),
        else => return error.TlsFailed,
    };
    const w = &tc.writer;
    w.writeInt(u16, @intCast(packet.len), .big) catch return writeFailure(&sw);
    w.writeAll(packet) catch return writeFailure(&sw);
    w.flush() catch return writeFailure(&sw);
    // The TLS writer hands its records to the socket writer; send them.
    sw.interface.flush() catch return writeFailure(&sw);

    const len = tc.reader.takeInt(u16, .big) catch |e| switch (e) {
        error.EndOfStream => return error.NetworkFailed,
        error.ReadFailed => return tlsReadFailure(&tc, &sr),
    };
    const out = try gpa.alloc(u8, len);
    errdefer gpa.free(out);
    tc.reader.readSliceAll(out) catch |e| switch (e) {
        error.EndOfStream => return error.NetworkFailed,
        error.ReadFailed => return tlsReadFailure(&tc, &sr),
    };
    // Best effort: close_notify, so the server sees a finished session.
    tc.end() catch {};
    sw.interface.flush() catch {};
    return out;
}

fn tlsReadFailure(tc: *const tlsclient.Client, sr: *const net.Stream.Reader) Error {
    if (sr.err) |e| if (e == error.Canceled) return error.Canceled;
    // A TLS-level fault (bad record, alert, truncation) is not a socket one.
    return if (tc.read_err != null) error.TlsFailed else error.NetworkFailed;
}

/// Cap for a DoH response body: a DNS message is at most 65 535 bytes
/// (RFC 8484 §6), so a larger body is invalid anyway (sweep REV-dns-1/-6: it
/// used to be 128 KiB, doubling the worst-case decode memory).
const max_doh_response = 65535;

/// RFC 8484 exchange over the http module. Returns the gpa-owned raw DNS
/// message from the response body.
fn dohExchange(r: *Resolver, packet: []const u8) Error![]u8 {
    if (!doh_enabled) return error.NoDohEndpoint;
    const url = r.options.doh_url orelse return error.NoDohEndpoint;
    const client = &(r.http_client.?);

    var res = switch (r.options.doh_method) {
        .post => client.request(.post, url, .{
            .headers = &.{
                .{ .name = "Content-Type", .value = "application/dns-message" },
                .{ .name = "Accept", .value = "application/dns-message" },
            },
            .body = packet,
        }),
        .get => blk: {
            const Encoder = std.base64.url_safe_no_pad.Encoder;
            var b64_buf: [Encoder.calcSize(message.max_query_len)]u8 = undefined;
            const dns_param = Encoder.encode(&b64_buf, packet);
            const sep: u8 = if (std.mem.findScalar(u8, url, '?') != null) '&' else '?';
            const full = r.gpa.print("{s}{c}dns={s}", .{ url, sep, dns_param }) catch
                return error.OutOfMemory;
            defer r.gpa.free(full);
            break :blk client.request(.get, full, .{
                .headers = &.{.{ .name = "Accept", .value = "application/dns-message" }},
            });
        },
    } catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        error.Timeout => return error.Timeout,
        else => return error.DohFailed,
    };
    defer res.deinit();
    if (res.status != 200) return error.DohFailed;
    return res.readAllAlloc(r.gpa, max_doh_response) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.DohFailed,
    };
}

// ── DoH-JSON (application/dns-json) ─────────────────────────────────────────

/// The Google/Cloudflare `application/dns-json` schema (the fields we care
/// about; unknown ones are ignored). Record data stays textual — parse
/// A/AAAA `data` with `netaddr.parseIp` if needed.
pub const JsonMessage = struct {
    Status: u32 = 0,
    TC: bool = false,
    Question: []const JsonQuestion = &.{},
    Answer: []const JsonRecord = &.{},
    Authority: []const JsonRecord = &.{},

    pub const JsonQuestion = struct {
        name: []const u8 = "",
        type: u16 = 0,
    };

    pub const JsonRecord = struct {
        name: []const u8 = "",
        type: u16 = 0,
        TTL: u32 = 0,
        data: []const u8 = "",
    };
};

pub const JsonAnswer = std.json.Parsed(JsonMessage);

/// Query via the non-standard-but-common DoH-JSON API. `Options.doh_url`
/// must point at a JSON-capable endpoint (https://dns.google/resolve or
/// https://cloudflare-dns.com/dns-query). Free with `JsonAnswer.deinit`.
pub fn queryJson(r: *Resolver, name: []const u8, ty: message.Type) Error!JsonAnswer {
    const owns_call = r.beginCall();
    defer r.endCall(owns_call);
    if (!doh_enabled) return error.NoDohEndpoint;
    const url = r.options.doh_url orelse return error.NoDohEndpoint;
    const client = &(r.http_client.?);

    const full = try jsonQueryUrl(r.gpa, url, name, ty);
    defer r.gpa.free(full);

    var res = client.request(.get, full, .{
        .headers = &.{.{ .name = "Accept", .value = "application/dns-json" }},
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        error.Timeout => return error.Timeout,
        else => return error.DohFailed,
    };
    defer res.deinit();
    if (res.status != 200) return error.DohFailed;
    const body = res.readAllAlloc(r.gpa, max_doh_response) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.DohFailed,
    };
    defer r.gpa.free(body);

    return std.json.parseFromSlice(JsonMessage, r.gpa, body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always, // body is freed on return
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
}

/// `url?name=<name>&type=<n>` for the DoH-JSON API. `name` is held to the
/// SAME rule the wire path applies (`writeName`: non-empty labels of at most
/// 63 bytes, 253 chars total — `error.BadName`/`error.NameTooLong` otherwise)
/// and then percent-encoded, so no byte a caller passes reaches the
/// request-line as syntax: RFC 3986 §2.3 unreserved characters pass, every
/// other byte — `&`, `=`, `#`, space, CR, LF, `%` itself — becomes `%XX`.
/// This was the one place in the module where a caller's name went onto the
/// wire unvalidated and unescaped: `name = "a&type=255&name=b"` rewrote the
/// query, and a name with a bare LF split the HTTP request line.
fn jsonQueryUrl(gpa: std.mem.Allocator, url: []const u8, name: []const u8, ty: message.Type) Error![]u8 {
    var discard: [message.max_name_text_len + 2]u8 = undefined;
    var w: std.Io.Writer = .fixed(&discard);
    message.writeName(&w, name) catch |err| switch (err) {
        error.NameTooLong, error.WriteFailed, error.BufferTooSmall => return error.NameTooLong,
        error.BadName => return error.BadName,
    };

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, url);
    try out.append(gpa, if (std.mem.findScalar(u8, url, '?') != null) '&' else '?');
    try out.appendSlice(gpa, "name=");
    for (name) |b| {
        if (std.ascii.isAlphanumeric(b) or b == '-' or b == '.' or b == '_' or b == '~') {
            try out.append(gpa, b);
        } else {
            const hex = "0123456789ABCDEF";
            try out.appendSlice(gpa, &.{ '%', hex[b >> 4], hex[b & 0xf] });
        }
    }
    try out.print(gpa, "&type={d}", .{@backingInt(ty)});
    return out.toOwnedSlice(gpa);
}

// ── tests (offline) ─────────────────────────────────────────────────────────

const testing = std.testing;

test "DoH-JSON schema parses a canned Cloudflare response" {
    const body =
        \\{"Status":3,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,
        \\ "Question":[{"name":"example.com","type":1}],
        \\ "Answer":[{"name":"example.com","type":1,"TTL":86400,"data":"93.184.216.34"},
        \\           {"name":"example.com","type":46,"TTL":86400,"data":"a 8 2 86400 sig"}],
        \\ "extra_field_from_the_future":{"x":1}}
    ;
    const parsed = try std.json.parseFromSlice(JsonMessage, testing.allocator, body, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    try testing.expectEqual(@as(u32, 3), parsed.value.Status);
    try testing.expectEqual(@as(usize, 1), parsed.value.Question.len);
    try testing.expectEqual(@as(usize, 2), parsed.value.Answer.len);
    try testing.expectEqual(@as(u16, 1), parsed.value.Answer[0].type);
    try testing.expectEqual(@as(u32, 86400), parsed.value.Answer[0].TTL);
    try testing.expectEqualStrings("93.184.216.34", parsed.value.Answer[0].data);
    // A-record data is netaddr-parseable.
    try testing.expect(netaddr.parseIp(parsed.value.Answer[0].data) != null);
}

test "decodeResponse rejects id mismatch and non-response packets (anti-spoofing)" {
    // decodeResponse is the only place the id/QR correlation check lives;
    // every live test above only ever sees a genuine, correctly-matched
    // reply, so this check has no coverage without a dedicated offline
    // test. `io` is unused by decodeResponse itself, so `undefined` is
    // fine here.
    var r: Resolver = .{
        .io = undefined,
        .gpa = testing.allocator,
        .options = .{},
        .http_client = null,
        .conf = null,
        .conf_text = null,
    };

    // A minimal, well-formed response: QR set, id 0x1234, our question echoed.
    const good = "\x12\x34" ++ "\x80\x00" ++ "\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x07example\x03com\x00" ++ "\x00\x01" ++ "\x00\x01";

    var msg = try r.decodeResponse(good, 0x1234, "example.com", .a);
    msg.deinit();

    // Same packet, wrong expected id: rejected, not silently accepted.
    try testing.expectError(error.MalformedResponse, r.decodeResponse(good, 0x1235, "example.com", .a));

    // QR=0 (a query, not a response) with the matching id: also rejected.
    var not_response = good.*;
    not_response[2] = 0x00;
    try testing.expectError(error.MalformedResponse, r.decodeResponse(&not_response, 0x1234, "example.com", .a));
}

test "decodeResponse: AD in a reply reaches the caller only with Options.authentic_data (RFC 6840 \u{a7}5.7, glibc trust-ad)" {
    var r: Resolver = .{
        .io = undefined,
        .gpa = testing.allocator,
        .options = .{},
        .http_client = null,
        .conf = null,
        .conf_text = null,
    };
    // QR | RD | RA | AD, id 0x1234, our question.
    const ad_reply = "\x12\x34" ++ "\x81\xa0" ++ "\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x07example\x03com\x00" ++ "\x00\x01" ++ "\x00\x01";
    var m1 = try r.decodeResponse(ad_reply, 0x1234, "example.com", .a);
    try testing.expect(!m1.header.authentic_data);
    m1.deinit();
    r.options.authentic_data = true;
    var m2 = try r.decodeResponse(ad_reply, 0x1234, "example.com", .a);
    try testing.expect(m2.header.authentic_data);
    m2.deinit();
}

test "Options.dnssec_ok without EDNS, or an oversized edns_options list, is InvalidOptions" {
    var r: Resolver = .{
        .io = undefined,
        .gpa = testing.allocator,
        .options = .{ .edns_udp_size = null, .dnssec_ok = true },
        .http_client = null,
        .conf = null,
        .conf_text = null,
    };
    var buf: [message.max_query_len]u8 = undefined;
    try testing.expectError(error.InvalidOptions, r.encodeChecked(&buf, "example.com", .a, 1));
    const big: [message.max_edns_options_len]u8 = @splat(0);
    r.options = .{ .edns_options = &.{.{ .code = 12, .data = &big }} };
    try testing.expectError(error.InvalidOptions, r.encodeChecked(&buf, "example.com", .a, 1));
    r.options = .{ .dnssec_ok = true, .checking_disabled = true };
    const q = try r.encodeChecked(&buf, "example.com", .a, 7);
    try testing.expectEqual(@as(u8, 0x01), q[2]); // RD
    try testing.expectEqual(@as(u8, 0x10), q[3]); // CD, no AD
}

test "decodeResponse: the echoed question must be OUR question — name, type, class, and exactly one (RFC 5452 \u{a7}9.1)" {
    // Before this check a reply needed only the id: a question section
    // naming `attacker.example TXT`, no question section at all, and a CH
    // class echo were all accepted as the answer to `example.com A`.
    var r: Resolver = .{
        .io = undefined,
        .gpa = testing.allocator,
        .options = .{},
        .http_client = null,
        .conf = null,
        .conf_text = null,
    };
    const head = "\x12\x34" ++ "\x80\x00";

    // (a) a different name
    const other_name = head ++ "\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x08attacker\x07example\x00" ++ "\x00\x01" ++ "\x00\x01";
    try testing.expectError(error.MalformedResponse, r.decodeResponse(other_name, 0x1234, "example.com", .a));
    // (b) no question section at all
    const no_question = head ++ "\x00\x00\x00\x00\x00\x00\x00\x00";
    try testing.expectError(error.MalformedResponse, r.decodeResponse(no_question, 0x1234, "example.com", .a));
    // (c) two questions
    const two = head ++ "\x00\x02\x00\x00\x00\x00\x00\x00" ++ "\x07example\x03com\x00\x00\x01\x00\x01" ++ "\x07example\x03com\x00\x00\x01\x00\x01";
    try testing.expectError(error.MalformedResponse, r.decodeResponse(two, 0x1234, "example.com", .a));
    // (d) our name, wrong type
    const wrong_type = head ++ "\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x07example\x03com\x00" ++ "\x00\x10" ++ "\x00\x01";
    try testing.expectError(error.MalformedResponse, r.decodeResponse(wrong_type, 0x1234, "example.com", .a));
    // (e) our name and type, class CH
    const wrong_class = head ++ "\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x07example\x03com\x00" ++ "\x00\x01" ++ "\x00\x03";
    try testing.expectError(error.MalformedResponse, r.decodeResponse(wrong_class, 0x1234, "example.com", .a));

    // Accepted: case differences (RFC 4343 — 0x20 randomization echoes the
    // query's case, other servers normalize) and our own trailing root dot.
    const upper = head ++ "\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x07EXAMPLE\x03Com\x00" ++ "\x00\x01" ++ "\x00\x01";
    var m1 = try r.decodeResponse(upper, 0x1234, "example.com", .a);
    m1.deinit();
    var m2 = try r.decodeResponse(upper, 0x1234, "Example.COM.", .a);
    m2.deinit();
}

// ── the hermetic half of the loopback question-check anchor (audit F20) ──────
//
// The frames below are not hand-written: `modules/dns/tools/interop.zig` binds
// a real UDP socket on 127.0.0.1, serves each of them to a real `query()` from
// a real second thread, checks the verdict there, and commits the exact bytes
// that travelled. So the frames carry what a hand-built vector cannot — that
// the wire path really does hand `decodeResponse` this question — while the
// per-commit lane pays no socket, no thread and no timeout for it.
//
// ⭐ WHY THAT MATTERS, MEASURED. Until 2026-09-08 this assertion lived in
// `test "query: a reply whose question is not ours is not the answer, over
// loopback"`, which drove the same exchange over a socket and then read the
// stub's `served` counter — from THIS thread, while the stub thread was still
// runnable, because the joining `await` was a `defer` and ran after the
// assertions. It failed twice in the wild (three concurrent agents on
// 2026-09-07, `scripts/test.sh all` on 2026-09-08), always as `expected 1,
// found 0`: the resolver had received the datagram and rejected it correctly
// every time, and only the measurement was wrong. Reproduced on 8 cores with
// 32 busy loops: 10 failures in 20 runs. This replacement has nothing to
// schedule and nothing to lose a race with; under that same load it passed
// 30 of 30, and the whole 70-test suite 10 of 10.
test "decodeResponse: the replies `interop-dns` captured off a real socket — hostile refused, honest accepted" {
    var r: Resolver = .{
        .io = undefined, // decodeResponse performs no I/O
        .gpa = testing.allocator,
        .options = .{},
        .http_client = null,
        .conf = null,
        .conf_text = null,
    };

    const wrong_question: []const u8 = @embedFile("testdata/reply_wrong_question.bin");
    const no_question: []const u8 = @embedFile("testdata/reply_no_question.bin");
    const honest: []const u8 = @embedFile("testdata/reply_honest.bin");

    // The expected id is read OUT of each frame (the recorder normalises it,
    // because `query` rolls a fresh id per datagram — audit F9). Taking it from
    // the frame is deliberate: it makes the id check pass by construction, so
    // what these three cases measure is the QUESTION check alone. The id/QR
    // check has its own test above.
    for ([_][]const u8{ wrong_question, no_question }) |frame| {
        const id = std.mem.readInt(u16, frame[0..2], .big);
        try testing.expectError(error.MalformedResponse, r.decodeResponse(frame, id, "example.com", .a));
    }

    // ⭐ Positive control, without which the two lines above stay green against
    // a `decodeResponse` that refuses everything and against a fixture that has
    // decayed into garbage: the honest capture decodes, and the off-bailiwick
    // record it also carries is dropped one layer up rather than here.
    const honest_id = std.mem.readInt(u16, honest[0..2], .big);
    var msg = try r.decodeResponse(honest, honest_id, "example.com", .a);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 2), msg.answers.len);

    var list: std.ArrayList(netaddr.Ip) = .empty;
    defer list.deinit(testing.allocator);
    try collectAddresses(testing.allocator, &list, &msg, "example.com");
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expect(list.items[0].eql(netaddr.parseIp("192.0.2.1").?)); // never 203.0.113.66
}

test "collectAddresses: only the queried owner and its CNAME chain count (bailiwick)" {
    // A reply to `example.com A` whose answer section carries an A record
    // for `victim.test`: `lookupIp` used to return that address. With a
    // CNAME chain (example.com -> www.example.com -> cdn.example.net), the
    // addresses of the chain's END are the answer; a record owned by a name
    // the chain never reaches is not, even in the same section.
    const resp = "\x00\x01\x81\x80" ++ "\x00\x01\x00\x05\x00\x00\x00\x00" ++
        // question @12: example.com A IN  (ends @29)
        "\x07example\x03com\x00\x00\x01\x00\x01" ++
        // @29: victim.test A 203.0.113.66 — NOT ours
        "\x06victim\x04test\x00" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xcb\x00\x71\x42" ++
        // @56: cdn.example.net A 198.51.100.7 — reached only via the chain, listed BEFORE the CNAMEs (order must not matter); ends @87
        "\x03cdn\x07example\x03net\x00" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xc6\x33\x64\x07" ++
        // @87: example.com (ptr @12) CNAME www.example.com  (rdata @99: "\x03www" + ptr @12)
        "\xc0\x0c" ++ "\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x06" ++ "\x03www\xc0\x0c" ++
        // @105: www.example.com (ptr @99 = 0x63) CNAME cdn.example.net (ptr @56 = 0x38)
        "\xc0\x63" ++ "\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x02" ++ "\xc0\x38" ++
        // @119: EXAMPLE.COM (different case, uncompressed) A 192.0.2.9 — ours
        "\x07EXAMPLE\x03COM\x00" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xc0\x00\x02\x09";
    var msg = try message.decode(testing.allocator, resp);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 5), msg.answers.len);
    try testing.expectEqualStrings("cdn.example.net", msg.answers[3].data.cname);

    var list: std.ArrayList(netaddr.Ip) = .empty;
    defer list.deinit(testing.allocator);
    try collectAddresses(testing.allocator, &list, &msg, "example.com");
    try testing.expectEqual(@as(usize, 2), list.items.len);
    try testing.expect(list.items[0].eql(netaddr.parseIp("198.51.100.7").?));
    try testing.expect(list.items[1].eql(netaddr.parseIp("192.0.2.9").?));

    // Asked about the victim instead, only its own record qualifies.
    list.clearRetainingCapacity();
    try collectAddresses(testing.allocator, &list, &msg, "victim.test.");
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expect(list.items[0].eql(netaddr.parseIp("203.0.113.66").?));
}

test "collectPtrNames: a PTR owned by another reverse name is not this answer; RFC 2317 CNAME delegation is" {
    // Reply to 1.2.0.192.in-addr.arpa PTR: a PTR for 2.2.0.192.in-addr.arpa
    // (not asked), then RFC 2317: 1.2.0.192.in-addr.arpa CNAME
    // 1.0-127.2.0.192.in-addr.arpa, whose PTR is the real answer.
    const resp = "\x00\x01\x81\x80" ++ "\x00\x01\x00\x03\x00\x00\x00\x00" ++
        // question @12: 1.2.0.192.in-addr.arpa PTR IN ("\x011\x012\x010\x03192\x07in-addr\x04arpa\x00" = 24 bytes, ends @40)
        "\x011\x012\x010\x03192\x07in-addr\x04arpa\x00" ++ "\x00\x0c\x00\x01" ++
        // @40: 2.2.0.192.in-addr.arpa (uncompressed) PTR other.example — NOT ours
        "\x012\x012\x010\x03192\x07in-addr\x04arpa\x00" ++ "\x00\x0c\x00\x01\x00\x00\x00\x3c\x00\x0f" ++ "\x05other\x07example\x00" ++
        // @89: 1.2.0.192.in-addr.arpa (ptr @12) CNAME 1.0-127.2.0.192.in-addr.arpa ("\x011\x050-127" + ptr @14 "2.0.192.in-addr.arpa")
        "\xc0\x0c" ++ "\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x0a" ++ "\x011\x050-127\xc0\x0e" ++
        // @111: 1.0-127.2.0.192.in-addr.arpa (ptr @101) PTR host.example
        "\xc0\x65" ++ "\x00\x0c\x00\x01\x00\x00\x00\x3c\x00\x0e" ++ "\x04host\x07example\x00";
    var msg = try message.decode(testing.allocator, resp);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 3), msg.answers.len);
    try testing.expectEqualStrings("1.0-127.2.0.192.in-addr.arpa", msg.answers[1].data.cname);
    try testing.expectEqualStrings("1.0-127.2.0.192.in-addr.arpa", msg.answers[2].name);

    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| testing.allocator.free(n);
        names.deinit(testing.allocator);
    }
    try collectPtrNames(testing.allocator, &names, &msg, "1.2.0.192.in-addr.arpa");
    try testing.expectEqual(@as(usize, 1), names.items.len);
    try testing.expectEqualStrings("host.example", names.items[0]);
}

test "OwnerChain: a CNAME loop and an over-long chain stay bounded" {
    // a -> b -> a (loop) plus c -> d: from `a`, the chain is {a, b}; `c`/`d`
    // are never reached. A chain of 12 hops is cut at max_cname_chain.
    const mk = struct {
        fn cname(owner: []const u8, target: []const u8) message.Record {
            return .{ .name = owner, .ty = .cname, .class = .in, .ttl = 0, .data = .{ .cname = target } };
        }
    };
    const loop = [_]message.Record{ mk.cname("a", "b"), mk.cname("b", "a"), mk.cname("c", "d") };
    var chain: OwnerChain = .init("a");
    chain.follow(&loop);
    try testing.expectEqual(@as(usize, 2), chain.len);
    try testing.expect(chain.contains("B"));
    try testing.expect(!chain.contains("c"));
    try testing.expect(!chain.contains("d"));

    const hops = [_][]const u8{ "n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9", "n10", "n11", "n12" };
    var long: [12]message.Record = undefined;
    for (&long, 0..) |*rec, i| rec.* = mk.cname(hops[i], hops[i + 1]);
    var chain2: OwnerChain = .init("n0");
    chain2.follow(&long);
    try testing.expectEqual(OwnerChain.max_cname_chain + 1, chain2.len);
    try testing.expect(chain2.contains("n8"));
    try testing.expect(!chain2.contains("n9"));

    // Only class-IN CNAMEs extend the chain: the alias chain `lookupIp` and
    // `reverse` trust is the IN one (`collectAddresses` doc: "class IN"); a
    // CHAOS-class CNAME is another namespace's data. Mutation 2026-10-04:
    // dropping the class check survived.
    var chaos = mk.cname("a", "victim.test");
    chaos.class = .ch;
    var chain3: OwnerChain = .init("a");
    chain3.follow(&.{chaos});
    try testing.expectEqual(@as(usize, 1), chain3.len);
    try testing.expect(!chain3.contains("victim.test"));
}

test "jsonQueryUrl: the name is validated like the wire path and percent-encoded" {
    const gpa = testing.allocator;
    const plain = try jsonQueryUrl(gpa, "https://dns.google/resolve", "example.com", .a);
    defer gpa.free(plain);
    try testing.expectEqualStrings("https://dns.google/resolve?name=example.com&type=1", plain);

    // An endpoint URL that already carries a query string gets `&`.
    const amp = try jsonQueryUrl(gpa, "https://x.test/r?ct=json", "a-b_c.test.", .aaaa);
    defer gpa.free(amp);
    try testing.expectEqualStrings("https://x.test/r?ct=json&name=a-b_c.test.&type=28", amp);

    // Parameter injection: `&`/`=` are data, not syntax.
    const inj = try jsonQueryUrl(gpa, "https://x.test/r", "example.com&type=255&name=attacker.test", .a);
    defer gpa.free(inj);
    try testing.expectEqualStrings("https://x.test/r?name=example.com%26type%3D255%26name%3Dattacker.test&type=1", inj);

    // Request-line splitting: CR, LF, space and `%` are escaped too.
    const crlf = try jsonQueryUrl(gpa, "https://x.test/r", "a.test\r\nX-Injected: yes%00", .a);
    defer gpa.free(crlf);
    try testing.expectEqualStrings("https://x.test/r?name=a.test%0D%0AX-Injected%3A%20yes%2500&type=1", crlf);

    // And what the wire path refuses, this refuses by the same name.
    try testing.expectError(error.BadName, jsonQueryUrl(gpa, "https://x.test/r", "a..b", .a));
    try testing.expectError(error.BadName, jsonQueryUrl(gpa, "https://x.test/r", strRepeat("a", 64) ++ ".test", .a));
    try testing.expectError(error.NameTooLong, jsonQueryUrl(gpa, "https://x.test/r", (strRepeat("abcdefg.", 32)) ++ "x", .a));
}

test "effectiveTimeoutMs/effectiveAttempts: resolv.conf wins only when Options was left at its own default (audit F10)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // No conf loaded at all (r.conf == null): the struct default, unchanged.
    var no_conf = Resolver.init(io, testing.allocator, .{});
    defer no_conf.deinit();
    try testing.expectEqual(default_timeout_ms, no_conf.effectiveTimeoutMs());
    try testing.expectEqual(default_attempts, no_conf.effectiveAttempts());

    // Conf present, tighter than the struct default, Options left alone:
    // resolv.conf wins.
    var tight = Resolver.init(io, testing.allocator, .{});
    defer tight.deinit();
    tight.conf = .{ .timeout_s = 1, .attempts = 1 };
    try testing.expectEqual(@as(u32, 1000), tight.effectiveTimeoutMs());
    try testing.expectEqual(@as(u8, 1), tight.effectiveAttempts());

    // Conf present, but the caller set an explicit (non-default) value:
    // the caller's choice wins, resolv.conf is not consulted.
    var explicit = Resolver.init(io, testing.allocator, .{ .timeout_ms = 777, .attempts = 4 });
    defer explicit.deinit();
    explicit.conf = .{ .timeout_s = 1, .attempts = 1 };
    try testing.expectEqual(@as(u32, 777), explicit.effectiveTimeoutMs());
    try testing.expectEqual(@as(u8, 4), explicit.effectiveAttempts());

    // Conf present with values that happen to equal the defaults (the
    // ordinary case: resolv.conf has no `options` line at all, so
    // `parseResolvConf` returns glibc's own 5/2) -- indistinguishable from
    // "no override", correctly a no-op either way.
    var same_as_default = Resolver.init(io, testing.allocator, .{});
    defer same_as_default.deinit();
    same_as_default.conf = .{ .timeout_s = 5, .attempts = 2 };
    try testing.expectEqual(default_timeout_ms, same_as_default.effectiveTimeoutMs());
    try testing.expectEqual(default_attempts, same_as_default.effectiveAttempts());
}

test "query: Options left at default honors resolv.conf's tightened timeout/attempts end to end (audit F10)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A bound-but-silent UDP "server": the datagram lands in the kernel's
    // socket receive queue and nothing ever answers it -- no ICMP
    // port-unreachable (which a send to a genuinely closed port would
    // trigger and short-circuit this test before the timeout logic ever
    // ran), no background thread needed, just a real bind.
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer sock.close(io);
    const port = sock.address.ip4.port;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const conf_path = try std.mem.print(&path_buf, ".zig-cache/tmp/{s}/resolv.conf", .{&tmp.sub_path});
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = conf_path,
        .data = "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
    });

    // `Options` left at its OWN struct defaults throughout -- no
    // `.timeout_ms`/`.attempts` set here at all, which is the entire point:
    // this reproduces the finding's exact administrator scenario, not a
    // caller who already knew to tighten the API directly.
    var r = Resolver.init(io, testing.allocator, .{
        .port = port,
        .use_search = false,
        .resolv_conf_path = conf_path,
    });
    defer r.deinit();

    const start = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Timeout, r.query("example.com", .a));
    const elapsed_ns = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    // resolv.conf's 1 attempt x 1000 ms, not Options' own 2 x 5000 ms: well
    // under half of even the single-attempt resolv.conf budget's own bound
    // rules out the old 10 s (2 x 5000 ms) shape, with headroom for a busy
    // machine.
    try testing.expect(elapsed_ns < 5 * std.time.ns_per_s);
}

test "serverList falls back to default_servers when resolv.conf is missing/empty" {
    // Every live test above runs against the sandbox's real /etc/resolv.conf,
    // which always names servers — so the "conf read failed or named none"
    // fallback to 127.0.0.1 / ::1 (Go's behavior) has no coverage without a
    // dedicated offline test pointed at a path that can't be read.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = Resolver.init(io, testing.allocator, .{
        .resolv_conf_path = "/nonexistent/zig-libs-dns-test-resolv.conf",
    });
    defer r.deinit();

    const servers = try r.serverList();
    try testing.expectEqual(@as(usize, 2), servers.len);
    try testing.expect(servers[0].eql(netaddr.parseIp("127.0.0.1").?));
    try testing.expect(servers[1].eql(netaddr.parseIp("::1").?));
}

test "toNetAddress maps netaddr.Ip to std.Io.net.IpAddress" {
    const v4 = toNetAddress(netaddr.parseIp("192.0.2.1").?, 53);
    try testing.expectEqual([4]u8{ 192, 0, 2, 1 }, v4.ip4.bytes);
    try testing.expectEqual(@as(u16, 53), v4.ip4.port);
    const v6 = toNetAddress(netaddr.parseIp("2001:db8::1").?, 853);
    try testing.expectEqual(@as(u8, 0x20), v6.ip6.bytes[0]);
    try testing.expectEqual(@as(u16, 853), v6.ip6.port);
}

// ── live-network tests: MOVED OUT 2026-09-09 ──────────────────────
//
// Seven `test "live: …"` used to sit here — recursive UDP/TCP, reverse PTR,
// and the three DoH shapes — each ending `catch |err| return skipLive(err)`,
// and `skipLive` narrated the skip with `std.debug.print`, i.e. to stderr.
// The gate driver treats stderr on an exit-0 step as a failure, so a slow
// resolver turned `test-dns` red and took a 217-module run with it, with
// nothing in this module changed.
//
// Silencing the print was the wrong fix and so was keeping the skip: a test
// that reports success for a run in which it did nothing is the defect, not
// the noise it makes. They are now `modules/dns/tools/live.zig`, run by
// `zig build live-dns` and COMPILED by `zig build check-interop` so they
// cannot rot — the shape `dtls` took on 2026-09-06 and this module's own
// hostile-loopback anchor took on 2026-09-07.
//
// Nothing here reaches the network any more. Everything below is loopback or
// bytes.

// ── tests (loopback stubs, offline) ──────────────────────────────────────────

/// Build a response to `query_bytes` on a loopback stub: echoes the id (and,
/// unless `lie_about_question`, the question section verbatim), then appends
/// `answers` raw records. Test-only — the module publishes no response
/// encoder, and the stubs here need to LIE in controlled ways.
fn stubResponse(buf: []u8, query_bytes: []const u8, flags: u16, question: []const u8, answers: []const u8, ancount: u16) []u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(query_bytes[0..2]) catch unreachable;
    w.writeInt(u16, flags, .big) catch unreachable;
    w.writeInt(u16, if (question.len == 0) 0 else 1, .big) catch unreachable;
    w.writeInt(u16, ancount, .big) catch unreachable;
    w.writeInt(u16, 0, .big) catch unreachable;
    w.writeInt(u16, 0, .big) catch unreachable;
    w.writeAll(question) catch unreachable;
    w.writeAll(answers) catch unreachable;
    return w.buffered();
}

/// One-shot UDP stub: receives a query and answers per `Script`.
const UdpStub = struct {
    io: std.Io,
    sock: net.Socket,
    script: Script,
    served: usize = 0,

    const Script = enum {
        /// Question echoed correctly; answer = victim.test A 203.0.113.66 + example.com A 192.0.2.1.
        off_bailiwick_plus_honest,
        /// Header only with the TC bit set: the resolver must go to TCP.
        truncated,
        /// Like `truncated` but without a question section (a bare header
        /// with TC set, which `decodeResponse` refuses): still TCP's business.
        truncated_bare,
        /// A datagram bigger than any resolver rbuf, TC bit NOT set: the kernel
        /// truncates delivery and only `IncomingMessage.flags.trunc` says so
        /// (audit F13).
        oversized_no_tc,
    };
    // The two lying-question scripts this stub also used to carry
    // (`wrong_question`, `no_question`) moved to
    // `modules/dns/tools/interop.zig` with the test that drove them; their
    // frames are replayed hermetically from `src/testdata/` instead.

    fn run(st: *UdpStub) void {
        st.serveOne() catch |err| std.debug.print("UdpStub: {t}\n", .{err});
    }

    fn serveOne(st: *UdpStub) !void {
        var rbuf: [message.max_query_len]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(5000), .clock = .awake } };
        const incoming = try st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io));
        const q = incoming.data;
        const question_echo = "\x07example\x03com\x00\x00\x01\x00\x01";
        const a_example = "\xc0\x0c" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xc0\x00\x02\x01";
        const a_victim = "\x06victim\x04test\x00" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xcb\x00\x71\x42";
        var out: [512]u8 = undefined;
        // Only `oversized_no_tc` needs more than `out` holds; kept out of the
        // shared buffer so the common cases stay a small stack frame.
        var big_out: [2048]u8 = undefined;
        const resp = switch (st.script) {
            .off_bailiwick_plus_honest => stubResponse(&out, q, 0x8180, question_echo, a_victim ++ a_example, 2),
            .truncated => stubResponse(&out, q, 0x8380, question_echo, "", 0),
            .truncated_bare => stubResponse(&out, q, 0x8380, "", "", 0),
            .oversized_no_tc => blk: {
                // TC bit clear (0x8180): a real server that respected the
                // advertised EDNS size would set TC instead of doing this.
                // The payload does not need to be a valid record -- the
                // datagram is bigger than the resolver's rbuf regardless of
                // what is inside it, and detection has to happen before
                // decode ever runs.
                var filler: [1800]u8 = undefined;
                @memset(&filler, 0xaa);
                break :blk stubResponse(&big_out, q, 0x8180, question_echo, &filler, 1);
            },
        };
        try st.sock.send(st.io, &incoming.from, resp);
        st.served += 1;
    }
};

/// Static, so the slice `Options.servers` keeps outlives every test that
/// hands it over (an `&.{…}` literal inside the call would dangle).
const loopback_servers = [_]netaddr.Ip{.{ .v4 = .{ 127, 0, 0, 1 } }};

fn udpStubResolver(io: std.Io, stub: *UdpStub, attempts: u8) !Resolver {
    const port = stub.sock.address.getPort();
    return Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = port,
        .timeout_ms = 1500,
        .attempts = attempts,
        .use_hosts = false,
        .use_search = false,
    });
}

fn bindUdpStub(io: std.Io, script: UdpStub.Script) !UdpStub {
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try addr.bind(io, .{ .mode = .dgram });
    return .{ .io = io, .sock = sock, .script = script };
}

test "call_timeout_ms: a silent server ends the whole call at the budget, not after timeout x attempts x families" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const silent = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer silent.close(io);

    // Without a call budget this would take 2 families x 5 attempts x 200 ms = 2 s.
    var r = Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = silent.address.getPort(),
        .timeout_ms = 200,
        .attempts = 5,
        .call_timeout_ms = 300,
        .use_hosts = false,
        .use_search = false,
    });
    defer r.deinit();
    const t0 = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Timeout, r.lookupIp("silent.test."));
    const ms = t0.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds();
    try testing.expect(ms >= 250 and ms < 1200);
    try testing.expect(r.call_deadline == null); // released for the next call

    // A budget shorter than one attempt bounds that attempt too.
    r.options.timeout_ms = 2000;
    r.options.call_timeout_ms = 100;
    const t1 = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Timeout, r.query("silent.test.", .a));
    try testing.expect(t1.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds() < 1000);
}

test "call_timeout_ms: nested public calls share the outer budget; 0 sets none" {
    var r: Resolver = .{ .io = undefined, .gpa = testing.allocator, .options = .{}, .http_client = null, .conf = null, .conf_text = null };
    try testing.expect(!r.beginCall()); // 0 = no budget
    try testing.expect(r.call_deadline == null);
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    r.io = threaded.io();
    r.options.call_timeout_ms = 1000;
    const outer = r.beginCall();
    try testing.expect(outer);
    const d = r.call_deadline.?;
    const inner = r.beginCall();
    try testing.expect(!inner); // the inner call does not move it
    try testing.expect(r.call_deadline.?.compare(.eq, d));
    r.endCall(inner);
    try testing.expect(r.call_deadline != null);
    r.endCall(outer);
    try testing.expect(r.call_deadline == null);
}

test "lookupIp/resolve: .onion and .invalid never reach the server (RFC 7686 \u{a7}2, RFC 6761 \u{a7}6.4)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // Silent server: any query sent would end in Timeout after 2 s.
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const silent = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer silent.close(io);
    var r = Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = silent.address.getPort(),
        .timeout_ms = 2000,
        .attempts = 1,
        .use_hosts = false,
        .use_search = false,
    });
    defer r.deinit();
    const t0 = std.Io.Clock.Timestamp.now(io, .awake);
    for ([_][]const u8{ "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", "x.ONION.", "host.invalid" }) |n| {
        const found = try r.lookupIpTtl(n);
        defer testing.allocator.free(found.ips);
        try testing.expectEqual(@as(usize, 0), found.ips.len);
        try testing.expectError(error.BadName, r.resolve(n, .a));
    }
    try testing.expect(t0.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds() < 500);
    // Nothing arrived at the server.
    var buf: [64]u8 = undefined;
    const quick: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
    try testing.expectError(error.Timeout, silent.receiveTimeout(io, &buf, quick.toDeadline(io)));
}

test "lookupIp: a server that never answers is a Timeout, not an empty list (simio pilot finding)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Bound but silent: every query times out.
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const silent = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer silent.close(io);

    var r = Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = silent.address.getPort(),
        .timeout_ms = 30,
        .attempts = 1,
        .use_hosts = false,
        .use_search = false,
    });
    defer r.deinit();
    try testing.expectError(error.Timeout, r.lookupIp("silent.test."));
}

test "lookupIp: an answer record the question never asked about is ignored (bailiwick), end to end over loopback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = bindUdpStub(io, .off_bailiwick_plus_honest) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer stub.sock.close(io);
    var stub_fut = try io.concurrent(UdpStub.run, .{&stub});
    defer stub_fut.await(io);

    var r = try udpStubResolver(io, &stub, 1);
    defer r.deinit();
    // The stub answers one datagram (the A query); the AAAA query times out
    // (1.5 s) and lookupIp tolerates one family failing.
    const found = try r.lookupIpTtl("example.com");
    const ips = found.ips;
    defer testing.allocator.free(ips);
    try testing.expectEqual(@as(usize, 1), ips.len);
    try testing.expect(ips[0].eql(netaddr.parseIp("192.0.2.1").?)); // never 203.0.113.66
    try testing.expectEqual(@as(?u32, 60), found.ttl_s); // the A record's TTL, over the wire
    try testing.expect(found.partial); // the AAAA query timed out
}

/// RFC 6891 §7 fallback stub: answers `max` datagrams for `example.com A`,
/// logging whether each query carried an OPT record (ARCOUNT > 0).
const EdnsStub = struct {
    io: std.Io,
    sock: net.Socket,
    mode: Mode,
    max: usize,
    had_opt: [4]bool = @splat(false),
    served: usize = 0,

    const Mode = enum {
        /// FORMERR (no OPT) to an EDNS query, an answer to a plain one.
        formerr_to_opt,
        /// FORMERR to every query: the fallback must stop after one retry.
        formerr_always,
        /// BADVERS (extended rcode 16 in a reply OPT) to an EDNS query.
        badvers,
    };

    fn run(st: *EdnsStub) void {
        while (st.served < st.max) st.serveOne() catch |err| {
            std.debug.print("EdnsStub: {t}\n", .{err});
            return;
        };
    }

    fn serveOne(st: *EdnsStub) !void {
        var rbuf: [message.max_query_len]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake } };
        const incoming = try st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io));
        const q = incoming.data;
        const has_opt = std.mem.readInt(u16, q[10..12], .big) > 0;
        st.had_opt[st.served] = has_opt;
        const question_echo = "\x07example\x03com\x00\x00\x01\x00\x01";
        const a_example = "\xc0\x0c" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xc0\x00\x02\x01";
        var out: [512]u8 = undefined;
        const resp = switch (st.mode) {
            .formerr_always => stubResponse(&out, q, 0x8181, question_echo, "", 0),
            .formerr_to_opt => if (has_opt) stubResponse(&out, q, 0x8181, question_echo, "", 0) else stubResponse(&out, q, 0x8180, question_echo, a_example, 1),
            .badvers => if (has_opt) blk: {
                // Header RCODE 0, OPT ttl top byte 1: extended RCODE 16.
                const r = stubResponse(&out, q, 0x8180, question_echo, "", 0);
                std.mem.writeInt(u16, out[10..12], 1, .big); // ARCOUNT
                const opt = "\x00" ++ "\x00\x29" ++ "\x04\xd0" ++ "\x01\x00\x00\x00" ++ "\x00\x00";
                @memcpy(out[r.len..][0..opt.len], opt);
                break :blk out[0 .. r.len + opt.len];
            } else stubResponse(&out, q, 0x8180, question_echo, a_example, 1),
        };
        try st.sock.send(st.io, &incoming.from, resp);
        st.served += 1;
    }
};

fn ednsStubResolver(io: std.Io, stub: *EdnsStub) Resolver {
    return Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = stub.sock.address.getPort(),
        .timeout_ms = 1500,
        .attempts = 1,
        .use_hosts = false,
        .use_search = false,
        .dnssec_ok = true, // dropped with the OPT record on the retry
    });
}

test "query: FORMERR to an EDNS query is retried once without OPT, and the server is remembered (RFC 6891 \u{a7}7)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var stub: EdnsStub = .{ .io = io, .sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err}), .mode = .formerr_to_opt, .max = 3 };
    defer stub.sock.close(io);
    var fut = try io.concurrent(EdnsStub.run, .{&stub});
    defer fut.await(io);

    var r = ednsStubResolver(io, &stub);
    defer r.deinit();
    var m1 = try r.query("example.com", .a);
    try testing.expectEqual(message.Rcode.no_error, m1.rcode());
    try testing.expectEqual(@as(usize, 1), m1.answers.len);
    m1.deinit();
    // Second lookup: plain from the start, no second FORMERR round trip.
    var m2 = try r.query("example.com", .a);
    m2.deinit();
    try testing.expectEqual(@as(usize, 3), stub.served);
    try testing.expectEqualSlices(bool, &.{ true, false, false }, stub.had_opt[0..3]);
}

test "query: a server that FORMERRs every query costs exactly one retry, and its FORMERR is the final answer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var stub: EdnsStub = .{ .io = io, .sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err}), .mode = .formerr_always, .max = 2 };
    defer stub.sock.close(io);
    var fut = try io.concurrent(EdnsStub.run, .{&stub});
    defer fut.await(io);

    var r = ednsStubResolver(io, &stub);
    defer r.deinit();
    var m = try r.query("example.com", .a);
    defer m.deinit();
    try testing.expectEqual(message.Rcode.form_err, m.rcode());
    try testing.expectEqual(@as(usize, 2), stub.served);
    try testing.expectEqualSlices(bool, &.{ true, false }, stub.had_opt[0..2]);
}

test "query: BADVERS (extended rcode 16) to an EDNS query is retried without OPT" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var stub: EdnsStub = .{ .io = io, .sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err}), .mode = .badvers, .max = 2 };
    defer stub.sock.close(io);
    var fut = try io.concurrent(EdnsStub.run, .{&stub});
    defer fut.await(io);

    var r = ednsStubResolver(io, &stub);
    defer r.deinit();
    var m = try r.query("example.com", .a);
    defer m.deinit();
    try testing.expectEqual(message.Rcode.no_error, m.rcode());
    try testing.expectEqualSlices(bool, &.{ true, false }, stub.had_opt[0..2]);
}

test "rememberNoEdns: bounded at max_no_edns, oldest replaced, no duplicates" {
    var r: Resolver = .{ .io = undefined, .gpa = testing.allocator, .options = .{}, .http_client = null, .conf = null, .conf_text = null };
    for (0..max_no_edns + 2) |i| r.rememberNoEdns(.{ .v4 = .{ 10, 0, 0, @intCast(i) } });
    r.rememberNoEdns(.{ .v4 = .{ 10, 0, 0, 9 } }); // already in: no shift
    try testing.expect(!r.refusedEdns(.{ .v4 = .{ 10, 0, 0, 0 } })); // replaced
    try testing.expect(!r.refusedEdns(.{ .v4 = .{ 10, 0, 0, 1 } }));
    for (2..max_no_edns + 2) |i| try testing.expect(r.refusedEdns(.{ .v4 = .{ 10, 0, 0, @intCast(i) } }));
}

/// A UDP stub that answers SEVERAL datagrams, each by echoing that query's
/// own question (so search-list candidates and both families get a reply
/// that passes `decodeResponse`), shaped by `mode`. Added with the mutation
/// run of 2026-10-04 for the transport and candidate loops, which `UdpStub`
/// (one fixed question, one datagram) cannot reach.
const EchoStub = struct {
    io: std.Io,
    sock: net.Socket,
    mode: Mode,
    /// Stop after this many datagrams, or after `idle_ms` without one.
    max: usize,
    idle_ms: i64 = 1000,
    ids: [8]u16 = @splat(0),
    served: usize = 0,

    const Mode = enum {
        /// A → A 192.0.2.1; any other type → NOERROR, no answer.
        a_only,
        /// The first query gets NOERROR with no answer (NODATA), then `a_only`.
        nodata_then_a,
        /// The first query is never answered, then `a_only`.
        drop_first,
        /// Before the honest reply, one with the id flipped claiming
        /// A 203.0.113.66.
        wrong_id_first,
        /// Before the honest reply, one with the RIGHT id and question
        /// claiming A 203.0.113.66, sent from another source port.
        other_port_first,
        /// Before the honest reply, three datagrams with the RIGHT id from
        /// the right source: QR clear, another question, undecodable.
        bogus_same_id_first,
        /// Before the honest reply, ONE datagram with the RIGHT id from the
        /// right source and QR clear (a query, not a response).
        qr_clear_first,
        /// Every query: SERVFAIL.
        servfail,
        /// A as `a_only`; AAAA: SERVFAIL.
        aaaa_servfail,
    };

    const a_honest = "\xc0\x0c" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xc0\x00\x02\x01";
    const a_lie = "\xc0\x0c" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xcb\x00\x71\x42";

    fn run(st: *EchoStub) void {
        st.serve() catch |err| std.debug.print("EchoStub: {t}\n", .{err});
    }

    /// Length of the question section at the start of `bytes` (an
    /// uncompressed name, as `writeName` emits it, plus type and class).
    fn questionLen(bytes: []const u8) usize {
        var i: usize = 0;
        while (bytes[i] != 0) i += 1 + bytes[i];
        return i + 1 + 4;
    }

    fn serve(st: *EchoStub) !void {
        var rbuf: [message.max_query_len]u8 = undefined;
        while (st.served < st.max) {
            const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(st.idle_ms), .clock = .awake } };
            const incoming = st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io)) catch |err| switch (err) {
                error.Timeout => return,
                else => |e| return e,
            };
            const q = incoming.data;
            const n = st.served;
            st.ids[n] = std.mem.readInt(u16, q[0..2], .big);
            st.served += 1;
            const question = q[message.header_len..][0..questionLen(q[message.header_len..])];
            const is_a = std.mem.readInt(u16, question[question.len - 4 ..][0..2], .big) == @backingInt(message.Type.a);
            var first: [512]u8 = undefined;
            switch (st.mode) {
                .a_only => {},
                .nodata_then_a => if (n == 0) {
                    try st.sock.send(st.io, &incoming.from, stubResponse(&first, q, 0x8180, question, "", 0));
                    continue;
                },
                .drop_first => if (n == 0) continue,
                .servfail, .aaaa_servfail => if (st.mode == .servfail or !is_a) {
                    try st.sock.send(st.io, &incoming.from, stubResponse(&first, q, 0x8182, question, "", 0));
                    continue;
                },
                .wrong_id_first => {
                    const resp = stubResponse(&first, q, 0x8180, question, a_lie, 1);
                    resp[0] ^= 0xff;
                    try st.sock.send(st.io, &incoming.from, resp);
                },
                .bogus_same_id_first => {}, // sent below, before the honest reply
                .qr_clear_first => try st.sock.send(st.io, &incoming.from, stubResponse(&first, q, 0x0180, question, a_lie, 1)),
                .other_port_first => {
                    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
                    const other = try addr.bind(st.io, .{ .mode = .dgram });
                    defer other.close(st.io);
                    try other.send(st.io, &incoming.from, stubResponse(&first, q, 0x8180, question, a_lie, 1));
                },
            }
            if (st.mode == .bogus_same_id_first) {
                const qr_clear = stubResponse(&first, q, 0x0180, question, a_lie, 1);
                try st.sock.send(st.io, &incoming.from, qr_clear);
                var other: [512]u8 = undefined;
                const wrong_q = stubResponse(&other, q, 0x8180, "\x04evil\x04test\x00\x00\x01\x00\x01", a_lie, 1);
                try st.sock.send(st.io, &incoming.from, wrong_q);
                var junk: [512]u8 = undefined;
                const garbage = stubResponse(&junk, q, 0x8180, question, "\xc0", 1);
                try st.sock.send(st.io, &incoming.from, garbage);
            }
            var out: [512]u8 = undefined;
            const honest = if (is_a)
                stubResponse(&out, q, 0x8180, question, a_honest, 1)
            else
                stubResponse(&out, q, 0x8180, question, "", 0);
            try st.sock.send(st.io, &incoming.from, honest);
        }
    }
};

fn bindEchoStub(io: std.Io, mode: EchoStub.Mode, max: usize) !EchoStub {
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try addr.bind(io, .{ .mode = .dgram });
    return .{ .io = io, .sock = sock, .mode = mode, .max = max };
}

/// A real `std.Io` whose `random` yields 0x0101, 0x0202, ... per call, so a
/// test can tell one transaction id from the next without a 2^-16 flake.
const SeqRandomIo = struct {
    vtable: std.Io.VTable,
    userdata: ?*anyopaque,

    var next: std.atomic.Value(u8) = .init(1);

    fn init(inner: std.Io) SeqRandomIo {
        var vt = inner.vtable.*;
        vt.random = random;
        return .{ .vtable = vt, .userdata = inner.userdata };
    }

    fn io(self: *const SeqRandomIo) std.Io {
        return .{ .userdata = self.userdata, .vtable = &self.vtable };
    }

    fn random(_: ?*anyopaque, buffer: []u8) void {
        @memset(buffer, next.fetchAdd(1, .monotonic));
    }
};

fn expectOnlyHonestA(msg: *const message.Message) !void {
    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    try testing.expect(dns.recordIp(msg.answers[0]).?.eql(netaddr.parseIp("192.0.2.1").?));
}

test "query: a datagram with another id is skipped and the right one still accepted" {
    // RFC 5452 §9.1: an answer must match the query's id. A reply carrying
    // another id is not an answer -- and not a reason to give up: the
    // receive loop must keep waiting for the real one (an off-path spoofer
    // could otherwise fail every query with one wrong guess). Mutation
    // 2026-10-04: returning the mismatched datagram survived.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = bindEchoStub(io, .wrong_id_first, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer stub.sock.close(io);
    var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
    defer r.deinit();
    var fut = try io.concurrent(EchoStub.run, .{&stub});
    const res = r.query("example.com", .a);
    fut.await(io);
    var msg = try res;
    defer msg.deinit();
    try expectOnlyHonestA(&msg);
}

test "query: a datagram from another source port is skipped, even with the right id and question" {
    // RFC 5452 §9.1 again: the reply must come from the address and port the
    // query went to. Mutation 2026-10-04: dropping the source check survived;
    // with it gone the forged A 203.0.113.66 won.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = bindEchoStub(io, .other_port_first, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer stub.sock.close(io);
    var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
    defer r.deinit();
    var fut = try io.concurrent(EchoStub.run, .{&stub});
    const res = r.query("example.com", .a);
    fut.await(io);
    var msg = try res;
    defer msg.deinit();
    try expectOnlyHonestA(&msg);
}

test "query: every retry carries a fresh transaction id" {
    // The comment in `query` states the rule: one id per datagram, so a
    // retry never re-uses an id an off-path attacker may have seen.
    // Mutation 2026-10-04: a fixed id survived. `SeqRandomIo` makes the ids
    // deterministic, so "different" is not a 2^-16 coin toss.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const real_io = threaded.io();
    var stub = bindEchoStub(real_io, .drop_first, 2) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer stub.sock.close(real_io);
    const seq: SeqRandomIo = .init(real_io);
    var r = Resolver.init(seq.io(), testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 300, .attempts = 2, .use_hosts = false, .use_search = false });
    defer r.deinit();
    var fut = try real_io.concurrent(EchoStub.run, .{&stub});
    const res = r.query("example.com", .a);
    fut.await(real_io);
    var msg = try res;
    defer msg.deinit();
    try expectOnlyHonestA(&msg);
    try testing.expectEqual(@as(usize, 2), stub.served);
    try testing.expect(stub.ids[0] != stub.ids[1]);
}

/// A resolv.conf in a test tmp dir carrying `search s1.test s2.test`; the
/// path is written into `path_buf`.
fn searchConf(io: std.Io, tmp: *const std.testing.TmpDir, path_buf: []u8) ![]const u8 {
    const conf_path = try std.mem.print(path_buf, ".zig-cache/tmp/{s}/resolv.conf", .{&tmp.sub_path});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = conf_path, .data = "search s1.test s2.test\n" });
    return conf_path;
}

test "resolve: a NODATA answer for one search candidate moves on to the next" {
    // `resolve` returns the first candidate with NOERROR AND answers (Go
    // `goLookupIPCNAMEOrder` likewise keeps going on an empty answer); a
    // NODATA reply for host.s1.test is not the answer for "host".
    // Mutation 2026-10-04: stopping at the empty answer survived.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const conf_path = try searchConf(io, &tmp, &path_buf);
    var stub = bindEchoStub(io, .nodata_then_a, 2) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer stub.sock.close(io);
    var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .resolv_conf_path = conf_path });
    defer r.deinit();
    var fut = try io.concurrent(EchoStub.run, .{&stub});
    const res = r.resolve("host", .a);
    fut.await(io);
    var msg = try res;
    defer msg.deinit();
    try testing.expectEqualStrings("host.s2.test", msg.questions[0].name);
    try expectOnlyHonestA(&msg);
}

test "lookupIpTtl: a SERVFAIL is an outage, not an empty answer; one family failing is partial" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    {
        var stub = bindEchoStub(io, .servfail, 2) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        defer stub.sock.close(io);
        var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
        defer r.deinit();
        var fut = try io.concurrent(EchoStub.run, .{&stub});
        const res = r.lookupIpTtl("example.com");
        fut.await(io);
        try testing.expectError(error.ServerFailed, res);
    }
    {
        var stub = bindEchoStub(io, .aaaa_servfail, 2) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        defer stub.sock.close(io);
        var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
        defer r.deinit();
        var fut = try io.concurrent(EchoStub.run, .{&stub});
        const res = r.lookupIpTtl("example.com");
        fut.await(io);
        const found = try res;
        defer testing.allocator.free(found.ips);
        try testing.expectEqual(@as(usize, 1), found.ips.len);
        try testing.expect(found.partial);
        try testing.expectEqual(@as(?u32, 60), found.ttl_s);
    }
}

test "lookupIp: the first search candidate with an address wins, later ones are not asked" {
    // `lookupIp` doc + Go `nameList` order: candidates are tried in order and
    // the first that yields addresses is the answer -- host.s1.test here;
    // host.s2.test and the bare "host" are other names whose addresses must
    // not be merged in. Mutation 2026-10-04: dropping the break survived.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [256]u8 = undefined;
    const conf_path = try searchConf(io, &tmp, &path_buf);
    var stub = bindEchoStub(io, .a_only, 6) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer stub.sock.close(io);
    var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .resolv_conf_path = conf_path });
    defer r.deinit();
    var fut = try io.concurrent(EchoStub.run, .{&stub});
    const res = r.lookupIp("host");
    fut.await(io);
    const ips = try res;
    defer testing.allocator.free(ips);
    try testing.expectEqual(@as(usize, 1), ips.len);
    try testing.expectEqual(@as(usize, 2), stub.served); // A + AAAA for host.s1.test only
}

/// A plain-HTTP loopback "DoH server" that answers every request with
/// `503 Service Unavailable` and the body `{}` -- a body neither DoH decoder
/// would turn into an answer, so a status check that is not made shows up
/// as a different error (mutation 2026-10-04).
const Http503 = struct {
    io: std.Io,
    server: net.Server,
    requests: usize,

    fn run(st: *Http503) void {
        st.serve() catch |err| std.debug.print("Http503: {t}\n", .{err});
    }

    fn serve(st: *Http503) !void {
        for (0..st.requests) |_| {
            const stream = try st.server.accept(st.io);
            defer stream.close(st.io);
            var rbuf: [4096]u8 = undefined;
            var sr = stream.reader(st.io, &rbuf);
            const in = &sr.interface;
            var body_len: usize = 0;
            while (true) {
                const line = try in.takeDelimiterInclusive('\n');
                if (std.mem.eql(u8, line, "\r\n")) break;
                const key = "content-length:";
                if (std.ascii.startsWithIgnoreCase(line, key))
                    body_len = try std.fmt.parseInt(usize, std.mem.trim(u8, line[key.len..], " \t\r\n"), 10);
            }
            try in.discardAll(body_len);
            var wbuf: [256]u8 = undefined;
            var sw = stream.writer(st.io, &wbuf);
            try sw.interface.writeAll("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/dns-message\r\n" ++
                "Content-Length: 2\r\nConnection: close\r\n\r\n{}");
            try sw.interface.flush();
        }
    }
};

test "DoH: a non-200 status is DohFailed on both the wire and the JSON path, never decoded" {
    // RFC 8484 §4.2.1: a DNS answer travels in a 2xx response; anything else
    // is an HTTP-level failure, not a DNS message to parse. Both paths must
    // refuse the body of a 503 before reading it as an answer. Mutation
    // 2026-10-04: dropping the check in `queryJson` survived (and the one in
    // `dohExchange` had no test either).
    if (!doh_enabled) return error.SkipZigTest; // the refusal has its own test
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var stub: Http503 = .{
        .io = io,
        .server = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err}),
        .requests = 2,
    };
    defer stub.server.socket.close(io);
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/dns-query", .{stub.server.socket.address.getPort()});
    var r = Resolver.init(io, testing.allocator, .{ .doh_url = url, .timeout_ms = 5000, .use_hosts = false, .use_search = false });
    defer r.deinit();
    var fut = try io.concurrent(Http503.run, .{&stub});
    const wire = r.query("example.com", .a);
    const json = r.queryJson("example.com", .a);
    fut.await(io);
    if (wire) |m| {
        var msg = m;
        msg.deinit();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.DohFailed, err);
    if (json) |a| {
        var ans = a;
        ans.deinit();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.DohFailed, err);
}

test "built without DoH (-Ddns-doh=false), a doh_url is refused on both paths, never asked over plain DNS" {
    // CONVENTIONS §4.2 rule 2: a capability cut fails loudly. Falling back to
    // UDP would send the query in the clear to whatever resolv.conf names,
    // which is exactly what a DoH caller chose to avoid. Under the default
    // build the DoH tests above cover the path.
    if (doh_enabled) return error.SkipZigTest;
    // Port 9 (discard): nothing is ever sent, so nothing needs to listen.
    var r = Resolver.init(testing.io, testing.allocator, .{ .doh_url = "http://127.0.0.1:9/dns-query", .timeout_ms = 200, .use_hosts = false, .use_search = false });
    defer r.deinit();
    try testing.expectError(error.NoDohEndpoint, r.query("example.com", .a));
    try testing.expectError(error.NoDohEndpoint, r.queryJson("example.com", .a));
    try testing.expectError(error.NoDohEndpoint, r.reverse(.{ .v4 = .{ 192, 0, 2, 1 } }));
}

// ⭐ THE QUESTION-CHECK EXCHANGE OVER A SOCKET LIVES IN
// `modules/dns/tools/interop.zig`, not here (audit F20, 2026-09-08).
//
// It used to be `test "query: a reply whose question is not ours is not the
// answer, over loopback"` in this file. What it asserted about PARSING is now
// the replay of that program's captures, next to the other `decodeResponse`
// tests above — unable to fail under load, because it schedules nothing. What
// genuinely needs a socket and a second thread stays a PROGRAM: `zig build
// interop-dns` runs it, `zig build check-interop` compiles it, and
// `scripts/test.sh interop` reaches it pre-release. That program's header
// argues the placement (§9 names a foreign toolchain; a thread the gate itself
// starves is the same class of dependency on an environment `test-dns` must not
// require) and records why adding `dns` to the serial `live` set would not have
// fixed the failure: it was an unsynchronised cross-thread read, not a starved
// scheduler, and a serial lane only hides a race.

/// A TCP listener that accepts the connection and never answers — the
/// shape that held the resolver until the OS gave up (measured 45-60 s in
/// the audit at `timeout_ms = 1000`).
const SilentTcp = struct {
    io: std.Io,
    server: net.Server,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: std.atomic.Value(u32) = .init(0),

    fn run(st: *SilentTcp) void {
        const stream = st.server.accept(st.io) catch return;
        defer stream.close(st.io);
        st.accepted.store(1, .release);
        st.io.futexWake(u32, &st.accepted.raw, 1);
        // Hold the connection open until told to stop; never write.
        while (st.stop.load(.acquire) == 0) {
            st.io.futexWaitTimeout(u32, &st.stop.raw, 0, .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } }) catch break;
        }
    }
};

test "tcpExchange: a server that accepts and never answers is bounded by timeout_ms (audit F1)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var silent: SilentTcp = .{ .io = io, .server = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err}) };
    defer silent.server.socket.close(io);
    var fut = try io.concurrent(SilentTcp.run, .{&silent});
    defer {
        silent.stop.store(1, .release);
        io.futexWake(u32, &silent.stop.raw, 1);
        fut.await(io);
    }

    var r = Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = silent.server.socket.address.ip4.port,
        .transport = .tcp,
        .timeout_ms = 300,
        .attempts = 1,
        .use_search = false,
    });
    defer r.deinit();

    const start = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Timeout, r.query("example.com", .a));
    const elapsed_ns = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    try testing.expect(elapsed_ns >= 250 * std.time.ns_per_ms);
    try testing.expect(elapsed_ns < 5 * std.time.ns_per_s); // was: until the OS gave up
}

test "query: the TC-bit path into a silent TCP server is bounded too (default transport .auto)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // TCP first on an ephemeral port, then UDP on the SAME port number.
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var silent: SilentTcp = .{ .io = io, .server = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err}) };
    defer silent.server.socket.close(io);
    const port = silent.server.socket.address.ip4.port;
    const udp_addr: net.IpAddress = .{ .ip4 = .loopback(port) };
    const udp_sock = udp_addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    var stub: UdpStub = .{ .io = io, .sock = udp_sock, .script = .truncated };
    defer stub.sock.close(io);

    var tcp_fut = try io.concurrent(SilentTcp.run, .{&silent});
    defer {
        silent.stop.store(1, .release);
        io.futexWake(u32, &silent.stop.raw, 1);
        tcp_fut.await(io);
    }
    // ⛔ `udp_joined` exists so `stub.served` is read AFTER the stub thread has
    // finished, never beside it. The sibling test that read that counter with
    // only a `defer`-ed `await` behind it failed 10 runs in 20 under load
    // (audit F20): the stub had sent the datagram — which is why the resolver's
    // verdict was right — and was preempted before `served += 1` retired. This
    // test happened to survive that only because the resolver spends its 300 ms
    // TCP budget after the UDP reply, which is luck of timing, not
    // synchronisation. The `defer` still covers the paths that return early.
    var udp_fut = try io.concurrent(UdpStub.run, .{&stub});
    var udp_joined = false;
    defer if (!udp_joined) udp_fut.await(io);

    var r = Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = port,
        .timeout_ms = 300,
        .attempts = 1,
        .use_search = false,
    });
    defer r.deinit();

    const start = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Timeout, r.query("example.com", .a));
    const elapsed_ns = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    udp_fut.await(io); // bounded: the stub's own receive deadline is 5 s
    udp_joined = true;
    try testing.expectEqual(@as(usize, 1), stub.served); // UDP answered with TC
    try testing.expect(elapsed_ns < 5 * std.time.ns_per_s);
}

test "query: a UDP reply the kernel truncated falls back to TCP even without TC set (audit F13)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Same shape as the TC-bit test above, but the UDP stub does not set TC:
    // only `IncomingMessage.flags.trunc` (kernel MSG_TRUNC) can tell the
    // resolver the reply did not fit. Before the fix `query` decoded the
    // truncated bytes directly and returned `MalformedResponse` without ever
    // dialing TCP -- this test's oracle is that it reaches the (silent) TCP
    // server at all, the same way the TC-bit sibling proves it.
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var silent: SilentTcp = .{ .io = io, .server = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err}) };
    defer silent.server.socket.close(io);
    const port = silent.server.socket.address.ip4.port;
    const udp_addr: net.IpAddress = .{ .ip4 = .loopback(port) };
    const udp_sock = udp_addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    var stub: UdpStub = .{ .io = io, .sock = udp_sock, .script = .oversized_no_tc };
    defer stub.sock.close(io);

    var tcp_fut = try io.concurrent(SilentTcp.run, .{&silent});
    defer {
        silent.stop.store(1, .release);
        io.futexWake(u32, &silent.stop.raw, 1);
        tcp_fut.await(io);
    }
    var udp_fut = try io.concurrent(UdpStub.run, .{&stub});
    var udp_joined = false;
    defer if (!udp_joined) udp_fut.await(io);

    var r = Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = port,
        .timeout_ms = 300,
        .attempts = 1,
        .use_search = false,
    });
    defer r.deinit();

    const start = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Timeout, r.query("example.com", .a));
    const elapsed_ns = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    udp_fut.await(io);
    udp_joined = true;
    try testing.expectEqual(@as(usize, 1), stub.served); // UDP delivered (truncated), TCP was then tried
    try testing.expect(elapsed_ns >= 250 * std.time.ns_per_ms); // spent the TCP budget, not a fast MalformedResponse
    try testing.expect(elapsed_ns < 5 * std.time.ns_per_s);
}

// ── tests (cancellation, offline) ────────────────────────────────────────────
//
// `tcpExchange` is the only place in this file that owns a TCP fd directly.
// `Future.cancel` does unblock a thread parked in a real `std.Io` read, but
// `Io.Reader.Error` cannot carry `Canceled` itself — the reason survives only
// in the concrete `Stream.Reader`'s out-of-band `err` field, which
// `readFailure` now consults. This drives `tcpExchange` against a loopback
// listener nobody ever accepts: `connect` and the length-prefixed write both
// still succeed (the kernel completes the handshake and buffers the write on
// its own), so the read genuinely parks in `takeInt`, waiting for a response
// length prefix that never arrives.

/// A real `std.Io` whose only changed slot counts `netRead` entries, so a
/// cancel test can cancel once the transport is INSIDE its reply read. With
/// a fixed sleep instead, a loaded machine could cancel an earlier step, and
/// the test passed by that route, not the read's. Earlier steps: connect and
/// request write, whose `Canceled` arms are separate code.
const ReadCueIo = struct {
    vtable: std.Io.VTable,
    userdata: ?*anyopaque,

    var inner_vtable: *const std.Io.VTable = undefined;
    var reads: std.atomic.Value(u32) = .init(0);

    fn init(inner: std.Io) ReadCueIo {
        inner_vtable = inner.vtable;
        reads.store(0, .release);
        var vt = inner.vtable.*;
        vt.operate = operate; // 0.17: socket reads are `Operation.net_read` through `vtable.operate`
        return .{ .vtable = vt, .userdata = inner.userdata };
    }

    fn io(self: *const ReadCueIo) std.Io {
        return .{ .userdata = self.userdata, .vtable = &self.vtable };
    }

    fn operate(userdata: ?*anyopaque, op: std.Io.Operation) std.Io.Cancelable!std.Io.Operation.Result {
        if (op == .net_read) _ = reads.fetchAdd(1, .monotonic);
        return inner_vtable.operate(userdata, op);
    }

    /// Wait until the transport has entered its `n`-th socket read. The
    /// deadline is a watchdog only: never getting there is a red, not a hang.
    fn awaitReads(real_io: std.Io, n: u32) bool {
        const start = std.Io.Clock.Timestamp.now(real_io, .awake);
        while (reads.load(.acquire) < n) {
            const waited = start.durationTo(std.Io.Clock.Timestamp.now(real_io, .awake)).raw.nanoseconds;
            if (waited > 60 * std.time.ns_per_s) return false;
            real_io.sleep(.fromMilliseconds(1), .awake) catch return reads.load(.acquire) >= n;
        }
        return true;
    }
};

test "tcpExchange: a canceled blocking read surfaces Canceled, not NetworkFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Port 0: an ephemeral port cannot collide with a parallel test run.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    // Not a skip. Binding an ephemeral loopback port is something every
    // machine that can run this suite can do; if it fails, the environment is
    // broken and the right report is a failure, not a pass. The skip that used
    // to be here also printed to stderr, which the gate driver turns into a
    // FAIL anyway -- so it never actually bought the tolerance it looked like.
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.socket.close(io);

    var cue: ReadCueIo = .init(io);
    // `timeout_ms = 0`: unbounded, so `tcpExchange` calls `tcpExchangeInner`
    // directly. With the default, `runBounded` wraps it and answers a cancel
    // with its OWN `Canceled`. Measured: the length read's arm mutated to
    // `return error.NetworkFailed` stayed green, so the test named for the
    // read was guarding `runBounded` instead.
    var r = Resolver.init(cue.io(), testing.allocator, .{
        .port = listener.socket.address.ip4.port,
        .transport = .tcp,
        .timeout_ms = 0,
    });
    defer r.deinit();

    var packet = [_]u8{ 0, 1, 2, 3 };
    var fut = try io.concurrent(Resolver.tcpExchange, .{ &r, netaddr.parseIp("127.0.0.1").?, &packet });
    // Cancel inside read #1, the length read. The connect lands in the
    // listener's backlog and the query in the kernel's send buffer, so
    // nothing else ever parks.
    const reached = ReadCueIo.awaitReads(io, 1);
    const result = fut.cancel(io);
    try testing.expect(reached);
    try testing.expectError(error.Canceled, result);
}

// ── which rcodes move on to the next server: glibc's, end to end ────────────

/// One of three UDP stubs on 127.0.0.1-3 sharing a port: answers every query
/// with `rcode` and no records, or, when `rcode` is null, A 192.0.2.1. Each
/// datagram it serves appends its own number (1-3) to the shared `log`.
const RcodeStub = struct {
    io: std.Io,
    sock: net.Socket,
    number: u8,
    rcode: ?u4,
    log: *RcodeLog,

    fn run(st: *RcodeStub) void {
        st.serve() catch |err| std.debug.print("RcodeStub: {t}\n", .{err});
    }

    fn serve(st: *RcodeStub) !void {
        var rbuf: [message.max_query_len]u8 = undefined;
        while (true) {
            const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(400), .clock = .awake } };
            const incoming = st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io)) catch |err| switch (err) {
                error.Timeout => return,
                else => |e| return e,
            };
            const q = incoming.data;
            const question = q[message.header_len..][0..EchoStub.questionLen(q[message.header_len..])];
            st.log.add(st.number);
            var out: [512]u8 = undefined;
            const resp = if (st.rcode) |rc|
                stubResponse(&out, q, 0x8180 | @as(u16, rc), question, "", 0)
            else
                stubResponse(&out, q, 0x8180, question, EchoStub.a_honest, 1);
            try st.sock.send(st.io, &incoming.from, resp);
        }
    }
};

/// R6 stub: answers A (192.0.2.1) and AAAA (2001:db8::1) for whatever name
/// it is asked, logging the qtypes. With `hold_ms`, a query waits up to 100 ms
/// for a second one to arrive and both are answered `hold_ms` after the first
/// arrived: parallel A+AAAA then take ~hold_ms, sequential ~2 x hold_ms.
const FamilyStub = struct {
    io: std.Io,
    sock: net.Socket,
    hold_ms: u32 = 0,
    types: [8]u16 = @splat(0),
    n: usize = 0,

    fn run(st: *FamilyStub) void {
        st.serve() catch |err| std.debug.print("FamilyStub: {t}\n", .{err});
    }

    fn serve(st: *FamilyStub) !void {
        var bufs: [2][message.max_query_len]u8 = undefined;
        while (true) {
            const idle: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(600), .clock = .awake } };
            const q1 = st.sock.receiveTimeout(st.io, &bufs[0], idle.toDeadline(st.io)) catch |err| switch (err) {
                error.Timeout => return,
                else => |e| return e,
            };
            const t0 = std.Io.Clock.Timestamp.now(st.io, .awake);
            var pending: [2]net.IncomingMessage = .{ q1, undefined };
            var count: usize = 1;
            if (st.hold_ms > 0) {
                const wait: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake } };
                if (st.sock.receiveTimeout(st.io, &bufs[1], wait.toDeadline(st.io))) |q2| {
                    pending[1] = q2;
                    count = 2;
                } else |_| {}
                const left = @as(i64, st.hold_ms) - t0.durationTo(std.Io.Clock.Timestamp.now(st.io, .awake)).raw.toMilliseconds();
                if (left > 0) try std.Io.Clock.Duration.sleep(.{ .raw = .fromMilliseconds(left), .clock = .awake }, st.io);
            }
            for (pending[0..count]) |inc| try st.answer(inc);
        }
    }

    fn answer(st: *FamilyStub, inc: net.IncomingMessage) !void {
        const q = inc.data;
        const qlen = EchoStub.questionLen(q[message.header_len..]);
        const question = q[message.header_len..][0..qlen];
        const ty = std.mem.readInt(u16, question[qlen - 4 ..][0..2], .big);
        if (st.n < st.types.len) st.types[st.n] = ty;
        st.n += 1;
        const rr_a = "\xc0\x0c" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xc0\x00\x02\x01";
        const rr_aaaa = "\xc0\x0c" ++ "\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" ++ "\x20\x01\x0d\xb8" ++ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        var out: [512]u8 = undefined;
        const resp = stubResponse(&out, q, 0x8180, question, if (ty == 28) rr_aaaa else rr_a, 1);
        try st.sock.send(st.io, &inc.from, resp);
    }
};

fn familyResolver(io: std.Io, gpa: std.mem.Allocator, stub: *FamilyStub, extra: Options) Resolver {
    var o = extra;
    o.servers = &loopback_servers;
    o.port = stub.sock.address.getPort();
    o.timeout_ms = 1500;
    o.attempts = 1;
    o.use_hosts = false;
    o.use_search = false;
    return Resolver.init(io, gpa, o);
}

test "family: .v4 sends no AAAA query, .v6 no A; a literal of the other family is no answer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var stub: FamilyStub = .{ .io = io, .sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err}) };
    defer stub.sock.close(io);
    var fut = try io.concurrent(FamilyStub.run, .{&stub});
    defer fut.await(io);

    var r4 = familyResolver(io, testing.allocator, &stub, .{ .family = .v4 });
    defer r4.deinit();
    const a = try r4.lookupIp("example.com.");
    defer testing.allocator.free(a);
    try testing.expectEqual(@as(usize, 1), a.len);
    try testing.expect(a[0] == .v4);
    var r6 = familyResolver(io, testing.allocator, &stub, .{ .family = .v6 });
    defer r6.deinit();
    const b = try r6.lookupIp("example.com.");
    defer testing.allocator.free(b);
    try testing.expectEqual(@as(usize, 1), b.len);
    try testing.expect(b[0] == .v6);
    const lit = try r6.lookupIp("192.0.2.7");
    defer testing.allocator.free(lit);
    try testing.expectEqual(@as(usize, 0), lit.len);
    try testing.expectEqualSlices(u16, &.{ 1, 28 }, stub.types[0..2]); // one A, then one AAAA, nothing else
    try testing.expectEqual(@as(usize, 2), stub.n);
}

test "parallel_families: A and AAAA leave together (~1 x the server's delay), sequential takes ~2 x; works over a non-thread-safe gpa" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var stub: FamilyStub = .{ .io = io, .sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err}), .hold_ms = 300 };
    defer stub.sock.close(io);
    var fut = try io.concurrent(FamilyStub.run, .{&stub});
    defer fut.await(io);

    // An arena is not thread-safe: the two concurrent queries must not race on it.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var rp = familyResolver(io, arena.allocator(), &stub, .{});
    defer rp.deinit();
    const t0 = std.Io.Clock.Timestamp.now(io, .awake);
    const both = try rp.lookupIpTtl("example.com.");
    const par_ms = t0.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds();
    try testing.expectEqual(@as(usize, 2), both.ips.len);
    try testing.expect(!both.partial);

    var rs = familyResolver(io, testing.allocator, &stub, .{ .parallel_families = false });
    defer rs.deinit();
    const t1 = std.Io.Clock.Timestamp.now(io, .awake);
    const seq = try rs.lookupIpTtl("example.com.");
    defer testing.allocator.free(seq.ips);
    const seq_ms = t1.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toMilliseconds();
    try testing.expectEqual(@as(usize, 2), seq.ips.len);
    if (!(par_ms < 500 and seq_ms >= 550)) {
        std.debug.print("parallel {d} ms, sequential {d} ms\n", .{ par_ms, seq_ms });
        return error.NotParallel;
    }
}

test "resolv.conf: no-aaaa asks A only, single-request goes sequential, rotate starts at the next server" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var log: RcodeLog = .{};
    var stubs = bindRcodeStubs(io, @splat(null), &log) orelse
        return testkit.loopbackSkip("127.0.0.1-3 not bindable on one port", .{});
    defer for (stubs) |st| st.sock.close(io);
    var futs: [3]std.Io.Future(void) = undefined;
    for (&futs, &stubs) |*f, *st| f.* = try io.concurrent(RcodeStub.run, .{st});
    defer for (&futs) |*f| f.await(io);

    try tmp.dir.writeFile(io, .{ .sub_path = "resolv.conf", .data = "nameserver 127.0.0.1\nnameserver 127.0.0.2\nnameserver 127.0.0.3\noptions rotate no-aaaa single-request\n" });
    var pbuf: [256]u8 = undefined;
    const path = try std.mem.print(&pbuf, ".zig-cache/tmp/{s}/resolv.conf", .{&tmp.sub_path});
    var r = Resolver.init(io, testing.allocator, .{ .resolv_conf_path = path, .port = stubs[0].sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false });
    defer r.deinit();
    for (0..3) |_| {
        var m = try r.query("probe.example.", .a);
        m.deinit();
    }
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, log.slice()); // rotate: each query starts at the next server
    try testing.expectEqual(Family.v4, r.effectiveFamily()); // no-aaaa
    try testing.expect(!r.parallelFamilies()); // single-request
    const ips = try r.lookupIp("probe.example.");
    defer testing.allocator.free(ips);
    try testing.expectEqual(@as(usize, 4), log.slice().len); // one query (A) for lookupIp, no AAAA
}

test "review X: the parallel path on a fresh Resolver loads resolv.conf ONCE (no leaked copy), and no-aaaa counts on the first lookup" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var stub: FamilyStub = .{ .io = io, .sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err}) };
    defer stub.sock.close(io);
    var fut = try io.concurrent(FamilyStub.run, .{&stub});
    defer fut.await(io);

    var pbuf: [256]u8 = undefined;
    try tmp.dir.writeFile(io, .{ .sub_path = "a.conf", .data = "nameserver 127.0.0.1\n" });
    const plain = try std.mem.print(&pbuf, ".zig-cache/tmp/{s}/a.conf", .{&tmp.sub_path});
    // testing.allocator: a second, never-freed resolv.conf text (the copy's) fails the test.
    var r = Resolver.init(io, testing.allocator, .{ .resolv_conf_path = plain, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
    defer r.deinit();
    const both = try r.lookupIp("example.com.");
    defer testing.allocator.free(both);
    try testing.expectEqual(@as(usize, 2), both.len);

    var p2: [256]u8 = undefined;
    try tmp.dir.writeFile(io, .{ .sub_path = "b.conf", .data = "nameserver 127.0.0.1\noptions no-aaaa\n" });
    const noaaaa = try std.mem.print(&p2, ".zig-cache/tmp/{s}/b.conf", .{&tmp.sub_path});
    var r4 = Resolver.init(io, testing.allocator, .{ .resolv_conf_path = noaaaa, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
    defer r4.deinit();
    const v4 = try r4.lookupIp("example.com.");
    defer testing.allocator.free(v4);
    try testing.expectEqual(@as(usize, 1), v4.len); // first lookup already honours no-aaaa
    try testing.expect(v4[0] == .v4);
}

test "review X: a null MX (RFC 7505, exchange \".\") is no mail host" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const null_mx: message.Record = .{ .name = "example.com", .ty = .mx, .class = .in, .ttl = 60, .data = .{ .mx = .{ .preference = 0, .exchange = "" } } };
    try testing.expect((try mxItem(arena.allocator(), &null_mx)) == null);
    const real: message.Record = .{ .name = "example.com", .ty = .mx, .class = .in, .ttl = 60, .data = .{ .mx = .{ .preference = 10, .exchange = "mail.example.com" } } };
    try testing.expectEqualStrings("mail.example.com", (try mxItem(arena.allocator(), &real)).?.host);
}

const RcodeLog = struct {
    numbers: [16]u8 = @splat(0),
    len: std.atomic.Value(usize) = .init(0),

    fn add(l: *RcodeLog, n: u8) void {
        const i = l.len.fetchAdd(1, .monotonic);
        if (i < l.numbers.len) l.numbers[i] = n;
    }

    fn slice(l: *RcodeLog) []const u8 {
        return l.numbers[0..@min(l.len.load(.monotonic), l.numbers.len)];
    }
};

const rcode_servers = [_]netaddr.Ip{
    .{ .v4 = .{ 127, 0, 0, 1 } }, .{ .v4 = .{ 127, 0, 0, 2 } }, .{ .v4 = .{ 127, 0, 0, 3 } },
};

/// Three stubs answering `rcodes[i]` (null: an answer) on 127.0.0.1-3 at one
/// port. Null when the loopback addresses cannot be bound on one port.
fn bindRcodeStubs(io: std.Io, rcodes: [3]?u4, log: *RcodeLog) ?[3]RcodeStub {
    var stubs: [3]RcodeStub = undefined;
    var port: u16 = 0;
    for (0..3) |i| {
        const addr: net.IpAddress = .{ .ip4 = .{ .bytes = rcode_servers[i].v4, .port = port } };
        const sock = addr.bind(io, .{ .mode = .dgram }) catch {
            for (stubs[0..i]) |st| st.sock.close(io);
            return null;
        };
        if (i == 0) port = sock.address.getPort();
        stubs[i] = .{ .io = io, .sock = sock, .number = @intCast(i + 1), .rcode = rcodes[i], .log = log };
    }
    return stubs;
}

test "query: the servers asked per rcode are the ones glibc asked (SERVFAIL, NOTIMP, REFUSED move on)" {
    // `testdata/config_oracle.zig` `rcodes`: glibc 2.43 over three servers
    // with its default two attempts, every server answering one rcode. The
    // same three servers here, as stubs, and the Resolver itself. Before this
    // test `query` returned the first server's SERVFAIL or REFUSED as the
    // answer, so one refusing nameserver failed every lookup getaddrinfo
    // still resolved.
    const rec = @import("testdata/config_oracle.zig");
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try testing.expectEqualStrings("nameserver 127.0.0.1\nnameserver 127.0.0.2\nnameserver 127.0.0.3\n", rec.rcodes_text);
    for (rec.rcodes) |fx| {
        var log: RcodeLog = .{};
        var stubs = bindRcodeStubs(io, @splat(fx.rcode), &log) orelse
            return testkit.loopbackSkip("127.0.0.1-3 not bindable on one port", .{});
        defer for (stubs) |st| st.sock.close(io);
        var futs: [3]std.Io.Future(void) = undefined;
        for (&futs, &stubs) |*f, *st| f.* = try io.concurrent(RcodeStub.run, .{st});
        // `edns_udp_size = null`: glibc's default (no `options edns0`) sends
        // no OPT, so it never meets the RFC 6891 §7 FORMERR fallback that an
        // EDNS query would trigger here (tested on its own with EdnsStub).
        var r = Resolver.init(io, testing.allocator, .{ .servers = &rcode_servers, .port = stubs[0].sock.address.getPort(), .timeout_ms = 1500, .attempts = 2, .use_hosts = false, .use_search = false, .edns_udp_size = null });
        defer r.deinit();
        const res = r.query("probe.example.", .a);
        for (&futs) |*f| f.await(io);
        var msg = try res;
        defer msg.deinit();
        // The reply handed back is the last one, whatever its rcode.
        try testing.expectEqual(@as(u12, fx.rcode), @backingInt(msg.rcode()));
        try testing.expectEqual(fx.tried.len, log.slice().len);
        for (fx.tried, log.slice()) |want, n| {
            var buf: [16]u8 = undefined;
            const got = try std.mem.print(&buf, "127.0.0.{d}", .{n});
            testing.expectEqualStrings(want, got) catch |e| {
                std.debug.print("rcode {d}: glibc asked {s}, ours {s}\n", .{ fx.rcode, want, got });
                return e;
            };
        }
    }
}

test "query: a refusing first server is skipped and the second server's answer returned" {
    // The everyday case behind the rule: the first nameserver refuses (a
    // resolver that serves only its own network), the second answers. The
    // refused reply is freed on the way (testing.allocator would see it).
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const refused: u4 = @intCast(@backingInt(message.Rcode.refused));
    var log: RcodeLog = .{};
    var stubs = bindRcodeStubs(io, .{ refused, null, null }, &log) orelse
        return testkit.loopbackSkip("127.0.0.1-3 not bindable on one port", .{});
    defer for (stubs) |st| st.sock.close(io);
    var futs: [3]std.Io.Future(void) = undefined;
    for (&futs, &stubs) |*f, *st| f.* = try io.concurrent(RcodeStub.run, .{st});
    var r = Resolver.init(io, testing.allocator, .{ .servers = &rcode_servers, .port = stubs[0].sock.address.getPort(), .timeout_ms = 1500, .attempts = 2, .use_hosts = false, .use_search = false });
    defer r.deinit();
    const res = r.query("example.com", .a);
    for (&futs) |*f| f.await(io);
    var msg = try res;
    defer msg.deinit();
    try expectOnlyHonestA(&msg);
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, log.slice());
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

test "query: bogus datagrams with the right id (QR clear, another question, undecodable) are dropped, the genuine reply still wins (sweep REV-dns-4)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = bindEchoStub(io, .bogus_same_id_first, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer stub.sock.close(io);
    var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
    defer r.deinit();
    var fut = try io.concurrent(EchoStub.run, .{&stub});
    const res = r.query("example.com", .a);
    fut.await(io);
    var msg = try res;
    defer msg.deinit();
    try expectOnlyHonestA(&msg);
}

test "resolve: a search entry that makes a bad name is skipped, not fatal (sweep REV-dns-3)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = 1, .transport = .tcp, .timeout_ms = 1000, .attempts = 1, .use_hosts = false });
    defer r.deinit();
    var conf: config.ResolvConf = .{};
    conf.search_buf[0] = "a..b"; // empty label: "host.a..b" is a BadName
    conf.nsearch = 1;
    r.conf = conf;
    // The bare name still gets asked: the failure is the network's (nothing
    // listens on port 1), not the search entry's BadName.
    try testing.expect(if (r.resolve("host", .a)) |m| blk: {
        var mm = m;
        mm.deinit();
        break :blk false;
    } else |err| err != error.BadName);
    // Nothing valid at all: the name error is still the answer.
    try testing.expectError(error.BadName, r.resolve("x..y", .a));
}

test "max_doh_response is the largest DNS message, 65535 bytes (sweep REV-dns-1)" {
    try testing.expectEqual(@as(usize, 65535), max_doh_response);
}

test "exchange: a datagram with the right id but QR clear is dropped, the genuine reply is returned (sweep audit GV-A1)" {
    // `query` would reject the QR-clear datagram in `decodeResponse` anyway;
    // `exchange` (used by dns update) has no question check, so the QR test in
    // `udpExchange` is its only defence against this forged datagram.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = bindEchoStub(io, .qr_clear_first, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer stub.sock.close(io);
    var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
    defer r.deinit();
    var qbuf: [message.max_query_len]u8 = undefined;
    const packet = try r.encodeChecked(&qbuf, "example.com", .a, 0x4242);
    var fut = try io.concurrent(EchoStub.run, .{&stub});
    const res = r.exchange(loopback_servers[0], packet);
    fut.await(io);
    const raw = try res;
    defer testing.allocator.free(raw);
    try testing.expect(raw[2] & 0x80 != 0);
    var msg = try message.decode(testing.allocator, raw);
    defer msg.deinit();
    try expectOnlyHonestA(&msg);
}

/// A plain-HTTP loopback "DoH server" that answers each request with 200 and
/// a body of `lens[i]` zero bytes.
const HttpBody = struct {
    io: std.Io,
    server: net.Server,
    lens: []const usize,

    fn run(st: *HttpBody) void {
        st.serve() catch |err| std.debug.print("HttpBody: {t}\n", .{err});
    }

    fn serve(st: *HttpBody) !void {
        for (st.lens) |len| {
            const stream = try st.server.accept(st.io);
            defer stream.close(st.io);
            var rbuf: [4096]u8 = undefined;
            var sr = stream.reader(st.io, &rbuf);
            const in = &sr.interface;
            var body_len: usize = 0;
            while (true) {
                const line = try in.takeDelimiterInclusive('\n');
                if (std.mem.eql(u8, line, "\r\n")) break;
                const key = "content-length:";
                if (std.ascii.startsWithIgnoreCase(line, key))
                    body_len = try std.fmt.parseInt(usize, std.mem.trim(u8, line[key.len..], " \t\r\n"), 10);
            }
            try in.discardAll(body_len);
            var wbuf: [4096]u8 = undefined;
            var sw = stream.writer(st.io, &wbuf);
            try sw.interface.print("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{len});
            var zeros: [1024]u8 = @splat(0);
            var left = len;
            while (left > 0) {
                const n = @min(left, zeros.len);
                try sw.interface.writeAll(zeros[0..n]);
                left -= n;
            }
            try sw.interface.flush();
        }
    }
};

test "DoH: a response body over 65535 bytes is DohFailed on both paths, one of exactly 65535 is read (sweep audit GV-A2)" {
    if (!doh_enabled) return error.SkipZigTest; // the refusal has its own test
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const lens = [_]usize{ 65_536, 65_536, 65_535, 65_535 };
    var stub: HttpBody = .{
        .io = io,
        .server = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err}),
        .lens = &lens,
    };
    defer stub.server.socket.close(io);
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/dns-query", .{stub.server.socket.address.getPort()});
    var r = Resolver.init(io, testing.allocator, .{ .doh_url = url, .timeout_ms = 5000, .use_hosts = false, .use_search = false });
    defer r.deinit();
    var fut = try io.concurrent(HttpBody.run, .{&stub});
    const wire_big = r.query("example.com", .a);
    const json_big = r.queryJson("example.com", .a);
    const wire_ok = r.query("example.com", .a);
    const json_ok = r.queryJson("example.com", .a);
    fut.await(io);
    if (wire_big) |m| {
        var msg = m;
        msg.deinit();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.DohFailed, err);
    if (json_big) |a| {
        var ans = a;
        ans.deinit();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.DohFailed, err);
    // Exactly at the cap the body is read, then found to be no DNS message.
    if (wire_ok) |m| {
        var msg = m;
        msg.deinit();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.MalformedResponse, err);
    if (json_ok) |a| {
        var ans = a;
        ans.deinit();
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.MalformedResponse, err);
}

test "query: a bare TC reply (header only, no question) goes to TCP, it is not dropped as undecodable (sweep audit GV-A7)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var silent: SilentTcp = .{ .io = io, .server = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err}) };
    defer silent.server.socket.close(io);
    const port = silent.server.socket.address.ip4.port;
    const udp_addr: net.IpAddress = .{ .ip4 = .loopback(port) };
    const udp_sock = udp_addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    var stub: UdpStub = .{ .io = io, .sock = udp_sock, .script = .truncated_bare };
    defer stub.sock.close(io);

    var tcp_fut = try io.concurrent(SilentTcp.run, .{&silent});
    var udp_fut = try io.concurrent(UdpStub.run, .{&stub});

    var r = Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .port = port,
        .timeout_ms = 300,
        .attempts = 1,
        .use_search = false,
        .use_hosts = false,
    });
    defer r.deinit();
    try testing.expectError(error.Timeout, r.query("example.com", .a));
    udp_fut.await(io);
    // Bounded wait for the accept to be recorded; without a TCP attempt the
    // acceptor never returns, so it is cancelled rather than awaited.
    io.futexWaitTimeout(u32, &silent.accepted.raw, 0, .{ .duration = .{ .raw = .fromMilliseconds(2000), .clock = .awake } }) catch {};
    silent.stop.store(1, .release);
    io.futexWake(u32, &silent.stop.raw, 1);
    tcp_fut.cancel(io);
    // The TCP connection was made: the bare TC reply was not discarded.
    try testing.expectEqual(@as(u32, 1), silent.accepted.load(.acquire));
}

test "query: an allocation failure at any point is OutOfMemory, never a swallowed datagram or a Timeout (sweep audit GV-A6)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var succeeded = false;
    var fail_index: usize = 0;
    while (fail_index < 300) : (fail_index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var stub = bindEchoStub(io, .a_only, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        defer stub.sock.close(io);
        stub.idle_ms = 300;
        var r = Resolver.init(io, failing.allocator(), .{ .servers = &loopback_servers, .port = stub.sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false });
        defer r.deinit();
        var fut = try io.concurrent(EchoStub.run, .{&stub});
        const res = r.query("example.com", .a);
        fut.await(io);
        if (res) |m| {
            var msg = m;
            msg.deinit();
            succeeded = true;
            break;
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
    try testing.expect(succeeded);
}

// ── typed lookups: tests (R5 / G2) ───────────────────────────────────────────

/// Raw wire bytes of an answer section, built record by record.
const WireBuf = struct {
    bytes: [1024]u8 = undefined,
    len: usize = 0,
    count: u16 = 0,

    fn put(b: *WireBuf, data: []const u8) void {
        @memcpy(b.bytes[b.len..][0..data.len], data);
        b.len += data.len;
    }

    fn putInt(b: *WireBuf, comptime T: type, v: T) void {
        var tmp: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, .big);
        b.put(&tmp);
    }

    fn putName(b: *WireBuf, n: []const u8) void {
        var it = std.mem.splitScalar(u8, n, '.');
        while (it.next()) |l| {
            if (l.len == 0) continue;
            b.putInt(u8, @intCast(l.len));
            b.put(l);
        }
        b.putInt(u8, 0);
    }

    fn rr(b: *WireBuf, owner: []const u8, ty: message.Type, ttl: u32, rd: *const WireBuf) void {
        b.putName(owner);
        b.putInt(u16, @backingInt(ty));
        b.putInt(u16, 1); // IN
        b.putInt(u32, ttl);
        b.putInt(u16, @intCast(rd.len));
        b.put(rd.bytes[0..rd.len]);
        b.count += 1;
    }

    fn mxRr(b: *WireBuf, owner: []const u8, ttl: u32, pref: u16, host: []const u8) void {
        var rd: WireBuf = .{};
        rd.putInt(u16, pref);
        rd.putName(host);
        b.rr(owner, .mx, ttl, &rd);
    }

    fn nameRr(b: *WireBuf, owner: []const u8, ty: message.Type, ttl: u32, target: []const u8) void {
        var rd: WireBuf = .{};
        rd.putName(target);
        b.rr(owner, ty, ttl, &rd);
    }

    fn txtRr(b: *WireBuf, owner: []const u8, ttl: u32, strings: []const []const u8) void {
        var rd: WireBuf = .{};
        for (strings) |s| {
            rd.putInt(u8, @intCast(s.len));
            rd.put(s);
        }
        b.rr(owner, .txt, ttl, &rd);
    }

    fn srvRr(b: *WireBuf, owner: []const u8, ttl: u32, priority: u16, weight: u16, port: u16, target: []const u8) void {
        var rd: WireBuf = .{};
        rd.putInt(u16, priority);
        rd.putInt(u16, weight);
        rd.putInt(u16, port);
        rd.putName(target);
        b.rr(owner, .srv, ttl, &rd);
    }

    fn aRr(b: *WireBuf, owner: []const u8, ttl: u32, addr: [4]u8) void {
        var rd: WireBuf = .{};
        rd.put(&addr);
        b.rr(owner, .a, ttl, &rd);
    }
};

/// Answers every query with the same canned answer section, echoing the
/// question it was asked.
const TypedStub = struct {
    io: std.Io,
    sock: net.Socket,
    flags: u16,
    answers: []const u8,
    ancount: u16,
    max: usize,
    idle_ms: i64 = 3000,
    served: usize = 0,

    fn run(st: *TypedStub) void {
        while (st.served < st.max) st.serveOne() catch return;
    }

    fn serveOne(st: *TypedStub) !void {
        var rbuf: [message.max_query_len]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(st.idle_ms), .clock = .awake } };
        const incoming = try st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io));
        const q = incoming.data;
        var p: usize = 12;
        while (p < q.len and q[p] != 0) p += @as(usize, q[p]) + 1;
        p += 5; // root label, type, class
        if (p > q.len) return error.BadQuery;
        var out: [2048]u8 = undefined;
        const resp = stubResponse(&out, q, st.flags, q[12..p], st.answers, st.ancount);
        try st.sock.send(st.io, &incoming.from, resp);
        st.served += 1;
    }
};

const TypedRig = struct {
    stub: TypedStub,
    r: Resolver,

    fn init(io: std.Io, r_io: std.Io, gpa: std.mem.Allocator, wb: *const WireBuf, flags: u16, max: usize) !TypedRig {
        const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        const sock = try addr.bind(io, .{ .mode = .dgram });
        return .{
            .stub = .{ .io = io, .sock = sock, .flags = flags, .answers = wb.bytes[0..wb.len], .ancount = wb.count, .max = max },
            .r = Resolver.init(r_io, gpa, .{ .servers = &loopback_servers, .port = sock.address.getPort(), .timeout_ms = 1500, .attempts = 1, .use_hosts = false, .use_search = false }),
        };
    }
};

/// `below` from a seeded PRNG, for the pure ordering helpers.
const PrngBelow = struct {
    p: *std.Random.DefaultPrng,
    fn below(self: PrngBelow, n: u64) u64 {
        return self.p.random().uintLessThan(u64, n);
    }
};

fn expectStrings(want: []const []const u8, got: []const []const u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expectEqualStrings(w, g);
}

test "lookupMx: sorted by preference, off-owner MX ignored, TTL from the used records" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const seq: SeqRandomIo = .init(io);
    var wb: WireBuf = .{};
    wb.mxRr("example.com", 300, 20, "mx2.example.com");
    wb.mxRr("example.com", 60, 10, "mx1.example.com");
    wb.mxRr("victim.test", 5, 0, "evil.test"); // out of bailiwick for the question
    wb.mxRr("example.com", 120, 10, "mx1b.example.com");
    var rg = TypedRig.init(io, seq.io(), testing.allocator, &wb, 0x8180, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer rg.stub.sock.close(io);
    defer rg.r.deinit();
    var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
    const res = rg.r.lookupMx("example.com");
    fut.await(io);
    var lk = try res;
    defer lk.deinit();
    try testing.expectEqual(@as(usize, 3), lk.items.len);
    try testing.expectEqual(@as(u16, 10), lk.items[0].preference);
    try testing.expectEqual(@as(u16, 10), lk.items[1].preference);
    try testing.expectEqual(@as(u16, 20), lk.items[2].preference);
    try testing.expectEqualStrings("mx2.example.com", lk.items[2].host);
    const first_two_ok = (std.mem.eql(u8, lk.items[0].host, "mx1.example.com") and std.mem.eql(u8, lk.items[1].host, "mx1b.example.com")) or
        (std.mem.eql(u8, lk.items[0].host, "mx1b.example.com") and std.mem.eql(u8, lk.items[1].host, "mx1.example.com"));
    try testing.expect(first_two_ok);
    try testing.expectEqual(@as(?u32, 60), lk.ttl_s);
}

test "orderMx: ascending preference; equal preferences come out in both orders" {
    var seen_ab = false;
    var seen_ba = false;
    for (0..64) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var items = [_]Mx{
            .{ .preference = 10, .host = "a" },
            .{ .preference = 10, .host = "b" },
            .{ .preference = 5, .host = "c" },
            .{ .preference = 30, .host = "d" },
        };
        orderMx(&items, PrngBelow{ .p = &prng });
        try testing.expectEqualStrings("c", items[0].host);
        try testing.expectEqualStrings("d", items[3].host);
        if (std.mem.eql(u8, items[1].host, "a")) seen_ab = true else seen_ba = true;
    }
    try testing.expect(seen_ab and seen_ba);
    var prng = std.Random.DefaultPrng.init(1);
    orderMx(&.{}, PrngBelow{ .p = &prng });
    var one = [_]Mx{.{ .preference = 1, .host = "x" }};
    orderMx(&one, PrngBelow{ .p = &prng });
    try testing.expectEqualStrings("x", one[0].host);
}

test "lookupTxt: the strings of one record are joined, one result per record" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wb: WireBuf = .{};
    wb.txtRr("example.com", 100, &.{ "v=spf1 ", "include:x.test", "" });
    wb.txtRr("example.com", 90, &.{"second"});
    var rg = TypedRig.init(io, io, testing.allocator, &wb, 0x8180, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer rg.stub.sock.close(io);
    defer rg.r.deinit();
    var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
    const res = rg.r.lookupTxt("example.com");
    fut.await(io);
    var lk = try res;
    defer lk.deinit();
    try expectStrings(&.{ "v=spf1 include:x.test", "second" }, lk.items);
    try testing.expectEqual(@as(?u32, 90), lk.ttl_s);
}

test "lookupNs: the name servers of the name" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wb: WireBuf = .{};
    wb.nameRr("example.com", .ns, 3600, "ns1.example.com");
    wb.nameRr("example.com", .ns, 3600, "ns2.example.net");
    wb.nameRr("other.test", .ns, 1, "ns.other.test");
    var rg = TypedRig.init(io, io, testing.allocator, &wb, 0x8180, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer rg.stub.sock.close(io);
    defer rg.r.deinit();
    var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
    const res = rg.r.lookupNs("example.com");
    fut.await(io);
    var lk = try res;
    defer lk.deinit();
    try expectStrings(&.{ "ns1.example.com", "ns2.example.net" }, lk.items);
    try testing.expectEqual(@as(?u32, 3600), lk.ttl_s);
}

fn cnameChainLookup(io: std.Io, hops: usize, last_buf: *[64]u8) ![]const u8 {
    // n0.example.com -> n1.example.com -> ... -> n<hops>.example.com (+ an A on the last).
    var wb: WireBuf = .{};
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    for (0..hops) |i| {
        const from = std.fmt.bufPrint(&a, "n{d}.example.com", .{i}) catch unreachable;
        const to = std.fmt.bufPrint(&b, "n{d}.example.com", .{i + 1}) catch unreachable;
        wb.nameRr(from, .cname, 200 + @as(u32, @intCast(i)), to);
    }
    const end = std.fmt.bufPrint(&b, "n{d}.example.com", .{hops}) catch unreachable;
    wb.aRr(end, 900, .{ 192, 0, 2, 7 });
    var rg = TypedRig.init(io, io, testing.allocator, &wb, 0x8180, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer rg.stub.sock.close(io);
    defer rg.r.deinit();
    var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
    const res = rg.r.lookupCname("n0.example.com");
    fut.await(io);
    const got = try res;
    defer testing.allocator.free(got);
    @memcpy(last_buf[0..got.len], got);
    return last_buf[0..got.len];
}

test "lookupCname: the end of a chain of 3, a chain cut at 8 hops, a name without CNAME" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("n3.example.com", try cnameChainLookup(io, 3, &buf));
    try testing.expectEqualStrings("n8.example.com", try cnameChainLookup(io, 10, &buf));
    try testing.expectEqualStrings("n0.example.com", try cnameChainLookup(io, 0, &buf));
}

test "typed lookups: SERVFAIL is ServerFailed, NXDOMAIN is an empty set" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const wb: WireBuf = .{};
    {
        var rg = TypedRig.init(io, io, testing.allocator, &wb, 0x8182, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        defer rg.stub.sock.close(io);
        defer rg.r.deinit();
        var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
        const res = rg.r.lookupMx("example.com");
        fut.await(io);
        try testing.expectError(error.ServerFailed, res);
    }
    {
        var rg = TypedRig.init(io, io, testing.allocator, &wb, 0x8183, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        defer rg.stub.sock.close(io);
        defer rg.r.deinit();
        var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
        const res = rg.r.lookupTxt("example.com");
        fut.await(io);
        var lk = try res;
        defer lk.deinit();
        try testing.expectEqual(@as(usize, 0), lk.items.len);
        try testing.expectEqual(@as(?u32, null), lk.ttl_s);
    }
}

test "lookupSrv: _service._proto.name is asked, priority ascending, off-owner SRV ignored" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wb: WireBuf = .{};
    wb.srvRr("_sip._tcp.example.com", 300, 20, 5, 5060, "c.example.com");
    wb.srvRr("_sip._tcp.example.com", 200, 10, 0, 5061, "a.example.com");
    wb.srvRr("_sip._tcp.example.com", 250, 10, 10, 5062, "b.example.com");
    wb.srvRr("_sip._udp.example.com", 1, 0, 1, 1, "wrong.example.com"); // not the owner asked
    var rg = TypedRig.init(io, io, testing.allocator, &wb, 0x8180, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    defer rg.stub.sock.close(io);
    defer rg.r.deinit();
    var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
    const res = rg.r.lookupSrv("sip", "tcp", "example.com");
    fut.await(io);
    var lk = try res;
    defer lk.deinit();
    try testing.expectEqual(@as(usize, 3), lk.items.len);
    try testing.expectEqual(@as(u16, 10), lk.items[0].priority);
    try testing.expectEqual(@as(u16, 10), lk.items[1].priority);
    try testing.expectEqual(@as(u16, 20), lk.items[2].priority);
    try testing.expectEqualStrings("c.example.com", lk.items[2].target);
    try testing.expectEqual(@as(u16, 5), lk.items[2].weight);
    try testing.expectEqual(@as(?u32, 200), lk.ttl_s);
}

test "lookupSrv: a \".\" target is an empty set; empty service and proto query the name as given" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    {
        var wb: WireBuf = .{};
        wb.srvRr("_x._tcp.example.com", 60, 0, 0, 0, ".");
        var rg = TypedRig.init(io, io, testing.allocator, &wb, 0x8180, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        defer rg.stub.sock.close(io);
        defer rg.r.deinit();
        var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
        const res = rg.r.lookupSrv("x", "tcp", "example.com");
        fut.await(io);
        var lk = try res;
        defer lk.deinit();
        try testing.expectEqual(@as(usize, 0), lk.items.len);
    }
    {
        var wb: WireBuf = .{};
        wb.srvRr("_x._tcp.example.com", 60, 1, 1, 80, "t.example.com");
        var rg = TypedRig.init(io, io, testing.allocator, &wb, 0x8180, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        defer rg.stub.sock.close(io);
        defer rg.r.deinit();
        var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
        const res = rg.r.lookupSrv("", "", "_x._tcp.example.com");
        fut.await(io);
        var lk = try res;
        defer lk.deinit();
        try testing.expectEqual(@as(usize, 1), lk.items.len);
        try testing.expectEqual(@as(u16, 80), lk.items[0].port);
    }
}

test "lookupSrv: a service name that does not fit is NameTooLong, nothing is sent" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var r = Resolver.init(io, testing.allocator, .{ .servers = &loopback_servers, .port = 1, .timeout_ms = 100, .attempts = 1, .use_hosts = false, .use_search = false });
    defer r.deinit();
    var name: [247]u8 = undefined; // four 61-byte labels
    @memset(&name, 'a');
    for ([_]usize{ 61, 123, 185 }) |dot| name[dot] = '.';
    try testing.expectError(error.NameTooLong, r.lookupSrv("sip", "tcp", &name));
}

test "orderSrv: weighted draws follow RFC 2782 over 10 000 seeded draws" {
    // RFC 2782: a random number in [0, sum], the first record whose running
    // sum reaches it, weight-0 records listed first. Weights {1, 3}: the
    // first draw picks "a" for numbers 0..1 of 0..4 = 2/5; weights {0, 1, 3}:
    // "z" for 0, "a" for 1, "b" for 2..4 = (1/5, 1/5, 3/5).
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rng = PrngBelow{ .p = &prng };
    const draws = 10_000;
    var first_a: usize = 0;
    var first_z: usize = 0;
    var first_b3: usize = 0;
    for (0..draws) |_| {
        var items = [_]Srv{
            .{ .priority = 20, .weight = 9, .port = 0, .target = "late" },
            .{ .priority = 10, .weight = 1, .port = 0, .target = "a" },
            .{ .priority = 10, .weight = 3, .port = 0, .target = "b" },
            .{ .priority = 5, .weight = 0, .port = 0, .target = "first" },
        };
        orderSrv(&items, rng);
        try testing.expectEqualStrings("first", items[0].target);
        try testing.expectEqualStrings("late", items[3].target);
        if (std.mem.eql(u8, items[1].target, "a")) first_a += 1;
        var zero = [_]Srv{
            .{ .priority = 1, .weight = 3, .port = 0, .target = "b" },
            .{ .priority = 1, .weight = 0, .port = 0, .target = "z" },
            .{ .priority = 1, .weight = 1, .port = 0, .target = "a" },
        };
        orderSrv(&zero, rng);
        if (std.mem.eql(u8, zero[0].target, "z")) first_z += 1;
        if (std.mem.eql(u8, zero[0].target, "b")) first_b3 += 1;
    }
    const n: f64 = draws;
    try testing.expectApproxEqAbs(0.4, @as(f64, @floatFromInt(first_a)) / n, 0.03);
    try testing.expectApproxEqAbs(0.2, @as(f64, @floatFromInt(first_z)) / n, 0.03);
    try testing.expectApproxEqAbs(0.6, @as(f64, @floatFromInt(first_b3)) / n, 0.03);
}

test "lookupMx: an allocation failure at any point is OutOfMemory, never a leak" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wb: WireBuf = .{};
    wb.mxRr("example.com", 300, 10, "mx.example.com");
    wb.mxRr("example.com", 300, 20, "mx2.example.com");
    var succeeded = false;
    var fail_index: usize = 0;
    while (fail_index < 300) : (fail_index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var rg = TypedRig.init(io, io, failing.allocator(), &wb, 0x8180, 1) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        defer rg.stub.sock.close(io);
        defer rg.r.deinit();
        rg.stub.idle_ms = 300;
        var fut = try io.concurrent(TypedStub.run, .{&rg.stub});
        const res = rg.r.lookupMx("example.com");
        fut.await(io);
        if (res) |l| {
            var lk = l;
            lk.deinit();
            succeeded = true;
            break;
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
    try testing.expect(succeeded);
}

// ── DoT (RFC 7858) over a loopback TLS server ───────────────────────────────
//
// The server is the collection's own `tlsserver` with its published P-256 test
// key vector (self-signed CA certificate, SAN `localhost`). Strict-mode tests
// put that certificate into the Resolver's CA bundle by hand, so the whole
// verification path (chain AND name) runs without a system CA store.

const tlsserver = if (dot_enabled) @import("tlsserver") else void;

/// One-connection DoT server on a thread: TLS handshake, then one framed
/// query answered per `mode`.
const DotStub = struct {
    io: std.Io,
    server: net.Server,
    /// The certificate and key it serves (borrowed from the rig).
    ck: tlsserver.CertifiedKey,
    mode: Mode = .answer,
    /// Queries received (framed and decrypted).
    queries: std.atomic.Value(u32) = .init(0),

    const Mode = enum {
        /// A canned A answer (EchoStub.a_honest) for the question asked.
        answer,
        /// A length prefix announcing 200 bytes, 10 of them, then close_notify.
        short_frame,
    };

    fn run(st: *DotStub) void {
        st.serve() catch {};
    }

    fn serve(st: *DotStub) !void {
        const gpa = testing.allocator;
        const ck = st.ck;
        var prng = std.Random.DefaultPrng.init(0xd07);
        const cfg: tlsserver.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };

        const stream = try st.server.accept(st.io);
        defer stream.close(st.io);
        const in_buf = try gpa.alloc(u8, tlsserver.record.max_record_len);
        defer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, tlsserver.server.minOutputLen(&cfg, &ck));
        defer gpa.free(out_buf);
        const joiner = try gpa.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message));
        defer gpa.free(joiner);
        var sr = stream.reader(st.io, in_buf);
        var sw = stream.writer(st.io, out_buf);
        var conn = tlsserver.Connection.init(&cfg, &sr.interface, &sw.interface, joiner);
        defer conn.deinit();

        const data = (try conn.read()) orelse return;
        if (data.len < 2 + message.header_len) return;
        const len = std.mem.readInt(u16, data[0..2], .big);
        if (data.len != 2 + @as(usize, len)) return;
        _ = st.queries.fetchAdd(1, .release);
        const q = data[2..];
        var out: [2 + 512]u8 = undefined;
        switch (st.mode) {
            .answer => {
                const question = q[message.header_len..][0..EchoStub.questionLen(q[message.header_len..])];
                const resp = stubResponse(out[2..], q, 0x8180, question, EchoStub.a_honest, 1);
                std.mem.writeInt(u16, out[0..2], @intCast(resp.len), .big);
                try conn.writeAll(out[0 .. 2 + resp.len]);
            },
            .short_frame => {
                std.mem.writeInt(u16, out[0..2], 200, .big);
                @memset(out[2..12], 0xab);
                try conn.writeAll(out[0..12]);
            },
        }
        try conn.close();
    }
};

/// A Resolver at a `DotStub`'s port, with the stub certificate trusted. The
/// plain port is a bound-but-silent UDP socket, so a test can prove that
/// nothing leaked out over plain DNS.
const DotRig = struct {
    pair: tlsserver.keys.CertKeyPair,
    stub: DotStub,
    plain: net.Socket,
    r: Resolver,

    fn init(rig: *DotRig, io: std.Io, mode: DotStub.Mode, name: ?[]const u8, verify: http.Client.TlsOptions.Verify) !void {
        const kv = comptime tlsserver.testKeyVector("p256-pkcs8");
        var pair: tlsserver.keys.CertKeyPair = undefined;
        try tlsserver.keys.CertKeyPair.fromPem(&pair, testing.allocator, kv.cert_pem, kv.key_pem);
        errdefer pair.deinit(testing.allocator);
        const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        const listener = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err});
        errdefer listener.socket.close(io);
        const plain = (net.IpAddress{ .ip4 = .loopback(0) }).bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        rig.* = .{
            .pair = pair,
            .stub = .{ .io = io, .server = listener, .ck = undefined, .mode = mode },
            .plain = plain,
            .r = Resolver.init(io, testing.allocator, .{
                .servers = &loopback_servers,
                .port = plain.address.ip4.port,
                .dot_port = listener.socket.address.ip4.port,
                .transport = .tls,
                .tls_server_name = name,
                .dot_tls = .{ .verify = verify },
                .timeout_ms = 5000,
                .attempts = 1,
                .use_hosts = false,
                .use_search = false,
            }),
        };
        // Trust the stub's own certificate; `scanned` keeps the system store out.
        rig.stub.ck = rig.pair.certifiedKey();
        const cert = rig.pair.chain[0];
        const ca = &rig.r.dot_ca;
        try ca.bundle.bytes.appendSlice(testing.allocator, cert);
        try ca.bundle.parseCert(testing.allocator, 0, 0);
        ca.scanned = true;
    }

    fn deinit(rig: *DotRig, io: std.Io) void {
        rig.r.deinit();
        rig.pair.deinit(testing.allocator);
        rig.plain.close(io);
        rig.stub.server.socket.close(io);
    }

    /// Nothing may have arrived on the plain UDP port.
    fn expectNoPlainDns(rig: *DotRig, io: std.Io) !void {
        var buf: [512]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake } };
        try testing.expectError(error.Timeout, rig.plain.receiveTimeout(io, &buf, t.toDeadline(io)));
    }
};

test "DoT: a query over transport .tls is answered through a verified TLS session" {
    if (!dot_enabled) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: DotRig = undefined;
    try rig.init(io, .answer, "localhost", .strict);
    defer rig.deinit(io);
    var fut = try io.concurrent(DotStub.run, .{&rig.stub});
    defer fut.await(io);

    var msg = try rig.r.query("example.com", .a);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 1), msg.answers.len);
    try testing.expectEqual(@as(u32, 1), rig.stub.queries.load(.acquire));
    try rig.expectNoPlainDns(io);
}

test "DoT: insecure_no_verify and no tls_server_name still completes (opportunistic privacy)" {
    if (!dot_enabled) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: DotRig = undefined;
    try rig.init(io, .answer, null, .insecure_no_verify);
    defer rig.deinit(io);
    var fut = try io.concurrent(DotStub.run, .{&rig.stub});
    defer fut.await(io);

    var msg = try rig.r.query("example.com", .a);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 1), msg.answers.len);
}

test "DoT: `exchange` carries a caller-built message over TLS too" {
    if (!dot_enabled) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: DotRig = undefined;
    try rig.init(io, .answer, "localhost", .strict);
    defer rig.deinit(io);
    var fut = try io.concurrent(DotStub.run, .{&rig.stub});
    defer fut.await(io);

    var qbuf: [message.max_query_len]u8 = undefined;
    const packet = try rig.r.encodeChecked(&qbuf, "example.com", .a, 0x1234);
    const raw = try rig.r.exchange(.{ .v4 = .{ 127, 0, 0, 1 } }, packet);
    defer testing.allocator.free(raw);
    try testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, raw[0..2], .big));
    try rig.expectNoPlainDns(io);
}

test "DoT: a certificate for another name is TlsFailed, and nothing is asked over plain DNS" {
    if (!dot_enabled) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: DotRig = undefined;
    try rig.init(io, .answer, "dns.example.net", .strict);
    defer rig.deinit(io);
    var fut = try io.concurrent(DotStub.run, .{&rig.stub});
    defer fut.await(io);

    try testing.expectError(error.TlsFailed, rig.r.query("example.com", .a));
    try testing.expectEqual(@as(u32, 0), rig.stub.queries.load(.acquire));
    try rig.expectNoPlainDns(io);
}

test "DoT: strict verification against an untrusted certificate is TlsFailed" {
    if (!dot_enabled) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: DotRig = undefined;
    try rig.init(io, .answer, "localhost", .strict);
    defer rig.deinit(io);
    // Drop the trust anchor `init` added: the self-signed stub is now unknown.
    rig.r.dot_ca.bundle.deinit(testing.allocator);
    rig.r.dot_ca.bundle = .empty;
    var fut = try io.concurrent(DotStub.run, .{&rig.stub});
    defer fut.await(io);

    try testing.expectError(error.TlsFailed, rig.r.query("example.com", .a));
    try rig.expectNoPlainDns(io);
}

test "DoT: a frame shorter than its length prefix is an error, not a panic or a short answer" {
    if (!dot_enabled) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rig: DotRig = undefined;
    try rig.init(io, .short_frame, "localhost", .strict);
    defer rig.deinit(io);
    var fut = try io.concurrent(DotStub.run, .{&rig.stub});
    defer fut.await(io);

    try testing.expectError(error.NetworkFailed, rig.r.query("example.com", .a));
    try rig.expectNoPlainDns(io);
}

test "DoT: a server that accepts and never speaks TLS is bounded by timeout_ms and by call_timeout_ms" {
    if (!dot_enabled) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var silent: SilentTcp = .{ .io = io, .server = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err}) };
    defer silent.server.socket.close(io);
    var fut = try io.concurrent(SilentTcp.run, .{&silent});
    defer {
        silent.stop.store(1, .release);
        io.futexWake(u32, &silent.stop.raw, 1);
        fut.await(io);
    }

    // Per-attempt bound.
    var r = Resolver.init(io, testing.allocator, .{
        .servers = &loopback_servers,
        .dot_port = silent.server.socket.address.ip4.port,
        .transport = .tls,
        .dot_tls = .{ .verify = .insecure_no_verify },
        .timeout_ms = 300,
        .attempts = 1,
        .use_search = false,
    });
    defer r.deinit();
    const start = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Timeout, r.query("example.com", .a));
    const elapsed_ns = start.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    try testing.expect(elapsed_ns >= 250 * std.time.ns_per_ms);
    try testing.expect(elapsed_ns < 5 * std.time.ns_per_s);

    // The call budget cuts the handshake short even with a long per-attempt one.
    r.options.timeout_ms = 20_000;
    r.options.call_timeout_ms = 300;
    const start2 = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Timeout, r.query("example.com", .a));
    const elapsed2 = start2.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    try testing.expect(elapsed2 < 5 * std.time.ns_per_s);
}

test "built without DoT (-Ddns-dot=false), transport .tls is refused on query and exchange, never asked in plain" {
    if (dot_enabled) return error.SkipZigTest;
    var r = Resolver.init(testing.io, testing.allocator, .{ .servers = &loopback_servers, .transport = .tls, .timeout_ms = 200, .use_hosts = false, .use_search = false });
    defer r.deinit();
    try testing.expectError(error.NoDotSupport, r.query("example.com", .a));
    var qbuf: [message.max_query_len]u8 = undefined;
    const packet = try r.encodeChecked(&qbuf, "example.com", .a, 1);
    try testing.expectError(error.NoDotSupport, r.exchange(.{ .v4 = .{ 127, 0, 0, 1 } }, packet));
}

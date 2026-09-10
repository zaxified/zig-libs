// SPDX-License-Identifier: MIT

//! DNS resolver — UDP (with TC-bit → TCP retry), TCP (RFC 1035 §4.2.2
//! two-byte length prefix) and DoH (RFC 8484, `application/dns-message` over
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
const builtin = @import("builtin");
const netaddr = @import("netaddr");
const http = @import("http");
const dns = @import("root.zig");
const message = @import("message.zig");
const config = @import("config.zig");
const net = std.Io.net;

const Resolver = @This();

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
/// Present iff `options.doh_url` is set.
http_client: ?http.Client,
/// resolv.conf, loaded lazily on first use (do not copy the Resolver after).
conf: ?config.ResolvConf,
conf_text: ?[]u8,

pub const Transport = enum {
    /// UDP first; retry over TCP when the response has the TC bit set.
    auto,
    /// TCP only.
    tcp,
};

pub const DohMethod = enum {
    /// RFC 8484 POST — the request body is the binary DNS message.
    post,
    /// RFC 8484 GET — the message travels base64url-encoded in `?dns=`.
    get,
};

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
    /// Per-attempt budget; 0 = no timeout. Enforced natively on UDP receive;
    /// see the module comment for the TCP/DoH connect caveat.
    timeout_ms: u32 = 5000,
    /// UDP retry rounds over the server list (min 1).
    attempts: u8 = 2,
    /// Consult /etc/hosts in `lookupIp`/`reverse` before querying.
    use_hosts: bool = true,
    /// Apply the resolv.conf search list / ndots in `resolve`/`lookupIp`.
    use_search: bool = true,
    /// EDNS(0) advertised UDP payload size; null disables the OPT record.
    edns_udp_size: ?u16 = 1232,
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
    Timeout,
    /// Socket-level failure (bind/send/connect/read).
    NetworkFailed,
    /// The response did not decode, or its id/QR did not match the query.
    MalformedResponse,
    /// DoH transport failed (HTTP error, non-200 status, oversized body).
    DohFailed,
    /// A DoH operation was requested without `Options.doh_url`.
    NoDohEndpoint,
    OutOfMemory,
    Canceled,
};

/// `io` must support net + async operations (e.g. `std.Io.Threaded`).
pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Resolver {
    return .{
        .io = io,
        .gpa = gpa,
        .options = options,
        .http_client = if (options.doh_url != null)
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
    if (r.http_client) |*c| c.deinit();
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
    while (it.next(&candidate_buf)) |candidate| {
        const msg = try r.query(candidate, ty);
        if (msg.rcode() == .no_error and msg.answers.len > 0) {
            if (last) |*m| m.deinit();
            return msg;
        }
        if (last) |*m| m.deinit();
        last = msg;
    }
    return last orelse error.BadName; // only an empty/over-long name yields no candidate
}

/// All IPv4 + IPv6 addresses for `name`: IP literals pass through, /etc/hosts
/// is consulted first (when enabled), then A and AAAA queries per search-list
/// candidate. On Linux the result is ordered by RFC 6724 destination rules
/// (netaddr) like getaddrinfo. Returns an empty slice when nothing resolves;
/// caller frees with `gpa.free`.
pub fn lookupIp(r: *Resolver, name: []const u8) Error![]netaddr.Ip {
    var list: std.ArrayList(netaddr.Ip) = .empty;
    errdefer list.deinit(r.gpa);

    if (netaddr.parseIp(name)) |ip| {
        try list.append(r.gpa, ip);
        return list.toOwnedSlice(r.gpa);
    }

    if (r.options.use_hosts) hosts: {
        const content = r.readHosts() orelse break :hosts;
        defer r.gpa.free(content);
        var ips: [16]netaddr.Ip = undefined;
        const n = config.hostsIpsForName(content, name, &ips);
        if (n > 0) {
            try list.appendSlice(r.gpa, ips[0..n]);
            sortIps(list.items);
            return list.toOwnedSlice(r.gpa);
        }
    }

    var search: []const []const u8 = &.{};
    var ndots: u8 = 1;
    if (r.options.use_search) {
        try r.ensureConfig();
        search = r.conf.?.search();
        ndots = r.conf.?.ndots;
    }

    var candidate_buf: [message.max_name_text_len]u8 = undefined;
    var it = config.NameIterator.init(name, search, ndots);
    while (it.next(&candidate_buf)) |candidate| {
        for ([_]message.Type{ .a, .aaaa }) |ty| {
            var msg = r.query(candidate, ty) catch |err| switch (err) {
                error.Canceled, error.OutOfMemory => |e| return e,
                else => continue, // tolerate one family failing (Go aggregates too)
            };
            defer msg.deinit();
            try collectAddresses(r.gpa, &list, &msg, candidate);
        }
        if (list.items.len > 0) break; // first useful candidate wins
    }

    sortIps(list.items);
    return list.toOwnedSlice(r.gpa);
}

/// PTR lookup: /etc/hosts first (when enabled), then a reverse query for the
/// `in-addr.arpa`/`ip6.arpa` name built via netaddr. Returns the host names
/// (possibly empty); free with `freeNames`.
pub fn reverse(r: *Resolver, ip: netaddr.Ip) Error![]const []const u8 {
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
pub fn query(r: *Resolver, name: []const u8, ty: message.Type) Error!message.Message {
    var qbuf: [message.max_query_len]u8 = undefined;

    if (r.options.doh_url != null) {
        // RFC 8484 §4.1: use id 0 so DoH caches can be effective.
        const packet = try encodeChecked(&qbuf, name, ty, 0, r.options.edns_udp_size);
        const raw = try r.dohExchange(packet);
        defer r.gpa.free(raw);
        return r.decodeResponse(raw, 0, name, ty);
    }

    // Validate the name before touching the network (the per-attempt encode
    // below cannot fail differently).
    _ = try encodeChecked(&qbuf, name, ty, 0, r.options.edns_udp_size);

    const servers = try r.serverList();
    const rbuf = try r.gpa.alloc(u8, @max(512, r.options.edns_udp_size orelse 0));
    defer r.gpa.free(rbuf);

    var last_err: ?Error = null;
    var attempt: u8 = 0;
    while (attempt < @max(1, r.options.attempts)) : (attempt += 1) {
        for (servers) |server| {
            // A fresh transaction id for EVERY datagram sent. One id per
            // `query` meant a retry re-used an id an off-path attacker may
            // already have seen or guessed on the previous attempt, so every
            // round was another shot at a half-known target.
            var id_bytes: [2]u8 = undefined;
            r.io.random(&id_bytes);
            const id = std.mem.readInt(u16, &id_bytes, .big);
            const packet = try encodeChecked(&qbuf, name, ty, id, r.options.edns_udp_size);

            if (r.options.transport == .tcp) {
                const raw = r.tcpExchange(server, packet) catch |err| switch (err) {
                    error.Canceled, error.OutOfMemory => |e| return e,
                    else => {
                        last_err = err;
                        continue;
                    },
                };
                defer r.gpa.free(raw);
                return r.decodeResponse(raw, id, name, ty);
            }

            const udp = r.udpExchange(server, packet, id, rbuf) catch |err| switch (err) {
                error.Canceled, error.OutOfMemory => |e| return e,
                else => {
                    last_err = err;
                    continue;
                },
            };
            const raw = udp.data;
            // Retry over TCP when either says the UDP reply is not the whole
            // answer: the TC bit the server itself set, or the kernel's own
            // truncation flag for a datagram the server sent oversized
            // without setting TC (audit F13). The truncated bytes are never
            // decoded -- a header whose counts no longer match its body is
            // exactly the malformed input this resolver already treats as
            // untrustworthy, so there is nothing to gain from trying first.
            if (udp.truncated or (raw.len >= 3 and raw[2] & 0x02 != 0)) {
                const traw = r.tcpExchange(server, packet) catch |err| switch (err) {
                    error.Canceled, error.OutOfMemory => |e| return e,
                    else => {
                        last_err = err;
                        continue;
                    },
                };
                defer r.gpa.free(traw);
                return r.decodeResponse(traw, id, name, ty);
            }
            return r.decodeResponse(raw, id, name, ty);
        }
    }
    return last_err orelse error.Timeout;
}

fn encodeChecked(buf: []u8, name: []const u8, ty: message.Type, id: u16, edns: ?u16) Error![]u8 {
    return message.encodeQuery(buf, name, ty, .{ .id = id, .edns_udp_size = edns }) catch |err| switch (err) {
        error.BufferTooSmall => unreachable, // max_query_len always fits
        error.NameTooLong => error.NameTooLong,
        error.BadName => error.BadName,
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
    return msg;
}

// ── configuration plumbing ──────────────────────────────────────────────────

/// Go's fallback when resolv.conf is missing or names no servers.
const default_servers = [_]netaddr.Ip{
    .{ .v4 = .{ 127, 0, 0, 1 } },
    .{ .v6 = [_]u8{0} ** 15 ++ [_]u8{1} },
};

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
    const ms = r.options.timeout_ms;
    if (ms == 0) return .none;
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
    return t.toDeadline(r.io);
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

/// One UDP round-trip. Datagrams from the wrong peer or with the wrong id
/// are ignored (anti-spoofing, same as Go/c-ares) until the deadline.
/// The returned slice points into `rbuf`.
fn udpExchange(r: *Resolver, server: netaddr.Ip, packet: []const u8, id: u16, rbuf: []u8) Error!UdpResult {
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

/// Practical cap for a DoH response body (a DNS message is ≤ 64 KiB).
const max_doh_response = 128 * 1024;

/// RFC 8484 exchange over the http module. Returns the gpa-owned raw DNS
/// message from the response body.
fn dohExchange(r: *Resolver, packet: []const u8) Error![]u8 {
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
            const sep: u8 = if (std.mem.indexOfScalar(u8, url, '?') != null) '&' else '?';
            const full = std.fmt.allocPrint(r.gpa, "{s}{c}dns={s}", .{ url, sep, dns_param }) catch
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
    try out.append(gpa, if (std.mem.indexOfScalar(u8, url, '?') != null) '&' else '?');
    try out.appendSlice(gpa, "name=");
    for (name) |b| {
        if (std.ascii.isAlphanumeric(b) or b == '-' or b == '.' or b == '_' or b == '~') {
            try out.append(gpa, b);
        } else {
            const hex = "0123456789ABCDEF";
            try out.appendSlice(gpa, &.{ '%', hex[b >> 4], hex[b & 0xf] });
        }
    }
    try out.print(gpa, "&type={d}", .{@intFromEnum(ty)});
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
    try testing.expectError(error.BadName, jsonQueryUrl(gpa, "https://x.test/r", "a" ** 64 ++ ".test", .a));
    try testing.expectError(error.NameTooLong, jsonQueryUrl(gpa, "https://x.test/r", ("abcdefg." ** 32) ++ "x", .a));
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

test "lookupIp: an answer record the question never asked about is ignored (bailiwick), end to end over loopback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = bindUdpStub(io, .off_bailiwick_plus_honest) catch return error.SkipZigTest;
    defer stub.sock.close(io);
    var stub_fut = try io.concurrent(UdpStub.run, .{&stub});
    defer stub_fut.await(io);

    var r = try udpStubResolver(io, &stub, 1);
    defer r.deinit();
    // The stub answers one datagram (the A query); the AAAA query times out
    // (1.5 s) and lookupIp tolerates one family failing.
    const ips = try r.lookupIp("example.com");
    defer testing.allocator.free(ips);
    try testing.expectEqual(@as(usize, 1), ips.len);
    try testing.expect(ips[0].eql(netaddr.parseIp("192.0.2.1").?)); // never 203.0.113.66
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

    fn run(st: *SilentTcp) void {
        const stream = st.server.accept(st.io) catch return;
        defer stream.close(st.io);
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
    var silent: SilentTcp = .{ .io = io, .server = addr.listen(io, .{ .reuse_address = true }) catch return error.SkipZigTest };
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
    var silent: SilentTcp = .{ .io = io, .server = addr.listen(io, .{ .reuse_address = true }) catch return error.SkipZigTest };
    defer silent.server.socket.close(io);
    const port = silent.server.socket.address.ip4.port;
    const udp_addr: net.IpAddress = .{ .ip4 = .loopback(port) };
    const udp_sock = udp_addr.bind(io, .{ .mode = .dgram }) catch return error.SkipZigTest;
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
    var silent: SilentTcp = .{ .io = io, .server = addr.listen(io, .{ .reuse_address = true }) catch return error.SkipZigTest };
    defer silent.server.socket.close(io);
    const port = silent.server.socket.address.ip4.port;
    const udp_addr: net.IpAddress = .{ .ip4 = .loopback(port) };
    const udp_sock = udp_addr.bind(io, .{ .mode = .dgram }) catch return error.SkipZigTest;
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

    var r = Resolver.init(io, testing.allocator, .{
        .port = listener.socket.address.ip4.port,
        .transport = .tcp,
    });
    defer r.deinit();

    var packet = [_]u8{ 0, 1, 2, 3 };
    var fut = try io.concurrent(Resolver.tcpExchange, .{ &r, netaddr.parseIp("127.0.0.1").?, &packet });
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

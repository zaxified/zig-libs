// SPDX-License-Identifier: MIT

//! An `acme.Client.Solver` for DNS-01 that does everything but the provider
//! call: follows the `_acme-challenge` CNAME delegation, finds the zone,
//! hands the record to a `Publisher`, and returns only once every
//! authoritative server of the zone answers with the value — lego's
//! `dns01.Challenge` + `PreCheck`, certmagic's `DNS01Solver`.
//!
//! ```zig
//! var pub_ = acmedns.Rfc2136.init(io, gpa, .{ .server = primary, .key = &key });
//! var solver = acmedns.Dns01Solver.init(io, gpa, .{ .publisher = pub_.publisher() });
//! defer solver.deinit();
//! var client = try acme.Client.init(io, gpa, .{
//!     .challenge_type = .dns_01,
//!     .solvers = &.{solver.solver()},
//!     ...
//! });
//! ```
//!
//! One solver per `acme.Client` (`single_owner`, like the client): it keeps
//! the records it published until their `cleanup`, so cleanup removes what
//! was published even if DNS changed in between.

const std = @import("std");
const acme = @import("acme");
const dns = @import("dns");
const netaddr = @import("netaddr");
const root = @import("root.zig");
const zone = @import("zone.zig");

const Dns01Solver = @This();

io: std.Io,
gpa: std.mem.Allocator,
options: Options,
pending: std.ArrayList(*Pending) = .empty,
/// Why the last `present` failed (a static string), for the caller's log.
note: []const u8 = "",

pub const Options = struct {
    publisher: root.Publisher,
    /// Recursive resolvers for the CNAME walk, the SOA walk and the NS
    /// lookup. Empty = /etc/resolv.conf.
    resolvers: []const netaddr.Ip = &.{},
    /// Port for every DNS query this solver makes (resolvers and
    /// authoritative servers alike). 53 outside of tests.
    port: u16 = 53,
    /// Per-query budget.
    query_timeout_ms: u32 = 3000,
    /// Publish at the end of `_acme-challenge.<domain>`'s CNAME chain
    /// (lego's default; certmagic needs an explicit override domain).
    follow_cname: bool = true,
    /// Publish here instead of `_acme-challenge.<domain>` — a delegation
    /// the caller knows without looking up a CNAME (certmagic's
    /// `OverrideDomain`). The CNAME walk still starts from it.
    override_name: ?[]const u8 = null,
    /// The zone to publish in; null = find it by the SOA walk.
    zone: ?[]const u8 = null,
    /// Wait until every authoritative server answers with the value before
    /// telling the CA to validate. Turning it off means `delay_ms` is all
    /// that stands between publishing and validation.
    check_propagation: bool = true,
    /// Ask these instead of the zone's NS records (a hidden primary, a
    /// split-horizon setup the public NS names do not reach from here).
    authoritative: []const netaddr.Ip = &.{},
    /// Every authoritative server must answer with the value (lego, certmagic);
    /// false: one is enough (lego `--dns.disable-cp`), for a zone whose
    /// secondaries transfer slowly but the CA is known to ask the primary.
    require_all_authoritative: bool = true,
    /// Also require the recursive `resolvers` to answer with the value (lego
    /// `--dns.propagation-rns`): catches a resolver still caching the
    /// NXDOMAIN it saw before the record existed.
    check_resolvers: bool = false,
    /// Give up after this long (lego 60 s, certmagic 2 min).
    propagation_timeout_ms: u32 = 120_000,
    /// Between checks (lego 2 s).
    propagation_interval_ms: u32 = 2_000,
    /// Extra wait after the check passed (or instead of it): resolvers the
    /// CA uses may lag the authoritative servers through caching of an
    /// earlier NXDOMAIN — certmagic's `PropagationDelay`.
    delay_ms: u32 = 0,
};

/// One published record, kept until its cleanup. Heap-allocated so the
/// record's slices into its own buffers stay valid as the list grows.
const Pending = struct {
    domain: []u8 = &.{},
    value: []u8 = &.{},
    token: []u8 = &.{},
    key_authorization: []u8 = &.{},
    record: root.Record = undefined,
    fqdn_buf: [zone.max_name_len]u8 = undefined,
    zone_buf: [zone.max_name_len]u8 = undefined,
};

pub fn init(io: std.Io, gpa: std.mem.Allocator, options: Options) Dns01Solver {
    return .{ .io = io, .gpa = gpa, .options = options };
}

pub fn deinit(s: *Dns01Solver) void {
    for (s.pending.items) |p| s.destroyPending(p);
    s.pending.deinit(s.gpa);
    s.* = undefined;
}

/// The `acme.Client.Solver` to put in `acme.Client.Options.solvers`. The
/// solver must outlive the client's use of it and must not move.
pub fn solver(s: *Dns01Solver) acme.Client.Solver {
    return .{ .ctx = s, .type = .dns_01, .present = presentFn, .cleanup = cleanupFn };
}

fn presentFn(ctx: ?*anyopaque, req: *const acme.Client.ChallengeRequest) acme.Client.SolverError!void {
    const s: *Dns01Solver = @ptrCast(@alignCast(ctx.?));
    return s.present(req.identifier, req.token, req.key_authorization) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.SolverFailed,
    };
}

fn cleanupFn(ctx: ?*anyopaque, req: *const acme.Client.ChallengeRequest) void {
    const s: *Dns01Solver = @ptrCast(@alignCast(ctx.?));
    s.cleanup(req.identifier, &req.dnsTxtValue());
}

pub const Error = zone.Error || root.PublishError || error{
    /// `check_propagation` and the value did not show up on every
    /// authoritative server within `propagation_timeout_ms`.
    PropagationTimeout,
    /// The zone has no NS records (and no `Options.authoritative`).
    NoNameservers,
};

/// Publish the DNS-01 record for `domain` (the authorization's identifier)
/// and wait for it, as the `Solver` does. Public for a caller that drives the
/// challenge itself.
pub fn present(s: *Dns01Solver, domain: []const u8, token: []const u8, key_authorization: []const u8) Error!void {
    s.note = "";
    const value = acme.jws.dns01TxtValueFromKeyAuthorization(key_authorization);

    const p = try s.gpa.create(Pending);
    p.* = .{};
    var kept = false;
    defer if (!kept) s.destroyPending(p);
    p.domain = try s.gpa.dupe(u8, domain);
    p.value = try s.gpa.dupe(u8, &value);
    p.token = try s.gpa.dupe(u8, token);
    p.key_authorization = try s.gpa.dupe(u8, key_authorization);

    var r = s.recursive();
    defer r.deinit();

    var name_buf: [acme.Client.dns01_max_name_len]u8 = undefined;
    const name = s.options.override_name orelse acme.Client.dns01RecordName(&name_buf, domain);
    const fqdn = if (s.options.follow_cname) zone.followCname(&r, name, &p.fqdn_buf) catch |err| {
        s.note = if (err == error.ResolverFailed) "the resolver failed (SERVFAIL/REFUSED) following the CNAME chain" else "following the _acme-challenge CNAME chain failed";
        return err;
    } else try copyInto(&p.fqdn_buf, name);
    const zone_name = if (s.options.zone) |z| try copyInto(&p.zone_buf, z) else zone.findZone(&r, fqdn, &p.zone_buf) catch |err| {
        s.note = if (err == error.ResolverFailed) "the resolver failed (SERVFAIL/REFUSED) on the SOA walk" else "no zone (SOA) found for the challenge name";
        return err;
    };
    if (!inZone(fqdn, zone_name)) {
        // An override that does not contain the name (a CNAME target in
        // another zone, a typo): the server would refuse with NOTZONE.
        s.note = "the challenge name is not inside Options.zone";
        return error.ZoneNotFound;
    }

    p.record = .{
        .domain = p.domain,
        .fqdn = fqdn,
        .zone = zone_name,
        .value = p.value,
        .token = p.token,
        .key_authorization = p.key_authorization,
    };
    // Room in the list BEFORE publishing: once the record is out there it
    // must be remembered, or nothing would ever remove it.
    try s.pending.ensureUnusedCapacity(s.gpa, 1);
    s.options.publisher.present(s.options.publisher.ctx, &p.record) catch |err| {
        s.note = "the publisher failed";
        // The update may have been applied before the failure showed (a lost
        // reply, a read error after the endpoint acted): remove it, best
        // effort, as lego cleans up after a failed Present. Publishers treat
        // removing an absent record as a no-op.
        s.options.publisher.cleanup(s.options.publisher.ctx, &p.record);
        return err;
    };
    s.pending.appendAssumeCapacity(p);
    kept = true;

    // The client calls cleanup only after a successful present, so a wait
    // that fails cleans up after itself.
    if (s.options.check_propagation) {
        s.waitPropagation(&r, p.record.fqdn, p.record.zone, p.value) catch |err| {
            s.cleanup(domain, &value);
            return err;
        };
    }
    if (s.options.delay_ms != 0) sleepMs(s.io, s.options.delay_ms) catch |err| {
        s.cleanup(domain, &value);
        return err;
    };
}

/// Remove what `present` published for (`domain`, `value`). Unknown pairs
/// are ignored.
pub fn cleanup(s: *Dns01Solver, domain: []const u8, value: []const u8) void {
    for (s.pending.items, 0..) |p, i| {
        if (!zone.eqlName(p.domain, domain) or !std.mem.eql(u8, p.value, value)) continue;
        s.options.publisher.cleanup(s.options.publisher.ctx, &p.record);
        _ = s.pending.orderedRemove(i);
        s.destroyPending(p);
        return;
    }
}

/// How many published records await their cleanup.
pub fn pendingCount(s: *const Dns01Solver) usize {
    return s.pending.items.len;
}

fn destroyPending(s: *Dns01Solver, p: *Pending) void {
    s.gpa.free(p.domain);
    s.gpa.free(p.value);
    s.gpa.free(p.token);
    std.crypto.secureZero(u8, p.key_authorization);
    s.gpa.free(p.key_authorization);
    s.gpa.destroy(p);
}

fn recursive(s: *Dns01Solver) dns.Resolver {
    return dns.Resolver.init(s.io, s.gpa, .{
        .servers = s.options.resolvers,
        .port = s.options.port,
        .timeout_ms = s.options.query_timeout_ms,
        .use_hosts = true,
        .use_search = false,
    });
}

/// Poll every authoritative server until all of them answer with `value`.
fn waitPropagation(s: *Dns01Solver, r: *dns.Resolver, fqdn: []const u8, zone_name: []const u8, value: []const u8) Error!void {
    var servers: std.ArrayList([]netaddr.Ip) = .empty;
    defer {
        for (servers.items) |ips| s.gpa.free(ips);
        servers.deinit(s.gpa);
    }
    var names: [][]u8 = &.{};
    defer zone.freeNames(s.gpa, names);
    if (s.options.authoritative.len != 0) {
        for (s.options.authoritative) |ip| try servers.append(s.gpa, try s.gpa.dupe(netaddr.Ip, &.{ip}));
    } else {
        names = zone.nameservers(r, s.gpa, zone_name) catch |err| {
            s.note = "looking up the zone's NS records failed";
            return err;
        };
        if (names.len == 0) {
            s.note = "the zone has no NS records";
            return error.NoNameservers;
        }
    }

    const start = std.Io.Clock.awake.now(s.io);
    while (true) {
        const auth_ok = if (names.len != 0)
            try s.namedServersHave(r, names, fqdn, value)
        else
            try s.allServersHave(servers.items, fqdn, value);
        if (auth_ok and try s.resolversHave(fqdn, value)) return;
        const elapsed: u64 = @intCast(@max(0, start.durationTo(std.Io.Clock.awake.now(s.io)).toMilliseconds()));
        if (elapsed >= s.options.propagation_timeout_ms) {
            s.note = "the TXT record did not reach every authoritative server in time";
            return error.PropagationTimeout;
        }
        try sleepMs(s.io, @min(s.options.propagation_interval_ms, s.options.propagation_timeout_ms - elapsed));
    }
}

/// Each server (a list of its addresses) must answer with the value from at
/// least one of its addresses; an address that does not answer at all is
/// skipped for the next one. With `require_all_authoritative` off, one
/// server answering is enough.
fn allServersHave(s: *Dns01Solver, servers: []const []netaddr.Ip, fqdn: []const u8, value: []const u8) Error!bool {
    var any = false;
    for (servers) |ips| {
        const has = try s.anyAddressHas(ips, fqdn, value, false);
        if (has) any = true;
        if (!has and s.options.require_all_authoritative) return false;
    }
    return any;
}

/// `allServersHave` over the zone's NS names, their addresses resolved on
/// every pass: a name whose lookup fails counts as "not yet" (lego: the
/// pre-check fails and is retried), never as absent — dropping it would let
/// the check pass without the server the CA may ask. A name with no address
/// at all (NODATA) cannot be asked by the CA either and is left out.
fn namedServersHave(s: *Dns01Solver, r: *dns.Resolver, names: []const []u8, fqdn: []const u8, value: []const u8) Error!bool {
    var any = false;
    var asked = false;
    for (names) |ns| {
        const ips = (try zone.nameserverIps(r, s.gpa, ns)) orelse {
            if (s.options.require_all_authoritative) return false;
            continue;
        };
        defer s.gpa.free(ips);
        if (ips.len == 0) continue;
        asked = true;
        const has = try s.anyAddressHas(ips, fqdn, value, false);
        if (has) any = true;
        if (!has and s.options.require_all_authoritative) return false;
    }
    return asked and any;
}

/// With `check_resolvers`: every configured recursive resolver (or the
/// system's, when none is configured) answers with the value.
fn resolversHave(s: *Dns01Solver, fqdn: []const u8, value: []const u8) Error!bool {
    if (!s.options.check_resolvers) return true;
    if (s.options.resolvers.len == 0) {
        var r = s.recursive();
        defer r.deinit();
        var msg = r.query(fqdn, .txt) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => return false,
        };
        defer msg.deinit();
        return zone.txtPresent(&msg, fqdn, value);
    }
    for (s.options.resolvers) |ip| {
        if (!try s.anyAddressHas(&.{ip}, fqdn, value, true)) return false;
    }
    return true;
}

fn anyAddressHas(s: *Dns01Solver, ips: []const netaddr.Ip, fqdn: []const u8, value: []const u8, recursive_query: bool) Error!bool {
    for (ips) |ip| {
        return zone.serverHasTxtRd(s.io, s.gpa, ip, s.options.port, s.options.query_timeout_ms, fqdn, value, recursive_query) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => continue,
        };
    }
    return false;
}

fn sleepMs(io: std.Io, ms: u64) error{Canceled}!void {
    const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(@intCast(ms)), .clock = .awake };
    d.sleep(io) catch return error.Canceled;
}

/// `name` is `zone_name` or under it (label boundary, case-insensitive).
fn inZone(name: []const u8, zone_name: []const u8) bool {
    if (zone_name.len == 0) return true;
    if (name.len == zone_name.len) return std.ascii.eqlIgnoreCase(name, zone_name);
    if (name.len < zone_name.len + 1) return false;
    const tail = name[name.len - zone_name.len ..];
    return name[name.len - zone_name.len - 1] == '.' and std.ascii.eqlIgnoreCase(tail, zone_name);
}

fn copyInto(out: *[zone.max_name_len]u8, name: []const u8) error{NameTooLong}![]const u8 {
    const n = zone.trimDot(name);
    if (n.len > out.len) return error.NameTooLong;
    @memcpy(out[0..n.len], n);
    return out[0..n.len];
}

// SPDX-License-Identifier: MIT

//! `zig build interop-acmedns -- --scratch DIR --dns-port N --http-port N
//! --exec PATH`, run by `tools/interop.sh`: `acmedns` against live peers.
//! `zig build interop-acmedns -- --real-api URL --real-dns N --scratch DIR`, run by
//! `tools/real_acmedns.sh`: the `AcmeDns` publisher, its account `Store` and the solver
//! against the real joohoi/acme-dns server (see `realAcmeDns`).
//!
//! 1. The DNS questions (`zone.zig`) against an authoritative server with
//!    two zones (`tools/peer.py`, built on `dns`'s `update_server.py`): the
//!    SOA walk, a CNAME delegation into the other zone, a CNAME loop, the NS
//!    lookup.
//! 2. Real issuance from Pebble, whose validation authority resolves through
//!    that same server (`-dnsserver`), once per publisher: RFC 2136 + TSIG
//!    (a wildcard and its base at one name), a CNAME-delegated name, acme-dns
//!    (a registered account, CNAME to its fulldomain), httpreq (default and
//!    RAW), exec (a script running BIND's `nsupdate`) — plus a wrong TSIG
//!    secret and a publisher that never publishes (propagation timeout),
//!    which must both fail before the CA is asked to validate. After each,
//!    nothing may be left pending and the TXT record must be gone.

const std = @import("std");
const acme = @import("acme");
const acmedns = @import("acmedns");
const dns = @import("dns");
const http = @import("http");
const netaddr = @import("netaddr");

const loopback: netaddr.Ip = .{ .v4 = .{ 127, 0, 0, 1 } };

var failures: usize = 0;

fn check(ok: bool, comptime fmt: []const u8, args: anytype) void {
    std.debug.print("{s}: " ++ fmt ++ "\n", .{if (ok) "ok  " else "FAIL"} ++ args);
    if (!ok) failures += 1;
}

const Noop = struct {
    fn publisher() acmedns.Publisher {
        return .{ .present = present, .cleanup = cleanup };
    }
    fn present(_: ?*anyopaque, _: *const acmedns.Record) acmedns.PublishError!void {}
    fn cleanup(_: ?*anyopaque, _: *const acmedns.Record) void {}
};

/// The real acme-dns server (joohoi/acme-dns, Go, MIT; started by `tools/real_acmedns.sh` with its
/// own DNS listener for `auth.delegated.test` at `dns_port`): the account registered through
/// `AcmeDns.Store`, the update the publisher sends, what the server's DNS then answers (the two newest
/// values are kept, as acme-dns does), a refused key or subdomain, the account file round trip and the
/// solver end to end (propagation checked against the server's own DNS listener).
fn realAcmeDns(io: std.Io, gpa: std.mem.Allocator, api: []const u8, dns_port: u16, scratch: []const u8) !void {
    const zone_name = "auth.delegated.test";
    var store = acmedns.AcmeDns.Store.init(gpa);
    defer store.deinit();
    const acct = store.register(io, "real.example.org", api, .{}, &.{}) catch |err| {
        check(false, "register against the real server: {t}", .{err});
        return;
    };
    check(std.mem.endsWith(u8, acct.fulldomain, "." ++ zone_name) and acct.username.len != 0 and acct.password.len != 0, "register: an account with fulldomain {s}", .{acct.fulldomain});

    var pub_ = acmedns.AcmeDns.init(io, gpa, .{ .server_url = api, .accounts = store.accounts() });
    defer pub_.deinit();
    const p = pub_.publisher();
    const v1 = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    const v2 = "Z9YqZKXkq1f0b2n3c4d5e6f7g8h9i0j1k2l3m4n5o6p";
    const v3 = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";
    const rec = struct {
        fn of(a: acmedns.AcmeDns.Account, v: []const u8) acmedns.Record {
            return .{ .domain = a.domain, .fqdn = a.fulldomain, .zone = zone_name, .value = v, .token = "t", .key_authorization = "t.k" };
        }
    }.of;
    var has: [3]bool = undefined;
    const ask = struct {
        fn all(i: std.Io, g: std.mem.Allocator, port: u16, fqdn: []const u8, out: *[3]bool) !void {
            for ([3][]const u8{ v1, v2, v3 }, out) |v, *o| o.* = try acmedns.zone.serverHasTxt(i, g, loopback, port, 2000, fqdn, v);
        }
    }.all;
    p.present(p.ctx, &rec(acct, v1)) catch |err| check(false, "update 1: {t} ({s})", .{ err, pub_.note });
    try ask(io, gpa, dns_port, acct.fulldomain, &has);
    check(pub_.last_status == 200 and has[0] and !has[1], "update 1: HTTP {d}, the server's DNS answers the value", .{pub_.last_status});
    p.present(p.ctx, &rec(acct, v2)) catch |err| check(false, "update 2: {t}", .{err});
    p.present(p.ctx, &rec(acct, v3)) catch |err| check(false, "update 3: {t}", .{err});
    try ask(io, gpa, dns_port, acct.fulldomain, &has);
    check(!has[0] and has[1] and has[2], "three updates leave the two newest values (acme-dns keeps two)", .{});

    // A wrong key and a subdomain that is not the account's are refused by the server.
    var bad = acct;
    bad.password = "not-the-password";
    var pub_bad = acmedns.AcmeDns.init(io, gpa, .{ .server_url = api, .accounts = &.{bad} });
    defer pub_bad.deinit();
    const pb = pub_bad.publisher();
    check(if (pb.present(pb.ctx, &rec(bad, v1))) |_| false else |e| e == error.PublishFailed, "a wrong API key is refused (HTTP {d}: {s})", .{ pub_bad.last_status, pub_bad.note });
    check(pub_bad.last_status == 401, "... with 401", .{});
    var other = acct;
    other.subdomain = "00000000-0000-4000-8000-000000000000";
    var pub_sub = acmedns.AcmeDns.init(io, gpa, .{ .server_url = api, .accounts = &.{other} });
    defer pub_sub.deinit();
    const ps = pub_sub.publisher();
    check(if (ps.present(ps.ctx, &rec(other, v1))) |_| false else |e| e == error.PublishFailed, "another account's subdomain is refused (HTTP {d})", .{pub_sub.last_status});

    // The account file: written at mode 0600, read back, and the read-back account still publishes.
    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, scratch, .{});
    defer dir.close(io);
    try store.save(io, dir, "acme-dns-accounts.json");
    var back = try acmedns.AcmeDns.Store.load(io, gpa, dir, "acme-dns-accounts.json");
    defer back.deinit();
    const again = back.find("real.example.org");
    check(again != null and std.mem.eql(u8, again.?.password, acct.password) and std.mem.eql(u8, again.?.fulldomain, acct.fulldomain), "the account file round-trips", .{});

    // The solver end to end: the value is published through acme-dns and the check asks the
    // server's own DNS listener until it answers with it.
    var solver = acmedns.Dns01Solver.init(io, gpa, .{
        .publisher = p,
        .follow_cname = false,
        .override_name = acct.fulldomain,
        .zone = zone_name,
        .port = dns_port,
        .authoritative = &.{loopback},
        .query_timeout_ms = 1000,
        .propagation_timeout_ms = 10_000,
        .propagation_interval_ms = 200,
    });
    defer solver.deinit();
    const key_auth = "tok.thumb";
    solver.present("real.example.org", "tok", key_auth) catch |err| {
        check(false, "solver.present: {t} ({s})", .{ err, solver.note });
        return;
    };
    const val = acme.jws.dns01TxtValueFromKeyAuthorization(key_auth);
    const seen = try acmedns.zone.serverHasTxt(io, gpa, loopback, dns_port, 2000, acct.fulldomain, &val);
    check(seen and solver.pendingCount() == 1, "the solver published and waited for the value", .{});
    solver.cleanup("real.example.org", &val);
    check(solver.pendingCount() == 0, "cleanup leaves nothing pending (acme-dns has no delete)", .{});
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    // The environment the exec publisher's child inherits comes from here:
    // `Io.Threaded` spawns with its own `environ`, empty unless passed.
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var scratch: []const u8 = "";
    var dns_port: u16 = 0;
    var http_port: u16 = 0;
    var exec_path: []const u8 = "";
    var real_api: []const u8 = "";
    var real_dns: u16 = 0;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--scratch")) scratch = args.next() orelse return 2;
        if (std.mem.eql(u8, a, "--dns-port")) dns_port = std.fmt.parseInt(u16, args.next() orelse return 2, 10) catch return 2;
        if (std.mem.eql(u8, a, "--http-port")) http_port = std.fmt.parseInt(u16, args.next() orelse return 2, 10) catch return 2;
        if (std.mem.eql(u8, a, "--exec")) exec_path = args.next() orelse return 2;
        if (std.mem.eql(u8, a, "--real-api")) real_api = args.next() orelse return 2;
        if (std.mem.eql(u8, a, "--real-dns")) real_dns = std.fmt.parseInt(u16, args.next() orelse return 2, 10) catch return 2;
    }
    if (real_api.len != 0) {
        if (real_dns == 0 or scratch.len == 0) {
            std.debug.print("usage: interop-acmedns --real-api URL --real-dns PORT --scratch DIR (run by tools/real_acmedns.sh)\n", .{});
            return 2;
        }
        try realAcmeDns(io, gpa, real_api, real_dns, scratch);
        std.debug.print("real acme-dns interop: {d} failure(s)\n", .{failures});
        return if (failures == 0) 0 else 1;
    }
    if (scratch.len == 0 or dns_port == 0 or http_port == 0 or exec_path.len == 0) {
        std.debug.print("usage: interop-acmedns --scratch DIR --dns-port N --http-port N --exec PATH (run by tools/interop.sh)\n", .{});
        return 2;
    }

    var secret: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hmac-sha256.key.", &secret, .{});
    const key: dns.tsig.Key = .{ .name = "hmac-sha256.key.", .secret = &secret };

    // ── 1. the DNS questions ────────────────────────────────────────────────
    var r = dns.Resolver.init(io, gpa, .{
        .servers = &.{loopback},
        .port = dns_port,
        .timeout_ms = 2000,
        .use_hosts = false,
        .use_search = false,
    });
    defer r.deinit();

    try setup(io, gpa, dns_port, &key, &.{
        .{ "_acme-challenge.cname.example.org", "_acme-challenge.target.delegated.test" },
        .{ "loop1.example.org", "loop2.example.org" },
        .{ "loop2.example.org", "loop1.example.org" },
        .{ "_acme-challenge.override.example.org", "_acme-challenge.ovr.delegated.test" },
    });
    var buf: [acmedns.zone.max_name_len]u8 = undefined;
    {
        const z = acmedns.zone.findZone(&r, "_acme-challenge.www.example.org", &buf);
        check(if (z) |v| std.mem.eql(u8, v, "example.org") else |_| false, "findZone(_acme-challenge.www.example.org) = example.org", .{});
        const z2 = acmedns.zone.findZone(&r, "x.y.auth.delegated.test.", &buf);
        check(if (z2) |v| std.mem.eql(u8, v, "delegated.test") else |_| false, "findZone(x.y.auth.delegated.test.) = delegated.test", .{});
        // The peer is authoritative only and REFUSEs a name outside its zones;
        // since the 2026-10-16 review findZone reads that as "could not find
        // out" (ResolverFailed), never as "no zone" -- a recursive resolver's
        // NXDOMAIN is what yields ZoneNotFound (the solver path: src/solver_test.zig).
        check(acmedns.zone.findZone(&r, "nothing.invalid", &buf) == error.ResolverFailed, "findZone(nothing.invalid) under a REFUSED = ResolverFailed", .{});
        const c = acmedns.zone.followCname(&r, "_acme-challenge.cname.example.org", &buf);
        check(if (c) |v| std.mem.eql(u8, v, "_acme-challenge.target.delegated.test") else |_| false, "followCname across zones", .{});
        const p = acmedns.zone.followCname(&r, "plain.example.org", &buf);
        check(if (p) |v| std.mem.eql(u8, v, "plain.example.org") else |_| false, "followCname of a name with no CNAME is the name", .{});
        check(acmedns.zone.followCname(&r, "loop1.example.org", &buf) == error.CnameLoop, "followCname loop = CnameLoop", .{});
        const ns = try acmedns.zone.nameservers(&r, gpa, "example.org");
        defer acmedns.zone.freeNames(gpa, ns);
        check(ns.len == 1 and std.mem.eql(u8, ns[0], "ns1.example.org"), "nameservers(example.org) = ns1.example.org", .{});
    }

    // ── 2. issuance from Pebble ─────────────────────────────────────────────
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var ca: http.Client.CaBundle = .{ .scanned = true };
    defer ca.deinit(gpa);
    try ca.bundle.addCertsFromFilePathAbsolute(gpa, io, std.Io.Clock.real.now(io), try std.mem.print(&path_buf, "{s}/ca.pem", .{scratch}));
    var transport = http.Client.init(io, gpa, .{ .shared_ca = &ca });
    defer transport.deinit();

    var url_buf: [64]u8 = undefined;
    const api = try std.mem.print(&url_buf, "http://127.0.0.1:{d}", .{http_port});
    var raw_buf: [64]u8 = undefined;
    const raw_api = try std.mem.print(&raw_buf, "http://127.0.0.1:{d}/raw", .{http_port});

    // acme-dns: register, then delegate the challenge name to the account.
    var reg = try acmedns.AcmeDns.register(io, gpa, api, .{}, &.{});
    defer reg.deinit();
    try setup(io, gpa, dns_port, &key, &.{.{ "_acme-challenge.acmedns.example.org", reg.value.fulldomain }});

    var rfc2136 = acmedns.Rfc2136.init(io, gpa, .{ .server = loopback, .port = dns_port, .key = &key });
    const wrong: dns.tsig.Key = .{ .name = "hmac-sha256.key.", .secret = "not the secret" };
    var rfc2136_bad = acmedns.Rfc2136.init(io, gpa, .{ .server = loopback, .port = dns_port, .key = &wrong });
    var acme_dns = acmedns.AcmeDns.init(io, gpa, .{ .server_url = api, .accounts = &.{.{
        .domain = "acmedns.example.org",
        .username = reg.value.username,
        .password = reg.value.password,
        .subdomain = reg.value.subdomain,
        .fulldomain = reg.value.fulldomain,
    }} });
    defer acme_dns.deinit();
    var httpreq = acmedns.HttpReq.init(io, gpa, .{ .endpoint = api, .username = "httpreq", .password = "httpreq-pass" });
    defer httpreq.deinit();
    var httpreq_raw = acmedns.HttpReq.init(io, gpa, .{ .endpoint = raw_api, .mode = .raw, .username = "httpreq", .password = "httpreq-pass" });
    defer httpreq_raw.deinit();
    var exec = acmedns.Exec.init(io, gpa, .{ .program = exec_path });

    const Expect = enum { issued, publish_failed };
    const Scenario = struct {
        name: []const u8,
        domains: []const []const u8,
        publisher: acmedns.Publisher,
        expect: Expect,
        /// Where the TXT record lands (checked gone afterwards); "" = skip
        /// (acme-dns keeps its two newest values by design).
        fqdn: []const u8,
        timeout_ms: u32 = 20_000,
        override_name: ?[]const u8 = null,
        check_resolvers: bool = false,
        /// Non-empty: ask these instead of the zone's NS records.
        authoritative: []const netaddr.Ip = &.{},
        require_all: bool = true,
    };
    // 127.0.0.2 runs nothing: a second "authoritative server" that never answers.
    const two: []const netaddr.Ip = &.{ loopback, .{ .v4 = .{ 127, 0, 0, 2 } } };
    const scenarios = [_]Scenario{
        .{ .name = "rfc2136-wildcard+base", .domains = &.{ "example.org", "*.example.org" }, .publisher = rfc2136.publisher(), .expect = .issued, .fqdn = "_acme-challenge.example.org" },
        .{ .name = "rfc2136-cname-delegation", .domains = &.{"cname.example.org"}, .publisher = rfc2136.publisher(), .expect = .issued, .fqdn = "_acme-challenge.target.delegated.test" },
        .{ .name = "acme-dns", .domains = &.{"acmedns.example.org"}, .publisher = acme_dns.publisher(), .expect = .issued, .fqdn = "" },
        .{ .name = "httpreq", .domains = &.{"httpreq.example.org"}, .publisher = httpreq.publisher(), .expect = .issued, .fqdn = "_acme-challenge.httpreq.example.org" },
        .{ .name = "httpreq-raw", .domains = &.{"raw.example.org"}, .publisher = httpreq_raw.publisher(), .expect = .issued, .fqdn = "_acme-challenge.raw.example.org" },
        .{ .name = "exec-nsupdate", .domains = &.{"exec.example.org"}, .publisher = exec.publisher(), .expect = .issued, .fqdn = "_acme-challenge.exec.example.org" },
        .{ .name = "override-name+check-resolvers", .domains = &.{"override.example.org"}, .publisher = rfc2136.publisher(), .expect = .issued, .fqdn = "_acme-challenge.ovr.delegated.test", .override_name = "_acme-challenge.ovr.delegated.test", .check_resolvers = true },
        .{ .name = "one-of-two-authoritative", .domains = &.{"one.example.org"}, .publisher = rfc2136.publisher(), .expect = .issued, .fqdn = "_acme-challenge.one.example.org", .authoritative = two, .require_all = false },
        .{ .name = "all-of-two-authoritative", .domains = &.{"all.example.org"}, .publisher = rfc2136.publisher(), .expect = .publish_failed, .fqdn = "_acme-challenge.all.example.org", .authoritative = two, .timeout_ms = 1500 },
        .{ .name = "rfc2136-wrong-secret", .domains = &.{"badkey.example.org"}, .publisher = rfc2136_bad.publisher(), .expect = .publish_failed, .fqdn = "_acme-challenge.badkey.example.org" },
        .{ .name = "never-propagates", .domains = &.{"silent.example.org"}, .publisher = Noop.publisher(), .expect = .publish_failed, .fqdn = "_acme-challenge.silent.example.org", .timeout_ms = 1500 },
    };

    for (scenarios, 0..) |sc, i| {
        var ec_key: acme.jws.KeyPair = undefined;
        try acme.jws.Es256.KeyPair.generateDeterministicInto(&ec_key, &@as([32]u8, @splat(@intCast(0x60 + i))));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&ec_key));

        var solver = acmedns.Dns01Solver.init(io, gpa, .{
            .publisher = sc.publisher,
            .resolvers = &.{loopback},
            .port = dns_port,
            .query_timeout_ms = 1000,
            .propagation_timeout_ms = sc.timeout_ms,
            .propagation_interval_ms = 200,
            .override_name = sc.override_name,
            .check_resolvers = sc.check_resolvers,
            .authoritative = sc.authoritative,
            .require_all_authoritative = sc.require_all,
        });
        defer solver.deinit();
        var client = acme.Client.init(io, gpa, &transport, &ec_key, .{
            .directory_url = "https://localhost:14000/dir",
            .challenge_type = .dns_01,
            .solvers = &.{solver.solver()},
            .contact = &.{"mailto:interop@acmedns.test"},
            .poll_interval_ms = 200,
            .max_polls = 100,
        });
        defer client.deinit();

        const got: Expect = if (client.obtain(sc.domains)) |cert_const| blk: {
            var cert = cert_const;
            defer cert.deinit(gpa);
            check(std.mem.startsWith(u8, cert.chain_pem, "-----BEGIN CERTIFICATE-----"), "{s}: a PEM chain came back", .{sc.name});
            break :blk .issued;
        } else |err| switch (err) {
            error.DnsPublishFailed => .publish_failed,
            else => {
                check(false, "{s}: {t} (problem: {s}; solver: {s})", .{ sc.name, err, client.lastProblem() orelse "-", solver.note });
                continue;
            },
        };
        check(got == sc.expect, "{s}: {t} (want {t}){s}{s}", .{ sc.name, got, sc.expect, if (solver.note.len != 0) " -- solver: " else "", solver.note });
        check(solver.pendingCount() == 0, "{s}: nothing left pending", .{sc.name});
        if (sc.fqdn.len != 0) {
            const left = acmedns.zone.serverHasTxtAny(io, gpa, loopback, dns_port, 1000, sc.fqdn) catch true;
            check(!left, "{s}: no TXT left at {s}", .{ sc.name, sc.fqdn });
        }
    }
    if (exec.stderr_len != 0) std.debug.print("exec stderr: {s}\n", .{exec.lastStderr()});
    check(std.mem.find(u8, rfc2136_bad.note, "BADSIG") != null, "wrong secret is reported as BADSIG: \"{s}\"", .{rfc2136_bad.note});

    std.debug.print("acmedns interop: {d} failure(s)\n", .{failures});
    return if (failures == 0) 0 else 1;
}

/// Create CNAME records (owner, target) with a signed RFC 2136 update.
fn setup(io: std.Io, gpa: std.mem.Allocator, port: u16, key: *const dns.tsig.Key, cnames: []const [2][]const u8) !void {
    var buf: [2048]u8 = undefined;
    var b = try dns.update.Builder.init(&buf, if (std.mem.endsWith(u8, cnames[0][0], ".delegated.test")) "delegated.test" else "example.org");
    var rd: [256]u8 = undefined;
    for (cnames) |c| {
        var w: std.Io.Writer = .fixed(&rd);
        try dns.message.writeName(&w, c[1]);
        try b.add(c[0], .cname, 60, w.buffered());
    }
    var r = dns.Resolver.init(io, gpa, .{ .servers = &.{loopback}, .port = port, .use_hosts = false, .use_search = false });
    defer r.deinit();
    const rcode = try dns.update.send(&r, loopback, &b, .{ .key = key });
    if (rcode != .no_error) return error.SetupRefused;
}

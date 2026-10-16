// SPDX-License-Identifier: MIT

//! `zig build interop-acmedns -- --scratch DIR --dns-port N --http-port N
//! --exec PATH`, run by `tools/interop.sh`: `acmedns` against live peers.
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
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--scratch")) scratch = args.next() orelse return 2;
        if (std.mem.eql(u8, a, "--dns-port")) dns_port = std.fmt.parseInt(u16, args.next() orelse return 2, 10) catch return 2;
        if (std.mem.eql(u8, a, "--http-port")) http_port = std.fmt.parseInt(u16, args.next() orelse return 2, 10) catch return 2;
        if (std.mem.eql(u8, a, "--exec")) exec_path = args.next() orelse return 2;
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
        check(acmedns.zone.findZone(&r, "nothing.invalid", &buf) == error.ZoneNotFound, "findZone(nothing.invalid) = ZoneNotFound", .{});
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
    try ca.bundle.addCertsFromFilePathAbsolute(gpa, io, std.Io.Clock.real.now(io), try std.fmt.bufPrint(&path_buf, "{s}/ca.pem", .{scratch}));
    var transport = http.Client.init(io, gpa, .{ .shared_ca = &ca });
    defer transport.deinit();

    var url_buf: [64]u8 = undefined;
    const api = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{http_port});
    var raw_buf: [64]u8 = undefined;
    const raw_api = try std.fmt.bufPrint(&raw_buf, "http://127.0.0.1:{d}/raw", .{http_port});

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
    check(std.mem.indexOf(u8, rfc2136_bad.note, "BADSIG") != null, "wrong secret is reported as BADSIG: \"{s}\"", .{rfc2136_bad.note});

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

// SPDX-License-Identifier: MIT

//! The acme client against Pebble (Let's Encrypt's ACME test CA, run by
//! `tools/pebble.sh`, which starts Pebble, pebble-challtestsrv and the
//! recording proxy first and then this program). Every scenario runs the
//! real `Client` through `https://localhost:14001/dir` -- the proxy in front
//! of Pebble -- with Pebble's own validation authority checking each
//! challenge over the loopback:
//!
//!   http01             one name, HTTP-01 served by this program on :5002
//!   http01-san         two names in one order
//!   dns01-wildcard     `*.w.test` over DNS-01, TXT set in challtestsrv
//!   tlsalpn01          TLS-ALPN-01: the proxy's TLS listener on :5001 serves
//!                      the validation certificate this program hands out on
//!                      :5003 (the client's `TlsAlpnResponder`)
//!   http01-unreachable a name whose A record points where nobody listens:
//!                      must end `AuthorizationFailed` (negative control --
//!                      Pebble really validates)
//!   rejected           a name on Pebble's block list: must end `AcmeProblem`
//!   lifecycle          one account through the calls beyond issuance
//!                      (2026-10-16): the `shortlived` profile (leaf lifetime
//!                      checked), ARI `renewalInfo`, a renewal with
//!                      `replaces`, revocation by account and by certificate
//!                      key, contact update, key rollover ES256 → ES384 and an
//!                      order with the new key, the alternate chain to
//!                      Pebble's second root (`preferred_chain`), deactivation
//!                      (an order afterwards must be refused)
//!
//! Pebble requires external account binding (`pebble.sh`), so every account
//! in every scenario is EAB-bound (RFC 8555 §7.3.4).
//! A successful chain must verify up to Pebble's root (`/roots/0`) and name
//! every ordered domain. Pebble runs with `-strict` and rejects 5% of nonces,
//! so `badNonce` retries happen in nearly every run (~60 POSTs). Not more: the
//! client gives up after four rejections in a row, which at 15% failed about
//! one run in thirty (2026-10-08). THIS IS A PROGRAM, NOT A TEST:
//! `zig build check-interop` compiles it; `tools/pebble.sh` runs it.

const std = @import("std");
const acme = @import("acme");
const http = @import("http");
const router = @import("router");

const Scratch = struct { path: []const u8 };

var current: ?*acme.Client = null;

fn challengeHandler(req: *http.Server.Request, res: *http.Server.ResponseWriter) anyerror!void {
    const prefix = acme.Client.Responder.path_prefix;
    var buf: [512]u8 = undefined;
    if (current) |c| if (std.mem.startsWith(u8, req.target, prefix)) {
        if (c.challengeResponder().lookup(req.target[prefix.len..], &buf)) |ka| {
            res.setStatus(200);
            try res.setHeader("Content-Type", "application/octet-stream");
            return res.writeAll(ka);
        }
    };
    res.setStatus(404);
    try res.writeAll("no such token");
}

fn materialHandler(req: *http.Server.Request, res: *http.Server.ResponseWriter) anyerror!void {
    const gpa = std.heap.smp_allocator;
    const prefix = "/alpn/";
    if (current) |c| if (std.mem.startsWith(u8, req.target, prefix)) {
        if (try c.tlsAlpnResponder().getMaterial(gpa, req.target[prefix.len..])) |m_const| {
            var m = m_const;
            defer m.deinit(gpa);
            res.setStatus(200);
            try res.writeAll(m.cert_der);
            try res.writeAll("\n--KEY--\n");
            return res.writeAll(m.key_pem);
        }
    };
    res.setStatus(404);
    try res.writeAll("no material");
}

const Mgmt = struct {
    http_client: *http.Client,

    fn post(m: Mgmt, path: []const u8, body: []const u8) bool {
        var url_buf: [128]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "http://127.0.0.1:8055{s}", .{path}) catch return false;
        var res = m.http_client.request(.post, url, .{ .body = body }) catch return false;
        defer res.deinit();
        return res.status == 200;
    }

    fn present(ctx: ?*anyopaque, name: []const u8, value: []const u8) bool {
        const m: *Mgmt = @ptrCast(@alignCast(ctx.?));
        var buf: [512]u8 = undefined;
        const body = std.fmt.bufPrint(&buf, "{{\"host\":\"{s}.\",\"value\":\"{s}\"}}", .{ name, value }) catch return false;
        return m.post("/set-txt", body);
    }

    fn cleanup(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
        _ = value;
        const m: *Mgmt = @ptrCast(@alignCast(ctx.?));
        var buf: [512]u8 = undefined;
        const body = std.fmt.bufPrint(&buf, "{{\"host\":\"{s}.\"}}", .{name}) catch return;
        _ = m.post("/clear-txt", body);
    }
};

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

/// Each PEM certificate of `chain` signs the one before it, the last is
/// signed by `root`, and the leaf names every domain.
fn verifyChain(gpa: std.mem.Allocator, chain: []const u8, root_pem: []const u8, domains: []const []const u8, now: i64) !void {
    var ders: std.ArrayList([]u8) = .empty;
    defer {
        for (ders.items) |d| gpa.free(d);
        ders.deinit(gpa);
    }
    const begin = "-----BEGIN CERTIFICATE-----";
    var rest = chain;
    while (std.mem.indexOf(u8, rest, begin)) |at| {
        const end_marker = "-----END CERTIFICATE-----";
        const end = (std.mem.indexOfPos(u8, rest, at, end_marker) orelse return error.BadPem) + end_marker.len;
        try ders.append(gpa, try acme.x509.pemDecode(gpa, "CERTIFICATE", rest[at..end]));
        rest = rest[end..];
    }
    if (ders.items.len < 2) return error.ChainTooShort;
    const root_der = try acme.x509.pemDecode(gpa, "CERTIFICATE", root_pem);
    defer gpa.free(root_der);
    const Cert = std.crypto.Certificate;
    for (ders.items, 0..) |der, i| {
        const subject = try (Cert{ .buffer = der, .index = 0 }).parse();
        const issuer_der = if (i + 1 < ders.items.len) ders.items[i + 1] else root_der;
        const issuer = try (Cert{ .buffer = issuer_der, .index = 0 }).parse();
        try subject.verify(issuer, now);
        if (i == 0) for (domains) |d| try subject.verifyHostName(d);
    }
}

fn mark(http_client: *http.Client, name: []const u8) !void {
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:14001/__scenario/{s}", .{name});
    var res = try http_client.request(.get, url, .{});
    res.deinit();
}

/// Pebble's `externalAccountMACKeys` entry in `pebble.sh` (kid → base64url key).
const eab_kid = "kid-interop";
const eab_key_b64 = "6t6Lq0SIHxWzWdIjFJ2jUnAnvT4h3JBqL7eMwRRqFNE";

/// Pebble's `shortlived` profile in `pebble.sh`: 6 days.
const shortlived_s = 518400;

fn step(failures: *usize, name: []const u8, ok: bool, c: *acme.Client) void {
    if (!ok) failures.* += 1;
    std.debug.print("lifecycle/{s}: {s}{s}{s}\n", .{
        name,                                        if (ok) "OK" else "FAIL",
        if (c.lastProblem() != null) " -- " else "", c.lastProblem() orelse "",
    });
}

/// The `lifecycle` scenario; returns the number of failed steps.
fn lifecycle(
    gpa: std.mem.Allocator,
    io: std.Io,
    transport: *http.Client,
    eab_key: []const u8,
    root_pem: []const u8,
    alt_root_pem: []const u8,
) !usize {
    var failures: usize = 0;
    const now = std.Io.Clock.real.now(io).toSeconds();
    const names: []const []const u8 = &.{"l.test"};

    var account_key: acme.jws.KeyPair = undefined;
    try acme.jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(0x60)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var client = acme.Client.init(io, gpa, transport, &account_key, .{
        .directory_url = "https://localhost:14001/dir",
        .eab = .{ .kid = eab_kid, .hmac_key = eab_key },
        .contact = &.{"mailto:interop@acme.test"},
        .poll_interval_ms = 200,
        .max_polls = 100,
    });
    defer client.deinit();
    current = &client;
    defer current = null;

    // The profile: offered, ordered, and the leaf really is short-lived.
    const offered = try client.profiles();
    var has_short = false;
    for (offered) |pf| has_short = has_short or std.mem.eql(u8, pf.name, "shortlived");
    step(&failures, "profiles-advertised", has_short, &client);
    var first = try client.obtainWith(names, .{ .profile = "shortlived" });
    defer first.deinit(gpa);
    const life: i64 = @as(i64, @intCast(first.not_after)) - now;
    step(&failures, "shortlived-issued", (verifyChain(gpa, first.chain_pem, root_pem, names, now) catch null) != null and
        life > 0 and life <= shortlived_s + 3600, &client);

    // ARI for it, then the renewal that names it.
    const first_der = try acme.x509.pemDecode(gpa, "CERTIFICATE", first.chain_pem);
    defer gpa.free(first_der);
    if (client.renewalInfo(first_der)) |info_const| {
        var info = info_const;
        defer info.deinit(gpa);
        step(&failures, "renewal-info", info.window_start < info.window_end and
            info.window_end <= @as(i64, @intCast(first.not_after)), &client);
    } else |err| {
        std.debug.print("renewalInfo: {t}\n", .{err});
        step(&failures, "renewal-info", false, &client);
    }
    const cert_id = try acme.x509.ariCertId(gpa, first_der);
    defer gpa.free(cert_id);
    var second = try client.obtainWith(names, .{ .replaces = cert_id });
    defer second.deinit(gpa);
    step(&failures, "renewal-replaces", (verifyChain(gpa, second.chain_pem, root_pem, names, now) catch null) != null, &client);

    // Revocation: the replaced one by the account, the renewal by its own key.
    step(&failures, "revoke-by-account", if (client.revoke(first_der, .superseded)) true else |_| false, &client);
    const second_der = try acme.x509.pemDecode(gpa, "CERTIFICATE", second.chain_pem);
    defer gpa.free(second_der);
    var cert_key: acme.jws.AnyKeyPair = undefined;
    try acme.x509.privateKeyFromPem(&cert_key, gpa, second.key_pem);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cert_key));
    step(&failures, "revoke-by-cert-key", if (client.revokeWithCertKey(second_der, &cert_key, null)) true else |_| false, &client);

    step(&failures, "update-contact", if (client.updateContact(&.{"mailto:other@acme.test"})) true else |_| false, &client);

    // Rollover to ES384; the next order is signed with the new key.
    var new_key: acme.jws.Es384.KeyPair = undefined;
    try acme.jws.Es384.KeyPair.generateDeterministicInto(&new_key, &@as([48]u8, @splat(0x61)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&new_key));
    step(&failures, "rollover-es384", if (client.rolloverKey(&new_key)) true else |_| false, &client);
    var third = try client.obtainWith(names, .{});
    defer third.deinit(gpa);
    step(&failures, "order-after-rollover", (verifyChain(gpa, third.chain_pem, root_pem, names, now) catch null) != null, &client);

    // The alternate chain up to Pebble's second root, picked by its CN.
    const alt_root_der = try acme.x509.pemDecode(gpa, "CERTIFICATE", alt_root_pem);
    defer gpa.free(alt_root_der);
    const alt_root = try (std.crypto.Certificate{ .buffer = alt_root_der, .index = 0 }).parse();
    var alt = try client.obtainWith(names, .{ .preferred_chain = alt_root.commonName() });
    defer alt.deinit(gpa);
    step(&failures, "preferred-chain", (verifyChain(gpa, alt.chain_pem, alt_root_pem, names, now) catch null) != null, &client);

    // Deactivated: the CA must refuse the account afterwards.
    step(&failures, "deactivate", if (client.deactivate()) true else |_| false, &client);
    const refused = if (client.obtain(names)) |cert_const| blk: {
        var cert = cert_const;
        cert.deinit(gpa);
        break :blk false;
    } else |err| err == error.AcmeProblem;
    step(&failures, "refused-after-deactivate", refused, &client);
    return failures;
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var scratch: []const u8 = "";
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--scratch")) scratch = args.next() orelse return 2;
    }
    if (scratch.len == 0) {
        std.debug.print("usage: interop-acme --scratch DIR (run by tools/pebble.sh)\n", .{});
        return 2;
    }
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const now_ts = std.Io.Clock.real.now(io);

    // Trust only the throwaway CA pebble.sh made for the proxy and Pebble.
    var ca: http.Client.CaBundle = .{ .scanned = true };
    defer ca.deinit(gpa);
    try ca.bundle.addCertsFromFilePathAbsolute(gpa, io, now_ts, try std.fmt.bufPrint(&path_buf, "{s}/ca.pem", .{scratch}));
    var transport = http.Client.init(io, gpa, .{ .shared_ca = &ca });
    defer transport.deinit();

    const root_pem = try std.Io.Dir.cwd().readFileAlloc(io, try std.fmt.bufPrint(&path_buf, "{s}/pebble-root.pem", .{scratch}), gpa, .limited(1 << 16));
    defer gpa.free(root_pem);
    const alt_root_pem = try std.Io.Dir.cwd().readFileAlloc(io, try std.fmt.bufPrint(&path_buf, "{s}/pebble-root-1.pem", .{scratch}), gpa, .limited(1 << 16));
    defer gpa.free(alt_root_pem);
    const eab_key = try acme.jws.base64UrlDecodeAlloc(gpa, eab_key_b64);
    defer {
        std.crypto.secureZero(u8, eab_key);
        gpa.free(eab_key);
    }

    // The two listeners Pebble's validation authority and the TLS-ALPN
    // listener reach: HTTP-01 on :5002, the validation material on :5003.
    var ch_server = http.Server.init(io, gpa, .{ .handler = challengeHandler, .port = 5002, .reuse_address = true });
    defer ch_server.deinit();
    try ch_server.bind();
    const ch_thread = try std.Thread.spawn(.{}, serveWrap, .{&ch_server});
    defer ch_thread.join();
    defer ch_server.shutdown();
    var mat_server = http.Server.init(io, gpa, .{ .handler = materialHandler, .port = 5003, .reuse_address = true });
    defer mat_server.deinit();
    try mat_server.bind();
    const mat_thread = try std.Thread.spawn(.{}, serveWrap, .{&mat_server});
    defer mat_thread.join();
    defer mat_server.shutdown();

    var mgmt: Mgmt = .{ .http_client = &transport };
    if (!mgmt.post("/add-a", "{\"host\":\"n.test.\",\"addresses\":[\"127.0.0.2\"]}")) {
        std.debug.print("challtestsrv: add-a failed\n", .{});
        return 1;
    }

    const Expect = enum { issued, authorization_failed, acme_problem };
    const Scenario = struct {
        name: []const u8,
        domains: []const []const u8,
        challenge: acme.Client.ChallengeType,
        expect: Expect,
    };
    const scenarios = [_]Scenario{
        .{ .name = "http01", .domains = &.{"a.test"}, .challenge = .http_01, .expect = .issued },
        .{ .name = "http01-san", .domains = &.{ "a.test", "b.test" }, .challenge = .http_01, .expect = .issued },
        .{ .name = "dns01-wildcard", .domains = &.{"*.w.test"}, .challenge = .dns_01, .expect = .issued },
        .{ .name = "tlsalpn01", .domains = &.{"t.test"}, .challenge = .tls_alpn_01, .expect = .issued },
        .{ .name = "http01-unreachable", .domains = &.{"n.test"}, .challenge = .http_01, .expect = .authorization_failed },
        .{ .name = "rejected", .domains = &.{"blocked.test"}, .challenge = .http_01, .expect = .acme_problem },
    };

    var failures: usize = 0;
    for (scenarios, 0..) |sc, i| {
        try mark(&transport, sc.name);
        var account_key: acme.jws.KeyPair = undefined;
        try acme.jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(@intCast(0x40 + i))));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
        var client = acme.Client.init(io, gpa, &transport, &account_key, .{
            .directory_url = "https://localhost:14001/dir",
            .challenge_type = sc.challenge,
            .dns_publisher = if (sc.challenge == .dns_01) .{ .ctx = &mgmt, .present = Mgmt.present, .cleanup = Mgmt.cleanup } else null,
            .eab = .{ .kid = eab_kid, .hmac_key = eab_key },
            .contact = &.{"mailto:interop@acme.test"},
            .poll_interval_ms = 200,
            .max_polls = 100,
        });
        defer client.deinit();
        current = &client;
        defer current = null;

        const got: Expect = if (client.obtain(sc.domains)) |cert_const| blk: {
            var cert = cert_const;
            defer cert.deinit(gpa);
            verifyChain(gpa, cert.chain_pem, root_pem, sc.domains, std.Io.Clock.real.now(io).toSeconds()) catch |err| {
                std.debug.print("{s}: issued, but the chain does not verify: {t}\n", .{ sc.name, err });
                failures += 1;
            };
            break :blk .issued;
        } else |err| switch (err) {
            error.AuthorizationFailed => .authorization_failed,
            error.AcmeProblem => .acme_problem,
            else => {
                std.debug.print("{s}: {t} (problem: {s})\n", .{ sc.name, err, client.lastProblem() orelse "-" });
                failures += 1;
                continue;
            },
        };
        if (got != sc.expect) failures += 1;
        std.debug.print("{s}: {s} {t} (want {t}){s}{s}\n", .{
            sc.name,                                          if (got == sc.expect) "OK  " else "FAIL",
            got,                                              sc.expect,
            if (client.lastProblem() != null) " -- " else "", client.lastProblem() orelse "",
        });
    }
    try mark(&transport, "lifecycle");
    const lifecycle_failures = lifecycle(gpa, io, &transport, eab_key, root_pem, alt_root_pem) catch |err| blk: {
        std.debug.print("lifecycle: aborted: {t}\n", .{err});
        break :blk 1;
    };
    try mark(&transport, "");
    std.debug.print("interop-acme: {d} of {d} scenarios as expected against Pebble, lifecycle {d} failed step(s)\n", .{
        scenarios.len - failures, scenarios.len, lifecycle_failures,
    });
    return if (failures == 0 and lifecycle_failures == 0) 0 else 1;
}

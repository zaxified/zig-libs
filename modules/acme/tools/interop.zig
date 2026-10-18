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
//!   rsa                an RS256 account key and an RSA-2048 certificate key
//!                      (2026-10-16)
//!   ip-http01          an IP identifier, 127.0.0.1, over HTTP-01 (RFC 8738)
//!   ip-tlsalpn01       the same IP over TLS-ALPN-01: Pebble's SNI is the
//!                      reverse name `1.0.0.127.in-addr.arpa` (RFC 8738 §6)
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
const netaddr = @import("netaddr");
const rsa = @import("rsa");

const Scratch = struct { path: []const u8 };

var current: ?*acme.Client = null;
/// The `manager` scenario's manager: its solvers publish into it, not into
/// the client's responders.
var current_manager: ?*acme.Manager = null;

fn challengeHandler(req: *http.Server.Request, res: *http.Server.ResponseWriter) anyerror!void {
    const prefix = acme.Client.Responder.path_prefix;
    var buf: [512]u8 = undefined;
    if (std.mem.startsWith(u8, req.target, prefix)) {
        const token = req.target[prefix.len..];
        const ka: ?[]const u8 = if (current_manager) |m|
            m.http_tokens.lookup(token, &buf)
        else if (current) |c|
            c.challengeResponder().lookup(token, &buf)
        else
            null;
        if (ka) |v| {
            res.setStatus(200);
            try res.setHeader("Content-Type", "application/octet-stream");
            return res.writeAll(v);
        }
    }
    res.setStatus(404);
    try res.writeAll("no such token");
}

fn materialHandler(req: *http.Server.Request, res: *http.Server.ResponseWriter) anyerror!void {
    const gpa = std.heap.smp_allocator;
    const prefix = "/alpn/";
    if (std.mem.startsWith(u8, req.target, prefix)) {
        const sni = req.target[prefix.len..];
        const found = if (current_manager) |m|
            try m.tlsAlpnMaterial(gpa, sni)
        else if (current) |c|
            try c.tlsAlpnResponder().getMaterial(gpa, sni)
        else
            null;
        if (found) |m_const| {
            var m = m_const;
            defer m.deinit(gpa);
            res.setStatus(200);
            try res.writeAll(m.cert_der);
            try res.writeAll("\n--KEY--\n");
            return res.writeAll(m.key_pem);
        }
    }
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
/// `verifyChain`, its error printed.
fn chainOk(gpa: std.mem.Allocator, chain: []const u8, root_pem: []const u8, domains: []const []const u8, now: i64) bool {
    verifyChain(gpa, chain, root_pem, domains, now) catch |err| {
        std.debug.print("chain does not verify: {t}\n", .{err});
        return false;
    };
    return true;
}

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
        if (i == 0) for (domains) |d| {
            if (netaddr.parseIp(d)) |ip| {
                // std checks dNSNames only: look for the iPAddress SAN bytes.
                const want: []const u8 = switch (ip) {
                    .v4 => |q| &q,
                    .v6 => |b| &b,
                };
                var tlv: [18]u8 = undefined;
                tlv[0] = 0x87;
                tlv[1] = @intCast(want.len);
                @memcpy(tlv[2..][0..want.len], want);
                if (std.mem.indexOf(u8, der, tlv[0 .. 2 + want.len]) == null) return error.NoIpSan;
            } else try subject.verifyHostName(d);
        };
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

fn step(scenario: []const u8, failures: *usize, name: []const u8, ok: bool, c: *acme.Client) void {
    if (!ok) failures.* += 1;
    std.debug.print("{s}/{s}: {s}{s}{s}\n", .{
        scenario,                  name,
        if (ok) "OK" else "FAIL",  if (c.lastProblem() != null) " -- " else "",
        c.lastProblem() orelse "",
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
    step("lifecycle", &failures, "profiles-advertised", has_short, &client);
    var first = try client.obtainWith(names, .{ .profile = "shortlived" });
    defer first.deinit(gpa);
    const life: i64 = @as(i64, @intCast(first.not_after)) - now;
    step("lifecycle", &failures, "shortlived-issued", chainOk(gpa, first.chain_pem, root_pem, names, std.Io.Clock.real.now(io).toSeconds()) and
        life > 0 and life <= shortlived_s + 3600, &client);

    // ARI for it, then the renewal that names it.
    const first_der = try acme.x509.pemDecode(gpa, "CERTIFICATE", first.chain_pem);
    defer gpa.free(first_der);
    if (client.renewalInfo(first_der)) |info_const| {
        var info = info_const;
        defer info.deinit(gpa);
        step("lifecycle", &failures, "renewal-info", info.window_start < info.window_end and
            info.window_end <= @as(i64, @intCast(first.not_after)), &client);
    } else |err| {
        std.debug.print("renewalInfo: {t}\n", .{err});
        step("lifecycle", &failures, "renewal-info", false, &client);
    }
    const cert_id = try acme.x509.ariCertId(gpa, first_der);
    defer gpa.free(cert_id);
    var second = try client.obtainWith(names, .{ .replaces = cert_id });
    defer second.deinit(gpa);
    step("lifecycle", &failures, "renewal-replaces", chainOk(gpa, second.chain_pem, root_pem, names, std.Io.Clock.real.now(io).toSeconds()), &client);

    // Revocation: the replaced one by the account, the renewal by its own key.
    step("lifecycle", &failures, "revoke-by-account", if (client.revoke(first_der, .superseded)) true else |_| false, &client);
    const second_der = try acme.x509.pemDecode(gpa, "CERTIFICATE", second.chain_pem);
    defer gpa.free(second_der);
    var cert_key: acme.jws.AnyKeyPair = undefined;
    try acme.x509.privateKeyFromPem(&cert_key, gpa, second.key_pem);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cert_key));
    step("lifecycle", &failures, "revoke-by-cert-key", if (client.revokeWithCertKey(second_der, &cert_key, null)) true else |_| false, &client);

    step("lifecycle", &failures, "update-contact", if (client.updateContact(&.{"mailto:other@acme.test"})) true else |_| false, &client);

    // Rollover to ES384; the next order is signed with the new key.
    var new_key: acme.jws.Es384.KeyPair = undefined;
    try acme.jws.Es384.KeyPair.generateDeterministicInto(&new_key, &@as([48]u8, @splat(0x61)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&new_key));
    step("lifecycle", &failures, "rollover-es384", if (client.rolloverKey(&new_key)) true else |_| false, &client);
    var third = try client.obtainWith(names, .{});
    defer third.deinit(gpa);
    step("lifecycle", &failures, "order-after-rollover", chainOk(gpa, third.chain_pem, root_pem, names, std.Io.Clock.real.now(io).toSeconds()), &client);

    // The alternate chain up to Pebble's second root, picked by its CN.
    const alt_root_der = try acme.x509.pemDecode(gpa, "CERTIFICATE", alt_root_pem);
    defer gpa.free(alt_root_der);
    const alt_root = try (std.crypto.Certificate{ .buffer = alt_root_der, .index = 0 }).parse();
    var alt = try client.obtainWith(names, .{ .preferred_chain = alt_root.commonName() });
    defer alt.deinit(gpa);
    step("lifecycle", &failures, "preferred-chain", chainOk(gpa, alt.chain_pem, alt_root_pem, names, std.Io.Clock.real.now(io).toSeconds()), &client);

    // Deactivated: the CA must refuse the account afterwards.
    step("lifecycle", &failures, "deactivate", if (client.deactivate()) true else |_| false, &client);
    const refused = if (client.obtain(names)) |cert_const| blk: {
        var cert = cert_const;
        cert.deinit(gpa);
        break :blk false;
    } else |err| err == error.AcmeProblem;
    step("lifecycle", &failures, "refused-after-deactivate", refused, &client);
    return failures;
}

/// HTTP-01 through a caller's `Solver` (serving from the client's own
/// responder, which the :5002 listener reads), counting its calls.
const CountingSolver = struct {
    presents: u32 = 0,
    cleanups: u32 = 0,

    fn solver(s: *CountingSolver) acme.Client.Solver {
        return .{ .ctx = s, .type = .http_01, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, req: *const acme.Client.ChallengeRequest) acme.Client.SolverError!void {
        const s: *CountingSolver = @ptrCast(@alignCast(ctx.?));
        s.presents += 1;
        try current.?.challengeResponder().set(req.token, req.key_authorization);
    }

    fn cleanup(ctx: ?*anyopaque, req: *const acme.Client.ChallengeRequest) void {
        const s: *CountingSolver = @ptrCast(@alignCast(ctx.?));
        s.cleanups += 1;
        current.?.challengeResponder().remove(req.token);
    }
};

/// The `steps` scenario: the order API one call at a time, HTTP-01 through a
/// caller's `Solver`, and an authorization deactivated; returns the number
/// of failed steps.
fn orderSteps(gpa: std.mem.Allocator, io: std.Io, transport: *http.Client, eab_key: []const u8, root_pem: []const u8) !usize {
    var failures: usize = 0;
    var account_key: acme.jws.KeyPair = undefined;
    try acme.jws.Es256.KeyPair.generateDeterministicInto(&account_key, &@as([32]u8, @splat(0x70)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    var cs: CountingSolver = .{};
    const solvers = [_]acme.Client.Solver{cs.solver()};
    var client = acme.Client.init(io, gpa, transport, &account_key, .{
        .directory_url = "https://localhost:14001/dir",
        .eab = .{ .kid = eab_kid, .hmac_key = eab_key },
        .solvers = &solvers,
        .poll_interval_ms = 200,
        .max_polls = 100,
    });
    defer client.deinit();
    current = &client;
    defer current = null;

    var order = try client.newOrder(&.{"s.test"}, .{});
    defer order.deinit();
    step("steps", &failures, "new-order", order.status == .pending and order.authorizations.len == 1 and
        order.identifiers.len == 1 and std.mem.eql(u8, order.identifiers[0], "s.test"), &client);
    var again = try client.fetchOrder(order.url);
    defer again.deinit();
    step("steps", &failures, "fetch-order", std.mem.eql(u8, again.authorizations[0], order.authorizations[0]) and
        std.mem.eql(u8, again.finalize, order.finalize), &client);
    var authz = try client.fetchAuthorization(order.authorizations[0]);
    defer authz.deinit();
    step("steps", &failures, "authorization", authz.status == .pending and !authz.ip and
        std.mem.eql(u8, authz.identifier, "s.test") and authz.challenge(.http_01) != null and
        authz.challenge(.dns_01) != null and authz.challenge(.tls_alpn_01) != null, &client);
    const solved = if (client.solveAuthorization(order.authorizations[0])) true else |_| false;
    step("steps", &failures, "custom-solver", solved and cs.presents == 1 and cs.cleanups == 1, &client);
    try client.waitOrder(&order, .ready);
    step("steps", &failures, "order-ready", order.status == .ready, &client);

    var cert_key: acme.jws.KeyPair = undefined;
    acme.jws.generateKeyPair(&cert_key, io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&cert_key));
    const csr = try acme.x509.csrDer(gpa, &cert_key, &.{"s.test"});
    defer gpa.free(csr);
    try client.finalize(&order, csr);
    try client.waitOrder(&order, .valid);
    var chain = try client.downloadChain(&order, null);
    defer chain.deinit(gpa);
    const now = std.Io.Clock.real.now(io).toSeconds();
    step("steps", &failures, "download-chain", order.status == .valid and
        chainOk(gpa, chain.chain_pem, root_pem, &.{"s.test"}, now), &client);

    var other = try client.newOrder(&.{"d.test"}, .{});
    defer other.deinit();
    step("steps", &failures, "deactivate-authorization", if (client.deactivateAuthorization(other.authorizations[0])) true else |_| false, &client);
    var gone = try client.fetchAuthorization(other.authorizations[0]);
    defer gone.deinit();
    step("steps", &failures, "deactivated", gone.status == .deactivated, &client);
    return failures;
}

/// The real clock plus an offset the `manager` scenario moves forward.
const ShiftedClock = struct {
    io: std.Io,
    offset: i64 = 0,
    fn clock(s: *ShiftedClock) acme.Manager.Clock {
        return .{ .ctx = s, .now = now };
    }
    fn now(ctx: ?*anyopaque) i64 {
        const s: *ShiftedClock = @ptrCast(@alignCast(ctx.?));
        return std.Io.Clock.real.now(s.io).toSeconds() + s.offset;
    }
};

const Events = struct {
    issued: u32 = 0,
    from_storage: u32 = 0,
    failed: u32 = 0,
    fn hook(e: *Events) acme.Manager.EventHook {
        return .{ .ctx = e, .call = call };
    }
    fn call(ctx: ?*anyopaque, ev: *const acme.Manager.Event) void {
        const e: *Events = @ptrCast(@alignCast(ctx.?));
        switch (ev.*) {
            .installed => |i| switch (i.source) {
                .issued => e.issued += 1,
                .storage => e.from_storage += 1,
            },
            .failed => |f| {
                e.failed += 1;
                std.debug.print("manager: failed: {s}\n", .{f.problem});
            },
            .storage_failed => {
                e.failed += 1;
                std.debug.print("manager: storing an issued certificate failed\n", .{});
            },
        }
    }
};

fn allowOdTest(ctx: ?*anyopaque, name: []const u8) bool {
    _ = ctx;
    return std.mem.eql(u8, name, "od.test");
}

fn mstep(failures: *usize, name: []const u8, ok: bool) void {
    if (!ok) failures.* += 1;
    std.debug.print("manager/{s}: {s}\n", .{ name, if (ok) "OK" else "FAIL" });
}

/// `clock` is read after the lookup: an on-demand certificate is issued by
/// it, and Pebble does not backdate notBefore.
fn servesVerified(gpa: std.mem.Allocator, m: *acme.Manager, sni: []const u8, root_pem: []const u8, names: []const []const u8, clock: *ShiftedClock) bool {
    var mat = (m.certificate(gpa, sni) catch return false) orelse return false;
    defer mat.deinit(gpa);
    return chainOk(gpa, mat.chain_pem, root_pem, names, ShiftedClock.now(clock));
}

/// The `manager` scenario (W5, 2026-10-16): the `Manager` over a real
/// `Client` and `DirStorage` — issue, ARI window, a renewal that names its
/// predecessor, a restart that serves from storage, TLS-ALPN-01 answered by
/// the manager, an on-demand issuance. Returns the number of failed steps.
fn managerScenario(gpa: std.mem.Allocator, io: std.Io, transport: *http.Client, eab_key: []const u8, root_pem: []const u8, scratch: []const u8) !usize {
    var failures: usize = 0;
    // A fresh storage directory per run (the scratch dir is .zig-cache).
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try std.fmt.bufPrint(&dir_buf, "{s}/manager-{d}", .{ scratch, std.Io.Clock.real.now(io).toSeconds() });
    try std.Io.Dir.cwd().createDir(io, dir_path, @fromBackingInt(@intCast(0o700)));
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);
    var ds = acme.DirStorage.init(io, dir);
    const root_der = try acme.x509.pemDecode(gpa, "CERTIFICATE", root_pem);
    defer gpa.free(root_der);
    var clock: ShiftedClock = .{ .io = io };
    var events: Events = .{};
    const names: []const []const u8 = &.{ "m.test", "m2.test" };

    var account_key: acme.jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
    try acme.Manager.loadOrCreateAccountKey(&account_key, io, gpa, ds.storage(), "pebble", .es256);

    {
        var m = acme.Manager.init(io, gpa, .{
            .storage = ds.storage(),
            .trust_anchors = &.{root_der},
            .on_event = events.hook(),
            .clock = clock.clock(),
        });
        defer m.deinit();
        current_manager = &m;
        defer current_manager = null;
        var client = acme.Client.init(io, gpa, transport, &account_key, .{
            .directory_url = "https://localhost:14001/dir",
            .eab = .{ .kid = eab_kid, .hmac_key = eab_key },
            .solvers = m.challengeSolvers(),
            .poll_interval_ms = 200,
            .max_polls = 100,
        });
        defer client.deinit();
        // Explicit profile: Pebble picks a RANDOM one for an order that names
        // none ("in true pebble chaos fashion", wfe.go), and a six-day
        // `shortlived` renewal is expired at the shifted clock (2026-10-17).
        var issuer: acme.Manager.AcmeIssuer = .{ .client = &client, .name = "pebble", .obtain = .{ .profile = "default" } };
        try m.addIssuer(issuer.issuer());
        try m.manage(names);

        const next = m.maintain();
        mstep(&failures, "issued", events.issued == 1 and events.failed == 0);
        mstep(&failures, "serves-verified", servesVerified(gpa, &m, "m2.test", root_pem, names, &clock));
        mstep(&failures, "stored", if (dir.statFile(io, "certificates/m.test.pem", .{})) |_| true else |_| false);
        // The ARI poll is due at once; Pebble answers with a window.
        mstep(&failures, "ari-due", next <= ShiftedClock.now(&clock));
        _ = m.maintain();
        const e = m.entries.items[0];
        mstep(&failures, "ari-window", e.ari_end > e.ari_start and e.renew_at >= e.ari_start and
            e.renew_at <= e.ari_end and e.ari_at != null);

        // Jump to the renewal time: renewed, naming its predecessor (Pebble
        // checks `replaces` against the account's certificates).
        // Compared by the chain itself: Pebble sets notAfter = notBefore +
        // validity in whole seconds, so a renewal within the same second as
        // the first issuance has the same not_after.
        const old_chain = try gpa.dupe(u8, e.cert.?.chain_pem);
        defer gpa.free(old_chain);
        clock.offset = e.renew_at - std.Io.Clock.real.now(io).toSeconds() + 1;
        _ = m.maintain();
        mstep(&failures, "renewed", events.issued == 2 and events.failed == 0 and
            !std.mem.eql(u8, m.entries.items[0].cert.?.chain_pem, old_chain));
        mstep(&failures, "renewed-verified", servesVerified(gpa, &m, "m.test", root_pem, names, &clock));
    }
    // Back to the real clock first: at the shifted one the fresh renewal can
    // already sit past its own (randomized) renewal point, and the restarted
    // manager, which has no issuer, then reports a failure that leaks into
    // the steps below (1 run in 3, 2026-10-17).
    clock.offset = 0;
    {
        // A restart: the renewed certificate comes from storage, no order.
        var m = acme.Manager.init(io, gpa, .{
            .storage = ds.storage(),
            .trust_anchors = &.{root_der},
            .on_event = events.hook(),
            .clock = clock.clock(),
        });
        defer m.deinit();
        try m.manage(names);
        _ = m.maintain();
        mstep(&failures, "restart-from-storage", events.from_storage == 1 and events.issued == 2);
    }
    {
        // TLS-ALPN-01 answered from the manager's store, and on-demand.
        var m = acme.Manager.init(io, gpa, .{
            .storage = ds.storage(),
            .trust_anchors = &.{root_der},
            .on_event = events.hook(),
            .on_demand = .{ .allow = allowOdTest },
        });
        defer m.deinit();
        current_manager = &m;
        defer current_manager = null;
        var client = acme.Client.init(io, gpa, transport, &account_key, .{
            .directory_url = "https://localhost:14001/dir",
            .eab = .{ .kid = eab_kid, .hmac_key = eab_key },
            .challenge_type = .tls_alpn_01,
            .solvers = m.challengeSolvers(),
            .poll_interval_ms = 200,
            .max_polls = 100,
        });
        defer client.deinit();
        // Explicit profile: Pebble picks a RANDOM one for an order that names
        // none ("in true pebble chaos fashion", wfe.go), and a six-day
        // `shortlived` renewal is expired at the shifted clock (2026-10-17).
        var issuer: acme.Manager.AcmeIssuer = .{ .client = &client, .name = "pebble", .obtain = .{ .profile = "default" } };
        try m.addIssuer(issuer.issuer());
        try m.manage(&.{"mt.test"});
        _ = m.maintain();
        mstep(&failures, "tlsalpn01-issued", events.issued == 3 and events.failed == 0);
        mstep(&failures, "tlsalpn01-verified", servesVerified(gpa, &m, "mt.test", root_pem, &.{"mt.test"}, &clock));
        mstep(&failures, "on-demand", servesVerified(gpa, &m, "od.test", root_pem, &.{"od.test"}, &clock) and events.issued == 4);
        mstep(&failures, "on-demand-refused", (m.certificate(gpa, "other.test") catch null) == null and events.issued == 4);
    }
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
        rsa: bool = false,
    };
    const scenarios = [_]Scenario{
        .{ .name = "http01", .domains = &.{"a.test"}, .challenge = .http_01, .expect = .issued },
        .{ .name = "http01-san", .domains = &.{ "a.test", "b.test" }, .challenge = .http_01, .expect = .issued },
        .{ .name = "dns01-wildcard", .domains = &.{"*.w.test"}, .challenge = .dns_01, .expect = .issued },
        .{ .name = "tlsalpn01", .domains = &.{"t.test"}, .challenge = .tls_alpn_01, .expect = .issued },
        .{ .name = "http01-unreachable", .domains = &.{"n.test"}, .challenge = .http_01, .expect = .authorization_failed },
        .{ .name = "rejected", .domains = &.{"blocked.test"}, .challenge = .http_01, .expect = .acme_problem },
        .{ .name = "rsa", .domains = &.{"r.test"}, .challenge = .http_01, .expect = .issued, .rsa = true },
        .{ .name = "ip-http01", .domains = &.{"127.0.0.1"}, .challenge = .http_01, .expect = .issued },
        .{ .name = "ip-tlsalpn01", .domains = &.{"127.0.0.1"}, .challenge = .tls_alpn_01, .expect = .issued },
    };

    var failures: usize = 0;
    for (scenarios, 0..) |sc, i| {
        try mark(&transport, sc.name);
        var ec_key: acme.jws.KeyPair = undefined;
        try acme.jws.Es256.KeyPair.generateDeterministicInto(&ec_key, &@as([32]u8, @splat(@intCast(0x40 + i))));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&ec_key));
        const rsa_key = try gpa.create(rsa.KeyPair);
        defer {
            std.crypto.secureZero(u8, std.mem.asBytes(rsa_key));
            gpa.destroy(rsa_key);
        }
        var account_key: acme.jws.AnyKeyPair = undefined;
        if (sc.rsa) {
            try acme.jws.generateRsaKeyPair(rsa_key, 2048, io);
            account_key = .{ .rs256 = rsa_key };
        } else account_key = .{ .es256 = ec_key };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&account_key));
        var client = acme.Client.init(io, gpa, &transport, &account_key, .{
            .cert_key_alg = if (sc.rsa) .rs256 else .es256,
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
    try mark(&transport, "steps");
    const steps_failures = orderSteps(gpa, io, &transport, eab_key, root_pem) catch |err| blk: {
        std.debug.print("steps: aborted: {t}\n", .{err});
        break :blk 1;
    };
    try mark(&transport, "manager");
    const manager_failures = managerScenario(gpa, io, &transport, eab_key, root_pem, scratch) catch |err| blk: {
        std.debug.print("manager: aborted: {t}\n", .{err});
        break :blk 1;
    };
    try mark(&transport, "");
    std.debug.print("interop-acme: {d} of {d} scenarios as expected against Pebble, lifecycle {d} failed step(s), steps {d} failed step(s), manager {d} failed step(s)\n", .{
        scenarios.len - failures, scenarios.len, lifecycle_failures, steps_failures, manager_failures,
    });
    return if (failures == 0 and lifecycle_failures == 0 and steps_failures == 0 and manager_failures == 0) 0 else 1;
}

// SPDX-License-Identifier: MIT

//! `Options.ocsp`: the Manager keeps an OCSP staple per certificate. A signing mock CA (signing_ca_test.zig) issues
//! leaves that name an OCSP responder and answers for them through a mock transport, so every staple here is a
//! really verified response; the clock is injected, so every schedule is exact.

const std = @import("std");
const ocspcache = @import("ocspcache");
const Manager = @import("Manager.zig");
const storage = @import("storage.zig");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");
const signing_ca = @import("signing_ca_test.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;
const day = std.time.s_per_day;
const day0: i64 = 1767225600; // 2026-01-01T00:00:00Z

const names: []const []const u8 = &.{"a.example"};

const Clock = struct {
    t: i64,
    fn clock(c: *Clock) Manager.Clock {
        return .{ .ctx = c, .now = now };
    }
    fn now(ctx: ?*anyopaque) i64 {
        const c: *Clock = @ptrCast(@alignCast(ctx.?));
        return c.t;
    }
};

/// Issues a leaf for a fresh deterministic key under the signing CA.
const Issuer = struct {
    ca: *signing_ca.SigningCa,
    calls: u8 = 0,
    /// The issuer offers an ARI window (a far-future one), polled every `window_retry_s`.
    with_ari: bool = false,
    window_retry_s: u64 = 700,
    window_calls: usize = 0,

    fn issuer(i: *Issuer) Manager.Issuer {
        return .{ .ctx = i, .name = "sign", .issue = issue, .renewal_window = if (i.with_ari) window else null };
    }

    fn window(ctx: *anyopaque, chain_pem: []const u8, diag: *Manager.Diagnostics) Manager.IssueError!Manager.Window {
        _ = chain_pem;
        _ = diag;
        const i: *Issuer = @ptrCast(@alignCast(ctx));
        i.window_calls += 1;
        return .{ .start = day0 + 80 * day, .end = day0 + 81 * day, .retry_after_s = i.window_retry_s };
    }

    fn issue(ctx: *anyopaque, gpa: Allocator, req: *const Manager.IssueRequest, diag: *Manager.Diagnostics) Manager.IssueError!Manager.Issued {
        _ = diag;
        const i: *Issuer = @ptrCast(@alignCast(ctx));
        i.calls += 1;
        var key: jws.KeyPair = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        jws.Es256.KeyPair.generateDeterministicInto(&key, &@as([32]u8, @splat(40 + i.calls))) catch return error.IssueFailed;
        const csr = x509.csrDer(gpa, &key, req.names) catch return error.IssueFailed;
        defer gpa.free(csr);
        const chain = i.ca.issue(gpa, csr, day0, day0 + 90 * day) catch return error.IssueFailed;
        errdefer gpa.free(chain);
        const key_pem = x509.ecPrivateKeyToPem(gpa, &key) catch return error.IssueFailed;
        return .{ .chain_pem = chain, .key_pem = key_pem, .not_after = 0 };
    }
};

/// The responder: answers for the CA's latest leaf.
const Responder = struct {
    ca: *signing_ca.SigningCa,
    clock: *Clock,
    mode: enum { good, revoked, down } = .good,
    calls: usize = 0,
    /// Seconds from `thisUpdate` (the clock) to `nextUpdate`.
    validity: i64 = 7 * day,

    fn transport(r: *Responder) ocspcache.Transport {
        return .{ .context = r, .fetchFn = fetch };
    }

    fn fetch(ctx: *anyopaque, gpa: Allocator, req: ocspcache.FetchRequest) ocspcache.FetchError!ocspcache.FetchResponse {
        const r: *Responder = @ptrCast(@alignCast(ctx));
        r.calls += 1;
        if (r.mode == .down) return error.TransportFailed;
        std.testing.expectEqualStrings("http://ocsp.test/", req.url) catch return error.TransportFailed;
        const status: signing_ca.OcspStatus = switch (r.mode) {
            .revoked => .{ .revoked = r.clock.t - 60 },
            else => .good,
        };
        const body = signing_ca.ocspResponse(r.ca, gpa, r.ca.last_serial, status, r.clock.t - 60, r.clock.t + r.validity) catch return error.OutOfMemory;
        return .{ .status = 200, .body = body };
    }
};

/// The adapter the README shows: `ocspcache` does the discovery, the fetch, the verification and reports `nextUpdate`.
const CacheStapler = struct {
    transport: ocspcache.Transport,

    fn stapler(c: *CacheStapler) Manager.Stapler {
        return .{ .ctx = c, .refresh = refresh };
    }

    fn untilOf(cache: *ocspcache.Cache, gpa: Allocator, leaf: []const u8, now: i64) ?struct { der: []u8, until: i64 } {
        const list = cache.exportEntries(gpa, now) catch return null;
        defer ocspcache.Cache.freeExported(gpa, list);
        const key = ocspcache.Cache.subjectKey(leaf);
        for (list) |x| if (std.mem.eql(u8, &x.subject_key, &key)) {
            const der = gpa.dupe(u8, x.response_der) catch return null;
            return .{ .der = der, .until = x.next_update_unix };
        };
        return null;
    }

    fn refresh(ctx: ?*anyopaque, gpa: Allocator, leaf: []const u8, issuer: []const u8, previous: ?[]const u8, now: i64) Manager.StapleResult {
        const c: *CacheStapler = @ptrCast(@alignCast(ctx.?));
        const url = ocspcache.discoverResponderUrl(leaf) catch null;
        if (url == null) return .none;
        var cache = ocspcache.Cache.init(gpa, c.transport, .{});
        defer cache.deinit();
        var imported = false;
        if (previous) |p| imported = if (cache.importStaple(leaf, issuer, p, now)) true else |_| false;
        var fetched = false;
        if (cache.needsRefresh(leaf, now)) {
            cache.refresh(leaf, issuer, now) catch |err| {
                if (err == error.CertRevoked) return .revoked;
                var keep: ?i64 = null;
                if (imported) if (untilOf(&cache, gpa, leaf, now)) |k| {
                    gpa.free(k.der);
                    keep = k.until;
                };
                return .{ .failed = .{ .problem = @errorName(err), .keep_until = keep } };
            };
            fetched = true;
        }
        const k = untilOf(&cache, gpa, leaf, now) orelse return .{ .failed = .{ .problem = "OutOfMemory" } };
        if (fetched) return .{ .staple = .{ .der = k.der, .until = k.until } };
        gpa.free(k.der);
        return .{ .keep = k.until };
    }
};

const Events = struct {
    stapled: usize = 0,
    revoked: usize = 0,
    failed: usize = 0,
    installed: usize = 0,
    fn hook(e: *Events) Manager.EventHook {
        return .{ .ctx = e, .call = call };
    }
    fn call(ctx: ?*anyopaque, ev: *const Manager.Event) void {
        const e: *Events = @ptrCast(@alignCast(ctx.?));
        switch (ev.*) {
            .installed => e.installed += 1,
            .ocsp => |o| switch (o.kind) {
                .stapled => e.stapled += 1,
                .revoked => e.revoked += 1,
                .failed => e.failed += 1,
            },
            else => {},
        }
    }
};

const Lab = struct {
    threaded: std.Io.Threaded,
    mem: storage.MemStorage,
    clock: Clock,
    ca: signing_ca.SigningCa,
    issuer: Issuer,
    responder: Responder,
    cache_stapler: CacheStapler,
    events: Events = .{},

    fn init(l: *Lab, with_url: bool) !void {
        l.threaded = std.Io.Threaded.init(testing.allocator, .{});
        l.mem = storage.MemStorage.init(testing.allocator);
        l.clock = .{ .t = day0 + day };
        l.ca = try signing_ca.SigningCa.init(testing.allocator, 7, 1735689600, 2051222400);
        if (with_url) l.ca.ocsp_url = "http://ocsp.test/";
        l.issuer = .{ .ca = &l.ca };
        l.responder = .{ .ca = &l.ca, .clock = &l.clock };
        l.cache_stapler = .{ .transport = l.responder.transport() };
        l.events = .{};
    }

    fn deinit(l: *Lab) void {
        l.ca.deinit(testing.allocator);
        l.mem.deinit();
        l.threaded.deinit();
    }

    fn manager(l: *Lab) !Manager {
        var m = try Manager.init(l.threaded.io(), testing.allocator, .{
            .storage = l.mem.storage(),
            .clock = l.clock.clock(),
            .on_event = l.events.hook(),
            .random_seed = 3,
            .node_id = "node-a",
            .use_ari = false,
            .ocsp = .{ .stapler = l.cache_stapler.stapler() },
        });
        errdefer m.deinit();
        try m.addIssuer(l.issuer.issuer());
        try m.manage(names);
        return m;
    }

    /// The staple the manager hands out now (caller frees), null when none.
    fn staple(l: *Lab, m: *Manager) !?[]u8 {
        _ = l;
        var mat = (try m.certificate(testing.allocator, "a.example")) orelse return error.NoCertificate;
        defer mat.deinit(testing.allocator);
        const s = mat.ocsp_staple orelse return null;
        return try testing.allocator.dupe(u8, s);
    }
};

test "ocsp: a staple is fetched after issuance, kept without a request while fresh, refreshed ahead of nextUpdate" {
    var l: Lab = undefined;
    try l.init(true);
    defer l.deinit();
    var m = try l.manager();
    defer m.deinit();

    _ = m.maintain(); // issues
    try testing.expectEqual(@as(usize, 1), l.events.installed);
    try testing.expectEqual(@as(usize, 0), l.responder.calls);
    _ = m.maintain(); // the first OCSP check
    try testing.expectEqual(@as(usize, 1), l.responder.calls);
    try testing.expectEqual(@as(usize, 1), l.events.stapled);
    const s1 = (try l.staple(&m)).?;
    defer testing.allocator.free(s1);
    try testing.expect(s1.len > 100 and s1[0] == 0x30);

    // An hour later: checked, but the staple is far from its nextUpdate: no request.
    l.clock.t += 3600;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 1), l.responder.calls);
    try testing.expectEqual(@as(usize, 1), l.events.stapled);

    // 6.6 days on, inside the 12 h refresh margin: a new response.
    l.clock.t += 6 * day + 14 * 3600;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 2), l.responder.calls);
    try testing.expectEqual(@as(usize, 2), l.events.stapled);
    const s2 = (try l.staple(&m)).?;
    defer testing.allocator.free(s2);
    try testing.expect(!std.mem.eql(u8, s1, s2));
}

test "ocsp: a failing responder keeps the old staple until its nextUpdate, then none; recovery restores it" {
    var l: Lab = undefined;
    try l.init(true);
    defer l.deinit();
    var m = try l.manager();
    defer m.deinit();
    _ = m.maintain();
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 1), l.events.stapled);
    const first_expiry = l.clock.t + l.responder.validity;

    l.responder.mode = .down;
    l.clock.t += 6 * day + 14 * 3600; // inside the margin: a fetch is attempted and fails
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 2), l.responder.calls);
    try testing.expectEqual(@as(usize, 1), l.events.failed);
    if (try l.staple(&m)) |s| testing.allocator.free(s) else return error.StapleLost;

    // Past nextUpdate nothing stale is handed out, even though the entry still holds it.
    l.clock.t = first_expiry + 1;
    try testing.expect((try l.staple(&m)) == null);

    l.responder.mode = .good;
    l.clock.t += 7200;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 2), l.events.stapled);
    if (try l.staple(&m)) |s| testing.allocator.free(s) else return error.StapleNotRestored;
}

test "ocsp: a revoked answer drops the staple and renews the certificate at once" {
    var l: Lab = undefined;
    try l.init(true);
    defer l.deinit();
    var m = try l.manager();
    defer m.deinit();
    _ = m.maintain();
    l.responder.mode = .revoked;
    _ = m.maintain(); // the check says revoked
    try testing.expectEqual(@as(usize, 1), l.events.revoked);
    try testing.expectEqual(@as(usize, 0), l.events.stapled);
    try testing.expect((try l.staple(&m)) == null);
    try testing.expectEqual(@as(u8, 1), l.issuer.calls);

    l.responder.mode = .good;
    _ = m.maintain(); // the replacement
    try testing.expectEqual(@as(u8, 2), l.issuer.calls);
    try testing.expectEqual(@as(usize, 2), l.events.installed);
    _ = m.maintain(); // and its staple
    try testing.expectEqual(@as(usize, 1), l.events.stapled);
    if (try l.staple(&m)) |s| testing.allocator.free(s) else return error.StapleMissing;
}

test "ocsp: a certificate whose leaf names no responder is left alone; Options.ocsp unset never calls out" {
    var l: Lab = undefined;
    try l.init(false);
    defer l.deinit();
    var m = try l.manager();
    defer m.deinit();
    _ = m.maintain();
    _ = m.maintain();
    l.clock.t += 2 * day;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 0), l.responder.calls);
    try testing.expectEqual(@as(usize, 0), l.events.stapled + l.events.failed);
    try testing.expect((try l.staple(&m)) == null);
}

test "ocsp: after a restart the staple comes from storage without a request" {
    var l: Lab = undefined;
    try l.init(true);
    defer l.deinit();
    {
        var m = try l.manager();
        defer m.deinit();
        _ = m.maintain();
        _ = m.maintain();
        try testing.expectEqual(@as(usize, 1), l.responder.calls);
    }
    l.responder.mode = .down; // a request would fail
    var m2 = try l.manager();
    defer m2.deinit();
    _ = m2.maintain(); // loads the certificate from storage
    _ = m2.maintain(); // imports the stored staple, verifies it, keeps it
    try testing.expectEqual(@as(usize, 1), l.responder.calls);
    if (try l.staple(&m2)) |s| testing.allocator.free(s) else return error.StapleNotRestored;
}

// ── delta mutation run 2026-11-25: the schedule and the bookkeeping of the OCSP checks ──

/// A stapler that answers as scripted and records its calls, so the Manager's own
/// scheduling and bookkeeping can be pinned exactly (`CacheStapler` above is the real adapter).
const Script = struct {
    mode: enum { staple, keep, none, revoked, fail, fail_keep } = .staple,
    until_s: i64 = 100000,
    calls: usize = 0,
    last_previous_null: bool = true,
    /// Call `unmanage` on this manager from inside the check (the name is removed while it runs).
    mgr: ?*Manager = null,

    fn stapler(s: *Script) Manager.Stapler {
        return .{ .ctx = s, .refresh = refresh };
    }

    fn refresh(ctx: ?*anyopaque, gpa: Allocator, leaf: []const u8, issuer: []const u8, previous: ?[]const u8, now: i64) Manager.StapleResult {
        _ = leaf;
        _ = issuer;
        const s: *Script = @ptrCast(@alignCast(ctx.?));
        s.calls += 1;
        s.last_previous_null = previous == null;
        if (s.mgr) |m| _ = m.unmanage("a.example");
        return switch (s.mode) {
            .staple => .{ .staple = .{ .der = gpa.dupe(u8, "STAPLE") catch return .none, .until = now + s.until_s } },
            .keep => .{ .keep = now + s.until_s },
            .none => .none,
            .revoked => .revoked,
            .fail => .{ .failed = .{ .problem = "scripted" } },
            .fail_keep => .{ .failed = .{ .problem = "scripted", .keep_until = now + s.until_s } },
        };
    }
};

fn scriptedManager(l: *Lab, s: *Script, interval_s: u32, with_ari: bool) !Manager {
    l.issuer.with_ari = with_ari;
    var m = try Manager.init(l.threaded.io(), testing.allocator, .{
        .storage = l.mem.storage(),
        .clock = l.clock.clock(),
        .on_event = l.events.hook(),
        .random_seed = 3,
        .node_id = "node-a",
        .use_ari = with_ari,
        .ocsp = .{ .stapler = s.stapler(), .interval_s = interval_s },
    });
    errdefer m.deinit();
    try m.addIssuer(l.issuer.issuer());
    try m.manage(names);
    return m;
}

test "mutation 2026-11-25: the next OCSP check: after a staple or a keep one interval (at least 60 s), after a failure a tenth of it (at least 60 s), after none never" {
    // staple: interval 100; the check is not made before it is due and is made when it is.
    {
        var l: Lab = undefined;
        try l.init(true);
        defer l.deinit();
        var s: Script = .{ .mode = .staple };
        var m = try scriptedManager(&l, &s, 100, false);
        defer m.deinit();
        _ = m.maintain(); // issues
        const t0 = l.clock.t;
        try testing.expectEqual(t0 + 100, m.maintain());
        try testing.expectEqual(@as(usize, 1), s.calls);
        l.clock.t = t0 + 99;
        try testing.expectEqual(t0 + 100, m.maintain());
        try testing.expectEqual(@as(usize, 1), s.calls);
        l.clock.t = t0 + 100;
        try testing.expectEqual(t0 + 200, m.maintain());
        try testing.expectEqual(@as(usize, 2), s.calls);
    }
    // keep: interval 1000.
    {
        var l: Lab = undefined;
        try l.init(true);
        defer l.deinit();
        var s: Script = .{ .mode = .keep };
        var m = try scriptedManager(&l, &s, 1000, false);
        defer m.deinit();
        _ = m.maintain();
        const t0 = l.clock.t;
        try testing.expectEqual(t0 + 1000, m.maintain());
    }
    // failure: a tenth of the interval, but at least a minute.
    inline for (.{ .{ 100, 60 }, .{ 1000, 100 } }) |c| {
        var l: Lab = undefined;
        try l.init(true);
        defer l.deinit();
        var s: Script = .{ .mode = .fail };
        var m = try scriptedManager(&l, &s, c[0], false);
        defer m.deinit();
        _ = m.maintain();
        const t0 = l.clock.t;
        try testing.expectEqual(t0 + c[1], m.maintain());
        try testing.expectEqual(@as(usize, 1), l.events.failed);
    }
    // none: nothing to staple, never asked again.
    {
        var l: Lab = undefined;
        try l.init(true);
        defer l.deinit();
        var s: Script = .{ .mode = .none };
        var m = try scriptedManager(&l, &s, 100, false);
        defer m.deinit();
        _ = m.maintain();
        const t0 = l.clock.t;
        try testing.expect(m.maintain() > t0 + day);
        l.clock.t = t0 + 500;
        try testing.expect(m.maintain() > t0 + day);
        try testing.expectEqual(@as(usize, 1), s.calls);
    }
    // a chain without an issuer: the stapler is not asked, and not asked again.
    {
        var l: Lab = undefined;
        try l.init(true);
        defer l.deinit();
        var s: Script = .{ .mode = .staple };
        var m = try scriptedManager(&l, &s, 100, false);
        defer m.deinit();
        _ = m.maintain();
        try testing.expectEqual(@as(usize, 1), l.events.installed);
        // The installed chain is cut to its leaf: there is no issuer to ask the responder about.
        {
            const ct = &m.entries.items[0].cert.?;
            const end_marker = "-----END CERTIFICATE-----\n";
            const cut = (std.mem.find(u8, ct.chain_pem, end_marker) orelse return error.TestUnexpectedResult) + end_marker.len;
            const only = try testing.allocator.dupe(u8, ct.chain_pem[0..cut]);
            testing.allocator.free(@constCast(ct.chain_pem));
            ct.chain_pem = only;
        }
        const t0 = l.clock.t;
        try testing.expect(m.maintain() > t0 + day);
        l.clock.t = t0 + 500;
        try testing.expect(m.maintain() > t0 + day);
        try testing.expectEqual(@as(usize, 0), s.calls);
    }
}

test "mutation 2026-11-25: a staple is served up to and including its nextUpdate; a revocation drops it and its stored copy; a renewal starts without one" {
    var l: Lab = undefined;
    try l.init(true);
    defer l.deinit();
    var s: Script = .{ .mode = .staple, .until_s = 3600 };
    var m = try scriptedManager(&l, &s, 100, false);
    defer m.deinit();
    _ = m.maintain();
    _ = m.maintain();
    const t_check = l.clock.t;
    try testing.expectEqual(@as(usize, 1), l.events.stapled);
    if (try l.staple(&m)) |x| testing.allocator.free(x) else return error.StapleMissing;
    l.clock.t = t_check + 3600; // exactly nextUpdate: still servable
    if (try l.staple(&m)) |x| testing.allocator.free(x) else return error.StapleDroppedEarly;
    l.clock.t = t_check + 3601;
    try testing.expect((try l.staple(&m)) == null);

    // Revoked at the next check: the staple is gone at once, and so is its stored copy.
    l.clock.t = t_check + 100;
    if (try l.staple(&m)) |x| testing.allocator.free(x) else return error.StapleMissing;
    s.mode = .revoked;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 1), l.events.revoked);
    try testing.expect((try l.staple(&m)) == null);
    s.mode = .staple;
    _ = m.maintain(); // the replacement certificate
    try testing.expectEqual(@as(u8, 2), l.issuer.calls);
    _ = m.maintain(); // its first check
    try testing.expectEqual(@as(usize, 3), s.calls); // the first check, the revoked answer, this check
    try testing.expect(s.last_previous_null); // nothing left in storage to hand over
}

test "mutation 2026-11-25: a renewal drops the old certificate's staple until its own first check" {
    var l: Lab = undefined;
    try l.init(true);
    defer l.deinit();
    var s: Script = .{ .mode = .staple, .until_s = 90 * day };
    var m = try scriptedManager(&l, &s, 1_000_000_000, false);
    defer m.deinit();
    _ = m.maintain();
    _ = m.maintain();
    if (try l.staple(&m)) |x| testing.allocator.free(x) else return error.StapleMissing;
    l.clock.t += 61 * day; // past the renewal point
    _ = m.maintain();
    try testing.expectEqual(@as(u8, 2), l.issuer.calls);
    try testing.expectEqual(@as(usize, 1), s.calls);
    try testing.expect((try l.staple(&m)) == null);
}

test "mutation 2026-11-25: ARI polls and OCSP checks run on their own schedules, and a name with nothing to staple is not asked on ARI's" {
    var l: Lab = undefined;
    try l.init(true);
    defer l.deinit();
    var s: Script = .{ .mode = .staple };
    var m = try scriptedManager(&l, &s, 1000, true);
    defer m.deinit();
    _ = m.maintain(); // issues
    const t0 = l.clock.t;
    try testing.expectEqual(t0 + 700, m.maintain()); // both are due once
    try testing.expectEqual(@as(usize, 1), l.issuer.window_calls);
    try testing.expectEqual(@as(usize, 1), s.calls);
    l.clock.t = t0 + 700; // ARI due, OCSP not
    try testing.expectEqual(t0 + 1000, m.maintain());
    try testing.expectEqual(@as(usize, 2), l.issuer.window_calls);
    try testing.expectEqual(@as(usize, 1), s.calls);
    l.clock.t = t0 + 1000; // OCSP due, ARI not
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 2), l.issuer.window_calls);
    try testing.expectEqual(@as(usize, 2), s.calls);

    // Nothing to staple: an ARI step does not ask the stapler.
    var l2: Lab = undefined;
    try l2.init(true);
    defer l2.deinit();
    var s2: Script = .{ .mode = .none };
    var m2 = try scriptedManager(&l2, &s2, 1000, true);
    defer m2.deinit();
    _ = m2.maintain();
    const t2 = l2.clock.t;
    _ = m2.maintain();
    try testing.expectEqual(@as(usize, 1), s2.calls);
    l2.clock.t = t2 + 700;
    _ = m2.maintain();
    try testing.expectEqual(@as(usize, 2), l2.issuer.window_calls);
    try testing.expectEqual(@as(usize, 1), s2.calls);
}

test "mutation 2026-11-25: a name removed while its OCSP check runs gets no staple event, no revocation event" {
    inline for (.{ .staple, .revoked }) |mode| {
        var l: Lab = undefined;
        try l.init(true);
        defer l.deinit();
        var s: Script = .{ .mode = mode };
        var m = try scriptedManager(&l, &s, 100, false);
        defer m.deinit();
        _ = m.maintain();
        s.mgr = &m;
        _ = m.maintain(); // the check unmanages the name
        try testing.expectEqual(@as(usize, 1), s.calls);
        try testing.expectEqual(@as(usize, 0), l.events.stapled);
        try testing.expectEqual(@as(usize, 0), l.events.revoked);
    }
}

test "mutation 2026-11-25: after a restart a kept or failed-but-servable staple from storage is adopted silently" {
    inline for (.{ .keep, .fail_keep }) |mode| {
        var l: Lab = undefined;
        try l.init(true);
        defer l.deinit();
        {
            var s1: Script = .{ .mode = .staple, .until_s = 90 * day };
            var m1 = try scriptedManager(&l, &s1, 100, false);
            defer m1.deinit();
            _ = m1.maintain();
            _ = m1.maintain();
            try testing.expectEqual(@as(usize, 1), l.events.stapled);
        }
        var s2: Script = .{ .mode = mode, .until_s = 90 * day };
        var m2 = try scriptedManager(&l, &s2, 100, false);
        defer m2.deinit();
        _ = m2.maintain(); // loads the stored certificate
        _ = m2.maintain(); // its first check
        try testing.expectEqual(@as(usize, 1), s2.calls);
        try testing.expect(!s2.last_previous_null); // the stored staple was handed to the stapler
        try testing.expectEqual(@as(usize, 1), l.events.stapled); // adopting it reports nothing
        if (try l.staple(&m2)) |x| testing.allocator.free(x) else return error.StapleNotAdopted;
    }
}

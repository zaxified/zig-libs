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

    fn issuer(i: *Issuer) Manager.Issuer {
        return .{ .ctx = i, .name = "sign", .issue = issue };
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

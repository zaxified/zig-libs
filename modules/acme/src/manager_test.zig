// SPDX-License-Identifier: MIT

//! Manager tests: a scripted issuer over committed fixtures
//! (`testdata/manager_fixtures.zig`, `tools/gen_manager_fixtures.sh`), an
//! injected clock, `MemStorage`. The fixtures' validity windows are fixed,
//! so every schedule below is exact.

const std = @import("std");
const testkit = @import("testkit");
const http = @import("http");
const router = @import("router");
const Manager = @import("Manager.zig");
const Client = @import("Client.zig");
const storage = @import("storage.zig");
const jws = @import("jws.zig");
const fx = @import("testdata/manager_fixtures.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;

const day = std.time.s_per_day;
/// 2026-01-01T00:00:00Z, the fixtures' usual notBefore.
const day0: i64 = 1767225600;

const a_names: []const []const u8 = &.{ "a.example", "www.a.example" };

fn chainOf(comptime leaf: []const u8) []const u8 {
    return leaf ++ "\n" ++ fx.ca_pem ++ "\n";
}

const FakeClock = struct {
    t: i64,
    fn clock(c: *FakeClock) Manager.Clock {
        return .{ .ctx = c, .now = now };
    }
    fn now(ctx: ?*anyopaque) i64 {
        const c: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return c.t;
    }
};

/// Hands out scripted results in order; records what it was asked.
const FakeIssuer = struct {
    name: []const u8 = "fake",
    script: []const Step,
    at: usize = 0,
    calls: usize = 0,
    last_replaces: ?[64]u8 = null,
    last_names: [4][32]u8 = undefined,
    last_names_len: usize = 0,
    ari_window: ?Manager.Window = null,
    window_calls: usize = 0,
    /// Make `issue` slow (needs `io`), for the concurrency tests.
    io: ?std.Io = null,
    delay_ms: u32 = 0,
    /// Calls inside `issue` right now, and the most ever at once.
    in_flight: std.atomic.Value(u32) = .init(0),
    max_in_flight: std.atomic.Value(u32) = .init(0),

    const Step = union(enum) {
        ok: struct { chain: []const u8, key: []const u8 },
        fail: struct { problem: []const u8, retry_after_s: ?u64 = null },
    };

    fn issuer(f: *FakeIssuer, with_ari: bool) Manager.Issuer {
        return .{ .ctx = f, .name = f.name, .issue = issue, .renewal_window = if (with_ari) window else null };
    }

    fn issue(ctx: *anyopaque, gpa: Allocator, req: *const Manager.IssueRequest, diag: *Manager.Diagnostics) Manager.IssueError!Manager.Issued {
        const f: *FakeIssuer = @ptrCast(@alignCast(ctx));
        const now_in = f.in_flight.fetchAdd(1, .acq_rel) + 1;
        defer _ = f.in_flight.fetchSub(1, .acq_rel);
        _ = f.max_in_flight.fetchMax(now_in, .acq_rel);
        f.calls += 1;
        if (f.io) |io| if (f.delay_ms != 0) {
            const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(f.delay_ms), .clock = .awake };
            d.sleep(io) catch {};
        };
        f.last_replaces = null;
        if (req.replaces) |r| {
            var b: [64]u8 = @splat(0);
            @memcpy(b[0..@min(r.len, 64)], r[0..@min(r.len, 64)]);
            f.last_replaces = b;
        }
        f.last_names_len = @min(req.names.len, 4);
        for (req.names[0..f.last_names_len], 0..) |n, i| {
            f.last_names[i] = @splat(0);
            @memcpy(f.last_names[i][0..@min(n.len, 32)], n[0..@min(n.len, 32)]);
        }
        if (f.at >= f.script.len) {
            diag.note("script exhausted");
            return error.IssueFailed;
        }
        const s = f.script[f.at];
        f.at += 1;
        switch (s) {
            .ok => |o| {
                const chain = try gpa.dupe(u8, o.chain);
                errdefer gpa.free(chain);
                return .{ .chain_pem = chain, .key_pem = try gpa.dupe(u8, o.key), .not_after = 0 };
            },
            .fail => |fl| {
                diag.note(fl.problem);
                diag.retry_after_s = fl.retry_after_s;
                return error.IssueFailed;
            },
        }
    }

    fn window(ctx: *anyopaque, chain_pem: []const u8, diag: *Manager.Diagnostics) Manager.IssueError!Manager.Window {
        _ = chain_pem;
        _ = diag;
        const f: *FakeIssuer = @ptrCast(@alignCast(ctx));
        f.window_calls += 1;
        return f.ari_window orelse error.NotSupported;
    }
};

/// Records events.
const Recorder = struct {
    installed: usize = 0,
    failed: usize = 0,
    storage_failed: usize = 0,
    last_source: ?Manager.Event.Source = null,
    last_issuer: [16]u8 = @splat(0),
    last_not_after: i64 = 0,
    last_retry_at: i64 = 0,
    last_problem: [64]u8 = @splat(0),

    fn hook(r: *Recorder) Manager.EventHook {
        return .{ .ctx = r, .call = call };
    }

    fn call(ctx: ?*anyopaque, ev: *const Manager.Event) void {
        const r: *Recorder = @ptrCast(@alignCast(ctx.?));
        switch (ev.*) {
            .installed => |i| {
                r.installed += 1;
                r.last_source = i.source;
                r.last_not_after = i.not_after;
                r.last_issuer = @splat(0);
                if (i.issuer) |n| @memcpy(r.last_issuer[0..@min(n.len, 16)], n[0..@min(n.len, 16)]);
            },
            .failed => |f| {
                r.failed += 1;
                r.last_retry_at = f.retry_at;
                r.last_problem = @splat(0);
                @memcpy(r.last_problem[0..@min(f.problem.len, 64)], f.problem[0..@min(f.problem.len, 64)]);
            },
            .storage_failed => r.storage_failed += 1,
        }
    }

    fn issuerIs(r: *const Recorder, name: []const u8) bool {
        return std.mem.eql(u8, std.mem.sliceTo(&r.last_issuer, 0), name);
    }

    fn problemIs(r: *const Recorder, p: []const u8) bool {
        return std.mem.eql(u8, std.mem.sliceTo(&r.last_problem, 0), p);
    }
};

const Fixture = struct {
    threaded: std.Io.Threaded,
    mem: storage.MemStorage,
    clock: FakeClock,
    rec: Recorder = .{},

    fn init(f: *Fixture, t: i64) void {
        f.* = .{
            .threaded = std.Io.Threaded.init(testing.allocator, .{}),
            .mem = storage.MemStorage.init(testing.allocator),
            .clock = .{ .t = t },
        };
    }

    fn deinit(f: *Fixture) void {
        f.mem.deinit();
        f.threaded.deinit();
    }

    fn manager(f: *Fixture, extra: Manager.Options) Manager {
        var o = extra;
        o.storage = f.mem.storage();
        o.clock = f.clock.clock();
        o.on_event = f.rec.hook();
        o.random_seed = 7;
        o.node_id = "node-a";
        return Manager.init(f.threaded.io(), testing.allocator, o);
    }
};

fn opts() Manager.Options {
    return .{ .storage = undefined };
}

fn expectServes(m: *Manager, sni: []const u8, want_chain: []const u8) !void {
    var mat = (try m.certificate(testing.allocator, sni)) orelse return error.TestExpectedCertificate;
    defer mat.deinit(testing.allocator);
    try testing.expectEqualStrings(want_chain, mat.chain_pem);
}

// ── checkPair ───────────────────────────────────────────────────────────────

test "checkPair: verifies chain, coverage, key and time" {
    const gpa = testing.allocator;
    const t = day0 + 30 * day;
    const ok = try Manager.checkPair(gpa, a_names, chainOf(fx.a1_crt), fx.a1_key, t, &.{});
    try testing.expectEqual(day0, ok.not_before);
    try testing.expectEqual(day0 + 90 * day, ok.not_after);

    // With the CA as an explicit anchor too.
    const ca_der = try @import("x509.zig").pemDecode(gpa, "CERTIFICATE", fx.ca_pem);
    defer gpa.free(ca_der);
    _ = try Manager.checkPair(gpa, a_names, chainOf(fx.a1_crt), fx.a1_key, t, &.{ca_der});
    // The leaf alone with the CA anchor: the anchor completes the path.
    _ = try Manager.checkPair(gpa, a_names, fx.a1_crt, fx.a1_key, t, &.{ca_der});

    try testing.expectError(error.KeyMismatch, Manager.checkPair(gpa, a_names, chainOf(fx.a1_crt), fx.a2_key, t, &.{}));
    try testing.expectError(error.KeyMismatch, Manager.checkPair(gpa, a_names, chainOf(fx.a1_crt), "not a key", t, &.{}));
    try testing.expectError(error.NameNotCovered, Manager.checkPair(gpa, &.{"b.example"}, chainOf(fx.a1_crt), fx.a1_key, t, &.{}));
    try testing.expectError(error.NameNotCovered, Manager.checkPair(gpa, &.{"*.a.example"}, chainOf(fx.a1_crt), fx.a1_key, t, &.{}));
    try testing.expectError(error.Expired, Manager.checkPair(gpa, a_names, chainOf(fx.a1_crt), fx.a1_key, day0 + 90 * day, &.{}));
    try testing.expectError(error.MalformedChain, Manager.checkPair(gpa, a_names, "", fx.a1_key, t, &.{}));
    // A leaf alone, no anchors: the leaf would be its own anchor, and it is
    // not self-signed — nothing verifies.
    try testing.expectError(error.Untrusted, Manager.checkPair(gpa, a_names, fx.a1_crt, fx.a1_key, t, &.{}));
    // Some other certificate as the only anchor.
    const b1_der = try @import("x509.zig").pemDecode(gpa, "CERTIFICATE", fx.b1_crt);
    defer gpa.free(b1_der);
    try testing.expectError(error.Untrusted, Manager.checkPair(gpa, a_names, chainOf(fx.a1_crt), fx.a1_key, t, &.{b1_der}));

    // Wildcards: the literal wildcard, its base, and a name under it.
    _ = try Manager.checkPair(gpa, &.{ "*.w.example", "w.example", "x.w.example" }, chainOf(fx.wild_crt), fx.wild_key, t, &.{});
    try testing.expectError(error.NameNotCovered, Manager.checkPair(gpa, &.{"a.b.w.example"}, chainOf(fx.wild_crt), fx.wild_key, t, &.{}));
    // A fresh certificate judged before its notBefore (clock skew) still passes.
    _ = try Manager.checkPair(gpa, a_names, chainOf(fx.a2_crt), fx.a2_key, day0 + 58 * day, &.{});
}

// ── the managed set ─────────────────────────────────────────────────────────

test "manage: issue, store, serve, renew at two thirds with replaces, restart from storage" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();

    var fake: FakeIssuer = .{ .script = &.{
        .{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } },
        .{ .ok = .{ .chain = chainOf(fx.a2_crt), .key = fx.a2_key } },
    } };
    {
        var m = f.manager(opts());
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try m.manage(&.{ "A.example", "www.a.example" }); // lower-cased

        try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "a.example"));
        const next = m.maintain();
        try testing.expectEqual(@as(usize, 1), fake.calls);
        try testing.expect(fake.last_replaces == null); // first issuance
        try testing.expectEqualStrings("a.example", std.mem.sliceTo(&fake.last_names[0], 0));
        try testing.expectEqual(@as(usize, 1), f.rec.installed);
        try testing.expectEqual(Manager.Event.Source.issued, f.rec.last_source.?);
        try testing.expect(f.rec.issuerIs("fake"));
        try testing.expectEqual(day0 + 60 * day, next); // 2/3 of 90 days
        try testing.expectEqual(@as(usize, 1), f.mem.count()); // key + chain, one value
        try expectServes(&m, "www.a.example", chainOf(fx.a1_crt));
        try expectServes(&m, "A.EXAMPLE.", chainOf(fx.a1_crt)); // case + trailing dot
        try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "b.example"));

        // Not due yet: nothing happens.
        f.clock.t = day0 + 59 * day;
        _ = m.maintain();
        try testing.expectEqual(@as(usize, 1), fake.calls);

        // Due: renewed, with the ARI `replaces` of the old certificate.
        f.clock.t = day0 + 60 * day;
        const next2 = m.maintain();
        try testing.expectEqual(@as(usize, 2), fake.calls);
        try testing.expect(fake.last_replaces != null);
        try testing.expectEqual(@as(usize, 2), f.rec.installed);
        try expectServes(&m, "a.example", chainOf(fx.a2_crt));
        try testing.expectEqual(day0 + 59 * day + 60 * day, next2);
    }
    // A restart on the same storage serves the renewed certificate without
    // asking the issuer.
    f.clock.t = day0 + 61 * day;
    var fake2: FakeIssuer = .{ .script = &.{} };
    var m2 = f.manager(opts());
    defer m2.deinit();
    try m2.addIssuer(fake2.issuer(false));
    try m2.manage(a_names);
    _ = m2.maintain();
    try testing.expectEqual(@as(usize, 0), fake2.calls);
    try testing.expectEqual(Manager.Event.Source.storage, f.rec.last_source.?);
    try expectServes(&m2, "a.example", chainOf(fx.a2_crt));
}

test "manage: a stored certificate past its renewal point is served and renewed" {
    var f: Fixture = undefined;
    f.init(day0 + 70 * day); // a1 renews at day 60
    defer f.deinit();
    const s = f.mem.storage();
    try s.store("certificates/a.example.pem", comptime (fx.a1_key ++ "\n" ++ chainOf(fx.a1_crt)));

    var fake: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "CA down" } }} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    _ = m.maintain();
    // Installed from storage first, then the renewal attempt failed — and
    // the stored certificate keeps serving.
    try testing.expectEqual(@as(usize, 1), f.rec.installed);
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqual(@as(usize, 1), f.rec.failed);
    try expectServes(&m, "a.example", chainOf(fx.a1_crt));
}

test "manage: failures back off 1 min doubling, Retry-After wins, cap holds" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{
        .{ .fail = .{ .problem = "boom" } },
        .{ .fail = .{ .problem = "boom" } },
        .{ .fail = .{ .problem = "rate limited", .retry_after_s = 3 * 3600 } },
        .{ .fail = .{ .problem = "boom" } },
        .{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } },
    } };
    var m = f.manager(.{ .storage = undefined, .max_backoff_s = 600 });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);

    const t0 = f.clock.t;
    try testing.expectEqual(t0 + 60, m.maintain());
    try testing.expect(f.rec.problemIs("boom"));
    try testing.expectEqual(t0 + 60, f.rec.last_retry_at);
    // Before the retry time nothing is attempted.
    f.clock.t = t0 + 59;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 1), fake.calls);
    f.clock.t = t0 + 60;
    try testing.expectEqual(t0 + 60 + 120, m.maintain());
    f.clock.t = t0 + 180;
    try testing.expectEqual(t0 + 180 + 3 * 3600, m.maintain()); // Retry-After beats 240 s
    f.clock.t = t0 + 180 + 3 * 3600;
    const t3 = f.clock.t;
    try testing.expectEqual(t3 + 480, m.maintain()); // 2^3 min = 480 ≤ cap 600
    f.clock.t = t3 + 480;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 5), fake.calls);
    try testing.expectEqual(@as(usize, 1), f.rec.installed);
    try testing.expectEqual(@as(usize, 4), f.rec.failed);
}

test "issuers: fallback in order, a chain that fails the checks counts as a failure" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var one: FakeIssuer = .{
        .name = "one",
        .script = &.{
            // Wrong key for the chain: rejected before storage.
            .{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.b1_key } },
        },
    };
    var two: FakeIssuer = .{ .name = "two", .script = &.{
        .{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } },
    } };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(one.issuer(false));
    try m.addIssuer(two.issuer(false));
    try m.manage(a_names);
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 1), one.calls);
    try testing.expectEqual(@as(usize, 1), two.calls);
    try testing.expect(f.rec.issuerIs("two"));
    try testing.expectEqual(@as(usize, 0), f.rec.failed);

    // Everything failing: one event, carrying the last issuer's problem.
    var three: FakeIssuer = .{ .name = "three", .script = &.{.{ .ok = .{ .chain = chainOf(fx.b1_crt), .key = fx.b1_key } }} };
    var m2 = f.manager(opts());
    defer m2.deinit();
    try m2.addIssuer(three.issuer(false));
    try m2.manage(&.{"c.example"});
    _ = m2.maintain();
    try testing.expectEqual(@as(usize, 1), f.rec.failed);
    try testing.expect(f.rec.problemIs("issued certificate does not cover every name"));
}

test "issuers: random policy spreads over issuers (seeded)" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    const ok: FakeIssuer.Step = .{ .ok = .{ .chain = chainOf(fx.b1_crt), .key = fx.b1_key } };
    var x: FakeIssuer = .{ .name = "x", .script = &@as([16]FakeIssuer.Step, @splat(ok)) };
    var y: FakeIssuer = .{ .name = "y", .script = &@as([16]FakeIssuer.Step, @splat(ok)) };
    // Sixteen managers, sixteen seeds: each issuer goes first sometimes, and
    // only the first is asked (it succeeds).
    for (0..16) |seed| {
        var o = opts();
        o.issuer_policy = .random;
        var m = f.manager(o);
        m.prng = std.Random.DefaultPrng.init(seed);
        defer m.deinit();
        try m.addIssuer(x.issuer(false));
        try m.addIssuer(y.issuer(false));
        try m.manage(&.{"b.example"});
        f.mem.storage().delete("certificates/b.example.pem") catch {};
        _ = m.maintain();
    }
    try testing.expectEqual(@as(usize, 16), x.calls + y.calls);
    try testing.expect(x.calls > 0 and y.calls > 0);
}

test "schedule: ten days or less renews at half the lifetime" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.short_crt), .key = fx.short_key } }} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(&.{"s.example"});
    try testing.expectEqual(day0 + 3 * day, m.maintain());
}

test "schedule: renewal_window_pct; the default server name answers an empty SNI" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }} };
    var o = opts();
    o.renewal_window_pct = 10; // the last 9 of 90 days
    o.default_server_name = "www.a.example";
    var m = f.manager(o);
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    try testing.expectEqual(day0 + 81 * day, m.maintain());
    try expectServes(&m, "", chainOf(fx.a1_crt));
}

test "ARI: the window decides, polled again at Retry-After, unchanged window keeps its pick" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{
        .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }},
        .ari_window = .{ .start = day0 + 40 * day, .end = day0 + 41 * day, .retry_after_s = 7200 },
    };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(true));
    try m.manage(a_names);
    // Issue; the ARI poll is due at once.
    try testing.expectEqual(f.clock.t, m.maintain());
    // Poll: the renewal moves into the window; next poll in two hours.
    const next = m.maintain();
    try testing.expectEqual(@as(usize, 1), fake.window_calls);
    try testing.expectEqual(f.clock.t + 7200, next);
    // Renewal time inside the window, reported once the poll is far.
    f.clock.t += 7200;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 2), fake.window_calls);
    m.mutex.lockUncancelable(m.io);
    const renew_at = m.entries.items[0].renew_at;
    m.mutex.unlock(m.io);
    try testing.expect(renew_at >= day0 + 40 * day and renew_at <= day0 + 41 * day);
    // Same window again: same pick.
    f.clock.t += 7200;
    _ = m.maintain();
    m.mutex.lockUncancelable(m.io);
    try testing.expectEqual(renew_at, m.entries.items[0].renew_at);
    m.mutex.unlock(m.io);

    // An issuer without ARI: polling stops (ari_at null), 2/3 rule stands.
    var f2: Fixture = undefined;
    f2.init(day0 + day);
    defer f2.deinit();
    var plain: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }} };
    var m2 = f2.manager(opts());
    defer m2.deinit();
    try m2.addIssuer(plain.issuer(true)); // offers the hook, answers NotSupported
    try m2.manage(a_names);
    _ = m2.maintain();
    try testing.expectEqual(day0 + 60 * day, m2.maintain());
    try testing.expectEqual(@as(usize, 1), plain.window_calls);
}

test "fleet: another node's lock defers, its stored result is adopted" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    const s = f.mem.storage();
    try testing.expect(try s.tryLock("issue/a.example", "node-b", f.clock.t, 900));

    var fake: FakeIssuer = .{ .script = &.{} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    try testing.expectEqual(f.clock.t + 60, m.maintain());
    try testing.expectEqual(@as(usize, 0), fake.calls);
    try testing.expectEqual(@as(usize, 0), f.rec.failed); // waiting is not failing

    // node-b finishes: its certificate lands in storage.
    try s.store("certificates/a.example.pem", comptime (fx.a1_key ++ "\n" ++ chainOf(fx.a1_crt)));
    f.clock.t += 60;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 0), fake.calls);
    try testing.expectEqual(Manager.Event.Source.storage, f.rec.last_source.?);
    try expectServes(&m, "a.example", chainOf(fx.a1_crt));
}

test "serving: wildcard lookup covers one label; unmanage" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.wild_crt), .key = fx.wild_key } }} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(&.{ "*.w.example", "w.example" });
    try testing.expectError(error.AlreadyManaged, m.manage(&.{"w.example"}));
    try testing.expectError(error.InvalidName, m.manage(&.{"bad name"}));
    try testing.expectError(error.InvalidName, m.manage(&.{}));
    _ = m.maintain();
    try expectServes(&m, "x.w.example", chainOf(fx.wild_crt));
    try expectServes(&m, "w.example", chainOf(fx.wild_crt));
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "a.b.w.example"));
    try testing.expect(!m.unmanage("w.example")); // not the first name
    try testing.expect(m.unmanage("*.w.example"));
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "w.example"));
    try m.manage(&.{"w.example"}); // the names are free again
}

// ── on-demand ───────────────────────────────────────────────────────────────

const Policy = struct {
    asked: usize = 0,
    fn allow(ctx: ?*anyopaque, name: []const u8) bool {
        const p: *Policy = @ptrCast(@alignCast(ctx.?));
        p.asked += 1;
        return std.mem.endsWith(u8, name, ".example") and !std.mem.startsWith(u8, name, "evil");
    }
};

test "on-demand: policy, rate limit, failure back-off, then renewed by maintain" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var policy: Policy = .{};
    var fake: FakeIssuer = .{ .script = &.{
        .{ .ok = .{ .chain = chainOf(fx.od1_crt), .key = fx.od1_key } },
        .{ .fail = .{ .problem = "no" } },
        .{ .ok = .{ .chain = chainOf(fx.od2_crt), .key = fx.od2_key } },
    } };
    var m = f.manager(.{ .storage = undefined, .on_demand = .{
        .ctx = &policy,
        .allow = Policy.allow,
        .rate = .{ .max = 2, .window_s = 60 },
        .failure_backoff_s = 300,
    } });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));

    try expectServes(&m, "od.example", chainOf(fx.od1_crt));
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try expectServes(&m, "od.example", chainOf(fx.od1_crt)); // cached
    try testing.expectEqual(@as(usize, 1), fake.calls);

    // Refused by policy: the CA is never asked.
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "evil.example"));
    try testing.expectEqual(@as(usize, 1), fake.calls);
    // A failure: no certificate, and none asked for again during the back-off.
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od2.example"));
    try testing.expectEqual(@as(usize, 2), fake.calls);
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od2.example"));
    try testing.expectEqual(@as(usize, 2), fake.calls);
    // The background never retries a name that has no certificate: only a
    // handshake asking for it does.
    f.clock.t += 3600;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 2), fake.calls);
    f.clock.t -= 3600;
    // Rate limit: two issuances in the window are used up.
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "other.example"));
    try testing.expectEqual(@as(usize, 2), fake.calls);
    // After the back-off the failed name is tried again.
    f.clock.t += 300;
    try expectServes(&m, "od2.example", chainOf(fx.od2_crt));
    try testing.expectEqual(@as(usize, 3), fake.calls);

    // On-demand names are managed: maintain renews them when due.
    f.clock.t = day0 + 61 * day;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 5), fake.calls); // both due, script exhausted → failures
}

fn askThread(m: *Manager, got: *std.atomic.Value(u32)) void {
    var mat = (m.certificate(testing.allocator, "od.example") catch return) orelse return;
    defer mat.deinit(testing.allocator);
    if (std.mem.eql(u8, mat.chain_pem, chainOf(fx.od1_crt))) _ = got.fetchAdd(1, .monotonic);
}

test "on-demand: concurrent handshakes for one name share one issuance" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var policy: Policy = .{};
    var fake: FakeIssuer = .{
        .script = &.{.{ .ok = .{ .chain = chainOf(fx.od1_crt), .key = fx.od1_key } }},
        .io = f.threaded.io(),
        .delay_ms = 100,
    };
    var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow } });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    var got: std.atomic.Value(u32) = .init(0);
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, askThread, .{ &m, &got });
    for (threads) |t| t.join();
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqual(@as(u32, 4), got.load(.monotonic));
}

/// MemStorage whose writes fail (reads still work).
const BrokenStore = struct {
    mem: *storage.MemStorage,
    fn storageOf(b: *BrokenStore) storage.Storage {
        return .{ .ptr = b, .vtable = &vt };
    }
    const vt: storage.Storage.VTable = .{ .load = load, .store = store, .delete = del, .tryLock = tryLock, .unlock = unlock };
    fn of(p: *anyopaque) *BrokenStore {
        return @ptrCast(@alignCast(p));
    }
    fn load(p: *anyopaque, gpa: Allocator, path: []const u8) storage.Error![]u8 {
        return of(p).mem.storage().vtable.load(of(p).mem, gpa, path);
    }
    fn store(_: *anyopaque, _: []const u8, _: []const u8) storage.Error!void {
        return error.StorageFailed;
    }
    fn del(_: *anyopaque, _: []const u8) storage.Error!void {}
    fn tryLock(p: *anyopaque, name: []const u8, owner: []const u8, t: i64, lease: u32) storage.Error!bool {
        return of(p).mem.storage().vtable.tryLock(of(p).mem, name, owner, t, lease);
    }
    fn unlock(p: *anyopaque, name: []const u8, owner: []const u8) void {
        of(p).mem.storage().vtable.unlock(of(p).mem, name, owner);
    }
};

test "storage: a failed write still serves the certificate, and says so" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var broken: BrokenStore = .{ .mem = &f.mem };
    var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }} };
    var m = f.manager(opts());
    m.options.storage = broken.storageOf();
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 1), f.rec.installed);
    try testing.expectEqual(@as(usize, 1), f.rec.storage_failed);
    try expectServes(&m, "a.example", chainOf(fx.a1_crt));
    try testing.expectEqual(@as(usize, 0), f.mem.count());
}

test "on-demand: without the option an unknown name gets nothing" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var m = f.manager(opts());
    defer m.deinit();
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od.example"));
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "")); // no default name
}

// ── challenges ──────────────────────────────────────────────────────────────

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn hApp(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("app");
}

const challenge_req: Client.ChallengeRequest = .{
    .type = .http_01,
    .identifier = "a.example",
    .ip = false,
    .wildcard = false,
    .token = "tok-123_ABC",
    .key_authorization = "tok-123_ABC.THUMB",
};

test "HTTP-01: solver + middleware; redirect fallback; another node answers from storage" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    var m = f.manager(.{ .storage = undefined, .http_redirect = true, .distributed_challenges = true });
    defer m.deinit();
    const solvers = m.challengeSolvers();
    try testing.expectEqual(Client.ChallengeType.http_01, solvers[0].type);
    try solvers[0].present(solvers[0].ctx, &challenge_req);

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(m.httpMiddleware());
    try r.get("/", hApp);
    var buf: [1024]u8 = undefined;

    const hit = runWire(&r, "GET /.well-known/acme-challenge/tok-123_ABC HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, hit, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.endsWith(u8, hit, "\r\n\r\ntok-123_ABC.THUMB"));
    const miss = runWire(&r, "GET /.well-known/acme-challenge/nope HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    // Not a base64url token: never looked up (nor read from storage).
    const odd = runWire(&r, "GET /.well-known/acme-challenge/tok.123 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, odd, "HTTP/1.1 404"));
    try testing.expect(std.mem.startsWith(u8, miss, "HTTP/1.1 404"));
    const redirect = runWire(&r, "GET /x?y=1 HTTP/1.1\r\nHost: a.example:80\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, redirect, "HTTP/1.1 302"));
    try testing.expect(std.mem.find(u8, redirect, "\r\nLocation: https://a.example/x?y=1\r\n") != null);
    const post = runWire(&r, "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, post, "HTTP/1.1 400"));
    const bad_host = runWire(&r, "GET / HTTP/1.1\r\nHost: a.example\"x\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, bad_host, "HTTP/1.1 400"));

    // A second node on the same storage answers the token it never saw.
    var m2 = f.manager(.{ .storage = undefined, .distributed_challenges = true });
    defer m2.deinit();
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    try r2.use(m2.httpMiddleware());
    try r2.get("/", hApp);
    const remote = runWire(&r2, "GET /.well-known/acme-challenge/tok-123_ABC HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.endsWith(u8, remote, "\r\n\r\ntok-123_ABC.THUMB"));
    // Without redirect, other paths pass through.
    const app = runWire(&r2, "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.endsWith(u8, app, "\r\n\r\napp"));

    // Cleanup removes it everywhere.
    solvers[0].cleanup(solvers[0].ctx, &challenge_req);
    const gone = runWire(&r2, "GET /.well-known/acme-challenge/tok-123_ABC HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, gone, "HTTP/1.1 404"));
    try testing.expectEqual(@as(usize, 0), f.mem.count());
}

test "TLS-ALPN-01: solver publishes locally and to storage; another node serves it" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    var m = f.manager(.{ .storage = undefined, .distributed_challenges = true });
    defer m.deinit();
    var m2 = f.manager(.{ .storage = undefined, .distributed_challenges = true });
    defer m2.deinit();
    const solvers = m.challengeSolvers();
    var req = challenge_req;
    req.type = .tls_alpn_01;
    try solvers[1].present(solvers[1].ctx, &req);

    var local = (try m.tlsAlpnMaterial(testing.allocator, "a.example")).?;
    defer local.deinit(testing.allocator);
    var remote = (try m2.tlsAlpnMaterial(testing.allocator, "a.example")).?;
    defer remote.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, local.cert_der, remote.cert_der);
    try testing.expectEqualStrings(local.key_pem, remote.key_pem);
    try testing.expect(std.mem.startsWith(u8, remote.key_pem, "-----BEGIN EC PRIVATE KEY-----"));
    try testing.expectEqual(@as(?Client.TlsAlpnResponder.Material, null), try m2.tlsAlpnMaterial(testing.allocator, "b.example"));

    solvers[1].cleanup(solvers[1].ctx, &req);
    try testing.expectEqual(@as(?Client.TlsAlpnResponder.Material, null), try m2.tlsAlpnMaterial(testing.allocator, "a.example"));
    try testing.expectEqual(@as(?Client.TlsAlpnResponder.Material, null), try m.tlsAlpnMaterial(testing.allocator, "a.example"));
}

// ── accounts, names, limiter ────────────────────────────────────────────────

test "loadOrCreateAccountKey: generated once, then loaded" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    const io = f.threaded.io();
    const s = f.mem.storage();
    var k1: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&k1));
    try Manager.loadOrCreateAccountKey(&k1, io, testing.allocator, s, "ca-one", .es256);
    var k2: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&k2));
    try Manager.loadOrCreateAccountKey(&k2, io, testing.allocator, s, "ca-one", .es256);
    var b1: [jws.AnyPublicKey.max_sec1_len]u8 = undefined;
    var b2: [jws.AnyPublicKey.max_sec1_len]u8 = undefined;
    try testing.expectEqualSlices(u8, k1.publicKey().uncompressedSec1(&b1), k2.publicKey().uncompressedSec1(&b2));
    // Another issuer gets its own account.
    var k3: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&k3));
    try Manager.loadOrCreateAccountKey(&k3, io, testing.allocator, s, "ca-two", .es384);
    try testing.expectEqual(jws.Alg.es384, k3.alg());
    try testing.expectError(error.UnsupportedKeyType, Manager.loadOrCreateAccountKey(&k3, io, testing.allocator, s, "ca-three", .rs256));
    try testing.expectError(error.InvalidKey, Manager.loadOrCreateAccountKey(&k3, io, testing.allocator, s, "../x", .es256));
}

/// A storage whose first `load` misses what is there: the window between
/// `loadOrCreateAccountKey`'s load and its create, in which another node
/// stored its key (audit L7, 2026-10-18).
const RacedStorage = struct {
    inner: storage.Storage,
    missed: bool = false,
    vt: storage.Storage.VTable = undefined,

    fn of(ptr: *anyopaque) *RacedStorage {
        return @ptrCast(@alignCast(ptr));
    }
    fn load(ptr: *anyopaque, gpa: Allocator, path: []const u8) storage.Error![]u8 {
        const r = of(ptr);
        if (!r.missed) {
            r.missed = true;
            return error.NotFound;
        }
        return r.inner.vtable.load(r.inner.ptr, gpa, path);
    }
    fn store(ptr: *anyopaque, path: []const u8, value: []const u8) storage.Error!void {
        return of(ptr).inner.vtable.store(of(ptr).inner.ptr, path, value);
    }
    fn delete(ptr: *anyopaque, path: []const u8) storage.Error!void {
        return of(ptr).inner.vtable.delete(of(ptr).inner.ptr, path);
    }
    fn create(ptr: *anyopaque, path: []const u8, value: []const u8) storage.Error!bool {
        return of(ptr).inner.vtable.create.?(of(ptr).inner.ptr, path, value);
    }
    fn tryLock(ptr: *anyopaque, name: []const u8, owner: []const u8, now: i64, lease_s: u32) storage.Error!bool {
        return of(ptr).inner.vtable.tryLock(of(ptr).inner.ptr, name, owner, now, lease_s);
    }
    fn unlock(ptr: *anyopaque, name: []const u8, owner: []const u8) void {
        of(ptr).inner.vtable.unlock(of(ptr).inner.ptr, name, owner);
    }
    /// Every call forwarded to `inner`; `create` only if `inner` has one.
    fn storage_(r: *RacedStorage) storage.Storage {
        r.vt = .{
            .load = load,
            .store = store,
            .delete = delete,
            .create = if (r.inner.vtable.create != null) create else null,
            .tryLock = tryLock,
            .unlock = unlock,
        };
        return .{ .ptr = r, .vtable = &r.vt };
    }
};

test "loadOrCreateAccountKey: a key stored meanwhile by another node wins (L7)" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    const io = f.threaded.io();
    var first: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&first));
    try Manager.loadOrCreateAccountKey(&first, io, testing.allocator, f.mem.storage(), "ca-one", .es256);
    // The second node's load misses that key; its create must then refuse
    // to replace it and hand back the stored one, not its own fresh key.
    var raced: RacedStorage = .{ .inner = f.mem.storage() };
    var second: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&second));
    try Manager.loadOrCreateAccountKey(&second, io, testing.allocator, raced.storage_(), "ca-one", .es256);
    try testing.expect(raced.missed);
    var b1: [jws.AnyPublicKey.max_sec1_len]u8 = undefined;
    var b2: [jws.AnyPublicKey.max_sec1_len]u8 = undefined;
    try testing.expectEqualSlices(u8, first.publicKey().uncompressedSec1(&b1), second.publicKey().uncompressedSec1(&b2));
    // A backend without `create` (load-then-store) takes the same path.
    var legacy_vt = f.mem.storage().vtable.*;
    legacy_vt.create = null;
    var raced2: RacedStorage = .{ .inner = .{ .ptr = f.mem.storage().ptr, .vtable = &legacy_vt } };
    var third: jws.AnyKeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&third));
    try Manager.loadOrCreateAccountKey(&third, io, testing.allocator, raced2.storage_(), "ca-one", .es256);
    try testing.expectEqualSlices(u8, first.publicKey().uncompressedSec1(&b1), third.publicKey().uncompressedSec1(&b2));
}

test "issuerName: storage-safe directory names" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("acme-v02.api.letsencrypt.org-directory", Manager.issuerName(&buf, Client.letsencrypt_production));
    try testing.expectEqualStrings("127.0.0.1-14000-dir", Manager.issuerName(&buf, "https://127.0.0.1:14000/dir"));
    try testing.expectEqualStrings("-", Manager.issuerName(&buf, "https://"));
    try testing.expect(storage.validKey(Manager.issuerName(&buf, "https://x.example/a b?c=d#e")));
}

// ── review findings (2026-10-16) ────────────────────────────────────────────

fn askName(m: *Manager, name: []const u8, got: *std.atomic.Value(u32)) void {
    var mat = (m.certificate(testing.allocator, name) catch return) orelse return;
    mat.deinit(testing.allocator);
    _ = got.fetchAdd(1, .monotonic);
}

test "review H1: one issuer is never driven by two threads at once" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var policy: Policy = .{};
    var fake: FakeIssuer = .{
        .script = &.{
            .{ .ok = .{ .chain = chainOf(fx.od1_crt), .key = fx.od1_key } },
            .{ .ok = .{ .chain = chainOf(fx.od2_crt), .key = fx.od2_key } },
        },
        .io = f.threaded.io(),
        .delay_ms = 100,
    };
    var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow } });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    var got: std.atomic.Value(u32) = .init(0);
    // Two different names: two entries, one issuer — the calls must queue.
    const t1 = try std.Thread.spawn(.{}, askName, .{ &m, "od.example", &got });
    const t2 = try std.Thread.spawn(.{}, askName, .{ &m, "od2.example", &got });
    t1.join();
    t2.join();
    try testing.expectEqual(@as(usize, 2), fake.calls);
    try testing.expectEqual(@as(u32, 1), fake.max_in_flight.load(.acquire));
    try testing.expectEqual(@as(u32, 2), got.load(.monotonic));
}

test "review M1: an ARI window in the past for a fresh certificate does not loop" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{
        .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }},
        .ari_window = .{ .start = day0 - 10 * day, .end = day0 - 9 * day },
    };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(true));
    try m.manage(a_names);
    _ = m.maintain(); // issue
    const next = m.maintain(); // ARI poll: the window is in the past
    try testing.expectEqual(@as(usize, 1), fake.calls);
    m.mutex.lockUncancelable(m.io);
    const renew_at = m.entries.items[0].renew_at;
    m.mutex.unlock(m.io);
    try testing.expectEqual(day0 + 9 * day, renew_at); // the floor: a tenth of 90 days
    try testing.expect(next > f.clock.t);
}

test "review M2/L13/N5: a failed on-demand name is forgotten after its back-off; limits" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var policy: Policy = .{};
    var fake: FakeIssuer = .{ .script = &.{ .{ .fail = .{ .problem = "no" } }, .{ .fail = .{ .problem = "no" } } } };
    var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow, .failure_backoff_s = 300 } });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od.example"));
    try testing.expectEqual(@as(usize, 1), m.entries.items.len);
    try testing.expectEqual(@as(usize, 1), policy.asked);
    // Within the back-off: refused without asking anyone.
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od.example"));
    try testing.expectEqual(@as(usize, 1), policy.asked);
    // After it: maintain forgets the name.
    f.clock.t += 300;
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 0), m.entries.items.len);
    // The next handshake asks the policy again.
    _ = try m.certificate(testing.allocator, "od.example");
    try testing.expectEqual(@as(usize, 2), policy.asked);
    try testing.expectEqual(@as(usize, 2), fake.calls);

    // L13: at most max_issuers.
    for (0..Manager.max_issuers - 1) |_| try m.addIssuer(fake.issuer(false));
    try testing.expectError(error.TooManyIssuers, m.addIssuer(fake.issuer(false)));
    // N5: a name whose storage key would be invalid is refused up front.
    try testing.expectError(error.InvalidName, m.manage(&.{"fe80::1%eth0"}));
}

test "review L3/L8: Retry-After never parks a valid certificate past its end; malformed SNI" {
    var f: Fixture = undefined;
    f.init(day0 + 70 * day); // a1 (stored) is due
    defer f.deinit();
    try f.mem.storage().store("certificates/a.example.pem", comptime (fx.a1_key ++ "\n" ++ chainOf(fx.a1_crt)));
    var fake: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "later", .retry_after_s = 365 * day } }} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    _ = m.maintain();
    try testing.expectEqual(day0 + 90 * day - 3600, f.rec.last_retry_at);
    try expectServes(&m, "a.example", chainOf(fx.a1_crt));
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, ".a.example"));
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "*.a.example"));
}

fn maintainThread(m: *Manager) void {
    _ = m.maintain();
}

test "review M4: a handshake does not wait for a managed name's first issuance" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var policy: Policy = .{};
    var fake: FakeIssuer = .{
        .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }},
        .io = f.threaded.io(),
        .delay_ms = 400,
    };
    var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow } });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    const th = try std.Thread.spawn(.{}, maintainThread, .{&m});
    defer th.join();
    while (fake.in_flight.load(.acquire) == 0) std.atomic.spinLoopHint();
    const io = f.threaded.io();
    const t0 = std.Io.Clock.awake.now(io);
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "a.example"));
    const waited = t0.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    try testing.expect(waited < 200);
    try testing.expectEqual(@as(usize, 0), policy.asked); // a managed name is never on-demand
}

test "review M3: run() serves a name managed while it sleeps within a second" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    const io = f.threaded.io();
    var fut = io.async(Manager.run, .{&m});
    // Nothing managed: run sleeps "an hour". Let it get there, then manage.
    const settle: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(200), .clock = .awake };
    try settle.sleep(io);
    try m.manage(a_names);
    var waited: u32 = 0;
    while (f.rec.installed == 0 and waited < 30) : (waited += 1) {
        const step: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(100), .clock = .awake };
        try step.sleep(io);
    }
    fut.cancel(io) catch {};
    try testing.expectEqual(@as(usize, 1), f.rec.installed);
}

// ── audit 2026-10-18: tests asked for by mutation survivors ─────────────────

test "schedule: renewal_window_pct 1 and 99 are percentages; 0 and 100 mean the default" {
    // life = 90 days; renew when pct percent of it remains.
    inline for (.{
        .{ 1, 7_698_240 },
        .{ 99, 77_760 },
        .{ 0, 60 * day },
        .{ 100, 60 * day },
    }) |c| {
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }} };
        var o = opts();
        o.renewal_window_pct = c[0];
        var m = f.manager(o);
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try m.manage(a_names);
        try testing.expectEqual(day0 + c[1], m.maintain());
    }
}

test "backoff: doubles from one minute for 20 steps then stays; Retry-After only lengthens it, at most a year" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    const fails = @as([22]FakeIssuer.Step, @splat(.{ .fail = .{ .problem = "boom" } }));
    var fake: FakeIssuer = .{ .script = &fails };
    var o = opts();
    o.max_backoff_s = 4_000_000_000;
    var m = f.manager(o);
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    var n: u6 = 1;
    while (n <= 22) : (n += 1) {
        _ = m.maintain();
        const want: i64 = @as(i64, 60) << @min(n - 1, 20);
        try testing.expectEqual(want, f.rec.last_retry_at - f.clock.t);
        f.clock.t = f.rec.last_retry_at;
    }

    // a short Retry-After does not shorten the back-off (third failure: 4 min)
    var f2: Fixture = undefined;
    f2.init(day0 + day);
    defer f2.deinit();
    var fake2: FakeIssuer = .{ .script = &.{
        .{ .fail = .{ .problem = "boom" } },
        .{ .fail = .{ .problem = "boom" } },
        .{ .fail = .{ .problem = "boom", .retry_after_s = 10 } },
    } };
    var m2 = f2.manager(opts());
    defer m2.deinit();
    try m2.addIssuer(fake2.issuer(false));
    try m2.manage(a_names);
    _ = m2.maintain();
    f2.clock.t = f2.rec.last_retry_at;
    _ = m2.maintain();
    f2.clock.t = f2.rec.last_retry_at;
    _ = m2.maintain();
    try testing.expectEqual(@as(i64, 240), f2.rec.last_retry_at - f2.clock.t);

    // a huge one is capped at a year (the configured cap is for the doubling only)
    var f3: Fixture = undefined;
    f3.init(day0 + day);
    defer f3.deinit();
    var fake3: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "boom", .retry_after_s = 400 * day } }} };
    var m3 = f3.manager(opts());
    defer m3.deinit();
    try m3.addIssuer(fake3.issuer(false));
    try m3.manage(a_names);
    _ = m3.maintain();
    try testing.expectEqual(@as(i64, 365 * day), f3.rec.last_retry_at - f3.clock.t);
}

test "backoff: a certificate that ends within the hour is retried in a minute, never in the past" {
    var f: Fixture = undefined;
    f.init(day0 + 90 * day - 1800);
    defer f.deinit();
    try f.mem.storage().store("certificates/a.example.pem", comptime (fx.a1_key ++ "\n" ++ chainOf(fx.a1_crt)));
    var fake: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "CA down" } }} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 1), f.rec.failed);
    try testing.expectEqual(@as(i64, 60), f.rec.last_retry_at - f.clock.t);
}

test "backoff: a success resets the failure count and the retry time" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{
        .{ .fail = .{ .problem = "boom" } },
        .{ .fail = .{ .problem = "boom" } },
        .{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } },
        .{ .fail = .{ .problem = "boom" } },
    } };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    _ = m.maintain();
    f.clock.t = f.rec.last_retry_at;
    _ = m.maintain();
    f.clock.t = f.rec.last_retry_at;
    try testing.expectEqual(day0 + 60 * day, m.maintain()); // issued; next due is the renewal, not a stale retry
    f.clock.t = day0 + 60 * day;
    _ = m.maintain(); // renewal fails: the FIRST failure of this certificate
    try testing.expectEqual(@as(i64, 60), f.rec.last_retry_at - f.clock.t);
}

test "adoptStored: a stored certificate exactly at its renewal point is renewed, not taken as done" {
    var f: Fixture = undefined;
    f.init(day0 + 60 * day);
    defer f.deinit();
    try f.mem.storage().store("certificates/a.example.pem", comptime (fx.a1_key ++ "\n" ++ chainOf(fx.a1_crt)));
    var fake: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "CA down" } }} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 1), fake.calls);
}

/// A storage that lets another node finish its issuance the moment ours takes
/// the lock (the window between the first look and the lock).
const RacingStorage = struct {
    inner: *storage.MemStorage,
    fired: bool = false,

    const vt: storage.Storage.VTable = .{
        .load = load,
        .store = store,
        .delete = delete,
        .create = null,
        .tryLock = tryLock,
        .unlock = unlock,
    };
    fn storageOf(r: *RacingStorage) storage.Storage {
        return .{ .ptr = r, .vtable = &vt };
    }
    fn of(p: *anyopaque) *RacingStorage {
        return @ptrCast(@alignCast(p));
    }
    fn load(p: *anyopaque, gpa: Allocator, key: []const u8) storage.Error![]u8 {
        return of(p).inner.storage().load(gpa, key);
    }
    fn store(p: *anyopaque, key: []const u8, value: []const u8) storage.Error!void {
        return of(p).inner.storage().store(key, value);
    }
    fn delete(p: *anyopaque, key: []const u8) storage.Error!void {
        return of(p).inner.storage().delete(key);
    }
    fn tryLock(p: *anyopaque, name: []const u8, owner: []const u8, now: i64, lease_s: u32) storage.Error!bool {
        const r = of(p);
        const got = try r.inner.storage().tryLock(name, owner, now, lease_s);
        if (!r.fired) {
            r.fired = true;
            try r.inner.storage().store("certificates/a.example.pem", comptime (fx.a1_key ++ "\n" ++ chainOf(fx.a1_crt)));
        }
        return got;
    }
    fn unlock(p: *anyopaque, name: []const u8, owner: []const u8) void {
        of(p).inner.storage().unlock(name, owner);
    }
};

test "fleet: a result stored while we were taking the lock is adopted, not ordered again" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var racing: RacingStorage = .{ .inner = &f.mem };
    var fake: FakeIssuer = .{ .script = &.{} };
    var o = opts();
    o.storage = racing.storageOf();
    var m = Manager.init(f.threaded.io(), testing.allocator, .{
        .storage = o.storage,
        .clock = f.clock.clock(),
        .on_event = f.rec.hook(),
        .random_seed = 7,
        .node_id = "node-a",
    });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try m.manage(a_names);
    _ = m.maintain();
    try testing.expect(racing.fired);
    try testing.expectEqual(@as(usize, 0), fake.calls);
    try testing.expectEqual(Manager.Event.Source.storage, f.rec.last_source.?);
}

test "issue: problems name what is wrong; the longest Retry-After of several issuers wins" {
    { // no issuer at all
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var m = f.manager(opts());
        defer m.deinit();
        try m.manage(a_names);
        _ = m.maintain();
        try testing.expectEqual(@as(usize, 1), f.rec.failed);
        try testing.expect(f.rec.problemIs("no issuer configured"));
    }
    { // the key is not the certificate's
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a2_key } }} };
        var m = f.manager(opts());
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try m.manage(a_names);
        _ = m.maintain();
        try testing.expect(f.rec.problemIs("issued certificate does not match its key"));
    }
    { // already expired
        var f: Fixture = undefined;
        f.init(day0 + 95 * day);
        defer f.deinit();
        var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }} };
        var m = f.manager(opts());
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try m.manage(a_names);
        _ = m.maintain();
        try testing.expect(f.rec.problemIs("issued certificate is not valid now"));
    }
    { // two issuers both refuse; the longer Retry-After counts, whichever came last
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var first: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "limit", .retry_after_s = 7200 } }} };
        var second: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "down", .retry_after_s = 60 } }} };
        var m = f.manager(opts());
        defer m.deinit();
        try m.addIssuer(first.issuer(false));
        try m.addIssuer(second.issuer(false));
        try m.manage(a_names);
        _ = m.maintain();
        try testing.expectEqual(@as(i64, 7200), f.rec.last_retry_at - f.clock.t);
    }
}

const UnmanagingIssuer = struct {
    m: *Manager,
    fn issue(ctx: *anyopaque, gpa: Allocator, req: *const Manager.IssueRequest, diag: *Manager.Diagnostics) Manager.IssueError!Manager.Issued {
        const s: *UnmanagingIssuer = @ptrCast(@alignCast(ctx));
        _ = req;
        _ = diag;
        _ = s.m.unmanage("a.example"); // while this very issuance is in flight
        const chain = try gpa.dupe(u8, chainOf(fx.a1_crt));
        errdefer gpa.free(chain);
        return .{ .chain_pem = chain, .key_pem = try gpa.dupe(u8, fx.a1_key), .not_after = 0 };
    }
};

test "unmanage during an issuance: the result is neither stored nor reported" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var m = f.manager(opts());
    defer m.deinit();
    var ui: UnmanagingIssuer = .{ .m = &m };
    try m.addIssuer(.{ .ctx = &ui, .name = "unmanaging", .issue = UnmanagingIssuer.issue });
    try m.manage(a_names);
    _ = m.maintain();
    try testing.expectEqual(@as(usize, 0), f.rec.installed);
    try testing.expectEqual(@as(usize, 0), f.mem.count());
}

test "maintain: nothing managed looks again in an hour" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    var m = f.manager(opts());
    defer m.deinit();
    try testing.expectEqual(day0 + 3600, m.maintain());
}

test "names: 100 per certificate, IP literals, storage stems for wildcards and IPv6" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.wild_crt), .key = fx.wild_key } }} };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));

    var bufs: [101][16]u8 = undefined;
    var names: [101][]const u8 = undefined;
    for (&names, &bufs, 0..) |*n, *b, i| n.* = std.mem.print(b, "n{d}.example", .{i}) catch unreachable;
    try testing.expectError(error.InvalidName, m.manage(names[0..101]));
    // The wildcard certificate comes first: the single scripted certificate goes to the first entry.
    try m.manage(&.{ "*.w.example", "w.example" });
    try m.manage(names[0..100]);

    try m.manage(&.{"192.0.2.1"});
    try m.manage(&.{"2001:db8::1"});
    // an IPv6 name's lock is keyed by its storage stem, ':' written '+': held by another node, it defers us
    try testing.expect(try f.mem.storage().tryLock("issue/2001+db8++1", "node-b", f.clock.t, 900));
    _ = m.maintain();
    // the wildcard certificate landed under its `_` stem
    const blob = try f.mem.storage().load(testing.allocator, "certificates/_.w.example.pem");
    testing.allocator.free(blob);
    // one certificate per manage() call: the wildcard one, the 100-name one and the IPv4 one asked the
    // issuer; the IPv6 one, whose lock another node holds, did not
    try testing.expectEqual(@as(usize, 3), fake.calls);
}

test "unmanage: a 253-character name is found" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    var m = f.manager(opts());
    defer m.deinit();
    const long = strRepeat((strRepeat("a", 63) ++ "."), 3) ++ (strRepeat("a", 61));
    try testing.expectEqual(@as(usize, 253), long.len);
    try m.manage(&.{long});
    try testing.expect(m.unmanage(long));
}

test "HTTP-01 edges: HEAD, a 256-character token, host validation, redirect targets, no storage fallback unless distributed" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    var m = f.manager(.{ .storage = undefined, .http_redirect = true });
    defer m.deinit();
    const solvers = m.challengeSolvers();
    try solvers[0].present(solvers[0].ctx, &challenge_req);
    const tok256 = strRepeat("a", 256);
    try m.http_tokens.set(tok256, "KA256");
    try m.http_tokens.set(strRepeat("b", 257), "KA257");
    // A value only another node would know (storage), without `distributed_challenges`.
    try f.mem.storage().store("challenges/http-01/stored", "FROMSTORAGE");

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(m.httpMiddleware());
    try r.get("/", hApp);
    var buf: [2048]u8 = undefined;

    const head = runWire(&r, "HEAD /.well-known/acme-challenge/tok-123_ABC HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200"));
    const t256 = runWire(&r, "GET /.well-known/acme-challenge/" ++ tok256 ++ " HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.endsWith(u8, t256, "KA256"));
    const t257 = runWire(&r, "GET /.well-known/acme-challenge/" ++ (strRepeat("b", 257)) ++ " HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, t257, "HTTP/1.1 404"));
    const local_only = runWire(&r, "GET /.well-known/acme-challenge/stored HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, local_only, "HTTP/1.1 404"));

    // host: '/' is not a host character; an IPv6 literal keeps its brackets; the LAST colon starts the port
    const slash = runWire(&r, "GET / HTTP/1.1\r\nHost: a.example/evil\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, slash, "HTTP/1.1 400"));
    const brk = runWire(&r, "GET / HTTP/1.1\r\nHost: [a/b]:80\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, brk, "HTTP/1.1 400"));
    const v6 = runWire(&r, "GET /p HTTP/1.1\r\nHost: [::1]:80\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.find(u8, v6, "\r\nLocation: https://[::1]/p\r\n") != null);
    const colons = runWire(&r, "GET / HTTP/1.1\r\nHost: a.example:1:2\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.find(u8, colons, "\r\nLocation: https://a.example:1/\r\n") != null);
    // 0x21 is the first byte a redirect target may carry
    const bang = runWire(&r, "GET /!x HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, bang, "HTTP/1.1 302"));
    try testing.expect(std.mem.find(u8, bang, "\r\nLocation: https://a.example/!x\r\n") != null);
}

test "HTTP-01 distributed: a stored key authorization exactly as long as the buffer is served" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    var m = f.manager(.{ .storage = undefined, .distributed_challenges = true });
    defer m.deinit();
    const v = strRepeat("k", jws.max_key_authorization_len);
    try f.mem.storage().store("challenges/http-01/full", v);
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(m.httpMiddleware());
    try r.get("/", hApp);
    var buf: [2048]u8 = undefined;
    const got = runWire(&r, "GET /.well-known/acme-challenge/full HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.endsWith(u8, got, v));
}

test "TLS-ALPN-01: without distributed_challenges the storage copy of another node is not consulted" {
    var f: Fixture = undefined;
    f.init(day0);
    defer f.deinit();
    var m = f.manager(.{ .storage = undefined, .distributed_challenges = true });
    defer m.deinit();
    var plain = f.manager(.{ .storage = undefined });
    defer plain.deinit();
    const solvers = m.challengeSolvers();
    var req = challenge_req;
    req.type = .tls_alpn_01;
    try solvers[1].present(solvers[1].ctx, &req);
    try testing.expectEqual(@as(?Client.TlsAlpnResponder.Material, null), try plain.tlsAlpnMaterial(testing.allocator, "a.example"));
}

test "on-demand rate limit: max 0 allows nothing; the window is exclusive at its far end" {
    var policy: Policy = .{};
    { // max 0
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var fake: FakeIssuer = .{ .script = &.{.{ .ok = .{ .chain = chainOf(fx.od1_crt), .key = fx.od1_key } }} };
        var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow, .rate = .{ .max = 0, .window_s = 60 } } });
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od.example"));
        try testing.expectEqual(@as(usize, 0), fake.calls);
    }
    { // one per 60 s: exactly 60 s later the next one is allowed
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var fake: FakeIssuer = .{ .script = &.{
            .{ .ok = .{ .chain = chainOf(fx.od1_crt), .key = fx.od1_key } },
            .{ .ok = .{ .chain = chainOf(fx.od2_crt), .key = fx.od2_key } },
        } };
        var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow, .rate = .{ .max = 1, .window_s = 60 } } });
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try expectServes(&m, "od.example", chainOf(fx.od1_crt));
        f.clock.t += 59;
        try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od2.example"));
        f.clock.t += 1;
        try expectServes(&m, "od2.example", chainOf(fx.od2_crt));
    }
}

test "issuerName: a trailing slash is not part of the name" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("ca.example-dir", Manager.issuerName(&buf, "https://ca.example/dir/"));
}

fn renewAtOf(m: *Manager) i64 {
    m.mutex.lockUncancelable(m.io);
    defer m.mutex.unlock(m.io);
    return m.entries.items[0].renew_at;
}

test "ARI: an end-only change re-picks, a window past the end clamps, Retry-After has a floor and a cap" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{
        .script = &.{.{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } }},
        .ari_window = .{ .start = day0 + 40 * day, .end = day0 + 41 * day, .retry_after_s = 5 },
    };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(true));
    try m.manage(a_names);
    _ = m.maintain(); // issued
    try testing.expectEqual(f.clock.t + 60, m.maintain()); // Retry-After 5 s is raised to a minute
    const first_pick = renewAtOf(&m);

    fake.ari_window.?.end = day0 + 45 * day; // same start, later end
    f.clock.t += 60;
    _ = m.maintain();
    try testing.expect(renewAtOf(&m) != first_pick);

    // A window after the certificate's end: renew an hour before it ends; Retry-After capped at a week.
    fake.ari_window = .{ .start = day0 + 200 * day, .end = day0 + 200 * day, .retry_after_s = 8 * day };
    f.clock.t += 60;
    const next = m.maintain();
    try testing.expectEqual(day0 + 90 * day - 3600, renewAtOf(&m));
    try testing.expectEqual(f.clock.t + 7 * day, next);
}

test "ARI: a renewed certificate takes the CA's window again, even an unchanged one" {
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{
        .script = &.{
            .{ .ok = .{ .chain = chainOf(fx.a1_crt), .key = fx.a1_key } },
            .{ .ok = .{ .chain = chainOf(fx.a2_crt), .key = fx.a2_key } },
        },
        .ari_window = .{ .start = day0 + 40 * day, .end = day0 + 41 * day, .retry_after_s = 3600 },
    };
    var m = f.manager(opts());
    defer m.deinit();
    try m.addIssuer(fake.issuer(true));
    try m.manage(a_names);
    _ = m.maintain(); // a1
    _ = m.maintain(); // window polled, renewal picked inside it
    f.clock.t = day0 + 42 * day;
    _ = m.maintain(); // due: a2 issued
    try expectServes(&m, "a.example", chainOf(fx.a2_crt));
    _ = m.maintain(); // the same window again, for the new certificate
    try testing.expect(renewAtOf(&m) < day0 + 100 * day); // a2's own 2/3 point is later than that
}

test "on-demand failures: the configured back-off applies to a name without a certificate only" {
    var policy: Policy = .{};
    { // no certificate yet: at least failure_backoff_s, here less than the first doubling step
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var fake: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "no" } }} };
        var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow, .failure_backoff_s = 30 } });
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od.example"));
        try testing.expectEqual(@as(i64, 60), f.rec.last_retry_at - f.clock.t);
    }
    { // no certificate yet and a long configured back-off: that one
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var fake: FakeIssuer = .{ .script = &.{.{ .fail = .{ .problem = "no" } }} };
        var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow, .failure_backoff_s = 300 } });
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od.example"));
        try testing.expectEqual(@as(i64, 300), f.rec.last_retry_at - f.clock.t);
    }
    { // with a certificate (a failed renewal): the ordinary back-off
        var f: Fixture = undefined;
        f.init(day0 + day);
        defer f.deinit();
        var fake: FakeIssuer = .{ .script = &.{
            .{ .ok = .{ .chain = chainOf(fx.od1_crt), .key = fx.od1_key } },
            .{ .fail = .{ .problem = "no" } },
        } };
        var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow, .failure_backoff_s = 300 } });
        defer m.deinit();
        try m.addIssuer(fake.issuer(false));
        try expectServes(&m, "od.example", chainOf(fx.od1_crt));
        f.clock.t = day0 + 61 * day;
        _ = m.maintain();
        try testing.expectEqual(@as(usize, 1), f.rec.failed);
        try testing.expectEqual(@as(i64, 60), f.rec.last_retry_at - f.clock.t);
    }
}

test "on-demand: a failed name is tried again exactly when its back-off ends" {
    var policy: Policy = .{};
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{
        .{ .fail = .{ .problem = "no" } },
        .{ .ok = .{ .chain = chainOf(fx.od1_crt), .key = fx.od1_key } },
    } };
    var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow, .failure_backoff_s = 300 } });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od.example"));
    const retry_at = f.rec.last_retry_at;
    f.clock.t = retry_at - 1;
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "od.example"));
    try testing.expectEqual(@as(usize, 1), fake.calls);
    f.clock.t = retry_at;
    try expectServes(&m, "od.example", chainOf(fx.od1_crt));
    try testing.expectEqual(@as(usize, 2), fake.calls);
}

test "certificate: malformed names never reach the policy; a 253-character name does" {
    var policy: Policy = .{};
    var f: Fixture = undefined;
    f.init(day0 + day);
    defer f.deinit();
    var fake: FakeIssuer = .{ .script = &.{} };
    var m = f.manager(.{ .storage = undefined, .on_demand = .{ .ctx = &policy, .allow = Policy.allow } });
    defer m.deinit();
    try m.addIssuer(fake.issuer(false));
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, "bad name.example"));
    try testing.expectEqual(@as(usize, 0), policy.asked);
    const long = strRepeat((strRepeat("a", 63) ++ "."), 3) ++ (strRepeat("a", 53)) ++ ".example";
    try testing.expectEqual(@as(usize, 253), long.len);
    try testing.expectEqual(@as(?Manager.Material, null), try m.certificate(testing.allocator, long));
    try testing.expectEqual(@as(usize, 1), policy.asked); // asked: the name was not too long
    // and the same for the TLS-ALPN-01 lookup of a 253-character SNI
    try m.tls_alpn.set(long, "der", "pem");
    var mat = (try m.tlsAlpnMaterial(testing.allocator, long)).?;
    mat.deinit(testing.allocator);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}

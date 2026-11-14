// SPDX-License-Identifier: MIT

//! `Dns01Solver` without a network: the zone given, CNAME following and the
//! propagation check off, so every DNS question is answered by the options
//! and what is left is the solver's own bookkeeping — the record the
//! publisher sees, what is kept for cleanup, and what a failure leaves
//! behind. The DNS half runs against a live server in `tools/interop.zig`.

const std = @import("std");
const acme = @import("acme");
const root = @import("root.zig");
const Dns01Solver = root.Dns01Solver;

const testing = std.testing;

const Fake = struct {
    presented: std.ArrayList([]const u8) = .empty,
    cleaned: std.ArrayList([]const u8) = .empty,
    fail: bool = false,
    last: ?root.Record = null,
    fqdn_copy: [256]u8 = undefined,
    zone_copy: [256]u8 = undefined,

    fn publisher(f: *Fake) root.Publisher {
        return .{ .ctx = f, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, rec: *const root.Record) root.PublishError!void {
        const f: *Fake = @ptrCast(@alignCast(ctx.?));
        if (f.fail) return error.PublishFailed;
        try f.presented.append(testing.allocator, try testing.allocator.dupe(u8, rec.value));
        f.last = rec.*;
        @memcpy(f.fqdn_copy[0..rec.fqdn.len], rec.fqdn);
        @memcpy(f.zone_copy[0..rec.zone.len], rec.zone);
        f.last.?.fqdn = f.fqdn_copy[0..rec.fqdn.len];
        f.last.?.zone = f.zone_copy[0..rec.zone.len];
    }

    fn cleanup(ctx: ?*anyopaque, rec: *const root.Record) void {
        const f: *Fake = @ptrCast(@alignCast(ctx.?));
        f.cleaned.append(testing.allocator, testing.allocator.dupe(u8, rec.value) catch unreachable) catch unreachable;
    }

    fn deinit(f: *Fake) void {
        for (f.presented.items) |v| testing.allocator.free(v);
        for (f.cleaned.items) |v| testing.allocator.free(v);
        f.presented.deinit(testing.allocator);
        f.cleaned.deinit(testing.allocator);
    }
};

fn offline(f: *Fake) Dns01Solver.Options {
    return .{
        .publisher = f.publisher(),
        .zone = "example.org.",
        .follow_cname = false,
        .check_propagation = false,
    };
}

test "present: the record the publisher gets, value as RFC 8555 §8.4 computes it" {
    var f: Fake = .{};
    defer f.deinit();
    var s = Dns01Solver.init(std.testing.io, testing.allocator, offline(&f));
    defer s.deinit();

    // RFC 8555 §8.4's own example token; the value is checked against the
    // separate `jws.dns01TxtValue` path, not the solver's.
    const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    var ka_buf: [acme.jws.max_key_authorization_len]u8 = undefined;
    const ka = try std.mem.print(&ka_buf, "{s}.{s}", .{ token, "nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypzEt62jcerQ" });
    try s.present("Example.org", token, ka);

    const rec = f.last.?;
    try testing.expectEqualStrings("_acme-challenge.Example.org", rec.fqdn);
    try testing.expectEqualStrings("example.org", rec.zone);
    try testing.expectEqualStrings("Example.org", rec.domain);
    try testing.expectEqualStrings(token, rec.token);
    try testing.expectEqualStrings(ka, rec.key_authorization);
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(ka, &sha, .{});
    var want: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&want, &sha);
    try testing.expectEqualStrings(&want, rec.value);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());

    // Cleanup by domain (any case) + value; an unknown pair is ignored.
    s.cleanup("example.org", "not-the-value");
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    s.cleanup("EXAMPLE.ORG", &want);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
    try testing.expectEqual(@as(usize, 1), f.cleaned.items.len);
    try testing.expectEqualStrings(&want, f.cleaned.items[0]);
}

test "present: a wildcard and its base keep two records at one name, cleaned one by one" {
    var f: Fake = .{};
    defer f.deinit();
    var s = Dns01Solver.init(std.testing.io, testing.allocator, offline(&f));
    defer s.deinit();
    try s.present("example.org", "tok-a", "tok-a.thumb");
    try s.present("example.org", "tok-b", "tok-b.thumb");
    try testing.expectEqual(@as(usize, 2), s.pendingCount());
    const second = acme.jws.dns01TxtValueFromKeyAuthorization("tok-b.thumb");
    s.cleanup("example.org", &second);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    try testing.expectEqualStrings(&second, f.cleaned.items[0]);
}

test "present: a failing publisher leaves nothing pending and says why" {
    var f: Fake = .{ .fail = true };
    defer f.deinit();
    var s = Dns01Solver.init(std.testing.io, testing.allocator, offline(&f));
    defer s.deinit();
    try testing.expectError(error.PublishFailed, s.present("example.org", "t", "t.k"));
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
    try testing.expectEqualStrings("the publisher failed", s.note);
    // The update may have landed before the failure showed: cleaned up once.
    try testing.expectEqual(@as(usize, 1), f.cleaned.items.len);
}

test "solver(): the acme.Client.Solver maps errors and cleans up through the vtable" {
    var f: Fake = .{};
    defer f.deinit();
    var s = Dns01Solver.init(std.testing.io, testing.allocator, offline(&f));
    defer s.deinit();
    const v = s.solver();
    try testing.expectEqual(acme.ChallengeType.dns_01, v.type);
    const req: acme.Client.ChallengeRequest = .{
        .type = .dns_01,
        .identifier = "example.org",
        .ip = false,
        .wildcard = true,
        .token = "tok",
        .key_authorization = "tok.thumb",
    };
    try v.present(v.ctx, &req);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    v.cleanup(v.ctx, &req);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
    f.fail = true;
    try testing.expectError(error.SolverFailed, v.present(v.ctx, &req));
}

test "present: override_name replaces _acme-challenge.<domain>" {
    var f: Fake = .{};
    defer f.deinit();
    var o = offline(&f);
    o.override_name = "example-org.acme.delegated.test.";
    o.zone = "acme.delegated.test.";
    var s = Dns01Solver.init(std.testing.io, testing.allocator, o);
    defer s.deinit();
    try s.present("example.org", "t", "t.k");
    try testing.expectEqualStrings("example-org.acme.delegated.test", f.last.?.fqdn);
    try testing.expectEqualStrings("example.org", f.last.?.domain);
}

test "present: an over-long zone override is refused before publishing" {
    var f: Fake = .{};
    defer f.deinit();
    var o = offline(&f);
    const long: [300]u8 = @splat('a');
    o.zone = &long;
    var s = Dns01Solver.init(std.testing.io, testing.allocator, o);
    defer s.deinit();
    try testing.expectError(error.NameTooLong, s.present("example.org", "t", "t.k"));
    try testing.expectEqual(@as(usize, 0), f.presented.items.len);
}

test "present: a name outside Options.zone is refused before publishing" {
    var f: Fake = .{};
    defer f.deinit();
    var o = offline(&f);
    o.override_name = "example-org.acme.delegated.test.";
    var s = Dns01Solver.init(std.testing.io, testing.allocator, o);
    defer s.deinit();
    try testing.expectError(error.ZoneNotFound, s.present("example.org", "t", "t.k"));
    try testing.expectEqual(@as(usize, 0), f.presented.items.len);
    try testing.expectEqualStrings("the challenge name is not inside Options.zone", s.note);
    // A label boundary, not a string suffix: "badexample.org" is not in "example.org".
    o.override_name = "_acme-challenge.badexample.org";
    var s2 = Dns01Solver.init(std.testing.io, testing.allocator, o);
    defer s2.deinit();
    o.zone = "example.org";
    try testing.expectError(error.ZoneNotFound, s2.present("example.org", "t", "t.k"));
}

// ── mutation-run tests (2026-11-14) ──────────────────────────────────────────

/// Counts calls and logs the cleaned records' domains.
const Dom = struct {
    presents: u32 = 0,
    log: [128]u8 = undefined,
    log_len: usize = 0,
    fail: bool = false,

    fn publisher(d: *Dom) root.Publisher {
        return .{ .ctx = d, .present = present, .cleanup = cleanup };
    }
    fn present(ctx: ?*anyopaque, _: *const root.Record) root.PublishError!void {
        const d: *Dom = @ptrCast(@alignCast(ctx.?));
        if (d.fail) return error.PublishFailed;
        d.presents += 1;
    }
    fn cleanup(ctx: ?*anyopaque, rec: *const root.Record) void {
        const d: *Dom = @ptrCast(@alignCast(ctx.?));
        if (d.log_len != 0) {
            d.log[d.log_len] = ',';
            d.log_len += 1;
        }
        @memcpy(d.log[d.log_len..][0..rec.domain.len], rec.domain);
        d.log_len += rec.domain.len;
    }
    fn cleaned(d: *const Dom) []const u8 {
        return d.log[0..d.log_len];
    }
};

fn domOptions(d: *Dom) Dns01Solver.Options {
    return .{ .publisher = d.publisher(), .zone = "example.org", .follow_cname = false, .check_propagation = false };
}

test "cleanup: matches domain AND value; one record per call, whatever is behind it" {
    var d: Dom = .{};
    var s = Dns01Solver.init(std.testing.io, testing.allocator, domOptions(&d));
    defer s.deinit();
    const v = acme.jws.dns01TxtValueFromKeyAuthorization("t.k");
    try s.present("a.example.org", "t", "t.k");
    try s.present("b.example.org", "t", "t.k"); // same value, other domain
    s.cleanup("B.example.org.", &v); // case and a trailing dot do not matter
    try testing.expectEqualStrings("b.example.org", d.cleaned());
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    s.cleanup("b.example.org", &v); // gone: ignored
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    // The same pair twice (a retried challenge): one cleanup removes one.
    try s.present("a.example.org", "t", "t.k");
    s.cleanup("a.example.org", &v);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    s.cleanup("a.example.org.", &v);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
}

test "present: note is reset by the next call; a failed allocation is OutOfMemory through the vtable" {
    var d: Dom = .{ .fail = true };
    var s = Dns01Solver.init(std.testing.io, testing.allocator, domOptions(&d));
    defer s.deinit();
    try testing.expectError(error.PublishFailed, s.present("a.example.org", "t", "t.k"));
    try testing.expect(s.note.len != 0);
    d.fail = false;
    try s.present("a.example.org", "t", "t.k");
    try testing.expectEqualStrings("", s.note);

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var s2 = Dns01Solver.init(std.testing.io, failing.allocator(), domOptions(&d));
    defer s2.deinit();
    const v = s2.solver();
    const req: acme.Client.ChallengeRequest = .{
        .type = .dns_01,
        .identifier = "a.example.org",
        .ip = false,
        .wildcard = false,
        .token = "t",
        .key_authorization = "t.k",
    };
    try testing.expectError(error.OutOfMemory, v.present(v.ctx, &req));
}

test "present: delay_ms waits after publishing" {
    var d: Dom = .{};
    var o = domOptions(&d);
    o.delay_ms = 300;
    var s = Dns01Solver.init(std.testing.io, testing.allocator, o);
    defer s.deinit();
    const t0 = std.Io.Clock.Timestamp.now(std.testing.io, .awake);
    try s.present("a.example.org", "t", "t.k");
    const took = t0.durationTo(std.Io.Clock.Timestamp.now(std.testing.io, .awake)).raw.toMilliseconds();
    try testing.expect(took >= 250);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
}

/// Notices when a block holding `needle` is freed without having been wiped.
const Spy = struct {
    inner: std.mem.Allocator,
    needle: []const u8,
    plain_free: bool = false,

    fn allocator(s: *Spy) std.mem.Allocator {
        return .{ .ptr = s, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const s: *Spy = @ptrCast(@alignCast(ctx));
        return s.inner.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const s: *Spy = @ptrCast(@alignCast(ctx));
        return s.inner.rawResize(m, a, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const s: *Spy = @ptrCast(@alignCast(ctx));
        return s.inner.rawRemap(m, a, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const s: *Spy = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, m, s.needle)) s.plain_free = true;
        s.inner.rawFree(m, a, ra);
    }
};

test "the key authorization is wiped before its copy is freed" {
    var spy: Spy = .{ .inner = testing.allocator, .needle = "tok.thumb" };
    var d: Dom = .{};
    var s = Dns01Solver.init(std.testing.io, spy.allocator(), domOptions(&d));
    defer s.deinit();
    try s.present("a.example.org", "tok", "tok.thumb");
    const v = acme.jws.dns01TxtValueFromKeyAuthorization("tok.thumb");
    s.cleanup("a.example.org", &v);
    try testing.expect(!spy.plain_free);
    // The control: the spy sees an unwiped free. Only without runtime
    // safety: `Allocator.free` overwrites the block with `undefined` before
    // the allocator sees it, which hides the wipe (and its absence) in safe
    // builds.
    if (!std.debug.runtime_safety) {
        const copy = try spy.allocator().dupe(u8, "tok.thumb");
        spy.allocator().free(copy);
        try testing.expect(spy.plain_free);
    }
}

test "present: a zone of exactly 253 bytes fits, 254 does not" {
    var d: Dom = .{};
    var o = domOptions(&d);
    var ok: [253]u8 = @splat('a');
    ok[2] = '.';
    o.zone = &ok;
    o.override_name = &ok;
    var s = Dns01Solver.init(std.testing.io, testing.allocator, o);
    defer s.deinit();
    try s.present("x.example.org", "t", "t.k");
    var long: [254]u8 = @splat('a');
    o.zone = &long;
    var s2 = Dns01Solver.init(std.testing.io, testing.allocator, o);
    defer s2.deinit();
    try testing.expectError(error.NameTooLong, s2.present("x.example.org", "t", "t.k"));
}

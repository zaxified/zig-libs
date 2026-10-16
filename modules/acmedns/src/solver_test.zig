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
    const ka = try std.fmt.bufPrint(&ka_buf, "{s}.{s}", .{ token, "nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypzEt62jcerQ" });
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

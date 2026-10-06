// SPDX-License-Identifier: MIT

//! OFFLINE replay of Pebble: what Let's Encrypt's ACME test CA answered the
//! real client in each scenario of `tools/pebble.sh` -- directory, nonces,
//! accounts, orders, authorizations, challenges, finalize, the issued chain,
//! its `badNonce` rejections and problem documents, with their Location,
//! Replay-Nonce, Retry-After and Link headers -- frozen in
//! `testdata/pebble_transcript.zig`. A plain-HTTP server answers the client
//! from it: each request gets the next recorded response for its method and
//! path (the last one again once they run out), with Pebble's URLs rewritten
//! to the replay's. The client must reach the same outcome it reached against
//! Pebble. No Pebble at test time.

const std = @import("std");
const testing = std.testing;
const http = @import("http");
const testkit = @import("testkit");
const acme = @import("root.zig");
const transcript = @import("testdata/pebble_transcript.zig");

const Replay = struct {
    scenario: []const u8,
    base: []const u8 = "",
    used: [transcript.exchanges.len]bool = @splat(false),
    served: usize = 0,
    bad_nonces: usize = 0,
    misses: usize = 0,
    lock: std.Io.Mutex = .init,

    /// The next unused recorded exchange for this request, else the last used one.
    fn pick(r: *Replay, method: []const u8, path: []const u8) ?usize {
        var last: ?usize = null;
        for (transcript.exchanges, 0..) |e, i| {
            if (!std.mem.eql(u8, e.scenario, r.scenario) or !std.ascii.eqlIgnoreCase(e.method, method) or
                !std.mem.eql(u8, e.path, path)) continue;
            if (!r.used[i]) {
                r.used[i] = true;
                return i;
            }
            last = i;
        }
        return last;
    }

    fn rewrite(r: *const Replay, gpa: std.mem.Allocator, text: []const u8) ![]u8 {
        return std.mem.replaceOwned(u8, gpa, text, transcript.origin, r.base);
    }
};

fn handler(req: *http.Server.Request, res: *http.Server.ResponseWriter) anyerror!void {
    const r: *Replay = @ptrCast(@alignCast(req.context.?));
    const gpa = testing.allocator;
    const at = blk: {
        r.lock.lockUncancelable(std.testing.io);
        defer r.lock.unlock(std.testing.io);
        const i = r.pick(@tagName(req.method), req.target) orelse {
            r.misses += 1;
            break :blk null;
        };
        r.served += 1;
        if (std.mem.indexOf(u8, transcript.exchanges[i].body, "badNonce") != null) r.bad_nonces += 1;
        break :blk i;
    };
    const e = transcript.exchanges[
        at orelse {
            res.setStatus(404);
            return res.writeAll("not in the transcript");
        }
    ];
    res.setStatus(e.status);
    var link: std.ArrayList(u8) = .empty;
    defer link.deinit(gpa);
    for (e.headers) |h| {
        const v = try r.rewrite(gpa, h.value);
        defer gpa.free(v);
        if (std.ascii.eqlIgnoreCase(h.name, "Link")) {
            // Repeated in the transcript; one field, list syntax (RFC 9110 §5.3).
            if (link.items.len != 0) try link.appendSlice(gpa, ", ");
            try link.appendSlice(gpa, v);
        } else try res.setHeader(h.name, v);
    }
    if (link.items.len != 0) try res.setHeader("Link", link.items);
    const body = try r.rewrite(gpa, e.body);
    defer gpa.free(body);
    try res.writeAll(body);
}

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

const Zone = struct {
    fn present(_: ?*anyopaque, _: []const u8, _: []const u8) bool {
        return true;
    }
    fn cleanup(_: ?*anyopaque, _: []const u8, _: []const u8) void {}
};

const Outcome = union(enum) { issued: []const []const u8, failed: struct { err: anyerror, problem: []const u8 } };

fn replayScenario(name: []const u8, domains: []const []const u8, challenge: acme.Client.ChallengeType, want: Outcome) !usize {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var replay: Replay = .{ .scenario = name };
    var server = http.Server.init(io, testing.allocator, .{ .handler = handler, .context = &replay });
    defer server.deinit();
    server.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    var base_buf: [64]u8 = undefined;
    replay.base = try std.fmt.bufPrint(&base_buf, "http://127.0.0.1:{d}", .{server.boundAddress().getPort()});
    var dir_buf: [80]u8 = undefined;
    const dir_url = try std.fmt.bufPrint(&dir_buf, "{s}/dir", .{replay.base});
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    var transport = http.Client.init(io, testing.allocator, .{});
    defer transport.deinit();
    var client = acme.Client.init(io, testing.allocator, &transport, try acme.jws.Es256.KeyPair.generateDeterministic(@splat(7)), .{
        .directory_url = dir_url,
        .challenge_type = challenge,
        .dns_publisher = if (challenge == .dns_01) .{ .present = Zone.present, .cleanup = Zone.cleanup } else null,
        .poll_interval_ms = 1,
        .max_polls = 20,
    });
    defer client.deinit();

    switch (want) {
        .issued => |names| {
            var cert = try client.obtain(domains);
            defer cert.deinit(testing.allocator);
            // The chain is Pebble's, byte for byte: what its certZ answered.
            const recorded = for (transcript.exchanges) |e| {
                if (std.mem.eql(u8, e.scenario, name) and e.status == 200 and
                    std.mem.startsWith(u8, e.path, "/certZ/")) break e.body;
            } else return error.NoRecordedChain;
            try testing.expectEqualStrings(recorded, cert.chain_pem);
            _ = names;
            try testing.expect(cert.not_after > 1_700_000_000);
            // Every proof was withdrawn again.
            try testing.expectEqual(@as(usize, 0), client.challengeResponder().count());
            try testing.expectEqual(@as(usize, 0), client.tlsAlpnResponder().count());
        },
        .failed => |f| {
            try testing.expectError(f.err, client.obtain(domains));
            try testing.expect(std.mem.startsWith(u8, client.lastProblem() orelse "", f.problem));
        },
    }
    try testing.expectEqual(@as(usize, 0), replay.misses);
    return replay.bad_nonces;
}

test "Pebble replay: the client reaches Pebble's outcome on Pebble's own answers" {
    var bad_nonces: usize = 0;
    bad_nonces += try replayScenario("http01", &.{"a.test"}, .http_01, .{ .issued = &.{"a.test"} });
    bad_nonces += try replayScenario("http01-san", &.{ "a.test", "b.test" }, .http_01, .{ .issued = &.{ "a.test", "b.test" } });
    bad_nonces += try replayScenario("dns01-wildcard", &.{"*.w.test"}, .dns_01, .{ .issued = &.{"*.w.test"} });
    bad_nonces += try replayScenario("tlsalpn01", &.{"t.test"}, .tls_alpn_01, .{ .issued = &.{"t.test"} });
    bad_nonces += try replayScenario("http01-unreachable", &.{"n.test"}, .http_01, .{ .failed = .{
        .err = error.AuthorizationFailed,
        .problem = "urn:ietf:params:acme:error:connection: ",
    } });
    bad_nonces += try replayScenario("rejected", &.{"blocked.test"}, .http_01, .{ .failed = .{
        .err = error.AcmeProblem,
        .problem = "urn:ietf:params:acme:error:rejectedIdentifier: ",
    } });
    // Pebble rejected some nonces (PEBBLE_WFE_NONCEREJECT=15 in tools/pebble.sh)
    // and the client retried through every one of them.
    try testing.expect(bad_nonces >= 1);
}

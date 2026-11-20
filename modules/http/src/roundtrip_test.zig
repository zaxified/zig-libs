// SPDX-License-Identifier: MIT

//! `Client.Options.round_tripper` and `Client.synthetic`: a client with no
//! network. Every test here is socket-free.

const std = @import("std");
const testing = std.testing;

const http = @import("root.zig");
const Client = @import("Client.zig");

const Rig = struct {
    calls: u32 = 0,
    last_path: [64]u8 = undefined,
    last_path_len: usize = 0,
    last_method: http.Method = .get,
    last_body_len: ?usize = null,

    fn trip(ctx: ?*anyopaque, c: *Client, req: Client.RoundTripRequest) Client.Error!Client.Response {
        const r: *Rig = @ptrCast(@alignCast(ctx.?));
        r.calls += 1;
        @memcpy(r.last_path[0..req.url.path.len], req.url.path);
        r.last_path_len = req.url.path.len;
        r.last_method = req.method;
        r.last_body_len = if (req.body) |b| b.len else null;
        if (std.mem.eql(u8, req.url.path, "/old")) {
            return c.synthetic(.{ .status = 302, .headers = &.{.{ .name = "Location", .value = "/new" }} });
        }
        if (std.mem.eql(u8, req.url.path, "/loop")) {
            return c.synthetic(.{ .status = 302, .headers = &.{.{ .name = "Location", .value = "/loop" }} });
        }
        if (std.mem.eql(u8, req.url.path, "/gone")) return c.synthetic(.{ .status = 404, .body = "nope" });
        return c.synthetic(.{ .headers = &.{.{ .name = "X-Seen", .value = "yes" }}, .body = "canned" });
    }
};

fn client(io: std.Io, rig: *Rig) Client {
    return Client.init(io, testing.allocator, .{ .round_tripper = .{ .ctx = rig, .round_trip = Rig.trip } });
}

test "round_tripper: a request is answered with no socket, head and body as built" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var rig: Rig = .{};
    var c = client(threaded.io(), &rig);
    defer c.deinit();

    var res = try c.request(.get, "http://example.invalid/hello", .{});
    defer res.deinit();
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("OK", res.reason);
    try testing.expectEqualStrings("yes", res.header("x-seen").?);
    try testing.expectEqualStrings("6", res.header("content-length").?);
    const body = try res.readAllAlloc(testing.allocator, 100);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("canned", body);
    try testing.expectEqual(@as(u32, 1), rig.calls);

    // The same over `requestPlain`, and https is refused there.
    var p = try c.requestPlain(.get, "http://example.invalid/gone", .{});
    defer p.deinit();
    try testing.expectEqual(@as(u16, 404), p.status);
    try testing.expectError(error.UnsupportedScheme, c.requestPlain(.get, "https://example.invalid/", .{}));
}

test "round_tripper: redirects are followed hop by hop, a 302 turns a POST into a GET" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var rig: Rig = .{};
    var c = client(threaded.io(), &rig);
    defer c.deinit();

    var res = try c.request(.post, "http://example.invalid/old", .{ .body = "payload" });
    defer res.deinit();
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqual(@as(u32, 2), rig.calls);
    try testing.expectEqualStrings("/new", rig.last_path[0..rig.last_path_len]);
    try testing.expectEqual(http.Method.get, rig.last_method);
    try testing.expectEqual(@as(?usize, null), rig.last_body_len);

    var rig2: Rig = .{};
    var c2 = client(threaded.io(), &rig2);
    defer c2.deinit();
    try testing.expectError(error.TooManyRedirects, c2.request(.get, "http://example.invalid/loop", .{}));
    try testing.expectEqual(@as(u32, c2.options.max_redirects) + 1, rig2.calls);

    // follow_redirects = false hands the 302 back.
    var rig3: Rig = .{};
    var c3 = client(threaded.io(), &rig3);
    defer c3.deinit();
    var r3 = try c3.request(.get, "http://example.invalid/old", .{ .follow_redirects = false });
    defer r3.deinit();
    try testing.expectEqual(@as(u16, 302), r3.status);
    try testing.expectEqual(@as(u32, 1), rig3.calls);
}

test "synthetic: no body for 204, a bad header is refused, nothing leaks" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var c = Client.init(threaded.io(), testing.allocator, .{});
    defer c.deinit();

    var r = try c.synthetic(.{ .status = 204, .body = "ignored" });
    defer r.deinit();
    const body = try r.readAllAlloc(testing.allocator, 10);
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(usize, 0), body.len);
    try testing.expect(r.header("content-length") == null);

    try testing.expectError(error.InvalidHeader, c.synthetic(.{ .headers = &.{.{ .name = "X", .value = "a\r\nb: c" }} }));
    try testing.expectError(error.InvalidHeader, c.synthetic(.{ .headers = &.{.{ .name = "", .value = "a" }} }));
}

test "synthetic: an interceptor answers by itself" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const I = struct {
        fn intercept(_: ?*anyopaque, chain: *Client.Chain) Client.Error!Client.Response {
            return chain.client.synthetic(.{ .status = 418, .body = "short-circuited" });
        }
    };
    const list = [_]Client.Interceptor{.{ .intercept = I.intercept }};
    var c = Client.init(threaded.io(), testing.allocator, .{ .interceptors = &list });
    defer c.deinit();
    var res = try c.request(.get, "http://example.invalid/", .{});
    defer res.deinit();
    try testing.expectEqual(@as(u16, 418), res.status);
    const body = try res.readAllAlloc(testing.allocator, 100);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("short-circuited", body);
}

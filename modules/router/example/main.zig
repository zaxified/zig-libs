// SPDX-License-Identifier: MIT

//! What an HTTP API server does with `router`: register a param route, a
//! prefixed group with its own middleware, and a static-file wildcard, then
//! drive real request bytes through the dispatcher and print the response —
//! socket-free, the same way the module's own tests exercise it, via
//! `http.Server.serveStream`.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `router` (or `http`) does not export.

const std = @import("std");
const http = @import("http");
const router = @import("router");

fn hUser(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("user=");
    try ctx.res.writeAll(ctx.params.get("id").?);
}

fn hStatic(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("static file: ");
    try ctx.res.writeAll(ctx.params.get("path").?);
}

fn mwStamp(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    try ctx.res.setHeader("X-Api-Version", "v1");
    try next.run(ctx);
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var r = router.Router.init(gpa);
    defer r.deinit();

    try r.get("/users/:id", hUser);
    try r.get("/static/*path", hStatic);

    // A prefixed group carries its own middleware, run inside the router's
    // own chain — a version header stamped on every /api/* response.
    const api = try r.group("/api");
    try api.use(.{ .run = mwStamp });
    try api.get("/users/:id", hUser);

    // Registering the identical (method, pattern) twice is a caller mistake
    // the router names rather than silently overwriting the first handler
    // or panicking — a route table built from config data needs this to be
    // catchable by name.
    if (r.get("/users/:id", hUser)) |_| {
        return error.DuplicateRouteUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.DuplicateRoute => std.debug.print("duplicate route rejected (DuplicateRoute)\n", .{}),
        else => return err,
    }

    var buf: [1024]u8 = undefined;

    const got1 = runWire(&r, request("GET", "/users/42"), &buf);
    std.debug.print("GET /users/42       -> {s}\n", .{got1});

    const got2 = runWire(&r, request("GET", "/api/users/7"), &buf);
    std.debug.print("GET /api/users/7    -> {s}\n", .{got2});
    std.debug.print("  has X-Api-Version: {}\n", .{std.mem.indexOf(u8, got2, "X-Api-Version: v1") != null});

    const got3 = runWire(&r, request("GET", "/static/css/app.css"), &buf);
    std.debug.print("GET /static/css/... -> {s}\n", .{got3});

    // A registered path with the wrong method: 405, with Allow listing what
    // IS registered there.
    const got4 = runWire(&r, request("DELETE", "/users/42"), &buf);
    std.debug.print("DELETE /users/42    -> {s}\n", .{got4});
}

fn request(comptime method: []const u8, comptime target: []const u8) []const u8 {
    return method ++ " " ++ target ++ " HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n";
}

/// Drive the router through the socket-free server codec with canned wire
/// bytes; returns the full response byte stream (headers + body).
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

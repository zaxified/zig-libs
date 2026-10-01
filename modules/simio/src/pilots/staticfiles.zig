// SPDX-License-Identifier: MIT

//! Pilot: `staticfiles.Handler` behind the real `http.Server`, reached by the
//! real `http.Client`, serving a tree on the simulated disk that holds
//! symbolic links — one inside the root, one pointing out of it at a secret.
//!
//! The property is the module's own make-or-break one: no response ever
//! carries a byte from outside the root, whatever the path says — a symlink,
//! a `..` walk, its percent-encoding. With links not followed (the default)
//! every link is refused; with them followed the inside one is served and
//! the escaping one still refused. A handler that sanitizes the path as text
//! and then opens it (no real-path check) is caught leaking the secret.

const std = @import("std");
const http = @import("http");
const staticfiles = @import("staticfiles");
const sched = @import("../sched.zig");

const Io = std.Io;
const net = Io.net;
const Dir = Io.Dir;
const Sim = sched.Sim;
const testing = std.testing;

const secret = "TOP-SECRET-KEY";

const Mode = enum { default, follow, naive };

/// The text-only handler: `sanitizePath` and an open that follows links.
fn naiveHandler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const s: *const Server = @ptrCast(@alignCast(req.context.?));
    var buf: [256]u8 = undefined;
    const rel = staticfiles.sanitizePath(req.path, &buf, .{}) catch return rw.setStatus(400);
    var out: [256]u8 = undefined;
    const data = s.root.readFile(s.io, rel, &out) catch return rw.setStatus(404);
    try rw.writeAll(data);
}

const Server = struct {
    mode: Mode,
    io: Io = undefined,
    root: Dir = undefined,
    handler: staticfiles.Handler = undefined,
};

fn serverMain(io: Io, gpa: std.mem.Allocator, s: *Server) !void {
    s.io = io;
    s.root = try Dir.cwd().openDir(io, "/srv/www", .{});
    s.handler = .init(io, s.root, .{ .follow_symlinks = s.mode == .follow });
    var srv = http.Server.init(io, gpa, .{
        .handler = if (s.mode == .naive) naiveHandler else staticfiles.httpHandler,
        .context = if (s.mode == .naive) @ptrCast(s) else @ptrCast(&s.handler),
        .addr = "0.0.0.0",
        .port = 80,
        .tcp_nodelay = false,
    });
    defer srv.deinit();
    try srv.bind();
    try srv.serve();
}

const Probe = struct {
    path: []const u8,
    status: u16 = 0,
    body: [256]u8 = undefined,
    len: usize = 0,

    fn bodySlice(p: *const Probe) []const u8 {
        return p.body[0..p.len];
    }
};

fn clientMain(io: Io, gpa: std.mem.Allocator, probes: []Probe) !void {
    try io.sleep(.fromMilliseconds(10), .awake);
    var c = http.Client.init(io, gpa, .{});
    defer c.deinit();
    for (probes) |*p| {
        var ub: [128]u8 = undefined;
        const url = try std.fmt.bufPrint(&ub, "http://files{s}", .{p.path});
        var res = try c.request(.get, url, .{});
        defer res.deinit();
        p.status = res.status;
        const body = try res.readAllAlloc(gpa, 1 << 16);
        defer gpa.free(body);
        p.len = @min(body.len, p.body.len);
        @memcpy(p.body[0..p.len], body[0..p.len]);
    }
}

fn run(mode: Mode, probes: []Probe) !void {
    var sim: Sim = undefined;
    sim.init(testing.allocator, .{ .seed = 9, .stack_size = 1024 * 1024 });
    defer sim.deinit();
    const s = try sim.addHost(.{ .name = "files" });
    const c = try sim.addHost(.{});
    try sim.link(s, c, .{ .latency_ns = 2 * std.time.ns_per_ms });
    try s.putFile("/srv/www/index.html", "<h1>home</h1>");
    try s.putFile("/srv/www/app.js", "console.log(1)");
    try s.putFile("/srv/secret.txt", secret);
    try s.spawn(makeLinks, .{s.io()});
    var server: Server = .{ .mode = mode };
    try s.spawn(serverMain, .{ s.io(), s.allocator(), &server });
    try c.spawn(clientMain, .{ c.io(), c.allocator(), probes });
    _ = sim.runFor(10 * std.time.ns_per_s);
    if (c.failure) |err| return err;
}

fn makeLinks(io: Io) !void {
    const www = try Dir.cwd().openDir(io, "/srv/www", .{});
    defer www.close(io);
    try www.symLink(io, "app.js", "inside.js", .{});
    try www.symLink(io, "../secret.txt", "escape.txt", .{});
    try www.symLink(io, "/srv", "up", .{ .is_directory = true });
}

fn probeSet() [7]Probe {
    return .{
        .{ .path = "/" },
        .{ .path = "/app.js" },
        .{ .path = "/inside.js" },
        .{ .path = "/escape.txt" },
        .{ .path = "/up/secret.txt" },
        .{ .path = "/../secret.txt" },
        .{ .path = "/%2e%2e/secret.txt" },
    };
}

fn expectNoSecret(probes: []const Probe) !void {
    for (probes) |p| {
        if (std.mem.indexOf(u8, p.bodySlice(), secret) != null) return error.SecretLeaked;
    }
}

test "pilot staticfiles: by default every symlink is refused and nothing leaves the root" {
    var probes = probeSet();
    try run(.default, &probes);
    try testing.expectEqual(@as(u16, 200), probes[0].status);
    try testing.expectEqualStrings("<h1>home</h1>", probes[0].bodySlice());
    try testing.expectEqualStrings("console.log(1)", probes[1].bodySlice());
    for (probes[2..5]) |p| try testing.expectEqual(@as(u16, 403), p.status);
    try expectNoSecret(&probes);
}

test "pilot staticfiles: with links followed the inside one is served, the escaping ones still refused" {
    var probes = probeSet();
    try run(.follow, &probes);
    try testing.expectEqual(@as(u16, 200), probes[2].status);
    try testing.expectEqualStrings("console.log(1)", probes[2].bodySlice());
    try testing.expect(probes[3].status >= 400 and probes[4].status >= 400);
    try expectNoSecret(&probes);
}

test "pilot staticfiles: a handler that only sanitizes the text leaks through a symlink, and the check sees it" {
    var probes = probeSet();
    try run(.naive, &probes);
    try testing.expectError(error.SecretLeaked, expectNoSecret(&probes));
}

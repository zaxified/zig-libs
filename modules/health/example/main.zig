// SPDX-License-Identifier: MIT

//! What a `router`-fronted service does with `health`: wire the middleware
//! in front of an app route, drive liveness and readiness probes over real
//! HTTP/1.1 wire bytes (`http.Server.serveStream`, offline, no sockets) --
//! liveness staying 200 while a dependency is down (the two signals are
//! orthogonal, on purpose), a dependency that reports unhealthy (503 +
//! its name) and its recovery back to 200, `detail = false` hiding names
//! without changing the status, HEAD probes (the module's own test suite
//! only ever covered GET), the 512-byte detail-body cap truncating instead
//! of growing under many simultaneous failures (the capacity pressure
//! path), and real concurrent probing from several OS threads against one
//! shared `Health` instance while a dependency flag flips underneath them.
//! `health` allocates nothing and its own surface has no error union
//! (`Check.checkFn` returns `bool`, `middleware()` cannot fail) -- so the
//! named-error and allocator-failure requirements are met one layer down,
//! on the `router` it is wired into. Everything runs under a
//! leak-checking allocator (there is nothing for `health` itself to leak;
//! the allocator belongs to the `router`/`http` scaffolding around it).
//!
//! This is an example in the gate sense -- it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps`:
//! `router`, `http`; no `test_deps`, no private declarations).

const std = @import("std");
const health = @import("health");
const router = @import("router");
const http = @import("http");

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [4096]u8 = undefined;
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

fn wire(comptime method: []const u8, comptime target: []const u8) []const u8 {
    return method ++ " " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn statusOf(got: []const u8) u16 {
    return std.fmt.parseInt(u16, got[9..12], 10) catch 0;
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

fn hApp(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("app");
}

/// The dependency the readiness check watches -- a plain atomic flag, the
/// module's documented contract for `CheckFn` (non-blocking, thread-safe,
/// no live ping per probe).
var db_ready = std.atomic.Value(bool).init(true);
fn dbCheck(_: ?*anyopaque) bool {
    return db_ready.load(.acquire);
}

/// A check that always fails, used to build the truncation scenario: many
/// distinct names, one shared function pointer.
fn failAlways(_: ?*anyopaque) bool {
    return false;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var checks = [_]health.Check{.{ .name = "database", .checkFn = dbCheck }};
    var h = health.Health{ .checks = &checks };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/", hApp);

    // 1. Liveness and readiness are orthogonal: with the dependency down,
    // liveness must still answer 200 (the process itself is fine -- a
    // liveness failure means "restart me", which this outage does not
    // warrant), while readiness answers 503 (take it out of rotation).
    {
        db_ready.store(false, .release);
        var buf: [2048]u8 = undefined;
        const live = runWire(&r, wire("GET", "/healthz"), &buf);
        std.debug.assert(statusOf(live) == 200);
        const ready = runWire(&r, wire("GET", "/readyz"), &buf);
        std.debug.assert(statusOf(ready) == 503);
        std.debug.assert(std.mem.eql(u8, bodyOf(ready), "not ready: database\n"));
        std.debug.print("liveness 200 + readiness 503: the two signals stayed independent\n", .{});
    }

    // 2. Recovery: once the dependency flag flips back, the very next probe
    // reflects it -- no caching, no sticky failure.
    {
        db_ready.store(true, .release);
        var buf: [2048]u8 = undefined;
        const ready = runWire(&r, wire("GET", "/readyz"), &buf);
        std.debug.assert(statusOf(ready) == 200);
        std.debug.assert(std.mem.eql(u8, bodyOf(ready), "OK\n"));
        std.debug.print("recovery: readiness returned to 200 as soon as the dependency did\n", .{});
    }

    // 3. HEAD is a probe method too (the module's own doc says GET/HEAD;
    // its own test suite, before this, only ever drove GET).
    {
        var buf: [2048]u8 = undefined;
        std.debug.assert(statusOf(runWire(&r, wire("HEAD", "/healthz"), &buf)) == 200);
        db_ready.store(false, .release);
        std.debug.assert(statusOf(runWire(&r, wire("HEAD", "/readyz"), &buf)) == 503);
        db_ready.store(true, .release);
        std.debug.print("HEAD probes on both paths behave like GET\n", .{});
    }

    // 4. A non-probe path and a non-probe method on a probe path both flow
    // through untouched -- the middleware only ever intercepts exactly the
    // two configured paths under GET/HEAD.
    {
        var buf: [2048]u8 = undefined;
        const app = runWire(&r, wire("GET", "/"), &buf);
        std.debug.assert(std.mem.eql(u8, bodyOf(app), "app"));
        const posted = runWire(&r, "POST /readyz HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", &buf);
        std.debug.assert(statusOf(posted) == 404); // no POST /readyz route registered
    }

    // 5. `detail = false`: the status is unchanged but the dependency name
    // is no longer published -- for a probe reachable from outside the
    // cluster, per the module's own threat-model note.
    {
        var checks2 = [_]health.Check{.{ .name = "database", .checkFn = dbCheck }};
        var h2 = health.Health{ .checks = &checks2, .detail = false };
        var r2 = router.Router.init(gpa);
        defer r2.deinit();
        try r2.use(h2.middleware());

        db_ready.store(false, .release);
        var buf: [2048]u8 = undefined;
        const down = runWire(&r2, wire("GET", "/readyz"), &buf);
        std.debug.assert(statusOf(down) == 503);
        std.debug.assert(std.mem.eql(u8, bodyOf(down), "not ready\n"));
        std.debug.assert(std.mem.indexOf(u8, down, "database") == null);
        db_ready.store(true, .release);
        std.debug.print("detail=false: 503 preserved, dependency name withheld\n", .{});
    }

    // 6. Capacity pressure on the fixed 512-byte detail buffer: many
    // simultaneous failures overflow it, and the body is truncated with a
    // marker instead of growing unbounded (this module never allocates --
    // the whole body lives on the stack).
    {
        var many: [40]health.Check = undefined;
        var names: [40][8]u8 = undefined;
        for (&many, 0..) |*c, i| {
            names[i] = undefined;
            const name = std.fmt.bufPrint(&names[i], "dep{d:0>3}", .{i}) catch unreachable;
            c.* = .{ .name = name, .checkFn = failAlways };
        }
        var h3 = health.Health{ .checks = &many };
        var r3 = router.Router.init(gpa);
        defer r3.deinit();
        try r3.use(h3.middleware());

        var buf: [4096]u8 = undefined;
        const down = runWire(&r3, wire("GET", "/readyz"), &buf);
        std.debug.assert(statusOf(down) == 503);
        const body = bodyOf(down);
        std.debug.assert(std.mem.endsWith(u8, body, "not ready: ...\n")); // truncation marker
        std.debug.assert(std.mem.indexOf(u8, body, "dep000") != null); // earliest failures survive
        std.debug.assert(std.mem.indexOf(u8, body, "dep039") == null); // the last one did not fit
        std.debug.print("capacity: {d} simultaneous failures truncated the 512-byte detail body ({d} bytes)\n", .{ many.len, body.len });
    }

    // 7. Concurrent, repeated operation: several real OS threads probing
    // ONE shared `Health` instance while the dependency flag flips
    // underneath them -- the documented thread-safety contract
    // (`checkFn` runs on the connection thread) exercised with genuine
    // concurrency, not just sequential calls.
    {
        const Flipper = struct {
            fn run(stop: *std.atomic.Value(bool)) void {
                while (!stop.load(.acquire)) {
                    const cur = db_ready.load(.acquire);
                    db_ready.store(!cur, .release);
                }
            }
        };
        const Prober = struct {
            fn run(rr: *router.Router, seen_200: *std.atomic.Value(u32), seen_503: *std.atomic.Value(u32)) void {
                var i: usize = 0;
                while (i < 2_000) : (i += 1) {
                    var buf: [2048]u8 = undefined;
                    const got = runWire(rr, wire("GET", "/readyz"), &buf);
                    switch (statusOf(got)) {
                        200 => _ = seen_200.fetchAdd(1, .seq_cst),
                        503 => _ = seen_503.fetchAdd(1, .seq_cst),
                        else => unreachable,
                    }
                }
            }
        };

        var stop = std.atomic.Value(bool).init(false);
        var seen_200 = std.atomic.Value(u32).init(0);
        var seen_503 = std.atomic.Value(u32).init(0);
        const flipper = try std.Thread.spawn(.{}, Flipper.run, .{&stop});

        var provers: [4]std.Thread = undefined;
        for (&provers) |*t| t.* = try std.Thread.spawn(.{}, Prober.run, .{ &r, &seen_200, &seen_503 });
        for (provers) |t| t.join();
        stop.store(true, .release);
        flipper.join();
        db_ready.store(true, .release);

        std.debug.assert(seen_200.load(.seq_cst) + seen_503.load(.seq_cst) == 4 * 2_000);
        std.debug.print("concurrency: 4 threads x 2000 probes raced a flipping dependency ({d} ok / {d} down), no crash\n", .{ seen_200.load(.seq_cst), seen_503.load(.seq_cst) });
    }

    // 8. `health` itself has no error union to catch (`Check.checkFn`
    // returns `bool`, `middleware()` cannot fail) and never allocates --
    // so the named-error and allocator-failure requirements are reached
    // one layer down, on the `router` this middleware is wired into (a
    // real consumer's actual failure mode: registration).
    {
        // 8a. A duplicate route registration, handled by name.
        var r4 = router.Router.init(gpa);
        defer r4.deinit();
        try r4.use(h.middleware());
        try r4.get("/dup", hApp);
        if (r4.get("/dup", hApp)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.DuplicateRoute => std.debug.print("duplicate route rejected: DuplicateRoute (expected)\n", .{}),
            else => return err,
        }
    }
    {
        // 8b. Allocator forced to fail partway through an allocating call:
        // registering a route on a router built over a FailingAllocator.
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        var r5 = router.Router.init(failing.allocator());
        defer r5.deinit();
        if (r5.get("/t", hApp)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("route registration under a FailingAllocator: OutOfMemory (expected)\n", .{}),
            else => return err,
        }
    }

    std.debug.print("health example done\n", .{});
}

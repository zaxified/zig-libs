// SPDX-License-Identifier: MIT

//! What a `router`-fronted API does with `throttle`: run the bare semaphore
//! through a capacity/release lifecycle, wire the middleware over real
//! HTTP/1.1 wire bytes (`http.Server.serveStream`, offline, no sockets) for
//! the pass-through/503/recovery cycle and for a handler that errors, drive
//! the bounded-wait path both ways (a release inside the window hands over
//! the slot; nobody releasing sheds once the deadline is honored), fill the
//! bounded waiter queue so a further arrival sheds instantly instead of
//! waiting, hammer one shared `Throttle` from real OS threads to prove the
//! cap is never exceeded under genuine concurrency, and -- since `throttle`'s
//! own surface returns `bool`/`void`, never an error union -- reach a NAMED
//! error one layer down, on the `router` this middleware is wired into
//! (`DuplicateRoute`, then `OutOfMemory` forced with
//! `std.testing.FailingAllocator`). Everything runs under a leak-checking
//! allocator.
//!
//! This is an example in the gate sense -- it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only:
//! `router`, `http`; no `test_deps`, no private declarations).

const std = @import("std");
const throttle = @import("throttle");
const router = @import("router");
const http = @import("http");

fn sleepMs(io: std.Io, ms: u32) !void {
    const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake };
    d.sleep(io) catch return error.Canceled;
}

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

fn wire(comptime target: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn statusOf(got: []const u8) u16 {
    return std.fmt.parseInt(u16, got[9..12], 10) catch 0;
}

fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

fn hCount(ctx: *router.Ctx) anyerror!void {
    const n: *u32 = @ptrCast(@alignCast(ctx.state.?));
    n.* += 1;
    try ctx.res.writeAll("ok");
}

fn hBoom(_: *router.Ctx) anyerror!void {
    return error.Boom;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 1. Bare semaphore: acquire to the cap, further attempts fail and
    // consume nothing, one release frees exactly one slot, a full drain
    // returns to zero and the slots stay reusable.
    {
        var th: throttle.Throttle = .init(.{ .max_in_flight = 3 });
        defer th.deinit();
        std.debug.assert(th.tryAcquire());
        std.debug.assert(th.tryAcquire());
        std.debug.assert(th.tryAcquire());
        std.debug.assert(th.inFlight() == 3);

        std.debug.assert(!th.tryAcquire()); // capacity: shed, consumes nothing
        std.debug.assert(!th.tryAcquire());
        std.debug.assert(th.inFlight() == 3);

        th.release();
        std.debug.assert(th.inFlight() == 2);
        std.debug.assert(th.tryAcquire());
        std.debug.assert(!th.tryAcquire());

        th.release();
        th.release();
        th.release();
        std.debug.assert(th.inFlight() == 0);
        std.debug.assert(th.tryAcquire());
        th.release();
        std.debug.print("bare semaphore: capacity held exactly at 3, recovered after release\n", .{});
    }

    // 2. Middleware over real HTTP/1.1 wire bytes: pass-through when free,
    // 503 + Retry-After when saturated (the denied/rejected-request
    // pressure path), recovers after release. `tryAcquire`/`acquire`
    // return `bool`, not an error union -- `throttle` genuinely has no
    // error union on its public surface (see step 8 for where a NAMED
    // error is reached instead, one layer down on `router`).
    {
        var th: throttle.Throttle = .init(.{ .max_in_flight = 1 });
        defer th.deinit();
        var hits: u32 = 0;
        var r = router.Router.init(gpa);
        defer r.deinit();
        r.state = &hits;
        try r.use(th.middleware());
        try r.get("/t", hCount);

        var buf: [1024]u8 = undefined;
        std.debug.assert(statusOf(runWire(&r, wire("/t"), &buf)) == 200);
        std.debug.assert(hits == 1);

        std.debug.assert(th.tryAcquire()); // occupy the only slot
        const shed = runWire(&r, wire("/t"), &buf);
        std.debug.assert(statusOf(shed) == 503);
        std.debug.assert(headerValue(shed, "Retry-After") != null);
        std.debug.assert(hits == 1); // handler never ran

        th.release();
        std.debug.assert(statusOf(runWire(&r, wire("/t"), &buf)) == 200);
        std.debug.assert(hits == 2);
        std.debug.print("middleware: 200 when free, 503+Retry-After when saturated, recovers after release\n", .{});
    }

    // 3. A worker (handler) that returns an error: the slot is still
    // released via `defer` -- the server answers 500, and the throttle is
    // immediately reusable, not wedged at "still held".
    {
        var th: throttle.Throttle = .init(.{ .max_in_flight = 1 });
        defer th.deinit();
        var r = router.Router.init(gpa);
        defer r.deinit();
        try r.use(th.middleware());
        try r.get("/boom", hBoom);

        var buf: [1024]u8 = undefined;
        std.debug.assert(statusOf(runWire(&r, wire("/boom"), &buf)) == 500);
        std.debug.assert(th.inFlight() == 0); // released despite the error
        std.debug.assert(th.tryAcquire());
        th.release();
        std.debug.print("handler error: slot still released, server answered 500\n", .{});
    }

    // 4. Bounded wait: a release inside the window hands the slot to the
    // waiter instead of shedding.
    {
        var th: throttle.Throttle = .init(.{
            .max_in_flight = 1,
            .max_wait_ms = 5_000, // far away: success must come via release
            .io = io,
        });
        defer th.deinit();
        std.debug.assert(th.tryAcquire()); // saturate

        const Releaser = struct {
            fn run(t: *throttle.Throttle, io_: std.Io) void {
                sleepMs(io_, 30) catch {};
                t.release();
            }
        };
        const releaser = try std.Thread.spawn(.{}, Releaser.run, .{ &th, io });
        defer releaser.join();

        std.debug.assert(th.acquire()); // woken well before the 5s deadline
        std.debug.assert(th.inFlight() == 1);
        th.release();
        std.debug.print("bounded wait: a release inside the window handed over the slot\n", .{});
    }

    // 5. Bounded wait, the closest this module has to "expiry": nobody
    // releases, so the wait sheds once its full deadline has been honored.
    {
        var th: throttle.Throttle = .init(.{
            .max_in_flight = 1,
            .max_wait_ms = 80,
            .io = io,
        });
        defer th.deinit();
        std.debug.assert(th.tryAcquire()); // saturate for good
        const t0 = throttle.Clock.monotonic.now();
        std.debug.assert(!th.acquire()); // parks, then sheds at the deadline
        const elapsed_ms = (throttle.Clock.monotonic.now() - t0) / std.time.ns_per_ms;
        std.debug.assert(elapsed_ms >= 80);
        std.debug.assert(th.waiting() == 0);
        th.release();
        std.debug.print("bounded wait: deadline honored ({d}ms), then shed\n", .{elapsed_ms});
    }

    // 6. Waiter-queue capacity, distinct from `max_in_flight`: with the
    // queue already full, a further arrival sheds immediately without
    // waiting at all (the SEDA bounded-queue rule this module cites) --
    // then the parked waiter still wins once the slot is freed.
    {
        var th: throttle.Throttle = .init(.{
            .max_in_flight = 1,
            .max_wait_ms = 60_000,
            .max_waiters = 1,
            .io = io,
        });
        defer th.deinit();
        std.debug.assert(th.tryAcquire()); // saturate

        const Waiter = struct {
            fn run(t: *throttle.Throttle, got: *std.atomic.Value(u8)) void {
                got.store(if (t.acquire()) 1 else 2, .seq_cst);
            }
        };
        var got: std.atomic.Value(u8) = .init(0);
        const waiter = try std.Thread.spawn(.{}, Waiter.run, .{ &th, &got });
        defer waiter.join();

        var tries: usize = 0;
        while (th.waiting() != 1) : (tries += 1) {
            if (tries > 2000) return error.ExampleTimeout;
            try sleepMs(io, 5);
        }

        const t0 = throttle.Clock.monotonic.now();
        std.debug.assert(!th.acquire()); // queue full -> shed now, no wait
        const elapsed_ms = (throttle.Clock.monotonic.now() - t0) / std.time.ns_per_ms;
        std.debug.assert(elapsed_ms < 5_000); // nowhere near the 60s deadline

        th.release(); // frees the slot for the parked waiter
        tries = 0;
        while (got.load(.seq_cst) == 0) : (tries += 1) {
            if (tries > 2000) return error.ExampleTimeout;
            try sleepMs(io, 5);
        }
        std.debug.assert(got.load(.seq_cst) == 1);
        th.release(); // on the waiter's behalf
        std.debug.print("waiter-queue capacity: a full queue sheds instantly ({d}ms); the parked waiter still won\n", .{elapsed_ms});
    }

    // 7. Concurrent, repeated operation: real OS threads hammering
    // tryAcquire/release on ONE shared Throttle -- the in-flight count
    // must never exceed the cap, proven by a shared gauge, not printed.
    {
        const cap = 4;
        const n_threads = 8;
        const iters = 5_000;
        var th: throttle.Throttle = .init(.{ .max_in_flight = cap });
        defer th.deinit();

        const Shared = struct {
            gauge: std.atomic.Value(i32) = .init(0),
            violations: std.atomic.Value(u32) = .init(0),
        };
        const Worker = struct {
            fn run(t: *throttle.Throttle, s: *Shared) void {
                for (0..iters) |_| {
                    if (t.tryAcquire()) {
                        const cur = s.gauge.fetchAdd(1, .seq_cst) + 1;
                        if (cur > cap) _ = s.violations.fetchAdd(1, .seq_cst);
                        std.atomic.spinLoopHint();
                        _ = s.gauge.fetchSub(1, .seq_cst);
                        t.release();
                    }
                }
            }
        };
        var shared: Shared = .{};
        var handles: [n_threads]std.Thread = undefined;
        for (&handles) |*h| h.* = try std.Thread.spawn(.{}, Worker.run, .{ &th, &shared });
        for (handles) |h| h.join();
        std.debug.assert(shared.violations.load(.seq_cst) == 0);
        std.debug.assert(th.inFlight() == 0);
        std.debug.print("concurrency: {d} threads x {d} iters hammering one Throttle, cap {d} never exceeded\n", .{ n_threads, iters, cap });
    }

    // 8. `throttle`'s own surface returns `bool`/`void`, never an error
    // union -- the named-error and allocator-failure requirements are met
    // one layer down, on the `router` this middleware is wired into (a
    // real consumer's actual failure mode: wiring `throttle` onto a
    // `Router` is what allocates).
    {
        // 8a. A duplicate route registration, handled by name.
        var th: throttle.Throttle = .init(.{ .max_in_flight = 1 });
        defer th.deinit();
        var r = router.Router.init(gpa);
        defer r.deinit();
        try r.use(th.middleware());
        try r.get("/t", hCount);
        if (r.get("/t", hCount)) |_| {
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
        var r2 = router.Router.init(failing.allocator());
        defer r2.deinit();
        if (r2.get("/t", hCount)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("route registration under a FailingAllocator: OutOfMemory (expected)\n", .{}),
            else => return err,
        }
    }

    std.debug.print("throttle example done\n", .{});
}

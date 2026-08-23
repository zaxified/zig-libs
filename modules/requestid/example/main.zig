// SPDX-License-Identifier: MIT

//! What a `router`-fronted service does with `requestid`: wire the
//! middleware first (outermost) in front of an app route and a route that
//! 404s, drive ID generation + propagation over real HTTP/1.1 wire bytes
//! (`http.Server.serveStream`, offline, no sockets) -- a generated ID
//! echoed back and visible to the handler via `current()`, uniqueness
//! across repeated requests, an inbound `X-Request-Id` that must be
//! honoured (an edge-assigned ID kept intact across the hop), several
//! malformed inbound values that must NOT be honoured (the wave-2 audit
//! F1 regression: log-metacharacters that used to pass a looser filter),
//! the exact `max_adopt_len` boundary, `trust_incoming = false` ignoring
//! even a valid inbound value, `echo = false` keeping `current()` without
//! sending the header, a 404 short-circuit still carrying the ID (the
//! whole reason to register this middleware outermost), and real
//! concurrent traffic on several OS threads proving the thread-local
//! `current()` never bleeds across threads. `requestid` allocates nothing
//! and its own surface has no error union (`current()` returns an
//! optional, `middleware()` cannot fail) -- so the named-error and
//! allocator-failure requirements are met one layer down, on the `router`
//! it is wired into. Everything runs under a leak-checking allocator.
//!
//! This is an example in the gate sense -- it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps`:
//! `router`, `http`; no `test_deps`, no private declarations).

const std = @import("std");
const requestid = @import("requestid");
const router = @import("router");
const http = @import("http");

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

fn statusOf(got: []const u8) u16 {
    return std.fmt.parseInt(u16, got[9..12], 10) catch 0;
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
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

/// Echoes `current()` into the body -- proves the handler saw the same ID
/// the response header carries (the propagation half of the contract).
fn hEcho(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll(requestid.current() orelse "<none>");
}

fn wireGet(comptime target: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var ri = requestid.RequestId{};
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(ri.middleware()); // registered first/outermost, as documented
    try r.get("/", hEcho);

    // 1. Generation + propagation: no inbound ID -> a fresh 32-hex ID is
    // generated, echoed on the response, and visible to the handler via
    // current() -- the same value on both sides of the boundary.
    {
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, wireGet("/"), &buf);
        const hdr = headerValue(got, "X-Request-Id").?;
        std.debug.assert(hdr.len == requestid.generated_len);
        for (hdr) |c| std.debug.assert(std.ascii.isHex(c));
        std.debug.assert(std.mem.eql(u8, hdr, bodyOf(got)));
        std.debug.print("generated ID: {s} (echoed + matches current())\n", .{hdr});
    }

    // 2. Repeated operation: two requests never collide.
    {
        var b1: [1024]u8 = undefined;
        var b2: [1024]u8 = undefined;
        const id1 = headerValue(runWire(&r, wireGet("/"), &b1), "X-Request-Id").?;
        const id2 = headerValue(runWire(&r, wireGet("/"), &b2), "X-Request-Id").?;
        std.debug.assert(!std.mem.eql(u8, id1, id2));
        std.debug.print("two requests: distinct generated IDs\n", .{});
    }

    // 3. An inbound ID that MUST be honoured: an edge/ingress already
    // assigned one -- the middleware adopts it verbatim instead of
    // overwriting it, so a trace stays correlated across the hop.
    {
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "X-Request-Id: edge-abc-123\r\nConnection: close\r\n\r\n", &buf);
        std.debug.assert(std.mem.eql(u8, headerValue(got, "X-Request-Id").?, "edge-abc-123"));
        std.debug.assert(std.mem.eql(u8, bodyOf(got), "edge-abc-123"));
        std.debug.print("inbound ID honoured: edge-abc-123 propagated unchanged\n", .{});
    }

    // 4. Several inbound IDs that must NOT be honoured: each carries a
    // structured-log metacharacter the module deliberately excludes (the
    // wave-2 audit F1 regression this module's own source documents) --
    // every one falls back to a fresh generated ID instead of leaking the
    // raw value into current() (and from there, an unescaped log sink).
    {
        const malformed = [_][]const u8{
            "has spaces",
            "id,injected",
            "id\"injected\"",
            "id\\injected",
            "id{injected}",
        };
        for (malformed) |bad| {
            var req_buf: [1024]u8 = undefined;
            var resp_buf: [1024]u8 = undefined;
            const req = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: {s}\r\nConnection: close\r\n\r\n", .{bad}) catch unreachable;
            const got = runWire(&r, req, &resp_buf);
            const hdr = headerValue(got, "X-Request-Id").?;
            std.debug.assert(hdr.len == requestid.generated_len); // regenerated, not adopted
            std.debug.assert(!std.mem.eql(u8, hdr, bad));
        }
        std.debug.print("{d} malformed inbound IDs all rejected, fresh IDs generated instead\n", .{malformed.len});
    }

    // 5. The adopt-length boundary: exactly `max_adopt_len` is adopted
    // verbatim; one byte over is rejected like any other malformed value
    // (a bound, not a cliff the caller can silently overrun).
    {
        var req_buf: [1024]u8 = undefined;
        var resp_buf: [1024]u8 = undefined;

        const at_cap: [requestid.max_adopt_len]u8 = @splat('a');
        const req1 = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: {s}\r\nConnection: close\r\n\r\n", .{at_cap}) catch unreachable;
        const got1 = runWire(&r, req1, &resp_buf);
        std.debug.assert(std.mem.eql(u8, headerValue(got1, "X-Request-Id").?, &at_cap));

        const over_cap: [requestid.max_adopt_len + 1]u8 = @splat('a');
        const req2 = std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: {s}\r\nConnection: close\r\n\r\n", .{over_cap}) catch unreachable;
        const got2 = runWire(&r, req2, &resp_buf);
        const hdr2 = headerValue(got2, "X-Request-Id").?;
        std.debug.assert(hdr2.len == requestid.generated_len); // over the cap: regenerated
        std.debug.print("adopt-length boundary: exactly {d} bytes adopted, {d} bytes regenerated\n", .{ requestid.max_adopt_len, requestid.max_adopt_len + 1 });
    }

    // 6. `trust_incoming = false`: even a perfectly valid inbound ID is
    // ignored -- a service that does not trust its edge to assign IDs.
    {
        var ri2 = requestid.RequestId{ .options = .{ .trust_incoming = false } };
        var r2 = router.Router.init(gpa);
        defer r2.deinit();
        try r2.use(ri2.middleware());
        try r2.get("/", hEcho);

        var buf: [1024]u8 = undefined;
        const got = runWire(&r2, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "X-Request-Id: edge-xyz\r\nConnection: close\r\n\r\n", &buf);
        std.debug.assert(!std.mem.eql(u8, "edge-xyz", headerValue(got, "X-Request-Id").?));
        std.debug.print("trust_incoming=false: a valid inbound ID was still ignored\n", .{});
    }

    // 7. `echo = false`: the ID is available to the handler/log via
    // current(), but never sent to the client.
    {
        var ri3 = requestid.RequestId{ .options = .{ .echo = false } };
        var r3 = router.Router.init(gpa);
        defer r3.deinit();
        try r3.use(ri3.middleware());
        try r3.get("/", hEcho);

        var buf: [1024]u8 = undefined;
        const got = runWire(&r3, wireGet("/"), &buf);
        std.debug.assert(headerValue(got, "X-Request-Id") == null);
        std.debug.assert(bodyOf(got).len == requestid.generated_len); // current() still set
        std.debug.print("echo=false: no response header, current() still populated\n", .{});
    }

    // 8. Custom header name: read AND written under the configured name.
    {
        var ri4 = requestid.RequestId{ .options = .{ .header_name = "X-Correlation-Id" } };
        var r4 = router.Router.init(gpa);
        defer r4.deinit();
        try r4.use(ri4.middleware());
        try r4.get("/", hEcho);

        var buf: [1024]u8 = undefined;
        const got = runWire(&r4, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "X-Correlation-Id: trace-42\r\nConnection: close\r\n\r\n", &buf);
        std.debug.assert(std.mem.eql(u8, headerValue(got, "X-Correlation-Id").?, "trace-42"));
    }

    // 9. Registered outermost: a 404 short-circuit (no route matches) still
    // carries the ID -- the entire reason the module doc says "register
    // first". A denied/no-route response is not exempt from correlation.
    {
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, wireGet("/does-not-exist"), &buf);
        std.debug.assert(statusOf(got) == 404);
        const hdr = headerValue(got, "X-Request-Id").?;
        std.debug.assert(hdr.len == requestid.generated_len);
        std.debug.print("404 short-circuit still carried a request ID\n", .{});
    }

    // 10. Concurrent, repeated operation: several real OS threads driving
    // requests through the SAME shared (immutable, threadsafe) RequestId
    // config at once. Thread-local storage backs both the generated-ID
    // buffer and current() -- this proves no cross-thread bleed: every
    // thread's handler sees exactly the ID that thread's response header
    // carries, never another thread's.
    {
        const Worker = struct {
            fn run(rr: *router.Router, bad_out: *std.atomic.Value(u32)) void {
                var i: usize = 0;
                while (i < 500) : (i += 1) {
                    var buf: [1024]u8 = undefined;
                    const got = runWire(rr, wireGet("/"), &buf);
                    const hdr = headerValue(got, "X-Request-Id") orelse {
                        _ = bad_out.fetchAdd(1, .seq_cst);
                        continue;
                    };
                    if (!std.mem.eql(u8, hdr, bodyOf(got))) _ = bad_out.fetchAdd(1, .seq_cst);
                }
            }
        };
        var mismatches = std.atomic.Value(u32).init(0);
        var threads: [4]std.Thread = undefined;
        for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &r, &mismatches });
        for (threads) |t| t.join();
        std.debug.assert(mismatches.load(.seq_cst) == 0);
        std.debug.print("concurrency: 4 threads x 500 requests each, header always matched current() (no cross-thread bleed)\n", .{});
    }

    // 11. `requestid` itself has no error union to catch and never
    // allocates -- so the named-error and allocator-failure requirements
    // are reached one layer down, on the `router` this middleware is
    // wired into (a real consumer's actual failure mode: registration).
    {
        // 11a. A duplicate route registration, handled by name.
        var r5 = router.Router.init(gpa);
        defer r5.deinit();
        try r5.use(ri.middleware());
        try r5.get("/dup", hEcho);
        if (r5.get("/dup", hEcho)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.DuplicateRoute => std.debug.print("duplicate route rejected: DuplicateRoute (expected)\n", .{}),
            else => return err,
        }
    }
    {
        // 11b. Allocator forced to fail partway through an allocating call:
        // registering a route on a router built over a FailingAllocator.
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        var r6 = router.Router.init(failing.allocator());
        defer r6.deinit();
        if (r6.get("/t", hEcho)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("route registration under a FailingAllocator: OutOfMemory (expected)\n", .{}),
            else => return err,
        }
    }

    std.debug.print("requestid example done\n", .{});
}

// SPDX-License-Identifier: MIT

//! What a router-based API does with `cors`: mount it as global middleware
//! in front of a real `http.Server` on real loopback, then drive it with
//! `curl` -- an outside HTTP client that knows nothing about this module's
//! internals -- through the shapes the Fetch Standard's CORS protocol
//! actually cares about: a simple cross-origin GET, a preflight carrying
//! `Access-Control-Request-Method`/`-Headers`, an origin NOT on the
//! allow-list, and the one thing the standard forbids outright
//! (credentialed responses paired with the `*` wildcard origin).
//!
//! External judge, ACTUALLY RUN: `curl`, against a real `http.Server` +
//! `router` bound to `127.0.0.1` on an OS-chosen port -- loopback only, no
//! internet. `curl` neither knows nor cares this is `zig-libs`; it just
//! sends real HTTP/1.1 requests and this example reads the real response
//! headers that came back over the real socket.
//!
//! The credentials+wildcard rejection is NOT a wire behavior -- the Fetch
//! Standard's ban is enforced at `Cors.init`, before any request exists to
//! send -- so that one is checked directly against the module's own
//! `InitError`, no curl involved; RFC 9110/the Fetch Standard's own text is
//! the judge there, not a peer.
//!
//! Also exercises a real allocation-failure path *inside the module*:
//! `Cors.init` makes up to three allocations (methods/headers/exposed-
//! headers, each `errdefer`-guarded); a `FixedBufferAllocator` sized to fit
//! only the first is used to force the second to fail, and this example
//! checks the `FixedBufferAllocator`'s own accounting to prove the first
//! allocation was actually freed by `Cors.init`'s `errdefer`, not just that
//! `OutOfMemory` came back.
//!
//! Built against the PUBLISHED module (`@import("cors")`, `@import("router")`,
//! `@import("http")` -- its two declared deps) plus plain `std` for the
//! server socket/thread and the `curl` subprocess plumbing. `zig build
//! check-examples` builds this against exactly that surface.

const std = @import("std");
const router = @import("router");
const http = @import("http");
const cors = @import("cors");

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

// ── documented fixture: the Fetch Standard's own credentials+wildcard ban ──

/// The Fetch Standard forbids `Access-Control-Allow-Origin: *` on a
/// credentialed response; `Cors.init` enforces this itself rather than
/// emitting the spec-forbidden pair, so this is checked directly against
/// the module's `InitError` -- no live request illustrates a header that
/// can never be sent in the first place.
fn checkCredentialsWithWildcardRejected(gpa: std.mem.Allocator) !void {
    if (cors.Cors.init(gpa, .{ .allowed_origins = .any, .allow_credentials = true })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.CredentialsWithWildcardOrigin => std.debug.print(
            "Cors.init(.any, allow_credentials=true): CredentialsWithWildcardOrigin (expected -- Fetch Standard forbids the pair)\n",
            .{},
        ),
        else => return err,
    }
}

/// `Cors.init` makes up to three allocations in sequence (methods, then
/// `.list` headers, then exposed headers), each guarded by its own
/// `errdefer`. A `FixedBufferAllocator` sized to fit only the first
/// ("GET" = 3 bytes) forces the second (a 1-byte header-name join) to fail
/// -- if the first allocation's `errdefer` didn't run, the FBA's own
/// `end_index` would still show it live. This is a real allocating failure
/// path INSIDE the module, checked for a leak by inspecting the allocator's
/// own bookkeeping, not merely by getting `OutOfMemory` back.
fn checkAllocFailureCleansUpPartialInit(gpa: std.mem.Allocator) !void {
    const backing = try gpa.alloc(u8, 3); // exactly "GET".len, nothing spare
    defer gpa.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);

    if (cors.Cors.init(fba.allocator(), .{
        .allowed_methods = &.{.get}, // "GET" -- exactly fills `backing`
        .allowed_headers = .{ .list = &.{"X"} }, // one more byte -- none left
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.OutOfMemory => {
            if (fba.end_index != 0) return error.PartialAllocationLeaked;
            std.debug.print(
                "Cors.init with a 3-byte allocator (fits methods, not headers): OutOfMemory (expected), " ++
                    "FixedBufferAllocator.end_index == 0 -- the first allocation's errdefer actually ran\n",
                .{},
            );
        },
        else => return err,
    }
}

// ── live section: a real http.Server + router, driven by curl ─────────────

fn serveThreadMain(server: *http.Server) void {
    server.serve() catch {}; // returns once `shutdown()` is called below
}

fn readAll(io: std.Io, file: std.Io.File, out_buf: []u8) ![]const u8 {
    var rbuf: [256]u8 = undefined;
    var sr = file.reader(io, &rbuf);
    var total: usize = 0;
    while (true) {
        const n = try sr.interface.readSliceShort(out_buf[total..]);
        if (n == 0) break;
        total += n;
    }
    return out_buf[0..total];
}

fn runCurl(io: std.Io, argv: []const []const u8, out_buf: []u8) ![]const u8 {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .close,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    const out = try readAll(io, child.stdout.?, out_buf);
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.CurlFailed,
        else => return error.CurlFailed,
    }
    return out;
}

fn headerPresent(headers: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, headers, needle) != null;
}

fn runLiveChecks(io: std.Io, gpa: std.mem.Allocator) !void {
    var c: cors.Cors = try .init(gpa, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
        .allowed_methods = &.{ .get, .post },
        .allowed_headers = .{ .list = &.{"Content-Type"} },
        .exposed_headers = &.{"X-Request-Id"},
        .allow_credentials = true,
        .max_age_s = 600,
    });
    defer c.deinit();

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(c.middleware()); // GLOBAL, before routes -- the module's own rule
    try r.get("/api", hOk);

    var server: http.Server = .init(io, gpa, .{
        .handler = r.handler(),
        .context = &r,
        .addr = "127.0.0.1",
        .port = 0,
        .server_name = "cors-example/1.0",
    });
    defer server.deinit();
    try server.bind();
    const port = server.boundAddress().getPort();

    const server_thread = try std.Thread.spawn(.{}, serveThreadMain, .{&server});
    defer {
        server.shutdown();
        server_thread.join();
    }

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/api", .{port});
    var curl_buf: [2048]u8 = undefined;

    // ── simple request, allowed origin: ACAO echoed + Vary: Origin ────────
    {
        const out = try runCurl(io, &.{ "curl", "-sS", "-D-", "-o", "/dev/null", "-H", "Origin: https://app.example", url }, &curl_buf);
        if (!std.mem.startsWith(u8, out, "HTTP/1.1 200")) return error.SimpleRequestNot200;
        if (!headerPresent(out, "Access-Control-Allow-Origin: https://app.example")) return error.MissingAcao;
        if (!headerPresent(out, "Vary: Origin")) return error.MissingVaryOrigin;
        if (!headerPresent(out, "Access-Control-Allow-Credentials: true")) return error.MissingCredentials;
        if (!headerPresent(out, "Access-Control-Expose-Headers: X-Request-Id")) return error.MissingExposeHeaders;
        std.debug.print("curl simple GET, allowed origin: 200, ACAO + Vary: Origin + credentials + exposed headers all present\n", .{});
    }

    // ── preflight: Origin + Access-Control-Request-Method + -Headers ──────
    {
        const out = try runCurl(io, &.{
            "curl", "-sS",                         "-X", "OPTIONS",                             "-D-", "-o",                                           "/dev/null",
            "-H",   "Origin: https://app.example", "-H", "Access-Control-Request-Method: POST", "-H",  "Access-Control-Request-Headers: Content-Type", url,
        }, &curl_buf);
        if (!std.mem.startsWith(u8, out, "HTTP/1.1 204")) return error.PreflightNot204;
        if (!headerPresent(out, "Access-Control-Allow-Methods: GET, POST")) return error.MissingAllowMethods;
        if (!headerPresent(out, "Access-Control-Allow-Headers: Content-Type")) return error.MissingAllowHeaders;
        if (!headerPresent(out, "Access-Control-Max-Age: 600")) return error.MissingMaxAge;
        std.debug.print("curl preflight (ACRM+ACRH, allowed): 204 with the full CORS header set\n", .{});
    }

    // ── preflight requesting a header NOT on the allow-list: 204, no CORS
    // headers -- the browser's "no" (README: "a failing preflight is still
    // a 204 -- just without the headers") ──────────────────────────────────
    {
        const out = try runCurl(io, &.{
            "curl", "-sS",                         "-X", "OPTIONS",                             "-D-", "-o",                                     "/dev/null",
            "-H",   "Origin: https://app.example", "-H", "Access-Control-Request-Method: POST", "-H",  "Access-Control-Request-Headers: X-Evil", url,
        }, &curl_buf);
        if (!std.mem.startsWith(u8, out, "HTTP/1.1 204")) return error.PreflightNot204;
        if (headerPresent(out, "Access-Control-Allow-Origin")) return error.UnexpectedAcaoForDisallowedHeader;
        std.debug.print("curl preflight requesting a disallowed header: 204, no CORS headers (the gate's \"no\")\n", .{});
    }

    // ── origin NOT on the allow-list: handler still runs (200), no CORS
    // headers -- CORS withholds readability, never blocks handling ────────
    {
        const out = try runCurl(io, &.{ "curl", "-sS", "-D-", "-o", "/dev/null", "-H", "Origin: https://evil.example", url }, &curl_buf);
        if (!std.mem.startsWith(u8, out, "HTTP/1.1 200")) return error.DisallowedOriginRequestNot200;
        if (headerPresent(out, "Access-Control-Allow-Origin")) return error.UnexpectedAcaoForDisallowedOrigin;
        if (headerPresent(out, "Vary: Origin")) return error.UnexpectedVaryForDisallowedOrigin;
        std.debug.print("curl simple GET, disallowed origin: 200 (handler still ran), no CORS headers\n", .{});
    }
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    try checkCredentialsWithWildcardRejected(gpa);
    try checkAllocFailureCleansUpPartialInit(gpa);

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try runLiveChecks(io, gpa);

    std.debug.print("OK: all cors example checks passed\n", .{});
}

// SPDX-License-Identifier: MIT

//! What a `router`-fronted API does with `aaa-gate`: wire the middleware in
//! front of a mutation route and an exempt liveness route, then drive a
//! realistic mix of requests over real HTTP/1.1 wire bytes
//! (`http.Server.serveStream`, offline, no sockets) -- an allowed bearer
//! request, a missing-credential denial, a wrong/unknown-principal denial, a
//! malformed `Authorization` header, a revoked token (rotate out via
//! `removeToken`), the denied-request throttle coalescing repeated 401s from
//! one client key and folding the suppressed count into the next admitted
//! entry once the injected clock crosses the window, an exempt route that
//! never touches auth or audit, an `.either`-mode gate where a valid API key
//! admits and bearer takes precedence when both are present, the
//! denied-request throttle's bounded store evicting under a small
//! `throttle_max_keys`, and two allocator-failure paths (`Gate.init` and
//! `Gate.addToken`) forced with `std.testing.FailingAllocator`. Everything
//! runs under a leak-checking allocator.
//!
//! This is an example in the gate sense -- it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only:
//! `router`, `http`; no `test_deps`, no private declarations).

const std = @import("std");
const aaa_gate = @import("aaa-gate");
const router = @import("router");
const http = @import("http");

/// A fake, caller-controlled clock -- the module injects one so the
/// denied-request throttle's window accounting is deterministic and
/// offline. Same shape as `aaa_gate.Clock`: `.ctx` + `.nowFn`.
const FakeClock = struct {
    ns: u64 = 0,

    fn clock(fc: *FakeClock) aaa_gate.Clock {
        return .{ .ctx = fc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) u64 {
        const fc: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return fc.ns;
    }
    fn advanceMs(fc: *FakeClock, ms: u64) void {
        fc.ns += ms * std.time.ns_per_ms;
    }
};

/// What the audit hook records: since `AuditEntry`'s slices borrow
/// request-scoped memory, a hook that outlives the call copies only what it
/// needs (here, plain counters/scalars) instead of the slices themselves.
const AuditLog = struct {
    authed: u32 = 0,
    denied: u32 = 0,
    last_suppressed: u64 = 0,
};

fn onAudit(ctx: ?*anyopaque, entry: aaa_gate.AuditEntry) void {
    const log: *AuditLog = @ptrCast(@alignCast(ctx.?));
    if (entry.authed) {
        log.authed += 1;
    } else {
        log.denied += 1;
        log.last_suppressed = entry.suppressed;
    }
}

/// The app state a protected handler sees: it stamps `Identity.audit_detail`
/// (the module's documented hook for "what did this mutation touch") and
/// records which scheme admitted the request, so `.either`-mode precedence
/// is observable from outside.
const App = struct {
    calls: u32 = 0,
    last_scheme: ?aaa_gate.Identity.Scheme = null,
};

fn hOrder(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    if (aaa_gate.identityOf(ctx)) |id| {
        app.last_scheme = id.scheme;
        id.audit_detail = "order-created";
    }
    try ctx.res.writeAll("created\n");
}

fn hHealth(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(200);
    try ctx.res.writeAll("ok\n");
}

/// Route exemption: `/healthz` never needs a credential even under
/// `protect = .all`, matched by pattern the way the module documents
/// (`ctx.matchedPattern()` — bounded cardinality, unlike the raw path).
fn isHealthzExempt(_: ?*anyopaque, ctx: *router.Ctx) bool {
    const p = ctx.matchedPattern() orelse return false;
    return std.mem.eql(u8, p, "/healthz");
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var response_body_buf: [4096]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
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
    // "HTTP/1.1 NNN ..."
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

/// POST to `/orders`, optionally with an `Authorization` header and an
/// `X-Forwarded-For` key (the throttle's client-key trust rule) --
/// `Connection: close` so `serveStream` returns after exactly one response.
fn reqOrders(buf: []u8, auth: ?[]const u8, xff: ?[]const u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll("POST /orders HTTP/1.1\r\nHost: t\r\n") catch unreachable;
    if (auth) |a| w.print("Authorization: {s}\r\n", .{a}) catch unreachable;
    if (xff) |x| w.print("X-Forwarded-For: {s}\r\n", .{x}) catch unreachable;
    w.writeAll("Connection: close\r\nContent-Length: 0\r\n\r\n") catch unreachable;
    return w.buffered();
}

fn reqHealthz(buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "GET /healthz HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{}) catch unreachable;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var fake_clock: FakeClock = .{};
    var log: AuditLog = .{};

    var g = try aaa_gate.Gate.init(gpa, .{
        .token = "s3cr3t-primary",
        .extra_tokens = &.{"s3cr3t-spare"},
        .protect = .all,
        .exempt = .{ .isExempt = isHealthzExempt },
        .on_audit = onAudit,
        .on_audit_ctx = &log,
        .throttle_window_ms = 1000,
        .throttle_max_keys = 4,
        .clock = fake_clock.clock(),
    });
    defer g.deinit();

    var app: App = .{};
    var r = router.Router.init(gpa);
    defer r.deinit();
    r.state = &app;
    try r.use(g.middleware());
    try r.post("/orders", hOrder);
    try r.get("/healthz", hHealth);

    // 1. Allowed request: a configured bearer token admits, the handler
    // runs, and the audit hook sees exactly one authenticated mutation.
    {
        var buf: [2048]u8 = undefined;
        const resp = runWire(&r, reqOrders(buf[1024..], "Bearer s3cr3t-primary", "10.0.0.1"), buf[0..1024]);
        std.debug.assert(statusOf(resp) == 200);
        std.debug.assert(app.calls == 1);
        std.debug.assert(app.last_scheme.? == .bearer);
        std.debug.assert(log.authed == 1);
        std.debug.print("allowed bearer request: 200, audited\n", .{});
    }

    // 2. Denied: no Authorization header at all. Must 401 with the RFC 6750
    // challenge, never reach the handler.
    {
        var buf: [2048]u8 = undefined;
        const resp = runWire(&r, reqOrders(buf[1024..], null, "10.0.0.2"), buf[0..1024]);
        std.debug.assert(statusOf(resp) == 401);
        std.debug.assert(std.mem.eql(u8, headerValue(resp, "WWW-Authenticate").?, "Bearer"));
        std.debug.assert(app.calls == 1); // unchanged
        std.debug.assert(log.denied == 1);
        std.debug.print("missing credential denied: 401 + WWW-Authenticate: Bearer\n", .{});
    }

    // 3. Denied: an unknown principal -- a well-formed bearer token that was
    // never configured. Same 401 shape, distinct client key so it is not
    // coalesced with step 2's denial.
    {
        var buf: [2048]u8 = undefined;
        const resp = runWire(&r, reqOrders(buf[1024..], "Bearer nobody-knows-this-token", "10.0.0.3"), buf[0..1024]);
        std.debug.assert(statusOf(resp) == 401);
        std.debug.assert(app.calls == 1);
        std.debug.assert(log.denied == 2);
        std.debug.print("unknown principal denied: 401\n", .{});
    }

    // 4. Denied: a malformed Authorization header (wrong scheme, and a
    // Bearer with no token) -- the module's parser must never panic on
    // arbitrary header bytes, only fall through to a clean 401.
    {
        var buf: [2048]u8 = undefined;
        const wrong_scheme = runWire(&r, reqOrders(buf[1024..], "Basic dXNlcjpwYXNz", "10.0.0.4"), buf[0..1024]);
        std.debug.assert(statusOf(wrong_scheme) == 401);
        const empty_bearer = runWire(&r, reqOrders(buf[1024..], "Bearer", "10.0.0.5"), buf[0..1024]);
        std.debug.assert(statusOf(empty_bearer) == 401);
        std.debug.assert(app.calls == 1);
        std.debug.print("malformed Authorization headers denied without panicking\n", .{});
    }

    // 5. Revoked credential: rotate the primary token out (`removeToken`,
    // step 1 of the documented rotation dance run in reverse). The token
    // that admitted step 1's request is now denied -- same principal, now
    // revoked, not merely unknown.
    {
        std.debug.assert(g.tokenCount() == 2);
        g.removeToken("s3cr3t-primary");
        std.debug.assert(g.tokenCount() == 1);
        var buf: [2048]u8 = undefined;
        const resp = runWire(&r, reqOrders(buf[1024..], "Bearer s3cr3t-primary", "10.0.0.6"), buf[0..1024]);
        std.debug.assert(statusOf(resp) == 401);
        std.debug.assert(app.calls == 1);
        // The spare token, never revoked, still admits.
        const resp2 = runWire(&r, reqOrders(buf[1024..], "Bearer s3cr3t-spare", "10.0.0.7"), buf[0..1024]);
        std.debug.assert(statusOf(resp2) == 200);
        std.debug.assert(app.calls == 2);
        std.debug.print("revoked token denied; un-revoked spare still admits\n", .{});
    }

    // 6. Denied-request throttle: repeated 401s from the SAME client key
    // within the window are coalesced (no new audit entry), and the
    // suppressed count folds into the next entry once the injected clock
    // crosses `throttle_window_ms`. This is the concurrent/repeated-request
    // pressure path the module's coalescing store exists for.
    {
        const denied_before = log.denied;
        var buf: [2048]u8 = undefined;
        _ = runWire(&r, reqOrders(buf[1024..], null, "10.0.0.99"), buf[0..1024]); // admitted denial #1
        std.debug.assert(log.denied == denied_before + 1);
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            _ = runWire(&r, reqOrders(buf[1024..], null, "10.0.0.99"), buf[0..1024]); // coalesced
        }
        std.debug.assert(log.denied == denied_before + 1); // still just the one entry

        fake_clock.advanceMs(1001); // > throttle_window_ms
        _ = runWire(&r, reqOrders(buf[1024..], null, "10.0.0.99"), buf[0..1024]); // window reopened
        std.debug.assert(log.denied == denied_before + 2);
        std.debug.assert(log.last_suppressed == 5); // the 5 coalesced denials, folded in
        std.debug.print("throttle: 5 repeated 401s from one key coalesced, suppressed count folded in as {d}\n", .{log.last_suppressed});
    }

    // 7. Exempt route: `/healthz` bypasses auth entirely under `protect =
    // .all` -- no credential, and (unlike an admitted OR denied request)
    // no audit entry at all, because an exempt request never enters the
    // gate's scope.
    {
        const authed_before = log.authed;
        const denied_before = log.denied;
        var buf: [2048]u8 = undefined;
        const resp = runWire(&r, reqHealthz(buf[1024..]), buf[0..1024]);
        std.debug.assert(statusOf(resp) == 200);
        std.debug.assert(log.authed == authed_before);
        std.debug.assert(log.denied == denied_before);
        std.debug.print("exempt /healthz: 200, no credential, no audit entry\n", .{});
    }

    // 8. `.either` mode: a valid API key alone admits (Identity.scheme ==
    // .api_key); when both a valid bearer and a valid API key are
    // presented, bearer takes precedence (documented). A second gate keeps
    // this independent of the primary gate's rotation/throttle state above.
    {
        var log2: AuditLog = .{};
        var g2 = try aaa_gate.Gate.init(gpa, .{
            .token = "either-bearer",
            .api_key = "either-key",
            .auth_mode = .either,
            .on_audit = onAudit,
            .on_audit_ctx = &log2,
            .clock = fake_clock.clock(),
        });
        defer g2.deinit();
        var app2: App = .{};
        var r2 = router.Router.init(gpa);
        defer r2.deinit();
        r2.state = &app2;
        try r2.use(g2.middleware());
        try r2.post("/orders", hOrder);

        var buf: [2048]u8 = undefined;
        var w: std.Io.Writer = .fixed(buf[1024..]);
        w.writeAll("POST /orders HTTP/1.1\r\nHost: t\r\nX-Api-Key: either-key\r\n") catch unreachable;
        w.writeAll("Connection: close\r\nContent-Length: 0\r\n\r\n") catch unreachable;
        const key_only = runWire(&r2, w.buffered(), buf[0..1024]);
        std.debug.assert(statusOf(key_only) == 200);
        std.debug.assert(app2.last_scheme.? == .api_key);

        var w2: std.Io.Writer = .fixed(buf[1024..]);
        w2.writeAll("POST /orders HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer either-bearer\r\n") catch unreachable;
        w2.writeAll("X-Api-Key: either-key\r\nConnection: close\r\nContent-Length: 0\r\n\r\n") catch unreachable;
        const both = runWire(&r2, w2.buffered(), buf[0..1024]);
        std.debug.assert(statusOf(both) == 200);
        std.debug.assert(app2.last_scheme.? == .bearer); // precedence, documented
        std.debug.print(".either mode: API key alone admits; bearer wins when both are presented\n", .{});
    }

    // 9. Denied-request throttle capacity: distinct client keys past
    // `throttle_max_keys` (4, set on the primary gate) force real LRU
    // eviction in the throttle store while denials are still arriving --
    // the tracked-key count must never exceed the configured cap.
    {
        var buf: [2048]u8 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            var key_buf: [16]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "192.0.2.{d}", .{i}) catch unreachable;
            _ = runWire(&r, reqOrders(buf[1024..], null, key), buf[0..1024]);
            std.debug.assert(g.throttleKeyCount() <= 4);
        }
        std.debug.print("throttle capacity: 16 distinct denied keys through a 4-key store, count stayed <= 4\n", .{});
    }

    // 10. Allocator failure, error return partway through `Gate.init`: the
    // very first allocation (the primary token's digest, appended into the
    // token list) fails. Must surface `error.OutOfMemory` by name -- not
    // trap, not leak the partially-built gate (the `errdefer` chain in
    // `init` is exactly what step 11's leak check is watching).
    {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        if (aaa_gate.Gate.init(failing.allocator(), .{ .token = "unreachable-token" })) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("Gate.init under a FailingAllocator: OutOfMemory (expected)\n", .{}),
        }
    }

    // 11. Allocator failure, error return partway through `addToken` (an
    // allocating call on an otherwise-live gate, mid-rotation): `init` with
    // no static credentials still performs its 4 fixed allocations
    // (challenge, api_key_header, deny_body, deny_content_type) -- give it
    // exactly that budget so it succeeds, leaving `tokens` still empty.
    // `addToken`'s very first call is then a genuinely fresh allocation
    // (growing from an empty list), landing exactly where the budget runs
    // out. Must surface `error.OutOfMemory` by name, and the gate must
    // still be usable/leak-free afterward.
    {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 4 });
        var g3 = try aaa_gate.Gate.init(failing.allocator(), .{ .allow_when_unconfigured = true });
        defer g3.deinit();
        if (g3.addToken("first-rotated-token")) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("addToken under a FailingAllocator: OutOfMemory (expected)\n", .{}),
        }
        std.debug.assert(g3.tokenCount() == 0); // the failed append left nothing behind
    }

    std.debug.print("aaa-gate example done; authed={d} denied={d} tokens={d}\n", .{ log.authed, log.denied, g.tokenCount() });
}

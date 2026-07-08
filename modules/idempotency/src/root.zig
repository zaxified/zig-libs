// SPDX-License-Identifier: MIT

//! idempotency — Idempotency-Key deduplication of unsafe request retries
//! (Stripe-style) as a `router` middleware over a `ramcache`-backed store.
//!
//! A client that retries an unsafe request (a dropped connection, a timeout,
//! a mobile network hiccup) risks performing the side effect twice — charging
//! a card twice, creating two orders. The fix: the client sends a stable
//! `Idempotency-Key: <key>` header on the request and *the same key on every
//! retry*. The **first** request with that key runs the handler and the server
//! remembers its response; a **replay** of the same key within a TTL returns
//! the remembered response **without re-running the handler** — so the retry
//! is a no-op that still hands the client the original result.
//!
//! ## Why the handler must cooperate (the honest contract)
//!
//! In this stack a `router` handler writes **directly** to
//! `ctx.res` (`http.Server.ResponseWriter`), which streams to the socket. There
//! is no interface seam to slip a capturing writer under — `Ctx.res` is a
//! concrete `*http.Server.ResponseWriter` the router hands the handler — so the
//! middleware **cannot** transparently buffer an already-streamed response and
//! cache it after the fact. The design is therefore **cooperative**:
//!
//! - The **middleware** owns the *replay* half. On a guarded request carrying a
//!   valid key it looks the key up in the `Store`; on a hit it writes the
//!   cached status + `Content-Type` + body and short-circuits the chain — the
//!   handler genuinely never runs (the strongest guarantee, and what the
//!   hit-counter test asserts). On a miss it exposes the (scoped) key via
//!   `currentKey()` and runs the chain.
//! - The **handler** owns the *record* half. Instead of writing to `ctx.res`
//!   directly it calls `store.respond(ctx, status, content_type, body)`, which
//!   writes the response **and** records it in the store under the key the
//!   middleware exposed. A handler that writes to `ctx.res` directly still
//!   works — it just is not deduplicated (nothing was recorded).
//!
//! This is approach (a) from the module brief: a cooperative `Store` over
//! `ramcache`, no response capture. Approach (b) — an interposed capturing
//! writer — is not expressible here because `ResponseWriter` is concrete, not
//! an interface the router lets you substitute.
//!
//! ## Key scoping
//!
//! By default the cache key is scoped to the request **target** (method +
//! path): the client's key namespaced by `"<METHOD> <path>"`, so the same key
//! value on two different endpoints cannot cross-replay (matching the header
//! draft's "unique in the scope of a resource"). Set `Options.scope =
//! .key_only` to key on the client's value alone.
//!
//! ## What is and isn't handled
//!
//! Cached: completed responses (status + optional `Content-Type` + body) with
//! a TTL and a bounded, W-TinyLFU-evicting store (`ramcache`). **Not** handled:
//! concurrent first-flights of the same key (two requests that arrive before
//! either records both execute — there is no in-progress "409 in flight" lock;
//! the store remembers only *completed* responses), and request-fingerprint
//! mismatch detection (a client reusing a key with a different body is the
//! client's bug — the recorded response is returned regardless).
//!
//! ## Usage
//!
//! ```zig
//! var cache = ramcache.Cache.init(gpa, .{ .max_bytes = 8 << 20, .max_entries = 4096 });
//! defer cache.deinit();
//! var store = idempotency.Store{ .cache = &cache };
//! var idem = idempotency.Idempotency{ .store = &store };
//! try r.use(idem.middleware()); // before the routes it guards
//!
//! fn createOrder(ctx: *router.Ctx) anyerror!void {
//!     const app: *App = @ptrCast(@alignCast(ctx.state.?));
//!     const body = try renderOrder(...);           // the side-effecting work
//!     try app.store.respond(ctx, 201, "application/json", body);
//! }
//! ```
//!
//! ## Concurrency
//!
//! `ramcache` is single-owner; `http.Server` serves from several connection
//! threads. The `Store` wraps every cache touch in an internal spinlock
//! (`std.atomic.Mutex` + `spinLoopHint`, the std SmpAllocator pattern — Zig
//! 0.16 std has no io-less blocking mutex), so it is **thread-safe**: `respond`
//! and the middleware may race across all connection threads. Critical sections
//! are a single map touch plus a bounded value copy — never socket I/O (the
//! cached bytes are copied out under the lock, then written to the socket
//! lock-free). The scoped key travels middleware→handler in thread-local
//! storage (the server is task-per-connection: one request at a time per
//! thread), the same model `requestid` uses. The `Store` and `Idempotency`
//! must outlive the `Router`, at stable addresses.

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");
const ramcache = @import("ramcache");

pub const meta = .{
    .status = .gap,
    .platform = .any,
    .role = .server,
    // Internally synchronized: the ramcache store sits behind a documented
    // spinlock, so it is safe from all connection threads at once. The scoped
    // key travels via thread-local storage owned by the connection task.
    .concurrency = .threadsafe,
    .model_after = "Idempotency-Key (Stripe / draft-ietf-httpapi-idempotency-key-header)",
    .deps = .{ "router", "http", "ramcache" },
};

/// Default request header carrying the client's key.
pub const default_header = "Idempotency-Key";

/// Default response header stamped on a replayed response (Stripe's
/// `Idempotent-Replayed`). Empty in `Options` disables it.
pub const default_replay_header = "Idempotent-Replayed";

/// Default retention of a recorded response (24 h, in nanoseconds).
pub const default_ttl_ns: i64 = 24 * 60 * 60 * std.time.ns_per_s;

/// Longest client key accepted; a longer one answers 400.
pub const default_max_key_len = 255;

/// Upper bound on a scoped cache key (`"<METHOD> <path> <key>"`). A request
/// whose scoped key would exceed this bypasses deduplication (runs normally,
/// nothing recorded) rather than being rejected.
pub const max_scoped_key = 1024;

/// How the client's key maps to a cache key.
pub const Scope = enum {
    /// Namespace the key by `"<METHOD> <path>"` (default) — the same key value
    /// on two endpoints cannot cross-replay.
    target,
    /// Use the client's key value verbatim (global across endpoints).
    key_only,
};

// ── clock injection (deterministic under test) ──────────────────────────────

/// Monotonic time source for TTL accounting, injected so tests are
/// deterministic. Non-decreasing; only differences matter (an in-memory cache
/// never persists, so a monotonic origin is fine).
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) i64,

    /// The OS monotonic clock — the production default and the only place the
    /// module reads a real clock.
    pub const monotonic: Clock = .{ .nowFn = monoNow };

    fn now(c: Clock) i64 {
        return c.nowFn(c.ctx);
    }
};

fn monoNow(_: ?*anyopaque) i64 {
    return monoNs();
}

fn monoNs() i64 {
    switch (builtin.os.tag) {
        .windows => {
            var qpf: std.os.windows.LARGE_INTEGER = undefined;
            var qpc: std.os.windows.LARGE_INTEGER = undefined;
            if (!std.os.windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) return 0;
            if (!std.os.windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool()) return 0;
            const freq: u64 = @bitCast(qpf);
            const count: u64 = @bitCast(qpc);
            return @intCast(@as(u128, count) * std.time.ns_per_s / freq);
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
            return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
        },
    }
}

// ── the store (over ramcache) ───────────────────────────────────────────────

/// The key→response store the middleware and handlers share, backed by a
/// caller-owned `ramcache.Cache` (which supplies the TTL expiry, the byte /
/// entry bounds and W-TinyLFU eviction). Thread-safe: every cache touch is
/// serialized by the internal spinlock. The `cache` must outlive the `Store`.
pub const Store = struct {
    /// The bounded, TTL-expiring cache. Caller owns it (init/deinit); the store
    /// only reads/writes through it under the lock. Its `alloc` is reused for
    /// the short-lived encode / read-out copies.
    cache: *ramcache.Cache,
    /// Retention of each recorded response. Applied as the ramcache TTL.
    ttl_ns: i64 = default_ttl_ns,
    /// Time source for TTL accounting (injected in tests).
    clock: Clock = .monotonic,
    lock: std.atomic.Mutex = .unlocked,

    /// Write `body` to the response with `status` and optional `content_type`,
    /// **and** record it under the key the middleware exposed for this request
    /// (via `currentKey()`) so a later replay of the same key returns it. When
    /// no key is in scope (the request carried none, or the method is not
    /// guarded), it simply writes the response — the one call works for both
    /// idempotent and plain requests. `body`/`content_type` are copied into the
    /// cache; the caller's buffers may be reused after.
    pub fn respond(
        store: *Store,
        ctx: *router.Ctx,
        status: u16,
        content_type: ?[]const u8,
        body: []const u8,
    ) anyerror!void {
        ctx.res.setStatus(status);
        if (content_type) |ct| try ctx.res.setHeader("Content-Type", ct);
        try ctx.res.writeAll(body);
        if (currentKey()) |key| store.record(key, status, content_type orelse "", body);
    }

    /// Record a completed response under `key`. Best-effort: a failed encode or
    /// a full cache silently skips caching (a missed dedup is never fatal — the
    /// next replay just re-runs the handler). Callable directly when a handler
    /// does not use `respond`.
    pub fn record(store: *Store, key: []const u8, status: u16, content_type: []const u8, body: []const u8) void {
        const blob = encode(store.cache.alloc, status, content_type, body) catch return;
        defer store.cache.alloc.free(blob);
        const now = store.clock.now();
        lockSpin(&store.lock);
        defer store.lock.unlock();
        store.cache.put(key, blob, now, store.ttl_ns, 0);
    }

    /// If `key` has a fresh recorded response, return an owned copy of its
    /// encoded blob (caller frees with `gpa`); else null. Copied under the lock
    /// so the caller decodes and writes to the socket lock-free.
    fn fetchCopy(store: *Store, key: []const u8, gpa: std.mem.Allocator) std.mem.Allocator.Error!?[]u8 {
        const now = store.clock.now();
        lockSpin(&store.lock);
        defer store.lock.unlock();
        const v = store.cache.get(key, now, 0) orelse return null;
        return try gpa.dupe(u8, v);
    }
};

// Stored blob layout: [status:u16 BE][ct_len:u16 BE][ct bytes][body bytes].
const RecordedResponse = struct {
    status: u16,
    content_type: []const u8,
    body: []const u8,
};

fn encode(gpa: std.mem.Allocator, status: u16, content_type: []const u8, body: []const u8) ![]u8 {
    const ct_len = std.math.cast(u16, content_type.len) orelse return error.InvalidRecord;
    const blob = try gpa.alloc(u8, 4 + content_type.len + body.len);
    std.mem.writeInt(u16, blob[0..2], status, .big);
    std.mem.writeInt(u16, blob[2..4], ct_len, .big);
    @memcpy(blob[4..][0..content_type.len], content_type);
    @memcpy(blob[4 + content_type.len ..], body);
    return blob;
}

fn decode(blob: []const u8) ?RecordedResponse {
    if (blob.len < 4) return null;
    const status = std.mem.readInt(u16, blob[0..2], .big);
    const ct_len = std.mem.readInt(u16, blob[2..4], .big);
    if (4 + @as(usize, ct_len) > blob.len) return null;
    return .{
        .status = status,
        .content_type = blob[4..][0..ct_len],
        .body = blob[4 + ct_len ..],
    };
}

// ── the middleware ──────────────────────────────────────────────────────────

pub const Options = struct {
    /// Request header carrying the client's key. Default `Idempotency-Key`.
    header_name: []const u8 = default_header,
    /// Response header stamped on a replayed response. Empty ⇒ none.
    replay_header: []const u8 = default_replay_header,
    /// Methods that are deduplicated. Default POST/PUT/PATCH (the unsafe,
    /// non-idempotent methods); a request with any other method bypasses.
    methods: []const http.Method = &.{ .post, .put, .patch },
    /// Longest client key accepted; a longer one answers 400.
    max_key_len: usize = default_max_key_len,
    /// How the client key maps to a cache key. Default `.target`.
    scope: Scope = .target,
};

/// Config + the middleware over a `Store`. Immutable once built; share one
/// across threads. The `store` it points at must outlive the `Router`.
pub const Idempotency = struct {
    store: *Store,
    options: Options = .{},

    pub fn middleware(idem: *const Idempotency) router.Middleware {
        return .{ .state = @constCast(idem), .run = middlewareRun };
    }
};

// The scoped cache key for the in-flight request, exposed to the handler so
// `Store.respond` records under the exact key the middleware looked up. Valid
// on the connection thread for the duration of the request only (see the
// module doc's concurrency note; same model as requestid).
threadlocal var key_buf: [max_scoped_key]u8 = undefined;
threadlocal var current_key: []const u8 = &.{};

// A replayed `Content-Type` value must outlive the middleware call (the
// ResponseWriter stores header value slices verbatim — no copy — and the head
// is not flushed until after the handler chain returns), so the decoded value
// (which borrows the soon-freed cache copy) is staged here. Task-per-connection
// makes this per-thread buffer valid until the response is flushed.
threadlocal var replay_ct_buf: [256]u8 = undefined;

/// The scoped idempotency key in effect for the current request, or null when
/// none is (the request carried no key, the method is not guarded, or the key
/// was invalid / too long to scope). Call it from the connection thread during
/// the request; `Store.respond` uses it internally.
pub fn currentKey() ?[]const u8 {
    return if (current_key.len == 0) null else current_key;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const idem: *const Idempotency = @ptrCast(@alignCast(state.?));
    // Clear any key left over from a prior request on this thread, so a
    // bypassed request never inherits a stale one.
    current_key = &.{};

    if (!methodGuarded(idem.options.methods, ctx.req.method)) return next.run(ctx);
    const client_key = ctx.req.header(idem.options.header_name) orelse return next.run(ctx);
    if (!validKey(client_key, idem.options.max_key_len)) return badRequest(ctx);

    const scoped = scopeKey(&key_buf, idem.options.scope, ctx.req, client_key) orelse
        // Too long to scope — degrade to running normally without dedup.
        return next.run(ctx);

    // Replay: a hit writes the recorded response and short-circuits the chain,
    // so the handler never runs.
    if (try idem.store.fetchCopy(scoped, idem.store.cache.alloc)) |blob| {
        defer idem.store.cache.alloc.free(blob);
        const rec = decode(blob) orelse return next.run(ctx); // corrupt ⇒ re-run
        ctx.res.setStatus(rec.status);
        // Stage Content-Type into thread-local storage: setHeader keeps the
        // slice, but `blob` is freed on return before the head is flushed.
        if (rec.content_type.len != 0 and rec.content_type.len <= replay_ct_buf.len) {
            @memcpy(replay_ct_buf[0..rec.content_type.len], rec.content_type);
            try ctx.res.setHeader("Content-Type", replay_ct_buf[0..rec.content_type.len]);
        }
        if (idem.options.replay_header.len != 0)
            try ctx.res.setHeader(idem.options.replay_header, "true");
        try ctx.res.writeAll(rec.body); // writeAll copies, so freeing blob after is safe
        return;
    }

    // Miss: expose the scoped key for the handler's `respond`, run the chain.
    current_key = scoped;
    defer current_key = &.{};
    return next.run(ctx);
}

fn methodGuarded(methods: []const http.Method, m: http.Method) bool {
    for (methods) |g| {
        if (g == m) return true;
    }
    return false;
}

/// A key is accepted when non-empty, within `max_len`, and every byte is a
/// printable non-space ASCII character (no controls — also rejected by
/// `setHeader` — and no spaces, keeping the scoped key a clean triple).
fn validKey(v: []const u8, max_len: usize) bool {
    if (v.len == 0 or v.len > max_len) return false;
    for (v) |c| {
        if (c <= ' ' or c >= 0x7f) return false;
    }
    return true;
}

/// Build the scoped cache key into `buf`, or null when it would overflow.
/// `client_key` is the already-fetched (and validated) header value.
fn scopeKey(buf: []u8, scope: Scope, req: *const http.Server.Request, client_key: []const u8) ?[]const u8 {
    switch (scope) {
        .key_only => return client_key,
        .target => return std.fmt.bufPrint(buf, "{s} {s} {s}", .{
            req.method.token(), req.path, client_key,
        }) catch null,
    }
}

fn badRequest(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(400);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Invalid Idempotency-Key\n");
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── tests (offline — through http.Server.serveStream + a real router) ───────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// A manual clock so TTL tests are deterministic.
const ManualClock = struct {
    now_ns: i64 = 0,
    fn clock(mc: *ManualClock) Clock {
        return .{ .ctx = mc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const mc: *ManualClock = @ptrCast(@alignCast(ctx.?));
        return mc.now_ns;
    }
};

/// Test app state: the shared store + a handler-invocation counter (the
/// "expensive work" that must run exactly once per distinct key).
const App = struct {
    store: *Store,
    calls: u32 = 0,
};

/// Handler: counts its invocation, then produces a body derived from the count
/// via the cooperative `respond` (writes + records). If it is ever replayed the
/// count would advance — the tests assert it does not.
fn hOrder(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    var body_buf: [32]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "order-{d}", .{app.calls}) catch unreachable;
    try app.store.respond(ctx, 201, "application/json", body);
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
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

fn reqKey(comptime method: []const u8, comptime path: []const u8, comptime key: []const u8) []const u8 {
    return method ++ " " ++ path ++ " HTTP/1.1\r\nHost: t\r\n" ++
        "Idempotency-Key: " ++ key ++ "\r\nConnection: close\r\n\r\n";
}

fn reqNoKey(comptime method: []const u8, comptime path: []const u8) []const u8 {
    return method ++ " " ++ path ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn newCache() ramcache.Cache {
    return ramcache.Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 256 });
}

test "first key runs the handler once; replay returns the cached response without re-running" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    var b1: [2048]u8 = undefined;
    const first = runWire(&r, reqKey("POST", "/orders", "abc-123"), &b1);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 201"));
    try testing.expectEqualStrings("order-1", bodyOf(first));
    try testing.expectEqual(@as(u32, 1), app.calls);
    // The first pass is not a replay.
    try testing.expectEqual(@as(?[]const u8, null), headerValue(first, "Idempotent-Replayed"));

    var b2: [2048]u8 = undefined;
    const replay = runWire(&r, reqKey("POST", "/orders", "abc-123"), &b2);
    try testing.expect(std.mem.startsWith(u8, replay, "HTTP/1.1 201"));
    // Same status + body as the first response…
    try testing.expectEqualStrings("order-1", bodyOf(replay));
    // …stamped as a replay, and the handler did NOT run again.
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expectEqualStrings("application/json", headerValue(replay, "Content-Type").?);
    try testing.expectEqual(@as(u32, 1), app.calls);
}

test "a different key runs the handler again" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    var b1: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqKey("POST", "/orders", "k1"), &b1)));
    var b2: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-2", bodyOf(runWire(&r, reqKey("POST", "/orders", "k2"), &b2)));
    try testing.expectEqual(@as(u32, 2), app.calls);
}

test "non-idempotent method (GET) bypasses — no caching, handler runs every time" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.get("/orders", hOrder);

    var b1: [2048]u8 = undefined;
    var b2: [2048]u8 = undefined;
    // Same key on two GETs: not guarded, so each runs (no replay stamp).
    const g1 = runWire(&r, reqKey("GET", "/orders", "same"), &b1);
    const g2 = runWire(&r, reqKey("GET", "/orders", "same"), &b2);
    try testing.expectEqualStrings("order-1", bodyOf(g1));
    try testing.expectEqualStrings("order-2", bodyOf(g2));
    try testing.expectEqual(@as(?[]const u8, null), headerValue(g2, "Idempotent-Replayed"));
    try testing.expectEqual(@as(u32, 2), app.calls);
}

test "POST without an Idempotency-Key bypasses — handler runs every time" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    var b1: [2048]u8 = undefined;
    var b2: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqNoKey("POST", "/orders"), &b1)));
    try testing.expectEqualStrings("order-2", bodyOf(runWire(&r, reqNoKey("POST", "/orders"), &b2)));
    try testing.expectEqual(@as(u32, 2), app.calls);
}

test "an invalid key answers 400 and the handler never runs" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    // Contains a space → invalid.
    var b1: [2048]u8 = undefined;
    const bad = runWire(&r, reqKey("POST", "/orders", "has\tcontrol"), &b1);
    try testing.expect(std.mem.startsWith(u8, bad, "HTTP/1.1 400"));
    try testing.expectEqual(@as(u32, 0), app.calls);
}

test "target scope: the same key on a different path does not cross-replay" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store }; // default scope = .target

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);
    try r.post("/refunds", hOrder);

    var b1: [2048]u8 = undefined;
    var b2: [2048]u8 = undefined;
    // Same client key, two endpoints → two distinct cache entries, both run.
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqKey("POST", "/orders", "dup"), &b1)));
    try testing.expectEqualStrings("order-2", bodyOf(runWire(&r, reqKey("POST", "/refunds", "dup"), &b2)));
    try testing.expectEqual(@as(u32, 2), app.calls);
    // And each still replays on its own endpoint.
    var b3: [2048]u8 = undefined;
    const replay = runWire(&r, reqKey("POST", "/orders", "dup"), &b3);
    try testing.expectEqualStrings("order-1", bodyOf(replay));
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 2), app.calls);
}

test "TTL expiry: after the recorded response expires, the handler re-runs" {
    var clk = ManualClock{ .now_ns = 1000 };
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache, .clock = clk.clock(), .ttl_ns = 100 };
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    var b1: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqKey("POST", "/orders", "t"), &b1)));

    // 50 ns later → still fresh → replay, no new call.
    clk.now_ns = 1050;
    var b2: [2048]u8 = undefined;
    const fresh = runWire(&r, reqKey("POST", "/orders", "t"), &b2);
    try testing.expectEqualStrings("order-1", bodyOf(fresh));
    try testing.expectEqualStrings("true", headerValue(fresh, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 1), app.calls);

    // Past the TTL → the entry expired → the handler runs again.
    clk.now_ns = 2000;
    var b3: [2048]u8 = undefined;
    const stale = runWire(&r, reqKey("POST", "/orders", "t"), &b3);
    try testing.expectEqualStrings("order-2", bodyOf(stale));
    try testing.expectEqual(@as(?[]const u8, null), headerValue(stale, "Idempotent-Replayed"));
    try testing.expectEqual(@as(u32, 2), app.calls);
}

test "encode/decode round-trips status, content-type and body" {
    const blob = try encode(testing.allocator, 201, "application/json", "{\"ok\":true}");
    defer testing.allocator.free(blob);
    const rec = decode(blob).?;
    try testing.expectEqual(@as(u16, 201), rec.status);
    try testing.expectEqualStrings("application/json", rec.content_type);
    try testing.expectEqualStrings("{\"ok\":true}", rec.body);

    // Empty content-type is valid.
    const blob2 = try encode(testing.allocator, 204, "", "");
    defer testing.allocator.free(blob2);
    const rec2 = decode(blob2).?;
    try testing.expectEqual(@as(u16, 204), rec2.status);
    try testing.expectEqualStrings("", rec2.content_type);
    try testing.expectEqualStrings("", rec2.body);

    // A truncated blob decodes to null rather than reading out of bounds.
    try testing.expectEqual(@as(?RecordedResponse, null), decode("x"));
}

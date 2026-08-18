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
//! a TTL and a bounded, W-TinyLFU-evicting store (`ramcache`). Concurrent
//! first-flights of the same key are handled by an **in-flight reservation**:
//! the first request reserves the key for the duration of its handler, and a
//! second same-key request arriving before it completes is answered **409**
//! (already in flight) rather than running the handler a second time — the
//! client retries once the original finishes and then gets the replay.
//!
//! **Request-fingerprint mismatch** (a client reusing one key for two
//! different requests) is covered two ways:
//!
//! - Different method or path, under the default `scope = .target`: these are
//!   *different cache entries*, so no cross-replay can happen. The dangerous
//!   confusion — a key from `POST /orders` replaying as the answer to
//!   `POST /refunds` — cannot occur unless you opt into `scope = .key_only`.
//! - Same method and path (or same key under `.key_only`), different
//!   **body**: detected via a SHA-256 fingerprint of the request body,
//!   recorded alongside the response and compared (constant-time) on every
//!   same-key request. A mismatch means this is not a retry — it is either a
//!   client bug or a replay of the key against different content — and the
//!   module answers **422** (the IETF Idempotency-Key draft's SHOULD) without
//!   running the handler. Detecting this needs the body buffered before the
//!   handler reads it, bounded by `Options.max_body_bytes` (default 16 KiB):
//!   a body over the cap cannot be safely fingerprinted, and letting it
//!   through unverified would just reopen this same hole by another name, so
//!   it fails closed — **413** — rather than silently skipping the check.
//!   The buffered bytes are re-exposed to the handler via `req.decoded`, so a
//!   handler that reads the body still sees it.
//!
//! ## Usage
//!
//! ```zig
//! var cache = ramcache.Cache.init(gpa, .{ .max_bytes = 8 << 20, .max_entries = 4096 });
//! defer cache.deinit();
//! var store = idempotency.Store{ .cache = &cache };
//! defer store.deinit();
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
//! thread), the same model `requestid` uses. The in-flight reservation set is
//! guarded by the same lock; call `Store.deinit()` once when the store is
//! retired to release it. The `Store` and `Idempotency` must outlive the
//! `Router`, at stable addresses.

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");
const ramcache = @import("ramcache");

pub const meta = .{
    .targets = .{.linux64},
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

/// Length of the body fingerprint (SHA-256).
pub const digest_len = std.crypto.hash.sha2.Sha256.digest_length;

/// Default cap on the request body buffered and fingerprinted for the
/// same-key mismatch check. Generous for a JSON payment/order payload — the
/// Idempotency-Key pattern's motivating use case — without letting an
/// unbounded body sit in memory per in-flight request. A body over the cap
/// (`Options.max_body_bytes`) cannot be safely fingerprinted, so it fails
/// closed with **413** rather than silently skipping the check (see the
/// module doc's "Request-fingerprint mismatch" note).
pub const default_max_body_bytes: usize = 16 * 1024;

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
    /// Keys with a request currently *executing* the handler (reserved on a
    /// miss, released when the handler returns). A second same-key request
    /// that arrives while the first is still in flight sees the reservation
    /// and is rejected (409) rather than running the handler a second time —
    /// closing the concurrent first-flight double-execution window. Keys are
    /// `cache.alloc`-owned copies; guarded by `lock`.
    in_flight: std.StringHashMapUnmanaged(void) = .empty,

    /// Release the in-flight reservation set. Call once when the store is no
    /// longer used. In steady state the set is empty (every reservation is
    /// released when its handler returns); this frees the map's backing.
    pub fn deinit(store: *Store) void {
        lockSpin(&store.lock);
        var it = store.in_flight.keyIterator();
        while (it.next()) |k| store.cache.alloc.free(k.*);
        store.in_flight.deinit(store.cache.alloc);
        store.lock.unlock();
        store.* = undefined;
    }

    /// The outcome of `beginOrReplay`.
    pub const Begin = union(enum) {
        /// A completed response is already recorded, and its fingerprint
        /// matches this request's body — an owned copy of the encoded blob
        /// (caller frees with the same allocator it passed).
        replay: []u8,
        /// A completed response is already recorded under this key, but its
        /// fingerprint does NOT match this request's body: not a retry — the
        /// caller must answer 422 without running the handler.
        mismatch,
        /// Another request holds the reservation for this key: the caller
        /// must answer 409 (in flight) without running the handler.
        in_flight,
        /// This request now owns the reservation and must run the handler,
        /// then call `finish(key)` exactly once to release it.
        reserved,
    };

    /// Atomically (under a single lock) either return a recorded response to
    /// replay, flag a body-fingerprint mismatch, reject a concurrent
    /// in-flight duplicate, or reserve `key` for this request. Doing the
    /// cache-check and the reservation together is what makes the second
    /// concurrent first-flight lose the race cleanly. `digest` is this
    /// request's SHA-256 body fingerprint, computed by the caller before the
    /// lock is taken (hashing never happens under the lock).
    fn beginOrReplay(store: *Store, key: []const u8, digest: [digest_len]u8, gpa: std.mem.Allocator) std.mem.Allocator.Error!Begin {
        const now = store.clock.now();
        lockSpin(&store.lock);
        defer store.lock.unlock();
        if (store.cache.get(key, now, 0)) |v| {
            // Check the fingerprint before ever handing back the recorded
            // response: a same-key request whose body differs from what was
            // recorded is not a retry (a client bug, or a replay of the key
            // against different content — the IETF Idempotency-Key draft's
            // 422 case). Constant-time because both operands are influenced
            // by the client (its own request's digest against the stored
            // one) — a variable-time compare would let a client binary-
            // search the stored digest byte by byte across retries, which
            // defeats fingerprinting as a check at all.
            //
            // An undecodable stored blob (corrupt/short — should not happen
            // in practice) skips the compare and falls through to the
            // existing replay path, which itself re-runs the handler on a
            // decode failure (see `middlewareRun`) — unchanged from before
            // fingerprinting landed.
            if (decode(v)) |rec| {
                if (!std.crypto.timing_safe.eql([digest_len]u8, rec.digest, digest)) return .mismatch;
            }
            return .{ .replay = try gpa.dupe(u8, v) };
        }
        if (store.in_flight.contains(key)) return .in_flight;
        const owned = try store.cache.alloc.dupe(u8, key);
        errdefer store.cache.alloc.free(owned);
        try store.in_flight.put(store.cache.alloc, owned, {});
        return .reserved;
    }

    /// Release the reservation taken by `beginOrReplay` for `key`.
    fn finish(store: *Store, key: []const u8) void {
        lockSpin(&store.lock);
        defer store.lock.unlock();
        if (store.in_flight.fetchRemove(key)) |kv| store.cache.alloc.free(kv.key);
    }

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
        // `current_key` and `current_digest` are set and cleared together by
        // the middleware (see `middlewareRun`), so a non-null key always has
        // a digest alongside it.
        if (currentKey()) |key| store.record(key, current_digest.?, status, content_type orelse "", body);
    }

    /// Record a completed response under `key`, alongside `digest` — the
    /// SHA-256 fingerprint of the request body that produced it, checked
    /// against a later same-key request (see `beginOrReplay`). Best-effort: a
    /// failed encode or a full cache silently skips caching (a missed dedup
    /// is never fatal — the next replay just re-runs the handler). Callable
    /// directly when a handler does not use `respond` — pair with
    /// `currentDigest()` for the matching fingerprint.
    pub fn record(store: *Store, key: []const u8, digest: [digest_len]u8, status: u16, content_type: []const u8, body: []const u8) void {
        const blob = encode(store.cache.alloc, digest, status, content_type, body) catch return;
        defer store.cache.alloc.free(blob);
        const now = store.clock.now();
        lockSpin(&store.lock);
        defer store.lock.unlock();
        store.cache.put(key, blob, now, store.ttl_ns, 0);
    }
};

// Stored blob layout:
// [digest:32][status:u16 BE][ct_len:u16 BE][ct bytes][body bytes].
const RecordedResponse = struct {
    digest: [digest_len]u8,
    status: u16,
    content_type: []const u8,
    body: []const u8,
};

fn encode(gpa: std.mem.Allocator, digest: [digest_len]u8, status: u16, content_type: []const u8, body: []const u8) ![]u8 {
    const ct_len = std.math.cast(u16, content_type.len) orelse return error.InvalidRecord;
    const blob = try gpa.alloc(u8, digest_len + 4 + content_type.len + body.len);
    @memcpy(blob[0..digest_len], &digest);
    std.mem.writeInt(u16, blob[digest_len..][0..2], status, .big);
    std.mem.writeInt(u16, blob[digest_len + 2 ..][0..2], ct_len, .big);
    @memcpy(blob[digest_len + 4 ..][0..content_type.len], content_type);
    @memcpy(blob[digest_len + 4 + content_type.len ..], body);
    return blob;
}

fn decode(blob: []const u8) ?RecordedResponse {
    if (blob.len < digest_len + 4) return null;
    var digest: [digest_len]u8 = undefined;
    @memcpy(&digest, blob[0..digest_len]);
    const status = std.mem.readInt(u16, blob[digest_len..][0..2], .big);
    const ct_len = std.mem.readInt(u16, blob[digest_len + 2 ..][0..2], .big);
    if (digest_len + 4 + @as(usize, ct_len) > blob.len) return null;
    return .{
        .digest = digest,
        .status = status,
        .content_type = blob[digest_len + 4 ..][0..ct_len],
        .body = blob[digest_len + 4 + ct_len ..],
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
    /// Cap on the request body buffered and SHA-256 fingerprinted to detect
    /// a same-key request with a different body. A body at or under this is
    /// hashed and compared (constant-time) against the fingerprint recorded
    /// for the first request under the key; a mismatch answers 422. A body
    /// over this cap cannot be safely fingerprinted and answers 413 instead
    /// of silently letting the mismatch check be skipped — see the module
    /// doc's "Request-fingerprint mismatch" note. Default
    /// `default_max_body_bytes` (16 KiB).
    max_body_bytes: usize = default_max_body_bytes,
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

// The SHA-256 fingerprint of the current request's (buffered) body, set
// alongside `current_key` by the middleware and cleared with it — so a
// non-null `current_key` always has a matching digest. See `currentDigest`.
threadlocal var current_digest: ?[digest_len]u8 = null;

/// The scoped idempotency key in effect for the current request, or null when
/// none is (the request carried no key, the method is not guarded, or the key
/// was invalid / too long to scope). Call it from the connection thread during
/// the request; `Store.respond` uses it internally.
pub fn currentKey() ?[]const u8 {
    return if (current_key.len == 0) null else current_key;
}

/// The SHA-256 fingerprint of the current request's body, or null exactly
/// when `currentKey()` is null (the two are set and cleared together). A
/// handler that records a response via `Store.record` directly instead of
/// `Store.respond` needs this to pass the matching digest.
pub fn currentDigest() ?[digest_len]u8 {
    return current_digest;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const idem: *const Idempotency = @ptrCast(@alignCast(state.?));
    // Clear any key/digest left over from a prior request on this thread, so
    // a bypassed request never inherits a stale one.
    current_key = &.{};
    current_digest = null;

    if (!methodGuarded(idem.options.methods, ctx.req.method)) return next.run(ctx);
    const client_key = ctx.req.header(idem.options.header_name) orelse return next.run(ctx);
    if (!validKey(client_key, idem.options.max_key_len)) return badRequest(ctx);

    const scoped = scopeKey(&key_buf, idem.options.scope, ctx.req, client_key) orelse
        // Too long to scope — degrade to running normally without dedup.
        return next.run(ctx);

    // Buffer and fingerprint the body before the cache decision: whether
    // this is a replay or a 422 mismatch depends on it. Bounded — a body
    // over `max_body_bytes` cannot be safely fingerprinted, so it fails
    // closed (413) instead of silently skipping the check (see the module
    // doc's "Request-fingerprint mismatch" note).
    //
    // `allocRemaining` treats reaching its limit exactly as `StreamTooLong`
    // (bytes up to the limit are read either way); probing at
    // `max_body_bytes + 1` is what makes a body of exactly the configured
    // cap succeed while one byte more is rejected — the documented boundary.
    const probe_cap = if (idem.options.max_body_bytes == std.math.maxInt(usize))
        idem.options.max_body_bytes
    else
        idem.options.max_body_bytes + 1;
    const body_bytes = ctx.req.reader().allocRemaining(idem.store.cache.alloc, .limited(probe_cap)) catch |err| switch (err) {
        error.StreamTooLong => return payloadTooLarge(ctx),
        else => |e| return e,
    };
    defer idem.store.cache.alloc.free(body_bytes);
    var digest: [digest_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body_bytes, &digest, .{});

    // We just drained the body ourselves — re-expose the buffered bytes to
    // the handler transparently via the `decoded` override seam (the same
    // one inbound gzip decoding uses), so a handler that reads the body
    // still sees it. Restored (not just nulled) on return, in case an outer
    // caller relies on whatever was there before us (e.g. a decompressed
    // stream from server-level gzip handling).
    var body_reader: std.Io.Reader = .fixed(body_bytes);
    const prev_decoded = ctx.req.decoded;
    ctx.req.decoded = &body_reader;
    defer ctx.req.decoded = prev_decoded;

    // One atomic step: replay a completed response, flag a body-fingerprint
    // mismatch, reject a concurrent in-flight duplicate (409), or reserve
    // this key and run the handler.
    switch (try idem.store.beginOrReplay(scoped, digest, idem.store.cache.alloc)) {
        .replay => |blob| {
            // A hit writes the recorded response and short-circuits the chain,
            // so the handler never runs.
            defer idem.store.cache.alloc.free(blob);
            const rec = decode(blob) orelse return next.run(ctx); // corrupt ⇒ re-run
            ctx.res.setStatus(rec.status);
            // Passed straight through: `setHeader` copies, so it does not matter
            // that `rec.content_type` borrows `blob`, which the `defer` above
            // frees before the head is flushed. Until 2026-08-12 this had to be
            // staged in a 256-byte thread-local, which silently DROPPED any
            // longer value; the cap was an artifact of that buffer, not a policy,
            // so a replay now reproduces the recorded Content-Type whatever its
            // length.
            if (rec.content_type.len != 0)
                try ctx.res.setHeader("Content-Type", rec.content_type);
            if (idem.options.replay_header.len != 0)
                try ctx.res.setHeader(idem.options.replay_header, "true");
            try ctx.res.writeAll(rec.body); // writeAll copies, so freeing blob after is safe
            return;
        },
        .mismatch => return unprocessable(ctx),
        .in_flight => return conflict(ctx),
        .reserved => {},
    }

    // Miss (reserved): expose the scoped key + digest for the handler's
    // `respond`, run the chain, then release the reservation so a later
    // retry can proceed.
    current_key = scoped;
    current_digest = digest;
    defer {
        current_key = &.{};
        current_digest = null;
        idem.store.finish(scoped);
    }
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

/// A same-key request that arrives while the first is still executing the
/// handler: the RFC/Stripe-recommended answer is 409 Conflict — the client
/// should retry once the original completes (and then get the replay).
fn conflict(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(409);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Idempotency-Key request already in flight\n");
}

/// A same-key, same-target request whose body fingerprint does not match the
/// one recorded for the first request under this key: not a retry — either a
/// client bug or a replay of the key against different content. The IETF
/// Idempotency-Key draft's SHOULD-422 case. The handler never runs.
fn unprocessable(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(422);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Idempotency-Key reused with a different request body\n");
}

/// A same-key request whose body exceeds `Options.max_body_bytes`: it cannot
/// be safely fingerprinted, and letting it through unverified would just
/// reopen the same-key/different-body hole this feature exists to close —
/// so it fails closed rather than silently falling back to no dedup.
fn payloadTooLarge(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(413);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Idempotency-Key request body exceeds the fingerprint cap\n");
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

/// Like `reqKey`, carrying a request body under `Content-Length` framing —
/// for the fingerprint tests, which need actual body bytes on the wire.
fn reqKeyBody(comptime method: []const u8, comptime path: []const u8, comptime key: []const u8, comptime body: []const u8) []const u8 {
    return method ++ " " ++ path ++ " HTTP/1.1\r\nHost: t\r\nIdempotency-Key: " ++ key ++
        "\r\nContent-Length: " ++ std.fmt.comptimePrint("{d}", .{body.len}) ++
        "\r\nConnection: close\r\n\r\n" ++ body;
}

fn newCache() ramcache.Cache {
    return ramcache.Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 256 });
}

test "first key runs the handler once; replay returns the cached response without re-running" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
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

/// Test app for the concurrent first-flight case: while its handler is still
/// running (still "in flight"), it fires a *second* request with the SAME key
/// back through the router — standing in for a second connection thread racing
/// the first. The reservation must make that second request a 409, never a
/// second handler run.
const ReentrantApp = struct {
    store: *Store,
    r: *router.Router,
    calls: u32 = 0,
    second_got_409: bool = false,
    second_key: []const u8,
};

fn hReentrant(ctx: *router.Ctx) anyerror!void {
    const app: *ReentrantApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    if (app.calls == 1) {
        var buf: [2048]u8 = undefined;
        const resp = runWire(app.r, app.second_key, &buf);
        app.second_got_409 = std.mem.startsWith(u8, resp, "HTTP/1.1 409");
    }
    try app.store.respond(ctx, 201, "application/json", "ok");
}

test "concurrent first-flight of the same key does not double-run (in-flight 409)" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    var app = ReentrantApp{
        .store = &store,
        .r = &r,
        .second_key = reqKey("POST", "/orders", "dup-key"),
    };
    r.state = &app;
    var idem = Idempotency{ .store = &store };
    try r.use(idem.middleware());
    try r.post("/orders", hReentrant);

    var buf: [2048]u8 = undefined;
    const first = runWire(&r, reqKey("POST", "/orders", "dup-key"), &buf);

    // The outer request completes normally…
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 201"));
    // …the handler ran EXACTLY once — the nested same-key request did not
    // re-enter it (the bug would have made this 2)…
    try testing.expectEqual(@as(u32, 1), app.calls);
    // …because the concurrent duplicate was rejected with 409 in-flight.
    try testing.expect(app.second_got_409);
}

test "a different key runs the handler again" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
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
    defer store.deinit();
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
    defer store.deinit();
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
    defer store.deinit();
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
    defer store.deinit();
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
    defer store.deinit();
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

test "encode/decode round-trips digest, status, content-type and body" {
    const d1: [digest_len]u8 = [_]u8{0xAB} ** digest_len;
    const blob = try encode(testing.allocator, d1, 201, "application/json", "{\"ok\":true}");
    defer testing.allocator.free(blob);
    const rec = decode(blob).?;
    try testing.expectEqualSlices(u8, &d1, &rec.digest);
    try testing.expectEqual(@as(u16, 201), rec.status);
    try testing.expectEqualStrings("application/json", rec.content_type);
    try testing.expectEqualStrings("{\"ok\":true}", rec.body);

    // Empty content-type is valid; an all-zero digest is a valid bit pattern
    // too (just not one SHA-256 is expected to ever actually produce).
    const d2: [digest_len]u8 = [_]u8{0} ** digest_len;
    const blob2 = try encode(testing.allocator, d2, 204, "", "");
    defer testing.allocator.free(blob2);
    const rec2 = decode(blob2).?;
    try testing.expectEqualSlices(u8, &d2, &rec2.digest);
    try testing.expectEqual(@as(u16, 204), rec2.status);
    try testing.expectEqualStrings("", rec2.content_type);
    try testing.expectEqualStrings("", rec2.body);

    // A truncated blob (shorter than the digest + header) decodes to null
    // rather than reading out of bounds.
    try testing.expectEqual(@as(?RecordedResponse, null), decode("x"));
}

// Graduated from the `GAP:` test pinning the documented limitation (commit
// 71540f3): same target, different body used to replay the first response
// unchecked. Now the body is fingerprinted and a mismatch answers 422
// without running the handler — this is the conformance test for that.
test "same key and target with a different body answers 422, not a replay" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    const with_body = "POST /orders HTTP/1.1\r\nHost: t\r\nIdempotency-Key: dup\r\n" ++
        "Content-Type: application/json\r\nContent-Length: 10\r\n" ++
        "Connection: close\r\n\r\n{\"amt\":10}";
    const other_body = "POST /orders HTTP/1.1\r\nHost: t\r\nIdempotency-Key: dup\r\n" ++
        "Content-Type: application/json\r\nContent-Length: 12\r\n" ++
        "Connection: close\r\n\r\n{\"amt\":1000}";

    var b1: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, with_body, &b1)));
    try testing.expectEqual(@as(u32, 1), app.calls);

    // A DIFFERENT payload under the same key: not a replay — 422, and the
    // handler never sees it.
    var b2: [2048]u8 = undefined;
    const second = runWire(&r, other_body, &b2);
    try testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 422"));
    try testing.expectEqual(@as(?[]const u8, null), headerValue(second, "Idempotent-Replayed"));
    try testing.expectEqual(@as(u32, 1), app.calls); // the handler never saw the second request

    // The original is still intact and still replays on its own — the
    // mismatch didn't clobber or evict the recorded entry.
    var b3: [2048]u8 = undefined;
    const replay = runWire(&r, with_body, &b3);
    try testing.expectEqualStrings("order-1", bodyOf(replay));
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 1), app.calls);
}

test "same key, same body: replays across a retry even with a real request body" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    var b1: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqKeyBody("POST", "/orders", "dup", "{\"amt\":10}"), &b1)));

    var b2: [2048]u8 = undefined;
    const replay = runWire(&r, reqKeyBody("POST", "/orders", "dup", "{\"amt\":10}"), &b2);
    try testing.expectEqualStrings("order-1", bodyOf(replay));
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 1), app.calls);
}

test "key_only scope: same key and same body still cross-replays across endpoints (unaffected by fingerprinting)" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store, .options = .{ .scope = .key_only } };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);
    try r.post("/refunds", hOrder);

    var b1: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqKeyBody("POST", "/orders", "dup", "same"), &b1)));

    // Different endpoint, SAME key and SAME body under `.key_only`: this is
    // the documented "global across endpoints" behavior — the fingerprint
    // check does not get in its way because the body genuinely matches.
    var b2: [2048]u8 = undefined;
    const cross = runWire(&r, reqKeyBody("POST", "/refunds", "dup", "same"), &b2);
    try testing.expectEqualStrings("order-1", bodyOf(cross));
    try testing.expectEqualStrings("true", headerValue(cross, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 1), app.calls);
}

test "body fingerprint cap: exactly at the cap fingerprints normally; one byte over answers 413" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store, .options = .{ .max_body_bytes = 8 } };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    // Exactly at the cap (8 bytes): fingerprinted normally, runs, and then
    // replays on retry like any other guarded request.
    var b1: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqKeyBody("POST", "/orders", "at-cap", "AAAAAAAA"), &b1)));
    try testing.expectEqual(@as(u32, 1), app.calls);
    var b2: [2048]u8 = undefined;
    const replay = runWire(&r, reqKeyBody("POST", "/orders", "at-cap", "AAAAAAAA"), &b2);
    try testing.expectEqualStrings("order-1", bodyOf(replay));
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 1), app.calls);

    // One byte over the cap (9 bytes), a fresh key: cannot be safely
    // fingerprinted, so the request fails closed (413) rather than either
    // silently skipping the check or being allowed through unchecked. The
    // handler never runs.
    var b3: [2048]u8 = undefined;
    const over = runWire(&r, reqKeyBody("POST", "/orders", "over-cap", "AAAAAAAAA"), &b3);
    try testing.expect(std.mem.startsWith(u8, over, "HTTP/1.1 413"));
    try testing.expectEqual(@as(u32, 1), app.calls); // still 1 — the over-cap request never ran
}

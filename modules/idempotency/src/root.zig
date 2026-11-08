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
//! ## Recording: transparent, or through `respond`
//!
//! - The **middleware** owns the *replay* half. On a guarded request carrying a
//!   valid key it looks the key up in the `Store`; on a hit it writes the
//!   cached status + `Content-Type` + the headers the guarded chain set +
//!   body and short-circuits the chain — the handler genuinely never runs
//!   (what the hit-counter test asserts). On a miss it exposes the (scoped)
//!   key via `Store.current(req)` and runs the chain.
//! - The *record* half is **transparent** by default (`Options.capture`,
//!   2026-11-06): when the handler returns without error and has not called
//!   `respond`, the middleware reads the status, headers and body off
//!   `ctx.res` -- before the server puts a buffered response on the wire --
//!   and records them. A body that outgrew the server's response buffer has
//!   streamed; its plain bytes were collected through `http`'s
//!   `ResponseWriter.BodyTap` seam, up to `Options.max_capture_bytes`. What a
//!   replay could not reproduce (an upgrade, tunnel or detach, a failed or
//!   HEAD response, trailers, a length mismatch, a body the handler coded
//!   itself, an event stream, a body over the cap) is not recorded and is
//!   counted in `Store.capture_refused`.
//! - `store.respond(ctx, status, content_type, body)` is the cooperative path:
//!   it writes the response **and** records it first (so a dropped client
//!   still leaves the record, streamed body or not); a handler that uses it
//!   is never captured a second time. With `capture = .off` it is the only
//!   way to record -- the module's contract before 2026-11-06.
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
//! Cached: completed responses (status + optional `Content-Type` + the
//! response headers set inside the guarded chain, e.g. `Location` + body) with
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
//! lock-free). The scoped key travels middleware→handler in the store itself,
//! bound to the request's address (`Store.current`) -- never in thread-local
//! storage, which a second request on the same thread (a nested dispatch, or
//! another fiber on an evented `Io`) would overwrite (A1 F2). The in-flight
//! reservation set is guarded by the same lock; call `Store.deinit()` once
//! when the store is retired to release it. The `Store` and `Idempotency`
//! must outlive the `Router`, at stable addresses.

const std = @import("std");
const clock_lib = @import("clock");
const router = @import("router");
const http = @import("http");
const ramcache = @import("ramcache");
const kv = @import("kv");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Idempotency-Key dedup of unsafe retries — middleware + store (ramcache, or a pluggable Backend; durable KvBackend) replaying a recorded response without re-running the handler",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .server,
    // Internally synchronized: the ramcache store sits behind a documented
    // spinlock, so it is safe from all connection threads at once. The scoped
    // key travels via thread-local storage owned by the connection task.
    .concurrency = .threadsafe,
    .model_after = "Idempotency-Key (Stripe / draft-ietf-httpapi-idempotency-key-header)",
    .deps = .{ "router", "http", "ramcache", "kv", "clock" },
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
    return std.math.cast(i64, clock_lib.monotonicNs()) orelse std.math.maxInt(i64);
}

// ── pluggable record store ──────────────────────────────────────────────────

/// Where a `Store` keeps its records and reservations when they must outlive
/// the process or be shared between processes: a type-erased interface a
/// Redis, SQL or `kv` adapter implements (`KvBackend` is the bundled
/// durable one). Without a backend, the `Store` uses its in-process
/// `ramcache` (`Store.cache`).
///
/// Contract, which every implementation must keep:
/// - `lookupOrReserve` is ATOMIC per key: of two concurrent calls for a key
///   with no live record and no reservation, exactly one gets `.reserved`.
///   It returns `.found` (a live record, a copy owned by `gpa`), `.in_flight`
///   (another request holds the reservation), or `.reserved` (this request
///   now holds it). A backend that cannot answer (an I/O error) answers
///   `.in_flight`: the request is refused (409, "retry later") instead of
///   running the side effect a second time.
/// - `lease_ns > 0` bounds a reservation's life: a backend may hand a key
///   whose reservation is older than that to a new request (a holder that
///   crashed or hung). 0 = held until `release`.
/// - `put` records `blob` under `key` for `ttl_ns`, best-effort (a failure
///   only means a later retry runs again, as with a full `ramcache`).
///   The `Store` calls `put` (if the handler recorded) BEFORE `release`.
/// - `release` drops the reservation, whether or not a record was put.
/// - All three may be called from several threads at once.
pub const Backend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    /// The allocator the `Store` uses for its own short-lived copies (the
    /// encoded record, reservation keys, replay blobs).
    gpa: std.mem.Allocator,

    pub const Lookup = union(enum) {
        found: []u8,
        in_flight,
        reserved,
    };

    pub const VTable = struct {
        lookupOrReserve: *const fn (ptr: *anyopaque, key: []const u8, now: i64, lease_ns: i64, gpa: std.mem.Allocator) std.mem.Allocator.Error!Lookup,
        put: *const fn (ptr: *anyopaque, key: []const u8, blob: []const u8, now: i64, ttl_ns: i64) void,
        release: *const fn (ptr: *anyopaque, key: []const u8) void,
    };
};

/// A durable `Backend` over a `kv.Db` (`kvbackend.zig`): records survive a
/// restart, so a retry after a crash still replays instead of re-running.
pub const KvBackend = @import("kvbackend.zig").KvBackend;

test {
    _ = @import("kvbackend_test.zig");
}

// ── the store ───────────────────────────────────────────────────────────────

/// The key→response store the middleware and handlers share. Records live in
/// a caller-owned `ramcache.Cache` (TTL expiry, byte / entry bounds,
/// W-TinyLFU eviction) or, when `backend` is set, in that `Backend`
/// (durable or shared). Thread-safe: every cache touch is serialized by the
/// internal spinlock; a backend synchronizes itself. The `cache` / backend
/// must outlive the `Store`. Exactly one of `cache` and `backend` is set.
pub const Store = struct {
    /// The bounded, TTL-expiring cache. Caller owns it (init/deinit); the store
    /// only reads/writes through it under the lock. Its `alloc` is reused for
    /// the short-lived encode / read-out copies. Null when `backend` is set.
    cache: ?*ramcache.Cache = null,
    /// Records and reservations kept outside the process (`Backend`). When
    /// set, `cache` is unused and `in_flight` stays empty: the backend holds
    /// the reservations.
    backend: ?Backend = null,
    /// Passed to `Backend.lookupOrReserve` (see there). The in-process path
    /// releases every reservation when its handler returns and ignores it.
    lease_ns: i64 = 0,
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
    /// The reservation each executing request holds, by the request's
    /// address: how `respond` (and `current`) find the key and fingerprint
    /// the middleware looked up FOR THAT REQUEST. It used to be a
    /// thread-local, and anything that ran a second request on the same
    /// thread while the first was inside its handler -- a nested dispatch, or
    /// on an evented `Io` just another fiber -- overwrote it (A1 F2). The key
    /// slices point into `in_flight`'s owned copies. Guarded by `lock`.
    pending: std.AutoHashMapUnmanaged(usize, Current) = .empty,
    /// Responses transparent capture (`Options.capture`) saw but would not
    /// record: a streamed body over `max_capture_bytes` or out of memory, an
    /// upgrade / tunnel / detach, a failed or HEAD response, declared
    /// trailers, a declared length the body does not match, a body already
    /// content-coded by the handler, an event stream. Each is a request
    /// whose retry runs the handler again -- watch this counter.
    capture_refused: std.atomic.Value(u64) = .init(0),

    /// What a request holding a reservation is recording under.
    pub const Current = struct {
        key: []const u8,
        digest: [digest_len]u8,
        /// `ctx.res.headers_len` when the middleware reserved the key: the
        /// response headers from here on were set inside the guarded chain
        /// and are recorded by `respond` (the ones before it belong to outer
        /// middleware, which runs again on a replay).
        headers_mark: usize = 0,
        /// `respond` recorded this request's answer: transparent capture
        /// (`Options.capture`) leaves it alone.
        recorded: bool = false,
    };

    /// Release the in-flight reservation set. Call once when the store is no
    /// longer used. In steady state the set is empty (every reservation is
    /// released when its handler returns); this frees the map's backing.
    /// Total for a `Store` that was never given a `cache` or `backend` (nothing
    /// was ever reserved, so there is nothing to free).
    pub fn deinit(store: *Store) void {
        if (store.cache == null and store.backend == null) {
            store.* = undefined;
            return;
        }
        lockSpin(&store.lock);
        const a = store.alloc();
        var it = store.in_flight.keyIterator();
        while (it.next()) |k| a.free(k.*);
        store.in_flight.deinit(a);
        if (store.backend != null) {
            // Backend path: `pending` owns its key copies.
            var pit = store.pending.valueIterator();
            while (pit.next()) |c| a.free(c.key);
        }
        store.pending.deinit(a);
        store.lock.unlock();
        store.* = undefined;
    }

    /// The outcome of `begin`.
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
    ///
    /// Public for a server that has no `router` (qap): build the key with
    /// `scopeKey`, fingerprint the body, `begin`; on `.reserved` run the side
    /// effect, `record` its answer, and `finish` -- or pass `request` to have
    /// `current` find the reservation from inside the handler.
    pub fn begin(store: *Store, key: []const u8, digest: [digest_len]u8, request: ?*const anyopaque, gpa: std.mem.Allocator) std.mem.Allocator.Error!Begin {
        const now = store.clock.now();
        if (store.backend) |b| return store.beginBackend(b, key, digest, request, gpa, now);
        const cache = store.cacheOrPanic();
        lockSpin(&store.lock);
        defer store.lock.unlock();
        if (cache.get(key, now, 0)) |v| {
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
        const owned = try cache.alloc.dupe(u8, key);
        errdefer cache.alloc.free(owned);
        try store.in_flight.put(cache.alloc, owned, {});
        errdefer _ = store.in_flight.remove(owned);
        if (request) |r| try store.pending.put(cache.alloc, @intFromPtr(r), .{ .key = owned, .digest = digest });
        return .reserved;
    }

    /// `begin` over a `Backend`: the backend makes lookup + reservation
    /// atomic; the fingerprint check and the request binding stay here.
    fn beginBackend(store: *Store, b: Backend, key: []const u8, digest: [digest_len]u8, request: ?*const anyopaque, gpa: std.mem.Allocator, now: i64) std.mem.Allocator.Error!Begin {
        switch (try b.vtable.lookupOrReserve(b.ptr, key, now, store.lease_ns, gpa)) {
            .found => |v| {
                if (decode(v)) |rec| {
                    // Constant-time for the reason given in `begin`.
                    if (!std.crypto.timing_safe.eql([digest_len]u8, rec.digest, digest)) {
                        gpa.free(v);
                        return .mismatch;
                    }
                }
                return .{ .replay = v };
            },
            .in_flight => return .in_flight,
            .reserved => {
                const r = request orelse return .reserved;
                errdefer b.vtable.release(b.ptr, key);
                const owned = try b.gpa.dupe(u8, key);
                errdefer b.gpa.free(owned);
                lockSpin(&store.lock);
                defer store.lock.unlock();
                try store.pending.put(b.gpa, @intFromPtr(r), .{ .key = owned, .digest = digest });
                return .reserved;
            },
        }
    }

    /// Release the reservation taken by `begin` for `key` (and `request`'s
    /// binding to it, when one was given).
    pub fn finish(store: *Store, key: []const u8, request: ?*const anyopaque) void {
        if (store.backend) |b| {
            if (request) |r| {
                lockSpin(&store.lock);
                const kv_ = store.pending.fetchRemove(@intFromPtr(r));
                store.lock.unlock();
                if (kv_) |e| b.gpa.free(e.value.key);
            }
            b.vtable.release(b.ptr, key);
            return;
        }
        lockSpin(&store.lock);
        defer store.lock.unlock();
        if (request) |r| _ = store.pending.remove(@intFromPtr(r));
        if (store.in_flight.fetchRemove(key)) |e| store.cacheOrPanic().alloc.free(e.key);
    }

    /// The allocator for the store's own copies: the cache's, or the backend's.
    /// Panics (every build mode) on a `Store` with neither: it has nowhere to
    /// keep a record, and the first request would otherwise unwrap null.
    pub fn alloc(store: *const Store) std.mem.Allocator {
        if (store.backend) |b| return b.gpa;
        return store.cacheOrPanic().alloc;
    }

    fn cacheOrPanic(store: *const Store) *ramcache.Cache {
        return store.cache orelse @panic("idempotency: Store needs either `cache` or `backend`");
    }

    /// The reservation `request` holds, or null when it holds none (no key,
    /// an unguarded method, an invalid key, a replay). The key slice is
    /// valid until that request's reservation is finished.
    pub fn current(store: *Store, request: *const anyopaque) ?Current {
        lockSpin(&store.lock);
        defer store.lock.unlock();
        return store.pending.get(@intFromPtr(request));
    }

    fn markHeaders(store: *Store, request: *const anyopaque, mark: usize) void {
        lockSpin(&store.lock);
        defer store.lock.unlock();
        if (store.pending.getPtr(@intFromPtr(request))) |c| c.headers_mark = mark;
    }

    fn markRecorded(store: *Store, request: *const anyopaque) void {
        lockSpin(&store.lock);
        defer store.lock.unlock();
        if (store.pending.getPtr(@intFromPtr(request))) |c| c.recorded = true;
    }

    /// Write `body` to the response with `status` and optional `content_type`,
    /// **and** record it under the key the middleware exposed for this request
    /// (`current(ctx.req)`) so a later replay of the same key returns it. When
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
        // Record BEFORE writing: once the handler has reached `respond` the
        // side effect has run, so a write that fails (the client dropped the
        // connection, the exact case this module exists for) must still leave
        // the record a retry replays. Until 2026-10-23 the write came first and
        // its error skipped the record -- the retry ran the side effect again.
        if (store.current(ctx.req)) |c| {
            const hs = ctx.res.headers[@min(c.headers_mark, ctx.res.headers_len)..ctx.res.headers_len];
            store.recordWithHeaders(c.key, c.digest, status, content_type orelse "", hs, body);
            store.markRecorded(ctx.req);
        }
        try ctx.res.writeAll(body);
    }

    /// Record a completed response under `key`, alongside `digest` — the
    /// SHA-256 fingerprint of the request body that produced it, checked
    /// against a later same-key request (see `begin`). **Best-effort, and
    /// that is a real limit, not a footnote** (A1 F3): a failed encode, a
    /// full cache, or an eviction before the TTL -- `ramcache` is bounded and
    /// W-TinyLFU, and other callers' keys compete for the same room -- all
    /// mean a later retry runs the side effect AGAIN. For a charge or an
    /// order that is a double execution. Size the cache for the retry window
    /// of the traffic it guards, and where a duplicate is unacceptable keep
    /// the record in the same store and transaction as the side effect.
    /// Callable directly when a handler does not use `respond` -- pair with
    /// `current(ctx.req)` for the key and matching fingerprint.
    pub fn record(store: *Store, key: []const u8, digest: [digest_len]u8, status: u16, content_type: []const u8, body: []const u8) void {
        store.recordWithHeaders(key, digest, status, content_type, &.{}, body);
    }

    /// `record` plus response headers to replay (what `respond` passes: the
    /// ones the guarded chain set). Headers that describe one transfer rather
    /// than the response -- `Content-Type` (recorded on its own),
    /// `Content-Length`, `Transfer-Encoding`, `Content-Encoding`, `Trailer`,
    /// `Connection`, `Keep-Alive`, `Upgrade`, `Date` -- are left out, and so
    /// is `Set-Cookie` (a cookie is the first caller's, not the response's).
    pub fn recordWithHeaders(store: *Store, key: []const u8, digest: [digest_len]u8, status: u16, content_type: []const u8, headers: []const http.Header, body: []const u8) void {
        const a = store.alloc();
        const blob = encode(a, digest, status, content_type, headers, body) catch return;
        defer {
            std.crypto.secureZero(u8, blob); // a copy of the response body
            a.free(blob);
        }
        const now = store.clock.now();
        if (store.backend) |b| return b.vtable.put(b.ptr, key, blob, now, store.ttl_ns);
        lockSpin(&store.lock);
        defer store.lock.unlock();
        store.cacheOrPanic().put(key, blob, now, store.ttl_ns, 0);
    }
};

// Stored blob layout:
// [digest:32][status:u16 BE][ct_len:u16 BE][ct bytes][body bytes].
/// A recorded response, as `decode` reads it out of a `Begin.replay` blob.
/// The slices borrow the blob.
pub const RecordedResponse = struct {
    digest: [digest_len]u8,
    status: u16,
    content_type: []const u8,
    body: []const u8,
    /// The recorded headers, encoded; walk them with `headerIterator`.
    headers: []const u8 = "",

    pub fn headerIterator(rec: *const RecordedResponse) HeaderIterator {
        return .{ .rest = rec.headers };
    }

    pub const HeaderIterator = struct {
        rest: []const u8,

        /// `decode` validated the block, so every entry is whole.
        pub fn next(it: *HeaderIterator) ?http.Header {
            if (it.rest.len == 0) return null;
            const nl = std.mem.readInt(u16, it.rest[0..2], .big);
            const vl = std.mem.readInt(u16, it.rest[2..4], .big);
            const h: http.Header = .{ .name = it.rest[4..][0..nl], .value = it.rest[4 + @as(usize, nl) ..][0..vl] };
            it.rest = it.rest[4 + @as(usize, nl) + vl ..];
            return h;
        }
    };
};

/// Status bit 15 set: a header block follows the content type. A record
/// without replayable headers keeps the original layout byte for byte, so
/// records written before 2026-10-23 (and `KvBackend` files) still decode.
const headers_flag: u16 = 0x8000;

fn replayable(name: []const u8) bool {
    // `set-cookie`: a cookie belongs to the caller it was issued to. A replay
    // goes to whoever presents the same key and body (any client, with the
    // default `principal = null`), and a session cookie -- a whole
    // `sessions.CookieManager` session -- would hand them the first caller's
    // session (audit G 2026-11-06, finding 3).
    const skip = [_][]const u8{ "content-type", "content-length", "transfer-encoding", "content-encoding", "trailer", "connection", "keep-alive", "upgrade", "date", "set-cookie" };
    for (skip) |n| if (std.ascii.eqlIgnoreCase(name, n)) return false;
    return true;
}

fn encode(gpa: std.mem.Allocator, digest: [digest_len]u8, status: u16, content_type: []const u8, headers: []const http.Header, body: []const u8) ![]u8 {
    if (status & headers_flag != 0) return error.InvalidRecord;
    const ct_len = std.math.cast(u16, content_type.len) orelse return error.InvalidRecord;
    var block_len: usize = 0;
    for (headers) |h| if (replayable(h.name)) {
        if (h.name.len > std.math.maxInt(u16) or h.value.len > std.math.maxInt(u16)) return error.InvalidRecord;
        block_len += 4 + h.name.len + h.value.len;
    };
    const block_len32 = std.math.cast(u32, block_len) orelse return error.InvalidRecord;
    const hdr_part: usize = if (block_len == 0) 0 else 4 + block_len;
    const blob = try gpa.alloc(u8, digest_len + 4 + content_type.len + hdr_part + body.len);
    @memcpy(blob[0..digest_len], &digest);
    std.mem.writeInt(u16, blob[digest_len..][0..2], if (block_len == 0) status else status | headers_flag, .big);
    std.mem.writeInt(u16, blob[digest_len + 2 ..][0..2], ct_len, .big);
    @memcpy(blob[digest_len + 4 ..][0..content_type.len], content_type);
    var at = digest_len + 4 + content_type.len;
    if (block_len != 0) {
        std.mem.writeInt(u32, blob[at..][0..4], block_len32, .big);
        at += 4;
        for (headers) |h| if (replayable(h.name)) {
            std.mem.writeInt(u16, blob[at..][0..2], @intCast(h.name.len), .big);
            std.mem.writeInt(u16, blob[at + 2 ..][0..2], @intCast(h.value.len), .big);
            @memcpy(blob[at + 4 ..][0..h.name.len], h.name);
            @memcpy(blob[at + 4 + h.name.len ..][0..h.value.len], h.value);
            at += 4 + h.name.len + h.value.len;
        };
    }
    @memcpy(blob[at..], body);
    return blob;
}

/// Read a `Begin.replay` blob; null for one that is not a record (a server
/// then runs the request instead, as the middleware does).
pub fn decode(blob: []const u8) ?RecordedResponse {
    if (blob.len < digest_len + 4) return null;
    var digest: [digest_len]u8 = undefined;
    @memcpy(&digest, blob[0..digest_len]);
    const raw_status = std.mem.readInt(u16, blob[digest_len..][0..2], .big);
    const ct_len = std.mem.readInt(u16, blob[digest_len + 2 ..][0..2], .big);
    var at = digest_len + 4 + @as(usize, ct_len);
    if (at > blob.len) return null;
    const content_type = blob[digest_len + 4 ..][0..ct_len];
    var headers: []const u8 = "";
    if (raw_status & headers_flag != 0) {
        if (blob.len - at < 4) return null;
        const block_len = std.mem.readInt(u32, blob[at..][0..4], .big);
        at += 4;
        if (block_len == 0 or blob.len - at < block_len) return null;
        headers = blob[at..][0..block_len];
        at += block_len;
        var rest = headers;
        while (rest.len != 0) {
            if (rest.len < 4) return null;
            const n = 4 + @as(usize, std.mem.readInt(u16, rest[0..2], .big)) + std.mem.readInt(u16, rest[2..4], .big);
            if (n > rest.len) return null;
            rest = rest[n..];
        }
    }
    return .{
        .digest = digest,
        .status = raw_status & ~headers_flag,
        .content_type = content_type,
        .body = blob[at..],
        .headers = headers,
    };
}

// ── the middleware ──────────────────────────────────────────────────────────

/// What transparent capture (`Options.capture`) records of a handler that
/// answered without `respond`.
pub const Capture = enum {
    /// Nothing: only `respond` records (the module before 2026-11-06).
    off,
    /// 2xx answers only -- IdempotentAPI's `CacheOnlySuccessResponses`. A
    /// 4xx/5xx the handler wrote is not kept, so the retry runs again.
    success,
    /// Every status, 5xx included -- Stripe's documented behaviour, and what
    /// `respond` records.
    all,
};

/// Default `Options.max_capture_bytes`: 1 MiB of response body.
pub const default_max_capture_bytes: usize = 1 << 20;

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
    /// A guarded-method request without the key header answers 400 instead
    /// of running without deduplication (draft rev 07 §2.7, node
    /// `enforceIdempotency`). Off by default: a client that never sends a
    /// key keeps working. Turn it on for an operation documented as
    /// requiring the key; mount the middleware on just those routes.
    require_key: bool = false,
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
    /// Who the caller is, for keeping records apart: each caller gets its own
    /// key namespace (A1 F1). Return the credential or identity the request
    /// authenticated with -- the `Authorization` value, an account id; it is
    /// hashed before it reaches the cache. A request it returns null for is
    /// run without deduplication.
    ///
    /// ⚠ **Null here -- the default -- is ONE namespace for every caller.**
    /// Two clients that pick the same key for the same endpoint and body
    /// then share a record: the second is handed the FIRST one's response,
    /// and with a different body learns (422) that the key is in use.
    /// Client keys are client-chosen and often guessable. Leave this null
    /// only where there is exactly one caller.
    principal: ?*const fn (req: *const http.Server.Request) ?[]const u8 = null,
    /// Record the response of a guarded handler that never called `respond`
    /// (node-idempotency's `onResponse`, IdempotentAPI's filter, Stripe
    /// server-side): status, the headers the guarded chain set, and the
    /// body, read off the `http` writer when the handler returns -- before
    /// the server puts a buffered response on the wire, so a client that
    /// dropped still finds the record. A body that streams past the
    /// server's response buffer is collected through
    /// `http.Server.ResponseWriter.BodyTap` up to `max_capture_bytes`.
    /// `respond` still records first and wins. A handler that returns an
    /// error records nothing. Responses that cannot be replayed faithfully
    /// are never recorded and counted in `Store.capture_refused` (see
    /// there). Default `.all` since 2026-11-06; `.off` restores the
    /// cooperative-only behaviour.
    capture: Capture = .all,
    /// Largest response body transparent capture keeps; a longer one is
    /// refused (not recorded, counted). The collection buffer is allocated
    /// from the store's allocator only once a body streams past the server's
    /// response buffer, and grows with it up to this.
    max_capture_bytes: usize = default_max_capture_bytes,
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

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const idem: *const Idempotency = @ptrCast(@alignCast(state.?));
    if (!methodGuarded(idem.options.methods, ctx.req.method)) return next.run(ctx);
    var fields = ctx.req.headerAll(idem.options.header_name);
    const raw_key = fields.next() orelse
        return if (idem.options.require_key) keyRequired(ctx) else next.run(ctx);
    // A second field line makes the value a list, not the one String the
    // draft defines (RFC 9651 combines repeated lines): which key is meant is
    // ambiguous, and a proxy that keeps the other one would disagree with us.
    if (fields.next() != null) return badRequest(ctx);
    var key_text: [max_scoped_key]u8 = undefined;
    const client_key = parseKey(raw_key, idem.options.max_key_len, &key_text) orelse return badRequest(ctx);

    // A caller-scoped server whose request names no caller has nobody to
    // keep the record apart for: run it, record nothing (A1 F1).
    var principal_buf: [principal_hex_len]u8 = undefined;
    const principal: ?[]const u8 = if (idem.options.principal) |f|
        principalTag(f(ctx.req) orelse return next.run(ctx), &principal_buf)
    else
        null;
    var key_buf: [max_scoped_key]u8 = undefined;
    const scoped = scopeKey(&key_buf, idem.options.scope, ctx.req.methodName(), ctx.req.path, principal, client_key) orelse
        // Too long to scope — degrade to running normally without dedup.
        return next.run(ctx);

    // Buffer and fingerprint the body before the cache decision: whether
    // this is a replay or a 422 mismatch depends on it. Bounded — a body
    // over `max_body_bytes` cannot be safely fingerprinted, so it fails
    // closed (413) instead of silently skipping the check (see the module
    // doc's "Request-fingerprint mismatch" note).
    //
    // Zig 0.17 `allocRemaining(.limited(n))` accepts exactly `n` bytes and
    // fails with `StreamTooLong` on the next one (0.16 failed at `n`, which
    // is why this used to probe at `max_body_bytes + 1`) -- exactly the
    // documented boundary. `maxInt` means unlimited (`n + 1` would overflow).
    const probe_cap: std.Io.Limit = if (idem.options.max_body_bytes == std.math.maxInt(usize))
        .unlimited
    else
        .limited(idem.options.max_body_bytes);
    const body_bytes = ctx.req.reader().allocRemaining(idem.store.alloc(), probe_cap) catch |err| switch (err) {
        error.StreamTooLong => return payloadTooLarge(ctx),
        else => |e| return e,
    };
    defer {
        // The caller's payload, on a heap the next request draws from (A1 F4).
        std.crypto.secureZero(u8, body_bytes);
        idem.store.alloc().free(body_bytes);
    }
    const digest = fingerprint(body_bytes, ctx.req.query);

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
    const begun = try idem.store.begin(scoped, digest, ctx.req, idem.store.alloc());
    if (begun == .reserved) idem.store.markHeaders(ctx.req, ctx.res.headers_len);
    switch (begun) {
        .replay => |blob| {
            // A hit writes the recorded response and short-circuits the chain,
            // so the handler never runs.
            // Wiped like every other copy of a recorded response
            // (`recordWithHeaders`, the capture buffers): it may hold a token.
            defer {
                std.crypto.secureZero(u8, blob);
                idem.store.alloc().free(blob);
            }
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
            var hs = rec.headerIterator();
            while (hs.next()) |h| try ctx.res.setHeader(h.name, h.value);
            if (idem.options.replay_header.len != 0)
                try ctx.res.setHeader(idem.options.replay_header, "true");
            try ctx.res.writeAll(rec.body); // writeAll copies, so freeing blob after is safe
            return;
        },
        .mismatch => return unprocessable(ctx),
        .in_flight => return conflict(ctx),
        .reserved => {},
    }

    // Miss (reserved): the reservation is bound to THIS request (`current`),
    // run the chain, then release it so a later retry can proceed.
    defer idem.store.finish(scoped, ctx.req);
    if (idem.options.capture == .off) return next.run(ctx);
    return captureRun(idem, ctx, next);
}

/// Collects the body bytes the writer drains while the guarded chain runs
/// (`http.Server.ResponseWriter.BodyTap`), bounded; forwards to the tap it
/// displaced so an outer capturer sees them too.
const Capturer = struct {
    gpa: std.mem.Allocator,
    limit: usize,
    prev: ?*const http.Server.ResponseWriter.BodyTap,
    bytes: std.ArrayList(u8) = .empty,
    /// Over `limit` or out of memory: the body is incomplete, never recorded.
    overflow: bool = false,

    fn observe(ctx: *anyopaque, chunk: []const u8) void {
        const c: *Capturer = @ptrCast(@alignCast(ctx));
        if (c.prev) |p| p.observe(p.ctx, chunk);
        if (c.overflow) return;
        if (chunk.len > c.limit - c.bytes.items.len) {
            c.overflow = true;
            return;
        }
        c.append(chunk) catch {
            c.overflow = true;
        };
    }

    /// `appendSlice` whose growth wipes the buffer it leaves behind:
    /// `ArrayList` frees the old copy of the body unwiped (audit G finding 5).
    fn append(c: *Capturer, chunk: []const u8) error{OutOfMemory}!void {
        const need = c.bytes.items.len + chunk.len;
        if (need > c.bytes.capacity) {
            const new_cap = @min(@max(need, c.bytes.capacity *| 2, 256), @max(need, c.limit));
            const fresh = try c.gpa.alloc(u8, new_cap);
            @memcpy(fresh[0..c.bytes.items.len], c.bytes.items);
            const old = c.bytes.allocatedSlice();
            std.crypto.secureZero(u8, old);
            c.gpa.free(old);
            c.bytes.items = fresh[0..c.bytes.items.len];
            c.bytes.capacity = new_cap;
        }
        c.bytes.appendSliceAssumeCapacity(chunk);
    }

    fn deinit(c: *Capturer) void {
        std.crypto.secureZero(u8, c.bytes.allocatedSlice());
        c.bytes.deinit(c.gpa);
    }
};

fn captureRun(idem: *const Idempotency, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const res = ctx.res;
    var cap: Capturer = .{ .gpa = idem.store.alloc(), .limit = idem.options.max_capture_bytes, .prev = res.body_tap };
    defer cap.deinit();
    const tap: http.Server.ResponseWriter.BodyTap = .{ .ctx = &cap, .observe = Capturer.observe };
    res.body_tap = &tap;
    defer res.body_tap = cap.prev;
    try next.run(ctx); // an error records nothing; `finish` releases
    // An inner tap that replaced ours without chaining to it or restoring it
    // hid part of the body from us: what we hold is a tail, not the response
    // (audit G finding 4).
    if (res.body_tap != &tap) return refuseCapture(idem.store);
    captureRecord(idem, ctx, &cap);
}

/// Record what the guarded chain answered, or refuse (and count) a response
/// a replay could not reproduce.
fn captureRecord(idem: *const Idempotency, ctx: *router.Ctx, cap: *Capturer) void {
    const store = idem.store;
    const c = store.current(ctx.req) orelse return;
    if (c.recorded) return; // `respond` did it
    const res = ctx.res;
    switch (idem.options.capture) {
        .off => return,
        .success => if (res.status < 200 or res.status > 299) return,
        .all => {},
    }
    const ct = res.getHeader("Content-Type") orelse "";
    const refuse = cap.overflow or
        // The connection is someone else's now (WebSocket, CONNECT), or the
        // embedder keeps writing past the handler: no complete response.
        res.handed_over or res.detached or
        res.failed or res.head_request or
        // A replay carries no trailer section.
        res.declared_trailers_len != 0 or
        // A body the handler coded itself: the replay would drop the coding
        // header (it describes a transfer, see `recordWithHeaders`).
        res.getHeader("Content-Encoding") != null or
        // An event stream is a feed, not an answer to replay.
        std.ascii.startsWithIgnoreCase(ct, "text/event-stream");
    if (refuse) return refuseCapture(store);
    const tail = res.bufferedBody();
    const body: []const u8 = if (cap.bytes.items.len == 0) tail else blk: {
        if (tail.len > cap.limit - cap.bytes.items.len) return refuseCapture(store);
        cap.append(tail) catch return refuseCapture(store);
        break :blk cap.bytes.items;
    };
    if (body.len > cap.limit) return refuseCapture(store);
    // `end` would fail this response (or has): not what the client gets.
    // A 204/304/1xx carries no body, whatever length it declares.
    const bodiless = res.status < 200 or res.status == 204 or res.status == 304;
    if (res.declared_len) |n| if (!bodiless and n != body.len) return refuseCapture(store);
    const hs = res.headers[@min(c.headers_mark, res.headers_len)..res.headers_len];
    store.recordWithHeaders(c.key, c.digest, res.status, ct, hs, body);
}

fn refuseCapture(store: *Store) void {
    _ = store.capture_refused.fetchAdd(1, .monotonic);
}

/// The request fingerprint recorded with a response and compared on a
/// same-key request: SHA-256 of the body, and -- only when the request has a
/// query string -- of `SHA-256(body) ++ 0x01 ++ query` (fixed-width first
/// part, so no two (body, query) pairs share an input). The scoped key holds
/// the path but not the query, so without this `POST /pay?to=alice` and
/// `POST /pay?to=mallory` with one key and one (empty) body replayed the
/// first answer for the second: the second request never ran, and the client
/// was told it had. A request without a query keeps the plain body digest,
/// so records stored before this stay valid.
fn fingerprint(body: []const u8, query: []const u8) [digest_len]u8 {
    var digest: [digest_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
    if (query.len == 0) return digest;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&digest);
    h.update(&.{0x01});
    h.update(query);
    h.final(&digest);
    return digest;
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
pub fn validKey(v: []const u8, max_len: usize) bool {
    if (v.len == 0 or v.len > max_len) return false;
    for (v) |c| {
        if (c <= ' ' or c >= 0x7f) return false;
    }
    return true;
}

/// The client key an `Idempotency-Key` field value names, or null when it
/// names none (answer 400). The draft (rev 07 §2) defines the value as an
/// RFC 9651 sf-string -- `"8e03978e-40d5-43e8-bc93-6894a57f9324"` -- and
/// Stripe sends the bare token; both are accepted, and both spellings of one
/// key are one key (the quotes and escapes are not part of it). A quoted key
/// may hold spaces (sf-string allows %x20-7E); a bare one must pass
/// `validKey`. Parameters after the string are refused. `buf` holds an
/// unescaped key, which can be no longer than `max_len`.
pub fn parseKey(raw: []const u8, max_len: usize, buf: []u8) ?[]const u8 {
    if (raw.len == 0 or raw[0] != '"') return if (validKey(raw, max_len)) raw else null;
    var n: usize = 0;
    var i: usize = 1;
    while (i < raw.len) : (i += 1) {
        var c = raw[i];
        if (c == '"') {
            if (i + 1 != raw.len or n == 0) return null; // trailing bytes / ""
            return buf[0..n];
        }
        if (c == '\\') {
            i += 1;
            if (i == raw.len) return null;
            c = raw[i];
            if (c != '"' and c != '\\') return null;
        } else if (c < 0x20 or c > 0x7e) return null;
        if (n == max_len or n == buf.len) return null;
        buf[n] = c;
        n += 1;
    }
    return null; // no closing quote
}

/// Build the scoped cache key into `buf`, or null when it would overflow.
/// `client_key` is the already-fetched (and validated) header value;
/// `principal` a `principalTag` (or null for a shared namespace).
pub fn scopeKey(
    buf: []u8,
    scope: Scope,
    /// The method's name as sent (`Request.methodName`): two extension
    /// methods must not share a key.
    method: []const u8,
    path: []const u8,
    principal: ?[]const u8,
    client_key: []const u8,
) ?[]const u8 {
    const who = principal orelse "*";
    return switch (scope) {
        .key_only => std.mem.print(buf, "{s} {s}", .{ who, client_key }) catch null,
        .target => std.mem.print(buf, "{s} {s} {s} {s}", .{
            who, method, path, client_key,
        }) catch null,
    };
}

/// Length of a `principalTag`.
pub const principal_hex_len = 32;

/// The caller's identity as it enters a cache key: 16 bytes of SHA-256, in
/// hex. Never the raw value -- a principal is typically a bearer token, and
/// the cache is a long-lived map that outlives the request and would hold
/// it at rest.
pub fn principalTag(principal: []const u8, out: *[principal_hex_len]u8) []const u8 {
    var d: [digest_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(principal, &d, .{});
    return std.mem.print(out, "{x}", .{d[0 .. principal_hex_len / 2]}) catch unreachable;
}

fn badRequest(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(400);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Invalid Idempotency-Key\n");
}

/// A guarded request without a key under `Options.require_key`: the draft's
/// SHOULD-400 (rev 07 §2.7). The handler never runs.
fn keyRequired(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(400);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Idempotency-Key required\n");
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
    const body = std.mem.print(&body_buf, "order-{d}", .{app.calls}) catch unreachable;
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
    const i = std.mem.find(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
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

test "a Store with neither cache nor backend can be deinit-ed (sweep ID-1)" {
    // Using it panics with a message (`alloc`); retiring it must stay total.
    var store = Store{};
    store.deinit();
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

// ── review additions (2026-10-23) ───────────────────────────────────────────

fn idemRouter(r: *router.Router, idem: *Idempotency, app: *App, h: router.Handler) !void {
    r.state = app;
    try r.use(idem.middleware());
    try r.post("/orders", h);
}

fn hBig(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    const body: [6000]u8 = @splat('z');
    try app.store.respond(ctx, 201, "text/plain", &body);
}

test "respond records before it writes: a write that fails still leaves the record the retry replays" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hBig);

    // 6000 bytes overflow the 4 KiB response buffer, so `writeAll` flushes
    // into a 64-byte connection: the write fails mid-body, after the side
    // effect. Kills: the record after the write.
    var tiny: [64]u8 = undefined;
    _ = runWire(&r, reqKey("POST", "/orders", "big-1"), &tiny);
    try testing.expectEqual(@as(u32, 1), app.calls);

    var b: [8192]u8 = undefined;
    const replay = runWire(&r, reqKey("POST", "/orders", "big-1"), &b);
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 1), app.calls);
}

var outer_count: u32 = 0;

fn outerStamp(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    outer_count += 1;
    var buf: [16]u8 = undefined;
    try ctx.res.setHeader("X-Outer", std.mem.print(&buf, "{d}", .{outer_count}) catch unreachable);
    return next.run(ctx);
}

fn hLocation(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    try ctx.res.setHeader("Location", "/orders/1");
    try ctx.res.setHeader("ETag", "\"v1\"");
    try app.store.respond(ctx, 201, "application/json", "{}");
}

test "a replay carries the headers the guarded handler set, not the outer middleware's" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    outer_count = 0;
    try r.use(.{ .state = null, .run = outerStamp }); // outside the guard
    try r.use(idem.middleware());
    try r.post("/orders", hLocation);

    var b1: [2048]u8 = undefined;
    const first = runWire(&r, reqKey("POST", "/orders", "loc-1"), &b1);
    try testing.expectEqualStrings("/orders/1", headerValue(first, "Location").?);
    try testing.expectEqualStrings("1", headerValue(first, "X-Outer").?);

    var b2: [2048]u8 = undefined;
    const replay = runWire(&r, reqKey("POST", "/orders", "loc-1"), &b2);
    try testing.expectEqual(@as(u32, 1), app.calls);
    try testing.expectEqualStrings("/orders/1", headerValue(replay, "Location").?);
    try testing.expectEqualStrings("\"v1\"", headerValue(replay, "ETag").?);
    try testing.expectEqualStrings("application/json", headerValue(replay, "Content-Type").?);
    // The outer middleware ran again for the replay; its old value is not
    // replayed over the new one.
    try testing.expectEqualStrings("2", headerValue(replay, "X-Outer").?);
}

test "the draft's sf-string key and the bare token are one key; parameters, empties and duplicates are 400" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hOrder);

    var b: [2048]u8 = undefined;
    _ = runWire(&r, reqKey("POST", "/orders", "\"8e03978e\""), &b);
    try testing.expectEqual(@as(u32, 1), app.calls);
    const bare = runWire(&r, reqKey("POST", "/orders", "8e03978e"), &b);
    try testing.expectEqualStrings("true", headerValue(bare, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 1), app.calls);
    // A space is fine inside quotes; an escape is unescaped.
    _ = runWire(&r, reqKey("POST", "/orders", "\"a b\""), &b);
    try testing.expectEqual(@as(u32, 2), app.calls);
    _ = runWire(&r, reqKey("POST", "/orders", "\"q\\\"x\""), &b);
    try testing.expectEqual(@as(u32, 3), app.calls);
    for ([_][]const u8{
        reqKey("POST", "/orders", "\"k\";p=1"),
        reqKey("POST", "/orders", "\"\""),
        reqKey("POST", "/orders", "\"open"),
        reqKey("POST", "/orders", "\"bad\\x\""),
        "POST /orders HTTP/1.1\r\nHost: t\r\nIdempotency-Key: k1\r\nIdempotency-Key: k2\r\nConnection: close\r\n\r\n",
    }) |req| {
        const got = runWire(&r, req, &b);
        try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 400"));
    }
    try testing.expectEqual(@as(u32, 3), app.calls);
}

fn hFailOnce(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    if (app.calls == 1) return error.Boom;
    try app.store.respond(ctx, 201, null, "done");
}

test "a handler that fails releases the reservation: the retry runs, it is not a 409" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hFailOnce);

    var b: [2048]u8 = undefined;
    const first = runWire(&r, reqKey("POST", "/orders", "f-1"), &b);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 500"));
    const retry = runWire(&r, reqKey("POST", "/orders", "f-1"), &b);
    try testing.expect(std.mem.startsWith(u8, retry, "HTTP/1.1 201"));
    try testing.expectEqual(@as(u32, 2), app.calls);
    try testing.expectEqual(@as(usize, 0), store.in_flight.count());
    // ...and its binding: a stale one would hand a later request at the same
    // address this key, and its `respond` would record over the key's answer.
    try testing.expectEqual(@as(usize, 0), store.pending.count());
}

test "encode keeps only replayable headers and refuses a status with bit 15; parseKey bounds" {
    const hs = [_]http.Header{
        .{ .name = "Date", .value = "Thu, 23 Oct 2026 00:00:00 GMT" },
        .{ .name = "Location", .value = "/x" },
        .{ .name = "content-length", .value = "2" },
        .{ .name = "Connection", .value = "close" },
    };
    const d: [digest_len]u8 = @splat(1);
    const blob = try encode(testing.allocator, d, 201, "text/plain", &hs, "ok");
    defer testing.allocator.free(blob);
    const rec = decode(blob).?;
    var it = rec.headerIterator();
    const only = it.next().?;
    try testing.expectEqualStrings("Location", only.name);
    try testing.expectEqualStrings("/x", only.value);
    try testing.expect(it.next() == null);
    try testing.expectEqual(@as(u16, 201), rec.status);
    try testing.expectError(error.InvalidRecord, encode(testing.allocator, d, 0x8000 | 201, "", &.{}, ""));

    var buf: [max_scoped_key]u8 = undefined;
    const k255 = "\"" ++ @as([255]u8, @splat('k')) ++ "\"";
    const k256 = "\"" ++ @as([256]u8, @splat('k')) ++ "\"";
    try testing.expectEqual(@as(usize, 255), parseKey(k255, 255, &buf).?.len);
    try testing.expect(parseKey(k256, 255, &buf) == null);
    try testing.expect(parseKey("\"a\x01b\"", 255, &buf) == null);
    try testing.expect(parseKey("\"a\x7fb\"", 255, &buf) == null);
    try testing.expectEqualStrings("a b", parseKey("\"a b\"", 255, &buf).?);
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

test "A1 F2: a nested same-key request does not erase the outer one's record -- the retry replays" {
    // The per-request key used to travel middleware -> handler in a
    // thread-local. Anything that runs a second request on the same thread
    // while the first is inside its handler -- this nested call, or on an
    // evented `Io` simply another fiber -- reset it: the outer `respond` then
    // recorded nothing, and the client's retry ran the side effect again.
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
    _ = runWire(&r, reqKey("POST", "/orders", "dup-key"), &buf);
    try testing.expectEqual(@as(u32, 1), app.calls);

    // The retry: a replay of the outer request's answer, handler untouched.
    var buf2: [2048]u8 = undefined;
    const retry = runWire(&r, reqKey("POST", "/orders", "dup-key"), &buf2);
    try testing.expectEqualStrings("true", headerValue(retry, "Idempotent-Replayed") orelse "");
    try testing.expectEqual(@as(u32, 1), app.calls);
}

fn authPrincipal(req: *const http.Server.Request) ?[]const u8 {
    return req.header("authorization");
}

fn reqAuthKey(comptime auth: []const u8, comptime key: []const u8) []const u8 {
    return "POST /orders HTTP/1.1\r\nHost: t\r\nAuthorization: " ++ auth ++
        "\r\nIdempotency-Key: " ++ key ++ "\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
}

test "A1 F1: with a principal, two callers' same key are two records -- neither is handed the other's answer" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store, .options = .{ .principal = authPrincipal } };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    var b: [2048]u8 = undefined;
    // Alice and Bob both pick the key "1" -- same endpoint, same body.
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqAuthKey("Bearer alice", "1"), &b)));
    const bob = runWire(&r, reqAuthKey("Bearer bob", "1"), &b);
    // Without the principal Bob got "order-1" -- Alice's order -- as a replay.
    try testing.expectEqualStrings("order-2", bodyOf(bob));
    try testing.expectEqual(@as(?[]const u8, null), headerValue(bob, "Idempotent-Replayed"));
    try testing.expectEqual(@as(u32, 2), app.calls);

    // Each caller's own retry still replays its own answer.
    const alice_retry = runWire(&r, reqAuthKey("Bearer alice", "1"), &b);
    try testing.expectEqualStrings("order-1", bodyOf(alice_retry));
    try testing.expectEqualStrings("true", headerValue(alice_retry, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 2), app.calls);
}

test "A1 F1: a request the principal hook cannot name runs without deduplication" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store, .options = .{ .principal = authPrincipal } };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);

    var b: [2048]u8 = undefined;
    _ = runWire(&r, reqKey("POST", "/orders", "anon"), &b);
    _ = runWire(&r, reqKey("POST", "/orders", "anon"), &b);
    try testing.expectEqual(@as(u32, 2), app.calls);
    try testing.expectEqual(@as(usize, 0), cache.stats.entries);
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

test "require_key: a guarded request without the key answers 400, others pass" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store, .options = .{ .require_key = true } };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);
    try r.get("/orders", hOrder);

    var b1: [2048]u8 = undefined;
    const missing = runWire(&r, reqNoKey("POST", "/orders"), &b1);
    try testing.expect(std.mem.startsWith(u8, missing, "HTTP/1.1 400"));
    try testing.expectEqualStrings("Idempotency-Key required\n", bodyOf(missing));
    try testing.expectEqual(@as(u32, 0), app.calls);
    // A method outside `methods` is not guarded, so no key is required.
    var b2: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqNoKey("GET", "/orders"), &b2)));
    // With the key, the request runs and records as usual.
    var b3: [2048]u8 = undefined;
    var b4: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-2", bodyOf(runWire(&r, reqKey("POST", "/orders", "k1"), &b3)));
    try testing.expectEqualStrings("order-2", bodyOf(runWire(&r, reqKey("POST", "/orders", "k1"), &b4)));
    try testing.expectEqual(@as(u32, 2), app.calls);
}

test "require_key: PUT and PATCH need the key too, DELETE is unguarded; a present but empty or oversized key is 'Invalid', not 'required'" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store, .options = .{ .require_key = true, .max_key_len = 8 } };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.put("/orders", hOrder);
    try r.patch("/orders", hOrder);
    try r.delete("/orders", hOrder);
    try r.post("/orders", hOrder);

    var b: [2048]u8 = undefined;
    for ([_][]const u8{ reqNoKey("PUT", "/orders"), reqNoKey("PATCH", "/orders") }) |w| {
        const got = runWire(&r, w, &b);
        try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 400"));
        try testing.expectEqualStrings("Idempotency-Key required\n", bodyOf(got));
        try testing.expectEqualStrings("text/plain", headerValue(got, "Content-Type").?);
    }
    try testing.expectEqual(@as(u32, 0), app.calls);
    // DELETE is not in `methods`: it runs without a key.
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, reqNoKey("DELETE", "/orders"), &b)));
    // A key that is present but unusable is a bad key, whatever require_key says.
    for ([_][]const u8{ reqKey("POST", "/orders", ""), reqKey("POST", "/orders", "abcdefghi"), reqKey("POST", "/orders", "a b") }) |w| {
        const got = runWire(&r, w, &b);
        try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 400"));
        try testing.expectEqualStrings("Invalid Idempotency-Key\n", bodyOf(got));
    }
    try testing.expectEqual(@as(u32, 1), app.calls);
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
    const d1: [digest_len]u8 = @as([digest_len]u8, @splat(0xAB));
    const blob = try encode(testing.allocator, d1, 201, "application/json", &.{}, "{\"ok\":true}");
    defer testing.allocator.free(blob);
    const rec = decode(blob).?;
    try testing.expectEqualSlices(u8, &d1, &rec.digest);
    try testing.expectEqual(@as(u16, 201), rec.status);
    try testing.expectEqualStrings("application/json", rec.content_type);
    try testing.expectEqualStrings("{\"ok\":true}", rec.body);

    // Empty content-type is valid; an all-zero digest is a valid bit pattern
    // too (just not one SHA-256 is expected to ever actually produce).
    const d2: [digest_len]u8 = @as([digest_len]u8, @splat(0));
    const blob2 = try encode(testing.allocator, d2, 204, "", &.{}, "");
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

test "same key and path with a different query answers 422, not a replay (audit 2026-10-19)" {
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

    const alice = reqKey("POST", "/orders?to=alice", "q1");
    const mallory = reqKey("POST", "/orders?to=mallory", "q1");

    var b1: [2048]u8 = undefined;
    try testing.expectEqualStrings("order-1", bodyOf(runWire(&r, alice, &b1)));
    // Same key, same path, same (empty) body, other query: a different
    // request. It must not be handed the first answer, and must not run.
    var b2: [2048]u8 = undefined;
    const second = runWire(&r, mallory, &b2);
    try testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 422"));
    try testing.expectEqual(@as(u32, 1), app.calls);
    // The identical request still replays.
    var b3: [2048]u8 = undefined;
    const replay = runWire(&r, alice, &b3);
    try testing.expectEqualStrings("order-1", bodyOf(replay));
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

// ── transparent capture (2026-11-06) ────────────────────────────────────────

/// `runWire` with a bigger response buffer budget on the wire side and,
/// with `gzip`, response compression on (min 16 bytes) -- the request
/// decides by its `Accept-Encoding`.
fn runWireGz(r: *router.Router, bytes: []const u8, out_buf: []u8, gzip: bool) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var response_body_buf: [4096]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
    const gz: ?*http.Server.GzipScratch = if (gzip) testing.allocator.create(http.Server.GzipScratch) catch @panic("OOM") else null;
    defer if (gz) |g| testing.allocator.destroy(g);
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
        .compression = if (gzip) .{ .min_size = 16 } else null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
        .gzip = gz,
    });
    return out.buffered();
}

/// What the capture handlers do, picked by the test.
const RawMode = enum { plain, status_500, big, upgrade, detach, sse, coded, trailer, fail, respond_then_more, json };

const RawApp = struct {
    calls: u32 = 0,
    mode: RawMode = .plain,
};

/// A handler that never calls `respond`: it writes `ctx.res` itself.
fn hRaw(ctx: *router.Ctx) anyerror!void {
    const app: *RawApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    var nb: [16]u8 = undefined;
    const n = std.mem.print(&nb, "{d}", .{app.calls}) catch unreachable;
    switch (app.mode) {
        .plain => {
            ctx.res.setStatus(201);
            try ctx.res.setHeader("Content-Type", "application/json");
            try ctx.res.setHeader("Location", "/orders/7");
            try ctx.res.writeAll("{\"order\":");
            try ctx.res.writeAll(n);
            try ctx.res.writeAll("}");
        },
        .status_500 => {
            ctx.res.setStatus(500);
            try ctx.res.writeAll("boom ");
            try ctx.res.writeAll(n);
        },
        .big => {
            // 6000 bytes in pieces: past the 4 KiB response buffer, so the
            // head goes out and the body streams through the tap.
            try ctx.res.setHeader("Content-Type", "text/plain");
            var i: usize = 0;
            while (i < 6000) : (i += 1) try ctx.res.writer().writeByte(@intCast('a' + (i + app.calls) % 26));
        },
        .upgrade => {
            try ctx.res.setHeader("Sec-WebSocket-Accept", "x");
            try ctx.res.upgrade("websocket");
        },
        .detach => {
            try ctx.res.writeAll("partial");
            ctx.res.detach();
        },
        .sse => {
            try ctx.res.setHeader("Content-Type", "text/event-stream");
            try ctx.res.writeAll("data: 1\n\n");
        },
        .coded => {
            try ctx.res.setHeader("Content-Encoding", "br");
            try ctx.res.writeAll("\x0b\x02\x80coded");
        },
        .trailer => {
            try ctx.res.declareTrailer("X-Sum");
            try ctx.res.writeAll("body");
            try ctx.res.setTrailer("X-Sum", "1");
        },
        .fail => {
            try ctx.res.writeAll("half");
            return error.SideEffectFailed;
        },
        .respond_then_more => {
            // `respond` records; the extra bytes after it are not the
            // recorded answer, and capture must not overwrite it.
            const app2: *Store = cap_store.?;
            try app2.respond(ctx, 200, "text/plain", "recorded");
            try ctx.res.writeAll("+extra");
        },
        .json => {
            try ctx.res.setHeader("Content-Type", "application/json");
            const as: [300]u8 = @splat('q');
            try ctx.res.writeAll("{\"v\":\"" ++ as ++ "\"}");
        },
    }
}

var cap_store: ?*Store = null;

const CapFixture = struct {
    cache: ramcache.Cache,
    store: Store,
    app: RawApp,
    idem: Idempotency,
    r: router.Router,

    fn init(f: *CapFixture, mode: RawMode, opts: Options) !void {
        f.cache = newCache();
        f.store = .{ .cache = &f.cache };
        f.app = .{ .mode = mode };
        f.idem = .{ .store = &f.store, .options = opts };
        f.r = router.Router.init(testing.allocator);
        f.r.state = &f.app;
        cap_store = &f.store;
        try f.r.use(f.idem.middleware());
        try f.r.post("/orders", hRaw);
    }

    fn deinit(f: *CapFixture) void {
        f.r.deinit();
        f.store.deinit();
        f.cache.deinit();
        cap_store = null;
    }
};

test "capture: a handler that never calls respond is recorded and replayed -- status, headers, body; it runs once" {
    var f: CapFixture = undefined;
    try f.init(.plain, .{}); // the default is `.all`
    defer f.deinit();
    var b1: [2048]u8 = undefined;
    const first = runWire(&f.r, reqKey("POST", "/orders", "cap-1"), &b1);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 201"));
    try testing.expectEqualStrings("{\"order\":1}", bodyOf(first));
    var b2: [2048]u8 = undefined;
    const replay = runWire(&f.r, reqKey("POST", "/orders", "cap-1"), &b2);
    try testing.expectEqual(@as(u32, 1), f.app.calls);
    try testing.expect(std.mem.startsWith(u8, replay, "HTTP/1.1 201"));
    try testing.expectEqualStrings("{\"order\":1}", bodyOf(replay));
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expectEqualStrings("application/json", headerValue(replay, "Content-Type").?);
    try testing.expectEqualStrings("/orders/7", headerValue(replay, "Location").?);
    try testing.expectEqualStrings("11", headerValue(replay, "Content-Length").?);
    try testing.expectEqual(@as(u64, 0), f.store.capture_refused.load(.monotonic));
}

test "capture: .off keeps the cooperative contract -- an unrecorded handler runs on every retry" {
    var f: CapFixture = undefined;
    try f.init(.plain, .{ .capture = .off });
    defer f.deinit();
    var b: [2048]u8 = undefined;
    _ = runWire(&f.r, reqKey("POST", "/orders", "off-1"), &b);
    const again = runWire(&f.r, reqKey("POST", "/orders", "off-1"), &b);
    try testing.expectEqual(@as(u32, 2), f.app.calls);
    try testing.expectEqualStrings("{\"order\":2}", bodyOf(again));
    try testing.expect(headerValue(again, "Idempotent-Replayed") == null);
}

test "capture: .success leaves a 5xx out (the retry runs), .all replays it (Stripe)" {
    {
        var f: CapFixture = undefined;
        try f.init(.status_500, .{ .capture = .success });
        defer f.deinit();
        var b: [2048]u8 = undefined;
        _ = runWire(&f.r, reqKey("POST", "/orders", "s-1"), &b);
        const again = runWire(&f.r, reqKey("POST", "/orders", "s-1"), &b);
        try testing.expectEqual(@as(u32, 2), f.app.calls);
        try testing.expectEqualStrings("boom 2", bodyOf(again));
        // A policy choice, not a refusal.
        try testing.expectEqual(@as(u64, 0), f.store.capture_refused.load(.monotonic));
    }
    {
        var f: CapFixture = undefined;
        try f.init(.status_500, .{ .capture = .all });
        defer f.deinit();
        var b: [2048]u8 = undefined;
        _ = runWire(&f.r, reqKey("POST", "/orders", "s-1"), &b);
        const again = runWire(&f.r, reqKey("POST", "/orders", "s-1"), &b);
        try testing.expectEqual(@as(u32, 1), f.app.calls);
        try testing.expect(std.mem.startsWith(u8, again, "HTTP/1.1 500"));
        try testing.expectEqualStrings("boom 1", bodyOf(again));
    }
}

test "capture: a body streamed past the server's response buffer is collected through the tap and replayed whole" {
    var f: CapFixture = undefined;
    try f.init(.big, .{});
    defer f.deinit();
    const b1 = try testing.allocator.alloc(u8, 16 * 1024);
    defer testing.allocator.free(b1);
    const first = runWire(&f.r, reqKey("POST", "/orders", "big-1"), b1);
    try testing.expectEqualStrings("chunked", headerValue(first, "Transfer-Encoding").?);
    var want: [6000]u8 = undefined;
    for (&want, 0..) |*c, i| c.* = @intCast('a' + (i + 1) % 26);
    const b2 = try testing.allocator.alloc(u8, 16 * 1024);
    defer testing.allocator.free(b2);
    const replay = runWire(&f.r, reqKey("POST", "/orders", "big-1"), b2);
    try testing.expectEqual(@as(u32, 1), f.app.calls);
    // The replay fits no buffer either and streams too: de-chunk it.
    var rd: Reader = .fixed(replay);
    var head_buf: [1024]u8 = undefined;
    _ = try http.h1.readHead(&rd, &head_buf);
    var cbuf: [128]u8 = undefined;
    var cr: http.h1.ChunkedReader = .init(&rd, &cbuf);
    var got: [8192]u8 = undefined;
    var gw: Writer = .fixed(&got);
    _ = try cr.reader.streamRemaining(&gw);
    try testing.expectEqualSlices(u8, &want, gw.buffered());
    try testing.expectEqual(@as(u64, 0), f.store.capture_refused.load(.monotonic));
}

test "capture: a body over max_capture_bytes is refused and counted; the retry runs again" {
    var f: CapFixture = undefined;
    try f.init(.big, .{ .max_capture_bytes = 5000 });
    defer f.deinit();
    const b = try testing.allocator.alloc(u8, 16 * 1024);
    defer testing.allocator.free(b);
    _ = runWire(&f.r, reqKey("POST", "/orders", "cap-over"), b);
    _ = runWire(&f.r, reqKey("POST", "/orders", "cap-over"), b);
    try testing.expectEqual(@as(u32, 2), f.app.calls);
    try testing.expectEqual(@as(u64, 2), f.store.capture_refused.load(.monotonic));
    // Exactly at the cap is kept: the boundary is inclusive.
    var g: CapFixture = undefined;
    try g.init(.big, .{ .max_capture_bytes = 6000 });
    defer g.deinit();
    _ = runWire(&g.r, reqKey("POST", "/orders", "cap-at"), b);
    _ = runWire(&g.r, reqKey("POST", "/orders", "cap-at"), b);
    try testing.expectEqual(@as(u32, 1), g.app.calls);
}

test "capture refuses what a replay cannot reproduce: upgrade, detach, event stream, handler-coded body, trailers" {
    const modes = [_]RawMode{ .upgrade, .detach, .sse, .coded, .trailer };
    for (modes) |m| {
        errdefer std.debug.print("capture refusal mode: {t}\n", .{m});
        var f: CapFixture = undefined;
        try f.init(m, .{});
        defer f.deinit();
        var b: [2048]u8 = undefined;
        _ = runWire(&f.r, reqKey("POST", "/orders", "ref-1"), &b);
        const again = runWire(&f.r, reqKey("POST", "/orders", "ref-1"), &b);
        try testing.expectEqual(@as(u32, 2), f.app.calls);
        try testing.expect(headerValue(again, "Idempotent-Replayed") == null);
        try testing.expectEqual(@as(u64, 2), f.store.capture_refused.load(.monotonic));
    }
}

test "capture: a handler that fails records nothing (not counted) and the retry runs" {
    var f: CapFixture = undefined;
    try f.init(.fail, .{});
    defer f.deinit();
    var b: [2048]u8 = undefined;
    _ = runWire(&f.r, reqKey("POST", "/orders", "fail-1"), &b);
    _ = runWire(&f.r, reqKey("POST", "/orders", "fail-1"), &b);
    try testing.expectEqual(@as(u32, 2), f.app.calls);
    try testing.expectEqual(@as(u64, 0), f.store.capture_refused.load(.monotonic));
}

test "capture: respond wins -- what it recorded is replayed, not the bytes written after it" {
    var f: CapFixture = undefined;
    try f.init(.respond_then_more, .{});
    defer f.deinit();
    var b1: [2048]u8 = undefined;
    const first = runWire(&f.r, reqKey("POST", "/orders", "rw-1"), &b1);
    try testing.expectEqualStrings("recorded+extra", bodyOf(first));
    var b2: [2048]u8 = undefined;
    const replay = runWire(&f.r, reqKey("POST", "/orders", "rw-1"), &b2);
    try testing.expectEqual(@as(u32, 1), f.app.calls);
    try testing.expectEqualStrings("recorded", bodyOf(replay));
}

test "capture under gzip: the plain body is recorded; a replay is coded afresh or not at all, never stale" {
    var f: CapFixture = undefined;
    try f.init(.json, .{});
    defer f.deinit();
    const gz_req = "POST /orders HTTP/1.1\r\nHost: t\r\nIdempotency-Key: gz-1\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";
    var b1: [4096]u8 = undefined;
    const first = runWireGz(&f.r, gz_req, &b1, true);
    try testing.expectEqualStrings("gzip", headerValue(first, "Content-Encoding").?);
    // The same key without gzip: the recorded PLAIN body, identity, with a
    // Content-Length that is its own -- no Content-Encoding left over.
    const as: [300]u8 = @splat('q');
    const plain = "{\"v\":\"" ++ as ++ "\"}";
    var b2: [4096]u8 = undefined;
    const ident = runWireGz(&f.r, reqKey("POST", "/orders", "gz-1"), &b2, true);
    try testing.expectEqual(@as(u32, 1), f.app.calls);
    try testing.expectEqualStrings("true", headerValue(ident, "Idempotent-Replayed").?);
    try testing.expect(headerValue(ident, "Content-Encoding") == null);
    var lb: [16]u8 = undefined;
    try testing.expectEqualStrings(std.mem.print(&lb, "{d}", .{plain.len}) catch unreachable, headerValue(ident, "Content-Length").?);
    try testing.expectEqualStrings(plain, bodyOf(ident));
    // With gzip again: coded once, by the server, from the plain record.
    var b3: [4096]u8 = undefined;
    const coded = runWireGz(&f.r, gz_req, &b3, true);
    try testing.expectEqual(@as(u32, 1), f.app.calls);
    try testing.expectEqualStrings("gzip", headerValue(coded, "Content-Encoding").?);
    try testing.expect(headerValue(coded, "Content-Length") == null);
    var rd: Reader = .fixed(coded);
    var head_buf: [1024]u8 = undefined;
    _ = try http.h1.readHead(&rd, &head_buf);
    var cbuf: [128]u8 = undefined;
    var cr: http.h1.ChunkedReader = .init(&rd, &cbuf);
    var zbuf: [2048]u8 = undefined;
    var zw: Writer = .fixed(&zbuf);
    _ = try cr.reader.streamRemaining(&zw);
    var zin: Reader = .fixed(zw.buffered());
    var dc: std.compress.flate.Decompress = .init(&zin, .gzip, &.{});
    var pbuf: [2048]u8 = undefined;
    var pw: Writer = .fixed(&pbuf);
    _ = try dc.reader.streamRemaining(&pw);
    try testing.expectEqualStrings(plain, pw.buffered());
}

test "capture under gzip, streamed: the tap records the plain bytes, not the coded ones" {
    var f: CapFixture = undefined;
    try f.init(.big, .{});
    defer f.deinit();
    const b = try testing.allocator.alloc(u8, 16 * 1024);
    defer testing.allocator.free(b);
    const gz_req = "POST /orders HTTP/1.1\r\nHost: t\r\nIdempotency-Key: gzs-1\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";
    const first = runWireGz(&f.r, gz_req, b, true);
    try testing.expectEqualStrings("gzip", headerValue(first, "Content-Encoding").?);
    const replay = runWireGz(&f.r, reqKey("POST", "/orders", "gzs-1"), b, true);
    try testing.expectEqual(@as(u32, 1), f.app.calls);
    try testing.expect(headerValue(replay, "Content-Encoding") == null);
    var want: [6000]u8 = undefined;
    for (&want, 0..) |*c, i| c.* = @intCast('a' + (i + 1) % 26);
    var rd: Reader = .fixed(replay);
    var head_buf: [1024]u8 = undefined;
    _ = try http.h1.readHead(&rd, &head_buf);
    var cbuf: [128]u8 = undefined;
    var cr: http.h1.ChunkedReader = .init(&rd, &cbuf);
    var got: [8192]u8 = undefined;
    var gw: Writer = .fixed(&got);
    _ = try cr.reader.streamRemaining(&gw);
    try testing.expectEqualSlices(u8, &want, gw.buffered());
}

// ── model-fuzz: seeded random request sequences vs. a naive reference model ──
//
// The model is a restatement of the documented semantics (module doc + SPEC
// "Design & invariants"): a linear list of recorded responses, an explicit
// decision order, no use of the module's cache, store or key builders.
//
//   1. a method outside POST/PUT/PATCH, or no key header: pass through;
//   2. a key that is empty, over `max_key_len` (255) or has a byte outside
//      0x21..0x7e: 400, handler not run;
//   3. principal configured but the request names none: pass through;
//   4. body over `max_body_bytes`: 413, handler not run;
//   5. a live record under (caller, key[, method, path]) whose body differs: 422;
//      one whose body matches: replay (status / content type / body, plus
//      `Idempotent-Replayed: true`), handler not run;
//   6. otherwise run the handler and record the answer for `ttl_ns` (a record
//      older than `ttl_ns` is gone) when it used `respond`, or -- `/raw`,
//      which writes `ctx.res` itself -- when transparent capture takes it
//      (`.all`: any status; `.success`: 2xx; `.off`: never).
//
// Sequential requests only: the 409 in-flight path is covered by the
// reentrant test above.

const fz_ttl: i64 = 1000;
const fz_cap: usize = 32;

fn fzPrincipal(req: *const http.Server.Request) ?[]const u8 {
    return req.header("X-Caller");
}

/// Handler: counts itself, echoes the request body it can read, and answers
/// with a status / content type derived from the call count. `/raw` writes
/// `ctx.res` directly (recorded only by transparent capture); every other
/// path uses `respond`.
fn fzHandler(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    const n = app.calls;
    const seen = try ctx.req.reader().allocRemaining(testing.allocator, .limited(4096));
    defer testing.allocator.free(seen);
    var buf: [128]u8 = undefined;
    const body = std.mem.print(&buf, "n{d}:{s}", .{ n, seen }) catch unreachable;
    const status: u16 = 200 + @as(u16, @intCast(n % 3));
    const ct: ?[]const u8 = if (n % 3 == 0) null else if (n % 2 == 0) "text/plain" else "application/json";
    if (std.mem.eql(u8, ctx.req.path, "/raw")) {
        // A 5xx now and then, for `Capture.success` to leave out.
        ctx.res.setStatus(if (n % 5 == 0) 500 else status);
        if (ct) |c| try ctx.res.setHeader("Content-Type", c);
        try ctx.res.writeAll(body);
    } else {
        try app.store.respond(ctx, status, ct, body);
    }
}

const FzRec = struct {
    caller: []const u8, // "*" when no principal is configured
    method: usize,
    path: usize,
    key: []u8,
    req_body: []u8,
    status: u16,
    ct: ?[]const u8,
    resp_body: []u8,
    at: i64,
};

const FzOp = struct {
    method: usize,
    path: usize,
    key: ?[]const u8,
    body: []const u8,
    caller: ?[]const u8,
};

fn fzKeyValid(k: []const u8) bool {
    return fzKey(k) != null;
}

/// The model of `parseKey` over the fuzz pool (no escapes in it): a quoted
/// key is its inside (spaces allowed, nothing after the closing quote), a
/// bare one is printable non-space ASCII; 1..255 bytes either way.
fn fzKey(k: []const u8) ?[]const u8 {
    var inner = k;
    var space_ok = false;
    if (k.len != 0 and k[0] == '"') {
        if (k.len < 2 or k[k.len - 1] != '"') return null;
        inner = k[1 .. k.len - 1];
        space_ok = true;
        if (std.mem.findAny(u8, inner, "\\\"") != null) return null;
    }
    if (inner.len == 0 or inner.len > 255) return null;
    for (inner) |c| {
        if (c > 0x7e or c < 0x20 or (c == ' ' and !space_ok)) return null;
    }
    return inner;
}

test "model-fuzz: request sequences through the middleware vs. a linear-scan model" {
    try fuzzSequences(false);
}

test "model-fuzz: the same sequences over KvBackend (kv on SimStorage) vs. the same model" {
    try fuzzSequences(true);
}

/// The sequence model-fuzz, over the in-process `ramcache` store or, with
/// `use_kv`, over `KvBackend` (records in `kv` on `SimStorage`, expiry on
/// kv's clock driven by the same manual clock read as milliseconds).
fn fuzzSequences(comptime use_kv: bool) !void {
    const seed: u64 = 0x6964656d706f3031;
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    const method_names = [_][]const u8{ "POST", "PUT", "PATCH", "GET", "DELETE" };
    const method_enums = [_]http.Method{ .post, .put, .patch, .get, .delete };
    const paths = [_][]const u8{ "/orders", "/refunds", "/raw" };
    const long255: [255]u8 = @splat('k');
    const long256: [256]u8 = @splat('k');
    // `"k1"` is k1 in the draft's sf-string spelling: one key, not two.
    const keys = [_][]const u8{ "k1", "k2", "k3", "a.b_c-d~!", &long255, "\"k1\"", "\"a b\"" };
    const bad_keys = [_][]const u8{ "bad key", &long256, "", "\"k1\";p=1", "\"\"", "\"open" };
    const x32: [fz_cap]u8 = @splat('x');
    const y32: [fz_cap]u8 = @splat('y');
    const x33: [fz_cap + 1]u8 = @splat('x');
    const bodies = [_][]const u8{ "", "A", "B", &x32, &y32, &x33 };
    const callers = [_][]const u8{ "alice", "bob" };

    var reach = struct {
        bypass_method: usize = 0,
        bypass_nokey: usize = 0,
        bypass_nocaller: usize = 0,
        bad_key: usize = 0,
        key255_ok: usize = 0,
        too_big: usize = 0,
        too_big_at_cap_ok: usize = 0,
        mismatch_422: usize = 0,
        replay: usize = 0,
        replay_cross_endpoint: usize = 0,
        expired_rerun: usize = 0,
        raw_rerun: usize = 0,
        raw_captured: usize = 0,
        raw_5xx_not_captured: usize = 0,
        target_isolated_miss: usize = 0,
        caller_isolated_miss: usize = 0,
        recorded: usize = 0,
        ttl_edge: usize = 0,
    }{};

    var seq: usize = 0;
    while (seq < 80) : (seq += 1) {
        const key_only = rnd.boolean();
        const use_principal = rnd.boolean();
        const capture: Capture = switch (rnd.uintLessThan(u8, 3)) {
            0 => .off,
            1 => .success,
            else => .all,
        };
        var clk = ManualClock{ .now_ns = 5000 };
        var cache = newCache();
        defer cache.deinit();
        var sim = kv.SimStorage.init(testing.allocator);
        defer sim.deinit();
        var db: kv.Db = undefined;
        var kb: KvBackend = undefined;
        if (use_kv) {
            db = try kv.Db.open(testing.allocator, sim.storage(), "idem.kv", .{ .clock = .{ .ctx = &clk, .nowFn = ManualClock.read } });
            kb = .{ .db = &db, .gpa = testing.allocator };
        }
        defer if (use_kv) {
            kb.deinit();
            db.close();
        };
        // kv counts its clock in ms: the same ticks, a ttl of `fz_ttl` ms.
        var store = if (use_kv)
            Store{ .backend = kb.backend(), .clock = clk.clock(), .ttl_ns = fz_ttl * std.time.ns_per_ms }
        else
            Store{ .cache = &cache, .clock = clk.clock(), .ttl_ns = fz_ttl };
        defer store.deinit();
        var app = App{ .store = &store };
        var idem = Idempotency{ .store = &store, .options = .{
            .scope = if (key_only) .key_only else .target,
            .max_body_bytes = fz_cap,
            .principal = if (use_principal) fzPrincipal else null,
            .capture = capture,
        } };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        r.state = &app;
        try r.use(idem.middleware());
        for (method_enums) |m| for (paths) |p| try r.add(m, p, fzHandler);

        var recs: std.ArrayList(FzRec) = .empty;
        defer {
            for (recs.items) |rec| {
                testing.allocator.free(rec.key);
                testing.allocator.free(rec.req_body);
                testing.allocator.free(rec.resp_body);
            }
            recs.deinit(testing.allocator);
        }
        var model_calls: u32 = 0;
        var prev: ?FzOp = null;

        var step: usize = 0;
        while (step < 80) : (step += 1) {
            errdefer std.debug.print("idempotency model-fuzz mismatch: seed=0x{x} seq={d} step={d} key_only={} principal={} capture={t}\n", .{ seed, seq, step, key_only, use_principal, capture });

            // Time moves first. A record whose age would equal ttl exactly is
            // nudged by 1 ns: that single instant is the cache's, not ours.
            const deltas = [_]i64{ 0, 0, 1, 10, 499, 501, 999, 1001, 2500 };
            clk.now_ns += deltas[rnd.uintLessThan(usize, deltas.len)];
            // Repeated until no record sits on the edge: one nudge can put
            // another record (recorded 1 ns later) exactly on it.
            nudge: while (true) {
                for (recs.items) |rec| if (clk.now_ns - rec.at == fz_ttl) {
                    clk.now_ns += 1;
                    continue :nudge;
                };
                break;
            }
            for (recs.items) |rec| {
                const age = clk.now_ns - rec.at;
                if (age == fz_ttl - 1 or age == fz_ttl + 1) reach.ttl_edge += 1;
            }

            // The operation: half the time a verbatim retry of the previous one.
            var op: FzOp = undefined;
            if (prev != null and rnd.boolean()) {
                op = prev.?;
            } else {
                op = .{
                    .method = switch (rnd.uintLessThan(u8, 8)) {
                        0...3 => 0,
                        4 => 1,
                        5 => 2,
                        6 => 3,
                        else => 4,
                    },
                    .path = rnd.uintLessThan(usize, paths.len),
                    .key = switch (rnd.uintLessThan(u8, 8)) {
                        0 => null,
                        1 => bad_keys[rnd.uintLessThan(usize, bad_keys.len)],
                        else => keys[rnd.uintLessThan(usize, keys.len)],
                    },
                    .body = bodies[rnd.uintLessThan(usize, bodies.len)],
                    .caller = if (rnd.uintLessThan(u8, 5) == 0) null else callers[rnd.uintLessThan(usize, callers.len)],
                };
            }
            prev = op;

            // Wire.
            var req_buf: [2048]u8 = undefined;
            var w: std.Io.Writer = .fixed(&req_buf);
            try w.print("{s} {s} HTTP/1.1\r\nHost: t\r\n", .{ method_names[op.method], paths[op.path] });
            if (op.key) |k| try w.print("Idempotency-Key: {s}\r\n", .{k});
            if (op.caller) |c| try w.print("X-Caller: {s}\r\n", .{c});
            try w.print("Content-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ op.body.len, op.body });
            var out: [2048]u8 = undefined;
            const got = runWire(&r, w.buffered(), &out);
            const status = try std.fmt.parseInt(u16, got[9..12], 10);
            const body = bodyOf(got);
            const replayed = headerValue(got, "Idempotent-Replayed");

            // Model.
            const guarded = op.method <= 2;
            const who: []const u8 = if (use_principal) (op.caller orelse "") else "*";
            enum_blk: {
                // Outcome classes that never reach the handler.
                if (guarded and op.key != null and !fzKeyValid(op.key.?)) {
                    reach.bad_key += 1;
                    try testing.expectEqual(@as(u16, 400), status);
                    try testing.expect(replayed == null);
                    break :enum_blk;
                }
                const bypass = !guarded or op.key == null or (use_principal and op.caller == null);
                if (!bypass and op.body.len > fz_cap) {
                    reach.too_big += 1;
                    try testing.expectEqual(@as(u16, 413), status);
                    break :enum_blk;
                }
                if (!bypass) {
                    if (op.body.len == fz_cap) reach.too_big_at_cap_ok += 1;
                    const mkey = fzKey(op.key.?).?;
                    if (mkey.len == 255) reach.key255_ok += 1;
                    // Find a live record that matches this request's scope.
                    var found: ?usize = null;
                    var i: usize = 0;
                    while (i < recs.items.len) : (i += 1) {
                        const rec = recs.items[i];
                        if (!std.mem.eql(u8, rec.caller, who)) continue;
                        if (!std.mem.eql(u8, rec.key, mkey)) continue;
                        if (!key_only and (rec.method != op.method or rec.path != op.path)) continue;
                        found = i;
                        break;
                    }
                    if (found) |fi| {
                        if (clk.now_ns - recs.items[fi].at > fz_ttl) {
                            reach.expired_rerun += 1;
                            const dead = recs.orderedRemove(fi);
                            testing.allocator.free(dead.key);
                            testing.allocator.free(dead.req_body);
                            testing.allocator.free(dead.resp_body);
                            found = null;
                        }
                    }
                    if (found) |fi| {
                        const rec = recs.items[fi];
                        if (!std.mem.eql(u8, rec.req_body, op.body)) {
                            reach.mismatch_422 += 1;
                            try testing.expectEqual(@as(u16, 422), status);
                            try testing.expect(replayed == null);
                        } else {
                            reach.replay += 1;
                            if (rec.method != op.method or rec.path != op.path) reach.replay_cross_endpoint += 1;
                            try testing.expectEqual(rec.status, status);
                            try testing.expectEqualStrings(rec.resp_body, body);
                            try testing.expectEqualStrings("true", replayed.?);
                            if (rec.ct) |ct| try testing.expectEqualStrings(ct, headerValue(got, "Content-Type").?);
                        }
                        break :enum_blk;
                    }
                    // Miss: classify what kept an existing record from matching.
                    for (recs.items) |rec| {
                        if (!std.mem.eql(u8, rec.key, mkey)) continue;
                        if (std.mem.eql(u8, rec.caller, who) and !key_only and (rec.method != op.method or rec.path != op.path))
                            reach.target_isolated_miss += 1;
                        if (!std.mem.eql(u8, rec.caller, who) and (key_only or (rec.method == op.method and rec.path == op.path)))
                            reach.caller_isolated_miss += 1;
                    }
                    if (op.path == 2 and capture == .off) reach.raw_rerun += 1;
                } else if (!guarded) {
                    reach.bypass_method += 1;
                } else if (op.key == null) {
                    reach.bypass_nokey += 1;
                } else reach.bypass_nocaller += 1;

                // The handler runs: model its answer, and record it if cooperative.
                model_calls += 1;
                const n = model_calls;
                var want_buf: [128]u8 = undefined;
                const want_body = std.mem.print(&want_buf, "n{d}:{s}", .{ n, op.body }) catch unreachable;
                const raw = op.path == 2;
                const want_status: u16 = if (raw and n % 5 == 0) 500 else 200 + @as(u16, @intCast(n % 3));
                try testing.expectEqual(want_status, status);
                try testing.expectEqualStrings(want_body, body);
                try testing.expect(replayed == null);
                const captured = switch (capture) {
                    .off => false,
                    .success => want_status < 300,
                    .all => true,
                };
                if (!bypass and raw) {
                    if (captured) reach.raw_captured += 1;
                    if (capture == .success and want_status == 500) reach.raw_5xx_not_captured += 1;
                }
                if (!bypass and (!raw or captured)) {
                    reach.recorded += 1;
                    const ct: ?[]const u8 = if (n % 3 == 0) null else if (n % 2 == 0) "text/plain" else "application/json";
                    try recs.append(testing.allocator, .{
                        .caller = who,
                        .method = op.method,
                        .path = op.path,
                        .key = try testing.allocator.dupe(u8, fzKey(op.key.?).?),
                        .req_body = try testing.allocator.dupe(u8, op.body),
                        .status = want_status,
                        .ct = ct,
                        .resp_body = try testing.allocator.dupe(u8, want_body),
                        .at = clk.now_ns,
                    });
                }
            }
            // The handler ran exactly as often as the model says.
            try testing.expectEqual(model_calls, app.calls);
        }
    }

    inline for (@typeInfo(@TypeOf(reach)).@"struct".field_names) |f_name| {
        if (@field(reach, f_name) == 0) {
            std.debug.print("idempotency model-fuzz: reach class never hit: {s}\n", .{f_name});
            return error.TestUnexpectedResult;
        }
    }
}

test "model-fuzz: validKey, scopeKey, principalTag and decode vs. models on random inputs" {
    const seed: u64 = 0x6964656d706f3032;
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    var valid_n: usize = 0;
    var invalid_n: usize = 0;
    var overflow_n: usize = 0;
    var fit_n: usize = 0;
    var dec_ok: usize = 0;
    var dec_null: usize = 0;

    var case: usize = 0;
    while (case < 3000) : (case += 1) {
        errdefer std.debug.print("idempotency model-fuzz(pure) mismatch: seed=0x{x} case={d}\n", .{ seed, case });
        // validKey: random bytes, lengths around the limit.
        var kb: [300]u8 = undefined;
        const klen: usize = switch (rnd.uintLessThan(u8, 5)) {
            0 => 0,
            1 => 255,
            2 => 256,
            else => rnd.uintLessThan(usize, 300),
        };
        const clean = rnd.boolean();
        for (kb[0..klen]) |*c| c.* = if (clean) 0x21 + rnd.uintLessThan(u8, 0x7e - 0x21 + 1) else rnd.int(u8);
        const max_len: usize = if (rnd.uintLessThan(u8, 4) == 0) rnd.uintLessThan(usize, 300) else 255;
        const key = kb[0..klen];
        var want = klen >= 1 and klen <= max_len;
        if (want) for (key) |c| {
            if (!(c >= 0x21 and c <= 0x7e)) want = false;
        };
        try testing.expectEqual(want, validKey(key, max_len));
        if (want) valid_n += 1 else invalid_n += 1;

        // scopeKey: compare with a hand-built string; null iff it overflows.
        var path_buf: [80]u8 = undefined;
        const plen = 1 + rnd.uintLessThan(usize, path_buf.len - 1);
        path_buf[0] = '/';
        for (path_buf[1..plen]) |*c| c.* = 'a' + rnd.uintLessThan(u8, 26);
        const path = path_buf[0..plen];
        const mi = rnd.uintLessThan(usize, 5);
        const methods = [_]http.Method{ .post, .put, .patch, .get, .delete };
        const names = [_][]const u8{ "POST", "PUT", "PATCH", "GET", "DELETE" };
        const sc: Scope = if (rnd.boolean()) .target else .key_only;
        const who: ?[]const u8 = if (rnd.boolean()) "0123456789abcdef0123456789abcdef" else null;
        var want_buf: [512]u8 = undefined;
        var wl: usize = 0;
        const wstr = if (who) |s| s else "*";
        const piece = if (sc == .target)
            std.mem.print(&want_buf, "{s} {s} {s} {s}", .{ wstr, names[mi], path, key[0..@min(klen, 100)] }) catch unreachable
        else
            std.mem.print(&want_buf, "{s} {s}", .{ wstr, key[0..@min(klen, 100)] }) catch unreachable;
        wl = piece.len;
        // Output buffer sized around the wanted length so both outcomes occur.
        var out_buf: [512]u8 = undefined;
        const room = if (rnd.boolean()) wl else wl -| (1 + rnd.uintLessThan(usize, 3));
        const got = scopeKey(out_buf[0..room], sc, methods[mi].token(), path, who, key[0..@min(klen, 100)]);
        if (room >= wl) {
            fit_n += 1;
            try testing.expectEqualStrings(want_buf[0..wl], got.?);
        } else {
            overflow_n += 1;
            try testing.expect(got == null);
        }

        // principalTag: first 16 bytes of SHA-256 in lowercase hex.
        var pbuf: [64]u8 = undefined;
        const pl = rnd.uintLessThan(usize, pbuf.len);
        rnd.bytes(pbuf[0..pl]);
        var tag_out: [principal_hex_len]u8 = undefined;
        const tag = principalTag(pbuf[0..pl], &tag_out);
        var dg: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(pbuf[0..pl], &dg, .{});
        const hex = "0123456789abcdef";
        var want_tag: [32]u8 = undefined;
        for (dg[0..16], 0..) |b, i| {
            want_tag[2 * i] = hex[b >> 4];
            want_tag[2 * i + 1] = hex[b & 15];
        }
        try testing.expectEqualStrings(&want_tag, tag);

        // decode: build a blob from fields (digest | status BE | ctlen BE | ct |
        // [block_len BE32 | (nl BE16, vl BE16, name, value)*] | body), the
        // header block only with status bit 15, then maybe truncate or
        // corrupt a length field.
        var blob: [400]u8 = undefined;
        rnd.bytes(blob[0..32]);
        const status: u16 = rnd.int(u15);
        const with_headers = rnd.boolean();
        const flagged = if (with_headers) status | 0x8000 else status;
        blob[32] = @intCast(flagged >> 8);
        blob[33] = @intCast(flagged & 0xff);
        const ctl = rnd.uintLessThan(usize, 20);
        blob[34] = @intCast(ctl >> 8);
        blob[35] = @intCast(ctl & 0xff);
        rnd.bytes(blob[36..][0..ctl]);
        var at: usize = 36 + ctl;
        var block_end: usize = at; // where the body starts
        var block_len: usize = 0;
        var n_headers: usize = 0;
        var bounds: [5]usize = undefined; // block offsets where an entry ends
        if (with_headers) {
            n_headers = 1 + rnd.uintLessThan(usize, 4);
            var q = at + 4;
            for (0..n_headers) |k| {
                const nl = rnd.uintLessThan(usize, 12);
                const vl = rnd.uintLessThan(usize, 20);
                std.mem.writeInt(u16, blob[q..][0..2], @intCast(nl), .big);
                std.mem.writeInt(u16, blob[q + 2 ..][0..2], @intCast(vl), .big);
                rnd.bytes(blob[q + 4 ..][0 .. nl + vl]);
                q += 4 + nl + vl;
                bounds[k] = q - at - 4;
            }
            block_len = q - at - 4;
            std.mem.writeInt(u32, blob[at..][0..4], @intCast(block_len), .big);
            block_end = q;
        }
        const bodyl = rnd.uintLessThan(usize, 40);
        rnd.bytes(blob[block_end..][0..bodyl]);
        at = block_end + bodyl;
        var bl = at;
        var block_lie = false;
        switch (rnd.uintLessThan(u8, 5)) {
            0 => bl = rnd.uintLessThan(usize, bl + 1), // truncate anywhere
            1 => { // claim a longer content type than present
                const lie = ctl + (block_end - 36 - ctl) + bodyl + 1 + rnd.uintLessThan(usize, 5);
                blob[34] = @intCast(lie >> 8);
                blob[35] = @intCast(lie & 0xff);
            },
            2 => if (with_headers) { // a block length that splits an entry
                const off = 36 + ctl;
                const short = rnd.uintLessThan(usize, block_len);
                std.mem.writeInt(u32, blob[off..][0..4], @intCast(short), .big);
                // On an entry boundary the shorter block is a valid record
                // with fewer headers, the rest read as body.
                block_lie = true;
                for (bounds[0..n_headers], 0..) |e, k| if (short != 0 and e == short) {
                    block_lie = false;
                    n_headers = k + 1;
                    block_end = 36 + ctl + 4 + short;
                };
            },
            else => {},
        }
        const claimed = (@as(usize, blob[34]) << 8) | blob[35];
        const decoded = decode(blob[0..bl]);
        // The model: a header block whose length is shorter than its entries
        // never parses (the lie cuts the last entry, or claims 0).
        const ok = bl >= 36 and 36 + claimed <= bl and claimed == ctl and
            (!with_headers or (!block_lie and bl >= block_end));
        const ok_v1 = !with_headers and bl >= 36 and 36 + claimed <= bl;
        if (ok or ok_v1) {
            dec_ok += 1;
            const d = decoded.?;
            try testing.expectEqualSlices(u8, blob[0..32], &d.digest);
            try testing.expectEqual(status, d.status);
            try testing.expectEqualSlices(u8, blob[36 .. 36 + claimed], d.content_type);
            if (with_headers) {
                try testing.expectEqualSlices(u8, blob[36 + ctl + 4 .. block_end], d.headers);
                var it = d.headerIterator();
                var seen: usize = 0;
                while (it.next()) |_| seen += 1;
                try testing.expectEqual(n_headers, seen);
                try testing.expectEqualSlices(u8, blob[block_end..bl], d.body);
            } else {
                try testing.expectEqualSlices(u8, blob[36 + claimed .. bl], d.body);
            }
        } else if (with_headers and claimed != ctl) {
            // A lied content-type length moves where the block is read
            // from: whatever decode answers, it must stay inside the blob.
            if (decoded) |d| try testing.expect(d.body.len <= bl);
        } else {
            dec_null += 1;
            try testing.expect(decoded == null);
        }
    }
    try testing.expect(valid_n > 0 and invalid_n > 0 and overflow_n > 0 and fit_n > 0 and dec_ok > 0 and dec_null > 0);
}

// ── delta audit 2026-11-06 (G): transparent-capture boundaries ──────────────

/// What `hShape` answers: status, `len` body bytes written one at a time,
/// an optional declared `Content-Length`.
const Shape = struct {
    status: u16 = 200,
    len: usize = 11,
    declared: ?[]const u8 = null,
};
var shape: Shape = .{};

fn hShape(ctx: *router.Ctx) anyerror!void {
    const app: *RawApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    ctx.res.setStatus(shape.status);
    try ctx.res.setHeader("Content-Type", "text/plain");
    if (shape.declared) |d| try ctx.res.setHeader("Content-Length", d);
    var i: usize = 0;
    while (i < shape.len) : (i += 1) try ctx.res.writer().writeByte(@intCast('a' + (i + app.calls) % 26));
}

/// An allocator that refuses every allocation of `fail_at_least` bytes or
/// more and never grows in place (growth = alloc, copy, free).
const WatchAlloc = struct {
    child: std.mem.Allocator = testing.allocator,
    fail_at_least: usize = std.math.maxInt(usize),

    fn allocator(w: *WatchAlloc) std.mem.Allocator {
        return .{ .ptr = w, .vtable = &vtable };
    }
    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const w: *WatchAlloc = @ptrCast(@alignCast(ctx));
        if (len >= w.fail_at_least) return null;
        return w.child.rawAlloc(len, a, ra);
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, mem: []u8, a: std.mem.Alignment, ra: usize) void {
        const w: *WatchAlloc = @ptrCast(@alignCast(ctx));
        w.child.rawFree(mem, a, ra);
    }
};

/// An outer middleware with a `BodyTap` of its own, placed before the
/// idempotency guard: it must keep seeing the streamed bytes, get its tap
/// back, and its pre-chain header must not be replayed over a fresh one.
const OuterTap = struct {
    seen: usize = 0,
    tail: usize = 0,
    restored: bool = false,
    req_n: u32 = 0,
    fn observe(ctx: *anyopaque, bytes: []const u8) void {
        const o: *OuterTap = @ptrCast(@alignCast(ctx));
        o.seen += bytes.len;
    }
    fn run(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const o: *OuterTap = @ptrCast(@alignCast(state.?));
        o.req_n += 1;
        var nb: [16]u8 = undefined;
        try ctx.res.setHeader("X-Req", std.mem.print(&nb, "{d}", .{o.req_n}) catch unreachable);
        const tap: http.Server.ResponseWriter.BodyTap = .{ .ctx = o, .observe = observe };
        const prev = ctx.res.body_tap;
        ctx.res.body_tap = &tap;
        defer ctx.res.body_tap = prev;
        try next.run(ctx);
        o.restored = if (ctx.res.body_tap) |t| t == &tap else false;
        o.tail = ctx.res.bufferedBody().len;
    }
};

const ShapeFixture = struct {
    cache: ramcache.Cache,
    store: Store,
    app: RawApp,
    idem: Idempotency,
    r: router.Router,

    fn init(f: *ShapeFixture, opts: Options, gpa: std.mem.Allocator, outer: ?router.Middleware) !void {
        f.cache = ramcache.Cache.init(gpa, .{ .max_bytes = 1 << 20, .max_entries = 16 });
        f.store = .{ .cache = &f.cache };
        f.app = .{};
        f.idem = .{ .store = &f.store, .options = opts };
        f.r = router.Router.init(testing.allocator);
        f.r.state = &f.app;
        if (outer) |o| try f.r.use(o);
        try f.r.use(f.idem.middleware());
        try f.r.post("/s", hShape);
        try f.r.head("/s", hShape);
    }

    fn deinit(f: *ShapeFixture) void {
        f.r.deinit();
        f.store.deinit();
        f.cache.deinit();
    }

    /// The same keyed request twice; the handler's call count after both.
    fn twice(f: *ShapeFixture, comptime method: []const u8, comptime key: []const u8) !u32 {
        const b = try testing.allocator.alloc(u8, 32 * 1024);
        defer testing.allocator.free(b);
        _ = runWire(&f.r, reqKey(method, "/s", key), b);
        _ = runWire(&f.r, reqKey(method, "/s", key), b);
        return f.app.calls;
    }

    fn refused(f: *ShapeFixture) u64 {
        return f.store.capture_refused.load(.monotonic);
    }
};

test "capture limits: a streamed chunk that fills the cap exactly is kept; overflow in the tap or the tail refuses, never truncates" {
    defer shape = .{};
    const cases = [_]struct { len: usize, cap: usize, calls: u32 }{
        .{ .len = 4097, .cap = 4097, .calls = 1 }, // buffer + the byte that drained it, exactly at the cap
        .{ .len = 6000, .cap = 1000, .calls = 2 }, // the first drained chunk alone is over the cap
        .{ .len = 4100, .cap = 1000, .calls = 2 }, // over in the tap, a small tail must not be recorded alone
        .{ .len = 11, .cap = 10, .calls = 2 }, // never streamed: the buffered body alone is over
        .{ .len = 11, .cap = 11, .calls = 1 },
    };
    for (cases) |c| {
        errdefer std.debug.print("capture limit case len={d} cap={d}\n", .{ c.len, c.cap });
        shape = .{ .len = c.len };
        var f: ShapeFixture = undefined;
        try f.init(.{ .max_capture_bytes = c.cap }, testing.allocator, null);
        defer f.deinit();
        try testing.expectEqual(c.calls, try f.twice("POST", "lim"));
        try testing.expectEqual(@as(u64, if (c.calls == 2) 2 else 0), f.refused());
    }
}

test "capture .success: 2xx at both edges -- 299 recorded, 199 and 300 not (and not counted)" {
    defer shape = .{};
    for ([_]u16{ 299, 199, 300 }) |st| {
        errdefer std.debug.print("status {d}\n", .{st});
        shape = .{ .status = st, .len = 0 };
        var f: ShapeFixture = undefined;
        try f.init(.{ .capture = .success }, testing.allocator, null);
        defer f.deinit();
        try testing.expectEqual(@as(u32, if (st == 299) 1 else 2), try f.twice("POST", "succ"));
        try testing.expectEqual(@as(u64, 0), f.refused());
    }
}

test "capture: a 204/304 declaring a length is recorded; a 200 whose body misses its declared length is refused" {
    defer shape = .{};
    const cases = [_]struct { status: u16, declared: []const u8, len: usize, calls: u32 }{
        .{ .status = 304, .declared = "10", .len = 0, .calls = 1 },
        .{ .status = 204, .declared = "10", .len = 0, .calls = 1 },
        .{ .status = 200, .declared = "100", .len = 11, .calls = 2 },
        .{ .status = 200, .declared = "11", .len = 11, .calls = 1 },
    };
    for (cases) |c| {
        errdefer std.debug.print("status {d} declared {s} len {d}\n", .{ c.status, c.declared, c.len });
        shape = .{ .status = c.status, .declared = c.declared, .len = c.len };
        var f: ShapeFixture = undefined;
        try f.init(.{}, testing.allocator, null);
        defer f.deinit();
        try testing.expectEqual(c.calls, try f.twice("POST", "bodiless"));
        try testing.expectEqual(@as(u64, if (c.calls == 2) 2 else 0), f.refused());
    }
}

test "capture refuses a HEAD response when HEAD is guarded" {
    var f: ShapeFixture = undefined;
    try f.init(.{ .methods = &.{ .post, .head } }, testing.allocator, null);
    defer f.deinit();
    try testing.expectEqual(@as(u32, 2), try f.twice("HEAD", "hd"));
    try testing.expectEqual(@as(u64, 2), f.refused());
}

test "capture chains the tap it displaced and restores it; a pre-guard header is not replayed over a fresh one" {
    defer shape = .{};
    shape = .{ .len = 6000 };
    var outer: OuterTap = .{};
    var f: ShapeFixture = undefined;
    try f.init(.{}, testing.allocator, .{ .state = &outer, .run = OuterTap.run });
    defer f.deinit();
    const b = try testing.allocator.alloc(u8, 32 * 1024);
    defer testing.allocator.free(b);
    _ = runWire(&f.r, reqKey("POST", "/s", "chain"), b);
    try testing.expect(outer.restored);
    try testing.expect(outer.seen > 0);
    try testing.expectEqual(@as(usize, 6000), outer.seen + outer.tail);
    const replay = runWire(&f.r, reqKey("POST", "/s", "chain"), b);
    try testing.expectEqual(@as(u32, 1), f.app.calls);
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expectEqualStrings("2", headerValue(replay, "X-Req").?);
}

test "capture: an allocation failure while collecting refuses the record instead of keeping the tail alone" {
    defer shape = .{};
    shape = .{ .len = 6000 };
    var wa: WatchAlloc = .{};
    var f: ShapeFixture = undefined;
    try f.init(.{}, wa.allocator(), null);
    defer f.deinit();
    wa.fail_at_least = 4096; // the collection buffer's first growth fails
    try testing.expectEqual(@as(u32, 2), try f.twice("POST", "oom"));
    try testing.expectEqual(@as(u64, 2), f.refused());
}

/// A middleware INSIDE the guard: after the handler it sets a cookie
/// (`cookie`) and/or installs a tap of its own that neither chains nor
/// restores the one it displaced (`rogue_tap`).
const InnerMw = struct {
    cookie: bool = false,
    rogue_tap: bool = false,
    fn observe(_: *anyopaque, _: []const u8) void {}
    fn run(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const self: *InnerMw = @ptrCast(@alignCast(state.?));
        const tap: http.Server.ResponseWriter.BodyTap = .{ .ctx = self, .observe = observe };
        if (self.rogue_tap) ctx.res.body_tap = &tap;
        defer if (self.rogue_tap) {
            ctx.res.body_tap = null;
        };
        try next.run(ctx);
        if (self.cookie) try ctx.res.addSetCookie("sid=SESSION-OF-FIRST-CALLER; HttpOnly");
    }
};

fn innerFixture(f: *ShapeFixture, inner: *InnerMw) !void {
    f.cache = ramcache.Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 16 });
    f.store = .{ .cache = &f.cache };
    f.app = .{};
    f.idem = .{ .store = &f.store, .options = .{} };
    f.r = router.Router.init(testing.allocator);
    f.r.state = &f.app;
    try f.r.use(f.idem.middleware());
    try f.r.use(.{ .state = inner, .run = InnerMw.run });
    try f.r.post("/s", hShape);
}

test "capture never replays a Set-Cookie: it is the first caller's (audit G finding 3)" {
    defer shape = .{};
    var inner: InnerMw = .{ .cookie = true };
    var f: ShapeFixture = undefined;
    try innerFixture(&f, &inner);
    defer f.deinit();
    const b = try testing.allocator.alloc(u8, 32 * 1024);
    defer testing.allocator.free(b);
    const first = runWire(&f.r, reqKey("POST", "/s", "ck"), b);
    try testing.expect(std.mem.find(u8, first, "SESSION-OF-FIRST-CALLER") != null);
    inner.cookie = false; // the second caller's own chain sets nothing
    const replay = runWire(&f.r, reqKey("POST", "/s", "ck"), b);
    try testing.expectEqual(@as(u32, 1), f.app.calls);
    try testing.expectEqualStrings("true", headerValue(replay, "Idempotent-Replayed").?);
    try testing.expect(std.mem.find(u8, replay, "SESSION-OF-FIRST-CALLER") == null);
}

test "capture refuses when an inner tap displaced its own without chaining or restoring (audit G finding 4)" {
    defer shape = .{};
    shape = .{ .len = 6000 };
    var inner: InnerMw = .{ .rogue_tap = true };
    var f: ShapeFixture = undefined;
    try innerFixture(&f, &inner);
    defer f.deinit();
    try testing.expectEqual(@as(u32, 2), try f.twice("POST", "rogue"));
    try testing.expectEqual(@as(u64, 2), f.refused());
}

// ── whole-module mutation run 2026-11-07 (A1): tests for the survivors ──────

/// An allocator that counts allocations and notes every freed block that still
/// holds `marker` (a block freed unwiped).
const WipeAlloc = struct {
    child: std.mem.Allocator = testing.allocator,
    marker: []const u8,
    /// Only blocks of exactly this length count (the library's own growth
    /// copies of a buffer have other lengths).
    only_len: ?usize = null,
    dirty: usize = 0,
    allocs: usize = 0,

    fn allocator(w: *WipeAlloc) std.mem.Allocator {
        return .{ .ptr = w, .vtable = &vtable };
    }
    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const w: *WipeAlloc = @ptrCast(@alignCast(ctx));
        w.allocs += 1;
        return w.child.rawAlloc(len, a, ra);
    }
    // Resizes go to the child: the standard library's own growth and shrink of a
    // buffer (the request body's) is not the module's to wipe, and must not be
    // reported as if it were.
    fn resize(ctx: *anyopaque, mem: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const w: *WipeAlloc = @ptrCast(@alignCast(ctx));
        return w.child.rawResize(mem, a, new_len, ra);
    }
    fn remap(ctx: *anyopaque, mem: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const w: *WipeAlloc = @ptrCast(@alignCast(ctx));
        return w.child.rawRemap(mem, a, new_len, ra);
    }
    fn free(ctx: *anyopaque, mem: []u8, a: std.mem.Alignment, ra: usize) void {
        const w: *WipeAlloc = @ptrCast(@alignCast(ctx));
        if ((w.only_len == null or w.only_len.? == mem.len) and std.mem.find(u8, mem, w.marker) != null) w.dirty += 1;
        w.child.rawFree(mem, a, ra);
    }
};

/// A small router fixture: one guarded POST route, a `RawApp` state, an
/// allocator the test chooses for the cache (and with it the store).
const MiniFixture = struct {
    cache: ramcache.Cache,
    store: Store,
    app: RawApp,
    idem: Idempotency,
    r: router.Router,

    fn init(f: *MiniFixture, gpa: std.mem.Allocator, path: []const u8, h: router.Handler, opts: Options) !void {
        f.cache = ramcache.Cache.init(gpa, .{ .max_bytes = 1 << 20, .max_entries = 16 });
        f.store = .{ .cache = &f.cache };
        f.app = .{};
        f.idem = .{ .store = &f.store, .options = opts };
        f.r = router.Router.init(testing.allocator);
        f.r.state = &f.app;
        try f.r.use(f.idem.middleware());
        try f.r.post(path, h);
    }

    fn deinit(f: *MiniFixture) void {
        f.r.deinit();
        f.store.deinit();
        f.cache.deinit();
    }

    /// The same keyed request twice; the handler's call count after both.
    fn twice(f: *MiniFixture, comptime path: []const u8, comptime key: []const u8) !u32 {
        var b: [2048]u8 = undefined;
        _ = runWire(&f.r, reqKey("POST", path, key), &b);
        _ = runWire(&f.r, reqKey("POST", path, key), &b);
        return f.app.calls;
    }
};

fn hMini(ctx: *router.Ctx) anyerror!void {
    const app: *RawApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    try ctx.res.writeAll("ok");
}

fn expectPlain(got: []const u8, status_line: []const u8, body: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, status_line));
    try testing.expectEqualStrings("text/plain", headerValue(got, "Content-Type").?);
    try testing.expectEqualStrings(body, bodyOf(got));
}

var nested_resp: [2048]u8 = undefined;
var nested_len: usize = 0;

fn hNested(ctx: *router.Ctx) anyerror!void {
    const app: *ReentrantApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    if (app.calls == 1) nested_len = runWire(app.r, app.second_key, &nested_resp).len;
    try app.store.respond(ctx, 201, "application/json", "ok");
}

test "the refusal answers carry text/plain and their documented bodies; a first answer carries respond's content type" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store, .options = .{ .max_body_bytes = 4 } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hOrder);
    var b: [2048]u8 = undefined;
    const first = runWire(&r, reqKeyBody("POST", "/orders", "ans-1", "abcd"), &b);
    try testing.expectEqualStrings("application/json", headerValue(first, "Content-Type").?);
    try expectPlain(runWire(&r, reqKey("POST", "/orders", "\"open"), &b), "HTTP/1.1 400", "Invalid Idempotency-Key\n");
    try expectPlain(runWire(&r, reqKeyBody("POST", "/orders", "ans-1", "wxyz"), &b), "HTTP/1.1 422", "Idempotency-Key reused with a different request body\n");
    try expectPlain(runWire(&r, reqKeyBody("POST", "/orders", "ans-2", "abcde"), &b), "HTTP/1.1 413", "Idempotency-Key request body exceeds the fingerprint cap\n");

    var strict = Idempotency{ .store = &store, .options = .{ .require_key = true } };
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    try idemRouter(&r2, &strict, &app, hOrder);
    try expectPlain(runWire(&r2, reqNoKey("POST", "/orders"), &b), "HTTP/1.1 400", "Idempotency-Key required\n");

    var plain = Idempotency{ .store = &store };
    var r3 = router.Router.init(testing.allocator);
    defer r3.deinit();
    var napp = ReentrantApp{ .store = &store, .r = &r3, .second_key = reqKey("POST", "/orders", "nest-1") };
    r3.state = &napp;
    try r3.use(plain.middleware());
    try r3.post("/orders", hNested);
    _ = runWire(&r3, reqKey("POST", "/orders", "nest-1"), &b);
    try expectPlain(nested_resp[0..nested_len], "HTTP/1.1 409", "Idempotency-Key request already in flight\n");
}

fn hLocNoCt(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    try ctx.res.setHeader("Location", "/orders/9");
    try app.store.respond(ctx, 202, null, "accepted");
}

test "respond without a content type: the handler's last header is recorded; the replay has no Content-Type either" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hLocNoCt);
    var b1: [2048]u8 = undefined;
    const first = runWire(&r, reqKey("POST", "/orders", "nc-1"), &b1);
    try testing.expect(headerValue(first, "Content-Type") == null);
    var b2: [2048]u8 = undefined;
    const replay = runWire(&r, reqKey("POST", "/orders", "nc-1"), &b2);
    try testing.expectEqual(@as(u32, 1), app.calls);
    try testing.expect(std.mem.startsWith(u8, replay, "HTTP/1.1 202"));
    try testing.expectEqualStrings("/orders/9", headerValue(replay, "Location").?);
    try testing.expect(headerValue(replay, "Content-Type") == null);
    try testing.expectEqualStrings("accepted", bodyOf(replay));
}

fn hQuiet(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    try app.store.respond(ctx, 201, "text/plain", "ok");
}

fn hSecretOut(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    try app.store.respond(ctx, 201, "text/plain", "SECRET-MARKER-0123456789 in the response");
}

test "the buffered request body and the encoded record are wiped before they are freed" {
    // `Allocator.free` poisons the block in safe builds before the allocator sees it:
    // only an unchecked build can observe a missing wipe.
    if (std.debug.runtime_safety) return error.SkipZigTest;
    const marker = "SECRET-MARKER-0123456789";
    var wipe: WipeAlloc = .{ .marker = marker };
    var cache = ramcache.Cache.init(wipe.allocator(), .{ .max_bytes = 1 << 20, .max_entries = 16 });
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hQuiet);
    var b: [2048]u8 = undefined;
    // The request body: only the middleware's buffered copy ever holds it.
    const req_body = marker ++ " in the request";
    wipe.only_len = req_body.len; // the exact-size buffer the middleware hands back
    _ = runWire(&r, reqKeyBody("POST", "/orders", "wipe-1", req_body), &b);
    try testing.expectEqual(@as(u32, 1), app.calls);
    try testing.expectEqual(@as(usize, 0), wipe.dirty);
    // The response body: the encoded record is the copy the module frees.
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    try idemRouter(&r2, &idem, &app, hSecretOut);
    wipe.only_len = digest_len + 4 + "text/plain".len + "SECRET-MARKER-0123456789 in the response".len;
    _ = runWire(&r2, reqKey("POST", "/orders", "wipe-2"), &b);
    try testing.expectEqual(@as(u32, 2), app.calls);
    try testing.expectEqual(@as(usize, 0), wipe.dirty);
    // The replay: `begin` hands the middleware its own copy of the stored
    // record, freed once the response is written (mutation 2026-11-07, F2).
    _ = runWire(&r2, reqKey("POST", "/orders", "wipe-2"), &b);
    try testing.expectEqual(@as(u32, 2), app.calls); // replayed, not re-run
    try testing.expectEqual(@as(usize, 0), wipe.dirty);
}

test "HeaderIterator: a recorded header name at the u16 edge (65535 bytes) iterates, no overflow" {
    // `4 + nl` used to be computed in u16: a name of 65532..65535 bytes, which
    // `encode` and `decode` accept, panicked on replay (mutation 2026-11-07, F1).
    const big = try testing.allocator.alloc(u8, 65535);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    const hs = [_]http.Header{ .{ .name = big, .value = "v" }, .{ .name = "After", .value = "w" } };
    const d: [digest_len]u8 = @splat(2);
    const blob = try encode(testing.allocator, d, 200, "", &hs, "b");
    defer testing.allocator.free(blob);
    var it = decode(blob).?.headerIterator();
    const h1 = it.next().?;
    try testing.expectEqual(@as(usize, 65535), h1.name.len);
    try testing.expectEqualStrings("v", h1.value);
    const h2 = it.next().?;
    try testing.expectEqualStrings("After", h2.name);
    try testing.expectEqualStrings("w", h2.value);
    try testing.expect(it.next() == null);
}

test "Capturer: the limit is exact, an overflow stops collection, growth stays under the limit" {
    var c: Capturer = .{ .gpa = testing.allocator, .limit = 10, .prev = null };
    defer c.deinit();
    Capturer.observe(&c, "12345678");
    try testing.expect(!c.overflow);
    Capturer.observe(&c, "abc"); // 3 bytes, 2 left
    try testing.expect(c.overflow);
    Capturer.observe(&c, "x"); // fits, but the body is already incomplete
    try testing.expectEqualStrings("12345678", c.bytes.items);

    var e: Capturer = .{ .gpa = testing.allocator, .limit = 10, .prev = null };
    defer e.deinit();
    Capturer.observe(&e, "0123456789"); // exactly the limit: kept
    try testing.expect(!e.overflow);
    try testing.expectEqual(@as(usize, 10), e.bytes.items.len);

    var g: Capturer = .{ .gpa = testing.allocator, .limit = 10, .prev = null };
    defer g.deinit();
    Capturer.observe(&g, "01234567890"); // one over
    try testing.expect(g.overflow);
    try testing.expectEqual(@as(usize, 0), g.bytes.items.len);

    var h: Capturer = .{ .gpa = testing.allocator, .limit = 300, .prev = null };
    defer h.deinit();
    const a200: [200]u8 = @splat('a');
    const a100: [100]u8 = @splat('b');
    Capturer.observe(&h, &a200);
    Capturer.observe(&h, &a100);
    try testing.expectEqual(@as(usize, 300), h.bytes.items.len);
    // The buffer is bounded by the limit, not by the doubling.
    try testing.expect(h.bytes.capacity <= 300);
}

test "Capturer: collecting byte by byte allocates a handful of times, not once per byte" {
    var wipe: WipeAlloc = .{ .marker = "~no-such-marker~" };
    var c: Capturer = .{ .gpa = wipe.allocator(), .limit = 1 << 20, .prev = null };
    defer c.deinit();
    for (0..1000) |_| Capturer.observe(&c, "z");
    try testing.expectEqual(@as(usize, 1000), c.bytes.items.len);
    try testing.expect(wipe.allocs <= 4);
}

test "Capturer: the buffer it outgrows and the one it ends with are wiped before they are freed" {
    if (std.debug.runtime_safety) return error.SkipZigTest; // see the request-body test above
    const marker = "SECRET-MARKER-0123456789";
    var wipe: WipeAlloc = .{ .marker = marker };
    var c: Capturer = .{ .gpa = wipe.allocator(), .limit = 1 << 20, .prev = null };
    Capturer.observe(&c, marker);
    const filler: [300]u8 = @splat('f');
    Capturer.observe(&c, &filler); // outgrows the first buffer
    try testing.expectEqual(@as(usize, 0), wipe.dirty);
    c.deinit();
    try testing.expectEqual(@as(usize, 0), wipe.dirty);
}

test "TTL on the ramcache path: a record lives through age == ttl and is gone one ns later" {
    var clk = ManualClock{ .now_ns = 1000 };
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache, .clock = clk.clock(), .ttl_ns = 100 };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hOrder);
    var b: [2048]u8 = undefined;
    _ = runWire(&r, reqKey("POST", "/orders", "edge-a"), &b);
    _ = runWire(&r, reqKey("POST", "/orders", "edge-b"), &b);
    try testing.expectEqual(@as(u32, 2), app.calls);
    clk.now_ns = 1100; // age == ttl
    const live = runWire(&r, reqKey("POST", "/orders", "edge-a"), &b);
    try testing.expectEqualStrings("true", headerValue(live, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 2), app.calls);
    clk.now_ns = 1101; // age == ttl + 1
    const gone = runWire(&r, reqKey("POST", "/orders", "edge-b"), &b);
    try testing.expect(headerValue(gone, "Idempotent-Replayed") == null);
    try testing.expectEqual(@as(u32, 3), app.calls);
}

test "defaults: a record lives exactly 24 h" {
    var clk = ManualClock{ .now_ns = 5_000 };
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache, .clock = clk.clock() };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hOrder);
    var b: [2048]u8 = undefined;
    _ = runWire(&r, reqKey("POST", "/orders", "d24-a"), &b);
    _ = runWire(&r, reqKey("POST", "/orders", "d24-b"), &b);
    clk.now_ns = 5_000 + 86_400_000_000_000;
    const live = runWire(&r, reqKey("POST", "/orders", "d24-a"), &b);
    try testing.expectEqualStrings("true", headerValue(live, "Idempotent-Replayed").?);
    try testing.expectEqual(@as(u32, 2), app.calls);
    clk.now_ns += 1;
    _ = runWire(&r, reqKey("POST", "/orders", "d24-b"), &b);
    try testing.expectEqual(@as(u32, 3), app.calls);
}

const body16k: [16384]u8 = @splat('B');
const body16k1: [16385]u8 = @splat('B');

test "defaults: a 16 KiB request body is fingerprinted, one byte more answers 413" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hOrder);
    var b: [2048]u8 = undefined;
    const at = runWire(&r, reqKeyBody("POST", "/orders", "cap16-a", &body16k), &b);
    try testing.expect(std.mem.startsWith(u8, at, "HTTP/1.1 201"));
    const over = runWire(&r, reqKeyBody("POST", "/orders", "cap16-b", &body16k1), &b);
    try testing.expect(std.mem.startsWith(u8, over, "HTTP/1.1 413"));
    try testing.expectEqual(@as(u32, 1), app.calls);
}

var huge_len: usize = 0;

fn hHuge(ctx: *router.Ctx) anyerror!void {
    const app: *RawApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    try ctx.res.setHeader("Content-Type", "application/octet-stream");
    const chunk: [4096]u8 = @splat('h');
    var left = huge_len;
    while (left > 0) {
        const n = @min(left, chunk.len);
        try ctx.res.writeAll(chunk[0..n]);
        left -= n;
    }
}

test "defaults: a 1 MiB response is captured, one byte more is refused and counted" {
    defer huge_len = 0;
    const cases = [_]struct { len: usize, calls: u32 }{
        .{ .len = 1 << 20, .calls = 1 },
        .{ .len = (1 << 20) + 1, .calls = 2 },
    };
    for (cases) |c| {
        errdefer std.debug.print("huge case len={d}\n", .{c.len});
        huge_len = c.len;
        var cache = ramcache.Cache.init(testing.allocator, .{ .max_bytes = 64 << 20, .max_entries = 16 });
        defer cache.deinit();
        var store = Store{ .cache = &cache };
        defer store.deinit();
        var app = RawApp{};
        var idem = Idempotency{ .store = &store };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        r.state = &app;
        try r.use(idem.middleware());
        try r.post("/orders", hHuge);
        const b = try testing.allocator.alloc(u8, 3 << 20);
        defer testing.allocator.free(b);
        _ = runWire(&r, reqKey("POST", "/orders", "huge"), b);
        _ = runWire(&r, reqKey("POST", "/orders", "huge"), b);
        try testing.expectEqual(c.calls, app.calls);
        try testing.expectEqual(@as(u64, if (c.calls == 2) 2 else 0), store.capture_refused.load(.monotonic));
    }
}

test "encode: lengths at the u16 edge -- 65535 fits, 65536 is refused (content type, header name, header value)" {
    const d: [digest_len]u8 = @splat(2);
    const big = try testing.allocator.alloc(u8, 65536);
    defer testing.allocator.free(big);
    @memset(big, 'x');

    const ok_ct = try encode(testing.allocator, d, 200, big[0..65535], &.{}, "b");
    defer testing.allocator.free(ok_ct);
    const rec_ct = decode(ok_ct).?;
    try testing.expectEqual(@as(usize, 65535), rec_ct.content_type.len);
    try testing.expectEqualStrings("b", rec_ct.body);
    try testing.expectError(error.InvalidRecord, encode(testing.allocator, d, 200, big, &.{}, "b"));

    const name_ok = [_]http.Header{.{ .name = big[0..65535], .value = "v" }};
    const ok_n = try encode(testing.allocator, d, 200, "", &name_ok, "b");
    defer testing.allocator.free(ok_n);
    const rec_n = decode(ok_n).?;
    // (Not walked with the iterator: its u16 offset arithmetic overflows at this length.)
    try testing.expectEqual(@as(usize, 4 + 65535 + 1), rec_n.headers.len);
    try testing.expectEqualStrings("b", rec_n.body);
    const name_bad = [_]http.Header{.{ .name = big, .value = "v" }};
    try testing.expectError(error.InvalidRecord, encode(testing.allocator, d, 200, "", &name_bad, "b"));

    const val_ok = [_]http.Header{.{ .name = "X-V", .value = big[0..65535] }};
    const ok_v = try encode(testing.allocator, d, 200, "", &val_ok, "b");
    defer testing.allocator.free(ok_v);
    const rec_v = decode(ok_v).?;
    var it_v = rec_v.headerIterator();
    const e_v = it_v.next().?;
    try testing.expectEqualStrings("X-V", e_v.name);
    try testing.expectEqual(@as(usize, 65535), e_v.value.len);
    try testing.expectEqualStrings("b", rec_v.body);
    const val_bad = [_]http.Header{.{ .name = "X-V", .value = big }};
    try testing.expectError(error.InvalidRecord, encode(testing.allocator, d, 200, "", &val_bad, "b"));
}

test "encode drops every transfer-level header, whatever its case, and keeps the rest" {
    const names = [_][]const u8{ "Content-Type", "CONTENT-LENGTH", "Transfer-Encoding", "content-encoding", "Trailer", "connection", "Keep-Alive", "UPGRADE", "date", "Set-Cookie" };
    var hs: [names.len + 1]http.Header = undefined;
    for (names, 0..) |n, i| hs[i] = .{ .name = n, .value = "v" };
    hs[names.len] = .{ .name = "X-Keep", .value = "k" };
    const d: [digest_len]u8 = @splat(3);
    const blob = try encode(testing.allocator, d, 201, "text/plain", &hs, "b");
    defer testing.allocator.free(blob);
    const rec = decode(blob).?;
    var it = rec.headerIterator();
    const only = it.next().?;
    try testing.expectEqualStrings("X-Keep", only.name);
    try testing.expectEqualStrings("k", only.value);
    try testing.expect(it.next() == null);
    try testing.expectEqualStrings("b", rec.body);
}

fn hAny201(ctx: *router.Ctx) anyerror!void {
    const app: *RawApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    ctx.res.setStatus(201);
    try ctx.res.writeAll("ok");
}

const long_path: []const u8 = "/" ++ @as([999]u8, @splat('p'));
const key16: []const u8 = &@as([16]u8, @splat('k'));
const key17: []const u8 = &@as([17]u8, @splat('k'));

test "a scoped key of exactly 1024 bytes is deduplicated; one byte more runs the handler normally" {
    // "* POST <path> <key>" = 8 + path + key bytes.
    {
        var f: MiniFixture = undefined;
        try f.init(testing.allocator, long_path, hAny201, .{});
        defer f.deinit();
        try testing.expectEqual(@as(u32, 1), try f.twice(long_path, key16));
    }
    {
        var f: MiniFixture = undefined;
        try f.init(testing.allocator, long_path, hAny201, .{});
        defer f.deinit();
        var b: [2048]u8 = undefined;
        const first = runWire(&f.r, reqKey("POST", long_path, key17), &b);
        try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 201"));
        const second = runWire(&f.r, reqKey("POST", long_path, key17), &b);
        try testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 201"));
        try testing.expect(headerValue(second, "Idempotent-Replayed") == null);
        try testing.expectEqual(@as(u32, 2), f.app.calls);
    }
}

test "a body that cannot be buffered or read is an error, never the 413 'too large'; nothing stays reserved" {
    var wa: WatchAlloc = .{};
    var f: MiniFixture = undefined;
    try f.init(wa.allocator(), "/m", hMini, .{});
    defer f.deinit();
    var b: [2048]u8 = undefined;
    wa.fail_at_least = 1; // buffering the body fails
    const oom = runWire(&f.r, reqKeyBody("POST", "/m", "oom-1", "0123456789"), &b);
    try testing.expect(!std.mem.startsWith(u8, oom, "HTTP/1.1 413"));
    try testing.expectEqual(@as(u32, 0), f.app.calls);
    wa.fail_at_least = std.math.maxInt(usize);
    // A body shorter than its Content-Length cannot be read to the end.
    const cut = runWire(&f.r, "POST /m HTTP/1.1\r\nHost: t\r\nIdempotency-Key: cut-1\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc", &b);
    try testing.expect(!std.mem.startsWith(u8, cut, "HTTP/1.1 413"));
    try testing.expectEqual(@as(u32, 0), f.app.calls);
    // Neither left a reservation: the same key with a whole body runs.
    const ok = runWire(&f.r, reqKeyBody("POST", "/m", "oom-1", "0123456789"), &b);
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200"));
    try testing.expectEqual(@as(u32, 1), f.app.calls);
}

var decoded_restored: bool = false;

fn outerDecoded(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    var mine: Reader = .fixed("");
    ctx.req.decoded = &mine;
    defer ctx.req.decoded = null;
    try next.run(ctx);
    decoded_restored = ctx.req.decoded == &mine;
}

test "the middleware puts back the decoded reader an outer layer had set" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    decoded_restored = false;
    try r.use(.{ .state = null, .run = outerDecoded });
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);
    var b: [2048]u8 = undefined;
    const first = runWire(&r, reqKey("POST", "/orders", "dec-1"), &b);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 201"));
    try testing.expect(decoded_restored);
}

test "an undecodable stored record re-runs the handler: no replay, no 422, no reservation" {
    var clk = ManualClock{ .now_ns = 1000 };
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache, .clock = clk.clock() };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = Idempotency{ .store = &store };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try idemRouter(&r, &idem, &app, hOrder);
    var key_buf: [max_scoped_key]u8 = undefined;
    const scoped = scopeKey(&key_buf, .target, "POST", "/orders", null, "bad-rec").?;
    cache.put(scoped, "garbage", clk.now_ns, 1_000_000, 0);
    var b: [2048]u8 = undefined;
    const first = runWire(&r, reqKey("POST", "/orders", "bad-rec"), &b);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 201"));
    try testing.expect(headerValue(first, "Idempotent-Replayed") == null);
    try testing.expectEqual(@as(u32, 1), app.calls);
    // The record stays what it was (a foreign writer's), so the retry runs again.
    const second = runWire(&r, reqKey("POST", "/orders", "bad-rec"), &b);
    try testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 201"));
    try testing.expectEqual(@as(u32, 2), app.calls);
}

fn innerFixtureOpts(f: *ShapeFixture, inner: *InnerMw, opts: Options) !void {
    f.cache = ramcache.Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 16 });
    f.store = .{ .cache = &f.cache };
    f.app = .{};
    f.idem = .{ .store = &f.store, .options = opts };
    f.r = router.Router.init(testing.allocator);
    f.r.state = &f.app;
    try f.r.use(f.idem.middleware());
    try f.r.use(.{ .state = inner, .run = InnerMw.run });
    try f.r.post("/s", hShape);
}

test "capture .off installs no tap: an inner layer displacing taps is not a counted refusal" {
    defer shape = .{};
    shape = .{ .len = 6000 };
    var inner: InnerMw = .{ .rogue_tap = true };
    var f: ShapeFixture = undefined;
    try innerFixtureOpts(&f, &inner, .{ .capture = .off });
    defer f.deinit();
    try testing.expectEqual(@as(u32, 2), try f.twice("POST", "off-rogue"));
    try testing.expectEqual(@as(u64, 0), f.refused());
}

var ct_name: []const u8 = "text/plain";

fn hCt(ctx: *router.Ctx) anyerror!void {
    const app: *RawApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    try ctx.res.setHeader("Content-Type", ct_name);
    try ctx.res.writeAll("data: 1\n\n");
}

test "capture: an event stream is refused whatever the case of its media type; other types are kept" {
    defer ct_name = "text/plain";
    const cases = [_]struct { ct: []const u8, calls: u32 }{
        .{ .ct = "Text/Event-Stream", .calls = 2 },
        .{ .ct = "text/event-stream; charset=utf-8", .calls = 2 },
        .{ .ct = "text/plain", .calls = 1 },
    };
    for (cases) |c| {
        errdefer std.debug.print("content type {s}\n", .{c.ct});
        ct_name = c.ct;
        var f: MiniFixture = undefined;
        try f.init(testing.allocator, "/m", hCt, .{});
        defer f.deinit();
        try testing.expectEqual(c.calls, try f.twice("/m", "ct-1"));
        try testing.expectEqual(@as(u64, if (c.calls == 2) 2 else 0), f.store.capture_refused.load(.monotonic));
    }
}

test "capture: whatever allocation fails while collecting, a re-run is a counted refusal and a kept record is not" {
    defer shape = .{};
    // Every doubling step of the collection buffer, for bodies whose tail needs a growth of its own.
    for ([_]usize{ 6000, 8193, 9000, 12200, 20000 }) |len| {
        for ([_]usize{ 4098, 8193, 16385, 32769 }) |fail_at| {
            errdefer std.debug.print("len={d} fail_at_least={d}\n", .{ len, fail_at });
            shape = .{ .len = len };
            var wa: WatchAlloc = .{};
            var f: ShapeFixture = undefined;
            try f.init(.{}, wa.allocator(), null);
            defer f.deinit();
            wa.fail_at_least = fail_at;
            const calls = try f.twice("POST", "oom-tail");
            try testing.expect(calls == 1 or calls == 2);
            try testing.expectEqual(@as(u64, if (calls == 2) 2 else 0), f.refused());
        }
    }
}

test "capture: a 1xx answer declaring a length is recorded like a 204 or 304" {
    defer shape = .{};
    shape = .{ .status = 199, .declared = "10", .len = 0 };
    var f: ShapeFixture = undefined;
    try f.init(.{}, testing.allocator, null);
    defer f.deinit();
    try testing.expectEqual(@as(u32, 1), try f.twice("POST", "one-xx"));
    try testing.expectEqual(@as(u64, 0), f.refused());
}

test "fingerprint: SHA-256 of the body; with a query SHA-256(SHA-256(body) ++ 0x01 ++ query) -- pinned, records outlive an upgrade" {
    try testing.expectEqualStrings("230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5", &std.fmt.bytesToHex(fingerprint("body", ""), .lower));
    try testing.expectEqualStrings("c090c58c2401c7316350f17c41336f42b6719d161f5e01fda570b905a5f60864", &std.fmt.bytesToHex(fingerprint("body", "a=1&b=2"), .lower));
    try testing.expectEqualStrings("638c85b41a88258335d5344b067b27456058ccac766dad0cfabb69329b2a90e7", &std.fmt.bytesToHex(fingerprint("", "to=alice"), .lower));
    try testing.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &std.fmt.bytesToHex(fingerprint("", ""), .lower));
}

test "parseKey and validKey at their edges: DEL, 0x1f, tilde, a trailing or doubled backslash, the end of the output buffer" {
    var buf: [max_scoped_key]u8 = undefined;
    try testing.expect(!validKey("a\x7fb", 255));
    try testing.expect(parseKey("a\x7fb", 255, &buf) == null);
    try testing.expect(parseKey("\"abc\\", 255, &buf) == null);
    try testing.expectEqualStrings("a\\b", parseKey("\"a\\\\b\"", 255, &buf).?);
    try testing.expect(parseKey("\"a\x1fb\"", 255, &buf) == null);
    try testing.expectEqualStrings("a~b", parseKey("\"a~b\"", 255, &buf).?);
    // `max_len` allows far more than `buf` holds: the buffer is the bound, never a panic.
    var small: [4]u8 = undefined;
    try testing.expectEqualStrings("abcd", parseKey("\"abcd\"", 255, &small).?);
    try testing.expect(parseKey("\"abcde\"", 255, &small) == null);
}

test "begin: an allocation failure leaves no reservation and leaks nothing" {
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    var cache = ramcache.Cache.init(fa.allocator(), .{ .max_bytes = 1 << 20, .max_entries = 16 });
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    defer store.deinit();
    const d: [digest_len]u8 = @splat(0);
    var req: u8 = 0;
    fa.fail_index = fa.alloc_index; // the key copy
    try testing.expectError(error.OutOfMemory, store.begin("k1", d, &req, testing.allocator));
    try testing.expectEqual(@as(usize, 0), store.in_flight.count());
    fa.fail_index = fa.alloc_index + 1; // the reservation set's growth: the key copy is freed
    try testing.expectError(error.OutOfMemory, store.begin("k2", d, &req, testing.allocator));
    try testing.expectEqual(@as(usize, 0), store.in_flight.count());
    fa.fail_index = fa.alloc_index + 2; // the request binding's growth: the reservation is withdrawn
    try testing.expectError(error.OutOfMemory, store.begin("k3", d, &req, testing.allocator));
    try testing.expectEqual(@as(usize, 0), store.in_flight.count());
    try testing.expectEqual(@as(usize, 0), store.pending.count());
    fa.fail_index = std.math.maxInt(usize);
    try testing.expect((try store.begin("k4", d, &req, testing.allocator)) == .reserved);
    store.finish("k4", &req);
}

test "Store.deinit frees the request binding of a reservation still held" {
    var cache = newCache();
    defer cache.deinit();
    var store = Store{ .cache = &cache };
    const d: [digest_len]u8 = @splat(0);
    var req: u8 = 0;
    try testing.expect((try store.begin("held", d, &req, testing.allocator)) == .reserved);
    store.deinit(); // its in_flight key is the binding's key: freed once
}

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
//!   `Store.current(req)` and runs the chain.
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
//! lock-free). The scoped key travels middleware→handler in the store itself,
//! bound to the request's address (`Store.current`) -- never in thread-local
//! storage, which a second request on the same thread (a nested dispatch, or
//! another fiber on an evented `Io`) would overwrite (A1 F2). The in-flight
//! reservation set is guarded by the same lock; call `Store.deinit()` once
//! when the store is retired to release it. The `Store` and `Idempotency`
//! must outlive the `Router`, at stable addresses.

const std = @import("std");
const builtin = @import("builtin");
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
    .deps = .{ "router", "http", "ramcache", "kv" },
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

    /// What a request holding a reservation is recording under.
    pub const Current = struct {
        key: []const u8,
        digest: [digest_len]u8,
    };

    /// Release the in-flight reservation set. Call once when the store is no
    /// longer used. In steady state the set is empty (every reservation is
    /// released when its handler returns); this frees the map's backing.
    pub fn deinit(store: *Store) void {
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
        const cache = store.cache.?;
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
        if (store.in_flight.fetchRemove(key)) |e| store.cache.?.alloc.free(e.key);
    }

    /// The allocator for the store's own copies: the cache's, or the backend's.
    pub fn alloc(store: *const Store) std.mem.Allocator {
        if (store.backend) |b| return b.gpa;
        return store.cache.?.alloc;
    }

    /// The reservation `request` holds, or null when it holds none (no key,
    /// an unguarded method, an invalid key, a replay). The key slice is
    /// valid until that request's reservation is finished.
    pub fn current(store: *Store, request: *const anyopaque) ?Current {
        lockSpin(&store.lock);
        defer store.lock.unlock();
        return store.pending.get(@intFromPtr(request));
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
        try ctx.res.writeAll(body);
        if (store.current(ctx.req)) |c| store.record(c.key, c.digest, status, content_type orelse "", body);
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
        const a = store.alloc();
        const blob = encode(a, digest, status, content_type, body) catch return;
        defer a.free(blob);
        const now = store.clock.now();
        if (store.backend) |b| return b.vtable.put(b.ptr, key, blob, now, store.ttl_ns);
        lockSpin(&store.lock);
        defer store.lock.unlock();
        store.cache.?.put(key, blob, now, store.ttl_ns, 0);
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

/// Read a `Begin.replay` blob; null for one that is not a record (a server
/// then runs the request instead, as the middleware does).
pub fn decode(blob: []const u8) ?RecordedResponse {
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
    const client_key = ctx.req.header(idem.options.header_name) orelse return next.run(ctx);
    if (!validKey(client_key, idem.options.max_key_len)) return badRequest(ctx);

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
    // `allocRemaining` treats reaching its limit exactly as `StreamTooLong`
    // (bytes up to the limit are read either way); probing at
    // `max_body_bytes + 1` is what makes a body of exactly the configured
    // cap succeed while one byte more is rejected — the documented boundary.
    const probe_cap = if (idem.options.max_body_bytes == std.math.maxInt(usize))
        idem.options.max_body_bytes
    else
        idem.options.max_body_bytes + 1;
    const body_bytes = ctx.req.reader().allocRemaining(idem.store.alloc(), .limited(probe_cap)) catch |err| switch (err) {
        error.StreamTooLong => return payloadTooLarge(ctx),
        else => |e| return e,
    };
    defer {
        // The caller's payload, on a heap the next request draws from (A1 F4).
        std.crypto.secureZero(u8, body_bytes);
        idem.store.alloc().free(body_bytes);
    }
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
    switch (try idem.store.begin(scoped, digest, ctx.req, idem.store.alloc())) {
        .replay => |blob| {
            // A hit writes the recorded response and short-circuits the chain,
            // so the handler never runs.
            defer idem.store.alloc().free(blob);
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

    // Miss (reserved): the reservation is bound to THIS request (`current`),
    // run the chain, then release it so a later retry can proceed.
    defer idem.store.finish(scoped, ctx.req);
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
pub fn validKey(v: []const u8, max_len: usize) bool {
    if (v.len == 0 or v.len > max_len) return false;
    for (v) |c| {
        if (c <= ' ' or c >= 0x7f) return false;
    }
    return true;
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
        .key_only => std.fmt.bufPrint(buf, "{s} {s}", .{ who, client_key }) catch null,
        .target => std.fmt.bufPrint(buf, "{s} {s} {s} {s}", .{
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
    return std.fmt.bufPrint(out, "{x}", .{d[0 .. principal_hex_len / 2]}) catch unreachable;
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
//   6. otherwise run the handler and, if it used `respond`, record the answer
//      for `ttl_ns` (a record older than `ttl_ns` is gone).
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
/// `ctx.res` directly (never recorded); every other path uses `respond`.
fn fzHandler(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    const n = app.calls;
    const seen = try ctx.req.reader().allocRemaining(testing.allocator, .limited(4096));
    defer testing.allocator.free(seen);
    var buf: [128]u8 = undefined;
    const body = std.fmt.bufPrint(&buf, "n{d}:{s}", .{ n, seen }) catch unreachable;
    const status: u16 = 200 + @as(u16, @intCast(n % 3));
    const ct: ?[]const u8 = if (n % 3 == 0) null else if (n % 2 == 0) "text/plain" else "application/json";
    if (std.mem.eql(u8, ctx.req.path, "/raw")) {
        ctx.res.setStatus(status);
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
    if (k.len == 0) return false;
    if (k.len > 255) return false;
    for (k) |c| {
        if (c < 0x21 or c > 0x7e) return false;
    }
    return true;
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
    const keys = [_][]const u8{ "k1", "k2", "k3", "a.b_c-d~!", &long255 };
    const bad_keys = [_][]const u8{ "bad key", &long256, "" };
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
        target_isolated_miss: usize = 0,
        caller_isolated_miss: usize = 0,
        recorded: usize = 0,
        ttl_edge: usize = 0,
    }{};

    var seq: usize = 0;
    while (seq < 80) : (seq += 1) {
        const key_only = rnd.boolean();
        const use_principal = rnd.boolean();
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
            errdefer std.debug.print("idempotency model-fuzz mismatch: seed=0x{x} seq={d} step={d} key_only={} principal={}\n", .{ seed, seq, step, key_only, use_principal });

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
                    if (op.key.?.len == 255) reach.key255_ok += 1;
                    // Find a live record that matches this request's scope.
                    var found: ?usize = null;
                    var i: usize = 0;
                    while (i < recs.items.len) : (i += 1) {
                        const rec = recs.items[i];
                        if (!std.mem.eql(u8, rec.caller, who)) continue;
                        if (!std.mem.eql(u8, rec.key, op.key.?)) continue;
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
                        if (!std.mem.eql(u8, rec.key, op.key.?)) continue;
                        if (std.mem.eql(u8, rec.caller, who) and !key_only and (rec.method != op.method or rec.path != op.path))
                            reach.target_isolated_miss += 1;
                        if (!std.mem.eql(u8, rec.caller, who) and (key_only or (rec.method == op.method and rec.path == op.path)))
                            reach.caller_isolated_miss += 1;
                    }
                    if (op.path == 2) reach.raw_rerun += 1;
                } else if (!guarded) {
                    reach.bypass_method += 1;
                } else if (op.key == null) {
                    reach.bypass_nokey += 1;
                } else reach.bypass_nocaller += 1;

                // The handler runs: model its answer, and record it if cooperative.
                model_calls += 1;
                const n = model_calls;
                var want_buf: [128]u8 = undefined;
                const want_body = std.fmt.bufPrint(&want_buf, "n{d}:{s}", .{ n, op.body }) catch unreachable;
                const want_status: u16 = 200 + @as(u16, @intCast(n % 3));
                try testing.expectEqual(want_status, status);
                try testing.expectEqualStrings(want_body, body);
                try testing.expect(replayed == null);
                if (!bypass and op.path != 2) {
                    reach.recorded += 1;
                    const ct: ?[]const u8 = if (n % 3 == 0) null else if (n % 2 == 0) "text/plain" else "application/json";
                    try recs.append(testing.allocator, .{
                        .caller = who,
                        .method = op.method,
                        .path = op.path,
                        .key = try testing.allocator.dupe(u8, op.key.?),
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

    inline for (@typeInfo(@TypeOf(reach)).@"struct".fields) |f| {
        if (@field(reach, f.name) == 0) {
            std.debug.print("idempotency model-fuzz: reach class never hit: {s}\n", .{f.name});
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
            std.fmt.bufPrint(&want_buf, "{s} {s} {s} {s}", .{ wstr, names[mi], path, key[0..@min(klen, 100)] }) catch unreachable
        else
            std.fmt.bufPrint(&want_buf, "{s} {s}", .{ wstr, key[0..@min(klen, 100)] }) catch unreachable;
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

        // decode: build a blob from fields (digest | status BE | ctlen BE | ct | body),
        // then maybe truncate or corrupt the length field.
        var blob: [200]u8 = undefined;
        var bl: usize = 0;
        rnd.bytes(blob[0..32]);
        const status: u16 = rnd.int(u16);
        blob[32] = @intCast(status >> 8);
        blob[33] = @intCast(status & 0xff);
        const ctl = rnd.uintLessThan(usize, 20);
        const bodyl = rnd.uintLessThan(usize, 40);
        blob[34] = @intCast(ctl >> 8);
        blob[35] = @intCast(ctl & 0xff);
        rnd.bytes(blob[36 .. 36 + ctl + bodyl]);
        bl = 36 + ctl + bodyl;
        switch (rnd.uintLessThan(u8, 4)) {
            0 => bl = rnd.uintLessThan(usize, bl + 1), // truncate anywhere
            1 => { // claim a longer content type than present
                const lie = ctl + bodyl + 1 + rnd.uintLessThan(usize, 5);
                blob[34] = @intCast(lie >> 8);
                blob[35] = @intCast(lie & 0xff);
            },
            else => {},
        }
        const claimed = (@as(usize, blob[34]) << 8) | blob[35];
        const decoded = decode(blob[0..bl]);
        if (bl >= 36 and 36 + claimed <= bl) {
            dec_ok += 1;
            const d = decoded.?;
            try testing.expectEqualSlices(u8, blob[0..32], &d.digest);
            try testing.expectEqual(status, d.status);
            try testing.expectEqualSlices(u8, blob[36 .. 36 + claimed], d.content_type);
            try testing.expectEqualSlices(u8, blob[36 + claimed .. bl], d.body);
        } else {
            dec_null += 1;
            try testing.expect(decoded == null);
        }
    }
    try testing.expect(valid_n > 0 and invalid_n > 0 and overflow_n > 0 and fit_n > 0 and dec_ok > 0 and dec_null > 0);
}

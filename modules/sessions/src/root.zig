// SPDX-License-Identifier: MIT

//! sessions — server-side web sessions + CSRF as a `router` middleware.
//!
//! A session is server-side state keyed by an opaque, unguessable id that the
//! browser echoes in a cookie. The id is generated from a CSPRNG
//! (`std.Io.random`, threaded in at construction — never the removed
//! `std.crypto.random`, never a test-only `DefaultPrng`), so a session id can
//! be neither guessed nor forged. The state lives in a pluggable `Store`
//! (default: a bounded, TTL-evicting `ramcache`; `KvStore` keeps sessions
//! across a restart in a `kv` store); the cookie carries only the id.
//!
//! ## What the middleware does (`Manager.middleware`)
//!
//! On each request it **loads** the session named by the cookie (rejecting and
//! evicting one past its idle or absolute timeout) or **creates** a fresh one,
//! attaches the `*Session` to `ctx.data` (the slot `router` reserves —
//! `sessionOf(ctx)` reads it back, the same pattern as `aaa-gate`'s identity),
//! runs the handler, then **saves**: it re-encodes the session into the store
//! and stamps a refreshed `Set-Cookie` (rolling idle expiry). A handler may
//! call `session.revoke()` (logout) — the middleware then **destroys** the
//! session (evicts it from the store and overwrites the cookie with
//! `Max-Age=-1`) instead of saving. A handler that changes the identity of the
//! logged-in principal should call `Manager.regenerate` (session-fixation
//! defense): a new id is minted, the data carried over, the old id killed in
//! the store.
//!
//! ## Values, remember-me, enumeration, hashed store keys
//!
//! `Session.putValue`/`getValue`/`popValue`/`removeValue`/`valueIterator`/
//! `clearValues` are a key/value + flash layer over the data blob (see
//! `values.zig`); `Session.rememberMe` with `Options.persist_cookie = false`
//! makes the cookie a browser-session cookie unless remembered;
//! `Manager.iterate` walks every live session (logout-everywhere; `KvStore`
//! only); `Options.hash_id_in_store` keys the store by SHA-256(id).
//!
//! ## Cookie hardening (OWASP Session Management Cheat Sheet)
//!
//! Session cookies are always `HttpOnly` (out of reach of page JS) and
//! `Secure` (HTTPS-only) with `SameSite=Lax` by default. `Secure` can be
//! dropped for a plain-HTTP dev server via the explicit
//! `Options.allow_insecure_cookie` escape hatch — never silently.
//!
//! ## CSRF (`csrf.zig`, re-exported as `Csrf`)
//!
//! A *signed double-submit* token: `HMAC-SHA256(key, session_id)`. The token
//! is bound to the session, so it cannot be replayed across sessions, and it
//! needs no server-side state (the server recomputes and compares in constant
//! time — `std.crypto.timing_safe.eql`, never `std.mem.eql`). `Csrf.middleware`
//! guards the unsafe methods (POST/PUT/PATCH/DELETE) and 403s a request whose
//! presented token (header, else query-param fallback) is missing or wrong;
//! safe methods pass and get a fresh token cookie to echo.
//!
//! ## Thread-safety
//!
//! A built `Manager` is immutable and shared across `http.Server`'s connection
//! threads; the only mutable state is the `Store`, whose default
//! `RamcacheStore` serializes every cache touch behind its own
//! `std.atomic.Mutex` (`ramcache` is single-owner). Every store record carries
//! a monotonic **generation**; `save` is a compare-and-swap against the
//! generation the request loaded, done atomically under that mutex, so a
//! `save` from one in-flight request cannot resurrect a session a *concurrent*
//! request just `destroy`ed or `regenerate`d (the delete/rotate bumped the
//! generation — the stale CAS no longer matches and is dropped, fail closed).
//! Per-request `Session` state lives on the serving thread's stack. The
//! `Set-Cookie` value is staged in a
//! thread-local buffer (the response writer stores header slices uncopied and
//! serializes them lazily at `writeHead`, after the handler returns — a stack
//! buffer would dangle; task-per-connection makes the thread-local safe).

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");
const cookies = @import("cookies");
const ramcache = @import("ramcache");
const entropy = @import("entropy");
const kv = @import("kv");

const csrf = @import("csrf.zig");
const idhex = @import("idhex.zig");
const values = @import("values.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Server-side web sessions + OWASP-hardened cookies + signed double-submit CSRF middleware",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .server,
    // The Manager is immutable once built; the only mutable state is the
    // Store, whose default impl serializes cache access behind its own lock.
    .concurrency = .threadsafe,
    .model_after = "OWASP Session Management + CSRF Prevention Cheat Sheets",
    .deps = .{ "router", "http", "cookies", "ramcache", "entropy", "kv" }, // entropy: the session-id draw; kv: KvStore
};

const Allocator = std.mem.Allocator;

/// CSRF (signed double-submit) — see `csrf.zig`.
pub const Csrf = csrf.Csrf;
pub const csrf_token_hex_len = csrf.token_hex_len;

// ── tunables ────────────────────────────────────────────────────────────────

/// Largest raw session-id length in bytes (hex-encoded to twice this in the
/// cookie). 32 is the default; 64 is the ceiling.
pub const max_id_bytes = 64;

/// Hard floor on `Options.id_bytes` (128 bits of CSPRNG entropy).
/// `Manager.init` rejects anything below this (a real error return, in every
/// build mode) — a caller-configured `id_bytes` of, say, 1 (8 bits) would
/// make the session id brute-forceable.
pub const min_id_bytes = 16;

/// Largest application payload one session may carry (kept inline in the
/// `Session` so the request path never allocates). Larger blobs belong in a
/// real datastore keyed by the session, not in the session itself.
pub const max_session_bytes = 4096;

/// Default idle timeout: a session unused for this long is rejected (30 min).
pub const default_idle_timeout_ns: i64 = 30 * 60 * std.time.ns_per_s;

/// Default absolute timeout: a session older than this is rejected regardless
/// of activity (12 h).
pub const default_absolute_timeout_ns: i64 = 12 * 60 * 60 * std.time.ns_per_s;

/// Default session cookie name.
pub const default_cookie_name = "session";

// Fixed record header: [created_ns i64 LE][last_seen_ns i64 LE], data follows.
//
// Bit 63 of the stored `created_ns` word is the session's remember-me flag
// (`Session.rememberMe`); the timestamp itself is the low 63 bits read as a
// signed (two's complement) 63-bit number, so any clock value in
// [-2^62, 2^62) -- about +-146 years of nanoseconds, a negative one included --
// round-trips exactly. Records written before the flag existed have bit 63
// clear for every non-negative time, i.e. read as "flag off" and unchanged.
const record_header_len = 16;
const remember_bit: u64 = 1 << 63;
const created_min: i64 = -(1 << 62);
const created_max: i64 = (1 << 62) - 1;

fn encodeCreated(created: i64, remember: bool) u64 {
    const c: u64 = @bitCast(std.math.clamp(created, created_min, created_max));
    return (c & ~remember_bit) | (if (remember) remember_bit else 0);
}

fn decodeCreated(word: u64) struct { created: i64, remember: bool } {
    // Sign-extend bit 62 into bit 63.
    const low = word & ~remember_bit;
    const ext = if (low & (1 << 62) != 0) low | remember_bit else low;
    return .{ .created = @bitCast(ext), .remember = word & remember_bit != 0 };
}

// ── clock injection (deterministic under test) ──────────────────────────────

/// Time source for timeout accounting (ns), injected so tests are
/// deterministic. Only differences matter, and the timestamps are stored in
/// the session record — so the clock must keep its origin for as long as a
/// record lives. `monotonic` does within one boot, which is all an in-process
/// store (`RamcacheStore`) needs; a store that survives a restart
/// (`KvStore`) needs `realtime`, and `Manager.init` refuses the pair
/// `monotonic` + persistent store.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) i64,

    /// The OS monotonic clock — the default, for in-process stores.
    pub const monotonic: Clock = .{ .nowFn = monotonicNowNs };

    /// `CLOCK_REALTIME` (ns since the Unix epoch) — for a persistent store.
    /// After a reboot the monotonic clock starts over near zero, so a record
    /// stamped before it would look created in the future and outlive its
    /// absolute timeout; wall time keeps the origin. A wall clock can be
    /// stepped (NTP): a step forward expires sessions early, a step back
    /// extends them by the step.
    pub const realtime: Clock = .{ .nowFn = realtimeNowNs };

    pub fn now(c: Clock) i64 {
        return c.nowFn(c.ctx);
    }
};

fn monotonicNowNs(_: ?*anyopaque) i64 {
    switch (builtin.os.tag) {
        .windows => {
            const windows = std.os.windows;
            var qpf: windows.LARGE_INTEGER = undefined;
            var qpc: windows.LARGE_INTEGER = undefined;
            if (!windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) return 0;
            if (!windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool()) return 0;
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

fn realtimeNowNs(_: ?*anyopaque) i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
}

// ── the Store interface ─────────────────────────────────────────────────────

pub const StoreError = error{OutOfMemory};

/// The generation (version) a store keeps per key for optimistic concurrency.
/// **0 means "no live record"** — absent or tombstoned. Every stored record
/// carries a generation `>= 1`, and *every* mutation (a CAS `put` or a
/// `delete`) bumps it, so a stale writer's expected generation can never match
/// the store again after any concurrent change to that key. This is the whole
/// mechanism behind the cross-request resurrection defense (see `Manager.save`
/// / `Manager.regenerate`).
pub const Generation = u64;

/// A record read from the store, tagged with the generation it was stored at.
/// The bytes are `gpa`-owned (caller frees).
pub const Loaded = struct {
    record: []u8,
    generation: Generation,
};

/// A key→record store the `Manager` persists sessions through. The record is
/// the opaque encoded session (`Manager` owns the layout); the store only
/// moves bytes and tracks a per-key `Generation` for compare-and-swap writes.
/// A default `RamcacheStore` is provided; a distributed backend (Redis, …) is
/// a future adapter implementing this same vtable (its `put` maps to a
/// CAS/Lua script or a `WATCH`/`MULTI` transaction on the generation).
pub const Store = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Return a `gpa`-owned copy of the live record under `id` and the
        /// generation it carries, or null when absent/tombstoned. A copy —
        /// not a borrow — because the backing store may mutate/evict the slot
        /// the moment the store's own lock is released.
        get: *const fn (ptr: *anyopaque, gpa: Allocator, id: []const u8) StoreError!?Loaded,
        /// **Compare-and-swap write.** Store `record` under `id` *iff* the
        /// generation the store currently holds for `id` equals `expected`
        /// (`expected == 0` is the create case: no live record must exist).
        /// The read-compare-write is atomic under the store's own lock.
        /// Returns the new, bumped generation on success, or **null** when the
        /// CAS fails because a concurrent request `put`/`delete`d `id` since
        /// `expected` was read — the stale write is then dropped, never
        /// applied. This is what makes a racing `save` unable to resurrect a
        /// session another request just destroyed or rotated.
        put: *const fn (ptr: *anyopaque, id: []const u8, record: []const u8, expected: Generation) ?Generation,
        /// Remove the record under `id` (idempotent) and **bump its
        /// generation** (leaving a tombstone that remembers the new
        /// generation) so any in-flight CAS `put` still holding the
        /// pre-delete generation fails closed — a delete always wins over a
        /// concurrent stale save.
        delete: *const fn (ptr: *anyopaque, id: []const u8) void,
        /// Optional enumeration of every live record: call `visit(ctx, id,
        /// loaded)` for each (`loaded.record` is borrowed for the call only;
        /// `id` is the store key, which under `Options.hash_id_in_store` is
        /// not the cookie id) and stop early when it returns false. Must not
        /// hold the store's lock across `visit` -- the callback may `delete`.
        /// Null = the store cannot enumerate (`Manager.iterate` then reports
        /// `error.Unsupported`).
        iterate: ?*const fn (ptr: *anyopaque, gpa: Allocator, ctx: ?*anyopaque, visit: *const fn (ctx: ?*anyopaque, id: []const u8, loaded: Loaded) bool) StoreError!void = null,
        /// The records outlive the process. `Manager.init` then refuses
        /// `Clock.monotonic`, whose origin a reboot resets (see `Clock`).
        persistent: bool = false,
    };

    pub fn get(s: Store, gpa: Allocator, id: []const u8) StoreError!?Loaded {
        return s.vtable.get(s.ptr, gpa, id);
    }
    /// CAS write; see `VTable.put`. Null ⇒ the caller's `expected` generation
    /// is stale (a concurrent writer won) and nothing was written.
    pub fn put(s: Store, id: []const u8, record: []const u8, expected: Generation) ?Generation {
        return s.vtable.put(s.ptr, id, record, expected);
    }
    pub fn delete(s: Store, id: []const u8) void {
        s.vtable.delete(s.ptr, id);
    }
    /// Enumerate the live records; see `VTable.iterate`.
    pub fn iterate(
        s: Store,
        gpa: Allocator,
        ctx: ?*anyopaque,
        visit: *const fn (ctx: ?*anyopaque, id: []const u8, loaded: Loaded) bool,
    ) error{ Unsupported, OutOfMemory }!void {
        const f = s.vtable.iterate orelse return error.Unsupported;
        return f(s.ptr, gpa, ctx, visit);
    }
};

/// The default `Store`, over a caller-owned `ramcache.Cache`. `ramcache` is
/// single-owner (`meta.concurrency = .single_owner`), so every touch is
/// serialized behind this store's **own** `std.atomic.Mutex` — making the
/// store safe from all of `http.Server`'s connection threads at once.
///
/// Optimistic concurrency: each cached value is framed as
/// `[generation u64 LE] ++ record`. A **tombstone** is the 8-byte generation
/// alone (no record); a live value is 8 + record bytes (a real record is
/// always ≥ `record_header_len`, so an 8-byte value is unambiguously a
/// tombstone). `get` reports a tombstone as absent but keeps the generation
/// so a `delete` can be *seen* by a racing `put`. `put` is a compare-and-swap
/// on that generation, done atomically under this store's lock. Because an
/// absent key reads as generation 0 and every live/tombstoned record is `>= 1`,
/// a stale `put` (whose `expected >= 1`) can never match even if the tombstone
/// is later LRU-evicted — the delete still wins. The tombstone occupies one
/// bounded cache slot (backstopped by `ttl_ns`) until overwritten or evicted.
pub const RamcacheStore = struct {
    cache: *ramcache.Cache,
    /// Time source handed to `ramcache` for its own TTL bookkeeping (the
    /// memory backstop; the `Manager` enforces the authoritative expiry).
    clock: Clock = .monotonic,
    /// `ramcache` TTL applied to every stored record (0 ⇒ evict by capacity
    /// only). A backstop so abandoned sessions don't pin memory forever.
    ttl_ns: i64 = default_absolute_timeout_ns,
    lock: std.atomic.Mutex = .unlocked,

    /// The `Store` view of this backend (per-instance state, no globals). The
    /// `RamcacheStore` must outlive the `Manager` using it, at a stable
    /// address.
    pub fn store(self: *RamcacheStore) Store {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Store.VTable = .{ .get = getImpl, .put = putImpl, .delete = deleteImpl };

    // Value framing: [generation u64 LE] ++ record.
    const gen_prefix_len = 8;

    /// Generation currently stored for `id` (0 = absent). Must be called with
    /// `self.lock` held. A value shorter than the generation prefix (should
    /// not occur; legacy/corrupt) reads as absent.
    fn currentGen(self: *RamcacheStore, id: []const u8, now: i64) Generation {
        const v = self.cache.get(id, now, 0) orelse return 0;
        if (v.len < gen_prefix_len) return 0;
        return std.mem.readInt(u64, v[0..gen_prefix_len], .little);
    }

    fn getImpl(ptr: *anyopaque, gpa: Allocator, id: []const u8) StoreError!?Loaded {
        const self: *RamcacheStore = @ptrCast(@alignCast(ptr));
        const now = self.clock.now();
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const v = self.cache.get(id, now, 0) orelse return null;
        if (v.len < gen_prefix_len) return null; // legacy/corrupt → absent
        const generation = std.mem.readInt(u64, v[0..gen_prefix_len], .little);
        if (v.len == gen_prefix_len) return null; // tombstone → no live record
        return .{ .record = try gpa.dupe(u8, v[gen_prefix_len..]), .generation = generation };
    }

    fn putImpl(ptr: *anyopaque, id: []const u8, record: []const u8, expected: Generation) ?Generation {
        const self: *RamcacheStore = @ptrCast(@alignCast(ptr));
        const now = self.clock.now();
        lockSpin(&self.lock);
        defer self.lock.unlock();
        // The compare of the CAS — atomic with the write below under the lock.
        if (self.currentGen(id, now) != expected) return null; // stale write dropped
        const next: Generation = expected + 1;
        var buf: [gen_prefix_len + record_header_len + max_session_bytes]u8 = undefined;
        if (record.len > buf.len - gen_prefix_len) return null; // never in practice
        std.mem.writeInt(u64, buf[0..gen_prefix_len], next, .little);
        @memcpy(buf[gen_prefix_len..][0..record.len], record);
        self.cache.put(id, buf[0 .. gen_prefix_len + record.len], now, self.ttl_ns, 0);
        return next;
    }

    fn deleteImpl(ptr: *anyopaque, id: []const u8) void {
        const self: *RamcacheStore = @ptrCast(@alignCast(ptr));
        const now = self.clock.now();
        lockSpin(&self.lock);
        defer self.lock.unlock();
        // Tombstone at a bumped generation so a concurrent stale `put` (which
        // holds the pre-delete generation) can no longer CAS-match — the
        // delete wins.
        const next: Generation = self.currentGen(id, now) + 1;
        var tomb: [gen_prefix_len]u8 = undefined;
        std.mem.writeInt(u64, tomb[0..gen_prefix_len], next, .little);
        self.cache.put(id, &tomb, now, self.ttl_ns, 0);
    }
};

/// A persistent `Store` over a caller-owned `kv.Db`: sessions survive a
/// restart of the server. Each record is stored under `prefix ++ id`, framed
/// `[generation u64 LE] ++ record` like `RamcacheStore`, with a `kv` expiry of
/// `ttl_ms` refreshed by every save — the backstop that removes abandoned
/// sessions, which `Manager` would otherwise only evict when their cookie
/// comes back. Expired records leave memory and disk at the `Db`'s next
/// `compact` (the caller's, as for any `kv` store) or reopen.
///
/// - **CAS:** read-compare-write under this store's own lock, as in
///   `RamcacheStore`. `delete` removes the key (no tombstone): an absent key
///   reads as generation 0 and every stale save expects `>= 1`, so a delete
///   still wins.
/// - **Cost:** every save and delete is a `kv` write + `fsync` under the
///   lock, and the middleware saves on every request that carries a session
///   (the rolling idle window). That caps session-carrying requests at the
///   disk's fsync rate — `kv` measured ~300/s appending on NVMe ext4.
/// - **Fail closed:** after any `kv` error on a write this store answers
///   every `get` with "absent" and refuses every `put`, until it is rebuilt
///   over a reopened `Db`. A failed `delete` (logout) must not leave the
///   session loadable, and `kv` itself refuses writes once poisoned.
/// - **Clock:** the manager over it must use `Clock.realtime` (enforced by
///   `Manager.init`). The `kv` expiry uses the `Db`'s own `Options.clock`.
pub const KvStore = struct {
    db: *kv.Db,
    prefix_buf: [max_prefix_len]u8 = undefined,
    prefix_len: usize = 0,
    ttl_ms: u64,
    /// Held across `Db` writes (an `fsync` each): an `std.Io.Mutex` when the
    /// `Db`'s storage has an `Io`, so a waiting task yields instead of
    /// spinning (see `kv.Lock`).
    lock: kv.Lock,
    failed: std.atomic.Value(bool) = .init(false),

    pub const max_prefix_len = 64;

    pub const Config = struct {
        /// Prepended to every session id, so the `Db` can hold other data
        /// too and `db.keys(gpa, prefix)` lists the sessions.
        prefix: []const u8 = "session:",
        /// `kv` expiry per record, refreshed by every save. It should cover
        /// the longest a session may live (the absolute timeout); 0 = none.
        ttl_ms: u64 = @intCast(@divTrunc(default_absolute_timeout_ns, std.time.ns_per_ms)),
    };

    pub fn init(db: *kv.Db, options: Config) error{PrefixTooLong}!KvStore {
        if (options.prefix.len > max_prefix_len) return error.PrefixTooLong;
        var self: KvStore = .{ .db = db, .ttl_ms = options.ttl_ms, .prefix_len = options.prefix.len, .lock = .{ .io = db.store.io } };
        @memcpy(self.prefix_buf[0..options.prefix.len], options.prefix);
        return self;
    }

    /// The `Store` view. The `KvStore` must outlive the `Manager` using it,
    /// at a stable address.
    pub fn store(self: *KvStore) Store {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// True once a `kv` write failed; from then on the store is closed.
    pub fn hasFailed(self: *const KvStore) bool {
        return self.failed.load(.acquire);
    }

    const vtable: Store.VTable = .{ .get = getImpl, .put = putImpl, .delete = deleteImpl, .iterate = iterateImpl, .persistent = true };

    const gen_prefix_len = 8;
    const KeyBuf = [max_prefix_len + 2 * max_id_bytes]u8;
    const ValueBuf = [gen_prefix_len + record_header_len + max_session_bytes]u8;

    /// `prefix ++ id` in `buf`, or null for an id no `Manager` mints.
    fn key(self: *const KvStore, buf: *KeyBuf, id: []const u8) ?[]const u8 {
        if (id.len > 2 * max_id_bytes) return null;
        @memcpy(buf[0..self.prefix_len], self.prefix_buf[0..self.prefix_len]);
        @memcpy(buf[self.prefix_len..][0..id.len], id);
        return buf[0 .. self.prefix_len + id.len];
    }

    /// The stored value under `k`, or null when absent, unreadable or not a
    /// framed record. Caller holds the lock.
    fn read(self: *KvStore, buf: *ValueBuf, k: []const u8) ?[]u8 {
        const v = (self.db.getBuf(buf, k) catch return null) orelse return null;
        if (v.len < gen_prefix_len + record_header_len) return null;
        return v;
    }

    fn getImpl(ptr: *anyopaque, gpa: Allocator, id: []const u8) StoreError!?Loaded {
        const self: *KvStore = @ptrCast(@alignCast(ptr));
        var kbuf: KeyBuf = undefined;
        const k = self.key(&kbuf, id) orelse return null;
        var vbuf: ValueBuf = undefined;
        self.lock.acquire();
        defer self.lock.release();
        if (self.hasFailed()) return null;
        const v = self.read(&vbuf, k) orelse return null;
        return .{
            .record = try gpa.dupe(u8, v[gen_prefix_len..]),
            .generation = std.mem.readInt(u64, v[0..gen_prefix_len], .little),
        };
    }

    fn putImpl(ptr: *anyopaque, id: []const u8, record: []const u8, expected: Generation) ?Generation {
        const self: *KvStore = @ptrCast(@alignCast(ptr));
        var kbuf: KeyBuf = undefined;
        const k = self.key(&kbuf, id) orelse return null;
        var vbuf: ValueBuf = undefined;
        if (record.len > vbuf.len - gen_prefix_len) return null; // never in practice
        self.lock.acquire();
        defer self.lock.release();
        if (self.hasFailed()) return null;
        // The compare of the CAS — atomic with the write below under the lock.
        const current: Generation = if (self.read(&vbuf, k)) |v| std.mem.readInt(u64, v[0..gen_prefix_len], .little) else 0;
        if (current != expected) return null; // stale write dropped
        const next: Generation = expected + 1;
        std.mem.writeInt(u64, vbuf[0..gen_prefix_len], next, .little);
        @memcpy(vbuf[gen_prefix_len..][0..record.len], record);
        const value = vbuf[0 .. gen_prefix_len + record.len];
        const written = if (self.ttl_ms == 0) self.db.put(k, value) else self.db.putTtl(k, value, self.ttl_ms);
        written catch {
            self.failed.store(true, .release);
            return null;
        };
        return next;
    }

    fn deleteImpl(ptr: *anyopaque, id: []const u8) void {
        const self: *KvStore = @ptrCast(@alignCast(ptr));
        var kbuf: KeyBuf = undefined;
        const k = self.key(&kbuf, id) orelse return;
        self.lock.acquire();
        defer self.lock.release();
        self.db.delete(k) catch self.failed.store(true, .release);
    }

    /// Every live session under this store's prefix: `db.keys` lists them
    /// (a snapshot), then each is read like `get` does. A key removed between
    /// the listing and its read, or not a framed record, is skipped. The lock
    /// is taken per read, never across `visit`, so the callback may `delete`.
    /// A closed (failed) store lists nothing.
    fn iterateImpl(
        ptr: *anyopaque,
        gpa: Allocator,
        ctx: ?*anyopaque,
        visit: *const fn (ctx: ?*anyopaque, id: []const u8, loaded: Loaded) bool,
    ) StoreError!void {
        const self: *KvStore = @ptrCast(@alignCast(ptr));
        if (self.hasFailed()) return;
        const listing = try self.db.keys(gpa, self.prefix_buf[0..self.prefix_len]);
        defer listing.deinit(gpa);
        for (listing.keys) |k| {
            const id = k[self.prefix_len..];
            const loaded = (try getImpl(ptr, gpa, id)) orelse continue;
            defer gpa.free(loaded.record);
            if (!visit(ctx, id, loaded)) return;
        }
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── the session ─────────────────────────────────────────────────────────────

/// One request's session: its id, timestamps and an inline application data
/// payload. Lives on the middleware's stack frame — valid for the handler call
/// only; `ctx.data` points at it and is restored afterwards. A handler reads
/// it via `sessionOf(ctx)`.
pub const Session = struct {
    /// Hex-encoded session id, backing storage.
    id_buf: [2 * max_id_bytes]u8 = undefined,
    id_len: usize = 0,
    /// When this session was first created (ns, injected clock).
    created_ns: i64 = 0,
    /// Last time it was seen (refreshed to "now" on load; drives idle expiry).
    last_seen_ns: i64 = 0,
    /// Inline application payload, backing storage.
    data_buf: [max_session_bytes]u8 = undefined,
    data_len: usize = 0,
    /// True for a session created this request (no prior cookie / expired).
    is_new: bool = true,
    /// The store generation this session was loaded at (`0` for a session that
    /// has never been persisted — a fresh `create` or the new id minted by
    /// `regenerate`). `save` CAS-writes against it: the write lands only if the
    /// store still holds this generation, so a save that raced a concurrent
    /// `destroy`/`regenerate` (which bumped the generation) is dropped instead
    /// of resurrecting the dead session. On a successful save it is advanced to
    /// the newly written generation.
    generation: Generation = 0,
    /// Set by `revoke()` — the middleware destroys instead of saving.
    revoked: bool = false,
    /// Set by `Manager.regenerate()` — the id in this `Session` has already
    /// been rotated (the old id killed in the store) during this request.
    /// The end-of-request save is still required (it persists the record
    /// and issues the cookie for the *new* id — nothing has saved that yet),
    /// but it can never resurrect the old id: `id()` already reflects the
    /// new one. Tracked explicitly (rather than left implicit) so the
    /// middleware's post-handler step is auditable and can't accidentally
    /// regress into re-saving under a stale id if it's ever refactored.
    regenerated: bool = false,
    /// Set by `setData` and `keep()` — the handler wants this session to
    /// exist. A new session nobody marked is not persisted at the end of the
    /// request (see `Options.persist_untouched_sessions`).
    kept: bool = false,
    /// The remember-me flag (`rememberMe`): with `Options.persist_cookie =
    /// false` it decides whether the cookie carries a `Max-Age`. Stored in the
    /// record, so it survives save/load.
    remember: bool = false,

    /// The hex-encoded session id (borrows this session's buffer).
    pub fn id(s: *const Session) []const u8 {
        return s.id_buf[0..s.id_len];
    }

    /// The application payload (borrows this session's buffer).
    pub fn data(s: *const Session) []const u8 {
        return s.data_buf[0..s.data_len];
    }

    /// Replace the application payload (copied inline). `error.Overflow` when
    /// it exceeds `max_session_bytes`.
    pub fn setData(s: *Session, bytes: []const u8) error{Overflow}!void {
        if (bytes.len > s.data_buf.len) return error.Overflow;
        @memcpy(s.data_buf[0..bytes.len], bytes);
        s.data_len = bytes.len;
        s.markModified();
    }

    /// The one place a mutation says "this session must be saved": every
    /// writer (`setData`, the values API, `rememberMe`) goes through it.
    fn markModified(s: *Session) void {
        s.kept = true;
    }

    // ── key/value + flash layer over the data blob ──────────────────────
    //
    // Encoding and rules: `values.zig`. This layer and raw `setData` share
    // one blob; mixing them on a session yields `error.Malformed` from here,
    // never a wrong value. scs analogues (alexedwards/scs v2.9.0 data.go):
    // Put 155, Get 175, Pop 188, Remove 207, Clear 225, Keys 256.

    /// (The parameter is `name`, not `key`: a value's name is no secret, and
    /// `check-secret-api` reads `key` as one.)
    ///
    /// The value stored under `name` (a slice into `data()`: invalidated by the
    /// next mutation), or null.
    pub fn getValue(s: *const Session, name: []const u8) error{Malformed}!?[]const u8 {
        return values.get(s.data(), name);
    }

    /// Store `val` under `name`, replacing a previous value in place or
    /// appending. `error.Overflow` when the blob would exceed
    /// `max_session_bytes`; `error.InvalidKey` for a name of 0 or more than 255
    /// bytes. Marks the session modified. On error nothing changes.
    pub fn putValue(s: *Session, name: []const u8, val: []const u8) ValueError!void {
        s.data_len = try values.put(max_session_bytes, &s.data_buf, s.data_len, name, val);
        s.markModified();
    }

    /// Remove `name`; true when it was there (and the session is then marked
    /// modified).
    pub fn removeValue(s: *Session, name: []const u8) error{Malformed}!bool {
        const r = try values.remove(&s.data_buf, s.data_len, name);
        if (!r.removed) return false;
        s.data_len = r.len;
        s.markModified();
        return true;
    }

    /// Flash message: copy the value of `name` into `buf`, then remove it.
    /// `error.BufferTooSmall` leaves the value in place. Null when absent.
    pub fn popValue(s: *Session, name: []const u8, buf: []u8) error{ Malformed, BufferTooSmall }!?[]u8 {
        const v = (try values.get(s.data(), name)) orelse return null;
        if (v.len > buf.len) return error.BufferTooSmall;
        const out = buf[0..v.len];
        @memcpy(out, v);
        _ = try s.removeValue(name);
        return out;
    }

    /// Entries in insertion order; the slices point into `data()`.
    pub fn valueIterator(s: *const Session) ValueIterator {
        return ValueIterator.init(s.data());
    }

    /// Drop every value (and any raw payload): `setData(&.{})`.
    pub fn clearValues(s: *Session) void {
        s.setData(&.{}) catch unreachable; // an empty payload always fits
    }

    /// Remember-me (scs `RememberMe`, data.go:534; `Cookie.Persist`,
    /// session.go:93-101): with `Options.persist_cookie = false` the session
    /// cookie is a browser-session cookie unless this is on. Stored with the
    /// session; marks it modified.
    pub fn rememberMe(s: *Session, on: bool) void {
        s.remember = on;
        s.markModified();
    }

    /// Persist this session at the end of the request even though the handler
    /// wrote no data — e.g. a login-form page that needs the session cookie so
    /// `Csrf` can issue a token bound to it. Without this (or `setData`), a
    /// session created for this request is dropped and no cookie is issued.
    pub fn keep(s: *Session) void {
        s.kept = true;
    }

    /// Mark the session for destruction (logout): the middleware evicts it
    /// from the store and expires the cookie instead of saving.
    pub fn revoke(s: *Session) void {
        s.revoked = true;
    }
};

/// Errors of the key/value layer (`Session.putValue`).
pub const ValueError = values.Error;
/// `Session.valueIterator`'s cursor: `next()` yields `{ key, val }` entries.
pub const ValueIterator = values.Iterator;

/// What `iterate`'s callback decides for the session it was just shown.
pub const IterateAction = enum {
    /// Leave it, go on to the next.
    keep,
    /// Remove it from the store (`Store.delete`: the generation is bumped,
    /// so a request already holding it cannot resurrect it), go on.
    destroy,
    /// End the enumeration here, leaving this session alone.
    stop,
};

/// The session the middleware attached to this request, or null when no
/// sessions middleware ran above the caller. Only meaningful below a
/// `Manager.middleware()` in the chain.
pub fn sessionOf(ctx: *const router.Ctx) ?*Session {
    const p = ctx.data orelse return null;
    return @ptrCast(@alignCast(p));
}

// ── the manager ─────────────────────────────────────────────────────────────

pub const Options = struct {
    /// CSPRNG source for session ids — threaded in once, exactly like
    /// `sealedbox`/`dns`/`http.Client`. Never `std.crypto.random` (removed in
    /// 0.16) and never a `DefaultPrng` (not cryptographically secure).
    io: std.Io,
    /// Injected clock for timeout accounting (a fake in tests).
    clock: Clock = .monotonic,
    /// Raw id length in bytes (hex-encoded to twice this in the cookie).
    /// `min_id_bytes`..=`max_id_bytes`; 32 (256 bits) is the OWASP-comfortable
    /// default. Values below `min_id_bytes` (128 bits) are rejected outright
    /// by `Manager.init` — anything smaller is brute-forceable.
    id_bytes: usize = 32,
    /// Reject a session unused for longer than this (rolling). 0 disables.
    idle_timeout_ns: i64 = default_idle_timeout_ns,
    /// Reject a session older than this regardless of activity. 0 disables.
    absolute_timeout_ns: i64 = default_absolute_timeout_ns,
    /// Session cookie name.
    cookie_name: []const u8 = default_cookie_name,
    /// Cookie `Path` (null ⇒ omit).
    cookie_path: ?[]const u8 = "/",
    /// Cookie `Domain` (null ⇒ omit; host-only cookie).
    cookie_domain: ?[]const u8 = null,
    /// `SameSite` attribute (default `.lax` — sane CSRF baseline).
    same_site: cookies.SameSite = .lax,
    /// Emit `Secure` (HTTPS-only). Default true; drop it only via
    /// `allow_insecure_cookie` for a plain-HTTP dev server.
    secure: bool = true,
    /// Explicit escape hatch: when true, omit `Secure` even though `secure`
    /// asks for it — the documented dev-only opt-out.
    allow_insecure_cookie: bool = false,
    /// When false (default), the middleware does not persist a session it
    /// created for this request unless the handler called `setData`, `keep`
    /// or `Manager.regenerate` — so cookieless traffic cannot fill a bounded
    /// store and evict live sessions. True restores "every request that
    /// arrives without a session gets one stored and a cookie issued".
    persist_untouched_sessions: bool = false,
    /// true (default, today's behaviour): the session cookie always carries
    /// `Max-Age` (rolling idle window). false: a browser-session cookie (no
    /// `Max-Age`) unless the session called `rememberMe(true)` -- scs
    /// `Cookie.Persist` (session.go:93-101, 211). The clearing cookie
    /// (`Max-Age=-1` on destroy) is unaffected. The server-side idle/absolute
    /// timeouts apply either way.
    persist_cookie: bool = true,
    /// false (default): the store is keyed by the session id itself. true: by
    /// `SHA-256(id)` (32 raw bytes) -- a leaked or read-only-readable store
    /// then does not hand out live session ids (scs `HashTokenInStore`,
    /// data.go:627-630, applied at 646-683). The cookie and `Csrf` keep using
    /// the real id. Changing it on a populated store logs everyone out.
    /// `Manager.iterate` then shows the store key as `Session.id()`.
    hash_id_in_store: bool = false,
};

/// The session manager: immutable config + the middleware over a `Store`.
/// Build one, share it across threads; the `Store` it points at must outlive
/// it, at a stable address.
pub const Manager = struct {
    store: Store,
    gpa: Allocator,
    io: std.Io,
    clock: Clock,
    id_bytes: usize,
    idle_timeout_ns: i64,
    absolute_timeout_ns: i64,
    cookie_name: []const u8,
    cookie_path: ?[]const u8,
    cookie_domain: ?[]const u8,
    same_site: cookies.SameSite,
    secure: bool,
    persist_untouched_sessions: bool,
    persist_cookie: bool,
    hash_id_in_store: bool,

    /// Build a manager. `gpa` is used only for the short-lived decode copies
    /// `Store.get` hands back (the store owns its own storage).
    ///
    /// Rejects `id_bytes` outside `[min_id_bytes, max_id_bytes]` and an empty
    /// `cookie_name`. This used to be two `std.debug.assert`s while the docs
    /// said "rejects anything below this" — and `std.debug.assert` is
    /// compiled out in ReleaseFast, which is a mode this module's own suite
    /// runs in. Both halves of the range mattered: below the floor the
    /// release build silently minted brute-forceable session ids (the very
    /// thing the floor exists to prevent), and above the ceiling `newId`
    /// wrote `id_bytes` random bytes into its `[max_id_bytes]u8` stack array
    /// and `id_bytes * 2` hex digits into a fixed `id_buf`, then handed the
    /// out-of-bounds slice to the store and the `Set-Cookie` header.
    pub const InitError = error{
        /// `id_bytes` is below `min_id_bytes` (brute-forceable ids) or above
        /// `max_id_bytes` (overflows the id buffers).
        InvalidIdBytes,
        EmptyCookieName,
        /// `Clock.monotonic` over a store whose records outlive the process:
        /// after a reboot every stored timestamp would lie in the "future"
        /// and no session would reach its timeouts. Use `Clock.realtime`.
        MonotonicClockWithPersistentStore,
    };

    pub fn init(gpa: Allocator, store: Store, options: Options) InitError!Manager {
        if (options.id_bytes < min_id_bytes or options.id_bytes > max_id_bytes)
            return error.InvalidIdBytes;
        if (options.cookie_name.len == 0) return error.EmptyCookieName;
        if (store.vtable.persistent and options.clock.nowFn == Clock.monotonic.nowFn)
            return error.MonotonicClockWithPersistentStore;
        return .{
            .store = store,
            .gpa = gpa,
            .io = options.io,
            .clock = options.clock,
            .id_bytes = options.id_bytes,
            .idle_timeout_ns = options.idle_timeout_ns,
            .absolute_timeout_ns = options.absolute_timeout_ns,
            .cookie_name = options.cookie_name,
            .cookie_path = options.cookie_path,
            .cookie_domain = options.cookie_domain,
            .same_site = options.same_site,
            .secure = options.secure and !options.allow_insecure_cookie,
            .persist_untouched_sessions = options.persist_untouched_sessions,
            .persist_cookie = options.persist_cookie,
            .hash_id_in_store = options.hash_id_in_store,
        };
    }

    /// Initialize `out` as a brand-new session: a fresh CSPRNG id, `created`
    /// and `last_seen` = now, empty payload.
    pub fn create(m: *const Manager, out: *Session) void {
        out.* = .{};
        m.newId(out);
        const now = m.clock.now();
        out.created_ns = now;
        out.last_seen_ns = now;
        out.is_new = true;
    }

    /// Outcome of `load`.
    pub const LoadResult = enum {
        /// A live session was decoded into `out`.
        loaded,
        /// No session cookie, or its record is gone/corrupt — `out` untouched.
        absent,
        /// A session existed but is past its idle/absolute timeout; it has
        /// been evicted and `out` is untouched.
        expired,
    };

    /// Load the session named by the request cookie into `out`. Rejects (and
    /// evicts) one past its idle or absolute timeout. On `.loaded`,
    /// `out.last_seen_ns` is refreshed to now (rolling idle window).
    pub fn load(m: *const Manager, req: *const http.Server.Request, out: *Session) LoadResult {
        const sid = cookies.get(req, m.cookie_name) orelse return .absent;
        return m.lookup(sid, out);
    }

    /// Load a session by its (already-extracted) id — the core of `load`,
    /// usable without an `http.Server.Request`.
    pub fn lookup(m: *const Manager, sid: []const u8, out: *Session) LoadResult {
        if (sid.len == 0 or sid.len > out.id_buf.len) return .absent;
        var key_buf: [store_key_max]u8 = undefined;
        const key = m.storeKey(&key_buf, sid);
        const loaded = (m.store.get(m.gpa, key) catch return .absent) orelse return .absent;
        defer m.gpa.free(loaded.record);
        const now = m.clock.now();
        switch (m.decode(key, loaded, out, now)) {
            .loaded => {
                // `decode` took the id from the store key; a cookie lookup
                // wants the real id (they differ under `hash_id_in_store`).
                @memcpy(out.id_buf[0..sid.len], sid);
                out.id_len = sid.len;
                out.last_seen_ns = now; // refresh idle window
                return .loaded;
            },
            .absent => return .absent,
            .expired => {
                m.store.delete(key);
                return .expired;
            },
        }
    }

    /// Decode a store record into `out` (id = the store `key` as given,
    /// `last_seen_ns` as stored) or say why not. Shared by `lookup` and
    /// `iterate`; deletes nothing.
    fn decode(m: *const Manager, key: []const u8, loaded: Loaded, out: *Session, now: i64) LoadResult {
        if (key.len == 0 or key.len > out.id_buf.len) return .absent;
        const rec = loaded.record;
        if (rec.len < record_header_len) return .absent; // corrupt
        const word = decodeCreated(std.mem.readInt(u64, rec[0..8], .little));
        const created = word.created;
        const last_seen = std.mem.readInt(i64, rec[8..16], .little);
        const payload = rec[record_header_len..];
        if (payload.len > out.data_buf.len) return .absent; // corrupt / oversized

        if (m.absolute_timeout_ns > 0 and now -| created > m.absolute_timeout_ns) return .expired;
        if (m.idle_timeout_ns > 0 and now -| last_seen > m.idle_timeout_ns) return .expired;

        out.* = .{};
        @memcpy(out.id_buf[0..key.len], key);
        out.id_len = key.len;
        out.created_ns = created;
        out.last_seen_ns = last_seen;
        out.remember = word.remember;
        @memcpy(out.data_buf[0..payload.len], payload);
        out.data_len = payload.len;
        out.is_new = false;
        out.generation = loaded.generation; // for the save-time CAS
        return .loaded;
    }

    /// Backing for a hashed key.
    const store_key_max = 32;

    /// The key `id` (a cookie value) is stored under: the id itself, or its
    /// SHA-256 as 32 raw bytes under `hash_id_in_store` (both `RamcacheStore`
    /// and `KvStore` take arbitrary key bytes). `buf` backs a hashed result.
    fn storeKey(m: *const Manager, buf: *[store_key_max]u8, id: []const u8) []const u8 {
        if (!m.hash_id_in_store) return id;
        std.crypto.hash.sha2.Sha256.hash(id, buf, .{});
        return buf;
    }

    /// Persist `s` to the store and stamp a refreshed `Set-Cookie`. Called by
    /// the middleware after the handler.
    ///
    /// The store write is a **compare-and-swap** against the generation the
    /// session was loaded at (see `persist`): if a *concurrent* request
    /// destroyed (`revoke`/`destroy`) or rotated (`regenerate`) this session
    /// since it was loaded — the harder cross-request resurrection race — the
    /// CAS fails, the store is left untouched (the session stays dead/rotated),
    /// and **no rolling cookie is issued** (fail closed). Only on a successful
    /// CAS is the refreshed `Set-Cookie` stamped.
    ///
    /// Best-effort on the cookie even on success: if the handler already
    /// flushed the response head (a large streamed body), the store is updated
    /// but the cookie can't be (re)issued this response — a documented limit
    /// for new sessions behind an early flush.
    pub fn save(m: *const Manager, res: *http.Server.ResponseWriter, s: *Session) void {
        if (m.persist(s)) {
            const max_age: ?i64 = if (m.persist_cookie or s.remember) maxAgeSeconds(m.idle_timeout_ns) else null;
            m.writeCookie(res, s.id(), max_age);
        }
        // else: a concurrent destroy/regenerate/newer-write won the CAS — the
        // stale save is a no-op and issues no cookie. The session remains what
        // the winning request made it; the browser keeps its current cookie and
        // the next request re-resolves it (absent after a logout ⇒ fresh login).
    }

    /// The store side of `save`: a **compare-and-swap** that writes this
    /// session's record only if the store still holds the generation it was
    /// loaded at (`s.generation`). Returns `true` and advances `s.generation`
    /// to the newly written generation on success; returns `false` (a no-op)
    /// when a concurrent request modified or deleted the record since it was
    /// loaded — the stale write is dropped, never resurrecting a logged-out or
    /// rotated session. Split out from `save` so the CAS is unit-testable
    /// without a `ResponseWriter`; a handler may also call it to force a
    /// mid-request persist and observe whether it won the race.
    pub fn persist(m: *const Manager, s: *Session) bool {
        s.last_seen_ns = m.clock.now();
        var buf: [record_header_len + max_session_bytes]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], encodeCreated(s.created_ns, s.remember), .little);
        std.mem.writeInt(i64, buf[8..16], s.last_seen_ns, .little);
        @memcpy(buf[record_header_len..][0..s.data_len], s.data());
        var key_buf: [store_key_max]u8 = undefined;
        const new_gen = m.store.put(m.storeKey(&key_buf, s.id()), buf[0 .. record_header_len + s.data_len], s.generation) orelse return false;
        s.generation = new_gen;
        return true;
    }

    /// Evict the session from the store and overwrite the cookie with
    /// `Max-Age=-1` (logout). Best-effort on the cookie (see `save`).
    ///
    /// **Called by the middleware itself** when the handler set
    /// `Session.revoke()` on the request's own session — that is the
    /// supported way for a handler to log the current request out. Calling
    /// `destroy` directly from a handler on the *current request's own*
    /// session id is a footgun: the middleware doesn't know about it (only
    /// `s.revoked` is consulted post-handler) and would still run `save`
    /// at request end, re-`put`ting the just-destroyed record right back and
    /// overwriting this `Max-Age=-1` cookie with a fresh, valid one. Use
    /// this directly only to destroy a *different* session's id (e.g. an
    /// admin ending someone else's session, or "log out my other devices").
    pub fn destroy(m: *const Manager, res: *http.Server.ResponseWriter, sid: []const u8) void {
        var key_buf: [store_key_max]u8 = undefined;
        m.store.delete(m.storeKey(&key_buf, sid));
        m.writeCookie(res, "", -1);
    }

    /// Rotate the session id, carrying the data over and killing the old id in
    /// the store — the session-fixation defense (call it right after a
    /// privilege change, e.g. login). The old id is `delete`d (its generation
    /// bumped to a tombstone, so a *concurrent* request still holding the old
    /// id can no longer CAS a stale record back over it — the rotation wins
    /// the cross-request race). The new id is persisted on the next `save`
    /// (the middleware's post-handler save covers it): `s.generation` is reset
    /// to 0 because the new id has never been stored, so that save is a
    /// *create* CAS (expected generation 0) against a fresh id — it can only
    /// persist the new record, never the old, just-deleted one. `s.regenerated`
    /// is set so that invariant is explicit rather than implicit in `id()`'s
    /// side effect.
    pub fn regenerate(m: *const Manager, s: *Session) void {
        var key_buf: [store_key_max]u8 = undefined;
        m.store.delete(m.storeKey(&key_buf, s.id())); // old id dead in the store (generation bumped)
        m.newId(s); // overwrite id; created + data preserved
        s.generation = 0; // the new id is unstored ⇒ next save is a create-CAS
        s.regenerated = true;
    }

    /// Enumerate every live session and let `f` keep, destroy or stop at each
    /// (scs `Iterate`, data.go:541-569, with memstore `All`): logout-everywhere
    /// for a user whose id the app stored in the session is one pass --
    /// `getValue("uid")`, compare, `.destroy`. Returns how many were destroyed.
    ///
    /// A record past its idle or absolute timeout is skipped (`f` is not
    /// called). `s` is decoded like `lookup` does and is valid for the call
    /// only; **`s.id()` is the store key** -- the cookie id, unless
    /// `Options.hash_id_in_store`, when it is `SHA-256(id)` as raw bytes and
    /// must not be treated as a cookie value. `error.Unsupported` when the store
    /// cannot enumerate (`RamcacheStore` has no entry iterator; `KvStore` can).
    pub fn iterate(
        m: *const Manager,
        gpa: Allocator,
        ctx: ?*anyopaque,
        f: *const fn (ctx: ?*anyopaque, s: *const Session) IterateAction,
    ) error{ Unsupported, OutOfMemory }!usize {
        var st: IterateState = .{ .m = m, .ctx = ctx, .f = f };
        try m.store.iterate(gpa, &st, IterateState.visit);
        return st.destroyed;
    }

    const IterateState = struct {
        m: *const Manager,
        ctx: ?*anyopaque,
        f: *const fn (ctx: ?*anyopaque, s: *const Session) IterateAction,
        destroyed: usize = 0,

        fn visit(state: ?*anyopaque, id: []const u8, loaded: Loaded) bool {
            const st: *IterateState = @ptrCast(@alignCast(state.?));
            var s: Session = undefined;
            if (st.m.decode(id, loaded, &s, st.m.clock.now()) != .loaded) return true;
            switch (st.f(st.ctx, &s)) {
                .keep => {},
                .destroy => {
                    st.m.store.delete(id);
                    st.destroyed += 1;
                },
                .stop => return false,
            }
            return true;
        }
    };

    /// A `router.Middleware` that loads-or-creates the session, attaches it to
    /// `ctx.data`, runs the chain, then saves (or destroys, if revoked).
    /// Register it once, before routes; the Manager must outlive the Router.
    pub fn middleware(m: *Manager) router.Middleware {
        return .{ .state = m, .run = middlewareRun };
    }

    // ── internals ───────────────────────────────────────────────────────

    fn newId(m: *const Manager, out: *Session) void {
        var raw: [max_id_bytes]u8 = undefined;
        const slice = raw[0..m.id_bytes];
        // The id is the bearer token: guessing one IS the session. Fails
        // closed — `newId` returns void (it is reached from `middleware`,
        // which cannot fail either), so there is no way to report a
        // degraded draw and every id after it would be forgeable.
        entropy.fill(m.io, slice);
        // Branch- and table-free: a `"0123456789abcdef"[b >> 4]` lookup
        // indexes memory by the secret id (ctgrind `sessions/newid`).
        idhex.encode(out.id_buf[0 .. 2 * slice.len], slice);
        out.id_len = m.id_bytes * 2;
    }

    fn writeCookie(m: *const Manager, res: *http.Server.ResponseWriter, value: []const u8, max_age: ?i64) void {
        const sc: cookies.SetCookie = .{
            .name = m.cookie_name,
            .value = value,
            .path = m.cookie_path,
            .domain = m.cookie_domain,
            .max_age = max_age,
            .secure = m.secure,
            .http_only = true,
            .same_site = m.same_site,
        };
        // addSetCookie copies the bytes into the writer's own header_buf
        // before returning, so this local only has to outlive the call.
        // Sized for name + 2*max_id_bytes hex + every attribute.
        var cookie_buf: [512]u8 = undefined;
        const v = sc.bufPrint(&cookie_buf) catch return; // too long / invalid → skip
        // Best-effort across the WHOLE of `SetHeaderError`, not just the
        // `HeadersSent` this comment used to name — `addSetCookie` also
        // returns `HeaderBytesExhausted` (a handler that spent the writer's
        // 4 KiB copy budget), `TooManyHeaders` and `InvalidHeader`.
        //
        // Deliberate, and the reason is that every one of them fails CLOSED.
        // `save` has already persisted the record and `destroy` has already
        // deleted it, so the store is authoritative either way: a lost
        // rolling refresh leaves the browser's current cookie working; a lost
        // new-session cookie means the browser simply has none and the user
        // is not logged in; a lost `Max-Age=-1` clearing cookie is harmless
        // because the record behind it is already gone, so the stale cookie
        // resolves to nothing on the next request. No case leaves a user
        // holding authority they should not have.
        //
        // `save`/`destroy` are `pub fn … void` with best-effort in their
        // contracts, so this is stated here rather than escalated.
        res.addSetCookie(v) catch {};
    }
};

fn maxAgeSeconds(idle_ns: i64) i64 {
    if (idle_ns <= 0) return default_absolute_timeout_ns / std.time.ns_per_s;
    return @divTrunc(idle_ns, std.time.ns_per_s);
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const m: *Manager = @ptrCast(@alignCast(state.?));

    var s: Session = .{};
    switch (m.load(ctx.req, &s)) {
        .loaded => {},
        .absent, .expired => m.create(&s),
    }

    const saved = ctx.data;
    ctx.data = &s;
    defer ctx.data = saved;

    try next.run(ctx); // handler error → propagate, no save (nothing persisted)

    // `s.revoked` (set by `Session.revoke()`) means the handler asked to log
    // this session out: destroy it, and — critically — do NOT also save,
    // which would immediately re-`put` the record right back and overwrite
    // the `Max-Age=-1` cookie with a fresh valid one, undoing the logout.
    //
    // Otherwise, `save` runs unconditionally, including when
    // `s.regenerated` (set by `Manager.regenerate()`) is true: that's safe,
    // not a resurrection, because `s.id()` already reflects the *new* id at
    // this point (`regenerate` overwrote it) and the *old* id was already
    // deleted from the store — this save can only persist the new record
    // and issue the cookie for the new id, which is required (nothing else
    // does it) and never touches the old, dead id.
    //
    // A session created for this request that the handler never marked
    // (`setData`/`keep`/`regenerate`) is dropped: storing one per cookieless
    // request lets anonymous traffic fill a bounded store and evict the live
    // sessions of other users (A1 sessions LOW#1).
    if (s.revoked) {
        m.destroy(ctx.res, s.id());
    } else if (s.is_new and !s.kept and !s.regenerated and !m.persist_untouched_sessions) {
        // nothing to persist, no cookie to issue
    } else {
        m.save(ctx.res, &s);
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

test {
    _ = csrf;
    _ = idhex;
    _ = values;
    _ = @import("stackprobe_test.zig");
}

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// A manual clock so timeout tests are deterministic.
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

fn newCache() ramcache.Cache {
    return ramcache.Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 256 });
}

/// Shared test scaffold: a cache, a RamcacheStore over it, and a manual clock.
const Env = struct {
    cache: ramcache.Cache,
    store: RamcacheStore = undefined,
    clk: ManualClock = .{ .now_ns = 1000 },

    fn init() Env {
        return .{ .cache = newCache() };
    }
    fn wire(e: *Env) void {
        e.store = .{ .cache = &e.cache, .clock = e.clk.clock() };
    }
    fn deinit(e: *Env) void {
        e.cache.deinit();
    }
    fn manager(e: *Env, opts: struct { idle: i64 = 0, absolute: i64 = 0, persist_untouched: bool = false }) !Manager {
        return try Manager.init(testing.allocator, e.store.store(), .{
            .io = testing.io, // real CSPRNG-backed test Io
            .clock = e.clk.clock(),
            .idle_timeout_ns = opts.idle,
            .absolute_timeout_ns = opts.absolute,
            .persist_untouched_sessions = opts.persist_untouched,
        });
    }
};

/// Persist a session straight into the store (bypasses the cookie writer).
/// A create-CAS (expected generation 0) — the seeded id is fresh in the store.
fn seed(m: *const Manager, s: *const Session) void {
    var buf: [record_header_len + max_session_bytes]u8 = undefined;
    std.mem.writeInt(i64, buf[0..8], s.created_ns, .little);
    std.mem.writeInt(i64, buf[8..16], s.last_seen_ns, .little);
    @memcpy(buf[record_header_len..][0..s.data_len], s.data());
    _ = m.store.put(s.id(), buf[0 .. record_header_len + s.data_len], 0);
}

test "create → seed → lookup round-trips id and data" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });

    var s: Session = .{};
    m.create(&s);
    try testing.expect(s.is_new);
    try testing.expectEqual(@as(usize, 64), s.id_len); // 32 raw bytes → 64 hex
    try s.setData("cart=3");
    const id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(id);
    seed(&m, &s);

    var loaded: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &loaded));
    try testing.expectEqualStrings(id, loaded.id());
    try testing.expectEqualStrings("cart=3", loaded.data());
    try testing.expect(!loaded.is_new);
}

test "forged / unknown session id → absent" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });

    var loaded: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup("deadbeefdeadbeefdeadbeefdeadbeef", &loaded));
}

test "expired session (idle window) → expired + evicted" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 500, .absolute = 100_000 });

    var s: Session = .{};
    m.create(&s);
    const id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(id);
    seed(&m, &s);

    // Within the idle window → loaded.
    env.clk.now_ns = 1400;
    var l1: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l1));

    // Past the idle window (from the original last_seen=1000) → expired…
    env.clk.now_ns = 2000;
    var l2: Session = .{};
    try testing.expectEqual(Manager.LoadResult.expired, m.lookup(id, &l2));
    // …and it was evicted, so a re-load finds nothing.
    var l3: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(id, &l3));
}

test "expired session (absolute cap) → expired even when recently active" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 1_000_000, .absolute = 5_000 });

    var s: Session = .{};
    m.create(&s); // created + last_seen = 1000
    const id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(id);
    seed(&m, &s);

    // Idle window huge, but past the absolute cap (created 1000 + 5000).
    env.clk.now_ns = 7000;
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.expired, m.lookup(id, &l));
}

test "regenerate: new id, data carried, old id dead (fixation defense)" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });

    var s: Session = .{};
    m.create(&s);
    try s.setData("uid=42");
    const old_id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(old_id);
    seed(&m, &s);

    m.regenerate(&s);
    try testing.expect(!std.mem.eql(u8, old_id, s.id())); // id rotated
    try testing.expectEqualStrings("uid=42", s.data()); // data carried

    // Old id is dead in the store.
    var lo: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(old_id, &lo));
}

test "cross-request race: a stale save cannot resurrect a session destroyed by a concurrent request" {
    // The hard cross-request resurrection race. Two genuinely concurrent
    // requests share one cookie (same id). Request B is mid-handler holding a
    // private copy when request A logs out (destroy ⇒ store delete). At
    // end-of-request B unconditionally saves. The generation CAS must reject
    // B's stale save so the logged-out session stays dead — a delete wins.
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });

    var s: Session = .{};
    m.create(&s);
    try s.setData("uid=7");
    const id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(id);
    seed(&m, &s); // store holds `id` at generation 1

    // Both in-flight requests load the SAME id → private copies at the same
    // generation.
    var a: Session = .{};
    var b: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &a));
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &b));
    try testing.expectEqual(a.generation, b.generation);

    // A logs out — the store effect of destroy()/revoke (bumps to a tombstone).
    m.store.delete(a.id());

    // B's trailing save races in with its stale generation → CAS FAILS (no-op).
    try testing.expect(!m.persist(&b));

    // The session stays dead: B did not resurrect it.
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(id, &l));
}

test "cross-request race: a stale save cannot resurrect a session rotated by a concurrent regenerate" {
    // Same race, regenerate half: A rotates the id (session-fixation defense)
    // while B holds a stale copy of the old id. B's trailing save must not
    // revive the old, just-rotated id — the regenerate wins.
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });

    var s: Session = .{};
    m.create(&s);
    try s.setData("uid=7");
    const old_id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(old_id);
    seed(&m, &s); // store holds old_id at generation 1

    var a: Session = .{};
    var b: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(old_id, &a));
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(old_id, &b));

    // A regenerates: old_id killed (generation bumped), a new id on A's copy.
    m.regenerate(&a);
    try testing.expect(!std.mem.eql(u8, old_id, a.id()));

    // B's trailing save still targets old_id at the stale generation → FAILS.
    try testing.expect(!m.persist(&b));

    // Old id stays dead — not revived by B's stale save.
    var lo: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(old_id, &lo));

    // A's own end-of-request save persists the NEW id (a create-CAS succeeds),
    // carrying the data over.
    try testing.expect(m.persist(&a));
    var ln: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(a.id(), &ln));
    try testing.expectEqualStrings("uid=7", ln.data());
}

test "single-owner save succeeds and bumps the generation; a second concurrent stale save no-ops" {
    // The legitimate flow still works, and the CAS-failure policy for two
    // concurrent DATA writes to a *live* session is first-writer-wins (the
    // stale second save is dropped, not resurrecting/clobbering — last-write-
    // wins is not required, only that a delete/rotate can't be undone).
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });

    var s: Session = .{};
    m.create(&s);
    const id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(id);
    seed(&m, &s); // generation 1

    // Legitimate single owner: load, modify, save → succeeds and bumps gen.
    var a: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &a));
    const g0 = a.generation;
    try a.setData("v=1");
    try testing.expect(m.persist(&a));
    try testing.expect(a.generation > g0); // generation advanced

    // Two concurrent data writes: both load the same generation; the first
    // save wins, the now-stale second is a no-op.
    var b: Session = .{};
    var c: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &b));
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &c));
    try b.setData("v=2");
    try c.setData("v=3");
    try testing.expect(m.persist(&b)); // wins
    try testing.expect(!m.persist(&c)); // stale → dropped

    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
    try testing.expectEqualStrings("v=2", l.data()); // b's write survived, not c's
}

// ── KvStore ─────────────────────────────────────────────────────────────────

/// A `kv` wall clock (ms) the test moves by hand.
const ManualKvClock = struct {
    now_ms: i64 = 1_000_000,
    fn clock(mc: *ManualKvClock) kv.Clock {
        return .{ .ctx = mc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const mc: *ManualKvClock = @ptrCast(@alignCast(ctx.?));
        return mc.now_ms;
    }
};

/// A simulated disk, a `kv.Db` on it, a `KvStore` over that and a manager.
/// `restart` closes and reopens the `Db` on the same simulated disk.
const KvEnv = struct {
    sim: kv.SimStorage,
    db: kv.Db = undefined,
    store: KvStore = undefined,
    kv_clk: ManualKvClock = .{},
    clk: ManualClock = .{ .now_ns = 1000 },

    const path = "sessions.kv";

    fn init(e: *KvEnv) !void {
        e.* = .{ .sim = kv.SimStorage.init(testing.allocator) };
        try e.open();
    }
    fn open(e: *KvEnv) !void {
        e.db = try kv.Db.open(testing.allocator, e.sim.storage(), path, .{ .clock = e.kv_clk.clock() });
        e.store = try KvStore.init(&e.db, .{ .ttl_ms = 60_000 });
    }
    fn restart(e: *KvEnv) !void {
        e.db.close();
        try e.open();
    }
    fn deinit(e: *KvEnv) void {
        e.db.close();
        e.sim.deinit();
    }
    fn manager(e: *KvEnv) !Manager {
        return try Manager.init(testing.allocator, e.store.store(), .{
            .io = testing.io,
            .clock = e.clk.clock(),
            .idle_timeout_ns = 10_000,
            .absolute_timeout_ns = 100_000,
        });
    }
    fn storeKey(e: *KvEnv, buf: *KvStore.KeyBuf, id: []const u8) []const u8 {
        return e.store.key(buf, id).?;
    }
};

test "KvStore: sessions survive a restart of the store" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    var s: Session = .{};
    const id = blk: {
        var m = try env.manager();
        m.create(&s);
        try s.setData("uid=42");
        try testing.expect(m.persist(&s));
        try testing.expect(m.persist(&s)); // generation 2
        break :blk try testing.allocator.dupe(u8, s.id());
    };
    defer testing.allocator.free(id);

    try env.restart(); // the server process comes back
    var m = try env.manager();
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
    try testing.expectEqualStrings("uid=42", l.data());
    try testing.expectEqual(s.created_ns, l.created_ns);
    try testing.expectEqual(@as(Generation, 2), l.generation);
    // The CAS carries on from the stored generation.
    try testing.expect(m.persist(&l));
    try testing.expectEqual(@as(Generation, 3), l.generation);
}

test "KvStore: a stale save cannot resurrect a destroyed or rotated session; first writer wins" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    var m = try env.manager();

    // Destroy wins.
    var s: Session = .{};
    m.create(&s);
    try s.setData("uid=7");
    try testing.expect(m.persist(&s));
    var b: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(s.id(), &b));
    m.store.delete(s.id());
    try testing.expect(!m.persist(&b));
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(s.id(), &l));
    // The delete reached the disk: gone after a restart too.
    const dead_id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(dead_id);
    try env.restart();
    m = try env.manager();
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(dead_id, &l));

    // Regenerate wins.
    var r: Session = .{};
    m.create(&r);
    try testing.expect(m.persist(&r));
    const old_id = try testing.allocator.dupe(u8, r.id());
    defer testing.allocator.free(old_id);
    var stale: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(old_id, &stale));
    m.regenerate(&r);
    try testing.expect(!m.persist(&stale));
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(old_id, &l));
    try testing.expect(m.persist(&r));
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(r.id(), &l));

    // Two data writes from the same generation: the first wins.
    var c1: Session = .{};
    var c2: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(r.id(), &c1));
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(r.id(), &c2));
    try c1.setData("v=1");
    try c2.setData("v=2");
    try testing.expect(m.persist(&c1));
    try testing.expect(!m.persist(&c2));
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(r.id(), &l));
    try testing.expectEqualStrings("v=1", l.data());
}

test "KvStore: every save refreshes the kv expiry backstop; an abandoned session goes away" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    var m = try env.manager();
    var s: Session = .{};
    m.create(&s);
    try testing.expect(m.persist(&s));
    var kbuf: KvStore.KeyBuf = undefined;
    const k = env.storeKey(&kbuf, s.id());
    try testing.expectEqual(kv.Expiry{ .at_ms = env.kv_clk.now_ms + 60_000 }, env.db.expiresAt(k).?);

    env.kv_clk.now_ms += 30_000;
    try testing.expect(m.persist(&s)); // a request came: the backstop moves
    try testing.expectEqual(kv.Expiry{ .at_ms = env.kv_clk.now_ms + 60_000 }, env.db.expiresAt(k).?);

    env.kv_clk.now_ms += 60_000; // abandoned: its cookie never came back
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(s.id(), &l));
    try env.db.compact();
    try testing.expectEqual(@as(usize, 0), env.db.count());
    try testing.expect(!env.db.keydir.contains(k));

    // ttl_ms = 0: no expiry at all.
    env.store = try KvStore.init(&env.db, .{ .ttl_ms = 0 });
    m = try env.manager();
    m.create(&s);
    try testing.expect(m.persist(&s));
    try testing.expectEqual(kv.Expiry.never, env.db.expiresAt(env.storeKey(&kbuf, s.id())).?);
}

test "KvStore: a failed kv write closes the store (a logout that did not reach the disk cannot be undone by a read)" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    var m = try env.manager();
    var s: Session = .{};
    m.create(&s);
    try testing.expect(m.persist(&s));

    env.sim.ops_until_crash = 0; // the logout's kv write fails
    m.store.delete(s.id());
    try testing.expect(env.store.hasFailed());
    // The record is still readable from kv (reads survive a poisoned Db) —
    // KvStore must not serve it.
    var kbuf: KvStore.KeyBuf = undefined;
    try testing.expect(env.db.exists(env.storeKey(&kbuf, s.id())));
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(s.id(), &l));
    // And nothing is written any more.
    var fresh: Session = .{};
    m.create(&fresh);
    try testing.expect(!m.persist(&fresh));

    // A failed save closes it too.
    env.sim.reboot();
    try env.restart();
    m = try env.manager();
    try testing.expect(!env.store.hasFailed());
    env.sim.ops_until_crash = 0;
    m.create(&fresh);
    try testing.expect(!m.persist(&fresh));
    try testing.expect(env.store.hasFailed());
    env.sim.reboot();
}

test "KvStore: sessions live under their prefix next to other data; ids no manager mints are refused" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    var m = try env.manager();
    try env.db.put("user:1", "not a session");
    var s: Session = .{};
    m.create(&s);
    try testing.expect(m.persist(&s));

    const sessions = try env.db.keys(testing.allocator, "session:");
    defer sessions.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), sessions.keys.len);
    try testing.expectEqualStrings(s.id(), sessions.keys[0]["session:".len..]);

    // A cookie naming a non-session key under no prefix, or an oversized id.
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup("user:1", &l));
    const long_id = strRepeat("a", 2 * max_id_bytes + 1);
    try testing.expect(m.store.put(long_id, "0123456789abcdef", 0) == null);
    const got = try m.store.get(testing.allocator, long_id);
    try testing.expect(got == null);
    // A value that is not a framed record reads as absent.
    try env.db.put("session:short", "xy");
    try testing.expect((try m.store.get(testing.allocator, "short")) == null);

    try testing.expectError(error.PrefixTooLong, KvStore.init(&env.db, .{ .prefix = strRepeat("p", KvStore.max_prefix_len + 1) }));
}

test "Manager.init refuses the monotonic clock over a persistent store" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    try testing.expectError(error.MonotonicClockWithPersistentStore, Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io }));
    _ = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .clock = .realtime });
    // An in-process store keeps the monotonic default.
    var cache = newCache();
    defer cache.deinit();
    var rs: RamcacheStore = .{ .cache = &cache };
    _ = try Manager.init(testing.allocator, rs.store(), .{ .io = testing.io });
}

test "Clock.realtime is wall time: nanoseconds since the Unix epoch" {
    const now = Clock.realtime.now();
    // Later than 2026-01-01 and earlier than 2100-01-01.
    try testing.expect(now > 1_767_225_600 * std.time.ns_per_s);
    try testing.expect(now < 4_102_444_800 * std.time.ns_per_s);
}

test "min_id_bytes floor: default and at-floor id_bytes are accepted" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    // Default (32 bytes) — fine.
    _ = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io });
    // Exactly at the floor — fine.
    _ = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .id_bytes = min_id_bytes });
    // Exactly at the ceiling — fine.
    _ = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .id_bytes = max_id_bytes });
}

test "insecure escape hatch drops Secure; default keeps it" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    const secure = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io });
    try testing.expect(secure.secure);
    const insecure = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .allow_insecure_cookie = true });
    try testing.expect(!insecure.secure);
}

/// The handler/middleware half of the dead-frame test below: mint a session
/// with a KNOWN id in a `Session` that lives entirely on THIS frame (mirroring
/// `middlewareRun`'s own `s: Session` local, which is exactly what happens in
/// production — `middlewareRun` calls `m.save(ctx.res, &s)` after the handler
/// returns, and `m.save` runs `writeCookie`, which formats its own `cookie_buf`
/// too), then call the real `Manager.save` and return.
///
/// A separate `noinline` function, not a block inside the test, and that is
/// the whole point: Zig gives each local its own slot for the enclosing
/// function's entire body in Debug, so a block scope frees nothing and a
/// borrowed-slice bug would stay invisible. Only a returned frame is really
/// reusable. Mirrors `http`'s `setFromDeadFrame` and `cookies`'s.
noinline fn setFromDeadFrame(m: *const Manager, res: *http.Server.ResponseWriter) void {
    var s: Session = .{};
    // A fixed, known id instead of `m.create`'s CSPRNG draw — the wire
    // assertion below needs an exact expected value, not just "looks like
    // hex". 64 bytes, all landing inside this frame's `s.id_buf`.
    const known_id = strRepeat("deadbeef", 8);
    @memcpy(s.id_buf[0..known_id.len], known_id);
    s.id_len = known_id.len;
    s.created_ns = 1;
    s.last_seen_ns = 1;
    s.generation = 0; // unstored ⇒ save's CAS is a create, and succeeds
    m.save(res, &s);
}

/// Reuse the frame `setFromDeadFrame` just left, the way the next call down
/// the stack would have. Bigger than `setFromDeadFrame` PLUS `Manager.save` /
/// `writeCookie` nested under it, so it covers every slot in both; `noinline`
/// + `doNotOptimizeAway` so neither the call nor the stores can be optimized
/// out.
noinline fn clobberDeadFrame() void {
    var scratch: [16384]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "Manager.save: the session id in the Set-Cookie survives writeCookie's dead frame" {
    // What this pins: `Manager.writeCookie` formats the `Set-Cookie` value
    // into its own stack buffer and hands it to `addSetCookie`, which is
    // `setHeader`'s cousin — both copy into the response writer's own
    // `header_buf` at call time (see `http`'s `ResponseWriter.dupe`). Without
    // that copy this would be a borrowed slice into a frame (`writeCookie`'s,
    // nested inside `setFromDeadFrame`'s) that is gone by the time `end()`
    // runs: `writeHead` runs inside `end()`, and both servers call `end()`
    // AFTER `middlewareRun` — which is where `Manager.save` is called from —
    // has already returned. Reproduced here with no server at all:
    // `setFromDeadFrame` IS `middlewareRun`'s post-handler half, and the
    // clobber is what the next stack user would have written over it.
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });

    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    setFromDeadFrame(&m, &rw);
    clobberDeadFrame();

    try rw.end();
    const wire = out.buffered();

    // The id, read back off the wire after every byte of its source frame
    // was overwritten, plus the hardening attributes `writeCookie` always
    // sets on a live session cookie.
    try testing.expect(std.mem.indexOf(u8, wire, "Set-Cookie: session=" ++ (strRepeat("deadbeef", 8)) ++ "; Path=/; Max-Age=10; Secure; HttpOnly; SameSite=Lax\r\n") != null);
    // …and not one byte of the clobber pattern anywhere on it.
    try testing.expect(std.mem.indexOf(u8, wire, "#") == null);
}

test "__Host- prefixed cookie name: the OWASP hardening measure the config surface already supports" {
    // A1 sessions LOW#2: the audit found the `__Host-` cookie-name prefix
    // (OWASP Session Management Cheat Sheet) nowhere in this module — neither
    // documented nor exercised — even though the prefix's own requirements
    // (`Secure`, `Path=/`, no `Domain` attribute) are this module's *defaults*
    // already. So this is not a code gap: `cookie_name` is a caller-supplied
    // `Options` field today. Pinned here so that claim is demonstrated end to
    // end through the real `Manager.save` / `writeCookie` path, not left as
    // an assertion in prose — see SPEC.md's "Cookie hardening" bullet.
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .clock = env.clk.clock(),
        .cookie_name = "__Host-session",
    });

    var s: Session = .{};
    const known_id = strRepeat("cafebabe", 8);
    @memcpy(s.id_buf[0..known_id.len], known_id);
    s.id_len = known_id.len;
    s.created_ns = 1;
    s.last_seen_ns = 1;
    s.generation = 0; // unstored ⇒ save's CAS is a create, and succeeds

    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    m.save(&rw, &s);
    try rw.end();
    const wire = out.buffered();

    const sc = headerValue(wire, "Set-Cookie").?;
    try testing.expect(std.mem.startsWith(u8, sc, "__Host-session=" ++ (strRepeat("cafebabe", 8))));
    try testing.expect(std.mem.indexOf(u8, sc, "Secure") != null);
    try testing.expect(std.mem.indexOf(u8, sc, "Path=/") != null);
    // The `__Host-` contract is void the moment a Domain attribute appears.
    try testing.expect(std.mem.indexOf(u8, sc, "Domain=") == null);
}

// ── middleware tests (offline — through http.Server.serveStream) ─────────────

const App = struct {
    manager: *Manager,
    action: enum { touch, write_big, revoke, regenerate, regenerate_only, read_only, keep, put_uid, remember, flash_set, flash_pop } = .touch,
};

fn hSession(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    const s = sessionOf(ctx).?;
    switch (app.action) {
        .touch => {
            try s.setData("hits=1");
            try ctx.res.writeAll(s.id());
        },
        .write_big => {
            try s.setData("hits=1");
            var big: [512]u8 = undefined;
            @memset(&big, 'x');
            try ctx.res.writeAll(&big); // exceeds a tiny response buffer → early flush
        },
        .revoke => {
            s.revoke();
            try ctx.res.writeAll("bye");
        },
        .regenerate => {
            app.manager.regenerate(s);
            try s.setData("uid=42"); // data set AFTER rotation must survive the final save
            try ctx.res.writeAll(s.id()); // echo the NEW id
        },
        .regenerate_only => {
            app.manager.regenerate(s); // no setData / keep
            try ctx.res.writeAll(s.id());
        },
        .read_only => try ctx.res.writeAll(s.id()),
        .keep => {
            s.keep();
            try ctx.res.writeAll(s.id());
        },
        .put_uid => {
            try s.putValue("uid", "42");
            try ctx.res.writeAll(s.id());
        },
        .remember => {
            s.rememberMe(true);
            try ctx.res.writeAll(s.id());
        },
        .flash_set => {
            try s.putValue("flash", "saved!");
            try ctx.res.writeAll(s.id());
        },
        .flash_pop => {
            var b: [32]u8 = undefined;
            try ctx.res.writeAll((try s.popValue("flash", &b)) orelse "<none>");
        },
    }
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8, resp_body_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = resp_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
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

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

fn cookieId(set_cookie: []const u8) []const u8 {
    const eq = std.mem.indexOfScalar(u8, set_cookie, '=').?;
    const rest = set_cookie[eq + 1 ..];
    const semi = std.mem.indexOfScalar(u8, rest, ';') orelse rest.len;
    return rest[0..semi];
}

test "middleware: fresh request gets a hardened Set-Cookie; round-trips" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
    var app = App{ .manager = &m };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);

    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;
    const first = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out, &rbody);
    const sc = headerValue(first, "Set-Cookie").?;
    try testing.expect(std.mem.indexOf(u8, sc, "HttpOnly") != null);
    try testing.expect(std.mem.indexOf(u8, sc, "Secure") != null);
    try testing.expect(std.mem.indexOf(u8, sc, "SameSite=Lax") != null);
    // maxAgeSeconds(idle_timeout_ns) must be the exact idle window in
    // seconds (10s here) -- no prior test checked the numeric value, only
    // that "Max-Age=-1" appears on a *destroy* cookie.
    try testing.expect(std.mem.indexOf(u8, sc, "Max-Age=10;") != null);
    const id = cookieId(sc);
    try testing.expectEqual(@as(usize, 64), id.len);
    try testing.expectEqualStrings(id, bodyOf(first)); // body echoed the cookie id

    // Send the cookie back → the SAME session id (loaded, not a new one).
    var out2: [4096]u8 = undefined;
    var rbody2: [1024]u8 = undefined;
    const reqline = std.fmt.allocPrint(testing.allocator, "GET / HTTP/1.1\r\nHost: t\r\nCookie: session={s}\r\nConnection: close\r\n\r\n", .{id}) catch unreachable;
    defer testing.allocator.free(reqline);
    const second = runWire(&r, reqline, &out2, &rbody2);
    try testing.expectEqualStrings(id, bodyOf(second));
}

fn getWithCookie(r: *router.Router, id: ?[]const u8, out: []u8, rbody: []u8) []const u8 {
    var req_buf: [256]u8 = undefined;
    const req = if (id) |sid|
        std.fmt.bufPrint(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nCookie: session={s}\r\nConnection: close\r\n\r\n", .{sid}) catch unreachable
    else
        "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
    return runWire(r, req, out, rbody);
}

// A1 sessions LOW#1: every cookieless request used to create AND store a
// session, so anonymous traffic filled the bounded default store and evicted
// the sessions of logged-in users.
test "middleware: anonymous requests that write nothing are not stored and cannot evict a live session" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{});
    var app = App{ .manager = &m };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);

    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;

    // A logged-in user: the handler writes, so the session is stored.
    app.action = .touch;
    const first = getWithCookie(&r, null, &out, &rbody);
    var id_buf: [64]u8 = undefined;
    const id = id_buf[0..cookieId(headerValue(first, "Set-Cookie").?).len];
    @memcpy(id, cookieId(headerValue(first, "Set-Cookie").?));

    // An anonymous request that writes nothing: no cookie, nothing stored.
    app.action = .read_only;
    const anon = getWithCookie(&r, null, &out, &rbody);
    try testing.expect(headerValue(anon, "Set-Cookie") == null);
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(bodyOf(anon), &l));

    // More cookieless requests than the store holds entries (`newCache`: 256).
    for (0..300) |_| _ = getWithCookie(&r, null, &out, &rbody);

    // The logged-in session is still there.
    const again = getWithCookie(&r, id, &out, &rbody);
    try testing.expectEqualStrings(id, bodyOf(again));
}

test "middleware: keep() persists a session the handler wrote nothing into" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{});
    var app = App{ .manager = &m, .action = .keep };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);

    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;
    const got = getWithCookie(&r, null, &out, &rbody);
    const id = cookieId(headerValue(got, "Set-Cookie").?);
    try testing.expectEqualStrings(id, bodyOf(got));
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
}

test "middleware: persist_untouched_sessions restores storing every new session" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .persist_untouched = true });
    var app = App{ .manager = &m, .action = .read_only };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);

    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;
    const got = getWithCookie(&r, null, &out, &rbody);
    const id = cookieId(headerValue(got, "Set-Cookie").?);
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
}

test "middleware: revoke expires the cookie and evicts the session" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
    var app = App{ .manager = &m };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.post("/", hSession);
    try r.post("/logout", hSession);

    // Seed a session (touch), capture its id.
    app.action = .touch;
    var out0: [4096]u8 = undefined;
    var rb0: [1024]u8 = undefined;
    const first = runWire(&r, "POST / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out0, &rb0);
    const id = try testing.allocator.dupe(u8, cookieId(headerValue(first, "Set-Cookie").?));
    defer testing.allocator.free(id);

    // Logout revokes it.
    app.action = .revoke;
    const reqline = std.fmt.allocPrint(testing.allocator, "POST /logout HTTP/1.1\r\nHost: t\r\nCookie: session={s}\r\nConnection: close\r\n\r\n", .{id}) catch unreachable;
    defer testing.allocator.free(reqline);
    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;
    const got = runWire(&r, reqline, &out, &rbody);
    try testing.expect(std.mem.indexOf(u8, headerValue(got, "Set-Cookie").?, "Max-Age=-1") != null);

    // And the session is gone from the store.
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(id, &l));
}

test "middleware: the trailing end-of-request save does not resurrect a session revoke()'d mid-request" {
    // Regression guard for the same-request part of the "end-of-request save
    // resurrects a destroyed/regenerated session" finding: `middlewareRun`
    // must not fall through to `m.save` after a handler called
    // `Session.revoke()`, even though the request otherwise completes
    // normally (handler returns no error, response is fully written).
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
    var app = App{ .manager = &m };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.post("/", hSession);
    try r.post("/logout", hSession);

    app.action = .touch;
    var out0: [4096]u8 = undefined;
    var rb0: [1024]u8 = undefined;
    const first = runWire(&r, "POST / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out0, &rb0);
    const id = try testing.allocator.dupe(u8, cookieId(headerValue(first, "Set-Cookie").?));
    defer testing.allocator.free(id);

    app.action = .revoke;
    const reqline = std.fmt.allocPrint(testing.allocator, "POST /logout HTTP/1.1\r\nHost: t\r\nCookie: session={s}\r\nConnection: close\r\n\r\n", .{id}) catch unreachable;
    defer testing.allocator.free(reqline);
    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;
    _ = runWire(&r, reqline, &out, &rbody);

    // The old id must not resolve — a follow-up lookup (as a later,
    // completely separate request would perform) proves the end-of-request
    // path did not re-`put` it back after `destroy` ran.
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(id, &l));
}

test "middleware: regenerate mid-request — old id dead, only the new id resolves, post-rotation data survives" {
    // Regression guard for the "regenerate" half of the same finding: after
    // `Manager.regenerate` mints a new id mid-handler, the trailing
    // `m.save` must persist under the NEW id only — the old id must stay
    // dead, and data set *after* regenerate() must still make it into the
    // store (proving the final save is required, not merely harmless).
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
    var app = App{ .manager = &m };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.post("/", hSession);
    try r.post("/login", hSession);

    app.action = .touch;
    var out0: [4096]u8 = undefined;
    var rb0: [1024]u8 = undefined;
    const first = runWire(&r, "POST / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out0, &rb0);
    const old_id = try testing.allocator.dupe(u8, cookieId(headerValue(first, "Set-Cookie").?));
    defer testing.allocator.free(old_id);

    app.action = .regenerate;
    const reqline = std.fmt.allocPrint(testing.allocator, "POST /login HTTP/1.1\r\nHost: t\r\nCookie: session={s}\r\nConnection: close\r\n\r\n", .{old_id}) catch unreachable;
    defer testing.allocator.free(reqline);
    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;
    const got = runWire(&r, reqline, &out, &rbody);
    const new_id = try testing.allocator.dupe(u8, cookieId(headerValue(got, "Set-Cookie").?));
    defer testing.allocator.free(new_id);

    try testing.expect(!std.mem.eql(u8, old_id, new_id)); // actually rotated
    try testing.expectEqualStrings(new_id, bodyOf(got)); // handler echoed the new id

    // Old id is dead — the trailing save did not resurrect it.
    var lo: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(old_id, &lo));

    // Only the new id resolves, and it carries the data set after rotation.
    var ln: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(new_id, &ln));
    try testing.expectEqualStrings("uid=42", ln.data());
}

test "middleware: small response buffer forces an early flush — no cookie-buffer corruption" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
    var app = App{ .manager = &m, .action = .write_big };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);

    var out: [4096]u8 = undefined;
    var tiny: [16]u8 = undefined; // < body → head flushes mid-handler, before save()
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out, &tiny);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    // Early flush → chunked framing; all 512 payload bytes survive intact (a
    // dangling cookie buffer would have overwritten or displaced some).
    try testing.expectEqual(@as(usize, 512), std.mem.count(u8, bodyOf(got), "x"));
    // Head already sent before save() → cookie can't be issued this response (documented).
    try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "Set-Cookie"));
}

// ── fuzz ───────────────────────────────────────────────────────────────────
//
// ⚠ Both targets below used to open `smith.bytes(&buf)` and then draw the
// length with `smith.valueRangeAtMost`. `bytes` consumes `@min(buf.len,
// in.len)` octets and a ranged draw reads EIGHT more as a little-endian
// `u64`, returning the range MINIMUM when fewer remain, so the length was 0
// for every input a corpus can carry — and neither target had a corpus, so
// the one input each ever ran was empty. `fuzzSessionRecordDecode` stored a
// ZERO-LENGTH record and `lookup` answered `.absent` on the `rec.len <
// record_header_len` line; `fuzzCookieParse` called `cookies.find("", …)`.
// Measured 2026-09-07: 1 round each, 0 non-empty inputs, 0 records decoded,
// 0 payload octets copied, 0 cookies found.
//
// ⚠ The record buffer was also `record_header_len + max_session_bytes`
// exactly — 4112 octets — which is one octet short of the smallest record
// that reaches `lookup`'s own `payload.len > out.data_buf.len` refusal
// (16 + 4097 = 4113). That branch was structurally unreachable from this
// harness, and a seed over the buffer reads back EMPTY, so a corpus alone
// could not have fixed it. The buffer now carries 16 octets of headroom.

/// The corpus for the record decoder, built at run time because the payload
/// sizes that matter here (4096 and 4097 octets) are not writable as literals.
///
/// ⭐ The harness and the guard below both build it from HERE. The clock is
/// `Env`'s `ManualClock` at `now_ns = 1000`, which is what makes the
/// `.loaded` / `.expired` split below deterministic.
const RecordCorpus = struct {
    const cap = record_header_len + max_session_bytes + 16;

    scratch: [cap]u8 = undefined,
    stores: [9][4 + cap]u8 = undefined,
    entries: [9][]const u8 = undefined,

    fn header(self: *RecordCorpus, created: i64, last_seen: i64, payload_len: usize, fill: u8) []const u8 {
        std.mem.writeInt(i64, self.scratch[0..8], created, .little);
        std.mem.writeInt(i64, self.scratch[8..16], last_seen, .little);
        @memset(self.scratch[record_header_len..][0..payload_len], fill);
        return self.scratch[0 .. record_header_len + payload_len];
    }

    fn build(self: *RecordCorpus) []const []const u8 {
        const kit = @import("testkit").fuzz;
        var n: usize = 0;

        // 0: a live record with no payload. `now_ns` is 1000, so `now - created`
        //    is 0 and neither timeout fires.
        self.entries[n] = kit.seedInto(&self.stores[n], self.header(1000, 1000, 0, 0));
        n += 1;
        // 1: a live record with a small payload — the ordinary `.loaded` case.
        self.entries[n] = kit.seedInto(&self.stores[n], self.header(1000, 1000, 5, 'x'));
        n += 1;
        // 2: a live record with `max_session_bytes` of payload — the largest
        //    record `lookup` is allowed to accept, and the memcpy at the edge.
        self.entries[n] = kit.seedInto(&self.stores[n], self.header(1000, 1000, max_session_bytes, 'y'));
        n += 1;
        // 3: ⭐ one octet past it. This is the `payload.len > out.data_buf.len`
        //    refusal, and it did not fit the old buffer at all.
        self.entries[n] = kit.seedInto(&self.stores[n], self.header(1000, 1000, max_session_bytes + 1, 'z'));
        n += 1;
        // 4: created far in the past → the absolute timeout (100 000 ns) fires.
        self.entries[n] = kit.seedInto(&self.stores[n], self.header(-1_000_000, 1000, 4, 'a'));
        n += 1;
        // 5: last_seen far in the past, created recent → the idle timeout
        //    (10 000 ns) fires, and only that one.
        self.entries[n] = kit.seedInto(&self.stores[n], self.header(1000, -1_000_000, 4, 'b'));
        n += 1;
        // 6: both timestamps at `maxInt(i64)` → the saturating `-|` path, where
        //    a plain subtraction would overflow.
        self.entries[n] = kit.seedInto(&self.stores[n], self.header(std.math.maxInt(i64), std.math.maxInt(i64), 0, 0));
        n += 1;
        // 7: fifteen octets — one short of a record header.
        self.entries[n] = kit.seedInto(&self.stores[n], self.header(1000, 1000, 0, 0)[0 .. record_header_len - 1]);
        n += 1;
        // 8: the empty record, which is what an empty corpus produced.
        self.entries[n] = kit.seedInto(&self.stores[n], self.scratch[0..0]);
        n += 1;

        std.debug.assert(n == self.entries.len);
        return &self.entries;
    }
};

fn fuzzSessionRecordDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var record: [RecordCorpus.cap]u8 = undefined;
    // ⚠ One byte-first draw. Never `bytes` then a ranged length.
    const len: usize = src.slice(&record);
    lookupRecord(record[0..len]);
}

fn lookupRecord(record: []const u8) void {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = env.manager(.{ .idle = 10_000, .absolute = 100_000 }) catch @panic("fuzz: Manager.init");

    // Bypass `seed`'s structured layout: put a fully arbitrary byte string
    // straight into the store under a fixed id, then decode it exactly like
    // a corrupted/attacker-controlled record would be decoded on `load`.
    // `Manager.lookup` is the wire-facing decoder (record header + payload
    // length checks) — arbitrary bytes must only ever yield `.absent`/
    // `.expired`, never a panic or OOB write into `out`'s fixed buffers.
    const id = "fuzz-session-id";
    _ = env.store.store().put(id, record, 0);
    var out: Session = .{};
    switch (m.lookup(id, &out)) {
        .loaded => fuzz_mark(.loaded),
        .expired => fuzz_mark(.expired),
        .absent => fuzz_mark(.absent),
    }
}

test "fuzz: Manager.lookup's session-record decode never panics on arbitrary bytes" {
    var corpus: RecordCorpus = .{};
    try testing.fuzz({}, fuzzScript(fuzzSessionRecordDecode, RecordCorpus.cap), .{ .corpus = corpus.build() });
}

test "corpus: every record seed reaches lookup, and the payload octets copied are pinned" {
    // ⭐ The measurement, executable. It draws exactly the way the harness
    // does, because the defect WAS the draw.
    //
    // `octets` is the second number and it is the load-bearing one: `.absent`
    // is a perfectly legal answer here — it is what a zero-length record
    // *should* produce, and it is what the collapsed harness got on every run
    // — so a guard counting "did not panic", or even "returned a result",
    // would have read green over nothing. Payload octets copied into
    // `out.data_buf` can only come from a record that passed every check.
    var corpus: RecordCorpus = .{};
    const seeds = corpus.build();

    var nonempty: usize = 0;
    var loaded: usize = 0;
    var expired: usize = 0;
    var absent: usize = 0;
    var octets: usize = 0;
    for (seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var record: [RecordCorpus.cap]u8 = undefined;
        const len: usize = smith.slice(&record);
        if (len != 0) nonempty += 1;

        var env = Env.init();
        env.wire();
        defer env.deinit();
        var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });
        const id = "fuzz-session-id";
        _ = env.store.store().put(id, record[0..len], 0);
        var out: Session = .{};
        switch (m.lookup(id, &out)) {
            .loaded => {
                loaded += 1;
                octets += out.data_len;
            },
            .expired => expired += 1,
            .absent => absent += 1,
        }
    }
    // Measured 2026-09-07. Before: 1 round, a zero-length record, `.absent`,
    // 0 payload octets.
    try testing.expectEqual(seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 4), loaded);
    try testing.expectEqual(@as(usize, 2), expired); // the absolute-timeout seed and the idle-timeout seed
    try testing.expectEqual(@as(usize, 3), absent); // the oversized payload, the 15-octet record, and the empty one
    try testing.expectEqual(@as(usize, 4101), octets); // 5 from the small record and 4096 from the max-size one
}

/// `testkit.fuzz.seed`, aliased so the cookie corpus reads as the headers it
/// is. A corpus entry is not the header: `Smith.slice` reads a little-endian
/// `u32` length first.
const fuzzSeed = @import("testkit").fuzz.seed;

/// `Cookie:` request-header values, in the format the length draw reads. The
/// function under test looks for `default_cookie_name`, so the corpus is
/// about the ways that name can be present, absent, or nearly present.
const cookie_header_seeds = [_][]const u8{
    fuzzSeed(default_cookie_name ++ "=abc123"), // the header `Manager.load` expects
    fuzzSeed("a=1; " ++ default_cookie_name ++ "=abc123; z=9"), // the id between two other cookies
    fuzzSeed(default_cookie_name ++ "=\"quoted;value\""), // a DQUOTE-wrapped id containing a ';'
    fuzzSeed(default_cookie_name ++ "="), // present with an empty value
    fuzzSeed(default_cookie_name ++ "x=abc123"), // a name that merely starts the same → must not match
    fuzzSeed("Session=abc123"), // RFC 6265 §5.4 is case-SENSITIVE → must not match
    fuzzSeed("a=1; b=2"), // the name is simply absent
    fuzzSeed(";;;  ;  "), // separators and OWS only
    fuzzSeed(default_cookie_name ++ "=" ++ strRepeat("a", 100)), // a 108-octet header, inside the 128 buffer
    fuzzSeed(""), // zero length: the ONLY input this target ever ran
};

fn fuzzCookieParse(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // ⚠ One byte-first draw. Never `bytes` then a ranged length.
    var header: [128]u8 = undefined;
    const len: usize = src.slice(&header);
    findCookie(header[0..len]);
}

fn findCookie(header: []const u8) void {
    // The Cookie request-header decoder this module relies on to find the
    // session id (`Manager.load` → `cookies.get` → `cookies.find`/`parse`):
    // arbitrary bytes must only ever yield null/a borrowed slice, never a
    // panic or OOB.
    if (cookies.find(header, default_cookie_name) != null) fuzz_mark(.cookie_found) else fuzz_mark(.cookie_missing);
}

test "fuzz: cookie header parse (as used by Manager.load) never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzScript(fuzzCookieParse, 128), .{ .corpus = &cookie_header_seeds });
}

test "corpus: every cookie seed reaches find, and the ids recovered are pinned" {
    // `id_octets` is the second number: `cookies.find` returns null on an
    // empty header and reports no error, so there is nothing a "did not
    // crash" guard could have noticed. A recovered id cannot come from an
    // empty input.
    var nonempty: usize = 0;
    var found: usize = 0;
    var id_octets: usize = 0;
    for (cookie_header_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var header: [128]u8 = undefined;
        const len: usize = smith.slice(&header);
        if (len != 0) nonempty += 1;
        const v = cookies.find(header[0..len], default_cookie_name) orelse continue;
        found += 1;
        id_octets += v.len;
    }
    // Measured 2026-09-07. Before: 1 round, `find("", …)`, 0 ids.
    try testing.expectEqual(cookie_header_seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 5), found);
    try testing.expectEqual(@as(usize, 124), id_octets);
}

test "Manager.init rejects an out-of-range id_bytes in every build mode" {
    // The floor and the ceiling were both `std.debug.assert`, which
    // ReleaseFast compiles out -- and this module's suite runs that mode.
    // Below the floor the release build silently minted brute-forceable
    // session ids; above the ceiling `newId` wrote `id_bytes` bytes into a
    // `[max_id_bytes]u8` stack array and `id_bytes * 2` hex digits into a
    // fixed `id_buf`, then handed that out-of-bounds slice to the store and
    // the Set-Cookie header.
    var env = Env.init();
    env.wire();
    defer env.deinit();

    try testing.expectError(error.InvalidIdBytes, Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .id_bytes = min_id_bytes - 1,
    }));
    try testing.expectError(error.InvalidIdBytes, Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .id_bytes = max_id_bytes + 1,
    }));
    try testing.expectError(error.InvalidIdBytes, Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .id_bytes = 1, // the doc's own example of a brute-forceable value
    }));
    try testing.expectError(error.EmptyCookieName, Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .cookie_name = "",
    }));

    // Both ends of the accepted range still construct.
    _ = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .id_bytes = min_id_bytes });
    _ = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .id_bytes = max_id_bytes });
}

test "KvStore waits on its lock through the Db's Io when the storage has one" {
    // simio pilot finding (kv): a spinlock held across an fsync starves a
    // task suspended inside it under an `Io` that runs several tasks on one
    // thread. Over `FsStorage` the store's lock is an `std.Io.Mutex`.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = kv.FsStorage.init(testing.io, tmp.dir);
    var db = try kv.Db.open(testing.allocator, fs_store.storage(), "s", .{});
    defer db.close();
    const over_fs = try KvStore.init(&db, .{});
    try testing.expect(over_fs.lock.io != null);

    var sim = kv.SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db2 = try kv.Db.open(testing.allocator, sim.storage(), "s", .{});
    defer db2.close();
    const over_sim = try KvStore.init(&db2, .{});
    try testing.expect(over_sim.lock.io == null);
}

// ── audit 2026-10-04: tests asked for by mutation survivors ──────────────────

test "setData takes exactly max_session_bytes, refuses one more" {
    // The documented bound: `error.Overflow` when the payload EXCEEDS
    // `max_session_bytes` — so the bound itself fits.
    var s: Session = .{};
    const full: [max_session_bytes]u8 = @splat('d');
    try s.setData(&full);
    try testing.expectEqual(@as(usize, max_session_bytes), s.data().len);
    const over: [max_session_bytes + 1]u8 = @splat('d');
    try testing.expectError(error.Overflow, s.setData(&over));
}

test "timeouts are strict: a session exactly at its idle or absolute limit still loads" {
    // `idle_timeout_ns`: "reject a session unused for LONGER than this";
    // `absolute_timeout_ns`: "OLDER than this" — strict inequalities, so the
    // limit itself is still valid and one nanosecond past it is not.
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 500, .absolute = 100_000 });
    var s: Session = .{};
    m.create(&s); // created = last_seen = 1000
    const id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(id);
    seed(&m, &s);
    env.clk.now_ns = 1500;
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
    // `lookup` refreshes `last_seen_ns` to now (its doc: "On .loaded,
    // out.last_seen_ns is refreshed to now").
    try testing.expectEqual(@as(i64, 1500), l.last_seen_ns);
    try testing.expectEqual(@as(i64, 1000), l.created_ns);

    var m2 = try env.manager(.{ .idle = 1_000_000, .absolute = 5_000 });
    var s2: Session = .{};
    m2.create(&s2); // created = 1500
    const id2 = try testing.allocator.dupe(u8, s2.id());
    defer testing.allocator.free(id2);
    seed(&m2, &s2);
    env.clk.now_ns = 6500;
    try testing.expectEqual(Manager.LoadResult.loaded, m2.lookup(id2, &l));
    env.clk.now_ns = 6501;
    try testing.expectEqual(Manager.LoadResult.expired, m2.lookup(id2, &l));
}

/// A `Store` that hands back one record whose payload is larger than any
/// `Session` can hold — what a corrupt or foreign backend (the `Store`
/// vtable is public) could return.
const OversizedStore = struct {
    fn get(_: *anyopaque, gpa: Allocator, _: []const u8) StoreError!?Loaded {
        const rec = try gpa.alloc(u8, record_header_len + max_session_bytes + 1);
        @memset(rec, 0);
        return .{ .record = rec, .generation = 1 };
    }
    fn put(_: *anyopaque, _: []const u8, _: []const u8, _: Generation) ?Generation {
        return null;
    }
    fn delete(_: *anyopaque, _: []const u8) void {}
    const vtable: Store.VTable = .{ .get = get, .put = put, .delete = delete };
};

test "lookup treats a record with an oversized payload as absent, never copies it" {
    // `lookup`'s contract: "corrupt / oversized → absent". The payload is
    // copied into the fixed `Session.data_buf`, so the check is all that
    // stands between a bad store and an out-of-bounds write.
    var dummy: u8 = 0;
    const store: Store = .{ .ptr = &dummy, .vtable = &OversizedStore.vtable };
    const m = try Manager.init(testing.allocator, store, .{ .io = testing.io, .idle_timeout_ns = 0, .absolute_timeout_ns = 0 });
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup("ab", &l));
}

test "maxAgeSeconds: a disabled idle timeout gives the absolute default, never 0" {
    // RFC 6265 §5.2.2: Max-Age ≤ 0 makes the cookie expire at once. With the
    // idle timeout disabled (0) the cookie must live as long as the absolute
    // default (12 h), not be deleted by the very response that issues it.
    try testing.expectEqual(@as(i64, 12 * 60 * 60), maxAgeSeconds(0));
    try testing.expectEqual(@as(i64, 12 * 60 * 60), maxAgeSeconds(-5));
    try testing.expectEqual(@as(i64, 30), maxAgeSeconds(30 * std.time.ns_per_s));
}

test "middleware: allow_insecure_cookie really drops Secure from the Set-Cookie" {
    // The escape hatch's whole effect is on the wire; the Manager field
    // alone (tested above) does not show the cookie writer honours it.
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .clock = env.clk.clock(), .allow_insecure_cookie = true });
    var app = App{ .manager = &m };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);
    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;
    const got = getWithCookie(&r, null, &out, &rbody);
    const sc = headerValue(got, "Set-Cookie").?;
    try testing.expect(std.mem.indexOf(u8, sc, "Secure") == null);
    try testing.expect(std.mem.indexOf(u8, sc, "HttpOnly") != null);
}

test "middleware: a new session whose handler only regenerates is persisted" {
    // `Options.persist_untouched_sessions` doc: a new session is dropped
    // "unless the handler called setData, keep or Manager.regenerate" — a
    // regenerate alone (e.g. a login step that stores nothing yet) counts.
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
    var app = App{ .manager = &m, .action = .regenerate_only };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);
    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;
    const got = getWithCookie(&r, null, &out, &rbody);
    const id = cookieId(headerValue(got, "Set-Cookie").?);
    try testing.expectEqualStrings(id, bodyOf(got));
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
}

test "KvStore: once closed by a failed write, a readable record is still not served" {
    // `KvStore` doc, "Fail closed": after any kv error on a write every `get`
    // answers absent — even when the disk can be read again, since the
    // failed write may have been a logout.
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    var m = try env.manager();
    var s: Session = .{};
    m.create(&s);
    try testing.expect(m.persist(&s));
    env.sim.ops_until_crash = 0;
    m.store.delete(s.id()); // the logout fails
    try testing.expect(env.store.hasFailed());
    env.sim.reboot(); // the disk answers reads again; the store stays closed
    var kbuf: KvStore.KeyBuf = undefined;
    var vbuf: KvStore.ValueBuf = undefined;
    try testing.expect((try env.db.getBuf(&vbuf, env.storeKey(&kbuf, s.id()))) != null); // non-vacuous
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(s.id(), &l));
}

// ── deterministic fuzz driver (2026-10-09) ───────────────────────────────────
//
// The two harnesses above are generic over their source of choices
// (`fn(comptime S, *S, gpa)`); `testing.fuzz` feeds them through `FuzzScript`,
// `SESSIONS_FUZZ=<runs>[,<first seed>]` through testkit's driver (`_MS`,
// `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). They stay in this file
// because `Env` and the corpora are private. Random bytes never form a valid
// record or carry the cookie name, so each harness has a "mutated" twin: a
// corpus entry, a few octets damaged, maybe cut short.

const fuzz_driver = @import("testkit").fuzz.driver;

const FuzzLabel = enum { absent, loaded, expired, cookie_found, cookie_missing, values_ok, values_malformed };
var fuzz_reach: [@typeInfo(FuzzLabel).@"enum".field_names.len]usize = @splat(0);

fn fuzz_mark(comptime l: FuzzLabel) void {
    fuzz_reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const FuzzScript = struct {
    cur: @import("testkit").fuzz.Cursor,

    pub fn valueRangeAtMost(self: *FuzzScript, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *FuzzScript, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            u8 => self.cur.byte(),
            u16 => self.cur.word(),
            else => @compileError("FuzzScript.value: unsupported type"),
        };
    }
    pub fn bytes(self: *FuzzScript, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *FuzzScript, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
    /// What `Smith.slice` returns for this script: up to `buf.len` of the
    /// remaining script bytes, and their count.
    pub fn slice(self: *FuzzScript, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

/// `testing.fuzz`'s callback for a harness; `max` bounds the script (the
/// first `slice` draw), which for the record decoder must hold a whole
/// 4096-octet record.
fn fuzzScript(comptime harness: anytype, comptime max: usize) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            var script: [max]u8 = undefined;
            const n = smith.slice(&script);
            var src: FuzzScript = .{ .cur = .{ .bytes = script[0..n] } };
            return harness(FuzzScript, &src, testing.allocator);
        }
    }.f;
}

/// A corpus entry with a few of its first octets damaged, maybe cut short.
fn damaged(comptime S: type, src: *S, entries: []const []const u8, buf: []u8) []const u8 {
    var smith: std.testing.Smith = .{ .in = entries[src.index(entries.len)] };
    var len: usize = smith.slice(buf);
    if (len == 0) return buf[0..0];
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| buf[src.index(@min(len, 24))] = src.value(u8);
    if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
    return buf[0..len];
}

fn fuzzSessionRecordMutated(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var corpus: RecordCorpus = .{};
    var record: [RecordCorpus.cap]u8 = undefined;
    lookupRecord(damaged(S, src, corpus.build(), &record));
}

fn fuzzCookieMutated(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var header: [128]u8 = undefined;
    findCookie(damaged(S, src, &cookie_header_seeds, &header));
}

test "fuzz: session-record decode, damaged corpus records" {
    try testing.fuzz({}, fuzzScript(fuzzSessionRecordMutated, 64), .{});
}

test "fuzz: cookie header parse, damaged corpus headers" {
    try testing.fuzz({}, fuzzScript(fuzzCookieMutated, 64), .{});
}

test "fuzz driver: SESSIONS_FUZZ" {
    try fuzz_driver.run(fuzzSessionRecordDecode, .{ .prefix = "SESSIONS_FUZZ", .name = "sessions-record" });
    try fuzz_driver.run(fuzzSessionRecordMutated, .{ .prefix = "SESSIONS_FUZZ", .name = "sessions-record-mutated" });
    try fuzz_driver.run(fuzzCookieParse, .{ .prefix = "SESSIONS_FUZZ", .name = "sessions-cookie" });
    try fuzz_driver.run(fuzzCookieMutated, .{ .prefix = "SESSIONS_FUZZ", .name = "sessions-cookie-mutated" });
    try fuzz_driver.run(fuzzValuesDecode, .{ .prefix = "SESSIONS_FUZZ", .name = "sessions-values" });
    try fuzz_driver.run(fuzzValuesMutated, .{ .prefix = "SESSIONS_FUZZ", .name = "sessions-values-mutated" });
}

// ── fuzz: the key/value decoder over arbitrary blob bytes ────────────────────

/// Corpus for the key/value decoder: valid blobs (built by the encoder itself),
/// a tag alone, the empty blob, a blob one octet short of the cap, and a
/// foreign tag. Run time again, for the large one.
const ValuesCorpus = struct {
    stores: [6][4 + max_session_bytes]u8 = undefined,
    entries: [6][]const u8 = undefined,

    fn build(self: *ValuesCorpus) []const []const u8 {
        const kit = @import("testkit").fuzz;
        var blob: [max_session_bytes]u8 = undefined;
        var len: usize = 0;
        var n: usize = 0;
        // 0: empty (no values).
        self.entries[n] = kit.seedInto(&self.stores[n], blob[0..0]);
        n += 1;
        // 1: one small entry.
        len = values.put(max_session_bytes, &blob, 0, "uid", "42") catch unreachable;
        self.entries[n] = kit.seedInto(&self.stores[n], blob[0..len]);
        n += 1;
        // 2: two entries, the second with an empty value.
        len = values.put(max_session_bytes, &blob, len, "flash", "") catch unreachable;
        self.entries[n] = kit.seedInto(&self.stores[n], blob[0..len]);
        n += 1;
        // 3: one entry that fills the blob to exactly max_session_bytes.
        len = values.put(max_session_bytes, &blob, 0, "big", &@as([max_session_bytes - 7]u8, @splat('z'))) catch unreachable;
        self.entries[n] = kit.seedInto(&self.stores[n], blob[0..len]);
        n += 1;
        // 4: the tag alone.
        blob[0] = values.tag;
        self.entries[n] = kit.seedInto(&self.stores[n], blob[0..1]);
        n += 1;
        // 5: a foreign tag.
        blob[0] = 0xA0;
        self.entries[n] = kit.seedInto(&self.stores[n], blob[0..1]);
        n += 1;
        std.debug.assert(n == self.entries.len);
        return &self.entries;
    }
};

/// Decode `blob` as a session's data three ways (iterator, `getValue`, a
/// mutation) and insist they agree: Malformed everywhere or nowhere, a failed
/// mutation changes nothing, a successful one is read back.
fn valuesCheck(blob: []const u8) !void {
    var s: Session = .{};
    @memcpy(s.data_buf[0..blob.len], blob);
    s.data_len = blob.len;

    var it = s.valueIterator();
    var malformed = false;
    while (true) {
        const e = it.next() catch {
            malformed = true;
            break;
        } orelse break;
        if (e.key.len == 0 or e.key.len > 255) return error.BadKey;
    }
    if (s.getValue("fz")) |_| {
        if (malformed) return error.GetDisagrees;
    } else |_| {
        if (!malformed) return error.GetDisagrees;
    }

    if (s.putValue("fz", "v")) {
        if (malformed) return error.PutAcceptedMalformed;
        if (!std.mem.eql(u8, (try s.getValue("fz")).?, "v")) return error.PutNotReadBack;
        if (!try s.removeValue("fz")) return error.RemoveMissed;
        fuzz_mark(.values_ok);
    } else |err| {
        if (!std.mem.eql(u8, s.data(), blob)) return error.FailedPutChanged;
        const is_malformed = err == error.Malformed;
        if (is_malformed != malformed) return error.PutDisagrees;
        if (is_malformed) fuzz_mark(.values_malformed) else fuzz_mark(.values_ok);
    }
}

fn fuzzValuesDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var blob: [max_session_bytes]u8 = undefined;
    // ⚠ One byte-first draw. Never `bytes` then a ranged length.
    const len: usize = src.slice(&blob);
    try valuesCheck(blob[0..len]);
}

fn fuzzValuesMutated(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var corpus: ValuesCorpus = .{};
    var blob: [max_session_bytes]u8 = undefined;
    try valuesCheck(damaged(S, src, corpus.build(), &blob));
}

test "fuzz: key/value decode never panics, and the iterator, getValue and putValue agree" {
    var corpus: ValuesCorpus = .{};
    try testing.fuzz({}, fuzzScript(fuzzValuesDecode, max_session_bytes), .{ .corpus = corpus.build() });
    try testing.fuzz({}, fuzzScript(fuzzValuesMutated, 64), .{});
}

test "corpus: every key/value seed reaches the decoder, and the entries recovered are pinned" {
    // Entries can only come from a blob that parsed; an empty corpus entry
    // is a valid empty set, so "did not panic" says nothing.
    var corpus: ValuesCorpus = .{};
    var ok: usize = 0;
    var bad: usize = 0;
    var entries: usize = 0;
    for (corpus.build()) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var blob: [max_session_bytes]u8 = undefined;
        const len: usize = smith.slice(&blob);
        var it = values.Iterator.init(blob[0..len]);
        while (true) {
            _ = it.next() catch {
                bad += 1;
                break;
            } orelse {
                ok += 1;
                break;
            };
            entries += 1;
        }
    }
    try testing.expectEqual(@as(usize, 5), ok);
    try testing.expectEqual(@as(usize, 1), bad);
    try testing.expectEqual(@as(usize, 4), entries); // 0 + 1 + 2 + 1 + 0
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    fuzz_reach = @splat(0);
    inline for (.{ fuzzSessionRecordDecode, fuzzSessionRecordMutated, fuzzCookieParse, fuzzCookieMutated, fuzzValuesDecode, fuzzValuesMutated }, 0..) |h, which| {
        for (0..400) |sd| {
            var prng = std.Random.DefaultPrng.init(sd);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print("sessions harness {d} seed {d}: {t}\n", .{ which, sd, err });
                return err;
            };
        }
    }
    for (fuzz_reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(FuzzLabel, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

// ── model-based differential: Manager + both stores vs a naive model ───────
//
// The tests above are hand-picked scenarios. This one drives `Manager`
// (create / lookup / persist / regenerate) and `Store.delete` with seeded
// random operation sequences, over `RamcacheStore` AND `KvStore`, and checks
// every result against `SessionModel`: a plain map from id to
// { generation, record } that re-states the documented semantics on its own —
// expiry is `now − created > absolute` or `now − last_seen > idle` (strict,
// 0 disables), and expiry deletes; `persist` is a compare-and-swap that lands
// iff the store's generation for the id equals the session's; `delete` bumps
// the generation and leaves a tombstone (`RamcacheStore`) or removes the key so
// the generation reads 0 again (`KvStore`, documented: "no tombstone"); a
// `regenerate`d session is a fresh id at generation 0 carrying the old
// `created` and data, with the old id deleted. Several handles may hold the
// same id at different generations: two requests racing on one session.

const SessionModel = struct {
    const Rec = struct { created: i64, last_seen: i64, data: []const u8 };
    const Entry = struct { gen: Generation = 0, rec: ?Rec = null };

    arena: Allocator,
    map: std.StringHashMapUnmanaged(Entry) = .empty,
    tombstones: bool,
    idle: i64,
    absolute: i64,

    fn entry(md: *SessionModel, id: []const u8) !*Entry {
        const gop = try md.map.getOrPut(md.arena, id);
        if (!gop.found_existing) {
            gop.key_ptr.* = try md.arena.dupe(u8, id);
            gop.value_ptr.* = .{};
        }
        return gop.value_ptr;
    }

    fn delete(md: *SessionModel, id: []const u8) !void {
        const e = try md.entry(id);
        e.rec = null;
        e.gen = if (md.tombstones) e.gen + 1 else 0;
    }

    const Lookup = union(enum) { absent, expired_absolute, expired_idle, loaded: struct { rec: Rec, gen: Generation } };

    fn lookup(md: *SessionModel, id: []const u8, now: i64) !Lookup {
        const e = try md.entry(id);
        const rec = e.rec orelse return .absent;
        if (md.absolute > 0 and now - rec.created > md.absolute) {
            try md.delete(id);
            return .expired_absolute;
        }
        if (md.idle > 0 and now - rec.last_seen > md.idle) {
            try md.delete(id);
            return .expired_idle;
        }
        return .{ .loaded = .{ .rec = rec, .gen = e.gen } };
    }

    /// The CAS: lands iff the generations match; returns the new one.
    fn persist(md: *SessionModel, id: []const u8, expected: Generation, created: i64, now: i64, data: []const u8) !?Generation {
        const e = try md.entry(id);
        if (e.gen != expected) return null;
        e.gen = expected + 1;
        e.rec = .{ .created = created, .last_seen = now, .data = try md.arena.dupe(u8, data) };
        return e.gen;
    }
};

const ModelReach = enum { loaded, absent, expired_idle, expired_absolute, persist_won, persist_stale, regenerated, deleted, restarted };

fn sessionModelRun(comptime kv_backed: bool, case_seed: u64, reach: *[@typeInfo(ModelReach).@"enum".field_names.len]usize) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(case_seed);
    const rnd = prng.random();

    const idle: i64 = if (rnd.boolean()) 1_000 else 0;
    const absolute: i64 = if (rnd.uintLessThan(u8, 4) != 0) 3_000 else 0;
    var env: if (kv_backed) KvEnv else Env = undefined;
    if (kv_backed) {
        try env.init();
    } else {
        env = Env.init();
        env.wire();
    }
    defer env.deinit();
    const clock_ptr = &env.clk; // the manager's clock (and RamcacheStore's)
    var m = try Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .clock = clock_ptr.clock(),
        .idle_timeout_ns = idle,
        .absolute_timeout_ns = absolute,
    });

    var md: SessionModel = .{ .arena = arena, .tombstones = !kv_backed, .idle = idle, .absolute = absolute };
    const handles = try testing.allocator.alloc(Session, 6);
    defer testing.allocator.free(handles);
    var live = @as([6]bool, @splat(false));
    var data_buf: [max_session_bytes]u8 = undefined;

    const steps = 60 + rnd.uintLessThan(usize, 120);
    for (0..steps) |step| {
        errdefer std.debug.print("sessions model: kv={} seed={d} step={d} now={d}\n", .{ kv_backed, case_seed, step, clock_ptr.now_ns });
        const h = rnd.uintLessThan(usize, handles.len);
        switch (rnd.uintLessThan(u8, 10)) {
            // A new session, persisted with random data (the create CAS).
            0, 1 => {
                m.create(&handles[h]);
                const n = if (rnd.uintLessThan(u8, 16) == 0) max_session_bytes else rnd.uintLessThan(usize, 64);
                rnd.bytes(data_buf[0..n]);
                try handles[h].setData(data_buf[0..n]);
                const want = try md.persist(handles[h].id(), 0, handles[h].created_ns, clock_ptr.now_ns, handles[h].data());
                try testing.expect(want != null); // a fresh CSPRNG id
                try testing.expect(m.persist(&handles[h]));
                try testing.expectEqual(want.?, handles[h].generation);
                live[h] = true;
            },
            // Time passes: often exactly onto, or one past, a timeout edge.
            2, 3 => clock_ptr.now_ns += switch (rnd.uintLessThan(u8, 6)) {
                0 => 0,
                1 => idle,
                2 => idle + 1,
                3 => @max(idle - 1, 0),
                else => @as(i64, rnd.uintLessThan(u32, 1_500)),
            },
            // A request comes back with the handle's id.
            4, 5 => if (live[h]) {
                const id = try arena.dupe(u8, handles[h].id());
                const want = try md.lookup(id, clock_ptr.now_ns);
                var got: Session = undefined;
                const r = m.lookup(id, &got);
                switch (want) {
                    .absent => {
                        try testing.expectEqual(Manager.LoadResult.absent, r);
                        reach[@backingInt(ModelReach.absent)] += 1;
                    },
                    .expired_absolute, .expired_idle => {
                        try testing.expectEqual(Manager.LoadResult.expired, r);
                        reach[@backingInt(if (want == .expired_idle) ModelReach.expired_idle else ModelReach.expired_absolute)] += 1;
                    },
                    .loaded => |l| {
                        try testing.expectEqual(Manager.LoadResult.loaded, r);
                        try testing.expectEqualSlices(u8, l.rec.data, got.data());
                        try testing.expectEqual(l.rec.created, got.created_ns);
                        try testing.expectEqual(l.gen, got.generation);
                        try testing.expectEqual(clock_ptr.now_ns, got.last_seen_ns);
                        handles[h] = got;
                        reach[@backingInt(ModelReach.loaded)] += 1;
                    },
                }
            },
            // The handle saves (maybe with new data): wins or is stale.
            6 => if (live[h]) {
                if (rnd.boolean()) {
                    const n = rnd.uintLessThan(usize, 64);
                    rnd.bytes(data_buf[0..n]);
                    try handles[h].setData(data_buf[0..n]);
                }
                const want = try md.persist(handles[h].id(), handles[h].generation, handles[h].created_ns, clock_ptr.now_ns, handles[h].data());
                const ok = m.persist(&handles[h]);
                try testing.expectEqual(want != null, ok);
                if (want) |g| try testing.expectEqual(g, handles[h].generation);
                reach[@backingInt(if (ok) ModelReach.persist_won else ModelReach.persist_stale)] += 1;
            },
            // A second request holds the same session.
            7 => if (live[h]) {
                const j = rnd.uintLessThan(usize, handles.len);
                handles[j] = handles[h];
                live[j] = true;
            },
            // Login: rotate the id (the old one is deleted in the store).
            8 => if (live[h]) {
                try md.delete(handles[h].id());
                m.regenerate(&handles[h]);
                try testing.expectEqual(@as(Generation, 0), handles[h].generation);
                reach[@backingInt(ModelReach.regenerated)] += 1;
            },
            // Logout / admin delete of the handle's id; or a restart (kv).
            else => if (kv_backed and rnd.uintLessThan(u8, 3) == 0) {
                try env.restart();
                reach[@backingInt(ModelReach.restarted)] += 1;
            } else if (live[h]) {
                try md.delete(handles[h].id());
                m.store.delete(handles[h].id());
                reach[@backingInt(ModelReach.deleted)] += 1;
            },
        }
    }
}

test "model: Manager over RamcacheStore and KvStore agrees with a naive session model on random operation sequences" {
    var reach = @as([@typeInfo(ModelReach).@"enum".field_names.len]usize, @splat(0));
    const seeds = if (@import("builtin").mode == .debug) 60 else 200;
    for (0..seeds) |case_seed| {
        try sessionModelRun(false, case_seed, &reach);
        try sessionModelRun(true, case_seed, &reach);
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("model reach: {t} never hit\n", .{@as(ModelReach, @fromBackingInt(@intCast(i)))});
        return error.ModelDoesNotReach;
    };
}

// ── key/value layer, remember-me, enumerate, hashed store keys (2026-10-11) ──

test "Session values: put/get/replace/remove/pop/iterate/clear, and they mark the session modified" {
    var s: Session = .{};
    try testing.expect(!s.kept);
    try testing.expect((try s.getValue("uid")) == null);
    try testing.expect(!s.kept); // reading marks nothing
    try testing.expect(!(try s.removeValue("uid")));
    try testing.expect(!s.kept); // removing nothing marks nothing

    try s.putValue("uid", "42");
    try testing.expect(s.kept);
    try s.putValue("theme", "dark");
    try s.putValue("uid", "4711"); // replaced in place, order kept
    try testing.expectEqualStrings("4711", (try s.getValue("uid")).?);
    var it = s.valueIterator();
    const e0 = (try it.next()).?;
    try testing.expectEqualStrings("uid", e0.key);
    try testing.expectEqualStrings("4711", e0.val);
    try testing.expectEqualStrings("theme", (try it.next()).?.key);
    try testing.expect((try it.next()) == null);

    // Flash: popped once.
    try s.putValue("flash", "saved");
    var small: [3]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, s.popValue("flash", &small));
    try testing.expectEqualStrings("saved", (try s.getValue("flash")).?); // not lost
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("saved", (try s.popValue("flash", &buf)).?);
    try testing.expect((try s.popValue("flash", &buf)) == null);
    try testing.expect((try s.getValue("flash")) == null);

    try testing.expect(try s.removeValue("theme"));
    s.kept = false;
    s.clearValues();
    try testing.expect(s.kept);
    try testing.expectEqual(@as(usize, 0), s.data().len);
    try testing.expect((try s.getValue("uid")) == null);

    try testing.expectError(error.InvalidKey, s.putValue("", "x"));
    try testing.expectError(error.InvalidKey, s.putValue(&@as([256]u8, @splat('k')), "x"));
    const huge: [max_session_bytes]u8 = @splat('v');
    try testing.expectError(error.Overflow, s.putValue("k", &huge));
    try testing.expectEqual(@as(usize, 0), s.data().len); // a refused put changed nothing
}

test "Session values: raw setData on the same session is Malformed, never a value or a panic" {
    var s: Session = .{};
    try s.setData("uid=42");
    try testing.expectError(error.Malformed, s.getValue("uid"));
    try testing.expectError(error.Malformed, s.putValue("uid", "1"));
    try testing.expectError(error.Malformed, s.removeValue("uid"));
    var buf: [8]u8 = undefined;
    try testing.expectError(error.Malformed, s.popValue("uid", &buf));
    var it = s.valueIterator();
    try testing.expectError(error.Malformed, it.next());
    try testing.expectEqualStrings("uid=42", s.data()); // untouched
    s.clearValues(); // the way out
    try s.putValue("uid", "1");
}

test "model: the key/value layer agrees with an ordered map on random operations" {
    const Reach = enum { put_new, put_replace, overflow, invalid_key, removed, remove_absent, popped, too_small, cleared, malformed };
    var reach = @as([@typeInfo(Reach).@"enum".field_names.len]usize, @splat(0));
    const key_pool = [_][]const u8{ "uid", "a", "flash", "csrf", "theme", strRepeat("k", 255), strRepeat("x", 40), "lang" };
    for (0..(if (@import("builtin").mode == .debug) 100 else 400)) |case_seed| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var prng = std.Random.DefaultPrng.init(case_seed);
        const rnd = prng.random();
        var md: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
        var s: Session = .{};
        var scratch: [max_session_bytes]u8 = undefined;

        for (0..60 + rnd.uintLessThan(usize, 80)) |step| {
            errdefer std.debug.print("values model: seed={d} step={d}\n", .{ case_seed, step });
            const key = key_pool[rnd.uintLessThan(usize, key_pool.len)];
            switch (rnd.uintLessThan(u8, 12)) {
                0, 1, 2, 3, 4 => {
                    const vlen: usize = if (rnd.uintLessThan(u8, 10) == 0) 1000 + rnd.uintLessThan(usize, 2200) else rnd.uintLessThan(usize, 40);
                    rnd.bytes(scratch[0..vlen]);
                    // The size the encoding would have afterwards.
                    var size: usize = 0;
                    for (md.keys(), md.values()) |k, v| size += 3 + k.len + v.len;
                    const old: usize = if (md.get(key)) |v| 3 + key.len + v.len else 0;
                    const after = (if (size == 0) 1 else 1 + size) - old + 3 + key.len + vlen;
                    if (after > max_session_bytes) {
                        try testing.expectError(error.Overflow, s.putValue(key, scratch[0..vlen]));
                        reach[@backingInt(Reach.overflow)] += 1;
                    } else {
                        try s.putValue(key, scratch[0..vlen]);
                        reach[@backingInt(if (old != 0) Reach.put_replace else Reach.put_new)] += 1;
                        try md.put(arena, key, try arena.dupe(u8, scratch[0..vlen]));
                    }
                },
                5 => {
                    const long_key: [256]u8 = @splat('z');
                    const bad_key: []const u8 = if (rnd.boolean()) "" else &long_key;
                    try testing.expectError(error.InvalidKey, s.putValue(bad_key, "v"));
                    reach[@backingInt(Reach.invalid_key)] += 1;
                },
                6, 7 => {
                    const had = md.contains(key);
                    try testing.expectEqual(had, try s.removeValue(key));
                    if (had) _ = md.orderedRemove(key);
                    reach[@backingInt(if (had) Reach.removed else Reach.remove_absent)] += 1;
                },
                8, 9 => {
                    var pbuf: [64]u8 = undefined;
                    const blen = rnd.uintLessThan(usize, pbuf.len + 1);
                    if (md.get(key)) |v| {
                        if (v.len > blen) {
                            try testing.expectError(error.BufferTooSmall, s.popValue(key, pbuf[0..blen]));
                            reach[@backingInt(Reach.too_small)] += 1;
                        } else {
                            try testing.expectEqualSlices(u8, v, (try s.popValue(key, pbuf[0..blen])).?);
                            _ = md.orderedRemove(key);
                            reach[@backingInt(Reach.popped)] += 1;
                        }
                    } else try testing.expect((try s.popValue(key, pbuf[0..blen])) == null);
                },
                10 => if (rnd.uintLessThan(u8, 3) == 0) {
                    s.clearValues();
                    md.clearRetainingCapacity();
                    reach[@backingInt(Reach.cleared)] += 1;
                },
                else => if (rnd.uintLessThan(u8, 6) == 0) {
                    // A raw payload on the same session: every access says so.
                    try s.setData("not a value blob");
                    try testing.expectError(error.Malformed, s.getValue(key));
                    s.clearValues();
                    md.clearRetainingCapacity();
                    reach[@backingInt(Reach.malformed)] += 1;
                },
            }
            // The whole state agrees: same entries, same order.
            var it = s.valueIterator();
            for (md.keys(), md.values()) |k, v| {
                const e = (try it.next()).?;
                try testing.expectEqualSlices(u8, k, e.key);
                try testing.expectEqualSlices(u8, v, e.val);
                try testing.expectEqualSlices(u8, v, (try s.getValue(k)).?);
            }
            try testing.expect((try it.next()) == null);
        }
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("values model reach: {t} never hit\n", .{@as(Reach, @fromBackingInt(@intCast(i)))});
        return error.ModelDoesNotReach;
    };
}

test "created word: the remember bit and the timestamp share it; any 63-bit time round-trips" {
    const times = [_]i64{ 0, 1, -1, 1000, -5000, std.math.maxInt(i64) >> 1, std.math.minInt(i64) >> 1, 1_800_000_000 * std.time.ns_per_s, -1_800_000_000 * std.time.ns_per_s };
    for (times) |t| for ([_]bool{ false, true }) |flag| {
        const d = decodeCreated(encodeCreated(t, flag));
        try testing.expectEqual(t, d.created);
        try testing.expectEqual(flag, d.remember);
    };
    // Out of range saturates instead of wrapping into the other sign.
    try testing.expectEqual(created_max, decodeCreated(encodeCreated(std.math.maxInt(i64), false)).created);
    try testing.expectEqual(created_min, decodeCreated(encodeCreated(std.math.minInt(i64), true)).created);
    // A record written before the flag existed (positive time, bit 63 clear) reads as off.
    try testing.expect(!decodeCreated(@bitCast(@as(i64, 1_790_000_000_000_000_000))).remember);
}

/// The `Set-Cookie` value `Manager.save` stamps for `s` (slice into `out_buf`).
fn setCookieOf(m: *const Manager, s: *Session, out_buf: *[1024]u8) []const u8 {
    var out: Writer = .fixed(out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    m.save(&rw, s);
    rw.end() catch unreachable;
    return headerValue(out.buffered(), "Set-Cookie").?;
}

fn knownSession(known_id: []const u8) Session {
    var s: Session = .{};
    @memcpy(s.id_buf[0..known_id.len], known_id);
    s.id_len = known_id.len;
    s.created_ns = 1;
    s.last_seen_ns = 1;
    return s;
}

test "persist_cookie: the three Set-Cookie shapes, byte for byte (and the clearing cookie unchanged)" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    const tail = "; Secure; HttpOnly; SameSite=Lax";
    var out_buf: [1024]u8 = undefined;
    const idle = 10 * std.time.ns_per_s;

    // 1. Default: every cookie carries Max-Age -- today's bytes.
    const m_default = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .clock = env.clk.clock(), .idle_timeout_ns = idle });
    var s1 = knownSession(strRepeat("deadbeef", 8));
    try testing.expectEqualStrings("session=" ++ (strRepeat("deadbeef", 8)) ++ "; Path=/; Max-Age=10" ++ tail, setCookieOf(&m_default, &s1, &out_buf));

    // 2. persist_cookie = false, not remembered: a browser-session cookie.
    const m_session = try Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .clock = env.clk.clock(), .idle_timeout_ns = idle, .persist_cookie = false });
    var s2 = knownSession(strRepeat("cafebabe", 8));
    try testing.expectEqualStrings("session=" ++ (strRepeat("cafebabe", 8)) ++ "; Path=/" ++ tail, setCookieOf(&m_session, &s2, &out_buf));

    // 3. persist_cookie = false, rememberMe(true): Max-Age again.
    var s3 = knownSession(strRepeat("feedface", 8));
    s3.rememberMe(true);
    try testing.expectEqualStrings("session=" ++ (strRepeat("feedface", 8)) ++ "; Path=/; Max-Age=10" ++ tail, setCookieOf(&m_session, &s3, &out_buf));

    // The default manager ignores the flag; rememberMe(false) is off again.
    var s4 = knownSession(strRepeat("0123abcd", 8));
    s4.rememberMe(true);
    s4.rememberMe(false);
    try testing.expectEqualStrings("session=" ++ (strRepeat("0123abcd", 8)) ++ "; Path=/" ++ tail, setCookieOf(&m_session, &s4, &out_buf));

    // The clearing cookie is the same for both.
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    m_session.destroy(&rw, strRepeat("cafebabe", 8));
    try rw.end();
    try testing.expectEqualStrings("session=; Path=/; Max-Age=-1" ++ tail, headerValue(out.buffered(), "Set-Cookie").?);
}

test "rememberMe: the flag survives save/load through RamcacheStore" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });
    var s: Session = .{};
    m.create(&s);
    try testing.expect(!s.remember);
    s.rememberMe(true);
    try testing.expect(s.kept); // marks the session modified
    try testing.expect(m.persist(&s));
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(s.id(), &l));
    try testing.expect(l.remember);
    try testing.expectEqual(s.created_ns, l.created_ns); // the timestamp is untouched by the flag
    l.rememberMe(false);
    try testing.expect(m.persist(&l));
    var l2: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(s.id(), &l2));
    try testing.expect(!l2.remember);
    // Rotating the id keeps it.
    l2.rememberMe(true);
    m.regenerate(&l2);
    try testing.expect(m.persist(&l2));
    var l3: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(l2.id(), &l3));
    try testing.expect(l3.remember);
}

test "rememberMe: the flag survives save/load and a restart through KvStore, also on a negative clock" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    env.clk.now_ns = -5000; // a Clock may have any origin
    var m = try env.manager();
    var s: Session = .{};
    m.create(&s);
    try testing.expectEqual(@as(i64, -5000), s.created_ns);
    s.rememberMe(true);
    try testing.expect(m.persist(&s));
    const id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(id);

    try env.restart();
    m = try env.manager();
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
    try testing.expect(l.remember);
    try testing.expectEqual(@as(i64, -5000), l.created_ns);
    // Timeouts still count from the negative origin.
    env.clk.now_ns = -5000 + 100_001;
    try testing.expectEqual(Manager.LoadResult.expired, m.lookup(id, &l));
}

test "middleware: persist_cookie = false gives a session cookie until the handler calls rememberMe" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .clock = env.clk.clock(),
        .idle_timeout_ns = 10 * std.time.ns_per_s,
        .absolute_timeout_ns = 100 * std.time.ns_per_s,
        .persist_cookie = false,
    });
    var app = App{ .manager = &m, .action = .put_uid };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);
    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;

    const first = getWithCookie(&r, null, &out, &rbody);
    const sc1 = headerValue(first, "Set-Cookie").?;
    try testing.expect(std.mem.indexOf(u8, sc1, "Max-Age") == null);
    try testing.expect(std.mem.indexOf(u8, sc1, "Expires") == null);
    var id_buf: [64]u8 = undefined;
    @memcpy(&id_buf, cookieId(sc1));
    const id: []const u8 = &id_buf;

    // Logging in with "remember me": from now on the cookie persists.
    app.action = .remember;
    const second = getWithCookie(&r, id, &out, &rbody);
    try testing.expect(std.mem.indexOf(u8, headerValue(second, "Set-Cookie").?, "Max-Age=10;") != null);
    app.action = .read_only;
    const third = getWithCookie(&r, id, &out, &rbody);
    try testing.expect(std.mem.indexOf(u8, headerValue(third, "Set-Cookie").?, "Max-Age=10;") != null);

    // A different visitor who did not tick the box still gets a session cookie.
    app.action = .put_uid;
    const other = getWithCookie(&r, null, &out, &rbody);
    try testing.expect(std.mem.indexOf(u8, headerValue(other, "Set-Cookie").?, "Max-Age") == null);
}

test "middleware: putValue creates and persists a session; a flash message is read once" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
    var app = App{ .manager = &m, .action = .flash_set };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);
    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;

    const first = getWithCookie(&r, null, &out, &rbody); // no setData / keep: putValue alone persists
    var id_buf: [64]u8 = undefined;
    @memcpy(&id_buf, cookieId(headerValue(first, "Set-Cookie").?));
    const id: []const u8 = &id_buf;
    app.action = .flash_pop;
    try testing.expectEqualStrings("saved!", bodyOf(getWithCookie(&r, id, &out, &rbody)));
    try testing.expectEqualStrings("<none>", bodyOf(getWithCookie(&r, id, &out, &rbody))); // gone: the pop was saved
}

/// `uid`-matching callback for `Manager.iterate`: logout-everywhere.
const Logout = struct {
    uid: []const u8,
    seen: usize = 0,
    stop_after: usize = std.math.maxInt(usize),

    fn visit(ctx: ?*anyopaque, s: *const Session) IterateAction {
        const c: *Logout = @ptrCast(@alignCast(ctx.?));
        c.seen += 1;
        if (c.seen >= c.stop_after) return .stop;
        const v = (s.getValue("uid") catch return .keep) orelse return .keep;
        return if (std.mem.eql(u8, v, c.uid)) .destroy else .keep;
    }
};

/// Five sessions in `m`: three of user "A", two of user "B".
fn fiveUsers(m: *const Manager, ids: *[5][64]u8) !void {
    for (ids, [_][]const u8{ "A", "A", "A", "B", "B" }) |*id, uid| {
        var s: Session = .{};
        m.create(&s);
        try s.putValue("uid", uid);
        try testing.expect(m.persist(&s));
        @memcpy(id, s.id());
    }
}

test "Manager.iterate: logout-everywhere for one user over KvStore; the CAS still holds" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    var m = try env.manager();
    var ids: [5][64]u8 = undefined;
    try fiveUsers(&m, &ids);
    // Not sessions: another key of the same Db, and a junk value under the prefix.
    try env.db.put("user:1", "not a session");
    try env.db.put("session:short", "xy");

    var stale: Session = .{}; // a request of user A already in flight
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(&ids[0], &stale));

    var ctx: Logout = .{ .uid = "A" };
    try testing.expectEqual(@as(usize, 3), try m.iterate(testing.allocator, &ctx, Logout.visit));
    try testing.expectEqual(@as(usize, 5), ctx.seen); // the two non-sessions were not shown
    var l: Session = .{};
    for (ids[0..3]) |*id| try testing.expectEqual(Manager.LoadResult.absent, m.lookup(id, &l));
    for (ids[3..5]) |*id| {
        try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
        try testing.expectEqualStrings("B", (try l.getValue("uid")).?);
    }
    // The destroy bumped the generation: the in-flight request cannot bring A back.
    try testing.expect(!m.persist(&stale));
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(&ids[0], &l));

    // Nothing left of A; B untouched.
    ctx = .{ .uid = "A" };
    try testing.expectEqual(@as(usize, 0), try m.iterate(testing.allocator, &ctx, Logout.visit));
    try testing.expectEqual(@as(usize, 2), ctx.seen);

    // `.stop` ends it early and destroys nothing.
    ctx = .{ .uid = "B", .stop_after = 1 };
    try testing.expectEqual(@as(usize, 0), try m.iterate(testing.allocator, &ctx, Logout.visit));
    try testing.expectEqual(@as(usize, 1), ctx.seen);

    // Past the idle timeout nothing is shown.
    env.clk.now_ns += 20_000;
    ctx = .{ .uid = "B" };
    try testing.expectEqual(@as(usize, 0), try m.iterate(testing.allocator, &ctx, Logout.visit));
    try testing.expectEqual(@as(usize, 0), ctx.seen);
}

test "Manager.iterate: RamcacheStore cannot enumerate" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try env.manager(.{ .idle = 10_000, .absolute = 100_000 });
    var ctx: Logout = .{ .uid = "A" };
    try testing.expectError(error.Unsupported, m.iterate(testing.allocator, &ctx, Logout.visit));
    try testing.expectEqual(@as(usize, 0), ctx.seen);
}

fn sha256Of(id: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(id, &h, .{});
    return h;
}

test "hash_id_in_store: RamcacheStore is keyed by SHA-256(id); create/load/regenerate/destroy round-trip" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .clock = env.clk.clock(),
        .idle_timeout_ns = 10_000,
        .absolute_timeout_ns = 100_000,
        .hash_id_in_store = true,
    });
    var s: Session = .{};
    m.create(&s);
    try s.putValue("uid", "42");
    try testing.expect(m.persist(&s));

    // The raw id is not a key; its hash is.
    try testing.expect((try env.store.store().get(testing.allocator, s.id())) == null);
    const h = sha256Of(s.id());
    const rec = (try env.store.store().get(testing.allocator, &h)).?;
    testing.allocator.free(rec.record);

    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(s.id(), &l));
    try testing.expectEqualStrings(s.id(), l.id()); // the real id, not the key
    try testing.expectEqualStrings("42", (try l.getValue("uid")).?);
    // Presenting the hash as a cookie finds nothing (it would be hashed again).
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(&h, &l));

    // Regenerate: the old key dies, the new id works.
    const old_id = try testing.allocator.dupe(u8, s.id());
    defer testing.allocator.free(old_id);
    m.regenerate(&s);
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(old_id, &l));
    try testing.expect(m.persist(&s));
    try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(s.id(), &l));
    try testing.expect((try env.store.store().get(testing.allocator, s.id())) == null);

    // Destroy by cookie id.
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    m.destroy(&rw, s.id());
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(s.id(), &l));
    const h2 = sha256Of(s.id());
    try testing.expect((try env.store.store().get(testing.allocator, &h2)) == null);
}

test "hash_id_in_store: through the middleware (cookie carries the real id; revoke removes the record)" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = try Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .clock = env.clk.clock(),
        .idle_timeout_ns = 10 * std.time.ns_per_s,
        .absolute_timeout_ns = 100 * std.time.ns_per_s,
        .hash_id_in_store = true,
    });
    var app = App{ .manager = &m, .action = .put_uid };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", hSession);
    var out: [4096]u8 = undefined;
    var rbody: [1024]u8 = undefined;

    const first = getWithCookie(&r, null, &out, &rbody);
    var id_buf: [64]u8 = undefined;
    @memcpy(&id_buf, cookieId(headerValue(first, "Set-Cookie").?));
    const id: []const u8 = &id_buf;
    try testing.expectEqualStrings(id, bodyOf(first));
    app.action = .read_only;
    try testing.expectEqualStrings(id, bodyOf(getWithCookie(&r, id, &out, &rbody))); // loaded, not re-minted
    app.action = .revoke;
    try testing.expect(std.mem.indexOf(u8, headerValue(getWithCookie(&r, id, &out, &rbody), "Set-Cookie").?, "Max-Age=-1") != null);
    var l: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup(id, &l));
}

test "hash_id_in_store: KvStore keys are prefix ++ SHA-256(id); iterate shows the store key, not a cookie id" {
    var env: KvEnv = undefined;
    try env.init();
    defer env.deinit();
    var m = try Manager.init(testing.allocator, env.store.store(), .{
        .io = testing.io,
        .clock = env.clk.clock(),
        .idle_timeout_ns = 10_000,
        .absolute_timeout_ns = 100_000,
        .hash_id_in_store = true,
    });
    var ids: [5][64]u8 = undefined;
    try fiveUsers(&m, &ids);

    // On disk: five keys, each prefix ++ 32 raw bytes; none contains a cookie id.
    const listing = try env.db.keys(testing.allocator, "session:");
    defer listing.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 5), listing.keys.len);
    for (listing.keys) |k| {
        try testing.expectEqual(@as(usize, "session:".len + 32), k.len);
        for (ids) |id| try testing.expect(std.mem.indexOf(u8, k, &id) == null);
    }
    var kb: [96]u8 = undefined;
    const raw_key = try std.fmt.bufPrint(&kb, "session:{s}", .{&ids[0]});
    try testing.expect(!env.db.exists(raw_key));
    const h = sha256Of(&ids[0]);
    const hashed_key = try std.fmt.bufPrint(&kb, "session:{s}", .{&h});
    try testing.expect(env.db.exists(hashed_key));

    // The callback's s.id() is the store key: 32 bytes, equal to SHA-256 of one of the cookie ids.
    const Probe = struct {
        ids: *const [5][64]u8,
        matched: usize = 0,
        fn visit(ctx: ?*anyopaque, s: *const Session) IterateAction {
            const p: *@This() = @ptrCast(@alignCast(ctx.?));
            if (s.id().len != 32) return .stop;
            for (p.ids) |*id| {
                const hh = sha256Of(id);
                if (std.mem.eql(u8, s.id(), &hh)) p.matched += 1;
            }
            return .keep;
        }
    };
    var probe: Probe = .{ .ids = &ids };
    _ = try m.iterate(testing.allocator, &probe, Probe.visit);
    try testing.expectEqual(@as(usize, 5), probe.matched);

    // Logout-everywhere works on the hashed store; cookie ids stop resolving.
    var ctx: Logout = .{ .uid = "A" };
    try testing.expectEqual(@as(usize, 3), try m.iterate(testing.allocator, &ctx, Logout.visit));
    var l: Session = .{};
    for (ids[0..3]) |*id| try testing.expectEqual(Manager.LoadResult.absent, m.lookup(id, &l));
    for (ids[3..5]) |*id| try testing.expectEqual(Manager.LoadResult.loaded, m.lookup(id, &l));
    try testing.expect(!env.db.exists(hashed_key));
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}

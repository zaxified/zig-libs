// SPDX-License-Identifier: MIT

//! sessions — server-side web sessions + CSRF as a `router` middleware.
//!
//! A session is server-side state keyed by an opaque, unguessable id that the
//! browser echoes in a cookie. The id is generated from a CSPRNG
//! (`std.Io.random`, threaded in at construction — never the removed
//! `std.crypto.random`, never a test-only `DefaultPrng`), so a session id can
//! be neither guessed nor forged. The state lives in a pluggable `Store`
//! (default: a bounded, TTL-evicting `ramcache`); the cookie carries only the
//! id.
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
//! `std.atomic.Mutex` (`ramcache` is single-owner). Per-request `Session` state
//! lives on the serving thread's stack. The `Set-Cookie` value is staged in a
//! thread-local buffer (the response writer stores header slices uncopied and
//! serializes them lazily at `writeHead`, after the handler returns — a stack
//! buffer would dangle; task-per-connection makes the thread-local safe).

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");
const cookies = @import("cookies");
const ramcache = @import("ramcache");

const csrf = @import("csrf.zig");

pub const meta = .{
    .platform = .any,
    .role = .server,
    // The Manager is immutable once built; the only mutable state is the
    // Store, whose default impl serializes cache access behind its own lock.
    .concurrency = .threadsafe,
    .model_after = "OWASP Session Management + CSRF Prevention Cheat Sheets",
    .deps = .{ "router", "http", "cookies", "ramcache" },
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
/// `Manager.init` rejects anything below this — a caller-configured
/// `id_bytes` of, say, 1 (8 bits) would make the session id brute-forceable.
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
const record_header_len = 16;

// ── clock injection (deterministic under test) ──────────────────────────────

/// Monotonic time source for timeout accounting, injected so tests are
/// deterministic. Non-decreasing; only differences matter (the store is
/// in-memory and never persists, so a monotonic origin is fine).
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) i64,

    /// The OS monotonic clock — the production default and the only place the
    /// module reads a real clock.
    pub const monotonic: Clock = .{ .nowFn = monotonicNowNs };

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

// ── the Store interface ─────────────────────────────────────────────────────

pub const StoreError = error{OutOfMemory};

/// A key→record store the `Manager` persists sessions through. The record is
/// the opaque encoded session (`Manager` owns the layout); the store only
/// moves bytes. A default `RamcacheStore` is provided; a distributed backend
/// (Redis, …) is a future adapter implementing this same vtable.
pub const Store = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Return a `gpa`-owned copy of the record stored under `id` (caller
        /// frees), or null when absent. A copy — not a borrow — because the
        /// backing store may mutate/evict the slot the moment the store's own
        /// lock is released.
        get: *const fn (ptr: *anyopaque, gpa: Allocator, id: []const u8) StoreError!?[]u8,
        /// Insert or replace the record under `id`.
        put: *const fn (ptr: *anyopaque, id: []const u8, record: []const u8) void,
        /// Remove the record under `id` (idempotent).
        delete: *const fn (ptr: *anyopaque, id: []const u8) void,
    };

    pub fn get(s: Store, gpa: Allocator, id: []const u8) StoreError!?[]u8 {
        return s.vtable.get(s.ptr, gpa, id);
    }
    pub fn put(s: Store, id: []const u8, record: []const u8) void {
        s.vtable.put(s.ptr, id, record);
    }
    pub fn delete(s: Store, id: []const u8) void {
        s.vtable.delete(s.ptr, id);
    }
};

/// The default `Store`, over a caller-owned `ramcache.Cache`. `ramcache` is
/// single-owner (`meta.concurrency = .single_owner`), so every touch is
/// serialized behind this store's **own** `std.atomic.Mutex` — making the
/// store safe from all of `http.Server`'s connection threads at once.
///
/// `ramcache` has no single-key delete in its public API, so `delete` writes a
/// zero-length **tombstone** value (`get` reports an empty record as absent);
/// a real session record is always ≥ `record_header_len` bytes, so the empty
/// value is unambiguous. The tombstone occupies one bounded cache slot until
/// it is overwritten or LRU-evicted.
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

    fn getImpl(ptr: *anyopaque, gpa: Allocator, id: []const u8) StoreError!?[]u8 {
        const self: *RamcacheStore = @ptrCast(@alignCast(ptr));
        const now = self.clock.now();
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const v = self.cache.get(id, now, 0) orelse return null;
        if (v.len == 0) return null; // tombstone
        return try gpa.dupe(u8, v);
    }

    fn putImpl(ptr: *anyopaque, id: []const u8, record: []const u8) void {
        const self: *RamcacheStore = @ptrCast(@alignCast(ptr));
        const now = self.clock.now();
        lockSpin(&self.lock);
        defer self.lock.unlock();
        self.cache.put(id, record, now, self.ttl_ns, 0);
    }

    fn deleteImpl(ptr: *anyopaque, id: []const u8) void {
        const self: *RamcacheStore = @ptrCast(@alignCast(ptr));
        const now = self.clock.now();
        lockSpin(&self.lock);
        defer self.lock.unlock();
        self.cache.put(id, "", now, self.ttl_ns, 0); // tombstone
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
    }

    /// Mark the session for destruction (logout): the middleware evicts it
    /// from the store and expires the cookie instead of saving.
    pub fn revoke(s: *Session) void {
        s.revoked = true;
    }
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

    /// Build a manager. `gpa` is used only for the short-lived decode copies
    /// `Store.get` hands back (the store owns its own storage). Asserts
    /// `min_id_bytes <= id_bytes <= max_id_bytes` — an `id_bytes` below the
    /// floor would make session ids brute-forceable.
    pub fn init(gpa: Allocator, store: Store, options: Options) Manager {
        std.debug.assert(options.id_bytes >= min_id_bytes and options.id_bytes <= max_id_bytes);
        std.debug.assert(options.cookie_name.len != 0);
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
        const rec = (m.store.get(m.gpa, sid) catch return .absent) orelse return .absent;
        defer m.gpa.free(rec);
        if (rec.len < record_header_len) return .absent; // corrupt
        const created = std.mem.readInt(i64, rec[0..8], .little);
        const last_seen = std.mem.readInt(i64, rec[8..16], .little);
        const payload = rec[record_header_len..];
        if (payload.len > out.data_buf.len) return .absent; // corrupt / oversized

        const now = m.clock.now();
        if (m.absolute_timeout_ns > 0 and now -| created > m.absolute_timeout_ns) {
            m.store.delete(sid);
            return .expired;
        }
        if (m.idle_timeout_ns > 0 and now -| last_seen > m.idle_timeout_ns) {
            m.store.delete(sid);
            return .expired;
        }

        out.* = .{};
        @memcpy(out.id_buf[0..sid.len], sid);
        out.id_len = sid.len;
        out.created_ns = created;
        out.last_seen_ns = now; // refresh idle window
        @memcpy(out.data_buf[0..payload.len], payload);
        out.data_len = payload.len;
        out.is_new = false;
        return .loaded;
    }

    /// Persist `s` to the store and stamp a refreshed `Set-Cookie`. Called by
    /// the middleware after the handler. Best-effort on the cookie: if the
    /// handler already flushed the response head (a large streamed body), the
    /// store is still updated but the cookie can't be (re)issued this response
    /// — a documented limit for new sessions behind an early flush.
    pub fn save(m: *const Manager, res: *http.Server.ResponseWriter, s: *Session) void {
        s.last_seen_ns = m.clock.now();
        var buf: [record_header_len + max_session_bytes]u8 = undefined;
        std.mem.writeInt(i64, buf[0..8], s.created_ns, .little);
        std.mem.writeInt(i64, buf[8..16], s.last_seen_ns, .little);
        @memcpy(buf[record_header_len..][0..s.data_len], s.data());
        m.store.put(s.id(), buf[0 .. record_header_len + s.data_len]);
        m.writeCookie(res, s.id(), maxAgeSeconds(m.idle_timeout_ns));
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
        m.store.delete(sid);
        m.writeCookie(res, "", -1);
    }

    /// Rotate the session id, carrying the data over and killing the old id in
    /// the store — the session-fixation defense (call it right after a
    /// privilege change, e.g. login). The new id is persisted on the next
    /// `save` (the middleware's post-handler save covers it) — that save is
    /// safe even though it's unconditional, because `s.id()` already reflects
    /// the *new* id by the time it runs: it can only (re-)persist the new
    /// record, never resurrect the old, just-deleted one. `s.regenerated` is
    /// set so that invariant is explicit rather than implicit in `id()`'s
    /// side effect.
    pub fn regenerate(m: *const Manager, s: *Session) void {
        m.store.delete(s.id()); // old id dead in the store
        m.newId(s); // overwrite id; created + data preserved
        s.regenerated = true;
    }

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
        m.io.random(slice);
        const hex = "0123456789abcdef";
        for (slice, 0..) |b, i| {
            out.id_buf[2 * i] = hex[b >> 4];
            out.id_buf[2 * i + 1] = hex[b & 0x0f];
        }
        out.id_len = m.id_bytes * 2;
    }

    fn writeCookie(m: *const Manager, res: *http.Server.ResponseWriter, value: []const u8, max_age: i64) void {
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
        // Stage into a thread-local buffer: the response writer keeps the
        // header slice uncopied and serializes it lazily at writeHead, after
        // this middleware returns — a stack buffer would dangle.
        const v = sc.bufPrint(&cookie_buf) catch return; // too long / invalid → skip
        res.addSetCookie(v) catch {}; // HeadersSent (early flush) → best-effort
    }
};

fn maxAgeSeconds(idle_ns: i64) i64 {
    if (idle_ns <= 0) return default_absolute_timeout_ns / std.time.ns_per_s;
    return @divTrunc(idle_ns, std.time.ns_per_s);
}

// The Set-Cookie value must outlive the whole request (see `writeCookie`).
// Task-per-connection makes this per-thread buffer valid until the head is
// flushed. Sized for name + 2*max_id_bytes hex + every attribute.
threadlocal var cookie_buf: [512]u8 = undefined;

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
    if (s.revoked) {
        m.destroy(ctx.res, s.id());
    } else {
        m.save(ctx.res, &s);
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

test {
    _ = csrf;
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
    fn manager(e: *Env, opts: struct { idle: i64 = 0, absolute: i64 = 0 }) Manager {
        return Manager.init(testing.allocator, e.store.store(), .{
            .io = testing.io, // real CSPRNG-backed test Io
            .clock = e.clk.clock(),
            .idle_timeout_ns = opts.idle,
            .absolute_timeout_ns = opts.absolute,
        });
    }
};

/// Persist a session straight into the store (bypasses the cookie writer).
fn seed(m: *const Manager, s: *const Session) void {
    var buf: [record_header_len + max_session_bytes]u8 = undefined;
    std.mem.writeInt(i64, buf[0..8], s.created_ns, .little);
    std.mem.writeInt(i64, buf[8..16], s.last_seen_ns, .little);
    @memcpy(buf[record_header_len..][0..s.data_len], s.data());
    m.store.put(s.id(), buf[0 .. record_header_len + s.data_len]);
}

test "create → seed → lookup round-trips id and data" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = env.manager(.{ .idle = 10_000, .absolute = 100_000 });

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
    var m = env.manager(.{ .idle = 10_000, .absolute = 100_000 });

    var loaded: Session = .{};
    try testing.expectEqual(Manager.LoadResult.absent, m.lookup("deadbeefdeadbeefdeadbeefdeadbeef", &loaded));
}

test "expired session (idle window) → expired + evicted" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = env.manager(.{ .idle = 500, .absolute = 100_000 });

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
    var m = env.manager(.{ .idle = 1_000_000, .absolute = 5_000 });

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
    var m = env.manager(.{ .idle = 10_000, .absolute = 100_000 });

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

test "min_id_bytes floor: default and at-floor id_bytes are accepted" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    // Default (32 bytes) — fine.
    _ = Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io });
    // Exactly at the floor — fine.
    _ = Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .id_bytes = min_id_bytes });
    // Exactly at the ceiling — fine.
    _ = Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .id_bytes = max_id_bytes });
}

test "insecure escape hatch drops Secure; default keeps it" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    const secure = Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io });
    try testing.expect(secure.secure);
    const insecure = Manager.init(testing.allocator, env.store.store(), .{ .io = testing.io, .allow_insecure_cookie = true });
    try testing.expect(!insecure.secure);
}

// ── middleware tests (offline — through http.Server.serveStream) ─────────────

const App = struct {
    manager: *Manager,
    action: enum { touch, write_big, revoke, regenerate } = .touch,
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
    var m = env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
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

test "middleware: revoke expires the cookie and evicts the session" {
    var env = Env.init();
    env.wire();
    defer env.deinit();
    var m = env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
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
    var m = env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
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
    var m = env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
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
    var m = env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
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

// SPDX-License-Identifier: MIT

//! h2_upstream — an HTTP/2 **upstream** connection pool for the reverse
//! proxy: it keeps ONE multiplexed h2 connection per backend origin and
//! lets many proxied requests share it (streams demuxed by the existing
//! `h2_client.Session`). This is the back-side counterpart of the h1
//! `Client`'s idle pool — but where h1 checks a whole connection *out* per
//! request, h2's entire value is multiplexing, so here every request runs
//! as a fresh **stream** on the one shared connection instead.
//!
//! ## Where it sits (the proxy seam)
//!
//! `proxy.zig` owns request/response *translation* (hop-by-hop stripping,
//! `X-Forwarded-*` / `Via`, status/header/body relay — shared with the h1
//! path); this module owns *connection multiplexing, dialing, reuse and
//! failure recovery*. The proxy, when a backend selects `.h2c`/`.h2`, builds
//! the pseudo-header request form and drives this pool:
//!
//!     const call = try pool.begin(backend, parts);   // opens a stream
//!     var res = try pool.complete(call);             // collects it
//!     defer res.deinit(pool.gpa);
//!
//! `begin` and `complete` are split precisely so a caller can launch several
//! streams before collecting any — that is what puts multiple proxied
//! requests concurrently in flight on the ONE connection (`begin` A, `begin`
//! B, `complete` A, `complete` B — both streams coexist on the wire; the
//! multiplex proof). `roundtrip` is the fused `begin`+`complete` for the
//! common one-at-a-time relay.
//!
//! ## Concurrency (and its honest bound)
//!
//! An `h2_client.Session` is **single-owner and blocking**: `awaitResponse`
//! pumps the socket, mutating shared demux state, so exactly one task may
//! touch a session at a time. Each shared session therefore carries an
//! `std.Io.Mutex` that serializes ALL of its I/O (both the brief `begin` send and the
//! blocking `complete` await). Consequences:
//! - Requests genuinely **multiplex on the wire**: nothing here checks a
//!   connection out exclusively, and any streams already sent keep running
//!   while another is collected — the demux table folds interleaved server
//!   frames onto the right stream regardless of order.
//! - But response *collection* is serialized per connection: while one task
//!   blocks in `complete`, another cannot `begin`/`complete` on the same
//!   backend until it returns. Full parallel-in-flight across OS threads is
//!   bounded by that (a genuinely parallel h2 proxy needs a dedicated
//!   per-connection reader task — a larger async redesign deliberately not
//!   taken here, to reuse the existing session engine rather than fork a
//!   second h2 stack). For deterministic simultaneity, issue several
//!   `begin`s before the first `complete`.
//! Distinct backends never contend (per-entry locks); dialing a cold backend
//! is serialized per backend (a `dial_mutex`) so a burst opens one
//! connection, not N.
//!
//! ## Bodies (a documented limitation vs. the h1 path)
//!
//! The reused `h2_client.Session` assembles a request body from memory and a
//! response body into memory (its per-stream `ArrayList`). So h2 upstreaming
//! **buffers** each body (bounded — the proxy caps both), where the h1
//! forward path streams them. Flow control is still exercised end to end: a
//! body larger than the 64 KiB initial window drives WINDOW_UPDATE on send
//! (`sendBody` blocks for grants) and on receive (`awaitResponse` replenishes
//! the window). The h2 client now surfaces a response trailer section
//! (`Response.trailers`), but this pool does not relay it to the proxied
//! response — trailer forwarding through the reverse proxy is still open.
//!
//! ## Failure recovery
//!
//! A connection-scoped death (peer GOAWAY, protocol error, transport close)
//! **retires** the shared session: the entry re-dials a fresh connection on
//! the next `begin`, and the dead session is freed once its last in-flight
//! `complete` drains. In-flight streams on a retired session still finish
//! against the session they were sent on (each `Call` pins its own session),
//! so a retire never strands a stream mid-collection.

const std = @import("std");
const testkit = @import("testkit");
const http = @import("root.zig");
const Client = @import("Client.zig");
const h2_client = @import("h2_client.zig");
const Allocator = std.mem.Allocator;

/// Dial + request + await failures. `Client.Error` covers the dial (connect/
/// TLS/DNS); `h2_client.Error` covers the stream (protocol/reset/goaway).
pub const Error = Client.Error || h2_client.Error || error{
    /// `Backend.host` is wider than an `Entry` can hold (see
    /// `Entry.max_host`). Reported rather than truncated: a truncated host
    /// silently defeated connection reuse and eventually wedged the pool.
    BackendHostTooLong,
};

/// One upstream origin to multiplex onto. `secure` selects h2-over-TLS,
/// which requires a custom `Options.dialer` (this module ships only the
/// cleartext h2c dialer — TLS termination stays bring-your-own, matching
/// the module's layering).
pub const Backend = struct {
    host: []const u8,
    port: u16,
    secure: bool = false,
};

/// The §8.3 pseudo-header request form + regular headers, ready to open a
/// stream. `proxy.zig` fills this from a `Server.Request` (with hop-by-hop
/// stripping and forwarding headers already applied).
pub const RequestParts = struct {
    method: http.Method,
    /// The `:method` token when `method` is `.other`.
    method_token: []const u8 = "",
    /// `:path` — origin-form, query included (e.g. the raw request target).
    path: []const u8,
    /// `:authority` (backend authority, or the client's Host when preserved).
    authority: []const u8,
    /// `:scheme` — "http" for h2c, "https" for h2-over-TLS (RFC 9113 §8.3.1).
    scheme: []const u8 = "http",
    /// Regular headers; the h2 client lowercases them and drops
    /// connection-specific ones + Host (§8.2.2).
    headers: []const http.Header = &.{},
    /// In-memory request body; null/empty → END_STREAM on HEADERS.
    body: ?[]const u8 = null,
    /// Cap on the buffered response body (`error.BodyTooLarge` over it);
    /// null = the session's `h2_client.Options.max_response_body_bytes`.
    max_response_body_bytes: ?u64 = null,
};

/// Custom dial seam (bring-your-own-TLS). Return a NEW `*Client.H2Session`
/// for `backend` — e.g. establish a TLS connection offering `http.alpn_offer`
/// and, when ALPN negotiated "h2", `Client.connectH2Over` the plaintext
/// stream. The pool owns the returned session and closes it via `.close()`.
pub const Dialer = struct {
    ctx: ?*anyopaque = null,
    dialFn: *const fn (ctx: ?*anyopaque, backend: Backend) Client.Error!*Client.H2Session,
};

pub const Options = struct {
    /// The h1/h2 `Client` whose connect plumbing the built-in h2c dialer
    /// reuses (`connectH2c`). Its `Options.buffer_pool`, if set, backs the
    /// dialed sessions' slabs.
    client: *Client,
    /// h2 SETTINGS + DoS limits for dialed sessions (see `h2_client.Options`).
    h2_options: h2_client.Options = .{},
    /// Max distinct backends tracked; each holds at most one multiplexed
    /// session. A `begin` for a new backend beyond this fails
    /// `error.ConnectFailed` (the pool refuses to grow unbounded).
    max_backends: u16 = 256,
    /// Custom dial seam; null = the built-in cleartext h2c dialer. Required
    /// for any `secure` backend.
    dialer: ?Dialer = null,
};

/// A shared, ref-counted h2 session. `mutex` serializes all of its I/O
/// (single-owner engine); `refs`/`retired` are guarded by the pool mutex.
const Shared = struct {
    hs: *Client.H2Session,
    /// Held across the session's socket I/O: an `std.Io.Mutex`, so a task
    /// waiting for it yields to the `Io` (a spinning or thread-yielding
    /// waiter starves a holder suspended in the socket when the `Io` runs
    /// several tasks on one thread).
    mutex: std.Io.Mutex = .init,
    /// Entry's own ref (+1) plus one per in-flight `Call`.
    refs: usize,
    /// Marked dead: the entry has dropped its ref and re-dials next time;
    /// this session is freed when its last `Call` drains.
    retired: bool = false,
};

/// Per-backend slot: the current shared session (if any) and a dial lock so
/// a burst on a cold backend opens exactly one connection.
const Entry = struct {
    host_buf: [max_host]u8 = undefined,
    host_len: u8,
    port: u16,
    secure: bool,
    current: ?*Shared = null,
    /// Held across a dial (a network connect): an `std.Io.Mutex`, as above.
    dial_mutex: std.Io.Mutex = .init,

    /// Widest backend host an entry can hold, inline. A DNS name is at most
    /// 253 octets (RFC 1035 §2.3.4's 255-octet wire form minus the length
    /// and root bytes) and a bracketed IPv6 literal at most 47, so this
    /// covers every addressable backend. A host that does NOT fit is
    /// rejected (`error.BackendHostTooLong`), never truncated — see
    /// `getOrCreateEntry`.
    const max_host = 255;

    fn host(e: *const Entry) []const u8 {
        return e.host_buf[0..e.host_len];
    }

    fn matches(e: *const Entry, b: Backend) bool {
        return e.port == b.port and e.secure == b.secure and
            std.ascii.eqlIgnoreCase(e.host(), b.host);
    }
};

/// A stream opened by `begin`, pinned to the exact session it was sent on so
/// `complete` collects it even if the entry re-dials meanwhile.
pub const Call = struct {
    entry: *Entry,
    shared: *Shared,
    sid: u31,
    max_body: ?u64,
};

pub const Pool = struct {
    gpa: Allocator,
    options: Options,
    mutex: std.atomic.Mutex = .unlocked,
    entries: std.ArrayList(*Entry) = .empty,
    /// Lifetime count of fresh upstream dials — the reuse proof in tests: a
    /// steady count across many proxied requests to one backend means they
    /// shared one connection.
    dials: std.atomic.Value(usize) = .init(0),

    pub fn init(gpa: Allocator, options: Options) Pool {
        return .{ .gpa = gpa, .options = options };
    }

    /// Close every live upstream session and free bookkeeping. Call only
    /// once nothing else can touch the pool (mirrors `Client.deinit`).
    pub fn deinit(p: *Pool) void {
        for (p.entries.items) |e| {
            if (e.current) |s| {
                s.hs.close();
                p.gpa.destroy(s);
            }
            p.gpa.destroy(e);
        }
        p.entries.deinit(p.gpa);
        p.* = undefined;
    }

    /// The `Io` every session of this pool does its I/O in (the `Client`'s).
    fn io(p: *const Pool) std.Io {
        return p.options.client.io;
    }

    /// Total upstream dials over the pool's life (diagnostics/tests).
    pub fn dialCount(p: *const Pool) usize {
        return p.dials.load(.monotonic);
    }

    /// Number of backends currently holding a live session.
    pub fn liveSessionCount(p: *Pool) usize {
        lockSpin(&p.mutex);
        defer p.mutex.unlock();
        var n: usize = 0;
        for (p.entries.items) |e| {
            if (e.current) |s| {
                if (!s.retired) n += 1;
            }
        }
        return n;
    }

    // ── the request lifecycle ────────────────────────────────────────────────

    /// Open a stream for `parts` on `backend`'s shared session (dialing it if
    /// cold or retired), send HEADERS + body under flow control, and return a
    /// `Call` to collect with `complete`. Retries once on a fresh session if
    /// the send hits a dead connection (safe: nothing of the response has been
    /// read yet, and the in-memory body can be resent verbatim).
    pub fn begin(p: *Pool, backend: Backend, parts: RequestParts) Error!Call {
        var shared = try p.acquireShared(backend);
        const sid = p.send(shared, parts) catch |err| retry: {
            if (!isDeadSession(err)) {
                p.releaseShared(shared);
                return err;
            }
            // Retire the dead session and try exactly once more, fresh.
            const entry = p.entryFor(backend).?;
            p.retire(entry, shared);
            p.releaseShared(shared);
            shared = try p.acquireShared(backend);
            break :retry p.send(shared, parts) catch |err2| {
                p.releaseShared(shared);
                return err2;
            };
        };
        return .{ .entry = p.entryFor(backend).?, .shared = shared, .sid = sid, .max_body = parts.max_response_body_bytes };
    }

    /// Collect the response for a `Call` (blocks, pumping the shared
    /// connection — which advances every in-flight stream on it). Consumes
    /// the `Call`; the returned `Response` is owned (free with
    /// `Response.deinit(pool.gpa)`).
    pub fn complete(p: *Pool, call: Call) Error!h2_client.Response {
        const shared = call.shared;
        const pio = p.io();
        shared.mutex.lockUncancelable(pio);
        const res = shared.hs.session.awaitResponseCapped(call.sid, call.max_body orelse shared.hs.session.max_response_body_bytes);
        // A connection-scoped death (or a latched GOAWAY) retires the session
        // so the next request re-dials; a lone stream reset does not.
        const broken = shared.hs.session.broken != null or shared.hs.session.goaway != null;
        shared.mutex.unlock(pio);

        if (res) |r| {
            if (broken) p.retire(call.entry, shared);
            p.releaseShared(shared);
            return r;
        } else |err| {
            if (broken or isDeadSession(err)) p.retire(call.entry, shared);
            p.releaseShared(shared);
            return err;
        }
    }

    /// Fused `begin` + `complete` for the one-request-at-a-time relay.
    pub fn roundtrip(p: *Pool, backend: Backend, parts: RequestParts) Error!h2_client.Response {
        const call = try p.begin(backend, parts);
        return p.complete(call);
    }

    // ── internals ────────────────────────────────────────────────────────────

    /// Send HEADERS (+ body) for `parts` on `shared` under its I/O lock.
    fn send(p: *Pool, shared: *Shared, parts: RequestParts) Error!u31 {
        const pio = p.io();
        shared.mutex.lockUncancelable(pio);
        defer shared.mutex.unlock(pio);
        return shared.hs.request(parts.method, parts.path, .{
            .method_token = parts.method_token,
            .scheme = parts.scheme,
            .authority = parts.authority,
            .headers = parts.headers,
            .body = parts.body,
        });
    }

    /// Find the entry for `backend` (or null). Under the pool lock.
    fn entryFor(p: *Pool, backend: Backend) ?*Entry {
        lockSpin(&p.mutex);
        defer p.mutex.unlock();
        for (p.entries.items) |e| if (e.matches(backend)) return e;
        return null;
    }

    /// Get-or-create the entry for `backend`. Under the pool lock; the entry
    /// pointer is stable for the pool's life (heap-allocated, never removed).
    fn getOrCreateEntry(p: *Pool, backend: Backend) Error!*Entry {
        lockSpin(&p.mutex);
        defer p.mutex.unlock();
        for (p.entries.items) |e| if (e.matches(backend)) return e;
        if (p.entries.items.len >= p.options.max_backends) return error.ConnectFailed;
        // A host wider than the entry used to be TRUNCATED into `host_buf`
        // while `matches` compared the truncated copy against the full
        // `backend.host` — different lengths, so the entry never matched
        // its own backend. Every `begin` then allocated a fresh entry and
        // dialed a NEW upstream connection (multiplexing and reuse both
        // silently lost), and once `max_backends` entries had accumulated —
        // they are never removed — every further request to that backend
        // failed `ConnectFailed` forever. Reject it up front instead: this
        // is a configuration error, and a silent wrong answer is the worst
        // possible way to report one.
        if (backend.host.len > Entry.max_host) return error.BackendHostTooLong;
        const e = p.gpa.create(Entry) catch return error.OutOfMemory;
        errdefer p.gpa.destroy(e);
        const n: u8 = @intCast(backend.host.len);
        e.* = .{ .host_len = n, .port = backend.port, .secure = backend.secure };
        @memcpy(e.host_buf[0..n], backend.host[0..n]);
        p.entries.append(p.gpa, e) catch return error.OutOfMemory;
        return e;
    }

    /// Return a ref-incremented live `*Shared` for `backend`, dialing a fresh
    /// connection when the entry is cold or its session was retired. Dialing
    /// is serialized per entry (`dial_mutex`) so a burst opens one connection.
    fn acquireShared(p: *Pool, backend: Backend) Error!*Shared {
        const entry = try p.getOrCreateEntry(backend);

        // Fast path: a live current session.
        {
            lockSpin(&p.mutex);
            if (entry.current) |s| {
                if (!s.retired) {
                    s.refs += 1;
                    p.mutex.unlock();
                    return s;
                }
            }
            p.mutex.unlock();
        }

        // Cold/retired: dial under the per-entry dial lock (other backends
        // and the global pool lock stay free during the connect).
        entry.dial_mutex.lockUncancelable(p.io());
        defer entry.dial_mutex.unlock(p.io());

        // Re-check: someone may have dialed while we waited for the lock.
        {
            lockSpin(&p.mutex);
            if (entry.current) |s| {
                if (!s.retired) {
                    s.refs += 1;
                    p.mutex.unlock();
                    return s;
                }
            }
            p.mutex.unlock();
        }

        const hs = try p.dial(backend);
        errdefer hs.close();
        const shared = p.gpa.create(Shared) catch return error.OutOfMemory;
        shared.* = .{ .hs = hs, .refs = 2 }; // entry ref + this caller's ref
        lockSpin(&p.mutex);
        entry.current = shared;
        p.mutex.unlock();
        return shared;
    }

    /// Dial a fresh h2 connection to `backend` (custom dialer, or built-in
    /// cleartext h2c via the `Client`). Counts one dial.
    fn dial(p: *Pool, backend: Backend) Error!*Client.H2Session {
        _ = p.dials.fetchAdd(1, .monotonic);
        if (p.options.dialer) |d| return d.dialFn(d.ctx, backend);
        if (backend.secure) return error.TlsFailed; // needs a custom (TLS) dialer
        return p.options.client.connectH2c(backend.host, backend.port, p.options.h2_options);
    }

    /// Drop one ref on `shared`; close + free it when the last ref goes
    /// (only possible once it is retired — the entry ref is dropped by
    /// `retire`).
    fn releaseShared(p: *Pool, shared: *Shared) void {
        var free_it = false;
        {
            lockSpin(&p.mutex);
            shared.refs -= 1;
            free_it = shared.refs == 0;
            p.mutex.unlock();
        }
        if (free_it) {
            shared.hs.close();
            p.gpa.destroy(shared);
        }
    }

    /// Retire `shared`: mark it dead and, if it is still the entry's current
    /// session, detach it and drop the entry's ref (freeing it when no `Call`
    /// still holds it). Idempotent across concurrent callers.
    fn retire(p: *Pool, entry: *Entry, shared: *Shared) void {
        var free_it = false;
        {
            lockSpin(&p.mutex);
            shared.retired = true;
            if (entry.current == shared) {
                entry.current = null;
                shared.refs -= 1; // the entry's own ref
                free_it = shared.refs == 0;
            }
            p.mutex.unlock();
        }
        if (free_it) {
            shared.hs.close();
            p.gpa.destroy(shared);
        }
    }
};

/// A stream/await error meaning the connection itself is dead — the next
/// request must dial fresh. A lone `StreamReset` leaves the session usable
/// and is NOT one of these.
fn isDeadSession(err: anyerror) bool {
    return switch (err) {
        error.ProtocolError,
        error.GoawayReceived,
        error.StreamRefused,
        error.ConnectionClosed,
        error.WriteFailed,
        => true,
        else => false,
    };
}

/// Short-critical-section lock (bookkeeping only): plain spin, same idiom as
/// `Client`'s idle pool.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// Loopback: a real h2c backend (http's own h2 server) behind the pool. The
// end-to-end proxy integration (client → h1 proxy → h2 backend) lives in
// `proxy.zig`; here we exercise the pool's multiplex + reuse + recovery
// directly.

const testing = std.testing;
const Server = @import("Server.zig");

fn backendHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/echo")) {
        var buf: [1 << 20]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        _ = try req.reader().streamRemaining(&w);
        try rw.setHeader("X-Echoed", "1");
        try rw.writeAll(w.buffered());
    } else if (std.mem.eql(u8, req.path, "/hello")) {
        try rw.setHeader("Content-Type", "text/plain");
        try rw.writeAll("hello from h2 backend");
    } else {
        rw.setStatus(404);
        try rw.writeAll("nope");
    }
}

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

fn h2Backend(io: std.Io) !*Server {
    const s = try testing.allocator.create(Server);
    errdefer testing.allocator.destroy(s);
    s.* = Server.init(io, testing.allocator, .{ .handler = backendHandler, .enable_h2c = true });
    s.bind() catch |err| {
        s.deinit();
        testing.allocator.destroy(s);
        return testkit.loopbackSkip("h2 backend bind failed ({t})", .{err});
    };
    return s;
}

test "h2_upstream: a backend host too wide for an entry is REJECTED, not truncated" {
    // The bug this pins: `getOrCreateEntry` truncated the host into
    // `Entry.host_buf` while `Entry.matches` compared that truncated copy
    // against the FULL `backend.host`. Different lengths, so the entry could
    // never match its own backend — every request dialed a new upstream
    // connection (reuse and multiplexing silently lost), and after
    // `max_backends` (256) entries piled up, every further request to that
    // backend failed `ConnectFailed` permanently, since entries are never
    // removed. No dialing happens in this test: it is all pool bookkeeping.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var client = Client.init(threaded.io(), gpa, .{});
    defer client.deinit();
    var pool = Pool.init(gpa, .{ .client = &client });
    defer pool.deinit();

    // 255 bytes is the widest host an entry holds (`Entry.max_host`).
    // Accepted — and, decisively, it MATCHES ITSELF on the next lookup, so
    // one backend keeps exactly one entry and one connection.
    const host_255 = strRepeat("h", 255);
    const be_255: Backend = .{ .host = host_255, .port = 8080 };
    const e1 = try pool.getOrCreateEntry(be_255);
    try testing.expectEqual(@as(usize, 255), e1.host().len);
    try testing.expectEqualStrings(host_255, e1.host());
    try testing.expect(e1.matches(be_255));
    const e2 = try pool.getOrCreateEntry(be_255);
    try testing.expectEqual(e1, e2);
    try testing.expectEqual(@as(usize, 1), pool.entries.items.len);

    // 256 bytes: a typed error at the first call, and no entry is created.
    const host_256 = strRepeat("h", 256);
    const be_256: Backend = .{ .host = host_256, .port = 8080 };
    try testing.expectError(error.BackendHostTooLong, pool.getOrCreateEntry(be_256));
    try testing.expectError(error.BackendHostTooLong, pool.getOrCreateEntry(be_256));
    try testing.expectEqual(@as(usize, 1), pool.entries.items.len);

    // ...and the reason truncation could never have worked: a 255-byte entry
    // does not match a 256-byte backend, so the truncated entry was dead
    // weight the moment it was written.
    try testing.expect(!e1.matches(be_256));
}

test "h2_upstream: multiplex two proxied streams over one upstream connection" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const backend = try h2Backend(io);
    defer testing.allocator.destroy(backend);
    defer backend.deinit();
    const bt = try std.Thread.spawn(.{}, serveWrap, .{backend});
    defer bt.join();
    defer backend.shutdown();
    const port = backend.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var pool = Pool.init(gpa, .{ .client = &client });
    defer pool.deinit();

    const be: Backend = .{ .host = "127.0.0.1", .port = port };

    // Two streams launched before either is collected → both in flight on the
    // ONE connection (the multiplex proof).
    const call_a = pool.begin(be, .{
        .method = .post,
        .path = "/echo",
        .authority = "backend",
        .body = "stream-A-body",
    }) catch |err| {
        return testkit.loopbackSkip("loopback h2c begin A failed ({t})", .{err});
    };
    const call_b = try pool.begin(be, .{
        .method = .post,
        .path = "/echo",
        .authority = "backend",
        .body = "stream-B-body",
    });

    var res_b = try pool.complete(call_b);
    defer res_b.deinit(gpa);
    var res_a = try pool.complete(call_a);
    defer res_a.deinit(gpa);

    try testing.expectEqual(@as(u16, 200), res_a.status);
    try testing.expectEqualStrings("stream-A-body", res_a.body);
    try testing.expectEqual(@as(u16, 200), res_b.status);
    try testing.expectEqualStrings("stream-B-body", res_b.body);

    // One dial served both streams — they multiplexed on one connection.
    try testing.expectEqual(@as(usize, 1), pool.dialCount());
    try testing.expectEqual(@as(usize, 1), pool.liveSessionCount());
}

test "h2_upstream: many sequential roundtrips reuse the one connection" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const backend = try h2Backend(io);
    defer testing.allocator.destroy(backend);
    defer backend.deinit();
    const bt = try std.Thread.spawn(.{}, serveWrap, .{backend});
    defer bt.join();
    defer backend.shutdown();
    const port = backend.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var pool = Pool.init(gpa, .{ .client = &client });
    defer pool.deinit();

    const be: Backend = .{ .host = "127.0.0.1", .port = port };
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        var res = pool.roundtrip(be, .{
            .method = .get,
            .path = "/hello",
            .authority = "backend",
        }) catch |err| {
            return testkit.loopbackSkip("loopback h2c roundtrip failed ({t})", .{err});
        };
        defer res.deinit(gpa);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("hello from h2 backend", res.body);
    }
    // Eight requests, one dial: the connection was reused throughout.
    try testing.expectEqual(@as(usize, 1), pool.dialCount());
}

test "h2_upstream: large body proxied through (flow control / WINDOW_UPDATE)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const backend = try h2Backend(io);
    defer testing.allocator.destroy(backend);
    defer backend.deinit();
    const bt = try std.Thread.spawn(.{}, serveWrap, .{backend});
    defer bt.join();
    defer backend.shutdown();
    const port = backend.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var pool = Pool.init(gpa, .{ .client = &client });
    defer pool.deinit();

    const be: Backend = .{ .host = "127.0.0.1", .port = port };

    // 200 KiB — well past the 64 KiB initial window, so both the send-side
    // (sendBody blocking for grants) and the receive-side (awaitResponse
    // replenishing) WINDOW_UPDATE paths run.
    const payload = strRepeat("abcdefgh", 25 * 1024); // 200 KiB
    var res = pool.roundtrip(be, .{
        .method = .post,
        .path = "/echo",
        .authority = "backend",
        .body = payload,
    }) catch |err| {
        return testkit.loopbackSkip("loopback h2c large-body roundtrip failed ({t})", .{err});
    };
    defer res.deinit(gpa);
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqual(payload.len, res.body.len);
    try testing.expectEqualStrings(payload, res.body);
}

test "h2_upstream: buffer pool backs dialed sessions and is reused across dials" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const backend = try h2Backend(io);
    defer testing.allocator.destroy(backend);
    defer backend.deinit();
    const bt = try std.Thread.spawn(.{}, serveWrap, .{backend});
    defer bt.join();
    defer backend.shutdown();
    const port = backend.boundAddress().getPort();

    // Buffer pool sized to the h2 client's slab layout.
    const opts: Client.Options = .{};
    var bp = try Client.BufferPool.init(gpa, opts.read_buffer_size + opts.write_buffer_size, 4);
    defer bp.deinit();
    var client = Client.init(io, gpa, .{ .buffer_pool = &bp });
    defer client.deinit();

    const be: Backend = .{ .host = "127.0.0.1", .port = port };

    // First pool: one dial, one slab checked out; deinit returns it.
    {
        var pool = Pool.init(gpa, .{ .client = &client });
        defer pool.deinit();
        var res = pool.roundtrip(be, .{ .method = .get, .path = "/hello", .authority = "b" }) catch |err| {
            return testkit.loopbackSkip("loopback h2c dial failed ({t})", .{err});
        };
        res.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 1), bp.checkoutCount());
    try testing.expectEqual(@as(usize, 1), bp.idleCount()); // slab returned to the pool

    // Second pool dials again — and reuses the retained slab (no new alloc).
    {
        var pool = Pool.init(gpa, .{ .client = &client });
        defer pool.deinit();
        var res = try pool.roundtrip(be, .{ .method = .get, .path = "/hello", .authority = "b" });
        res.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 2), bp.checkoutCount());
    try testing.expectEqual(@as(usize, 1), bp.reuseCount()); // second dial reused the slab
    try testing.expectEqual(@as(usize, 1), bp.allocCount()); // only the first ever allocated
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

test "re-audit 2026-10-28: h2_upstream: a per-call max_response_body_bytes caps the proxied response" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const backend = try h2Backend(io);
    defer testing.allocator.destroy(backend);
    defer backend.deinit();
    const bt = try std.Thread.spawn(.{}, serveWrap, .{backend});
    defer bt.join();
    defer backend.shutdown();
    const port = backend.boundAddress().getPort();

    // The session's own cap is the (large) default; only the per-call cap
    // can refuse this 8 KiB echo.
    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var pool = Pool.init(gpa, .{ .client = &client });
    defer pool.deinit();
    const be: Backend = .{ .host = "127.0.0.1", .port = port };
    const payload = strRepeat("abcdefgh", 1024); // 8 KiB

    if (pool.roundtrip(be, .{
        .method = .post,
        .path = "/echo",
        .authority = "backend",
        .body = payload,
        .max_response_body_bytes = 1024,
    })) |r| {
        var res = r;
        res.deinit(gpa);
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.BodyTooLarge => {},
        else => return testkit.loopbackSkip("loopback h2c capped roundtrip failed ({t})", .{err}),
    }

    // The cap is per call: the same pool serves an uncapped call after it.
    var res = pool.roundtrip(be, .{
        .method = .post,
        .path = "/echo",
        .authority = "backend",
        .body = payload,
    }) catch |err| return testkit.loopbackSkip("loopback h2c roundtrip failed ({t})", .{err});
    defer res.deinit(gpa);
    try testing.expectEqual(payload.len, res.body.len);
}

// ── whole-module mutation run, wave 2 (2026-11-07): tests the schemata asked for ──

test "mutation run 2: h2_upstream — max_backends refuses a new backend without dialing; a secure backend without a dialer is TlsFailed" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var client = Client.init(io, gpa, .{});
    defer client.deinit();

    var pool = Pool.init(gpa, .{ .client = &client, .max_backends = 1 });
    defer pool.deinit();
    // Port 1 on loopback: nothing listens, the dial fails — but the entry
    // for this backend now exists and fills the one slot.
    if (pool.roundtrip(.{ .host = "127.0.0.1", .port = 1 }, .{ .method = .get, .path = "/", .authority = "a" })) |r| {
        var res = r;
        res.deinit(gpa);
        return error.SkipZigTest; // something answers on port 1
    } else |_| {}
    try testing.expectEqual(@as(usize, 1), pool.dialCount());
    try testing.expectError(error.ConnectFailed, pool.roundtrip(.{ .host = "127.0.0.1", .port = 2 }, .{ .method = .get, .path = "/", .authority = "b" }));
    try testing.expectEqual(@as(usize, 1), pool.dialCount()); // refused before any dial

    var pool2 = Pool.init(gpa, .{ .client = &client });
    defer pool2.deinit();
    try testing.expectError(error.TlsFailed, pool2.roundtrip(.{ .host = "127.0.0.1", .port = 1, .secure = true }, .{ .method = .get, .path = "/", .authority = "s" }));
}

test "mutation run 2: h2_upstream — a backend that GOAWAYs after every stream is re-dialed each time, and every retired session is freed" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const backend = try testing.allocator.create(Server);
    defer testing.allocator.destroy(backend);
    backend.* = Server.init(io, testing.allocator, .{
        .handler = backendHandler,
        .enable_h2c = true,
        .h2_limits = .{ .max_streams_per_connection = 1 },
    });
    defer backend.deinit();
    backend.bind() catch |err| return testkit.loopbackSkip("h2 backend bind failed ({t})", .{err});
    const bt = try std.Thread.spawn(.{}, serveWrap, .{backend});
    defer bt.join();
    defer backend.shutdown();
    const port = backend.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var pool = Pool.init(gpa, .{ .client = &client });
    defer pool.deinit();
    const be: Backend = .{ .host = "127.0.0.1", .port = port };
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var res = pool.roundtrip(be, .{ .method = .get, .path = "/hello", .authority = "backend" }) catch |err| {
            return testkit.loopbackSkip("loopback h2c roundtrip failed ({t})", .{err});
        };
        defer res.deinit(gpa);
        try testing.expectEqualStrings("hello from h2 backend", res.body);
    }
    try testing.expectEqual(@as(usize, 3), pool.dialCount());
    // The testing allocator's leak check is the other half of the assertion:
    // each retired session must be closed and freed once its last ref goes.
}

test "mutation run 2: h2_upstream — a request error that is not a dead session keeps the connection" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const backend = try h2Backend(io);
    defer testing.allocator.destroy(backend);
    defer backend.deinit();
    const bt = try std.Thread.spawn(.{}, serveWrap, .{backend});
    defer bt.join();
    defer backend.shutdown();
    const port = backend.boundAddress().getPort();
    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var pool = Pool.init(gpa, .{ .client = &client });
    defer pool.deinit();
    const be: Backend = .{ .host = "127.0.0.1", .port = port };
    {
        var res = pool.roundtrip(be, .{ .method = .get, .path = "/hello", .authority = "backend" }) catch |err| {
            return testkit.loopbackSkip("loopback h2c roundtrip failed ({t})", .{err});
        };
        res.deinit(gpa);
    }
    try testing.expectError(error.InvalidHeader, pool.roundtrip(be, .{
        .method = .get,
        .path = "/hello",
        .authority = "backend",
        .headers = &.{.{ .name = "x-bad", .value = "a\r\nb" }},
    }));
    {
        var res = try pool.roundtrip(be, .{ .method = .get, .path = "/hello", .authority = "backend" });
        res.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 1), pool.dialCount());
}

// ── tests (wave 4: a raw h2 backend, and the dial lock) ─────────────────────

const wave4_h2 = @import("h2.zig");
const wave4_hpack = @import("hpack.zig");

/// A one-connection h2c backend: finishes the handshake, takes the first
/// request and answers it by `script`, then reads until the client hangs up.
const Wave4Origin = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    script: Script,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: std.atomic.Value(u32) = .init(0),

    const Script = enum {
        /// RST_STREAM(CANCEL): a lone stream reset, the session stays usable.
        reset,
        /// GOAWAY (the stream is still covered by it), then RST_STREAM(CANCEL).
        goaway_then_reset,
    };

    fn run(p: *Wave4Origin) void {
        p.serve() catch {};
    }

    fn release(p: *Wave4Origin, port: u16) void {
        p.stop.store(1, .release);
        if (p.accepted.load(.acquire) != 0) return;
        const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
        const s = addr.connect(p.io, .{ .mode = .stream }) catch return;
        s.close(p.io);
    }

    fn flush(w: *std.Io.Writer, wire: *std.ArrayList(u8)) !void {
        if (wire.items.len == 0) return;
        try w.writeAll(wire.items);
        try w.flush();
        wire.clearRetainingCapacity();
    }

    fn serve(p: *Wave4Origin) !void {
        const gpa = testing.allocator;
        const s = try p.listener.accept(p.io);
        p.accepted.store(1, .release);
        defer s.close(p.io);
        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        var sw = s.writer(p.io, &wbuf);
        const r = &sr.interface;
        const w = &sw.interface;
        var conn: wave4_h2.Connection = .init(gpa, .server, .{});
        defer conn.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        var events: std.ArrayList(wave4_h2.Event) = .empty;
        defer {
            for (events.items) |*ev| ev.deinit(gpa);
            events.deinit(gpa);
        }
        try conn.sendPreface(&wire);
        try flush(w, &wire);
        var answered = false;
        while (true) {
            _ = try r.peekGreedy(1);
            const bytes = r.buffered();
            try conn.recv(bytes, &wire, &events);
            r.toss(bytes.len);
            var request_sid: ?u31 = null;
            for (events.items) |*ev| {
                switch (ev.*) {
                    .headers => |h| {
                        if (request_sid == null) request_sid = h.stream_id;
                    },
                    else => {},
                }
                ev.deinit(gpa);
            }
            events.clearRetainingCapacity();
            const id = request_sid orelse {
                try flush(w, &wire);
                continue;
            };
            if (!answered) {
                answered = true;
                switch (p.script) {
                    .reset => try conn.sendRstStream(&wire, id, .cancel),
                    .goaway_then_reset => {
                        try conn.sendGoaway(&wire, .no_error, "");
                        try conn.sendRstStream(&wire, id, .cancel);
                    },
                }
            }
            try flush(w, &wire);
        }
    }
};

// 23004 / 23005: `complete` retires the session when the connection is gone
// (`broken`, a latched GOAWAY) or the error says so, and keeps it for a lone
// stream reset. Two backends: a plain RST_STREAM leaves the session in the
// pool (a mutant that retires on any error drops it), and a GOAWAY that still
// covers the stream followed by the reset retires it although the reset
// itself is no dead-session error (a mutant that looks only at the error, or
// ANDs the two, keeps it). `liveSessionCount` reads the entry right after
// `complete` returned, before anything can redial.
fn wave4ResetCase(script: Wave4Origin.Script, want_live: usize) !void {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        return testkit.loopbackSkip("wave4 h2 origin listen failed ({t})", .{err});
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var origin: Wave4Origin = .{ .io = io, .listener = &listener, .script = script };
    const origin_thread = try std.Thread.spawn(.{}, Wave4Origin.run, .{&origin});
    defer origin_thread.join();
    defer origin.release(port);

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var pool = Pool.init(gpa, .{ .client = &client });
    defer pool.deinit();
    const be: Backend = .{ .host = "127.0.0.1", .port = port };
    try testing.expectError(error.StreamReset, pool.roundtrip(be, .{ .method = .get, .path = "/x", .authority = "backend" }));
    try testing.expectEqual(@as(usize, 1), pool.dialCount());
    try testing.expectEqual(want_live, pool.liveSessionCount());
}

test "wave4: h2_upstream: a lone stream reset keeps the session in the pool (23004, 23005)" {
    try wave4ResetCase(.reset, 1);
}

test "wave4: h2_upstream: a stream reset under a latched GOAWAY retires the session (23004, 23005)" {
    try wave4ResetCase(.goaway_then_reset, 0);
}

const Wave4DialGate = struct {
    client: *Client,
    io: std.Io,
    started: std.atomic.Value(u32) = .init(0),

    /// Holds the dial until both callers are inside `roundtrip`, then a
    /// margin, so the second one is certainly waiting on the dial lock.
    fn dial(ctx: ?*anyopaque, backend: Backend) Client.Error!*Client.H2Session {
        const g: *Wave4DialGate = @ptrCast(@alignCast(ctx.?));
        var spins: usize = 0;
        while (g.started.load(.acquire) < 2 and spins < 10_000) : (spins += 1)
            g.io.sleep(.fromMilliseconds(1), .awake) catch break;
        g.io.sleep(.fromMilliseconds(200), .awake) catch {};
        return g.client.connectH2c(backend.host, backend.port, .{});
    }
};

const Wave4Caller = struct {
    pool: *Pool,
    be: Backend,
    started: *std.atomic.Value(u32),
    ok: bool = false,

    fn run(c: *Wave4Caller) void {
        _ = c.started.fetchAdd(1, .acq_rel);
        var res = c.pool.roundtrip(c.be, .{ .method = .get, .path = "/hello", .authority = "backend" }) catch return;
        res.deinit(c.pool.gpa);
        c.ok = true;
    }
};

// 23013: two callers meet a cold entry. The one that gets the dial lock
// dials; the other must find the session in the re-check under the lock and
// not dial again. Without the re-check a burst dials once per caller. The
// dialer holds the first dial until both callers are in, so the dials
// overlap by construction (one-sided: with the re-check the count is 1
// whatever the timing).
test "wave4: h2_upstream: a burst against a cold backend dials once (23013)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const backend = try h2Backend(io);
    defer testing.allocator.destroy(backend);
    defer backend.deinit();
    const bt = try std.Thread.spawn(.{}, serveWrap, .{backend});
    defer bt.join();
    defer backend.shutdown();
    const port = backend.boundAddress().getPort();

    var client = Client.init(io, gpa, .{});
    defer client.deinit();
    var gate: Wave4DialGate = .{ .client = &client, .io = io };
    var pool = Pool.init(gpa, .{ .client = &client, .dialer = .{ .ctx = &gate, .dialFn = Wave4DialGate.dial } });
    defer pool.deinit();
    const be: Backend = .{ .host = "127.0.0.1", .port = port };

    var a: Wave4Caller = .{ .pool = &pool, .be = be, .started = &gate.started };
    var b: Wave4Caller = .{ .pool = &pool, .be = be, .started = &gate.started };
    const ta = try std.Thread.spawn(.{}, Wave4Caller.run, .{&a});
    const tb = try std.Thread.spawn(.{}, Wave4Caller.run, .{&b});
    ta.join();
    tb.join();
    try testing.expect(a.ok);
    try testing.expect(b.ok);
    try testing.expectEqual(@as(usize, 1), pool.dialCount());
}

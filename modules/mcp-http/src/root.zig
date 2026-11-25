// SPDX-License-Identifier: MIT

//! mcp-http — the MCP **Streamable HTTP** transport as a `router` middleware,
//! so a `mcp.Server` (JSON-RPC 2.0 tools / resources / prompts) is reachable
//! remotely over HTTP instead of only over stdio. Two revisions, decided per
//! POST like the server itself decides: the session-era transport
//! (2025-06-18 / 2025-11-25, described below) and the stateless one of
//! 2026-07-28 (`modern.zig`: no session, the request-metadata headers checked
//! against the body, `HeaderMismatch` -32020 as 400, the spec's 400/404
//! statuses, multi round-trip requests instead of server→client requests,
//! `subscriptions/listen`).
//!
//! A single endpoint (`/mcp` by default) where the client **POST**s one
//! JSON-RPC message. The response is delivered one of two ways:
//!
//! - **`application/json`** — a single response object (the default; also the
//!   only mode a client that doesn't `Accept: text/event-stream` gets).
//! - **SSE** (`text/event-stream`) — when the client accepts it, the response
//!   is an event stream so a tool call's `notifications/progress` reach the
//!   client **live**; each JSON-RPC message the server emits becomes one SSE
//!   `data:` event, and the stream closes after the response.
//!
//! A notification (or anything with no reply) answers **202 Accepted**, no
//! body, in either mode. It wraps the transport-agnostic
//! `mcp.Server.handleMessage`, which does all protocol work (version
//! negotiation, dispatch, error objects) and, per the MCP spec, rejects
//! JSON-RPC batches.
//!
//! ## Server→client requests (sampling / elicitation)
//!
//! `mcp.Server` can issue `sampling/createMessage` and `elicitation/create`.
//! Over HTTP those are **not** request/response within one connection: the
//! client's answer arrives as a *later, separate POST*, so nothing can park
//! waiting for it (same constraint as the `GET` stream — see `Sessions`).
//! What this transport wires up:
//!
//! - **Peer scoping — requires `sessions`.** Each session gets a numeric handle
//!   (`Sessions.tagOf`) passed to `mcp.Server.handleMessageFrom` as the *peer*.
//!   A response POSTed on session B can never resolve a request issued to
//!   session A, so one user's sampling completion or elicitation answer cannot
//!   be delivered into another user's tool call. **A stateless endpoint has no
//!   such handle** — every POST is peer 0, which the peer check cannot
//!   distinguish — so it refuses correlatable responses outright (400) unless
//!   you assert it serves a single client with
//!   `stateless_responses = .single_client`. See `Transport.StatelessResponses`.
//! - **Delivery.** A request issued from inside a `tools/call` rides that
//!   POST's own response — an SSE `data:` event in stream mode; in
//!   `application/json` mode the body must stay a single object, so it is
//!   queued for the session's `GET` stream instead. To issue one *outside* a
//!   call, write it to a `std.Io.Writer.Allocating` and `Sessions.push` the
//!   bytes:
//!
//!   ```zig
//!   var line: std.Io.Writer.Allocating = .init(gpa);
//!   defer line.deinit();
//!   _ = try server.sendSamplingRequest(&line.writer, req, .{
//!       .peer = sessions.tagOf(sid).?, .on_response = &onAnswer, .ctx = app,
//!   });
//!   _ = try sessions.push(sid, std.mem.trimEnd(u8, line.written(), "\n"));
//!   ```
//!
//! - **The answer.** The client POSTs its JSON-RPC response to `/mcp`; the
//!   server produces no reply for it, so the endpoint answers **202 Accepted**
//!   and the registered `mcp.ResponseHandler` runs during that POST.
//!
//! **Sessions** (optional — set `Transport.sessions` to a `*Sessions`): the
//! transport assigns an `Mcp-Session-Id` at `initialize`, validates it on later
//! requests (unknown ⇒ 404 so the client re-initializes), tears one down on
//! `DELETE /mcp`, and serves server→client messages on `GET /mcp` — a
//! drain-and-close SSE stream with resumable replay (`Last-Event-ID`); enqueue
//! with `Sessions.push`. Leave `sessions` null for a **stateless** server (no
//! session id; `GET`/`DELETE` → 405; a client's *response* to a server→client
//! request → 400, because a stateless endpoint cannot tell which client sent
//! it). See `Sessions` for the delivery model.
//!
//! ## Security
//!
//! **Origin validation** (the MCP-mandated DNS-rebinding defense) is built in:
//! set `Transport.allowed_origins` and a browser request forging another site's
//! `Origin` gets 403 (empty ⇒ accept all — the dev default). **Authentication**
//! is not: register an `aaa-gate`/`jwt` middleware **before** this one to gate
//! the endpoint (MCP has no read/write method split, so gate every POST). Bind
//! to loopback for a local integration, or terminate auth at a reverse proxy.
//!
//! ## Usage
//!
//! ```zig
//! var server = mcp.Server.init(gpa, .{ .name = "netops", .version = "1.0" });
//! defer server.deinit();
//! try server.addTool(.{ ... });
//! var transport = mcphttp.Transport{ .gpa = gpa, .server = &server };
//! try router.use(transport.middleware()); // after any auth/origin middleware
//! ```
//!
//! ## Concurrency
//!
//! `mcp.Server` holds mutable state (e.g. `client_initialized`) and is not
//! internally synchronized; `http.Server` serves from several connection
//! threads. Inject `Transport.lock` (see `Lock`) to serialize `handleMessage`
//! under a threaded server, or run the server single-threaded. Body reads and
//! response framing happen outside the lock.

const std = @import("std");
const clock_lib = @import("clock");
const sidhex = @import("sidhex.zig");
const router = @import("router");
const http = @import("http");
const mcp = @import("mcp");
const modern = @import("modern.zig");
const netaddr = @import("netaddr");
/// MCP authorization, resource-server side: the bearer gate and the RFC 9728
/// document (`Transport.auth`); see `auth.zig`.
pub const auth = @import("auth.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "MCP Streamable HTTP transport (2026-07-28 stateless + 2025-06-18 sessions) — `POST /mcp` with JSON or live SSE, header/body validation, Origin (DNS-rebind) guard.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .server,
    // Reentrant except the shared mcp.Server — inject Lock under a threaded
    // http.Server (documented).
    .concurrency = .reentrant,
    .model_after = "MCP Streamable HTTP transport (2026-07-28 and 2025-06-18); python-sdk captured session as oracle",
    .deps = .{ "router", "http", "mcp", "clock", "aaa-gate", "netaddr" },
};

/// Serialization seam for the shared `mcp.Server` under a multi-threaded
/// `http.Server` (same shape as `jwt.Lock`). Default `.none` is a no-op —
/// correct for a single-threaded server or an externally-synchronized one.
/// Plug a real mutex (`std.Thread.Mutex`) in for the default threaded server.
pub const Lock = struct {
    ctx: ?*anyopaque = null,
    lockFn: *const fn (?*anyopaque) void = noop,
    unlockFn: *const fn (?*anyopaque) void = noop,

    pub const none: Lock = .{};

    fn noop(_: ?*anyopaque) void {}
    fn acquire(l: Lock) void {
        l.lockFn(l.ctx);
    }
    fn release(l: Lock) void {
        l.unlockFn(l.ctx);
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

/// 128 bits from the kernel CSPRNG. Same shape as `ssh`/`bulletproofs` use —
/// `getrandom(2)` directly, retrying on `EINTR`, panicking rather than
/// returning weak bytes, because a session id that is merely *probably*
/// random is exactly the defect this replaced.
fn fillRandom(buf: []u8) void {
    if (@import("builtin").os.tag != .linux)
        @compileError("fillRandom: only the Linux getrandom(2) entropy path is wired up");
    var off: usize = 0;
    while (off < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            if (signed == -@as(isize, @backingInt(std.os.linux.E.INTR))) continue;
            @panic("getrandom failed");
        }
        off += @intCast(signed);
    }
}

fn monoNs() u64 {
    return clock_lib.monotonicNs();
}

/// Server-side session registry for the Streamable HTTP transport. Optional —
/// leave `Transport.sessions` null for a **stateless** server (no session id;
/// `GET`/`DELETE` → 405). When set, the transport assigns an `Mcp-Session-Id`
/// at `initialize`, validates it on later requests (unknown ⇒ 404, so the
/// client re-initializes), tears a session down on `DELETE`, and serves
/// server→client messages on `GET /mcp`.
///
/// **Delivery model — the `GET` stream is held open** (as the reference
/// SDKs' Streamable HTTP servers do): over a real connection a `GET` replays
/// every event queued after its `Last-Event-ID` and then stays open
/// (`http.Server.Hold`, see `Transport.hold_get`); each later `push` /
/// `pushTag` / `mcp` notification reaches it at once, with an `id:` for
/// resumption. One stream per session: a second `GET` while one is open is
/// 409. It ends when the client leaves, the session ends (`DELETE`,
/// `close`, eviction), the server shuts down or its queue overflows
/// (`Transport.listen_queue_bytes`); the client's `EventSource` reconnects
/// with `Last-Event-ID` and replays what it missed. Where no connection can
/// be held (socket-free `serveStream`, `hold_get = false`, a refused hold)
/// the stream is a drain-and-close long-poll: replay, then close, the client
/// reconnects for more. Events are buffered either way; nothing is lost
/// within the bounded replay buffer (`replay_depth`); a client gone longer
/// than that many events loses the overflow, so size it for your burst.
///
/// Thread-safe: all state sits behind one spinlock (short critical sections —
/// a map touch / an event copy, never socket I/O). `push` may be called from
/// any thread; `GET` handlers snapshot under the lock and write outside it, so
/// a concurrent `DELETE` can free a session without a use-after-free.
pub const Sessions = struct {
    gpa: std.mem.Allocator,
    lock: std.atomic.Mutex = .unlocked,
    map: std.StringHashMapUnmanaged(*Session) = .empty,
    /// Peer handle -> session, so `pushTag`/`hasTag` (once per notified peer)
    /// are O(1) instead of a scan of the whole table (sweep HS-5).
    by_tag: std.AutoHashMapUnmanaged(u64, *Session) = .empty,
    seq: u64 = 0,
    /// Buffered events retained per session for resumable replay. Older events
    /// are evicted; a client reconnecting past this depth loses them.
    replay_depth: usize = 256,
    /// Hard cap on live sessions. `create` refuses a new session past this,
    /// so an unauthenticated peer spamming `initialize` cannot grow the
    /// registry (and its per-session replay buffers) without bound.
    max_sessions: usize = 10_000,
    /// How long a session may go untouched before a full table may reclaim it.
    /// Only consulted when `create` would otherwise refuse, so an idle session
    /// on a quiet server is never taken away from a client that comes back.
    max_idle_ns: u64 = 30 * std.time.ns_per_min,

    const Session = struct {
        id: []const u8, // gpa-owned, stable for the session's life
        /// Stable numeric handle for this session, handed to
        /// `mcp.Server.handleMessageFrom` as the *peer*. It scopes the
        /// correlation of server→client requests: a sampling/elicitation answer
        /// POSTed on session B can never resolve a request issued to session A.
        tag: u64,
        events: std.ArrayList(StoredEvent) = .empty,
        next_event_id: u64 = 1,
        closing: bool = false,
        /// Monotonic nanoseconds at the last request that named this session.
        /// Without it a full table was a permanent lockout: nothing but an
        /// explicit `DELETE` ever freed a session
        /// (W2 re-audit 2026-09-02, `mcp-http` F2).
        last_seen_ns: u64,
        /// The `GET` stream held open on this session (`heldGet`), or null.
        /// Set and cleared under the registry lock; `enqueue` feeds it.
        held: ?*http.Server.Hold = null,
    };
    const StoredEvent = struct { id: u64, data: []const u8 }; // data gpa-owned

    pub fn init(gpa: std.mem.Allocator) Sessions {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Sessions) void {
        lockSpin(&self.lock);
        var it = self.map.valueIterator();
        while (it.next()) |sp| self.freeSession(sp.*);
        self.map.deinit(self.gpa);
        self.by_tag.deinit(self.gpa);
        self.lock.unlock();
        self.* = undefined;
    }

    fn freeSession(self: *Sessions, s: *Session) void {
        // A held `GET` ends (its owner finds the session gone and writes no more).
        if (s.held) |h| h.finish();
        _ = self.by_tag.remove(s.tag);
        for (s.events.items) |e| self.gpa.free(e.data);
        s.events.deinit(self.gpa);
        self.gpa.free(s.id);
        self.gpa.destroy(s);
    }

    /// A freshly created session: its id (store-owned, stable — the caller
    /// echoes it in the `Mcp-Session-Id` header) together with its peer handle.
    /// Both are returned from `create` so the caller never has to look the tag
    /// back up by id: that second lookup was a failure mode with no honest
    /// answer (the session exists — it was just made), and it used to be
    /// swallowed with `orelse 0`, i.e. dropped into the shared peer-0 bucket.
    pub const Created = struct {
        id: []const u8,
        tag: u64,
        /// The peer handle of a session evicted to make room, if any. The
        /// caller must `mcp.Server.forgetPeer` it.
        evicted: ?u64 = null,
    };

    /// Create a session; returns its id and peer handle (see `Created`).
    fn create(self: *Sessions) error{ OutOfMemory, TooManySessions }!Created {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        var evicted: ?u64 = null;
        if (self.map.count() >= self.max_sessions) {
            // A full table used to be permanent: nothing but an explicit
            // DELETE ever freed a session, so `max_sessions` abandoned
            // `initialize`s locked every later client out forever. The cap
            // bounded memory and the quantity it bounded never fell on its own
            // (W2 re-audit 2026-09-02, `mcp-http` F2).
            evicted = self.evictIdle() orelse return error.TooManySessions;
        }
        self.seq += 1;
        // ⚠ 128 bits from the CSPRNG, and it has to be: possession of this id
        // is the ENTIRE gate on GET/POST/DELETE for a session, so the module's
        // advertised peer-scoping property ("a response POSTed on session B
        // can never resolve a request issued to session A") holds only if a
        // peer cannot guess another peer's id.
        //
        // It used to be `monoNs() ^ (@intFromPtr(self) *% K)` in the high half
        // and a plain incrementing `seq` in the low half, with a comment
        // calling that "hard to guess". It was not. The low half is exact —
        // bracket the victim's `initialize` with two of your own and its seq
        // is yours+1. The high half's `K` is constant for the process, so
        // XORing two of your own ids cancels it completely and leaves only the
        // clock delta between two closely-spaced calls: measured, **2^20
        // candidates**, each testable over the wire as one `GET`. Reproduced
        // end to end — read another session's pending `sampling/createMessage`
        // and answer it with forged content
        // (W2 re-audit 2026-09-02, `mcp-http` F1).
        var raw: [16]u8 = undefined;
        fillRandom(&raw);
        var idbuf: [32]u8 = undefined;
        // Not `std.fmt` `{x}`: it indexes a digit table by each secret nibble
        // (ctgrind `mcp-http/sid`, 2026-10-10). Same lowercase text.
        sidhex.encode(&idbuf, &raw);
        const id_txt: []const u8 = &idbuf;
        // A collision would silently merge two peers, which is the very thing
        // the id exists to prevent. At 128 bits it never happens; refusing is
        // still the only honest answer if it does.
        if (self.map.contains(id_txt)) return error.TooManySessions;
        const id = try self.gpa.dupe(u8, id_txt);
        errdefer self.gpa.free(id);
        const s = try self.gpa.create(Session);
        errdefer self.gpa.destroy(s);
        // seq is allocated under the lock and never reused, so it is a unique
        // peer handle for this session's lifetime.
        s.* = .{ .id = id, .tag = self.seq, .last_seen_ns = monoNs() };
        try self.by_tag.put(self.gpa, s.tag, s);
        errdefer _ = self.by_tag.remove(s.tag);
        try self.map.put(self.gpa, id, s);
        return .{ .id = id, .tag = s.tag, .evicted = evicted };
    }

    /// Drop the least-recently-touched session **if** it has been idle longer
    /// than `max_idle_ns`. Caller holds the lock. Returns the freed session's
    /// peer handle, so the caller can hand it to `mcp.Server.forgetPeer` — the
    /// server keeps per-peer handshake state and has no other way to learn
    /// that a session is gone.
    ///
    /// Deliberately not a plain LRU eviction: taking a live session away from
    /// a client to make room for a new one would turn a flood into a
    /// cross-client denial instead of an outage, which is worse. An abandoned
    /// flood self-heals; a busy server still refuses.
    fn evictIdle(self: *Sessions) ?u64 {
        const now = monoNs();
        var oldest_key: ?[]const u8 = null;
        var oldest_seen: u64 = std.math.maxInt(u64);
        var it = self.map.iterator();
        while (it.next()) |e| {
            const seen = e.value_ptr.*.last_seen_ns;
            if (seen < oldest_seen) {
                oldest_seen = seen;
                oldest_key = e.key_ptr.*;
            }
        }
        const key = oldest_key orelse return null;
        if (now -| oldest_seen < self.max_idle_ns) return null;
        const kv = self.map.fetchRemove(key) orelse return null;
        const tag = kv.value.tag;
        self.freeSession(kv.value);
        return tag;
    }

    fn exists(self: *Sessions, id: []const u8) bool {
        return self.tagOf(id) != null;
    }

    /// The session's peer handle (see `Session.tag`), or null when unknown.
    /// Pass it as `mcp.RequestOptions.peer` when issuing a server→client
    /// request for this session, so only that session's answer resolves it.
    pub fn tagOf(self: *Sessions, id: []const u8) ?u64 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return null;
        s.last_seen_ns = monoNs();
        return s.tag;
    }

    /// Tear a session down (on `DELETE`). Returns its peer handle when it
    /// existed, so the caller can `mcp.Server.forgetPeer` it (see `evictIdle`).
    fn destroy(self: *Sessions, id: []const u8) ?u64 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const kv = self.map.fetchRemove(id) orelse return null;
        const tag = kv.value.tag;
        self.freeSession(kv.value);
        return tag;
    }

    /// Enqueue a server→client message for a session's `GET` stream (deliver on
    /// the client's next connect/reconnect). Callable from any thread. Returns
    /// false if the session is unknown. `data` is copied.
    pub fn push(self: *Sessions, id: []const u8, data: []const u8) error{OutOfMemory}!bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return false;
        try self.enqueue(s, data);
        return true;
    }

    /// `push` by peer handle (`Session.tag`): how `Transport.pushSink` delivers
    /// `mcp`'s change notifications to a session's `GET` stream.
    pub fn pushTag(self: *Sessions, tag: u64, data: []const u8) error{OutOfMemory}!bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.by_tag.get(tag) orelse return false;
        try self.enqueue(s, data);
        return true;
    }

    /// Whether `tag` names a live session.
    fn hasTag(self: *Sessions, tag: u64) bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        return self.by_tag.contains(tag);
    }

    /// Caller holds the lock.
    fn enqueue(self: *Sessions, s: *Session, data: []const u8) error{OutOfMemory}!void {
        const copy = try self.gpa.dupe(u8, data);
        errdefer self.gpa.free(copy);
        defer if (self.replay_depth == 0) self.gpa.free(copy); // not stored
        // `replay_depth == 0` keeps no replay buffer at all (a held `GET` still
        // gets the event live); it used to index `items[0]` of an empty list.
        while (s.events.items.len > 0 and s.events.items.len >= self.replay_depth) {
            self.gpa.free(s.events.items[0].data);
            _ = s.events.orderedRemove(0);
        }
        const id = s.next_event_id;
        s.next_event_id += 1;
        if (self.replay_depth > 0) {
            // The id is consumed only once the event is stored (or deliberately not).
            s.events.append(self.gpa, .{ .id = id, .data = copy }) catch |e| {
                s.next_event_id -= 1;
                return e;
            };
        }
        // A held `GET` gets it at once; the buffer keeps it for a reconnect
        // (`Last-Event-ID`). A queue overflow ends that stream: the client
        // reconnects and replays.
        if (s.held) |h| {
            var aw: std.Io.Writer.Allocating = .init(self.gpa);
            defer aw.deinit();
            var idbuf: [24]u8 = undefined;
            const idstr = std.mem.print(&idbuf, "{d}", .{id}) catch unreachable;
            http.sse.writeEvent(&aw.writer, .{ .id = idstr, .data = copy }) catch return;
            h.send(aw.written()) catch {};
        }
    }

    /// Mark a session closing — its next `GET` drains what is queued and ends.
    pub fn close(self: *Sessions, id: []const u8) void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.map.get(id)) |s| {
            s.closing = true;
            if (s.held) |h| h.finish();
        }
    }

    const Attach = union(enum) { unknown, conflict, ok: struct { closing: bool } };

    /// Start holding `hold` as the session's `GET` stream: under one lock,
    /// snapshot every event after `after` into `out` and make `hold` the
    /// stream later events go to, so none falls between the replay and the
    /// live feed. `.conflict` when another stream is held and its peer is
    /// still there (one stream per session, as the reference SDKs).
    fn attachHold(
        self: *Sessions,
        id: []const u8,
        hold: *http.Server.Hold,
        after: u64,
        arena: std.mem.Allocator,
        out: *std.ArrayList(StoredEvent),
    ) error{OutOfMemory}!Attach {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return .unknown;
        if (s.held) |h| if (!h.gone()) return .conflict;
        for (s.events.items) |e| {
            if (e.id > after)
                try out.append(arena, .{ .id = e.id, .data = try arena.dupe(u8, e.data) });
        }
        s.held = hold;
        return .{ .ok = .{ .closing = s.closing } };
    }

    /// Stop feeding `hold`; whether the session is closing (or gone: false).
    /// After this returns no feeder touches `hold`.
    fn detachHold(self: *Sessions, id: []const u8, hold: *http.Server.Hold) bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return false;
        if (s.held == hold) s.held = null;
        return s.closing;
    }

    /// Whether a `GET` stream is held on the session now (null: unknown session).
    fn heldNow(self: *Sessions, id: []const u8) ?bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return null;
        return if (s.held) |h| !h.gone() else false;
    }

    /// Snapshot (into `arena`) every event with id > `after`, returning them via
    /// `out`; the bool is the session's `closing` flag. Null ⇒ unknown session.
    /// Copies under the lock so the caller can write to the socket lock-free.
    fn drainAfter(
        self: *Sessions,
        id: []const u8,
        after: u64,
        arena: std.mem.Allocator,
        out: *std.ArrayList(StoredEvent),
    ) error{OutOfMemory}!?bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return null;
        for (s.events.items) |e| {
            if (e.id > after)
                try out.append(arena, .{ .id = e.id, .data = try arena.dupe(u8, e.data) });
        }
        return s.closing;
    }
};

/// A peer handle no session and no other request uses: from 2^62 up (session
/// tags count from 1). A 2026-07-28 request is otherwise served as peer 0, which
/// every client shares; a held listen and a cancellable `tools/call` need one of
/// their own, so that a notification or a cancellation reaches only them.
var private_peer_seq: std.atomic.Value(u64) = .init(1 << 62);

fn privatePeer() u64 {
    return private_peer_seq.fetchAdd(1, .monotonic);
}

/// The open 2026-07-28 `subscriptions/listen` streams — the only push channel
/// of that revision — held open on their POST (`http.Server.Hold`). Optional:
/// set `Transport.listens` to hold them; without it a listen is acknowledged
/// and closed at once (the graceful closure), as before. `mcp.Server.push`
/// must be on too, or `mcp` itself closes every listen.
///
/// Each held listen gets a peer handle of its own (`privatePeer`, never a
/// session tag), so `mcp` routes a listen's notifications to exactly that
/// stream. `Transport.pushSink` maps a peer to its stream (or, for a session
/// peer, to the session's `GET` queue). Thread-safe; must outlive the Router.
pub const Listens = struct {
    gpa: std.mem.Allocator,
    lock: std.atomic.Mutex = .unlocked,
    map: std.AutoHashMapUnmanaged(u64, *http.Server.Hold) = .empty,
    /// The sink's writer and its routing state: used only inside
    /// `mcp.Server.notify*`, which run under `Transport.lock`.
    feed: std.Io.Writer = .{ .vtable = &.{ .drain = feedDrain }, .buffer = &.{} },
    line: std.ArrayList(u8) = .empty,
    cur_peer: u64 = 0,
    cur_sessions: ?*Sessions = null,

    pub fn init(gpa: std.mem.Allocator) Listens {
        return .{ .gpa = gpa };
    }

    /// Call only once no listen is held any more (after the server stopped).
    pub fn deinit(self: *Listens) void {
        self.map.deinit(self.gpa);
        self.line.deinit(self.gpa);
        self.* = undefined;
    }

    /// Listen streams held open now.
    pub fn count(self: *Listens) usize {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        return self.map.count();
    }

    /// End every held listen gracefully: each answers its request with the
    /// subscription's graceful-close result (subscriptions.mdx "Graceful
    /// Closure") and its response ends. `http.Server.shutdownGraceful` does
    /// the same for the listens on that server.
    pub fn finishAll(self: *Listens) void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        var it = self.map.valueIterator();
        while (it.next()) |h| h.*.finish();
    }

    fn add(self: *Listens, peer: u64, hold: *http.Server.Hold) error{OutOfMemory}!void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        try self.map.put(self.gpa, peer, hold);
    }

    fn remove(self: *Listens, peer: u64) void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        _ = self.map.remove(peer);
    }

    fn holdOf(self: *Listens, peer: u64) ?*http.Server.Hold {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        return self.map.get(peer);
    }

    /// `mcp` writes whole newline-terminated lines; each goes to `cur_peer`.
    fn feedDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Listens = @alignCast(@fieldParentPtr("feed", w));
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.line.appendSlice(self.gpa, d) catch return error.WriteFailed;
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| self.line.appendSlice(self.gpa, last) catch return error.WriteFailed;
        consumed += last.len * splat;
        while (std.mem.findScalar(u8, self.line.items, '\n')) |nl| {
            const ok = self.route(std.mem.trimEnd(u8, self.line.items[0..nl], "\r"));
            const rest = self.line.items.len - (nl + 1);
            std.mem.copyForwards(u8, self.line.items[0..rest], self.line.items[nl + 1 ..]);
            self.line.shrinkRetainingCapacity(rest);
            if (!ok) {
                self.line.clearRetainingCapacity();
                return error.WriteFailed;
            }
        }
        return consumed;
    }

    fn route(self: *Listens, line: []const u8) bool {
        if (line.len == 0) return true;
        if (self.holdOf(self.cur_peer)) |h| {
            var aw: std.Io.Writer.Allocating = .init(self.gpa);
            defer aw.deinit();
            http.sse.writeEvent(&aw.writer, .{ .data = line }) catch return false;
            h.send(aw.written()) catch return false;
            return true;
        }
        const sessions = self.cur_sessions orelse return false;
        return sessions.pushTag(self.cur_peer, line) catch false;
    }
};

/// The Streamable HTTP transport over one `mcp.Server`. Immutable config; the
/// `server` and this `Transport` must outlive the Router.
pub const Transport = struct {
    /// Allocator for the per-request body read + response capture (short-lived;
    /// freed before the handler returns).
    gpa: std.mem.Allocator,
    /// The MCP server this endpoint fronts. Must outlive the Router.
    server: *mcp.Server,
    /// Endpoint path (exact match). Default `/mcp`.
    path: []const u8 = "/mcp",
    /// Largest POST body accepted before answering 413. Default 4 MiB.
    max_body: usize = 4 << 20,
    /// Serialize `handleMessage` (see `Lock`). Default `.none`.
    lock: Lock = .none,
    /// Allowed `Origin` header values (exact match) — the MCP-mandated
    /// DNS-rebinding defense for a locally-bound server (browser JS on another
    /// site cannot forge `Origin`). **Empty ⇒ every origin is accepted** (the
    /// dev default; safe only when the port is not reachable by a browser, e.g.
    /// loopback with no local web content, or auth in front). When non-empty, a
    /// request whose `Origin` header is present but not listed gets **403**; a
    /// request with **no** `Origin` (a non-browser client) is allowed — the
    /// attack this blocks is browser-driven. List full origins,
    /// e.g. `"http://localhost:7717"`.
    allowed_origins: []const []const u8 = &.{},
    /// The `Host` half of the DNS-rebinding defense (the TypeScript SDK's
    /// `hostHeaderValidation`, the Python SDK's `allowed_hosts`): a page that
    /// rebinds a name of its own to the server's address reaches it with the
    /// attacker's `Host`. With a guard every request's `Host` must pass it
    /// (`http.HostGuard`: names without the port, `.example.org` for
    /// subdomains, IP literals and `localhost` allowed unless turned off),
    /// else **403**.
    host_guard: ?http.HostGuard = null,
    /// Without `host_guard`: a request that arrives from a loopback address
    /// must carry a loopback `Host` (`localhost`, `127.0.0.1`, `[::1]`, any
    /// port), else **403** — the Go SDK's default DNS-rebinding protection (its
    /// `DisableLocalhostProtection` turns it off; so does `false` here). A
    /// reverse proxy on the same machine that forwards a public `Host` needs a
    /// `host_guard` naming it, or this off. Requests from other addresses, and
    /// socket-free ones, are not checked.
    localhost_protection: bool = true,
    /// Authorization (`auth.Auth`): with it every request to `path` needs a
    /// valid bearer token, the RFC 9728 document is served, and handlers see
    /// the token's `mcp.AuthInfo` as `call.auth`. Null (the default): no
    /// authorization, though an `mcp.AuthInfo` a middleware of the caller's
    /// own stored with `ctx.setTyped` is still passed on. Must outlive the
    /// Router.
    auth: ?*const auth.Auth = null,
    /// Response delivery policy. `.auto` (default): when the client's `Accept`
    /// header includes `text/event-stream`, the POST response is delivered as
    /// an **SSE stream** so a tool call's `notifications/progress` reach the
    /// client live (each JSON-RPC message becomes one SSE `data:` event; the
    /// stream closes after the response). Clients that don't accept SSE still
    /// get a single `application/json` response. `.off`: always
    /// `application/json` (no streaming).
    stream: StreamMode = .auto,
    /// Optional session registry. Null ⇒ **stateless** (no `Mcp-Session-Id`;
    /// `GET`/`DELETE` → 405). Set a `*Sessions` to enable session assignment /
    /// validation and the server→client `GET /mcp` stream. Must outlive the
    /// Router.
    sessions: ?*Sessions = null,
    /// What a **stateless** endpoint does with a client's JSON-RPC *response*
    /// to a server→client request. Only consulted when `sessions` is null;
    /// with a registry every POST carries its session's peer handle and the
    /// question does not arise. See `StatelessResponses`.
    stateless_responses: StatelessResponses = .reject,
    /// Held-open `subscriptions/listen` streams (see `Listens`). Null (the
    /// default): a listen is acknowledged and closed at once.
    listens: ?*Listens = null,
    /// Bytes of notifications one held listen may have queued and not yet
    /// written; a burst past it ends that stream with the graceful close
    /// (the client re-subscribes) rather than dropping notifications unseen.
    listen_queue_bytes: usize = 64 * 1024,
    /// Idle timeout and heartbeat of a held listen (`http.Server.Hold.Options`;
    /// `on_full` is always `.end_stream`). Default: neither, as the
    /// reference SDKs.
    listen_hold: http.Server.Hold.Options = .{},
    /// With `sessions`: hold the session's `GET` stream open over a real
    /// connection (`http.Server.Hold`), as the reference SDKs do, so
    /// server-initiated messages reach the client at once; `listen_queue_bytes`
    /// and `listen_hold` apply to it too. A second `GET` while one is held
    /// is 409. False: each `GET` replays what is queued and closes (the
    /// client's `EventSource` reconnects), the behaviour before 2026-11-24.
    /// Socket-free (`serveStream` without a socket) and refused holds
    /// (`max_held_responses`, h2 without a dispatcher) fall back to it.
    hold_get: bool = true,

    pub const StreamMode = enum { auto, off };

    /// The `mcp.PushSink` for `mcp.Server.notifyListChanged` /
    /// `notifyResourceUpdated`: a held listen's peer writes SSE events on its
    /// stream, a session peer queues on the session's `GET` stream. Call the
    /// `notify*` functions under `lock`, like every other `mcp.Server` call.
    /// Needs `listens`; without it every peer is skipped.
    pub fn pushSink(t: *const Transport) mcp.PushSink {
        return .{ .ctx = @constCast(t), .writerFor = sinkWriterFor };
    }

    fn sinkWriterFor(ctx: ?*anyopaque, peer: u64) ?*std.Io.Writer {
        const t: *const Transport = @ptrCast(@alignCast(ctx.?));
        const l = t.listens orelse return null;
        if (l.holdOf(peer) == null) {
            const sessions = t.sessions orelse return null;
            if (!sessions.hasTag(peer)) return null;
        }
        l.cur_peer = peer;
        l.cur_sessions = t.sessions;
        l.line.clearRetainingCapacity();
        return &l.feed;
    }

    /// Whether a stateless endpoint may correlate a client's response to a
    /// server→client request (`sampling/createMessage`, `elicitation/create`).
    ///
    /// Without a `Sessions` registry the transport has **no** way to tell two
    /// clients apart: every POST is peer 0, so `mcp`'s peer check (which only
    /// ever compares the issuing peer against the answering one) admits any
    /// client's answer to any client's request. Request ids are small
    /// consecutive integers, so guessing one is not work.
    pub const StatelessResponses = enum {
        /// Fail closed (the default). A POST that could correlate — no
        /// `method`, an integer `id`, and a `result` or `error` — is refused
        /// with **400** and never reaches `mcp.Server`, so no client's answer
        /// can land in another client's flow. A stateless endpoint therefore
        /// cannot complete a sampling/elicitation round trip at all; configure
        /// `sessions` for that, which is what the transport spec's session
        /// model is for.
        reject,
        /// Trust every client to be the same client: correlate responses as
        /// peer 0. Only for an endpoint that genuinely serves **one** client
        /// (a loopback bridge, a test harness, a single-tenant sidecar). On a
        /// multi-client endpoint this is a data leak between clients, and the
        /// transport cannot detect the difference — that is the whole reason
        /// this is an explicit opt-in and not the default.
        single_client,
    };

    pub fn middleware(t: *const Transport) router.Middleware {
        return .{ .state = @constCast(t), .run = middlewareRun };
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const t: *const Transport = @ptrCast(@alignCast(state.?));

    if (t.auth) |a| if (a.metadata) |*md| {
        var pbuf: [1024]u8 = undefined;
        if (auth.metadataPath(&pbuf, t.path)) |mp| if (std.mem.eql(u8, ctx.req.path, mp)) return serveMetadata(ctx, md);
    };

    if (!std.mem.eql(u8, ctx.req.path, t.path)) return next.run(ctx);

    if (!hostAllowed(t, ctx.req) or !originAllowed(t, ctx.req)) {
        ctx.res.setStatus(403);
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("Forbidden\n");
        return;
    }

    if (t.auth) |a| {
        var arena_state = std.heap.ArenaAllocator.init(t.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var fields = ctx.req.headerAll("authorization");
        const first = fields.next();
        const repeated = fields.next() != null;
        const outcome = auth.check(a, arena, first, repeated) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.VerifierFailed => return authServerError(ctx),
        };
        var info: mcp.AuthInfo = switch (outcome) {
            .refused => |r| return refuseAuth(ctx, arena, a, r),
            .ok => |i| i,
        };
        const prev = ctx.setTyped(mcp.AuthInfo, &info) catch return authServerError(ctx);
        defer _ = ctx.setTyped(mcp.AuthInfo, prev) catch {};
        return dispatch(t, ctx);
    }
    return dispatch(t, ctx);
}

fn dispatch(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    switch (ctx.req.method) {
        .post => return handlePost(t, ctx),
        .get => if (t.sessions != null) return handleGet(t, ctx) else return methodNotAllowed(t, ctx),
        .delete => if (t.sessions != null) return handleDelete(t, ctx) else return methodNotAllowed(t, ctx),
        else => return methodNotAllowed(t, ctx),
    }
}

/// The RFC 9728 document: unauthenticated, readable cross-origin (a
/// browser-based client fetches it from the challenge's URL).
fn serveMetadata(ctx: *router.Ctx, md: *const auth.ProtectedResourceMetadata) anyerror!void {
    if (ctx.req.method != .get) {
        ctx.res.setStatus(405);
        try ctx.res.setHeader("Allow", "GET");
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("Method Not Allowed\n");
        return;
    }
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    md.write(&w) catch return authServerError(ctx); // a document over 8 KiB: misconfigured
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.setHeader("Access-Control-Allow-Origin", "*");
    try ctx.res.setHeader("Cache-Control", "max-age=3600");
    try ctx.res.writeAll(w.buffered());
}

/// 401/403 with the RFC 6750 challenge and the TypeScript SDK's JSON body.
fn refuseAuth(ctx: *router.Ctx, arena: std.mem.Allocator, a: *const auth.Auth, r: auth.Refusal) anyerror!void {
    var hv: std.Io.Writer.Allocating = .init(arena);
    try auth.challenge(&hv.writer, a, r);
    var body: std.Io.Writer.Allocating = .init(arena);
    try auth.refusalBody(&body.writer, r);
    ctx.res.setStatus(r.status);
    try ctx.res.setHeader("WWW-Authenticate", hv.written());
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writeAll(body.written());
}

fn authServerError(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(500);
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writeAll("{\"error\":\"server_error\",\"error_description\":\"Token verification failed\"}");
}

/// DNS-rebinding guard, `Host` half (see `Transport.host_guard` and
/// `localhost_protection`).
fn hostAllowed(t: *const Transport, req: *const http.Server.Request) bool {
    if (t.host_guard) |*g| return g.check(req);
    if (!t.localhost_protection) return true;
    const peer = req.peer orelse return true;
    if (!netaddr.Ip.fromStd(peer).isLoopback()) return true;
    const loopback_only: http.HostGuard = .{};
    return loopback_only.check(req);
}

fn methodNotAllowed(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(405);
    try ctx.res.setHeader("Allow", if (t.sessions != null) "POST, GET, DELETE" else "POST");
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Method Not Allowed\n");
}

fn notFound(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(404);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Session Not Found\n");
}

/// DNS-rebinding guard (MCP transport security): with a non-empty allowlist, a
/// present `Origin` must match exactly; an absent `Origin` (non-browser client)
/// is allowed. An empty allowlist accepts everything.
fn originAllowed(t: *const Transport, req: *const http.Server.Request) bool {
    if (t.allowed_origins.len == 0) return true;
    const origin = req.header("origin") orelse return true;
    for (t.allowed_origins) |allowed| {
        if (std.mem.eql(u8, allowed, origin)) return true;
    }
    return false;
}

/// Whether the client's `Accept` header admits an SSE response.
fn acceptsSse(req: *const http.Server.Request) bool {
    const accept = req.header("accept") orelse return false;
    return std.ascii.findIgnoreCase(accept, "text/event-stream") != null;
}

/// Best-effort check whether a POST body is an `initialize` request (so the
/// transport assigns a session). A single-pass token scan — not a full
/// `std.json.Value` tree parse — since this only needs to answer one
/// question (does the top-level `method` say `"initialize"`?) and
/// `handleMessage`/`handleMessageFrom` does the real, authoritative parse
/// right after this returns; paying for a second full recursive-descent
/// parse (with a nested-map allocation per object/array level) just to ask
/// that one question was the redundant work. A malformed body here is not
/// an initialize either way — the real parse right after surfaces the
/// actual error.
fn isInitialize(gpa: std.mem.Allocator, body: []const u8) bool {
    var scanner: std.json.Scanner = .initCompleteInput(gpa, body);
    defer scanner.deinit();
    // Far longer than any real "method" key or "initialize" value; bounds
    // the scan against a pathological single giant token.
    const max_field_len = 64;

    if ((scanner.next() catch return false) != .object_begin) return false;
    var result = false;
    while (true) {
        const key_tok = scanner.nextAllocMax(gpa, .alloc_if_needed, max_field_len) catch return false;
        const key: []const u8 = switch (key_tok) {
            .object_end => return result,
            .string, .allocated_string => |k| k,
            else => return false, // malformed; the real parse will report it
        };
        defer if (key_tok == .allocated_string) gpa.free(key);

        if (std.mem.eql(u8, key, "method")) {
            const val_tok = scanner.nextAllocMax(gpa, .alloc_if_needed, max_field_len) catch return false;
            const val: []const u8 = switch (val_tok) {
                .string, .allocated_string => |s| s,
                else => "",
            };
            defer if (val_tok == .allocated_string) gpa.free(val);
            result = std.mem.eql(u8, val, "initialize");
        } else {
            if (!skipOneValue(&scanner)) return false;
        }
    }
}

/// Whether this POST body is a JSON-RPC message that could resolve one of our
/// pending server→client requests: a top-level object with **no** `method`, a
/// `result` or `error`, and an `id` that is a non-negative integer.
///
/// That is exactly `mcp.Server`'s own correlation predicate (`deliverResponse`
/// drops any id that is not a non-negative integer, and `handleMessageFrom`
/// only routes a `method`-less object carrying `result`/`error` there), so a
/// stateless endpoint refusing this set refuses precisely what it cannot
/// attribute — and nothing else keeps its previous behaviour. Same single-pass
/// scan as `isInitialize`, for the same reason: the authoritative parse happens
/// in `handleMessageFrom` right after.
fn correlatableResponse(gpa: std.mem.Allocator, body: []const u8) bool {
    var scanner: std.json.Scanner = .initCompleteInput(gpa, body);
    defer scanner.deinit();
    const max_field_len = 64; // longer than any key here or than a u64 in decimal

    if ((scanner.next() catch return false) != .object_begin) return false;
    var has_method = false;
    var has_payload = false;
    var has_int_id = false;
    while (true) {
        const key_tok = scanner.nextAllocMax(gpa, .alloc_if_needed, max_field_len) catch return false;
        const key: []const u8 = switch (key_tok) {
            .object_end => return !has_method and has_payload and has_int_id,
            .string, .allocated_string => |k| k,
            else => return false, // malformed; the real parse will report it
        };
        defer if (key_tok == .allocated_string) gpa.free(key);

        if (std.mem.eql(u8, key, "id")) {
            // Peek first so a non-numeric id is skipped as one whole value —
            // consuming only an `object_begin` here would desync the scan and
            // let a nested key masquerade as a top-level one.
            if ((scanner.peekNextTokenType() catch return false) != .number) {
                if (!skipOneValue(&scanner)) return false;
                continue;
            }
            const val_tok = scanner.nextAllocMax(gpa, .alloc_if_needed, max_field_len) catch return false;
            const txt: []const u8 = switch (val_tok) {
                .number, .allocated_number => |n| n,
                else => "",
            };
            defer if (val_tok == .allocated_number) gpa.free(txt);
            has_int_id = if (std.fmt.parseInt(u64, txt, 10)) |_| true else |_| false;
            continue;
        }
        if (std.mem.eql(u8, key, "method")) has_method = true;
        if (std.mem.eql(u8, key, "result") or std.mem.eql(u8, key, "error")) has_payload = true;
        if (!skipOneValue(&scanner)) return false;
    }
}

/// `Scanner.skipValue` after the checks it leaves to the caller. Its
/// `peekNextTokenType` reads the next octet without consulting the grammar, so
/// the value of `{"a":}` is "an object end", and `skipValue` meets that with
/// `unreachable` ("attempt to skip a non-value token") -- a panic in Debug and
/// ReleaseSafe, undefined behaviour in ReleaseFast, from a POST body nobody has
/// authenticated. Found by the 2026-10-10 fuzz driver (`{"a":}`, `[1,]`-shaped
/// members). A false return means "not a well-formed value here": neither
/// scanner's caller wants anything from such a body.
fn skipOneValue(scanner: *std.json.Scanner) bool {
    switch (scanner.peekNextTokenType() catch return false) {
        .object_end, .array_end, .end_of_document => return false,
        else => {},
    }
    scanner.skipValue() catch return false;
    return true;
}

/// The `Last-Event-ID` request header as a u64 (0 when absent/invalid ⇒ replay
/// the whole buffer).
fn parseLastEventId(req: *const http.Server.Request) u64 {
    const h = req.header("last-event-id") orelse return 0;
    return std.fmt.parseInt(u64, std.mem.trim(u8, h, " \t"), 10) catch 0;
}

/// `GET /mcp`: the server→client stream. Drain-and-close — replay every event
/// queued since `Last-Event-ID`, then close (the client reconnects for more).
fn handleGet(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    const sessions = t.sessions.?;
    const sid = ctx.req.header("mcp-session-id") orelse return notFound(ctx);
    const after = parseLastEventId(ctx.req);
    if (t.hold_get and try heldGet(t, ctx, sessions, sid, after)) return;

    var arena_state = std.heap.ArenaAllocator.init(t.gpa);
    defer arena_state.deinit();

    var batch: std.ArrayList(Sessions.StoredEvent) = .empty;
    // Snapshot under the store lock (copies into the arena) so writing to the
    // socket below holds no lock and races no concurrent DELETE.
    // `drainAfter`'s bool is the session's `closing` flag. It used to be
    // discarded, and nothing else read the flag either — so the public
    // `Sessions.close` was inert: after it the session still accepted `push`,
    // still `exists`, and was never torn down. Honour it here, which is what
    // its doc always said ("its next GET drains what is queued and ends")
    // (W2 re-audit 2026-09-02, `mcp-http` F3).
    const closing = (try sessions.drainAfter(sid, after, arena_state.allocator(), &batch)) orelse
        return notFound(ctx);

    var es = try http.sse.EventStream.start(ctx.res);
    if (batch.items.len == 0) {
        // Nothing queued: a heartbeat keeps the response well-formed; the
        // client's EventSource reconnects (with Last-Event-ID) for later events.
        try es.comment("keep-alive");
        if (closing) forgetSession(t, sessions, sid);
        return;
    }
    for (batch.items) |e| {
        var idbuf: [24]u8 = undefined;
        const idstr = std.mem.print(&idbuf, "{d}", .{e.id}) catch unreachable;
        try es.send(.{ .id = idstr, .data = e.data });
    }
    // Everything queued has now been written, so the session has nothing left
    // to deliver and can go.
    if (closing) forgetSession(t, sessions, sid);
}

/// `GET /mcp` held open: replay what is queued after `Last-Event-ID`, then
/// keep the stream and write every message the session is sent
/// (`Sessions.enqueue`) until the client leaves, the session ends (`DELETE`,
/// `Sessions.close`, eviction), the server shuts down or the queue overflows.
/// False: not held (no real connection, or the server refuses a hold): the
/// caller drains and closes instead.
fn heldGet(t: *const Transport, ctx: *router.Ctx, sessions: *Sessions, sid: []const u8, after: u64) anyerror!bool {
    switch (sessions.heldNow(sid) orelse {
        try notFound(ctx);
        return true;
    }) {
        true => {
            ctx.res.setStatus(409);
            try ctx.res.setHeader("Content-Type", "application/json");
            try ctx.res.writeAll("{\"jsonrpc\":\"2.0\",\"id\":\"server-error\",\"error\":{\"code\":-32600,\"message\":\"Conflict: Only one SSE stream is allowed per session\"}}");
            return true;
        },
        false => {},
    }
    const queue = try t.gpa.alloc(u8, @max(t.listen_queue_bytes, 1));
    defer t.gpa.free(queue);
    var es = try http.sse.EventStream.start(ctx.res);
    var hold: http.Server.Hold = .{};
    var opts = t.listen_hold;
    opts.on_full = .end_stream;
    hold.begin(ctx.req, ctx.res, queue, opts) catch return false;
    if (hold.source == null) {
        hold.end();
        return false;
    }
    defer hold.end();

    var arena_state = std.heap.ArenaAllocator.init(t.gpa);
    defer arena_state.deinit();
    var batch: std.ArrayList(Sessions.StoredEvent) = .empty;
    const attached = try sessions.attachHold(sid, &hold, after, arena_state.allocator(), &batch);
    var closing = false;
    switch (attached) {
        .ok => |a| closing = a.closing,
        // Gone or taken in the meantime: the head is out, the stream ends empty.
        .unknown, .conflict => return true,
    }
    var send_failed = false;
    for (batch.items) |e| {
        var idbuf: [24]u8 = undefined;
        const idstr = std.mem.print(&idbuf, "{d}", .{e.id}) catch unreachable;
        es.send(.{ .id = idstr, .data = e.data }) catch {
            send_failed = true;
            break;
        };
    }
    if (!send_failed and !closing) _ = hold.run();
    if (sessions.detachHold(sid, &hold) or closing) forgetSession(t, sessions, sid);
    return true;
}

/// Destroy a session AND drop the server-side handshake state that belongs to
/// it. `mcp.Server` scopes capabilities, the negotiated revision and the
/// pending budget per peer (`mcp.PeerState`); nothing else tells it a peer has
/// gone, so a transport that tore sessions down without this would walk into
/// `Server.max_peers` and start refusing new handshakes outright.
fn forgetSession(t: *const Transport, sessions: *Sessions, sid: []const u8) void {
    const tag = sessions.destroy(sid) orelse return;
    t.lock.acquire();
    defer t.lock.release();
    t.server.forgetPeer(tag);
}

/// `DELETE /mcp`: tear down the session named by `Mcp-Session-Id`.
fn handleDelete(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    const sid = ctx.req.header("mcp-session-id") orelse return notFound(ctx);
    const sessions = t.sessions.?;
    if (sessions.tagOf(sid) == null) return notFound(ctx);
    forgetSession(t, sessions, sid);
    ctx.res.setStatus(204);
}

fn handlePost(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    const body = ctx.req.reader().allocRemaining(t.gpa, .limited(t.max_body)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => {
            ctx.res.setStatus(413);
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Payload Too Large\n");
            return;
        },
        error.ReadFailed => {
            ctx.res.setStatus(400);
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Bad Request\n");
            return;
        },
    };
    defer t.gpa.free(body);

    // Per-operation scopes (`auth.Auth.scope_for`): the token was accepted
    // in `middlewareRun`; this operation may need more.
    if (t.auth) |a| if (a.scope_for != null) if (ctx.getTyped(mcp.AuthInfo)) |info| {
        var arena_state = std.heap.ArenaAllocator.init(t.gpa);
        defer arena_state.deinit();
        const op = auth.operationOf(t.gpa, arena_state.allocator(), body) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Fail closed: `scope_for` is never asked about an operation that
            // could not be read. `mcp` answers such a body with a parse error
            // anyway, so no legitimate request is lost (sweep HS-2).
            error.Unreadable => {
                ctx.res.setStatus(400);
                try ctx.res.setHeader("Content-Type", "application/json");
                try ctx.res.writeAll("{\"error\":\"invalid_request\",\"error_description\":\"Unreadable request body\"}");
                return;
            },
        };
        if (auth.checkOperation(a, .{ .method = op.method, .target = op.target, .auth = info })) |r|
            return refuseAuth(ctx, arena_state.allocator(), a, r);
    };

    // Spec 2026-07-28: a request whose body carries the `_meta` protocol
    // version is served statelessly, whatever sessions are configured — no
    // session is required, none is minted, `Mcp-Session-Id` is ignored — once
    // its request-metadata headers agree with its body (see `modern.zig`).
    {
        var arena_state = std.heap.ArenaAllocator.init(t.gpa);
        defer arena_state.deinit();
        var hv: HeaderView = .{ .req = ctx.req };
        t.lock.acquire();
        const verdict = modern.classify(arena_state.allocator(), hv.headers(), body, t.server);
        t.lock.release();
        switch (try verdict) {
            .legacy => {},
            .mismatch => |line| {
                ctx.res.setStatus(400);
                try ctx.res.setHeader("Content-Type", "application/json");
                try ctx.res.writeAll(line);
                return;
            },
            .modern => {
                if (t.stream == .auto and acceptsSse(ctx.req)) return modernStreamResponse(t, ctx, body);
                return modernJsonResponse(t, ctx, body);
            },
        }
    }

    // Session handling (only when a registry is configured). The client gets a
    // session id at `initialize` and must present it on every later request.
    // `sid`/`peer` identify the session for the rest of the request: `peer` is
    // what scopes server→client request correlation (see `Session.tag`).
    var sid: ?[]const u8 = null;
    var peer: u64 = 0;
    if (t.sessions) |sessions| {
        if (isInitialize(t.gpa, body)) {
            const created = sessions.create() catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.TooManySessions => {
                    ctx.res.setStatus(429);
                    try ctx.res.setHeader("Content-Type", "text/plain");
                    try ctx.res.writeAll("Too Many Sessions\n");
                    return;
                },
            };
            // A session evicted to make room takes its server-side handshake
            // state with it (see `forgetSession`); otherwise the peer entry
            // outlives every session that ever used the slot.
            if (created.evicted) |gone| {
                t.lock.acquire();
                t.server.forgetPeer(gone);
                t.lock.release();
            }
            try ctx.res.setHeader("Mcp-Session-Id", created.id);
            sid = created.id;
            // The tag comes back from `create` itself: there is no second
            // lookup that could fail, so no failure to answer inconsistently
            // (this line used to be `tagOf(new_sid) orelse 0`, which put a
            // session it could not resolve into the *shared* peer-0 bucket,
            // while the sibling lookup below fails closed with a 404).
            peer = created.tag;
        } else {
            const have = ctx.req.header("mcp-session-id") orelse return notFound(ctx);
            peer = sessions.tagOf(have) orelse return notFound(ctx);
            sid = have;
        }
    } else if (t.stateless_responses == .reject and correlatableResponse(t.gpa, body)) {
        // Stateless: every client is peer 0, so correlating this response
        // would let any client consume any other client's sampling completion
        // or elicitation answer. Refuse rather than guess (see
        // `Transport.StatelessResponses`).
        ctx.res.setStatus(400);
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("Client Responses Require A Session\n");
        return;
    }

    if (t.stream == .auto and acceptsSse(ctx.req)) return streamResponse(t, ctx, body, peer);
    return jsonResponse(t, ctx, body, sid, peer);
}

/// The single-JSON-response path (client did not ask for SSE): capture what the
/// server writes and return `application/json`, or 202 for a notification (and
/// for a JSON-RPC *response* — a client answering a server→client request also
/// produces no reply, which is exactly what the Streamable HTTP spec wants
/// answered with 202).
///
/// The server may write **several** lines for one message: a tool's
/// `notifications/progress` and any `sampling/createMessage` /
/// `elicitation/create` it issues precede the response line. An
/// `application/json` body must be a single JSON object, so only the last line
/// (the response) becomes the body; the earlier server→client lines are queued
/// on the session's `GET` stream when a registry is configured, and dropped
/// when it is not — a stateless endpoint has no channel to deliver them on.
fn jsonResponse(t: *const Transport, ctx: *router.Ctx, body: []const u8, sid: ?[]const u8, peer: u64) anyerror!void {
    var out: std.Io.Writer.Allocating = .init(t.gpa);
    defer out.deinit();

    t.lock.acquire();
    const rc = t.server.handleMessageAs(body, &out.writer, peer, ctx.getTyped(mcp.AuthInfo));
    t.lock.release();
    // handleMessage only fails on OOM or a transport write failure; the
    // Allocating writer fails solely on OOM, so both surface as a 500.
    rc catch return error.OutOfMemory;

    // Split into lines; the last non-empty one is the response to this POST.
    var resp: []const u8 = "";
    var it = std.mem.splitScalar(u8, out.written(), '\n');
    var prior: std.ArrayList([]const u8) = .empty;
    defer prior.deinit(t.gpa);
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (resp.len != 0) try prior.append(t.gpa, resp);
        resp = line;
    }
    if (prior.items.len != 0) {
        if (t.sessions) |sessions| {
            if (sid) |session_id| {
                for (prior.items) |line| _ = try sessions.push(session_id, line);
            }
        }
    }

    // A notification, or the client's response to one of our requests: no reply.
    if (resp.len == 0) {
        ctx.res.setStatus(202); // Accepted, no body
        return;
    }
    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writeAll(resp); // writeAll copies, so freeing `out` after is safe
}

/// The SSE-response path: run the server against an adapter that re-frames each
/// JSON-RPC line the server writes (progress notifications, then the response)
/// as an SSE `data:` event, flushed live. If the message was a notification
/// (the server wrote nothing), no stream is started and we answer 202.
fn streamResponse(t: *const Transport, ctx: *router.Ctx, body: []const u8, peer: u64) anyerror!void {
    var buf: [4096]u8 = undefined;
    var adapter = SseAdapter.init(t.gpa, ctx.res, &buf);
    defer adapter.deinit();

    t.lock.acquire();
    const rc = t.server.handleMessageAs(body, &adapter.writer, peer, ctx.getTyped(mcp.AuthInfo));
    t.lock.release();
    adapter.writer.flush() catch {}; // drain any bytes still buffered
    adapter.finish(); // emit a trailing partial line (defensive; mcp ends with \n)
    rc catch |err| return err;

    if (!adapter.started) ctx.res.setStatus(202); // notification: no stream, no body
    // else: the SSE stream carried the response; returning ends it (end() writes
    // the terminating chunk), which is the server-closes-after-response contract.
}

/// `modern.Headers` over an `http` request.
const HeaderView = struct {
    req: *const http.Server.Request,

    fn headers(self: *const HeaderView) modern.Headers {
        return .{ .ctx = self, .getFn = get, .countFn = count };
    }
    fn get(ctx: *const anyopaque, name: []const u8) ?[]const u8 {
        const self: *const HeaderView = @ptrCast(@alignCast(ctx));
        return self.req.header(name);
    }
    fn count(ctx: *const anyopaque, name: []const u8) usize {
        const self: *const HeaderView = @ptrCast(@alignCast(ctx));
        var it = self.req.iterateHeaders();
        var n: usize = 0;
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) n += 1;
        }
        return n;
    }
};

/// A 2026-07-28 request, `application/json`: the last line the server wrote
/// is the body, with the status its JSON-RPC answer maps to
/// (`modern.statusFor`). Anything written before it (progress) has nowhere
/// to go — that revision has no `GET` stream — and is dropped, as it is on a
/// stateless session-era endpoint. Nothing written: a notification, 202.
fn modernJsonResponse(t: *const Transport, ctx: *router.Ctx, body: []const u8) anyerror!void {
    var id_arena: std.heap.ArenaAllocator = .init(t.gpa);
    defer id_arena.deinit();
    var cancel: CallCancel = undefined;
    var watch: http.Server.PeerWatch = .{};
    const peer = cancel.watch(t, ctx, body, id_arena.allocator(), &watch);
    defer watch.stop();

    var out: std.Io.Writer.Allocating = .init(t.gpa);
    defer out.deinit();
    t.lock.acquire();
    // The client may have left while this call waited for the lock: the watch
    // fired when no call was in flight to cancel yet, so it is not run at all.
    if (watch.gone()) {
        t.lock.release();
        return;
    }
    const rc = t.server.handleMessageAs(body, &out.writer, peer, ctx.getTyped(mcp.AuthInfo));
    t.lock.release();
    rc catch return error.OutOfMemory; // see `jsonResponse`

    const resp = lastLine(out.written());
    if (resp.len == 0) {
        ctx.res.setStatus(202);
        return;
    }
    var arena_state = std.heap.ArenaAllocator.init(t.gpa);
    defer arena_state.deinit();
    ctx.res.setStatus(modern.statusFor(arena_state.allocator(), resp));
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writeAll(resp);
}

fn lastLine(written: []const u8) []const u8 {
    var resp: []const u8 = "";
    var it = std.mem.splitScalar(u8, written, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len != 0) resp = line;
    }
    return resp;
}

/// A 2026-07-28 request whose client accepts SSE. The stream opens with the
/// first **notification** the server writes (progress, a listen
/// acknowledgment), so it carries them live, and ends with the response. A
/// request answered by its response alone — every refusal among them — goes
/// out as `application/json` with its mapped status instead: an SSE stream
/// is committed to 200, and the spec's 400/404 answers must be visible to a
/// client that decides its era fallback from the status.
///
/// Closing the stream is the client's cancellation (streamable-http.mdx
/// "Cancellation"): once a write fails nothing more is sent and the failure is
/// not an error of this request; a `tools/call` is also watched
/// (`CallCancel`), so the running tool sees `ToolCall.cancelled()` as soon as
/// the connection goes, not only at its next write.
fn modernStreamResponse(t: *const Transport, ctx: *router.Ctx, body: []const u8) anyerror!void {
    if (t.listens != null and std.mem.eql(u8, ctx.req.header("mcp-method") orelse "", "subscriptions/listen"))
        return heldListen(t, ctx, body);
    var id_arena: std.heap.ArenaAllocator = .init(t.gpa);
    defer id_arena.deinit();
    var cancel: CallCancel = undefined;
    var watch: http.Server.PeerWatch = .{};
    const peer = cancel.watch(t, ctx, body, id_arena.allocator(), &watch);
    defer watch.stop();

    var buf: [4096]u8 = undefined;
    var adapter = SseAdapter.init(t.gpa, ctx.res, &buf);
    adapter.hold_lone_response = true;
    defer adapter.deinit();

    t.lock.acquire();
    // See `modernJsonResponse`: a client gone before the call started.
    if (watch.gone()) {
        t.lock.release();
        return;
    }
    const rc = t.server.handleMessageAs(body, &adapter.writer, peer, ctx.getTyped(mcp.AuthInfo));
    t.lock.release();
    adapter.writer.flush() catch {};
    adapter.finish();
    return modernStreamTail(t, ctx, &adapter, rc);
}

/// What follows `handleMessageFrom` on a 2026-07-28 SSE request: a refused
/// write after the stream started is the client's cancellation; a lone
/// response goes out as `application/json` with its status; nothing at all
/// is a 202.
fn modernStreamTail(t: *const Transport, ctx: *router.Ctx, adapter: *SseAdapter, rc: mcp.Error!void) anyerror!void {
    rc catch |err| switch (err) {
        error.WriteFailed => if (!adapter.started) return err, // cancelled: see above
        else => return err,
    };

    if (adapter.held) |line| {
        var arena_state = std.heap.ArenaAllocator.init(t.gpa);
        defer arena_state.deinit();
        ctx.res.setStatus(modern.statusFor(arena_state.allocator(), line));
        try ctx.res.setHeader("Content-Type", "application/json");
        try ctx.res.writeAll(line);
        return;
    }
    if (!adapter.started) ctx.res.setStatus(202);
}

/// A 2026-07-28 `subscriptions/listen` held open (`Transport.listens`): the
/// acknowledgment opens the SSE stream, then the POST stays open on an
/// `http.Server.Hold` and carries every notification `mcp` pushes to the
/// listen's private peer (`Transport.pushSink`), until the client closes it
/// (its cancellation: nothing more is written), the server shuts down, the
/// application calls `Listens.finishAll`, the queue overflows or the idle
/// timeout passes — those four end it with the graceful-close result.
/// A listen `mcp` answered at once (push off, a refusal) is not held.
fn heldListen(t: *const Transport, ctx: *router.Ctx, body: []const u8) anyerror!void {
    const l = t.listens.?;
    const peer = privatePeer();
    var buf: [4096]u8 = undefined;
    var adapter = SseAdapter.init(t.gpa, ctx.res, &buf);
    adapter.hold_lone_response = true;
    adapter.track_response = true;
    defer adapter.deinit();
    const queue = try t.gpa.alloc(u8, @max(t.listen_queue_bytes, 1));
    defer t.gpa.free(queue);
    var hold: http.Server.Hold = .{};
    var opts = t.listen_hold;
    opts.on_full = .end_stream;

    // Under one lock with the call: no notification can be written to this
    // peer between the acknowledgment and the registration (`notify*` runs
    // under `lock` too).
    var holding = false;
    t.lock.acquire();
    const rc = t.server.handleMessageAs(body, &adapter.writer, peer, ctx.getTyped(mcp.AuthInfo));
    adapter.writer.flush() catch {};
    adapter.finish();
    if (rc) |_| {
        if (adapter.started and !adapter.saw_response) {
            if (hold.begin(ctx.req, ctx.res, queue, opts)) |_| {
                if (l.add(peer, &hold)) |_| {
                    holding = true;
                } else |_| hold.end();
            } else |_| {}
            // Cannot be held (`max_held_responses`, memory): end it now, as
            // the server ending it would.
            if (!holding) closeListen(t, &adapter, peer);
        }
    } else |_| {}
    if (!holding) t.server.forgetPeer(peer);
    t.lock.release();
    if (!holding) return modernStreamTail(t, ctx, &adapter, rc);

    const why = hold.run();
    t.lock.acquire();
    l.remove(peer);
    if (why != .peer_gone and why != .write_failed) closeListen(t, &adapter, peer);
    t.server.forgetPeer(peer);
    t.lock.release();
    hold.end();
}

/// The graceful close of `peer`'s listen, as the stream's last event.
/// Caller holds `lock`.
fn closeListen(t: *const Transport, adapter: *SseAdapter, peer: u64) void {
    _ = t.server.endSubscriptions(&adapter.writer, peer) catch {};
    adapter.writer.flush() catch {};
}

/// 2026-07-28: the client closing a `tools/call`'s connection cancels the
/// call (streamable-http.mdx "Cancellation"). A `PeerWatch` fires
/// `mcp.Server.cancelInflight` for the request's id on the request's private
/// peer, so only this call can be hit. The session era does not get it: its
/// revision says a disconnect is not a cancellation (a client sends
/// `notifications/cancelled`).
const CallCancel = struct {
    server: *mcp.Server,
    peer: u64,
    id: std.json.Value,

    /// Start watching when the request is a `tools/call` with an id and the
    /// connection can be watched; the peer to serve it as (0 otherwise).
    fn watch(c: *CallCancel, t: *const Transport, ctx: *router.Ctx, body: []const u8, arena: std.mem.Allocator, pw: *http.Server.PeerWatch) u64 {
        if (!std.mem.eql(u8, ctx.req.header("mcp-method") orelse "", "tools/call")) return 0;
        const id = topLevelId(arena, body) orelse return 0;
        c.* = .{ .server = t.server, .peer = privatePeer(), .id = id };
        pw.start(ctx.req, .{ .ctx = c, .f = fire }) catch return 0;
        return c.peer;
    }

    fn fire(ctx: ?*anyopaque) void {
        const c: *CallCancel = @ptrCast(@alignCast(ctx.?));
        _ = c.server.cancelInflightSticky(c.peer, c.id);
    }
};

/// The top-level `id` of a JSON-RPC request when it is a string or an integer
/// (the only ids `mcp` registers for cancellation), else null. One scan, as
/// `isInitialize`.
fn topLevelId(arena: std.mem.Allocator, body: []const u8) ?std.json.Value {
    var scanner: std.json.Scanner = .initCompleteInput(arena, body);
    if ((scanner.next() catch return null) != .object_begin) return null;
    while (true) {
        const key_tok = scanner.nextAllocMax(arena, .alloc_if_needed, 64) catch return null;
        const key: []const u8 = switch (key_tok) {
            .string, .allocated_string => |k| k,
            else => return null, // object end or malformed
        };
        if (std.mem.eql(u8, key, "id")) {
            const v = scanner.nextAllocMax(arena, .alloc_always, 256) catch return null;
            return switch (v) {
                .allocated_string => |x| .{ .string = x },
                .allocated_number => |n| .{ .integer = std.fmt.parseInt(i64, n, 10) catch return null },
                else => null,
            };
        }
        if (!skipOneValue(&scanner)) return null;
    }
}

/// A `std.Io.Writer` that turns the server's newline-delimited JSON-RPC output
/// into SSE `data:` events on `rw`. Each complete line (the server writes one
/// JSON object per line, flushing after each) is emitted as its own event and
/// flushed to the socket; the `text/event-stream` head is written lazily on the
/// first event, so a no-output notification leaves the response free for a 202.
const SseAdapter = struct {
    rw: *http.Server.ResponseWriter,
    gpa: std.mem.Allocator,
    pending: std.ArrayList(u8) = .empty,
    es: http.sse.EventStream = undefined,
    started: bool = false,
    writer: std.Io.Writer,
    /// 2026-07-28 only: keep a *response* that would be the stream's first
    /// event back instead (in `held`), so the caller can send it as
    /// `application/json` with its own status. A notification opens the
    /// stream as usual.
    hold_lone_response: bool = false,
    held: ?[]u8 = null,
    /// Note whether a JSON-RPC response went out (`saw_response`): a
    /// `subscriptions/listen` still open has written none.
    track_response: bool = false,
    saw_response: bool = false,

    fn init(gpa: std.mem.Allocator, rw: *http.Server.ResponseWriter, buffer: []u8) SseAdapter {
        return .{
            .rw = rw,
            .gpa = gpa,
            .writer = .{ .vtable = &.{ .drain = drainFn }, .buffer = buffer },
        };
    }

    fn deinit(self: *SseAdapter) void {
        self.pending.deinit(self.gpa);
        if (self.held) |h| self.gpa.free(h);
    }

    fn drainFn(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *SseAdapter = @alignCast(@fieldParentPtr("writer", w));
        self.pending.appendSlice(self.gpa, w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.pending.appendSlice(self.gpa, d) catch return error.WriteFailed;
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| self.pending.appendSlice(self.gpa, last) catch return error.WriteFailed;
        consumed += last.len * splat;
        try self.emitComplete();
        return consumed;
    }

    /// Emit every complete (newline-terminated) line currently buffered.
    fn emitComplete(self: *SseAdapter) std.Io.Writer.Error!void {
        while (std.mem.findScalar(u8, self.pending.items, '\n')) |nl| {
            try self.emitLine(self.pending.items[0..nl]);
            const rest = self.pending.items.len - (nl + 1);
            std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[nl + 1 ..]);
            self.pending.shrinkRetainingCapacity(rest);
        }
    }

    fn emitLine(self: *SseAdapter, line: []const u8) std.Io.Writer.Error!void {
        const trimmed = std.mem.trimEnd(u8, line, "\r"); // tolerate CRLF
        if (trimmed.len == 0) return; // never seen from mcp, but skip blanks
        if (self.hold_lone_response and !self.started) {
            if (self.held == null and isResponse(self.gpa, trimmed)) {
                self.held = self.gpa.dupe(u8, trimmed) catch return error.WriteFailed;
                return;
            }
            // More follows a held line (never from `mcp`, whose response is
            // its last line): it was not alone after all — stream both.
            if (self.held) |h| {
                self.held = null;
                defer self.gpa.free(h);
                try self.startStream();
                self.es.send(.{ .data = h }) catch return error.WriteFailed;
            }
        }
        if (!self.started) try self.startStream();
        if (self.track_response and isResponse(self.gpa, trimmed)) self.saw_response = true;
        self.es.send(.{ .data = trimmed }) catch return error.WriteFailed;
    }

    fn startStream(self: *SseAdapter) std.Io.Writer.Error!void {
        self.es = http.sse.EventStream.start(self.rw) catch return error.WriteFailed;
        self.started = true;
    }

    fn isResponse(gpa: std.mem.Allocator, line: []const u8) bool {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        return modern.isResponseLine(arena_state.allocator(), line);
    }

    /// Flush a trailing line with no final newline (defensive — mcp always ends
    /// its messages with one). Best-effort.
    fn finish(self: *SseAdapter) void {
        const rest = std.mem.trimEnd(u8, self.pending.items, "\r\n");
        if (rest.len != 0) self.emitLine(rest) catch {};
    }
};

// ── tests (offline — through http.Server.serveStream + a real router) ───────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

fn echoTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.write("{\"ok\":true}");
    return false;
}

fn workTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.reportProgress(1, 2, "step one"); // no-op unless the client sent a token
    call.reportProgress(2, 2, "step two");
    call.write("{\"done\":true}");
    return false;
}

// ── tools mirroring the real python-mcp reference capture (oracle tests) ────

/// Echoes back the `text` argument wrapped as `{"result": <value>}`, matching
/// the wrapping convention the official python `mcp` SDK's FastMCP-style
/// server (`mcp.server.mcpserver.MCPServer`) uses for a scalar tool return —
/// see `oracle_vectors.zig`'s `echo_call_response_json`, captured from a real
/// run of that SDK.
fn oracleEchoTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    const text = call.strArg("text") orelse return call.fail("missing 'text'");
    call.print("{{\"result\":\"{s}\"}}", .{text});
    return false;
}

/// Reports the same two progress steps the real captured `work` tool did
/// (`oracle_vectors.zig`'s `progress_1_json`/`progress_2_json`), then returns
/// `{"result":"done"}` in the same wrapping convention as `oracleEchoTool`.
fn oracleWorkTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.reportProgress(1, 2, "step one");
    call.reportProgress(2, 2, "step two");
    call.write("{\"result\":\"done\"}");
    return false;
}

fn buildOracleServer(gpa: std.mem.Allocator) !mcp.Server {
    var server = mcp.Server.init(gpa, .{ .name = "test", .version = "1.0" });
    errdefer server.deinit();
    try server.addTool(.{
        .name = "echo",
        .description = "Echo the given text back.",
        .input_schema = "{\"type\":\"object\"}",
        .handler = oracleEchoTool,
    });
    try server.addTool(.{
        .name = "work",
        .description = "Do some work, reporting progress twice.",
        .input_schema = "{\"type\":\"object\"}",
        .handler = oracleWorkTool,
    });
    return server;
}

fn buildServer(gpa: std.mem.Allocator) !mcp.Server {
    var server = mcp.Server.init(gpa, .{ .name = "test", .version = "1.0" });
    errdefer server.deinit();
    try server.addTool(.{
        .name = "echo",
        .description = "echo",
        .input_schema = "{\"type\":\"object\"}",
        .handler = echoTool,
    });
    try server.addTool(.{
        .name = "work",
        .description = "work with progress",
        .input_schema = "{\"type\":\"object\"}",
        .handler = workTool,
    });
    return server;
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [4096]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
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

fn post(comptime target: []const u8, comptime json: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "POST {s} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ target, json.len, json },
    );
}

fn postOrigin(comptime origin: []const u8, comptime json: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ origin, json.len, json },
    );
}

fn postAccept(comptime accept: []const u8, comptime json: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ accept, json.len, json },
    );
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.find(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

/// Header value of `name` (case-insensitive) from a raw response, or null.
fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

const init_body =
    \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}
;
const list_body =
    \\{"jsonrpc":"2.0","id":2,"method":"tools/list"}
;

fn postWithSession(buf: []u8, sid: []const u8, json: []const u8) []const u8 {
    return std.mem.print(buf, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: {s}\r\n" ++
        "Content-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ sid, json.len, json }) catch unreachable;
}

fn getWithSession(buf: []u8, sid: []const u8, last_event_id: ?[]const u8) []const u8 {
    if (last_event_id) |lei| {
        return std.mem.print(buf, "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: {s}\r\n" ++
            "Last-Event-ID: {s}\r\nConnection: close\r\n\r\n", .{ sid, lei }) catch unreachable;
    }
    return std.mem.print(buf, "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: {s}\r\nConnection: close\r\n\r\n", .{sid}) catch unreachable;
}

fn deleteWithSession(buf: []u8, sid: []const u8) []const u8 {
    return std.mem.print(buf, "DELETE /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: {s}\r\nConnection: close\r\n\r\n", .{sid}) catch unreachable;
}

fn hApp(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("app");
}

test "isInitialize: single-pass scan matches the old full-tree-parse semantics (F2)" {
    const gpa = testing.allocator;
    // Plain, "method" first.
    try testing.expect(isInitialize(gpa, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}"));
    // A different method.
    try testing.expect(!isInitialize(gpa, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"));
    // "method" preceded by nested objects/arrays the scan must skip *without
    // desyncing* (`skipValue` on every non-"method" key) — the part most
    // likely to break in a hand-rolled scan.
    try testing.expect(isInitialize(gpa,
        \\{"a":{"nested":[1,2,{"x":3}]},"b":[1,[2,3],{}],"c":null,"d":true,"method":"initialize"}
    ));
    try testing.expect(!isInitialize(gpa,
        \\{"a":{"nested":[1,2,{"x":3}]},"b":[1,[2,3],{}],"method":"tools/list"}
    ));
    // Escaped method value still compares correctly (forces the
    // `.allocated_string` path, not just the zero-copy `.string` one).
    try testing.expect(isInitialize(gpa, "{\"method\":\"in\\u0069tialize\"}"));
    // No "method" key at all.
    try testing.expect(!isInitialize(gpa, "{\"jsonrpc\":\"2.0\",\"id\":1}"));
    // Malformed / non-object bodies are never an initialize — the real
    // parse in `handleMessage` surfaces the actual error.
    try testing.expect(!isInitialize(gpa, "not json"));
    try testing.expect(!isInitialize(gpa, "[1,2,3]"));
    try testing.expect(!isInitialize(gpa, "{"));
    try testing.expect(!isInitialize(gpa, "{}"));
    // A "method" value long enough to require allocation past a short cap
    // is still read correctly (regression guard on `max_field_len`).
    try testing.expect(!isInitialize(gpa, "{\"method\":\"" ++ strRepeat("x", 100) ++ "\"}"));
}

test "POST initialize → 200 application/json with a result" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    try r.get("/", hApp);

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got, "Content-Type: application/json") != null);
    const b = bodyOf(got);
    try testing.expect(std.mem.find(u8, b, "\"jsonrpc\":\"2.0\"") != null);
    try testing.expect(std.mem.find(u8, b, "\"id\":1") != null);
    try testing.expect(std.mem.find(u8, b, "\"result\"") != null);
    try testing.expect(std.mem.find(u8, b, "\"serverInfo\"") != null);
}

test "POST tools/list → the registered tool; tools/call → its result" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const list = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, list, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, bodyOf(list), "\"echo\"") != null);

    var buf2: [4096]u8 = undefined;
    const call = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}
    ), &buf2);
    try testing.expect(std.mem.startsWith(u8, call, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, bodyOf(call), "\\\"ok\\\":true") != null);
}

test "POST a notification → 202 Accepted, no body" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expectEqualStrings("", bodyOf(got));
}

test "non-/mcp path passes through; GET /mcp → 405" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    try r.get("/", hApp);

    var buf: [2048]u8 = undefined;
    const app = runWire(&r, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("app", bodyOf(app));

    var buf2: [2048]u8 = undefined;
    const get = runWire(&r, "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", &buf2);
    try testing.expect(std.mem.startsWith(u8, get, "HTTP/1.1 405"));
    try testing.expect(std.mem.find(u8, get, "Allow: POST") != null);
}

test "Origin allowlist: match → 200, mismatch → 403, absent → allowed" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    const origins = [_][]const u8{"http://localhost:7717"};
    var transport = Transport{ .gpa = gpa, .server = &server, .allowed_origins = &origins };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var b1: [4096]u8 = undefined;
    const ok = runWire(&r, postOrigin("http://localhost:7717",
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ), &b1);
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200"));

    var b2: [4096]u8 = undefined;
    const bad = runWire(&r, postOrigin("http://evil.example",
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list"}
    ), &b2);
    try testing.expect(std.mem.startsWith(u8, bad, "HTTP/1.1 403"));

    // A client that sends no Origin (non-browser) is allowed even with an
    // allowlist — the DNS-rebinding attack is browser-driven.
    var b3: [4096]u8 = undefined;
    const no_origin = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":3,"method":"tools/list"}
    ), &b3);
    try testing.expect(std.mem.startsWith(u8, no_origin, "HTTP/1.1 200"));
}

test "SSE-on-POST: Accept text/event-stream → response delivered as an SSE data event" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    const got = runWire(&r, postAccept("application/json, text/event-stream",
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got, "Content-Type: text/event-stream") != null);
    try testing.expect(std.mem.find(u8, got, "Transfer-Encoding: chunked") != null);
    // The JSON-RPC response is framed as one SSE data event (whole event in one
    // chunk, so the substrings are contiguous).
    try testing.expect(std.mem.find(u8, got, "data: {\"jsonrpc\"") != null);
    try testing.expect(std.mem.find(u8, got, "\"echo\"") != null);
}

test "SSE-on-POST: tool progress notifications stream live, then the result" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    const got = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"work","arguments":{},"_meta":{"progressToken":"p1"}}}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    // Two progress notifications + the final result = 3 data events.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "notifications/progress"));
    try testing.expect(std.mem.count(u8, got, "data: ") >= 3);
    try testing.expect(std.mem.find(u8, got, "\\\"done\\\":true") != null);
}

test "SSE-on-POST: a notification with SSE Accept → 202, no stream started" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expect(std.mem.find(u8, got, "text/event-stream") == null);
}

test "stream=.off forces application/json even when the client accepts SSE" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .stream = .off };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got, "Content-Type: application/json") != null);
    try testing.expect(std.mem.find(u8, got, "text/event-stream") == null);
}

test "sessions: initialize assigns Mcp-Session-Id; missing/unknown → 404; DELETE tears down" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;

    // initialize → 200 + a session id.
    const init = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    try testing.expect(std.mem.startsWith(u8, init, "HTTP/1.1 200"));
    const sid_hdr = headerValue(init, "Mcp-Session-Id") orelse return error.NoSession;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_hdr.len], sid_hdr);
    const sid = sidbuf[0..sid_hdr.len];

    // A follow-up with no session id → 404.
    const noid = runWire(&r, postWithSession(&rbuf, "", list_body), &out);
    try testing.expect(std.mem.startsWith(u8, noid, "HTTP/1.1 404"));

    // With a bogus session id → 404.
    const bogus = runWire(&r, postWithSession(&rbuf, "deadbeef", list_body), &out);
    try testing.expect(std.mem.startsWith(u8, bogus, "HTTP/1.1 404"));

    // With the real session id → 200.
    const okid = runWire(&r, postWithSession(&rbuf, sid, list_body), &out);
    try testing.expect(std.mem.startsWith(u8, okid, "HTTP/1.1 200"));

    // DELETE → 204; afterwards the id is gone → 404.
    const del = runWire(&r, deleteWithSession(&rbuf, sid), &out);
    try testing.expect(std.mem.startsWith(u8, del, "HTTP/1.1 204"));
    const gone = runWire(&r, postWithSession(&rbuf, sid, list_body), &out);
    try testing.expect(std.mem.startsWith(u8, gone, "HTTP/1.1 404"));
}

test "sessions: tearing a session down also drops its server-side handshake state" {
    // `mcp.Server` scopes capabilities/revision/pending budget per peer, and a
    // peer handle is this transport's session tag. Nothing tells the server a
    // session ended, so without this the peer table only ever grows — and past
    // `Server.max_peers` the server starts refusing new handshakes outright.
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    server.max_peers = 2;
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;

    // Two sessions fill the server's peer table exactly.
    var ids: [2][64]u8 = undefined;
    var lens: [2]usize = undefined;
    for (0..2) |i| {
        const res = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
        try testing.expect(std.mem.startsWith(u8, res, "HTTP/1.1 200"));
        const h = headerValue(res, "Mcp-Session-Id") orelse return error.NoSession;
        @memcpy(ids[i][0..h.len], h);
        lens[i] = h.len;
    }
    try testing.expectEqual(@as(usize, 2), server.peers.items.len);

    // DELETE the first one: the server must forget that peer, not just the
    // session store.
    const del = runWire(&r, deleteWithSession(&rbuf, ids[0][0..lens[0]]), &out);
    try testing.expect(std.mem.startsWith(u8, del, "HTTP/1.1 204"));
    try testing.expectEqual(@as(usize, 1), server.peers.items.len);

    // ...so a third client can still hand shake. Without the write-back the
    // table would be full and this `initialize` would come back an error.
    const third = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    try testing.expect(std.mem.startsWith(u8, third, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, third, "\"error\"") == null);
    try testing.expectEqual(@as(usize, 2), server.peers.items.len);
}

test "sessions: GET streams pushed events as SSE; Last-Event-ID replays only newer" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;

    const init = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    const sid_hdr = headerValue(init, "Mcp-Session-Id").?;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_hdr.len], sid_hdr);
    const sid = sidbuf[0..sid_hdr.len];

    // Push to an unknown session is a no-op (false); to ours, true.
    try testing.expect((try sessions.push("nope", "x")) == false);
    try testing.expect((try sessions.push(sid, "{\"n\":1}")) == true);
    try testing.expect((try sessions.push(sid, "{\"n\":2}")) == true);

    // GET with no Last-Event-ID → both events, id-tagged, as SSE.
    const got = runWire(&r, getWithSession(&rbuf, sid, null), &out);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got, "Content-Type: text/event-stream") != null);
    try testing.expect(std.mem.find(u8, got, "id: 1") != null);
    try testing.expect(std.mem.find(u8, got, "data: {\"n\":1}") != null);
    try testing.expect(std.mem.find(u8, got, "id: 2") != null);
    try testing.expect(std.mem.find(u8, got, "data: {\"n\":2}") != null);

    // GET with Last-Event-ID: 1 → only event 2 (resumable replay).
    const got2 = runWire(&r, getWithSession(&rbuf, sid, "1"), &out);
    try testing.expect(std.mem.find(u8, got2, "id: 2") != null);
    try testing.expect(std.mem.find(u8, got2, "data: {\"n\":1}") == null);

    // GET past the last id → nothing queued: a heartbeat comment, still 200.
    const got3 = runWire(&r, getWithSession(&rbuf, sid, "2"), &out);
    try testing.expect(std.mem.startsWith(u8, got3, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got3, ": keep-alive") != null);
    try testing.expect(std.mem.find(u8, got3, "data:") == null);
}

test "sessions: GET/DELETE with an unknown session → 404" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [512]u8 = undefined;
    var out: [2048]u8 = undefined;
    try testing.expect(std.mem.startsWith(u8, runWire(&r, getWithSession(&rbuf, "ghost", null), &out), "HTTP/1.1 404"));
    try testing.expect(std.mem.startsWith(u8, runWire(&r, deleteWithSession(&rbuf, "ghost"), &out), "HTTP/1.1 404"));
}

test "oversized POST body → 413" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .max_body = 16 };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"padding":"xxxxxxxxxxxx"}}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 413"));
}

test "POST body cap boundary: exactly max_body is accepted, one byte over → 413" {
    // Zig 0.17 `allocRemaining(.limited(n))` accepts exactly n bytes; the
    // documented `max_body` is the largest accepted POST body.
    const gpa = testing.allocator;
    const json =
        \\{"jsonrpc":"2.0","id":9,"method":"tools/list"}
    ;
    var server = try buildServer(gpa);
    defer server.deinit();

    var buf: [8192]u8 = undefined;
    inline for (.{ .{ json.len, false }, .{ json.len - 1, true } }) |c| {
        var transport = Transport{ .gpa = gpa, .server = &server, .max_body = c[0] };
        var r = router.Router.init(gpa);
        defer r.deinit();
        try r.use(transport.middleware());
        const got = runWire(&r, post("/mcp", json), &buf);
        try testing.expectEqual(c[1], std.mem.startsWith(u8, got, "HTTP/1.1 413"));
    }
}

// ── server→client requests over HTTP ───────────────────────────────────────

const init_sampling_body =
    \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"sampling":{},"elicitation":{}},"clientInfo":{"name":"c","version":"1"}}}
;

/// Records the client's answer to a server→client request.
const Answers = struct {
    calls: u32 = 0,
    text: [64]u8 = @splat(0),
    len: usize = 0,

    fn on(ctx: ?*anyopaque, resp: *const mcp.ClientResponse) void {
        const self: *Answers = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        const r = resp.samplingResult() catch return;
        const n = @min(r.content.text.len, self.text.len);
        @memcpy(self.text[0..n], r.content.text[0..n]);
        self.len = n;
    }
};

/// A tool that fires an elicitation and returns immediately (the seam's shape).
fn askTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    _ = call.requestElicitation(.{ .form = .{
        .message = "Please provide your GitHub username",
        .requested_schema =
        \\{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}
        ,
    } }, .{}) catch return call.fail("refused");
    call.write("{\"asked\":true}");
    return false;
}

test "stateless single_client: POST of a JSON-RPC response → 202 and the handler runs" {
    // The `.single_client` opt-in is what makes a stateless round trip work at
    // all: the default refuses this POST (next test but one), because without
    // a session it cannot know the answer came from the client it asked.
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .stateless_responses = .single_client };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var out: [4096]u8 = undefined;
    _ = runWire(&r, post("/mcp", init_sampling_body), &out);

    // Issue a sampling request out of band (stateless endpoint: the bytes would
    // go wherever the app sends them; here we only need the pending entry).
    var answers = Answers{};
    var line: std.Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    const id = try server.sendSamplingRequest(&line.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 32,
    }, .{ .on_response = &Answers.on, .ctx = &answers });
    try testing.expectEqual(@as(u64, 1), id);
    try testing.expectEqual(@as(usize, 1), server.pendingCount());

    // The client answers with a POST. No reply body ⇒ 202 Accepted.
    const got = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"Paris"},"model":"m","stopReason":"endTurn"}}
    ), &out);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expectEqualStrings("", bodyOf(got));
    try testing.expectEqual(@as(u32, 1), answers.calls);
    try testing.expectEqualStrings("Paris", answers.text[0..answers.len]);
    try testing.expectEqual(@as(usize, 0), server.pendingCount());
}

/// A tool that asks the client's LLM for a completion **and registers a
/// handler for the answer** — the shape an app uses when it actually needs the
/// reply. `ctx` is the `*Answers` the answer is recorded into, so the test can
/// see exactly whose flow a given response landed in.
fn samplingTool(ctx: ?*anyopaque, call: *mcp.ToolCall) bool {
    _ = call.requestSampling(.{
        .messages = &.{.{ .role = .user, .content = .{ .text = "which city?" } }},
        .max_tokens = 32,
    }, .{ .on_response = &Answers.on, .ctx = ctx }) catch return call.fail("refused");
    call.write("{\"asked\":true}");
    return false;
}

test "stateless: a third party's response POST must not resolve another client's pending request" {
    // The attacker's test for the peer-scoping promise, on a **stateless**
    // endpoint (`sessions == null`). Every `runWire` call below is a separate
    // connection — a separate client — and the transport has no session handle
    // to tell them apart, which is exactly the question: does the promise
    // "one client cannot consume another's sampling reply" hold here too?
    //
    // Two distinct victims are in play on purpose. A one-client scenario
    // cannot distinguish "peer scoping works" from "peer scoping does not
    // exist": the bystander is an innocent third party whose pending request
    // must be untouched whatever the attacker does.
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var victim = Answers{};
    var bystander = Answers{};
    try server.addTool(.{
        .name = "ask_a",
        .description = "asks the client's LLM (client A's flow)",
        .input_schema = "{\"type\":\"object\"}",
        .handler = samplingTool,
        .ctx = &victim,
    });
    try server.addTool(.{
        .name = "ask_c",
        .description = "asks the client's LLM (bystander C's flow)",
        .input_schema = "{\"type\":\"object\"}",
        .handler = samplingTool,
        .ctx = &bystander,
    });
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var out: [8192]u8 = undefined;
    _ = runWire(&r, post("/mcp", init_sampling_body), &out);

    // Client A's tool call leaves `sampling/createMessage` id 1 outstanding,
    // delivered to A on its own POST's SSE stream.
    var out_a: [8192]u8 = undefined;
    const a_call = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ask_a"}}
    ), &out_a);
    try testing.expect(std.mem.find(u8, a_call, "sampling/createMessage") != null);

    // Bystander C does the same: id 2 outstanding, nothing to do with A.
    var out_c: [8192]u8 = undefined;
    _ = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"ask_c"}}
    ), &out_c);
    try testing.expectEqual(@as(usize, 2), server.pendingCount()); // both really pending

    // Client B — a different client, never asked anything — POSTs a response
    // carrying A's request id. It must not reach A's handler, and must not
    // disturb the bystander either.
    var out_b: [4096]u8 = undefined;
    const from_b = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"attacker"},"model":"m","stopReason":"endTurn"}}
    ), &out_b);
    try testing.expectEqual(@as(u32, 0), victim.calls); // A's flow untouched
    try testing.expectEqual(@as(u32, 0), bystander.calls); // C's flow untouched
    try testing.expectEqual(@as(usize, 2), server.pendingCount());
    // …because the endpoint refused to correlate it at all: with no session
    // there is no honest answer to "which client is this?".
    try testing.expect(std.mem.startsWith(u8, from_b, "HTTP/1.1 400"));

    // The refusal is the *documented cost*, not a filter that happens to catch
    // attackers: A's own answer is refused too, for the identical reason. A
    // stateless endpoint cannot complete this round trip — configure sessions.
    var out_a2: [4096]u8 = undefined;
    const from_a = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"genuine"},"model":"m","stopReason":"endTurn"}}
    ), &out_a2);
    try testing.expect(std.mem.startsWith(u8, from_a, "HTTP/1.1 400"));
    try testing.expectEqual(@as(u32, 0), victim.calls);

    // Everything that is not a correlatable response is unaffected: an
    // ordinary request still works on the same stateless endpoint.
    var out_l: [4096]u8 = undefined;
    const list = runWire(&r, post("/mcp", list_body), &out_l);
    try testing.expect(std.mem.startsWith(u8, list, "HTTP/1.1 200"));
}

test "stateless single_client: the opt-in really does correlate any client's response (its cost)" {
    // The other half of the decision, asserted rather than described: under
    // `.single_client` a response from a *different* connection resolves the
    // pending request. That is a leak on a multi-client endpoint — which is
    // why it is an explicit opt-in — and it is what a genuinely single-client
    // deployment is buying. If this test ever fails, the opt-in has stopped
    // meaning anything and the flag should go.
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var victim = Answers{};
    try server.addTool(.{
        .name = "ask_a",
        .description = "asks the client's LLM",
        .input_schema = "{\"type\":\"object\"}",
        .handler = samplingTool,
        .ctx = &victim,
    });
    var transport = Transport{ .gpa = gpa, .server = &server, .stateless_responses = .single_client };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var out: [8192]u8 = undefined;
    _ = runWire(&r, post("/mcp", init_sampling_body), &out);
    var out_a: [8192]u8 = undefined;
    _ = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ask_a"}}
    ), &out_a);
    try testing.expectEqual(@as(usize, 1), server.pendingCount());

    var out_b: [4096]u8 = undefined;
    const from_b = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"anyone"},"model":"m","stopReason":"endTurn"}}
    ), &out_b);
    try testing.expect(std.mem.startsWith(u8, from_b, "HTTP/1.1 202"));
    try testing.expectEqual(@as(u32, 1), victim.calls);
    try testing.expectEqualStrings("anyone", victim.text[0..victim.len]);
}

test "correlatableResponse: exactly the shapes mcp would route to deliverResponse" {
    const gpa = testing.allocator;
    // Responses: no `method`, an integer id, a result or an error.
    try testing.expect(correlatableResponse(gpa,
        \\{"jsonrpc":"2.0","id":1,"result":{"x":1}}
    ));
    try testing.expect(correlatableResponse(gpa,
        \\{"jsonrpc":"2.0","id":42,"error":{"code":-1,"message":"user rejected"}}
    ));
    try testing.expect(correlatableResponse(gpa,
        \\{"result":null,"id":7}
    )); // key order is not a signal
    // Requests and notifications keep their old path (`method` present).
    try testing.expect(!correlatableResponse(gpa,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ));
    try testing.expect(!correlatableResponse(gpa,
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
    ));
    // `method` decides even when a bogus `result` rides along: `mcp` looks up
    // `method` first and dispatches this as a *request*, so refusing it here
    // would change the behaviour of a message this transport is not entitled
    // to judge. Dropping the `!has_method` term otherwise survives the whole
    // suite — the malformed-but-method-bearing body is the only input that
    // separates the two.
    try testing.expect(!correlatableResponse(gpa,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","result":{}}
    ));
    // Nothing our ids could ever match: no id, a non-integer id, a negative
    // id, no payload at all. `mcp` drops or refuses these itself.
    try testing.expect(!correlatableResponse(gpa, "{\"result\":{}}"));
    try testing.expect(!correlatableResponse(gpa, "{\"id\":\"1\",\"result\":{}}"));
    try testing.expect(!correlatableResponse(gpa, "{\"id\":-1,\"result\":{}}"));
    try testing.expect(!correlatableResponse(gpa, "{\"id\":1.5,\"result\":{}}"));
    try testing.expect(!correlatableResponse(gpa, "{\"jsonrpc\":\"2.0\",\"id\":1}"));
    // A non-numeric id must be skipped as one whole value: if the scan
    // consumed only its `object_begin`, the nested "result" below would be
    // read as a top-level key and this would answer true on a body that
    // carries no top-level payload at all.
    try testing.expect(!correlatableResponse(gpa,
        \\{"id":{"result":1},"jsonrpc":"2.0"}
    ));
    // Malformed / non-object bodies are not responses; the real parse reports.
    try testing.expect(!correlatableResponse(gpa, "not json"));
    try testing.expect(!correlatableResponse(gpa, "[{\"id\":1,\"result\":{}}]"));
    try testing.expect(!correlatableResponse(gpa, "{"));
    try testing.expect(!correlatableResponse(gpa, "{}"));
}

test "sessions: a response POSTed on another session cannot resolve the request" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;

    // Two independent sessions over the same mcp.Server.
    const a_init = runWire(&r, postWithSession(&rbuf, "", init_sampling_body), &out);
    var a_buf: [64]u8 = undefined;
    const a_hdr = headerValue(a_init, "Mcp-Session-Id").?;
    @memcpy(a_buf[0..a_hdr.len], a_hdr);
    const sid_a = a_buf[0..a_hdr.len];

    const b_init = runWire(&r, postWithSession(&rbuf, "", init_sampling_body), &out);
    var b_buf: [64]u8 = undefined;
    const b_hdr = headerValue(b_init, "Mcp-Session-Id").?;
    @memcpy(b_buf[0..b_hdr.len], b_hdr);
    const sid_b = b_buf[0..b_hdr.len];
    const c_init = runWire(&r, postWithSession(&rbuf, "", init_sampling_body), &out);
    var c_buf: [64]u8 = undefined;
    const c_hdr = headerValue(c_init, "Mcp-Session-Id").?;
    @memcpy(c_buf[0..c_hdr.len], c_hdr);
    const sid_c = c_buf[0..c_hdr.len];
    try testing.expect(!std.mem.eql(u8, sid_a, sid_b));
    try testing.expect(sessions.tagOf(sid_a).? != sessions.tagOf(sid_b).?);
    try testing.expect(sessions.tagOf(sid_c).? != sessions.tagOf(sid_a).?);

    // A sampling request bound to session A (id 1) — and one bound to the
    // bystander session C (id 2), which must survive every step below
    // untouched. Without the bystander, "the request stayed pending" could
    // pass for the wrong reason (nothing ever resolves anything).
    var answers = Answers{};
    var bystander = Answers{};
    var line: std.Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    _ = try server.sendSamplingRequest(&line.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 32,
    }, .{ .peer = sessions.tagOf(sid_a).?, .on_response = &Answers.on, .ctx = &answers });
    _ = try sessions.push(sid_a, std.mem.trimEnd(u8, line.written(), "\n"));

    var line_c: std.Io.Writer.Allocating = .init(gpa);
    defer line_c.deinit();
    _ = try server.sendSamplingRequest(&line_c.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 32,
    }, .{ .peer = sessions.tagOf(sid_c).?, .on_response = &Answers.on, .ctx = &bystander });
    _ = try sessions.push(sid_c, std.mem.trimEnd(u8, line_c.written(), "\n"));
    try testing.expectEqual(@as(usize, 2), server.pendingCount());

    const answer =
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"leaked"},"model":"m"}}
    ;
    // Session B answers with the right id: 202 (nothing to reply), but the
    // request must NOT resolve — otherwise B's user's data lands in A's flow.
    const from_b = runWire(&r, postWithSession(&rbuf, sid_b, answer), &out);
    try testing.expect(std.mem.startsWith(u8, from_b, "HTTP/1.1 202"));
    try testing.expectEqual(@as(u32, 0), answers.calls);
    try testing.expectEqual(@as(u32, 0), bystander.calls);
    try testing.expectEqual(@as(usize, 2), server.pendingCount());

    // B tries the bystander's id too — a foreign session is foreign to every
    // pending request, not just to the one it was aimed at.
    const at_c =
        \\{"jsonrpc":"2.0","id":2,"result":{"role":"assistant","content":{"type":"text","text":"leaked"},"model":"m"}}
    ;
    const from_b2 = runWire(&r, postWithSession(&rbuf, sid_b, at_c), &out);
    try testing.expect(std.mem.startsWith(u8, from_b2, "HTTP/1.1 202"));
    try testing.expectEqual(@as(u32, 0), bystander.calls);
    try testing.expectEqual(@as(usize, 2), server.pendingCount());

    // Session A answers: delivered — and only A's own request resolves.
    const from_a = runWire(&r, postWithSession(&rbuf, sid_a, answer), &out);
    try testing.expect(std.mem.startsWith(u8, from_a, "HTTP/1.1 202"));
    try testing.expectEqual(@as(u32, 1), answers.calls);
    try testing.expectEqualStrings("leaked", answers.text[0..answers.len]);
    try testing.expectEqual(@as(u32, 0), bystander.calls);
    try testing.expectEqual(@as(usize, 1), server.pendingCount());

    // The request itself was delivered to A's GET stream, not B's.
    const a_stream = runWire(&r, getWithSession(&rbuf, sid_a, null), &out);
    try testing.expect(std.mem.find(u8, a_stream, "sampling/createMessage") != null);
    const b_stream = runWire(&r, getWithSession(&rbuf, sid_b, null), &out);
    try testing.expect(std.mem.find(u8, b_stream, "sampling/createMessage") == null);
}

test "application/json mode: a tool's outbound request never lands in the body" {
    // An `application/json` body must be exactly one JSON object. A tool that
    // issues elicitation writes two lines; the earlier one must be routed to
    // the session stream, not concatenated into the response.
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{
        .name = "ask",
        .description = "asks the user",
        .input_schema = "{\"type\":\"object\"}",
        .handler = askTool,
    });
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const init = runWire(&r, postWithSession(&rbuf, "", init_sampling_body), &out);
    const sid_hdr = headerValue(init, "Mcp-Session-Id").?;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_hdr.len], sid_hdr);
    const sid = sidbuf[0..sid_hdr.len];

    const got = runWire(&r, postWithSession(&rbuf, sid,
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ask"}}
    ), &out);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const b = bodyOf(got);
    // Exactly the tool result, and nothing of the elicitation request.
    try testing.expect(std.mem.find(u8, b, "elicitation/create") == null);
    try testing.expect(std.mem.find(u8, b, "\"id\":5") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, b, "\"jsonrpc\""));

    // The elicitation request went to the session's GET stream instead.
    const stream = runWire(&r, getWithSession(&rbuf, sid, null), &out);
    try testing.expect(std.mem.find(u8, stream, "elicitation/create") != null);
}

test "SSE mode: a tool's outbound request streams as its own event before the result" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{
        .name = "ask",
        .description = "asks the user",
        .input_schema = "{\"type\":\"object\"}",
        .handler = askTool,
    });
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var out: [8192]u8 = undefined;
    _ = runWire(&r, post("/mcp", init_sampling_body), &out);

    var out2: [8192]u8 = undefined;
    const got = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"ask"}}
    ), &out2);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const req_at = std.mem.find(u8, got, "elicitation/create") orelse return error.NoRequestEvent;
    const res_at = std.mem.find(u8, got, "\"id\":6") orelse return error.NoResult;
    try testing.expect(req_at < res_at); // request precedes the tool result
    try testing.expect(std.mem.count(u8, got, "data: ") >= 2);
}

test "Sessions.push: past replay_depth, the OLDEST event is evicted (mutation guard)" {
    // No prior test ever set a small replay_depth, so the FIFO-eviction branch
    // in push() (`s.events.items.len >= self.replay_depth`) was reachable only
    // by inspection: a mutation loosening it to '>' (keeping one extra event)
    // built and passed the whole suite.
    var s = Sessions.init(testing.allocator);
    defer s.deinit();
    s.replay_depth = 2;
    const id = (try s.create()).id;

    _ = try s.push(id, "a");
    _ = try s.push(id, "b");
    _ = try s.push(id, "c"); // over the cap -> "a" (event id 1) evicted

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var batch: std.ArrayList(Sessions.StoredEvent) = .empty;
    _ = (try s.drainAfter(id, 0, arena_state.allocator(), &batch)).?;
    try testing.expectEqual(@as(usize, 2), batch.items.len);
    try testing.expectEqualStrings("b", batch.items[0].data);
    try testing.expectEqualStrings("c", batch.items[1].data);
}

test "GET: a malformed Last-Event-ID header replays the whole buffer, not nothing (mutation guard)" {
    // parseLastEventId's error fallback (catch 0) is documented as "replay the
    // whole buffer" but no test ever sent an actually malformed header value
    // -- every existing GET test either omits it or sends a valid number.
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const init = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    const sid_hdr = headerValue(init, "Mcp-Session-Id").?;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_hdr.len], sid_hdr);
    const sid = sidbuf[0..sid_hdr.len];

    _ = try sessions.push(sid, "{\"n\":1}");

    const got = runWire(&r, getWithSession(&rbuf, sid, "not-a-number"), &out);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got, "data: {\"n\":1}") != null);
}

test "Sessions.create: refuses new sessions past max_sessions (audit MED)" {
    // Batch-10 audit MED: create() had no cap, so an unauthenticated peer
    // spamming `initialize` grew the registry (and per-session replay buffers)
    // without bound. Past max_sessions, create() must fail closed.
    var s = Sessions.init(testing.allocator);
    defer s.deinit();
    s.max_sessions = 2;
    const first = try s.create();
    const second = try s.create();
    try testing.expectError(error.TooManySessions, s.create());
    // Every session's peer handle is distinct, and it is the one `tagOf`
    // reports — `create` hands it back so the transport never has to look it
    // up again (and never has to answer a lookup that failed).
    try testing.expect(first.tag != second.tag);
    try testing.expectEqual(first.tag, s.tagOf(first.id).?);
    try testing.expectEqual(second.tag, s.tagOf(second.id).?);
}

// ── oracle: replay of a real python-mcp SDK session (see oracle_vectors.zig) ─
//
// The tests below feed the EXACT request bytes a real run of the official
// `mcp` Python SDK's client sent to a real run of its server (captured once,
// frozen in `oracle_vectors.zig`, no socket opened here) through this
// module's own `Transport`, via the same offline `runWire` harness every
// other test in this file uses. This closes the gap `NOTICE`/`README.md`
// used to describe ("cross-checked for parity against a reference Dart
// server") without any captured bytes or live check ever backing it: the
// reference is now the specification's own SDK, exercised as a black-box
// oracle, and the check is real and offline.

const oracle = @import("oracle_vectors.zig");

test "oracle: the real python-mcp client's initialize request negotiates the real protocolVersion" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    // The real client's own Accept header, byte-exact — see oracle_vectors.zig.
    const got = runWire(&r, postAccept("application/json, text/event-stream", oracle.init_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got, "Content-Type: text/event-stream") != null);
    try testing.expect(headerValue(got, "Mcp-Session-Id") != null);
    const b = bodyOf(got);
    try testing.expect(std.mem.find(u8, b, "\"jsonrpc\":\"2.0\"") != null);
    try testing.expect(std.mem.find(u8, b, "\"id\":1") != null);
    // The exact protocolVersion string the real reference SDK negotiated for
    // this exact request (both request and response frozen from the same
    // live capture, so this is not a value we invented).
    try testing.expect(std.mem.find(u8, oracle.init_response_json, "\"protocolVersion\":\"2025-11-25\"") != null);
    try testing.expect(std.mem.find(u8, b, "\"protocolVersion\":\"2025-11-25\"") != null);
}

test "oracle: notifications/initialized (real client bytes) -> 202, matching the real server" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, post("/mcp", oracle.notifications_initialized_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expectEqualStrings("", bodyOf(got));
    // The real reference server answered the identical bytes the same way.
    try testing.expect(std.mem.startsWith(u8, oracle.notifications_initialized_status, "HTTP/1.1 202"));
}

test "oracle: tools/list (real client bytes) lists this module's tools" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, postAccept("application/json, text/event-stream", oracle.tools_list_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const b = bodyOf(got);
    try testing.expect(std.mem.find(u8, b, "\"echo\"") != null);
    try testing.expect(std.mem.find(u8, b, "\"work\"") != null);
    // Same two tool names the real reference server reported for this
    // module's own tools/list request (frozen from the live capture).
    try testing.expect(std.mem.find(u8, oracle.tools_list_response_json, "\"echo\"") != null);
    try testing.expect(std.mem.find(u8, oracle.tools_list_response_json, "\"work\"") != null);
}

test "oracle: tools/call \"echo\" (real client bytes) reproduces the real argument" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    // The real client's captured tools/call request, byte-exact, including
    // its real argument value "hello-mcp-http-oracle". Plain `post` (no SSE
    // Accept) so the response is a single `application/json` object,
    // directly parseable — the SSE-framing path is exercised separately by
    // the "work" oracle test below.
    const got = runWire(&r, post("/mcp", oracle.echo_call_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const b = bodyOf(got);

    // structuredContent is byte-comparable field-by-field (this module's tool
    // deliberately wrote the same `{"result": <value>}` wrapping FastMCP used
    // for the real capture — see oracleEchoTool's doc comment).
    var ours = try std.json.parseFromSlice(std.json.Value, gpa, b, .{});
    defer ours.deinit();
    var real = try std.json.parseFromSlice(std.json.Value, gpa, oracle.echo_call_response_json, .{});
    defer real.deinit();
    const our_sc = ours.value.object.get("result").?.object.get("structuredContent").?.object.get("result").?.string;
    const real_sc = real.value.object.get("result").?.object.get("structuredContent").?.object.get("result").?.string;
    try testing.expectEqualStrings("hello-mcp-http-oracle", real_sc); // sanity: this IS the real captured value
    try testing.expectEqualStrings(real_sc, our_sc);

    // content[0].text is NOT byte-comparable: the real SDK's framework layer
    // (FastMCP) puts the bare scalar there for a plain-string tool return,
    // while this module's lower-level ToolCall.write is opaque raw text (the
    // caller supplied the whole `{"result":...}` object as the text) — a
    // real, benign convention difference between the two layers, not a bug.
    // The marker value is still present in both, which is what we assert.
    try testing.expect(std.mem.find(u8, b, "hello-mcp-http-oracle") != null);
    try testing.expect(std.mem.find(u8, oracle.echo_call_response_json, "hello-mcp-http-oracle") != null);
}

test "oracle: tools/call \"work\" (real client bytes) reproduces the real progress frames byte-exact" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    // The real client's captured tools/call request (progressToken: 4, a
    // bare JSON number), byte-exact.
    const got = runWire(&r, postAccept("text/event-stream", oracle.work_call_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got, "Content-Type: text/event-stream") != null);

    // Byte-exact: this module's own notifications/progress field order
    // matches the real reference server's, so the captured lines are
    // asserted as literal substrings of THIS module's own SSE output.
    try testing.expect(std.mem.find(u8, got, oracle.progress_1_json) != null);
    try testing.expect(std.mem.find(u8, got, oracle.progress_2_json) != null);
    try testing.expect(std.mem.count(u8, got, "data: ") >= 3); // 2 progress + 1 result

    // Final result: structural comparison, same convention note as the echo
    // test above (content.text differs by framework convention; compare
    // structuredContent, which was deliberately written to match).
    const last_data = std.mem.findLast(u8, got, "data: ") orelse return error.NoResultEvent;
    const after = got[last_data + "data: ".len ..];
    const line_end = std.mem.findAny(u8, after, "\r\n") orelse after.len;
    const result_line = after[0..line_end];
    var ours = try std.json.parseFromSlice(std.json.Value, gpa, result_line, .{});
    defer ours.deinit();
    var real = try std.json.parseFromSlice(std.json.Value, gpa, oracle.work_call_response_json, .{});
    defer real.deinit();
    try testing.expectEqualStrings(
        real.value.object.get("result").?.object.get("structuredContent").?.object.get("result").?.string,
        ours.value.object.get("result").?.object.get("structuredContent").?.object.get("result").?.string,
    );
}

test "regression: a member with no value is not a body, and does not trip skipValue's unreachable" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ "{\"a\":}", "{\"id\":}", "{\"x\":1,\"a\":}", "{\"jsonrpc\":\"2.0\",\"y\":]", "{\"a\":" }) |body| {
        try std.testing.expect(!isInitialize(gpa, body));
        try std.testing.expect(!correlatableResponse(gpa, body));
    }
}

test "regression: a POST whose body has a member with no value is answered, not a panic" {
    const gpa = std.testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var out: [4096]u8 = undefined;
    const got = runWire(&r, post("/mcp", "{\"a\":}"), &out);
    try std.testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 "));
}

// ── fuzz: the pre-parse scanners never panic, OOB, or leak ─────────────────
//
// `isInitialize` and `correlatableResponse` are the decode entry point that
// sees a POST body BEFORE `mcp.Server.handleMessageFrom`'s authoritative
// parse — a single-pass `std.json.Scanner` walk over attacker-controlled
// bytes, hand-written (not delegated to a library parse call) specifically
// to avoid a second full tree parse. That hand-written loop is exactly the
// kind of code this gate exists for: the doc comments on both functions
// already argue "a malformed body surfaces its real error later", which is
// true for VALIDITY but says nothing about whether the scan loop itself can
// panic, run out of bounds, or leak the `.allocated_string`/`.allocated_number`
// it frees on every branch. `handleMessageFrom` itself lives in `mcp`, whose
// own decode surface is that module's obligation, not this one's.
const fuzzseed = @import("testkit").fuzz;

/// ⛔ Every string in the corpus this replaces — twelve real JSON-RPC bodies,
/// including the `initialize` request the scanners exist to recognise —
/// reached `isInitialize` as the EMPTY body. `buildJsonRpcish` opened with
/// `smith.valueRangeAtMost(u8, 0, 5)`, which reads EIGHT octets as a
/// little-endian `u64` and returns the range MINIMUM unless that whole word
/// already lies in 0..5. `{"jsonrpc` is nowhere near, so every seed took the
/// "pure arbitrary bytes" branch, `smith.bytes(&raw)` ate the rest of the
/// body, and the ranged length after it found nothing left and returned 0.
/// Measured 2026-09-07: **0 of 12 seeds carried an octet, and neither scanner
/// ever got past `object_begin`.**
///
/// Seeds are scripts now. Octet 0 selects: `0x00` means "the rest of this seed
/// IS the body, verbatim" — which is what lets a real JSON-RPC message be a
/// seed — and anything else means "the rest is a script assembling a JSON
/// object" from the keys the scanners branch on.
const jsonrpc_corpus = [_][]const u8{
    fuzzseed.seed("\x00" ++ "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}"), // ⭐ the request both scanners exist for
    fuzzseed.seed("\x00" ++ "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"),
    fuzzseed.seed("\x00" ++ "{\"a\":{\"nested\":[1,2,{\"x\":3}]},\"b\":[1,[2,3],{}],\"c\":null,\"d\":true,\"method\":\"initialize\"}"), // the key that matters, behind nesting
    fuzzseed.seed("\x00" ++ "{\"method\":\"in\\u0069tialize\"}"), // ⭐ the escape that forces `.allocated_string`
    fuzzseed.seed("\x00" ++ "{\"jsonrpc\":\"2.0\",\"id\":1}"),
    fuzzseed.seed("\x00" ++ "not json"),
    fuzzseed.seed("\x00" ++ "[1,2,3]"), // an array, not an object
    fuzzseed.seed("\x00" ++ "{"), // truncated at `object_begin`
    fuzzseed.seed("\x00" ++ "{}"), // ⭐ the empty object: legal JSON, no keys — the shape an `accepted > 0` guard would score
    fuzzseed.seed("\x00" ++ "{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{}}"), // ⭐ a correlatable response
    fuzzseed.seed("\x00" ++ "{\"jsonrpc\":\"2.0\",\"id\":5,\"error\":{\"code\":-1,\"message\":\"x\"}}"), // the error form of one
    fuzzseed.seed("\x00" ++ "{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"result\":null}"), // a string id
    fuzzseed.seed("\x00" ++ "{\"method\":\"" ++ strRepeat("x", 100) ++ "\"}"), // a method name past `max_field_len`
    fuzzseed.seed("\x00" ++ "{\"method\":\"initialize\",\"method\":\"tools/list\"}"), // ⭐ the key twice: which one wins is a real decision
    fuzzseed.seed("\x00"), // the empty body
    fuzzseed.seed("\x01" ++ "\x03\x00\x00\x01\x01\x02\x02"), // script: an object of three fields
    fuzzseed.seed("\x01" ++ "\x02\x02\x04\x01\x03\x05"), // script: nested object and array values
    fuzzseed.seed("\x01" ++ "\x01\x00\x01\x01\x01"), // script: a long string, forcing the allocating scanner path
};

test "fuzz: isInitialize / correlatableResponse never panic, OOB or leak on arbitrary JSON-RPC-shaped bytes" {
    try std.testing.fuzz({}, fuzzPreParseNeverLeaks, .{ .corpus = &jsonrpc_corpus });
}

const jsonrpc_buf_len = 2048;

fn fuzzPreParseNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var raw: [1 + jsonrpc_buf_len]u8 = undefined;
    // ⚠ ONE byte-first draw. See `jsonrpc_corpus` for what the ranged draws
    // did to twelve real JSON-RPC bodies.
    const n: usize = smith.slice(&raw);
    var buf: [jsonrpc_buf_len]u8 = undefined;
    const body = buildJsonRpcish(raw[0..n], &buf);
    const gpa = std.testing.allocator;
    _ = isInitialize(gpa, body);
    _ = correlatableResponse(gpa, body);
}

/// Octet 0 selects: `0x00` means the remaining octets are the body verbatim;
/// anything else means they are a script assembling a JSON object from the
/// field names the two scanners actually branch on (`method`, `id`, `result`,
/// `error`, plus filler keys), with scalar/nested/long/escaped values —
/// arbitrary bytes essentially never spell a well-formed JSON object, so
/// without the script the scan loop past `object_begin` would almost never
/// run.
fn buildJsonRpcish(seed: []const u8, buf: []u8) []const u8 {
    if (seed.len == 0) return buf[0..0];
    if (seed[0] == 0) {
        const body = seed[1..];
        const n = @min(body.len, buf.len);
        @memcpy(buf[0..n], body[0..n]);
        return buf[0..n];
    }
    var script: fuzzseed.Cursor = .{ .bytes = seed[1..] };
    var w: std.Io.Writer = .fixed(buf);
    writeJsonObject(&script, &w, 3);
    return w.buffered();
}

test "corpus: every body reaches both scanners, and what they recognise is pinned" {
    // ⭐ `{}` is legal JSON with no keys, so "the scanner returned without an
    // error" would have read green on a corpus that walked nothing. The
    // numbers the empty body cannot produce are the `initialize` requests
    // RECOGNISED and the responses found CORRELATABLE — the two decisions
    // these scanners exist to make.
    const gpa = std.testing.allocator;
    var nonempty: usize = 0;
    var octets: usize = 0;
    var initializes: usize = 0;
    var correlatable: usize = 0;
    for (jsonrpc_corpus) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [1 + jsonrpc_buf_len]u8 = undefined;
        const n: usize = smith.slice(&raw);
        var buf: [jsonrpc_buf_len]u8 = undefined;
        const body = buildJsonRpcish(raw[0..n], &buf);
        if (body.len != 0) nonempty += 1;
        octets += body.len;
        if (isInitialize(gpa, body)) initializes += 1;
        if (correlatableResponse(gpa, body)) correlatable += 1;
    }
    // Measured 2026-09-07. The corpus this replaces handed the scanners 0
    // octets, from twelve real JSON-RPC bodies.
    try testing.expectEqual(@as(usize, 17), nonempty);
    try testing.expectEqual(@as(usize, 1129), octets);
    try testing.expectEqual(@as(usize, 3), initializes);
    try testing.expectEqual(@as(usize, 2), correlatable);
}

fn writeJsonObject(script: *fuzzseed.Cursor, w: *std.Io.Writer, depth_left: u8) void {
    w.writeByte('{') catch return;
    const n = script.ranged(0, 3);
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        if (k != 0) w.writeByte(',') catch return;
        writeJsonField(script, w, depth_left);
    }
    w.writeByte('}') catch {};
}

fn writeJsonArray(script: *fuzzseed.Cursor, w: *std.Io.Writer, depth_left: u8) void {
    w.writeByte('[') catch return;
    const n = script.ranged(0, 3);
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        if (k != 0) w.writeByte(',') catch return;
        writeJsonValue(script, w, depth_left);
    }
    w.writeByte(']') catch {};
}

fn writeJsonField(script: *fuzzseed.Cursor, w: *std.Io.Writer, depth_left: u8) void {
    const keys = [_][]const u8{ "method", "id", "result", "error", "jsonrpc", "params", "x" };
    w.print("\"{s}\":", .{keys[script.ranged(0, keys.len - 1)]}) catch return;
    writeJsonValue(script, w, depth_left);
}

fn writeJsonValue(script: *fuzzseed.Cursor, w: *std.Io.Writer, depth_left: u8) void {
    const kind = if (depth_left == 0) script.ranged(0, 3) else script.ranged(0, 5);
    switch (kind) {
        0 => w.writeAll("\"initialize\"") catch {},
        1 => writeJsonString(script, w),
        2 => w.print("{d}", .{@as(i32, @bitCast((@as(u32, script.word()) << 16) | @as(u32, script.word())))}) catch {},
        3 => w.writeAll(switch (script.ranged(0, 2)) {
            0 => "null",
            1 => "true",
            else => "false",
        }) catch {},
        4 => writeJsonObject(script, w, depth_left - 1),
        else => writeJsonArray(script, w, depth_left - 1),
    }
}

/// A short plain string, a long one (past `max_field_len`, forcing the
/// `.allocated_string` path both scanners must free), or one containing a
/// `\u` escape (same forced-allocation path via a different route).
fn writeJsonString(script: *fuzzseed.Cursor, w: *std.Io.Writer) void {
    const long = script.byte() & 1 == 1;
    const len = if (long) script.ranged(60, 120) else script.ranged(0, 8);
    w.writeByte('"') catch return;
    var j: u32 = 0;
    while (j < len) : (j += 1) {
        switch (script.ranged(0, 2)) {
            0 => w.writeByte('a') catch return,
            1 => w.writeAll("\\u0069") catch return,
            else => w.writeByte('x') catch return,
        }
    }
    w.writeByte('"') catch {};
}

test "a session id carries no counter and no clock" {
    const gpa = testing.allocator;
    var s = Sessions.init(gpa);
    defer s.deinit();

    // The id used to be `monoNs() ^ (@intFromPtr(store) *% K)` in the high 64
    // bits and a plain incrementing `seq` in the low 64. Possession of an id
    // is the entire gate on GET/POST/DELETE for a session, so the module's
    // advertised peer-scoping property rested on it being unguessable — and
    // two of an attacker's own ids, taken either side of the victim's, cancel
    // the constant `K` and pin the counter exactly, leaving ~2^20 candidates
    // (W2 re-audit 2026-09-02, `mcp-http` F1).
    const n = 8;
    var ids: [n][]const u8 = undefined;
    for (&ids) |*slot| {
        const c = try s.create();
        slot.* = c.id;
    }

    for (ids, 0..) |id, i| {
        try testing.expectEqual(@as(usize, 32), id.len);
        for (id) |ch| try testing.expect(std.ascii.isHex(ch));
        // No two ids share a half: a counter in either half would make the
        // low halves consecutive, and a process-constant mixed with a clock
        // would make the high halves differ only in their bottom bits.
        for (ids, 0..) |other, j| {
            if (i == j) continue;
            try testing.expect(!std.mem.eql(u8, id[0..16], other[0..16]));
            try testing.expect(!std.mem.eql(u8, id[16..32], other[16..32]));
        }
    }

    // The sharpest single check: the low half of consecutive ids differed by
    // exactly 1 before the fix.
    const a = try std.fmt.parseInt(u64, ids[0][16..32], 16);
    const b = try std.fmt.parseInt(u64, ids[1][16..32], 16);
    try testing.expect(b -% a != 1);

    // And the population is spread, not clustered: half the bits set, give or
    // take. A clock-derived high half fails this by a mile.
    var ones: usize = 0;
    for (ids) |id| {
        const hi = try std.fmt.parseInt(u64, id[0..16], 16);
        const lo = try std.fmt.parseInt(u64, id[16..32], 16);
        ones += @popCount(hi) + @popCount(lo);
    }
    try testing.expect(ones > n * 128 / 4);
    try testing.expect(ones < n * 128 * 3 / 4);
}

test "a table filled by an abandoned flood heals; a busy one still refuses" {
    const gpa = testing.allocator;
    var s = Sessions.init(gpa);
    defer s.deinit();
    s.max_sessions = 3;

    for (0..3) |_| _ = try s.create();
    // Busy table: every session was just touched, so the cap holds — evicting
    // a live session to make room would turn a flood into a cross-client
    // denial, which is worse than an outage.
    try testing.expectError(error.TooManySessions, s.create());

    // The same table, abandoned. Nothing but an explicit DELETE used to free a
    // session, so `max_sessions` unclaimed `initialize`s locked every later
    // client out permanently (W2 re-audit 2026-09-02, `mcp-http` F2).
    s.max_idle_ns = 0;
    const fresh = try s.create();
    try testing.expect(s.exists(fresh.id));
    try testing.expectEqual(@as(usize, 3), s.map.count());
}

test "close() actually ends the session it marks" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [8192]u8 = undefined;
    const created = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    const sid_h = headerValue(created, "Mcp-Session-Id").?;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_h.len], sid_h);
    const sid = sidbuf[0..sid_h.len];

    try testing.expect(try sessions.push(sid, "a"));
    sessions.close(sid);

    // ⚠ Driven THROUGH THE WIRE on purpose. `closing` was written and never
    // read — `handleGet` discarded `drainAfter`'s bool — so the public `close`
    // was inert (F3). A test that asserts `drainAfter` returns the flag passes
    // either way: it pins the flag, not the wiring. Only the second GET can
    // tell whether anything acted on it.
    var out2: [8192]u8 = undefined;
    const drained = runWire(&r, getWithSession(&rbuf, sid, null), &out2);
    try testing.expect(std.mem.startsWith(u8, drained, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, drained, "data: a") != null);

    var out3: [8192]u8 = undefined;
    const after = runWire(&r, getWithSession(&rbuf, sid, null), &out3);
    try testing.expect(std.mem.startsWith(u8, after, "HTTP/1.1 404"));
    try testing.expect(!sessions.exists(sid));
}

// ── spec 2026-07-28: the stateless transport (see modern.zig) ───────────────

test {
    _ = modern;
    _ = sidhex;
    _ = @import("sdk_oracle.zig");
}

/// A POST with arbitrary extra header lines (each ending `\r\n`).
fn postHeaders(comptime headers: []const u8, comptime json: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n{s}Content-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ headers, json.len, json },
    );
}

const modern_meta =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"ExampleClient","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}}
;
const modern_call_headers = "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: echo\r\n";
const modern_call_body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"x\":1}," ++ modern_meta ++ "}}";

test "2026-07-28: a modern tools/call is served statelessly — even with sessions configured, no session needed or minted" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    // A stale session id rides along: ignored, not 404.
    const got = runWire(&r, postHeaders(modern_call_headers ++ "Mcp-Session-Id: stale\r\n", modern_call_body), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expectEqualStrings("application/json", headerValue(got, "content-type").?);
    try testing.expect(headerValue(got, "mcp-session-id") == null);
    try testing.expect(std.mem.find(u8, bodyOf(got), "\"resultType\":\"complete\"") != null);
    try testing.expect(std.mem.find(u8, bodyOf(got), "\"id\":1") != null);
    // Nothing was recorded against any peer.
    try testing.expectEqual(@as(usize, 0), server.peers.items.len);
}

test "2026-07-28: header problems are 400 HeaderMismatch before the server runs" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    const cases = [_][]const u8{
        postHeaders("", modern_call_body), // no headers at all
        postHeaders("MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\n", modern_call_body), // no Mcp-Name
        postHeaders("MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: other\r\n", modern_call_body),
        postHeaders(modern_call_headers ++ "Mcp-Name: echo\r\n", modern_call_body), // duplicated
        // A modern header on a session-era body.
        postHeaders("MCP-Protocol-Version: 2026-07-28\r\n", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"),
    };
    for (cases) |req| {
        var buf: [8192]u8 = undefined;
        const got = runWire(&r, req, &buf);
        try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 400"));
        try testing.expectEqualStrings("application/json", headerValue(got, "content-type").?);
        try testing.expect(std.mem.find(u8, bodyOf(got), "\"code\":-32020") != null);
    }
}

test "2026-07-28: an unsupported revision is 400, an unknown method 404, an ordinary JSON-RPC error 200" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    const future = runWire(&r, postHeaders("MCP-Protocol-Version: 2099-01-01\r\nMcp-Method: tools/list\r\n",
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, future, "HTTP/1.1 400"));
    try testing.expect(std.mem.find(u8, bodyOf(future), "\"code\":-32022") != null);

    // `ping` was removed in 2026-07-28: -32601, and the transport says 404 —
    // also when the client accepts SSE (a lone response is never a stream).
    var buf2: [8192]u8 = undefined;
    const ping = runWire(&r, postHeaders("Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: ping\r\n", "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\",\"params\":{" ++ modern_meta ++ "}}"), &buf2);
    try testing.expect(std.mem.startsWith(u8, ping, "HTTP/1.1 404"));
    try testing.expectEqualStrings("application/json", headerValue(ping, "content-type").?);
    try testing.expect(std.mem.find(u8, bodyOf(ping), "\"code\":-32601") != null);

    var buf3: [8192]u8 = undefined;
    const unknown_tool = runWire(&r, postHeaders("MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: nope\r\n", "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"nope\"," ++ modern_meta ++ "}}"), &buf3);
    try testing.expect(std.mem.startsWith(u8, unknown_tool, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, bodyOf(unknown_tool), "\"code\":-32602") != null);
}

test "2026-07-28 SSE: progress streams live then the result; a lone result stays application/json" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    const got = runWire(&r, postHeaders("Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: work\r\n", "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"work\",\"arguments\":{},\"_meta\":{\"progressToken\":\"p1\",\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}"), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expectEqualStrings("text/event-stream", headerValue(got, "content-type").?);
    try testing.expectEqualStrings("no", headerValue(got, "x-accel-buffering").?);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "notifications/progress"));
    try testing.expect(std.mem.find(u8, got, "data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"resultType\":\"complete\"") != null);

    var buf2: [8192]u8 = undefined;
    const lone = runWire(&r, postHeaders("Accept: application/json, text/event-stream\r\n" ++ modern_call_headers, modern_call_body), &buf2);
    try testing.expect(std.mem.startsWith(u8, lone, "HTTP/1.1 200"));
    try testing.expectEqualStrings("application/json", headerValue(lone, "content-type").?);
    try testing.expect(std.mem.startsWith(u8, bodyOf(lone), "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\""));
}

test "2026-07-28 SSE: subscriptions/listen is the acknowledgment then the graceful close, as one stream" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    const got = runWire(&r, postHeaders("Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: subscriptions/listen\r\n", "{\"jsonrpc\":\"2.0\",\"id\":\"listen-1\",\"method\":\"subscriptions/listen\",\"params\":{" ++ modern_meta ++ ",\"notifications\":{\"toolsListChanged\":true}}}"), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expectEqualStrings("text/event-stream", headerValue(got, "content-type").?);
    const ack = std.mem.find(u8, got, "notifications/subscriptions/acknowledged").?;
    const done = std.mem.find(u8, got, "\"id\":\"listen-1\",\"result\"").?;
    try testing.expect(ack < done);
}

fn askingTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    if (call.input.elicitation("branch")) |r| {
        call.print("deploying {s}", .{r.content.?.object.get("branch").?.string});
        return false;
    }
    call.input.ask("branch", .{ .elicitation = .{ .form = .{
        .message = "Which branch?",
        .requested_schema = "{\"type\":\"object\",\"properties\":{\"branch\":{\"type\":\"string\"}}}",
    } } }) catch return call.fail("cannot ask");
    return false;
}

test "2026-07-28: a multi round-trip tool over HTTP — InputRequiredResult, then the retry completes" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{ .name = "deploy", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = askingTool });
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    const hdrs = "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: deploy\r\n";
    const meta_elicit =
        \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}
    ;
    var buf: [8192]u8 = undefined;
    const first = runWire(&r, postHeaders(hdrs, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"deploy\"," ++ meta_elicit ++ "}}"), &buf);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, bodyOf(first), "\"resultType\":\"input_required\"") != null);
    try testing.expect(std.mem.find(u8, bodyOf(first), "\"branch\":{\"method\":\"elicitation/create\"") != null);

    var buf2: [8192]u8 = undefined;
    const second = runWire(&r, postHeaders(hdrs, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"deploy\"," ++ meta_elicit ++
        ",\"inputResponses\":{\"branch\":{\"action\":\"accept\",\"content\":{\"branch\":\"main\"}}}}}"), &buf2);
    try testing.expect(std.mem.find(u8, bodyOf(second), "deploying main") != null);
    try testing.expect(std.mem.find(u8, bodyOf(second), "\"resultType\":\"complete\"") != null);
}

test "2026-07-28: Mcp-Param headers are checked against the tool's x-mcp-header schema over HTTP" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{
        .name = "execute_sql",
        .description = "Execute SQL on Google Cloud Spanner",
        .input_schema =
        \\{"type":"object","properties":{"region":{"type":"string","description":"The region to execute the query in","x-mcp-header":"Region"},"query":{"type":"string","description":"The SQL query to execute"}},"required":["region","query"]}
        ,
        .handler = echoTool,
    });
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    // streamable-http.mdx "Resulting HTTP request", body compacted.
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{" ++ modern_meta ++ ",\"name\":\"execute_sql\",\"arguments\":{\"region\":\"us-west1\",\"query\":\"SELECT * FROM users\"}}}";
    const base = "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: execute_sql\r\n";
    var buf: [8192]u8 = undefined;
    const ok = runWire(&r, postHeaders(base ++ "Mcp-Param-Region: us-west1\r\n", body), &buf);
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200"));
    var buf2: [8192]u8 = undefined;
    const missing = runWire(&r, postHeaders(base, body), &buf2);
    try testing.expect(std.mem.startsWith(u8, missing, "HTTP/1.1 400"));
    try testing.expect(std.mem.find(u8, bodyOf(missing), "Mcp-Param-Region") != null);
}

test "the session era is untouched: an initialize-era POST under a session-revision header keeps its old reply" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var buf: [8192]u8 = undefined;
    const got = runWire(&r, postHeaders("MCP-Protocol-Version: 2025-11-25\r\n", list_body), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, bodyOf(got), "resultType") == null);
    try testing.expect(std.mem.find(u8, bodyOf(got), "\"name\":\"echo\"") != null);
}

// ── deterministic fuzz driver (MCP_HTTP_FUZZ, added 2026-10-10) ─────────────

const fz = @import("fuzz_test.zig");
const testkit = @import("testkit");

const PreMark = fz.Marker(enum { initialize, not_initialize, correlatable, not_correlatable, damaged });

pub fn fuzzPreParse(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [1 + jsonrpc_buf_len]u8 = undefined;
    var n: usize = 0;
    var damaged = false;
    if (S == fz.fuzz_driver.Rng and src.value(bool)) {
        // A corpus entry (frames carry a little-endian u32 length header) with
        // 0-3 octets damaged and maybe truncated.
        const entry = jsonrpc_corpus[src.index(jsonrpc_corpus.len)];
        const flen = std.mem.readInt(u32, entry[0..4], .little);
        const frame = entry[4..][0..@min(flen, entry.len - 4)];
        n = fz.damage(src, &raw, frame);
        damaged = true;
    } else n = src.slice(&raw);
    var buf: [jsonrpc_buf_len]u8 = undefined;
    const body = buildJsonRpcish(raw[0..n], &buf);
    if (damaged) PreMark.mark(.damaged);
    if (isInitialize(gpa, body)) PreMark.mark(.initialize) else PreMark.mark(.not_initialize);
    if (correlatableResponse(gpa, body)) PreMark.mark(.correlatable) else PreMark.mark(.not_correlatable);
}

fn fuzzPreParseSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzPreParse(std.testing.Smith, smith, std.testing.allocator);
}

test "fuzz: the pre-parse scanners, driver harness" {
    try std.testing.fuzz({}, fuzzPreParseSmith, .{});
}

test "fuzz driver: MCP_HTTP_FUZZ (pre-parse)" {
    try fz.fuzz_driver.run(fuzzPreParse, .{ .prefix = "MCP_HTTP_FUZZ", .name = "mcp-http-pre-parse" });
}

test "fuzz harness: pre-parse, 500 seeds, reaches every outcome" {
    try PreMark.reach(fuzzPreParse, "mcp-http-pre-parse", 500);
}

// ── fuzz: topLevelId against std.json ───────────────────────────────────────
//
// `topLevelId` decides which request id a client's disconnect cancels. The
// oracle is the authoritative parse (`std.json.Value`): on every body it
// accepts, the scanner must find the same id (a string or an integer; anything
// else is null) — the scanner's documented limits aside (a top-level key past
// 64 bytes, an id past 256).

const IdMark = fz.Marker(enum { int_id, string_id, no_id, duplicate_id, nested_decoy, escaped_key, limit, malformed, damaged });

/// What the generator put in the body that the scanner is allowed to refuse.
const IdGen = struct {
    limit: bool = false,
    ids: u32 = 0,
    decoy: bool = false,
    escaped: bool = false,
};

fn genIdBody(seed: []const u8, buf: []u8, info: *IdGen) []const u8 {
    if (seed.len == 0) return buf[0..0];
    if (seed[0] == 0) {
        const n = @min(seed.len - 1, buf.len);
        @memcpy(buf[0..n], seed[1..][0..n]);
        info.limit = n > 256; // a verbatim body may hold a token past the limits
        return buf[0..n];
    }
    var script: fuzzseed.Cursor = .{ .bytes = seed[1..] };
    var w: std.Io.Writer = .fixed(buf);
    w.writeByte('{') catch return w.buffered();
    const members = script.ranged(0, 5);
    var k: u32 = 0;
    while (k < members) : (k += 1) {
        if (k != 0) w.writeByte(',') catch break;
        const key_kind = script.ranged(0, 7);
        var is_id = false;
        switch (key_kind) {
            0, 1, 2 => {
                w.writeAll("\"id\":") catch break;
                is_id = true;
            },
            3 => {
                w.writeAll("\"\\u0069d\":") catch break;
                is_id = true;
                info.escaped = true;
            },
            4 => w.writeAll("\"params\":") catch break,
            5 => w.writeAll("\"method\":") catch break,
            6 => w.writeAll("\"i\":") catch break,
            else => {
                // A top-level key past the scanner's 64-byte limit.
                w.writeByte('"') catch break;
                for (0..70) |_| w.writeByte('k') catch break;
                w.writeAll("\":") catch break;
                info.limit = true;
            },
        }
        if (is_id) info.ids += 1;
        switch (script.ranged(0, 11)) {
            0 => w.print("{d}", .{@as(i16, @bitCast(script.word()))}) catch break,
            1 => w.print("{d}", .{@as(i64, @bitCast((@as(u64, script.word()) << 48) | (@as(u64, script.word()) << 32) | (@as(u64, script.word()) << 16) | script.word()))}) catch break,
            2 => w.writeAll("123456789012345678901234567890") catch break, // past i64
            3 => w.writeAll("1.5") catch break,
            4 => w.writeAll("1e2") catch break,
            5 => w.writeAll("\"abc\"") catch break,
            6 => w.writeAll("\"a\\u0041\\n\\\"\\\\\"") catch break,
            7 => {
                w.writeByte('"') catch break;
                for (0..300) |_| w.writeByte('z') catch break;
                w.writeByte('"') catch break;
                if (is_id) info.limit = true;
            },
            8 => w.writeAll(switch (script.ranged(0, 2)) {
                0 => "null",
                1 => "true",
                else => "false",
            }) catch break,
            9 => {
                w.writeAll("{\"id\":9,\"a\":[{\"id\":\"z\"},1],\"b\":{\"id\":null}}") catch break;
                info.decoy = true;
            },
            10 => w.writeAll("[1,{\"id\":3},[]]") catch break,
            else => w.writeAll("{}") catch break,
        }
    }
    w.writeByte('}') catch {};
    return w.buffered();
}

fn sameId(a: std.json.Value, b: std.json.Value) bool {
    return switch (a) {
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        .integer => |x| b == .integer and x == b.integer,
        else => false,
    };
}

pub fn fuzzTopLevelId(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [1 + 1024]u8 = undefined;
    var n: usize = 0;
    var damaged = false;
    if (S == fz.fuzz_driver.Rng and src.value(bool)) {
        const entry = id_corpus[src.index(id_corpus.len)];
        const flen = std.mem.readInt(u32, entry[0..4], .little);
        n = fz.damage(src, &raw, entry[4..][0..@min(flen, entry.len - 4)]);
        damaged = true;
    } else n = src.slice(&raw);
    var buf: [2048]u8 = undefined;
    var info: IdGen = .{};
    const body = genIdBody(raw[0..n], &buf, &info);
    if (damaged) IdMark.mark(.damaged);
    if (info.decoy) IdMark.mark(.nested_decoy);
    if (info.escaped) IdMark.mark(.escaped_key);
    if (info.limit) IdMark.mark(.limit);
    if (info.ids > 1) IdMark.mark(.duplicate_id);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const got = topLevelId(arena_state.allocator(), body);

    const parsed = std.json.parseFromSlice(std.json.Value, gpa, body, .{}) catch {
        IdMark.mark(.malformed); // nothing is promised on a body the parse refuses
        return;
    };
    defer parsed.deinit();
    const want: ?std.json.Value = switch (parsed.value) {
        .object => |o| if (o.get("id")) |v| switch (v) {
            .string, .integer => v,
            else => null,
        } else null,
        else => null,
    };
    if (want) |w| {
        if (w == .string) IdMark.mark(.string_id) else IdMark.mark(.int_id);
    } else IdMark.mark(.no_id);

    if (got) |g| {
        if (want == null or !sameId(g, want.?)) {
            std.debug.print("topLevelId: got {any}, the parse says {any}, body {s}\n", .{ g, want, body });
            return error.IdDisagrees;
        }
    } else if (want != null and !info.limit) {
        std.debug.print("topLevelId: found nothing, the parse says {any}, body {s}\n", .{ want, body });
        return error.IdMissed;
    }
}

const id_corpus = [_][]const u8{
    fuzzseed.seed("\x00" ++ "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\"}"),
    fuzzseed.seed("\x00" ++ "{\"id\":\"x\",\"params\":{\"id\":1}}"),
    fuzzseed.seed("\x00" ++ "{\"id\":1,\"id\":2}"), // the key twice: the parse keeps the last
    fuzzseed.seed("\x00" ++ "{\"i\\u0064\":5}"),
    fuzzseed.seed("\x00" ++ "{\"id\":null,\"id\":3}"),
    fuzzseed.seed("\x00" ++ "{\"id\":4,\"id\":null}"),
    fuzzseed.seed("\x01" ++ "\x03\x00\x01\x00\x00\x02\x00"),
    fuzzseed.seed("\x01" ++ "\x04\x00\x05\x00\x00\x00\x07\x09\x00\x01\x00"),
};

fn fuzzTopLevelIdSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzTopLevelId(std.testing.Smith, smith, std.testing.allocator);
}

test "fuzz: topLevelId against std.json, driver harness" {
    try std.testing.fuzz({}, fuzzTopLevelIdSmith, .{ .corpus = &id_corpus });
}

test "fuzz driver: MCP_HTTP_FUZZ (top-level id)" {
    try fz.fuzz_driver.run(fuzzTopLevelId, .{ .prefix = "MCP_HTTP_FUZZ", .name = "mcp-http-top-level-id" });
}

test "fuzz harness: top-level id, 500 seeds, reaches every outcome" {
    try IdMark.reach(fuzzTopLevelId, "mcp-http-top-level-id", 500);
}

const WireMark = fz.Marker(enum {
    list_ok,
    call_ok,
    notification_accepted,
    get_stream,
    delete_then_gone,
    origin_refused,
    forged_session_refused,
    damaged_request_answered,
    damaged_request_dropped,
    garbage,
});

fn statusOf(got: []const u8) ?u16 {
    if (got.len < 12 or !std.mem.startsWith(u8, got, "HTTP/1.1 ")) return null;
    return std.fmt.parseInt(u16, got[9..12], 10) catch null;
}

const call_body = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"hi\"}}}";
const note_body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";

pub fn fuzzWire(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    const origins = [_][]const u8{"https://ok.example"};
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions, .allowed_origins = &origins };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var out: [8192]u8 = undefined;
    var rbuf: [1536]u8 = undefined;
    // Two live sessions.
    var sids: [2][32]u8 = undefined;
    for (&sids) |*sid| {
        const init = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
        const hdr = headerValue(init, "Mcp-Session-Id") orelse return error.NoSession;
        if (hdr.len != 32) return error.UnexpectedSessionIdLength;
        @memcpy(sid, hdr);
    }
    if (!(try sessions.push(&sids[0], "{\"n\":1}"))) return error.PushFailed;

    const Kind = enum { list, call, note, get, delete, origin, forged, damaged, garbage };
    var kind: Kind = .garbage;
    if (S == fz.fuzz_driver.Rng) {
        kind = @fromBackingInt(@intCast(src.index(9)));
    }
    var req_buf: [2048]u8 = undefined;
    const sid_a: []const u8 = &sids[0];
    const sid_b: []const u8 = &sids[1];
    switch (kind) {
        .list => {
            const got = runWire(&r, postWithSession(&req_buf, sid_a, list_body), &out);
            if (statusOf(got) != 200 or std.mem.find(u8, bodyOf(got), "echo") == null) return error.ListFailed;
            WireMark.mark(.list_ok);
        },
        .call => {
            const got = runWire(&r, postWithSession(&req_buf, sid_b, call_body), &out);
            if (statusOf(got) != 200 or std.mem.find(u8, got, "\"ok\":true") == null) return error.CallFailed;
            WireMark.mark(.call_ok);
        },
        .note => {
            const got = runWire(&r, postWithSession(&req_buf, sid_a, note_body), &out);
            if (statusOf(got) != 202) return error.NotificationNotAccepted;
            WireMark.mark(.notification_accepted);
        },
        .get => {
            const got = runWire(&r, getWithSession(&req_buf, sid_a, null), &out);
            if (statusOf(got) != 200 or std.mem.find(u8, got, "data: {\"n\":1}") == null) return error.StreamFailed;
            // The other session does not see session A's event.
            const other = runWire(&r, getWithSession(&req_buf, sid_b, null), &out);
            if (std.mem.find(u8, other, "{\"n\":1}") != null) return error.EventLeakedAcrossSessions;
            WireMark.mark(.get_stream);
        },
        .delete => {
            const got = runWire(&r, deleteWithSession(&req_buf, sid_b), &out);
            if (statusOf(got) != 204) return error.DeleteFailed;
            const gone = runWire(&r, postWithSession(&req_buf, sid_b, list_body), &out);
            if (statusOf(gone) != 404) return error.DeletedSessionStillLive;
            const alive = runWire(&r, postWithSession(&req_buf, sid_a, list_body), &out);
            if (statusOf(alive) != 200) return error.DeleteTookTheOtherSession;
            WireMark.mark(.delete_then_gone);
        },
        .origin => {
            const bad = [_][]const u8{ "https://evil.example", "https://ok.example.evil", "null", "" };
            const o = bad[src.index(bad.len)];
            const got = runWire(&r, std.mem.print(&req_buf, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {s}\r\nMcp-Session-Id: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ o, sid_a, list_body.len, list_body }) catch unreachable, &out);
            if (statusOf(got) != 403) return error.ForeignOriginAccepted;
            WireMark.mark(.origin_refused);
        },
        .forged => {
            // A session id that is neither: one octet of a live id changed.
            var forged: [32]u8 = sids[src.index(2)];
            const at = src.index(forged.len);
            const old = forged[at];
            forged[at] = "0123456789abcdefABCDEFxyz-_ "[src.index(28)];
            if (forged[at] == old) forged[at] = if (old == 'z') 'y' else 'z';
            const verb = src.index(3);
            const got = switch (verb) {
                0 => runWire(&r, postWithSession(&req_buf, &forged, list_body), &out),
                1 => runWire(&r, getWithSession(&req_buf, &forged, null), &out),
                else => runWire(&r, deleteWithSession(&req_buf, &forged), &out),
            };
            if (statusOf(got) != 404) {
                std.debug.print("mcp-http-wire: a session id differing from a live one in one octet got status {?d}\n", .{statusOf(got)});
                return error.ForgedSessionAccepted;
            }
            // ...and both real sessions are still there.
            for (sids) |s| {
                const alive = runWire(&r, postWithSession(&req_buf, &s, list_body), &out);
                if (statusOf(alive) != 200) return error.RealSessionLost;
            }
            WireMark.mark(.forged_session_refused);
        },
        .damaged => {
            var genuine_buf: [1536]u8 = undefined;
            const base = switch (src.index(5)) {
                0 => postWithSession(&genuine_buf, sid_a, list_body),
                1 => postWithSession(&genuine_buf, sid_b, call_body),
                2 => postWithSession(&genuine_buf, "", init_body),
                3 => getWithSession(&genuine_buf, sid_a, "1"),
                else => deleteWithSession(&genuine_buf, sid_b),
            };
            const n = fz.damage(src, &req_buf, base);
            const got = runWire(&r, req_buf[0..n], &out);
            if (got.len == 0) {
                WireMark.mark(.damaged_request_dropped);
            } else {
                // Whatever it answered, it is an HTTP response.
                if (statusOf(got) == null) return error.NotAnHttpResponse;
                WireMark.mark(.damaged_request_answered);
            }
        },
        .garbage => {
            const n = src.slice(&req_buf);
            const got = runWire(&r, req_buf[0..n], &out);
            if (got.len != 0 and statusOf(got) == null) return error.NotAnHttpResponse;
            WireMark.mark(.garbage);
        },
    }
}

fn fuzzWireSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzWire(testkit.fuzz.ScriptSource, &src, std.testing.allocator);
}

test "fuzz: HTTP requests, damaged, against two live sessions" {
    try std.testing.fuzz({}, fuzzWireSmith, .{});
}

test "fuzz driver: MCP_HTTP_FUZZ (wire)" {
    try fz.fuzz_driver.run(fuzzWire, .{ .prefix = "MCP_HTTP_FUZZ", .name = "mcp-http-wire", .scale = 2 });
}

test "fuzz harness: wire, 400 seeds, reaches every outcome" {
    try WireMark.reach(fuzzWire, "mcp-http-wire", 400);
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

// ── boundaries and state left behind (whole-module mutation audit) ─────────

test "405 names the methods the endpoint takes, and a full session table is 429" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var plain = Transport{ .gpa = gpa, .server = &server };
    var r1 = router.Router.init(gpa);
    defer r1.deinit();
    try r1.use(plain.middleware());
    var buf: [2048]u8 = undefined;
    const put = runWire(&r1, "PUT /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, put, "HTTP/1.1 405"));
    try testing.expectEqualStrings("POST", headerValue(put, "allow").?);

    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    sessions.max_sessions = 1;
    var with = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };
    var r2 = router.Router.init(gpa);
    defer r2.deinit();
    try r2.use(with.middleware());
    var buf2: [2048]u8 = undefined;
    const put2 = runWire(&r2, "PUT /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", &buf2);
    try testing.expectEqualStrings("POST, GET, DELETE", headerValue(put2, "allow").?);

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const first = runWire(&r2, postWithSession(&rbuf, "", init_body), &out);
    try testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 200"));
    var out2: [4096]u8 = undefined;
    const second = runWire(&r2, postWithSession(&rbuf, "", init_body), &out2);
    try testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 429"));
}

test "GET: an empty queue is a heartbeat that keeps the session; a closed one ends after it" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var rbuf: [1024]u8 = undefined;
    var out: [8192]u8 = undefined;
    const created = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    const sid_h = headerValue(created, "Mcp-Session-Id").?;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_h.len], sid_h);
    const sid = sidbuf[0..sid_h.len];

    for (0..2) |_| {
        var o: [8192]u8 = undefined;
        const beat = runWire(&r, getWithSession(&rbuf, sid, null), &o);
        try testing.expect(std.mem.startsWith(u8, beat, "HTTP/1.1 200"));
        try testing.expect(std.mem.find(u8, beat, "keep-alive") != null);
    }
    try testing.expect(sessions.map.contains(sid));
    sessions.close(sid);
    var o3: [8192]u8 = undefined;
    const last = runWire(&r, getWithSession(&rbuf, sid, null), &o3);
    try testing.expect(std.mem.startsWith(u8, last, "HTTP/1.1 200"));
    var o4: [8192]u8 = undefined;
    const gone = runWire(&r, getWithSession(&rbuf, sid, null), &o4);
    try testing.expect(std.mem.startsWith(u8, gone, "HTTP/1.1 404"));
}

test "eviction takes the session idle the longest, and naming a session refreshes it" {
    const gpa = testing.allocator;
    var s = Sessions.init(gpa);
    defer s.deinit();
    s.max_sessions = 30;
    var ids: [30][32]u8 = undefined;
    var tags: [30]u64 = undefined;
    for (&ids, &tags) |*id, *tag| {
        const c = try s.create();
        try testing.expectEqual(@as(usize, 32), c.id.len);
        @memcpy(id, c.id);
        tag.* = c.tag;
    }
    // the very oldest is named again, so the next one in line is the oldest now
    try testing.expectEqual(@as(?u64, tags[0]), s.tagOf(&ids[0]));
    s.max_idle_ns = 0;
    const fresh = try s.create();
    try testing.expectEqual(@as(?u64, tags[1]), fresh.evicted);
    try testing.expect(s.map.contains(&ids[0]));
    try testing.expect(!s.map.contains(&ids[1]));
    try testing.expectEqual(@as(usize, 30), s.map.count());
}

test "an evicted session takes its server-side handshake state with it" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    server.max_peers = 2;
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    sessions.max_sessions = 1;
    sessions.max_idle_ns = 0;
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var rbuf: [1024]u8 = undefined;
    for (0..3) |_| {
        var out: [4096]u8 = undefined;
        const res = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
        try testing.expect(std.mem.startsWith(u8, res, "HTTP/1.1 200"));
        try testing.expect(std.mem.find(u8, res, "\"error\"") == null);
        try testing.expectEqual(@as(usize, 1), server.peers.items.len);
    }
}

test "correlatableResponse: the last id wins, as the parser reads it" {
    const gpa = testing.allocator;
    try testing.expect(correlatableResponse(gpa, "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"id\":7,\"result\":{}}"));
}

test "2026-07-28: a notification is 202 with no body, whichever Accept it sends" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    const body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1," ++ modern_meta ++ "}}";
    const hdr = "MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: notifications/cancelled\r\n";
    var buf: [4096]u8 = undefined;
    const sse = runWire(&r, postHeaders("Accept: application/json, text/event-stream\r\n" ++ hdr, body), &buf);
    try testing.expect(std.mem.startsWith(u8, sse, "HTTP/1.1 202"));
    try testing.expectEqualStrings("", bodyOf(sse));
    var buf2: [4096]u8 = undefined;
    const json = runWire(&r, postHeaders("Accept: application/json\r\n" ++ hdr, body), &buf2);
    try testing.expect(std.mem.startsWith(u8, json, "HTTP/1.1 202"));
    try testing.expectEqualStrings("", bodyOf(json));
}

const q_filler: [6000]u8 = @splat('Q');

test "SSE: a response larger than the stream buffer arrives once, byte for byte" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var buf: [16384]u8 = undefined;
    const got = runWire(&r, postHeaders("Accept: text/event-stream\r\n", "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"" ++ &q_filler ++ "\"}}}"), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    // the tool result carries the text twice (`content` and `structuredContent`)
    try testing.expectEqual(@as(usize, 12000), std.mem.count(u8, got, "Q"));
}

test "a POST whose body ends before its Content-Length is a 400" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var buf: [2048]u8 = undefined;
    const got = runWire(&r, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 50\r\nConnection: close\r\n\r\n{\"a\"", &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 400"));
}

// ── held listens and cancellation over a real socket ───────────────────────

const SpinLock = struct {
    m: std.atomic.Mutex = .unlocked,
    fn lock(ctx: ?*anyopaque) void {
        const self: *SpinLock = @ptrCast(@alignCast(ctx.?));
        lockSpin(&self.m);
    }
    fn unlock(ctx: ?*anyopaque) void {
        const self: *SpinLock = @ptrCast(@alignCast(ctx.?));
        self.m.unlock();
    }
    fn iface(self: *SpinLock) Lock {
        return .{ .ctx = self, .lockFn = lock, .unlockFn = unlock };
    }
};

fn sleepMs(io: std.Io, ms: u32) void {
    const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake };
    d.sleep(io) catch {};
}

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

/// A real `http.Server` (threads) in front of a router with the transport.
const Live = struct {
    threaded: std.Io.Threaded,
    server: http.Server,
    thread: std.Thread,

    fn start(self: *Live, r: *router.Router) !bool {
        self.threaded = std.Io.Threaded.init(testing.allocator, .{});
        self.server = http.Server.init(self.threaded.io(), testing.allocator, .{ .handler = r.handler(), .context = r });
        self.server.bind() catch {
            self.server.deinit();
            self.threaded.deinit();
            return false;
        };
        self.thread = try std.Thread.spawn(.{}, serveWrap, .{&self.server});
        return true;
    }

    fn io(self: *Live) std.Io {
        return self.threaded.io();
    }

    fn connect(self: *Live) !std.Io.net.Stream {
        return self.server.boundAddress().connect(self.io(), .{ .mode = .stream });
    }

    fn stop(self: *Live) void {
        self.server.close();
        self.server.shutdown();
        self.thread.join();
        self.server.deinit();
        self.threaded.deinit();
    }
};

fn sendAll(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    var wbuf: [256]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    try sw.interface.writeAll(bytes);
    try sw.interface.flush();
}

fn readToEnd(io: std.Io, stream: std.Io.net.Stream, buf: []u8) []const u8 {
    var rbuf: [256]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var w: std.Io.Writer = .fixed(buf);
    _ = sr.interface.streamRemaining(&w) catch {};
    return w.buffered();
}

fn waitFor(io: std.Io, ctx: anytype, comptime ready: fn (@TypeOf(ctx)) bool) !void {
    var waited: u32 = 0;
    while (!ready(ctx)) : (waited += 2) {
        if (waited > 5000) return error.ConditionNeverHeld;
        sleepMs(io, 2);
    }
}

fn oneListen(l: *Listens) bool {
    return l.count() == 1;
}

fn noListen(l: *Listens) bool {
    return l.count() == 0;
}

const listen_wire = postHeaders("Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: subscriptions/listen\r\n", "{\"jsonrpc\":\"2.0\",\"id\":\"listen-1\",\"method\":\"subscriptions/listen\",\"params\":{" ++ modern_meta ++ ",\"notifications\":{\"toolsListChanged\":true,\"resourceSubscriptions\":[\"file:///a\"]}}}");

test "held listen: notifications pushed from another thread stream live, finishAll ends with the graceful close" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    server.push = true;
    var listens = Listens.init(gpa);
    defer listens.deinit();
    var spin: SpinLock = .{};
    var transport = Transport{ .gpa = gpa, .server = &server, .listens = &listens, .lock = spin.iface() };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var live: Live = undefined;
    if (!try live.start(&r)) return error.SkipZigTest;
    defer live.stop();
    const io = live.io();

    const stream = try live.connect();
    defer stream.close(io);
    try sendAll(io, stream, listen_wire);
    try waitFor(io, &listens, oneListen);

    transport.lock.acquire();
    const n1 = server.notifyListChanged(transport.pushSink(), .tools);
    const n2 = server.notifyListChanged(transport.pushSink(), .prompts); // not asked for
    const n3 = server.notifyResourceUpdated(transport.pushSink(), "file:///a");
    transport.lock.release();
    try testing.expectEqual(@as(usize, 1), n1);
    try testing.expectEqual(@as(usize, 0), n2);
    try testing.expectEqual(@as(usize, 1), n3);
    listens.finishAll();

    var buf: [8192]u8 = undefined;
    const got = readToEnd(io, stream, &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const ack = std.mem.find(u8, got, "notifications/subscriptions/acknowledged").?;
    const tools = std.mem.find(u8, got, "notifications/tools/list_changed").?;
    const res = std.mem.find(u8, got, "notifications/resources/updated").?;
    const done = std.mem.find(u8, got, "\"id\":\"listen-1\",\"result\"").?;
    try testing.expect(ack < tools and tools < res and res < done);
    try testing.expect(std.mem.find(u8, got, "/subscriptionId\":\"listen-1\"") != null);
    try testing.expect(std.mem.endsWith(u8, got, "0\r\n\r\n"));
    try waitFor(io, &listens, noListen);
    // The listen's peer is forgotten: nothing is left to notify.
    transport.lock.acquire();
    const after = server.notifyListChanged(transport.pushSink(), .tools);
    transport.lock.release();
    try testing.expectEqual(@as(usize, 0), after);
}

fn twoListens(l: *Listens) bool {
    return l.count() == 2;
}

test "held listen: two listens on one server each get only what they asked for" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    server.push = true;
    var listens = Listens.init(gpa);
    defer listens.deinit();
    var spin: SpinLock = .{};
    var transport = Transport{ .gpa = gpa, .server = &server, .listens = &listens, .lock = spin.iface() };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var live: Live = undefined;
    if (!try live.start(&r)) return error.SkipZigTest;
    defer live.stop();
    const io = live.io();

    const wire_b = postHeaders("Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: subscriptions/listen\r\n", "{\"jsonrpc\":\"2.0\",\"id\":\"listen-2\",\"method\":\"subscriptions/listen\",\"params\":{" ++ modern_meta ++ ",\"notifications\":{\"resourceSubscriptions\":[\"file:///b\"]}}}");
    const a = try live.connect();
    defer a.close(io);
    try sendAll(io, a, listen_wire);
    try waitFor(io, &listens, oneListen);
    const b = try live.connect();
    defer b.close(io);
    try sendAll(io, b, wire_b);
    try waitFor(io, &listens, twoListens);

    transport.lock.acquire();
    const n = server.notifyResourceUpdated(transport.pushSink(), "file:///b");
    transport.lock.release();
    try testing.expectEqual(@as(usize, 1), n);
    listens.finishAll();

    var abuf: [8192]u8 = undefined;
    const got_a = readToEnd(io, a, &abuf);
    var bbuf: [8192]u8 = undefined;
    const got_b = readToEnd(io, b, &bbuf);
    try testing.expect(std.mem.find(u8, got_a, "notifications/resources/updated") == null);
    try testing.expect(std.mem.find(u8, got_b, "notifications/resources/updated") != null);
    try testing.expect(std.mem.find(u8, got_b, "\"id\":\"listen-2\",\"result\"") != null);
    try testing.expect(std.mem.find(u8, got_a, "\"id\":\"listen-1\",\"result\"") != null);
    try waitFor(io, &listens, noListen);
}

test "held listen: the client closing ends it and drops the subscription" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    server.push = true;
    var listens = Listens.init(gpa);
    defer listens.deinit();
    var spin: SpinLock = .{};
    var transport = Transport{ .gpa = gpa, .server = &server, .listens = &listens, .lock = spin.iface() };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var live: Live = undefined;
    if (!try live.start(&r)) return error.SkipZigTest;
    defer live.stop();
    const io = live.io();

    const stream = try live.connect();
    try sendAll(io, stream, listen_wire);
    try waitFor(io, &listens, oneListen);
    stream.close(io);
    try waitFor(io, &listens, noListen);
    transport.lock.acquire();
    const n = server.notifyListChanged(transport.pushSink(), .tools);
    transport.lock.release();
    try testing.expectEqual(@as(usize, 0), n);
}

test "held listen: without Transport.listens the listen is acknowledged and closed, as before" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    server.push = true;
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var buf: [8192]u8 = undefined;
    const got = runWire(&r, listen_wire, &buf);
    try testing.expect(std.mem.find(u8, got, "notifications/subscriptions/acknowledged") != null);
    // `mcp` holds it open (push on) and nothing ends it here: no result.
    try testing.expect(std.mem.find(u8, got, "\"result\"") == null);
    try testing.expect(std.mem.endsWith(u8, got, "0\r\n\r\n"));
    server.forgetPeer(0);
}

var slow_started: std.atomic.Value(bool) = .init(false);
var slow_saw_cancel: std.atomic.Value(bool) = .init(false);

fn slowTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    slow_started.store(true, .release);
    var spins: u32 = 0;
    while (!call.cancelled() and spins < 5000) : (spins += 1) {
        // ~5 s at most; the cancellation ends it long before.
        var ts: std.os.linux.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    slow_saw_cancel.store(call.cancelled(), .release);
    call.write("{\"ok\":true}");
    return false;
}

fn slowStarted(_: void) bool {
    return slow_started.load(.acquire);
}

test "2026-07-28: closing the connection of a running tools/call cancels it (ToolCall.cancelled)" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{ .name = "slow", .description = "waits for cancellation", .input_schema = "{\"type\":\"object\"}", .handler = slowTool });
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var live: Live = undefined;
    if (!try live.start(&r)) return error.SkipZigTest;
    defer live.stop();
    const io = live.io();

    for ([_][]const u8{ "", "Accept: application/json, text/event-stream\r\n" }) |accept| {
        slow_started.store(false, .release);
        slow_saw_cancel.store(false, .release);
        var wire_buf: [1024]u8 = undefined;
        const body = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"slow\",\"arguments\":{}," ++ modern_meta ++ "}}";
        const wire = try std.mem.print(&wire_buf, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n{s}MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: slow\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ accept, body.len, body });
        const stream = try live.connect();
        try sendAll(io, stream, wire);
        try waitFor(io, {}, slowStarted);
        stream.close(io);
        var waited: u32 = 0;
        while (!slow_saw_cancel.load(.acquire) and waited < 4000) : (waited += 2) sleepMs(io, 2);
        try testing.expect(slow_saw_cancel.load(.acquire));
    }
}

test "2026-07-28: a client that left while its tools/call waited for the transport lock never runs the call" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{ .name = "slow", .description = "waits for cancellation", .input_schema = "{\"type\":\"object\"}", .handler = slowTool });
    var spin: SpinLock = .{};
    var transport = Transport{ .gpa = gpa, .server = &server, .lock = spin.iface() };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var live: Live = undefined;
    if (!try live.start(&r)) return error.SkipZigTest;
    defer live.stop();
    const io = live.io();

    for ([_][]const u8{ "", "Accept: application/json, text/event-stream\r\n" }) |accept| {
        slow_started.store(false, .release);
        slow_saw_cancel.store(false, .release);
        var wire_buf: [1024]u8 = undefined;
        const body = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"slow\",\"arguments\":{}," ++ modern_meta ++ "}}";
        const wire = try std.mem.print(&wire_buf, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n{s}MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: slow\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ accept, body.len, body });
        // Another call holds the transport: the request waits for the lock
        // with its watch already running, and the client leaves meanwhile.
        transport.lock.acquire();
        const stream = try live.connect();
        try sendAll(io, stream, wire);
        sleepMs(io, 150);
        stream.close(io);
        sleepMs(io, 150); // the watch fires; no call is in flight to cancel yet
        transport.lock.release();
        sleepMs(io, 400);
        try testing.expect(!slow_started.load(.acquire));
    }
}

test "2026-07-28: a chunked tools/call body is still watched (cancellation reaches the running call)" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{ .name = "slow", .description = "waits for cancellation", .input_schema = "{\"type\":\"object\"}", .handler = slowTool });
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var live: Live = undefined;
    if (!try live.start(&r)) return error.SkipZigTest;
    defer live.stop();
    const io = live.io();

    slow_started.store(false, .release);
    slow_saw_cancel.store(false, .release);
    var wire_buf: [1024]u8 = undefined;
    const body = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"slow\",\"arguments\":{}," ++ modern_meta ++ "}}";
    const wire = try std.mem.print(&wire_buf, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: slow\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n{s}\r\n0\r\n\r\n", .{ body.len, body });
    const stream = try live.connect();
    try sendAll(io, stream, wire);
    try waitFor(io, {}, slowStarted);
    stream.close(io);
    var waited: u32 = 0;
    while (!slow_saw_cancel.load(.acquire) and waited < 4000) : (waited += 2) sleepMs(io, 2);
    try testing.expect(slow_saw_cancel.load(.acquire));
}

test "topLevelId: string and integer ids, nothing else" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqual(@as(i64, 7), topLevelId(a, "{\"params\":{\"id\":1},\"id\":7}").?.integer);
    try testing.expectEqualStrings("x", topLevelId(a, "{\"id\":\"x\"}").?.string);
    try testing.expect(topLevelId(a, "{\"id\":1.5}") == null);
    try testing.expect(topLevelId(a, "{\"id\":null}") == null);
    try testing.expect(topLevelId(a, "{\"a\":}") == null);
    try testing.expect(topLevelId(a, "[1]") == null);
}

// ── the held session GET stream ─────────────────────────────────────────────

fn getWire(buf: []u8, sid: []const u8, last_event_id: ?u64) []const u8 {
    if (last_event_id) |n| return std.mem.print(buf, "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: {s}\r\nLast-Event-ID: {d}\r\n\r\n", .{ sid, n }) catch unreachable;
    return std.mem.print(buf, "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: {s}\r\n\r\n", .{sid}) catch unreachable;
}

const HeldGetRig = struct {
    server: mcp.Server,
    sessions: Sessions,
    spin: SpinLock = .{},
    transport: Transport = undefined,
    r: router.Router = undefined,
    live: Live = undefined,

    fn start(rig: *HeldGetRig, gpa: std.mem.Allocator, hold_get: bool) !bool {
        rig.server = try buildServer(gpa);
        rig.sessions = Sessions.init(gpa);
        rig.spin = .{};
        rig.transport = .{ .gpa = gpa, .server = &rig.server, .sessions = &rig.sessions, .lock = rig.spin.iface(), .hold_get = hold_get };
        rig.r = router.Router.init(gpa);
        try rig.r.use(rig.transport.middleware());
        if (!try rig.live.start(&rig.r)) {
            rig.deinit();
            return false;
        }
        return true;
    }

    fn stop(rig: *HeldGetRig) void {
        rig.live.stop();
        rig.deinit();
    }

    fn deinit(rig: *HeldGetRig) void {
        rig.r.deinit();
        rig.sessions.deinit();
        rig.server.deinit();
    }
};

const HeldProbe = struct { s: *Sessions, sid: []const u8, want: bool };

fn heldIs(p: HeldProbe) bool {
    return (p.s.heldNow(p.sid) orelse false) == p.want;
}

test "held GET: a message pushed to the session reaches the open stream, then Sessions.close ends it" {
    var rig: HeldGetRig = undefined;
    if (!try rig.start(testing.allocator, true)) return error.SkipZigTest;
    defer rig.stop();
    const io = rig.live.io();
    const created = try rig.sessions.create();
    var wbuf: [256]u8 = undefined;
    const stream = try rig.live.connect();
    defer stream.close(io);
    try sendAll(io, stream, getWire(&wbuf, created.id, null));
    try waitFor(io, HeldProbe{ .s = &rig.sessions, .sid = created.id, .want = true }, heldIs);
    // Still open well after the head (a drain-and-close would have ended).
    sleepMs(io, 150);
    try testing.expect(rig.sessions.heldNow(created.id).?);

    try testing.expect(try rig.sessions.push(created.id, "{\"n\":1}"));
    try testing.expect(try rig.sessions.pushTag(created.tag, "{\"n\":2}"));
    rig.sessions.close(created.id);

    var buf: [4096]u8 = undefined;
    const got = readToEnd(io, stream, &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.find(u8, got, "text/event-stream") != null);
    const one = std.mem.find(u8, got, "id: 1\ndata: {\"n\":1}\n\n").?;
    const two = std.mem.find(u8, got, "id: 2\ndata: {\"n\":2}\n\n").?;
    try testing.expect(one < two);
    try testing.expect(std.mem.endsWith(u8, got, "0\r\n\r\n"));
}

test "held GET: Last-Event-ID replays what is newer, then the stream goes live" {
    var rig: HeldGetRig = undefined;
    if (!try rig.start(testing.allocator, true)) return error.SkipZigTest;
    defer rig.stop();
    const io = rig.live.io();
    const created = try rig.sessions.create();
    for ([_][]const u8{ "{\"n\":1}", "{\"n\":2}", "{\"n\":3}" }) |m| _ = try rig.sessions.push(created.id, m);
    var wbuf: [256]u8 = undefined;
    const stream = try rig.live.connect();
    defer stream.close(io);
    try sendAll(io, stream, getWire(&wbuf, created.id, 1));
    try waitFor(io, HeldProbe{ .s = &rig.sessions, .sid = created.id, .want = true }, heldIs);
    _ = try rig.sessions.push(created.id, "{\"n\":4}");
    rig.sessions.close(created.id);
    var buf: [4096]u8 = undefined;
    const got = readToEnd(io, stream, &buf);
    try testing.expect(std.mem.find(u8, got, "{\"n\":1}") == null);
    const two = std.mem.find(u8, got, "id: 2\n").?;
    const three = std.mem.find(u8, got, "id: 3\n").?;
    const four = std.mem.find(u8, got, "id: 4\ndata: {\"n\":4}").?;
    try testing.expect(two < three and three < four);
}

test "held GET: a second GET on the session is 409; after the first one leaves a new one is held" {
    var rig: HeldGetRig = undefined;
    if (!try rig.start(testing.allocator, true)) return error.SkipZigTest;
    defer rig.stop();
    const io = rig.live.io();
    const created = try rig.sessions.create();
    var wbuf: [256]u8 = undefined;
    const first = try rig.live.connect();
    try sendAll(io, first, getWire(&wbuf, created.id, null));
    try waitFor(io, HeldProbe{ .s = &rig.sessions, .sid = created.id, .want = true }, heldIs);

    const second = try rig.live.connect();
    defer second.close(io);
    try sendAll(io, second, getWire(&wbuf, created.id, null));
    var buf: [2048]u8 = undefined;
    const got = readToEnd(io, second, &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 409"));
    try testing.expect(std.mem.find(u8, got, "Only one SSE stream is allowed per session") != null);

    first.close(io);
    try waitFor(io, HeldProbe{ .s = &rig.sessions, .sid = created.id, .want = false }, heldIs);
    const third = try rig.live.connect();
    defer third.close(io);
    try sendAll(io, third, getWire(&wbuf, created.id, null));
    try waitFor(io, HeldProbe{ .s = &rig.sessions, .sid = created.id, .want = true }, heldIs);
}

test "held GET: DELETE ends the open stream and the session is gone" {
    var rig: HeldGetRig = undefined;
    if (!try rig.start(testing.allocator, true)) return error.SkipZigTest;
    defer rig.stop();
    const io = rig.live.io();
    const created = try rig.sessions.create();
    var wbuf: [256]u8 = undefined;
    const stream = try rig.live.connect();
    defer stream.close(io);
    try sendAll(io, stream, getWire(&wbuf, created.id, null));
    try waitFor(io, HeldProbe{ .s = &rig.sessions, .sid = created.id, .want = true }, heldIs);

    const del = try rig.live.connect();
    defer del.close(io);
    const dwire = try std.mem.print(&wbuf, "DELETE /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: {s}\r\nConnection: close\r\n\r\n", .{created.id});
    try sendAll(io, del, dwire);
    var dbuf: [512]u8 = undefined;
    try testing.expect(std.mem.startsWith(u8, readToEnd(io, del, &dbuf), "HTTP/1.1 204"));

    var buf: [2048]u8 = undefined;
    const got = readToEnd(io, stream, &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.endsWith(u8, got, "0\r\n\r\n"));
    try testing.expect(rig.sessions.heldNow(created.id) == null);
}

test "held GET: hold_get = false drains and closes as before" {
    var rig: HeldGetRig = undefined;
    if (!try rig.start(testing.allocator, false)) return error.SkipZigTest;
    defer rig.stop();
    const io = rig.live.io();
    const created = try rig.sessions.create();
    _ = try rig.sessions.push(created.id, "{\"n\":1}");
    var wbuf: [256]u8 = undefined;
    const stream = try rig.live.connect();
    defer stream.close(io);
    try sendAll(io, stream, getWire(&wbuf, created.id, null));
    var buf: [2048]u8 = undefined;
    const got = readToEnd(io, stream, &buf); // returns: the response ended by itself
    try testing.expect(std.mem.find(u8, got, "id: 1\ndata: {\"n\":1}") != null);
    try testing.expect(rig.sessions.heldNow(created.id).? == false);
}

test "Sessions: replay_depth 0 keeps no buffer and does not index an empty list (sweep HS-3)" {
    var sessions = Sessions.init(testing.allocator);
    defer sessions.deinit();
    sessions.replay_depth = 0;
    const c = try sessions.create();
    try testing.expect(try sessions.push(c.id, "{\"n\":1}"));
    try testing.expect(try sessions.pushTag(c.tag, "{\"n\":2}"));
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var batch: std.ArrayList(Sessions.StoredEvent) = .empty;
    _ = (try sessions.drainAfter(c.id, 0, arena_state.allocator(), &batch)).?;
    try testing.expectEqual(@as(usize, 0), batch.items.len);
}

test "Sessions: the tag index follows create, destroy and eviction (sweep HS-5)" {
    var sessions = Sessions.init(testing.allocator);
    defer sessions.deinit();
    sessions.max_sessions = 2;
    sessions.max_idle_ns = 0; // anything may be evicted
    const a = try sessions.create();
    const b = try sessions.create();
    try testing.expect(sessions.hasTag(a.tag) and sessions.hasTag(b.tag));
    try testing.expect(try sessions.pushTag(b.tag, "x"));
    try testing.expect(!try sessions.pushTag(b.tag +% 1000, "x"));
    try testing.expectEqual(@as(?u64, b.tag), sessions.destroy(b.id));
    try testing.expect(!sessions.hasTag(b.tag));
    try testing.expect(!try sessions.pushTag(b.tag, "x"));
    const c = try sessions.create(); // table has room again
    const d = try sessions.create(); // full: the idlest (a) is evicted
    try testing.expectEqual(@as(?u64, a.tag), d.evicted);
    try testing.expect(!sessions.hasTag(a.tag));
    try testing.expect(sessions.hasTag(c.tag) and sessions.hasTag(d.tag));
}

// ── authorization (auth.zig) over the wire ──────────────────────────────────

const auth_scopes = [_][]const u8{ "mcp:read", "mcp:tools" };

fn authTestVerify(_: ?*anyopaque, _: std.mem.Allocator, token: []const u8) error{ OutOfMemory, VerifierFailed }!auth.Verdict {
    if (std.mem.eql(u8, token, "good")) return .{ .ok = .{ .client_id = "cli-9", .scopes = &auth_scopes, .expires_at = std.math.maxInt(i64), .resource = "https://mcp.example/mcp" } };
    if (std.mem.eql(u8, token, "readonly")) return .{ .ok = .{ .client_id = "ro", .scopes = auth_scopes[0..1], .expires_at = std.math.maxInt(i64), .resource = "https://mcp.example/mcp" } };
    if (std.mem.eql(u8, token, "boom")) return error.VerifierFailed;
    return .{ .invalid = "Unknown token" };
}

fn toolsNeedToolsScope(_: ?*anyopaque, op: auth.Operation) []const []const u8 {
    if (std.mem.eql(u8, op.method, "tools/call")) return auth_scopes[1..2];
    return &.{};
}

fn whoAmITool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.write(if (call.auth) |a| a.client_id else "anonymous");
    return false;
}

fn buildAuthServer(gpa: std.mem.Allocator) !mcp.Server {
    var server = try buildServer(gpa);
    errdefer server.deinit();
    try server.addTool(.{ .name = "whoami", .description = "who", .input_schema = "{\"type\":\"object\"}", .handler = whoAmITool });
    return server;
}

const auth_as = [_][]const u8{"https://auth.example"};
const test_mcp_auth: auth.Auth = .{
    .verify = authTestVerify,
    .resource_metadata_url = "https://mcp.example/.well-known/oauth-protected-resource/mcp",
    .metadata = .{ .resource = "https://mcp.example/mcp", .authorization_servers = &auth_as, .scopes_supported = &auth_scopes },
    .required_scopes = auth_scopes[0..1],
    .expected_resource = "https://mcp.example/mcp",
    .scope_for = toolsNeedToolsScope,
};

fn postAuth(comptime authz: []const u8, comptime json: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ authz, json.len, json },
    );
}

test "auth: RFC 9728 document, 401 challenges, 403 scopes, handlers see the token's AuthInfo" {
    const gpa = testing.allocator;
    var server = try buildAuthServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .auth = &test_mcp_auth };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    const meta_url = "resource_metadata=\"https://mcp.example/.well-known/oauth-protected-resource/mcp\"";

    // The metadata document: unauthenticated, path-aware, readable cross-origin.
    var b0: [4096]u8 = undefined;
    const md = runWire(&r, "GET /.well-known/oauth-protected-resource/mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", &b0);
    try testing.expectEqual(@as(?u16, 200), statusOf(md));
    try testing.expectEqualStrings("*", headerValue(md, "access-control-allow-origin").?);
    try testing.expectEqualStrings(
        \\{"resource":"https://mcp.example/mcp","authorization_servers":["https://auth.example"],"scopes_supported":["mcp:read","mcp:tools"],"bearer_methods_supported":["header"]}
    , bodyOf(md));
    var b0b: [4096]u8 = undefined;
    const md_post = runWire(&r, post("/.well-known/oauth-protected-resource/mcp", "{}"), &b0b);
    try testing.expectEqual(@as(?u16, 405), statusOf(md_post));

    // No token: 401, the challenge names the metadata and the scope, no error code.
    var b1: [4096]u8 = undefined;
    const none = runWire(&r, post("/mcp", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"), &b1);
    try testing.expectEqual(@as(?u16, 401), statusOf(none));
    const ch = headerValue(none, "www-authenticate").?;
    try testing.expect(std.mem.startsWith(u8, ch, "Bearer scope=\"mcp:read\", "));
    try testing.expect(std.mem.find(u8, ch, meta_url) != null);
    try testing.expect(std.mem.find(u8, ch, "error=") == null);

    // Unknown token: 401 invalid_token, with the verifier's reason.
    var b2: [4096]u8 = undefined;
    const bad = runWire(&r, postAuth("Bearer nope", "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"), &b2);
    try testing.expectEqual(@as(?u16, 401), statusOf(bad));
    try testing.expect(std.mem.find(u8, headerValue(bad, "www-authenticate").?, "error=\"invalid_token\", error_description=\"Unknown token\"") != null);
    try testing.expectEqualStrings("{\"error\":\"invalid_token\",\"error_description\":\"Unknown token\"}", bodyOf(bad));

    // A valid token: the list is served and the tool sees who called it.
    var b3: [4096]u8 = undefined;
    const ok = runWire(&r, postAuth("Bearer good", "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"whoami\",\"arguments\":{}}}"), &b3);
    try testing.expectEqual(@as(?u16, 200), statusOf(ok));
    try testing.expect(std.mem.find(u8, ok, "cli-9") != null);

    // Per-operation scope: a read-only token may list but not call.
    var b4: [4096]u8 = undefined;
    const ro_list = runWire(&r, postAuth("Bearer readonly", "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/list\"}"), &b4);
    try testing.expectEqual(@as(?u16, 200), statusOf(ro_list));
    var b5: [4096]u8 = undefined;
    const ro_call = runWire(&r, postAuth("Bearer readonly", "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"whoami\",\"arguments\":{}}}"), &b5);
    try testing.expectEqual(@as(?u16, 403), statusOf(ro_call));
    try testing.expect(std.mem.find(u8, headerValue(ro_call, "www-authenticate").?, "error=\"insufficient_scope\"") != null);
    try testing.expect(std.mem.find(u8, headerValue(ro_call, "www-authenticate").?, "scope=\"mcp:tools\"") != null);

    // A verifier that cannot decide is a 500, never an accepted request.
    var b6: [4096]u8 = undefined;
    const boom = runWire(&r, postAuth("Bearer boom", "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/list\"}"), &b6);
    try testing.expectEqual(@as(?u16, 500), statusOf(boom));

    // Two Authorization fields are refused.
    var b7: [4096]u8 = undefined;
    const two = runWire(&r, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer good\r\nAuthorization: Bearer good\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", &b7);
    try testing.expectEqual(@as(?u16, 401), statusOf(two));
}

test "auth: scope_for cannot be evaded with long keys or unreadable bodies (sweep HS-2)" {
    const gpa = testing.allocator;
    var server = try buildAuthServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .auth = &test_mcp_auth };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    const out = try gpa.alloc(u8, 32 * 1024);
    defer gpa.free(out);
    const long = try gpa.alloc(u8, 9 * 1024);
    defer gpa.free(long);
    @memset(long, 'k');

    const call = "\"method\":\"tools/call\",\"params\":{\"name\":\"whoami\",\"arguments\":{}}";
    const bodies = [_][]const u8{
        // 9 KiB key ahead of `method`: the old scan ended there with no operation.
        try std.fmt.allocPrint(gpa, "{{\"{s}\":1,\"jsonrpc\":\"2.0\",\"id\":5,{s}}}", .{ long, call }),
        // The same with the long key inside params.
        try std.fmt.allocPrint(gpa, "{{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{{\"{s}\":1,\"name\":\"whoami\",\"arguments\":{{}}}}}}", .{long}),
    };
    defer for (bodies) |b| gpa.free(b);
    for (bodies) |b| {
        const req = try std.fmt.allocPrint(gpa, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer readonly\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ b.len, b });
        defer gpa.free(req);
        const got = runWire(&r, req, out);
        try testing.expectEqual(@as(?u16, 403), statusOf(got));
        try testing.expect(std.mem.find(u8, got, ":\"ro\"") == null);
    }

    // A body that is not one JSON object is refused 400 before scope_for or mcp.
    const unreadable = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/list\"} trailing";
    const req = try std.fmt.allocPrint(gpa, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer readonly\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ unreadable.len, unreadable });
    defer gpa.free(req);
    const got = runWire(&r, req, out);
    try testing.expectEqual(@as(?u16, 400), statusOf(got));
    try testing.expectEqualStrings("{\"error\":\"invalid_request\",\"error_description\":\"Unreadable request body\"}", bodyOf(got));

    // A repeated `method` never runs the tool the scan did not see: the scan
    // reads the last one, and `mcp` refuses the repeat outright.
    const dup = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"method\":\"tools/list\",\"params\":{\"name\":\"whoami\",\"arguments\":{}}}";
    const req2 = try std.fmt.allocPrint(gpa, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer readonly\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ dup.len, dup });
    defer gpa.free(req2);
    const got2 = runWire(&r, req2, out);
    try testing.expect(std.mem.find(u8, got2, ":\"ro\"") == null);
    try testing.expect(std.mem.find(u8, got2, "-32700") != null); // mcp's parse refuses the repeated key
}

test "auth: GET and DELETE of a session endpoint are gated too" {
    const gpa = testing.allocator;
    var server = try buildAuthServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions, .auth = &test_mcp_auth };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var b1: [4096]u8 = undefined;
    try testing.expectEqual(@as(?u16, 401), statusOf(runWire(&r, "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: x\r\nConnection: close\r\n\r\n", &b1)));
    var b2: [4096]u8 = undefined;
    try testing.expectEqual(@as(?u16, 401), statusOf(runWire(&r, "DELETE /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nMcp-Session-Id: x\r\nConnection: close\r\n\r\n", &b2)));
    var b3: [4096]u8 = undefined;
    try testing.expectEqual(@as(?u16, 404), statusOf(runWire(&r, "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer good\r\nMcp-Session-Id: x\r\nConnection: close\r\n\r\n", &b3)));
}

test "host_guard: listed names (any case, any port), IP literals and localhost served, other names 403" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    const names = [_][]const u8{"mcp.example"};
    var transport = Transport{ .gpa = gpa, .server = &server, .host_guard = .{ .allowed = &names } };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
    const cases = [_]struct { []const u8, u16 }{
        .{ "Host: MCP.example:7717\r\n", 200 },
        .{ "Host: mcp.example\r\n", 200 },
        .{ "Host: 127.0.0.1:7717\r\n", 200 },
        .{ "Host: localhost:1\r\n", 200 },
        .{ "Host: evil.example:7717\r\n", 403 },
        .{ "Host: mcp.example.evil\r\n", 403 },
        .{ "", 400 }, // HTTP/1.1 without Host: http.Server's own 400 (RFC 9112 §3.2), before the guard
    };
    inline for (cases) |c| {
        var b: [4096]u8 = undefined;
        const got = runWire(&r, std.fmt.comptimePrint("POST /mcp HTTP/1.1\r\n{s}Content-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ c[0], body.len, body }), &b);
        try testing.expectEqual(@as(?u16, c[1]), statusOf(got));
    }
}

test "localhost_protection: a loopback peer with a foreign Host is 403, with a loopback Host served, and off when disabled" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var spin: SpinLock = .{};
    var transport = Transport{ .gpa = gpa, .server = &server, .lock = spin.iface() };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var live: Live = undefined;
    if (!try live.start(&r)) return error.SkipZigTest;
    defer live.stop();
    const io = live.io();
    const body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
    const cases = [_]struct { []const u8, bool, u16 }{
        .{ "rebound.evil.example:80", true, 403 },
        .{ "localhost:9", true, 200 },
        .{ "127.0.0.1:9", true, 200 },
        .{ "[::1]:9", true, 200 },
        .{ "rebound.evil.example:80", false, 200 },
    };
    for (cases) |c| {
        transport.localhost_protection = c[1];
        const stream = try live.connect();
        defer stream.close(io);
        var req_buf: [512]u8 = undefined;
        try sendAll(io, stream, try std.mem.print(&req_buf, "POST /mcp HTTP/1.1\r\nHost: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ c[0], body.len, body }));
        var buf: [4096]u8 = undefined;
        try testing.expectEqual(@as(?u16, c[2]), statusOf(readToEnd(io, stream, &buf)));
    }
}

fn ownAuthMiddleware(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    var info: mcp.AuthInfo = .{ .client_id = "from-my-gate" };
    const prev = try ctx.setTyped(mcp.AuthInfo, &info);
    defer _ = ctx.setTyped(mcp.AuthInfo, prev) catch {};
    return next.run(ctx);
}

test "auth: an AuthInfo a caller's own middleware stored is passed to the handlers" {
    const gpa = testing.allocator;
    var server = try buildAuthServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(.{ .run = ownAuthMiddleware });
    try r.use(transport.middleware());
    var b: [4096]u8 = undefined;
    const got = runWire(&r, post("/mcp", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"whoami\",\"arguments\":{}}}"), &b);
    try testing.expect(std.mem.find(u8, got, "from-my-gate") != null);
}

// ── fuzz: the bearer gate (auth.zig) ────────────────────────────────────────

const AuthMark = fz.Marker(enum { served, unauthenticated, invalid_token, insufficient_scope, unreadable });

const auth_fuzz_bodies = [_][]const u8{
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"whoami\",\"arguments\":{}}}",
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}",
    "{\"params\":{\"arguments\":{},\"name\":\"whoami\"},\"id\":3,\"method\":\"tools/call\",\"jsonrpc\":\"2.0\"}",
    "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"name\":\"x\"}}}",
};

const auth_fuzz_headers = [_][]const u8{
    "",
    "Authorization: Bearer good\r\n",
    "Authorization: Bearer readonly\r\n",
    "Authorization: Bearer nope\r\n",
    "Authorization: bearer   readonly  \r\n",
    "Authorization: Basic cmVhZG9ubHk6eA==\r\n",
    "Authorization: Bearer readonly\r\nAuthorization: Bearer good\r\n",
    "Authorization: Bearer\r\n",
};

/// Damaged bearer-gated requests: a token without `mcp:tools` must never run
/// `tools/call` (whoever sent it, however the body is spelled), and every
/// answer is one of the gate's statuses or the transport's own.
pub fn fuzzAuth(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var server = try buildAuthServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .auth = &test_mcp_auth };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var body_buf: [4096]u8 = undefined;
    const seed = auth_fuzz_bodies[src.index(auth_fuzz_bodies.len)];
    var body_len: usize = 0;
    // Sometimes a long key first (the HS-2 shape), sometimes damaged octets.
    if (src.value(bool)) {
        const pad = src.valueRangeAtMost(u16, 0, 3000);
        const head = "{\"";
        @memcpy(body_buf[0..head.len], head);
        @memset(body_buf[head.len..][0..pad], 'k');
        const tail = "\":0,";
        @memcpy(body_buf[head.len + pad ..][0..tail.len], tail);
        body_len = head.len + pad + tail.len;
        @memcpy(body_buf[body_len..][0 .. seed.len - 1], seed[1..]);
        body_len += seed.len - 1;
    } else body_len = fz.damage(src, &body_buf, seed);
    const body = body_buf[0..body_len];
    const hdr = auth_fuzz_headers[src.index(auth_fuzz_headers.len)];

    var req_buf: [8192]u8 = undefined;
    const req = std.mem.print(&req_buf, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n{s}Content-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ hdr, body.len, body }) catch unreachable; // 8 KiB > every part
    var out: [16 * 1024]u8 = undefined;
    const got = runWire(&r, req, &out);
    const status = statusOf(got) orelse return; // the wire codec dropped a damaged request
    // The read-only token never reaches a tool call: `whoami` writes the
    // caller's client id, "ro" for it.
    if (std.mem.find(u8, got, ":\"ro\"") != null) {
        std.debug.print("mcp-http-auth: a read-only token ran a tool: {s}\n", .{got});
        return error.ScopeBypassed;
    }
    switch (status) {
        200, 202 => AuthMark.mark(.served),
        401 => if (std.mem.find(u8, got, "error=\"invalid_token\"") != null) AuthMark.mark(.invalid_token) else AuthMark.mark(.unauthenticated),
        403 => AuthMark.mark(.insufficient_scope),
        400 => if (std.mem.find(u8, got, "Unreadable request body") != null) AuthMark.mark(.unreadable),
        404, 405, 413, 431 => {}, // the transport's and the codec's own answers to a damaged request
        else => {
            std.debug.print("mcp-http-auth: unexpected status {d}: {s}\n", .{ status, got });
            return error.UnexpectedStatus;
        },
    }
}

test "fuzz driver: MCP_HTTP_FUZZ (auth)" {
    try fz.fuzz_driver.run(fuzzAuth, .{ .prefix = "MCP_HTTP_FUZZ", .name = "mcp-http-auth" });
}

test "fuzz harness: auth, 400 seeds, reaches every outcome" {
    try AuthMark.reach(fuzzAuth, "mcp-http-auth", 400);
}

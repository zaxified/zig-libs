// SPDX-License-Identifier: MIT

//! Long-lived responses: a handler that learns its peer went away
//! (`PeerWatch`) and a response that stays open and is fed later from other
//! threads (`Hold`) — the shape an SSE push channel, a long poll or a
//! cancellable streamed answer needs.
//!
//! The model is Go `net/http`'s: the handler runs on its own task and simply
//! stays in it. Go streams with `http.Flusher` / `ResponseController.Flush`,
//! learns that the client left through `Request.Context().Done()` (cancelled
//! when the connection's background read, started once the body hit EOF,
//! sees EOF or an error, and on HTTP/2 when the stream is reset or the
//! connection ends) and runs a callback with `context.AfterFunc`. Here:
//!
//! - `PeerWatch.start(req, hook)` / `gone()` / `stop()` is
//!   `Context().Done()` + `AfterFunc`. On HTTP/1.1 over a socket a task on the
//!   server's `Io` waits in poll(2) for the socket's `POLLRDHUP`/`POLLHUP`/
//!   `POLLERR` — it consumes no byte, so a pipelined next request (or a TLS
//!   record) stays where the serving loop will read it, and only the peer
//!   closing (half-close included, as Go's EOF) counts as gone. On HTTP/2
//!   with `Options.h2_dispatcher` the connection task fires the hook when the
//!   stream is reset or the connection ends; no task is started.
//! - `Hold` is a held-open response: the handler commits the head
//!   (`begin`), then `run` writes whatever other threads `send` until the
//!   stream ends (`End`). The owner waits in poll(2) on an eventfd (and on
//!   HTTP/1.1 on the socket's hang-up), so a held response costs its own task
//!   and nothing else. `send` copies into a bounded queue the caller sized:
//!   Go's writer blocks on the socket, and hyper/axum's `Sse` stream is a
//!   bounded channel the producer awaits — a feeder on another thread here
//!   has no `Io` to wait with safely, so a full queue is an answer
//!   (`Options.on_full`), never a block.
//!
//! Server shutdown (`Server.shutdownGraceful` / `close`) wakes every `Hold`
//! and `run` returns `.shutdown`, so the handler can send a last event
//! before it returns — what Go leaves to `RegisterOnShutdown`. Limits are
//! opt-in, as in the references (Go, hyper, Starlette cap neither the number
//! of streaming handlers nor their idle time):
//! `Server.Options.max_held_responses`, `Hold.Options.idle_timeout_ms`,
//! `Hold.Options.heartbeat_ms` (axum's and sse-starlette's 15 s ping, here
//! off unless asked for).
//!
//! Linux only (eventfd, `POLLRDHUP`), as the module. Both waits block an OS
//! thread: under a fiber `Io` the HTTP/2 `Hold` is refused
//! (`Dispatcher.io`), and an HTTP/1.1 server should run on threads.

const std = @import("std");
const linux = std.os.linux;
const Server = @import("Server.zig");

/// `POLLRDHUP` (Linux, the value on every architecture this module targets).
const pollrdhup: i16 = 0x2000;

/// A callback run once when the peer is gone — Go's `context.AfterFunc`. It
/// runs on another thread (the watch task, or the HTTP/2 connection task with
/// the session locked): keep it short and never call back into the response.
pub const GoneHook = struct {
    ctx: ?*anyopaque = null,
    f: *const fn (ctx: ?*anyopaque) void,
};

/// The per-request record the HTTP/2 connection task fires. Internal to
/// `PeerWatch` / `Hold`, public only for `h2_server`.
pub const Watcher = struct {
    gone: std.atomic.Value(bool) = .init(false),
    hook: ?GoneHook = null,
    /// An eventfd to wake (a `Hold`'s owner), or -1.
    efd: linux.fd_t = -1,

    pub fn fire(w: *Watcher) void {
        if (w.gone.swap(true, .acq_rel)) return;
        if (w.hook) |h| h.f(h.ctx);
        if (w.efd >= 0) wake(w.efd);
    }
};

/// How an HTTP/2 stream served by the dispatcher reports its peer leaving
/// (`Request.h2_live`). Set by `h2_server` only; null on every other path.
pub const StreamLiveness = struct {
    ctx: *anyopaque,
    id: u31,
    server: ?*Server,
    /// False when the handler runs on a fiber (`Dispatcher.io`): a `Hold`
    /// would block the thread its connection task needs.
    can_block: bool,
    /// Registers `w` for the stream; false when the stream is already gone.
    attachFn: *const fn (ctx: *anyopaque, id: u31, w: *Watcher) bool,
    /// Unregisters; after it returns the connection task no longer fires.
    detachFn: *const fn (ctx: *anyopaque, id: u31) void,
};

pub const StartError = error{
    /// Nothing tells this request that its peer left: served socket-free
    /// (`serveStream` without a socket), HTTP/2 without `h2_dispatcher`, or
    /// an `Io` that cannot run the watch task.
    Unsupported,
    /// HTTP/1.1: the request body has not been read to its end. Bytes still
    /// owed by the peer are not a sign of life or death; read (or discard)
    /// the body first — Go starts its background read at the same point.
    BodyUnread,
    /// eventfd failed (descriptor limit).
    SystemResources,
};

/// Whether an HTTP/1.1 request body has been read to its end, without
/// reading (a read here could block on a peer that is still sending).
fn bodyDone(req: *const Server.Request) bool {
    return switch (req.body.*) {
        .none => true,
        .limited => |*lr| lr.remaining == 0,
        .chunked => |*cr| cr.state == .done,
        .capped => |*cc| cc.inner.state == .done,
        .external => true,
    };
}

/// Where a request's peer can be watched.
const Source = union(enum) {
    /// HTTP/1.1 over a socket: the connection's control.
    socket: *Server.ConnControl,
    h2: *const StreamLiveness,
};

fn sourceOf(req: *const Server.Request) StartError!Source {
    if (req.h2_live) |l| return .{ .h2 = l };
    if (req.stream_id != null) return error.Unsupported; // h2 without a dispatcher
    const c = req.control orelse return error.Unsupported;
    if (c.tr == null) return error.Unsupported;
    if (!bodyDone(req)) return error.BodyUnread;
    return .{ .socket = c };
}

fn newEventFd() StartError!linux.fd_t {
    const rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    if (linux.errno(rc) != .SUCCESS) return error.SystemResources;
    return @intCast(rc);
}

fn wake(efd: linux.fd_t) void {
    const one: u64 = 1;
    // EAGAIN only when the counter is saturated: the owner is woken anyway.
    _ = linux.write(efd, std.mem.asBytes(&one), 8);
}

fn drainEventFd(efd: linux.fd_t) void {
    var v: u64 = 0;
    _ = linux.read(efd, std.mem.asBytes(&v), 8);
}

fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

/// Revents that mean the peer is gone (closed, half-closed, reset).
fn hungUp(revents: i16) bool {
    return revents & (pollrdhup | linux.POLL.HUP | linux.POLL.ERR | linux.POLL.NVAL) != 0;
}

fn monoMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

/// Observe whether the peer of a running handler is still there — Go's
/// `Request.Context().Done()` plus `context.AfterFunc`. The handler owns the
/// storage, which must not move between `start` and `stop`:
///
/// ```zig
/// var watch: http.Server.PeerWatch = .{};
/// watch.start(req, .{ .ctx = job, .f = cancelJob }) catch {}; // runs without
/// defer watch.stop();
/// // … long work; `watch.gone()` may be polled, the hook fires on its own.
/// ```
///
/// `stop` must run before the handler returns. After it returns the hook
/// does not fire any more (one already running has finished).
pub const PeerWatch = struct {
    w: Watcher = .{},
    source: ?Source = null,
    /// HTTP/1.1: the stop eventfd and the watch task.
    stop_fd: linux.fd_t = -1,
    task: ?std.Io.Future(void) = null,

    pub fn start(pw: *PeerWatch, req: *const Server.Request, on_gone: ?GoneHook) StartError!void {
        pw.* = .{ .w = .{ .hook = on_gone } };
        const src = try sourceOf(req);
        switch (src) {
            .h2 => |l| if (!l.attachFn(l.ctx, l.id, &pw.w)) pw.w.fire(),
            .socket => |c| {
                pw.stop_fd = try newEventFd();
                pw.task = c.server.io.concurrent(watchTask, .{ pw, c.stream.socket.handle }) catch {
                    closeFd(pw.stop_fd);
                    pw.stop_fd = -1;
                    return error.Unsupported;
                };
            },
        }
        pw.source = src;
    }

    /// The peer closed the connection, reset the stream, or the connection
    /// ended. Thread-safe.
    pub fn gone(pw: *const PeerWatch) bool {
        return pw.w.gone.load(.acquire);
    }

    /// Stop watching (idempotent; a no-op when `start` failed).
    pub fn stop(pw: *PeerWatch) void {
        const src = pw.source orelse return;
        pw.source = null;
        switch (src) {
            .h2 => |l| l.detachFn(l.ctx, l.id),
            .socket => |c| {
                wake(pw.stop_fd);
                if (pw.task) |*t| t.await(c.server.io);
                pw.task = null;
                closeFd(pw.stop_fd);
                pw.stop_fd = -1;
            },
        }
    }

    fn watchTask(pw: *PeerWatch, sock: linux.fd_t) void {
        var fds = [2]linux.pollfd{
            .{ .fd = sock, .events = pollrdhup, .revents = 0 },
            .{ .fd = pw.stop_fd, .events = linux.POLL.IN, .revents = 0 },
        };
        while (true) {
            const rc = linux.poll(&fds, fds.len, -1);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return, // cannot watch: the peer is not reported gone
            }
            if (fds[1].revents != 0) return;
            if (hungUp(fds[0].revents)) {
                pw.w.fire();
                return;
            }
        }
    }
};

/// A held-open response: the handler commits the head, then writes what
/// other threads `send` until the stream ends. The owner (the handler's
/// task) calls `begin`, `run` and `end`; any thread may call `send`,
/// `finish` and `gone`. The storage must not move between `begin` and
/// `end`:
///
/// ```zig
/// var es = try http.sse.EventStream.start(rw); // headers only
/// var queue: [16 * 1024]u8 = undefined;
/// var hold: http.Server.Hold = .{};
/// try hold.begin(req, rw, &queue, .{ .heartbeat_ms = 15_000, .heartbeat = ": ping\n\n" });
/// defer hold.end();
/// registry.add(&hold); // feeders: hold.send(event_bytes) / hold.finish()
/// defer registry.remove(&hold);
/// switch (hold.run()) { .shutdown => es.data(goodbye) catch {}, else => {} }
/// ```
///
/// Feeders must be unregistered (`end` makes later `send`s fail
/// `error.Closed`, but the storage itself goes away with the handler): take
/// the feeder's pointer out of whatever shares it before the handler
/// returns.
pub const Hold = struct {
    rw: *Server.ResponseWriter = undefined,
    opts: Options = .{},
    w: Watcher = .{},
    source: ?Source = null,
    /// HTTP/1.1 over a socket: polled for the peer's hang-up.
    sock: linux.fd_t = -1,
    efd: linux.fd_t = -1,
    server: ?*Server = null,
    node: std.DoublyLinkedList.Node = .{},
    registered: bool = false,
    shutdown: std.atomic.Value(bool) = .init(false),

    /// Queue state, under `lock`: a ring over the caller's buffer.
    lock: std.atomic.Mutex = .unlocked,
    buf: []u8 = &.{},
    head: usize = 0,
    len: usize = 0,
    finished: bool = false,
    overflow: bool = false,
    closed: bool = false,
    /// Monotonic ms of the last `send` (the idle clock).
    last_send_ms: std.atomic.Value(u64) = .init(0),

    pub const Options = struct {
        /// What a `send` that does not fit the queue does. Either way that
        /// `send` fails `error.Full` and queues nothing.
        on_full: OnFull = .end_stream,
        /// End the stream (`End.idle`) after this long without a `send`;
        /// null = never (Go, hyper, Starlette have no such bound).
        idle_timeout_ms: ?u32 = null,
        /// Write `heartbeat` after this long without output (a `send` or an
        /// earlier heartbeat); null = never. For SSE an `: ping\n\n` comment
        /// (axum `KeepAlive`, sse-starlette ping: 15 s when enabled). It also
        /// finds a dead peer the hang-up does not show (a vanished host): the
        /// write stall timeout then fails it.
        heartbeat_ms: ?u32 = null,
        heartbeat: []const u8 = "",
    };

    pub const OnFull = enum {
        /// The slow consumer is disconnected: `run` returns `.overflow`, and
        /// nothing later is queued. The default: a gap in a push stream is
        /// invisible to the client, an end makes it re-subscribe.
        end_stream,
        /// The stream stays open; the feeder decides (drop, retry later).
        reject,
    };

    /// Why `run` returned.
    pub const End = enum {
        /// `finish` was called and everything queued before it was written.
        finished,
        /// The peer closed the connection or reset the stream.
        peer_gone,
        /// The server began shutting down (queued data was written first).
        shutdown,
        /// `idle_timeout_ms` passed without a `send`.
        idle,
        /// A `send` did not fit under `.end_stream`.
        overflow,
        /// Writing to the peer failed (it stopped reading: the write stall
        /// timeout, or a reset).
        write_failed,
    };

    pub const BeginError = error{
        /// HTTP/2 without `Options.h2_dispatcher`, or with a fiber
        /// dispatcher (`Dispatcher.io`): holding the handler would stop the
        /// connection's only reader, or block the thread its fibers share.
        Unsupported,
        /// HTTP/1.1: read the request body to its end first (see `PeerWatch`).
        BodyUnread,
        /// `Server.Options.max_held_responses` responses are held already;
        /// answer 503.
        TooManyHeld,
        /// `queue` is empty.
        NoQueue,
        SystemResources,
        /// Committing the head failed.
        WriteFailed,
    };

    /// Commit the response head (status and headers must be set: this
    /// flushes) and start holding. Socket-free (`serveStream` without a
    /// socket, a test, `router`'s in-memory runs) the response is held with
    /// no peer detection. Lifts `response_timeout_ms` for this response
    /// (Go needs `ResponseController.SetWriteDeadline` for that); the
    /// per-write stall (`write_timeout_ms`) still applies to every write.
    pub fn begin(h: *Hold, req: *const Server.Request, rw: *Server.ResponseWriter, queue: []u8, opts: Options) BeginError!void {
        h.* = .{ .rw = rw, .opts = opts, .buf = queue };
        if (queue.len == 0) return error.NoQueue;
        const src: ?Source = sourceOf(req) catch |e| switch (e) {
            error.BodyUnread => return error.BodyUnread,
            error.SystemResources => return error.SystemResources,
            error.Unsupported => if (req.stream_id != null) return error.Unsupported else null,
        };
        if (src) |s| switch (s) {
            .h2 => |l| if (!l.can_block) return error.Unsupported,
            .socket => {},
        };
        h.efd = try newEventFd();
        errdefer {
            closeFd(h.efd);
            h.efd = -1;
        }
        h.w.efd = h.efd;
        h.server = if (src) |s| switch (s) {
            .socket => |c| c.server,
            .h2 => |l| l.server,
        } else null;
        if (h.server) |srv| try srv.registerHold(h);
        errdefer if (h.server) |srv| srv.unregisterHold(h);
        if (src) |s| switch (s) {
            .socket => |c| {
                h.sock = c.stream.socket.handle;
                req.setWriteDeadline(0) catch {};
            },
            .h2 => |l| if (!l.attachFn(l.ctx, l.id, &h.w)) h.w.fire(),
        };
        h.source = src;
        errdefer h.detach();
        rw.flush() catch return error.WriteFailed;
        h.last_send_ms.store(monoMs(), .monotonic);
    }

    fn detach(h: *Hold) void {
        const src = h.source orelse return;
        h.source = null;
        switch (src) {
            .h2 => |l| l.detachFn(l.ctx, l.id),
            .socket => {},
        }
    }

    /// Queue `bytes` (one message, copied whole or not at all) and wake the
    /// owner. Thread-safe. `error.Closed` once the stream ended or `finish`
    /// was called; `error.Full` when it does not fit what is still unsent
    /// (see `Options.on_full`).
    pub fn send(h: *Hold, bytes: []const u8) error{ Closed, Full }!void {
        if (bytes.len == 0) return;
        lockSpin(&h.lock);
        if (h.closed or h.finished or h.overflow) {
            h.lock.unlock();
            return error.Closed;
        }
        if (bytes.len > h.buf.len - h.len) {
            const end_it = h.opts.on_full == .end_stream;
            if (end_it) h.overflow = true;
            h.lock.unlock();
            if (end_it) wake(h.efd);
            return error.Full;
        }
        const cap = h.buf.len;
        const tail = (h.head + h.len) % cap;
        const first = @min(bytes.len, cap - tail);
        @memcpy(h.buf[tail..][0..first], bytes[0..first]);
        @memcpy(h.buf[0 .. bytes.len - first], bytes[first..]);
        h.len += bytes.len;
        h.lock.unlock();
        h.last_send_ms.store(monoMs(), .monotonic);
        wake(h.efd);
    }

    /// Ask the owner to end the stream once everything queued is written
    /// (`End.finished`). Thread-safe, idempotent.
    pub fn finish(h: *Hold) void {
        lockSpin(&h.lock);
        const was = h.finished or h.closed;
        h.finished = true;
        h.lock.unlock();
        if (!was) wake(h.efd);
    }

    /// The peer is gone (see `PeerWatch.gone`). Thread-safe.
    pub fn gone(h: *const Hold) bool {
        return h.w.gone.load(.acquire);
    }

    /// Called by the server under its registry lock (`shutdownGraceful`,
    /// `close`).
    pub fn wakeForShutdown(h: *Hold) void {
        h.shutdown.store(true, .release);
        wake(h.efd);
    }

    /// Write what is queued, then wait; until the stream ends. Owner only.
    /// The response stays open when it returns: the handler may write a
    /// last event (unless `.peer_gone` / `.write_failed`) before returning,
    /// which ends it as any response ends.
    pub fn run(h: *Hold) End {
        var last_out_ms = monoMs();
        while (true) {
            if (h.gone()) return .peer_gone;
            switch (h.writeQueued()) {
                .failed => return .write_failed,
                .wrote => last_out_ms = monoMs(),
                .none => {},
            }
            lockSpin(&h.lock);
            const finished = h.finished and h.len == 0;
            const overflow = h.overflow;
            const pending = h.len != 0;
            h.lock.unlock();
            if (overflow) return .overflow;
            if (finished) return .finished;
            if (pending) continue;
            if (h.shutdown.load(.acquire)) return .shutdown;

            const now = monoMs();
            var timeout: i64 = -1;
            if (h.opts.idle_timeout_ms) |ms| {
                const due = h.last_send_ms.load(.monotonic) + ms;
                if (now >= due) return .idle;
                timeout = @intCast(due - now);
            }
            if (h.opts.heartbeat_ms) |ms| {
                const due = last_out_ms + ms;
                if (now >= due) {
                    h.rw.writeAll(h.opts.heartbeat) catch return .write_failed;
                    h.rw.flush() catch return .write_failed;
                    last_out_ms = monoMs();
                    continue;
                }
                const left: i64 = @intCast(due - now);
                timeout = if (timeout < 0) left else @min(timeout, left);
            }
            h.wait(@intCast(@min(timeout, std.math.maxInt(i32))));
        }
    }

    const Drained = enum { none, wrote, failed };

    /// Copy the queue to the response and flush. The segment being written
    /// stays in the ring until it is on its way: feeders only write the free
    /// part, so no copy under the lock is needed.
    fn writeQueued(h: *Hold) Drained {
        var wrote = false;
        while (true) {
            lockSpin(&h.lock);
            const n = @min(h.len, h.buf.len - h.head);
            const seg = h.buf[h.head..][0..n];
            h.lock.unlock();
            if (n == 0) break;
            h.rw.writeAll(seg) catch return .failed;
            lockSpin(&h.lock);
            h.head = (h.head + n) % h.buf.len;
            h.len -= n;
            h.lock.unlock();
            wrote = true;
        }
        if (!wrote) return .none;
        h.rw.flush() catch return .failed;
        return .wrote;
    }

    fn wait(h: *Hold, timeout_ms: i32) void {
        var fds = [2]linux.pollfd{
            .{ .fd = h.efd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = h.sock, .events = pollrdhup, .revents = 0 },
        };
        const n: usize = if (h.sock >= 0) 2 else 1;
        const rc = linux.poll(&fds, n, timeout_ms);
        if (linux.errno(rc) != .SUCCESS) return; // EINTR: the loop looks again
        if (fds[0].revents != 0) drainEventFd(h.efd);
        if (n == 2 and hungUp(fds[1].revents)) h.w.fire();
    }

    /// Stop holding (idempotent): later `send`s fail `error.Closed`, the
    /// server forgets the response. Owner only; must run before the handler
    /// returns. Ending the response itself is the serving loop's, as for
    /// any handler.
    pub fn end(h: *Hold) void {
        if (h.efd < 0) return;
        lockSpin(&h.lock);
        h.closed = true;
        h.lock.unlock();
        h.detach();
        if (h.server) |srv| srv.unregisterHold(h);
        h.server = null;
        closeFd(h.efd);
        h.efd = -1;
        h.w.efd = -1;
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const testkit = @import("testkit");
const sse = @import("sse.zig");

fn sleepMs(io: std.Io, ms: u32) void {
    const d: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake };
    d.sleep(io) catch {};
}

/// Shared between a test, its server's handler and the feeder.
const Probe = struct {
    io: std.Io,
    opts: Hold.Options = .{},
    hold: std.atomic.Value(?*Hold) = .init(null),
    /// `@intFromEnum(Hold.End)` once `run` returned; 0xff before.
    end: std.atomic.Value(u8) = .init(0xff),
    hook_ran: std.atomic.Value(bool) = .init(false),
    /// How long `/watch` waits for the peer to go.
    watch_ms: u32 = 3000,
    refused: std.atomic.Value(u32) = .init(0),

    fn onGone(ctx: ?*anyopaque) void {
        const p: *Probe = @ptrCast(@alignCast(ctx.?));
        p.hook_ran.store(true, .release);
    }

    fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        const p: *Probe = @ptrCast(@alignCast(req.context.?));
        if (std.mem.eql(u8, req.path, "/hold")) {
            var es = try sse.EventStream.start(rw);
            var q: [64]u8 = undefined;
            var h: Hold = .{};
            h.begin(req, rw, &q, p.opts) catch |e| switch (e) {
                error.TooManyHeld => {
                    _ = p.refused.fetchAdd(1, .monotonic);
                    rw.setStatus(503);
                    return;
                },
                else => return e,
            };
            defer h.end();
            p.hold.store(&h, .release);
            const e = h.run();
            p.hold.store(null, .release);
            p.end.store(@backingInt(e), .release);
            if (e == .shutdown) es.data("bye") catch {};
        } else if (std.mem.eql(u8, req.path, "/watch")) {
            _ = try req.reader().discardRemaining();
            var pw: PeerWatch = .{};
            try pw.start(req, .{ .ctx = p, .f = onGone });
            defer pw.stop();
            var waited: u32 = 0;
            while (!pw.gone() and waited < p.watch_ms) : (waited += 5) sleepMs(p.io, 5);
            try rw.writeAll(if (pw.gone()) "gone" else "alive");
        } else {
            try rw.writeAll("plain");
        }
    }

    fn waitHold(p: *Probe) !*Hold {
        var waited: u32 = 0;
        while (waited < 5000) : (waited += 2) {
            if (p.hold.load(.acquire)) |h| return h;
            sleepMs(p.io, 2);
        }
        return error.HoldNeverBegan;
    }

    fn waitEnd(p: *Probe) !Hold.End {
        var waited: u32 = 0;
        while (waited < 5000) : (waited += 2) {
            const v = p.end.load(.acquire);
            if (v != 0xff) return @fromBackingInt(@intCast(v));
            sleepMs(p.io, 2);
        }
        return error.HoldNeverEnded;
    }
};

fn serveWrap(s: *Server) void {
    s.serve() catch {};
}

const Fixture = struct {
    threaded: std.Io.Threaded,
    server: Server,
    thread: std.Thread,

    /// Null: loopback unavailable (the caller skips).
    fn start(f: *Fixture, probe: *Probe, extra: Server.Options) !bool {
        var o = extra;
        o.handler = Probe.handler;
        o.context = probe;
        f.server = Server.init(probe.io, testing.allocator, o);
        f.server.bind() catch |err| {
            f.server.deinit();
            testkit.loopbackSkip("loopback bind failed ({t})", .{err}) catch {};
            return false;
        };
        f.thread = try std.Thread.spawn(.{}, serveWrap, .{&f.server});
        return true;
    }

    fn stop(f: *Fixture) void {
        f.server.close();
        f.server.shutdown();
        f.thread.join();
        f.server.deinit();
    }
};

fn writeAll(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    var wbuf: [256]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    try sw.interface.writeAll(bytes);
    try sw.interface.flush();
}

fn readAll(io: std.Io, stream: std.Io.net.Stream, buf: []u8) []const u8 {
    var rbuf: [256]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var w: std.Io.Writer = .fixed(buf);
    _ = sr.interface.streamRemaining(&w) catch {};
    return w.buffered();
}

test "Hold: events sent from another thread reach the client, finish ends the response" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var probe: Probe = .{ .io = threaded.io() };
    var f: Fixture = undefined;
    if (!try f.start(&probe, .{ .handler = Probe.handler })) return;
    defer f.stop();
    const io = probe.io;

    const stream = try f.server.boundAddress().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, "GET /hold HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    const h = try probe.waitHold();
    try h.send("data: one\n\n");
    try h.send("data: two\n\n");
    h.finish();
    try testing.expectError(error.Closed, h.send("late"));
    var buf: [2048]u8 = undefined;
    const got = readAll(io, stream, &buf);
    try testing.expectEqual(Hold.End.finished, try probe.waitEnd());
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, got, "text/event-stream") != null);
    const one = std.mem.indexOf(u8, got, "data: one").?;
    const two = std.mem.indexOf(u8, got, "data: two").?;
    try testing.expect(one < two);
    try testing.expect(std.mem.endsWith(u8, got, "0\r\n\r\n"));
}

test "Hold: a pipelined next request is not a gone peer; it is served after the held response" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var probe: Probe = .{ .io = threaded.io() };
    var f: Fixture = undefined;
    if (!try f.start(&probe, .{ .handler = Probe.handler })) return;
    defer f.stop();
    const io = probe.io;

    const stream = try f.server.boundAddress().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, "GET /hold HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /next HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    const h = try probe.waitHold();
    sleepMs(io, 100); // the next request's bytes sit on the socket meanwhile
    try testing.expect(!h.gone());
    try h.send("data: x\n\n");
    h.finish();
    var buf: [2048]u8 = undefined;
    const got = readAll(io, stream, &buf);
    try testing.expectEqual(Hold.End.finished, try probe.waitEnd());
    const ev = std.mem.indexOf(u8, got, "data: x").?;
    const next = std.mem.lastIndexOf(u8, got, "HTTP/1.1 200 OK").?;
    try testing.expect(ev < next);
    try testing.expect(std.mem.endsWith(u8, got, "plain"));
}

test "Hold: the peer closing ends run with peer_gone" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var probe: Probe = .{ .io = threaded.io() };
    var f: Fixture = undefined;
    if (!try f.start(&probe, .{ .handler = Probe.handler })) return;
    defer f.stop();
    const io = probe.io;

    const stream = try f.server.boundAddress().connect(io, .{ .mode = .stream });
    try writeAll(io, stream, "GET /hold HTTP/1.1\r\nHost: t\r\n\r\n");
    _ = try probe.waitHold();
    stream.close(io);
    try testing.expectEqual(Hold.End.peer_gone, try probe.waitEnd());
}

test "Hold: shutdownGraceful ends run with shutdown and the handler's last event goes out" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var probe: Probe = .{ .io = threaded.io() };
    var f: Fixture = undefined;
    if (!try f.start(&probe, .{ .handler = Probe.handler })) return;
    defer f.stop();
    const io = probe.io;

    const stream = try f.server.boundAddress().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, "GET /hold HTTP/1.1\r\nHost: t\r\n\r\n");
    _ = try probe.waitHold();
    try testing.expectEqual(@as(usize, 1), f.server.heldResponses());
    try f.server.shutdownGraceful(5000);
    try testing.expectEqual(Hold.End.shutdown, try probe.waitEnd());
    var buf: [2048]u8 = undefined;
    const got = readAll(io, stream, &buf);
    try testing.expect(std.mem.indexOf(u8, got, "data: bye\n\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "0\r\n\r\n"));
    try testing.expectEqual(@as(usize, 0), f.server.heldResponses());
}

test "Hold: max_held_responses refuses the next one, idle_timeout_ms and the heartbeat" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var probe: Probe = .{ .io = threaded.io(), .opts = .{ .idle_timeout_ms = 300, .heartbeat_ms = 40, .heartbeat = ": ping\n\n" } };
    var f: Fixture = undefined;
    if (!try f.start(&probe, .{ .handler = Probe.handler, .max_held_responses = 1 })) return;
    defer f.stop();
    const io = probe.io;

    const a = try f.server.boundAddress().connect(io, .{ .mode = .stream });
    defer a.close(io);
    try writeAll(io, a, "GET /hold HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    _ = try probe.waitHold();
    const b = try f.server.boundAddress().connect(io, .{ .mode = .stream });
    defer b.close(io);
    try writeAll(io, b, "GET /hold HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    var bbuf: [512]u8 = undefined;
    try testing.expect(std.mem.startsWith(u8, readAll(io, b, &bbuf), "HTTP/1.1 503 "));
    try testing.expectEqual(@as(u32, 1), probe.refused.load(.monotonic));

    var buf: [4096]u8 = undefined;
    const got = readAll(io, a, &buf);
    try testing.expectEqual(Hold.End.idle, try probe.waitEnd());
    try testing.expect(std.mem.indexOf(u8, got, ": ping\n\n") != null);
}

test "PeerWatch: a half-close is a gone peer and fires the hook; the response still goes out" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var probe: Probe = .{ .io = threaded.io() };
    var f: Fixture = undefined;
    if (!try f.start(&probe, .{ .handler = Probe.handler })) return;
    defer f.stop();
    const io = probe.io;

    const stream = try f.server.boundAddress().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, "POST /watch HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc");
    sleepMs(io, 50);
    try stream.shutdown(io, .send);
    var buf: [1024]u8 = undefined;
    const got = readAll(io, stream, &buf);
    try testing.expect(std.mem.endsWith(u8, got, "gone"));
    try testing.expect(probe.hook_ran.load(.acquire));
}

test "PeerWatch: a pipelined next request is not a gone peer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var probe: Probe = .{ .io = threaded.io(), .watch_ms = 200 };
    var f: Fixture = undefined;
    if (!try f.start(&probe, .{ .handler = Probe.handler })) return;
    defer f.stop();
    const io = probe.io;

    const stream = try f.server.boundAddress().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, "GET /watch HTTP/1.1\r\nHost: t\r\n\r\n" ++
        "GET /next HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    var buf: [1024]u8 = undefined;
    const got = readAll(io, stream, &buf);
    try testing.expect(std.mem.indexOf(u8, got, "alive") != null);
    try testing.expect(std.mem.endsWith(u8, got, "plain"));
    try testing.expect(!probe.hook_ran.load(.acquire));
}

test "PeerWatch: an unread body is refused, socket-free is unsupported" {
    const T = struct {
        var unread: ?anyerror = null;
        var free: ?anyerror = null;
        fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
            var pw: PeerWatch = .{};
            pw.start(req, null) catch |e| {
                if (std.mem.eql(u8, req.path, "/a")) unread = e else free = e;
            };
            pw.stop();
            _ = try req.reader().discardRemaining();
            try rw.writeAll("x");
        }
    };
    // Socket-free: no control, so even a bodiless request is unsupported.
    var out_buf: [1024]u8 = undefined;
    var in: std.Io.Reader = .fixed("GET /b HTTP/1.1\r\nHost: t\r\n\r\n");
    var out: std.Io.Writer = .fixed(&out_buf);
    var head: [1024]u8 = undefined;
    var body: [256]u8 = undefined;
    var req_body: [256]u8 = undefined;
    var chunk: [64]u8 = undefined;
    Server.serveStream(.{ .handler = T.handler }, &in, &out, .{ .head = &head, .response_body = &body, .request_body = &req_body, .chunk = &chunk });
    try testing.expectEqual(@as(?anyerror, error.Unsupported), T.free);
    // `bodyDone` on an unread Content-Length body.
    var r: std.Io.Reader = .fixed("abc");
    var rb: Server.RequestBody = .{ .limited = .init(&r, 3, &req_body) };
    var req: Server.Request = .{ .method = .post, .target = "/a", .path = "/a", .query = "", .head = undefined, .body = &rb, .context = null };
    try testing.expect(!bodyDone(&req));
    _ = try rb.reader().discardRemaining();
    try testing.expect(bodyDone(&req));
}

test "Hold socket-free: send/finish from a thread, on_full reject keeps the stream, end_stream ends it" {
    const T = struct {
        var hold: std.atomic.Value(?*Hold) = .init(null);
        var end: std.atomic.Value(u8) = .init(0xff);
        var opts: Hold.Options = .{};
        fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
            var q: [8]u8 = undefined;
            var h: Hold = .{};
            try h.begin(req, rw, &q, opts);
            defer h.end();
            hold.store(&h, .release);
            const e = h.run();
            hold.store(null, .release);
            end.store(@backingInt(e), .release);
        }
        fn feed(reject: bool) void {
            const h = while (true) {
                if (hold.load(.acquire)) |p| break p;
                std.atomic.spinLoopHint();
            };
            h.send("abcd") catch unreachable;
            h.send("efgh") catch unreachable; // fills the 8-byte queue unless drained
            if (reject) {
                // Whatever is still queued, a 9-byte message never fits.
                if (h.send("123456789")) |_| unreachable else |e| std.debug.assert(e == error.Full);
                h.finish();
            } else {
                if (h.send("123456789")) |_| unreachable else |e| std.debug.assert(e == error.Full);
            }
        }
    };
    for ([_]bool{ true, false }) |reject| {
        T.opts = .{ .on_full = if (reject) .reject else .end_stream };
        T.end.store(0xff, .release);
        const th = try std.Thread.spawn(.{}, T.feed, .{reject});
        var out_buf: [2048]u8 = undefined;
        var in: std.Io.Reader = .fixed("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        var out: std.Io.Writer = .fixed(&out_buf);
        var head: [1024]u8 = undefined;
        var body: [256]u8 = undefined;
        var req_body: [256]u8 = undefined;
        var chunk: [64]u8 = undefined;
        Server.serveStream(.{ .handler = T.handler }, &in, &out, .{ .head = &head, .response_body = &body, .request_body = &req_body, .chunk = &chunk });
        th.join();
        const want: Hold.End = if (reject) .finished else .overflow;
        try testing.expectEqual(@backingInt(want), T.end.load(.acquire));
        if (reject) try testing.expect(std.mem.indexOf(u8, out.buffered(), "abcd") != null);
    }
}

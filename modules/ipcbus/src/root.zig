// SPDX-License-Identifier: MIT
//! ipcbus — same-host unix-socket control plane: one owner process serves
//! request/reply over a framed unix socket + a capped in-memory KV bus. Linux.
//!
//! Design constraints (v1):
//!  * **Single owner.** One process owns the listen socket and the `Bus`; the
//!    `Bus` is lock-free and MUST be touched from that one thread/loop only.
//!  * **One connection per request.** Every request is a fresh `connect →
//!    write one frame → read one frame → close`. There is no persistent
//!    multiplexed connection. `acceptOne` + `handleOne` service exactly one
//!    connection at a time; `Mux` is the single-threaded poll loop that serves
//!    many at once, each with its own deadline.
//!  * **No baked-in dispatch.** `Server.handleOne` takes a caller-supplied
//!    `dispatch` callback `fn(ctx, req_bytes, gpa) !reply_bytes`. All
//!    application command handling lives in the app, never in this module.
//!  * **Framing is delegated.** Every message is a length-prefixed frame via
//!    the `framing` module — this module never re-implements the wire format.

const std = @import("std");
const framing = @import("framing");
const linux = std.os.linux;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Same-host unix-socket control plane — a request/reply server plus a capped in-memory scratch key→bytes bus.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{.linux64},
    .platform = .linux,
    .role = .server,
    .concurrency = .single_owner,
    .model_after = "unix-domain control socket + in-memory scratch bus",
    .deps = .{"framing"},
};

/// Raw Linux file descriptor.
pub const Fd = linux.fd_t;

/// Errors from the raw unix-socket transport helpers.
pub const TransportError = error{
    SocketFailed,
    BindFailed,
    ListenFailed,
    ConnectFailed,
    AcceptFailed,
    WriteFailed,
    ReadFailed,
    /// An operation with a timeout (`Options.timeout_ms`) did not finish in time.
    Timeout,
    /// `getsockopt(SO_PEERCRED)` failed (not a unix socket, or closed fd).
    PeerCredFailed,
    /// The peer closed the connection before the expected bytes arrived.
    EndOfStream,
};

/// Scratch buffer size for the per-connection framing reader/writer. Any frame
/// larger than this streams straight through (the `std.Io` reader/writer spill
/// past their buffer), so this only bounds syscall batching, not message size.
const io_buf_size = 4096;

fn closeFd(fd: Fd) void {
    _ = linux.close(fd);
}

// ── raw unix-socket transport (libc-free, CLOEXEC-hardened) ─────────────────

/// Build a `sockaddr.un` for a pathname (non-abstract) unix socket. `path` is
/// truncated to 107 bytes + NUL (the kernel limit) if longer.
pub fn unixAddr(path: [:0]const u8) linux.sockaddr.un {
    var addr = linux.sockaddr.un{ .family = linux.AF.UNIX, .path = @as([108]u8, @splat(0)) };
    const n = @min(path.len, 107);
    @memcpy(addr.path[0..n], path[0..n]);
    return addr;
}

/// Connect to a listening unix socket at `path`. The fd is opened `CLOEXEC` so
/// it is never leaked across a `fork`+`exec` in the owning process.
pub fn connectUnix(path: [:0]const u8) TransportError!Fd {
    const s = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(s) != .SUCCESS) return error.SocketFailed;
    const fd: Fd = @intCast(s);
    errdefer closeFd(fd);
    var addr = unixAddr(path);
    if (linux.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS)
        return error.ConnectFailed;
    return fd;
}

/// Bind + listen a unix socket at `path`. `CLOEXEC` is critical: an owner that
/// spawns children via `fork`+`exec` must not leak the listening fd, or a
/// connect could succeed through a child's inherited fd even after the owner
/// dies — defeating owner-liveness detection and hanging on the missing reply.
pub fn listenUnix(path: [:0]const u8) TransportError!Fd {
    const s = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(s) != .SUCCESS) return error.SocketFailed;
    const fd: Fd = @intCast(s);
    errdefer closeFd(fd);
    var addr = unixAddr(path);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS)
        return error.BindFailed;
    if (linux.errno(linux.listen(fd, 64)) != .SUCCESS)
        return error.ListenFailed;
    return fd;
}

/// Per-call options for `Client.requestWithOptions` / `Server.handleOneWithOptions`.
pub const Options = struct {
    /// Total budget in milliseconds for the whole call after the connection
    /// exists (client: write request + read reply; server: read request,
    /// dispatch is NOT counted but the reply write is, from the same start).
    /// `null` (default) = block forever, the pre-timeout behaviour. A budget
    /// that runs out returns `error.Timeout`, never a hang.
    timeout_ms: ?u32 = null,
};

/// A monotonic-clock deadline; `end_ns == null` means "never".
const Deadline = struct {
    end_ns: ?u64 = null,

    fn nowNs() u64 {
        var ts: linux.timespec = undefined;
        if (linux.errno(linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
        return @as(u64, @intCast(ts.sec)) *% 1_000_000_000 +% @as(u64, @intCast(ts.nsec));
    }

    fn after(timeout_ms: ?u32) Deadline {
        const ms = timeout_ms orelse return .{};
        return .{ .end_ns = nowNs() +| @as(u64, ms) * 1_000_000 };
    }

    /// Milliseconds left, rounded up, as a `poll` timeout (-1 = infinite).
    fn pollMs(self: Deadline) i32 {
        const end = self.end_ns orelse return -1;
        const now = nowNs();
        if (now >= end) return 0;
        const left = (end - now + 999_999) / 1_000_000;
        return @intCast(@min(left, std.math.maxInt(i32)));
    }
};

/// Wait until `fd` is ready for `events` (a hang-up/error also counts as
/// ready: the following read/write reports it). `error.Timeout` on expiry.
fn waitReady(fd: Fd, events: i16, deadline: Deadline) TransportError!void {
    while (true) {
        var pfd = [1]linux.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        const rc = linux.poll(&pfd, 1, deadline.pollMs());
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (rc == 0) {
            if (deadline.end_ns == null) continue; // cannot happen with -1
            return error.Timeout;
        }
        return;
    }
}

/// Write every byte of `bytes` to `fd`, retrying short writes and `EINTR`.
pub fn writeAllFd(fd: Fd, bytes: []const u8) TransportError!void {
    return writeAllFdDeadline(fd, bytes, .{});
}

fn writeAllFdDeadline(fd: Fd, bytes: []const u8, deadline: Deadline) TransportError!void {
    var off: usize = 0;
    while (off < bytes.len) {
        if (deadline.end_ns != null) {
            // Never block in write(2): wait for room, then send without blocking.
            waitReady(fd, linux.POLL.OUT, deadline) catch |e| return if (e == error.Timeout) e else error.WriteFailed;
            const rc = linux.sendto(fd, bytes.ptr + off, bytes.len - off, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue,
                else => return error.WriteFailed,
            }
            if (rc == 0) return error.WriteFailed;
            off += rc;
            continue;
        }
        // MSG_NOSIGNAL: a peer that closed before reading must cost an error, not a SIGPIPE that ends the process.
        // A non-socket `fd` (ENOTSOCK) takes write(2).
        var rc = linux.sendto(fd, bytes.ptr + off, bytes.len - off, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(rc) == .NOTSOCK) rc = linux.write(fd, bytes.ptr + off, bytes.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.WriteFailed,
        }
        if (rc == 0) return error.WriteFailed;
        off += rc;
    }
}

/// Credentials of the process that connected to a unix socket (`SO_PEERCRED`),
/// as recorded by the kernel at `connect` time.
pub const PeerCred = struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

/// Peer credentials of the connected unix-socket `fd` (a socket from
/// `Server.acceptOne`, `connectUnix` or `socketpair`). Linux `SO_PEERCRED`.
pub fn peerCred(fd: Fd) TransportError!PeerCred {
    const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };
    var uc: Ucred = undefined;
    var len: linux.socklen_t = @sizeOf(Ucred);
    const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.PEERCRED, @ptrCast(&uc), &len);
    if (linux.errno(rc) != .SUCCESS or len != @sizeOf(Ucred)) return error.PeerCredFailed;
    return .{ .pid = uc.pid, .uid = uc.uid, .gid = uc.gid };
}

/// Fill `buf` completely from `fd`, retrying short reads and `EINTR`. Returns
/// `error.EndOfStream` if the peer closes before `buf` is full.
pub fn readExact(fd: Fd, buf: []u8) TransportError!void {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = linux.read(fd, buf.ptr + off, buf.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (rc == 0) return error.EndOfStream;
        off += rc;
    }
}

// ── std.Io ⇄ raw-fd adapters (so `framing` can drive a socket) ──────────────
// `framing.writeFrame`/`readFrame` operate on `*std.Io.Writer`/`*std.Io.Reader`.
// These minimal adapters back those interfaces with blocking `read`/`write`
// syscalls — no libc, no `std.Io` runtime instance required.

/// A `std.Io.Reader` whose backing store is a blocking socket fd.
pub const FdReader = struct {
    fd: Fd,
    interface: std.Io.Reader,
    /// Optional deadline; once it passes a read fails with `error.ReadFailed`
    /// and `timed_out` is set (std.Io.Reader cannot carry a custom error).
    deadline: Deadline = .{},
    timed_out: bool = false,

    pub fn init(fd: Fd, buffer: []u8) FdReader {
        return .{
            .fd = fd,
            .interface = .{
                .vtable = &.{ .stream = stream, .readVec = refillReadVec },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *FdReader = @alignCast(@fieldParentPtr("interface", io_r));
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        while (true) {
            if (self.deadline.end_ns != null) {
                waitReady(self.fd, linux.POLL.IN, self.deadline) catch |e| {
                    if (e == error.Timeout) self.timed_out = true;
                    return error.ReadFailed;
                };
            }
            const rc = linux.read(self.fd, dest.ptr, dest.len);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.EndOfStream;
                    io_w.advance(rc);
                    return rc;
                },
                .INTR => continue,
                else => return error.ReadFailed,
            }
        }
    }
};

/// A `std.Io.Writer` whose backing sink is a blocking socket fd.
pub const FdWriter = struct {
    fd: Fd,
    interface: std.Io.Writer,
    /// Optional deadline; see `FdReader.deadline`.
    deadline: Deadline = .{},
    timed_out: bool = false,

    pub fn init(fd: Fd, buffer: []u8) FdWriter {
        return .{
            .fd = fd,
            .interface = .{
                .vtable = &.{ .drain = drain },
                .buffer = buffer,
            },
        };
    }

    fn put(self: *FdWriter, bytes: []const u8) std.Io.Writer.Error!void {
        writeAllFdDeadline(self.fd, bytes, self.deadline) catch |e| {
            if (e == error.Timeout) self.timed_out = true;
            return error.WriteFailed;
        };
    }

    fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *FdWriter = @alignCast(@fieldParentPtr("interface", io_w));
        const buffered = io_w.buffered();
        try self.put(buffered);
        var extra: usize = 0;
        if (data.len > 0) {
            for (data[0 .. data.len - 1]) |bytes| {
                try self.put(bytes);
                extra += bytes.len;
            }
            const pattern = data[data.len - 1];
            var i: usize = 0;
            while (i < splat) : (i += 1) {
                try self.put(pattern);
                extra += pattern.len;
            }
        }
        return io_w.consume(buffered.len + extra);
    }
};

// ── server ──────────────────────────────────────────────────────────────────

/// Who may connect to a `Server`, judged by the kernel-recorded `SO_PEERCRED`
/// uid of the peer. The check is made by `Server.acceptOne`; a refused peer's
/// connection is closed and never reaches the caller.
///
/// Same rule as the D-Bus session bus, where the `EXTERNAL` SASL mechanism
/// makes the identity "a Unix user" taken from kernel-passed credentials: by
/// default only the server's own uid is admitted.
pub const PeerPolicy = union(enum) {
    /// Admit only peers whose uid equals the server's effective uid at
    /// `Server.listen` time (default).
    same_uid,
    /// Admit only peers whose uid is in this list (the server's own uid is NOT
    /// implied; list it too if it should connect). The slice must outlive the
    /// server.
    uids: []const u32,
    /// Admit every peer that can reach the socket path (the pre-2026-11-18
    /// behaviour: filesystem permissions are the only access control).
    any,

    /// Pure decision: does this policy admit a peer with credentials `cred`,
    /// given the server's own uid?
    pub fn allows(self: PeerPolicy, own_uid: u32, cred: PeerCred) bool {
        return switch (self) {
            .same_uid => cred.uid == own_uid,
            .uids => |list| for (list) |u| {
                if (u == cred.uid) break true;
            } else false,
            .any => true,
        };
    }
};

/// A single-owner request/reply server over a unix socket. The owning thread
/// loops `acceptOne` → `handleOne`; there is no internal concurrency.
pub const Server = struct {
    listen_fd: Fd,
    path: [:0]const u8,
    /// Peer admission rule applied by `acceptOne` (default `.same_uid`).
    policy: PeerPolicy = .same_uid,
    /// The server's effective uid, taken at `listen` (what `.same_uid` compares to).
    own_uid: u32 = 0,
    /// Number of connections `acceptOne` has refused (and closed) so far.
    refused: u64 = 0,

    /// Bind + listen at `path`, unlinking any stale socket left by a prior run.
    /// Peers are admitted by `PeerPolicy.same_uid`; see `listenWithPolicy`.
    pub fn listen(path: [:0]const u8) TransportError!Server {
        return listenWithPolicy(path, .same_uid);
    }

    /// `listen` with an explicit peer admission policy.
    pub fn listenWithPolicy(path: [:0]const u8, policy: PeerPolicy) TransportError!Server {
        _ = linux.unlink(path.ptr);
        const fd = try listenUnix(path);
        return .{ .listen_fd = fd, .path = path, .policy = policy, .own_uid = linux.geteuid() };
    }

    /// Close the listen socket and remove its path.
    pub fn deinit(self: *Server) void {
        closeFd(self.listen_fd);
        _ = linux.unlink(self.path.ptr);
    }

    /// Accept one connection with no credential check (internal building block).
    fn acceptRaw(self: *Server) TransportError!Fd {
        while (true) {
            const rc = linux.accept4(self.listen_fd, null, null, linux.SOCK.CLOEXEC);
            switch (linux.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR, .AGAIN => continue,
                else => return error.AcceptFailed,
            }
        }
    }

    /// Apply `policy` to the accepted `fd`. A peer whose credentials cannot be
    /// read, or that the policy refuses, has its fd closed and is counted in
    /// `refused`. Returns whether the peer was admitted.
    fn admit(self: *Server, fd: Fd) bool {
        if (self.policy == .any) return true;
        const cred = peerCred(fd) catch {
            closeFd(fd);
            self.refused +|= 1;
            return false;
        };
        if (self.policy.allows(self.own_uid, cred)) return true;
        closeFd(fd);
        self.refused +|= 1;
        return false;
    }

    /// Block until an admitted client connects; returns the accepted (CLOEXEC)
    /// conn fd. Caller owns the fd — pass it to `handleOne`, which closes it.
    ///
    /// Behaviour change (2026-11-18): the peer's `SO_PEERCRED` uid is checked
    /// against `policy` (default: the server's own uid). A refused peer is
    /// closed silently and the loop keeps waiting, so a local user who is not
    /// admitted can neither reach `dispatch` nor stop the accept loop; the
    /// count is in `refused`. Use `listenWithPolicy(path, .any)` for the old
    /// behaviour.
    pub fn acceptOne(self: *Server) TransportError!Fd {
        while (true) {
            const fd = try self.acceptRaw();
            if (self.admit(fd)) return fd;
        }
    }

    /// Serve exactly one connection: read one framed request, run the
    /// caller-supplied `dispatch`, write one framed reply, then close `conn_fd`.
    ///
    /// `dispatch(ctx, req_bytes, gpa) !reply_bytes` is where ALL application
    /// command handling lives — this module contributes none. `gpa` is used
    /// for the request scratch buffer and is available to `dispatch` for
    /// building the reply; callers should pass a per-connection arena and reset
    /// it after the call. A malformed/oversize frame errors cleanly (the length
    /// cap is checked before the body is read, so an oversize header never
    /// blocks waiting for a body that will not arrive).
    ///
    /// The request buffer is sized to the frame's announced length (checked
    /// against `limits.max_frame` first), not to the cap — so a small request
    /// costs a small allocation even with the 1 MiB default, and the cap stays
    /// a rejection threshold rather than a per-connection price an unauthorized
    /// peer gets to impose by connecting.
    pub fn handleOne(
        conn_fd: Fd,
        ctx: anytype,
        comptime dispatch: fn (@TypeOf(ctx), []const u8, std.mem.Allocator) anyerror![]const u8,
        gpa: std.mem.Allocator,
        limits: framing.Limits,
    ) !void {
        return handleOneWithOptions(conn_fd, ctx, dispatch, gpa, limits, .{});
    }

    /// `handleOne` with `Options`: with `timeout_ms` set, a peer that never
    /// sends (or never drains) its frame makes this return `error.Timeout`
    /// (and close `conn_fd`) instead of blocking the accept loop. The budget
    /// covers the read of the request and the write of the reply (each polled
    /// against one deadline started on entry); time spent inside `dispatch`
    /// is the callback's own business and is not interrupted.
    ///
    /// The caller's uid has already been checked by `acceptOne` against the
    /// server's `PeerPolicy`; call `peerCred(conn_fd)` for finer decisions.
    pub fn handleOneWithOptions(
        conn_fd: Fd,
        ctx: anytype,
        comptime dispatch: fn (@TypeOf(ctx), []const u8, std.mem.Allocator) anyerror![]const u8,
        gpa: std.mem.Allocator,
        limits: framing.Limits,
        opts: Options,
    ) !void {
        defer closeFd(conn_fd);
        const deadline = Deadline.after(opts.timeout_ms);

        var rbuf: [io_buf_size]u8 = undefined;
        var fr = FdReader.init(conn_fd, &rbuf);
        fr.deadline = deadline;
        const req = framing.readFrameAlloc(&fr.interface, gpa, limits) catch |e|
            return if (fr.timed_out) error.Timeout else e;
        defer gpa.free(req);

        const reply = try dispatch(ctx, req, gpa);

        var wbuf: [io_buf_size]u8 = undefined;
        var fw = FdWriter.init(conn_fd, &wbuf);
        fw.deadline = deadline;
        framing.writeFrame(&fw.interface, reply, limits) catch |e|
            return if (fw.timed_out) error.Timeout else e;
        fw.interface.flush() catch |e|
            return if (fw.timed_out) error.Timeout else e;
    }
};

// ── multiplexed server loop ─────────────────────────────────────────────────

/// Options of `Mux`.
pub const MuxOptions = struct {
    /// Connections in service at once. Further clients wait in the listen backlog (accepting
    /// resumes as slots free), so a flood cannot exhaust descriptors or memory.
    max_conns: u16 = 64,
    /// Budget for one connection from accept to the end of its reply: a client that has not
    /// delivered a whole frame, or has not drained its reply, by then is closed (counted in
    /// `Mux.timed_out`). `null` = no deadline (a stalled client then holds its slot forever).
    timeout_ms: ?u32 = 5000,
    /// Frame limits, as `Server.handleOne`'s.
    limits: framing.Limits = .{},
};

/// A single-threaded, poll-based server loop over a `Server`: many connections are in flight at
/// once, each read and written with non-blocking I/O against its own deadline, so one slow or
/// stalled client no longer blocks the others. `dispatch` still runs one request at a time on
/// the calling thread, so the `Bus` and the owner's state keep their single-owner discipline.
/// The connection model is unchanged (one framed request, one framed reply, close), the peer
/// admission policy of the `Server` applies at accept.
///
/// Drive it from the owner's loop: `while (running) _ = try mux.step(ctx, dispatch, 250);`.
pub const Mux = struct {
    server: *Server,
    gpa: std.mem.Allocator,
    opts: MuxOptions,
    conns: []Conn,
    pfds: []linux.pollfd,
    /// Connections currently in service.
    open: usize = 0,
    /// Replies fully written.
    served: u64 = 0,
    /// Connections closed for blowing `timeout_ms`.
    timed_out: u64 = 0,
    /// Connections closed for a bad frame, an early EOF, an I/O error or a failing `dispatch`.
    failed: u64 = 0,

    const Conn = struct {
        fd: Fd = -1,
        deadline: Deadline = .{},
        dec: framing.Decoder = undefined,
        out: []u8 = &.{},
        out_off: usize = 0,
        writing: bool = false,
    };

    pub const StepError = error{ OutOfMemory, PollFailed };

    pub fn init(gpa: std.mem.Allocator, server: *Server, opts: MuxOptions) std.mem.Allocator.Error!Mux {
        const n: usize = @max(opts.max_conns, 1);
        const conns = try gpa.alloc(Conn, n);
        errdefer gpa.free(conns);
        @memset(conns, .{});
        const pfds = try gpa.alloc(linux.pollfd, n + 1);
        return .{ .server = server, .gpa = gpa, .opts = opts, .conns = conns, .pfds = pfds };
    }

    /// Close every connection still open and free the tables. The `Server` stays the caller's.
    pub fn deinit(self: *Mux) void {
        for (self.conns) |*c| if (c.fd >= 0) self.drop(c);
        self.gpa.free(self.conns);
        self.gpa.free(self.pfds);
        self.* = undefined;
    }

    fn drop(self: *Mux, c: *Conn) void {
        closeFd(c.fd);
        c.dec.deinit(self.gpa);
        if (c.out.len != 0) self.gpa.free(c.out);
        c.* = .{};
        self.open -= 1;
    }

    /// One round: wait up to `poll_ms` (-1 = until something happens; shortened to the nearest
    /// connection deadline) for readiness, accept a pending client when a slot is free, read what
    /// arrived, run `dispatch` for every connection whose request is complete, write replies as far
    /// as the sockets take them, and close the expired. Returns the number of requests dispatched.
    ///
    /// `dispatch(ctx, req, scratch) ![]const u8` is `Server.handleOne`'s callback; `scratch` is
    /// `arena.allocator()` and the arena is reset after each request once the reply is copied. An
    /// error from `dispatch` closes that one connection (no reply, counted in `failed`); it does
    /// not stop the loop.
    pub fn step(
        self: *Mux,
        ctx: anytype,
        comptime dispatch: fn (@TypeOf(ctx), []const u8, std.mem.Allocator) anyerror![]const u8,
        arena: *std.heap.ArenaAllocator,
        poll_ms: i32,
    ) StepError!usize {
        // 1. the poll set: slot 0 is the listen socket, switched off while every slot is taken.
        self.pfds[0] = .{ .fd = if (self.open < self.conns.len) self.server.listen_fd else -1, .events = linux.POLL.IN, .revents = 0 };
        var wait_ms = poll_ms;
        for (self.conns, 0..) |*c, i| {
            self.pfds[i + 1] = .{ .fd = c.fd, .events = if (c.writing) linux.POLL.OUT else linux.POLL.IN, .revents = 0 };
            if (c.fd >= 0 and c.deadline.end_ns != null) {
                const left = c.deadline.pollMs();
                if (wait_ms < 0 or left < wait_ms) wait_ms = left;
            }
        }
        const rc = linux.poll(self.pfds.ptr, @intCast(self.pfds.len), wait_ms);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => return 0,
            else => return error.PollFailed,
        }

        // 2. accept (one per round; the listen socket stays readable while more wait).
        if (self.pfds[0].revents & linux.POLL.IN != 0) try self.acceptOneNonBlocking();

        // 3. service ready connections.
        var dispatched: usize = 0;
        for (self.conns, 0..) |*c, i| {
            if (c.fd < 0) continue;
            const re = self.pfds[i + 1].revents;
            if (re == 0) continue;
            if (c.writing) {
                self.flushReply(c);
            } else if (try self.readRequest(c, ctx, dispatch, arena)) dispatched += 1;
        }

        // 4. deadlines.
        for (self.conns) |*c| {
            if (c.fd < 0) continue;
            if (c.deadline.end_ns) |end| if (Deadline.nowNs() >= end) {
                self.timed_out +|= 1;
                self.drop(c);
            };
        }
        return dispatched;
    }

    fn acceptOneNonBlocking(self: *Mux) StepError!void {
        const rc = linux.accept4(self.server.listen_fd, null, null, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN, .CONNABORTED => return,
            // EMFILE/ENFILE/ENOBUFS/ENOMEM: no descriptor to give; the client waits in the backlog.
            else => return,
        }
        const fd: Fd = @intCast(rc);
        if (!self.server.admit(fd)) return;
        for (self.conns) |*c| {
            if (c.fd >= 0) continue;
            c.* = .{ .fd = fd, .deadline = Deadline.after(self.opts.timeout_ms), .dec = framing.Decoder.init(self.opts.limits) };
            self.open += 1;
            return;
        }
        closeFd(fd); // unreachable: the listen socket is not polled while full
    }

    /// Read what is there; when a whole frame arrived run `dispatch` and start the reply.
    /// Returns true when a request was dispatched.
    fn readRequest(
        self: *Mux,
        c: *Conn,
        ctx: anytype,
        comptime dispatch: fn (@TypeOf(ctx), []const u8, std.mem.Allocator) anyerror![]const u8,
        arena: *std.heap.ArenaAllocator,
    ) StepError!bool {
        var buf: [io_buf_size]u8 = undefined;
        while (true) {
            const rc = linux.read(c.fd, &buf, buf.len);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                .AGAIN => return false,
                else => {
                    self.failed +|= 1;
                    self.drop(c);
                    return false;
                },
            }
            if (rc == 0) { // EOF before a whole frame
                self.failed +|= 1;
                self.drop(c);
                return false;
            }
            c.dec.feed(self.gpa, buf[0..rc]) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.NotDrained => {
                    self.failed +|= 1;
                    self.drop(c);
                    return false;
                },
            };
            const frame = c.dec.next() catch {
                self.failed +|= 1; // oversize or bad length, refused before the body arrived
                self.drop(c);
                return false;
            } orelse continue;
            defer _ = arena.reset(.retain_capacity);
            const reply = dispatch(ctx, frame, arena.allocator()) catch {
                self.failed +|= 1;
                self.drop(c);
                return true;
            };
            var aw: std.Io.Writer.Allocating = .init(self.gpa);
            errdefer aw.deinit();
            framing.writeFrame(&aw.writer, reply, self.opts.limits) catch |e| switch (e) {
                error.WriteFailed => return error.OutOfMemory,
                else => { // reply over the frame cap: nothing to send
                    aw.deinit();
                    self.failed +|= 1;
                    self.drop(c);
                    return true;
                },
            };
            c.out = aw.toOwnedSlice() catch return error.OutOfMemory;
            c.out_off = 0;
            c.writing = true;
            self.flushReply(c);
            return true;
        }
    }

    /// Write as much of the reply as the socket takes; close when it is all out.
    fn flushReply(self: *Mux, c: *Conn) void {
        while (c.out_off < c.out.len) {
            // MSG_NOSIGNAL: a peer that closed without reading its reply is EPIPE (counted, dropped), not a SIGPIPE
            // that ends the server.
            const rc = linux.sendto(c.fd, c.out[c.out_off..].ptr, c.out.len - c.out_off, linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => c.out_off += rc,
                .INTR => continue,
                .AGAIN => return, // wait for POLLOUT
                else => {
                    self.failed +|= 1;
                    self.drop(c);
                    return;
                },
            }
        }
        self.served +|= 1;
        self.drop(c);
    }
};

// ── client ──────────────────────────────────────────────────────────────────

/// Stateless request client: each `request` is one `connect → write → read →
/// close` round-trip. There is no persistent/multiplexed connection.
pub const Client = struct {
    /// Send one framed `req` to the server at `path` and return the framed
    /// reply written into `reply_buf` (a sub-slice of it). Fails cleanly with
    /// `error.FrameTooLarge` if the reply exceeds `limits.max_frame` or
    /// `reply_buf`.
    pub fn request(
        path: [:0]const u8,
        req: []const u8,
        reply_buf: []u8,
        limits: framing.Limits,
    ) ![]u8 {
        return requestWithOptions(path, req, reply_buf, limits, .{});
    }

    /// `request` with `Options`: with `timeout_ms` set, a silent or stalled
    /// server makes this return `error.Timeout` once the budget (write of the
    /// request + read of the reply, one deadline from the moment the
    /// connection exists) is spent. `connect` on a unix socket does not wait
    /// for the peer to `accept` while the backlog has room, so it is not timed.
    pub fn requestWithOptions(
        path: [:0]const u8,
        req: []const u8,
        reply_buf: []u8,
        limits: framing.Limits,
        opts: Options,
    ) ![]u8 {
        const fd = try connectUnix(path);
        defer closeFd(fd);
        const deadline = Deadline.after(opts.timeout_ms);

        var wbuf: [io_buf_size]u8 = undefined;
        var fw = FdWriter.init(fd, &wbuf);
        fw.deadline = deadline;
        framing.writeFrame(&fw.interface, req, limits) catch |e|
            return if (fw.timed_out) error.Timeout else e;
        fw.interface.flush() catch |e|
            return if (fw.timed_out) error.Timeout else e;

        var rbuf: [io_buf_size]u8 = undefined;
        var fr = FdReader.init(fd, &rbuf);
        fr.deadline = deadline;
        return framing.readFrame(&fr.interface, reply_buf, limits) catch |e|
            return if (fr.timed_out) error.Timeout else e;
    }
};

// ── in-memory scratch bus (transport-independent) ────────────────────────────

/// A capped in-memory string→bytes KV scratch bus. Keys and values are owned
/// (duped on `set`, freed on overwrite/evict/clear/deinit). Not synchronized —
/// this is the single-owner state: touch it from one thread only. Inserting a
/// new key when full evicts an arbitrary existing entry (`max_keys` cap).
pub fn Bus(comptime max_keys: usize) type {
    if (max_keys == 0) @compileError("Bus(max_keys): max_keys must be > 0");
    return struct {
        const Self = @This();

        map: std.StringHashMapUnmanaged([]u8) = .empty,
        gpa: std.mem.Allocator,
        /// Monotonic counter bumped on every mutation (set/clear); lets pollers
        /// detect change without diffing. Subscribers poll this — there is no
        /// server push (see DEFER in README).
        version: u64 = 0,

        pub fn init(gpa: std.mem.Allocator) Self {
            return .{ .gpa = gpa };
        }

        pub fn deinit(self: *Self) void {
            self.freeAll();
            self.map.deinit(self.gpa);
        }

        fn freeAll(self: *Self) void {
            var it = self.map.iterator();
            while (it.next()) |e| {
                self.gpa.free(e.key_ptr.*);
                self.gpa.free(e.value_ptr.*);
            }
        }

        fn evictOne(self: *Self) void {
            var it = self.map.iterator();
            if (it.next()) |e| {
                const k = e.key_ptr.*;
                const v = e.value_ptr.*;
                _ = self.map.remove(k);
                self.gpa.free(k);
                self.gpa.free(v);
            }
        }

        /// Set `key` to a copy of `value`. Overwrites in place if present;
        /// otherwise inserts, evicting an arbitrary entry first if at capacity.
        pub fn set(self: *Self, key: []const u8, value: []const u8) std.mem.Allocator.Error!void {
            if (self.map.getPtr(key)) |vp| {
                const dup = try self.gpa.dupe(u8, value);
                self.gpa.free(vp.*);
                vp.* = dup;
                self.version += 1;
                return;
            }
            if (self.map.count() >= max_keys) self.evictOne();
            const kdup = try self.gpa.dupe(u8, key);
            errdefer self.gpa.free(kdup);
            const vdup = try self.gpa.dupe(u8, value);
            errdefer self.gpa.free(vdup);
            try self.map.put(self.gpa, kdup, vdup);
            self.version += 1;
        }

        /// Borrow the current value for `key` (valid until the next mutation).
        pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
            return self.map.get(key);
        }

        /// Fill `out` with the current keys (borrowed, valid until the next
        /// mutation) and return the populated sub-slice. Size `out` to
        /// `max_keys` to guarantee it holds every key.
        pub fn list(self: *const Self, out: [][]const u8) [][]const u8 {
            var n: usize = 0;
            var it = self.map.iterator();
            while (it.next()) |e| {
                if (n >= out.len) break;
                out[n] = e.key_ptr.*;
                n += 1;
            }
            return out[0..n];
        }

        /// Number of keys currently stored.
        pub fn count(self: *const Self) usize {
            return self.map.count();
        }

        /// Drop every entry (bumps `version`), retaining map capacity.
        pub fn clear(self: *Self) void {
            self.freeAll();
            self.map.clearRetainingCapacity();
            self.version += 1;
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// `readVec` for a reader with only `stream` behind it. Zig 0.17's
/// `defaultReadVec` streams straight into the caller's slice whenever that
/// slice is at least the buffer's free tail, and nothing moves the unread
/// octets back to the front: once the buffer had been filled to its end,
/// every small `readSlice*` became its own `stream` call. Rebasing first
/// leaves the whole buffer free, so a small read refills it.
fn refillReadVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
    const live = r.end - r.seek;
    @memmove(r.buffer[0..live], r.buffer[r.seek..r.end]);
    r.seek = 0;
    r.end = live;
    return std.Io.Reader.defaultReadVec(r, data);
}

test "Bus: set/get/list + eviction at max_keys (no transport)" {
    var bus = Bus(3).init(testing.allocator);
    defer bus.deinit();

    try testing.expectEqual(@as(usize, 0), bus.count());
    try testing.expect(bus.get("nope") == null);

    // fresh inserts (not just overwrites) must also bump version
    const v_init = bus.version;
    try bus.set("a", "1");
    try bus.set("b", "2");
    try bus.set("c", "3");
    try testing.expect(bus.version > v_init);
    try testing.expectEqual(@as(usize, 3), bus.count());
    try testing.expectEqualStrings("1", bus.get("a").?);
    try testing.expectEqualStrings("3", bus.get("c").?);

    // overwrite in place — count unchanged, value replaced, version bumps
    const v_before = bus.version;
    try bus.set("a", "111");
    try testing.expectEqual(@as(usize, 3), bus.count());
    try testing.expectEqualStrings("111", bus.get("a").?);
    try testing.expect(bus.version > v_before);

    // list returns exactly the live keys
    var keybuf: [3][]const u8 = undefined;
    const keys = bus.list(&keybuf);
    try testing.expectEqual(@as(usize, 3), keys.len);

    // inserting a 4th key evicts one → count stays at the cap; the
    // eviction-insert path must also bump version
    const v_before_evict = bus.version;
    try bus.set("d", "4");
    try testing.expect(bus.version > v_before_evict);
    try testing.expectEqual(@as(usize, 3), bus.count());
    try testing.expectEqualStrings("4", bus.get("d").?);

    // clear drops everything
    bus.clear();
    try testing.expectEqual(@as(usize, 0), bus.count());
    try testing.expect(bus.get("d") == null);
}

test "unixAddr: overlong path is truncated to 107 bytes, leaving path[107] as NUL" {
    var long_path: [200:0]u8 = undefined;
    @memset(&long_path, 'x');
    const addr = unixAddr(&long_path);
    try testing.expectEqual(@as(u8, 'x'), addr.path[106]);
    try testing.expectEqual(@as(u8, 0), addr.path[107]);
}

test "Bus: list into an undersized buffer is truncated, never overflows" {
    var bus = Bus(8).init(testing.allocator);
    defer bus.deinit();
    try bus.set("x", "1");
    try bus.set("y", "2");
    try bus.set("z", "3");
    var small: [2][]const u8 = undefined;
    const got = bus.list(&small);
    try testing.expectEqual(@as(usize, 2), got.len);
}

// A unique per-test socket path (pid + counter keep it under the 107-byte cap).
var path_counter: u32 = 0;
fn testSocketPath(buf: []u8) [:0]u8 {
    path_counter += 1;
    return std.mem.printSentinel(buf, "/tmp/ipcbus-t-{d}-{d}.sock", .{ linux.getpid(), path_counter }, 0) catch unreachable;
}

// A trivial echo: the reply is a copy of the request. Domain-free stand-in for
// a real caller-supplied dispatch — proves the module bakes in no commands.
fn echoDispatch(_: void, req: []const u8, gpa: std.mem.Allocator) anyerror![]const u8 {
    return gpa.dupe(u8, req);
}

fn echoServerLoop(srv: *Server, iterations: usize) void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator); // global-alloc-ok: test-only echo-server thread body (std.Thread.spawn target below), not the published module; no caller-supplied allocator reaches a spawned thread
    defer arena.deinit();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const conn = srv.acceptOne() catch return;
        // Swallow per-connection errors (e.g. a garbage frame): a single bad
        // client must never take the server down or hang the loop.
        Server.handleOne(conn, {}, echoDispatch, arena.allocator(), .{}) catch {};
        _ = arena.reset(.retain_capacity);
    }
}

test "Server+Client: N framed round-trips through a trivial echo dispatch" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);

    var srv = try Server.listen(path);
    defer srv.deinit();

    const n_rounds = 5;
    // n_rounds echo requests + 1 garbage connection handled by the server.
    const th = try std.Thread.spawn(.{}, echoServerLoop, .{ &srv, n_rounds + 1 });
    defer th.join();

    // Happy path: varied payloads, including empty and larger-than-buffer.
    const big = strRepeat("x", io_buf_size + 123);
    const msgs = [_][]const u8{ "ping", "", "hello world", "{\"cmd\":\"get\"}", big };
    var reply_buf: [io_buf_size * 2]u8 = undefined;
    for (msgs) |m| {
        const reply = try Client.request(path, m, &reply_buf, .{});
        try testing.expectEqualStrings(m, reply);
    }

    // Garbage/oversize frame: announce a length past the cap. The server must
    // reject it (length checked before body) and stay alive — proven by the
    // loop reaching its iteration count and the thread joining cleanly.
    const fd = try connectUnix(path);
    defer closeFd(fd);
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, 0xFFFF_FFFF, .little); // > default 1 MiB cap
    try writeAllFd(fd, &hdr);
    // no body sent, connection then closed via defer — server must not hang
}

test "framing bridge: oversize header errors cleanly over a socketpair (no hang)" {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    // A header claiming more than max_frame, with NO body following.
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, 2_000_000, .little); // > 1 MiB default
    try writeAllFd(fds[0], &hdr);

    var rbuf: [io_buf_size]u8 = undefined;
    var fr = FdReader.init(fds[1], &rbuf);
    var payload_buf: [64]u8 = undefined;
    // readFrame checks the length cap before reading the body → returns at once.
    try testing.expectError(error.FrameTooLarge, framing.readFrame(&fr.interface, &payload_buf, .{}));
}

test "framing bridge: truncated body (peer closed) errors, does not hang" {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    defer closeFd(fds[1]);

    // Announce a 10-byte payload but send only 3, then close the write end.
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, 10, .little);
    try writeAllFd(fds[0], &hdr);
    try writeAllFd(fds[0], "abc");
    closeFd(fds[0]); // EOF for the reader

    var rbuf: [io_buf_size]u8 = undefined;
    var fr = FdReader.init(fds[1], &rbuf);
    var payload_buf: [64]u8 = undefined;
    try testing.expectError(error.EndOfStream, framing.readFrame(&fr.interface, &payload_buf, .{}));
}

fn isCloexec(fd: Fd) !bool {
    const rc = linux.fcntl(fd, linux.F.GETFD, 0);
    if (linux.errno(rc) != .SUCCESS) return error.BadFd;
    return rc & linux.FD_CLOEXEC != 0;
}

test "listen, connect and accept fds are all CLOEXEC" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    try testing.expect(try isCloexec(srv.listen_fd));

    const c = try connectUnix(path); // queued in the backlog; accept below
    defer closeFd(c);
    try testing.expect(try isCloexec(c));
    const a = try srv.acceptOne();
    defer closeFd(a);
    try testing.expect(try isCloexec(a));
}

test "Server.listen replaces a stale socket file; deinit removes its own" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    // A previous owner that died without cleaning up: its path is still bound.
    const stale = try listenUnix(path);
    closeFd(stale);

    var srv = try Server.listen(path);
    try testing.expect(linux.errno(linux.access(path.ptr, linux.F_OK)) == .SUCCESS);
    srv.deinit();
    try testing.expect(linux.errno(linux.access(path.ptr, linux.F_OK)) == .NOENT);
}

test "writeAllFd / readExact move every byte, one-byte messages included, and readExact reports EOF" {
    // Non-blocking, so a byte that was never written fails the read instead of
    // hanging it.
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[1]);

    try writeAllFd(fds[0], "x");
    try writeAllFd(fds[0], "yz");
    var got: [3]u8 = undefined;
    try readExact(fds[1], got[0..1]);
    try readExact(fds[1], got[1..3]);
    try testing.expectEqualStrings("xyz", &got);

    try writeAllFd(fds[0], "q");
    closeFd(fds[0]);
    var two: [2]u8 = undefined;
    try testing.expectError(error.EndOfStream, readExact(fds[1], &two));
}

test "FdWriter.drain writes every slice and the splatted pattern, and reports the count" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[1]);

    // No buffer: every write goes straight to `drain`.
    var fw = FdWriter.init(fds[0], &.{});
    const n = try fw.interface.writeSplat(&.{ "ab", "c" }, 3);
    try testing.expectEqual(@as(usize, 5), n);
    closeFd(fds[0]);

    var got: [8]u8 = undefined;
    var len: usize = 0;
    while (len < got.len) {
        const rc = linux.read(fds[1], got[len..].ptr, got.len - len);
        try testing.expect(linux.errno(rc) == .SUCCESS);
        if (rc == 0) break;
        len += rc;
    }
    try testing.expectEqualStrings("abccc", got[0..len]);
}

test "Client.requestWithOptions: a silent peer times out within a bound" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path); // listens, never accepts/replies
    defer srv.deinit();

    var reply: [16]u8 = undefined;
    const t0 = Deadline.nowNs();
    try testing.expectError(error.Timeout, Client.requestWithOptions(path, "ping", &reply, .{}, .{ .timeout_ms = 100 }));
    const el = Deadline.nowNs() - t0;
    try testing.expect(el >= 90_000_000);
    try testing.expect(el < 3_000_000_000);
}

test "Client.requestWithOptions: a generous timeout still completes a round-trip" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    const th = try std.Thread.spawn(.{}, echoServerLoop, .{ &srv, 1 });
    defer th.join();
    var reply: [16]u8 = undefined;
    const got = try Client.requestWithOptions(path, "pong", &reply, .{}, .{ .timeout_ms = 5000 });
    try testing.expectEqualStrings("pong", got);
}

test "Server.handleOneWithOptions: a peer that never writes times out and the fd is closed" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[0]);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const t0 = Deadline.nowNs();
    try testing.expectError(error.Timeout, Server.handleOneWithOptions(fds[1], {}, echoDispatch, arena.allocator(), .{}, .{ .timeout_ms = 100 }));
    const el = Deadline.nowNs() - t0;
    try testing.expect(el >= 90_000_000);
    try testing.expect(el < 3_000_000_000);
    try testing.expectError(error.BadFd, isCloexec(fds[1]));
}

test "Server.handleOneWithOptions: a peer that sends a partial frame times out; a peer that never reads the reply times out" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[0]);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, 10, .little);
    try writeAllFd(fds[0], &hdr);
    try writeAllFd(fds[0], "abc");
    try testing.expectError(error.Timeout, Server.handleOneWithOptions(fds[1], {}, echoDispatch, arena.allocator(), .{}, .{ .timeout_ms = 100 }));

    // Reply write: the request is complete but the reply (bigger than the
    // socket buffer) is never drained by the peer.
    var fds2: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds2)) == .SUCCESS);
    defer closeFd(fds2[0]);
    const big = try testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer testing.allocator.free(big);
    @memset(big, 'z');
    const lim: framing.Limits = .{ .max_frame = 8 * 1024 * 1024 };
    var wbuf: [64]u8 = undefined;
    var fw = FdWriter.init(fds2[0], &wbuf);
    // Writer side only sends a small request; dispatch returns the big blob.
    try framing.writeFrame(&fw.interface, "x", lim);
    try fw.interface.flush();
    const Big = struct {
        fn d(b: []const u8, _: []const u8, _: std.mem.Allocator) anyerror![]const u8 {
            return b;
        }
    };
    try testing.expectError(error.Timeout, Server.handleOneWithOptions(fds2[1], @as([]const u8, big), Big.d, arena.allocator(), lim, .{ .timeout_ms = 150 }));
}

test "peerCred: socketpair and a real connection report our own pid/uid/gid" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);
    const me = linux.getpid();
    const pc = try peerCred(fds[0]);
    try testing.expectEqual(me, pc.pid);
    try testing.expectEqual(linux.getuid(), pc.uid);
    try testing.expectEqual(linux.getgid(), pc.gid);

    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    const c = try connectUnix(path);
    defer closeFd(c);
    const a = try srv.acceptOne();
    defer closeFd(a);
    const pa = try peerCred(a);
    try testing.expectEqual(me, pa.pid);
    try testing.expectEqual(linux.getuid(), pa.uid);
    try testing.expectEqual(linux.getgid(), pa.gid);
}

test "peerCred: a non-socket fd is an error, not UB" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) == .SUCCESS);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);
    try testing.expectError(error.PeerCredFailed, peerCred(fds[0]));
    try testing.expectError(error.PeerCredFailed, peerCred(-1));
}

test "handleOne closes the connection fd it was given" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[0]);

    var wbuf: [64]u8 = undefined;
    var fw = FdWriter.init(fds[0], &wbuf);
    try framing.writeFrame(&fw.interface, "hi", .{});
    try fw.interface.flush();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try Server.handleOne(fds[1], {}, echoDispatch, arena.allocator(), .{});
    try testing.expectError(error.BadFd, isCloexec(fds[1]));

    var rbuf: [64]u8 = undefined;
    var fr = FdReader.init(fds[0], &rbuf);
    var reply: [8]u8 = undefined;
    try testing.expectEqualStrings("hi", try framing.readFrame(&fr.interface, &reply, .{}));
}

test "Bus: clear bumps version" {
    var bus = Bus(2).init(testing.allocator);
    defer bus.deinit();
    try bus.set("a", "1");
    const v = bus.version;
    bus.clear();
    try testing.expect(bus.version > v);
}

fn setNewKey(gpa: std.mem.Allocator) !void {
    var bus = Bus(2).init(gpa);
    defer bus.deinit();
    try bus.set("key", "value");
}

test "Bus.set leaks nothing when any of its allocations fails" {
    try testing.checkAllAllocationFailures(testing.allocator, setNewKey, .{});
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

// Guards the std 0.17 `defaultReadVec` direct read: a reader without `.readVec = refillReadVec` fails this.
test "FdReader: small reads after the buffer filled are served from a refilled buffer" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);
    var plain: [6000]u8 = undefined;
    for (&plain, 0..) |*b, i| b.* = @truncate(i *% 7 +% i / 13);
    try writeAllFd(fds[0], &plain);

    var buf: [64]u8 = undefined;
    var fr = FdReader.init(fds[1], &buf);
    var got: [8]u8 = undefined;
    var off: usize = 0;
    var reads: usize = 0;
    var buffered: usize = 0;
    while (off < plain.len) : (off += got.len) {
        try fr.interface.readSliceAll(&got);
        try testing.expectEqualSlices(u8, plain[off..][0..got.len], &got);
        reads += 1;
        if (fr.interface.bufferedLen() > 0) buffered += 1;
    }
    try testing.expect(buffered * 2 >= reads);
}

test "PeerPolicy.allows: same_uid, uids and any decide on the uid alone" {
    const cred = PeerCred{ .pid = 1, .uid = 1000, .gid = 7 };
    try testing.expect((PeerPolicy{ .same_uid = {} }).allows(1000, cred));
    try testing.expect(!(PeerPolicy{ .same_uid = {} }).allows(1001, cred));
    try testing.expect(!(PeerPolicy{ .same_uid = {} }).allows(0, cred)); // root server does not admit others
    const list = [_]u32{ 5, 1000 };
    try testing.expect((PeerPolicy{ .uids = &list }).allows(99, cred)); // own uid is not implied, listed one matches
    try testing.expect(!(PeerPolicy{ .uids = &[_]u32{5} }).allows(1000, cred)); // own uid not implied
    try testing.expect(!(PeerPolicy{ .uids = &.{} }).allows(1000, cred));
    try testing.expect((PeerPolicy{ .any = {} }).allows(99, cred));
}

test "Server.listen defaults to same_uid: a same-uid peer is accepted" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    try testing.expect(srv.policy == .same_uid);
    try testing.expectEqual(linux.geteuid(), srv.own_uid);
    const c = try connectUnix(path);
    defer closeFd(c);
    const a = try srv.acceptOne(); // queued; does not block
    defer closeFd(a);
    try testing.expectEqual(@as(u64, 0), srv.refused);
}

test "Server.admit: a peer outside the policy is closed and counted (injected own uid)" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    const c = try connectUnix(path);
    defer closeFd(c);
    const a = try srv.acceptRaw();
    srv.own_uid = linux.geteuid() +% 1; // pretend the server runs as someone else
    try testing.expect(!srv.admit(a));
    try testing.expectEqual(@as(u64, 1), srv.refused);
    // the refused connection is closed: the client sees end of stream
    var b: [1]u8 = undefined;
    try testing.expectError(error.EndOfStream, readExact(c, &b));

    // an explicit allowlist: refuses our uid when absent, admits it when listed
    const c2 = try connectUnix(path);
    defer closeFd(c2);
    const a2 = try srv.acceptRaw();
    srv.policy = .{ .uids = &[_]u32{linux.geteuid() +% 1} };
    try testing.expect(!srv.admit(a2));
    try testing.expectEqual(@as(u64, 2), srv.refused);
    const c3 = try connectUnix(path);
    defer closeFd(c3);
    const a3 = try srv.acceptRaw();
    defer closeFd(a3);
    srv.policy = .{ .uids = &[_]u32{ 1, linux.geteuid() } };
    try testing.expect(srv.admit(a3));
    try testing.expectEqual(@as(u64, 2), srv.refused);
}

test "Server.admit: a non-socket fd (credentials unreadable) is refused" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) == .SUCCESS);
    defer closeFd(fds[1]);
    try testing.expect(!srv.admit(fds[0])); // closes fds[0]
    try testing.expectEqual(linux.E.BADF, linux.errno(linux.fcntl(fds[0], linux.F.GETFD, 0)));
    try testing.expectEqual(@as(u64, 1), srv.refused);
}

test "Server.listenWithPolicy(.any): admits regardless of own uid, no credential read" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listenWithPolicy(path, .any);
    defer srv.deinit();
    srv.own_uid = linux.geteuid() +% 1;
    const c = try connectUnix(path);
    defer closeFd(c);
    const a = try srv.acceptOne();
    defer closeFd(a);
    try testing.expectEqual(@as(u64, 0), srv.refused);
}

test "Server.acceptOne: an allowlist that names our uid admits us" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    const me = linux.geteuid();
    var srv = try Server.listenWithPolicy(path, .{ .uids = &[_]u32{me} });
    defer srv.deinit();
    const c = try connectUnix(path);
    defer closeFd(c);
    const a = try srv.acceptOne();
    defer closeFd(a);
    try testing.expectEqual(me, (try peerCred(a)).uid);
}

// ── mutation 2026-11-25: whole-module run, tests for the survivors ─────────────

fn patternByte(i: usize) u8 {
    return @truncate(i *% 7 +% i / 13);
}

fn sleepMs(ms: u32) void {
    const ts: linux.timespec = .{ .sec = 0, .nsec = @as(isize, ms) * 1_000_000 };
    _ = linux.nanosleep(&ts, null);
}

const DrainCtx = struct { fd: Fd, n: usize, ok: bool = false };

fn drainVerify(c: *DrainCtx) void {
    var buf: [4096]u8 = undefined;
    var off: usize = 0;
    while (off < c.n) {
        const want = @min(buf.len, c.n - off);
        readExact(c.fd, buf[0..want]) catch return;
        for (buf[0..want], 0..) |b, i| if (b != patternByte(off + i)) return;
        off += want;
    }
    c.ok = true;
}

test "mutation 2026-11-25: writeAllFd continues from the right offset across short writes, blocking and deadline paths" {
    const n = 2 * 1024 * 1024;
    const data = try testing.allocator.alloc(u8, n);
    defer testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = patternByte(i);
    inline for (.{ false, true }) |with_deadline| {
        var fds: [2]i32 = undefined;
        try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
        var ctx = DrainCtx{ .fd = fds[1], .n = n };
        const th = try std.Thread.spawn(.{}, drainVerify, .{&ctx});
        if (with_deadline) try writeAllFdDeadline(fds[0], data, Deadline.after(20_000)) else try writeAllFd(fds[0], data);
        th.join();
        closeFd(fds[0]);
        closeFd(fds[1]);
        try testing.expect(ctx.ok);
    }
}

test "mutation 2026-11-25: the Deadline clock counts nanoseconds and pollMs clamps to i32" {
    const t0 = Deadline.nowNs();
    const ts: linux.timespec = .{ .sec = 1, .nsec = 200_000_000 };
    _ = linux.nanosleep(&ts, null);
    const dt = Deadline.nowNs() - t0;
    try testing.expect(dt >= 1_150_000_000 and dt < 4_000_000_000);
    const d = Deadline.after(std.math.maxInt(u32));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), d.pollMs());
}

fn nextFd() Fd {
    const s = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    const fd: Fd = @intCast(s);
    closeFd(fd);
    return fd;
}

test "mutation 2026-11-25: connectUnix and listenUnix report their failures and leak no descriptor" {
    const before = nextFd();
    try testing.expectError(error.ConnectFailed, connectUnix("/nonexistent-ipcbus-dir/x.sock"));
    try testing.expectEqual(before, nextFd());
    try testing.expectError(error.BindFailed, listenUnix("/nonexistent-ipcbus-dir/x.sock"));
    try testing.expectEqual(before, nextFd());
}

test "mutation 2026-11-25: Server.deinit closes the listen socket" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    const lfd = srv.listen_fd;
    srv.deinit();
    try testing.expectEqual(linux.E.BADF, linux.errno(linux.fcntl(lfd, linux.F.GETFD, 0)));
}

test "mutation 2026-11-25: Server.admit with .any admits a descriptor that has no credentials" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listenWithPolicy(path, .any);
    defer srv.deinit();
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) == .SUCCESS);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);
    try testing.expect(srv.admit(fds[0]));
    try testing.expectEqual(@as(u64, 0), srv.refused);
}

const AcceptCtx = struct { srv: *Server, fd: ?Fd = null };

fn acceptThread(c: *AcceptCtx) void {
    c.fd = c.srv.acceptOne() catch null;
}

test "mutation 2026-11-25: acceptOne keeps waiting after it refused a peer and returns the next admitted one" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    const real = srv.own_uid;
    srv.own_uid = real +% 1; // everybody is refused for now
    var ctx = AcceptCtx{ .srv = &srv };
    const th = try std.Thread.spawn(.{}, acceptThread, .{&ctx});
    const a = try connectUnix(path);
    defer closeFd(a);
    var i: usize = 0;
    while (@atomicLoad(u64, &srv.refused, .acquire) == 0 and i < 500) : (i += 1) sleepMs(10);
    try testing.expectEqual(@as(u64, 1), @atomicLoad(u64, &srv.refused, .acquire));
    @atomicStore(u32, &srv.own_uid, real, .release);
    const b = try connectUnix(path);
    defer closeFd(b);
    th.join();
    const got = ctx.fd orelse return error.TestUnexpectedResult;
    defer closeFd(got);
    try writeAllFd(b, "B");
    var one: [1]u8 = undefined;
    try readExact(got, &one);
    try testing.expectEqual(@as(u8, 'B'), one[0]);
}

fn staticDispatch(_: void, _: []const u8, _: std.mem.Allocator) anyerror![]const u8 {
    return "ok";
}

fn fillDispatch(fd: Fd, _: []const u8, _: std.mem.Allocator) anyerror![]const u8 {
    // Fill the connection's send queue so that the reply cannot be flushed.
    const junk: [4096]u8 = @splat(0xAA);
    while (true) {
        const rc = linux.sendto(fd, &junk, junk.len, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(rc) != .SUCCESS) break;
    }
    return "reply";
}

test "mutation 2026-11-25: handleOne frees its request buffer; a reply that cannot be flushed in time is Timeout" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[0]);
    try writeAllFd(fds[0], &.{ 3, 0, 0, 0, 'a', 'b', 'c' });
    try Server.handleOne(fds[1], {}, staticDispatch, testing.allocator, .{});
    var out: [6]u8 = undefined;
    try readExact(fds[0], &out);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0, 'o', 'k' }, &out);

    var fds2: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds2)) == .SUCCESS);
    defer closeFd(fds2[0]);
    try writeAllFd(fds2[0], &.{ 3, 0, 0, 0, 'a', 'b', 'c' });
    try testing.expectError(error.Timeout, Server.handleOneWithOptions(fds2[1], fds2[1], fillDispatch, testing.allocator, .{}, .{ .timeout_ms = 150 }));
}

test "mutation 2026-11-25: Client.requestWithOptions: a request the peer never reads times out on the write" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path); // listens, never accepts or reads
    defer srv.deinit();
    const big = try testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer testing.allocator.free(big);
    @memset(big, 'q');
    var reply: [16]u8 = undefined;
    try testing.expectError(error.Timeout, Client.requestWithOptions(path, big, &reply, .{ .max_frame = 8 * 1024 * 1024 }, .{ .timeout_ms = 200 }));
}

test "mutation 2026-11-25: refillReadVec keeps the unread bytes when it rebases the buffer" {
    var fds: [2]i32 = undefined;
    try testing.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) == .SUCCESS);
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);
    var buf: [16]u8 = undefined;
    var fr = FdReader.init(fds[1], &buf);
    for (buf[0..10], 0..) |*b, i| b.* = @intCast('a' + i);
    fr.interface.seek = 3;
    fr.interface.end = 10;
    try writeAllFd(fds[0], "XYZ");
    var one: [1]u8 = undefined;
    var data = [_][]u8{&one};
    _ = try refillReadVec(&fr.interface, &data);
    try testing.expectEqualStrings("defghijXYZ", fr.interface.buffered());
}

fn allocDispatch(_: void, _: []const u8, a: std.mem.Allocator) anyerror![]const u8 {
    const out = try a.alloc(u8, 8000);
    @memset(out, 'x');
    return out[0..4];
}

fn bigDispatch(_: void, _: []const u8, a: std.mem.Allocator) anyerror![]const u8 {
    const out = try a.alloc(u8, 600 * 1024);
    for (out, 0..) |*b, i| b.* = patternByte(i);
    return out;
}

fn hugeReplyDispatch(_: void, _: []const u8, a: std.mem.Allocator) anyerror![]const u8 {
    const out = try a.alloc(u8, 100);
    @memset(out, 'h');
    return out;
}

/// One client, one tiny request, stepped until `step` reports it dispatched; the reply must
/// already be readable (it is written in the dispatching step). Returns the arena capacity.
fn muxRoundTrip(mux: *Mux, arena: *std.heap.ArenaAllocator, path: [:0]const u8, comptime dispatch: fn (void, []const u8, std.mem.Allocator) anyerror![]const u8) !usize {
    const c = try connectUnix(path);
    defer closeFd(c);
    try writeAllFd(c, &.{ 4, 0, 0, 0, 'p', 'i', 'n', 'g' });
    var dispatched: usize = 0;
    var i: usize = 0;
    while (dispatched == 0 and i < 50) : (i += 1) dispatched += try mux.step({}, dispatch, arena, 50);
    try testing.expectEqual(@as(usize, 1), dispatched);
    var b: [8]u8 = undefined;
    const rc = linux.recvfrom(c, &b, b.len, linux.MSG.DONTWAIT, null, null);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try testing.expectEqual(@as(usize, 8), rc);
    return arena.queryCapacity();
}

test "mutation 2026-11-25: Mux step reports dispatched requests, flushes the reply in that step, resets its arena, sets CLOEXEC on accepted descriptors" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var mux = try Mux.init(testing.allocator, &srv, .{});
    defer mux.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const cap1 = try muxRoundTrip(&mux, &arena, path, allocDispatch);
    _ = try muxRoundTrip(&mux, &arena, path, allocDispatch);
    const cap3 = try muxRoundTrip(&mux, &arena, path, allocDispatch);
    try testing.expectEqual(cap1, cap3);

    // an accepted descriptor is CLOEXEC
    const idle = try connectUnix(path);
    defer closeFd(idle);
    _ = try mux.step({}, allocDispatch, &arena, 50);
    try testing.expectEqual(@as(usize, 1), mux.open);
    try testing.expect(try isCloexec(mux.conns[0].fd));
}

test "mutation 2026-11-25: Mux counts a failing dispatch as dispatched, an oversize reply as failed (no leak), an EOF mid-frame as failed" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var mux = try Mux.init(testing.allocator, &srv, .{ .limits = .{ .max_frame = 16 } });
    defer mux.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // dispatch fails: the step still reports the request, and the connection is closed
    const c1 = try connectUnix(path);
    defer closeFd(c1);
    try writeAllFd(c1, &.{ 4, 0, 0, 0, 'b', 'o', 'o', 'm' });
    var dispatched: usize = 0;
    var i: usize = 0;
    while (dispatched == 0 and i < 50) : (i += 1) dispatched += try mux.step({}, failingDispatch, &arena, 50);
    try testing.expectEqual(@as(usize, 1), dispatched);
    try testing.expectEqual(@as(u64, 1), mux.failed);

    // the reply is over the frame cap: counted, closed, nothing leaked (testing allocator)
    const c2 = try connectUnix(path);
    defer closeFd(c2);
    try writeAllFd(c2, &.{ 4, 0, 0, 0, 'p', 'i', 'n', 'g' });
    i = 0;
    while (mux.failed < 2 and i < 50) : (i += 1) _ = try mux.step({}, hugeReplyDispatch, &arena, 50);
    try testing.expectEqual(@as(u64, 2), mux.failed);
    try testing.expectEqual(@as(usize, 0), mux.open);

    // the client closes in the middle of a frame
    const c3 = try connectUnix(path);
    try writeAllFd(c3, &.{ 10, 0, 0, 0, 'a' });
    closeFd(c3);
    i = 0;
    while (mux.failed < 3 and i < 50) : (i += 1) _ = try mux.step({}, hugeReplyDispatch, &arena, 50);
    try testing.expectEqual(@as(u64, 3), mux.failed);
    try testing.expectEqual(@as(usize, 0), mux.open);
}

test "mutation 2026-11-25: Mux closes a timed-out client's socket and wakes at the nearest deadline even with poll_ms = -1; with no deadline step returns after poll_ms" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    {
        var mux = try Mux.init(testing.allocator, &srv, .{ .timeout_ms = 100 });
        defer mux.deinit();
        const stalled = try connectUnix(path);
        defer closeFd(stalled);
        _ = try mux.step({}, echoDispatch, &arena, 50); // accepts it
        try testing.expectEqual(@as(usize, 1), mux.open);
        const t0 = Deadline.nowNs();
        _ = try mux.step({}, echoDispatch, &arena, -1); // must end at the connection's deadline
        try testing.expect(Deadline.nowNs() - t0 < 3_000_000_000);
        try testing.expectEqual(@as(u64, 1), mux.timed_out);
        var b: [1]u8 = undefined;
        const rc = linux.recvfrom(stalled, &b, 1, linux.MSG.DONTWAIT, null, null);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
        try testing.expectEqual(@as(usize, 0), rc); // the server closed its end: EOF, not "would block"
    }
    {
        var mux = try Mux.init(testing.allocator, &srv, .{ .timeout_ms = null });
        defer mux.deinit();
        const idle = try connectUnix(path);
        defer closeFd(idle);
        _ = try mux.step({}, echoDispatch, &arena, 50);
        try testing.expectEqual(@as(usize, 1), mux.open);
        const t0 = Deadline.nowNs();
        _ = try mux.step({}, echoDispatch, &arena, 30); // nothing to do: returns after ~30 ms
        try testing.expect(Deadline.nowNs() - t0 < 3_000_000_000);
    }
}

test "mutation 2026-11-25: Mux with max_conns = 0 still serves one connection" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var mux = try Mux.init(testing.allocator, &srv, .{ .max_conns = 0 });
    defer mux.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    _ = try muxRoundTrip(&mux, &arena, path, allocDispatch);
}

fn drainMux(mux: *Mux, arena: *std.heap.ArenaAllocator, c: Fd, got: []u8) !usize {
    var n: usize = 0;
    var rounds: usize = 0;
    while (n < got.len and rounds < 300) : (rounds += 1) {
        const rc = linux.recvfrom(c, got[n..].ptr, got.len - n, linux.MSG.DONTWAIT, null, null);
        if (linux.errno(rc) == .SUCCESS and rc > 0) n += rc;
        _ = try mux.step({}, bigDispatch, arena, 20);
    }
    return n;
}

test "mutation 2026-11-25: Mux writes a reply larger than the socket buffer across rounds, from the right offset, waiting for POLLOUT" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var mux = try Mux.init(testing.allocator, &srv, .{});
    defer mux.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const c = try connectUnix(path);
    defer closeFd(c);
    try writeAllFd(c, &.{ 4, 0, 0, 0, 'p', 'i', 'n', 'g' });
    var i: usize = 0;
    var dispatched: usize = 0;
    while (dispatched == 0 and i < 50) : (i += 1) dispatched += try mux.step({}, bigDispatch, &arena, 50);
    try testing.expectEqual(@as(usize, 1), dispatched);
    // the client has read nothing: the reply is stuck half-written, the connection still in service
    try testing.expectEqual(@as(usize, 1), mux.open);
    try testing.expectEqual(@as(u64, 0), mux.served);
    const total = 4 + 600 * 1024;
    const got = try testing.allocator.alloc(u8, total);
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, total), try drainMux(&mux, &arena, c, got));
    try testing.expectEqual(@as(u32, 600 * 1024), std.mem.readInt(u32, got[0..4], .little));
    for (got[4..], 0..) |b, k| if (b != patternByte(k)) return error.TestUnexpectedResult;
    i = 0;
    while (mux.served < 1 and i < 20) : (i += 1) _ = try mux.step({}, bigDispatch, &arena, 20);
    try testing.expectEqual(@as(u64, 1), mux.served);

    // a client that goes away before its reply is written: write fails (SIGPIPE ignored for this
    // test), the connection is counted failed and closed
    const ign: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.IGN }, .mask = linux.sigemptyset(), .flags = 0 };
    var old: linux.Sigaction = undefined;
    _ = linux.sigaction(.PIPE, &ign, &old);
    defer _ = linux.sigaction(.PIPE, &old, null);
    const c2 = try connectUnix(path);
    try writeAllFd(c2, &.{ 4, 0, 0, 0, 'p', 'i', 'n', 'g' });
    closeFd(c2);
    i = 0;
    while (mux.failed < 1 and i < 50) : (i += 1) _ = try mux.step({}, bigDispatch, &arena, 50);
    try testing.expectEqual(@as(u64, 1), mux.failed);
    try testing.expectEqual(@as(usize, 0), mux.open);
}

// ── Mux tests ───────────────────────────────────────────────────────────────

fn muxClient(path: [:0]const u8, msg: []const u8, out: *[]u8, buf: []u8, ok: *bool) void {
    out.* = Client.request(path, msg, buf, .{}) catch return;
    ok.* = true;
}

/// Step `mux` until `done` says so or ~5 s pass.
fn muxUntil(mux: *Mux, arena: *std.heap.ArenaAllocator, comptime done: fn (*const Mux) bool) !void {
    var rounds: usize = 0;
    while (!done(mux) and rounds < 100) : (rounds += 1)
        _ = try mux.step({}, echoDispatch, arena, 50);
    try testing.expect(done(mux));
}

fn servedOne(m: *const Mux) bool {
    return m.served >= 1;
}
fn servedTwo(m: *const Mux) bool {
    return m.served >= 2;
}

test "Mux: a stalled client does not block a fast one; the stalled one is closed at its deadline" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var mux = try Mux.init(testing.allocator, &srv, .{ .timeout_ms = 300 });
    defer mux.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // A client that connects and says nothing.
    const stalled = try connectUnix(path);
    defer closeFd(stalled);
    // A half-frame client: the 4-byte prefix announces 10 bytes, 3 arrive.
    const half = try connectUnix(path);
    defer closeFd(half);
    try writeAllFd(half, &.{ 10, 0, 0, 0, 'a', 'b', 'c' });

    var reply_buf: [64]u8 = undefined;
    var reply: []u8 = &.{};
    var ok = false;
    const th = try std.Thread.spawn(.{}, muxClient, .{ path, "ping", &reply, &reply_buf, &ok });
    try muxUntil(&mux, &arena, servedOne);
    th.join();
    try testing.expect(ok);
    try testing.expectEqualStrings("ping", reply);
    // The two silent ones are still in service until their deadline passes.
    try testing.expectEqual(@as(usize, 2), mux.open);
    var rounds: usize = 0;
    while (mux.open != 0 and rounds < 100) : (rounds += 1) _ = try mux.step({}, echoDispatch, &arena, 50);
    try testing.expectEqual(@as(usize, 0), mux.open);
    try testing.expectEqual(@as(u64, 2), mux.timed_out);
    try testing.expectEqual(@as(u64, 1), mux.served);
}

test "Mux: a request dribbled in one byte at a time is served; the reply may exceed a socket buffer" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var mux = try Mux.init(testing.allocator, &srv, .{});
    defer mux.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const fd = try connectUnix(path);
    defer closeFd(fd);
    const payload = "dribble";
    var frame: [4 + payload.len]u8 = undefined;
    std.mem.writeInt(u32, frame[0..4], payload.len, .little);
    @memcpy(frame[4..], payload);
    for (frame) |b| {
        try writeAllFd(fd, &.{b});
        _ = try mux.step({}, echoDispatch, &arena, 20);
    }
    try muxUntil(&mux, &arena, servedOne);
    var out: [4 + payload.len]u8 = undefined;
    try readExact(fd, &out);
    try testing.expectEqualSlices(u8, &frame, &out);

    // A ~600 KiB echo: the non-blocking write must continue across rounds until the client drains it.
    const big = try testing.allocator.alloc(u8, 600 * 1024);
    defer testing.allocator.free(big);
    @memset(big, 'z');
    const rb = try testing.allocator.alloc(u8, 700 * 1024);
    defer testing.allocator.free(rb);
    var reply: []u8 = &.{};
    var ok = false;
    const th = try std.Thread.spawn(.{}, muxClient, .{ path, big, &reply, rb, &ok });
    try muxUntil(&mux, &arena, servedTwo);
    th.join();
    try testing.expect(ok);
    try testing.expectEqual(big.len, reply.len);
}

fn failingDispatch(_: void, req: []const u8, gpa: std.mem.Allocator) anyerror![]const u8 {
    if (std.mem.eql(u8, req, "boom")) return error.Boom;
    return gpa.dupe(u8, req);
}

test "Mux: max_conns bounds the connections in service, the rest wait in the backlog; a failing dispatch closes only its own connection; an oversize frame is refused" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listen(path);
    defer srv.deinit();
    var mux = try Mux.init(testing.allocator, &srv, .{ .max_conns = 2, .timeout_ms = 2000, .limits = .{ .max_frame = 1024 } });
    defer mux.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Two idle clients fill the table; a third connects and must wait.
    const a = try connectUnix(path);
    defer closeFd(a);
    const b = try connectUnix(path);
    defer closeFd(b);
    var i: usize = 0;
    while (mux.open < 2 and i < 20) : (i += 1) _ = try mux.step({}, failingDispatch, &arena, 20);
    try testing.expectEqual(@as(usize, 2), mux.open);
    var reply_buf: [64]u8 = undefined;
    var reply: []u8 = &.{};
    var ok = false;
    const th = try std.Thread.spawn(.{}, muxClient, .{ path, "third", &reply, &reply_buf, &ok });
    for (0..5) |_| _ = try mux.step({}, failingDispatch, &arena, 20);
    try testing.expectEqual(@as(usize, 2), mux.open); // still not accepted
    try testing.expectEqual(@as(u64, 0), mux.served);
    // Free a slot: `a` sends "boom" (dispatch fails, only `a` closes), the third is accepted and served.
    try writeAllFd(a, &.{ 4, 0, 0, 0, 'b', 'o', 'o', 'm' });
    i = 0;
    while (mux.served < 1 and i < 100) : (i += 1) _ = try mux.step({}, failingDispatch, &arena, 50);
    th.join();
    try testing.expect(ok);
    try testing.expectEqualStrings("third", reply);
    try testing.expectEqual(@as(u64, 1), mux.failed);
    // `b` announces more than max_frame: refused before a body arrives.
    try writeAllFd(b, &.{ 0xff, 0xff, 0x00, 0x00 });
    i = 0;
    while (mux.failed < 2 and i < 50) : (i += 1) _ = try mux.step({}, failingDispatch, &arena, 20);
    try testing.expectEqual(@as(u64, 2), mux.failed);
    try testing.expectEqual(@as(usize, 0), mux.open);
}

test "Mux: a refused peer is counted and closed like acceptOne does; deinit closes what is open" {
    var pbuf: [64]u8 = undefined;
    const path = testSocketPath(&pbuf);
    var srv = try Server.listenWithPolicy(path, .{ .uids = &.{} }); // nobody is admitted
    defer srv.deinit();
    var mux = try Mux.init(testing.allocator, &srv, .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const fd = try connectUnix(path);
    defer closeFd(fd);
    var i: usize = 0;
    while (srv.refused == 0 and i < 20) : (i += 1) _ = try mux.step({}, echoDispatch, &arena, 20);
    try testing.expectEqual(@as(u64, 1), srv.refused);
    try testing.expectEqual(@as(usize, 0), mux.open);
    mux.deinit();
}

test "writeAllFd: a peer that closed before reading is WriteFailed, not a SIGPIPE that ends the process" {
    // Zig programs ignore SIGPIPE by default (std.options.keep_sigpipe), so the child restores the default action
    // first: a process that keeps SIGPIPE (or a C host) must not be killed by a peer that hung up.
    const pid = linux.fork();
    try testing.expect(linux.errno(pid) == .SUCCESS);
    if (pid == 0) {
        var act: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.DFL }, .mask = linux.sigemptyset(), .flags = 0 };
        _ = linux.sigaction(linux.SIG.PIPE, &act, null);
        var fds: [2]i32 = undefined;
        if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds)) != .SUCCESS) linux.exit(2);
        _ = linux.close(fds[1]);
        const ok = if (writeAllFd(fds[0], "reply nobody reads")) |_| false else |e| e == error.WriteFailed;
        linux.exit(if (ok) 0 else 1);
    }
    var status: i32 = 0;
    _ = linux.waitpid(@intCast(pid), &status, 0);
    const st: u32 = @bitCast(status);
    try testing.expect(linux.W.IFEXITED(st)); // not killed by SIGPIPE
    try testing.expectEqual(@as(u32, 0), linux.W.EXITSTATUS(st));
}

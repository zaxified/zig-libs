// SPDX-License-Identifier: MIT
//! ipcbus — same-host unix-socket control plane: one owner process serves
//! request/reply over a framed unix socket + a capped in-memory KV bus. Linux.
//!
//! Design constraints (v1):
//!  * **Single owner.** One process owns the listen socket and the `Bus`; the
//!    `Bus` is lock-free and MUST be touched from that one thread/loop only.
//!  * **One connection per request.** Every request is a fresh `connect →
//!    write one frame → read one frame → close`. There is no persistent
//!    multiplexed connection and no server-side concurrency: `acceptOne` +
//!    `handleOne` service exactly one connection at a time.
//!  * **No baked-in dispatch.** `Server.handleOne` takes a caller-supplied
//!    `dispatch` callback `fn(ctx, req_bytes, gpa) !reply_bytes`. All
//!    application command handling lives in the app, never in this module.
//!  * **Framing is delegated.** Every message is a length-prefixed frame via
//!    the `framing` module — this module never re-implements the wire format.

const std = @import("std");
const framing = @import("framing");
const linux = std.os.linux;

pub const meta = .{
    .status = .extract, // seed: poc-wf-analytic/src/main.zig (unix transport + ctlHandleConn + bus_map)
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
    var addr = linux.sockaddr.un{ .family = linux.AF.UNIX, .path = [_]u8{0} ** 108 };
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

/// Write every byte of `bytes` to `fd`, retrying short writes and `EINTR`.
pub fn writeAllFd(fd: Fd, bytes: []const u8) TransportError!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + off, bytes.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.WriteFailed,
        }
        if (rc == 0) return error.WriteFailed;
        off += rc;
    }
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

    pub fn init(fd: Fd, buffer: []u8) FdReader {
        return .{
            .fd = fd,
            .interface = .{
                .vtable = &.{ .stream = stream },
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

    pub fn init(fd: Fd, buffer: []u8) FdWriter {
        return .{
            .fd = fd,
            .interface = .{
                .vtable = &.{ .drain = drain },
                .buffer = buffer,
            },
        };
    }

    fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *FdWriter = @alignCast(@fieldParentPtr("interface", io_w));
        const buffered = io_w.buffered();
        writeAllFd(self.fd, buffered) catch return error.WriteFailed;
        var extra: usize = 0;
        if (data.len > 0) {
            for (data[0 .. data.len - 1]) |bytes| {
                writeAllFd(self.fd, bytes) catch return error.WriteFailed;
                extra += bytes.len;
            }
            const pattern = data[data.len - 1];
            var i: usize = 0;
            while (i < splat) : (i += 1) {
                writeAllFd(self.fd, pattern) catch return error.WriteFailed;
                extra += pattern.len;
            }
        }
        return io_w.consume(buffered.len + extra);
    }
};

// ── server ──────────────────────────────────────────────────────────────────

/// A single-owner request/reply server over a unix socket. The owning thread
/// loops `acceptOne` → `handleOne`; there is no internal concurrency.
pub const Server = struct {
    listen_fd: Fd,
    path: [:0]const u8,

    /// Bind + listen at `path`, unlinking any stale socket left by a prior run.
    pub fn listen(path: [:0]const u8) TransportError!Server {
        _ = linux.unlink(path.ptr);
        const fd = try listenUnix(path);
        return .{ .listen_fd = fd, .path = path };
    }

    /// Close the listen socket and remove its path.
    pub fn deinit(self: *Server) void {
        closeFd(self.listen_fd);
        _ = linux.unlink(self.path.ptr);
    }

    /// Block until a client connects; returns the accepted (CLOEXEC) conn fd.
    /// Caller owns the fd — pass it to `handleOne`, which closes it.
    pub fn acceptOne(self: *Server) TransportError!Fd {
        while (true) {
            const rc = linux.accept4(self.listen_fd, null, null, linux.SOCK.CLOEXEC);
            switch (linux.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR, .AGAIN => continue,
                else => return error.AcceptFailed,
            }
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
    /// Note: `limits.max_frame` bytes are allocated from `gpa` for the request
    /// buffer, so set it to your protocol's real cap (not the 1 MiB default) if
    /// per-request allocation matters.
    pub fn handleOne(
        conn_fd: Fd,
        ctx: anytype,
        comptime dispatch: fn (@TypeOf(ctx), []const u8, std.mem.Allocator) anyerror![]const u8,
        gpa: std.mem.Allocator,
        limits: framing.Limits,
    ) !void {
        defer closeFd(conn_fd);

        var rbuf: [io_buf_size]u8 = undefined;
        var fr = FdReader.init(conn_fd, &rbuf);
        const req_store = try gpa.alloc(u8, limits.max_frame);
        defer gpa.free(req_store);
        const req = try framing.readFrame(&fr.interface, req_store, limits);

        const reply = try dispatch(ctx, req, gpa);

        var wbuf: [io_buf_size]u8 = undefined;
        var fw = FdWriter.init(conn_fd, &wbuf);
        try framing.writeFrame(&fw.interface, reply, limits);
        try fw.interface.flush();
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
        const fd = try connectUnix(path);
        defer closeFd(fd);

        var wbuf: [io_buf_size]u8 = undefined;
        var fw = FdWriter.init(fd, &wbuf);
        try framing.writeFrame(&fw.interface, req, limits);
        try fw.interface.flush();

        var rbuf: [io_buf_size]u8 = undefined;
        var fr = FdReader.init(fd, &rbuf);
        return framing.readFrame(&fr.interface, reply_buf, limits);
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

test "Bus: set/get/list + eviction at max_keys (no transport)" {
    var bus = Bus(3).init(testing.allocator);
    defer bus.deinit();

    try testing.expectEqual(@as(usize, 0), bus.count());
    try testing.expect(bus.get("nope") == null);

    try bus.set("a", "1");
    try bus.set("b", "2");
    try bus.set("c", "3");
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

    // inserting a 4th key evicts one → count stays at the cap
    try bus.set("d", "4");
    try testing.expectEqual(@as(usize, 3), bus.count());
    try testing.expectEqualStrings("4", bus.get("d").?);

    // clear drops everything
    bus.clear();
    try testing.expectEqual(@as(usize, 0), bus.count());
    try testing.expect(bus.get("d") == null);
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
    return std.fmt.bufPrintZ(buf, "/tmp/ipcbus-t-{d}-{d}.sock", .{ linux.getpid(), path_counter }) catch unreachable;
}

// A trivial echo: the reply is a copy of the request. Domain-free stand-in for
// a real caller-supplied dispatch — proves the module bakes in no commands.
fn echoDispatch(_: void, req: []const u8, gpa: std.mem.Allocator) anyerror![]const u8 {
    return gpa.dupe(u8, req);
}

fn echoServerLoop(srv: *Server, iterations: usize) void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
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
    const big = "x" ** (io_buf_size + 123);
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

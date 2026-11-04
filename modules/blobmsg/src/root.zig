// SPDX-License-Identifier: MIT
//! blobmsg — native ubus client + blob/blobmsg wire codec (OpenWRT's typed
//! message bus).
//!
//! Talk the ubus unix-socket protocol directly — list objects, invoke
//! methods with JSON args, subscribe to events — with no `ubus` CLI
//! shell-outs, no libubox binding, no libc. All syscalls go through
//! `std.os.linux` (errno-encoded raw syscalls), so the socket client is
//! Linux-only by design; the wire codec in `codec.zig` is platform-pure,
//! golden-tested and fuzzed, and compiles/tests on any OS.
//!
//! ```zig
//! var c = try blobmsg.Client.open(gpa, null); // /var/run/ubus/ubus.sock
//! defer c.close();
//! const objs = try c.list(null); // []Object incl. decoded signatures
//! defer blobmsg.freeObjects(gpa, objs);
//! const board = try c.invoke("system", "board", null); // JSON text
//! defer gpa.free(board);
//! ```
//!
//! The wire format is a clean-room reimplementation, byte-for-byte from the
//! OpenWRT C header specs (openwrt/ubus `ubusmsg.h`, openwrt/libubox
//! `blob.h` + `blobmsg.h`) — pinned by golden-byte tests derived from those
//! headers, not from a captured device transcript. An integration test
//! exercises `list`/`invoke` against a real ubusd when one is reachable
//! (connectivity + well-formed JSON out, not byte comparison); `codec.zig`'s
//! "real-daemon capture" section additionally freezes wire bytes and the
//! matching `ubus -S` JSON stdout from a real `ubus`/`ubusd` pair run once
//! inside the `scripts/vm/` OpenWRT VM lane — a genuine textual byte-parity
//! check, not just "parses without error" (audit F11: this comment used to
//! say the opposite, stale after that capture landed — see SPEC.md).
//! Two daemon behaviors are reproduced exactly because ubusd depends on them:
//!
//! 1. An INVOKE must carry a `UBUS_ATTR_DATA` attr even when there are no
//!    arguments — ubusd rejects an arg-less invoke with INVALID_ARGUMENT.
//! 2. An INVOKE is answered by an ack-STATUS (no OBJID), then the DATA
//!    result, then the completion STATUS (which carries OBJID + the return
//!    code) — the two STATUS replies are distinguished by the OBJID attr.
//!    ubusd-internal objects (like the event registry) instead answer
//!    directly with a single STATUS.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const codec = @import("codec.zig");
pub const AttrIterator = codec.AttrIterator;
pub const FieldIterator = codec.FieldIterator;
pub const Value = codec.Value;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "OpenWRT ubus client + blob/blobmsg wire codec.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux** (codec itself: any)",
    .targets = .{ .linux64, .linux32 },
    .platform = .linux, // client = raw unix-socket syscalls; codec itself is .any
    .role = .client,
    .concurrency = .reentrant, // no globals; one Client per thread/loop
    .model_after = "OpenWRT libubox/ubus wire format (clean-room)",
    .deps = .{}, // std only — std.json for the JSON<->blobmsg mapping
};

pub const Error = error{
    /// No ubus daemon reachable on any candidate socket path.
    Connect,
    /// The daemon closed the stream (or timed out) mid-message.
    ShortRead,
    ShortWrite,
    /// A reply failed wire-format validation (bounds/length/type checks).
    BadMessage,
    /// A reply exceeded the 1 MiB message cap, or a request exceeded a wire
    /// field limit.
    TooLarge,
    /// LOOKUP matched no object of that name.
    NotFound,
    /// The daemon answered the request with a non-zero status code.
    UbusError,
    /// The argument JSON has no blobmsg mapping (null values / non-object).
    Unsupported,
    /// A single call's reply stream ran past `call_deadline_ns` — the
    /// per-recv `SO_RCVTIMEO` bounds only one syscall, so a chatty daemon
    /// that keeps sending resets it forever without this (audit F2).
    Timeout,
    OutOfMemory,
};

/// The well-known ubus socket locations, tried in order by `Client.open`
/// when no explicit path is given.
pub const default_socket_paths = [_][]const u8{ "/var/run/ubus/ubus.sock", "/var/run/ubus.sock" };

/// Blocking-recv bound so a wedged daemon cannot hang the caller forever.
const recv_timeout_s = 5;
/// Reply-size cap — same ceiling as ubusd's own UBUS_MAX_MSG_LEN (1 MiB).
const max_msg = 1024 * 1024;
/// Whole-call wall-clock bound for a multi-message reply stream (`list`,
/// `invoke`, `subscribe`'s handshake, `EventStream.poll`'s drain). Real
/// round-trips finish in micro/milliseconds; this only has to be far above
/// that. `recv_timeout_s` bounds a single `recv` — a peer that keeps
/// sending resets it on every call, so it does not bound the call as a
/// whole (audit F2).
const call_deadline_ns: u64 = 2 * std.time.ns_per_s;
/// Per-connection limits of the request/reply calls (`ubus -t` and its byte
/// cap). Defaults are the module's historical fixed values. Fed to
/// `Client.openWith`; `EventStream` inherits them from the `Client` that
/// subscribed.
pub const Options = struct {
    /// Wall-clock bound of one whole call (`list`, `invoke`, `sendEvent`,
    /// `subscribe`'s handshake, one `EventStream.poll` drain) and of every
    /// request write: a slow method (wireless scan, package install) needs
    /// more than 2 s, a watchdog wants less. 0 is refused by `openWith`
    /// (`error.Unsupported`): there is no unbounded call.
    call_timeout_ms: u32 = 2000,
    /// Aggregate reply payload budget of one call (0 is refused). A single
    /// frame is still capped at 1 MiB (ubusd's own `UBUS_MAX_MSG_LEN`); this
    /// bounds how many frames one call may accumulate, and an event frame
    /// bigger than it is `error.TooLarge` from `EventStream.poll`.
    max_reply_bytes: usize = max_msg,

    fn deadline(self: Options) u64 {
        return monoNs() +| @as(u64, @max(self.call_timeout_ms, 1)) *| std.time.ns_per_ms;
    }
};

/// sockaddr_un.sun_path capacity minus the terminating NUL.
const max_path = @sizeOf(@FieldType(linux.sockaddr.un, "path")) - 1;

/// One object returned by `Client.list`. `name` and `signature_json` are
/// allocated with the Client's allocator — free the slice with
/// `freeObjects`.
pub const Object = struct {
    /// Daemon-assigned numeric object id.
    id: u32,
    /// Object path, e.g. "system" or "network.interface.lan".
    name: []u8,
    /// The object's method signature decoded to JSON text (method name →
    /// argument-policy table), or null when the daemon sent none.
    signature_json: ?[]u8,
};

/// Free a slice returned by `Client.list`.
pub fn freeObjects(gpa: std.mem.Allocator, objects: []Object) void {
    for (objects) |o| {
        gpa.free(o.name);
        if (o.signature_json) |s| gpa.free(s);
    }
    gpa.free(objects);
}

// ── socket plumbing (shared by Client, EventStream and the test daemon) ─────

/// Milliseconds from `now` until `deadline_ns`, clamped to a `poll` timeout
/// (0 = already due).
fn msUntil(deadline_ns: u64, now: u64) i32 {
    if (now >= deadline_ns) return 0;
    const ms = (deadline_ns - now) / std.time.ns_per_ms + 1;
    return @intCast(@min(ms, 60 * std.time.ns_per_s / std.time.ns_per_ms));
}

/// Wait until `fd` is ready for `events` or `deadline_ns` (CLOCK_MONOTONIC)
/// passes: `error.Timeout`. `poll` itself failing (not EINTR) is `fail`.
fn waitReady(fd: i32, events: i16, deadline_ns: u64, fail: Error) Error!void {
    while (true) {
        const now = monoNs();
        if (now >= deadline_ns) return Error.Timeout;
        var pfd = [_]linux.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        const pr = linux.poll(&pfd, 1, msUntil(deadline_ns, now));
        switch (linux.errno(pr)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return fail,
        }
        if (pr != 0) return;
    }
}

/// Write all of `bytes` before `deadline_ns` (sweep BM-2/BM-3; every request
/// message gets a fresh `call_deadline_ns`, a blocking write used to wait
/// forever on a daemon that stopped reading). `send` with
/// `MSG.NOSIGNAL`: a peer that went away is `ShortWrite`, never SIGPIPE (whose
/// default action kills the host process). Non-blocking sends gated by `poll`,
/// so a daemon that stops reading cannot wedge the caller: `error.Timeout`.
fn writeAll(fd: i32, bytes: []const u8, deadline_ns: u64) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.sendto(fd, bytes[off..].ptr, bytes.len - off, linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .AGAIN, .INTR => {
                try waitReady(fd, linux.POLL.OUT, deadline_ns, Error.ShortWrite);
                continue;
            },
            else => return Error.ShortWrite,
        }
        if (rc == 0) return Error.ShortWrite;
        off += rc;
    }
}

/// Fill `buf` before `deadline_ns` (sweep BM-3): the deadline is checked
/// between reads, so a peer dripping one byte per second cannot stretch one
/// frame past it (`SO_RCVTIMEO` only bounds each single recv). A peer that
/// stalls mid-frame is now `error.Timeout` after the call deadline (2 s); it
/// used to be `ShortRead` after the 5 s recv timeout.
fn readAll(fd: i32, buf: []u8, deadline_ns: u64, touched: *bool) Error!void {
    var eof = false;
    return readAllEx(fd, buf, deadline_ns, touched, &eof);
}

/// `readAll` that also tells, through `eof`, whether a `ShortRead` was the
/// stream ending (EOF or a reset: the peer is gone) rather than a read that
/// failed with some other errno (EIO, ENOBUFS, EBADF, ...): the two are not the
/// same news for a caller deciding between "closed" and "broken".
fn readAllEx(fd: i32, buf: []u8, deadline_ns: u64, touched: *bool, eof: *bool) Error!void {
    var off: usize = 0;
    while (off < buf.len) {
        try waitReady(fd, linux.POLL.IN, deadline_ns, Error.ShortRead);
        const rc = linux.read(fd, buf[off..].ptr, buf.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN => continue,
            .CONNRESET, .PIPE => {
                eof.* = true;
                return Error.ShortRead;
            },
            else => return Error.ShortRead,
        }
        if (rc == 0) { // EOF
            eof.* = true;
            return Error.ShortRead;
        }
        off += rc;
        touched.* = true;
    }
}

/// A received ubus message: the header fields + the raw child-attr bytes
/// (the payload after the top blob_attr header), allocated in `gpa`.
const Msg = struct {
    type: u8,
    seq: u16,
    peer: u32,
    payload: []u8,

    fn deinit(self: Msg, gpa: std.mem.Allocator) void {
        gpa.free(self.payload);
    }
};

/// Read one framed message: the 8-byte msghdr, then the top blob_attr (its
/// id_len gives the total length), then the children.
fn readMessage(fd: i32, gpa: std.mem.Allocator, deadline_ns: u64) Error!Msg {
    var touched = false;
    var eof = false;
    return readMessageEx(fd, gpa, deadline_ns, &touched, &eof);
}

/// `readMessage` that reports through `touched` whether any byte of the frame
/// was consumed before an error: after that the stream is mid-frame, i.e.
/// desynchronised (sweep RV-BM-2).
fn readMessageEx(fd: i32, gpa: std.mem.Allocator, deadline_ns: u64, touched: *bool, eof: *bool) Error!Msg {
    var hdr: [codec.msghdr_len]u8 = undefined;
    try readAllEx(fd, &hdr, deadline_ns, touched, eof);
    const h = codec.parseMsgHeader(&hdr);

    var top: [4]u8 = undefined;
    try readAllEx(fd, &top, deadline_ns, touched, eof);
    const top_len = std.mem.readInt(u32, &top, .big) & codec.LEN_MASK; // includes the 4-byte header
    if (top_len < 4) return Error.BadMessage;
    if (top_len > max_msg) return Error.TooLarge;

    const payload = gpa.alloc(u8, top_len - 4) catch return Error.OutOfMemory;
    errdefer gpa.free(payload);
    if (payload.len > 0) try readAllEx(fd, payload, deadline_ns, touched, eof);
    return .{ .type = h.type, .seq = h.seq, .peer = h.peer, .payload = payload };
}

/// Bounds a whole reply-reading call (`list`, `invoke`, `lookupId`,
/// `subscribe`'s handshake, one `EventStream.poll` drain) against a daemon
/// that never stops talking. `readMessage`'s `max_msg` cap bounds one
/// frame; it does not bound how many frames a `while (true)` reply loop
/// reads before its own terminating message arrives. Two independent
/// bounds, either one sufficient alone: a wall-clock deadline (catches a
/// fast flood of tiny messages, which never trips a byte budget) and a
/// total payload-byte budget across every message in the call (catches a
/// slow drip that would otherwise run until the deadline while still
/// allocating without limit) — audit F2, measured 96 062 933 B live from a
/// LOOKUP reply that never sent a closing STATUS.
/// Monotonic nanoseconds since some unspecified epoch (`CLOCK_MONOTONIC`) —
/// `std.time.Timer`/`Instant` do not exist in this toolchain (0.16), and
/// this module already talks to the kernel directly (`linux.*`, no
/// `std.posix`) rather than through std wrappers.
fn monoNs() u64 {
    var ts: linux.timespec = .{ .sec = 0, .nsec = 0 };
    const rc = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return monoFrom(rc, ts);
}

/// The clock reading of a `clock_gettime` result. A failing clock (a seccomp filter that
/// refuses the call is a real consumer shape) reads as the end of time, so every deadline
/// is already past and every call ends in `Timeout`: it fails shut, it never panics.
fn monoFrom(rc: usize, ts: linux.timespec) u64 {
    if (linux.errno(rc) != .SUCCESS or ts.sec < 0 or ts.nsec < 0) return std.math.maxInt(u64);
    return @as(u64, @intCast(ts.sec)) *| std.time.ns_per_s +| @as(u64, @intCast(ts.nsec));
}

const CallBudget = struct {
    deadline_ns: u64,
    bytes_left: usize = max_msg,
    /// Set when the LAST read failed after consuming part of its frame (stream
    /// desynchronised); reset at the start of every `read`.
    partial: bool = false,
    /// Set when the LAST read failed because the stream ended (EOF or reset).
    eof: bool = false,

    fn start() Error!CallBudget {
        return startWith(.{});
    }

    fn startWith(opts: Options) Error!CallBudget {
        return .{ .deadline_ns = opts.deadline(), .bytes_left = opts.max_reply_bytes };
    }

    /// A budget whose deadline was taken earlier (at the entry of a multi-step call), so
    /// that every step shares one bound.
    fn startAt(opts: Options, deadline_ns: u64) CallBudget {
        return .{ .deadline_ns = deadline_ns, .bytes_left = opts.max_reply_bytes };
    }

    /// `readMessage`, charged against this call's deadline and byte budget.
    fn read(self: *CallBudget, fd: i32, gpa: std.mem.Allocator) Error!Msg {
        // Per message: a frame read whole leaves the stream in sync, so only
        // the frame that fails may mark it partial (delta audit GY lead).
        self.partial = false;
        self.eof = false;
        if (monoNs() > self.deadline_ns) return Error.Timeout;
        const msg = try readMessageEx(fd, gpa, self.deadline_ns, &self.partial, &self.eof);
        if (msg.payload.len > self.bytes_left) {
            var m = msg;
            m.deinit(gpa);
            return Error.TooLarge;
        }
        self.bytes_left -= msg.payload.len;
        return msg;
    }
};

/// Frame + send one request: msghdr (BE seq/peer) followed by the top
/// blob_attr (id 0) wrapping `children`.
fn sendMessage(fd: i32, gpa: std.mem.Allocator, mtype: u8, seq: u16, peer: u32, children: []const u8) Error!void {
    return sendMessageWith(fd, gpa, mtype, seq, peer, children, .{});
}

fn sendMessageWith(fd: i32, gpa: std.mem.Allocator, mtype: u8, seq: u16, peer: u32, children: []const u8, opts: Options) Error!void {
    return sendMessageBy(fd, gpa, mtype, seq, peer, children, opts.deadline());
}

fn sendMessageBy(fd: i32, gpa: std.mem.Allocator, mtype: u8, seq: u16, peer: u32, children: []const u8, deadline_ns: u64) Error!void {
    const buf = codec.encodeMessage(gpa, mtype, seq, peer, children) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.TooLarge,
    };
    defer gpa.free(buf);
    try writeAll(fd, buf, deadline_ns);
}

const Conn = struct { fd: i32, client_id: u32 };

/// Connect to one ubus socket path and consume the daemon's HELLO greeting
/// (its msghdr peer is our daemon-assigned client id).
fn connectPath(gpa: std.mem.Allocator, path: []const u8, deadline_ns: u64) Error!Conn {
    if (path.len == 0 or path.len > max_path) return Error.Connect;
    // NONBLOCK: a unix `connect` to a listener whose backlog is full would
    // block forever otherwise (EAGAIN here = `Connect`); every read and write
    // below is poll-gated against a deadline, so the flag costs nothing.
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(rc) != .SUCCESS) return Error.Connect;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);

    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    const alen: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1);
    if (linux.errno(linux.connect(fd, @ptrCast(&addr), alen)) != .SUCCESS) return Error.Connect;

    // Bound the blocking recv so a wedged daemon can't hang the caller.
    const tv = linux.timeval{ .sec = recv_timeout_s, .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));

    const hello = readMessage(fd, gpa, deadline_ns) catch return Error.Connect;
    defer hello.deinit(gpa);
    if (hello.type != codec.MSG.HELLO) return Error.Connect;
    return .{ .fd = fd, .client_id = hello.peer };
}

fn mapEncode(err: codec.EncodeError) Error {
    return switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
        error.Unsupported => Error.Unsupported,
        error.TooLarge, error.TooDeep => Error.TooLarge,
    };
}

/// blobmsg children → owned JSON text, with codec errors folded into the
/// client error set.
fn decodeJson(gpa: std.mem.Allocator, children: []const u8) Error![]u8 {
    return codec.decodeToJsonAlloc(gpa, children) catch |err| switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
        else => Error.BadMessage,
    };
}

/// POLLRDHUP (std has no name for it; 0x2000 on every Linux target this module
/// builds for, MIPS and ARM included).
const poll_rdhup: i16 = 0x2000;

/// UBUS_STATUS_NOT_FOUND of the daemon's status codes.
const status_not_found: i32 = 4;

/// The `UBUS_ATTR_STATUS` code of a message payload (last copy wins, like
/// every duplicate attr here); null when the message carries none. An attr
/// shorter than 4 bytes or a malformed walk is `BadMessage`.
fn statusCode(payload: []const u8) Error!?i32 {
    var code: ?i32 = null;
    var it: codec.AttrIterator = .{ .buf = payload };
    while (it.next() catch return Error.BadMessage) |a| {
        if (a.id != codec.ATTR.STATUS) continue;
        if (a.data.len < 4) return Error.BadMessage;
        code = std.mem.readInt(i32, a.data[0..4], .big);
    }
    return code;
}

/// Read replies of request `seq` on a fresh connection until its closing STATUS and
/// return the STATUS code (a closing STATUS without one is `BadMessage`: the daemon
/// always sends it, captured). The last OBJID of the replies is stored in `objid`.
fn awaitStatus(fd: i32, gpa: std.mem.Allocator, budget: *CallBudget, seq: u16, objid: ?*?u32) Error!i32 {
    while (true) {
        const msg = try budget.read(fd, gpa);
        defer msg.deinit(gpa);
        if (msg.seq != seq) continue;
        if (msg.type != codec.MSG.DATA and msg.type != codec.MSG.STATUS) continue;
        if (objid) |o| {
            var it: codec.AttrIterator = .{ .buf = msg.payload };
            while (it.next() catch return Error.BadMessage) |a| {
                if (a.id == codec.ATTR.OBJID and a.data.len >= 4)
                    o.* = std.mem.readInt(u32, a.data[0..4], .big);
            }
        }
        if (msg.type == codec.MSG.STATUS) return (try statusCode(msg.payload)) orelse Error.BadMessage;
    }
}

/// `awaitStatus` for a LOOKUP of exactly `want`: only a DATA entry whose OBJPATH is `want`
/// counts (a stray entry of another name is ignored), and it must carry its OBJID, else
/// `BadMessage`. The last matching entry wins, as in `list`.
fn awaitLookup(fd: i32, gpa: std.mem.Allocator, budget: *CallBudget, seq: u16, want: []const u8, objid: *?u32) Error!i32 {
    while (true) {
        const msg = try budget.read(fd, gpa);
        defer msg.deinit(gpa);
        if (msg.seq != seq) continue;
        if (msg.type == codec.MSG.DATA) {
            var path: ?[]const u8 = null;
            var id: ?u32 = null;
            var it: codec.AttrIterator = .{ .buf = msg.payload };
            while (it.next() catch return Error.BadMessage) |a| switch (a.id) {
                codec.ATTR.OBJPATH => path = std.mem.trimEnd(u8, a.data, "\x00"),
                codec.ATTR.OBJID => if (a.data.len >= 4) {
                    id = std.mem.readInt(u32, a.data[0..4], .big);
                },
                else => {},
            };
            if (path == null or !std.mem.eql(u8, path.?, want)) continue;
            objid.* = id orelse return Error.BadMessage;
        } else if (msg.type == codec.MSG.STATUS) {
            return (try statusCode(msg.payload)) orelse Error.BadMessage;
        }
    }
}

fn sleepNs(ns: u64) void {
    const ts: linux.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = linux.nanosleep(&ts, null);
}

// ── the client ──────────────────────────────────────────────────────────────

/// A blocking ubus unix-socket client. One instance per thread/loop; no
/// shared state. The connection persists across calls; every request gets a
/// fresh sequence number and replies are matched on it, so a previous
/// request's stragglers are skipped rather than misread.
pub const Client = struct {
    gpa: std.mem.Allocator,
    fd: i32,
    /// Daemon-assigned client id (from the HELLO greeting).
    client_id: u32,
    seq: u16 = 0,
    /// Limits of every call on this client (see `Options`).
    opts: Options = .{},
    /// The daemon's status code of the last request it answered with a
    /// non-zero one (`error.UbusError`, or `error.NotFound` from `list`):
    /// `ubus call` prints it as "Command failed: <reason>" (UBUS_STATUS_*:
    /// 1 invalid command, 2 invalid argument, 3 method not found, 4 not
    /// found, 5 no data, 6 permission denied, 7 timeout, 8 not supported,
    /// 9 unknown error, 10 connection failed). 0 until one happens.
    last_status: i32 = 0,
    /// Sticky (sweep RV-BM-2): set after a write that failed or timed out, or
    /// a read that failed or hit EOF, because the request/reply stream may be
    /// desynchronised. Every later `list`/`invoke` then returns
    /// `error.ShortRead` without touching the socket; `close` and `open`
    /// again. One rule: the verbs that use THIS connection (`list`, `invoke`,
    /// `sendEvent`, `waitFor`) refuse a broken client; the verbs that open a
    /// connection of their own (`subscribe`, `subscribeMany`, `subscribeObject`,
    /// `monitor`) do not look at it.
    broken: bool = false,
    path_buf: [max_path]u8 = @splat(0),
    path_len: u8 = 0,

    /// Connect to the ubus daemon. `socket_path` null = try the well-known
    /// locations (`default_socket_paths`) in order.
    pub fn open(gpa: std.mem.Allocator, socket_path: ?[]const u8) Error!Client {
        return openWith(gpa, socket_path, .{});
    }

    /// `open` with caller-chosen limits (`ubus -t`): `opts.call_timeout_ms`
    /// also bounds the connect handshake, `opts.max_reply_bytes` each call.
    pub fn openWith(gpa: std.mem.Allocator, socket_path: ?[]const u8, opts: Options) Error!Client {
        if (comptime builtin.os.tag != .linux)
            @compileError("blobmsg.Client is Linux-only (raw unix-socket syscalls)");
        // 0 is refused, not "no limit" and not "1 ms": every call here is
        // bounded by design, and a zero budget could never succeed.
        if (opts.call_timeout_ms == 0 or opts.max_reply_bytes == 0) return Error.Unsupported;

        var one: [1][]const u8 = undefined;
        const candidates: []const []const u8 = if (socket_path) |p| blk: {
            one[0] = p;
            break :blk &one;
        } else &default_socket_paths;

        const deadline_ns = opts.deadline();
        for (candidates) |p| {
            const conn = connectPath(gpa, p, deadline_ns) catch continue;
            var c: Client = .{ .gpa = gpa, .fd = conn.fd, .client_id = conn.client_id, .opts = opts };
            @memcpy(c.path_buf[0..p.len], p);
            c.path_len = @intCast(p.len);
            return c;
        }
        return Error.Connect;
    }

    pub fn close(self: *Client) void {
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    fn path(self: *const Client) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    fn send(self: *Client, mtype: u8, seq: u16, peer: u32, children: []const u8) Error!void {
        sendMessageWith(self.fd, self.gpa, mtype, seq, peer, children, self.opts) catch |e| {
            if (e == Error.ShortWrite or e == Error.Timeout) self.broken = true;
            return e;
        };
    }

    fn newBudget(self: *const Client) Error!CallBudget {
        return CallBudget.startWith(self.opts);
    }

    fn recv(self: *Client, budget: *CallBudget) Error!Msg {
        return budget.read(self.fd, self.gpa) catch |e| {
            if (budget.partial or e == Error.ShortRead) self.broken = true;
            return e;
        };
    }

    fn nextSeq(self: *Client) u16 {
        self.seq +%= 1;
        if (self.seq == 0) self.seq = 1;
        return self.seq;
    }

    /// `ubus list [pattern]` natively: LOOKUP (optionally filtered by an
    /// object path / wildcard pattern) and return each replied object's
    /// path, id and decoded method signature. Free with `freeObjects`.
    pub fn list(self: *Client, pattern: ?[]const u8) Error![]Object {
        self.last_status = 0;
        if (self.broken) return Error.ShortRead;
        const seq = self.nextSeq();
        var children: std.ArrayList(u8) = .empty;
        defer children.deinit(self.gpa);
        if (pattern) |p|
            codec.appendAttrString(self.gpa, &children, codec.ATTR.OBJPATH, p) catch |e| return mapEncode(e);
        try self.send(codec.MSG.LOOKUP, seq, 0, children.items);

        var objects: std.ArrayList(Object) = .empty;
        errdefer {
            for (objects.items) |o| {
                self.gpa.free(o.name);
                if (o.signature_json) |s| self.gpa.free(s);
            }
            objects.deinit(self.gpa);
        }
        // One DATA reply per matching object, then a closing STATUS —
        // bounded by CallBudget (audit F2: unbounded otherwise, against a
        // daemon that never sends the closing STATUS).
        var budget = try self.newBudget();
        while (true) {
            const msg = try self.recv(&budget);
            defer msg.deinit(self.gpa);
            if (msg.seq != seq) continue;
            if (msg.type == codec.MSG.DATA) {
                if (try self.parseListEntry(msg.payload)) |obj| {
                    objects.append(self.gpa, obj) catch {
                        self.gpa.free(obj.name);
                        if (obj.signature_json) |s| self.gpa.free(s);
                        return Error.OutOfMemory;
                    };
                }
            } else if (msg.type == codec.MSG.STATUS) {
                // The closing STATUS is the daemon's verdict: a non-zero code
                // is NOT "an empty, complete listing" (`ubus list nosuch`
                // fails with "Not found"). A real ubusd's closing STATUS of a
                // LOOKUP always carries its code (captured 2026-11-04: 0 after
                // the entries, 4 for no match), so one without it, or with an
                // attr too short to hold it, is a `BadMessage`, not "0". A
                // wildcard that matched nothing may be answered NOT_FOUND
                // too: that is a true empty answer.
                const code = (try statusCode(msg.payload)) orelse return Error.BadMessage;
                if (code != 0) {
                    self.last_status = code;
                    const wildcard = if (pattern) |p| std.mem.indexOfScalar(u8, p, '*') != null else true;
                    if (code == status_not_found and wildcard) break;
                    return if (code == status_not_found) Error.NotFound else Error.UbusError;
                }
                break;
            }
        }
        return objects.toOwnedSlice(self.gpa) catch Error.OutOfMemory;
    }

    /// Parse one LOOKUP DATA reply into an owned Object (`BadMessage` when
    /// the reply lacks the mandatory path/id attrs).
    fn parseListEntry(self: *Client, payload: []const u8) Error!?Object {
        var name: ?[]const u8 = null;
        var id: ?u32 = null;
        var sig: ?[]u8 = null;
        errdefer if (sig) |s| self.gpa.free(s);

        var it: codec.AttrIterator = .{ .buf = payload };
        while (it.next() catch return Error.BadMessage) |a| switch (a.id) {
            codec.ATTR.OBJPATH => name = std.mem.trimEnd(u8, a.data, "\x00"),
            codec.ATTR.OBJID => {
                if (a.data.len >= 4) id = std.mem.readInt(u32, a.data[0..4], .big);
            },
            codec.ATTR.SIGNATURE => {
                // Last one wins — matches upstream `blob_parse_attr`'s
                // single-slot-per-id storage, and matches `name` above
                // (already unconditional). Previously first-wins, the one
                // mismatch audit F4 measured composing one `Object` out of
                // two different duplicate LOOKUP DATA copies.
                const decoded = try decodeJson(self.gpa, a.data);
                if (sig) |old| self.gpa.free(old);
                sig = decoded;
            },
            else => {},
        };
        if (name == null or id == null) {
            // An entry without its mandatory path/id (or with an id attr
            // shorter than 4 bytes) is a malformed reply, not an absent
            // object: dropping it would hand back a listing that is silently
            // missing one entry as if it were complete. (`sig` is freed by the
            // errdefer above: freeing it here too was a double free, found by
            // the client fuzz harness.)
            return Error.BadMessage;
        }
        const owned = self.gpa.dupe(u8, name.?) catch return Error.OutOfMemory;
        return .{ .id = id.?, .name = owned, .signature_json = sig };
    }

    /// Resolve an object name to its numeric id via LOOKUP. The reply
    /// stream is drained to its closing STATUS so the connection stays in
    /// sync for the next request.
    fn lookupId(self: *Client, object: []const u8) Error!u32 {
        return self.lookupIdWithin(object, std.math.maxInt(u64));
    }

    /// `lookupId` whose deadline is also capped at `cap_ns` (CLOCK_MONOTONIC),
    /// so `waitFor`'s own deadline bounds each lookup, not only the loop.
    fn lookupIdWithin(self: *Client, object: []const u8, cap_ns: u64) Error!u32 {
        const seq = self.nextSeq();
        var children: std.ArrayList(u8) = .empty;
        defer children.deinit(self.gpa);
        codec.appendAttrString(self.gpa, &children, codec.ATTR.OBJPATH, object) catch |e| return mapEncode(e);
        try self.send(codec.MSG.LOOKUP, seq, 0, children.items);

        var found: ?u32 = null;
        var budget = try self.newBudget();
        budget.deadline_ns = @min(budget.deadline_ns, cap_ns);
        while (true) {
            const msg = try self.recv(&budget);
            defer msg.deinit(self.gpa);
            if (msg.seq != seq) continue;
            if (msg.type == codec.MSG.DATA) {
                // Only an entry whose OBJPATH IS the requested name counts: a name with
                // a `*` is a pattern for the daemon, not an object, and must not be
                // resolved to whichever entry came last. The matching entry must carry
                // its OBJID (`BadMessage` otherwise, as in `awaitLookup`).
                var epath: ?[]const u8 = null;
                var id: ?u32 = null;
                var it: codec.AttrIterator = .{ .buf = msg.payload };
                while (it.next() catch return Error.BadMessage) |a| {
                    // Last copy wins (was first-wins) — matching `list()`'s
                    // last-wins for the same duplicate-attr case (audit F4).
                    if (a.id == codec.ATTR.OBJPATH) epath = std.mem.trimEnd(u8, a.data, "\x00");
                    if (a.id == codec.ATTR.OBJID and a.data.len >= 4)
                        id = std.mem.readInt(u32, a.data[0..4], .big);
                }
                if (epath) |p| if (std.mem.eql(u8, p, object)) {
                    found = id orelse return Error.BadMessage;
                };
            } else if (msg.type == codec.MSG.STATUS) {
                const code = (try statusCode(msg.payload)) orelse return Error.BadMessage; // as in `list`
                if (code != 0 and code != status_not_found) {
                    self.last_status = code;
                    return Error.UbusError; // e.g. permission denied: not "no such object"
                }
                if (found) |id| return id;
                self.last_status = status_not_found;
                return Error.NotFound;
            }
        }
    }

    /// `ubus call <object> <method> [json_args]` natively. Resolves the
    /// object id, sends INVOKE (args encoded into UBUS_ATTR_DATA) and
    /// returns the reply decoded to JSON text (`"{}"` for a void method).
    /// `args_json` null/""/"{}" = no arguments; args must be a JSON object
    /// whose values all have a blobmsg mapping (else `error.Unsupported`).
    /// Caller owns the returned bytes.
    pub fn invoke(self: *Client, object: []const u8, method: []const u8, args_json: ?[]const u8) Error![]u8 {
        const r = try self.invokeReply(object, method, args_json);
        if (r.status != 0) {
            self.gpa.free(r.data);
            return Error.UbusError; // `last_status` has the code
        }
        return r.data;
    }

    /// What a method answered: its return code and the DATA it sent (`"{}"`
    /// when none), which a method may send together with a non-zero code.
    pub const Reply = struct {
        /// The method's return code (0 = ok; UBUS_STATUS_* otherwise).
        status: i32,
        /// Owned by the caller (`gpa.free`).
        data: []u8,
    };

    /// `invoke`, but a non-zero method status is returned as `Reply.status`
    /// together with whatever DATA came with it, instead of dropping the data
    /// into `error.UbusError`. A refusal by the daemon itself (no method ran)
    /// is still `error.UbusError`.
    pub fn invokeReply(self: *Client, object: []const u8, method: []const u8, args_json: ?[]const u8) Error!Reply {
        self.last_status = 0;
        if (self.broken) return Error.ShortRead;
        const objid = try self.lookupId(object);
        const seq = self.nextSeq();

        var children: std.ArrayList(u8) = .empty;
        defer children.deinit(self.gpa);
        codec.appendAttrU32(self.gpa, &children, codec.ATTR.OBJID, objid) catch |e| return mapEncode(e);
        codec.appendAttrString(self.gpa, &children, codec.ATTR.METHOD, method) catch |e| return mapEncode(e);

        // Daemon gotcha #1: the INVOKE must
        // carry a UBUS_ATTR_DATA attr even when there are no arguments —
        // ubusd rejects an arg-less invoke with INVALID_ARGUMENT otherwise.
        const args = std.mem.trim(u8, args_json orelse "", " \t\r\n");
        if (args.len == 0 or std.mem.eql(u8, args, "{}")) {
            codec.appendAttr(self.gpa, &children, codec.ATTR.DATA, &.{}) catch |e| return mapEncode(e);
        } else {
            var parsed = std.json.parseFromSlice(std.json.Value, self.gpa, args, .{}) catch |err|
                switch (err) {
                    error.OutOfMemory => return Error.OutOfMemory,
                    else => return Error.BadMessage,
                };
            defer parsed.deinit();
            const data = codec.encodeArgs(self.gpa, parsed.value) catch |e| return mapEncode(e);
            defer self.gpa.free(data);
            codec.appendAttr(self.gpa, &children, codec.ATTR.DATA, data) catch |e| return mapEncode(e);
        }
        try self.send(codec.MSG.INVOKE, seq, objid, children.items);

        var result: ?[]u8 = null;
        errdefer if (result) |r| self.gpa.free(r);

        // Daemon gotcha #2: reply sequence = ack STATUS
        // (no OBJID) → DATA (the result) → completion STATUS (carries OBJID
        // + the method's return code). Ignore the ack, capture the DATA,
        // stop on the completion — distinguished by the OBJID attr.
        var budget = try self.newBudget();
        while (true) {
            const msg = try self.recv(&budget);
            defer msg.deinit(self.gpa);
            if (msg.seq != seq) continue;
            if (msg.type == codec.MSG.DATA) {
                var it: codec.AttrIterator = .{ .buf = msg.payload };
                while (it.next() catch return Error.BadMessage) |a| {
                    // Last DATA wins (was first-wins) — the same
                    // consistency fix as `list()`/`lookupId()` (audit F4).
                    if (a.id == codec.ATTR.DATA) {
                        const decoded = try decodeJson(self.gpa, a.data);
                        if (result) |old| self.gpa.free(old);
                        result = decoded;
                    }
                }
            } else if (msg.type == codec.MSG.STATUS) {
                var is_completion = false;
                var it: codec.AttrIterator = .{ .buf = msg.payload };
                while (it.next() catch return Error.BadMessage) |a| {
                    if (a.id == codec.ATTR.OBJID) is_completion = true;
                }
                if (!is_completion) {
                    // The ack carries status 0. A non-zero code on a STATUS
                    // with no OBJID is the daemon refusing the request
                    // itself: surface it now instead of waiting out the
                    // deadline for a completion that will never come.
                    if (try statusCode(msg.payload)) |code| if (code != 0) {
                        self.last_status = code;
                        return Error.UbusError;
                    };
                    continue;
                }
                // A completion without a status code (or with a short one)
                // says nothing about success: not "0 = ok".
                const status = (try statusCode(msg.payload)) orelse return Error.BadMessage;
                self.last_status = status;
                // A void method sends no DATA → an empty object, so the
                // result is always valid JSON.
                const data = result orelse (self.gpa.dupe(u8, "{}") catch return Error.OutOfMemory);
                result = null;
                return .{ .status = status, .data = data };
            }
        }
    }

    /// Subscribe to ubus events matching `pattern` (null/"" = all, "*").
    /// Opens a dedicated connection (events arrive as unsolicited INVOKEs,
    /// which must not interleave with this client's request/reply stream),
    /// registers an anonymous listener object (ADD_OBJECT) and INVOKEs the
    /// event registry's "register" method with its id. Close the returned
    /// stream independently of this client.
    pub fn subscribe(self: *Client, pattern: ?[]const u8) Error!EventStream {
        const pat = if (pattern) |p| (if (p.len > 0) p else "*") else "*";
        return self.subscribeMany(&.{pat});
    }

    /// `ubus listen <pattern>...`: one listener object registered for several event
    /// patterns (the real CLI sends one `register` per pattern on one connection, captured:
    /// an event matching any of them arrives once per matching pattern). No pattern is `"*"`;
    /// more than 64 or an empty one is `Unsupported`.
    pub fn subscribeMany(self: *Client, patterns: []const []const u8) Error!EventStream {
        self.last_status = 0;
        if (patterns.len > 64) return Error.Unsupported;
        for (patterns) |p| if (p.len == 0) return Error.Unsupported;
        const star: []const []const u8 = &.{"*"};
        const pats = if (patterns.len == 0) star else patterns;
        const gpa = self.gpa;
        // ONE deadline for the whole handshake (connect, every write, every answer).
        var budget = CallBudget.startAt(self.opts, self.opts.deadline());
        const conn = try connectPath(gpa, self.path(), budget.deadline_ns);
        errdefer _ = linux.close(conn.fd);

        // 1. ADD_OBJECT: an anonymous object (the catch-all event handler),
        //    with no attrs at all, exactly what the real `ubus listen` sends
        //    (captured). The daemon answers a DATA carrying the assigned OBJID,
        //    then a STATUS with the verdict (none is no verdict: `BadMessage`).
        try sendMessageBy(conn.fd, gpa, codec.MSG.ADD_OBJECT, 1, 0, &.{}, budget.deadline_ns);
        var obj_id: ?u32 = null;
        const add_code = try awaitStatus(conn.fd, gpa, &budget, 1, &obj_id);
        if (add_code != 0) {
            self.last_status = add_code;
            return Error.UbusError;
        }
        const my_id = obj_id orelse return Error.BadMessage;

        // 2. INVOKE event(1) "register" {object, pattern}. The "object" id
        //    MUST be a blobmsg INT32 (the registry's policy) — not the
        //    generic JSON-int mapping, which could pick INT64 for a large
        //    id. The registry requires BOTH fields; "*" = all events.
        for (pats, 0..) |pat, i| {
            const seq: u16 = @intCast(2 + i);
            var regargs: std.ArrayList(u8) = .empty;
            defer regargs.deinit(gpa);
            codec.appendU32(gpa, &regargs, "object", my_id) catch |e| return mapEncode(e);
            codec.appendString(gpa, &regargs, "pattern", pat) catch |e| return mapEncode(e);

            var inv: std.ArrayList(u8) = .empty;
            defer inv.deinit(gpa);
            codec.appendAttrU32(gpa, &inv, codec.ATTR.OBJID, codec.SYS_OBJECT_EVENT) catch |e| return mapEncode(e);
            codec.appendAttrString(gpa, &inv, codec.ATTR.METHOD, "register") catch |e| return mapEncode(e);
            codec.appendAttr(gpa, &inv, codec.ATTR.DATA, regargs.items) catch |e| return mapEncode(e);
            try sendMessageBy(conn.fd, gpa, codec.MSG.INVOKE, seq, codec.SYS_OBJECT_EVENT, inv.items, budget.deadline_ns);

            // The event registry is a ubusd-internal object, so "register" is
            // answered directly with a single STATUS (no forwarding ack/OBJID,
            // unlike a provider INVOKE), matched on its seq. No status code in
            // the answer is no verdict: not "0 = ok".
            const status = try awaitStatus(conn.fd, gpa, &budget, seq, null);
            if (status != 0) {
                self.last_status = status;
                return Error.UbusError;
            }
        }
        return .{ .gpa = gpa, .fd = conn.fd, .opts = self.opts };
    }

    /// `ubus subscribe <object>`: receive the notifications object `object`
    /// sends (`ubus_notify` on the provider's side). Dedicated connection, like
    /// `subscribe`; the wire order is the real CLI's, captured from a live ubusd
    /// (`testdata/ubusd_capture.zig`): ADD_OBJECT of an anonymous object, LOOKUP
    /// of the target, SUBSCRIBE{OBJID = ours, TARGET = theirs}. Errors: the
    /// object does not exist `NotFound`; the daemon refuses any step
    /// `UbusError` (`last_status`; an ordinary user is refused on a router
    /// without ACL entries); an answer without its status code `BadMessage`.
    /// `object` is one exact path: empty or with `*` is `Unsupported` (the
    /// wildcard form of `list` has no subscribe counterpart here). Close the
    /// returned stream independently of this client.
    pub fn subscribeObject(self: *Client, object: []const u8) Error!ObjectStream {
        self.last_status = 0;
        // Refused before any connection: an empty or wildcard name, a NUL (a C reader
        // would cut the name there), a name no message can carry.
        if (object.len == 0 or std.mem.indexOfAny(u8, object, "*\x00") != null) return Error.Unsupported;
        if (object.len >= max_msg - 64) return Error.TooLarge;
        const gpa = self.gpa;
        // ONE deadline for the whole handshake (connect, every write, every answer).
        var budget = CallBudget.startAt(self.opts, self.opts.deadline());
        const conn = try connectPath(gpa, self.path(), budget.deadline_ns);
        errdefer _ = linux.close(conn.fd);

        // 1. ADD_OBJECT, no attrs at all (what the real CLI sends): answered by a
        //    DATA carrying our OBJID, then a STATUS with the verdict.
        try sendMessageBy(conn.fd, gpa, codec.MSG.ADD_OBJECT, 1, 0, &.{}, budget.deadline_ns);
        var own: ?u32 = null;
        var code = try awaitStatus(conn.fd, gpa, &budget, 1, &own);
        if (code != 0) {
            self.last_status = code;
            return Error.UbusError;
        }
        const own_id = own orelse return Error.BadMessage;

        // 2. LOOKUP of the target: DATA entries, then a closing STATUS (4 = no such object).
        var children: std.ArrayList(u8) = .empty;
        defer children.deinit(gpa);
        codec.appendAttrString(gpa, &children, codec.ATTR.OBJPATH, object) catch |e| return mapEncode(e);
        try sendMessageBy(conn.fd, gpa, codec.MSG.LOOKUP, 2, 0, children.items, budget.deadline_ns);
        var target: ?u32 = null;
        code = try awaitLookup(conn.fd, gpa, &budget, 2, object, &target);
        if (code != 0) {
            self.last_status = code;
            return if (code == status_not_found) Error.NotFound else Error.UbusError;
        }
        const target_id = target orelse {
            self.last_status = status_not_found;
            return Error.NotFound;
        };

        // 3. SUBSCRIBE{OBJID = ours, TARGET = theirs}: answered by a STATUS.
        children.clearRetainingCapacity();
        codec.appendAttrU32(gpa, &children, codec.ATTR.OBJID, own_id) catch |e| return mapEncode(e);
        codec.appendAttrU32(gpa, &children, codec.ATTR.TARGET, target_id) catch |e| return mapEncode(e);
        try sendMessageBy(conn.fd, gpa, codec.MSG.SUBSCRIBE, 3, 0, children.items, budget.deadline_ns);
        code = try awaitStatus(conn.fd, gpa, &budget, 3, null);
        if (code != 0) {
            self.last_status = code;
            return Error.UbusError;
        }
        return .{ .gpa = gpa, .fd = conn.fd, .opts = self.opts, .own_id = own_id, .target_id = target_id };
    }

    /// `ubus monitor`: tap every message the daemon routes. Dedicated
    /// connection; the request is the real CLI's (INVOKE `add` on the daemon's
    /// monitor object, captured byte for byte), the daemon then sends one
    /// MONITOR frame per message of every client, including ours. `poll`
    /// appends one JSON line per frame (see `monitorJson`); the filters of
    /// `ubus monitor -m/-M` are the caller's (the real CLI filters on its side
    /// too: the request does not change with them). The daemon may refuse the
    /// tap (`UbusError`, `last_status`).
    pub fn monitor(self: *Client) Error!MonitorStream {
        self.last_status = 0;
        const gpa = self.gpa;
        // ONE deadline for the whole handshake (connect, the write, the answer).
        var budget = CallBudget.startAt(self.opts, self.opts.deadline());
        const conn = try connectPath(gpa, self.path(), budget.deadline_ns);
        errdefer _ = linux.close(conn.fd);

        var inv: std.ArrayList(u8) = .empty;
        defer inv.deinit(gpa);
        codec.appendAttrU32(gpa, &inv, codec.ATTR.OBJID, codec.SYS_OBJECT_MONITOR) catch |e| return mapEncode(e);
        codec.appendAttrString(gpa, &inv, codec.ATTR.METHOD, "add") catch |e| return mapEncode(e);
        codec.appendAttr(gpa, &inv, codec.ATTR.DATA, &codec.monitor_add_data) catch |e| return mapEncode(e);
        try sendMessageBy(conn.fd, gpa, codec.MSG.INVOKE, 1, codec.SYS_OBJECT_MONITOR, inv.items, budget.deadline_ns);

        var st: MonitorStream = .{ .gpa = gpa, .fd = conn.fd, .opts = self.opts };
        errdefer st.pending.deinit(gpa);
        // The first MONITOR frame (the answer, as seen by the tap) arrives BEFORE the
        // answer itself: frames read while waiting for the verdict are kept.
        while (true) {
            const msg = try budget.read(conn.fd, gpa);
            defer msg.deinit(gpa);
            if (msg.type == codec.MSG.MONITOR) {
                try st.monitorLine(msg.payload, &st.pending);
                continue;
            }
            if (msg.type != codec.MSG.STATUS or msg.seq != 1) continue;
            const code = (try statusCode(msg.payload)) orelse return Error.BadMessage;
            if (code != 0) {
                self.last_status = code;
                return Error.UbusError;
            }
            break;
        }
        return st;
    }

    /// `ubus send <type> [json]`: publish an event to the daemon's event
    /// registry, which delivers it to every `subscribe`r whose pattern
    /// matches `event_type`. `data_json` null/""/"{}" = no payload, otherwise
    /// a JSON object whose values all have a blobmsg mapping
    /// (`error.Unsupported` otherwise; so is an empty `event_type`). Returns
    /// when the daemon has accepted it; a refusal is `error.UbusError`
    /// (`last_status` has the code). The wire shape (INVOKE of the registry's
    /// `send` with `{id, data}`) follows the documented `ubus send` and is
    /// checked live by the integration test, not by a captured transcript.
    pub fn sendEvent(self: *Client, event_type: []const u8, data_json: ?[]const u8) Error!void {
        self.last_status = 0;
        if (self.broken) return Error.ShortRead;
        if (event_type.len == 0) return Error.Unsupported;
        const gpa = self.gpa;

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(gpa);
        const args = std.mem.trim(u8, data_json orelse "", " \t\r\n");
        if (args.len > 0 and !std.mem.eql(u8, args, "{}")) {
            var parsed = std.json.parseFromSlice(std.json.Value, gpa, args, .{}) catch |err|
                switch (err) {
                    error.OutOfMemory => return Error.OutOfMemory,
                    else => return Error.BadMessage,
                };
            defer parsed.deinit();
            const body = codec.encodeArgs(gpa, parsed.value) catch |e| return mapEncode(e);
            defer gpa.free(body);
            payload.appendSlice(gpa, body) catch return Error.OutOfMemory;
        }
        var regargs: std.ArrayList(u8) = .empty;
        defer regargs.deinit(gpa);
        codec.appendString(gpa, &regargs, "id", event_type) catch |e| return mapEncode(e);
        codec.appendTable(gpa, &regargs, "data", payload.items) catch |e| return mapEncode(e);

        const seq = self.nextSeq();
        var inv: std.ArrayList(u8) = .empty;
        defer inv.deinit(gpa);
        codec.appendAttrU32(gpa, &inv, codec.ATTR.OBJID, codec.SYS_OBJECT_EVENT) catch |e| return mapEncode(e);
        codec.appendAttrString(gpa, &inv, codec.ATTR.METHOD, "send") catch |e| return mapEncode(e);
        codec.appendAttr(gpa, &inv, codec.ATTR.DATA, regargs.items) catch |e| return mapEncode(e);
        try self.send(codec.MSG.INVOKE, seq, codec.SYS_OBJECT_EVENT, inv.items);

        // Answered directly with one STATUS (the registry is ubusd-internal).
        var budget = try self.newBudget();
        while (true) {
            const msg = try self.recv(&budget);
            defer msg.deinit(gpa);
            if (msg.seq != seq or msg.type != codec.MSG.STATUS) continue;
            const status = (try statusCode(msg.payload)) orelse return Error.BadMessage;
            if (status != 0) {
                self.last_status = status;
                return Error.UbusError;
            }
            return;
        }
    }

    /// `ubus wait_for <object>...`: block until every named object exists on
    /// the bus. Polls LOOKUP every 50 ms (an object registered between two
    /// polls is seen at the next one) for at most `timeout_ms` in total,
    /// then `error.Timeout` (the deadline also bounds each lookup, so a silent
    /// daemon cannot hold the call past it); the first check always happens, so 0 asks "are
    /// they all there now". Any failure other than "not found" (a read
    /// error, a refusal, a malformed reply) ends the wait with that error:
    /// it is never mistaken for the object being absent. No names is
    /// `error.Unsupported`: waiting for nothing proves nothing.
    pub fn waitFor(self: *Client, names: []const []const u8, timeout_ms: u32) Error!void {
        self.last_status = 0;
        if (names.len == 0) return Error.Unsupported;
        if (self.broken) return Error.ShortRead;
        const deadline = monoNs() +| @as(u64, timeout_ms) *| std.time.ns_per_ms;
        const poll_ns = 50 * std.time.ns_per_ms;
        var found_upto: usize = 0; // names[0..found_upto] have been seen
        var first = true;
        while (true) {
            // No lookup is sent past the deadline (the first look always is).
            if (!first and monoNs() >= deadline) {
                self.last_status = 0;
                return Error.Timeout;
            }
            first = false;
            while (found_upto < names.len) {
                // 0 = one look, bounded by the call deadline only.
                const cap = if (timeout_ms == 0) std.math.maxInt(u64) else deadline;
                _ = self.lookupIdWithin(names[found_upto], cap) catch |e| switch (e) {
                    Error.NotFound => break,
                    Error.Timeout => {
                        self.last_status = 0; // the daemon gave no verdict
                        return e;
                    },
                    else => return e,
                };
                found_upto += 1;
            }
            if (found_upto == names.len) {
                self.last_status = 0; // an earlier NotFound is not this call's verdict
                return;
            }
            const now = monoNs();
            if (now >= deadline) {
                self.last_status = 0; // no verdict from the daemon: it only never appeared
                return Error.Timeout;
            }
            sleepNs(@min(poll_ns, deadline - now));
        }
    }
};

/// An open event subscription (its own connection to the daemon). Events
/// arrive as INVOKE messages (METHOD = event name, DATA = payload); they
/// carry NO_REPLY, so nothing is answered.
const StreamKind = enum { events, object, monitor };

/// An open event subscription (`Client.subscribe`): see `Stream`.
pub const EventStream = Stream(.events);
/// An open subscription to one object's notifications (`Client.subscribeObject`),
/// the `ubus subscribe <object>` verb: see `Stream`. `poll` answers every
/// notification that wants an answer, so the notifier is not left waiting.
pub const ObjectStream = Stream(.object);
/// An open tap of the daemon's traffic (`Client.monitor`), the `ubus monitor`
/// verb: see `Stream`.
pub const MonitorStream = Stream(.monitor);

fn Stream(comptime kind: StreamKind) type {
    return struct {
        const Self = @This();
        gpa: std.mem.Allocator,
        fd: i32,
        /// Sticky (sweep RV-BM-2): the stream hit EOF, a read failed mid-frame, or
        /// a frame header was impossible, so it cannot be read in sync any more.
        /// `poll` then returns `true` ("closed") without touching the socket;
        /// `close` it and `subscribe` again.
        broken: bool = false,
        /// The limits of the `Client` that subscribed (`poll`'s drain budget).
        opts: Options = .{},
        /// CLOCK_MONOTONIC ns at which `poll` first saw a frame header that is
        /// still incomplete (0 = none): a peer that stops mid-header ends in
        /// `Timeout` after `opts.call_timeout_ms`, not in `false` for ever.
        stall_ns: u64 = 0,
        /// `ObjectStream`: the id of our own (anonymous) object, the notification target.
        own_id: u32 = 0,
        /// `ObjectStream`: the id of the object we subscribed to (an UNSUBSCRIBE counts only for it).
        target_id: u32 = 0,
        /// `ObjectStream`: the daemon told us the subscribed object went away
        /// (UNSUBSCRIBE). The connection stays up; no more notifications will come.
        target_gone: bool = false,
        /// Frames `poll` read but did not understand (a malformed event body, a
        /// monitor frame without its mandatory attrs): skipped, counted, never silent.
        malformed: u32 = 0,
        /// `MonitorStream`: lines made during the handshake, handed out by the first `poll`.
        pending: std.ArrayList(u8) = .empty,

        pub fn close(self: *Self) void {
            self.pending.deinit(self.gpa);
            _ = linux.close(self.fd);
            self.* = undefined;
        }

        /// Drain pending events (non-blocking: poll timeout 0) and append each as
        /// a JSON line `{"<event>":<data>}\n` to `out` — mirroring `ubus listen`
        /// output. Returns `true` only when the stream is finished: the daemon
        /// closed the connection, or it is broken (see `broken`). Returns `false`
        /// when nothing more is ready *or the per-call budget (1 MiB of payload,
        /// 2 s) stopped the drain*: more events may be pending, call again. A
        /// frame that would not fit the remaining byte budget is left unread in
        /// the socket (peeked, never consumed), so no event is dropped. A
        /// malformed event is skipped. `poll` does not wait for a frame header that
        /// is still arriving (`false`; a peer that hung up mid-header is EOF, `true`;
        /// one that stays silent for `Options.call_timeout_ms` after a partial header
        /// is `Timeout`). Once a header is complete the frame is read to its end,
        /// waiting at most what remains of this call's `call_timeout_ms` for the body. Errors (the stream is then
        /// `broken`, later calls return `true`): `OutOfMemory`; `ShortRead` when
        /// `poll(2)` or a read fails with an errno other than a reset; `Timeout`
        /// when a peer stalls inside a frame; `TooLarge` when a frame cannot fit
        /// `Options.max_reply_bytes` even in a fresh call. Only EOF or a reset is
        /// `true`.
        pub fn poll(self: *Self, out: *std.ArrayList(u8)) Error!bool {
            if (self.broken) return true;
            if (kind == .monitor and self.pending.items.len > 0) {
                out.appendSlice(self.gpa, self.pending.items) catch return Error.OutOfMemory;
                self.pending.clearRetainingCapacity();
            }
            // Bounded the same way as the request/reply calls (audit F2).
            var budget = try CallBudget.startWith(self.opts);
            while (true) {
                var pfd = [_]linux.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN | poll_rdhup, .revents = 0 }};
                const pr = linux.poll(&pfd, 1, 0);
                switch (linux.errno(pr)) {
                    .SUCCESS => {},
                    .INTR => return false, // interrupted: nothing consumed, ask again
                    else => {
                        // A failing poll is not "nothing ready": the stream's
                        // state is unknown, so it is surfaced and then sticky.
                        self.broken = true;
                        return Error.ShortRead;
                    },
                }
                if (pr == 0) return false; // nothing ready
                if (monoNs() > budget.deadline_ns) return false; // deadline: more may be pending

                // Peek the frame header: decide on the byte budget before consuming.
                var head: [codec.msghdr_len + 4]u8 = undefined;
                const pk = linux.recvfrom(self.fd, &head, head.len, linux.MSG.PEEK | linux.MSG.DONTWAIT, null, null);
                switch (linux.errno(pk)) {
                    .SUCCESS => {},
                    .AGAIN, .INTR => return false,
                    // The peer went away: the stream is finished.
                    .CONNRESET, .PIPE => {
                        self.broken = true;
                        return true;
                    },
                    // Anything else (EIO, ENOBUFS, ENOMEM, ...) is a failed read
                    // of a stream that may well be alive: never "closed".
                    else => {
                        self.broken = true;
                        return Error.ShortRead;
                    },
                }
                if (pk == 0) { // EOF
                    self.broken = true;
                    return true;
                }
                if (pk < head.len) {
                    // A header still arriving: `poll` never waits for it. If the
                    // peer has hung up the rest will never come (EOF mid-frame).
                    if (pfd[0].revents & (linux.POLL.HUP | poll_rdhup) != 0) {
                        self.broken = true;
                        return true;
                    }
                    const now = monoNs();
                    if (self.stall_ns == 0) self.stall_ns = now;
                    if (now -| self.stall_ns > @as(u64, self.opts.call_timeout_ms) *| std.time.ns_per_ms) {
                        self.broken = true;
                        return Error.Timeout; // stalled inside a header
                    }
                    return false;
                }
                self.stall_ns = 0;
                const top_len = std.mem.readInt(u32, head[codec.msghdr_len..][0..4], .big) & codec.LEN_MASK;
                if (top_len < 4 or top_len > max_msg) { // impossible frame: cannot resynchronise
                    self.broken = true;
                    return true;
                }
                if (top_len - 4 > self.opts.max_reply_bytes) {
                    // Bigger than a whole call's budget: it will never fit, so
                    // "next call, fresh budget" would peek it for ever (a caller
                    // looping on `poll` would spin). The stream is dead.
                    self.broken = true;
                    return Error.TooLarge;
                }
                if (top_len - 4 > budget.bytes_left) return false; // next call, fresh budget

                // The header is here: the frame is read to its end, waiting at
                // most what remains of this call's `opts.call_timeout_ms` for the
                // body (a 1 MiB frame does not fit the socket buffer, so it cannot
                // be peeked whole).
                const msg = budget.read(self.fd, self.gpa) catch |e| switch (e) {
                    error.OutOfMemory => return Error.OutOfMemory,
                    // Deadline between frames: nothing consumed, still in sync.
                    // Inside a frame: the stream cannot be resumed, and a stalled
                    // peer is a timeout, not a close.
                    error.Timeout => if (budget.partial) {
                        self.broken = true;
                        return Error.Timeout;
                    } else return false,
                    // EOF (or a reset) is the stream ending; any other read errno
                    // is an error, never "closed".
                    error.ShortRead => {
                        self.broken = true;
                        if (budget.eof) return true;
                        return Error.ShortRead;
                    },
                    else => {
                        self.broken = true;
                        return e;
                    },
                };
                defer msg.deinit(self.gpa);
                try self.handle(msg, out);
            }
        }

        /// One received frame of this stream's kind into `out` (and, for an
        /// `ObjectStream`, the answer the notifier is waiting for).
        fn handle(self: *Self, msg: Msg, out: *std.ArrayList(u8)) Error!void {
            switch (kind) {
                .events => {
                    if (msg.type != codec.MSG.INVOKE) return;
                    _ = try self.eventLine(msg.payload, out);
                },
                .object => switch (msg.type) {
                    codec.MSG.UNSUBSCRIBE => {
                        // Only the daemon's word about OUR subscription ends it: OBJID = our
                        // object, TARGET = the one we subscribed to. Anything else is counted.
                        var o: ?u32 = null;
                        var t: ?u32 = null;
                        var it: codec.AttrIterator = .{ .buf = msg.payload };
                        while (it.next() catch null) |a| if (a.data.len >= 4) switch (a.id) {
                            codec.ATTR.OBJID => o = std.mem.readInt(u32, a.data[0..4], .big),
                            codec.ATTR.TARGET => t = std.mem.readInt(u32, a.data[0..4], .big),
                            else => {},
                        };
                        if (o == self.own_id and t == self.target_id) self.target_gone = true else self.malformed +|= 1;
                    },
                    codec.MSG.INVOKE => {
                        var addressed = false;
                        var no_reply = false;
                        var walked = true;
                        var it: codec.AttrIterator = .{ .buf = msg.payload };
                        while (true) {
                            const a = (it.next() catch {
                                walked = false;
                                break;
                            }) orelse break;
                            switch (a.id) {
                                codec.ATTR.OBJID => if (a.data.len >= 4) {
                                    addressed = std.mem.readInt(u32, a.data[0..4], .big) == self.own_id;
                                },
                                codec.ATTR.NO_REPLY => no_reply = a.data.len == 0 or a.data[0] != 0,
                                else => {},
                            }
                        }
                        // The notifier waits for every subscriber's STATUS (captured: the real
                        // `ubus subscribe` answers 0 with the INVOKE's seq and peer). A frame
                        // whose attrs cannot be walked is counted; it is answered
                        // INVALID_ARGUMENT only when what was read before the damage already
                        // says it is ours and wants an answer (the header's seq and peer are
                        // intact), otherwise it is not answered: a stray STATUS for a NO_REPLY
                        // event or a frame of another object is not known to be harmless.
                        if (!walked) {
                            self.malformed +|= 1;
                            if (addressed and !no_reply) try self.answer(msg, 2);
                            return;
                        }
                        if (!addressed) return;
                        const ok = try self.eventLine(msg.payload, out);
                        if (no_reply) return;
                        try self.answer(msg, if (ok) 0 else 2); // an unreadable body: INVALID_ARGUMENT
                    },
                    else => {},
                },
                .monitor => if (msg.type == codec.MSG.MONITOR) try self.monitorLine(msg.payload, out),
            }
        }

        /// STATUS `code` for the notification `msg` (its seq and peer, our OBJID).
        fn answer(self: *Self, msg: Msg, code: u32) Error!void {
            var rep: std.ArrayList(u8) = .empty;
            defer rep.deinit(self.gpa);
            codec.appendAttrU32(self.gpa, &rep, codec.ATTR.STATUS, code) catch |e| return mapEncode(e);
            codec.appendAttrU32(self.gpa, &rep, codec.ATTR.OBJID, self.own_id) catch |e| return mapEncode(e);
            sendMessageWith(self.fd, self.gpa, codec.MSG.STATUS, msg.seq, msg.peer, rep.items, self.opts) catch |e| {
                self.broken = true;
                return e;
            };
        }

        /// `{"<method>":<data>}\n` of an INVOKE payload; false (and `malformed` + 1)
        /// when the frame is not well formed.
        fn eventLine(self: *Self, payload: []const u8, out: *std.ArrayList(u8)) Error!bool {
            var method: []const u8 = "";
            var data: []const u8 = &.{};
            var it: codec.AttrIterator = .{ .buf = payload };
            while (it.next() catch {
                self.malformed +|= 1; // skip a malformed event
                return false;
            }) |a| switch (a.id) {
                codec.ATTR.METHOD => method = std.mem.trimEnd(u8, a.data, "\x00"),
                codec.ATTR.DATA => data = a.data,
                else => {},
            };
            var aw = std.Io.Writer.Allocating.init(self.gpa);
            defer aw.deinit();
            var s: std.json.Stringify = .{ .writer = &aw.writer };
            s.beginObject() catch return Error.OutOfMemory;
            s.objectField(method) catch return Error.OutOfMemory;
            codec.streamInto(&s, data, false) catch |err| switch (err) {
                error.WriteFailed => return Error.OutOfMemory,
                else => { // malformed event body: skipped
                    self.malformed +|= 1;
                    return false;
                },
            };
            s.endObject() catch return Error.OutOfMemory;
            out.appendSlice(self.gpa, aw.written()) catch return Error.OutOfMemory;
            out.append(self.gpa, '\n') catch return Error.OutOfMemory;
            return true;
        }

        /// One MONITOR frame as a JSON line (see `Client.monitor`); a frame without
        /// its mandatory attrs or with an unreadable body is skipped and counted.
        fn monitorLine(self: *Self, payload: []const u8, out: *std.ArrayList(u8)) Error!void {
            var line = std.Io.Writer.Allocating.init(self.gpa);
            defer line.deinit();
            const ok = monitorJson(&line.writer, payload) catch |err| switch (err) {
                error.WriteFailed => return Error.OutOfMemory,
            };
            if (!ok) {
                self.malformed +|= 1;
                return;
            }
            out.appendSlice(self.gpa, line.written()) catch return Error.OutOfMemory;
            out.append(self.gpa, '\n') catch return Error.OutOfMemory;
        }
    };
}

/// The names the real `ubus monitor` prints for a message type (hello, status, data, lookup,
/// invoke: seen in the captured output). Every other type is written as its number: its name
/// would be recalled, not observed.
fn msgTypeName(t: u32) ?[]const u8 {
    return switch (t) {
        codec.MSG.HELLO => "hello",
        codec.MSG.STATUS => "status",
        codec.MSG.DATA => "data",
        codec.MSG.LOOKUP => "lookup",
        codec.MSG.INVOKE => "invoke",
        else => null,
    };
}

/// Write the JSON text of one MONITOR payload to `w`; false when it lacks one
/// of client/peer/send/seq/type/data or a part is unreadable (what was written
/// is then to be dropped by the caller).
/// `{"send":bool,"client":N,"peer":N,"seq":N,"type":"invoke","message":{"objid":N,...}}`:
/// ids are unsigned (the real CLI prints them as signed 32-bit), the message
/// attrs are named like the real CLI's output names them (status, objpath, objid, method,
/// objtype, signature, data, user, group); any other attr is `"attr<N>":"<hex>"`, since no CLI
/// output shows a name for it. A repeated attr id or a non-UTF-8 string makes the frame malformed.
fn monitorJson(w: *std.Io.Writer, payload: []const u8) std.Io.Writer.Error!bool {
    var client: ?u32 = null;
    var peer: ?u32 = null;
    var send: ?bool = null;
    var seq: ?u32 = null;
    var mtype: ?u32 = null;
    var inner: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = payload };
    while (it.next() catch return false) |a| switch (a.id) {
        codec.MON.CLIENT, codec.MON.PEER, codec.MON.SEQ, codec.MON.TYPE => {
            if (a.data.len != 4) return false;
            const v = std.mem.readInt(u32, a.data[0..4], .big);
            switch (a.id) {
                codec.MON.CLIENT => client = v,
                codec.MON.PEER => peer = v,
                codec.MON.SEQ => seq = v,
                else => mtype = v,
            }
        },
        codec.MON.SEND => {
            if (a.data.len != 1) return false;
            send = a.data[0] != 0;
        },
        codec.MON.DATA => inner = a.data,
        else => {},
    };
    if (client == null or peer == null or send == null or seq == null or mtype == null or inner == null) return false;
    var s: std.json.Stringify = .{ .writer = w };
    try s.beginObject();
    try s.objectField("send");
    try s.write(send.?);
    try s.objectField("client");
    try s.write(client.?);
    try s.objectField("peer");
    try s.write(peer.?);
    try s.objectField("seq");
    try s.write(seq.?);
    try s.objectField("type");
    if (msgTypeName(mtype.?)) |n| try s.write(n) else try s.write(mtype.?);
    try s.objectField("message");
    try s.beginObject();
    var mi: codec.AttrIterator = .{ .buf = inner.? };
    // A repeated attr id would write the same JSON key twice: the frame is malformed.
    var seen: u128 = 0;
    while (mi.next() catch return false) |a| {
        const bit = @as(u128, 1) << @as(u7, @truncate(a.id));
        if (a.id > 127 or seen & bit != 0) return false;
        seen |= bit;
        var nbuf: [16]u8 = undefined;
        const name: []const u8 = switch (a.id) {
            codec.ATTR.STATUS => "status",
            codec.ATTR.OBJPATH => "objpath",
            codec.ATTR.OBJID => "objid",
            codec.ATTR.METHOD => "method",
            codec.ATTR.OBJTYPE => "objtype",
            codec.ATTR.SIGNATURE => "signature",
            codec.ATTR.DATA => "data",
            codec.ATTR.USER => "user",
            codec.ATTR.GROUP => "group",
            else => std.fmt.bufPrint(&nbuf, "attr{d}", .{a.id}) catch unreachable,
        };
        try s.objectField(name);
        switch (a.id) {
            codec.ATTR.STATUS => {
                if (a.data.len != 4) return false;
                try s.write(std.mem.readInt(i32, a.data[0..4], .big));
            },
            codec.ATTR.OBJID, codec.ATTR.OBJTYPE => {
                if (a.data.len != 4) return false;
                try s.write(std.mem.readInt(u32, a.data[0..4], .big));
            },
            codec.ATTR.OBJPATH, codec.ATTR.METHOD, codec.ATTR.USER, codec.ATTR.GROUP => {
                const str = std.mem.trimEnd(u8, a.data, "\x00");
                if (!std.unicode.utf8ValidateSlice(str)) return false;
                try s.write(str);
            },
            codec.ATTR.SIGNATURE, codec.ATTR.DATA => codec.streamInto(&s, a.data, false) catch |err| switch (err) {
                error.WriteFailed => return error.WriteFailed,
                else => return false,
            },
            else => {
                try s.beginWriteRaw();
                try w.writeByte('"');
                for (a.data) |b| try w.print("{x:0>2}", .{b});
                try w.writeByte('"');
                s.endWriteRaw();
            },
        }
    }
    try s.endObject();
    try s.endObject();
    return true;
}

// ── tests: scripted in-process daemon (headless, no ubusd needed) ───────────
// A minimal ubusd stand-in speaking the exact reply choreography of the real
// daemon — incl. the ack-STATUS → DATA → completion-STATUS(OBJID) sequence —
// so the client's full request logic is exercised without OpenWRT hardware.

const testing = std.testing;

/// The children of a closing `STATUS 0` (one raw attr: id 1, 8 bytes, BE 0).
const status_ok = [_]u8{ 0x01, 0, 0, 0x08, 0, 0, 0, 0 };

const MockCtx = struct {
    listen_fd: i32,
    conns: u8,
    send_event_after_register: bool = false,
    /// Set when any INVOKE arrives WITHOUT a UBUS_ATTR_DATA attr — asserting
    /// daemon gotcha #1 (the client must always send it).
    invoke_missing_data: bool = false,
    got_args: [256]u8 = @splat(0),
    got_args_len: usize = 0,
    late_after: u32 = 0,
    late_lookups: u32 = 0,
};

fn mockBind(path: []const u8) !i32 {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    const alen: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), alen)) != .SUCCESS) return error.BindFailed;
    if (linux.errno(linux.listen(fd, 2)) != .SUCCESS) return error.ListenFailed;
    return fd;
}

fn mockServe(ctx: *MockCtx) void {
    var threads: [4]?std.Thread = @splat(null);
    var i: u8 = 0;
    while (i < ctx.conns) : (i += 1) {
        const rc = linux.accept(ctx.listen_fd, null, null);
        if (linux.errno(rc) != .SUCCESS) break;
        const cfd: i32 = @intCast(rc);
        threads[i] = std.Thread.spawn(.{}, mockConnThread, .{ ctx, cfd, @as(u32, 100) + i }) catch {
            _ = linux.close(cfd);
            break;
        };
    }
    for (threads) |t| if (t) |th| th.join();
}

fn mockConnThread(ctx: *MockCtx, fd: i32, client_id: u32) void {
    const gpa = std.heap.page_allocator; // global-alloc-ok: test-only mock daemon thread body (mockServe's std.Thread.spawn target), not the published module; no caller-supplied allocator reaches a spawned thread
    defer _ = linux.close(fd);
    sendMessage(fd, gpa, codec.MSG.HELLO, 0, client_id, &.{}) catch return;
    while (true) {
        const msg = readMessage(fd, gpa, std.math.maxInt(u64)) catch return; // client closed
        defer msg.deinit(gpa);
        const done = mockHandle(ctx, fd, gpa, msg) catch return;
        if (done) return;
    }
}

/// Dispatch one client request; returns true when the connection should be
/// closed (after delivering the scripted event).
fn mockHandle(ctx: *MockCtx, fd: i32, gpa: std.mem.Allocator, msg: Msg) !bool {
    switch (msg.type) {
        codec.MSG.LOOKUP => try mockLookup(ctx, fd, gpa, msg),
        codec.MSG.ADD_OBJECT => {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            try codec.appendAttrU32(gpa, &out, codec.ATTR.STATUS, 0);
            try codec.appendAttrU32(gpa, &out, codec.ATTR.OBJID, 0x77);
            try sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, out.items);
        },
        codec.MSG.INVOKE => return try mockInvoke(ctx, fd, gpa, msg),
        else => {},
    }
    return false;
}

const mock_objects = [_]struct { name: []const u8, id: u32, method: []const u8 }{
    .{ .name = "system", .id = 0x10, .method = "board" },
    .{ .name = "network", .id = 0x11, .method = "restart" },
    // Empty method = "the daemon sent no SIGNATURE attr for this object" —
    // the documented `signature_json == null` case (a real daemon omits it
    // for some internal objects); mockLookup below skips the attr entirely.
    .{ .name = "nosig", .id = 0x12, .method = "" },
};

fn mockLookup(ctx: *MockCtx, fd: i32, gpa: std.mem.Allocator, msg: Msg) !void {
    var pattern: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = msg.payload };
    while (try it.next()) |a| {
        if (a.id == codec.ATTR.OBJPATH) pattern = std.mem.trimEnd(u8, a.data, "\x00");
    }
    // "late" is an object that only appears from the (late_after+1)th lookup
    // of it on (wait_for's polling).
    if (pattern) |p| if (std.mem.eql(u8, p, "late")) {
        ctx.late_lookups += 1;
        if (ctx.late_lookups > ctx.late_after) {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            try codec.appendAttrU32(gpa, &out, codec.ATTR.OBJID, 0x13);
            try codec.appendAttrString(gpa, &out, codec.ATTR.OBJPATH, "late");
            try sendMessage(fd, gpa, codec.MSG.DATA, msg.seq, 0, out.items);
            try sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, &status_ok);
        } else {
            var st: std.ArrayList(u8) = .empty;
            defer st.deinit(gpa);
            try codec.appendAttrU32(gpa, &st, codec.ATTR.STATUS, 4);
            try sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, st.items);
        }
        return;
    };
    for (mock_objects) |obj| {
        if (pattern) |p| if (!std.mem.eql(u8, p, obj.name)) continue;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try codec.appendAttrU32(gpa, &out, codec.ATTR.OBJID, obj.id);
        try codec.appendAttrString(gpa, &out, codec.ATTR.OBJPATH, obj.name);
        if (obj.method.len > 0) {
            var sig: std.ArrayList(u8) = .empty;
            defer sig.deinit(gpa);
            try codec.appendTable(gpa, &sig, obj.method, &.{}); // {"<method>":{}}
            try codec.appendAttr(gpa, &out, codec.ATTR.SIGNATURE, sig.items);
        }
        try sendMessage(fd, gpa, codec.MSG.DATA, msg.seq, 0, out.items);
    }
    try sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, &status_ok);
}

fn mockInvoke(ctx: *MockCtx, fd: i32, gpa: std.mem.Allocator, msg: Msg) !bool {
    var objid: u32 = 0;
    var method: []const u8 = "";
    var has_data = false;
    var it: codec.AttrIterator = .{ .buf = msg.payload };
    while (try it.next()) |a| switch (a.id) {
        codec.ATTR.OBJID => objid = std.mem.readInt(u32, a.data[0..4], .big),
        codec.ATTR.METHOD => method = std.mem.trimEnd(u8, a.data, "\x00"),
        codec.ATTR.DATA => {
            has_data = true;
            if (a.data.len > 0) { // record decoded args for the test's assert
                const json = try codec.decodeToJsonAlloc(gpa, a.data);
                defer gpa.free(json);
                const n = @min(json.len, ctx.got_args.len);
                @memcpy(ctx.got_args[0..n], json[0..n]);
                ctx.got_args_len = n;
            }
        },
        else => {},
    };
    if (!has_data) ctx.invoke_missing_data = true;

    if (objid == codec.SYS_OBJECT_EVENT and (std.mem.eql(u8, method, "register") or std.mem.eql(u8, method, "send"))) {
        // ubusd-internal object: answered directly with a single STATUS.
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try codec.appendAttrU32(gpa, &out, codec.ATTR.STATUS, 0);
        try sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, out.items);
        if (ctx.send_event_after_register) {
            var ev: std.ArrayList(u8) = .empty;
            defer ev.deinit(gpa);
            try codec.appendInt32(gpa, &ev, "count", 7);
            var out2: std.ArrayList(u8) = .empty;
            defer out2.deinit(gpa);
            try codec.appendAttrString(gpa, &out2, codec.ATTR.METHOD, "test.event");
            try codec.appendAttr(gpa, &out2, codec.ATTR.DATA, ev.items);
            try sendMessage(fd, gpa, codec.MSG.INVOKE, 99, 0x77, out2.items);
            return true; // close — lets the poll-EOF path be tested too
        }
        return false;
    }

    // Provider object: the real daemon choreography — ack STATUS (no
    // OBJID), DATA, completion STATUS (OBJID + return code).
    var ack: std.ArrayList(u8) = .empty;
    defer ack.deinit(gpa);
    try codec.appendAttrU32(gpa, &ack, codec.ATTR.STATUS, 0);
    try sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, ack.items);

    var status: u32 = 0;
    if (std.mem.eql(u8, method, "board")) {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try codec.appendString(gpa, &body, "model", "TestRouter");
        try codec.appendInt32(gpa, &body, "cores", 4);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try codec.appendAttr(gpa, &out, codec.ATTR.DATA, body.items);
        try sendMessage(fd, gpa, codec.MSG.DATA, msg.seq, 0, out.items);
    } else if (std.mem.eql(u8, method, "fail")) {
        status = 6; // nonzero return code → client maps to UbusError
    } // "void": no DATA at all

    var fin: std.ArrayList(u8) = .empty;
    defer fin.deinit(gpa);
    try codec.appendAttrU32(gpa, &fin, codec.ATTR.STATUS, status);
    try codec.appendAttrU32(gpa, &fin, codec.ATTR.OBJID, objid);
    try sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, fin.items);
    return false;
}

fn mockSocketPath(buf: []u8, tag: []const u8) ![:0]const u8 {
    return std.mem.printSentinel(buf, "/tmp/zl-blobmsg-{d}-{s}.sock", .{ linux.getpid(), tag }, 0);
}

fn sleepMs(ms: u64) void {
    const ts: linux.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = linux.nanosleep(&ts, null);
}

test "client vs scripted daemon: list, invoke, void, error, DATA gotcha" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "a");
    _ = linux.unlink(sock_path.ptr);
    defer _ = linux.unlink(sock_path.ptr);

    var ctx: MockCtx = .{ .listen_fd = try mockBind(sock_path), .conns = 1 };
    defer _ = linux.close(ctx.listen_fd);
    const th = try std.Thread.spawn(.{}, mockServe, .{&ctx});

    var c = try Client.openWith(gpa, sock_path, .{ .call_timeout_ms = 5000 });
    try testing.expectEqual(@as(u32, 100), c.client_id);
    try testing.expectEqual(@as(u32, 5000), c.opts.call_timeout_ms);

    // list: objects with ids + decoded signatures, wire order.
    const objs = try c.list(null);
    defer freeObjects(gpa, objs);
    try testing.expectEqual(@as(usize, 3), objs.len);
    try testing.expectEqualStrings("system", objs[0].name);
    try testing.expectEqual(@as(u32, 0x10), objs[0].id);
    try testing.expectEqualStrings("{\"board\":{}}", objs[0].signature_json.?);
    try testing.expectEqualStrings("network", objs[1].name);
    // Documented case: the daemon sent no SIGNATURE attr at all for this
    // object -> signature_json is null, not an empty string or a dropped
    // entry (name/id are the only mandatory attrs).
    try testing.expectEqualStrings("nosig", objs[2].name);
    try testing.expectEqual(@as(u32, 0x12), objs[2].id);
    try testing.expectEqual(@as(?[]u8, null), objs[2].signature_json);

    // filtered list.
    const one = try c.list("network");
    defer freeObjects(gpa, one);
    try testing.expectEqual(@as(usize, 1), one.len);
    try testing.expectEqual(@as(u32, 0x11), one[0].id);

    // invoke with args: result decoded, args round-tripped daemon-side.
    const res = try c.invoke("system", "board", "{\"verbose\":true,\"n\":5}");
    defer gpa.free(res);
    try testing.expectEqualStrings("{\"model\":\"TestRouter\",\"cores\":4}", res);

    // void method → "{}" (and still carries the empty DATA attr).
    const v = try c.invoke("system", "void", null);
    defer gpa.free(v);
    try testing.expectEqualStrings("{}", v);

    // non-zero completion status → UbusError.
    try testing.expectError(Error.UbusError, c.invoke("system", "fail", "{}"));
    try testing.expectEqual(@as(i32, 6), c.last_status); // the daemon's own code is kept

    // unknown object → NotFound.
    try testing.expectError(Error.NotFound, c.invoke("nonesuch", "x", null));

    c.close();
    th.join();
    try testing.expect(!ctx.invoke_missing_data); // gotcha #1 held for EVERY invoke
    try testing.expectEqualStrings("{\"verbose\":true,\"n\":5}", ctx.got_args[0..ctx.got_args_len]);
}

test "client vs scripted daemon: sendEvent reaches the event registry as {id, data}" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "send");
    _ = linux.unlink(sock_path.ptr);
    defer _ = linux.unlink(sock_path.ptr);

    var ctx: MockCtx = .{ .listen_fd = try mockBind(sock_path), .conns = 1 };
    defer _ = linux.close(ctx.listen_fd);
    const th = try std.Thread.spawn(.{}, mockServe, .{&ctx});

    var c = try Client.open(gpa, sock_path);
    try c.sendEvent("test.evt", "{\"n\":5}");
    try testing.expectEqualStrings("{\"id\":\"test.evt\",\"data\":{\"n\":5}}", ctx.got_args[0..ctx.got_args_len]);
    try c.sendEvent("bare", null); // no payload: an empty data table, still sent
    try testing.expectEqualStrings("{\"id\":\"bare\",\"data\":{}}", ctx.got_args[0..ctx.got_args_len]);
    try testing.expectError(Error.Unsupported, c.sendEvent("", null));
    try testing.expectError(Error.BadMessage, c.sendEvent("x", "{not json"));

    // wait_for: present now, appearing on the third look, and never.
    try c.waitFor(&.{ "system", "network" }, 0);
    ctx.late_after = 2;
    const t0 = monoNs();
    try c.waitFor(&.{ "system", "late" }, 5000);
    try testing.expect(monoNs() - t0 >= 90 * std.time.ns_per_ms); // two 50 ms sleeps
    try testing.expectError(Error.Timeout, c.waitFor(&.{"nonesuch"}, 120));
    try testing.expectError(Error.Unsupported, c.waitFor(&.{}, 100));

    c.close();
    th.join();
    try testing.expect(!ctx.invoke_missing_data);
}

test "client vs scripted daemon: subscribe, event delivery, EOF" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "b");
    _ = linux.unlink(sock_path.ptr);
    defer _ = linux.unlink(sock_path.ptr);

    var ctx: MockCtx = .{
        .listen_fd = try mockBind(sock_path),
        .conns = 2,
        .send_event_after_register = true,
    };
    defer _ = linux.close(ctx.listen_fd);
    const th = try std.Thread.spawn(.{}, mockServe, .{&ctx});

    var c = try Client.open(gpa, sock_path);
    var es = try c.subscribe("test.*");

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var eof = false;
    var tries: usize = 0;
    while (out.items.len == 0 and tries < 400) : (tries += 1) {
        eof = try es.poll(&out);
        if (out.items.len == 0 and !eof) sleepMs(5);
    }
    try testing.expectEqualStrings("{\"test.event\":{\"count\":7}}\n", out.items);

    // The scripted daemon closes the event connection after delivering —
    // poll must report end-of-stream, not hang or error.
    tries = 0;
    while (!eof and tries < 400) : (tries += 1) {
        eof = try es.poll(&out);
        if (!eof) sleepMs(5);
    }
    try testing.expect(eof);

    es.close();
    c.close();
    th.join();
    try testing.expect(!ctx.invoke_missing_data); // register carried DATA too
}

// ── tests: hostile/misbehaving scripted daemons (audit F2, F4, F7) ──────────

fn floodConn(fd: i32) void {
    const gpa = std.heap.page_allocator; // global-alloc-ok: test-only mock daemon thread body, not the published module; no caller-supplied allocator reaches a spawned thread
    defer _ = linux.close(fd);
    sendMessage(fd, gpa, codec.MSG.HELLO, 0, 200, &.{}) catch return;
    const req = readMessage(fd, gpa, std.math.maxInt(u64)) catch return;
    defer req.deinit(gpa);
    // A well-formed entry (path + id: an entry without them is BadMessage)
    // plus one unrecognized top-level attr per message (id 99 hits
    // `parseListEntry`'s `else` branch and is ignored) carrying an 8000-byte
    // filler payload.
    const filler = gpa.alloc(u8, 8000) catch return;
    defer gpa.free(filler);
    @memset(filler, 0);
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    codec.appendAttrU32(gpa, &body, codec.ATTR.OBJID, 0x42) catch return;
    codec.appendAttrString(gpa, &body, codec.ATTR.OBJPATH, "flood") catch return;
    codec.appendAttr(gpa, &body, 99, filler) catch return;
    // 300 * ~8000 B = 2.4 MB, well past the 1 MiB call budget, and NO
    // closing STATUS is ever sent -- this is the daemon audit F2 measured
    // (a LOOKUP reply stream with no upper bound on message count or total
    // bytes). The iteration cap is this test's own safety net, not the
    // client's.
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        sendMessage(fd, gpa, codec.MSG.DATA, req.seq, 0, body.items) catch return;
    }
}

fn floodAcceptAndServe(listen_fd: i32) void {
    const rc = linux.accept(listen_fd, null, null);
    if (linux.errno(rc) != .SUCCESS) return;
    floodConn(@intCast(rc));
}

test "F2: list() is bounded by an aggregate byte budget, not by the daemon" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "flood");
    _ = linux.unlink(sock_path.ptr);
    defer _ = linux.unlink(sock_path.ptr);

    const listen_fd = try mockBind(sock_path);
    defer _ = linux.close(listen_fd);
    const th = try std.Thread.spawn(.{}, floodAcceptAndServe, .{listen_fd});

    var c = try Client.open(gpa, sock_path);
    try testing.expectError(Error.TooLarge, c.list(null));
    // Close BEFORE joining: the daemon is still mid-flood and will block on
    // a full socket send buffer once this side stops reading (which is the
    // point of the test) — closing unblocks that write with EPIPE/ECONNRESET
    // instead of deadlocking against the still-open fd.
    c.close();
    th.join();
}

const DupCtx = struct { objid_seen: u32 = 0 };

fn dupConnThread(ctx: *DupCtx, fd: i32) void {
    const gpa = std.heap.page_allocator; // global-alloc-ok: test-only mock daemon thread body, not the published module; no caller-supplied allocator reaches a spawned thread
    defer _ = linux.close(fd);
    sendMessage(fd, gpa, codec.MSG.HELLO, 0, 300, &.{}) catch return;
    while (true) {
        const msg = readMessage(fd, gpa, std.math.maxInt(u64)) catch return;
        defer msg.deinit(gpa);
        if (msg.type == codec.MSG.LOOKUP) {
            // One LOOKUP DATA reply, two full copies of OBJID/OBJPATH/
            // SIGNATURE for the "same" object -- the shape audit F4
            // measured against a real daemon.
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            codec.appendAttrU32(gpa, &out, codec.ATTR.OBJID, 0x1111) catch return;
            codec.appendAttrString(gpa, &out, codec.ATTR.OBJPATH, "alpha") catch return;
            var sig1: std.ArrayList(u8) = .empty;
            defer sig1.deinit(gpa);
            codec.appendTable(gpa, &sig1, "first", &.{}) catch return;
            codec.appendAttr(gpa, &out, codec.ATTR.SIGNATURE, sig1.items) catch return;
            codec.appendAttrU32(gpa, &out, codec.ATTR.OBJID, 0x2222) catch return;
            codec.appendAttrString(gpa, &out, codec.ATTR.OBJPATH, "omega") catch return;
            var sig2: std.ArrayList(u8) = .empty;
            defer sig2.deinit(gpa);
            codec.appendTable(gpa, &sig2, "second", &.{}) catch return;
            codec.appendAttr(gpa, &out, codec.ATTR.SIGNATURE, sig2.items) catch return;
            sendMessage(fd, gpa, codec.MSG.DATA, msg.seq, 0, out.items) catch return;
            sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, &status_ok) catch return;
        } else if (msg.type == codec.MSG.INVOKE) {
            var it: codec.AttrIterator = .{ .buf = msg.payload };
            while (it.next() catch return) |a| {
                if (a.id == codec.ATTR.OBJID and a.data.len >= 4)
                    ctx.objid_seen = std.mem.readInt(u32, a.data[0..4], .big);
            }
            var fin: std.ArrayList(u8) = .empty;
            defer fin.deinit(gpa);
            codec.appendAttrU32(gpa, &fin, codec.ATTR.STATUS, 0) catch return;
            codec.appendAttrU32(gpa, &fin, codec.ATTR.OBJID, ctx.objid_seen) catch return;
            sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, fin.items) catch return;
            return;
        }
    }
}

fn dupAcceptAndServe(listen_fd: i32, ctx: *DupCtx) void {
    const rc = linux.accept(listen_fd, null, null);
    if (linux.errno(rc) != .SUCCESS) return;
    dupConnThread(ctx, @intCast(rc));
}

test "F4: duplicate LOOKUP-reply attrs resolve consistently (last copy wins everywhere)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "dup");
    _ = linux.unlink(sock_path.ptr);
    defer _ = linux.unlink(sock_path.ptr);

    const listen_fd = try mockBind(sock_path);
    defer _ = linux.close(listen_fd);
    var ctx: DupCtx = .{};
    const th = try std.Thread.spawn(.{}, dupAcceptAndServe, .{ listen_fd, &ctx });

    var c = try Client.open(gpa, sock_path);
    defer c.close();

    // Every field of the resulting Object must come from the SAME (the
    // last) copy — before the fix, name/id came from the second copy while
    // signature_json came from the first.
    const objs = try c.list(null);
    defer freeObjects(gpa, objs);
    try testing.expectEqual(@as(usize, 1), objs.len);
    try testing.expectEqualStrings("omega", objs[0].name);
    try testing.expectEqual(@as(u32, 0x2222), objs[0].id);
    try testing.expectEqualStrings("{\"second\":{}}", objs[0].signature_json.?);

    // invoke()'s lookupId() must resolve the SAME id list() did (0x2222) —
    // before the fix it took the FIRST OBJID (0x1111): the two calls
    // disagreed about which object "the same name" meant.
    const res = try c.invoke("omega", "method", null); // the last OBJPATH copy is the name
    defer gpa.free(res);
    th.join();
    try testing.expectEqual(@as(u32, 0x2222), ctx.objid_seen);
}

fn nonHelloConn(fd: i32) void {
    const gpa = std.heap.page_allocator; // global-alloc-ok: test-only mock daemon thread body, not the published module; no caller-supplied allocator reaches a spawned thread
    defer _ = linux.close(fd);
    // A STATUS where the HELLO greeting must be.
    sendMessage(fd, gpa, codec.MSG.STATUS, 0, 0, &.{}) catch return;
}

fn nonHelloAcceptAndServe(listen_fd: i32) void {
    const rc = linux.accept(listen_fd, null, null);
    if (linux.errno(rc) != .SUCCESS) return;
    nonHelloConn(@intCast(rc));
}

test "F7: a first message that is not HELLO is rejected, not accepted as the greeting" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "nohello");
    _ = linux.unlink(sock_path.ptr);
    defer _ = linux.unlink(sock_path.ptr);
    const listen_fd = try mockBind(sock_path);
    defer _ = linux.close(listen_fd);
    const th = try std.Thread.spawn(.{}, nonHelloAcceptAndServe, .{listen_fd});
    try testing.expectError(Error.Connect, Client.open(testing.allocator, sock_path));
    th.join();
}

fn shortObjidConn(fd: i32) void {
    const gpa = std.heap.page_allocator; // global-alloc-ok: test-only mock daemon thread body, not the published module; no caller-supplied allocator reaches a spawned thread
    defer _ = linux.close(fd);
    sendMessage(fd, gpa, codec.MSG.HELLO, 0, 400, &.{}) catch return;
    const req = readMessage(fd, gpa, std.math.maxInt(u64)) catch return;
    defer req.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    codec.appendAttrString(gpa, &out, codec.ATTR.OBJPATH, "short") catch return;
    // OBJID with 2 payload bytes instead of 4 -- a hostile/short reply.
    codec.appendAttr(gpa, &out, codec.ATTR.OBJID, &.{ 0x00, 0x01 }) catch return;
    sendMessage(fd, gpa, codec.MSG.DATA, req.seq, 0, out.items) catch return;
    sendMessage(fd, gpa, codec.MSG.STATUS, req.seq, 0, &status_ok) catch return;
}

fn shortObjidAcceptAndServe(listen_fd: i32) void {
    const rc = linux.accept(listen_fd, null, null);
    if (linux.errno(rc) != .SUCCESS) return;
    shortObjidConn(@intCast(rc));
}

test "F7: a too-short OBJID attr is BadMessage instead of indexing out of bounds" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "shortid");
    _ = linux.unlink(sock_path.ptr);
    defer _ = linux.unlink(sock_path.ptr);
    const listen_fd = try mockBind(sock_path);
    defer _ = linux.close(listen_fd);
    const th = try std.Thread.spawn(.{}, shortObjidAcceptAndServe, .{listen_fd});
    var c = try Client.open(gpa, sock_path);
    defer c.close();
    // An entry whose id cannot be read is a malformed reply, never a listing
    // that silently lacks it.
    try testing.expectError(Error.BadMessage, c.list(null));
    th.join();
}

fn staleSeqConn(fd: i32) void {
    const gpa = std.heap.page_allocator; // global-alloc-ok: test-only mock daemon thread body, not the published module; no caller-supplied allocator reaches a spawned thread
    defer _ = linux.close(fd);
    sendMessage(fd, gpa, codec.MSG.HELLO, 0, 500, &.{}) catch return;
    const req = readMessage(fd, gpa, std.math.maxInt(u64)) catch return;
    defer req.deinit(gpa);
    // A stray DATA from some earlier, already-abandoned request.
    var stray: std.ArrayList(u8) = .empty;
    defer stray.deinit(gpa);
    codec.appendAttrString(gpa, &stray, codec.ATTR.OBJPATH, "ghost") catch return;
    codec.appendAttrU32(gpa, &stray, codec.ATTR.OBJID, 0xdead) catch return;
    sendMessage(fd, gpa, codec.MSG.DATA, req.seq +% 77, 0, stray.items) catch return;
    // The real, correctly seq'd, empty reply.
    sendMessage(fd, gpa, codec.MSG.STATUS, req.seq, 0, &status_ok) catch return;
}

fn staleSeqAcceptAndServe(listen_fd: i32) void {
    const rc = linux.accept(listen_fd, null, null);
    if (linux.errno(rc) != .SUCCESS) return;
    staleSeqConn(@intCast(rc));
}

test "F7: a reply carrying a stale sequence number is skipped, not merged in" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "staleseq");
    _ = linux.unlink(sock_path.ptr);
    defer _ = linux.unlink(sock_path.ptr);
    const listen_fd = try mockBind(sock_path);
    defer _ = linux.close(listen_fd);
    const th = try std.Thread.spawn(.{}, staleSeqAcceptAndServe, .{listen_fd});
    var c = try Client.open(gpa, sock_path);
    defer c.close();
    const objs = try c.list(null);
    defer freeObjects(gpa, objs);
    try testing.expectEqual(@as(usize, 0), objs.len); // the stray "ghost" must not appear
    th.join();
}

test "open reports Connect when no daemon is there" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "gone");
    try testing.expectError(Error.Connect, Client.open(testing.allocator, sock_path));
}

// ── integration: a real ubusd, when present (OpenWRT host) ──────────────────

/// The socket a live test talks to: `BLOBMSG_UBUS_SOCKET` (the capture tool starts a
/// private ubusd, see tools/ubus_capture.py), else the well-known paths.
fn liveSocketPath() ?[]const u8 {
    return std.testing.environ.getPosix("BLOBMSG_UBUS_SOCKET");
}

test "integration: real ubusd list + invoke system.board or the tool's probe.echo (skips when absent)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    // A socket named by the environment is a promise: anything that goes wrong then FAILS.
    // Without one, the well-known paths are tried and a missing daemon is a skip.
    const strict = liveSocketPath() != null;
    var c = Client.open(gpa, liveSocketPath()) catch |err| switch (err) {
        error.Connect => return if (strict) err else error.SkipZigTest,
        else => return err,
    };
    defer c.close();

    const objs = try c.list(null);
    defer freeObjects(gpa, objs);
    const board = c.invoke("system", "board", null) catch |err| switch (err) {
        error.NotFound => blk: {
            // A bare ubusd has no system object; the capture tool's provider has "probe".
            if (!strict and objs.len == 0) return error.SkipZigTest;
            break :blk try c.invoke("probe", "echo", "{\"msg\":\"hi\"}");
        },
        else => return err,
    };
    defer gpa.free(board);
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, board, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .object);
}

const SubScript = struct {
    listen_fd: i32,
    /// Does the ADD_OBJECT answer carry a status code attr?
    addobj_code: bool,
    /// Does the `register` answer carry one?
    register_code: bool,
};

fn subScriptServe(sc: *SubScript) void {
    const gpa = std.heap.page_allocator; // global-alloc-ok: test-only mock daemon thread body
    var held: [2]i32 = .{ -1, -1 };
    defer for (held) |f| if (f >= 0) {
        _ = linux.close(f);
    };
    for (0..2) |i| {
        const rc = linux.accept(sc.listen_fd, null, null);
        if (linux.errno(rc) != .SUCCESS) return;
        held[i] = @intCast(rc);
        sendMessage(held[i], gpa, codec.MSG.HELLO, 0, 50, &.{}) catch return;
    }
    const fd = held[1];
    var req = readMessage(fd, gpa, std.math.maxInt(u64)) catch return; // ADD_OBJECT
    req.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    if (sc.addobj_code) codec.appendAttrU32(gpa, &out, codec.ATTR.STATUS, 0) catch return;
    codec.appendAttrU32(gpa, &out, codec.ATTR.OBJID, 0x77) catch return;
    sendMessage(fd, gpa, codec.MSG.STATUS, 1, 0, out.items) catch return;
    req = readMessage(fd, gpa, std.math.maxInt(u64)) catch return; // register
    req.deinit(gpa);
    out.clearRetainingCapacity();
    if (sc.register_code) codec.appendAttrU32(gpa, &out, codec.ATTR.STATUS, 0) catch return;
    sendMessage(fd, gpa, codec.MSG.STATUS, 2, 0, out.items) catch return;
    sleepMs(100);
}

test "subscribe: an ADD_OBJECT answer or a register answer without a code is BadMessage (captured: the real ones carry it)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_][2]bool{ .{ true, true }, .{ true, false }, .{ false, true } }) |codes| {
        var pathbuf: [64]u8 = undefined;
        const sock_path = try mockSocketPath(&pathbuf, if (codes[0] and codes[1]) "subok" else if (codes[0]) "subbad" else "subbad0");
        _ = linux.unlink(sock_path.ptr);
        defer _ = linux.unlink(sock_path.ptr);
        var sc: SubScript = .{ .listen_fd = try mockBind(sock_path), .addobj_code = codes[0], .register_code = codes[1] };
        defer _ = linux.close(sc.listen_fd);
        const th = try std.Thread.spawn(.{}, subScriptServe, .{&sc});
        var c = try Client.open(testing.allocator, sock_path);
        if (codes[0] and codes[1]) {
            var es = try c.subscribe(null);
            es.close();
        } else {
            try testing.expectError(Error.BadMessage, c.subscribe(null));
        }
        c.close();
        th.join();
    }
}

test "integration: real ubusd sendEvent reaches a subscriber (skips when absent)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const strict = liveSocketPath() != null;
    var c = Client.open(gpa, liveSocketPath()) catch |err| switch (err) {
        error.Connect => return if (strict) err else error.SkipZigTest,
        else => return err,
    };
    defer c.close();
    var es = c.subscribe("zl.blobmsg.test") catch |err| switch (err) {
        // an ordinary user is refused by a default-path daemon; a named socket must accept
        error.UbusError => return if (strict) err else error.SkipZigTest,
        else => return err,
    };
    defer es.close();
    c.sendEvent("zl.blobmsg.test", "{\"n\":1}") catch |err| switch (err) {
        error.UbusError => return if (strict) err else error.SkipZigTest,
        else => return err,
    };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var tries: usize = 0;
    while (out.items.len == 0 and tries < 400) : (tries += 1) {
        _ = try es.poll(&out);
        if (out.items.len == 0) sleepMs(5);
    }
    try testing.expectEqualStrings("{\"zl.blobmsg.test\":{\"n\":1}}\n", out.items);
}

test {
    _ = codec;
    _ = @import("sweep_test.zig");
    _ = @import("capture_test.zig");
    // External anchor: libubox's own JSON <-> blobmsg codec on the same
    // values (tools/libubox_oracle.py), replayed without libubox.
    _ = @import("libubox_oracle_test.zig");
    // Scripted-peer fuzz over the client's reply state machines.
    _ = @import("client_fuzz_test.zig");
}

test "writeAll: a peer that stops reading ends in Timeout at the deadline (sweep BM-3)" {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    // A plain blocking write would sit in send() for this whole 3 s timeout,
    // overrunning the 100 ms deadline; the poll-gated one returns promptly.
    const tv = linux.timeval{ .sec = 3, .usec = 0 };
    _ = linux.setsockopt(fds[0], linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    const big = try testing.allocator.alloc(u8, 8 * 1024 * 1024); // far more than the socket buffer
    defer testing.allocator.free(big);
    @memset(big, 'x');
    const t0 = monoNs();
    try testing.expectError(Error.Timeout, writeAll(fds[0], big, t0 + 100 * std.time.ns_per_ms));
    try testing.expect(monoNs() - t0 < 2 * std.time.ns_per_s);
}

test "readAll: an already expired deadline is Timeout; EOF is ShortRead (sweep BM-3)" {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(fds[0]);
    var b: [4]u8 = undefined;
    var touched = false;
    try testing.expectError(Error.Timeout, readAll(fds[0], &b, monoNs() -| 1, &touched));
    _ = linux.close(fds[1]);
    try testing.expectError(Error.ShortRead, readAll(fds[0], &b, monoNs() + std.time.ns_per_s, &touched));
}

test "readAllEx: EOF is the stream ending, a read that fails with another errno is not (round 2)" {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(fds[0]);
    _ = linux.close(fds[1]);
    var b: [4]u8 = undefined;
    var touched = false;
    var eof = false;
    try testing.expectError(Error.ShortRead, readAllEx(fds[0], &b, monoNs() + std.time.ns_per_s, &touched, &eof));
    try testing.expect(eof);

    // Fault injection: a directory polls ready and `read` fails with EISDIR.
    const rc = linux.openat(linux.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const dfd: i32 = @intCast(rc);
    defer _ = linux.close(dfd);
    eof = false;
    try testing.expectError(Error.ShortRead, readAllEx(dfd, &b, monoNs() + std.time.ns_per_s, &touched, &eof));
    try testing.expect(!eof);
}

test "monoFrom: a failing clock reads as the end of time (every deadline past), never a panic (dbm)" {
    const err: usize = @bitCast(@as(isize, -@as(isize, @backingInt(linux.E.PERM))));
    try testing.expectEqual(std.math.maxInt(u64), monoFrom(err, .{ .sec = 0, .nsec = 0 }));
    try testing.expectEqual(std.math.maxInt(u64), monoFrom(0, .{ .sec = -1, .nsec = 5 }));
    try testing.expectEqual(std.math.maxInt(u64), monoFrom(0, .{ .sec = 1, .nsec = -5 }));
    try testing.expectEqual(@as(u64, 5 * std.time.ns_per_s + 7), monoFrom(0, .{ .sec = 5, .nsec = 7 }));
}

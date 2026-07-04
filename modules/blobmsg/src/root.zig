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
//! The wire format was clean-room ported byte-for-byte from the OpenWRT C
//! sources (openwrt/ubus `ubusmsg.h` + `libubus-io.c`, openwrt/libubox
//! `blob.h` + `blobmsg.h`) in the seed project and verified against a real
//! daemon (native output must equal `ubus -S`). Two daemon behaviors are
//! ported verbatim because ubusd depends on them:
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
    .status = .extract, // seeded in axp axp-core/src/ubus.zig — carved out here
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
    OutOfMemory,
};

/// The well-known ubus socket locations, tried in order by `Client.open`
/// when no explicit path is given.
pub const default_socket_paths = [_][]const u8{ "/var/run/ubus/ubus.sock", "/var/run/ubus.sock" };

/// Blocking-recv bound so a wedged daemon cannot hang the caller forever.
const recv_timeout_s = 5;
/// Reply-size cap — same ceiling as ubusd's own UBUS_MAX_MSG_LEN (1 MiB).
const max_msg = 1024 * 1024;
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

fn writeAll(fd: i32, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (linux.errno(rc) != .SUCCESS or rc == 0) return Error.ShortWrite;
        off += rc;
    }
}

fn readAll(fd: i32, buf: []u8) Error!void {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = linux.read(fd, buf[off..].ptr, buf.len - off);
        if (linux.errno(rc) != .SUCCESS or rc == 0) return Error.ShortRead; // error or EOF
        off += rc;
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
fn readMessage(fd: i32, gpa: std.mem.Allocator) Error!Msg {
    var hdr: [codec.msghdr_len]u8 = undefined;
    try readAll(fd, &hdr);
    const h = codec.parseMsgHeader(&hdr);

    var top: [4]u8 = undefined;
    try readAll(fd, &top);
    const top_len = std.mem.readInt(u32, &top, .big) & codec.LEN_MASK; // includes the 4-byte header
    if (top_len < 4) return Error.BadMessage;
    if (top_len > max_msg) return Error.TooLarge;

    const payload = gpa.alloc(u8, top_len - 4) catch return Error.OutOfMemory;
    errdefer gpa.free(payload);
    if (payload.len > 0) try readAll(fd, payload);
    return .{ .type = h.type, .seq = h.seq, .peer = h.peer, .payload = payload };
}

/// Frame + send one request: msghdr (BE seq/peer) followed by the top
/// blob_attr (id 0) wrapping `children`.
fn sendMessage(fd: i32, gpa: std.mem.Allocator, mtype: u8, seq: u16, peer: u32, children: []const u8) Error!void {
    const buf = codec.encodeMessage(gpa, mtype, seq, peer, children) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.TooLarge,
    };
    defer gpa.free(buf);
    try writeAll(fd, buf);
}

const Conn = struct { fd: i32, client_id: u32 };

/// Connect to one ubus socket path and consume the daemon's HELLO greeting
/// (its msghdr peer is our daemon-assigned client id).
fn connectPath(gpa: std.mem.Allocator, path: []const u8) Error!Conn {
    if (path.len == 0 or path.len > max_path) return Error.Connect;
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
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

    const hello = readMessage(fd, gpa) catch return Error.Connect;
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
    path_buf: [max_path]u8 = @splat(0),
    path_len: u8 = 0,

    /// Connect to the ubus daemon. `socket_path` null = try the well-known
    /// locations (`default_socket_paths`) in order.
    pub fn open(gpa: std.mem.Allocator, socket_path: ?[]const u8) Error!Client {
        if (comptime builtin.os.tag != .linux)
            @compileError("blobmsg.Client is Linux-only (raw unix-socket syscalls)");

        var one: [1][]const u8 = undefined;
        const candidates: []const []const u8 = if (socket_path) |p| blk: {
            one[0] = p;
            break :blk &one;
        } else &default_socket_paths;

        for (candidates) |p| {
            const conn = connectPath(gpa, p) catch continue;
            var c: Client = .{ .gpa = gpa, .fd = conn.fd, .client_id = conn.client_id };
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

    fn nextSeq(self: *Client) u16 {
        self.seq +%= 1;
        if (self.seq == 0) self.seq = 1;
        return self.seq;
    }

    /// `ubus list [pattern]` natively: LOOKUP (optionally filtered by an
    /// object path / wildcard pattern) and return each replied object's
    /// path, id and decoded method signature. Free with `freeObjects`.
    pub fn list(self: *Client, pattern: ?[]const u8) Error![]Object {
        const seq = self.nextSeq();
        var children: std.ArrayList(u8) = .empty;
        defer children.deinit(self.gpa);
        if (pattern) |p|
            codec.appendAttrString(self.gpa, &children, codec.ATTR.OBJPATH, p) catch |e| return mapEncode(e);
        try sendMessage(self.fd, self.gpa, codec.MSG.LOOKUP, seq, 0, children.items);

        var objects: std.ArrayList(Object) = .empty;
        errdefer {
            for (objects.items) |o| {
                self.gpa.free(o.name);
                if (o.signature_json) |s| self.gpa.free(s);
            }
            objects.deinit(self.gpa);
        }
        // One DATA reply per matching object, then a closing STATUS.
        while (true) {
            const msg = try readMessage(self.fd, self.gpa);
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
            } else if (msg.type == codec.MSG.STATUS) break;
        }
        return objects.toOwnedSlice(self.gpa) catch Error.OutOfMemory;
    }

    /// Parse one LOOKUP DATA reply into an owned Object (null when the
    /// reply lacks the mandatory path/id attrs).
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
                if (sig == null) sig = try decodeJson(self.gpa, a.data);
            },
            else => {},
        };
        if (name == null or id == null) {
            if (sig) |s| self.gpa.free(s);
            return null;
        }
        const owned = self.gpa.dupe(u8, name.?) catch return Error.OutOfMemory;
        return .{ .id = id.?, .name = owned, .signature_json = sig };
    }

    /// Resolve an object name to its numeric id via LOOKUP. The reply
    /// stream is drained to its closing STATUS so the connection stays in
    /// sync for the next request.
    fn lookupId(self: *Client, object: []const u8) Error!u32 {
        const seq = self.nextSeq();
        var children: std.ArrayList(u8) = .empty;
        defer children.deinit(self.gpa);
        codec.appendAttrString(self.gpa, &children, codec.ATTR.OBJPATH, object) catch |e| return mapEncode(e);
        try sendMessage(self.fd, self.gpa, codec.MSG.LOOKUP, seq, 0, children.items);

        var found: ?u32 = null;
        while (true) {
            const msg = try readMessage(self.fd, self.gpa);
            defer msg.deinit(self.gpa);
            if (msg.seq != seq) continue;
            if (msg.type == codec.MSG.DATA) {
                var it: codec.AttrIterator = .{ .buf = msg.payload };
                while (it.next() catch return Error.BadMessage) |a| {
                    if (a.id == codec.ATTR.OBJID and a.data.len >= 4 and found == null)
                        found = std.mem.readInt(u32, a.data[0..4], .big);
                }
            } else if (msg.type == codec.MSG.STATUS) {
                return found orelse Error.NotFound;
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
        const objid = try self.lookupId(object);
        const seq = self.nextSeq();

        var children: std.ArrayList(u8) = .empty;
        defer children.deinit(self.gpa);
        codec.appendAttrU32(self.gpa, &children, codec.ATTR.OBJID, objid) catch |e| return mapEncode(e);
        codec.appendAttrString(self.gpa, &children, codec.ATTR.METHOD, method) catch |e| return mapEncode(e);

        // Daemon gotcha #1 (ported verbatim from the seed): the INVOKE must
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
        try sendMessage(self.fd, self.gpa, codec.MSG.INVOKE, seq, objid, children.items);

        var result: ?[]u8 = null;
        errdefer if (result) |r| self.gpa.free(r);

        // Daemon gotcha #2 (ported verbatim): reply sequence = ack STATUS
        // (no OBJID) → DATA (the result) → completion STATUS (carries OBJID
        // + the method's return code). Ignore the ack, capture the DATA,
        // stop on the completion — distinguished by the OBJID attr.
        while (true) {
            const msg = try readMessage(self.fd, self.gpa);
            defer msg.deinit(self.gpa);
            if (msg.seq != seq) continue;
            if (msg.type == codec.MSG.DATA) {
                var it: codec.AttrIterator = .{ .buf = msg.payload };
                while (it.next() catch return Error.BadMessage) |a| {
                    if (a.id == codec.ATTR.DATA and result == null)
                        result = try decodeJson(self.gpa, a.data);
                }
            } else if (msg.type == codec.MSG.STATUS) {
                var status: i32 = 0;
                var is_completion = false;
                var it: codec.AttrIterator = .{ .buf = msg.payload };
                while (it.next() catch return Error.BadMessage) |a| {
                    if (a.id == codec.ATTR.STATUS and a.data.len >= 4)
                        status = std.mem.readInt(i32, a.data[0..4], .big);
                    if (a.id == codec.ATTR.OBJID) is_completion = true;
                }
                if (!is_completion) continue; // the ack — keep reading
                if (status != 0) return Error.UbusError;
                break;
            }
        }
        // A void method sends no DATA → return an empty object so the
        // result is always valid JSON.
        if (result) |r| return r;
        return self.gpa.dupe(u8, "{}") catch Error.OutOfMemory;
    }

    /// Subscribe to ubus events matching `pattern` (null/"" = all, "*").
    /// Opens a dedicated connection (events arrive as unsolicited INVOKEs,
    /// which must not interleave with this client's request/reply stream),
    /// registers an anonymous listener object (ADD_OBJECT) and INVOKEs the
    /// event registry's "register" method with its id. Close the returned
    /// stream independently of this client.
    pub fn subscribe(self: *Client, pattern: ?[]const u8) Error!EventStream {
        const gpa = self.gpa;
        const conn = try connectPath(gpa, self.path());
        errdefer _ = linux.close(conn.fd);

        // 1. ADD_OBJECT: an anonymous one-method object (the catch-all event
        //    handler). Its SIGNATURE is one empty-named, empty method table;
        //    the daemon's STATUS reply carries the assigned OBJID.
        var sig: std.ArrayList(u8) = .empty;
        defer sig.deinit(gpa);
        codec.appendTable(gpa, &sig, "", &.{}) catch |e| return mapEncode(e);
        var addobj: std.ArrayList(u8) = .empty;
        defer addobj.deinit(gpa);
        codec.appendAttr(gpa, &addobj, codec.ATTR.SIGNATURE, sig.items) catch |e| return mapEncode(e);
        try sendMessage(conn.fd, gpa, codec.MSG.ADD_OBJECT, 1, 0, addobj.items);

        var obj_id: ?u32 = null;
        while (true) {
            const msg = try readMessage(conn.fd, gpa);
            defer msg.deinit(gpa);
            var it: codec.AttrIterator = .{ .buf = msg.payload };
            while (it.next() catch return Error.BadMessage) |a| {
                if (a.id == codec.ATTR.OBJID and a.data.len >= 4)
                    obj_id = std.mem.readInt(u32, a.data[0..4], .big);
            }
            if (msg.type == codec.MSG.STATUS) break; // ADD_OBJECT is answered directly
        }
        const my_id = obj_id orelse return Error.BadMessage;

        // 2. INVOKE event(1) "register" {object, pattern}. The "object" id
        //    MUST be a blobmsg INT32 (the registry's policy) — not the
        //    generic JSON-int mapping, which could pick INT64 for a large
        //    id. The registry requires BOTH fields; "*" = all events.
        const pat = if (pattern) |p| (if (p.len > 0) p else "*") else "*";
        var regargs: std.ArrayList(u8) = .empty;
        defer regargs.deinit(gpa);
        codec.appendU32(gpa, &regargs, "object", my_id) catch |e| return mapEncode(e);
        codec.appendString(gpa, &regargs, "pattern", pat) catch |e| return mapEncode(e);

        var inv: std.ArrayList(u8) = .empty;
        defer inv.deinit(gpa);
        codec.appendAttrU32(gpa, &inv, codec.ATTR.OBJID, codec.SYS_OBJECT_EVENT) catch |e| return mapEncode(e);
        codec.appendAttrString(gpa, &inv, codec.ATTR.METHOD, "register") catch |e| return mapEncode(e);
        codec.appendAttr(gpa, &inv, codec.ATTR.DATA, regargs.items) catch |e| return mapEncode(e);
        try sendMessage(conn.fd, gpa, codec.MSG.INVOKE, 2, codec.SYS_OBJECT_EVENT, inv.items);

        // The event registry is a ubusd-internal object, so "register" is
        // answered directly with a single STATUS (no forwarding ack/OBJID,
        // unlike a provider INVOKE).
        while (true) {
            const msg = try readMessage(conn.fd, gpa);
            defer msg.deinit(gpa);
            if (msg.type != codec.MSG.STATUS) continue;
            var status: i32 = 0;
            var it: codec.AttrIterator = .{ .buf = msg.payload };
            while (it.next() catch return Error.BadMessage) |a| {
                if (a.id == codec.ATTR.STATUS and a.data.len >= 4)
                    status = std.mem.readInt(i32, a.data[0..4], .big);
            }
            if (status != 0) return Error.UbusError;
            break;
        }
        return .{ .gpa = gpa, .fd = conn.fd };
    }
};

/// An open event subscription (its own connection to the daemon). Events
/// arrive as INVOKE messages (METHOD = event name, DATA = payload); they
/// carry NO_REPLY, so nothing is answered.
pub const EventStream = struct {
    gpa: std.mem.Allocator,
    fd: i32,

    pub fn close(self: *EventStream) void {
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    /// Drain any pending events (non-blocking, poll timeout 0) and append
    /// each as a JSON line `{"<event>":<data>}\n` to `out` — mirroring
    /// `ubus listen` output. Returns true when the daemon closed the
    /// connection (end of stream).
    pub fn poll(self: *EventStream, out: *std.ArrayList(u8)) Error!bool {
        while (true) {
            var pfd = [_]linux.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN, .revents = 0 }};
            const pr = linux.poll(&pfd, 1, 0);
            if (linux.errno(pr) != .SUCCESS or pr == 0) return false; // nothing ready
            const msg = readMessage(self.fd, self.gpa) catch return true; // EOF / error → end
            defer msg.deinit(self.gpa);
            if (msg.type != codec.MSG.INVOKE) continue;

            var method: []const u8 = "";
            var data: []const u8 = &.{};
            var it: codec.AttrIterator = .{ .buf = msg.payload };
            while (it.next() catch return Error.BadMessage) |a| switch (a.id) {
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
                else => return Error.BadMessage,
            };
            s.endObject() catch return Error.OutOfMemory;
            out.appendSlice(self.gpa, aw.written()) catch return Error.OutOfMemory;
            out.append(self.gpa, '\n') catch return Error.OutOfMemory;
        }
    }
};

// ── tests: scripted in-process daemon (headless, no ubusd needed) ───────────
// A minimal ubusd stand-in speaking the exact reply choreography of the real
// daemon — incl. the ack-STATUS → DATA → completion-STATUS(OBJID) sequence —
// so the client's full request logic is exercised without OpenWRT hardware.

const testing = std.testing;

const MockCtx = struct {
    listen_fd: i32,
    conns: u8,
    send_event_after_register: bool = false,
    /// Set when any INVOKE arrives WITHOUT a UBUS_ATTR_DATA attr — asserting
    /// daemon gotcha #1 (the client must always send it).
    invoke_missing_data: bool = false,
    got_args: [256]u8 = @splat(0),
    got_args_len: usize = 0,
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
    const gpa = std.heap.page_allocator;
    defer _ = linux.close(fd);
    sendMessage(fd, gpa, codec.MSG.HELLO, 0, client_id, &.{}) catch return;
    while (true) {
        const msg = readMessage(fd, gpa) catch return; // client closed
        defer msg.deinit(gpa);
        const done = mockHandle(ctx, fd, gpa, msg) catch return;
        if (done) return;
    }
}

/// Dispatch one client request; returns true when the connection should be
/// closed (after delivering the scripted event).
fn mockHandle(ctx: *MockCtx, fd: i32, gpa: std.mem.Allocator, msg: Msg) !bool {
    switch (msg.type) {
        codec.MSG.LOOKUP => try mockLookup(fd, gpa, msg),
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
};

fn mockLookup(fd: i32, gpa: std.mem.Allocator, msg: Msg) !void {
    var pattern: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = msg.payload };
    while (try it.next()) |a| {
        if (a.id == codec.ATTR.OBJPATH) pattern = std.mem.trimEnd(u8, a.data, "\x00");
    }
    for (mock_objects) |obj| {
        if (pattern) |p| if (!std.mem.eql(u8, p, obj.name)) continue;
        var sig: std.ArrayList(u8) = .empty;
        defer sig.deinit(gpa);
        try codec.appendTable(gpa, &sig, obj.method, &.{}); // {"<method>":{}}
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try codec.appendAttrU32(gpa, &out, codec.ATTR.OBJID, obj.id);
        try codec.appendAttrString(gpa, &out, codec.ATTR.OBJPATH, obj.name);
        try codec.appendAttr(gpa, &out, codec.ATTR.SIGNATURE, sig.items);
        try sendMessage(fd, gpa, codec.MSG.DATA, msg.seq, 0, out.items);
    }
    try sendMessage(fd, gpa, codec.MSG.STATUS, msg.seq, 0, &.{});
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

    if (objid == codec.SYS_OBJECT_EVENT and std.mem.eql(u8, method, "register")) {
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
    return std.fmt.bufPrintZ(buf, "/tmp/zl-blobmsg-{d}-{s}.sock", .{ linux.getpid(), tag });
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

    var c = try Client.open(gpa, sock_path);
    try testing.expectEqual(@as(u32, 100), c.client_id);

    // list: objects with ids + decoded signatures, wire order.
    const objs = try c.list(null);
    defer freeObjects(gpa, objs);
    try testing.expectEqual(@as(usize, 2), objs.len);
    try testing.expectEqualStrings("system", objs[0].name);
    try testing.expectEqual(@as(u32, 0x10), objs[0].id);
    try testing.expectEqualStrings("{\"board\":{}}", objs[0].signature_json.?);
    try testing.expectEqualStrings("network", objs[1].name);

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

    // unknown object → NotFound.
    try testing.expectError(Error.NotFound, c.invoke("nonesuch", "x", null));

    c.close();
    th.join();
    try testing.expect(!ctx.invoke_missing_data); // gotcha #1 held for EVERY invoke
    try testing.expectEqualStrings("{\"verbose\":true,\"n\":5}", ctx.got_args[0..ctx.got_args_len]);
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

test "open reports Connect when no daemon is there" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var pathbuf: [64]u8 = undefined;
    const sock_path = try mockSocketPath(&pathbuf, "gone");
    try testing.expectError(Error.Connect, Client.open(testing.allocator, sock_path));
}

// ── integration: a real ubusd, when present (OpenWRT host) ──────────────────

test "integration: real ubusd list + invoke system.board (skips when absent)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var c = Client.open(gpa, null) catch |err| switch (err) {
        error.Connect => return error.SkipZigTest, // no ubus socket on this host
        else => return err,
    };
    defer c.close();

    const objs = try c.list(null);
    defer freeObjects(gpa, objs);
    try testing.expect(objs.len > 0);

    const board = c.invoke("system", "board", null) catch |err| switch (err) {
        error.NotFound => return error.SkipZigTest, // bus without the system object
        else => return err,
    };
    defer gpa.free(board);
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, board, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .object);
}

test {
    _ = codec;
}

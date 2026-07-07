// SPDX-License-Identifier: MIT
//! Minimal generic-netlink (genetlink) layer: the 4-byte `genlmsghdr` that
//! sits between the `nlmsghdr` and the attributes, family-id resolution via
//! the nlctrl family (`CTRL_CMD_GETFAMILY`), and a blocking `NETLINK_GENERIC`
//! socket. Wire framing and TLV walking are reused from the `netlink`
//! module's codec; this file only adds what genetlink puts on top.
//!
//! Wire format per the kernel UAPI `linux/genetlink.h`:
//!
//! ```text
//! genlmsghdr:  u8 cmd | u8 version | u16 reserved   (4 bytes)
//! ```
//!
//! The socket mirrors `netlink.Socket`'s transport discipline (kernel-assigned
//! portid, MSG_PEEK|MSG_TRUNC receive-buffer growth, non-kernel datagrams
//! dropped) but speaks `NETLINK_GENERIC` and leaves request building to the
//! caller — genetlink payloads are family-specific.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const netlink = @import("netlink");
const codec = netlink.codec;
const native_endian = builtin.cpu.arch.endian();

// ── kernel UAPI constants (linux/genetlink.h) ───────────────────────────────

/// sizeof(struct genlmsghdr), already 4-byte aligned.
pub const header_len = 4;

/// GENL_ID_CTRL — the fixed message type of the nlctrl (control) family.
pub const GENL_ID_CTRL: u16 = 0x10;

/// nlctrl commands (CTRL_CMD_*); only GETFAMILY is needed here.
pub const CTRL_CMD_GETFAMILY: u8 = 3;

/// nlctrl attributes (CTRL_ATTR_*).
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

/// GENL_NAMSIZ — family names incl. NUL. A longer CTRL_ATTR_FAMILY_NAME is
/// rejected by the kernel's policy with EINVAL, so it is caught client-side.
pub const GENL_NAMSIZ = 16;

// ── genlmsghdr codec ────────────────────────────────────────────────────────

/// Append a `struct genlmsghdr` (cmd, version, reserved = 0).
pub fn appendHeader(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    cmd: u8,
    version: u8,
) std.mem.Allocator.Error!void {
    try list.appendSlice(gpa, &.{ cmd, version, 0, 0 });
}

/// Split a genetlink message payload into its `genlmsghdr` command byte and
/// the attribute bytes that follow.
pub fn splitPayload(payload: []const u8) codec.Error!struct { cmd: u8, attrs: []const u8 } {
    if (payload.len < header_len) return error.Truncated;
    return .{ .cmd = payload[0], .attrs = payload[header_len..] };
}

// ── family resolution request (pure, golden-testable) ──────────────────────

/// Build a complete `CTRL_CMD_GETFAMILY` request message resolving `name`
/// to a family id. Caller frees the returned buffer.
pub fn buildGetFamilyRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    name: []const u8,
) (std.mem.Allocator.Error || error{NameTooLong})![]u8 {
    if (name.len >= GENL_NAMSIZ) return error.NameTooLong;
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        GENL_ID_CTRL,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendHeader(gpa, &list, CTRL_CMD_GETFAMILY, 1);
    codec.appendAttrString(gpa, &list, CTRL_ATTR_FAMILY_NAME, name) catch |err| switch (err) {
        error.AttrTooLong => return error.NameTooLong,
        error.OutOfMemory => return error.OutOfMemory,
    };
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── socket transport ────────────────────────────────────────────────────────

pub const OpenError = error{
    OutOfMemory,
    AccessDenied,
    /// Kernel without AF_NETLINK/NETLINK_GENERIC support.
    ProtocolNotSupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    Unexpected,
};

pub const SendError = error{ SendFailed, AccessDenied, SystemResources };

pub const RecvError = error{ OutOfMemory, RecvFailed, MalformedReply, SystemResources };

pub const ResolveError = error{
    OutOfMemory,
    SendFailed,
    RecvFailed,
    /// A reply failed wire-format validation (bounds/length checks).
    MalformedReply,
    /// The requested family is not registered (e.g. kernel module not
    /// loaded) — ENOENT from nlctrl.
    FamilyNotFound,
    NameTooLong,
    AccessDenied,
    SystemResources,
    Unexpected,
};

const initial_recv_buf_len = 8192;
const max_recv_buf_len = 1 << 24;

/// A blocking `NETLINK_GENERIC` socket. One instance per thread/loop; no
/// shared state.
pub const Socket = struct {
    gpa: std.mem.Allocator,
    fd: i32,
    /// Kernel-assigned netlink port id (from getsockname after bind);
    /// replies are matched against it.
    portid: u32,
    seq: u32,
    /// Receive buffer; grown on demand (MSG_PEEK|MSG_TRUNC size probe).
    buf: []u8,

    pub fn open(gpa: std.mem.Allocator) OpenError!Socket {
        if (comptime builtin.os.tag != .linux)
            @compileError("genl.Socket is Linux-only (AF_NETLINK raw syscalls)");

        const rc = linux.socket(
            linux.AF.NETLINK,
            linux.SOCK.RAW | linux.SOCK.CLOEXEC,
            linux.NETLINK.GENERIC,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .AFNOSUPPORT, .PROTONOSUPPORT => return error.ProtocolNotSupported,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);

        // pid 0 = let the kernel assign a unique port id.
        const sa: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        switch (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl)))) {
            .SUCCESS => {},
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        var bound: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        var blen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
        switch (linux.errno(linux.getsockname(fd, @ptrCast(&bound), &blen))) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }

        const buf = try gpa.alloc(u8, initial_recv_buf_len);
        return .{ .gpa = gpa, .fd = fd, .portid = bound.pid, .seq = 0, .buf = buf };
    }

    pub fn close(self: *Socket) void {
        self.gpa.free(self.buf);
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    /// Next request sequence number (never 0, so stale replies from an
    /// unbootstrapped state can't match).
    pub fn nextSeq(self: *Socket) u32 {
        self.seq +%= 1;
        if (self.seq == 0) self.seq = 1;
        return self.seq;
    }

    /// Send one complete netlink message to the kernel.
    pub fn send(self: *Socket, msg: []const u8) SendError!void {
        const dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        while (true) {
            const rc = linux.sendto(
                self.fd,
                msg.ptr,
                msg.len,
                0,
                @ptrCast(&dst),
                @sizeOf(linux.sockaddr.nl),
            );
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                .ACCES, .PERM => return error.AccessDenied,
                else => return error.SendFailed,
            }
        }
    }

    /// Receive one whole datagram, growing `self.buf` as needed via a
    /// MSG_PEEK|MSG_TRUNC size probe. Datagrams not sent by the kernel
    /// (sender pid != 0) are dropped.
    pub fn recvDatagram(self: *Socket) RecvError![]const u8 {
        while (true) {
            const prc = linux.recvfrom(
                self.fd,
                self.buf.ptr,
                self.buf.len,
                linux.MSG.PEEK | linux.MSG.TRUNC,
                null,
                null,
            );
            switch (linux.errno(prc)) {
                .SUCCESS => {},
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.RecvFailed,
            }
            if (prc > self.buf.len) {
                if (prc > max_recv_buf_len) return error.MalformedReply;
                const new_len = std.mem.alignForward(usize, prc, initial_recv_buf_len);
                self.buf = self.gpa.realloc(self.buf, new_len) catch return error.OutOfMemory;
                continue; // re-probe; the datagram is still queued
            }

            var src: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
            var slen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
            const rc = linux.recvfrom(self.fd, self.buf.ptr, self.buf.len, 0, @ptrCast(&src), &slen);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.RecvFailed,
            }
            if (slen >= @sizeOf(linux.sockaddr.nl) and src.pid != 0) continue; // not the kernel
            return self.buf[0..rc];
        }
    }

    /// Resolve a genetlink family name (e.g. "wireguard") to its dynamic
    /// message-type id via `CTRL_CMD_GETFAMILY`. Unprivileged.
    pub fn resolveFamily(self: *Socket, name: []const u8) ResolveError!u16 {
        const seq = self.nextSeq();
        const req = try buildGetFamilyRequest(self.gpa, seq, name);
        defer self.gpa.free(req);
        try self.send(req);

        var family_id: ?u16 = null;
        while (true) {
            const dgram = try self.recvDatagram();
            var it: codec.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                if (m.pid != self.portid or m.seq != seq) continue;
                switch (m.type) {
                    codec.NLMSG_ERROR => {
                        const code = m.errorCode() catch return error.MalformedReply;
                        if (code == 0) return family_id orelse error.MalformedReply; // ACK
                        return switch (@as(u32, @bitCast(-%code))) {
                            @intFromEnum(linux.E.NOENT) => error.FamilyNotFound,
                            @intFromEnum(linux.E.PERM),
                            @intFromEnum(linux.E.ACCES),
                            => error.AccessDenied,
                            @intFromEnum(linux.E.NOBUFS),
                            @intFromEnum(linux.E.NOMEM),
                            => error.SystemResources,
                            else => error.Unexpected,
                        };
                    },
                    GENL_ID_CTRL => {
                        const p = splitPayload(m.payload) catch return error.MalformedReply;
                        var attrs: codec.AttrIterator = .{ .buf = p.attrs };
                        while (attrs.next() catch return error.MalformedReply) |a| {
                            if (a.type == CTRL_ATTR_FAMILY_ID)
                                family_id = a.asU16() catch return error.MalformedReply;
                        }
                    },
                    else => {},
                }
            }
        }
    }
};

// ── offline tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "golden: CTRL_CMD_GETFAMILY request bytes" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE
    const req = try buildGetFamilyRequest(testing.allocator, 7, "wireguard");
    defer testing.allocator.free(req);
    try testing.expectEqualSlices(u8, &.{
        0x24, 0x00, 0x00, 0x00, // nlmsg_len = 36
        0x10, 0x00, // type = GENL_ID_CTRL
        0x05, 0x00, // flags = REQUEST | ACK
        0x07, 0x00, 0x00, 0x00, // seq
        0x00, 0x00, 0x00, 0x00, // pid
        0x03, 0x01, 0x00, 0x00, // genlmsghdr: cmd GETFAMILY, version 1
        0x0e, 0x00, 0x02, 0x00, // attr len 14, CTRL_ATTR_FAMILY_NAME
        'w',  'i',  'r',  'e',
        'g',  'u',  'a',  'r',
        'd', 0x00, 0x00, 0x00, // NUL + pad to 4
    }, req);
}

test "splitPayload rejects a truncated genlmsghdr" {
    try testing.expectError(error.Truncated, splitPayload(&.{}));
    try testing.expectError(error.Truncated, splitPayload(&.{ 1, 1, 0 }));
    const p = try splitPayload(&.{ 0, 1, 0, 0, 0xaa });
    try testing.expectEqual(@as(u8, 0), p.cmd);
    try testing.expectEqualSlices(u8, &.{0xaa}, p.attrs);
}

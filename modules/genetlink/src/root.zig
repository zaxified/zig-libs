// SPDX-License-Identifier: MIT
//! genetlink — pure-Zig generic-netlink (genl) transport: the 4-byte
//! `genlmsghdr` that sits between the `nlmsghdr` and the attributes,
//! family-id resolution via the nlctrl family (`CTRL_CMD_GETFAMILY`),
//! multicast group-id resolution (`CTRL_ATTR_MCAST_GROUPS`), and a blocking
//! `NETLINK_GENERIC` socket. Wire framing, TLV walking **and the socket
//! transport itself** are reused from the `netlink` module; this module only
//! adds what genetlink puts on top.
//!
//! `genetlink` is to generic-netlink families (ethtool, devlink, nl80211,
//! the `wireguard` family, …) what `netlink` is to rtnetlink: a
//! transport-agnostic foundation. Family-specific commands, attributes and
//! request/response layouts are the caller's job — this module ends at the
//! generic layer.
//!
//! Wire format per the kernel UAPI `linux/genetlink.h`:
//!
//! ```text
//! genlmsghdr:  u8 cmd | u8 version | u16 reserved   (4 bytes)
//! ```
//!
//! ```zig
//! const genetlink = @import("genetlink");
//!
//! var sock = try genetlink.Socket.open(gpa);
//! defer sock.close();
//! const family_id = try sock.resolveFamily("wireguard");
//! ```
//!
//! The socket **is** `netlink.Socket` opened with `openProtocol(…,
//! NETLINK_GENERIC)`: socket creation, bind, kernel-assigned portid,
//! `NETLINK_EXT_ACK`, the sequence counter, the `MSG_PEEK|MSG_TRUNC`
//! receive-sizing loop and the extended-ACK capture all live there once, for
//! every netlink protocol. This module keeps only the genl-specific layer and
//! leaves request building beyond family/group resolution to the caller —
//! genetlink payloads are family-specific.
//!
//! Provenance: clean-room from the kernel UAPI (`linux/genetlink.h`,
//! GPL-2.0 WITH Linux-syscall-note — the command/attribute constants and
//! their layouts are the kernel's OS ABI, not copyrightable interface code).
//! Extracted from the `wireguard` module, which was the first consumer; see
//! `NOTICE`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const netlink = @import("netlink");
const codec = netlink.codec;
const native_endian = builtin.cpu.arch.endian();

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Generic-netlink (genl) transport — genlmsghdr framing + nlctrl family-id resolution; shared foundation for ethtool/devlink/nl80211/wireguard clients",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{.linux64},
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .reentrant, // no globals; one Socket per thread/loop
    .model_after = "netlink module's shared transport + kernel UAPI linux/genetlink.h (nlctrl protocol)",
    .deps = .{"netlink"}, // wire codec (nlmsghdr + nlattr TLV) + the socket transport are reused
};

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
/// Nest of one sub-nest per multicast group the family publishes.
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;

/// Attributes inside one entry of `CTRL_ATTR_MCAST_GROUPS`
/// (`CTRL_ATTR_MCAST_GRP_*`).
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

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

// ── multicast group resolution (pure half) ─────────────────────────────────

/// Find the id of the multicast group named `want` in the attribute bytes of a
/// `CTRL_CMD_NEWFAMILY` reply (i.e. the nlctrl payload past its own
/// `genlmsghdr`). `null` = the family publishes no such group.
///
/// Pure — byte slices in, an id out — so it is golden-tested offline against a
/// captured reply. `Socket.resolveMcastGroup` is the round-trip on top.
///
/// A group entry that carries a matching name but no id is a wire-format
/// failure (`error.BadLength`): the kernel always emits both.
pub fn findMcastGroupId(attr_bytes: []const u8, want: []const u8) codec.Error!?u32 {
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| {
        if (a.type != CTRL_ATTR_MCAST_GROUPS) continue;
        var groups: codec.AttrIterator = .{ .buf = a.data };
        while (try groups.next()) |g| {
            var id: ?u32 = null;
            var name: ?[]const u8 = null;
            var inner: codec.AttrIterator = .{ .buf = g.data };
            while (try inner.next()) |x| switch (x.type) {
                CTRL_ATTR_MCAST_GRP_ID => id = try x.asU32(),
                CTRL_ATTR_MCAST_GRP_NAME => name = x.asString(),
                else => {},
            };
            if (name) |n| {
                if (std.mem.eql(u8, n, want)) return id orelse return error.BadLength;
            }
        }
    }
    return null;
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

/// `RecvError` with the two conditions `recvDatagram` folds away kept apart —
/// `Overrun` (`ENOBUFS`: the kernel dropped messages, so an event stream must
/// be resynchronised) and `WouldBlock` (`EAGAIN`: nothing queued, or
/// `setRecvTimeout` expired). See `recvDatagramStrict`.
pub const StrictRecvError = netlink.StrictRecvError;

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

/// `ResolveError` plus the one outcome that is specific to group resolution:
/// the family exists but publishes no group under that name (a kernel too old
/// for it, or a typo).
pub const McastGroupError = ResolveError || error{GroupNotFound};

/// Map an nlctrl `NLMSG_ERROR` errno onto `ResolveError`.
fn resolveErrorFromCode(code: i32) ResolveError {
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
}

/// A blocking `NETLINK_GENERIC` socket. One instance per thread/loop; no
/// shared state.
///
/// The transport underneath is `netlink.Socket` (opened with
/// `openProtocol(gpa, NETLINK_GENERIC)`) — this module carries no syscall
/// discipline of its own. The state stays in this struct's own fields because
/// they are part of the public API (`fd` for poll/epoll and `setsockopt`,
/// `portid`/`seq` for consumers that walk replies themselves, `gpa` as the
/// client allocator), so each operation materialises a transport view over
/// them with `transport()` and writes the mutated half back with `sync()`.
pub const Socket = struct {
    gpa: std.mem.Allocator,
    fd: i32,
    /// Kernel-assigned netlink port id (from getsockname after bind);
    /// replies are matched against it.
    portid: u32,
    seq: u32,
    /// Receive buffer; grown on demand (MSG_PEEK|MSG_TRUNC size probe).
    buf: []u8,
    /// Last extended-ACK reason string from the kernel — see
    /// `lastErrorMessage`. Sized and shaped by the shared transport.
    ext_ack_buf: @FieldType(netlink.Socket, "ext_ack_buf") = @splat(0),
    ext_ack_len: usize = 0,

    /// Borrow this socket's state as the shared `netlink` transport. Cheap
    /// (a struct copy); the borrow is always scoped to one operation.
    fn transport(self: *const Socket) netlink.Socket {
        return .{
            .gpa = self.gpa,
            .fd = self.fd,
            .portid = self.portid,
            .seq = self.seq,
            .buf = self.buf,
            .ext_ack_buf = self.ext_ack_buf,
            .ext_ack_len = self.ext_ack_len,
        };
    }

    /// Write a borrowed transport's mutable state back: `nextSeq` advances
    /// `seq`, the receive path may have grown (reallocated) `buf`, and an
    /// extended ACK may have been captured. `gpa`/`fd`/`portid` are fixed for
    /// the socket's lifetime and need no write-back.
    fn sync(self: *Socket, t: netlink.Socket) void {
        self.seq = t.seq;
        self.buf = t.buf;
        self.ext_ack_buf = t.ext_ack_buf;
        self.ext_ack_len = t.ext_ack_len;
    }

    pub fn open(gpa: std.mem.Allocator) OpenError!Socket {
        if (comptime builtin.os.tag != .linux)
            @compileError("genetlink.Socket is Linux-only (AF_NETLINK raw syscalls)");

        const t = try netlink.Socket.openProtocol(gpa, linux.NETLINK.GENERIC);
        return .{
            .gpa = t.gpa,
            .fd = t.fd,
            .portid = t.portid,
            .seq = t.seq,
            .buf = t.buf,
            .ext_ack_buf = t.ext_ack_buf,
            .ext_ack_len = t.ext_ack_len,
        };
    }

    pub fn close(self: *Socket) void {
        var t = self.transport();
        t.close();
        self.* = undefined;
    }

    /// The raw file descriptor, for poll/epoll integration, `setsockopt`
    /// (multicast membership) or `fcntl(O_NONBLOCK)`. Do not close it — that
    /// is `close`'s job. Equivalent to reading the `fd` field.
    pub fn handle(self: *const Socket) i32 {
        return self.fd;
    }

    /// Bound how long a receive may block (`SO_RCVTIMEO`); 0 restores the
    /// default of blocking forever. A timeout surfaces as
    /// `StrictRecvError.WouldBlock` from `recvDatagramStrict`, and as
    /// `RecvError.RecvFailed` from `recvDatagram`.
    pub fn setRecvTimeout(self: *Socket, millis: u32) error{Unexpected}!void {
        var t = self.transport();
        defer self.sync(t);
        return t.setRecvTimeout(millis);
    }

    /// The kernel's reason for the last failed request, from the extended ACK
    /// (`NLMSGERR_ATTR_MSG`). Empty when the kernel attached none (pre-4.12
    /// kernel, or an errno with no message). Valid until the next request on
    /// this socket.
    pub fn lastErrorMessage(self: *const Socket) []const u8 {
        return self.ext_ack_buf[0..self.ext_ack_len];
    }

    /// Next request sequence number (never 0, so stale replies from an
    /// unbootstrapped state can't match).
    pub fn nextSeq(self: *Socket) u32 {
        var t = self.transport();
        defer self.sync(t);
        return t.nextSeq();
    }

    /// Send one complete netlink message to the kernel.
    pub fn send(self: *Socket, msg: []const u8) SendError!void {
        var t = self.transport();
        defer self.sync(t);
        return t.send(msg);
    }

    /// Receive one whole datagram, growing `self.buf` as needed via a
    /// MSG_PEEK|MSG_TRUNC size probe. Datagrams not sent by the kernel
    /// (sender pid != 0) are dropped. The returned slice borrows this
    /// socket's receive buffer and is valid only until the next call on it.
    pub fn recvDatagram(self: *Socket) RecvError![]const u8 {
        var t = self.transport();
        defer self.sync(t);
        return t.recvDatagram();
    }

    /// `recvDatagram` for callers that need `Overrun` (`ENOBUFS` — the kernel
    /// dropped messages, so an event subscription must resynchronise) and
    /// `WouldBlock` (`EAGAIN` — nothing queued, or `setRecvTimeout` expired)
    /// reported as themselves instead of folded onto
    /// `SystemResources`/`RecvFailed`. Same discipline otherwise.
    pub fn recvDatagramStrict(self: *Socket) StrictRecvError![]const u8 {
        var t = self.transport();
        defer self.sync(t);
        return t.recvDatagramStrict();
    }

    /// Resolve a genetlink family name (e.g. "wireguard") to its dynamic
    /// message-type id via `CTRL_CMD_GETFAMILY`. Unprivileged.
    pub fn resolveFamily(self: *Socket, name: []const u8) ResolveError!u16 {
        const id = (try self.ctrlGetFamily(name, null)) orelse return error.MalformedReply;
        return @truncate(id);
    }

    /// Resolve one of `family`'s multicast group names (e.g. nl80211's
    /// "scan", ethtool's "monitor") to its dynamic group id, over the same
    /// `CTRL_CMD_GETFAMILY` round trip. Unprivileged — *joining* the group
    /// (`NETLINK_ADD_MEMBERSHIP` on `fd`) may not be.
    ///
    /// `error.GroupNotFound` = the family resolved but publishes no group
    /// under that name; `error.FamilyNotFound` = no such family.
    pub fn resolveMcastGroup(
        self: *Socket,
        family: []const u8,
        group: []const u8,
    ) McastGroupError!u32 {
        return (try self.ctrlGetFamily(family, group)) orelse error.GroupNotFound;
    }

    /// The one nlctrl round trip both resolvers share: send
    /// `CTRL_CMD_GETFAMILY(family)`, then walk the replies until the ACK.
    /// With `group == null` the answer is `CTRL_ATTR_FAMILY_ID`, otherwise the
    /// id of that multicast group; `null` = the reply never carried it.
    fn ctrlGetFamily(self: *Socket, family: []const u8, group: ?[]const u8) ResolveError!?u32 {
        var t = self.transport();
        defer self.sync(t);

        const seq = t.nextSeq();
        const req = try buildGetFamilyRequest(t.gpa, seq, family);
        defer t.gpa.free(req);
        try t.send(req);

        var found: ?u32 = null;
        while (true) {
            const dgram = try t.recvDatagram();
            var it: codec.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                // The shared dump triage: (portid, seq) matching, NLMSG_DONE /
                // bare-ACK termination, NLMSG_OVERRUN and a short NLMSG_ERROR
                // payload. `.restart` (NLM_F_DUMP_INTR) cannot reach a
                // GETFAMILY-by-name — that is the kernel's doit path, not a
                // dump — and a flagged reply is dropped rather than trusted.
                switch (codec.classifyDumpMessage(m, t.portid, seq)) {
                    .skip, .restart => {},
                    .done => return found,
                    .failed => |code| {
                        t.captureExtAck(m);
                        return resolveErrorFromCode(code);
                    },
                    .overrun => return error.SystemResources,
                    .malformed => return error.MalformedReply,
                    .record => |rec| {
                        if (rec.type != GENL_ID_CTRL) continue;
                        const p = splitPayload(rec.payload) catch return error.MalformedReply;
                        if (group) |want| {
                            // Sticky: a later reply message that carries no
                            // group nest must not erase an id already found.
                            found = (findMcastGroupId(p.attrs, want) catch
                                return error.MalformedReply) orelse found;
                        } else {
                            var attrs: codec.AttrIterator = .{ .buf = p.attrs };
                            while (attrs.next() catch return error.MalformedReply) |a| {
                                if (a.type == CTRL_ATTR_FAMILY_ID)
                                    found = a.asU16() catch return error.MalformedReply;
                            }
                        }
                    },
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

test "buildGetFamilyRequest rejects a name too long for GENL_NAMSIZ" {
    try testing.expectError(error.NameTooLong, buildGetFamilyRequest(
        testing.allocator,
        1,
        "a-family-name-way-too-long-for-genl-namsiz",
    ));
}

test "buildGetFamilyRequest: GENL_NAMSIZ boundary — one under fits, exactly at it rejects" {
    // GENL_NAMSIZ (16) includes the NUL terminator, so the longest name that
    // fits is 15 bytes; a name of exactly 16 bytes must be rejected even
    // though it is nowhere near the "way too long" case above.
    const fits = "a" ** (GENL_NAMSIZ - 1);
    const req = try buildGetFamilyRequest(testing.allocator, 1, fits);
    testing.allocator.free(req);

    const boundary = "a" ** GENL_NAMSIZ;
    try testing.expectError(error.NameTooLong, buildGetFamilyRequest(testing.allocator, 1, boundary));
}

test "splitPayload rejects a truncated genlmsghdr" {
    try testing.expectError(error.Truncated, splitPayload(&.{}));
    try testing.expectError(error.Truncated, splitPayload(&.{ 1, 1, 0 }));
    const p = try splitPayload(&.{ 0, 1, 0, 0, 0xaa });
    try testing.expectEqual(@as(u8, 0), p.cmd);
    try testing.expectEqualSlices(u8, &.{0xaa}, p.attrs);
}

test "splitPayload accepts a payload of exactly header_len bytes (empty attrs)" {
    // The boundary itself: exactly 4 bytes is a complete genlmsghdr with no
    // attributes following, not a truncation.
    const p = try splitPayload(&.{ 7, 1, 0, 0 });
    try testing.expectEqual(@as(u8, 7), p.cmd);
    try testing.expectEqualSlices(u8, &.{}, p.attrs);
}

test "appendHeader encodes cmd/version with a zeroed reserved field" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try appendHeader(testing.allocator, &list, 3, 1);
    try testing.expectEqualSlices(u8, &.{ 3, 1, 0, 0 }, list.items);
}

/// Build the `CTRL_ATTR_MCAST_GROUPS` half of a `CTRL_CMD_NEWFAMILY` reply:
/// a nest of one sub-nest per group, each carrying NAME + ID.
fn buildMcastGroupsAttrs(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    groups: []const struct { name: []const u8, id: u32 },
) !void {
    // A sibling attribute before the nest, to prove the walker skips it.
    try codec.appendAttrU16(gpa, list, CTRL_ATTR_FAMILY_ID, 0x1c);
    const outer = try codec.nestBegin(gpa, list, CTRL_ATTR_MCAST_GROUPS);
    for (groups, 1..) |g, idx| {
        const inner = try codec.nestBegin(gpa, list, @intCast(idx));
        try codec.appendAttrU32(gpa, list, CTRL_ATTR_MCAST_GRP_ID, g.id);
        try codec.appendAttrString(gpa, list, CTRL_ATTR_MCAST_GRP_NAME, g.name);
        codec.nestEnd(list, inner);
    }
    codec.nestEnd(list, outer);
}

// ── fuzz: genlmsghdr split + nlctrl attribute walk, never panic ────────────
//
// `splitPayload` and `findMcastGroupId` are the two byte-parsers this module
// runs directly against a kernel reply's payload before any interpretation —
// a genl reply is as untrusted as any other netlink datagram (a compromised
// or buggy kernel module, a malicious network namespace peer with
// CAP_NET_ADMIN, or simply a future kernel that reshapes the nlctrl wire
// format). `splitPayload` itself is a single length check, so the harness
// also drives `findMcastGroupId`'s nested-nest TLV walk (outer
// CTRL_ATTR_MCAST_GROUPS -> per-group nest -> NAME/ID) — the deeper,
// actually-interesting parser reachable from `splitPayload`'s output.

test "fuzz: splitPayload never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzSplitPayload, .{});
}

fn fuzzSplitPayload(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = splitPayload(buf[0..len]) catch {};
}

test "fuzz: findMcastGroupId never panics on arbitrary or structurally-nested attribute bytes" {
    try testing.fuzz({}, fuzzFindMcastGroupId, .{});
}

fn fuzzFindMcastGroupId(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;

    // Half the time: raw random bytes (the outer AttrIterator walk itself).
    // The other half: a structurally valid CTRL_ATTR_MCAST_GROUPS nest of
    // valid group sub-nests wrapping RANDOM name/id attribute bytes, so the
    // fuzzer reaches the inner nest walk and the name-comparison branch
    // instead of bailing out at the first `Truncated`/`BadLength`.
    const len: usize = if (smith.value(bool)) blk: {
        smith.bytes(&buf);
        break :blk smith.valueRangeAtMost(u16, 0, buf.len);
    } else blk: {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(testing.allocator);
        const outer = codec.nestBegin(testing.allocator, &list, CTRL_ATTR_MCAST_GROUPS) catch return;
        const n_groups = smith.valueRangeAtMost(u8, 0, 4);
        for (0..n_groups) |i| {
            const inner = codec.nestBegin(testing.allocator, &list, @intCast(i + 1)) catch return;
            if (smith.value(bool)) {
                codec.appendAttrU32(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_ID, smith.value(u32)) catch return;
            }
            var name_buf: [16]u8 = undefined;
            smith.bytes(&name_buf);
            const name_len: usize = smith.valueRangeAtMost(u8, 0, name_buf.len);
            codec.appendAttrString(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_NAME, name_buf[0..name_len]) catch return;
            codec.nestEnd(&list, inner);
        }
        codec.nestEnd(&list, outer);
        if (list.items.len > buf.len) return;
        @memcpy(buf[0..list.items.len], list.items);
        break :blk list.items.len;
    };

    var want_buf: [16]u8 = undefined;
    smith.bytes(&want_buf);
    const want_len: usize = smith.valueRangeAtMost(u8, 0, want_buf.len);
    _ = findMcastGroupId(buf[0..len], want_buf[0..want_len]) catch {};
}

test "findMcastGroupId picks the named group out of CTRL_ATTR_MCAST_GROUPS" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try buildMcastGroupsAttrs(testing.allocator, &list, &.{
        .{ .name = "config", .id = 5 },
        .{ .name = "scan", .id = 6 },
        .{ .name = "mlme", .id = 8 },
    });

    try testing.expectEqual(@as(?u32, 5), try findMcastGroupId(list.items, "config"));
    try testing.expectEqual(@as(?u32, 6), try findMcastGroupId(list.items, "scan"));
    try testing.expectEqual(@as(?u32, 8), try findMcastGroupId(list.items, "mlme"));
    // Absent group, and a prefix of a real one, are both "not published".
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(list.items, "vendor"));
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(list.items, "sca"));
    // A reply with no group nest at all.
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(&.{}, "scan"));
}

test "golden: findMcastGroupId decodes a real CTRL_ATTR_MCAST_GROUPS nest byte-for-byte" {
    // Captured shape of a CTRL_CMD_NEWFAMILY reply's mcast-group nest for
    // nlctrl itself (one group, "notify", id 0x15) — literal wire bytes per
    // linux/genetlink.h (CTRL_ATTR_MCAST_GRP_NAME = 1, _GRP_ID = 2), not
    // built via `codec.appendAttr*` with this module's own symbolic
    // constants. `buildMcastGroupsAttrs` below round-trips through those same
    // constants, so a swap of NAME/ID's numeric values would be invisible to
    // every other test in this file; this one pins the real kernel encoding.
    if (native_endian != .little) return error.SkipZigTest;
    const attrs = [_]u8{
        0x1c, 0x00, 0x07, 0x00, // outer nest, len 28, CTRL_ATTR_MCAST_GROUPS
        0x18, 0x00, 0x01, 0x00, // inner nest #1, len 24
        0x0b, 0x00, 0x01, 0x00, 'n', 'o', 't', 'i', 'f', 'y', 0x00, 0x00, // GRP_NAME=1 "notify" + pad
        0x08, 0x00, 0x02, 0x00, 0x15, 0x00, 0x00, 0x00, // GRP_ID=2, 0x15
    };
    try testing.expectEqual(@as(?u32, 0x15), try findMcastGroupId(&attrs, "notify"));
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(&attrs, "config"));
}

test "findMcastGroupId rejects a matching group with no id" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const outer = try codec.nestBegin(testing.allocator, &list, CTRL_ATTR_MCAST_GROUPS);
    const inner = try codec.nestBegin(testing.allocator, &list, 1);
    try codec.appendAttrString(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_NAME, "scan");
    codec.nestEnd(&list, inner);
    codec.nestEnd(&list, outer);

    try testing.expectError(error.BadLength, findMcastGroupId(list.items, "scan"));
}

test "findMcastGroupId reports a truncated nest instead of reading past it" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try buildMcastGroupsAttrs(testing.allocator, &list, &.{.{ .name = "scan", .id = 6 }});
    // Chop the last byte: the outer nest now claims more than is there.
    try testing.expectError(
        error.Truncated,
        findMcastGroupId(list.items[0 .. list.items.len - 1], "scan"),
    );
}

// ── integration tests (real kernel; unprivileged) ───────────────────────────

test "golden: real nlctrl CTRL_CMD_GETFAMILY request+reply captured from the live kernel" {
    // Unlike every other golden in this file, these bytes were not built by
    // hand from the UAPI header — both sides of an actual
    // `CTRL_CMD_GETFAMILY("nlctrl")` exchange were captured once against this
    // machine's real kernel (`Socket.send`/`recvDatagram`, unprivileged
    // NETLINK_GENERIC, seq fixed at 1 so the request side reproduces
    // byte-for-byte) and frozen here. This is what a swapped attribute
    // constant slips past when the offline goldens are all self-built: every
    // other golden in this file round-trips this module's OWN encoder against
    // its OWN decoder (or hand-typed bytes matching the encoder's own
    // constants), so a `CTRL_ATTR_MCAST_GRP_NAME`/`_ID` swap made consistently
    // in both directions would still pass every one of them. These bytes came
    // out of a real kernel that was never told our constant values, so they
    // fail if this module's parser stops agreeing with the kernel's actual
    // encoding. See NOTICE for the black-box-oracle provenance.
    if (native_endian != .little) return error.SkipZigTest;

    const captured_req = [_]u8{
        0x20, 0x00, 0x00, 0x00, // nlmsg_len = 32
        0x10, 0x00, // type = GENL_ID_CTRL
        0x05, 0x00, // flags = REQUEST | ACK
        0x01, 0x00, 0x00, 0x00, // seq = 1
        0x00, 0x00, 0x00, 0x00, // pid
        0x03, 0x01, 0x00, 0x00, // genlmsghdr: cmd GETFAMILY, version 1
        0x0b, 0x00, 0x02, 0x00, // attr len 11, CTRL_ATTR_FAMILY_NAME
        'n',  'l',  'c',  't',
        'r', 'l', 0x00, 0x00, // "nlctrl" + NUL + pad to 4
    };
    const req = try buildGetFamilyRequest(testing.allocator, 1, "nlctrl");
    defer testing.allocator.free(req);
    try testing.expectEqualSlices(u8, &captured_req, req);

    // The kernel's real CTRL_CMD_NEWFAMILY reply to that exact request: nlctrl
    // resolving itself. FAMILY_ID=0x10, VERSION=2, HDRSIZE=0, MAXATTR=0, an
    // OPS nest (two op ids, not modeled by this module), and the MCAST_GROUPS
    // nest with the real "notify" group and its real (kernel-assigned) id.
    const captured_reply = [_]u8{
        0x88, 0x00, 0x00, 0x00, // nlmsg_len = 136
        0x10, 0x00, // type = GENL_ID_CTRL
        0x00, 0x00, // flags
        0x01, 0x00, 0x00, 0x00, // seq = 1 (echoed)
        0x22, 0x09, 0x25, 0x00, // pid (kernel-assigned, opaque to this test)
        0x01, 0x02, 0x00, 0x00, // genlmsghdr: cmd NEWFAMILY, version 2
        0x0b, 0x00, 0x02, 0x00, 'n', 'l', 'c', 't', 'r', 'l', 0x00, 0x00, // FAMILY_NAME
        0x06, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, // FAMILY_ID = 0x10
        0x08, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, // CTRL_ATTR_VERSION = 2
        0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // CTRL_ATTR_HDRSIZE = 0
        0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // CTRL_ATTR_MAXATTR = 0
        0x2c, 0x00, 0x06, 0x00, // CTRL_ATTR_OPS nest, len 44 (2 op entries, unmodeled)
        0x14, 0x00, 0x01, 0x00,
        0x08, 0x00, 0x01, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00,
        0x0e, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x01, 0x00,
        0x0a, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00,
        0x0c, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x07, 0x00, // CTRL_ATTR_MCAST_GROUPS nest, len 28
        0x18, 0x00, 0x01, 0x00, // group entry #1, len 24
        0x08, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x00, // MCAST_GRP_ID = 0x10
        0x0b, 0x00, 0x01, 0x00, 'n', 'o', 't', 'i', 'f', 'y', 0x00, 0x00, // MCAST_GRP_NAME = "notify"
    };

    var it: codec.MessageIterator = .{ .buf = &captured_reply };
    const msg = (try it.next()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, GENL_ID_CTRL), msg.type);
    try testing.expectEqual(@as(?codec.Message, null), try it.next()); // exactly one record

    const p = try splitPayload(msg.payload);
    try testing.expectEqual(@as(u8, 1), p.cmd); // CTRL_CMD_NEWFAMILY

    var family_id: ?u16 = null;
    var attrs: codec.AttrIterator = .{ .buf = p.attrs };
    while (try attrs.next()) |a| {
        if (a.type == CTRL_ATTR_FAMILY_ID) family_id = try a.asU16();
    }
    try testing.expectEqual(@as(?u16, GENL_ID_CTRL), family_id);

    const notify_id = try findMcastGroupId(p.attrs, "notify");
    try testing.expectEqual(@as(?u32, 0x10), notify_id);
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(p.attrs, "config"));
}

test "integration: nlctrl family resolve (unprivileged)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var sock = Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer sock.close();

    // A family that certainly does not exist (short enough for the
    // GENL_NAMSIZ policy — a longer name would be EINVALed, not looked up).
    try testing.expectError(error.FamilyNotFound, sock.resolveFamily("zig-libs-nope"));
    try testing.expectError(error.NameTooLong, sock.resolveFamily("a-family-name-way-too-long"));

    // nlctrl always resolves to itself.
    const ctrl = try sock.resolveFamily("nlctrl");
    try testing.expectEqual(GENL_ID_CTRL, ctrl);
}

test "integration: nlctrl multicast group resolve (unprivileged)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var sock = Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer sock.close();

    // nlctrl publishes exactly one group, "notify" — the family-registration
    // notification channel. Its id is dynamic; only "nonzero" is guaranteed.
    const id = try sock.resolveMcastGroup("nlctrl", "notify");
    try testing.expect(id != 0);

    // A family that resolves but has no such group, and a family that does
    // not resolve at all, are distinct errors.
    try testing.expectError(error.GroupNotFound, sock.resolveMcastGroup("nlctrl", "zig-libs-nope"));
    try testing.expectError(error.FamilyNotFound, sock.resolveMcastGroup("zig-libs-nope", "notify"));
}

test "integration: the shared transport seam is reachable on a genl socket" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var sock = Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer sock.close();

    try testing.expect(sock.handle() >= 0);
    try testing.expectEqual(sock.fd, sock.handle());
    try testing.expect(sock.portid != 0);

    // A bounded receive on an idle socket must time out rather than hang, and
    // the two receive flavours must name that outcome differently.
    try sock.setRecvTimeout(50);
    try testing.expectError(error.WouldBlock, sock.recvDatagramStrict());
    try testing.expectError(error.RecvFailed, sock.recvDatagram());

    // The socket still works afterwards, and `seq` keeps advancing across
    // both the raw seam and the resolvers.
    try sock.setRecvTimeout(0);
    const before = sock.nextSeq();
    _ = try sock.resolveFamily("nlctrl");
    try testing.expect(sock.seq > before);
}

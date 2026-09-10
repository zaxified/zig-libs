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
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads. A corpus entry is
// not the frame — `Smith.slice` reads a little-endian u32 length first. See
// `testkit/src/fuzz.zig` for the three hazards it carries for the caller.
const testkit = @import("testkit");

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

/// nlctrl commands (CTRL_CMD_*). `NEWFAMILY` is the reply to `GETFAMILY`,
/// verified on every reply record (see F2 in the audit) so a `DELFAMILY`
/// notification or another control message can't be mistaken for one.
pub const CTRL_CMD_NEWFAMILY: u8 = 1;
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

/// GENL_MAX_ID — the highest genl id the kernel's dynamic allocator ever
/// hands out (`linux/genetlink.h`). The lower bound of that same range is
/// `GENL_ID_CTRL` itself (`GENL_MIN_ID == NLMSG_MIN_TYPE == GENL_ID_CTRL` in
/// the kernel header) — nlctrl resolving its own name returns exactly that
/// value, so the valid range for a resolved family id is `[GENL_ID_CTRL,
/// GENL_MAX_ID]` inclusive. Used to reject an out-of-range id in a reply
/// (F2).
pub const GENL_MAX_ID: u16 = 1023;

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
/// failure (`error.BadLength`): the kernel always emits both. So is a
/// matching entry whose id is 0 (F8): every genl multicast group id this
/// module has ever observed from a real kernel is dynamically assigned and
/// nonzero (this module's own integration test asserts exactly that —
/// `"Its id is dynamic; only nonzero is guaranteed"` — and the captured
/// `nlctrl`/`notify` golden below resolves to `0x15`), so an entry claiming
/// id 0 is as malformed as one claiming no id at all, not a group callers
/// should ever join.
///
/// `want.len == 0` never matches, even against a group entry whose own name
/// is empty (also F8): no genl family publishes an unnamed group, so an
/// empty `want` is a caller bug, not a lookup that should silently succeed
/// against whatever unnamed entry happens to come first.
pub fn findMcastGroupId(attr_bytes: []const u8, want: []const u8) codec.Error!?u32 {
    if (want.len == 0) return null;
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
                if (n.len == 0) continue;
                if (std.mem.eql(u8, n, want)) {
                    const v = id orelse return error.BadLength;
                    if (v == 0) return error.BadLength;
                    return v;
                }
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
    /// The reply loop consumed `max_reply_messages` datagrams without ever
    /// reaching `NLMSG_DONE`/a bare ACK for our request. Bug F1: previously
    /// unbounded — a kernel reply stream that never terminates the exchange
    /// (missing `NLMSG_DONE`, a stuck `NLM_F_DUMP_INTR` restart, or a flood
    /// of foreign-`seq` datagrams) spun `resolveFamily`/`resolveMcastGroup`
    /// forever.
    TooManyMessages,
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
        const id = (try self.ctrlGetFamily(name, .family_id)) orelse return error.MalformedReply;
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
        return (try self.ctrlGetFamily(family, .{ .one_group = group })) orelse error.GroupNotFound;
    }

    /// Resolve several of `family`'s multicast group names over a **single**
    /// `CTRL_CMD_GETFAMILY` round trip, instead of one round trip per name
    /// (audit finding F6: a caller joining N groups — `nl80211` joins 6+ on
    /// `open()` — used to pay N request/reply pairs for information the
    /// first reply already carried in full, since `findMcastGroupId` is a
    /// pure walk over bytes already in hand).
    ///
    /// `names` and `out` must have equal length; `out[i]` receives the id of
    /// `names[i]`, or stays `null` when the family does not publish a group
    /// under that name — same per-name outcome as `resolveMcastGroup`
    /// returning `error.GroupNotFound`, just not fatal to the rest of the
    /// batch. `error.FamilyNotFound` still fails the whole call, same as
    /// `resolveMcastGroup`.
    pub fn resolveMcastGroups(
        self: *Socket,
        family: []const u8,
        names: []const []const u8,
        out: []?u32,
    ) ResolveError!void {
        std.debug.assert(names.len == out.len);
        @memset(out, null);
        _ = try self.ctrlGetFamily(family, .{ .many_groups = .{ .names = names, .out = out } });
    }

    /// What one `CTRL_CMD_GETFAMILY` round trip is being asked to extract
    /// from the resolved family's reply, besides the family's own identity
    /// (name and id), which `ctrlGetFamilyOver` verifies unconditionally.
    const FamilyQuery = union(enum) {
        /// `resolveFamily`: the answer is `CTRL_ATTR_FAMILY_ID` itself.
        family_id,
        /// `resolveMcastGroup`: one group name, resolved to its id.
        one_group: []const u8,
        /// `resolveMcastGroups`: many group names resolved over the same
        /// reply (F6). `names[i]` -> `out[i]`.
        many_groups: struct { names: []const []const u8, out: []?u32 },
    };

    /// The one nlctrl round trip every resolver shares: send
    /// `CTRL_CMD_GETFAMILY(family)`, then hand the reply stream to
    /// `ctrlGetFamilyOver`.
    ///
    /// F3: `lastErrorMessage()` must not outlive the request it describes —
    /// cleared here, unconditionally, before the request is even sent, same
    /// as `netlink.Socket.awaitAckStrict` clears its own `ext_ack_len`/
    /// `last_errno` before each bounded engine call.
    ///
    /// F7: the `GENL_NAMSIZ` guard runs before `nextSeq()` is ever called, so
    /// an oversized name never spends a sequence number on a request that is
    /// never built or sent.
    fn ctrlGetFamily(self: *Socket, family: []const u8, query: FamilyQuery) ResolveError!?u32 {
        if (family.len >= GENL_NAMSIZ) return error.NameTooLong;

        var t = self.transport();
        defer self.sync(t);
        t.ext_ack_len = 0;

        const seq = t.nextSeq();
        const req = try buildGetFamilyRequest(t.gpa, seq, family);
        defer t.gpa.free(req);
        try t.send(req);

        return ctrlGetFamilyOver(&t, family, query, seq);
    }
};

/// Message budget for the nlctrl reply loop below — mirrors `netlink`'s
/// `max_await_messages`/`max_dump_messages`. A reply stream that never
/// reaches `NLMSG_DONE`/a bare ACK for our `seq` used to spin the loop
/// forever: no terminator (audit F1 shape a), a stream of `NLM_F_DUMP_INTR`
/// replies that `.restart` drops without acting on (shape b — the one
/// SPEC's row 9 called impossible for a by-name lookup; the budget no longer
/// depends on that holding), or a flood of foreign-`seq` datagrams (shape
/// c). `ctrlGetFamilyOver` is the bounded engine, factored out so a scripted
/// transport can drive it without a real socket.
const max_reply_messages: u32 = 65536;

/// The receive half of `Socket.ctrlGetFamily`: consume replies to `seq`
/// until `NLMSG_DONE`/a bare ACK, an error, or `max_reply_messages`
/// datagrams (`error.TooManyMessages`, F1). `transport` must offer
/// `recvDatagram()`, `portId()` and `captureExtAck(msg)` — `netlink.Socket`
/// and the `GenlScripted` test fixture below both do.
///
/// F2: a reply record is accepted only if **all three** of its identity axes
/// agree with what was asked for: `CTRL_CMD_NEWFAMILY` (not `DELFAMILY` or
/// any other control command), `CTRL_ATTR_FAMILY_NAME` present and equal to
/// `family` byte-for-byte (the real kernel always echoes it — see the
/// "golden: real nlctrl" test — so requiring it costs nothing and closes the
/// NUL-truncation confusion: a `family` slice with an embedded NUL and
/// trailing garbage can never equal the echoed name, which the kernel reads
/// only up to its own NUL), and `CTRL_ATTR_FAMILY_ID` inside
/// `[GENL_ID_CTRL, GENL_MAX_ID]`, the kernel's own dynamic-id range. Any
/// other combination is `error.MalformedReply`, same vocabulary the wire
/// already uses for a hostile/malformed datagram.
fn ctrlGetFamilyOver(
    transport: anytype,
    family: []const u8,
    query: Socket.FamilyQuery,
    seq: u32,
) ResolveError!?u32 {
    var found: ?u32 = null;
    var msgs: u32 = 0;
    while (true) {
        if (msgs >= max_reply_messages) return error.TooManyMessages;
        const dgram = try transport.recvDatagram();
        msgs += 1;
        var it: codec.MessageIterator = .{ .buf = dgram };
        while (it.next() catch return error.MalformedReply) |m| {
            // The shared dump triage: (portid, seq) matching, NLMSG_DONE /
            // bare-ACK termination, NLMSG_OVERRUN and a short NLMSG_ERROR
            // payload. A `.restart` (NLM_F_DUMP_INTR) reply is dropped
            // rather than trusted — see `max_reply_messages` above for why
            // that no longer needs the "cannot occur" claim to be safe.
            switch (codec.classifyDumpMessage(m, transport.portId(), seq)) {
                .skip, .restart => {},
                .done => return found,
                .failed => |code| {
                    transport.captureExtAck(m);
                    return resolveErrorFromCode(code);
                },
                .overrun => return error.SystemResources,
                .malformed => return error.MalformedReply,
                .record => |rec| {
                    if (rec.type != GENL_ID_CTRL) continue;
                    const p = splitPayload(rec.payload) catch return error.MalformedReply;
                    if (p.cmd != CTRL_CMD_NEWFAMILY) return error.MalformedReply;
                    switch (query) {
                        .family_id => {
                            var attrs: codec.AttrIterator = .{ .buf = p.attrs };
                            var name_ok = false;
                            var id: ?u16 = null;
                            while (attrs.next() catch return error.MalformedReply) |a| {
                                switch (a.type) {
                                    CTRL_ATTR_FAMILY_NAME => name_ok = std.mem.eql(u8, a.asString(), family),
                                    CTRL_ATTR_FAMILY_ID => id = a.asU16() catch return error.MalformedReply,
                                    else => {},
                                }
                            }
                            if (id) |v| {
                                if (!name_ok) return error.MalformedReply;
                                if (v < GENL_ID_CTRL or v > GENL_MAX_ID) return error.MalformedReply;
                                found = v;
                            }
                        },
                        .one_group => |want| {
                            // Sticky: a later reply message that carries no
                            // group nest must not erase an id already found.
                            found = (findMcastGroupId(p.attrs, want) catch
                                return error.MalformedReply) orelse found;
                        },
                        .many_groups => |batch| {
                            for (batch.names, batch.out) |want, *slot| {
                                slot.* = (findMcastGroupId(p.attrs, want) catch
                                    return error.MalformedReply) orelse slot.*;
                            }
                        },
                    }
                },
            }
        }
    }
}

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
        try codec.nestEnd(list, inner);
    }
    try codec.nestEnd(list, outer);
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

/// genl payloads for `fuzzSplitPayload`, in the format `Smith.slice` reads
/// (see `testkit.fuzz`): a little-endian u32 length, then the frame.
///
/// ⭐ Built at run time by this module's and `codec`'s own encoders rather than
/// quoted as hex. The genlmsghdr itself is byte-order-free, but everything
/// after it is a netlink TLV, whose lengths and scalars are HOST byte order —
/// a hex corpus would be a little-endian one and the pinned counts below would
/// be false on a big-endian target rather than failing there.
const Corpus = struct {
    scratch: [2048]u8 = undefined,
    store: [2048]u8 = undefined,
    used: usize = 0,
    entries: [8][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *Corpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *Corpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // A bare genlmsghdr: the shortest payload `splitPayload` accepts, and
        // the one whose attribute list is empty.
        var bare: std.ArrayList(u8) = .empty;
        try appendHeader(gpa, &bare, CTRL_CMD_GETFAMILY, 1);
        self.push(bare.items);

        // A CTRL_CMD_NEWFAMILY-shaped reply: genlmsghdr, a family id, and the
        // mcast-group nest `findMcastGroupId` walks.
        var reply: std.ArrayList(u8) = .empty;
        try appendHeader(gpa, &reply, 1, 2); // CTRL_CMD_NEWFAMILY, version 2
        try buildMcastGroupsAttrs(gpa, &reply, &.{
            .{ .name = "config", .id = 5 },
            .{ .name = "scan", .id = 6 },
        });
        self.push(reply.items);

        // The same reply with its last octet chopped: the outer nest now
        // claims more than is there.
        self.push(reply.items[0 .. reply.items.len - 1]);

        // Header plus an attribute whose declared length runs past the buffer.
        var overrun: std.ArrayList(u8) = .empty;
        try appendHeader(gpa, &overrun, 1, 2);
        var bad: [4]u8 = undefined;
        std.mem.writeInt(u16, bad[0..2], 200, native_endian);
        std.mem.writeInt(u16, bad[2..4], CTRL_ATTR_FAMILY_ID, native_endian);
        try overrun.appendSlice(gpa, &bad);
        self.push(overrun.items);

        // One and three octets: shorter than the 4-byte genlmsghdr, which is
        // the only thing `splitPayload` itself checks.
        self.push(&[_]u8{0x03});
        self.push(&[_]u8{ 0x03, 0x01, 0x00 });

        return self.entries[0..self.n];
    }
};

test "fuzz: splitPayload never panics on arbitrary bytes" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzSplitPayload, .{ .corpus = try corpus.build() });
}

fn fuzzSplitPayload(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `splitPayload` was handed an empty
    // slice with the payload sitting unread in `buf`. Measured 2026-09-07 over
    // the corpus above: **0 of 6 seeds non-empty and 0 accepted before, 6 of 6
    // non-empty and 4 accepted after.**
    const len: usize = smith.slice(&buf);
    _ = splitPayload(buf[0..len]) catch {};
}

test "corpus: every splitPayload seed reaches it, and the accepted count is pinned" {
    // ⭐ The measurement, executable rather than in a comment, over the SAME
    // corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the 64-octet buffer, which
    // `Smith.slice` reads back as the empty one. `accepted` is pinned rather
    // than asserted `> 0` — and it matters here more than usual, because
    // `splitPayload` accepts anything four octets or longer, so a corpus of
    // nothing but 4-byte headers would score full marks while walking nothing.
    // `attrs` is what says the attribute list behind the header is real.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var attrs: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (splitPayload(buf[0..len])) |split| {
            accepted += 1;
            var it: codec.AttrIterator = .{ .buf = split.attrs };
            while (it.next() catch null) |_| attrs += 1;
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 4), accepted);
    try testing.expectEqual(@as(usize, 3), attrs);
}

/// Attribute blobs and the group name to look for, laid out the way
/// `fuzzFindMcastGroupId` draws them: two `testkit.fuzz` slice seeds back to
/// back (u32 length + bytes, twice).
///
/// The attribute bytes come from `buildMcastGroupsAttrs` at run time, so the
/// corpus tracks this module's encoder instead of freezing a paste of it.
const FindCorpus = struct {
    scratch: [2048]u8 = undefined,
    store: [4096]u8 = undefined,
    used: usize = 0,
    entries: [8][]const u8 = undefined,
    wants: [8][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *FindCorpus, attrs: []const u8, want: []const u8) void {
        const a = testkit.fuzz.seedInto(self.store[self.used..], attrs);
        const b = testkit.fuzz.seedInto(self.store[self.used + a.len ..], want);
        self.entries[self.n] = self.store[self.used..][0 .. a.len + b.len];
        self.wants[self.n] = want;
        self.used += a.len + b.len;
        self.n += 1;
    }

    fn build(self: *FindCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        var groups: std.ArrayList(u8) = .empty;
        try buildMcastGroupsAttrs(gpa, &groups, &.{
            .{ .name = "config", .id = 5 },
            .{ .name = "scan", .id = 6 },
            .{ .name = "mlme", .id = 8 },
        });
        // A name that is published, one that is not, and a prefix of a real
        // one — the three outcomes of the comparison branch.
        self.push(groups.items, "scan");
        self.push(groups.items, "vendor");
        self.push(groups.items, "sca");
        // The truncated nest: the outer length now claims more than is there.
        self.push(groups.items[0 .. groups.items.len - 1], "scan");

        // A matching group with no id at all — `error.BadLength`, the one
        // refusal this function raises about its own contents rather than
        // about the framing.
        var noid: std.ArrayList(u8) = .empty;
        {
            const outer = try codec.nestBegin(gpa, &noid, CTRL_ATTR_MCAST_GROUPS);
            const inner = try codec.nestBegin(gpa, &noid, 1);
            try codec.appendAttrString(gpa, &noid, CTRL_ATTR_MCAST_GRP_NAME, "scan");
            try codec.nestEnd(&noid, inner);
            try codec.nestEnd(&noid, outer);
        }
        self.push(noid.items, "scan");

        // An empty outer nest, and attribute bytes that are not a nest at all.
        var empty: std.ArrayList(u8) = .empty;
        {
            const outer = try codec.nestBegin(gpa, &empty, CTRL_ATTR_MCAST_GROUPS);
            try codec.nestEnd(&empty, outer);
        }
        self.push(empty.items, "scan");

        var sibling: std.ArrayList(u8) = .empty;
        try codec.appendAttrU16(gpa, &sibling, CTRL_ATTR_FAMILY_ID, 0x1c);
        self.push(sibling.items, "scan");

        return self.entries[0..self.n];
    }
};

test "fuzz: findMcastGroupId never panics on arbitrary or structurally-nested attribute bytes" {
    var corpus: FindCorpus = .{};
    try testing.fuzz({}, fuzzFindMcastGroupId, .{ .corpus = try corpus.build() });
}

fn fuzzFindMcastGroupId(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    var want_buf: [16]u8 = undefined;
    // ⚠ The bytes come FIRST, in one `slice` call each. This harness used to
    // open with `smith.value(bool)` to pick between a raw walk and a
    // structured one — a 1-bit draw, which outside `--fuzz` is the range
    // MINIMUM for all but 1 in 2^63 seeds, so the raw branch was dead and the
    // seed was discarded before a single octet of it had been read. Inside the
    // surviving branch `n_groups` was `valueRangeAtMost(u8, 0, 4)`, also the
    // minimum, so the nest it built had ZERO groups: the inner nest walk and
    // the name comparison that branch exists for were never reached either.
    // Both halves now run on every seed, from the same drawn octets. Measured
    // 2026-09-07 over the corpus above: **not one of the 7 seeds contributed a
    // single octet before — the harness built the identical 4-octet empty nest
    // for every one of them, 0 group ids found and 0 refusals — against 7 of 7
    // seeds non-empty, 1 id found and 2 refused after.**
    const attrs_len: usize = smith.slice(&buf);
    const want_len: usize = smith.slice(&want_buf);
    const want = want_buf[0..want_len];

    // (a) The raw walk: the drawn octets straight into the outer iterator.
    _ = findMcastGroupId(buf[0..attrs_len], want) catch {};

    // (b) The structured walk: the same octets carved into group NAME
    //     attributes inside a well-formed CTRL_ATTR_MCAST_GROUPS nest, so the
    //     inner walk and the name comparison are reached even when the drawn
    //     bytes are not a valid nest.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const outer = codec.nestBegin(testing.allocator, &list, CTRL_ATTR_MCAST_GROUPS) catch return;
    const n_groups: usize = @intCast(smith.value(u64) % 5);
    var off: usize = 0;
    for (0..n_groups) |i| {
        const inner = codec.nestBegin(testing.allocator, &list, @intCast(i + 1)) catch return;
        if (smith.eos()) {
            codec.appendAttrU32(
                testing.allocator,
                &list,
                CTRL_ATTR_MCAST_GRP_ID,
                @truncate(smith.value(u64)),
            ) catch return;
        }
        const take = @min(attrs_len - off, @as(usize, 16));
        codec.appendAttrString(
            testing.allocator,
            &list,
            CTRL_ATTR_MCAST_GRP_NAME,
            buf[off..][0..take],
        ) catch return;
        off += take;
        codec.nestEnd(&list, inner) catch return;
    }
    codec.nestEnd(&list, outer) catch return;
    _ = findMcastGroupId(list.items, want) catch {};
}

test "corpus: every findMcastGroupId seed reaches the walk, and the counts are pinned" {
    // ⭐ The measurement, executable rather than in a comment, over the SAME
    // corpus the harness gets. `found` is pinned rather than asserted `> 0`:
    // `findMcastGroupId` answers `null` for "walked the whole nest and the
    // group is not published", which is a success, so a corpus that never
    // matched anything would look exactly as healthy as this one.
    var corpus: FindCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var found: usize = 0;
    var refused: usize = 0;
    for (entries, corpus.wants[0..corpus.n]) |sd, want| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        var want_buf: [16]u8 = undefined;
        const attrs_len: usize = smith.slice(&buf);
        const want_len: usize = smith.slice(&want_buf);
        if (attrs_len != 0) nonempty += 1;
        try testing.expectEqualSlices(u8, want, want_buf[0..want_len]);
        if (findMcastGroupId(buf[0..attrs_len], want_buf[0..want_len])) |id| {
            if (id != null) found += 1;
        } else |_| refused += 1;
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 1), found);
    try testing.expectEqual(@as(usize, 2), refused);
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
    try codec.nestEnd(&list, inner);
    try codec.nestEnd(&list, outer);

    try testing.expectError(error.BadLength, findMcastGroupId(list.items, "scan"));
}

test "F8: findMcastGroupId rejects a matching group whose id is 0" {
    // Every id this module has ever observed from a real kernel is nonzero
    // (see the golden captures below); id 0 on a name match is as malformed
    // as no id at all, not a group a caller should join.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const outer = try codec.nestBegin(testing.allocator, &list, CTRL_ATTR_MCAST_GROUPS);
    const inner = try codec.nestBegin(testing.allocator, &list, 1);
    try codec.appendAttrString(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_NAME, "peers");
    try codec.appendAttrU32(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_ID, 0);
    try codec.nestEnd(&list, inner);
    try codec.nestEnd(&list, outer);

    try testing.expectError(error.BadLength, findMcastGroupId(list.items, "peers"));

    // Positive control: the same shape with a nonzero id must still resolve.
    var ok: std.ArrayList(u8) = .empty;
    defer ok.deinit(testing.allocator);
    try buildMcastGroupsAttrs(testing.allocator, &ok, &.{.{ .name = "peers", .id = 7 }});
    try testing.expectEqual(@as(?u32, 7), try findMcastGroupId(ok.items, "peers"));
}

test "F8: findMcastGroupId never matches an empty query against an empty group name" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const outer = try codec.nestBegin(testing.allocator, &list, CTRL_ATTR_MCAST_GROUPS);
    const inner = try codec.nestBegin(testing.allocator, &list, 1);
    try codec.appendAttrString(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_NAME, "");
    try codec.appendAttrU32(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_ID, 42);
    try codec.nestEnd(&list, inner);
    try codec.nestEnd(&list, outer);

    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(list.items, ""));
    // Positive control: a real name against the same nest still misses (the
    // group published is unnamed, not "peers").
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(list.items, "peers"));
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

test "F7: a name too long for GENL_NAMSIZ is rejected before a sequence number is spent" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var sock = Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer sock.close();

    const before = sock.seq;
    try testing.expectError(error.NameTooLong, sock.resolveFamily("a-family-name-way-too-long"));
    try testing.expectEqual(before, sock.seq);

    // Positive control: a request that actually gets built and sent still
    // advances `seq` — the guard above must not have swallowed the counter
    // altogether.
    _ = try sock.resolveFamily("nlctrl");
    try testing.expect(sock.seq > before);
}

test "F3: lastErrorMessage does not survive into the next, unrelated request" {
    // Real reproduction of a *stale, wrong-errno* message needs a kernel that
    // attaches an extended-ACK reason to ENOENT, which this host's does not
    // (see genetlink.md F3) — so this drives the socket's own state directly,
    // which is exactly what `ctrlGetFamily` must clear regardless of why it
    // was set. Before the fix, `ext_ack_len` was never touched by a
    // successful call, so the stale text would still read back afterwards.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var sock = Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer sock.close();

    const stale = "stale reason from an earlier, unrelated failure";
    @memcpy(sock.ext_ack_buf[0..stale.len], stale);
    sock.ext_ack_len = stale.len;
    try testing.expectEqualStrings(stale, sock.lastErrorMessage());

    _ = try sock.resolveFamily("nlctrl");
    try testing.expectEqual(@as(usize, 0), sock.lastErrorMessage().len);
}

test "integration: resolveMcastGroups resolves several names over one round trip (F6)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var sock = Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer sock.close();

    var out: [3]?u32 = undefined;
    try sock.resolveMcastGroups("nlctrl", &.{ "notify", "zig-libs-nope", "notify" }, &out);
    try testing.expect(out[0] != null and out[0].? != 0);
    try testing.expectEqual(@as(?u32, null), out[1]);
    try testing.expectEqual(out[0], out[2]);

    // Positive control: matches what the single-name resolver returns.
    const single = try sock.resolveMcastGroup("nlctrl", "notify");
    try testing.expectEqual(single, out[0].?);

    // FamilyNotFound still fails the whole batch.
    try testing.expectError(
        error.FamilyNotFound,
        sock.resolveMcastGroups("zig-libs-nope", &.{"notify"}, out[0..1]),
    );
}

// ── scripted-transport tests: the reply loop itself (F1, F2, F4) ───────────
//
// `ctrlGetFamily`'s receive loop makes real syscalls through `netlink.Socket`,
// so mutating its behaviour was previously unreachable from `zig build
// test-genetlink` without a live or faked kernel (audit F4: 10 mutations to
// this loop passed 16/16 green). `ctrlGetFamilyOver` is the same loop
// factored out over an `anytype` transport — same shape `netlink`'s own
// `awaitAckOver`/`dumpOver` already use for exactly this reason — so it runs
// here against a scripted transport instead: deterministic, no socket, no
// namespace, no privilege.

/// A transport that satisfies `ctrlGetFamilyOver`'s shape without a socket.
/// Scripted datagrams are delivered in order; once they run out, `filler` is
/// returned forever (or `error.RecvFailed` if there is none) — the same
/// design as `netlink`'s own `ScriptedTransport`.
const GenlScripted = struct {
    script: []const []const u8 = &.{},
    filler: ?[]const u8 = null,
    pos: usize = 0,
    recvs: usize = 0,
    pid: u32,
    ext_ack_len: usize = 0,
    ext_ack_buf: [64]u8 = @splat(0),

    fn portId(self: *const GenlScripted) u32 {
        return self.pid;
    }
    fn captureExtAck(self: *GenlScripted, m: codec.Message) void {
        self.ext_ack_len = 0;
        const msg = (m.errorMessage() catch return) orelse return;
        const n = @min(msg.len, self.ext_ack_buf.len);
        @memcpy(self.ext_ack_buf[0..n], msg[0..n]);
        self.ext_ack_len = n;
    }
    fn recvDatagram(self: *GenlScripted) RecvError![]const u8 {
        self.recvs += 1;
        if (self.pos < self.script.len) {
            defer self.pos += 1;
            return self.script[self.pos];
        }
        return self.filler orelse error.RecvFailed;
    }
};

/// Build one `CTRL_CMD_GETFAMILY` reply record (genl type = `GENL_ID_CTRL`)
/// naming `name`/`id`, for the scripted-transport tests below.
fn buildFamilyReply(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    cmd: u8,
    seq: u32,
    pid: u32,
    name: ?[]const u8,
    id: ?u16,
) !void {
    const h = try codec.appendHeader(gpa, list, GENL_ID_CTRL, 0, seq, pid);
    try appendHeader(gpa, list, cmd, 2);
    if (name) |n| try codec.appendAttrString(gpa, list, CTRL_ATTR_FAMILY_NAME, n);
    if (id) |v| try codec.appendAttrU16(gpa, list, CTRL_ATTR_FAMILY_ID, v);
    codec.finishHeader(list, h);
}

/// Append a bare ACK (`NLMSG_ERROR`, errno 0) for (`seq`, `pid`) — the
/// terminator a `CTRL_CMD_GETFAMILY` reply needs after its data record.
fn appendBareAck(gpa: std.mem.Allocator, list: *std.ArrayList(u8), seq: u32, pid: u32) !void {
    const h = try codec.appendHeader(gpa, list, codec.NLMSG_ERROR, 0, seq, pid);
    try list.appendSlice(gpa, &[_]u8{ 0, 0, 0, 0 });
    codec.finishHeader(list, h);
}

test "ctrlGetFamilyOver: positive control — a well-formed matching reply resolves" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try buildFamilyReply(testing.allocator, &list, CTRL_CMD_NEWFAMILY, 42, 7, "nlctrl", GENL_ID_CTRL);
    try appendBareAck(testing.allocator, &list, 42, 7);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectEqual(
        @as(?u32, @as(u32, GENL_ID_CTRL)),
        try ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42),
    );
    try testing.expectEqual(@as(usize, 1), t.recvs);
}

test "F1: ctrlGetFamilyOver gives up instead of spinning when the reply never terminates" {
    // Shape (a) from the audit: no NLMSG_DONE, no ACK — a NOOP addressed to
    // us on our own seq, forever. Without a budget this loop never returns.
    var noop: std.ArrayList(u8) = .empty;
    defer noop.deinit(testing.allocator);
    const h = try codec.appendHeader(testing.allocator, &noop, codec.NLMSG_NOOP, 0, 42, 7);
    codec.finishHeader(&noop, h);

    var t: GenlScripted = .{ .filler = noop.items, .pid = 7 };
    try testing.expectError(error.TooManyMessages, ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
    try testing.expectEqual(@as(usize, max_reply_messages), t.recvs);
}

test "F1: a stream of NLM_F_DUMP_INTR replies (SPEC row 9's 'cannot occur' case) still terminates" {
    // Shape (b) from the audit: `.restart` is dropped like `.skip`, so a
    // kernel that only ever sends DUMP_INTR-flagged replies used to hang
    // forever regardless of whether a real nlctrl would do this.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const h = try codec.appendHeader(testing.allocator, &list, GENL_ID_CTRL, codec.NLM_F_DUMP_INTR, 42, 7);
    codec.finishHeader(&list, h);

    var t: GenlScripted = .{ .filler = list.items, .pid = 7 };
    try testing.expectError(error.TooManyMessages, ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
}

test "F2: a reply naming a different family than requested is rejected" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try buildFamilyReply(testing.allocator, &list, CTRL_CMD_NEWFAMILY, 42, 7, "nlctrl", GENL_ID_CTRL);
    try appendBareAck(testing.allocator, &list, 42, 7);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectError(error.MalformedReply, ctrlGetFamilyOver(&t, "wireguard", .family_id, 42));
}

test "F2: a reply with no CTRL_ATTR_FAMILY_NAME at all is rejected" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try buildFamilyReply(testing.allocator, &list, CTRL_CMD_NEWFAMILY, 42, 7, null, GENL_ID_CTRL);
    try appendBareAck(testing.allocator, &list, 42, 7);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectError(error.MalformedReply, ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
}

test "F2: a CTRL_CMD_DELFAMILY payload is rejected, not parsed as a resolution" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try buildFamilyReply(testing.allocator, &list, 2, 42, 7, "nlctrl", GENL_ID_CTRL); // 2 = CTRL_CMD_DELFAMILY
    try appendBareAck(testing.allocator, &list, 42, 7);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectError(error.MalformedReply, ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
}

test "F2: a family id outside [GENL_ID_CTRL, GENL_MAX_ID] is rejected" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    // id = 3, the numeric value of NLMSG_DONE — the audit's own live probe.
    try buildFamilyReply(testing.allocator, &list, CTRL_CMD_NEWFAMILY, 42, 7, "nlctrl", 3);
    try appendBareAck(testing.allocator, &list, 42, 7);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectError(error.MalformedReply, ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
}

test "F4: a reply from a foreign portid is skipped, not accepted as ours" {
    // A record from a foreign pid must be skipped, not accepted — the exact
    // axis the audit's F4 found the module-level gate blind to (10 mutations
    // to this loop, including deleting the (portid, seq) match, passed
    // `zig build test-genetlink` 16/16 green). Skipped forever (a foreign
    // pid never satisfies our DONE either) surfaces as the F1 budget, which
    // is itself evidence the record was never treated as ours.
    var only: std.ArrayList(u8) = .empty;
    defer only.deinit(testing.allocator);
    try buildFamilyReply(testing.allocator, &only, CTRL_CMD_NEWFAMILY, 42, 999, "nlctrl", GENL_ID_CTRL);

    var t: GenlScripted = .{ .filler = only.items, .pid = 7 }; // foreign pid throughout
    try testing.expectError(error.TooManyMessages, ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
}

test "F4: a record whose genl type is not GENL_ID_CTRL is ignored" {
    // The `if (rec.type != GENL_ID_CTRL) continue;` filter, mutated away in
    // the audit's F4 battery without a single test noticing (an earlier
    // version of this test used `.filler` — an infinite repeat of the
    // wrongly-typed record — which converges to `error.TooManyMessages`
    // whether or not the filter runs, so it could not actually distinguish
    // them; caught by mutating the filter away during this fix and finding
    // 34/35 still green). A record typed for some other genl family (e.g.
    // `nl80211`'s own dynamic id, modelled here as 0x99), followed by a
    // real terminating ACK, must be skipped rather than read as the
    // `CTRL_CMD_NEWFAMILY` reply it looks like: the resolve completes
    // (reaches the ACK) but finds nothing, `null`, not the id the
    // wrongly-typed record carried.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const h = try codec.appendHeader(testing.allocator, &list, 0x99, 0, 42, 7);
    try appendHeader(testing.allocator, &list, CTRL_CMD_NEWFAMILY, 2);
    try codec.appendAttrString(testing.allocator, &list, CTRL_ATTR_FAMILY_NAME, "nlctrl");
    try codec.appendAttrU16(testing.allocator, &list, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
    codec.finishHeader(&list, h);
    try appendBareAck(testing.allocator, &list, 42, 7);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectEqual(@as(?u32, null), try ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
}

test "F4: a group id already found survives a later record that carries no group nest (sticky)" {
    // The one deliberate hardening SPEC already documents ("One deliberate
    // hardening over the copies") — `found = find(...) orelse found` — had
    // no test of its own: a mutation removing the `orelse found` (plain
    // assignment instead) passed the module's gate green. Two records in
    // one reply: the first carries the group nest, the second carries none.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    // First record: genlmsghdr + FAMILY_NAME/_ID + the group nest, all
    // inside ONE nlmsghdr (finishHeader closes it after everything is in).
    {
        const h = try codec.appendHeader(testing.allocator, &list, GENL_ID_CTRL, 0, 42, 7);
        try appendHeader(testing.allocator, &list, CTRL_CMD_NEWFAMILY, 2);
        try codec.appendAttrString(testing.allocator, &list, CTRL_ATTR_FAMILY_NAME, "nlctrl");
        try codec.appendAttrU16(testing.allocator, &list, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
        const outer = try codec.nestBegin(testing.allocator, &list, CTRL_ATTR_MCAST_GROUPS);
        const inner = try codec.nestBegin(testing.allocator, &list, 1);
        try codec.appendAttrString(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_NAME, "notify");
        try codec.appendAttrU32(testing.allocator, &list, CTRL_ATTR_MCAST_GRP_ID, 5);
        try codec.nestEnd(&list, inner);
        try codec.nestEnd(&list, outer);
        codec.finishHeader(&list, h);
    }
    // A second, separate record in the same reply: same family, no group
    // nest at all — this must not erase the id the first record found.
    try buildFamilyReply(testing.allocator, &list, CTRL_CMD_NEWFAMILY, 42, 7, "nlctrl", GENL_ID_CTRL);
    try appendBareAck(testing.allocator, &list, 42, 7);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectEqual(
        @as(?u32, 5),
        try ctrlGetFamilyOver(&t, "nlctrl", .{ .one_group = "notify" }, 42),
    );
}

test "F4: NLMSG_OVERRUN is a typed error, not a silent skip" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const h = try codec.appendHeader(testing.allocator, &list, codec.NLMSG_OVERRUN, 0, 42, 7);
    codec.finishHeader(&list, h);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectError(error.SystemResources, ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
}

test "F4: a short NLMSG_ERROR payload is a typed error, not a silent skip" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const h = try codec.appendHeader(testing.allocator, &list, codec.NLMSG_ERROR, 0, 42, 7);
    try list.appendSlice(testing.allocator, &[_]u8{ 0, 0 }); // < 4 bytes: too short for errorCode()
    codec.finishHeader(&list, h);

    var t: GenlScripted = .{ .script = &.{list.items}, .pid = 7 };
    try testing.expectError(error.MalformedReply, ctrlGetFamilyOver(&t, "nlctrl", .family_id, 42));
}

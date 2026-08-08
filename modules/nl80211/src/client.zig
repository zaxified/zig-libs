// SPDX-License-Identifier: MIT
//! The nl80211 client: one `NETLINK_GENERIC` socket plus the resolved
//! `nl80211` family id, the typed commands built on top, and a separate
//! **event socket** for the multicast groups scan/MLME/regulatory
//! notifications arrive on.
//!
//! ## The blocking seam
//!
//! Command methods (`wiphys`, `scanResults`, `connect`, …) are ordinary
//! blocking request/reply calls: they send, then read until the kernel's ACK
//! or `NLMSG_DONE`.
//!
//! Events are different, and this module refuses to hide that. **`EventSocket`
//! has exactly one blocking call — `waitForEvent`** — and it does exactly one
//! `recvmsg` when its buffer is drained. There is no timer thread, no deadline
//! and no event loop here: a caller that wants a bounded wait polls `fd()`
//! itself and only calls `waitForEvent` once the fd is readable. That is the
//! same seam discipline the sibling `netconf` (`Client.pumpOnce`) and `ebpf`
//! (ring-buffer consumer) modules use, and for the same reason — threading
//! policy belongs to the application, not to a protocol library.
//!
//! ## Why the event socket is separate
//!
//! Multicast membership is per-socket. Subscribing the *command* socket would
//! mean every dump loop had to filter out unsolicited events that interleave
//! with its replies, and an event arriving between two dump messages would sit
//! in the command socket's queue. A dedicated socket keeps both paths simple
//! and lets the caller poll the event fd independently.
//!
//! Note the ordering hazard `scan.zig` documents: **subscribe before
//! triggering**, or the completion event can fire in the gap and be lost.
//!
//! ## Multicast group resolution now lives in `genetlink`
//!
//! It used to live here: nl80211 was the first family that needed group ids,
//! so the nlctrl reply walk was written in this file with a note saying *"if a
//! second family ever needs it, this is the code to promote into
//! `genetlink`"*. Two more families needed it (`ethtool`, then `devlink`), so
//! it was promoted — `genetlink.findMcastGroupId` is the pure function and
//! `genetlink.Socket.resolveMcastGroup` the round trip on top. The names below
//! are kept as thin wrappers so this module's public API is unchanged.

const std = @import("std");
const linux = std.os.linux;
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");

const uapi = @import("uapi.zig");
const iface = @import("iface.zig");
const station_mod = @import("station.zig");
const wiphy_mod = @import("wiphy.zig");
const scan_mod = @import("scan.zig");
const connect_mod = @import("connect.zig");
const reg_mod = @import("reg.zig");

/// `NETLINK_ADD_MEMBERSHIP` / `NETLINK_DROP_MEMBERSHIP` (linux/netlink.h).
pub const NETLINK_ADD_MEMBERSHIP: u32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: u32 = 2;

pub const RequestError = error{
    OutOfMemory,
    SendFailed,
    RecvFailed,
    /// A reply failed wire-format validation (bounds/length checks).
    MalformedReply,
    /// The command needs a capability this process does not have — most
    /// nl80211 writes want CAP_NET_ADMIN, and `TRIGGER_SCAN` wants it too.
    AccessDenied,
    /// The kernel rejected the request's contents, or this module built one it
    /// knows the kernel would reject.
    InvalidRequest,
    /// No such interface / wiphy.
    NoSuchDevice,
    /// The driver does not implement this command.
    NotSupported,
    /// A scan is already running, or the device is busy.
    Busy,
    /// Not connected (e.g. `DISCONNECT` on an idle interface).
    NotConnected,
    /// The interface exists but is administratively down (`ENETDOWN`), so the
    /// command cannot reach the radio. Distinct from `NoSuchDevice` (there is
    /// a device) and from `NotConnected` (that is about association state, not
    /// link state).
    ///
    /// Found by running this module's own live tests as real root against a
    /// real radio in the VM lane (`scripts/vm/run.sh nl80211 debian`), which
    /// is the first time the `TRIGGER_SCAN` test had the CAP_NET_ADMIN to get
    /// this far: the kernel answered `-100` and `errnoToError` had no case for
    /// it, so the single most ordinary failure of a scan — "the interface is
    /// down" — surfaced as `error.Unexpected`. Nothing could have caught that
    /// on an unprivileged host, because the only test that reaches it skipped.
    NetworkDown,
    SystemResources,
    Unexpected,
    /// **W2 audit finding, campaign C-06 (`nl80211` F5)**: `Dump.next`/
    /// `awaitAck` looped on `recvDatagram` with no upper bound. A peer that
    /// never sends `NLMSG_DONE`/a matching ACK — a kernel bug, or (this
    /// module was worst-of-four here: it neither forwarded
    /// `setRecvTimeout` nor exposed the command socket's fd) anything else
    /// able to answer on this socket — hung the caller forever.
    TooManyMessages,
};

pub const OpenError = genl.OpenError || genl.ResolveError;

/// The family exists but does not publish the multicast group that was asked
/// for — a kernel too old for it, or a typo in the name.
pub const SubscribeError = RequestError || error{GroupNotFound};

/// Map a `NLMSG_ERROR` errno onto the request error set.
pub fn errnoToError(code: i32) RequestError {
    if (code >= 0 or code == std.math.minInt(i32)) return error.Unexpected;
    return switch (@as(u32, @intCast(-code))) {
        @intFromEnum(linux.E.PERM), @intFromEnum(linux.E.ACCES) => error.AccessDenied,
        @intFromEnum(linux.E.NODEV), @intFromEnum(linux.E.NXIO) => error.NoSuchDevice,
        // ENOENT from a family command means "no such interface"; from nlctrl
        // it means "no such family", which `genl.resolveFamily` handles.
        @intFromEnum(linux.E.NOENT) => error.NoSuchDevice,
        @intFromEnum(linux.E.INVAL), @intFromEnum(linux.E.MSGSIZE) => error.InvalidRequest,
        @intFromEnum(linux.E.OPNOTSUPP) => error.NotSupported,
        @intFromEnum(linux.E.BUSY), @intFromEnum(linux.E.AGAIN) => error.Busy,
        @intFromEnum(linux.E.NOTCONN), @intFromEnum(linux.E.ALREADY) => error.NotConnected,
        @intFromEnum(linux.E.NOBUFS), @intFromEnum(linux.E.NOMEM) => error.SystemResources,
        // Measured, not assumed: `TRIGGER_SCAN` on an administratively-down
        // interface answers `-100` (ENETDOWN). See `NetworkDown`.
        @intFromEnum(linux.E.NETDOWN) => error.NetworkDown,
        else => error.Unexpected,
    };
}

// ── multicast group resolution ─────────────────────────────────────────────

/// Find the id of the multicast group named `want` in the attribute bytes of a
/// `CTRL_CMD_NEWFAMILY` reply (i.e. the nlctrl payload past its own
/// `genlmsghdr`). Pure — golden-tested offline against a captured reply.
///
/// A thin wrapper over `genetlink.findMcastGroupId`, which is where this walk
/// now lives; kept under its old name because it is part of this module's
/// public API and `goldens.zig` drives it.
pub fn findMcastGroupId(attr_bytes: []const u8, want: []const u8) codec.Error!?u32 {
    return genl.findMcastGroupId(attr_bytes, want);
}

/// Fold the shared resolver's error set onto this module's. `FamilyNotFound`
/// becomes `NoSuchDevice`, which is exactly what an `ENOENT` from nlctrl
/// mapped to through `errnoToError` before the resolver was shared;
/// `NameTooLong` cannot happen for a name this module hardcodes.
fn mapResolve(e: genl.McastGroupError) SubscribeError {
    return switch (e) {
        error.GroupNotFound => error.GroupNotFound,
        error.FamilyNotFound => error.NoSuchDevice,
        error.NameTooLong => unreachable, // "nl80211" fits GENL_NAMSIZ
        error.OutOfMemory => error.OutOfMemory,
        error.SendFailed => error.SendFailed,
        error.RecvFailed => error.RecvFailed,
        error.MalformedReply => error.MalformedReply,
        error.AccessDenied => error.AccessDenied,
        error.SystemResources => error.SystemResources,
        error.Unexpected => error.Unexpected,
    };
}

// ── the command socket ─────────────────────────────────────────────────────

/// Wi-Fi control client. One instance per thread/loop; no shared state.
pub const Nl80211 = struct {
    sock: genl.Socket,
    /// The dynamically resolved `nl80211` message-type id.
    family_id: u16,

    /// Open a `NETLINK_GENERIC` socket and resolve the nl80211 family.
    /// `error.FamilyNotFound` means no cfg80211 in this kernel (or none
    /// visible in this network namespace).
    pub fn open(gpa: std.mem.Allocator) OpenError!Nl80211 {
        var sock = try genl.Socket.open(gpa);
        errdefer sock.close();
        const family_id = try sock.resolveFamily(uapi.family_name);
        return .{ .sock = sock, .family_id = family_id };
    }

    pub fn close(cl: *Nl80211) void {
        cl.sock.close();
        cl.* = undefined;
    }

    pub fn allocator(cl: *Nl80211) std.mem.Allocator {
        return cl.sock.gpa;
    }

    // ── enumeration ────────────────────────────────────────────────────────

    /// Dump every radio's capabilities. Unprivileged.
    ///
    /// Requests the *split* dump, so a radio arrives spread over many messages
    /// and is reassembled by `wiphy.Parser` — see that file's header.
    /// Free with `nl80211.wiphy.freeAll`.
    pub fn wiphys(cl: *Nl80211) RequestError![]wiphy_mod.Wiphy {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        const hdr = try codec.appendHeader(
            gpa,
            &req,
            cl.family_id,
            codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_DUMP,
            seq,
            0,
        );
        try genl.appendHeader(gpa, &req, uapi.CMD.GET_WIPHY, uapi.family_version);
        // Without this the kernel truncates each radio to one message.
        codec.appendAttr(gpa, &req, uapi.ATTR.SPLIT_WIPHY_DUMP, &.{}) catch return error.OutOfMemory;
        codec.finishHeader(&req, hdr);
        try cl.send(req.items);

        var parser: wiphy_mod.Parser = .init(gpa);
        defer parser.deinit();
        var walk: Dump = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            if (m.cmd != uapi.CMD.NEW_WIPHY) continue;
            parser.feed(m.attrs) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.MalformedReply,
            };
        }
        return parser.finish() catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.MalformedReply,
        };
    }

    /// Dump every wireless interface. Unprivileged. Caller frees the slice.
    pub fn interfaces(cl: *Nl80211) RequestError![]iface.Interface {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = try cl.buildSimple(seq, uapi.CMD.GET_INTERFACE, true, null);
        defer gpa.free(req);
        try cl.send(req);

        var out: std.ArrayList(iface.Interface) = .empty;
        errdefer out.deinit(gpa);
        var walk: Dump = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            if (m.cmd != uapi.CMD.NEW_INTERFACE) continue;
            const i = iface.parse(m.attrs) catch return error.MalformedReply;
            try out.append(gpa, i);
        }
        return out.toOwnedSlice(gpa);
    }

    /// One interface's state (`NL80211_CMD_GET_INTERFACE`, not a dump).
    pub fn interfaceByIndex(cl: *Nl80211, ifindex: u32) RequestError!iface.Interface {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = try cl.buildSimple(seq, uapi.CMD.GET_INTERFACE, false, ifindex);
        defer gpa.free(req);
        try cl.send(req);

        var walk: Dump = .{ .cl = cl, .seq = seq };
        var found: ?iface.Interface = null;
        while (try walk.next()) |m| {
            if (m.cmd != uapi.CMD.NEW_INTERFACE or found != null) continue;
            found = iface.parse(m.attrs) catch return error.MalformedReply;
        }
        return found orelse error.NoSuchDevice;
    }

    // ── station statistics ─────────────────────────────────────────────────

    /// Dump every associated peer of an interface. On a managed (client)
    /// interface this is the AP, or nothing when not associated.
    /// Unprivileged. Caller frees the slice.
    pub fn stations(cl: *Nl80211, ifindex: u32) RequestError![]station_mod.Station {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = try cl.buildSimple(seq, uapi.CMD.GET_STATION, true, ifindex);
        defer gpa.free(req);
        try cl.send(req);

        var out: std.ArrayList(station_mod.Station) = .empty;
        errdefer out.deinit(gpa);
        var walk: Dump = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            if (m.cmd != uapi.CMD.NEW_STATION) continue;
            const s = station_mod.parse(m.attrs) catch return error.MalformedReply;
            try out.append(gpa, s);
        }
        return out.toOwnedSlice(gpa);
    }

    // ── scanning ───────────────────────────────────────────────────────────

    /// Start a scan (`NL80211_CMD_TRIGGER_SCAN`). Needs **CAP_NET_ADMIN**.
    ///
    /// Returns as soon as the kernel ACKs the *start*. Results are not in the
    /// reply — see `scan.zig`'s header for the subscribe → trigger → wait →
    /// dump sequence, and `EventSocket` for step 3.
    pub fn triggerScan(cl: *Nl80211, opts: scan_mod.TriggerOptions) RequestError!void {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = scan_mod.buildTriggerScan(gpa, cl.family_id, seq, opts) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidRequest => return error.InvalidRequest,
        };
        defer gpa.free(req);
        try cl.send(req);
        try cl.awaitAck(seq);
    }

    /// Dump the kernel's BSS table for an interface (`NL80211_CMD_GET_SCAN`).
    /// Unprivileged. Free with `nl80211.scan.freeAll`.
    pub fn scanResults(cl: *Nl80211, ifindex: u32) RequestError![]scan_mod.Bss {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = try scan_mod.buildGetScan(gpa, cl.family_id, seq, ifindex);
        defer gpa.free(req);
        try cl.send(req);

        var out: std.ArrayList(scan_mod.Bss) = .empty;
        errdefer {
            for (out.items) |*b| b.deinit(gpa);
            out.deinit(gpa);
        }
        var walk: Dump = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            if (m.cmd != uapi.CMD.NEW_SCAN_RESULTS) continue;
            const maybe = scan_mod.parseBss(gpa, m.attrs) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.MalformedReply,
            };
            if (maybe) |b| {
                errdefer {
                    var tmp = b;
                    tmp.deinit(gpa);
                }
                try out.append(gpa, b);
            }
        }
        return out.toOwnedSlice(gpa);
    }

    // ── association ────────────────────────────────────────────────────────

    /// `NL80211_CMD_CONNECT`. Needs **CAP_NET_ADMIN**. Read `connect.zig`'s
    /// header first — this only works on a driver whose firmware runs the SME.
    ///
    /// The ACK means "the request was accepted", not "you are associated": the
    /// outcome arrives later as an MLME-group `NL80211_CMD_CONNECT` event
    /// carrying `NL80211_ATTR_STATUS_CODE`.
    pub fn connect(cl: *Nl80211, opts: connect_mod.ConnectOptions) RequestError!void {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = connect_mod.buildConnect(gpa, cl.family_id, seq, opts) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidRequest => return error.InvalidRequest,
        };
        defer gpa.free(req);
        try cl.send(req);
        try cl.awaitAck(seq);
    }

    /// `NL80211_CMD_DISCONNECT`. Needs **CAP_NET_ADMIN**.
    pub fn disconnect(cl: *Nl80211, ifindex: u32, reason_code: ?u16) RequestError!void {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = try connect_mod.buildDisconnect(gpa, cl.family_id, seq, ifindex, reason_code);
        defer gpa.free(req);
        try cl.send(req);
        try cl.awaitAck(seq);
    }

    // ── regulatory ─────────────────────────────────────────────────────────

    /// Dump the regulatory domains (`NL80211_CMD_GET_REG`). Unprivileged.
    /// A modern kernel answers with the global domain plus one per
    /// self-managed radio. Free with `nl80211.reg.freeAll`.
    pub fn regDomains(cl: *Nl80211) RequestError![]reg_mod.RegDomain {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = try reg_mod.buildGetReg(gpa, cl.family_id, seq);
        defer gpa.free(req);
        try cl.send(req);

        var out: std.ArrayList(reg_mod.RegDomain) = .empty;
        errdefer {
            for (out.items) |*d| d.deinit(gpa);
            out.deinit(gpa);
        }
        var walk: Dump = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            if (m.cmd != uapi.CMD.GET_REG) continue;
            const d = reg_mod.parse(gpa, m.attrs) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.MalformedReply,
            };
            {
                errdefer {
                    var tmp = d;
                    tmp.deinit(gpa);
                }
                try out.append(gpa, d);
            }
        }
        return out.toOwnedSlice(gpa);
    }

    /// Hint a regulatory domain (`NL80211_CMD_REQ_SET_REG`). Needs
    /// **CAP_NET_ADMIN**. It is a hint: the kernel intersects it with the
    /// driver's and the world regdomain's constraints.
    pub fn requestRegDomain(cl: *Nl80211, alpha2: []const u8) RequestError!void {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        const req = reg_mod.buildReqSetReg(gpa, cl.family_id, seq, alpha2) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidRequest => return error.InvalidRequest,
        };
        defer gpa.free(req);
        try cl.send(req);
        try cl.awaitAck(seq);
    }

    // ── multicast groups ───────────────────────────────────────────────────

    /// Resolve one of nl80211's multicast group names ("scan", "mlme", …) to
    /// its dynamic id. Unprivileged.
    ///
    /// The nlctrl round trip is `genetlink.Socket.resolveMcastGroup`; this is
    /// the error-set adapter over it.
    pub fn resolveMulticastGroup(cl: *Nl80211, name: []const u8) SubscribeError!u32 {
        return cl.sock.resolveMcastGroup(uapi.family_name, name) catch |e| return mapResolve(e);
    }

    // ── raw escape hatch ───────────────────────────────────────────────────

    /// A command this module does not model, with attributes the caller
    /// encoded itself (with `netlink.codec`). Everything nl80211 can do that
    /// is not in the typed API above is reachable through this.
    pub const RawRequest = struct {
        cmd: u8,
        /// Pre-encoded attribute TLVs — everything after the `genlmsghdr`.
        attrs: []const u8 = &.{},
        /// Add `NLM_F_DUMP` and collect every reply until `NLMSG_DONE`.
        dump: bool = false,
        /// Extra `NLM_F_*` bits beyond REQUEST|ACK (and DUMP when `dump`).
        extra_flags: u16 = 0,
        version: u8 = uapi.family_version,
    };

    /// One reply message of a raw request. `attrs` is an owned copy, so the
    /// list survives the receive buffer.
    pub const RawReply = struct {
        cmd: u8,
        attrs: []u8,
    };

    pub fn freeRawReplies(gpa: std.mem.Allocator, list: []RawReply) void {
        for (list) |r| gpa.free(r.attrs);
        gpa.free(list);
    }

    /// Send a raw request and collect every family reply. An ACK-only command
    /// yields an empty list. Free with `freeRawReplies`.
    pub fn raw(cl: *Nl80211, req: RawRequest) RequestError![]RawReply {
        const gpa = cl.allocator();
        const seq = cl.sock.nextSeq();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        var flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK | req.extra_flags;
        if (req.dump) flags |= codec.NLM_F_DUMP;
        const hdr = try codec.appendHeader(gpa, &msg, cl.family_id, flags, seq, 0);
        try genl.appendHeader(gpa, &msg, req.cmd, req.version);
        try msg.appendSlice(gpa, req.attrs);
        codec.finishHeader(&msg, hdr);
        try cl.send(msg.items);

        var out: std.ArrayList(RawReply) = .empty;
        errdefer {
            for (out.items) |r| gpa.free(r.attrs);
            out.deinit(gpa);
        }
        var walk: Dump = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            const copy = try gpa.dupe(u8, m.attrs);
            errdefer gpa.free(copy);
            try out.append(gpa, .{ .cmd = m.cmd, .attrs = copy });
        }
        return out.toOwnedSlice(gpa);
    }

    // ── plumbing ───────────────────────────────────────────────────────────

    fn buildSimple(
        cl: *Nl80211,
        seq: u32,
        cmd: u8,
        dump: bool,
        ifindex: ?u32,
    ) RequestError![]u8 {
        const gpa = cl.allocator();
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        var flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK;
        if (dump) flags |= codec.NLM_F_DUMP;
        const hdr = try codec.appendHeader(gpa, &list, cl.family_id, flags, seq, 0);
        try genl.appendHeader(gpa, &list, cmd, uapi.family_version);
        if (ifindex) |i| try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, i);
        codec.finishHeader(&list, hdr);
        return list.toOwnedSlice(gpa);
    }

    fn send(cl: *Nl80211, msg: []const u8) RequestError!void {
        cl.sock.send(msg) catch |e| return switch (e) {
            error.AccessDenied => error.AccessDenied,
            error.SystemResources => error.SystemResources,
            error.SendFailed => error.SendFailed,
        };
    }

    fn awaitAck(cl: *Nl80211, seq: u32) RequestError!void {
        return awaitAckStep(cl, seq);
    }

    /// Bound how long a `recvDatagram` on the command socket may block
    /// (`SO_RCVTIMEO`); 0 restores the default of blocking forever. Belt and
    /// braces alongside `max_dump_messages`: the message budget bounds a
    /// peer that keeps talking without ever sending `NLMSG_DONE`/an ACK, this
    /// bounds a peer that stops talking entirely. **W2 audit finding,
    /// campaign C-06 (`nl80211` F5)**: this wrapper did not exist before —
    /// the underlying `genetlink.Socket.setRecvTimeout` was reachable only
    /// by reaching into the `sock` field directly, which is exactly the gap
    /// the sibling `ethtool`/`conntrack` clients do not have (they wrap it).
    pub fn setRecvTimeout(cl: *Nl80211, millis: u32) error{Unexpected}!void {
        return cl.sock.setRecvTimeout(millis);
    }

    /// The raw command-socket file descriptor, for poll/epoll integration —
    /// same reason `EventSocket.fd` exists. Do not close it; `close` is.
    pub fn fd(cl: *const Nl80211) i32 {
        return cl.sock.fd;
    }
};

/// Ceiling on how many netlink messages one `Dump`/`awaitAck` scan may
/// consume before giving up. See the sibling `ethtool`/`devlink` clients'
/// identical constant for the full rationale: the kernel is the only
/// verified sender on this socket, so this is a robustness ceiling against a
/// malfunctioning driver, not an attacker-facing bound.
const max_dump_messages: u32 = 65536;

/// The body of `Nl80211.awaitAck`, factored out the same way `dumpStep` is —
/// `cl` need only look like `*Nl80211` for `cl.sock.recvDatagram()` /
/// `cl.sock.portid`.
fn awaitAckStep(cl: anytype, seq: u32) RequestError!void {
    var msgs: u32 = 0;
    while (true) {
        if (msgs >= max_dump_messages) return error.TooManyMessages;
        const dgram = cl.sock.recvDatagram() catch |e| return recvErr(e);
        msgs += 1;
        var it: codec.MessageIterator = .{ .buf = dgram };
        while (it.next() catch return error.MalformedReply) |m| {
            if (m.pid != cl.sock.portid or m.seq != seq) continue;
            if (m.type != codec.NLMSG_ERROR) continue;
            const code = m.errorCode() catch return error.MalformedReply;
            if (code == 0) return; // ACK
            return errnoToError(code);
        }
    }
}

fn recvErr(e: genl.RecvError) RequestError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MalformedReply => error.MalformedReply,
        error.SystemResources => error.SystemResources,
        error.RecvFailed => error.RecvFailed,
    };
}

/// One family reply message of a dump. `attrs` borrows the socket's receive
/// buffer and is valid only until the next `Dump.next` call.
pub const DumpMessage = struct {
    cmd: u8,
    attrs: []const u8,
};

/// Walks a multi-part reply, hiding datagram boundaries. Terminates on
/// `NLMSG_DONE` (a dump), on the ACK (a single-shot request), or on
/// `error.TooManyMessages` once `max_dump_messages` is exceeded.
const Dump = struct {
    cl: *Nl80211,
    seq: u32,
    it: codec.MessageIterator = .{ .buf = &.{} },
    finished: bool = false,
    msgs: u32 = 0,

    fn next(w: *Dump) RequestError!?DumpMessage {
        return dumpStep(w.cl, w.seq, &w.it, &w.finished, &w.msgs);
    }
};

/// The body of `Dump.next`, factored out so a mock transport can drive it in
/// tests without a real socket (same technique as the sibling `conntrack`
/// module's `dumpOver` and `ethtool`'s `walkStep`). `cl` need only look like
/// `*Nl80211` for the fields this loop touches: `cl.sock.recvDatagram()`,
/// `cl.sock.portid`, `cl.family_id`.
fn dumpStep(
    cl: anytype,
    seq: u32,
    it: *codec.MessageIterator,
    finished: *bool,
    msgs: *u32,
) RequestError!?DumpMessage {
    while (true) {
        if (finished.*) return null;
        const maybe = it.next() catch return error.MalformedReply;
        const m = maybe orelse {
            if (msgs.* >= max_dump_messages) return error.TooManyMessages;
            const dgram = cl.sock.recvDatagram() catch |e| return recvErr(e);
            msgs.* += 1;
            it.* = .{ .buf = dgram };
            continue;
        };
        if (m.pid != cl.sock.portid or m.seq != seq) continue;
        switch (m.type) {
            codec.NLMSG_DONE => {
                finished.* = true;
                return null;
            },
            codec.NLMSG_ERROR => {
                const code = m.errorCode() catch return error.MalformedReply;
                if (code != 0) return errnoToError(code);
                // A zero-error message is the ACK of a non-dump request:
                // everything that was going to arrive has arrived.
                finished.* = true;
                return null;
            },
            codec.NLMSG_NOOP => continue,
            codec.NLMSG_OVERRUN => return error.SystemResources,
            else => {
                if (m.type != cl.family_id) continue;
                const p = genl.splitPayload(m.payload) catch return error.MalformedReply;
                return .{ .cmd = p.cmd, .attrs = p.attrs };
            },
        }
    }
}

// ── the event socket ───────────────────────────────────────────────────────

/// A decoded nl80211 multicast event. Everything it carries is copied, so an
/// `Event` outlives the datagram it came from.
pub const Event = struct {
    /// The `NL80211_CMD_*` value. Commands this module does not model still
    /// arrive here with their raw number.
    cmd: u8,
    wiphy: ?u32 = null,
    ifindex: ?u32 = null,
    wdev: ?u64 = null,
    /// `NL80211_ATTR_STATUS_CODE` of a CONNECT/ASSOCIATE outcome.
    status_code: ?u16 = null,
    /// `NL80211_ATTR_REASON_CODE` of a DISCONNECT/DEAUTH.
    reason_code: ?u16 = null,
    mac: ?uapi.Mac = null,

    /// A scan finished and its results are in the kernel's BSS table.
    pub fn isScanComplete(e: Event) bool {
        return e.cmd == uapi.CMD.NEW_SCAN_RESULTS;
    }

    /// A scan ended without usable results.
    pub fn isScanAborted(e: Event) bool {
        return e.cmd == uapi.CMD.SCAN_ABORTED;
    }

    /// Either terminal outcome of a triggered scan.
    pub fn endsScan(e: Event) bool {
        return e.isScanComplete() or e.isScanAborted();
    }
};

/// A `NETLINK_GENERIC` socket subscribed to nl80211 multicast groups.
///
/// **One blocking call: `waitForEvent`.** See the file header for why the
/// threading policy is the caller's.
pub const EventSocket = struct {
    sock: genl.Socket,
    family_id: u16,
    /// Unconsumed bytes of the datagram most recently received. Points into
    /// `sock.buf`, which is only reallocated by `recvDatagram` — and that is
    /// called only when this is empty.
    it: codec.MessageIterator = .{ .buf = &.{} },

    /// Open an event socket and subscribe to `groups` (names from
    /// `uapi.mcast_group`). Resolving group ids is unprivileged; so is joining
    /// an nl80211 group.
    ///
    /// This opens a throwaway command socket to resolve the ids. A caller that
    /// already has an `Nl80211` should use `openWith` instead.
    pub fn open(
        gpa: std.mem.Allocator,
        groups: []const []const u8,
    ) (OpenError || SubscribeError)!EventSocket {
        var cmd = try Nl80211.open(gpa);
        defer cmd.close();
        return openWith(&cmd, groups);
    }

    /// Open an event socket, resolving the group ids over an existing command
    /// socket.
    pub fn openWith(
        cmd: *Nl80211,
        groups: []const []const u8,
    ) (OpenError || SubscribeError)!EventSocket {
        var ev: EventSocket = .{
            .sock = try genl.Socket.open(cmd.allocator()),
            .family_id = cmd.family_id,
        };
        errdefer ev.sock.close();
        for (groups) |g| try ev.joinGroup(try cmd.resolveMulticastGroup(g));
        return ev;
    }

    /// Subscribe to an already-resolved group id.
    pub fn joinGroup(ev: *EventSocket, group_id: u32) RequestError!void {
        const rc = linux.setsockopt(
            ev.sock.fd,
            linux.SOL.NETLINK,
            NETLINK_ADD_MEMBERSHIP,
            @ptrCast(&group_id),
            @sizeOf(u32),
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .INVAL => return error.InvalidRequest,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    }

    pub fn leaveGroup(ev: *EventSocket, group_id: u32) void {
        _ = linux.setsockopt(
            ev.sock.fd,
            linux.SOL.NETLINK,
            NETLINK_DROP_MEMBERSHIP,
            @ptrCast(&group_id),
            @sizeOf(u32),
        );
    }

    pub fn close(ev: *EventSocket) void {
        ev.sock.close();
        ev.* = undefined;
    }

    /// The raw socket descriptor, for a caller that wants a bounded wait: poll
    /// this for readability, and only then call `waitForEvent`.
    pub fn fd(ev: *const EventSocket) i32 {
        return ev.sock.fd;
    }

    /// **The one blocking call.** Returns the next nl80211 event, performing a
    /// single `recvmsg` only when the previously received datagram has been
    /// drained. Messages that are not nl80211 family messages are skipped.
    pub fn waitForEvent(ev: *EventSocket) RequestError!Event {
        while (true) {
            const maybe = ev.it.next() catch return error.MalformedReply;
            const m = maybe orelse {
                const dgram = ev.sock.recvDatagram() catch |e| return recvErr(e);
                ev.it = .{ .buf = dgram };
                continue;
            };
            // Events come from the kernel with seq 0 and pid 0; anything else
            // on this socket is not an event.
            if (m.type != ev.family_id) continue;
            const p = genl.splitPayload(m.payload) catch return error.MalformedReply;
            return parseEvent(p.cmd, p.attrs) catch return error.MalformedReply;
        }
    }
};

/// Decode one event message's command + attribute bytes. Pure.
pub fn parseEvent(cmd: u8, attr_bytes: []const u8) codec.Error!Event {
    var e: Event = .{ .cmd = cmd };
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.WIPHY => e.wiphy = try a.asU32(),
        uapi.ATTR.IFINDEX => e.ifindex = try a.asU32(),
        uapi.ATTR.STATUS_CODE => e.status_code = try a.asU16(),
        uapi.ATTR.REASON_CODE => e.reason_code = try a.asU16(),
        uapi.ATTR.WDEV => {
            if (a.data.len != 8) return error.BadLength;
            e.wdev = std.mem.readInt(u64, a.data[0..8], .little);
        },
        uapi.ATTR.MAC => {
            if (a.data.len != 6) return error.BadLength;
            e.mac = a.data[0..6].*;
        },
        else => {},
    };
    return e;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "errnoToError maps the errnos nl80211 actually returns" {
    try testing.expectEqual(error.AccessDenied, errnoToError(-@as(i32, @intFromEnum(linux.E.PERM))));
    try testing.expectEqual(error.NoSuchDevice, errnoToError(-@as(i32, @intFromEnum(linux.E.NODEV))));
    try testing.expectEqual(error.InvalidRequest, errnoToError(-@as(i32, @intFromEnum(linux.E.INVAL))));
    try testing.expectEqual(error.NotSupported, errnoToError(-@as(i32, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expectEqual(error.Busy, errnoToError(-@as(i32, @intFromEnum(linux.E.BUSY))));
    try testing.expectEqual(error.NotConnected, errnoToError(-@as(i32, @intFromEnum(linux.E.NOTCONN))));
    try testing.expectEqual(error.SystemResources, errnoToError(-@as(i32, @intFromEnum(linux.E.NOMEM))));
    // Non-negative codes are not errors at all.
    try testing.expectEqual(error.Unexpected, errnoToError(0));
    try testing.expectEqual(error.Unexpected, errnoToError(5));
    try testing.expectEqual(error.Unexpected, errnoToError(std.math.minInt(i32)));
}

test "findMcastGroupId on a hand-built nlctrl reply" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try codec.appendAttrU16(gpa, &attrs, uapi.CTRL_ATTR.FAMILY_ID, 41);
    const groups = try codec.nestBegin(gpa, &attrs, uapi.CTRL_ATTR.MCAST_GROUPS);
    for ([_]struct { n: []const u8, id: u32 }{
        .{ .n = "config", .id = 22 },
        .{ .n = "scan", .id = 23 },
        .{ .n = "mlme", .id = 25 },
    }, 1..) |g, i| {
        const one = try codec.nestBegin(gpa, &attrs, @intCast(i));
        try codec.appendAttrU32(gpa, &attrs, uapi.CTRL_ATTR_MCAST_GRP.ID, g.id);
        try codec.appendAttrString(gpa, &attrs, uapi.CTRL_ATTR_MCAST_GRP.NAME, g.n);
        codec.nestEnd(&attrs, one);
    }
    codec.nestEnd(&attrs, groups);

    try testing.expectEqual(@as(?u32, 23), try findMcastGroupId(attrs.items, "scan"));
    try testing.expectEqual(@as(?u32, 22), try findMcastGroupId(attrs.items, "config"));
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(attrs.items, "nope"));
    // A reply with no groups at all.
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(&.{}, "scan"));
    // A truncated nest.
    try testing.expectError(error.Truncated, findMcastGroupId(&.{ 0x40, 0x00, 0x07, 0x00, 1 }, "scan"));
}

test "findMcastGroupId: a group entry with a name but no id is a bad reply" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    const groups = try codec.nestBegin(gpa, &attrs, uapi.CTRL_ATTR.MCAST_GROUPS);
    const one = try codec.nestBegin(gpa, &attrs, 1);
    try codec.appendAttrString(gpa, &attrs, uapi.CTRL_ATTR_MCAST_GRP.NAME, "scan");
    codec.nestEnd(&attrs, one);
    codec.nestEnd(&attrs, groups);
    try testing.expectError(error.BadLength, findMcastGroupId(attrs.items, "scan"));
}

test "parseEvent decodes the fields a scan/MLME event carries" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try codec.appendAttrU32(gpa, &attrs, uapi.ATTR.WIPHY, 0);
    try codec.appendAttrU32(gpa, &attrs, uapi.ATTR.IFINDEX, 3);
    try codec.appendAttr(gpa, &attrs, uapi.ATTR.WDEV, &.{ 1, 0, 0, 0, 0, 0, 0, 0 });

    const e = try parseEvent(uapi.CMD.NEW_SCAN_RESULTS, attrs.items);
    try testing.expect(e.isScanComplete());
    try testing.expect(e.endsScan());
    try testing.expect(!e.isScanAborted());
    try testing.expectEqual(@as(?u32, 3), e.ifindex);
    try testing.expectEqual(@as(?u64, 1), e.wdev);

    const aborted = try parseEvent(uapi.CMD.SCAN_ABORTED, attrs.items);
    try testing.expect(aborted.isScanAborted());
    try testing.expect(aborted.endsScan());

    const other = try parseEvent(uapi.CMD.REG_CHANGE, attrs.items);
    try testing.expect(!other.endsScan());
    try testing.expectEqual(@as(u8, uapi.CMD.REG_CHANGE), other.cmd);
}

test "parseEvent: a connect outcome carries a status code and a BSSID" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try codec.appendAttrU32(gpa, &attrs, uapi.ATTR.IFINDEX, 3);
    try codec.appendAttr(gpa, &attrs, uapi.ATTR.MAC, &.{ 0x02, 0, 0, 0xaa, 0xbb, 0xcc });
    try codec.appendAttrU16(gpa, &attrs, uapi.ATTR.STATUS_CODE, 0);
    const e = try parseEvent(uapi.CMD.CONNECT, attrs.items);
    try testing.expectEqual(@as(?u16, 0), e.status_code);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0xaa, 0xbb, 0xcc }, &e.mac.?);
}

test "parseEvent: malformed attributes are typed errors" {
    try testing.expectError(error.Truncated, parseEvent(1, &.{ 0x40, 0x00 }));
    // WDEV with the wrong width.
    try testing.expectError(error.BadLength, parseEvent(1, &.{ 0x08, 0x00, 0x99, 0x00, 1, 0, 0, 0 }));
}

test "fuzz: event parsing never crashes" {
    try testing.fuzz({}, fuzzEvent, .{});
}

// ── C-06 regression: the dump/ACK loops must not spin forever ──────────────
// W2-nn (`nl80211` F5, campaign C-06): `Dump.next` and `awaitAck` looped on
// `recvDatagram` with no upper bound, so a peer that never sends
// `NLMSG_DONE`/a matching ACK hangs the caller forever. `dumpStep` was
// factored out of `Dump.next` precisely so a scripted stand-in can drive it
// here, the same technique the sibling `conntrack` module's
// `ScriptedTransport` uses for `dumpOver`.

/// Hands back the same never-matching datagram forever.
const MockSock = struct {
    portid: u32,
    datagram: []const u8,

    fn recvDatagram(self: *MockSock) genl.RecvError![]const u8 {
        return self.datagram;
    }
};

const MockNl80211 = struct {
    sock: MockSock,
    family_id: u16,
};

/// One message with `NLM_F_MULTI` set and a type that never matches
/// `family_id`, so `Dump`'s `else` arm skips it and asks for another
/// datagram — forever, absent a budget.
fn nonTerminatingDatagram(gpa: std.mem.Allocator, pid: u32, seq: u32, family_id: u16) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, family_id +% 1, codec.NLM_F_MULTI, seq, pid);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

test "Dump.next errors out instead of looping forever on a never-DONE reply" {
    const family_id: u16 = 41;
    const seq: u32 = 5;
    const pid: u32 = 100;
    const dgram = try nonTerminatingDatagram(testing.allocator, pid, seq, family_id);
    defer testing.allocator.free(dgram);

    var cl: MockNl80211 = .{ .sock = .{ .portid = pid, .datagram = dgram }, .family_id = family_id };
    var it: codec.MessageIterator = .{ .buf = &.{} };
    var finished = false;
    var msgs: u32 = 0;
    try testing.expectError(error.TooManyMessages, dumpStep(&cl, seq, &it, &finished, &msgs));
    try testing.expectEqual(max_dump_messages, msgs);
}

test "awaitAck errors out instead of looping forever on a never-matching reply" {
    // pid/seq deliberately do NOT match, so awaitAckStep's `continue`
    // (not a type mismatch) is what keeps asking for another datagram.
    const family_id: u16 = 41;
    const seq: u32 = 5;
    const pid: u32 = 100;
    const dgram = try nonTerminatingDatagram(testing.allocator, pid + 1, seq + 1, family_id);
    defer testing.allocator.free(dgram);

    var cl: MockNl80211 = .{ .sock = .{ .portid = pid, .datagram = dgram }, .family_id = family_id };
    try testing.expectError(error.TooManyMessages, awaitAckStep(&cl, seq));
}

fn fuzzEvent(_: void, smith: *std.testing.Smith) !void {
    var raw: [256]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const cmd = smith.valueRangeAtMost(u8, 0, 255);
    if (parseEvent(cmd, raw[0..len])) |e| std.mem.doNotOptimizeAway(&e) else |_| {}
    if (findMcastGroupId(raw[0..len], "scan")) |g| std.mem.doNotOptimizeAway(&g) else |_| {}
}

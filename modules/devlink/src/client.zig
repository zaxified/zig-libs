// SPDX-License-Identifier: MIT
//! The devlink client: one `NETLINK_GENERIC` socket plus the resolved
//! `devlink` family id, the typed commands built on it, and a separate
//! **event socket** for the family's single `config` multicast group.
//!
//! ## The blocking seam
//!
//! Command methods (`devices`, `ports`, `readRegion`, `setParam`, …) are
//! ordinary blocking request/reply calls: they send one message and read until
//! the kernel's ACK or `NLMSG_DONE`.
//!
//! Notifications are different, and this module refuses to hide that.
//! **`EventSocket` has exactly one blocking call — `waitForNotification`** —
//! and it does exactly one `recvmsg` when its buffer is drained. There is no
//! timer thread, no deadline and no event loop here: a caller that wants a
//! bounded wait polls `fd()` itself and only calls `waitForNotification` once
//! the fd is readable. That is the same seam discipline the sibling `ethtool`
//! (`EventSocket.waitForNotification`), `nl80211` (`waitForEvent`), `netconf`
//! (`Client.pumpOnce`) and `ebpf` (ring-buffer consumer) modules use, and for
//! the same reason — threading policy belongs to the application, not to a
//! protocol library.
//!
//! ## Dumps do not filter
//!
//! devlink's dump handlers walk every registered instance; the handle a
//! caller passes to `ports`/`params`/`regions`/`healthReporters` is applied
//! **client-side** after the dump, not sent to the kernel. That is what the
//! `devlink` binary does too, and it is why those methods take an *optional*
//! handle: passing null costs nothing extra.
//!
//! The single-object forms (`port`, `param`, `region`, `healthReporter`,
//! `info`, `eswitch`) are real `doit` requests and do reach the kernel with
//! the handle.
//!
//! ## Extended ACKs
//!
//! The shared transport enables `NETLINK_EXT_ACK`, so a rejection carries the
//! kernel's own sentence. `lastErrorMessage` returns it, out of the transport's
//! own buffer — this module keeps no second copy.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");

const uapi = @import("uapi.zig");
const handle_mod = @import("handle.zig");
const dev_mod = @import("dev.zig");
const port_mod = @import("port.zig");
const param_mod = @import("param.zig");
const resource_mod = @import("resource.zig");
const region_mod = @import("region.zig");
const health_mod = @import("health.zig");
const eswitch_mod = @import("eswitch.zig");

/// `NETLINK_ADD_MEMBERSHIP` / `NETLINK_DROP_MEMBERSHIP` (linux/netlink.h).
pub const NETLINK_ADD_MEMBERSHIP: u32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: u32 = 2;

pub const RequestError = error{
    OutOfMemory,
    SendFailed,
    RecvFailed,
    /// A reply failed wire-format validation (bounds/length checks), or a
    /// nested list exceeded this module's depth/size bounds.
    MalformedReply,
    /// The command needs a capability this process does not have. Every
    /// devlink write wants **CAP_NET_ADMIN**, and so do a few reads —
    /// `ESWITCH_GET` and `REGION_READ` among them.
    AccessDenied,
    /// The kernel rejected the request's contents, or this module built one it
    /// knows the kernel would reject. Check `lastErrorMessage`.
    InvalidRequest,
    /// No devlink instance with that handle, or no such port / region /
    /// parameter / reporter on it.
    NoSuchDevice,
    /// The driver does not implement this operation — the usual answer from a
    /// device that registers a devlink instance but few of its objects.
    NotSupported,
    Busy,
    SystemResources,
    Unexpected,
    /// **W2 audit finding, campaign C-06 (`devlink` F5)**: `Walk.next`
    /// exceeded `max_walk_messages` without reaching `NLMSG_DONE`/an ACK/a
    /// family message — a kernel bug or a socket fed by something other
    /// than the kernel would otherwise spin the caller (and every dump
    /// collector built on `Walk`: `devices`/`ports`/`params`/`regions`/
    /// `healthReporters`) forever.
    TooManyMessages,
    /// **W2 audit finding, campaign C-10 (`devlink` F4)**: a single-object
    /// (`doit`) reply's echoed handle does not name the object that was
    /// asked about. Correlation used to rest solely on `Walk`'s `(portid,
    /// seq)` match.
    UnexpectedHandle,
};

pub const OpenError = genl.OpenError || genl.ResolveError;

/// The family exists but does not publish the multicast group that was asked
/// for — a kernel too old for it, or a typo in the name.
pub const SubscribeError = RequestError || error{GroupNotFound};

/// Map an `NLMSG_ERROR` errno onto the request error set.
pub fn errnoToError(code: i32) RequestError {
    if (code >= 0 or code == std.math.minInt(i32)) return error.Unexpected;
    return switch (@as(u32, @intCast(-code))) {
        @intFromEnum(linux.E.PERM), @intFromEnum(linux.E.ACCES) => error.AccessDenied,
        @intFromEnum(linux.E.NODEV), @intFromEnum(linux.E.NXIO) => error.NoSuchDevice,
        // ENOENT from a devlink command means "no such object"; from nlctrl it
        // means "no such family", which `genl.resolveFamily` handles.
        @intFromEnum(linux.E.NOENT) => error.NoSuchDevice,
        @intFromEnum(linux.E.OPNOTSUPP) => error.NotSupported,
        @intFromEnum(linux.E.INVAL), @intFromEnum(linux.E.MSGSIZE) => error.InvalidRequest,
        @intFromEnum(linux.E.BUSY), @intFromEnum(linux.E.AGAIN) => error.Busy,
        @intFromEnum(linux.E.NOBUFS), @intFromEnum(linux.E.NOMEM) => error.SystemResources,
        else => error.Unexpected,
    };
}

/// One reply message, with the attribute bytes copied so they outlive the
/// socket's receive buffer.
pub const Reply = struct {
    cmd: u8,
    attrs: []u8,

    pub fn deinit(r: *Reply, gpa: std.mem.Allocator) void {
        gpa.free(r.attrs);
        r.* = .{ .cmd = 0, .attrs = &.{} };
    }
};

// ── the command socket ─────────────────────────────────────────────────────

/// devlink control client. One instance per thread/loop; no shared state.
pub const Devlink = struct {
    sock: genl.Socket,
    /// The dynamically resolved `devlink` message-type id (0x19 on the
    /// development machine — never hardcode it).
    family_id: u16,

    /// Open a `NETLINK_GENERIC` socket and resolve the devlink family.
    /// `error.FamilyNotFound` means a kernel built without `CONFIG_NET_DEVLINK`
    /// — which is rare; a kernel *with* it registers the family even when no
    /// driver has created an instance, and answers every dump empty.
    pub fn open(gpa: std.mem.Allocator) OpenError!Devlink {
        var sock = try genl.Socket.open(gpa);
        errdefer sock.close();
        const family_id = try sock.resolveFamily(uapi.family_name);
        return .{ .sock = sock, .family_id = family_id };
    }

    pub fn close(cl: *Devlink) void {
        cl.sock.close();
        cl.* = undefined;
    }

    pub fn allocator(cl: *Devlink) std.mem.Allocator {
        return cl.sock.gpa;
    }

    /// The kernel's own explanation of the most recent rejection
    /// (`NLMSGERR_ATTR_MSG`), or null when it attached none. Valid until the
    /// next request on this client. The buffer belongs to the shared netlink
    /// transport; this module keeps no copy of its own.
    pub fn lastErrorMessage(cl: *const Devlink) ?[]const u8 {
        const s = cl.sock.lastErrorMessage();
        return if (s.len == 0) null else s;
    }

    // ── devices ────────────────────────────────────────────────────────────

    /// `DEVLINK_CMD_GET` (dump) — every registered devlink instance.
    /// Unprivileged. **An empty slice is the normal answer** on a machine
    /// without a SmartNIC or switch ASIC. Free with `gpa.free`.
    pub fn devices(cl: *Devlink) RequestError![]dev_mod.Device {
        const gpa = cl.allocator();
        const seq = try cl.sendSimple(uapi.CMD.GET, null, true);

        var out: std.ArrayList(dev_mod.Device) = .empty;
        errdefer out.deinit(gpa);
        var walk: Walk = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            const d = dev_mod.parseDevice(m.attrs) catch return error.MalformedReply;
            if (!d.handle.isComplete()) continue;
            try out.append(gpa, d);
        }
        return out.toOwnedSlice(gpa);
    }

    /// `DEVLINK_CMD_INFO_GET` for one device — driver name, serial numbers and
    /// the fixed/running/stored firmware versions. Unprivileged. Free with
    /// `Info.deinit`.
    pub fn info(cl: *Devlink, h: handle_mod.Handle) RequestError!dev_mod.Info {
        const gpa = cl.allocator();
        var reply = try cl.simpleGet(uapi.CMD.INFO_GET, h);
        defer reply.deinit(gpa);
        var out = dev_mod.parseInfo(gpa, reply.attrs) catch |e| return mapParse(e);
        errdefer out.deinit(gpa);
        try checkHandleEcho(h, out.handle);
        return out;
    }

    // ── ports ──────────────────────────────────────────────────────────────

    /// `DEVLINK_CMD_PORT_GET` (dump). Unprivileged. `filter` selects one
    /// device's ports **client-side** — see the note at the top of this file.
    /// Free with `gpa.free`.
    pub fn ports(cl: *Devlink, filter: ?handle_mod.Handle) RequestError![]port_mod.Port {
        const gpa = cl.allocator();
        if (filter) |h| try validate(h);
        const seq = try cl.sendSimple(uapi.CMD.PORT_GET, null, true);

        var out: std.ArrayList(port_mod.Port) = .empty;
        errdefer out.deinit(gpa);
        var walk: Walk = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            const p = port_mod.parse(m.attrs) catch return error.MalformedReply;
            if (!p.handle.isComplete()) continue;
            if (filter) |h| {
                if (!p.handle.eql(h)) continue;
            }
            try out.append(gpa, p);
        }
        return out.toOwnedSlice(gpa);
    }

    /// `DEVLINK_CMD_PORT_GET` for one port. Unprivileged.
    pub fn port(cl: *Devlink, p: handle_mod.PortHandle) RequestError!port_mod.Port {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.CMD.PORT_GET, false);
        handle_mod.appendPort(gpa, &msg, p) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse return error.MalformedReply;
        defer reply.deinit(gpa);
        const out = port_mod.parse(reply.attrs) catch return error.MalformedReply;
        try checkPortHandleEcho(p, out.handle, out.index);
        return out;
    }

    /// `DEVLINK_CMD_PORT_SET` — change a port's type. Needs **CAP_NET_ADMIN**.
    pub fn setPortType(
        cl: *Devlink,
        p: handle_mod.PortHandle,
        t: uapi.PortType,
    ) RequestError!void {
        return cl.actPort(uapi.CMD.PORT_SET, p, struct {
            fn f(gpa: std.mem.Allocator, msg: *std.ArrayList(u8), ph: handle_mod.PortHandle, arg: u32) port_mod.Error!void {
                return port_mod.appendSetType(gpa, msg, ph, @enumFromInt(@as(u16, @intCast(arg))));
            }
        }.f, @intFromEnum(t));
    }

    /// `DEVLINK_CMD_PORT_SPLIT` — split a port into `count` lanes. Needs
    /// **CAP_NET_ADMIN**, and only works on a port with `splittable` set.
    pub fn splitPort(cl: *Devlink, p: handle_mod.PortHandle, count: u32) RequestError!void {
        return cl.actPort(uapi.CMD.PORT_SPLIT, p, port_mod.appendSplit, count);
    }

    /// `DEVLINK_CMD_PORT_UNSPLIT` — undo a split. Needs **CAP_NET_ADMIN**.
    pub fn unsplitPort(cl: *Devlink, p: handle_mod.PortHandle) RequestError!void {
        return cl.actPort(uapi.CMD.PORT_UNSPLIT, p, struct {
            fn f(gpa: std.mem.Allocator, msg: *std.ArrayList(u8), ph: handle_mod.PortHandle, _: u32) port_mod.Error!void {
                return port_mod.appendUnsplit(gpa, msg, ph);
            }
        }.f, 0);
    }

    fn actPort(
        cl: *Devlink,
        cmd: u8,
        p: handle_mod.PortHandle,
        comptime build: fn (std.mem.Allocator, *std.ArrayList(u8), handle_mod.PortHandle, u32) port_mod.Error!void,
        arg: u32,
    ) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, cmd, false);
        build(gpa, &msg, p, arg) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    // ── parameters ─────────────────────────────────────────────────────────

    /// `DEVLINK_CMD_PARAM_GET` (dump). Unprivileged. `filter` is applied
    /// client-side. Free with `param.freeAll`.
    pub fn params(cl: *Devlink, filter: ?handle_mod.Handle) RequestError![]param_mod.Param {
        const gpa = cl.allocator();
        if (filter) |h| try validate(h);
        const seq = try cl.sendSimple(uapi.CMD.PARAM_GET, null, true);

        var out: std.ArrayList(param_mod.Param) = .empty;
        errdefer {
            for (out.items) |*p| p.deinit(gpa);
            out.deinit(gpa);
        }
        var walk: Walk = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            var p = param_mod.parse(gpa, m.attrs) catch |e| return mapParse(e);
            const keep = p.name_len != 0 and p.handle.isComplete() and
                (filter == null or p.handle.eql(filter.?));
            if (!keep) {
                p.deinit(gpa);
                continue;
            }
            errdefer p.deinit(gpa);
            try out.append(gpa, p);
        }
        return out.toOwnedSlice(gpa);
    }

    /// `DEVLINK_CMD_PARAM_GET` for one named parameter. Unprivileged.
    /// Free with `Param.deinit`.
    pub fn param(
        cl: *Devlink,
        h: handle_mod.Handle,
        name: []const u8,
    ) RequestError!param_mod.Param {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.PARAM_GET, false);
        param_mod.appendGetByName(gpa, &msg, h, name) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse return error.MalformedReply;
        defer reply.deinit(gpa);
        var out = param_mod.parse(gpa, reply.attrs) catch |e| return mapParse(e);
        errdefer out.deinit(gpa);
        try checkHandleEcho(h, out.handle);
        if (!std.mem.eql(u8, out.name(), name)) return error.UnexpectedHandle;
        return out;
    }

    /// `DEVLINK_CMD_PARAM_SET`. Needs **CAP_NET_ADMIN**.
    ///
    /// The `PARAM_TYPE` on the wire is derived from `value`, so it cannot
    /// disagree with the width of the data — but it *can* disagree with what
    /// the driver declared, and the kernel answers EINVAL when it does. Read
    /// the parameter first if the type is not known statically.
    pub fn setParam(
        cl: *Devlink,
        h: handle_mod.Handle,
        name: []const u8,
        cmode: uapi.ParamCmode,
        value: param_mod.Value,
    ) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.PARAM_SET, false);
        param_mod.appendSet(gpa, &msg, h, name, cmode, value) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    // ── resources ──────────────────────────────────────────────────────────

    /// `DEVLINK_CMD_RESOURCE_DUMP` — the device's recursive resource tree.
    /// Unprivileged. Free with `Resources.deinit`.
    ///
    /// Despite the name this is a `doit`, not a netlink dump: the whole tree
    /// arrives in one message.
    pub fn resources(cl: *Devlink, h: handle_mod.Handle) RequestError!resource_mod.Resources {
        const gpa = cl.allocator();
        var reply = try cl.simpleGet(uapi.CMD.RESOURCE_DUMP, h);
        defer reply.deinit(gpa);
        var out = resource_mod.parse(gpa, reply.attrs) catch |e| return mapParse(e);
        errdefer out.deinit(gpa);
        try checkHandleEcho(h, out.handle);
        return out;
    }

    /// `DEVLINK_CMD_RESOURCE_SET` — request a new size for one resource.
    /// Needs **CAP_NET_ADMIN**; takes effect at the next `devlink dev reload`.
    pub fn setResourceSize(
        cl: *Devlink,
        h: handle_mod.Handle,
        resource_id: u64,
        size: u64,
    ) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.RESOURCE_SET, false);
        resource_mod.appendSet(gpa, &msg, h, resource_id, size) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    // ── regions ────────────────────────────────────────────────────────────

    /// `DEVLINK_CMD_REGION_GET` (dump). Unprivileged. `filter` is applied
    /// client-side. Free with `gpa.free`.
    pub fn regions(cl: *Devlink, filter: ?handle_mod.Handle) RequestError![]region_mod.Region {
        const gpa = cl.allocator();
        if (filter) |h| try validate(h);
        const seq = try cl.sendSimple(uapi.CMD.REGION_GET, null, true);

        var out: std.ArrayList(region_mod.Region) = .empty;
        errdefer out.deinit(gpa);
        var walk: Walk = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            const r = region_mod.parseRegion(m.attrs) catch return error.MalformedReply;
            if (r.name_len == 0 or !r.handle.isComplete()) continue;
            if (filter) |h| {
                if (!r.handle.eql(h)) continue;
            }
            try out.append(gpa, r);
        }
        return out.toOwnedSlice(gpa);
    }

    /// `DEVLINK_CMD_REGION_GET` for one named region. Unprivileged.
    pub fn region(
        cl: *Devlink,
        h: handle_mod.Handle,
        name: []const u8,
    ) RequestError!region_mod.Region {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.REGION_GET, false);
        region_mod.appendGet(gpa, &msg, h, name) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse return error.MalformedReply;
        defer reply.deinit(gpa);
        const out = region_mod.parseRegion(reply.attrs) catch return error.MalformedReply;
        try checkHandleEcho(h, out.handle);
        if (!std.mem.eql(u8, out.name(), name)) return error.UnexpectedHandle;
        return out;
    }

    /// `DEVLINK_CMD_REGION_NEW` — take a snapshot. Needs **CAP_NET_ADMIN**.
    /// Returns the snapshot's id, which the kernel picks when `snapshot_id` is
    /// null.
    pub fn newSnapshot(
        cl: *Devlink,
        h: handle_mod.Handle,
        name: []const u8,
        snapshot_id: ?u32,
    ) RequestError!u32 {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.REGION_NEW, false);
        region_mod.appendNewSnapshot(gpa, &msg, h, name, snapshot_id) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse
            // No reply message: the kernel acknowledged without echoing the
            // snapshot. Only an explicitly requested id is knowable then.
            return snapshot_id orelse error.MalformedReply;
        defer reply.deinit(gpa);
        const r = region_mod.parseRegion(reply.attrs) catch return error.MalformedReply;
        if (r.snapshot_count == 0) return snapshot_id orelse error.MalformedReply;
        return r.snapshot_ids[0];
    }

    /// `DEVLINK_CMD_REGION_DEL` — drop a snapshot. Needs **CAP_NET_ADMIN**.
    pub fn delSnapshot(
        cl: *Devlink,
        h: handle_mod.Handle,
        name: []const u8,
        snapshot_id: u32,
    ) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.REGION_DEL, false);
        region_mod.appendDelSnapshot(gpa, &msg, h, name, snapshot_id) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    /// `DEVLINK_CMD_REGION_READ` — read a window of a region or one of its
    /// snapshots, reassembling the chunked dump reply by address. Needs
    /// **CAP_NET_ADMIN**. Free with `Data.deinit`.
    ///
    /// A short read is *not* an error: check `Data.isComplete`.
    pub fn readRegion(
        cl: *Devlink,
        h: handle_mod.Handle,
        req: region_mod.ReadRequest,
    ) RequestError!region_mod.Data {
        const gpa = cl.allocator();
        if (req.length > std.math.maxInt(usize)) return error.InvalidRequest;

        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.REGION_READ, true);
        region_mod.appendRead(gpa, &msg, h, req) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);

        var assembler = region_mod.Assembler.init(gpa, req.address, @intCast(req.length)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidRequest => return error.InvalidRequest,
        };
        errdefer assembler.deinit(gpa);

        try cl.send(msg.items);
        var walk: Walk = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            assembler.feed(m.attrs) catch return error.MalformedReply;
        }
        return assembler.finish(gpa);
    }

    // ── health reporters ───────────────────────────────────────────────────

    /// `DEVLINK_CMD_HEALTH_REPORTER_GET` (dump). Unprivileged. `filter` is
    /// applied client-side. Free with `gpa.free`.
    pub fn healthReporters(
        cl: *Devlink,
        filter: ?handle_mod.Handle,
    ) RequestError![]health_mod.Reporter {
        const gpa = cl.allocator();
        if (filter) |h| try validate(h);
        const seq = try cl.sendSimple(uapi.CMD.HEALTH_REPORTER_GET, null, true);

        var out: std.ArrayList(health_mod.Reporter) = .empty;
        errdefer out.deinit(gpa);
        var walk: Walk = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            const r = health_mod.parse(m.attrs) catch return error.MalformedReply;
            if (r.name_len == 0 or !r.handle.isComplete()) continue;
            if (filter) |h| {
                if (!r.handle.eql(h)) continue;
            }
            try out.append(gpa, r);
        }
        return out.toOwnedSlice(gpa);
    }

    /// `DEVLINK_CMD_HEALTH_REPORTER_GET` for one named reporter.
    /// Unprivileged.
    pub fn healthReporter(
        cl: *Devlink,
        h: handle_mod.Handle,
        name: []const u8,
    ) RequestError!health_mod.Reporter {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.HEALTH_REPORTER_GET, false);
        health_mod.appendGet(gpa, &msg, h, name) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse return error.MalformedReply;
        defer reply.deinit(gpa);
        const out = health_mod.parse(reply.attrs) catch return error.MalformedReply;
        try checkHandleEcho(h, out.handle);
        if (!std.mem.eql(u8, out.name(), name)) return error.UnexpectedHandle;
        return out;
    }

    /// `DEVLINK_CMD_HEALTH_REPORTER_RECOVER` — run the driver's recovery
    /// routine now. Needs **CAP_NET_ADMIN**, and typically **resets the
    /// device**. This is not a health check; `healthReporter` is.
    pub fn recoverHealthReporter(
        cl: *Devlink,
        h: handle_mod.Handle,
        name: []const u8,
    ) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.HEALTH_REPORTER_RECOVER, false);
        health_mod.appendRecover(gpa, &msg, h, name) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    // ── eswitch ────────────────────────────────────────────────────────────

    /// `DEVLINK_CMD_ESWITCH_GET`. **Privileged** — the kernel marks this read
    /// `GENL_ADMIN_PERM`, so it answers `EPERM`, not `EOPNOTSUPP`, to an
    /// ordinary user.
    pub fn eswitch(cl: *Devlink, h: handle_mod.Handle) RequestError!eswitch_mod.Eswitch {
        const gpa = cl.allocator();
        var reply = try cl.simpleGet(uapi.CMD.ESWITCH_GET, h);
        defer reply.deinit(gpa);
        const out = eswitch_mod.parse(reply.attrs) catch return error.MalformedReply;
        try checkHandleEcho(h, out.handle);
        return out;
    }

    /// `DEVLINK_CMD_ESWITCH_SET`. Needs **CAP_NET_ADMIN**, and changing the
    /// mode tears down and re-creates the device's VF netdevs.
    pub fn setEswitch(
        cl: *Devlink,
        h: handle_mod.Handle,
        set: eswitch_mod.Set,
    ) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, uapi.CMD.ESWITCH_SET, false);
        eswitch_mod.appendSet(gpa, &msg, h, set) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    // ── multicast groups ───────────────────────────────────────────────────

    /// Resolve one of the family's multicast group names — devlink publishes
    /// exactly one, `config` — to its dynamic id. Unprivileged.
    ///
    /// This is the shared `genetlink` resolver; devlink carries no copy of the
    /// nlctrl reply walk.
    pub fn resolveMulticastGroup(cl: *Devlink, name: []const u8) SubscribeError!u32 {
        return cl.sock.resolveMcastGroup(uapi.family_name, name) catch |e| return mapResolve(e);
    }

    // ── raw escape hatch ───────────────────────────────────────────────────

    /// A command this module does not model, with attributes the caller
    /// encoded itself. Everything devlink can do that is not in the typed API
    /// above — rate objects, traps, DPIPE, shared buffers, flash update,
    /// selftests, linecards, reload, port function — is reachable through this.
    pub const RawRequest = struct {
        cmd: u8,
        /// Pre-encoded attribute TLVs, everything after the `genlmsghdr`.
        attrs: []const u8 = &.{},
        /// Add `NLM_F_DUMP` and collect every reply until `NLMSG_DONE`.
        dump: bool = false,
        /// Extra `NLM_F_*` bits beyond REQUEST|ACK (and DUMP when `dump`).
        extra_flags: u16 = 0,
        /// Clear `NLM_F_ACK`. The real `devlink` binary omits it on a few
        /// commands (`RESOURCE_DUMP`, `RESOURCE_SET`); the typed API here
        /// always asks for one.
        no_ack: bool = false,
        version: u8 = uapi.family_version,
    };

    pub fn freeRawReplies(gpa: std.mem.Allocator, list: []Reply) void {
        for (list) |r| gpa.free(r.attrs);
        gpa.free(list);
    }

    /// Send a raw request and collect every family reply. An ACK-only command
    /// yields an empty list. Free with `freeRawReplies`.
    pub fn raw(cl: *Devlink, req: RawRequest) RequestError![]Reply {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        var flags = codec.NLM_F_REQUEST | req.extra_flags;
        if (!req.no_ack) flags |= codec.NLM_F_ACK;
        if (req.dump) flags |= codec.NLM_F_DUMP;
        const off = try codec.appendHeader(gpa, &msg, cl.family_id, flags, seq, 0);
        try genl.appendHeader(gpa, &msg, req.cmd, req.version);
        try msg.appendSlice(gpa, req.attrs);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);

        var out: std.ArrayList(Reply) = .empty;
        errdefer {
            for (out.items) |r| gpa.free(r.attrs);
            out.deinit(gpa);
        }
        var walk: Walk = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            const copy = try gpa.dupe(u8, m.attrs);
            errdefer gpa.free(copy);
            try out.append(gpa, .{ .cmd = m.cmd, .attrs = copy });
        }
        return out.toOwnedSlice(gpa);
    }

    // ── plumbing ───────────────────────────────────────────────────────────

    fn begin(
        cl: *Devlink,
        msg: *std.ArrayList(u8),
        seq: u32,
        cmd: u8,
        dump: bool,
    ) RequestError!usize {
        const gpa = cl.allocator();
        cl.sock.ext_ack_len = 0;
        var flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK;
        if (dump) flags |= codec.NLM_F_DUMP;
        const off = try codec.appendHeader(gpa, msg, cl.family_id, flags, seq, 0);
        try genl.appendHeader(gpa, msg, cmd, uapi.family_version);
        return off;
    }

    /// Build and send a command whose only attributes are an optional handle.
    fn sendSimple(
        cl: *Devlink,
        cmd: u8,
        h: ?handle_mod.Handle,
        dump: bool,
    ) RequestError!u32 {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const off = try cl.begin(&msg, seq, cmd, dump);
        if (h) |x| handle_mod.append(gpa, &msg, x) catch |e| return mapBuild(e);
        codec.finishHeader(&msg, off);
        try cl.send(msg.items);
        return seq;
    }

    /// A `doit` GET whose only attributes are the handle, returning its one
    /// reply message.
    fn simpleGet(cl: *Devlink, cmd: u8, h: handle_mod.Handle) RequestError!Reply {
        const seq = try cl.sendSimple(cmd, h, false);
        return (try cl.collect(seq)) orelse error.MalformedReply;
    }

    /// Read to the end of a request's replies, keeping the first family
    /// message. A command answered with a bare ACK yields null.
    fn collect(cl: *Devlink, seq: u32) RequestError!?Reply {
        const gpa = cl.allocator();
        var found: ?Reply = null;
        errdefer if (found) |r| gpa.free(r.attrs);
        var walk: Walk = .{ .cl = cl, .seq = seq };
        while (try walk.next()) |m| {
            if (found != null) continue; // drain the rest, keep the first
            found = .{ .cmd = m.cmd, .attrs = try gpa.dupe(u8, m.attrs) };
        }
        return found;
    }

    fn send(cl: *Devlink, msg: []const u8) RequestError!void {
        cl.sock.send(msg) catch |e| return switch (e) {
            error.AccessDenied => error.AccessDenied,
            error.SystemResources => error.SystemResources,
            error.SendFailed => error.SendFailed,
        };
    }

    /// Keep the kernel's own sentence out of an `NLMSG_ERROR`, in the shared
    /// transport's buffer. Mirrors `netlink.Socket.captureExtAck`, which is
    /// not reachable through the `genetlink` facade.
    fn noteErrorMessage(cl: *Devlink, m: codec.Message) void {
        cl.sock.ext_ack_len = 0;
        const maybe = m.errorMessage() catch return;
        const s = maybe orelse return;
        const n = @min(s.len, cl.sock.ext_ack_buf.len);
        @memcpy(cl.sock.ext_ack_buf[0..n], s[0..n]);
        cl.sock.ext_ack_len = n;
    }
};

fn validate(h: handle_mod.Handle) RequestError!void {
    h.validate() catch return error.InvalidRequest;
}

/// C-10 binding check for the single-object (`doit`) device-scoped
/// commands: the reply's echoed handle must name the exact device the
/// request asked about. The dump variants (`ports`/`params`/`regions`/
/// `healthReporters`) already filter client-side on `p.handle.eql(h)`; this
/// is that same invariant enforced on the `doit` path, which is the one
/// that writes hardware.
fn checkHandleEcho(want: handle_mod.Handle, got: handle_mod.Owned) RequestError!void {
    if (!got.isComplete()) return error.UnexpectedHandle;
    if (!got.eql(want)) return error.UnexpectedHandle;
}

/// Same check for `port`, whose identity is a device handle *plus* a port
/// index — `PortHandle` has no `.eql` of its own, so both halves are
/// compared here.
fn checkPortHandleEcho(want: handle_mod.PortHandle, got: handle_mod.Owned, got_index: ?u32) RequestError!void {
    try checkHandleEcho(want.handle, got);
    if (got_index != want.index) return error.UnexpectedHandle;
}

fn recvErr(e: genl.RecvError) RequestError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MalformedReply => error.MalformedReply,
        error.SystemResources => error.SystemResources,
        error.RecvFailed => error.RecvFailed,
    };
}

fn mapBuild(e: anyerror) RequestError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidRequest => error.InvalidRequest,
        else => error.InvalidRequest,
    };
}

fn mapParse(e: anyerror) RequestError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.MalformedReply,
    };
}

/// Fold the shared resolver's error set onto this module's. `FamilyNotFound`
/// becomes `NoSuchDevice`, which is what an `ENOENT` from nlctrl mapped to
/// before the resolver was shared; `NameTooLong` cannot happen for a name this
/// module hardcodes.
fn mapResolve(e: genl.McastGroupError) SubscribeError {
    return switch (e) {
        error.GroupNotFound => error.GroupNotFound,
        error.FamilyNotFound => error.NoSuchDevice,
        error.NameTooLong => unreachable, // "devlink" fits GENL_NAMSIZ
        error.OutOfMemory => error.OutOfMemory,
        error.SendFailed => error.SendFailed,
        error.RecvFailed => error.RecvFailed,
        error.MalformedReply => error.MalformedReply,
        error.AccessDenied => error.AccessDenied,
        error.SystemResources => error.SystemResources,
        error.Unexpected => error.Unexpected,
    };
}

/// One family reply message. `attrs` borrows the socket's receive buffer and is
/// valid only until the next `Walk.next` call.
const WalkMessage = struct {
    cmd: u8,
    attrs: []const u8,
};

/// Ceiling on how many netlink messages one `Walk` scan may consume before
/// giving up. **W2 audit finding, campaign C-06**: the kernel is the only
/// verified sender on this socket, so this is a robustness ceiling against a
/// malfunctioning driver, not an attacker-facing bound — but without it, a
/// kernel that never sends `NLMSG_DONE` hangs the caller (and every dump
/// collector built on `Walk`) forever. Generous relative to any real dump.
const max_walk_messages: u32 = 65536;

/// Walks a request's replies, hiding datagram boundaries. Terminates on the
/// ACK (a `doit`), on `NLMSG_DONE` (a dump), or on `error.TooManyMessages`
/// once `max_walk_messages` is exceeded.
const Walk = struct {
    cl: *Devlink,
    seq: u32,
    it: codec.MessageIterator = .{ .buf = &.{} },
    finished: bool = false,
    msgs: u32 = 0,

    fn next(w: *Walk) RequestError!?WalkMessage {
        return walkStep(w.cl, w.seq, &w.it, &w.finished, &w.msgs);
    }
};

/// The body of `Walk.next`, factored out so a mock transport can drive it in
/// tests without a real socket (same technique as the sibling `conntrack`
/// module's `dumpOver` and `ethtool`'s `walkStep`). `cl` need only look like
/// `*Devlink` for the fields/methods this loop touches:
/// `cl.sock.recvDatagram()`, `cl.sock.portid`, `cl.family_id`,
/// `cl.noteErrorMessage(msg)`.
fn walkStep(
    cl: anytype,
    seq: u32,
    it: *codec.MessageIterator,
    finished: *bool,
    msgs: *u32,
) RequestError!?WalkMessage {
    while (true) {
        if (finished.*) return null;
        const maybe = it.next() catch return error.MalformedReply;
        const m = maybe orelse {
            if (msgs.* >= max_walk_messages) return error.TooManyMessages;
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
                if (code != 0) {
                    // Keep the kernel's sentence before mapping the errno:
                    // "no such region" says far more than ENODEV.
                    cl.noteErrorMessage(m);
                    return errnoToError(code);
                }
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

/// One decoded message off the `config` group. `attrs` is an owned copy, so a
/// notification outlives the datagram it came from — hand it to the matching
/// typed parser (`port.parse`, `param.parse`, `region.parseRegion`, …) to read
/// the payload.
pub const Notification = struct {
    /// The `DEVLINK_CMD_*` value. devlink has no separate `_NTF` namespace:
    /// the kernel multicasts the same `NEW`/`DEL` commands it uses for
    /// replies — see `uapi.isNotifyCommand`.
    cmd: u8,
    /// The devlink instance the notification is about, when the message
    /// carried a handle.
    handle: handle_mod.Owned = .{},
    attrs: []u8,

    pub fn deinit(n: *Notification, gpa: std.mem.Allocator) void {
        gpa.free(n.attrs);
        n.* = .{ .cmd = 0, .attrs = &.{} };
    }

    /// Is this one of the commands the kernel actually multicasts, rather than
    /// a stray reply that happened to land on this socket?
    pub fn isNotification(n: Notification) bool {
        return uapi.isNotifyCommand(n.cmd);
    }
};

/// A `NETLINK_GENERIC` socket subscribed to devlink's `config` group.
///
/// **One blocking call: `waitForNotification`.** See the file header for why
/// the threading policy is the caller's.
///
/// The group carries every devlink change on the system — a port appearing, a
/// parameter being written, a snapshot being taken, a health reporter tripping,
/// flash-update progress — including changes made by *other* processes, which
/// is the point.
pub const EventSocket = struct {
    sock: genl.Socket,
    family_id: u16,
    /// Unconsumed bytes of the datagram most recently received. Points into
    /// `sock.buf`, which is only reallocated by `recvDatagram` — and that is
    /// called only when this is empty.
    it: codec.MessageIterator = .{ .buf = &.{} },

    /// Open an event socket and subscribe to `groups` (normally just
    /// `uapi.mcast_group.config`). Resolving and joining are unprivileged.
    ///
    /// This opens a throwaway command socket to resolve the ids; a caller that
    /// already has a `Devlink` should use `openWith`.
    pub fn open(
        gpa: std.mem.Allocator,
        groups: []const []const u8,
    ) (OpenError || SubscribeError)!EventSocket {
        var cmd = try Devlink.open(gpa);
        defer cmd.close();
        return openWith(&cmd, groups);
    }

    /// Open an event socket, resolving the group ids over an existing command
    /// socket.
    pub fn openWith(
        cmd: *Devlink,
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
    /// this for readability, and only then call `waitForNotification`.
    pub fn fd(ev: *const EventSocket) i32 {
        return ev.sock.fd;
    }

    /// **The one blocking call.** Returns the next devlink notification,
    /// performing a single `recvmsg` only when the previously received datagram
    /// has been drained. Messages that are not devlink-family messages are
    /// skipped. Free the result with `deinit`.
    pub fn waitForNotification(ev: *EventSocket, gpa: std.mem.Allocator) RequestError!Notification {
        while (true) {
            const maybe = ev.it.next() catch return error.MalformedReply;
            const m = maybe orelse {
                const dgram = ev.sock.recvDatagram() catch |e| return recvErr(e);
                ev.it = .{ .buf = dgram };
                continue;
            };
            if (m.type != ev.family_id) continue;
            const p = genl.splitPayload(m.payload) catch return error.MalformedReply;
            return parseNotification(gpa, p.cmd, p.attrs) catch |e| return mapParse(e);
        }
    }
};

/// Decode one notification's command + attribute bytes into an owned
/// `Notification`. Pure apart from the copy.
pub fn parseNotification(
    gpa: std.mem.Allocator,
    cmd: u8,
    attr_bytes: []const u8,
) (codec.Error || error{OutOfMemory})!Notification {
    const h = try handle_mod.parse(attr_bytes);
    const copy = try gpa.dupe(u8, attr_bytes);
    return .{ .cmd = cmd, .handle = h, .attrs = copy };
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "errnoToError maps the errnos devlink actually returns" {
    try testing.expectEqual(error.AccessDenied, errnoToError(-@as(i32, @intFromEnum(linux.E.PERM))));
    // The single most common devlink outcome: a valid request against a
    // handle no driver has registered.
    try testing.expectEqual(error.NoSuchDevice, errnoToError(-@as(i32, @intFromEnum(linux.E.NODEV))));
    try testing.expectEqual(error.NoSuchDevice, errnoToError(-@as(i32, @intFromEnum(linux.E.NOENT))));
    try testing.expectEqual(error.NotSupported, errnoToError(-@as(i32, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expectEqual(error.InvalidRequest, errnoToError(-@as(i32, @intFromEnum(linux.E.INVAL))));
    try testing.expectEqual(error.Busy, errnoToError(-@as(i32, @intFromEnum(linux.E.BUSY))));
    try testing.expectEqual(error.SystemResources, errnoToError(-@as(i32, @intFromEnum(linux.E.NOMEM))));
    try testing.expectEqual(error.Unexpected, errnoToError(0));
    try testing.expectEqual(error.Unexpected, errnoToError(7));
    try testing.expectEqual(error.Unexpected, errnoToError(std.math.minInt(i32)));
}

test "mapResolve folds the shared resolver's extra errors onto this set" {
    try testing.expectEqual(error.GroupNotFound, mapResolve(error.GroupNotFound));
    // What an ENOENT from nlctrl mapped to before the resolver was shared.
    try testing.expectEqual(error.NoSuchDevice, mapResolve(error.FamilyNotFound));
    try testing.expectEqual(error.AccessDenied, mapResolve(error.AccessDenied));
    try testing.expectEqual(error.MalformedReply, mapResolve(error.MalformedReply));
}

test "parseNotification recovers the command and the handle" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try handle_mod.append(gpa, &attrs, .pci("0000:65:00.0"));
    try codec.appendAttrU32(gpa, &attrs, uapi.ATTR.PORT_INDEX, 3);
    try codec.appendAttrU16(gpa, &attrs, uapi.ATTR.PORT_TYPE, @intFromEnum(uapi.PortType.eth));

    var n = try parseNotification(gpa, uapi.CMD.PORT_NEW, attrs.items);
    defer n.deinit(gpa);
    try testing.expect(n.isNotification());
    try testing.expectEqualStrings("0000:65:00.0", n.handle.dev());
    // The payload decodes with the ordinary typed parser.
    const p = try port_mod.parse(n.attrs);
    try testing.expectEqual(@as(?u32, 3), p.index);
    try testing.expectEqual(@as(?uapi.PortType, .eth), p.type);
}

test "parseNotification on a request-only command is not a notification" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try handle_mod.append(gpa, &attrs, .pci("0000:65:00.0"));
    var n = try parseNotification(gpa, uapi.CMD.PORT_GET, attrs.items);
    defer n.deinit(gpa);
    try testing.expect(!n.isNotification());
    try testing.expect(n.handle.isComplete());
}

test "parseNotification: malformed attributes are typed errors" {
    try testing.expectError(error.Truncated, parseNotification(testing.allocator, 1, &.{ 0x40, 0x00 }));
    // A DEV_NAME longer than `Owned` can hold: rejected, not truncated.
    const oversize = [_]u8{ 0x45, 0x00, 0x02, 0x00 } ++ [_]u8{'x'} ** 65;
    try testing.expectError(error.BadLength, parseNotification(testing.allocator, 1, &oversize));
}

test "fuzz: notification parsing never crashes" {
    try testing.fuzz({}, fuzzNotification, .{});
}

fn fuzzNotification(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    const cmd = smith.valueRangeAtMost(u8, 0, 255);
    if (parseNotification(testing.allocator, cmd, buf[0..len])) |n| {
        var v = n;
        _ = v.isNotification();
        v.deinit(testing.allocator);
    } else |_| {}
}

// ── C-10 regression: single-object requests must bind the reply's handle ───
// W2-nn (`devlink` F4, campaign C-10): `port`/`param`/`region`/
// `healthReporter`/`info`/`eswitch`/`resources` handed the reply straight to
// the typed parser with no check that the echoed handle named the device
// (and, for `port`, the port index) that was asked about. `checkHandleEcho`/
// `checkPortHandleEcho` are the fix, and both are pure (no socket needed).

fn ownedHandle(bus: []const u8, dev: []const u8) handle_mod.Owned {
    var o: handle_mod.Owned = .{};
    @memcpy(o.bus_buf[0..bus.len], bus);
    o.bus_len = @intCast(bus.len);
    @memcpy(o.dev_buf[0..dev.len], dev);
    o.dev_len = @intCast(dev.len);
    return o;
}

test "checkHandleEcho accepts a reply that echoes the requested handle" {
    try checkHandleEcho(.pci("0000:65:00.0"), ownedHandle("pci", "0000:65:00.0"));
}

test "checkHandleEcho rejects a reply for a different device" {
    try testing.expectError(
        error.UnexpectedHandle,
        checkHandleEcho(.pci("0000:65:00.0"), ownedHandle("pci", "0000:03:00.0")),
    );
}

test "checkHandleEcho rejects a reply with only half a handle" {
    try testing.expectError(
        error.UnexpectedHandle,
        checkHandleEcho(.pci("0000:65:00.0"), ownedHandle("pci", "")),
    );
}

test "checkPortHandleEcho accepts a reply that echoes handle and index" {
    try checkPortHandleEcho(
        .{ .handle = .pci("0000:65:00.0"), .index = 3 },
        ownedHandle("pci", "0000:65:00.0"),
        3,
    );
}

test "checkPortHandleEcho rejects a reply for the right device but wrong port index" {
    try testing.expectError(
        error.UnexpectedHandle,
        checkPortHandleEcho(
            .{ .handle = .pci("0000:65:00.0"), .index = 3 },
            ownedHandle("pci", "0000:65:00.0"),
            4,
        ),
    );
}

test "checkPortHandleEcho rejects a reply that carries no index at all" {
    try testing.expectError(
        error.UnexpectedHandle,
        checkPortHandleEcho(
            .{ .handle = .pci("0000:65:00.0"), .index = 3 },
            ownedHandle("pci", "0000:65:00.0"),
            null,
        ),
    );
}

// ── C-06 regression: the dump loop must not spin forever ───────────────────
// W2-nn (`devlink` F5, campaign C-06): `Walk.next` looped on `recvDatagram`
// with no upper bound, so a peer that never sends `NLMSG_DONE`/an ACK hangs
// the caller (and every dump collector built on `Walk`) forever. `walkStep`
// was factored out of `Walk.next` precisely so a scripted stand-in can drive
// it here, the same technique the sibling `conntrack` module's
// `ScriptedTransport` uses for `dumpOver`.

const MockSock = struct {
    portid: u32,
    datagram: []const u8,

    fn recvDatagram(self: *MockSock) genl.RecvError![]const u8 {
        return self.datagram;
    }
};

const MockDevlink = struct {
    sock: MockSock,
    family_id: u16,

    fn noteErrorMessage(_: *MockDevlink, _: codec.Message) void {}
};

fn nonTerminatingDatagram(gpa: std.mem.Allocator, pid: u32, seq: u32, family_id: u16) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, family_id +% 1, codec.NLM_F_MULTI, seq, pid);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

test "Walk.next errors out instead of looping forever on a never-DONE reply" {
    const family_id: u16 = 0x19;
    const seq: u32 = 5;
    const pid: u32 = 100;
    const dgram = try nonTerminatingDatagram(testing.allocator, pid, seq, family_id);
    defer testing.allocator.free(dgram);

    var cl: MockDevlink = .{ .sock = .{ .portid = pid, .datagram = dgram }, .family_id = family_id };
    var it: codec.MessageIterator = .{ .buf = &.{} };
    var finished = false;
    var msgs: u32 = 0;
    try testing.expectError(error.TooManyMessages, walkStep(&cl, seq, &it, &finished, &msgs));
    try testing.expectEqual(max_walk_messages, msgs);
}

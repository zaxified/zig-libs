// SPDX-License-Identifier: MIT
//! The ethtool client: one `NETLINK_GENERIC` socket plus the resolved `ethtool`
//! family id, the typed commands built on it, and a separate **event socket**
//! for the family's single `monitor` multicast group.
//!
//! ## The blocking seam
//!
//! Command methods (`linkModes`, `rings`, `setPause`, …) are ordinary blocking
//! request/reply calls: they send one message and read until the kernel's ACK.
//!
//! Notifications are different, and this module refuses to hide that.
//! **`EventSocket` has exactly one blocking call — `waitForNotification`** —
//! and it does exactly one `recvmsg` when its buffer is drained. There is no
//! timer thread, no deadline and no event loop here: a caller that wants a
//! bounded wait polls `fd()` itself and only calls `waitForNotification` once
//! the fd is readable. That is the same seam discipline the sibling `nl80211`
//! (`EventSocket.waitForEvent`), `netconf` (`Client.pumpOnce`) and `ebpf`
//! (ring-buffer consumer) modules use, and for the same reason — threading
//! policy belongs to the application, not to a protocol library.
//!
//! ## Extended ACKs
//!
//! The shared `netlink` transport enables `NETLINK_EXT_ACK` on every socket it
//! opens, so a rejection carries the kernel's own sentence — "failed to
//! retrieve link settings" is what a Wi-Fi interface answers a `LINKMODES_GET`
//! with. `lastErrorMessage` returns it, out of the transport's own buffer;
//! this module keeps no second copy. Without the sockopt the same rejection is
//! a bare `EOPNOTSUPP`, which is why it is on by default and not an option.
//!
//! ## Every reply is a single message
//!
//! Unlike rtnetlink or nl80211, an ethtool GET for one device answers with one
//! message and then an ACK — there is no split dump to reassemble. (Requests
//! with an *empty* header nest can be dumped across all devices with
//! `NLM_F_DUMP`; that is reachable through `raw` and is not modelled in the
//! typed API — see SPEC.md.)

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");

const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");
const link = @import("link.zig");
const params = @import("params.zig");
const features_mod = @import("features.zig");
const stats_mod = @import("stats.zig");
const moduleinfo = @import("moduleinfo.zig");

/// `NETLINK_ADD_MEMBERSHIP` / `NETLINK_DROP_MEMBERSHIP` (linux/netlink.h) —
/// used by `EventSocket` below.
pub const NETLINK_ADD_MEMBERSHIP: u32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: u32 = 2;
/// `NETLINK_EXT_ACK`. This module no longer sets it — the shared `netlink`
/// transport does, on every socket — but the constant stays public because it
/// always was.
pub const NETLINK_EXT_ACK: u32 = 11;

pub const RequestError = error{
    OutOfMemory,
    SendFailed,
    RecvFailed,
    /// A reply failed wire-format validation (bounds/length checks).
    MalformedReply,
    /// The command needs a capability this process does not have — every
    /// ethtool SET wants **CAP_NET_ADMIN**, and so do a few GETs (`WOL_GET`).
    AccessDenied,
    /// The kernel rejected the request's contents, or this module built one it
    /// knows the kernel would reject. Check `lastErrorMessage`.
    InvalidRequest,
    /// No such interface.
    NoSuchDevice,
    /// The driver does not implement this operation — by far the most common
    /// outcome of a perfectly valid ethtool request. Not a bug: a virtual
    /// interface implements almost none of this family.
    NotSupported,
    Busy,
    SystemResources,
    Unexpected,
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
        // ENOENT from an ethtool command means "no such interface"; from
        // nlctrl it means "no such family", which `genl.resolveFamily` handles.
        @intFromEnum(linux.E.NOENT) => error.NoSuchDevice,
        @intFromEnum(linux.E.OPNOTSUPP) => error.NotSupported,
        @intFromEnum(linux.E.INVAL), @intFromEnum(linux.E.MSGSIZE) => error.InvalidRequest,
        @intFromEnum(linux.E.BUSY), @intFromEnum(linux.E.AGAIN) => error.Busy,
        @intFromEnum(linux.E.NOBUFS), @intFromEnum(linux.E.NOMEM) => error.SystemResources,
        else => error.Unexpected,
    };
}

/// Which bitset encoding to ask the kernel for. Verbose costs bytes and gives
/// names; compact is cheap and gives bare bit numbers whose meaning has to come
/// from a `stringSet` lookup. See `bitset.zig`.
pub const BitsetForm = enum {
    verbose,
    compact,

    fn compactFlag(f: BitsetForm) bool {
        return f == .compact;
    }
};

/// Find the id of the multicast group named `want` in the attribute bytes of a
/// `CTRL_CMD_NEWFAMILY` reply. Pure — golden-tested offline against a captured
/// nlctrl reply.
///
/// A thin wrapper over `genetlink.findMcastGroupId`. This walk was copied here
/// from `nl80211`, which asked for exactly that to be promoted once a second
/// family needed it; it has been, and the name is kept because it is part of
/// this module's public API and `goldens.zig` drives it.
pub fn findMcastGroupId(attr_bytes: []const u8, want: []const u8) codec.Error!?u32 {
    return genl.findMcastGroupId(attr_bytes, want);
}

/// nlctrl attributes, re-exported from `genetlink` — this module used to
/// declare its own copies.
pub const CTRL_ATTR_MCAST_GROUPS = genl.CTRL_ATTR_MCAST_GROUPS;
pub const CTRL_ATTR_MCAST_GRP_NAME = genl.CTRL_ATTR_MCAST_GRP_NAME;
pub const CTRL_ATTR_MCAST_GRP_ID = genl.CTRL_ATTR_MCAST_GRP_ID;

/// The longest kernel extended-ACK sentence kept. Now the shared netlink
/// transport's own cap rather than a second, smaller buffer here; anything
/// longer is truncated rather than allocated.
pub const max_error_message = @FieldType(genl.Socket, "ext_ack_buf").len;

/// Fold the shared resolver's error set onto this module's. `FamilyNotFound`
/// becomes `NoSuchDevice`, which is exactly what an `ENOENT` from nlctrl
/// mapped to through `errnoToError` before the resolver was shared;
/// `NameTooLong` cannot happen for a name this module hardcodes.
fn mapResolve(e: genl.McastGroupError) SubscribeError {
    return switch (e) {
        error.GroupNotFound => error.GroupNotFound,
        error.FamilyNotFound => error.NoSuchDevice,
        error.NameTooLong => unreachable, // "ethtool" fits GENL_NAMSIZ
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

/// Ethernet device control client. One instance per thread/loop; no shared
/// state.
pub const Ethtool = struct {
    sock: genl.Socket,
    /// The dynamically resolved `ethtool` message-type id (23 on the
    /// development machine — never hardcode it).
    family_id: u16,

    /// Open a `NETLINK_GENERIC` socket and resolve the ethtool family.
    /// `error.FamilyNotFound` means a kernel without `CONFIG_ETHTOOL_NETLINK`
    /// (or none visible in this network namespace).
    ///
    /// `NETLINK_EXT_ACK` is set by the shared transport, not here.
    pub fn open(gpa: std.mem.Allocator) OpenError!Ethtool {
        var sock = try genl.Socket.open(gpa);
        errdefer sock.close();
        const family_id = try sock.resolveFamily(uapi.family_name);
        return .{ .sock = sock, .family_id = family_id };
    }

    pub fn close(cl: *Ethtool) void {
        cl.sock.close();
        cl.* = undefined;
    }

    pub fn allocator(cl: *Ethtool) std.mem.Allocator {
        return cl.sock.gpa;
    }

    /// The kernel's own explanation of the most recent rejection
    /// (`NLMSGERR_ATTR_MSG`), or null when it attached none. Valid until the
    /// next request on this client. The buffer belongs to the shared netlink
    /// transport; this module keeps no copy of its own.
    pub fn lastErrorMessage(cl: *const Ethtool) ?[]const u8 {
        const s = cl.sock.lastErrorMessage();
        return if (s.len == 0) null else s;
    }

    // ── link ───────────────────────────────────────────────────────────────

    /// `ETHTOOL_MSG_LINKINFO_GET` — port, PHY address, MDI-X, transceiver.
    /// Unprivileged.
    pub fn linkInfo(cl: *Ethtool, target: header.Target) RequestError!link.LinkInfo {
        var reply = try cl.simpleGet(uapi.MSG.LINKINFO_GET, uapi.LINKINFO.HEADER, .{ .target = target });
        defer reply.deinit(cl.allocator());
        return link.parseLinkInfo(reply.attrs) catch error.MalformedReply;
    }

    /// `ETHTOOL_MSG_LINKINFO_SET`. Needs **CAP_NET_ADMIN**.
    pub fn setLinkInfo(cl: *Ethtool, target: header.Target, set: link.LinkInfoSet) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.LINKINFO_SET, false);
        try cl.appendHeaderNest(&msg, uapi.LINKINFO.HEADER, .{ .target = target });
        try link.appendLinkInfoSet(gpa, &msg, set);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    /// `ETHTOOL_MSG_LINKMODES_GET` — autoneg, speed, duplex and the
    /// supported/advertised link-mode bitsets. Unprivileged.
    ///
    /// `form` decides the bitset encoding: `.verbose` (the default worth
    /// wanting) carries the kernel's name for every mode, `.compact` carries
    /// bare words. See `bitset.zig`.
    pub fn linkModes(
        cl: *Ethtool,
        target: header.Target,
        form: BitsetForm,
    ) RequestError!link.LinkModes {
        var reply = try cl.simpleGet(uapi.MSG.LINKMODES_GET, uapi.LINKMODES.HEADER, .{
            .target = target,
            .compact_bitsets = form.compactFlag(),
        });
        defer reply.deinit(cl.allocator());
        return link.parseLinkModes(cl.allocator(), reply.attrs) catch |e| return mapParse(e);
    }

    /// `ETHTOOL_MSG_LINKMODES_SET`. Needs **CAP_NET_ADMIN**.
    pub fn setLinkModes(cl: *Ethtool, target: header.Target, set: link.LinkModesSet) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.LINKMODES_SET, false);
        try cl.appendHeaderNest(&msg, uapi.LINKMODES.HEADER, .{ .target = target });
        link.appendLinkModesSet(gpa, &msg, set) catch |e| return mapParse(e);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    /// `ETHTOOL_MSG_LINKSTATE_GET` — carrier, SQI, and why the link is down.
    /// Unprivileged.
    pub fn linkState(cl: *Ethtool, target: header.Target) RequestError!link.LinkState {
        var reply = try cl.simpleGet(uapi.MSG.LINKSTATE_GET, uapi.LINKSTATE.HEADER, .{ .target = target });
        defer reply.deinit(cl.allocator());
        return link.parseLinkState(reply.attrs) catch error.MalformedReply;
    }

    // ── ring / channel / coalesce / pause parameters ───────────────────────

    /// `ETHTOOL_MSG_RINGS_GET`. Unprivileged.
    pub fn rings(cl: *Ethtool, target: header.Target) RequestError!params.Rings {
        var reply = try cl.simpleGet(uapi.MSG.RINGS_GET, uapi.RINGS.HEADER, .{ .target = target });
        defer reply.deinit(cl.allocator());
        return params.parseRings(reply.attrs) catch error.MalformedReply;
    }

    /// `ETHTOOL_MSG_RINGS_SET`. Needs **CAP_NET_ADMIN**.
    pub fn setRings(cl: *Ethtool, target: header.Target, set: params.RingsSet) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.RINGS_SET, false);
        try cl.appendHeaderNest(&msg, uapi.RINGS.HEADER, .{ .target = target });
        try params.appendRingsSet(gpa, &msg, set);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    /// `ETHTOOL_MSG_CHANNELS_GET`. Unprivileged.
    pub fn channels(cl: *Ethtool, target: header.Target) RequestError!params.Channels {
        var reply = try cl.simpleGet(uapi.MSG.CHANNELS_GET, uapi.CHANNELS.HEADER, .{ .target = target });
        defer reply.deinit(cl.allocator());
        return params.parseChannels(reply.attrs) catch error.MalformedReply;
    }

    /// `ETHTOOL_MSG_CHANNELS_SET`. Needs **CAP_NET_ADMIN**.
    pub fn setChannels(cl: *Ethtool, target: header.Target, set: params.ChannelsSet) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.CHANNELS_SET, false);
        try cl.appendHeaderNest(&msg, uapi.CHANNELS.HEADER, .{ .target = target });
        try params.appendChannelsSet(gpa, &msg, set);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    /// `ETHTOOL_MSG_COALESCE_GET`. Unprivileged.
    pub fn coalesce(cl: *Ethtool, target: header.Target) RequestError!params.Coalesce {
        var reply = try cl.simpleGet(uapi.MSG.COALESCE_GET, uapi.COALESCE.HEADER, .{ .target = target });
        defer reply.deinit(cl.allocator());
        return params.parseCoalesce(reply.attrs) catch error.MalformedReply;
    }

    /// `ETHTOOL_MSG_COALESCE_SET`. Needs **CAP_NET_ADMIN**.
    pub fn setCoalesce(cl: *Ethtool, target: header.Target, set: params.CoalesceSet) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.COALESCE_SET, false);
        try cl.appendHeaderNest(&msg, uapi.COALESCE.HEADER, .{ .target = target });
        try params.appendCoalesceSet(gpa, &msg, set);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    /// `ETHTOOL_MSG_PAUSE_GET`. Unprivileged. `want_stats` sets
    /// `ETHTOOL_FLAG_STATS`, which is the only way the optional pause-frame
    /// counters come back.
    pub fn pauseParams(cl: *Ethtool, target: header.Target, want_stats: bool) RequestError!params.Pause {
        var reply = try cl.simpleGet(uapi.MSG.PAUSE_GET, uapi.PAUSE.HEADER, .{
            .target = target,
            .stats = want_stats,
        });
        defer reply.deinit(cl.allocator());
        return params.parsePause(reply.attrs) catch error.MalformedReply;
    }

    /// `ETHTOOL_MSG_PAUSE_SET`. Needs **CAP_NET_ADMIN**.
    pub fn setPause(cl: *Ethtool, target: header.Target, set: params.PauseSet) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.PAUSE_SET, false);
        try cl.appendHeaderNest(&msg, uapi.PAUSE.HEADER, .{ .target = target });
        try params.appendPauseSet(gpa, &msg, set);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    // ── features ───────────────────────────────────────────────────────────

    /// `ETHTOOL_MSG_FEATURES_GET` — the four feature bitsets. Unprivileged.
    pub fn features(
        cl: *Ethtool,
        target: header.Target,
        form: BitsetForm,
    ) RequestError!features_mod.Features {
        var reply = try cl.simpleGet(uapi.MSG.FEATURES_GET, uapi.FEATURES.HEADER, .{
            .target = target,
            .compact_bitsets = form.compactFlag(),
        });
        defer reply.deinit(cl.allocator());
        return features_mod.parse(cl.allocator(), reply.attrs) catch |e| return mapParse(e);
    }

    /// `ETHTOOL_MSG_FEATURES_SET` by feature name. Needs **CAP_NET_ADMIN**.
    ///
    /// **Read the result.** The ACK only means the request was processed; the
    /// returned `SetResult` is what says whether the bits actually changed.
    /// Free it with `deinit`.
    pub fn setFeaturesByName(
        cl: *Ethtool,
        target: header.Target,
        entries: []const bitset.NamedValue,
    ) RequestError!features_mod.SetResult {
        return cl.setFeaturesImpl(target, entries, null);
    }

    /// Same, keyed by bit index rather than name.
    pub fn setFeaturesByIndex(
        cl: *Ethtool,
        target: header.Target,
        entries: []const bitset.IndexedValue,
    ) RequestError!features_mod.SetResult {
        return cl.setFeaturesImpl(target, null, entries);
    }

    fn setFeaturesImpl(
        cl: *Ethtool,
        target: header.Target,
        by_name: ?[]const bitset.NamedValue,
        by_index: ?[]const bitset.IndexedValue,
    ) RequestError!features_mod.SetResult {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.FEATURES_SET, false);
        try cl.appendHeaderNest(&msg, uapi.FEATURES.HEADER, .{ .target = target });
        if (by_name) |e| features_mod.appendSetByName(gpa, &msg, e) catch |err| return mapParse(err);
        if (by_index) |e| features_mod.appendSetByIndex(gpa, &msg, e) catch |err| return mapParse(err);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse return .{};
        defer reply.deinit(gpa);
        return features_mod.parseSetResult(gpa, reply.attrs) catch |e| return mapParse(e);
    }

    // ── statistics and string sets ─────────────────────────────────────────

    /// `ETHTOOL_MSG_STATS_GET` for the named standard groups
    /// (`ethtool.stats.group_names`). Unprivileged. Free with `deinit`.
    ///
    /// A driver that implements none of them answers with empty groups — see
    /// `stats.zig`'s header.
    pub fn stats(
        cl: *Ethtool,
        target: header.Target,
        groups: []const []const u8,
    ) RequestError!stats_mod.Stats {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.STATS_GET, false);
        try cl.appendHeaderNest(&msg, uapi.STATS.HEADER, .{ .target = target });
        if (groups.len != 0)
            stats_mod.appendGroupSelector(gpa, &msg, groups) catch |e| return mapParse(e);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse return error.MalformedReply;
        defer reply.deinit(gpa);
        return stats_mod.parse(gpa, reply.attrs) catch |e| return mapParse(e);
    }

    /// `ETHTOOL_MSG_STRSET_GET` — the kernel's string tables. Unprivileged.
    ///
    /// `target` is optional: the device-independent sets (`.features`,
    /// `.link_modes`, `.stats_std`, …) are answered by the kernel itself and
    /// `ethtool` asks for them with an empty header nest, which is what
    /// passing null does. Free with `deinit`.
    pub fn stringSet(
        cl: *Ethtool,
        target: ?header.Target,
        ids: []const uapi.StringSetId,
    ) RequestError!stats_mod.StringSets {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.STRSET_GET, false);
        if (target) |t| {
            try cl.appendHeaderNest(&msg, uapi.STRSET.HEADER, .{ .target = t });
        } else {
            header.appendGlobal(gpa, &msg, uapi.STRSET.HEADER, 0) catch |e| return mapHeader(e);
        }
        try stats_mod.appendStringSetSelector(gpa, &msg, ids);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse return error.MalformedReply;
        defer reply.deinit(gpa);
        return stats_mod.parseStringSets(gpa, reply.attrs) catch |e| return mapParse(e);
    }

    // ── pluggable module ───────────────────────────────────────────────────

    /// `ETHTOOL_MSG_MODULE_GET` — the transceiver's power-mode policy.
    /// `error.NotSupported` on any device without a pluggable module.
    pub fn moduleInfo(cl: *Ethtool, target: header.Target) RequestError!moduleinfo.ModuleInfo {
        var reply = try cl.simpleGet(uapi.MSG.MODULE_GET, uapi.MODULE.HEADER, .{ .target = target });
        defer reply.deinit(cl.allocator());
        return moduleinfo.parse(reply.attrs) catch error.MalformedReply;
    }

    /// `ETHTOOL_MSG_MODULE_SET`. Needs **CAP_NET_ADMIN**.
    pub fn setModulePowerPolicy(
        cl: *Ethtool,
        target: header.Target,
        policy: uapi.ModulePowerModePolicy,
    ) RequestError!void {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.MODULE_SET, false);
        try cl.appendHeaderNest(&msg, uapi.MODULE.HEADER, .{ .target = target });
        try moduleinfo.appendSet(gpa, &msg, policy);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        var reply = try cl.collect(seq);
        if (reply) |*r| r.deinit(gpa);
    }

    /// `ETHTOOL_MSG_MODULE_EEPROM_GET` — up to 128 raw bytes of the module's
    /// EEPROM. Unprivileged on a device that has a module; `EOPNOTSUPP`
    /// otherwise. Free with `deinit`.
    pub fn moduleEeprom(
        cl: *Ethtool,
        target: header.Target,
        req: moduleinfo.EepromRequest,
    ) RequestError!moduleinfo.Eeprom {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, uapi.MSG.MODULE_EEPROM_GET, false);
        try cl.appendHeaderNest(&msg, uapi.MODULE_EEPROM.HEADER, .{ .target = target });
        moduleinfo.appendEepromRequest(gpa, &msg, req) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidRequest => return error.InvalidRequest,
        };
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);

        var reply = (try cl.collect(seq)) orelse return error.MalformedReply;
        defer reply.deinit(gpa);
        return moduleinfo.parseEeprom(gpa, reply.attrs) catch |e| return mapParse(e);
    }

    // ── multicast groups ───────────────────────────────────────────────────

    /// Resolve the family's `monitor` multicast group to its dynamic id.
    /// Unprivileged.
    ///
    /// The nlctrl round trip is `genetlink.Socket.resolveMcastGroup`; this is
    /// the error-set adapter over it.
    pub fn resolveMulticastGroup(cl: *Ethtool, name: []const u8) SubscribeError!u32 {
        return cl.sock.resolveMcastGroup(uapi.family_name, name) catch |e| return mapResolve(e);
    }

    // ── raw escape hatch ───────────────────────────────────────────────────

    /// A command this module does not model, with attributes the caller
    /// encoded itself. Everything the ethtool family can do that is not in the
    /// typed API above — WOL, EEE, FEC, PRIVFLAGS, TSINFO, cable tests, RSS,
    /// PLCA, and the all-device dump form — is reachable through this.
    pub const RawRequest = struct {
        cmd: u8,
        /// Pre-encoded attribute TLVs — everything after the `genlmsghdr`,
        /// **including the header nest**, which every ethtool message needs.
        attrs: []const u8 = &.{},
        /// Add `NLM_F_DUMP` and collect every reply until `NLMSG_DONE`. Only
        /// meaningful with an empty header nest (= all devices).
        dump: bool = false,
        extra_flags: u16 = 0,
        version: u8 = uapi.family_version,
    };

    pub fn freeRawReplies(gpa: std.mem.Allocator, list: []Reply) void {
        for (list) |r| gpa.free(r.attrs);
        gpa.free(list);
    }

    /// Send a raw request and collect every family reply. An ACK-only command
    /// yields an empty list. Free with `freeRawReplies`.
    pub fn raw(cl: *Ethtool, req: RawRequest) RequestError![]Reply {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        var flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK | req.extra_flags;
        if (req.dump) flags |= codec.NLM_F_DUMP;
        const h = try codec.appendHeader(gpa, &msg, cl.family_id, flags, seq, 0);
        try genl.appendHeader(gpa, &msg, req.cmd, req.version);
        try msg.appendSlice(gpa, req.attrs);
        codec.finishHeader(&msg, h);
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
        cl: *Ethtool,
        msg: *std.ArrayList(u8),
        seq: u32,
        cmd: u8,
        dump: bool,
    ) RequestError!usize {
        const gpa = cl.allocator();
        cl.sock.ext_ack_len = 0;
        var flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK;
        if (dump) flags |= codec.NLM_F_DUMP;
        const h = try codec.appendHeader(gpa, msg, cl.family_id, flags, seq, 0);
        try genl.appendHeader(gpa, msg, cmd, uapi.family_version);
        return h;
    }

    fn appendHeaderNest(
        cl: *Ethtool,
        msg: *std.ArrayList(u8),
        attr_type: u16,
        opts: header.Options,
    ) RequestError!void {
        header.append(cl.allocator(), msg, attr_type, opts) catch |e| return mapHeader(e);
    }

    /// Build + send a device GET with no extra attributes and return its one
    /// reply message.
    fn simpleGet(
        cl: *Ethtool,
        cmd: u8,
        hdr_attr: u16,
        opts: header.Options,
    ) RequestError!Reply {
        const gpa = cl.allocator();
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const seq = cl.sock.nextSeq();
        const h = try cl.begin(&msg, seq, cmd, false);
        try cl.appendHeaderNest(&msg, hdr_attr, opts);
        codec.finishHeader(&msg, h);
        try cl.send(msg.items);
        return (try cl.collect(seq)) orelse error.MalformedReply;
    }

    /// Read to the end of a request's replies, keeping the first family
    /// message. A SET that was answered with a bare ACK yields null.
    fn collect(cl: *Ethtool, seq: u32) RequestError!?Reply {
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

    fn send(cl: *Ethtool, msg: []const u8) RequestError!void {
        cl.sock.send(msg) catch |e| return switch (e) {
            error.AccessDenied => error.AccessDenied,
            error.SystemResources => error.SystemResources,
            error.SendFailed => error.SendFailed,
        };
    }

    /// Keep the kernel's own sentence out of an `NLMSG_ERROR`, in the shared
    /// transport's buffer. Mirrors `netlink.Socket.captureExtAck`, which is not
    /// reachable through the `genetlink` facade.
    fn noteErrorMessage(cl: *Ethtool, m: codec.Message) void {
        cl.sock.ext_ack_len = 0;
        const maybe = m.errorMessage() catch return;
        const s = maybe orelse return;
        const n = @min(s.len, cl.sock.ext_ack_buf.len);
        @memcpy(cl.sock.ext_ack_buf[0..n], s[0..n]);
        cl.sock.ext_ack_len = n;
    }
};

fn recvErr(e: genl.RecvError) RequestError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MalformedReply => error.MalformedReply,
        error.SystemResources => error.SystemResources,
        error.RecvFailed => error.RecvFailed,
    };
}

fn mapParse(e: anyerror) RequestError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidRequest => error.InvalidRequest,
        else => error.MalformedReply,
    };
}

fn mapHeader(e: header.Error) RequestError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidRequest => error.InvalidRequest,
    };
}

/// One family reply message. `attrs` borrows the socket's receive buffer and is
/// valid only until the next `Walk.next` call.
const WalkMessage = struct {
    cmd: u8,
    attrs: []const u8,
};

/// Walks a request's replies, hiding datagram boundaries. Terminates on the
/// ACK (the normal case) or on `NLMSG_DONE` (a dump).
const Walk = struct {
    cl: *Ethtool,
    seq: u32,
    it: codec.MessageIterator = .{ .buf = &.{} },
    finished: bool = false,

    fn next(w: *Walk) RequestError!?WalkMessage {
        while (true) {
            if (w.finished) return null;
            const maybe = w.it.next() catch return error.MalformedReply;
            const m = maybe orelse {
                const dgram = w.cl.sock.recvDatagram() catch |e| return recvErr(e);
                w.it = .{ .buf = dgram };
                continue;
            };
            if (m.pid != w.cl.sock.portid or m.seq != w.seq) continue;
            switch (m.type) {
                codec.NLMSG_DONE => {
                    w.finished = true;
                    return null;
                },
                codec.NLMSG_ERROR => {
                    const code = m.errorCode() catch return error.MalformedReply;
                    if (code != 0) {
                        // Keep the kernel's own sentence before mapping the
                        // errno — "EOPNOTSUPP" alone loses the interesting half.
                        w.cl.noteErrorMessage(m);
                        return errnoToError(code);
                    }
                    w.finished = true;
                    return null;
                },
                codec.NLMSG_NOOP => continue,
                codec.NLMSG_OVERRUN => return error.SystemResources,
                else => {
                    if (m.type != w.cl.family_id) continue;
                    const p = genl.splitPayload(m.payload) catch return error.MalformedReply;
                    return .{ .cmd = p.cmd, .attrs = p.attrs };
                },
            }
        }
    }
};

// ── the event socket ───────────────────────────────────────────────────────

/// One decoded `*_NTF` message off the `monitor` group. `attrs` is an owned
/// copy, so a notification outlives the datagram it came from — hand it to the
/// matching typed parser (`link.parseLinkModes`, `params.parseRings`, …) to
/// read the payload.
pub const Notification = struct {
    /// The `ETHTOOL_MSG_*_NTF` value (`uapi.REPLY`).
    cmd: u8,
    /// The device the notification is about, when the message carried a
    /// recognisable header nest.
    device: ?header.Device = null,
    attrs: []u8,

    pub fn deinit(n: *Notification, gpa: std.mem.Allocator) void {
        gpa.free(n.attrs);
        n.* = .{ .cmd = 0, .attrs = &.{} };
    }

    /// Is this actually one of the family's notifications, rather than a stray
    /// reply that happened to land on this socket?
    pub fn isNotification(n: Notification) bool {
        return uapi.isNotification(n.cmd);
    }
};

/// A `NETLINK_GENERIC` socket subscribed to the ethtool `monitor` group.
///
/// **One blocking call: `waitForNotification`.** See the file header for why
/// the threading policy is the caller's.
///
/// The group is emitted to whenever a device's link settings, features, ring or
/// coalesce parameters change — including changes made by *other* processes,
/// which is the point: it is how a fleet agent learns that someone ran
/// `ethtool -K` behind its back.
pub const EventSocket = struct {
    sock: genl.Socket,
    family_id: u16,
    /// Unconsumed bytes of the datagram most recently received. Points into
    /// `sock.buf`, which is only reallocated by `recvDatagram` — and that is
    /// called only when this is empty.
    it: codec.MessageIterator = .{ .buf = &.{} },

    /// Open an event socket and subscribe to `groups` (normally just
    /// `uapi.mcast_group.monitor`). Resolving and joining are unprivileged.
    ///
    /// This opens a throwaway command socket to resolve the ids; a caller that
    /// already has an `Ethtool` should use `openWith`.
    pub fn open(
        gpa: std.mem.Allocator,
        groups: []const []const u8,
    ) (OpenError || SubscribeError)!EventSocket {
        var cmd = try Ethtool.open(gpa);
        defer cmd.close();
        return openWith(&cmd, groups);
    }

    /// Open an event socket, resolving the group ids over an existing command
    /// socket.
    pub fn openWith(
        cmd: *Ethtool,
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

    /// **The one blocking call.** Returns the next ethtool notification,
    /// performing a single `recvmsg` only when the previously received datagram
    /// has been drained. Messages that are not ethtool-family messages are
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
    const device = try header.parseLeading(attr_bytes);
    const copy = try gpa.dupe(u8, attr_bytes);
    return .{ .cmd = cmd, .device = device, .attrs = copy };
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "errnoToError maps the errnos ethtool actually returns" {
    try testing.expectEqual(error.AccessDenied, errnoToError(-@as(i32, @intFromEnum(linux.E.PERM))));
    try testing.expectEqual(error.NoSuchDevice, errnoToError(-@as(i32, @intFromEnum(linux.E.NODEV))));
    try testing.expectEqual(error.NoSuchDevice, errnoToError(-@as(i32, @intFromEnum(linux.E.NOENT))));
    // The single most common ethtool outcome: a valid request the driver has
    // no implementation for.
    try testing.expectEqual(error.NotSupported, errnoToError(-@as(i32, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expectEqual(error.InvalidRequest, errnoToError(-@as(i32, @intFromEnum(linux.E.INVAL))));
    try testing.expectEqual(error.Busy, errnoToError(-@as(i32, @intFromEnum(linux.E.BUSY))));
    try testing.expectEqual(error.SystemResources, errnoToError(-@as(i32, @intFromEnum(linux.E.NOMEM))));
    try testing.expectEqual(error.Unexpected, errnoToError(0));
    try testing.expectEqual(error.Unexpected, errnoToError(7));
    try testing.expectEqual(error.Unexpected, errnoToError(std.math.minInt(i32)));
}

test "findMcastGroupId on a hand-built nlctrl reply" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    const groups = try codec.nestBegin(gpa, &attrs, CTRL_ATTR_MCAST_GROUPS);
    const one = try codec.nestBegin(gpa, &attrs, 1);
    try codec.appendAttrU32(gpa, &attrs, CTRL_ATTR_MCAST_GRP_ID, 8);
    try codec.appendAttrString(gpa, &attrs, CTRL_ATTR_MCAST_GRP_NAME, uapi.mcast_group.monitor);
    codec.nestEnd(&attrs, one);
    codec.nestEnd(&attrs, groups);

    try testing.expectEqual(@as(?u32, 8), try findMcastGroupId(attrs.items, "monitor"));
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(attrs.items, "nope"));
    try testing.expectEqual(@as(?u32, null), try findMcastGroupId(&.{}, "monitor"));
    try testing.expectError(error.Truncated, findMcastGroupId(&.{ 0x40, 0x00, 0x07, 0x00, 1 }, "monitor"));
}

test "findMcastGroupId: a named group with no id is a bad reply" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    const groups = try codec.nestBegin(gpa, &attrs, CTRL_ATTR_MCAST_GROUPS);
    const one = try codec.nestBegin(gpa, &attrs, 1);
    try codec.appendAttrString(gpa, &attrs, CTRL_ATTR_MCAST_GRP_NAME, "monitor");
    codec.nestEnd(&attrs, one);
    codec.nestEnd(&attrs, groups);
    try testing.expectError(error.BadLength, findMcastGroupId(attrs.items, "monitor"));
}

test "parseNotification recovers the command and the device" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try header.append(gpa, &attrs, uapi.RINGS.HEADER, .{ .target = .byIndex(2) });
    try codec.appendAttrU32(gpa, &attrs, uapi.RINGS.RX, 512);

    var n = try parseNotification(gpa, uapi.REPLY.RINGS_NTF, attrs.items);
    defer n.deinit(gpa);
    try testing.expect(n.isNotification());
    try testing.expectEqual(@as(?u32, 2), n.device.?.index);
    // The payload is decodable with the ordinary typed parser.
    const r = try params.parseRings(n.attrs);
    try testing.expectEqual(@as(?u32, 512), r.rx);
}

test "parseNotification on a message with no header nest reports no device" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try codec.appendAttrU32(gpa, &attrs, 99, 1);
    var n = try parseNotification(gpa, uapi.REPLY.LINKSTATE_GET, attrs.items);
    defer n.deinit(gpa);
    try testing.expect(!n.isNotification()); // a GET reply, not an NTF
    try testing.expect(n.device == null);
}

test "parseNotification: malformed attributes are typed errors" {
    const gpa = testing.allocator;
    try testing.expectError(error.Truncated, parseNotification(gpa, 1, &.{ 0x40, 0x00 }));
}

test "BitsetForm maps onto the header flag" {
    try testing.expect(BitsetForm.compact.compactFlag());
    try testing.expect(!BitsetForm.verbose.compactFlag());
}

test "fuzz: notification parsing never crashes" {
    try testing.fuzz({}, fuzzNotification, .{});
}

fn fuzzNotification(_: void, smith: *std.testing.Smith) !void {
    var raw_buf: [256]u8 = undefined;
    smith.bytes(&raw_buf);
    const len = smith.valueRangeAtMost(u16, 0, raw_buf.len);
    const cmd = smith.valueRangeAtMost(u8, 0, 255);
    if (parseNotification(testing.allocator, cmd, raw_buf[0..len])) |n| {
        var v = n;
        v.deinit(testing.allocator);
    } else |_| {}
    if (findMcastGroupId(raw_buf[0..len], "monitor")) |g| std.mem.doNotOptimizeAway(&g) else |_| {}
}

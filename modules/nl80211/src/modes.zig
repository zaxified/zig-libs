// SPDX-License-Identifier: MIT
//! Ad-hoc (IBSS) and mesh (802.11s) networks — `iw dev <dev> ibss join|leave`
//! and `iw dev <dev> mesh join|leave`.
//!
//! Every request builder is pinned byte-for-byte against `iw` 6.17 in
//! `goldens.zig` (captured inside `unshare -rn` against `lo`, which the kernel
//! refuses, so nothing on the host changes). The interface must already be of
//! type `adhoc` (IBSS) or `mesh_point` (mesh): change it with
//! `config.buildSetInterfaceType` first, as `iw` requires too.
//!
//! Not modelled: IBSS/mesh security (SAE, `ie` blobs for mesh vendor
//! extensions, `NL80211_ATTR_MESH_CONFIG` parameters). Both are reachable
//! through `Nl80211.raw`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");
const config = @import("config.zig");

pub const BuildError = config.BuildError;

/// Parameters of `IBSS join`.
pub const IbssOptions = struct {
    ifindex: u32,
    /// The network name, 0 to 32 bytes (raw, not NUL-terminated).
    ssid: []const u8,
    channel: config.Channel,
    /// Stay on `channel` instead of following the cell (`fixed-freq`).
    freq_fixed: bool = false,
    /// Join this specific cell (`NL80211_ATTR_MAC`).
    bssid: ?uapi.Mac = null,
    /// Beacon interval in time units (1024 us). Null = kernel default (100).
    beacon_interval_tu: ?u32 = null,
};

/// Build `NL80211_CMD_JOIN_IBSS`. Attribute order is `iw`'s.
pub fn buildJoinIbss(gpa: std.mem.Allocator, family_id: u16, seq: u32, opts: IbssOptions) BuildError![]u8 {
    if (opts.ssid.len > uapi.max_ssid_len) return error.InvalidRequest;
    if (opts.beacon_interval_tu) |b| if (b == 0) return error.InvalidRequest;
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, uapi.CMD.JOIN_IBSS);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, opts.ifindex);
    codec.appendAttr(gpa, &list, uapi.ATTR.SSID, opts.ssid) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.AttrTooLong => error.InvalidRequest,
    };
    try config.appendChandef(gpa, &list, opts.channel);
    if (opts.freq_fixed) try config.appendBytes(gpa, &list, uapi.ATTR.FREQ_FIXED, &.{});
    if (opts.bssid) |m| try config.appendBytes(gpa, &list, uapi.ATTR.MAC, &m);
    if (opts.beacon_interval_tu) |b| try codec.appendAttrU32(gpa, &list, uapi.ATTR.BEACON_INTERVAL, b);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build `NL80211_CMD_LEAVE_IBSS` (`iw dev <dev> ibss leave`).
pub fn buildLeaveIbss(gpa: std.mem.Allocator, family_id: u16, seq: u32, ifindex: u32) BuildError![]u8 {
    return ifindexOnly(gpa, family_id, seq, uapi.CMD.LEAVE_IBSS, ifindex);
}

/// Parameters of `MESH join`.
pub const MeshOptions = struct {
    ifindex: u32,
    /// The mesh id, 0 to 32 bytes (raw, not NUL-terminated).
    mesh_id: []const u8,
    channel: config.Channel,
};

/// Build `NL80211_CMD_JOIN_MESH` (`iw dev <dev> mesh join <id> freq <mhz> …`).
pub fn buildJoinMesh(gpa: std.mem.Allocator, family_id: u16, seq: u32, opts: MeshOptions) BuildError![]u8 {
    if (opts.mesh_id.len > uapi.max_ssid_len) return error.InvalidRequest;
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, uapi.CMD.JOIN_MESH);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, opts.ifindex);
    codec.appendAttr(gpa, &list, uapi.ATTR.MESH_ID, opts.mesh_id) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.AttrTooLong => error.InvalidRequest,
    };
    try config.appendChandef(gpa, &list, opts.channel);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build `NL80211_CMD_LEAVE_MESH` (`iw dev <dev> mesh leave`).
pub fn buildLeaveMesh(gpa: std.mem.Allocator, family_id: u16, seq: u32, ifindex: u32) BuildError![]u8 {
    return ifindexOnly(gpa, family_id, seq, uapi.CMD.LEAVE_MESH, ifindex);
}

fn begin(gpa: std.mem.Allocator, list: *std.ArrayList(u8), family_id: u16, seq: u32, cmd: u8) !usize {
    const hdr = try codec.appendHeader(gpa, list, family_id, codec.NLM_F_REQUEST | codec.NLM_F_ACK, seq, 0);
    try genl.appendHeader(gpa, list, cmd, uapi.family_version);
    return hdr;
}

fn ifindexOnly(gpa: std.mem.Allocator, family_id: u16, seq: u32, cmd: u8, ifindex: u32) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, cmd);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, ifindex);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

const testing = std.testing;

test "IBSS and MESH builders refuse over-long names and a zero beacon interval" {
    const long: [33]u8 = @splat('a');
    const ch = config.Channel.legacy(2412);
    try testing.expectError(error.InvalidRequest, buildJoinIbss(testing.allocator, 41, 1, .{ .ifindex = 1, .ssid = &long, .channel = ch }));
    try testing.expectError(error.InvalidRequest, buildJoinIbss(testing.allocator, 41, 1, .{ .ifindex = 1, .ssid = "x", .channel = ch, .beacon_interval_tu = 0 }));
    try testing.expectError(error.InvalidRequest, buildJoinMesh(testing.allocator, 41, 1, .{ .ifindex = 1, .mesh_id = &long, .channel = ch }));
    try testing.expectError(error.InvalidRequest, buildJoinMesh(testing.allocator, 41, 1, .{ .ifindex = 1, .mesh_id = "m", .channel = .{ .freq_mhz = 2437, .width = .@"40" } }));
}

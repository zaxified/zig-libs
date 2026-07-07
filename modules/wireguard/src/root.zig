// SPDX-License-Identifier: MIT
//! wireguard — native WireGuard device configuration over the kernel's
//! generic-netlink API. Get/set devices, peers and allowed-ips without
//! shelling out to the `wg` tool.
//!
//! ```zig
//! var wg = try wireguard.Wireguard.open(gpa);
//! defer wg.close();
//!
//! var dev = try wg.getDevice("wg0"); // typed Device, owned
//! defer dev.deinit(gpa);
//!
//! try wg.setDevice(.{
//!     .ifname = "wg0",
//!     .private_key = try wireguard.keyFromBase64(priv_b64),
//!     .listen_port = 51820,
//!     .replace_peers = true,
//!     .peers = &.{.{
//!         .public_key = try wireguard.keyFromBase64(peer_b64),
//!         .endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 5 }, .port = 51820 } },
//!         .replace_allowed_ips = true,
//!         .allowed_ips = &.{wireguard.AllowedIp.v4(.{ 10, 0, 0, 0 }, 24)},
//!     }},
//! });
//! ```
//!
//! The wire work splits cleanly: `genl.zig` is the generic-netlink plumbing
//! (genlmsghdr + nlctrl family resolve + a NETLINK_GENERIC socket), while
//! this file speaks the WireGuard family — WG_CMD_GET_DEVICE dump parsing
//! (incl. peers continued across multipart messages) and WG_CMD_SET_DEVICE
//! request building (incl. splitting a large config across messages, the way
//! the `wg` tool does). Both directions are pure functions over byte slices,
//! so they are golden-byte-tested offline; the socket only ferries buffers.
//!
//! Privileges: both WG_CMD_GET_DEVICE and WG_CMD_SET_DEVICE require
//! CAP_NET_ADMIN (the family registers with GENL_UNS_ADMIN_PERM).
//!
//! Provenance: clean-room from the documented WireGuard netlink UAPI
//! (`uapi/wireguard.h`, GPL-2.0 WITH Linux-syscall-note — the command,
//! attribute and flag constants and their layouts are the kernel's OS ABI,
//! not copyrightable interface code) and the genetlink UAPI
//! (`linux/genetlink.h`). Behavior modeled after wgctrl-go
//! (golang.zx2c4.com/wireguard/wgctrl, MIT) and the `wg` tool's protocol
//! usage — behavior/attribute-shape reference only, no source consulted or
//! copied.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const netlink = @import("netlink");
const codec = netlink.codec;
const native_endian = builtin.cpu.arch.endian();

pub const genl = @import("genl.zig");

pub const meta = .{
    .status = .gap, // no maintained pure-Zig WireGuard-netlink client exists
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .reentrant, // no globals; one Wireguard per thread/loop
    .model_after = "WireGuard genetlink UAPI / wgctrl-go",
    .deps = .{"netlink"}, // wire codec (nlmsghdr + nlattr TLV) is reused
};

// ── kernel UAPI constants (uapi/wireguard.h) ────────────────────────────────

/// The genetlink family name resolved via nlctrl.
pub const WG_GENL_NAME = "wireguard";
pub const WG_GENL_VERSION: u8 = 1;

/// Raw key length — private, public and preshared keys alike.
pub const key_len = 32;
pub const Key = [key_len]u8;

/// WireGuard genetlink commands (enum wg_cmd).
pub const WG_CMD = struct {
    pub const GET_DEVICE: u8 = 0;
    pub const SET_DEVICE: u8 = 1;
};

/// Device flags (enum wgdevice_flag) for WGDEVICE_A_FLAGS.
pub const WGDEVICE_F = struct {
    pub const REPLACE_PEERS: u32 = 1 << 0;
};

/// Device attributes (enum wgdevice_attribute).
pub const WGDEVICE_A = struct {
    pub const UNSPEC: u16 = 0;
    pub const IFINDEX: u16 = 1;
    pub const IFNAME: u16 = 2;
    pub const PRIVATE_KEY: u16 = 3;
    pub const PUBLIC_KEY: u16 = 4;
    pub const FLAGS: u16 = 5;
    pub const LISTEN_PORT: u16 = 6;
    pub const FWMARK: u16 = 7;
    pub const PEERS: u16 = 8;
};

/// Peer flags (enum wgpeer_flag) for WGPEER_A_FLAGS.
pub const WGPEER_F = struct {
    pub const REMOVE_ME: u32 = 1 << 0;
    pub const REPLACE_ALLOWEDIPS: u32 = 1 << 1;
    pub const UPDATE_ONLY: u32 = 1 << 2;
};

/// Peer attributes (enum wgpeer_attribute).
pub const WGPEER_A = struct {
    pub const UNSPEC: u16 = 0;
    pub const PUBLIC_KEY: u16 = 1;
    pub const PRESHARED_KEY: u16 = 2;
    pub const FLAGS: u16 = 3;
    pub const ENDPOINT: u16 = 4;
    pub const PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
    pub const LAST_HANDSHAKE_TIME: u16 = 6;
    pub const RX_BYTES: u16 = 7;
    pub const TX_BYTES: u16 = 8;
    pub const ALLOWEDIPS: u16 = 9;
    pub const PROTOCOL_VERSION: u16 = 10;
};

/// Allowed-ip attributes (enum wgallowedip_attribute).
pub const WGALLOWEDIP_A = struct {
    pub const UNSPEC: u16 = 0;
    pub const FAMILY: u16 = 1;
    pub const IPADDR: u16 = 2;
    pub const CIDR_MASK: u16 = 3;
};

/// Address families as they appear on the wire (sa_family_t / nla u16).
pub const AF = struct {
    pub const INET: u16 = 2;
    pub const INET6: u16 = 10;
};

/// IFNAMSIZ (linux/if.h) — interface names incl. NUL.
pub const ifnamsiz = 16;

// ── key text format (the `wg` tool's base64) ────────────────────────────────

/// Length of a key in the wg base64 text format (44 chars incl. one '=').
pub const key_b64_len = 44;

/// Format a raw 32-byte key as the wg base64 text form.
pub fn keyToBase64(key: Key) [key_b64_len]u8 {
    var out: [key_b64_len]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &key);
    return out;
}

pub const KeyParseError = error{InvalidKey};

/// Parse a wg base64 key string into raw bytes. Strict: exactly 44 chars
/// and canonical encoding (re-encodes to the same string), like `wg` itself.
pub fn keyFromBase64(s: []const u8) KeyParseError!Key {
    if (s.len != key_b64_len) return error.InvalidKey;
    var key: Key = undefined;
    std.base64.standard.Decoder.decode(&key, s) catch return error.InvalidKey;
    // Reject non-canonical trailing bits (e.g. "…B=" where "…A=" is meant).
    const back = keyToBase64(key);
    if (!std.mem.eql(u8, &back, s)) return error.InvalidKey;
    return key;
}

// ── typed model ─────────────────────────────────────────────────────────────

/// A peer/listen endpoint — struct sockaddr_in / sockaddr_in6 on the wire.
pub const Endpoint = union(enum) {
    v4: V4,
    v6: V6,

    pub const V4 = struct { addr: [4]u8, port: u16 };
    pub const V6 = struct {
        addr: [16]u8,
        port: u16,
        flowinfo: u32 = 0,
        scope_id: u32 = 0,
    };

    pub fn port(e: Endpoint) u16 {
        return switch (e) {
            .v4 => |v| v.port,
            .v6 => |v| v.port,
        };
    }
};

/// One allowed-ip entry: an address prefix routed to (and accepted from) a
/// peer.
pub const AllowedIp = struct {
    /// AF.INET or AF.INET6.
    family: u16,
    addr: [16]u8 = @splat(0),
    /// Valid bytes in `addr`: 4 (IPv4) or 16 (IPv6).
    addr_len: u8 = 0,
    /// Prefix length (≤ 32 for IPv4, ≤ 128 for IPv6).
    cidr: u8 = 0,

    pub fn v4(addr: [4]u8, cidr: u8) AllowedIp {
        var ip: AllowedIp = .{ .family = AF.INET, .addr_len = 4, .cidr = cidr };
        ip.addr[0..4].* = addr;
        return ip;
    }

    pub fn v6(addr: [16]u8, cidr: u8) AllowedIp {
        return .{ .family = AF.INET6, .addr = addr, .addr_len = 16, .cidr = cidr };
    }

    /// The address bytes (4 or 16).
    pub fn bytes(ip: *const AllowedIp) []const u8 {
        return ip.addr[0..ip.addr_len];
    }

    fn valid(ip: AllowedIp) bool {
        return switch (ip.family) {
            AF.INET => ip.addr_len == 4 and ip.cidr <= 32,
            AF.INET6 => ip.addr_len == 16 and ip.cidr <= 128,
            else => false,
        };
    }
};

/// struct __kernel_timespec — WGPEER_A_LAST_HANDSHAKE_TIME. Zero = never.
pub const Timespec = struct { sec: i64 = 0, nsec: i64 = 0 };

/// One peer as reported by WG_CMD_GET_DEVICE.
pub const Peer = struct {
    public_key: Key = @splat(0),
    /// Null when unset (the kernel reports an all-zero PSK as "none").
    preshared_key: ?Key = null,
    endpoint: ?Endpoint = null,
    /// Seconds; 0 = keepalive disabled.
    persistent_keepalive_interval: u16 = 0,
    last_handshake_time: Timespec = .{},
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    protocol_version: u32 = 0,
    /// Owned by the enclosing Device.
    allowed_ips: []AllowedIp = &.{},
};

/// One device as reported by WG_CMD_GET_DEVICE. Free with `deinit`.
pub const Device = struct {
    ifindex: u32 = 0,
    name_buf: [ifnamsiz]u8 = @splat(0),
    name_len: u8 = 0,
    /// Null when the device has no identity yet (or the kernel withheld it).
    private_key: ?Key = null,
    public_key: ?Key = null,
    listen_port: u16 = 0,
    fwmark: u32 = 0,
    peers: []Peer = &.{},

    pub fn ifname(d: *const Device) []const u8 {
        return d.name_buf[0..d.name_len];
    }

    pub fn deinit(d: *Device, gpa: std.mem.Allocator) void {
        for (d.peers) |p| gpa.free(p.allowed_ips);
        gpa.free(d.peers);
        d.* = undefined;
    }
};

// ── WG_CMD_GET_DEVICE response parsing (pure, offline-testable) ─────────────

pub const ParseError = codec.Error || error{OutOfMemory};

/// Accumulates a Device across the multipart messages of one
/// WG_CMD_GET_DEVICE dump. A device with many peers/allowed-ips is split
/// across messages; when a peer's allowed-ips overflow a message, the next
/// message repeats that peer carrying only its public key plus the remaining
/// allowed-ips — `feed` detects this (first peer of a message, same public
/// key as the previously accumulated peer) and merges.
pub const DeviceParser = struct {
    gpa: std.mem.Allocator,
    dev: Device = .{},
    peers: std.ArrayList(Peer) = .empty,

    pub fn init(gpa: std.mem.Allocator) DeviceParser {
        return .{ .gpa = gpa };
    }

    pub fn deinit(p: *DeviceParser) void {
        for (p.peers.items) |peer| p.gpa.free(peer.allowed_ips);
        p.peers.deinit(p.gpa);
        p.* = undefined;
    }

    /// Feed one genetlink message payload (genlmsghdr + WGDEVICE_A_*
    /// attributes). Malformed bytes yield a typed error — never a panic.
    pub fn feed(p: *DeviceParser, payload: []const u8) ParseError!void {
        const g = try genl.splitPayload(payload);
        var it: codec.AttrIterator = .{ .buf = g.attrs };
        var first_peer_in_msg = true;
        while (try it.next()) |a| switch (a.type) {
            WGDEVICE_A.IFINDEX => p.dev.ifindex = try a.asU32(),
            WGDEVICE_A.IFNAME => {
                const s = a.asString();
                if (s.len >= ifnamsiz) return error.BadLength;
                @memcpy(p.dev.name_buf[0..s.len], s);
                p.dev.name_len = @intCast(s.len);
            },
            WGDEVICE_A.PRIVATE_KEY => p.dev.private_key = try optionalKeyAttr(a),
            WGDEVICE_A.PUBLIC_KEY => p.dev.public_key = try optionalKeyAttr(a),
            WGDEVICE_A.LISTEN_PORT => p.dev.listen_port = try a.asU16(),
            WGDEVICE_A.FWMARK => p.dev.fwmark = try a.asU32(),
            WGDEVICE_A.PEERS => {
                var pit = a.nested();
                while (try pit.next()) |entry| {
                    try p.feedPeer(entry, first_peer_in_msg);
                    first_peer_in_msg = false;
                }
            },
            else => {}, // unknown attributes: forward-compatible skip
        };
    }

    /// Hand over the accumulated Device. The parser is left empty (finish
    /// then deinit is safe); the caller frees the Device with `deinit`.
    pub fn finish(p: *DeviceParser) error{OutOfMemory}!Device {
        p.dev.peers = try p.peers.toOwnedSlice(p.gpa);
        const dev = p.dev;
        p.dev = .{};
        return dev;
    }

    fn feedPeer(p: *DeviceParser, entry: codec.Attr, first_in_msg: bool) ParseError!void {
        var peer: Peer = .{};
        var ips: std.ArrayList(AllowedIp) = .empty;
        defer ips.deinit(p.gpa);
        var has_public_key = false;

        var it = entry.nested();
        while (try it.next()) |a| switch (a.type) {
            WGPEER_A.PUBLIC_KEY => {
                peer.public_key = try keyAttr(a);
                has_public_key = true;
            },
            WGPEER_A.PRESHARED_KEY => peer.preshared_key = try optionalKeyAttr(a),
            WGPEER_A.ENDPOINT => peer.endpoint = try parseEndpoint(a.data),
            WGPEER_A.PERSISTENT_KEEPALIVE_INTERVAL => peer.persistent_keepalive_interval = try a.asU16(),
            WGPEER_A.LAST_HANDSHAKE_TIME => {
                // struct __kernel_timespec: i64 sec, i64 nsec.
                if (a.data.len < 16) return error.BadLength;
                peer.last_handshake_time = .{
                    .sec = std.mem.readInt(i64, a.data[0..8], native_endian),
                    .nsec = std.mem.readInt(i64, a.data[8..16], native_endian),
                };
            },
            WGPEER_A.RX_BYTES => peer.rx_bytes = try u64Attr(a),
            WGPEER_A.TX_BYTES => peer.tx_bytes = try u64Attr(a),
            WGPEER_A.PROTOCOL_VERSION => peer.protocol_version = try a.asU32(),
            WGPEER_A.ALLOWEDIPS => {
                var ait = a.nested();
                while (try ait.next()) |ip_entry|
                    try ips.append(p.gpa, try parseAllowedIp(ip_entry));
            },
            else => {},
        };
        if (!has_public_key) return error.BadLength;

        // Multipart continuation: the first peer of a follow-up message with
        // the same public key as the last accumulated peer carries only the
        // allowed-ips that did not fit — append them.
        if (first_in_msg and p.peers.items.len > 0) {
            const last = &p.peers.items[p.peers.items.len - 1];
            if (std.mem.eql(u8, &last.public_key, &peer.public_key)) {
                const merged = try p.gpa.alloc(AllowedIp, last.allowed_ips.len + ips.items.len);
                @memcpy(merged[0..last.allowed_ips.len], last.allowed_ips);
                @memcpy(merged[last.allowed_ips.len..], ips.items);
                p.gpa.free(last.allowed_ips);
                last.allowed_ips = merged;
                return;
            }
        }
        peer.allowed_ips = try p.gpa.dupe(AllowedIp, ips.items);
        errdefer p.gpa.free(peer.allowed_ips);
        try p.peers.append(p.gpa, peer);
    }
};

/// A key attribute that must be exactly 32 bytes.
fn keyAttr(a: codec.Attr) codec.Error!Key {
    if (a.data.len != key_len) return error.BadLength;
    return a.data[0..key_len].*;
}

/// Like `keyAttr`, but an all-zero key means "unset" → null.
fn optionalKeyAttr(a: codec.Attr) codec.Error!?Key {
    const key = try keyAttr(a);
    return if (std.mem.allEqual(u8, &key, 0)) null else key;
}

fn u64Attr(a: codec.Attr) codec.Error!u64 {
    if (a.data.len != 8) return error.BadLength;
    return std.mem.readInt(u64, a.data[0..8], native_endian);
}

/// Decode WGPEER_A_ENDPOINT: struct sockaddr_in (16 bytes) or sockaddr_in6
/// (28 bytes). Ports (and sin6_flowinfo) are big-endian per sockaddr.
fn parseEndpoint(data: []const u8) codec.Error!Endpoint {
    if (data.len == 16 and std.mem.readInt(u16, data[0..2], native_endian) == AF.INET) {
        return .{ .v4 = .{
            .addr = data[4..8].*,
            .port = std.mem.readInt(u16, data[2..4], .big),
        } };
    }
    if (data.len == 28 and std.mem.readInt(u16, data[0..2], native_endian) == AF.INET6) {
        return .{ .v6 = .{
            .addr = data[8..24].*,
            .port = std.mem.readInt(u16, data[2..4], .big),
            .flowinfo = std.mem.readInt(u32, data[4..8], .big),
            .scope_id = std.mem.readInt(u32, data[24..28], native_endian),
        } };
    }
    return error.BadLength;
}

/// Decode one nested WGALLOWEDIP_A_* entry. All three attributes are
/// required; family/length/cidr must be consistent.
fn parseAllowedIp(entry: codec.Attr) codec.Error!AllowedIp {
    var family: ?u16 = null;
    var addr: ?[]const u8 = null;
    var cidr: ?u8 = null;
    var it = entry.nested();
    while (try it.next()) |a| switch (a.type) {
        WGALLOWEDIP_A.FAMILY => family = try a.asU16(),
        WGALLOWEDIP_A.IPADDR => addr = a.data,
        WGALLOWEDIP_A.CIDR_MASK => cidr = try a.asU8(),
        else => {},
    };
    const fam = family orelse return error.BadLength;
    const ab = addr orelse return error.BadLength;
    var ip: AllowedIp = .{
        .family = fam,
        .addr_len = if (ab.len == 4 or ab.len == 16) @intCast(ab.len) else return error.BadLength,
        .cidr = cidr orelse return error.BadLength,
    };
    @memcpy(ip.addr[0..ab.len], ab);
    if (!ip.valid()) return error.BadLength;
    return ip;
}

// ── WG_CMD_SET_DEVICE request building (pure, offline-testable) ─────────────

/// Desired device configuration for `setDevice`. Null fields are left
/// untouched on the device; `listen_port = 0` / `fwmark = 0` clear them.
pub const Config = struct {
    /// Target device by name (preferred) — or by `ifindex` when empty.
    ifname: []const u8 = "",
    ifindex: u32 = 0,
    private_key: ?Key = null,
    listen_port: ?u16 = null,
    fwmark: ?u32 = null,
    /// Remove all peers not listed in `peers` (WGDEVICE_F_REPLACE_PEERS).
    replace_peers: bool = false,
    peers: []const PeerConfig = &.{},
};

/// One peer in a `Config`.
pub const PeerConfig = struct {
    public_key: Key,
    /// Remove this peer (WGPEER_F_REMOVE_ME); other fields are ignored.
    remove: bool = false,
    /// Only update an existing peer, never create (WGPEER_F_UPDATE_ONLY).
    update_only: bool = false,
    /// Replace the peer's allowed-ips instead of appending
    /// (WGPEER_F_REPLACE_ALLOWEDIPS).
    replace_allowed_ips: bool = false,
    /// Null = untouched; an all-zero key clears the PSK.
    preshared_key: ?Key = null,
    endpoint: ?Endpoint = null,
    /// Seconds; 0 disables. Null = untouched.
    persistent_keepalive_interval: ?u16 = null,
    allowed_ips: []const AllowedIp = &.{},

    fn wireFlags(p: PeerConfig) u32 {
        var flags: u32 = 0;
        if (p.remove) flags |= WGPEER_F.REMOVE_ME;
        if (p.update_only) flags |= WGPEER_F.UPDATE_ONLY;
        if (p.replace_allowed_ips) flags |= WGPEER_F.REPLACE_ALLOWEDIPS;
        return flags;
    }
};

pub const BuildError = error{ OutOfMemory, InvalidConfig };

/// Soft per-message ceiling used by `setDevice` — the same order of
/// magnitude as the `wg` tool's socket buffer.
pub const default_max_msg_len: usize = 8192;

/// One or more complete WG_CMD_SET_DEVICE netlink messages, back to back.
pub const SetRequests = struct {
    buf: []u8,
    msg_count: u32,

    pub fn deinit(r: *SetRequests, gpa: std.mem.Allocator) void {
        gpa.free(r.buf);
        r.* = undefined;
    }
};

/// Encode `cfg` as WG_CMD_SET_DEVICE message(s) with sequence numbers
/// `first_seq`, `first_seq+1`, …. A config too large for `max_msg_len` is
/// split the way the `wg` tool does: follow-up messages repeat only the
/// interface identity, and a peer whose allowed-ips overflow continues in
/// the next message carrying only its public key + the remaining
/// allowed-ips (never re-sending REPLACE_* flags, which would undo earlier
/// fragments). `max_msg_len` is a soft ceiling: a single indivisible
/// attribute group never splits, so one message may exceed it slightly.
pub fn buildSetRequests(
    gpa: std.mem.Allocator,
    family_id: u16,
    first_seq: u32,
    cfg: Config,
    max_msg_len: usize,
) BuildError!SetRequests {
    if (cfg.ifname.len == 0 and cfg.ifindex == 0) return error.InvalidConfig;
    if (cfg.ifname.len >= ifnamsiz) return error.InvalidConfig;
    for (cfg.peers) |p| for (p.allowed_ips) |ip| if (!ip.valid()) return error.InvalidConfig;

    var b: SetBuilder = .{
        .gpa = gpa,
        .family_id = family_id,
        .next_seq = first_seq,
        .max_msg_len = max_msg_len,
        .cfg = &cfg,
    };
    errdefer b.list.deinit(gpa);

    try b.beginMessage(true);
    for (cfg.peers) |p| {
        var need = peerBaseSpace(p, false);
        if (p.allowed_ips.len > 0)
            need += codec.attr_header_len + allowedIpSpace(p.allowed_ips[0]);
        if (b.wouldOverflow(need)) try b.startContinuation();

        const peer_nest = try b.beginPeer(p, false);
        if (p.allowed_ips.len > 0) {
            var ips_nest = try nestBegin(gpa, &b.list, WGPEER_A.ALLOWEDIPS);
            var cur_peer_nest = peer_nest;
            for (p.allowed_ips) |ip| {
                if (b.wouldOverflow(allowedIpSpace(ip))) {
                    nestEnd(&b.list, ips_nest);
                    nestEnd(&b.list, cur_peer_nest);
                    try b.startContinuation();
                    cur_peer_nest = try b.beginPeer(p, true);
                    ips_nest = try nestBegin(gpa, &b.list, WGPEER_A.ALLOWEDIPS);
                }
                try appendAllowedIp(gpa, &b.list, ip);
                b.units += 1;
            }
            nestEnd(&b.list, ips_nest);
            nestEnd(&b.list, cur_peer_nest);
        } else {
            nestEnd(&b.list, peer_nest);
        }
        b.units += 1;
    }
    b.endMessage();

    return .{ .buf = try b.list.toOwnedSlice(gpa), .msg_count = b.msg_count };
}

const SetBuilder = struct {
    gpa: std.mem.Allocator,
    list: std.ArrayList(u8) = .empty,
    family_id: u16,
    next_seq: u32,
    max_msg_len: usize,
    cfg: *const Config,
    msg_start: usize = 0,
    hdr_off: usize = 0,
    peers_nest: ?usize = null,
    /// Complete units (peer entries / allowed-ip entries) already emitted in
    /// the current message. Splitting only happens when > 0, so every
    /// message makes progress no matter how small `max_msg_len` is.
    units: usize = 0,
    msg_count: u32 = 0,

    fn beginMessage(b: *SetBuilder, first: bool) BuildError!void {
        const cfg = b.cfg;
        b.msg_start = b.list.items.len;
        b.hdr_off = try codec.appendHeader(
            b.gpa,
            &b.list,
            b.family_id,
            codec.NLM_F_REQUEST | codec.NLM_F_ACK,
            b.next_seq,
            0,
        );
        b.next_seq +%= 1;
        b.msg_count += 1;
        b.units = 0;
        try genl.appendHeader(b.gpa, &b.list, WG_CMD.SET_DEVICE, WG_GENL_VERSION);

        // Interface identity goes into every message fragment.
        if (cfg.ifname.len > 0) {
            codec.appendAttrString(b.gpa, &b.list, WGDEVICE_A.IFNAME, cfg.ifname) catch |err|
                switch (err) {
                    error.AttrTooLong => unreachable, // len < ifnamsiz, checked
                    error.OutOfMemory => return error.OutOfMemory,
                };
        } else {
            try codec.appendAttrU32(b.gpa, &b.list, WGDEVICE_A.IFINDEX, cfg.ifindex);
        }

        // Device-level settings only once, in the first message.
        if (first) {
            if (cfg.replace_peers)
                try codec.appendAttrU32(b.gpa, &b.list, WGDEVICE_A.FLAGS, WGDEVICE_F.REPLACE_PEERS);
            if (cfg.private_key) |key| try attrRaw(b.gpa, &b.list, WGDEVICE_A.PRIVATE_KEY, &key);
            if (cfg.listen_port) |p| try attrU16(b.gpa, &b.list, WGDEVICE_A.LISTEN_PORT, p);
            if (cfg.fwmark) |m| try codec.appendAttrU32(b.gpa, &b.list, WGDEVICE_A.FWMARK, m);
        }

        if (cfg.peers.len > 0)
            b.peers_nest = try nestBegin(b.gpa, &b.list, WGDEVICE_A.PEERS);
    }

    fn endMessage(b: *SetBuilder) void {
        if (b.peers_nest) |off| nestEnd(&b.list, off);
        b.peers_nest = null;
        codec.finishHeader(&b.list, b.hdr_off);
    }

    fn startContinuation(b: *SetBuilder) BuildError!void {
        b.endMessage();
        try b.beginMessage(false);
    }

    fn wouldOverflow(b: *const SetBuilder, extra: usize) bool {
        return b.units > 0 and (b.list.items.len - b.msg_start) + extra > b.max_msg_len;
    }

    /// Open a peer entry. A continuation fragment carries only the public
    /// key: flags/psk/endpoint/keepalive were already applied by the first
    /// fragment, and repeating REPLACE_ALLOWEDIPS would wipe the allowed-ips
    /// sent so far.
    fn beginPeer(b: *SetBuilder, p: PeerConfig, continuation: bool) BuildError!usize {
        const off = try nestBegin(b.gpa, &b.list, 0);
        try attrRaw(b.gpa, &b.list, WGPEER_A.PUBLIC_KEY, &p.public_key);
        if (!continuation) {
            const flags = p.wireFlags();
            if (flags != 0) try codec.appendAttrU32(b.gpa, &b.list, WGPEER_A.FLAGS, flags);
            if (p.preshared_key) |key| try attrRaw(b.gpa, &b.list, WGPEER_A.PRESHARED_KEY, &key);
            if (p.endpoint) |ep| try appendEndpoint(b.gpa, &b.list, ep);
            if (p.persistent_keepalive_interval) |ka|
                try attrU16(b.gpa, &b.list, WGPEER_A.PERSISTENT_KEEPALIVE_INTERVAL, ka);
        }
        return off;
    }
};

// Encoded space (attr header + payload, 4-aligned) helpers for splitting.

fn attrSpace(payload_len: usize) usize {
    return codec.alignUp(codec.attr_header_len + payload_len);
}

fn allowedIpSpace(ip: AllowedIp) usize {
    return codec.attr_header_len + attrSpace(2) + attrSpace(ip.addr_len) + attrSpace(1);
}

fn peerBaseSpace(p: PeerConfig, continuation: bool) usize {
    var n: usize = codec.attr_header_len + attrSpace(key_len);
    if (!continuation) {
        if (p.wireFlags() != 0) n += attrSpace(4);
        if (p.preshared_key != null) n += attrSpace(key_len);
        if (p.endpoint) |ep| n += switch (ep) {
            .v4 => attrSpace(16),
            .v6 => attrSpace(28),
        };
        if (p.persistent_keepalive_interval != null) n += attrSpace(2);
    }
    return n;
}

/// Open a nested attribute (NLA_F_NESTED set, length patched by `nestEnd`).
fn nestBegin(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
) error{OutOfMemory}!usize {
    const off = list.items.len;
    var hdr: [codec.attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], 0, native_endian); // patched by nestEnd
    std.mem.writeInt(u16, hdr[2..4], attr_type | codec.NLA_F_NESTED, native_endian);
    try list.appendSlice(gpa, &hdr);
    return off;
}

fn nestEnd(list: *std.ArrayList(u8), off: usize) void {
    // Inner attributes are self-aligned, so the total needs no padding.
    const total: u16 = @intCast(list.items.len - off);
    std.mem.writeInt(u16, list.items[off..][0..2], total, native_endian);
}

fn attrRaw(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) error{OutOfMemory}!void {
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // all our payloads are ≤ 36 bytes
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn attrU8(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u8,
) error{OutOfMemory}!void {
    try attrRaw(gpa, list, attr_type, &.{value});
}

fn attrU16(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u16,
) error{OutOfMemory}!void {
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, value, native_endian);
    try attrRaw(gpa, list, attr_type, &raw);
}

/// Encode WGPEER_A_ENDPOINT as struct sockaddr_in / sockaddr_in6.
fn appendEndpoint(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ep: Endpoint,
) error{OutOfMemory}!void {
    switch (ep) {
        .v4 => |v| {
            var raw: [16]u8 = @splat(0);
            std.mem.writeInt(u16, raw[0..2], AF.INET, native_endian);
            std.mem.writeInt(u16, raw[2..4], v.port, .big);
            raw[4..8].* = v.addr;
            try attrRaw(gpa, list, WGPEER_A.ENDPOINT, &raw);
        },
        .v6 => |v| {
            var raw: [28]u8 = @splat(0);
            std.mem.writeInt(u16, raw[0..2], AF.INET6, native_endian);
            std.mem.writeInt(u16, raw[2..4], v.port, .big);
            std.mem.writeInt(u32, raw[4..8], v.flowinfo, .big);
            raw[8..24].* = v.addr;
            std.mem.writeInt(u32, raw[24..28], v.scope_id, native_endian);
            try attrRaw(gpa, list, WGPEER_A.ENDPOINT, &raw);
        },
    }
}

/// Encode one nested allowed-ip entry (caller validated `ip`).
fn appendAllowedIp(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ip: AllowedIp,
) error{OutOfMemory}!void {
    const off = try nestBegin(gpa, list, 0);
    try attrU16(gpa, list, WGALLOWEDIP_A.FAMILY, ip.family);
    try attrRaw(gpa, list, WGALLOWEDIP_A.IPADDR, ip.bytes());
    try attrU8(gpa, list, WGALLOWEDIP_A.CIDR_MASK, ip.cidr);
    nestEnd(list, off);
}

// ── client ──────────────────────────────────────────────────────────────────

pub const RequestError = error{
    OutOfMemory,
    SendFailed,
    RecvFailed,
    /// A reply failed wire-format validation (bounds/length checks).
    MalformedReply,
    /// Missing CAP_NET_ADMIN — both WG commands are privileged.
    AccessDenied,
    InvalidRequest,
    /// No such interface, or it is not a WireGuard device.
    NoSuchDevice,
    NotSupported,
    SystemResources,
    Unexpected,
};

pub const GetError = RequestError;
pub const SetError = RequestError || BuildError;

/// Map the negative errno of an NLMSG_ERROR reply onto the request error set.
fn errnoToError(code: i32) RequestError {
    if (code >= 0 or code == std.math.minInt(i32)) return error.Unexpected;
    return switch (@as(u32, @intCast(-code))) {
        @intFromEnum(linux.E.PERM), @intFromEnum(linux.E.ACCES) => error.AccessDenied,
        @intFromEnum(linux.E.NODEV), @intFromEnum(linux.E.NOENT) => error.NoSuchDevice,
        @intFromEnum(linux.E.INVAL) => error.InvalidRequest,
        @intFromEnum(linux.E.OPNOTSUPP) => error.NotSupported,
        @intFromEnum(linux.E.NOBUFS), @intFromEnum(linux.E.NOMEM) => error.SystemResources,
        else => error.Unexpected,
    };
}

/// WireGuard control client: one NETLINK_GENERIC socket plus the resolved
/// "wireguard" family id. One instance per thread/loop; no shared state.
/// All Device allocations use the allocator passed to `open`.
pub const Wireguard = struct {
    sock: genl.Socket,
    family_id: u16,

    pub const OpenError = genl.OpenError || genl.ResolveError;

    /// Open a genetlink socket and resolve the "wireguard" family.
    /// `error.FamilyNotFound` means the wireguard kernel module is not
    /// loaded (creating a wg interface loads it).
    pub fn open(gpa: std.mem.Allocator) OpenError!Wireguard {
        var sock = try genl.Socket.open(gpa);
        errdefer sock.close();
        const family_id = try sock.resolveFamily(WG_GENL_NAME);
        return .{ .sock = sock, .family_id = family_id };
    }

    pub fn close(wg: *Wireguard) void {
        wg.sock.close();
        wg.* = undefined;
    }

    /// Fetch a device's full configuration + runtime state (peers with
    /// allowed-ips, handshake times, transfer counters). Needs
    /// CAP_NET_ADMIN. Free the result with `Device.deinit`.
    pub fn getDevice(wg: *Wireguard, ifname: []const u8) GetError!Device {
        if (ifname.len == 0 or ifname.len >= ifnamsiz) return error.InvalidRequest;
        const gpa = wg.sock.gpa;
        const seq = wg.sock.nextSeq();

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        const hdr = try codec.appendHeader(
            gpa,
            &req,
            wg.family_id,
            codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_DUMP,
            seq,
            0,
        );
        try genl.appendHeader(gpa, &req, WG_CMD.GET_DEVICE, WG_GENL_VERSION);
        codec.appendAttrString(gpa, &req, WGDEVICE_A.IFNAME, ifname) catch |err| switch (err) {
            error.AttrTooLong => unreachable, // len < ifnamsiz, checked
            error.OutOfMemory => return error.OutOfMemory,
        };
        codec.finishHeader(&req, hdr);
        try wg.sock.send(req.items);

        var parser: DeviceParser = .init(gpa);
        errdefer parser.deinit();
        while (true) {
            const dgram = try wg.sock.recvDatagram();
            var it: codec.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                if (m.pid != wg.sock.portid or m.seq != seq) continue;
                switch (m.type) {
                    codec.NLMSG_DONE => return parser.finish(),
                    codec.NLMSG_ERROR => {
                        const code = m.errorCode() catch return error.MalformedReply;
                        if (code == 0) continue; // stray ACK
                        return errnoToError(code);
                    },
                    codec.NLMSG_NOOP => {},
                    codec.NLMSG_OVERRUN => return error.SystemResources,
                    else => {
                        if (m.type != wg.family_id) continue;
                        parser.feed(m.payload) catch |err| switch (err) {
                            error.OutOfMemory => return error.OutOfMemory,
                            else => return error.MalformedReply,
                        };
                    },
                }
            }
        }
    }

    /// Apply a configuration (WG_CMD_SET_DEVICE). Needs CAP_NET_ADMIN.
    /// Large configs are split across messages; each message is ACKed by
    /// the kernel before the next is sent.
    pub fn setDevice(wg: *Wireguard, cfg: Config) SetError!void {
        const gpa = wg.sock.gpa;
        const first_seq = wg.sock.nextSeq();
        var reqs = try buildSetRequests(gpa, wg.family_id, first_seq, cfg, default_max_msg_len);
        defer reqs.deinit(gpa);
        wg.sock.seq = first_seq +% (reqs.msg_count - 1);

        var off: usize = 0;
        while (off < reqs.buf.len) {
            const mlen = std.mem.readInt(u32, reqs.buf[off..][0..4], native_endian);
            const seq = std.mem.readInt(u32, reqs.buf[off + 8 ..][0..4], native_endian);
            try wg.sock.send(reqs.buf[off..][0..mlen]);
            try wg.awaitAck(seq);
            off += codec.alignUp(mlen);
        }
    }

    fn awaitAck(wg: *Wireguard, seq: u32) RequestError!void {
        while (true) {
            const dgram = try wg.sock.recvDatagram();
            var it: codec.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                if (m.pid != wg.sock.portid or m.seq != seq) continue;
                if (m.type != codec.NLMSG_ERROR) continue;
                const code = m.errorCode() catch return error.MalformedReply;
                if (code == 0) return; // ACK
                return errnoToError(code);
            }
        }
    }
};

// ── offline tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "wire constants agree with the documented UAPI" {
    try testing.expectEqual(@as(u8, 0), WG_CMD.GET_DEVICE);
    try testing.expectEqual(@as(u8, 1), WG_CMD.SET_DEVICE);
    try testing.expectEqual(@as(u32, 1), WGDEVICE_F.REPLACE_PEERS);
    try testing.expectEqual(@as(u16, 8), WGDEVICE_A.PEERS);
    try testing.expectEqual(@as(u32, 1), WGPEER_F.REMOVE_ME);
    try testing.expectEqual(@as(u32, 2), WGPEER_F.REPLACE_ALLOWEDIPS);
    try testing.expectEqual(@as(u32, 4), WGPEER_F.UPDATE_ONLY);
    try testing.expectEqual(@as(u16, 9), WGPEER_A.ALLOWEDIPS);
    try testing.expectEqual(@as(u16, 3), WGALLOWEDIP_A.CIDR_MASK);
    try testing.expectEqual(@as(u16, 0x10), genl.GENL_ID_CTRL);
    try testing.expectEqual(@as(usize, 4), genl.header_len);
}

test "key base64: zero-key vector, round-trip, malformed inputs" {
    const zero: Key = @splat(0);
    const zero_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    try testing.expectEqualStrings(zero_b64, &keyToBase64(zero));
    try testing.expectEqual(zero, try keyFromBase64(zero_b64));

    var key: Key = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i * 7 % 256);
    const text = keyToBase64(key);
    try testing.expectEqual(key, try keyFromBase64(&text));

    try testing.expectError(error.InvalidKey, keyFromBase64(""));
    try testing.expectError(error.InvalidKey, keyFromBase64("short"));
    try testing.expectError(error.InvalidKey, keyFromBase64(zero_b64[0..43]));
    var bad_char = text;
    bad_char[10] = '!';
    try testing.expectError(error.InvalidKey, keyFromBase64(&bad_char));
    // Non-canonical: nonzero trailing bits in the final symbol.
    const noncanon = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=";
    try testing.expectError(error.InvalidKey, keyFromBase64(noncanon));
}

fn patternKey(comptime base: u8) Key {
    var key: Key = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(base + i);
    return key;
}

test "golden: WG_CMD_SET_DEVICE request bytes (device + peer + allowed-ip)" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE
    const priv = comptime patternKey(0x00);
    const peer_pub = comptime patternKey(0x40);

    var reqs = try buildSetRequests(testing.allocator, 0x1c, 1, .{
        .ifname = "wg0",
        .private_key = priv,
        .listen_port = 51820,
        .replace_peers = true,
        .peers = &.{.{
            .public_key = peer_pub,
            .replace_allowed_ips = true,
            .endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 5 }, .port = 12345 } },
            .persistent_keepalive_interval = 25,
            .allowed_ips = &.{AllowedIp.v4(.{ 10, 0, 0, 0 }, 24)},
        }},
    }, default_max_msg_len);
    defer reqs.deinit(testing.allocator);

    const expected = [_]u8{
        // nlmsghdr
        0xc0, 0x00, 0x00, 0x00, // len = 192
        0x1c, 0x00, // type = resolved family id
        0x05, 0x00, // flags = REQUEST | ACK
        0x01, 0x00, 0x00, 0x00, // seq
        0x00, 0x00, 0x00, 0x00, // pid
        // genlmsghdr
        0x01, 0x01, 0x00, 0x00, // cmd = SET_DEVICE, version = 1
        // WGDEVICE_A_IFNAME "wg0"
        0x08, 0x00, 0x02, 0x00,
        'w',  'g',  '0',  0x00,
        // WGDEVICE_A_FLAGS = REPLACE_PEERS
        0x08, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00,
        // WGDEVICE_A_PRIVATE_KEY
        0x24, 0x00, 0x03, 0x00,
    } ++ priv ++ [_]u8{
        // WGDEVICE_A_LISTEN_PORT = 51820
        0x06, 0x00, 0x06, 0x00, 0x6c, 0xca, 0x00, 0x00,
        // WGDEVICE_A_PEERS (nested)
        0x70, 0x00, 0x08, 0x80,
        // peer entry (nested, type 0)
        0x6c, 0x00, 0x00, 0x80,
        // WGPEER_A_PUBLIC_KEY
        0x24, 0x00, 0x01, 0x00,
    } ++ peer_pub ++ [_]u8{
        // WGPEER_A_FLAGS = REPLACE_ALLOWEDIPS
        0x08, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00,
        // WGPEER_A_ENDPOINT: sockaddr_in 203.0.113.5:12345
        0x14, 0x00, 0x04, 0x00, 0x02, 0x00, 0x30, 0x39,
        203,  0,    113,  5,    0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL = 25
        0x06, 0x00, 0x05, 0x00,
        0x19, 0x00, 0x00, 0x00,
        // WGPEER_A_ALLOWEDIPS (nested)
        0x20, 0x00, 0x09, 0x80,
        // allowed-ip entry (nested, type 0)
        0x1c, 0x00, 0x00, 0x80,
        // WGALLOWEDIP_A_FAMILY = AF_INET
        0x06, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00,
        // WGALLOWEDIP_A_IPADDR = 10.0.0.0
        0x08, 0x00, 0x02, 0x00,
        10,   0,    0,    0,
        // WGALLOWEDIP_A_CIDR_MASK = 24
           0x05, 0x00, 0x03, 0x00,
        24,   0x00, 0x00, 0x00,
    };
    try testing.expectEqual(@as(u32, 1), reqs.msg_count);
    try testing.expectEqualSlices(u8, &expected, reqs.buf);
}

test "set builder: ifindex identity, remove peer, config validation" {
    const gpa = testing.allocator;

    // Remove-peer request addressed by ifindex.
    var reqs = try buildSetRequests(gpa, 0x1c, 5, .{
        .ifindex = 7,
        .peers = &.{.{ .public_key = patternKey(0x10), .remove = true }},
    }, default_max_msg_len);
    defer reqs.deinit(gpa);

    var it: codec.MessageIterator = .{ .buf = reqs.buf };
    const m = (try it.next()).?;
    try testing.expectEqual(@as(?codec.Message, null), try it.next());
    const g = try genl.splitPayload(m.payload);
    try testing.expectEqual(WG_CMD.SET_DEVICE, g.cmd);

    var attrs: codec.AttrIterator = .{ .buf = g.attrs };
    const ifindex_attr = (try attrs.next()).?;
    try testing.expectEqual(WGDEVICE_A.IFINDEX, ifindex_attr.type);
    try testing.expectEqual(@as(u32, 7), try ifindex_attr.asU32());
    const peers_attr = (try attrs.next()).?;
    try testing.expectEqual(WGDEVICE_A.PEERS, peers_attr.type);
    try testing.expect(peers_attr.raw_type & codec.NLA_F_NESTED != 0);
    var peers_it = peers_attr.nested();
    var entry_it = (try peers_it.next()).?.nested();
    var saw_remove = false;
    while (try entry_it.next()) |a| {
        if (a.type == WGPEER_A.FLAGS)
            saw_remove = (try a.asU32()) & WGPEER_F.REMOVE_ME != 0;
    }
    try testing.expect(saw_remove);

    // Invalid configs are rejected before any wire bytes exist.
    try testing.expectError(error.InvalidConfig, buildSetRequests(gpa, 1, 1, .{}, 8192));
    try testing.expectError(error.InvalidConfig, buildSetRequests(gpa, 1, 1, .{
        .ifname = "an-interface-name-way-too-long",
    }, 8192));
    try testing.expectError(error.InvalidConfig, buildSetRequests(gpa, 1, 1, .{
        .ifname = "wg0",
        .peers = &.{.{
            .public_key = patternKey(0),
            .allowed_ips = &.{.{ .family = AF.INET, .addr_len = 16, .cidr = 24 }},
        }},
    }, 8192));
    try testing.expectError(error.InvalidConfig, buildSetRequests(gpa, 1, 1, .{
        .ifname = "wg0",
        .peers = &.{.{
            .public_key = patternKey(0),
            .allowed_ips = &.{AllowedIp.v4(.{ 10, 0, 0, 0 }, 33)},
        }},
    }, 8192));
}

test "set builder splits a large config and the parser reassembles it" {
    const gpa = testing.allocator;

    // Peer 1: eight IPv6 allowed-ips (40 bytes each) + peer 2 — with a
    // 256-byte soft ceiling this must split across ≥ 2 messages.
    var ips1: [8]AllowedIp = undefined;
    for (&ips1, 0..) |*ip, i| {
        var addr: [16]u8 = @splat(0);
        addr[0] = 0xfd;
        addr[15] = @intCast(i + 1);
        ip.* = AllowedIp.v6(addr, 64);
    }
    const cfg: Config = .{
        .ifname = "wg0",
        .listen_port = 51820,
        .peers = &.{
            .{
                .public_key = patternKey(0x40),
                .replace_allowed_ips = true,
                .allowed_ips = &ips1,
            },
            .{
                .public_key = patternKey(0x80),
                .allowed_ips = &.{AllowedIp.v4(.{ 10, 9, 8, 0 }, 24)},
            },
        },
    };
    var reqs = try buildSetRequests(gpa, 0x1c, 100, cfg, 256);
    defer reqs.deinit(gpa);
    try testing.expect(reqs.msg_count >= 2);

    // Feed every message back through the GET parser (same attribute
    // grammar): continuations must merge into two typed peers.
    var parser: DeviceParser = .init(gpa);
    defer parser.deinit();
    var flags_attrs: usize = 0;
    var peer_entries: usize = 0;
    var prev_seq: ?u32 = null;
    var it: codec.MessageIterator = .{ .buf = reqs.buf };
    var msg_count: u32 = 0;
    while (try it.next()) |m| {
        msg_count += 1;
        try testing.expect(m.payload.len + codec.header_len <= 256);
        if (prev_seq) |prev| try testing.expectEqual(prev +% 1, m.seq); // consecutive seqs
        prev_seq = m.seq;
        try parser.feed(m.payload);

        // Count peer entries and WGPEER_A_FLAGS occurrences: flags may only
        // ever be sent once per configured peer (continuation fragments must
        // not repeat REPLACE_ALLOWEDIPS).
        const g = try genl.splitPayload(m.payload);
        var attrs: codec.AttrIterator = .{ .buf = g.attrs };
        while (try attrs.next()) |a| {
            if (a.type != WGDEVICE_A.PEERS) continue;
            var pit = a.nested();
            while (try pit.next()) |entry| {
                peer_entries += 1;
                var eit = entry.nested();
                while (try eit.next()) |pa| {
                    if (pa.type == WGPEER_A.FLAGS) flags_attrs += 1;
                }
            }
        }
    }
    try testing.expectEqual(reqs.msg_count, msg_count);
    try testing.expect(peer_entries > cfg.peers.len); // a split actually happened
    try testing.expectEqual(@as(usize, 1), flags_attrs); // only peer 1 has flags

    var dev = try parser.finish();
    defer dev.deinit(gpa);
    try testing.expectEqualStrings("wg0", dev.ifname());
    try testing.expectEqual(@as(u16, 51820), dev.listen_port);
    try testing.expectEqual(@as(usize, 2), dev.peers.len);
    try testing.expectEqual(patternKey(0x40), dev.peers[0].public_key);
    try testing.expectEqual(@as(usize, 8), dev.peers[0].allowed_ips.len);
    for (dev.peers[0].allowed_ips, 0..) |ip, i| {
        try testing.expectEqual(AF.INET6, ip.family);
        try testing.expectEqual(@as(u8, @intCast(i + 1)), ip.addr[15]);
        try testing.expectEqual(@as(u8, 64), ip.cidr);
    }
    try testing.expectEqual(patternKey(0x80), dev.peers[1].public_key);
    try testing.expectEqual(@as(usize, 1), dev.peers[1].allowed_ips.len);
    try testing.expectEqualSlices(u8, &.{ 10, 9, 8, 0 }, dev.peers[1].allowed_ips[0].bytes());
}

// Hand-assemble a WG_CMD_GET_DEVICE reply payload for parser tests.
const GetFixture = struct {
    fn deviceHeader(gpa: std.mem.Allocator, list: *std.ArrayList(u8), ifindex: u32) !void {
        try genl.appendHeader(gpa, list, WG_CMD.GET_DEVICE, WG_GENL_VERSION);
        try codec.appendAttrU32(gpa, list, WGDEVICE_A.IFINDEX, ifindex);
        try codec.appendAttrString(gpa, list, WGDEVICE_A.IFNAME, "wg-test");
    }

    fn timespecAttr(gpa: std.mem.Allocator, list: *std.ArrayList(u8), sec: i64, nsec: i64) !void {
        var raw: [16]u8 = undefined;
        std.mem.writeInt(i64, raw[0..8], sec, native_endian);
        std.mem.writeInt(i64, raw[8..16], nsec, native_endian);
        try attrRaw(gpa, list, WGPEER_A.LAST_HANDSHAKE_TIME, &raw);
    }

    fn u64Attr(gpa: std.mem.Allocator, list: *std.ArrayList(u8), t: u16, v: u64) !void {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(u64, &raw, v, native_endian);
        try attrRaw(gpa, list, t, &raw);
    }
};

test "get parse: multipart device with peer continuation across messages" {
    const gpa = testing.allocator;
    const dev_pub = patternKey(0x01);
    const peer_a = patternKey(0x40);
    const peer_b = patternKey(0x80);
    const psk = patternKey(0xc0);

    // Message 1: full device attrs + peer A (endpoint, counters, one ip).
    var msg1: std.ArrayList(u8) = .empty;
    defer msg1.deinit(gpa);
    try GetFixture.deviceHeader(gpa, &msg1, 7);
    try attrRaw(gpa, &msg1, WGDEVICE_A.PUBLIC_KEY, &dev_pub);
    try attrU16(gpa, &msg1, WGDEVICE_A.LISTEN_PORT, 51820);
    try codec.appendAttrU32(gpa, &msg1, WGDEVICE_A.FWMARK, 0x2a);
    {
        const peers = try nestBegin(gpa, &msg1, WGDEVICE_A.PEERS);
        const entry = try nestBegin(gpa, &msg1, 0);
        try attrRaw(gpa, &msg1, WGPEER_A.PUBLIC_KEY, &peer_a);
        try attrRaw(gpa, &msg1, WGPEER_A.PRESHARED_KEY, &psk);
        try appendEndpoint(gpa, &msg1, .{ .v6 = .{
            .addr = [_]u8{0xfd} ++ [_]u8{0} ** 14 ++ [_]u8{1},
            .port = 1234,
            .scope_id = 3,
        } });
        try attrU16(gpa, &msg1, WGPEER_A.PERSISTENT_KEEPALIVE_INTERVAL, 15);
        try GetFixture.timespecAttr(gpa, &msg1, 1700000000, 123);
        try GetFixture.u64Attr(gpa, &msg1, WGPEER_A.RX_BYTES, 1000);
        try GetFixture.u64Attr(gpa, &msg1, WGPEER_A.TX_BYTES, 2000);
        try codec.appendAttrU32(gpa, &msg1, WGPEER_A.PROTOCOL_VERSION, 1);
        const ips = try nestBegin(gpa, &msg1, WGPEER_A.ALLOWEDIPS);
        try appendAllowedIp(gpa, &msg1, AllowedIp.v4(.{ 10, 0, 0, 0 }, 24));
        nestEnd(&msg1, ips);
        nestEnd(&msg1, entry);
        nestEnd(&msg1, peers);
    }

    // Message 2: peer A continuation (public key + one more ip) + peer B
    // with an all-zero PSK (= unset).
    var msg2: std.ArrayList(u8) = .empty;
    defer msg2.deinit(gpa);
    try GetFixture.deviceHeader(gpa, &msg2, 7);
    {
        const peers = try nestBegin(gpa, &msg2, WGDEVICE_A.PEERS);
        var entry = try nestBegin(gpa, &msg2, 0);
        try attrRaw(gpa, &msg2, WGPEER_A.PUBLIC_KEY, &peer_a);
        const ips = try nestBegin(gpa, &msg2, WGPEER_A.ALLOWEDIPS);
        try appendAllowedIp(gpa, &msg2, AllowedIp.v6([_]u8{0xfd} ++ [_]u8{0} ** 15, 64));
        nestEnd(&msg2, ips);
        nestEnd(&msg2, entry);
        entry = try nestBegin(gpa, &msg2, 0);
        try attrRaw(gpa, &msg2, WGPEER_A.PUBLIC_KEY, &peer_b);
        try attrRaw(gpa, &msg2, WGPEER_A.PRESHARED_KEY, &(@as(Key, @splat(0))));
        nestEnd(&msg2, entry);
        nestEnd(&msg2, peers);
    }

    var parser: DeviceParser = .init(gpa);
    defer parser.deinit();
    try parser.feed(msg1.items);
    try parser.feed(msg2.items);
    var dev = try parser.finish();
    defer dev.deinit(gpa);

    try testing.expectEqual(@as(u32, 7), dev.ifindex);
    try testing.expectEqualStrings("wg-test", dev.ifname());
    try testing.expectEqual(dev_pub, dev.public_key.?);
    try testing.expectEqual(@as(?Key, null), dev.private_key);
    try testing.expectEqual(@as(u16, 51820), dev.listen_port);
    try testing.expectEqual(@as(u32, 0x2a), dev.fwmark);
    try testing.expectEqual(@as(usize, 2), dev.peers.len);

    const a = dev.peers[0];
    try testing.expectEqual(peer_a, a.public_key);
    try testing.expectEqual(psk, a.preshared_key.?);
    try testing.expectEqual(@as(u16, 1234), a.endpoint.?.port());
    try testing.expectEqual(@as(u32, 3), a.endpoint.?.v6.scope_id);
    try testing.expectEqual(@as(u8, 0xfd), a.endpoint.?.v6.addr[0]);
    try testing.expectEqual(@as(u16, 15), a.persistent_keepalive_interval);
    try testing.expectEqual(@as(i64, 1700000000), a.last_handshake_time.sec);
    try testing.expectEqual(@as(i64, 123), a.last_handshake_time.nsec);
    try testing.expectEqual(@as(u64, 1000), a.rx_bytes);
    try testing.expectEqual(@as(u64, 2000), a.tx_bytes);
    try testing.expectEqual(@as(u32, 1), a.protocol_version);
    try testing.expectEqual(@as(usize, 2), a.allowed_ips.len);
    try testing.expectEqual(AF.INET, a.allowed_ips[0].family);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 0 }, a.allowed_ips[0].bytes());
    try testing.expectEqual(@as(u8, 24), a.allowed_ips[0].cidr);
    try testing.expectEqual(AF.INET6, a.allowed_ips[1].family);
    try testing.expectEqual(@as(u8, 64), a.allowed_ips[1].cidr);

    const b = dev.peers[1];
    try testing.expectEqual(peer_b, b.public_key);
    try testing.expectEqual(@as(?Key, null), b.preshared_key); // zero PSK = unset
    try testing.expectEqual(@as(?Endpoint, null), b.endpoint);
    try testing.expectEqual(@as(usize, 0), b.allowed_ips.len);
}

test "get parse: malformed replies yield typed errors, never a panic" {
    const gpa = testing.allocator;

    // Truncated genlmsghdr.
    {
        var parser: DeviceParser = .init(gpa);
        defer parser.deinit();
        try testing.expectError(error.Truncated, parser.feed(&.{ 0, 1 }));
    }
    // Key attribute with a wrong length.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try genl.appendHeader(gpa, &list, WG_CMD.GET_DEVICE, WG_GENL_VERSION);
        try attrRaw(gpa, &list, WGDEVICE_A.PRIVATE_KEY, &.{ 1, 2, 3 });
        var parser: DeviceParser = .init(gpa);
        defer parser.deinit();
        try testing.expectError(error.BadLength, parser.feed(list.items));
    }
    // Attribute whose declared length overruns the payload.
    {
        var raw: [genl.header_len + 4]u8 = @splat(0);
        raw[1] = WG_GENL_VERSION;
        std.mem.writeInt(u16, raw[4..6], 200, native_endian);
        std.mem.writeInt(u16, raw[6..8], WGDEVICE_A.IFNAME, native_endian);
        var parser: DeviceParser = .init(gpa);
        defer parser.deinit();
        try testing.expectError(error.Truncated, parser.feed(&raw));
    }
    // Allowed-ip whose family contradicts its address length.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try genl.appendHeader(gpa, &list, WG_CMD.GET_DEVICE, WG_GENL_VERSION);
        const peers = try nestBegin(gpa, &list, WGDEVICE_A.PEERS);
        const entry = try nestBegin(gpa, &list, 0);
        try attrRaw(gpa, &list, WGPEER_A.PUBLIC_KEY, &patternKey(1));
        const ips = try nestBegin(gpa, &list, WGPEER_A.ALLOWEDIPS);
        const ip_entry = try nestBegin(gpa, &list, 0);
        try attrU16(gpa, &list, WGALLOWEDIP_A.FAMILY, AF.INET);
        try attrRaw(gpa, &list, WGALLOWEDIP_A.IPADDR, &([_]u8{0} ** 16)); // 16B for AF_INET
        try attrU8(gpa, &list, WGALLOWEDIP_A.CIDR_MASK, 24);
        nestEnd(&list, ip_entry);
        nestEnd(&list, ips);
        nestEnd(&list, entry);
        nestEnd(&list, peers);
        var parser: DeviceParser = .init(gpa);
        defer parser.deinit();
        try testing.expectError(error.BadLength, parser.feed(list.items));
    }
    // Endpoint that is neither sockaddr_in nor sockaddr_in6.
    try testing.expectError(error.BadLength, parseEndpoint(&([_]u8{0} ** 12)));
    var bogus: [16]u8 = @splat(0);
    bogus[0] = 99; // unknown family
    try testing.expectError(error.BadLength, parseEndpoint(&bogus));
}

test "errnoToError maps kernel NLMSG_ERROR codes" {
    try testing.expectEqual(error.AccessDenied, errnoToError(-@as(i32, @intFromEnum(linux.E.PERM))));
    try testing.expectEqual(error.NoSuchDevice, errnoToError(-@as(i32, @intFromEnum(linux.E.NODEV))));
    try testing.expectEqual(error.InvalidRequest, errnoToError(-@as(i32, @intFromEnum(linux.E.INVAL))));
    try testing.expectEqual(error.NotSupported, errnoToError(-@as(i32, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expectEqual(error.SystemResources, errnoToError(-@as(i32, @intFromEnum(linux.E.NOBUFS))));
    try testing.expectEqual(error.Unexpected, errnoToError(0));
    try testing.expectEqual(error.Unexpected, errnoToError(17));
    try testing.expectEqual(error.Unexpected, errnoToError(std.math.minInt(i32)));
}

test "fuzz: device parser never crashes on arbitrary payloads" {
    try testing.fuzz({}, fuzzParser, .{});
}

fn fuzzParser(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    var parser: DeviceParser = .init(testing.allocator);
    defer parser.deinit();
    parser.feed(raw[0..len]) catch {};
    parser.feed(raw[0..len]) catch {}; // feeding twice exercises the merge path
    _ = parseEndpoint(raw[0..@min(len, 28)]) catch {};
}

// ── integration tests (real kernel) ─────────────────────────────────────────

test "integration: nlctrl family resolve (unprivileged)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var sock = genl.Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer sock.close();

    // A family that certainly does not exist (short enough for the
    // GENL_NAMSIZ policy — a longer name would be EINVALed, not looked up).
    try testing.expectError(error.FamilyNotFound, sock.resolveFamily("zigwg-nope"));
    try testing.expectError(error.NameTooLong, sock.resolveFamily("zig-wg-name-way-too-long"));

    // nlctrl always resolves to itself.
    const ctrl = try sock.resolveFamily("nlctrl");
    try testing.expectEqual(genl.GENL_ID_CTRL, ctrl);

    // The wireguard family resolves only when the module is loaded.
    if (sock.resolveFamily(WG_GENL_NAME)) |id| {
        try testing.expect(id > genl.GENL_ID_CTRL);
    } else |err| switch (err) {
        error.FamilyNotFound => {}, // module not loaded — fine
        else => return err,
    }
}

/// Run `ip` with the given arguments; error.SkipZigTest when unavailable.
fn runIp(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !u8 {
    const candidates = [_][]const u8{ "ip", "/usr/sbin/ip", "/sbin/ip" };
    for (candidates) |argv0| {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.append(gpa, argv0);
        try argv.appendSlice(gpa, args);
        const res = std.process.run(gpa, io, .{ .argv = argv.items }) catch continue;
        defer gpa.free(res.stdout);
        defer gpa.free(res.stderr);
        return switch (res.term) {
            .exited => |code| code,
            else => 255,
        };
    }
    return error.SkipZigTest;
}

test "integration (root): set + get round-trip on a real wg interface" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest; // needs CAP_NET_ADMIN
    const gpa = testing.allocator;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ifname = "zigwgtest0";
    // Requires the wireguard kernel module; skip when unavailable.
    if (try runIp(gpa, io, &.{ "link", "add", ifname, "type", "wireguard" }) != 0)
        return error.SkipZigTest;
    defer _ = runIp(gpa, io, &.{ "link", "del", ifname }) catch 255;

    var wg = Wireguard.open(gpa) catch return error.SkipZigTest;
    defer wg.close();

    // Pre-clamped private key so the kernel reports it back unchanged.
    var priv = patternKey(0x07);
    priv[0] &= 248;
    priv[31] = (priv[31] & 127) | 64;
    const peer_pub = patternKey(0xa0);

    try wg.setDevice(.{
        .ifname = ifname,
        .private_key = priv,
        .listen_port = 51999,
        .fwmark = 0x51,
        .replace_peers = true,
        .peers = &.{.{
            .public_key = peer_pub,
            .endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 7 }, .port = 4321 } },
            .persistent_keepalive_interval = 25,
            .replace_allowed_ips = true,
            .allowed_ips = &.{
                AllowedIp.v4(.{ 10, 20, 30, 0 }, 24),
                AllowedIp.v6([_]u8{0xfd} ++ [_]u8{0} ** 15, 64),
            },
        }},
    });

    var dev = try wg.getDevice(ifname);
    defer dev.deinit(gpa);
    try testing.expectEqualStrings(ifname, dev.ifname());
    try testing.expectEqual(priv, dev.private_key.?);
    try testing.expectEqual(@as(u16, 51999), dev.listen_port);
    try testing.expectEqual(@as(u32, 0x51), dev.fwmark);
    try testing.expectEqual(@as(usize, 1), dev.peers.len);
    const peer = dev.peers[0];
    try testing.expectEqual(peer_pub, peer.public_key);
    try testing.expectEqual(@as(u16, 25), peer.persistent_keepalive_interval);
    try testing.expectEqual(@as(u16, 4321), peer.endpoint.?.port());
    try testing.expectEqualSlices(u8, &.{ 203, 0, 113, 7 }, &peer.endpoint.?.v4.addr);
    try testing.expectEqual(@as(usize, 2), peer.allowed_ips.len);
    var saw_v4 = false;
    var saw_v6 = false;
    for (peer.allowed_ips) |ip| switch (ip.family) {
        AF.INET => {
            try testing.expectEqualSlices(u8, &.{ 10, 20, 30, 0 }, ip.bytes());
            try testing.expectEqual(@as(u8, 24), ip.cidr);
            saw_v4 = true;
        },
        AF.INET6 => {
            try testing.expectEqual(@as(u8, 0xfd), ip.bytes()[0]);
            try testing.expectEqual(@as(u8, 64), ip.cidr);
            saw_v6 = true;
        },
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(saw_v4 and saw_v6);

    // Remove the peer, verify it is gone.
    try wg.setDevice(.{
        .ifname = ifname,
        .peers = &.{.{ .public_key = peer_pub, .remove = true }},
    });
    var dev2 = try wg.getDevice(ifname);
    defer dev2.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), dev2.peers.len);

    // A device that does not exist maps to a typed error.
    try testing.expectError(error.NoSuchDevice, wg.getDevice("zigwgnope0"));
}

test {
    _ = genl;
}

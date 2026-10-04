// SPDX-License-Identifier: MIT

//! DHCP (RFC 2131) message + options (RFC 2132) codec.
//!
//! - `Message.parse` — the fixed 236-byte header, the magic cookie
//!   (0x63825363), and a single pass over the options field that fills the
//!   typed fields (message type, requested IP, server identifier, lease
//!   time, subnet mask, routers, DNS servers, domain name, host name,
//!   parameter request list, client identifier). Everything is a slice
//!   into the caller's buffer — no allocation.
//! - `OptionIterator` — raw `{code, data}` walk over any options region
//!   (Pad(0) skipped, End(255) terminates); unknown options pass through
//!   untouched.
//! - `Builder` — header + cookie + options into a caller buffer, with
//!   typed helpers for the common options; `finish` appends End and can
//!   pad to the classic BOOTP 300-byte minimum.
//!
//! Option overload (option 52) is handled minimally: the overload value is
//! surfaced as `Message.overload` and the `sname`/`file` regions are
//! exposed raw, so a caller can run `OptionIterator` over them; the typed
//! fields are only extracted from the main options field.
//!
//! Provenance: clean-room from RFC 2131 (message format) and RFC 2132
//! (option codes and layouts).

const std = @import("std");
const netaddr = @import("netaddr");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");
const Mac = @import("mac.zig").Mac;

pub const ParseError = error{
    /// Shorter than the 236-byte fixed header + 4-byte cookie.
    Truncated,
    /// The four bytes after the header are not 0x63825363.
    BadCookie,
    /// An option header or its declared length overruns the buffer.
    TruncatedOption,
    /// A known fixed-layout option carries an impossible length
    /// (e.g. subnet mask with 3 bytes).
    BadOptionLength,
};

pub const BuildError = error{
    BufferTooSmall,
    /// Option data longer than 255 bytes.
    OptionTooLong,
};

/// Offset of the magic cookie == size of the fixed BOOTP header.
pub const header_len = 236;
pub const magic_cookie = [4]u8{ 0x63, 0x82, 0x53, 0x63 };
/// Classic minimum BOOTP packet length; some relays/servers drop shorter.
pub const bootp_min_len = 300;

pub const Op = enum(u8) {
    boot_request = 1,
    boot_reply = 2,
    _,
};

pub const MessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
    _,
};

/// RFC 2132 option codes this codec decodes into typed fields. Anything
/// else flows through `OptionIterator` as raw `{code, data}`.
pub const OptionCode = enum(u8) {
    pad = 0,
    subnet_mask = 1,
    router = 3,
    dns_server = 6,
    host_name = 12,
    domain_name = 15,
    ntp_servers = 42,
    vendor_specific = 43,
    requested_ip = 50,
    lease_time = 51,
    option_overload = 52,
    message_type = 53,
    server_id = 54,
    param_request_list = 55,
    vendor_class_id = 60,
    client_id = 61,
    tftp_server_name = 66,
    bootfile_name = 67,
    relay_agent_info = 82,
    domain_search = 119,
    classless_static_route = 121,
    end = 255,
    _,
};

/// Option 52 value: which extra regions carry options.
pub const Overload = enum(u8) {
    file = 1,
    sname = 2,
    both = 3,
    _,
};

/// One raw option as seen on the wire (Pad/End never surface here).
pub const RawOption = struct {
    code: u8,
    data: []const u8,
};

/// Bounds-checked walk over an options region. Yields raw options until
/// End(255) or the end of the buffer; Pad(0) is skipped.
pub const OptionIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(options_region: []const u8) OptionIterator {
        return .{ .buf = options_region };
    }

    pub fn next(it: *OptionIterator) ParseError!?RawOption {
        while (it.pos < it.buf.len) {
            const code = it.buf[it.pos];
            switch (code) {
                @intFromEnum(OptionCode.pad) => it.pos += 1,
                @intFromEnum(OptionCode.end) => {
                    it.pos = it.buf.len;
                    return null;
                },
                else => {
                    if (it.pos + 2 > it.buf.len) return ParseError.TruncatedOption;
                    const len: usize = it.buf[it.pos + 1];
                    if (it.pos + 2 + len > it.buf.len) return ParseError.TruncatedOption;
                    const data = it.buf[it.pos + 2 ..][0..len];
                    it.pos += 2 + len;
                    return .{ .code = code, .data = data };
                },
            }
        }
        return null;
    }
};

/// A list of IPv4 addresses packed as 4-byte groups (router, DNS, …).
pub const Ip4List = struct {
    bytes: []const u8, // length is a validated multiple of 4, >= 4

    pub fn count(l: Ip4List) usize {
        return l.bytes.len / 4;
    }

    pub fn at(l: Ip4List, i: usize) [4]u8 {
        return l.bytes[i * 4 ..][0..4].*;
    }

    pub fn first(l: Ip4List) [4]u8 {
        return l.at(0);
    }

    pub fn firstIp(l: Ip4List) netaddr.Ip {
        return .{ .v4 = l.first() };
    }
};

/// A parsed DHCP message. All slices point into the parsed buffer.
pub const Message = struct {
    op: Op,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: [4]u8,
    yiaddr: [4]u8,
    siaddr: [4]u8,
    giaddr: [4]u8,
    chaddr: [16]u8,
    /// Raw server-name region (may hold overloaded options).
    sname: *const [64]u8,
    /// Raw boot-file region (may hold overloaded options).
    file: *const [128]u8,
    /// The raw options field (after the cookie), for re-iteration.
    options_raw: []const u8,

    // Typed options (null when absent).
    message_type: ?MessageType = null,
    requested_ip: ?[4]u8 = null,
    server_id: ?[4]u8 = null,
    lease_time_s: ?u32 = null,
    subnet_mask: ?[4]u8 = null,
    routers: ?Ip4List = null,
    dns_servers: ?Ip4List = null,
    domain_name: ?[]const u8 = null,
    host_name: ?[]const u8 = null,
    param_request_list: ?[]const u8 = null,
    /// Raw client identifier (first byte is the hardware type when the
    /// common `htype + address` form is used).
    client_id: ?[]const u8 = null,
    overload: ?Overload = null,
    /// Option 42 (RFC 2132 §8.3).
    ntp_servers: ?Ip4List = null,
    /// Option 43, vendor-defined content (RFC 2132 §8.4).
    vendor_specific: ?[]const u8 = null,
    /// Option 60 (RFC 2132 §9.13), e.g. "MSFT 5.0", "PXEClient:…".
    vendor_class_id: ?[]const u8 = null,
    /// Options 66/67 (RFC 2132 §9.4/§9.5) — PXE / phone provisioning.
    tftp_server_name: ?[]const u8 = null,
    bootfile_name: ?[]const u8 = null,
    /// Option 82 (RFC 3046); walk it with `relayAgentInfo` (which reports
    /// malformed sub-options as errors).
    relay_agent_info: ?[]const u8 = null,
    /// Option 119 (RFC 3397); decode it with `domainSearch`.
    domain_search: ?[]const u8 = null,
    /// Option 121 (RFC 3442); walk it with `classlessRoutes` (which reports a
    /// malformed route as an error).
    classless_static_routes: ?[]const u8 = null,

    pub fn parse(bytes: []const u8) ParseError!Message {
        if (bytes.len < header_len + magic_cookie.len) return ParseError.Truncated;
        if (!std.mem.eql(u8, bytes[header_len..][0..4], &magic_cookie)) return ParseError.BadCookie;

        var m: Message = .{
            .op = @enumFromInt(bytes[0]),
            .htype = bytes[1],
            .hlen = bytes[2],
            .hops = bytes[3],
            .xid = std.mem.readInt(u32, bytes[4..8], .big),
            .secs = std.mem.readInt(u16, bytes[8..10], .big),
            .flags = std.mem.readInt(u16, bytes[10..12], .big),
            .ciaddr = bytes[12..16].*,
            .yiaddr = bytes[16..20].*,
            .siaddr = bytes[20..24].*,
            .giaddr = bytes[24..28].*,
            .chaddr = bytes[28..44].*,
            .sname = bytes[44..108],
            .file = bytes[108..236],
            .options_raw = bytes[header_len + magic_cookie.len ..],
        };

        var it = OptionIterator.init(m.options_raw);
        while (try it.next()) |opt| {
            switch (@as(OptionCode, @enumFromInt(opt.code))) {
                .message_type => m.message_type = @enumFromInt(try one(opt.data)),
                .requested_ip => m.requested_ip = try four(opt.data),
                .server_id => m.server_id = try four(opt.data),
                .lease_time => m.lease_time_s = std.mem.readInt(u32, &try four(opt.data), .big),
                .subnet_mask => m.subnet_mask = try four(opt.data),
                .router => m.routers = try ip4List(opt.data),
                .dns_server => m.dns_servers = try ip4List(opt.data),
                .domain_name => m.domain_name = opt.data,
                .host_name => m.host_name = opt.data,
                .param_request_list => m.param_request_list = opt.data,
                .client_id => m.client_id = opt.data,
                .option_overload => m.overload = @enumFromInt(try one(opt.data)),
                .ntp_servers => m.ntp_servers = try ip4List(opt.data),
                .vendor_specific => m.vendor_specific = opt.data,
                .vendor_class_id => m.vendor_class_id = opt.data,
                .tftp_server_name => m.tftp_server_name = opt.data,
                .bootfile_name => m.bootfile_name = opt.data,
                // 82/119/121 are validated lazily, by their iterators: a
                // malformed sub-structure must not make the whole message
                // unparseable — a caller watching for rogue DHCP servers
                // still needs the header and server id of a message whose
                // option 121 is garbage.
                .relay_agent_info => m.relay_agent_info = opt.data,
                .domain_search => m.domain_search = opt.data,
                .classless_static_route => m.classless_static_routes = opt.data,
                else => {}, // unknown/untyped: reachable via optionIterator()
            }
        }
        return m;
    }

    /// Option 82's sub-options (circuit id = 1, remote id = 2, …).
    pub fn relayAgentInfo(m: *const Message) ?RelayAgentIterator {
        const d = m.relay_agent_info orelse return null;
        return .{ .data = d };
    }

    /// Option 121's routes, in the order the server sent them.
    pub fn classlessRoutes(m: *const Message) ?ClasslessRouteIterator {
        const d = m.classless_static_routes orelse return null;
        return .{ .data = d };
    }

    /// Option 119's domain names.
    pub fn domainSearch(m: *const Message) ?DomainSearchIterator {
        const d = m.domain_search orelse return null;
        return .{ .data = d };
    }

    /// Re-iterate the raw options field (unknown options included).
    pub fn optionIterator(m: *const Message) OptionIterator {
        return OptionIterator.init(m.options_raw);
    }

    /// Iterate options overloaded into `sname` (check `overload` first).
    pub fn snameOptionIterator(m: *const Message) OptionIterator {
        return OptionIterator.init(m.sname);
    }

    /// Iterate options overloaded into `file` (check `overload` first).
    pub fn fileOptionIterator(m: *const Message) OptionIterator {
        return OptionIterator.init(m.file);
    }

    /// The RFC 2131 BROADCAST flag (bit 15 of `flags`).
    pub fn broadcastFlag(m: *const Message) bool {
        return m.flags & 0x8000 != 0;
    }

    /// The client hardware address as a MAC when htype/hlen say Ethernet.
    pub fn clientMac(m: *const Message) ?Mac {
        if (m.htype != 1 or m.hlen != 6) return null;
        return .{ .octets = m.chaddr[0..6].* };
    }

    pub fn yourIp(m: *const Message) netaddr.Ip {
        return .{ .v4 = m.yiaddr };
    }

    pub fn serverIdIp(m: *const Message) ?netaddr.Ip {
        return if (m.server_id) |sid| .{ .v4 = sid } else null;
    }

    fn one(data: []const u8) ParseError!u8 {
        if (data.len != 1) return ParseError.BadOptionLength;
        return data[0];
    }

    fn four(data: []const u8) ParseError![4]u8 {
        if (data.len != 4) return ParseError.BadOptionLength;
        return data[0..4].*;
    }

    fn ip4List(data: []const u8) ParseError!Ip4List {
        if (data.len < 4 or data.len % 4 != 0) return ParseError.BadOptionLength;
        return .{ .bytes = data };
    }
};

/// One RFC 3046 sub-option of option 82.
pub const RelayAgentSubOption = struct {
    /// 1 = Agent Circuit ID, 2 = Agent Remote ID (RFC 3046 §2.0).
    code: u8,
    data: []const u8,
};

pub const RelayAgentIterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(it: *RelayAgentIterator) ParseError!?RelayAgentSubOption {
        if (it.pos == it.data.len) return null;
        if (it.data.len - it.pos < 2) return ParseError.BadOptionLength;
        const len: usize = it.data[it.pos + 1];
        if (it.data.len - it.pos - 2 < len) return ParseError.BadOptionLength;
        const out: RelayAgentSubOption = .{ .code = it.data[it.pos], .data = it.data[it.pos + 2 ..][0..len] };
        it.pos += 2 + len;
        return out;
    }
};

/// One RFC 3442 route: destination prefix and the router to reach it.
pub const ClasslessRoute = struct {
    destination: [4]u8,
    prefix_len: u6,
    router: [4]u8,
};

/// RFC 3442 encoding: width (0-32), the ceil(width/8) significant octets of
/// the destination, then the 4-byte router.
pub const ClasslessRouteIterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(it: *ClasslessRouteIterator) ParseError!?ClasslessRoute {
        if (it.pos == it.data.len) return null;
        const width = it.data[it.pos];
        if (width > 32) return ParseError.BadOptionLength;
        const sig: usize = (@as(usize, width) + 7) / 8;
        if (it.data.len - it.pos - 1 < sig + 4) return ParseError.BadOptionLength;
        var r: ClasslessRoute = .{ .destination = @splat(0), .prefix_len = @intCast(width), .router = undefined };
        @memcpy(r.destination[0..sig], it.data[it.pos + 1 ..][0..sig]);
        r.router = it.data[it.pos + 1 + sig ..][0..4].*;
        it.pos += 1 + sig + 4;
        return r;
    }
};

/// Option 119 (RFC 3397): a list of RFC 1035 domain names, compressed with
/// pointers whose offsets count from the start of the option data.
pub const DomainSearchIterator = struct {
    data: []const u8,
    pos: usize = 0,

    /// The longest dotted name `next` can produce (RFC 1035: 255 octets on
    /// the wire, one fewer as text).
    pub const max_name_len = 254;

    /// Decode the next name into `out` (dotted, no trailing dot). A pointer
    /// must point strictly before the label that holds it, so a hostile
    /// option cannot loop.
    pub fn next(it: *DomainSearchIterator, out: *[max_name_len]u8) ParseError!?[]const u8 {
        if (it.pos == it.data.len) return null;
        var len: usize = 0;
        var p = it.pos;
        var jumped = false;
        while (true) {
            if (p >= it.data.len) return ParseError.BadOptionLength;
            const b = it.data[p];
            if (b == 0) {
                if (!jumped) it.pos = p + 1;
                break;
            }
            if (b & 0xc0 == 0xc0) {
                if (p + 1 >= it.data.len) return ParseError.BadOptionLength;
                const target = (@as(usize, b & 0x3f) << 8) | it.data[p + 1];
                if (target >= p) return ParseError.BadOptionLength;
                if (!jumped) it.pos = p + 2;
                jumped = true;
                p = target;
                continue;
            }
            if (b & 0xc0 != 0) return ParseError.BadOptionLength; // 0x40/0x80: reserved
            if (it.data.len - p - 1 < b) return ParseError.BadOptionLength;
            const sep: usize = if (len == 0) 0 else 1;
            if (len + sep + b > max_name_len) return ParseError.BadOptionLength;
            if (sep == 1) out[len] = '.';
            @memcpy(out[len + sep ..][0..b], it.data[p + 1 ..][0..b]);
            len += sep + b;
            p += 1 + b;
        }
        return out[0..len];
    }
};

/// Header fields for `Builder.init`; addresses default to 0.0.0.0.
pub const HeaderOptions = struct {
    op: Op,
    htype: u8 = 1, // Ethernet
    hlen: u8 = 6,
    hops: u8 = 0,
    xid: u32,
    secs: u16 = 0,
    /// Sets the BROADCAST flag (bit 15).
    broadcast: bool = false,
    ciaddr: [4]u8 = @splat(0),
    yiaddr: [4]u8 = @splat(0),
    siaddr: [4]u8 = @splat(0),
    giaddr: [4]u8 = @splat(0),
    /// Client hardware address; the first `hlen` bytes are significant.
    chaddr: [16]u8 = @splat(0),
};

/// Builds a DHCP message into a caller buffer: header + cookie at `init`,
/// options appended in call order, `finish` writes End (and optional pad).
pub const Builder = struct {
    buf: []u8,
    pos: usize,

    pub fn init(buf: []u8, hdr: HeaderOptions) BuildError!Builder {
        if (buf.len < header_len + magic_cookie.len + 1) return BuildError.BufferTooSmall;
        @memset(buf[0..header_len], 0);
        buf[0] = @intFromEnum(hdr.op);
        buf[1] = hdr.htype;
        buf[2] = hdr.hlen;
        buf[3] = hdr.hops;
        std.mem.writeInt(u32, buf[4..8], hdr.xid, .big);
        std.mem.writeInt(u16, buf[8..10], hdr.secs, .big);
        std.mem.writeInt(u16, buf[10..12], if (hdr.broadcast) 0x8000 else 0, .big);
        buf[12..16].* = hdr.ciaddr;
        buf[16..20].* = hdr.yiaddr;
        buf[20..24].* = hdr.siaddr;
        buf[24..28].* = hdr.giaddr;
        buf[28..44].* = hdr.chaddr;
        buf[header_len..][0..4].* = magic_cookie;
        return .{ .buf = buf, .pos = header_len + magic_cookie.len };
    }

    /// Convenience: an Ethernet chaddr from a MAC.
    pub fn chaddrFromMac(mac: Mac) [16]u8 {
        var out: [16]u8 = @splat(0);
        out[0..6].* = mac.octets;
        return out;
    }

    /// Appends a raw option (any code).
    pub fn addOption(b: *Builder, code: u8, data: []const u8) BuildError!void {
        if (data.len > 255) return BuildError.OptionTooLong;
        if (b.pos + 2 + data.len > b.buf.len) return BuildError.BufferTooSmall;
        b.buf[b.pos] = code;
        b.buf[b.pos + 1] = @intCast(data.len);
        @memcpy(b.buf[b.pos + 2 ..][0..data.len], data);
        b.pos += 2 + data.len;
    }

    /// Option 42; `addrs` as for `addRouters`.
    pub fn addNtpServers(b: *Builder, addrs: []const u8) BuildError!void {
        std.debug.assert(addrs.len >= 4 and addrs.len % 4 == 0);
        try b.addOption(@intFromEnum(OptionCode.ntp_servers), addrs);
    }

    pub fn addVendorClassId(b: *Builder, id: []const u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.vendor_class_id), id);
    }

    pub fn addTftpServerName(b: *Builder, name: []const u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.tftp_server_name), name);
    }

    pub fn addBootfileName(b: *Builder, name: []const u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.bootfile_name), name);
    }

    /// Option 82 with an Agent Circuit ID and/or an Agent Remote ID.
    pub fn addRelayAgentInfo(b: *Builder, circuit_id: ?[]const u8, remote_id: ?[]const u8) BuildError!void {
        var tmp: [255]u8 = undefined;
        var n: usize = 0;
        for ([_]struct { u8, ?[]const u8 }{ .{ 1, circuit_id }, .{ 2, remote_id } }) |sub| {
            const d = sub[1] orelse continue;
            if (d.len > 255 or n + 2 + d.len > tmp.len) return BuildError.OptionTooLong;
            tmp[n] = sub[0];
            tmp[n + 1] = @intCast(d.len);
            @memcpy(tmp[n + 2 ..][0..d.len], d);
            n += 2 + d.len;
        }
        try b.addOption(@intFromEnum(OptionCode.relay_agent_info), tmp[0..n]);
    }

    /// Option 121. Host bits beyond `prefix_len` in a destination are not
    /// sent (RFC 3442 carries only the significant octets).
    pub fn addClasslessRoutes(b: *Builder, routes: []const ClasslessRoute) BuildError!void {
        var tmp: [255]u8 = undefined;
        var n: usize = 0;
        for (routes) |r| {
            if (r.prefix_len > 32) return BuildError.OptionTooLong;
            const sig: usize = (@as(usize, r.prefix_len) + 7) / 8;
            if (n + 1 + sig + 4 > tmp.len) return BuildError.OptionTooLong;
            tmp[n] = r.prefix_len;
            @memcpy(tmp[n + 1 ..][0..sig], r.destination[0..sig]);
            @memcpy(tmp[n + 1 + sig ..][0..4], &r.router);
            n += 1 + sig + 4;
        }
        try b.addOption(@intFromEnum(OptionCode.classless_static_route), tmp[0..n]);
    }

    /// Option 119, uncompressed (every receiver must accept that). Each name
    /// is dotted text; a label must be 1-63 bytes.
    pub fn addDomainSearch(b: *Builder, names: []const []const u8) BuildError!void {
        var tmp: [255]u8 = undefined;
        var n: usize = 0;
        for (names) |name| {
            var labels = std.mem.splitScalar(u8, name, '.');
            while (labels.next()) |label| {
                if (label.len == 0 or label.len > 63) return BuildError.OptionTooLong;
                if (n + 1 + label.len > tmp.len) return BuildError.OptionTooLong;
                tmp[n] = @intCast(label.len);
                @memcpy(tmp[n + 1 ..][0..label.len], label);
                n += 1 + label.len;
            }
            if (n + 1 > tmp.len) return BuildError.OptionTooLong;
            tmp[n] = 0;
            n += 1;
        }
        try b.addOption(@intFromEnum(OptionCode.domain_search), tmp[0..n]);
    }

    pub fn addMessageType(b: *Builder, t: MessageType) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.message_type), &.{@intFromEnum(t)});
    }

    pub fn addRequestedIp(b: *Builder, ip: [4]u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.requested_ip), &ip);
    }

    pub fn addServerId(b: *Builder, ip: [4]u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.server_id), &ip);
    }

    pub fn addLeaseTime(b: *Builder, seconds: u32) BuildError!void {
        var be: [4]u8 = undefined;
        std.mem.writeInt(u32, &be, seconds, .big);
        try b.addOption(@intFromEnum(OptionCode.lease_time), &be);
    }

    pub fn addSubnetMask(b: *Builder, mask: [4]u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.subnet_mask), &mask);
    }

    /// `addrs` is a packed list of 4-byte addresses (len % 4 == 0, >= 4).
    pub fn addRouters(b: *Builder, addrs: []const u8) BuildError!void {
        std.debug.assert(addrs.len >= 4 and addrs.len % 4 == 0);
        try b.addOption(@intFromEnum(OptionCode.router), addrs);
    }

    /// `addrs` is a packed list of 4-byte addresses (len % 4 == 0, >= 4).
    pub fn addDnsServers(b: *Builder, addrs: []const u8) BuildError!void {
        std.debug.assert(addrs.len >= 4 and addrs.len % 4 == 0);
        try b.addOption(@intFromEnum(OptionCode.dns_server), addrs);
    }

    pub fn addDomainName(b: *Builder, name: []const u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.domain_name), name);
    }

    pub fn addHostName(b: *Builder, name: []const u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.host_name), name);
    }

    pub fn addParamRequestList(b: *Builder, codes: []const u8) BuildError!void {
        try b.addOption(@intFromEnum(OptionCode.param_request_list), codes);
    }

    /// The common `htype + hardware address` client identifier.
    pub fn addClientIdMac(b: *Builder, mac: Mac) BuildError!void {
        const data = [_]u8{0x01} ++ mac.octets;
        try b.addOption(@intFromEnum(OptionCode.client_id), &data);
    }

    pub const FinishOptions = struct {
        /// Zero-pad the message up to this total length (e.g.
        /// `bootp_min_len`); 0 = no padding.
        pad_to: usize = 0,
    };

    /// Appends End(255) and returns the finished message bytes.
    pub fn finish(b: *Builder, opts: FinishOptions) BuildError![]const u8 {
        if (b.pos + 1 > b.buf.len) return BuildError.BufferTooSmall;
        b.buf[b.pos] = @intFromEnum(OptionCode.end);
        b.pos += 1;
        if (b.pos < opts.pad_to) {
            if (opts.pad_to > b.buf.len) return BuildError.BufferTooSmall;
            @memset(b.buf[b.pos..opts.pad_to], 0);
            b.pos = opts.pad_to;
        }
        return b.buf[0..b.pos];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const kat_mac = Mac{ .octets = .{ 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42 } };

// Golden DHCPDISCOVER, transcribed field-by-field from the RFC 2131 figure 1
// layout + RFC 2132 option formats.
const kat_discover = [_]u8{ 0x01, 0x01, 0x06, 0x00 } // op, htype, hlen, hops
    ++ [_]u8{ 0x39, 0x03, 0xf3, 0x26 } // xid
    ++ [_]u8{ 0x00, 0x00, 0x00, 0x00 } // secs, flags
    ++ [_]u8{0} ** 16 // ciaddr, yiaddr, siaddr, giaddr
    ++ [_]u8{ 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42 } ++ [_]u8{0} ** 10 // chaddr
    ++ [_]u8{0} ** 64 // sname
    ++ [_]u8{0} ** 128 // file
    ++ magic_cookie ++ [_]u8{ 53, 1, 1 } // message type: DISCOVER
    ++ [_]u8{ 61, 7, 0x01, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42 } // client id
    ++ [_]u8{ 50, 4, 192, 168, 0, 10 } // requested IP
    ++ [_]u8{ 55, 4, 1, 3, 6, 15 } // param request list
    ++ [_]u8{ 12, 8 } ++ "zig-host".* // host name
    ++ [_]u8{255}; // end

// Golden DHCPACK for the same transaction.
const kat_ack = [_]u8{ 0x02, 0x01, 0x06, 0x00 } // op: BOOTREPLY
    ++ [_]u8{ 0x39, 0x03, 0xf3, 0x26 } // xid
    ++ [_]u8{ 0x00, 0x00, 0x00, 0x00 } // secs, flags
    ++ [_]u8{ 0, 0, 0, 0 } // ciaddr
    ++ [_]u8{ 192, 168, 0, 10 } // yiaddr
    ++ [_]u8{ 192, 168, 0, 1 } // siaddr
    ++ [_]u8{ 0, 0, 0, 0 } // giaddr
    ++ [_]u8{ 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42 } ++ [_]u8{0} ** 10 // chaddr
    ++ [_]u8{0} ** 64 // sname
    ++ [_]u8{0} ** 128 // file
    ++ magic_cookie ++ [_]u8{ 53, 1, 5 } // message type: ACK
    ++ [_]u8{ 54, 4, 192, 168, 0, 1 } // server identifier
    ++ [_]u8{ 51, 4, 0x00, 0x01, 0x51, 0x80 } // lease time: 86400 s
    ++ [_]u8{ 1, 4, 255, 255, 255, 0 } // subnet mask
    ++ [_]u8{ 3, 4, 192, 168, 0, 1 } // router
    ++ [_]u8{ 6, 8, 8, 8, 8, 8, 8, 8, 4, 4 } // DNS: 8.8.8.8, 8.8.4.4
    ++ [_]u8{ 15, 3 } ++ "lan".* // domain name
    ++ [_]u8{255}; // end

test "DHCP KAT: parse DISCOVER" {
    const m = try Message.parse(&kat_discover);
    try testing.expectEqual(Op.boot_request, m.op);
    try testing.expectEqual(@as(u32, 0x3903f326), m.xid);
    try testing.expectEqual(MessageType.discover, m.message_type.?);
    try testing.expect(m.clientMac().?.eql(kat_mac));
    try testing.expectEqualSlices(u8, &.{ 192, 168, 0, 10 }, &m.requested_ip.?);
    try testing.expectEqualSlices(u8, &.{ 1, 3, 6, 15 }, m.param_request_list.?);
    try testing.expectEqualStrings("zig-host", m.host_name.?);
    try testing.expectEqualSlices(u8, &([_]u8{0x01} ++ kat_mac.octets), m.client_id.?);
    try testing.expect(!m.broadcastFlag());
    try testing.expect(m.server_id == null);
    try testing.expect(m.lease_time_s == null);
}

test "DHCP: clientMac requires BOTH Ethernet htype and hlen 6" {
    var buf: [300]u8 = undefined;
    // Non-Ethernet hardware type (e.g. IEEE 802 Token Ring = 6), hlen still 6:
    // the address bytes look plausible but this is not an Ethernet MAC.
    {
        var b = try Builder.init(&buf, .{
            .op = .boot_request,
            .xid = 1,
            .htype = 6,
            .hlen = 6,
            .chaddr = Builder.chaddrFromMac(kat_mac),
        });
        const bytes = try b.finish(.{});
        const m = try Message.parse(bytes);
        try testing.expectEqual(@as(?Mac, null), m.clientMac());
    }
    // Ethernet htype but a non-6 hlen: also not a usable MAC.
    {
        var b = try Builder.init(&buf, .{
            .op = .boot_request,
            .xid = 1,
            .htype = 1,
            .hlen = 4,
            .chaddr = Builder.chaddrFromMac(kat_mac),
        });
        const bytes = try b.finish(.{});
        const m = try Message.parse(bytes);
        try testing.expectEqual(@as(?Mac, null), m.clientMac());
    }
}

test "DHCP KAT: parse ACK" {
    const m = try Message.parse(&kat_ack);
    try testing.expectEqual(Op.boot_reply, m.op);
    try testing.expectEqual(MessageType.ack, m.message_type.?);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 0, 10 }, &m.yiaddr);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 0, 1 }, &m.server_id.?);
    try testing.expectEqual(@as(u32, 86400), m.lease_time_s.?);
    try testing.expectEqualSlices(u8, &.{ 255, 255, 255, 0 }, &m.subnet_mask.?);
    try testing.expectEqual(@as(usize, 1), m.routers.?.count());
    try testing.expectEqualSlices(u8, &.{ 192, 168, 0, 1 }, &m.routers.?.first());
    try testing.expectEqual(@as(usize, 2), m.dns_servers.?.count());
    try testing.expectEqualSlices(u8, &.{ 8, 8, 8, 8 }, &m.dns_servers.?.at(0));
    try testing.expectEqualSlices(u8, &.{ 8, 8, 4, 4 }, &m.dns_servers.?.at(1));
    try testing.expectEqualStrings("lan", m.domain_name.?);

    // netaddr bridge.
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("192.168.0.10", netaddr.formatIp(m.yourIp(), &buf));
    try testing.expectEqualStrings("192.168.0.1", netaddr.formatIp(m.serverIdIp().?, &buf));
}

test "DHCP round-trip: builder reproduces the golden bytes" {
    var buf: [512]u8 = undefined;

    var d = try Builder.init(&buf, .{
        .op = .boot_request,
        .xid = 0x3903f326,
        .chaddr = Builder.chaddrFromMac(kat_mac),
    });
    try d.addMessageType(.discover);
    try d.addClientIdMac(kat_mac);
    try d.addRequestedIp(.{ 192, 168, 0, 10 });
    try d.addParamRequestList(&.{ 1, 3, 6, 15 });
    try d.addHostName("zig-host");
    try testing.expectEqualSlices(u8, &kat_discover, try d.finish(.{}));

    var a = try Builder.init(&buf, .{
        .op = .boot_reply,
        .xid = 0x3903f326,
        .yiaddr = .{ 192, 168, 0, 10 },
        .siaddr = .{ 192, 168, 0, 1 },
        .chaddr = Builder.chaddrFromMac(kat_mac),
    });
    try a.addMessageType(.ack);
    try a.addServerId(.{ 192, 168, 0, 1 });
    try a.addLeaseTime(86400);
    try a.addSubnetMask(.{ 255, 255, 255, 0 });
    try a.addRouters(&.{ 192, 168, 0, 1 });
    try a.addDnsServers(&.{ 8, 8, 8, 8, 8, 8, 4, 4 });
    try a.addDomainName("lan");
    const ack_bytes = try a.finish(.{});
    try testing.expectEqualSlices(u8, &kat_ack, ack_bytes);

    // build → parse agrees with the typed model.
    const m = try Message.parse(ack_bytes);
    try testing.expectEqual(MessageType.ack, m.message_type.?);
    try testing.expectEqual(@as(u32, 86400), m.lease_time_s.?);
}

test "DHCP: pad + unknown options pass through; BOOTP min padding" {
    var buf: [400]u8 = undefined;
    var b = try Builder.init(&buf, .{ .op = .boot_request, .xid = 1, .broadcast = true });
    try b.addMessageType(.request);
    try b.addOption(43, &.{ 0xde, 0xad }); // vendor-specific: not typed
    const bytes = try b.finish(.{ .pad_to = bootp_min_len });
    try testing.expectEqual(@as(usize, bootp_min_len), bytes.len);

    const m = try Message.parse(bytes);
    try testing.expect(m.broadcastFlag());
    try testing.expectEqual(MessageType.request, m.message_type.?);

    // The unknown option is reachable via the raw iterator.
    var it = m.optionIterator();
    var saw_vendor = false;
    while (try it.next()) |opt| {
        if (opt.code == 43) {
            try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, opt.data);
            saw_vendor = true;
        }
    }
    try testing.expect(saw_vendor);
}

test "DHCP: option overload surfaced" {
    var buf: [400]u8 = undefined;
    var b = try Builder.init(&buf, .{ .op = .boot_reply, .xid = 2 });
    try b.addMessageType(.offer);
    try b.addOption(@intFromEnum(OptionCode.option_overload), &.{2}); // sname holds options
    const bytes = try b.finish(.{});
    const m = try Message.parse(bytes);
    try testing.expectEqual(Overload.sname, m.overload.?);
    // sname region is all-zero here: iterating it yields nothing (all Pad).
    var it = m.snameOptionIterator();
    try testing.expectEqual(@as(?RawOption, null), try it.next());
}

test "DHCP malformed: typed errors, no panic" {
    // Too short.
    try testing.expectError(ParseError.Truncated, Message.parse(&.{}));
    try testing.expectError(ParseError.Truncated, Message.parse(kat_ack[0..header_len]));

    // Bad cookie.
    var bad_cookie = kat_ack;
    bad_cookie[header_len] = 0x64;
    try testing.expectError(ParseError.BadCookie, Message.parse(&bad_cookie));

    // Option length overruns the buffer (last option's len points past end).
    var overrun = kat_ack;
    overrun[kat_ack.len - 5] = 200; // domain-name length byte (15, LEN, "lan", 255)
    try testing.expectError(ParseError.TruncatedOption, Message.parse(&overrun));

    // Known option with an impossible length.
    var badlen = kat_ack;
    badlen[header_len + 4 + 1] = 2; // message-type option claims len 2
    // (now the stream is misaligned too, either error is acceptable — but it
    // must be a typed error, not a panic)
    try testing.expect(if (Message.parse(&badlen)) |_| false else |err| switch (err) {
        ParseError.BadOptionLength, ParseError.TruncatedOption => true,
        else => false,
    });

    // Option value cut short: host-name option (12, 8, "zig-host", 255)
    // claims 8 bytes but the buffer ends mid-value → TruncatedOption.
    const cut = kat_discover[0 .. kat_discover.len - 4];
    try testing.expectError(ParseError.TruncatedOption, Message.parse(cut));
}

test "DHCP garbage sweep: no panics on random input" {
    var prng = std.Random.DefaultPrng.init(0x44484350); // "DHCP"
    const random = prng.random();
    var buf: [512]u8 = undefined;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = random.uintAtMost(usize, buf.len);
        random.bytes(buf[0..len]);
        // Half the sweeps get a valid header+cookie so the option walker
        // itself is exercised, not just the cookie check.
        if (i % 2 == 0 and len >= header_len + 4) {
            buf[header_len..][0..4].* = magic_cookie;
        }
        _ = Message.parse(buf[0..len]) catch {};
    }
}

// ── fuzz: DHCP message parse off the wire, never panics ────────────────────
//
// `Message.parse` runs on a UDP datagram from any host on the broadcast
// domain (client or server, both unauthenticated at this layer). Stamp the
// magic cookie in about half the cases (mirroring the manual sweep above) so
// the option walker past the cookie gate is actually reached by `Smith`'s
// otherwise-uniform bytes, not just the 4-byte cookie check.

/// DHCP datagrams for `fuzzDhcpParse`, in the format `Smith.slice` reads (see
/// `testkit.fuzz`): a little-endian u32 length, then the datagram.
///
/// ⭐ Built at run time from this file's two golden messages rather than
/// quoted as hex — a DHCP datagram is 240 octets of header before the first
/// option, and a hex literal of that is not a thing anyone reviews.
///
/// ⛔ The old harness stamped the magic cookie into its buffer "in about half
/// the cases … so the option walker past the cookie gate is actually reached".
/// It never was, twice over: `smith.boolWeighted(1, 1)` came after the input
/// was spent, and the length was 0 anyway, so `len >= header_len + 4` was
/// false on every seed and the stamp never happened at all. A comment
/// describing a bias the code had never once taken.
const DhcpCorpus = struct {
    store: [16384]u8 = undefined,
    used: usize = 0,
    entries: [15][]const u8 = undefined,
    n: usize = 0,

    /// The fixed header plus the cookie, which is where every seed starts.
    const prefix_len = header_len + magic_cookie.len;

    fn push(self: *DhcpCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    /// The golden DISCOVER's header and cookie with `tail` as the options
    /// field — so every seed below differs only in the part being tested.
    fn withOptions(self: *DhcpCorpus, tail: []const u8) void {
        var frame: [prefix_len + 256]u8 = undefined;
        frame[0..prefix_len].* = kat_discover[0..prefix_len].*;
        @memcpy(frame[prefix_len..][0..tail.len], tail);
        self.push(frame[0 .. prefix_len + tail.len]);
    }

    fn build(self: *DhcpCorpus) []const []const u8 {
        // The two golden messages: a DISCOVER and the ACK for the same
        // transaction, which between them carry every typed option.
        self.push(&kat_discover);
        self.push(&kat_ack);

        // Header and cookie, no options at all. Legal, and every typed field
        // stays null — the shape a reach guard must not count as work.
        self.withOptions(&.{});
        // Pad octets, then End, then trailing bytes the walker must not read.
        self.withOptions(&.{ 0, 0, 0, 255, 0xde, 0xad });

        // ── the option walker's bounds ─────────────────────────────────────
        // A code with no length octet behind it (`pos + 2 > buf.len`).
        self.withOptions(&.{53});
        // A length octet declaring more than remains (`pos + 2 + len`).
        self.withOptions(&.{ 53, 255, 1 });

        // ── the per-option length checks ───────────────────────────────────
        // `one()`: message type with two octets.
        self.withOptions(&.{ 53, 2, 1, 0, 255 });
        // `four()`: requested IP with three.
        self.withOptions(&.{ 50, 3, 192, 168, 0, 255 });
        // `ip4List()`: a router list of six octets, and a DNS list of zero.
        self.withOptions(&.{ 3, 6, 192, 168, 0, 1, 10, 0, 255 });
        self.withOptions(&.{ 6, 0, 255 });
        // A router list of three addresses — the `Ip4List` walk with more
        // than one entry in it.
        self.withOptions(&.{ 3, 12, 192, 168, 0, 1, 192, 168, 0, 2, 10, 0, 0, 1, 255 });

        // ── option overloading (RFC 2132 §9.3) ─────────────────────────────
        // Overload = 3 (both), with real options planted in `sname` and
        // `file`. `snameOptionIterator`/`fileOptionIterator` are public API
        // and nothing but this seed drives them from the fuzz side.
        {
            var frame: [prefix_len + 8]u8 = undefined;
            frame[0..prefix_len].* = kat_discover[0..prefix_len].*;
            // sname is bytes 44..108, file is 108..236.
            @memcpy(frame[44..][0..8], &[_]u8{ 12, 3, 'a', 'b', 'c', 255, 0, 0 });
            @memcpy(frame[108..][0..8], &[_]u8{ 67, 3, 'p', 'x', 'e', 255, 0, 0 });
            @memcpy(frame[prefix_len..][0..8], &[_]u8{ 52, 1, 3, 53, 1, 1, 255, 0 });
            self.push(frame[0 .. prefix_len + 8]);
        }

        // ── the refusals ───────────────────────────────────────────────────
        // The cookie is wrong.
        {
            var frame: [prefix_len]u8 = kat_discover[0..prefix_len].*;
            frame[header_len] ^= 0xff;
            self.push(&frame);
        }
        // One octet short of header + cookie.
        self.push(kat_discover[0 .. prefix_len - 1]);
        // Nothing at all.
        self.push(&.{});

        return self.entries[0..self.n];
    }
};

/// What one datagram yielded. Shared by the fuzz target and its corpus guard
/// so the guard drives the SAME walk.
const DhcpTally = struct {
    parsed: usize = 0,
    typed: usize = 0,
    options: usize = 0,
    overloaded: usize = 0,
    ips: usize = 0,
};

fn walkDhcp(bytes: []const u8) DhcpTally {
    var t: DhcpTally = .{};
    const m = Message.parse(bytes) catch return t;
    t.parsed = 1;
    inline for (.{
        m.message_type != null,       m.requested_ip != null, m.server_id != null,
        m.lease_time_s != null,       m.subnet_mask != null,  m.routers != null,
        m.dns_servers != null,        m.domain_name != null,  m.host_name != null,
        m.param_request_list != null, m.client_id != null,    m.overload != null,
    }) |present| {
        if (present) t.typed += 1;
    }
    if (m.routers) |l| t.ips += l.count();
    if (m.dns_servers) |l| t.ips += l.count();
    var it = m.optionIterator();
    while (it.next() catch null) |_| t.options += 1;
    if (m.overload != null) {
        var sit = m.snameOptionIterator();
        while (sit.next() catch null) |_| t.overloaded += 1;
        var fit = m.fileOptionIterator();
        while (fit.next() catch null) |_| t.overloaded += 1;
    }
    std.mem.doNotOptimizeAway(m.broadcastFlag());
    std.mem.doNotOptimizeAway(m.clientMac());
    std.mem.doNotOptimizeAway(m.yourIp());
    std.mem.doNotOptimizeAway(m.serverIdIp());
    return t;
}

test "fuzz: DHCP Message.parse never panics on arbitrary bytes" {
    var corpus: DhcpCorpus = .{};
    try testing.fuzz({}, fuzzDhcpParse, .{ .corpus = corpus.build() });
}

fn fuzzDhcpParse(_: void, smith: *std.testing.Smith) !void {
    // 1024, not 512: `bootp_min_len` is 300 and a DHCP datagram carrying a
    // full parameter list runs well past that. A seed longer than the buffer
    // is not a big seed — `Smith.slice` reads it back as the EMPTY one.
    var buf: [1024]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `Message.parse` was handed an EMPTY
    // slice with the datagram sitting unread in `buf`.
    //
    // ⛔ Measured 2026-09-07 over the corpus above: **0 of 15 seeds non-empty,
    // 0 messages parsed and 0 options walked before; 14 of 15 non-empty (one
    // seed IS the empty datagram), 6 parsed, 15 options walked, 15 typed
    // fields decoded, 6 addresses listed and 2 overloaded options read,
    // after.** The empty slice is refused at `bytes.len < 240`, so the option
    // walker this target exists for had never run.
    const len: usize = smith.slice(&buf);
    std.mem.doNotOptimizeAway(walkDhcp(buf[0..len]));
}

test "corpus: every DHCP seed reaches the option walker, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets, through the SAME `walkDhcp`. `nonempty` is
    // the reach claim and the only check that catches a seed grown past the
    // harness's buffer, which `Smith.slice` reads back as the EMPTY one.
    //
    // ⛔ `parsed` cannot be the guard: a 240-octet header with the cookie and
    // no options at all is a legal DHCP datagram, so a message parses with
    // every typed field null and the walker never entering its loop — and one
    // of the seeds above is exactly that, on purpose. `options`, `typed`,
    // `ips` and `overloaded` count work the empty input cannot do.
    var corpus: DhcpCorpus = .{};
    const entries = corpus.build();
    var nonempty: usize = 0;
    var total: DhcpTally = .{};
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [1024]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const t = walkDhcp(buf[0..len]);
        total.parsed += t.parsed;
        total.typed += t.typed;
        total.options += t.options;
        total.overloaded += t.overloaded;
        total.ips += t.ips;
    }
    try testing.expectEqual(entries.len - 1, nonempty); // one seed IS the empty datagram
    try testing.expectEqual(@as(usize, 6), total.parsed);
    try testing.expectEqual(@as(usize, 15), total.typed);
    try testing.expectEqual(@as(usize, 15), total.options);
    try testing.expectEqual(@as(usize, 2), total.overloaded);
    try testing.expectEqual(@as(usize, 6), total.ips);
}

// ── 2026-10-04: options 42, 43, 60, 66, 67, 82, 119, 121 ──────────────────

/// A DHCPACK generated for this test and decoded by tcpdump 4.99.6
/// (`tcpdump -vvv -r`); the expected values are what tcpdump printed, quoted
/// next to each assertion. tcpdump has no decoder for option 119, so that one
/// is checked against RFC 3397's own example below instead.
const ack_with_options = blk: {
    const h =
        "020106001234abcd00000000000000000a01013200000000000000000011223344550000000000000000000000000000" ++
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363" ++
        "35010536040a0101012a080a0101050a0101062b060104616263643c084d53465420352e30420c746674702e6578616d" ++
        "706c654308626f6f742e65666952100106657468303a350206001122334455771803656e67076578616d706c6503636f" ++
        "6d0004636f7270c0047913080a0a01010116c0a8040a010102000a0101feff";
    @setEvalBranchQuota(10000);
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    break :blk out;
};

test "options 42/43/60/66/67/82/121 decode to what tcpdump printed" {
    const m = try Message.parse(&ack_with_options);
    // "NTP (42), length 8: 10.1.1.5,10.1.1.6"
    try testing.expectEqual(@as(usize, 2), m.ntp_servers.?.count());
    try testing.expectEqual([4]u8{ 10, 1, 1, 6 }, m.ntp_servers.?.at(1));
    // "Vendor-Option (43), length 6: 1.4.97.98.99.100"
    try testing.expectEqualSlices(u8, &.{ 1, 4, 97, 98, 99, 100 }, m.vendor_specific.?);
    // "Vendor-Class (60), length 8: \"MSFT 5.0\""
    try testing.expectEqualStrings("MSFT 5.0", m.vendor_class_id.?);
    // "TFTP (66), length 12: \"tftp.example\"", "BF (67), length 8: \"boot.efi\""
    try testing.expectEqualStrings("tftp.example", m.tftp_server_name.?);
    try testing.expectEqualStrings("boot.efi", m.bootfile_name.?);
    // "Circuit-ID SubOption 1, length 6: eth0:5", "Remote-ID SubOption 2, length 6"
    var ri = m.relayAgentInfo().?;
    const c = (try ri.next()).?;
    try testing.expectEqual(@as(u8, 1), c.code);
    try testing.expectEqualStrings("eth0:5", c.data);
    const r = (try ri.next()).?;
    try testing.expectEqual(@as(u8, 2), r.code);
    try testing.expectEqualSlices(u8, &.{ 0, 0x11, 0x22, 0x33, 0x44, 0x55 }, r.data);
    try testing.expect((try ri.next()) == null);
    // "(10.0.0.0/8:10.1.1.1),(192.168.4.0/22:10.1.1.2),(default:10.1.1.254)"
    const want = [_]ClasslessRoute{
        .{ .destination = .{ 10, 0, 0, 0 }, .prefix_len = 8, .router = .{ 10, 1, 1, 1 } },
        .{ .destination = .{ 192, 168, 4, 0 }, .prefix_len = 22, .router = .{ 10, 1, 1, 2 } },
        .{ .destination = .{ 0, 0, 0, 0 }, .prefix_len = 0, .router = .{ 10, 1, 1, 254 } },
    };
    var ci = m.classlessRoutes().?;
    for (want) |w| try testing.expectEqualDeep(w, (try ci.next()).?);
    try testing.expect((try ci.next()) == null);
    // Option 119 is present; its names: the second one is a label plus a
    // pointer to offset 4 ("example.com" inside the first name).
    var di = m.domainSearch().?;
    var name: [DomainSearchIterator.max_name_len]u8 = undefined;
    try testing.expectEqualStrings("eng.example.com", (try di.next(&name)).?);
    try testing.expectEqualStrings("corp.example.com", (try di.next(&name)).?);
    try testing.expect((try di.next(&name)) == null);
}

test "option 119: RFC 3397 section 2's example decodes to its two names" {
    // RFC 3397 §2: "eng.apple.com." and "marketing.apple.com.", the second
    // compressed to "marketing" + a pointer to offset 4.
    const rfc = [_]u8{ 3, 'e', 'n', 'g', 5, 'a', 'p', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 9, 'm', 'a', 'r', 'k', 'e', 't', 'i', 'n', 'g', 0xc0, 4 };
    var it: DomainSearchIterator = .{ .data = &rfc };
    var name: [DomainSearchIterator.max_name_len]u8 = undefined;
    try testing.expectEqualStrings("eng.apple.com", (try it.next(&name)).?);
    try testing.expectEqualStrings("marketing.apple.com", (try it.next(&name)).?);
    try testing.expect((try it.next(&name)) == null);
}

test "option 119: loops, forward pointers, overruns and reserved label types are refused" {
    var name: [DomainSearchIterator.max_name_len]u8 = undefined;
    const bad = [_][]const u8{
        &.{ 0xc0, 0 }, // points at itself
        &.{ 1, 'a', 0xc0, 4, 0 }, // points forward
        &.{ 3, 'a', 'b' }, // label runs past the data
        &.{ 1, 'a' }, // no terminating zero
        &.{0x40}, // reserved 01 label type
        &([_]u8{0x40} ++ [_]u8{'a'} ** 64 ++ [_]u8{0}), // 01 type with 64 bytes behind it: still reserved, not a label
        &([_]u8{0x80} ++ [_]u8{'a'} ** 128 ++ [_]u8{0}), // 10 type likewise
        &.{0xc0}, // pointer cut in half
    };
    for (bad) |b| {
        var it: DomainSearchIterator = .{ .data = b };
        try testing.expectError(error.BadOptionLength, it.next(&name));
    }
    // A name longer than 254 characters (five 63-byte labels) is refused,
    // one of 254 exactly (63+1+63+1+63+1+62) is not.
    var long: [5 * 64 + 1]u8 = undefined;
    for (0..5) |i| {
        long[i * 64] = 63;
        @memset(long[i * 64 + 1 ..][0..63], 'x');
    }
    long[5 * 64] = 0;
    var li: DomainSearchIterator = .{ .data = &long };
    try testing.expectError(error.BadOptionLength, li.next(&name));
    var ok: [64 * 3 + 63 + 1]u8 = undefined;
    for (0..3) |i| {
        ok[i * 64] = 63;
        @memset(ok[i * 64 + 1 ..][0..63], 'y');
    }
    ok[192] = 62;
    @memset(ok[193..255], 'z');
    ok[255] = 0;
    var oi: DomainSearchIterator = .{ .data = &ok };
    try testing.expectEqual(@as(usize, 254), (try oi.next(&name)).?.len);
}

test "options 82 and 121 with broken framing: the message parses, the iterator refuses" {
    var buf: [400]u8 = undefined;
    for ([_]struct { u8, []const u8 }{
        .{ 82, &.{ 1, 5, 'a' } }, // sub-option longer than the option
        .{ 82, &.{1} }, // half a sub-option header
        .{ 121, &.{ 33, 10, 0, 0, 0, 10, 1, 1, 1 } }, // width 33
        .{ 121, &.{ 33, 10, 0, 0, 0, 0, 10, 1, 1, 1 } }, // width 33 with 5 + 4 bytes behind it (RFC 3442: 0-32)
        .{ 121, &.{ 24, 10, 0, 0, 10, 1, 1 } }, // router cut short
    }) |c| {
        var b = try Builder.init(&buf, .{ .op = .boot_reply, .xid = 1 });
        try b.addServerId(.{ 10, 9, 9, 9 });
        try b.addOption(c[0], c[1]);
        const bytes = try b.finish(.{});
        // The rest of the message stays readable (a rogue-server check
        // needs the server id even when option 121 is garbage)…
        const m = try Message.parse(bytes);
        try testing.expectEqual([4]u8{ 10, 9, 9, 9 }, m.server_id.?);
        // …and the broken option reports itself when walked.
        if (c[0] == 82) {
            var it = m.relayAgentInfo().?;
            try testing.expectError(error.BadOptionLength, it.next());
        } else {
            var it = m.classlessRoutes().?;
            try testing.expectError(error.BadOptionLength, it.next());
        }
    }
}

test "Builder: the new options reproduce the tcpdump-checked bytes" {
    var buf: [400]u8 = undefined;
    var b = try Builder.init(&buf, .{ .op = .boot_reply, .xid = 0x1234abcd });
    try b.addMessageType(.ack);
    try b.addServerId(.{ 10, 1, 1, 1 });
    try b.addNtpServers(&.{ 10, 1, 1, 5, 10, 1, 1, 6 });
    try b.addOption(@intFromEnum(OptionCode.vendor_specific), &.{ 1, 4, 'a', 'b', 'c', 'd' });
    try b.addVendorClassId("MSFT 5.0");
    try b.addTftpServerName("tftp.example");
    try b.addBootfileName("boot.efi");
    try b.addRelayAgentInfo("eth0:5", &.{ 0, 0x11, 0x22, 0x33, 0x44, 0x55 });
    const built = try b.finish(.{});
    // The options region of the captured message up to (excluding) option 119.
    const opts = ack_with_options[header_len + 4 ..];
    const end119 = std.mem.indexOf(u8, opts, &.{ 119, 24 }).?;
    try testing.expectEqualSlices(u8, opts[0..end119], built[header_len + 4 ..][0..end119]);

    var b2 = try Builder.init(&buf, .{ .op = .boot_reply, .xid = 1 });
    // Host bits past /22 are not sent: 192.168.7.9/22 encodes as 192.168.4.
    try b2.addClasslessRoutes(&.{
        .{ .destination = .{ 10, 0, 0, 0 }, .prefix_len = 8, .router = .{ 10, 1, 1, 1 } },
        .{ .destination = .{ 192, 168, 4, 0 }, .prefix_len = 22, .router = .{ 10, 1, 1, 2 } },
        .{ .destination = .{ 0, 0, 0, 0 }, .prefix_len = 0, .router = .{ 10, 1, 1, 254 } },
    });
    try b2.addDomainSearch(&.{ "eng.example.com", "corp.example.com" });
    const m = try Message.parse(try b2.finish(.{}));
    const at121 = std.mem.indexOf(u8, opts, &.{ 121, 19 }).?;
    try testing.expectEqualSlices(u8, opts[at121 + 2 ..][0..19], m.classless_static_routes.?);
    var di = m.domainSearch().?;
    var name: [DomainSearchIterator.max_name_len]u8 = undefined;
    try testing.expectEqualStrings("eng.example.com", (try di.next(&name)).?);
    try testing.expectEqualStrings("corp.example.com", (try di.next(&name)).?);
    try testing.expectError(error.OptionTooLong, b2.addDomainSearch(&.{"a..b"}));
}

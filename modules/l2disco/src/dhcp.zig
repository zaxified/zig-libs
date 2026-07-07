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
    requested_ip = 50,
    lease_time = 51,
    option_overload = 52,
    message_type = 53,
    server_id = 54,
    param_request_list = 55,
    client_id = 61,
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
                else => {}, // unknown/untyped: reachable via optionIterator()
            }
        }
        return m;
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

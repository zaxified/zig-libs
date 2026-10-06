// SPDX-License-Identifier: MIT

//! **External anchor: what tcpdump's dissectors read in every TLV shape.**
//!
//! The vendored captures in `capture_test.zig` are real traffic, but reach
//! only the TLVs their senders happened to send. `testdata/tcpdump_facts.zig`
//! (made by `tools/tcpdump_oracle.py`) holds LLDP and CDP frames built from the
//! standards to reach every shape this module decodes -- every chassis and
//! port subtype family, TTL 0, IPv4 and IPv6 management addresses, 802.1
//! PVID / PPVID / VLAN name, 802.3 MAC/PHY / power via MDI / max frame size,
//! LLDP-MED capabilities / network policy / location / extended power / all
//! seven inventory fields, a full CDPv2 frame and an odd-length CDPv1 one,
//! DHCP offer / request / renewing ACK / inform / relayed discover with
//! options 82, 119 and 121 -- with the FACTS tcpdump printed for each, parsed
//! out of its text (option 119, which tcpdump leaves undecoded, read by
//! dnspython instead). Here the
//! same facts are rendered from this module's decoders and must be the same
//! list.

const std = @import("std");
const testing = std.testing;
const netaddr = @import("netaddr");
const lldp = @import("lldp.zig");
const cdp = @import("cdp.zig");
const dhcp = @import("dhcp.zig");
const rec = @import("testdata/tcpdump_facts.zig");

const Facts = std.ArrayList([]const u8);

fn add(a: std.mem.Allocator, out: *Facts, comptime fmt: []const u8, args: anytype) !void {
    try out.append(a, try std.fmt.allocPrint(a, fmt, args));
}

fn ipText(a: std.mem.Allocator, ip: netaddr.Ip) ![]const u8 {
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    return a.dupe(u8, netaddr.formatIp(ip, &buf));
}

fn macText(a: std.mem.Allocator, m: [6]u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{ m[0], m[1], m[2], m[3], m[4], m[5] });
}

/// How tcpdump prints an ID: a MAC as colon hex, a network address as the
/// address, anything else as its text.
fn idText(a: std.mem.Allocator, id: anytype) ![]const u8 {
    if (id.mac()) |m| return macText(a, m.octets);
    if (id.ip()) |ip| return ipText(a, ip);
    return id.text() orelse error.TestUnexpectedResult;
}

fn lldpFacts(a: std.mem.Allocator, frame: []const u8) !Facts {
    var out: Facts = .empty;
    const du = try lldp.Lldpdu.parse(frame[14..], .{});
    try add(a, &out, "chassis={d}:{s}", .{ @intFromEnum(du.chassis_id.subtype), try idText(a, du.chassis_id) });
    try add(a, &out, "port={d}:{s}", .{ @intFromEnum(du.port_id.subtype), try idText(a, du.port_id) });
    try add(a, &out, "ttl={d}", .{du.ttl_s});
    if (du.port_description) |s| try add(a, &out, "port_desc={s}", .{s});
    if (du.system_name) |s| try add(a, &out, "sys_name={s}", .{s});
    if (du.system_description) |s| try add(a, &out, "sys_desc={s}", .{s});
    if (du.capabilities) |c| try add(a, &out, "caps=0x{x:0>4}/0x{x:0>4}", .{ c.capabilities.toWire(), c.enabled.toWire() });
    var mi = du.managementAddressIterator();
    while (try mi.next()) |m| {
        try add(a, &out, "mgmt={s}/{d}/{d}", .{ try ipText(a, m.ip().?), @intFromEnum(m.interface_subtype), m.interface_number });
    }
    var oi = du.orgIterator();
    while (try oi.next()) |o| switch (o.decode() orelse return error.TestUnexpectedResult) {
        .port_vlan_id => |v| try add(a, &out, "pvid={d}", .{v}),
        .port_protocol_vlan => |v| try add(a, &out, "ppvid={d}/0x{x:0>2}", .{ v.ppvid, v.flags }),
        .vlan_name => |v| try add(a, &out, "vlan_name={d}:{s}", .{ v.vlan_id, v.name }),
        .mac_phy => |v| try add(a, &out, "mac_phy=0x{x:0>2}/0x{x:0>4}/{d}", .{ v.autoneg, v.pmd_advertised, v.operational_mau }),
        .max_frame_size => |v| try add(a, &out, "max_frame={d}", .{v}),
        .power_via_mdi => |v| try add(a, &out, "power=0x{x:0>2}/{d}/{d}", .{ v.mdi_support, v.pse_power_pair, v.power_class }),
        .med_capabilities => |v| try add(a, &out, "med_caps=0x{x:0>4}/{d}", .{ v.capabilities, @intFromEnum(v.device_type) }),
        .med_network_policy => |v| try add(a, &out, "policy={d}/{d}/{d}/{d}/{d}/{d}", .{ v.application, @intFromBool(v.unknown_policy), @intFromBool(v.tagged), v.vlan_id, v.l2_priority, v.dscp }),
        .med_location => |v| try add(a, &out, "location={d}", .{v.format}),
        .med_ext_power => |v| try add(a, &out, "ext_power={d}/{d}/{d}/{d}", .{ v.power_type, v.power_source, v.priority, v.power_dw }),
        .med_inventory => |v| try add(a, &out, "inventory={d}:{s}", .{ @intFromEnum(v.field), v.text }),
    };
    return out;
}

fn cdpFacts(a: std.mem.Allocator, frame: []const u8) !Facts {
    var out: Facts = .empty;
    // Ethernet (14) + LLC/SNAP (8), then the CDP PDU. tcpdump does not
    // verify the CDP checksum ("unverified"), so this oracle does not either.
    const f = try cdp.Frame.parse(frame[22..], .{ .verify_checksum = false });
    try add(a, &out, "cdp_version={d}", .{f.version});
    try add(a, &out, "cdp_ttl={d}", .{f.ttl_s});
    if (f.device_id) |s| try add(a, &out, "device_id={s}", .{s});
    if (try f.addressIterator()) |it_| {
        var it = it_;
        while (try it.next()) |ad| try add(a, &out, "address={s}", .{try ipText(a, ad.ip().?)});
    }
    if (f.port_id) |s| try add(a, &out, "port_id={s}", .{s});
    if (f.capabilities) |c| try add(a, &out, "cdp_caps=0x{x:0>8}", .{c.toWire()});
    if (f.software_version) |s| try add(a, &out, "software={s}", .{s});
    if (f.platform) |s| try add(a, &out, "platform={s}", .{s});
    if (f.vtp_domain) |s| try add(a, &out, "vtp={s}", .{s});
    if (f.native_vlan) |v| try add(a, &out, "native_vlan={d}", .{v});
    if (f.duplex) |d| try add(a, &out, "duplex={s}", .{@tagName(d)});
    return out;
}

fn dotted(a: std.mem.Allocator, q: [4]u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{d}.{d}.{d}.{d}", .{ q[0], q[1], q[2], q[3] });
}

fn ipList(a: std.mem.Allocator, l: dhcp.Ip4List) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    for (0..l.count()) |i| {
        if (i > 0) try s.append(a, ',');
        try s.appendSlice(a, try dotted(a, l.at(i)));
    }
    return s.items;
}

fn dhcpFacts(a: std.mem.Allocator, frame: []const u8) !Facts {
    var out: Facts = .empty;
    // Ethernet (14) + IPv4 (20) + UDP (8), then BOOTP.
    const m = try dhcp.Message.parse(frame[42..]);
    try add(a, &out, "dhcp_op={d}", .{@intFromEnum(m.op)});
    try add(a, &out, "xid=0x{x:0>8}", .{m.xid});
    if (m.secs != 0) try add(a, &out, "secs={d}", .{m.secs}); // tcpdump prints secs only when set
    try add(a, &out, "flags=0x{x:0>4}", .{m.flags});
    // ...and the addresses only when set.
    const zero: [4]u8 = @splat(0);
    if (!std.mem.eql(u8, &m.ciaddr, &zero)) try add(a, &out, "ciaddr={s}", .{try dotted(a, m.ciaddr)});
    if (!std.mem.eql(u8, &m.yiaddr, &zero)) try add(a, &out, "yiaddr={s}", .{try dotted(a, m.yiaddr)});
    if (!std.mem.eql(u8, &m.siaddr, &zero)) try add(a, &out, "siaddr={s}", .{try dotted(a, m.siaddr)});
    if (!std.mem.eql(u8, &m.giaddr, &zero)) try add(a, &out, "giaddr={s}", .{try dotted(a, m.giaddr)});
    try add(a, &out, "chaddr={s}", .{try macText(a, m.clientMac().?.octets)});
    if (m.message_type) |t| try add(a, &out, "msg_type={d}", .{@intFromEnum(t)});
    if (m.server_id) |q| try add(a, &out, "server_id={s}", .{try dotted(a, q)});
    if (m.requested_ip) |q| try add(a, &out, "requested_ip={s}", .{try dotted(a, q)});
    if (m.lease_time_s) |v| try add(a, &out, "lease={d}", .{v});
    if (m.subnet_mask) |q| try add(a, &out, "subnet={s}", .{try dotted(a, q)});
    if (m.routers) |l| try add(a, &out, "routers={s}", .{try ipList(a, l)});
    if (m.dns_servers) |l| try add(a, &out, "dns={s}", .{try ipList(a, l)});
    if (m.ntp_servers) |l| try add(a, &out, "ntp={s}", .{try ipList(a, l)});
    if (m.domain_name) |s| try add(a, &out, "domain={s}", .{s});
    if (m.host_name) |s| try add(a, &out, "hostname={s}", .{s});
    if (m.vendor_class_id) |s| try add(a, &out, "vendor_class={s}", .{s});
    if (m.tftp_server_name) |s| try add(a, &out, "tftp={s}", .{s});
    if (m.bootfile_name) |s| try add(a, &out, "bootfile={s}", .{s});
    if (m.client_id) |c| {
        if (c.len == 7 and c[0] == 1) try add(a, &out, "client_id=1:{s}", .{try macText(a, c[1..7].*)});
    }
    if (m.param_request_list) |l| {
        var s: std.ArrayList(u8) = .empty;
        for (l, 0..) |code, i| {
            if (i > 0) try s.append(a, ',');
            try s.print(a, "{d}", .{code});
        }
        try add(a, &out, "prl={s}", .{s.items});
    }
    if (m.relayAgentInfo()) |it_| {
        var it = it_;
        while (try it.next()) |sub| try add(a, &out, "relay={d}:{s}", .{ sub.code, sub.data });
    }
    if (m.classlessRoutes()) |it_| {
        var it = it_;
        while (try it.next()) |r| try add(a, &out, "route={s}/{d}:{s}", .{ try dotted(a, r.destination), r.prefix_len, try dotted(a, r.router) });
    }
    if (m.domainSearch()) |it_| {
        var it = it_;
        var buf: [dhcp.DomainSearchIterator.max_name_len]u8 = undefined;
        // dnspython writes names absolute ("example.com."); ours has no dot.
        while (try it.next(&buf)) |name| try add(a, &out, "search={s}.", .{name});
    }
    return out;
}

fn lessThan(_: void, x: []const u8, y: []const u8) bool {
    return std.mem.order(u8, x, y) == .lt;
}

test "tcpdump oracle: every TLV shape decodes to what tcpdump read" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var total: usize = 0;
    for (rec.frames) |fr| {
        const bytes = try a.alloc(u8, fr.bytes.len / 2);
        _ = try std.fmt.hexToBytes(bytes, fr.bytes);
        const ours = if (std.mem.startsWith(u8, fr.name, "cdp"))
            try cdpFacts(a, bytes)
        else if (std.mem.startsWith(u8, fr.name, "dhcp"))
            try dhcpFacts(a, bytes)
        else
            try lldpFacts(a, bytes);
        const want = try a.dupe([]const u8, fr.facts);
        std.mem.sort([]const u8, ours.items, {}, lessThan);
        std.mem.sort([]const u8, want, {}, lessThan);
        testing.expectEqual(want.len, ours.items.len) catch |e| {
            std.debug.print("{s}: tcpdump {d} facts, ours {d}\n", .{ fr.name, want.len, ours.items.len });
            for (ours.items) |x| std.debug.print("  ours: {s}\n", .{x});
            return e;
        };
        for (want, ours.items) |w, o| testing.expectEqualStrings(w, o) catch |e| {
            std.debug.print("{s}\n", .{fr.name});
            return e;
        };
        total += want.len;
    }
    try testing.expectEqual(@as(usize, 14), rec.frames.len);
    try testing.expectEqual(@as(usize, 128), total); // pinned: a regenerated table that lost facts shows here
}

fn frameBytes(a: std.mem.Allocator, name: []const u8) ![]u8 {
    for (rec.frames) |fr| if (std.mem.eql(u8, fr.name, name)) {
        const b = try a.alloc(u8, fr.bytes.len / 2);
        _ = try std.fmt.hexToBytes(b, fr.bytes);
        return b;
    };
    return error.TestUnexpectedResult;
}

test "tcpdump oracle: the Builders emit the very frames tcpdump read" {
    // The frames above were built by the generator, not by this module; here
    // the module's own Builders must reproduce them byte for byte, so the
    // encode direction is anchored to tcpdump's reading too.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [1500]u8 = undefined;
    const mac: @import("mac.zig").Mac = .{ .octets = .{ 2, 0, 0, 0, 0, 1 } };

    {
        var b = lldp.Builder.init(&buf);
        try b.addChassisIdMac(mac);
        try b.addPortIdIfName("eth0");
        try b.addTtl(120);
        try b.addPortDescription("uplink to core");
        try b.addSystemName("sw1.example");
        try b.addSystemDescription("Linux 6.8 x86_64");
        try b.addSystemCapabilities(.fromWire(0x0014), .fromWire(0x0004));
        try b.addManagementAddress(.{ .ip = .{ .v4 = .{ 10, 0, 0, 1 } }, .interface_subtype = .if_index, .interface_number = 3 });
        try b.addManagementAddress(.{ .ip = .{ .v6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }, .interface_subtype = .system_port, .interface_number = 7 });
        try b.addPortVlanId(10);
        try b.addOrgSpecific(.{ 0x00, 0x80, 0xc2 }, 2, &.{ 0x06, 0x00, 20 });
        try b.addOrgSpecific(.{ 0x00, 0x80, 0xc2 }, 3, &.{ 0, 30, 4, 'm', 'g', 'm', 't' });
        try b.addOrgSpecific(.{ 0x00, 0x12, 0x0f }, 1, &.{ 0x03, 0x6c, 0x00, 0x00, 0x10 });
        try b.addMaxFrameSize(9216);
        try testing.expectEqualSlices(u8, (try frameBytes(a, "lldp_switch_port"))[14..], try b.finish());
    }
    {
        var b = lldp.Builder.init(&buf);
        try b.addChassisIdMac(mac);
        try b.addPortId(.mac_address, &mac.octets);
        try b.addTtl(180);
        try b.addMedCapabilities(0x0033, @enumFromInt(3));
        try b.addMedNetworkPolicy(.{ .application = 1, .unknown_policy = false, .tagged = true, .vlan_id = 100, .l2_priority = 5, .dscp = 46 });
        try b.addMedNetworkPolicy(.{ .application = 2, .unknown_policy = true, .tagged = false, .vlan_id = 0, .l2_priority = 0, .dscp = 0 });
        try b.addOrgSpecific(.{ 0x00, 0x12, 0xbb }, 4, &.{ 0x52, 0x00, 65 });
        for ([_][]const u8{ "1.2", "fw-3.4", "sw-5.6", "SN0042", "Acme", "Phone 9", "asset-7" }, 5..) |text, sub| {
            try b.addOrgSpecific(.{ 0x00, 0x12, 0xbb }, @intCast(sub), text);
        }
        try testing.expectEqualSlices(u8, (try frameBytes(a, "lldp_med_phone"))[14..], try b.finish());
    }
    {
        var b = try cdp.Builder.init(&buf, .{ .version = 2, .ttl_s = 180 });
        try b.addDeviceId("core-sw1");
        try b.addAddressesIpv4(&.{ .{ 192, 0, 2, 1 }, .{ 198, 51, 100, 7 } });
        try b.addPortId("GigabitEthernet0/1");
        try b.addCapabilities(.fromWire(0x29));
        try b.addSoftwareVersion("Cisco IOS Software, Version 15.2(4)E");
        try b.addPlatform("cisco WS-C2960X-48TS-L");
        try b.addVtpDomain("lab");
        try b.addNativeVlan(42);
        try b.addDuplex(.full);
        try testing.expectEqualSlices(u8, (try frameBytes(a, "cdp_v2_full"))[22..], b.finish());
    }
    // DHCP: Ethernet + IPv4 + UDP (42 bytes), then BOOTP. `dhcp_offer`'s
    // option 119 uses a compression pointer, which this Builder does not
    // emit, so the uncompressed `dhcp_inform_search` stands in for it.
    var chaddr: [16]u8 = @splat(0);
    chaddr[0..6].* = mac.octets;
    {
        var b = try dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 0x0BADF00D, .chaddr = chaddr });
        try b.addMessageType(.request);
        try b.addRequestedIp(.{ 192, 168, 1, 10 });
        try b.addServerId(.{ 192, 168, 1, 1 });
        try b.addHostName("laptop");
        try b.addClientIdMac(mac);
        try b.addParamRequestList(&.{ 1, 3, 6, 15, 119, 121 });
        try b.addVendorClassId("MSFT 5.0");
        try testing.expectEqualSlices(u8, (try frameBytes(a, "dhcp_request"))[42..], try b.finish(.{}));
    }
    {
        var b = try dhcp.Builder.init(&buf, .{ .op = .boot_reply, .xid = 0x00C0FFEE, .ciaddr = .{ 192, 168, 1, 10 }, .yiaddr = .{ 192, 168, 1, 10 }, .chaddr = chaddr });
        try b.addMessageType(.ack);
        try b.addServerId(.{ 192, 168, 1, 1 });
        try b.addLeaseTime(86400);
        try b.addSubnetMask(.{ 255, 255, 0, 0 });
        try b.addRouters(&.{ 192, 168, 1, 1, 192, 168, 1, 254 });
        try b.addDnsServers(&.{ 9, 9, 9, 9, 1, 0, 0, 1, 8, 8, 4, 4 });
        try testing.expectEqualSlices(u8, (try frameBytes(a, "dhcp_ack_renew"))[42..], try b.finish(.{}));
    }
    {
        var b = try dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 0x0D15EA5E, .ciaddr = .{ 192, 168, 1, 10 }, .chaddr = chaddr });
        try b.addMessageType(.inform);
        try b.addParamRequestList(&.{ 6, 15, 119 });
        try b.addDomainSearch(&.{ "example.com", "corp.example.com" });
        try testing.expectEqualSlices(u8, (try frameBytes(a, "dhcp_inform_search"))[42..], try b.finish(.{}));
    }
    {
        var b = try dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 0x55AA55AA, .hops = 1, .giaddr = .{ 10, 0, 0, 1 }, .chaddr = chaddr });
        try b.addMessageType(.discover);
        try b.addRelayAgentInfo("ge-0/0/1.100", "sw-access-3");
        try testing.expectEqualSlices(u8, (try frameBytes(a, "dhcp_relayed_discover"))[42..], try b.finish(.{}));
    }
    {
        var b = try dhcp.Builder.init(&buf, .{ .op = .boot_reply, .xid = 0x1234ABCD, .secs = 3, .broadcast = true, .yiaddr = .{ 192, 168, 1, 10 }, .siaddr = .{ 192, 168, 1, 1 }, .giaddr = .{ 10, 0, 0, 1 }, .chaddr = chaddr });
        try b.addMessageType(.offer);
        try b.addServerId(.{ 192, 168, 1, 1 });
        try b.addLeaseTime(3600);
        try b.addSubnetMask(.{ 255, 255, 255, 0 });
        try b.addRouters(&.{ 192, 168, 1, 1 });
        try b.addDnsServers(&.{ 1, 1, 1, 1, 8, 8, 8, 8 });
        try b.addDomainName("example.com");
        try b.addHostName("host1");
        try b.addNtpServers(&.{ 192, 168, 1, 5 });
        try b.addTftpServerName("tftp.example");
        try b.addBootfileName("pxelinux.0");
        try b.addClasslessRoutes(&.{
            .{ .destination = .{ 10, 0, 0, 0 }, .prefix_len = 8, .router = .{ 192, 168, 1, 1 } },
            .{ .destination = .{ 172, 16, 5, 0 }, .prefix_len = 24, .router = .{ 192, 168, 1, 2 } },
            .{ .destination = .{ 0, 0, 0, 0 }, .prefix_len = 0, .router = .{ 192, 168, 1, 1 } },
        });
        const offer = (try frameBytes(a, "dhcp_offer"))[42..];
        const built = try b.finish(.{});
        // Everything up to option 119, which the frame then carries compressed.
        try testing.expectEqualSlices(u8, offer[0 .. built.len - 1], built[0 .. built.len - 1]);
        try testing.expectEqual(@as(u8, 119), offer[built.len - 1]);
    }
}

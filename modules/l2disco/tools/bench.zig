// SPDX-License-Identifier: MIT

//! Comparative benchmark: `l2disco`'s decoders against
//! `github.com/gopacket/gopacket` v1.7.2 `layers` (BSD-3-Clause; the
//! reference, `tools/go_bench`), the program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-l2disco` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! gopacket v1.7.2 in the module cache (`GOPROXY=off`, go.sum committed).
//! Run from the repository root. CPU-bound decode loops only: no socket.
//!
//! One op = 64 inputs of a fixed seed, written by this driver into
//! `.zig-cache/bench-l2disco/` (the Go side reads the same files). Every input
//! is the protocol payload only (LLDPDU, CDP PDU from the version byte, ARP
//! packet, the DHCP UDP payload, the ICMPv6 message):
//!   lldp   chassis MAC, port interface name, TTL, port/system description, system
//!          name, capabilities, 2-5 of {802.1 PVID, 802.3 max frame, MED
//!          capabilities, MED network policy}. Ours `Lldpdu.parse` + every org
//!          TLV through `OrgSpecific.decode`; Go `gopacket.NewPacket(NoCopy)`
//!          (the only public LLDP path: the LLDP layer and its Info layer, strings
//!          built) + `Decode8021`, `Decode8023`, `DecodeMedia`.
//!   cdp    device id, 1-3 IPv4 addresses, port id, capabilities, software, platform,
//!          VTP domain, native VLAN, duplex. Ours `Frame.parse` with
//!          `verify_checksum = false` (gopacket never verifies it) + the address
//!          walk; Go `NewPacket(NoCopy)` (CDP and its Info layer).
//!   arp    Ethernet/IPv4 requests and replies. Ours the generic `Packet.parse`;
//!          Go `ARP.DecodeFromBytes` on a reused layer.
//!   dhcp4  OFFER/ACK with message type, server id, lease, subnet, routers, DNS,
//!          domain, host name. Ours `Message.parse` (typed fields in one pass); Go
//!          `DHCPv4.DecodeFromBytes` (options as a list) and a scan for the four
//!          options the sum reads.
//!   dhcp6  Reply with Client/Server ID, an IA_NA with an address, an IA_PD with a
//!          prefix, DNS, domain list, preference. Ours `Message.parse` (the option
//!          framing is checked) + a raw option walk; Go `DHCPv6.DecodeFromBytes`
//!          (option list) + the same walk. Neither side decodes the IAs.
//!   nd_ra  Router Advertisement with source link-layer address, MTU and 1-2 prefix
//!          information options. Ours `nd.Message.parse` + `options()` walk; Go
//!          `ICMPv6RouterAdvertisement.DecodeFromBytes` on the body (its 4-byte
//!          ICMPv6 header is peeled by the caller on that side).
//! HONESTY NOTE on lldp (0.05x) and cdp (0.02x): these are NOT parser-for-parser.
//! gopacket builds a packet object, copies every TLV value into strings and
//! slices and decodes a second (Info) layer per call -- the GC allocates for each
//! frame -- while ours slices the input and allocates nothing. The honest reading
//! is "the library path a Go user takes against the allocation-free path a Zig
//! user takes", not a ratio of two equal parsers. The reused-layer rows (arp,
//! dhcp4, dhcp6, nd_ra) are the closer pairs.
//!
//! Rows dhcp4 and dhcp6 also run github.com/insomniacslk/dhcp (the `alt`, BSD-3,
//! typed options: its DHCPv4 option map and DHCPv6 typed options are built per
//! call) to fill the `fastest` ratio. The dhcp6 sum is message type, transaction id and,
//! per option, its code plus one: lengths are left out because that library decodes
//! typed options and could only re-encode them to know a length. It decodes the IAs and
//! DUIDs; ours does not, which favours ours.
//!
//! Both sides sum the same decoded facts (see the two `sum` blocks); the counts
//! must agree or the run fails. Ratios are ours/Go by wall time; the verdict is
//! the WORST ratio. Arguments filter workloads.
//!
//! What gopacket does that ours does not (so the rows are fair, not equal): its
//! layers own copies of strings and slices, built per call (GC); ours slices the
//! input and allocates nothing. What ours does that gopacket does not: it validates
//! mandatory-TLV order, LLDP/CDP value lengths and DHCPv6 option framing strictly.

const std = @import("std");
const bench = @import("testkit").bench;
const l2 = @import("l2disco");

const ref_short = "Go";
const ref_card = "Go gopacket v1.7.2";
const bench_name = "bench-l2disco";
const work_dir = ".zig-cache/bench-l2disco";
const go_dir = "modules/l2disco/tools/go_bench";
const N = 64;

const Op = enum { lldp, cdp, arp, dhcp4, dhcp6, nd_ra };

const Ctx = struct {
    op: Op = .lldp,
    msgs: [6][N][]const u8 = undefined, // indexed by Op
};

// ── the timed ops ────────────────────────────────────────────────────────────

fn lenOf(s: ?[]const u8) usize {
    return if (s) |x| x.len else 0;
}

fn sumLldp(m: []const u8) u64 {
    const du = l2.lldp.Lldpdu.parse(m, .{}) catch @panic("bench-l2disco: lldp");
    var t: u64 = @backingInt(du.chassis_id.subtype);
    t += du.chassis_id.value.len + @backingInt(du.port_id.subtype) + du.port_id.value.len + du.ttl_s;
    t += lenOf(du.system_name) + lenOf(du.system_description) + lenOf(du.port_description);
    if (du.capabilities) |c| t += @as(u64, c.capabilities.toWire()) + c.enabled.toWire();
    var it = du.orgIterator();
    var pvid: u64 = 0;
    var mtu: u64 = 0;
    var vlan: u64 = 0;
    while (it.next() catch @panic("bench-l2disco: lldp org")) |o| {
        t += 1;
        if (o.decode()) |v| switch (v) {
            .port_vlan_id => |x| pvid = x,
            .max_frame_size => |x| mtu = x,
            .med_network_policy => |x| vlan = x.vlan_id,
            else => {},
        };
    }
    return t + pvid + mtu + vlan;
}

fn sumCdp(m: []const u8) u64 {
    const f = l2.cdp.Frame.parse(m, .{ .verify_checksum = false }) catch @panic("bench-l2disco: cdp");
    var t: u64 = @as(u64, f.version) + f.ttl_s + lenOf(f.device_id) + lenOf(f.port_id);
    t += lenOf(f.platform) + lenOf(f.software_version) + (f.native_vlan orelse 0);
    if (f.addressIterator() catch @panic("bench-l2disco: cdp addr")) |a0| {
        var a = a0;
        while (a.next() catch @panic("bench-l2disco: cdp addr")) |_| t += 1;
    }
    return t;
}

fn sumArp(m: []const u8) u64 {
    const p = l2.arp.Packet.parse(m) catch @panic("bench-l2disco: arp");
    var t: u64 = @as(u64, @backingInt(p.oper)) + p.sha.len + p.spa.len + p.tha.len + p.tpa.len;
    for (p.spa) |c| t += c;
    for (p.tpa) |c| t += c;
    return t;
}

fn sumDhcp4(m: []const u8) u64 {
    const d = l2.dhcp.Message.parse(m) catch @panic("bench-l2disco: dhcp4");
    var t: u64 = @as(u64, @backingInt(d.op)) + d.xid + d.secs + d.flags;
    for (d.yiaddr) |c| t += c;
    if (d.message_type) |x| t += @backingInt(x);
    t += d.lease_time_s orelse 0;
    if (d.server_id) |s| for (s) |c| {
        t += c;
    };
    t += lenOf(d.host_name);
    return t;
}

fn sumDhcp6(m: []const u8) u64 {
    const d = l2.dhcp6.Message.parse(m) catch @panic("bench-l2disco: dhcp6");
    var t: u64 = @as(u64, @backingInt(d.msg_type)) + d.xid;
    var it = d.options();
    while (it.next() catch @panic("bench-l2disco: dhcp6 opt")) |o| t += @as(u64, o.code) + 1;
    return t;
}

fn sumNd(m: []const u8) u64 {
    const r = l2.nd.Message.parse(m) catch @panic("bench-l2disco: nd");
    const ra = r.body.router_advertisement;
    const flags: u8 = (@as(u8, @intFromBool(ra.managed)) << 7) | (@as(u8, @intFromBool(ra.other)) << 6) | (@as(u8, ra.preference) << 3);
    var t: u64 = @as(u64, ra.cur_hop_limit) + flags + ra.router_lifetime_s + ra.reachable_ms + ra.retrans_ms;
    var it = r.options();
    while (it.next() catch @panic("bench-l2disco: nd opt")) |o| t += 1 + o.type;
    return t;
}

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    const msgs = c.msgs[@backingInt(c.op)];
    switch (c.op) {
        inline else => |op| {
            const f = switch (op) {
                .lldp => sumLldp,
                .cdp => sumCdp,
                .arp => sumArp,
                .dhcp4 => sumDhcp4,
                .dhcp6 => sumDhcp6,
                .nd_ra => sumNd,
            };
            for (msgs) |m| t +%= f(m);
        },
    }
    return t;
}

// ── the corpus ───────────────────────────────────────────────────────────────

fn text(arena: std.mem.Allocator, r: std.Random, lo: usize, hi: usize) ![]const u8 {
    const s = try arena.alloc(u8, r.intRangeAtMost(usize, lo, hi));
    for (s) |*ch| ch.* = 'a' + r.uintLessThan(u8, 26);
    return s;
}

fn macOf(r: std.Random) l2.Mac {
    var m: [6]u8 = undefined;
    r.bytes(&m);
    m[0] &= 0xfe;
    return .{ .octets = m };
}

fn buildLldp(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const buf = try arena.alloc(u8, 1500);
    var b = l2.lldp.Builder.init(buf);
    try b.addChassisIdMac(macOf(r));
    try b.addPortIdIfName(try text(arena, r, 4, 12));
    try b.addTtl(r.int(u16));
    try b.addPortDescription(try text(arena, r, 5, 30));
    try b.addSystemName(try text(arena, r, 6, 20));
    try b.addSystemDescription(try text(arena, r, 20, 90));
    try b.addSystemCapabilities(.fromWire(r.int(u8)), .fromWire(r.int(u8)));
    var made: u8 = 0;
    const want = r.intRangeAtMost(u8, 2, 5);
    while (made < want) : (made += 1) switch (r.uintLessThan(u8, 4)) {
        0 => try b.addPortVlanId(r.intRangeAtMost(u16, 1, 4094)),
        1 => try b.addMaxFrameSize(r.intRangeAtMost(u16, 1500, 9216)),
        2 => try b.addMedCapabilities(0x0033, @fromBackingInt(3)),
        else => try b.addMedNetworkPolicy(.{ .application = 1, .unknown_policy = false, .tagged = true, .vlan_id = r.intRangeAtMost(u12, 1, 4094), .l2_priority = r.int(u3), .dscp = r.int(u6) }),
    };
    return try b.finish();
}

fn buildCdp(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const buf = try arena.alloc(u8, 1500);
    var b = try l2.cdp.Builder.init(buf, .{ .version = 2, .ttl_s = r.int(u8) });
    try b.addDeviceId(try text(arena, r, 6, 20));
    var addrs: [3][4]u8 = undefined;
    for (&addrs) |*a| r.bytes(a);
    try b.addAddressesIpv4(addrs[0..r.intRangeAtMost(usize, 1, 3)]);
    try b.addPortId(try text(arena, r, 8, 22));
    try b.addCapabilities(.fromWire(r.int(u8) & 0x2f));
    try b.addSoftwareVersion(try text(arena, r, 30, 100));
    try b.addPlatform(try text(arena, r, 10, 24));
    try b.addVtpDomain(try text(arena, r, 3, 10));
    try b.addNativeVlan(r.intRangeAtMost(u16, 1, 4094));
    try b.addDuplex(.full);
    return b.finish();
}

fn buildArp(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const m1 = macOf(r);
    var ip1: [4]u8 = undefined;
    var ip2: [4]u8 = undefined;
    r.bytes(&ip1);
    r.bytes(&ip2);
    const p = if (r.boolean()) l2.arp.EthIpv4.request(m1, ip1, ip2) else l2.arp.EthIpv4.reply(m1, ip1, macOf(r), ip2);
    return arena.dupe(u8, &p.encode());
}

fn buildDhcp4(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const buf = try arena.alloc(u8, 600);
    var ip: [4]u8 = undefined;
    r.bytes(&ip);
    var sv: [4]u8 = undefined;
    r.bytes(&sv);
    var b = try l2.dhcp.Builder.init(buf, .{
        .op = .boot_reply,
        .xid = r.int(u32),
        .secs = r.int(u16),
        .broadcast = r.boolean(),
        .yiaddr = ip,
        .siaddr = sv,
        .chaddr = l2.dhcp.Builder.chaddrFromMac(macOf(r)),
    });
    try b.addMessageType(if (r.boolean()) .offer else .ack);
    try b.addServerId(sv);
    try b.addLeaseTime(r.int(u32));
    try b.addSubnetMask(.{ 255, 255, 255, 0 });
    try b.addRouters(&sv);
    try b.addDnsServers(&.{ 1, 1, 1, 1, 8, 8, 8, 8 });
    try b.addDomainName(try text(arena, r, 6, 20));
    try b.addHostName(try text(arena, r, 4, 12));
    return try b.finish(.{});
}

fn buildDhcp6(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const buf = try arena.alloc(u8, 600);
    var b = try l2.dhcp6.Builder.init(buf, .reply, r.int(u24));
    var llt: [14]u8 = undefined;
    try b.addClientId(l2.dhcp6.duidLlt(&llt, macOf(r), r.int(u32)));
    var ll: [10]u8 = undefined;
    try b.addServerId(l2.dhcp6.duidLl(&ll, macOf(r)));
    var a: [16]u8 = undefined;
    r.bytes(&a);
    const na = try b.beginIa(.na, r.int(u32), 3600, 5400);
    try b.addIaAddr(a, 7200, 14400);
    try b.end(na);
    const pd = try b.beginIa(.pd, r.int(u32), 3600, 5400);
    try b.addIaPrefix(a, 56, 7200, 14400);
    try b.end(pd);
    try b.addAddressList(l2.dhcp6.OptionCode.dns_servers, &.{ a, a });
    try b.addDomainList(&.{ "example.com", "lab.example.org" });
    try b.addPreference(r.int(u8));
    return b.finish();
}

fn buildNd(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const m = try arena.alloc(u8, 16 + 8 + 8 + 32 * 2);
    @memset(m, 0);
    m[0] = 134;
    m[4] = r.int(u8); // cur hop limit
    m[5] = (@as(u8, r.int(u1)) << 7) | (@as(u8, r.int(u1)) << 6) | (@as(u8, r.int(u2)) << 3); // M, O, preference
    std.mem.writeInt(u16, m[6..8], r.int(u16), .big);
    std.mem.writeInt(u32, m[8..12], r.int(u32), .big);
    std.mem.writeInt(u32, m[12..16], r.int(u32), .big);
    var at: usize = 16;
    m[at] = 1; // source link-layer address
    m[at + 1] = 1;
    r.bytes(m[at + 2 ..][0..6]);
    at += 8;
    m[at] = 5; // MTU
    m[at + 1] = 1;
    std.mem.writeInt(u32, m[at + 4 ..][0..4], r.intRangeAtMost(u32, 1280, 9000), .big);
    at += 8;
    for (0..r.intRangeAtMost(usize, 1, 2)) |_| {
        m[at] = 3; // prefix information
        m[at + 1] = 4;
        m[at + 2] = 64;
        m[at + 3] = 0xc0;
        std.mem.writeInt(u32, m[at + 4 ..][0..4], 86400, .big);
        std.mem.writeInt(u32, m[at + 8 ..][0..4], 14400, .big);
        r.bytes(m[at + 16 ..][0..16]);
        at += 32;
    }
    return m[0..at];
}

fn writeMsgs(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, file: []const u8, msgs: *const [N][]const u8) !void {
    var out: std.ArrayList(u8) = .empty;
    var total: usize = 0;
    for (msgs) |m| {
        try out.appendSlice(arena, &.{ @truncate(m.len >> 8), @truncate(m.len) });
        try out.appendSlice(arena, m);
        total += m.len;
    }
    try dir.writeFile(io, .{ .sub_path = file, .data = out.items });
    std.debug.print("{s}: {s}: {d} messages, {d} bytes ({d} avg)\n", .{ bench_name, file, N, total, total / N });
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, c: *Ctx) !void {
    var prng = std.Random.DefaultPrng.init(0x12d1_5c05);
    const r = prng.random();
    inline for (.{
        .{ Op.lldp, "lldp.bin", buildLldp },
        .{ Op.cdp, "cdp.bin", buildCdp },
        .{ Op.arp, "arp.bin", buildArp },
        .{ Op.dhcp4, "dhcp4.bin", buildDhcp4 },
        .{ Op.dhcp6, "dhcp6.bin", buildDhcp6 },
        .{ Op.nd_ra, "nd_ra.bin", buildNd },
    }) |b| {
        const slot = &c.msgs[@backingInt(b[0])];
        for (slot) |*m| m.* = try b[2](arena, r);
        try writeMsgs(arena, io, dir, b[1], slot);
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    var ctx: Ctx = .{};
    try setup(arena, io, dir, &ctx);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "lldp", .op = .lldp, .ref = "lldp", .wall_only = true },
        .{ .name = "cdp", .op = .cdp, .ref = "cdp", .wall_only = true },
        .{ .name = "arp", .op = .arp, .ref = "arp", .wall_only = true },
        .{ .name = "dhcp4", .op = .dhcp4, .ref = "dhcp4", .alt = "dhcp4_idhcp", .wall_only = true },
        .{ .name = "dhcp6", .op = .dhcp6, .ref = "dhcp6", .alt = "dhcp6_idhcp", .wall_only = true },
        .{ .name = "nd_ra", .op = .nd_ra, .ref = "nd_ra", .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{exe},
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, s.worst_ref, s.best_ref });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card });
    try w.flush();
    return 0;
}

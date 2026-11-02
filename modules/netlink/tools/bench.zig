// SPDX-License-Identifier: MIT

//! Comparative benchmark: `netlink`'s decoders and request builder against
//! github.com/vishvananda/netlink v1.3.1 (Apache-2.0, the Go de-facto
//! package; `tools/go_bench`), the program behind the `**Performance:**` line
//! of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-netlink` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! github.com/vishvananda/netlink v1.3.1 + its two dependencies in the module
//! cache (`GOPROXY=off`). Run from the repository root. CPU-bound codec loops
//! only: no socket and no kernel is involved (a kernel round trip is the
//! kernel's time, whoever asks).
//!
//! One op = 64 inputs of a fixed seed, written by this driver into
//! `.zig-cache/bench-netlink/` (the Go side reads the same files):
//!   dec_link    a dumped `RTM_NEWLINK` payload (~250 bytes: name, MTU, MAC,
//!               broadcast, txqlen, operstate, parent, master, a 192-byte
//!               `IFLA_STATS64`, and for three quarters an `IFLA_LINKINFO`:
//!               veth, 802.1Q VLAN, VXLAN with six attributes). Ours
//!               `parseLink` into `Link` (inline name/kind buffers, typed
//!               `Link.info`); Go `netlink.LinkDeserialize` into a `Link`
//!               interface value (`*Veth`/`*Vlan`/`*Vxlan`/`*Device`, strings
//!               and slices on the GC heap).
//!   dec_addr    an `RTM_NEWADDR` payload (v4 with label and broadcast, or v6),
//!               with `IFA_CACHEINFO` and `IFA_FLAGS`. Ours `parseAddress`;
//!               Go the unexported `parseAddr` (reached with go:linkname).
//!   dec_route   an `RTM_NEWROUTE` payload: prefix, gateway or a two-hop
//!               `RTA_MULTIPATH` (a third of them), oif, priority, `RTA_TABLE`
//!               (> 255 for some), prefsrc, `RTA_METRICS{MTU}`. Ours
//!               `parseRoute`; Go the unexported `deserializeRoute`.
//!   dec_neigh   an `RTM_NEWNEIGH` payload with dst, lladdr, cacheinfo, probes.
//!               Ours `parseNeighbor`; Go `netlink.NeighDeserialize`.
//!   enc_route   an `RTM_NEWROUTE` request: unicast route via a gateway with
//!               priority, table (> 255 for some) and MTU. Ours
//!               `netlink.builders.route` (allocates the message, freed by the
//!               driver, as `Socket.routeAdd` does); Go `nl.NewNetlinkRequest`
//!               + `nl.NewRtMsg` + the unexported `(*Handle).prepareRouteReq`
//!               (what `RouteAdd` runs before it sends) + `req.Serialize()`,
//!               which allocates. Go always appends `RTA_OIF`, so every record
//!               has an oif and the messages are the same set of attributes.
//! Both sides add up, per message, the fields they decode (or, for the
//! encoder, the message length plus every byte after the 16-byte header: the
//! sequence number is the one field that differs); the counts must agree or
//! the run fails. Ratios are ours/Go by wall time; the verdict is the WORST
//! ratio. Arguments filter workloads.
//!
//! What vishvananda/netlink does that ours does not (so the rows are fair, not
//! equal): its `Link`/`Addr`/`Route` values own strings and slices on the GC
//! heap, `Link` is an interface value that needs a type switch, and a route
//! keeps `*net.IPNet`; ours returns plain values that keep no bytes. What ours
//! does that Go does not: every attribute length is bounds-checked before a
//! slice is formed, a `RTA_MULTIPATH` list is walked with that check, and the
//! request is built without a `net.IP` round trip.
//!
//! `enc_route_mp` and `dec_route_mp` are INFORMATIONAL and Zig only: a
//! four-hop multipath route built and parsed, with no reference (the Go
//! encoder's `RTA_OIF` rule makes its count differ by construction).

const std = @import("std");
const bench = @import("testkit").bench;
const nl = @import("netlink");
const codec = nl.codec;

const ref_short = "Go";
const ref_card = "Go vishvananda/netlink v1.3.1";
const bench_name = "bench-netlink";
const work_dir = ".zig-cache/bench-netlink";
const go_dir = "modules/netlink/tools/go_bench";
const N = 64;
const rec_len = 4 + 1 + 4 + 4 + 4 + 4 + 4;

const Op = enum { dec_link, dec_addr, dec_route, dec_neigh, enc_route };

const Ctx = struct {
    op: Op = .dec_link,
    msgs: [4][N][]const u8 = undefined, // indexed by Op for the four decoders
    routes: [N]nl.RouteSpec = undefined,
};

const gpa = std.heap.smp_allocator;

// ── the timed ops ────────────────────────────────────────────────────────────

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    switch (c.op) {
        .dec_link => for (c.msgs[0]) |m| {
            t +%= decodeLink(m);
        },
        .dec_addr => for (c.msgs[1]) |m| {
            t +%= decodeAddr(m);
        },
        .dec_route => for (c.msgs[2]) |m| {
            t +%= decodeRoute(m);
        },
        .dec_neigh => for (c.msgs[3]) |m| {
            t +%= decodeNeigh(m);
        },
        .enc_route => for (c.routes) |spec| {
            const req = nl.builders.route(gpa, 1, nl.RTM_NEWROUTE, (nl.Create{}).flags(), spec) catch @panic("bench-netlink: build");
            t +%= req.len;
            for (req[codec.header_len..]) |b| t +%= b;
            gpa.free(req);
        },
    }
    return t;
}

fn sum(b: []const u8) u64 {
    var t: u64 = 0;
    for (b) |c| t += c;
    return t;
}

fn decodeLink(m: []const u8) u64 {
    const l = (nl.parseLink(m) catch @panic("bench-netlink: link")).?;
    var t: u64 = @as(u64, l.index) + l.mtu + l.txqlen + l.operstate + l.parent + l.master;
    t += sum(l.name());
    if (l.mac) |mac| t += sum(&mac);
    if (l.stats) |s| t +%= s.rx_bytes +% s.tx_bytes;
    if (l.vlan_id) |v| t += v;
    switch (l.info) {
        .vxlan => |v| t += @as(u64, v.vni) + v.port + v.ttl + sum(v.group.bytes()) + v.link,
        else => {},
    }
    return t;
}

fn decodeAddr(m: []const u8) u64 {
    const a = (nl.parseAddress(m) catch @panic("bench-netlink: addr")).?;
    return @as(u64, a.ifindex) + a.prefixlen + a.scope + sum(a.bytes()) + a.valid_lft + a.preferred_lft + a.flags32 + sum(a.label());
}

fn decodeRoute(m: []const u8) u64 {
    const r = (nl.parseRoute(m) catch @panic("bench-netlink: route")).?;
    var t: u64 = @as(u64, r.oif) + r.priority + r.table + r.mtu + sum(r.gatewayBytes()) + sum(r.prefsrcBytes()) + sum(r.dstBytes());
    for (r.hopSlice()) |h| t += @as(u64, h.oif) + h.weight + sum(h.gatewayBytes());
    return t;
}

fn decodeNeigh(m: []const u8) u64 {
    const n = (nl.parseNeighbor(m) catch @panic("bench-netlink: neigh")).?;
    return @as(u64, n.ifindex) + n.state + n.flags + n.ntype + sum(n.dstBytes()) + sum(n.lladdrBytes());
}

// ── the corpus ───────────────────────────────────────────────────────────────

const A = std.mem.Allocator;

fn attr(a: A, l: *std.ArrayList(u8), t: u16, data: []const u8) !void {
    try codec.appendAttr(a, l, t, data);
}
fn attrU32(a: A, l: *std.ArrayList(u8), t: u16, v: u32) !void {
    try codec.appendAttrU32(a, l, t, v);
}

fn buildLink(a: A, r: std.Random, i: u16) ![]const u8 {
    var l: std.ArrayList(u8) = .empty;
    var fixed: [nl.ifinfomsg_len]u8 = @splat(0);
    std.mem.writeInt(u16, fixed[2..4], 1, .little); // ARPHRD_ETHER
    std.mem.writeInt(u32, fixed[4..8], @as(u32, i) + 2, .little);
    std.mem.writeInt(u32, fixed[8..12], 0x1043, .little);
    try codec.appendPadded(a, &l, &fixed);
    var name: [16]u8 = undefined;
    const kind_sel = i % 4;
    const stems = [_][]const u8{ "eth", "veth", "eth", "vx" };
    const stem = stems[kind_sel];
    const nm = try std.fmt.bufPrint(&name, "{s}{d}", .{ stem, i });
    try codec.appendAttrString(a, &l, nl.IFLA_IFNAME, nm);
    try attrU32(a, &l, nl.IFLA_MTU, r.intRangeAtMost(u32, 576, 9000));
    var mac: [6]u8 = undefined;
    r.bytes(&mac);
    try attr(a, &l, nl.IFLA_ADDRESS, &mac);
    try attr(a, &l, 2, &@as([6]u8, @splat(0xff))); // IFLA_BROADCAST
    try attrU32(a, &l, nl.IFLA_TXQLEN, 1000);
    try codec.appendAttrU8(a, &l, nl.IFLA_OPERSTATE, nl.IF_OPER.UP);
    try attrU32(a, &l, nl.IFLA_LINK, if (kind_sel == 0) 0 else r.intRangeAtMost(u32, 1, 40));
    if (kind_sel != 3) try attrU32(a, &l, nl.IFLA_MASTER, r.intRangeAtMost(u32, 1, 8));
    var stats: [192]u8 = undefined;
    r.bytes(&stats);
    try attr(a, &l, nl.IFLA_STATS64, &stats);
    if (kind_sel != 0) {
        const li = try codec.nestBegin(a, &l, nl.IFLA_LINKINFO);
        const kinds = [_][]const u8{ "", "veth", "vlan", "vxlan" };
        const kind = kinds[kind_sel];
        try codec.appendAttrString(a, &l, nl.IFLA_INFO.KIND, kind);
        if (kind_sel == 2) {
            const d = try codec.nestBegin(a, &l, nl.IFLA_INFO.DATA);
            try codec.appendAttrBe16(a, &l, nl.IFLA_VLAN.PROTOCOL, 0x8100);
            try codec.appendAttrU16(a, &l, nl.IFLA_VLAN.ID, r.intRangeAtMost(u16, 1, 4094));
            try codec.nestEnd(&l, d);
        } else if (kind_sel == 3) {
            const d = try codec.nestBegin(a, &l, nl.IFLA_INFO.DATA);
            try attrU32(a, &l, nl.ext.IFLA_VXLAN.ID, r.intRangeAtMost(u32, 1, 0xffffff));
            try attr(a, &l, nl.ext.IFLA_VXLAN.GROUP, &.{ 239, 1, 1, r.int(u8) });
            try attrU32(a, &l, nl.ext.IFLA_VXLAN.LINK, r.intRangeAtMost(u32, 1, 40));
            try codec.appendAttrU8(a, &l, nl.ext.IFLA_VXLAN.TTL, 64);
            try codec.appendAttrU8(a, &l, nl.ext.IFLA_VXLAN.LEARNING, 1);
            try codec.appendAttrBe16(a, &l, nl.ext.IFLA_VXLAN.PORT, 4789);
            try codec.nestEnd(&l, d);
        }
        try codec.nestEnd(&l, li);
    }
    return l.items;
}

fn buildAddr(a: A, r: std.Random, i: u16) ![]const u8 {
    var l: std.ArrayList(u8) = .empty;
    const v6 = i % 3 == 0;
    var fixed: [nl.ifaddrmsg_len]u8 = @splat(0);
    fixed[0] = if (v6) nl.AF.INET6 else nl.AF.INET;
    fixed[1] = if (v6) 64 else r.intRangeAtMost(u8, 8, 30);
    std.mem.writeInt(u32, fixed[4..8], r.intRangeAtMost(u32, 1, 40), .little);
    try codec.appendPadded(a, &l, &fixed);
    if (v6) {
        var ip: [16]u8 = undefined;
        r.bytes(&ip);
        try attr(a, &l, 1, &ip); // IFA_ADDRESS
    } else {
        const ip = [4]u8{ 10, r.int(u8), r.int(u8), r.int(u8) };
        try attr(a, &l, 1, &ip);
        try attr(a, &l, 2, &ip); // IFA_LOCAL
        try codec.appendAttrString(a, &l, 3, "eth0"); // IFA_LABEL
        try attr(a, &l, 4, &.{ 10, ip[1], ip[2], 255 }); // IFA_BROADCAST
    }
    var ci: [16]u8 = @splat(0);
    std.mem.writeInt(u32, ci[0..4], r.intRangeAtMost(u32, 100, 5000), .little);
    std.mem.writeInt(u32, ci[4..8], r.intRangeAtMost(u32, 5000, 9000), .little);
    try attr(a, &l, 6, &ci); // IFA_CACHEINFO
    try attrU32(a, &l, 8, 0x80 | r.int(u8)); // IFA_FLAGS
    return l.items;
}

fn buildRoute(a: A, r: std.Random, i: u16) ![]const u8 {
    var l: std.ArrayList(u8) = .empty;
    const multipath = i % 3 == 0;
    var fixed: [nl.rtmsg_len]u8 = @splat(0);
    fixed[0] = nl.AF.INET;
    fixed[1] = r.intRangeAtMost(u8, 8, 30);
    fixed[4] = nl.RT_TABLE.MAIN;
    fixed[5] = nl.RTPROT.BOOT;
    fixed[7] = nl.RTN.UNICAST;
    try codec.appendPadded(a, &l, &fixed);
    try attr(a, &l, nl.RTA.DST, &.{ 10, r.int(u8), r.int(u8), 0 });
    if (multipath) {
        const mp = try codec.nestBegin(a, &l, nl.RTA.MULTIPATH);
        for (0..2) |_| {
            const start = l.items.len;
            var h: [8]u8 = @splat(0);
            h[3] = r.intRangeAtMost(u8, 0, 3);
            std.mem.writeInt(u32, h[4..8], r.intRangeAtMost(u32, 1, 40), .little);
            try l.appendSlice(a, &h);
            try attr(a, &l, nl.RTA.GATEWAY, &.{ 10, r.int(u8), r.int(u8), 1 });
            std.mem.writeInt(u16, l.items[start..][0..2], @intCast(l.items.len - start), .little);
        }
        try codec.nestEnd(&l, mp);
    } else {
        try attr(a, &l, nl.RTA.GATEWAY, &.{ 10, r.int(u8), r.int(u8), 1 });
        try attrU32(a, &l, nl.RTA.OIF, r.intRangeAtMost(u32, 1, 40));
    }
    try attrU32(a, &l, nl.RTA.PRIORITY, r.intRangeAtMost(u32, 1, 2000));
    if (i % 5 == 0) try attrU32(a, &l, nl.RTA.TABLE, r.intRangeAtMost(u32, 256, 4000));
    if (i % 2 == 0) try attr(a, &l, nl.RTA.PREFSRC, &.{ 10, 0, r.int(u8), 2 });
    if (i % 4 == 0) {
        const m = try codec.nestBegin(a, &l, nl.RTA.METRICS);
        try attrU32(a, &l, nl.ext.RTAX.MTU, r.intRangeAtMost(u32, 576, 9000));
        try codec.nestEnd(&l, m);
    }
    return l.items;
}

fn buildNeigh(a: A, r: std.Random, i: u16) ![]const u8 {
    var l: std.ArrayList(u8) = .empty;
    const v6 = i % 4 == 0;
    var fixed: [nl.ndmsg_len]u8 = @splat(0);
    fixed[0] = if (v6) nl.AF.INET6 else nl.AF.INET;
    std.mem.writeInt(u32, fixed[4..8], r.intRangeAtMost(u32, 1, 40), .little);
    std.mem.writeInt(u16, fixed[8..10], nl.NUD.REACHABLE, .little);
    fixed[11] = nl.RTN.UNICAST;
    try codec.appendPadded(a, &l, &fixed);
    if (v6) {
        var ip: [16]u8 = undefined;
        r.bytes(&ip);
        try attr(a, &l, nl.NDA.DST, &ip);
    } else {
        try attr(a, &l, nl.NDA.DST, &.{ 192, 168, r.int(u8), r.int(u8) });
    }
    var mac: [6]u8 = undefined;
    r.bytes(&mac);
    try attr(a, &l, nl.NDA.LLADDR, &mac);
    try attr(a, &l, 3, &@as([16]u8, @splat(1))); // NDA_CACHEINFO
    try attrU32(a, &l, 4, 3); // NDA_PROBES
    return l.items;
}

fn writeMsgs(arena: A, io: std.Io, dir: std.Io.Dir, file: []const u8, msgs: *const [N][]const u8) !void {
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

fn setup(arena: A, io: std.Io, dir: std.Io.Dir, c: *Ctx) !void {
    var prng = std.Random.DefaultPrng.init(0x6e65_746c_0001);
    const r = prng.random();
    inline for (.{
        .{ 0, "dec_link.bin", buildLink },
        .{ 1, "dec_addr.bin", buildAddr },
        .{ 2, "dec_route.bin", buildRoute },
        .{ 3, "dec_neigh.bin", buildNeigh },
    }) |b| {
        for (&c.msgs[b[0]], 0..) |*m, i| m.* = try b[2](arena, r, @intCast(i));
        try writeMsgs(arena, io, dir, b[1], &c.msgs[b[0]]);
    }
    var recs: std.ArrayList(u8) = .empty;
    for (&c.routes) |*spec| {
        const dst = try arena.dupe(u8, &.{ 10, r.int(u8), r.int(u8), 0 });
        const gw = try arena.dupe(u8, &.{ 10, r.int(u8), r.int(u8), 1 });
        const plen = r.intRangeAtMost(u8, 8, 30);
        const oif = r.intRangeAtMost(u32, 1, 40);
        const prio = r.intRangeAtMost(u32, 1, 2000);
        const table: u32 = if (r.boolean()) 254 else r.intRangeAtMost(u32, 256, 4000);
        const mtu: u32 = if (r.boolean()) 0 else r.intRangeAtMost(u32, 576, 9000);
        spec.* = .{ .dst = dst, .dst_prefixlen = plen, .gateway = gw, .oif = oif, .priority = prio, .table = table, .mtu = if (mtu == 0) null else mtu };
        try recs.appendSlice(arena, dst);
        try recs.append(arena, plen);
        try recs.appendSlice(arena, gw);
        for ([_]u32{ oif, prio, table, mtu }) |v| try recs.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToLittle(u32, v)));
    }
    std.debug.assert(recs.items.len == N * rec_len);
    try dir.writeFile(io, .{ .sub_path = "enc_route.bin", .data = recs.items });
}

// ── informational: four-hop multipath, Zig only ──────────────────────────────

const MpCtx = struct { msg: []const u8 = &.{}, spec: nl.RouteSpec = .{} };

fn encMp(c: *MpCtx) u64 {
    var t: u64 = 0;
    for (0..N) |_| {
        const req = nl.builders.route(gpa, 1, nl.RTM_NEWROUTE, (nl.Create{}).flags(), c.spec) catch @panic("bench-netlink: build mp");
        t +%= req.len;
        gpa.free(req);
    }
    return t;
}

fn decMp(c: *MpCtx) u64 {
    var t: u64 = 0;
    for (0..N) |_| t +%= decodeRoute(c.msg);
    return t;
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
        .{ .name = "dec_link", .op = .dec_link, .ref = "dec_link", .wall_only = true },
        .{ .name = "dec_addr", .op = .dec_addr, .ref = "dec_addr", .wall_only = true },
        .{ .name = "dec_route", .op = .dec_route, .ref = "dec_route", .wall_only = true },
        .{ .name = "dec_neigh", .op = .dec_neigh, .ref = "dec_neigh", .wall_only = true },
        .{ .name = "enc_route", .op = .enc_route, .ref = "enc_route", .wall_only = true },
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

    // Multipath, informational (ours only).
    const cyc: bench.Cycles = .open();
    defer cyc.close();
    var mp: MpCtx = .{};
    const hops = [_]nl.HopSpec{
        .{ .gateway = &.{ 10, 0, 0, 1 }, .oif = 2 },
        .{ .gateway = &.{ 10, 0, 1, 1 }, .oif = 3, .weight = 2 },
        .{ .gateway = &.{ 10, 0, 2, 1 }, .oif = 4 },
        .{ .gateway = &.{ 10, 0, 3, 1 }, .oif = 5, .weight = 4 },
    };
    mp.spec = .{ .dst = &.{ 10, 9, 0, 0 }, .dst_prefixlen = 16, .hops = &hops, .priority = 10 };
    const req = try nl.builders.route(gpa, 1, nl.RTM_NEWROUTE, 0, mp.spec);
    defer gpa.free(req);
    mp.msg = req[codec.header_len..];
    var best_e: f64 = std.math.inf(f64);
    var best_d: f64 = std.math.inf(f64);
    for (0..rounds) |_| {
        best_e = @min(best_e, bench.timeIt(io, cyc, encMp, .{&mp}, true).ns);
        best_d = @min(best_d, bench.timeIt(io, cyc, decMp, .{&mp}, true).ns);
    }
    try w.print("enc_route_mp  {d:>11.0} ns/{d} routes (informational, no reference)\n", .{ best_e, N });
    try w.print("dec_route_mp  {d:>11.0} ns/{d} routes (informational, no reference)\n", .{ best_d, N });
    try w.flush();
    return 0;
}

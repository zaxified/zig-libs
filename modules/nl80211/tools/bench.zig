// SPDX-License-Identifier: MIT

//! Comparative benchmark: `nl80211`'s pure decode of interface and station
//! messages against github.com/mdlayher/wifi v0.10.0 (MIT, `tools/go_bench`),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-nl80211` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! mdlayher/wifi v0.10.0 with its dependencies in the module cache
//! (`GOPROXY=off`). Run from the repository root. CPU-bound decode only: no
//! socket and no kernel is involved, so a live dump is not benchmarked.
//!
//! Only two decoders of mdlayher/wifi are exported (`ParseInterfaces`,
//! `ParseStationInfo`); its scan, wiphy and regulatory decoders are not
//! callable, so there is no row for them. One op = 64 messages of a fixed
//! seed, laid out the way the kernel sends them (attribute order, NUL-
//! terminated names, nested `STA_INFO` / `RATE_INFO`), written to
//! `.zig-cache/bench-nl80211/` (the Go side reads the same files). Names,
//! indices, addresses, frequencies, counters and rates are random per message:
//!   dec_iface    64 `NEW_INTERFACE` messages. Ours `iface.parse` on each; Go
//!                `wifi.ParseInterfaces` on the whole list. Both decode
//!                ifindex, name, MAC, wiphy, type, wdev, frequency and width;
//!                ours also decodes generation, centre frequencies, tx power,
//!                4addr and SSID, which the corpus carries and Go skips.
//!   dec_station  64 `NEW_STATION` messages. Ours `station.parse` on each; Go
//!                `wifi.ParseStationInfo` on each. Both decode the counters
//!                (32- and 64-bit), signals, times, packets, retries, failures,
//!                beacon loss and both bitrate nests; both skip a 200-byte
//!                `TID_STATS` nest and the chain signals; ours also decodes
//!                nothing extra that the corpus carries.
//! Both sides add up, per message, the fields above; the counts must agree or
//! the run fails. Ratios are ours/Go by wall time; the verdict is the WORST
//! ratio. Arguments filter workloads.
//!
//! What ours does that Go does not (so the rows are fair, not equal): it
//! rejects a wrong-sized scalar and an over-long name instead of reading past
//! it; what Go does that ours does not: allocate the result per message (GC).

const std = @import("std");
const bench = @import("testkit").bench;
const nl80211 = @import("nl80211");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = nl80211.uapi;

const ref_short = "Go";
const ref_card = "Go mdlayher/wifi v0.10.0";
const bench_name = "bench-nl80211";
const work_dir = ".zig-cache/bench-nl80211";
const go_dir = "modules/nl80211/tools/go_bench";
const N = 64;

const Op = enum { dec_iface, dec_station };

const Ctx = struct {
    op: Op = .dec_iface,
    /// Message attribute bytes (the genl payload past the genl header).
    ifaces: [N][]const u8 = undefined,
    stations: [N][]const u8 = undefined,
};

// ── the timed ops ────────────────────────────────────────────────────────────

fn tallyIface(i: *const nl80211.Interface) u64 {
    var t: u64 = 0;
    t +%= i.ifindex orelse 0;
    t +%= i.wiphy orelse 0;
    t +%= @backingInt(i.iftype);
    t +%= i.wdev orelse 0;
    t +%= i.freq_mhz orelse 0;
    t +%= if (i.chan_width) |w| @backingInt(w) else 0;
    t +%= i.name().len;
    t +%= i.name()[0];
    const m = i.mac.?;
    t +%= m[0];
    t +%= m[5];
    return t;
}

fn tallyRate(r: ?nl80211.RateInfo) u64 {
    const x = r orelse return 0;
    return (x.kilobitsPerSecond() orelse 0) / 100;
}

fn tallyStation(s: *const nl80211.Station) u64 {
    var t: u64 = 0;
    t +%= s.ifindex orelse 0;
    const m = s.mac.?;
    t +%= m[0];
    t +%= m[5];
    t +%= s.connected_time_s orelse 0;
    t +%= s.inactive_time_ms orelse 0;
    t +%= s.rx_bytes orelse 0;
    t +%= s.tx_bytes orelse 0;
    t +%= s.rx_packets orelse 0;
    t +%= s.tx_packets orelse 0;
    t +%= s.tx_retries orelse 0;
    t +%= s.tx_failed orelse 0;
    t +%= s.beacon_loss orelse 0;
    t +%= @as(u64, @intCast(@as(i64, s.signal_dbm orelse 0) + 200));
    t +%= @as(u64, @intCast(@as(i64, s.signal_avg_dbm orelse 0) + 200));
    t +%= tallyRate(s.rx_bitrate);
    t +%= tallyRate(s.tx_bitrate);
    return t;
}

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    switch (c.op) {
        .dec_iface => for (c.ifaces) |p| {
            const i = nl80211.iface.parse(p) catch @panic("bench-nl80211: iface");
            t +%= tallyIface(&i);
        },
        .dec_station => for (c.stations) |p| {
            const s = nl80211.station.parse(p) catch @panic("bench-nl80211: station");
            t +%= tallyStation(&s);
        },
    }
    return t;
}

// ── the corpus ───────────────────────────────────────────────────────────────

const freqs = [_]u32{ 2412, 2437, 2462, 5180, 5240, 5500, 5745, 5955, 6115 };

fn buildIface(arena: std.mem.Allocator, r: std.Random, i: usize) ![]const u8 {
    var l: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(arena, &l, uapi.ATTR.IFINDEX, r.intRangeAtMost(u32, 1, 4000));
    var name_buf: [16]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "wlan{d}", .{r.intRangeAtMost(u32, 0, 99999)});
    try codec.appendAttrString(arena, &l, uapi.ATTR.IFNAME, name);
    try codec.appendAttrU32(arena, &l, uapi.ATTR.WIPHY, r.intRangeAtMost(u32, 0, 7));
    try codec.appendAttrU32(arena, &l, uapi.ATTR.IFTYPE, r.intRangeAtMost(u32, 1, 10));
    var wdev: [8]u8 = undefined;
    std.mem.writeInt(u64, &wdev, @as(u64, 0x100000000) | r.int(u32), .little);
    try codec.appendAttr(arena, &l, uapi.ATTR.WDEV, &wdev);
    var mac: [6]u8 = undefined;
    r.bytes(&mac);
    mac[0] |= 0x02;
    try codec.appendAttr(arena, &l, uapi.ATTR.MAC, &mac);
    try codec.appendAttrU32(arena, &l, uapi.ATTR.GENERATION, r.int(u32));
    try codec.appendAttrU8(arena, &l, uapi.ATTR.@"4ADDR", r.int(u1));
    const f = freqs[r.uintLessThan(usize, freqs.len)];
    try codec.appendAttrU32(arena, &l, uapi.ATTR.WIPHY_FREQ, f);
    try codec.appendAttrU32(arena, &l, uapi.ATTR.CHANNEL_WIDTH, r.intRangeAtMost(u32, 0, 5));
    try codec.appendAttrU32(arena, &l, uapi.ATTR.CENTER_FREQ1, f + 10);
    try codec.appendAttrU32(arena, &l, uapi.ATTR.WIPHY_TX_POWER_LEVEL, r.intRangeAtMost(u32, 500, 3000));
    if (i % 4 != 3) {
        var ssid: [32]u8 = undefined;
        const n = r.intRangeAtMost(usize, 1, 32);
        r.bytes(ssid[0..n]);
        try codec.appendAttr(arena, &l, uapi.ATTR.SSID, ssid[0..n]);
    }
    return l.items;
}

fn rateNest(arena: std.mem.Allocator, l: *std.ArrayList(u8), ty: u16, r: std.Random) !void {
    const n = try codec.nestBegin(arena, l, codec.NLA_F_NESTED | ty);
    const br = r.intRangeAtMost(u32, 60, 28000);
    try codec.appendAttrU32(arena, l, uapi.RATE_INFO.BITRATE32, br);
    try codec.appendAttrU16(arena, l, uapi.RATE_INFO.BITRATE, @truncate(br));
    try codec.appendAttrU8(arena, l, uapi.RATE_INFO.VHT_MCS, r.intRangeAtMost(u8, 0, 9));
    try codec.appendAttrU8(arena, l, uapi.RATE_INFO.VHT_NSS, r.intRangeAtMost(u8, 1, 4));
    try codec.appendAttr(arena, l, uapi.RATE_INFO.@"80_MHZ_WIDTH", &.{});
    try codec.appendAttr(arena, l, uapi.RATE_INFO.SHORT_GI, &.{});
    try codec.nestEnd(l, n);
}

fn buildStation(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    var l: std.ArrayList(u8) = .empty;
    try codec.appendAttrU32(arena, &l, uapi.ATTR.IFINDEX, r.intRangeAtMost(u32, 1, 4000));
    var mac: [6]u8 = undefined;
    r.bytes(&mac);
    try codec.appendAttr(arena, &l, uapi.ATTR.MAC, &mac);
    try codec.appendAttrU32(arena, &l, uapi.ATTR.GENERATION, r.int(u32));
    const si = try codec.nestBegin(arena, &l, uapi.ATTR.STA_INFO);
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.CONNECTED_TIME, r.intRangeAtMost(u32, 1, 900000));
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.INACTIVE_TIME, r.intRangeAtMost(u32, 0, 60000));
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.RX_BYTES, r.int(u32));
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.TX_BYTES, r.int(u32));
    var b64: [8]u8 = undefined;
    std.mem.writeInt(u64, &b64, r.int(u40), .little);
    try codec.appendAttr(arena, &l, uapi.STA_INFO.RX_BYTES64, &b64);
    std.mem.writeInt(u64, &b64, r.int(u40), .little);
    try codec.appendAttr(arena, &l, uapi.STA_INFO.TX_BYTES64, &b64);
    try codec.appendAttrU8(arena, &l, uapi.STA_INFO.SIGNAL, @bitCast(r.intRangeAtMost(i8, -90, -30)));
    try codec.appendAttrU8(arena, &l, uapi.STA_INFO.SIGNAL_AVG, @bitCast(r.intRangeAtMost(i8, -90, -30)));
    // Two chain signals and a TID_STATS nest: attributes neither side decodes.
    {
        const cs = try codec.nestBegin(arena, &l, uapi.STA_INFO.CHAIN_SIGNAL);
        try codec.appendAttrU8(arena, &l, 1, @bitCast(r.intRangeAtMost(i8, -90, -30)));
        try codec.appendAttrU8(arena, &l, 2, @bitCast(r.intRangeAtMost(i8, -90, -30)));
        try codec.nestEnd(&l, cs);
        const tid = try codec.nestBegin(arena, &l, uapi.STA_INFO.TID_STATS);
        var k: u16 = 1;
        while (k <= 4) : (k += 1) {
            const e = try codec.nestBegin(arena, &l, k);
            var filler: [40]u8 = undefined;
            r.bytes(&filler);
            try codec.appendAttr(arena, &l, 1, &filler);
            try codec.nestEnd(&l, e);
        }
        try codec.nestEnd(&l, tid);
    }
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.RX_PACKETS, r.int(u32));
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.TX_PACKETS, r.int(u32));
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.TX_RETRIES, r.int(u24));
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.TX_FAILED, r.int(u16));
    try codec.appendAttrU32(arena, &l, uapi.STA_INFO.BEACON_LOSS, r.int(u8));
    try rateNest(arena, &l, uapi.STA_INFO.RX_BITRATE, r);
    try rateNest(arena, &l, uapi.STA_INFO.TX_BITRATE, r);
    try codec.nestEnd(&l, si);
    return l.items;
}

fn writeFrames(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, file: []const u8, frames: []const []const u8) !void {
    var out: std.ArrayList(u8) = .empty;
    var total: usize = 0;
    for (frames) |m| {
        try out.appendSlice(arena, &.{ @truncate(m.len >> 8), @truncate(m.len) });
        try out.appendSlice(arena, m);
        total += m.len;
    }
    try dir.writeFile(io, .{ .sub_path = file, .data = out.items });
    std.debug.print("{s}: {s}: {d} frames, {d} bytes ({d} avg)\n", .{ bench_name, file, frames.len, total, total / frames.len });
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, c: *Ctx) !void {
    var prng = std.Random.DefaultPrng.init(0x80211_0001);
    const r = prng.random();
    for (&c.ifaces, 0..) |*p, i| p.* = try buildIface(arena, r, i);
    try writeFrames(arena, io, dir, "dec_iface.bin", &c.ifaces);
    for (&c.stations) |*p| p.* = try buildStation(arena, r);
    try writeFrames(arena, io, dir, "dec_station.bin", &c.stations);
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
        .{ .name = "dec_iface", .op = .dec_iface, .ref = "dec_iface", .wall_only = true },
        .{ .name = "dec_station", .op = .dec_station, .ref = "dec_station", .wall_only = true },
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

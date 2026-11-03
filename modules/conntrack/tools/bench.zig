// SPDX-License-Identifier: MIT

//! Comparative benchmark: `conntrack`'s pure decode of a captured dump against
//! github.com/ti-mo/conntrack v0.6.0 (MIT, `tools/go_bench`), the program
//! behind the `**Performance:**` line of the maturity card (CONVENTIONS.md §9,
//! kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-conntrack` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! ti-mo/conntrack v0.6.0 with its dependencies in the module cache
//! (`GOPROXY=off`). Run from the repository root. CPU-bound decode only: no
//! socket and no kernel is involved, so there is no "kernel tie" row, and a
//! live dump in a netns (which is mostly kernel work) is not benchmarked.
//!
//! One op = 64 flows of a fixed seed, built here the way the kernel lays a
//! dump record out (tuples with IP and PROTO nests, status, timeout, mark, id,
//! use, TCP protoinfo, and for about half the flows 64-bit counters, a start
//! timestamp and a zone; one in four is IPv6, one in three UDP), written to
//! `.zig-cache/bench-conntrack/` (the Go side reads the same files):
//!   dec_flow   each flow's message payload, decoded into the typed model.
//!              Ours `decodeFlow` (a pointer-free `Flow` value, addresses as
//!              byte arrays); Go `conntrack.Event.Unmarshal` on a
//!              `netlink.Message` (a heap `Flow`, `netip.Addr` addresses,
//!              `time.Time` timestamps, pointer-linked protoinfo). Both
//!              decode every field the kernel sends; ours additionally walks
//!              the helper, label, seq-adjust, synproxy, SCTP and DCCP
//!              attributes the corpus does not carry, Go the same set.
//!   dec_dgram  the same flows as four datagrams of 16 messages, framing and
//!              decode as a dump reply arrives: ours `MessageIterator` +
//!              `decodeFlow`; Go `netlink.Message.UnmarshalBinary` per message (x/netlink exports no
//!              whole-datagram parser; the walk by `nlmsg_len` is ours to write) +
//!              `Unmarshal`.
//! Both sides add up, per flow: the four ports, status, timeout, mark, id,
//! use, zone, both counter pairs, the TCP state, the start timestamp, the
//! first byte of the original source and the last of the destination; the
//! counts must agree or the run fails. Ratios are ours/Go by wall time; the
//! verdict is the WORST ratio. Arguments filter workloads.
//!
//! What ours does that Go does not (so the rows are fair, not equal): it
//! cross-checks the address families (flow against both tuples) and refuses a
//! wrong-sized scalar; what Go does that ours does not: allocate the result
//! and its children per flow (GC) and refuse any unknown tuple child.

const std = @import("std");
const bench = @import("testkit").bench;
const conntrack = @import("conntrack");
const netlink = @import("netlink");
const netaddr = @import("netaddr");
const codec = netlink.codec;
const wire = conntrack.wire;

const ref_short = "Go";
const ref_card = "Go ti-mo/conntrack v0.6.0";
const bench_name = "bench-conntrack";
const work_dir = ".zig-cache/bench-conntrack";
const go_dir = "modules/conntrack/tools/go_bench";
const N = 64;
const per_dgram = 16;

const Op = enum { dec_flow, dec_dgram };

const Ctx = struct {
    op: Op = .dec_flow,
    /// Message payloads (`nfgenmsg` + attributes).
    payloads: [N][]const u8 = undefined,
    /// Datagrams of `per_dgram` whole messages.
    dgrams: [N / per_dgram][]const u8 = undefined,
};

// ── the timed ops ────────────────────────────────────────────────────────────

fn tally(f: *const wire.Flow) u64 {
    var t: u64 = 0;
    t +%= f.orig.src_port orelse 0;
    t +%= f.orig.dst_port orelse 0;
    t +%= f.reply.src_port orelse 0;
    t +%= f.reply.dst_port orelse 0;
    t +%= f.status orelse 0;
    t +%= f.timeout orelse 0;
    t +%= f.mark orelse 0;
    t +%= f.id orelse 0;
    t +%= f.use orelse 0;
    t +%= f.zone orelse 0;
    if (f.counters_orig) |c| t +%= c.packets +% c.bytes;
    if (f.counters_reply) |c| t +%= c.packets +% c.bytes;
    if (f.tcp_state) |s| t +%= @backingInt(s);
    t +%= f.timestamp_start orelse 0;
    t +%= switch (f.orig.src.?) {
        .v4 => |a| a[0],
        .v6 => |a| a[0],
    };
    t +%= switch (f.orig.dst.?) {
        .v4 => |a| a[3],
        .v6 => |a| a[15],
    };
    return t;
}

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    switch (c.op) {
        .dec_flow => for (c.payloads) |p| {
            const f = wire.decodeFlow(p) catch @panic("bench-conntrack: decode");
            t +%= tally(&f);
        },
        .dec_dgram => for (c.dgrams) |d| {
            var it: codec.MessageIterator = .{ .buf = d };
            while (it.next() catch @panic("bench-conntrack: framing")) |m| {
                const f = wire.decodeFlow(m.payload) catch @panic("bench-conntrack: decode");
                t +%= tally(&f);
            }
        },
    }
    return t;
}

// ── the corpus ───────────────────────────────────────────────────────────────

fn buildFlow(arena: std.mem.Allocator, r: std.Random, i: usize) ![]const u8 {
    var list: std.ArrayList(u8) = .empty;
    const v6 = i % 4 == 3;
    const udp = i % 3 == 0;
    const proto: u8 = if (udp) wire.IPPROTO.UDP else wire.IPPROTO.TCP;
    const fam: wire.Family = if (v6) .ipv6 else .ipv4;
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    r.bytes(&a);
    r.bytes(&b);
    const sp = r.intRangeAtMost(u16, 1024, 65535);
    const dp = r.intRangeAtMost(u16, 1, 1023);
    const src: netaddr.Ip = if (v6) .{ .v6 = a } else .{ .v4 = a[0..4].* };
    const dst: netaddr.Ip = if (v6) .{ .v6 = b } else .{ .v4 = b[0..4].* };
    const orig: wire.Tuple = .{ .src = src, .dst = dst, .proto = proto, .src_port = sp, .dst_port = dp };
    try wire.appendNfgenmsg(arena, &list, fam, 0);
    try wire.appendTuple(arena, &list, wire.CTA.TUPLE_ORIG, orig);
    try wire.appendTuple(arena, &list, wire.CTA.TUPLE_REPLY, orig.invert());
    try codec.appendAttrBe32(arena, &list, wire.CTA.STATUS, wire.IPS.SEEN_REPLY | wire.IPS.CONFIRMED | (r.int(u32) & wire.IPS.ASSURED));
    if (!udp) {
        const pi = try codec.nestBegin(arena, &list, codec.NLA_F_NESTED | wire.CTA.PROTOINFO);
        const tcp = try codec.nestBegin(arena, &list, codec.NLA_F_NESTED | wire.CTA_PROTOINFO.TCP);
        try codec.appendAttrU8(arena, &list, wire.CTA_PROTOINFO_TCP.STATE, r.intRangeAtMost(u8, 1, 9));
        try codec.appendAttrU8(arena, &list, wire.CTA_PROTOINFO_TCP.WSCALE_ORIGINAL, 7);
        try codec.appendAttrU8(arena, &list, wire.CTA_PROTOINFO_TCP.WSCALE_REPLY, 7);
        try codec.appendAttr(arena, &list, wire.CTA_PROTOINFO_TCP.FLAGS_ORIGINAL, &.{ 0x0a, 0x0a });
        try codec.appendAttr(arena, &list, wire.CTA_PROTOINFO_TCP.FLAGS_REPLY, &.{ 0x0a, 0x0a });
        try codec.nestEnd(&list, tcp);
        try codec.nestEnd(&list, pi);
    }
    const rich = i % 2 == 0;
    if (rich) {
        inline for (.{ wire.CTA.COUNTERS_ORIG, wire.CTA.COUNTERS_REPLY }) |ty| {
            const c = try codec.nestBegin(arena, &list, codec.NLA_F_NESTED | ty);
            try codec.appendAttrBe64(arena, &list, wire.CTA_COUNTERS.PACKETS, r.int(u32));
            try codec.appendAttrBe64(arena, &list, wire.CTA_COUNTERS.BYTES, r.int(u40));
            try codec.nestEnd(&list, c);
        }
        const ts = try codec.nestBegin(arena, &list, codec.NLA_F_NESTED | wire.CTA.TIMESTAMP);
        try codec.appendAttrBe64(arena, &list, wire.CTA_TIMESTAMP.START, r.int(u60));
        try codec.nestEnd(&list, ts);
        try codec.appendAttrBe16(arena, &list, wire.CTA.ZONE, r.intRangeAtMost(u16, 1, 100));
    }
    try codec.appendAttrBe32(arena, &list, wire.CTA.TIMEOUT, r.intRangeAtMost(u32, 1, 432000));
    try codec.appendAttrBe32(arena, &list, wire.CTA.MARK, r.int(u32));
    try codec.appendAttrBe32(arena, &list, wire.CTA.ID, r.int(u32));
    try codec.appendAttrBe32(arena, &list, wire.CTA.USE, 1);
    return list.items;
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
    var prng = std.Random.DefaultPrng.init(0xc017_7ac4);
    const r = prng.random();
    for (&c.payloads, 0..) |*p, i| p.* = try buildFlow(arena, r, i);
    try writeFrames(arena, io, dir, "dec_flow.bin", &c.payloads);
    for (&c.dgrams, 0..) |*d, k| {
        var list: std.ArrayList(u8) = .empty;
        for (c.payloads[k * per_dgram ..][0..per_dgram]) |p| {
            // Whole messages the way the kernel frames a dump record:
            // IPCTNL_MSG_CT_NEW, NLM_F_MULTI, then the payload.
            const hdr = try codec.appendHeader(arena, &list, wire.msg_ct_new, codec.NLM_F_MULTI, 1, 0);
            try list.appendSlice(arena, p);
            codec.finishHeader(&list, hdr);
        }
        d.* = list.items;
    }
    try writeFrames(arena, io, dir, "dec_dgram.bin", &c.dgrams);
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
        .{ .name = "dec_flow", .op = .dec_flow, .ref = "dec_flow", .wall_only = true },
        .{ .name = "dec_dgram", .op = .dec_dgram, .ref = "dec_dgram", .wall_only = true },
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

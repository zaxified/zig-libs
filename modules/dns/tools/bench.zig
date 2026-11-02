// SPDX-License-Identifier: MIT

//! Comparative benchmark: `dns` against Go's `golang.org/x/net/dns/dnsmessage`
//! v0.59.0 (the reference, `tools/go_bench`; the pin is the one of
//! `tools/go_oracle`), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-dns` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! golang.org/x/net v0.59.0 in the module cache (`GOPROXY=off`). Run from the
//! repository root. CPU-bound codec loops only: no socket is involved.
//!
//! One op = 64 inputs of a fixed seed, written by this driver into
//! `.zig-cache/bench-dns/` (the Go side reads the same files):
//!   enc_query   encode an A query + EDNS0 OPT (1232) for 64 names of 1-6
//!               labels, 7-60 chars. Compression OFF on both sides (a query
//!               has one name). Ours `encodeQuery` into a stack buffer + a
//!               `dupe` of the result; Go `NewBuilder(make([]byte, 0, 512))`,
//!               `StartQuestions`, `Question`, `StartAdditionals`,
//!               `OPTResource` (`SetEDNS0`), `Finish` -- the same wire bytes,
//!               count = sum of all output bytes.
//!   dec_small   a typical A answer: question, 2 CNAMEs, 2 A, OPT, owner and
//!               rdata names compressed.
//!   dec_big     a ~4 KB answer: 20 answers (4 MX, 8 TXT of 2 x 220 bytes,
//!               4 SRV, 4 NS), 8 glue A + OPT, heavy compression.
//!   dec_ptr     a PTR answer (reverse name, one record), the zpinger trace path.
//!   names_deep  names of up to 127 labels reached through 8-10 chained
//!               compression pointers (Go refuses more than 10 jumps).
//! The dec_* ops decode each message completely. Ours `decode` (all strings
//! in the message arena over `smp_allocator`) then `deinit`; Go `Parser`
//! `Start`, `AllQuestions`, `AllAnswers`, `AllAuthorities`, `AllAdditionals`
//! (typed bodies, slices allocated by the GC), then every name is turned into
//! a string with `Name.String()` (ours are strings already). Both then walk
//! the result and add up: one per question and record, the length of each
//! owner name (no root dot), per record the TTL (not OPT), and per type: the
//! address bytes, the length of the target name, MX preference / SRV port,
//! the TXT bytes, the OPT payload size. The counts must agree or the run
//! fails. Ratios are ours/Go by wall time; the verdict is the WORST ratio.
//! Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const dns = @import("dns");

const ref_short = "Go";
const ref_card = "Go dnsmessage v0.59.0";
const bench_name = "bench-dns";
const work_dir = ".zig-cache/bench-dns";
const go_dir = "modules/dns/tools/go_bench";
const N = 64;

const Op = enum { enc_query, dec_small, dec_big, dec_ptr, names_deep };

const Ctx = struct {
    op: Op = .enc_query,
    names: [N][]const u8 = undefined,
    msgs: [5][N][]const u8 = undefined, // indexed by Op; [0] unused
};

// ── the timed ops ────────────────────────────────────────────────────────────

fn once(c: *Ctx) u64 {
    return run(c) catch |e| std.debug.panic("{s}: {t}", .{ bench_name, e });
}

fn run(c: *Ctx) !u64 {
    const a = std.heap.smp_allocator;
    var t: u64 = 0;
    switch (c.op) {
        .enc_query => {
            var buf: [dns.max_query_len]u8 = undefined;
            for (c.names) |n| {
                const q = try dns.encodeQuery(&buf, n, .a, .{ .id = 0, .recursion_desired = true, .edns_udp_size = 1232 });
                const out = try a.dupe(u8, q);
                for (out) |b| t += b;
                a.free(out);
            }
        },
        else => for (c.msgs[@backingInt(c.op)]) |m| {
            var msg = try dns.decode(a, m);
            t +%= countMessage(&msg);
            msg.deinit();
        },
    }
    return t;
}

fn nameLen(s: []const u8) u64 {
    return if (s.len > 0 and s[s.len - 1] == '.') s.len - 1 else s.len;
}

fn countRecord(r: dns.Record) u64 {
    var t: u64 = 1 + nameLen(r.name);
    if (r.data != .opt) t +%= r.ttl;
    switch (r.data) {
        .a => |v| for (v) |b| {
            t += b;
        },
        .aaaa => |v| for (v) |b| {
            t += b;
        },
        .cname, .ns, .ptr => |s| t += nameLen(s),
        .mx => |m| t += @as(u64, m.preference) + nameLen(m.exchange),
        .txt => |ss| for (ss) |s| {
            t += s.len;
        },
        .srv => |s| t += @as(u64, s.port) + nameLen(s.target),
        .opt => |o| t += o.udp_payload_size,
        else => {},
    }
    return t;
}

fn countMessage(m: *const dns.Message) u64 {
    var t: u64 = 0;
    for (m.questions) |q| t += 1 + nameLen(q.name);
    for (m.answers) |r| t +%= countRecord(r);
    for (m.authorities) |r| t +%= countRecord(r);
    for (m.additionals) |r| t +%= countRecord(r);
    return t;
}

// ── the corpus ───────────────────────────────────────────────────────────────

const Wire = struct {
    a: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,
    /// Name suffix (text) -> wire offset of its first literal label.
    seen: std.StringHashMapUnmanaged(u16) = .empty,

    fn u8_(w: *Wire, v: u8) !void {
        try w.buf.append(w.a, v);
    }
    fn u16_(w: *Wire, v: u16) !void {
        try w.buf.appendSlice(w.a, &.{ @truncate(v >> 8), @truncate(v) });
    }
    fn u32_(w: *Wire, v: u32) !void {
        try w.u16_(@truncate(v >> 16));
        try w.u16_(@truncate(v));
    }
    fn raw(w: *Wire, s: []const u8) !void {
        try w.buf.appendSlice(w.a, s);
    }
    fn header(w: *Wire, id: u16, an: u16, ns: u16, ar: u16) !void {
        try w.u16_(id);
        try w.u16_(0x8180);
        try w.u16_(1);
        try w.u16_(an);
        try w.u16_(ns);
        try w.u16_(ar);
    }
    /// A name in wire format; with `compress`, a suffix already seen becomes a
    /// pointer, and every suffix written is remembered. `text` must stay alive
    /// (arena strings only).
    fn name(w: *Wire, text: []const u8, compress: bool) !void {
        var rest = text;
        while (rest.len > 0) {
            if (compress) {
                if (w.seen.get(rest)) |off| return w.u16_(0xC000 | off);
                if (w.buf.items.len < 0x3FFF) try w.seen.put(w.a, rest, @intCast(w.buf.items.len));
            }
            const dot = std.mem.findScalar(u8, rest, '.') orelse rest.len;
            try w.u8_(@intCast(dot));
            try w.raw(rest[0..dot]);
            rest = if (dot < rest.len) rest[dot + 1 ..] else rest[rest.len..];
        }
        try w.u8_(0);
    }
    /// Owner + type + class + ttl + a zero RDLENGTH placeholder; returns the
    /// offset to patch with `endRdata`.
    fn rrHead(w: *Wire, owner: []const u8, ty: dns.Type, ttl: u32) !usize {
        try w.name(owner, true);
        try w.u16_(@backingInt(ty));
        try w.u16_(1);
        try w.u32_(ttl);
        try w.u16_(0);
        return w.buf.items.len;
    }
    fn endRdata(w: *Wire, start: usize) void {
        const len = w.buf.items.len - start;
        w.buf.items[start - 2] = @truncate(len >> 8);
        w.buf.items[start - 1] = @truncate(len);
    }
    fn opt(w: *Wire) !void {
        try w.u8_(0);
        try w.u16_(@backingInt(dns.Type.opt));
        try w.u16_(1232);
        try w.u32_(0);
        try w.u16_(0);
    }
};

fn randLabel(arena: std.mem.Allocator, r: std.Random, len: usize) ![]u8 {
    const alpha = "abcdefghijklmnopqrstuvwxyz0123456789";
    const s = try arena.alloc(u8, len);
    for (s) |*c| c.* = alpha[r.uintLessThan(usize, alpha.len)];
    return s;
}

fn domain(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const tlds = [_][]const u8{ "com", "net", "org", "io", "cz" };
    return arena.print("{s}.{s}", .{ try randLabel(arena, r, r.intRangeAtMost(usize, 5, 12)), tlds[r.uintLessThan(usize, tlds.len)] });
}

fn queryName(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const labels = r.intRangeAtMost(usize, 1, 6);
    const total = r.intRangeAtMost(usize, @max(7, 2 * labels - 1), 60);
    const chars = total - (labels - 1);
    var out: std.ArrayList(u8) = .empty;
    for (0..labels) |i| {
        if (i > 0) try out.append(arena, '.');
        const l = chars / labels + @intFromBool(i < chars % labels);
        try out.appendSlice(arena, try randLabel(arena, r, l));
    }
    return out.items;
}

fn ip4(r: std.Random) u32 {
    return r.int(u32);
}

fn buildSmall(arena: std.mem.Allocator, r: std.Random, id: u16) ![]const u8 {
    var w: Wire = .{ .a = arena };
    const host = try arena.print("{s}.{s}", .{ try randLabel(arena, r, r.intRangeAtMost(usize, 3, 8)), try domain(arena, r) });
    const cdn = try domain(arena, r);
    const c1 = try arena.print("edge{d}.cdn.{s}", .{ id, cdn });
    const c2 = try arena.print("srv{d}.cdn.{s}", .{ id, cdn });
    try w.header(id, 4, 0, 1);
    try w.name(host, true);
    try w.u16_(1);
    try w.u16_(1);
    var s = try w.rrHead(host, .cname, 3600);
    try w.name(c1, true);
    w.endRdata(s);
    s = try w.rrHead(c1, .cname, 600);
    try w.name(c2, true);
    w.endRdata(s);
    for (0..2) |_| {
        s = try w.rrHead(c2, .a, 300);
        try w.u32_(ip4(r));
        w.endRdata(s);
    }
    try w.opt();
    return w.buf.items;
}

fn txtBody(w: *Wire, arena: std.mem.Allocator, r: std.Random) !void {
    for (0..2) |_| {
        const l = try randLabel(arena, r, 220);
        try w.u8_(220);
        try w.raw(l);
    }
}

fn buildBig(arena: std.mem.Allocator, r: std.Random, id: u16) ![]const u8 {
    var w: Wire = .{ .a = arena };
    const dom = try domain(arena, r);
    try w.header(id, 20, 0, 9);
    try w.name(dom, true);
    try w.u16_(@backingInt(dns.Type.mx));
    try w.u16_(1);
    var mail: [4][]const u8 = undefined;
    var nsn: [4][]const u8 = undefined;
    for (0..4) |i| {
        mail[i] = try arena.print("mail{d}.{s}", .{ i, dom });
        nsn[i] = try arena.print("ns{d}.{s}", .{ i, dom });
    }
    for (0..4) |i| {
        const s = try w.rrHead(dom, .mx, 3600);
        try w.u16_(@intCast(10 * (i + 1)));
        try w.name(mail[i], true);
        w.endRdata(s);
    }
    for (0..8) |_| {
        const s = try w.rrHead(dom, .txt, 300);
        try txtBody(&w, arena, r);
        w.endRdata(s);
    }
    const srv_owner = try arena.print("_sip._tcp.{s}", .{dom});
    for (0..4) |i| {
        const s = try w.rrHead(srv_owner, .srv, 3600);
        try w.u16_(@intCast(i));
        try w.u16_(@intCast(10 + i));
        try w.u16_(5060);
        try w.name(try arena.print("sip{d}.{s}", .{ i, dom }), true);
        w.endRdata(s);
    }
    for (0..4) |i| {
        const s = try w.rrHead(dom, .ns, 86400);
        try w.name(nsn[i], true);
        w.endRdata(s);
    }
    for (0..4) |i| {
        const s = try w.rrHead(nsn[i], .a, 3600);
        try w.u32_(ip4(r));
        w.endRdata(s);
    }
    for (0..4) |i| {
        const s = try w.rrHead(mail[i], .a, 3600);
        try w.u32_(ip4(r));
        w.endRdata(s);
    }
    try w.opt();
    return w.buf.items;
}

fn buildPtr(arena: std.mem.Allocator, r: std.Random, id: u16) ![]const u8 {
    var w: Wire = .{ .a = arena };
    const ip = ip4(r);
    const rev = try arena.print("{d}.{d}.{d}.{d}.in-addr.arpa", .{ ip & 255, (ip >> 8) & 255, (ip >> 16) & 255, ip >> 24 });
    try w.header(id, 1, 0, 0);
    try w.name(rev, true);
    try w.u16_(@backingInt(dns.Type.ptr));
    try w.u16_(1);
    const s = try w.rrHead(rev, .ptr, 3600);
    try w.name(try arena.print("{s}.{s}", .{ try randLabel(arena, r, r.intRangeAtMost(usize, 4, 10)), try domain(arena, r) }), false);
    w.endRdata(s);
    return w.buf.items;
}

/// 127 one-char labels in 10 segments (7 x 13 + 3 x 12), each segment ending
/// in a pointer to the one before; the question is the first segment, the
/// answers own segment k = 1..9 and a bare pointer to the last (10 jumps).
fn buildDeep(arena: std.mem.Allocator, r: std.Random, id: u16) ![]const u8 {
    var w: Wire = .{ .a = arena };
    try w.header(id, 10, 0, 0);
    var prev: u16 = 12;
    var starts: [10]u16 = undefined;
    for (0..10) |k| {
        const nl: usize = if (k < 7) 13 else 12;
        starts[k] = @intCast(w.buf.items.len);
        for (0..nl) |_| {
            try w.u8_(1);
            try w.u8_("abcdefghijklmnopqrstuvwxyz"[r.uintLessThan(usize, 26)]);
        }
        if (k == 0) {
            try w.u8_(0);
            try w.u16_(@backingInt(dns.Type.a));
            try w.u16_(1);
        } else {
            try w.u16_(0xC000 | prev);
            try w.u16_(@backingInt(dns.Type.a));
            try w.u16_(1);
            try w.u32_(60);
            try w.u16_(4);
            try w.u32_(ip4(r));
        }
        prev = starts[k];
    }
    try w.u16_(0xC000 | prev);
    try w.u16_(@backingInt(dns.Type.a));
    try w.u16_(1);
    try w.u32_(60);
    try w.u16_(4);
    try w.u32_(ip4(r));
    return w.buf.items;
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
    var prng = std.Random.DefaultPrng.init(0xd45_b3c4);
    const r = prng.random();
    var names: std.ArrayList(u8) = .empty;
    for (0..N) |i| {
        c.names[i] = try queryName(arena, r);
        try names.appendSlice(arena, c.names[i]);
        try names.append(arena, '\n');
    }
    try dir.writeFile(io, .{ .sub_path = "names.txt", .data = names.items });
    inline for (.{
        .{ Op.dec_small, "dec_small.bin", buildSmall },
        .{ Op.dec_big, "dec_big.bin", buildBig },
        .{ Op.dec_ptr, "dec_ptr.bin", buildPtr },
        .{ Op.names_deep, "names_deep.bin", buildDeep },
    }) |b| {
        const slot = &c.msgs[@backingInt(b[0])];
        for (slot, 0..) |*m, i| m.* = try b[2](arena, r, @intCast(i));
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
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var ctx: Ctx = .{};
    try setup(arena, io, dir, &ctx);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "enc_query", .op = .enc_query, .ref = "enc_query", .wall_only = true },
        .{ .name = "dec_small", .op = .dec_small, .ref = "dec_small", .wall_only = true },
        .{ .name = "dec_big", .op = .dec_big, .ref = "dec_big", .wall_only = true },
        .{ .name = "dec_ptr", .op = .dec_ptr, .ref = "dec_ptr", .wall_only = true },
        .{ .name = "names_deep", .op = .names_deep, .ref = "names_deep", .wall_only = true },
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

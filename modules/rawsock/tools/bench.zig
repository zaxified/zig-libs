// SPDX-License-Identifier: MIT

//! Comparative benchmark: `rawsock`'s pure-userspace paths against libpcap
//! 1.10.6 (the reference; `tools/c_bench.c`, linked against the system's
//! libpcap.so, its few declarations written out so no headers are needed). The
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md section 9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-rawsock` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `cc` and the
//! system's libpcap.so.0.8 (`LIBPCAP` overrides the path). Run from the
//! repository root. CPU-bound loops only: no socket is involved.
//!
//! LIVE CAPTURE IS NOT A ROW. `Socket.recv` and libpcap's `pcap_next_ex` both
//! end in the same `recvfrom`/`recvmsg` on the same AF_PACKET socket; the
//! kernel's cost is the same on both sides, so a ratio would measure the
//! harness. The one place libpcap does something different is its
//! `TPACKET_V3` ring (mmap'd blocks instead of one syscall per frame), which
//! this module does not have (SPEC.md, Backlog) and which is therefore not
//! measured against it.
//!
//! One op, both sides doing the same work on the same bytes (the corpus is
//! written by this driver into `.zig-cache/bench-rawsock/`: 10 000 frames,
//! ARP / IPv4 TCP, UDP, ICMP / IPv6 TCP, UDP, sizes 42..1514, fixed seed):
//!   compile      eight tcpdump expressions (ports, nets, offset expressions,
//!                IPv6 prefixes, `len`) to a classic-BPF program, freed again.
//!                Ours `filter.compile` (unoptimised code); libpcap
//!                `pcap_compile(.., optimize = 0)`. Count = expressions
//!                compiled (8): the programs differ (libpcap's code generator
//!                is smarter) so lengths are not compared.
//!   compile_opt  INFO row, not in the verdict: the same against
//!                `pcap_compile(.., optimize = 1)`, which is what tcpdump
//!                ships; ours has no optimiser (SPEC.md, rejected: never
//!                different in meaning).
//!   filter_run   the eight programs OUR compiler emitted (written to the work
//!                directory) run over the first 2 000 frames: ours
//!                `filter.run`, libpcap `pcap_offline_filter` (its userspace
//!                `bpf_filter`). The identical program on both sides, so this
//!                pairs interpreter against interpreter. Count = frames
//!                accepted, summed over the programs.
//!   filter_run_lp  the same, over libpcap's OWN optimised programs for the
//!                eight expressions (`pcap_compile(.., optimize = 1)`, what
//!                `tcpdump -dd` prints, written by the C side); ours runs the
//!                same instructions. Count = frames accepted.
//!   pcap_read    the whole classic savefile (a slice in memory on our side; an
//!                in-memory `FILE` from `fmemopen` through
//!                `pcap_fopen_offline` on libpcap's, which has no slice API and
//!                copies each record out through stdio). Count = sum of
//!                captured length + wire length + microsecond timestamp.
//!   pcap_write   the same frames written to a memory buffer: ours
//!                `pcap.writeRecord` into a fixed `Writer`, libpcap
//!                `pcap_dump` to a `fmemopen` stream. Count = bytes written.
//!   pcapng_read  our `pcapng` writer's file read back: ours `pcapng.Reader`,
//!                libpcap `pcap_next_ex` (libpcap reads pcapng; 1.10 cannot
//!                write it, so there is no write row). Count as pcap_read
//!                (libpcap reports microseconds, ours is divided to match).
//! Build: ours ReleaseFast (build.zig compiles every bench `.fast`); the C side
//! `cc -O3 -march=native` against the DISTRO's libpcap.so.0.8 1.10.6 (a build
//! from the pinned source tarball was not possible in the 2026-11-03 fix round,
//! see SPEC). `-Djcc-safe` (`BENCH_JCC_SAFE`) adds the JCC-erratum assembler
//! flag to the C side and re-assembles ours; the card's numbers were measured
//! WITHOUT it. Default rounds: 11 (`BENCH_ROUNDS`), best of each side.

const std = @import("std");
const bench = @import("testkit").bench;
const rawsock = @import("rawsock");
const filter = rawsock.filter;
const pcap = rawsock.pcap;
const pcapng = rawsock.pcapng;

const bench_name = "bench-rawsock";
const work_dir = ".zig-cache/bench-rawsock";
const n_frames = 10_000;
const n_run_frames = 2_000;

const exprs = [_][]const u8{
    "tcp dst port 22 and not ip src net 10.0.0.0/8",
    "host 10.1.2.3 or host 10.1.2.4",
    "udp portrange 5000-5400",
    "ip6 net 2001:db8::/32 and tcp",
    "ip[6:2] & 0x1fff = 0 and tcp[13] & 2 != 0",
    "arp or rarp",
    "len <= 100 and not multicast",
    "(tcp port 80 or tcp port 443) and ip dst net 192.0.2.0/24",
};

const Op = enum { compile, compile_opt, filter_run, filter_run_lp, pcap_read, pcap_write, pcapng_read };

const Rec = struct { ts_ns: u64, data: []const u8 };

const Ctx = struct {
    op: Op = .compile,
    frames: []const Rec = &.{},
    progs: []const []const rawsock.BpfInsn = &.{},
    /// libpcap's own optimised programs for the same expressions (`dump_progs`).
    lp_progs: []const []const rawsock.BpfInsn = &.{},
    pcap_bytes: []const u8 = &.{},
    ng_bytes: []const u8 = &.{},
    out: []u8 = &.{},
};

const gpa = std.heap.smp_allocator;

fn once(c: *Ctx) u64 {
    switch (c.op) {
        .compile, .compile_opt => {
            var n: u64 = 0;
            for (exprs) |e| {
                const p = filter.compile(gpa, e) catch @panic("bench-rawsock: compile");
                gpa.free(p);
                n += 1;
            }
            return n;
        },
        .filter_run, .filter_run_lp => {
            var n: u64 = 0;
            for (if (c.op == .filter_run) c.progs else c.lp_progs) |p| {
                for (c.frames[0..n_run_frames]) |f| {
                    if (filter.run(p, f.data) != 0) n += 1;
                }
            }
            return n;
        },
        .pcap_read => {
            var r = pcap.Reader.init(c.pcap_bytes) catch @panic("bench-rawsock: pcap header");
            var sum: u64 = 0;
            while (r.next() catch @panic("bench-rawsock: pcap record")) |rec| {
                sum +%= rec.data.len + rec.orig_len + rec.ts_ns / 1000;
            }
            return sum;
        },
        .pcap_write => {
            var w: std.Io.Writer = .fixed(c.out);
            pcap.writeHeader(&w, .{}) catch @panic("bench-rawsock: header");
            for (c.frames) |f| pcap.writeRecord(&w, .micro, f.ts_ns, @intCast(f.data.len), f.data) catch @panic("bench-rawsock: record");
            return w.buffered().len;
        },
        .pcapng_read => {
            var r = pcapng.Reader.init(c.ng_bytes) catch @panic("bench-rawsock: pcapng header");
            var sum: u64 = 0;
            while (r.next() catch @panic("bench-rawsock: pcapng record")) |rec| {
                sum +%= rec.data.len + rec.orig_len + rec.ts_ns / 1000;
            }
            return sum;
        },
    }
}

// ── the corpus ───────────────────────────────────────────────────────────────

fn put16(b: []u8, at: usize, v: u16) void {
    std.mem.writeInt(u16, b[at..][0..2], v, .big);
}

fn makeFrame(arena: std.mem.Allocator, r: std.Random) ![]u8 {
    const kind = r.uintLessThan(u8, 100);
    const size: usize = blk: {
        const s = r.uintLessThan(u8, 10);
        if (s < 5) break :blk r.intRangeAtMost(usize, 60, 120);
        if (s < 8) break :blk r.intRangeAtMost(usize, 121, 600);
        break :blk r.intRangeAtMost(usize, 1400, 1514);
    };
    if (kind < 5) { // ARP request or reply, 42 bytes
        const f = try arena.alloc(u8, 42);
        r.bytes(f);
        @memcpy(f[0..6], &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });
        put16(f, 12, 0x0806);
        put16(f, 14, 1);
        put16(f, 16, 0x0800);
        f[18] = 6;
        f[19] = 4;
        put16(f, 20, 1 + r.uintLessThan(u16, 2));
        f[38] = 10;
        return f;
    }
    const f = try arena.alloc(u8, size);
    r.bytes(f);
    f[0] = if (r.uintLessThan(u8, 20) == 0) 0x01 else 0x02; // a multicast destination now and then
    f[6] = 0x02;
    if (kind < 70) { // IPv4
        put16(f, 12, 0x0800);
        f[14] = 0x45;
        put16(f, 16, @intCast(size - 14));
        put16(f, 20, if (r.uintLessThan(u8, 10) == 0) 0x2000 else 0x4000); // MF now and then
        const proto: u8 = switch (r.uintLessThan(u8, 10)) {
            0...5 => 6,
            6...8 => 17,
            else => 1,
        };
        f[22] = 64;
        f[23] = proto;
        const nets = [_][4]u8{ .{ 10, 1, 2, 3 }, .{ 10, 1, 2, 4 }, .{ 192, 0, 2, 9 }, .{ 172, 16, 0, 1 } };
        @memcpy(f[26..30], &nets[r.uintLessThan(usize, nets.len)]);
        @memcpy(f[30..34], &nets[r.uintLessThan(usize, nets.len)]);
        const ports = [_]u16{ 22, 80, 443, 53, 5100, 5400, 8080 };
        put16(f, 34, ports[r.uintLessThan(usize, ports.len)]);
        put16(f, 36, ports[r.uintLessThan(usize, ports.len)]);
        f[47] = if (proto == 6) @as(u8, if (r.boolean()) 0x02 else 0x10) else f[47];
    } else { // IPv6
        put16(f, 12, 0x86dd);
        f[14] = 0x60;
        f[20] = if (r.boolean()) 6 else 17;
        @memcpy(f[22..26], &[_]u8{ 0x20, 0x01, 0x0d, 0xb8 });
        const ports = [_]u16{ 22, 80, 443, 53, 5100 };
        put16(f, 54, ports[r.uintLessThan(usize, ports.len)]);
        put16(f, 56, ports[r.uintLessThan(usize, ports.len)]);
    }
    return f;
}

fn writeBin(io: std.Io, dir: std.Io.Dir, name: []const u8, prog: []const rawsock.BpfInsn) !void {
    try dir.writeFile(io, .{ .sub_path = name, .data = std.mem.sliceAsBytes(prog) });
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
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 11;

    var prng = std.Random.DefaultPrng.init(0x4a5_2026_1103);
    const r = prng.random();
    const frames = try arena.alloc(Rec, n_frames);
    var pcap_out: std.Io.Writer.Allocating = .init(arena);
    var ng_out: std.Io.Writer.Allocating = .init(arena);
    try pcap.writeHeader(&pcap_out.writer, .{});
    try pcapng.writeHeader(&ng_out.writer, .{});
    for (frames, 0..) |*f, i| {
        const data = try makeFrame(arena, r);
        const ts_ns = (1_700_000_000 + i) * std.time.ns_per_s + r.uintLessThan(u64, 1_000_000) * 1000;
        f.* = .{ .ts_ns = ts_ns, .data = data };
        try pcap.writeRecord(&pcap_out.writer, .micro, ts_ns, @intCast(data.len), data);
        try pcapng.writeRecord(&ng_out.writer, .nano, ts_ns, @intCast(data.len), data);
    }
    try dir.writeFile(io, .{ .sub_path = "frames.pcap", .data = pcap_out.written() });
    try dir.writeFile(io, .{ .sub_path = "frames.pcapng", .data = ng_out.written() });
    var list: std.Io.Writer.Allocating = .init(arena);
    for (exprs) |e| try list.writer.print("{s}\n", .{e});
    try dir.writeFile(io, .{ .sub_path = "exprs.txt", .data = list.written() });
    const progs = try arena.alloc([]const rawsock.BpfInsn, exprs.len);
    for (exprs, progs, 0..) |e, *p, i| {
        p.* = try filter.compile(arena, e);
        try writeBin(io, dir, try std.fmt.allocPrint(arena, "prog_{d}.bin", .{i}), p.*);
    }
    std.debug.print("{s}: {d} frames, classic file {d} bytes, pcapng {d} bytes\n", .{ bench_name, n_frames, pcap_out.written().len, ng_out.written().len });

    var ctx: Ctx = .{ .frames = frames, .progs = progs, .pcap_bytes = pcap_out.written(), .ng_bytes = ng_out.written() };
    ctx.out = try arena.alloc(u8, pcap_out.written().len + 4096);

    const jcc_safe = init.environ_map.get("BENCH_JCC_SAFE") != null;
    const libpcap = init.environ_map.get("LIBPCAP") orelse "/usr/lib/x86_64-linux-gnu/libpcap.so.0.8";
    const c_exe = try bench.buildForeign(arena, io, bench_name, &.{ "cc", if (jcc_safe) "-Wa,-mbranches-within-32B-boundaries" else "-DNO_JCC_PADDING" }, abs, "modules/rawsock/tools/c_bench.c", &.{libpcap});

    // libpcap's own programs (written by the C side), read back as instructions.
    try bench.foreignOnce(arena, io, bench_name, c_exe, abs, "dump_progs");
    const lp_progs = try arena.alloc([]const rawsock.BpfInsn, exprs.len);
    for (lp_progs, 0..) |*p, i| {
        const bytes = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "prog_lp_{d}.bin", .{i}), arena, .limited(1 << 20));
        const insns = try arena.alloc(rawsock.BpfInsn, bytes.len / 8);
        @memcpy(std.mem.sliceAsBytes(insns), bytes[0 .. insns.len * 8]);
        p.* = insns;
    }
    ctx.lp_progs = lp_progs;

    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "compile", .op = .compile, .ref = "compile", .wall_only = true },
        .{ .name = "compile_opt", .op = .compile_opt, .ref = "compile_opt", .wall_only = true, .info = true },
        .{ .name = "filter_run", .op = .filter_run, .ref = "filter_run", .wall_only = true },
        .{ .name = "filter_run_lp", .op = .filter_run_lp, .ref = "filter_run_lp", .wall_only = true },
        .{ .name = "pcap_read", .op = .pcap_read, .ref = "pcap_read", .wall_only = true },
        .{ .name = "pcap_write", .op = .pcap_write, .ref = "pcap_write", .wall_only = true },
        .{ .name = "pcapng_read", .op = .pcapng_read, .ref = "pcapng_read", .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{c_exe},
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/libpcap = {d:.2} (best {d:.2})\n", .{ s.worst_ref, s.best_ref });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}-{d:.2}x libpcap 1.10.6 (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

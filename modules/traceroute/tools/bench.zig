// SPDX-License-Identifier: MIT

//! Comparative benchmark: `traceroute`'s wire path (the `icmp` codec it is
//! built on) against Go's `golang.org/x/net/icmp` v0.61.0 (the reference,
//! `tools/go_bench`), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-traceroute` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! golang.org/x/net v0.61.0 + golang.org/x/sys v0.49.0 in the module cache
//! (`GOPROXY=off`). Run from the repository root. CPU-bound codec loops only:
//! no socket is involved.
//!
//! One op = 64 inputs of a fixed seed, written by this driver into
//! `.zig-cache/bench-traceroute/` (the Go side reads the same files):
//!   enc_echo_v4  an ICMP Echo Request, 8-byte header + 24 zero payload bytes
//!                (traceroute's default probe), checksum filled. Ours
//!                `echo.writeEchoRequest` into a reused stack buffer (what
//!                `traceWith` does: `@memset` the payload, write the header),
//!                no allocation; Go `icmp.Message.Marshal(nil)` with an
//!                `icmp.Echo`, which allocates (the API returns a fresh slice).
//!                Count = sum of all output bytes.
//!   enc_echo_v6  the same for ICMPv6: no checksum on either side (the kernel
//!                fills it, it needs the pseudo-header).
//!   dec_te       a v4 Time Exceeded (code 0/1) quoting our whole 52-byte probe
//!                (IP header + echo + payload), as a Linux router sends it
//!                (60 bytes). Ours `echo.parseV4(.., false)` (verifies the
//!                ICMP checksum, finds the quoted echo, returns type, code,
//!                quoted dst, quoted ident/seq) + `mplsOf`; Go: the
//!                checksum (a local copy of x/net's unexported `checksum`:
//!                ParseMessage does not verify it and the hostile-intake path
//!                must), `icmp.ParseMessage` (type, code, body `TimeExceeded`
//!                with the quote copied out and the RFC 4884 extension
//!                attempt), `ipv4.ParseHeader` on the quote (quoted dst), and
//!                a second `icmp.ParseMessage` on the quoted bytes (quoted
//!                echo ident/seq: the only way x/net exposes them), then the
//!                MPLS labels of `Extensions`.
//!   dec_ext      the same with an RFC 4884 extension: the quote padded to
//!                128 bytes, extension header + one MPLS label stack of 2-4
//!                labels, checksums valid (~170 bytes). Ours also verifies the
//!                extension checksum (in `mplsOf`); so does x/net.
//!   dec_garbage  64 packets that are not ours: type 17, Time Exceeded
//!                quoting UDP, 0-7 byte stubs, and Time Exceeded with one
//!                flipped bit (bad checksum). Every one must be rejected; the
//!                count is the number rejected.
//! Both sides add up, per accepted packet: type, code, ident, seq, the four
//! bytes of the quoted dst, and per MPLS label label + tc + ttl + bottom; the
//! counts must agree or the run fails. Ratios are ours/Go by wall time; the
//! verdict is the WORST ratio. Arguments filter workloads.
//!
//! What x/net does that ours does not (so the rows are fair, not equal): the
//! `Message`/`Body` objects and the copy of the quote are heap-allocated
//! (GC); ours returns a value and keeps no bytes. What ours does that x/net
//! does not: it verifies the checksum itself (Go gets a local copy of the
//! loop) and refuses anything but a quoted echo/timestamp request.
//!
//! `trace_30` is INFORMATIONAL and Zig only: `traceWith` over a canned
//! 30-hop in-process transport (three probes per hop, reply at hop 30), the
//! whole engine per call, no reference. With a `parallel` option in `Options`
//! it is also run with `parallel = 16`.

const std = @import("std");
const bench = @import("testkit").bench;
const traceroute = @import("traceroute");
const icmp = @import("icmp");
const echo = icmp.echo;
const netaddr = @import("netaddr");

const ref_short = "Go";
const ref_card = "Go x/net/icmp v0.61.0";
const bench_name = "bench-traceroute";
const work_dir = ".zig-cache/bench-traceroute";
const go_dir = "modules/traceroute/tools/go_bench";
const N = 64;
const payload_len = 24;
const probe_len = echo.echo_header_len + payload_len;

const Op = enum { enc_echo_v4, enc_echo_v6, dec_te, dec_ext, dec_garbage };

const Ctx = struct {
    op: Op = .enc_echo_v4,
    ids: [N][2]u16 = undefined,
    msgs: [5][N][]const u8 = undefined, // indexed by Op; [0], [1] unused
};

// ── the timed ops ────────────────────────────────────────────────────────────

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    switch (c.op) {
        .enc_echo_v4, .enc_echo_v6 => {
            const fam: echo.Family = if (c.op == .enc_echo_v4) .v4 else .v6;
            var buf: [probe_len]u8 = undefined;
            for (c.ids) |id| {
                @memset(&buf, 0);
                echo.writeEchoRequest(fam, &buf, id[0], id[1]) catch @panic("bench-traceroute: buffer");
                for (buf) |b| t += b;
            }
        },
        .dec_te, .dec_ext => for (c.msgs[@backingInt(c.op)]) |m| {
            t +%= decodeOurs(m);
        },
        .dec_garbage => for (c.msgs[@backingInt(c.op)]) |m| {
            t +%= switch (echo.parseV4(m, false)) {
                .ignored => 1,
                else => 1000,
            };
        },
    }
    return t;
}

fn decodeOurs(m: []const u8) u64 {
    const r = echo.parseV4(m, false);
    const e = switch (r) {
        .icmp_error => |e| e,
        else => return 1000000,
    };
    var t: u64 = switch (e.kind) {
        .time_exceeded => 11,
        .dest_unreachable => 3,
        else => 99,
    };
    t += e.code;
    t += e.orig_ident;
    t += e.orig_seq;
    for (e.quoted_dst[0..4]) |b| t += b;
    const mpls = traceroute.mplsOf(.v4, m);
    for (mpls.slice()) |x| t += @as(u64, x.label) + x.tc + x.ttl + @intFromBool(x.bottom);
    return t;
}

// ── trace_30: the engine over a canned transport ─────────────────────────────

const hops_n = 30;

const Canned = struct {
    const Entry = struct { len: usize, from: netaddr.Ip, arrival: u64, bytes: [96]u8 };
    q: [256]Entry = undefined,
    n: usize = 0,
    clock: u64 = 1_000_000,
    sends: u64 = 0,
    dest: netaddr.Ip,

    fn transport(f: *Canned) traceroute.Transport {
        return .{ .ctx = f, .sendFn = send, .recvFn = recv, .nowFn = now };
    }

    fn now(ctx: *anyopaque) u64 {
        const f: *Canned = @ptrCast(@alignCast(ctx));
        return f.clock;
    }

    fn send(ctx: *anyopaque, ttl: u8, packet: []const u8) traceroute.TransportError!void {
        const f: *Canned = @ptrCast(@alignCast(ctx));
        f.sends += 1;
        if (f.n == f.q.len) return error.SendFailed;
        const e = &f.q[f.n];
        f.n += 1;
        e.arrival = f.clock + f.sends * std.time.ns_per_ms;
        @memset(&e.bytes, 0);
        if (ttl >= hops_n) {
            @memcpy(e.bytes[0..packet.len], packet);
            e.bytes[0] = echo.v4.echo_reply;
            e.len = packet.len;
            e.from = f.dest;
        } else {
            e.bytes[0] = echo.v4.time_exceeded;
            e.bytes[8] = 0x45;
            @memcpy(e.bytes[8 + 16 ..][0..4], &f.dest.v4);
            @memcpy(e.bytes[8 + 20 ..][0..echo.echo_header_len], packet[0..echo.echo_header_len]);
            e.len = 8 + 20 + echo.echo_header_len;
            e.from = .{ .v4 = .{ 10, 0, ttl, 1 } };
        }
        std.mem.writeInt(u16, e.bytes[2..4], 0, .big);
        std.mem.writeInt(u16, e.bytes[2..4], echo.checksum(e.bytes[0..e.len]), .big);
    }

    fn recv(ctx: *anyopaque, buf: []u8, timeout_ns: u64) traceroute.TransportError!?traceroute.Packet {
        const f: *Canned = @ptrCast(@alignCast(ctx));
        var best: ?usize = null;
        for (f.q[0..f.n], 0..) |c, i| {
            if (c.arrival > f.clock + timeout_ns) continue;
            if (best == null or c.arrival < f.q[best.?].arrival) best = i;
        }
        const i = best orelse {
            f.clock += timeout_ns;
            return null;
        };
        const c = f.q[i];
        f.n -= 1;
        f.q[i] = f.q[f.n];
        @memcpy(buf[0..c.len], c.bytes[0..c.len]);
        f.clock = @max(f.clock, c.arrival);
        return .{ .len = c.len, .from = c.from };
    }
};

const TraceCtx = struct { parallel: u8 = 1 };

fn trace30(c: *TraceCtx) u64 {
    var f: Canned = .{ .dest = .{ .v4 = .{ 192, 0, 2, 99 } } };
    var o: traceroute.Options = .{};
    if (comptime @hasField(traceroute.Options, "parallel")) o.parallel = c.parallel;
    var tr = traceroute.traceWith(std.heap.smp_allocator, f.transport(), f.dest, o) catch |e|
        std.debug.panic("{s}: trace_30: {t}", .{ bench_name, e });
    defer tr.deinit(std.heap.smp_allocator);
    if (!tr.reached) @panic("bench-traceroute: trace_30 did not reach the destination");
    return tr.hops.len;
}

// ── the corpus ───────────────────────────────────────────────────────────────

fn put16(b: []u8, v: u16) void {
    std.mem.writeInt(u16, b[0..2], v, .big);
}

fn fixSum(msg: []u8) void {
    put16(msg[2..], 0);
    put16(msg[2..], echo.checksum(msg));
}

/// The 52-byte probe as it sits on the wire: IPv4 header, echo request, 24
/// zero payload bytes.
fn quote(r: std.Random, ident: u16, seq: u16, out: *[20 + probe_len]u8) void {
    @memset(out, 0);
    out[0] = 0x45;
    put16(out[2..], 20 + probe_len);
    put16(out[4..], r.int(u16));
    put16(out[6..], 0x4000);
    out[8] = 1; // ttl, expired
    out[9] = 1; // ICMP
    std.mem.writeInt(u32, out[12..16], r.int(u32), .big);
    std.mem.writeInt(u32, out[16..20], r.int(u32), .big);
    put16(out[10..], echo.checksum(out[0..20]));
    out[20] = echo.v4.echo_request;
    put16(out[24..], ident);
    put16(out[26..], seq);
    put16(out[22..], echo.checksum(out[20..]));
}

fn buildTe(arena: std.mem.Allocator, r: std.Random, _: u16) ![]const u8 {
    var q: [20 + probe_len]u8 = undefined;
    quote(r, r.int(u16), r.int(u16), &q);
    const m = try arena.alloc(u8, 8 + q.len);
    @memset(m[0..8], 0);
    m[0] = echo.v4.time_exceeded;
    m[1] = r.uintLessThan(u8, 2);
    @memcpy(m[8..], &q);
    fixSum(m);
    return m;
}

fn buildExt(arena: std.mem.Allocator, r: std.Random, _: u16) ![]const u8 {
    var q: [20 + probe_len]u8 = undefined;
    quote(r, r.int(u16), r.int(u16), &q);
    const labels = r.intRangeAtMost(usize, 2, 4);
    const ext_len = 4 + 4 + 4 * labels;
    const m = try arena.alloc(u8, 8 + 128 + ext_len);
    @memset(m, 0);
    m[0] = echo.v4.time_exceeded;
    m[1] = r.uintLessThan(u8, 2);
    m[5] = 128 / 4;
    @memcpy(m[8..][0..q.len], &q);
    const ext = m[8 + 128 ..];
    ext[0] = 0x20; // version 2
    put16(ext[4..], @intCast(4 + 4 * labels)); // object length
    ext[6] = 1; // class: MPLS label stack
    ext[7] = 1; // c-type: incoming
    for (0..labels) |i| {
        const v: u32 = (r.int(u32) & 0xfffffe00) | (@as(u32, @intFromBool(i + 1 == labels)) << 8) | r.int(u8);
        std.mem.writeInt(u32, ext[8 + 4 * i ..][0..4], v, .big);
    }
    put16(ext[2..], echo.checksum(ext));
    fixSum(m);
    return m;
}

/// Four kinds of foreign packet, in turn.
fn buildGarbage(arena: std.mem.Allocator, r: std.Random, i: u16) ![]const u8 {
    switch (i % 4) {
        0 => { // type 17 (address mask request), valid checksum
            const m = try arena.alloc(u8, 12);
            r.bytes(m);
            m[0] = 17;
            m[1] = 0;
            fixSum(m);
            return m;
        },
        1 => { // Time Exceeded quoting a UDP datagram (source port 0xC0xx)
            var q: [20 + 8 + 24]u8 = undefined;
            r.bytes(&q);
            q[0] = 0x45;
            q[9] = 17;
            q[20] = 0xc0;
            const m = try arena.alloc(u8, 8 + q.len);
            @memset(m[0..8], 0);
            m[0] = echo.v4.time_exceeded;
            @memcpy(m[8..], &q);
            fixSum(m);
            return m;
        },
        2 => { // stub shorter than an ICMP echo header
            const m = try arena.alloc(u8, r.uintLessThan(usize, echo.echo_header_len));
            r.bytes(m);
            return m;
        },
        else => { // a good Time Exceeded with one bit flipped
            const m: []u8 = @constCast(try buildTe(arena, r, 0));
            m[8 + r.uintLessThan(usize, m.len - 8)] ^= @as(u8, 1) << r.int(u3);
            return m;
        },
    }
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
    var prng = std.Random.DefaultPrng.init(0x7452_ace0);
    const r = prng.random();
    var ids: std.ArrayList(u8) = .empty;
    for (&c.ids) |*id| {
        id.* = .{ r.int(u16), r.int(u16) };
        try ids.appendSlice(arena, &.{ @truncate(id[0] >> 8), @truncate(id[0]), @truncate(id[1] >> 8), @truncate(id[1]) });
    }
    try dir.writeFile(io, .{ .sub_path = "enc_echo.bin", .data = ids.items });
    inline for (.{
        .{ Op.dec_te, "dec_te.bin", buildTe },
        .{ Op.dec_ext, "dec_ext.bin", buildExt },
        .{ Op.dec_garbage, "dec_garbage.bin", buildGarbage },
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
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    var ctx: Ctx = .{};
    try setup(arena, io, dir, &ctx);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "enc_echo_v4", .op = .enc_echo_v4, .ref = "enc_echo_v4", .wall_only = true },
        .{ .name = "enc_echo_v6", .op = .enc_echo_v6, .ref = "enc_echo_v6", .wall_only = true },
        .{ .name = "dec_te", .op = .dec_te, .ref = "dec_te", .wall_only = true },
        .{ .name = "dec_ext", .op = .dec_ext, .ref = "dec_ext", .wall_only = true },
        .{ .name = "dec_garbage", .op = .dec_garbage, .ref = "dec_garbage", .wall_only = true },
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

    // trace_30: informational, ours only.
    const cyc: bench.Cycles = .open();
    defer cyc.close();
    var tc: TraceCtx = .{};
    const par = [_]u8{ 1, 16 };
    for (par) |p| {
        if (p != 1 and !@hasField(traceroute.Options, "parallel")) continue;
        tc.parallel = p;
        var best: f64 = std.math.inf(f64);
        for (0..rounds) |_| best = @min(best, bench.timeIt(io, cyc, trace30, .{&tc}, true).ns);
        try w.print("trace_30 parallel={d:<2}  {d:>11.0} ns/trace (informational, no reference)\n", .{ p, best });
    }
    try w.flush();
    return 0;
}

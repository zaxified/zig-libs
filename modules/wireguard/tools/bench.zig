// SPDX-License-Identifier: MIT

//! Comparative benchmark: `wireguard` (handshake + transport data path)
//! against a per-primitive composition of the same work in OpenSSL and
//! libsodium (the reference: neither the in-kernel WireGuard -- root and a
//! tunnel -- nor wireguard-go is available to time op for op here), the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-wireguard` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`), the
//! system OpenSSL 3 (`libcrypto.so.3`, or `LIBCRYPTO_SO`) and libsodium
//! (`libsodium.so.23`, or `SODIUM_SO`); no headers needed. Run from the
//! repository root.
//!
//! Workloads:
//!   seal_<n>   `transport.SendSession.seal` of an n-byte packet (header,
//!              pad to 16, AEAD, counter) vs the C composition (OpenSSL
//!              ChaCha20-Poly1305 + the same header and padding)
//!   open_<n>   `transport.RecvSession.open` of the next of 64 messages sealed
//!              with counters 0..63 (the replay window is reset once per 64
//!              opens, in our time) vs header parse + OpenSSL AEAD open of one
//!              sealed message
//!   handshake  one full handshake, both roles (`createInitiation`,
//!              `consumeInitiation`, `createResponse`, `consumeResponse`,
//!              fresh ephemerals from `io`) vs ONLY its X25519 work in
//!              libsodium (2 base + 8 variable-base scalar multiplications) --
//!              a lower bound on the reference, so this ratio is pessimistic
//! with n = 64 and 1420 (a 1500-byte MTU's payload). Inputs are written into
//! `.zig-cache/bench-wireguard/` from fixed seeds.
//!
//! Method (shared driver at the bottom): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them, else by
//! wall time. Before timing anything the composition's transport message for
//! counter 0 must equal ours byte for byte. Arguments filter workloads.

const std = @import("std");
const wireguard = @import("wireguard");
const hs = wireguard.handshake;
const transport = wireguard.transport;

const bench_name = "bench-wireguard";
const work_dir = ".zig-cache/bench-wireguard";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const default_sodium = "/usr/lib/x86_64-linux-gnu/libsodium.so.23";
const sizes = [_]usize{ 64, 1420 };
const now_s: u64 = 1_700_000_000;
const receiver: u32 = 0x1234_5678;
const ring_len = 64;

const Op = union(enum) { seal: usize, open: usize, handshake };

const Ctx = struct {
    io: std.Io,
    key: [32]u8,
    msgs: [sizes.len][]u8,
    ring: [sizes.len][ring_len][]u8,
    ring_pos: usize = 0,
    out: []u8,
    send: transport.SendSession,
    recv: transport.RecvSession,
    ini: hs.Handshake,
    rsp: hs.Handshake,
    op: Op = undefined,
};

fn sizeIndex(n: usize) usize {
    return std.mem.indexOfScalar(usize, &sizes, n).?;
}

fn once(x: *Ctx) usize {
    switch (x.op) {
        .seal => |n| return (x.send.seal(x.out, x.msgs[sizeIndex(n)], now_s) catch unreachable).len,
        .open => |n| {
            if (x.ring_pos == ring_len) {
                x.recv.window.reset();
                x.ring_pos = 0;
            }
            defer x.ring_pos += 1;
            return (x.recv.open(x.out, x.ring[sizeIndex(n)][x.ring_pos], now_s) catch unreachable).len;
        },
        .handshake => {
            var ini = x.ini;
            var rsp = x.rsp;
            const m1 = ini.createInitiation(x.io, @splat(0x42)) catch unreachable;
            rsp.consumeInitiation(m1) catch unreachable;
            const m2 = rsp.createResponse(x.io) catch unreachable;
            ini.consumeResponse(m2) catch unreachable;
            std.mem.doNotOptimizeAway(&ini);
            std.mem.doNotOptimizeAway(&rsp);
            return 2;
        },
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
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var prng = std.Random.DefaultPrng.init(0x3c_3a2d);
    const r = prng.random();
    var ctx: Ctx = undefined;
    ctx.io = io;
    r.bytes(&ctx.key);
    ctx.out = try arena.alloc(u8, 2048);
    try dir.writeFile(io, .{ .sub_path = "key.bin", .data = &ctx.key });
    var ri: [4]u8 = undefined;
    std.mem.writeInt(u32, &ri, receiver, .little);
    try dir.writeFile(io, .{ .sub_path = "receiver.bin", .data = &ri });
    ctx.send.init(&ctx.key, receiver, now_s);
    ctx.recv.init(&ctx.key, receiver, now_s);
    ctx.ring_pos = 0;
    for (sizes, 0..) |n, i| {
        ctx.msgs[i] = try arena.alloc(u8, n);
        r.bytes(ctx.msgs[i]);
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "msg{d}.bin", .{n}), .data = ctx.msgs[i] });
        var ring_sender: transport.SendSession = undefined;
        ring_sender.init(&ctx.key, receiver, now_s);
        for (&ctx.ring[i]) |*slot| {
            slot.* = try arena.alloc(u8, transport.sealedLen(n));
            _ = try ring_sender.seal(slot.*, ctx.msgs[i], now_s);
        }
    }

    var s_i: hs.PrivateKey = undefined;
    var s_r: hs.PrivateKey = undefined;
    r.bytes(&s_i);
    r.bytes(&s_r);
    try dir.writeFile(io, .{ .sub_path = "s_i.bin", .data = &s_i });
    try dir.writeFile(io, .{ .sub_path = "s_r.bin", .data = &s_r });
    var kp_i: hs.Keypair = undefined;
    var kp_r: hs.Keypair = undefined;
    try hs.Keypair.fromPrivateKey(&s_i, &kp_i);
    try hs.Keypair.fromPrivateKey(&s_r, &kp_r);
    ctx.ini = .{ .static_keypair = kp_i, .remote_static_public = kp_r.public, .local_index = 1 };
    ctx.rsp = .{ .static_keypair = kp_r, .remote_static_public = kp_i.public, .local_index = 2 };

    const so_c = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const so_s = init.environ_map.get("SODIUM_SO") orelse default_sodium;
    const exe = try buildForeign(arena, io, abs, "modules/wireguard/tools/c_bench/foreign_bench.c", &.{ so_c, so_s });

    // Interop before timing: counter 0 of msg1420 under a fresh session.
    try foreignOnce(arena, io, exe, abs, "interop");
    {
        var fresh: transport.SendSession = undefined;
        fresh.init(&ctx.key, receiver, now_s);
        const mine = ctx.out[0..(try fresh.seal(ctx.out, ctx.msgs[sizeIndex(1420)], now_s)).len];
        const theirs = try dir.readFileAlloc(io, "comp_sealed_1420.bin", arena, .limited(4096));
        if (!std.mem.eql(u8, mine, theirs)) {
            std.debug.print("bench-wireguard: FAILED -- the composed transport message differs from ours\n", .{});
            return 1;
        }
    }
    // And one handshake must complete before it is timed.
    ctx.op = .handshake;
    _ = once(&ctx);

    const ws = [_]Work{
        .{ .name = "seal_64", .op = .{ .seal = 64 }, .ref = "comp.seal_64" },
        .{ .name = "seal_1420", .op = .{ .seal = 1420 }, .ref = "comp.seal_1420" },
        .{ .name = "open_64", .op = .{ .open = 64 }, .ref = "comp.open_64" },
        .{ .name = "open_1420", .op = .{ .open = 1420 }, .ref = "comp.open_1420" },
        .{ .name = "handshake", .op = .handshake, .ref = "comp.handshake" },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try drive(io, arena, &.{exe}, abs, &ctx, &ws, filters, rounds, w);
    try w.print("reference (last row): {s}\nworst ours/composition = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> ChaCha20-Poly1305 + libsodium <version> X25519 composition · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

// ---- comparison driver (the same in every crypto module's tools/bench.zig) ----

/// One timed side: per-op wall time and user-mode cycles (0 = no counter).
const Row = struct { ns: f64, cycles: f64 = 0, count: u64 };

/// Best and worst of the rounds of one side.
const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    best_cyc: f64 = std.math.inf(f64),
    worst_cyc: f64 = 0,
    count: u64 = 0,

    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.best_cyc = @min(s.best_cyc, r.cycles);
        s.worst_cyc = @max(s.worst_cyc, r.cycles);
        s.count = r.count;
    }
    fn best(s: Side, cyc: bool) f64 {
        return if (cyc) s.best_cyc else s.best_ns;
    }
    fn spread(s: Side, cyc: bool) f64 {
        return if (cyc) s.worst_cyc / s.best_cyc - 1 else s.worst_ns / s.best_ns - 1;
    }
};

/// This thread's user-mode cycle counter (`perf stat -e cycles:u`).
const Cycles = struct {
    fd: ?i32,

    fn open() Cycles {
        if (@import("builtin").os.tag != .linux) return .{ .fd = null };
        const linux = std.os.linux;
        var attr: linux.perf_event_attr = .{
            .type = .HARDWARE,
            .config = @intFromEnum(linux.PERF.COUNT.HW.CPU_CYCLES),
            .flags = .{ .exclude_kernel = true, .exclude_hv = true },
        };
        const rc = linux.perf_event_open(&attr, 0, -1, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return .{ .fd = null };
        return .{ .fd = @intCast(rc) };
    }

    fn read(c: Cycles) u64 {
        const fd = c.fd orelse return 0;
        var v: u64 = 0;
        _ = std.os.linux.read(fd, @ptrCast(&v), @sizeOf(u64));
        return v;
    }
};

fn timeIt(io: std.Io, cyc: Cycles, x: *Ctx) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(x));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var best_cycles: u64 = std.math.maxInt(u64);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        const c0 = cyc.read();
        for (0..n) |_| count = once(x);
        best_cycles = @min(best_cycles, cyc.read() - c0);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    const nf: f64 = @floatFromInt(n);
    return .{ .ns = @as(f64, @floatFromInt(best)) / nf, .cycles = @as(f64, @floatFromInt(best_cycles)) / nf, .count = count };
}

/// Run the foreign program for one workload: `<exe> <work dir> <name>`, which
/// prints `name \t ns/op \t cycles/op \t count` and its banner on stderr.
fn foreign(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8, banner: *[]const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    banner.* = res.stderr;
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const cycles = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .cycles = cycles, .count = count };
}

/// One workload: `op` for our side, the foreign program's workload `ref`
/// (the reference) and optionally `alt` (a second implementation in the
/// field, for the `fastest` ratio); `*_exe` index the foreign programs.
const Work = struct { name: []const u8, op: Op, ref: []const u8, alt: ?[]const u8 = null, ref_exe: usize = 0, alt_exe: usize = 0 };

const Summary = struct {
    best_ref: f64 = std.math.inf(f64),
    worst_ref: f64 = 0,
    /// Worst of ours / min(ref, alt) over the workloads that have an `alt`.
    worst_fast: ?f64 = null,
    max_spread: f64 = 0,
    banner: []const u8 = "",
    alt_banner: []const u8 = "",
};

fn drive(io: std.Io, arena: std.mem.Allocator, exes: []const []const u8, abs: []const u8, ctx: *Ctx, ws: []const Work, filters: []const [:0]const u8, rounds: usize, w: *std.Io.Writer) !Summary {
    const cyc: Cycles = .open();
    var s: Summary = .{};
    var metric_cycles = true;
    var mismatch = false;
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    try w.flush();
    for (ws) |x| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, x.name, f) != null;
            if (!hit) continue;
        }
        ctx.op = x.op;
        var ours: Side = .{};
        var ref: Side = .{};
        var alt: Side = .{};
        // The sides alternate, `rounds` times, each keeping its best: timed one
        // after the other they would see different loads of a shared machine.
        for (0..rounds) |_| {
            ref.add(try foreign(arena, io, exes[x.ref_exe], abs, x.ref, &s.banner));
            ours.add(timeIt(io, cyc, ctx));
            if (x.alt) |a| alt.add(try foreign(arena, io, exes[x.alt_exe], abs, a, &s.alt_banner));
        }
        const by_cyc = ours.best_cyc > 0 and ref.best_cyc > 0 and (x.alt == null or alt.best_cyc > 0);
        metric_cycles = metric_cycles and by_cyc;
        const r_ref = ours.best(by_cyc) / ref.best(by_cyc);
        s.worst_ref = @max(s.worst_ref, r_ref);
        s.best_ref = @min(s.best_ref, r_ref);
        var r_fast: f64 = r_ref;
        if (x.alt != null) {
            r_fast = ours.best(by_cyc) / @min(ref.best(by_cyc), alt.best(by_cyc));
            s.worst_fast = @max(s.worst_fast orelse 0, r_fast);
        }
        const spr_alt = if (x.alt != null) alt.spread(by_cyc) else 0;
        s.max_spread = @max(s.max_spread, @max(ours.spread(by_cyc), @max(ref.spread(by_cyc), spr_alt)));
        const same = ours.count == ref.count and (x.alt == null or ours.count == alt.count);
        mismatch = mismatch or !same;
        try w.print("{s:<18} {d:>11.0} {d:>11.0} {d:>11.0} {d:>7.3} {d:>7.3} {d:>5.1}% {d:>5.1}% {d:>5.1}%  {d}{s}\n", .{
            x.name,        ours.best_ns, ref.best_ns,               if (x.alt != null) alt.best_ns else 0,
            r_ref,         r_fast,       100 * ours.spread(by_cyc), 100 * ref.spread(by_cyc),
            100 * spr_alt, ours.count,
            if (same) "" else " ≠",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (metric_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.flush();
    if (mismatch) {
        std.debug.print("{s}: FAILED -- an output size differs between the sides\n", .{bench_name});
        return error.CountMismatch;
    }
    return s;
}

/// The foreign program, built from `src` with `zig cc -O3 -march=native`
/// against `libs` (shared objects named by path, so no headers are needed).
fn buildForeign(arena: std.mem.Allocator, io: std.Io, abs: []const u8, src: []const u8, libs: []const []const u8) ![]const u8 {
    const exe = try std.fmt.allocPrint(arena, "{s}/foreign_bench", .{abs});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "zig", "cc", "-O3", "-march=native", src });
    try argv.appendSlice(arena, libs);
    try argv.appendSlice(arena, &.{ "-o", exe });
    std.debug.print("{s}: building the foreign side ({s}) ...\n", .{ bench_name, src });
    const cc = try std.process.run(arena, io, .{ .argv = argv.items });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("{s}: zig cc failed:\n{s}\n", .{ bench_name, cc.stderr });
        return error.ForeignBuildFailed;
    }
    return exe;
}

/// Run the foreign program once in a non-timing mode (`interop`, `keygen`).
fn foreignOnce(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, mode: []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, mode } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed in {s}:\n{s}\n", .{ bench_name, mode, res.stderr });
        return error.ForeignFailed;
    }
}

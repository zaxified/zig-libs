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
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them, else by
//! wall time. Before timing anything the composition's transport message for
//! counter 0 must equal ours byte for byte. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
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
    return std.mem.findScalar(usize, &sizes, n).?;
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
        try dir.writeFile(io, .{ .sub_path = try arena.print("msg{d}.bin", .{n}), .data = ctx.msgs[i] });
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
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/wireguard/tools/c_bench/foreign_bench.c", &.{ so_c, so_s });

    // Interop before timing: counter 0 of msg1420 under a fresh session.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
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
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, &ws, w);
    try w.print("reference (last row): {s}\nworst ours/composition = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> ChaCha20-Poly1305 + libsodium <version> X25519 composition · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

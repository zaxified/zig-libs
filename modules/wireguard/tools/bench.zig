// SPDX-License-Identifier: MIT

//! Comparative benchmark: `wireguard`'s data plane through `Tunnel`, the program
//! behind the `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3). The configuration plane is not benched: its time is the
//! kernel's and a syscall's.
//!
//! **Reference: wireguard-go (`tools/go_bench`), candidate for fastest: boringtun
//! 0.7.1's `noise::Tunn` (`tools/rust_bench`).** Both run a stitched AVX2
//! ChaCha20-Poly1305 (x/crypto, ring), which `chachapoly` does not have, and that is
//! the whole of the transport gap: see the `aead_*` rows and the SPEC's Backlog. The
//! old composition (OpenSSL's AEAD, libsodium's X25519, `tools/c_bench`) is printed
//! as information only: the owner refused it as a reference (2026-11-03).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-wireguard` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! wireguard-go b3bc704ef0ee in the module cache (`GOPROXY=off`), cargo and
//! boringtun 0.7.1 in its registry (`--offline`; `tools/rust_bench`), `zig cc`, the
//! system OpenSSL 3 (`libcrypto.so.3`, or `LIBCRYPTO_SO`) and libsodium
//! (`libsodium.so.23`, or `SODIUM_SO`). Run from the repository root.
//!
//! Workloads, what each side does (more in each side's header):
//!   seal_<n>   ours `Tunnel.encapsulate` on an established session (session
//!              check, seal, counters, timers); Go the same per-packet work of its
//!              two send goroutines in one thread, without queues and locks;
//!              Rust `Tunn::encapsulate`.
//!   open_<n>   ours `Tunnel.decapsulate` (session lookup, replay window, AEAD,
//!              timers, inner IP length) of the next of 64 messages, the window reset
//!              once per 64 in the time; Go the same work, the same ring and reset;
//!              Rust `Tunn::decapsulate` of a ring of 1024 with a new session
//!              between rings, outside the time.
//!   handshake  both roles, end to end. Ours `Tunnel`: `initiateHandshake`,
//!              `decapsulate` (peek, accept, response), `decapsulate` (response,
//!              session, first keepalive), `decapsulate` (keepalive). Rust the same
//!              four calls. Go its Device API, without the keepalive (about 1 us
//!              of 150). All three precompute static-static outside the time.
//!   aead_*     INFORMATION: the bare AEAD, `chachapoly` against x/crypto's, to show
//!              what of the seal and open rows is the sibling's and what is ours.
//! with n = 64 and 1424 (a 1500-byte MTU's payload rounded up to the padding,
//! because boringtun does not pad and every side should do the same work). Inputs are real IPv4 headers
//! over seeded random bytes, written into `.zig-cache/bench-wireguard/`.
//!
//! Method (`testkit.bench`): each side doubles its batch until it takes over 100
//! ms and keeps the best of five; per workload the sides alternate for
//! `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the spread printed
//! is (worst round − best round) / best round per side. Ratios are by wall time, as
//! Go counts no cycles. Before timing anything the Go and C transport messages
//! for counter 0 must equal ours byte for byte, and a full handshake must complete
//! on our side (boringtun and wireguard-go check their own). Arguments filter
//! workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const wireguard = @import("wireguard");
const hs = wireguard.handshake;
const tunnel = wireguard.tunnel;
const transport = wireguard.transport;
const Tunnel = wireguard.Tunnel;

const bench_name = "bench-wireguard";
const work_dir = ".zig-cache/bench-wireguard";
const go_dir = "modules/wireguard/tools/go_bench";
const cargo_manifest = "modules/wireguard/tools/rust_bench/Cargo.toml";
const rust_exe = "modules/wireguard/tools/rust_bench/target/release/wireguard_rust_bench";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const default_sodium = "/usr/lib/x86_64-linux-gnu/libsodium.so.23";
const sizes = [_]usize{ 64, 1424 };
const now_s: u64 = 1_700_000_000;
const receiver: u32 = 0x1234_5678;
const ring_len = 64;

const Op = union(enum) { seal: usize, open: usize, handshake, aead_seal: usize, aead_open: usize };

const Ctx = struct {
    io: std.Io,
    key: [32]u8,
    msgs: [sizes.len][]u8,
    ring: [sizes.len][ring_len][]u8,
    aead_ct: [sizes.len][]u8,
    ring_pos: usize = 0,
    out: []u8,
    out2: []u8,
    a: Tunnel,
    b: Tunnel,
    ha: Tunnel,
    hb: Tunnel,
    hs_ms: u64 = 1_000_000,
    op: Op = undefined,
};

fn sizeIndex(n: usize) usize {
    return std.mem.findScalar(usize, &sizes, n).?;
}

const fixed_clock: tunnel.Clock = .{ .mono_ms = 1_000, .tai64n = tunnel.tai64n(1, 0) };

fn output(o: tunnel.Output) []u8 {
    return switch (o) {
        .network, .tunnel => |b| b,
        .none => @panic("bench: no output"),
    };
}

fn once(x: *Ctx) usize {
    switch (x.op) {
        .seal => |n| return output(x.a.encapsulate(x.io, fixed_clock, x.msgs[sizeIndex(n)], x.out) catch unreachable).len,
        .open => |n| {
            if (x.ring_pos == ring_len) {
                x.b.current.?.session.recv.window.reset();
                x.ring_pos = 0;
            }
            defer x.ring_pos += 1;
            const r = x.b.decapsulate(x.io, fixed_clock, x.ring[sizeIndex(n)][x.ring_pos], x.out) catch unreachable;
            return output(r.output).len;
        },
        .aead_seal => |n| {
            const m = x.msgs[sizeIndex(n)];
            wireguard.noise.Aead.encrypt(x.out[0..n], x.out[n..][0..16], m, "", transport.counterNonce(0), x.key);
            return n + 16;
        },
        .aead_open => |n| {
            const i = sizeIndex(n);
            wireguard.noise.Aead.decrypt(x.out[0..n], x.aead_ct[i][0..n], x.aead_ct[i][n..][0..16].*, "", transport.counterNonce(0), x.key) catch unreachable;
            return n + 16;
        },
        .handshake => {
            // Each round a new second: the rate limits and the replay stamp pass,
            // as they do for a tunnel that rekeys once in a while.
            x.hs_ms += 6_000;
            const clk: tunnel.Clock = .{ .mono_ms = x.hs_ms, .tai64n = tunnel.tai64n(x.hs_ms / 1000, 0) };
            const m1 = output(x.ha.initiateHandshake(x.io, clk, x.out) catch unreachable);
            const n1 = m1.len;
            const m2 = output((x.hb.decapsulate(x.io, clk, m1, x.out2) catch unreachable).output);
            const n2 = m2.len;
            const k = output((x.ha.decapsulate(x.io, clk, m2, x.out) catch unreachable).output);
            const last = x.hb.decapsulate(x.io, clk, k, x.out2) catch unreachable;
            if (last.output != .none) @panic("bench: keepalive produced output");
            return n1 + n2;
        },
    }
}

/// A valid IPv4 packet of `n` bytes: both foreign tunnels read its header.
fn fillPacket(msg: []u8, r: std.Random) void {
    r.bytes(msg);
    msg[0] = 0x45;
    std.mem.writeInt(u16, msg[2..4], @intCast(msg.len), .big);
}

fn establish(a: *Tunnel, b: *Tunnel, io: std.Io, out: []u8, out2: []u8) !void {
    const m1 = output(try a.initiateHandshake(io, fixed_clock, out));
    const m2 = output((try b.decapsulate(io, fixed_clock, m1, out2)).output);
    const k = output((try a.decapsulate(io, fixed_clock, m2, out)).output);
    _ = try b.decapsulate(io, fixed_clock, k, out2);
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
    ctx.out2 = try arena.alloc(u8, 2048);
    try dir.writeFile(io, .{ .sub_path = "key.bin", .data = &ctx.key });
    var ri: [4]u8 = undefined;
    std.mem.writeInt(u32, &ri, receiver, .little);
    try dir.writeFile(io, .{ .sub_path = "receiver.bin", .data = &ri });
    for (sizes, 0..) |n, i| {
        ctx.msgs[i] = try arena.alloc(u8, n);
        fillPacket(ctx.msgs[i], r);
        try dir.writeFile(io, .{ .sub_path = try arena.print("msg{d}.bin", .{n}), .data = ctx.msgs[i] });
        ctx.aead_ct[i] = try arena.alloc(u8, n + 16);
        wireguard.noise.Aead.encrypt(ctx.aead_ct[i][0..n], ctx.aead_ct[i][n..][0..16], ctx.msgs[i], "", transport.counterNonce(0), ctx.key);
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
    const opt_i: tunnel.Options = .{ .allowed_ips = null, .static_private = &s_i, .remote_static = kp_r.public };
    const opt_r: tunnel.Options = .{ .allowed_ips = null, .static_private = &s_r, .remote_static = kp_i.public };
    try Tunnel.init(&ctx.a, &opt_i, io, fixed_clock);
    try Tunnel.init(&ctx.b, &opt_r, io, fixed_clock);
    try Tunnel.init(&ctx.ha, &opt_i, io, fixed_clock);
    try Tunnel.init(&ctx.hb, &opt_r, io, fixed_clock);
    ctx.hs_ms = 1_000_000;

    // Our established pair, and the rings it sealed.
    try establish(&ctx.a, &ctx.b, io, ctx.out, ctx.out2);
    ctx.ring_pos = 0;
    for (sizes, 0..) |n, i| {
        for (&ctx.ring[i]) |*slot| {
            slot.* = try arena.alloc(u8, transport.sealedLen(n));
            @memcpy(slot.*, output(try ctx.a.encapsulate(io, fixed_clock, ctx.msgs[i], ctx.out)));
        }
    }

    const so_c = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const so_s = init.environ_map.get("SODIUM_SO") orelse default_sodium;
    const c_exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/wireguard/tools/c_bench/foreign_bench.c", &.{ so_c, so_s });
    const go_exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const cargo = try std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", cargo_manifest },
        .cwd = .inherit,
    });
    if (cargo.term != .exited or cargo.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, cargo.stderr });
        return 1;
    }

    // Interop before timing: counter 0 of msg1420 under a fresh session.
    try bench.foreignOnce(arena, io, bench_name, c_exe, abs, "interop");
    try bench.foreignOnce(arena, io, bench_name, go_exe, abs, "go.interop");
    {
        var fresh: transport.SendSession = undefined;
        fresh.init(&ctx.key, receiver, now_s);
        const mine = ctx.out[0..(try fresh.seal(ctx.out, ctx.msgs[sizeIndex(1424)], now_s)).len];
        for ([_][]const u8{ "comp_sealed_1424.bin", "go_sealed_1424.bin" }) |file| {
            const theirs = try dir.readFileAlloc(io, file, arena, .limited(4096));
            if (!std.mem.eql(u8, mine, theirs)) {
                std.debug.print("bench-wireguard: FAILED -- {s} differs from our transport message\n", .{file});
                return 1;
            }
        }
    }
    // And one handshake must complete before it is timed.
    ctx.op = .handshake;
    _ = once(&ctx);

    const exes = [_][]const u8{ go_exe, rust_exe, c_exe };
    const ws = [_]Work{
        .{ .name = "seal_64", .op = .{ .seal = 64 }, .ref = "go.seal_64", .alt = "rt.seal_64", .alt_exe = 1 },
        .{ .name = "seal_1424", .op = .{ .seal = 1424 }, .ref = "go.seal_1424", .alt = "rt.seal_1424", .alt_exe = 1 },
        .{ .name = "open_64", .op = .{ .open = 64 }, .ref = "go.open_64", .alt = "rt.open_64", .alt_exe = 1 },
        .{ .name = "open_1424", .op = .{ .open = 1424 }, .ref = "go.open_1424", .alt = "rt.open_1424", .alt_exe = 1 },
        .{ .name = "handshake", .op = .handshake, .ref = "go.handshake", .alt = "rt.handshake", .alt_exe = 1 },
        // Information: the old composition, and the bare AEAD against x/crypto's.
        .{ .name = "c_seal_64", .op = .{ .seal = 64 }, .ref = "comp.seal_64", .ref_exe = 2, .info = true },
        .{ .name = "c_seal_1424", .op = .{ .seal = 1424 }, .ref = "comp.seal_1424", .ref_exe = 2, .info = true },
        .{ .name = "c_open_64", .op = .{ .open = 64 }, .ref = "comp.open_64", .ref_exe = 2, .info = true },
        .{ .name = "c_open_1424", .op = .{ .open = 1424 }, .ref = "comp.open_1424", .ref_exe = 2, .info = true },
        .{ .name = "c_handshake", .op = .handshake, .ref = "comp.handshake", .ref_exe = 2, .info = true },
        .{ .name = "aead_seal_64", .op = .{ .aead_seal = 64 }, .ref = "go.aead_seal_64", .info = true },
        .{ .name = "aead_seal_1424", .op = .{ .aead_seal = 1424 }, .ref = "go.aead_seal_1424", .info = true },
        .{ .name = "aead_open_64", .op = .{ .aead_open = 64 }, .ref = "go.aead_open_64", .info = true },
        .{ .name = "aead_open_1424", .op = .{ .aead_open = 1424 }, .ref = "go.aead_open_1424", .info = true },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &exes, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, &ws, w);
    try w.print("reference: {s}\nfastest candidate: {s}\nworst ours/ref = {d:.3} (best {d:.3}); worst ours/fastest of the two = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× wireguard-go b3bc704ef0ee · fastest {d:.2}× boringtun 0.7.1\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}

// SPDX-License-Identifier: MIT

//! Comparative benchmark: `aes192` against OpenSSL's EVP AES-192 (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-aes192` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL 3 (`libcrypto.so.3`, path below or `LIBCRYPTO_SO`; no
//! headers needed). Run from the repository root.
//!
//! Workloads, over one 16 KiB message under a key set up once unless named:
//! `ecb_enc_16384` / `ecb_dec_16384` -- independent blocks (ours:
//! `encryptWide`/`decryptWide` at std's `optimal_parallel_blocks`, theirs: EVP
//! AES-192-ECB); `cbc_enc_16384` -- chained blocks, i.e. the latency of one
//! block (ours: `encrypt` on the XOR of the previous output, theirs: EVP
//! AES-192-CBC with the IV set per op); `ctr_16384` -- counter mode (ours:
//! `std.crypto.core.modes.ctr` over `Aes192EncryptCtx`, as `ssh`'s aes192-ctr
//! does; theirs: EVP AES-192-CTR, IV set per op); `key_enc` / `key_dec` -- one
//! key schedule per op (ours: `Aes192EncryptCtx.init` / `Aes192DecryptCtx.init`,
//! burn included; theirs: `EVP_*Init_ex` with only the key on a context that
//! already holds the cipher). Inputs are written into `.zig-cache/bench-aes192/`
//! from fixed seeds.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything OpenSSL's
//! ECB, CBC and CTR outputs of the 16 KiB message must equal ours byte for
//! byte. Arguments filter workloads by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const aes192 = @import("aes192");

const bench_name = "bench-aes192";
const work_dir = ".zig-cache/bench-aes192";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const len = 16384;
const wide = aes192.Block.parallel.optimal_parallel_blocks;

const Op = enum { ecb_enc, ecb_dec, cbc_enc, ctr, key_enc, key_dec };

const Ctx = struct {
    enc: aes192.Aes192EncryptCtx,
    dec: aes192.Aes192DecryptCtx,
    key: [24]u8,
    iv: [16]u8,
    msg: *[len]u8,
    out: *[len]u8,
    op: Op = undefined,
};

fn ecbEnc(c: aes192.Aes192EncryptCtx, out: *[len]u8, msg: *const [len]u8) void {
    var i: usize = 0;
    while (i < len) : (i += 16 * wide) c.encryptWide(wide, out[i..][0 .. 16 * wide], msg[i..][0 .. 16 * wide]);
}

fn ecbDec(c: aes192.Aes192DecryptCtx, out: *[len]u8, msg: *const [len]u8) void {
    var i: usize = 0;
    while (i < len) : (i += 16 * wide) c.decryptWide(wide, out[i..][0 .. 16 * wide], msg[i..][0 .. 16 * wide]);
}

fn cbcEnc(c: aes192.Aes192EncryptCtx, out: *[len]u8, msg: *const [len]u8, iv: [16]u8) void {
    var prev = iv;
    var i: usize = 0;
    while (i < len) : (i += 16) {
        var x: [16]u8 = undefined;
        for (&x, prev, msg[i..][0..16]) |*d, p, m| d.* = p ^ m;
        c.encrypt(out[i..][0..16], &x);
        prev = out[i..][0..16].*;
    }
}

fn once(x: *Ctx) usize {
    switch (x.op) {
        .ecb_enc => ecbEnc(x.enc, x.out, x.msg),
        .ecb_dec => ecbDec(x.dec, x.out, x.msg),
        .cbc_enc => cbcEnc(x.enc, x.out, x.msg, x.iv),
        .ctr => std.crypto.core.modes.ctr(aes192.Aes192EncryptCtx, x.enc, x.out, x.msg, x.iv, .big),
        .key_enc => {
            const c = aes192.Aes192EncryptCtx.init(x.key);
            std.mem.doNotOptimizeAway(&c);
            return 0;
        },
        .key_dec => {
            const c = aes192.Aes192DecryptCtx.init(x.key);
            std.mem.doNotOptimizeAway(&c);
            return 0;
        },
    }
    std.mem.doNotOptimizeAway(x.out);
    return len;
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

    var prng = std.Random.DefaultPrng.init(0xae5_192_b3c4);
    const r = prng.random();
    var ctx: Ctx = undefined;
    r.bytes(&ctx.key);
    r.bytes(&ctx.iv);
    ctx.msg = try arena.create([len]u8);
    ctx.out = try arena.create([len]u8);
    r.bytes(ctx.msg);
    ctx.enc = .init(ctx.key);
    ctx.dec = .init(ctx.key);
    try dir.writeFile(io, .{ .sub_path = "key24.bin", .data = &ctx.key });
    try dir.writeFile(io, .{ .sub_path = "iv.bin", .data = &ctx.iv });
    try dir.writeFile(io, .{ .sub_path = "msg16384.bin", .data = ctx.msg });

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/aes192/tools/c_bench/foreign_bench.c", &.{so});

    // Interop before timing: ECB both ways, CBC, CTR.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    const checks = [_]struct { file: []const u8, op: Op }{ .{ .file = "ossl_ecb.bin", .op = .ecb_enc }, .{ .file = "ossl_cbc.bin", .op = .cbc_enc }, .{ .file = "ossl_ctr.bin", .op = .ctr } };
    for (checks) |c| {
        const theirs = try dir.readFileAlloc(io, c.file, arena, .limited(1 << 20));
        ctx.op = c.op;
        _ = once(&ctx);
        if (!std.mem.eql(u8, theirs, ctx.out)) {
            std.debug.print("bench-aes192: FAILED -- OpenSSL's {s} differs from ours\n", .{c.file});
            return 1;
        }
        if (c.op == .ecb_enc) {
            const back = try arena.create([len]u8);
            ecbDec(ctx.dec, back, ctx.out);
            if (!std.mem.eql(u8, back, ctx.msg)) {
                std.debug.print("bench-aes192: FAILED -- ECB decrypt does not invert encrypt\n", .{});
                return 1;
            }
        }
    }

    var ws: std.ArrayList(Work) = .empty;
    for ([_]struct { []const u8, Op }{
        .{ "ecb_enc_16384", .ecb_enc }, .{ "ecb_dec_16384", .ecb_dec }, .{ "cbc_enc_16384", .cbc_enc },
        .{ "ctr_16384", .ctr },         .{ "key_enc", .key_enc },       .{ "key_dec", .key_dec },
    }) |w| try ws.append(arena, .{ .name = w[0], .op = w[1], .ref = w[0] });

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> EVP AES-192 · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

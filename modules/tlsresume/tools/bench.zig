// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tlsresume` against OpenSSL 3 (the reference named by
//! the maturity card), the program behind the `**Performance:**` line of the
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! ⚠ What "like for like" means here. OpenSSL keeps ticket protection and the
//! resumption key schedule inside its handshake engine (its default ticket
//! format is AES-CBC + HMAC with a different layout, not reachable alone), so
//! there is no OpenSSL call to time against `StekRing.seal` or `psk.*`. The
//! reference side therefore performs THE SAME computations -- byte for byte
//! the same outputs, checked before timing -- written against OpenSSL's public
//! EVP API (`tools/c_bench/foreign_bench.c`): AES-256-GCM through
//! `EVP_CIPHER_CTX`, HKDF composed from HMAC-SHA256 through `EVP_MAC`. What is
//! compared is therefore this module's wrapping (ring lookup, blob layout,
//! stack burning, the std primitives under it) against the same recipe on
//! OpenSSL's primitives; the card line says so.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tlsresume` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL 3 (`libcrypto.so.3`, path below or `LIBCRYPTO_SO`; no
//! headers needed). Run from the repository root.
//!
//! Workloads (a server's per-connection resumption work):
//!   seal_128 / seal_512   `StekRing.seal` of a 128- / 512-byte session state
//!   open_128 / open_512   `StekRing.open` of that blob (key lookup + tag check)
//!   binder                derivePsk + earlySecret + binderKey + computeBinder
//!                         (SHA-256), the resumed ClientHello's binder chain
//! Inputs are written into `.zig-cache/bench-tlsresume/` from fixed seeds. The
//! count is the bytes produced per op. The strike register (a hash set) and the
//! 4-byte ticket codec have no OpenSSL counterpart and are not timed.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything OpenSSL's
//! sealed blobs and binder must equal ours byte for byte. Arguments filter
//! workloads by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const tlsresume = @import("tlsresume");

const bench_name = "bench-tlsresume";
const work_dir = ".zig-cache/bench-tlsresume";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const lens = [_]usize{ 128, 512 };
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Ring = tlsresume.stek.StekRing(3);

const Kind = enum { seal, open, binder };
const Op = struct { kind: Kind, len_index: usize };

const Ctx = struct {
    ring: Ring,
    nonce: [12]u8,
    rms: [32]u8,
    th: [32]u8,
    empty_hash: [32]u8,
    pts: [lens.len][]u8,
    blobs: [lens.len][]u8,
    out: []u8,
    binder_out: [32]u8 = undefined,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    switch (x.op.kind) {
        .seal => {
            const r = x.ring.seal(x.pts[x.op.len_index], x.nonce, x.out) catch unreachable;
            return r.len;
        },
        .open => {
            const r = x.ring.open(x.blobs[x.op.len_index], x.out) catch unreachable;
            std.mem.doNotOptimizeAway(r.ptr);
            return r.len;
        },
        .binder => {
            var psk: [32]u8 = undefined;
            var early: [32]u8 = undefined;
            var bkey: [32]u8 = undefined;
            tlsresume.psk.derivePsk(Hkdf, 32, &psk, &x.rms, &[_]u8{ 0, 0 });
            tlsresume.psk.earlySecret(Hkdf, &early, &psk);
            tlsresume.psk.binderKey(Hkdf, &bkey, &early, &x.empty_hash);
            tlsresume.psk.computeBinder(Hkdf, Hmac, &x.binder_out, &bkey, &x.th);
            std.mem.doNotOptimizeAway(&x.binder_out);
            return 32;
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

    var prng = std.Random.DefaultPrng.init(0x7154_e5a3_0001);
    const r = prng.random();
    var key: [32]u8 = undefined;
    const ctx = try arena.create(Ctx);
    r.bytes(&key);
    r.bytes(&ctx.nonce);
    r.bytes(&ctx.rms);
    r.bytes(&ctx.th);
    std.crypto.hash.sha2.Sha256.hash("", &ctx.empty_hash, .{});
    ctx.ring = Ring.init();
    ctx.ring.rotate(1, &key, 0);
    ctx.out = try arena.alloc(u8, 1024);
    try dir.writeFile(io, .{ .sub_path = "key32.bin", .data = &key });
    try dir.writeFile(io, .{ .sub_path = "nonce12.bin", .data = &ctx.nonce });
    try dir.writeFile(io, .{ .sub_path = "rms32.bin", .data = &ctx.rms });
    try dir.writeFile(io, .{ .sub_path = "th32.bin", .data = &ctx.th });
    try dir.writeFile(io, .{ .sub_path = "empty_hash32.bin", .data = &ctx.empty_hash });
    for (lens, 0..) |n, i| {
        ctx.pts[i] = try arena.alloc(u8, n);
        r.bytes(ctx.pts[i]);
        const sealed = try ctx.ring.seal(ctx.pts[i], ctx.nonce, ctx.out);
        ctx.blobs[i] = try arena.dupe(u8, sealed);
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "pt{d}.bin", .{n}), .data = ctx.pts[i] });
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "blob{d}.bin", .{n}), .data = ctx.blobs[i] });
    }

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/tlsresume/tools/c_bench/foreign_bench.c", &.{so});

    // Interop before timing.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    for (lens, 0..) |n, i| {
        const theirs = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "ossl_seal_{d}.bin", .{n}), arena, .limited(1 << 16));
        if (!std.mem.eql(u8, theirs, ctx.blobs[i])) {
            std.debug.print("{s}: FAILED -- OpenSSL's sealed {d}-byte ticket differs from ours\n", .{ bench_name, n });
            return 1;
        }
    }
    ctx.op = .{ .kind = .binder, .len_index = 0 };
    _ = once(ctx);
    const theirs_binder = try dir.readFileAlloc(io, "ossl_binder.bin", arena, .limited(64));
    if (!std.mem.eql(u8, theirs_binder, &ctx.binder_out)) {
        std.debug.print("{s}: FAILED -- OpenSSL's PSK binder differs from ours\n", .{bench_name});
        return 1;
    }

    var ws: std.ArrayList(Work) = .empty;
    for (lens, 0..) |n, i| inline for (.{ Kind.seal, Kind.open }) |k| {
        const name = try std.fmt.allocPrint(arena, "{s}_{d}", .{ @tagName(k), n });
        try ws.append(arena, .{ .name = name, .op = .{ .kind = k, .len_index = i }, .ref = name });
    };
    try ws.append(arena, .{ .name = "binder", .op = .{ .kind = .binder, .len_index = 0 }, .ref = "binder" });

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> EVP (same recipe: AES-256-GCM ticket seal/open, HKDF/HMAC-SHA256 binder chain) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

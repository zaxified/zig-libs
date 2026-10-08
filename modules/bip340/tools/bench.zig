// SPDX-License-Identifier: MIT

//! Comparative benchmark: `bip340` against libsecp256k1 v0.8.0's `schnorrsig` +
//! `extrakeys` (the reference), the program behind the `**Performance:**` line
//! of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-bip340` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH and
//! the libsecp256k1 v0.8.0 SOURCE TREE (path below or `SECP256K1_SRC`): the C
//! side, `tools/c_bench/secp_bench.c`, is compiled by `zig cc -O3` together with
//! the library's `secp256k1.c`, `precomputed_ecmult.c` and
//! `precomputed_ecmult_gen.c` (upstream default window and comb parameters,
//! x86-64 field assembly). The library's own build system is never run. If the
//! source tree is missing the program prints the fetch recipe and exits 2.
//! Run from the repository root.
//!
//! Workloads, each timed per operation:
//!   keypair  secret key -> x-only public key (ours: `KeyPair.fromSecretKey`,
//!            theirs: `keypair_create` + `keypair_xonly_pub`)
//!   sign     BIP340 signature of a 32-byte message from a ready key pair
//!            (ours: `signWithKeyPair`, theirs: `schnorrsig_sign32`); ours
//!            also runs its mandatory self-verification
//! Until 2026-10-07 ours signed with `sign(secret_key)`, which also derives
//! the public key on every call (~27 µs more than the pair form).
//!   verify   one signature (ours lifts the x-only key per call, theirs parses
//!            it once beforehand)
//! plus an informational row `verifyBatch/sig`, ours only (libsecp has no batch
//! verification), no ratio. Both sides double the batch until it takes over
//! 100 ms and keep the best of five. Inputs are written into
//! `.zig-cache/bench-bip340/` from fixed seeds.
//!
//! Before timing anything, a libsecp256k1 signature must verify here and ours
//! must verify there; the signatures are also compared (BIP340 signing is
//! deterministic given the aux randomness, so they should be byte-equal).

const std = @import("std");
const bip340 = @import("bip340");

const work_dir = ".zig-cache/bench-bip340";
const default_src = ".zig-cache/foreign/secp256k1/secp256k1-0.8.0";
const fetch_recipe =
    \\bench-bip340: libsecp256k1 v0.8.0 source not found at {s}
    \\  fetch it (and review it before compiling; never run its build system):
    \\    curl -L -o secp256k1-0.8.0.tar.gz https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.8.0.tar.gz
    \\    echo "eb52b0e9239dff7dc26be5f9623567141b8720ec47da29eb3c1e0a660d17c8bb  secp256k1-0.8.0.tar.gz" | sha256sum -c
    \\    tar -xzf secp256k1-0.8.0.tar.gz   # then: SECP256K1_SRC=<dir>/secp256k1-0.8.0 zig build bench-bip340
    \\
;

const Row = struct { ns: f64, count: u64 };

const Ctx = struct {
    io: std.Io,
    sk: bip340.SecretKey,
    kp: *const bip340.KeyPair,
    pk: bip340.XOnlyPublicKey,
    msg: [32]u8,
    aux: [32]u8,
    sig: bip340.Signature,
    batch: []const bip340.BatchItem,
};

fn doKeypair(c: Ctx) usize {
    var kp: bip340.KeyPair = undefined;
    bip340.KeyPair.fromSecretKey(&kp, &c.sk) catch unreachable;
    std.mem.doNotOptimizeAway(&kp);
    return 1;
}
fn doSign(c: Ctx) usize {
    const s = bip340.signWithKeyPair(c.kp, &c.msg, c.aux, c.io) catch unreachable;
    std.mem.doNotOptimizeAway(&s);
    return 1;
}
fn doVerify(c: Ctx) usize {
    if (!bip340.verify(c.pk, &c.msg, c.sig)) unreachable;
    return 1;
}
fn doBatch(c: Ctx) usize {
    if (!bip340.verifyBatch(c.batch, c.io)) unreachable;
    return c.batch.len;
}

fn timeIt(io: std.Io, c: Ctx, comptime f: fn (Ctx) usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(f(c));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = f(c);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const cwd = std.Io.Dir.cwd();
    const src = init.environ_map.get("SECP256K1_SRC") orelse default_src;
    cwd.access(io, src, .{}) catch {
        std.debug.print(fetch_recipe, .{src});
        return 2;
    };
    const src_abs = try cwd.realPathFileAlloc(io, src, arena);

    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var prng = std.Random.DefaultPrng.init(0xb1b3_4040_5ec9);
    const r = prng.random();
    var sk_bytes: [32]u8 = undefined;
    var msg: [32]u8 = undefined;
    var aux: [32]u8 = undefined;
    r.bytes(&sk_bytes);
    r.bytes(&msg);
    r.bytes(&aux);
    const sk = try bip340.SecretKey.fromBytes(sk_bytes);
    var kp: bip340.KeyPair = undefined;
    try bip340.KeyPair.fromSecretKey(&kp, &sk);
    const sig_bytes = try bip340.sign(&sk, &msg, aux, io);
    const sig = try bip340.Signature.fromBytes(sig_bytes);
    try dir.writeFile(io, .{ .sub_path = "sk.bin", .data = &sk_bytes });
    try dir.writeFile(io, .{ .sub_path = "msg.bin", .data = &msg });
    try dir.writeFile(io, .{ .sub_path = "aux.bin", .data = &aux });
    try dir.writeFile(io, .{ .sub_path = "sig.zig.bin", .data = &sig_bytes });

    // Build the C side: our harness plus libsecp256k1's three translation units.
    const exe = try std.fmt.allocPrint(arena, "{s}/secp_bench", .{abs});
    const inc_api = try std.fmt.allocPrint(arena, "-I{s}/include", .{src_abs});
    const inc_src = try std.fmt.allocPrint(arena, "-I{s}/src", .{src_abs});
    const u_main = try std.fmt.allocPrint(arena, "{s}/src/secp256k1.c", .{src_abs});
    const u_ecmult = try std.fmt.allocPrint(arena, "{s}/src/precomputed_ecmult.c", .{src_abs});
    const u_gen = try std.fmt.allocPrint(arena, "{s}/src/precomputed_ecmult_gen.c", .{src_abs});
    std.debug.print("bench-bip340: building the libsecp256k1 side from {s} (zig cc -O3, takes a while) ...\n", .{src});
    const cc = try std.process.run(arena, io, .{ .argv = &.{
        "zig",                          "cc",                          "-O3",
        "-DENABLE_MODULE_SCHNORRSIG=1", "-DENABLE_MODULE_EXTRAKEYS=1", "-DUSE_ASM_X86_64=1",
        inc_api,                        inc_src,                       "modules/bip340/tools/c_bench/secp_bench.c",
        u_main,                         u_ecmult,                      u_gen,
        "-o",                           exe,
    } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("bench-bip340: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-bip340: libsecp256k1 side failed:\n{s}\n", .{res.stderr});
        return 1;
    }
    var rows: std.StringHashMapUnmanaged(Row) = .empty;
    var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
        const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
        try rows.put(arena, name, .{ .ns = ns, .count = count });
    }

    // Interop before timing. (The C side already verified our signature.)
    const their_pk = try dir.readFileAlloc(io, "pk.c.bin", arena, .limited(64));
    if (!std.mem.eql(u8, their_pk, &kp.public.toBytes())) {
        std.debug.print("bench-bip340: FAILED -- the x-only public keys differ\n", .{});
        return 1;
    }
    const their_sig = try dir.readFileAlloc(io, "sig.c.bin", arena, .limited(128));
    if (their_sig.len != 64) return error.BadForeignOutput;
    const their_parsed = try bip340.Signature.fromBytes(their_sig[0..64].*);
    if (!bip340.verify(kp.public, &msg, their_parsed)) {
        std.debug.print("bench-bip340: FAILED -- a libsecp256k1 signature does not verify here\n", .{});
        return 1;
    }
    const identical = std.mem.eql(u8, their_sig, &sig_bytes);

    // 64 distinct (key, message, signature) triples for the informational batch row.
    const items = try arena.alloc(bip340.BatchItem, 64);
    for (items) |*it| {
        var b: [32]u8 = undefined;
        var m: [32]u8 = undefined;
        var a: [32]u8 = undefined;
        r.bytes(&b);
        r.bytes(&m);
        r.bytes(&a);
        var k: bip340.KeyPair = undefined;
        const item_sk = try bip340.SecretKey.fromBytes(b);
        try bip340.KeyPair.fromSecretKey(&k, &item_sk);
        const s = try bip340.sign(&item_sk, &m, a, io);
        it.* = .{ .pubkey = k.public, .msg = try arena.dupe(u8, &m), .sig = try bip340.Signature.fromBytes(s) };
    }

    const ctx: Ctx = .{ .io = io, .sk = sk, .kp = &kp, .pk = kp.public, .msg = msg, .aux = aux, .sig = sig, .batch = items };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("reference: {s}", .{res.stderr});
    try w.print("interop: both directions verify; signatures byte-identical: {}\n", .{identical});
    try w.print("{s:<10} {s:>12} {s:>13} {s:>14}\n", .{ "workload", "ours ns/op", "secp256k1 ns", "ours/secp256k1" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    inline for (.{ .{ "keypair", doKeypair }, .{ "sign", doSign }, .{ "verify", doVerify } }) |x| {
        const ours = timeIt(io, ctx, x[1]);
        const t = rows.get(x[0]) orelse return error.MissingRow;
        const ratio = ours.ns / t.ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        try w.print("{s:<10} {d:>12.0} {d:>13.0} {d:>14.2}\n", .{ x[0], ours.ns, t.ns, ratio });
        try w.flush();
    }
    const batch = timeIt(io, ctx, doBatch);
    try w.print("{s:<10} {d:>12.0} {s:>13} {s:>14}   (64-signature batch, per signature)\n", .{ "verifyBatch", batch.ns / @as(f64, @floatFromInt(batch.count)), "-", "-" });
    try w.print("\nworst ours/secp256k1 = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× libsecp256k1 v0.8.0 schnorrsig · fastest ? (measured 2026-10-07)\n", .{ best, worst });
    try w.flush();
    return 0;
}

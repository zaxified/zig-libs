// SPDX-License-Identifier: MIT

//! Comparative benchmark: `slhdsa` against OpenSSL 3.5's SLH-DSA (EVP_PKEY
//! "SLH-DSA-*"), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! The card names liboqs (slhdsa-c) as its reference; that is foreign code not
//! pinned in this tree, so the reference here is the SLH-DSA that ships in the
//! system OpenSSL -- the same FIPS 205 algorithm, a different implementation,
//! and the one an application using a system TLS stack would call. The card
//! line names it as such.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-slhdsa` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system OpenSSL >= 3.5 (`libcrypto.so.3`, path below or `LIBCRYPTO_SO`;
//! no headers needed). Run from the repository root.
//!
//! Workloads: for the parameter sets SHA2-128s, SHA2-128f, SHA2-192s,
//! SHA2-256s, SHAKE-128s and SHAKE-128f (the sizes/families a certificate or
//! signature consumer meets): `<set>/sign` (deterministic, 1 KiB message --
//! the size of a TBSCertificate -- empty context), `<set>/verify` and
//! `<set>/keygen`. Keys come from fixed seeds written into
//! `.zig-cache/bench-slhdsa/`; the key is imported into OpenSSL once (ours is
//! a plain struct), the per-call EVP_MD_CTX of the one-shot API is inside
//! OpenSSL's timed loop. Keygen is not seeded on the OpenSSL side (its RNG
//! cost is a few microseconds against milliseconds of tree hashing). The
//! count is the output size (signature / 1 / 1).
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything OpenSSL's
//! deterministic signature of every set must equal ours byte for byte, and
//! OpenSSL must accept ours. Arguments filter workloads by substring (no card
//! line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const slhdsa = @import("slhdsa");

const bench_name = "bench-slhdsa";
const work_dir = ".zig-cache/bench-slhdsa";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const msg_len = 1024;

const set_names = [_][]const u8{ "sha2_128s", "sha2_128f", "sha2_192s", "sha2_256s", "shake_128s", "shake_128f" };
const Sets = .{ slhdsa.SlhDsaSha2_128s, slhdsa.SlhDsaSha2_128f, slhdsa.SlhDsaSha2_192s, slhdsa.SlhDsaSha2_256s, slhdsa.SlhDsaShake_128s, slhdsa.SlhDsaShake_128f };

const Kind = enum { sign, verify, keygen };
const Op = struct { kind: Kind, set: usize };

fn Case(comptime S: type) type {
    return struct {
        sk: S.SecretKey,
        pk: S.PublicKey,
        sig: [S.signature_length]u8,
        seed: [3 * S.n]u8,
        out: [S.signature_length]u8 = undefined,
        kp: S.KeyPair = undefined,
    };
}

const Ctx = struct {
    cases: @Tuple(&blk: {
        var t: [Sets.len]type = undefined;
        for (Sets, 0..) |S, i| t[i] = Case(S);
        break :blk t;
    }),
    msg: [msg_len]u8,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    inline for (Sets, 0..) |S, i| {
        if (x.op.set == i) {
            const c = &x.cases[i];
            switch (x.op.kind) {
                .sign => {
                    S.sign(&c.out, &x.msg, &c.sk, "", null) catch unreachable;
                    std.mem.doNotOptimizeAway(&c.out);
                    return S.signature_length;
                },
                .verify => {
                    if (!S.verify(&c.sig, &x.msg, c.pk, "")) unreachable;
                    return 1;
                },
                .keygen => {
                    S.keyGen(&c.kp, &c.seed);
                    std.mem.doNotOptimizeAway(&c.kp);
                    return 1;
                },
            }
        }
    }
    unreachable;
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

    var prng = std.Random.DefaultPrng.init(0x5148_d5a2_0205);
    const r = prng.random();
    const ctx = try arena.create(Ctx);
    r.bytes(&ctx.msg);
    try dir.writeFile(io, .{ .sub_path = "msg.bin", .data = &ctx.msg });
    inline for (Sets, 0..) |S, i| {
        const c = &ctx.cases[i];
        r.bytes(&c.seed);
        var kp: S.KeyPair = undefined;
        S.keyGen(&kp, &c.seed);
        c.sk = kp.sk;
        c.pk = kp.pk;
        var skb: [S.secret_key_length]u8 = undefined;
        c.sk.toBytes(&skb);
        try S.sign(&c.sig, &ctx.msg, &c.sk, "", null);
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "sk_{s}.bin", .{set_names[i]}), .data = &skb });
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "sig_{s}.bin", .{set_names[i]}), .data = &c.sig });
    }

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/slhdsa/tools/c_bench/foreign_bench.c", &.{so});

    // Interop before timing: OpenSSL accepts ours and signs identically.
    inline for (Sets, 0..) |S, i| {
        try bench.foreignOnce(arena, io, bench_name, exe, abs, try std.fmt.allocPrint(arena, "interop/{s}", .{set_names[i]}));
        const theirs = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "ossl_sig_{s}.bin", .{set_names[i]}), arena, .limited(1 << 20));
        if (!std.mem.eql(u8, theirs, &ctx.cases[i].sig)) {
            std.debug.print("{s}: FAILED -- OpenSSL's deterministic {s} signature differs from ours\n", .{ bench_name, set_names[i] });
            return 1;
        }
        _ = S;
    }

    var ws: std.ArrayList(Work) = .empty;
    for (set_names, 0..) |sn, i| inline for (.{ Kind.sign, Kind.verify, Kind.keygen }) |k| {
        const name = try std.fmt.allocPrint(arena, "{s}/{s}", .{ sn, @tagName(k) });
        try ws.append(arena, .{ .name = name, .op = .{ .kind = k, .set = i }, .ref = name });
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> SLH-DSA · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

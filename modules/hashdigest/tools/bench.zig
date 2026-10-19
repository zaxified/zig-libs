// SPDX-License-Identifier: MIT

//! Comparative benchmark: `hashdigest` against Go's one-shot digests +
//! `encoding/hex` (the reference the module's scope was surveyed against;
//! `tools/go_bench/main.go`) and OpenSSL's EVP digests (the other
//! implementation in the field measured here; libsodium's `crypto_generichash`
//! for BLAKE2b-256, which OpenSSL offers only as BLAKE2b-512), the program
//! behind the `**Performance:**` line of the maturity card (CONVENTIONS.md §9,
//! kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-hashdigest` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `go` on PATH with
//! golang.org/x/crypto v0.57.0 in the module cache (GOPROXY=off; `go.sum`
//! pins it; built in a copy under `.zig-cache/bench-hashdigest/go/`), `zig`
//! (it builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`), the
//! system OpenSSL 3 (`libcrypto.so.3`, or `LIBCRYPTO_SO`) and libsodium
//! (`libsodium.so.23`, or `SODIUM_SO`); no headers needed. Run from the
//! repository root.
//!
//! Workloads: `hashdigest.hex(algo, msg, out)` -- one-shot digest plus
//! lowercase hex, the module's job -- of a 64-byte and a 64 KiB message for
//! every `Algorithm` but BLAKE3 (no reference library installed here), against
//! the same digest + hex in C (EVP_MD fetched and EVP_MD_CTX allocated once).
//! Inputs are written into `.zig-cache/bench-hashdigest/` from fixed seeds.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them, else by
//! wall time (the Go side has no cycle counter, so in practice wall time);
//! `/fast` is ours over the faster of Go and OpenSSL/libsodium. Before timing
//! anything every foreign hex digest of the 64 KiB message must equal ours.
//! Arguments filter workloads by substring.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const hashdigest = @import("hashdigest");
const Algorithm = hashdigest.Algorithm;

const bench_name = "bench-hashdigest";
const work_dir = ".zig-cache/bench-hashdigest";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const default_sodium = "/usr/lib/x86_64-linux-gnu/libsodium.so.23";
const sizes = [_]usize{ 64, 65536 };
const algos = [_]Algorithm{ .sha256, .sha224, .sha384, .sha512, .sha512_256, .sha3_256, .sha3_512, .blake2b256 };

const Op = struct { algo: Algorithm, msg: []const u8 };

const Ctx = struct {
    out: [hashdigest.max_hex_len]u8,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    return (hashdigest.hex(x.op.algo, x.op.msg, &x.out) catch unreachable).len;
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

    var prng = std.Random.DefaultPrng.init(0x4a54_d16e);
    var msgs: [sizes.len][]u8 = undefined;
    for (sizes, 0..) |n, i| {
        msgs[i] = try arena.alloc(u8, n);
        prng.random().bytes(msgs[i]);
        try dir.writeFile(io, .{ .sub_path = try arena.print("msg{d}.bin", .{n}), .data = msgs[i] });
    }

    const so_c = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const so_s = init.environ_map.get("SODIUM_SO") orelse default_sodium;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/hashdigest/tools/c_bench/foreign_bench.c", &.{ so_c, so_s });

    // The Go side, built in a copy of tools/go_bench.
    try cwd.createDirPath(io, work_dir ++ "/go");
    for ([_][]const u8{ "go.mod", "go.sum", "main.go" }) |f| {
        const src = try cwd.readFileAlloc(io, try arena.print("modules/hashdigest/tools/go_bench/{s}", .{f}), arena, .limited(1 << 20));
        try dir.writeFile(io, .{ .sub_path = try arena.print("go/{s}", .{f}), .data = src });
    }
    const go_exe = try arena.print("{s}/go_bench", .{abs});
    const go_dir = try arena.print("{s}/go", .{abs});
    std.debug.print("bench-hashdigest: building the Go side ...\n", .{});
    const gb = try std.process.run(arena, io, .{ .argv = &.{ "env", "GOPROXY=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOWORK=off", "go", "-C", go_dir, "build", "-o", go_exe, "." } });
    if (gb.term != .exited or gb.term.exited != 0) {
        std.debug.print("bench-hashdigest: go build failed (is x/crypto v0.57.0 in the module cache?):\n{s}\n", .{gb.stderr});
        return 1;
    }

    var ctx: Ctx = .{ .out = undefined };
    // Interop before timing.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    try bench.foreignOnce(arena, io, bench_name, go_exe, abs, "interop");
    for (algos) |a| for ([_][]const u8{ "", "go_" }) |prefix| {
        const theirs = try dir.readFileAlloc(io, try arena.print("{s}{s}.hex", .{ prefix, @tagName(a) }), arena, .limited(4096));
        const ours = try hashdigest.hex(a, msgs[1], &ctx.out);
        if (!std.mem.eql(u8, theirs, ours)) {
            std.debug.print("bench-hashdigest: FAILED -- {s}{s} differs from ours\n", .{ prefix, @tagName(a) });
            return 1;
        }
    };

    var ws: std.ArrayList(Work) = .empty;
    for (algos) |a| for (sizes, 0..) |n, i| {
        const impl = if (a == .blake2b256) "sodium" else "ossl";
        try ws.append(arena, .{
            .name = try arena.print("{s}_{d}", .{ @tagName(a), n }),
            .op = .{ .algo = a, .msg = msgs[i] },
            .ref = try arena.print("go.{s}_{d}", .{ @tagName(a), n }),
            .ref_exe = 1,
            .alt = try arena.print("{s}.{s}_{d}", .{ impl, @tagName(a), n }),
        });
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ exe, go_exe }, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/Go = {d:.3} (best {d:.3}); worst ours/fastest = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go <version> crypto + encoding/hex · fastest {d:.2}× OpenSSL <version> (measured <today>)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}

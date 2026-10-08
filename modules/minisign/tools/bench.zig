// SPDX-License-Identifier: MIT

//! Comparative benchmark: `minisign` against the jedisct1/minisign CLI (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-minisign` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `minisign` on
//! PATH (its version is printed). Run from the repository root.
//!
//! One key pair (an unencrypted secret key file, as `minisign -G -W` writes)
//! and a 256 MiB random file in `.zig-cache/bench-minisign/`. Workloads: sign
//! the file (prehashed, BLAKE2b-512 then Ed25519, with a trusted comment) and
//! verify it — the CLI as a whole process (`minisign -S`/`-V`), ours as a
//! 64 KiB streaming BLAKE2b-512 plus `signFileDigest`/`verifyFileDigest`, both
//! from the page cache. The
//! file is large so the CLI's process start is under 1 % of its time. Best of
//! five each. Before timing, the CLI must verify our signature and we must
//! verify the CLI's: a benchmark of two things that disagree measures nothing.

const std = @import("std");
const minisign = @import("minisign");

const work_dir = ".zig-cache/bench-minisign";
const file_len = 256 << 20;
const comment = "timestamp:1700000000\tfile:data.bin";

fn runOk(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8) !void {
    const r = try std.process.run(arena, io, .{ .argv = argv });
    if (r.term != .exited or r.term.exited != 0) {
        std.debug.print("bench-minisign: `{s} {s}` failed:\n{s}{s}\n", .{ argv[0], argv[1], r.stdout, r.stderr });
        return error.ForeignSideFailed;
    }
}

fn bestOf5Cli(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8) !f64 {
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        try runOk(arena, io, argv);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return @floatFromInt(best);
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const gpa = std.heap.smp_allocator;

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const p = struct {
        fn path(a: std.mem.Allocator, base: []const u8, name: []const u8) []const u8 {
            return std.fmt.allocPrint(a, "{s}/{s}", .{ base, name }) catch @panic("OOM");
        }
    }.path;

    const ver = std.process.run(arena, io, .{ .argv = &.{ "minisign", "-v" } }) catch |e| {
        std.debug.print("bench-minisign: could not run minisign ({t})\n", .{e});
        return 1;
    };

    // Key pair and file.
    var kp: minisign.KeyPair = undefined;
    minisign.KeyPair.generate(&kp, io);
    defer kp.wipe();
    var out: std.Io.Writer.Allocating = .init(arena);
    try minisign.writePublicKeyFile(&out.writer, "bench key", kp.publicKey());
    try dir.writeFile(io, .{ .sub_path = "pub.key", .data = out.written() });
    out.clearRetainingCapacity();
    var raw: minisign.RawSecretKey = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&raw));
    kp.toRawSecretKeyPlain(&raw);
    try minisign.writeSecretKeyFile(&out.writer, "bench key", &raw);
    try dir.writeFile(io, .{ .sub_path = "sec.key", .data = out.written() });
    {
        const data = try gpa.alloc(u8, file_len);
        defer gpa.free(data);
        var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_3151);
        prng.random().bytes(data);
        try dir.writeFile(io, .{ .sub_path = "data.bin", .data = data });
    }

    // Ours: read + sign / read + verify.
    // Ours streams the file as the CLI does (64 KiB reads into BLAKE2b-512,
    // the module's documented `*FileDigest` path for files not held in
    // memory), so both sides do the same I/O.
    const Ours = struct {
        fn digest(i: std.Io, d: std.Io.Dir) ![minisign.prehash_length]u8 {
            var f = try d.openFile(i, "data.bin", .{});
            defer f.close(i);
            var h = std.crypto.hash.blake2.Blake2b512.init(.{});
            var chunk: [64 * 1024]u8 = undefined;
            var r = f.readerStreaming(i, &.{});
            while (true) {
                const n = try r.interface.readSliceShort(&chunk);
                if (n == 0) break;
                h.update(chunk[0..n]);
            }
            var dg: [minisign.prehash_length]u8 = undefined;
            h.final(&dg);
            return dg;
        }
        fn sign(a: std.mem.Allocator, i: std.Io, d: std.Io.Dir, k: *const minisign.KeyPair) !minisign.SignedFile {
            return minisign.signFileDigest(a, k, try digest(i, d), comment);
        }
        fn verify(a: std.mem.Allocator, i: std.Io, d: std.Io.Dir, pk: minisign.RawPublicKey, sig_text: []const u8) !void {
            const parsed = try minisign.parseSignatureFile(sig_text);
            try minisign.verifyFileDigest(a, pk, try digest(i, d), parsed);
        }
    };
    const signed = try Ours.sign(gpa, io, dir, &kp);
    out.clearRetainingCapacity();
    try minisign.writeSignatureFile(&out.writer, "signature from the bench", signed.signature, comment, signed.global_signature);
    const our_sig = try arena.dupe(u8, out.written());
    try dir.writeFile(io, .{ .sub_path = "data.bin.minisig", .data = our_sig });

    // Interop both ways, before timing.
    std.debug.print("bench-minisign: interop checks ...\n", .{});
    try runOk(arena, io, &.{ "minisign", "-V", "-q", "-p", p(arena, abs, "pub.key"), "-m", p(arena, abs, "data.bin") });
    try runOk(arena, io, &.{ "minisign", "-S", "-s", p(arena, abs, "sec.key"), "-m", p(arena, abs, "data.bin"), "-x", p(arena, abs, "cli.minisig"), "-t", comment });
    const cli_sig = try dir.readFileAlloc(io, "cli.minisig", arena, .limited(4096));
    Ours.verify(gpa, io, dir, kp.publicKey(), cli_sig) catch {
        std.debug.print("bench-minisign: FAILED -- the CLI's signature does not verify here\n", .{});
        return 1;
    };

    std.debug.print("bench-minisign: timing (about a minute) ...\n", .{});
    const cli_sign = try bestOf5Cli(arena, io, &.{ "minisign", "-S", "-s", p(arena, abs, "sec.key"), "-m", p(arena, abs, "data.bin"), "-x", p(arena, abs, "cli.minisig"), "-t", comment });
    const cli_verify = try bestOf5Cli(arena, io, &.{ "minisign", "-V", "-q", "-p", p(arena, abs, "pub.key"), "-m", p(arena, abs, "data.bin"), "-x", p(arena, abs, "cli.minisig") });
    var our_sign: i96 = std.math.maxInt(i96);
    var our_verify: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        var t = std.Io.Clock.Timestamp.now(io, .awake);
        _ = try Ours.sign(gpa, io, dir, &kp);
        our_sign = @min(our_sign, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
        t = std.Io.Clock.Timestamp.now(io, .awake);
        try Ours.verify(gpa, io, dir, kp.publicKey(), cli_sig);
        our_verify = @min(our_verify, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }

    var buf: [2048]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("reference: {s}", .{ver.stdout});
    try w.print("{s:<8} {s:>12} {s:>12} {s:>9}   (256 MiB, best of 5)\n", .{ "op", "ours ms", "cli ms", "ours/cli" });
    const rs = [_]f64{ @as(f64, @floatFromInt(our_sign)) / cli_sign, @as(f64, @floatFromInt(our_verify)) / cli_verify };
    try w.print("{s:<8} {d:>12.1} {d:>12.1} {d:>9.2}\n", .{ "sign", @as(f64, @floatFromInt(our_sign)) / 1e6, cli_sign / 1e6, rs[0] });
    try w.print("{s:<8} {d:>12.1} {d:>12.1} {d:>9.2}\n", .{ "verify", @as(f64, @floatFromInt(our_verify)) / 1e6, cli_verify / 1e6, rs[1] });
    try w.print("\ncard: **Performance:** ref {d:.2}–{d:.2}× minisign <version> CLI · fastest ? (measured <today>)\n", .{ @min(rs[0], rs[1]), @max(rs[0], rs[1]) });
    try w.flush();
    return 0;
}

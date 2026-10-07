// SPDX-License-Identifier: MIT

//! Comparative benchmark: `blindrsa` against Cloudflare CIRCL v1.6.1
//! `blindsign/blindrsa` (Go), the program behind the `**Performance:**` line of
//! the maturity card (CONVENTIONS.md §9, kept instrument kind 3). RFC 9474 itself
//! is code-free; CIRCL is the measurable stand-in for the RFC reference, and the
//! card and SPEC rows say so.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-blindrsa` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` and `go`
//! (1.26.0) on PATH and CIRCL v1.6.1 in the Go module cache (`GOPROXY=off`:
//! nothing is downloaded; if it is missing the program prints the fetch recipe
//! and exits 2). Run from the repository root.
//!
//! Workloads: blind (client), blindSign (server), finalize (client, unblind +
//! verify) and verify, for RSA-2048 and RSA-4096, variants
//! RSABSSA-SHA384-PSS-Randomized and RSABSSA-SHA384-PSSZERO-Deterministic. The
//! key is generated once (by the Go side) into `.zig-cache/bench-blindrsa/` as
//! PKCS#1 DER and loaded by both sides. Both sides double the batch until it
//! takes over 100 ms and keep the best of five. Before timing anything:
//!   * ours blind-signs the message CIRCL blinded and CIRCL finalizes it;
//!   * CIRCL verifies the signature our client finalized;
//!   * ours verifies CIRCL's signature;
//!   * for the same blinded input the two blind signatures are byte-equal (an
//!     RSA signature over a fixed input is deterministic), and in the
//!     Deterministic variant so are the final signatures.
//! Timing note: CIRCL draws its randomness from `crypto/rand` (getrandom), ours
//! from a ChaCha CSPRNG, as each library's callers would.

const std = @import("std");
const blindrsa = @import("blindrsa");
const rsa = @import("rsa");

const Sha384 = std.crypto.hash.sha2.Sha384;

const work_dir = ".zig-cache/bench-blindrsa";
const recipe =
    \\bench-blindrsa: Go or CIRCL v1.6.1 not usable (see the error above)
    \\  needs go 1.26.0 and github.com/cloudflare/circl@v1.6.1 in the Go module cache
    \\  (offline, GOPROXY=off). Fetch (and review) it once with a network:
    \\    GOFLAGS=-mod=mod go mod download github.com/cloudflare/circl@v1.6.1
    \\  expected go.sum lines are committed in modules/blindrsa/tools/go_bench/go.sum.
    \\
;

const Row = struct { ns: f64, count: u64 };

const Variant = struct { name: []const u8, salt_len: usize, randomized: bool };
const variants = [_]Variant{
    .{ .name = "rand", .salt_len = 48, .randomized = true },
    .{ .name = "zero", .salt_len = 0, .randomized = false },
};
const sizes = [_]usize{ 2048, 4096 };

const State = struct {
    pk: rsa.PublicKey,
    sk: *const rsa.SecretKey,
    csprng: std.Random.DefaultCsprng,
    prepared: []const u8,
    salt_len: usize,
    ctx: blindrsa.Context,
    blinded: [rsa.max_modulus_len]u8,
    blinded_len: usize,
    blind_sig: [rsa.max_modulus_len]u8,
    sig: [rsa.max_modulus_len]u8,
    out: [rsa.max_modulus_len]u8,

    fn doBlind(s: *State) usize {
        const r = blindrsa.blind(s.pk, Sha384, s.prepared, s.salt_len, s.csprng.random(), &s.ctx, &s.out) catch unreachable;
        return r.len;
    }
    fn doBlindSign(s: *State) usize {
        const r = blindrsa.blindSign(s.sk, s.pk, s.csprng.random(), s.blinded[0..s.blinded_len], &s.out) catch unreachable;
        return r.len;
    }
    fn doFinalize(s: *State) usize {
        const r = blindrsa.finalize(s.pk, Sha384, s.blind_sig[0..s.blinded_len], &s.ctx, &s.out) catch unreachable;
        return r.len;
    }
    fn doVerify(s: *State) usize {
        blindrsa.verify(s.pk, Sha384, s.prepared, s.sig[0..s.blinded_len], s.salt_len) catch unreachable;
        return s.blinded_len;
    }
};

fn timeIt(io: std.Io, s: *State, comptime f: fn (*State) usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(f(s));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = f(s);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

fn runGo(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, abs: []const u8, phase: []const u8) !std.process.RunResult {
    const res = try std.process.run(arena, io, .{
        .argv = &.{ "go", "run", ".", abs, phase },
        .environ_map = env,
        .cwd = .{ .path = "modules/blindrsa/tools/go_bench" },
    });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-blindrsa: Go side ({s}) failed:\n{s}\n", .{ phase, res.stderr });
        return error.ForeignSideFailed;
    }
    return res;
}

fn fail(comptime fmt: []const u8, args: anytype) u8 {
    std.debug.print("bench-blindrsa: FAILED -- " ++ fmt ++ "\n", args);
    return 1;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_b11d);
    var msg: [64]u8 = undefined;
    prng.random().bytes(&msg);
    try dir.writeFile(io, .{ .sub_path = "msg.bin", .data = &msg });

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=mod");
    try env.put("GONOSUMDB", "*");
    try env.put("GOSUMDB", "off");

    std.debug.print("bench-blindrsa: CIRCL blind phase (keys are generated on the first run) ...\n", .{});
    _ = runGo(arena, io, &env, abs, "blind") catch {
        std.debug.print(recipe, .{});
        return 2;
    };

    // Interop before timing, and the per-configuration states.
    var states: [sizes.len * variants.len]*State = undefined;
    var si: usize = 0;
    for (sizes) |bits| {
        const key_file = try std.fmt.allocPrint(arena, "key{d}.der", .{bits});
        const pub_file = try std.fmt.allocPrint(arena, "pub{d}.der", .{bits});
        const sk = try arena.create(rsa.SecretKey);
        sk.* = try rsa.SecretKey.fromDer(try dir.readFileAlloc(io, key_file, arena, .limited(1 << 14)));
        const pk = try rsa.PublicKey.fromDer(try dir.readFileAlloc(io, pub_file, arena, .limited(1 << 14)));
        for (variants) |va| {
            const tag = try std.fmt.allocPrint(arena, "{d}_{s}", .{ bits, va.name });
            const rd = struct {
                fn f(d: std.Io.Dir, i: std.Io, a: std.mem.Allocator, t: []const u8, ext: []const u8) ![]u8 {
                    return d.readFileAlloc(i, try std.fmt.allocPrint(a, "{s}.{s}", .{ t, ext }), a, .limited(1 << 14));
                }
            }.f;
            const go_prepared = try rd(dir, io, arena, tag, "prepared");
            const go_blinded = try rd(dir, io, arena, tag, "blinded");
            const go_blindsig = try rd(dir, io, arena, tag, "go_blindsig");
            const go_sig = try rd(dir, io, arena, tag, "go_sig");

            const s = try arena.create(State);
            states[si] = s;
            si += 1;
            var seed: [32]u8 = @splat(0x42);
            seed[0] = @truncate(bits >> 4);
            s.* = .{
                .pk = pk,
                .sk = sk,
                .csprng = std.Random.DefaultCsprng.init(seed),
                .prepared = undefined,
                .salt_len = va.salt_len,
                .ctx = undefined,
                .blinded = undefined,
                .blinded_len = 0,
                .blind_sig = undefined,
                .sig = undefined,
                .out = undefined,
            };
            const k = (bits + 7) / 8;
            s.blinded_len = k;

            // (a) ours signs what CIRCL blinded; CIRCL finalizes it in the next phase.
            const ours_bs = try blindrsa.blindSign(sk, pk, s.csprng.random(), go_blinded, &s.out);
            if (!std.mem.eql(u8, ours_bs, go_blindsig)) return fail("{s}: our blind signature differs from CIRCL's for the same blinded message", .{tag});
            try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.ours_blindsig", .{tag}), .data = ours_bs });

            // (b) ours verifies CIRCL's final signature.
            blindrsa.verify(pk, Sha384, go_prepared, go_sig, va.salt_len) catch return fail("{s}: we reject the signature CIRCL finalized", .{tag});

            // (c) our whole client pipeline; CIRCL verifies the result in the next phase.
            const prepared_buf = try arena.alloc(u8, 32 + msg.len);
            s.prepared = if (va.randomized) try blindrsa.prepareRandomize(&msg, s.csprng.random(), prepared_buf) else blindrsa.prepareIdentity(&msg);
            const blinded = try blindrsa.blind(pk, Sha384, s.prepared, va.salt_len, s.csprng.random(), &s.ctx, &s.out);
            @memcpy(s.blinded[0..k], blinded);
            const bsig = try blindrsa.blindSign(sk, pk, s.csprng.random(), s.blinded[0..k], &s.out);
            @memcpy(s.blind_sig[0..k], bsig);
            const sig = try blindrsa.finalize(pk, Sha384, s.blind_sig[0..k], &s.ctx, &s.out);
            @memcpy(s.sig[0..k], sig);
            try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.ours_prepared", .{tag}), .data = s.prepared });
            try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.ours_sig", .{tag}), .data = sig });

            // (d) Deterministic variant: same prepared message, so the same signature.
            if (!va.randomized and !std.mem.eql(u8, sig, go_sig)) return fail("{s}: the Deterministic signature differs from CIRCL's", .{tag});
        }
    }

    std.debug.print("bench-blindrsa: CIRCL finalize/verify phase and timing ...\n", .{});
    const gres = runGo(arena, io, &env, abs, "finalize") catch return 1;
    var grows: std.StringHashMapUnmanaged(Row) = .empty;
    var lines = std.mem.tokenizeScalar(u8, gres.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
        const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
        try grows.put(arena, name, .{ .ns = ns, .count = count });
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("reference: {s} (stand-in for RFC 9474)\n", .{gres.stderr});
    try w.print("interop: CIRCL finalizes our blind signatures and verifies our signatures; we verify CIRCL's; blind signatures byte-equal; Deterministic signatures byte-equal\n", .{});
    try w.print("{s:<22} {s:>12} {s:>12} {s:>11}  bytes\n", .{ "workload", "ours ns/op", "CIRCL ns/op", "ours/CIRCL" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    si = 0;
    for (sizes) |bits| {
        for (variants) |va| {
            const s = states[si];
            si += 1;
            // timeIt's work reuses s.out; the per-op inputs stay in s.
            inline for (.{ "blind", "blindsign", "finalize", "verify" }) |wl| {
                const ours = switch (comptime std.meta.stringToEnum(enum { blind, blindsign, finalize, verify }, wl).?) {
                    .blind => blk: {
                        const r = timeIt(io, s, State.doBlind);
                        // doBlind replaced s.ctx; restore the pipeline state for the rest.
                        const b = try blindrsa.blind(s.pk, Sha384, s.prepared, s.salt_len, s.csprng.random(), &s.ctx, &s.out);
                        @memcpy(s.blinded[0..b.len], b);
                        const bs = try blindrsa.blindSign(s.sk, s.pk, s.csprng.random(), s.blinded[0..b.len], &s.out);
                        @memcpy(s.blind_sig[0..bs.len], bs);
                        const sg = try blindrsa.finalize(s.pk, Sha384, s.blind_sig[0..bs.len], &s.ctx, &s.out);
                        @memcpy(s.sig[0..sg.len], sg);
                        break :blk r;
                    },
                    .blindsign => timeIt(io, s, State.doBlindSign),
                    .finalize => timeIt(io, s, State.doFinalize),
                    .verify => timeIt(io, s, State.doVerify),
                };
                const name = try std.fmt.allocPrint(arena, "{d}_{s}_{s}", .{ bits, va.name, wl });
                const t = grows.get(name) orelse return error.MissingRow;
                const ratio = ours.ns / t.ns;
                worst = @max(worst, ratio);
                best = @min(best, ratio);
                const same = ours.count == t.count;
                if (!same) mismatch = true;
                try w.print("{s:<22} {d:>12.0} {d:>12.0} {d:>11.2}  {d}{s}\n", .{ name, ours.ns, t.ns, ratio, ours.count, if (same) "" else " ≠" });
                try w.flush();
            }
        }
    }
    if (mismatch) return 1;
    try w.print("\nworst ours/CIRCL = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× CIRCL v1.6.1 blindsign/blindrsa (stand-in for RFC 9474) · fastest ? (measured 2026-10-07)\n", .{ best, worst });
    try w.flush();
    return 0;
}

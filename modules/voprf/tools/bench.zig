// SPDX-License-Identifier: MIT

//! Comparative benchmark: `voprf` against Cloudflare CIRCL v1.6.1 `oprf` (Go),
//! the program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3). CIRCL is the measurable
//! reference for RFC 9497 (the RFC itself is code-free).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-voprf` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` and `go`
//! (1.26.x) on PATH and CIRCL v1.6.1 with go-ristretto v1.2.3 and x/crypto in
//! the Go module cache (`GOPROXY=off`: nothing is downloaded; if they are
//! missing the program prints the recipe and exits 2). Run from the repository
//! root.
//!
//! Suites: ristretto255-SHA512, P256-SHA256, P384-SHA384, P521-SHA512 (CIRCL
//! has no decaf448-SHAKE256, so that suite is not measured). Modes OPRF, VOPRF,
//! POPRF (info = "bench info"), batch size 1, input 64 bytes.
//!
//! API granularity: voprf's role objects (`OprfClient`/`VoprfClient`/
//! `PoprfClient`, `OprfServer`/...) against CIRCL's `Client`/`VerifiableClient`/
//! `PartialObliviousClient` and the matching servers. Workloads:
//!   blind      client Blind with a fresh random blind (ours: ChaCha CSPRNG
//!              draw + scalarFromWideBytes + blind; CIRCL: `Blind` with
//!              crypto/rand). Ours POPRF blind also derives the tweaked key
//!              (CIRCL does that in Finalize), hence the `client` row below.
//!   blindeval  server BlindEvaluate (VOPRF/POPRF include proof generation
//!              with a fresh random r)
//!   finalize   client Finalize (VOPRF/POPRF include proof verification)
//!   fulleval   server FullEvaluate / `evaluate`
//!   client     blind + finalize (a computed row: the sum of the two above).
//!              For POPRF the card counts this row instead of blind and
//!              finalize separately, whose split differs between the two.
//! Both sides double the batch until it takes over 100 ms and keep the best of
//! five.
//!
//! Interop before timing, per suite x mode:
//!   * DeriveKeyPair(seed, info) gives the same sk (and pk) on both sides;
//!   * FullEvaluate outputs are byte-equal;
//!   * both clients use the same blind scalar, so the blinded elements are
//!     byte-equal; our server evaluates CIRCL's blinded element and CIRCL
//!     finalizes it (verifying our proof in VOPRF/POPRF; output equals its
//!     FullEvaluate);
//!   * CIRCL's server evaluates the blinded element and we finalize it
//!     (verifying its proof; output equals our FullEvaluate).
//! Files go through `.zig-cache/bench-voprf/`.

const std = @import("std");
const voprf = @import("voprf");

const work_dir = ".zig-cache/bench-voprf";
const recipe =
    \\bench-voprf: Go or CIRCL v1.6.1 not usable (see the error above)
    \\  needs go 1.26.x and github.com/cloudflare/circl@v1.6.1 (+ go-ristretto v1.2.3, x/crypto v0.13.0,
    \\  x/sys v0.12.0) in the Go module cache (offline, GOPROXY=off). Fetch (and review) them once with a network:
    \\    (cd modules/voprf/tools/go_bench && GOFLAGS=-mod=mod go mod download)
    \\  expected go.sum lines are committed in modules/voprf/tools/go_bench/go.sum.
    \\
;

const Row = struct { ns: f64, count: u64 };
const GoRows = std.StringHashMapUnmanaged(Row);

const Mode = voprf.Mode;
const modes = [_]Mode{ .oprf, .voprf, .poprf };
const suite_names = [_][]const u8{ "r255", "p256", "p384", "p521" };
const key_seed: [32]u8 = @splat(0xa3);
const key_info = "bench key";
const poprf_info = "bench info";

const Stats = struct {
    worst: [suite_names.len]f64 = @splat(0),
    best: [suite_names.len]f64 = @splat(std.math.inf(f64)),
    worst_all: f64 = 0,
    best_all: f64 = std.math.inf(f64),
    mismatch: bool = false,

    fn add(s: *Stats, suite: usize, ratio: f64) void {
        s.worst[suite] = @max(s.worst[suite], ratio);
        s.best[suite] = @min(s.best[suite], ratio);
        s.worst_all = @max(s.worst_all, ratio);
        s.best_all = @min(s.best_all, ratio);
    }
};

const Ctx = struct {
    io: std.Io,
    arena: std.mem.Allocator,
    dir: std.Io.Dir,
    msg: []const u8,
};

fn readExact(c: Ctx, comptime N: usize, name: []const u8) ![N]u8 {
    const data = try c.dir.readFileAlloc(c.io, name, c.arena, .limited(1 << 12));
    if (data.len != N) {
        std.debug.print("bench-voprf: {s} has {d} bytes, expected {d}\n", .{ name, data.len, N });
        return error.BadForeignFile;
    }
    return data[0..N].*;
}

fn Runner(comptime P: type, comptime mode: Mode) type {
    const Ns = P.Ns;
    const Ne = P.Ne;
    const Nh = P.Nh;
    const Client = switch (mode) {
        .oprf => P.OprfClient,
        .voprf => P.VoprfClient,
        .poprf => P.PoprfClient,
    };
    const Server = switch (mode) {
        .oprf => P.OprfServer,
        .voprf => P.VoprfServer,
        .poprf => P.PoprfServer,
    };
    const verifiable = mode != .oprf;

    return struct {
        const Self = @This();

        tag: []const u8,
        suite: usize,
        input: []const u8,
        csprng: std.Random.DefaultCsprng,
        server: Server,
        pk: P.Element, // VOPRF/POPRF only (undefined for OPRF)
        blind_scalar: [Ns]u8,
        client: Client,
        evaluated: P.Element,
        proof: P.Proof, // VOPRF/POPRF only
        full: [Nh]u8,
        out: [Nh]u8,

        fn randScalar(s: *Self) [Ns]u8 {
            var wide: [P.wide_length]u8 = undefined;
            s.csprng.random().bytes(&wide);
            var sc: [Ns]u8 = undefined;
            P.scalarFromWideBytes(&wide, &sc);
            return sc;
        }

        fn makeClient(s: *Self, sc: *const [Ns]u8) Client {
            return switch (mode) {
                .oprf => Client.blind(s.input, sc) catch unreachable,
                .voprf => Client.blind(s.input, sc) catch unreachable,
                .poprf => Client.blind(s.input, poprf_info, s.pk, sc) catch unreachable,
            };
        }

        fn serverEval(s: *Self, blinded: P.Element, r: *const [Ns]u8) void {
            switch (mode) {
                .oprf => s.evaluated = s.server.blindEvaluate(blinded),
                .voprf => {
                    const v = s.server.blindEvaluate(blinded, r) catch unreachable;
                    s.evaluated = v.evaluated_element;
                    s.proof = v.proof;
                },
                .poprf => {
                    const v = s.server.blindEvaluate(blinded, poprf_info, r) catch unreachable;
                    s.evaluated = v.evaluated_element;
                    s.proof = v.proof;
                },
            }
        }

        fn clientFinalize(s: *Self, c: *const Client, evaluated: P.Element, proof: P.Proof) !void {
            switch (mode) {
                .oprf => try c.finalize(s.input, evaluated, &s.out),
                .voprf => try c.finalize(s.input, evaluated, proof, s.pk, &s.out),
                .poprf => try c.finalize(s.input, evaluated, proof, poprf_info, &s.out),
            }
        }

        // ---- timed operations ----
        fn doBlind(s: *Self) usize {
            const sc = s.randScalar();
            const c = s.makeClient(&sc);
            std.mem.doNotOptimizeAway(c);
            return Ne;
        }
        fn doBlindEval(s: *Self) usize {
            const r = s.randScalar();
            switch (mode) {
                .oprf => std.mem.doNotOptimizeAway(s.server.blindEvaluate(s.client.blinded_element)),
                .voprf => std.mem.doNotOptimizeAway(s.server.blindEvaluate(s.client.blinded_element, &r) catch unreachable),
                .poprf => std.mem.doNotOptimizeAway(s.server.blindEvaluate(s.client.blinded_element, poprf_info, &r) catch unreachable),
            }
            return Ne;
        }
        fn doFinalize(s: *Self) usize {
            s.clientFinalize(&s.client, s.evaluated, s.proof) catch unreachable;
            std.mem.doNotOptimizeAway(&s.out);
            return Nh;
        }
        fn doFull(s: *Self) usize {
            switch (mode) {
                .poprf => s.server.evaluate(s.input, poprf_info, &s.out) catch unreachable,
                else => s.server.evaluate(s.input, &s.out) catch unreachable,
            }
            std.mem.doNotOptimizeAway(&s.out);
            return Nh;
        }

        fn timeIt(io: std.Io, s: *Self, comptime f: fn (*Self) usize) Row {
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

        // ---- phases ----
        fn setup(c: Ctx, suite: usize, tag: []const u8) !*Self {
            const s = try c.arena.create(Self);
            s.tag = tag;
            s.suite = suite;
            s.input = c.msg;
            var seed: [32]u8 = @splat(0x42);
            seed[0] = @intCast(suite);
            seed[1] = @backingInt(mode);
            s.csprng = std.Random.DefaultCsprng.init(seed);
            s.server = try Server.derive(&key_seed, key_info);
            s.proof = undefined;
            s.pk = undefined;
            if (verifiable) s.pk = s.server.publicKey();
            s.blind_scalar = s.randScalar();
            try c.dir.writeFile(c.io, .{ .sub_path = try c.arena.print("{s}.blind", .{tag}), .data = &s.blind_scalar });
            s.client = s.makeClient(&s.blind_scalar);
            return s;
        }

        fn sk(s: *const Self) *const [Ns]u8 {
            return if (verifiable) &s.server.key_pair.sk else &s.server.sk;
        }

        /// After Go `prep`: compare, evaluate Go's blinded element, finalize Go's evaluation.
        fn check(s: *Self, c: Ctx) !?[]const u8 {
            const tag = s.tag;
            const nm = struct {
                fn f(a: std.mem.Allocator, t: []const u8, ext: []const u8) []const u8 {
                    return a.print("{s}.{s}", .{ t, ext }) catch unreachable;
                }
            }.f;
            const go_sk = try readExact(c, Ns, nm(c.arena, tag, "sk"));
            if (!std.mem.eql(u8, &go_sk, s.sk())) return "DeriveKeyPair: our sk differs from CIRCL's";
            if (verifiable) {
                const go_pk = try readExact(c, Ne, nm(c.arena, tag, "pk"));
                if (!std.mem.eql(u8, &go_pk, &s.pk.toBytes())) return "DeriveKeyPair: our pk differs from CIRCL's";
            }
            const go_full = try readExact(c, Nh, nm(c.arena, tag, "go_full"));
            s.doFullChecked();
            if (!std.mem.eql(u8, &go_full, &s.out)) return "FullEvaluate output differs from CIRCL's";
            s.full = go_full;

            // Same blind scalar on both sides: the blinded elements must be equal.
            const go_blinded_bytes = try readExact(c, Ne, nm(c.arena, tag, "go_blinded"));
            if (!std.mem.eql(u8, &go_blinded_bytes, &s.client.blinded_element.toBytes())) return "blinded element differs from CIRCL's for the same blind";
            const go_blinded = P.Element.fromBytes(go_blinded_bytes) catch return "cannot parse CIRCL's blinded element";

            // Our server evaluates CIRCL's blinded element; CIRCL finalizes in `run`.
            const r = s.randScalar();
            s.serverEval(go_blinded, &r);
            try c.dir.writeFile(c.io, .{ .sub_path = nm(c.arena, tag, "ours_eval"), .data = &s.evaluated.toBytes() });
            if (verifiable) try c.dir.writeFile(c.io, .{ .sub_path = nm(c.arena, tag, "ours_proof"), .data = &s.proof.toBytes() });

            // CIRCL's server evaluated the blinded element; we finalize it.
            const go_eval = P.Element.fromBytes(try readExact(c, Ne, nm(c.arena, tag, "go_eval"))) catch return "cannot parse CIRCL's evaluated element";
            var go_proof: P.Proof = undefined;
            if (verifiable) go_proof = P.Proof.fromBytes(try readExact(c, 2 * Ns, nm(c.arena, tag, "go_proof"))) catch return "cannot parse CIRCL's proof";
            s.clientFinalize(&s.client, go_eval, go_proof) catch return "we cannot finalize (verify) CIRCL's evaluation";
            if (!std.mem.eql(u8, &s.out, &go_full)) return "our finalize of CIRCL's evaluation differs from FullEvaluate";

            // Our own evaluation, finalized by us, for the timing state.
            if (!std.mem.eql(u8, &s.evaluated.toBytes(), &go_eval.toBytes())) return "our evaluated element differs from CIRCL's";
            s.clientFinalize(&s.client, s.evaluated, s.proof) catch return "we cannot finalize our own evaluation";
            if (!std.mem.eql(u8, &s.out, &go_full)) return "our finalize of our evaluation differs from FullEvaluate";
            return null;
        }

        fn doFullChecked(s: *Self) void {
            _ = s.doFull();
        }

        fn timing(s: *Self, c: Ctx, w: *std.Io.Writer, go: *const GoRows, stats: *Stats) !void {
            const ours = [_]Row{
                timeIt(c.io, s, doBlind),
                timeIt(c.io, s, doBlindEval),
                timeIt(c.io, s, doFinalize),
                timeIt(c.io, s, doFull),
            };
            const names = [_][]const u8{ "blind", "blindeval", "finalize", "fulleval" };
            var sum_ours: f64 = 0;
            var sum_go: f64 = 0;
            for (ours, names, 0..) |o, wl, i| {
                const name = try c.arena.print("{s}_{s}", .{ s.tag, wl });
                const t = go.get(name) orelse return error.MissingRow;
                const ratio = o.ns / t.ns;
                // POPRF splits the client's work differently: RFC 9497 (and
                // ours) derives the tweaked key in Blind, CIRCL in Finalize.
                // Those two rows are shown but not paired one to one; the
                // card takes their sum, the `client` row, which is.
                const split_differs = mode == .poprf and (i == 0 or i == 2);
                if (!split_differs) stats.add(s.suite, ratio);
                const same = o.count == t.count;
                if (!same) stats.mismatch = true;
                try w.print("{s:<22} {d:>12.0} {d:>12.0} {d:>11.2}  {d}{s}{s}\n", .{ name, o.ns, t.ns, ratio, o.count, if (same) "" else " ≠", if (split_differs) "  (split differs, see client)" else "" });
                if (i == 0 or i == 2) {
                    sum_ours += o.ns;
                    sum_go += t.ns;
                }
            }
            const name = try c.arena.print("{s}_client", .{s.tag});
            const ratio = sum_ours / sum_go;
            stats.add(s.suite, ratio);
            try w.print("{s:<22} {d:>12.0} {d:>12.0} {d:>11.2}  blind+finalize\n", .{ name, sum_ours, sum_go, ratio });
            try w.flush();
        }
    };
}

/// Type-erased entry so one list holds every suite x mode instantiation.
const Entry = struct {
    ctx: *anyopaque,
    tag: []const u8,
    checkFn: *const fn (*anyopaque, Ctx) anyerror!?[]const u8,
    timingFn: *const fn (*anyopaque, Ctx, *std.Io.Writer, *const GoRows, *Stats) anyerror!void,
};

fn entryFor(comptime P: type, comptime mode: Mode, c: Ctx, suite: usize, tag: []const u8) !Entry {
    const R = Runner(P, mode);
    const s = try R.setup(c, suite, tag);
    const thunks = struct {
        fn check(p: *anyopaque, cc: Ctx) anyerror!?[]const u8 {
            return R.check(@ptrCast(@alignCast(p)), cc);
        }
        fn timing(p: *anyopaque, cc: Ctx, w: *std.Io.Writer, go: *const GoRows, st: *Stats) anyerror!void {
            return R.timing(@ptrCast(@alignCast(p)), cc, w, go, st);
        }
    };
    return .{ .ctx = s, .tag = tag, .checkFn = thunks.check, .timingFn = thunks.timing };
}

fn runGo(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, abs: []const u8, phase: []const u8) !std.process.RunResult {
    const res = try std.process.run(arena, io, .{
        .argv = &.{ "go", "run", ".", abs, phase },
        .environ_map = env,
        .cwd = .{ .path = "modules/voprf/tools/go_bench" },
    });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-voprf: Go side ({s}) failed:\n{s}\n", .{ phase, res.stderr });
        return error.ForeignSideFailed;
    }
    return res;
}

fn fail(comptime fmt: []const u8, args: anytype) u8 {
    std.debug.print("bench-voprf: FAILED -- " ++ fmt ++ "\n", args);
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

    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_0f2f);
    var msg: [64]u8 = undefined;
    prng.random().bytes(&msg);
    try dir.writeFile(io, .{ .sub_path = "msg.bin", .data = &msg });
    const c: Ctx = .{ .io = io, .arena = arena, .dir = dir, .msg = &msg };

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=mod");
    try env.put("GONOSUMDB", "*");
    try env.put("GOSUMDB", "off");

    const protos = .{ voprf.Ristretto255Sha512, voprf.P256Sha256, voprf.P384Sha384, voprf.P521Sha512 };
    var entries: std.ArrayList(Entry) = .empty;
    inline for (protos, 0..) |P, si| {
        inline for (modes) |m| {
            const tag = try arena.print("{s}_{s}", .{ suite_names[si], @tagName(m) });
            try entries.append(arena, try entryFor(P, m, c, si, tag));
        }
    }

    std.debug.print("bench-voprf: CIRCL prep phase ...\n", .{});
    _ = runGo(arena, io, &env, abs, "prep") catch {
        std.debug.print(recipe, .{});
        return 2;
    };

    for (entries.items) |e| {
        if (try e.checkFn(e.ctx, c)) |why| return fail("{s}: {s}", .{ e.tag, why });
    }

    std.debug.print("bench-voprf: CIRCL finalize phase and timing ...\n", .{});
    const gres = runGo(arena, io, &env, abs, "run") catch return 1;
    var grows: GoRows = .empty;
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
    try w.print("reference: {s} (RFC 9497 has no code; decaf448-SHAKE256 not measured: CIRCL lacks it)\n", .{gres.stderr});
    try w.print("granularity: role objects (Oprf/Voprf/PoprfClient + Server) vs CIRCL Client/VerifiableClient/PartialObliviousClient + Server, batch 1\n", .{});
    try w.print("interop: same DeriveKeyPair sk/pk, FullEvaluate byte-equal, blinded elements byte-equal (shared blind), CIRCL finalizes our evaluation+proof, we finalize CIRCL's\n", .{});
    try w.print("{s:<22} {s:>12} {s:>12} {s:>11}  bytes\n", .{ "workload", "ours ns/op", "CIRCL ns/op", "ours/CIRCL" });
    var stats: Stats = .{};
    for (entries.items) |e| try e.timingFn(e.ctx, c, w, &grows, &stats);
    if (stats.mismatch) return 1;
    try w.print("\n", .{});
    for (suite_names, 0..) |sn, i| try w.print("{s}: worst ours/CIRCL = {d:.2} (best {d:.2})\n", .{ sn, stats.worst[i], stats.best[i] });
    try w.print("worst ours/CIRCL = {d:.2} (best {d:.2})\n", .{ stats.worst_all, stats.best_all });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× CIRCL v1.6.1 oprf (RFC 9497 reference stand-in; no decaf448) · fastest ? (measured 2026-11-14)\n", .{ stats.best_all, stats.worst_all });
    try w.flush();
    return 0;
}

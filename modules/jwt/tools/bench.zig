// SPDX-License-Identifier: MIT

//! Comparative benchmark: `jwt` against github.com/golang-jwt/jwt/v5 (the
//! reference: the most used JWT library of a compiled language, over Go's
//! standard-library crypto), the program behind the `**Performance:**` line
//! of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-jwt` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `go` on PATH and
//! golang-jwt v5.3.1 in the Go module cache (`go mod download
//! github.com/golang-jwt/jwt/v5@v5.3.1`; nothing is fetched by the bench:
//! GOPROXY=off, and `tools/go_bench/go.sum` pins the module). The Go side,
//! `tools/go_bench/main.go`, is copied into `.zig-cache/bench-jwt/go/` and
//! built there. Run from the repository root.
//!
//! Workloads, for HS256, ES256, ES384, ES512, EdDSA, RS256 and PS256 (since
//! 2026-10-13; HS256/ES256/EdDSA before), over the same keys on both sides
//! and a typical access token (iss, sub, aud, exp, nbf, iat, scope):
//!   <alg>_sign    `encodeJson(gpa, claims, key, .{})` (+ free) vs
//!                 `jwt.NewWithClaims(...).SignedString(key)`
//!   <alg>_verify  `parseAndVerify` with issuer, audience and expiry required
//!                 (+ deinit) vs `jwt.Parse` with the method pinned and
//!                 `WithIssuer`/`WithAudience`/`WithExpirationRequired`
//! Ours allocates from `std.heap.smp_allocator`; Go's side runs under its GC.
//! Keys and claims are written into `.zig-cache/bench-jwt/` from fixed seeds;
//! the RSA key (2048 bits) is RFC 7520 §3.4's, as raw n/d/p/q for Go.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. The Go
//! side has no cycle counter, so ratios are by wall time. Before timing
//! anything golang-jwt must accept our token for every algorithm and we must
//! accept its. Arguments filter workloads by substring.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const jwt = @import("jwt");

const bench_name = "bench-jwt";
const work_dir = ".zig-cache/bench-jwt";
const issuer = "https://issuer.example.com";
const audience = "api.example.com";
const claims_json =
    \\{"aud":"api.example.com","exp":4102444800,"iat":1700000000,"iss":"https://issuer.example.com","nbf":1700000000,"scope":"read write","sub":"user-1234567890"}
;
const algs = [_][]const u8{ "hs256", "es256", "es384", "es512", "eddsa", "rs256", "ps256" };

/// RFC 7520 §3.4 (Figure 4), base64url.
const rsa_n = "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_" ++ "AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpP" ++ "e7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg" ++ "_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw";
const rsa_d = "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwM" ++ "SMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2M" ++ "UBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQ" ++ "fGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ";
const rsa_p = "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9" ++ "JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k";
const rsa_q = "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15v" ++ "MMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc";

fn b64Alloc(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    const dec = std.base64.url_safe_no_pad.Decoder;
    const out = try arena.alloc(u8, try dec.calcSizeForSlice(s));
    try dec.decode(out, s);
    return out;
}

const Op = struct { alg: usize, verify: bool };

const Ctx = struct {
    signing: [algs.len]jwt.SigningKey,
    tokens: [algs.len][]const u8,
    op: Op = undefined,
};

const opts: jwt.Options = .{ .now_s = 1_760_000_000, .issuer = .{ .required = issuer }, .audience = .{ .required = audience } };

fn once(x: *Ctx) usize {
    const gpa = std.heap.smp_allocator;
    const key = x.signing[x.op.alg];
    if (x.op.verify) {
        var parsed = jwt.parseAndVerify(gpa, x.tokens[x.op.alg], key.verificationKey(), opts) catch unreachable;
        parsed.deinit();
        return 1;
    }
    const tok = jwt.encodeJson(gpa, claims_json, key, .{}) catch unreachable;
    defer gpa.free(tok);
    return tok.len;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir ++ "/go");
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    // Keys, shared with the Go side.
    var prng = std.Random.DefaultPrng.init(0x1a7_be7c);
    const r = prng.random();
    var hmac_key: [32]u8 = undefined;
    r.bytes(&hmac_key);
    var ec_seed: [jwt.EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    r.bytes(&ec_seed);
    const ec_kp = try arena.create(jwt.EcdsaP256Sha256.KeyPair);
    ec_kp.* = try jwt.EcdsaP256Sha256.KeyPair.generateDeterministic(ec_seed);
    var ed_seed: [32]u8 = undefined;
    r.bytes(&ed_seed);
    const ed_kp = try arena.create(jwt.Ed25519.KeyPair);
    ed_kp.* = try jwt.Ed25519.KeyPair.generateDeterministic(ed_seed);
    var ec384_seed: [jwt.EcdsaP384Sha384.KeyPair.seed_length]u8 = undefined;
    r.bytes(&ec384_seed);
    const ec384_kp = try arena.create(jwt.EcdsaP384Sha384.KeyPair);
    ec384_kp.* = try jwt.EcdsaP384Sha384.KeyPair.generateDeterministic(ec384_seed);
    var ec521_seed: [jwt.EcdsaP521Sha512.KeyPair.seed_length]u8 = undefined;
    r.bytes(&ec521_seed);
    const ec521_kp = try arena.create(jwt.EcdsaP521Sha512.KeyPair);
    try jwt.EcdsaP521Sha512.KeyPair.generateDeterministicInto(ec521_kp, &ec521_seed);
    const n = try b64Alloc(arena, rsa_n);
    const rsa_kp = try arena.create(jwt.rsa.KeyPair);
    try jwt.rsa.SecretKey.fromPrimes(&rsa_kp.secret_key, try b64Alloc(arena, rsa_p), try b64Alloc(arena, rsa_q), &.{ 1, 0, 1 });
    rsa_kp.public_key = try jwt.rsa.PublicKey.fromBytes(n, &.{ 1, 0, 1 });
    // PS256's salt and blinding: a fixed-seed CSPRNG (a bench, not a key).
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5a)));
    try dir.writeFile(io, .{ .sub_path = "hs256.key", .data = &hmac_key });
    try dir.writeFile(io, .{ .sub_path = "es256.key", .data = &ec_kp.secret_key.toBytes() });
    try dir.writeFile(io, .{ .sub_path = "es384.key", .data = &ec384_kp.secret_key.toBytes() });
    try dir.writeFile(io, .{ .sub_path = "es512.key", .data = &ec521_kp.secret_key.toBytes() });
    try dir.writeFile(io, .{ .sub_path = "eddsa.seed", .data = &ed_seed });
    try dir.writeFile(io, .{ .sub_path = "rsa.n", .data = n });
    try dir.writeFile(io, .{ .sub_path = "rsa.d", .data = try b64Alloc(arena, rsa_d) });
    try dir.writeFile(io, .{ .sub_path = "rsa.p", .data = try b64Alloc(arena, rsa_p) });
    try dir.writeFile(io, .{ .sub_path = "rsa.q", .data = try b64Alloc(arena, rsa_q) });

    var ctx: Ctx = .{ .signing = .{
        .{ .hs256 = &hmac_key },
        .{ .es256 = ec_kp },
        .{ .es384 = ec384_kp },
        .{ .es512 = ec521_kp },
        .{ .ed25519 = ed_kp },
        .{ .rs256 = rsa_kp },
        .{ .ps256 = .{ .key = rsa_kp, .random = csprng.random() } },
    }, .tokens = undefined };
    for (algs, 0..) |a, i| {
        ctx.tokens[i] = try jwt.encodeJson(arena, claims_json, ctx.signing[i], .{});
        try dir.writeFile(io, .{ .sub_path = try arena.print("zig_{s}.jwt", .{a}), .data = ctx.tokens[i] });
    }

    // Build the Go side in a copy of tools/go_bench.
    for ([_][]const u8{ "go.mod", "go.sum", "main.go" }) |f| {
        const src = try cwd.readFileAlloc(io, try arena.print("modules/jwt/tools/go_bench/{s}", .{f}), arena, .limited(1 << 20));
        try dir.writeFile(io, .{ .sub_path = try arena.print("go/{s}", .{f}), .data = src });
    }
    const exe = try arena.print("{s}/foreign_bench", .{abs});
    const go_dir = try arena.print("{s}/go", .{abs});
    std.debug.print("bench-jwt: building the Go side ...\n", .{});
    const gb = try std.process.run(arena, io, .{ .argv = &.{ "env", "GOPROXY=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOWORK=off", "go", "-C", go_dir, "build", "-o", exe, "." } });
    if (gb.term != .exited or gb.term.exited != 0) {
        std.debug.print("bench-jwt: go build failed (is golang-jwt v5.3.1 in the module cache?):\n{s}\n", .{gb.stderr});
        return 1;
    }

    // Interop before timing: Go accepted ours inside `interop`; now we accept Go's.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    for (algs, 0..) |a, i| {
        const theirs = try dir.readFileAlloc(io, try arena.print("go_{s}.jwt", .{a}), arena, .limited(1 << 16));
        var parsed = jwt.parseAndVerify(arena, theirs, ctx.signing[i].verificationKey(), opts) catch |e| {
            std.debug.print("bench-jwt: FAILED -- golang-jwt's {s} token is rejected here: {s}\n", .{ a, @errorName(e) });
            return 1;
        };
        parsed.deinit();
    }

    var ws: std.ArrayList(Work) = .empty;
    for (algs, 0..) |a, i| for ([_]bool{ false, true }) |verify| {
        const op = if (verify) "verify" else "sign";
        try ws.append(arena, .{
            .name = try arena.print("{s}_{s}", .{ a, op }),
            .op = .{ .alg = i, .verify = verify },
            .ref = try arena.print("go.{s}_{s}", .{ a, op }),
        });
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/golang-jwt = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× golang-jwt v5.3.1 (Go <version>) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

// SPDX-License-Identifier: MIT

//! Comparative benchmark: `mlkem` against OpenSSL 3.5's libcrypto (the
//! reference named by the maturity card), aws-lc-rs 1.18.0 (the fastest ML-KEM
//! in the field) and, as an informational baseline, `std.crypto.kem.ml_kem`.
//! The program behind the `**Performance:**` line of the card (CONVENTIONS.md
//! §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-mlkem` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds the C side, `tools/c_bench/foreign_bench.c`, with `zig cc -O3
//! -march=native`), the system OpenSSL 3.5 (`libcrypto.so.3`, path below or
//! `LIBCRYPTO_SO`; no headers needed) and `cargo` (the Rust side,
//! `tools/rust_bench`, is built once with `--release --locked --offline` into
//! `.zig-cache/bench-mlkem/target`). Run from the repository root.
//!
//! Workloads, for each of ML-KEM-512, -768 and -1024 (`<n>`), what a TLS
//! stack does with the KEM -- public APIs only:
//!   keygen_<n>    generate a key pair and encode the encapsulation key (the
//!                 client's key share). Ours: `KeyPair.generateDeterministicInto`
//!                 from a seed drawn from a ChaCha CSPRNG (inside the timed
//!                 region), `PublicKey.toBytes`; OpenSSL: EVP_PKEY_generate +
//!                 "pub"; aws-lc-rs: `DecapsulationKey::generate` +
//!                 `encapsulation_key().key_bytes()`.
//!   encaps_<n>    parse the ek octets and encapsulate (the server). Ours:
//!                 `PublicKey.fromBytes` + `encapsDeterministic` (m from the
//!                 CSPRNG); OpenSSL: EVP_PKEY_fromdata + EVP_PKEY_encapsulate;
//!                 aws-lc-rs: `EncapsulationKey::new` + `encapsulate`.
//!   decaps_<n>    decapsulate with an already loaded key (the client).
//!   ek_parse_<n>  `fromBytes` alone. INFO rows, kept out of the verdict:
//!                 aws-lc-rs does not run the FIPS 203 §7.2 modulus check there
//!                 and ours also expands the matrix, so the sides do not do the
//!                 same work.
//! The count of a row is the size of its output (ek, ciphertext, 32), which the
//! sides must agree on. Randomness: ours draws from the CSPRNG (the std lane
//! too), OpenSSL and aws-lc-rs from their own DRBGs; no `getrandom` call is in a
//! timed region. Ratios are ours / reference by user-mode cycles when all sides
//! count them, else by wall time.
//!
//! Before anything is timed: ours and std must agree byte for byte (keygen from
//! a seed, deterministic encaps, decaps, an implicit-rejection decaps); then
//! each foreign side must (interop gate) decapsulate our ciphertext with our dk
//! loaded into it, accept our ek and encapsulate to it (we decapsulate that),
//! and hand us its own ek/dk, to which we encapsulate (it decapsulates that).
//!
//! Method (`testkit.bench`): each side doubles its batch until it takes over
//! 100 ms and keeps the best of five; per workload the sides alternate for
//! `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the spread printed
//! is (worst round - best round) / best round per side. `/fast` is ours over the
//! faster of OpenSSL and aws-lc-rs per row. The `std` table that follows times
//! ours and std alternately the same way. Arguments filter workloads by
//! substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const mlkem = @import("mlkem");

const StdKem = std.crypto.kem.ml_kem;
const Work = bench.Work(Op);

const bench_name = "bench-mlkem";
const work_dir = ".zig-cache/bench-mlkem";
const cargo_manifest = "modules/mlkem/tools/rust_bench/Cargo.toml";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const seed_byte: u8 = 0x5e;

const Kind = enum { keygen, encaps, decaps, parse };
const Lane = enum { ours, std };
const Op = struct { kind: Kind = .keygen, set: u8 = 0, lane: Lane = .ours };
const Ctx = struct { op: Op = .{} };

var csprng: std.Random.DefaultCsprng = undefined;

/// One parameter set, both implementations: the state the timed operations use.
fn Set(comptime Ours: type, comptime Std: type) type {
    return struct {
        const ek_len = Ours.PublicKey.encoded_length;
        const dk_len = Ours.SecretKey.encoded_length;
        const ct_len = Ours.ciphertext_length;
        comptime {
            std.debug.assert(ek_len == Std.PublicKey.encoded_length);
            std.debug.assert(dk_len == Std.SecretKey.encoded_length);
            std.debug.assert(ct_len == Std.ciphertext_length);
        }

        var seed: [64]u8 = undefined;
        var m: [32]u8 = undefined;
        var ours_kp: Ours.KeyPair = undefined;
        var std_kp: Std.KeyPair = undefined;
        var scratch_kp: Ours.KeyPair = undefined;
        var ek: [ek_len]u8 = undefined;
        var dk: [dk_len]u8 = undefined;
        var ct: [ct_len]u8 = undefined;
        var ss: [32]u8 = undefined;

        /// Fixed inputs, and the ours-vs-std agreement gate.
        fn setup() !void {
            csprng.random().bytes(&seed);
            csprng.random().bytes(&m);
            ours_kp = Ours.KeyPair.generateDeterministic(seed);
            std_kp = try Std.KeyPair.generateDeterministic(seed);
            ek = ours_kp.public_key.toBytes();
            dk = ours_kp.secret_key.toBytes();
            if (!std.mem.eql(u8, &ek, &std_kp.public_key.toBytes())) return fail("{s}: keygen ek differs from std", .{Ours.name});
            if (!std.mem.eql(u8, &dk, &std_kp.secret_key.toBytes())) return fail("{s}: keygen dk differs from std", .{Ours.name});
            const e = ours_kp.public_key.encapsDeterministic(&m);
            const f = std_kp.public_key.encapsDeterministic(&m);
            if (!std.mem.eql(u8, &e.ciphertext, &f.ciphertext) or !std.mem.eql(u8, &e.shared_secret, &f.shared_secret))
                return fail("{s}: encaps differs from std", .{Ours.name});
            ct = e.ciphertext;
            ss = e.shared_secret;
            if (!std.mem.eql(u8, &ours_kp.secret_key.decaps(&ct), &ss)) return fail("{s}: decaps does not return the encapsulated secret", .{Ours.name});
            var bad = ct;
            bad[7] ^= 0x10;
            if (!std.mem.eql(u8, &ours_kp.secret_key.decaps(&bad), &(try std_kp.secret_key.decaps(&bad))))
                return fail("{s}: implicit-rejection decaps differs from std", .{Ours.name});
        }

        fn run(kind: Kind, lane: Lane) usize {
            switch (lane) {
                .ours => switch (kind) {
                    .keygen => {
                        csprng.random().bytes(&seed);
                        Ours.KeyPair.generateDeterministicInto(&scratch_kp, &seed);
                        const out = scratch_kp.public_key.toBytes();
                        std.mem.doNotOptimizeAway(&out);
                        return out.len;
                    },
                    .encaps => {
                        const pk = Ours.PublicKey.fromBytes(&ek) catch @panic("PublicKey.fromBytes");
                        csprng.random().bytes(&m);
                        const r = pk.encapsDeterministic(&m);
                        std.mem.doNotOptimizeAway(&r);
                        return r.ciphertext.len;
                    },
                    .decaps => {
                        const r = ours_kp.secret_key.decaps(&ct);
                        std.mem.doNotOptimizeAway(&r);
                        return r.len;
                    },
                    .parse => {
                        const pk = Ours.PublicKey.fromBytes(&ek) catch @panic("PublicKey.fromBytes");
                        std.mem.doNotOptimizeAway(&pk);
                        return ek_len;
                    },
                },
                .std => switch (kind) {
                    .keygen => {
                        csprng.random().bytes(&seed);
                        const kp = Std.KeyPair.generateDeterministic(seed) catch @panic("std keygen");
                        const out = kp.public_key.toBytes();
                        std.mem.doNotOptimizeAway(&out);
                        return out.len;
                    },
                    .encaps => {
                        const pk = Std.PublicKey.fromBytes(&ek) catch @panic("std fromBytes");
                        csprng.random().bytes(&m);
                        const r = pk.encapsDeterministic(&m);
                        std.mem.doNotOptimizeAway(&r);
                        return r.ciphertext.len;
                    },
                    .decaps => {
                        const r = std_kp.secret_key.decaps(&ct) catch @panic("std decaps");
                        std.mem.doNotOptimizeAway(&r);
                        return r.len;
                    },
                    .parse => {
                        const pk = Std.PublicKey.fromBytes(&ek) catch @panic("std fromBytes");
                        std.mem.doNotOptimizeAway(&pk);
                        return ek_len;
                    },
                },
            }
        }

        /// Our half of the interop gate. `zin_*` is what the foreign sides get.
        fn writeOurs(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime n: []const u8) !void {
            try put(dir, io, arena, "zin_mlkem" ++ n ++ ".ek", &ek);
            try put(dir, io, arena, "zin_mlkem" ++ n ++ ".dk", &dk);
            try put(dir, io, arena, "zin_mlkem" ++ n ++ ".ct", &ct);
            try put(dir, io, arena, "zin_mlkem" ++ n ++ ".ss", &ss);
        }

        /// The foreign side `who` encapsulated to our ek and generated a key pair.
        fn check(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime n: []const u8, comptime who: Who) !void {
            const label = who.label ++ " ML-KEM-" ++ n;
            const t_ct = try get(dir, io, arena, who.theirs ++ "_mlkem" ++ n ++ ".ct");
            const t_ss = try get(dir, io, arena, who.theirs ++ "_mlkem" ++ n ++ ".ss");
            if (t_ct.len != ct_len or t_ss.len != 32) return fail("{s}: bad ciphertext or secret length", .{label});
            if (!std.mem.eql(u8, &ours_kp.secret_key.decaps(t_ct[0..ct_len]), t_ss))
                return fail("{s}: we decapsulate its ciphertext to another secret", .{label});
            const t_ek = try get(dir, io, arena, who.theirs ++ "_mlkem" ++ n ++ ".ek");
            const t_dk = try get(dir, io, arena, who.theirs ++ "_mlkem" ++ n ++ ".dk");
            if (t_ek.len != ek_len or t_dk.len != dk_len) return fail("{s}: bad key length", .{label});
            const pk = Ours.PublicKey.fromBytes(t_ek[0..ek_len]) catch |e| return fail("{s}: we reject its ek ({t})", .{ label, e });
            _ = Ours.SecretKey.fromBytes(t_dk[0..dk_len]) catch |e| return fail("{s}: we reject its dk ({t})", .{ label, e });
            // FIPS 203 dk = dkPKE ‖ ek ‖ H(ek) ‖ z.
            if (!std.mem.eql(u8, t_dk[dk_len - ek_len - 64 ..][0..ek_len], t_ek)) return fail("{s}: its dk does not embed its ek", .{label});
            const e = pk.encapsDeterministic(&m);
            try put(dir, io, arena, who.ours ++ "_mlkem" ++ n ++ ".ct", &e.ciphertext);
            try put(dir, io, arena, who.ours ++ "_mlkem" ++ n ++ ".ss", &e.shared_secret);
        }
    };
}

const S512 = Set(mlkem.MLKem512, StdKem.MLKem512);
const S768 = Set(mlkem.MLKem768, StdKem.MLKem768);
const S1024 = Set(mlkem.MLKem1024, StdKem.MLKem1024);
const set_names = [_][]const u8{ "512", "768", "1024" };

fn once(x: *Ctx) usize {
    const o = x.op;
    return switch (o.set) {
        0 => S512.run(o.kind, o.lane),
        1 => S768.run(o.kind, o.lane),
        else => S1024.run(o.kind, o.lane),
    };
}

// ---- interop ----

fn put(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime name: []const u8, data: []const u8) !void {
    _ = arena;
    try dir.writeFile(io, .{ .sub_path = name, .data = data });
}

fn get(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime name: []const u8) ![]u8 {
    return dir.readFileAlloc(io, name, arena, .limited(1 << 16));
}

fn fail(comptime fmt: []const u8, args: anytype) error{InteropFailed} {
    std.debug.print(bench_name ++ ": FAILED -- " ++ fmt ++ "\n", args);
    return error.InteropFailed;
}

const Who = struct { label: []const u8, theirs: []const u8, ours: []const u8 };
const ossl: Who = .{ .label = "OpenSSL", .theirs = "ossl", .ours = "zig" };
const aws: Who = .{ .label = "aws-lc-rs", .theirs = "aws", .ours = "zigA" };

fn checkAll(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator, comptime who: Who) !void {
    try S512.check(dir, io, arena, "512", who);
    try S768.check(dir, io, arena, "768", who);
    try S1024.check(dir, io, arena, "1024", who);
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

    csprng = .init(@splat(seed_byte));
    try S512.setup();
    try S768.setup();
    try S1024.setup();
    try S512.writeOurs(dir, io, arena, "512");
    try S768.writeOurs(dir, io, arena, "768");
    try S1024.writeOurs(dir, io, arena, "1024");
    std.debug.print("{s}: ours and std agree byte for byte (keygen, encaps, decaps, implicit rejection; 3 sets)\n", .{bench_name});

    const crypto_so = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/mlkem/tools/c_bench/foreign_bench.c", &.{crypto_so});
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    try checkAll(dir, io, arena, ossl);
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop2");
    std.debug.print("{s}: interop OK with OpenSSL (3 sets, both directions)\n", .{bench_name});

    // aws-lc-rs: built once, offline, then the same gate.
    var env = try init.environ_map.clone(arena);
    const target = try arena.print("{s}/target", .{abs});
    try env.put("CARGO_TARGET_DIR", target);
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const cargo = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", cargo_manifest },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return 1;
    };
    if (cargo.term != .exited or cargo.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, cargo.stderr });
        return 1;
    }
    const rust_exe = try arena.print("{s}/release/rust_bench", .{target});
    try bench.foreignOnce(arena, io, bench_name, rust_exe, abs, "interop");
    try checkAll(dir, io, arena, aws);
    try bench.foreignOnce(arena, io, bench_name, rust_exe, abs, "interop2");
    std.debug.print("{s}: interop OK with aws-lc-rs (same checks)\n", .{bench_name});

    var ws: std.ArrayList(Work) = .empty;
    inline for (.{ .keygen, .encaps, .decaps, .parse }) |k| {
        for (set_names, 0..) |sn, i| {
            const n = try arena.print("{s}_{s}", .{ if (k == .parse) "ek_parse" else @tagName(k), sn });
            try ws.append(arena, .{ .name = n, .op = .{ .kind = k, .set = @intCast(i) }, .ref = n, .alt = n, .alt_exe = 1, .info = k == .parse });
        }
    }

    var ctx: Ctx = .{};
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ exe, rust_exe }, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\ncandidate: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3}); worst ours/min(OpenSSL, aws-lc-rs) = {d:.3}  (ek_parse rows are info, not counted)\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });

    // The informational std baseline: ours and std, alternating, same method.
    try w.print("\nstd.crypto.kem.ml_kem baseline (info)\n{s:<18} {s:>11} {s:>11} {s:>7}\n", .{ "workload", "ours ns", "std ns", "/std" });
    const cyc: bench.Cycles = .open();
    defer cyc.close();
    for (ws.items) |x| {
        if (!bench.selected(x.name, filters)) continue;
        var ours: bench.Side = .{};
        var theirs: bench.Side = .{};
        for (0..@max(1, rounds)) |_| {
            ctx.op = x.op;
            ctx.op.lane = .ours;
            ours.add(bench.timeIt(io, cyc, once, .{&ctx}, false));
            ctx.op.lane = .std;
            theirs.add(bench.timeIt(io, cyc, once, .{&ctx}, false));
        }
        const by = ours.best_cyc > 0 and theirs.best_cyc > 0;
        try w.print("{s:<18} {d:>11.0} {d:>11.0} {d:>7.3}\n", .{ x.name, ours.best_ns, theirs.best_ns, ours.best(by) / theirs.best(by) });
    }
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> libcrypto (keygen, encaps, decaps × 3 sets) · fastest {d:.2}× worst vs the faster of OpenSSL and aws-lc-rs 1.18.0 (measured <today>)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}

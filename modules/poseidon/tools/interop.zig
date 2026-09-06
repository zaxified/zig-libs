// SPDX-License-Identifier: MIT
//! The sympy oracle behind `src/mds_replay_test.zig` — the instrument that
//! TAKES the MDS subspace-trail anchor, kept outside the module.
//!
//! ## Why this is a program and not a test
//!
//! A module in this repository is standalone Zig with no external dependency.
//! Until 2026-09-06 this comparison lived in `src/reference_interop.zig`: it
//! `@embedFile`d a 285-line Python driver into module source and spawned
//! `python3` from inside `zig build test-poseidon`, so every consumer of the
//! library carried foreign source and the module's own test lane needed a
//! toolchain it has no business needing. It skipped loudly without it — and a
//! skip is not an assertion, so on any host without sympy the four algorithms
//! had no oracle at all.
//!
//! The split, per `build.zig`'s interop mechanism:
//!
//!   * this program drives `tools/subspace_trail.py` and CAPTURES what it says
//!     into `src/testdata/mds_subspace_trail.txt`;
//!   * `src/mds_replay_test.zig` replays that transcript with no Python
//!     anywhere, which is where the anchor's value now runs;
//!   * `zig build check-interop` compiles this file and runs nothing, so the
//!     instrument cannot rot unnoticed.
//!
//! ## What the oracle is worth — unchanged by the move
//!
//! **Tier 2, not an external anchor.** sage is not installed here, so the peer
//! is a Python transcription of the *same* `reference_params.sage` text the Zig
//! side was written from. It catches transcription slips — an index off by one,
//! a wrong sub-code, a rejection that fails to advance the Grain stream — and it
//! categorically does **not** catch a shared misreading of the specification.
//! The grade-1 anchor for this module remains circomlib's and the authors'
//! published constants, which `constants_test.zig` pins. See `SPEC.md`
//! §"Anchoring".
//!
//! Where it IS strong: the inputs are chosen so the checks *fail*. Over BN254 a
//! random matrix passes with probability `1 - 2^-236`, so an oracle fed only
//! Poseidon-sized inputs would agree with `return true`. Most batches here are
//! over `p = 101` and `p = 251`, where matrices are rejected constantly, and the
//! comparison is on the sub-code and the failing round, not on a boolean.
//!
//! ## Usage
//!
//! ```sh
//! zig build interop-poseidon                # live: reference vs the committed
//!                                           # transcript, exit 1 on drift
//! zig build interop-poseidon -- --capture   # re-take the transcript
//! ```
//!
//! Needs `python3` with `sympy`; without it the program exits non-zero and says
//! so, which is the difference between an instrument and a skip.
//!
//! ## The input set is authored HERE, and cross-checked THERE
//!
//! This program builds every matrix it sends to the oracle, so `--capture` is
//! one self-contained command. `src/mds_replay_test.zig` regenerates the same
//! matrices from the module's own code and requires them to equal the ones the
//! transcript records, so this file's arithmetic is not trusted — a divergence
//! between the two ports fails the module's hermetic lane, loudly.

const std = @import("std");
const poseidon = @import("poseidon");
const bn254 = @import("bn254");

const grain = poseidon.grain;

const default_fixture = "modules/poseidon/src/testdata/mds_subspace_trail.txt";
const default_driver = "modules/poseidon/tools/subspace_trail.py";
const default_scratch = ".zig-cache/interop-poseidon";

const p101: u256 = 101;
const p251: u256 = 251;

/// One matrix's verdicts, exactly the six numbers the driver prints.
const Verdict = struct {
    alg1_secure: bool,
    alg1_code: u8,
    alg1_round: usize,
    alg2: bool,
    alg3: bool,
    minpoly: bool,
};

/// A named set of matrices over one prime at one width, plus whether the
/// minimal-polynomial condition is asked for. `vals` is `count * t * t`
/// decimals, row-major, one matrix after another.
const Batch = struct {
    id: []const u8,
    p: u256,
    t: usize,
    want_minpoly: bool,
    vals: []const u256,

    fn count(b: Batch) usize {
        return b.vals.len / (b.t * b.t);
    }
};

// ── the input set ───────────────────────────────────────────────────────────

/// The same LCG `mds_replay_test.zig`'s `samples()` uses: a plain deterministic
/// stream, so a case can be quoted in a bug report without shipping an RNG.
fn randomBatch(
    gpa: std.mem.Allocator,
    id: []const u8,
    p: u256,
    t: usize,
    n: usize,
    seed: u64,
) !Batch {
    const vals = try gpa.alloc(u256, n * t * t);
    var state = seed;
    for (vals) |*v| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        // The module side writes `state >> 11` big-endian into 32 bytes and
        // calls `Fr.reduceWide`, which is exactly this reduction.
        v.* = @as(u256, state >> 11) % p;
    }
    return .{ .id = id, .p = p, .t = t, .want_minpoly = true, .vals = vals };
}

fn literalBatch(
    gpa: std.mem.Allocator,
    id: []const u8,
    p: u256,
    t: usize,
    want_minpoly: bool,
    vals: []const u64,
) !Batch {
    const out = try gpa.alloc(u256, vals.len);
    for (vals, out) |v, *o| o.* = v;
    return .{ .id = id, .p = p, .t = t, .want_minpoly = want_minpoly, .vals = out };
}

/// `a^-1 mod p` by Fermat. Six lines rather than an import: this program cannot
/// see the module's test-only `small_field.zig` (it is deliberately not
/// exported), and the replay test proves the two agree.
fn invMod(a: u64, p: u64) u64 {
    var result: u64 = 1;
    var base = a % p;
    var e: u64 = p - 2;
    while (e > 0) : (e >>= 1) {
        if (e & 1 == 1) result = result * base % p;
        base = base * base % p;
    }
    return result;
}

/// The exact `create_mds_p` candidates the rejection loop draws over GF(101)
/// for `t = 5, R_F = 8, R_P = 21` — accepted and rejected alike. This is the
/// input distribution an argument about `derive` is really about, and it is not
/// a random one.
fn cauchyBatch(gpa: std.mem.Allocator, id: []const u8) !Batch {
    const p: u64 = 101;
    const t: usize = 5;
    const n: u12 = 7;
    const r_f: u10 = 8;
    const r_p: u10 = 21;
    const wanted = 3;

    var lfsr: grain.Lfsr = .init(n, @intCast(t), r_f, r_p);
    // Skip the round constants: each is drawn with rejection against p, and
    // that rejection is what advances the stream to where the MDS draw starts.
    const num_constants = (@as(usize, r_f) + r_p) * t;
    for (0..num_constants) |_| {
        var v = lfsr.nextNum(n);
        while (v >= p) v = lfsr.nextNum(n);
    }

    var vals = try gpa.alloc(u256, wanted * t * t);
    var drawn: usize = 0;
    while (drawn < wanted) {
        var rand_list: [2 * t]u64 = undefined;
        while (true) {
            // `reduceWide` of the drawn number, which for these widths is the
            // number itself reduced mod p.
            for (&rand_list) |*e| e.* = @intCast(lfsr.nextNum(n) % p);
            var dup = false;
            for (0..2 * t) |i| {
                for (i + 1..2 * t) |j| {
                    if (rand_list[i] == rand_list[j]) dup = true;
                }
            }
            if (!dup) break;
        }
        var singular = false;
        var m: [t * t]u64 = undefined;
        for (0..t) |i| {
            for (0..t) |j| {
                const s = (rand_list[i] + rand_list[t + j]) % p;
                if (s == 0) singular = true else m[i * t + j] = invMod(s, p);
            }
        }
        if (singular) continue;
        for (m, 0..) |v, k| vals[drawn * t * t + k] = v;
        drawn += 1;
    }
    return .{ .id = id, .p = p, .t = t, .want_minpoly = false, .vals = vals };
}

/// The shipped BN254 MDS matrix at the real field size. Everything here passes
/// — which is exactly why the small-field batches exist — but it proves neither
/// port depends on the modulus being small.
fn bn254Batch(gpa: std.mem.Allocator, id: []const u8) !Batch {
    const t = 3;
    const P = poseidon.bn254.Perm(t).init();
    var vals = try gpa.alloc(u256, t * t);
    for (0..t) |i| {
        for (0..t) |j| {
            const be = P.mds[i][j].toBytes();
            vals[i * t + j] = std.mem.readInt(u256, &be, .big);
        }
    }
    return .{
        .id = id,
        .p = std.mem.readInt(u256, &bn254.scalar.r_bytes, .big),
        .t = t,
        .want_minpoly = false,
        .vals = vals,
    };
}

/// Constructed `algorithm_1` failures — one per sub-code, per width. Random
/// matrices over GF(101) never fail `algorithm_1` (measured: 0 of 168; its
/// failures need a rank-deficient observability matrix, a ~1/p event), so
/// without these the sub-code comparison — the whole reason the oracle is worth
/// running — would be vacuous. The reasoning for each is in
/// `src/mds_replay_test.zig`, next to the assertions.
const constructed_t3 = [_]u64{
    1, 0, 0, 0, 1, 0, 0, 0, 1, // scalar at i = 1: the identity
    0, 4, 0, 1, 0, 0, 0, 0, 2, // scalar at i = 2 but not i = 1: M^2 = 4I
    2, 0, 0, 0, 3, 0, 0, 0, 5, // diagonal: eigenvectors inside S_1
    2, 5, 0, 0, 3, 0, 0, 0, 3, // block triangular, rational trailing eigenvalue
    0, 0, 1, 1, 0, 0, 0, 1, 0, // 3-cycle: only lambda = 1 is rational
    7, 0, 0, 3, 2, 5, 11, 13, 4, // e_0 fixed: the row sequence stalls at once
};

const constructed_t4 = [_]u64{
    2, 3, 0, 0, 5, 7, 0, 0, 0, 0, 11, 0, 0, 0, 0, 13, // block diagonal
    2, 3, 0, 0, 5, 7, 0, 0, 9, 1, 11, 2, 4, 6, 8, 13, // non-diagonal trailing block
    0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, // doubled 2-cycle: M^2 = I
    3, 0, 0, 0, 0, 3, 0, 0, 0, 0, 3, 0, 0, 0, 0, 3, // scalar
};

/// Every batch, in transcript order. 182 matrices.
fn buildBatches(gpa: std.mem.Allocator) ![]Batch {
    var list: std.ArrayList(Batch) = .empty;
    errdefer list.deinit(gpa);

    inline for (.{ 3, 4, 5, 6 }) |t| {
        try list.append(gpa, try randomBatch(
            gpa,
            std.fmt.comptimePrint("gf101_random_t{d}", .{t}),
            p101,
            t,
            26,
            0xC0FFEE + t,
        ));
    }
    inline for (.{ 3, 4, 5, 6 }) |t| {
        try list.append(gpa, try randomBatch(
            gpa,
            std.fmt.comptimePrint("gf251_random_t{d}", .{t}),
            p251,
            t,
            16,
            0xBEEF + t,
        ));
    }
    try list.append(gpa, try literalBatch(gpa, "gf101_constructed_t3", p101, 3, true, &constructed_t3));
    try list.append(gpa, try literalBatch(gpa, "gf101_constructed_t4", p101, 4, true, &constructed_t4));
    try list.append(gpa, try cauchyBatch(gpa, "gf101_cauchy_t5"));
    try list.append(gpa, try bn254Batch(gpa, "bn254_mds_t3"));

    return list.toOwnedSlice(gpa);
}

// ── running the oracle ──────────────────────────────────────────────────────

const Ref = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    driver: []const u8,
    scratch: []const u8,
    in_path: []const u8,
    out_path: []const u8,

    fn init(gpa: std.mem.Allocator, io: std.Io, driver: []const u8, scratch: []const u8) !Ref {
        try std.Io.Dir.cwd().createDirPath(io, scratch);
        return .{
            .gpa = gpa,
            .io = io,
            .driver = driver,
            .scratch = scratch,
            .in_path = try std.fmt.allocPrint(gpa, "{s}/in.txt", .{scratch}),
            .out_path = try std.fmt.allocPrint(gpa, "{s}/out.txt", .{scratch}),
        };
    }

    fn deinit(self: *Ref) void {
        self.gpa.free(self.in_path);
        self.gpa.free(self.out_path);
    }

    /// `python3 <driver> --meta` — the provenance line for the transcript
    /// header. Doubles as the "is the peer installed" probe.
    fn meta(self: *Ref) ![]u8 {
        var child = std.process.spawn(self.io, .{
            .argv = &.{ "python3", self.driver, "--meta" },
            .stdin = .close,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch |e| {
            std.debug.print(
                "cannot run `python3 {s}`: {t}\n" ++
                    "This program needs python3 with sympy (pip install sympy), and it must\n" ++
                    "be run from the repository root so the driver path resolves.\n",
                .{ self.driver, e },
            );
            return error.NoPeer;
        };
        var out_buf: [4096]u8 = undefined;
        var err_buf: [4096]u8 = undefined;
        var out_reader = child.stdout.?.reader(self.io, &out_buf);
        var err_reader = child.stderr.?.reader(self.io, &err_buf);
        const out = try out_reader.interface.allocRemaining(self.gpa, .limited(1 << 16));
        errdefer self.gpa.free(out);
        const err = try err_reader.interface.allocRemaining(self.gpa, .limited(1 << 16));
        defer self.gpa.free(err);
        switch (try child.wait(self.io)) {
            .exited => |code| if (code != 0) {
                std.debug.print("`python3 {s} --meta` failed:\n{s}\n", .{ self.driver, err });
                return error.NoPeer;
            },
            else => return error.NoPeer,
        }
        return out;
    }

    /// Runs one batch through the oracle. Caller frees.
    fn run(self: *Ref, b: Batch) ![]Verdict {
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        const w = &aw.writer;
        try w.print("{d}\n{d}\n{d}\n{d}\n", .{ b.p, b.t, b.count(), @intFromBool(b.want_minpoly) });
        for (b.vals, 0..) |v, i| {
            try w.print("{d}", .{v});
            try w.writeAll(if ((i + 1) % b.t == 0) "\n" else " ");
        }
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = self.in_path, .data = aw.written() });
        std.Io.Dir.cwd().deleteFile(self.io, self.out_path) catch {};

        var child = try std.process.spawn(self.io, .{
            .argv = &.{ "python3", self.driver, self.in_path, self.out_path },
            .stdin = .close,
            .stdout = .ignore,
            .stderr = .pipe,
        });
        var err_buf: [8192]u8 = undefined;
        var err_reader = child.stderr.?.reader(self.io, &err_buf);
        const err = try err_reader.interface.allocRemaining(self.gpa, .limited(1 << 20));
        defer self.gpa.free(err);
        switch (try child.wait(self.io)) {
            .exited => |code| if (code != 0) {
                std.debug.print("driver failed on batch {s}:\n{s}\n", .{ b.id, err });
                return error.ReferenceFailed;
            },
            else => return error.ReferenceCrashed,
        }

        const text = try std.Io.Dir.cwd().readFileAlloc(self.io, self.out_path, self.gpa, .limited(1 << 20));
        defer self.gpa.free(text);
        return parseVerdicts(self.gpa, text);
    }
};

fn parseVerdicts(gpa: std.mem.Allocator, text: []const u8) ![]Verdict {
    var out: std.ArrayList(Verdict) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \r");
        try out.append(gpa, .{
            .alg1_secure = (try std.fmt.parseInt(u8, f.next() orelse return error.ShortLine, 10)) == 1,
            .alg1_code = try std.fmt.parseInt(u8, f.next() orelse return error.ShortLine, 10),
            .alg1_round = try std.fmt.parseInt(usize, f.next() orelse return error.ShortLine, 10),
            .alg2 = (try std.fmt.parseInt(u8, f.next() orelse return error.ShortLine, 10)) == 1,
            .alg3 = (try std.fmt.parseInt(u8, f.next() orelse return error.ShortLine, 10)) == 1,
            .minpoly = (try std.fmt.parseInt(u8, f.next() orelse return error.ShortLine, 10)) == 1,
        });
    }
    return out.toOwnedSlice(gpa);
}

// ── the transcript ──────────────────────────────────────────────────────────

fn writeFixture(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    driver: []const u8,
    meta_line: []const u8,
    batches: []const Batch,
    verdicts: []const []Verdict,
) !void {
    var it = std.mem.tokenizeAny(u8, meta_line, " \r\n");
    const python = it.next() orelse "unknown";
    const sympy = it.next() orelse "unknown";
    const captured = it.next() orelse "unknown";

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const w = &aw.writer;

    try w.print(
        \\# MDS subspace-trail transcript — what the sympy oracle said, captured once.
        \\#
        \\# reference : {s}
        \\#             an independent port of `algorithm_1`/`2`/`3` and
        \\#             `check_minpoly_condition` from the Poseidon authors'
        \\#             `generate_parameters_grain.sage`, on sympy's DomainMatrix.
        \\#             Tier 2: a second transcription of the same sage text, not
        \\#             an external implementation. See that file and SPEC.md.
        \\# python    : {s}
        \\# sympy     : {s}
        \\# captured  : {s}
        \\# command   : zig build interop-poseidon -- --capture
        \\#
        \\# Determinism: the verdicts are a pure function of (p, t, matrix) — the
        \\# four algorithms take no randomness, no time and no environment, and
        \\# the matrices below are recorded in full. Nothing else has to be
        \\# pinned for this file to be reproducible.
        \\#
        \\# Format: `batch <id> p=<prime> t=<width> minpoly=<0|1> count=<n>`, then
        \\# per matrix an `m` line of t*t decimals (row-major) and a `v` line of
        \\# `alg1_secure alg1_code alg1_round alg2 alg3 minpoly`.
        \\#
        \\# `src/mds_replay_test.zig` regenerates every matrix from the module's
        \\# own code and requires it to equal the `m` line here, so this file
        \\# cannot drift into pinning inputs nobody produces any more.
        \\
    , .{ driver, python, sympy, captured });

    for (batches, verdicts) |b, vs| {
        try w.print("\nbatch {s} p={d} t={d} minpoly={d} count={d}\n", .{
            b.id, b.p, b.t, @intFromBool(b.want_minpoly), b.count(),
        });
        for (vs, 0..) |v, k| {
            try w.writeAll("m");
            for (b.vals[k * b.t * b.t ..][0 .. b.t * b.t]) |e| try w.print(" {d}", .{e});
            try w.print("\nv {d} {d} {d} {d} {d} {d}\n", .{
                @intFromBool(v.alg1_secure), v.alg1_code,          v.alg1_round,
                @intFromBool(v.alg2),        @intFromBool(v.alg3), @intFromBool(v.minpoly),
            });
        }
    }

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = aw.written() });
}

/// The committed transcript's verdicts for one batch, by id.
fn fixtureVerdicts(gpa: std.mem.Allocator, text: []const u8, id: []const u8) ![]Verdict {
    var out: std.ArrayList(Verdict) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    var inside = false;
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "batch ")) {
            var f = std.mem.tokenizeAny(u8, line[6..], " \r");
            inside = std.mem.eql(u8, f.next() orelse "", id);
            continue;
        }
        if (!inside or !std.mem.startsWith(u8, line, "v ")) continue;
        const one = try parseVerdicts(gpa, line[2..]);
        defer gpa.free(one);
        try out.append(gpa, one[0]);
    }
    return out.toOwnedSlice(gpa);
}

// ── main ────────────────────────────────────────────────────────────────────

const usage =
    \\usage: zig build interop-poseidon [-- <options>]
    \\
    \\  (no options)        run the sympy oracle and diff it against the committed
    \\                      transcript; exit 1 on any drift
    \\  --capture           run the oracle and rewrite the transcript
    \\  --fixture <path>    transcript path (default modules/poseidon/src/testdata/…)
    \\  --driver <path>     the Python driver (default modules/poseidon/tools/…)
    \\  --scratch <dir>     scratch directory (default .zig-cache/interop-poseidon)
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var capture = false;
    var fixture_path: []const u8 = default_fixture;
    var driver_path: []const u8 = default_driver;
    var scratch: []const u8 = default_scratch;

    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, a, "--fixture")) {
            fixture_path = args.next() orelse return usageError();
        } else if (std.mem.eql(u8, a, "--driver")) {
            driver_path = args.next() orelse return usageError();
        } else if (std.mem.eql(u8, a, "--scratch")) {
            scratch = args.next() orelse return usageError();
        } else {
            return usageError();
        }
    }

    const batches = try buildBatches(gpa);
    defer {
        for (batches) |b| gpa.free(b.vals);
        gpa.free(batches);
    }

    var ref = try Ref.init(gpa, io, driver_path, scratch);
    defer ref.deinit();

    const meta_line = ref.meta() catch return 1;
    defer gpa.free(meta_line);
    std.debug.print("oracle: {s}", .{meta_line});

    var all: std.ArrayList([]Verdict) = .empty;
    defer {
        for (all.items) |v| gpa.free(v);
        all.deinit(gpa);
    }
    var total: usize = 0;
    for (batches) |b| {
        const vs = try ref.run(b);
        if (vs.len != b.count()) {
            gpa.free(vs);
            std.debug.print("batch {s}: oracle returned {d} verdicts for {d} matrices\n", .{ b.id, vs.len, b.count() });
            return 1;
        }
        try all.append(gpa, vs);
        total += vs.len;
        var rejected: usize = 0;
        for (vs) |v| {
            if (!v.alg1_secure or !v.alg2 or !v.alg3) rejected += 1;
        }
        std.debug.print("  {s}: {d} matrices, {d} rejected\n", .{ b.id, vs.len, rejected });
    }

    if (capture) {
        try writeFixture(gpa, io, fixture_path, driver_path, meta_line, batches, all.items);
        std.debug.print("captured {d} matrices in {d} batches to {s}\n", .{ total, batches.len, fixture_path });
        return 0;
    }

    // Live mode: the oracle against the committed transcript. What the module's
    // own tests cannot see is the peer CHANGING — a sympy upgrade, a different
    // Python, a fix upstream — and that is exactly what this compares.
    const text = std.Io.Dir.cwd().readFileAlloc(io, fixture_path, gpa, .limited(8 << 20)) catch |e| {
        std.debug.print("cannot read {s}: {t} (run with --capture to create it)\n", .{ fixture_path, e });
        return 1;
    };
    defer gpa.free(text);

    var drift: usize = 0;
    for (batches, all.items) |b, live| {
        const stored = try fixtureVerdicts(gpa, text, b.id);
        defer gpa.free(stored);
        if (stored.len != live.len) {
            std.debug.print("batch {s}: transcript has {d} verdicts, oracle produced {d}\n", .{ b.id, stored.len, live.len });
            drift += 1;
            continue;
        }
        for (stored, live, 0..) |s, l, i| {
            if (std.meta.eql(s, l)) continue;
            std.debug.print(
                "batch {s} case {d}: transcript {any}\n                 oracle     {any}\n",
                .{ b.id, i, s, l },
            );
            drift += 1;
        }
    }
    if (drift != 0) {
        std.debug.print("\n{d} divergence(s): the reference no longer says what {s} records.\n" ++
            "Investigate before re-capturing — a changed verdict is a finding, not a chore.\n", .{ drift, fixture_path });
        return 1;
    }
    std.debug.print("\n{d} matrices in {d} batches: the oracle still agrees with the transcript.\n", .{ total, batches.len });
    return 0;
}

fn usageError() u8 {
    std.debug.print("{s}", .{usage});
    return 2;
}

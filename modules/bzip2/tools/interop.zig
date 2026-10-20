// SPDX-License-Identifier: MIT

//! Differential oracle against libbzip2 1.0.8 (built from the pinned clone by
//! `build-oracle.sh`, driven as a black box through `c_oracle/bzref.c`) and
//! against Python's `bz2` module (libbz2 as shipped).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-bzip2` runs it,
//! `zig build check-interop` only compiles it. From the repository root:
//!
//!   zig build interop-bzip2                 # live comparison, all shapes
//!   zig build interop-bzip2 -- --capture    # ... and rewrite src/testdata/
//!   zig build interop-bzip2 -- --quick      # fewer levels / mutants
//!
//! What it checks, per input shape (`bzip2.interop_corpus`):
//!   1. our compressed bytes == libbzip2's, at levels 1..9 (a subset for the
//!      big shapes), work factors 1/30/100 on the repetitive ones, and with
//!      libbzip2 fed in 5000-byte `BZ_RUN` calls the way the bzip2 CLI does;
//!   2. Python's `bz2.decompress` returns the input from OUR stream;
//!   3. our decoder returns the input from libbzip2's stream and from
//!      Python's `bz2.compress`; concatenated streams; a randomised block;
//!   4. mutated streams (bit flips, cuts, overwrites): ours and libbzip2's
//!      verdicts agree (accepts with the same length, or both refuse).
//! `--capture` freezes (1) as SHA-256 digests plus small reference streams
//! into `src/testdata/`, which `src/golden_test.zig` replays offline.
//!
//! Needs `cc` (first run), `git` (first run, to fetch the pinned source) and
//! `python3`. Missing references are failures, not skips.

const std = @import("std");
const bzip2 = @import("bzip2");
const corpus = bzip2.interop_corpus;

const scratch = ".zig-cache/bzip2-interop";
const bzref = ".zig-cache/bzip2-oracle/bzref";
const testdata = "modules/bzip2/src/testdata";

const Ctx = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    failures: usize = 0,
    checks: usize = 0,

    fn fail(c: *Ctx, comptime fmt: []const u8, args: anytype) void {
        c.failures += 1;
        std.debug.print("FAIL " ++ fmt ++ "\n", args);
    }

    fn exec(c: *Ctx, argv: []const []const u8) !std.process.RunResult {
        return std.process.run(c.gpa, c.io, .{ .argv = argv }) catch |e| {
            std.debug.print("could not run {s} ({s})\n", .{ argv[0], @errorName(e) });
            return error.NoReference;
        };
    }

    fn put(c: *Ctx, name: []const u8, data: []const u8) !void {
        try c.dir.writeFile(c.io, .{ .sub_path = name, .data = data });
    }

    fn get(c: *Ctx, name: []const u8) ![]u8 {
        return c.dir.readFileAlloc(c.io, name, c.gpa, .unlimited);
    }

    fn okExit(r: std.process.RunResult) bool {
        return switch (r.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    /// libbzip2's compression of `plain`; chunk 0 = one BZ_RUN call.
    fn refCompress(c: *Ctx, plain: []const u8, level: u8, wf: u8, chunk: usize) ![]u8 {
        try c.put("in.bin", plain);
        var lb: [4]u8 = undefined;
        var wb: [4]u8 = undefined;
        var cb: [16]u8 = undefined;
        const r = try c.exec(&.{
            bzref,                                   "c",
            try std.mem.print(&lb, "{d}", .{level}), try std.mem.print(&wb, "{d}", .{wf}),
            try std.mem.print(&cb, "{d}", .{chunk}), scratch ++ "/in.bin",
            scratch ++ "/ref.bz2",
        });
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) return error.ReferenceFailed;
        return c.get("ref.bz2");
    }

    /// libbzip2's verdict on a stream: status name and output length.
    const Verdict = struct { ok: bool, len: usize };
    fn refVerdict(c: *Ctx, stream: []const u8) !Verdict {
        try c.put("v.bz2", stream);
        const r = try c.exec(&.{ bzref, "t", scratch ++ "/v.bz2" });
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) return error.ReferenceFailed;
        var it = std.mem.tokenizeScalar(u8, r.stdout, ' ');
        const status = it.next() orelse return error.ReferenceFailed;
        const n = std.fmt.parseInt(usize, std.mem.trim(u8, it.next() orelse "0", "\n"), 10) catch return error.ReferenceFailed;
        return .{ .ok = std.mem.eql(u8, status, "BZ_STREAM_END"), .len = n };
    }

    fn pyDecompress(c: *Ctx, stream: []const u8) !?[]u8 {
        try c.put("p.bz2", stream);
        const r = try c.exec(&.{
            "python3",                                                                                     "-I",                "-c",
            "import bz2,sys\nopen(sys.argv[2],'wb').write(bz2.decompress(open(sys.argv[1],'rb').read()))", scratch ++ "/p.bz2", scratch ++ "/p.out",
        });
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) return null;
        return try c.get("p.out");
    }

    fn pyCompress(c: *Ctx, plain: []const u8, level: u8) ![]u8 {
        try c.put("in.bin", plain);
        var lb: [4]u8 = undefined;
        const r = try c.exec(&.{
            "python3",                                                                                                     "-I",                 "-c",
            "import bz2,sys\nopen(sys.argv[2],'wb').write(bz2.compress(open(sys.argv[1],'rb').read(), int(sys.argv[3])))", scratch ++ "/in.bin", scratch ++ "/py.bz2",
            try std.mem.print(&lb, "{d}", .{level}),
        });
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) return error.ReferenceFailed;
        return c.get("py.bz2");
    }
};

fn sha256Hex(data: []const u8) [64]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return std.fmt.bytesToHex(h, .lower);
}

const Golden = struct { shape: []const u8, level: u8, wf: u8, len: usize, sha: [64]u8, stream: ?[]const u8 };

fn levelsFor(len: usize, quick: bool) []const u8 {
    if (quick) return &.{ 1, 9 };
    return if (len <= 400_000) &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 } else &.{ 1, 5, 9 };
}

fn encoderParity(c: *Ctx, quick: bool, goldens: *std.ArrayList(Golden)) !void {
    for (corpus.shapes) |shape| {
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        var wfs: []const u8 = &.{30};
        // `tc-*` (table-count thresholds) and `wf-*` (sort path) shapes exist
        // for level 9 only; the `wf-*` ones take all three work factors.
        const tc = std.mem.startsWith(u8, shape.name, "tc-");
        const wfshape = std.mem.startsWith(u8, shape.name, "wf-");
        switch (shape.kind) {
            .zeros, .periodic, .skewed, .runs, .text => if ((shape.len >= 100_000 and !quick) or wfshape) {
                wfs = &.{ 1, 30, 100 };
            },
            else => {},
        }
        const levels: []const u8 = if (tc or wfshape) &.{9} else levelsFor(shape.len, quick);
        for (levels) |level| {
            for (wfs) |wf| {
                const want = try c.refCompress(plain, level, wf, 0);
                defer c.gpa.free(want);
                const got = try bzip2.compress(c.gpa, plain, .{ .level = @intCast(level), .work_factor = wf });
                defer c.gpa.free(got);
                c.checks += 1;
                if (!std.mem.eql(u8, want, got)) {
                    c.fail("encoder {s} level {d} wf {d}: {d} bytes vs libbzip2's {d}", .{ shape.name, level, wf, got.len, want.len });
                    continue;
                }
                if (try c.pyDecompress(got)) |back| {
                    defer c.gpa.free(back);
                    c.checks += 1;
                    if (!std.mem.eql(u8, back, plain)) c.fail("python bz2 read {s} level {d} wrongly", .{ shape.name, level });
                } else c.fail("python bz2 refused our {s} level {d}", .{ shape.name, level });

                const keep_stream = !tc and !wfshape and shape.len <= 10_000 and (level == 1 or level == 9) and wf == 30;
                if (level == 1 or level == 9 or wf != 30) {
                    try goldens.append(c.gpa, .{
                        .shape = shape.name,
                        .level = level,
                        .wf = wf,
                        .len = got.len,
                        .sha = sha256Hex(got),
                        .stream = if (keep_stream) try c.gpa.dupe(u8, got) else null,
                    });
                }
            }
        }
        // Fed in 5000-byte pieces the way the bzip2 CLI does, libbzip2 gives
        // the same bytes (block closing is not chunk dependent for us).
        if (shape.len > 0) {
            for ([_]u8{ 1, 9 }) |level| {
                const want = try c.refCompress(plain, level, 30, 5000);
                defer c.gpa.free(want);
                var out: std.Io.Writer.Allocating = .init(c.gpa);
                defer out.deinit();
                var enc = try bzip2.Encoder.init(c.gpa, &out.writer, .{ .level = @intCast(level) });
                defer enc.deinit();
                var at: usize = 0;
                while (at < plain.len) : (at += 5000) try enc.write(plain[at..@min(at + 5000, plain.len)]);
                try enc.finish();
                c.checks += 1;
                if (!std.mem.eql(u8, want, out.written())) c.fail("encoder {s} level {d}: 5000-byte pieces differ from libbzip2's", .{ shape.name, level });
            }
        }
    }
}

fn decoderChecks(c: *Ctx, quick: bool) !void {
    // Python-made streams, libbzip2-made streams, multi-stream, randomised.
    for (corpus.shapes) |shape| {
        if (shape.len > 400_000 and quick) continue;
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        for ([_]u8{ 1, 9 }) |level| {
            const py = try c.pyCompress(plain, level);
            defer c.gpa.free(py);
            const back = bzip2.decompress(c.gpa, py, .{}) catch |e| {
                c.fail("decoder {s} python level {d}: {s}", .{ shape.name, level, @errorName(e) });
                continue;
            };
            defer c.gpa.free(back);
            c.checks += 1;
            if (!std.mem.eql(u8, back, plain)) c.fail("decoder {s} python level {d}: wrong output", .{ shape.name, level });
        }
    }
    // Stream boundaries: concatenation, an empty stream, trailing bytes.
    {
        const pa = try corpus.generate(c.gpa, corpus.find("text-small").?);
        defer c.gpa.free(pa);
        const za = try c.refCompress(pa, 9, 30, 0);
        defer c.gpa.free(za);
        const ze = try c.refCompress("", 1, 30, 0);
        defer c.gpa.free(ze);
        const parts = [_][]const []const u8{
            &.{ za, za },                           &.{ za, ze, za }, &.{ ze, ze },     &.{ ze, za, ze },
            &.{ za, "junk" },                       &.{ za, "BZ" },   &.{ za, "BZh9" }, &.{ za, &.{ 0, 0, 0, 0 } },
            &.{ za, za[0..20] },                    &.{ za, "BZh0" }, &.{ za, "BZh1" }, &.{za[0 .. za.len - 1]},
            &.{za},                                 &.{ze},           &.{""},           &.{"BZh9"},
            &.{"BZh9\x17rE8P\x90\x00\x00\x00\x00"},
        };
        for (parts, 0..) |ps, i| {
            const joined = try std.mem.concat(c.gpa, u8, ps);
            defer c.gpa.free(joined);
            const v = try c.refVerdict(joined);
            c.checks += 1;
            if (bzip2.decompress(c.gpa, joined, .{})) |out| {
                defer c.gpa.free(out);
                if (!v.ok or v.len != out.len) c.fail("stream-boundary case {d}: we accept {d} bytes, libbzip2 ok={} len={d}", .{ i, out.len, v.ok, v.len });
            } else |e| if (v.ok) c.fail("stream-boundary case {d}: we refuse ({s}), libbzip2 accepts {d} bytes", .{ i, @errorName(e), v.len });
        }
    }
    // Randomised blocks: crafted by our encoder, read by libbzip2.
    for ([_][]const u8{ "text-small", "zeros-2m", "runs-300", "all-bytes", "run259" }) |name| {
        const shape = corpus.find(name).?;
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        var out: std.Io.Writer.Allocating = .init(c.gpa);
        defer out.deinit();
        var enc = try bzip2.Encoder.init(c.gpa, &out.writer, .{ .level = 1 });
        defer enc.deinit();
        enc.randomise = true;
        try enc.write(plain);
        try enc.finish();
        const v = try c.refVerdict(out.written());
        c.checks += 1;
        if (!v.ok or v.len != plain.len) c.fail("libbzip2 does not read our randomised {s}", .{name});
        const ours = try bzip2.decompress(c.gpa, out.written(), .{});
        defer c.gpa.free(ours);
        if (!std.mem.eql(u8, ours, plain)) c.fail("we do not read our randomised {s}", .{name});
    }
}

fn mutantChecks(c: *Ctx, quick: bool) !void {
    const names = [_][]const u8{ "text-9999", "random-small", "run259", "all-bytes", "sparse-100" };
    var prng: std.Random.DefaultPrng = .init(0xb21b);
    const rnd = prng.random();
    const per: usize = if (quick) 40 else 300;
    var agree_ok: usize = 0;
    var agree_err: usize = 0;
    for (names) |name| {
        var shape = corpus.find(name).?;
        shape.len = @min(shape.len, 20_000);
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        const base = try c.refCompress(plain, 9, 30, 0);
        defer c.gpa.free(base);
        for (0..per) |_| {
            const m = try c.gpa.dupe(u8, base);
            defer c.gpa.free(m);
            var cut: usize = m.len;
            switch (rnd.uintLessThan(u8, 5)) {
                0 => m[rnd.uintLessThan(usize, m.len)] ^= @as(u8, 1) << rnd.int(u3),
                1 => cut = rnd.uintLessThan(usize, m.len),
                2 => m[rnd.uintLessThan(usize, m.len)] = rnd.int(u8),
                3 => for (0..1 + rnd.uintLessThan(u8, 4)) |_| {
                    m[rnd.uintLessThan(usize, m.len)] ^= @as(u8, 1) << rnd.int(u3);
                },
                else => @memset(m[rnd.uintLessThan(usize, m.len)..][0..1], 0xff),
            }
            const s = m[0..cut];
            const v = try c.refVerdict(s);
            c.checks += 1;
            if (bzip2.decompress(c.gpa, s, .{})) |out| {
                defer c.gpa.free(out);
                if (!v.ok or v.len != out.len) {
                    c.fail("mutant of {s}: we accept ({d} bytes), libbzip2 says ok={} len={d}", .{ name, out.len, v.ok, v.len });
                    try c.put("mutant.bz2", s);
                } else agree_ok += 1;
            } else |e| {
                if (v.ok) {
                    c.fail("mutant of {s}: we refuse ({s}), libbzip2 accepts {d} bytes", .{ name, @errorName(e), v.len });
                    try c.put("mutant.bz2", s);
                } else agree_err += 1;
            }
        }
    }
    std.debug.print("mutants: {d} agreed on acceptance, {d} on refusal\n", .{ agree_ok, agree_err });
}

fn writeGoldens(c: *Ctx, goldens: []const Golden) !void {
    var out: std.Io.Writer.Allocating = .init(c.gpa);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll(
        \\// SPDX-License-Identifier: MIT
        \\//
        \\// GENERATED by `zig build interop-bzip2 -- --capture` (tools/interop.zig).
        \\// libbzip2 1.0.8's output for the shapes of `shapes.zig`: SHA-256 and
        \\// length of the whole stream, and the stream itself for the small ones.
        \\
        \\pub const Golden = struct {
        \\    shape: []const u8,
        \\    level: u8,
        \\    work_factor: u8,
        \\    len: usize,
        \\    sha256: []const u8,
        \\    stream: ?[]const u8 = null,
        \\};
        \\
        \\pub const goldens = [_]Golden{
        \\
    );
    for (goldens) |g| {
        try w.print("    .{{ .shape = \"{s}\", .level = {d}, .work_factor = {d}, .len = {d}, .sha256 = \"{s}\"", .{ g.shape, g.level, g.wf, g.len, g.sha });
        if (g.stream != null) try w.print(", .stream = @embedFile(\"ref/{s}-{d}.bz2\")", .{ g.shape, g.level });
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    try std.Io.Dir.cwd().createDirPath(c.io, testdata ++ "/ref");
    var d = try std.Io.Dir.cwd().openDir(c.io, testdata, .{});
    defer d.close(c.io);
    try d.writeFile(c.io, .{ .sub_path = "goldens.zig", .data = out.written() });
    for (goldens) |g| if (g.stream) |s| {
        var nb: [128]u8 = undefined;
        const name = try std.mem.print(&nb, "ref/{s}-{d}.bz2", .{ g.shape, g.level });
        try d.writeFile(c.io, .{ .sub_path = name, .data = s });
    };
    std.debug.print("wrote {d} goldens\n", .{goldens.len});
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var capture = false;
    var quick = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) capture = true else if (std.mem.eql(u8, a, "--quick")) quick = true else {
            std.debug.print("usage: interop-bzip2 [--capture] [--quick]\n", .{});
            return 2;
        }
    }

    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, scratch, .{});
    defer dir.close(io);
    var c: Ctx = .{ .gpa = gpa, .io = io, .dir = dir };

    if (std.Io.Dir.cwd().access(io, bzref, .{})) {} else |_| {
        std.debug.print("building the libbzip2 oracle ...\n", .{});
        const r = try c.exec(&.{ "bash", "modules/bzip2/tools/build-oracle.sh" });
        gpa.free(r.stdout);
        gpa.free(r.stderr);
        if (!Ctx.okExit(r)) return error.OracleBuildFailed;
    }

    var goldens: std.ArrayList(Golden) = .empty;
    defer {
        for (goldens.items) |g| if (g.stream) |s| gpa.free(s);
        goldens.deinit(gpa);
    }
    try encoderParity(&c, quick, &goldens);
    try decoderChecks(&c, quick);
    try mutantChecks(&c, quick);
    std.debug.print("{d} checks, {d} failures\n", .{ c.checks, c.failures });
    if (c.failures != 0) return 1;
    if (capture) try writeGoldens(&c, goldens.items);
    return 0;
}

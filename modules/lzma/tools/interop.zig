// SPDX-License-Identifier: MIT

//! Differential oracle against liblzma 5.8.1 (built from the pinned XZ Utils
//! clone by `build-oracle.sh`, driven as a black box through `c_oracle/lzref.c`),
//! against the `xz` command-line program installed on the machine, and against
//! Python's `lzma` module (liblzma as shipped).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-lzma` runs it,
//! `zig build check-interop` only compiles it. From the repository root:
//!
//!   zig build interop-lzma                 # live comparison, all shapes
//!   zig build interop-lzma -- --capture    # ... and rewrite src/testdata/
//!   zig build interop-lzma -- --quick      # fewer presets / shapes / mutants
//!   zig build interop-lzma -- --decoder    # the decoder checks only
//!
//! What it checks, per input shape (`lzma.interop_corpus`):
//!   1. decoder: our decoder returns the input from streams made by liblzma
//!      (xz with every check type, .lzma, raw LZMA1 with and without the end
//!      marker, raw LZMA2), by the `xz` program (multi-block, threaded) and by
//!      Python's `lzma` (FORMAT_XZ, FORMAT_ALONE, FORMAT_RAW);
//!   2. stream structure: concatenated streams, stream padding, trailing
//!      bytes, truncations: liblzma's verdict equals ours;
//!   3. mutated streams (bit flips, cuts, overwrites) of xz / .lzma / raw LZMA2:
//!      liblzma's verdict and output equal ours;
//!   4. encoder: our compressed bytes equal liblzma's, byte for byte, and
//!      Python and `xz -d` read our streams.
//! `--capture` freezes (4) as SHA-256 digests plus small reference streams
//! into `src/testdata/`, which `src/golden_test.zig` replays offline.
//!
//! Needs `cc` and `git` (first run, to build the oracle), `python3` and `xz`.
//! Missing references are failures, not skips.

const std = @import("std");
const lzma = @import("lzma");
const corpus = lzma.interop_corpus;

const scratch = ".zig-cache/lzma-interop";
const lzref = ".zig-cache/lzma-oracle/lzref";
const testdata = "modules/lzma/src/testdata";

/// The dictionary sizes of liblzma's presets 0..9.
const preset_dict = [10]u32{ 256 << 10, 1 << 20, 2 << 20, 4 << 20, 4 << 20, 8 << 20, 8 << 20, 16 << 20, 32 << 20, 64 << 20 };

const Ctx = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    failures: usize = 0,
    checks: usize = 0,
    quick: bool = false,
    goldens: ?*std.ArrayList(Golden) = null,

    fn fail(c: *Ctx, comptime fmt: []const u8, args: anytype) void {
        c.failures += 1;
        std.debug.print("FAIL " ++ fmt ++ "\n", args);
    }

    fn exec(c: *Ctx, argv: []const []const u8) !std.process.RunResult {
        return std.process.run(c.gpa, c.io, .{ .argv = argv, .stdout_limit = .limited(1 << 26) }) catch |e| {
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

    /// Run, require exit 0, free the captured output.
    fn run(c: *Ctx, argv: []const []const u8) !void {
        const r = try c.exec(argv);
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) {
            std.debug.print("{s} failed: {s}\n", .{ argv[0], r.stderr });
            return error.ReferenceFailed;
        }
    }

    /// liblzma's compression of `plain`. `fmt` is xz | alone | raw1 | raw2.
    fn refEnc(c: *Ctx, plain: []const u8, fmt: []const u8, spec: []const u8, check: []const u8) ![]u8 {
        try c.put("in.bin", plain);
        try c.run(&.{ lzref, "enc", fmt, spec, check, scratch ++ "/in.bin", scratch ++ "/ref.out" });
        return c.get("ref.out");
    }

    /// liblzma's verdict on a stream, and its output when it accepts.
    const Verdict = struct { ok: bool, len: usize, out: []u8 };
    fn refDec(c: *Ctx, fmt: []const u8, stream: []const u8) !Verdict {
        try c.put("v.in", stream);
        const r = try c.exec(&.{ lzref, "dec", fmt, scratch ++ "/v.in", scratch ++ "/v.out" });
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) return error.ReferenceFailed;
        var it = std.mem.tokenizeAny(u8, r.stdout, " \n");
        const status = it.next() orelse return error.ReferenceFailed;
        const out = try c.get("v.out");
        if (std.mem.eql(u8, status, "OK")) return .{ .ok = true, .len = out.len, .out = out };
        return .{ .ok = false, .len = out.len, .out = out };
    }

    fn refDecRaw1(c: *Ctx, props: [5]u8, size: i64, eopm: bool, stream: []const u8) !Verdict {
        try c.put("v.in", stream);
        const hex = std.fmt.bytesToHex(props, .lower);
        var sb: [24]u8 = undefined;
        const r = try c.exec(&.{ lzref, "raw1", &hex, try std.mem.print(&sb, "{d}", .{size}), if (eopm) "1" else "0", scratch ++ "/v.in", scratch ++ "/v.out" });
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) return error.ReferenceFailed;
        const out = try c.get("v.out");
        return .{ .ok = std.mem.startsWith(u8, r.stdout, "OK"), .len = out.len, .out = out };
    }

    /// Python: `import lzma; <expr>` over input `d`, result written out.
    fn py(c: *Ctx, plain: []const u8, code: []const u8, extra: []const []const u8) !?[]u8 {
        try c.put("py.in", plain);
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(c.gpa);
        try argv.appendSlice(c.gpa, &.{ "python3", "-I", "-c", code, scratch ++ "/py.in", scratch ++ "/py.out" });
        try argv.appendSlice(c.gpa, extra);
        const r = try c.exec(argv.items);
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) return null;
        return try c.get("py.out");
    }

    fn xzCli(c: *Ctx, plain: []const u8, args: []const []const u8) ![]u8 {
        try c.put("xz.in", plain);
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(c.gpa);
        try argv.appendSlice(c.gpa, &.{ "xz", "-c", "-k" });
        try argv.appendSlice(c.gpa, args);
        try argv.append(c.gpa, scratch ++ "/xz.in");
        const r = try c.exec(argv.items);
        defer c.gpa.free(r.stderr);
        if (!okExit(r)) {
            c.gpa.free(r.stdout);
            return error.ReferenceFailed;
        }
        return r.stdout;
    }
};

fn sha256Hex(data: []const u8) [64]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return std.fmt.bytesToHex(h, .lower);
}

fn presetsFor(len: usize, quick: bool) []const []const u8 {
    if (quick) return &.{ "1", "6" };
    if (len > 2_000_000) return &.{ "1", "6e" };
    return &.{ "0", "1", "3", "6", "9", "6e", "9e" };
}

const checks = [_][]const u8{ "crc64", "crc32", "none", "sha256" };

const dec_opts: lzma.DecodeOptions = .{ .max_dict = 256 << 20 };

fn expectSame(c: *Ctx, what: []const u8, shape: []const u8, got: anyerror![]u8, plain: []const u8) void {
    c.checks += 1;
    const g = got catch |e| {
        c.fail("{s} {s}: {s}", .{ what, shape, @errorName(e) });
        return;
    };
    defer c.gpa.free(g);
    if (!std.mem.eql(u8, g, plain)) c.fail("{s} {s}: wrong output ({d} bytes, want {d})", .{ what, shape, g.len, plain.len });
}

fn decodeFromLiblzma(c: *Ctx) !void {
    var n: usize = 0;
    for (corpus.shapes) |shape| {
        if (c.quick and shape.len > 1_500_000) continue;
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        for (presetsFor(shape.len, c.quick)) |spec| {
            const preset = spec[0] - '0';
            const xz = try c.refEnc(plain, "xz", spec, checks[n % checks.len]);
            defer c.gpa.free(xz);
            n += 1;
            expectSame(c, "xz", shape.name, lzma.decompress(c.gpa, xz, .xz, dec_opts), plain);

            const alone = try c.refEnc(plain, "alone", spec, "");
            defer c.gpa.free(alone);
            expectSame(c, "alone", shape.name, lzma.decompress(c.gpa, alone, .lzma_alone, dec_opts), plain);

            // The .lzma payload is raw LZMA1 with an end marker; the header
            // carries the properties.
            const props = try lzma.Lzma1Props.fromBytes(alone[0..5]);
            expectSame(c, "raw1", shape.name, lzma.decompress(c.gpa, alone[13..], .{ .lzma1 = .{ .props = props } }, dec_opts), plain);
            // With the size given, the end marker is still accepted ...
            expectSame(c, "raw1+size", shape.name, lzma.decompress(c.gpa, alone[13..], .{ .lzma1 = .{ .props = props, .uncompressed_size = plain.len } }, dec_opts), plain);
            // ... unless the caller says it must not be there.
            c.checks += 1;
            if (lzma.decompress(c.gpa, alone[13..], .{ .lzma1 = .{ .props = props, .uncompressed_size = plain.len, .allow_eopm = false } }, dec_opts)) |o| {
                c.gpa.free(o);
                c.fail("raw1 {s}: end marker accepted with allow_eopm = false", .{shape.name});
            } else |_| {}

            const raw2 = try c.refEnc(plain, "raw2", spec, "");
            defer c.gpa.free(raw2);
            expectSame(c, "raw2", shape.name, lzma.decompress(c.gpa, raw2, .{ .lzma2 = .{ .dict_size = preset_dict[preset] } }, dec_opts), plain);
        }
    }
}

fn decodeFromPython(c: *Ctx) !void {
    const names = [_][]const u8{ "text-small", "text-150k", "random-70k", "records-400k", "far-100k", "empty", "one", "mixed-200k", "zeros-2m" };
    const xz_code = "import lzma,sys\nd=open(sys.argv[1],'rb').read()\nopen(sys.argv[2],'wb').write(lzma.compress(d,format=lzma.FORMAT_XZ,check=int(sys.argv[3]),preset=int(sys.argv[4])))";
    const alone_code = "import lzma,sys\nd=open(sys.argv[1],'rb').read()\nopen(sys.argv[2],'wb').write(lzma.compress(d,format=lzma.FORMAT_ALONE,preset=int(sys.argv[3])))";
    const raw2_code = "import lzma,sys\nd=open(sys.argv[1],'rb').read()\nf=[{'id':lzma.FILTER_LZMA2,'preset':int(sys.argv[3])}]\nopen(sys.argv[2],'wb').write(lzma.compress(d,format=lzma.FORMAT_RAW,filters=f))";
    const raw1_code = "import lzma,sys\nd=open(sys.argv[1],'rb').read()\nf=[{'id':lzma.FILTER_LZMA1,'preset':int(sys.argv[3]),'dict_size':int(sys.argv[4]),'lc':int(sys.argv[5]),'lp':int(sys.argv[6]),'pb':int(sys.argv[7])}]\nopen(sys.argv[2],'wb').write(lzma.compress(d,format=lzma.FORMAT_RAW,filters=f))";
    const check_ids = [_][]const u8{ "0", "1", "4", "10" }; // none, crc32, crc64, sha256
    for (names) |name| {
        const shape = corpus.find(name).?;
        if (c.quick and shape.len > 500_000) continue;
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        for (check_ids, 0..) |chk, i| {
            const presets = [_][]const u8{ "0", "6", "9", "3" };
            const preset = presets[i];
            const z = (try c.py(plain, xz_code, &.{ chk, preset })) orelse return error.ReferenceFailed;
            defer c.gpa.free(z);
            expectSame(c, "python xz", name, lzma.decompress(c.gpa, z, .xz, dec_opts), plain);
        }
        {
            const z = (try c.py(plain, alone_code, &.{"5"})) orelse return error.ReferenceFailed;
            defer c.gpa.free(z);
            expectSame(c, "python alone", name, lzma.decompress(c.gpa, z, .lzma_alone, dec_opts), plain);
        }
        {
            const z = (try c.py(plain, raw2_code, &.{"4"})) orelse return error.ReferenceFailed;
            defer c.gpa.free(z);
            expectSame(c, "python raw lzma2", name, lzma.decompress(c.gpa, z, .{ .lzma2 = .{ .dict_size = preset_dict[4] } }, dec_opts), plain);
        }
        // Raw LZMA1 with unusual lc/lp/pb (what 7-Zip and ZIP writers produce).
        for ([_][3]u8{ .{ 3, 0, 2 }, .{ 0, 0, 0 }, .{ 0, 4, 4 }, .{ 4, 0, 0 }, .{ 1, 3, 1 } }) |p| {
            var b: [3][4]u8 = undefined;
            const z = (try c.py(plain, raw1_code, &.{
                "4",
                "1048576",
                try std.mem.print(&b[0], "{d}", .{p[0]}),
                try std.mem.print(&b[1], "{d}", .{p[1]}),
                try std.mem.print(&b[2], "{d}", .{p[2]}),
            })) orelse return error.ReferenceFailed;
            defer c.gpa.free(z);
            const props: lzma.Lzma1Props = .{ .lc = p[0], .lp = p[1], .pb = p[2], .dict_size = 1 << 20 };
            // liblzma's raw LZMA1 encoder writes the end marker, so the stream is
            // good with or without the size, and truncation is refused.
            expectSame(c, "python raw lzma1", name, lzma.decompress(c.gpa, z, .{ .lzma1 = .{ .props = props, .uncompressed_size = plain.len } }, dec_opts), plain);
            expectSame(c, "python raw lzma1 (no size)", name, lzma.decompress(c.gpa, z, .{ .lzma1 = .{ .props = props } }, dec_opts), plain);
            c.checks += 1;
            if (lzma.decompress(c.gpa, z[0 .. z.len - 1], .{ .lzma1 = .{ .props = props } }, dec_opts)) |o| {
                c.gpa.free(o);
                c.fail("python raw lzma1 {s}: truncated stream accepted", .{name});
            } else |_| {}
        }
    }
}

fn decodeFromXzProgram(c: *Ctx) !void {
    for ([_][]const u8{ "text-1m", "mixed-200k", "records-400k", "random-300k" }) |name| {
        const plain = try corpus.generate(c.gpa, corpus.find(name).?);
        defer c.gpa.free(plain);
        const variants = [_][]const []const u8{
            &.{"--block-size=65536"},
            &.{ "-T2", "--block-size=100000", "-3" },
            &.{ "--check=sha256", "--block-size=300000" },
            &.{ "--check=none", "-0" },
            &.{ "--check=crc32", "--lzma2=preset=4,lc=0,lp=2,pb=0" },
            &.{"--lzma2=preset=6,dict=4096,nice=16,mf=hc3,mode=fast"},
            &.{"--lzma2=dict=1MiB,lc=4,lp=0,pb=4,mf=bt2"},
        };
        for (variants, 0..) |args, i| {
            const z = c.xzCli(plain, args) catch |e| {
                c.fail("xz program refused variant {d} ({s})", .{ i, @errorName(e) });
                continue;
            };
            defer c.gpa.free(z);
            var what: [32]u8 = undefined;
            expectSame(c, try std.mem.print(&what, "xz program v{d}", .{i}), name, lzma.decompress(c.gpa, z, .xz, dec_opts), plain);
        }
    }
}

fn verdictAgrees(c: *Ctx, what: []const u8, ours: anyerror![]u8, v: Ctx.Verdict, tolerated: *usize) bool {
    c.checks += 1;
    if (ours) |out| {
        defer c.gpa.free(out);
        if (!v.ok) {
            c.fail("{s}: we accept ({d} bytes), liblzma refuses", .{ what, out.len });
            return false;
        }
        if (!std.mem.eql(u8, out, v.out)) {
            c.fail("{s}: output differs from liblzma's ({d} vs {d} bytes)", .{ what, out.len, v.len });
            return false;
        }
        return true;
    } else |e| {
        if (v.ok) {
            switch (e) {
                // Deliberate refusals liblzma does not make.
                error.UnsupportedFilter, error.UnsupportedCheck, error.DictTooLarge => {
                    tolerated.* += 1;
                    return true;
                },
                else => {
                    c.fail("{s}: we refuse ({s}), liblzma accepts {d} bytes", .{ what, @errorName(e), v.len });
                    return false;
                },
            }
        }
        return true;
    }
}

fn structureChecks(c: *Ctx) !void {
    const plain = try corpus.generate(c.gpa, corpus.find("text-small").?);
    defer c.gpa.free(plain);
    const za = try c.refEnc(plain, "xz", "6", "crc64");
    defer c.gpa.free(za);
    const zb = try c.refEnc(plain[0..1000], "xz", "1", "crc32");
    defer c.gpa.free(zb);
    const ze = try c.refEnc("", "xz", "6", "none");
    defer c.gpa.free(ze);
    const pad4 = &[_]u8{ 0, 0, 0, 0 };
    const parts = [_][]const []const u8{
        &.{ za, zb },
        &.{ za, pad4, zb },
        &.{ za, pad4, pad4, zb },
        &.{ za, &.{ 0, 0 }, zb },
        &.{ za, &.{ 0, 0, 0 }, zb },
        &.{ za, ze, za },
        &.{ za, pad4 },
        &.{ za, &.{ 0, 0, 0 } },
        &.{ za, "junk" },
        &.{ za, pad4, "junk" },
        &.{ za, za[0..5] },
        &.{ za, za[0..12] },
        &.{ za, za[0 .. za.len - 1] },
        &.{za[0 .. za.len - 1]},
        &.{za[0 .. za.len - 12]},
        &.{za[0..12]},
        &.{za[0..11]},
        &.{za},
        &.{ze},
        &.{""},
        &.{"\xfd7zXZ"},
    };
    var tol: usize = 0;
    for (parts, 0..) |ps, i| {
        const joined = try std.mem.concat(c.gpa, u8, ps);
        defer c.gpa.free(joined);
        const v = try c.refDec("xz", joined);
        defer c.gpa.free(v.out);
        var w: [48]u8 = undefined;
        _ = verdictAgrees(c, try std.mem.print(&w, "xz structure case {d}", .{i}), lzma.decompress(c.gpa, joined, .xz, dec_opts), v, &tol);
    }
    // .lzma: trailing bytes and truncation.
    const al = try c.refEnc(plain, "alone", "6", "");
    defer c.gpa.free(al);
    const aparts = [_][]const []const u8{ &.{al}, &.{ al, "x" }, &.{al[0 .. al.len - 1]}, &.{al[0..13]}, &.{al[0..12]}, &.{ al, al } };
    for (aparts, 0..) |ps, i| {
        const joined = try std.mem.concat(c.gpa, u8, ps);
        defer c.gpa.free(joined);
        const v = try c.refDec("alone", joined);
        defer c.gpa.free(v.out);
        var w: [48]u8 = undefined;
        var o = dec_opts;
        o.ignore_trailing_garbage = true; // liblzma ignores what follows a .lzma stream
        _ = verdictAgrees(c, try std.mem.print(&w, "alone structure case {d}", .{i}), lzma.decompress(c.gpa, joined, .lzma_alone, o), v, &tol);
    }
    c.checks += 1;
    {
        const joined = try std.mem.concat(c.gpa, u8, &.{ al, "x" });
        defer c.gpa.free(joined);
        if (lzma.decompress(c.gpa, joined, .lzma_alone, dec_opts)) |o| {
            c.gpa.free(o);
            c.fail("alone: trailing byte accepted by default", .{});
        } else |e| if (e != error.TrailingData) c.fail("alone: trailing byte gave {s}", .{@errorName(e)});
    }
}

const Golden = struct { shape: []const u8, spec: []const u8, fmt: []const u8, check: []const u8, len: usize, sha: [64]u8, stream: ?[]u8 };

/// One comparison: our bytes for (shape, spec, format) against liblzma's.
fn parity(c: *Ctx, shape: []const u8, plain: []const u8, fmt: []const u8, spec: []const u8, check: []const u8, keep: bool) !void {
    const want = try c.refEnc(plain, fmt, spec, check);
    defer c.gpa.free(want);
    const o = try lzma.interop_spec.parse(spec);
    const got = try lzma.compress(c.gpa, plain, lzma.interop_spec.formatOf(fmt), .{ .lzma = o, .check = lzma.interop_spec.checkOf(check) });
    defer c.gpa.free(got);
    c.checks += 1;
    if (!std.mem.eql(u8, want, got)) {
        const at = std.mem.indexOfDiff(u8, want, got) orelse @min(want.len, got.len);
        c.fail("encoder {s} {s} spec {s}: {d} bytes vs liblzma's {d}, first difference at {d}", .{ shape, fmt, spec, got.len, want.len, at });
        return;
    }
    if (keep) if (c.goldens) |g| {
        try g.append(c.gpa, .{
            .shape = shape,
            .spec = spec,
            .fmt = fmt,
            .check = check,
            .len = got.len,
            .sha = sha256Hex(got),
            .stream = if (plain.len <= 10_000 and std.mem.eql(u8, fmt, "xz") and (std.mem.eql(u8, spec, "1") or std.mem.eql(u8, spec, "6"))) try c.gpa.dupe(u8, got) else null,
        });
    };
}

fn encoderParity(c: *Ctx) !void {
    const presets_all = [_][]const u8{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "3e", "6e", "9e" };
    const presets_small = [_][]const u8{ "0", "1", "3", "4", "6", "6e" };
    const golden_presets = [_][]const u8{ "0", "1", "3" };
    const golden_small = [_][]const u8{ "6", "6e" };
    const custom = [_][]const u8{
        "6,dict=4096",            "6,dict=65536",       "5,lc=0,lp=2,pb=0",   "5,lc=4,lp=0,pb=4",
        "4,mf=bt3",               "4,mf=bt2",           "4,mf=hc3,mode=fast", "2,mf=hc4,nice=8",
        "3,mode=normal,nice=273", "6,nice=273,depth=3", "1,mf=bt4,mode=fast", "5,dict=200000,nice=32",
    };
    for (corpus.shapes) |shape| {
        if (c.quick and shape.len > 1_500_000) continue;
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        const big = shape.len > 1_500_000;
        const list: []const []const u8 = if (big) &.{ "1", "6" } else if (shape.len > 200_000) &presets_small else &presets_all;
        for (list, 0..) |spec, i| {
            const check = checks[(i + shape.len) % checks.len];
            const golden = shape.len <= 200_000 and (inList(&golden_presets, spec) or (shape.len <= 20_000 and inList(&golden_small, spec)) or (shape.len <= 5000 and std.mem.eql(u8, spec, "9")));
            try parity(c, shape.name, plain, "xz", spec, check, golden);
            if (i % 3 == 0) try parity(c, shape.name, plain, "alone", spec, "", golden and shape.len <= 20_000 and (std.mem.eql(u8, spec, "1") or std.mem.eql(u8, spec, "6")));
            if (i % 4 == 1) try parity(c, shape.name, plain, "raw2", spec, "", golden and shape.len <= 20_000 and (std.mem.eql(u8, spec, "1") or std.mem.eql(u8, spec, "6")));
            if (i % 5 == 2) try parity(c, shape.name, plain, "raw1", spec, "", golden and shape.len <= 20_000 and (std.mem.eql(u8, spec, "1") or std.mem.eql(u8, spec, "6")));
        }
        if (!big and shape.len <= 500_000) {
            for (custom) |spec| try parity(c, shape.name, plain, "xz", spec, "crc64", shape.len <= 20_000);
        }
    }
}

fn inList(list: []const []const u8, x: []const u8) bool {
    for (list) |l| if (std.mem.eql(u8, l, x)) return true;
    return false;
}

fn writeGoldens(c: *Ctx, goldens: []const Golden) !void {
    var out: std.Io.Writer.Allocating = .init(c.gpa);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll(
        \\// SPDX-License-Identifier: MIT
        \\//
        \\// GENERATED by `zig build interop-lzma -- --capture` (tools/interop.zig).
        \\// liblzma 5.8.1's output for the shapes of `shapes.zig`: SHA-256 and
        \\// length of the whole stream, and the stream itself for the small ones.
        \\
        \\pub const Golden = struct {
        \\    shape: []const u8,
        \\    /// The option string of `spec.zig`.
        \\    spec: []const u8,
        \\    /// xz | alone | raw1 | raw2
        \\    format: []const u8,
        \\    check: []const u8,
        \\    len: usize,
        \\    sha256: []const u8,
        \\    stream: ?[]const u8 = null,
        \\};
        \\
        \\pub const goldens = [_]Golden{
        \\
    );
    for (goldens) |g| {
        try w.print("    .{{ .shape = \"{s}\", .spec = \"{s}\", .format = \"{s}\", .check = \"{s}\", .len = {d}, .sha256 = \"{s}\"", .{ g.shape, g.spec, g.fmt, g.check, g.len, g.sha });
        if (g.stream != null) try w.print(", .stream = @embedFile(\"ref/{s}-{s}.xz\")", .{ g.shape, g.spec });
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    try std.Io.Dir.cwd().createDirPath(c.io, testdata ++ "/ref");
    var d = try std.Io.Dir.cwd().openDir(c.io, testdata, .{});
    defer d.close(c.io);
    try d.writeFile(c.io, .{ .sub_path = "goldens.zig", .data = out.written() });
    for (goldens) |g| if (g.stream) |s| {
        var nb: [128]u8 = undefined;
        const name = try std.mem.print(&nb, "ref/{s}-{s}.xz", .{ g.shape, g.spec });
        try d.writeFile(c.io, .{ .sub_path = name, .data = s });
    };
    std.debug.print("wrote {d} goldens\n", .{goldens.len});
}

fn mutantChecks(c: *Ctx) !void {
    const names = [_][]const u8{ "text-9999", "random-small", "runs-5", "all-bytes", "mixed-small" };
    var prng: std.Random.DefaultPrng = .init(0x1a2b);
    const rnd = prng.random();
    const per: usize = if (c.quick) 40 else 400;
    var tol: usize = 0;
    var agree_ok: usize = 0;
    var agree_err: usize = 0;
    const bases = [_]struct { fmt: []const u8, spec: []const u8, check: []const u8 }{
        .{ .fmt = "xz", .spec = "6", .check = "none" },
        .{ .fmt = "xz", .spec = "1", .check = "crc64" },
        .{ .fmt = "alone", .spec = "6", .check = "" },
    };
    for (names) |name| {
        var shape = corpus.find(name) orelse corpus.Shape{ .name = "mixed-small", .kind = .mixed, .len = 20_000, .param = 3000 };
        if (std.mem.eql(u8, name, "text-9999")) shape = .{ .name = name, .kind = .text, .len = 9999 };
        shape.len = @min(shape.len, 20_000);
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        for (bases) |b| {
            const base = try c.refEnc(plain, b.fmt, b.spec, b.check);
            defer c.gpa.free(base);
            for (0..per) |_| {
                const m = try c.gpa.dupe(u8, base);
                defer c.gpa.free(m);
                var cut: usize = m.len;
                switch (rnd.uintLessThan(u8, 6)) {
                    0 => m[rnd.uintLessThan(usize, m.len)] ^= @as(u8, 1) << rnd.int(u3),
                    1 => cut = rnd.uintLessThan(usize, m.len),
                    2 => m[rnd.uintLessThan(usize, m.len)] = rnd.int(u8),
                    3 => for (0..1 + rnd.uintLessThan(u8, 4)) |_| {
                        m[rnd.uintLessThan(usize, m.len)] ^= @as(u8, 1) << rnd.int(u3);
                    },
                    4 => {
                        // Inside the first bytes of the payload, where the
                        // headers and the first symbols live.
                        const at = rnd.uintLessThan(usize, @min(m.len, 40));
                        m[at] ^= @as(u8, 1) << rnd.int(u3);
                    },
                    else => @memset(m[rnd.uintLessThan(usize, m.len)..][0..1], 0xff),
                }
                const s = m[0..cut];
                const fmt: lzma.Format = if (std.mem.eql(u8, b.fmt, "xz")) .xz else .lzma_alone;
                const v = try c.refDec(b.fmt, s);
                defer c.gpa.free(v.out);
                const before = c.failures;
                _ = verdictAgrees(c, name, lzma.decompress(c.gpa, s, fmt, dec_opts), v, &tol);
                if (c.failures != before) {
                    try c.put("mutant.bin", s);
                    std.debug.print("  (mutant of {s} {s}, saved as {s}/mutant.bin)\n", .{ name, b.fmt, scratch });
                } else if (v.ok) agree_ok += 1 else agree_err += 1;
            }
        }
    }
    std.debug.print("mutants: {d} agreed on acceptance, {d} on refusal, {d} tolerated (we refuse a feature liblzma has)\n", .{ agree_ok, agree_err, tol });
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
    var decoder_only = false;
    var encoder_only = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) capture = true else if (std.mem.eql(u8, a, "--quick")) quick = true else if (std.mem.eql(u8, a, "--decoder")) decoder_only = true else if (std.mem.eql(u8, a, "--encoder")) encoder_only = true else {
            std.debug.print("usage: interop-lzma [--capture] [--quick] [--decoder]\n", .{});
            return 2;
        }
    }

    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, scratch, .{});
    defer dir.close(io);
    var c: Ctx = .{ .gpa = gpa, .io = io, .dir = dir, .quick = quick };

    if (std.Io.Dir.cwd().access(io, lzref, .{})) {} else |_| {
        std.debug.print("building the liblzma oracle ...\n", .{});
        try c.run(&.{ "bash", "modules/lzma/tools/build-oracle.sh" });
    }

    var goldens: std.ArrayList(Golden) = .empty;
    defer {
        for (goldens.items) |g| if (g.stream) |st| gpa.free(st);
        goldens.deinit(gpa);
    }
    if (capture) c.goldens = &goldens;
    if (!encoder_only) {
        try decodeFromLiblzma(&c);
        try decodeFromPython(&c);
        try decodeFromXzProgram(&c);
        try structureChecks(&c);
        try mutantChecks(&c);
    }
    if (!decoder_only) try encoderParity(&c);

    std.debug.print("{d} checks, {d} failures\n", .{ c.checks, c.failures });
    if (c.failures != 0) return 1;
    if (capture) try writeGoldens(&c, goldens.items);
    return 0;
}

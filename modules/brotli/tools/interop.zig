// SPDX-License-Identifier: MIT

//! Live interop against the **reference** Brotli implementation — the Python
//! `brotli` package, a C-extension binding to google/brotli itself.
//!
//! THIS IS A PROGRAM, NOT A TEST. It is built and run by
//! `zig build interop-brotli`, compiled (never run) by
//! `zig build check-interop`, and is not part of `test-brotli` or of the
//! `brotli` module. Until 2026-09-06 it was `src/reference_interop.zig`: a test
//! inside the module that `@embedFile`d a Python driver and spawned `python3`
//! from inside the test suite. Every consumer of the module then carried
//! foreign source, and the suite could not run without a toolchain it had no
//! business needing — it "skipped loudly" instead, which in CI (where the peer
//! install is `continue-on-error`) is a skip nobody reads.
//!
//! Our own decoder agreeing with our own encoder proves nothing: a shared
//! misreading of RFC 7932 stays invisible to a self round trip. Only an
//! outside decoder sees it. The split keeps that evidence and moves where it
//! is taken:
//!
//!   - `--capture` runs the reference and freezes two things into
//!     `src/testdata/`. `ref/*.br` are streams the REFERENCE COMPRESSED, which
//!     our decoder must reproduce the input from — the reference exercising
//!     encoder features this module never emits. `interop_blessed.zig` records,
//!     for every input shape, the SHA-256 of the stream OUR encoder produced
//!     and the fact that google/brotli decompressed it back to the exact input.
//!   - the default mode re-derives all of that live. It is what discovers a
//!     NEW divergence, and it is a pre-release check rather than a per-commit
//!     one.
//!
//! Why a digest rather than the streams themselves for our own output: the
//! blessing is about bytes, so the fixture has to pin bytes, and 45 shapes of
//! them run to several megabytes. A digest pins the same bytes in 32. When the
//! encoder legitimately changes, `test-brotli` goes red until someone re-runs
//! this program — which is the intended workflow, not an accident: an encoder
//! change that nothing outside this repository has ever accepted is exactly
//! what the anchor is for.
//!
//! Usage, from the repository root:
//!
//!   zig build interop-brotli                  # live check against python3
//!   zig build interop-brotli -- --capture     # …and rewrite the fixtures
//!   zig build interop-brotli -- --driver P    # non-default reference.py
//!
//! Needs `python3` with `pip install brotli`. It does not skip: an absent
//! reference is a failure here, because running this program IS the request to
//! consult the reference.

const std = @import("std");
const brotli = @import("brotli");
const corpus = brotli.interop_corpus;

const default_driver = "modules/brotli/tools/reference.py";
const default_scratch = ".zig-cache/interop-brotli";
const testdata = "modules/brotli/src/testdata";
const ref_dir = testdata ++ "/ref";
const blessed_path = testdata ++ "/interop_blessed.zig";

const Sha256 = std.crypto.hash.sha2.Sha256;

/// SHA-256, lowercase hex. A hex STRING rather than `[32]u8` because the
/// fixture is a source file the module compiles: 90 `hexToBytes` calls at
/// comptime blow past the eval branch quota, and a string comparison at run
/// time is the same evidence for none of the ceremony.
fn digestOf(bytes: []const u8) [64]u8 {
    var raw: [32]u8 = undefined;
    Sha256.hash(bytes, &raw, .{});
    return std.fmt.bytesToHex(raw, .lower);
}

/// Anything the reference is asked about goes through here.
const Ref = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    driver: []const u8,
    scratch: []const u8,
    dir: std.Io.Dir,

    const in_bin = "in.bin";
    const out_bin = "out.bin";

    fn init(gpa: std.mem.Allocator, io: std.Io, driver: []const u8, scratch: []const u8) !Ref {
        // Scratch lives under `.zig-cache/`, never `/tmp`: these buffers run to
        // megabytes, and `/tmp` is RAM.
        var dir = try std.Io.Dir.cwd().createDirPathOpen(io, scratch, .{});
        errdefer dir.close(io);
        return .{ .gpa = gpa, .io = io, .driver = driver, .scratch = scratch, .dir = dir };
    }

    fn deinit(self: *Ref) void {
        self.dir.close(self.io);
    }

    fn call(self: *Ref, argv: []const []const u8, quiet: bool) !void {
        var child = std.process.spawn(self.io, .{
            .argv = argv,
            .stdin = .close,
            .stdout = .ignore,
            .stderr = if (quiet) .ignore else .inherit,
        }) catch |e| {
            std.debug.print("could not spawn python3 ({s}) — the reference is required, not optional\n", .{@errorName(e)});
            return error.NoReference;
        };
        const term = try child.wait(self.io);
        switch (term) {
            .exited => |code| if (code != 0) return error.ReferenceRejected,
            else => return error.ReferenceCrashed,
        }
    }

    fn path(self: *Ref, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.gpa, "{s}/{s}", .{ self.scratch, name });
    }

    fn read(self: *Ref, name: []const u8) ![]u8 {
        return self.dir.readFileAlloc(self.io, name, self.gpa, .unlimited);
    }

    fn version(self: *Ref) ![]u8 {
        const out = try self.path(out_bin);
        defer self.gpa.free(out);
        try self.call(&.{ "python3", self.driver, "version", out }, false);
        return self.read(out_bin);
    }

    /// The reference decoder's verdict on `stream`. `error.ReferenceRejected`
    /// means it refused — the failure this program exists to catch.
    fn decompress(self: *Ref, stream: []const u8) ![]u8 {
        try self.dir.writeFile(self.io, .{ .sub_path = in_bin, .data = stream });
        const in = try self.path(in_bin);
        defer self.gpa.free(in);
        const out = try self.path(out_bin);
        defer self.gpa.free(out);
        try self.call(&.{ "python3", self.driver, "decompress", in, out }, true);
        return self.read(out_bin);
    }

    fn compress(self: *Ref, plain: []const u8, quality: u8, lgwin: u8) ![]u8 {
        try self.dir.writeFile(self.io, .{ .sub_path = in_bin, .data = plain });
        const in = try self.path(in_bin);
        defer self.gpa.free(in);
        const out = try self.path(out_bin);
        defer self.gpa.free(out);
        var qbuf: [8]u8 = undefined;
        var wbuf: [8]u8 = undefined;
        const q = std.fmt.bufPrint(&qbuf, "{d}", .{quality}) catch unreachable;
        const w = std.fmt.bufPrint(&wbuf, "{d}", .{lgwin}) catch unreachable;
        try self.call(&.{ "python3", self.driver, "compress", q, w, in, out }, false);
        return self.read(out_bin);
    }
};

// ── tallies ─────────────────────────────────────────────────────────────────

var checks: usize = 0;
var failures: usize = 0;
var notes: usize = 0;

fn ok() void {
    checks += 1;
}

fn bad(comptime fmt: []const u8, args: anytype) void {
    checks += 1;
    failures += 1;
    std.debug.print("MISMATCH  " ++ fmt ++ "\n", args);
}

fn note(comptime fmt: []const u8, args: anytype) void {
    notes += 1;
    std.debug.print("NOTE      " ++ fmt ++ "\n", args);
}

fn frozenFor(name: []const u8) ?corpus.blessed.Blessed {
    for (corpus.blessed.entries) |e| {
        if (std.mem.eql(u8, e.name, name)) return e;
    }
    return null;
}

// ── direction A: the reference decodes what WE emit ─────────────────────────

/// Returns our stream, blessed by the reference, or null if anything failed.
fn blessShape(ref: *Ref, shape: corpus.Shape) !?[]u8 {
    const gpa = ref.gpa;
    const input = try corpus.build(gpa, shape);
    defer gpa.free(input);

    const stream = try brotli.compress(gpa, input);
    errdefer gpa.free(stream);

    const back = ref.decompress(stream) catch |e| switch (e) {
        error.ReferenceRejected => {
            bad("{s}: google/brotli REFUSED our {d}-byte stream", .{ shape.name, stream.len });
            gpa.free(stream);
            return null;
        },
        else => return e,
    };
    defer gpa.free(back);

    if (!std.mem.eql(u8, input, back)) {
        bad("{s}: google/brotli decoded our stream to different bytes ({d} in, {d} out)", .{ shape.name, input.len, back.len });
        gpa.free(stream);
        return null;
    }
    ok();
    return stream;
}

fn checkEncoderDirection(ref: *Ref) !void {
    const gpa = ref.gpa;
    for (corpus.shapes) |shape| {
        const stream = (try blessShape(ref, shape)) orelse continue;
        defer gpa.free(stream);

        // …and is the committed record still about THESE bytes?
        const frozen = frozenFor(shape.name) orelse {
            bad("{s}: no frozen entry — run with --capture", .{shape.name});
            continue;
        };
        const d = digestOf(stream);
        if (frozen.stream_len != stream.len or !std.mem.eql(u8, frozen.stream_sha256, &d)) {
            bad("{s}: the encoder no longer emits the stream the fixture pins ({d} -> {d} bytes) — run with --capture", .{ shape.name, frozen.stream_len, stream.len });
        } else ok();
    }
}

// ── direction B: we decode what the REFERENCE emits ─────────────────────────

fn checkDecoderDirection(ref: *Ref) !void {
    const gpa = ref.gpa;
    for (corpus.ref_streams) |r| {
        const in_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ testdata, r.input });
        defer gpa.free(in_path);
        const plain = try std.Io.Dir.cwd().readFileAlloc(ref.io, in_path, gpa, .unlimited);
        defer gpa.free(plain);

        const stream = try ref.compress(plain, r.quality, r.lgwin);
        defer gpa.free(stream);

        const back = brotli.decompress(gpa, stream, .{ .max_output = 1 << 24 }) catch |e| {
            bad("{s} q{d} w{d}: we could not decode the reference's stream ({s})", .{ r.input, r.quality, r.lgwin, @errorName(e) });
            continue;
        };
        defer gpa.free(back);
        if (!std.mem.eql(u8, plain, back)) {
            bad("{s} q{d} w{d}: we decoded the reference's stream to different bytes", .{ r.input, r.quality, r.lgwin });
            continue;
        }
        ok();

        // The committed stream is a RECORDING of this build of the reference.
        // A different google/brotli version legitimately emits different bytes
        // for the same input, so a difference here is news, not a failure: the
        // check that matters is the one above, and it just passed on freshly
        // produced bytes.
        const fx_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ ref_dir, r.file });
        defer gpa.free(fx_path);
        if (std.Io.Dir.cwd().readFileAlloc(ref.io, fx_path, gpa, .unlimited)) |committed| {
            defer gpa.free(committed);
            if (!std.mem.eql(u8, committed, stream))
                note("{s}: the committed stream is not what this build of the reference emits ({d} vs {d} bytes) — --capture re-records it", .{ r.file, committed.len, stream.len });
        } else |_| {
            note("{s}: not committed yet — run with --capture", .{r.file});
        }
    }
}

// ── the capture ─────────────────────────────────────────────────────────────

fn captureRefStreams(ref: *Ref) !void {
    const gpa = ref.gpa;
    try std.Io.Dir.cwd().createDirPath(ref.io, ref_dir);
    var total: usize = 0;
    for (corpus.ref_streams) |r| {
        const in_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ testdata, r.input });
        defer gpa.free(in_path);
        const plain = try std.Io.Dir.cwd().readFileAlloc(ref.io, in_path, gpa, .unlimited);
        defer gpa.free(plain);

        const stream = try ref.compress(plain, r.quality, r.lgwin);
        defer gpa.free(stream);

        const out_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ ref_dir, r.file });
        defer gpa.free(out_path);
        try std.Io.Dir.cwd().writeFile(ref.io, .{ .sub_path = out_path, .data = stream });
        total += stream.len;
    }
    std.debug.print("wrote {d} reference streams into {s}/ ({d} bytes total)\n", .{ corpus.ref_streams.len, ref_dir, total });
}

fn captureBlessed(ref: *Ref, provenance: []const u8) !void {
    const gpa = ref.gpa;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try out.print(gpa,
        \\// SPDX-License-Identifier: MIT
        \\
        \\//! What google/brotli said about THIS encoder's output, frozen.
        \\//!
        \\//! For every shape in `interop_corpus.zig`, the reference decompressed
        \\//! the stream `brotli.compress` produced and got the input back, byte for
        \\//! byte. `stream_sha256` identifies the exact stream that happened to;
        \\//! `input_sha256` identifies the exact input, so a corpus generator that
        \\//! drifts is told apart from an encoder that drifts.
        \\//!
        \\//! This is the only hermetic form the encoder direction can take. What
        \\//! the reference judged is a stream, not a function of committed data:
        \\//! replaying it without the reference means pinning the bytes it blessed
        \\//! and checking we still emit them. So an encoder change that alters ANY
        \\//! output turns `test-brotli` red until someone re-runs the interop
        \\//! program against a real google/brotli — which is the point. The
        \\//! alternative, checking our decoder against our encoder, is precisely
        \\//! the self-round-trip this anchor exists to escape.
        \\//!
        \\//! GENERATED FILE. Regenerate:
        \\//!
        \\//!   zig build interop-brotli -- --capture
        \\//!
        \\//! Reference: {s}
        \\
        \\pub const Blessed = struct {{
        \\    name: []const u8,
        \\    input_len: usize,
        \\    /// SHA-256 of the input, lowercase hex.
        \\    input_sha256: []const u8,
        \\    stream_len: usize,
        \\    /// SHA-256 of the stream google/brotli accepted, lowercase hex.
        \\    stream_sha256: []const u8,
        \\}};
        \\
        \\pub const entries = [_]Blessed{{
        \\
    , .{provenance});

    var blessed_count: usize = 0;
    for (corpus.shapes) |shape| {
        const input = try corpus.build(gpa, shape);
        defer gpa.free(input);
        const stream = (try blessShape(ref, shape)) orelse {
            std.debug.print("REFUSING TO CAPTURE: '{s}' was not blessed by the reference\n", .{shape.name});
            return error.ReferenceRejectedOurStream;
        };
        defer gpa.free(stream);
        blessed_count += 1;

        try out.print(gpa, "    .{{ .name = \"{s}\", .input_len = {d}, .input_sha256 = \"{s}\", .stream_len = {d}, .stream_sha256 = \"{s}\" }},\n", .{
            shape.name, input.len, &digestOf(input), stream.len, &digestOf(stream),
        });
    }
    try out.appendSlice(gpa, "};\n");

    try std.Io.Dir.cwd().writeFile(ref.io, .{ .sub_path = blessed_path, .data = out.items });
    std.debug.print("wrote {s} ({d} shapes)\n", .{ blessed_path, blessed_count });
}

// ── entry point ─────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var driver: []const u8 = default_driver;
    var scratch: []const u8 = default_scratch;
    var capture = false;

    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, a, "--driver")) {
            driver = args.next() orelse return usage();
        } else if (std.mem.eql(u8, a, "--scratch")) {
            scratch = args.next() orelse return usage();
        } else {
            std.debug.print("unknown argument '{s}'\n", .{a});
            return usage();
        }
    }

    var ref = Ref.init(gpa, io, driver, scratch) catch |e| {
        std.debug.print("could not open scratch dir '{s}': {s}\n", .{ scratch, @errorName(e) });
        return 2;
    };
    defer ref.deinit();

    const provenance = ref.version() catch |e| {
        std.debug.print(
            \\could not run the reference driver '{s}': {s}
            \\
            \\This program needs python3 with `pip install brotli`, and it must be
            \\run from the repository root (`zig build interop-brotli`).
            \\
        , .{ driver, @errorName(e) });
        return 2;
    };
    defer gpa.free(provenance);
    std.debug.print("reference: {s}\n", .{provenance});

    if (capture) {
        // Capture and stop. The live check compares against the fixtures as
        // this binary was COMPILED with, which the writes above just made
        // stale — reporting on that would be reporting on nothing.
        try captureRefStreams(&ref);
        try captureBlessed(&ref, provenance);
        std.debug.print("fixtures rewritten — re-run `zig build interop-brotli` to verify them\n", .{});
        return 0;
    }

    try checkEncoderDirection(&ref);
    try checkDecoderDirection(&ref);
    std.debug.print("{d} checks, {d} mismatches, {d} notes\n", .{ checks, failures, notes });
    return if (failures == 0) 0 else 1;
}

fn usage() u8 {
    std.debug.print(
        \\usage: zig build interop-brotli -- [--capture] [--driver PATH] [--scratch DIR]
        \\
    , .{});
    return 2;
}

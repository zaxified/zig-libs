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
//! Raw prefix dictionaries (RFC 9841 / `dcb`) are beyond the Python binding:
//! for those the reference is libbrotli itself, through a small C program
//! (`tools/c_oracle/shared_oracle.c`) built with `zig cc` against the system
//! library (`--libbrotli DIR`, default /usr/lib/x86_64-linux-gnu).
//!
//! Serialized shared dictionaries (RFC 9841 §5) need more: a packaged
//! libbrotli refuses them unless built with BROTLI_EXPERIMENTAL. With
//! `--brotli-src DIR` (a google/brotli checkout, security-reviewed first:
//! this compiles its `c/`) the program builds that oracle and checks — and
//! with `--capture` records — the serialized-dictionary streams; without
//! it, a NOTE says they were not re-taken.
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
        return self.gpa.print("{s}/{s}", .{ self.scratch, name });
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
        const q = std.mem.print(&qbuf, "{d}", .{quality}) catch unreachable;
        const w = std.mem.print(&wbuf, "{d}", .{lgwin}) catch unreachable;
        try self.call(&.{ "python3", self.driver, "compress", q, w, in, out }, false);
        return self.read(out_bin);
    }
};

/// libbrotli itself (`tools/c_oracle/shared_oracle.c`, built here with
/// `zig cc` against the system library), for what the Python binding cannot
/// reach: raw prefix dictionaries and the large window.
const Shared = struct {
    ref: *Ref,
    exe: []const u8,

    const lib_dir_default = "/usr/lib/x86_64-linux-gnu";
    const src = "modules/brotli/tools/c_oracle/shared_oracle.c";

    fn build(ref: *Ref, lib_dir: []const u8) !Shared {
        const gpa = ref.gpa;
        const exe = try ref.path("shared_oracle");
        errdefer gpa.free(exe);
        var libs: [3][]u8 = undefined;
        for (&libs, [_][]const u8{ "enc", "dec", "common" }) |*l, n| l.* = try gpa.print("{s}/libbrotli{s}.so.1", .{ lib_dir, n });
        defer for (libs) |l| gpa.free(l);
        const r = try std.process.run(gpa, ref.io, .{ .argv = &.{ "zig", "cc", "-O2", src, libs[0], libs[1], libs[2], "-o", exe } });
        defer gpa.free(r.stdout);
        defer gpa.free(r.stderr);
        if (r.term != .exited or r.term.exited != 0) {
            std.debug.print("could not build {s} against {s} (LIBBROTLI_DIR):\n{s}\n", .{ src, lib_dir, r.stderr });
            return error.NoReference;
        }
        return .{ .ref = ref, .exe = exe };
    }

    /// The same oracle built from google/brotli's own sources with
    /// BROTLI_EXPERIMENTAL — what serialized shared dictionaries need (a
    /// packaged library refuses them: "DO NOT USE: methods accepting this
    /// value will fail"). `src` is a google/brotli checkout (its `c/`
    /// directory), reviewed before it is given here: this compiles it.
    fn buildExperimental(ref: *Ref, checkout: []const u8) !Shared {
        const gpa = ref.gpa;
        const exe = try ref.path("shared_oracle_experimental");
        errdefer gpa.free(exe);
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        var owned: std.ArrayList([]u8) = .empty;
        defer {
            for (owned.items) |o| gpa.free(o);
            owned.deinit(gpa);
        }
        const inc = try gpa.print("-I{s}/c/include", .{checkout});
        try owned.append(gpa, inc);
        try argv.appendSlice(gpa, &.{ "zig", "cc", "-O2", "-DBROTLI_EXPERIMENTAL", inc, Shared.src, "-lm", "-o", exe });
        for ([_][]const u8{ "common", "dec", "enc" }) |part| {
            const dir_path = try gpa.print("{s}/c/{s}", .{ checkout, part });
            defer gpa.free(dir_path);
            var dir = std.Io.Dir.cwd().openDir(ref.io, dir_path, .{ .iterate = true }) catch {
                std.debug.print("--brotli-src {s}: no {s}\n", .{ checkout, dir_path });
                return error.NoReference;
            };
            defer dir.close(ref.io);
            var it = dir.iterate();
            while (try it.next(ref.io)) |e| {
                if (e.kind != .file or !std.mem.endsWith(u8, e.name, ".c")) continue;
                const f = try gpa.print("{s}/{s}", .{ dir_path, e.name });
                try owned.append(gpa, f);
                try argv.append(gpa, f);
            }
        }
        const r = try std.process.run(gpa, ref.io, .{ .argv = argv.items });
        defer gpa.free(r.stdout);
        defer gpa.free(r.stderr);
        if (r.term != .exited or r.term.exited != 0) {
            std.debug.print("could not build google/brotli from {s} with BROTLI_EXPERIMENTAL:\n{s}\n", .{ checkout, r.stderr });
            return error.NoReference;
        }
        return .{ .ref = ref, .exe = exe };
    }

    fn deinit(sh: *Shared) void {
        sh.ref.gpa.free(sh.exe);
    }

    fn file(sh: *Shared, name: []const u8, data: ?[]const u8) ![]u8 {
        if (data) |d| try sh.ref.dir.writeFile(sh.ref.io, .{ .sub_path = name, .data = d });
        return sh.ref.path(name);
    }

    /// The library's stream for `plain` against `dict` (empty: none).
    fn compress(sh: *Shared, dict: []const u8, plain: []const u8, quality: u8, lgwin: u8, large: bool) ![]u8 {
        const gpa = sh.ref.gpa;
        const d = if (dict.len == 0) try gpa.dupe(u8, "-") else try sh.file("dict.bin", dict);
        defer gpa.free(d);
        const in = try sh.file(Ref.in_bin, plain);
        defer gpa.free(in);
        const out = try sh.file(Ref.out_bin, null);
        defer gpa.free(out);
        var qb: [4]u8 = undefined;
        var wb: [4]u8 = undefined;
        try sh.ref.call(&.{ sh.exe, "enc", std.mem.print(&qb, "{d}", .{quality}) catch unreachable, std.mem.print(&wb, "{d}", .{lgwin}) catch unreachable, if (large) "1" else "0", d, in, out }, false);
        return sh.ref.read(Ref.out_bin);
    }

    /// The library's stream for `plain` against a serialized dictionary.
    fn compressSerialized(sh: *Shared, dict: []const u8, plain: []const u8, quality: u8) ![]u8 {
        const gpa = sh.ref.gpa;
        const d = try sh.file("dict.bin", dict);
        defer gpa.free(d);
        const sd = try gpa.print("s:{s}", .{d});
        defer gpa.free(sd);
        const in = try sh.file(Ref.in_bin, plain);
        defer gpa.free(in);
        const out = try sh.file(Ref.out_bin, null);
        defer gpa.free(out);
        var qb: [4]u8 = undefined;
        try sh.ref.call(&.{ sh.exe, "enc", std.mem.print(&qb, "{d}", .{quality}) catch unreachable, "22", "0", sd, in, out }, false);
        return sh.ref.read(Ref.out_bin);
    }

    /// The library's verdict on `stream` against `dict`;
    /// `error.ReferenceRejected` when it refuses it.
    fn decompress(sh: *Shared, dict: []const u8, stream: []const u8, large: bool) ![]u8 {
        const gpa = sh.ref.gpa;
        const d = if (dict.len == 0) try gpa.dupe(u8, "-") else try sh.file("dict.bin", dict);
        defer gpa.free(d);
        const in = try sh.file(Ref.in_bin, stream);
        defer gpa.free(in);
        const out = try sh.file(Ref.out_bin, null);
        defer gpa.free(out);
        try sh.ref.call(&.{ sh.exe, "dec", if (large) "1" else "0", d, in, out }, true);
        return sh.ref.read(Ref.out_bin);
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

fn frozenFor(name: []const u8, effort: []const u8) ?corpus.blessed.Blessed {
    for (corpus.blessed.entries) |e| {
        if (std.mem.eql(u8, e.name, name) and std.mem.eql(u8, e.effort, effort)) return e;
    }
    return null;
}

// ── direction A: the reference decodes what WE emit ─────────────────────────

/// Returns our stream, blessed by the reference, or null if anything failed.
fn blessShape(ref: *Ref, shape: corpus.Shape, enc: corpus.Encoding) !?[]u8 {
    const gpa = ref.gpa;
    const effort = enc.tag;
    const input = try corpus.build(gpa, shape);
    defer gpa.free(input);

    const stream = try corpus.encode(gpa, input, enc);
    errdefer gpa.free(stream);

    const back = ref.decompress(stream) catch |e| switch (e) {
        error.ReferenceRejected => {
            bad("{s} ({s}): google/brotli REFUSED our {d}-byte stream", .{ shape.name, effort, stream.len });
            gpa.free(stream);
            return null;
        },
        else => return e,
    };
    defer gpa.free(back);

    if (!std.mem.eql(u8, input, back)) {
        bad("{s} ({s}): google/brotli decoded our stream to different bytes ({d} in, {d} out)", .{ shape.name, effort, input.len, back.len });
        gpa.free(stream);
        return null;
    }
    ok();
    return stream;
}

fn checkEncoderDirection(ref: *Ref) !void {
    const gpa = ref.gpa;
    for (corpus.encodings) |enc| for (corpus.shapes) |shape| {
        if (!enc.covers(shape.name)) continue;
        const effort = enc.tag;
        const stream = (try blessShape(ref, shape, enc)) orelse continue;
        defer gpa.free(stream);

        // …and is the committed record still about THESE bytes?
        const frozen = frozenFor(shape.name, effort) orelse {
            bad("{s} ({s}): no frozen entry — run with --capture", .{ shape.name, effort });
            continue;
        };
        const d = digestOf(stream);
        if (frozen.stream_len != stream.len or !std.mem.eql(u8, frozen.stream_sha256, &d)) {
            bad("{s} ({s}): the encoder no longer emits the stream the fixture pins ({d} -> {d} bytes) — run with --capture", .{ shape.name, effort, frozen.stream_len, stream.len });
        } else ok();
    };
}

// ── direction B: we decode what the REFERENCE emits ─────────────────────────

fn checkDecoderDirection(ref: *Ref) !void {
    const gpa = ref.gpa;
    for (corpus.ref_streams) |r| {
        const in_path = try gpa.print("{s}/{s}", .{ testdata, r.input });
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
        const fx_path = try gpa.print("{s}/{s}", .{ ref_dir, r.file });
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

// ── raw prefix dictionaries: the library's streams, our decoders ───────────

/// Every way this module decodes, against `dict`: they must all give `plain`.
fn ourDecoders(gpa: std.mem.Allocator, dict: []const u8, stream: []const u8, plain: []const u8) !?[]const u8 {
    const opts: brotli.Options = .{ .dictionary = dict, .max_output = 1 << 24 };
    const a = brotli.decompress(gpa, stream, opts) catch |e| return @errorName(e);
    defer gpa.free(a);
    if (!std.mem.eql(u8, a, plain)) return "decompress: different bytes";
    const buf = try gpa.alloc(u8, plain.len + 1);
    defer gpa.free(buf);
    const b = brotli.decompressInto(gpa, buf, stream, opts) catch |e| return @errorName(e);
    if (!std.mem.eql(u8, b, plain)) return "decompressInto: different bytes";
    var r: std.Io.Reader = .fixed(stream);
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    _ = brotli.decompressStream(gpa, &r, &w.writer, opts) catch |e| return @errorName(e);
    if (!std.mem.eql(u8, w.written(), plain)) return "decompressStream: different bytes";
    return null;
}

fn checkDictDecoderDirection(sh: *Shared) !void {
    const gpa = sh.ref.gpa;
    inline for (corpus.dict_cases) |c| {
        const dict = try c.dict.build(gpa);
        defer gpa.free(dict);
        const plain = try c.input.build(gpa);
        defer gpa.free(plain);
        inline for (corpus.dict_qualities) |q| {
            const stream = try sh.compress(dict, plain, q, c.lgwin, false);
            defer gpa.free(stream);
            if (try ourDecoders(gpa, dict, stream, plain)) |why| {
                bad("dict {s} q{d}: we did not decode the library's stream ({s})", .{ c.name, q, why });
            } else ok();
            const fx = try gpa.print("{s}/{s}", .{ ref_dir, comptime corpus.dictRefFile(c, q) });
            defer gpa.free(fx);
            if (std.Io.Dir.cwd().readFileAlloc(sh.ref.io, fx, gpa, .unlimited)) |committed| {
                defer gpa.free(committed);
                if (!std.mem.eql(u8, committed, stream))
                    note("{s}: the committed stream is not what this library emits ({d} vs {d} bytes) — --capture re-records it", .{ fx, committed.len, stream.len });
            } else |_| note("{s}: not committed yet — run with --capture", .{fx});
        }
    }
}

/// Our stream for `c` at `effort`, if libbrotli decodes it to the input.
fn blessDict(sh: *Shared, comptime c: corpus.DictCase, comptime effort: []const u8) !?[]u8 {
    const gpa = sh.ref.gpa;
    const dict = try c.dict.build(gpa);
    defer gpa.free(dict);
    const plain = try c.input.build(gpa);
    defer gpa.free(plain);
    const stream = try corpus.encodeDict(gpa, c, @field(brotli.Effort, effort));
    errdefer gpa.free(stream);
    const back = sh.decompress(dict, stream, false) catch |e| switch (e) {
        error.ReferenceRejected => {
            bad("dict {s} ({s}): libbrotli REFUSED our {d}-byte stream", .{ c.name, effort, stream.len });
            gpa.free(stream);
            return null;
        },
        else => return e,
    };
    defer gpa.free(back);
    if (!std.mem.eql(u8, back, plain)) {
        bad("dict {s} ({s}): libbrotli decoded our stream to different bytes", .{ c.name, effort });
        gpa.free(stream);
        return null;
    }
    ok();
    return stream;
}

fn checkDictEncoderDirection(sh: *Shared) !void {
    const gpa = sh.ref.gpa;
    inline for (corpus.dict_cases) |c| inline for (corpus.dict_efforts) |effort| {
        if (try blessDict(sh, c, effort)) |stream| {
            defer gpa.free(stream);
            const tag = "dict_" ++ effort;
            if (frozenFor(c.name, tag)) |frozen| {
                const d = digestOf(stream);
                if (frozen.stream_len != stream.len or !std.mem.eql(u8, frozen.stream_sha256, &d)) {
                    bad("dict {s} ({s}): the encoder no longer emits the stream the fixture pins ({d} -> {d} bytes) — run with --capture", .{ c.name, effort, frozen.stream_len, stream.len });
                } else ok();
            } else bad("dict {s} ({s}): no frozen entry — run with --capture", .{ c.name, effort });
        }
    };
}

// ── the large window: the library's streams, our decoders ──────────────────

fn checkLargeDecoderDirection(sh: *Shared) !void {
    const gpa = sh.ref.gpa;
    inline for (corpus.large_cases) |c| {
        const plain = try c.input.build(gpa);
        defer gpa.free(plain);
        inline for (corpus.large_qualities) |q| {
            const stream = try sh.compress("", plain, q, c.lgwin, true);
            defer gpa.free(stream);
            if (try ourLargeDecoders(gpa, stream, plain)) |why| {
                bad("large {s} q{d}: we did not decode the library's stream ({s})", .{ c.name, q, why });
            } else ok();
            const fx = ref_dir ++ "/" ++ comptime corpus.largeRefFile(c, q);
            if (std.Io.Dir.cwd().readFileAlloc(sh.ref.io, fx, gpa, .unlimited)) |committed| {
                defer gpa.free(committed);
                if (!std.mem.eql(u8, committed, stream))
                    note("{s}: the committed stream is not what this library emits ({d} vs {d} bytes) — --capture re-records it", .{ fx, committed.len, stream.len });
            } else |_| note("{s}: not committed yet — run with --capture", .{fx});
        }
    }
}

/// Our large-window stream for `c` at `effort`, if libbrotli decodes it.
fn blessLarge(sh: *Shared, comptime c: corpus.LargeCase, comptime effort: []const u8) !?[]u8 {
    const gpa = sh.ref.gpa;
    const plain = try c.input.build(gpa);
    defer gpa.free(plain);
    const stream = try corpus.encodeLarge(gpa, c, @field(brotli.Effort, effort));
    errdefer gpa.free(stream);
    const back = sh.decompress("", stream, true) catch |e| switch (e) {
        error.ReferenceRejected => {
            bad("large {s} ({s}): libbrotli REFUSED our {d}-byte stream", .{ c.name, effort, stream.len });
            gpa.free(stream);
            return null;
        },
        else => return e,
    };
    defer gpa.free(back);
    if (!std.mem.eql(u8, back, plain)) {
        bad("large {s} ({s}): libbrotli decoded our stream to different bytes", .{ c.name, effort });
        gpa.free(stream);
        return null;
    }
    ok();
    return stream;
}

fn checkLargeEncoderDirection(sh: *Shared) !void {
    const gpa = sh.ref.gpa;
    inline for (corpus.large_cases) |c| inline for (corpus.large_efforts) |effort| {
        if (try blessLarge(sh, c, effort)) |stream| {
            defer gpa.free(stream);
            if (frozenFor(c.name, "large_" ++ effort)) |frozen| {
                const d = digestOf(stream);
                if (frozen.stream_len != stream.len or !std.mem.eql(u8, frozen.stream_sha256, &d)) {
                    bad("large {s} ({s}): the encoder no longer emits the stream the fixture pins ({d} -> {d} bytes) — run with --capture", .{ c.name, effort, frozen.stream_len, stream.len });
                } else ok();
            } else bad("large {s} ({s}): no frozen entry — run with --capture", .{ c.name, effort });
        }
    };
}

fn ourLargeDecoders(gpa: std.mem.Allocator, stream: []const u8, plain: []const u8) !?[]const u8 {
    const opts: brotli.Options = .{ .large_window = true, .max_output = 1 << 26 };
    if (brotli.decompress(gpa, stream, .{ .max_output = 1 << 26 })) |x| {
        gpa.free(x);
        return "accepted without large_window";
    } else |_| {}
    const a = brotli.decompress(gpa, stream, opts) catch |e| return @errorName(e);
    defer gpa.free(a);
    if (!std.mem.eql(u8, a, plain)) return "decompress: different bytes";
    var r: std.Io.Reader = .fixed(stream);
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    _ = brotli.decompressStream(gpa, &r, &w.writer, opts) catch |e| return @errorName(e);
    if (!std.mem.eql(u8, w.written(), plain)) return "decompressStream: different bytes";
    return null;
}

fn captureLargeRefStreams(sh: *Shared) !void {
    const gpa = sh.ref.gpa;
    try std.Io.Dir.cwd().createDirPath(sh.ref.io, ref_dir ++ "/large");
    var total: usize = 0;
    inline for (corpus.large_cases) |c| {
        const plain = try c.input.build(gpa);
        defer gpa.free(plain);
        inline for (corpus.large_qualities) |q| {
            const stream = try sh.compress("", plain, q, c.lgwin, true);
            defer gpa.free(stream);
            try std.Io.Dir.cwd().writeFile(sh.ref.io, .{ .sub_path = ref_dir ++ "/" ++ comptime corpus.largeRefFile(c, q), .data = stream });
            total += stream.len;
        }
    }
    std.debug.print("wrote {d} large-window reference streams into {s}/large/ ({d} bytes total)\n", .{ corpus.large_cases.len * corpus.large_qualities.len, ref_dir, total });
}

// ── serialized shared dictionaries: libbrotli's streams, our decoders ───────

fn checkSerialDecoderDirection(ex: *Shared) !void {
    inline for (corpus.serial_cases) |c| try checkSerialCase(ex, c);
}

fn checkSerialCase(ex: *Shared, comptime c: corpus.SerialCase) !void {
    const gpa = ex.ref.gpa;
    const dict = try corpus.serialize(gpa, c.dict);
    defer gpa.free(dict);
    const plain = try c.input.build(gpa);
    defer gpa.free(plain);
    var sd = brotli.parseSharedDictionary(gpa, dict) catch |e| {
        bad("serial {s}: we could not parse the dictionary ({s})", .{ c.name, @errorName(e) });
        return;
    };
    defer sd.deinit();
    inline for (corpus.serial_qualities) |q| {
        const stream = try ex.compressSerialized(dict, plain, q);
        defer gpa.free(stream);
        if (try ourSerialDecoders(gpa, &sd, stream, plain)) |why| {
            bad("serial {s} q{d}: we did not decode the library's stream ({s})", .{ c.name, q, why });
        } else ok();
        const fx = ref_dir ++ "/" ++ comptime corpus.serialRefFile(c, q);
        if (std.Io.Dir.cwd().readFileAlloc(ex.ref.io, fx, gpa, .unlimited)) |committed| {
            defer gpa.free(committed);
            if (!std.mem.eql(u8, committed, stream))
                note("{s}: the committed stream is not what this library emits ({d} vs {d} bytes) — --capture re-records it", .{ fx, committed.len, stream.len });
        } else |_| note("{s}: not committed yet — run with --capture --brotli-src DIR", .{fx});
    }
}

fn ourSerialDecoders(gpa: std.mem.Allocator, sd: *const brotli.SharedDictionary, stream: []const u8, plain: []const u8) !?[]const u8 {
    const opts: brotli.Options = .{ .shared_dictionary = sd, .max_output = 1 << 24 };
    const a = brotli.decompress(gpa, stream, opts) catch |e| return @errorName(e);
    defer gpa.free(a);
    if (!std.mem.eql(u8, a, plain)) return "decompress: different bytes";
    var r: std.Io.Reader = .fixed(stream);
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    _ = brotli.decompressStream(gpa, &r, &w.writer, opts) catch |e| return @errorName(e);
    if (!std.mem.eql(u8, w.written(), plain)) return "decompressStream: different bytes";
    return null;
}

fn captureSerialRefStreams(ex: *Shared) !void {
    const gpa = ex.ref.gpa;
    try std.Io.Dir.cwd().createDirPath(ex.ref.io, ref_dir ++ "/serial");
    var total: usize = 0;
    inline for (corpus.serial_cases) |c| {
        const dict = try corpus.serialize(gpa, c.dict);
        defer gpa.free(dict);
        const plain = try c.input.build(gpa);
        defer gpa.free(plain);
        inline for (corpus.serial_qualities) |q| {
            const stream = try ex.compressSerialized(dict, plain, q);
            defer gpa.free(stream);
            try std.Io.Dir.cwd().writeFile(ex.ref.io, .{ .sub_path = ref_dir ++ "/" ++ comptime corpus.serialRefFile(c, q), .data = stream });
            total += stream.len;
        }
    }
    std.debug.print("wrote {d} serialized-dictionary reference streams into {s}/serial/ ({d} bytes total)\n", .{ corpus.serial_cases.len * corpus.serial_qualities.len, ref_dir, total });
}

fn captureDictRefStreams(sh: *Shared) !void {
    const gpa = sh.ref.gpa;
    try std.Io.Dir.cwd().createDirPath(sh.ref.io, ref_dir ++ "/dict");
    var total: usize = 0;
    var n: usize = 0;
    inline for (corpus.dict_cases) |c| {
        const dict = try c.dict.build(gpa);
        defer gpa.free(dict);
        const plain = try c.input.build(gpa);
        defer gpa.free(plain);
        inline for (corpus.dict_qualities) |q| {
            const stream = try sh.compress(dict, plain, q, c.lgwin, false);
            defer gpa.free(stream);
            const out = ref_dir ++ "/" ++ comptime corpus.dictRefFile(c, q);
            try std.Io.Dir.cwd().writeFile(sh.ref.io, .{ .sub_path = out, .data = stream });
            total += stream.len;
            n += 1;
        }
    }
    std.debug.print("wrote {d} dictionary reference streams into {s}/dict/ ({d} bytes total)\n", .{ n, ref_dir, total });
}

// ── the capture ─────────────────────────────────────────────────────────────

fn captureRefStreams(ref: *Ref) !void {
    const gpa = ref.gpa;
    try std.Io.Dir.cwd().createDirPath(ref.io, ref_dir);
    var total: usize = 0;
    for (corpus.ref_streams) |r| {
        const in_path = try gpa.print("{s}/{s}", .{ testdata, r.input });
        defer gpa.free(in_path);
        const plain = try std.Io.Dir.cwd().readFileAlloc(ref.io, in_path, gpa, .unlimited);
        defer gpa.free(plain);

        const stream = try ref.compress(plain, r.quality, r.lgwin);
        defer gpa.free(stream);

        const out_path = try gpa.print("{s}/{s}", .{ ref_dir, r.file });
        defer gpa.free(out_path);
        try std.Io.Dir.cwd().writeFile(ref.io, .{ .sub_path = out_path, .data = stream });
        total += stream.len;
    }
    std.debug.print("wrote {d} reference streams into {s}/ ({d} bytes total)\n", .{ corpus.ref_streams.len, ref_dir, total });
}

fn captureBlessed(ref: *Ref, sh: *Shared, provenance: []const u8) !void {
    const gpa = ref.gpa;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try out.print(gpa,
        \\// SPDX-License-Identifier: MIT
        \\
        \\//! What google/brotli said about THIS encoder's output, frozen.
        \\//!
        \\//! For every shape in `interop_corpus.zig` and every encoding there (the
        \\//! efforts, and the variants on the shapes they name), the reference
        \\//! decompressed the stream `interop_corpus.encode` produced and got
        \\//! the input back, byte for byte. `stream_sha256` identifies the exact stream that happened to;
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
        \\    /// `interop_corpus.Encoding.tag`: an effort's name, or a variant's.
        \\    effort: []const u8,
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
    for (corpus.encodings) |enc| for (corpus.shapes) |shape| {
        if (!enc.covers(shape.name)) continue;
        const effort = enc.tag;
        const input = try corpus.build(gpa, shape);
        defer gpa.free(input);
        const stream = (try blessShape(ref, shape, enc)) orelse {
            std.debug.print("REFUSING TO CAPTURE: '{s}' ({s}) was not blessed by the reference\n", .{ shape.name, effort });
            return error.ReferenceRejectedOurStream;
        };
        defer gpa.free(stream);
        blessed_count += 1;

        try out.print(gpa, "    .{{ .name = \"{s}\", .effort = \"{s}\", .input_len = {d}, .input_sha256 = \"{s}\", .stream_len = {d}, .stream_sha256 = \"{s}\" }},\n", .{
            shape.name, effort, input.len, &digestOf(input), stream.len, &digestOf(stream),
        });
    };
    // Raw-dictionary streams: libbrotli is the judge (`Shared`); the input
    // digest is of the input alone.
    inline for (corpus.dict_cases) |c| inline for (corpus.dict_efforts) |effort| {
        const input = try c.input.build(gpa);
        defer gpa.free(input);
        const stream = (try blessDict(sh, c, effort)) orelse {
            std.debug.print("REFUSING TO CAPTURE: dict '{s}' ({s}) was not blessed by libbrotli\n", .{ c.name, effort });
            return error.ReferenceRejectedOurStream;
        };
        defer gpa.free(stream);
        blessed_count += 1;
        try out.print(gpa, "    .{{ .name = \"{s}\", .effort = \"dict_{s}\", .input_len = {d}, .input_sha256 = \"{s}\", .stream_len = {d}, .stream_sha256 = \"{s}\" }},\n", .{
            c.name, effort, input.len, &digestOf(input), stream.len, &digestOf(stream),
        });
    };
    inline for (corpus.large_cases) |c| inline for (corpus.large_efforts) |effort| {
        const input = try c.input.build(gpa);
        defer gpa.free(input);
        const stream = (try blessLarge(sh, c, effort)) orelse {
            std.debug.print("REFUSING TO CAPTURE: large '{s}' ({s}) was not blessed by libbrotli\n", .{ c.name, effort });
            return error.ReferenceRejectedOurStream;
        };
        defer gpa.free(stream);
        blessed_count += 1;
        try out.print(gpa, "    .{{ .name = \"{s}\", .effort = \"large_{s}\", .input_len = {d}, .input_sha256 = \"{s}\", .stream_len = {d}, .stream_sha256 = \"{s}\" }},\n", .{
            c.name, effort, input.len, &digestOf(input), stream.len, &digestOf(stream),
        });
    };
    try out.appendSlice(gpa, "};\n");

    try std.Io.Dir.cwd().writeFile(ref.io, .{ .sub_path = blessed_path, .data = out.items });
    std.debug.print("wrote {s} ({d} shape x encoding streams)\n", .{ blessed_path, blessed_count });
}

// ── entry point ─────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // The environment, so spawned programs are found on the caller's PATH
    // (`zig` for the libbrotli oracle).
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var driver: []const u8 = default_driver;
    var lib_dir: []const u8 = Shared.lib_dir_default;
    var brotli_src: ?[]const u8 = null;
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
        } else if (std.mem.eql(u8, a, "--libbrotli")) {
            lib_dir = args.next() orelse return usage();
        } else if (std.mem.eql(u8, a, "--brotli-src")) {
            brotli_src = args.next() orelse return usage();
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

    var shared = Shared.build(&ref, lib_dir) catch |e| {
        std.debug.print("could not build the libbrotli oracle: {s}\n", .{@errorName(e)});
        return 2;
    };
    defer shared.deinit();
    var experimental: ?Shared = if (brotli_src) |src| Shared.buildExperimental(&ref, src) catch |e| {
        std.debug.print("could not build the experimental oracle: {s}\n", .{@errorName(e)});
        return 2;
    } else null;
    defer if (experimental) |*x| x.deinit();

    if (capture) {
        // Capture and stop. The live check compares against the fixtures as
        // this binary was COMPILED with, which the writes above just made
        // stale — reporting on that would be reporting on nothing.
        try captureRefStreams(&ref);
        try captureDictRefStreams(&shared);
        try captureLargeRefStreams(&shared);
        if (experimental) |*x| try captureSerialRefStreams(x) else std.debug.print("serialized-dictionary streams kept as committed (no --brotli-src)\n", .{});
        try captureBlessed(&ref, &shared, provenance);
        std.debug.print("fixtures rewritten — re-run `zig build interop-brotli` to verify them\n", .{});
        return 0;
    }

    try checkEncoderDirection(&ref);
    try checkDecoderDirection(&ref);
    try checkDictDecoderDirection(&shared);
    try checkDictEncoderDirection(&shared);
    try checkLargeDecoderDirection(&shared);
    try checkLargeEncoderDirection(&shared);
    if (experimental) |*x| {
        try checkSerialDecoderDirection(x);
    } else note("serialized shared dictionaries not re-taken: they need google/brotli built with BROTLI_EXPERIMENTAL (--brotli-src DIR); the replay test still checks the committed streams", .{});
    std.debug.print("{d} checks, {d} mismatches, {d} notes\n", .{ checks, failures, notes });
    return if (failures == 0) 0 else 1;
}

fn usage() u8 {
    std.debug.print(
        \\usage: zig build interop-brotli -- [--capture] [--driver PATH] [--scratch DIR] [--libbrotli DIR] [--brotli-src DIR]
        \\
    , .{});
    return 2;
}

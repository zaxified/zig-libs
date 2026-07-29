// SPDX-License-Identifier: MIT

//! Live interop against the **reference** Brotli implementation.
//!
//! Everything this module's *encoder* emits is checked here by a third party —
//! the Python `brotli` package, which is a CFFI/C-extension binding to the
//! actual google/brotli C library (`python3 -c "import brotli"`). That is the
//! whole point of this file: our own decoder agreeing with our own encoder
//! proves nothing on its own, because a shared misreading of RFC 7932 stays
//! invisible to a self round-trip. Only an outside decoder can see it.
//!
//! Both directions are exercised:
//!   - reference **decompresses** what `brotli.compress` produced;
//!   - our decoder decompresses what the reference **compressed** (at several
//!     quality levels, so the reference exercises encoder features we do not
//!     emit ourselves).
//!
//! Data is exchanged through files in a `std.testing.tmpDir` (the child's cwd),
//! not pipes: no plumbing, no deadlock window, and the failing bytes stay on
//! disk under `.zig-cache/tmp/` if a case ever fails mid-run.
//!
//! Every test **skips loudly** when python3 or the `brotli` package is missing
//! — never silently, and never as a failure. Set `ZIG_LIBS_VERBOSE_SKIP` to see
//! the reason (`zig build test` must be silent on success, so the reason is
//! opt-in; the skip still shows in the summary either way).

const std = @import("std");
const testing = std.testing;
const brotli = @import("root.zig");

fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

fn skip(comptime reason: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("SKIPPED: " ++ reason ++ "\n", .{});
    return error.SkipZigTest;
}

/// `python3 -c "import brotli"` must succeed, otherwise every test here skips.
fn requirePython(io: std.Io) error{SkipZigTest}!void {
    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", "import brotli" },
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return skip("python3 not found — reference-interop tests need it");
    const term = child.wait(io) catch return skip("python3 could not be waited on");
    switch (term) {
        .exited => |code| if (code != 0)
            return skip("python3 has no `brotli` module (pip install brotli)"),
        else => return skip("python3 terminated abnormally"),
    }
}

/// A scratch directory plus the reference driver, used as the child's cwd.
const Ref = struct {
    tmp: testing.TmpDir,
    io: std.Io,
    gpa: std.mem.Allocator,

    /// `argv[1]` selects the operation, `argv[2]` the quality for compression.
    /// Reads `in.bin`, writes `out.bin`. Any exception exits non-zero.
    const driver =
        \\import sys, brotli
        \\data = open("in.bin", "rb").read()
        \\if sys.argv[1] == "d":
        \\    out = brotli.decompress(data)
        \\else:
        \\    out = brotli.compress(data, quality=int(sys.argv[2]))
        \\open("out.bin", "wb").write(out)
    ;

    fn init(gpa: std.mem.Allocator, io: std.Io) error{SkipZigTest}!Ref {
        try requirePython(io);
        return .{ .tmp = testing.tmpDir(.{}), .io = io, .gpa = gpa };
    }

    fn deinit(self: *Ref) void {
        self.tmp.cleanup();
    }

    fn run(self: *Ref, op: []const u8, quality: []const u8, data: []const u8) ![]u8 {
        try self.tmp.dir.writeFile(self.io, .{ .sub_path = "in.bin", .data = data });
        self.tmp.dir.deleteFile(self.io, "out.bin") catch {};

        var child = try std.process.spawn(self.io, .{
            .argv = &.{ "python3", "-c", driver, op, quality },
            .cwd = .{ .dir = self.tmp.dir },
            .stdin = .close,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        const term = try child.wait(self.io);
        switch (term) {
            .exited => |code| if (code != 0) return error.ReferenceRejected,
            else => return error.ReferenceCrashed,
        }
        return self.tmp.dir.readFileAlloc(self.io, "out.bin", self.gpa, .unlimited);
    }

    /// The reference decoder's verdict on `stream`. `error.ReferenceRejected`
    /// means the reference refused the stream — the failure this file exists
    /// to catch.
    fn decompress(self: *Ref, stream: []const u8) ![]u8 {
        return self.run("d", "0", stream);
    }

    fn compress(self: *Ref, plain: []const u8, quality: u8) ![]u8 {
        var qbuf: [4]u8 = undefined;
        return self.run("c", std.fmt.bufPrint(&qbuf, "{d}", .{quality}) catch unreachable, plain);
    }

    /// The core assertion: our encoder's output, decoded by the reference,
    /// must be the original bytes.
    fn expectOurStreamDecodes(self: *Ref, plain: []const u8) !void {
        const stream = try brotli.compress(self.gpa, plain);
        defer self.gpa.free(stream);
        const back = try self.decompress(stream);
        defer self.gpa.free(back);
        try testing.expectEqualSlices(u8, plain, back);
    }
};

// ── the two-way anchor check ────────────────────────────────────────────────

test "reference: accepts our encoder output (round trip through google/brotli)" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();

    try ref.expectOurStreamDecodes("");
    try ref.expectOurStreamDecodes("x");
    try ref.expectOurStreamDecodes("hello world hello world hello world");
    try ref.expectOurStreamDecodes(@embedFile("testdata/alice29.txt"));
}

test "reference: our decoder accepts reference output at every quality" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();

    const plain = @embedFile("testdata/alice29.txt");
    for ([_]u8{ 0, 1, 5, 9, 11 }) |q| {
        const stream = try ref.compress(plain, q);
        defer testing.allocator.free(stream);
        const back = try brotli.decompress(testing.allocator, stream, .{});
        defer testing.allocator.free(back);
        try testing.expectEqualSlices(u8, plain, back);
    }
}

// ── property sweep: every input shape, judged by the reference ──────────────

/// Deterministic xorshift so a failure is reproducible from the seed alone.
const Rng = struct {
    s: u64,
    fn next(self: *Rng) u64 {
        self.s ^= self.s << 13;
        self.s ^= self.s >> 7;
        self.s ^= self.s << 17;
        return self.s;
    }
    fn byte(self: *Rng) u8 {
        return @truncate(self.next() >> 24);
    }
};

fn fill(gpa: std.mem.Allocator, n: usize, f: anytype) ![]u8 {
    const buf = try gpa.alloc(u8, n);
    for (buf, 0..) |*b, i| b.* = f(i);
    return buf;
}

test "reference: property sweep over input shapes" {
    const gpa = testing.allocator;
    var ref = try Ref.init(gpa, testing.io);
    defer ref.deinit();

    // Degenerate and tiny.
    for ([_][]const u8{ "", "x", "xy", "xyz", "aaaa", "\x00", "\xff\xff\xff\xff\xff" }) |c|
        try ref.expectOurStreamDecodes(c);

    // Runs of one byte around the copy/insert length code boundaries.
    for ([_]usize{ 1, 2, 3, 4, 5, 6, 9, 10, 63, 64, 65, 1000, 22593, 22594, 22595 }) |n| {
        const buf = try fill(gpa, n, struct {
            fn f(_: usize) u8 {
                return 'q';
            }
        }.f);
        defer gpa.free(buf);
        try ref.expectOurStreamDecodes(buf);
    }

    // Every byte value, once and many times over: forces a dense literal code.
    {
        const buf = try fill(gpa, 256, struct {
            fn f(i: usize) u8 {
                return @intCast(i);
            }
        }.f);
        defer gpa.free(buf);
        try ref.expectOurStreamDecodes(buf);
    }
    {
        const buf = try fill(gpa, 256 * 40, struct {
            fn f(i: usize) u8 {
                return @intCast((i * 7 + i / 256) & 0xff);
            }
        }.f);
        defer gpa.free(buf);
        try ref.expectOurStreamDecodes(buf);
    }

    // Small alphabets: 1..5 distinct literals exercise every simple-code shape
    // and the first complex one, both with flat and with skewed frequencies.
    var rng = Rng{ .s = 0x9e3779b97f4a7c15 };
    for ([_]usize{ 1, 2, 3, 4, 5 }) |alpha| {
        for ([_]bool{ false, true }) |skewed| {
            const buf = try gpa.alloc(u8, 30000);
            defer gpa.free(buf);
            for (buf) |*b| {
                const r = rng.next();
                const pick: usize = if (skewed and (r >> 40) % 10 != 0) 0 else @as(usize, @truncate(r >> 3)) % alpha;
                b.* = @intCast(pick * 37 + 1);
            }
            try ref.expectOurStreamDecodes(buf);
        }
    }

    // Incompressible: the store-mode fallback must produce a stream the
    // reference still accepts.
    for ([_]usize{ 16, 1000, 70000 }) |n| {
        const buf = try gpa.alloc(u8, n);
        defer gpa.free(buf);
        for (buf) |*b| b.* = rng.byte();
        try ref.expectOurStreamDecodes(buf);
    }

    // Text, and text repeated past the window-bits switch at 65520 bytes.
    const alice = @embedFile("testdata/alice29.txt");
    try ref.expectOurStreamDecodes(alice[0..65519]);
    try ref.expectOurStreamDecodes(alice[0..65521]);
    try ref.expectOurStreamDecodes(alice);
}

test "reference: multi-meta-block streams, compressed and stored mixed" {
    const gpa = testing.allocator;
    var ref = try Ref.init(gpa, testing.io);
    defer ref.deinit();

    const block = 1 << 20; // must match the encoder's meta-block size
    const alice = @embedFile("testdata/alice29.txt");
    var rng = Rng{ .s = 0x243f_6a88_85a3_08d3 };

    // A stored block followed by a compressed final block, and the reverse:
    // both orders have to terminate the stream correctly.
    for ([_]bool{ false, true }) |random_first| {
        const buf = try gpa.alloc(u8, block + 40000);
        defer gpa.free(buf);
        const split = block;
        for (buf, 0..) |*b, i| {
            const random_here = (i < split) == random_first;
            b.* = if (random_here) rng.byte() else alice[i % alice.len];
        }
        try ref.expectOurStreamDecodes(buf);
    }

    // Exactly on the block boundary, and one byte past it.
    for ([_]usize{ block, block + 1 }) |n| {
        const buf = try gpa.alloc(u8, n);
        defer gpa.free(buf);
        for (buf, 0..) |*b, i| b.* = alice[i % alice.len];
        try ref.expectOurStreamDecodes(buf);
    }
}

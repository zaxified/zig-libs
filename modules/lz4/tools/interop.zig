// SPDX-License-Identifier: MIT

//! Differential oracle against the reference LZ4: the `lz4` CLI (v1.10.0)
//! and liblz4 through python-lz4 (4.4.5, which links the system liblz4) and
//! `ctypes` (`LZ4_decompress_safe`).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-lz4` runs it,
//! `zig build check-interop` only compiles it. From the repository root:
//!
//!   zig build interop-lz4               # everything
//!   zig build interop-lz4 -- --quick    # fewer flags and mutants
//!
//! What it checks, per input shape (`lz4.interop_corpus`):
//!   1. our frames (several option sets) decode with `lz4 -d` and with
//!      python-lz4's `lz4.frame.decompress` to the input;
//!   2. frames the CLI writes (default, HC levels, --fast, linked blocks,
//!      every block size, block checksums, content size, legacy `-l`) and
//!      frames python-lz4 writes decode with ours to the input;
//!   3. our blocks decode with liblz4's `LZ4_decompress_safe`, and blocks
//!      python-lz4 writes (fast and HC) decode with ours;
//!   4. mutated blocks and frames: whatever liblz4 accepts we accept with the
//!      same bytes, except a block with a 0 offset (the format calls it
//!      corrupted, liblz4 fills zeros); whatever we accept and liblz4 refuses
//!      breaks one of the format's optional end-of-block rules (last 5 bytes
//!      literals, last match 12 bytes before the end), which liblz4 enforces
//!      and this module does not (SPEC.md "Behaviour choices").
//!
//! Needs `lz4` and `python3` with the `lz4` package. Missing references are
//! failures, not skips.

const std = @import("std");
const lz4 = @import("lz4");
const corpus = lz4.interop_corpus;

const scratch = ".zig-cache/lz4-interop";

/// Batch verdicts from liblz4: records `u32 kind, u32 cap, u32 len, bytes`
/// (kind 0 = raw block, `LZ4_decompress_safe` with capacity `cap`; kind 1 =
/// frame, `lz4.frame.decompress`), one line per record: `OK <len> <sha256>`
/// or `ERR`.
const py_verdicts =
    \\import sys, struct, hashlib, ctypes, ctypes.util, lz4.frame
    \\L = ctypes.CDLL(ctypes.util.find_library('lz4'))
    \\d = open(sys.argv[1], 'rb').read(); i = 0; out = []
    \\while i < len(d):
    \\    kind, cap, n = struct.unpack_from('<III', d, i); i += 12
    \\    rec = d[i:i+n]; i += n
    \\    if kind == 0:
    \\        dst = ctypes.create_string_buffer(max(cap, 1))
    \\        r = L.LZ4_decompress_safe(rec, dst, n, cap)
    \\        res = dst.raw[:r] if r >= 0 else None
    \\    else:
    \\        try: res = lz4.frame.decompress(rec)
    \\        except Exception: res = None
    \\    out.append('ERR' if res is None else 'OK %d %s' % (len(res), hashlib.sha256(res).hexdigest()))
    \\open(sys.argv[2], 'w').write('\n'.join(out) + '\n')
;

const py_compress =
    \\import sys, lz4.frame, lz4.block
    \\d = open(sys.argv[1], 'rb').read(); o = sys.argv[2]
    \\open(o + '.f0', 'wb').write(lz4.frame.compress(d))
    \\open(o + '.f1', 'wb').write(lz4.frame.compress(d, block_size=lz4.frame.BLOCKSIZE_MAX256KB, block_linked=False, content_checksum=True, block_checksum=True))
    \\open(o + '.f2', 'wb').write(lz4.frame.compress(d, compression_level=9, block_size=lz4.frame.BLOCKSIZE_MAX1MB, store_size=False))
    \\open(o + '.f3', 'wb').write(lz4.frame.compress(d, compression_level=-20, block_linked=True))
    \\open(o + '.b0', 'wb').write(lz4.block.compress(d, store_size=False))
    \\open(o + '.b1', 'wb').write(lz4.block.compress(d, mode='high_compression', compression=12, store_size=False))
    \\open(o + '.b2', 'wb').write(lz4.block.compress(d, mode='fast', acceleration=30, store_size=False))
;

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

    fn run(c: *Ctx, argv: []const []const u8) !bool {
        const r = try c.exec(argv);
        defer c.gpa.free(r.stdout);
        defer c.gpa.free(r.stderr);
        return switch (r.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    fn put(c: *Ctx, name: []const u8, data: []const u8) !void {
        try c.dir.writeFile(c.io, .{ .sub_path = name, .data = data });
    }

    fn get(c: *Ctx, name: []const u8) ![]u8 {
        return c.dir.readFileAlloc(c.io, name, c.gpa, .unlimited);
    }
};

fn sha256Hex(data: []const u8) [64]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return std.fmt.bytesToHex(h, .lower);
}

const our_frame_opts = [_]struct { name: []const u8, o: lz4.EncodeOptions }{
    .{ .name = "default", .o = .{} },
    .{ .name = "indep-4M-all-checks", .o = .{ .block_size = .max4MB, .independent_blocks = true, .block_checksum = true, .content_checksum = true, .content_size = true } },
    .{ .name = "linked-256K-bsum", .o = .{ .block_size = .max256KB, .block_checksum = true } },
    .{ .name = "linked-1M-accel8", .o = .{ .block_size = .max1MB, .acceleration = 8, .content_checksum = true } },
};

const cli_flags = [_][]const []const u8{
    &.{},
    &.{"-9"},
    &.{ "-12", "-BD" },
    &.{"--fast=3"},
    &.{ "-BD", "-B4", "-BX", "--content-size" },
    &.{ "-B5", "--no-frame-crc" },
    &.{ "-B6", "-BX" },
    &.{ "-B7", "-BD", "-3" },
    &.{"-l"},
};

/// Our frames, liblz4's frames, our blocks, liblz4's blocks: every shape.
fn shapeChecks(c: *Ctx, quick: bool) !void {
    var batch: std.ArrayList(u8) = .empty;
    defer batch.deinit(c.gpa);
    var want: std.ArrayList([64]u8) = .empty;
    defer want.deinit(c.gpa);
    var lens: std.ArrayList(usize) = .empty;
    defer lens.deinit(c.gpa);

    for (corpus.shapes) |shape| {
        const plain = try corpus.generate(c.gpa, shape);
        defer c.gpa.free(plain);
        const big = plain.len > 1_500_000;
        try c.put("in.bin", plain);

        // 1. Our frames through the CLI, and into the python batch.
        for (our_frame_opts) |fo| {
            const z = try lz4.compress(c.gpa, plain, fo.o);
            defer c.gpa.free(z);
            try c.put("ours.lz4", z);
            c.checks += 1;
            if (!try c.run(&.{ "lz4", "-q", "-d", "-f", scratch ++ "/ours.lz4", scratch ++ "/ours.out" })) {
                c.fail("{s}/{s}: lz4 -d refused our frame", .{ shape.name, fo.name });
            } else {
                const back = try c.get("ours.out");
                defer c.gpa.free(back);
                if (!std.mem.eql(u8, back, plain)) c.fail("{s}/{s}: lz4 -d decoded other bytes", .{ shape.name, fo.name });
            }
            try appendRecord(c, &batch, 1, 0, z);
            try want.append(c.gpa, sha256Hex(plain));
            try lens.append(c.gpa, plain.len);
        }

        // 2. CLI frames into ours.
        for (cli_flags, 0..) |flags, fi| {
            if ((quick or big) and fi % 3 != 0) continue;
            var argv: std.ArrayList([]const u8) = .empty;
            defer argv.deinit(c.gpa);
            try argv.appendSlice(c.gpa, &.{ "lz4", "-q", "-f" });
            try argv.appendSlice(c.gpa, flags);
            try argv.appendSlice(c.gpa, &.{ scratch ++ "/in.bin", scratch ++ "/cli.lz4" });
            if (!try c.run(argv.items)) return error.ReferenceFailed;
            const z = try c.get("cli.lz4");
            defer c.gpa.free(z);
            c.checks += 1;
            const back = lz4.decompress(c.gpa, z, .{ .max_output = null }) catch |e| {
                c.fail("{s}: our decoder refused `lz4 {s}`: {t}", .{ shape.name, if (flags.len > 0) flags[0] else "", e });
                continue;
            };
            defer c.gpa.free(back);
            if (!std.mem.eql(u8, back, plain)) c.fail("{s}: `lz4 {s}` decoded to other bytes", .{ shape.name, if (flags.len > 0) flags[0] else "" });
        }

        // 2b/3b. python-lz4's frames and blocks into ours.
        if (!try c.run(&.{ "python3", "-I", "-c", py_compress, scratch ++ "/in.bin", scratch ++ "/py" })) return error.ReferenceFailed;
        for ([_][]const u8{ "py.f0", "py.f1", "py.f2", "py.f3" }) |name| {
            const z = try c.get(name);
            defer c.gpa.free(z);
            c.checks += 1;
            const back = lz4.decompress(c.gpa, z, .{ .max_output = null }) catch |e| {
                c.fail("{s}: our decoder refused python-lz4's {s}: {t}", .{ shape.name, name, e });
                continue;
            };
            defer c.gpa.free(back);
            if (!std.mem.eql(u8, back, plain)) c.fail("{s}: python-lz4's {s} decoded to other bytes", .{ shape.name, name });
        }
        const out = try c.gpa.alloc(u8, plain.len);
        defer c.gpa.free(out);
        for ([_][]const u8{ "py.b0", "py.b1", "py.b2" }) |name| {
            const z = try c.get(name);
            defer c.gpa.free(z);
            c.checks += 1;
            const n = lz4.decompressBlock(z, out) catch |e| {
                c.fail("{s}: our block decoder refused python-lz4's {s}: {t}", .{ shape.name, name, e });
                continue;
            };
            if (!std.mem.eql(u8, out[0..n], plain)) c.fail("{s}: python-lz4's {s} decoded to other bytes", .{ shape.name, name });
        }

        // 3. Our blocks into the batch (LZ4_decompress_safe, exact capacity).
        if (plain.len <= lz4.max_block_input) {
            for ([_]u32{ 1, 4, 100 }) |accel| {
                const z = try c.gpa.alloc(u8, lz4.compressBlockBound(plain.len));
                defer c.gpa.free(z);
                const n = try lz4.compressBlock(plain, z, .{ .acceleration = accel });
                try appendRecord(c, &batch, 0, plain.len, z[0..n]);
                try want.append(c.gpa, sha256Hex(plain));
                try lens.append(c.gpa, plain.len);
            }
        }
    }

    // liblz4's verdicts on everything we wrote.
    const verdicts = try pyVerdicts(c, batch.items);
    defer c.gpa.free(verdicts);
    var lines = std.mem.splitScalar(u8, verdicts, '\n');
    for (want.items, lens.items, 0..) |w, n, i| {
        const line = lines.next() orelse return error.ReferenceFailed;
        c.checks += 1;
        var buf: [96]u8 = undefined;
        const expect = try std.fmt.bufPrint(&buf, "OK {d} {s}", .{ n, &w });
        if (!std.mem.eql(u8, line, expect)) c.fail("record {d}: liblz4 says `{s}` of our output", .{ i, line });
    }
}

fn appendRecord(c: *Ctx, batch: *std.ArrayList(u8), kind: u32, cap: usize, data: []const u8) !void {
    var h: [12]u8 = undefined;
    std.mem.writeInt(u32, h[0..4], kind, .little);
    std.mem.writeInt(u32, h[4..8], @intCast(cap), .little);
    std.mem.writeInt(u32, h[8..12], @intCast(data.len), .little);
    try batch.appendSlice(c.gpa, &h);
    try batch.appendSlice(c.gpa, data);
}

fn pyVerdicts(c: *Ctx, batch: []const u8) ![]u8 {
    try c.put("batch.bin", batch);
    if (!try c.run(&.{ "python3", "-I", "-c", py_verdicts, scratch ++ "/batch.bin", scratch ++ "/verdicts.txt" })) return error.ReferenceFailed;
    return c.get("verdicts.txt");
}

/// What a block breaks of the format's optional end-of-block rules (or the
/// offset-0 rule). Parses a block our decoder accepted.
const BlockFacts = struct { zero_offset: bool = false, end_rules: bool = false };

fn blockFacts(blk: []const u8, cap: usize, history: usize) BlockFacts {
    var f: BlockFacts = .{};
    var ip: usize = 0;
    var op: usize = history;
    var last_match_start: ?usize = null;
    var last_lits: usize = 0;
    var first_lit_input_rule = false;
    while (ip < blk.len) {
        const t = blk[ip];
        ip += 1;
        var lit: usize = t >> 4;
        if (lit == 15) while (true) {
            const b = blk[ip];
            ip += 1;
            lit += b;
            if (b != 255) break;
        };
        ip += lit;
        op += lit;
        last_lits = lit;
        if (ip == blk.len) break;
        // liblz4's safe loop: a literal run that is not the last one must
        // leave 8 bytes of input and end 12 bytes before the capacity.
        if (ip + 8 > blk.len or op + 12 > history + cap) first_lit_input_rule = true;
        const off = @as(usize, blk[ip]) | @as(usize, blk[ip + 1]) << 8;
        ip += 2;
        if (off == 0) f.zero_offset = true;
        var ml: usize = t & 15;
        if (ml == 15) while (true) {
            const b = blk[ip];
            ip += 1;
            ml += b;
            if (b != 255) break;
        };
        last_match_start = op;
        op += ml + 4;
        if (op + 5 > history + cap) first_lit_input_rule = true;
    }
    const end = op;
    if (last_match_start) |m| {
        if (m + 12 > end or last_lits < 5) f.end_rules = true;
    }
    if (first_lit_input_rule) f.end_rules = true;
    return f;
}

fn mutate(rnd: std.Random, buf: *std.ArrayList(u8), gpa: std.mem.Allocator, from: usize) !void {
    for (0..1 + rnd.uintLessThan(usize, 3)) |_| {
        if (buf.items.len <= from) return;
        const at = from + rnd.uintLessThan(usize, buf.items.len - from);
        switch (rnd.uintLessThan(u8, 4)) {
            0 => buf.items[at] ^= @as(u8, 1) << rnd.int(u3),
            1 => buf.items[at] = rnd.int(u8),
            2 => buf.shrinkRetainingCapacity(at),
            else => try buf.insert(gpa, at, rnd.int(u8)),
        }
    }
}

fn mutantChecks(c: *Ctx, quick: bool) !void {
    var prng: std.Random.DefaultPrng = .init(0x1a4);
    const rnd = prng.random();
    const n_mutants: usize = if (quick) 1500 else 6000;

    var batch: std.ArrayList(u8) = .empty;
    defer batch.deinit(c.gpa);
    const Rec = struct { data: []u8, cap: usize, frame: bool };
    var recs: std.ArrayList(Rec) = .empty;
    defer {
        for (recs.items) |r| c.gpa.free(r.data);
        recs.deinit(c.gpa);
    }

    var bases: std.ArrayList([]u8) = .empty;
    defer {
        for (bases.items) |b| c.gpa.free(b);
        bases.deinit(c.gpa);
    }
    for (corpus.shapes) |shape| {
        if (corpus.length(shape) > 20_000) continue;
        try bases.append(c.gpa, try corpus.generate(c.gpa, shape));
    }

    // Fixed blocks on the two known divergences, so both explanations below
    // are exercised every run: a 0 offset (liblz4 zero-fills, we refuse) and
    // blocks breaking only the optional end-of-block rules (we accept,
    // liblz4 refuses).
    const fixed = [_]struct { b: []const u8, cap: usize }{
        .{ .b = "\x50hello\x00\x00\x50world", .cap = 100 },
        .{ .b = "\x10a\x01\x00\x10b", .cap = 100 },
        .{ .b = "\x10a\x01\x00\x10b", .cap = 6 },
        .{ .b = "\xf0\x05abcdefghijklmnopqrst\x14\x00\x50vwxyz", .cap = 29 },
        .{ .b = "\xf0\x05abcdefghijklmnopqrst\x04\x00\x00", .cap = 100 },
    };
    for (fixed) |f| {
        try appendRecord(c, &batch, 0, f.cap, f.b);
        try recs.append(c.gpa, .{ .data = try c.gpa.dupe(u8, f.b), .cap = f.cap, .frame = false });
    }

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(c.gpa);
    for (0..n_mutants) |i| {
        const plain = bases.items[rnd.uintLessThan(usize, bases.items.len)];
        const take = plain[0..rnd.uintLessThan(usize, plain.len + 1)];
        buf.clearRetainingCapacity();
        const frame = i % 3 == 0;
        var cap: usize = 0;
        if (frame) {
            const z = try lz4.compress(c.gpa, take, .{
                .independent_blocks = rnd.boolean(),
                .block_checksum = rnd.uintLessThan(u8, 4) == 0,
                .content_checksum = rnd.uintLessThan(u8, 4) == 0,
                .content_size = rnd.boolean(),
            });
            defer c.gpa.free(z);
            try buf.appendSlice(c.gpa, z);
            try mutate(rnd, &buf, c.gpa, 4);
        } else {
            try buf.ensureTotalCapacity(c.gpa, lz4.compressBlockBound(take.len));
            buf.items.len = lz4.compressBlockBound(take.len);
            buf.items.len = try lz4.compressBlock(take, buf.items, .{});
            try mutate(rnd, &buf, c.gpa, 0);
            cap = take.len + rnd.uintLessThan(usize, 64);
        }
        try appendRecord(c, &batch, @intFromBool(frame), cap, buf.items);
        try recs.append(c.gpa, .{ .data = try c.gpa.dupe(u8, buf.items), .cap = cap, .frame = frame });
    }

    const verdicts = try pyVerdicts(c, batch.items);
    defer c.gpa.free(verdicts);
    var lines = std.mem.splitScalar(u8, verdicts, '\n');
    var agree_ok: usize = 0;
    var agree_err: usize = 0;
    var zero_off: usize = 0;
    var end_rule: usize = 0;
    var zero_cap: usize = 0;
    for (recs.items, 0..) |r, i| {
        const line = lines.next() orelse return error.ReferenceFailed;
        c.checks += 1;
        const ref_ok = std.mem.startsWith(u8, line, "OK ");
        const ours: ?[]u8 = if (r.frame)
            lz4.decompress(c.gpa, r.data, .{ .multi_frame = false, .ignore_trailing_garbage = true }) catch null
        else blk: {
            const o = try c.gpa.alloc(u8, r.cap);
            const n = lz4.decompressBlock(r.data, o) catch {
                c.gpa.free(o);
                break :blk null;
            };
            break :blk try c.gpa.realloc(o, n);
        };
        defer if (ours) |o| c.gpa.free(o);
        if (ours) |o| {
            if (ref_ok) {
                var b: [96]u8 = undefined;
                const expect = try std.fmt.bufPrint(&b, "OK {d} {s}", .{ o.len, &sha256Hex(o) });
                if (!std.mem.eql(u8, line, expect)) c.fail("mutant {d}: liblz4 `{s}`, ours {d} bytes", .{ i, line, o.len }) else agree_ok += 1;
            } else if (!r.frame and blockFacts(r.data, r.cap, 0).end_rules) {
                end_rule += 1;
            } else if (!r.frame and r.cap == 0 and r.data.len == 1 and r.data[0] >> 4 == 0) {
                // liblz4 with capacity 0 accepts only the byte 0x00; a
                // literal-only token's match nibble is otherwise ignored
                // (by liblz4 too, at any other capacity).
                zero_cap += 1;
            } else if (r.frame and frameEndRules(r.data)) {
                end_rule += 1;
            } else {
                c.fail("mutant {d} ({s}): we accept {d} bytes, liblz4 refuses, no end-of-block rule explains it", .{ i, if (r.frame) "frame" else "block", o.len });
                try c.put("mutant.bin", r.data);
            }
        } else {
            if (!ref_ok) {
                agree_err += 1;
            } else if (zeroOffset(r)) {
                zero_off += 1;
            } else {
                c.fail("mutant {d} ({s}): we refuse, liblz4 accepts: {s}", .{ i, if (r.frame) "frame" else "block", line });
                try c.put("mutant.bin", r.data);
            }
        }
    }
    if (zero_off == 0 or end_rule < 4) c.fail("the fixed divergence blocks were not classified ({d} offset-0, {d} end-rule)", .{ zero_off, end_rule });
    std.debug.print("mutants: {d} both accept (same bytes), {d} both refuse, {d} offset 0 (liblz4 zero-fills), {d} end-of-block rule (liblz4 refuses), {d} zero-capacity token\n", .{ agree_ok, agree_err, zero_off, end_rule, zero_cap });
}

/// The compressed blocks of a frame (as far as it parses), each judged by
/// `blockFacts` with a full window of history (offsets are not the question).
fn frameEndRules(f: []const u8) bool {
    if (f.len < 7) return false;
    const flg = f[4];
    var at: usize = 7 + @as(usize, if (flg & 8 != 0) 8 else 0) + @as(usize, if (flg & 1 != 0) 4 else 0);
    const bmax = @as(usize, 1) << @intCast(8 + 2 * @as(u5, @intCast((f[5] >> 4) & 7)));
    while (at + 4 <= f.len) {
        const w = std.mem.readInt(u32, f[at..][0..4], .little);
        at += 4;
        if (w == 0) break;
        const len: usize = w & 0x7FFF_FFFF;
        if (at + len > f.len) return false;
        const blk = f[at..][0..len];
        at += len + @as(usize, if (flg & 0x10 != 0) 4 else 0);
        if (w & 0x8000_0000 == 0 and blockFactsSafe(blk, bmax)) return true;
    }
    return false;
}

fn blockFactsSafe(blk: []const u8, cap: usize) bool {
    // A structurally complete block (ends with a literal run): judge it.
    var ip: usize = 0;
    while (ip < blk.len) {
        const t = blk[ip];
        ip += 1;
        var lit: usize = t >> 4;
        if (lit == 15) while (true) {
            if (ip >= blk.len) return false;
            const b = blk[ip];
            ip += 1;
            lit += b;
            if (b != 255) break;
        };
        ip += lit;
        if (ip == blk.len) return blockFacts(blk, cap, 1 << 16).end_rules;
        if (ip + 2 > blk.len) return false;
        ip += 2;
        if (t & 15 == 15) while (true) {
            if (ip >= blk.len) return false;
            const b = blk[ip];
            ip += 1;
            if (b != 255) break;
        };
    }
    return false;
}

fn zeroOffset(r: anytype) bool {
    if (!r.frame) return blockFactsZero(r.data);
    // A frame: any compressed block with a 0 offset.
    const f = r.data;
    if (f.len < 7) return false;
    const flg = f[4];
    var at: usize = 7 + @as(usize, if (flg & 8 != 0) 8 else 0) + @as(usize, if (flg & 1 != 0) 4 else 0);
    while (at + 4 <= f.len) {
        const w = std.mem.readInt(u32, f[at..][0..4], .little);
        at += 4;
        if (w == 0) break;
        const len: usize = w & 0x7FFF_FFFF;
        if (at + len > f.len) return false;
        if (w & 0x8000_0000 == 0 and blockFactsZero(f[at..][0..len])) return true;
        at += len + @as(usize, if (flg & 0x10 != 0) 4 else 0);
    }
    return false;
}

fn blockFactsZero(blk: []const u8) bool {
    var ip: usize = 0;
    while (ip < blk.len) {
        const t = blk[ip];
        ip += 1;
        var lit: usize = t >> 4;
        if (lit == 15) while (true) {
            if (ip >= blk.len) return false;
            const b = blk[ip];
            ip += 1;
            lit += b;
            if (b != 255) break;
        };
        ip += lit;
        if (ip >= blk.len) return false;
        if (ip + 2 > blk.len) return false;
        if (blk[ip] == 0 and blk[ip + 1] == 0) return true;
        ip += 2;
        if (t & 15 == 15) while (true) {
            if (ip >= blk.len) return false;
            const b = blk[ip];
            ip += 1;
            if (b != 255) break;
        };
    }
    return false;
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var quick = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--quick")) quick = true else {
            std.debug.print("usage: interop-lz4 [--quick]\n", .{});
            return 2;
        }
    }

    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, scratch, .{});
    defer dir.close(io);
    var c: Ctx = .{ .gpa = gpa, .io = io, .dir = dir };

    try shapeChecks(&c, quick);
    try mutantChecks(&c, quick);
    std.debug.print("{d} checks, {d} failures\n", .{ c.checks, c.failures });
    return if (c.failures == 0) 0 else 1;
}

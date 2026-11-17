// SPDX-License-Identifier: MIT

//! Comparative benchmark: `lz4` against liblz4 1.10.0 as its CLI measures it
//! (`lz4 -b1`), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-lz4` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `lz4` on PATH.
//! Run from the repository root.
//!
//! Payloads, written into `.zig-cache/bench-lz4/` from the module's shapes,
//! 8 MiB each: `text` (pseudo-English), `noisy` (text with 1 byte in 40
//! random) and `runs` (runs of random bytes). The workload is the one
//! `lz4 -b1 -B65536` times: the file cut into 64 KiB pieces, each compressed
//! as an independent block at the default level (acceleration 1) and each
//! decompressed back. Ours: `compressBlock` / `decompressBlock` over the same
//! pieces, 5 rounds, each timing passes for at least 200 ms.
//! Ratio = ours / theirs by time per byte (MB/s inverted); below 1 = faster.
//! Ours is the median of the rounds, its spread (slowest and fastest round)
//! beside it; theirs is what `lz4 -b` prints (its best iteration).
//! The compressed sizes are printed beside it (the matchers differ, so the
//! sizes may too).
//!
//! `zig build bench-lz4 -- ours c|d [PASSES]`: ours only, a fixed number of
//! passes (default 20) over every payload and nothing timed, for counting
//! instructions with `perf stat -e instructions:u` (an A/B that a loaded
//! machine's wall time cannot give).

const std = @import("std");
const lz4 = @import("lz4");
const shapes = lz4.interop_corpus;

const work_dir = ".zig-cache/bench-lz4";
const piece = 65536;
const mib = 8;

const Payload = struct { name: []const u8, shape: shapes.Shape };
const payloads = [_]Payload{
    .{ .name = "text", .shape = .{ .name = "text", .kind = .text, .len = mib << 20, .seed = 21 } },
    .{ .name = "noisy", .shape = .{ .name = "noisy", .kind = .noisy_text, .len = mib << 20, .param = 40, .seed = 22 } },
    .{ .name = "runs", .shape = .{ .name = "runs", .kind = .runs, .len = mib << 20, .param = 40, .seed = 23 } },
};

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
}

const Ours = struct { c_mbs: f64, d_mbs: f64, c_lo: f64, c_hi: f64, d_lo: f64, d_hi: f64, size: usize };

const max_rounds = 32;

/// MB/s of the median, slowest and fastest of `ns[0..n]` (ns per pass).
fn stats(ns: []i96, bytes: f64) [3]f64 {
    std.mem.sort(i96, ns, {}, std.sort.asc(i96));
    const f = struct {
        fn mbs(t: i96, b: f64) f64 {
            return b / @as(f64, @floatFromInt(t)) * 1e3;
        }
    }.mbs;
    return .{ f(ns[ns.len / 2], bytes), f(ns[ns.len - 1], bytes), f(ns[0], bytes) };
}

fn measureOurs(io: std.Io, gpa: std.mem.Allocator, plain: []const u8, rounds: usize) !Ours {
    const n_pieces = (plain.len + piece - 1) / piece;
    const z = try gpa.alloc(u8, n_pieces * lz4.compressBlockBound(piece));
    defer gpa.free(z);
    const zlen = try gpa.alloc(usize, n_pieces);
    defer gpa.free(zlen);
    const back = try gpa.alloc(u8, plain.len);
    defer gpa.free(back);
    const stride = lz4.compressBlockBound(piece);

    var c_ns: [max_rounds]i96 = undefined;
    var d_ns: [max_rounds]i96 = undefined;
    var size: usize = 0;
    for (0..rounds) |round| {
        var reps: usize = 0;
        const t0 = nowNs(io);
        while (true) {
            size = 0;
            for (0..n_pieces) |i| {
                const src = plain[i * piece .. @min(plain.len, (i + 1) * piece)];
                zlen[i] = try lz4.compressBlock(src, z[i * stride ..][0..stride], .{});
                size += zlen[i];
            }
            reps += 1;
            if (nowNs(io) - t0 > 200_000_000) break;
        }
        c_ns[round] = @divTrunc(nowNs(io) - t0, @as(i96, @intCast(reps)));

        reps = 0;
        const t1 = nowNs(io);
        while (true) {
            for (0..n_pieces) |i| {
                const dst = back[i * piece .. @min(plain.len, (i + 1) * piece)];
                const k = try lz4.decompressBlock(z[i * stride ..][0..zlen[i]], dst);
                std.debug.assert(k == dst.len);
            }
            reps += 1;
            if (nowNs(io) - t1 > 200_000_000) break;
        }
        d_ns[round] = @divTrunc(nowNs(io) - t1, @as(i96, @intCast(reps)));
    }
    if (!std.mem.eql(u8, back, plain)) return error.RoundTripFailed;
    const bytes: f64 = @floatFromInt(plain.len);
    const c = stats(c_ns[0..rounds], bytes);
    const d = stats(d_ns[0..rounds], bytes);
    return .{ .c_mbs = c[0], .c_lo = c[1], .c_hi = c[2], .d_mbs = d[0], .d_lo = d[1], .d_hi = d[2], .size = size };
}

/// The `ours` mode: `passes` untimed passes of one direction over `plain`.
/// Returns the compressed size (so the work cannot be dropped).
fn runOurs(gpa: std.mem.Allocator, plain: []const u8, decompress: bool, passes: usize) !usize {
    const n_pieces = (plain.len + piece - 1) / piece;
    const stride = lz4.compressBlockBound(piece);
    const z = try gpa.alloc(u8, n_pieces * stride);
    defer gpa.free(z);
    const zlen = try gpa.alloc(usize, n_pieces);
    defer gpa.free(zlen);
    const back = try gpa.alloc(u8, plain.len);
    defer gpa.free(back);
    var size: usize = 0;
    for (0..if (decompress) 1 else passes) |_| {
        size = 0;
        for (0..n_pieces) |i| {
            const src = plain[i * piece .. @min(plain.len, (i + 1) * piece)];
            zlen[i] = try lz4.compressBlock(src, z[i * stride ..][0..stride], .{});
            size += zlen[i];
        }
    }
    if (decompress) {
        for (0..passes) |_| {
            for (0..n_pieces) |i| {
                const dst = back[i * piece .. @min(plain.len, (i + 1) * piece)];
                const k = try lz4.decompressBlock(z[i * stride ..][0..zlen[i]], dst);
                if (k != dst.len) return error.RoundTripFailed;
            }
        }
        if (!std.mem.eql(u8, back, plain)) return error.RoundTripFailed;
    }
    return size;
}

const Theirs = struct { c_mbs: f64, d_mbs: f64, size: usize };

/// Parse `lz4 -b1`'s result: the last progress segment (they are separated
/// by carriage returns) that carries both speeds,
/// `... : N -> SIZE (ratio),C MB/s, D MB/s`.
fn parseTheirs(out: []const u8) !Theirs {
    var last: ?[]const u8 = null;
    var segs = std.mem.tokenizeAny(u8, out, "\r\n");
    while (segs.next()) |seg| {
        if (std.mem.count(u8, seg, "MB/s") == 2) last = seg;
    }
    const line = last orelse return error.BadForeignOutput;
    const arrow = std.mem.lastIndexOf(u8, line, "->") orelse return error.BadForeignOutput;
    var it = std.mem.tokenizeAny(u8, line[arrow + 2 ..], " ,()");
    const size = try std.fmt.parseInt(usize, it.next() orelse return error.BadForeignOutput, 10);
    _ = it.next(); // ratio
    const c = try std.fmt.parseFloat(f64, it.next() orelse return error.BadForeignOutput);
    _ = it.next(); // MB/s
    const d = try std.fmt.parseFloat(f64, it.next() orelse return error.BadForeignOutput);
    return .{ .c_mbs = c, .d_mbs = d, .size = size };
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const args = try init.args.toSlice(arena_state.allocator());
    if (args.len >= 3 and std.mem.eql(u8, args[1], "ours")) {
        const dec = std.mem.eql(u8, args[2], "d");
        const passes = if (args.len >= 4) try std.fmt.parseInt(usize, args[3], 10) else 20;
        for (payloads) |p| {
            const plain = try shapes.generate(gpa, p.shape);
            defer gpa.free(plain);
            const size = try runOurs(gpa, plain, dec, passes);
            std.debug.print("{s:<6} {s} x{d} size {d}\n", .{ p.name, if (dec) "decompress" else "compress", passes, size });
        }
        return 0;
    }

    const rounds: usize = 5;
    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, work_dir, .{});
    defer dir.close(io);

    var worst_c: f64 = 0;
    var worst_d: f64 = 0;
    for (payloads) |p| {
        const plain = try shapes.generate(gpa, p.shape);
        defer gpa.free(plain);
        var name_buf: [64]u8 = undefined;
        const file = try std.fmt.bufPrint(&name_buf, "{s}.bin", .{p.name});
        try dir.writeFile(io, .{ .sub_path = file, .data = plain });
        var path_buf: [128]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, work_dir ++ "/{s}", .{file});

        const r = try std.process.run(gpa, io, .{ .argv = &.{ "lz4", "-b1", "-i2", "-B65536", path } });
        defer gpa.free(r.stdout);
        defer gpa.free(r.stderr);
        const theirs = parseTheirs(r.stdout) catch parseTheirs(r.stderr) catch {
            std.debug.print("could not parse lz4 -b output:\n{s}{s}\n", .{ r.stdout, r.stderr });
            return 1;
        };
        const ours = try measureOurs(io, gpa, plain, rounds);
        const rc = theirs.c_mbs / ours.c_mbs;
        const rd = theirs.d_mbs / ours.d_mbs;
        worst_c = @max(worst_c, rc);
        worst_d = @max(worst_d, rd);
        std.debug.print("{s:<6} compress ours {d:>7.1} MB/s ({d:.1}..{d:.1}) lz4 {d:>7.1} MB/s ratio {d:.2}x | decompress ours {d:>7.1} MB/s ({d:.1}..{d:.1}) lz4 {d:>7.1} MB/s ratio {d:.2}x | size ours {d} lz4 {d}\n", .{
            p.name,      ours.c_mbs, ours.c_lo, ours.c_hi,    theirs.c_mbs, rc,
            ours.d_mbs,  ours.d_lo,  ours.d_hi, theirs.d_mbs, rd,           ours.size,
            theirs.size,
        });
    }
    std.debug.print("worst ratio (ours/theirs time): compress {d:.2}x, decompress {d:.2}x\n", .{ worst_c, worst_d });
    return 0;
}

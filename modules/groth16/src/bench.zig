// SPDX-License-Identifier: MIT

//! bench — opt-in timing of `phase2.contribute`'s C/H rescaling, the part that
//! is all of its cost on a real key. Off by default; opt in with
//! `GROTH16_BENCH`:
//!
//!   GROTH16_BENCH=1 scripts/modtest groth16 -Doptimize=ReleaseFast -Dtest-filter=bench
//!
//! Each round times the plain path (`scaleAllRef`: double-and-add-always
//! `scalarMul` + one inversion per point) and the new one (`scaleAll`: 4-bit
//! window, one inversion per batch) on the same points, alternately, and
//! prints both and their ratio; the spread across rounds is the noise.

const std = @import("std");
const bn254 = @import("bn254");
const phase2 = @import("phase2.zig");

const Fr = bn254.Fr;
const G1 = bn254.G1;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "bench: contribute's C/H rescaling, plain vs windowed + batch-normalised" {
    if (std.testing.environ.getPosix("GROTH16_BENCH") == null) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const n = 2048;
    const pts = try gpa.alloc(G1.Affine, n);
    defer gpa.free(pts);
    const work = try gpa.alloc(G1.Affine, n);
    defer gpa.free(work);
    var acc = G1.Jacobian.fromAffine(G1.Affine.generator);
    const step = acc.scalarMul(Fr.reduceWide(&@as([64]u8, @splat(0x3c))));
    for (pts) |*p| {
        p.* = acc.toAffine();
        acc = acc.add(step);
    }
    const scratch = try gpa.create(phase2.ScaleScratch);
    defer gpa.destroy(scratch);
    const k = Fr.reduceWide(&@as([64]u8, @splat(0xa7)));
    const k_be = k.toBytes();
    std.debug.print("\n-- groth16 contribute rescaling, {d} G1 points --\n", .{n});
    for (0..5) |round| {
        @memcpy(work, pts);
        const t0 = nowNs();
        phase2.scaleAllRef(work, k);
        const t1 = nowNs();
        std.mem.doNotOptimizeAway(work.ptr);
        @memcpy(work, pts);
        const t2 = nowNs();
        phase2.scaleAll(scratch, work, &k_be);
        const t3 = nowNs();
        std.mem.doNotOptimizeAway(work.ptr);
        const ref_ns = t1 - t0;
        const new_ns = t3 - t2;
        std.debug.print("round {d}: plain {d:.1} us/pt  windowed {d:.1} us/pt  ratio {d:.2}x\n", .{
            round,
            @as(f64, @floatFromInt(ref_ns)) / (n * 1000.0),
            @as(f64, @floatFromInt(new_ns)) / (n * 1000.0),
            @as(f64, @floatFromInt(ref_ns)) / @as(f64, @floatFromInt(new_ns)),
        });
    }
}

// SPDX-License-Identifier: MIT

//! Peak stack of the slot-dispatched `DynModint` operations `pow`, `inverse`
//! and `sqrt` (review finding REV-montint-1): the measured dirty depth must stay
//! within the documented `DynModint(max_bits).stack_bytes`.
//!
//! Method: `testkit.stackprobe` (paint a window below the call, run it, read how
//! deep the paint was overwritten); only the depth (`dirty_depth`) is used here,
//! no needles. ReleaseFast / ReleaseSmall only (`skipUnlessOptimized`): Debug
//! and ReleaseSafe fill `undefined` with 0xaa, so the depth cannot be read.
//! Run with `scripts/modtest montint -Doptimize=ReleaseFast`.
//!
//! The modulus is `2^(64·max_limbs) − 1` (full width, so the top slot runs; it
//! is 7 mod 8, so `sqrt` takes the `a^((p+1)/4)` path).

const std = @import("std");
const sp = @import("testkit").stackprobe;
const DynModint = @import("root.zig").DynModint;

/// Print every measurement (sizes the documented table).
const verbose = false;

const P = sp.Probe(.{ .window = 1024 * 1024, .repeats = 1, .verbose = false });

fn peakOf(comptime label: []const u8, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f))) !usize {
    const r = try P.run(label, f, args, &.{}, .{ .burn = false, .residue = false });
    return r.dirty_depth;
}

fn probe(comptime max_bits: comptime_int) !void {
    const M = DynModint(max_bits);
    var mod: M.Elem = @splat(std.math.maxInt(u64));
    const m = try M.fromLimbs(&mod);
    var base: M.Elem = @splat(0x0123_4567_89ab_cdef);
    base[M.max_limbs - 1] = 0x0123_4567_89ab_cdef >> 8;
    var exp: M.Elem = @splat(0x7fed_cba9_8765_4321);
    var out: M.Elem = undefined;

    const pow_peak = try peakOf("DynModint.pow", M.pow, .{ &m, &base, &exp });
    const inv_peak = try peakOf("DynModint.inverse", M.inverse, .{ &m, &base, &out });
    const sqrt_peak = try peakOf("DynModint.sqrt", M.sqrt, .{ &m, &base, &out });
    if (verbose) std.debug.print("STACKPROBE montint {d}: pow {d} inverse {d} sqrt {d} documented {d}\n", .{ max_bits, pow_peak, inv_peak, sqrt_peak, M.stack_bytes });
    try std.testing.expect(pow_peak != 0 and inv_peak != 0 and sqrt_peak != 0); // the probe sees the call
    try std.testing.expect(pow_peak <= M.stack_bytes);
    try std.testing.expect(inv_peak <= M.stack_bytes);
    try std.testing.expect(sqrt_peak <= M.stack_bytes);
}

test "STACKPROBE: DynModint pow / inverse / sqrt stay within the documented stack_bytes (review REV-montint-1)" {
    try sp.skipUnlessOptimized();
    try probe(2048);
    try probe(4096);
    try probe(8192);
}

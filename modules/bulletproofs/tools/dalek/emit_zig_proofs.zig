// SPDX-License-Identifier: MIT

//! Prints range proofs made by THIS module, one per line, for
//! `tools/dalek` to verify with dalek's `RangeProof::verify_single`:
//!
//!     <n> <label hex> <V hex> <proof hex>
//!
//! then aggregated ones (`proveMultiple`) for dalek's `verify_multiple`,
//! with the commitments joined by `,` in the V field:
//!
//!     <n> <label hex> <V_0 hex>,<V_1 hex>,... <proof hex>
//!
//! The prover draws its blinding from getrandom(2), so every run prints
//! different proofs; the committed `zig_proofs.txt` is one such run. See
//! `tools/README.md` for the command line.

const std = @import("std");
const bp = @import("bulletproofs");

pub const label = "zig-libs bulletproofs interop";

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    const w = &out.interface;

    for ([_]usize{ 8, 16, 32, 64 }) |n| {
        const gens = try bp.Generators.init(gpa, n);
        defer gens.deinit(gpa);
        const max: u64 = if (n == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(n)) - 1;
        for ([_]u64{ 0, 1, max / 3, max }) |v| {
            var gamma: [32]u8 = undefined;
            init.io.random(&gamma);
            gamma = bp.Ristretto255.scalar.reduce(gamma);
            var v_bytes = [_]u8{0} ** 32;
            std.mem.writeInt(u64, v_bytes[0..8], v, .little);
            const commitment = bp.commit(gens, v_bytes, gamma);

            var t = bp.Transcript.init(label);
            const proof = try bp.prove(gpa, gens, &t, &v, gamma);
            defer proof.deinit(gpa);
            const bytes = try proof.toBytesAlloc(gpa);
            defer gpa.free(bytes);

            const v_enc = commitment.toBytes();
            try w.print("{d} {x} {x} {x}\n", .{ n, @as([]const u8, label), @as([]const u8, &v_enc), bytes });
        }
    }

    const batches = [_]struct { n: usize, values: []const u64 }{
        .{ .n = 8, .values = &.{ 255, 0 } },
        .{ .n = 8, .values = &.{ 9, 8, 7, 6, 5, 4, 3, 2 } },
        .{ .n = 16, .values = &.{ 65535, 1, 0, 30000 } },
        .{ .n = 32, .values = &.{ 0, std.math.maxInt(u32) } },
        .{ .n = 64, .values = &.{ 0, 1, std.math.maxInt(u64), 1 << 63 } },
    };
    for (batches) |b| {
        const gens = try bp.Generators.initParties(gpa, b.n, b.values.len);
        defer gens.deinit(gpa);
        const gammas = try gpa.alloc([32]u8, b.values.len);
        defer gpa.free(gammas);
        try w.print("{d} {x} ", .{ b.n, @as([]const u8, label) });
        for (b.values, gammas, 0..) |v, *gamma, j| {
            init.io.random(gamma);
            gamma.* = bp.Ristretto255.scalar.reduce(gamma.*);
            var v_bytes = [_]u8{0} ** 32;
            std.mem.writeInt(u64, v_bytes[0..8], v, .little);
            const v_enc = bp.commit(gens, v_bytes, gamma.*).toBytes();
            try w.print("{s}{x}", .{ if (j == 0) "" else ",", @as([]const u8, &v_enc) });
        }
        var t = bp.Transcript.init(label);
        const proof = try bp.proveMultiple(gpa, gens, &t, b.values, gammas);
        defer proof.deinit(gpa);
        const bytes = try proof.toBytesAlloc(gpa);
        defer gpa.free(bytes);
        try w.print(" {x}\n", .{bytes});
    }
    try w.flush();
}

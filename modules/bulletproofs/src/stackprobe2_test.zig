// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the multi-party party side,
//! `mpc.Party`: its three rounds `init`, `applyBitChallenge` and
//! `applyPolyChallenge` (the single-prover `prove` is `stackprobe_test.zig`'s).
//! ReleaseFast/ReleaseSmall only (`skipUnlessOptimized`).
//!
//! Needles, read after each call: the blinding `gamma`, the party's random
//! blinding scalars `alpha`, `rho`, `tau1`, `tau2` and the first of its
//! `s_L`/`s_R` (the state `init` writes), the round-2 polynomial coefficients
//! `t1`, `t2` (re-derived here from the state) and round 3's `z^(2+j)·gamma`.
//! The engine's residue rule covers every other intermediate below the burn.
//! The probe calls each round several times; an arena takes the allocations.

const std = @import("std");
const mpc = @import("mpc.zig");
const scalarvec = @import("scalarvec.zig");
const Generators = @import("generators.zig").Generators;
const Transcript = @import("transcript.zig").Transcript;
const scalar = std.crypto.ecc.Ristretto255.scalar;
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 192 * 1024 });

var party: mpc.Party = undefined;
var share: mpc.ProofShare = undefined;
var gamma: [32]u8 = undefined;
var t1: [32]u8 = undefined;
var t2: [32]u8 = undefined;
var zg: [32]u8 = undefined;

fn stateNeedles(extra: []const []const u8, buf: *[12][]const u8) []const []const u8 {
    const base = [_][]const u8{ &gamma, &party.alpha, &party.rho, &party.tau1, &party.tau2, &party.s_l[0], &party.s_r[0] };
    @memcpy(buf[0..base.len], &base);
    @memcpy(buf[base.len..][0..extra.len], extra);
    return buf[0 .. base.len + extra.len];
}

test "STACKPROBE: mpc.Party's three rounds leave no witness or blinding scalar on the dead stack" {
    try sp.skipUnlessOptimized();
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const gens = try Generators.initParties(a, 64, 2);
    const j: usize = 1;
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("bulletproofs mpc probe gamma", &wide, .{});
    gamma = scalar.reduce64(wide);
    const v: u64 = 0x1234_5678_9abc_def0;

    var buf: [12][]const u8 = undefined;
    // `s_L`/`s_R` live behind pointers `init` itself writes, so they are
    // needles from the second round on (the slice must exist before `run`).
    _ = try P.run("mpc.Party.init", mpc.Party.init, .{ &party, a, std.testing.io, gens, j, v, &gamma }, &.{ &gamma, &party.alpha, &party.rho, &party.tau1, &party.tau2 }, .{});

    // Public challenges, as a dealer would send them.
    var y: [32]u8 = undefined;
    var z: [32]u8 = undefined;
    var x: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("y", &wide, .{});
    y = scalar.reduce64(wide);
    std.crypto.hash.sha2.Sha512.hash("z", &wide, .{});
    z = scalar.reduce64(wide);
    std.crypto.hash.sha2.Sha512.hash("x", &wide, .{});
    x = scalar.reduce64(wide);

    _ = try P.run("mpc.Party.applyBitChallenge", mpc.Party.applyBitChallenge, .{ &party, mpc.BitChallenge{ .y = y, .z = z } }, stateNeedles(&.{}, &buf), .{});
    // The round-2 coefficients from the state the call left.
    t1 = scalar.add(try scalarvec.innerProduct(party.l0, party.r1), try scalarvec.innerProduct(party.s_l, party.r0));
    t2 = try scalarvec.innerProduct(party.s_l, party.r1);
    _ = try P.run("mpc.Party.applyBitChallenge (t1, t2)", mpc.Party.applyBitChallenge, .{ &party, mpc.BitChallenge{ .y = y, .z = z } }, stateNeedles(&.{ &t1, &t2 }, &buf), .{});

    var zp = scalarvec.one;
    for (0..2 + j) |_| zp = scalar.mul(zp, z);
    zg = scalar.mul(zp, gamma);
    _ = try P.run("mpc.Party.applyPolyChallenge", mpc.Party.applyPolyChallenge, .{ &party, mpc.PolyChallenge{ .x = x }, &share }, stateNeedles(&.{ &t1, &t2, &zg }, &buf), .{});

    // The probed rounds produced a consistent share: t_x = <l, r>.
    try std.testing.expectEqualSlices(u8, &share.t_x, &try scalarvec.innerProduct(share.l_vec, share.r_vec));
}

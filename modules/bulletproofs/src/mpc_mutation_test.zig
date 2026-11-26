// SPDX-License-Identifier: MIT
//! Tests for the delta mutation run of `mpc.zig` (2026-11-25): the guards,
//! randomness, wipes and audit equations the first mpc tests did not pin.

const std = @import("std");
const builtin = @import("builtin");
const mpc = @import("mpc.zig");
const rp = @import("rangeproof.zig");
const Generators = @import("generators.zig").Generators;
const Transcript = @import("transcript.zig").Transcript;
const scalarvec = @import("scalarvec.zig");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;
const testing = std.testing;
const talloc = testing.allocator;

fn gammaFor(j: usize) [32]u8 {
    var g: [32]u8 = @splat(0);
    std.mem.writeInt(u64, g[0..8], 0x2545_f491_4f6c_dd1d *% (@as(u64, j) + 3), .little);
    return scalar.reduce(g);
}

const Tamper = struct {
    /// Add G to this party's T1 and x to its t_x: only `t_x = <l, r>` is violated.
    t1_plus_g: ?usize = null,
    /// Add 1 to this party's `t_x_blinding`: only the t_x commitment equation fails.
    t_x_blinding: ?usize = null,
    /// Add 1 to this party's `e_blinding`: only the vector equation fails.
    e_blinding: ?usize = null,
    /// Advance the dealer's transcript after `Dealer.init`: every share is honest, the sum does not verify.
    transcript_extra: bool = false,
};

const Run = struct { proof: rp.RangeProof, vs: [4]Ristretto255 };

fn drive(gens: Generators, values: []const u64, tamper: Tamper, bad: []bool) mpc.MpcError!Run {
    const m = values.len;
    var t = Transcript.init("mpc mutation");
    var dealer = try mpc.Dealer.init(gens, &t, m);
    if (tamper.transcript_extra) t.appendMessage("extra", "x");
    var parties: [4]mpc.Party = undefined;
    var bcs: [4]mpc.BitCommitment = undefined;
    var made: usize = 0;
    defer for (parties[0..made]) |*p| p.deinit();
    for (values, 0..) |v, j| {
        bcs[j] = try mpc.Party.init(&parties[j], talloc, testing.io, gens, j, v, &gammaFor(j));
        made += 1;
    }
    const bit_c = try dealer.receiveBitCommitments(bcs[0..m]);
    var pcs: [4]mpc.PolyCommitment = undefined;
    for (parties[0..m], 0..) |*p, j| pcs[j] = p.applyBitChallenge(bit_c);
    if (tamper.t1_plus_g) |c| pcs[c].t1 = pcs[c].t1.add(gens.g);
    const poly_c = try dealer.receivePolyCommitments(pcs[0..m]);
    var shares: [4]mpc.ProofShare = undefined;
    var nshares: usize = 0;
    defer for (shares[0..nshares]) |sh| sh.deinit(talloc);
    for (parties[0..m], 0..) |*p, j| {
        try p.applyPolyChallenge(poly_c, &shares[j]);
        nshares += 1;
    }
    if (tamper.t1_plus_g) |c| shares[c].t_x = scalar.add(shares[c].t_x, poly_c.x);
    if (tamper.t_x_blinding) |c| shares[c].t_x_blinding = scalar.add(shares[c].t_x_blinding, scalarvec.one);
    if (tamper.e_blinding) |c| shares[c].e_blinding = scalar.add(shares[c].e_blinding, scalarvec.one);
    var run: Run = .{ .proof = try dealer.receiveShares(talloc, shares[0..m], bad), .vs = undefined };
    for (bcs[0..m], 0..) |bc, j| run.vs[j] = bc.v;
    return run;
}

test "mutation 2026-11-25: mpc with 64-bit values: bit 63 is committed, and the proof verifies" {
    const gens = try Generators.initParties(talloc, 64, 1);
    defer gens.deinit(talloc);
    var bad: [1]bool = .{true};
    const v: u64 = (1 << 63) | 0x1234_5678;
    const run = try drive(gens, &.{v}, .{}, &bad);
    defer run.proof.deinit(talloc);
    try testing.expect(!bad[0]); // a verifying proof leaves `bad` all false
    var t = Transcript.init("mpc mutation");
    try testing.expect(rp.verifyMultiple(gens, &t, run.vs[0..1], run.proof));
}

test "mutation 2026-11-25: a party's randomness is non-zero, and deinit wipes every scalar it holds" {
    const gens = try Generators.initParties(talloc, 8, 2);
    defer gens.deinit(talloc);
    const zero: [32]u8 = @splat(0);
    var p: mpc.Party = undefined;
    _ = try mpc.Party.init(&p, talloc, testing.io, gens, 0, 5, &gammaFor(0));
    try testing.expect(!std.mem.eql(u8, &zero, &p.alpha));
    try testing.expect(!std.mem.eql(u8, &zero, &p.rho));
    try testing.expect(!std.mem.eql(u8, &zero, &p.tau1));
    try testing.expect(!std.mem.eql(u8, &zero, &p.tau2));
    for (p.s_l, p.s_r) |sl, sr| {
        try testing.expect(!std.mem.eql(u8, &zero, &sl));
        try testing.expect(!std.mem.eql(u8, &zero, &sr));
    }
    try testing.expect(!std.mem.eql(u8, &zero, &p.gamma));
    // The struct outlives deinit (a stack variable): its scalar fields read back zero.
    p.deinit();
    for ([_]*const [32]u8{ &p.gamma, &p.alpha, &p.rho, &p.tau1, &p.tau2 }) |f| try testing.expectEqualSlices(u8, &zero, f);
}

test "mutation 2026-11-25: Party.init frees what it allocated when an allocation fails (no leak)" {
    const gens = try Generators.initParties(talloc, 8, 2);
    defer gens.deinit(talloc);
    for (0..7) |k| {
        var fa = testing.FailingAllocator.init(talloc, .{ .fail_index = k });
        var p: mpc.Party = undefined;
        try testing.expectError(error.OutOfMemory, mpc.Party.init(&p, fa.allocator(), testing.io, gens, 0, 5, &gammaFor(0)));
    }
}

test "mutation 2026-11-25: the dealer refuses counts that do not match, at every round" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    var t0 = Transcript.init("x");
    // 3 parties are no power of two even though 4 are allowed.
    try testing.expectError(error.InvalidAggregation, mpc.Dealer.init(gens, &t0, 3));
    _ = try mpc.Dealer.init(gens, &t0, 4);

    var t = Transcript.init("counts");
    var dealer = try mpc.Dealer.init(gens, &t, 2);
    var parties: [2]mpc.Party = undefined;
    var bcs: [2]mpc.BitCommitment = undefined;
    for (&parties, 0..) |*p, j| bcs[j] = try mpc.Party.init(p, talloc, testing.io, gens, j, 10 + j, &gammaFor(j));
    defer for (&parties) |*p| p.deinit();
    const bit_c = try dealer.receiveBitCommitments(&bcs);
    var pcs: [2]mpc.PolyCommitment = undefined;
    for (&parties, 0..) |*p, j| pcs[j] = p.applyBitChallenge(bit_c);
    try testing.expectError(error.InvalidAggregation, dealer.receivePolyCommitments(pcs[0..1]));
    const poly_c = try dealer.receivePolyCommitments(&pcs);
    var shares: [2]mpc.ProofShare = undefined;
    for (&parties, 0..) |*p, j| try p.applyPolyChallenge(poly_c, &shares[j]);
    defer for (shares) |sh| sh.deinit(talloc);

    var bad2: [2]bool = undefined;
    var bad1: [1]bool = undefined;
    try testing.expectError(error.InvalidAggregation, dealer.receiveShares(talloc, shares[0..1], &bad2));
    try testing.expectError(error.InvalidAggregation, dealer.receiveShares(talloc, &shares, &bad1));
    // A share whose l or r vector is not n long.
    var short_l = shares;
    short_l[1].l_vec = shares[1].l_vec[0..7];
    try testing.expectError(error.MalformedShare, dealer.receiveShares(talloc, &short_l, &bad2));
    var short_r = shares;
    short_r[0].r_vec = shares[0].r_vec[0..7];
    try testing.expectError(error.MalformedShare, dealer.receiveShares(talloc, &short_r, &bad2));
    // And the real shares still go through (the checks above are before any transcript use).
    bad2 = .{ true, true };
    const proof = try dealer.receiveShares(talloc, &shares, &bad2);
    defer proof.deinit(talloc);
    try testing.expectEqualSlices(bool, &.{ false, false }, &bad2);
}

test "mutation 2026-11-25: the share audit blames the party whose ONE equation fails, and everyone when none does" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    const values = [_]u64{ 3, 9, 27, 81 };
    for ([_]Tamper{ .{ .t1_plus_g = 2 }, .{ .t_x_blinding = 1 }, .{ .e_blinding = 3 } }, [_]usize{ 2, 1, 3 }) |tamper, who| {
        var bad: [4]bool = undefined;
        try testing.expectError(error.MalformedProofShares, drive(gens, &values, tamper, &bad));
        for (bad, 0..) |b, j| try testing.expectEqual(j == who, b);
    }
    // Every share audits (they match the dealer's challenges) yet the proof does not verify
    // for the verifier's transcript: blame cannot be placed, all are named.
    var bad: [4]bool = undefined;
    try testing.expectError(error.MalformedProofShares, drive(gens, &values, .{ .transcript_extra = true }, &bad));
    try testing.expectEqualSlices(bool, &.{ true, true, true, true }, &bad);
}

/// Counts the blocks freed with a non-zero byte, and fills new blocks with 0xA5.
/// `Allocator.free` poisons a block before the vtable sees it in the safe modes,
/// so the tests using it run in ReleaseFast/ReleaseSmall only.
const Scan = struct {
    parent: std.mem.Allocator,
    fail_at: usize = std.math.maxInt(usize),
    allocs: usize = 0,
    frees: usize = 0,
    dirty: usize = 0,

    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn allocator(self: *Scan) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Scan = @ptrCast(@alignCast(ctx));
        self.allocs += 1;
        if (self.allocs > self.fail_at) return null;
        const p = self.parent.rawAlloc(len, alignment, ra) orelse return null;
        @memset(p[0..len], 0xA5);
        return p;
    }

    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *Scan = @ptrCast(@alignCast(ctx));
        self.frees += 1;
        for (memory) |b| if (b != 0) {
            self.dirty += 1;
            break;
        };
        self.parent.rawFree(memory, alignment, ra);
    }
};

test "mutation 2026-11-25: the party's seven heap buffers are zero when freed (deinit and a failed init); ReleaseFast only" {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
    const gens = try Generators.initParties(talloc, 8, 2);
    defer gens.deinit(talloc);
    var s: Scan = .{ .parent = talloc };
    var p: mpc.Party = undefined;
    _ = try mpc.Party.init(&p, s.allocator(), testing.io, gens, 0, 5, &gammaFor(0));
    p.deinit();
    try testing.expectEqual(@as(usize, 7), s.frees);
    try testing.expectEqual(@as(usize, 0), s.dirty);
    // The fourth allocation fails: the three made are wiped on the way out.
    var f: Scan = .{ .parent = talloc, .fail_at = 3 };
    var q: mpc.Party = undefined;
    try testing.expectError(error.OutOfMemory, mpc.Party.init(&q, f.allocator(), testing.io, gens, 0, 5, &gammaFor(0)));
    try testing.expectEqual(@as(usize, 3), f.frees);
    try testing.expectEqual(@as(usize, 0), f.dirty);
}

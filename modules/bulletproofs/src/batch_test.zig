// SPDX-License-Identifier: MIT

//! batch_test — `verifyBatch`: one MSM over several independent proofs.
//! Completeness on mixed `m`, rejection of a batch holding one forged proof
//! (every field of the per-field tamper set, at every position), the
//! verdict of a one-proof batch equal to `verifyMultiple`'s on the same
//! inputs, and dalek's own single and aggregated proofs verified as batches.

const std = @import("std");
const bp = @import("root.zig");
const vectors = @import("interop_vectors.zig");
const Generators = bp.Generators;
const Transcript = bp.Transcript;
const Ristretto255 = bp.Ristretto255;
const scalar = Ristretto255.scalar;

const talloc = std.testing.allocator;
const tio = std.testing.io;

fn gammaFor(j: usize) [32]u8 {
    var g = @as([32]u8, @splat(0));
    std.mem.writeInt(u64, g[0..8], 0x2545_f491_4f6c_dd1d *% (@as(u64, j) + 7), .little);
    return scalar.reduce(g);
}

const Proved = struct {
    proof: bp.RangeProof,
    commitments: []Ristretto255,

    fn deinit(self: Proved) void {
        self.proof.deinit(talloc);
        talloc.free(self.commitments);
    }
};

fn proveValues(gens: Generators, values: []const u64, salt: usize) !Proved {
    const gammas = try talloc.alloc([32]u8, values.len);
    defer talloc.free(gammas);
    const commitments = try talloc.alloc(Ristretto255, values.len);
    errdefer talloc.free(commitments);
    for (values, gammas, commitments, 0..) |v, *g, *c, j| {
        g.* = gammaFor(j + 16 * salt);
        var vb = @as([32]u8, @splat(0));
        std.mem.writeInt(u64, vb[0..8], v, .little);
        c.* = bp.commit(gens, vb, g.*);
    }
    var t = Transcript.init(bp.rangeproof_domain);
    const proof = try bp.proveMultiple(talloc, tio, gens, &t, values, gammas);
    return .{ .proof = proof, .commitments = commitments };
}

/// Batch-verifies `items` with fresh transcripts.
fn batch(gens: Generators, items: []const Proved) !bool {
    var ts: [16]Transcript = undefined;
    var es: [16]bp.BatchEntry = undefined;
    std.debug.assert(items.len <= es.len);
    for (items, 0..) |it, i| {
        ts[i] = Transcript.init(bp.rangeproof_domain);
        es[i] = .{ .transcript = &ts[i], .commitments = it.commitments, .proof = it.proof };
    }
    return bp.verifyBatch(gens, tio, es[0..items.len]);
}

fn single(gens: Generators, it: Proved) bool {
    var t = Transcript.init(bp.rangeproof_domain);
    return bp.verifyMultiple(gens, &t, it.commitments, it.proof);
}

/// A small proof set with mixed m: 1, 2, 1, 4.
fn proveSet(gens: Generators, out: []Proved) !void {
    const sets = [_][]const u64{ &.{200}, &.{ 0, 255 }, &.{17}, &.{ 1, 2, 254, 128 } };
    std.debug.assert(out.len == sets.len);
    var made: usize = 0;
    errdefer for (out[0..made]) |p| p.deinit();
    for (sets, 0..) |vals, i| {
        out[i] = try proveValues(gens, vals, i);
        made += 1;
    }
}

test "verifyBatch: honest proofs with mixed m verify as one batch; empty batch is true" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    var set: [4]Proved = undefined;
    try proveSet(gens, &set);
    defer for (set) |p| p.deinit();
    try std.testing.expect(try batch(gens, &set));
    try std.testing.expect(try batch(gens, set[0..1]));
    try std.testing.expect(try batch(gens, &.{}));
}

/// The tamper set: one field of one proof changed. Each variant is a proof
/// `verifyMultiple` must reject.
const Tamper = enum { t_hat, tau_x, mu, ipa_a, ipa_b, a, s, t1, t2, l0, r_last, commitment, swap_commitments };

fn applyTamper(p: *Proved, which: Tamper, gens: Generators) bool {
    const one = [_]u8{1} ++ @as([31]u8, @splat(0));
    switch (which) {
        .t_hat => p.proof.t_hat = scalar.add(p.proof.t_hat, one),
        .tau_x => p.proof.tau_x = scalar.add(p.proof.tau_x, one),
        .mu => p.proof.mu = scalar.add(p.proof.mu, one),
        .ipa_a => p.proof.ipa.a = scalar.add(p.proof.ipa.a, one),
        .ipa_b => p.proof.ipa.b = scalar.add(p.proof.ipa.b, one),
        .a => p.proof.a = p.proof.a.add(gens.g),
        .s => p.proof.s = p.proof.s.add(gens.g),
        .t1 => p.proof.t1 = p.proof.t1.add(gens.h),
        .t2 => p.proof.t2 = p.proof.t2.add(gens.h),
        .l0 => p.proof.ipa.l_vec[0] = p.proof.ipa.l_vec[0].add(gens.g),
        .r_last => p.proof.ipa.r_vec[p.proof.ipa.r_vec.len - 1] = p.proof.ipa.r_vec[p.proof.ipa.r_vec.len - 1].add(gens.g),
        .commitment => p.commitments[0] = p.commitments[0].add(gens.g),
        .swap_commitments => {
            if (p.commitments.len < 2) return false;
            std.mem.swap(Ristretto255, &p.commitments[0], &p.commitments[1]);
        },
    }
    return true;
}

test "verifyBatch: one forged proof anywhere in the batch fails it — every field, every position" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    var set: [4]Proved = undefined;
    try proveSet(gens, &set);
    defer for (set) |p| p.deinit();

    for (0..set.len) |pos| {
        for (std.enums.values(Tamper)) |which| {
            // Work on a copy of the victim's mutable parts, restore after.
            const saved_proof = set[pos].proof;
            const saved_l = try talloc.dupe(Ristretto255, set[pos].proof.ipa.l_vec);
            defer talloc.free(saved_l);
            const saved_r = try talloc.dupe(Ristretto255, set[pos].proof.ipa.r_vec);
            defer talloc.free(saved_r);
            const saved_c = try talloc.dupe(Ristretto255, set[pos].commitments);
            defer talloc.free(saved_c);

            if (applyTamper(&set[pos], which, gens)) {
                try std.testing.expect(!single(gens, set[pos])); // the forgery is real
                try std.testing.expect(!try batch(gens, &set));
                try std.testing.expect(!try batch(gens, set[pos .. pos + 1]));
            }
            const l = set[pos].proof.ipa.l_vec;
            const r = set[pos].proof.ipa.r_vec;
            @memcpy(l, saved_l);
            @memcpy(r, saved_r);
            @memcpy(set[pos].commitments, saved_c);
            set[pos].proof = saved_proof;
            set[pos].proof.ipa.l_vec = l;
            set[pos].proof.ipa.r_vec = r;
        }
        try std.testing.expect(try batch(gens, &set)); // restored
    }
}

test "verifyBatch: a proof against the wrong transcript label or another proof's commitments fails" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    var set: [4]Proved = undefined;
    try proveSet(gens, &set);
    defer for (set) |p| p.deinit();

    // Commitments of proof 0 and 2 (both m = 1) exchanged: each proof is
    // valid, but not for the commitments it is batched with.
    var ts: [2]Transcript = .{ Transcript.init(bp.rangeproof_domain), Transcript.init(bp.rangeproof_domain) };
    var es = [_]bp.BatchEntry{
        .{ .transcript = &ts[0], .commitments = set[2].commitments, .proof = set[0].proof },
        .{ .transcript = &ts[1], .commitments = set[0].commitments, .proof = set[2].proof },
    };
    try std.testing.expect(!try bp.verifyBatch(gens, tio, &es));

    var wrong = Transcript.init("another label");
    var good = Transcript.init(bp.rangeproof_domain);
    var es2 = [_]bp.BatchEntry{
        .{ .transcript = &good, .commitments = set[1].commitments, .proof = set[1].proof },
        .{ .transcript = &wrong, .commitments = set[0].commitments, .proof = set[0].proof },
    };
    try std.testing.expect(!try bp.verifyBatch(gens, tio, &es2));

    // A proof whose IPA round count does not match its commitment count
    // (an m = 4 proof given two commitments) is refused up front.
    var t3 = Transcript.init(bp.rangeproof_domain);
    var es3 = [_]bp.BatchEntry{.{ .transcript = &t3, .commitments = set[3].commitments[0..2], .proof = set[3].proof }};
    try std.testing.expect(!try bp.verifyBatch(gens, tio, &es3));
}

fn hexAlloc(hex: []const u8) ![]u8 {
    const out = try talloc.alloc(u8, hex.len / 2);
    errdefer talloc.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn point(hex: []const u8) !Ristretto255 {
    var b: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, hex);
    return Ristretto255.fromBytes(b);
}

test "verifyBatch: dalek's single and aggregated proofs verify as batches, per width" {
    for ([_]usize{ 8, 16, 32, 64 }) |n| {
        const gens = try Generators.initParties(talloc, n, 8);
        defer gens.deinit(talloc);

        var proofs: std.ArrayList(bp.RangeProof) = .empty;
        defer {
            for (proofs.items) |p| p.deinit(talloc);
            proofs.deinit(talloc);
        }
        var commits: std.ArrayList([]Ristretto255) = .empty;
        defer {
            for (commits.items) |c| talloc.free(c);
            commits.deinit(talloc);
        }
        for (vectors.dalek_proofs) |c| {
            if (c.n != n) continue;
            const bytes = try hexAlloc(c.proof);
            defer talloc.free(bytes);
            try proofs.append(talloc, try bp.RangeProof.fromBytesAlloc(talloc, bytes));
            const vs = try talloc.alloc(Ristretto255, 1);
            vs[0] = try point(c.v);
            try commits.append(talloc, vs);
        }
        for (vectors.dalek_multi_proofs) |c| {
            if (c.n != n) continue;
            const bytes = try hexAlloc(c.proof);
            defer talloc.free(bytes);
            try proofs.append(talloc, try bp.RangeProof.fromBytesAlloc(talloc, bytes));
            const vs = try talloc.alloc(Ristretto255, c.vs.len);
            for (vs, c.vs) |*p, h| p.* = try point(h);
            try commits.append(talloc, vs);
        }
        if (proofs.items.len == 0) continue;

        const ts = try talloc.alloc(Transcript, proofs.items.len);
        defer talloc.free(ts);
        const es = try talloc.alloc(bp.BatchEntry, proofs.items.len);
        defer talloc.free(es);
        for (ts, es, proofs.items, commits.items) |*t, *e, p, c| {
            t.* = Transcript.init(vectors.label);
            e.* = .{ .transcript = t, .commitments = c, .proof = p };
        }
        try std.testing.expect(try bp.verifyBatch(gens, tio, es));
    }
}

test "verifyBatch: an identity L/R, or a proof with fewer IPA rounds than its commitments imply, fails" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    var set: [4]Proved = undefined;
    try proveSet(gens, &set);
    defer for (set) |p| p.deinit();

    // dalek refuses an identity L/R before binding it; so must the batch.
    const saved = set[1].proof.ipa.l_vec[0];
    set[1].proof.ipa.l_vec[0] = bp.scalarvec.identity_point;
    try std.testing.expect(!single(gens, set[1]));
    try std.testing.expect(!try batch(gens, &set));
    set[1].proof.ipa.l_vec[0] = saved;
    try std.testing.expect(try batch(gens, &set));

    // An m = 1 proof (3 rounds at n = 8) presented with two commitments
    // (which imply 4): the shape check must refuse it before the replay
    // reads a fourth L/R that is not there.
    const two = [_]Ristretto255{ set[0].commitments[0], set[2].commitments[0] };
    var t = Transcript.init(bp.rangeproof_domain);
    var es = [_]bp.BatchEntry{.{ .transcript = &t, .commitments = &two, .proof = set[0].proof }};
    try std.testing.expect(!try bp.verifyBatch(gens, tio, &es));
}

test "verifyBatch: every entry draws two fresh random weights" {
    // The weights are the batch's soundness: fixed ones would let a prover
    // build forgeries that cancel across proofs. No verdict can show that,
    // so the draws themselves are checked (`test_randoms` records every
    // scalar the module's `randomScalar` returns in test builds).
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    var set: [4]Proved = undefined;
    try proveSet(gens, &set);
    defer for (set) |p| p.deinit();

    const rp = @import("rangeproof.zig");
    rp.test_random_count = 0;
    try std.testing.expect(try batch(gens, &set));
    try std.testing.expectEqual(@as(usize, 2 * set.len), rp.test_random_count);
    const drawn = rp.test_randoms[0..rp.test_random_count];
    for (drawn, 0..) |a, i| {
        try std.testing.expect(!std.mem.eql(u8, &a, &bp.scalarvec.zero));
        try std.testing.expect(!std.mem.eql(u8, &a, &bp.scalarvec.one));
        for (drawn[i + 1 ..]) |b| try std.testing.expect(!std.mem.eql(u8, &a, &b));
    }
}

// ── a scripted `Io`: chosen blinding draws, so a proof can carry an identity point ──

/// What `scriptedIo` hands out: draw number `i` (the module asks for one 64-byte
/// buffer per scalar) is all zero when `zero_from <= i < zero_to` or `i` is
/// `zero_also`, else a fixed non-zero pattern that differs per draw.
const Script = struct {
    zero_from: usize = 0,
    zero_to: usize = 0,
    zero_also: usize = std.math.maxInt(usize),
    draws: usize = 0,
};
var script: Script = .{};
var script_vtable: std.Io.VTable = undefined;

fn scriptedRandomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    const i = script.draws;
    script.draws += 1;
    const zero = (i >= script.zero_from and i < script.zero_to) or i == script.zero_also;
    for (buffer, 0..) |*b, k| b.* = if (zero) 0 else @truncate(0x31 +% i *% 7 +% k *% 13);
}

fn scriptedSwapCancelProtection(_: ?*anyopaque, _: std.Io.CancelProtection) std.Io.CancelProtection {
    return .unblocked;
}

fn scriptedIo(s: Script) std.Io {
    script = s;
    script_vtable = std.Io.failing.vtable.*;
    script_vtable.randomSecure = scriptedRandomSecure;
    script_vtable.swapCancelProtection = scriptedSwapCancelProtection;
    return .{ .userdata = null, .vtable = &script_vtable };
}

/// One m = 1, n = 8 proof made with the scripted draws. Draw order in the
/// prover: alpha (0), s_L/s_R pairs (1 .. 2n), rho (2n + 1), tau1, tau2.
fn proveScripted(gens: Generators, s: Script, value: u64) !Proved {
    const gammas = [_][32]u8{gammaFor(3)};
    var vb = @as([32]u8, @splat(0));
    std.mem.writeInt(u64, vb[0..8], value, .little);
    const commitments = try talloc.alloc(Ristretto255, 1);
    errdefer talloc.free(commitments);
    commitments[0] = bp.commit(gens, vb, gammas[0]);
    var t = Transcript.init(bp.rangeproof_domain);
    const proof = try bp.proveMultiple(talloc, scriptedIo(s), gens, &t, &.{value}, &gammas);
    return .{ .proof = proof, .commitments = commitments };
}

fn expectRefused(gens: Generators, p: Proved) !void {
    try std.testing.expect(!single(gens, p));
    try std.testing.expect(!try batch(gens, &.{p}));
}

test "a valid proof that carries an identity S, T_1 or T_2 is refused by verifyMultiple and by verifyBatch (dalek parity)" {
    // The proofs below satisfy both equations — only the identity refusal
    // stands between them and acceptance: an honest prover cannot make one
    // (its blinding is uniform), so the draws are scripted. n = 8: draws
    // 1 ..= 16 are s_L/s_R, 17 is rho, 18/19 are tau1/tau2.
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);

    // Control: the scripted draws alone, all non-zero, give an ordinary proof.
    const ok = try proveScripted(gens, .{}, 77);
    defer ok.deinit();
    try std.testing.expect(single(gens, ok));
    try std.testing.expect(try batch(gens, &.{ok}));

    // s_L = s_R = 0 and rho = 0: S = O, while T_1 = tau1*h and T_2 = tau2*h.
    const s_id = try proveScripted(gens, .{ .zero_from = 1, .zero_to = 18 }, 77);
    defer s_id.deinit();
    try std.testing.expect(s_id.proof.s.equivalent(bp.scalarvec.identity_point));
    try expectRefused(gens, s_id);

    // s = 0 and tau1 = 0: t1 = 0, so T_1 = O; S = rho*h and T_2 = tau2*h.
    const t1_id = try proveScripted(gens, .{ .zero_from = 1, .zero_to = 17, .zero_also = 18 }, 77);
    defer t1_id.deinit();
    try std.testing.expect(t1_id.proof.t1.equivalent(bp.scalarvec.identity_point));
    try expectRefused(gens, t1_id);

    // s = 0 and tau2 = 0: t2 = <s_L, y^n s_R> = 0, so T_2 = O.
    const t2_id = try proveScripted(gens, .{ .zero_from = 1, .zero_to = 17, .zero_also = 19 }, 77);
    defer t2_id.deinit();
    try std.testing.expect(t2_id.proof.t2.equivalent(bp.scalarvec.identity_point));
    try expectRefused(gens, t2_id);
}

test "proveMultiple draws exactly one scalar for alpha, rho, tau1, tau2 and each of s_L/s_R (no draw reused)" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    const rp = @import("rangeproof.zig");
    for ([_]usize{ 1, 2, 4 }) |m| {
        var values: [4]u64 = .{ 1, 2, 3, 4 };
        var gammas: [4][32]u8 = undefined;
        for (&gammas, 0..) |*g, j| g.* = gammaFor(j);
        rp.test_random_count = 0;
        var t = Transcript.init(bp.rangeproof_domain);
        const proof = try bp.proveMultiple(talloc, tio, gens, &t, values[0..m], gammas[0..m]);
        proof.deinit(talloc);
        try std.testing.expectEqual(4 + 2 * 8 * m, rp.test_random_count);
        const drawn = rp.test_randoms[0..rp.test_random_count];
        for (drawn, 0..) |a, i| {
            for (drawn[i + 1 ..]) |b| try std.testing.expect(!std.mem.eql(u8, &a, &b));
        }
    }
}

test "verifyBatch refuses an unusable generator set or width before looking at the entries" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    var set: [4]Proved = undefined;
    try proveSet(gens, &set);
    defer for (set) |p| p.deinit();

    // Empty batch over a good set: true. Over a bad one it is false, not true.
    try std.testing.expect(try bp.verifyBatch(gens, tio, &.{}));
    var bad = gens;
    bad.n = 6; // not a power of two
    try std.testing.expect(!try bp.verifyBatch(bad, tio, &.{}));
    bad = gens;
    bad.g_vec = gens.g_vec[0 .. gens.g_vec.len - 1];
    try std.testing.expect(!try bp.verifyBatch(bad, tio, &.{}));
    bad = gens;
    bad.h_vec = gens.h_vec[0 .. gens.h_vec.len - 1];
    try std.testing.expect(!try bp.verifyBatch(bad, tio, &.{}));
    // A vector pair LONGER than parties * n is refused too (not silently sliced).
    const wide = try Generators.initParties(talloc, 8, 8);
    defer wide.deinit(talloc);
    bad = gens;
    bad.g_vec = wide.g_vec;
    bad.h_vec = wide.h_vec;
    try std.testing.expect(!try bp.verifyBatch(bad, tio, &.{}));
    try std.testing.expect(!single(bad, set[0]));
    try std.testing.expect(!try batch(bad, set[0..1]));
    bad = gens;
    bad.g_vec = wide.g_vec;
    try std.testing.expect(!single(bad, set[0]));
    bad = gens;
    bad.h_vec = wide.h_vec;
    try std.testing.expect(!single(bad, set[0]));

    // An entry with more commitments than the set has parties.
    var few = gens;
    few.parties = 1;
    few.g_vec = gens.g_vec[0..8];
    few.h_vec = gens.h_vec[0..8];
    try std.testing.expect(!try batch(few, set[1..2]));
    // A width that is not a power of two, with a vector pair that matches it.
    const g6 = try Generators.init(talloc, 6);
    defer g6.deinit(talloc);
    try std.testing.expect(!try bp.verifyBatch(g6, tio, &.{}));
    // A commitment count that is not a power of two, behind a proof whose
    // round count fits it (3 * 8 = 24 -> 4 rounds, as the m = 2 proof has).
    const three = [_]Ristretto255{ set[1].commitments[0], set[1].commitments[1], set[2].commitments[0] };
    var t3 = Transcript.init(bp.rangeproof_domain);
    var e3 = [_]bp.BatchEntry{.{ .transcript = &t3, .commitments = &three, .proof = set[1].proof }};
    try std.testing.expect(!try bp.verifyBatch(gens, tio, &e3));

    // A width counter that overflows usize: refused, not a panic.
    var huge = gens;
    huge.n = 8;
    huge.parties = std.math.maxInt(usize) / 2;
    try std.testing.expect(!try bp.verifyBatch(huge, tio, &.{}));
    var t2 = Transcript.init(bp.rangeproof_domain);
    try std.testing.expect(!bp.verifyMultiple(huge, &t2, set[0].commitments, set[0].proof));
}

test "verifyBatch refuses a proof whose L and R vectors differ in length, either way round" {
    const gens = try Generators.initParties(talloc, 8, 4);
    defer gens.deinit(talloc);
    var set: [4]Proved = undefined;
    try proveSet(gens, &set);
    defer for (set) |p| p.deinit();

    var short_l = set[0].proof;
    short_l.ipa.l_vec = set[0].proof.ipa.l_vec[0 .. set[0].proof.ipa.l_vec.len - 1];
    var t1 = Transcript.init(bp.rangeproof_domain);
    var e1 = [_]bp.BatchEntry{.{ .transcript = &t1, .commitments = set[0].commitments, .proof = short_l }};
    try std.testing.expect(!try bp.verifyBatch(gens, tio, &e1));

    var short_r = set[0].proof;
    short_r.ipa.r_vec = set[0].proof.ipa.r_vec[0 .. set[0].proof.ipa.r_vec.len - 1];
    var t2 = Transcript.init(bp.rangeproof_domain);
    var e2 = [_]bp.BatchEntry{.{ .transcript = &t2, .commitments = set[0].commitments, .proof = short_r }};
    try std.testing.expect(!try bp.verifyBatch(gens, tio, &e2));
}

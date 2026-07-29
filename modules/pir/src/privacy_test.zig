// SPDX-License-Identifier: MIT

//! privacy_test — the battery for the property a round-trip test cannot touch:
//! **one server, holding one query share, learns nothing about the index.**
//!
//! This file is deliberately separate from `pir.zig` because its tests are of
//! a different *kind*. Correctness is exact and exhaustive; privacy is not.
//! Read `SPEC.md` §"Privacy — what is and is not established" before trusting
//! anything here, and read the label on each test:
//!
//!   EXACT — a deterministic assertion that holds for every input tried, with
//!           no statistical margin. These are real but *narrow*: each pins one
//!           structural way the share could have leaked and did not.
//!   STAT  — a two-sample statistic over pseudorandom seeds. It has a
//!           measurable detection floor and a calibrated false-positive rate,
//!           and it is accompanied by NEGATIVE CONTROLs that prove it can
//!           reject a share which really does leak. It establishes **nothing
//!           about computational indistinguishability** — the actual security
//!           claim — and is not presented as doing so.
//!
//! The honest summary: the security of this composition is inherited whole
//! from the DPF's hiding property (`fss/SPEC.md`), which rests on the PRG
//! being a PRG. No unit test can establish that. What these tests establish is
//! that **this module does not undo it** — no index-derived byte, length or
//! access pattern escapes into what a single server sees.

const std = @import("std");
const fss = @import("fss");
const pir = @import("pir.zig");
const db_mod = @import("db.zig");

const testing = std.testing;
const Database = db_mod.Database;

/// Deterministic seed pair, so a failure here is permanent rather than a
/// flake. Production `query` calls need fresh CSPRNG seeds; see `pir.zig`.
fn detSeeds(tag: u64) [2]fss.prg.Seed {
    var h: [32]u8 = undefined;
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, tag, .little);
    std.crypto.hash.sha2.Sha256.hash(&buf, &h, .{});
    return .{ h[0..16].*, h[16..32].* };
}

// ── EXACT: structural non-leakage ─────────────────────────────────────────

test "EXACT: a query share's serialized length is a constant, whatever the index" {
    // The first thing a length-based side channel would show up in. It is a
    // compile-time constant here, so this is exact by construction — asserted
    // anyway because "obviously constant" is how length channels get shipped.
    const P = pir.Pir(7, 4);
    const seeds = detSeeds(1);
    for (0..P.domain_size) |i| {
        var buf: [P.share_len]u8 = undefined;
        const shares = try P.query(i, seeds[0], seeds[1]);
        P.shareToBytes(shares[0], &buf);
        P.shareToBytes(shares[1], &buf);
        try testing.expectEqual(@as(usize, 16 + 7 * (16 + 2) + 4), buf.len);
    }
}

test "EXACT: an answer's length depends only on the database geometry" {
    // The other direction: server → client. If the answer's size varied with
    // the retrieved record, a network observer would narrow down the index.
    const P = pir.Pir(5, 8);
    for ([_]usize{ 1, 7, 8, 9, 64 }) |record_len| {
        const expected = P.answerBytesLen(record_len);
        var bytes: [20 * 64]u8 = @splat(0);
        for (&bytes, 0..) |*b, k| b.* = @truncate(k * 31 + 7);
        const database = try Database.init(bytes[0 .. 20 * record_len], record_len);
        var out: [8]P.Word = undefined;
        var wire: [64]u8 = undefined;
        const n_words = P.answerWords(record_len);
        for (0..20) |i| {
            const seeds = detSeeds(@intCast(100 + i));
            const shares = try P.query(i, seeds[0], seeds[1]);
            try P.answer(0, shares[0], database, out[0..n_words]);
            // A buffer sized from the geometry alone must fit every index's
            // answer exactly — no index needs one byte more or fewer.
            try P.answerToBytes(out[0..n_words], wire[0..expected]);
        }
    }
}

test "EXACT: party b's share embeds exactly the caller's seed, for every index" {
    // The 16 root-seed bytes are the largest single chunk of a share. They are
    // a verbatim copy of the caller's randomness — index-independent by
    // construction, and this pins it.
    const P = pir.Pir(6, 4);
    const seeds = detSeeds(2);
    for (0..P.domain_size) |i| {
        const shares = try P.query(i, seeds[0], seeds[1]);
        try testing.expectEqualSlices(u8, &seeds[0], &shares[0].seed);
        try testing.expectEqualSlices(u8, &seeds[1], &shares[1].seed);
    }
}

test "EXACT: the two shares differ ONLY in the root seed — why collusion is fatal" {
    // Not a privacy guarantee; the opposite. The correction words are
    // byte-identical between the two shares, so the ONLY thing a colluding
    // pair needs is the two root seeds, and from those the index falls out
    // immediately (demonstrated below). This is the threat model made
    // executable rather than a caveat in prose.
    const P = pir.Pir(6, 4);
    const seeds = detSeeds(3);
    const target = 41;
    const shares = try P.query(target, seeds[0], seeds[1]);

    var cw0: [P.Dpf.Key.cw_serialized_len]u8 = undefined;
    var cw1: [P.Dpf.Key.cw_serialized_len]u8 = undefined;
    shares[0].serializeCw(&cw0);
    shares[1].serializeCw(&cw1);
    try testing.expectEqualSlices(u8, &cw0, &cw1);

    // And the collusion attack itself, in four lines: hold both shares,
    // evaluate both at every index, add, and the one non-zero sum is the
    // index. No cryptanalysis, no work beyond a full-domain scan.
    var recovered: ?usize = null;
    for (0..P.domain_size) |x| {
        const sum = P.Dpf.eval(0, shares[0], @intCast(x)) +%
            P.Dpf.eval(1, shares[1], @intCast(x));
        if (sum != 0) {
            try testing.expect(recovered == null); // exactly one spike
            recovered = x;
        }
    }
    try testing.expectEqual(@as(?usize, target), recovered);
}

test "EXACT: level-1 control-bit CW parity is index-independent (BGI re-derivation)" {
    // From `fss`'s construction, at level 1 (where both parties' PRG outputs
    // are fixed by the caller's seeds and nothing has diverged yet):
    //     t_cw_l = t0_L ⊕ t1_L ⊕ α_1 ⊕ 1
    //     t_cw_r = t0_R ⊕ t1_R ⊕ α_1
    //     t_cw_l ⊕ t_cw_r = t0_L ⊕ t1_L ⊕ t0_R ⊕ t1_R ⊕ 1     ← α cancels
    // So this parity is *exactly* index-independent, not merely masked. It is
    // the one place in a share where α-independence is a fact rather than a
    // computational assumption, and it is worth pinning because a transcription
    // slip in either formula would break it.
    const P = pir.Pir(6, 4);
    const seeds = detSeeds(4);
    var expected: ?u1 = null;
    for (0..P.domain_size) |i| {
        const shares = try P.query(i, seeds[0], seeds[1]);
        const c = shares[0].cw[0];
        const parity: u1 = c.t_cw_l ^ c.t_cw_r;
        if (expected) |p| {
            try testing.expectEqual(p, parity);
        } else {
            expected = parity;
        }
    }
}

test "EXACT: the level-1 seed CW *does* depend on the top index bit — privacy is computational" {
    // The counterweight to the test above, and the most important honest
    // statement in this file. Hold the seeds fixed and the level-1 seed
    // correction word takes exactly TWO values across the whole domain,
    // partitioned precisely by the top bit of the index. The dependence on the
    // index is real and structural. What hides it is that a server never sees
    // two shares under the same seeds: with fresh seeds each query, `s_cw` is
    // a pseudorandom value the server cannot correlate with anything.
    //
    // Privacy here is therefore COMPUTATIONAL and rests entirely on the PRG.
    // Any test that appeared to show "the share is independent of the index"
    // in an information-theoretic sense would be measuring something else.
    const P = pir.Pir(5, 4);
    const seeds = detSeeds(5);
    var s_cw_top0: ?[16]u8 = null;
    var s_cw_top1: ?[16]u8 = null;
    for (0..P.domain_size) |i| {
        const shares = try P.query(i, seeds[0], seeds[1]);
        const s_cw = shares[0].cw[0].s_cw;
        const top_bit = (i >> (5 - 1)) & 1;
        const slot = if (top_bit == 0) &s_cw_top0 else &s_cw_top1;
        if (slot.*) |prev| {
            try testing.expectEqualSlices(u8, &prev, &s_cw);
        } else {
            slot.* = s_cw;
        }
    }
    // Exactly two values, and they are different.
    try testing.expect(s_cw_top0 != null and s_cw_top1 != null);
    try testing.expect(!std.mem.eql(u8, &s_cw_top0.?, &s_cw_top1.?));
}

// ── STAT: two-sample bit-frequency comparison + negative controls ─────────

/// Samples per index. With `m = 512` the standard deviation of the difference
/// of two independent bit frequencies is `sqrt(2·0.25/512) ≈ 0.031`.
const m: u32 = 512;

/// Rejection threshold on the maximum per-bit frequency gap: `≈ 6.4 σ`. Over
/// the `share_len·8` bit positions compared, the probability that honest
/// shares trip it is on the order of `1e-7` — and the seeds are deterministic,
/// so in practice this test either passes forever or fails forever.
///
/// This threshold is also the statistic's **detection floor**: a leak that
/// shifts no single bit's frequency by more than ~0.20 is invisible to it.
const reject_gap: f64 = 0.20;

const P8 = pir.Pir(8, 4);
const share_bits = P8.share_len * 8;

fn accumulateBits(counts: []u32, bytes: []const u8) void {
    for (bytes, 0..) |byte, i| {
        for (0..8) |k| counts[i * 8 + k] += @as(u32, (byte >> @intCast(k)) & 1);
    }
}

fn maxGap(a: []const u32, b: []const u32) f64 {
    const denom: f64 = @floatFromInt(m);
    var worst: f64 = 0;
    for (a, b) |x, y| {
        const fx: f64 = @as(f64, @floatFromInt(x)) / denom;
        const fy: f64 = @as(f64, @floatFromInt(y)) / denom;
        worst = @max(worst, @abs(fx - fy));
    }
    return worst;
}

/// How the leak, if any, is injected into the serialized share. `.none` is the
/// real thing; the others are deliberately broken shares that exist only to
/// give the statistic teeth.
const Leak = enum { none, whole_index_byte, one_index_bit };

fn sampleCounts(index: usize, stream: u64, leak: Leak, counts: *[share_bits]u32) !void {
    @memset(counts, 0);
    var buf: [P8.share_len]u8 = undefined;
    for (0..m) |t| {
        const seeds = detSeeds(stream *% 1_000_003 +% @as(u64, @intCast(t)));
        const shares = try P8.query(index, seeds[0], seeds[1]);
        P8.shareToBytes(shares[0], &buf);
        switch (leak) {
            .none => {},
            // NEGATIVE CONTROL 1: the index copied verbatim into the share.
            .whole_index_byte => buf[0] = @truncate(index),
            // NEGATIVE CONTROL 2: ONE bit of the index in ONE bit of the
            // share — the subtlest leak this statistic is claimed to catch.
            .one_index_bit => buf[0] = (buf[0] & 0xFE) | @as(u8, @truncate(index & 1)),
        }
        accumulateBits(counts, &buf);
    }
}

test "STAT: a single share's bit distribution does not separate index i from index i'" {
    // The security statement is "the distribution of one share given i is
    // indistinguishable from its distribution given i'". This is the weakest
    // honest shadow of it that fits in a unit test: sample both distributions
    // and check no single bit position's frequency separates them beyond the
    // calibrated threshold. Independent seed streams, so the binomial
    // calibration of `reject_gap` applies as written.
    var counts_a: [share_bits]u32 = undefined;
    var counts_b: [share_bits]u32 = undefined;
    try sampleCounts(0, 1001, .none, &counts_a);
    try sampleCounts(200, 2002, .none, &counts_b);
    const gap = maxGap(&counts_a, &counts_b);
    try testing.expect(gap < reject_gap);

    // A second pair, far apart in the tree (0b00000001 vs 0b11111111) so the
    // α-paths share no internal node below the root.
    try sampleCounts(1, 3003, .none, &counts_a);
    try sampleCounts(255, 4004, .none, &counts_b);
    try testing.expect(maxGap(&counts_a, &counts_b) < reject_gap);

    // A third pair, ADJACENT (0 vs 1): the two α-paths agree at every level
    // but the last, and the indices differ in exactly one bit — the low one.
    // Without this pair the test would be blind to any leak keyed on the
    // index's low bit, because every other pair here differs only in higher
    // bits. Choosing index pairs is part of the statistic, not a detail.
    try sampleCounts(0, 5005, .none, &counts_a);
    try sampleCounts(1, 6006, .none, &counts_b);
    try testing.expect(maxGap(&counts_a, &counts_b) < reject_gap);
}

test "STAT NEGATIVE CONTROL: the same statistic rejects a share that leaks the index" {
    // Without this the test above is worthless: a statistic that never fires
    // proves nothing. Control 1 is a blatant leak; control 2 is a single bit.
    // Both must be rejected by the identical code path and threshold.
    var counts_a: [share_bits]u32 = undefined;
    var counts_b: [share_bits]u32 = undefined;

    try sampleCounts(0, 1001, .whole_index_byte, &counts_a);
    try sampleCounts(255, 2002, .whole_index_byte, &counts_b);
    try testing.expect(maxGap(&counts_a, &counts_b) >= reject_gap);

    try sampleCounts(0, 1001, .one_index_bit, &counts_a);
    try sampleCounts(1, 2002, .one_index_bit, &counts_b);
    try testing.expect(maxGap(&counts_a, &counts_b) >= reject_gap);
}

test "EXACT: which bits of a serialized share are structurally constant" {
    // A census of the encoding, not a privacy proof — but it is what makes the
    // STAT test above interpretable. The control-bit correction words are
    // stored one per BYTE with values 0/1, so seven bits of each such byte are
    // always zero. A blanket "the share looks uniformly random" assertion
    // would fail on exactly those bits, and papering over that with a loose
    // threshold is how a real constant would get missed. So: assert that the
    // never-varying positions are EXACTLY the ones the layout predicts, and
    // that every other position takes both values.
    var seen_zero: [share_bits]bool = @splat(false);
    var seen_one: [share_bits]bool = @splat(false);
    var buf: [P8.share_len]u8 = undefined;
    for (0..256) |t| {
        const seeds = detSeeds(@intCast(90000 + t));
        const shares = try P8.query(t & 0xFF, seeds[0], seeds[1]);
        P8.shareToBytes(shares[0], &buf);
        for (buf, 0..) |byte, i| {
            for (0..8) |k| {
                const pos = i * 8 + k;
                if ((byte >> @intCast(k)) & 1 == 0) seen_zero[pos] = true else seen_one[pos] = true;
            }
        }
    }
    // Layout: seed(16) || per level { s_cw(16), t_cw_l(1), t_cw_r(1) } || cw_final(4)
    for (0..share_bits) |pos| {
        const byte_idx = pos / 8;
        const bit_idx = pos % 8;
        const in_cw_region = byte_idx >= 16 and byte_idx < 16 + 8 * 18;
        const off = if (in_cw_region) (byte_idx - 16) % 18 else 0;
        const is_t_cw_padding = in_cw_region and (off == 16 or off == 17) and bit_idx != 0;
        const varies = seen_zero[pos] and seen_one[pos];
        if (is_t_cw_padding) {
            try testing.expect(!varies and seen_zero[pos]); // always 0
        } else {
            try testing.expect(varies);
        }
    }
}

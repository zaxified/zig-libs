// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11-27 whole-module mutation run: one per guard the
//! run found unpinned. Every expected value is derived from the documented
//! contract (`db.zig` `Error`, the doc comments of `place`, `answerSlicesRange`,
//! `Verified.query`/`reconstruct`), never from running the code.

const std = @import("std");
const root = @import("root.zig");
const testing = std.testing;

fn mutSeed(tag: u64) [16]u8 {
    var h: [32]u8 = undefined;
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, tag, .little);
    std.crypto.hash.sha2.Sha256.hash(&buf, &h, .{});
    return h[0..16].*;
}

// ── cuckoo ────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: cuckoo candidates are keyed by the public seed" {
    const C = root.Cuckoo(8, 3);
    const kws = [_][]const u8{ "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel" };
    const a: [16]u8 = @splat(1);
    const b: [16]u8 = @splat(2);
    for (kws) |k| {
        const ca = C.candidates(&a, k);
        const cb = C.candidates(&b, k);
        try testing.expect(!std.mem.eql(usize, &ca, &cb));
    }
}

test "mutation 2026-11-27: cuckoo places exactly as many keywords as slots when it can" {
    // `keywords.len > slots` is the refusal; `== slots` is a full table, which
    // some seed accepts (place's doc: TableFull only when it cannot place).
    const C = root.Cuckoo(1, 2);
    const kws = [_][]const u8{ "k0", "k1" };
    var table: [C.slots]u32 = undefined;
    var slot_of: [2]usize = undefined;
    var found: usize = 0;
    for (0..256) |s| {
        var seed: [16]u8 = @splat(0);
        seed[0] = @intCast(s);
        C.place(&seed, &kws, &table, &slot_of, 50) catch |e| {
            try testing.expectEqual(error.TableFull, e);
            continue;
        };
        found += 1;
        try testing.expect(slot_of[0] != slot_of[1]);
        try testing.expectEqual(@as(u32, 0), table[slot_of[0]]);
        try testing.expectEqual(@as(u32, 1), table[slot_of[1]]);
    }
    try testing.expect(found > 0);
}

test "mutation 2026-11-27: cuckoo refuses more keywords than slots at once, and gives up after max_kicks" {
    const C = root.Cuckoo(1, 2);
    var table: [C.slots]u32 = undefined;

    // 3 keywords into 2 slots: refused up front, even with an unbounded kick budget
    // (without the refusal the walk would never end).
    const three = [_][]const u8{ "a", "b", "c" };
    var slot3: [3]usize = undefined;
    const seed: [16]u8 = @splat(9);
    try testing.expectError(error.TableFull, C.place(&seed, &three, &table, &slot3, std.math.maxInt(usize)));

    // Two keywords whose candidates are all the same slot cannot both be placed:
    // the walk must stop after exactly its kick budget.
    const two = [_][]const u8{ "k0", "k1" };
    var slot2: [2]usize = undefined;
    var seen = false;
    for (0..2048) |s| {
        var sd: [16]u8 = @splat(0);
        std.mem.writeInt(u16, sd[0..2], @intCast(s), .little);
        const c0 = C.candidates(&sd, two[0]);
        const c1 = C.candidates(&sd, two[1]);
        if (c0[0] != c0[1] or c1[0] != c1[1] or c0[0] != c1[0]) continue;
        seen = true;
        try testing.expectError(error.TableFull, C.place(&sd, &two, &table, &slot2, 10));
        break;
    }
    try testing.expect(seen);
}

test "mutation 2026-11-27: cuckoo max_kicks is the number of evictions allowed per keyword" {
    // place's doc: "up to `max_kicks` evictions per keyword (error.TableFull)".
    // Find a seed where k1's candidates are all the slot k0 took first-fit and
    // k0 has another candidate: with 0 evictions allowed k1 cannot be placed,
    // with 1 it evicts k0 and k0 moves to its other slot.
    const C = root.Cuckoo(2, 2);
    const kws = [_][]const u8{ "k0", "k1" };
    var table: [C.slots]u32 = undefined;
    var slot_of: [2]usize = undefined;
    var seen = false;
    for (0..4096) |s| {
        var sd: [16]u8 = @splat(0);
        std.mem.writeInt(u16, sd[0..2], @intCast(s), .little);
        const c0 = C.candidates(&sd, kws[0]);
        const c1 = C.candidates(&sd, kws[1]);
        if (c0[0] == c0[1] or c1[0] != c0[0] or c1[1] != c0[0]) continue;
        seen = true;
        try testing.expectError(error.TableFull, C.place(&sd, &kws, &table, &slot_of, 0));
        try C.place(&sd, &kws, &table, &slot_of, 1);
        try testing.expectEqual(c0[0], slot_of[1]);
        try testing.expectEqual(c0[1], slot_of[0]);
        try testing.expectEqual(@as(u32, 1), table[c0[0]]);
        try testing.expectEqual(@as(u32, 0), table[c0[1]]);
        break;
    }
    try testing.expect(seen);
}

// ── answerSlices guards ───────────────────────────────────────────────────

test "mutation 2026-11-27: answerSlicesRange refuses a domain that is too small, a wrong out length and a malformed range" {
    const P = root.Pir(2, 4); // domain 4
    const s0 = mutSeed(1);
    const s1 = mutSeed(2);
    var shares: [2]P.Share = undefined;
    try P.query(1, &s0, &s1, &shares);

    const rec = "abcd";
    const four = [_][]const u8{ rec, rec, rec, rec };
    const five = [_][]const u8{ rec, rec, rec, rec, rec };
    var out: [1]P.Word = undefined;

    // exactly the domain size fits, one more does not (Error.DomainTooSmall)
    try P.answerSlices(0, &shares[0], &four, &out);
    try testing.expectError(error.DomainTooSmall, P.answerSlices(0, &shares[0], &five, &out));

    // out must be answerWords(record_len) long, longer is as wrong as shorter
    var two_words: [2]P.Word = undefined;
    try testing.expectError(error.AnswerLengthMismatch, P.answerSlices(0, &shares[0], &four, &two_words));
    try testing.expectError(error.AnswerLengthMismatch, P.answerSlices(0, &shares[0], &four, out[0..0]));

    // InvalidRange: lo > hi, or hi past the records
    try testing.expectError(error.InvalidRange, P.answerSlicesRange(0, &shares[0], &four, 3, 2, &out));
    try testing.expectError(error.InvalidRange, P.answerSlicesRange(0, &shares[0], &four, 0, 5, &out));
    try P.answerSlicesRange(0, &shares[0], &four, 4, 4, &out); // empty range at the end is fine
}

// ── Multi ─────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: Multi.reconstruct and answerAggregate check every length" {
    const P = root.Pir(4, 4);
    const M = P.Multi(3);
    const record_len = 5; // 2 words
    var s0: [3][16]u8 = undefined;
    var s1: [3][16]u8 = undefined;
    for (0..3) |j| {
        s0[j] = mutSeed(10 + j);
        s1[j] = mutSeed(20 + j);
    }
    var shares: [2]M.Share = undefined;
    try M.query(.{ 1, 2, 3 }, &s0, &s1, &shares);
    var bytes: [12 * record_len]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    const db = try root.Database.init(&bytes, record_len);

    const need = try M.answerWords(record_len);
    try testing.expectEqual(@as(usize, 6), need);
    var a0: [7]M.Word = undefined;
    var a1: [7]M.Word = undefined;
    try M.answer(0, &shares[0], db, a0[0..need]);
    try M.answer(1, &shares[1], db, a1[0..need]);
    a0[6] = 0;
    a1[6] = 0;
    var recs: [3 * record_len]u8 = undefined;
    try M.reconstruct(a0[0..need], a1[0..need], record_len, &recs);
    try testing.expectEqualSlices(u8, db.record(1), recs[0..record_len]);
    try testing.expectEqualSlices(u8, db.record(3), recs[2 * record_len ..][0..record_len]);
    // each of the two answers one word too long (a shorter one would trip a bounds check anyway)
    try testing.expectError(error.AnswerLengthMismatch, M.reconstruct(a0[0..7], a1[0..need], record_len, &recs));
    try testing.expectError(error.AnswerLengthMismatch, M.reconstruct(a0[0..need], a1[0..7], record_len, &recs));

    // the aggregate answer is exactly one record's worth of words
    var agg: [3]M.Word = undefined;
    try M.answerAggregate(0, &shares[0], db, agg[0..2]);
    try testing.expectError(error.AnswerLengthMismatch, M.answerAggregate(0, &shares[0], db, &agg));
    try testing.expectError(error.AnswerLengthMismatch, M.answerAggregate(0, &shares[0], db, agg[0..1]));
}

// ── Verified ──────────────────────────────────────────────────────────────

const VV = root.Verified(4, 4, 8);

test "mutation 2026-11-27: Verified.query refuses a repeated seed in every one of the six pairs" {
    var mac: [VV.tag_word_len]u8 = undefined;
    for (&mac, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
    var seeds: [4][16]u8 = undefined;
    for (&seeds, 0..) |*s, i| s.* = mutSeed(100 + i);
    var q: VV.Query = undefined;
    // all distinct: fine
    try VV.query(0, &mac, &seeds[0], &seeds[1], &seeds[2], &seeds[3], &q);
    q.wipe();
    for (0..4) |a| {
        for (a + 1..4) |b| {
            var t = seeds;
            t[b] = t[a];
            try testing.expectError(error.SeedReuse, VV.query(0, &mac, &t[0], &t[1], &t[2], &t[3], &q));
        }
    }
}

test "mutation 2026-11-27: Verified.tagAnswerToBytes needs a buffer of exactly words * tag_word_len" {
    const words = [3]VV.TagWord{ 1, 2, 3 };
    const need = 3 * VV.tag_word_len;
    var buf: [need + 1]u8 = undefined;
    try VV.tagAnswerToBytes(&words, buf[0..need]);
    try testing.expectError(error.AnswerLengthMismatch, VV.tagAnswerToBytes(&words, buf[0 .. need + 1]));
    try testing.expectError(error.AnswerLengthMismatch, VV.tagAnswerToBytes(&words, buf[0 .. need - 1]));
}

test "mutation 2026-11-27: Verified.reconstruct and reconstructFromBytes check the length of each of the four answers" {
    const record_len = 5; // 2 value words, 3 tag words
    var mac: [VV.tag_word_len]u8 = undefined;
    for (&mac, 0..) |*b, i| b.* = @truncate(i *% 11 +% 3);
    var q: VV.Query = undefined;
    try VV.query(4, &mac, &mutSeed(200), &mutSeed(201), &mutSeed(202), &mutSeed(203), &q);
    var bytes: [12 * record_len]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i *% 29 +% 17);
    const db = try root.Database.init(&bytes, record_len);

    var v: [2][3]VV.Word = undefined; // one spare word each
    var t: [2][4]VV.TagWord = undefined;
    for (0..2) |b| {
        v[b] = @splat(0);
        t[b] = @splat(0);
        try VV.answer(@intCast(b), &q.shares[b], db, v[b][0..2], t[b][0..3]);
    }
    var rec: [record_len]u8 = undefined;
    try VV.reconstruct(&q.secret, v[0][0..2], v[1][0..2], t[0][0..3], t[1][0..3], &rec);
    try testing.expectEqualSlices(u8, db.record(4), &rec);

    // one answer too long at a time
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstruct(&q.secret, v[0][0..3], v[1][0..2], t[0][0..3], t[1][0..3], &rec));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstruct(&q.secret, v[0][0..2], v[1][0..3], t[0][0..3], t[1][0..3], &rec));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstruct(&q.secret, v[0][0..2], v[1][0..2], t[0][0..4], t[1][0..3], &rec));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstruct(&q.secret, v[0][0..2], v[1][0..2], t[0][0..3], t[1][0..4], &rec));

    // the serialized twin
    var vb: [2][9]u8 = undefined;
    var tb: [2][4 * VV.tag_word_len]u8 = undefined;
    for (0..2) |b| {
        vb[b] = @splat(0);
        tb[b] = @splat(0);
        try VV.Value.answerToBytes(v[b][0..2], vb[b][0..8]);
        try VV.tagAnswerToBytes(t[b][0..3], tb[b][0 .. 3 * VV.tag_word_len]);
    }
    const tn = 3 * VV.tag_word_len;
    var rec2: [record_len]u8 = undefined;
    try VV.reconstructFromBytes(&q.secret, vb[0][0..8], vb[1][0..8], tb[0][0..tn], tb[1][0..tn], &rec2);
    try testing.expectEqualSlices(u8, db.record(4), &rec2);
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstructFromBytes(&q.secret, vb[0][0..9], vb[1][0..8], tb[0][0..tn], tb[1][0..tn], &rec2));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstructFromBytes(&q.secret, vb[0][0..8], vb[1][0..9], tb[0][0..tn], tb[1][0..tn], &rec2));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstructFromBytes(&q.secret, vb[0][0..8], vb[1][0..8], tb[0][0 .. tn + 1], tb[1][0..tn], &rec2));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstructFromBytes(&q.secret, vb[0][0..8], vb[1][0..8], tb[0][0..tn], tb[1][0 .. tn + 1], &rec2));
}

test "mutation 2026-11-27: a mis-sized value answer is a length error even when the tags are forged too (shape before content)" {
    // `Value.reconstruct` repeats the value-length check, so the verifier's own
    // check shows only in which error wins for an answer that is both too long
    // and forged: the shape is refused first, the forged tag is never looked at.
    const record_len = 5;
    var mac: [VV.tag_word_len]u8 = undefined;
    for (&mac, 0..) |*b, i| b.* = @truncate(i *% 5 +% 9);
    var q: VV.Query = undefined;
    try VV.query(2, &mac, &mutSeed(300), &mutSeed(301), &mutSeed(302), &mutSeed(303), &q);
    var bytes: [12 * record_len]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i *% 19 +% 23);
    const db = try root.Database.init(&bytes, record_len);

    var v: [2][3]VV.Word = undefined;
    var t: [2][3]VV.TagWord = undefined;
    for (0..2) |b| {
        v[b] = @splat(0);
        try VV.answer(@intCast(b), &q.shares[b], db, v[b][0..2], &t[b]);
    }
    var rec: [record_len]u8 = undefined;
    // forged: server 0's first tag word is off by one
    t[0][0] +%= 1;
    try testing.expectError(error.AnswerRejected, VV.reconstruct(&q.secret, v[0][0..2], v[1][0..2], &t[0], &t[1], &rec));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstruct(&q.secret, v[0][0..3], v[1][0..2], &t[0], &t[1], &rec));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstruct(&q.secret, v[0][0..2], v[1][0..3], &t[0], &t[1], &rec));

    var vb: [2][9]u8 = undefined;
    var tb: [2][3 * VV.tag_word_len]u8 = undefined;
    for (0..2) |b| {
        vb[b] = @splat(0);
        try VV.Value.answerToBytes(v[b][0..2], vb[b][0..8]);
        try VV.tagAnswerToBytes(&t[b], &tb[b]);
    }
    try testing.expectError(error.AnswerRejected, VV.reconstructFromBytes(&q.secret, vb[0][0..8], vb[1][0..8], &tb[0], &tb[1], &rec));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstructFromBytes(&q.secret, vb[0][0..9], vb[1][0..8], &tb[0], &tb[1], &rec));
    try testing.expectError(error.AnswerLengthMismatch, VV.reconstructFromBytes(&q.secret, vb[0][0..8], vb[1][0..9], &tb[0], &tb[1], &rec));
}

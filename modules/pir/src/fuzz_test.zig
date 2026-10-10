// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for pir (added 2026-10-10, the jwt pattern).
//!
//! Driver: `PIR_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `pir-plain`, `pir-multi`, `pir-verified`, `pir-db`.
//! Whole protocol runs over random databases, through the byte codecs:
//!
//!   - an undamaged run reconstructs the database's own record;
//!   - wrong buffer lengths are refused (`ShareLengthMismatch`,
//!     `AnswerLengthMismatch`), never half-served;
//!   - plain PIR is unauthenticated: a damaged share must not panic, and a
//!     flipped octet inside the record region of an answer changes the
//!     reconstructed record;
//!   - verified PIR detects tampering: any flipped octet of either server's
//!     value or tag answer is `AnswerRejected`, and whatever a damaged SHARE
//!     leads to is either rejected or the correct record, never a wrong one.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const pir = @import("root.zig");
pub const fuzz_driver = testkit.fuzz.driver;

pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

const P = pir.Pir(4, 4);
const Mu = P.Multi(2);
const V = pir.Verified(4, 4, 8);

const PlainMark = Marker(enum { genuine, share_damaged, answer_flipped, length_refused });
const MultiMark = Marker(enum { genuine, share_damaged, length_refused });
const VerMark = Marker(enum { genuine, flipped_value, flipped_tag, share_damaged_rejected, share_damaged_correct, length_refused, swapped });

fn drawDb(comptime S: type, src: *S, buf: []u8) !struct { db: pir.Database, rlen: usize } {
    const rlen: usize = 1 + src.index(12);
    const count: usize = 1 + src.index(16);
    src.bytes(buf[0 .. rlen * count]);
    return .{ .db = try pir.Database.init(buf[0 .. rlen * count], rlen), .rlen = rlen };
}

pub fn fuzzPlain(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var dbb: [16 * 12]u8 = undefined;
    const d = try drawDb(S, src, &dbb);
    const idx = src.index(d.db.count());
    var s0: P.Seed = undefined;
    var s1: P.Seed = undefined;
    src.bytes(&s0);
    src.bytes(&s1);
    var shares: [2]P.Share = undefined;
    try P.query(idx, &s0, &s1, &shares);

    var wire: [2][P.share_len]u8 = undefined;
    P.shareToBytes(&shares[0], &wire[0]);
    P.shareToBytes(&shares[1], &wire[1]);
    const damage_share = src.valueRangeAtMost(u8, 0, 3) == 0;
    if (damage_share) {
        wire[src.index(2)][src.index(P.share_len)] ^= src.valueRangeAtMost(u8, 1, 255);
        PlainMark.mark(.share_damaged);
    }
    // a wrong-length share buffer is refused
    var tmp: P.Share = undefined;
    if (P.shareFromBytes(&tmp, wire[0][0 .. P.share_len - 1])) |_| return error.ShortShareAccepted else |e| {
        if (e != error.ShareLengthMismatch) return error.UnexpectedError;
    }

    const nwords = P.answerWords(d.rlen);
    var ans: [2][8]P.Word = undefined;
    var ab: [2][32]u8 = undefined;
    const nb = try P.answerBytesLen(d.rlen);
    for (0..2) |b| {
        var sh: P.Share = undefined;
        try P.shareFromBytes(&sh, &wire[b]);
        try P.answer(@intCast(b), &sh, d.db, ans[b][0..nwords]);
        try P.answerToBytes(ans[b][0..nwords], ab[b][0..nb]);
    }
    var flipped_in_record = false;
    if (!damage_share and src.valueRangeAtMost(u8, 0, 3) == 0) {
        const at = src.index(nb);
        ab[src.index(2)][at] ^= src.valueRangeAtMost(u8, 1, 255);
        flipped_in_record = at < d.rlen;
        PlainMark.mark(.answer_flipped);
    }
    // wrong-length answers are refused
    var rec: [12]u8 = undefined;
    if (P.reconstructFromBytes(ab[0][0 .. nb - 1], ab[1][0..nb], rec[0..d.rlen])) |_| return error.ShortAnswerAccepted else |e| {
        if (e != error.AnswerLengthMismatch) return error.UnexpectedError;
        PlainMark.mark(.length_refused);
    }
    try P.reconstructFromBytes(ab[0][0..nb], ab[1][0..nb], rec[0..d.rlen]);
    const truth = d.db.record(idx);
    const same = std.mem.eql(u8, rec[0..d.rlen], truth);
    if (!damage_share and !flipped_in_record) {
        // untouched or flipped past the record: the record is right
        if (!same) return error.GenuineWrongRecord;
        PlainMark.mark(.genuine);
    }
    if (flipped_in_record and same) return error.FlippedOctetUnnoticed;
}

pub fn fuzzMulti(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var dbb: [16 * 12]u8 = undefined;
    const d = try drawDb(S, src, &dbb);
    var idx: [2]usize = undefined;
    for (&idx) |*i| i.* = src.index(d.db.count());
    var s0: [2]P.Seed = undefined;
    var s1: [2]P.Seed = undefined;
    for (&s0) |*s| src.bytes(s);
    for (&s1) |*s| src.bytes(s);
    var shares: [2]Mu.Share = undefined;
    Mu.query(idx, &s0, &s1, &shares) catch |e| {
        if (e != error.SeedReuse and e != error.InvalidIndex and e != error.DomainTooSmall) return e;
        return;
    };
    var wire: [2][Mu.share_len]u8 = undefined;
    Mu.shareToBytes(&shares[0], &wire[0]);
    Mu.shareToBytes(&shares[1], &wire[1]);
    const damaged = src.valueRangeAtMost(u8, 0, 3) == 0;
    if (damaged) {
        wire[src.index(2)][src.index(Mu.share_len)] ^= src.valueRangeAtMost(u8, 1, 255);
        MultiMark.mark(.share_damaged);
    }
    var tmp: Mu.Share = undefined;
    if (Mu.shareFromBytes(&tmp, wire[0][0 .. Mu.share_len - 1])) |_| return error.ShortShareAccepted else |_| {}
    const nwords = try Mu.answerWords(d.rlen);
    const nbytes = try Mu.answerBytesLen(d.rlen);
    var ans: [2][32]Mu.Word = undefined;
    var ab: [2][128]u8 = undefined;
    for (0..2) |b| {
        var sh: Mu.Share = undefined;
        try Mu.shareFromBytes(&sh, &wire[b]);
        try Mu.answer(@intCast(b), &sh, d.db, ans[b][0..nwords]);
        for (ans[b][0..nwords], 0..) |w, j| std.mem.writeInt(u32, ab[b][j * 4 ..][0..4], w, .little);
    }
    var out: [24]u8 = undefined;
    if (Mu.reconstructFromBytes(ab[0][0 .. nbytes - 1], ab[1][0..nbytes], d.rlen, out[0 .. 2 * d.rlen])) |_| return error.ShortAnswerAccepted else |e| {
        if (e != error.AnswerLengthMismatch) return error.UnexpectedError;
        MultiMark.mark(.length_refused);
    }
    try Mu.reconstructFromBytes(ab[0][0..nbytes], ab[1][0..nbytes], d.rlen, out[0 .. 2 * d.rlen]);
    if (!damaged) {
        // The multi-index layer's blocks are reconstructed record by record,
        // except where both points coincide (blocks then each hold the sum).
        if (idx[0] != idx[1]) {
            if (!std.mem.eql(u8, out[0..d.rlen], d.db.record(idx[0])) or !std.mem.eql(u8, out[d.rlen..][0..d.rlen], d.db.record(idx[1]))) return error.GenuineWrongRecord;
        }
        MultiMark.mark(.genuine);
    }
}

pub fn fuzzVerified(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var dbb: [16 * 12]u8 = undefined;
    const d = try drawDb(S, src, &dbb);
    const idx = src.index(d.db.count());
    var mac: [V.tag_word_len]u8 = undefined;
    var seeds: [4]P.Seed = undefined;
    src.bytes(&mac);
    for (&seeds) |*s| src.bytes(s);
    var q: V.Query = undefined;
    try V.query(idx, &mac, &seeds[0], &seeds[1], &seeds[2], &seeds[3], &q);

    var wire: [2][V.share_len]u8 = undefined;
    V.shareToBytes(&q.shares[0], &wire[0]);
    V.shareToBytes(&q.shares[1], &wire[1]);
    const damaged_share = src.valueRangeAtMost(u8, 0, 3) == 0;
    if (damaged_share) wire[src.index(2)][src.index(V.share_len)] ^= src.valueRangeAtMost(u8, 1, 255);
    var tmp: V.Share = undefined;
    if (V.shareFromBytes(&tmp, wire[0][0 .. V.share_len - 1])) |_| return error.ShortShareAccepted else |_| {}

    const vw = P.answerWords(d.rlen);
    const tw = V.tagWords(d.rlen);
    var va: [2][8]V.Word = undefined;
    var ta: [2][9]V.TagWord = undefined;
    var vb: [2][32]u8 = undefined;
    var tb: [2][9 * V.tag_word_len]u8 = undefined;
    const vn = vw * 4;
    const tn = try V.tagBytesLen(d.rlen);
    for (0..2) |b| {
        var sh: V.Share = undefined;
        try V.shareFromBytes(&sh, &wire[b]);
        try V.answer(@intCast(b), &sh, d.db, va[b][0..vw], ta[b][0..tw]);
        try V.Value.answerToBytes(va[b][0..vw], vb[b][0..vn]);
        try V.tagAnswerToBytes(ta[b][0..tw], tb[b][0..tn]);
    }
    var mode: u8 = src.valueRangeAtMost(u8, 0, 4);
    if (damaged_share) mode = 0;
    switch (mode) {
        1 => vb[src.index(2)][src.index(vn)] ^= src.valueRangeAtMost(u8, 1, 255),
        2 => tb[src.index(2)][src.index(tn)] ^= src.valueRangeAtMost(u8, 1, 255),
        3 => { // swap the two servers' answers: still a well-formed pair, and the sum is the same
            std.mem.swap([32]u8, &vb[0], &vb[1]);
            std.mem.swap([9 * V.tag_word_len]u8, &tb[0], &tb[1]);
        },
        else => {},
    }
    var rec: [12]u8 = undefined;
    if (V.reconstructFromBytes(&q.secret, vb[0][0 .. vn - 1], vb[1][0..vn], tb[0][0..tn], tb[1][0..tn], rec[0..d.rlen])) |_| return error.ShortAnswerAccepted else |e| {
        if (e != error.AnswerLengthMismatch) return error.UnexpectedError;
        VerMark.mark(.length_refused);
    }
    const r = V.reconstructFromBytes(&q.secret, vb[0][0..vn], vb[1][0..vn], tb[0][0..tn], tb[1][0..tn], rec[0..d.rlen]);
    const truth = d.db.record(idx);
    if (damaged_share) {
        if (r) |_| {
            if (!std.mem.eql(u8, rec[0..d.rlen], truth)) return error.WrongRecordAccepted;
            VerMark.mark(.share_damaged_correct);
        } else |_| VerMark.mark(.share_damaged_rejected);
        return;
    }
    switch (mode) {
        1, 2 => {
            if (r) |_| return error.TamperedAnswerAccepted else |e| {
                if (e != error.AnswerRejected) return error.UnexpectedError;
            }
            if (mode == 1) VerMark.mark(.flipped_value) else VerMark.mark(.flipped_tag);
        },
        else => {
            try r;
            if (!std.mem.eql(u8, rec[0..d.rlen], truth)) return error.GenuineWrongRecord;
            if (mode == 3) VerMark.mark(.swapped) else VerMark.mark(.genuine);
        },
    }
}

const DbMark = Marker(enum { accepted, zero_len, empty, ragged, bits_ok, bits_empty });

pub fn fuzzDb(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [64]u8 = undefined;
    const n: usize = src.index(buf.len + 1);
    src.bytes(buf[0..n]);
    const rlen: usize = switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => 0,
        1 => src.index(70),
        2 => if (n != 0) n / (1 + src.index(4)) else 1,
        else => @as(usize, src.value(u16)),
    };
    if (pir.Database.init(buf[0..n], rlen)) |db| {
        if (db.count() * db.record_len != n) return error.CountDoesNotCover;
        if (db.count() == 0) return error.EmptyAccepted;
        _ = db.record(db.count() - 1);
        DbMark.mark(.accepted);
    } else |e| switch (e) {
        error.ZeroRecordLen => DbMark.mark(.zero_len),
        error.EmptyDatabase => DbMark.mark(.empty),
        error.RaggedDatabase => DbMark.mark(.ragged),
        else => return error.UnexpectedError,
    }
    const count: usize = if (src.value(bool)) src.value(u16) else @as(usize, src.value(u64) >> @intCast(src.index(64)));
    if (pir.domainBitsFor(count)) |bits| {
        if (bits < 1 or bits > 31 or (@as(u64, 1) << @intCast(bits)) < count) return error.DomainBitsTooSmall;
        DbMark.mark(.bits_ok);
    } else |_| DbMark.mark(.bits_empty);
    _ = pir.wordsPerRecord(rlen, 1 + src.index(8));
}

test "fuzz driver: PIR_FUZZ (plain)" {
    try fuzz_driver.run(fuzzPlain, .{ .prefix = "PIR_FUZZ", .name = "pir-plain" });
}
test "fuzz driver: PIR_FUZZ (multi)" {
    try fuzz_driver.run(fuzzMulti, .{ .prefix = "PIR_FUZZ", .name = "pir-multi" });
}
test "fuzz driver: PIR_FUZZ (verified)" {
    try fuzz_driver.run(fuzzVerified, .{ .prefix = "PIR_FUZZ", .name = "pir-verified" });
}
test "fuzz driver: PIR_FUZZ (db)" {
    try fuzz_driver.run(fuzzDb, .{ .prefix = "PIR_FUZZ", .name = "pir-db" });
}
test "fuzz harness: plain, 300 seeds, reaches every outcome" {
    try PlainMark.reach(fuzzPlain, "pir-plain", 300);
}
test "fuzz harness: multi, 300 seeds, reaches every outcome" {
    try MultiMark.reach(fuzzMulti, "pir-multi", 300);
}
test "fuzz harness: verified, 300 seeds, reaches every outcome" {
    try VerMark.reach(fuzzVerified, "pir-verified", 300);
}
test "fuzz harness: db, 300 seeds, reaches every outcome" {
    try DbMark.reach(fuzzDb, "pir-db", 300);
}

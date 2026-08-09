// SPDX-License-Identifier: MIT

//! db — the non-generic half of the PIR module: the database view a server
//! answers over, the record↔word decomposition the answer arithmetic needs,
//! and the domain-sizing helper a client uses to pick `Pir`'s `domain_bits`.
//!
//! Nothing here is a *storage format*. A `Database` is a borrowed view over
//! bytes the caller already has — it never owns, copies, allocates, opens or
//! parses a file. That is deliberate: PIR's answer computation needs exactly
//! two facts about a database (how many records, and where record `i` starts),
//! and asking for anything more would drag a storage opinion into a module
//! whose whole job is arithmetic. See `SPEC.md` §"Where the library stops".
//!
//! ## Why records are fixed-length
//!
//! The answer is *record-sized*. If records had different lengths, the answer
//! size would have to be the maximum (leaking nothing, but wasteful) or the
//! selected record's length (leaking the record's length, and therefore
//! narrowing which record was selected — a direct privacy break). Fixed
//! length removes the question: pad at ingest, and every answer is the same
//! size no matter which index was queried.

const std = @import("std");

/// Every error this module can return. All but one are length/size
/// disagreements or out-of-range parameters; the exception is
/// `AnswerRejected`, the `Verified` layer's integrity failure (the base
/// protocol still has no verification step — see `SPEC.md`).
pub const Error = error{
    /// a database with no records: there is nothing to retrieve
    EmptyDatabase,
    /// `record_len == 0`: records must be at least one byte
    ZeroRecordLen,
    /// `bytes.len` is not a whole multiple of `record_len`
    RaggedDatabase,
    /// `answerSlices` was handed records of differing lengths
    RaggedRecords,
    /// more records than `2^domain_bits`: the DPF domain cannot address them
    DomainTooSmall,
    /// the requested index is `>= 2^domain_bits`
    IndexOutOfDomain,
    /// a serialized query share was not exactly `share_len` bytes
    ShareLengthMismatch,
    /// an answer buffer's length disagrees with the record/word geometry
    AnswerLengthMismatch,
    /// a multi-index reconstruction buffer is not exactly `k * record_len`
    RecordsLengthMismatch,
    /// two of a multi-index query's `2k` root seeds are byte-identical.
    /// Raised by `fss`'s multi-point Gen, not here: reusing a seed pair across
    /// two of the query's instances makes the shared prefix of the two indices
    /// readable straight out of the correction words. See `fss/mpf.zig`.
    SeedReuse,
    /// more than `2^31` records — beyond the DPF's maximum domain
    DatabaseTooLarge,
    /// the `Verified` layer's integrity check failed: at least one server's
    /// answer is not the honest answer over the two servers' common database
    /// (or the queried index is past the database — see `verify.zig` on why
    /// that case rejects). Detection only: no recovery, no attribution.
    AnswerRejected,
    /// `answerRange`/`answerSlicesRange`'s `[lo, hi)` was malformed: `lo >
    /// hi`, or `hi` past the database's record count. A caller sharding
    /// `[0, count())` by hand cannot produce this from correct arithmetic —
    /// it means the shard boundaries themselves are wrong.
    InvalidRange,
};

/// A borrowed, fixed-record-length view over a database. Both servers MUST
/// hold byte-identical databases (same records, same order, same count):
/// reconstruction cancels the two servers' off-target shares term by term, so
/// a record that differs between them — or a record only one of them has —
/// leaves an uncancelled term and corrupts the answer. See `SPEC.md`.
pub const Database = struct {
    bytes: []const u8,
    record_len: usize,

    /// Validate and take a view. `bytes.len` must be a non-zero multiple of
    /// `record_len`, and `record_len` must be non-zero — checked here so that
    /// `count`/`record` are total functions afterwards (in particular there is
    /// no division by a zero `record_len` anywhere downstream).
    pub fn init(bytes: []const u8, record_len: usize) Error!Database {
        if (record_len == 0) return error.ZeroRecordLen;
        if (bytes.len == 0) return error.EmptyDatabase;
        if (bytes.len % record_len != 0) return error.RaggedDatabase;
        return .{ .bytes = bytes, .record_len = record_len };
    }

    /// number of records
    pub fn count(self: Database) usize {
        return self.bytes.len / self.record_len;
    }

    /// record `i` (asserts `i < count()`; this is the server's own index, not
    /// anything derived from a client's bytes)
    pub fn record(self: Database, i: usize) []const u8 {
        std.debug.assert(i < self.count());
        return self.bytes[i * self.record_len ..][0..self.record_len];
    }
};

/// Smallest DPF domain (in bits) that can address `count` records, clamped to
/// the `Dpf` module's `1..31` range. Use it to pick `Pir`'s `domain_bits`:
/// the domain may be *larger* than the database (the unused tail of the domain
/// is simply never evaluated), never smaller.
pub fn domainBitsFor(count: usize) Error!usize {
    if (count == 0) return error.EmptyDatabase;
    const c: u64 = count;
    var n: usize = 1;
    while (n <= 31) : (n += 1) {
        if (@as(u64, 1) << @intCast(n) >= c) return n;
    }
    return error.DatabaseTooLarge;
}

/// Number of `word_bytes`-sized words a `record_len`-byte record decomposes
/// into (the last word is zero-padded). This is the length of an answer.
/// Written as `q + (r != 0)` rather than `(len + word_bytes - 1) / word_bytes`
/// so it cannot overflow for a `record_len` near `maxInt(usize)`.
pub fn wordsPerRecord(record_len: usize, word_bytes: usize) usize {
    std.debug.assert(word_bytes > 0);
    return record_len / word_bytes + @intFromBool(record_len % word_bytes != 0);
}

// ── tests ─────────────────────────────────────────────────────────────────
// Labelling (CONVENTIONS.md §7 / SPEC.md §"Anchoring"): everything here is a
// SELF property/round-trip test of mechanical geometry. Nothing in this file
// has, or could have, an external anchor.

test "SELF: Database.init validates geometry" {
    const bytes = [_]u8{0} ** 12;
    const db = try Database.init(&bytes, 4);
    try std.testing.expectEqual(@as(usize, 3), db.count());
    try std.testing.expectEqual(@as(usize, 4), db.record(2).len);

    try std.testing.expectError(error.ZeroRecordLen, Database.init(&bytes, 0));
    try std.testing.expectError(error.RaggedDatabase, Database.init(&bytes, 5));
    try std.testing.expectError(error.EmptyDatabase, Database.init(bytes[0..0], 4));
}

test "SELF: Database.record slices the right bytes" {
    const bytes = [_]u8{ 1, 2, 3, 4, 5, 6 };
    const db = try Database.init(&bytes, 2);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, db.record(0));
    try std.testing.expectEqualSlices(u8, &.{ 5, 6 }, db.record(2));
}

test "SELF: domainBitsFor is the smallest sufficient power of two" {
    try std.testing.expectError(error.EmptyDatabase, domainBitsFor(0));
    // A 1-record database still needs a 1-bit domain: Dpf's minimum.
    try std.testing.expectEqual(@as(usize, 1), try domainBitsFor(1));
    try std.testing.expectEqual(@as(usize, 1), try domainBitsFor(2));
    try std.testing.expectEqual(@as(usize, 2), try domainBitsFor(3));
    try std.testing.expectEqual(@as(usize, 2), try domainBitsFor(4));
    try std.testing.expectEqual(@as(usize, 3), try domainBitsFor(5));
    try std.testing.expectEqual(@as(usize, 8), try domainBitsFor(256));
    try std.testing.expectEqual(@as(usize, 9), try domainBitsFor(257));
    try std.testing.expectEqual(@as(usize, 31), try domainBitsFor(1 << 31));
    if (@sizeOf(usize) > 4) {
        try std.testing.expectError(error.DatabaseTooLarge, domainBitsFor((1 << 31) + 1));
    }
}

test "SELF: wordsPerRecord rounds up and cannot overflow" {
    try std.testing.expectEqual(@as(usize, 0), wordsPerRecord(0, 4));
    try std.testing.expectEqual(@as(usize, 1), wordsPerRecord(1, 4));
    try std.testing.expectEqual(@as(usize, 1), wordsPerRecord(4, 4));
    try std.testing.expectEqual(@as(usize, 2), wordsPerRecord(5, 4));
    try std.testing.expectEqual(@as(usize, 9), wordsPerRecord(33, 4));
    // The naive `(len + word_bytes - 1) / word_bytes` would overflow here.
    try std.testing.expectEqual(
        @as(usize, std.math.maxInt(usize) / 4 + 1),
        wordsPerRecord(std.math.maxInt(usize), 4),
    );
}

fn fuzzDatabaseInit(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    // record_len is fully attacker-chosen, INCLUDING 0 (the division-by-zero
    // shape) and values far larger than the buffer.
    const record_len: usize = smith.valueRangeAtMost(u32, 0, 1 << 20);
    const db = Database.init(buf[0..len], record_len) catch return;
    // Every accessor must be total on a Database that init accepted.
    const n = db.count();
    if (n > 0) _ = db.record(n - 1);
    _ = try domainBitsFor(n);
    _ = wordsPerRecord(db.record_len, 4);
}
test "fuzz Database.init never panics" {
    try std.testing.fuzz({}, fuzzDatabaseInit, .{});
}

fn fuzzDomainBitsFor(_: void, smith: *std.testing.Smith) !void {
    const count: usize = smith.value(usize);
    _ = domainBitsFor(count) catch return;
}
test "fuzz domainBitsFor never panics" {
    try std.testing.fuzz({}, fuzzDomainBitsFor, .{});
}

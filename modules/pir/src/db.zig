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
/// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
/// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

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

/// Seeds for `fuzzDatabaseInit`, laid out the way its draws read them: a
/// `testkit.fuzz` slice seed carrying the database bytes, then an eight-octet
/// little-endian word carrying `record_len`.
///
/// ⛔ Built here rather than quoted as a literal because nothing about the
/// database CONTENT matters to `init` — only its length, against a
/// `record_len` chosen independently of it. The corpus is therefore a list of
/// geometries, and a geometry cannot be written as a byte string.
const DbCorpus = struct {
    scratch: [256]u8 = undefined,
    store: [4096]u8 = undefined,
    used: usize = 0,
    entries: [9][]const u8 = undefined,
    record_lens: [9]usize = undefined,
    n: usize = 0,

    fn push(self: *DbCorpus, bytes_len: usize, record_len: usize) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], self.scratch[0..bytes_len]);
        std.mem.writeInt(u64, self.store[self.used + head.len ..][0..8], record_len, .little);
        self.entries[self.n] = self.store[self.used..][0 .. head.len + 8];
        self.record_lens[self.n] = record_len;
        self.used += head.len + 8;
        self.n += 1;
    }

    fn build(self: *DbCorpus) []const []const u8 {
        for (&self.scratch, 0..) |*b, i| b.* = @truncate(i);
        // Accepted geometries, chosen so `count()` differs across them — the
        // number the guard pins, and the one an empty input cannot make.
        self.push(64, 8); // 8 records
        self.push(12, 4); // the geometry the value test above uses
        self.push(255, 1); // 255 one-octet records
        self.push(256, 256); // a single record filling the buffer
        self.push(240, 16); // 15 records
        // Refusals, one per branch of `init`.
        self.push(12, 5); // RaggedDatabase
        self.push(0, 4); // EmptyDatabase
        self.push(12, 0); // ZeroRecordLen — and see the harness's comment:
        //                   this is the ONE input the target used to run
        self.push(16, 1 << 20); // record_len far past the buffer: RaggedDatabase
        return self.entries[0..self.n];
    }
};

fn fuzzDatabaseInit(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length: `bytes` eats `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM.
    const len: usize = smith.slice(&buf);
    // record_len is fully attacker-chosen, INCLUDING 0 (the division-by-zero
    // shape) and values far larger than the buffer.
    //
    // ⛔ `smith.value(u64)` and a `%`, not `valueRangeAtMost(u32, 0, 1 << 20)`.
    // A ranged draw placed after the byte draw is the range minimum on every
    // replay, so `record_len` was **0 every time** — `Database.init` returned
    // `ZeroRecordLen` before it looked at anything else, and `count`, `record`,
    // `domainBitsFor` and `wordsPerRecord` below it had never once executed in
    // this harness. Measured 2026-09-07: 0 of 9 seeds accepted before, 5 after.
    const record_len: usize = @intCast(smith.value(u64) % ((1 << 20) + 1));
    const db = Database.init(buf[0..len], record_len) catch return;
    // Every accessor must be total on a Database that init accepted.
    const n = db.count();
    if (n > 0) _ = db.record(n - 1);
    _ = try domainBitsFor(n);
    _ = wordsPerRecord(db.record_len, 4);
}
test "fuzz Database.init never panics" {
    var corpus: DbCorpus = .{};
    try std.testing.fuzz({}, fuzzDatabaseInit, .{ .corpus = corpus.build() });
}

test "corpus: every Database.init seed reaches init, and the counts are pinned" {
    // ⭐ Built from the SAME place the harness builds it. `records` is the
    // second number, the one `accepted` cannot stand in for: `init` refuses
    // every degenerate input here, but a corpus that silently collapsed to the
    // empty seed would still report a consistent-looking `accepted` of 0 — and
    // `records` is what only a seed's own declared geometry can move.
    var corpus: DbCorpus = .{};
    const entries = corpus.build();
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var records: usize = 0;
    var lens_ok: usize = 0;
    for (entries, corpus.record_lens[0..corpus.n]) |sd, want_rl| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const record_len: usize = @intCast(smith.value(u64) % ((1 << 20) + 1));
        if (record_len == want_rl) lens_ok += 1;
        const db = Database.init(buf[0..len], record_len) catch continue;
        accepted += 1;
        records += db.count();
    }
    try std.testing.expectEqual(entries.len - 1, nonempty); // the 0-byte seed
    try std.testing.expectEqual(entries.len, lens_ok);
    try std.testing.expectEqual(@as(usize, 5), accepted);
    try std.testing.expectEqual(@as(usize, 282), records);
}

fn fuzzDomainBitsFor(_: void, smith: *std.testing.Smith) !void {
    const count: usize = smith.value(usize);
    _ = domainBitsFor(count) catch return;
}

/// `smith.value(usize)` reads eight octets straight off the input with no
/// length header, so a seed here is exactly those eight octets — no
/// `testkit.fuzz.seed` wrapper, which would be read as a length and shift
/// everything by four.
///
/// ⚠ The draw was never the problem for this target (a full-width `value` is
/// faithful); the CORPUS was. With none, the lane ran one input for ever — the
/// empty one, i.e. `domainBitsFor(0)`, the single argument that returns before
/// the loop is entered.
/// ⚠ `usize`, not `u64`: `value(usize)` reads `@sizeOf(usize)` octets, so a
/// `u64` seed would be four octets of tail on a 32-bit target and the pinned
/// counts below would be false there rather than failing.
fn dbfSeed(comptime count: usize) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(usize, count));
    }.bytes;
}

const dbf_seeds = [_][]const u8{
    dbfSeed(0), // EmptyDatabase — the only input this target used to run
    dbfSeed(1), // the 1-bit floor
    dbfSeed(2),
    dbfSeed(3), // the first count that rounds up
    dbfSeed(256),
    dbfSeed(257),
    dbfSeed(1 << 31), // the largest addressable domain
    dbfSeed((1 << 31) + 1), // DatabaseTooLarge, one past it
    dbfSeed(std.math.maxInt(usize)),
};

test "fuzz domainBitsFor never panics" {
    try std.testing.fuzz({}, fuzzDomainBitsFor, .{ .corpus = &dbf_seeds });
}

test "corpus: every domainBitsFor seed arrives as written, and the sum is pinned" {
    // The second number is the sum of the domains actually returned: an empty
    // input produces `EmptyDatabase` and contributes nothing, so a sum of 0
    // would mean the corpus never arrived.
    var accepted: usize = 0;
    var bits_total: usize = 0;
    for (dbf_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        const count: usize = smith.value(usize);
        const bits = domainBitsFor(count) catch continue;
        accepted += 1;
        bits_total += bits;
    }
    try std.testing.expectEqual(@as(usize, 6), accepted);
    try std.testing.expectEqual(@as(usize, 52), bits_total);
}

// SPDX-License-Identifier: MIT
//! Collision-free keyword lookup: a cuckoo-hashed sparse database, as the
//! reference's cuckoo-hashed DPF-PIR (google/distributed_point_functions
//! `pir/`: `num_hash_functions` candidate buckets per key, the client queries
//! every candidate). The server operator places each keyword at one of its
//! `h` candidate slots (`place`, offline, over keywords it knows); the client
//! computes the same `h` candidates (`candidates`) and retrieves all of them
//! with `Pir(...).Multi(h)` — unconditionally, so the query shape never
//! depends on where (or whether) the keyword lives. A keyword's record is the
//! one whose own key field matches; a miss is all candidates mismatching.
//!
//! The hash family is public and keyed by a public `seed` the operator
//! publishes with the database (a placement that fails is retried with a new
//! seed, the reference's approach to a full table). Candidates are
//! `SHA-256(seed || i || keyword) mod 2^domain_bits` for `i < h`; two
//! candidates of one keyword may coincide (the query then retrieves that slot
//! twice). Placement is the textbook random walk with a deterministic victim
//! choice (a PRNG keyed by the public seed, never the slot just written):
//! insert at the first free candidate, else evict one occupant and re-insert
//! it, up to
//! `max_kicks` evictions per keyword (`error.TableFull`). No stash (the
//! reference's file listing shows none; inferred, its source not read); at a load below ~0.9 for `h = 3` (~0.5 for
//! `h = 2`) placement succeeds except with small probability, and the
//! operator re-seeds.

const std = @import("std");

pub const Error = error{
    /// `keywords.len` exceeds the slots, or the walk hit `max_kicks`.
    TableFull,
    /// `table.len` is not `2^domain_bits`, or `slot_of.len != keywords.len`.
    BufferLengthMismatch,
};

/// The empty-slot marker in a placement table.
pub const empty: u32 = std.math.maxInt(u32);

pub fn Cuckoo(comptime domain_bits: usize, comptime h: usize) type {
    comptime std.debug.assert(h >= 2 and h <= 255);
    comptime std.debug.assert(domain_bits >= 1 and domain_bits <= 32);
    return struct {
        pub const slots: usize = @as(usize, 1) << domain_bits;
        pub const hash_count = h;

        /// The `h` candidate slots of `keyword` under `seed`.
        pub fn candidates(seed: *const [16]u8, keyword: []const u8) [h]usize {
            var out: [h]usize = undefined;
            for (&out, 0..) |*c, i| {
                var st = std.crypto.hash.sha2.Sha256.init(.{});
                st.update(seed);
                st.update(&[_]u8{@intCast(i)});
                st.update(keyword);
                var d: [32]u8 = undefined;
                st.final(&d);
                c.* = @intCast(std.mem.readInt(u64, d[0..8], .little) & (slots - 1));
            }
            return out;
        }

        /// Place every keyword: `table[s]` becomes the index into `keywords`
        /// of the keyword stored at slot `s` (or `empty`), `slot_of[k]` the
        /// slot of keyword `k`. Duplicate keywords are the caller's to avoid
        /// (two equal keywords take two candidate slots, harmlessly). Server
        /// side, over public keywords; not constant time.
        pub fn place(
            seed: *const [16]u8,
            keywords: []const []const u8,
            table: []u32,
            slot_of: []usize,
            max_kicks: usize,
        ) Error!void {
            if (table.len != slots or slot_of.len != keywords.len) return error.BufferLengthMismatch;
            if (keywords.len > slots or keywords.len >= empty) return error.TableFull;
            @memset(table, empty);
            // The walk's victim choice: a PRNG keyed by the public seed, so a
            // placement is reproducible; never the slot just written.
            var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, seed[0..8], .little));
            const rnd = prng.random();
            for (0..keywords.len) |k0| {
                var cur: u32 = @intCast(k0);
                var kicks: usize = 0;
                var prev: usize = slots; // none
                while (true) {
                    const cand = candidates(seed, keywords[cur]);
                    var placed = false;
                    for (cand) |s| if (table[s] == empty) {
                        table[s] = cur;
                        slot_of[cur] = s;
                        placed = true;
                        break;
                    };
                    if (placed) break;
                    if (kicks == max_kicks) return error.TableFull;
                    var j = rnd.uintLessThan(usize, h);
                    if (cand[j] == prev) j = (j + 1) % h;
                    const s = cand[j];
                    const victim = table[s];
                    table[s] = cur;
                    slot_of[cur] = s;
                    cur = victim;
                    prev = s;
                    kicks += 1;
                }
            }
        }
    };
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const pir = @import("pir.zig");
const db_mod = @import("db.zig");

fn testKeyword(buf: *[12]u8, i: usize) []const u8 {
    return std.fmt.bufPrint(buf, "user-{d}", .{i}) catch unreachable;
}

test "cuckoo: every keyword lands on one of its candidates, no slot holds two" {
    const C = Cuckoo(11, 3);
    const n = 1500; // load 0.73
    var bufs: [n][12]u8 = undefined;
    var kws: [n][]const u8 = undefined;
    for (&kws, 0..) |*k, i| k.* = testKeyword(&bufs[i], i);
    var table: [C.slots]u32 = undefined;
    var slot_of: [n]usize = undefined;
    const seed: [16]u8 = @splat(7);
    try C.place(&seed, &kws, &table, &slot_of, 500);
    var used: usize = 0;
    for (table) |t| if (t != empty) {
        used += 1;
    };
    try testing.expectEqual(@as(usize, n), used);
    for (kws, slot_of, 0..) |k, s, i| {
        try testing.expectEqual(@as(u32, @intCast(i)), table[s]);
        const cand = C.candidates(&seed, k);
        try testing.expect(std.mem.indexOfScalar(usize, &cand, s) != null);
    }
}

test "cuckoo: a table that cannot hold the keywords is TableFull, wrong buffers BufferLengthMismatch" {
    const C = Cuckoo(3, 2);
    var bufs: [9][12]u8 = undefined;
    var kws: [9][]const u8 = undefined;
    for (&kws, 0..) |*k, i| k.* = testKeyword(&bufs[i], i);
    var table: [C.slots]u32 = undefined;
    var slot_of: [9]usize = undefined;
    const seed: [16]u8 = @splat(1);
    try testing.expectError(error.TableFull, C.place(&seed, &kws, &table, &slot_of, 100));
    try testing.expectError(error.BufferLengthMismatch, C.place(&seed, kws[0..2], table[0..4], slot_of[0..2], 10));
    try testing.expectError(error.BufferLengthMismatch, C.place(&seed, kws[0..2], &table, slot_of[0..1], 10));
}

test "cuckoo: end to end, a keyword retrieved through Multi(h) over its candidates; a miss matches no candidate" {
    const bits = 8;
    const h = 3;
    const C = Cuckoo(bits, h);
    const M = pir.Pir(bits, 4).Multi(h);
    const n = 150;
    const record_len = 16; // 12-byte key field + 4-byte value
    var bufs: [n][12]u8 = undefined;
    var kws: [n][]const u8 = undefined;
    for (&kws, 0..) |*k, i| k.* = testKeyword(&bufs[i], i);
    var table: [C.slots]u32 = undefined;
    var slot_of: [n]usize = undefined;
    const seed: [16]u8 = @splat(0x3c);
    try C.place(&seed, &kws, &table, &slot_of, 300);

    // The database: slot s holds (keyword padded to 12, value = index + 1).
    var bytes: [C.slots * record_len]u8 = @splat(0);
    for (table, 0..) |t, s| if (t != empty) {
        const r = bytes[s * record_len ..][0..record_len];
        @memcpy(r[0..kws[t].len], kws[t]);
        std.mem.writeInt(u32, r[12..16], t + 1, .little);
    };
    const database = try db_mod.Database.init(&bytes, record_len);
    const n_words = try M.answerWords(record_len);
    var a0: [h * 4]M.Word = undefined;
    var a1: [h * 4]M.Word = undefined;
    var got: [h * record_len]u8 = undefined;

    for ([_]usize{ 0, 17, 149 }) |want| {
        const cand = C.candidates(&seed, kws[want]);
        var s0: [h]M.Seed = undefined;
        var s1: [h]M.Seed = undefined;
        for (0..h) |j| {
            s0[j] = @splat(@intCast(want + 10 * j + 1));
            s1[j] = @splat(@intCast(want + 10 * j + 2));
        }
        var shares: [2]M.Share = undefined;
        try M.query(cand, &s0, &s1, &shares);
        try M.answer(0, &shares[0], database, a0[0..n_words]);
        try M.answer(1, &shares[1], database, a1[0..n_words]);
        try M.reconstruct(a0[0..n_words], a1[0..n_words], record_len, &got);
        var hits: usize = 0;
        for (0..h) |j| {
            const r = got[j * record_len ..][0..record_len];
            if (std.mem.eql(u8, r[0..kws[want].len], kws[want]) and r[kws[want].len] == 0) {
                hits += 1;
                try testing.expectEqual(@as(u32, @intCast(want + 1)), std.mem.readInt(u32, r[12..16], .little));
            }
        }
        try testing.expect(hits >= 1);
    }
    // A keyword not in the database matches none of its candidates.
    const absent = "nobody-here";
    const cand = C.candidates(&seed, absent);
    var s0: [h]M.Seed = @splat(@splat(0x11));
    var s1: [h]M.Seed = @splat(@splat(0x22));
    for (0..h) |j| {
        s0[j][0] = @intCast(j);
        s1[j][0] = @intCast(j + 100);
    }
    var shares: [2]M.Share = undefined;
    try M.query(cand, &s0, &s1, &shares);
    try M.answer(0, &shares[0], database, a0[0..n_words]);
    try M.answer(1, &shares[1], database, a1[0..n_words]);
    try M.reconstruct(a0[0..n_words], a1[0..n_words], record_len, &got);
    for (0..h) |j| try testing.expect(!std.mem.eql(u8, got[j * record_len ..][0..absent.len], absent));
}

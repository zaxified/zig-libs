// SPDX-License-Identifier: MIT

//! trie — a memory-efficient, frozen **prefix index for instant autocomplete**
//! over a large, static string set.
//!
//! The driving consumer is a Czech RÚIAN address search: millions of UTF-8
//! address strings, a user-typed prefix, and a sub-millisecond "top-N
//! completions" answer. The module is general: build an index from
//! `(key, value)` pairs, FREEZE it to a flat, self-describing, versioned,
//! little-endian byte buffer, then query that buffer **zero-copy** from an
//! mmap'd / read-only slice with no per-query allocation on the exact-lookup
//! path.
//!
//! Query shapes: exact `lookup`, a lexicographic `prefixIterator` and `range`,
//! a ranked `topN` completions helper with an explicit visit **budget** — the
//! DoS guard that stops a one-character prefix from walking millions of keys —
//! and an `after` cursor for the next page, common-prefix search
//! (`prefixesOf` / `longestPrefix`), and rank ↔ key (`ordinal` / `keyAt`).
//!
//! Keys are arbitrary bytes and are compared bytewise. Unicode normalization
//! (NFC/case-folding/diacritic-stripping) is the CALLER's responsibility: to get
//! accent-insensitive matching, fold both the stored keys and the query prefix
//! the same way before handing them to this module. See SPEC.md.
//!
//! Structure: a serialized, path-compressed (format version 2) byte-labelled
//! trie with per-node `subtree_best` (max descendant value) for top-N pruning,
//! written children-first by a streaming builder (`SortedBuilder`). Not
//! minimized into a DAFSA (that is the documented deferred item); chosen for a
//! robust, easily bounds-checkable frozen format over an untrusted buffer. See SPEC.md for the
//! design rationale and the wire format field-by-field.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Prefix index for instant autocomplete over a large static string set.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure logic; the monotonic-clock use is test-only benchmarking
    .role = .util,
    .concurrency = .reentrant, // a frozen buffer is immutable → any number of concurrent readers
    .model_after = "BurntSushi/fst (Rust), Lucene FST",
    .deps = .{},
};

const builder = @import("builder.zig");
const query = @import("query.zig");
const stream = @import("stream.zig");
pub const format = @import("format.zig");

// ── public API ──────────────────────────────────────────────────────────────

pub const Builder = builder.Builder;
pub const Pair = builder.Pair;
pub const freezeFromPairs = builder.freezeFromPairs;
pub const freezeFromPairsWith = builder.freezeFromPairsWith;
pub const FreezeOptions = builder.FreezeOptions;
pub const BuildError = builder.BuildError;
pub const FreezeError = builder.FreezeError;

/// Streaming v2 writer over keys in ascending order; see `stream.zig`.
pub const SortedBuilder = stream.SortedBuilder;
pub const StreamOptions = stream.Options;
pub const StreamError = stream.Error;

pub const Frozen = query.Frozen;
pub const Completion = query.Completion;
pub const QueryOptions = query.QueryOptions;
pub const TopNStatus = query.TopNStatus;
pub const TopNResult = query.TopNResult;
pub const PrefixIterator = query.PrefixIterator;
pub const KeyIterator = query.KeyIterator;
pub const Range = query.Range;
pub const PrefixesOf = query.PrefixesOf;
pub const LoadError = query.LoadError;
pub const QueryError = query.QueryError;
pub const OrdinalError = query.OrdinalError;
pub const max_depth = query.max_depth;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────────────

test {
    std.testing.refAllDecls(@This());
    _ = @import("format.zig");
    _ = @import("builder.zig");
    _ = @import("query.zig");
    _ = @import("stream.zig");
}

const testing = std.testing;

// ── a naive reference oracle: sorted [](key,value) + binary/linear scan ──────
//
// Deliberately unrelated to the trie internals so the differential test is a
// genuine cross-check. Keys are unique (last-write-wins already applied).

const Oracle = struct {
    keys: [][]const u8,
    vals: []u32,

    /// Build from raw (possibly duplicate) pairs applying last-write-wins, then
    /// sort ascending by key. All storage from `arena`.
    fn build(arena: std.mem.Allocator, pairs: []const Pair) !Oracle {
        var map = std.StringHashMap(u32).init(arena);
        for (pairs) |p| try map.put(p.key, p.value); // last write wins
        const n = map.count();
        var keys = try arena.alloc([]const u8, n);
        var vals = try arena.alloc(u32, n);
        var it = map.iterator();
        var i: usize = 0;
        while (it.next()) |e| : (i += 1) {
            keys[i] = e.key_ptr.*;
            vals[i] = e.value_ptr.*;
        }
        // simple insertion co-sort by key (n is small in tests)
        var a: usize = 1;
        while (a < n) : (a += 1) {
            var b = a;
            while (b > 0 and std.mem.lessThan(u8, keys[b], keys[b - 1])) : (b -= 1) {
                std.mem.swap([]const u8, &keys[b], &keys[b - 1]);
                std.mem.swap(u32, &vals[b], &vals[b - 1]);
            }
        }
        return .{ .keys = keys, .vals = vals };
    }

    fn lookup(self: Oracle, key: []const u8) ?u32 {
        var lo: usize = 0;
        var hi: usize = self.keys.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, self.keys[mid], key)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return self.vals[mid],
            }
        }
        return null;
    }

    fn hasPrefix(key: []const u8, prefix: []const u8) bool {
        return key.len >= prefix.len and std.mem.eql(u8, key[0..prefix.len], prefix);
    }
};

// ── differential harness ─────────────────────────────────────────────────────

fn genKeys(arena: std.mem.Allocator, prng: *std.Random.DefaultPrng, count: usize) ![]Pair {
    const rnd = prng.random();
    // Small alphabet incl. raw bytes of Czech diacritics (bytewise multi-byte).
    const alphabet = [_]u8{ 'a', 'b', 'c', 'd', 0xC4, 0x9B, 0xC5, 0xA1, 0xC5, 0x99, 0xC3, 0xA1 };
    const pairs = try arena.alloc(Pair, count);
    for (pairs) |*p| {
        const len = rnd.intRangeAtMost(usize, 0, 9); // includes empty key
        const k = try arena.alloc(u8, len);
        for (k) |*c| c.* = alphabet[rnd.intRangeLessThan(usize, 0, alphabet.len)];
        p.* = .{ .key = k, .value = rnd.int(u32) };
    }
    return pairs;
}

fn differentialRound(seed: u64, count: usize, fmt: FreezeOptions) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(seed);

    const pairs = try genKeys(arena, &prng, count);
    const oracle = try Oracle.build(arena, pairs);
    const buf = try freezeFromPairsWith(testing.allocator, testing.allocator, pairs, fmt);
    defer testing.allocator.free(buf);
    const f = try Frozen.loadVerified(buf);
    try testing.expectEqual(@as(u64, oracle.keys.len), f.keyCount());

    const rnd = prng.random();

    // 0. ordinals: rank i ↔ oracle.keys[i], both directions.
    if (f.hasOrdinals()) {
        var okb: [64]u8 = undefined;
        for (oracle.keys, oracle.vals, 0..) |k, v, i| {
            try testing.expectEqual(@as(?u32, @intCast(i)), try f.ordinal(k));
            const c = (try f.keyAt(@intCast(i), &okb)).?;
            try testing.expectEqualStrings(k, c.key);
            try testing.expectEqual(v, c.value);
        }
        try testing.expectEqual(@as(?Completion, null), try f.keyAt(@intCast(oracle.keys.len), &okb));
    }
    var kb: [64]u8 = undefined;

    // Probe set: every stored key, random prefixes of them, and random noise.
    var probe: usize = 0;
    while (probe < count * 3) : (probe += 1) {
        const query_key = blk: {
            const pick = rnd.intRangeLessThan(usize, 0, 3);
            if (pick == 0 and oracle.keys.len > 0) {
                break :blk oracle.keys[rnd.intRangeLessThan(usize, 0, oracle.keys.len)];
            } else if (pick == 1 and oracle.keys.len > 0) {
                const key = oracle.keys[rnd.intRangeLessThan(usize, 0, oracle.keys.len)];
                break :blk key[0..rnd.intRangeAtMost(usize, 0, key.len)]; // a prefix
            } else {
                const len = rnd.intRangeAtMost(usize, 0, 5);
                const k = kb[0..len];
                for (k) |*c| c.* = "abcd"[rnd.intRangeLessThan(usize, 0, 4)];
                break :blk k;
            }
        };

        // 1. exact lookup agreement
        try testing.expectEqual(oracle.lookup(query_key), try f.lookup(query_key));

        // 2. prefix set agreement (lexicographic)
        {
            var it = try f.prefixIterator(arena, query_key);
            defer it.deinit();
            var ikb: [64]u8 = undefined;
            var expect_i: usize = 0;
            // walk oracle keys in order, matching those with the prefix
            for (oracle.keys, oracle.vals) |ok, ov| {
                if (!Oracle.hasPrefix(ok, query_key)) continue;
                const got = (try it.next(&ikb)) orelse return error.TrieYieldedTooFew;
                try testing.expectEqualStrings(ok, got.key);
                try testing.expectEqual(ov, got.value);
                expect_i += 1;
            }
            try testing.expect((try it.next(&ikb)) == null); // no extras
        }

        // 3. top-N agreement (unbounded budget → must be complete + exact order)
        {
            const N = 6;
            var results: [N]Completion = undefined;
            var tkb: [N * 64]u8 = undefined;
            const r = try f.topN(query_key, &results, &tkb, .{ .max_visited = 0 });
            try testing.expectEqual(TopNStatus.complete, r.status);

            // Oracle top-N: collect matches, sort by (value desc, key asc), take N.
            var mk: std.ArrayList([]const u8) = .empty;
            defer mk.deinit(arena);
            var mv: std.ArrayList(u32) = .empty;
            defer mv.deinit(arena);
            for (oracle.keys, oracle.vals) |ok, ov| {
                if (Oracle.hasPrefix(ok, query_key)) {
                    try mk.append(arena, ok);
                    try mv.append(arena, ov);
                }
            }
            // insertion sort by (value desc, key asc)
            var a: usize = 1;
            while (a < mk.items.len) : (a += 1) {
                var b = a;
                while (b > 0 and rankBefore(mv.items[b], mk.items[b], mv.items[b - 1], mk.items[b - 1])) : (b -= 1) {
                    std.mem.swap([]const u8, &mk.items[b], &mk.items[b - 1]);
                    std.mem.swap(u32, &mv.items[b], &mv.items[b - 1]);
                }
            }
            const want_n = @min(@as(usize, N), mk.items.len);
            try testing.expectEqual(want_n, r.items.len);
            for (0..want_n) |i| {
                try testing.expectEqual(mv.items[i], r.items[i].value);
                try testing.expectEqualStrings(mk.items[i], r.items[i].key);
            }

            // 4. pagination: pages of 3 chained by `after` give the same
            //    ranking, every item exactly once.
            var pres: [3]Completion = undefined;
            var pkb: [3 * 64]u8 = undefined;
            var after: ?Completion = null;
            var got: usize = 0;
            while (true) {
                const page = try f.topN(query_key, &pres, &pkb, .{ .max_visited = 0, .after = after });
                if (page.items.len == 0) break;
                for (page.items) |c| {
                    try testing.expect(got < mk.items.len);
                    try testing.expectEqual(mv.items[got], c.value);
                    try testing.expectEqualStrings(mk.items[got], c.key);
                    got += 1;
                }
                after = page.items[page.items.len - 1];
            }
            try testing.expectEqual(mk.items.len, got);
        }

        // 5. common-prefix search: the oracle keys that are prefixes of the
        //    probe, in sorted order (= by length).
        {
            var it = try f.prefixesOf(query_key);
            for (oracle.keys, oracle.vals) |ok, ov| {
                if (!Oracle.hasPrefix(query_key, ok)) continue;
                const got = (try it.next()) orelse return error.TrieYieldedTooFew;
                try testing.expectEqualStrings(ok, got.key);
                try testing.expectEqual(ov, got.value);
            }
            try testing.expect((try it.next()) == null);
        }

        // 6. range: the probe as one bound, a random key/noise as the other,
        //    random inclusivity; the oracle filters its sorted list.
        {
            const other: []const u8 = if (oracle.keys.len > 0 and rnd.boolean())
                oracle.keys[rnd.intRangeLessThan(usize, 0, oracle.keys.len)]
            else
                "bc"[0..rnd.intRangeAtMost(usize, 0, 2)];
            const swap = rnd.boolean();
            const r: Range = .{
                .lo = if (rnd.intRangeLessThan(u8, 0, 5) == 0) null else if (swap) other else query_key,
                .lo_inclusive = rnd.boolean(),
                .hi = if (rnd.intRangeLessThan(u8, 0, 5) == 0) null else if (swap) query_key else other,
                .hi_inclusive = rnd.boolean(),
            };
            var it = try f.range(arena, r, 0);
            defer it.deinit();
            var rkb: [64]u8 = undefined;
            for (oracle.keys, oracle.vals) |ok, ov| {
                if (r.lo) |lo| switch (std.mem.order(u8, ok, lo)) {
                    .lt => continue,
                    .eq => if (!r.lo_inclusive) continue,
                    .gt => {},
                };
                if (r.hi) |hi| switch (std.mem.order(u8, ok, hi)) {
                    .gt => continue,
                    .eq => if (!r.hi_inclusive) continue,
                    .lt => {},
                };
                const got = (try it.next(&rkb)) orelse return error.TrieYieldedTooFew;
                try testing.expectEqualStrings(ok, got.key);
                try testing.expectEqual(ov, got.value);
            }
            try testing.expect((try it.next(&rkb)) == null);
        }
    }
}

const all_formats = [_]FreezeOptions{ .v1, .{ .v2 = .{} }, .{ .v2 = .{ .ordinals = true } } };

fn rankBefore(av: u32, ak: []const u8, bv: u32, bk: []const u8) bool {
    if (av != bv) return av > bv;
    return std.mem.lessThan(u8, ak, bk);
}

test "differential: real trie vs naive oracle across many random key sets" {
    for (all_formats) |fmt| {
        var seed: u64 = 1;
        while (seed <= 30) : (seed += 1) {
            try differentialRound(seed, 40, fmt);
        }
    }
}

test "differential: adversarial hand-picked key sets" {
    const sets = [_][]const Pair{
        &.{}, // empty index
        &.{.{ .key = "", .value = 7 }}, // only the empty key
        &.{ .{ .key = "a", .value = 1 }, .{ .key = "a", .value = 2 } }, // duplicate → last wins
        &.{ .{ .key = "a", .value = 1 }, .{ .key = "ab", .value = 2 }, .{ .key = "abc", .value = 3 } }, // strict-prefix chain
        &.{ .{ .key = "x", .value = 1 }, .{ .key = "y", .value = 2 }, .{ .key = "z", .value = 3 } }, // single-byte keys
        &.{ .{ .key = "commonprefixA", .value = 1 }, .{ .key = "commonprefixB", .value = 2 }, .{ .key = "commonprefixC", .value = 3 } }, // differ only in final byte
        &.{ .{ .key = "měšťan", .value = 1 }, .{ .key = "město", .value = 2 }, .{ .key = "řeka", .value = 3 } }, // multi-byte Czech UTF-8
    };
    for (all_formats) |fmt| for (sets) |pairs| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const oracle = try Oracle.build(arena, pairs);
        const buf = try freezeFromPairsWith(testing.allocator, testing.allocator, pairs, fmt);
        defer testing.allocator.free(buf);
        const f = try Frozen.load(buf);
        for (oracle.keys, oracle.vals) |k, v|
            try testing.expectEqual(@as(?u32, v), try f.lookup(k));
        // empty prefix returns every key
        var it = try f.prefixIterator(arena, "");
        defer it.deinit();
        var kb: [64]u8 = undefined;
        var i: usize = 0;
        while (try it.next(&kb)) |_| i += 1;
        try testing.expectEqual(oracle.keys.len, i);
    };
}

test "round-trip: pre-freeze answers equal post-freeze answers" {
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    const pairs = [_]Pair{
        .{ .key = "praha", .value = 100 },
        .{ .key = "plzen", .value = 200 },
        .{ .key = "prahasever", .value = 150 },
    };
    for (pairs) |p| try b.insert(p.key, p.value);
    // Freeze twice — the builder must be reusable and deterministic.
    const buf1 = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf1);
    const buf2 = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf2);
    try testing.expectEqualSlices(u8, buf1, buf2);
    const f = try Frozen.load(buf1);
    try testing.expectEqual(@as(?u32, 100), try f.lookup("praha"));
    try testing.expectEqual(@as(?u32, 150), try f.lookup("prahasever"));
}

test "large key set crosses the u16 offset boundary (node region > 64 KiB)" {
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    var kbuf: [24]u8 = undefined;
    var i: u32 = 0;
    // ~5000 distinct 12-byte keys → node region well past 65535 bytes, so many
    // child offsets exceed what a u16 could hold; the u32 offsets must still
    // resolve. (This index uses a single u32 offset width, no tiers.)
    while (i < 5000) : (i += 1) {
        const k = try std.fmt.bufPrint(&kbuf, "addr-{d:0>7}", .{i});
        try b.insert(k, i);
    }
    const buf = try b.freezeWith(testing.allocator, .v1);
    defer testing.allocator.free(buf);
    try testing.expect(buf.len > 65535); // node region crossed the boundary
    const f = try Frozen.load(buf);
    // Deep lookups of the first and last keys resolve through high offsets.
    try testing.expectEqual(@as(?u32, 0), try f.lookup("addr-0000000"));
    try testing.expectEqual(@as(?u32, 4999), try f.lookup("addr-0004999"));
}

// ── positive controls: prove the checkers have teeth ─────────────────────────

test "positive control: a corrupted stored value makes the trie DISAGREE with the oracle" {
    const pairs = [_]Pair{
        .{ .key = "alpha", .value = 111 },
        .{ .key = "beta", .value = 222 },
    };
    // Version 1: the walk below decodes v1 nodes by hand.
    const buf = try freezeFromPairsWith(testing.allocator, testing.allocator, &pairs, .v1);
    defer testing.allocator.free(buf);
    // Sanity: a clean index agrees.
    {
        const f = try Frozen.load(buf);
        try testing.expectEqual(@as(?u32, 111), try f.lookup("alpha"));
    }
    // Deliberately corrupt the stored value bytes of some terminal node, then
    // demonstrate the differential comparison we rely on WOULD trip: the value
    // no longer equals the oracle's. (Search for the value 111 little-endian.)
    var mut = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(mut);
    // Walk to the terminal node for "alpha" and corrupt its value field
    // directly (its offset+1..+5), rather than searching for the value bytes —
    // which also appear in ancestors' subtree_best fields.
    var node = try format.nodeAt(mut, format.header_size);
    for ("alpha") |c| node = try format.follow(node, node.findEdge(c).?.child);
    try testing.expect(node.terminal);
    mut[node.offset + 1] = 99; // value low byte: 111 → 99
    const f = try Frozen.load(mut); // structurally still valid (load skips body CRC)
    const got = try f.lookup("alpha");
    try testing.expect(got != null and got.? != 111); // the oracle expects 111 → disagreement caught
    try testing.expectError(error.BodyCorrupt, Frozen.loadVerified(mut)); // and the CRC catches it too
}

// ── frozen-buffer robustness: never panic / OOB / loop on bad input ──────────

test "permanent malformed control: a back-pointing child offset is rejected, not looped" {
    // Hand-build a two-node buffer whose root edge points its child BACK at the
    // root (violating the strictly-increasing invariant) — a cycle a naive
    // walker would loop on forever. The query path must return error.Corrupt.
    const child_node = [_]u8{ 0, 0, 0, 0, 0, 0, 0 }; // non-terminal, best=0, 0 edges
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    // root: non-terminal, best=0, 1 edge labelled 'a' → child_offset = header_size (back-pointer)
    try body.append(testing.allocator, 0); // flags
    try body.appendSlice(testing.allocator, &[_]u8{ 0, 0, 0, 0 }); // best
    try body.appendSlice(testing.allocator, &[_]u8{ 1, 0 }); // edge_count = 1
    try body.append(testing.allocator, 'a'); // label
    try body.appendSlice(testing.allocator, &[_]u8{ format.header_size, 0, 0, 0 }); // child → root (cycle!)
    try body.appendSlice(testing.allocator, &child_node);

    const buf = try testing.allocator.alloc(u8, format.header_size + body.items.len);
    defer testing.allocator.free(buf);
    @memcpy(buf[format.header_size..], body.items);
    const h = format.Header{ .version = format.format_version, .flags = 0, .node_region_len = @intCast(body.items.len), .key_count = 1, .root_offset = format.header_size };
    h.encode(buf, buf[format.header_size..]);

    const f = try Frozen.load(buf); // header is well-formed
    try testing.expectError(error.Corrupt, f.lookup("a")); // cycle rejected, no infinite loop
}

test "truncated buffers of every length load-fail without panic" {
    for (all_formats) |fmt| try truncatedRound(fmt);
}

fn truncatedRound(fmt: FreezeOptions) !void {
    const buf = try freezeFromPairsWith(testing.allocator, testing.allocator, &.{
        .{ .key = "hello", .value = 1 },
        .{ .key = "help", .value = 2 },
    }, fmt);
    defer testing.allocator.free(buf);
    // A v2 buffer is found from its END, so every proper prefix must refuse
    // to load at all (the footer moved); v1 tolerates trailing bytes, so for
    // it the point is only: no panic, no OOB.
    if (fmt == .v2) {
        for (0..buf.len) |n| try testing.expect(Frozen.load(buf[0..n]) catch null == null);
    }
    var len: usize = 0;
    while (len < buf.len) : (len += 1) {
        // Every truncation either fails to load or loads a header but any query
        // stays bounds-checked — the point is simply: no panic, no OOB.
        const f = Frozen.load(buf[0..len]) catch continue;
        var kb: [16]u8 = undefined;
        _ = f.lookup("hello") catch {};
        var results: [3]Completion = undefined;
        var tkb: [3 * 16]u8 = undefined;
        _ = f.topN("h", &results, &tkb, .{}) catch {};
        var it = f.prefixIterator(testing.allocator, "h") catch continue;
        defer it.deinit();
        _ = it.next(&kb) catch {};
    }
}

fn runQueries(f: Frozen) void {
    var kb: [32]u8 = undefined;
    _ = f.lookup("a") catch {};
    _ = f.lookup("abc") catch {};
    // The 2026-10-04 queries, bounded the same way as the walks below.
    _ = f.longestPrefix("prahasever") catch {};
    _ = f.ordinal("praha") catch {};
    for (0..4) |i| _ = f.keyAt(@intCast(i), &kb) catch {};
    if (f.range(testing.allocator, .{ .lo = "p", .hi = "q" }, 1000)) |it_const| {
        var it = it_const;
        defer it.deinit();
        var guard: usize = 0;
        while (guard < 100) : (guard += 1) {
            const got = it.next(&kb) catch break;
            if (got == null) break;
        }
    } else |_| {}
    var results: [4]Completion = undefined;
    var tkb: [4 * 32]u8 = undefined;
    _ = f.topN("", &results, &tkb, .{ .max_visited = 1000 }) catch {};
    _ = f.topN("a", &results, &tkb, .{ .max_visited = 1000 }) catch {};
    var it = f.prefixIterator(testing.allocator, "") catch return;
    defer it.deinit();
    var guard: usize = 0;
    while (guard < 10000) : (guard += 1) {
        const got = it.next(&kb) catch break;
        if (got == null) break;
    }
}

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. See `testkit/src/fuzz.zig` for the hazards it carries.
const testkit = @import("testkit");
const fuzzSeed = testkit.fuzz.seed;

// ⛔ `fuzzRandom` used to fill `buf` with `smith.bytes` and then draw the
// length with `valueRangeAtMost(u16, 0, buf.len)`. A ranged `Smith` draw reads
// EIGHT octets as a little-endian u64 and returns the range MINIMUM when fewer
// remain, so the length was 0 for every input a corpus can carry and
// `Frozen.load` was handed an empty slice — `error.Truncated` before it had
// looked at the magic. With no corpus, that was the only input it ever ran.

/// Whole frozen buffers, in the format the length draw reads. The header is 36
/// octets of little-endian fields with its own CRC over `[0..32)`, so a
/// hand-written header has to carry a correct `header_crc` to get past
/// `Header.load` at all — these were computed with `std.hash.Crc32` and are
/// what makes the structural refusals below (`MalformedRoot`, a lying
/// `node_region_len`) reachable rather than masked by `HeaderCorrupt`.
const random_seeds = [_][]const u8{
    fuzzSeed("ZTR1"), // the magic alone: Truncated
    fuzzSeed("ZTR0" ++ "\x01\x00" ++ "\x02\x01" ++ "\x00" ** 28), // wrong magic
    fuzzSeed("ZTR1" ++ "\x01\x00" ++ "\x02\x01" ++ "\x00" ** 28), // right magic, wrong header CRC
    fuzzSeed("ZTR1\xff\xff\x02\x01\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xff\xbcc^\x00\x00\x00\x00\x00\x00\x00\x00"), // an unsupported version, correctly sealed
    fuzzSeed("ZTR1\x01\x00\x01\x02\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xcf,\xf4\xc5\x00\x00\x00\x00\x00\x00\x00\x00"), // the endian marker byte-swapped, correctly sealed
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xa4\xc5\xbfo"), // node_region_len 4 GiB, correctly sealed: Truncated
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00^;\xaf\xe5\x00\x00\x00\x00\x00\x00\x00\x00"), // root_offset 4 GiB over a real node region: MalformedRoot
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xd6\xa1\x95\x9f"), // node_region_len 0: MalformedRoot
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xf3\x0aS\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), // ⭐ a sealed header over an all-zero node region: LOADS, and every query is then bounds-checked
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xf3\x0aS\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), // ⭐ the same, all-ones node region: an edge_count of 65535 the walk must refuse
    fuzzSeed("\x00" ** 36), // an all-zero header
    fuzzSeed("\xff" ** 64), // all ones
    fuzzSeed(""), // the empty buffer: what the collapsed harness ran, every time
};

fn fuzzRandom(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const f = Frozen.load(buf[0..len]) catch return;
    runQueries(f);
}

test "fuzz: loader + query path never panic on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzRandom, .{ .corpus = &random_seeds });
}

/// What one mutation script asked for, so the corpus guard can measure the
/// damage rather than assert that the harness ran.
const Damage = struct {
    /// Octets whose value actually changed (a flip that writes the byte
    /// already there is not damage).
    changed: usize = 0,
    /// True when the script asked for the header CRC to be recomputed.
    resealed: bool = false,
};

/// ⛔⛔ The two defects this replaces, both measured.
///
/// 1. `flips` came from `smith.valueRangeAtMost(u8, 0, 12)` as the FIRST draw,
///    which returns the range MINIMUM for all but one input word in 2^64. So
///    the flip count was **0** and the harness loaded the pristine buffer on
///    every iteration — 20 000 iterations reported clean with an escaping bug
///    planted in the traversal. Its comment claimed the fuzzer "spends its time
///    past the magic/CRC gate, deep in node traversal"; it spent it re-loading
///    an untouched index.
///
/// 2. ⭐ Even with the count fixed, a blind byte flip is **CRC-gated**. Any
///    octet in `[0..36)` breaks the header CRC over `[0..32)`, so every header
///    mutation comes straight back as `error.HeaderCorrupt` and the traverse
///    this harness exists for is never entered — the harness would measure the
///    rejection path and nothing else. The script therefore carries a RE-SEAL
///    bit: recompute `header_crc` (and optionally `body_crc`) after mutating,
///    which is exactly what an attacker handing over a crafted index does. That
///    is what makes a damaged `root_offset`, `node_region_len` or `key_count`
///    reach the bounds-checked walk instead of dying at the checksum.
///
/// Script layout, one octet each unless noted:
///
///     0      flags: bit0 = re-seal `header_crc`, bit1 = also re-seal `body_crc`
///     1      flip count, modulo 13
///     2..    per flip: offset (2 octets, big-endian, modulo `buf.len`), value
///
/// A short script CYCLES rather than running out; the empty script is the
/// collapsed harness exactly — zero flips, no re-seal.
fn damage(script: []const u8, buf: []u8, out: *Damage) void {
    var s = testkit.fuzz.Cursor{ .bytes = script };
    out.* = .{};
    if (buf.len == 0) return;
    const flags = s.byte();
    const flips: usize = s.byte() % 13;
    var i: usize = 0;
    while (i < flips) : (i += 1) {
        const at: usize = @as(usize, s.word()) % buf.len;
        const v = s.byte();
        if (buf[at] != v) out.changed += 1;
        buf[at] = v;
    }
    if (flags & 1 != 0 and buf.len >= format.header_size) {
        out.resealed = true;
        if (flags & 2 != 0) {
            const region = std.mem.readInt(u32, buf[12..16], .little);
            const end = @min(buf.len, format.header_size + @as(usize, region));
            std.mem.writeInt(u32, buf[28..32], std.hash.Crc32.hash(buf[format.header_size..end]), .little);
        }
        std.mem.writeInt(u32, buf[32..36], std.hash.Crc32.hash(buf[0..32]), .little);
    }
}

const mutated_seeds = [_][]const u8{
    fuzzSeed("\x00\x00"), // no flips, no re-seal: the pristine index — and exactly what the collapsed harness ran
    fuzzSeed("\x01\x01" ++ "\x00\x18\xff"), // root_offset high byte → 0xff, RE-SEALED: MalformedRoot instead of HeaderCorrupt
    fuzzSeed("\x01\x01" ++ "\x00\x0c\xff"), // node_region_len damaged, re-sealed: the length the walk is bounded by
    fuzzSeed("\x01\x01" ++ "\x00\x10\xff"), // key_count damaged, re-sealed
    fuzzSeed("\x01\x02" ++ "\x00\x04\x02"), // version → 2, re-sealed: now read as a v2 buffer, whose footer (the last 24 bytes) fails its CRC — HeaderCorrupt
    fuzzSeed("\x00\x01" ++ "\x00\x18\xff"), // ⭐ the same root_offset flip WITHOUT the re-seal: HeaderCorrupt, the rejection path the old harness could only have measured
    fuzzSeed("\x01\x04" ++ "\x00\x28\xff\x00\x29\xff\x00\x2a\xff\x00\x2b\xff"), // four octets deep in the node region: edge labels and child offsets
    fuzzSeed("\x01\x08" ++ "\x00\x30\x00\x00\x31\x00\x00\x32\x00\x00\x33\x00\x00\x34\xff\x00\x35\xff\x00\x36\xff\x00\x37\xff"), // eight octets of node payload zeroed and maxed
    fuzzSeed("\x03\x04" ++ "\x00\x28\xff\x00\x2c\xff\x00\x30\xff\x00\x34\xff"), // node region damaged with BOTH CRCs re-sealed: `loadVerified` accepts it too
    fuzzSeed("\x01\x0c" ++ "\x00\x24\x01"), // the maximum flip count, cycling over one offset
    fuzzSeed(""), // the empty script: zero flips, no re-seal
};

fn fuzzMutated(base: []const u8, smith: *std.testing.Smith) !void {
    var script: [64]u8 = undefined;
    const n: usize = smith.slice(&script);
    var copy: [1024]u8 = undefined;
    if (base.len > copy.len) return;
    @memcpy(copy[0..base.len], base);
    var d: Damage = .{};
    damage(script[0..n], copy[0..base.len], &d);
    // Both openers: `load` checks the header only, `loadVerified` also walks
    // the node region's CRC, so a script that re-seals only the header takes
    // different branches in the two.
    _ = Frozen.loadVerified(copy[0..base.len]) catch {};
    const f = Frozen.load(copy[0..base.len]) catch return;
    runQueries(f);
}

test "fuzz: mutated-valid-buffer loader + query path never panic" {
    // Version 1: the seed scripts below name v1 header offsets.
    const base = try freezeFromPairsWith(testing.allocator, testing.allocator, &.{
        .{ .key = "praha", .value = 1 },
        .{ .key = "prahasever", .value = 2 },
        .{ .key = "plzen", .value = 3 },
        .{ .key = "brno", .value = 4 },
    }, .v1);
    defer testing.allocator.free(base);
    try std.testing.fuzz(base, fuzzMutated, .{ .corpus = &mutated_seeds });
}

test "corpus: the random buffers reach the loader, and what they get past is pinned" {
    var nonempty: usize = 0;
    var loaded: usize = 0;
    var header_corrupt: usize = 0;
    for (random_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (Frozen.load(buf[0..len])) |_| {
            loaded += 1;
        } else |e| {
            if (e == error.HeaderCorrupt) header_corrupt += 1;
        }
    }
    // One seed is deliberately the empty buffer.
    try testing.expectEqual(random_seeds.len - 1, nonempty);
    // Measured 2026-09-07: both were 0 before the draw was fixed — every
    // iteration handed `Frozen.load` an empty slice and got `Truncated`.
    try testing.expectEqual(@as(usize, 2), loaded);
    try testing.expectEqual(@as(usize, 1), header_corrupt);
}

test "corpus: the mutation scripts actually damage the index, and reach the traverse" {
    // ⭐⭐ Neither "no seed panicked" nor "some seed loaded" is a guard here.
    // The old harness applied ZERO flips, so the pristine index loaded on every
    // iteration and both would have read 100% while nothing was ever mutated.
    // The numbers the empty script cannot produce are the octets actually
    // changed and — the CRC trap — the number of DAMAGED buffers that still got
    // past `Header.load` into the bounds-checked walk.
    const base = try freezeFromPairsWith(testing.allocator, testing.allocator, &.{
        .{ .key = "praha", .value = 1 },
        .{ .key = "prahasever", .value = 2 },
        .{ .key = "plzen", .value = 3 },
        .{ .key = "brno", .value = 4 },
    }, .v1);
    defer testing.allocator.free(base);

    var changed_total: usize = 0;
    var damaged_and_loaded: usize = 0;
    var damaged_and_verified: usize = 0;
    var damaged_and_rejected: usize = 0;
    for (mutated_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [64]u8 = undefined;
        const n: usize = smith.slice(&script);
        var copy: [1024]u8 = undefined;
        @memcpy(copy[0..base.len], base);
        var d: Damage = .{};
        damage(script[0..n], copy[0..base.len], &d);
        changed_total += d.changed;
        if (d.changed == 0) continue;
        if (Frozen.loadVerified(copy[0..base.len])) |_| damaged_and_verified += 1 else |_| {}
        if (Frozen.load(copy[0..base.len])) |f| {
            damaged_and_loaded += 1;
            runQueries(f);
        } else |_| damaged_and_rejected += 1;
    }
    // Measured 2026-09-07: `changed_total` was 0 — the flip count was the
    // first draw and therefore always the range minimum.
    try testing.expectEqual(@as(usize, 23), changed_total);
    // ⭐ The CRC trap, as a number: without the re-seal bit every one of these
    // would land in `damaged_and_rejected` and the traverse would stay unvisited.
    try testing.expectEqual(@as(usize, 5), damaged_and_loaded);
    try testing.expectEqual(@as(usize, 4), damaged_and_rejected);
    try testing.expectEqual(@as(usize, 2), damaged_and_verified);
}

// ── format 2: a deterministic corrupt-buffer sweep ───────────────────────────
//
// The Smith-driven harnesses above are pinned to version-1 offsets. This one
// damages version-2 buffers from a seeded PRNG (never `Smith{ .in = random }`,
// which collapses every ranged draw to its minimum) and RE-SEALS both CRCs on
// most inputs, so the damage reaches the node walk instead of dying at the
// footer check. Reach is measured, not assumed: the counts below are what
// separates "every damaged buffer was rejected at the door" from "the walks
// ran on damaged nodes and stayed in bounds".

fn resealV2(buf: []u8) void {
    if (buf.len < format.v2_front_size + format.v2_footer_size) return;
    const foot = buf[buf.len - format.v2_footer_size ..];
    const region = std.mem.readInt(u32, foot[0..4], .little);
    const end = @min(buf.len - format.v2_footer_size, format.v2_front_size + @as(usize, region));
    if (end >= format.v2_front_size)
        std.mem.writeInt(u32, foot[16..20], std.hash.Crc32.hash(buf[format.v2_front_size..end]), .little);
    var c = std.hash.Crc32.init();
    c.update(buf[0..format.v2_front_size]);
    c.update(foot[0..20]);
    std.mem.writeInt(u32, foot[20..24], c.final(), .little);
}

const SweepReach = struct { loaded: usize = 0, verified: usize = 0, lookups_ok: usize = 0, corrupt: usize = 0 };

fn sweepV2(base: []const u8, seeds: u64, reach: *SweepReach) !void {
    var copy: [4096]u8 = undefined;
    std.debug.assert(base.len <= copy.len);
    var seed: u64 = 0;
    while (seed < seeds) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        @memcpy(copy[0..base.len], base);
        const buf = copy[0..base.len];
        const flips = r.intRangeAtMost(usize, 1, 6);
        for (0..flips) |_| {
            // Mostly node bytes; sometimes the front or the footer.
            const at = r.intRangeLessThan(usize, 0, buf.len);
            buf[at] = switch (r.intRangeLessThan(u8, 0, 4)) {
                0 => 0,
                1 => 0xff,
                2 => buf[at] ^ (@as(u8, 1) << r.intRangeLessThan(u3, 0, 7)),
                else => r.int(u8),
            };
        }
        if (r.intRangeLessThan(u8, 0, 8) != 0) resealV2(buf);
        if (Frozen.loadVerified(buf)) |_| reach.verified += 1 else |_| {}
        const f = Frozen.load(buf) catch continue;
        reach.loaded += 1;
        if (f.lookup("praha")) |_| {
            reach.lookups_ok += 1;
        } else |e| {
            if (e == error.Corrupt) reach.corrupt += 1;
        }
        runQueries(f);
    }
}

test "format 2: seeded corrupt-buffer sweep never panics, and reaches the walk" {
    for ([_]FreezeOptions{ .{ .v2 = .{} }, .{ .v2 = .{ .ordinals = true } } }) |fmt| {
        const base = try freezeFromPairsWith(testing.allocator, testing.allocator, &.{
            .{ .key = "praha", .value = 1 },                                  .{ .key = "prahasever", .value = 2 },
            .{ .key = "plzen", .value = 3 },                                  .{ .key = "brno", .value = 4 },
            .{ .key = "", .value = 5 },                                       .{ .key = "pra", .value = 6 },
            .{ .key = "prague-and-a-long-tail-that-compresses", .value = 7 },
        }, fmt);
        defer testing.allocator.free(base);
        var reach: SweepReach = .{};
        try sweepV2(base, 4000, &reach);
        // Measured 2026-10-04: loaded 2789 / 2941, answered 1893 / 2134,
        // Corrupt 896 / 807 (plain / ordinals). Most damaged
        // buffers load (re-sealed), the walk answers on some and reports
        // Corrupt on others. A harness that only ever hit the CRC check would
        // show loaded ≈ 500 (the unsealed eighth) and corrupt = 0.
        try testing.expect(reach.loaded > 2500);
        try testing.expect(reach.lookups_ok > 1500);
        try testing.expect(reach.corrupt > 600);
    }
}

test "format 2: each load and decode check refuses its own damage" {
    // One targeted damage per check (mutation 2026-10-04: the seeded sweep
    // never asserts WHICH error, so dropping any single check below survived
    // it). Each case re-seals what it does not mean to break.
    const base = try freezeFromPairs(testing.allocator, testing.allocator, &.{
        .{ .key = "ab", .value = 1 }, .{ .key = "ac", .value = 2 },
    });
    defer testing.allocator.free(base);
    // Layout (hand-checked like the stream golden): @12 "ab" leaf (6 bytes),
    // @18 "ac" leaf (6), @24 node "a" (two edges, so not merged; 17 bytes),
    // @41 root (12 bytes); region 41 bytes.
    const h = try format.Header.load(base);
    try testing.expectEqual(@as(u32, 41), h.node_region_len);
    try testing.expectEqual(@as(u32, 41), h.root_offset);
    var buf: [128]u8 = undefined;
    const n = base.len;

    // Footer CRC: one footer byte flipped, NOT re-sealed.
    @memcpy(buf[0..n], base);
    buf[n - 24 + 8] ^= 1; // key_count
    try testing.expectError(error.HeaderCorrupt, Frozen.load(buf[0..n]));

    // Unknown header flag (bit 1), sealed: a feature, not damage.
    @memcpy(buf[0..n], base);
    buf[8] |= 0x02;
    resealV2(buf[0..n]);
    try testing.expectError(error.UnsupportedVersion, Frozen.load(buf[0..n]));

    // One byte more than the footer accounts for, sealed: the region length
    // no longer adds up to the buffer.
    @memcpy(buf[0 .. n - 24], base[0 .. n - 24]);
    buf[n - 24] = 0;
    @memcpy(buf[n - 23 .. n + 1], base[n - 24 ..]);
    resealV2(buf[0 .. n + 1]);
    try testing.expectError(error.Truncated, Frozen.load(buf[0 .. n + 1]));

    // root_offset inside the front header, sealed.
    @memcpy(buf[0..n], base);
    std.mem.writeInt(u32, buf[n - 24 + 4 ..][0..4], 4, .little);
    resealV2(buf[0..n]);
    try testing.expectError(error.MalformedRoot, Frozen.load(buf[0..n]));

    // An unknown NODE flag bit on the root, sealed: loads, then every query
    // that decodes the root refuses.
    @memcpy(buf[0..n], base);
    buf[41] |= 0x04;
    resealV2(buf[0..n]);
    try testing.expectError(error.Corrupt, (try Frozen.load(buf[0..n])).lookup("ab"));

    // Edge labels out of order under node "a" ('c' before 'b'), sealed.
    @memcpy(buf[0..n], base);
    // "a" @24: flags, tail_len, best(4), n-1, then edges at 31 and 36.
    std.mem.swap(u8, &buf[31], &buf[36]);
    resealV2(buf[0..n]);
    try testing.expectError(error.Corrupt, (try Frozen.load(buf[0..n])).lookup("ab"));

    // An edge pointing at its own node (a v2 child must sit strictly BELOW
    // its parent): the root's edge → 41, sealed.
    @memcpy(buf[0..n], base);
    std.mem.writeInt(u32, buf[41 + 8 ..][0..4], 41, .little);
    resealV2(buf[0..n]);
    const f = try Frozen.load(buf[0..n]);
    try testing.expectError(error.Corrupt, f.lookup("ab"));

    // Positive control: the untouched buffer answers.
    try testing.expectEqual(@as(?u32, 1), try (try Frozen.loadVerified(base)).lookup("ab"));
}

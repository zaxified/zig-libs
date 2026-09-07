// SPDX-License-Identifier: MIT

//! fuzzysearch — bounded-edit-distance, typo-tolerant lookup over a large,
//! static string set. The typo-tolerant sibling of the exact-prefix `trie`.
//!
//! Given a query and a maximum edit distance `k`, return the stored keys within
//! OSA (restricted Damerau–Levenshtein) distance `k` of the query, ranked and
//! sub-millisecond over a large static set. The driving consumer is Czech RÚIAN
//! address autocomplete where the user mistypes ("Vaclvske" → "Vaclavske").
//!
//! The index IS a `trie`: `fuzzysearch` builds and freezes a plain `trie` buffer
//! (magic `"ZTR1"`) — it adds no wire bytes of its own. The typo tolerance is a
//! query algorithm (a Levenshtein automaton walked over the trie), not a data
//! format. So the same frozen file serves both exact `trie` completion and this
//! fuzzy search. See `search.zig` for the walk, `distance.zig` for the reference
//! metric, and SPEC.md for the design decision, wire format, and threat model.
//!
//! Keys are arbitrary bytes and edit distance is over BYTES — a multi-byte UTF-8
//! codepoint counts as several byte-edits. Unicode-aware matching (NFC /
//! case-folding / diacritic-stripping) is the CALLER's job: fold both the stored
//! keys and the query the same way before indexing, the same contract as `trie`.

const std = @import("std");
const trie = @import("trie");
const search = @import("search.zig");
const distance = @import("distance.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Bounded-edit-distance typo-tolerant lookup over a static string set — DoS-bounded, the typo-tolerant sibling of `trie`.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure logic; no OS dependency
    .role = .util,
    .concurrency = .reentrant, // a frozen buffer is immutable → concurrent readers, no sync
    .model_after = "Levenshtein automaton over a trie (Hanov); Lucene FuzzyQuery; Schulz–Mihov",
    .deps = .{"trie"},
};

// ── public API ────────────────────────────────────────────────────────────────
//
// Build/freeze is `trie`'s, re-exported: a fuzzysearch index is a trie index.

pub const Builder = trie.Builder;
pub const Pair = trie.Pair;
pub const freezeFromPairs = trie.freezeFromPairs;
pub const BuildError = trie.BuildError;
pub const FreezeError = trie.FreezeError;

pub const Frozen = search.Frozen;
pub const Match = search.Match;
pub const SearchOptions = search.SearchOptions;
pub const SearchResult = search.SearchResult;
pub const SearchStatus = search.SearchStatus;
pub const SearchError = search.SearchError;
pub const LoadError = search.LoadError;
pub const max_query_len = search.max_query_len;
pub const max_depth = search.max_depth;
pub const max_k = search.max_k;

/// The reference OSA (restricted Damerau–Levenshtein) distance over bytes — a
/// public single-pair verification helper (also the differential-test oracle).
pub const osaDistance = distance.osaDistance;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────────────

test {
    std.testing.refAllDecls(@This());
    _ = @import("search.zig");
    _ = @import("distance.zig");
}

const testing = std.testing;

// ── a naive reference oracle: brute-force OSA over every stored key ───────────
//
// Deliberately unrelated to the search's incremental DP-over-trie: it computes
// the full-matrix OSA (distance.zig) against every key, so the differential is a
// genuine cross-check of the pruned automaton walk.

const OracleMatch = struct { distance: u32, value: u32, key: []const u8 };

fn rankBefore(a: OracleMatch, b: OracleMatch) bool {
    if (a.distance != b.distance) return a.distance < b.distance;
    if (a.value != b.value) return a.value > b.value;
    return std.mem.lessThan(u8, a.key, b.key);
}

const Oracle = struct {
    keys: [][]const u8,
    vals: []u32,

    /// Build from raw (possibly duplicate) pairs applying last-write-wins.
    fn build(arena: std.mem.Allocator, pairs: []const Pair) !Oracle {
        var map = std.StringHashMap(u32).init(arena);
        for (pairs) |p| try map.put(p.key, p.value); // last write wins
        const n = map.count();
        const keys = try arena.alloc([]const u8, n);
        const vals = try arena.alloc(u32, n);
        var it = map.iterator();
        var i: usize = 0;
        while (it.next()) |e| : (i += 1) {
            keys[i] = e.key_ptr.*;
            vals[i] = e.value_ptr.*;
        }
        return .{ .keys = keys, .vals = vals };
    }

    /// All matches within `k`, ranked best-first (into `arena`).
    fn matches(self: Oracle, arena: std.mem.Allocator, query: []const u8, k: u8) ![]OracleMatch {
        var list: std.ArrayListUnmanaged(OracleMatch) = .empty;
        for (self.keys, self.vals) |kk, vv| {
            const d = try distance.osaDistance(query, kk);
            if (d <= k) try list.append(arena, .{ .distance = d, .value = vv, .key = kk });
        }
        std.mem.sort(OracleMatch, list.items, {}, struct {
            fn less(_: void, a: OracleMatch, b: OracleMatch) bool {
                return rankBefore(a, b);
            }
        }.less);
        return list.items;
    }
};

// ── differential harness ─────────────────────────────────────────────────────

fn genKeys(arena: std.mem.Allocator, prng: *std.Random.DefaultPrng, count: usize) ![]Pair {
    const rnd = prng.random();
    // Small alphabet incl. raw bytes of Czech diacritics (bytewise multi-byte).
    const alphabet = [_]u8{ 'a', 'b', 'c', 'd', 0xC4, 0x9B, 0xC5, 0xA1, 0xC5, 0x99, 0xC3, 0xA1 };
    const pairs = try arena.alloc(Pair, count);
    for (pairs) |*p| {
        const len = rnd.intRangeAtMost(usize, 0, 8); // includes the empty key
        const key = try arena.alloc(u8, len);
        for (key) |*ch| ch.* = alphabet[rnd.intRangeLessThan(usize, 0, alphabet.len)];
        p.* = .{ .key = key, .value = rnd.int(u32) };
    }
    return pairs;
}

/// Produce a near-miss query by applying up to `edits` random single-byte edits
/// to `base` — the queries that actually exercise the ≤ k matching paths.
fn mutate(arena: std.mem.Allocator, rnd: std.Random, base: []const u8, edits: usize) ![]const u8 {
    const alphabet = "abcd";
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    try buf.appendSlice(arena, base);
    var e: usize = 0;
    while (e < edits) : (e += 1) {
        if (buf.items.len == 0) {
            try buf.append(arena, alphabet[rnd.intRangeLessThan(usize, 0, 4)]);
            continue;
        }
        const pos = rnd.intRangeLessThan(usize, 0, buf.items.len);
        switch (rnd.intRangeLessThan(usize, 0, 4)) {
            0 => buf.items[pos] = alphabet[rnd.intRangeLessThan(usize, 0, 4)], // substitute
            1 => _ = buf.orderedRemove(pos), // delete
            2 => try buf.insert(arena, pos, alphabet[rnd.intRangeLessThan(usize, 0, 4)]), // insert
            else => if (pos + 1 < buf.items.len) { // transpose
                std.mem.swap(u8, &buf.items[pos], &buf.items[pos + 1]);
            },
        }
    }
    return buf.items;
}

fn differentialRound(seed: u64, count: usize) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    const pairs = try genKeys(arena, &prng, count);
    const oracle = try Oracle.build(arena, pairs);
    const buf = try freezeFromPairs(testing.allocator, testing.allocator, pairs);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    try testing.expectEqual(@as(u64, oracle.keys.len), f.keyCount());

    const N = 8;
    var probe: usize = 0;
    while (probe < count * 4) : (probe += 1) {
        // A query: a stored key mutated by a few edits, or random noise.
        const query = blk: {
            if (oracle.keys.len > 0 and rnd.boolean()) {
                const base = oracle.keys[rnd.intRangeLessThan(usize, 0, oracle.keys.len)];
                break :blk try mutate(arena, rnd, base, rnd.intRangeAtMost(usize, 0, 3));
            } else {
                const len = rnd.intRangeAtMost(usize, 0, 6);
                const q = try arena.alloc(u8, len);
                for (q) |*ch| ch.* = "abcd"[rnd.intRangeLessThan(usize, 0, 4)];
                break :blk q;
            }
        };
        const k: u8 = @intCast(rnd.intRangeAtMost(usize, 0, 3));

        var results: [N]Match = undefined;
        var kb: [N * 32]u8 = undefined;
        // Unbounded budget: the returned items must be the exact ranked best-N.
        const r = try f.search(query, k, &results, &kb, .{ .max_visited = 0 });
        try testing.expectEqual(SearchStatus.complete, r.status);

        const want = try oracle.matches(arena, query, k);
        const want_n = @min(@as(usize, N), want.len);
        try testing.expectEqual(want_n, r.items.len);
        for (0..want_n) |i| {
            try testing.expectEqual(want[i].distance, r.items[i].distance);
            try testing.expectEqual(want[i].value, r.items[i].value);
            try testing.expectEqualStrings(want[i].key, r.items[i].key);
        }
        // Every reported match really is within k and at its true OSA distance.
        for (r.items) |it| {
            try testing.expect(it.distance <= k);
            try testing.expectEqual(it.distance, try osaDistance(query, it.key));
        }
    }
}

test "differential: pruned automaton walk vs brute-force OSA over many key sets" {
    var seed: u64 = 1;
    while (seed <= 40) : (seed += 1) {
        try differentialRound(seed, 40);
    }
}

test "differential: adversarial hand-picked key sets and boundary queries" {
    const sets = [_][]const Pair{
        &.{}, // empty index
        &.{.{ .key = "", .value = 7 }}, // only the empty key
        &.{ .{ .key = "a", .value = 1 }, .{ .key = "a", .value = 2 } }, // duplicate → last wins
        &.{ .{ .key = "teh", .value = 1 }, .{ .key = "the", .value = 2 }, .{ .key = "tea", .value = 3 } }, // transposition neighbours
        &.{ .{ .key = "abcd", .value = 1 }, .{ .key = "abxd", .value = 2 }, .{ .key = "abcde", .value = 3 }, .{ .key = "abc", .value = 4 } }, // sub/ins/del at distance 1
        &.{ .{ .key = "měšťan", .value = 1 }, .{ .key = "město", .value = 2 }, .{ .key = "mesto", .value = 3 } }, // multi-byte Czech UTF-8
        &.{ .{ .key = "aaaa", .value = 1 }, .{ .key = "aaab", .value = 2 }, .{ .key = "aaba", .value = 3 }, .{ .key = "abaa", .value = 4 } }, // near-identical cluster
    };
    const queries = [_][]const u8{ "", "a", "the", "abcd", "abx", "město", "mesto", "aaaa", "zzz" };
    for (sets) |pairs| {
        for (queries) |query| {
            var k: u8 = 0;
            while (k <= 4) : (k += 1) {
                var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
                defer arena_state.deinit();
                const arena = arena_state.allocator();
                const oracle = try Oracle.build(arena, pairs);
                const buf = try freezeFromPairs(testing.allocator, testing.allocator, pairs);
                defer testing.allocator.free(buf);
                const f = try Frozen.load(buf);

                var results: [16]Match = undefined;
                var kb: [16 * 16]u8 = undefined;
                const r = try f.search(query, k, &results, &kb, .{ .max_visited = 0 });
                const want = try oracle.matches(arena, query, k);
                const want_n = @min(@as(usize, 16), want.len);
                try testing.expectEqual(want_n, r.items.len);
                for (0..want_n) |i| {
                    try testing.expectEqual(want[i].distance, r.items[i].distance);
                    try testing.expectEqual(want[i].value, r.items[i].value);
                    try testing.expectEqualStrings(want[i].key, r.items[i].key);
                }
            }
        }
    }
}

test "round-trip: build → freeze → load → search equals in-memory brute force" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pairs = [_]Pair{
        .{ .key = "vaclavske", .value = 100 },
        .{ .key = "namesti", .value = 90 },
        .{ .key = "vaclavska", .value = 80 },
        .{ .key = "vodickova", .value = 70 },
    };
    const oracle = try Oracle.build(arena, &pairs);
    const buf = try freezeFromPairs(testing.allocator, testing.allocator, &pairs);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [8]Match = undefined;
    var kb: [8 * 32]u8 = undefined;
    const r = try f.search("vaclvske", 2, &results, &kb, .{ .max_visited = 0 });
    const want = try oracle.matches(arena, "vaclvske", 2);
    try testing.expectEqual(want.len, r.items.len);
    for (want, r.items) |w, got| {
        try testing.expectEqual(w.distance, got.distance);
        try testing.expectEqualStrings(w.key, got.key);
    }
}

// ── positive controls: prove the checkers have teeth ─────────────────────────

test "positive control: a corrupted stored value makes search DISAGREE with the oracle" {
    const pairs = [_]Pair{
        .{ .key = "alpha", .value = 111 },
        .{ .key = "beta", .value = 222 },
    };
    const buf = try freezeFromPairs(testing.allocator, testing.allocator, &pairs);
    defer testing.allocator.free(buf);
    // Clean index agrees with the oracle.
    {
        const f = try Frozen.load(buf);
        var results: [4]Match = undefined;
        var kb: [4 * 16]u8 = undefined;
        const r = try f.search("alpha", 0, &results, &kb, .{});
        try testing.expectEqual(@as(usize, 1), r.items.len);
        try testing.expectEqual(@as(u32, 111), r.items[0].value);
    }
    // Corrupt "alpha"'s terminal value field directly, then show the value the
    // differential compares no longer matches the oracle's 111 — the check bites.
    var mut = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(mut);
    var node = try trie.format.nodeAt(mut, trie.format.header_size);
    for ("alpha") |c| node = try trie.format.follow(node, node.findEdge(c).?.child);
    try testing.expect(node.terminal);
    mut[node.offset + 1] = 99; // value low byte: 111 → 99
    const f = try Frozen.load(mut);
    var results: [4]Match = undefined;
    var kb: [4 * 16]u8 = undefined;
    const r = try f.search("alpha", 0, &results, &kb, .{});
    try testing.expectEqual(@as(usize, 1), r.items.len);
    try testing.expect(r.items[0].value != 111); // oracle expects 111 → disagreement caught
    try testing.expectError(error.BodyCorrupt, Frozen.loadVerified(mut)); // and the CRC catches it
}

// ── frozen-buffer robustness: never panic / OOB / loop on bad input ──────────

test "permanent malformed control: a back-pointing child offset is rejected, not looped" {
    // Hand-build a two-node buffer whose root edge points its child BACK at the
    // root (violating the strictly-increasing invariant) — a cycle a naive walker
    // would loop on forever. The search path must return error.Corrupt.
    const format = trie.format;
    const child_node = [_]u8{ 0, 0, 0, 0, 0, 0, 0 }; // non-terminal, best=0, 0 edges
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(testing.allocator);
    try body.append(testing.allocator, 0); // root flags: non-terminal
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
    var results: [4]Match = undefined;
    var kb: [4 * 16]u8 = undefined;
    try testing.expectError(error.Corrupt, f.search("a", 1, &results, &kb, .{})); // cycle rejected, no loop
}

fn runQueries(f: Frozen) void {
    var results: [4]Match = undefined;
    var kb: [4 * 32]u8 = undefined;
    // Always a bounded budget on untrusted buffers — a crafted DAG could
    // otherwise fan out; the budget caps total work.
    _ = f.search("a", 1, &results, &kb, .{ .max_visited = 2000 }) catch {};
    _ = f.search("", 2, &results, &kb, .{ .max_visited = 2000 }) catch {};
    _ = f.search("abc", 3, &results, &kb, .{ .max_visited = 2000 }) catch {};
}

test "truncated buffers of every length load-fail or search safely, no panic" {
    const buf = try freezeFromPairs(testing.allocator, testing.allocator, &.{
        .{ .key = "hello", .value = 1 },
        .{ .key = "help", .value = 2 },
        .{ .key = "helm", .value = 3 },
    });
    defer testing.allocator.free(buf);
    var len: usize = 0;
    while (len < buf.len) : (len += 1) {
        const f = Frozen.load(buf[0..len]) catch continue;
        runQueries(f);
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

/// Whole frozen buffers, in the format the length draw reads. The wire format
/// is `trie`'s (`"ZTR1"`, a 36-octet header whose `header_crc` covers
/// `[0..32)`), so a hand-written header needs a correct CRC to get past
/// `Header.load` at all — these were computed with `std.hash.Crc32`, which is
/// what makes the structural refusals reachable rather than masked.
const random_seeds = [_][]const u8{
    fuzzSeed("ZTR1"), // the magic alone: Truncated
    fuzzSeed("ZTR0" ++ "\x01\x00" ++ "\x02\x01" ++ "\x00" ** 28), // wrong magic
    fuzzSeed("ZTR1" ++ "\x01\x00" ++ "\x02\x01" ++ "\x00" ** 28), // right magic, wrong header CRC
    fuzzSeed("ZTR1\xff\xff\x02\x01\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xff\xbcc^\x00\x00\x00\x00\x00\x00\x00\x00"), // an unsupported version, correctly sealed
    fuzzSeed("ZTR1\x01\x00\x01\x02\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xcf,\xf4\xc5\x00\x00\x00\x00\x00\x00\x00\x00"), // the endian marker byte-swapped, correctly sealed
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xa4\xc5\xbfo"), // node_region_len 4 GiB, correctly sealed: Truncated
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00^;\xaf\xe5\x00\x00\x00\x00\x00\x00\x00\x00"), // root_offset 4 GiB over a real node region: MalformedRoot
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xf3\x0aS\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), // ⭐ a sealed header over an all-zero node region: LOADS, and the search is then bounds-checked
    fuzzSeed("ZTR1\x01\x00\x02\x01\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\xf3\x0aS\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), // ⭐ the same, all-ones node region: an edge_count of 65535 the walk must refuse
    fuzzSeed("\x00" ** 36), // an all-zero header
    fuzzSeed(""), // the empty buffer: what the collapsed harness ran, every time
};

fn fuzzRandom(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const f = Frozen.load(buf[0..len]) catch return;
    runQueries(f);
}

test "fuzz: loader + search path never panic on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzRandom, .{ .corpus = &random_seeds });
}

/// What one mutation script asked for, so the corpus guard can measure the
/// damage rather than assert that the harness ran.
const Damage = struct {
    changed: usize = 0,
    resealed: bool = false,
};

/// ⛔⛔ Two defects, both measured, both shared with `trie` (whose wire format
/// this is) and with `geoindex`.
///
/// 1. `flips` came from `smith.valueRangeAtMost(u8, 0, 12)` as the FIRST draw,
///    which returns the range MINIMUM for all but one input word in 2^64. The
///    flip count was therefore **0** and the harness re-loaded the pristine
///    index on every iteration, while its comment claimed the fuzzer "spends
///    its time past the magic/CRC gate, deep in node traversal".
///
/// 2. ⭐ Even with the count fixed, a blind byte flip is **CRC-gated**: any
///    octet in `[0..36)` breaks the header CRC over `[0..32)`, so every header
///    mutation returns `error.HeaderCorrupt` and the Levenshtein walk this
///    harness exists for is never entered. The script carries a RE-SEAL bit —
///    recompute `header_crc` (and optionally `body_crc`) after mutating, which
///    is what an attacker shipping a crafted index does.
///
/// Script layout: octet 0 = flags (bit0 re-seal `header_crc`, bit1 also
/// `body_crc`), octet 1 = flip count modulo 13, then per flip an offset (2
/// octets, big-endian, modulo `buf.len`) and a value. A short script CYCLES;
/// the empty script is the collapsed harness exactly.
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
    if (flags & 1 != 0 and buf.len >= trie.format.header_size) {
        out.resealed = true;
        if (flags & 2 != 0) {
            const region = std.mem.readInt(u32, buf[12..16], .little);
            const end = @min(buf.len, trie.format.header_size + @as(usize, region));
            std.mem.writeInt(u32, buf[28..32], std.hash.Crc32.hash(buf[trie.format.header_size..end]), .little);
        }
        std.mem.writeInt(u32, buf[32..36], std.hash.Crc32.hash(buf[0..32]), .little);
    }
}

const mutated_seeds = [_][]const u8{
    fuzzSeed("\x00\x00"), // no flips, no re-seal: the pristine index — what the collapsed harness ran
    fuzzSeed("\x01\x01" ++ "\x00\x18\xff"), // root_offset high byte → 0xff, RE-SEALED: MalformedRoot, not HeaderCorrupt
    fuzzSeed("\x01\x01" ++ "\x00\x0c\xff"), // node_region_len damaged, re-sealed: the bound the walk trusts
    fuzzSeed("\x01\x01" ++ "\x00\x10\xff"), // key_count damaged, re-sealed
    fuzzSeed("\x01\x02" ++ "\x00\x04\x02"), // version → 2, re-sealed: UnsupportedVersion
    fuzzSeed("\x00\x01" ++ "\x00\x18\xff"), // ⭐ the same root_offset flip WITHOUT the re-seal: HeaderCorrupt — all the old harness could ever have measured
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
    _ = Frozen.loadVerified(copy[0..base.len]) catch {};
    const f = Frozen.load(copy[0..base.len]) catch return;
    runQueries(f);
}

test "fuzz: mutated-valid-buffer loader + search path never panic" {
    const base = try freezeFromPairs(testing.allocator, testing.allocator, &.{
        .{ .key = "praha", .value = 1 },
        .{ .key = "prahasever", .value = 2 },
        .{ .key = "plzen", .value = 3 },
        .{ .key = "brno", .value = 4 },
    });
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
        if (Frozen.load(buf[0..len])) |f| {
            loaded += 1;
            runQueries(f);
        } else |e| {
            if (e == error.HeaderCorrupt) header_corrupt += 1;
        }
    }
    try testing.expectEqual(random_seeds.len - 1, nonempty);
    // Measured 2026-09-07: both were 0 before the draw was fixed — the loader
    // was handed an empty slice on every iteration.
    try testing.expectEqual(@as(usize, 2), loaded);
    try testing.expectEqual(@as(usize, 1), header_corrupt);
}

test "corpus: the mutation scripts actually damage the index, and reach the search" {
    // ⭐⭐ Neither "no seed panicked" nor "some seed loaded" is a guard here.
    // The old harness applied ZERO flips, so the pristine index loaded on every
    // iteration and both would have read 100% while nothing was ever mutated.
    // The numbers the empty script cannot produce are the octets actually
    // changed and — the CRC trap — the DAMAGED buffers that still got past
    // `Header.load` into the bounded Levenshtein walk.
    const base = try freezeFromPairs(testing.allocator, testing.allocator, &.{
        .{ .key = "praha", .value = 1 },
        .{ .key = "prahasever", .value = 2 },
        .{ .key = "plzen", .value = 3 },
        .{ .key = "brno", .value = 4 },
    });
    defer testing.allocator.free(base);

    var changed_total: usize = 0;
    var damaged_and_loaded: usize = 0;
    var damaged_and_rejected: usize = 0;
    var damaged_and_verified: usize = 0;
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
    // Measured 2026-09-07: `changed_total` was 0 — the flip count was the first
    // draw and therefore always the range minimum.
    try testing.expectEqual(@as(usize, 23), changed_total);
    // ⭐ The CRC trap as a number: without the re-seal bit every one of these
    // would land in `damaged_and_rejected` and the search would stay unvisited.
    try testing.expectEqual(@as(usize, 5), damaged_and_loaded);
    try testing.expectEqual(@as(usize, 4), damaged_and_rejected);
    try testing.expectEqual(@as(usize, 2), damaged_and_verified);
}

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
//! Three query shapes: exact `lookup`, a lexicographic `prefixIterator`, and a
//! ranked `topN` completions helper with an explicit visit **budget** — the DoS
//! guard that stops a one-character prefix from walking millions of keys.
//!
//! Keys are arbitrary bytes and are compared bytewise. Unicode normalization
//! (NFC/case-folding/diacritic-stripping) is the CALLER's responsibility: to get
//! accent-insensitive matching, fold both the stored keys and the query prefix
//! the same way before handing them to this module. See SPEC.md.
//!
//! Structure: a serialized byte-labelled trie with per-node `subtree_best`
//! (max descendant value) for top-N pruning. Not minimized into a DAFSA (that
//! is the documented deferred item); chosen for a robust, easily
//! bounds-checkable frozen format over an untrusted buffer. See SPEC.md for the
//! design rationale and the wire format field-by-field.

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any, // pure logic; the monotonic-clock use is test-only benchmarking
    .role = .util,
    .concurrency = .reentrant, // a frozen buffer is immutable → any number of concurrent readers
    .model_after = "BurntSushi/fst (Rust), Lucene FST",
    .deps = .{},
};

const builder = @import("builder.zig");
const query = @import("query.zig");
pub const format = @import("format.zig");

// ── public API ──────────────────────────────────────────────────────────────

pub const Builder = builder.Builder;
pub const Pair = builder.Pair;
pub const freezeFromPairs = builder.freezeFromPairs;
pub const BuildError = builder.BuildError;
pub const FreezeError = builder.FreezeError;

pub const Frozen = query.Frozen;
pub const Completion = query.Completion;
pub const QueryOptions = query.QueryOptions;
pub const TopNStatus = query.TopNStatus;
pub const TopNResult = query.TopNResult;
pub const PrefixIterator = query.PrefixIterator;
pub const LoadError = query.LoadError;
pub const QueryError = query.QueryError;
pub const max_depth = query.max_depth;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────────────

test {
    std.testing.refAllDecls(@This());
    _ = @import("format.zig");
    _ = @import("builder.zig");
    _ = @import("query.zig");
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

fn differentialRound(seed: u64, count: usize) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(seed);

    const pairs = try genKeys(arena, &prng, count);
    const oracle = try Oracle.build(arena, pairs);
    const buf = try freezeFromPairs(testing.allocator, testing.allocator, pairs);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    try testing.expectEqual(@as(u64, oracle.keys.len), f.keyCount());

    const rnd = prng.random();
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
        }
    }
}

fn rankBefore(av: u32, ak: []const u8, bv: u32, bk: []const u8) bool {
    if (av != bv) return av > bv;
    return std.mem.lessThan(u8, ak, bk);
}

test "differential: real trie vs naive oracle across many random key sets" {
    var seed: u64 = 1;
    while (seed <= 30) : (seed += 1) {
        try differentialRound(seed, 40);
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
    for (sets) |pairs| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const oracle = try Oracle.build(arena, pairs);
        const buf = try freezeFromPairs(testing.allocator, testing.allocator, pairs);
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
    }
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
    const buf = try b.freeze(testing.allocator);
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
    const buf = try freezeFromPairs(testing.allocator, testing.allocator, &pairs);
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
    const buf = try freezeFromPairs(testing.allocator, testing.allocator, &.{
        .{ .key = "hello", .value = 1 },
        .{ .key = "help", .value = 2 },
    });
    defer testing.allocator.free(buf);
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

fn fuzzRandom(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const f = Frozen.load(buf[0..len]) catch return;
    runQueries(f);
}

test "fuzz: loader + query path never panic on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzRandom, .{});
}

fn fuzzMutated(base: []const u8, smith: *std.testing.Smith) !void {
    var copy: [1024]u8 = undefined;
    if (base.len > copy.len) return;
    @memcpy(copy[0..base.len], base);
    // Apply a handful of smith-driven byte flips to a VALID buffer, so the
    // fuzzer spends its time past the magic/CRC gate, deep in node traversal.
    var i: usize = 0;
    const flips: usize = smith.valueRangeAtMost(u8, 0, 12);
    while (i < flips) : (i += 1) {
        const at: usize = smith.valueRangeAtMost(u16, 0, @intCast(base.len - 1));
        copy[at] = smith.value(u8);
    }
    const f = Frozen.load(copy[0..base.len]) catch return;
    runQueries(f);
}

test "fuzz: mutated-valid-buffer loader + query path never panic" {
    const base = try freezeFromPairs(testing.allocator, testing.allocator, &.{
        .{ .key = "praha", .value = 1 },
        .{ .key = "prahasever", .value = 2 },
        .{ .key = "plzen", .value = 3 },
        .{ .key = "brno", .value = 4 },
    });
    defer testing.allocator.free(base);
    try std.testing.fuzz(base, fuzzMutated, .{});
}

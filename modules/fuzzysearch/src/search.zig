// SPDX-License-Identifier: MIT

//! search — the read side: bounded-edit-distance ("fuzzy") lookup over a frozen
//! `trie` buffer, IN PLACE, with no copy of the index and no per-query heap
//! allocation (caller supplies the result + key buffers).
//!
//! The frozen buffer is a `trie` index (magic `"ZTR1"`, see the `trie` module);
//! `fuzzysearch` adds NO bytes of its own — a fuzzysearch index and a trie index
//! are the same file. The typo tolerance lives entirely in this query
//! algorithm, not in the data.
//!
//! Algorithm — a Levenshtein automaton walked over the trie (Hanov's
//! "trie + dynamic-programming row" method; the design lineage of Lucene's
//! `FuzzyQuery` / Schulz–Mihov universal Levenshtein automaton). A DFS visits
//! trie nodes; at each node it holds one DP row `row[0..m]` where `row[j]` is the
//! OSA edit distance between the node's path string and `query[0..j]`. Descending
//! an edge extends the path by one byte and computes the child row from the
//! parent row (and the grandparent row, for the transposition term). A subtree
//! is PRUNED the moment its row minimum exceeds `k`: the row minimum is provably
//! non-decreasing down every path, so no descendant can then reach distance ≤ k.
//! A visit budget bounds worst-case work — the DoS guard.
//!
//! Every offset followed out of the (possibly untrusted) buffer is bounds- and
//! invariant-checked by `trie`'s `format` decoder; a corrupt buffer yields
//! `error.Corrupt`, never an OOB read, panic, or infinite loop. Traversal
//! termination rests on `trie`'s strictly-increasing child-offset invariant.

const std = @import("std");
const trie = @import("trie");
const format = trie.format;

pub const LoadError = format.LoadError;

/// Errors returned by `search`. `Corrupt` comes from `trie`'s bounds-checked
/// decoder on a malformed buffer; the rest are usage/limit errors.
pub const SearchError = format.DecodeError || error{
    /// A key path in the index is deeper than `max_depth` bytes.
    KeyTooLong,
    /// `query` is longer than `max_query_len` bytes.
    QueryTooLong,
    /// `k` exceeds `max_k`.
    DistanceTooLarge,
    /// A matched key does not fit its share (`key_buf.len / results.len`) of
    /// the caller's key buffer. Size `key_buf` as results.len × longest key.
    KeyBufTooSmall,
};

/// Longest `query` accepted. Fuzzy search is a partial-query search box; this is
/// generous. A longer query yields `error.QueryTooLong`.
pub const max_query_len: usize = 256;

/// Longest stored-key path the DFS walks. Comfortably above any address string;
/// a deeper key yields `error.KeyTooLong`. Bounds the inline DFS stacks.
pub const max_depth: usize = 1024;

/// Largest edit distance accepted, so the capped DP cell (`k + 1`) fits a u8.
pub const max_k: u8 = 254;

/// Options controlling `search`'s bounded work.
pub const SearchOptions = struct {
    /// Maximum number of trie nodes `search` may decode before it stops and
    /// reports `.truncated_budget`. This is the DoS guard: a short query with a
    /// large `k` sits above much of the set, so this caps worst-case latency.
    /// Row-minimum pruning means a well-formed query usually finishes far under
    /// budget. 0 means "unbounded" — do NOT use on attacker-influenced queries
    /// or untrusted buffers.
    max_visited: usize = 50_000,
};

/// One match returned by `search`. `key` borrows the caller-supplied `key_buf`,
/// not the frozen index — it is valid only until that buffer is reused.
pub const Match = struct {
    /// OSA edit distance between `query` and this key (0..=k).
    distance: u32,
    /// The caller's stored `u32` (a record id).
    value: u32,
    key: []const u8,
};

pub const SearchStatus = enum {
    /// The whole index was searched within budget; `items` is the exact best-N.
    complete,
    /// The visit budget was hit; `items` is a best-effort partial answer and may
    /// omit better matches that were never reached.
    truncated_budget,
};

pub const SearchResult = struct {
    items: []Match,
    status: SearchStatus,
};

/// Ranking: distance ascending, then stored value descending, then key
/// ascending (lexicographic bytes). Keys in a frozen trie are distinct, so this
/// is a total order — the top-N is unambiguous.
fn betterMatch(a: Match, b: Match) bool {
    if (a.distance != b.distance) return a.distance < b.distance;
    if (a.value != b.value) return a.value > b.value;
    return std.mem.lessThan(u8, a.key, b.key);
}

// ── Frozen: a loaded, query-ready view over a frozen trie buffer ─────────────

/// A loaded fuzzy-search view. Wraps a `trie.Frozen` (which validated the header
/// — magic, version, endian, header CRC, root offset). Zero-copy: the buffer is
/// kept by reference and may be a read-only mmap. Immutable → any number of
/// threads may search one `Frozen` concurrently.
pub const Frozen = struct {
    inner: trie.Frozen,

    /// Fast open: validate the header only (O(1)). Per-node bounds-checking
    /// during the search keeps traversal safe even though the body is not
    /// scanned here.
    pub fn load(buf: []const u8) LoadError!Frozen {
        return .{ .inner = try trie.Frozen.load(buf) };
    }

    /// Untrusted-file open: `load` plus a full node-region CRC check. Prefer for
    /// files crossing a trust boundary; the search is bounds-checked regardless,
    /// but this rejects silent bit-rot up front.
    pub fn loadVerified(buf: []const u8) LoadError!Frozen {
        return .{ .inner = try trie.Frozen.loadVerified(buf) };
    }

    pub fn keyCount(self: Frozen) u64 {
        return self.inner.keyCount();
    }

    /// Find every stored key within OSA edit distance `k` of `query`, ranked
    /// best-first (distance asc, value desc, key asc), into the caller's
    /// `results` and `key_buf`. Keeps the best `results.len` matches; if the
    /// full search completes within budget the returned items are the exact
    /// best-N (`status == .complete`), otherwise `.truncated_budget`.
    ///
    /// `key_buf` is SHARED across the `results.len` output slots — it is sliced
    /// into `results.len` equal strides, so it must hold
    /// `results.len × longest-matched-key` bytes; an undersized share yields
    /// `error.KeyBufTooSmall`.
    ///
    /// Zero heap allocation: the DP rows and DFS stack are fixed inline arrays.
    pub fn search(
        self: Frozen,
        query: []const u8,
        k: u8,
        results: []Match,
        key_buf: []u8,
        opts: SearchOptions,
    ) SearchError!SearchResult {
        return searchInto(self.inner, query, k, results, key_buf, opts);
    }
};

// ── best-N selector (mirrors trie's, with the 3-key ranking) ─────────────────
//
// Fixed-capacity selector writing keys into caller storage. Physical key slots
// (`key_buf` split into N equal strides) are decoupled from rank order, so
// re-ranking never moves key bytes — a displaced slot is simply overwritten.

const Selector = struct {
    results: []Match,
    key_buf: []u8,
    stride: usize,
    count: usize = 0,

    fn init(results: []Match, key_buf: []u8) Selector {
        const n = results.len;
        const stride = if (n == 0) 0 else key_buf.len / n;
        return .{ .results = results, .key_buf = key_buf, .stride = stride };
    }

    fn slot(self: *Selector, i: usize) []u8 {
        return self.key_buf[i * self.stride ..][0..self.stride];
    }

    fn consider(self: *Selector, m: Match) SearchError!void {
        const n = self.results.len;
        if (n == 0) return;
        if (self.count == n and !betterMatch(m, self.results[n - 1])) return;
        if (m.key.len > self.stride) return error.KeyBufTooSmall;

        var dst: []u8 = undefined;
        if (self.count < n) {
            dst = self.slot(self.count);
        } else {
            // Recycle the (about-to-be-evicted) worst slot's physical storage.
            const worst_ptr = self.results[n - 1].key.ptr;
            const idx = (@intFromPtr(worst_ptr) - @intFromPtr(self.key_buf.ptr)) / self.stride;
            dst = self.slot(idx);
            self.count -= 1;
        }
        @memcpy(dst[0..m.key.len], m.key);
        const item = Match{ .distance = m.distance, .value = m.value, .key = dst[0..m.key.len] };

        // Insert into the sorted-by-rank prefix results[0..count].
        var pos: usize = 0;
        while (pos < self.count and !betterMatch(item, self.results[pos])) pos += 1;
        var j: usize = self.count;
        while (j > pos) : (j -= 1) self.results[j] = self.results[j - 1];
        self.results[pos] = item;
        self.count += 1;
    }
};

// ── the DP-over-trie walk ─────────────────────────────────────────────────────

const Frame = struct { node: format.NodeView, edge_idx: u16 };

fn searchInto(
    f: trie.Frozen,
    query: []const u8,
    k: u8,
    results: []Match,
    key_buf: []u8,
    opts: SearchOptions,
) SearchError!SearchResult {
    if (query.len > max_query_len) return error.QueryTooLong;
    if (k > max_k) return error.DistanceTooLarge;

    var sel = Selector.init(results, key_buf);
    const m = query.len;
    const cap: u16 = @as(u16, k) + 1; // any true distance > k collapses to this

    // DP rows, one per depth on the current path. row_store[d][0..m+1] is the
    // row for the node at depth d. u8 cells: every distance we care about is
    // ≤ k ≤ 254, and values above k are capped at `cap` (≤ 255).
    var row_store: [max_depth + 1][max_query_len + 1]u8 = undefined;
    // Reconstructed key: path_store[0..depth] are the edge labels root→node.
    var path_store: [max_depth]u8 = undefined;
    var stack: [max_depth + 1]Frame = undefined;

    // Root: depth 0, path "". row[0][j] = min(j, cap) (j deletions from query).
    const root = try format.nodeAt(f.buf, f.header.root_offset);
    {
        var j: usize = 0;
        while (j <= m) : (j += 1) row_store[0][j] = @intCast(@min(@as(u16, @intCast(j)), cap));
    }
    if (root.terminal and row_store[0][m] <= k) {
        try sel.consider(.{ .distance = row_store[0][m], .value = root.value, .key = path_store[0..0] });
    }

    var sp: usize = 1;
    stack[0] = .{ .node = root, .edge_idx = 0 };
    var visited: usize = 0;
    var status: SearchStatus = .complete;

    outer: while (sp > 0) {
        const top = &stack[sp - 1];
        const d = sp - 1; // depth of the node at the top of the stack
        if (top.edge_idx >= top.node.edge_count) {
            sp -= 1; // done with this node; backtrack
            continue;
        }
        const e = top.node.edge(top.edge_idx);
        top.edge_idx += 1;

        if (opts.max_visited != 0 and visited >= opts.max_visited) {
            status = .truncated_budget;
            break :outer;
        }
        visited += 1;

        const child = try format.follow(top.node, e.child); // bounds-checked
        const nd = d + 1; // child depth
        if (nd > max_depth) return error.KeyTooLong;

        // Compute the child's DP row from the parent row (row_store[d]) and, for
        // the transposition term, the grandparent row (row_store[d-1]).
        path_store[d] = e.label;
        const c = e.label;
        const prev = &row_store[d];
        const cur = &row_store[nd];
        cur[0] = @intCast(@min(@as(u16, @intCast(nd)), cap));
        var row_min: u16 = cur[0];
        var j: usize = 1;
        while (j <= m) : (j += 1) {
            const cost: u16 = if (c == query[j - 1]) 0 else 1;
            var v: u16 = @min(@min(@as(u16, cur[j - 1]) + 1, @as(u16, prev[j]) + 1), @as(u16, prev[j - 1]) + cost);
            // Adjacent transposition: needs a grandparent (nd ≥ 2 ⇒ d ≥ 1) and
            // c == query[j-2], prev_char == query[j-1] where prev_char is the
            // label leading into the depth-d node = path_store[d-1].
            if (d >= 1 and j >= 2 and c == query[j - 2] and path_store[d - 1] == query[j - 1]) {
                v = @min(v, @as(u16, row_store[d - 1][j - 2]) + 1);
            }
            if (v > cap) v = cap;
            cur[j] = @intCast(v);
            if (v < row_min) row_min = v;
        }

        // Prune: if the whole row already exceeds k, no descendant can reach ≤ k
        // (row minimum is non-decreasing down every path). Skip this subtree.
        if (row_min > k) continue :outer;

        if (child.terminal and cur[m] <= k) {
            try sel.consider(.{ .distance = cur[m], .value = child.value, .key = path_store[0..nd] });
        }
        stack[sp] = .{ .node = child, .edge_idx = 0 };
        sp += 1;
    }

    return .{ .items = results[0..sel.count], .status = status };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn build(pairs: []const trie.Pair) ![]u8 {
    return trie.freezeFromPairs(testing.allocator, testing.allocator, pairs);
}

test "search: exact match at k=0" {
    const buf = try build(&.{
        .{ .key = "praha", .value = 1 },
        .{ .key = "plzen", .value = 2 },
        .{ .key = "brno", .value = 3 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [8]Match = undefined;
    var kb: [8 * 32]u8 = undefined;
    const r = try f.search("praha", 0, &results, &kb, .{});
    try testing.expectEqual(SearchStatus.complete, r.status);
    try testing.expectEqual(@as(usize, 1), r.items.len);
    try testing.expectEqualStrings("praha", r.items[0].key);
    try testing.expectEqual(@as(u32, 0), r.items[0].distance);
    try testing.expectEqual(@as(u32, 1), r.items[0].value);
}

test "search: one typo of each kind at k=1" {
    const buf = try build(&.{
        .{ .key = "vaclavske", .value = 10 },
        .{ .key = "namesti", .value = 20 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [8]Match = undefined;
    var kb: [8 * 32]u8 = undefined;
    // insertion: "vaclvske" -> "vaclavske" (missing 'a')
    // substitution: "vaclovske"
    // deletion: "vaaclavske" (extra 'a')
    // transposition: "vaclasvke" (sv <-> vs)? use "vacalvske" (al<->la)
    const queries = [_][]const u8{ "vaclvske", "vaclovske", "vaaclavske", "vaclasvke" };
    for (queries) |q| {
        const r = try f.search(q, 1, &results, &kb, .{});
        try testing.expect(r.items.len >= 1);
        var found = false;
        for (r.items) |it| if (std.mem.eql(u8, it.key, "vaclavske")) {
            found = true;
        };
        try testing.expect(found);
    }
}

test "search: k larger than key length matches everything" {
    const buf = try build(&.{
        .{ .key = "ab", .value = 1 },
        .{ .key = "cd", .value = 2 },
        .{ .key = "ef", .value = 3 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [8]Match = undefined;
    var kb: [8 * 16]u8 = undefined;
    const r = try f.search("zz", 10, &results, &kb, .{});
    try testing.expectEqual(@as(usize, 3), r.items.len);
}

test "search: empty query returns keys shorter than or equal to k" {
    const buf = try build(&.{
        .{ .key = "a", .value = 1 },
        .{ .key = "ab", .value = 2 },
        .{ .key = "abc", .value = 3 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [8]Match = undefined;
    var kb: [8 * 16]u8 = undefined;
    const r = try f.search("", 2, &results, &kb, .{});
    // "a" (d=1), "ab" (d=2) match; "abc" (d=3) does not.
    try testing.expectEqual(@as(usize, 2), r.items.len);
}

test "search: empty key in the set matches short queries" {
    const buf = try build(&.{
        .{ .key = "", .value = 42 },
        .{ .key = "xy", .value = 7 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [8]Match = undefined;
    var kb: [8 * 16]u8 = undefined;
    const r = try f.search("x", 1, &results, &kb, .{});
    // "" is distance 1 from "x"; "xy" is distance 1 too.
    try testing.expectEqual(@as(usize, 2), r.items.len);
}

test "search: ranking is distance asc, then value desc, then key asc" {
    const buf = try build(&.{
        .{ .key = "aaa", .value = 5 }, // d0 from query
        .{ .key = "aab", .value = 9 }, // d1
        .{ .key = "aac", .value = 9 }, // d1, ties aab on value -> key asc: aab<aac
        .{ .key = "abb", .value = 1 }, // d2
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [8]Match = undefined;
    var kb: [8 * 16]u8 = undefined;
    const r = try f.search("aaa", 2, &results, &kb, .{});
    try testing.expectEqual(@as(usize, 4), r.items.len);
    try testing.expectEqualStrings("aaa", r.items[0].key); // distance 0
    try testing.expectEqualStrings("aab", r.items[1].key); // d1, val9, key asc
    try testing.expectEqualStrings("aac", r.items[2].key); // d1, val9
    try testing.expectEqualStrings("abb", r.items[3].key); // d2
}

test "search: boundary — distance exactly k included, k+1 excluded" {
    const buf = try build(&.{
        .{ .key = "abcd", .value = 1 }, // d2 from "abxy"
        .{ .key = "abcy", .value = 2 }, // d1
        .{ .key = "wxyz", .value = 3 }, // d4
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [8]Match = undefined;
    var kb: [8 * 16]u8 = undefined;
    const r = try f.search("abxy", 2, &results, &kb, .{});
    // abcy d1, abcd d2 included; wxyz d4 excluded.
    try testing.expectEqual(@as(usize, 2), r.items.len);
    for (r.items) |it| try testing.expect(it.distance <= 2);
}

test "search: top-N truncation when more matches than result slots" {
    var b = try trie.Builder.init(testing.allocator);
    defer b.deinit();
    var kbuf: [16]u8 = undefined;
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        const key = try std.fmt.bufPrint(&kbuf, "key{d:0>4}", .{i});
        try b.insert(key, i);
    }
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [3]Match = undefined;
    var kb: [3 * 16]u8 = undefined;
    // "key0000" matches many keys within k=2; only the best 3 are kept.
    const r = try f.search("key0000", 2, &results, &kb, .{});
    try testing.expectEqual(@as(usize, 3), r.items.len);
    // Still "complete": the full set was searched, only the output was capped.
    try testing.expectEqual(SearchStatus.complete, r.status);
}

test "search: budget exhaustion reported as truncated" {
    var b = try trie.Builder.init(testing.allocator);
    defer b.deinit();
    var kbuf: [16]u8 = undefined;
    var i: u32 = 0;
    while (i < 500) : (i += 1) {
        const key = try std.fmt.bufPrint(&kbuf, "n{d:0>6}", .{i});
        try b.insert(key, i);
    }
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [5]Match = undefined;
    var kb: [5 * 16]u8 = undefined;
    const r = try f.search("n000000", 5, &results, &kb, .{ .max_visited = 8 });
    try testing.expectEqual(SearchStatus.truncated_budget, r.status);
}

test "search: usage-limit errors" {
    const buf = try build(&.{.{ .key = "a", .value = 1 }});
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [4]Match = undefined;
    var kb: [4 * 8]u8 = undefined;
    var longq: [max_query_len + 1]u8 = undefined;
    @memset(&longq, 'a');
    try testing.expectError(error.QueryTooLong, f.search(&longq, 1, &results, &kb, .{}));
    try testing.expectError(error.DistanceTooLarge, f.search("a", max_k + 1, &results, &kb, .{}));
}

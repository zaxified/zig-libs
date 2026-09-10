// SPDX-License-Identifier: MIT

//! query — the read side: load a frozen buffer and answer queries against it
//! IN PLACE, with no copy of the index and (for `lookup`) no allocation at all.
//!
//! Three query shapes, in the brief's order of importance:
//!   * `lookup(key)`        — exact match → the stored value, or null.
//!   * `topN(prefix, …)`    — the best N completions under a prefix, ranked, with
//!                            an explicit visit budget (the DoS guard).
//!   * `prefixIterator(pfx)`— every key under a prefix, in lexicographic order.
//!
//! Every offset followed out of the (possibly untrusted) buffer is bounds- and
//! invariant-checked in `format`; a corrupt buffer yields `error.Corrupt`, never
//! an OOB read, panic, or infinite loop. Traversal termination is guaranteed by
//! the strictly-increasing child-offset invariant enforced in `format.follow`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const format = @import("format.zig");

pub const LoadError = format.LoadError;
pub const QueryError = format.DecodeError || error{ KeyTooLong, TooComplex };

/// Options controlling `topN`'s bounded work.
pub const QueryOptions = struct {
    /// Maximum number of nodes `topN` may decode before it stops and reports a
    /// truncated result. This is the DoS guard: a one-character prefix over
    /// millions of keys cannot walk the whole set — it stops here. Choose it to
    /// bound worst-case latency; `subtree_best` pruning means well-ranked
    /// queries usually finish far under budget. 0 means "unbounded" (do not use
    /// on untrusted prefixes).
    max_visited: usize = 50_000,
};

/// One completion returned by `topN` / `prefixIterator`. `key` borrows the
/// caller-supplied key buffer, not the frozen index — it is valid until the
/// buffer is reused.
pub const Completion = struct { value: u32, key: []const u8 };

pub const TopNStatus = enum {
    /// The full set under the prefix was considered; `items` is the true top-N.
    complete,
    /// The visit budget was hit; `items` is a best-effort partial answer and may
    /// omit better completions that were never reached.
    truncated_budget,
};

pub const TopNResult = struct {
    items: []Completion,
    status: TopNStatus,
};

// ── Frozen: a loaded, query-ready view over a frozen buffer ──────────────────

pub const Frozen = struct {
    buf: []const u8,
    header: format.Header,

    /// Fast open: validate the header only (O(1)) and keep the buffer by
    /// reference (zero-copy). Per-node bounds-checking during queries keeps
    /// traversal safe even though the body was not scanned here.
    pub fn load(buf: []const u8) LoadError!Frozen {
        const header = try format.Header.load(buf);
        // Bound the kept slice to exactly the node region `Header.load` just
        // proved fits (`buf.len >= header_size + node_region_len`). `nodeAt`'s
        // every bounds check is against this slice's `.len`, so this is what
        // keeps a (possibly attacker-chosen) edge from ever resolving into the
        // trailing padding `Header.load` tolerates on purpose ("an mmap'd file
        // may be page-rounded") — see A1/trie.md F2: without it, `loadVerified`
        // still reports success on a buffer whose padding was silently
        // bit-flipped, because the CRC it checks never covered that padding
        // and neither did any node's bounds check.
        const end = format.header_size + @as(usize, header.node_region_len);
        return .{ .buf = buf[0..end], .header = header };
    }

    /// Untrusted-file open: `load` plus a full node-region CRC check. Prefer
    /// this for files from outside the process's trust boundary; queries remain
    /// bounds-checked regardless, but this rejects any silent bit-rot up front.
    pub fn loadVerified(buf: []const u8) LoadError!Frozen {
        const f = try load(buf);
        try f.header.verifyBody(buf);
        return f;
    }

    pub fn keyCount(self: Frozen) u64 {
        return self.header.key_count;
    }

    fn root(self: Frozen) QueryError!format.NodeView {
        return format.nodeAt(self.buf, self.header.root_offset);
    }

    /// Walk from the root consuming every byte of `prefix`. Returns the node the
    /// prefix ends at (the root of that prefix's subtree), or null if the prefix
    /// is not present as a path. Bounded by `prefix.len`.
    fn seek(self: Frozen, prefix: []const u8) QueryError!?format.NodeView {
        var node = try self.root();
        for (prefix) |b| {
            const e = node.findEdge(b) orelse return null;
            node = try format.follow(node, e.child);
        }
        return node;
    }

    /// Exact lookup: the value stored for `key`, or null if `key` is not a
    /// stored key. Zero allocation; O(key.len) node decodes.
    pub fn lookup(self: Frozen, key: []const u8) QueryError!?u32 {
        const node = (try self.seek(key)) orelse return null;
        return if (node.terminal) node.value else null;
    }

    /// Top-N completions under `prefix`, ranked best-first, into the caller's
    /// `results` and `key_buf`. See `topNInto` for the full contract.
    pub fn topN(
        self: Frozen,
        prefix: []const u8,
        results: []Completion,
        key_buf: []u8,
        opts: QueryOptions,
    ) QueryError!TopNResult {
        return topNInto(self, prefix, results, key_buf, opts);
    }

    /// Iterate every key under `prefix` in lexicographic order. The iterator
    /// borrows a small traversal stack from `gpa` (typically a reused arena, so
    /// effectively free); the frozen index itself is never copied. Call
    /// `deinit` when done.
    ///
    /// ⚠ Unbounded: nothing in the wire format forbids two edges from pointing
    /// at the same child, so a buffer that is not self-built (or otherwise
    /// trusted) can encode far more keys than its size suggests — a buffer
    /// under 1 KB can be built to enumerate 2^60 keys (A1/trie.md F1). Over an
    /// untrusted buffer, use `prefixIteratorBounded` instead.
    pub fn prefixIterator(self: Frozen, gpa: Allocator, prefix: []const u8) (QueryError || Allocator.Error)!PrefixIterator {
        return PrefixIterator.init(gpa, self, prefix, 0);
    }

    /// Same as `prefixIterator`, but bounded: `next` returns `error.TooComplex`
    /// once more than `max_visited` nodes have been decoded over the
    /// iterator's whole lifetime, instead of continuing to walk an arbitrarily
    /// large (over a hostile buffer, effectively unbounded) subtree. Prefer
    /// this over `prefixIterator` whenever `buf` may not be self-built.
    pub fn prefixIteratorBounded(
        self: Frozen,
        gpa: Allocator,
        prefix: []const u8,
        max_visited: usize,
    ) (QueryError || Allocator.Error)!PrefixIterator {
        return PrefixIterator.init(gpa, self, prefix, max_visited);
    }
};

// ── top-N ─────────────────────────────────────────────────────────────────────
//
// Ranking contract (documented in README/SPEC):
//   primary   — higher stored value ranks first (descending u32);
//   tie-break — smaller key ranks first (lexicographic byte order).
// Keys in a frozen trie are distinct, so this is a total order.
//
// Implementation: a lexicographic DFS under the prefix feeds every terminal it
// reaches into a fixed-size selector that keeps the N best under that order.
// `subtree_best` pruning skips whole subtrees that cannot beat the current
// worst-kept value (strict inequality only — an equal-valued subtree is still
// explored so the key tie-break stays exact). A visit budget bounds total work.

/// Explicit DFS stack cap. Reconstructed keys deeper than this yield
/// `error.KeyTooLong`; addresses are far shorter. Kept as a fixed inline stack
/// so `topN` needs no allocation.
pub const max_depth: usize = 4096;

fn better(av: u32, ak: []const u8, bv: u32, bk: []const u8) bool {
    if (av != bv) return av > bv;
    return std.mem.lessThan(u8, ak, bk);
}

/// Fixed-capacity best-N selector writing keys into caller storage. Physical key
/// slots (`key_buf` divided into N equal strides) are decoupled from rank order,
/// so re-ranking never moves key bytes — a displaced slot is simply overwritten.
const Selector = struct {
    results: []Completion,
    key_buf: []u8,
    stride: usize,
    count: usize = 0,

    fn init(results: []Completion, key_buf: []u8) Selector {
        const n = results.len;
        const stride = if (n == 0) 0 else key_buf.len / n;
        return .{ .results = results, .key_buf = key_buf, .stride = stride };
    }

    fn slot(self: *Selector, i: usize) []u8 {
        return self.key_buf[i * self.stride ..][0..self.stride];
    }

    fn consider(self: *Selector, value: u32, key: []const u8) QueryError!void {
        const n = self.results.len;
        if (n == 0) return;
        if (self.count == n and !better(value, key, self.results[n - 1].value, self.results[n - 1].key))
            return;
        if (key.len > self.stride) return error.KeyTooLong;

        var dst: []u8 = undefined;
        if (self.count < n) {
            dst = self.slot(self.count);
        } else {
            // `stride == 0` happens whenever the caller's `key_buf` is
            // shorter than `results.len` slots. Only an empty key can then
            // pass the size check above, and a trie stores at most one empty
            // key (the root), so a SECOND, better-ranked empty key reaching
            // this eviction branch (the only place that divides by `stride`)
            // was reasoned to be unreachable — but that reasoning lived only
            // in a comment, nowhere a test held it (A1/trie.md F5). Reject it
            // explicitly rather than dividing by zero.
            if (self.stride == 0) return error.KeyTooLong;
            // Reuse the (about-to-be-evicted) worst slot's physical storage.
            const worst_ptr = self.results[n - 1].key.ptr;
            const idx = (@intFromPtr(worst_ptr) - @intFromPtr(self.key_buf.ptr)) / self.stride;
            dst = self.slot(idx);
            self.count -= 1;
        }
        @memcpy(dst[0..key.len], key);
        const item = Completion{ .value = value, .key = dst[0..key.len] };

        // Insert into the sorted-by-rank prefix results[0..count].
        var pos: usize = 0;
        while (pos < self.count and !better(item.value, item.key, self.results[pos].value, self.results[pos].key))
            pos += 1;
        var j: usize = self.count;
        while (j > pos) : (j -= 1) self.results[j] = self.results[j - 1];
        self.results[pos] = item;
        self.count += 1;
    }
};

fn topNInto(
    self: Frozen,
    prefix: []const u8,
    results: []Completion,
    key_buf: []u8,
    opts: QueryOptions,
) QueryError!TopNResult {
    var sel = Selector.init(results, key_buf);
    const sub = (try self.seek(prefix)) orelse
        return .{ .items = results[0..0], .status = .complete };

    // Reconstructed-key path buffer (prefix + labels), and the DFS frame stack.
    var path_store: [max_depth]u8 = undefined;
    if (prefix.len > path_store.len) return error.KeyTooLong;
    @memcpy(path_store[0..prefix.len], prefix);
    var path_len: usize = prefix.len;

    const Frame = struct { node: format.NodeView, edge_idx: u16, mark: usize };
    var stack: [max_depth]Frame = undefined;
    var sp: usize = 0;
    stack[sp] = .{ .node = sub, .edge_idx = 0, .mark = prefix.len };
    sp += 1;
    if (sub.terminal) try sel.consider(sub.value, path_store[0..path_len]);

    var visited: usize = 0;
    var status: TopNStatus = .complete;

    outer: while (sp > 0) {
        const top = &stack[sp - 1];
        if (top.edge_idx < top.node.edge_count) {
            const e = top.node.edge(top.edge_idx);
            top.edge_idx += 1;

            if (opts.max_visited != 0 and visited >= opts.max_visited) {
                status = .truncated_budget;
                break :outer;
            }
            visited += 1;
            const child = try format.follow(top.node, e.child);

            // Prune whole subtrees that cannot beat the current worst kept value
            // (strict: ties are still explored so the key tie-break is exact).
            if (sel.count == results.len and results.len != 0 and
                child.subtree_best < results[results.len - 1].value)
                continue :outer;

            if (path_len >= path_store.len or sp >= stack.len) return error.KeyTooLong;
            path_store[path_len] = e.label;
            path_len += 1;
            if (child.terminal) try sel.consider(child.value, path_store[0..path_len]);
            stack[sp] = .{ .node = child, .edge_idx = 0, .mark = path_len - 1 };
            sp += 1;
        } else {
            path_len = top.mark;
            sp -= 1;
        }
    }

    return .{ .items = results[0..sel.count], .status = status };
}

// ── prefix iterator ───────────────────────────────────────────────────────────

/// Lexicographic-order iterator over every key under a prefix. Pull-based: the
/// caller paces the work (the natural bound for enumeration), and each `next`
/// reconstructs the key into a caller buffer. The frozen index is never copied.
pub const PrefixIterator = struct {
    gpa: Allocator,
    frozen: Frozen,
    /// Reconstructed key so far (prefix + labels along the DFS path).
    path: std.ArrayListUnmanaged(u8) = .empty,
    stack: std.ArrayListUnmanaged(Frame) = .empty,
    /// True once the subtree root's own terminal (if any) has been considered.
    exhausted: bool,
    /// Node-decode budget for this iterator's whole lifetime. 0 (used by
    /// `Frozen.prefixIterator`) means unbounded — see `prefixIteratorBounded`.
    max_visited: usize = 0,
    /// Nodes decoded (edges followed) so far.
    visited: usize = 0,

    const Frame = struct {
        node: format.NodeView,
        edge_idx: u16 = 0,
        self_done: bool = false,
        /// path length to restore when this frame is popped.
        mark: usize,
    };

    fn init(gpa: Allocator, frozen: Frozen, prefix: []const u8, max_visited: usize) (QueryError || Allocator.Error)!PrefixIterator {
        var it = PrefixIterator{ .gpa = gpa, .frozen = frozen, .exhausted = false, .max_visited = max_visited };
        const sub = (try frozen.seek(prefix)) orelse {
            it.exhausted = true;
            return it;
        };
        try it.path.appendSlice(gpa, prefix);
        try it.stack.append(gpa, .{ .node = sub, .mark = prefix.len });
        return it;
    }

    pub fn deinit(self: *PrefixIterator) void {
        self.path.deinit(self.gpa);
        self.stack.deinit(self.gpa);
        self.* = undefined;
    }

    /// Next key under the prefix, in lexicographic order, reconstructed into
    /// `key_buf` (which the returned `key` borrows). null when exhausted.
    /// `error.KeyTooLong` if a key does not fit `key_buf`.
    pub fn next(self: *PrefixIterator, key_buf: []u8) (QueryError || Allocator.Error)!?Completion {
        while (self.stack.items.len > 0) {
            const top = &self.stack.items[self.stack.items.len - 1];
            if (!top.self_done) {
                top.self_done = true;
                if (top.node.terminal) {
                    return try emit(self.path.items, top.node.value, key_buf);
                }
            }
            if (top.edge_idx < top.node.edge_count) {
                const e = top.node.edge(top.edge_idx);
                top.edge_idx += 1;
                if (self.max_visited != 0 and self.visited >= self.max_visited) return error.TooComplex;
                self.visited += 1;
                const child = try format.follow(top.node, e.child);
                try self.path.append(self.gpa, e.label);
                try self.stack.append(self.gpa, .{ .node = child, .mark = self.path.items.len - 1 });
            } else {
                const mark = top.mark;
                self.path.shrinkRetainingCapacity(mark);
                _ = self.stack.pop();
            }
        }
        return null;
    }

    fn emit(path: []const u8, value: u32, key_buf: []u8) QueryError!Completion {
        if (path.len > key_buf.len) return error.KeyTooLong;
        @memcpy(key_buf[0..path.len], path);
        return .{ .value = value, .key = key_buf[0..path.len] };
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const builder = @import("builder.zig");
const testing = std.testing;

fn build(pairs: []const builder.Pair) ![]u8 {
    return builder.freezeFromPairs(testing.allocator, testing.allocator, pairs);
}

/// Hand-build a `k`-level chain where each non-terminal node has two edges
/// ('a','b') pointing at the SAME next node, ending in one terminal leaf.
/// `Builder` can never produce this (a child always has exactly one parent),
/// but nothing in the wire format forbids it: the buffer is `17k + 11` bytes
/// and denotes `2^k` distinct keys — the DAG shape from A1/trie.md F1.
fn buildChainDag(allocator: std.mem.Allocator, k: usize) ![]u8 {
    const region_len = 17 * k + 11;
    const buf = try allocator.alloc(u8, format.header_size + region_len);
    errdefer allocator.free(buf);
    var i: usize = 0;
    while (i < k) : (i += 1) {
        const off = format.header_size + 17 * i;
        const next_off: u32 = @intCast(format.header_size + 17 * (i + 1)); // last level -> the leaf
        buf[off] = 0; // non-terminal
        std.mem.writeInt(u32, buf[off + 1 .. off + 5][0..4], 0, .little); // best
        std.mem.writeInt(u16, buf[off + 5 .. off + 7][0..2], 2, .little); // edge_count = 2
        buf[off + 7] = 'a';
        std.mem.writeInt(u32, buf[off + 8 .. off + 12][0..4], next_off, .little);
        buf[off + 12] = 'b';
        std.mem.writeInt(u32, buf[off + 13 .. off + 17][0..4], next_off, .little);
    }
    const leaf_off = format.header_size + 17 * k;
    buf[leaf_off] = format.terminal_bit;
    std.mem.writeInt(u32, buf[leaf_off + 1 .. leaf_off + 5][0..4], 1, .little); // value
    std.mem.writeInt(u32, buf[leaf_off + 5 .. leaf_off + 9][0..4], 1, .little); // best
    std.mem.writeInt(u16, buf[leaf_off + 9 .. leaf_off + 11][0..2], 0, .little); // edge_count = 0

    const h = format.Header{ .version = format.format_version, .flags = 0, .node_region_len = @intCast(region_len), .key_count = 1, .root_offset = format.header_size };
    h.encode(buf, buf[format.header_size..]);
    return buf;
}

test "lookup: exact match, miss, prefix-of-a-key is not itself a key" {
    const buf = try build(&.{
        .{ .key = "car", .value = 1 },
        .{ .key = "card", .value = 2 },
        .{ .key = "care", .value = 3 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    try testing.expectEqual(@as(?u32, 1), try f.lookup("car"));
    try testing.expectEqual(@as(?u32, 2), try f.lookup("card"));
    try testing.expectEqual(@as(?u32, null), try f.lookup("ca")); // path but not terminal
    try testing.expectEqual(@as(?u32, null), try f.lookup("cars")); // no such path
    try testing.expectEqual(@as(?u32, null), try f.lookup("")); // empty not stored
}

test "prefixIterator yields all keys under a prefix in lexicographic order" {
    const buf = try build(&.{
        .{ .key = "care", .value = 3 },
        .{ .key = "car", .value = 1 },
        .{ .key = "cart", .value = 4 },
        .{ .key = "card", .value = 2 },
        .{ .key = "dog", .value = 9 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var it = try f.prefixIterator(testing.allocator, "car");
    defer it.deinit();
    var kb: [64]u8 = undefined;
    const want = [_][]const u8{ "car", "card", "care", "cart" };
    var i: usize = 0;
    while (try it.next(&kb)) |c| : (i += 1) {
        try testing.expectEqualStrings(want[i], c.key);
    }
    try testing.expectEqual(want.len, i);
}

test "topN: ranked by value desc, tie-broken by key asc" {
    const buf = try build(&.{
        .{ .key = "aa", .value = 5 },
        .{ .key = "ab", .value = 9 },
        .{ .key = "ac", .value = 5 }, // ties with aa on value → aa (smaller key) first
        .{ .key = "ad", .value = 1 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [3]Completion = undefined;
    var kb: [3 * 16]u8 = undefined;
    const r = try f.topN("a", &results, &kb, .{});
    try testing.expectEqual(TopNStatus.complete, r.status);
    try testing.expectEqual(@as(usize, 3), r.items.len);
    try testing.expectEqualStrings("ab", r.items[0].key); // 9
    try testing.expectEqualStrings("aa", r.items[1].key); // 5, smaller key
    try testing.expectEqualStrings("ac", r.items[2].key); // 5, larger key
}

test "topN: budget exhaustion is reported as truncated" {
    var b = try builder.Builder.init(testing.allocator);
    defer b.deinit();
    var kbuf: [16]u8 = undefined;
    var i: u32 = 0;
    while (i < 500) : (i += 1) {
        const k = try std.fmt.bufPrint(&kbuf, "k{d:0>6}", .{i});
        try b.insert(k, i);
    }
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var results: [5]Completion = undefined;
    var kb: [5 * 16]u8 = undefined;
    const r = try f.topN("k", &results, &kb, .{ .max_visited = 10 });
    try testing.expectEqual(TopNStatus.truncated_budget, r.status);
}

test "prefixIterator.next: undersized key_buf is KeyTooLong, not a truncated/corrupt key" {
    // `emit`'s bounds check (`error.KeyTooLong` on `path.len > key_buf.len`) had
    // no call site anywhere in the suite before this test — an off-by-one here
    // (e.g. accepting a `key_buf` exactly `path.len` bytes short) would have
    // gone unnoticed, silently or by @memcpy panicking on an untrusted-sized
    // caller buffer instead of returning the documented typed error.
    const buf = try build(&.{.{ .key = "hello", .value = 1 }});
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);

    var it1 = try f.prefixIterator(testing.allocator, "");
    defer it1.deinit();
    var too_small: [4]u8 = undefined; // "hello" is 5 bytes
    try testing.expectError(error.KeyTooLong, it1.next(&too_small));

    // A fresh iterator (the failed attempt above already advanced `it1` past
    // "hello" — `next` does not retry a slot it already tried to emit).
    var it2 = try f.prefixIterator(testing.allocator, "");
    defer it2.deinit();
    var just_right: [5]u8 = undefined; // boundary: exactly key.len must succeed
    const c = try it2.next(&just_right);
    try testing.expectEqualStrings("hello", c.?.key);
}

test "topN: a reconstructed key crossing max_depth is KeyTooLong via the path_len gate specifically" {
    // `topNInto`'s DFS depth gate is `path_len >= path_store.len or sp >=
    // stack.len` — two conditions with no call site anywhere in the suite
    // before this. Naively pushing a single very long stored key past
    // `max_depth` from an EMPTY prefix moves `path_len` and `sp` (the DFS
    // stack depth) in lockstep, so it can't tell the two conditions apart —
    // an off-by-one in the `path_len` half specifically would go unnoticed
    // (as verified: reverting that half to `>` alone left this suite green).
    // Using a long PREFIX instead decouples them: `seek` walks the prefix
    // bytes BEFORE topNInto's DFS stack exists at all, so `path_len` starts
    // near the limit already while `sp` starts fresh at 1 and only grows by
    // the short remaining suffix — isolating the `path_len` check.
    var b = try builder.Builder.init(testing.allocator);
    defer b.deinit();
    const prefix_len = max_depth - 5;
    var long_key: [prefix_len + 10]u8 = undefined;
    @memset(long_key[0..prefix_len], 'a');
    @memcpy(long_key[prefix_len..], "bcdefghijk");
    try b.insert(&long_key, 1);
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);

    var results: [1]Completion = undefined;
    var kb: [long_key.len]u8 = undefined;
    try testing.expectError(error.KeyTooLong, f.topN(long_key[0..prefix_len], &results, &kb, .{}));
}

test "loadVerified rejects a body bit-flip that load accepts" {
    const buf = try build(&.{.{ .key = "hello", .value = 7 }});
    defer testing.allocator.free(buf);
    var corrupt = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(corrupt);
    corrupt[format.header_size + 2] ^= 0xff; // flip a node byte
    try testing.expect(Frozen.load(corrupt) != error.BodyCorrupt); // load still opens
    try testing.expectError(error.BodyCorrupt, Frozen.loadVerified(corrupt));
}

test "an edge redirected into trailing padding is rejected, not silently followed" {
    // Real node region: root (1 edge 'h' -> child) + child (terminal, value=1).
    // `node_region_len` declares only these 23 bytes; a further 11 bytes of
    // "padding" (tolerated by `Header.load` for a page-rounded mmap) hold a
    // PLANTED node the root's edge is redirected to point at instead of the
    // real child — A1/trie.md F2.
    const root_off = format.header_size;
    const child_off = root_off + 12; // root: flags(1)+best(4)+edge_count(2)+1 edge(5)
    const region_len = 12 + 11; // + child: flags(1)+value(4)+best(4)+edge_count(2)
    const fake_off = root_off + region_len; // first byte past the declared region

    var buf: [format.header_size + region_len + 11]u8 = undefined;
    // root: non-terminal, 1 edge 'h' -> fake_off (NOT the real child_off)
    buf[root_off] = 0;
    std.mem.writeInt(u32, buf[root_off + 1 .. root_off + 5], 0, .little); // best
    std.mem.writeInt(u16, buf[root_off + 5 .. root_off + 7], 1, .little); // edge_count = 1
    buf[root_off + 7] = 'h';
    std.mem.writeInt(u32, buf[root_off + 8 .. root_off + 12], fake_off, .little);
    // the real child, present so the declared region is self-consistent, but
    // never reached via the redirected edge
    buf[child_off] = format.terminal_bit;
    std.mem.writeInt(u32, buf[child_off + 1 .. child_off + 5], 1, .little); // value
    std.mem.writeInt(u32, buf[child_off + 5 .. child_off + 9], 1, .little); // best
    std.mem.writeInt(u16, buf[child_off + 9 .. child_off + 11], 0, .little); // edge_count = 0
    // the planted node, living entirely in the padding beyond node_region_len
    buf[fake_off] = format.terminal_bit;
    std.mem.writeInt(u32, buf[fake_off + 1 .. fake_off + 5], 0xDEADBEEF, .little); // value
    std.mem.writeInt(u32, buf[fake_off + 5 .. fake_off + 9], 0, .little); // best
    std.mem.writeInt(u16, buf[fake_off + 9 .. fake_off + 11], 0, .little); // edge_count = 0

    const h = format.Header{ .version = format.format_version, .flags = 0, .node_region_len = region_len, .key_count = 1, .root_offset = root_off };
    h.encode(&buf, buf[format.header_size .. format.header_size + region_len]); // CRC covers ONLY the declared region

    // RED (pre-fix shape): `Header.load` + a raw walk over the UNTRUNCATED
    // buffer — exactly what the old `Frozen.load` handed `nodeAt`, since it
    // kept the buffer by reference at full length — follows the redirected
    // edge straight into the padding and reads the planted value back as if
    // it were the real child's.
    {
        const hdr = try format.Header.load(&buf);
        const root = try format.nodeAt(&buf, hdr.root_offset);
        const e = root.findEdge('h').?;
        const got = try format.follow(root, e.child);
        try testing.expect(got.terminal);
        try testing.expectEqual(@as(u32, 0xDEADBEEF), got.value); // padding, not the real child's 1
    }

    // GREEN: the fixed `Frozen.load` bounds its kept slice to exactly
    // `header_size + node_region_len`. `loadVerified` still opens (the CRC
    // never covered the padding either way — that half of the finding does
    // not change), but the SAME redirected edge now lands outside the kept
    // slice and every query on it is rejected instead of resolving.
    const f = try Frozen.loadVerified(&buf);
    try testing.expectError(error.Corrupt, f.lookup("h"));
}

test "prefixIteratorBounded aborts a DAG-shaped buffer long before draining it" {
    // Chain of k levels, each with two edges ('a','b') pointing at the SAME
    // next node: 2^k distinct root-to-leaf paths in O(k) buffer bytes — the
    // shape from A1/trie.md F1 (there measured up to k=60: a 1067-byte file
    // denoting 2^60 keys, "1142 years" to drain). k=20 here keeps the RED
    // side below fast enough to actually run: the module's own measured
    // throughput is ~32M keys/s, so draining 2^20 keys is tens of ms.
    const k: usize = 20;
    const buf = try buildChainDag(testing.allocator, k);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);

    // RED: `prefixIterator` (the only entry point before this fix) has no
    // way to stop early — it decodes every one of the 2^k paths.
    {
        var it = try f.prefixIterator(testing.allocator, "");
        defer it.deinit();
        var kb: [k]u8 = undefined;
        var n: usize = 0;
        while (try it.next(&kb)) |_| n += 1;
        try testing.expectEqual(@as(usize, 1) << 20, n); // all 2^20 keys, no early stop
    }

    // GREEN: the SAME buffer, through `prefixIteratorBounded` with a budget
    // three orders of magnitude below 2^k, aborts with `error.TooComplex`
    // after visiting at most `budget` nodes — nowhere near a full drain.
    {
        const budget: usize = 1000;
        var it = try f.prefixIteratorBounded(testing.allocator, "", budget);
        defer it.deinit();
        var kb: [k]u8 = undefined;
        var n: usize = 0;
        var saw_too_complex = false;
        while (true) {
            const c = it.next(&kb) catch |err| {
                try testing.expectEqual(error.TooComplex, err);
                saw_too_complex = true;
                break;
            };
            if (c == null) break;
            n += 1;
        }
        try testing.expect(saw_too_complex);
        try testing.expect(n <= budget);
    }
}

test "Selector.consider: stride == 0 (key_buf shorter than results.len) is KeyTooLong, not a division by zero" {
    // `stride = key_buf.len / results.len` is 0 whenever `key_buf` is shorter
    // than `results.len`. The `key.len > self.stride` guard alone stops any
    // NON-empty key, but an empty key (len 0) passed it -- and if the
    // selector is already full when a second, better-ranked empty key
    // arrives, the eviction branch divides by `self.stride` (A1/trie.md F5).
    // A real trie stores at most one empty key, so `topN`/`topNInto` cannot
    // reach this today -- exercised directly against the (otherwise private)
    // `Selector` so the guard is tested independent of that call-order
    // reasoning, which is exactly what the finding says was never written
    // down or held by a test.
    var results: [1]Completion = undefined;
    var key_buf: [0]u8 = .{};
    var sel = Selector.init(&results, &key_buf);
    try sel.consider(1, ""); // count 0 -> 1: an empty key fits an empty stride
    try testing.expectError(error.KeyTooLong, sel.consider(2, "")); // would have divided by self.stride == 0
}

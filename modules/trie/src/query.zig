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
pub const QueryError = format.DecodeError || error{KeyTooLong};

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
        return .{ .buf = buf, .header = header };
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
    pub fn prefixIterator(self: Frozen, gpa: Allocator, prefix: []const u8) (QueryError || Allocator.Error)!PrefixIterator {
        return PrefixIterator.init(gpa, self, prefix);
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

    const Frame = struct {
        node: format.NodeView,
        edge_idx: u16 = 0,
        self_done: bool = false,
        /// path length to restore when this frame is popped.
        mark: usize,
    };

    fn init(gpa: Allocator, frozen: Frozen, prefix: []const u8) (QueryError || Allocator.Error)!PrefixIterator {
        var it = PrefixIterator{ .gpa = gpa, .frozen = frozen, .exhausted = false };
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

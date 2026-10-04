// SPDX-License-Identifier: MIT

//! query — the read side: load a frozen buffer and answer queries against it
//! IN PLACE, with no copy of the index and (for `lookup`) no allocation at all.
//!
//! Query shapes:
//!   * `lookup(key)`          — exact match → the stored value, or null.
//!   * `topN(prefix, …)`      — the best N completions under a prefix, ranked,
//!                              with a visit budget (the DoS guard) and an
//!                              `after` cursor for the next page.
//!   * `prefixIterator(pfx)`  — every key under a prefix, in lexicographic order.
//!   * `range(lo, hi)`        — every key in a lexicographic range, in order.
//!   * `prefixesOf(key)` / `longestPrefix(key)` — the stored keys that are
//!                              prefixes of a text (dictionary segmentation,
//!                              longest-prefix match).
//!   * `ordinal(key)` / `keyAt(i)` — a key's rank in sorted order and the key
//!                              at a rank (v2 buffers built with `ordinals`).
//!
//! Both frozen format versions are read; see `format`. Every offset followed
//! out of the (possibly untrusted) buffer is bounds- and invariant-checked in
//! `format`; a corrupt buffer yields `error.Corrupt`, never an OOB read, panic,
//! or infinite loop. Termination is guaranteed by the strictly monotone
//! child-offset invariant enforced in `format.follow`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const format = @import("format.zig");

pub const LoadError = format.LoadError;
pub const QueryError = format.DecodeError || error{ KeyTooLong, TooComplex };
/// `ordinal` / `keyAt` on a buffer without the per-edge counts (any v1
/// buffer, or a v2 buffer frozen without `ordinals`).
pub const OrdinalError = QueryError || error{NoOrdinals};

/// Options controlling `topN`'s bounded work.
pub const QueryOptions = struct {
    /// Maximum number of nodes `topN` may decode before it stops and reports a
    /// truncated result. This is the DoS guard: a one-character prefix over
    /// millions of keys cannot walk the whole set — it stops here. Choose it to
    /// bound worst-case latency; `subtree_best` pruning means well-ranked
    /// queries usually finish far under budget. 0 means "unbounded" (do not use
    /// on untrusted prefixes).
    max_visited: usize = 50_000,
    /// Pagination cursor: when set, only completions ranked strictly AFTER
    /// this one are considered — pass the last item of the previous page to
    /// get the next page. The key is copied before the walk starts, so it may
    /// point into the very `key_buf` this call writes. Each page is a fresh
    /// walk (cost grows with the page number, still capped by `max_visited`).
    after: ?Completion = null,
};

/// One completion returned by `topN` / the iterators. `key` borrows the
/// caller-supplied key buffer (or, for `prefixesOf`, the caller's text), not
/// the frozen index — it is valid until that buffer is reused.
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

/// A lexicographic key range for `Frozen.range`. A null bound is open.
pub const Range = struct {
    lo: ?[]const u8 = null,
    lo_inclusive: bool = true,
    hi: ?[]const u8 = null,
    hi_inclusive: bool = false,
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
        // proved fits. `nodeAt`'s every bounds check is against this slice's
        // `.len`, so this is what keeps a (possibly attacker-chosen) edge from
        // ever resolving into the trailing padding a v1 `Header.load`
        // tolerates on purpose ("an mmap'd file may be page-rounded") — see
        // A1/trie.md F2: without it, `loadVerified` still reports success on a
        // buffer whose padding was silently bit-flipped, because the CRC it
        // checks never covered that padding and neither did any node's bounds
        // check. In v2 the same cut keeps nodes out of the footer.
        const end = header.regionStart() + @as(usize, header.node_region_len);
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

    /// Whether `ordinal` / `keyAt` work on this buffer.
    pub fn hasOrdinals(self: Frozen) bool {
        return self.header.hasOrdinals();
    }

    /// The decoded root node, for walkers outside this module (`fuzzysearch`
    /// runs its own DFS over `format.NodeView`). Children are reached with
    /// `format.follow`; in v2 a child's incoming string is `label ++ tail`.
    pub fn rootNode(self: Frozen) format.DecodeError!format.NodeView {
        if (self.header.version == format.format_version_2) {
            const r = try format.nodeAtV2(self.buf, self.header.root_offset, self.header.hasOrdinals());
            if (r.tail.len != 0) return error.Corrupt; // a root has no incoming edge
            return r;
        }
        return format.nodeAt(self.buf, self.header.root_offset);
    }

    const Seek = struct {
        node: format.NodeView,
        /// The part of `node`'s incoming tail AFTER the end of the prefix: a
        /// v2 prefix may end in the middle of a compressed edge. Empty when the
        /// prefix ends exactly at `node`.
        rest: []const u8,
    };

    /// Walk from the root consuming every byte of `prefix`. Returns the node
    /// whose subtree holds exactly the keys starting with `prefix`, or null if
    /// no stored key does. Bounded by `prefix.len`.
    fn seek(self: Frozen, prefix: []const u8) QueryError!?Seek {
        var node = try self.rootNode();
        var i: usize = 0;
        while (i < prefix.len) {
            const e = node.findEdge(prefix[i]) orelse return null;
            node = try format.follow(node, e.child);
            i += 1;
            const t = node.tail;
            const m = @min(t.len, prefix.len - i);
            if (!std.mem.eql(u8, t[0..m], prefix[i..][0..m])) return null;
            i += m;
            if (m < t.len) return .{ .node = node, .rest = t[m..] };
        }
        return .{ .node = node, .rest = "" };
    }

    /// Exact lookup: the value stored for `key`, or null if `key` is not a
    /// stored key. Zero allocation; O(key.len) node decodes.
    pub fn lookup(self: Frozen, key: []const u8) QueryError!?u32 {
        const s = (try self.seek(key)) orelse return null;
        if (s.rest.len != 0) return null;
        return if (s.node.terminal) s.node.value else null;
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
    /// ⚠ Unbounded: nothing in the v1 wire format forbids two edges from
    /// pointing at the same child (v2 likewise), so a buffer that is not
    /// self-built (or otherwise trusted) can encode far more keys than its size
    /// suggests — a buffer under 1 KB can be built to enumerate 2^60 keys
    /// (A1/trie.md F1). Over an untrusted buffer, use `prefixIteratorBounded`.
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

    /// Iterate every key in `r` in lexicographic order (BurntSushi/fst's
    /// `range`). Positioning on `r.lo` costs O(lo.len) node decodes; after
    /// that each key costs what `prefixIterator` pays. `max_visited` bounds
    /// the whole iteration like `prefixIteratorBounded` (0 = unbounded, for
    /// self-built buffers only). For "the next page after key K", use
    /// `.{ .lo = K, .lo_inclusive = false }`.
    pub fn range(
        self: Frozen,
        gpa: Allocator,
        r: Range,
        max_visited: usize,
    ) (QueryError || Allocator.Error)!PrefixIterator {
        return PrefixIterator.initRange(gpa, self, r, max_visited);
    }

    /// Iterate the stored keys that are prefixes of `text`, shortest first
    /// (marisa-trie's common-prefix search; darts' `commonPrefixSearch`). No
    /// allocation; each `Completion.key` is a slice of `text`. O(text.len)
    /// node decodes over the whole iteration.
    pub fn prefixesOf(self: Frozen, text: []const u8) QueryError!PrefixesOf {
        return .{ .node = try self.rootNode(), .text = text };
    }

    /// The longest stored key that is a prefix of `text`, or null.
    pub fn longestPrefix(self: Frozen, text: []const u8) QueryError!?Completion {
        var it = try self.prefixesOf(text);
        var best: ?Completion = null;
        while (try it.next()) |c| best = c;
        return best;
    }

    /// The rank of `key` among the stored keys in ascending byte order
    /// (0-based), or null when `key` is not stored. O(key.len) node decodes,
    /// no allocation. Needs a v2 buffer frozen with `.ordinals = true`.
    pub fn ordinal(self: Frozen, key: []const u8) OrdinalError!?u32 {
        var node = try self.rootNode();
        if (!self.header.hasOrdinals()) return error.NoOrdinals;
        var acc: u64 = 0;
        var i: usize = 0;
        while (i < key.len) {
            // The node's own key is a proper prefix of `key`: it sorts first.
            if (node.terminal) acc += 1;
            const e = node.findEdge(key[i]) orelse return null;
            acc += e.before;
            node = try format.follow(node, e.child);
            i += 1;
            const t = node.tail;
            if (key.len - i < t.len or !std.mem.eql(u8, t, key[i..][0..t.len])) return null;
            i += t.len;
        }
        if (!node.terminal) return null;
        if (acc > std.math.maxInt(u32)) return error.Corrupt;
        return @intCast(acc);
    }

    /// The key at rank `i` (0-based, ascending byte order) and its value,
    /// reconstructed into `key_buf`; null when `i >= keyCount()`. The inverse
    /// of `ordinal` — marisa-trie's reverse lookup. O(depth · log 256) node
    /// work, no allocation. Needs a v2 buffer frozen with `.ordinals = true`.
    pub fn keyAt(self: Frozen, i: u32, key_buf: []u8) OrdinalError!?Completion {
        var node = try self.rootNode();
        if (!self.header.hasOrdinals()) return error.NoOrdinals;
        if (i >= self.header.key_count) return null;
        var rem: u64 = i;
        var len: usize = 0;
        while (true) {
            if (node.terminal) {
                if (rem == 0) return .{ .value = node.value, .key = key_buf[0..len] };
                rem -= 1;
            }
            // The header promised a key at this rank, so it must lie below.
            if (node.edge_count == 0) return error.Corrupt;
            // The last edge whose `before` is ≤ rem.
            var lo: usize = 0;
            var hi: usize = node.edge_count;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (node.edge(mid).before <= rem) lo = mid + 1 else hi = mid;
            }
            if (lo == 0) return error.Corrupt;
            const e = node.edge(lo - 1);
            rem -= e.before;
            const child = try format.follow(node, e.child);
            if (len + 1 + child.tail.len > key_buf.len) return error.KeyTooLong;
            key_buf[len] = e.label;
            @memcpy(key_buf[len + 1 ..][0..child.tail.len], child.tail);
            len += 1 + child.tail.len;
            node = child;
        }
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
    /// Pagination: only items ranked strictly after this are kept.
    after: ?Completion = null,

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
        if (self.after) |a| if (!better(a.value, a.key, value, key)) return;
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
    // The cursor key may alias `key_buf`, which the walk overwrites: copy it.
    var after_store: [max_depth]u8 = undefined;
    if (opts.after) |a| {
        if (a.key.len > after_store.len) return error.KeyTooLong;
        @memcpy(after_store[0..a.key.len], a.key);
        sel.after = .{ .value = a.value, .key = after_store[0..a.key.len] };
    }
    const s = (try self.seek(prefix)) orelse
        return .{ .items = results[0..0], .status = .complete };
    const sub = s.node;

    // Reconstructed-key path buffer (prefix + the rest of a compressed edge
    // the prefix ended in + labels and tails below), and the DFS frame stack.
    var path_store: [max_depth]u8 = undefined;
    if (prefix.len + s.rest.len > path_store.len) return error.KeyTooLong;
    @memcpy(path_store[0..prefix.len], prefix);
    @memcpy(path_store[prefix.len..][0..s.rest.len], s.rest);
    var path_len: usize = prefix.len + s.rest.len;

    const Frame = struct { node: format.NodeView, edge_idx: u16, mark: usize };
    var stack: [max_depth]Frame = undefined;
    var sp: usize = 0;
    stack[sp] = .{ .node = sub, .edge_idx = 0, .mark = path_len };
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

            if (path_len + 1 + child.tail.len > path_store.len or sp >= stack.len) return error.KeyTooLong;
            const mark = path_len;
            path_store[path_len] = e.label;
            @memcpy(path_store[path_len + 1 ..][0..child.tail.len], child.tail);
            path_len += 1 + child.tail.len;
            if (child.terminal) try sel.consider(child.value, path_store[0..path_len]);
            stack[sp] = .{ .node = child, .edge_idx = 0, .mark = mark };
            sp += 1;
        } else {
            path_len = top.mark;
            sp -= 1;
        }
    }

    return .{ .items = results[0..sel.count], .status = status };
}

// ── key iterator (prefix and range) ──────────────────────────────────────────

/// Lexicographic-order iterator over the keys under a prefix (`prefixIterator`)
/// or in a range (`range`). Pull-based: the caller paces the work (the natural
/// bound for enumeration), and each `next` reconstructs the key into a caller
/// buffer. The frozen index is never copied.
pub const PrefixIterator = struct {
    gpa: Allocator,
    frozen: Frozen,
    /// Reconstructed key so far (labels and tails along the DFS path).
    path: std.ArrayListUnmanaged(u8) = .empty,
    stack: std.ArrayListUnmanaged(Frame) = .empty,
    /// Exclusive upper bound (owned), null when open.
    hi: ?[]u8 = null,
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
        var it = PrefixIterator{ .gpa = gpa, .frozen = frozen, .max_visited = max_visited };
        errdefer it.deinit();
        const s = (try frozen.seek(prefix)) orelse return it;
        try it.path.appendSlice(gpa, prefix);
        try it.path.appendSlice(gpa, s.rest);
        try it.stack.append(gpa, .{ .node = s.node, .mark = it.path.items.len });
        return it;
    }

    fn initRange(gpa: Allocator, frozen: Frozen, r: Range, max_visited: usize) (QueryError || Allocator.Error)!PrefixIterator {
        var it = PrefixIterator{ .gpa = gpa, .frozen = frozen, .max_visited = max_visited };
        errdefer it.deinit();

        // Normalize to [lo, hi): K ++ 0x00 is the immediate successor of K in
        // byte order, so an exclusive lo and an inclusive hi both become it.
        var lo_owned: std.ArrayListUnmanaged(u8) = .empty;
        defer lo_owned.deinit(gpa);
        if (r.lo) |lo| {
            try lo_owned.appendSlice(gpa, lo);
            if (!r.lo_inclusive) try lo_owned.append(gpa, 0);
        }
        const lo = lo_owned.items;
        if (r.hi) |hi| {
            const h = try gpa.alloc(u8, hi.len + @intFromBool(r.hi_inclusive));
            @memcpy(h[0..hi.len], hi);
            if (r.hi_inclusive) h[hi.len] = 0;
            it.hi = h;
            if (std.mem.order(u8, lo, h) != .lt) return it; // empty range
        }

        // Descend along `lo`, leaving every frame positioned at its first edge
        // whose subtree can hold a key ≥ lo. Invariant: path == lo[0..path.len].
        var node = try frozen.rootNode();
        var mark: usize = 0;
        while (true) {
            const d = it.path.items.len;
            if (d == lo.len) {
                try it.stack.append(gpa, .{ .node = node, .mark = mark });
                break;
            }
            const b = lo[d];
            // First edge with label ≥ b.
            var lo_i: usize = 0;
            var hi_i: usize = node.edge_count;
            while (lo_i < hi_i) {
                const mid = lo_i + (hi_i - lo_i) / 2;
                if (node.edge(mid).label < b) lo_i = mid + 1 else hi_i = mid;
            }
            // This node's own key is a proper prefix of lo: below the range.
            var frame = Frame{ .node = node, .edge_idx = @intCast(lo_i), .self_done = true, .mark = mark };
            if (lo_i == node.edge_count or node.edge(lo_i).label != b) {
                try it.stack.append(gpa, frame);
                break;
            }
            const e = node.edge(lo_i);
            const child = try format.follow(node, e.child);
            const t = child.tail;
            const want = lo[d + 1 ..];
            const m = @min(t.len, want.len);
            switch (std.mem.order(u8, t[0..m], want[0..m])) {
                // The whole child subtree sorts below lo: start after it.
                .lt => frame.edge_idx += 1,
                // The whole child subtree sorts above lo: start at it.
                .gt => {},
                .eq => if (m == t.len) {
                    // The edge is a prefix of the rest of lo: descend.
                    frame.edge_idx += 1;
                    try it.stack.append(gpa, frame);
                    mark = d;
                    try it.path.append(gpa, b);
                    try it.path.appendSlice(gpa, t);
                    node = child;
                    continue;
                },
                // .eq with m < t.len: lo ends inside the edge, so every key
                // below it is longer than lo with lo as prefix — above lo.
            }
            try it.stack.append(gpa, frame);
            break;
        }
        return it;
    }

    pub fn deinit(self: *PrefixIterator) void {
        self.path.deinit(self.gpa);
        self.stack.deinit(self.gpa);
        if (self.hi) |h| self.gpa.free(h);
        self.* = undefined;
    }

    /// Next key, in lexicographic order, reconstructed into `key_buf` (which
    /// the returned `key` borrows). null when exhausted. `error.KeyTooLong` if
    /// a key does not fit `key_buf`.
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
                const mark = self.path.items.len;
                try self.path.append(self.gpa, e.label);
                try self.path.appendSlice(self.gpa, child.tail);
                if (self.hi) |h| if (std.mem.order(u8, self.path.items, h) != .lt) {
                    // Every key from here on starts with this path or sorts
                    // after it: all ≥ hi. Done.
                    self.stack.clearRetainingCapacity();
                    return null;
                };
                try self.stack.append(self.gpa, .{ .node = child, .mark = mark });
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

/// The name for a range iterator; the same type as `PrefixIterator`.
pub const KeyIterator = PrefixIterator;

/// Iterator over the stored keys that are prefixes of a text; see
/// `Frozen.prefixesOf`. Allocation-free; every step moves strictly forward in
/// the text, so it decodes at most `text.len + 1` nodes.
pub const PrefixesOf = struct {
    node: ?format.NodeView,
    text: []const u8,
    pos: usize = 0,
    self_pending: bool = true,

    pub fn next(self: *PrefixesOf) QueryError!?Completion {
        while (self.node) |node| {
            if (self.self_pending) {
                self.self_pending = false;
                if (node.terminal) return .{ .value = node.value, .key = self.text[0..self.pos] };
            }
            self.node = null;
            if (self.pos == self.text.len) break;
            const e = node.findEdge(self.text[self.pos]) orelse break;
            const child = try format.follow(node, e.child);
            const t = child.tail;
            const at = self.pos + 1;
            if (self.text.len - at < t.len or !std.mem.eql(u8, t, self.text[at..][0..t.len])) break;
            self.pos = at + t.len;
            self.node = child;
            self.self_pending = true;
        }
        return null;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const builder = @import("builder.zig");
const testing = std.testing;

fn build(pairs: []const builder.Pair) ![]u8 {
    return builder.freezeFromPairs(testing.allocator, testing.allocator, pairs);
}

fn buildWith(pairs: []const builder.Pair, opts: builder.FreezeOptions) ![]u8 {
    return builder.freezeFromPairsWith(testing.allocator, testing.allocator, pairs, opts);
}

/// Every format the writer can produce; format-independent tests run on all.
const all_formats = [_]builder.FreezeOptions{ .v1, .{ .v2 = .{} }, .{ .v2 = .{ .ordinals = true } } };

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
    // Version 1 specifically: one node per byte is what makes `sp` grow by
    // one per suffix byte. (In v2 the suffix is one compressed edge; the
    // test below covers that path.)
    const buf = try b.freezeWith(testing.allocator, .v1);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);

    var results: [1]Completion = undefined;
    var kb: [long_key.len]u8 = undefined;
    try testing.expectError(error.KeyTooLong, f.topN(long_key[0..prefix_len], &results, &kb, .{}));
}

test "topN (v2): a key whose compressed edge would cross max_depth is KeyTooLong, at the boundary exactly" {
    // Two keys share max_depth - 5 bytes, then diverge into 5- and 6-byte
    // tails: the 5-byte one ends exactly at max_depth (fits), the 6-byte one
    // one byte past it. The check is `path_len + 1 + tail.len > max_depth`.
    var b = try builder.Builder.init(testing.allocator);
    defer b.deinit();
    var k1: [max_depth]u8 = undefined;
    @memset(&k1, 'a');
    k1[max_depth - 5] = 'b';
    var k2: [max_depth + 1]u8 = undefined;
    @memset(&k2, 'a');
    k2[max_depth - 5] = 'c';
    try b.insert(&k1, 1);
    const buf1 = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf1);
    const f1 = try Frozen.load(buf1);
    var results: [2]Completion = undefined;
    var kb: [2 * (max_depth + 1)]u8 = undefined;
    const r = try f1.topN(k1[0 .. max_depth - 5], &results, &kb, .{});
    try testing.expectEqual(@as(usize, 1), r.items.len);
    try testing.expectEqual(max_depth, r.items[0].key.len);

    try b.insert(&k2, 2);
    const buf2 = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf2);
    const f2 = try Frozen.load(buf2);
    try testing.expectError(error.KeyTooLong, f2.topN(k1[0 .. max_depth - 5], &results, &kb, .{}));
}

test "loadVerified rejects a body bit-flip that load accepts" {
    for (all_formats) |fmt| {
        const buf = try buildWith(&.{.{ .key = "hello", .value = 7 }}, fmt);
        defer testing.allocator.free(buf);
        var corrupt = try testing.allocator.dupe(u8, buf);
        defer testing.allocator.free(corrupt);
        // A byte inside the node region: v1 nodes start at 36, v2 at 12 (and
        // v2's last 24 bytes are the footer, which the footer CRC guards).
        const h = try format.Header.load(buf);
        corrupt[h.regionStart() + 2] ^= 0xff;
        try testing.expect(Frozen.load(corrupt) != error.BodyCorrupt); // load still opens
        try testing.expectError(error.BodyCorrupt, Frozen.loadVerified(corrupt));
    }
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

test "a prefix ending inside a compressed edge still finds the keys below it" {
    // v2 stores "carpet" under 'c' with tail "arpet"; the prefix "carp" ends
    // inside that tail. lookup("carp") must miss (not a stored key), while the
    // prefix queries must reconstruct the FULL key, not "carp".
    for (all_formats) |fmt| {
        const buf = try buildWith(&.{ .{ .key = "carpet", .value = 3 }, .{ .key = "dog", .value = 1 } }, fmt);
        defer testing.allocator.free(buf);
        const f = try Frozen.load(buf);
        try testing.expectEqual(@as(?u32, null), try f.lookup("carp"));
        try testing.expectEqual(@as(?u32, null), try f.lookup("carpets"));
        try testing.expectEqual(@as(?u32, null), try f.lookup("carx"));
        try testing.expectEqual(@as(?u32, 3), try f.lookup("carpet"));
        var it = try f.prefixIterator(testing.allocator, "carp");
        defer it.deinit();
        var kb: [16]u8 = undefined;
        try testing.expectEqualStrings("carpet", (try it.next(&kb)).?.key);
        try testing.expect((try it.next(&kb)) == null);
        var results: [2]Completion = undefined;
        var tkb: [32]u8 = undefined;
        const r = try f.topN("carp", &results, &tkb, .{});
        try testing.expectEqual(@as(usize, 1), r.items.len);
        try testing.expectEqualStrings("carpet", r.items[0].key);
        try testing.expectEqual(@as(usize, 0), (try f.topN("carx", &results, &tkb, .{})).items.len);
    }
}

test "range: bounds, inclusivity, and lo inside / beyond a compressed edge" {
    // Sorted keys: "", a, ab, abc, abd, b, ba. Expected sets are read off that
    // list by hand.
    const pairs = [_]builder.Pair{
        .{ .key = "", .value = 0 },    .{ .key = "a", .value = 1 },   .{ .key = "ab", .value = 2 },
        .{ .key = "abc", .value = 3 }, .{ .key = "abd", .value = 4 }, .{ .key = "b", .value = 5 },
        .{ .key = "ba", .value = 6 },
    };
    const Case = struct { r: Range, want: []const []const u8 };
    const cases = [_]Case{
        .{ .r = .{}, .want = &.{ "", "a", "ab", "abc", "abd", "b", "ba" } },
        .{ .r = .{ .lo = "ab" }, .want = &.{ "ab", "abc", "abd", "b", "ba" } },
        .{ .r = .{ .lo = "ab", .lo_inclusive = false }, .want = &.{ "abc", "abd", "b", "ba" } },
        .{ .r = .{ .lo = "abb" }, .want = &.{ "abc", "abd", "b", "ba" } }, // lo not stored
        .{ .r = .{ .lo = "abz" }, .want = &.{ "b", "ba" } }, // past a whole subtree
        .{ .r = .{ .hi = "abd" }, .want = &.{ "", "a", "ab", "abc" } },
        .{ .r = .{ .hi = "abd", .hi_inclusive = true }, .want = &.{ "", "a", "ab", "abc", "abd" } },
        .{ .r = .{ .lo = "a", .hi = "b" }, .want = &.{ "a", "ab", "abc", "abd" } },
        .{ .r = .{ .lo = "b", .hi = "b" }, .want = &.{} }, // empty
        .{ .r = .{ .lo = "c", .hi = "a" }, .want = &.{} }, // inverted
        .{ .r = .{ .lo = "", .lo_inclusive = false }, .want = &.{ "a", "ab", "abc", "abd", "b", "ba" } },
        .{ .r = .{ .lo = "zzz" }, .want = &.{} },
    };
    for (all_formats) |fmt| {
        const buf = try buildWith(&pairs, fmt);
        defer testing.allocator.free(buf);
        const f = try Frozen.load(buf);
        for (cases) |c| {
            var it = try f.range(testing.allocator, c.r, 0);
            defer it.deinit();
            var kb: [8]u8 = undefined;
            for (c.want) |w| try testing.expectEqualStrings(w, (try it.next(&kb)).?.key);
            try testing.expect((try it.next(&kb)) == null);
        }
    }
    // lo ending inside a v2 compressed edge: "carpet" is one edge below the
    // root, lo = "carp" must still return it, lo = "carq" must not.
    const buf = try build(&.{ .{ .key = "carpet", .value = 1 }, .{ .key = "dog", .value = 2 } });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var kb: [8]u8 = undefined;
    {
        var it = try f.range(testing.allocator, .{ .lo = "carp" }, 0);
        defer it.deinit();
        try testing.expectEqualStrings("carpet", (try it.next(&kb)).?.key);
        try testing.expectEqualStrings("dog", (try it.next(&kb)).?.key);
    }
    {
        var it = try f.range(testing.allocator, .{ .lo = "carq", .hi = "carz" }, 0);
        defer it.deinit();
        try testing.expect((try it.next(&kb)) == null);
    }
}

test "prefixesOf / longestPrefix: every stored prefix of a text, shortest first" {
    for (all_formats) |fmt| {
        const buf = try buildWith(&.{
            .{ .key = "", .value = 9 },       .{ .key = "pra", .value = 1 },
            .{ .key = "praha", .value = 2 },  .{ .key = "prahasever", .value = 3 },
            .{ .key = "prague", .value = 4 },
        }, fmt);
        defer testing.allocator.free(buf);
        const f = try Frozen.load(buf);
        var it = try f.prefixesOf("prahase");
        const want = [_][]const u8{ "", "pra", "praha" };
        for (want) |w| try testing.expectEqualStrings(w, (try it.next()).?.key);
        try testing.expect((try it.next()) == null);
        try testing.expectEqualStrings("prahasever", (try f.longestPrefix("prahasevernibrno")).?.key);
        try testing.expectEqualStrings("", (try f.longestPrefix("brno")).?.key);
    }
}

test "ordinal / keyAt are inverse over every stored key, and refuse buffers without counts" {
    const pairs = [_]builder.Pair{
        .{ .key = "b", .value = 1 }, .{ .key = "", .value = 2 },    .{ .key = "ab", .value = 3 },
        .{ .key = "a", .value = 4 }, .{ .key = "abc", .value = 5 }, .{ .key = "ba", .value = 6 },
    };
    // Sorted: "", a, ab, abc, b, ba → ranks 0..5.
    const sorted = [_][]const u8{ "", "a", "ab", "abc", "b", "ba" };
    const buf = try buildWith(&pairs, .{ .v2 = .{ .ordinals = true } });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var kb: [8]u8 = undefined;
    for (sorted, 0..) |k, i| {
        try testing.expectEqual(@as(?u32, @intCast(i)), try f.ordinal(k));
        try testing.expectEqualStrings(k, (try f.keyAt(@intCast(i), &kb)).?.key);
    }
    try testing.expectEqual(@as(?Completion, null), try f.keyAt(sorted.len, &kb));
    try testing.expectEqual(@as(?u32, null), try f.ordinal("abd"));
    try testing.expectEqual(@as(?u32, null), try f.ordinal("aa"));
    var tiny: [2]u8 = undefined;
    try testing.expectError(error.KeyTooLong, f.keyAt(3, &tiny));

    for ([_]builder.FreezeOptions{ .v1, .{ .v2 = .{} } }) |fmt| {
        const plain = try buildWith(&pairs, fmt);
        defer testing.allocator.free(plain);
        const g = try Frozen.load(plain);
        try testing.expectError(error.NoOrdinals, g.ordinal("a"));
        try testing.expectError(error.NoOrdinals, g.keyAt(0, &kb));
    }
}

test "topN pagination: pages chained by `after` enumerate the whole ranking once" {
    // Values with ties so the key tie-break matters across page boundaries.
    const pairs = [_]builder.Pair{
        .{ .key = "a1", .value = 5 },  .{ .key = "a2", .value = 9 }, .{ .key = "a3", .value = 5 },
        .{ .key = "a4", .value = 1 },  .{ .key = "a5", .value = 5 }, .{ .key = "a6", .value = 7 },
        .{ .key = "b", .value = 100 },
    };
    // By (value desc, key asc): a2 9, a6 7, a1 5, a3 5, a5 5, a4 1.
    const want = [_][]const u8{ "a2", "a6", "a1", "a3", "a5", "a4" };
    for (all_formats) |fmt| {
        const buf = try buildWith(&pairs, fmt);
        defer testing.allocator.free(buf);
        const f = try Frozen.load(buf);
        var results: [2]Completion = undefined;
        var kb: [2 * 8]u8 = undefined;
        var got: usize = 0;
        var after: ?Completion = null;
        while (true) {
            // The same key_buf every page: `after.key` points into it.
            const r = try f.topN("a", &results, &kb, .{ .after = after });
            if (r.items.len == 0) break;
            for (r.items) |c| {
                try testing.expectEqualStrings(want[got], c.key);
                got += 1;
            }
            after = r.items[r.items.len - 1];
        }
        try testing.expectEqual(want.len, got);
    }
}

test "rootNode refuses a v2 root carrying a tail" {
    // Hand-made v2 buffer: one node (the root), terminal, tail "x". A root has
    // no incoming edge, so a tail there is corruption, not data.
    const node = [_]u8{ format.terminal_bit, 1, 'x', 7, 0, 0, 0 };
    var buf: [format.v2_front_size + node.len + format.v2_footer_size]u8 = undefined;
    @memcpy(buf[0..4], format.magic);
    std.mem.writeInt(u16, buf[4..6], format.format_version_2, .little);
    std.mem.writeInt(u16, buf[6..8], format.endian_marker, .little);
    std.mem.writeInt(u32, buf[8..12], 0, .little);
    @memcpy(buf[12..][0..node.len], &node);
    const foot = buf[12 + node.len ..];
    std.mem.writeInt(u32, foot[0..4], node.len, .little);
    std.mem.writeInt(u32, foot[4..8], 12, .little);
    std.mem.writeInt(u64, foot[8..16], 1, .little);
    std.mem.writeInt(u32, foot[16..20], std.hash.Crc32.hash(&node), .little);
    var c = std.hash.Crc32.init();
    c.update(buf[0..12]);
    c.update(foot[0..20]);
    std.mem.writeInt(u32, foot[20..24], c.final(), .little);
    const f = try Frozen.loadVerified(&buf);
    try testing.expectError(error.Corrupt, f.lookup(""));
    // Positive control: the same node with tail_len 0 is a valid one-key index.
    const ok_node = [_]u8{ format.terminal_bit, 0, 7, 0, 0, 0 };
    var ok: [format.v2_front_size + ok_node.len + format.v2_footer_size]u8 = undefined;
    @memcpy(ok[0..12], buf[0..12]);
    @memcpy(ok[12..][0..ok_node.len], &ok_node);
    const of = ok[12 + ok_node.len ..];
    std.mem.writeInt(u32, of[0..4], ok_node.len, .little);
    std.mem.writeInt(u32, of[4..8], 12, .little);
    std.mem.writeInt(u64, of[8..16], 1, .little);
    std.mem.writeInt(u32, of[16..20], std.hash.Crc32.hash(&ok_node), .little);
    var c2 = std.hash.Crc32.init();
    c2.update(ok[0..12]);
    c2.update(of[0..20]);
    std.mem.writeInt(u32, of[20..24], c2.final(), .little);
    const g = try Frozen.loadVerified(&ok);
    try testing.expectEqual(@as(?u32, 7), try g.lookup(""));
}

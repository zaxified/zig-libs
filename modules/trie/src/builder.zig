// SPDX-License-Identifier: MIT

//! builder — the BUILD phase: construct an in-memory trie from
//! `(key, value)` pairs, then FREEZE it into the flat `format` byte buffer.
//!
//! The in-memory trie is a plain pointer-free node pool: nodes reference their
//! children by node id. A key invariant falls out of the construction order —
//! a child node is always appended to the pool AFTER its parent, so a child's
//! id is always greater than its parent's. Because `freeze` emits nodes in id
//! order, that becomes the on-disk "child offset strictly greater than parent
//! offset" invariant the query path relies on for guaranteed termination.
//!
//! Duplicate keys: **last write wins.** Inserting the same key twice keeps the
//! value from the later `insert` call. This mirrors a map/dictionary and is the
//! behaviour the RÚIAN-style consumer wants (re-ingesting a record updates it).

const std = @import("std");
const Allocator = std.mem.Allocator;
const format = @import("format.zig");

pub const BuildError = error{OutOfMemory};

pub const FreezeError = error{
    OutOfMemory,
    /// The serialized node region would exceed the u32 offset space (~4 GiB).
    /// Far beyond the intended millions-of-keys workload; reported, never
    /// silently truncated.
    TooLarge,
};

/// Sentinel "no edge" index — the empty first_edge / end of a sibling list.
const no_edge: u32 = std.math.maxInt(u32);

/// One in-memory trie node. Children are an intrusive singly-linked sibling
/// list threaded through the builder-global `edges` pool (`first_edge` heads
/// the list, each `Edge.next` chains on); this keeps the whole trie in just TWO
/// growable pools (`nodes` + `edges`) with amortized O(1) allocations total,
/// instead of two grow-by-doubling arrays PER node. `best` is filled in by
/// `freeze`'s post-order pass. The sibling list is unordered during build;
/// `freeze` sorts each node's edges by label (the format requires ascending
/// labels for the query-side binary search).
const Node = struct {
    terminal: bool = false,
    value: u32 = 0,
    best: u32 = 0,
    first_edge: u32 = no_edge,
    edge_count: u16 = 0,
};

/// One parent→child edge in the builder-global pool. `child` is a node id;
/// `next` chains to the next sibling under the same parent (or `no_edge`).
const Edge = struct {
    label: u8,
    child: u32,
    next: u32,
};

/// Incremental trie builder. Insert `(key, value)` pairs in any order, then
/// `freeze` once. Not reusable after `freeze` consumes it (call `deinit` if you
/// abandon a builder without freezing).
///
/// Memory: exactly two growable pools (`nodes`, `edges`), each doubling only
/// O(log N) times over the WHOLE build — so a millions-of-keys build is a
/// handful of allocations, not millions of tiny ones. That makes build RSS both
/// low (~32 B/node) and allocator-insensitive: it no longer explodes under a
/// debug/safety allocator, which is what previously OOM'd a large build.
pub const Builder = struct {
    gpa: Allocator,
    nodes: std.ArrayListUnmanaged(Node),
    edges: std.ArrayListUnmanaged(Edge),
    key_count: u64 = 0,

    pub fn init(gpa: Allocator) BuildError!Builder {
        var nodes: std.ArrayListUnmanaged(Node) = .empty;
        try nodes.append(gpa, .{}); // node 0 = root
        return .{ .gpa = gpa, .nodes = nodes, .edges = .empty };
    }

    pub fn deinit(self: *Builder) void {
        self.nodes.deinit(self.gpa);
        self.edges.deinit(self.gpa);
        self.* = undefined;
    }

    /// Index of the edge under node `parent` whose label is `b`, or `no_edge`.
    /// Linear over the sibling list — child counts are tiny (≤ 256 distinct
    /// byte labels, in practice a handful).
    fn findChildEdge(self: *const Builder, parent: u32, b: u8) u32 {
        var e = self.nodes.items[parent].first_edge;
        while (e != no_edge) : (e = self.edges.items[e].next) {
            if (self.edges.items[e].label == b) return e;
        }
        return no_edge;
    }

    /// Insert or overwrite `key` → `value`. Arbitrary bytes; the empty key is
    /// allowed (it marks the root terminal). Last write wins for duplicates.
    pub fn insert(self: *Builder, key: []const u8, value: u32) BuildError!void {
        var cur: u32 = 0; // root
        for (key) |b| {
            const found = self.findChildEdge(cur, b);
            if (found != no_edge) {
                cur = self.edges.items[found].child;
            } else {
                // Append the child node and its edge to the global pools (each
                // may realloc). Read the parent's old list head BEFORE the
                // appends, then re-index the parent by id afterwards — never
                // hold a pointer across an append.
                const new_id: u32 = @intCast(self.nodes.items.len);
                const prev_head = self.nodes.items[cur].first_edge;
                try self.nodes.append(self.gpa, .{});
                const new_edge: u32 = @intCast(self.edges.items.len);
                try self.edges.append(self.gpa, .{ .label = b, .child = new_id, .next = prev_head });
                const parent = &self.nodes.items[cur];
                parent.first_edge = new_edge; // prepend (order fixed at freeze)
                parent.edge_count += 1;
                cur = new_id;
            }
        }
        const n = &self.nodes.items[cur];
        if (!n.terminal) self.key_count += 1;
        n.terminal = true;
        n.value = value; // last write wins
    }

    /// Serialize the trie into a freshly-allocated frozen buffer (caller owns
    /// and frees it). The builder is left intact and may be frozen again.
    pub fn freeze(self: *Builder, out_gpa: Allocator) FreezeError![]u8 {
        // 1. Post-order max: because a child's id always exceeds its parent's,
        //    iterating ids in reverse visits every child before its parent.
        {
            var i: usize = self.nodes.items.len;
            while (i > 0) {
                i -= 1;
                const n = &self.nodes.items[i];
                var best: u32 = if (n.terminal) n.value else 0;
                var e = n.first_edge;
                while (e != no_edge) : (e = self.edges.items[e].next) {
                    best = @max(best, self.nodes.items[self.edges.items[e].child].best);
                }
                n.best = best;
            }
        }

        // 2. Assign each node an absolute offset (prefix sum of node sizes).
        const n_nodes = self.nodes.items.len;
        const offsets = try out_gpa.alloc(u32, n_nodes);
        defer out_gpa.free(offsets);
        var cursor: usize = format.header_size;
        for (self.nodes.items, 0..) |*n, i| {
            if (cursor > std.math.maxInt(u32)) return error.TooLarge;
            offsets[i] = @intCast(cursor);
            cursor += nodeSize(n);
        }
        const total = cursor;
        if (total - format.header_size > std.math.maxInt(u32)) return error.TooLarge;

        // 3. Lay down the buffer: header placeholder + node region.
        const buf = try out_gpa.alloc(u8, total);
        errdefer out_gpa.free(buf);
        var p: usize = format.header_size;
        for (self.nodes.items) |*n| {
            var flags: u8 = 0;
            if (n.terminal) flags |= format.terminal_bit;
            buf[p] = flags;
            p += format.flags_size;
            if (n.terminal) {
                std.mem.writeInt(u32, buf[p .. p + 4][0..4], n.value, .little);
                p += format.value_size;
            }
            std.mem.writeInt(u32, buf[p .. p + 4][0..4], n.best, .little);
            p += format.best_size;
            std.mem.writeInt(u16, buf[p .. p + 2][0..2], n.edge_count, .little);
            p += format.edge_count_size;
            // Collect this node's sibling list and sort by label ascending — the
            // format (and the query-side binary search) require ordered edges.
            // A node has at most 256 distinct byte labels, so a fixed buffer and
            // a small sort suffice; no allocation.
            var tmp: [256]Edge = undefined;
            var cnt: usize = 0;
            var e = n.first_edge;
            while (e != no_edge) : (e = self.edges.items[e].next) {
                tmp[cnt] = self.edges.items[e];
                cnt += 1;
            }
            std.debug.assert(cnt == n.edge_count);
            std.mem.sort(Edge, tmp[0..cnt], {}, edgeLabelLess);
            for (tmp[0..cnt]) |edge| {
                buf[p] = edge.label;
                std.mem.writeInt(u32, buf[p + 1 .. p + 5][0..4], offsets[edge.child], .little);
                p += format.edge_size;
            }
        }
        std.debug.assert(p == total);

        const header = format.Header{
            .version = format.format_version,
            .flags = 0,
            .node_region_len = @intCast(total - format.header_size),
            .key_count = self.key_count,
            .root_offset = format.header_size,
        };
        header.encode(buf, buf[format.header_size..]);
        return buf;
    }
};

fn edgeLabelLess(_: void, a: Edge, b: Edge) bool {
    return a.label < b.label;
}

fn nodeSize(n: *const Node) usize {
    var s: usize = format.flags_size + format.best_size + format.edge_count_size;
    if (n.terminal) s += format.value_size;
    s += @as(usize, n.edge_count) * format.edge_size;
    return s;
}

/// Convenience: build + freeze from a slice of pairs in one call.
pub const Pair = struct { key: []const u8, value: u32 };

pub fn freezeFromPairs(gpa: Allocator, out_gpa: Allocator, pairs: []const Pair) FreezeError![]u8 {
    var b = Builder.init(gpa) catch return error.OutOfMemory;
    defer b.deinit();
    for (pairs) |pr| b.insert(pr.key, pr.value) catch return error.OutOfMemory;
    return b.freeze(out_gpa);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "build: child ids always exceed parent ids (offset invariant precondition)" {
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    try b.insert("abc", 1);
    try b.insert("abd", 2);
    try b.insert("xyz", 3);
    // Re-walk: every edge must point to a higher id.
    for (b.nodes.items, 0..) |*n, id| {
        var e = n.first_edge;
        while (e != no_edge) : (e = b.edges.items[e].next) {
            try testing.expect(b.edges.items[e].child > id);
        }
    }
}

test "build: duplicate key keeps the last value; key_count counts distinct" {
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    try b.insert("k", 10);
    try b.insert("k", 20);
    try b.insert("other", 5);
    try testing.expectEqual(@as(u64, 2), b.key_count);

    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    try testing.expectEqual(@as(u64, 2), h.key_count);
}

test "freeze: subtree_best is the max value under each node" {
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    try b.insert("ab", 3);
    try b.insert("ac", 9);
    try b.insert("az", 5);
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const root = try format.nodeAt(buf, format.header_size);
    // root has one edge 'a'; that node's subtree_best is 9.
    const e = root.findEdge('a').?;
    const a_node = try format.follow(root, e.child);
    try testing.expectEqual(@as(u32, 9), a_node.subtree_best);
}

test "freeze then load: header key_count and root offset are consistent" {
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    try b.insert("", 42); // empty key → root terminal
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    try testing.expectEqual(@as(u64, 1), h.key_count);
    const root = try format.nodeAt(buf, h.root_offset);
    try testing.expect(root.terminal);
    try testing.expectEqual(@as(u32, 42), root.value);
}

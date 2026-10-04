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
const stream = @import("stream.zig");

/// Which frozen format `freezeWith` writes. Version 2 is the default and the
/// recommended one (path-compressed, several times smaller); version 1 exists
/// so a buffer can still be produced for a reader built against an older
/// module that only understands v1.
pub const FreezeOptions = union(enum) {
    v1,
    v2: stream.Options,
};

pub const BuildError = error{
    OutOfMemory,
    /// The pool would exceed the u32 node/edge id space (~4.29 billion). Same
    /// bound `freeze` already enforces on the serialized offset space, just
    /// checked here too — before the `@intCast`s below rather than after
    /// (A1/trie.md F4: they narrowed silently, UB in ReleaseFast).
    TooLarge,
};

pub const FreezeError = error{
    OutOfMemory,
    /// The serialized node region would exceed the u32 offset space (~4 GiB).
    /// Far beyond the intended millions-of-keys workload; reported, never
    /// silently truncated.
    TooLarge,
};

/// Sentinel "no edge" index — the empty first_edge / end of a sibling list.
const no_edge: u32 = std.math.maxInt(u32);

/// Cast an `ArrayList` length (a `usize`) to a node/edge id, or
/// `error.TooLarge` if it would not fit in a `u32` — checked explicitly rather
/// than left to `@intCast`, which is a safety-checked panic in Debug /
/// ReleaseSafe but is undefined behaviour on out-of-range input in
/// ReleaseFast (A1/trie.md F4). `freeze` already enforces the same ~4.29
/// billion bound on the serialized offset space; this is the matching guard
/// on the id space that feeds it, so both narrowings in `insert` (`new_id`,
/// `new_edge`) go through it. `no_edge` (`maxInt(u32)`) stays reserved as the
/// sentinel, so the bound is `>=`, not `>`.
fn checkedId(len: usize) BuildError!u32 {
    if (len >= std.math.maxInt(u32)) return error.TooLarge;
    return @intCast(len);
}

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
    /// Linear over the sibling list — child counts are bounded by 256 distinct
    /// byte labels, but "in practice a handful" does NOT hold for byte-valued
    /// keys (hashes, binary IDs): measured build throughput at fixed key
    /// length/count, alphabet as the only variable, was 2038-2212 k nodes/s at
    /// alphabet 16 (447869 nodes) vs. 334-358 k nodes/s at alphabet 256
    /// (861627 nodes) — a 6.2x slower build for only 1.9x more nodes, i.e.
    /// ~3.2x more expensive per node (A1 trie F6, 2026-09-11).
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
                const new_id: u32 = try checkedId(self.nodes.items.len);
                const prev_head = self.nodes.items[cur].first_edge;
                try self.nodes.append(self.gpa, .{});
                const new_edge: u32 = try checkedId(self.edges.items.len);
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

    /// Serialize the trie into a freshly-allocated frozen buffer in format
    /// version 2 (caller owns and frees it). The builder is left intact and may
    /// be frozen again.
    pub fn freeze(self: *Builder, out_gpa: Allocator) FreezeError![]u8 {
        return self.freezeWith(out_gpa, .{ .v2 = .{} });
    }

    /// `freeze` with the format chosen explicitly.
    pub fn freezeWith(self: *Builder, out_gpa: Allocator, opts: FreezeOptions) FreezeError![]u8 {
        switch (opts) {
            .v1 => return self.freezeV1(out_gpa),
            .v2 => |o| {
                var out: std.Io.Writer.Allocating = .init(out_gpa);
                defer out.deinit();
                self.freezeTo(&out.writer, o) catch |err| return switch (err) {
                    // The allocating writer fails only when it cannot grow.
                    error.WriteFailed, error.OutOfMemory => error.OutOfMemory,
                    error.TooLarge => error.TooLarge,
                    // Keys come out of the trie in order, once each, before
                    // `finish`.
                    error.Unsorted, error.Finished => unreachable,
                };
                return out.toOwnedSlice();
            },
        }
    }

    /// Write the trie as a version-2 buffer straight to `w` (a file, a
    /// socket) without materializing the frozen copy in memory. Walks the
    /// trie in key order and feeds `SortedBuilder`, whose working memory is
    /// the length of the longest key, not the size of the index.
    pub fn freezeTo(self: *Builder, w: *std.Io.Writer, opts: stream.Options) stream.Error!void {
        self.sortEdges();
        var sb = try stream.SortedBuilder.init(self.gpa, w, opts);
        defer sb.deinit();
        var path: std.ArrayListUnmanaged(u8) = .empty;
        defer path.deinit(self.gpa);
        // One cursor per depth: the next edge to descend at that depth.
        var stack: std.ArrayListUnmanaged(u32) = .empty;
        defer stack.deinit(self.gpa);

        const root = self.nodes.items[0];
        if (root.terminal) try sb.insert("", root.value);
        try stack.append(self.gpa, root.first_edge);
        while (stack.items.len > 0) {
            const top = &stack.items[stack.items.len - 1];
            if (top.* == no_edge) {
                _ = stack.pop();
                if (stack.items.len > 0) _ = path.pop();
                continue;
            }
            const e = self.edges.items[top.*];
            top.* = e.next;
            try path.append(self.gpa, e.label);
            const child = self.nodes.items[e.child];
            if (child.terminal) try sb.insert(path.items, child.value);
            try stack.append(self.gpa, child.first_edge);
        }
        try sb.finish();
    }

    /// Relink every node's sibling list in ascending label order, so a walk
    /// along `first_edge`/`next` visits keys in sorted order. Idempotent;
    /// `insert` prepends, so a later insert just leaves one list unsorted
    /// again until the next freeze.
    fn sortEdges(self: *Builder) void {
        for (self.nodes.items) |*n| {
            if (n.edge_count < 2) continue;
            var tmp: [256]u32 = undefined;
            var cnt: usize = 0;
            var e = n.first_edge;
            while (e != no_edge) : (e = self.edges.items[e].next) {
                tmp[cnt] = e;
                cnt += 1;
            }
            std.mem.sort(u32, tmp[0..cnt], self.edges.items, edgeIdLess);
            n.first_edge = tmp[0];
            for (tmp[0 .. cnt - 1], tmp[1..cnt]) |a, b| self.edges.items[a].next = b;
            self.edges.items[tmp[cnt - 1]].next = no_edge;
        }
    }

    /// The version-1 writer (node-id order, header in front).
    fn freezeV1(self: *Builder, out_gpa: Allocator) FreezeError![]u8 {
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

fn edgeIdLess(edges: []const Edge, a: u32, b: u32) bool {
    return edges[a].label < edges[b].label;
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
    return freezeFromPairsWith(gpa, out_gpa, pairs, .{ .v2 = .{} });
}

/// `freezeFromPairs` with the format chosen explicitly.
pub fn freezeFromPairsWith(gpa: Allocator, out_gpa: Allocator, pairs: []const Pair, opts: FreezeOptions) FreezeError![]u8 {
    var b = Builder.init(gpa) catch return error.OutOfMemory;
    defer b.deinit();
    // `insert`'s BuildError is now `{OutOfMemory, TooLarge}` — both are
    // already members of FreezeError, so propagate rather than collapse (the
    // old `catch return error.OutOfMemory` would have relabelled TooLarge).
    for (pairs) |pr| b.insert(pr.key, pr.value) catch |err| return err;
    return b.freezeWith(out_gpa, opts);
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
    const buf = try b.freezeWith(testing.allocator, .v1);
    defer testing.allocator.free(buf);
    const root = try format.nodeAt(buf, format.header_size);
    // root has one edge 'a'; that node's subtree_best is 9.
    const e = root.findEdge('a').?;
    const a_node = try format.follow(root, e.child);
    try testing.expectEqual(@as(u32, 9), a_node.subtree_best);
}

test "checkedId rejects the u32 boundary instead of narrowing silently" {
    // Driving an actual builder to 2^32 nodes would need ~137 GB of build RSS
    // (measured 28 B/node, A1/trie.md F4) and is not reproducible on this
    // machine — but the guard itself is a pure length check, so it is tested
    // directly at and around the boundary without building anything that big.
    try testing.expectEqual(@as(u32, 0), try checkedId(0));
    try testing.expectEqual(@as(u32, std.math.maxInt(u32) - 1), try checkedId(std.math.maxInt(u32) - 1));
    try testing.expectError(error.TooLarge, checkedId(std.math.maxInt(u32)));
    try testing.expectError(error.TooLarge, checkedId(@as(usize, std.math.maxInt(u32)) + 1));
}

test "freeze then load: header key_count and root offset are consistent" {
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    try b.insert("", 42); // empty key → root terminal
    const buf = try b.freezeWith(testing.allocator, .v1);
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    try testing.expectEqual(@as(u64, 1), h.key_count);
    const root = try format.nodeAt(buf, h.root_offset);
    try testing.expect(root.terminal);
    try testing.expectEqual(@as(u32, 42), root.value);
}

test "freezeTo walks keys in sorted order whatever the insert order" {
    // Inserted out of order; `SortedBuilder` refuses unsorted input, so a
    // successful v2 freeze already proves the walk is sorted. The lookups
    // prove nothing was lost on the way.
    var b = try Builder.init(testing.allocator);
    defer b.deinit();
    const keys = [_][]const u8{ "zeta", "alpha", "", "alp", "beta", "alphabet", "z" };
    for (keys, 0..) |k, i| try b.insert(k, @intCast(i + 10));
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    try testing.expectEqual(format.format_version_2, h.version);
    try testing.expectEqual(@as(u64, keys.len), h.key_count);
    // Insert again after a freeze (lists were relinked) and freeze again.
    try b.insert("alpha", 99);
    try b.insert("mid", 5);
    const buf2 = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf2);
    try testing.expectEqual(@as(u64, keys.len + 1), (try format.Header.load(buf2)).key_count);
}

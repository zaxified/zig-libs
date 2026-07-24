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

/// One in-memory trie node. Children are kept as two parallel, label-sorted
/// arrays (`labels[i]` routes to `kids[i]`); binary search descends during
/// build. `best` is filled in by `freeze`'s post-order pass.
const Node = struct {
    terminal: bool = false,
    value: u32 = 0,
    best: u32 = 0,
    labels: std.ArrayListUnmanaged(u8) = .empty,
    kids: std.ArrayListUnmanaged(u32) = .empty,

    fn deinit(self: *Node, gpa: Allocator) void {
        self.labels.deinit(gpa);
        self.kids.deinit(gpa);
    }

    /// Index of `label` in the sorted `labels`, or the insertion point.
    fn search(self: *const Node, label: u8) struct { found: bool, index: usize } {
        var lo: usize = 0;
        var hi: usize = self.labels.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const l = self.labels.items[mid];
            if (l < label) {
                lo = mid + 1;
            } else if (l > label) {
                hi = mid;
            } else {
                return .{ .found = true, .index = mid };
            }
        }
        return .{ .found = false, .index = lo };
    }
};

/// Incremental trie builder. Insert `(key, value)` pairs in any order, then
/// `freeze` once. Not reusable after `freeze` consumes it (call `deinit` if you
/// abandon a builder without freezing).
pub const Builder = struct {
    gpa: Allocator,
    nodes: std.ArrayListUnmanaged(Node),
    key_count: u64 = 0,

    pub fn init(gpa: Allocator) BuildError!Builder {
        var nodes: std.ArrayListUnmanaged(Node) = .empty;
        try nodes.append(gpa, .{}); // node 0 = root
        return .{ .gpa = gpa, .nodes = nodes };
    }

    pub fn deinit(self: *Builder) void {
        for (self.nodes.items) |*n| n.deinit(self.gpa);
        self.nodes.deinit(self.gpa);
        self.* = undefined;
    }

    /// Insert or overwrite `key` → `value`. Arbitrary bytes; the empty key is
    /// allowed (it marks the root terminal). Last write wins for duplicates.
    pub fn insert(self: *Builder, key: []const u8, value: u32) BuildError!void {
        var cur: u32 = 0; // root
        for (key) |b| {
            const s = self.nodes.items[cur].search(b);
            if (s.found) {
                cur = self.nodes.items[cur].kids.items[s.index];
            } else {
                // Create the child first (may realloc the pool); then edit the
                // parent by index — never hold a Node pointer across the append.
                const new_id: u32 = @intCast(self.nodes.items.len);
                try self.nodes.append(self.gpa, .{});
                const parent = &self.nodes.items[cur];
                try parent.labels.insert(self.gpa, s.index, b);
                errdefer _ = parent.labels.orderedRemove(s.index);
                try parent.kids.insert(self.gpa, s.index, new_id);
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
                for (n.kids.items) |kid| best = @max(best, self.nodes.items[kid].best);
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
            std.mem.writeInt(u16, buf[p .. p + 2][0..2], @intCast(n.labels.items.len), .little);
            p += format.edge_count_size;
            for (n.labels.items, n.kids.items) |label, kid| {
                buf[p] = label;
                std.mem.writeInt(u32, buf[p + 1 .. p + 5][0..4], offsets[kid], .little);
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

fn nodeSize(n: *const Node) usize {
    var s: usize = format.flags_size + format.best_size + format.edge_count_size;
    if (n.terminal) s += format.value_size;
    s += n.labels.items.len * format.edge_size;
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
        for (n.kids.items) |kid| try testing.expect(kid > id);
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

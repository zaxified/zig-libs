// SPDX-License-Identifier: MIT

//! stream — the format-2 WRITER: a streaming builder over keys inserted in
//! ascending byte order, writing the frozen buffer to any `std.Io.Writer`
//! while holding only the current key's path in memory (BurntSushi/fst's
//! build model). `Builder.freeze` feeds its in-memory trie through this too,
//! so there is one v2 serializer.
//!
//! How a node gets written exactly once, children first:
//!
//!   * `frames[d]` is the still-open node at depth `d` of the LAST inserted
//!     key (`frames[0]` is the root). A new key closes every frame below the
//!     common prefix with the previous key, deepest first.
//!   * A closed node is handed to its parent. It is written at once, unless
//!     the parent might still turn out to be a non-terminal node with exactly
//!     one child — then the parent HOLDS it (`Frame.held`). The parent writes
//!     its held child the moment a second child arrives; a parent that closes
//!     still holding its only child is merged INTO that child instead (path
//!     compression: the child's tail grows by the parent's incoming label).
//!   * So a frame holds at most one unwritten child, and memory is
//!     O(key length × (256 edges + 255 tail bytes)), independent of the number
//!     of keys.

const std = @import("std");
const Allocator = std.mem.Allocator;
const format = @import("format.zig");

pub const Options = struct {
    /// Store the per-edge `before` counts (format flag bit 0), which
    /// `Frozen.ordinal` / `Frozen.keyAt` need. Costs 4 bytes per edge.
    ordinals: bool = false,
};

pub const Error = error{
    OutOfMemory,
    /// A key smaller than the previous one. Equal keys are allowed (the later
    /// value wins, as in `Builder`).
    Unsorted,
    /// The node region would exceed the u32 offset space, or (with
    /// `ordinals`) the key count the u32 `before` field.
    TooLarge,
    /// The underlying writer failed.
    WriteFailed,
    /// `insert` after `finish`.
    Finished,
};

/// A written child as its parent's edge needs it.
const EdgeOut = struct { label: u8, offset: u32, best: u32, count: u64 };

/// A closed node that is not written yet.
const Held = struct {
    terminal: bool = false,
    value: u32 = 0,
    tail_len: usize = 0,
    tail: [format.max_tail]u8 = undefined,
    edges: std.ArrayListUnmanaged(EdgeOut) = .empty,
};

const Frame = struct {
    terminal: bool = false,
    value: u32 = 0,
    /// Written children, in ascending label order (sorted input guarantees it).
    edges: std.ArrayListUnmanaged(EdgeOut) = .empty,
    /// The single unwritten child, only while this node is non-terminal and
    /// has no written child (otherwise it could never be merged).
    has_held: bool = false,
    held_label: u8 = 0,
    held: Held = .{},

    fn reset(self: *Frame) void {
        self.terminal = false;
        self.value = 0;
        self.edges.clearRetainingCapacity();
        self.has_held = false;
        self.held.edges.clearRetainingCapacity();
    }

    fn deinit(self: *Frame, gpa: Allocator) void {
        self.edges.deinit(gpa);
        self.held.edges.deinit(gpa);
    }
};

/// Largest encoded v2 node: flags, tail_len, tail, value, best, count, 256
/// edges with `before`.
const max_node_bytes = 2 + format.max_tail + 4 + 4 + 1 + 256 * format.edge_size_ordinals;

pub const SortedBuilder = struct {
    gpa: Allocator,
    w: *std.Io.Writer,
    opts: Options,
    frames: std.ArrayListUnmanaged(Frame) = .empty,
    last: std.ArrayListUnmanaged(u8) = .empty,
    started: bool = false,
    finished: bool = false,
    key_count: u64 = 0,
    /// Absolute offset of the next byte written.
    pos: u64 = format.v2_front_size,
    crc: std.hash.Crc32 = .init(),
    front: [format.v2_front_size]u8 = undefined,
    scratch: [max_node_bytes]u8 = undefined,

    /// Write the 12-byte front to `w` and start an empty index.
    pub fn init(gpa: Allocator, w: *std.Io.Writer, opts: Options) Error!SortedBuilder {
        var self: SortedBuilder = .{ .gpa = gpa, .w = w, .opts = opts };
        @memcpy(self.front[0..4], format.magic);
        std.mem.writeInt(u16, self.front[4..6], format.format_version_2, .little);
        std.mem.writeInt(u16, self.front[6..8], format.endian_marker, .little);
        std.mem.writeInt(u32, self.front[8..12], if (opts.ordinals) format.v2_flag_ordinals else 0, .little);
        try self.frames.append(gpa, .{});
        errdefer self.frames.deinit(gpa);
        try w.writeAll(&self.front);
        return self;
    }

    pub fn deinit(self: *SortedBuilder) void {
        for (self.frames.items) |*f| f.deinit(self.gpa);
        self.frames.deinit(self.gpa);
        self.last.deinit(self.gpa);
        self.* = undefined;
    }

    /// Add `key` → `value`. Keys must arrive in ascending bytewise order; an
    /// equal key overwrites the previous value.
    pub fn insert(self: *SortedBuilder, key: []const u8, value: u32) Error!void {
        if (self.finished) return error.Finished;
        var common: usize = 0;
        if (self.started) {
            switch (std.mem.order(u8, key, self.last.items)) {
                .lt => return error.Unsorted,
                .eq => {
                    self.frames.items[key.len].value = value;
                    return;
                },
                .gt => {},
            }
            common = std.mem.indexOfDiff(u8, key, self.last.items) orelse key.len;
            var d = self.last.items.len;
            while (d > common) : (d -= 1) try self.close(d);
        }
        while (self.frames.items.len < key.len + 1) try self.frames.append(self.gpa, .{});
        const f = &self.frames.items[key.len];
        f.terminal = true;
        f.value = value;
        self.last.clearRetainingCapacity();
        try self.last.appendSlice(self.gpa, key);
        self.started = true;
        self.key_count += 1;
    }

    /// Close every open node, write the root and the footer, and flush `w`.
    /// The builder accepts no further keys.
    pub fn finish(self: *SortedBuilder) Error!void {
        if (self.finished) return error.Finished;
        self.finished = true;
        var d = self.last.items.len;
        while (d > 0) : (d -= 1) try self.close(d);
        // The root is never merged into its child: a v2 root has no tail.
        const root = &self.frames.items[0];
        try self.flushHeld(root);
        var as_held: Held = .{ .terminal = root.terminal, .value = root.value };
        std.mem.swap(std.ArrayListUnmanaged(EdgeOut), &as_held.edges, &root.edges);
        defer std.mem.swap(std.ArrayListUnmanaged(EdgeOut), &as_held.edges, &root.edges);
        const r = try self.writeNode(&as_held);
        if (self.opts.ordinals and self.key_count > std.math.maxInt(u32)) return error.TooLarge;

        var foot: [format.v2_footer_size]u8 = undefined;
        const region = self.pos - format.v2_front_size;
        if (region > std.math.maxInt(u32)) return error.TooLarge;
        std.mem.writeInt(u32, foot[0..4], @intCast(region), .little);
        std.mem.writeInt(u32, foot[4..8], r.offset, .little);
        std.mem.writeInt(u64, foot[8..16], self.key_count, .little);
        std.mem.writeInt(u32, foot[16..20], self.crc.final(), .little);
        var fc = std.hash.Crc32.init();
        fc.update(&self.front);
        fc.update(foot[0..20]);
        std.mem.writeInt(u32, foot[20..24], fc.final(), .little);
        try self.w.writeAll(&foot);
        try self.w.flush();
    }

    /// Close the node at depth `d` (≥ 1) and hand it to its parent.
    fn close(self: *SortedBuilder, d: usize) Error!void {
        const f = &self.frames.items[d];
        const parent = &self.frames.items[d - 1];
        const label = self.last.items[d - 1];

        // Turn `f` into a Held in `f.held`: either merged into its single held
        // child (path compression), or as itself with its children written.
        if (!f.terminal and f.edges.items.len == 0 and f.has_held and f.held.tail_len < format.max_tail) {
            const h = &f.held;
            std.mem.copyBackwards(u8, h.tail[1 .. h.tail_len + 1], h.tail[0..h.tail_len]);
            h.tail[0] = f.held_label;
            h.tail_len += 1;
        } else {
            try self.flushHeld(f);
            f.held.terminal = f.terminal;
            f.held.value = f.value;
            f.held.tail_len = 0;
            std.mem.swap(std.ArrayListUnmanaged(EdgeOut), &f.held.edges, &f.edges);
        }

        if (!parent.terminal and parent.edges.items.len == 0 and !parent.has_held) {
            // The parent may still close with this as its only child: hold it.
            parent.has_held = true;
            parent.held_label = label;
            parent.held.terminal = f.held.terminal;
            parent.held.value = f.held.value;
            parent.held.tail_len = f.held.tail_len;
            @memcpy(parent.held.tail[0..f.held.tail_len], f.held.tail[0..f.held.tail_len]);
            parent.held.edges.clearRetainingCapacity();
            std.mem.swap(std.ArrayListUnmanaged(EdgeOut), &parent.held.edges, &f.held.edges);
        } else {
            try self.flushHeld(parent);
            const e = try self.writeNode(&f.held);
            try parent.edges.append(self.gpa, .{ .label = label, .offset = e.offset, .best = e.best, .count = e.count });
        }
        f.reset();
    }

    /// Write `f`'s held child (if any) and record it as a written edge.
    fn flushHeld(self: *SortedBuilder, f: *Frame) Error!void {
        if (!f.has_held) return;
        const e = try self.writeNode(&f.held);
        try f.edges.append(self.gpa, .{ .label = f.held_label, .offset = e.offset, .best = e.best, .count = e.count });
        f.has_held = false;
        f.held.edges.clearRetainingCapacity();
    }

    const Written = struct { offset: u32, best: u32, count: u64 };

    fn writeNode(self: *SortedBuilder, h: *const Held) Error!Written {
        if (self.pos > std.math.maxInt(u32)) return error.TooLarge;
        const offset: u32 = @intCast(self.pos);
        var best: u32 = if (h.terminal) h.value else 0;
        var count: u64 = @intFromBool(h.terminal);
        for (h.edges.items) |e| {
            best = @max(best, e.best);
            count += e.count;
        }

        const b = &self.scratch;
        var p: usize = 0;
        const has_edges = h.edges.items.len > 0;
        b[p] = (if (h.terminal) format.terminal_bit else 0) | (if (has_edges) format.v2_edges_bit else 0);
        b[p + 1] = @intCast(h.tail_len);
        p += 2;
        @memcpy(b[p..][0..h.tail_len], h.tail[0..h.tail_len]);
        p += h.tail_len;
        if (h.terminal) {
            std.mem.writeInt(u32, b[p..][0..4], h.value, .little);
            p += 4;
        }
        if (has_edges) {
            std.debug.assert(h.edges.items.len <= 256);
            std.mem.writeInt(u32, b[p..][0..4], best, .little);
            b[p + 4] = @intCast(h.edges.items.len - 1);
            p += 5;
            // `before` counts keys under EARLIER edges only; the node's own
            // terminal (which sorts before all of them) is added by the reader.
            var before: u64 = 0;
            for (h.edges.items) |e| {
                b[p] = e.label;
                std.mem.writeInt(u32, b[p + 1 ..][0..4], e.offset, .little);
                p += format.edge_size;
                if (self.opts.ordinals) {
                    if (before > std.math.maxInt(u32)) return error.TooLarge;
                    std.mem.writeInt(u32, b[p..][0..4], @intCast(before), .little);
                    p += 4;
                }
                before += e.count;
            }
        }
        self.crc.update(b[0..p]);
        try self.w.writeAll(b[0..p]);
        self.pos += p;
        return .{ .offset = offset, .best = best, .count = count };
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn buildSorted(keys: []const []const u8, opts: Options) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var sb = try SortedBuilder.init(testing.allocator, &out.writer, opts);
    defer sb.deinit();
    for (keys, 0..) |k, i| try sb.insert(k, @intCast(i + 1));
    try sb.finish();
    return out.toOwnedSlice();
}

test "a single key becomes one leaf under the root, its whole suffix in the tail" {
    // "hello" alone: root (no tail, one edge 'h') → leaf with tail "ello". In
    // v1 the same key costs five chain nodes.
    const buf = try buildSorted(&.{"hello"}, .{});
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    try testing.expectEqual(format.format_version_2, h.version);
    try testing.expectEqual(@as(u64, 1), h.key_count);
    const region = buf[0 .. format.v2_front_size + h.node_region_len];
    const root = try format.nodeAtV2(region, h.root_offset, false);
    try testing.expectEqual(@as(u16, 1), root.edge_count);
    try testing.expectEqualStrings("", root.tail);
    const e = root.edge(0);
    try testing.expectEqual(@as(u8, 'h'), e.label);
    const leaf = try format.follow(root, e.child);
    try testing.expectEqualStrings("ello", leaf.tail);
    try testing.expect(leaf.terminal);
    try testing.expectEqual(@as(u32, 1), leaf.value);
    // Root: flags, tail_len, best, count, 1 edge = 2+4+1+5; leaf: 2+4+4.
    try testing.expectEqual(@as(u32, 12 + 10), h.node_region_len);
    try h.verifyBody(buf);
}

test "a terminal node is never merged into its child, and the root never into anything" {
    // "a" is a stored key, so the node for "a" must stay a node even though it
    // has one child; "abc" hangs below it with tail "c".
    const buf = try buildSorted(&.{ "a", "abc" }, .{});
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    const region = buf[0 .. format.v2_front_size + h.node_region_len];
    const root = try format.nodeAtV2(region, h.root_offset, false);
    try testing.expect(!root.terminal);
    const a = try format.follow(root, root.findEdge('a').?.child);
    try testing.expect(a.terminal);
    try testing.expectEqualStrings("", a.tail);
    const abc = try format.follow(a, a.findEdge('b').?.child);
    try testing.expectEqualStrings("c", abc.tail);
}

test "a chain longer than max_tail keeps a node every 256 bytes" {
    // One key of 600 bytes: the incoming string of a node is label ++ tail,
    // at most 256 bytes, so the path splits into ceil(600 / 256) = 3 nodes
    // below the root.
    var key: [600]u8 = undefined;
    for (&key, 0..) |*c, i| c.* = @intCast('a' + i % 26);
    const buf = try buildSorted(&.{&key}, .{});
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    const region = buf[0 .. format.v2_front_size + h.node_region_len];
    var node = try format.nodeAtV2(region, h.root_offset, false);
    var consumed: usize = 0;
    var nodes: usize = 0;
    while (node.edge_count > 0) {
        const e = node.edge(0);
        try testing.expectEqual(key[consumed], e.label);
        node = try format.follow(node, e.child);
        try testing.expectEqualSlices(u8, key[consumed + 1 ..][0..node.tail.len], node.tail);
        consumed += 1 + node.tail.len;
        nodes += 1;
    }
    try testing.expectEqual(@as(usize, 600), consumed);
    try testing.expectEqual(@as(usize, 3), nodes);
    try testing.expect(node.terminal);
}

test "unsorted input is refused; an equal key overwrites" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var sb = try SortedBuilder.init(testing.allocator, &out.writer, .{});
    defer sb.deinit();
    try sb.insert("b", 1);
    try testing.expectError(error.Unsorted, sb.insert("a", 2));
    try sb.insert("b", 7);
    try sb.finish();
    try testing.expectError(error.Finished, sb.insert("c", 1));
    const h = try format.Header.load(out.written());
    try testing.expectEqual(@as(u64, 1), h.key_count);
    // The later value is the one stored (mutation 2026-10-04: dropping the
    // overwrite survived while only the key count was checked).
    const region = out.written()[0 .. format.v2_front_size + h.node_region_len];
    const root = try format.nodeAtV2(region, h.root_offset, false);
    const b = try format.follow(root, root.findEdge('b').?.child);
    try testing.expectEqual(@as(u32, 7), b.value);
}

test "golden: the exact v2 bytes for a, ab, acx, acy" {
    // Hand-derived from the layout in format.zig, not from the writer.
    // Children before parents; a node is written when it can no longer be
    // merged — "ab" as soon as "acx" arrives (its parent "a" is terminal, so
    // it can never be merged into "ab"), "acx" when "acy" arrives, "ac" and
    // "a" at finish. (Mutation 2026-10-04: letting a terminal parent HOLD its
    // child moved "ab" after "acy" — still a valid index, so only the layout
    // shows it.)
    const buf = try buildSorted(&.{ "a", "ab", "acx", "acy" }, .{});
    defer testing.allocator.free(buf);
    const region = [_]u8{
        // @12 "ab": terminal leaf, value 2
        0x01, 0x00, 2,    0,    0,   0,
        // @18 "acx": terminal leaf, value 3
        0x01, 0x00, 3,    0,    0,   0,
        // @24 "acy": terminal leaf, value 4
        0x01, 0x00, 4,    0,    0,   0,
        // @30 "ac": edges only; best 4; 2 edges: 'x' → 18, 'y' → 24
        0x02, 0x00, 4,    0,    0,   0,
        1,    'x',  18,   0,    0,   0,
        'y',  24,   0,    0,    0,
        // @47 "a": terminal + edges; value 1; best 4; 'b' → 12, 'c' → 30
          0x03,
        0x00, 1,    0,    0,    0,   4,
        0,    0,    0,    1,    'b', 12,
        0,    0,    0,    'c',  30,  0,
        0,    0,
        // @68 root: edges only; best 4; 1 edge: 'a' → 47
           0x02, 0x00, 4,   0,
        0,    0,    0,    'a',  47,  0,
        0,    0,
    };
    try testing.expectEqualSlices(u8, "ZTR1\x02\x00\x02\x01\x00\x00\x00\x00", buf[0..12]);
    try testing.expectEqualSlices(u8, &region, buf[12 .. 12 + region.len]);
    const foot = buf[12 + region.len ..];
    try testing.expectEqual(@as(usize, 24), foot.len);
    try testing.expectEqual(@as(u32, region.len), std.mem.readInt(u32, foot[0..4], .little));
    try testing.expectEqual(@as(u32, 68), std.mem.readInt(u32, foot[4..8], .little)); // root last
    try testing.expectEqual(@as(u64, 4), std.mem.readInt(u64, foot[8..16], .little));
    try testing.expectEqual(std.hash.Crc32.hash(&region), std.mem.readInt(u32, foot[16..20], .little));
}

test "ordinals: `before` counts keys under earlier edges only" {
    // Keys a, b, ba, c: root edges a (1 key), b (2 keys: b, ba), c (1 key).
    // So before = 0, 1, 3.
    const buf = try buildSorted(&.{ "a", "b", "ba", "c" }, .{ .ordinals = true });
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    try testing.expect(h.hasOrdinals());
    const region = buf[0 .. format.v2_front_size + h.node_region_len];
    const root = try format.nodeAtV2(region, h.root_offset, true);
    try testing.expectEqual(@as(u16, 3), root.edge_count);
    try testing.expectEqual(@as(u32, 0), root.edge(0).before);
    try testing.expectEqual(@as(u32, 1), root.edge(1).before);
    try testing.expectEqual(@as(u32, 3), root.edge(2).before);
}

test "the empty index is a single empty root" {
    const buf = try buildSorted(&.{}, .{});
    defer testing.allocator.free(buf);
    try testing.expectEqual(@as(usize, 12 + 2 + 24), buf.len);
    const h = try format.Header.load(buf);
    try testing.expectEqual(@as(u64, 0), h.key_count);
}

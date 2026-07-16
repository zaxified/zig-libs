// SPDX-License-Identifier: MIT

//! format — the on-disk page layout and the MECHANICAL B-tree node machinery.
//!
//! This is pure, allocator-explicit, I/O-free code: it turns page-sized byte
//! buffers into typed views (`Meta`, `Leaf`, `Branch`) and back, does the
//! in-node binary search, and performs the classic B-tree node mutations —
//! insert, delete and split. None of it is the Fable core: node split is
//! textbook, deterministic, and unit-tested here directly (see the tests at
//! the bottom). (Deletes remove the key in place; there is no merge/rebalance
//! yet — underflowed and empty leaves simply persist, a documented backlog
//! item, never a correctness issue.) The correctness-critical parts —
//! *when* a commit's dirty pages become durable and *which* meta page a crash
//! recovery adopts, and *when* a freed page may be recycled without a live
//! reader still seeing it — live in `core.zig`.
//!
//! Layout (LMDB/BoltDB lineage, single 4 KiB page unit):
//!
//!   page 0, page 1  — the two META pages (double-buffered; a commit writes
//!                     the one it is NOT currently rooted at, then fsyncs, so a
//!                     torn meta write never destroys the last good one).
//!   page 2…         — tree nodes + freelist pages, allocated by the `Pager`.
//!
//! A node is a slotted page: an 8-byte header, then a `count`-entry slot
//! directory of 2-byte cell offsets kept in ascending key order, then the
//! variable-length cells packed from the end of the page toward the front.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const page_size: usize = 4096;

/// Page number. Byte offset of page `id` in the file is `id * page_size`.
pub const PageId = u32;

pub const meta_page_a: PageId = 0;
pub const meta_page_b: PageId = 1;
/// The first page the allocator may hand out for tree/freelist data.
pub const first_data_page: PageId = 2;

pub const NodeKind = enum(u8) { leaf = 0, branch = 1 };

const meta_magic = "ZKVT";
const format_version: u32 = 1;

/// A single leaf entry (borrowed slices into a page buffer, or into a builder's
/// arena — never owns).
pub const Entry = struct { key: []const u8, val: []const u8 };

// ── Meta page ────────────────────────────────────────────────────────────────

/// The root-of-everything record. Two copies exist on disk (pages 0 and 1);
/// `decode` validates ONE page structurally (magic/version/geometry/CRC) but
/// deliberately does NOT choose between the two or bounds-check the pointers
/// against the live file — that selection is the crash-recovery invariant and
/// belongs to `core.recover` (the Fable core).
pub const Meta = struct {
    /// Monotonic commit sequence. Higher = newer. 0 = the freshly-formatted
    /// empty store's first meta.
    txn_id: u64,
    /// Root page of the B-tree (a leaf when the tree is small/empty).
    root: PageId,
    /// Head of the on-disk freelist page chain (0 = empty freelist).
    free_root: PageId,
    /// Number of page ids currently on the freelist.
    free_count: u64,
    /// Total pages the file has ever grown to; the next never-before-used page
    /// id. Every valid page id in a committed tree is `< high_water`.
    high_water: u64,

    const crc_off = 44; // bytes [0..44) are covered by the CRC at [44..48)

    pub fn encode(self: Meta, page: *[page_size]u8) void {
        @memset(page, 0);
        @memcpy(page[0..4], meta_magic);
        std.mem.writeInt(u32, page[4..8], format_version, .little);
        std.mem.writeInt(u32, page[8..12], @intCast(page_size), .little);
        std.mem.writeInt(u64, page[12..20], self.txn_id, .little);
        std.mem.writeInt(u32, page[20..24], self.root, .little);
        std.mem.writeInt(u32, page[24..28], self.free_root, .little);
        std.mem.writeInt(u64, page[28..36], self.free_count, .little);
        std.mem.writeInt(u64, page[36..44], self.high_water, .little);
        const crc = std.hash.Crc32.hash(page[0..crc_off]);
        std.mem.writeInt(u32, page[crc_off .. crc_off + 4][0..4], crc, .little);
    }

    /// Structural + CRC validation only. `null` = not a valid meta page of
    /// this format (bad magic/version/geometry, or a torn/corrupt page whose
    /// CRC does not hold). A non-null result is a self-consistent meta record;
    /// whether it is the one to *adopt* is `core.recover`'s call.
    pub fn decode(page: *const [page_size]u8) ?Meta {
        if (!std.mem.eql(u8, page[0..4], meta_magic)) return null;
        if (std.mem.readInt(u32, page[4..8], .little) != format_version) return null;
        if (std.mem.readInt(u32, page[8..12], .little) != page_size) return null;
        const want = std.mem.readInt(u32, page[crc_off .. crc_off + 4][0..4], .little);
        if (std.hash.Crc32.hash(page[0..crc_off]) != want) return null;
        return .{
            .txn_id = std.mem.readInt(u64, page[12..20], .little),
            .root = std.mem.readInt(u32, page[20..24], .little),
            .free_root = std.mem.readInt(u32, page[24..28], .little),
            .free_count = std.mem.readInt(u64, page[28..36], .little),
            .high_water = std.mem.readInt(u64, page[36..44], .little),
        };
    }
};

// ── node header + slot directory (shared leaf/branch) ────────────────────────

const hdr_len = 8;
const slot_len = 2;

fn nodeKind(page: *const [page_size]u8) NodeKind {
    return @enumFromInt(page[0]);
}
fn nodeCount(page: *const [page_size]u8) u16 {
    return std.mem.readInt(u16, page[2..4], .little);
}
fn nodeLeftmost(page: *const [page_size]u8) PageId {
    return std.mem.readInt(u32, page[4..8], .little);
}
fn slotOffset(page: *const [page_size]u8, i: usize) usize {
    const base = hdr_len + i * slot_len;
    return std.mem.readInt(u16, page[base .. base + 2][0..2], .little);
}

pub fn kindOf(page: *const [page_size]u8) NodeKind {
    return nodeKind(page);
}

/// Result of an in-node key search.
pub const Search = struct {
    /// True iff an entry with the exact key exists at `index`.
    found: bool,
    /// If found, its slot index; otherwise the slot the key would be inserted
    /// at (0..count) to keep the directory sorted.
    index: u16,
};

// ── Leaf: read-only view over a leaf page ────────────────────────────────────

pub const Leaf = struct {
    page: *const [page_size]u8,

    pub fn init(page: *const [page_size]u8) Leaf {
        std.debug.assert(nodeKind(page) == .leaf);
        return .{ .page = page };
    }

    pub fn count(self: Leaf) u16 {
        return nodeCount(self.page);
    }

    pub fn keyAt(self: Leaf, i: usize) []const u8 {
        const o = slotOffset(self.page, i);
        const klen = std.mem.readInt(u16, self.page[o .. o + 2][0..2], .little);
        return self.page[o + 6 ..][0..klen];
    }

    pub fn valAt(self: Leaf, i: usize) []const u8 {
        const o = slotOffset(self.page, i);
        const klen = std.mem.readInt(u16, self.page[o .. o + 2][0..2], .little);
        const vlen = std.mem.readInt(u32, self.page[o + 2 .. o + 6][0..4], .little);
        return self.page[o + 6 + klen ..][0..vlen];
    }

    pub fn search(self: Leaf, key: []const u8) Search {
        return binarySearch(Leaf, self, key);
    }
};

// ── Branch: read-only view over a branch page ────────────────────────────────
//
// `count` = number of separator keys = number of cells; there are `count + 1`
// children: `leftmost`, then each cell's `right_child` in slot order. Child
// `i` covers keys in [sep[i-1], sep[i]) with sep[-1] = -inf, sep[count] = +inf.

pub const Branch = struct {
    page: *const [page_size]u8,

    pub fn init(page: *const [page_size]u8) Branch {
        std.debug.assert(nodeKind(page) == .branch);
        return .{ .page = page };
    }

    pub fn count(self: Branch) u16 {
        return nodeCount(self.page);
    }

    pub fn leftmost(self: Branch) PageId {
        return nodeLeftmost(self.page);
    }

    /// Separator key of cell `i` (0..count-1).
    pub fn keyAt(self: Branch, i: usize) []const u8 {
        const o = slotOffset(self.page, i);
        const klen = std.mem.readInt(u16, self.page[o .. o + 2][0..2], .little);
        return self.page[o + 6 ..][0..klen];
    }

    /// Right child of cell `i` (0..count-1).
    pub fn rightChildAt(self: Branch, i: usize) PageId {
        const o = slotOffset(self.page, i);
        return std.mem.readInt(u32, self.page[o + 2 .. o + 6][0..4], .little);
    }

    /// Child page by ordinal: 0 = leftmost, i (1..count) = cell[i-1].right_child.
    /// There are `count + 1` valid indices (0..count).
    pub fn childAtIndex(self: Branch, i: usize) PageId {
        if (i == 0) return self.leftmost();
        return self.rightChildAt(i - 1);
    }

    /// Ordinal of the child to descend into for `key` (0..count).
    pub fn childIndexFor(self: Branch, key: []const u8) usize {
        // lo = number of separators <= key → child ordinal.
        var lo: usize = 0;
        var hi: usize = self.count();
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, self.keyAt(mid), key)) {
                .lt, .eq => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return lo;
    }

    /// Child page to descend into for `key`. Index 0 = leftmost; index i+1 =
    /// cell[i].right_child.
    pub fn childFor(self: Branch, key: []const u8) PageId {
        return self.childAtIndex(self.childIndexFor(key));
    }
};

/// Crash-recovery helper: a bounds-checked `Branch` view over a POSSIBLY
/// GARBAGE page (a stale meta candidate may reference torn/recycled pages).
/// Returns `null` unless the header, slot directory and every cell lie fully
/// inside the page — after which the normal `Branch` accessors are safe. The
/// regular views assert well-formedness instead (their pages come from a
/// validated committed tree); recovery must reject, never crash.
pub fn branchViewSafe(page: *const [page_size]u8) ?Branch {
    if (page[0] != @intFromEnum(NodeKind.branch)) return null;
    const count: usize = nodeCount(page);
    const dir_end = hdr_len + count * slot_len;
    if (dir_end > page_size) return null;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const o = slotOffset(page, i);
        if (o < dir_end or o + 6 > page_size) return null;
        const klen = std.mem.readInt(u16, page[o .. o + 2][0..2], .little);
        if (o + 6 + @as(usize, klen) > page_size) return null;
    }
    return Branch.init(page);
}

/// Generic ascending binary search over a leaf's/branch's key directory.
fn binarySearch(comptime V: type, view: V, key: []const u8) Search {
    var lo: usize = 0;
    var hi: usize = view.count();
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const cmp = std.mem.order(u8, view.keyAt(mid), key);
        switch (cmp) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return .{ .found = true, .index = @intCast(mid) },
        }
    }
    return .{ .found = false, .index = @intCast(lo) };
}

// ── Builders: MUTABLE, owned decoded nodes for the write/commit path ─────────
//
// A commit decodes a page into a builder, mutates it (put/del/insert), then
// either re-encodes it (fits) or splits it into two pages plus a separator.
// All key/value bytes are duped into the builder's arena so the source page
// buffer can be reused freely. This is the mechanical half of the B-tree; the
// COW page-allocation + durability wrapping around it is `core.commit`.

pub const max_key_len = std.math.maxInt(u16);

/// A key/value pair a single leaf can never hold, no matter how empty (would
/// not fit one page even alone) — the scaffold rejects it; overflow pages for
/// large values are a documented backlog item (see SPEC.md).
pub const oversize_error = error.EntryTooLarge;

pub const LeafBuilder = struct {
    arena: Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(arena: Allocator) LeafBuilder {
        return .{ .arena = arena };
    }

    pub fn deinit(self: *LeafBuilder) void {
        self.entries.deinit(self.arena);
    }

    pub fn fromPage(arena: Allocator, page: *const [page_size]u8) !LeafBuilder {
        var b = LeafBuilder.init(arena);
        const leaf = Leaf.init(page);
        var i: usize = 0;
        while (i < leaf.count()) : (i += 1) {
            try b.entries.append(arena, .{
                .key = try arena.dupe(u8, leaf.keyAt(i)),
                .val = try arena.dupe(u8, leaf.valAt(i)),
            });
        }
        return b;
    }

    /// Insert or overwrite. Returns error.EntryTooLarge if a single k/v cannot
    /// fit an otherwise-empty page.
    pub fn put(self: *LeafBuilder, key: []const u8, val: []const u8) !void {
        if (leafCellBytes(key.len, val.len) + hdr_len + slot_len > page_size)
            return oversize_error;
        const s = self.search(key);
        const e = Entry{ .key = try self.arena.dupe(u8, key), .val = try self.arena.dupe(u8, val) };
        if (s.found) {
            self.entries.items[s.index] = e;
        } else {
            try self.entries.insert(self.arena, s.index, e);
        }
    }

    /// Remove `key` if present; returns whether it existed.
    pub fn del(self: *LeafBuilder, key: []const u8) bool {
        const s = self.search(key);
        if (!s.found) return false;
        _ = self.entries.orderedRemove(s.index);
        return true;
    }

    pub fn search(self: *const LeafBuilder, key: []const u8) Search {
        var lo: usize = 0;
        var hi: usize = self.entries.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, self.entries.items[mid].key, key)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return .{ .found = true, .index = @intCast(mid) },
            }
        }
        return .{ .found = false, .index = @intCast(lo) };
    }

    /// Total encoded byte size if flushed now.
    pub fn byteSize(self: *const LeafBuilder) usize {
        var n: usize = hdr_len;
        for (self.entries.items) |e| n += slot_len + leafCellBytes(e.key.len, e.val.len);
        return n;
    }

    pub fn overflows(self: *const LeafBuilder) bool {
        return self.byteSize() > page_size;
    }

    pub fn underflows(self: *const LeafBuilder) bool {
        return self.byteSize() < page_size / 4;
    }

    pub fn encode(self: *const LeafBuilder, page: *[page_size]u8) void {
        encodeLeaf(page, self.entries.items);
    }

    /// Split an overflowing leaf into two, at the entry midpoint. Returns the
    /// right half plus the separator key (== the right half's first key). The
    /// receiver becomes the left half. Both halves own copies in `arena`.
    pub fn split(self: *LeafBuilder) !SplitLeaf {
        const n = self.entries.items.len;
        std.debug.assert(n >= 2);
        const mid = n / 2;
        var right = LeafBuilder.init(self.arena);
        for (self.entries.items[mid..]) |e|
            try right.entries.append(self.arena, e);
        const sep = try self.arena.dupe(u8, self.entries.items[mid].key);
        self.entries.shrinkRetainingCapacity(mid);
        return .{ .right = right, .sep = sep };
    }
};

pub const SplitLeaf = struct { right: LeafBuilder, sep: []const u8 };

pub const BranchBuilder = struct {
    arena: Allocator,
    leftmost: PageId,
    /// Ascending separators paired with their right children.
    cells: std.ArrayList(Cell) = .empty,

    pub const Cell = struct { sep: []const u8, child: PageId };

    pub fn init(arena: Allocator, leftmost: PageId) BranchBuilder {
        return .{ .arena = arena, .leftmost = leftmost };
    }

    pub fn deinit(self: *BranchBuilder) void {
        self.cells.deinit(self.arena);
    }

    pub fn fromPage(arena: Allocator, page: *const [page_size]u8) !BranchBuilder {
        const br = Branch.init(page);
        var b = BranchBuilder.init(arena, br.leftmost());
        var i: usize = 0;
        while (i < br.count()) : (i += 1) {
            try b.cells.append(arena, .{
                .sep = try arena.dupe(u8, br.keyAt(i)),
                .child = br.rightChildAt(i),
            });
        }
        return b;
    }

    /// Insert a (separator, right-child) pair, keeping the directory sorted.
    /// Used after a child split promotes a separator up.
    pub fn insert(self: *BranchBuilder, sep: []const u8, child: PageId) !void {
        var lo: usize = 0;
        var hi: usize = self.cells.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (std.mem.lessThan(u8, self.cells.items[mid].sep, sep)) lo = mid + 1 else hi = mid;
        }
        try self.cells.insert(self.arena, lo, .{ .sep = try self.arena.dupe(u8, sep), .child = child });
    }

    pub fn byteSize(self: *const BranchBuilder) usize {
        var n: usize = hdr_len;
        for (self.cells.items) |c| n += slot_len + branchCellBytes(c.sep.len);
        return n;
    }

    pub fn overflows(self: *const BranchBuilder) bool {
        return self.byteSize() > page_size;
    }

    pub fn encode(self: *const BranchBuilder, page: *[page_size]u8) void {
        encodeBranch(page, self.leftmost, self.cells.items);
    }

    /// Split an overflowing branch. The middle separator is promoted OUT (it
    /// becomes the parent's separator and does not live in either half — proper
    /// B-tree branch split), the right half's leftmost child is the promoted
    /// cell's child.
    pub fn split(self: *BranchBuilder) !SplitBranch {
        const n = self.cells.items.len;
        std.debug.assert(n >= 2);
        const mid = n / 2;
        const promoted = self.cells.items[mid];
        var right = BranchBuilder.init(self.arena, promoted.child);
        for (self.cells.items[mid + 1 ..]) |c|
            try right.cells.append(self.arena, c);
        self.cells.shrinkRetainingCapacity(mid);
        return .{ .right = right, .sep = promoted.sep };
    }
};

pub const SplitBranch = struct { right: BranchBuilder, sep: []const u8 };

// ── low-level cell sizing + slotted-page encoders ────────────────────────────

fn leafCellBytes(klen: usize, vlen: usize) usize {
    return 6 + klen + vlen; // key_len(2) + val_len(4) + key + val
}
fn branchCellBytes(klen: usize) usize {
    return 6 + klen; // key_len(2) + right_child(4) + key
}

fn writeHeader(page: *[page_size]u8, kind: NodeKind, count: u16, leftmost: PageId) void {
    @memset(page, 0);
    page[0] = @intFromEnum(kind);
    page[1] = 0;
    std.mem.writeInt(u16, page[2..4], count, .little);
    std.mem.writeInt(u32, page[4..8], leftmost, .little);
}

fn encodeLeaf(page: *[page_size]u8, entries: []const Entry) void {
    writeHeader(page, .leaf, @intCast(entries.len), 0);
    var tail: usize = page_size; // cells packed from the end downward
    for (entries, 0..) |e, i| {
        const cell = leafCellBytes(e.key.len, e.val.len);
        tail -= cell;
        std.mem.writeInt(u16, page[tail .. tail + 2][0..2], @intCast(e.key.len), .little);
        std.mem.writeInt(u32, page[tail + 2 .. tail + 6][0..4], @intCast(e.val.len), .little);
        @memcpy(page[tail + 6 ..][0..e.key.len], e.key);
        @memcpy(page[tail + 6 + e.key.len ..][0..e.val.len], e.val);
        const slot = hdr_len + i * slot_len;
        std.mem.writeInt(u16, page[slot .. slot + 2][0..2], @intCast(tail), .little);
    }
}

fn encodeBranch(page: *[page_size]u8, leftmost: PageId, cells: []const BranchBuilder.Cell) void {
    writeHeader(page, .branch, @intCast(cells.len), leftmost);
    var tail: usize = page_size;
    for (cells, 0..) |c, i| {
        const cell = branchCellBytes(c.sep.len);
        tail -= cell;
        std.mem.writeInt(u16, page[tail .. tail + 2][0..2], @intCast(c.sep.len), .little);
        std.mem.writeInt(u32, page[tail + 2 .. tail + 6][0..4], c.child, .little);
        @memcpy(page[tail + 6 ..][0..c.sep.len], c.sep);
        const slot = hdr_len + i * slot_len;
        std.mem.writeInt(u16, page[slot .. slot + 2][0..2], @intCast(tail), .little);
    }
}

/// Format a fresh empty-leaf root page (the initial tree).
pub fn encodeEmptyLeaf(page: *[page_size]u8) void {
    writeHeader(page, .leaf, 0, 0);
}

// ── tests: the mechanical machinery, all real today ──────────────────────────

const testing = std.testing;

test "meta round-trips and the CRC catches a flipped byte" {
    var page: [page_size]u8 = undefined;
    const m = Meta{ .txn_id = 7, .root = 42, .free_root = 9, .free_count = 3, .high_water = 100 };
    m.encode(&page);
    const got = Meta.decode(&page).?;
    try testing.expectEqual(m, got);
    page[30] ^= 0xff; // corrupt a field byte
    try testing.expect(Meta.decode(&page) == null);
}

test "meta rejects foreign / wrong-version pages" {
    var page: [page_size]u8 = @splat(0);
    try testing.expect(Meta.decode(&page) == null); // no magic
    @memcpy(page[0..4], meta_magic);
    std.mem.writeInt(u32, page[4..8], 999, .little); // wrong version
    try testing.expect(Meta.decode(&page) == null);
}

test "leaf encode/decode round-trip + binary search (found + insertion point)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var b = LeafBuilder.init(a);
    try b.put("banana", "yellow");
    try b.put("apple", "red");
    try b.put("cherry", "dark");
    try b.put("apple", "green"); // overwrite
    try testing.expectEqual(@as(usize, 3), b.entries.items.len);

    var page: [page_size]u8 = undefined;
    b.encode(&page);
    const leaf = Leaf.init(&page);
    try testing.expectEqual(@as(u16, 3), leaf.count());
    // sorted: apple, banana, cherry
    try testing.expectEqualStrings("apple", leaf.keyAt(0));
    try testing.expectEqualStrings("green", leaf.valAt(0)); // overwrite won
    try testing.expectEqualStrings("cherry", leaf.keyAt(2));

    try testing.expect(leaf.search("banana").found);
    try testing.expectEqual(@as(u16, 1), leaf.search("banana").index);
    const miss = leaf.search("blueberry");
    try testing.expect(!miss.found);
    try testing.expectEqual(@as(u16, 2), miss.index); // would insert before cherry
}

test "leaf delete" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var b = LeafBuilder.init(arena_state.allocator());
    try b.put("a", "1");
    try b.put("b", "2");
    try testing.expect(b.del("a"));
    try testing.expect(!b.del("a"));
    try testing.expectEqual(@as(usize, 1), b.entries.items.len);
    try testing.expectEqualStrings("b", b.entries.items[0].key);
}

test "leaf split halves entries and reports a correct separator" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var b = LeafBuilder.init(a);
    // Fill until it overflows a page (big values force it fast).
    var big: [400]u8 = undefined;
    @memset(&big, 'x');
    var i: usize = 0;
    while (!b.overflows()) : (i += 1) {
        var kb: [8]u8 = undefined;
        try b.put(try std.fmt.bufPrint(&kb, "k{d:0>5}", .{i}), &big);
    }
    const before = b.entries.items.len;
    const sp = try b.split();
    try testing.expectEqual(before, b.entries.items.len + sp.right.entries.items.len);
    // separator == right half's first key; every left key < separator.
    try testing.expectEqualStrings(sp.right.entries.items[0].key, sp.sep);
    for (b.entries.items) |e| try testing.expect(std.mem.lessThan(u8, e.key, sp.sep));
    // both halves individually fit a page now.
    try testing.expect(!b.overflows());
    try testing.expect(!sp.right.overflows());
}

test "branch encode/decode round-trip + childFor routing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // leftmost=10; separators m,t → children 10,20,30
    var b = BranchBuilder.init(a, 10);
    try b.insert("m", 20);
    try b.insert("t", 30);

    var page: [page_size]u8 = undefined;
    b.encode(&page);
    const br = Branch.init(&page);
    try testing.expectEqual(@as(u16, 2), br.count());
    try testing.expectEqual(@as(PageId, 10), br.leftmost());
    try testing.expectEqual(@as(PageId, 10), br.childFor("a")); // < m → leftmost
    try testing.expectEqual(@as(PageId, 20), br.childFor("m")); // == m → right of m
    try testing.expectEqual(@as(PageId, 20), br.childFor("p")); // m<=p<t
    try testing.expectEqual(@as(PageId, 30), br.childFor("t")); // >= t
    try testing.expectEqual(@as(PageId, 30), br.childFor("z"));
}

test "branch split promotes the middle separator out of both halves" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var b = BranchBuilder.init(a, 1);
    // separators a,b,c,d,e with children 2..6
    const seps = [_][]const u8{ "a", "b", "c", "d", "e" };
    for (seps, 0..) |s, k| try b.insert(s, @intCast(k + 2));
    const total_children_before = b.cells.items.len + 1;
    const sp = try b.split();
    // promoted separator is in neither half; children conserved.
    const total_children_after = (b.cells.items.len + 1) + (sp.right.cells.items.len + 1);
    try testing.expectEqual(total_children_before, total_children_after);
    for (b.cells.items) |c| try testing.expect(std.mem.lessThan(u8, c.sep, sp.sep));
    for (sp.right.cells.items) |c| try testing.expect(std.mem.lessThan(u8, sp.sep, c.sep));
}

test "branchViewSafe accepts a real branch, rejects garbage geometry" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var b = BranchBuilder.init(arena_state.allocator(), 10);
    try b.insert("m", 20);
    var page: [page_size]u8 = undefined;
    b.encode(&page);
    try testing.expect(branchViewSafe(&page) != null);

    var bad = page;
    bad[0] = 0; // a leaf is not a branch
    try testing.expect(branchViewSafe(&bad) == null);
    bad = page;
    bad[0] = 7; // not a node kind at all
    try testing.expect(branchViewSafe(&bad) == null);
    bad = page;
    std.mem.writeInt(u16, bad[2..4], 3000, .little); // count overruns the page
    try testing.expect(branchViewSafe(&bad) == null);
    bad = page;
    std.mem.writeInt(u16, bad[8..10], page_size - 2, .little); // cell off the end
    try testing.expect(branchViewSafe(&bad) == null);
}

test "oversize entry is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var b = LeafBuilder.init(arena_state.allocator());
    const huge = try arena_state.allocator().alloc(u8, page_size);
    try testing.expectError(error.EntryTooLarge, b.put("k", huge));
}

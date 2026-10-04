// SPDX-License-Identifier: MIT

//! Bulk load: a fresh store written bottom-up from entries in ascending key
//! order. `Snapshot.copyTo` builds a backup -- and with it a compacted copy --
//! this way.
//!
//! This is not the commit path, and it needs none of the commit core's
//! ordering: the file it writes is a temp that `copyTo` renames into place only
//! after `finish` has synced it, so a crash part-way leaves nothing at the
//! destination path, and there is no older version in the file to protect.
//!
//! What the copy looks like. Every node is filled until the next entry would
//! not fit. (A commit halves a node that overflows, so a store grown by
//! commits has nodes between half and fully used; its copy has them full.)
//! Each level holds one finished node back, so that at the end the last two
//! nodes of a level can be shared out by bytes, as a commit's merge does: the
//! last node is not left with a single entry, and with entries of similar
//! size no node but the root is under a quarter full. No branch has a single
//! child. Pages are written in key order from page 2 up, an
//! overflow chain just before the leaf that refers to it. Nothing is free, so
//! the freelist is empty and `high_water` is exactly the pages written. Both
//! meta slots get the same meta at txn 0, the shape `initFresh` gives an empty
//! store.
const std = @import("std");
const Allocator = std.mem.Allocator;
const kv = @import("kv");
const format = @import("format.zig");
const pager_mod = @import("pager.zig");

const page_size = format.page_size;
const PageId = format.PageId;
const Pager = pager_mod.Pager;

pub const Error = kv.Storage.Error || error{
    OutOfMemory,
    /// A key/value pair no leaf can hold (see `format.oversize_error`).
    EntryTooLarge,
    /// A key not strictly above the one before it. From a cursor over a
    /// store, that is a tree whose leaves are out of order -- and a copy must
    /// not carry rot forward.
    Corrupt,
};

/// Branch levels a store can have: every branch has at least two children,
/// so a tree of at most 2^32 pages is at most 32 levels above its leaves.
const max_levels = 32;

/// Writes through `pager`, from page 2 up. Pinned once used: it hands out
/// allocators of arenas it holds by value, so create it in place and use it
/// through a pointer.
pub const Loader = struct {
    gpa: Allocator,
    pager: *Pager,
    next_id: PageId = format.first_data_page,
    wrote_overflow: bool = false,
    leaves: Level(format.LeafBuilder),
    /// `levels[0]` holds the leaves' parents, each next one the level above.
    levels: [max_levels]Level(format.BranchBuilder) = undefined,
    n_levels: usize = 0,

    pub fn init(gpa: Allocator, pager: *Pager) Loader {
        return .{ .gpa = gpa, .pager = pager, .leaves = .init(gpa) };
    }

    pub fn deinit(self: *Loader) void {
        self.leaves.deinit();
        for (self.levels[0..self.n_levels]) |*l| l.deinit();
        self.* = undefined;
    }

    /// Append one entry; keys must come in strictly ascending order.
    pub fn add(self: *Loader, key: []const u8, val: []const u8) Error!void {
        if (self.leaves.lastKey()) |last| if (!std.mem.lessThan(u8, last, key)) return error.Corrupt;
        if (format.fitsInline(key.len, val.len)) return self.addLeafEntry(key, val, null);
        // The same rule as the commit path: a value goes to overflow pages
        // exactly when its cell does not fit an empty leaf.
        if (val.len > format.max_value_len or !format.fitsOverflowRef(key.len)) return error.EntryTooLarge;
        var ref: [format.ovf_ref_len]u8 = undefined;
        std.mem.writeInt(u32, &ref, try self.writeOverflow(val), .little);
        return self.addLeafEntry(key, &ref, @intCast(val.len));
    }

    /// Write what is held back, then both meta slots, and sync. The store is
    /// complete once this returns; the `Loader` is spent.
    pub fn finish(self: *Loader) Error!void {
        const root = try self.finishTree();
        const m = format.Meta{
            .txn_id = 0,
            .root = root,
            .free_root = 0,
            .free_count = 0,
            .high_water = self.next_id,
            .version = if (self.wrote_overflow) format.format_v3 else format.format_v2,
        };
        var buf: [page_size]u8 = undefined;
        m.encode(&buf);
        try self.pager.writePage(format.meta_page_a, &buf);
        try self.pager.writePage(format.meta_page_b, &buf);
        try self.pager.sync();
    }

    fn finishTree(self: *Loader) Error!PageId {
        const lf = &self.leaves;
        if (lf.prev == null) {
            // One leaf at most, so it is the root (an empty one for no entries).
            std.debug.assert(self.n_levels == 0);
            if (lf.cur) |*c| return self.writeNode(c);
            var buf: [page_size]u8 = undefined;
            format.encodeEmptyLeaf(&buf);
            return self.writeRaw(&buf);
        }
        {
            var p = lf.prev.?;
            const c = lf.cur.?; // a rotation is always followed by an entry
            if (c.underflows()) {
                // Into `p`'s arena; `c`'s stays alive until `deinit`.
                try p.entries.appendSlice(p.arena, c.entries.items);
                try self.splitPair(0, &p, p.entries.items[0].key);
            } else {
                try self.addChild(0, p.entries.items[0].key, try self.writeNode(&p));
                try self.addChild(0, c.entries.items[0].key, try self.writeNode(&c));
            }
        }
        var lv: usize = 0;
        while (true) : (lv += 1) {
            const l = &self.levels[lv];
            const c = &l.cur.?;
            if (lv + 1 == self.n_levels and l.prev == null) {
                // The top level, holding one node: the root. It has two
                // children at least -- the level below closed a node before
                // this one opened, and wrote it or the pair it split into.
                std.debug.assert(c.cells.items.len > 0);
                return self.writeNode(c);
            }
            // Not the top, or the top with two nodes: either way the level
            // above has (or gets, from the writes below) a parent for these.
            var p = l.prev.?;
            if (c.underflows()) {
                try p.cells.append(p.arena, .{ .sep = l.cur_sep, .child = c.leftmost });
                try p.cells.appendSlice(p.arena, c.cells.items);
                try self.splitPair(lv + 1, &p, l.prev_sep);
            } else {
                try self.addChild(lv + 1, l.prev_sep, try self.writeNode(&p));
                try self.addChild(lv + 1, l.cur_sep, try self.writeNode(c));
            }
        }
    }

    /// Write `node` -- the union of a level's last two nodes, referred to by
    /// `sep` -- as two pages shared out by bytes, and hand them to the level
    /// `parent`. The union never fits one page: the first of the two was
    /// closed because the entry that opened the second did not fit in it.
    fn splitPair(self: *Loader, parent: usize, node: anytype, sep: []const u8) Error!void {
        std.debug.assert(node.overflows());
        var sp = try node.split();
        try self.addChild(parent, sep, try self.writeNode(node));
        try self.addChild(parent, sp.sep, try self.writeNode(&sp.right));
    }

    fn addLeafEntry(self: *Loader, key: []const u8, val: []const u8, ovf_len: ?u32) Error!void {
        const l = &self.leaves;
        const need = format.leafEntryBytes(key.len, val.len);
        // A lone entry always fits (`add` checked), so `cur` is not empty here.
        if (l.cur != null and l.cur_bytes + need > page_size) {
            if (l.prev) |*p| try self.addChild(0, p.entries.items[0].key, try self.writeNode(p));
            l.rotate();
        }
        const a = l.arenas[l.cur_arena].allocator();
        if (l.cur == null) l.cur = format.LeafBuilder.init(a);
        try l.cur.?.entries.append(a, .{ .key = try a.dupe(u8, key), .val = try a.dupe(u8, val), .ovf_len = ovf_len });
        l.cur_bytes += need;
    }

    /// Hand the node at `id`, referred to by `sep`, to branch level `lv`.
    fn addChild(self: *Loader, lv: usize, sep: []const u8, id: PageId) Error!void {
        if (lv == self.n_levels) {
            std.debug.assert(lv < max_levels);
            self.levels[lv] = .init(self.gpa);
            self.n_levels += 1;
        }
        const l = &self.levels[lv];
        const need = format.branchEntryBytes(sep.len);
        if (l.cur) |*c| {
            if (l.cur_bytes + need <= page_size) {
                const a = l.arenas[l.cur_arena].allocator();
                try c.cells.append(a, .{ .sep = try a.dupe(u8, sep), .child = id });
                l.cur_bytes += need;
                return;
            }
            // A branch takes any one cell after its leftmost child (a key
            // that fits a leaf fits a branch), so `cur` has a cell here.
            if (l.prev) |*p| try self.addChild(lv + 1, l.prev_sep, try self.writeNode(p));
            l.rotate();
        }
        // The child opens a node: it is the leftmost, and its separator is
        // the one the new node is referred to by.
        const a = l.arenas[l.cur_arena].allocator();
        l.cur = format.BranchBuilder.init(a, id);
        l.cur_sep = try a.dupe(u8, sep);
    }

    fn writeOverflow(self: *Loader, val: []const u8) Error!PageId {
        const n = format.ovfPages(val.len);
        const first = self.next_id;
        var buf: [page_size]u8 = undefined;
        for (0..n) |k| {
            const start = k * format.ovf_data;
            const end = @min(val.len, start + format.ovf_data);
            format.encodeOverflow(&buf, if (k + 1 < n) self.next_id + 1 else 0, val[start..end]);
            _ = try self.writeRaw(&buf);
        }
        self.wrote_overflow = true;
        return first;
    }

    fn writeNode(self: *Loader, node: anytype) Error!PageId {
        var buf: [page_size]u8 = undefined;
        node.encode(&buf);
        return self.writeRaw(&buf);
    }

    fn writeRaw(self: *Loader, buf: *const [page_size]u8) Error!PageId {
        const id = self.next_id;
        try self.pager.writePage(id, buf);
        self.next_id += 1;
        return id;
    }
};

/// One level of the tree being built: the node being filled (`cur`) and the
/// full one held back (`prev`), each in its own arena. Builders borrow every
/// key and separator, so a node's arena lives until the node is written --
/// and the held-back node's until the one after it is full.
fn Level(comptime Builder: type) type {
    return struct {
        const Self = @This();

        arenas: [2]std.heap.ArenaAllocator,
        /// Which of `arenas` `cur` lives in; `prev` lives in the other.
        cur_arena: u1 = 0,
        cur: ?Builder = null,
        cur_bytes: usize = format.empty_node_bytes,
        /// The separator `cur` is referred to by in its parent. Branches
        /// only: a leaf's is its first key.
        cur_sep: []const u8 = "",
        prev: ?Builder = null,
        prev_sep: []const u8 = "",

        fn init(gpa: Allocator) Self {
            return .{ .arenas = .{ .init(gpa), .init(gpa) } };
        }

        fn deinit(self: *Self) void {
            for (&self.arenas) |*a| a.deinit();
        }

        /// `cur` is full and `prev` written: hold `cur` back, and free the
        /// written node's arena for the next one.
        fn rotate(self: *Self) void {
            self.prev = self.cur;
            self.prev_sep = self.cur_sep;
            self.cur_arena ^= 1;
            _ = self.arenas[self.cur_arena].reset(.retain_capacity);
            self.cur = null;
            self.cur_sep = "";
            self.cur_bytes = format.empty_node_bytes;
        }

        /// The last key added (leaves only): `cur`'s last, since a rotation
        /// is always followed by the entry that caused it.
        fn lastKey(self: *const Self) ?[]const u8 {
            const c = self.cur orelse return null;
            return c.entries.items[c.entries.items.len - 1].key;
        }
    };
}

test "a key not above the one before it is Corrupt: a copy does not carry a tree out of order forward" {
    var sim = kv.SimStorage.init(std.testing.allocator);
    defer sim.deinit();
    const s = sim.storage();
    const h = try s.open("b", .create_truncate);
    defer s.close(h);
    var pager = Pager.init(s, h, 0);
    var l = Loader.init(std.testing.allocator, &pager);
    defer l.deinit();
    try l.add("b", "1");
    try std.testing.expectError(error.Corrupt, l.add("b", "2"));
    try std.testing.expectError(error.Corrupt, l.add("a", "2"));
    try l.add("c", "3");
}

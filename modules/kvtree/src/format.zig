// SPDX-License-Identifier: MIT

//! format — the on-disk page layout and the MECHANICAL B-tree node machinery.
//!
//! This is pure, allocator-explicit, I/O-free code: it turns page-sized byte
//! buffers into typed views (`Meta`, `Leaf`, `Branch`) and back, does the
//! in-node binary search, and performs the classic B-tree node mutations —
//! insert, delete and split. Node split is textbook, deterministic, and
//! unit-tested here directly (see the tests at the bottom); `underflows` tells
//! the commit (`core.mergeUnderfull`) when a node is to be merged with a
//! sibling or dropped. The correctness-critical parts —
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
//! variable-length cells packed against the end of the page (a leaf's in
//! ascending key order; readers only follow the slot offsets).

const std = @import("std");
const crc32 = @import("crc32");
const Allocator = std.mem.Allocator;

pub const page_size: usize = 4096;

/// Page number. Byte offset of page `id` in the file is `id * page_size`.
pub const PageId = u32;

pub const meta_page_a: PageId = 0;
pub const meta_page_b: PageId = 1;
/// The first page the allocator may hand out for tree/freelist data.
pub const first_data_page: PageId = 2;

/// The deepest tree (node levels from the root down to a leaf) any walk of a
/// file accepts; deeper is `error.Corrupt` -- at open (`core.recover`) and again
/// at each descent, so a node that rotted into a cycle ends in an error, not a
/// loop. Derivation: a tree this module writes has at least two children per
/// branch (a root left with one is collapsed at its commit, a non-root branch
/// left with one is merged into a sibling), so with at most 2^32 pages it has
/// at most 32 branch levels above its leaves (`bulk.max_levels`), i.e. 33 node
/// levels. 40 leaves slack for a single-child chain a commit might park
/// transiently, and bounds the recursion of a commit (`core.applyRec`: one
/// 4 KiB page buffer + ~0.3 KiB of locals per level) to about 175 KiB of stack
/// (estimated from the buffer sizes, not measured).
pub const max_tree_depth: usize = 40;

/// How many buckets may nest inside one another (the top level's buckets are
/// level 1). Deeper is `error.BucketTooDeep` from `createBucket` and `Corrupt`
/// for a file that has it. The recursion over nested buckets (`applyTree`,
/// `treeOf`, `copyTree`) holds one page buffer or less per level, so 16 levels
/// stay under ~100 KiB of stack.
pub const max_bucket_depth: usize = 16;

pub const NodeKind = enum(u8) { leaf = 0, branch = 1 };

const meta_magic = "ZKVT";
/// Bumped 1 -> 2 when the freelist gained page chaining: its page header grew
/// from `count(2)` to `count(2) + next(4)`, so a v1 freelist page read with the
/// v2 layout yields a garbage `next` pointer (v1 held the first entry in those
/// bytes) and every entry after it shifted by 4. Freelist pages carry no magic
/// or CRC of their own -- this version, checked in `Meta.decode`, is the ONLY
/// thing standing between an old file and a chain walk into arbitrary pages, so
/// opening a v1 file must fail closed rather than misread it.
///
/// Bumped 2 -> 3 for overflow values (a leaf cell whose value lives in a chain
/// of overflow pages, flagged in its `val_len`) -- but only for a store that
/// has one: a commit writes v3 once it writes an overflow value, and every
/// commit after it keeps v3 (`Meta.version`). A store that never held a value
/// larger than a page stays v2 and opens with an older build. A v3 store is
/// refused by one (its `decode` accepts exactly its own version), where the
/// alternative -- reading a flagged `val_len` as a length -- would reject the
/// newest meta in `recover` and silently adopt the one before it.
///
/// Bumped 3 -> 4 for buckets (a leaf cell flagged `bucket_flag` whose value is
/// a nested tree's root), on the same sticky terms: a store gets v4 with its
/// first bucket and keeps it; one that never had a bucket stays v2/v3.
pub const format_v2: u32 = 2;
pub const format_v3: u32 = 3;
pub const format_v4: u32 = 4;

/// The version a store holding what `overflow`/`bucket` say needs, never below
/// `base` (versions are sticky).
pub fn versionFor(base: u32, overflow: bool, bucket: bool) u32 {
    const need: u32 = if (bucket) format_v4 else if (overflow) format_v3 else format_v2;
    return @max(base, need);
}

/// A single leaf entry (borrowed slices into a page buffer, or into a builder's
/// arena — never owns). For an overflow value (`ovf_len` set) `val` is not the
/// value but its `ovf_ref_len`-byte reference: the first overflow page's id.
///
/// A BUCKET entry (`bucket`) has a `bucket_hdr_len`-byte `BucketHdr` as its
/// value: the root of the nested tree that holds the bucket's keys.
pub const Entry = struct { key: []const u8, val: []const u8, ovf_len: ?u32 = null, bucket: bool = false };

// ── Buckets ──────────────────────────────────────────────────────────────────
//
// A bucket is a named, nested key space (bbolt's `Bucket`): a whole B-tree of
// its own, whose root a cell in its parent's leaf points to. The cell's
// `val_len` carries `bucket_flag` (an inline cell never has a length anywhere
// near it, an overflow cell has `ovf_flag` instead), and its value is a
// `BucketHdr`. Everything else -- copy-on-write, the freelist, the reclaim
// gate, the two fsyncs -- is the parent tree's: a commit rewrites a bucket's
// tree bottom-up and then the cell that points to it, like any other value.

/// `val_len`'s second bit: the value is a `BucketHdr` (inline cells only).
pub const bucket_flag: u32 = 0x4000_0000;
/// Bytes of a bucket cell's value: `root(4) seq(8)`.
pub const bucket_hdr_len = 12;

/// A bucket cell's value: the nested tree's root page and the bucket's
/// sequence counter (bbolt's `NextSequence`).
pub const BucketHdr = struct {
    root: PageId,
    seq: u64,

    pub fn encode(self: BucketHdr, out: *[bucket_hdr_len]u8) void {
        std.mem.writeInt(u32, out[0..4], self.root, .little);
        std.mem.writeInt(u64, out[4..12], self.seq, .little);
    }

    /// `error.Corrupt` for a value that is not exactly `bucket_hdr_len` bytes:
    /// the length comes out of a page, so it is data, not an invariant.
    pub fn decode(bytes: []const u8) error{Corrupt}!BucketHdr {
        if (bytes.len != bucket_hdr_len) return error.Corrupt;
        return .{
            .root = std.mem.readInt(u32, bytes[0..4], .little),
            .seq = std.mem.readInt(u64, bytes[4..12], .little),
        };
    }
};

// ── Overflow values ──────────────────────────────────────────────────────────
//
// A value whose cell does not fit an otherwise-empty leaf lives in a chain of
// OVERFLOW pages, and its leaf cell carries only a reference: `val_len` has its
// top bit set (`ovf_flag`), the low 31 bits are the value's length, and the
// cell's value bytes are the first overflow page's id. Everything that fits a
// leaf stays inline, exactly as before overflow existed -- so a store's inline
// values, and `getRef`'s ability to lend them, never change with this.
//
// An overflow page is `kind(1) = overflow_kind, 0(3), next(4)` and then up to
// `ovf_data` value bytes; `next` is 0 on the last page. The chain is written
// once, copy-on-write like everything else: a new or overwritten value gets a
// fresh chain, and the old one goes to the freelist with the leaf's other dead
// pages. A leaf rewritten for another key's sake keeps the reference as it is,
// so the chain is shared between versions like an untouched subtree is.

/// `val_len`'s top bit: the value is in overflow pages.
pub const ovf_flag: u32 = 0x8000_0000;
/// Bytes of a leaf cell's value field that hold an overflow reference.
pub const ovf_ref_len = 4;
/// The longest value a store accepts (the low 31 bits of `val_len`).
pub const max_value_len: usize = ovf_flag - 1;
/// An overflow page's kind byte -- never a `NodeKind`, so `kindOf` answers
/// `null` for it and a tree walk that reaches one reports corruption.
pub const overflow_kind: u8 = 2;
const ovf_hdr = 8;
/// Value bytes one overflow page holds.
pub const ovf_data = page_size - ovf_hdr;

/// Overflow pages a value of `len` bytes takes.
pub fn ovfPages(len: usize) usize {
    return (len + ovf_data - 1) / ovf_data;
}

/// Write one overflow page: `data` (at most `ovf_data` bytes) then zeros.
pub fn encodeOverflow(page: *[page_size]u8, next: PageId, data: []const u8) void {
    std.debug.assert(data.len <= ovf_data);
    zeroPage(page);
    page[0] = overflow_kind;
    std.mem.writeInt(u32, page[4..8], next, .little);
    @memcpy(page[ovf_hdr..][0..data.len], data);
}

/// An overflow page's `next` pointer, or `null` when the page is not one.
pub fn overflowNext(page: *const [page_size]u8) ?PageId {
    if (page[0] != overflow_kind) return null;
    return std.mem.readInt(u32, page[4..8], .little);
}

/// An overflow page's value bytes (all of them; the caller takes its share).
pub fn overflowData(page: *const [page_size]u8) *const [ovf_data]u8 {
    return page[ovf_hdr..];
}

/// Zero a whole page with 32-byte volatile vector stores.
///
/// Not `@memset`: without libc that lowers to `compiler_rt.memset`, which in
/// Zig 0.16 stores ONE BYTE at a time -- measured at ~5 600 instructions per
/// 4 KiB page in ReleaseFast, 19 % of the user-side cost of a `kvtree` commit
/// (qap perf audit, 2026-09-21). The vector loop is ~170. Volatile so LLVM's
/// loop-idiom pass cannot fold the loop back into that same `memset` call.
pub fn zeroPage(page: *[page_size]u8) void {
    const V = @Vector(32, u8);
    comptime std.debug.assert(page_size % @sizeOf(V) == 0);
    // Page buffers are plain `[page_size]u8` on callers' stacks: byte
    // aligned, so the stores are the unaligned form (a `movdqu`, not a
    // `movdqa` -- same cost on every x86 since Nehalem, and no trap).
    const words: [*]align(1) volatile V = @ptrCast(page);
    for (0..page_size / @sizeOf(V)) |k| words[k] = @splat(0);
}

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
    /// `format_v2`, or `format_v3` once the store has held an overflow value
    /// (see `format_v3`). Sticky: a commit never writes a lower version than
    /// its base.
    version: u32 = format_v2,

    const crc_off = 44; // bytes [0..44) are covered by the CRC at [44..48)

    pub fn encode(self: Meta, page: *[page_size]u8) void {
        zeroPage(page);
        @memcpy(page[0..4], meta_magic);
        std.debug.assert(self.version >= format_v2 and self.version <= format_v4);
        std.mem.writeInt(u32, page[4..8], self.version, .little);
        std.mem.writeInt(u32, page[8..12], @intCast(page_size), .little);
        std.mem.writeInt(u64, page[12..20], self.txn_id, .little);
        std.mem.writeInt(u32, page[20..24], self.root, .little);
        std.mem.writeInt(u32, page[24..28], self.free_root, .little);
        std.mem.writeInt(u64, page[28..36], self.free_count, .little);
        std.mem.writeInt(u64, page[36..44], self.high_water, .little);
        const crc = crc32.hash(page[0..crc_off]);
        std.mem.writeInt(u32, page[crc_off .. crc_off + 4][0..4], crc, .little);
    }

    /// Structural + CRC validation only. `null` = not a valid meta page of
    /// this format (bad magic/version/geometry, or a torn/corrupt page whose
    /// CRC does not hold). A non-null result is a self-consistent meta record;
    /// whether it is the one to *adopt* is `core.recover`'s call.
    pub fn decode(page: *const [page_size]u8) ?Meta {
        if (!std.mem.eql(u8, page[0..4], meta_magic)) return null;
        const version = std.mem.readInt(u32, page[4..8], .little);
        if (version < format_v2 or version > format_v4) return null;
        if (std.mem.readInt(u32, page[8..12], .little) != page_size) return null;
        const want = std.mem.readInt(u32, page[crc_off .. crc_off + 4][0..4], .little);
        if (crc32.hash(page[0..crc_off]) != want) return null;
        return .{
            .txn_id = std.mem.readInt(u64, page[12..20], .little),
            .root = std.mem.readInt(u32, page[20..24], .little),
            .free_root = std.mem.readInt(u32, page[24..28], .little),
            .free_count = std.mem.readInt(u64, page[28..36], .little),
            .high_water = std.mem.readInt(u64, page[36..44], .little),
            .version = version,
        };
    }
};

// ── node header + slot directory (shared leaf/branch) ────────────────────────

const hdr_len = 8;
const slot_len = 2;

fn nodeKind(page: *const [page_size]u8) NodeKind {
    return @fromBackingInt(@intCast(page[0]));
}

/// The most slots any node page can hold: a cell is at least 6 bytes and takes
/// a 2-byte slot, so `count` above this cannot come from a page this format
/// wrote -- it is rot, and every accessor below says `Corrupt` for it.
pub const max_node_count: usize = (page_size - hdr_len) / (slot_len + 6);
/// The longest single cell (and so the longest key, with its 6 header bytes)
/// an otherwise-empty node can hold. A rotted length above it is `Corrupt`; it
/// also guarantees a lone cell never overflows its node, which `split` relies on.
const max_cell_len: usize = page_size - hdr_len - slot_len;

fn nodeCount(page: *const [page_size]u8) error{Corrupt}!u16 {
    const n = std.mem.readInt(u16, page[2..4], .little);
    if (n > max_node_count) return error.Corrupt;
    return n;
}
fn nodeLeftmost(page: *const [page_size]u8) PageId {
    return std.mem.readInt(u32, page[4..8], .little);
}

// SQLite-style point-of-use checking (owner decision 2026-10-29): node pages
// carry no CRC and `recover` validates them once, at open. A page can rot (or
// be rewritten by another process) after that, so every offset, length and
// count read out of a page below is compared against the page bounds where it
// is used -- one compare per decoded field, no extra pass -- and a bad one is
// `error.Corrupt`, never a slice out of range.
fn slotOffset(page: *const [page_size]u8, i: usize) error{Corrupt}!usize {
    const base = hdr_len + i * slot_len;
    if (base + 2 > page_size) return error.Corrupt;
    return std.mem.readInt(u16, page[base .. base + 2][0..2], .little);
}

/// A decoded cell header: where the cell starts, its key length and the
/// second header word (`val_len` of a leaf cell, `right_child` of a branch's).
const CellHdr = struct { o: usize, klen: usize, raw: u32 };

fn cellHdr(page: *const [page_size]u8, i: usize) error{Corrupt}!CellHdr {
    const o = try slotOffset(page, i);
    if (o + 6 > page_size) return error.Corrupt;
    return .{
        .o = o,
        .klen = std.mem.readInt(u16, page[o .. o + 2][0..2], .little),
        .raw = std.mem.readInt(u32, page[o + 2 .. o + 6][0..4], .little),
    };
}

/// The key of the cell `c`, bounds-checked.
fn cellKey(page: *const [page_size]u8, c: CellHdr) error{Corrupt}![]const u8 {
    if (c.o + 6 + c.klen > page_size or 6 + c.klen > max_cell_len) return error.Corrupt;
    return page[c.o + 6 ..][0..c.klen];
}

/// A leaf cell's value length as the page states it (the reference size for
/// an overflow value), and the `ovf` flag.
fn leafValLen(raw: u32) usize {
    return if (raw & ovf_flag != 0) ovf_ref_len else raw & ~bucket_flag;
}

/// The value of leaf cell `c`, bounds-checked together with its key.
fn leafCellVal(page: *const [page_size]u8, c: CellHdr) error{Corrupt}![]const u8 {
    const vlen = leafValLen(c.raw);
    if (c.o + 6 + c.klen + vlen > page_size or 6 + c.klen + vlen > max_cell_len) return error.Corrupt;
    return page[c.o + 6 + c.klen ..][0..vlen];
}

/// Bounds-checked dispatch on a page's kind byte: `null` for any byte that is
/// not a valid `NodeKind` tag, instead of `@enumFromInt`'s illegal behavior
/// (a checked panic under safety, undefined in ReleaseFast). Node pages carry
/// no CRC (only meta pages do), so a single flipped byte on media — or a page
/// this open session read after `recover`'s one-time validation but before it
/// was next touched — is enough to reach an out-of-range byte here. Callers
/// on the committed-tree read/write paths turn `null` into `error.Corrupt`;
/// `nodeKind` (used by `Leaf.init`/`Branch.init`'s asserts) stays raw because
/// every caller of THOSE has already gone through here first.
pub fn kindOf(page: *const [page_size]u8) ?NodeKind {
    return switch (page[0]) {
        @backingInt(NodeKind.leaf) => .leaf,
        @backingInt(NodeKind.branch) => .branch,
        else => null,
    };
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

    /// Number of entries; `error.Corrupt` for a count no page can hold.
    pub fn count(self: Leaf) error{Corrupt}!u16 {
        return nodeCount(self.page);
    }

    pub fn keyAt(self: Leaf, i: usize) error{Corrupt}![]const u8 {
        return cellKey(self.page, try cellHdr(self.page, i));
    }

    /// The value of entry `i` -- or, for an overflow value (`ovfLen`), its
    /// `ovf_ref_len`-byte reference; see `entryAt`.
    pub fn valAt(self: Leaf, i: usize) error{Corrupt}![]const u8 {
        return leafCellVal(self.page, try cellHdr(self.page, i));
    }

    /// Whether entry `i` is a bucket (its value is a `BucketHdr`).
    pub fn isBucket(self: Leaf, i: usize) error{Corrupt}!bool {
        const raw = (try cellHdr(self.page, i)).raw;
        return raw & ovf_flag == 0 and raw & bucket_flag != 0;
    }

    /// The length of entry `i`'s value when it lives in overflow pages, else
    /// `null` (the value is `valAt(i)` itself).
    pub fn ovfLen(self: Leaf, i: usize) error{Corrupt}!?u32 {
        const raw = (try cellHdr(self.page, i)).raw;
        return if (raw & ovf_flag != 0) raw & ~ovf_flag else null;
    }

    /// The first overflow page of entry `i`, whose `ovfLen` is set.
    pub fn ovfFirst(self: Leaf, i: usize) error{Corrupt}!PageId {
        return std.mem.readInt(u32, (try self.valAt(i))[0..ovf_ref_len], .little);
    }

    /// Entry `i` in one decode of its cell header — what `keyAt`, `valAt`,
    /// `ovfLen` and `isBucket` would each re-read from the slot directory (a
    /// cursor's `next` takes every entry this way). A bucket cell whose value
    /// is not a `BucketHdr` is `Corrupt` here, so a builder never carries one.
    pub fn entryAt(self: Leaf, i: usize) error{Corrupt}!Entry {
        const c = try cellHdr(self.page, i);
        const ovf = c.raw & ovf_flag != 0;
        const bucket = !ovf and c.raw & bucket_flag != 0;
        const val = try leafCellVal(self.page, c);
        if (bucket and val.len != bucket_hdr_len) return error.Corrupt;
        return .{
            .key = try cellKey(self.page, c),
            .val = val,
            .ovf_len = if (ovf) c.raw & ~ovf_flag else null,
            .bucket = bucket,
        };
    }

    pub fn search(self: Leaf, key: []const u8) error{Corrupt}!Search {
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

    pub fn count(self: Branch) error{Corrupt}!u16 {
        return nodeCount(self.page);
    }

    pub fn leftmost(self: Branch) PageId {
        return nodeLeftmost(self.page);
    }

    /// Separator key of cell `i` (0..count-1).
    pub fn keyAt(self: Branch, i: usize) error{Corrupt}![]const u8 {
        return cellKey(self.page, try cellHdr(self.page, i));
    }

    /// Right child of cell `i` (0..count-1).
    pub fn rightChildAt(self: Branch, i: usize) error{Corrupt}!PageId {
        return (try cellHdr(self.page, i)).raw;
    }

    /// Child page by ordinal: 0 = leftmost, i (1..count) = cell[i-1].right_child.
    /// There are `count + 1` valid indices (0..count).
    pub fn childAtIndex(self: Branch, i: usize) error{Corrupt}!PageId {
        if (i == 0) return self.leftmost();
        return self.rightChildAt(i - 1);
    }

    /// Ordinal of the child to descend into for `key` (0..count).
    pub fn childIndexFor(self: Branch, key: []const u8) error{Corrupt}!usize {
        // lo = number of separators <= key → child ordinal.
        var lo: usize = 0;
        var hi: usize = try self.count();
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (orderKeys(try self.keyAt(mid), key)) {
                .lt, .eq => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return lo;
    }

    /// Child page to descend into for `key`. Index 0 = leftmost; index i+1 =
    /// cell[i].right_child.
    pub fn childFor(self: Branch, key: []const u8) error{Corrupt}!PageId {
        return self.childAtIndex(try self.childIndexFor(key));
    }
};

/// Crash-recovery helper: a bounds-checked `Branch` view over a POSSIBLY
/// GARBAGE page (a stale meta candidate may reference torn/recycled pages).
/// Returns `null` unless the header, slot directory and every cell lie fully
/// inside the page — after which the normal `Branch` accessors are safe. The
/// regular views assert well-formedness instead (their pages come from a
/// validated committed tree); recovery must reject, never crash.
pub fn branchViewSafe(page: *const [page_size]u8) ?Branch {
    if (page[0] != @backingInt(NodeKind.branch)) return null;
    const count: usize = nodeCount(page) catch return null;
    const dir_end = hdr_len + count * slot_len;
    if (dir_end > page_size) return null;
    // Separators must be strictly ascending — not just in-bounds. A slot
    // directory whose entries were reordered (or a torn write that shuffled
    // them) stays perfectly in-bounds, so the bounds checks below accept it;
    // `childIndexFor`'s binary search then still returns a valid 0..count
    // ordinal (memory-safe) but routes to the WRONG child, so lookups on an
    // adopted-but-unsorted branch silently miss keys that are physically
    // present. Recovery must reject this, not adopt it.
    var prev_key: ?[]const u8 = null;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const o = slotOffset(page, i) catch return null;
        if (o < dir_end or o + 6 > page_size) return null;
        const klen = std.mem.readInt(u16, page[o .. o + 2][0..2], .little);
        if (o + 6 + @as(usize, klen) > page_size or 6 + @as(usize, klen) > max_cell_len) return null;
        const key = page[o + 6 ..][0..klen];
        if (prev_key) |p| if (!std.mem.lessThan(u8, p, key)) return null;
        prev_key = key;
    }
    return Branch.init(page);
}

/// The leaf dual of `branchViewSafe`, and required for the same reason: a leaf
/// page reached from a stale/torn/corrupt meta candidate is untrusted bytes.
///
/// Recovery used to accept a leaf on its KIND BYTE ALONE, on the strength of
/// the sentence above ("their pages come from a validated committed tree") —
/// but nothing validated leaves, so the premise was false and the tree walk's
/// documented promise to trust nothing held for branches only. A leaf whose
/// `count` field is `0xFFFF` was adopted by `recover` and then sent
/// `binarySearch` off the end of the caller's 4 KiB page buffer on the first
/// probe; `valAt`'s length is a **u32**, so a cell could also name a 4 GiB
/// value inside a 4 KiB page. Node pages carry no CRC (only meta pages do), so
/// a single corrupted length byte on media is enough — squarely inside this
/// module's stated "I/O faults" threat model.
///
/// A leaf cell is `(key_len: u16, val_len: u32, key, val)`, so the check is
/// `branchViewSafe`'s plus the value bytes, keys strictly ascending included
/// (a shuffled slot directory would make `binarySearch` miss present keys).
/// Lengths are widened to `usize` before they are added, so the bound cannot
/// be defeated by wrapping.
pub fn leafViewSafe(page: *const [page_size]u8) ?Leaf {
    if (page[0] != @backingInt(NodeKind.leaf)) return null;
    const count: usize = nodeCount(page) catch return null;
    const dir_end = hdr_len + count * slot_len;
    if (dir_end > page_size) return null;
    var prev_key: ?[]const u8 = null;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const o = slotOffset(page, i) catch return null;
        if (o < dir_end or o + 6 > page_size) return null;
        const klen = std.mem.readInt(u16, page[o .. o + 2][0..2], .little);
        const raw = std.mem.readInt(u32, page[o + 2 .. o + 6][0..4], .little);
        // An overflow reference: a length of 0 is no value anyone wrote (a
        // value that short is inline), so it is corruption, not a chain.
        if (raw == ovf_flag) return null;
        // A bucket cell's value is a header of exactly one size; any other
        // length under the flag is no cell this format writes.
        if (raw & ovf_flag == 0 and raw & bucket_flag != 0 and raw != bucket_flag | bucket_hdr_len) return null;
        const vlen = leafValLen(raw);
        if (o + 6 + @as(usize, klen) + vlen > page_size or 6 + @as(usize, klen) + vlen > max_cell_len) return null;
        const key = page[o + 6 ..][0..klen];
        if (prev_key) |p| if (orderKeys(p, key) != .lt) return null;
        prev_key = key;
    }
    return Leaf.init(page);
}

/// Bytewise lexicographic order of two keys, exactly `std.mem.order(u8, a, b)`,
/// eight bytes per step: a big-endian load turns the first differing byte of a
/// word into the word's order. Every descent and every commit fold compares
/// keys; std's byte loop was the largest single cost of a resident `get`
/// (perf, 2026-10-11).
pub fn orderKeys(a: []const u8, b: []const u8) std.math.Order {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i + 8 <= n) : (i += 8) {
        const x = std.mem.readInt(u64, a[i..][0..8], .big);
        const y = std.mem.readInt(u64, b[i..][0..8], .big);
        if (x != y) return std.math.order(x, y);
    }
    while (i < n) : (i += 1) {
        if (a[i] != b[i]) return std.math.order(a[i], b[i]);
    }
    return std.math.order(a.len, b.len);
}

/// Generic ascending binary search over a leaf's/branch's key directory.
/// `error.Corrupt` when a probed slot or cell lies outside the page.
fn binarySearch(comptime V: type, view: V, key: []const u8) error{Corrupt}!Search {
    var lo: usize = 0;
    var hi: usize = try view.count();
    // Prefetch only for a node type that has the slot directory (both do).
    const may_prefetch = comptime (V == Leaf or V == Branch);
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        // A probe's first touch of its cell is a cache miss, and each probe
        // waited for the one before it (perf 2026-10-25: 35 % of a resident
        // get on one load). The next probe is the middle of one half or the
        // other; asking for both cells now overlaps the misses. The slot
        // directory itself is a line or two, warm after the first probe. A
        // page's offsets are clamped: a prefetch must not fault on a damaged
        // slot that the search itself never reads. (`count` is at most
        // `max_node_count`, so the directory is inside the page.)
        if (may_prefetch) {
            const a = lo + (mid - lo) / 2;
            const b = mid + 1 + (hi - mid - 1) / 2;
            if (a < mid) @prefetch(&view.page[@min(slotOffset(view.page, a) catch 0, page_size - 1)], .{});
            if (b < hi) @prefetch(&view.page[@min(slotOffset(view.page, b) catch 0, page_size - 1)], .{});
        }
        const cmp = orderKeys(try view.keyAt(mid), key);
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

/// A key/value pair no leaf can hold even with its value in overflow pages: a
/// key whose cell with an overflow reference does not fit an empty page, or a
/// value longer than `max_value_len`.
pub const oversize_error = error.EntryTooLarge;

/// Does `(key, value)` fit an otherwise-empty leaf inline?
pub fn fitsInline(klen: usize, vlen: usize) bool {
    return vlen <= max_value_len and leafCellBytes(klen, vlen) + hdr_len + slot_len <= page_size;
}

/// Does a key of `klen` fit an otherwise-empty leaf with an overflow reference?
pub fn fitsOverflowRef(klen: usize) bool {
    return leafCellBytes(klen, ovf_ref_len) + hdr_len + slot_len <= page_size;
}

/// Can a store hold `(key, value)` at all: inline, or with the value in
/// overflow pages? The test `Txn.put` applies, and `core.commit` repeats.
pub fn fitsEntry(klen: usize, vlen: usize) bool {
    return fitsInline(klen, vlen) or (vlen <= max_value_len and fitsOverflowRef(klen));
}

/// What an empty node takes (its header), and what one more leaf entry or
/// branch cell adds to it (slot + cell): for the bulk loader (`bulk.zig`),
/// which has to know whether an entry fits before it copies it.
pub const empty_node_bytes = hdr_len;
pub fn leafEntryBytes(klen: usize, vlen: usize) usize {
    return slot_len + leafCellBytes(klen, vlen);
}
pub fn branchEntryBytes(klen: usize) usize {
    return slot_len + branchCellBytes(klen);
}

/// Node builders BORROW every key, value and separator handed to them --
/// from the page they were decoded from (`fromPage`), from the caller's
/// change list (`put`), from a child's promoted separator (`insert`). Nothing
/// is copied into the arena except what must outlive its source: the
/// separator a `split` promotes to the parent, whose page frame is gone by
/// the time the parent encodes. The arena pays for the entry lists only.
///
/// The contract that buys: whatever a builder was given stays alive and
/// unchanged until the builder has been `encode`d (or `split` off it). The
/// commit path honours it by construction -- a node's page buffer and the
/// transaction's staging arena both outlive `finishNodes`. It used to copy
/// everything, which made a leaf rewrite cost two arena allocations per entry
/// on top of the page memset; that was the bulk of a commit's user-side cost.
pub const LeafBuilder = struct {
    arena: Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(arena: Allocator) LeafBuilder {
        return .{ .arena = arena };
    }

    pub fn deinit(self: *LeafBuilder) void {
        self.entries.deinit(self.arena);
    }

    /// Decode `page` into a builder whose entries point INTO `page`.
    pub fn fromPage(arena: Allocator, page: *const [page_size]u8) !LeafBuilder {
        var b = LeafBuilder.init(arena);
        const leaf = Leaf.init(page);
        const n = try leaf.count();
        // One entry more than the page holds: the common case is one insert.
        try b.entries.ensureTotalCapacityPrecise(arena, @as(usize, n) + 1);
        var i: usize = 0;
        while (i < n) : (i += 1)
            b.entries.appendAssumeCapacity(try leaf.entryAt(i));
        return b;
    }

    /// Insert or overwrite. Returns error.EntryTooLarge if a single k/v cannot
    /// fit an otherwise-empty page. This is the ONLY key-length bound this
    /// module enforces (there used to be a separate, unenforced `max_key_len
    /// = maxInt(u16)` constant here — dead, and looser than this check by
    /// three orders of magnitude, since `leafCellBytes` already forces any
    /// key over ~4080 bytes to fail here first; removed rather than left to
    /// read as a live invariant it never was).
    pub fn put(self: *LeafBuilder, key: []const u8, val: []const u8) !void {
        if (!fitsInline(key.len, val.len)) return oversize_error;
        try self.set(.{ .key = key, .val = val });
    }

    /// Insert or overwrite `key` with a reference to an overflow value of
    /// `len` bytes whose chain starts at page `first_ref` (`ovf_ref_len`
    /// bytes, borrowed like every other slice here). The chain is the
    /// caller's to write; a builder does no I/O.
    pub fn putOverflow(self: *LeafBuilder, key: []const u8, first_ref: []const u8, len: u32) !void {
        std.debug.assert(first_ref.len == ovf_ref_len and len != 0 and len <= max_value_len);
        if (!fitsOverflowRef(key.len)) return oversize_error;
        try self.set(.{ .key = key, .val = first_ref, .ovf_len = len });
    }

    /// Insert or overwrite `key` as a bucket whose header is `hdr`
    /// (`bucket_hdr_len` bytes, borrowed like every other slice here).
    pub fn putBucket(self: *LeafBuilder, key: []const u8, hdr: []const u8) !void {
        std.debug.assert(hdr.len == bucket_hdr_len);
        if (!fitsInline(key.len, bucket_hdr_len)) return oversize_error;
        try self.set(.{ .key = key, .val = hdr, .bucket = true });
    }

    fn set(self: *LeafBuilder, e: Entry) !void {
        const s = self.search(e.key);
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
            switch (orderKeys(self.entries.items[mid].key, key)) {
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

    /// Split an overflowing leaf into two, where the halves' BYTES are closest
    /// to equal (not their entry counts: with values of mixed sizes a count
    /// midpoint can leave one half nearly empty, and an underfull half is
    /// merged straight back by the next commit that touches it). Returns the
    /// right half plus the separator key (== the right half's first key). The
    /// receiver becomes the left half. The separator is the one copy made:
    /// it is promoted into a parent that outlives this leaf's page frame.
    pub fn split(self: *LeafBuilder) !SplitLeaf {
        const n = self.entries.items.len;
        std.debug.assert(n >= 2);
        const sizes = try self.arena.alloc(usize, n);
        for (self.entries.items, sizes) |e, *z| z.* = slot_len + leafCellBytes(e.key.len, e.val.len);
        const mid = balancedCut(sizes, false);
        var right = LeafBuilder.init(self.arena);
        try right.entries.ensureTotalCapacityPrecise(self.arena, n - mid);
        for (self.entries.items[mid..]) |e|
            right.entries.appendAssumeCapacity(e);
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

    /// Decode `page` into a builder whose separators point INTO `page`.
    pub fn fromPage(arena: Allocator, page: *const [page_size]u8) !BranchBuilder {
        const br = Branch.init(page);
        var b = BranchBuilder.init(arena, br.leftmost());
        const n = try br.count();
        try b.cells.ensureTotalCapacityPrecise(arena, @as(usize, n) + 1);
        var i: usize = 0;
        while (i < n) : (i += 1)
            b.cells.appendAssumeCapacity(.{ .sep = try br.keyAt(i), .child = try br.rightChildAt(i) });
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
        try self.cells.insert(self.arena, lo, .{ .sep = sep, .child = child });
    }

    pub fn byteSize(self: *const BranchBuilder) usize {
        var n: usize = hdr_len;
        for (self.cells.items) |c| n += slot_len + branchCellBytes(c.sep.len);
        return n;
    }

    pub fn overflows(self: *const BranchBuilder) bool {
        return self.byteSize() > page_size;
    }

    pub fn underflows(self: *const BranchBuilder) bool {
        return self.byteSize() < page_size / 4;
    }

    pub fn encode(self: *const BranchBuilder, page: *[page_size]u8) void {
        encodeBranch(page, self.leftmost, self.cells.items);
    }

    /// Split an overflowing branch where the halves' bytes are closest to
    /// equal (see `LeafBuilder.split`). The cut separator is promoted OUT (it
    /// becomes the parent's separator and does not live in either half —
    /// proper B-tree branch split), the right half's leftmost child is the
    /// promoted cell's child.
    pub fn split(self: *BranchBuilder) !SplitBranch {
        const n = self.cells.items.len;
        std.debug.assert(n >= 2);
        const sizes = try self.arena.alloc(usize, n);
        for (self.cells.items, sizes) |c, *z| z.* = slot_len + branchCellBytes(c.sep.len);
        const mid = balancedCut(sizes, true);
        const promoted = self.cells.items[mid];
        var right = BranchBuilder.init(self.arena, promoted.child);
        try right.cells.ensureTotalCapacityPrecise(self.arena, self.cells.items.len - mid);
        for (self.cells.items[mid + 1 ..]) |c|
            right.cells.appendAssumeCapacity(c);
        self.cells.shrinkRetainingCapacity(mid);
        // The one copy: the separator leaves this node for its parent, and
        // the page it points into does not live that long.
        return .{ .right = right, .sep = try self.arena.dupe(u8, promoted.sep) };
    }
};

pub const SplitBranch = struct { right: BranchBuilder, sep: []const u8 };

/// Where to cut a node of cells sized `sizes` (n >= 2) so the larger half is
/// as small as it can be: the first cell of the right half for a leaf, the
/// promoted cell for a branch (`promote`: it belongs to neither half). Always
/// in `1..n-1`, so both halves of a leaf hold an entry, and a branch's left
/// half keeps a separator.
fn balancedCut(sizes: []const usize, promote: bool) usize {
    var total: usize = 0;
    for (sizes) |z| total += z;
    var best: usize = 1;
    var best_max: usize = std.math.maxInt(usize);
    var left: usize = 0;
    for (1..sizes.len) |mid| {
        left += sizes[mid - 1];
        const right = total - left - (if (promote) sizes[mid] else 0);
        const worst = @max(left, right);
        if (worst < best_max) {
            best_max = worst;
            best = mid;
        }
    }
    return best;
}

// ── low-level cell sizing + slotted-page encoders ────────────────────────────

fn leafCellBytes(klen: usize, vlen: usize) usize {
    return 6 + klen + vlen; // key_len(2) + val_len(4) + key + val
}
fn branchCellBytes(klen: usize) usize {
    return 6 + klen; // key_len(2) + right_child(4) + key
}

fn writeHeader(page: *[page_size]u8, kind: NodeKind, count: u16, leftmost: PageId) void {
    zeroPage(page);
    page[0] = @backingInt(kind);
    page[1] = 0;
    std.mem.writeInt(u16, page[2..4], count, .little);
    std.mem.writeInt(u32, page[4..8], leftmost, .little);
}

fn encodeLeaf(page: *[page_size]u8, entries: []const Entry) void {
    writeHeader(page, .leaf, @intCast(entries.len), 0);
    // The cells sit at the end of the page, as always, but in ASCENDING key
    // order: a cursor then walks a leaf's memory forward, the direction the
    // hardware prefetcher follows best (a resident scan was 69 % first-touch
    // misses on cells laid out downward, perf 2026-10-11). Readers go through
    // the slot directory, so the order is no part of the format.
    var total: usize = 0;
    for (entries) |e| total += leafCellBytes(e.key.len, e.val.len);
    var tail: usize = page_size - total;
    for (entries, 0..) |e, i| {
        const cell = leafCellBytes(e.key.len, e.val.len);
        defer tail += cell;
        std.mem.writeInt(u16, page[tail .. tail + 2][0..2], @intCast(e.key.len), .little);
        const vlen: u32 = if (e.ovf_len) |l| ovf_flag | l else if (e.bucket) bucket_flag | @as(u32, @intCast(e.val.len)) else @intCast(e.val.len);
        std.mem.writeInt(u32, page[tail + 2 .. tail + 6][0..4], vlen, .little);
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
    try testing.expectEqual(@as(u16, 3), (try leaf.count()));
    // sorted: apple, banana, cherry
    try testing.expectEqualStrings("apple", (try leaf.keyAt(0)));
    try testing.expectEqualStrings("green", (try leaf.valAt(0))); // overwrite won
    try testing.expectEqualStrings("cherry", (try leaf.keyAt(2)));

    try testing.expect((try leaf.search("banana")).found);
    try testing.expectEqual(@as(u16, 1), (try leaf.search("banana")).index);
    const miss = (try leaf.search("blueberry"));
    try testing.expect(!miss.found);
    try testing.expectEqual(@as(u16, 2), miss.index); // would insert before cherry
}

test "kvtree sweep KT-2/KT-8: a slot index past the page and a value above max_value_len are refused" {
    var page: [page_size]u8 = undefined;
    encodeEmptyLeaf(&page);
    const leaf = Leaf.init(&page);
    try testing.expectError(error.Corrupt, leaf.keyAt(2044)); // the slot would start at byte 4096
    try testing.expectError(error.Corrupt, leaf.keyAt(page_size));
    try testing.expect(fitsEntry(1, max_value_len)); // an overflow value of the largest size
    try testing.expect(!fitsEntry(1, max_value_len + 1));
}

test "zeroPage clears every byte" {
    var page: [page_size]u8 = undefined;
    @memset(&page, 0xA5);
    zeroPage(&page);
    for (page) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "builders borrow: the encoded page reads what the caller's buffers hold at encode time" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var b = LeafBuilder.init(arena_state.allocator());
    var key = "k".*;
    var val = "v".*;
    try b.put(&key, &val);
    val[0] = 'w'; // still the caller's buffer: the builder holds no copy
    var page: [page_size]u8 = undefined;
    b.encode(&page);
    try testing.expectEqualStrings("w", (try Leaf.init(&page).valAt(0)));
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
        // The builder borrows its keys, so each one needs its own bytes.
        try b.put(try a.print("k{d:0>5}", .{i}), &big);
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
    try testing.expectEqual(@as(u16, 2), (try br.count()));
    try testing.expectEqual(@as(PageId, 10), br.leftmost());
    try testing.expectEqual(@as(PageId, 10), (try br.childFor("a"))); // < m → leftmost
    try testing.expectEqual(@as(PageId, 20), (try br.childFor("m"))); // == m → right of m
    try testing.expectEqual(@as(PageId, 20), (try br.childFor("p"))); // m<=p<t
    try testing.expectEqual(@as(PageId, 30), (try br.childFor("t"))); // >= t
    try testing.expectEqual(@as(PageId, 30), (try br.childFor("z")));
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

test "kindOf rejects any byte that is not a valid NodeKind tag" {
    var page: [page_size]u8 = @splat(0);
    page[0] = @backingInt(NodeKind.leaf);
    try testing.expectEqual(NodeKind.leaf, kindOf(&page).?);
    page[0] = @backingInt(NodeKind.branch);
    try testing.expectEqual(NodeKind.branch, kindOf(&page).?);

    // Every byte a freelist chain page's header (a `u16` entry count, low
    // byte first) can legally put at offset 0 that is NOT 0 or 1 — exactly
    // the "kind byte is actually a recycled freelist page's entry count"
    // shape the audit's reachability argument named.
    var v: usize = 2;
    while (v <= 255) : (v += 1) {
        page[0] = @intCast(v);
        try testing.expect(kindOf(&page) == null);
    }
}

test "branchViewSafe rejects a structurally in-bounds but unsorted slot directory" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var b = BranchBuilder.init(arena_state.allocator(), 10);
    try b.insert("b", 20);
    try b.insert("m", 30);
    var page: [page_size]u8 = undefined;
    b.encode(&page);
    try testing.expect(branchViewSafe(&page) != null); // ascending: accepted

    // Swap the two slot-directory entries only (not the cells themselves):
    // every offset/length in the directory stays perfectly in-bounds, so the
    // OLD geometry-only check accepted this — but keyAt(0) is now "m" and
    // keyAt(1) is "b", not ascending.
    const slot0 = page[hdr_len .. hdr_len + slot_len][0..slot_len].*;
    const slot1 = page[hdr_len + slot_len .. hdr_len + 2 * slot_len][0..slot_len].*;
    @memcpy(page[hdr_len .. hdr_len + slot_len], &slot1);
    @memcpy(page[hdr_len + slot_len .. hdr_len + 2 * slot_len], &slot0);
    try testing.expect(branchViewSafe(&page) == null);
}

test "leaf split cuts where the bytes balance, not at the entry midpoint" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var b = LeafBuilder.init(a);
    const big: [3000]u8 = @splat('b');
    try b.put("a", &big);
    for (0..10) |i| try b.put(try a.print("k{d}", .{i}), "small");
    const sp = try b.split();
    // The big entry alone is the heavier half; a count midpoint would have
    // put four small ones next to it.
    try testing.expectEqual(@as(usize, 1), b.entries.items.len);
    try testing.expectEqual(@as(usize, 10), sp.right.entries.items.len);
}

test "branch split leaves the promoted separator out of the balance" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Cells of 10, 50 and 50 bytes: promoting the middle one leaves halves of
    // 10 and 50; counting it on the right would pick the third (60 and 0).
    var b = BranchBuilder.init(a, 1);
    const k2: [42]u8 = @splat('c');
    const k3: [42]u8 = @splat('d');
    try b.insert("ab", 2);
    try b.insert(&k2, 3);
    try b.insert(&k3, 4);
    const sp = try b.split();
    try testing.expectEqualStrings(&k2, sp.sep);
    try testing.expectEqual(@as(usize, 1), b.cells.items.len);
    try testing.expectEqual(@as(usize, 1), sp.right.cells.items.len);
}

test "leafViewSafe rejects a structurally in-bounds but unsorted slot directory" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var b = LeafBuilder.init(arena_state.allocator());
    try b.put("b", "1");
    try b.put("m", "2");
    var page: [page_size]u8 = undefined;
    b.encode(&page);
    try testing.expect(leafViewSafe(&page) != null); // ascending: accepted
    // Swap the slot-directory entries only: in bounds, but "m" before "b".
    const slot0 = page[hdr_len .. hdr_len + slot_len][0..slot_len].*;
    const slot1 = page[hdr_len + slot_len .. hdr_len + 2 * slot_len][0..slot_len].*;
    @memcpy(page[hdr_len .. hdr_len + slot_len], &slot1);
    @memcpy(page[hdr_len + slot_len .. hdr_len + 2 * slot_len], &slot0);
    try testing.expect(leafViewSafe(&page) == null);
    // A duplicate key is no leaf either.
    @memcpy(page[hdr_len .. hdr_len + slot_len], &slot0);
    try testing.expect(leafViewSafe(&page) == null);
}

test "leafViewSafe rejects an overflow reference of length zero" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var b = LeafBuilder.init(arena_state.allocator());
    const ref = [_]u8{ 9, 0, 0, 0 };
    try b.putOverflow("k", &ref, 1);
    var page: [page_size]u8 = undefined;
    b.encode(&page);
    try testing.expect(leafViewSafe(&page) != null);
    try testing.expectEqual(@as(?u32, 1), (try Leaf.init(&page).ovfLen(0)));
    // Clear the length bits, keep the flag: no value anyone wrote.
    const o = std.mem.readInt(u16, page[hdr_len..][0..2], .little);
    std.mem.writeInt(u32, page[o + 2 ..][0..4], ovf_flag, .little);
    try testing.expect(leafViewSafe(&page) == null);
}

test "the inline limit is the page: a cell that exactly fills an empty leaf stays inline" {
    // header 8 + one slot 2 + cell (2 + 4 + key + value) = 4096
    const vlen = page_size - hdr_len - slot_len - 6 - 1;
    try testing.expect(fitsInline(1, vlen));
    try testing.expect(!fitsInline(1, vlen + 1));
}

test "orderKeys is std.mem.order: every length pair to 19, a difference at every position" {
    // Byte values that break a signed or little-endian word compare (0x7f/0x80)
    // and the extremes; a difference planted at each position, including the
    // word tail, and every prefix relation (equal, shorter, longer).
    const vals = [_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff };
    var a: [19]u8 = undefined;
    var b: [19]u8 = undefined;
    for (0..a.len + 1) |la| for (0..b.len + 1) |lb| for (vals) |fill| {
        @memset(&a, fill);
        @memset(&b, fill);
        try testing.expectEqual(std.mem.order(u8, a[0..la], b[0..lb]), orderKeys(a[0..la], b[0..lb]));
        for (0..@min(la, lb)) |pos| for (vals) |other| {
            b[pos] = other;
            try testing.expectEqual(std.mem.order(u8, a[0..la], b[0..lb]), orderKeys(a[0..la], b[0..lb]));
            try testing.expectEqual(std.mem.order(u8, b[0..lb], a[0..la]), orderKeys(b[0..lb], a[0..la]));
            b[pos] = fill;
        };
    };
}

test "leafViewSafe rejects a bucket cell whose length is no header and a slot that points into the directory" {
    var page: [page_size]u8 = undefined;
    // `bucket_hdr_len` is the one length a bucket cell may carry.
    const hdr: [bucket_hdr_len]u8 = @splat(0);
    encodeLeaf(&page, &.{.{ .key = "b", .val = &hdr, .bucket = true }});
    try testing.expect(leafViewSafe(&page) != null);
    const o = try slotOffset(&page, 0);
    for ([_]u32{ 5, bucket_hdr_len + 1, 0 }) |len| {
        var bad = page;
        std.mem.writeInt(u32, bad[o + 2 .. o + 6][0..4], bucket_flag | len, .little);
        try testing.expect(leafViewSafe(&bad) == null);
    }
    // A cell that starts inside the slot directory (offset 9 of a one-slot
    // leaf is its second byte) is no cell, however well it fits the page: the
    // directory's end is the bound, not the header's.
    encodeLeaf(&page, &.{.{ .key = "k", .val = "v" }});
    try testing.expect(leafViewSafe(&page) != null);
    std.mem.writeInt(u16, page[hdr_len .. hdr_len + 2][0..2], hdr_len + 1, .little);
    try testing.expect(leafViewSafe(&page) == null);
}

test "the quarter-page underflow line and the overflow-reference key limit are exact" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // header 8 + slot 2 + cell (6 + key + value) = 1024 is NOT under a quarter.
    const key = "12345678";
    const val = try a.alloc(u8, page_size / 4 - hdr_len - slot_len - 6 - key.len);
    @memset(val, 'v');
    var lb = LeafBuilder.init(a);
    try lb.put(key, val);
    try testing.expectEqual(page_size / 4, lb.byteSize());
    try testing.expect(!lb.underflows());
    _ = lb.del(key);
    try lb.put(key, val[1..]);
    try testing.expect(lb.underflows());

    const sep = try a.alloc(u8, page_size / 4 - hdr_len - slot_len - 6);
    @memset(sep, 's');
    var bb = BranchBuilder.init(a, 2);
    try bb.cells.append(a, .{ .sep = sep, .child = 3 });
    try testing.expectEqual(page_size / 4, bb.byteSize());
    try testing.expect(!bb.underflows());
    bb.cells.items[0].sep = sep[1..];
    try testing.expect(bb.underflows());

    // A key whose cell with a 4-byte reference exactly fills an empty leaf.
    const klen = page_size - hdr_len - slot_len - 6 - ovf_ref_len;
    try testing.expect(fitsOverflowRef(klen));
    try testing.expect(!fitsOverflowRef(klen + 1));
}

test "an overflow value of 2^30 bytes or more is not a bucket: the length's second bit is only a flag on inline cells" {
    var page: [page_size]u8 = undefined;
    const ref = [_]u8{ 7, 0, 0, 0 };
    const len: u32 = bucket_flag | 1; // 0x4000_0001, a legal overflow length
    encodeLeaf(&page, &.{.{ .key = "k", .val = &ref, .ovf_len = len }});
    const leaf = leafViewSafe(&page).?;
    try testing.expect(!(try leaf.isBucket(0)));
    try testing.expectEqual(@as(?u32, len), (try leaf.ovfLen(0)));
    try testing.expectEqual(@as(usize, ovf_ref_len), (try leaf.valAt(0)).len);
    const e = (try leaf.entryAt(0));
    try testing.expect(!e.bucket);
    try testing.expectEqual(@as(?u32, len), e.ovf_len);
    try testing.expectEqualSlices(u8, &ref, e.val);
}

test "binarySearch: the prefetch of the probes it never makes cannot fault, whatever the slots there say" {
    var page: [page_size]u8 = undefined;
    encodeLeaf(&page, &.{
        .{ .key = "a", .val = "1" }, .{ .key = "b", .val = "2" }, .{ .key = "c", .val = "3" },
        .{ .key = "d", .val = "4" }, .{ .key = "e", .val = "5" },
    });
    // The first probe is slot 2; slots 1 and 4 are the middles of its two
    // halves, which a search for "c" never reads. A slot that points past the
    // page there must not be followed by the prefetch.
    for ([_]usize{ 1, 4 }) |i| std.mem.writeInt(u16, page[hdr_len + i * slot_len ..][0..2], 0xFFFF, .little);
    const s = (try Leaf.init(&page).search("c"));
    try testing.expect(s.found);
    try testing.expectEqual(@as(u16, 2), s.index);
}

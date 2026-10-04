// SPDX-License-Identifier: MIT

//! format — the frozen wire format: header + node codec, and the
//! bounds-checked node decoder the query path runs against.
//!
//! The frozen buffer is self-describing, versioned and little-endian. It is
//! designed to be loaded **zero-copy** from an mmap'd / read-only `[]const u8`
//! and queried in place with no per-query allocation. Because that buffer may
//! come from an untrusted file, EVERY field the query path follows out of it is
//! bounds-checked here (`nodeAt`, `NodeView.edge`) — a corrupt buffer yields a
//! typed `error.Corrupt`, never an out-of-bounds read, panic, or infinite loop.
//!
//! Layout (all integers little-endian):
//!
//!   Header (36 bytes, at offset 0):
//!     0   magic            [4]u8  = "ZTR1"
//!     4   version          u16    = format_version
//!     6   endian_marker    u16    = 0x0102  (detects a wrong-endian/garbage load)
//!     8   flags            u32    (reserved, currently 0)
//!     12  node_region_len  u32    (bytes of the node region)
//!     16  key_count        u64    (number of distinct keys)
//!     24  root_offset      u32    (absolute byte offset of the root node)
//!     28  body_crc         u32    (CRC-32 of the node region; checked by loadVerified)
//!     32  header_crc       u32    (CRC-32 of bytes [0..32))
//!
//!   Node region (starts at offset 36):
//!     A contiguous array of nodes, one per trie node, emitted in node-id order.
//!     By construction a child's id is always greater than its parent's, so a
//!     child node always sits at a STRICTLY GREATER offset than its parent.
//!     The query path enforces that invariant (`child_offset > parent_offset`),
//!     which is what makes traversal termination provable even on a corrupt
//!     buffer: offsets strictly increase and are bounded by the buffer length.
//!
//!   Node:
//!     u8   flags            bit0 = terminal (node is the end of a stored key)
//!     u32  value            present IFF terminal — the caller's stored value
//!     u32  subtree_best     max stored value among this node's terminal
//!                           descendants (including itself); drives top-N pruning
//!     u16  edge_count       number of child edges
//!     edge_count × edge, each: { u8 label, u32 child_offset }, sorted ascending
//!       by label; child_offset is an absolute buffer offset, strictly greater
//!       than this node's own offset.
//!
//! That is format VERSION 1. Version 2 (the default writer since 2026-10-04)
//! is described in the "Format version 2" section further down: it keeps the
//! magic and the `version` field at the same offsets (so one `Header.load`
//! dispatches on it) and changes the rest. Readers accept both.

const std = @import("std");

pub const magic = "ZTR1";
/// Version 1 — the layout documented at the top of this file. The name is kept
/// for the hand-built v1 buffers in tests and in sibling modules.
pub const format_version: u16 = 1;
/// Version 2 — path-compressed, children before parents, footer metadata. See
/// the "Format version 2" section. What `Builder.freeze` writes by default.
pub const format_version_2: u16 = 2;
pub const endian_marker: u16 = 0x0102;
pub const header_size: usize = 36;

/// Fixed byte sizes of the parts of a node (see the layout comment above).
pub const flags_size = 1;
pub const value_size = 4;
pub const best_size = 4;
pub const edge_count_size = 2;
pub const edge_size = 5; // 1 label + 4 child_offset

pub const terminal_bit: u8 = 0x01;

/// Errors returned while decoding a node OR walking the buffer during a query.
/// `Corrupt` means the frozen buffer is structurally invalid at some offset we
/// tried to follow — the caller loaded a truncated / bit-flipped / hand-crafted
/// buffer. It is never a bug in a well-formed index.
pub const DecodeError = error{Corrupt};

/// Errors returned by `Header.load` when opening a frozen buffer.
pub const LoadError = error{
    /// Buffer is shorter than the header, or shorter than header + node region.
    Truncated,
    /// First four bytes are not the `magic`.
    BadMagic,
    /// `version` is a format this build cannot read.
    UnsupportedVersion,
    /// `endian_marker` is wrong — a wrong-endian or otherwise garbage buffer.
    BadEndian,
    /// The header's own CRC does not hold (a corrupted header).
    HeaderCorrupt,
    /// `root_offset` does not point inside the node region.
    MalformedRoot,
    /// `loadVerified` only: the node region's CRC does not hold.
    BodyCorrupt,
};

// ── Header ───────────────────────────────────────────────────────────────────

pub const Header = struct {
    version: u16,
    flags: u32,
    node_region_len: u32,
    key_count: u64,
    root_offset: u32,

    /// Encode a header into the first `header_size` bytes of `buf` (which must
    /// be at least that long) and compute both CRCs. `body` is the already-laid
    /// node region that immediately follows the header in `buf`.
    pub fn encode(self: Header, buf: []u8, body: []const u8) void {
        std.debug.assert(buf.len >= header_size);
        @memcpy(buf[0..4], magic);
        std.mem.writeInt(u16, buf[4..6], self.version, .little);
        std.mem.writeInt(u16, buf[6..8], endian_marker, .little);
        std.mem.writeInt(u32, buf[8..12], self.flags, .little);
        std.mem.writeInt(u32, buf[12..16], self.node_region_len, .little);
        std.mem.writeInt(u64, buf[16..24], self.key_count, .little);
        std.mem.writeInt(u32, buf[24..28], self.root_offset, .little);
        std.mem.writeInt(u32, buf[28..32], std.hash.Crc32.hash(body), .little);
        std.mem.writeInt(u32, buf[32..36], std.hash.Crc32.hash(buf[0..32]), .little);
    }

    /// Validate + decode the header of a frozen buffer. Cheap (O(1)) — it does
    /// NOT scan the whole node region; per-node bounds-checking during queries
    /// keeps traversal safe. Use `verifyBody` (via `loadVerified` in query.zig)
    /// for a full integrity check of an untrusted file.
    ///
    /// Dispatches on the `version` field (same offset in every version): 2 is
    /// read by `loadV2`, everything else by the version-1 rules below, which
    /// report any version other than 1 as `UnsupportedVersion` once the v1
    /// header CRC holds.
    pub fn load(buf: []const u8) LoadError!Header {
        if (buf.len >= 6 and std.mem.eql(u8, buf[0..4], magic) and
            std.mem.readInt(u16, buf[4..6], .little) == format_version_2)
            return loadV2(buf);
        if (buf.len < header_size) return error.Truncated;
        if (!std.mem.eql(u8, buf[0..4], magic)) return error.BadMagic;
        const want_hcrc = std.mem.readInt(u32, buf[32..36], .little);
        if (std.hash.Crc32.hash(buf[0..32]) != want_hcrc) return error.HeaderCorrupt;
        if (std.mem.readInt(u16, buf[6..8], .little) != endian_marker) return error.BadEndian;
        const version = std.mem.readInt(u16, buf[4..6], .little);
        if (version != format_version) return error.UnsupportedVersion;

        const node_region_len = std.mem.readInt(u32, buf[12..16], .little);
        // Node region must fit within the buffer (trailing padding tolerated:
        // an mmap'd file may be page-rounded).
        const total = header_size + @as(usize, node_region_len);
        if (buf.len < total) return error.Truncated;

        const root_offset = std.mem.readInt(u32, buf[24..28], .little);
        const key_count = std.mem.readInt(u64, buf[16..24], .little);
        // root_offset must land at the very start of the node region (the root
        // is always emitted first). An empty node region (no nodes at all) is
        // not something we produce — the builder always emits a root node.
        if (root_offset != header_size or node_region_len == 0) return error.MalformedRoot;
        if (root_offset >= total) return error.MalformedRoot;

        return .{
            .version = version,
            .flags = std.mem.readInt(u32, buf[8..12], .little),
            .node_region_len = node_region_len,
            .key_count = key_count,
            .root_offset = root_offset,
        };
    }

    /// Full body integrity check: recompute the node-region CRC and compare.
    /// Separate from `load` so the fast path stays O(1); untrusted files should
    /// pass through here (via `Frozen.loadVerified`).
    pub fn verifyBody(self: Header, buf: []const u8) LoadError!void {
        const start = self.regionStart();
        const end = start + @as(usize, self.node_region_len);
        if (buf.len < end) return error.Truncated;
        const want = if (self.version == format_version_2)
            std.mem.readInt(u32, buf[end + 16 ..][0..4], .little)
        else
            std.mem.readInt(u32, buf[28..32], .little);
        if (std.hash.Crc32.hash(buf[start..end]) != want) return error.BodyCorrupt;
    }

    /// Absolute offset of the first node-region byte.
    pub fn regionStart(self: Header) usize {
        return if (self.version == format_version_2) v2_front_size else header_size;
    }

    /// v2 only: whether edges carry the `before` counts.
    pub fn hasOrdinals(self: Header) bool {
        return self.version == format_version_2 and self.flags & v2_flag_ordinals != 0;
    }

    /// Version-2 header: the 12-byte front plus the 24-byte footer, which must
    /// END the buffer exactly (v2 tolerates no trailing padding — the footer is
    /// found from the end). Same error vocabulary as version 1.
    fn loadV2(buf: []const u8) LoadError!Header {
        if (buf.len < v2_front_size + v2_footer_size) return error.Truncated;
        const foot = buf[buf.len - v2_footer_size ..];
        var crc = std.hash.Crc32.init();
        crc.update(buf[0..v2_front_size]);
        crc.update(foot[0..20]);
        if (crc.final() != std.mem.readInt(u32, foot[20..24], .little)) return error.HeaderCorrupt;
        if (std.mem.readInt(u16, buf[6..8], .little) != endian_marker) return error.BadEndian;
        const flags = std.mem.readInt(u32, buf[8..12], .little);
        // An unknown flag is a feature this build cannot read, not damage: the
        // footer CRC above already held.
        if (flags & ~v2_known_flags != 0) return error.UnsupportedVersion;
        const node_region_len = std.mem.readInt(u32, foot[0..4], .little);
        if (@as(usize, node_region_len) + v2_front_size + v2_footer_size != buf.len) return error.Truncated;
        if (node_region_len == 0) return error.MalformedRoot;
        const root_offset = std.mem.readInt(u32, foot[4..8], .little);
        // The root is written LAST, so it lies inside the region; the decoder
        // bounds the rest.
        if (root_offset < v2_front_size or root_offset >= v2_front_size + @as(usize, node_region_len))
            return error.MalformedRoot;
        return .{
            .version = format_version_2,
            .flags = flags,
            .node_region_len = node_region_len,
            .key_count = std.mem.readInt(u64, foot[8..16], .little),
            .root_offset = root_offset,
        };
    }
};

// ── Format version 2 ─────────────────────────────────────────────────────────
//
// Version 1 spends a whole node (11 bytes + a 5-byte edge in the parent) on
// every byte of every key suffix no other key shares. On the RÚIAN address
// index that is 140 bytes per key (2 835 455 keys, 397 MB; measured
// 2026-10-04). Version 2 changes three things:
//
//   * Path compression. A non-terminal node with exactly one child is merged
//     into that child: the child stores the bytes of the merged chain after
//     the edge label as its `tail` (≤ 255 bytes; a longer chain keeps a node
//     every 256 bytes). An edge therefore stands for the string `label ++
//     child.tail`, and a key may end in the middle of it only as a PREFIX
//     query — a stored key always ends at a node.
//   * Compact nodes. A node without edges stores no `subtree_best` (it is
//     its own value) and no edge count; the edge count is one byte (`n - 1`,
//     a node has 1..256 edges).
//   * Children BEFORE parents (post-order), the root last, and the metadata
//     in a FOOTER. That is what lets `SortedBuilder` stream a buffer to any
//     writer while holding only the current key's path: a node is written
//     once all its children are, and nothing before it is revisited. The
//     termination argument is the mirror image of v1's: a child's offset is
//     strictly SMALLER than its parent's (`follow` enforces it) and never
//     below the region start, so any walk visits strictly decreasing offsets.
//
// Optional (header flag bit 0, `v2_flag_ordinals`): each edge also carries
// `before`, the number of stored keys under the node's earlier edges. With it
// a key's rank in sorted order (`Frozen.ordinal`) and the key at a rank
// (`Frozen.keyAt`) are O(depth) walks — marisa-trie's reverse lookup.
//
// Layout (all integers little-endian):
//
//   Front (12 bytes, offset 0):
//     0   magic           [4]u8 = "ZTR1"
//     4   version         u16   = 2
//     6   endian_marker   u16   = 0x0102
//     8   flags           u32   bit0 = ordinals; other bits must be 0
//   Node region (offset 12, node_region_len bytes), root last.
//   Footer (the LAST 24 bytes of the buffer):
//     +0  node_region_len u32
//     +4  root_offset     u32   absolute
//     +8  key_count       u64
//     +16 body_crc        u32   CRC-32 of the node region
//     +20 footer_crc      u32   CRC-32 of front[0..12) ++ footer[0..20)
//
//   Node:
//     u8  flags       bit0 = terminal, bit1 = has edges; other bits must be 0
//     u8  tail_len    then tail_len bytes of tail (0 at the root)
//     u32 value       present IFF terminal
//     — present IFF has edges: —
//     u32 subtree_best
//     u8  edge_count - 1
//     edge_count × { u8 label, u32 child_offset [, u32 before] } sorted strictly
//       ascending by label; child_offset < this node's offset, ≥ 12.
//   A node without edges has subtree_best = its value (0 if not terminal —
//   only the root of an empty index is like that).

pub const v2_front_size: usize = 12;
pub const v2_footer_size: usize = 24;
pub const v2_flag_ordinals: u32 = 0x1;
pub const v2_known_flags: u32 = v2_flag_ordinals;
pub const v2_edges_bit: u8 = 0x02;
pub const v2_known_node_flags: u8 = terminal_bit | v2_edges_bit;
pub const max_tail: usize = 255;
pub const edge_size_ordinals: usize = 9; // label + child_offset + before

/// Decode + fully bounds-check the version-2 node at `off`. The v2
/// counterpart of `nodeAt`: `error.Corrupt` unless every field lies inside
/// `buf` (the kept slice ends at the node region, so "inside `buf`" means
/// inside the region), no unknown flag bit is set, and the edges are strictly
/// ascending by label.
pub fn nodeAtV2(buf: []const u8, off: u32, ordinals: bool) DecodeError!NodeView {
    if (off < v2_front_size or off >= buf.len) return error.Corrupt;
    var p: usize = off;
    const flags = buf[p];
    p += 1;
    if (flags & ~v2_known_node_flags != 0) return error.Corrupt;
    const terminal = (flags & terminal_bit) != 0;

    if (p + 1 > buf.len) return error.Corrupt;
    const tail_len: usize = buf[p];
    p += 1;
    if (p + tail_len > buf.len) return error.Corrupt;
    const tail = buf[p .. p + tail_len];
    p += tail_len;

    var value: u32 = 0;
    if (terminal) {
        if (p + value_size > buf.len) return error.Corrupt;
        value = std.mem.readInt(u32, buf[p..][0..4], .little);
        p += value_size;
    }

    const stride: usize = if (ordinals) edge_size_ordinals else edge_size;
    var best = value;
    var edge_count: u16 = 0;
    if (flags & v2_edges_bit != 0) {
        if (p + best_size + 1 > buf.len) return error.Corrupt;
        best = std.mem.readInt(u32, buf[p..][0..4], .little);
        p += best_size;
        edge_count = @as(u16, buf[p]) + 1;
        p += 1;
        if (p + @as(usize, edge_count) * stride > buf.len) return error.Corrupt;
        var i: usize = 1;
        while (i < edge_count) : (i += 1) {
            if (buf[p + i * stride] <= buf[p + (i - 1) * stride]) return error.Corrupt;
        }
    }
    return .{
        .buf = buf,
        .offset = off,
        .terminal = terminal,
        .value = value,
        .subtree_best = best,
        .edge_count = edge_count,
        .edges_at = p,
        .version = format_version_2,
        .tail = tail,
        .edge_stride = stride,
    };
}

// ── Node decoding (bounds-checked; runs against untrusted buffers) ───────────

/// A validated, borrowed view onto one node in the frozen buffer. Produced only
/// by `nodeAt`, which has already proven the whole node (header + every edge
/// record) lies inside the buffer, so the accessors below cannot read OOB.
pub const NodeView = struct {
    buf: []const u8,
    /// This node's own absolute offset — the anchor for the child-offset
    /// invariant (strictly greater than it in v1, strictly smaller in v2).
    offset: u32,
    terminal: bool,
    value: u32,
    subtree_best: u32,
    edge_count: u16,
    /// Absolute offset of the first edge record.
    edges_at: usize,
    /// Format version the node was decoded as; `follow` decodes the child the
    /// same way and checks the direction that version promises.
    version: u16 = format_version,
    /// v2 only: the bytes of the incoming edge after its label (path
    /// compression). The full string the parent's edge stands for is
    /// `label ++ tail`. Always empty in v1, and empty at a v2 root.
    tail: []const u8 = "",
    /// Bytes per edge record: `edge_size` (5), or `edge_size_ordinals` (9)
    /// in a v2 buffer built with ordinals.
    edge_stride: usize = edge_size,

    pub const Edge = struct {
        label: u8,
        child: u32,
        /// v2 with ordinals only (0 otherwise): the number of stored keys in
        /// the subtrees of the edges BEFORE this one under the same node.
        before: u32 = 0,
    };

    /// Edge `i` (0..edge_count). Bounds already validated by `nodeAt`.
    pub fn edge(self: NodeView, i: usize) Edge {
        std.debug.assert(i < self.edge_count);
        const o = self.edges_at + i * self.edge_stride;
        return .{
            .label = self.buf[o],
            .child = std.mem.readInt(u32, self.buf[o + 1 .. o + 5][0..4], .little),
            .before = if (self.edge_stride == edge_size_ordinals)
                std.mem.readInt(u32, self.buf[o + 5 .. o + 9][0..4], .little)
            else
                0,
        };
    }

    /// True when the buffer carries the per-edge `before` counts.
    pub fn hasOrdinals(self: NodeView) bool {
        return self.edge_stride == edge_size_ordinals;
    }

    /// Binary-search this node's (label-sorted) edges for `label`.
    pub fn findEdge(self: NodeView, label: u8) ?Edge {
        var lo: usize = 0;
        var hi: usize = self.edge_count;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const e = self.edge(mid);
            if (e.label < label) {
                lo = mid + 1;
            } else if (e.label > label) {
                hi = mid;
            } else {
                return e;
            }
        }
        return null;
    }
};

/// Decode + fully bounds-check the node at absolute offset `off`. Returns
/// `error.Corrupt` unless the flags byte, the optional value, the subtree_best,
/// the edge count and every edge record all lie inside `buf`. This is the ONLY
/// way the query path turns an offset into a `NodeView`, so a node view is
/// always safe to read.
pub fn nodeAt(buf: []const u8, off: u32) DecodeError!NodeView {
    // The node must start inside the node region (never in the header).
    if (off < header_size or off >= buf.len) return error.Corrupt;
    var p: usize = off;

    if (p + flags_size > buf.len) return error.Corrupt;
    const flags = buf[p];
    p += flags_size;
    const terminal = (flags & terminal_bit) != 0;

    var value: u32 = 0;
    if (terminal) {
        if (p + value_size > buf.len) return error.Corrupt;
        value = std.mem.readInt(u32, buf[p .. p + 4][0..4], .little);
        p += value_size;
    }

    if (p + best_size > buf.len) return error.Corrupt;
    const subtree_best = std.mem.readInt(u32, buf[p .. p + 4][0..4], .little);
    p += best_size;

    if (p + edge_count_size > buf.len) return error.Corrupt;
    const edge_count = std.mem.readInt(u16, buf[p .. p + 2][0..2], .little);
    p += edge_count_size;

    const edges_at = p;
    // Guard against overflow before the multiply, then the range.
    const edges_bytes = @as(usize, edge_count) * edge_size;
    if (edges_at + edges_bytes > buf.len) return error.Corrupt;

    // The format requires edges sorted strictly ascending by label (the
    // layout comment above, and the precondition `findEdge`'s binary search
    // relies on) — nothing enforced it before. An unsorted or duplicate-label
    // node made `lookup` (binary search) disagree with `prefixIterator`/`topN`
    // (linear index order) on the very same buffer, and let a duplicate label
    // hide a key from `lookup` entirely (A1/trie.md F3). One check here closes
    // it for all three query paths at once, since they all go through `nodeAt`.
    if (edge_count > 1) {
        var i: usize = 1;
        while (i < edge_count) : (i += 1) {
            const prev_label = buf[edges_at + (i - 1) * edge_size];
            const cur_label = buf[edges_at + i * edge_size];
            if (cur_label <= prev_label) return error.Corrupt;
        }
    }

    return .{
        .buf = buf,
        .offset = off,
        .terminal = terminal,
        .value = value,
        .subtree_best = subtree_best,
        .edge_count = edge_count,
        .edges_at = edges_at,
    };
}

/// Follow a child edge with the strictly-increasing-offset invariant enforced.
/// A well-formed buffer always has `child > parent.offset`; a corrupt one that
/// points a child back at or before its parent is rejected here, which is what
/// bounds the number of nodes any traversal can visit (offsets strictly
/// increase, buffer is finite) and thus rules out infinite loops.
pub fn follow(parent: NodeView, child: u32) DecodeError!NodeView {
    if (parent.version == format_version_2) {
        if (child >= parent.offset) return error.Corrupt;
        return nodeAtV2(parent.buf, child, parent.hasOrdinals());
    }
    if (child <= parent.offset) return error.Corrupt;
    return nodeAt(parent.buf, child);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "header round-trips and both CRCs validate" {
    const body = [_]u8{ 1, 2, 3, 4, 5 };
    var buf: [header_size + body.len]u8 = undefined;
    @memcpy(buf[header_size..], &body);
    const h = Header{
        .version = format_version,
        .flags = 0,
        .node_region_len = body.len,
        .key_count = 42,
        .root_offset = header_size,
    };
    h.encode(&buf, buf[header_size..]);

    const got = try Header.load(&buf);
    try testing.expectEqual(@as(u64, 42), got.key_count);
    try testing.expectEqual(@as(u32, header_size), got.root_offset);
    try testing.expectEqual(@as(u32, body.len), got.node_region_len);
    try got.verifyBody(&buf);
}

test "header load rejects short / bad-magic / bad-version / bad-endian / flipped" {
    const body = [_]u8{ 9, 8, 7 };
    var buf: [header_size + body.len]u8 = undefined;
    @memcpy(buf[header_size..], &body);
    const h = Header{ .version = format_version, .flags = 0, .node_region_len = body.len, .key_count = 1, .root_offset = header_size };
    h.encode(&buf, buf[header_size..]);

    try testing.expectError(error.Truncated, Header.load(buf[0 .. header_size - 1]));

    var b = buf;
    b[0] = 'X';
    // Corrupting magic also breaks header CRC; both are rejections. The order
    // in `load` reports HeaderCorrupt first for a flipped magic byte, so accept
    // either as "not loadable".
    try testing.expect(Header.load(&b) catch null == null);

    b = buf;
    std.mem.writeInt(u16, b[4..6], 999, .little);
    std.mem.writeInt(u32, b[32..36], std.hash.Crc32.hash(b[0..32]), .little); // fix header CRC
    try testing.expectError(error.UnsupportedVersion, Header.load(&b));

    b = buf;
    std.mem.writeInt(u16, b[6..8], 0x0201, .little);
    std.mem.writeInt(u32, b[32..36], std.hash.Crc32.hash(b[0..32]), .little);
    try testing.expectError(error.BadEndian, Header.load(&b));

    b = buf;
    b[15] ^= 0xff; // flip node_region_len without fixing header CRC
    try testing.expectError(error.HeaderCorrupt, Header.load(&b));

    b = buf;
    b[header_size] ^= 0xff; // flip a body byte → header still loads, verifyBody fails
    const hh = try Header.load(&b);
    try testing.expectError(error.BodyCorrupt, hh.verifyBody(&b));
}

test "nodeAt rejects offsets and geometry that leave the buffer" {
    // Hand-build a tiny buffer with one leaf node: terminal value=7, best=7, 0 edges.
    var body: [flags_size + value_size + best_size + edge_count_size]u8 = undefined;
    body[0] = terminal_bit;
    std.mem.writeInt(u32, body[1..5], 7, .little);
    std.mem.writeInt(u32, body[5..9], 7, .little);
    std.mem.writeInt(u16, body[9..11], 0, .little);
    var buf: [header_size + body.len]u8 = undefined;
    @memcpy(buf[header_size..], &body);
    const h = Header{ .version = format_version, .flags = 0, .node_region_len = body.len, .key_count = 1, .root_offset = header_size };
    h.encode(&buf, buf[header_size..]);

    const n = try nodeAt(&buf, header_size);
    try testing.expect(n.terminal);
    try testing.expectEqual(@as(u32, 7), n.value);
    try testing.expectEqual(@as(u16, 0), n.edge_count);

    try testing.expectError(error.Corrupt, nodeAt(&buf, 0)); // inside header
    try testing.expectError(error.Corrupt, nodeAt(&buf, @intCast(buf.len))); // past end
    try testing.expectError(error.Corrupt, nodeAt(&buf, @intCast(buf.len - 1))); // header claims edges off end

    // A node whose edge_count overruns the buffer must be rejected, not read.
    var bad = buf;
    std.mem.writeInt(u16, bad[header_size + 9 .. header_size + 11][0..2], 5000, .little);
    try testing.expectError(error.Corrupt, nodeAt(&bad, header_size));
}

test "nodeAt rejects edges that are not strictly ascending by label (and duplicates)" {
    // Root: non-terminal, 3 edges labelled 'c','a','b' (in THAT order), each
    // pointing at the same terminal leaf right after it. The layout comment
    // requires edges "sorted ascending by label" and `findEdge`'s binary
    // search depends on it, but nothing checked it before this fix — `lookup`
    // (binary search) and `prefixIterator`/`topN` (linear edge order) then
    // disagreed about the very same buffer, and a duplicate label could hide
    // a key from `lookup` outright (A1/trie.md F3).
    const root_edges = flags_size + best_size + edge_count_size + 3 * edge_size; // 22
    const leaf_size = flags_size + value_size + best_size + edge_count_size; // 11
    var body: [root_edges + leaf_size]u8 = undefined;
    const leaf_off: u32 = header_size + root_edges;

    body[0] = 0; // root: non-terminal
    std.mem.writeInt(u32, body[1..5], 1, .little); // best
    std.mem.writeInt(u16, body[5..7], 3, .little); // edge_count = 3
    const labels_out_of_order = [_]u8{ 'c', 'a', 'b' };
    for (labels_out_of_order, 0..) |label, i| {
        const o = 7 + i * edge_size;
        body[o] = label;
        std.mem.writeInt(u32, body[o + 1 .. o + 5][0..4], leaf_off, .little);
    }
    body[root_edges] = terminal_bit; // leaf: terminal
    std.mem.writeInt(u32, body[root_edges + 1 .. root_edges + 5][0..4], 1, .little); // value
    std.mem.writeInt(u32, body[root_edges + 5 .. root_edges + 9][0..4], 1, .little); // best
    std.mem.writeInt(u16, body[root_edges + 9 .. root_edges + 11][0..2], 0, .little); // edge_count = 0

    var buf: [header_size + body.len]u8 = undefined;
    @memcpy(buf[header_size..], &body);
    var h = Header{ .version = format_version, .flags = 0, .node_region_len = body.len, .key_count = 1, .root_offset = header_size };
    h.encode(&buf, buf[header_size..]);
    try testing.expectError(error.Corrupt, nodeAt(&buf, header_size));

    // Positive control: the SAME bytes, edges reordered strictly ascending,
    // load cleanly — proving the rejection above is about order, not some
    // other mistake in the hand-built buffer.
    const labels_sorted = [_]u8{ 'a', 'b', 'c' };
    for (labels_sorted, 0..) |label, i| {
        const o = 7 + i * edge_size;
        body[o] = label;
        std.mem.writeInt(u32, body[o + 1 .. o + 5][0..4], leaf_off, .little);
    }
    @memcpy(buf[header_size..], &body);
    h.encode(&buf, buf[header_size..]);
    const n = try nodeAt(&buf, header_size);
    try testing.expectEqual(@as(u16, 3), n.edge_count);

    // Duplicate labels are equally rejected (strict `<`, not `<=`).
    const labels_dup = [_]u8{ 'a', 'a', 'b' };
    for (labels_dup, 0..) |label, i| {
        const o = 7 + i * edge_size;
        body[o] = label;
        std.mem.writeInt(u32, body[o + 1 .. o + 5][0..4], leaf_off, .little);
    }
    @memcpy(buf[header_size..], &body);
    h.encode(&buf, buf[header_size..]);
    try testing.expectError(error.Corrupt, nodeAt(&buf, header_size));
}

test "follow enforces the strictly-increasing child-offset invariant" {
    var body: [flags_size + best_size + edge_count_size]u8 = undefined;
    body[0] = 0; // non-terminal
    std.mem.writeInt(u32, body[1..5], 0, .little);
    std.mem.writeInt(u16, body[5..7], 0, .little);
    var buf: [header_size + body.len]u8 = undefined;
    @memcpy(buf[header_size..], &body);
    const h = Header{ .version = format_version, .flags = 0, .node_region_len = body.len, .key_count = 0, .root_offset = header_size };
    h.encode(&buf, buf[header_size..]);
    const n = try nodeAt(&buf, header_size);
    // A child pointing back at (or before) the parent is corruption.
    try testing.expectError(error.Corrupt, follow(n, n.offset));
    try testing.expectError(error.Corrupt, follow(n, n.offset - 1));
}

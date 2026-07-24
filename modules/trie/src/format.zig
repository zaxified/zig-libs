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

const std = @import("std");

pub const magic = "ZTR1";
pub const format_version: u16 = 1;
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
    pub fn load(buf: []const u8) LoadError!Header {
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
        const start = header_size;
        const end = start + @as(usize, self.node_region_len);
        if (buf.len < end) return error.Truncated;
        const want = std.mem.readInt(u32, buf[28..32], .little);
        if (std.hash.Crc32.hash(buf[start..end]) != want) return error.BodyCorrupt;
    }
};

// ── Node decoding (bounds-checked; runs against untrusted buffers) ───────────

/// A validated, borrowed view onto one node in the frozen buffer. Produced only
/// by `nodeAt`, which has already proven the whole node (header + every edge
/// record) lies inside the buffer, so the accessors below cannot read OOB.
pub const NodeView = struct {
    buf: []const u8,
    /// This node's own absolute offset — the anchor for the strictly-increasing
    /// child-offset invariant.
    offset: u32,
    terminal: bool,
    value: u32,
    subtree_best: u32,
    edge_count: u16,
    /// Absolute offset of the first edge record.
    edges_at: usize,

    pub const Edge = struct { label: u8, child: u32 };

    /// Edge `i` (0..edge_count). Bounds already validated by `nodeAt`.
    pub fn edge(self: NodeView, i: usize) Edge {
        std.debug.assert(i < self.edge_count);
        const o = self.edges_at + i * edge_size;
        return .{
            .label = self.buf[o],
            .child = std.mem.readInt(u32, self.buf[o + 1 .. o + 5][0..4], .little),
        };
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

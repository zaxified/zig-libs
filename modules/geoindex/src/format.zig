// SPDX-License-Identifier: MIT

//! format — the frozen wire format: header + fixed-size node record codec, and
//! the bounds-checked node decoder the query path runs against.
//!
//! The frozen buffer is self-describing, versioned and little-endian. It is
//! designed to be loaded **zero-copy** from an mmap'd / read-only `[]const u8`
//! and queried in place with no per-query allocation. Because that buffer may
//! come from an untrusted file, EVERY field the query path follows out of it is
//! bounds-checked here (`Nodes.at`, `Nodes.child`) — a corrupt buffer yields a
//! typed `error.Corrupt`, never an out-of-bounds read, panic, or infinite loop.
//!
//! Layout (all integers little-endian; f64 stored as its IEEE-754 u64 bit
//! pattern, also little-endian):
//!
//!   Header (40 bytes, at offset 0):
//!     0   magic         [4]u8  = "ZGI1"
//!     4   version       u16    = format_version
//!     6   endian_marker u16    = 0x0102  (detects a wrong-endian / garbage load)
//!     8   flags         u32    (reserved, currently 0)
//!     12  node_count    u32    (number of node records in the region)
//!     16  node_bytes    u16    = node_size_bytes (record stride; validated)
//!     18  fanout        u16    (build-time R-tree node fan-out; informational)
//!     20  item_count    u64    (number of indexed points)
//!     28  root_index    u32    (index of the root node record)
//!     32  body_crc      u32    (CRC-32 of the node region; checked by loadVerified)
//!     36  header_crc    u32    (CRC-32 of bytes [0..36))
//!
//!   Node region (starts at offset 40):
//!     A contiguous array of `node_count` fixed-size records (stride
//!     `node_bytes`). The tree is packed BOTTOM-UP: the leaf records come first
//!     (indices [0, item_count)), then each successive internal level, and the
//!     root LAST. By construction every child of a node has a STRICTLY SMALLER
//!     index than the node itself, and a node's children occupy a contiguous
//!     block that lies entirely below the node's own index. The query path
//!     enforces that invariant (`child_index < parent_index`), which is what
//!     makes traversal termination provable even on a corrupt buffer: followed
//!     indices strictly decrease and are bounded below by 0.
//!
//!   Node record (39 bytes):
//!     u8   flags        bit0 = leaf (record is a single indexed point)
//!     f64  min_lat      bounding box (for a leaf, min == max == the point)
//!     f64  min_lon
//!     f64  max_lat
//!     f64  max_lon
//!     u32  data         leaf: the caller's stored value (record id);
//!                       internal: child_start — index of the first child record
//!     u16  child_count  internal: number of contiguous children; leaf: 0

const std = @import("std");

pub const magic = "ZGI1";
pub const format_version: u16 = 1;
pub const endian_marker: u16 = 0x0102;
pub const header_size: usize = 40;

/// Fixed byte offsets inside a node record and the total stride.
pub const off_flags: usize = 0;
pub const off_min_lat: usize = 1;
pub const off_min_lon: usize = 9;
pub const off_max_lat: usize = 17;
pub const off_max_lon: usize = 25;
pub const off_data: usize = 33;
pub const off_child_count: usize = 37;
pub const node_size_bytes: usize = 39;

pub const leaf_bit: u8 = 0x01;

/// Errors returned while decoding a node OR walking the buffer during a query.
/// `Corrupt` means the frozen buffer is structurally invalid at some index we
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
    /// `node_bytes` is not the record stride this build understands.
    BadNodeBytes,
    /// `endian_marker` is wrong — a wrong-endian or otherwise garbage buffer.
    BadEndian,
    /// The header's own CRC does not hold (a corrupted header).
    HeaderCorrupt,
    /// `root_index`/`node_count`/`item_count` are mutually inconsistent, or the
    /// root index is out of range.
    MalformedRoot,
    /// `loadVerified` only: the node region's CRC does not hold.
    BodyCorrupt,
};

// ── little-endian f64 helpers (unaligned, like the integer reads) ────────────

pub fn readF64(buf: []const u8, off: usize) f64 {
    return @bitCast(std.mem.readInt(u64, buf[off .. off + 8][0..8], .little));
}

pub fn writeF64(buf: []u8, off: usize, v: f64) void {
    std.mem.writeInt(u64, buf[off .. off + 8][0..8], @bitCast(v), .little);
}

// ── Header ───────────────────────────────────────────────────────────────────

pub const Header = struct {
    flags: u32,
    node_count: u32,
    fanout: u16,
    item_count: u64,
    root_index: u32,

    /// Encode a header into the first `header_size` bytes of `buf` and compute
    /// both CRCs. `body` is the already-laid node region that follows the header.
    pub fn encode(self: Header, buf: []u8, body: []const u8) void {
        std.debug.assert(buf.len >= header_size);
        @memcpy(buf[0..4], magic);
        std.mem.writeInt(u16, buf[4..6], format_version, .little);
        std.mem.writeInt(u16, buf[6..8], endian_marker, .little);
        std.mem.writeInt(u32, buf[8..12], self.flags, .little);
        std.mem.writeInt(u32, buf[12..16], self.node_count, .little);
        std.mem.writeInt(u16, buf[16..18], @intCast(node_size_bytes), .little);
        std.mem.writeInt(u16, buf[18..20], self.fanout, .little);
        std.mem.writeInt(u64, buf[20..28], self.item_count, .little);
        std.mem.writeInt(u32, buf[28..32], self.root_index, .little);
        std.mem.writeInt(u32, buf[32..36], std.hash.Crc32.hash(body), .little);
        std.mem.writeInt(u32, buf[36..40], std.hash.Crc32.hash(buf[0..36]), .little);
    }

    /// Validate + decode the header of a frozen buffer. Cheap (O(1)) — it does
    /// NOT scan the node region; per-node bounds-checking during queries keeps
    /// traversal safe. Use `verifyBody` (via `loadVerified`) for a full integrity
    /// check of an untrusted file.
    pub fn load(buf: []const u8) LoadError!Header {
        if (buf.len < header_size) return error.Truncated;
        if (!std.mem.eql(u8, buf[0..4], magic)) return error.BadMagic;
        const want_hcrc = std.mem.readInt(u32, buf[36..40], .little);
        if (std.hash.Crc32.hash(buf[0..36]) != want_hcrc) return error.HeaderCorrupt;
        if (std.mem.readInt(u16, buf[6..8], .little) != endian_marker) return error.BadEndian;
        if (std.mem.readInt(u16, buf[4..6], .little) != format_version) return error.UnsupportedVersion;
        if (std.mem.readInt(u16, buf[16..18], .little) != node_size_bytes) return error.BadNodeBytes;

        const node_count = std.mem.readInt(u32, buf[12..16], .little);
        const item_count = std.mem.readInt(u64, buf[20..28], .little);
        const root_index = std.mem.readInt(u32, buf[28..32], .little);

        // The node region must fit within the buffer (trailing padding tolerated:
        // an mmap'd file may be page-rounded).
        const region_bytes = @as(usize, node_count) * node_size_bytes;
        const total = header_size + region_bytes;
        if (buf.len < total) return error.Truncated;

        // Consistency of the empty index vs a populated one, and root in range.
        if (item_count == 0) {
            if (node_count != 0) return error.MalformedRoot;
        } else {
            if (node_count == 0 or root_index >= node_count) return error.MalformedRoot;
            // There is always at least one node per item (leaves) plus internal
            // nodes, so node_count must be at least item_count.
            if (node_count < item_count) return error.MalformedRoot;
        }

        return .{
            .flags = std.mem.readInt(u32, buf[8..12], .little),
            .node_count = node_count,
            .fanout = std.mem.readInt(u16, buf[18..20], .little),
            .item_count = item_count,
            .root_index = root_index,
        };
    }

    /// Full body integrity check: recompute the node-region CRC and compare.
    /// Separate from `load` so the fast path stays O(1); untrusted files should
    /// pass through here (via `Frozen.loadVerified`).
    pub fn verifyBody(self: Header, buf: []const u8) LoadError!void {
        const start = header_size;
        const end = start + @as(usize, self.node_count) * node_size_bytes;
        if (buf.len < end) return error.Truncated;
        const want = std.mem.readInt(u32, buf[32..36], .little);
        if (std.hash.Crc32.hash(buf[start..end]) != want) return error.BodyCorrupt;
    }
};

// ── Node decoding (bounds-checked; runs against untrusted buffers) ───────────

/// A validated, borrowed view onto one node record. Produced only by `Nodes.at`,
/// which has already proven the whole fixed-size record lies inside the buffer,
/// so the fields below are always safe to read.
pub const NodeView = struct {
    index: u32,
    leaf: bool,
    min_lat: f64,
    min_lon: f64,
    max_lat: f64,
    max_lon: f64,
    /// leaf: the caller's stored value; internal: index of the first child.
    data: u32,
    /// internal: number of contiguous children; leaf: 0.
    child_count: u16,
};

/// A bounds-checked view over the node region of a frozen buffer. `at` and
/// `child` are the ONLY ways the query path turns an index into a `NodeView`,
/// so every node view is safe to read and every traversal step is validated.
pub const Nodes = struct {
    buf: []const u8,
    count: u32,

    pub fn init(buf: []const u8, header: Header) Nodes {
        return .{ .buf = buf, .count = header.node_count };
    }

    /// Decode + fully bounds-check the node record at `index`. Returns
    /// `error.Corrupt` unless `index` is in range and the whole record lies
    /// inside the buffer.
    pub fn at(self: Nodes, index: u32) DecodeError!NodeView {
        if (index >= self.count) return error.Corrupt;
        const base = header_size + @as(usize, index) * node_size_bytes;
        // `Header.load` already proved node_count records fit, but re-check so a
        // NodeView is safe even if a caller hands us an inconsistent Nodes.
        if (base + node_size_bytes > self.buf.len) return error.Corrupt;
        const flags = self.buf[base + off_flags];
        return .{
            .index = index,
            .leaf = (flags & leaf_bit) != 0,
            .min_lat = readF64(self.buf, base + off_min_lat),
            .min_lon = readF64(self.buf, base + off_min_lon),
            .max_lat = readF64(self.buf, base + off_max_lat),
            .max_lon = readF64(self.buf, base + off_max_lon),
            .data = std.mem.readInt(u32, self.buf[base + off_data ..][0..4], .little),
            .child_count = std.mem.readInt(u16, self.buf[base + off_child_count ..][0..2], .little),
        };
    }

    /// Decode child `child_index` of `parent`, enforcing the strictly-decreasing
    /// index invariant. A well-formed buffer always has `child_index <
    /// parent.index`; a corrupt one that points a child at or above its parent is
    /// rejected here, which bounds the number of nodes any traversal can visit
    /// (followed indices strictly decrease, are bounded below by 0) and thus
    /// rules out infinite loops.
    pub fn child(self: Nodes, parent: NodeView, child_index: u32) DecodeError!NodeView {
        if (child_index >= parent.index) return error.Corrupt;
        return self.at(child_index);
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn encodeLeaf(buf: []u8, base: usize, lat: f64, lon: f64, value: u32) void {
    buf[base + off_flags] = leaf_bit;
    writeF64(buf, base + off_min_lat, lat);
    writeF64(buf, base + off_min_lon, lon);
    writeF64(buf, base + off_max_lat, lat);
    writeF64(buf, base + off_max_lon, lon);
    std.mem.writeInt(u32, buf[base + off_data ..][0..4], value, .little);
    std.mem.writeInt(u16, buf[base + off_child_count ..][0..2], 0, .little);
}

test "header round-trips and both CRCs validate" {
    const body = [_]u8{0} ** node_size_bytes;
    var buf: [header_size + body.len]u8 = undefined;
    @memcpy(buf[header_size..], &body);
    const h = Header{ .flags = 0, .node_count = 1, .fanout = 16, .item_count = 1, .root_index = 0 };
    h.encode(&buf, buf[header_size..]);

    const got = try Header.load(&buf);
    try testing.expectEqual(@as(u64, 1), got.item_count);
    try testing.expectEqual(@as(u32, 1), got.node_count);
    try testing.expectEqual(@as(u32, 0), got.root_index);
    try got.verifyBody(&buf);
}

test "header load rejects short / bad-magic / bad-version / bad-endian / flipped" {
    const body = [_]u8{0} ** node_size_bytes;
    var buf: [header_size + body.len]u8 = undefined;
    @memcpy(buf[header_size..], &body);
    const h = Header{ .flags = 0, .node_count = 1, .fanout = 16, .item_count = 1, .root_index = 0 };
    h.encode(&buf, buf[header_size..]);

    try testing.expectError(error.Truncated, Header.load(buf[0 .. header_size - 1]));

    var b = buf;
    b[0] = 'X';
    try testing.expect(Header.load(&b) catch null == null); // magic and/or CRC rejects

    b = buf;
    std.mem.writeInt(u16, b[4..6], 999, .little);
    std.mem.writeInt(u32, b[36..40], std.hash.Crc32.hash(b[0..36]), .little); // fix header CRC
    try testing.expectError(error.UnsupportedVersion, Header.load(&b));

    b = buf;
    std.mem.writeInt(u16, b[6..8], 0x0201, .little);
    std.mem.writeInt(u32, b[36..40], std.hash.Crc32.hash(b[0..36]), .little);
    try testing.expectError(error.BadEndian, Header.load(&b));

    b = buf;
    std.mem.writeInt(u16, b[16..18], 7, .little); // wrong node stride
    std.mem.writeInt(u32, b[36..40], std.hash.Crc32.hash(b[0..36]), .little);
    try testing.expectError(error.BadNodeBytes, Header.load(&b));

    b = buf;
    b[13] ^= 0xff; // flip node_count without fixing header CRC
    try testing.expectError(error.HeaderCorrupt, Header.load(&b));

    b = buf;
    b[header_size] ^= 0xff; // flip a body byte → header still loads, verifyBody fails
    const hh = try Header.load(&b);
    try testing.expectError(error.BodyCorrupt, hh.verifyBody(&b));
}

test "Nodes.at rejects out-of-range indices and decodes a leaf" {
    var buf: [header_size + node_size_bytes]u8 = undefined;
    encodeLeaf(&buf, header_size, 50.0, 14.0, 77);
    const h = Header{ .flags = 0, .node_count = 1, .fanout = 16, .item_count = 1, .root_index = 0 };
    h.encode(&buf, buf[header_size..]);

    const nodes = Nodes.init(&buf, try Header.load(&buf));
    const n = try nodes.at(0);
    try testing.expect(n.leaf);
    try testing.expectEqual(@as(u32, 77), n.data);
    try testing.expectEqual(@as(f64, 50.0), n.min_lat);
    try testing.expectEqual(@as(f64, 14.0), n.max_lon);
    try testing.expectError(error.Corrupt, nodes.at(1)); // out of range
}

test "Nodes.child enforces the strictly-decreasing index invariant" {
    // Two leaves + one internal root (index 2) pointing at children [0,2).
    var buf: [header_size + 3 * node_size_bytes]u8 = undefined;
    encodeLeaf(&buf, header_size, 1.0, 1.0, 10);
    encodeLeaf(&buf, header_size + node_size_bytes, 2.0, 2.0, 20);
    const root_base = header_size + 2 * node_size_bytes;
    buf[root_base + off_flags] = 0; // internal
    writeF64(&buf, root_base + off_min_lat, 1.0);
    writeF64(&buf, root_base + off_min_lon, 1.0);
    writeF64(&buf, root_base + off_max_lat, 2.0);
    writeF64(&buf, root_base + off_max_lon, 2.0);
    std.mem.writeInt(u32, buf[root_base + off_data ..][0..4], 0, .little); // child_start
    std.mem.writeInt(u16, buf[root_base + off_child_count ..][0..2], 2, .little);
    const h = Header{ .flags = 0, .node_count = 3, .fanout = 16, .item_count = 2, .root_index = 2 };
    h.encode(&buf, buf[header_size..]);

    const nodes = Nodes.init(&buf, try Header.load(&buf));
    const root = try nodes.at(2);
    try testing.expect(!root.leaf);
    try testing.expectEqual(@as(u16, 2), root.child_count);
    _ = try nodes.child(root, 0); // ok, 0 < 2
    _ = try nodes.child(root, 1); // ok, 1 < 2
    try testing.expectError(error.Corrupt, nodes.child(root, 2)); // == parent → rejected
    try testing.expectError(error.Corrupt, nodes.child(root, 3)); // > parent → rejected
}

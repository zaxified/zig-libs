// SPDX-License-Identifier: MIT
// Generated mechanically from lightning/bolts `bolt07/extended-queries.json` --
// see modules/lnwire/NOTICE for the required CC-BY 4.0 attribution. Do not
// hand-edit the vector bodies below; regenerate instead if the upstream file
// changes.
//!
//! All 10 rows of the upstream file are transcribed: the full wire `hex`
//! plus the decoded `msg` fields `bolt7.zig`'s tests need to drive both
//! DECODE (parse `hex`, assert fields) and ENCODE (build from fields, assert
//! byte-exact `hex`) checks. Several rows use the `COMPRESSED_ZLIB`
//! short_channel_id/query_flags encoding this module does not implement (see
//! README's Scope / `ANCHOR-TASKS.tsv`) -- `bolt7.zig`'s tests skip
//! reconstructing/verifying the *decoded content* of a `.zlib`-encoded field
//! (documented per-vector there), while still checking everything this
//! module's codec does interpret: `chain_hash`, the block-range/complete
//! fields, message framing, and (for `checksums_tlv`, which BOLT#7 never
//! compresses) the raw fixed-width content even in an otherwise-zlib vector.

pub const ScidEncoding = enum { uncompressed, zlib };

/// BOLT#7 `short_channel_id`: `block_height (3 bytes) || tx_index (3 bytes)
/// || output_index (2 bytes)`, big-endian, packed into one `u64` wire value
/// by `lnwire`'s own `ShortChannelId` type (see `message.zig`).
pub const Scid = struct { block: u24, tx_index: u24, output_index: u16 };

pub const QueryChannelRangeVector = struct {
    description: []const u8,
    hex: []const u8,
    chain_hash_hex: []const u8,
    first_blocknum: u32,
    number_of_blocks: u32,
    /// `query_option` TLV (type 1): a single raw flag byte. `null` when the
    /// vector's extension is empty.
    query_option: ?u8 = null,
};

pub const query_channel_range_vectors = [_]QueryChannelRangeVector{
    .{
        .description = "no tlv extension",
        .hex = "01070f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206000186a0000005dc",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .first_blocknum = 100000,
        .number_of_blocks = 1500,
    },
    .{
        .description = "query_option WANT_TIMESTAMPS | WANT_CHECKSUMS",
        .hex = "01070f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206000088b800000064010103",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .first_blocknum = 35000,
        .number_of_blocks = 100,
        .query_option = 0x03,
    },
};

pub const TimestampPair = struct { timestamp1: u32, timestamp2: u32 };
pub const ChecksumPair = struct { checksum1: u32, checksum2: u32 };

pub const ReplyChannelRangeVector = struct {
    description: []const u8,
    hex: []const u8,
    chain_hash_hex: []const u8,
    first_blocknum: u32,
    number_of_blocks: u32,
    complete: u8,
    scid_encoding: ScidEncoding,
    /// Populated only when `scid_encoding == .uncompressed` -- this module
    /// never decodes a zlib-compressed short_channel_id list (opaque bytes
    /// throughout, see SPEC.md), so a `.zlib` vector's decoded array isn't
    /// independently reconstructed here.
    scids: []const Scid = &.{},
    /// `timestamps_tlv` (type 1) encoding, when the TLV is present.
    timestamps_encoding: ?ScidEncoding = null,
    /// Populated only when `timestamps_encoding == .uncompressed`.
    timestamps: []const TimestampPair = &.{},
    /// `checksums_tlv` (type 3). BOLT#7 defines NO encoding byte for it
    /// (always raw fixed-width `u32` pairs) -- so it is independently
    /// checkable even in a vector whose short_channel_id/timestamps are
    /// zlib-compressed.
    checksums: []const ChecksumPair = &.{},
};

pub const reply_channel_range_vectors = [_]ReplyChannelRangeVector{
    .{
        .description = "uncompressed scids, no tlv extension",
        .hex = "01080f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206000b8a06000005dc01001900000000000000008e0000000000003c69000000000045a6c4",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .first_blocknum = 756230,
        .number_of_blocks = 1500,
        .complete = 1,
        .scid_encoding = .uncompressed,
        .scids = &.{
            .{ .block = 0, .tx_index = 0, .output_index = 142 },
            .{ .block = 0, .tx_index = 0, .output_index = 15465 },
            .{ .block = 0, .tx_index = 69, .output_index = 42692 },
        },
    },
    .{
        .description = "zlib-compressed scids, no tlv extension",
        .hex = "01080f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206000006400000006e01001601789c636000833e08659309a65878be010010a9023a",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .first_blocknum = 1600,
        .number_of_blocks = 110,
        .complete = 1,
        .scid_encoding = .zlib,
    },
    .{
        .description = "uncompressed scids + uncompressed timestamps_tlv + checksums_tlv",
        .hex = "01080f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e22060001ddde000005dc01001900000000000000304300000000000778d6000000000046e1c1011900000282c1000e77c5000778ad00490ab00000b57800955bff031800000457000008ae00000d050000115c000015b300001a0a",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .first_blocknum = 122334,
        .number_of_blocks = 1500,
        .complete = 1,
        .scid_encoding = .uncompressed,
        .scids = &.{
            .{ .block = 0, .tx_index = 0, .output_index = 12355 },
            .{ .block = 0, .tx_index = 7, .output_index = 30934 },
            .{ .block = 0, .tx_index = 70, .output_index = 57793 },
        },
        .timestamps_encoding = .uncompressed,
        .timestamps = &.{
            .{ .timestamp1 = 164545, .timestamp2 = 948165 },
            .{ .timestamp1 = 489645, .timestamp2 = 4786864 },
            .{ .timestamp1 = 46456, .timestamp2 = 9788415 },
        },
        .checksums = &.{
            .{ .checksum1 = 1111, .checksum2 = 2222 },
            .{ .checksum1 = 3333, .checksum2 = 4444 },
            .{ .checksum1 = 5555, .checksum2 = 6666 },
        },
    },
    .{
        .description = "zlib-compressed scids + zlib-compressed timestamps_tlv + checksums_tlv",
        .hex = "01080f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e22060001ddde000005dc01001801789c63600001036730c55e710d4cbb3d3c080017c303b1012201789c63606a3ac8c0577e9481bd622d8327d7060686ad150c53a3ff0300554707db031800000457000008ae00000d050000115c000015b300001a0a",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .first_blocknum = 122334,
        .number_of_blocks = 1500,
        .complete = 1,
        .scid_encoding = .zlib,
        .timestamps_encoding = .zlib,
        // checksums_tlv is raw regardless of the other two fields' encoding.
        .checksums = &.{
            .{ .checksum1 = 1111, .checksum2 = 2222 },
            .{ .checksum1 = 3333, .checksum2 = 4444 },
            .{ .checksum1 = 5555, .checksum2 = 6666 },
        },
    },
};

pub const QueryShortChannelIdsVector = struct {
    description: []const u8,
    hex: []const u8,
    chain_hash_hex: []const u8,
    scid_encoding: ScidEncoding,
    /// Populated only when `scid_encoding == .uncompressed`.
    scids: []const Scid = &.{},
    /// `query_flags` TLV (type 1) presence. Its per-`short_channel_id` bit
    /// array is out of this module's scope regardless of its OWN encoding
    /// byte (SPEC.md's deferred "per-field TLV value semantics" -- a
    /// `query_flags` value is handed back as an opaque raw byte string
    /// whether or not it happens to be zlib-compressed), so only presence,
    /// never content, is asserted.
    has_query_flags_tlv: bool = false,
};

pub const query_short_channel_ids_vectors = [_]QueryShortChannelIdsVector{
    .{
        .description = "uncompressed scids, no tlv extension",
        .hex = "01050f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206001900000000000000008e0000000000003c69000000000045a6c4",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .scid_encoding = .uncompressed,
        .scids = &.{
            .{ .block = 0, .tx_index = 0, .output_index = 142 },
            .{ .block = 0, .tx_index = 0, .output_index = 15465 },
            .{ .block = 0, .tx_index = 69, .output_index = 42692 },
        },
    },
    .{
        .description = "zlib-compressed scids, no tlv extension",
        .hex = "01050f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206001801789c63600001c12b608a69e73e30edbaec0800203b040e",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .scid_encoding = .zlib,
    },
    .{
        .description = "uncompressed scids + query_flags tlv (itself zlib-compressed)",
        .hex = "01050f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e22060019000000000000002fc80000000000003cc4000000000045a6c4010c01789c6364620100000e0008",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .scid_encoding = .uncompressed,
        .scids = &.{
            .{ .block = 0, .tx_index = 0, .output_index = 12232 },
            .{ .block = 0, .tx_index = 0, .output_index = 15556 },
            .{ .block = 0, .tx_index = 69, .output_index = 42692 },
        },
        .has_query_flags_tlv = true,
    },
    .{
        .description = "zlib-compressed scids + query_flags tlv (itself zlib-compressed)",
        .hex = "01050f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206001801789c63600001f30a30c5b0cd144cb92e3b020017c6034a010c01789c6364620100000e0008",
        .chain_hash_hex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        .scid_encoding = .zlib,
        .has_query_flags_tlv = true,
    },
};

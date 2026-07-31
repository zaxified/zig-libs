// SPDX-License-Identifier: MIT

//! IS-IS common PDU header (ISO/IEC 10589, clause 9.1).
//!
//! Every IS-IS PDU opens with the same 8-byte fixed preamble, followed by a
//! per-PDU-type fixed header (parsed in `pdu.zig`) and then a TLV stream
//! (`tlv.zig`). This file models only the 8-byte common part plus the typed
//! `PduType` enum:
//!
//! ```
//!  0               1               2               3
//!  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Intradomain    | Length         | Version /       | ID Length |
//! | Routing Proto  | Indicator      | Protocol ID Ext |           |
//! | Discriminator  | (header len)   | (= 1)           | (0 => 6)  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | R R R | PduType | Version (= 1)  | Reserved (= 0)  | Max Area  |
//! |       | (5 bits)|                |                 | (0 => 3)  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - **Intradomain Routing Protocol Discriminator** (byte 0): the constant
//!   `0x83` (NLPID) identifying IS-IS. `decode` rejects any other value.
//! - **Length Indicator** (byte 1): the length in octets of the *fixed* header
//!   for this PDU type — the common 8 bytes plus the type-specific fixed header
//!   (e.g. 27 for an LSP, 20 for a P2P IIH). It is **not** the total PDU length
//!   (that is the per-body "PDU Length" field). `decode` bounds-checks it
//!   against the buffer and against a floor of `common_header_len`.
//! - **Version / Protocol ID Extension** (byte 2): constant `1`.
//! - **ID Length** (byte 3): the length of a system-id in octets. The wire
//!   convention is `0 => 6` (the default, MAC-sized id SPB uses) and
//!   `255 => 0`; `1..8` carry the value literally. `decode` normalizes this to
//!   `id_length` (0 is reported as 6).
//! - **PDU Type** (byte 4, low 5 bits): the message kind (`PduType`); the top 3
//!   bits are reserved and MUST be zero — `decode` rejects a nonzero reserved
//!   field rather than masking it.
//! - **Version** (byte 5): constant `1` (a second version byte, per ISO 10589).
//! - **Reserved** (byte 6): MUST be zero on transmit; carried, not rejected, on
//!   receive (a legacy soft field).
//! - **Maximum Area Addresses** (byte 7): `0 => 3`; carried verbatim.
//!
//! All multi-byte fields elsewhere in IS-IS are big-endian; the common header
//! has no multi-byte field, so endianness first bites in the bodies.

const std = @import("std");

/// Byte 0 of every IS-IS PDU: the NLPID that marks the intradomain routing
/// protocol as IS-IS (ISO/IEC 10589 / ISO 9577).
pub const discriminator: u8 = 0x83;

/// Byte 2 / byte 5 constant: the protocol version this codec speaks.
pub const version: u8 = 1;

/// Length of the common (type-independent) header, in octets.
pub const common_header_len: usize = 8;

/// The default system-id length in octets. On the wire an ID-Length byte of `0`
/// denotes this value; SPB uses 6-octet (MAC-sized) system ids.
pub const default_id_length: u8 = 6;

/// The default Maximum-Area-Addresses value an on-wire `0` denotes.
pub const default_max_area_addresses: u8 = 3;

/// The IS-IS PDU types (ISO/IEC 10589), carried in the low 5 bits of byte 4.
/// The exhaustive-but-open enum keeps unknown/reserved type numbers
/// representable so a decoder never panics on an unexpected type.
pub const PduType = enum(u5) {
    l1_lan_iih = 15,
    l2_lan_iih = 16,
    p2p_iih = 17,
    l1_lsp = 18,
    l2_lsp = 20,
    l1_csnp = 24,
    l2_csnp = 25,
    l1_psnp = 26,
    l2_psnp = 27,
    _,

    /// True for the three Hello (IIH) PDU types.
    pub fn isHello(t: PduType) bool {
        return switch (t) {
            .l1_lan_iih, .l2_lan_iih, .p2p_iih => true,
            else => false,
        };
    }

    /// True for the two Link State PDU types.
    pub fn isLsp(t: PduType) bool {
        return t == .l1_lsp or t == .l2_lsp;
    }

    /// True for a Complete Sequence Numbers PDU (CSNP).
    pub fn isCsnp(t: PduType) bool {
        return t == .l1_csnp or t == .l2_csnp;
    }

    /// True for a Partial Sequence Numbers PDU (PSNP).
    pub fn isPsnp(t: PduType) bool {
        return t == .l1_psnp or t == .l2_psnp;
    }
};

/// A decoded common header. `id_length` and `max_area_addresses` are already
/// normalized (the `0 => 6` / `0 => 3` wire conventions resolved), so a consumer
/// reads real widths, not raw codes.
pub const CommonHeader = struct {
    /// Length in octets of the whole fixed header (common + type-specific).
    length_indicator: u8,
    /// The message kind.
    pdu_type: PduType,
    /// System-id length in octets (a raw `0` is reported here as 6).
    id_length: u8,
    /// Maximum area addresses (a raw `0` is reported here as 3).
    max_area_addresses: u8,
    /// Byte 6: reserved. Carried verbatim (not validated) for faithful re-encode.
    reserved: u8 = 0,
};

pub const DecodeError = error{
    /// Fewer than `common_header_len` (8) bytes were supplied.
    Truncated,
    /// Byte 0 is not the IS-IS discriminator `0x83`.
    BadDiscriminator,
    /// Byte 2 or byte 5 is not protocol version 1.
    BadVersion,
    /// A reserved bit in the PDU-type octet (top 3 bits) was set.
    ReservedBitSet,
    /// The Length Indicator is smaller than the common header (8) — a header
    /// that cannot even describe its own common part.
    BadLengthIndicator,
};

/// Parses the 8-byte common header from the front of `bytes`. Validates the two
/// version constants, the discriminator, the reserved PDU-type bits, and that
/// the Length Indicator is self-consistent with the buffer. Reads nothing past
/// byte 7 and allocates nothing.
pub fn decode(bytes: []const u8) DecodeError!CommonHeader {
    if (bytes.len < common_header_len) return error.Truncated;
    if (bytes[0] != discriminator) return error.BadDiscriminator;
    if (bytes[2] != version) return error.BadVersion;
    const raw_id_len = bytes[3];
    // Top 3 bits of byte 4 are reserved and must be zero (not masked away).
    if (bytes[4] & 0xE0 != 0) return error.ReservedBitSet;
    const pdu_type: PduType = @enumFromInt(@as(u5, @intCast(bytes[4] & 0x1F)));
    if (bytes[5] != version) return error.BadVersion;
    const length_indicator = bytes[1];
    // The fixed header must be at least the common part. Its upper bound (the
    // type-specific fixed header must actually be present) is the body
    // decoder's concern — `decode` here validates only the 8 common octets, so
    // a caller may hand it exactly a common header without the body attached.
    if (length_indicator < common_header_len) return error.BadLengthIndicator;
    return .{
        .length_indicator = length_indicator,
        .pdu_type = pdu_type,
        .id_length = if (raw_id_len == 0) default_id_length else raw_id_len,
        .max_area_addresses = if (bytes[7] == 0) default_max_area_addresses else bytes[7],
        .reserved = bytes[6],
    };
}

/// Writes the 8-byte common header into `out` (which must be at least
/// `common_header_len`). `id_length` and `max_area_addresses` are written
/// verbatim — pass `6`/`3` for the defaults (this encoder does not fold them
/// back to the `0` short-form, keeping encode total and predictable).
pub fn encode(hdr: CommonHeader, out: []u8) error{BufferTooSmall}!void {
    if (out.len < common_header_len) return error.BufferTooSmall;
    out[0] = discriminator;
    out[1] = hdr.length_indicator;
    out[2] = version;
    out[3] = hdr.id_length;
    out[4] = @as(u8, @intFromEnum(hdr.pdu_type)); // top 3 bits already zero (u5)
    out[5] = version;
    out[6] = hdr.reserved;
    out[7] = hdr.max_area_addresses;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "common header round-trips a P2P IIH preamble" {
    const hdr: CommonHeader = .{
        .length_indicator = 20,
        .pdu_type = .p2p_iih,
        .id_length = 6,
        .max_area_addresses = 3,
    };
    var buf: [common_header_len]u8 = undefined;
    try encode(hdr, &buf);
    const golden = [_]u8{ 0x83, 0x14, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03 };
    try testing.expectEqualSlices(u8, &golden, &buf);
    const back = try decode(&buf);
    try testing.expectEqual(hdr, back);
}

test "id-length and max-area-addresses zero shorthands normalize" {
    const wire = [_]u8{ 0x83, 0x1b, 0x01, 0x00, 0x12, 0x01, 0x00, 0x00 };
    const h = try decode(&wire);
    try testing.expectEqual(PduType.l1_lsp, h.pdu_type);
    try testing.expectEqual(@as(u8, 6), h.id_length); // 0 => 6
    try testing.expectEqual(@as(u8, 3), h.max_area_addresses); // 0 => 3
}

test "reserved PDU-type bits are rejected, not masked" {
    var wire = [_]u8{ 0x83, 0x14, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03 };
    wire[4] = 0x20 | 0x11; // set a reserved bit above the 5-bit type
    try testing.expectError(error.ReservedBitSet, decode(&wire));
}

test "bad discriminator / version / length-indicator rejected" {
    var wire = [_]u8{ 0x83, 0x14, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03 };
    var bad_disc = wire;
    bad_disc[0] = 0x82;
    try testing.expectError(error.BadDiscriminator, decode(&bad_disc));
    var bad_ver = wire;
    bad_ver[2] = 2;
    try testing.expectError(error.BadVersion, decode(&bad_ver));
    var bad_ver2 = wire;
    bad_ver2[5] = 2;
    try testing.expectError(error.BadVersion, decode(&bad_ver2));
    // Length indicator below the common header is rejected.
    wire[1] = 7;
    try testing.expectError(error.BadLengthIndicator, decode(&wire));
    // A length indicator pointing past these 8 bytes is fine here — the body
    // is validated by the body decoder, not the common-header decode.
    wire[1] = 99;
    _ = try decode(&wire);
}

test "truncated below 8 bytes is Truncated at every length" {
    const full = [_]u8{ 0x83, 0x14, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03 };
    var n: usize = 0;
    while (n < common_header_len) : (n += 1) {
        try testing.expectError(error.Truncated, decode(full[0..n]));
    }
    _ = try decode(&full);
}

test "isLsp / isCsnp / isPsnp classify each PDU type, no other type" {
    const lsp_types = [_]PduType{ .l1_lsp, .l2_lsp };
    const csnp_types = [_]PduType{ .l1_csnp, .l2_csnp };
    const psnp_types = [_]PduType{ .l1_psnp, .l2_psnp };
    const other_types = [_]PduType{ .l1_lan_iih, .l2_lan_iih, .p2p_iih };

    for (lsp_types) |t| try testing.expect(t.isLsp());
    for (csnp_types) |t| try testing.expect(t.isCsnp());
    for (psnp_types) |t| try testing.expect(t.isPsnp());

    // Cross-check: none of the "other" (non-LSP/CSNP/PSNP) types classify as
    // any of the three, and each family rejects the other two families' types.
    for (other_types) |t| {
        try testing.expect(!t.isLsp());
        try testing.expect(!t.isCsnp());
        try testing.expect(!t.isPsnp());
    }
    for (lsp_types) |t| {
        try testing.expect(!t.isCsnp());
        try testing.expect(!t.isPsnp());
    }
    for (csnp_types) |t| {
        try testing.expect(!t.isLsp());
        try testing.expect(!t.isPsnp());
    }
    for (psnp_types) |t| {
        try testing.expect(!t.isLsp());
        try testing.expect(!t.isCsnp());
    }
}

test "unknown PDU type stays representable, never panics" {
    const wire = [_]u8{ 0x83, 0x14, 0x01, 0x06, 0x01, 0x01, 0x00, 0x03 }; // type 1
    const h = try decode(&wire);
    try testing.expectEqual(@as(u5, 1), @intFromEnum(h.pdu_type));
    try testing.expect(!h.pdu_type.isHello());
}

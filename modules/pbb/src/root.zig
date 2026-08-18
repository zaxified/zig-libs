// SPDX-License-Identifier: MIT
//! pbb — IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) encapsulation codec.
//!
//! Wraps a customer Ethernet frame so it rides a provider backbone addressed by
//! **backbone MACs** (B-DA/B-SA), optionally VLAN-tagged on the backbone
//! (B-Tag / B-VID), with the 802.1ah **I-TAG** carrying the 24-bit **I-SID**
//! service instance plus the relocated customer addresses. This is the
//! real-Ethernet SPB (802.1aq) data-plane encapsulation.
//!
//! **Contrast with the sibling `l2encap`.** `l2encap` is the *lean over-WireGuard*
//! variant: because an encrypted WireGuard backbone already supplies transport
//! addressing and crypto, it **drops** the backbone MACs and the B-VID, shrinking
//! the header to 8 bytes. `pbb` is the full IEEE frame for a *real Ethernet*
//! backbone that has no such tunnel: it must address the backbone with real MACs,
//! so B-DA/B-SA/B-Tag are present. Both agree on the 24-bit I-SID tenant id (a
//! `u24`), so a fabric can map one to the other.
//!
//! Standalone codec: no network, no clock, and **no allocation on the decode
//! path** — `decode` returns the customer bytes as a subslice of the input.
//! Concurrency `.reentrant` (no shared state). Consumer: the S1b SCADA/OT L2VPN
//! fabric's real-Ethernet edge. See ~/CML/S1B-scada-l2vpn-venture-plan.md.
//!
//! ## Wire format (IEEE 802.1Q-2014 clause 9.7 I-TAG + clause 25/26 PBB)
//! The backbone frame, in order (FCS is a frame-level trailer and out of scope):
//!
//! ```
//! +-------------------+  B-DA  : backbone destination MAC        (6 octets)
//! +-------------------+  B-SA  : backbone source MAC             (6 octets)
//! +-------------------+  B-Tag : OPTIONAL 802.1ad S-Tag          (4 octets)
//! |  0x88A8  |  B-TCI |          TPID 0x88A8 + TCI(PCP/DEI/B-VID)
//! +-------------------+  I-TAG : EtherType 0x88E7               (2 octets)
//! |       0x88E7      |
//! +-------------------+          I-TCI                          (4 octets)
//! | I-PCP|DEI|UCA|Res |          PCP(3) DEI(1) UCA(1) Res(3)  (octet 0)
//! |     I-SID (24)    |          I-SID (24-bit)             (octets 1..3)
//! +-------------------+  C-DA  : encapsulated customer DA       (6 octets)
//! +-------------------+  C-SA  : encapsulated customer SA       (6 octets)
//! +-------------------+  customer data: EtherType/tags/payload  (opaque)
//! ```
//!
//! ### The I-TAG includes the encapsulated customer addresses
//! Per 802.1Q clause 9.7 the **I-TAG structure itself contains C-DA and C-SA** —
//! PBB *relocates* the customer frame's own destination/source MACs into the
//! I-TAG rather than leaving them at the front of the payload. So on the wire the
//! customer addresses appear **once**, inside the I-TAG, and are **not** repeated
//! in the carried bytes. This codec models that faithfully: `c_da`/`c_sa` are
//! `Fields`, and the `customer_data` argument/slice is *everything the customer
//! frame carries after its own DA/SA* (its EtherType, any C-VLAN/S-VLAN tags, and
//! payload) — carried opaque. A caller holding a *complete* customer Ethernet
//! frame therefore splits its first 12 bytes into `c_da`/`c_sa` and passes the
//! remainder as `customer_data`; a receiver reassembles the full frame by
//! prepending `c_da`/`c_sa` to the decoded `customer_data`.
//!
//! ### I-TCI bit order (the crux field — verified against 802.1Q clause 9.7)
//! The 4-octet I-TCI, most-significant bit first:
//!
//! | bits | field | notes |
//! |------|-------|-------|
//! | 31..29 | I-PCP | priority code point |
//! | 28     | I-DEI | drop eligible indicator |
//! | 27     | UCA   | Use Customer Addresses |
//! | 26..24 | Res   | reserved — transmitted 0, **ignored on receipt** |
//! | 23..0  | I-SID | 24-bit backbone service instance identifier |
//!
//! Reserved bits are ignored on decode (the standard mandates transmit-as-0,
//! ignore-on-receipt) — unlike `l2encap`, whose *own* versioned header rejects
//! reserved bits to close a covert channel. `pbb` is a real IEEE format and must
//! interoperate, so it fails **open** on reserved bits and always transmits 0.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "IEEE 802.1ah PBB (MAC-in-MAC) I-TAG frame format (802.1Q-2014 clause 9.7 / clause 25/26)",
    .deps = .{}, // std only
};

// ── constants ─────────────────────────────────────────────────────────────────

/// A backbone or customer MAC address — six raw octets, carried verbatim.
pub const Mac = [6]u8;

/// Octets in a MAC address.
pub const mac_len: usize = 6;

/// EtherType/TPID of the B-Tag: an 802.1ad S-Tag (`0x88A8`). Its presence at the
/// tag region marks a B-VLAN-tagged backbone frame.
pub const b_tpid: u16 = 0x88A8;

/// The 802.1ah I-TAG EtherType (`0x88E7`). Always present; `decode` requires it.
pub const itag_ethertype: u16 = 0x88E7;

/// B-DA(6) + B-SA(6).
pub const b_mac_len: usize = 2 * mac_len;

/// A B-Tag on the wire: TPID(2) + B-TCI(2).
pub const b_tag_len: usize = 4;

/// The full I-TAG: EtherType(2) + I-TCI(4) + C-DA(6) + C-SA(6).
pub const itag_len: usize = 2 + 4 + 2 * mac_len;

/// Smallest valid backbone frame (no B-Tag, empty customer data): B-MACs + I-TAG.
pub const min_frame_len: usize = b_mac_len + itag_len;

/// Largest backbone frame this codec will encode or accept on decode.
///
/// No single external standard fixes one number here — 802.1ah leaves the
/// carried frame size to the backbone port's own MTU — so this mirrors the
/// sibling `ethfrag`'s `max_frame_len` (`std.math.maxInt(u16)` = 65535)
/// rather than inventing a third convention: this module's own doc comment
/// already says "no real 802.1ah backbone port will carry" a 9 KiB+ frame,
/// and `ethfrag`/`l2encap` already treat 65535 as the shared backbone
/// ceiling. `UNVERIFIED:` against an external standard for the exact value;
/// the *shape* of the bound (some ceiling must exist) is not in question.
pub const max_frame_len: usize = std.math.maxInt(u16);

/// Largest representable I-SID (24-bit). Enforced by the `u24` type on `Fields`.
pub const max_isid: u24 = std.math.maxInt(u24);

// ── B-Tag (optional backbone S-Tag) ────────────────────────────────────────────

/// The optional 802.1ad S-Tag carried on the backbone VLAN. Absent (`b_tag =
/// null` in `Fields`) means the frame is untagged on the B-VLAN.
pub const BTag = struct {
    /// Backbone priority code point.
    pcp: u3,
    /// Backbone drop-eligible indicator.
    dei: bool,
    /// The B-VID (12-bit backbone VLAN id).
    vid: u12,
};

/// Pack a `BTag` into its 2-octet TCI: PCP(3) | DEI(1) | B-VID(12), MSB first.
fn encodeBTci(t: BTag) u16 {
    return (@as(u16, t.pcp) << 13) |
        (@as(u16, @intFromBool(t.dei)) << 12) |
        @as(u16, t.vid);
}

/// Inverse of `encodeBTci`. Every 16-bit value maps to a valid `BTag`.
fn decodeBTci(tci: u16) BTag {
    return .{
        .pcp = @intCast((tci >> 13) & 0x7),
        .dei = (tci >> 12) & 0x1 != 0,
        .vid = @intCast(tci & 0x0FFF),
    };
}

// ── decoded frame fields ────────────────────────────────────────────────────────

/// The backbone + I-TAG metadata of one PBB frame. The customer bytes that follow
/// the I-TAG are carried separately (as the `encode` argument / the `Decoded`
/// slice), not in this struct.
pub const Fields = struct {
    /// Backbone destination MAC.
    b_da: Mac,
    /// Backbone source MAC.
    b_sa: Mac,
    /// Backbone S-Tag, or `null` when the frame is untagged on the B-VLAN.
    b_tag: ?BTag,
    /// I-TAG priority code point.
    i_pcp: u3,
    /// I-TAG drop-eligible indicator.
    i_dei: bool,
    /// Use Customer Addresses bit (I-TCI bit 27, mask `0x08` in the flag
    /// octet). This field records the **raw bit only** — the codec attaches no
    /// forwarding semantics to it, so its value round-trips unchanged
    /// regardless of which of the two conflicting readings below is correct.
    ///
    /// Naming: kept as `uca` (matches the rest of this struct's 802.1Q/802.1ah
    /// vocabulary — I-PCP/I-DEI/I-SID/B-TCI are all standard terms — and
    /// matches independent vendor usage: Nokia SR OS's PBB docs also say
    /// "UCA"). Wireshark's own IEEE 802.1ah dissector calls the *identical
    /// bit* `ieee8021ah.nca`, and — verified by forcing this bit to 1 through
    /// `scripts/dissect.py`/sharkd (see the second Wireshark-anchored golden
    /// below) — its `nca` output tracks the **same raw polarity**, not the
    /// logical inverse: bit=1 reads as both `uca=true` here and
    /// `ieee8021ah.nca == 1` in Wireshark, whose dissector's own embedded
    /// string table names that state "No Customer Addresses". So this is a
    /// genuine opposite-meaning naming conflict on one shared bit, not a
    /// cosmetic spelling difference — and it is left unresolved on purpose:
    /// the IEEE 802.1Q-2014 primary text that would adjudicate it is
    /// paywalled and was not available to this repo. `uca` was kept, not
    /// renamed, because renaming on the strength of one of two conflicting
    /// secondary sources would trade one unverified guess for another.
    uca: bool,
    /// 24-bit backbone service instance identifier (the tenant/VPN key). Agrees
    /// with `l2encap`'s I-SID width so the two encapsulations map 1:1.
    i_sid: u24,
    /// Encapsulated (relocated) customer destination MAC — an I-TAG field.
    c_da: Mac,
    /// Encapsulated (relocated) customer source MAC — an I-TAG field.
    c_sa: Mac,

    /// True iff the frame carries a B-Tag (is tagged on the B-VLAN).
    pub fn hasBTag(f: Fields) bool {
        return f.b_tag != null;
    }

    /// The B-VID, flattening the optional B-Tag: `null` if untagged.
    pub fn bvid(f: Fields) ?u12 {
        return if (f.b_tag) |t| t.vid else null;
    }
};

/// Pack the I-TCI: I-PCP(3) | I-DEI(1) | UCA(1) | Res(3=0) | I-SID(24), MSB first.
fn encodeITci(f: Fields) u32 {
    return (@as(u32, f.i_pcp) << 29) |
        (@as(u32, @intFromBool(f.i_dei)) << 28) |
        (@as(u32, @intFromBool(f.uca)) << 27) |
        // bits 26..24 reserved — transmitted as 0
        @as(u32, f.i_sid);
}

// ── encode (send side) ──────────────────────────────────────────────────────────

pub const EncodeError = error{
    /// `out` is smaller than `encodedLen(fields, customer_data.len)`.
    BufferTooSmall,
    /// `encodedLen(fields, customer_data.len)` exceeds `max_frame_len`.
    FrameTooLarge,
};

/// Header size for a frame with/without a B-Tag (everything before the customer
/// data): B-MACs + optional B-Tag + I-TAG (incl. the C-DA/C-SA).
pub fn headerLen(has_btag: bool) usize {
    return b_mac_len + (if (has_btag) b_tag_len else 0) + itag_len;
}

/// Total bytes `encode` writes: the header (per B-Tag presence) plus the opaque
/// customer data verbatim.
pub fn encodedLen(fields: Fields, customer_data_len: usize) usize {
    return headerLen(fields.b_tag != null) + customer_data_len;
}

fn writeMac(out: []u8, mac: Mac) void {
    @memcpy(out[0..mac_len], &mac);
}

/// Encapsulate `customer_data` (the opaque bytes *after* the customer frame's own
/// DA/SA — see the module doc comment) under `fields` into caller-supplied `out`.
/// Zero allocation. Returns the exact filled prefix of `out`. Never partially
/// writes on error.
pub fn encode(fields: Fields, customer_data: []const u8, out: []u8) EncodeError![]u8 {
    const total = encodedLen(fields, customer_data.len);
    if (total > max_frame_len) return error.FrameTooLarge;
    if (out.len < total) return error.BufferTooSmall;

    var off: usize = 0;
    writeMac(out[off..], fields.b_da);
    off += mac_len;
    writeMac(out[off..], fields.b_sa);
    off += mac_len;

    if (fields.b_tag) |t| {
        std.mem.writeInt(u16, out[off..][0..2], b_tpid, .big);
        std.mem.writeInt(u16, out[off + 2 ..][0..2], encodeBTci(t), .big);
        off += b_tag_len;
    }

    std.mem.writeInt(u16, out[off..][0..2], itag_ethertype, .big);
    off += 2;
    std.mem.writeInt(u32, out[off..][0..4], encodeITci(fields), .big);
    off += 4;
    writeMac(out[off..], fields.c_da);
    off += mac_len;
    writeMac(out[off..], fields.c_sa);
    off += mac_len;

    @memcpy(out[off..total], customer_data);
    return out[0..total];
}

/// Allocating convenience wrapper over `encode`: returns freshly-owned bytes the
/// caller frees with the same allocator. Mirrors `l2encap.encodeAlloc`.
pub fn encodeAlloc(allocator: Allocator, fields: Fields, customer_data: []const u8) (Allocator.Error || error{FrameTooLarge})![]u8 {
    const total = encodedLen(fields, customer_data.len);
    if (total > max_frame_len) return error.FrameTooLarge;
    const buf = try allocator.alloc(u8, total);
    // Cannot fail: `buf` is exactly `encodedLen` bytes, and the size was
    // already checked against `max_frame_len` above.
    return encode(fields, customer_data, buf) catch unreachable;
}

// ── decode (receive side) ───────────────────────────────────────────────────────

/// A decoded PBB frame. `customer_data` is a **subslice of the input** (not owned,
/// not copied) — `decode` allocates nothing, so it can never allocate more than
/// its input, by construction.
pub const Decoded = struct {
    fields: Fields,
    /// The opaque customer bytes after the I-TAG (customer EtherType/tags/payload,
    /// *without* the customer DA/SA, which live in `fields.c_da`/`c_sa`). May be
    /// empty.
    customer_data: []const u8,
};

pub const DecodeError = error{
    /// Fewer bytes than the field being read requires.
    Truncated,
    /// The tag region after the B-MACs is neither a B-Tag (0x88A8) nor the I-TAG
    /// EtherType (0x88E7).
    UnexpectedEtherType,
    /// A B-Tag was present but was not followed by the I-TAG EtherType (0x88E7).
    MissingITag,
    /// `bytes.len` exceeds `max_frame_len`.
    FrameTooLarge,
};

/// Parse one PBB frame from untrusted link bytes. Every field is bounds-checked
/// before it is read; a truncated frame, a wrong tag-region EtherType, or a B-Tag
/// not followed by the I-TAG returns a typed error and never panics, reads out of
/// bounds, loops, or allocates. Reserved I-TCI bits are ignored (per spec).
pub fn decode(bytes: []const u8) DecodeError!Decoded {
    if (bytes.len > max_frame_len) return error.FrameTooLarge;
    // B-DA + B-SA + at least the 2-octet tag-region EtherType.
    if (bytes.len < b_mac_len + 2) return error.Truncated;

    var b_da: Mac = undefined;
    @memcpy(&b_da, bytes[0..mac_len]);
    var b_sa: Mac = undefined;
    @memcpy(&b_sa, bytes[mac_len..b_mac_len]);

    var off: usize = b_mac_len;
    var b_tag: ?BTag = null;

    const first_et = std.mem.readInt(u16, bytes[off..][0..2], .big);
    if (first_et == b_tpid) {
        // B-Tag: TPID(2) already read at `off`; need TCI(2) + the next
        // EtherType(2) to be present before we advance.
        if (bytes.len < off + b_tag_len + 2) return error.Truncated;
        b_tag = decodeBTci(std.mem.readInt(u16, bytes[off + 2 ..][0..2], .big));
        off += b_tag_len;
        if (std.mem.readInt(u16, bytes[off..][0..2], .big) != itag_ethertype)
            return error.MissingITag;
    } else if (first_et != itag_ethertype) {
        return error.UnexpectedEtherType;
    }

    // `off` now points at the I-TAG EtherType. Need the whole I-TAG present.
    if (bytes.len < off + itag_len) return error.Truncated;
    off += 2; // I-TAG EtherType (already validated as 0x88E7)

    const i_tci = std.mem.readInt(u32, bytes[off..][0..4], .big);
    off += 4;

    var c_da: Mac = undefined;
    @memcpy(&c_da, bytes[off..][0..mac_len]);
    off += mac_len;
    var c_sa: Mac = undefined;
    @memcpy(&c_sa, bytes[off..][0..mac_len]);
    off += mac_len;

    return .{
        .fields = .{
            .b_da = b_da,
            .b_sa = b_sa,
            .b_tag = b_tag,
            .i_pcp = @intCast((i_tci >> 29) & 0x7),
            .i_dei = (i_tci >> 28) & 0x1 != 0,
            .uca = (i_tci >> 27) & 0x1 != 0,
            // bits 26..24 reserved — ignored on receipt (spec).
            .i_sid = @intCast(i_tci & 0xFF_FFFF),
            .c_da = c_da,
            .c_sa = c_sa,
        },
        .customer_data = bytes[off..],
    };
}

// ── tests ───────────────────────────────────────────────────────────────────────

const testing = std.testing;

// The golden frames below are **hand-assembled field-by-field from the IEEE
// 802.1ah / 802.1Q-2014 clause 9.7 layout** — no packet capture was available, so
// every octet is annotated with the field and offset it encodes and cross-checked
// against the bit table in the module doc comment.

test "golden: full frame with B-Tag, byte-exact + decode recovers every field" {
    const fields: Fields = .{
        .b_da = .{ 0x10, 0x00, 0x00, 0x00, 0x00, 0xBB },
        .b_sa = .{ 0x10, 0x00, 0x00, 0x00, 0x00, 0xAA },
        .b_tag = .{ .pcp = 3, .dei = false, .vid = 100 }, // B-VID = 100 = 0x064
        .i_pcp = 5,
        .i_dei = false,
        .uca = true,
        .i_sid = 0x00_0123,
        .c_da = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .c_sa = .{ 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE },
    };
    const customer_data = [_]u8{ 0x08, 0x00, 0xDE, 0xAD }; // C-EtherType 0x0800 + data

    var buf: [64]u8 = undefined;
    const out = try encode(fields, &customer_data, &buf);

    const golden = [_]u8{
        0x10, 0x00, 0x00, 0x00, 0x00, 0xBB, // B-DA        (offset 0)
        0x10, 0x00, 0x00, 0x00, 0x00, 0xAA, // B-SA        (offset 6)
        0x88, 0xA8, //                          B-Tag TPID  (offset 12)
        0x60, 0x64, //                          B-TCI: PCP=3 DEI=0 VID=100 (offset 14)
        0x88, 0xE7, //                          I-TAG EtherType (offset 16)
        0xA8, 0x00, 0x01, 0x23, //              I-TCI: PCP=5 DEI=0 UCA=1 Res=0 I-SID=0x123 (offset 18)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // C-DA        (offset 22)
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // C-SA        (offset 28)
        0x08, 0x00, 0xDE, 0xAD, //              customer data (offset 34)
    };
    try testing.expectEqualSlices(u8, &golden, out);

    const dec = try decode(out);
    try testing.expectEqual(fields, dec.fields);
    try testing.expectEqualSlices(u8, &customer_data, dec.customer_data);
    try testing.expectEqual(@as(?u12, 100), dec.fields.bvid());
    try testing.expect(dec.fields.hasBTag());
}

test "golden: untagged B-VLAN (no B-Tag), byte-exact + round-trip" {
    const fields: Fields = .{
        .b_da = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .b_sa = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
        .b_tag = null, // untagged on the backbone VLAN
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 0x00_ABCD,
        .c_da = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // customer broadcast
        .c_sa = .{ 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
    };
    var buf: [64]u8 = undefined;
    const out = try encode(fields, "", &buf);

    const golden = [_]u8{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // B-DA
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // B-SA
        0x88, 0xE7, //                          I-TAG EtherType — no B-Tag before it
        0x00, 0x00, 0xAB, 0xCD, //              I-TCI: all zero flags, I-SID=0xABCD
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // C-DA
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // C-SA
    };
    try testing.expectEqualSlices(u8, &golden, out);
    try testing.expectEqual(min_frame_len, out.len);

    const dec = try decode(out);
    try testing.expectEqual(fields, dec.fields);
    try testing.expectEqual(@as(usize, 0), dec.customer_data.len);
    try testing.expectEqual(@as(?u12, null), dec.fields.bvid());
    try testing.expect(!dec.fields.hasBTag());
}

test "I-TCI bit-field correctness: distinct I-PCP/I-DEI/UCA/I-SID land in the right bits" {
    // Pick values that are wrong under any bit-swap: I-PCP=6 (110), I-DEI=1,
    // UCA=0, I-SID=0xABCDEF. The first I-TCI octet must be:
    //   110 1 0 000 = 0xD0  (PCP<<5 | DEI<<4 | UCA<<3 | Res).
    const fields: Fields = .{
        .b_da = @splat(0),
        .b_sa = @splat(0),
        .b_tag = null,
        .i_pcp = 6,
        .i_dei = true,
        .uca = false,
        .i_sid = 0xAB_CDEF,
        .c_da = @splat(0),
        .c_sa = @splat(0),
    };
    var buf: [min_frame_len]u8 = undefined;
    const out = try encode(fields, "", &buf);
    // I-TCI is at offset b_mac_len + 2 (after the I-TAG EtherType).
    const tci_off = b_mac_len + 2;
    try testing.expectEqual(@as(u8, 0xD0), out[tci_off]); // PCP/DEI/UCA/Res octet
    try testing.expectEqual(@as(u8, 0xAB), out[tci_off + 1]); // I-SID high
    try testing.expectEqual(@as(u8, 0xCD), out[tci_off + 2]);
    try testing.expectEqual(@as(u8, 0xEF), out[tci_off + 3]);

    const dec = try decode(out);
    try testing.expectEqual(@as(u3, 6), dec.fields.i_pcp);
    try testing.expect(dec.fields.i_dei);
    try testing.expect(!dec.fields.uca);
    try testing.expectEqual(@as(u24, 0xAB_CDEF), dec.fields.i_sid);
}

test "F4: B-TCI top-of-range byte golden (PCP=7, DEI=1, VID=4095), not just round-trip" {
    // decodeBTci is documented "every 16-bit value maps to a valid BTag",
    // but the only dei=true B-Tag in the suite was a pure round trip or the
    // Wireshark golden's PCP=2/DEI=1/VID=200 — never the top-of-range
    // corner. PCP=7 (111), DEI=1, VID=0xFFF (all 12 bits set) packs to
    // 0b111_1_111111111111 = 0xFFFF, i.e. every bit of the 16-bit TCI set —
    // the case most likely to expose a mispositioned field.
    const fields: Fields = .{
        .b_da = @splat(0),
        .b_sa = @splat(0),
        .b_tag = .{ .pcp = 7, .dei = true, .vid = 4095 },
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 0,
        .c_da = @splat(0),
        .c_sa = @splat(0),
    };
    var buf: [min_frame_len + b_tag_len]u8 = undefined;
    const out = try encode(fields, "", &buf);

    // B-TCI sits right after the B-TPID, which itself follows B-DA/B-SA.
    const btci_off = b_mac_len + 2;
    try testing.expectEqual(@as(u8, 0xFF), out[btci_off]);
    try testing.expectEqual(@as(u8, 0xFF), out[btci_off + 1]);

    const dec = try decode(out);
    const bt = dec.fields.b_tag orelse return error.TestExpectedBTag;
    try testing.expectEqual(@as(u3, 7), bt.pcp);
    try testing.expect(bt.dei);
    try testing.expectEqual(@as(u12, 4095), bt.vid);
}

test "positive control: swapping UCA and I-DEI bits would flip the golden octet" {
    // Permanent guard that the I-TCI test pins the exact bit positions. UCA is
    // bit 27 (mask 0x08 in octet 0), I-DEI is bit 28 (mask 0x10). A swapped-impl
    // would emit the other octet; assert our octet is the correct one and that
    // the two masks are genuinely distinct bits after decode.
    const fields: Fields = .{
        .b_da = @splat(0),
        .b_sa = @splat(0),
        .b_tag = null,
        .i_pcp = 0,
        .i_dei = false,
        .uca = true, // UCA set, DEI clear
        .i_sid = 0,
        .c_da = @splat(0),
        .c_sa = @splat(0),
    };
    var buf: [min_frame_len]u8 = undefined;
    const out = try encode(fields, "", &buf);
    const tci0 = out[b_mac_len + 2];
    try testing.expectEqual(@as(u8, 0x08), tci0); // UCA bit only
    try testing.expect(tci0 != 0x10); // NOT the I-DEI bit (would be the swap bug)

    // Decode a byte with only I-DEI set: must read dei=true, uca=false — proving
    // the two occupy different bits (a swap bug would read them backwards).
    var wire: [min_frame_len]u8 = out[0..min_frame_len].*;
    wire[b_mac_len + 2] = 0x10; // I-DEI bit only
    const dec = try decode(&wire);
    try testing.expect(dec.fields.i_dei);
    try testing.expect(!dec.fields.uca);
}

test "positive control: I-SID read from the wrong 3 bytes yields a different tenant" {
    // If decode read the I-SID from octets 0..3 of the I-TCI (including the flag
    // octet) instead of the low 24 bits, this would disagree.
    const fields: Fields = .{
        .b_da = @splat(0),
        .b_sa = @splat(0),
        .b_tag = null,
        .i_pcp = 7, // makes the flag octet 0xE0 — a wrong reader would pick it up
        .i_dei = false,
        .uca = false,
        .i_sid = 0x01_0203,
        .c_da = @splat(0),
        .c_sa = @splat(0),
    };
    var buf: [min_frame_len]u8 = undefined;
    const out = try encode(fields, "", &buf);
    const dec = try decode(out);
    try testing.expectEqual(@as(u24, 0x01_0203), dec.fields.i_sid);
    // The wrong 3 bytes (flag octet + first 2 I-SID octets) would be 0xE00102.
    const wrong: u24 = @intCast(std.mem.readInt(u24, out[b_mac_len + 2 ..][0..3], .big));
    try testing.expectEqual(@as(u24, 0xE0_0102), wrong);
    try testing.expect(dec.fields.i_sid != wrong);
}

test "encodedLen / headerLen match what encode writes" {
    const tagged: Fields = .{
        .b_da = @splat(0),
        .b_sa = @splat(0),
        .b_tag = .{ .pcp = 0, .dei = false, .vid = 1 },
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 0,
        .c_da = @splat(0),
        .c_sa = @splat(0),
    };
    var untagged = tagged;
    untagged.b_tag = null;

    try testing.expectEqual(min_frame_len, headerLen(false));
    try testing.expectEqual(min_frame_len + b_tag_len, headerLen(true));
    try testing.expectEqual(min_frame_len, encodedLen(untagged, 0));
    try testing.expectEqual(min_frame_len + b_tag_len + 5, encodedLen(tagged, 5));
}

test "encode: buffer too small is rejected, never partially writes" {
    const fields: Fields = .{
        .b_da = @splat(0xAA),
        .b_sa = @splat(0xBB),
        .b_tag = null,
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 0,
        .c_da = @splat(0),
        .c_sa = @splat(0),
    };
    var too_small: [min_frame_len - 1]u8 = @splat(0x5A);
    try testing.expectError(error.BufferTooSmall, encode(fields, "", &too_small));
    for (too_small) |b| try testing.expectEqual(@as(u8, 0x5A), b); // untouched
}

test "encode: exactly max_frame_len is accepted, one byte more is FrameTooLarge" {
    const fields: Fields = .{
        .b_da = @splat(0x11),
        .b_sa = @splat(0x22),
        .b_tag = null,
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 1,
        .c_da = @splat(0x33),
        .c_sa = @splat(0x44),
    };
    const at_cap_len = max_frame_len - headerLen(false);
    const data = try testing.allocator.alloc(u8, at_cap_len);
    defer testing.allocator.free(data);
    const wire = try encodeAlloc(testing.allocator, fields, data);
    defer testing.allocator.free(wire);
    try testing.expectEqual(@as(usize, max_frame_len), wire.len);

    const over = try testing.allocator.alloc(u8, at_cap_len + 1);
    defer testing.allocator.free(over);
    try testing.expectError(error.FrameTooLarge, encodeAlloc(testing.allocator, fields, over));
}

test "decode: exactly max_frame_len is accepted, one byte more is FrameTooLarge" {
    const buf = try testing.allocator.alloc(u8, max_frame_len + 1);
    defer testing.allocator.free(buf);
    @memset(buf, 0);
    // A minimal valid untagged header at the front: B-DA/B-SA (zero, arbitrary)
    // followed directly by the I-TAG EtherType.
    std.mem.writeInt(u16, buf[b_mac_len..][0..2], itag_ethertype, .big);

    try testing.expectError(error.FrameTooLarge, decode(buf));

    const at_cap = buf[0..max_frame_len];
    const dec = try decode(at_cap);
    try testing.expectEqual(max_frame_len - min_frame_len, dec.customer_data.len);
}

test "encodeAlloc equals caller-buffer encode" {
    const fields: Fields = .{
        .b_da = .{ 1, 2, 3, 4, 5, 6 },
        .b_sa = .{ 7, 8, 9, 10, 11, 12 },
        .b_tag = .{ .pcp = 4, .dei = true, .vid = 4094 },
        .i_pcp = 2,
        .i_dei = true,
        .uca = true,
        .i_sid = 0xF0_F0F0,
        .c_da = .{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 },
        .c_sa = .{ 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02 },
    };
    const data = "opaque customer ethertype+payload";
    const owned = try encodeAlloc(testing.allocator, fields, data);
    defer testing.allocator.free(owned);
    var buf: [128]u8 = undefined;
    const inline_out = try encode(fields, data, &buf);
    try testing.expectEqualSlices(u8, inline_out, owned);
}

test "property: encode -> decode round-trips fields + customer bytes byte-identical" {
    var prng = std.Random.DefaultPrng.init(0x0BAD_C0DE_F00D_1357);
    const rand = prng.random();

    var iter: usize = 0;
    while (iter < 500) : (iter += 1) {
        const i_sid: u24 = switch (iter % 3) {
            0 => 0,
            1 => max_isid,
            else => rand.int(u24),
        };
        const b_tag: ?BTag = if (iter % 2 == 0) .{
            .pcp = rand.int(u3),
            .dei = rand.boolean(),
            .vid = rand.int(u12),
        } else null;

        var b_da: Mac = undefined;
        rand.bytes(&b_da);
        var b_sa: Mac = undefined;
        rand.bytes(&b_sa);
        var c_da: Mac = undefined;
        rand.bytes(&c_da);
        var c_sa: Mac = undefined;
        rand.bytes(&c_sa);

        const fields: Fields = .{
            .b_da = b_da,
            .b_sa = b_sa,
            .b_tag = b_tag,
            .i_pcp = rand.int(u3),
            .i_dei = rand.boolean(),
            .uca = rand.boolean(),
            .i_sid = i_sid,
            .c_da = c_da,
            .c_sa = c_sa,
        };

        const data_len = switch (iter % 4) {
            0 => 0,
            1 => 1,
            2 => rand.intRangeAtMost(usize, 2, 1600),
            else => rand.intRangeAtMost(usize, 0, 4096),
        };
        const data = try testing.allocator.alloc(u8, data_len);
        defer testing.allocator.free(data);
        rand.bytes(data);

        const wire = try encodeAlloc(testing.allocator, fields, data);
        defer testing.allocator.free(wire);

        const dec = try decode(wire);
        try testing.expectEqual(fields, dec.fields);
        try testing.expectEqualSlices(u8, data, dec.customer_data);
    }
}

test "decode: truncated at every length below a full untagged frame is rejected" {
    const fields: Fields = .{
        .b_da = @splat(0x11),
        .b_sa = @splat(0x22),
        .b_tag = null,
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 0x12_3456,
        .c_da = @splat(0x33),
        .c_sa = @splat(0x44),
    };
    var buf: [min_frame_len]u8 = undefined;
    const full = try encode(fields, "", &buf);
    var len: usize = 0;
    while (len < full.len) : (len += 1) {
        try testing.expectError(error.Truncated, decode(full[0..len]));
    }
    _ = try decode(full); // exactly min_frame_len decodes
}

test "decode: truncated mid-B-Tag frame is rejected before over-read" {
    const fields: Fields = .{
        .b_da = @splat(0x11),
        .b_sa = @splat(0x22),
        .b_tag = .{ .pcp = 1, .dei = false, .vid = 7 },
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 0,
        .c_da = @splat(0x33),
        .c_sa = @splat(0x44),
    };
    var buf: [64]u8 = undefined;
    const full = try encode(fields, "", &buf);
    // Every truncation between "B-Tag TPID readable" and the full frame errors.
    var len: usize = b_mac_len;
    while (len < full.len) : (len += 1) {
        try testing.expectError(error.Truncated, decode(full[0..len]));
    }
    _ = try decode(full);
}

test "decode: wrong tag-region EtherType is rejected" {
    var buf: [min_frame_len]u8 = @splat(0);
    // Neither 0x88A8 nor 0x88E7 at the tag region.
    std.mem.writeInt(u16, buf[b_mac_len..][0..2], 0x0800, .big);
    try testing.expectError(error.UnexpectedEtherType, decode(&buf));
}

test "decode: B-Tag not followed by the I-TAG EtherType is rejected" {
    var buf: [min_frame_len + b_tag_len]u8 = @splat(0);
    std.mem.writeInt(u16, buf[b_mac_len..][0..2], b_tpid, .big); // B-Tag TPID
    // B-TCI at +2 is anything; the EtherType after the B-Tag is wrong (0x0000).
    try testing.expectError(error.MissingITag, decode(&buf));
    // Fix it up: now it must decode.
    std.mem.writeInt(u16, buf[b_mac_len + b_tag_len ..][0..2], itag_ethertype, .big);
    _ = try decode(&buf);
}

test "decode: reserved I-TCI bits are ignored (fail-open, per spec), not rejected" {
    const fields: Fields = .{
        .b_da = @splat(0),
        .b_sa = @splat(0),
        .b_tag = null,
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 0x00_0055,
        .c_da = @splat(0),
        .c_sa = @splat(0),
    };
    var buf: [min_frame_len]u8 = undefined;
    const out = try encode(fields, "", &buf);
    var wire: [min_frame_len]u8 = out[0..min_frame_len].*;
    // Set the 3 reserved bits (bits 26..24 = low 3 bits of the flag octet).
    wire[b_mac_len + 2] |= 0x07;
    const dec = try decode(&wire); // accepted, not rejected
    try testing.expectEqual(fields.i_sid, dec.fields.i_sid);
    try testing.expect(!dec.fields.uca);
    try testing.expect(!dec.fields.i_dei);
}

test "semantics: two I-SIDs decode to distinct tenants (isolation key round-trips)" {
    const base: Fields = .{
        .b_da = @splat(0),
        .b_sa = @splat(0),
        .b_tag = null,
        .i_pcp = 0,
        .i_dei = false,
        .uca = false,
        .i_sid = 0,
        .c_da = @splat(0),
        .c_sa = @splat(0),
    };
    var a = base;
    a.i_sid = 100;
    var b = base;
    b.i_sid = 200;
    const data = "customer payload";
    const wa = try encodeAlloc(testing.allocator, a, data);
    defer testing.allocator.free(wa);
    const wb = try encodeAlloc(testing.allocator, b, data);
    defer testing.allocator.free(wb);
    const da = try decode(wa);
    const db = try decode(wb);
    try testing.expect(da.fields.i_sid != db.fields.i_sid);
    try testing.expectEqualSlices(u8, da.customer_data, db.customer_data);
}

// ── fuzz target ───────────────────────────────────────────────────────────────

test "fuzz: decode never panics/OOBs on hostile bytes and stays within input bounds" {
    // `decode` reads straight off an untrusted link, so this drives arbitrary
    // bytes — truncated, wrong EtherTypes, B-Tag with/without a following I-TAG,
    // absurd lengths — and asserts only: never panics, and any successful
    // decode's customer slice is strictly within the input. Under a plain `zig
    // build test` this runs once as a smoke test (same convention as l2encap).
    try testing.fuzz({}, fuzzDecode, .{});
}

// ── External anchor: Wireshark 4.6.4 (sharkd, via scripts/dissect.py) ───────────
//
// The two goldens above were hand-assembled from the spec text — an anchor
// whose authority comes from the same head that wrote the encoder is not an
// external anchor (our encoder and our own reading of 802.1ah could share one
// misunderstanding and both goldens would still "pass"). The vector below was
// instead produced by this module's own `encode()` and fed through
// `scripts/dissect.py`, which runs Wireshark 4.6.4's real IEEE 802.1ah
// dissector (sharkd, offline, no network, no capture), then pinned to what
// Wireshark actually printed. This is a behaviour cross-check, not a port: no
// third-party source was copied into this codec (see `/NOTICE` — none needed).
//
// Command:
//   scripts/dissect.py --frame raw --fields '00 1b 21 00 00 01 00 1b 21 00 00
//   02 88 a8 50 c8 88 e7 90 00 10 00 00 50 56 00 00 01 00 50 56 00 00 02 81 00
//   00 0a 08 00 45 00 00 1c 00 01 00 00 40 fd 65 e2 0a 00 00 01 0a 00 00 02 41
//   42 43 44 45 46 47 48'
//
// Wireshark printed (verbatim, trimmed to the load-bearing lines):
//   frame.protocols == "eth:ethertype:ieee8021ad:ethertype:vlan:ethertype:ip:data"
//   eth.type == 0x88a8 = Type: 802.1ad Provider Bridge (Q-in-Q) (0x88a8)
//   ieee8021ad.priority == 2 = Priority: 2            (B-TCI PCP)
//   ieee8021ad.dei == 1                                (B-TCI DEI)
//   ieee8021ad.id == 200 = ID: 200                     (B-VID)
//   ieee8021ah.priority == 4 = Priority: 4             (I-TCI I-PCP)
//   ieee8021ah.drop == 1                               (I-TCI I-DEI)
//   ieee8021ah.nca == 0                                (I-TCI bit 27 — see note below)
//   ieee8021ah.res1 == 0 / ieee8021ah.res2 == 0        (reserved, both 0)
//   ieee8021ah.isid == 4096 = I-SID: 4096
//   ieee8021ah.cdst == 00:50:56:00:00:01 = C-Destination
//   ieee8021ah.csrc == 00:50:56:00:00:02 = C-Source
//   ieee8021ah.etype == 0x8100 = Type: 802.1Q Virtual LAN (0x8100)
//   vlan.priority == 0 / vlan.dei == False / vlan.id == 10
//   vlan.etype == 0x0800 = Type: IPv4 (0x0800)
//   ip = Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.0.0.2
//   ip.proto == 253 = Protocol: Unknown (253)
//   data = Data (8 bytes); data.data == 41:42:43:44:45:46:47:48
// No `_ws.expert`/`_ws.malformed` anywhere in this frame (checked with --json).
//
// This independently confirms the B-TCI bit order, the I-TCI bit order
// (including bit 27), the 24-bit I-SID window, C-DA/C-SA placement, the
// 0x88E7 I-TAG ethertype, and — the sharpest test of the encapsulation
// boundary — that Wireshark's own dissector, handed nothing but our wire
// bytes, recurses cleanly through B-Tag -> I-Tag -> the encapsulated frame's
// *own* 802.1Q C-VLAN tag -> IPv4 -> opaque data. That recursion only works if
// `customer_data` starts at exactly the byte this codec says it does.
//
// Naming note (not a wire bug — the earlier README/SPEC claim that no
// external oracle exists for this module was itself the bug this task fixed;
// this note is the one substantive disagreement that check turned up).
// Wireshark's dissector calls this module's `uca` field `ieee8021ah.nca`
// ("No Customer Addresses") — the identical bit, mask 0x08 in the flag octet
// / 0x08000000 of the 32-bit I-TCI — under an opposite-sounding name. At least
// one router vendor's own docs use this module's name for the same bit
// ("PBB packets with UCA bit set are dropped", Nokia SR OS PBB configuration
// guidelines). The two industry sources disagree on what to call the bit;
// neither disagrees on its *position*. Left as `uca`: renaming on the
// strength of one of two conflicting secondary sources would trade one
// unverifiable guess for another, and the published 802.1Q-2014 text itself
// (the only source that could settle it) is paywalled and unavailable here.
const golden_wireshark_customer_vlan = [_]u8{
    0x00, 0x1b, 0x21, 0x00, 0x00, 0x01, // B-DA
    0x00, 0x1b, 0x21, 0x00, 0x00, 0x02, // B-SA
    0x88, 0xa8, 0x50, 0xc8, //             B-Tag: TPID + TCI(PCP=2,DEI=1,VID=200)
    0x88, 0xe7, //                         I-TAG EtherType
    0x90, 0x00, 0x10, 0x00, //             I-TCI: PCP=4 DEI=1 UCA/NCA=0 Res=0 I-SID=0x1000
    0x00, 0x50, 0x56, 0x00, 0x00, 0x01, // C-DA
    0x00, 0x50, 0x56, 0x00, 0x00, 0x02, // C-SA
    // customer_data: the encapsulated frame's OWN 802.1Q C-VLAN tag (VID=10),
    // its own ethertype (IPv4), a byte-exact IPv4 header (proto=253, an
    // IANA-reserved-for-experimentation value with no Wireshark sub-dissector,
    // chosen so the anchor output stays free of unrelated expert info), and 8
    // opaque payload bytes.
    0x81, 0x00, 0x00, 0x0a, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x1c, 0x00, 0x01,
    0x00, 0x00, 0x40, 0xfd, 0x65, 0xe2,
    0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
    0x00, 0x02, 0x41, 0x42, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48,
};

test "golden (Wireshark-anchored): customer frame carrying its own 802.1Q tag — builder reproduces the exact bytes" {
    const fields: Fields = .{
        .b_da = .{ 0x00, 0x1b, 0x21, 0x00, 0x00, 0x01 },
        .b_sa = .{ 0x00, 0x1b, 0x21, 0x00, 0x00, 0x02 },
        .b_tag = .{ .pcp = 2, .dei = true, .vid = 200 },
        .i_pcp = 4,
        .i_dei = true,
        .uca = false,
        .i_sid = 0x00_1000,
        .c_da = .{ 0x00, 0x50, 0x56, 0x00, 0x00, 0x01 },
        .c_sa = .{ 0x00, 0x50, 0x56, 0x00, 0x00, 0x02 },
    };
    const customer_data = golden_wireshark_customer_vlan[headerLen(true)..];
    var buf: [golden_wireshark_customer_vlan.len]u8 = undefined;
    const out = try encode(fields, customer_data, &buf);
    try testing.expectEqualSlices(u8, &golden_wireshark_customer_vlan, out);
}

test "golden (Wireshark-anchored): decode recovers every field, including the recursion boundary" {
    const dec = try decode(&golden_wireshark_customer_vlan);
    try testing.expectEqual(@as(u3, 2), dec.fields.b_tag.?.pcp);
    try testing.expect(dec.fields.b_tag.?.dei);
    try testing.expectEqual(@as(u12, 200), dec.fields.bvid().?);
    try testing.expectEqual(@as(u3, 4), dec.fields.i_pcp);
    try testing.expect(dec.fields.i_dei);
    try testing.expect(!dec.fields.uca);
    try testing.expectEqual(@as(u24, 0x00_1000), dec.fields.i_sid);
    try testing.expectEqual([6]u8{ 0x00, 0x50, 0x56, 0x00, 0x00, 0x01 }, dec.fields.c_da);
    try testing.expectEqual([6]u8{ 0x00, 0x50, 0x56, 0x00, 0x00, 0x02 }, dec.fields.c_sa);
    // The customer_data boundary Wireshark recursed on: the encapsulated
    // frame's own 802.1Q tag (VID=10) starts at byte 0 of customer_data.
    try testing.expectEqual(@as(u16, 0x8100), std.mem.readInt(u16, dec.customer_data[0..2], .big));
    try testing.expectEqual(@as(u16, 0x000a), std.mem.readInt(u16, dec.customer_data[2..4], .big));
    try testing.expectEqualSlices(u8, golden_wireshark_customer_vlan[headerLen(true)..], dec.customer_data);
}

// ── UCA/NCA naming resolution: pin that the two names conflict, not just spell
// differently ──────────────────────────────────────────────────────────────
//
// The golden above has `uca = false`, which cannot distinguish "Wireshark's
// `nca` is a same-polarity relabelling of our bit" from "Wireshark's `nca` is
// the logical inverse of our bit" — both hypotheses agree when the raw bit is
// 0. This golden is the same frame with only that one bit forced to 1, run
// through the identical `scripts/dissect.py`/sharkd pipeline, to settle it.
//
// Command:
//   scripts/dissect.py --frame raw --fields '00 1b 21 00 00 01 00 1b 21 00 00
//   02 88 a8 50 c8 88 e7 98 00 10 00 00 50 56 00 00 01 00 50 56 00 00 02 81 00
//   00 0a 08 00 45 00 00 1c 00 01 00 00 40 fd 65 e2 0a 00 00 01 0a 00 00 02 41
//   42 43 44 45 46 47 48'
//
// Wireshark printed (trimmed to the load-bearing line; every other field is
// unchanged from the bit=0 golden above and was re-checked to still hold, no
// `_ws.expert`/`_ws.malformed` anywhere):
//   ieee8021ah.nca == 1 = .... 1... .... .... .... .... .... .... = NCA: 1
//
// Result: raw bit 1 -> Wireshark's `nca` reads 1, the *same* value our `uca`
// reads for that bit — not `nca = !uca`. So "UCA" and "NCA" are not two
// spellings of one fact; they are opposite claims about the identical wire
// state (this module: bit=1 means "use customer addresses"; Wireshark's own
// embedded field-name string for that state, extracted from
// `libwireshark.so`'s string table, is literally "No Customer Addresses").
// See the naming resolution on `Fields.uca`'s doc comment for the decision
// this pins.
const golden_wireshark_uca_bit_set = blk: {
    var frame = golden_wireshark_customer_vlan;
    frame[b_mac_len + b_tag_len + 2] |= 0x08; // I-TCI flag octet: set bit 27 (UCA/NCA)
    break :blk frame;
};

test "golden (Wireshark-anchored): UCA bit forced to 1 decodes uca=true — Wireshark's nca==1 for the same raw bit, not its inverse" {
    const dec = try decode(&golden_wireshark_uca_bit_set);
    try testing.expect(dec.fields.uca); // this module: "customer addresses are used"
    // Everything else is untouched by the single flipped bit.
    try testing.expectEqual(@as(u3, 4), dec.fields.i_pcp);
    try testing.expect(dec.fields.i_dei);
    try testing.expectEqual(@as(u24, 0x00_1000), dec.fields.i_sid);

    // Round-trip: encoding fields with uca=true reproduces this exact frame.
    var fields = dec.fields;
    fields.uca = true;
    var buf: [golden_wireshark_uca_bit_set.len]u8 = undefined;
    const out = try encode(fields, dec.customer_data, &buf);
    try testing.expectEqualSlices(u8, &golden_wireshark_uca_bit_set, out);
}

/// The largest frame a PBB backbone port can be handed: a 9000-octet jumbo
/// customer frame behind the B-MACs, the optional B-TAG and the I-TAG. W2 A3
/// recorded that the harness used to cap the driven buffer at
/// `min_frame_len + b_tag_len + 64` = 92 octets, so a multi-kilobyte hostile
/// frame — the ordinary case on a provider backbone — was never decoded here at
/// all. The bound is safe by construction (the customer data is a subslice and
/// there is no length field), but the harness could not demonstrate it.
const fuzz_max_frame: usize = min_frame_len + b_tag_len + 9000;

/// Only the tag region is drawn from the fuzzer: past the I-TAG every octet is
/// opaque customer data that `decode` merely slices, so drawing nine kilobytes
/// an iteration would buy nothing and cost the fuzzer most of its throughput.
const fuzz_drawn: usize = min_frame_len + b_tag_len + 64;

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_max_frame]u8 = undefined;
    smith.bytes(buf[0..fuzz_drawn]);
    // A size class rather than one uniform draw: uniform over the whole range
    // would almost never land near `min_frame_len`, where the truncations are.
    const len: usize = switch (smith.valueRangeAtMost(u8, 0, 5)) {
        0 => smith.valueRangeAtMost(u16, 0, @intCast(fuzz_drawn)),
        1 => min_frame_len + 1500,
        2 => min_frame_len + b_tag_len + 1500,
        3 => fuzz_max_frame, // jumbo
        4 => smith.valueRangeAtMost(u16, 0, @intCast(fuzz_max_frame)),
        else => smith.valueRangeAtMost(u16, @intCast(min_frame_len), @intCast(fuzz_max_frame)),
    };
    @memset(buf[fuzz_drawn..], smith.value(u8));

    // Bias toward the deeper paths: sometimes plant a valid tag region so the
    // fuzzer reaches the I-TCI/C-DA/C-SA parsing instead of bailing early.
    if (len >= b_mac_len + 2 and smith.value(bool)) {
        const et: u16 = if (smith.value(bool)) itag_ethertype else b_tpid;
        std.mem.writeInt(u16, buf[b_mac_len..][0..2], et, .big);
        if (et == b_tpid and len >= b_mac_len + b_tag_len + 2)
            std.mem.writeInt(u16, buf[b_mac_len + b_tag_len ..][0..2], itag_ethertype, .big);
    }

    const dec = decode(buf[0..len]) catch return; // any typed error is fine
    // If it decoded, the customer slice is exactly the tail and never escapes.
    try testing.expect(len >= min_frame_len);
    const consumed = len - dec.customer_data.len;
    try testing.expect(consumed == min_frame_len or consumed == min_frame_len + b_tag_len);
    try testing.expect(@intFromPtr(dec.customer_data.ptr) >= @intFromPtr(&buf));
    try testing.expect(@intFromPtr(dec.customer_data.ptr) + dec.customer_data.len <=
        @intFromPtr(&buf) + len);
}

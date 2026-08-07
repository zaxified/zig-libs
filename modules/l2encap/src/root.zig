// SPDX-License-Identifier: MIT
//! l2encap — tenant-tagged L2-over-tunnel encapsulation for a multi-tenant
//! L2VPN fabric.
//!
//! Wraps an opaque customer Ethernet frame in a lean, versioned 8-byte header
//! that carries exactly the fabric-forwarding metadata WireGuard does not
//! already provide: a 24-bit **I-SID** (the tenant/VPN this frame belongs to),
//! a per-PE-hop **TTL** loop backstop, a **BUM** (broadcast / unknown-unicast /
//! multicast) bit, and the **ingress-PE id** that drives the split-horizon
//! decision. Because the encrypted WireGuard backbone already supplies transport
//! addressing and crypto, this encapsulation carries **no backbone MAC
//! addresses** — that is the deliberate difference from full 802.1ah PBB.
//! Standalone codec: no network, no clock, no allocation on the decode path.
//! Consumer: the S1b L2-over-WireGuard data plane. See
//! ~/CML/S1B-scada-l2vpn-venture-plan.md.
//!
//! ## Wire format
//! Every encapsulated frame is an 8-byte header followed by the opaque customer
//! frame bytes:
//!
//! ```
//!  0               1               2               3
//!  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    version    |     flags     |            I-SID (24 bits)    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      TTL      |       ingress PE id (16 bits) |   customer    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   frame ...   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! All multi-byte fields are big-endian (network byte order), matching
//! `ethfrag`/`rawsock`. Field by field:
//!
//! - **version** (byte 0): format version. `version_current` = 1. `decode`
//!   rejects any other value (`UnsupportedVersion`) rather than best-effort
//!   parsing an unknown layout — so a future v2 can change everything after the
//!   version byte and old peers fail closed instead of misreading it. (An
//!   all-zero buffer is rejected here, since 0 is not a defined version.)
//! - **flags** (byte 1): bit 0 = `bum` (1 = BUM, 0 = unicast). Bits 1..7 are
//!   reserved and MUST be zero — `decode` rejects any nonzero reserved bit
//!   (`InvalidHeader`) rather than masking it, closing a reserved-field covert
//!   channel exactly as `ethfrag` does.
//! - **I-SID** (bytes 2..5, 24-bit big-endian): the tenant service identifier.
//!   24 bits is the PBB I-TAG / VXLAN / Geneve convention — 16,777,216 tenants,
//!   far past any realistic fabric — and is the tenant-isolation key: two frames
//!   differing only in I-SID decode to two distinct tenants and never share a
//!   forwarding/MAC-learning domain.
//! - **TTL** (byte 5): decremented by one at every transit PE (`decrementTtl`).
//!   A frame received with TTL 0 is dropped. This is the data-plane loop
//!   backstop: any transient loop dies after at most `initial_ttl` PE hops,
//!   independent of the control plane.
//! - **ingress PE id** (bytes 6..7, 16-bit big-endian): the fabric-scoped id of
//!   the PE that first encapsulated this frame (its SPB-style source nickname;
//!   65,536 PEs). It is the input to the split-horizon decision — a PE that
//!   ingress-replicated a BUM frame recognizes its own id if that frame comes
//!   back and drops it (`droppedBySplitHorizon`).
//!
//! The header carries **no explicit payload-length field** — the customer frame
//! is simply "everything after byte 8". There is therefore no length value to
//! lie about at this layer (no teardrop-class length-overrun surface here);
//! carrier-level length/MTU integrity is `ethfrag`'s job, downstream.
//!
//! ## Forwarding contract (loop prevention + split-horizon)
//! This module is the codec plus the two pure per-frame decision primitives; it
//! does not forward, replicate, or learn. A transit/egress PE applies, in order:
//!
//! 1. `droppedBySplitHorizon(fields, this_pe)` — if the frame is BUM and its
//!    `ingress_pe` equals this PE's id, drop it (this PE originally replicated
//!    it; do not re-deliver/re-replicate the reflection).
//! 2. `decrementTtl(fields)` before forwarding onward — on `TtlExpired` (the
//!    incoming TTL was already 0) drop; otherwise forward the frame carrying the
//!    decremented TTL.
//!
//! What this does and does not guarantee: the ingress-PE-id + TTL fields are the
//! **necessary inputs** to loop mitigation, and TTL alone bounds any loop to a
//! finite hop count. Step 1 stops **reflection only**. It does not stop a
//! *relayed* copy: `ingress_pe` names the originator and is preserved across
//! `decrementTtl` (deliberately — that is what makes step 1 work), so a third PE
//! compares its id against the originator's, never against the relayer's. The
//! steady-state core relay that follows from that is closed in `l2forward`, by
//! classifying where the frame arrived from; see SPEC.md, "Honest scope of the
//! loop claim". Full loop-freedom of the BUM distribution tree (SPB/TRILL
//! reverse-path-forwarding-check, tree computation) is a **control-plane**
//! property built on top of these fields, not something a stateless codec can
//! assert on its own — see SPEC.md's deferred list.
//!
//! ## Composition
//! `encode` produces a plain `[]u8` (header + opaque payload). The intended
//! pipeline is **encapsulate → fragment → encrypt**: hand this output to a
//! fragmenter (the sibling `ethfrag`, whose `max_frame_len` is 65535) and the
//! fragments to `wireguard`. This module deliberately does **not** import those
//! siblings — separation of concerns; the caller chains them.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "802.1ah PBB I-SID + VXLAN/Geneve VNI + SPB (802.1aq) source-id/TTL loop mitigation, lean over-WireGuard variant",
    .deps = .{}, // std only
};

// ── constants ─────────────────────────────────────────────────────────────────

/// Encoded header size in bytes. See the module doc comment for the layout.
pub const header_len: usize = 8;

/// The only header version this build encodes and accepts. A different value on
/// the wire is rejected by `decode` (`UnsupportedVersion`).
pub const version_current: u8 = 1;

/// Suggested initial TTL an ingress PE stamps into a frame. Sized like IP's
/// default and far larger than any realistic fabric diameter; the ingress PE is
/// free to choose another value. The TTL is purely a loop backstop.
pub const default_ttl: u8 = 64;

/// Largest representable I-SID (24-bit). The `Fields.isid` field is a `u24`, so
/// this ceiling is enforced by the type — an out-of-range I-SID is unpresentable
/// rather than a runtime check.
pub const max_isid: u24 = std.math.maxInt(u24);

/// Largest total encoded frame (`header_len` + payload) this codec will
/// produce or accept. The module doc comment already names the number:
/// "hand this output to a fragmenter (the sibling `ethfrag`, whose
/// `max_frame_len` is 65535)" — that contract used to live only in prose and
/// in a test comment ("composition sanity: encode output is a plain []u8
/// ready to fragment"), never enforced in code. Using the same constant here
/// (rather than importing `ethfrag`, which this module deliberately does
/// not) keeps the separation-of-concerns the module doc comment describes
/// while finally checking the number it already asserts.
pub const max_frame_len: usize = 65535;

/// `flags` byte bit 0: set = BUM (broadcast / unknown-unicast / multicast),
/// clear = unicast.
const flag_bum: u8 = 1 << 0;

/// Every `flags` bit other than `flag_bum` is reserved and must be zero on the
/// wire; `decode` rejects a nonzero reserved bit.
const flag_reserved_mask: u8 = ~flag_bum;

// ── decoded header fields ─────────────────────────────────────────────────────

/// The fabric-forwarding metadata carried ahead of the customer frame. The
/// `version` byte is not modelled here: `encode` always stamps `version_current`
/// and `decode` only ever returns fields it has already validated as that
/// version, so a caller cannot accidentally emit a wrong version.
pub const Fields = struct {
    /// Tenant service identifier (24-bit). The tenant-isolation key.
    isid: u24,
    /// Remaining PE hops. Decremented per transit PE; 0 on receipt means drop.
    ttl: u8,
    /// True = BUM (broadcast/unknown-unicast/multicast); false = unicast.
    bum: bool,
    /// Fabric-scoped id of the PE that first encapsulated this frame.
    ingress_pe: u16,
};

fn writeHeader(f: Fields, out: *[header_len]u8) void {
    out[0] = version_current;
    out[1] = if (f.bum) flag_bum else 0;
    std.mem.writeInt(u24, out[2..5], f.isid, .big);
    out[5] = f.ttl;
    std.mem.writeInt(u16, out[6..8], f.ingress_pe, .big);
}

// ── encode (send side) ────────────────────────────────────────────────────────

pub const EncodeError = error{
    /// `out` is smaller than `encodedLen(customer_frame.len)`.
    BufferTooSmall,
    /// `encodedLen(customer_frame.len)` exceeds `max_frame_len`.
    FrameTooLarge,
};

/// Number of bytes `encode` will write for a customer frame of `payload_len`
/// bytes: the fixed header plus the payload, verbatim.
pub fn encodedLen(payload_len: usize) usize {
    return header_len + payload_len;
}

/// Encapsulates `customer_frame` (treated as opaque bytes) under `fields` into
/// the caller-supplied `out` buffer — zero allocation, the hot-path form.
/// Returns the exact filled prefix of `out` (`encodedLen(customer_frame.len)`
/// bytes). Errors if `out` is too small; never partially writes on error.
pub fn encode(fields: Fields, customer_frame: []const u8, out: []u8) EncodeError![]u8 {
    const total = header_len + customer_frame.len;
    if (total > max_frame_len) return error.FrameTooLarge;
    if (out.len < total) return error.BufferTooSmall;
    writeHeader(fields, out[0..header_len]);
    @memcpy(out[header_len..total], customer_frame);
    return out[0..total];
}

/// Allocating convenience wrapper over `encode`: returns a freshly-owned
/// `[]u8` the caller must free with the same allocator. Mirrors `ethfrag`'s
/// owned-bytes convention for callers that don't manage their own buffer.
pub fn encodeAlloc(allocator: Allocator, fields: Fields, customer_frame: []const u8) (Allocator.Error || error{FrameTooLarge})![]u8 {
    const total = header_len + customer_frame.len;
    if (total > max_frame_len) return error.FrameTooLarge;
    const buf = try allocator.alloc(u8, total);
    // Cannot fail: `buf` is exactly `encodedLen` bytes, and the size was
    // already checked against `max_frame_len` above.
    return encode(fields, customer_frame, buf) catch unreachable;
}

// ── decode (receive side) ─────────────────────────────────────────────────────

/// A decoded encapsulation. `payload` is a **subslice of the input** (not owned,
/// not copied) — `decode` allocates nothing, so it can never allocate more than
/// its input, by construction.
pub const Decoded = struct {
    fields: Fields,
    /// The opaque customer frame: every byte after the header. May be empty.
    payload: []const u8,
};

pub const DecodeError = error{
    /// Fewer than `header_len` bytes were supplied.
    Truncated,
    /// The version byte is not `version_current`.
    UnsupportedVersion,
    /// A reserved `flags` bit was set.
    InvalidHeader,
    /// `bytes.len` exceeds `max_frame_len`.
    FrameTooLarge,
};

/// Parses one encapsulated frame from untrusted tunnel bytes. Every field is
/// bounds-checked before it is read; a truncated, wrong-version, or
/// reserved-bit-dirty buffer returns a typed error and never panics, reads out
/// of bounds, loops, or allocates.
pub fn decode(bytes: []const u8) DecodeError!Decoded {
    if (bytes.len > max_frame_len) return error.FrameTooLarge;
    if (bytes.len < header_len) return error.Truncated;
    if (bytes[0] != version_current) return error.UnsupportedVersion;
    const flags = bytes[1];
    if (flags & flag_reserved_mask != 0) return error.InvalidHeader;
    return .{
        .fields = .{
            .isid = std.mem.readInt(u24, bytes[2..5], .big),
            .ttl = bytes[5],
            .bum = flags & flag_bum != 0,
            .ingress_pe = std.mem.readInt(u16, bytes[6..8], .big),
        },
        .payload = bytes[header_len..],
    };
}

// ── forwarding decision helpers (pure) ────────────────────────────────────────

pub const ForwardError = error{
    /// The frame arrived with TTL 0 — it has exhausted its hop budget and must
    /// be dropped, not forwarded.
    TtlExpired,
};

/// The per-hop TTL step a transit PE applies before forwarding a frame onward.
/// Returns `fields` with TTL decremented by one, or `TtlExpired` if the incoming
/// TTL was already 0 (drop-on-zero). Pure — no state, no clock.
pub fn decrementTtl(fields: Fields) ForwardError!Fields {
    if (fields.ttl == 0) return error.TtlExpired;
    var f = fields;
    f.ttl -= 1;
    return f;
}

/// The split-horizon test: given a decoded frame and the local PE's fabric id,
/// should this frame be dropped because *this* PE was its ingress replicator?
/// True iff the frame is BUM and its `ingress_pe` equals `this_pe`. A unicast
/// frame is never dropped by split-horizon (this returns false), and a BUM frame
/// from any other PE is accepted. Pure.
pub fn droppedBySplitHorizon(fields: Fields, this_pe: u16) bool {
    return fields.bum and fields.ingress_pe == this_pe;
}

// ── optional payload sniff (advisory only) ────────────────────────────────────

/// Minimum length of an Ethernet II header (dst+src+ethertype), mirroring
/// `rawsock.eth_hdr_len`.
pub const eth_hdr_len: usize = 14;

/// Advisory-only check that the opaque payload is at least large enough to hold
/// an Ethernet II header. `decode` does **not** call this — the customer frame is
/// carried as opaque bytes by design; a consumer that wants to reject non-frames
/// may call this itself. Never rejects on content, only on length.
pub fn looksLikeEthernet(customer_frame: []const u8) bool {
    return customer_frame.len >= eth_hdr_len;
}

// ── tests ─────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "golden: exact byte layout is pinned field-by-field" {
    // version=1, bum=1, I-SID=0x0ABBCC, TTL=64, ingress_pe=0x1234, payload="Hi".
    const fields: Fields = .{ .isid = 0x0A_BB_CC, .ttl = 64, .bum = true, .ingress_pe = 0x1234 };
    var buf: [64]u8 = undefined;
    const out = try encode(fields, "Hi", &buf);

    const golden = [_]u8{
        0x01, // version
        0x01, // flags: bum
        0x0A, 0xBB, 0xCC, // I-SID (big-endian)
        0x40, // TTL = 64
        0x12, 0x34, // ingress PE id (big-endian)
        'H', 'i', // opaque payload
    };
    try testing.expectEqualSlices(u8, &golden, out);
}

test "golden: unicast, I-SID 0, empty payload" {
    const fields: Fields = .{ .isid = 0, .ttl = 1, .bum = false, .ingress_pe = 0 };
    var buf: [header_len]u8 = undefined;
    const out = try encode(fields, "", &buf);
    const golden = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    try testing.expectEqualSlices(u8, &golden, out);
    // Round-trips to an empty payload.
    const dec = try decode(out);
    try testing.expectEqual(@as(usize, 0), dec.payload.len);
    try testing.expectEqual(fields, dec.fields);
}

test "encodedLen matches what encode writes" {
    try testing.expectEqual(header_len, encodedLen(0));
    try testing.expectEqual(header_len + 100, encodedLen(100));
}

test "encode: buffer too small is rejected, never partially writes" {
    const fields: Fields = .{ .isid = 5, .ttl = 10, .bum = false, .ingress_pe = 1 };
    var too_small: [header_len + 2]u8 = @splat(0xAA);
    try testing.expectError(error.BufferTooSmall, encode(fields, "abc", &too_small));
    // Nothing was written: still all sentinel.
    for (too_small) |b| try testing.expectEqual(@as(u8, 0xAA), b);
}

test "encode: exactly max_frame_len is accepted, one byte more is FrameTooLarge" {
    const fields: Fields = .{ .isid = 5, .ttl = 10, .bum = false, .ingress_pe = 1 };
    const at_cap_len = max_frame_len - header_len;
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
    buf[0] = version_current; // otherwise-empty valid header

    try testing.expectError(error.FrameTooLarge, decode(buf));

    const at_cap = buf[0..max_frame_len];
    const dec = try decode(at_cap);
    try testing.expectEqual(max_frame_len - header_len, dec.payload.len);
}

test "encodeAlloc equals caller-buffer encode" {
    const fields: Fields = .{ .isid = 0xABCDEF, .ttl = 200, .bum = true, .ingress_pe = 0xBEEF };
    const frame = "the quick brown frame";
    const owned = try encodeAlloc(testing.allocator, fields, frame);
    defer testing.allocator.free(owned);
    var buf: [64]u8 = undefined;
    const inline_out = try encode(fields, frame, &buf);
    try testing.expectEqualSlices(u8, inline_out, owned);
}

test "property: encode -> decode round-trips fields + payload byte-identical" {
    var prng = std.Random.DefaultPrng.init(0x1234_5678_9ABC_DEF0);
    const rand = prng.random();

    var iter: usize = 0;
    while (iter < 500) : (iter += 1) {
        // Cover the extremes explicitly plus random middles.
        const isid: u24 = switch (iter % 3) {
            0 => 0,
            1 => max_isid,
            else => rand.int(u24),
        };
        const fields: Fields = .{
            .isid = isid,
            .ttl = rand.int(u8),
            .bum = rand.boolean(),
            .ingress_pe = rand.int(u16),
        };
        const frame_len = switch (iter % 4) {
            0 => 0, // empty
            1 => 1,
            2 => rand.intRangeAtMost(usize, 2, 1600), // ~Ethernet MTU range
            else => rand.intRangeAtMost(usize, 0, 4096),
        };
        const frame = try testing.allocator.alloc(u8, frame_len);
        defer testing.allocator.free(frame);
        rand.bytes(frame);

        const wire = try encodeAlloc(testing.allocator, fields, frame);
        defer testing.allocator.free(wire);

        const dec = try decode(wire);
        try testing.expectEqual(fields, dec.fields);
        try testing.expectEqualSlices(u8, frame, dec.payload);
    }
}

test "positive control: an I-SID written little-endian disagrees with the golden" {
    // A permanent guard that the round-trip/golden tests actually pin
    // endianness: hand-build the header with the I-SID bytes reversed and prove
    // it is NOT what encode produces.
    const fields: Fields = .{ .isid = 0x0A_BB_CC, .ttl = 64, .bum = true, .ingress_pe = 0x1234 };
    var buf: [header_len]u8 = undefined;
    const correct = try encode(fields, "", &buf);

    var wrong = correct[0..header_len].*;
    // Reverse the 3 I-SID bytes (bytes 2..5): what a little-endian bug emits.
    std.mem.swap(u8, &wrong[2], &wrong[4]);
    try testing.expect(!std.mem.eql(u8, correct, &wrong));
    // And decoding the wrong-endian bytes yields a different (wrong) tenant.
    const bad = try decode(&wrong);
    try testing.expect(bad.fields.isid != fields.isid);
    try testing.expectEqual(@as(u24, 0xCC_BB_0A), bad.fields.isid);
}

test "decode: truncated at every length below header_len is rejected" {
    const full = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00 };
    var len: usize = 0;
    while (len < header_len) : (len += 1) {
        try testing.expectError(error.Truncated, decode(full[0..len]));
    }
    // Exactly header_len bytes decodes (empty payload).
    const dec = try decode(&full);
    try testing.expectEqual(@as(usize, 0), dec.payload.len);
}

test "decode: wrong version is rejected" {
    var buf = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00 };
    try testing.expectError(error.UnsupportedVersion, decode(&buf));
    buf[0] = 0x00; // all-zero version also rejected
    try testing.expectError(error.UnsupportedVersion, decode(&buf));
    buf[0] = version_current;
    _ = try decode(&buf);
}

test "decode: reserved flag bits are rejected, never masked" {
    var buf = [_]u8{ 0x01, 0x02, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00 }; // reserved bit 1 set
    try testing.expectError(error.InvalidHeader, decode(&buf));
    buf[1] = 0xFE; // every reserved bit set, bum clear
    try testing.expectError(error.InvalidHeader, decode(&buf));
    buf[1] = flag_bum; // only bum set — valid
    const dec = try decode(&buf);
    try testing.expect(dec.fields.bum);
}

test "semantics: TTL decrements and drops at zero" {
    const f: Fields = .{ .isid = 1, .ttl = 2, .bum = false, .ingress_pe = 7 };
    const f1 = try decrementTtl(f);
    try testing.expectEqual(@as(u8, 1), f1.ttl);
    const f2 = try decrementTtl(f1);
    try testing.expectEqual(@as(u8, 0), f2.ttl);
    // TTL 0 on receipt: expired, must not forward.
    try testing.expectError(error.TtlExpired, decrementTtl(f2));
    // Every other field is preserved across the decrement.
    try testing.expectEqual(f.isid, f1.isid);
    try testing.expectEqual(f.ingress_pe, f1.ingress_pe);
    try testing.expectEqual(f.bum, f1.bum);
}

test "semantics: split-horizon drops a BUM frame reflected to its own ingress PE" {
    const this_pe: u16 = 42;
    // BUM frame this PE originally replicated (ingress_pe == this_pe): drop.
    const own_bum: Fields = .{ .isid = 9, .ttl = 10, .bum = true, .ingress_pe = this_pe };
    try testing.expect(droppedBySplitHorizon(own_bum, this_pe));
    // Same BUM frame from a different ingress PE: accept.
    const other_bum: Fields = .{ .isid = 9, .ttl = 10, .bum = true, .ingress_pe = 99 };
    try testing.expect(!droppedBySplitHorizon(other_bum, this_pe));
    // A unicast frame is never dropped by split-horizon, even from this PE.
    const own_unicast: Fields = .{ .isid = 9, .ttl = 10, .bum = false, .ingress_pe = this_pe };
    try testing.expect(!droppedBySplitHorizon(own_unicast, this_pe));
}

// The negative space of the rule above, made executable. `SPEC.md`'s "Honest
// scope of the loop claim" used to name only the transient reconvergence loop as
// the residue; the dominant failure was the steady-state core relay, and the
// reason this predicate cannot see it is a property of THIS header — see the
// corrected paragraph (audit BD-12).
test "semantics: split-horizon cannot see a RELAYED copy — ingress_pe names the originator, not the last hop" {
    const pe_a: u16 = 1; // originator: ingress-replicates the BUM frame
    const pe_b: u16 = 2; // first core hop: relays it onward
    const pe_c: u16 = 3; // third PE: receives B's relayed copy

    const at_b: Fields = .{ .isid = 9, .ttl = 64, .bum = true, .ingress_pe = pe_a };
    // B accepts it (not its own id) and forwards. `decrementTtl` touches the TTL
    // and nothing else — deliberately, because rewriting `ingress_pe` per hop is
    // what would break the reflection rule the field exists for.
    try testing.expect(!droppedBySplitHorizon(at_b, pe_b));
    const at_c = try decrementTtl(at_b);
    try testing.expectEqual(pe_a, at_c.ingress_pe);
    try testing.expectEqual(@as(u8, 63), at_c.ttl);

    // The consequence: at C the predicate compares C against the ORIGINATOR, so
    // a copy that reached C only because B relayed it is indistinguishable from
    // a legitimate first delivery. This must stay FALSE — a "fix" that made it
    // true would drop every legitimate BUM delivery from the fabric.
    try testing.expect(!droppedBySplitHorizon(at_c, pe_c));
    // And the same copy handed back to A IS caught — the one case the rule owns,
    // however many hops it took to get there.
    try testing.expect(droppedBySplitHorizon(at_c, pe_a));

    // Only the TTL bounds the relay: 64 hops, not the split-horizon predicate.
    var f = at_c;
    var hops: usize = 1;
    while (decrementTtl(f)) |next| : (hops += 1) {
        try testing.expect(!droppedBySplitHorizon(next, pe_c));
        f = next;
    } else |err| try testing.expectEqual(ForwardError.TtlExpired, err);
    try testing.expectEqual(@as(usize, 64), hops);
}

test "semantics: looksLikeEthernet is a pure length check at the eth_hdr_len boundary" {
    var buf: [eth_hdr_len]u8 = @splat(0);
    // Exactly eth_hdr_len bytes: long enough to hold an Ethernet II header.
    try testing.expect(looksLikeEthernet(&buf));
    // One byte short: not long enough.
    try testing.expect(!looksLikeEthernet(buf[0 .. eth_hdr_len - 1]));
    // Well past the minimum is still fine; empty is not.
    var longer: [eth_hdr_len + 50]u8 = @splat(0);
    try testing.expect(looksLikeEthernet(&longer));
    try testing.expect(!looksLikeEthernet(&.{}));
}

test "semantics: two I-SIDs decode to distinct tenants (isolation key round-trips)" {
    const frame = "customer payload";
    const a: Fields = .{ .isid = 100, .ttl = 64, .bum = false, .ingress_pe = 1 };
    const b: Fields = .{ .isid = 200, .ttl = 64, .bum = false, .ingress_pe = 1 };
    const wa = try encodeAlloc(testing.allocator, a, frame);
    defer testing.allocator.free(wa);
    const wb = try encodeAlloc(testing.allocator, b, frame);
    defer testing.allocator.free(wb);

    const da = try decode(wa);
    const db = try decode(wb);
    try testing.expect(da.fields.isid != db.fields.isid);
    try testing.expectEqual(@as(u24, 100), da.fields.isid);
    try testing.expectEqual(@as(u24, 200), db.fields.isid);
    // Same customer bytes, different tenants — the I-SID is the only isolator.
    try testing.expectEqualSlices(u8, da.payload, db.payload);
}

test "composition sanity: encode output is a plain []u8 ready to fragment" {
    // The intended pipeline is encapsulate -> fragment -> WireGuard. This module
    // does not import the fragmenter (separation of concerns); it just proves
    // its output is a contiguous byte slice a fragmenter can chunk. `ethfrag`'s
    // max_frame_len (65535) conceptually caps encodedLen(payload); we assert the
    // shape/size relationship without importing it.
    const fields: Fields = .{ .isid = 7, .ttl = 64, .bum = false, .ingress_pe = 3 };
    const frame = "opaque customer ethernet frame bytes";
    const wire = try encodeAlloc(testing.allocator, fields, frame);
    defer testing.allocator.free(wire);
    try testing.expectEqual(encodedLen(frame.len), wire.len);
    try testing.expect(@TypeOf(wire) == []u8);
    // A downstream fragmenter would re-derive the tenant by decoding one copy.
    const dec = try decode(wire);
    try testing.expectEqualSlices(u8, frame, dec.payload);
}

// ── fuzz target ───────────────────────────────────────────────────────────────

test "fuzz: decode never panics/OOBs on hostile bytes and stays within input bounds" {
    // Fuzzing is built into the toolchain (`zig build test --fuzz`); under a
    // plain `zig build test` this runs once as a smoke test (same convention as
    // the icmp/ethfrag modules). `decode` reads straight from an untrusted
    // tunnel, so this drives arbitrary bytes — truncated, wrong-version,
    // reserved-bit-dirty, bit-flipped — and asserts only: never panics, and any
    // successful decode's payload is a subslice strictly within the input.
    try testing.fuzz({}, fuzzDecode, .{});
}

/// The largest frame this decoder can be handed on a real tunnel: a 9000-octet
/// jumbo payload behind the 8-octet header. W2 A3 recorded that the harness
/// used to cap the driven buffer at `header_len + 64` = 72 octets, because the
/// length was drawn as a `u8` — so `decode` was never fuzzed at an ordinary
/// 1500-octet Ethernet size, let alone a jumbo one. The bound is safe by
/// construction (there is no length field; the payload is a subslice), but a
/// harness that cannot reach the size cannot show it.
const fuzz_max_frame: usize = header_len + 9000;

/// Only the header region is drawn from the fuzzer. Filling nine kilobytes per
/// iteration would cost far more than it buys: past the header every octet is
/// opaque payload the decoder only ever *slices*, so what matters at size is
/// the length, not the content.
const fuzz_drawn: usize = header_len + 64;

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_max_frame]u8 = undefined;
    smith.bytes(buf[0..fuzz_drawn]);
    // A size class rather than a uniform draw: a uniform length over the whole
    // range would almost never land on the header boundary, which is where the
    // interesting truncations are, and a `u8` draw never leaves it.
    const len: usize = switch (smith.valueRangeAtMost(u8, 0, 5)) {
        0 => smith.valueRangeAtMost(u8, 0, @intCast(fuzz_drawn)),
        1 => 1500, // ordinary Ethernet MTU behind the header
        2 => header_len + 1500,
        3 => fuzz_max_frame, // jumbo
        4 => smith.valueRangeAtMost(u16, 0, @intCast(fuzz_max_frame)),
        else => smith.valueRangeAtMost(u16, header_len, @intCast(fuzz_max_frame)),
    };
    @memset(buf[fuzz_drawn..], smith.value(u8));

    // Half the time, force a valid version byte so the deeper flag/field paths
    // are reached instead of always bailing at the version check.
    if (len >= 1 and smith.value(bool)) buf[0] = version_current;

    const dec = decode(buf[0..len]) catch return; // any typed error is fine
    // If it decoded, the header must have fit and the payload is exactly the
    // remainder — never larger than, or outside, the input.
    try testing.expect(len >= header_len);
    try testing.expect(dec.payload.len == len - header_len);
    try testing.expect(dec.payload.ptr == buf[header_len..].ptr);

    // The decision helpers must also never panic on decoded-from-hostile fields.
    _ = decrementTtl(dec.fields) catch {};
    _ = droppedBySplitHorizon(dec.fields, smith.value(u16));
}

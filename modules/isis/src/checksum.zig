// SPDX-License-Identifier: MIT

//! The ISO 8473 Fletcher checksum, in the "with correction" form ISO/IEC 10589
//! §7.3.11 uses for the Link State PDU.
//!
//! ## The construction (normative text)
//! ISO 8473's algorithm is reproduced verbatim in **RFC 905 Annex B** (the ISO
//! Transport Protocol carries the identical checksum; ISO 8473 §6.11, reproduced
//! in RFC 994, states only the two verification congruences and defers the
//! generation algorithm to its own Annex C). Using RFC 905 Annex B's symbols —
//! `L` = length of the buffer, `n` = 1-based position of the **first** checksum
//! octet, `C0`/`C1` = the two accumulators, `X`/`Y` = the two checksum octets:
//!
//! - B.3.1 set up the complete PDU **with the checksum field set to zero**;
//! - B.3.2 initialise `C0` and `C1` to zero;
//! - B.3.3 for each octet `i = 1..L`: `C0 += octet`, then `C1 += C0`;
//! - B.3.4 `X = -C1 + (L-n)·C0`, `Y = C1 - (L-n+1)·C0`;
//! - B.3.5 place `X` and `Y` in octets `n` and `n+1`.
//! - B.4 verification: run B.3.2/B.3.3 over the buffer **as received** (checksum
//!   octets included); if either `C0` or `C1` is non-zero the checksum fails.
//!   "The nature of the algorithm is such that it is not necessary to compare
//!   explicitly the stored checksum bytes."
//!
//! All arithmetic is modulo 255 (B.2 a). B.2 b) additionally allows one's
//! complement, where a variable holding minus zero (255) is read as plus zero,
//! so `X`/`Y` are normalised to `1..255` rather than `0..254`: **a correctly
//! computed checksum is therefore never `0x0000`**, which is what makes the
//! all-zero field usable as a distinct "not computed" marker (RFC 3719 §7: "A
//! checksum of 0 is impossible if the checksum is computed according to the
//! rules of ISO 8473"). `compute` never returns zero, and never returns a
//! checksum with a zero octet.
//!
//! ## Where IS-IS applies it
//! ISO/IEC 10589 §7.3.11: "The checksum shall be computed over all fields in the
//! LSP which appear after the Remaining Lifetime field. This field (and those
//! appearing before it) are excluded so that the LSP may be aged by systems
//! without requiring re-computation." — see `pdu.lspChecksumRegion`, which is
//! the only place that offset is encoded.
//!
//! This module is the *primitive* only: it takes a byte range and the offset of
//! the checksum field inside it. `pdu.zig` owns the LSP-specific framing and
//! `isis-lsdb` owns the ISO §7.3.14.2 receive policy.

const std = @import("std");

/// Accumulate RFC 905 B.3.3 over `bytes`, treating the two octets at
/// `skip` (when given) as zero. Returns `.{ C0, C1 }`, each in `0..254`.
fn accumulate(bytes: []const u8, skip: ?usize) struct { u32, u32 } {
    var c0: u32 = 0;
    var c1: u32 = 0;
    for (bytes, 0..) |b, i| {
        const v: u32 = if (skip) |s| (if (i == s or i == s + 1) 0 else b) else b;
        c0 = (c0 + v) % 255;
        c1 = (c1 + c0) % 255;
    }
    return .{ c0, c1 };
}

/// RFC 905 Annex B.3 / ISO 8473 Annex C: the checksum octet pair for `bytes`,
/// where the checksum field itself occupies `bytes[csum_off]` and
/// `bytes[csum_off + 1]` (those two octets are treated as zero while computing,
/// per B.3.1). Returns the pair as a big-endian `u16` — `X` is the high octet —
/// i.e. exactly the value the LSP's Checksum field carries.
///
/// Never returns `0x0000` (see the module doc); asserts the checksum field lies
/// inside `bytes`.
pub fn compute(bytes: []const u8, csum_off: usize) u16 {
    std.debug.assert(csum_off + 1 < bytes.len);
    const c = accumulate(bytes, csum_off);
    const c0: i32 = @intCast(c[0]);
    const c1: i32 = @intCast(c[1]);

    // B.3.4 with 1-based n = csum_off + 1 and L = bytes.len, so (L - n) is
    // (bytes.len - csum_off - 1).
    const span: i32 = @intCast(bytes.len - csum_off - 1);
    var x: i32 = @mod(span * c0 - c1, 255);
    // B.2 b): 0 and 255 are the same residue; pick 255 so no checksum octet is
    // ever zero (RFC 3719 §7 — a zero checksum must stay distinguishable).
    if (x == 0) x = 255;
    // Y ≡ C1 - (L-n+1)·C0 ≡ -C0 - X (mod 255); 510 keeps the subtraction
    // positive for every C0 ≤ 254 and X ≤ 255.
    var y: i32 = 510 - c0 - x;
    if (y > 255) y -= 255;

    return (@as(u16, @intCast(x)) << 8) | @as(u16, @intCast(y));
}

/// RFC 905 Annex B.4 / ISO 8473 §6.11: verify a buffer **as received**, checksum
/// octets included. True iff both accumulators end at zero. Note this is a
/// property of the whole range, so the caller does not say where the checksum
/// field is — and a buffer whose checksum field is all-zero can still satisfy
/// it (an all-zero PDU does), which is why the LSP layer checks the
/// "not computed" convention separately (see `pdu.checkLspChecksum`).
pub fn verify(bytes: []const u8) bool {
    const c = accumulate(bytes, null);
    return c[0] == 0 and c[1] == 0;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

// ── External KAT: Wireshark 4.6.4's own Fletcher implementation ──────────────
//
// These are the LSP bytes frozen in `modules/isis-lsdb/src/goldens.zig` (Golden
// 1), reproduced here because `isis` must not depend on its consumer. Their
// provenance is recorded there in full: they were dissected with `sharkd` via
// `scripts/dissect.py`, `frame.protocols == "eth:llc:osi:isis:isis.lsp"` (the
// real IS-IS dissector, not a `data` fallback), and Wireshark graded the
// checksum field itself:
//
//   isis.lsp.checksum == 0xaee7 = Checksum: 0xaee7 [correct]
//   isis.lsp.checksum.status == "Good" = Checksum Status: Good
//
// and, with the same bytes carrying the placeholder 0x1111 instead:
//
//   isis.lsp.checksum == 0x1111 = Checksum: 0x1111 incorrect, should be 0xaee7
//   isis.lsp.checksum.status == "Bad" = Checksum Status: Bad
//
// So 0xaee7 is a value an *independent* implementation computed over these
// octets — the KAT this primitive is anchored on, not our own arithmetic.
const wireshark_lsp = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x14, 0x01, 0x00, 0x03,
    0x00, 0x1b, 0x03, 0x84, 0xaa, 0xbb, 0xcc, 0xdd,
    0xee, 0xff, 0x07, 0x03, 0x80, 0x00, 0x00, 0x07,
    0xae, 0xe7, 0xd7,
};
/// ISO 10589 §7.3.11's region: everything after the Remaining Lifetime field.
const ws_region = wireshark_lsp[12..];
/// The Checksum field at PDU offset 24, i.e. offset 12 inside that region.
const ws_csum_off = 12;

test "KAT (Wireshark-graded): compute reproduces 0xaee7 over the ISO §7.3.11 region" {
    try testing.expectEqual(@as(u16, 0xaee7), compute(ws_region, ws_csum_off));
}

test "KAT (Wireshark-graded): verify accepts the graded-Good bytes and rejects the graded-Bad ones" {
    try testing.expect(verify(ws_region));

    // The same octets with Wireshark's graded-"Bad" 0x1111 placeholder.
    var bad = wireshark_lsp;
    bad[24] = 0x11;
    bad[25] = 0x11;
    try testing.expect(!verify(bad[12..]));

    // Every single-octet corruption of the covered region is caught. (±1 rather
    // than a random delta on purpose: modulo-255 arithmetic cannot see a
    // 0xFF↔0x00 substitution, the algorithm's one documented blind spot, and
    // 0xff is one of the octets below.) This pins that the region and the offset
    // are the ones the checksum was computed over — a wrong region would leave
    // the out-of-region octets undetected.
    for (12..wireshark_lsp.len) |i| {
        var m = wireshark_lsp;
        m[i] ^= 0x01;
        try testing.expect(!verify(m[12..]));
    }
}

test "B.3 and B.4 agree: a computed checksum always verifies" {
    var buf: [64]u8 = undefined;
    var seed: u32 = 0x1234_5678;
    for (0..256) |_| {
        for (&buf) |*b| {
            seed = seed *% 1664525 +% 1013904223;
            b.* = @truncate(seed >> 16);
        }
        const off = seed % (buf.len - 1);
        const c = compute(&buf, off);
        buf[off] = @intCast(c >> 8);
        buf[off + 1] = @intCast(c & 0xFF);
        try testing.expect(verify(&buf));
        // Recomputing over the now-stamped buffer is idempotent.
        try testing.expectEqual(c, compute(&buf, off));
    }
}

test "a computed checksum is never zero and has no zero octet (RFC 3719 §7)" {
    var buf: [40]u8 = undefined;
    var seed: u32 = 0xC0FFEE;
    for (0..512) |_| {
        for (&buf) |*b| {
            seed = seed *% 1103515245 +% 12345;
            b.* = @truncate(seed >> 16);
        }
        const c = compute(&buf, 8);
        try testing.expect(c != 0);
        try testing.expect(c >> 8 != 0);
        try testing.expect(c & 0xFF != 0);
    }
    // The all-zero buffer is the degenerate case the correction formula must
    // still not answer with 0x0000.
    @memset(&buf, 0);
    try testing.expectEqual(@as(u16, 0xFFFF), compute(&buf, 8));
    buf[8] = 0xFF;
    buf[9] = 0xFF;
    try testing.expect(verify(&buf));
}

test "the offset is load-bearing: computing at the wrong offset does not verify" {
    var buf: [32]u8 = .{0x5A} ** 32;
    const c = compute(&buf, 10);
    buf[10] = @intCast(c >> 8);
    buf[11] = @intCast(c & 0xFF);
    try testing.expect(verify(&buf));
    // Same bytes, checksum placed two octets over → the congruence fails.
    var other: [32]u8 = .{0x5A} ** 32;
    other[12] = @intCast(c >> 8);
    other[13] = @intCast(c & 0xFF);
    try testing.expect(!verify(&other));
}

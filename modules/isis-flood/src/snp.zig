// SPDX-License-Identifier: MIT

//! CSNP / PSNP generation for the flooding scheduler (ISO/IEC 10589 §7.3.15):
//! turn a set of LSP-Entries into one or more Sequence-Numbers PDUs, chunked to a
//! per-PDU entry cap, and — for a CSNP — tiled into contiguous `[start, end]`
//! LSP-ID ranges that cover the summarised space with no gap and no overlap.
//!
//! Pure and leaf: every PDU is built into a caller-supplied scratch buffer with
//! the sibling `isis` builders; no allocation, no I/O, no clock. The scheduler
//! (`scheduler.zig`) owns the *when* and the *which*; this file owns only the
//! *how to serialise* and the range math.
//!
//! ## One TLV per PDU, or packed to an MTU
//! An 8-bit TLV length caps one LSP-Entries (#9) TLV at 255 octets = 15
//! sixteen-octet entries, so `max_entries_per_pdu` is 15 and the scheduler's
//! default is one #9 TLV per PDU. A builder given more entries than that splits
//! them over several #9 TLVs of at most 15 each, and `entriesFitting` says how
//! many entries fill a PDU of a given size, which is how the scheduler packs an
//! MTU (`Config.snp_pdu_len`: FRR packs to the LSP buffer size the same way).
//! The receive side walks every #9 TLV, so nothing changes there.

const std = @import("std");
const isis = @import("isis");

/// An 8-octet LSP-ID: system-id (6) + pseudonode (1) + LSP-number (1).
pub const LspId = [8]u8;

/// The 16-octet SNP summary record (lifetime, LSP-ID, sequence, checksum), as
/// modeled by the `isis` codec — reused verbatim so encode/decode round-trip.
pub const LspEntry = isis.tlvs.LspEntry;

/// The inclusive bottom and top of the LSP-ID space — the range a full-DB CSNP
/// series spans (`[00…00, FF…FF]`).
pub const min_lsp_id: LspId = @splat(0x00);
pub const max_lsp_id: LspId = @splat(0xFF);

/// The entry cap of ONE #9 TLV: `floor(255 / 16)`. The scheduler's default
/// per-PDU count; a builder splits more entries over several TLVs.
pub const max_entries_per_pdu: usize = 15;

pub const BuildError = error{
    /// The scratch slice cannot hold the built PDU.
    BufferTooSmall,
    /// A key's Authentication TLV does not fit its TLV (a secret over 254 octets).
    ValueTooLong,
};

/// The big-endian +1 successor of an 8-octet LSP-ID, saturating at all-ones. Used
/// to make one CSNP's range start exactly one past the previous CSNP's last
/// LSP-ID, so a chunked series tiles the space with no gap and no overlap.
pub fn successor(id: LspId) LspId {
    var out = id;
    var i: usize = out.len;
    while (i > 0) {
        i -= 1;
        if (out[i] == 0xFF) {
            out[i] = 0;
        } else {
            out[i] += 1;
            return out;
        }
    }
    return max_lsp_id; // successor(FF…FF) saturates
}

/// The big-endian midpoint `a + (b - a) / 2` of two LSP-IDs, for narrowing a
/// CSNP window that holds more entries than one summary buffer can enumerate
/// (see `scheduler.emitCsnp`). The result is always in `[min, max)` when the two
/// differ, and equal to them when they are equal, so repeated halving strictly
/// shrinks the window and terminates. Total: the operands are ordered here, so a
/// swapped call is well-defined rather than an underflow.
pub fn midpoint(a: LspId, b: LspId) LspId {
    const x = std.mem.readInt(u64, &a, .big);
    const y = std.mem.readInt(u64, &b, .big);
    const lo = @min(x, y);
    const hi = @max(x, y);
    var out: LspId = undefined;
    std.mem.writeInt(u64, &out, lo + (hi - lo) / 2, .big);
    return out;
}

fn lessThanEntry(_: void, a: LspEntry, b: LspEntry) bool {
    return std.mem.order(u8, &a.lsp_id, &b.lsp_id) == .lt;
}

/// Sort LSP-Entries ascending by LSP-ID in place. CSNP range tiling requires
/// order; PSNP output is sorted too so the wire bytes are canonical (and thus a
/// deterministic function of the database state).
pub fn sortEntries(entries: []LspEntry) void {
    std.mem.sort(LspEntry, entries, {}, lessThanEntry);
}

/// Build one PSNP carrying `entries` (an ack or a request set) into `scratch`.
/// More than `max_entries_per_pdu` entries go into several #9 TLVs. Unsigned; see `buildPsnpSigned`.
pub fn buildPsnp(scratch: []u8, source_id: [7]u8, is_l2: bool, entries: []const LspEntry) BuildError![]const u8 {
    return buildPsnpSigned(scratch, source_id, is_l2, entries, null);
}

/// `buildPsnp` that, given a `key`, puts an Authentication TLV (#10) first and
/// signs the finished PDU (RFC 5304 §2 / RFC 5310 §3: a sender whose circuit
/// is authenticated signs every IS-IS PDU, SNPs included). `null` = the
/// unsigned PDU `buildPsnp` makes, byte for byte.
pub fn buildPsnpSigned(scratch: []u8, source_id: [7]u8, is_l2: bool, entries: []const LspEntry, key: ?isis.auth.Key) BuildError![]const u8 {
    var b = isis.pdu.PsnpBuilder.init(scratch, .{ .source_id = source_id, .is_l2 = is_l2 }) catch return error.BufferTooSmall;
    if (key) |k| isis.auth.addPlaceholder(&b.tlvs, k) catch |e| return mapBuildError(e);
    addEntriesPacked(&b.tlvs, entries, true) catch |e| return mapBuildError(e);
    return signed(scratch, b.finish(), key);
}

/// Appends `entries` as #9 TLVs of at most `max_entries_per_pdu` entries each.
/// No entries: one empty #9 TLV when `allow_empty` (a PSNP's shape), none otherwise.
fn addEntriesPacked(tlvs: anytype, entries: []const LspEntry, allow_empty: bool) !void {
    if (entries.len == 0) {
        if (allow_empty) try isis.tlvs.addLspEntries(tlvs, entries);
        return;
    }
    var i: usize = 0;
    while (i < entries.len) {
        const j = @min(i + max_entries_per_pdu, entries.len);
        try isis.tlvs.addLspEntries(tlvs, entries[i..j]);
        i = j;
    }
}

pub const SnpKind = enum { csnp, psnp };

/// How many LSP-Entries fill an SNP PDU of at most `pdu_len` octets (the link's
/// MTU less its framing, e.g. 1492 on Ethernet), counting the PDU header, the
/// Authentication TLV of `key` and the 2-octet header of each #9 TLV. At least 1.
pub fn entriesFitting(pdu_len: usize, kind: SnpKind, key: ?isis.auth.Key) usize {
    var tmp: [512]u8 = undefined;
    const sid: [7]u8 = @splat(0);
    const wire = switch (kind) {
        .csnp => buildCsnpSigned(&tmp, sid, false, min_lsp_id, max_lsp_id, &.{}, key),
        .psnp => buildPsnpSigned(&tmp, sid, false, &.{}, key),
    } catch return 1;
    // An empty PSNP carries one empty #9 TLV (2 octets) that packing replaces.
    const overhead = wire.len - (if (kind == .psnp) @as(usize, 2) else 0);
    if (pdu_len < overhead + 2 + 16) return 1;
    const room = pdu_len - overhead;
    const tlv_full = 2 + max_entries_per_pdu * 16;
    const rest = room % tlv_full;
    const extra: usize = if (rest >= 2 + 16) (rest - 2) / 16 else 0;
    return @max(1, room / tlv_full * max_entries_per_pdu + extra);
}

/// Build one CSNP summarising `entries` over the inclusive range `[start, end]`
/// into `scratch`. More than `max_entries_per_pdu` entries go into several #9 TLVs; an empty
/// `entries` is legal (a CSNP asserting "nothing in this range"). Unsigned; see
/// `buildCsnpSigned`.
pub fn buildCsnp(scratch: []u8, source_id: [7]u8, is_l2: bool, start: LspId, end: LspId, entries: []const LspEntry) BuildError![]const u8 {
    return buildCsnpSigned(scratch, source_id, is_l2, start, end, entries, null);
}

/// `buildCsnp` that, given a `key`, adds and fills the Authentication TLV
/// like `buildPsnpSigned`.
pub fn buildCsnpSigned(scratch: []u8, source_id: [7]u8, is_l2: bool, start: LspId, end: LspId, entries: []const LspEntry, key: ?isis.auth.Key) BuildError![]const u8 {
    var b = isis.pdu.CsnpBuilder.init(scratch, .{
        .source_id = source_id,
        .is_l2 = is_l2,
        .start_lsp_id = start,
        .end_lsp_id = end,
    }) catch return error.BufferTooSmall;
    if (key) |k| isis.auth.addPlaceholder(&b.tlvs, k) catch |e| return mapBuildError(e);
    addEntriesPacked(&b.tlvs, entries, false) catch |e| return mapBuildError(e);
    return signed(scratch, b.finish(), key);
}

/// Fill in the digest of a finished PDU that lives at the start of `scratch`.
fn signed(scratch: []u8, wire: []const u8, key: ?isis.auth.Key) BuildError![]const u8 {
    const k = key orelse return wire;
    const out = scratch[0..wire.len];
    // The only way `sign` can fail on a PDU this file just built is a key the
    // placeholder could not describe; `addPlaceholder` already refused those.
    isis.auth.sign(out, k) catch return error.ValueTooLong;
    return out;
}

fn mapBuildError(e: anytype) BuildError {
    return switch (e) {
        error.BufferTooSmall => error.BufferTooSmall,
        error.ValueTooLong => error.ValueTooLong,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "successor increments big-endian with carry and saturates" {
    try testing.expectEqual(LspId{ 0, 0, 0, 0, 0, 0, 0, 1 }, successor(min_lsp_id));
    try testing.expectEqual(LspId{ 0, 0, 0, 0, 0, 0, 1, 0 }, successor(.{ 0, 0, 0, 0, 0, 0, 0, 0xFF }));
    try testing.expectEqual(LspId{ 0, 0, 0, 0, 0, 1, 0, 0 }, successor(.{ 0, 0, 0, 0, 0, 0, 0xFF, 0xFF }));
    try testing.expectEqual(max_lsp_id, successor(max_lsp_id)); // saturates
}

test "entriesFitting counts the header, the authentication TLV and every #9 TLV header" {
    // CSNP header 33 octets: (1492 - 33) / 242 = 6 full TLVs (90 entries) with
    // 7 octets over, too few for another entry.
    try testing.expectEqual(@as(usize, 90), entriesFitting(1492, .csnp, null));
    // PSNP header 17 octets: (1492 - 17) = 6 x 242 + 23 -> 90 + 1 entry.
    try testing.expectEqual(@as(usize, 91), entriesFitting(1492, .psnp, null));
    try testing.expectEqual(@as(usize, 15), entriesFitting(33 + 242, .csnp, null));
    // Too small for one entry still answers 1: the caller's buffer decides.
    try testing.expectEqual(@as(usize, 1), entriesFitting(10, .csnp, null));
    // An HMAC-MD5 key costs 2 + 17 octets of Authentication TLV.
    const key: isis.auth.Key = .{ .algorithm = .hmac_md5, .id = 1, .secret = "k" };
    try testing.expectEqual(@as(usize, 89), entriesFitting(1492, .csnp, key));
}

test "a builder packs more than 15 entries into several #9 TLVs and the PDU decodes whole" {
    var entries: [40]LspEntry = undefined;
    for (&entries, 0..) |*e, i| e.* = .{
        .remaining_lifetime = 900,
        .lsp_id = .{ 0, 0, 0, 0, 0, 0, 0, @intCast(i) },
        .sequence_number = 1,
        .checksum = 0x1234,
    };
    var buf: [1024]u8 = undefined;
    const wire = try buildPsnp(&buf, @splat(1), false, &entries);
    const p = try isis.Psnp.decode(wire);
    var tit = isis.tlv.TlvIterator.init(p.tlv_bytes);
    var tlvs_seen: usize = 0;
    var seen: usize = 0;
    while (try tit.next()) |t| {
        if (t.code != isis.tlvs.code.lsp_entries) continue;
        tlvs_seen += 1;
        var it = isis.tlvs.LspEntryIterator.init(t.value);
        while (try it.next()) |e| : (seen += 1) try testing.expectEqual(entries[seen].lsp_id, e.lsp_id);
    }
    try testing.expectEqual(@as(usize, 3), tlvs_seen);
    try testing.expectEqual(@as(usize, 40), seen);
}

test "midpoint halves a window and always terminates" {
    // Exact halving of the whole space.
    try testing.expectEqual(LspId{ 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, midpoint(min_lsp_id, max_lsp_id));
    // Adjacent IDs: the midpoint is the lower one, so the window shrinks.
    const a: LspId = .{ 0, 0, 0, 0, 0, 0, 0, 4 };
    const b: LspId = .{ 0, 0, 0, 0, 0, 0, 0, 5 };
    try testing.expectEqual(a, midpoint(a, b));
    // Equal endpoints are a fixed point.
    try testing.expectEqual(a, midpoint(a, a));

    // Repeated halving from the top of the space reaches `start` in <= 64 steps
    // — the termination argument `emitCsnp`'s narrowing loop relies on.
    var end = max_lsp_id;
    var steps: usize = 0;
    while (!std.mem.eql(u8, &end, &min_lsp_id)) : (steps += 1) {
        end = midpoint(min_lsp_id, end);
        try testing.expect(steps < 64);
    }
    try testing.expectEqual(@as(usize, 64), steps);
}

test "sortEntries orders by LSP-ID" {
    var e = [_]LspEntry{
        .{ .remaining_lifetime = 1, .lsp_id = .{ 0, 0, 0, 0, 0, 3, 0, 0 }, .sequence_number = 1, .checksum = 0 },
        .{ .remaining_lifetime = 1, .lsp_id = .{ 0, 0, 0, 0, 0, 1, 0, 0 }, .sequence_number = 1, .checksum = 0 },
        .{ .remaining_lifetime = 1, .lsp_id = .{ 0, 0, 0, 0, 0, 2, 0, 0 }, .sequence_number = 1, .checksum = 0 },
    };
    sortEntries(&e);
    try testing.expectEqual(@as(u8, 1), e[0].lsp_id[5]);
    try testing.expectEqual(@as(u8, 2), e[1].lsp_id[5]);
    try testing.expectEqual(@as(u8, 3), e[2].lsp_id[5]);
}

test "buildPsnp / buildCsnp round-trip through the isis codec" {
    const entries = [_]LspEntry{
        .{ .remaining_lifetime = 900, .lsp_id = .{ 0, 0, 0, 0, 0, 1, 0, 0 }, .sequence_number = 7, .checksum = 0x1234 },
    };
    var buf: [128]u8 = undefined;

    const pw = try buildPsnp(&buf, .{ 0, 0, 0, 0, 0, 2, 0 }, false, &entries);
    const ps = try isis.Psnp.decode(pw);
    var pi = isis.tlvs.LspEntryIterator.init((try isis.tlv.findFirst(ps.tlv_bytes, isis.tlvs.code.lsp_entries)).?);
    try testing.expectEqual(@as(u32, 7), (try pi.next()).?.sequence_number);

    const cw = try buildCsnp(&buf, .{ 0, 0, 0, 0, 0, 1, 0 }, false, min_lsp_id, max_lsp_id, &entries);
    const cs = try isis.Csnp.decode(cw);
    try testing.expectEqual(min_lsp_id, cs.start_lsp_id);
    try testing.expectEqual(max_lsp_id, cs.end_lsp_id);
    var ci = isis.tlvs.LspEntryIterator.init((try isis.tlv.findFirst(cs.tlv_bytes, isis.tlvs.code.lsp_entries)).?);
    try testing.expectEqual(@as(u16, 900), (try ci.next()).?.remaining_lifetime);
}

test "empty CSNP is legal and carries no LSP-Entries" {
    var buf: [64]u8 = undefined;
    const cw = try buildCsnp(&buf, .{ 0, 0, 0, 0, 0, 1, 0 }, false, min_lsp_id, max_lsp_id, &.{});
    const cs = try isis.Csnp.decode(cw);
    try testing.expectEqual(@as(?[]const u8, null), try isis.tlv.findFirst(cs.tlv_bytes, isis.tlvs.code.lsp_entries));
}

test "a too-small scratch is a typed BufferTooSmall, never a panic" {
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, buildPsnp(&tiny, @splat(0), false, &.{}));
}

// ── whole-module mutation audit ───────────────────────────────────

test "successor carries into the top octet and treats 0xFE as an ordinary value" {
    try testing.expectEqual(LspId{ 1, 0, 0, 0, 0, 0, 0, 0 }, successor(.{ 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
    try testing.expectEqual(LspId{ 0, 0, 0, 0, 0, 0, 0, 0xFF }, successor(.{ 0, 0, 0, 0, 0, 0, 0, 0xFE }));
    try testing.expectEqual(LspId{ 0, 0, 0, 0, 0, 0, 0, 0xFE }, successor(.{ 0, 0, 0, 0, 0, 0, 0, 0xFD }));
}

test "midpoint does not depend on the operand order" {
    try testing.expectEqual(midpoint(min_lsp_id, max_lsp_id), midpoint(max_lsp_id, min_lsp_id));
    const a: LspId = .{ 0, 0, 0, 0, 0, 0, 0, 4 };
    const b: LspId = .{ 0, 0, 0, 0, 0, 0, 0, 5 };
    try testing.expectEqual(a, midpoint(b, a));
    const c: LspId = .{ 0, 0, 0, 0, 0, 0, 0, 10 };
    try testing.expectEqual(LspId{ 0, 0, 0, 0, 0, 0, 0, 7 }, midpoint(a, c));
}

test "buildPsnp / buildCsnp: 16 entries take a second #9 TLV, BufferTooSmall for every shorter scratch" {
    var entries: [16]LspEntry = undefined;
    for (&entries, 0..) |*e, i| e.* = .{ .remaining_lifetime = 1, .lsp_id = .{ 0, 0, 0, 0, 0, 1, 0, @intCast(i) }, .sequence_number = 1, .checksum = 0 };
    var buf: [512]u8 = undefined;
    const sid: [7]u8 = @splat(0);
    const one_tlv = (try buildPsnp(&buf, sid, false, entries[0..15])).len;
    // 15 is one TLV's ceiling; the 16th costs a second TLV header and its 16 octets.
    try testing.expectEqual(one_tlv + 2 + 16, (try buildPsnp(&buf, sid, false, &entries)).len);
    const csnp_one = (try buildCsnp(&buf, sid, false, min_lsp_id, max_lsp_id, entries[0..15])).len;
    try testing.expectEqual(csnp_one + 2 + 16, (try buildCsnp(&buf, sid, false, min_lsp_id, max_lsp_id, &entries)).len);

    const one = entries[0..1];
    const psnp_len = (try buildPsnp(&buf, sid, false, one)).len;
    for (0..psnp_len) |n| try testing.expectError(error.BufferTooSmall, buildPsnp(buf[0..n], sid, false, one));
    const csnp_len = (try buildCsnp(&buf, sid, false, min_lsp_id, max_lsp_id, one)).len;
    for (0..csnp_len) |n| try testing.expectError(error.BufferTooSmall, buildCsnp(buf[0..n], sid, false, min_lsp_id, max_lsp_id, one));
}

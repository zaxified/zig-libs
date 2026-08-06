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
//! ## Single-TLV per PDU
//! Each emitted PDU carries exactly one LSP-Entries (#9) TLV. An 8-bit TLV length
//! caps that TLV at 255 octets = 15 sixteen-octet entries, so `max_entries_per_pdu`
//! is 15. Packing several #9 TLVs into one PDU to fill an MTU is a deferred
//! optimisation (see `../SPEC.md`); it changes nothing about the reconcile side,
//! which walks *every* #9 TLV regardless.

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

/// The hard per-PDU entry cap: `floor(255 / 16)`, one #9 TLV's worth.
pub const max_entries_per_pdu: usize = 15;

pub const BuildError = error{
    /// The scratch slice cannot hold the built PDU.
    BufferTooSmall,
    /// More entries were handed than fit one #9 TLV (caller must chunk first).
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
/// `entries.len` must be `<= max_entries_per_pdu`.
pub fn buildPsnp(scratch: []u8, source_id: [7]u8, is_l2: bool, entries: []const LspEntry) BuildError![]const u8 {
    var b = isis.pdu.PsnpBuilder.init(scratch, .{ .source_id = source_id, .is_l2 = is_l2 }) catch return error.BufferTooSmall;
    isis.tlvs.addLspEntries(&b.tlvs, entries) catch |e| return mapBuildError(e);
    return b.finish();
}

/// Build one CSNP summarising `entries` over the inclusive range `[start, end]`
/// into `scratch`. `entries.len` must be `<= max_entries_per_pdu`; an empty
/// `entries` is legal (a CSNP asserting "nothing in this range").
pub fn buildCsnp(scratch: []u8, source_id: [7]u8, is_l2: bool, start: LspId, end: LspId, entries: []const LspEntry) BuildError![]const u8 {
    var b = isis.pdu.CsnpBuilder.init(scratch, .{
        .source_id = source_id,
        .is_l2 = is_l2,
        .start_lsp_id = start,
        .end_lsp_id = end,
    }) catch return error.BufferTooSmall;
    if (entries.len > 0) isis.tlvs.addLspEntries(&b.tlvs, entries) catch |e| return mapBuildError(e);
    return b.finish();
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

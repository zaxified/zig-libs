// SPDX-License-Identifier: MIT

//! IEC 61850 **reporting** — the report control blocks (BRCB / URCB) and the
//! reports they emit through an MMS `InformationReport`.
//!
//! A report is a positional list of MMS `Data` values whose **shape is decided
//! by a bit string**: `OptFlds` says which optional header fields are present,
//! and every absent one shifts everything after it. Decoding a report without
//! reading `OptFlds` first is guaranteed to misparse; and because the values
//! themselves are just `Data`, a wrong offset does not fail — it silently
//! reports the sequence number as a measurement.
//!
//! The order, once `OptFlds` is known, is fixed:
//!
//! ```text
//! RptID, OptFlds,
//! [SqNum]        if sequence_number
//! [TimeOfEntry]  if report_time_stamp
//! [DatSet]       if data_set_name
//! [BufOvfl]      if buffer_overflow
//! [EntryID]      if entry_id
//! [ConfRev]      if conf_revision
//! [SubSeqNum, MoreSegmentsFollow] if segmentation
//! Inclusion-bitstring
//! [DataRefs]     if data_reference — one per *included* entry
//! Values                            — one per *included* entry
//! [ReasonCodes]  if reason_for_inclusion — one per *included* entry
//! ```
//!
//! The two "one per included entry" runs are counted from the **inclusion bit
//! string**, not from the data set's size, which is what makes a partial report
//! (only the members that changed) decodable at all.

const std = @import("std");
const ber = @import("ber.zig");
const mms = @import("mms.zig");
const mmsdata = @import("mmsdata.zig");

pub const Error = mms.Error || error{
    /// The report ended before a field `OptFlds` promised.
    TruncatedReport,
    /// More data-set entries than the fixed inclusion table holds.
    TooManyEntries,
    /// A field carried the wrong `Data` alternative for its position.
    BadReportField,
};

/// The maximum data-set size this decoder tracks per report.
pub const max_entries: usize = 128;

// ── bit strings ─────────────────────────────────────────────────────────────

/// `OptFlds` (IEC 61850-7-2). Ten defined bits, bit 0 reserved. Bit numbering
/// is from the **first** bit of the BIT STRING, which is bit 7 of the first
/// octet.
pub const OptFlds = struct {
    sequence_number: bool = false,
    report_time_stamp: bool = false,
    reason_for_inclusion: bool = false,
    data_set_name: bool = false,
    data_reference: bool = false,
    buffer_overflow: bool = false,
    entry_id: bool = false,
    conf_revision: bool = false,
    segmentation: bool = false,

    pub const bit_count: u8 = 10;

    pub fn parse(bs: ber.BitString) OptFlds {
        return .{
            .sequence_number = bs.bit(1),
            .report_time_stamp = bs.bit(2),
            .reason_for_inclusion = bs.bit(3),
            .data_set_name = bs.bit(4),
            .data_reference = bs.bit(5),
            .buffer_overflow = bs.bit(6),
            .entry_id = bs.bit(7),
            .conf_revision = bs.bit(8),
            .segmentation = bs.bit(9),
        };
    }

    pub fn toInt(self: OptFlds) u64 {
        var v: u64 = 0;
        // Bit 0 is reserved and always zero.
        if (self.sequence_number) v |= @as(u64, 1) << (bit_count - 1 - 1);
        if (self.report_time_stamp) v |= @as(u64, 1) << (bit_count - 1 - 2);
        if (self.reason_for_inclusion) v |= @as(u64, 1) << (bit_count - 1 - 3);
        if (self.data_set_name) v |= @as(u64, 1) << (bit_count - 1 - 4);
        if (self.data_reference) v |= @as(u64, 1) << (bit_count - 1 - 5);
        if (self.buffer_overflow) v |= @as(u64, 1) << (bit_count - 1 - 6);
        if (self.entry_id) v |= @as(u64, 1) << (bit_count - 1 - 7);
        if (self.conf_revision) v |= @as(u64, 1) << (bit_count - 1 - 8);
        if (self.segmentation) v |= @as(u64, 1) << (bit_count - 1 - 9);
        return v;
    }

    pub fn emit(self: OptFlds, w: *ber.Writer) Error!void {
        try w.bitString(mmsdata.Kind.bit_string.tag(), self.toInt(), bit_count);
    }
};

/// `TrgOps` — which conditions cause a report to be sent. Six bits, bit 0
/// reserved.
pub const TrgOps = struct {
    data_change: bool = false,
    quality_change: bool = false,
    data_update: bool = false,
    integrity: bool = false,
    general_interrogation: bool = false,

    pub const bit_count: u8 = 6;

    pub fn parse(bs: ber.BitString) TrgOps {
        return .{
            .data_change = bs.bit(1),
            .quality_change = bs.bit(2),
            .data_update = bs.bit(3),
            .integrity = bs.bit(4),
            .general_interrogation = bs.bit(5),
        };
    }

    pub fn toInt(self: TrgOps) u64 {
        var v: u64 = 0;
        if (self.data_change) v |= @as(u64, 1) << (bit_count - 1 - 1);
        if (self.quality_change) v |= @as(u64, 1) << (bit_count - 1 - 2);
        if (self.data_update) v |= @as(u64, 1) << (bit_count - 1 - 3);
        if (self.integrity) v |= @as(u64, 1) << (bit_count - 1 - 4);
        if (self.general_interrogation) v |= @as(u64, 1) << (bit_count - 1 - 5);
        return v;
    }

    pub fn emit(self: TrgOps, w: *ber.Writer) Error!void {
        try w.bitString(mmsdata.Kind.bit_string.tag(), self.toInt(), bit_count);
    }
};

/// Why one data-set member appears in this report. Same six-bit layout as
/// `TrgOps`.
pub const Reason = struct {
    data_change: bool = false,
    quality_change: bool = false,
    data_update: bool = false,
    integrity: bool = false,
    general_interrogation: bool = false,

    pub fn parse(bs: ber.BitString) Reason {
        return .{
            .data_change = bs.bit(1),
            .quality_change = bs.bit(2),
            .data_update = bs.bit(3),
            .integrity = bs.bit(4),
            .general_interrogation = bs.bit(5),
        };
    }

    pub const bit_count: u8 = 6;

    pub fn any(self: Reason) bool {
        return self.data_change or self.quality_change or self.data_update or
            self.integrity or self.general_interrogation;
    }

    pub fn toInt(self: Reason) u64 {
        var v: u64 = 0;
        if (self.data_change) v |= @as(u64, 1) << (bit_count - 1 - 1);
        if (self.quality_change) v |= @as(u64, 1) << (bit_count - 1 - 2);
        if (self.data_update) v |= @as(u64, 1) << (bit_count - 1 - 3);
        if (self.integrity) v |= @as(u64, 1) << (bit_count - 1 - 4);
        if (self.general_interrogation) v |= @as(u64, 1) << (bit_count - 1 - 5);
        return v;
    }

    pub fn emit(self: Reason, w: *ber.Writer) Error!void {
        try w.bitString(mmsdata.Kind.bit_string.tag(), self.toInt(), bit_count);
    }
};

// ── report control blocks ───────────────────────────────────────────────────

pub const RcbKind = enum { buffered, unbuffered };

/// A report control block as read from an IED — the MMS `structure` a read of
/// `LD/LLN0$RP$xxx` or `LD/LLN0$BR$xxx` returns.
///
/// The two shapes differ by more than a member. A URCB has eleven members and
/// carries `Resv` third; a BRCB has **no `Resv` at all** and instead appends
/// `PurgeBuf`, `EntryID`, `TimeOfEntry` and `ResvTms` *after* `GI`:
///
/// ```text
/// URCB: RptID RptEna Resv DatSet ConfRev OptFlds BufTm SqNum TrgOps IntgPd GI
/// BRCB: RptID RptEna      DatSet ConfRev OptFlds BufTm SqNum TrgOps IntgPd GI
///       PurgeBuf EntryID TimeOfEntry ResvTms
/// ```
///
/// Members are matched by **order**, because MMS structures carry no names, so
/// getting this wrong reads `PurgeBuf` out of `DatSet`. The layout is the one
/// `scl.default_urcb_attributes` / `scl.default_brcb_attributes` name and was
/// confirmed member by member against a live third-party IED (SPEC.md).
pub const Rcb = struct {
    kind: RcbKind,
    rpt_id: []const u8 = &.{},
    rpt_ena: bool = false,
    /// URCB only.
    resv: ?bool = null,
    /// BRCB only.
    purge_buf: ?bool = null,
    dat_set: []const u8 = &.{},
    conf_rev: u32 = 0,
    opt_flds: OptFlds = .{},
    buf_tm_ms: u32 = 0,
    sq_num: u32 = 0,
    trg_ops: TrgOps = .{},
    intg_pd_ms: u32 = 0,
    gi: bool = false,
    /// BRCB only.
    entry_id: ?[]const u8 = null,
    /// BRCB only, and only when the IED exposes the edition-2 member.
    resv_tms: ?i16 = null,

    /// Decodes the `structure` an RCB read returns.
    pub fn decode(d: mmsdata.Data, kind: RcbKind) Error!Rcb {
        var r = Rcb{ .kind = kind };
        var it = try d.members();
        r.rpt_id = try (try next(&it)).visibleString();
        r.rpt_ena = try (try next(&it)).boolean();
        if (kind == .unbuffered) r.resv = try (try next(&it)).boolean();
        r.dat_set = try (try next(&it)).visibleString();
        r.conf_rev = try (try next(&it)).unsigned(u32);
        r.opt_flds = OptFlds.parse(try (try next(&it)).bitString());
        r.buf_tm_ms = try (try next(&it)).unsigned(u32);
        r.sq_num = try (try next(&it)).unsigned(u32);
        r.trg_ops = TrgOps.parse(try (try next(&it)).bitString());
        r.intg_pd_ms = try (try next(&it)).unsigned(u32);
        r.gi = try (try next(&it)).boolean();
        // A BRCB's PurgeBuf, EntryID, TimeOfEntry and ResvTms follow, each only
        // when the IED includes it — edition 1 stops after TimeOfEntry.
        if (kind == .buffered) {
            if (try it.next()) |e| r.purge_buf = try e.boolean();
            if (try it.next()) |e| r.entry_id = e.octetString() catch null;
            _ = try it.next(); // TimeOfEntry: decoded by the caller if wanted.
            if (try it.next()) |e| r.resv_tms = e.integer(i16) catch null;
        }
        return r;
    }

    fn next(it: *mmsdata.Members) Error!mmsdata.Data {
        return (try it.next()) orelse error.TruncatedReport;
    }
};

// ── the report itself ───────────────────────────────────────────────────────

/// One included data-set member.
pub const Entry = struct {
    /// Index into the data set, taken from the inclusion bit string.
    index: usize,
    /// Present only when `OptFlds.data_reference` was set.
    reference: ?[]const u8,
    value: mmsdata.Data,
    /// Present only when `OptFlds.reason_for_inclusion` was set.
    reason: ?Reason,
};

pub const Report = struct {
    rpt_id: []const u8,
    opt_flds: OptFlds,
    sq_num: ?u32 = null,
    time_of_entry: ?mmsdata.BinaryTime = null,
    dat_set: ?[]const u8 = null,
    buf_ovfl: ?bool = null,
    entry_id: ?[]const u8 = null,
    conf_rev: ?u32 = null,
    sub_seq_num: ?u32 = null,
    more_segments_follow: ?bool = null,
    /// Which data-set members this report carries.
    inclusion: ber.BitString,
    entries: [max_entries]Entry = undefined,
    entry_count: u16 = 0,

    pub fn included(self: *const Report) []const Entry {
        return self.entries[0..self.entry_count];
    }

    /// Decodes an `InformationReport`'s access-result list into a report.
    ///
    /// `results` is consumed. Every field is read in the order `OptFlds`
    /// dictates; a field of the wrong `Data` alternative is `BadReportField`
    /// rather than a silently shifted parse.
    pub fn decode(results: *mms.AccessResultIterator) Error!Report {
        const rpt_id_d = try nextValue(results);
        const opt_d = try nextValue(results);
        const opt_flds = OptFlds.parse(try opt_d.bitString());
        var r = Report{
            .rpt_id = try rpt_id_d.visibleString(),
            .opt_flds = opt_flds,
            .inclusion = undefined,
        };
        if (opt_flds.sequence_number) r.sq_num = try (try nextValue(results)).unsigned(u32);
        if (opt_flds.report_time_stamp) r.time_of_entry = try (try nextValue(results)).binaryTime();
        if (opt_flds.data_set_name) r.dat_set = try (try nextValue(results)).visibleString();
        if (opt_flds.buffer_overflow) r.buf_ovfl = try (try nextValue(results)).boolean();
        if (opt_flds.entry_id) r.entry_id = try (try nextValue(results)).octetString();
        if (opt_flds.conf_revision) r.conf_rev = try (try nextValue(results)).unsigned(u32);
        if (opt_flds.segmentation) {
            r.sub_seq_num = try (try nextValue(results)).unsigned(u32);
            r.more_segments_follow = try (try nextValue(results)).boolean();
        }
        r.inclusion = try (try nextValue(results)).bitString();

        // How many members the inclusion bit string says are present.
        var count: usize = 0;
        var i: usize = 0;
        while (i < r.inclusion.bitCount()) : (i += 1) {
            if (r.inclusion.bit(i)) count += 1;
        }
        if (count > max_entries) return error.TooManyEntries;

        // The three runs, each `count` long, in the order the standard fixes.
        var refs: [max_entries][]const u8 = undefined;
        if (opt_flds.data_reference) {
            var k: usize = 0;
            while (k < count) : (k += 1) refs[k] = try (try nextValue(results)).visibleString();
        }
        var values: [max_entries]mmsdata.Data = undefined;
        var k: usize = 0;
        while (k < count) : (k += 1) values[k] = try nextValue(results);
        var reasons: [max_entries]Reason = undefined;
        if (opt_flds.reason_for_inclusion) {
            k = 0;
            while (k < count) : (k += 1) reasons[k] = Reason.parse(try (try nextValue(results)).bitString());
        }

        // Map each present value back to its data-set index.
        var slot: usize = 0;
        i = 0;
        while (i < r.inclusion.bitCount()) : (i += 1) {
            if (!r.inclusion.bit(i)) continue;
            r.entries[slot] = .{
                .index = i,
                .reference = if (opt_flds.data_reference) refs[slot] else null,
                .value = values[slot],
                .reason = if (opt_flds.reason_for_inclusion) reasons[slot] else null,
            };
            slot += 1;
        }
        r.entry_count = @intCast(slot);
        return r;
    }

    fn nextValue(results: *mms.AccessResultIterator) Error!mmsdata.Data {
        const ar = (try results.next()) orelse return error.TruncatedReport;
        return switch (ar) {
            .success => |d| d,
            .failure => error.BadReportField,
        };
    }
};

/// Decodes an `InformationReport` PDU body straight into a `Report`, checking
/// that it really is a report (`RPT` VMD-specific variable list) first.
pub fn decodeInformationReport(body: []const u8) Error!Report {
    var ir = try mms.decodeInformationReport(body);
    return Report.decode(&ir.results);
}

/// The conventional VMD-specific name an `InformationReport` carrying a report
/// uses.
pub const report_variable_name = "RPT";

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// An `InformationReport` captured from a real IED: the first report after a
/// general interrogation of `LLN0$Events`.
const captured_report = [_]u8{
    0xA3, 0x66, 0xA0, 0x64,
    0xA1, 0x05, 0x80, 0x03,
    'R',  'P',  'T',  0xA0,
    0x5B, 0x8A, 0x07, 'E',
    'v',  'e',  'n',  't',
    's',  '1',  0x84, 0x03,
    0x06, 0x78, 0x80, 0x86,
    0x01, 0x00, 0x8C, 0x06,
    0x01, 0xE9, 0xC1, 0x11,
    0x3C, 0xB8, 0x8A, 0x1D,
    's',  'i',  'm',  'p',
    'l',  'e',  'I',  'O',
    'G',  'e',  'n',  'e',
    'r',  'i',  'c',  'I',
    'O',  '/',  'L',  'L',
    'N',  '0',  '$',  'E',
    'v',  'e',  'n',  't',
    's',  0x86, 0x01, 0x01,
    0x84, 0x02, 0x04, 0xF0,
    0x83, 0x01, 0x00, 0x83,
    0x01, 0x00, 0x83, 0x01,
    0x00, 0x83, 0x01, 0x00,
    0x84, 0x02, 0x02, 0x04,
    0x84, 0x02, 0x02, 0x04,
    0x84, 0x02, 0x02, 0x04,
    0x84, 0x02, 0x02, 0x04,
};

/// The same publisher's fourth report, with `integrity` reasons instead of
/// general-interrogation ones and `SqNum` advanced.
const captured_report_integrity = [_]u8{
    0xA3, 0x66, 0xA0, 0x64,
    0xA1, 0x05, 0x80, 0x03,
    'R',  'P',  'T',  0xA0,
    0x5B, 0x8A, 0x07, 'E',
    'v',  'e',  'n',  't',
    's',  '1',  0x84, 0x03,
    0x06, 0x78, 0x80, 0x86,
    0x01, 0x03, 0x8C, 0x06,
    0x01, 0xE9, 0xF7, 0xC0,
    0x3C, 0xB8, 0x8A, 0x1D,
    's',  'i',  'm',  'p',
    'l',  'e',  'I',  'O',
    'G',  'e',  'n',  'e',
    'r',  'i',  'c',  'I',
    'O',  '/',  'L',  'L',
    'N',  '0',  '$',  'E',
    'v',  'e',  'n',  't',
    's',  0x86, 0x01, 0x01,
    0x84, 0x02, 0x04, 0xF0,
    0x83, 0x01, 0x00, 0x83,
    0x01, 0x00, 0x83, 0x01,
    0x00, 0x83, 0x01, 0x00,
    0x84, 0x02, 0x02, 0x08,
    0x84, 0x02, 0x02, 0x08,
    0x84, 0x02, 0x02, 0x08,
    0x84, 0x02, 0x02, 0x08,
};

test "the captured report decodes field by field" {
    const pdu = try mms.decode(&captured_report);
    const r = try decodeInformationReport(pdu.unconfirmed.body);
    try testing.expectEqualStrings("Events1", r.rpt_id);
    try testing.expect(r.opt_flds.sequence_number);
    try testing.expect(r.opt_flds.report_time_stamp);
    try testing.expect(r.opt_flds.reason_for_inclusion);
    try testing.expect(r.opt_flds.data_set_name);
    try testing.expect(r.opt_flds.conf_revision);
    try testing.expect(!r.opt_flds.data_reference);
    try testing.expect(!r.opt_flds.entry_id);
    try testing.expect(!r.opt_flds.segmentation);

    try testing.expectEqual(@as(u32, 0), r.sq_num.?);
    try testing.expectEqual(@as(u32, 0x01E9C111), r.time_of_entry.?.ms_since_midnight);
    try testing.expectEqualStrings("simpleIOGenericIO/LLN0$Events", r.dat_set.?);
    try testing.expectEqual(@as(u32, 1), r.conf_rev.?);

    // Four data-set members, all included.
    try testing.expectEqual(@as(usize, 4), r.inclusion.bitCount());
    try testing.expectEqual(@as(u16, 4), r.entry_count);
    for (r.included(), 0..) |e, i| {
        try testing.expectEqual(i, e.index);
        try testing.expectEqual(false, try e.value.boolean());
        try testing.expect(e.reason.?.general_interrogation);
        try testing.expect(!e.reason.?.integrity);
        try testing.expect(e.reference == null);
    }
}

test "the fourth captured report shows the reason changing to integrity" {
    const pdu = try mms.decode(&captured_report_integrity);
    const r = try decodeInformationReport(pdu.unconfirmed.body);
    try testing.expectEqual(@as(u32, 3), r.sq_num.?);
    for (r.included()) |e| {
        try testing.expect(e.reason.?.integrity);
        try testing.expect(!e.reason.?.general_interrogation);
    }
    // The two captured reports carry the same OptFlds and inclusion set.
    const first = try decodeInformationReport((try mms.decode(&captured_report)).unconfirmed.body);
    try testing.expectEqual(first.opt_flds, r.opt_flds);
    try testing.expectEqual(first.entry_count, r.entry_count);
}

test "the captured URCB decodes and its bit strings round trip" {
    // The URCB structure a real IED returned for `LLN0$RP$EventsRCB01`.
    const bytes = [_]u8{
        0xA2, 0x47,
        0x8A, 0x07,
        'E',  'v',
        'e',  'n',
        't',  's',
        '1',  0x83,
        0x01, 0x00,
        0x83, 0x01,
        0x00, 0x8A,
        0x1D, 's',
        'i',  'm',
        'p',  'l',
        'e',  'I',
        'O',  'G',
        'e',  'n',
        'e',  'r',
        'i',  'c',
        'I',  'O',
        '/',  'L',
        'L',  'N',
        '0',  '$',
        'E',  'v',
        'e',  'n',
        't',  's',
        0x86, 0x01,
        0x01, 0x84,
        0x03, 0x06,
        0x7A, 0x80,
        0x86, 0x01,
        0x32, 0x86,
        0x01, 0x00,
        0x84, 0x02,
        0x02, 0x0C,
        0x86, 0x02,
        0x03, 0xE8,
        0x83, 0x01,
        0x00,
    };
    const d = try mmsdata.Data.decode(&bytes);
    const rcb = try Rcb.decode(d, .unbuffered);
    try testing.expectEqualStrings("Events1", rcb.rpt_id);
    try testing.expect(!rcb.rpt_ena);
    try testing.expectEqual(false, rcb.resv.?);
    try testing.expect(rcb.purge_buf == null);
    try testing.expectEqualStrings("simpleIOGenericIO/LLN0$Events", rcb.dat_set);
    try testing.expectEqual(@as(u32, 1), rcb.conf_rev);
    try testing.expectEqual(@as(u32, 50), rcb.buf_tm_ms);
    try testing.expectEqual(@as(u32, 0), rcb.sq_num);
    try testing.expectEqual(@as(u32, 1000), rcb.intg_pd_ms);
    try testing.expect(!rcb.gi);
    // TrgOps `02 0c` = integrity + general interrogation.
    try testing.expect(rcb.trg_ops.integrity);
    try testing.expect(rcb.trg_ops.general_interrogation);
    try testing.expect(!rcb.trg_ops.data_change);
    // OptFlds `06 7a 80`.
    try testing.expect(rcb.opt_flds.sequence_number);
    try testing.expect(rcb.opt_flds.buffer_overflow);
    try testing.expect(!rcb.opt_flds.entry_id);
}

test "OptFlds and TrgOps re-encode to the captured octets" {
    var buf: [16]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const opt = OptFlds{
        .sequence_number = true,
        .report_time_stamp = true,
        .reason_for_inclusion = true,
        .data_set_name = true,
        .conf_revision = true,
    };
    try opt.emit(&w);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x84, 0x03, 0x06, 0x78, 0x80 }, w.done());

    var buf2: [16]u8 = undefined;
    var w2 = ber.Writer.init(&buf2);
    const opt2 = OptFlds{
        .sequence_number = true,
        .report_time_stamp = true,
        .reason_for_inclusion = true,
        .data_set_name = true,
        .buffer_overflow = true,
        .conf_revision = true,
    };
    try opt2.emit(&w2);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x84, 0x03, 0x06, 0x7A, 0x80 }, w2.done());

    var buf3: [16]u8 = undefined;
    var w3 = ber.Writer.init(&buf3);
    try (TrgOps{ .integrity = true, .general_interrogation = true }).emit(&w3);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x84, 0x02, 0x02, 0x0C }, w3.done());

    var buf4: [16]u8 = undefined;
    var w4 = ber.Writer.init(&buf4);
    try (TrgOps{ .data_update = true, .integrity = true, .general_interrogation = true }).emit(&w4);
    // Exactly the TrgOps the captured client wrote back to the IED.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x84, 0x02, 0x02, 0x1C }, w4.done());
}

test "OptFlds round trips through its bit string" {
    const cases = [_]OptFlds{
        .{},
        .{ .sequence_number = true },
        .{ .segmentation = true },
        .{ .entry_id = true, .conf_revision = true },
        .{
            .sequence_number = true,
            .report_time_stamp = true,
            .reason_for_inclusion = true,
            .data_set_name = true,
            .data_reference = true,
            .buffer_overflow = true,
            .entry_id = true,
            .conf_revision = true,
            .segmentation = true,
        },
    };
    for (cases) |c| {
        var buf: [16]u8 = undefined;
        var w = ber.Writer.init(&buf);
        try c.emit(&w);
        const d = try mmsdata.Data.decode(w.done());
        try testing.expectEqual(c, OptFlds.parse(try d.bitString()));
    }
}

test "a partial report maps its values back to the right data-set indices" {
    // Six data-set members; only 1, 3 and 4 changed.
    var buf: [256]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    // Written back to front: reasons, values, inclusion, header.
    var i: usize = 3;
    while (i > 0) : (i -= 1) try w.bitString(mmsdata.Kind.bit_string.tag(), 0b010000, 6);
    try mmsdata.Emit.integer(&w, 30);
    try mmsdata.Emit.integer(&w, 20);
    try mmsdata.Emit.integer(&w, 10);
    try w.bitString(mmsdata.Kind.bit_string.tag(), 0b010110, 6); // members 1, 3, 4
    try mmsdata.Emit.unsigned(&w, 7);
    try (OptFlds{ .sequence_number = true, .reason_for_inclusion = true }).emit(&w);
    try mmsdata.Emit.visibleString(&w, "RPT1");
    try mms.closeInformationReport(&w, m, .{ .variable_list = .{ .vmd_specific = report_variable_name } });

    const pdu = try mms.decode(w.done());
    const r = try decodeInformationReport(pdu.unconfirmed.body);
    try testing.expectEqualStrings("RPT1", r.rpt_id);
    try testing.expectEqual(@as(u32, 7), r.sq_num.?);
    try testing.expect(r.time_of_entry == null);
    try testing.expect(r.dat_set == null);
    try testing.expectEqual(@as(u16, 3), r.entry_count);
    try testing.expectEqual(@as(usize, 1), r.included()[0].index);
    try testing.expectEqual(@as(usize, 3), r.included()[1].index);
    try testing.expectEqual(@as(usize, 4), r.included()[2].index);
    try testing.expectEqual(@as(i32, 10), try r.included()[0].value.integer(i32));
    try testing.expectEqual(@as(i32, 20), try r.included()[1].value.integer(i32));
    try testing.expectEqual(@as(i32, 30), try r.included()[2].value.integer(i32));
    for (r.included()) |e| try testing.expect(e.reason.?.data_change);
}

test "data references are read when OptFlds asks for them" {
    var buf: [512]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    try mmsdata.Emit.integer(&w, 42);
    try mmsdata.Emit.visibleString(&w, "LD/GGIO1$ST$Ind1$stVal");
    try w.bitString(mmsdata.Kind.bit_string.tag(), 0b10, 2);
    try (OptFlds{ .data_reference = true }).emit(&w);
    try mmsdata.Emit.visibleString(&w, "RPT2");
    try mms.closeInformationReport(&w, m, .{ .variable_list = .{ .vmd_specific = report_variable_name } });

    const pdu = try mms.decode(w.done());
    const r = try decodeInformationReport(pdu.unconfirmed.body);
    try testing.expectEqual(@as(u16, 1), r.entry_count);
    try testing.expectEqualStrings("LD/GGIO1$ST$Ind1$stVal", r.included()[0].reference.?);
    try testing.expectEqual(@as(i32, 42), try r.included()[0].value.integer(i32));
    try testing.expect(r.included()[0].reason == null);
}

test "a segmented report reads its two extra fields" {
    var buf: [256]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    try mmsdata.Emit.boolean(&w, true);
    try w.bitString(mmsdata.Kind.bit_string.tag(), 0b1, 1);
    try mmsdata.Emit.boolean(&w, true); // MoreSegmentsFollow
    try mmsdata.Emit.unsigned(&w, 2); // SubSeqNum
    try (OptFlds{ .segmentation = true }).emit(&w);
    try mmsdata.Emit.visibleString(&w, "RPT3");
    try mms.closeInformationReport(&w, m, .{ .variable_list = .{ .vmd_specific = report_variable_name } });

    const pdu = try mms.decode(w.done());
    const r = try decodeInformationReport(pdu.unconfirmed.body);
    try testing.expectEqual(@as(u32, 2), r.sub_seq_num.?);
    try testing.expect(r.more_segments_follow.?);
    try testing.expectEqual(@as(u16, 1), r.entry_count);
}

test "a report that ends before OptFlds promised is refused" {
    // OptFlds says sequence-number and report-time-stamp, then nothing.
    var buf: [128]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    try (OptFlds{ .sequence_number = true, .report_time_stamp = true }).emit(&w);
    try mmsdata.Emit.visibleString(&w, "RPT4");
    try mms.closeInformationReport(&w, m, .{ .variable_list = .{ .vmd_specific = report_variable_name } });
    const pdu = try mms.decode(w.done());
    try testing.expectError(error.TruncatedReport, decodeInformationReport(pdu.unconfirmed.body));
}

test "a report field of the wrong Data alternative is refused, not shifted" {
    // SqNum sent as a visible-string.
    var buf: [128]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    try w.bitString(mmsdata.Kind.bit_string.tag(), 0, 1);
    try mmsdata.Emit.visibleString(&w, "nope");
    try (OptFlds{ .sequence_number = true }).emit(&w);
    try mmsdata.Emit.visibleString(&w, "RPT5");
    try mms.closeInformationReport(&w, m, .{ .variable_list = .{ .vmd_specific = report_variable_name } });
    const pdu = try mms.decode(w.done());
    try testing.expectError(error.WrongDataType, decodeInformationReport(pdu.unconfirmed.body));
}

test "an access-result failure inside a report is refused" {
    var buf: [128]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const m = w.mark();
    try mms.emitAccessFailure(&w, .object_access_denied);
    try (OptFlds{}).emit(&w);
    try mmsdata.Emit.visibleString(&w, "RPT6");
    try mms.closeInformationReport(&w, m, .{ .variable_list = .{ .vmd_specific = report_variable_name } });
    const pdu = try mms.decode(w.done());
    try testing.expectError(error.BadReportField, decodeInformationReport(pdu.unconfirmed.body));
}

test "an RCB structure that stops early is refused" {
    const bytes = [_]u8{ 0xA2, 0x0E, 0x8A, 0x03, 'a', 'b', 'c', 0x83, 0x01, 0x00, 0x83, 0x01, 0x00, 0x86, 0x01, 0x01 };
    const d = try mmsdata.Data.decode(&bytes);
    try testing.expectError(error.WrongDataType, Rcb.decode(d, .unbuffered));
    // And a structure with too few members entirely.
    const short = [_]u8{ 0xA2, 0x05, 0x8A, 0x03, 'a', 'b', 'c' };
    try testing.expectError(error.TruncatedReport, Rcb.decode(try mmsdata.Data.decode(&short), .unbuffered));
}

test "fuzz: report decode never panics" {
    try std.testing.fuzz({}, fuzzReport, .{});
}

fn fuzzReport(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeInformationReport(buf[0..len]) catch {};
    const d = mmsdata.Data.decode(buf[0..len]) catch return;
    d.validate() catch return;
    _ = Rcb.decode(d, .unbuffered) catch {};
    _ = Rcb.decode(d, .buffered) catch {};
}

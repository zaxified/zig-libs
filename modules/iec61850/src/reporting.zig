// SPDX-License-Identifier: MIT

//! The **server side** of IEC 61850 reporting (IEC 61850-7-2 §17): live report
//! control blocks that evaluate `TrgOps`, buffer entries, assign `EntryID`s and
//! emit the `InformationReport`s a client subscribes to.
//!
//! `report.zig` is the *client* half — it decodes a report and reads an RCB
//! structure. This file is the half that produces them, and the two are held
//! together by construction: every test here encodes with `encode` and decodes
//! the result with `report.Report.decode`, for every `OptFlds` combination.
//!
//! Three things are worth knowing before reading further.
//!
//! **`BufTm` coalesces, it does not delay.** A change opens an entry with a
//! deadline `BufTm` milliseconds out; every further change to the same data set
//! inside that window merges into the *same* entry, OR-ing the inclusion bit and
//! the reason. One report leaves, not five. `BufTm = 0` closes the entry
//! immediately, which is the "every change is its own report" behaviour.
//!
//! **A BRCB buffers when nobody is listening.** That is the whole difference
//! between the two kinds and the reason the letter B is in the name: events that
//! happen while `RptEna` is false — or while no client is associated at all —
//! are kept, and a client that re-enables the block with the `EntryID` it last
//! saw resumes from there. The buffer is **bounded** (the caller supplies the
//! storage), and when it wraps over an entry the client has not seen yet the
//! `BufOvfl` flag is raised on the next report rather than the buffer growing.
//! A URCB's buffer is purged on disable, which is the other half of the
//! definition.
//!
//! **There is no clock.** `BufTm`, `IntgPd` and a `ResvTms` reservation are
//! deadlines the caller advances by calling `tick`, exactly like the control
//! model's `sboTimeout`. Nothing here reads a real clock or owns a thread.
//!
//! Three more things this block does, all of them about *other clients*:
//!
//! - **Segmentation.** A report larger than the negotiated MMS PDU is split.
//!   Every segment repeats the header and carries `SubSeqNum` and
//!   `MoreSegmentsFollow`; the whole set shares one `SqNum`, one `EntryID` and
//!   one `TimeOfEntry`, and each segment's **inclusion bit string is its own** —
//!   full data-set width, bits set only for the members it carries. That last
//!   choice is what lets a receiver that does not reassemble still name every
//!   member correctly, and it is what a third-party client was observed doing.
//! - **Runtime `DatSet`.** A client may re-point a **disabled** block at another
//!   data set; that re-resolves it, bumps `ConfRev` and throws the buffer away.
//!   While `RptEna` is set the write is refused — the ordering rule is the whole
//!   safety property, because otherwise one client silently changes what another
//!   is subscribed to.
//! - **Reservation.** `Resv` (URCB) and `ResvTms` (BRCB) name the client that
//!   holds the block, `Owner` reports who that is, and every write from anyone
//!   else is refused. A URCB reservation dies with its association; a BRCB's
//!   outlives it by `ResvTms` seconds, which is what lets a client reconnect and
//!   still own its buffer.
//!
//! Storage is caller-owned throughout: a `Buffer` is a slice of `Entry` plus a
//! byte arena split into equal slots, one per entry. Nothing allocates.

const std = @import("std");
const ber = @import("ber.zig");
const mms = @import("mms.zig");
const mmsdata = @import("mmsdata.zig");
const report = @import("report.zig");

pub const OptFlds = report.OptFlds;
pub const TrgOps = report.TrgOps;
pub const Reason = report.Reason;
pub const RcbKind = report.RcbKind;

pub const Error = report.Error || error{
    /// The data set has more members than the inclusion bit string can address.
    TooManyMembers,
    /// One entry's captured values do not fit the buffer slot they were given.
    EntryTooLarge,
    /// `EntryID` names a resume point the buffer no longer holds.
    EntryIdNotFound,
    /// The caller gave a `Buffer` with no entries, or slots too small to be
    /// useful.
    ReportBufferTooSmall,
    /// A reconfiguration a client is not allowed to make while `RptEna` is set.
    ReportEnabled,
    /// The `DatSet` this block names does not resolve to a data set.
    UnknownDataSet,
    /// One data-set member on its own is larger than a whole report segment,
    /// so segmentation cannot make progress. Never a truncated member.
    SegmentTooSmall,
};

/// The longest `DatSet` / `RptID` a client may bind at runtime. It is
/// `acsi.max_reference_len`, restated here so this file stays dependency-free.
pub const max_reference_len: usize = 129;

/// The largest data set a control block reports on. The inclusion bit string is
/// carried in a `u64`, which is the bound — and 64 is comfortably above the
/// data-set sizes real IEDs configure.
pub const max_members: usize = 64;

/// The octet length of an `EntryID`. IEC 61850-8-1 leaves it to the server; the
/// eight-octet form is what every stack observed here uses, and it is wide
/// enough that a monotonic counter never wraps.
pub const entry_id_len: usize = 8;

// ── what causes a report ────────────────────────────────────────────────────

/// Why a member is being put into a report. The first three are per-member
/// events the application signals; the last two are whole-data-set sweeps the
/// control block itself produces.
pub const Trigger = enum {
    data_change,
    quality_change,
    data_update,
    integrity,
    general_interrogation,

    /// Whether `TrgOps` enables this trigger.
    pub fn enabledBy(self: Trigger, t: TrgOps) bool {
        return switch (self) {
            .data_change => t.data_change,
            .quality_change => t.quality_change,
            .data_update => t.data_update,
            .integrity => t.integrity,
            .general_interrogation => t.general_interrogation,
        };
    }

    pub fn toReason(self: Trigger) Reason {
        return switch (self) {
            .data_change => .{ .data_change = true },
            .quality_change => .{ .quality_change = true },
            .data_update => .{ .data_update = true },
            .integrity => .{ .integrity = true },
            .general_interrogation => .{ .general_interrogation = true },
        };
    }

    fn bit(self: Trigger) u8 {
        return @as(u8, 1) << @intCast(@intFromEnum(self));
    }
};

/// Reasons packed one byte per member — the buffer holds one of these per
/// data-set member per entry, so the compact form is what makes a sixteen-entry
/// buffer a few kilobytes instead of tens.
fn reasonFromBits(bits: u8) Reason {
    return .{
        .data_change = bits & Trigger.data_change.bit() != 0,
        .quality_change = bits & Trigger.quality_change.bit() != 0,
        .data_update = bits & Trigger.data_update.bit() != 0,
        .integrity = bits & Trigger.integrity.bit() != 0,
        .general_interrogation = bits & Trigger.general_interrogation.bit() != 0,
    };
}

// ── the value seam ──────────────────────────────────────────────────────────

/// Where a control block reads the data set it reports. The engine never owns
/// the model: it asks for the member count, for one member's current encoded
/// `Data`, and — only when `OptFlds.data_reference` is set — for the member's
/// object reference.
///
/// Keeping this a seam is what makes the whole engine testable with no server,
/// and what lets the server hand it a `Model` without the engine knowing what a
/// `Model` is.
pub const Source = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        count: *const fn (ctx: *anyopaque, data_set: usize) usize,
        value: *const fn (ctx: *anyopaque, data_set: usize, member: usize) ?[]const u8,
        reference: *const fn (ctx: *anyopaque, data_set: usize, member: usize, out: []u8) ?[]const u8,
        /// Resolves a `DatSet` reference — `LD/LLN0$Events`, exactly as it goes
        /// on the wire — to a data-set index. Optional: a vtable that leaves it
        /// null simply refuses a runtime `DatSet` re-bind, which is what this
        /// engine did before the seam existed.
        resolve: ?*const fn (ctx: *anyopaque, ds_reference: []const u8) ?usize = null,
    };

    pub fn count(self: Source, data_set: usize) usize {
        return self.vtable.count(self.ctx, data_set);
    }
    pub fn value(self: Source, data_set: usize, member: usize) ?[]const u8 {
        return self.vtable.value(self.ctx, data_set, member);
    }
    pub fn reference(self: Source, data_set: usize, member: usize, out: []u8) ?[]const u8 {
        return self.vtable.reference(self.ctx, data_set, member, out);
    }
    /// Null when this source cannot resolve names at all, which is a different
    /// answer from "no such data set".
    pub fn resolve(self: Source, ds_reference: []const u8) ??usize {
        const f = self.vtable.resolve orelse return null;
        return f(self.ctx, ds_reference);
    }
};

// ── the buffer ──────────────────────────────────────────────────────────────

/// One buffered event: everything a report needs except the header fields the
/// control block owns.
pub const Entry = struct {
    entry_id: u64 = 0,
    time_ms: u64 = 0,
    /// Bit `max_members - 1 - i` set means member `i` is included, which is the
    /// orientation `ber.bitStringContent` writes.
    inclusion: u64 = 0,
    reasons: [max_members]u8 = @splat(0),
    offsets: [max_members]u16 = @splat(0),
    lens: [max_members]u16 = @splat(0),
    /// Bytes used in this entry's slot.
    used: u16 = 0,
    /// An **open** entry is still inside its `BufTm` window and may take more
    /// members; a closed one is a report waiting to go out.
    open: bool = false,
    deadline_ms: u64 = 0,

    pub fn includes(self: *const Entry, member: usize) bool {
        if (member >= max_members) return false;
        return self.inclusion & (@as(u64, 1) << @intCast(max_members - 1 - member)) != 0;
    }

    fn include(self: *Entry, member: usize) void {
        self.inclusion |= @as(u64, 1) << @intCast(max_members - 1 - member);
    }

    /// How many members this entry carries.
    pub fn memberCount(self: *const Entry) usize {
        return @popCount(self.inclusion);
    }
};

/// A bounded ring of entries over caller-owned storage. `arena` is split into
/// `entries.len` equal slots; slot `i` belongs to `entries[i]`.
pub const Buffer = struct {
    entries: []Entry,
    arena: []u8,
    slot_len: usize,
    /// Physical index of the oldest entry.
    head: usize = 0,
    count: usize = 0,
    /// Set when an entry the reader had not yet seen was evicted. Cleared once
    /// it has been reported in a `BufOvfl` field.
    overflow: bool = false,

    pub fn init(entries: []Entry, arena: []u8) Error!Buffer {
        if (entries.len == 0) return error.ReportBufferTooSmall;
        const slot = arena.len / entries.len;
        // A slot smaller than one small `Data` value can never hold a report.
        if (slot < 8) return error.ReportBufferTooSmall;
        return .{ .entries = entries, .arena = arena, .slot_len = slot };
    }

    /// A buffer with no storage at all — legal for a control block that is never
    /// enabled, and what `Server` leaves in a block the caller did not configure.
    pub const none = Buffer{ .entries = &.{}, .arena = &.{}, .slot_len = 0 };

    pub fn clear(self: *Buffer) void {
        self.head = 0;
        self.count = 0;
        self.overflow = false;
    }

    fn physical(self: *const Buffer, logical: usize) usize {
        return (self.head + logical) % self.entries.len;
    }

    pub fn at(self: *Buffer, logical: usize) *Entry {
        return &self.entries[self.physical(logical)];
    }

    fn slotOf(self: *Buffer, logical: usize) []u8 {
        const p = self.physical(logical);
        return self.arena[p * self.slot_len ..][0..self.slot_len];
    }

    /// Appends a fresh entry, evicting the oldest when full. `keep_from` is the
    /// `EntryID` the reader still needs: evicting anything at or above it is
    /// what `BufOvfl` means.
    fn push(self: *Buffer, keep_from: u64) Error!*Entry {
        if (self.entries.len == 0) return error.ReportBufferTooSmall;
        if (self.count == self.entries.len) {
            if (self.at(0).entry_id >= keep_from) self.overflow = true;
            self.head = (self.head + 1) % self.entries.len;
            self.count -= 1;
        }
        const e = self.at(self.count);
        self.count += 1;
        e.* = .{};
        return e;
    }

    /// Drops the oldest entry (a URCB does this after every report).
    fn popOldest(self: *Buffer) void {
        if (self.count == 0) return;
        self.head = (self.head + 1) % self.entries.len;
        self.count -= 1;
    }

    /// The logical index of the still-open entry, if there is one. Only the
    /// newest entry can be open.
    fn openIndex(self: *Buffer) ?usize {
        if (self.count == 0) return null;
        return if (self.at(self.count - 1).open) self.count - 1 else null;
    }

    pub fn oldestEntryId(self: *Buffer) ?u64 {
        return if (self.count == 0) null else self.at(0).entry_id;
    }

    pub fn newestEntryId(self: *Buffer) ?u64 {
        return if (self.count == 0) null else self.at(self.count - 1).entry_id;
    }

    pub fn holds(self: *Buffer, entry_id: u64) bool {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.at(i).entry_id == entry_id) return true;
        }
        return false;
    }
};

// ── the control block ───────────────────────────────────────────────────────

/// The result of a client write to one RCB attribute.
pub const WriteOutcome = enum {
    ok,
    /// The attribute exists but the client may not write it now (`RptEna` set,
    /// or another client holds the reservation).
    denied,
    /// The value was the wrong `Data` alternative or out of range.
    invalid,
    /// No such attribute on this kind of control block.
    unknown,
};

/// A live report control block. The caller fills in the configuration fields
/// and hands over a `Buffer`; everything below `// state` is owned by the
/// engine.
pub const ControlBlock = struct {
    kind: RcbKind,
    /// The MMS domain the block lives in.
    domain: []const u8,
    /// The block's MMS item **prefix**, e.g. `LLN0$RP$EventsRCB01`. Attribute
    /// names hang off it with a `$`.
    item: []const u8,
    /// `RptID`. An empty one means "use the block's own reference", which is
    /// what the standard says a client that reads an unconfigured `RptID` gets.
    rpt_id: []const u8 = "",
    /// The data-set reference exactly as it goes on the wire,
    /// e.g. `simpleIOGenericIO/LLN0$Events`.
    dat_set: []const u8 = "",
    /// Which data set of the `Source` this block reports.
    data_set: usize = 0,
    conf_rev: u32 = 1,
    opt_flds: OptFlds = .{},
    trg_ops: TrgOps = .{},
    buf_tm_ms: u32 = 0,
    intg_pd_ms: u32 = 0,
    /// Storage for buffered entries. `Buffer.none` disables buffering entirely.
    buffer: Buffer = Buffer.none,
    /// The largest `InformationReport` this block emits, in octets. Zero means
    /// "no limit": a report that does not fit the caller's writer is a
    /// `BufferTooSmall`, which is what this engine did before segmentation
    /// existed. Set it to the **negotiated MMS PDU size** and set
    /// `OptFlds.segmentation`, and a report larger than that is split instead.
    max_pdu_len: usize = 0,
    /// Whether `Owner` is part of this block's MMS structure. Edition 2 puts it
    /// there; edition 1 does not, and a client that reads a structure it did
    /// not expect gets the fields wrong — so this is opt-in and the attribute
    /// stays readable by name either way.
    include_owner: bool = false,

    // state
    rpt_ena: bool = false,
    /// URCB only: the reservation a client takes so a second client cannot
    /// enable the block underneath it. Released when the owning association
    /// drops.
    resv: bool = false,
    /// BRCB only, edition 2: the reservation lifetime in **seconds**.
    ///
    /// - `0` — not reserved.
    /// - `> 0` — reserved for the writing client, and the reservation outlives
    ///   the association by that many seconds, which is the whole point: a
    ///   client that reconnects inside the window still owns its buffer.
    /// - `-1` — reserved until the owning client writes `0`.
    resv_tms: i16 = 0,
    /// When a timed (`ResvTms > 0`) reservation lapses. Zero means no timer is
    /// running. Advanced by `tick`, like every other deadline here.
    resv_deadline_ms: u64 = 0,
    /// Inline storage for a `DatSet` a client re-bound at runtime. Read it with
    /// `datSet()`, never directly: the block stays **movable** because nothing
    /// points into it.
    dat_set_buf: [max_reference_len]u8 = undefined,
    dat_set_len: u8 = 0,
    /// The same for `RptID`.
    rpt_id_buf: [max_reference_len]u8 = undefined,
    rpt_id_len: u8 = 0,
    /// Segmentation state: which included member the next segment starts at,
    /// and the `SubSeqNum` it carries. `seg_member == 0 and sub_seq_num == 0`
    /// is "no segmented report in flight".
    seg_member: usize = 0,
    sub_seq_num: u32 = 0,
    /// BRCB only.
    purge_buf: bool = false,
    gi: bool = false,
    sq_num: u32 = 0,
    /// Which client owns the block. `null` means unowned.
    owner: ?u32 = null,
    /// The next `EntryID` to hand out. Starts at 1 so that 0 can mean "from the
    /// beginning" in a client's resume request.
    next_entry_id: u64 = 1,
    /// The oldest `EntryID` not yet delivered.
    send_cursor: u64 = 1,
    /// When the next integrity report is due. Only meaningful while enabled.
    next_integrity_ms: u64 = 0,
    /// The creation time of the last entry **delivered** — what a `TimeOfEntry`
    /// read reports.
    last_entry_time_ms: u64 = 0,
    /// Diagnostics.
    reports_emitted: u64 = 0,
    entries_buffered: u64 = 0,
    entries_dropped: u64 = 0,

    // ── enable / disable ────────────────────────────────────────────────────

    /// A client enabled the block. A BRCB keeps whatever it buffered; a URCB
    /// starts from empty, which is the definition of unbuffered.
    pub fn enable(self: *ControlBlock, peer: u32, now_ms: u64) void {
        if (self.rpt_ena) return;
        self.rpt_ena = true;
        self.owner = peer;
        // Enabling clears a pending timed reservation: the client is back.
        self.resv_deadline_ms = 0;
        if (self.kind == .unbuffered) {
            self.buffer.clear();
            self.send_cursor = self.next_entry_id;
        }
        self.resetSegmentation();
        self.next_integrity_ms = now_ms +| self.intg_pd_ms;
    }

    pub fn disable(self: *ControlBlock) void {
        self.rpt_ena = false;
        self.gi = false;
        // A block that is *reserved* keeps its owner across a disable —
        // otherwise the reservation would name nobody and the next client
        // would walk straight in.
        if (self.reservedBy() == null) self.owner = null;
        if (self.kind == .unbuffered) self.buffer.clear();
        self.resetSegmentation();
    }

    /// The association went away. A URCB loses everything including its
    /// reservation; a BRCB keeps its buffer — that is the guarantee.
    ///
    /// This is the single-association form and it releases the block
    /// unconditionally. `associationLostBy` is the multi-client one.
    pub fn associationLost(self: *ControlBlock) void {
        self.rpt_ena = false;
        self.gi = false;
        if (self.kind == .unbuffered) {
            self.buffer.clear();
            self.resv = false;
        }
        self.owner = null;
        self.resv_deadline_ms = 0;
        self.resetSegmentation();
    }

    /// One of several associations went away. A block another client holds is
    /// left alone; the holder's own block is released **according to its
    /// reservation**:
    ///
    /// - a URCB drops `Resv` — the reservation does not outlive the association
    ///   that took it;
    /// - a BRCB with `ResvTms > 0` keeps its owner for that many seconds, so a
    ///   client that reconnects inside the window still owns its buffer;
    /// - a BRCB with `ResvTms == -1` keeps it until the client releases it;
    /// - anything else is released now.
    pub fn associationLostBy(self: *ControlBlock, peer: u32, now_ms: u64) void {
        const o = self.owner orelse return;
        if (o != peer) return;
        self.rpt_ena = false;
        self.gi = false;
        self.resetSegmentation();
        if (self.kind == .unbuffered) {
            self.buffer.clear();
            self.resv = false;
            self.owner = null;
            return;
        }
        if (self.resv_tms > 0) {
            self.resv_deadline_ms = now_ms +| (@as(u64, @intCast(self.resv_tms)) * 1000);
            return;
        }
        if (self.resv_tms < 0) return;
        self.owner = null;
    }

    /// Which client the *reservation* names, ignoring who merely enabled the
    /// block. Null when the block is not reserved.
    pub fn reservedBy(self: *const ControlBlock) ?u32 {
        return switch (self.kind) {
            .unbuffered => if (self.resv) self.owner else null,
            .buffered => if (self.resv_tms != 0) self.owner else null,
        };
    }

    /// Which client currently holds the block against every other one: the
    /// reservation if there is one, otherwise whoever enabled it. This is the
    /// predicate a second association is refused by.
    pub fn heldBy(self: *const ControlBlock) ?u32 {
        if (self.rpt_ena) return self.owner;
        return self.reservedBy();
    }

    fn resetSegmentation(self: *ControlBlock) void {
        self.seg_member = 0;
        self.sub_seq_num = 0;
    }

    /// `DatSet` as it stands: the reference a client re-bound at runtime, or the
    /// configured one. Never a pointer into the block, so the block may be
    /// moved.
    pub fn datSet(self: *const ControlBlock) []const u8 {
        return if (self.dat_set_len > 0) self.dat_set_buf[0..self.dat_set_len] else self.dat_set;
    }

    /// `RptID` as it stands. An unconfigured `RptID` reads back as the block's
    /// own reference, which is what the standard says.
    pub fn rptId(self: *const ControlBlock) []const u8 {
        if (self.rpt_id_len > 0) return self.rpt_id_buf[0..self.rpt_id_len];
        return if (self.rpt_id.len > 0) self.rpt_id else self.item;
    }

    /// Re-points the block at another data set — the server side of a client
    /// writing `DatSet`.
    ///
    /// Two rules make this safe and they are the whole of it: the block must be
    /// **disabled** (otherwise a client silently changes what another client is
    /// subscribed to), and `ConfRev` is **bumped**, which is how every other
    /// client learns its cached configuration is stale. The buffer is thrown
    /// away because its entries index members of the *old* data set.
    pub fn rebind(self: *ControlBlock, src: Source, reference: []const u8) Error!void {
        if (self.rpt_ena) return error.ReportEnabled;
        if (reference.len > max_reference_len) return error.UnknownDataSet;
        const answer = src.resolve(reference) orelse return error.UnknownDataSet;
        const idx = answer orelse return error.UnknownDataSet;
        // Writing back the value that was read is not a reconfiguration, and
        // every client stack observed here does exactly that when it sets an
        // RCB. Bumping `ConfRev` for it would tell every *other* client its
        // cached configuration had changed when nothing had.
        if (std.mem.eql(u8, reference, self.datSet())) return;
        @memcpy(self.dat_set_buf[0..reference.len], reference);
        self.dat_set_len = @intCast(reference.len);
        self.data_set = idx;
        self.conf_rev +%= 1;
        self.buffer.clear();
        self.send_cursor = self.next_entry_id;
        self.resetSegmentation();
    }

    /// Resumes delivery after the `EntryID` a client last acknowledged.
    /// `entry_id == 0` means "everything still buffered".
    pub fn resumeAfter(self: *ControlBlock, entry_id: u64) Error!void {
        if (self.kind != .buffered) return error.EntryIdNotFound;
        if (entry_id == 0) {
            self.send_cursor = self.buffer.oldestEntryId() orelse self.next_entry_id;
            return;
        }
        if (!self.buffer.holds(entry_id)) return error.EntryIdNotFound;
        self.send_cursor = entry_id + 1;
    }

    /// Throws the buffer away (`PurgeBuf`).
    pub fn purge(self: *ControlBlock) void {
        self.buffer.clear();
        self.send_cursor = self.next_entry_id;
    }

    // ── triggers ────────────────────────────────────────────────────────────

    /// The application signalled a per-member event. Returns false when the
    /// block ignored it (wrong `TrgOps`, not this data set, or a URCB with no
    /// client).
    pub fn signal(
        self: *ControlBlock,
        src: Source,
        data_set: usize,
        member: usize,
        trigger: Trigger,
        now_ms: u64,
    ) Error!bool {
        if (data_set != self.data_set) return false;
        if (!trigger.enabledBy(self.trg_ops)) return false;
        // A URCB with nobody listening drops the event on the floor; a BRCB
        // keeps it, which is why it is called buffered.
        if (!self.rpt_ena and self.kind == .unbuffered) return false;
        if (self.buffer.entries.len == 0) return false;
        const total = src.count(self.data_set);
        if (total > max_members) return error.TooManyMembers;
        if (member >= total) return false;

        const e = try self.openEntry(now_ms);
        try self.capture(src, e, member, trigger);
        if (self.buf_tm_ms == 0) e.open = false;
        return true;
    }

    /// Produces one whole-data-set report — an integrity sweep or a general
    /// interrogation. It never merges into an open entry: the standard treats
    /// it as its own report.
    pub fn sweep(self: *ControlBlock, src: Source, trigger: Trigger, now_ms: u64) Error!bool {
        if (!trigger.enabledBy(self.trg_ops)) return false;
        if (self.buffer.entries.len == 0) return false;
        const total = src.count(self.data_set);
        if (total > max_members) return error.TooManyMembers;
        if (total == 0) return false;
        // Close whatever was still coalescing so the ordering stays causal.
        if (self.buffer.openIndex()) |i| self.buffer.at(i).open = false;

        const e = try self.newEntry(now_ms);
        var i: usize = 0;
        while (i < total) : (i += 1) try self.capture(src, e, i, trigger);
        e.open = false;
        return true;
    }

    /// Advances the clock: closes an entry whose `BufTm` ran out and raises an
    /// integrity report when `IntgPd` comes due. Returns true when something
    /// became sendable.
    pub fn tick(self: *ControlBlock, src: Source, now_ms: u64) Error!bool {
        var produced = false;
        // A timed reservation lapses here, not on a thread — same rule as every
        // other deadline in this module.
        if (self.resv_deadline_ms != 0 and now_ms >= self.resv_deadline_ms) {
            self.resv_deadline_ms = 0;
            self.resv_tms = 0;
            if (!self.rpt_ena) self.owner = null;
        }
        if (self.buffer.openIndex()) |i| {
            const e = self.buffer.at(i);
            if (now_ms >= e.deadline_ms) {
                e.open = false;
                produced = true;
            }
        }
        if (self.rpt_ena and self.intg_pd_ms > 0 and self.trg_ops.integrity) {
            if (now_ms >= self.next_integrity_ms) {
                if (try self.sweep(src, .integrity, now_ms)) produced = true;
                // Re-arm from `now` rather than by accumulation, so a caller
                // that ticks coarsely does not queue a burst of catch-up
                // reports.
                self.next_integrity_ms = now_ms +| self.intg_pd_ms;
            }
        }
        return produced;
    }

    fn openEntry(self: *ControlBlock, now_ms: u64) Error!*Entry {
        if (self.buffer.openIndex()) |i| {
            const e = self.buffer.at(i);
            if (now_ms < e.deadline_ms) return e;
            e.open = false;
        }
        const e = try self.newEntry(now_ms);
        e.open = self.buf_tm_ms > 0;
        e.deadline_ms = now_ms +| self.buf_tm_ms;
        return e;
    }

    fn newEntry(self: *ControlBlock, now_ms: u64) Error!*Entry {
        if (self.buffer.count == self.buffer.entries.len and self.buffer.count > 0) {
            if (self.buffer.at(0).entry_id >= self.send_cursor) self.entries_dropped += 1;
        }
        const e = try self.buffer.push(self.send_cursor);
        e.entry_id = self.next_entry_id;
        e.time_ms = now_ms;
        self.next_entry_id += 1;
        self.entries_buffered += 1;
        if (self.send_cursor < self.buffer.oldestEntryId().?) {
            self.send_cursor = self.buffer.oldestEntryId().?;
        }
        return e;
    }

    /// Copies one member's current value into the entry's slot and ORs in the
    /// reason. Re-capturing a member inside the same `BufTm` window appends a
    /// fresh copy: the newest value is the one reported, which is what
    /// coalescing means.
    fn capture(self: *ControlBlock, src: Source, e: *Entry, member: usize, trigger: Trigger) Error!void {
        const v = src.value(self.data_set, member) orelse return;
        // The open entry is always the newest, so its slot is the last one.
        const slot = self.buffer.slotOf(self.buffer.count - 1);
        if (@as(usize, e.used) + v.len > slot.len) return error.EntryTooLarge;
        if (v.len > std.math.maxInt(u16)) return error.EntryTooLarge;
        @memcpy(slot[e.used..][0..v.len], v);
        e.offsets[member] = e.used;
        e.lens[member] = @intCast(v.len);
        e.used += @intCast(v.len);
        e.include(member);
        e.reasons[member] |= trigger.bit();
    }

    // ── emitting ────────────────────────────────────────────────────────────

    /// Whether a closed entry is waiting to be sent to the enabled client.
    pub fn pending(self: *ControlBlock) bool {
        return self.pendingIndex() != null;
    }

    fn pendingIndex(self: *ControlBlock) ?usize {
        if (!self.rpt_ena) return null;
        var i: usize = 0;
        while (i < self.buffer.count) : (i += 1) {
            const e = self.buffer.at(i);
            if (e.open) continue;
            if (e.entry_id < self.send_cursor) continue;
            return i;
        }
        return null;
    }

    /// Whether a segmented report is half-delivered. `emitNext` must be called
    /// again — the entry is not released and `SqNum` does not advance until the
    /// last segment is out.
    pub fn segmenting(self: *const ControlBlock) bool {
        return self.seg_member > 0;
    }

    /// Encodes the next pending report as a complete `InformationReport` PDU and
    /// advances the block's state. Returns false when nothing is pending.
    ///
    /// `w` is a backwards writer over the caller's buffer; the PDU it leaves is
    /// `w.done()`.
    ///
    /// **Segmentation.** When `OptFlds.segmentation` is set and `max_pdu_len` is
    /// non-zero, a report that does not fit is split: each call produces one
    /// segment carrying `SubSeqNum` (0 upwards) and `MoreSegmentsFollow`, and
    /// the whole set shares one `SqNum`, one `EntryID` and one `TimeOfEntry`.
    /// Each segment's **inclusion bit string is that segment's own** — full
    /// data-set width, bits set only for the members it carries — which is what
    /// lets a receiver map values back to members without `data-reference`, and
    /// what `report.Report.decode` already reads.
    pub fn emitNext(self: *ControlBlock, src: Source, w: *ber.Writer) Error!bool {
        return self.emitNextWithin(src, w, 0);
    }

    /// `emitNext` with the caller's own PDU limit folded in — the negotiated MMS
    /// PDU size, which the block itself has no way of knowing. The effective
    /// budget is the smaller of the two; zero on both sides means no limit.
    pub fn emitNextWithin(self: *ControlBlock, src: Source, w: *ber.Writer, limit: usize) Error!bool {
        const idx = self.pendingIndex() orelse return false;
        const e = self.buffer.at(idx);
        const slot = self.buffer.slotOf(idx);

        var included: [max_members]Included = undefined;
        var ref_bytes: [max_members * 64]u8 = undefined;
        var ref_used: usize = 0;

        const total = src.count(self.data_set);
        if (total > max_members) return error.TooManyMembers;
        var n: usize = 0;
        var i: usize = 0;
        while (i < total) : (i += 1) {
            if (!e.includes(i)) continue;
            var reference: []const u8 = "";
            if (self.opt_flds.data_reference) {
                if (ref_used + 64 <= ref_bytes.len) {
                    if (src.reference(self.data_set, i, ref_bytes[ref_used..][0..64])) |r| {
                        reference = r;
                        ref_used += r.len;
                    }
                }
            }
            included[n] = .{
                .index = i,
                .reference = reference,
                .value = slot[e.offsets[i]..][0..e.lens[i]],
                .reason = reasonFromBits(e.reasons[i]),
            };
            n += 1;
        }

        var id_bytes: [entry_id_len]u8 = undefined;
        std.mem.writeInt(u64, &id_bytes, e.entry_id, .big);

        var fields = Fields{
            .rpt_id = self.rptId(),
            .opt_flds = self.opt_flds,
            .sq_num = self.sq_num,
            .time_of_entry = binaryTimeFromMillis(e.time_ms),
            .dat_set = self.datSet(),
            .buf_ovfl = self.buffer.overflow,
            .entry_id = &id_bytes,
            .conf_rev = self.conf_rev,
        };

        const pdu_budget = blk: {
            if (self.max_pdu_len == 0) break :blk limit;
            if (limit == 0) break :blk self.max_pdu_len;
            break :blk @min(self.max_pdu_len, limit);
        };
        const segmented = self.opt_flds.segmentation and pdu_budget > 0;
        if (!segmented) {
            self.resetSegmentation();
            try encode(w, fields, total, included[0..n]);
        } else {
            if (self.seg_member >= n) self.resetSegmentation();
            const first = self.seg_member;
            const budget = @min(pdu_budget, w.buf.len);
            const start = w.start;
            var take: usize = n - first;
            fields.sub_seq_num = self.sub_seq_num;
            while (true) {
                w.start = start;
                fields.more_segments_follow = first + take < n;
                const attempt = encode(w, fields, total, included[first..][0..take]);
                const overrun = if (attempt) |_| (start - w.start) > budget else |err| switch (err) {
                    error.BufferTooSmall => true,
                    else => return err,
                };
                if (!overrun) break;
                // One member that does not fit a whole segment can never be
                // sent; say so rather than emitting a truncated value.
                if (take <= 1) {
                    w.start = start;
                    return error.SegmentTooSmall;
                }
                take -= 1;
            }
            if (fields.more_segments_follow) {
                self.seg_member = first + take;
                self.sub_seq_num +%= 1;
                self.reports_emitted += 1;
                // The entry stays put and `SqNum` stays still: the report is
                // not finished.
                return true;
            }
            self.resetSegmentation();
        }

        self.sq_num = (self.sq_num +% 1) & 0xFFFF;
        self.send_cursor = e.entry_id + 1;
        self.last_entry_time_ms = e.time_ms;
        self.buffer.overflow = false;
        self.reports_emitted += 1;
        // A URCB keeps nothing: once the report is out the entry is gone.
        if (self.kind == .unbuffered and idx == 0) self.buffer.popOldest();
        return true;
    }

    // ── the RCB as an MMS variable ──────────────────────────────────────────

    /// The attribute names of this control block, in the order IEC 61850-8-1
    /// fixes for the MMS structure — the order `report.Rcb.decode` reads.
    pub fn attributes(self: *const ControlBlock) []const []const u8 {
        return switch (self.kind) {
            .unbuffered => if (self.include_owner) &urcb_attributes_owner else &urcb_attributes,
            .buffered => if (self.include_owner) &brcb_attributes_owner else &brcb_attributes,
        };
    }

    /// Emits the whole control block as one MMS `structure`.
    pub fn emitStructure(self: *const ControlBlock, w: *ber.Writer) Error!void {
        const m = w.mark();
        const names = self.attributes();
        var i: usize = names.len;
        while (i > 0) {
            i -= 1;
            try self.emitAttribute(names[i], w);
        }
        try mmsdata.Emit.structure(w, m);
    }

    /// Emits one attribute's value.
    pub fn emitAttribute(self: *const ControlBlock, name: []const u8, w: *ber.Writer) Error!void {
        const eq = std.mem.eql;
        if (eq(u8, name, "RptID")) {
            try mmsdata.Emit.visibleString(w, self.rptId());
        } else if (eq(u8, name, "RptEna")) {
            try mmsdata.Emit.boolean(w, self.rpt_ena);
        } else if (eq(u8, name, "Resv")) {
            try mmsdata.Emit.boolean(w, self.resv);
        } else if (eq(u8, name, "DatSet")) {
            try mmsdata.Emit.visibleString(w, self.datSet());
        } else if (eq(u8, name, "ConfRev")) {
            try mmsdata.Emit.unsigned(w, self.conf_rev);
        } else if (eq(u8, name, "OptFlds")) {
            try self.opt_flds.emit(w);
        } else if (eq(u8, name, "BufTm")) {
            try mmsdata.Emit.unsigned(w, self.buf_tm_ms);
        } else if (eq(u8, name, "SqNum")) {
            try mmsdata.Emit.unsigned(w, self.sq_num);
        } else if (eq(u8, name, "TrgOps")) {
            try self.trg_ops.emit(w);
        } else if (eq(u8, name, "IntgPd")) {
            try mmsdata.Emit.unsigned(w, self.intg_pd_ms);
        } else if (eq(u8, name, "GI")) {
            try mmsdata.Emit.boolean(w, self.gi);
        } else if (eq(u8, name, "PurgeBuf")) {
            try mmsdata.Emit.boolean(w, self.purge_buf);
        } else if (eq(u8, name, "EntryID")) {
            var id: [entry_id_len]u8 = undefined;
            // The EntryID a client reads is the last one *delivered*, which is
            // the resume point it would write back.
            std.mem.writeInt(u64, &id, self.send_cursor -| 1, .big);
            try mmsdata.Emit.octetString(w, &id);
        } else if (eq(u8, name, "TimeOfEntry") or eq(u8, name, "TimeofEntry")) {
            try mmsdata.Emit.binaryTime(w, binaryTimeFromMillis(self.last_entry_time_ms));
        } else if (eq(u8, name, "ResvTms")) {
            try w.integer(mmsdata.Kind.integer.tag(), self.resv_tms);
        } else if (eq(u8, name, "Owner")) {
            // IEC 61850-7-2 leaves `Owner` an OCTET STRING and says only that it
            // identifies the client that owns the block; every stack observed
            // here puts the client's IPv4 address in it, which is exactly the
            // four big-endian octets of the caller's peer id. An **unowned**
            // block emits a zero-length string rather than four zero octets:
            // "nobody" and "0.0.0.0" are different answers.
            if (self.owner) |o| {
                var owner: [4]u8 = undefined;
                std.mem.writeInt(u32, &owner, o, .big);
                try mmsdata.Emit.octetString(w, &owner);
            } else {
                try mmsdata.Emit.octetString(w, &.{});
            }
        } else return error.BadReportField;
    }

    /// Applies a client write to one attribute. This is the single-association
    /// form: it cannot re-bind `DatSet`, because that needs a `Source` to
    /// resolve the new name against. `writeAttributeFrom` is the full one.
    pub fn writeAttribute(
        self: *ControlBlock,
        name: []const u8,
        d: mmsdata.Data,
        peer: u32,
        now_ms: u64,
    ) WriteOutcome {
        return self.writeAttributeFrom(name, d, null, peer, now_ms);
    }

    /// Applies a client write to one attribute, with the model the block reports
    /// on in hand so a `DatSet` write can be resolved.
    pub fn writeAttributeFrom(
        self: *ControlBlock,
        name: []const u8,
        d: mmsdata.Data,
        src: ?Source,
        peer: u32,
        now_ms: u64,
    ) WriteOutcome {
        const eq = std.mem.eql;
        // Whoever holds the block — by reservation, or simply by having it
        // enabled — locks every other association out of it entirely. This is
        // what `Resv` / `ResvTms` are for and it is enforced on **every**
        // attribute, not just the interesting ones.
        if (self.heldBy()) |o| {
            if (o != peer) return .denied;
        }
        if (eq(u8, name, "RptEna")) {
            const v = d.boolean() catch return .invalid;
            if (v) {
                if (self.datSet().len == 0) return .invalid;
                self.enable(peer, now_ms);
            } else self.disable();
            return .ok;
        }
        if (eq(u8, name, "GI")) {
            const v = d.boolean() catch return .invalid;
            self.gi = v;
            return .ok;
        }
        if (eq(u8, name, "Resv")) {
            if (self.kind != .unbuffered) return .unknown;
            const v = d.boolean() catch return .invalid;
            // Taking or dropping the reservation out from under a live
            // subscription is refused; the client disables first.
            if (self.rpt_ena) return .denied;
            self.resv = v;
            self.owner = if (v) peer else null;
            return .ok;
        }
        if (eq(u8, name, "ResvTms")) {
            // `ResvTms` is a **BRCB** attribute — it is what `brcb_attributes`
            // carries and what `Resv` is to a URCB.
            if (self.kind != .buffered) return .unknown;
            const v = d.integer(i16) catch return .invalid;
            if (v < -1) return .invalid;
            self.resv_tms = v;
            self.resv_deadline_ms = 0;
            if (v == 0) {
                if (!self.rpt_ena) self.owner = null;
            } else {
                self.owner = peer;
            }
            return .ok;
        }
        if (eq(u8, name, "PurgeBuf")) {
            if (self.kind != .buffered) return .unknown;
            const v = d.boolean() catch return .invalid;
            if (v) self.purge();
            return .ok;
        }
        if (eq(u8, name, "EntryID")) {
            if (self.kind != .buffered) return .unknown;
            const raw = d.octetString() catch return .invalid;
            if (raw.len > entry_id_len) return .invalid;
            var id: u64 = 0;
            for (raw) |b| id = (id << 8) | b;
            self.resumeAfter(id) catch return .invalid;
            return .ok;
        }
        // `SqNum`, `ConfRev`, `TimeOfEntry` and `Owner` are the server's to set.
        if (eq(u8, name, "SqNum") or eq(u8, name, "ConfRev") or
            eq(u8, name, "TimeOfEntry") or eq(u8, name, "TimeofEntry") or eq(u8, name, "Owner"))
        {
            return .denied;
        }
        // Everything below reconfigures the block, which a client may only do
        // while it is disabled. IEC 61850-7-2 is explicit about this and it is
        // the difference between a safe reconfiguration and a client silently
        // changing what another client is subscribed to. An attribute this
        // block does not have is still `unknown`, enabled or not.
        if (!isReconfigurable(name)) return .unknown;
        if (self.rpt_ena) return .denied;
        if (eq(u8, name, "RptID")) {
            const s = d.visibleString() catch return .invalid;
            if (s.len > max_reference_len) return .invalid;
            // Copied, never aliased: the string lives in the request buffer,
            // which the caller reuses on the next exchange.
            @memcpy(self.rpt_id_buf[0..s.len], s);
            self.rpt_id_len = @intCast(s.len);
            return .ok;
        }
        if (eq(u8, name, "DatSet")) {
            const s = d.visibleString() catch return .invalid;
            const source = src orelse return .denied;
            if (source.vtable.resolve == null) return .denied;
            self.rebind(source, s) catch |e| return switch (e) {
                // `rpt_ena` was already checked above, so this is the name.
                error.ReportEnabled => .denied,
                else => .invalid,
            };
            return .ok;
        }
        if (eq(u8, name, "OptFlds")) {
            const bs = d.bitString() catch return .invalid;
            self.opt_flds = OptFlds.parse(bs);
            return .ok;
        }
        if (eq(u8, name, "TrgOps")) {
            const bs = d.bitString() catch return .invalid;
            self.trg_ops = TrgOps.parse(bs);
            return .ok;
        }
        if (eq(u8, name, "BufTm")) {
            self.buf_tm_ms = d.unsigned(u32) catch return .invalid;
            return .ok;
        }
        if (eq(u8, name, "IntgPd")) {
            self.intg_pd_ms = d.unsigned(u32) catch return .invalid;
            return .ok;
        }
        return .unknown;
    }
};

fn isReconfigurable(name: []const u8) bool {
    const names = [_][]const u8{ "RptID", "DatSet", "OptFlds", "TrgOps", "BufTm", "IntgPd" };
    for (names) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

/// The eleven attributes of a URCB, in MMS structure order.
pub const urcb_attributes = [_][]const u8{
    "RptID", "RptEna", "Resv",   "DatSet", "ConfRev", "OptFlds",
    "BufTm", "SqNum",  "TrgOps", "IntgPd", "GI",
};

/// The fourteen attributes of a BRCB, in MMS structure order. A BRCB has **no**
/// `Resv`; `PurgeBuf` comes after `GI`, not in `Resv`'s place.
pub const brcb_attributes = [_][]const u8{
    "RptID",  "RptEna", "DatSet", "ConfRev",  "OptFlds", "BufTm",       "SqNum",
    "TrgOps", "IntgPd", "GI",     "PurgeBuf", "EntryID", "TimeOfEntry", "ResvTms",
};

/// The edition-2 forms, with `Owner` appended. Selected by
/// `ControlBlock.include_owner`; a client that reads a structure of the wrong
/// shape mis-assigns every field after the change, which is why this is opt-in
/// rather than the default.
pub const urcb_attributes_owner = urcb_attributes ++ [_][]const u8{"Owner"};
pub const brcb_attributes_owner = brcb_attributes ++ [_][]const u8{"Owner"};

// ── the report encoder ──────────────────────────────────────────────────────

/// Everything in a report's header. Which of these actually reach the wire is
/// decided entirely by `opt_flds`, and the order is the one
/// `report.Report.decode` reads.
pub const Fields = struct {
    rpt_id: []const u8,
    opt_flds: OptFlds,
    sq_num: u32 = 0,
    time_of_entry: mmsdata.BinaryTime = .{ .ms_since_midnight = 0, .days_since_1984 = 0 },
    dat_set: []const u8 = "",
    buf_ovfl: bool = false,
    /// The `EntryID` octets, exactly as they go on the wire.
    entry_id: []const u8 = &.{},
    conf_rev: u32 = 0,
    sub_seq_num: u32 = 0,
    more_segments_follow: bool = false,
};

/// One member of the report.
pub const Included = struct {
    /// Index into the data set — this is what sets the inclusion bit.
    index: usize,
    reference: []const u8 = "",
    /// The member's value as a complete `Data` TLV.
    value: []const u8,
    reason: Reason = .{},
};

/// Encodes one report and closes it as an `InformationReport` PDU.
///
/// `members` is the **whole** data set's size: it fixes the width of the
/// inclusion bit string, which is what lets a partial report be decoded back to
/// the right indices.
pub fn encode(
    w: *ber.Writer,
    f: Fields,
    members: usize,
    included: []const Included,
) Error!void {
    if (members > max_members) return error.TooManyMembers;
    if (included.len > members) return error.TooManyEntries;

    var inclusion: u64 = 0;
    for (included) |e| {
        if (e.index >= members) return error.TooManyEntries;
        inclusion |= @as(u64, 1) << @intCast(members - 1 - e.index);
    }

    const m = w.mark();
    // Backwards: the last field first.
    if (f.opt_flds.reason_for_inclusion) {
        var i: usize = included.len;
        while (i > 0) {
            i -= 1;
            try included[i].reason.emit(w);
        }
    }
    var i: usize = included.len;
    while (i > 0) {
        i -= 1;
        try w.bytes(included[i].value);
    }
    if (f.opt_flds.data_reference) {
        i = included.len;
        while (i > 0) {
            i -= 1;
            try mmsdata.Emit.visibleString(w, included[i].reference);
        }
    }
    try w.bitString(mmsdata.Kind.bit_string.tag(), inclusion, @intCast(members));
    if (f.opt_flds.segmentation) {
        try mmsdata.Emit.boolean(w, f.more_segments_follow);
        try mmsdata.Emit.unsigned(w, f.sub_seq_num);
    }
    if (f.opt_flds.conf_revision) try mmsdata.Emit.unsigned(w, f.conf_rev);
    if (f.opt_flds.entry_id) try mmsdata.Emit.octetString(w, f.entry_id);
    if (f.opt_flds.buffer_overflow) try mmsdata.Emit.boolean(w, f.buf_ovfl);
    if (f.opt_flds.data_set_name) try mmsdata.Emit.visibleString(w, f.dat_set);
    if (f.opt_flds.report_time_stamp) try mmsdata.Emit.binaryTime(w, f.time_of_entry);
    if (f.opt_flds.sequence_number) try mmsdata.Emit.unsigned(w, f.sq_num);
    try f.opt_flds.emit(w);
    try mmsdata.Emit.visibleString(w, f.rpt_id);
    try mms.closeInformationReport(w, m, .{
        .variable_list = .{ .vmd_specific = report.report_variable_name },
    });
}

/// Milliseconds since the Unix epoch as an MMS `BinaryTime` — days since
/// 1984-01-01 plus milliseconds into the day, which is the six-octet form every
/// report timestamp uses.
pub fn binaryTimeFromMillis(ms: u64) mmsdata.BinaryTime {
    const epoch_1984_days: u64 = 5114; // 1970-01-01 → 1984-01-01
    const days_total = ms / mmsdata.BinaryTime.ms_per_day;
    const in_day: u32 = @intCast(ms % mmsdata.BinaryTime.ms_per_day);
    const days: u64 = if (days_total > epoch_1984_days) days_total - epoch_1984_days else 0;
    return .{
        .ms_since_midnight = in_day,
        .days_since_1984 = @intCast(days & 0xFFFF),
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A four-member data set of booleans, the shape the oracle IED's `Events` data
/// set has.
const TestSource = struct {
    values: [4][8]u8 = undefined,
    lens: [4]usize = @splat(0),
    refs: [4][]const u8 = .{
        "TESTLD/GGIO1$ST$Ind1$stVal",
        "TESTLD/GGIO1$ST$Ind2$stVal",
        "TESTLD/GGIO1$ST$Ind3$stVal",
        "TESTLD/GGIO1$ST$Ind4$stVal",
    },
    count_override: ?usize = null,

    fn init(self: *TestSource) !void {
        for (0..4) |i| try self.set(i, false);
    }

    fn set(self: *TestSource, i: usize, v: bool) !void {
        var w = ber.Writer.init(&self.values[i]);
        try mmsdata.Emit.boolean(&w, v);
        const d = w.done();
        std.mem.copyForwards(u8, self.values[i][0..d.len], d);
        self.lens[i] = d.len;
    }

    fn source(self: *TestSource) Source {
        return .{ .ctx = self, .vtable = &.{
            .count = countFn,
            .value = valueFn,
            .reference = referenceFn,
        } };
    }

    fn countFn(ctx: *anyopaque, _: usize) usize {
        const self: *TestSource = @ptrCast(@alignCast(ctx));
        return self.count_override orelse 4;
    }
    fn valueFn(ctx: *anyopaque, _: usize, member: usize) ?[]const u8 {
        const self: *TestSource = @ptrCast(@alignCast(ctx));
        if (member >= 4) return null;
        return self.values[member][0..self.lens[member]];
    }
    fn referenceFn(ctx: *anyopaque, _: usize, member: usize, out: []u8) ?[]const u8 {
        const self: *TestSource = @ptrCast(@alignCast(ctx));
        if (member >= 4) return null;
        const r = self.refs[member];
        if (r.len > out.len) return null;
        @memcpy(out[0..r.len], r);
        return out[0..r.len];
    }
};

fn testBuffer(entries: []Entry, arena: []u8) Buffer {
    return Buffer.init(entries, arena) catch unreachable;
}

// ── the byte-exact anchor ───────────────────────────────────────────────────

/// **Third-party golden.** The first report a real IEC 61850 IED pushed after a
/// general interrogation of `LLN0$Events` — the same octets `report.zig`
/// decodes, here used the other way round: our *encoder* must reproduce them.
///
/// Captured from a live third-party stack (SPEC.md); no substation identity is
/// in it, the logical device is the reference model's own `simpleIOGenericIO`.
const oracle_gi_report = [_]u8{
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

test "the encoder reproduces a real IED's GI report octet for octet" {
    var vals: [4][8]u8 = undefined;
    var included: [4]Included = undefined;
    for (0..4) |i| {
        var w = ber.Writer.init(&vals[i]);
        try mmsdata.Emit.boolean(&w, false);
        const d = w.done();
        std.mem.copyForwards(u8, vals[i][0..d.len], d);
        included[i] = .{
            .index = i,
            .value = vals[i][0..d.len],
            .reason = .{ .general_interrogation = true },
        };
    }

    var buf: [512]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try encode(&w, .{
        .rpt_id = "Events1",
        .opt_flds = .{
            .sequence_number = true,
            .report_time_stamp = true,
            .reason_for_inclusion = true,
            .data_set_name = true,
            .conf_revision = true,
        },
        .sq_num = 0,
        .time_of_entry = .{ .ms_since_midnight = 0x01E9C111, .days_since_1984 = 0x3CB8 },
        .dat_set = "simpleIOGenericIO/LLN0$Events",
        .conf_rev = 1,
    }, 4, &included);

    try testing.expectEqualSlices(u8, &oracle_gi_report, w.done());
}

test "every OptFlds combination the encoder supports round trips through the decoder" {
    var vals: [3][8]u8 = undefined;
    var included: [3]Included = undefined;
    const refs = [_][]const u8{ "LD/GGIO1$ST$A$stVal", "LD/GGIO1$ST$B$stVal", "LD/GGIO1$ST$C$stVal" };
    for (0..3) |i| {
        var vw = ber.Writer.init(&vals[i]);
        try mmsdata.Emit.integer(&vw, @intCast(i * 11));
        const d = vw.done();
        std.mem.copyForwards(u8, vals[i][0..d.len], d);
        included[i] = .{
            .index = i * 2, // 0, 2, 4 — a partial report over six members
            .reference = refs[i],
            .value = vals[i][0..d.len],
            .reason = .{ .data_change = true, .integrity = i == 1 },
        };
    }

    // All 512 combinations of the nine defined bits.
    var mask: u16 = 0;
    var checked: usize = 0;
    while (mask < 512) : (mask += 1) {
        const opt = OptFlds{
            .sequence_number = mask & 1 != 0,
            .report_time_stamp = mask & 2 != 0,
            .reason_for_inclusion = mask & 4 != 0,
            .data_set_name = mask & 8 != 0,
            .data_reference = mask & 16 != 0,
            .buffer_overflow = mask & 32 != 0,
            .entry_id = mask & 64 != 0,
            .conf_revision = mask & 128 != 0,
            .segmentation = mask & 256 != 0,
        };
        var buf: [1024]u8 = undefined;
        var w = ber.Writer.init(&buf);
        const id = [_]u8{ 0, 0, 0, 0, 0, 0, 0x12, 0x34 };
        try encode(&w, .{
            .rpt_id = "RPT-X",
            .opt_flds = opt,
            .sq_num = 7,
            .time_of_entry = .{ .ms_since_midnight = 1234, .days_since_1984 = 15544 },
            .dat_set = "LD/LLN0$Events",
            .buf_ovfl = true,
            .entry_id = &id,
            .conf_rev = 3,
            .sub_seq_num = 2,
            .more_segments_follow = true,
        }, 6, &included);

        const pdu = try mms.decode(w.done());
        const r = try report.decodeInformationReport(pdu.unconfirmed.body);
        try testing.expectEqualStrings("RPT-X", r.rpt_id);
        try testing.expectEqual(opt, r.opt_flds);
        try testing.expectEqual(@as(u16, 3), r.entry_count);
        try testing.expectEqual(@as(usize, 6), r.inclusion.bitCount());
        try testing.expectEqual(@as(usize, 0), r.included()[0].index);
        try testing.expectEqual(@as(usize, 2), r.included()[1].index);
        try testing.expectEqual(@as(usize, 4), r.included()[2].index);
        if (opt.sequence_number) try testing.expectEqual(@as(u32, 7), r.sq_num.?);
        if (opt.report_time_stamp) try testing.expectEqual(@as(u32, 1234), r.time_of_entry.?.ms_since_midnight);
        if (opt.data_set_name) try testing.expectEqualStrings("LD/LLN0$Events", r.dat_set.?);
        if (opt.buffer_overflow) try testing.expect(r.buf_ovfl.?);
        if (opt.entry_id) try testing.expectEqualSlices(u8, &id, r.entry_id.?);
        if (opt.conf_revision) try testing.expectEqual(@as(u32, 3), r.conf_rev.?);
        if (opt.segmentation) {
            try testing.expectEqual(@as(u32, 2), r.sub_seq_num.?);
            try testing.expect(r.more_segments_follow.?);
        }
        if (opt.data_reference) {
            for (r.included(), 0..) |e, i| try testing.expectEqualStrings(refs[i], e.reference.?);
        }
        if (opt.reason_for_inclusion) {
            for (r.included()) |e| try testing.expect(e.reason.?.data_change);
            try testing.expect(r.included()[1].reason.?.integrity);
        }
        for (r.included(), 0..) |e, i| {
            try testing.expectEqual(@as(i32, @intCast(i * 11)), try e.value.integer(i32));
        }
        checked += 1;
    }
    try testing.expectEqual(@as(usize, 512), checked);
}

// ── the engine ──────────────────────────────────────────────────────────────

const Harness = struct {
    src: TestSource = .{},
    entries: [8]Entry = @splat(.{}),
    arena: [8 * 128]u8 = undefined,
    out: [2048]u8 = undefined,

    fn block(self: *Harness, kind: RcbKind) ControlBlock {
        return .{
            .kind = kind,
            .domain = "TESTLD",
            .item = if (kind == .buffered) "LLN0$BR$brcb01" else "LLN0$RP$urcb01",
            .rpt_id = "RPT1",
            .dat_set = "TESTLD/LLN0$Events",
            .conf_rev = 1,
            .opt_flds = .{
                .sequence_number = true,
                .report_time_stamp = true,
                .reason_for_inclusion = true,
                .data_set_name = true,
                .buffer_overflow = true,
                .entry_id = true,
                .conf_revision = true,
            },
            .trg_ops = .{
                .data_change = true,
                .quality_change = true,
                .integrity = true,
                .general_interrogation = true,
            },
            .buffer = testBuffer(&self.entries, &self.arena),
        };
    }

    /// Emits the next pending report and decodes it straight back.
    fn next(self: *Harness, cb: *ControlBlock) !?report.Report {
        var w = ber.Writer.init(&self.out);
        if (!try cb.emitNext(self.src.source(), &w)) return null;
        const pdu = try mms.decode(w.done());
        return try report.decodeInformationReport(pdu.unconfirmed.body);
    }
};

test "a data change on an enabled URCB produces one report with the right reason" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    cb.enable(1, 0);

    try h.src.set(2, true);
    try testing.expect(try cb.signal(h.src.source(), 0, 2, .data_change, 100));
    const r = (try h.next(&cb)).?;
    try testing.expectEqual(@as(u16, 1), r.entry_count);
    try testing.expectEqual(@as(usize, 2), r.included()[0].index);
    try testing.expect(r.included()[0].reason.?.data_change);
    try testing.expectEqual(true, try r.included()[0].value.boolean());
    try testing.expectEqual(@as(u32, 0), r.sq_num.?);
    // And nothing is left over.
    try testing.expect((try h.next(&cb)) == null);
    try testing.expectEqual(@as(u64, 1), cb.reports_emitted);
    try testing.expectEqual(@as(u32, 1), cb.sq_num);
}

test "BufTm coalesces a burst into one report instead of a storm" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    cb.buf_tm_ms = 50;
    cb.enable(1, 0);

    // Four changes inside one 50 ms window.
    for ([_]usize{ 0, 1, 2, 3 }, 0..) |m, k| {
        try h.src.set(m, true);
        _ = try cb.signal(h.src.source(), 0, m, .data_change, 10 + k * 5);
    }
    // Still coalescing: nothing to send.
    try testing.expect(!cb.pending());
    _ = try cb.tick(h.src.source(), 40);
    try testing.expect(!cb.pending());
    // The window closes.
    _ = try cb.tick(h.src.source(), 60);
    const r = (try h.next(&cb)).?;
    try testing.expectEqual(@as(u16, 4), r.entry_count);
    try testing.expect((try h.next(&cb)) == null);
    // One report, not four.
    try testing.expectEqual(@as(u64, 1), cb.reports_emitted);
    try testing.expectEqual(@as(u64, 1), cb.entries_buffered);
}

test "BufTm zero sends every change on its own" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    cb.buf_tm_ms = 0;
    cb.enable(1, 0);
    for ([_]usize{ 0, 1, 2 }) |m| {
        try h.src.set(m, true);
        _ = try cb.signal(h.src.source(), 0, m, .data_change, 10);
    }
    var n: usize = 0;
    while (try h.next(&cb)) |r| : (n += 1) try testing.expectEqual(@as(u16, 1), r.entry_count);
    try testing.expectEqual(@as(usize, 3), n);
}

test "the integrity period fires on its own and reports every member" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    cb.intg_pd_ms = 1000;
    cb.enable(1, 0);

    try testing.expect(!try cb.tick(h.src.source(), 999));
    try testing.expect(try cb.tick(h.src.source(), 1000));
    const r = (try h.next(&cb)).?;
    try testing.expectEqual(@as(u16, 4), r.entry_count);
    for (r.included()) |e| {
        try testing.expect(e.reason.?.integrity);
        try testing.expect(!e.reason.?.general_interrogation);
    }
    // And again one period later, not before.
    try testing.expect(!try cb.tick(h.src.source(), 1500));
    try testing.expect(try cb.tick(h.src.source(), 2000));
}

test "a general interrogation reports every member with the GI reason" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    cb.enable(1, 0);
    try testing.expect(try cb.sweep(h.src.source(), .general_interrogation, 5));
    const r = (try h.next(&cb)).?;
    try testing.expectEqual(@as(u16, 4), r.entry_count);
    for (r.included()) |e| try testing.expect(e.reason.?.general_interrogation);
}

test "TrgOps really gates: a data change with dchg off produces nothing" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    cb.trg_ops = .{ .quality_change = true };
    cb.enable(1, 0);
    try testing.expect(!try cb.signal(h.src.source(), 0, 0, .data_change, 1));
    try testing.expect(try cb.signal(h.src.source(), 0, 0, .quality_change, 1));
    const r = (try h.next(&cb)).?;
    try testing.expect(r.included()[0].reason.?.quality_change);
    try testing.expect(!r.included()[0].reason.?.data_change);
}

test "a URCB drops what happens while it is disabled; a BRCB keeps it" {
    var h: Harness = .{};
    try h.src.init();
    var u = h.block(.unbuffered);
    try h.src.set(0, true);
    _ = try u.signal(h.src.source(), 0, 0, .data_change, 1);
    u.enable(1, 10);
    try testing.expect((try h.next(&u)) == null);

    var hb: Harness = .{};
    try hb.src.init();
    var b = hb.block(.buffered);
    try hb.src.set(0, true);
    try testing.expect(try b.signal(hb.src.source(), 0, 0, .data_change, 1));
    try testing.expect(!b.pending()); // not enabled, so not sendable…
    b.enable(1, 10);
    try testing.expect(b.pending()); // …but kept, and delivered on enable.
    const r = (try hb.next(&b)).?;
    try testing.expectEqual(@as(usize, 0), r.included()[0].index);
    try testing.expect(r.included()[0].reason.?.data_change);
}

test "a BRCB resumes from the EntryID the client last saw" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.buffered);
    cb.enable(1, 0);
    // Three separate events.
    for ([_]usize{ 0, 1, 2 }) |m| {
        try h.src.set(m, true);
        _ = try cb.signal(h.src.source(), 0, m, .data_change, 10);
    }
    const first = (try h.next(&cb)).?;
    const first_id = std.mem.readInt(u64, first.entry_id.?[0..8], .big);
    // The client goes away after the first report.
    cb.associationLost();
    try testing.expect(!cb.rpt_ena);
    // …and comes back, resuming after what it saw.
    cb.enable(1, 100);
    try cb.resumeAfter(first_id);
    var seen: usize = 0;
    while (try h.next(&cb)) |_| seen += 1;
    try testing.expectEqual(@as(usize, 2), seen);
}

test "a BRCB resume point that has fallen out of the buffer is a typed error" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.buffered);
    cb.enable(1, 0);
    // Overrun the eight-entry buffer.
    var k: usize = 0;
    while (k < 20) : (k += 1) {
        try h.src.set(k % 4, k % 2 == 0);
        _ = try cb.signal(h.src.source(), 0, k % 4, .data_change, 10);
    }
    try testing.expectError(error.EntryIdNotFound, cb.resumeAfter(1));
    // Zero means "whatever is left", which always resolves.
    try cb.resumeAfter(0);
    try testing.expect(cb.pending());
}

test "a bounded BRCB buffer raises BufOvfl instead of growing" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.buffered);
    // Fill past the eight entries without ever reading.
    var k: usize = 0;
    while (k < 12) : (k += 1) {
        try h.src.set(k % 4, k % 2 == 0);
        _ = try cb.signal(h.src.source(), 0, k % 4, .data_change, 10);
    }
    try testing.expectEqual(@as(usize, 8), cb.buffer.count);
    try testing.expect(cb.buffer.overflow);
    try testing.expect(cb.entries_dropped > 0);

    cb.enable(1, 20);
    try cb.resumeAfter(0);
    const r = (try h.next(&cb)).?;
    // The first report after the loss says so, and only the first.
    try testing.expect(r.buf_ovfl.?);
    const r2 = (try h.next(&cb)).?;
    try testing.expect(!r2.buf_ovfl.?);
}

test "the emitted EntryID advances and is what a resume writes back" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.buffered);
    cb.enable(1, 0);
    try h.src.set(0, true);
    _ = try cb.signal(h.src.source(), 0, 0, .data_change, 1);
    try h.src.set(1, true);
    _ = try cb.signal(h.src.source(), 0, 1, .data_change, 2);
    // Each report is decoded in place over the same output buffer, so the id
    // has to be read out before the next one overwrites it.
    const a = (try h.next(&cb)).?;
    try testing.expectEqual(@as(usize, entry_id_len), a.entry_id.?.len);
    const ida = std.mem.readInt(u64, a.entry_id.?[0..8], .big);
    const b = (try h.next(&cb)).?;
    const idb = std.mem.readInt(u64, b.entry_id.?[0..8], .big);
    try testing.expect(idb > ida);
}

test "an RCB structure this server emits decodes with the client's own decoder" {
    for ([_]RcbKind{ .unbuffered, .buffered }) |kind| {
        var hh: Harness = .{};
        var cb = hh.block(kind);
        cb.buf_tm_ms = 50;
        cb.intg_pd_ms = 1000;
        cb.resv_tms = 0;
        var buf: [512]u8 = undefined;
        var w = ber.Writer.init(&buf);
        try cb.emitStructure(&w);
        const d = try mmsdata.Data.decode(w.done());
        try d.validate();
        const rcb = try report.Rcb.decode(d, kind);
        try testing.expectEqualStrings("RPT1", rcb.rpt_id);
        try testing.expect(!rcb.rpt_ena);
        try testing.expectEqualStrings("TESTLD/LLN0$Events", rcb.dat_set);
        try testing.expectEqual(@as(u32, 1), rcb.conf_rev);
        try testing.expectEqual(@as(u32, 50), rcb.buf_tm_ms);
        try testing.expectEqual(@as(u32, 1000), rcb.intg_pd_ms);
        try testing.expectEqual(cb.opt_flds, rcb.opt_flds);
        try testing.expectEqual(cb.trg_ops, rcb.trg_ops);
        switch (kind) {
            .unbuffered => {
                try testing.expectEqual(false, rcb.resv.?);
                try testing.expect(rcb.purge_buf == null);
            },
            .buffered => {
                try testing.expect(rcb.resv == null);
                try testing.expectEqual(false, rcb.purge_buf.?);
                try testing.expectEqual(@as(usize, entry_id_len), rcb.entry_id.?.len);
                try testing.expectEqual(@as(i16, 0), rcb.resv_tms.?);
            },
        }
    }
}

test "a client may not reconfigure an enabled control block" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    var buf: [32]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try mmsdata.Emit.unsigned(&w, 250);
    const d = try mmsdata.Data.decode(w.done());

    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("BufTm", d, 1, 0));
    try testing.expectEqual(@as(u32, 250), cb.buf_tm_ms);
    cb.enable(1, 0);
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("BufTm", d, 1, 0));
    try testing.expectEqual(@as(u32, 250), cb.buf_tm_ms);
    // GI and RptEna are always writable.
    var bw = ber.Writer.init(&buf);
    try mmsdata.Emit.boolean(&bw, true);
    const t = try mmsdata.Data.decode(bw.done());
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("GI", t, 1, 0));
    try testing.expectEqual(WriteOutcome.unknown, cb.writeAttribute("NoSuchThing", t, 1, 0));
}

test "a URCB reservation keeps a second client out" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    var buf: [32]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try mmsdata.Emit.boolean(&w, true);
    const t = try mmsdata.Data.decode(w.done());
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("Resv", t, 1, 0));
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("RptEna", t, 2, 0));
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("RptEna", t, 1, 0));
    try testing.expect(cb.rpt_ena);
}

test "a data set larger than the inclusion bit string is a typed error" {
    var h: Harness = .{};
    try h.src.init();
    h.src.count_override = max_members + 1;
    var cb = h.block(.unbuffered);
    cb.enable(1, 0);
    try testing.expectError(error.TooManyMembers, cb.signal(h.src.source(), 0, 0, .data_change, 1));
    try testing.expectError(error.TooManyMembers, cb.sweep(h.src.source(), .general_interrogation, 1));
}

test "an entry whose values do not fit its slot is refused, not truncated" {
    var src: TestSource = .{};
    try src.init();
    var entries: [2]Entry = @splat(.{});
    // Ten bytes a slot: a three-octet boolean fits three times, not four.
    var arena: [20]u8 = undefined;
    var cb = ControlBlock{
        .kind = .unbuffered,
        .domain = "TESTLD",
        .item = "LLN0$RP$urcb01",
        .dat_set = "TESTLD/LLN0$Events",
        .trg_ops = .{ .general_interrogation = true },
        .buffer = try Buffer.init(&entries, &arena),
    };
    cb.enable(1, 0);
    try testing.expectError(error.EntryTooLarge, cb.sweep(src.source(), .general_interrogation, 1));
}

test "a control block with no buffer storage at all simply reports nothing" {
    var src: TestSource = .{};
    try src.init();
    var cb = ControlBlock{
        .kind = .unbuffered,
        .domain = "TESTLD",
        .item = "LLN0$RP$urcb01",
        .dat_set = "TESTLD/LLN0$Events",
        .trg_ops = .{ .data_change = true, .general_interrogation = true },
    };
    cb.enable(1, 0);
    try testing.expect(!try cb.signal(src.source(), 0, 0, .data_change, 1));
    try testing.expect(!try cb.sweep(src.source(), .general_interrogation, 1));
    try testing.expect(!cb.pending());
    try testing.expectError(error.ReportBufferTooSmall, Buffer.init(&.{}, &.{}));
}

test "encode refuses a member index outside the data set" {
    var buf: [128]u8 = undefined;
    var w = ber.Writer.init(&buf);
    var val: [4]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try mmsdata.Emit.boolean(&vw, true);
    const included = [_]Included{.{ .index = 9, .value = vw.done() }};
    try testing.expectError(error.TooManyEntries, encode(&w, .{
        .rpt_id = "R",
        .opt_flds = .{},
    }, 4, &included));
    try testing.expectError(error.TooManyMembers, encode(&w, .{
        .rpt_id = "R",
        .opt_flds = .{},
    }, max_members + 1, &.{}));
}

test "binary time round trips through the decoder" {
    const t = binaryTimeFromMillis(1_700_000_000_000);
    var buf: [16]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try mmsdata.Emit.binaryTime(&w, t);
    const d = try mmsdata.Data.decode(w.done());
    const back = try d.binaryTime();
    try testing.expectEqual(t.ms_since_midnight, back.ms_since_midnight);
    try testing.expectEqual(t.days_since_1984.?, back.days_since_1984.?);
}

test "fuzz: an arbitrary write to an RCB attribute never panics" {
    try std.testing.fuzz({}, fuzzRcbWrite, .{});
}

fn fuzzRcbWrite(_: void, smith: *std.testing.Smith) !void {
    var h: Harness = .{};
    h.src.init() catch return;
    var cb = h.block(if (smith.valueRangeAtMost(u8, 0, 1) == 1) .buffered else .unbuffered);
    var input: [128]u8 = undefined;
    smith.bytes(&input);
    const len: usize = smith.valueRangeAtMost(u8, 0, input.len);
    const d = mmsdata.Data.decode(input[0..len]) catch return;
    d.validate() catch return;
    const names = cb.attributes();
    const which: usize = smith.valueRangeAtMost(u8, 0, @intCast(names.len - 1));
    _ = cb.writeAttribute(names[which], d, 1, 0);
    _ = cb.tick(h.src.source(), 1000) catch {};
    var w = ber.Writer.init(&h.out);
    _ = cb.emitNext(h.src.source(), &w) catch {};
}

// ── report segmentation ─────────────────────────────────────────────────────

/// A data set whose members are big enough that a whole report cannot fit one
/// PDU. Each member is a distinct octet string, so a reassembled report can be
/// checked member by member rather than just counted.
const WideSource = struct {
    members: usize = 6,
    payload: usize = 40,
    scratch: [64][256]u8 = undefined,
    lens: [64]usize = @splat(0),
    resolves: ?usize = null,

    fn init(self: *WideSource) !void {
        for (0..self.members) |i| {
            var body: [256]u8 = undefined;
            for (0..self.payload) |k| body[k] = @intCast((i * 7 + k) & 0xFF);
            var w = ber.Writer.init(&self.scratch[i]);
            try mmsdata.Emit.octetString(&w, body[0..self.payload]);
            const d = w.done();
            std.mem.copyForwards(u8, self.scratch[i][0..d.len], d);
            self.lens[i] = d.len;
        }
    }

    fn source(self: *WideSource) Source {
        return .{ .ctx = self, .vtable = &.{
            .count = countFn,
            .value = valueFn,
            .reference = referenceFn,
            .resolve = resolveFn,
        } };
    }

    fn countFn(ctx: *anyopaque, _: usize) usize {
        const self: *WideSource = @ptrCast(@alignCast(ctx));
        return self.members;
    }
    fn valueFn(ctx: *anyopaque, _: usize, member: usize) ?[]const u8 {
        const self: *WideSource = @ptrCast(@alignCast(ctx));
        if (member >= self.members) return null;
        return self.scratch[member][0..self.lens[member]];
    }
    fn referenceFn(ctx: *anyopaque, _: usize, member: usize, out: []u8) ?[]const u8 {
        const self: *WideSource = @ptrCast(@alignCast(ctx));
        if (member >= self.members) return null;
        return std.fmt.bufPrint(out, "TESTLD/GGIO1$ST$M{d}$stVal", .{member}) catch null;
    }
    fn resolveFn(ctx: *anyopaque, ds_reference: []const u8) ?usize {
        const self: *WideSource = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, ds_reference, "TESTLD/LLN0$Events")) return 0;
        if (std.mem.eql(u8, ds_reference, "TESTLD/LLN0$Wide")) return self.resolves orelse 1;
        return null;
    }
};

const SegHarness = struct {
    src: WideSource = .{},
    entries: [4]Entry = @splat(.{}),
    arena: [4 * 4096]u8 = undefined,
    out: [4096]u8 = undefined,

    fn block(self: *SegHarness, budget: usize) ControlBlock {
        return .{
            .kind = .unbuffered,
            .domain = "TESTLD",
            .item = "LLN0$RP$urcbSeg",
            .rpt_id = "SEG1",
            .dat_set = "TESTLD/LLN0$Wide",
            .conf_rev = 3,
            .opt_flds = .{
                .sequence_number = true,
                .report_time_stamp = true,
                .reason_for_inclusion = true,
                .data_set_name = true,
                .entry_id = true,
                .conf_revision = true,
                .segmentation = true,
            },
            .trg_ops = .{ .data_change = true, .general_interrogation = true },
            .max_pdu_len = budget,
            .buffer = testBuffer(&self.entries, &self.arena),
        };
    }
};

test "a report larger than the PDU budget is split, and every segment decodes" {
    var h: SegHarness = .{};
    try h.src.init();
    var cb = h.block(200);
    cb.enable(1, 0);
    try testing.expect(try cb.sweep(h.src.source(), .general_interrogation, 1000));

    var slots: [16]report.AssembledEntry = undefined;
    var arena: [4096]u8 = undefined;
    var re = report.Reassembler.init(&slots, &arena);

    var segments: usize = 0;
    var assembled: ?report.Assembled = null;
    while (segments < 16) {
        var w = ber.Writer.init(&h.out);
        if (!try cb.emitNext(h.src.source(), &w)) break;
        segments += 1;
        // Every segment on its own is a complete, decodable InformationReport
        // that never exceeds the budget.
        try testing.expect(w.done().len <= 200);
        const pdu = try mms.decode(w.done());
        const r = try report.decodeInformationReport(pdu.unconfirmed.body);
        try testing.expectEqual(@as(u32, @intCast(segments - 1)), r.sub_seq_num.?);
        // Every segment repeats the same header.
        try testing.expectEqualStrings("SEG1", r.rpt_id);
        try testing.expectEqual(@as(u32, 0), r.sq_num.?);
        try testing.expectEqual(@as(u32, 3), r.conf_rev.?);
        if (try re.push(r)) |done| {
            assembled = done;
            break;
        }
        try testing.expect(r.more_segments_follow.?);
    }
    try testing.expect(segments > 1);
    const a = assembled orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, @intCast(segments)), a.segments);
    try testing.expectEqual(@as(usize, 6), a.entries.len);
    // The reassembled members are the source's, in order and byte for byte.
    for (a.entries, 0..) |e, i| {
        try testing.expectEqual(i, e.index);
        try testing.expectEqualSlices(u8, h.src.scratch[i][0..h.src.lens[i]], e.value);
        try testing.expect(e.reason.?.general_interrogation);
    }
    // The whole report counted as one: the entry is gone and `SqNum` moved once.
    try testing.expect(!cb.segmenting());
    try testing.expect(!cb.pending());
    try testing.expectEqual(@as(u32, 1), cb.sq_num);
}

test "a segmented report keeps one SqNum and one EntryID across its segments" {
    var h: SegHarness = .{};
    try h.src.init();
    var cb = h.block(160);
    cb.enable(1, 0);
    _ = try cb.sweep(h.src.source(), .general_interrogation, 1000);

    var first_id: [8]u8 = undefined;
    var n: usize = 0;
    while (n < 16) : (n += 1) {
        var w = ber.Writer.init(&h.out);
        if (!try cb.emitNext(h.src.source(), &w)) break;
        const pdu = try mms.decode(w.done());
        const r = try report.decodeInformationReport(pdu.unconfirmed.body);
        if (n == 0) {
            @memcpy(&first_id, r.entry_id.?[0..8]);
        } else {
            try testing.expectEqualSlices(u8, &first_id, r.entry_id.?);
            try testing.expectEqual(@as(u32, 0), r.sq_num.?);
        }
        if (!r.more_segments_follow.?) break;
    }
    // A second report starts a fresh SubSeqNum at zero.
    try h.src.init();
    _ = try cb.sweep(h.src.source(), .general_interrogation, 2000);
    var w2 = ber.Writer.init(&h.out);
    try testing.expect(try cb.emitNext(h.src.source(), &w2));
    const pdu2 = try mms.decode(w2.done());
    const r2 = try report.decodeInformationReport(pdu2.unconfirmed.body);
    try testing.expectEqual(@as(u32, 0), r2.sub_seq_num.?);
    try testing.expectEqual(@as(u32, 1), r2.sq_num.?);
}

test "segmentation is off unless both OptFlds and a budget say so" {
    var h: SegHarness = .{};
    try h.src.init();
    // A budget with no `OptFlds.segmentation`: the report is emitted whole and
    // simply fails if it does not fit, which is the pre-segmentation contract.
    var cb = h.block(200);
    cb.opt_flds.segmentation = false;
    cb.enable(1, 0);
    _ = try cb.sweep(h.src.source(), .general_interrogation, 1000);
    var w = ber.Writer.init(&h.out);
    try testing.expect(try cb.emitNext(h.src.source(), &w));
    try testing.expect(w.done().len > 200);
    try testing.expect(!cb.segmenting());

    // …and `OptFlds.segmentation` with no budget is also whole.
    var cb2 = h.block(0);
    cb2.enable(1, 0);
    _ = try cb2.sweep(h.src.source(), .general_interrogation, 1000);
    var w2 = ber.Writer.init(&h.out);
    try testing.expect(try cb2.emitNext(h.src.source(), &w2));
    const pdu = try mms.decode(w2.done());
    const r = try report.decodeInformationReport(pdu.unconfirmed.body);
    try testing.expectEqual(@as(u16, 6), r.entry_count);
    try testing.expectEqual(@as(u32, 0), r.sub_seq_num.?);
    try testing.expect(!r.more_segments_follow.?);
}

test "a member that cannot fit a whole segment is a typed error, never truncated" {
    var h: SegHarness = .{};
    h.src.payload = 200;
    try h.src.init();
    var cb = h.block(80); // smaller than one member
    cb.enable(1, 0);
    _ = try cb.sweep(h.src.source(), .general_interrogation, 1000);
    var w = ber.Writer.init(&h.out);
    try testing.expectError(error.SegmentTooSmall, cb.emitNext(h.src.source(), &w));
}

test "emitNextWithin folds the caller's PDU limit into the block's own" {
    var h: SegHarness = .{};
    try h.src.init();
    var cb = h.block(0); // the block itself has no limit
    cb.enable(1, 0);
    _ = try cb.sweep(h.src.source(), .general_interrogation, 1000);
    var w = ber.Writer.init(&h.out);
    try testing.expect(try cb.emitNextWithin(h.src.source(), &w, 200));
    try testing.expect(w.done().len <= 200);
    try testing.expect(cb.segmenting());
}

// ── runtime DatSet re-binding ───────────────────────────────────────────────

test "a client re-points a disabled RCB at another data set and ConfRev moves" {
    var h: SegHarness = .{};
    try h.src.init();
    var cb = h.block(0);
    cb.data_set = 1;
    try testing.expectEqualStrings("TESTLD/LLN0$Wide", cb.datSet());

    var buf: [64]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try mmsdata.Emit.visibleString(&w, "TESTLD/LLN0$Events");
    const d = try mmsdata.Data.decode(w.done());
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttributeFrom("DatSet", d, h.src.source(), 1, 0));
    try testing.expectEqualStrings("TESTLD/LLN0$Events", cb.datSet());
    try testing.expectEqual(@as(usize, 0), cb.data_set);
    try testing.expectEqual(@as(u32, 4), cb.conf_rev); // was 3

    // The re-bound name survives a *move* of the block, because nothing points
    // into it.
    var moved = cb;
    try testing.expectEqualStrings("TESTLD/LLN0$Events", moved.datSet());

    // …and it is what the RCB reads back as.
    var out: [128]u8 = undefined;
    var ow = ber.Writer.init(&out);
    try cb.emitAttribute("DatSet", &ow);
    const back = try mmsdata.Data.decode(ow.done());
    try testing.expectEqualStrings("TESTLD/LLN0$Events", try back.visibleString());
}

test "a DatSet write is refused while RptEna is set, and the binding does not move" {
    var h: SegHarness = .{};
    try h.src.init();
    var cb = h.block(0);
    cb.data_set = 1;
    cb.enable(1, 0);

    var buf: [64]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try mmsdata.Emit.visibleString(&w, "TESTLD/LLN0$Events");
    const d = try mmsdata.Data.decode(w.done());
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttributeFrom("DatSet", d, h.src.source(), 1, 0));
    try testing.expectEqualStrings("TESTLD/LLN0$Wide", cb.datSet());
    try testing.expectEqual(@as(u32, 3), cb.conf_rev);
    try testing.expectError(error.ReportEnabled, cb.rebind(h.src.source(), "TESTLD/LLN0$Events"));
}

test "a DatSet naming something that does not resolve is refused and changes nothing" {
    var h: SegHarness = .{};
    try h.src.init();
    var cb = h.block(0);
    var buf: [64]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try mmsdata.Emit.visibleString(&w, "TESTLD/LLN0$NoSuchSet");
    const d = try mmsdata.Data.decode(w.done());
    try testing.expectEqual(WriteOutcome.invalid, cb.writeAttributeFrom("DatSet", d, h.src.source(), 1, 0));
    try testing.expectEqualStrings("TESTLD/LLN0$Wide", cb.datSet());
    try testing.expectEqual(@as(u32, 3), cb.conf_rev);
    try testing.expectError(error.UnknownDataSet, cb.rebind(h.src.source(), ""));

    // A source with no resolver at all refuses rather than pretending.
    var plain: TestSource = .{};
    try plain.init();
    try testing.expectEqual(
        WriteOutcome.denied,
        cb.writeAttributeFrom("DatSet", d, plain.source(), 1, 0),
    );
    // …and so does the single-association form, which has no source to ask.
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("DatSet", d, 1, 0));
}

test "a re-bind throws away buffered entries that index the old data set" {
    var h: SegHarness = .{};
    try h.src.init();
    var cb = h.block(0);
    cb.kind = .buffered;
    cb.data_set = 1;
    _ = try cb.signal(h.src.source(), 1, 0, .data_change, 10);
    _ = try cb.signal(h.src.source(), 1, 1, .data_change, 20);
    try testing.expectEqual(@as(usize, 2), cb.buffer.count);
    try cb.rebind(h.src.source(), "TESTLD/LLN0$Events");
    try testing.expectEqual(@as(usize, 0), cb.buffer.count);
}

// ── multi-client reservation ────────────────────────────────────────────────

test "a URCB reserved by one association locks every other one out" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);

    var t: [8]u8 = undefined;
    var tw = ber.Writer.init(&t);
    try mmsdata.Emit.boolean(&tw, true);
    const yes = try mmsdata.Data.decode(tw.done());

    // Client 1 reserves.
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("Resv", yes, 1, 0));
    try testing.expectEqual(@as(u32, 1), cb.reservedBy().?);
    try testing.expectEqual(@as(u32, 1), cb.heldBy().?);

    // Client 2 can do nothing at all with it — not even enable it.
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("RptEna", yes, 2, 0));
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("Resv", yes, 2, 0));
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("GI", yes, 2, 0));
    try testing.expect(!cb.rpt_ena);

    // Client 1 still can.
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("RptEna", yes, 1, 0));
    try testing.expect(cb.rpt_ena);
    try testing.expectEqual(@as(u32, 1), cb.owner.?);

    // Client 1's association drops: a URCB reservation does not survive it.
    cb.associationLostBy(1, 5_000);
    try testing.expect(!cb.resv);
    try testing.expect(cb.owner == null);
    try testing.expect(cb.heldBy() == null);
    // …and now client 2 walks in.
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("RptEna", yes, 2, 0));
    try testing.expectEqual(@as(u32, 2), cb.owner.?);
}

test "an enabled URCB is held against a second association even without Resv" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    var t: [8]u8 = undefined;
    var tw = ber.Writer.init(&t);
    try mmsdata.Emit.boolean(&tw, true);
    const yes = try mmsdata.Data.decode(tw.done());
    var f: [8]u8 = undefined;
    var fw = ber.Writer.init(&f);
    try mmsdata.Emit.boolean(&fw, false);
    const no = try mmsdata.Data.decode(fw.done());

    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("RptEna", yes, 1, 0));
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("RptEna", no, 2, 0));
    try testing.expect(cb.rpt_ena);
    // A second client cannot steal the block by disabling it either.
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("RptEna", no, 1, 0));
    try testing.expect(cb.heldBy() == null);
}

test "a BRCB ResvTms reservation outlives the association and then expires" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.buffered);

    var b: [8]u8 = undefined;
    var bw = ber.Writer.init(&b);
    try mmsdata.Emit.integer(&bw, 30); // thirty seconds
    const thirty = try mmsdata.Data.decode(bw.done());
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("ResvTms", thirty, 7, 0));
    try testing.expectEqual(@as(i16, 30), cb.resv_tms);
    try testing.expectEqual(@as(u32, 7), cb.reservedBy().?);

    // A second client is locked out.
    var t: [8]u8 = undefined;
    var tw = ber.Writer.init(&t);
    try mmsdata.Emit.boolean(&tw, true);
    const yes = try mmsdata.Data.decode(tw.done());
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("RptEna", yes, 9, 0));

    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("RptEna", yes, 7, 0));
    // Client 7 goes away. The BRCB keeps the buffer *and* the reservation.
    try testing.expect(try cb.signal(h.src.source(), 0, 1, .data_change, 100));
    cb.associationLostBy(7, 100_000);
    try testing.expect(!cb.rpt_ena);
    try testing.expectEqual(@as(u32, 7), cb.owner.?);
    try testing.expectEqual(@as(usize, 1), cb.buffer.count);
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("RptEna", yes, 9, 100_000));

    // Twenty-nine seconds later it is still theirs…
    _ = try cb.tick(h.src.source(), 129_000);
    try testing.expectEqual(@as(u32, 7), cb.owner.?);
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("RptEna", yes, 9, 129_000));
    // …and at thirty it lapses.
    _ = try cb.tick(h.src.source(), 130_000);
    try testing.expect(cb.owner == null);
    try testing.expectEqual(@as(i16, 0), cb.resv_tms);
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("RptEna", yes, 9, 130_000));
    // The buffered entry survived all of it — that is the BRCB guarantee.
    try testing.expectEqual(@as(usize, 1), cb.buffer.count);
}

test "ResvTms -1 holds a BRCB until its client gives it back" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.buffered);
    var b: [8]u8 = undefined;
    var bw = ber.Writer.init(&b);
    try mmsdata.Emit.integer(&bw, -1);
    const forever = try mmsdata.Data.decode(bw.done());
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("ResvTms", forever, 4, 0));
    cb.associationLostBy(4, 1_000);
    try testing.expectEqual(@as(u32, 4), cb.owner.?);
    _ = try cb.tick(h.src.source(), 10_000_000);
    try testing.expectEqual(@as(u32, 4), cb.owner.?);

    var z: [8]u8 = undefined;
    var zw = ber.Writer.init(&z);
    try mmsdata.Emit.integer(&zw, 0);
    const zero = try mmsdata.Data.decode(zw.done());
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("ResvTms", zero, 5, 0));
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("ResvTms", zero, 4, 0));
    try testing.expect(cb.heldBy() == null);

    // Below -1 is not a reservation lifetime at all.
    var n: [8]u8 = undefined;
    var nw = ber.Writer.init(&n);
    try mmsdata.Emit.integer(&nw, -2);
    const bad = try mmsdata.Data.decode(nw.done());
    try testing.expectEqual(WriteOutcome.invalid, cb.writeAttribute("ResvTms", bad, 4, 0));
}

test "Resv belongs to a URCB and ResvTms to a BRCB, and neither answers for the other" {
    var h: Harness = .{};
    try h.src.init();
    var urcb = h.block(.unbuffered);
    var brcb = h.block(.buffered);
    var b: [8]u8 = undefined;
    var bw = ber.Writer.init(&b);
    try mmsdata.Emit.integer(&bw, 10);
    const ten = try mmsdata.Data.decode(bw.done());
    var t: [8]u8 = undefined;
    var tw = ber.Writer.init(&t);
    try mmsdata.Emit.boolean(&tw, true);
    const yes = try mmsdata.Data.decode(tw.done());

    try testing.expectEqual(WriteOutcome.unknown, urcb.writeAttribute("ResvTms", ten, 1, 0));
    try testing.expectEqual(WriteOutcome.unknown, brcb.writeAttribute("Resv", yes, 1, 0));
    // …which is exactly what the two attribute lists say.
    var seen_resv = false;
    for (urcb.attributes()) |a| {
        if (std.mem.eql(u8, a, "Resv")) seen_resv = true;
    }
    try testing.expect(seen_resv);
    var seen_tms = false;
    for (brcb.attributes()) |a| {
        if (std.mem.eql(u8, a, "ResvTms")) seen_tms = true;
    }
    try testing.expect(seen_tms);
}

// ── Owner ───────────────────────────────────────────────────────────────────

test "Owner names the holding client and is empty when nobody holds the block" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    var out: [64]u8 = undefined;

    var w = ber.Writer.init(&out);
    try cb.emitAttribute("Owner", &w);
    const empty = try mmsdata.Data.decode(w.done());
    try testing.expectEqual(@as(usize, 0), (try empty.octetString()).len);

    cb.enable(0xC0A8_0105, 0); // 192.168.1.5
    var w2 = ber.Writer.init(&out);
    try cb.emitAttribute("Owner", &w2);
    const owned = try mmsdata.Data.decode(w2.done());
    try testing.expectEqualSlices(u8, &[_]u8{ 0xC0, 0xA8, 0x01, 0x05 }, try owned.octetString());

    // A client may read it and never write it.
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("Owner", owned, 0xC0A8_0105, 0));
}

test "include_owner appends Owner to the structure and the read decodes as an RCB" {
    var h: Harness = .{};
    try h.src.init();
    var cb = h.block(.unbuffered);
    try testing.expectEqual(@as(usize, 11), cb.attributes().len);
    cb.include_owner = true;
    try testing.expectEqual(@as(usize, 12), cb.attributes().len);
    try testing.expectEqualStrings("Owner", cb.attributes()[11]);
    cb.enable(0x0A00_0001, 0);

    var out: [512]u8 = undefined;
    var w = ber.Writer.init(&out);
    try cb.emitStructure(&w);
    // The eleven edition-1 members still decode as a URCB — `Rcb.decode` reads
    // positionally and stops where it stops, which is what makes the extra
    // member safe to append.
    const d = try mmsdata.Data.decode(w.done());
    const rcb = try report.Rcb.decode(d, .unbuffered);
    try testing.expectEqualStrings("RPT1", rcb.rpt_id);
    try testing.expectEqual(true, rcb.rpt_ena);

    var brcb = h.block(.buffered);
    brcb.include_owner = true;
    try testing.expectEqual(@as(usize, 15), brcb.attributes().len);
    try testing.expectEqualStrings("Owner", brcb.attributes()[14]);
}

// ── byte-exact goldens for the segmented shapes ─────────────────────────────

/// **Self-derived golden**, not a third-party capture: no oracle model here is
/// wide enough to make a real IED segment a report, so these are this module's
/// own octets. What makes them worth pinning is that the *shape* comes from
/// IEC 61850-8-1's report layout — `SubSeqNum` then `MoreSegmentsFollow`,
/// immediately after `ConfRev` and before the inclusion bit string — and that
/// both segments decode and **re-encode identically**, and that Wireshark's own
/// MMS dissector reads them field by field (SPEC.md).
///
/// Four members of sixteen octets each, split at a 120-octet budget: members 0
/// and 1 here…
const segmented_report_first = [_]u8{
    0xA3, 0x76, 0xA0, 0x74, 0xA1, 0x05, 0x80, 0x03,
    0x52, 0x50, 0x54, 0xA0, 0x6B, 0x8A, 0x04, 0x53,
    0x45, 0x47, 0x31, 0x84, 0x03, 0x06, 0x79, 0xC0,
    0x86, 0x01, 0x00, 0x8C, 0x06, 0x04, 0xC4, 0xB4,
    0x00, 0x38, 0xE1, 0x8A, 0x10, 0x54, 0x45, 0x53,
    0x54, 0x4C, 0x44, 0x2F, 0x4C, 0x4C, 0x4E, 0x30,
    0x24, 0x57, 0x69, 0x64, 0x65, 0x89, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86,
    0x01, 0x03, 0x86, 0x01, 0x00, 0x83, 0x01, 0x01,
    0x84, 0x02, 0x04, 0xC0, 0x89, 0x10, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x89, 0x10,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x84, 0x02, 0x02, 0x04, 0x84, 0x02, 0x02, 0x04,
};

/// …and members 2 and 3 here. The header repeats verbatim — same `RptID`, same
/// `SqNum` (0), same `TimeOfEntry`, same `EntryID`, same `ConfRev` — and only
/// `SubSeqNum` (0 → 1), `MoreSegmentsFollow` (true → false), the inclusion bit
/// string (`0xC0` → `0x30`) and the values differ.
const segmented_report_last = [_]u8{
    0xA3, 0x76, 0xA0, 0x74, 0xA1, 0x05, 0x80, 0x03,
    0x52, 0x50, 0x54, 0xA0, 0x6B, 0x8A, 0x04, 0x53,
    0x45, 0x47, 0x31, 0x84, 0x03, 0x06, 0x79, 0xC0,
    0x86, 0x01, 0x00, 0x8C, 0x06, 0x04, 0xC4, 0xB4,
    0x00, 0x38, 0xE1, 0x8A, 0x10, 0x54, 0x45, 0x53,
    0x54, 0x4C, 0x44, 0x2F, 0x4C, 0x4C, 0x4E, 0x30,
    0x24, 0x57, 0x69, 0x64, 0x65, 0x89, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86,
    0x01, 0x03, 0x86, 0x01, 0x01, 0x83, 0x01, 0x00,
    0x84, 0x02, 0x04, 0x30, 0x89, 0x10, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x89, 0x10,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x84, 0x02, 0x02, 0x04, 0x84, 0x02, 0x02, 0x04,
};

fn segmentGoldenBlock(h: *SegHarness) !ControlBlock {
    h.src.members = 4;
    h.src.payload = 16;
    try h.src.init();
    var cb = h.block(120);
    cb.enable(1, 0);
    _ = try cb.sweep(h.src.source(), .general_interrogation, 1_700_000_000_000);
    return cb;
}

test "golden: a two-segment report is emitted octet for octet" {
    var h: SegHarness = .{};
    var cb = try segmentGoldenBlock(&h);

    var w = ber.Writer.init(&h.out);
    try testing.expect(try cb.emitNext(h.src.source(), &w));
    try testing.expectEqualSlices(u8, &segmented_report_first, w.done());

    var w2 = ber.Writer.init(&h.out);
    try testing.expect(try cb.emitNext(h.src.source(), &w2));
    try testing.expectEqualSlices(u8, &segmented_report_last, w2.done());

    // Two segments and no more: the report is complete.
    try testing.expect(!try cb.emitNext(h.src.source(), &w2));
}

test "golden: both segments decode and re-encode to the identical octets" {
    for ([_][]const u8{ &segmented_report_first, &segmented_report_last }) |golden| {
        const pdu = try mms.decode(golden);
        const r = try report.decodeInformationReport(pdu.unconfirmed.body);
        try testing.expectEqualStrings("SEG1", r.rpt_id);
        try testing.expectEqual(@as(u32, 0), r.sq_num.?);
        try testing.expectEqual(@as(u32, 3), r.conf_rev.?);
        try testing.expectEqual(@as(u16, 2), r.entry_count);

        var included: [2]Included = undefined;
        for (r.included(), 0..) |e, i| {
            included[i] = .{
                .index = e.index,
                .value = e.value.raw,
                .reason = e.reason.?,
            };
        }
        var buf: [256]u8 = undefined;
        var w = ber.Writer.init(&buf);
        try encode(&w, .{
            .rpt_id = r.rpt_id,
            .opt_flds = r.opt_flds,
            .sq_num = r.sq_num.?,
            .time_of_entry = r.time_of_entry.?,
            .dat_set = r.dat_set.?,
            .entry_id = r.entry_id.?,
            .conf_rev = r.conf_rev.?,
            .sub_seq_num = r.sub_seq_num.?,
            .more_segments_follow = r.more_segments_follow.?,
        }, r.inclusion.bitCount(), &included);
        try testing.expectEqualSlices(u8, golden, w.done());
    }
}

/// Goldens for the reservation attributes, each the complete MMS `Data` TLV a
/// client reads: `Resv` is `boolean [3]`, `ResvTms` is `integer [5]` and
/// `Owner` is `octet-string [9]`.
///
/// `Resv` and `Owner` are **confirmed against a third party**: a live capture of
/// a reference client reading this server's URCB carries `83 01 01` for the
/// `Resv` it had just taken and `89 04 C0 A8 01 01` for `Owner`, and the
/// client's own printout rendered the latter as `c0a80101`. Only the address
/// octets differ from the ones pinned here. `ResvTms` is **self-derived**: it is
/// a BRCB attribute and no reference client writes it.
const golden_resv_true = [_]u8{ 0x83, 0x01, 0x01 };
const golden_resv_tms_30 = [_]u8{ 0x85, 0x01, 0x1E };
const golden_owner_ipv4 = [_]u8{ 0x89, 0x04, 0xC0, 0xA8, 0x01, 0x05 };

test "golden: the reservation attributes are the octets a client reads" {
    var h: Harness = .{};
    try h.src.init();
    var u = h.block(.unbuffered);
    u.resv = true;
    u.owner = 0xC0A8_0105;
    var out: [64]u8 = undefined;

    var w = ber.Writer.init(&out);
    try u.emitAttribute("Resv", &w);
    try testing.expectEqualSlices(u8, &golden_resv_true, w.done());
    try testing.expectEqual(true, try (try mmsdata.Data.decode(&golden_resv_true)).boolean());

    var w2 = ber.Writer.init(&out);
    try u.emitAttribute("Owner", &w2);
    try testing.expectEqualSlices(u8, &golden_owner_ipv4, w2.done());
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xC0, 0xA8, 0x01, 0x05 },
        try (try mmsdata.Data.decode(&golden_owner_ipv4)).octetString(),
    );

    var b = h.block(.buffered);
    b.resv_tms = 30;
    var w3 = ber.Writer.init(&out);
    try b.emitAttribute("ResvTms", &w3);
    try testing.expectEqualSlices(u8, &golden_resv_tms_30, w3.done());
    try testing.expectEqual(
        @as(i16, 30),
        try (try mmsdata.Data.decode(&golden_resv_tms_30)).integer(i16),
    );
}

test "fuzz: an arbitrary segment sequence never panics and never hangs" {
    try std.testing.fuzz({}, fuzzReassemble, .{});
}

fn fuzzReassemble(_: void, smith: *std.testing.Smith) !void {
    var h: SegHarness = .{};
    h.src.members = smith.valueRangeAtMost(u8, 1, 8);
    h.src.payload = smith.valueRangeAtMost(u8, 1, 64);
    h.src.init() catch return;
    var cb = h.block(smith.valueRangeAtMost(u16, 0, 400));
    cb.enable(1, 0);
    _ = cb.sweep(h.src.source(), .general_interrogation, 1000) catch return;

    var slots: [16]report.AssembledEntry = undefined;
    var arena: [512]u8 = undefined;
    var re = report.Reassembler.init(&slots, &arena);
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        var w = ber.Writer.init(&h.out);
        const more = cb.emitNext(h.src.source(), &w) catch break;
        if (!more) break;
        // Randomly drop segments, so the reassembler sees skips as well as
        // ordered runs.
        if (smith.valueRangeAtMost(u8, 0, 3) == 0) continue;
        const pdu = mms.decode(w.done()) catch continue;
        const r = report.decodeInformationReport(pdu.unconfirmed.body) catch continue;
        _ = re.push(r) catch {
            re.reset();
            continue;
        };
    }
}

test "writing back the DatSet a client just read is a no-op, not a ConfRev bump" {
    // Found by a live capture: every reference client writes the whole RCB back
    // when it enables reporting, `DatSet` included. Treating that as a
    // reconfiguration made `ConfRev` climb on every subscription.
    var h: SegHarness = .{};
    try h.src.init();
    var cb = h.block(0);
    cb.data_set = 1;
    var buf: [64]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try mmsdata.Emit.visibleString(&w, "TESTLD/LLN0$Wide");
    const same = try mmsdata.Data.decode(w.done());
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttributeFrom("DatSet", same, h.src.source(), 1, 0));
    try testing.expectEqual(@as(u32, 3), cb.conf_rev);
    try testing.expectEqual(@as(usize, 1), cb.data_set);
    try testing.expectEqual(@as(u8, 0), cb.dat_set_len);

    // …and it is still a no-op once the block has been re-bound, which is when
    // `datSet()` and `dat_set` disagree.
    try cb.rebind(h.src.source(), "TESTLD/LLN0$Events");
    try testing.expectEqual(@as(u32, 4), cb.conf_rev);
    try cb.rebind(h.src.source(), "TESTLD/LLN0$Events");
    try testing.expectEqual(@as(u32, 4), cb.conf_rev);
}

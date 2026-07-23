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
//! **There is no clock.** `BufTm` and `IntgPd` are deadlines the caller advances
//! by calling `tick`, exactly like the control model's `sboTimeout`. Nothing
//! here reads a real clock or owns a thread.
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
};

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

    // state
    rpt_ena: bool = false,
    /// URCB only: the reservation a client takes so a second client cannot
    /// enable the block underneath it.
    resv: bool = false,
    /// URCB, edition 2: the reservation lifetime in seconds. Modelled as a
    /// value, not as a timer — nothing here expires it.
    resv_tms: i16 = 0,
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
        if (self.kind == .unbuffered) {
            self.buffer.clear();
            self.send_cursor = self.next_entry_id;
        }
        self.next_integrity_ms = now_ms +| self.intg_pd_ms;
    }

    pub fn disable(self: *ControlBlock) void {
        self.rpt_ena = false;
        self.owner = null;
        self.gi = false;
        if (self.kind == .unbuffered) self.buffer.clear();
    }

    /// The association went away. A URCB loses everything including its
    /// reservation; a BRCB keeps its buffer — that is the guarantee.
    pub fn associationLost(self: *ControlBlock) void {
        self.disable();
        if (self.kind == .unbuffered) self.resv = false;
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

    /// Encodes the next pending report as a complete `InformationReport` PDU and
    /// advances the block's state. Returns false when nothing is pending.
    ///
    /// `w` is a backwards writer over the caller's buffer; the PDU it leaves is
    /// `w.done()`.
    pub fn emitNext(self: *ControlBlock, src: Source, w: *ber.Writer) Error!bool {
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

        try encode(w, .{
            .rpt_id = if (self.rpt_id.len > 0) self.rpt_id else self.item,
            .opt_flds = self.opt_flds,
            .sq_num = self.sq_num,
            .time_of_entry = binaryTimeFromMillis(e.time_ms),
            .dat_set = self.dat_set,
            .buf_ovfl = self.buffer.overflow,
            .entry_id = &id_bytes,
            .conf_rev = self.conf_rev,
        }, total, included[0..n]);

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
            .unbuffered => &urcb_attributes,
            .buffered => &brcb_attributes,
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
            try mmsdata.Emit.visibleString(w, if (self.rpt_id.len > 0) self.rpt_id else self.item);
        } else if (eq(u8, name, "RptEna")) {
            try mmsdata.Emit.boolean(w, self.rpt_ena);
        } else if (eq(u8, name, "Resv")) {
            try mmsdata.Emit.boolean(w, self.resv);
        } else if (eq(u8, name, "DatSet")) {
            try mmsdata.Emit.visibleString(w, self.dat_set);
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
            var owner: [4]u8 = @splat(0);
            if (self.owner) |o| std.mem.writeInt(u32, &owner, o, .big);
            try mmsdata.Emit.octetString(w, &owner);
        } else return error.BadReportField;
    }

    /// Applies a client write to one attribute.
    pub fn writeAttribute(
        self: *ControlBlock,
        name: []const u8,
        d: mmsdata.Data,
        peer: u32,
        now_ms: u64,
    ) WriteOutcome {
        const eq = std.mem.eql;
        // Another client's reservation locks the block out entirely.
        if (self.kind == .unbuffered and self.resv and self.owner != null and self.owner.? != peer) {
            return .denied;
        }
        if (eq(u8, name, "RptEna")) {
            const v = d.boolean() catch return .invalid;
            if (v) {
                if (self.dat_set.len == 0) return .invalid;
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
            if (v and self.resv and self.owner != null and self.owner.? != peer) return .denied;
            self.resv = v;
            self.owner = if (v) peer else null;
            return .ok;
        }
        if (eq(u8, name, "ResvTms")) {
            if (self.kind != .unbuffered) return .unknown;
            self.resv_tms = d.integer(i16) catch return .invalid;
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
            _ = d.visibleString() catch return .invalid;
            // The reference is borrowed from the request buffer, which the
            // caller owns and will reuse — so the value is validated and
            // dropped rather than aliased.
            return .ok;
        }
        if (eq(u8, name, "DatSet")) {
            _ = d.visibleString() catch return .invalid;
            return .denied;
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

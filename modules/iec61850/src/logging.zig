// SPDX-License-Identifier: MIT

//! IEC 61850 **logging** (IEC 61850-7-2 §18): the log control block, the log
//! itself, and the MMS journal services a client reads it back with.
//!
//! A log is a report that nobody was listening to. The same `TrgOps` decide
//! what goes in, the same data set says what a member is — but instead of an
//! `InformationReport` leaving immediately, the entry is written to a **store**
//! that a client queries later with `ReadJournal`. That is the entire point:
//! a disturbance recorder that survives the client being disconnected.
//!
//! Three shapes matter and all three were taken from a live third-party IED
//! (SPEC.md records exactly which octets):
//!
//! * **The LCB** is an MMS structure of nine members in this order — `LogEna`,
//!   `LogRef`, `DatSet`, `OldEntrTm`, `NewEntrTm`, `OldEntr`, `NewEntr`,
//!   `TrgOps`, `IntgPd`. The four in the middle are the *log's* status, not the
//!   control block's, and reading them is what IEC 61850 calls
//!   `GetLogStatusValues`.
//! * **`ReadJournal`** (MMS service `[65]`) carries the journal's `ObjectName`
//!   plus an optional time range or an `entryToStartAfter`.
//! * **A journal entry** is `{entryIdentifier, originatingApplication,
//!   entryContent{occurrenceTime, listOfVariables}}`, and the list alternates a
//!   member's reference with a pseudo-variable called `ReasonCode` carrying the
//!   same six-bit reason a report would put in `ReasonCode`.
//!
//! **The store is bounded and the bound is the caller's.** `Store.init` takes a
//! slice of entries and a byte arena split into equal slots; when it wraps, the
//! oldest entry is dropped and `OldEntr`/`OldEntrTm` move forward — which is
//! what a real IED's circular log does, and is visible to the client rather than
//! silent. A query that spans the purged range simply returns what is left.
//!
//! Like everything else here there is **no clock**: `IntgPd` is a deadline the
//! caller advances with `tick`.

const std = @import("std");
const ber = @import("ber.zig");
const mms = @import("mms.zig");
const mmsdata = @import("mmsdata.zig");
const report = @import("report.zig");
const reporting = @import("reporting.zig");

pub const TrgOps = report.TrgOps;
pub const Reason = report.Reason;
pub const Trigger = reporting.Trigger;
pub const Source = reporting.Source;

pub const Error = report.Error || error{
    /// The caller gave a store with no entries or unusably small slots.
    LogStoreTooSmall,
    /// One entry's captured values do not fit the slot they were given.
    EntryTooLarge,
    /// More data-set members than one entry can hold.
    TooManyMembers,
    /// The request named a journal this server does not serve.
    UnknownJournal,
};

/// How many `(reference, value)` pairs one log entry holds. Each data-set
/// member contributes one pair plus its `ReasonCode`, so this is twice the
/// largest data set a log can be driven from.
pub const max_entry_variables: usize = 64;

/// The octet length of a log `EntryID`, matching the report engine's.
pub const entry_id_len: usize = reporting.entry_id_len;

/// The pseudo-variable name a journal entry uses to carry the reason a member
/// was logged. It is not a data attribute: it is how IEC 61850 smuggles the
/// report's `ReasonCode` through the MMS journal's flat variable list.
pub const reason_code_tag = "ReasonCode";

/// A log's `ReasonCode` is **seven** bits wide, not the six a report's
/// `ReasonCode` uses: IEC 61850-7-2 adds `application-trigger`, which only a log
/// entry can carry. The captured third-party entries use the seven-bit form, so
/// this encoder does too — a client that assumes six reads the wrong bit.
pub const log_reason_bits: u8 = 7;

/// Emits a report `Reason` in the log's seven-bit form. The extra bit is
/// `application-trigger` and this server never sets it.
pub fn emitLogReason(w: *ber.Writer, r: Reason) Error!void {
    var v: u64 = 0;
    if (r.data_change) v |= @as(u64, 1) << (log_reason_bits - 1 - 1);
    if (r.quality_change) v |= @as(u64, 1) << (log_reason_bits - 1 - 2);
    if (r.data_update) v |= @as(u64, 1) << (log_reason_bits - 1 - 3);
    if (r.integrity) v |= @as(u64, 1) << (log_reason_bits - 1 - 4);
    if (r.general_interrogation) v |= @as(u64, 1) << (log_reason_bits - 1 - 5);
    try w.bitString(mmsdata.Kind.bit_string.tag(), v, log_reason_bits);
}

/// Parses the seven-bit log form back into a report `Reason`. The bit positions
/// are the same; only the width differs.
pub fn parseLogReason(bs: ber.BitString) Reason {
    return Reason.parse(bs);
}

// ── the store ───────────────────────────────────────────────────────────────

/// One log entry: a timestamp, a reason, and the members that caused it.
pub const Entry = struct {
    entry_id: u64 = 0,
    time_ms: u64 = 0,
    reason: Reason = .{},
    count: u8 = 0,
    tag_off: [max_entry_variables]u16 = @splat(0),
    tag_len: [max_entry_variables]u16 = @splat(0),
    val_off: [max_entry_variables]u16 = @splat(0),
    val_len: [max_entry_variables]u16 = @splat(0),
    used: u16 = 0,
};

/// A bounded circular log over caller-owned storage.
pub const Store = struct {
    entries: []Entry,
    arena: []u8,
    slot_len: usize,
    head: usize = 0,
    count: usize = 0,
    /// How many entries have been dropped to make room. A client cannot see
    /// this directly — it sees `OldEntr` having moved — but a test can.
    purged: u64 = 0,

    pub const none = Store{ .entries = &.{}, .arena = &.{}, .slot_len = 0 };

    pub fn init(entries: []Entry, arena: []u8) Error!Store {
        if (entries.len == 0) return error.LogStoreTooSmall;
        const slot = arena.len / entries.len;
        if (slot < 16) return error.LogStoreTooSmall;
        return .{ .entries = entries, .arena = arena, .slot_len = slot };
    }

    pub fn clear(self: *Store) void {
        self.head = 0;
        self.count = 0;
    }

    fn physical(self: *const Store, logical: usize) usize {
        return (self.head + logical) % self.entries.len;
    }

    pub fn at(self: *Store, logical: usize) *Entry {
        return &self.entries[self.physical(logical)];
    }

    pub fn slotOf(self: *Store, logical: usize) []u8 {
        const p = self.physical(logical);
        return self.arena[p * self.slot_len ..][0..self.slot_len];
    }

    fn push(self: *Store) Error!*Entry {
        if (self.entries.len == 0) return error.LogStoreTooSmall;
        if (self.count == self.entries.len) {
            self.head = (self.head + 1) % self.entries.len;
            self.count -= 1;
            self.purged += 1;
        }
        const e = self.at(self.count);
        self.count += 1;
        e.* = .{};
        return e;
    }

    /// Drops the oldest entry — what a journal deletion does, one entry at a
    /// time. It does **not** count as a purge: the client asked for it.
    pub fn dropOldest(self: *Store) void {
        if (self.count == 0) return;
        self.head = (self.head + 1) % self.entries.len;
        self.count -= 1;
    }

    pub fn oldest(self: *Store) ?*Entry {
        return if (self.count == 0) null else self.at(0);
    }

    pub fn newest(self: *Store) ?*Entry {
        return if (self.count == 0) null else self.at(self.count - 1);
    }
};

// ── the log control block ───────────────────────────────────────────────────

/// The attribute names of an LCB, in MMS structure order. Confirmed member by
/// member against a live third-party IED.
pub const lcb_attributes = [_][]const u8{
    "LogEna",  "LogRef",  "DatSet", "OldEntrTm", "NewEntrTm",
    "OldEntr", "NewEntr", "TrgOps", "IntgPd",
};

pub const WriteOutcome = reporting.WriteOutcome;

pub const ControlBlock = struct {
    /// The MMS domain.
    domain: []const u8,
    /// The MMS item prefix, e.g. `LLN0$LG$EventLog`.
    item: []const u8,
    /// The journal's own MMS item id — what a `ReadJournal` names. IEC 61850
    /// spells it `<LN>$<log name>`, i.e. without the `LG` constraint.
    journal: []const u8 = "",
    /// `LogRef`: the ACSI reference of the log, e.g. `LD/LLN0$EventLog`.
    log_ref: []const u8 = "",
    dat_set: []const u8 = "",
    /// Which data set of the `Source` this log records.
    data_set: usize = 0,
    trg_ops: TrgOps = .{},
    intg_pd_ms: u32 = 0,
    store: Store = Store.none,

    // state
    log_ena: bool = false,
    next_entry_id: u64 = 1,
    next_integrity_ms: u64 = 0,
    entries_written: u64 = 0,

    /// Records one member event. Returns false when the log ignored it.
    pub fn signal(
        self: *ControlBlock,
        src: Source,
        data_set: usize,
        member: usize,
        trigger: Trigger,
        now_ms: u64,
    ) Error!bool {
        if (!self.log_ena) return false;
        if (data_set != self.data_set) return false;
        if (!trigger.enabledBy(self.trg_ops)) return false;
        if (self.store.entries.len == 0) return false;
        const total = src.count(self.data_set);
        if (member >= total) return false;

        const e = try self.store.push();
        e.entry_id = self.next_entry_id;
        self.next_entry_id += 1;
        e.time_ms = now_ms;
        e.reason = trigger.toReason();
        try self.capture(src, e, member, trigger);
        self.entries_written += 1;
        return true;
    }

    /// Records every member in one entry — the integrity sweep.
    pub fn sweep(self: *ControlBlock, src: Source, trigger: Trigger, now_ms: u64) Error!bool {
        if (!self.log_ena) return false;
        if (!trigger.enabledBy(self.trg_ops)) return false;
        if (self.store.entries.len == 0) return false;
        const total = src.count(self.data_set);
        if (total == 0) return false;
        if (total * 2 > max_entry_variables) return error.TooManyMembers;

        const e = try self.store.push();
        e.entry_id = self.next_entry_id;
        self.next_entry_id += 1;
        e.time_ms = now_ms;
        e.reason = trigger.toReason();
        var i: usize = 0;
        while (i < total) : (i += 1) try self.capture(src, e, i, trigger);
        self.entries_written += 1;
        return true;
    }

    pub fn tick(self: *ControlBlock, src: Source, now_ms: u64) Error!bool {
        if (!self.log_ena or self.intg_pd_ms == 0 or !self.trg_ops.integrity) return false;
        if (now_ms < self.next_integrity_ms) return false;
        const wrote = try self.sweep(src, .integrity, now_ms);
        self.next_integrity_ms = now_ms +| self.intg_pd_ms;
        return wrote;
    }

    /// Appends the member's reference and value, then the `ReasonCode`
    /// pseudo-variable — the layout a real IED's journal entries use.
    fn capture(self: *ControlBlock, src: Source, e: *Entry, member: usize, trigger: Trigger) Error!void {
        const value = src.value(self.data_set, member) orelse return;
        var ref_buf: [128]u8 = undefined;
        const reference = src.reference(self.data_set, member, &ref_buf) orelse "";
        const slot = self.store.slotOf(self.store.count - 1);

        try self.append(e, slot, reference, value);
        var reason_buf: [8]u8 = undefined;
        var rw = ber.Writer.init(&reason_buf);
        try emitLogReason(&rw, trigger.toReason());
        try self.append(e, slot, reason_code_tag, rw.done());
    }

    fn append(_: *ControlBlock, e: *Entry, slot: []u8, tag: []const u8, value: []const u8) Error!void {
        if (e.count == max_entry_variables) return error.EntryTooLarge;
        if (@as(usize, e.used) + tag.len + value.len > slot.len) return error.EntryTooLarge;
        @memcpy(slot[e.used..][0..tag.len], tag);
        e.tag_off[e.count] = e.used;
        e.tag_len[e.count] = @intCast(tag.len);
        e.used += @intCast(tag.len);
        @memcpy(slot[e.used..][0..value.len], value);
        e.val_off[e.count] = e.used;
        e.val_len[e.count] = @intCast(value.len);
        e.used += @intCast(value.len);
        e.count += 1;
    }

    // ── the LCB as an MMS variable ──────────────────────────────────────────

    pub fn attributes(_: *const ControlBlock) []const []const u8 {
        return &lcb_attributes;
    }

    pub fn emitStructure(self: *ControlBlock, w: *ber.Writer) Error!void {
        const m = w.mark();
        var i: usize = lcb_attributes.len;
        while (i > 0) {
            i -= 1;
            try self.emitAttribute(lcb_attributes[i], w);
        }
        try mmsdata.Emit.structure(w, m);
    }

    pub fn emitAttribute(self: *ControlBlock, name: []const u8, w: *ber.Writer) Error!void {
        const eq = std.mem.eql;
        if (eq(u8, name, "LogEna")) {
            try mmsdata.Emit.boolean(w, self.log_ena);
        } else if (eq(u8, name, "LogRef")) {
            try mmsdata.Emit.visibleString(w, self.log_ref);
        } else if (eq(u8, name, "DatSet")) {
            try mmsdata.Emit.visibleString(w, self.dat_set);
        } else if (eq(u8, name, "OldEntrTm")) {
            const t: u64 = if (self.store.oldest()) |e| e.time_ms else 0;
            try mmsdata.Emit.binaryTime(w, reporting.binaryTimeFromMillis(t));
        } else if (eq(u8, name, "NewEntrTm")) {
            const t: u64 = if (self.store.newest()) |e| e.time_ms else 0;
            try mmsdata.Emit.binaryTime(w, reporting.binaryTimeFromMillis(t));
        } else if (eq(u8, name, "OldEntr")) {
            try emitEntryId(w, if (self.store.oldest()) |e| e.entry_id else 0);
        } else if (eq(u8, name, "NewEntr")) {
            try emitEntryId(w, if (self.store.newest()) |e| e.entry_id else 0);
        } else if (eq(u8, name, "TrgOps")) {
            try self.trg_ops.emit(w);
        } else if (eq(u8, name, "IntgPd")) {
            try mmsdata.Emit.unsigned(w, self.intg_pd_ms);
        } else return error.BadReportField;
    }

    pub fn writeAttribute(self: *ControlBlock, name: []const u8, d: mmsdata.Data, now_ms: u64) WriteOutcome {
        const eq = std.mem.eql;
        if (eq(u8, name, "LogEna")) {
            self.log_ena = d.boolean() catch return .invalid;
            if (self.log_ena) self.next_integrity_ms = now_ms +| self.intg_pd_ms;
            return .ok;
        }
        if (eq(u8, name, "TrgOps")) {
            const bs = d.bitString() catch return .invalid;
            self.trg_ops = TrgOps.parse(bs);
            return .ok;
        }
        if (eq(u8, name, "IntgPd")) {
            self.intg_pd_ms = d.unsigned(u32) catch return .invalid;
            return .ok;
        }
        if (eq(u8, name, "DatSet")) {
            _ = d.visibleString() catch return .invalid;
            // Re-binding a log to another data set at runtime is a
            // reconfiguration this server does not offer.
            return .denied;
        }
        for (lcb_attributes) |a| {
            if (eq(u8, a, name)) return .denied; // the log's own status
        }
        return .unknown;
    }
};

fn emitEntryId(w: *ber.Writer, id: u64) Error!void {
    var buf: [entry_id_len]u8 = undefined;
    std.mem.writeInt(u64, &buf, id, .big);
    try mmsdata.Emit.octetString(w, &buf);
}

// ── the MMS journal services ────────────────────────────────────────────────

/// `ReadJournal` is MMS confirmed service `[65]`; `GetJournalStatus` is `[68]`.
pub const read_journal_service: mms.Service = @enumFromInt(65);
pub const get_journal_status_service: mms.Service = @enumFromInt(68);

/// Where a `ReadJournal` starts and stops. Both halves are optional and a
/// request with neither means "everything".
pub const Range = struct {
    starting_time: ?mmsdata.BinaryTime = null,
    ending_time: ?mmsdata.BinaryTime = null,
    /// `rangeStopSpecification.numberOfEntries`.
    number_of_entries: ?i32 = null,
    /// `rangeStartSpecification.startingEntry`.
    starting_entry: ?[]const u8 = null,
    /// `entryToStartAfter` — the resume form, `{timeSpecification,
    /// entrySpecification}`.
    after_time: ?mmsdata.BinaryTime = null,
    after_entry: ?[]const u8 = null,
};

/// The context tag `entryToStartAfter` arrives under.
///
/// **Observed, not assumed.** A live third-party client sends `[5]` here, which
/// is what this decoder matches; `[4]` is accepted as well because published
/// renderings of the ISO 9506-2 module disagree about the index and a lenient
/// decoder costs nothing.
pub const entry_to_start_after_tag: u32 = 5;

/// The most `listOfVariables` names one query may carry. A filter longer than
/// this is a typed error, not a truncated filter that silently returns more
/// than the client asked for.
pub const max_filter_variables: usize = 16;

/// `listOfVariables` — the tag of the `SEQUENCE OF VisibleString` that narrows a
/// query to particular variables.
///
/// **Self-derived**, from the published ISO 9506-2 layout: no reference client
/// offers the filter, so nothing was observed here. `entryToStartAfter` at `[4]`
/// / `[5]` above *was* observed, and the two do not collide.
pub const list_of_variables_tag: u32 = 3;

pub const ReadJournalRequest = struct {
    journal: mms.ObjectName,
    range: Range = .{},
    /// `listOfVariables`. Empty means "the whole entry", which is what every
    /// client observed here asks for.
    variables: [max_filter_variables][]const u8 = undefined,
    variable_count: u8 = 0,

    pub fn filter(self: *const ReadJournalRequest) []const []const u8 {
        return self.variables[0..self.variable_count];
    }

    /// Whether a stored variable's tag is one the query asked for. An empty
    /// filter matches everything.
    pub fn wants(self: *const ReadJournalRequest, tag: []const u8) bool {
        if (self.variable_count == 0) return true;
        for (self.filter()) |v| {
            if (std.mem.eql(u8, v, tag)) return true;
        }
        return false;
    }
};

/// Encodes a `ReadJournal` request — the client half, so the decoder can be
/// tested against something other than itself.
pub fn encodeReadJournal(
    invoke_id: u32,
    journal: mms.ObjectName,
    range: Range,
    out: []u8,
) Error![]const u8 {
    return encodeReadJournalFiltered(invoke_id, journal, range, &.{}, out);
}

/// `ReadJournal` with a `listOfVariables` filter.
pub fn encodeReadJournalFiltered(
    invoke_id: u32,
    journal: mms.ObjectName,
    range: Range,
    variables: []const []const u8,
    out: []u8,
) Error![]const u8 {
    if (variables.len > max_filter_variables) return error.TooManyEntries;
    var w = ber.Writer.init(out);
    const m = w.mark();
    if (range.after_entry != null or range.after_time != null) {
        const e = w.mark();
        if (range.after_entry) |x| try w.primitive(ber.Tag.ctx(1), x);
        if (range.after_time) |t| try emitTime(&w, ber.Tag.ctx(0), t);
        try w.header(ber.Tag.ctxc(entry_to_start_after_tag), e);
    }
    // `listOfVariables [3]` sits between the stop specification and
    // `entryToStartAfter`, so a backwards writer puts it here.
    if (variables.len > 0) {
        const v = w.mark();
        var i: usize = variables.len;
        while (i > 0) {
            i -= 1;
            try w.primitive(ber.Tag.uni(ber.Universal.visible_string), variables[i]);
        }
        try w.header(ber.Tag.ctxc(list_of_variables_tag), v);
    }
    if (range.ending_time != null or range.number_of_entries != null) {
        const e = w.mark();
        if (range.number_of_entries) |n| try w.integer(ber.Tag.ctx(1), n);
        if (range.ending_time) |t| try emitTime(&w, ber.Tag.ctx(0), t);
        try w.header(ber.Tag.ctxc(2), e);
    }
    if (range.starting_time != null or range.starting_entry != null) {
        const e = w.mark();
        if (range.starting_entry) |x| try w.primitive(ber.Tag.ctx(1), x);
        if (range.starting_time) |t| try emitTime(&w, ber.Tag.ctx(0), t);
        try w.header(ber.Tag.ctxc(1), e);
    }
    const jn = w.mark();
    try journal.encode(&w);
    try w.header(ber.Tag.ctxc(0), jn);
    try mms.closeConfirmedRequest(&w, m, read_journal_service, invoke_id);
    return w.done();
}

pub fn decodeReadJournal(body: []const u8) Error!ReadJournalRequest {
    var r = ReadJournalRequest{ .journal = .{ .vmd_specific = "" } };
    var seen = false;
    var it = ber.Iterator.init(body);
    while (try it.next()) |e| {
        if (e.tag.class != .context) continue;
        switch (e.tag.number) {
            0 => {
                r.journal = try mms.ObjectName.decode(e.content);
                seen = true;
            },
            1 => {
                var s = ber.Iterator.init(e.content);
                while (try s.next()) |f| {
                    switch (f.tag.number) {
                        0 => r.range.starting_time = try mmsdata.BinaryTime.parse(f.content),
                        1 => r.range.starting_entry = f.content,
                        else => {},
                    }
                }
            },
            2 => {
                var s = ber.Iterator.init(e.content);
                while (try s.next()) |f| {
                    switch (f.tag.number) {
                        0 => r.range.ending_time = try mmsdata.BinaryTime.parse(f.content),
                        1 => r.range.number_of_entries = try ber.decodeInt(i32, f.content),
                        else => {},
                    }
                }
            },
            list_of_variables_tag => {
                var s = ber.Iterator.init(e.content);
                while (try s.next()) |f| {
                    if (r.variable_count == max_filter_variables) return error.TooManyEntries;
                    r.variables[r.variable_count] = f.content;
                    r.variable_count += 1;
                }
            },
            4, entry_to_start_after_tag => {
                var s = ber.Iterator.init(e.content);
                while (try s.next()) |f| {
                    switch (f.tag.number) {
                        0 => r.range.after_time = try mmsdata.BinaryTime.parse(f.content),
                        1 => r.range.after_entry = f.content,
                        else => {},
                    }
                }
            },
            else => {},
        }
    }
    if (!seen) return error.MissingField;
    return r;
}

fn emitTime(w: *ber.Writer, tag: ber.Tag, t: mmsdata.BinaryTime) Error!void {
    var buf: [6]u8 = undefined;
    try w.primitive(tag, try t.encode(&buf));
}

/// One `(variableTag, valueSpecification)` pair of a journal entry.
pub const JournalVariable = struct {
    tag: []const u8,
    /// A complete `Data` TLV.
    value: []const u8,
};

/// One journal entry, ready to encode.
pub const JournalEntry = struct {
    entry_id: []const u8,
    occurrence_time: mmsdata.BinaryTime,
    variables: []const JournalVariable,
};

/// Emits one `JournalEntry` (a `SEQUENCE`) into a backwards writer.
fn emitJournalEntry(w: *ber.Writer, e: JournalEntry) Error!void {
    const outer = w.mark();
    // entryContent [2]
    const content = w.mark();
    const form = w.mark();
    const list = w.mark();
    var i: usize = e.variables.len;
    while (i > 0) {
        i -= 1;
        const v = w.mark();
        const spec = w.mark();
        try w.bytes(e.variables[i].value);
        try w.header(ber.Tag.ctxc(1), spec);
        try w.primitive(ber.Tag.ctx(0), e.variables[i].tag);
        try w.header(ber.Tag.sequence, v);
    }
    try w.header(ber.Tag.ctxc(1), list); // listOfVariables [1]
    try w.header(ber.Tag.ctxc(2), form); // entryForm.data [2]
    try emitTime(w, ber.Tag.ctx(0), e.occurrence_time);
    try w.header(ber.Tag.ctxc(2), content);
    // originatingApplication [1]: an empty ApplicationReference, which is what
    // a server that does not track the originator emits.
    const app = w.mark();
    try w.header(ber.Tag.sequence, app);
    try w.header(ber.Tag.ctxc(1), app);
    try w.primitive(ber.Tag.ctx(0), e.entry_id);
    try w.header(ber.Tag.sequence, outer);
}

/// Encodes a `ReadJournal` response over already-built entries.
pub fn encodeReadJournalResponse(
    invoke_id: u32,
    entries: []const JournalEntry,
    more_follows: bool,
    out: []u8,
) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    // `moreFollows` is DEFAULT FALSE and a real IED omits it when false.
    if (more_follows) try w.boolean(ber.Tag.ctx(1), true);
    const list = w.mark();
    var i: usize = entries.len;
    while (i > 0) {
        i -= 1;
        try emitJournalEntry(&w, entries[i]);
    }
    try w.header(ber.Tag.ctxc(0), list);
    try mms.closeConfirmedResponse(&w, m, read_journal_service, invoke_id);
    return w.done();
}

/// The client-side view of one decoded journal entry.
pub const DecodedEntry = struct {
    entry_id: []const u8,
    occurrence_time: ?mmsdata.BinaryTime,
    /// The `listOfVariables` body, walked with `VariableIterator`.
    variables: []const u8,

    pub fn iterate(self: DecodedEntry) VariableIterator {
        return .{ .inner = ber.Iterator.init(self.variables) };
    }
};

pub const VariableIterator = struct {
    inner: ber.Iterator,

    pub fn next(self: *VariableIterator) Error!?JournalVariable {
        const e = (try self.inner.next()) orelse return null;
        var it = ber.Iterator.init(e.content);
        var v = JournalVariable{ .tag = "", .value = "" };
        while (try it.next()) |f| {
            if (f.tag.class != .context) continue;
            switch (f.tag.number) {
                0 => v.tag = f.content,
                1 => v.value = f.content,
                else => {},
            }
        }
        return v;
    }
};

pub const EntryIterator = struct {
    inner: ber.Iterator,

    pub fn next(self: *EntryIterator) Error!?DecodedEntry {
        const e = (try self.inner.next()) orelse return null;
        var out = DecodedEntry{ .entry_id = "", .occurrence_time = null, .variables = "" };
        var it = ber.Iterator.init(e.content);
        while (try it.next()) |f| {
            if (f.tag.class != .context) continue;
            switch (f.tag.number) {
                0 => out.entry_id = f.content,
                2 => {
                    var c = ber.Iterator.init(f.content);
                    while (try c.next()) |g| {
                        if (g.tag.class != .context) continue;
                        switch (g.tag.number) {
                            0 => out.occurrence_time = try mmsdata.BinaryTime.parse(g.content),
                            2 => {
                                var d = ber.Iterator.init(g.content);
                                while (try d.next()) |h| {
                                    if (h.tag.eql(ber.Tag.ctxc(1))) out.variables = h.content;
                                }
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }
        return out;
    }
};

pub const ReadJournalResponse = struct {
    entries: EntryIterator,
    more_follows: bool,
};

pub fn decodeReadJournalResponse(body: []const u8) Error!ReadJournalResponse {
    var r = ReadJournalResponse{ .entries = .{ .inner = ber.Iterator.init("") }, .more_follows = false };
    var it = ber.Iterator.init(body);
    while (try it.next()) |e| {
        if (e.tag.class != .context) continue;
        switch (e.tag.number) {
            0 => r.entries = .{ .inner = ber.Iterator.init(e.content) },
            1 => r.more_follows = try ber.decodeBool(e.content),
            else => {},
        }
    }
    return r;
}

/// `GetJournalStatus` — how many entries the journal currently holds and how
/// many it can.
///
/// **Self-derived.** IEC 61850's own `GetLogStatusValues` is served by *reading
/// the LCB* (`OldEntr`/`NewEntr`/`OldEntrTm`/`NewEntrTm`), which is the path
/// that is driven against a third party here. The MMS `[68]` service below is
/// the ISO 9506 one, encoded from the published layout and cross-checked
/// against the Wireshark MMS dissector — no peer was observed sending it.
pub const JournalStatus = struct {
    current_entries: u32,
    limit_entries: ?u32 = null,
};

pub fn encodeGetJournalStatus(invoke_id: u32, journal: mms.ObjectName, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try journal.encode(&w);
    try mms.closeConfirmedRequest(&w, m, get_journal_status_service, invoke_id);
    return w.done();
}

pub fn decodeGetJournalStatus(body: []const u8) Error!mms.ObjectName {
    return mms.ObjectName.decode(body);
}

pub fn encodeGetJournalStatusResponse(invoke_id: u32, s: JournalStatus, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    if (s.limit_entries) |l| try w.unsigned(ber.Tag.ctx(1), l);
    try w.unsigned(ber.Tag.ctx(0), s.current_entries);
    try mms.closeConfirmedResponse(&w, m, get_journal_status_service, invoke_id);
    return w.done();
}

pub fn decodeGetJournalStatusResponse(body: []const u8) Error!JournalStatus {
    var s = JournalStatus{ .current_entries = 0 };
    var it = ber.Iterator.init(body);
    while (try it.next()) |e| {
        if (e.tag.class != .context) continue;
        switch (e.tag.number) {
            0 => s.current_entries = try ber.decodeUint(u32, e.content),
            1 => s.limit_entries = try ber.decodeUint(u32, e.content),
            else => {},
        }
    }
    return s;
}

// ── answering a query out of the store ──────────────────────────────────────

/// The largest number of entries one `ReadJournal` response carries. A query
/// that matches more sets `moreFollows` and the client asks again with
/// `entryToStartAfter`.
pub const max_entries_per_response: usize = 16;

/// Answers a `ReadJournal` out of a `ControlBlock`'s store. `out` receives the
/// complete response PDU.
pub fn answerReadJournal(
    lcb: *ControlBlock,
    req: ReadJournalRequest,
    invoke_id: u32,
    out: []u8,
) Error![]const u8 {
    var entries: [max_entries_per_response]JournalEntry = undefined;
    var vars: [max_entries_per_response][max_entry_variables]JournalVariable = undefined;
    var ids: [max_entries_per_response][entry_id_len]u8 = undefined;
    var n: usize = 0;
    var more = false;

    // `entryToStartAfter` wins over a time range: it is the resume form and a
    // client that uses it has already seen everything up to that entry.
    var after: ?u64 = null;
    if (req.range.after_entry) |raw| {
        var id: u64 = 0;
        for (raw) |b| id = (id << 8) | b;
        after = id;
    } else if (req.range.starting_entry) |raw| {
        var id: u64 = 0;
        for (raw) |b| id = (id << 8) | b;
        // `startingEntry` is inclusive, `entryToStartAfter` is not.
        after = if (id == 0) 0 else id - 1;
    }

    var i: usize = 0;
    while (i < lcb.store.count) : (i += 1) {
        const e = lcb.store.at(i);
        if (after) |a| {
            if (e.entry_id <= a) continue;
        } else {
            if (req.range.starting_time) |t| {
                if (e.time_ms < millisOf(t)) continue;
            }
        }
        if (req.range.ending_time) |t| {
            if (e.time_ms > millisOf(t)) continue;
        }
        if (req.range.number_of_entries) |limit| {
            if (limit >= 0 and n >= @as(usize, @intCast(limit))) {
                more = true;
                break;
            }
        }
        if (n == max_entries_per_response) {
            more = true;
            break;
        }
        const slot = lcb.store.slotOf(i);
        var k: usize = 0;
        var kept: usize = 0;
        while (k < e.count) : (k += 1) {
            const tag = slot[e.tag_off[k]..][0..e.tag_len[k]];
            // `listOfVariables`: an entry is returned only if it carries at
            // least one of the named variables, and only those are put in it.
            // An empty filter keeps everything, which is the observed case.
            if (!req.wants(tag)) continue;
            vars[n][kept] = .{
                .tag = tag,
                .value = slot[e.val_off[k]..][0..e.val_len[k]],
            };
            kept += 1;
        }
        if (kept == 0) continue;
        std.mem.writeInt(u64, &ids[n], e.entry_id, .big);
        entries[n] = .{
            .entry_id = &ids[n],
            .occurrence_time = reporting.binaryTimeFromMillis(e.time_ms),
            .variables = vars[n][0..kept],
        };
        n += 1;
    }
    return encodeReadJournalResponse(invoke_id, entries[0..n], more, out);
}

// ── the journal deletion services ───────────────────────────────────────────

/// `InitializeJournal` is MMS confirmed service `[67]` and `DeleteJournal` is
/// `[70]`. Both are **self-derived** from the published ISO 9506-2 layout: no
/// reference client offers either, so neither was observed on a wire. They are
/// round-tripped against this module's own decoders and dissected by Wireshark.
pub const initialize_journal_service: mms.Service = @enumFromInt(67);
pub const delete_journal_service: mms.Service = @enumFromInt(70);

/// How far an `InitializeJournal` deletes. Absent halves mean "no bound", so a
/// request with neither empties the journal.
pub const Limit = struct {
    /// `limitingTime` — entries at or before this time go.
    limiting_time: ?mmsdata.BinaryTime = null,
    /// `limitingEntry` — entries up to and including this `EntryID` go.
    limiting_entry: ?[]const u8 = null,
};

pub const InitializeJournalRequest = struct {
    journal: mms.ObjectName,
    limit: Limit = .{},
};

pub fn encodeInitializeJournal(
    invoke_id: u32,
    journal: mms.ObjectName,
    limit: Limit,
    out: []u8,
) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    if (limit.limiting_time != null or limit.limiting_entry != null) {
        const e = w.mark();
        if (limit.limiting_entry) |x| try w.primitive(ber.Tag.ctx(1), x);
        if (limit.limiting_time) |t| try emitTime(&w, ber.Tag.ctx(0), t);
        try w.header(ber.Tag.ctxc(1), e);
    }
    const jn = w.mark();
    try journal.encode(&w);
    try w.header(ber.Tag.ctxc(0), jn);
    try mms.closeConfirmedRequest(&w, m, initialize_journal_service, invoke_id);
    return w.done();
}

pub fn decodeInitializeJournal(body: []const u8) Error!InitializeJournalRequest {
    var r = InitializeJournalRequest{ .journal = .{ .vmd_specific = "" } };
    var seen = false;
    var it = ber.Iterator.init(body);
    while (try it.next()) |e| {
        if (e.tag.class != .context) continue;
        switch (e.tag.number) {
            0 => {
                r.journal = try mms.ObjectName.decode(e.content);
                seen = true;
            },
            1 => {
                var s = ber.Iterator.init(e.content);
                while (try s.next()) |f| {
                    switch (f.tag.number) {
                        0 => r.limit.limiting_time = try mmsdata.BinaryTime.parse(f.content),
                        1 => r.limit.limiting_entry = f.content,
                        else => {},
                    }
                }
            },
            else => {},
        }
    }
    if (!seen) return error.MissingField;
    return r;
}

pub fn encodeInitializeJournalResponse(invoke_id: u32, deleted: u32, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try w.unsigned(ber.Tag.ctx(0), deleted);
    try mms.closeConfirmedResponse(&w, m, initialize_journal_service, invoke_id);
    return w.done();
}

pub fn decodeInitializeJournalResponse(body: []const u8) Error!u32 {
    var it = ber.Iterator.init(body);
    while (try it.next()) |e| {
        if (e.tag.class == .context and e.tag.number == 0) return ber.decodeUint(u32, e.content);
    }
    return error.MissingField;
}

pub fn encodeDeleteJournal(invoke_id: u32, journal: mms.ObjectName, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try journal.encode(&w);
    try mms.closeConfirmedRequest(&w, m, delete_journal_service, invoke_id);
    return w.done();
}

pub fn decodeDeleteJournal(body: []const u8) Error!mms.ObjectName {
    return mms.ObjectName.decode(body);
}

/// `DeleteJournal-Response ::= NULL` — an empty body.
pub fn encodeDeleteJournalResponse(invoke_id: u32, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const m = w.mark();
    try mms.closeConfirmedResponse(&w, m, delete_journal_service, invoke_id);
    return w.done();
}

/// Deletes the oldest entries a limit covers and returns how many went.
///
/// A journal deletes from the **oldest end**: that is what a bounded circular
/// store can do without leaving holes, and what `limitingTime` /
/// `limitingEntry` describe. A limit that reaches past entries the store has
/// already purged deletes what survives and reports that count — spanning the
/// purge boundary is not an error, because from the client's point of view the
/// purged entries are already gone.
pub fn initializeJournal(lcb: *ControlBlock, limit: Limit) u32 {
    var until_id: ?u64 = null;
    if (limit.limiting_entry) |raw| {
        var id: u64 = 0;
        for (raw) |b| id = (id << 8) | b;
        until_id = id;
    }
    const until_ms: ?u64 = if (limit.limiting_time) |t| millisOf(t) else null;
    const unbounded = until_id == null and until_ms == null;

    var deleted: u32 = 0;
    while (lcb.store.count > 0) {
        const e = lcb.store.at(0);
        const covered = unbounded or
            (until_id != null and e.entry_id <= until_id.?) or
            (until_ms != null and e.time_ms <= until_ms.?);
        if (!covered) break;
        lcb.store.dropOldest();
        deleted += 1;
    }
    return deleted;
}

fn millisOf(t: mmsdata.BinaryTime) u64 {
    const epoch_1984_days: u64 = 5114;
    const days: u64 = (t.days_since_1984 orelse 0) + epoch_1984_days;
    return days * mmsdata.BinaryTime.ms_per_day + t.ms_since_midnight;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// **Third-party golden.** A `ReadJournal` request a real IEC 61850 stack sent,
/// as the service body (inside the `[65]` tag): the journal's `ObjectName`, a
/// starting time and an ending time.
const oracle_read_journal_request = [_]u8{
    0xA0, 0x24, 0xA1, 0x22,
    0x1A, 0x11, 's',  'i',
    'm',  'p',  'l',  'e',
    'I',  'O',  'G',  'e',
    'n',  'e',  'r',  'i',
    'c',  'I',  'O',  0x1A,
    0x0D, 'L',  'L',  'N',
    '0',  '$',  'E',  'v',
    'e',  'n',  't',  'L',
    'o',  'g',  0xA1, 0x08,
    0x80, 0x06, 0x00, 0xC1,
    0x84, 0xE1, 0x3C, 0x73,
    0xA2, 0x08, 0x80, 0x06,
    0x03, 0x0B, 0x74, 0xE1,
    0x3C, 0xB8,
};

/// **Third-party golden.** The `ReadJournal` response that IED sent back: one
/// entry, four variables, the `ReasonCode` pseudo-variable after each real one.
const oracle_read_journal_response = [_]u8{
    0xA0, 0x81, 0xAD, 0x30,
    0x81, 0xAA, 0x80, 0x08,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xA1, 0x02, 0x30, 0x00,
    0xA2, 0x81, 0x99, 0x80,
    0x06, 0x03, 0x0A, 0x2F,
    0xED, 0x3C, 0xB8, 0xA2,
    0x81, 0x8E, 0xA1, 0x81,
    0x8B, 0x30, 0x2E, 0x80,
    0x27, 's',  'i',  'm',
    'p',  'l',  'e',  'I',
    'O',  'G',  'e',  'n',
    'e',  'r',  'i',  'o',
    'I',  'O',  '/',  'G',
    'P',  'I',  'O',  '1',
    '$',  'S',  'T',  '$',
    'S',  'P',  'C',  'S',
    'O',  '1',  '$',  's',
    't',  'V',  'a',  'l',
    0xA1, 0x03, 0x85, 0x01,
    0x7B, 0x30, 0x12, 0x80,
    0x0A, 'R',  'e',  'a',
    's',  'o',  'n',  'C',
    'o',  'd',  'e',  0xA1,
    0x04, 0x84, 0x02, 0x01,
    0x00, 0x30, 0x31, 0x80,
    0x23, 's',  'i',  'm',
    'p',  'l',  'e',  'I',
    'O',  'G',  'e',  'n',
    'e',  'r',  'i',  'o',
    'I',  'O',  '/',  'G',
    'P',  'I',  'O',  '1',
    '$',  'S',  'T',  '$',
    'S',  'P',  'C',  'S',
    'O',  '1',  '$',  't',
    0xA1, 0x0A, 0x91, 0x08,
    0x6A, 0x62, 0x20, 0xB7,
    0x46, 0xE9, 0x78, 0x0A,
    0x30, 0x12, 0x80, 0x0A,
    'R',  'e',  'a',  's',
    'o',  'n',  'C',  'o',
    'd',  'e',  0xA1, 0x04,
    0x84, 0x02, 0x01, 0x00,
};

test "the captured ReadJournal request decodes field by field" {
    const r = try decodeReadJournal(&oracle_read_journal_request);
    try testing.expectEqualStrings("simpleIOGenericIO", r.journal.domain_specific.domain);
    try testing.expectEqualStrings("LLN0$EventLog", r.journal.domain_specific.item);
    try testing.expectEqual(@as(u32, 0x00C184E1), r.range.starting_time.?.ms_since_midnight);
    try testing.expectEqual(@as(u16, 0x3C73), r.range.starting_time.?.days_since_1984.?);
    try testing.expectEqual(@as(u32, 0x030B74E1), r.range.ending_time.?.ms_since_midnight);
    try testing.expectEqual(@as(u16, 0x3CB8), r.range.ending_time.?.days_since_1984.?);
    try testing.expect(r.range.after_entry == null);
}

test "our encoder rebuilds the captured ReadJournal request octet for octet" {
    var buf: [256]u8 = undefined;
    const pdu = try encodeReadJournal(1, .{ .domain_specific = .{
        .domain = "simpleIOGenericIO",
        .item = "LLN0$EventLog",
    } }, .{
        .starting_time = .{ .ms_since_midnight = 0x00C184E1, .days_since_1984 = 0x3C73 },
        .ending_time = .{ .ms_since_midnight = 0x030B74E1, .days_since_1984 = 0x3CB8 },
    }, &buf);
    const req = (try mms.decode(pdu)).confirmed_request;
    try testing.expectEqual(read_journal_service, req.service);
    try testing.expectEqualSlices(u8, &oracle_read_journal_request, req.body);
}

test "the captured ReadJournal response decodes entry by entry" {
    const r = try decodeReadJournalResponse(&oracle_read_journal_response);
    try testing.expect(!r.more_follows);
    var it = r.entries;
    const e = (try it.next()).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 }, e.entry_id);
    try testing.expectEqual(@as(u16, 0x3CB8), e.occurrence_time.?.days_since_1984.?);

    var vars = e.iterate();
    const a = (try vars.next()).?;
    try testing.expectEqualStrings("simpleIOGenerioIO/GPIO1$ST$SPCSO1$stVal", a.tag);
    try testing.expectEqual(@as(i32, 123), try (try mmsdata.Data.decode(a.value)).integer(i32));
    const b = (try vars.next()).?;
    try testing.expectEqualStrings(reason_code_tag, b.tag);
    const bits = try (try mmsdata.Data.decode(b.value)).bitString();
    // Seven bits, not six — the log form. That IED left every one of them
    // clear, which is itself worth recording: a log entry may carry no reason.
    try testing.expectEqual(@as(usize, log_reason_bits), bits.bitCount());
    try testing.expect(!parseLogReason(bits).any());
    const c = (try vars.next()).?;
    try testing.expectEqualStrings("simpleIOGenerioIO/GPIO1$ST$SPCSO1$t", c.tag);
    try testing.expectEqual(mmsdata.Kind.utc_time, (try mmsdata.Data.decode(c.value)).kind);
    _ = (try vars.next()).?; // the second ReasonCode
    try testing.expect((try vars.next()) == null);
    try testing.expect((try it.next()) == null);
}

test "our encoder rebuilds the captured ReadJournal response octet for octet" {
    // The four variables of that entry, rebuilt from their decoded parts.
    var v1: [8]u8 = undefined;
    var w1 = ber.Writer.init(&v1);
    try mmsdata.Emit.integer(&w1, 123);
    // The captured `ReasonCode` verbatim: a seven-bit bit string with nothing
    // set. It is an opaque `Data` value as far as the journal framing goes.
    const reason_value = [_]u8{ 0x84, 0x02, 0x01, 0x00 };
    const utc = [_]u8{ 0x91, 0x08, 0x6A, 0x62, 0x20, 0xB7, 0x46, 0xE9, 0x78, 0x0A };

    const vars = [_]JournalVariable{
        .{ .tag = "simpleIOGenerioIO/GPIO1$ST$SPCSO1$stVal", .value = w1.done() },
        .{ .tag = reason_code_tag, .value = &reason_value },
        .{ .tag = "simpleIOGenerioIO/GPIO1$ST$SPCSO1$t", .value = &utc },
        .{ .tag = reason_code_tag, .value = &reason_value },
    };
    const id = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };
    const entries = [_]JournalEntry{.{
        .entry_id = &id,
        .occurrence_time = .{ .ms_since_midnight = 0x030A2FED, .days_since_1984 = 0x3CB8 },
        .variables = &vars,
    }};
    var buf: [1024]u8 = undefined;
    const pdu = try encodeReadJournalResponse(3, &entries, false, &buf);
    const resp = (try mms.decode(pdu)).confirmed_response;
    try testing.expectEqualSlices(u8, &oracle_read_journal_response, resp.body);
}

// ── the log control block and store ─────────────────────────────────────────

const TestSource = struct {
    values: [3][8]u8 = undefined,
    lens: [3]usize = @splat(0),
    refs: [3][]const u8 = .{
        "TESTLD/GGIO1$ST$Ind1$stVal",
        "TESTLD/GGIO1$ST$Ind2$stVal",
        "TESTLD/GGIO1$ST$Ind3$stVal",
    },

    fn init(self: *TestSource) !void {
        for (0..3) |i| try self.set(i, false);
    }
    fn set(self: *TestSource, i: usize, v: bool) !void {
        var w = ber.Writer.init(&self.values[i]);
        try mmsdata.Emit.boolean(&w, v);
        const d = w.done();
        std.mem.copyForwards(u8, self.values[i][0..d.len], d);
        self.lens[i] = d.len;
    }
    fn source(self: *TestSource) Source {
        return .{ .ctx = self, .vtable = &.{ .count = countFn, .value = valueFn, .reference = referenceFn } };
    }
    fn countFn(_: *anyopaque, _: usize) usize {
        return 3;
    }
    fn valueFn(ctx: *anyopaque, _: usize, m: usize) ?[]const u8 {
        const self: *TestSource = @ptrCast(@alignCast(ctx));
        if (m >= 3) return null;
        return self.values[m][0..self.lens[m]];
    }
    fn referenceFn(ctx: *anyopaque, _: usize, m: usize, out: []u8) ?[]const u8 {
        const self: *TestSource = @ptrCast(@alignCast(ctx));
        if (m >= 3) return null;
        const r = self.refs[m];
        if (r.len > out.len) return null;
        @memcpy(out[0..r.len], r);
        return out[0..r.len];
    }
};

const Harness = struct {
    src: TestSource = .{},
    entries: [4]Entry = @splat(.{}),
    arena: [4 * 256]u8 = undefined,
    out: [4096]u8 = undefined,

    fn lcb(self: *Harness) ControlBlock {
        return .{
            .domain = "TESTLD",
            .item = "LLN0$LG$EventLog",
            .journal = "LLN0$EventLog",
            .log_ref = "TESTLD/LLN0$EventLog",
            .dat_set = "TESTLD/LLN0$Events",
            .trg_ops = .{ .data_change = true, .quality_change = true, .integrity = true },
            .store = Store.init(&self.entries, &self.arena) catch unreachable,
        };
    }
};

test "a log records what its TrgOps allow and nothing else" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    // A disabled log records nothing at all.
    try testing.expect(!try lcb.signal(h.src.source(), 0, 0, .data_change, 1));
    lcb.log_ena = true;
    try testing.expect(try lcb.signal(h.src.source(), 0, 0, .data_change, 10));
    try testing.expect(!try lcb.signal(h.src.source(), 0, 0, .data_update, 11));
    try testing.expectEqual(@as(usize, 1), lcb.store.count);

    const e = lcb.store.newest().?;
    try testing.expectEqual(@as(u8, 2), e.count); // the member and its ReasonCode
    try testing.expect(e.reason.data_change);
}

test "the log store is bounded and the oldest entry falls out" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    lcb.log_ena = true;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        try h.src.set(i % 3, i % 2 == 0);
        _ = try lcb.signal(h.src.source(), 0, i % 3, .data_change, 100 + i);
    }
    try testing.expectEqual(@as(usize, 4), lcb.store.count);
    try testing.expectEqual(@as(u64, 6), lcb.store.purged);
    try testing.expectEqual(@as(u64, 7), lcb.store.oldest().?.entry_id);
    try testing.expectEqual(@as(u64, 10), lcb.store.newest().?.entry_id);
}

test "a query that spans a purge returns what is left, not an error" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    lcb.log_ena = true;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        try h.src.set(i % 3, i % 2 == 0);
        _ = try lcb.signal(h.src.source(), 0, i % 3, .data_change, 100 + i);
    }
    // Resume after entry 2 — long gone.
    var after: [entry_id_len]u8 = undefined;
    std.mem.writeInt(u64, &after, 2, .big);
    const pdu = try answerReadJournal(&lcb, .{
        .journal = .{ .domain_specific = .{ .domain = "TESTLD", .item = "LLN0$EventLog" } },
        .range = .{ .after_entry = &after },
    }, 5, &h.out);
    const resp = (try mms.decode(pdu)).confirmed_response;
    const r = try decodeReadJournalResponse(resp.body);
    var it = r.entries;
    var n: usize = 0;
    var first: u64 = 0;
    while (try it.next()) |e| : (n += 1) {
        if (n == 0) first = std.mem.readInt(u64, e.entry_id[0..8], .big);
    }
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqual(@as(u64, 7), first);
}

test "a time range selects the entries inside it" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    lcb.log_ena = true;
    const base: u64 = 1_700_000_000_000;
    for (0..3) |i| {
        try h.src.set(i, true);
        _ = try lcb.signal(h.src.source(), 0, i, .data_change, base + i * 1000);
    }
    const pdu = try answerReadJournal(&lcb, .{
        .journal = .{ .domain_specific = .{ .domain = "TESTLD", .item = "LLN0$EventLog" } },
        .range = .{
            .starting_time = reporting.binaryTimeFromMillis(base + 1000),
            .ending_time = reporting.binaryTimeFromMillis(base + 1999),
        },
    }, 1, &h.out);
    const resp = (try mms.decode(pdu)).confirmed_response;
    const r = try decodeReadJournalResponse(resp.body);
    var it = r.entries;
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 1), n);
}

test "numberOfEntries caps the response and sets moreFollows" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    lcb.log_ena = true;
    for (0..3) |i| {
        try h.src.set(i, true);
        _ = try lcb.signal(h.src.source(), 0, i, .data_change, 10 + i);
    }
    const pdu = try answerReadJournal(&lcb, .{
        .journal = .{ .domain_specific = .{ .domain = "TESTLD", .item = "LLN0$EventLog" } },
        .range = .{ .number_of_entries = 2 },
    }, 1, &h.out);
    const resp = (try mms.decode(pdu)).confirmed_response;
    const r = try decodeReadJournalResponse(resp.body);
    try testing.expect(r.more_follows);
    var it = r.entries;
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 2), n);
}

test "the LCB structure this server emits carries the nine members in order" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    lcb.log_ena = true;
    _ = try lcb.signal(h.src.source(), 0, 0, .data_change, 1_700_000_000_000);

    var buf: [512]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try lcb.emitStructure(&w);
    const d = try mmsdata.Data.decode(w.done());
    try d.validate();
    var it = try d.members();
    try testing.expectEqual(true, try (try it.next()).?.boolean()); // LogEna
    try testing.expectEqualStrings("TESTLD/LLN0$EventLog", try (try it.next()).?.visibleString());
    try testing.expectEqualStrings("TESTLD/LLN0$Events", try (try it.next()).?.visibleString());
    _ = try (try it.next()).?.binaryTime(); // OldEntrTm
    _ = try (try it.next()).?.binaryTime(); // NewEntrTm
    const old = try (try it.next()).?.octetString();
    const new = try (try it.next()).?.octetString();
    try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, old[0..8], .big));
    try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, new[0..8], .big));
    const trg = TrgOps.parse(try (try it.next()).?.bitString());
    try testing.expect(trg.data_change);
    try testing.expectEqual(@as(u32, 0), try (try it.next()).?.unsigned(u32));
    try testing.expect((try it.next()) == null);
}

test "GetJournalStatus round trips" {
    var buf: [128]u8 = undefined;
    const req = try encodeGetJournalStatus(9, .{ .domain_specific = .{
        .domain = "TESTLD",
        .item = "LLN0$EventLog",
    } }, &buf);
    const decoded = (try mms.decode(req)).confirmed_request;
    try testing.expectEqual(get_journal_status_service, decoded.service);
    const name = try decodeGetJournalStatus(decoded.body);
    try testing.expectEqualStrings("LLN0$EventLog", name.domain_specific.item);

    var rbuf: [128]u8 = undefined;
    const resp = try encodeGetJournalStatusResponse(9, .{ .current_entries = 4, .limit_entries = 16 }, &rbuf);
    const dr = (try mms.decode(resp)).confirmed_response;
    const s = try decodeGetJournalStatusResponse(dr.body);
    try testing.expectEqual(@as(u32, 4), s.current_entries);
    try testing.expectEqual(@as(u32, 16), s.limit_entries.?);
}

test "an entry too large for its slot is a typed error, not a truncation" {
    var src: TestSource = .{};
    try src.init();
    var entries: [2]Entry = @splat(.{});
    var arena: [2 * 20]u8 = undefined; // 20 bytes a slot
    var lcb = ControlBlock{
        .domain = "TESTLD",
        .item = "LLN0$LG$EventLog",
        .trg_ops = .{ .integrity = true },
        .store = try Store.init(&entries, &arena),
        .log_ena = true,
    };
    try testing.expectError(error.EntryTooLarge, lcb.sweep(src.source(), .integrity, 1));
    try testing.expectError(error.LogStoreTooSmall, Store.init(&.{}, &.{}));
}

test "a log with no store simply records nothing" {
    var src: TestSource = .{};
    try src.init();
    var lcb = ControlBlock{
        .domain = "TESTLD",
        .item = "LLN0$LG$EventLog",
        .trg_ops = .{ .data_change = true },
        .log_ena = true,
    };
    try testing.expect(!try lcb.signal(src.source(), 0, 0, .data_change, 1));
}

test "the integrity period writes one entry a period" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    lcb.intg_pd_ms = 500;
    lcb.log_ena = true;
    lcb.next_integrity_ms = 500;
    try testing.expect(!try lcb.tick(h.src.source(), 499));
    try testing.expect(try lcb.tick(h.src.source(), 500));
    try testing.expectEqual(@as(u8, 6), lcb.store.newest().?.count); // 3 members × 2
    try testing.expect(!try lcb.tick(h.src.source(), 900));
    try testing.expect(try lcb.tick(h.src.source(), 1000));
}

test "fuzz: journal decoding never panics" {
    try std.testing.fuzz({}, fuzzJournal, .{});
}

fn fuzzJournal(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeReadJournal(buf[0..len]) catch {};
    if (decodeReadJournalResponse(buf[0..len])) |r| {
        var it = r.entries;
        while (it.next() catch null) |e| {
            var v = e.iterate();
            while (v.next() catch null) |_| {}
        }
    } else |_| {}
    _ = decodeGetJournalStatus(buf[0..len]) catch {};
    _ = decodeGetJournalStatusResponse(buf[0..len]) catch {};
}

// ── listOfVariables filtering ───────────────────────────────────────────────

/// Walks a `ReadJournal` response and counts entries and variable tags.
fn journalShape(body: []const u8) !struct { entries: usize, variables: usize, first_tag: []const u8 } {
    const resp = (try mms.decode(body)).confirmed_response;
    const r = try decodeReadJournalResponse(resp.body);
    var it = r.entries;
    var entries: usize = 0;
    var variables: usize = 0;
    var first_tag: []const u8 = "";
    while (try it.next()) |e| : (entries += 1) {
        var vars = e.iterate();
        while (try vars.next()) |v| {
            if (first_tag.len == 0) first_tag = v.tag;
            variables += 1;
        }
    }
    return .{ .entries = entries, .variables = variables, .first_tag = first_tag };
}

test "listOfVariables narrows a query to the variables it names" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    lcb.log_ena = true;
    _ = try lcb.signal(h.src.source(), 0, 0, .data_change, 100);
    _ = try lcb.signal(h.src.source(), 0, 1, .data_change, 200);

    const query = ReadJournalRequest{
        .journal = .{ .domain_specific = .{ .domain = "TESTLD", .item = "LLN0$EventLog" } },
    };
    // Unfiltered: two entries, each the member plus its ReasonCode.
    const all = try journalShape(try answerReadJournal(&lcb, query, 1, &h.out));
    try testing.expectEqual(@as(usize, 2), all.entries);
    try testing.expectEqual(@as(usize, 4), all.variables);

    // Filtered to one member's reference: one entry, one variable.
    var one = query;
    one.variables[0] = h.src.refs[1];
    one.variable_count = 1;
    const got = try journalShape(try answerReadJournal(&lcb, one, 2, &h.out));
    try testing.expectEqual(@as(usize, 1), got.entries);
    try testing.expectEqual(@as(usize, 1), got.variables);
    try testing.expectEqualStrings(h.src.refs[1], got.first_tag);

    // Filtered to `ReasonCode` alone: both entries, one variable each.
    var reasons = query;
    reasons.variables[0] = reason_code_tag;
    reasons.variable_count = 1;
    const only = try journalShape(try answerReadJournal(&lcb, reasons, 3, &h.out));
    try testing.expectEqual(@as(usize, 2), only.entries);
    try testing.expectEqual(@as(usize, 2), only.variables);
    try testing.expectEqualStrings(reason_code_tag, only.first_tag);

    // A filter naming nothing the log holds returns no entries at all — never
    // an error, and never the whole log.
    var none = query;
    none.variables[0] = "TESTLD/GGIO9$ST$Nope$stVal";
    none.variable_count = 1;
    const empty = try journalShape(try answerReadJournal(&lcb, none, 4, &h.out));
    try testing.expectEqual(@as(usize, 0), empty.entries);
}

test "a listOfVariables filter survives the request encoder and decoder" {
    var buf: [512]u8 = undefined;
    const names = [_][]const u8{ "TESTLD/GGIO1$ST$Ind1$stVal", reason_code_tag };
    const pdu = try encodeReadJournalFiltered(
        9,
        .{ .domain_specific = .{ .domain = "TESTLD", .item = "LLN0$EventLog" } },
        .{ .number_of_entries = 4 },
        &names,
        &buf,
    );
    const req = (try mms.decode(pdu)).confirmed_request;
    const q = try decodeReadJournal(req.body);
    try testing.expectEqual(@as(u8, 2), q.variable_count);
    try testing.expectEqualStrings(names[0], q.filter()[0]);
    try testing.expectEqualStrings(names[1], q.filter()[1]);
    try testing.expectEqual(@as(i32, 4), q.range.number_of_entries.?);
    try testing.expect(q.wants(names[0]));
    try testing.expect(!q.wants("something else"));

    // And it re-encodes to the identical octets.
    var again: [512]u8 = undefined;
    const round = try encodeReadJournalFiltered(9, q.journal, q.range, q.filter(), &again);
    try testing.expectEqualSlices(u8, pdu, round);

    // A filter longer than the fixed table is a typed error on both sides.
    const many: [max_filter_variables + 1][]const u8 = @splat("x");
    try testing.expectError(error.TooManyEntries, encodeReadJournalFiltered(
        9,
        q.journal,
        .{},
        &many,
        &buf,
    ));
}

// ── deleting log entries ────────────────────────────────────────────────────

fn fillLog(h: *Harness, lcb: *ControlBlock, n: usize, base: u64) !void {
    lcb.log_ena = true;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        try h.src.set(i % 3, i % 2 == 0);
        _ = try lcb.signal(h.src.source(), 0, i % 3, .data_change, base + i * 1000);
    }
}

test "InitializeJournal deletes up to a limiting EntryID and reports the count" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    try fillLog(&h, &lcb, 4, 1_700_000_000_000);
    try testing.expectEqual(@as(usize, 4), lcb.store.count);

    var id: [entry_id_len]u8 = undefined;
    std.mem.writeInt(u64, &id, 2, .big);
    try testing.expectEqual(@as(u32, 2), initializeJournal(&lcb, .{ .limiting_entry = &id }));
    try testing.expectEqual(@as(usize, 2), lcb.store.count);
    try testing.expectEqual(@as(u64, 3), lcb.store.oldest().?.entry_id);
    // Deleting is not purging: the client asked for it.
    try testing.expectEqual(@as(u64, 0), lcb.store.purged);

    // No limit at all empties the journal.
    try testing.expectEqual(@as(u32, 2), initializeJournal(&lcb, .{}));
    try testing.expectEqual(@as(usize, 0), lcb.store.count);
    // …and doing it again deletes nothing rather than failing.
    try testing.expectEqual(@as(u32, 0), initializeJournal(&lcb, .{}));
}

test "a deletion spanning the purge boundary deletes what survived" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    // Ten entries into a four-entry store: 1..6 are already gone.
    try fillLog(&h, &lcb, 10, 1_700_000_000_000);
    try testing.expectEqual(@as(u64, 6), lcb.store.purged);
    try testing.expectEqual(@as(u64, 7), lcb.store.oldest().?.entry_id);

    // Delete "everything up to entry 8" — half of which the store never had.
    var id: [entry_id_len]u8 = undefined;
    std.mem.writeInt(u64, &id, 8, .big);
    try testing.expectEqual(@as(u32, 2), initializeJournal(&lcb, .{ .limiting_entry = &id }));
    try testing.expectEqual(@as(usize, 2), lcb.store.count);
    try testing.expectEqual(@as(u64, 9), lcb.store.oldest().?.entry_id);

    // …and one reaching past the far end deletes the rest, still without error.
    std.mem.writeInt(u64, &id, 1000, .big);
    try testing.expectEqual(@as(u32, 2), initializeJournal(&lcb, .{ .limiting_entry = &id }));
    try testing.expectEqual(@as(usize, 0), lcb.store.count);
}

test "InitializeJournal deletes by time and leaves later entries alone" {
    var h: Harness = .{};
    try h.src.init();
    var lcb = h.lcb();
    const base: u64 = 1_700_000_000_000;
    try fillLog(&h, &lcb, 4, base);
    const cut = reporting.binaryTimeFromMillis(base + 1000);
    try testing.expectEqual(@as(u32, 2), initializeJournal(&lcb, .{ .limiting_time = cut }));
    try testing.expectEqual(@as(usize, 2), lcb.store.count);
    try testing.expectEqual(@as(u64, 3), lcb.store.oldest().?.entry_id);
    // A cut before everything deletes nothing.
    const early = reporting.binaryTimeFromMillis(base - 10_000);
    try testing.expectEqual(@as(u32, 0), initializeJournal(&lcb, .{ .limiting_time = early }));
    try testing.expectEqual(@as(usize, 2), lcb.store.count);
}

test "the deletion services round trip through their own codecs" {
    var buf: [256]u8 = undefined;
    const name = mms.ObjectName{
        .domain_specific = .{ .domain = "TESTLD", .item = "LLN0$EventLog" },
    };
    var id: [entry_id_len]u8 = undefined;
    std.mem.writeInt(u64, &id, 42, .big);
    const limit = Limit{
        .limiting_time = reporting.binaryTimeFromMillis(1_700_000_000_000),
        .limiting_entry = &id,
    };
    const pdu = try encodeInitializeJournal(7, name, limit, &buf);
    const req = (try mms.decode(pdu)).confirmed_request;
    try testing.expectEqual(initialize_journal_service, req.service);
    const q = try decodeInitializeJournal(req.body);
    try testing.expectEqualStrings("LLN0$EventLog", q.journal.domain_specific.item);
    try testing.expectEqualSlices(u8, &id, q.limit.limiting_entry.?);
    try testing.expectEqual(limit.limiting_time.?.ms_since_midnight, q.limit.limiting_time.?.ms_since_midnight);
    var again: [256]u8 = undefined;
    try testing.expectEqualSlices(u8, pdu, try encodeInitializeJournal(7, q.journal, q.limit, &again));

    const resp = try encodeInitializeJournalResponse(7, 13, &buf);
    const dec = (try mms.decode(resp)).confirmed_response;
    try testing.expectEqual(@as(u32, 13), try decodeInitializeJournalResponse(dec.body));

    const del = try encodeDeleteJournal(8, name, &buf);
    const dreq = (try mms.decode(del)).confirmed_request;
    try testing.expectEqual(delete_journal_service, dreq.service);
    const dn = try decodeDeleteJournal(dreq.body);
    try testing.expectEqualStrings("LLN0$EventLog", dn.domain_specific.item);
    const dresp = try encodeDeleteJournalResponse(8, &buf);
    const ddec = (try mms.decode(dresp)).confirmed_response;
    try testing.expectEqual(@as(usize, 0), ddec.body.len);

    // Hostile input: a request with no journal name at all.
    try testing.expectError(error.MissingField, decodeInitializeJournal(&.{}));
}

test "fuzz: the deletion services never panic on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzDeletion, .{});
}

fn fuzzDeletion(_: void, smith: *std.testing.Smith) !void {
    var input: [128]u8 = undefined;
    smith.bytes(&input);
    const len: usize = smith.valueRangeAtMost(u8, 0, input.len);
    const body = input[0..len];
    if (decodeInitializeJournal(body)) |q| {
        var h: Harness = .{};
        h.src.init() catch return;
        var lcb = h.lcb();
        fillLog(&h, &lcb, 4, 1_700_000_000_000) catch return;
        _ = initializeJournal(&lcb, q.limit);
    } else |_| {}
    _ = decodeDeleteJournal(body) catch {};
    _ = decodeInitializeJournalResponse(body) catch {};
}

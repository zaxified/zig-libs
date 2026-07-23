// SPDX-License-Identifier: MIT

//! The **IEC 61850 control model** — IEC 61850-7-2 §20, mapped onto MMS by
//! IEC 61850-8-1. This is what turns a client that can *read* a substation into
//! one that can *operate* it.
//!
//! Four models an IED advertises in `ctlModel`, and the difference between the
//! two halves is the whole difficulty:
//!
//! ```text
//!   direct-with-normal-security    write Oper  → write response = the answer
//!   sbo-with-normal-security       read  SBO   → write Oper → write response
//!   direct-with-enhanced-security  write Oper  → response, THEN CommandTermination
//!   sbo-with-enhanced-security     write SBOw  → write Oper → response, THEN CommandTermination
//! ```
//!
//! **The enhanced models are where naive clients report success too early.** A
//! positive write response to `Oper` means only "the command was accepted for
//! execution"; whether the breaker actually moved arrives *later and
//! unsolicited*, as an `InformationReport` naming the control object — a
//! `CommandTermination`. A client that stops at the write response reports a
//! trip that never happened. Worse, the **negative** termination is an
//! `InformationReport` carrying **two** variables: `LastApplError` first and the
//! control object second, so a decoder that assumes one value per report reads
//! the wrong one.
//!
//! `LastApplError` is the difference between "it failed" and "it failed because
//! the synchrocheck refused" — it carries the control object reference, an error
//! code, the originator, the `ctlNum` and an `AddCause`, and `AddCause` is a
//! 28-value enumeration naming every reason an IED refuses to operate.
//!
//! Everything here is **pure and time-injected**, like the rest of this module:
//! the two state machines (`Machine` on the client side, `Point` on the server
//! side) take "now" as an argument and own no timer, no thread and no buffer.
//! `sboTimeout` is enforced by the caller calling `tick`.
//!
//! Layouts are derived from the published IEC 61850-7-2 / -8-1 definitions and
//! then **confirmed against captured octets** — see `controlgoldens.zig`.

const std = @import("std");
const ber = @import("ber.zig");
const mms = @import("mms.zig");
const mmsdata = @import("mmsdata.zig");
const acsi = @import("acsi.zig");

pub const Error = mmsdata.Error || mms.Error || acsi.Error || error{
    /// `ctlModel` held a value outside 0..4.
    UnknownCtlModel,
    /// `orCat` held a value outside 0..8.
    UnknownOrCat,
    /// `AddCause` held a value outside the standard enumeration.
    UnknownAddCause,
    /// The `error` field of a `LastApplError` is not one of the four codes.
    UnknownControlError,
    /// A control structure whose members are not the documented sequence.
    BadControlStructure,
    /// The reference does not name a control object.
    NotAControlObject,
    /// A response or termination whose `ctlNum` is not the one we sent.
    CtlNumMismatch,
    /// The state machine was driven out of order.
    WrongState,
    /// The select expired before the operate reached the server.
    SelectExpired,
    /// The server refused the command; `Machine.failure` says why.
    ControlRejected,
};

// ── ctlModel ────────────────────────────────────────────────────────────────

/// `CtlModels` — the `ctlModel` enumeration of IEC 61850-7-3, which every
/// controllable data object carries under the `CF` functional constraint. A
/// client that does not read it first cannot know whether to select.
pub const CtlModel = enum(u8) {
    /// Not controllable at all; there is no `Oper` to write.
    status_only = 0,
    direct_with_normal_security = 1,
    sbo_with_normal_security = 2,
    direct_with_enhanced_security = 3,
    sbo_with_enhanced_security = 4,

    pub fn fromInt(v: i64) Error!CtlModel {
        return switch (v) {
            0...4 => @enumFromInt(@as(u8, @intCast(v))),
            else => error.UnknownCtlModel,
        };
    }

    /// Decodes the value of a `…$CF$<DO>$ctlModel` read.
    pub fn fromData(d: mmsdata.Data) Error!CtlModel {
        return fromInt(try d.asInt());
    }

    /// Select-before-operate: the command needs a select step first.
    pub fn needsSelect(self: CtlModel) bool {
        return self == .sbo_with_normal_security or self == .sbo_with_enhanced_security;
    }

    /// Enhanced security adds `CommandTermination` after the operation.
    pub fn isEnhanced(self: CtlModel) bool {
        return self == .direct_with_enhanced_security or self == .sbo_with_enhanced_security;
    }

    /// How the select is performed: normal security **reads** `SBO` (a
    /// `VisibleString` that comes back holding the object reference on success);
    /// enhanced security **writes** `SBOw` (the same structure as `Oper`).
    pub fn selectAttribute(self: CtlModel) ?[]const u8 {
        return switch (self) {
            .sbo_with_normal_security => "SBO",
            .sbo_with_enhanced_security => "SBOw",
            else => null,
        };
    }

    /// The SCL spelling, i.e. the `EnumVal` text of the `CtlModels` enum type.
    pub fn sclName(self: CtlModel) []const u8 {
        return switch (self) {
            .status_only => "status-only",
            .direct_with_normal_security => "direct-with-normal-security",
            .sbo_with_normal_security => "sbo-with-normal-security",
            .direct_with_enhanced_security => "direct-with-enhanced-security",
            .sbo_with_enhanced_security => "sbo-with-enhanced-security",
        };
    }

    pub fn parseScl(s: []const u8) Error!CtlModel {
        inline for (@typeInfo(CtlModel).@"enum".fields) |f| {
            const m: CtlModel = @enumFromInt(f.value);
            if (std.mem.eql(u8, s, m.sclName())) return m;
        }
        // SCL files in the wild also carry the bare ordinal.
        const v = std.fmt.parseInt(i64, s, 10) catch return error.UnknownCtlModel;
        return fromInt(v);
    }
};

// ── originator ──────────────────────────────────────────────────────────────

/// `orCat` — *who* issued the command. It is not a credential (IEC 61850 has
/// none); it is an audit field, and a `LastApplError` echoes it back so a client
/// can tell its own rejected command from another client's.
pub const OrCat = enum(u8) {
    not_supported = 0,
    bay_control = 1,
    station_control = 2,
    remote_control = 3,
    automatic_bay = 4,
    automatic_station = 5,
    automatic_remote = 6,
    maintenance = 7,
    process = 8,

    pub fn fromInt(v: i64) Error!OrCat {
        return switch (v) {
            0...8 => @enumFromInt(@as(u8, @intCast(v))),
            else => error.UnknownOrCat,
        };
    }
};

/// `Originator ::= SEQUENCE { orCat, orIdent }`. `orIdent` is an OCTET STRING of
/// at most 64 octets and is free-form: most clients put their own name in it.
pub const Origin = struct {
    or_cat: OrCat = .not_supported,
    or_ident: []const u8 = "",

    pub const max_ident_len: usize = 64;

    /// Emits `structure { integer orCat, octet-string orIdent }` through the
    /// backwards writer, so the members go out last-to-first.
    pub fn emit(self: Origin, w: *ber.Writer) Error!void {
        if (self.or_ident.len > max_ident_len) return error.BufferTooSmall;
        const m = w.mark();
        try mmsdata.Emit.octetString(w, self.or_ident);
        try mmsdata.Emit.integer(w, @intFromEnum(self.or_cat));
        try mmsdata.Emit.structure(w, m);
    }

    pub fn decode(d: mmsdata.Data) Error!Origin {
        if (d.kind != .structure) return error.BadControlStructure;
        var it = try d.members();
        const cat = (try it.next()) orelse return error.BadControlStructure;
        const ident = (try it.next()) orelse return error.BadControlStructure;
        if ((try it.next()) != null) return error.BadControlStructure;
        return .{
            .or_cat = try OrCat.fromInt(try cat.asInt()),
            .or_ident = ident.octetString() catch ident.visibleString() catch
                return error.BadControlStructure,
        };
    }

    pub fn eql(a: Origin, b: Origin) bool {
        return a.or_cat == b.or_cat and std.mem.eql(u8, a.or_ident, b.or_ident);
    }
};

// ── Check ───────────────────────────────────────────────────────────────────

/// `Check ::= PACKED LIST { synchrocheck, interlock-check }` — a two-bit BIT
/// STRING that asks the IED to *skip* the named check. Setting a bit is a
/// deliberate override of a safety interlock, which is why it is spelled out
/// rather than hidden behind a `u8`.
pub const Check = struct {
    synchrocheck: bool = false,
    interlock_check: bool = false,

    pub const bits: u8 = 2;

    pub fn toBits(self: Check) u64 {
        return (@as(u64, @intFromBool(self.synchrocheck)) << 1) |
            @intFromBool(self.interlock_check);
    }

    pub fn parse(bs: ber.BitString) Check {
        return .{ .synchrocheck = bs.bit(0), .interlock_check = bs.bit(1) };
    }

    pub fn emit(self: Check, w: *ber.Writer) Error!void {
        try mmsdata.Emit.bitString(w, self.toBits(), bits);
    }

    pub fn any(self: Check) bool {
        return self.synchrocheck or self.interlock_check;
    }
};

// ── the command structure ───────────────────────────────────────────────────

/// The value written to `Oper`, `SBOw` or `Cancel`.
///
/// ```text
/// Oper   ::= SEQUENCE { ctlVal, [operTm,] origin, ctlNum, T, Test, Check }
/// SBOw   ::= same as Oper
/// Cancel ::= SEQUENCE { ctlVal, [operTm,] origin, ctlNum, T, Test }
/// ```
///
/// Two shapes vary per object and are visible in its SCL `DAType`: `operTm`
/// (a timed operate) is present only in the `…Operate_5`-style templates, and
/// `Check` is absent from `Cancel`. Both are therefore **optional here and
/// recovered from the decoded structure by shape**, not assumed: member 1 is
/// `operTm` when it is a `utc-time` and `origin` when it is a `structure`, and a
/// trailing `bit-string` is `Check`. That is unambiguous because no other member
/// can take those alternatives.
///
/// `ctl_val` is a complete, already-encoded `Data` TLV, because the controlled
/// value's type comes from the common data class: `BOOLEAN` for an SPC, a
/// two-bit `Dbpos` bit-string for a DPC, `INT32` for an INC, a float for an APC.
pub const Command = struct {
    ctl_val: []const u8,
    /// A timed operate — "close at this instant". Present only when the object's
    /// `DAType` has it.
    oper_tm: ?mmsdata.UtcTime = null,
    origin: Origin = .{},
    /// 0 is "no control in progress"; a real command counts 1..255.
    ctl_num: u8 = 0,
    /// The control timestamp — when the *client* issued the command.
    t: mmsdata.UtcTime,
    /// A test command must not move the plant.
    test_mode: bool = false,
    /// Absent on `Cancel`.
    check: ?Check = .{},

    /// The largest control structure this module builds: seven members, the
    /// biggest of which is a 64-octet `orIdent` plus a `ctlVal` of up to 32.
    pub const max_encoded_len: usize = 192;

    pub fn emit(self: Command, w: *ber.Writer) Error!void {
        const m = w.mark();
        if (self.check) |c| try c.emit(w);
        try mmsdata.Emit.boolean(w, self.test_mode);
        try mmsdata.Emit.utcTime(w, self.t);
        try mmsdata.Emit.unsigned(w, self.ctl_num);
        try self.origin.emit(w);
        if (self.oper_tm) |o| try mmsdata.Emit.utcTime(w, o);
        try w.bytes(self.ctl_val);
        try mmsdata.Emit.structure(w, m);
    }

    /// Encodes into the **front** of `out` and returns the slice. The writer
    /// builds backwards, so the result is moved down afterwards — callers get a
    /// plain `[]const u8` they can hand straight to `Client.writeName`.
    pub fn encode(self: Command, out: []u8) Error![]const u8 {
        var w = ber.Writer.init(out);
        try self.emit(&w);
        const d = w.done();
        const n = d.len;
        std.mem.copyForwards(u8, out[0..n], d);
        return out[0..n];
    }

    pub fn decode(d: mmsdata.Data) Error!Command {
        if (d.kind != .structure) return error.BadControlStructure;
        var it = try d.members();
        const ctl_val = (try it.next()) orelse return error.BadControlStructure;

        var cmd = Command{ .ctl_val = ctl_val.raw, .t = undefined };
        var next = (try it.next()) orelse return error.BadControlStructure;
        if (next.kind == .utc_time) {
            cmd.oper_tm = try next.utcTime();
            next = (try it.next()) orelse return error.BadControlStructure;
        }
        cmd.origin = try Origin.decode(next);

        const num = (try it.next()) orelse return error.BadControlStructure;
        const n = try num.asInt();
        if (n < 0 or n > 255) return error.BadControlStructure;
        cmd.ctl_num = @intCast(n);

        const t = (try it.next()) orelse return error.BadControlStructure;
        cmd.t = try t.utcTime();

        const test_mode = (try it.next()) orelse return error.BadControlStructure;
        cmd.test_mode = try test_mode.boolean();

        if (try it.next()) |c| {
            cmd.check = Check.parse(try c.bitString());
            if ((try it.next()) != null) return error.BadControlStructure;
        } else {
            cmd.check = null;
        }
        return cmd;
    }

    /// The `ctlVal` as a boolean — the SPC/DPC case, which is most switchgear.
    pub fn boolValue(self: Command) Error!bool {
        return (try mmsdata.Data.decode(self.ctl_val)).boolean();
    }
};

// ── AddCause ────────────────────────────────────────────────────────────────

/// `AddCause` — IEC 61850-7-2 §20's enumeration of *why* an operation was
/// refused. This is the field that makes a control client diagnosable: without
/// it every failure is "the IED said no".
pub const AddCause = enum(i32) {
    unknown = 0,
    not_supported = 1,
    blocked_by_switching_hierarchy = 2,
    select_failed = 3,
    invalid_position = 4,
    position_reached = 5,
    parameter_change_in_execution = 6,
    step_limit = 7,
    blocked_by_mode = 8,
    blocked_by_process = 9,
    blocked_by_interlocking = 10,
    blocked_by_synchrocheck = 11,
    command_already_in_execution = 12,
    blocked_by_health = 13,
    one_of_n_control = 14,
    abortion_by_cancel = 15,
    time_limit_over = 16,
    abortion_by_trip = 17,
    object_not_selected = 18,
    object_already_selected = 19,
    no_access_authority = 20,
    ended_with_overshoot = 21,
    abortion_due_to_deviation = 22,
    abortion_by_communication_loss = 23,
    blocked_by_command = 24,
    none = 25,
    inconsistent_parameters = 26,
    locked_by_other_client = 27,

    pub fn fromInt(v: i64) Error!AddCause {
        return switch (v) {
            0...27 => @enumFromInt(@as(i32, @intCast(v))),
            else => error.UnknownAddCause,
        };
    }

    pub fn name(self: AddCause) []const u8 {
        return @tagName(self);
    }

    /// Whether retrying the identical command could plausibly succeed. A
    /// synchrocheck or an interlock may clear; "not supported" will not.
    pub fn transient(self: AddCause) bool {
        return switch (self) {
            .blocked_by_synchrocheck,
            .blocked_by_interlocking,
            .command_already_in_execution,
            .object_already_selected,
            .blocked_by_process,
            .locked_by_other_client,
            .time_limit_over,
            .parameter_change_in_execution,
            => true,
            else => false,
        };
    }
};

/// The `error` member of `LastApplError`.
pub const ControlError = enum(i32) {
    no_error = 0,
    unknown = 1,
    timeout_test_not_ok = 2,
    operator_test_not_ok = 3,

    pub fn fromInt(v: i64) Error!ControlError {
        return switch (v) {
            0...3 => @enumFromInt(@as(i32, @intCast(v))),
            else => error.UnknownControlError,
        };
    }
};

/// The MMS variable name a `LastApplError` arrives under. It is **VMD-specific**
/// — it belongs to the association, not to any logical device — which is what
/// distinguishes it from every other unsolicited value.
pub const last_appl_error_name = "LastApplError";

/// ```text
/// LastApplError ::= SEQUENCE {
///   CntrlObj  VisibleString,   -- the control object that failed
///   Error     INTEGER,
///   Origin    Originator,
///   ctlNum    INT8U,
///   AddCause  INTEGER }
/// ```
pub const LastApplError = struct {
    ctl_obj_ref: []const u8,
    err: ControlError = .unknown,
    origin: Origin = .{},
    ctl_num: u8 = 0,
    add_cause: AddCause = .unknown,

    pub fn decode(d: mmsdata.Data) Error!LastApplError {
        if (d.kind != .structure) return error.BadControlStructure;
        var it = try d.members();
        const ref = (try it.next()) orelse return error.BadControlStructure;
        const e = (try it.next()) orelse return error.BadControlStructure;
        const org = (try it.next()) orelse return error.BadControlStructure;
        const num = (try it.next()) orelse return error.BadControlStructure;
        const cause = (try it.next()) orelse return error.BadControlStructure;
        if ((try it.next()) != null) return error.BadControlStructure;
        const n = try num.asInt();
        if (n < 0 or n > 255) return error.BadControlStructure;
        return .{
            .ctl_obj_ref = try ref.visibleString(),
            .err = try ControlError.fromInt(try e.asInt()),
            .origin = try Origin.decode(org),
            .ctl_num = @intCast(n),
            .add_cause = try AddCause.fromInt(try cause.asInt()),
        };
    }

    pub fn emit(self: LastApplError, w: *ber.Writer) Error!void {
        const m = w.mark();
        try mmsdata.Emit.integer(w, @intFromEnum(self.add_cause));
        try mmsdata.Emit.unsigned(w, self.ctl_num);
        try self.origin.emit(w);
        try mmsdata.Emit.integer(w, @intFromEnum(self.err));
        try mmsdata.Emit.visibleString(w, self.ctl_obj_ref);
        try mmsdata.Emit.structure(w, m);
    }
};

// ── unsolicited notifications ───────────────────────────────────────────────

/// What an `InformationReport` turned out to be. A control client must tell
/// these apart from an ordinary buffered/unbuffered report, and the negative
/// termination is the one that carries **two** variables.
pub const NotificationKind = enum {
    /// `CommandTermination+`: the operation completed. One variable, the
    /// control object, carrying the `Oper` value echoed back.
    command_termination_positive,
    /// `CommandTermination-`: the operation failed after being accepted. Two
    /// variables, `LastApplError` first.
    command_termination_negative,
    /// A `LastApplError` on its own — an operate or select that was refused
    /// before it started.
    last_appl_error,
};

pub const Notification = struct {
    kind: NotificationKind,
    /// The control object the report named, e.g.
    /// `domain_specific{"simpleIOGenericIO", "GGIO1$CO$SPCSO4$Oper"}`.
    object: ?mms.ObjectName = null,
    /// The echoed command, when the report carried one.
    command: ?Command = null,
    /// Present on both `…_negative` and `last_appl_error`.
    last_error: ?LastApplError = null,

    pub fn addCause(self: Notification) ?AddCause {
        return if (self.last_error) |e| e.add_cause else null;
    }

    /// The `ctlNum` this notification refers to, from whichever member carries
    /// it. A client matches it against the command it sent.
    pub fn ctlNum(self: Notification) ?u8 {
        if (self.last_error) |e| return e.ctl_num;
        if (self.command) |c| return c.ctl_num;
        return null;
    }
};

/// Is this MMS item id a control object — i.e. does it end in one of the four
/// control attributes under the `CO` functional constraint?
pub fn controlAttribute(item: []const u8) ?[]const u8 {
    const names = [_][]const u8{ "Oper", "SBOw", "SBO", "Cancel" };
    for (names) |n| {
        if (item.len > n.len + 1 and
            item[item.len - n.len - 1] == '$' and
            std.mem.eql(u8, item[item.len - n.len ..], n)) return n;
    }
    return null;
}

/// Splits `LN$CO$DO…$Oper` into the control object prefix and the attribute.
pub fn splitControlItem(item: []const u8) ?struct { prefix: []const u8, attribute: []const u8 } {
    const attr = controlAttribute(item) orelse return null;
    const prefix = item[0 .. item.len - attr.len - 1];
    // The functional constraint must be CO, else this is a status attribute
    // that merely happens to be spelled like one.
    var it = std.mem.splitScalar(u8, prefix, '$');
    _ = it.first();
    const fc = it.next() orelse return null;
    if (!std.mem.eql(u8, fc, "CO")) return null;
    return .{ .prefix = prefix, .attribute = attr };
}

/// Classifies one decoded `InformationReport`. Returns null when the report is
/// not a control notification (an ordinary `RPT`, say), which is exactly the
/// discrimination `Client.dispatchUnconfirmed` needs.
pub fn classify(info: mms.InformationReport) Error!?Notification {
    var names = switch (info.spec) {
        .variables => |v| v,
        // A report control block's report is addressed by variable-list name;
        // a control notification never is.
        .variable_list => return null,
    };
    var results = info.results;

    var n: Notification = .{ .kind = .last_appl_error };
    var saw_last_appl_error = false;
    var saw_object = false;
    var count: usize = 0;

    while (try names.next()) |name| {
        count += 1;
        if (count > 4) return error.BadControlStructure;
        const value = (try results.next()) orelse return error.BadControlStructure;
        const d = switch (value) {
            .success => |v| v,
            // A failure inside a control notification is not something this
            // model has a meaning for.
            .failure => return null,
        };
        switch (name) {
            .vmd_specific => |s| {
                if (!std.mem.eql(u8, s, last_appl_error_name)) return null;
                try d.validate();
                n.last_error = try LastApplError.decode(d);
                saw_last_appl_error = true;
            },
            .domain_specific => |ds| {
                // `LastApplError` is VMD-specific in the standard, but some
                // stacks scope it to the domain; accept both.
                if (std.mem.eql(u8, ds.item, last_appl_error_name)) {
                    try d.validate();
                    n.last_error = try LastApplError.decode(d);
                    saw_last_appl_error = true;
                    continue;
                }
                const split = splitControlItem(ds.item) orelse return null;
                if (!std.mem.eql(u8, split.attribute, "Oper") and
                    !std.mem.eql(u8, split.attribute, "SBOw")) return null;
                try d.validate();
                n.object = name;
                n.command = try Command.decode(d);
                saw_object = true;
            },
            .aa_specific => return null,
        }
    }
    if (!saw_last_appl_error and !saw_object) return null;
    n.kind = if (saw_last_appl_error and saw_object)
        .command_termination_negative
    else if (saw_object)
        .command_termination_positive
    else
        .last_appl_error;
    return n;
}

// ── the client-side state machine ───────────────────────────────────────────

/// Where a command is. `awaiting_termination` is the state that exists only
/// under enhanced security and that a naive client never enters.
pub const State = enum {
    idle,
    selecting,
    selected,
    operating,
    awaiting_termination,
    succeeded,
    failed,
};

/// What the driver should do next.
pub const Step = enum {
    /// Read `…$CO$<DO>$SBO`; a non-empty `VisibleString` back means selected.
    read_sbo,
    /// Write the command to `…$CO$<DO>$SBOw`.
    write_sbow,
    /// Write the command to `…$CO$<DO>$Oper`.
    write_oper,
    /// Wait for the `CommandTermination`.
    wait_termination,
    /// Nothing more to do; look at `Machine.state`.
    finished,
};

pub const Stage = enum { select, operate, terminate };

pub const Failure = struct {
    stage: Stage,
    add_cause: ?AddCause = null,
    err: ?ControlError = null,
    /// Set when the failure was local — a select that timed out before the
    /// operate went out, say — rather than reported by the IED.
    local: bool = false,
};

/// The client half of the control model: select → operate → termination, with
/// the `sboTimeout`, the `ctlNum` rule and a `Cancel` that may arrive at any
/// point. **Pure**: every transition takes "now" and returns the next step.
pub const Machine = struct {
    model: CtlModel,
    /// From `…$CF$<DO>$sboTimeout`, in milliseconds. 0 means the IED did not
    /// publish one; nothing expires locally then.
    sbo_timeout_ms: u32 = 0,
    /// How long to wait for a `CommandTermination` before giving up. Purely a
    /// client-side patience limit; the standard puts no bound on it.
    termination_timeout_ms: u32 = 30_000,

    state: State = .idle,
    /// The `ctlNum` of the command in flight. Never 0 while a command is live.
    ctl_num: u8 = 0,
    /// Absolute deadline of the select, or 0 when nothing is armed.
    select_deadline_ms: u64 = 0,
    termination_deadline_ms: u64 = 0,
    failure: ?Failure = null,

    pub fn init(model: CtlModel, sbo_timeout_ms: u32) Machine {
        return .{ .model = model, .sbo_timeout_ms = sbo_timeout_ms };
    }

    /// Begins a new command and hands back the first step. Bumps `ctlNum`,
    /// which wraps 1..255 — **0 is reserved** and means "no control".
    pub fn start(self: *Machine, now_ms: u64) Error!Step {
        if (self.state != .idle and self.state != .succeeded and self.state != .failed) {
            return error.WrongState;
        }
        if (self.model == .status_only) {
            self.state = .failed;
            self.failure = .{ .stage = .operate, .add_cause = .not_supported, .local = true };
            return error.ControlRejected;
        }
        self.failure = null;
        self.ctl_num = if (self.ctl_num == 255) 1 else self.ctl_num + 1;
        if (self.model.needsSelect()) {
            self.state = .selecting;
            self.select_deadline_ms = if (self.sbo_timeout_ms == 0) 0 else now_ms + self.sbo_timeout_ms;
            return switch (self.model) {
                .sbo_with_normal_security => .read_sbo,
                else => .write_sbow,
            };
        }
        self.state = .operating;
        return .write_oper;
    }

    /// The select succeeded. Under IEC 61850-7-2 the `sboTimeout` window opens
    /// **when the IED grants the select**, so the deadline is re-armed here
    /// rather than left where `start` put it.
    pub fn selectSucceeded(self: *Machine, now_ms: u64) Error!Step {
        if (self.state != .selecting) return error.WrongState;
        self.state = .selected;
        self.select_deadline_ms = if (self.sbo_timeout_ms == 0) 0 else now_ms + self.sbo_timeout_ms;
        return .write_oper;
    }

    pub fn selectFailed(self: *Machine, cause: ?AddCause, err: ?ControlError) Step {
        self.state = .failed;
        self.failure = .{ .stage = .select, .add_cause = cause orelse .select_failed, .err = err };
        self.select_deadline_ms = 0;
        return .finished;
    }

    /// Moves from `selected` (or straight from `start` for a direct model) into
    /// the operate. Fails when the select expired in the meantime — the case
    /// that produces `Object-not-selected` at the IED if it is not caught here.
    pub fn beginOperate(self: *Machine, now_ms: u64) Error!Step {
        switch (self.state) {
            .selected => {
                if (self.expired(now_ms)) {
                    self.state = .failed;
                    self.failure = .{ .stage = .operate, .add_cause = .object_not_selected, .local = true };
                    return error.SelectExpired;
                }
            },
            .operating => {},
            else => return error.WrongState,
        }
        self.state = .operating;
        return .write_oper;
    }

    /// The IED accepted the write. For a normal-security model that is the
    /// whole answer; for an enhanced one it is only "accepted for execution".
    pub fn operateAccepted(self: *Machine, now_ms: u64) Error!Step {
        if (self.state != .operating) return error.WrongState;
        self.select_deadline_ms = 0;
        if (self.model.isEnhanced()) {
            self.state = .awaiting_termination;
            self.termination_deadline_ms = now_ms + self.termination_timeout_ms;
            return .wait_termination;
        }
        self.state = .succeeded;
        return .finished;
    }

    pub fn operateRejected(self: *Machine, cause: ?AddCause, err: ?ControlError) Step {
        self.state = .failed;
        self.failure = .{ .stage = .operate, .add_cause = cause, .err = err };
        self.select_deadline_ms = 0;
        return .finished;
    }

    /// A `CommandTermination` arrived. The `ctlNum` **must** match the command
    /// in flight: an IED serving several clients terminates each one's command
    /// separately, and a client that ignores the number reports another
    /// client's success as its own.
    pub fn terminated(self: *Machine, n: Notification) Error!Step {
        if (self.state != .awaiting_termination) return error.WrongState;
        if (n.ctlNum()) |num| {
            if (num != self.ctl_num) return error.CtlNumMismatch;
        }
        self.termination_deadline_ms = 0;
        switch (n.kind) {
            .command_termination_positive => {
                self.state = .succeeded;
                return .finished;
            },
            .command_termination_negative, .last_appl_error => {
                self.state = .failed;
                self.failure = .{
                    .stage = .terminate,
                    .add_cause = n.addCause(),
                    .err = if (n.last_error) |e| e.err else null,
                };
                return .finished;
            },
        }
    }

    /// The client cancelled its own command.
    pub fn cancelled(self: *Machine) Step {
        self.state = .failed;
        self.failure = .{ .stage = .operate, .add_cause = .abortion_by_cancel, .local = true };
        self.select_deadline_ms = 0;
        self.termination_deadline_ms = 0;
        return .finished;
    }

    /// Advances the clock. Returns the failure a timeout produced, if any.
    /// This is the only place time enters, and it is the caller's clock.
    pub fn tick(self: *Machine, now_ms: u64) ?Failure {
        switch (self.state) {
            .selecting, .selected => {
                if (self.expired(now_ms)) {
                    self.state = .failed;
                    self.failure = .{ .stage = .select, .add_cause = .time_limit_over, .local = true };
                    self.select_deadline_ms = 0;
                    return self.failure;
                }
            },
            .awaiting_termination => {
                if (self.termination_deadline_ms != 0 and now_ms >= self.termination_deadline_ms) {
                    self.state = .failed;
                    self.failure = .{ .stage = .terminate, .add_cause = .time_limit_over, .local = true };
                    self.termination_deadline_ms = 0;
                    return self.failure;
                }
            },
            else => {},
        }
        return null;
    }

    fn expired(self: *const Machine, now_ms: u64) bool {
        return self.select_deadline_ms != 0 and now_ms >= self.select_deadline_ms;
    }

    pub fn done(self: *const Machine) bool {
        return self.state == .succeeded or self.state == .failed;
    }
};

// ── the server-side state machine ───────────────────────────────────────────

/// The runtime state of one controllable object at the IED.
pub const PointState = enum { unselected, selected, executing };

/// The outcome of a select, an operate or a cancel at the server.
pub const Outcome = union(enum) {
    /// Accepted. `terminate` is true when the model owes a
    /// `CommandTermination` once execution finishes.
    accepted: struct { terminate: bool = false },
    /// Refused, with the reason the IED must put in `LastApplError`.
    rejected: AddCause,
};

/// One controllable data object at the server: the model it advertises, the
/// interlocks the application raises, and the select that may be armed.
///
/// **Pure and time-injected.** `select`, `operate`, `cancel` and `tick` all take
/// "now" in milliseconds; nothing here owns a timer, and `sboTimeout` is
/// enforced only because the caller keeps calling `tick`.
/// What the controlled value is. The common data class decides it: an SPC/DPC
/// is a boolean, an INC an integer, an APC a float. It matters because a client
/// asks the IED for the type before it writes.
pub const ValueType = enum { boolean, integer, float };

pub const Point = struct {
    /// The MMS item id **prefix** of the object, e.g. `"GGIO1$CO$SPCSO4"`.
    /// `Oper`, `SBO`, `SBOw` and `Cancel` hang off it.
    item: []const u8,
    domain: []const u8,
    ctl_model: CtlModel,
    /// The IED's own select window. 0 disables expiry.
    sbo_timeout_ms: u32 = 30_000,
    /// How long an enhanced-security execution may take before the IED gives up
    /// and terminates it negatively with `Time-limit-over`.
    execution_timeout_ms: u32 = 5_000,
    /// Index into the server's variable table of the `…$ST$<DO>$stVal` this
    /// object drives, when there is one.
    st_val: ?usize = null,
    /// The type of `ctlVal`.
    value_type: ValueType = .boolean,
    /// Whether the control structures carry `operTm` (a timed operate).
    oper_tm: bool = false,

    // Interlocks the application raises. `Check` asks the IED to *skip* a
    // check; whether it is allowed to is the IED's decision, not the client's,
    // so `allow_check_override` gates it.
    interlocked: bool = false,
    synchrocheck_failed: bool = false,
    blocked_by_mode: bool = false,
    unhealthy: bool = false,
    allow_check_override: bool = false,

    state: PointState = .unselected,
    /// The `ctlNum` of the armed select, and of the command executing.
    ctl_num: u8 = 0,
    /// Identifies the client that holds the select. Any non-zero value the
    /// caller likes; a second client with a different id is refused.
    owner: u32 = 0,
    select_deadline_ms: u64 = 0,
    execution_deadline_ms: u64 = 0,

    /// Common gate for select and operate: everything that blocks the object
    /// regardless of who asked.
    fn blocked(self: *const Point, cmd: ?Command) ?AddCause {
        if (self.ctl_model == .status_only) return .not_supported;
        if (self.unhealthy) return .blocked_by_health;
        if (self.blocked_by_mode) return .blocked_by_mode;
        const check: Check = if (cmd) |c| (c.check orelse .{}) else .{};
        const override = self.allow_check_override;
        if (self.interlocked and !(override and check.interlock_check)) return .blocked_by_interlocking;
        if (self.synchrocheck_failed and !(override and check.synchrocheck)) return .blocked_by_synchrocheck;
        return null;
    }

    /// A select. `cmd` is null for `sbo-with-normal-security` (where the select
    /// is a *read* of `SBO` and carries no value) and the `SBOw` value
    /// otherwise.
    pub fn select(self: *Point, owner: u32, cmd: ?Command, now_ms: u64) Outcome {
        _ = self.tick(now_ms);
        if (!self.ctl_model.needsSelect()) return .{ .rejected = .not_supported };
        if (self.blocked(cmd)) |c| return .{ .rejected = c };
        switch (self.state) {
            .selected => {
                // Re-selecting your own object is legal; another client's is not.
                if (self.owner != owner) return .{ .rejected = .locked_by_other_client };
            },
            .executing => return .{ .rejected = .command_already_in_execution },
            .unselected => {},
        }
        self.state = .selected;
        self.owner = owner;
        self.ctl_num = if (cmd) |c| c.ctl_num else 0;
        self.select_deadline_ms = if (self.sbo_timeout_ms == 0) 0 else now_ms + self.sbo_timeout_ms;
        return .{ .accepted = .{} };
    }

    /// An operate. Enforces the model, the select, the `ctlNum` and the
    /// interlocks, in that order — which is the order that produces the
    /// `AddCause` a real IED produces.
    pub fn operate(self: *Point, owner: u32, cmd: Command, now_ms: u64) Outcome {
        const expired = self.tick(now_ms);
        if (self.blocked(cmd)) |c| return .{ .rejected = c };
        if (self.state == .executing) return .{ .rejected = .command_already_in_execution };
        if (self.ctl_model.needsSelect()) {
            if (self.state != .selected) {
                return .{ .rejected = if (expired) .object_not_selected else .object_not_selected };
            }
            if (self.owner != owner) return .{ .rejected = .locked_by_other_client };
            // `sbo-with-enhanced-security` carries a ctlNum in the SBOw; the
            // Oper must repeat it. Normal security selects with a bare read and
            // has no number to match, which is why 0 means "unset" here.
            if (self.ctl_num != 0 and cmd.ctl_num != self.ctl_num) {
                return .{ .rejected = .inconsistent_parameters };
            }
        }
        self.ctl_num = cmd.ctl_num;
        self.owner = owner;
        if (self.ctl_model.isEnhanced()) {
            self.state = .executing;
            self.select_deadline_ms = 0;
            self.execution_deadline_ms = if (self.execution_timeout_ms == 0)
                0
            else
                now_ms + self.execution_timeout_ms;
            return .{ .accepted = .{ .terminate = true } };
        }
        self.state = .unselected;
        self.select_deadline_ms = 0;
        return .{ .accepted = .{} };
    }

    /// A `Cancel` may arrive at any point: it deselects an armed select and
    /// aborts an execution in flight.
    pub fn cancel(self: *Point, owner: u32, cmd: Command, now_ms: u64) Outcome {
        _ = self.tick(now_ms);
        switch (self.state) {
            .unselected => return .{ .rejected = .object_not_selected },
            .selected, .executing => {
                if (self.owner != owner) return .{ .rejected = .locked_by_other_client };
                if (self.ctl_num != 0 and cmd.ctl_num != self.ctl_num) {
                    return .{ .rejected = .inconsistent_parameters };
                }
                const was_executing = self.state == .executing;
                self.reset();
                return .{ .accepted = .{ .terminate = was_executing } };
            },
        }
    }

    /// The application finished executing. Returns true when the model owes a
    /// `CommandTermination`.
    pub fn completed(self: *Point) bool {
        const owed = self.state == .executing;
        self.reset();
        return owed;
    }

    /// Advances the clock. Returns true when something **just** expired — an
    /// armed select or an execution — so the caller can emit the negative
    /// termination the standard requires.
    pub fn tick(self: *Point, now_ms: u64) bool {
        if (self.state == .selected and self.select_deadline_ms != 0 and
            now_ms >= self.select_deadline_ms)
        {
            self.reset();
            return true;
        }
        if (self.state == .executing and self.execution_deadline_ms != 0 and
            now_ms >= self.execution_deadline_ms)
        {
            self.reset();
            return true;
        }
        return false;
    }

    fn reset(self: *Point) void {
        self.state = .unselected;
        self.owner = 0;
        self.ctl_num = 0;
        self.select_deadline_ms = 0;
        self.execution_deadline_ms = 0;
    }

    /// Emits the MMS `TypeSpecification` of this control object — the answer to
    /// `GetVariableAccessAttributes` on `LN$CO$DO`. A real control client asks
    /// for it **before** it writes anything, and treats a failure as "the
    /// object does not exist"; a responder that cannot describe its own control
    /// objects therefore cannot be operated at all, however correct its
    /// `Oper` handling is.
    ///
    /// The member list follows `ctlModel`: `SBO` only under normal-security
    /// select-before-operate, `SBOw` only under enhanced, and `Cancel` on
    /// everything that can be interrupted.
    pub fn emitTypeSpec(self: *const Point, w: *ber.Writer) Error!void {
        const m = w.mark();
        // Backwards: last member first.
        if (self.ctl_model != .direct_with_normal_security) {
            const c = w.mark();
            try self.emitCommandType(w, false);
            try mms.closeTypeComponent(w, c, "Cancel");
        }
        {
            const c = w.mark();
            try self.emitCommandType(w, true);
            try mms.closeTypeComponent(w, c, "Oper");
        }
        switch (self.ctl_model) {
            .sbo_with_normal_security => {
                const c = w.mark();
                try mms.emitTypeVisibleString(w, -64);
                try mms.closeTypeComponent(w, c, "SBO");
            },
            .sbo_with_enhanced_security => {
                const c = w.mark();
                try self.emitCommandType(w, true);
                try mms.closeTypeComponent(w, c, "SBOw");
            },
            else => {},
        }
        try mms.closeTypeStructure(w, m);
    }

    /// `Oper`/`SBOw` (`with_check`) or `Cancel`.
    fn emitCommandType(self: *const Point, w: *ber.Writer, with_check: bool) Error!void {
        const m = w.mark();
        if (with_check) {
            const c = w.mark();
            try mms.emitTypeBitString(w, -2);
            try mms.closeTypeComponent(w, c, "Check");
        }
        {
            const c = w.mark();
            try mms.emitTypeBoolean(w);
            try mms.closeTypeComponent(w, c, "Test");
        }
        {
            const c = w.mark();
            try mms.emitTypeUtcTime(w);
            try mms.closeTypeComponent(w, c, "T");
        }
        {
            const c = w.mark();
            try mms.emitTypeUnsigned(w, 8);
            try mms.closeTypeComponent(w, c, "ctlNum");
        }
        {
            const c = w.mark();
            const o = w.mark();
            const oi = w.mark();
            try mms.emitTypeOctetString(w, -64);
            try mms.closeTypeComponent(w, oi, "orIdent");
            const oc = w.mark();
            try mms.emitTypeInteger(w, 8);
            try mms.closeTypeComponent(w, oc, "orCat");
            try mms.closeTypeStructure(w, o);
            try mms.closeTypeComponent(w, c, "origin");
        }
        if (self.oper_tm) {
            const c = w.mark();
            try mms.emitTypeUtcTime(w);
            try mms.closeTypeComponent(w, c, "operTm");
        }
        {
            const c = w.mark();
            switch (self.value_type) {
                .boolean => try mms.emitTypeBoolean(w),
                .integer => try mms.emitTypeInteger(w, 32),
                .float => try mms.emitTypeInteger(w, 32),
            }
            try mms.closeTypeComponent(w, c, "ctlVal");
        }
        try mms.closeTypeStructure(w, m);
    }

    /// The object reference an `SBO` read returns on success:
    /// `<domain>/<prefix>`, e.g. `simpleIOGenericIO/GGIO1$CO$SPCSO2`. An empty
    /// string is how the standard says "select refused".
    pub fn sboReference(self: *const Point, out: []u8) Error![]const u8 {
        const n = self.domain.len + 1 + self.item.len;
        if (out.len < n) return error.BufferTooSmall;
        @memcpy(out[0..self.domain.len], self.domain);
        out[self.domain.len] = '/';
        @memcpy(out[self.domain.len + 1 ..][0..self.item.len], self.item);
        return out[0..n];
    }
};

// ── reference helpers ───────────────────────────────────────────────────────

/// `LD/LN.DO` + an attribute → the MMS `ObjectName` a control write needs.
/// `attribute` is one of `Oper`, `SBO`, `SBOw`, `Cancel` (under `CO`) or
/// `ctlModel` / `sboTimeout` (under `CF`).
pub fn controlName(
    reference: []const u8,
    fc: acsi.FunctionalConstraint,
    attribute: []const u8,
    item_buf: []u8,
) Error!mms.ObjectName {
    var ref = try acsi.parseAcsi(reference, fc);
    if (ref.component_count == 0) return error.NotAControlObject;
    if (ref.component_count >= acsi.max_components) return error.TooManyComponents;
    ref.components[ref.component_count] = attribute;
    ref.component_count += 1;
    return ref.objectName(item_buf);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the ctlModel enumeration matches the SCL spelling in both directions" {
    try testing.expectEqual(CtlModel.status_only, try CtlModel.parseScl("status-only"));
    try testing.expectEqual(
        CtlModel.direct_with_normal_security,
        try CtlModel.parseScl("direct-with-normal-security"),
    );
    try testing.expectEqual(
        CtlModel.sbo_with_enhanced_security,
        try CtlModel.parseScl("sbo-with-enhanced-security"),
    );
    // The bare ordinal is also seen in the wild.
    try testing.expectEqual(CtlModel.direct_with_enhanced_security, try CtlModel.parseScl("3"));
    try testing.expectError(error.UnknownCtlModel, CtlModel.parseScl("sbo"));
    try testing.expectError(error.UnknownCtlModel, CtlModel.fromInt(5));
    try testing.expectError(error.UnknownCtlModel, CtlModel.fromInt(-1));

    // The two properties the whole state machine turns on.
    try testing.expect(!CtlModel.direct_with_normal_security.needsSelect());
    try testing.expect(CtlModel.sbo_with_normal_security.needsSelect());
    try testing.expect(!CtlModel.sbo_with_normal_security.isEnhanced());
    try testing.expect(CtlModel.direct_with_enhanced_security.isEnhanced());
    try testing.expect(CtlModel.sbo_with_enhanced_security.isEnhanced());
    try testing.expectEqualStrings("SBO", CtlModel.sbo_with_normal_security.selectAttribute().?);
    try testing.expectEqualStrings("SBOw", CtlModel.sbo_with_enhanced_security.selectAttribute().?);
    try testing.expect(CtlModel.direct_with_enhanced_security.selectAttribute() == null);
}

test "an Oper structure encodes to the octets a third-party client puts on the wire" {
    // The `Oper` value of the captured `GGIO1$CO$SPCSO1$Oper` write. See
    // controlgoldens.zig for the whole frame.
    const captured = [_]u8{
        0xA2, 0x1E,
        0x83, 0x01, 0x01, // ctlVal = true
        0xA2, 0x05, 0x85, 0x01, 0x03, 0x89, 0x00, // origin { orCat = 3, orIdent = "" }
        0x86, 0x01, 0x01, // ctlNum = 1
        0x91, 0x08, 0x6A, 0x62, 0x05, 0x91, 0x62, 0x0C, 0x49, 0x00, // T
        0x83, 0x01, 0x00, // Test = false
        0x84, 0x02, 0x06, 0x00, // Check = { }
    };
    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try mmsdata.Emit.boolean(&vw, true);

    const cmd = Command{
        .ctl_val = vw.done(),
        .origin = .{ .or_cat = .remote_control },
        .ctl_num = 1,
        .t = try mmsdata.UtcTime.parse(captured[17..25]),
        .test_mode = false,
        .check = .{},
    };
    var out: [Command.max_encoded_len]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured, try cmd.encode(&out));

    // And it decodes back to the same fields.
    const back = try Command.decode(try mmsdata.Data.decode(&captured));
    try testing.expectEqual(@as(u8, 1), back.ctl_num);
    try testing.expectEqual(OrCat.remote_control, back.origin.or_cat);
    try testing.expectEqual(@as(usize, 0), back.origin.or_ident.len);
    try testing.expect(back.oper_tm == null);
    try testing.expect(!back.test_mode);
    try testing.expect(!back.check.?.any());
    try testing.expect(try back.boolValue());
}

test "operTm and Check are recovered by shape, not assumed" {
    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try mmsdata.Emit.boolean(&vw, false);
    const t = mmsdata.UtcTime.fromMillis(1_700_000_000_000, 10);
    const oper_tm = mmsdata.UtcTime.fromMillis(1_700_000_060_000, 10);

    // A timed operate: seven members.
    const timed = Command{
        .ctl_val = vw.done(),
        .oper_tm = oper_tm,
        .origin = .{ .or_cat = .station_control, .or_ident = "zig-libs" },
        .ctl_num = 7,
        .t = t,
        .check = .{ .interlock_check = true },
    };
    var buf: [Command.max_encoded_len]u8 = undefined;
    const encoded = try timed.encode(&buf);
    const d = try mmsdata.Data.decode(encoded);
    try d.validate();
    try testing.expectEqual(@as(usize, 7), try d.memberCount());
    const back = try Command.decode(d);
    try testing.expectEqual(oper_tm.seconds, back.oper_tm.?.seconds);
    try testing.expectEqual(OrCat.station_control, back.origin.or_cat);
    try testing.expectEqualStrings("zig-libs", back.origin.or_ident);
    try testing.expectEqual(@as(u8, 7), back.ctl_num);
    try testing.expect(back.check.?.interlock_check);
    try testing.expect(!back.check.?.synchrocheck);

    // A Cancel: no operTm, no Check — five members, and `check` comes back null
    // rather than defaulted, so a caller cannot mistake it for "no overrides".
    const cancel = Command{
        .ctl_val = vw.done(),
        .origin = .{ .or_cat = .bay_control },
        .ctl_num = 7,
        .t = t,
        .check = null,
    };
    const enc2 = try cancel.encode(&buf);
    const d2 = try mmsdata.Data.decode(enc2);
    try testing.expectEqual(@as(usize, 5), try d2.memberCount());
    const back2 = try Command.decode(d2);
    try testing.expect(back2.check == null);
    try testing.expect(back2.oper_tm == null);
}

test "the Check bits are the two safety overrides, in the standard's order" {
    var buf: [16]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try (Check{ .synchrocheck = true, .interlock_check = false }).emit(&w);
    // Two bits, first one set: unused = 6, octet = 0x80.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x84, 0x02, 0x06, 0x80 }, w.done());
    const bs = try (try mmsdata.Data.decode(w.done())).bitString();
    const c = Check.parse(bs);
    try testing.expect(c.synchrocheck and !c.interlock_check);

    var w2 = ber.Writer.init(&buf);
    try (Check{ .interlock_check = true }).emit(&w2);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x84, 0x02, 0x06, 0x40 }, w2.done());
    try testing.expect(Check.parse(try (try mmsdata.Data.decode(w2.done())).bitString()).interlock_check);
}

test "every AddCause is named and out-of-range is a typed error" {
    try testing.expectEqual(@as(usize, 28), @typeInfo(AddCause).@"enum".fields.len);
    try testing.expectEqual(AddCause.blocked_by_interlocking, try AddCause.fromInt(10));
    try testing.expectEqual(AddCause.blocked_by_synchrocheck, try AddCause.fromInt(11));
    try testing.expectEqual(AddCause.object_not_selected, try AddCause.fromInt(18));
    try testing.expectEqual(AddCause.locked_by_other_client, try AddCause.fromInt(27));
    try testing.expectError(error.UnknownAddCause, AddCause.fromInt(28));
    try testing.expectError(error.UnknownAddCause, AddCause.fromInt(-1));
    try testing.expectError(error.UnknownAddCause, AddCause.fromInt(1 << 40));
    // The distinction a retrying client needs.
    try testing.expect(AddCause.blocked_by_synchrocheck.transient());
    try testing.expect(!AddCause.not_supported.transient());
    try testing.expectEqualStrings("select_failed", AddCause.select_failed.name());
}

test "a LastApplError round trips and refuses an impossible AddCause" {
    const e = LastApplError{
        .ctl_obj_ref = "simpleIOGenericIO/GGIO1$CO$SPCSO4",
        .err = .unknown,
        .origin = .{ .or_cat = .remote_control, .or_ident = "zig" },
        .ctl_num = 3,
        .add_cause = .blocked_by_interlocking,
    };
    var buf: [256]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try e.emit(&w);
    const d = try mmsdata.Data.decode(w.done());
    try d.validate();
    const back = try LastApplError.decode(d);
    try testing.expectEqualStrings(e.ctl_obj_ref, back.ctl_obj_ref);
    try testing.expectEqual(ControlError.unknown, back.err);
    try testing.expectEqual(AddCause.blocked_by_interlocking, back.add_cause);
    try testing.expectEqual(@as(u8, 3), back.ctl_num);
    try testing.expect(e.origin.eql(back.origin));

    // An AddCause the standard does not define is refused, not passed through
    // as a number a caller might switch on.
    var bad = ber.Writer.init(&buf);
    const m = bad.mark();
    try mmsdata.Emit.integer(&bad, 99);
    try mmsdata.Emit.unsigned(&bad, 3);
    try (Origin{}).emit(&bad);
    try mmsdata.Emit.integer(&bad, 1);
    try mmsdata.Emit.visibleString(&bad, "LD/LN$CO$DO");
    try mmsdata.Emit.structure(&bad, m);
    try testing.expectError(
        error.UnknownAddCause,
        LastApplError.decode(try mmsdata.Data.decode(bad.done())),
    );
}

test "a control item is recognised only under the CO functional constraint" {
    try testing.expectEqualStrings("Oper", controlAttribute("GGIO1$CO$SPCSO1$Oper").?);
    try testing.expectEqualStrings("SBOw", controlAttribute("GGIO1$CO$SPCSO4$SBOw").?);
    try testing.expectEqualStrings("SBO", controlAttribute("GGIO1$CO$SPCSO2$SBO").?);
    try testing.expectEqualStrings("Cancel", controlAttribute("GGIO1$CO$SPCSO2$Cancel").?);
    try testing.expect(controlAttribute("GGIO1$ST$Ind1$stVal") == null);
    try testing.expect(controlAttribute("Oper") == null);

    const s = splitControlItem("GGIO1$CO$SPCSO1$Oper").?;
    try testing.expectEqualStrings("GGIO1$CO$SPCSO1", s.prefix);
    try testing.expectEqualStrings("Oper", s.attribute);
    // A status attribute that merely ends in `Oper` is not a control object.
    try testing.expect(splitControlItem("GGIO1$ST$SPCSO1$Oper") == null);
    try testing.expect(splitControlItem("GGIO1$SPCSO1$Oper") == null);
}

test "the direct-with-normal-security path is two steps and no waiting" {
    var m = Machine.init(.direct_with_normal_security, 0);
    try testing.expectEqual(Step.write_oper, try m.start(1000));
    try testing.expectEqual(@as(u8, 1), m.ctl_num);
    try testing.expectEqual(State.operating, m.state);
    try testing.expectEqual(Step.finished, try m.operateAccepted(1010));
    try testing.expectEqual(State.succeeded, m.state);
    try testing.expect(m.done());

    // A second command reuses the machine and bumps ctlNum.
    try testing.expectEqual(Step.write_oper, try m.start(2000));
    try testing.expectEqual(@as(u8, 2), m.ctl_num);
}

test "a direct-with-enhanced-security operate is not finished at the write response" {
    var m = Machine.init(.direct_with_enhanced_security, 0);
    try testing.expectEqual(Step.write_oper, try m.start(0));
    // The write succeeded — a naive client stops here and reports success.
    try testing.expectEqual(Step.wait_termination, try m.operateAccepted(100));
    try testing.expectEqual(State.awaiting_termination, m.state);
    try testing.expect(!m.done());

    const n = Notification{ .kind = .command_termination_positive, .command = .{
        .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 },
        .ctl_num = 1,
        .t = mmsdata.UtcTime.fromMillis(0, null),
    } };
    try testing.expectEqual(Step.finished, try m.terminated(n));
    try testing.expectEqual(State.succeeded, m.state);
}

test "a negative CommandTermination carries the AddCause into the failure" {
    var m = Machine.init(.sbo_with_enhanced_security, 2000);
    try testing.expectEqual(Step.write_sbow, try m.start(0));
    try testing.expectEqual(Step.write_oper, try m.selectSucceeded(10));
    try testing.expectEqual(Step.write_oper, try m.beginOperate(20));
    try testing.expectEqual(Step.wait_termination, try m.operateAccepted(30));

    const n = Notification{
        .kind = .command_termination_negative,
        .last_error = .{ .ctl_obj_ref = "LD/GGIO1$CO$SPCSO4", .ctl_num = 1, .add_cause = .abortion_by_trip },
        .command = .{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 1, .t = mmsdata.UtcTime.fromMillis(0, null) },
    };
    try testing.expectEqual(Step.finished, try m.terminated(n));
    try testing.expectEqual(State.failed, m.state);
    try testing.expectEqual(AddCause.abortion_by_trip, m.failure.?.add_cause.?);
    try testing.expectEqual(Stage.terminate, m.failure.?.stage);
    try testing.expect(!m.failure.?.local);
}

test "a termination for another client's ctlNum is refused" {
    var m = Machine.init(.direct_with_enhanced_security, 0);
    _ = try m.start(0);
    _ = try m.operateAccepted(0);
    const other = Notification{ .kind = .command_termination_positive, .command = .{
        .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 },
        .ctl_num = 42,
        .t = mmsdata.UtcTime.fromMillis(0, null),
    } };
    try testing.expectError(error.CtlNumMismatch, m.terminated(other));
    // And the machine is still waiting, not wrongly finished.
    try testing.expectEqual(State.awaiting_termination, m.state);
}

test "a select that expires mid-operate fails locally instead of at the IED" {
    var m = Machine.init(.sbo_with_normal_security, 2000);
    try testing.expectEqual(Step.read_sbo, try m.start(1000));
    try testing.expectEqual(Step.write_oper, try m.selectSucceeded(1100));
    try testing.expectEqual(@as(u64, 3100), m.select_deadline_ms);
    // The operator hesitated past sboTimeout.
    try testing.expectError(error.SelectExpired, m.beginOperate(3200));
    try testing.expectEqual(State.failed, m.state);
    try testing.expectEqual(AddCause.object_not_selected, m.failure.?.add_cause.?);
    try testing.expect(m.failure.?.local);
}

test "tick is the only place time enters the client machine" {
    var m = Machine.init(.sbo_with_enhanced_security, 1000);
    _ = try m.start(0);
    try testing.expect(m.tick(500) == null);
    const f = m.tick(1000).?;
    try testing.expectEqual(Stage.select, f.stage);
    try testing.expectEqual(AddCause.time_limit_over, f.add_cause.?);
    try testing.expectEqual(State.failed, m.state);

    // The termination wait has its own patience limit.
    var m2 = Machine.init(.direct_with_enhanced_security, 0);
    m2.termination_timeout_ms = 5_000;
    _ = try m2.start(0);
    _ = try m2.operateAccepted(0);
    try testing.expect(m2.tick(4_999) == null);
    try testing.expectEqual(AddCause.time_limit_over, m2.tick(5_000).?.add_cause.?);
}

test "a status-only object cannot be operated at all" {
    var m = Machine.init(.status_only, 0);
    try testing.expectError(error.ControlRejected, m.start(0));
    try testing.expectEqual(AddCause.not_supported, m.failure.?.add_cause.?);
}

test "the machine refuses to be driven out of order" {
    var m = Machine.init(.sbo_with_normal_security, 0);
    try testing.expectError(error.WrongState, m.selectSucceeded(0));
    try testing.expectError(error.WrongState, m.operateAccepted(0));
    _ = try m.start(0);
    try testing.expectError(error.WrongState, m.operateAccepted(0));
    try testing.expectError(error.WrongState, m.start(0));
}

test "the server refuses an operate on an unselected sbo object" {
    var p = Point{ .item = "GGIO1$CO$SPCSO2", .domain = "LD", .ctl_model = .sbo_with_normal_security };
    const cmd = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 1, .t = mmsdata.UtcTime.fromMillis(0, null) };
    try testing.expectEqual(Outcome{ .rejected = .object_not_selected }, p.operate(1, cmd, 0));

    // Select, then operate.
    try testing.expectEqual(Outcome{ .accepted = .{} }, p.select(1, null, 0));
    try testing.expectEqual(PointState.selected, p.state);
    try testing.expectEqual(Outcome{ .accepted = .{} }, p.operate(1, cmd, 10));
    // Normal security completes at the write; no termination is owed.
    try testing.expectEqual(PointState.unselected, p.state);
}

test "a select expires at sboTimeout and the operate that follows says why" {
    var p = Point{
        .item = "GGIO1$CO$SPCSO2",
        .domain = "LD",
        .ctl_model = .sbo_with_normal_security,
        .sbo_timeout_ms = 2000,
    };
    _ = p.select(1, null, 1000);
    try testing.expectEqual(@as(u64, 3000), p.select_deadline_ms);
    try testing.expect(!p.tick(2999));
    try testing.expect(p.tick(3000));
    try testing.expectEqual(PointState.unselected, p.state);

    const cmd = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 1, .t = mmsdata.UtcTime.fromMillis(0, null) };
    try testing.expectEqual(Outcome{ .rejected = .object_not_selected }, p.operate(1, cmd, 3100));
}

test "another client cannot steal or operate a held select" {
    var p = Point{ .item = "GGIO1$CO$SPCSO4", .domain = "LD", .ctl_model = .sbo_with_enhanced_security };
    const cmd = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 5, .t = mmsdata.UtcTime.fromMillis(0, null) };
    try testing.expectEqual(Outcome{ .accepted = .{} }, p.select(1, cmd, 0));
    try testing.expectEqual(Outcome{ .rejected = .locked_by_other_client }, p.select(2, cmd, 0));
    try testing.expectEqual(Outcome{ .rejected = .locked_by_other_client }, p.operate(2, cmd, 0));
    // Re-selecting your own object is legal.
    try testing.expectEqual(Outcome{ .accepted = .{} }, p.select(1, cmd, 0));
}

test "the SBOw ctlNum must be repeated by the Oper" {
    var p = Point{ .item = "GGIO1$CO$SPCSO4", .domain = "LD", .ctl_model = .sbo_with_enhanced_security };
    const t = mmsdata.UtcTime.fromMillis(0, null);
    const select = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 5, .t = t };
    const wrong = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 6, .t = t };
    const right = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 5, .t = t };
    _ = p.select(1, select, 0);
    try testing.expectEqual(Outcome{ .rejected = .inconsistent_parameters }, p.operate(1, wrong, 0));
    const ok = p.operate(1, right, 0);
    try testing.expect(ok.accepted.terminate);
    try testing.expectEqual(PointState.executing, p.state);
    try testing.expect(p.completed());
    try testing.expectEqual(PointState.unselected, p.state);
}

test "the interlocks produce the AddCause a real IED produces" {
    const t = mmsdata.UtcTime.fromMillis(0, null);
    const plain = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 1, .t = t };
    const override = Command{
        .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 },
        .ctl_num = 1,
        .t = t,
        .check = .{ .interlock_check = true, .synchrocheck = true },
    };

    var p = Point{ .item = "GGIO1$CO$SPCSO1", .domain = "LD", .ctl_model = .direct_with_normal_security };
    p.interlocked = true;
    try testing.expectEqual(Outcome{ .rejected = .blocked_by_interlocking }, p.operate(1, plain, 0));
    // Asking to skip the check does nothing unless the IED allows overrides.
    try testing.expectEqual(Outcome{ .rejected = .blocked_by_interlocking }, p.operate(1, override, 0));
    p.allow_check_override = true;
    try testing.expectEqual(Outcome{ .accepted = .{} }, p.operate(1, override, 0));

    p.interlocked = false;
    p.synchrocheck_failed = true;
    p.allow_check_override = false;
    try testing.expectEqual(Outcome{ .rejected = .blocked_by_synchrocheck }, p.operate(1, plain, 0));

    p.synchrocheck_failed = false;
    p.unhealthy = true;
    try testing.expectEqual(Outcome{ .rejected = .blocked_by_health }, p.operate(1, plain, 0));
    p.unhealthy = false;
    p.blocked_by_mode = true;
    try testing.expectEqual(Outcome{ .rejected = .blocked_by_mode }, p.operate(1, plain, 0));

    var s = Point{ .item = "GGIO1$CO$Mod", .domain = "LD", .ctl_model = .status_only };
    try testing.expectEqual(Outcome{ .rejected = .not_supported }, s.operate(1, plain, 0));
    try testing.expectEqual(Outcome{ .rejected = .not_supported }, s.select(1, null, 0));
}

test "a Cancel aborts a select and an execution, and is refused when there is neither" {
    const t = mmsdata.UtcTime.fromMillis(0, null);
    const cmd = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 4, .t = t, .check = null };
    var p = Point{ .item = "GGIO1$CO$SPCSO4", .domain = "LD", .ctl_model = .sbo_with_enhanced_security };
    try testing.expectEqual(Outcome{ .rejected = .object_not_selected }, p.cancel(1, cmd, 0));

    _ = p.select(1, .{ .ctl_val = cmd.ctl_val, .ctl_num = 4, .t = t }, 0);
    const c1 = p.cancel(1, cmd, 10);
    try testing.expect(!c1.accepted.terminate); // nothing was executing
    try testing.expectEqual(PointState.unselected, p.state);

    _ = p.select(1, .{ .ctl_val = cmd.ctl_val, .ctl_num = 4, .t = t }, 20);
    _ = p.operate(1, .{ .ctl_val = cmd.ctl_val, .ctl_num = 4, .t = t }, 25);
    try testing.expectEqual(PointState.executing, p.state);
    // A cancel during execution owes a negative CommandTermination.
    const c2 = p.cancel(1, cmd, 30);
    try testing.expect(c2.accepted.terminate);
    try testing.expectEqual(PointState.unselected, p.state);
}

test "an execution that never completes is timed out by the server" {
    const t = mmsdata.UtcTime.fromMillis(0, null);
    const cmd = Command{ .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 }, .ctl_num = 1, .t = t };
    var p = Point{
        .item = "GGIO1$CO$SPCSO3",
        .domain = "LD",
        .ctl_model = .direct_with_enhanced_security,
        .execution_timeout_ms = 1000,
    };
    _ = p.operate(1, cmd, 500);
    try testing.expectEqual(PointState.executing, p.state);
    try testing.expect(!p.tick(1499));
    try testing.expect(p.tick(1500));
    try testing.expectEqual(PointState.unselected, p.state);
    // And a second operate cannot be accepted while one is executing.
    _ = p.operate(1, cmd, 2000);
    try testing.expectEqual(Outcome{ .rejected = .command_already_in_execution }, p.operate(1, cmd, 2001));
}

test "the SBO reference a select returns is the object reference" {
    const p = Point{ .item = "GGIO1$CO$SPCSO2", .domain = "simpleIOGenericIO", .ctl_model = .sbo_with_normal_security };
    var buf: [64]u8 = undefined;
    // Exactly what the captured IED answered the SBO read with.
    try testing.expectEqualStrings("simpleIOGenericIO/GGIO1$CO$SPCSO2", try p.sboReference(&buf));
    var small: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, p.sboReference(&small));
}

test "controlName injects CO and the control attribute" {
    var buf: [128]u8 = undefined;
    const n = try controlName("simpleIOGenericIO/GGIO1.SPCSO1", .CO, "Oper", &buf);
    try testing.expectEqualStrings("simpleIOGenericIO", n.domain_specific.domain);
    try testing.expectEqualStrings("GGIO1$CO$SPCSO1$Oper", n.domain_specific.item);
    const c = try controlName("simpleIOGenericIO/GGIO1.SPCSO2", .CF, "ctlModel", &buf);
    try testing.expectEqualStrings("GGIO1$CF$SPCSO2$ctlModel", c.domain_specific.item);
    // A bare logical node names no control object.
    try testing.expectError(error.NotAControlObject, controlName("LD/GGIO1", .CO, "Oper", &buf));
}

test "fuzz: control structures decode to a typed error or a valid value" {
    try std.testing.fuzz({}, fuzzControl, .{});
}

fn fuzzControl(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const bytes = buf[0..len];
    const d = mmsdata.Data.decode(bytes) catch return;
    d.validate() catch return;

    if (Command.decode(d)) |cmd| {
        // Anything that decoded must re-encode and decode again to the same
        // shape — the control structure is the one a write puts on the wire.
        var out: [1024]u8 = undefined;
        const again = cmd.encode(&out) catch return;
        const back = try Command.decode(try mmsdata.Data.decode(again));
        try testing.expectEqual(cmd.ctl_num, back.ctl_num);
        try testing.expectEqual(cmd.test_mode, back.test_mode);
        try testing.expectEqual(cmd.oper_tm == null, back.oper_tm == null);
        try testing.expectEqual(cmd.check == null, back.check == null);
        try testing.expect(cmd.origin.eql(back.origin));
    } else |_| {}

    if (LastApplError.decode(d)) |e| {
        var out: [1024]u8 = undefined;
        var w = ber.Writer.init(&out);
        e.emit(&w) catch return;
        const back = try LastApplError.decode(try mmsdata.Data.decode(w.done()));
        try testing.expectEqual(e.add_cause, back.add_cause);
        try testing.expectEqual(e.ctl_num, back.ctl_num);
        try testing.expectEqualStrings(e.ctl_obj_ref, back.ctl_obj_ref);
    } else |_| {}

    _ = CtlModel.fromData(d) catch {};
}

test "fuzz: classifying an unsolicited report never panics" {
    try std.testing.fuzz({}, fuzzClassify, .{});
}

fn fuzzClassify(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const info = mms.decodeInformationReport(buf[0..len]) catch return;
    _ = classify(info) catch return;
}

test "fuzz: the server-side point never panics and never wedges" {
    try std.testing.fuzz({}, fuzzPoint, .{});
}

fn fuzzPoint(_: void, smith: *std.testing.Smith) !void {
    var p = Point{
        .item = "GGIO1$CO$SPCSO1",
        .domain = "LD",
        .ctl_model = try CtlModel.fromInt(smith.valueRangeAtMost(u8, 0, 4)),
        .sbo_timeout_ms = smith.valueRangeAtMost(u16, 0, 5000),
        .execution_timeout_ms = smith.valueRangeAtMost(u16, 0, 5000),
    };
    var now: u64 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        now += smith.valueRangeAtMost(u16, 0, 2000);
        const cmd = Command{
            .ctl_val = &[_]u8{ 0x83, 0x01, 0x01 },
            .ctl_num = smith.valueRangeAtMost(u8, 0, 255),
            .t = mmsdata.UtcTime.fromMillis(now, null),
        };
        switch (smith.valueRangeAtMost(u8, 0, 4)) {
            0 => _ = p.select(smith.valueRangeAtMost(u8, 1, 3), null, now),
            1 => _ = p.select(smith.valueRangeAtMost(u8, 1, 3), cmd, now),
            2 => _ = p.operate(smith.valueRangeAtMost(u8, 1, 3), cmd, now),
            3 => _ = p.cancel(smith.valueRangeAtMost(u8, 1, 3), cmd, now),
            else => _ = p.tick(now),
        }
        // An unselected point never holds an owner or a deadline.
        if (p.state == .unselected) {
            try testing.expectEqual(@as(u32, 0), p.owner);
            try testing.expectEqual(@as(u64, 0), p.select_deadline_ms);
        }
    }
}

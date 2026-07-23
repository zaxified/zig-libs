// SPDX-License-Identifier: MIT

//! **Setting groups** (IEC 61850-7-2 §19): several complete parameter sets in
//! one IED, one of them active, another one editable — and a two-step
//! edit-then-confirm protocol between them.
//!
//! The whole point is that a protection engineer can change a whole set of
//! relay settings *without* any of them taking effect halfway through. The
//! services are:
//!
//! | ACSI                  | on the wire                    |
//! |-----------------------|--------------------------------|
//! | `SelectActiveSG`      | write `LLN0$SP$SGCB$ActSG`     |
//! | `SelectEditSG`        | write `LLN0$SP$SGCB$EditSG`    |
//! | `SetEditSGValue`      | write `LN$SE$…`                |
//! | `ConfirmEditSGValues` | write `LLN0$SP$SGCB$CnfEdit`   |
//! | `GetSGValues`         | read `LN$SG$…`                 |
//! | `GetEditSGValue`      | read `LN$SE$…`                 |
//!
//! There are no new MMS services: everything is a `Read` or a `Write` on names
//! the SCL resolver already produces, which is why `scl.zig` mirrors every `SE`
//! attribute into an `SG` one.
//!
//! **The invariant this file exists to hold:** an edit that has not been
//! confirmed is invisible. Writing `LN$SE$StrVal$setMag$f` changes the *edit
//! buffer*; reading `LN$SG$StrVal$setMag$f` still returns the active group's
//! value. Only `CnfEdit = true` copies the buffer into the group it was
//! selected for, and a confirm with no preceding edit is refused rather than
//! silently committing whatever was in the buffer.
//!
//! Storage is caller-owned: each `Setting` gets `NumOfSG + 1` equal slots — one
//! per group and one edit buffer. Nothing allocates.

const std = @import("std");
const ber = @import("ber.zig");
const mmsdata = @import("mmsdata.zig");
const reporting = @import("reporting.zig");

pub const Error = error{
    /// The group number is outside `1..NumOfSG`.
    BadGroup,
    /// `SetEditSGValue` or `ConfirmEditSGValues` with no `SelectEditSG` first.
    NoEditGroup,
    /// `ConfirmEditSGValues` with nothing edited since the selection.
    NothingEdited,
    /// Another client holds the edit selection.
    EditGroupBusy,
    /// The value does not fit the slot the caller supplied.
    ValueTooLarge,
    /// The caller's `Setting` storage is not `NumOfSG + 1` usable slots.
    SettingStorageTooSmall,
    /// No such attribute on the SGCB.
    UnknownAttribute,
};

pub const WriteOutcome = reporting.WriteOutcome;

/// The five mandatory attributes of the setting-group control block, in MMS
/// structure order. Confirmed member by member against a live third-party IED.
pub const sgcb_attributes = [_][]const u8{ "NumOfSG", "ActSG", "EditSG", "CnfEdit", "LActTm" };

// ── one setting ─────────────────────────────────────────────────────────────

/// One functionally-constrained setting, held once per group plus once in the
/// edit buffer.
///
/// The MMS names are derived, not stored twice: `<ln>$SG$<path>` is the active
/// group's read-only view and `<ln>$SE$<path>` is the editable one.
pub const Setting = struct {
    domain: []const u8,
    /// The logical node, e.g. `PTOC1`.
    ln: []const u8,
    /// Everything below the functional constraint, e.g. `StrVal$setMag$f`.
    path: []const u8,
    /// `groups + 1` equal slots: slot `g - 1` is group `g`, the last is the
    /// edit buffer.
    storage: []u8,
    /// One length per slot; same length as the slot count.
    lens: []usize,

    pub fn slotCount(self: Setting) usize {
        return self.lens.len;
    }

    pub fn slotLen(self: Setting) usize {
        return self.storage.len / self.lens.len;
    }

    fn slot(self: Setting, index: usize) []u8 {
        const n = self.slotLen();
        return self.storage[index * n ..][0..n];
    }

    pub fn value(self: Setting, index: usize) []const u8 {
        return self.slot(index)[0..self.lens[index]];
    }

    fn store(self: Setting, index: usize, bytes: []const u8) Error!void {
        const s = self.slot(index);
        if (bytes.len > s.len) return error.ValueTooLarge;
        @memcpy(s[0..bytes.len], bytes);
        self.lens[index] = bytes.len;
    }

    fn editIndex(self: Setting) usize {
        return self.lens.len - 1;
    }
};

/// Which half of a setting a name addresses.
pub const Half = enum { active, edit };

// ── the control block ───────────────────────────────────────────────────────

pub const ControlBlock = struct {
    domain: []const u8,
    /// Always `LLN0$SP$SGCB` in practice; kept configurable because the logical
    /// node name is the caller's.
    item: []const u8 = "LLN0$SP$SGCB",
    /// `NumOfSG`.
    groups: u8 = 1,
    settings: []Setting = &.{},

    // state
    act_sg: u8 = 1,
    edit_sg: u8 = 0,
    /// `LActTm` — when the active group last changed.
    l_act_tm_ms: u64 = 0,
    /// How many bits of `LActTm`'s fraction the server claims are significant.
    /// Ten is millisecond resolution; the default zero matches the reference
    /// IED, which is what a server whose clock the caller supplies should say.
    time_accuracy: ?u5 = 0,
    /// The client holding the edit selection.
    editor: ?u32 = null,
    /// Whether anything has been written to the edit buffer since the
    /// selection. `ConfirmEditSGValues` without this is refused.
    edited: bool = false,
    // diagnostics
    activations: u64 = 0,
    confirmations: u64 = 0,

    /// Checks the caller's storage matches `groups`.
    pub fn validate(self: *const ControlBlock) Error!void {
        if (self.groups == 0) return error.BadGroup;
        for (self.settings) |s| {
            if (s.lens.len != @as(usize, self.groups) + 1) return error.SettingStorageTooSmall;
            if (s.storage.len < s.lens.len) return error.SettingStorageTooSmall;
        }
    }

    // ── the services ────────────────────────────────────────────────────────

    /// `SelectActiveSG`. The active group changes immediately, which is the one
    /// setting-group operation that *is* a single step.
    pub fn selectActiveSG(self: *ControlBlock, group: u8, now_ms: u64) Error!void {
        if (group == 0 or group > self.groups) return error.BadGroup;
        self.act_sg = group;
        self.l_act_tm_ms = now_ms;
        self.activations += 1;
    }

    /// `SelectEditSG`. Group 0 releases the selection. Selecting a group loads
    /// its values into the edit buffer, so a client that edits one attribute
    /// and confirms does not blank the rest.
    pub fn selectEditSG(self: *ControlBlock, group: u8, peer: u32) Error!void {
        if (group == 0) {
            if (self.editor) |o| {
                if (o != peer) return error.EditGroupBusy;
            }
            self.edit_sg = 0;
            self.editor = null;
            self.edited = false;
            return;
        }
        if (group > self.groups) return error.BadGroup;
        if (self.editor) |o| {
            if (o != peer and self.edit_sg != 0) return error.EditGroupBusy;
        }
        self.edit_sg = group;
        self.editor = peer;
        self.edited = false;
        for (self.settings) |s| {
            try s.store(s.editIndex(), s.value(group - 1));
        }
    }

    /// `SetEditSGValue` — a write to `LN$SE$…`.
    pub fn setEditValue(self: *ControlBlock, index: usize, peer: u32, value: []const u8) Error!void {
        if (self.edit_sg == 0) return error.NoEditGroup;
        if (self.editor) |o| {
            if (o != peer) return error.EditGroupBusy;
        }
        if (index >= self.settings.len) return error.BadGroup;
        const s = self.settings[index];
        try s.store(s.editIndex(), value);
        self.edited = true;
    }

    /// `ConfirmEditSGValues`. This is the step that makes an edit real: until it
    /// runs, `GetSGValues` is unchanged even when the edited group *is* the
    /// active one.
    pub fn confirmEdit(self: *ControlBlock, peer: u32) Error!void {
        if (self.edit_sg == 0) return error.NoEditGroup;
        if (self.editor) |o| {
            if (o != peer) return error.EditGroupBusy;
        }
        if (!self.edited) return error.NothingEdited;
        const group = self.edit_sg - 1;
        for (self.settings) |s| {
            try s.store(group, s.value(s.editIndex()));
        }
        self.edited = false;
        self.confirmations += 1;
    }

    /// `GetSGValues` — the active group's value of one setting.
    pub fn activeValue(self: *const ControlBlock, index: usize) Error![]const u8 {
        if (index >= self.settings.len) return error.BadGroup;
        return self.settings[index].value(self.act_sg - 1);
    }

    /// `GetEditSGValue`. Reading an `SE` attribute with no edit group selected
    /// is refused — which is exactly what a real IED does, and why a client that
    /// browses the whole name space sees `SE` reads fail until it selects.
    pub fn editValue(self: *const ControlBlock, index: usize) Error![]const u8 {
        if (self.edit_sg == 0) return error.NoEditGroup;
        if (index >= self.settings.len) return error.BadGroup;
        const s = self.settings[index];
        return s.value(s.editIndex());
    }

    /// The association went away: any half-finished edit is dropped. Leaving it
    /// selected would lock every other client out of the setting groups for
    /// good.
    pub fn associationLost(self: *ControlBlock, peer: u32) void {
        if (self.editor) |o| {
            if (o != peer) return;
        }
        self.edit_sg = 0;
        self.editor = null;
        self.edited = false;
    }

    // ── name resolution ─────────────────────────────────────────────────────

    /// Finds the setting an MMS item id addresses, and which half.
    /// `PTOC1$SE$StrVal$setMag$f` → `{index, .edit}`.
    pub fn find(self: *const ControlBlock, domain: []const u8, item: []const u8) ?struct {
        index: usize,
        half: Half,
    } {
        for (self.settings, 0..) |s, i| {
            if (!std.mem.eql(u8, s.domain, domain)) continue;
            if (!std.mem.startsWith(u8, item, s.ln)) continue;
            const rest = item[s.ln.len..];
            const half: Half = if (std.mem.startsWith(u8, rest, "$SG$"))
                .active
            else if (std.mem.startsWith(u8, rest, "$SE$"))
                .edit
            else
                continue;
            if (!std.mem.eql(u8, rest[4..], s.path)) continue;
            return .{ .index = i, .half = half };
        }
        return null;
    }

    // ── the SGCB as an MMS variable ─────────────────────────────────────────

    pub fn attributes(_: *const ControlBlock) []const []const u8 {
        return &sgcb_attributes;
    }

    pub fn emitStructure(self: *const ControlBlock, w: *ber.Writer) !void {
        const m = w.mark();
        var i: usize = sgcb_attributes.len;
        while (i > 0) {
            i -= 1;
            try self.emitAttribute(sgcb_attributes[i], w);
        }
        try mmsdata.Emit.structure(w, m);
    }

    pub fn emitAttribute(self: *const ControlBlock, name: []const u8, w: *ber.Writer) !void {
        const eq = std.mem.eql;
        if (eq(u8, name, "NumOfSG")) {
            try mmsdata.Emit.unsigned(w, self.groups);
        } else if (eq(u8, name, "ActSG")) {
            try mmsdata.Emit.unsigned(w, self.act_sg);
        } else if (eq(u8, name, "EditSG")) {
            try mmsdata.Emit.unsigned(w, self.edit_sg);
        } else if (eq(u8, name, "CnfEdit")) {
            // `CnfEdit` reads back as "an edit is pending", which is the only
            // useful thing a client can learn from it.
            try mmsdata.Emit.boolean(w, self.edited);
        } else if (eq(u8, name, "LActTm")) {
            // `TimeAccuracy` is declared, not left "unspecified": a caller-fed
            // clock has whatever resolution the caller gives it, and the
            // reference IED emits 0 for a timestamp it has never set.
            try mmsdata.Emit.utcTime(w, mmsdata.UtcTime.fromMillis(self.l_act_tm_ms, self.time_accuracy));
        } else if (eq(u8, name, "ResvTms")) {
            try mmsdata.Emit.unsigned(w, 0);
        } else return error.UnknownAttribute;
    }

    /// Applies a client write to one SGCB attribute.
    pub fn writeAttribute(
        self: *ControlBlock,
        name: []const u8,
        d: mmsdata.Data,
        peer: u32,
        now_ms: u64,
    ) WriteOutcome {
        const eq = std.mem.eql;
        if (eq(u8, name, "ActSG")) {
            const v = d.unsigned(u32) catch return .invalid;
            if (v > 255) return .invalid;
            self.selectActiveSG(@intCast(v), now_ms) catch return .invalid;
            return .ok;
        }
        if (eq(u8, name, "EditSG")) {
            const v = d.unsigned(u32) catch return .invalid;
            if (v > 255) return .invalid;
            self.selectEditSG(@intCast(v), peer) catch |e| return switch (e) {
                error.EditGroupBusy => .denied,
                else => .invalid,
            };
            return .ok;
        }
        if (eq(u8, name, "CnfEdit")) {
            const v = d.boolean() catch return .invalid;
            if (!v) return .ok;
            self.confirmEdit(peer) catch |e| return switch (e) {
                error.EditGroupBusy => .denied,
                // A confirm with no preceding edit is a client bug, and saying
                // so beats committing an empty buffer over a live relay setting.
                error.NoEditGroup, error.NothingEdited => .invalid,
                else => .invalid,
            };
            return .ok;
        }
        if (eq(u8, name, "NumOfSG") or eq(u8, name, "LActTm")) return .denied;
        return .unknown;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// **Third-party golden.** The SGCB structure a real IED returned for
/// `LLN0$SP$SGCB`: five groups, group one active, nothing being edited.
const oracle_sgcb = [_]u8{
    0xA2, 0x16,
    0x86, 0x01,
    0x05, 0x86,
    0x01, 0x01,
    0x86, 0x01,
    0x00, 0x83,
    0x01, 0x00,
    0x91, 0x08,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
};

test "the captured SGCB decodes into the five attributes in order" {
    const d = try mmsdata.Data.decode(&oracle_sgcb);
    try d.validate();
    var it = try d.members();
    try testing.expectEqual(@as(u32, 5), try (try it.next()).?.unsigned(u32));
    try testing.expectEqual(@as(u32, 1), try (try it.next()).?.unsigned(u32));
    try testing.expectEqual(@as(u32, 0), try (try it.next()).?.unsigned(u32));
    try testing.expectEqual(false, try (try it.next()).?.boolean());
    const t = try (try it.next()).?.utcTime();
    try testing.expectEqual(@as(u64, 0), t.millis());
    try testing.expect((try it.next()) == null);
}

test "our SGCB emitter reproduces the captured structure octet for octet" {
    var cb = ControlBlock{ .domain = "DEMOPROT", .groups = 5 };
    var buf: [128]u8 = undefined;
    var w = ber.Writer.init(&buf);
    try cb.emitStructure(&w);
    try testing.expectEqualSlices(u8, &oracle_sgcb, w.done());
}

/// Two settings across three groups plus an edit buffer.
const Fixture = struct {
    a_store: [4 * 16]u8 = undefined,
    a_lens: [4]usize = @splat(0),
    b_store: [4 * 16]u8 = undefined,
    b_lens: [4]usize = @splat(0),
    settings: [2]Setting = undefined,

    fn init(self: *Fixture) !ControlBlock {
        self.settings[0] = .{
            .domain = "DEMOPROT",
            .ln = "PTOC1",
            .path = "StrVal$setMag$f",
            .storage = &self.a_store,
            .lens = &self.a_lens,
        };
        self.settings[1] = .{
            .domain = "DEMOPROT",
            .ln = "PTOC1",
            .path = "OpDlTmms$setVal",
            .storage = &self.b_store,
            .lens = &self.b_lens,
        };
        // Group 1..3 get 1.0, 2.0, 3.0 and 100, 200, 300.
        for (0..3) |g| {
            try seedFloat(self.settings[0], g, @floatFromInt(g + 1));
            try seedInt(self.settings[1], g, @intCast((g + 1) * 100));
        }
        var cb = ControlBlock{ .domain = "DEMOPROT", .groups = 3, .settings = &self.settings };
        try cb.validate();
        return cb;
    }
};

fn seedFloat(s: Setting, slot: usize, v: f32) !void {
    var tmp: [16]u8 = undefined;
    var w = ber.Writer.init(&tmp);
    try mmsdata.Emit.float(&w, v);
    try s.store(slot, w.done());
}

fn seedInt(s: Setting, slot: usize, v: i64) !void {
    var tmp: [16]u8 = undefined;
    var w = ber.Writer.init(&tmp);
    try mmsdata.Emit.integer(&w, v);
    try s.store(slot, w.done());
}

fn floatOf(bytes: []const u8) !f64 {
    return (try mmsdata.Data.decode(bytes)).asFloat();
}

test "SelectActiveSG switches which group GetSGValues returns" {
    var fx: Fixture = .{};
    var cb = try fx.init();
    try testing.expectApproxEqAbs(@as(f64, 1.0), try floatOf(try cb.activeValue(0)), 1e-6);
    try cb.selectActiveSG(3, 1234);
    try testing.expectApproxEqAbs(@as(f64, 3.0), try floatOf(try cb.activeValue(0)), 1e-6);
    try testing.expectEqual(@as(u64, 1234), cb.l_act_tm_ms);
    try testing.expectError(error.BadGroup, cb.selectActiveSG(0, 0));
    try testing.expectError(error.BadGroup, cb.selectActiveSG(4, 0));
    // A refused selection changes nothing.
    try testing.expectEqual(@as(u8, 3), cb.act_sg);
}

test "an uncommitted edit is invisible, even to the group it edits" {
    var fx: Fixture = .{};
    var cb = try fx.init();
    // Edit the *active* group — the case where a leak would be worst.
    try cb.selectEditSG(1, 7);
    try seedFloatInto(&cb, 0, 42.0, 7);
    // The edit buffer has it…
    try testing.expectApproxEqAbs(@as(f64, 42.0), try floatOf(try cb.editValue(0)), 1e-6);
    // …and the active group does not.
    try testing.expectApproxEqAbs(@as(f64, 1.0), try floatOf(try cb.activeValue(0)), 1e-6);

    try cb.confirmEdit(7);
    try testing.expectApproxEqAbs(@as(f64, 42.0), try floatOf(try cb.activeValue(0)), 1e-6);
    try testing.expectEqual(@as(u64, 1), cb.confirmations);
}

fn seedFloatInto(cb: *ControlBlock, index: usize, v: f32, peer: u32) !void {
    var tmp: [16]u8 = undefined;
    var w = ber.Writer.init(&tmp);
    try mmsdata.Emit.float(&w, v);
    try cb.setEditValue(index, peer, w.done());
}

test "SelectEditSG loads the group so an unedited setting is not blanked" {
    var fx: Fixture = .{};
    var cb = try fx.init();
    try cb.selectEditSG(2, 1);
    // Only the first setting is edited.
    try seedFloatInto(&cb, 0, 9.0, 1);
    try cb.confirmEdit(1);
    try cb.selectActiveSG(2, 0);
    try testing.expectApproxEqAbs(@as(f64, 9.0), try floatOf(try cb.activeValue(0)), 1e-6);
    // The second still holds group two's original value, not zero.
    try testing.expectEqual(@as(i64, 200), try (try mmsdata.Data.decode(try cb.activeValue(1))).asInt());
}

test "a confirm without a preceding edit is refused" {
    var fx: Fixture = .{};
    var cb = try fx.init();
    try testing.expectError(error.NoEditGroup, cb.confirmEdit(1));
    try cb.selectEditSG(1, 1);
    try testing.expectError(error.NothingEdited, cb.confirmEdit(1));
    // …and a write to SE without a selection is refused too.
    try cb.selectEditSG(0, 1);
    var tmp: [16]u8 = undefined;
    var w = ber.Writer.init(&tmp);
    try mmsdata.Emit.float(&w, 1.0);
    try testing.expectError(error.NoEditGroup, cb.setEditValue(0, 1, w.done()));
    try testing.expectError(error.NoEditGroup, cb.editValue(0));
}

test "a second client cannot take the edit selection or confirm someone else's" {
    var fx: Fixture = .{};
    var cb = try fx.init();
    try cb.selectEditSG(2, 1);
    try testing.expectError(error.EditGroupBusy, cb.selectEditSG(3, 2));
    try seedFloatInto(&cb, 0, 5.0, 1);
    try testing.expectError(error.EditGroupBusy, cb.confirmEdit(2));
    try cb.confirmEdit(1);
    // When that client's association drops, the selection is released.
    try cb.selectEditSG(2, 1);
    cb.associationLost(1);
    try cb.selectEditSG(3, 2);
    try testing.expectEqual(@as(u8, 3), cb.edit_sg);
}

test "an SE or SG name resolves to the right setting and half" {
    var fx: Fixture = .{};
    const cb = try fx.init();
    const a = cb.find("DEMOPROT", "PTOC1$SE$StrVal$setMag$f").?;
    try testing.expectEqual(@as(usize, 0), a.index);
    try testing.expectEqual(Half.edit, a.half);
    const b = cb.find("DEMOPROT", "PTOC1$SG$OpDlTmms$setVal").?;
    try testing.expectEqual(@as(usize, 1), b.index);
    try testing.expectEqual(Half.active, b.half);
    // A functional constraint that is not a setting one does not resolve.
    try testing.expect(cb.find("DEMOPROT", "PTOC1$ST$StrVal$setMag$f") == null);
    try testing.expect(cb.find("OTHER", "PTOC1$SG$StrVal$setMag$f") == null);
    try testing.expect(cb.find("DEMOPROT", "PTOC1$SG$Nope") == null);
}

test "a value larger than the slot is refused rather than overrunning it" {
    var fx: Fixture = .{};
    var cb = try fx.init();
    try cb.selectEditSG(1, 1);
    const big = [_]u8{0x8A} ++ [_]u8{0x20} ++ ("x" ** 32).*;
    try testing.expectError(error.ValueTooLarge, cb.setEditValue(0, 1, &big));
    try testing.expectError(error.BadGroup, cb.setEditValue(9, 1, &big));
}

test "storage that does not match NumOfSG is refused at validate" {
    var store: [4 * 8]u8 = undefined;
    var lens: [4]usize = @splat(0);
    var settings = [_]Setting{.{
        .domain = "D",
        .ln = "PTOC1",
        .path = "x",
        .storage = &store,
        .lens = &lens,
    }};
    // Four slots means three groups plus an edit buffer, not five.
    var cb = ControlBlock{ .domain = "D", .groups = 5, .settings = &settings };
    try testing.expectError(error.SettingStorageTooSmall, cb.validate());
    cb.groups = 3;
    try cb.validate();
    cb.groups = 0;
    try testing.expectError(error.BadGroup, cb.validate());
}

test "the SGCB write path maps every service onto its attribute" {
    var fx: Fixture = .{};
    var cb = try fx.init();
    var buf: [16]u8 = undefined;

    var w = ber.Writer.init(&buf);
    try mmsdata.Emit.unsigned(&w, 2);
    const two = try mmsdata.Data.decode(w.done());
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("ActSG", two, 1, 99));
    try testing.expectEqual(@as(u8, 2), cb.act_sg);
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("EditSG", two, 1, 0));
    try testing.expectEqual(@as(u8, 2), cb.edit_sg);

    var bw = ber.Writer.init(&buf);
    try mmsdata.Emit.boolean(&bw, true);
    const yes = try mmsdata.Data.decode(bw.done());
    // Nothing edited yet.
    try testing.expectEqual(WriteOutcome.invalid, cb.writeAttribute("CnfEdit", yes, 1, 0));
    try seedFloatInto(&cb, 0, 7.5, 1);
    try testing.expectEqual(WriteOutcome.ok, cb.writeAttribute("CnfEdit", yes, 1, 0));
    try testing.expectApproxEqAbs(@as(f64, 7.5), try floatOf(try cb.activeValue(0)), 1e-6);

    // Out of range, read-only and unknown.
    var ow = ber.Writer.init(&buf);
    try mmsdata.Emit.unsigned(&ow, 9);
    const nine = try mmsdata.Data.decode(ow.done());
    try testing.expectEqual(WriteOutcome.invalid, cb.writeAttribute("ActSG", nine, 1, 0));
    try testing.expectEqual(WriteOutcome.denied, cb.writeAttribute("NumOfSG", nine, 1, 0));
    try testing.expectEqual(WriteOutcome.unknown, cb.writeAttribute("Nope", nine, 1, 0));
}

test "fuzz: an arbitrary SGCB write never panics" {
    try std.testing.fuzz({}, fuzzSgcb, .{});
}

fn fuzzSgcb(_: void, smith: *std.testing.Smith) !void {
    var fx: Fixture = .{};
    var cb = fx.init() catch return;
    var input: [64]u8 = undefined;
    smith.bytes(&input);
    const len: usize = smith.valueRangeAtMost(u8, 0, input.len);
    const d = mmsdata.Data.decode(input[0..len]) catch return;
    d.validate() catch return;
    const which: usize = smith.valueRangeAtMost(u8, 0, sgcb_attributes.len - 1);
    _ = cb.writeAttribute(sgcb_attributes[which], d, 1, 0);
    _ = cb.setEditValue(0, 1, input[0..len]) catch {};
    _ = cb.confirmEdit(1) catch {};
    _ = cb.activeValue(0) catch {};
    _ = cb.editValue(0) catch {};
}

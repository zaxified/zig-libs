// SPDX-License-Identifier: MIT

//! **Clause 13 — alarm and event services**, encoded and decoded on top of
//! `tag`: the event notification (confirmed and unconfirmed), `AcknowledgeAlarm`,
//! `GetEventInformation` and `GetAlarmSummary`, with the datatypes they share
//! (`BACnetTimeStamp`, `BACnetEventType`, `BACnetNotifyType`, the three-bit
//! transition strings).
//!
//! Same conventions as `service`: an event notification's `event values` are a
//! CHOICE keyed by the event type and are handed back as the raw tagged
//! octets of the opened `[12]` block (`OutOfRange` decodes the one this
//! module's device produces); nothing here allocates.

const std = @import("std");
const types = @import("types.zig");
const tag = @import("tag.zig");
const service = @import("service.zig");

pub const Error = service.Error;

const ObjectId = tag.ObjectId;
const EventState = types.EventState;

/// `BACnetEventType` (clause 21).
pub const EventType = enum(u32) {
    change_of_bitstring = 0,
    change_of_state = 1,
    change_of_value = 2,
    command_failure = 3,
    floating_limit = 4,
    out_of_range = 5,
    complex_event_type = 6,
    change_of_life_safety = 8,
    extended = 9,
    buffer_ready = 10,
    unsigned_range = 11,
    access_event = 13,
    double_out_of_range = 14,
    signed_out_of_range = 15,
    unsigned_out_of_range = 16,
    change_of_characterstring = 17,
    change_of_status_flags = 18,
    change_of_reliability = 19,
    none = 20,
    change_of_discrete_value = 21,
    change_of_timer = 22,
    _,
};

/// `BACnetNotifyType` (clause 21).
pub const NotifyType = enum(u32) {
    alarm = 0,
    event = 1,
    ack_notification = 2,
    _,
};

/// The three event transitions, which are also the bit numbers of
/// `BACnetEventTransitionBits` (`Event_Enable`, `Acked_Transitions`, a
/// recipient's `transitions`).
pub const Transition = enum(u2) {
    to_offnormal = 0,
    to_fault = 1,
    to_normal = 2,

    /// The transition into `state`: normal is `to_normal`, a fault is
    /// `to_fault`, every other state is `to_offnormal`.
    pub fn into(state: EventState) Transition {
        return switch (state) {
            .normal => .to_normal,
            .fault => .to_fault,
            else => .to_offnormal,
        };
    }
};

/// Three transition bits as one value, bit 0 (`to-offnormal`) first.
pub const TransitionBits = struct {
    bits: u3 = 0,

    pub const all: TransitionBits = .{ .bits = 0b111 };

    pub fn get(self: TransitionBits, t: Transition) bool {
        return (self.bits >> @backingInt(t)) & 1 != 0;
    }

    pub fn set(self: *TransitionBits, t: Transition, v: bool) void {
        const m: u3 = @as(u3, 1) << @backingInt(t);
        if (v) self.bits |= m else self.bits &= ~m;
    }

    /// The BitString octet: bit 0 is the most significant of the three.
    pub fn toOctet(self: TransitionBits) u8 {
        var o: u8 = 0;
        inline for (0..3) |i| {
            if ((self.bits >> i) & 1 != 0) o |= @as(u8, 0x80) >> i;
        }
        return o;
    }

    pub fn fromBitString(bs: tag.BitString) TransitionBits {
        var out: TransitionBits = .{};
        inline for (0..3) |i| {
            if (bs.bit(i)) out.bits |= @as(u3, 1) << i;
        }
        return out;
    }

    pub fn encodeApp(self: TransitionBits, w: *tag.Writer) Error!void {
        try w.appBitString(.{ .unused_bits = 5, .bytes = &.{self.toOctet()} });
    }

    pub fn encodeCtx(self: TransitionBits, w: *tag.Writer, n: u32) Error!void {
        try w.tagged(.context, n, &.{ 5, self.toOctet() });
    }

    pub fn decodeCtx(r: *tag.Reader, n: u32) Error!TransitionBits {
        const t = try r.next();
        if (!t.isContext(n)) return error.UnexpectedTag;
        if (t.len < 1) return error.InvalidLength;
        const d = try r.take(t.len);
        if (d[0] > 7 or (d.len == 1 and d[0] != 0)) return error.InvalidValue;
        return fromBitString(.{ .unused_bits = @intCast(d[0]), .bytes = d[1..] });
    }

    pub fn decodeApp(r: *tag.Reader) Error!TransitionBits {
        return fromBitString((try r.expectApp(.bit_string)).bit_string);
    }
};

/// `BACnetTimeStamp` (clause 21): a CHOICE of a time of day, a sequence
/// number or a date and time. A device with no wall clock stamps with a
/// sequence number.
pub const TimeStamp = union(enum) {
    time: tag.Time,
    sequence_number: u32,
    date_time: service.DateTime,

    /// "No time known": the wildcard time `FF FF FF FF`, which is what an
    /// object that has not yet had a transition reports.
    pub const unspecified: TimeStamp = .{ .time = .unspecified };

    /// The choice alone, as it sits inside a list of time stamps.
    pub fn encode(self: TimeStamp, w: *tag.Writer) Error!void {
        switch (self) {
            .time => |t| try w.ctxTime(0, t),
            .sequence_number => |n| try w.ctxUnsigned(1, n),
            .date_time => |dt| {
                try w.open(2);
                try dt.encode(w);
                try w.close(2);
            },
        }
    }

    pub fn decode(r: *tag.Reader) Error!TimeStamp {
        const t = try r.peek();
        if (t.isContext(0)) {
            _ = try r.next();
            if (t.len != 4) return error.InvalidLength;
            const d = try r.take(4);
            const out: tag.Time = .{ .hour = d[0], .minute = d[1], .second = d[2], .hundredths = d[3] };
            try out.validate();
            return .{ .time = out };
        }
        if (t.isContext(1)) return .{ .sequence_number = try narrow32(try r.ctxUnsigned(1)) };
        if (t.isOpening(2)) {
            _ = try r.next();
            const dt = try service.DateTime.decodeFrom(r);
            try r.expectClose(2);
            return .{ .date_time = dt };
        }
        return error.UnexpectedTag;
    }

    /// The choice wrapped in context tag `n`, which is how a time stamp
    /// appears as a named parameter.
    pub fn encodeCtx(self: TimeStamp, w: *tag.Writer, n: u32) Error!void {
        try w.open(n);
        try self.encode(w);
        try w.close(n);
    }

    pub fn decodeCtx(r: *tag.Reader, n: u32) Error!TimeStamp {
        try r.expectOpen(n);
        const ts = try decode(r);
        try r.expectClose(n);
        return ts;
    }

    pub fn eql(a: TimeStamp, b: TimeStamp) bool {
        return switch (a) {
            .time => |x| switch (b) {
                .time => |y| std.meta.eql(x, y),
                else => false,
            },
            .sequence_number => |x| switch (b) {
                .sequence_number => |y| x == y,
                else => false,
            },
            .date_time => |x| switch (b) {
                .date_time => |y| std.meta.eql(x.date, y.date) and std.meta.eql(x.time, y.time),
                else => false,
            },
        };
    }
};

fn narrow32(v: u64) Error!u32 {
    if (v > std.math.maxInt(u32)) return error.InvalidParameter;
    return @intCast(v);
}

fn narrow8(v: u64) Error!u8 {
    if (v > std.math.maxInt(u8)) return error.InvalidParameter;
    return @intCast(v);
}

/// The `[5]` block of an OUT_OF_RANGE notification's event values
/// (clause 13.3): the value that crossed, the object's status flags, the
/// deadband and the limit.
pub const OutOfRange = struct {
    exceeding_value: f32,
    /// The four `BACnetStatusFlags` bits, in `types.StatusFlags` order.
    status_flags: types.StatusFlags = .{},
    deadband: f32,
    exceeded_limit: f32,

    /// Writes the whole `[12] { [5] { ... } }` event-values parameter.
    pub fn encodeValues(self: OutOfRange, w: *tag.Writer) Error!void {
        try w.open(12);
        try w.open(5);
        try w.ctxReal(0, self.exceeding_value);
        try w.tagged(.context, 1, &.{ 4, self.status_flags.toOctet() });
        try w.ctxReal(2, self.deadband);
        try w.ctxReal(3, self.exceeded_limit);
        try w.close(5);
        try w.close(12);
    }

    /// Decodes the octets inside `[12]` (`EventNotification.values`).
    pub fn decodeValues(values: []const u8) Error!OutOfRange {
        var r = tag.Reader.init(values);
        try r.expectOpen(5);
        const exceeding = try ctxReal(&r, 0);
        const t = try r.next();
        if (!t.isContext(1) or t.len != 2) return error.UnexpectedTag;
        const sf = try r.take(2);
        const deadband = try ctxReal(&r, 2);
        const limit = try ctxReal(&r, 3);
        try r.expectClose(5);
        return .{
            .exceeding_value = exceeding,
            .status_flags = types.StatusFlags.fromOctet(sf[1]),
            .deadband = deadband,
            .exceeded_limit = limit,
        };
    }
};

fn ctxReal(r: *tag.Reader, n: u32) Error!f32 {
    const t = try r.next();
    if (!t.isContext(n)) return error.UnexpectedTag;
    if (t.len != 4) return error.InvalidLength;
    const d = try r.take(4);
    return @bitCast(std.mem.readInt(u32, d[0..4], .big));
}

/// `ConfirmedEventNotification` / `UnconfirmedEventNotification` (clause
/// 13.8, 13.9): same parameters, one is acknowledged and one is not.
pub const EventNotification = struct {
    process_id: u32,
    initiating_device: ObjectId,
    event_object: ObjectId,
    time_stamp: TimeStamp,
    notification_class: u32,
    priority: u8,
    event_type: EventType,
    message_text: ?[]const u8 = null,
    notify_type: NotifyType,
    /// Absent for `ack_notification`.
    ack_required: ?bool = null,
    /// Absent for `ack_notification`.
    from_state: ?EventState = null,
    to_state: EventState,
    /// The octets inside the `[12]` block, when the notification carries
    /// event values (`OutOfRange.decodeValues` reads the OUT_OF_RANGE one).
    values: ?[]const u8 = null,

    pub fn encode(self: EventNotification, w: *tag.Writer) Error!void {
        try w.ctxUnsigned(0, self.process_id);
        try w.ctxObjectId(1, self.initiating_device);
        try w.ctxObjectId(2, self.event_object);
        try self.time_stamp.encodeCtx(w, 3);
        try w.ctxUnsigned(4, self.notification_class);
        try w.ctxUnsigned(5, self.priority);
        try w.ctxEnumerated(6, @backingInt(self.event_type));
        if (self.message_text) |m| try w.ctxString(7, m);
        try w.ctxEnumerated(8, @backingInt(self.notify_type));
        if (self.ack_required) |a| try w.ctxBool(9, a);
        if (self.from_state) |f| try w.ctxEnumerated(10, @backingInt(f));
        try w.ctxEnumerated(11, @backingInt(self.to_state));
        if (self.values) |v| {
            try w.open(12);
            try w.raw(v);
            try w.close(12);
        }
    }

    pub fn decode(data: []const u8) Error!EventNotification {
        var r = tag.Reader.init(data);
        var out: EventNotification = undefined;
        out.process_id = try narrow32(try r.ctxUnsigned(0));
        out.initiating_device = try r.ctxObjectId(1);
        out.event_object = try r.ctxObjectId(2);
        out.time_stamp = try TimeStamp.decodeCtx(&r, 3);
        out.notification_class = try narrow32(try r.ctxUnsigned(4));
        out.priority = try narrow8(try r.ctxUnsigned(5));
        out.event_type = @fromBackingInt((try r.ctxEnumerated(6)));
        out.message_text = null;
        if ((try r.peek()).isContext(7)) {
            const s = try r.ctxString(7);
            out.message_text = s.asUtf8() orelse return error.InvalidValue;
        }
        out.notify_type = @fromBackingInt((try r.ctxEnumerated(8)));
        out.ack_required = null;
        if ((try r.peek()).isContext(9)) out.ack_required = try r.ctxBool(9);
        out.from_state = null;
        if ((try r.peek()).isContext(10)) out.from_state = @fromBackingInt((try r.ctxEnumerated(10)));
        out.to_state = @fromBackingInt((try r.ctxEnumerated(11)));
        out.values = null;
        if (!r.atEnd()) out.values = try r.openedBlock(12);
        if (!r.atEnd()) return error.InvalidParameter;
        return out;
    }
};

/// `AcknowledgeAlarm` request (clause 13.5).
pub const AcknowledgeAlarm = struct {
    process_id: u32,
    event_object: ObjectId,
    /// The state being acknowledged (it selects the transition).
    state: EventState,
    /// The time stamp of the transition, as the notification carried it.
    time_stamp: TimeStamp,
    source: []const u8,
    /// When the operator acknowledged.
    time_of_ack: TimeStamp,

    pub fn encode(self: AcknowledgeAlarm, w: *tag.Writer) Error!void {
        try w.ctxUnsigned(0, self.process_id);
        try w.ctxObjectId(1, self.event_object);
        try w.ctxEnumerated(2, @backingInt(self.state));
        try self.time_stamp.encodeCtx(w, 3);
        try w.ctxString(4, self.source);
        try self.time_of_ack.encodeCtx(w, 5);
    }

    pub fn decode(data: []const u8) Error!AcknowledgeAlarm {
        var r = tag.Reader.init(data);
        const process_id = try narrow32(try r.ctxUnsigned(0));
        const object = try r.ctxObjectId(1);
        const state: EventState = @fromBackingInt((try r.ctxEnumerated(2)));
        const ts = try TimeStamp.decodeCtx(&r, 3);
        const src = try r.ctxString(4);
        const ack_ts = try TimeStamp.decodeCtx(&r, 5);
        if (!r.atEnd()) return error.InvalidParameter;
        return .{
            .process_id = process_id,
            .event_object = object,
            .state = state,
            .time_stamp = ts,
            .source = src.asUtf8() orelse return error.InvalidValue,
            .time_of_ack = ack_ts,
        };
    }
};

/// `GetEventInformation` request (clause 13.12): the object after which the
/// list continues, for a second page.
pub const GetEventInformation = struct {
    last_received: ?ObjectId = null,

    pub fn encode(self: GetEventInformation, w: *tag.Writer) Error!void {
        if (self.last_received) |o| try w.ctxObjectId(0, o);
    }

    pub fn decode(data: []const u8) Error!GetEventInformation {
        var r = tag.Reader.init(data);
        if (r.atEnd()) return .{};
        const o = try r.ctxObjectId(0);
        if (!r.atEnd()) return error.InvalidParameter;
        return .{ .last_received = o };
    }
};

/// One `BACnetEventSummary` of a `GetEventInformation-ACK`.
pub const EventSummary = struct {
    object: ObjectId,
    state: EventState,
    acked_transitions: TransitionBits,
    /// One time stamp per transition, `to-offnormal` first.
    time_stamps: [3]TimeStamp,
    notify_type: NotifyType,
    event_enable: TransitionBits,
    /// One priority per transition.
    priorities: [3]u8,

    pub fn encode(self: EventSummary, w: *tag.Writer) Error!void {
        try w.ctxObjectId(0, self.object);
        try w.ctxEnumerated(1, @backingInt(self.state));
        try self.acked_transitions.encodeCtx(w, 2);
        try w.open(3);
        for (self.time_stamps) |ts| try ts.encode(w);
        try w.close(3);
        try w.ctxEnumerated(4, @backingInt(self.notify_type));
        try self.event_enable.encodeCtx(w, 5);
        try w.open(6);
        for (self.priorities) |p| try w.appUnsigned(p);
        try w.close(6);
    }

    pub fn decode(r: *tag.Reader) Error!EventSummary {
        var out: EventSummary = undefined;
        out.object = try r.ctxObjectId(0);
        out.state = @fromBackingInt((try r.ctxEnumerated(1)));
        out.acked_transitions = try TransitionBits.decodeCtx(r, 2);
        try r.expectOpen(3);
        for (&out.time_stamps) |*ts| ts.* = try TimeStamp.decode(r);
        try r.expectClose(3);
        out.notify_type = @fromBackingInt((try r.ctxEnumerated(4)));
        out.event_enable = try TransitionBits.decodeCtx(r, 5);
        try r.expectOpen(6);
        for (&out.priorities) |*p| p.* = try narrow8((try r.expectApp(.unsigned)).unsigned);
        try r.expectClose(6);
        return out;
    }
};

/// `GetEventInformation-ACK` (clause 13.12): the summaries and whether more
/// remain. Build with `Builder`, walk with `summaries`.
pub const GetEventInformationAck = struct {
    /// The octets inside `[0]`.
    list: []const u8,
    more_events: bool,

    pub fn decode(data: []const u8) Error!GetEventInformationAck {
        var r = tag.Reader.init(data);
        const list = try r.openedBlock(0);
        const more = try r.ctxBool(1);
        if (!r.atEnd()) return error.InvalidParameter;
        return .{ .list = list, .more_events = more };
    }

    pub fn summaries(self: GetEventInformationAck) SummaryIterator {
        return .{ .r = tag.Reader.init(self.list) };
    }

    pub const SummaryIterator = struct {
        r: tag.Reader,

        pub fn next(self: *SummaryIterator) Error!?EventSummary {
            if (self.r.atEnd()) return null;
            return try EventSummary.decode(&self.r);
        }
    };

    /// Writes the ACK around summaries already encoded one after another.
    pub fn encode(list: []const u8, more_events: bool, w: *tag.Writer) Error!void {
        try w.open(0);
        try w.raw(list);
        try w.close(0);
        try w.ctxBool(1, more_events);
    }
};

/// One entry of a `GetAlarmSummary-ACK` (clause 13.7): all three fields are
/// application-tagged.
pub const AlarmSummary = struct {
    object: ObjectId,
    state: EventState,
    acked_transitions: TransitionBits,

    pub fn encode(self: AlarmSummary, w: *tag.Writer) Error!void {
        try w.appObjectId(self.object);
        try w.appEnumerated(@backingInt(self.state));
        try self.acked_transitions.encodeApp(w);
    }

    pub fn decode(r: *tag.Reader) Error!AlarmSummary {
        const o = (try r.expectApp(.object_identifier)).object_identifier;
        const s = (try r.expectApp(.enumerated)).enumerated;
        return .{
            .object = o,
            .state = @fromBackingInt(s),
            .acked_transitions = try TransitionBits.decodeApp(r),
        };
    }
};

/// Walks the data of a `GetAlarmSummary-ACK`.
pub const AlarmSummaryIterator = struct {
    r: tag.Reader,

    pub fn init(data: []const u8) AlarmSummaryIterator {
        return .{ .r = tag.Reader.init(data) };
    }

    pub fn next(self: *AlarmSummaryIterator) Error!?AlarmSummary {
        if (self.r.atEnd()) return null;
        return try AlarmSummary.decode(&self.r);
    }
};

// ── event values of the other algorithms (clause 13.2, 21) ──────────────────

fn ctxBitString(w: *tag.Writer, n: u32, bs: tag.BitString) Error!void {
    if (bs.bytes.len == 0 and bs.unused_bits != 0) return error.InvalidValue;
    try w.header(.{ .class = .context, .number = n, .form = .primitive, .len = @intCast(bs.bytes.len + 1) });
    try w.byte(bs.unused_bits);
    try w.raw(bs.bytes);
}

fn readCtxBitString(r: *tag.Reader, n: u32) Error!tag.BitString {
    const t = try r.next();
    if (!t.isContext(n)) return error.UnexpectedTag;
    if (t.len < 1) return error.InvalidLength;
    const d = try r.take(t.len);
    if (d[0] > 7 or (d.len == 1 and d[0] != 0)) return error.InvalidValue;
    return .{ .unused_bits = @intCast(d[0]), .bytes = d[1..] };
}

fn putStatusFlags(w: *tag.Writer, n: u32, sf: types.StatusFlags) Error!void {
    try w.tagged(.context, n, &.{ 4, sf.toOctet() });
}

fn getStatusFlags(r: *tag.Reader, n: u32) Error!types.StatusFlags {
    const t = try r.next();
    if (!t.isContext(n) or t.len != 2) return error.UnexpectedTag;
    const sf = try r.take(2);
    return types.StatusFlags.fromOctet(sf[1]);
}

/// One `BACnetPropertyStates` value (clause 21): a CHOICE whose alternatives
/// are all a Boolean, an Enumerated or an Unsigned, so a choice number and
/// the value is the whole of it. A context-tagged Boolean and a one-octet
/// Unsigned are the same octets, which is why one `value` serves both.
pub const PropertyState = struct {
    /// The CHOICE number (`boolean_value` ... `life_safety_state`, below).
    choice: u32,
    value: u32,

    pub const boolean_value: u32 = 0;
    pub const binary_value: u32 = 1;
    pub const event_type: u32 = 2;
    pub const polarity: u32 = 3;
    pub const reliability: u32 = 7;
    pub const state: u32 = 8;
    pub const unsigned_value: u32 = 11;
    pub const life_safety_mode: u32 = 12;
    pub const life_safety_state: u32 = 13;

    /// The alternative alone, as it sits inside a list of states.
    pub fn encode(self: PropertyState, w: *tag.Writer) Error!void {
        try w.ctxUnsigned(self.choice, self.value);
    }

    pub fn decode(r: *tag.Reader) Error!PropertyState {
        const t = try r.next();
        if (t.class != .context or t.form != .primitive) return error.UnexpectedTag;
        if (t.len == 0 or t.len > 4) return error.InvalidLength;
        const v = try tag.unpackUnsigned(try r.take(t.len));
        return .{ .choice = t.number, .value = @intCast(v) };
    }

    /// The alternative wrapped in context tag `n` (a named parameter).
    pub fn encodeCtx(self: PropertyState, w: *tag.Writer, n: u32) Error!void {
        try w.open(n);
        try self.encode(w);
        try w.close(n);
    }

    pub fn decodeCtx(r: *tag.Reader, n: u32) Error!PropertyState {
        try r.expectOpen(n);
        const s = try decode(r);
        try r.expectClose(n);
        return s;
    }
};

/// Writes `[12] { [choice] { body } }` around `body`.
fn writeValues(w: *tag.Writer, choice: u32, ctx: anytype, comptime body: fn (@TypeOf(ctx), *tag.Writer) Error!void) Error!void {
    try w.open(12);
    try w.open(choice);
    try body(ctx, w);
    try w.close(choice);
    try w.close(12);
}

/// `CHANGE_OF_BITSTRING` event values (clause 13.3, `[0]`).
pub const ChangeOfBitstring = struct {
    referenced_bitstring: tag.BitString,
    status_flags: types.StatusFlags = .{},

    pub fn encodeValues(self: ChangeOfBitstring, w: *tag.Writer) Error!void {
        try writeValues(w, 0, self, body);
    }
    fn body(self: ChangeOfBitstring, w: *tag.Writer) Error!void {
        try ctxBitString(w, 0, self.referenced_bitstring);
        try putStatusFlags(w, 1, self.status_flags);
    }
    pub fn decodeValues(values: []const u8) Error!ChangeOfBitstring {
        var r = tag.Reader.init(values);
        try r.expectOpen(0);
        const bs = try readCtxBitString(&r, 0);
        const sf = try getStatusFlags(&r, 1);
        try r.expectClose(0);
        return .{ .referenced_bitstring = bs, .status_flags = sf };
    }
};

/// `CHANGE_OF_STATE` event values (clause 13.3, `[1]`).
pub const ChangeOfState = struct {
    new_state: PropertyState,
    status_flags: types.StatusFlags = .{},

    pub fn encodeValues(self: ChangeOfState, w: *tag.Writer) Error!void {
        try writeValues(w, 1, self, body);
    }
    fn body(self: ChangeOfState, w: *tag.Writer) Error!void {
        try self.new_state.encodeCtx(w, 0);
        try putStatusFlags(w, 1, self.status_flags);
    }
    pub fn decodeValues(values: []const u8) Error!ChangeOfState {
        var r = tag.Reader.init(values);
        try r.expectOpen(1);
        const st = try PropertyState.decodeCtx(&r, 0);
        const sf = try getStatusFlags(&r, 1);
        try r.expectClose(1);
        return .{ .new_state = st, .status_flags = sf };
    }
};

/// `CHANGE_OF_VALUE` event values (clause 13.3, `[2]`): the changed bits of
/// a bit string, or the new value of a Real.
pub const ChangeOfValue = struct {
    new_value: union(enum) { changed_bits: tag.BitString, changed_value: f32 },
    status_flags: types.StatusFlags = .{},

    pub fn encodeValues(self: ChangeOfValue, w: *tag.Writer) Error!void {
        try writeValues(w, 2, self, body);
    }
    fn body(self: ChangeOfValue, w: *tag.Writer) Error!void {
        try w.open(0);
        switch (self.new_value) {
            .changed_bits => |b| try ctxBitString(w, 0, b),
            .changed_value => |v| try w.ctxReal(1, v),
        }
        try w.close(0);
        try putStatusFlags(w, 1, self.status_flags);
    }
    pub fn decodeValues(values: []const u8) Error!ChangeOfValue {
        var r = tag.Reader.init(values);
        try r.expectOpen(2);
        try r.expectOpen(0);
        const t = try r.peek();
        const nv: @FieldType(ChangeOfValue, "new_value") = if (t.isContext(0))
            .{ .changed_bits = try readCtxBitString(&r, 0) }
        else
            .{ .changed_value = try ctxReal(&r, 1) };
        try r.expectClose(0);
        const sf = try getStatusFlags(&r, 1);
        try r.expectClose(2);
        return .{ .new_value = nv, .status_flags = sf };
    }
};

/// `COMMAND_FAILURE` event values (clause 13.3, `[3]`). The command and
/// feedback values are any application-tagged datum; they are handed back as
/// the octets inside their brackets.
pub const CommandFailure = struct {
    command_value: []const u8,
    status_flags: types.StatusFlags = .{},
    feedback_value: []const u8,

    pub fn encodeValues(self: CommandFailure, w: *tag.Writer) Error!void {
        try writeValues(w, 3, self, body);
    }
    fn body(self: CommandFailure, w: *tag.Writer) Error!void {
        try w.open(0);
        try w.raw(self.command_value);
        try w.close(0);
        try putStatusFlags(w, 1, self.status_flags);
        try w.open(2);
        try w.raw(self.feedback_value);
        try w.close(2);
    }
    pub fn decodeValues(values: []const u8) Error!CommandFailure {
        var r = tag.Reader.init(values);
        try r.expectOpen(3);
        const cv = try r.openedBlock(0);
        const sf = try getStatusFlags(&r, 1);
        const fv = try r.openedBlock(2);
        try r.expectClose(3);
        return .{ .command_value = cv, .status_flags = sf, .feedback_value = fv };
    }
};

/// `FLOATING_LIMIT` event values (clause 13.3, `[4]`).
pub const FloatingLimit = struct {
    reference_value: f32,
    status_flags: types.StatusFlags = .{},
    setpoint_value: f32,
    /// The difference to the setpoint that was exceeded.
    error_limit: f32,

    pub fn encodeValues(self: FloatingLimit, w: *tag.Writer) Error!void {
        try writeValues(w, 4, self, body);
    }
    fn body(self: FloatingLimit, w: *tag.Writer) Error!void {
        try w.ctxReal(0, self.reference_value);
        try putStatusFlags(w, 1, self.status_flags);
        try w.ctxReal(2, self.setpoint_value);
        try w.ctxReal(3, self.error_limit);
    }
    pub fn decodeValues(values: []const u8) Error!FloatingLimit {
        var r = tag.Reader.init(values);
        try r.expectOpen(4);
        const rv = try ctxReal(&r, 0);
        const sf = try getStatusFlags(&r, 1);
        const sp = try ctxReal(&r, 2);
        const el = try ctxReal(&r, 3);
        try r.expectClose(4);
        return .{ .reference_value = rv, .status_flags = sf, .setpoint_value = sp, .error_limit = el };
    }
};

/// `UNSIGNED_RANGE` event values (clause 13.3, `[11]`).
pub const UnsignedRange = struct {
    exceeding_value: u64,
    status_flags: types.StatusFlags = .{},
    exceeded_limit: u64,

    pub fn encodeValues(self: UnsignedRange, w: *tag.Writer) Error!void {
        try writeValues(w, 11, self, body);
    }
    fn body(self: UnsignedRange, w: *tag.Writer) Error!void {
        try w.ctxUnsigned(0, self.exceeding_value);
        try putStatusFlags(w, 1, self.status_flags);
        try w.ctxUnsigned(2, self.exceeded_limit);
    }
    pub fn decodeValues(values: []const u8) Error!UnsignedRange {
        var r = tag.Reader.init(values);
        try r.expectOpen(11);
        const ev = try r.ctxUnsigned(0);
        const sf = try getStatusFlags(&r, 1);
        const el = try r.ctxUnsigned(2);
        try r.expectClose(11);
        return .{ .exceeding_value = ev, .status_flags = sf, .exceeded_limit = el };
    }
};

/// `CHANGE_OF_RELIABILITY` event values (clause 13.3, `[19]`): what a
/// to-fault transition carries.
pub const ChangeOfReliability = struct {
    reliability: types.Reliability,
    status_flags: types.StatusFlags = .{},
    /// The octets inside `[2]`: a list of `BACnetPropertyValue`, usually empty.
    property_values: []const u8 = &.{},

    pub fn encodeValues(self: ChangeOfReliability, w: *tag.Writer) Error!void {
        try writeValues(w, 19, self, body);
    }
    fn body(self: ChangeOfReliability, w: *tag.Writer) Error!void {
        try w.ctxEnumerated(0, @backingInt(self.reliability));
        try putStatusFlags(w, 1, self.status_flags);
        try w.open(2);
        try w.raw(self.property_values);
        try w.close(2);
    }
    pub fn decodeValues(values: []const u8) Error!ChangeOfReliability {
        var r = tag.Reader.init(values);
        try r.expectOpen(19);
        const rel: types.Reliability = @fromBackingInt(try r.ctxEnumerated(0));
        const sf = try getStatusFlags(&r, 1);
        const pv = try r.openedBlock(2);
        try r.expectClose(19);
        return .{ .reliability = rel, .status_flags = sf, .property_values = pv };
    }
};

/// `CHANGE_OF_LIFE_SAFETY` event values (clause 13.3, `[8]`). The three
/// enumerations (`BACnetLifeSafetyState`, `BACnetLifeSafetyMode`,
/// `BACnetLifeSafetyOperation`) are carried as numbers.
pub const ChangeOfLifeSafety = struct {
    new_state: u32,
    new_mode: u32,
    status_flags: types.StatusFlags = .{},
    operation_expected: u32,

    pub fn encodeValues(self: ChangeOfLifeSafety, w: *tag.Writer) Error!void {
        try writeValues(w, 8, self, body);
    }
    fn body(self: ChangeOfLifeSafety, w: *tag.Writer) Error!void {
        try w.ctxEnumerated(0, self.new_state);
        try w.ctxEnumerated(1, self.new_mode);
        try putStatusFlags(w, 2, self.status_flags);
        try w.ctxEnumerated(3, self.operation_expected);
    }
    pub fn decodeValues(values: []const u8) Error!ChangeOfLifeSafety {
        var r = tag.Reader.init(values);
        try r.expectOpen(8);
        const ns = try r.ctxEnumerated(0);
        const nm = try r.ctxEnumerated(1);
        const sf = try getStatusFlags(&r, 2);
        const oe = try r.ctxEnumerated(3);
        try r.expectClose(8);
        return .{ .new_state = ns, .new_mode = nm, .status_flags = sf, .operation_expected = oe };
    }
};

/// The event values of a notification, by event type, for the algorithms
/// this module knows. `decode` returns null for an event type it has no
/// codec for (the raw `EventNotification.values` stay available).
pub const EventValues = union(enum) {
    change_of_bitstring: ChangeOfBitstring,
    change_of_state: ChangeOfState,
    change_of_value: ChangeOfValue,
    command_failure: CommandFailure,
    floating_limit: FloatingLimit,
    out_of_range: OutOfRange,
    change_of_life_safety: ChangeOfLifeSafety,
    unsigned_range: UnsignedRange,
    change_of_reliability: ChangeOfReliability,

    pub fn decode(event_type: EventType, values: []const u8) Error!?EventValues {
        return switch (event_type) {
            .change_of_bitstring => .{ .change_of_bitstring = try ChangeOfBitstring.decodeValues(values) },
            .change_of_state => .{ .change_of_state = try ChangeOfState.decodeValues(values) },
            .change_of_value => .{ .change_of_value = try ChangeOfValue.decodeValues(values) },
            .command_failure => .{ .command_failure = try CommandFailure.decodeValues(values) },
            .floating_limit => .{ .floating_limit = try FloatingLimit.decodeValues(values) },
            .out_of_range => .{ .out_of_range = try OutOfRange.decodeValues(values) },
            .change_of_life_safety => .{ .change_of_life_safety = try ChangeOfLifeSafety.decodeValues(values) },
            .unsigned_range => .{ .unsigned_range = try UnsignedRange.decodeValues(values) },
            .change_of_reliability => .{ .change_of_reliability = try ChangeOfReliability.decodeValues(values) },
            else => null,
        };
    }
};

// ── Event_Parameters of an Event Enrollment object (clause 12.12.11) ────────

/// `BACnetObjectPropertyReference` / `BACnetDeviceObjectPropertyReference`
/// (clause 21): an object, one of its properties, an optional array index
/// and, for the device form, the device that holds the object.
pub const PropertyReference = struct {
    object: ObjectId,
    property: types.PropertyIdentifier,
    array_index: ?u32 = null,
    /// Absent: the object is in the device that holds the reference.
    device: ?ObjectId = null,

    pub fn encode(self: PropertyReference, w: *tag.Writer) Error!void {
        try w.ctxObjectId(0, self.object);
        try w.ctxEnumerated(1, @backingInt(self.property));
        if (self.array_index) |i| try w.ctxUnsigned(2, i);
        if (self.device) |d| try w.ctxObjectId(3, d);
    }

    pub fn decode(r: *tag.Reader) Error!PropertyReference {
        var out: PropertyReference = undefined;
        out.object = try r.ctxObjectId(0);
        out.property = @fromBackingInt(try r.ctxEnumerated(1));
        out.array_index = null;
        out.device = null;
        if (!r.atEnd() and (try r.peek()).isContext(2)) out.array_index = try narrow32(try r.ctxUnsigned(2));
        if (!r.atEnd() and (try r.peek()).isContext(3)) out.device = try r.ctxObjectId(3);
        return out;
    }

    pub fn encodeCtx(self: PropertyReference, w: *tag.Writer, n: u32) Error!void {
        try w.open(n);
        try self.encode(w);
        try w.close(n);
    }

    pub fn decodeCtx(r: *tag.Reader, n: u32) Error!PropertyReference {
        const inner = try r.openedBlock(n);
        var ir = tag.Reader.init(inner);
        const out = try decode(&ir);
        if (!ir.atEnd()) return error.InvalidParameter;
        return out;
    }
};

/// `BACnetEventParameter` (clause 12.12.11, 21): what the Event Enrollment
/// object's `Event_Parameters` property holds, by algorithm. Lists are
/// handed back as the octets they occupy; `statesIterator` and
/// `bitstringsIterator` walk them.
pub const EventParameters = union(enum) {
    change_of_bitstring: struct { time_delay: u32, bitmask: tag.BitString, values: []const u8 },
    change_of_state: struct { time_delay: u32, values: []const u8 },
    change_of_value: struct { time_delay: u32, criteria: union(enum) { bitmask: tag.BitString, increment: f32 } },
    command_failure: struct { time_delay: u32, feedback: PropertyReference },
    floating_limit: struct { time_delay: u32, setpoint: PropertyReference, low_diff_limit: f32, high_diff_limit: f32, deadband: f32 },
    out_of_range: struct { time_delay: u32, low_limit: f32, high_limit: f32, deadband: f32 },
    unsigned_range: struct { time_delay: u32, low_limit: u64, high_limit: u64 },
    /// `NONE`: the object detects nothing (`[20]` Null).
    none,

    pub fn eventType(self: EventParameters) EventType {
        return switch (self) {
            .change_of_bitstring => .change_of_bitstring,
            .change_of_state => .change_of_state,
            .change_of_value => .change_of_value,
            .command_failure => .command_failure,
            .floating_limit => .floating_limit,
            .out_of_range => .out_of_range,
            .unsigned_range => .unsigned_range,
            .none => .none,
        };
    }

    pub fn encode(self: EventParameters, w: *tag.Writer) Error!void {
        switch (self) {
            .change_of_bitstring => |p| {
                try w.open(0);
                try w.ctxUnsigned(0, p.time_delay);
                try ctxBitString(w, 1, p.bitmask);
                try w.open(2);
                try w.raw(p.values);
                try w.close(2);
                try w.close(0);
            },
            .change_of_state => |p| {
                try w.open(1);
                try w.ctxUnsigned(0, p.time_delay);
                try w.open(1);
                try w.raw(p.values);
                try w.close(1);
                try w.close(1);
            },
            .change_of_value => |p| {
                try w.open(2);
                try w.ctxUnsigned(0, p.time_delay);
                try w.open(1);
                switch (p.criteria) {
                    .bitmask => |b| try ctxBitString(w, 0, b),
                    .increment => |v| try w.ctxReal(1, v),
                }
                try w.close(1);
                try w.close(2);
            },
            .command_failure => |p| {
                try w.open(3);
                try w.ctxUnsigned(0, p.time_delay);
                try p.feedback.encodeCtx(w, 1);
                try w.close(3);
            },
            .floating_limit => |p| {
                try w.open(4);
                try w.ctxUnsigned(0, p.time_delay);
                try p.setpoint.encodeCtx(w, 1);
                try w.ctxReal(2, p.low_diff_limit);
                try w.ctxReal(3, p.high_diff_limit);
                try w.ctxReal(4, p.deadband);
                try w.close(4);
            },
            .out_of_range => |p| {
                try w.open(5);
                try w.ctxUnsigned(0, p.time_delay);
                try w.ctxReal(1, p.low_limit);
                try w.ctxReal(2, p.high_limit);
                try w.ctxReal(3, p.deadband);
                try w.close(5);
            },
            .unsigned_range => |p| {
                try w.open(11);
                try w.ctxUnsigned(0, p.time_delay);
                try w.ctxUnsigned(1, p.low_limit);
                try w.ctxUnsigned(2, p.high_limit);
                try w.close(11);
            },
            .none => try w.ctxNull(20),
        }
    }

    /// Decodes the whole property value (exactly one choice).
    pub fn decode(data: []const u8) Error!EventParameters {
        var r = tag.Reader.init(data);
        const out = try decodeFrom(&r);
        if (!r.atEnd()) return error.InvalidParameter;
        return out;
    }

    fn decodeFrom(r: *tag.Reader) Error!EventParameters {
        const t = try r.peek();
        if (t.class != .context) return error.UnexpectedTag;
        if (t.isContext(20)) {
            _ = try r.next();
            if (t.len != 0) return error.InvalidLength;
            return .none;
        }
        const body = try r.openedBlock(t.number);
        var b = tag.Reader.init(body);
        const delay = try narrow32(try b.ctxUnsigned(0));
        const out: EventParameters = switch (t.number) {
            0 => blk: {
                const mask = try readCtxBitString(&b, 1);
                break :blk .{ .change_of_bitstring = .{ .time_delay = delay, .bitmask = mask, .values = try b.openedBlock(2) } };
            },
            1 => .{ .change_of_state = .{ .time_delay = delay, .values = try b.openedBlock(1) } },
            2 => blk: {
                const crit = try b.openedBlock(1);
                var cr = tag.Reader.init(crit);
                const c: @FieldType(@FieldType(EventParameters, "change_of_value"), "criteria") = if ((try cr.peek()).isContext(0))
                    .{ .bitmask = try readCtxBitString(&cr, 0) }
                else
                    .{ .increment = try ctxReal(&cr, 1) };
                if (!cr.atEnd()) return error.InvalidParameter;
                break :blk .{ .change_of_value = .{ .time_delay = delay, .criteria = c } };
            },
            3 => .{ .command_failure = .{ .time_delay = delay, .feedback = try PropertyReference.decodeCtx(&b, 1) } },
            4 => blk: {
                const sp = try PropertyReference.decodeCtx(&b, 1);
                const lo = try ctxReal(&b, 2);
                const hi = try ctxReal(&b, 3);
                const db = try ctxReal(&b, 4);
                break :blk .{ .floating_limit = .{ .time_delay = delay, .setpoint = sp, .low_diff_limit = lo, .high_diff_limit = hi, .deadband = db } };
            },
            5 => blk: {
                const lo = try ctxReal(&b, 1);
                const hi = try ctxReal(&b, 2);
                const db = try ctxReal(&b, 3);
                break :blk .{ .out_of_range = .{ .time_delay = delay, .low_limit = lo, .high_limit = hi, .deadband = db } };
            },
            11 => blk: {
                const lo = try b.ctxUnsigned(1);
                const hi = try b.ctxUnsigned(2);
                break :blk .{ .unsigned_range = .{ .time_delay = delay, .low_limit = lo, .high_limit = hi } };
            },
            else => return error.UnexpectedTag,
        };
        if (!b.atEnd()) return error.InvalidParameter;
        return out;
    }

    /// Walks a `change_of_state` list of `BACnetPropertyStates`.
    pub fn statesIterator(values: []const u8) StatesIterator {
        return .{ .r = tag.Reader.init(values) };
    }

    pub const StatesIterator = struct {
        r: tag.Reader,
        pub fn next(self: *StatesIterator) Error!?PropertyState {
            if (self.r.atEnd()) return null;
            return try PropertyState.decode(&self.r);
        }
    };

    /// Walks a `change_of_bitstring` list of bit strings.
    pub fn bitstringsIterator(values: []const u8) BitstringsIterator {
        return .{ .r = tag.Reader.init(values) };
    }

    pub const BitstringsIterator = struct {
        r: tag.Reader,
        pub fn next(self: *BitstringsIterator) Error!?tag.BitString {
            if (self.r.atEnd()) return null;
            return (try self.r.expectApp(.bit_string)).bit_string;
        }
    };
};

/// `BACnetLifeSafetyOperation` (clause 21): what a `LifeSafetyOperation`
/// request asks for.
pub const LifeSafetyOperation = enum(u32) {
    none = 0,
    silence = 1,
    silence_audible = 2,
    silence_visual = 3,
    reset = 4,
    reset_alarm = 5,
    reset_fault = 6,
    unsilence = 7,
    unsilence_audible = 8,
    unsilence_visual = 9,
    _,
};

/// `LifeSafetyOperation` request (clause 13.13).
pub const LifeSafetyOperationRequest = struct {
    process_id: u32,
    source: []const u8,
    request: LifeSafetyOperation,
    /// Absent: the request is for every life safety object of the device.
    object: ?ObjectId = null,

    pub fn encode(self: LifeSafetyOperationRequest, w: *tag.Writer) Error!void {
        try w.ctxUnsigned(0, self.process_id);
        try w.ctxString(1, self.source);
        try w.ctxEnumerated(2, @backingInt(self.request));
        if (self.object) |o| try w.ctxObjectId(3, o);
    }

    pub fn decode(data: []const u8) Error!LifeSafetyOperationRequest {
        var r = tag.Reader.init(data);
        const pid = try narrow32(try r.ctxUnsigned(0));
        const src = try r.ctxString(1);
        const op: LifeSafetyOperation = @fromBackingInt(try r.ctxEnumerated(2));
        var obj: ?ObjectId = null;
        if (!r.atEnd()) obj = try r.ctxObjectId(3);
        if (!r.atEnd()) return error.InvalidParameter;
        return .{
            .process_id = pid,
            .source = src.asUtf8() orelse return error.InvalidValue,
            .request = op,
            .object = obj,
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const testkit = @import("testkit");
const hex = testkit.hex.literal;

// The hex strings below were emitted by bacpypes3 0.0.106 (black box; recipe
// in `tools/event_goldens.py`), service body only.

const ai5: ObjectId = .{ .type = .analog_input, .instance = 5 };

fn encodeOf(v: anytype, buf: []u8) ![]const u8 {
    var w = tag.Writer.init(buf);
    try v.encode(&w);
    return w.written();
}

test "event notification: golden bytes both ways, OUT_OF_RANGE values" {
    var vbuf: [64]u8 = undefined;
    var vw = tag.Writer.init(&vbuf);
    const oor: OutOfRange = .{ .exceeding_value = 91.5, .status_flags = .{ .in_alarm = true }, .deadband = 2.0, .exceeded_limit = 90.0 };
    try oor.encodeValues(&vw);
    const wire = hex("09071c020002572c000000053e19053f4903596469057c00686f7489009901a900b903ce5e0c42b700001a04802c400000003c42b400005fcf");
    // `values` is what sits inside [12].
    const inner = vw.written()[1 .. vw.written().len - 1];
    const n: EventNotification = .{
        .process_id = 7,
        .initiating_device = .{ .type = .device, .instance = 599 },
        .event_object = ai5,
        .time_stamp = .{ .sequence_number = 5 },
        .notification_class = 3,
        .priority = 100,
        .event_type = .out_of_range,
        .message_text = "hot",
        .notify_type = .alarm,
        .ack_required = true,
        .from_state = .normal,
        .to_state = .high_limit,
        .values = inner,
    };
    var buf: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encodeOf(n, &buf));

    const back = try EventNotification.decode(&wire);
    try testing.expectEqual(@as(u32, 7), back.process_id);
    try testing.expect(back.time_stamp.eql(.{ .sequence_number = 5 }));
    try testing.expectEqual(EventType.out_of_range, back.event_type);
    try testing.expectEqualStrings("hot", back.message_text.?);
    try testing.expectEqual(EventState.high_limit, back.to_state);
    try testing.expectEqual(@as(?EventState, .normal), back.from_state);
    const v = try OutOfRange.decodeValues(back.values.?);
    try testing.expectEqual(@as(f32, 91.5), v.exceeding_value);
    try testing.expect(v.status_flags.in_alarm and !v.status_flags.fault);
    try testing.expectEqual(@as(f32, 90.0), v.exceeded_limit);

    // The optional parameters really are optional (an ack notification has
    // neither ack-required nor a from state), and trailing octets are refused.
    var m = n;
    m.ack_required = null;
    m.from_state = null;
    m.values = null;
    m.message_text = null;
    m.notify_type = .ack_notification;
    const mb = try encodeOf(m, &buf);
    const mback = try EventNotification.decode(mb);
    try testing.expectEqual(@as(?bool, null), mback.ack_required);
    try testing.expectEqual(@as(?[]const u8, null), mback.values);
    try testing.expectEqual(NotifyType.ack_notification, mback.notify_type);
    var longer: [130]u8 = undefined;
    @memcpy(longer[0..mb.len], mb);
    longer[mb.len] = 0x09;
    longer[mb.len + 1] = 0x01;
    try testing.expectError(error.UnexpectedTag, EventNotification.decode(longer[0 .. mb.len + 2]));
    // A truncated one is a typed error, never a panic.
    for (0..wire.len) |cut| {
        _ = EventNotification.decode(wire[0..cut]) catch continue;
    }
}

test "time stamps: the three choices round-trip" {
    var buf: [32]u8 = undefined;
    const cases = [_]TimeStamp{
        .{ .time = .{ .hour = 13, .minute = 5, .second = 0, .hundredths = 0 } },
        .{ .sequence_number = 70000 },
        .{ .date_time = .{ .date = .{ .year = 126, .month = 11, .day = 21, .weekday = 6 }, .time = .{ .hour = 1, .minute = 2, .second = 3, .hundredths = 4 } } },
        TimeStamp.unspecified,
    };
    for (cases) |c| {
        var w = tag.Writer.init(&buf);
        try c.encodeCtx(&w, 3);
        var r = tag.Reader.init(w.written());
        try testing.expect(c.eql(try TimeStamp.decodeCtx(&r, 3)));
        try testing.expect(r.atEnd());
    }
    // A time with an impossible hour is refused on decode.
    var r = tag.Reader.init(&hex("0c18000000"));
    try testing.expectError(error.InvalidValue, TimeStamp.decode(&r));
}

test "AcknowledgeAlarm and GetEventInformation: golden bytes both ways" {
    var buf: [128]u8 = undefined;
    const ack: AcknowledgeAlarm = .{
        .process_id = 7,
        .event_object = ai5,
        .state = .high_limit,
        .time_stamp = .{ .sequence_number = 5 },
        .source = "op",
        .time_of_ack = .{ .sequence_number = 6 },
    };
    const aw = hex("09071c0000000529033e19053f4b006f705e19065f");
    try testing.expectEqualSlices(u8, &aw, try encodeOf(ack, &buf));
    const aback = try AcknowledgeAlarm.decode(&aw);
    try testing.expectEqual(EventState.high_limit, aback.state);
    try testing.expectEqualStrings("op", aback.source);
    try testing.expect(aback.time_of_ack.eql(.{ .sequence_number = 6 }));

    try testing.expectEqualSlices(u8, &hex("0c00000005"), try encodeOf(GetEventInformation{ .last_received = ai5 }, &buf));
    try testing.expectEqualSlices(u8, &.{}, try encodeOf(GetEventInformation{}, &buf));
    try testing.expectEqual(ai5, (try GetEventInformation.decode(&hex("0c00000005"))).last_received.?);
    try testing.expectEqual(@as(?ObjectId, null), (try GetEventInformation.decode(&.{})).last_received);

    const sum: EventSummary = .{
        .object = ai5,
        .state = .high_limit,
        .acked_transitions = .{ .bits = 0b110 },
        .time_stamps = .{ .{ .sequence_number = 5 }, .{ .sequence_number = 0 }, .{ .sequence_number = 9 } },
        .notify_type = .alarm,
        .event_enable = .{ .bits = 0b101 },
        .priorities = .{ 100, 100, 200 },
    };
    var lbuf: [96]u8 = undefined;
    var lw = tag.Writer.init(&lbuf);
    try sum.encode(&lw);
    var w = tag.Writer.init(&buf);
    try GetEventInformationAck.encode(lw.written(), true, &w);
    const gw = hex("0e0c0000000519032a05603e1905190019093f49005a05a06e2164216421c86f0f1901");
    try testing.expectEqualSlices(u8, &gw, w.written());
    const g = try GetEventInformationAck.decode(&gw);
    try testing.expect(g.more_events);
    var it = g.summaries();
    const first = (try it.next()).?;
    try testing.expectEqual(sum.priorities, first.priorities);
    try testing.expectEqual(sum.acked_transitions, first.acked_transitions);
    try testing.expectEqual(sum.event_enable, first.event_enable);
    try testing.expect(first.time_stamps[2].eql(.{ .sequence_number = 9 }));
    try testing.expectEqual(@as(?EventSummary, null), try it.next());
}

test "GetAlarmSummary-ACK: golden bytes both ways" {
    var buf: [32]u8 = undefined;
    const e: AlarmSummary = .{ .object = ai5, .state = .high_limit, .acked_transitions = .{ .bits = 0b110 } };
    const wire = hex("c4000000059103820560");
    try testing.expectEqualSlices(u8, &wire, try encodeOf(e, &buf));
    var it = AlarmSummaryIterator.init(&wire);
    const back = (try it.next()).?;
    try testing.expectEqual(EventState.high_limit, back.state);
    try testing.expect(back.acked_transitions.get(.to_fault) and back.acked_transitions.get(.to_normal) and !back.acked_transitions.get(.to_offnormal));
    try testing.expectEqual(@as(?AlarmSummary, null), try it.next());
    // Too many unused bits, or a one-octet string with a non-zero count.
    var bad = tag.Reader.init(&hex("2a0860"));
    try testing.expectError(error.InvalidValue, TransitionBits.decodeCtx(&bad, 2));
    try testing.expectEqual(@as(u8, 0xA0), (TransitionBits{ .bits = 0b101 }).toOctet());
    try testing.expectEqual(Transition.to_normal, Transition.into(.normal));
    try testing.expectEqual(Transition.to_offnormal, Transition.into(.low_limit));
    try testing.expectEqual(Transition.to_fault, Transition.into(.fault));
}

// The goldens below are bacpypes3 0.0.106 output (black box; recipe in
// `tools/event_goldens.py`, second half): the choice alone, which is what
// sits inside `[12]`.

fn expectValues(golden: []const u8, v: anytype) !void {
    var buf: [128]u8 = undefined;
    var w = tag.Writer.init(&buf);
    try v.encodeValues(&w);
    const out = w.written();
    try testing.expectEqual(@as(u8, 0xCE), out[0]);
    try testing.expectEqualSlices(u8, golden, out[1 .. out.len - 1]);
}

test "event values of the other algorithms: golden bytes both ways" {
    const sf1: types.StatusFlags = .{ .in_alarm = true };

    const g_bits = hex("0e0a03b01a04800f");
    try expectValues(&g_bits, ChangeOfBitstring{ .referenced_bitstring = .{ .unused_bits = 3, .bytes = &.{0xB0} }, .status_flags = sf1 });
    const bits = try ChangeOfBitstring.decodeValues(&g_bits);
    try testing.expectEqual(@as(usize, 5), bits.referenced_bitstring.bitCount());
    try testing.expect(bits.referenced_bitstring.bit(2) and !bits.referenced_bitstring.bit(1));

    const g_state = hex("1e0e19010f1a04801f");
    try expectValues(&g_state, ChangeOfState{ .new_state = .{ .choice = PropertyState.binary_value, .value = 1 }, .status_flags = sf1 });
    const st = try ChangeOfState.decodeValues(&g_state);
    try testing.expectEqual(@as(u32, 1), st.new_state.value);
    try testing.expect(st.status_flags.in_alarm);

    const g_cov_bits = hex("2e0e0a05600f1a04802f");
    try expectValues(&g_cov_bits, ChangeOfValue{ .new_value = .{ .changed_bits = .{ .unused_bits = 5, .bytes = &.{0x60} } }, .status_flags = sf1 });
    try testing.expectEqual(@as(u8, 0x60), (try ChangeOfValue.decodeValues(&g_cov_bits)).new_value.changed_bits.bytes[0]);
    const g_cov_real = hex("2e0e1c414800000f1a04802f");
    try expectValues(&g_cov_real, ChangeOfValue{ .new_value = .{ .changed_value = 12.5 }, .status_flags = sf1 });
    try testing.expectEqual(@as(f32, 12.5), (try ChangeOfValue.decodeValues(&g_cov_real)).new_value.changed_value);

    const g_cmd = hex("3e0e91010f1a04802e91002f3f");
    try expectValues(&g_cmd, CommandFailure{ .command_value = &hex("9101"), .status_flags = sf1, .feedback_value = &hex("9100") });
    const cf = try CommandFailure.decodeValues(&g_cmd);
    try testing.expectEqualSlices(u8, &hex("9101"), cf.command_value);
    try testing.expectEqualSlices(u8, &hex("9100"), cf.feedback_value);

    const g_fl = hex("4e0c428f00001a04802c428c00003c3f8000004f");
    try expectValues(&g_fl, FloatingLimit{ .reference_value = 71.5, .status_flags = sf1, .setpoint_value = 70.0, .error_limit = 1.0 });
    try testing.expectEqual(@as(f32, 71.5), (try FloatingLimit.decodeValues(&g_fl)).reference_value);

    const g_ur = hex("be0a05dc1a04802a03e8bf");
    try expectValues(&g_ur, UnsignedRange{ .exceeding_value = 1500, .status_flags = sf1, .exceeded_limit = 1000 });
    try testing.expectEqual(@as(u64, 1000), (try UnsignedRange.decodeValues(&g_ur)).exceeded_limit);

    const g_rel = hex("fe1309021a04c02e2fff13");
    try expectValues(&g_rel, ChangeOfReliability{ .reliability = .over_range, .status_flags = .{ .in_alarm = true, .fault = true } });
    const rel = try ChangeOfReliability.decodeValues(&g_rel);
    try testing.expectEqual(types.Reliability.over_range, rel.reliability);
    try testing.expect(rel.status_flags.fault and rel.property_values.len == 0);

    // With the monitored object's values (what a device sends with a fault).
    const g_relpv = hex("fe13090e1a04c02e09552e4442be00002f09672e910e2f2fff13");
    try expectValues(&g_relpv, ChangeOfReliability{
        .reliability = .monitored_object_fault,
        .status_flags = .{ .in_alarm = true, .fault = true },
        .property_values = &hex("09552e4442be00002f09672e910e2f"),
    });
    try testing.expectEqual(@as(usize, 15), (try ChangeOfReliability.decodeValues(&g_relpv)).property_values.len);

    const g_ls = hex("8e090219012a048039018f");
    try expectValues(&g_ls, ChangeOfLifeSafety{ .new_state = 2, .new_mode = 1, .status_flags = sf1, .operation_expected = 1 });
    try testing.expectEqual(@as(u32, 1), (try ChangeOfLifeSafety.decodeValues(&g_ls)).operation_expected);

    // The union picks the codec by event type; types without one give null.
    const v = (try EventValues.decode(.floating_limit, &g_fl)).?;
    try testing.expectEqual(@as(f32, 70.0), v.floating_limit.setpoint_value);
    try testing.expectEqual(@as(?EventValues, null), try EventValues.decode(.buffer_ready, &g_fl));
    // A block of another choice, and every truncation, are typed errors.
    try testing.expectError(error.UnexpectedTag, ChangeOfState.decodeValues(&g_fl));
    for ([_][]const u8{ &g_bits, &g_state, &g_cov_bits, &g_cov_real, &g_cmd, &g_fl, &g_ur, &g_rel, &g_ls }) |g| {
        for (0..g.len) |cut| {
            _ = ChangeOfBitstring.decodeValues(g[0..cut]) catch {};
            _ = ChangeOfState.decodeValues(g[0..cut]) catch {};
            _ = ChangeOfValue.decodeValues(g[0..cut]) catch {};
            _ = CommandFailure.decodeValues(g[0..cut]) catch {};
            _ = FloatingLimit.decodeValues(g[0..cut]) catch {};
            _ = UnsignedRange.decodeValues(g[0..cut]) catch {};
            _ = ChangeOfReliability.decodeValues(g[0..cut]) catch {};
            _ = ChangeOfLifeSafety.decodeValues(g[0..cut]) catch {};
        }
    }
}

fn expectParams(golden: []const u8, p: EventParameters) !void {
    var buf: [128]u8 = undefined;
    var w = tag.Writer.init(&buf);
    try p.encode(&w);
    try testing.expectEqualSlices(u8, golden, w.written());
}

test "Event_Parameters and property references: golden bytes both ways" {
    const ai5_pv: PropertyReference = .{ .object = ai5, .property = .present_value };
    const g_ref = hex("0c000000051955");
    var buf: [64]u8 = undefined;
    var w = tag.Writer.init(&buf);
    try ai5_pv.encode(&w);
    try testing.expectEqualSlices(u8, &g_ref, w.written());
    const full: PropertyReference = .{ .object = .{ .type = .multi_state_value, .instance = 5 }, .property = .present_value, .array_index = 3, .device = .{ .type = .device, .instance = 599 } };
    w = tag.Writer.init(&buf);
    try full.encode(&w);
    const g_full = hex("0c04c00005195529033c02000257");
    try testing.expectEqualSlices(u8, &g_full, w.written());
    var r = tag.Reader.init(&g_full);
    const back = try PropertyReference.decode(&r);
    try testing.expectEqual(@as(?u32, 3), back.array_index);
    try testing.expectEqual(@as(u22, 599), back.device.?.instance);

    const g_bs = hex("0e09051a04c02e8204808204402f0f");
    try expectParams(&g_bs, .{ .change_of_bitstring = .{ .time_delay = 5, .bitmask = .{ .unused_bits = 4, .bytes = &.{0xC0} }, .values = &hex("820480820440") } });
    const p_bs = try EventParameters.decode(&g_bs);
    var bit_it = EventParameters.bitstringsIterator(p_bs.change_of_bitstring.values);
    try testing.expectEqual(@as(u8, 0x80), (try bit_it.next()).?.bytes[0]);
    try testing.expectEqual(@as(u8, 0x40), (try bit_it.next()).?.bytes[0]);
    try testing.expectEqual(@as(?tag.BitString, null), try bit_it.next());

    const g_st = hex("1e09051e1901b9031f1f");
    try expectParams(&g_st, .{ .change_of_state = .{ .time_delay = 5, .values = &hex("1901b903") } });
    const p_st = try EventParameters.decode(&g_st);
    var st_it = EventParameters.statesIterator(p_st.change_of_state.values);
    try testing.expectEqual(PropertyState{ .choice = 1, .value = 1 }, (try st_it.next()).?);
    try testing.expectEqual(PropertyState{ .choice = 11, .value = 3 }, (try st_it.next()).?);
    try testing.expectEqual(@as(?PropertyState, null), try st_it.next());

    const g_ci = hex("2e09051e1c3f0000001f2f");
    try expectParams(&g_ci, .{ .change_of_value = .{ .time_delay = 5, .criteria = .{ .increment = 0.5 } } });
    try testing.expectEqual(@as(f32, 0.5), (try EventParameters.decode(&g_ci)).change_of_value.criteria.increment);
    const g_cm = hex("2e09051e0a05e01f2f");
    try expectParams(&g_cm, .{ .change_of_value = .{ .time_delay = 5, .criteria = .{ .bitmask = .{ .unused_bits = 5, .bytes = &.{0xE0} } } } });
    try testing.expectEqual(@as(u8, 0xE0), (try EventParameters.decode(&g_cm)).change_of_value.criteria.bitmask.bytes[0]);

    const g_cmd = hex("3e09051e0c0000000519551f3f");
    try expectParams(&g_cmd, .{ .command_failure = .{ .time_delay = 5, .feedback = ai5_pv } });
    try testing.expect((try EventParameters.decode(&g_cmd)).command_failure.feedback.object.eql(ai5));

    const g_fl = hex("4e09051e0c0000000519551f2c3fc000003c402000004c3f0000004f");
    try expectParams(&g_fl, .{ .floating_limit = .{ .time_delay = 5, .setpoint = ai5_pv, .low_diff_limit = 1.5, .high_diff_limit = 2.5, .deadband = 0.5 } });
    try testing.expectEqual(@as(f32, 2.5), (try EventParameters.decode(&g_fl)).floating_limit.high_diff_limit);

    const g_oor = hex("5e09051c412000002c42b400003c400000005f");
    try expectParams(&g_oor, .{ .out_of_range = .{ .time_delay = 5, .low_limit = 10.0, .high_limit = 90.0, .deadband = 2.0 } });
    try testing.expectEqual(@as(f32, 90.0), (try EventParameters.decode(&g_oor)).out_of_range.high_limit);

    const g_ur = hex("be0905190a295abf");
    try expectParams(&g_ur, .{ .unsigned_range = .{ .time_delay = 5, .low_limit = 10, .high_limit = 90 } });
    try testing.expectEqual(@as(u64, 90), (try EventParameters.decode(&g_ur)).unsigned_range.high_limit);

    const g_none = hex("f814");
    try expectParams(&g_none, .none);
    try testing.expectEqual(EventType.none, (try EventParameters.decode(&g_none)).eventType());
    try testing.expectEqual(EventType.floating_limit, (try EventParameters.decode(&g_fl)).eventType());

    // Trailing octets, an unknown choice and every truncation are typed errors.
    try testing.expectError(error.InvalidParameter, EventParameters.decode(&hex("f81400")));
    try testing.expectError(error.UnexpectedTag, EventParameters.decode(&hex("9e09051f")));
    for ([_][]const u8{ &g_bs, &g_st, &g_ci, &g_cm, &g_cmd, &g_fl, &g_oor, &g_ur, &g_none }) |g| {
        for (0..g.len) |cut| _ = EventParameters.decode(g[0..cut]) catch {};
    }
}

test "LifeSafetyOperation: golden bytes both ways" {
    var buf: [32]u8 = undefined;
    const with: LifeSafetyOperationRequest = .{ .process_id = 7, .source = "op", .request = .silence, .object = .{ .type = .life_safety_point, .instance = 3 } };
    const g_with = hex("09071b006f7029013c05400003");
    try testing.expectEqualSlices(u8, &g_with, try encodeOf(with, &buf));
    const back = try LifeSafetyOperationRequest.decode(&g_with);
    try testing.expectEqual(LifeSafetyOperation.silence, back.request);
    try testing.expectEqual(@as(u22, 3), back.object.?.instance);
    const g_all = hex("09071b006f702905");
    try testing.expectEqualSlices(u8, &g_all, try encodeOf(LifeSafetyOperationRequest{ .process_id = 7, .source = "op", .request = .reset_alarm }, &buf));
    try testing.expectEqual(@as(?ObjectId, null), (try LifeSafetyOperationRequest.decode(&g_all)).object);
    try testing.expectError(error.UnexpectedTag, LifeSafetyOperationRequest.decode(&hex("09071b006f70290500")));
}

// ── fuzzing: every decoder over arbitrary bodies ───────────────────────────

const fuzzSeed = testkit.fuzz.seedHex;
const fz = @import("fuzz_test.zig");

const event_seeds = [_][]const u8{
    fuzzSeed("09071c020002572c000000053e19053f4903596469057c00686f7489009901a900b903ce5e0c42b700001a04802c400000003c42b400005fcf"), // notification
    fuzzSeed("09071c0000000529033e19053f4b006f705e19065f"), // AcknowledgeAlarm
    fuzzSeed("0c00000005"), // GetEventInformation
    fuzzSeed("0e0c0000000519032a05603e1905190019093f49005a05a06e2164216421c86f0f1901"), // its ACK
    fuzzSeed("c4000000059103820560"), // GetAlarmSummary ACK
    fuzzSeed("3e19053f"), // a wrapped time stamp
    fuzzSeed("0e0c000000051903"), // truncated inside a summary
};

test "fuzz: events decoders never crash on arbitrary bodies" {
    try std.testing.fuzz({}, fuzzEventsSmith, .{ .corpus = &event_seeds });
}

const fuzzEventsMark = fz.Marker(enum { ran, nonempty, notification, ack, summary_list, alarm_list });

fn fuzzEventsSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzEvents(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzEvents(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [192]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &event_seeds);
    fuzzEventsMark.mark(.ran);
    if (len != 0) fuzzEventsMark.mark(.nonempty);
    const data = buf[0..len];

    if (EventNotification.decode(data)) |n| {
        fuzzEventsMark.mark(.notification);
        if (n.values) |v| _ = OutOfRange.decodeValues(v) catch {};
        // What decodes must encode again (the optional pieces are all in range).
        var out: [256]u8 = undefined;
        var w = tag.Writer.init(&out);
        n.encode(&w) catch {};
    } else |_| {}
    if (AcknowledgeAlarm.decode(data)) |_| fuzzEventsMark.mark(.ack) else |_| {}
    _ = GetEventInformation.decode(data) catch {};
    if (GetEventInformationAck.decode(data)) |g| {
        var it = g.summaries();
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            _ = (it.next() catch break) orelse break;
            fuzzEventsMark.mark(.summary_list);
        }
    } else |_| {}
    var ait = AlarmSummaryIterator.init(data);
    var guard: usize = 0;
    while (guard < 64) : (guard += 1) {
        _ = (ait.next() catch break) orelse break;
        fuzzEventsMark.mark(.alarm_list);
    }
    var r = tag.Reader.init(data);
    _ = TimeStamp.decodeCtx(&r, 3) catch {};
}

test "fuzz driver: BACNET_FUZZ (fuzzEvents)" {
    try fz.fuzz_driver.run(fuzzEvents, .{ .prefix = "BACNET_FUZZ", .name = "bacnet-events-events" });
}

test "fuzz harness: fuzzEvents, 600 seeds, reaches every outcome" {
    try fuzzEventsMark.reach(fuzzEvents, "bacnet-events-events", 600);
}

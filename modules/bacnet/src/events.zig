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
/// (clause 13.3.2): the value that crossed, the object's status flags, the
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

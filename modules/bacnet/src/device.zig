// SPDX-License-Identifier: MIT

//! A BACnet/IP **device** (responder): a small object database that answers
//! discovery, property reads and writes, and change-of-value subscriptions.
//! Stand one up per simulated device for fleet simulation, or in front of real
//! data to expose it to a building-management system.
//!
//! Same shape as the client and for the same reasons: **no clock, no thread,
//! no socket**. `poll(now_ms)` reads at most one datagram, answers it, and
//! reports what it did; subscription lifetimes and COV re-notification are
//! driven by the `now_ms` the caller supplies.
//!
//! What it deliberately does not do:
//!
//! * **It segments only when told to** (`Config.segmented_responses`, off by
//!   default). Without it the Device object advertises
//!   `segmentation_supported = none` and a request whose answer would
//!   overflow the peer's `max-APDU-length-accepted` gets
//!   `Abort(buffer_overflow)`, which is what clause 5.4 prescribes: it fails
//!   cleanly rather than silently truncating. With it, such an answer goes out
//!   as a segmented ComplexACK to a requester that accepts them.
//! * **It reassembles a segmented request only with a buffer**
//!   (`Config.reassembly`); without one it answers
//!   `Abort(segmentation_not_supported)`.
//! * **It has no persistence and no allocator.** The object table is the
//!   caller's slice; property values live in it.

const std = @import("std");
const types = @import("types.zig");
const tag = @import("tag.zig");
const bvll = @import("bvll.zig");
const npdu = @import("npdu.zig");
const apdu = @import("apdu.zig");
const service = @import("service.zig");
const events = @import("events.zig");
const transport = @import("transport.zig");

const ObjectId = tag.ObjectId;
const BipAddress = bvll.BipAddress;
const PropertyIdentifier = types.PropertyIdentifier;
const Transport = transport.Transport;

pub const Error = tag.Error || apdu.Error || service.Error || bvll.Error ||
    npdu.Error || transport.TransportError;

/// A property value the device can store and serve. `raw` is the escape
/// hatch: pre-encoded tagged octets for anything richer than a primitive (an
/// array, a constructed type, a priority array).
pub const Value = union(enum) {
    null,
    boolean: bool,
    unsigned: u32,
    signed: i32,
    real: f32,
    double: f64,
    enumerated: u32,
    /// UTF-8; the encoding octet is added on the wire.
    string: []const u8,
    bit_string: struct { unused_bits: u3 = 0, bytes: []const u8 },
    object_id: ObjectId,
    /// Already-tagged octets, emitted verbatim.
    raw: []const u8,
    /// A commandable property's priority array: sixteen slots, `null` for
    /// "no command at this priority", encoded as an array of
    /// `BACnetPriorityValue` (a Null or the value's own application tag). The
    /// slots are those of the sibling property that carries
    /// `Property.priority_slots` (the same pointer).
    priority_array: *const [16]?Value,

    pub fn encode(self: Value, w: *tag.Writer) tag.Error!void {
        switch (self) {
            .null => try w.appNull(),
            .boolean => |b| try w.appBool(b),
            .unsigned => |u| try w.appUnsigned(u),
            .signed => |i| try w.appSigned(i),
            .real => |r| try w.appReal(r),
            .double => |d| try w.appDouble(d),
            .enumerated => |e| try w.appEnumerated(e),
            .string => |s| try w.appString(s),
            .bit_string => |b| try w.appBitString(.{
                .unused_bits = b.unused_bits,
                .bytes = b.bytes,
            }),
            .object_id => |o| try w.appObjectId(o),
            .raw => |r| try w.raw(r),
            .priority_array => |slots| for (slots) |slot| {
                if (slot) |v| try v.encode(w) else try w.appNull();
            },
        }
    }

    /// Parses an incoming WriteProperty value into the same shape, so a write
    /// can be type-checked against what is already stored. Returns null for
    /// anything this union does not model.
    pub fn parse(bytes: []const u8) ?Value {
        var r = tag.Reader.init(bytes);
        const v = r.appValue() catch return null;
        if (!r.atEnd()) return null;
        return switch (v) {
            .null => .null,
            .boolean => |b| .{ .boolean = b },
            .unsigned => |u| if (u <= std.math.maxInt(u32)) .{ .unsigned = @intCast(u) } else null,
            .signed => |i| if (i >= std.math.minInt(i32) and i <= std.math.maxInt(i32))
                .{ .signed = @intCast(i) }
            else
                null,
            .real => |x| .{ .real = x },
            .double => |x| .{ .double = x },
            .enumerated => |e| .{ .enumerated = e },
            .object_identifier => |o| .{ .object_id = o },
            else => null,
        };
    }

    /// True when two values are the same *kind*. A WriteProperty that changes
    /// a property's datatype is `invalid_data_type`, not a silent coercion.
    pub fn sameKind(a: Value, b: Value) bool {
        return std.meta.activeTag(a) == std.meta.activeTag(b);
    }
};

/// One property of one object.
pub const Property = struct {
    id: PropertyIdentifier,
    value: Value,
    /// Whether WriteProperty may change it.
    writable: bool = false,
    /// Whether it is one of the properties a COV subscription watches. In the
    /// standard, COV on an analog object reports `present_value` and
    /// `status_flags`; this flag is how a caller says so.
    cov_reported: bool = false,
    /// Whether it belongs to the object's *required* set, for the RPM
    /// `REQUIRED`/`OPTIONAL` wildcards.
    required: bool = true,
    /// Makes this property (a `present_value`) **commandable** (clause 19.2):
    /// the sixteen priority slots, in the caller's storage. A write at
    /// priority `p` (16 when none is given) fills slot `p`, a relinquish
    /// (a Null) empties it, and `value` is always the highest-priority
    /// non-empty slot, or else the object's `relinquish_default` property
    /// (which must exist and carry the property's kind). Priority 6 is
    /// reserved for the minimum on/off algorithm and refused to clients. Serve
    /// the array with a sibling property
    /// `.{ .id = .priority_array, .value = .{ .priority_array = slots } }`.
    priority_slots: ?*[16]?Value = null,
    /// The last value a COV notification was sent for, which
    /// `COV_Increment` is measured against (set by the device).
    cov_last: ?f32 = null,
    /// Turns an object's `event_state` property into **intrinsic reporting**
    /// for an analog object (clause 13.3.2, OUT_OF_RANGE): the caller's
    /// `EventData` holds the state machine, and the device keeps the
    /// object's `event_state`, `acked_transitions` and `event_time_stamps`
    /// properties in step with it (see `EventData`).
    event: ?*EventData = null,
};

/// The state of one object's intrinsic reporting, in the caller's storage
/// (attach it with `Property.event` on the object's `event_state` property).
///
/// The algorithm is OUT_OF_RANGE (clause 13.3.2) over the object's own
/// properties: Real `present_value`, `high_limit`, `low_limit`, `deadband`,
/// BitString `limit_enable` (low, high) and `event_enable` (to-offnormal,
/// to-fault, to-normal), Unsigned `notification_class`, `time_delay` and
/// optional `time_delay_normal` (seconds), Enumerated `notify_type`, and
/// optional `status_flags`. A transition happens once the condition has held
/// for the delay; it is stamped with a **sequence number** (the device has no
/// wall clock), and is announced to the recipients of the object's
/// Notification Class object when `event_enable` allows it.
pub const EventData = struct {
    state: types.EventState = .normal,
    /// `Acked_Transitions`: a transition that needs no acknowledgement (or is
    /// not enabled) is acknowledged from the start.
    acked: events.TransitionBits = .all,
    /// The time stamp of the last transition of each kind.
    stamps: [3]events.TimeStamp = @splat(events.TimeStamp.unspecified),
    /// The state each of those transitions went to.
    stamp_states: [3]types.EventState = .{ .offnormal, .fault, .normal },
    /// A transition the condition currently asks for, and since when.
    pending: ?types.EventState = null,
    pending_since_ms: u64 = 0,
    acked_octet: [1]u8 = .{0xE0},
    stamps_wire: [24]u8 = undefined,
    stamps_wire_len: usize = 0,

    /// Writes the state into the object's `event_state`,
    /// `acked_transitions` and `event_time_stamps` properties (those that
    /// exist). The device does it after every change; call it once after
    /// wiring so that a read before the first transition is served from
    /// here. The properties then point into this struct, so it must stay put.
    pub fn sync(self: *EventData, props: []Property) void {
        var w = tag.Writer.init(&self.stamps_wire);
        for (self.stamps) |ts| ts.encode(&w) catch {};
        self.stamps_wire_len = w.written().len;
        self.acked_octet[0] = self.acked.toOctet();
        for (props) |*p| switch (p.id) {
            .event_state => p.value = .{ .enumerated = @backingInt(self.state) },
            .acked_transitions => p.value = .{ .bit_string = .{ .unused_bits = 5, .bytes = &self.acked_octet } },
            .event_time_stamps => p.value = .{ .raw = self.stamps_wire[0..self.stamps_wire_len] },
            else => {},
        };
    }
};

/// One object in the device's database.
pub const Object = struct {
    id: ObjectId,
    properties: []Property,

    pub fn find(self: *const Object, p: PropertyIdentifier) ?*Property {
        for (self.properties) |*prop| {
            if (prop.id == p) return prop;
        }
        return null;
    }
};

/// An active COV subscription.
pub const Subscription = struct {
    active: bool = false,
    subscriber: BipAddress = .{ .ip = @splat(0) },
    process_id: u32 = 0,
    object: ObjectId = .{ .type = .device, .instance = 0 },
    confirmed: bool = false,
    /// Absolute expiry. Null = indefinite (lifetime 0).
    expires_ms: ?u64 = null,
    /// Invoke id of an outstanding confirmed notification, if any.
    outstanding: ?u8 = null,
};

pub const Config = struct {
    /// This device's instance number. Must be unique on the internetwork;
    /// `4194303` means "unconfigured" and is what a factory-fresh device ships
    /// with.
    instance: u22,
    vendor_id: u16 = 0,
    /// The largest APDU this device will accept.
    max_apdu: apdu.MaxApdu = .up_to_1476,
    /// Answered COV subscriptions are clamped to this many seconds so a
    /// vanished subscriber's subscription eventually lapses. 0 disables the
    /// clamp (and allows indefinite subscriptions).
    max_cov_lifetime_s: u32 = 3600,
    /// The password `DeviceCommunicationControl` and `ReinitializeDevice`
    /// must carry (1..20 characters; clause 16.1.2, 16.4.2). `null` accepts
    /// any password, or none: a simulator rarely has one.
    password: ?[]const u8 = null,
    /// Send a reply larger than the requester's max APDU as a **segmented
    /// ComplexACK** (clause 5.4.4) when the request accepts segmented
    /// responses, instead of `Abort(buffer_overflow)`. The device then says
    /// `segmentation_supported = transmit` in its I-Am. One segmented reply
    /// is in flight at a time (up to `max_segmented_reply` octets); a second
    /// request that needs one meanwhile is aborted with `out_of_resources`.
    /// Off by default: the device then never segments, as before.
    segmented_responses: bool = false,
    /// The window of segments sent before an acknowledgement is awaited
    /// (1..127), further limited by the requester's own window.
    segment_window: u8 = 4,
    /// Milliseconds to wait for a `SegmentACK` before the window is resent.
    segment_timeout_ms: u32 = 2000,
    /// Resends of a window before the transfer is abandoned with
    /// `Abort(tsm_timeout)`.
    segment_retries: u8 = 3,
    /// Room to reassemble a **segmented request** (clause 5.4.5), owned by
    /// the caller. With a buffer the device takes the segments of one request
    /// at a time (a `SegmentACK` per `segment_window` segments and for the
    /// last), serves the whole request, and says `receive` (or `both`) in its
    /// I-Am. A request larger than the buffer is aborted with
    /// `buffer_overflow`; a second one while one is in progress with
    /// `out_of_resources`; silence for `segment_timeout_ms` drops the
    /// transfer. With `null` (the default) a segmented request is answered
    /// with `Abort(segmentation_not_supported)`.
    reassembly: ?[]u8 = null,
};

/// The largest reply a segmented transfer can carry.
pub const max_segmented_reply: usize = 8192;

/// What `poll` reports — a device is mostly silent, so these are for logging
/// and for tests rather than for control flow.
pub const Event = union(enum) {
    none,
    /// Answered a Who-Is with an I-Am.
    announced,
    /// Answered a Who-Has with an I-Have.
    answered_who_has,
    /// Served a read.
    read: struct { object: ObjectId, property: PropertyIdentifier },
    /// Served a write. The caller may want to act on the new value.
    wrote: struct { object: ObjectId, property: PropertyIdentifier },
    /// Accepted or cancelled a COV subscription.
    subscribed: struct { object: ObjectId, cancelled: bool },
    /// Finished a segmented reply: every segment was acknowledged.
    segmented_reply_sent: struct { invoke_id: u8, segments: u16 },
    /// Served a `WritePropertyMultiple`: every write up to the first failure
    /// was applied (clause 15.10.2 does not roll back); `count` of them.
    wrote_multiple: struct { count: usize },
    /// Accepted a `DeviceCommunicationControl`; the new state (the device
    /// applies it by itself, this is for logging).
    communication_control: struct { state: service.CommunicationState, duration_minutes: ?u16 },
    /// Accepted a `ReinitializeDevice` and acknowledged it. The device cannot
    /// restart itself: the application does what `state` asks.
    reinitialize: struct { state: service.ReinitializedState },
    /// Received a `TimeSynchronization` (`utc` false) or
    /// `UTCTimeSynchronization`. The device has no clock of its own to set:
    /// the application applies `time`.
    time_synchronized: struct { time: service.DateTime, utc: bool },
    /// Intrinsic reporting moved an object to a new event state (and sent
    /// the notifications its Notification Class asks for).
    event_transition: struct { object: ObjectId, from: types.EventState, to: types.EventState },
    /// Accepted an `AcknowledgeAlarm`.
    alarm_acknowledged: struct { object: ObjectId, state: types.EventState },
    /// Refused a request.
    refused: struct { class: types.ErrorClass, code: types.ErrorCode },
    /// Something arrived that this device does not serve.
    unhandled,
};

/// A segmented ComplexACK being sent.
const SegTx = struct {
    active: bool = false,
    peer: BipAddress = .{ .ip = @splat(0) },
    invoke_id: u8 = 0,
    svc: types.ConfirmedService = .read_property,
    data: [max_segmented_reply]u8 = undefined,
    len: usize = 0,
    seg_size: usize = 1,
    total: u16 = 0,
    /// The next segment to send, and the first one not yet acknowledged.
    next: u16 = 0,
    base: u16 = 0,
    window: u8 = 1,
    deadline_ms: u64 = 0,
    retries_left: u8 = 0,
};

/// A segmented request being received (clause 5.4.5).
const SegRx = struct {
    active: bool = false,
    peer: BipAddress = .{ .ip = @splat(0) },
    invoke_id: u8 = 0,
    svc: types.ConfirmedService = .read_property,
    /// The sequence number the next segment must carry.
    expected: u8 = 0,
    len: usize = 0,
    /// The window agreed (the sender's proposal capped by ours), and how many
    /// segments came since the last acknowledgement.
    window: u8 = 1,
    since_ack: u8 = 0,
    last_ms: u64 = 0,
};

fn realOf(p: ?*Property) ?f32 {
    const q = p orelse return null;
    return if (q.value == .real) q.value.real else null;
}

fn unsignedOf(p: ?*Property) ?u32 {
    const q = p orelse return null;
    return if (q.value == .unsigned) q.value.unsigned else null;
}

fn enumOf(p: ?*Property) ?u32 {
    const q = p orelse return null;
    return if (q.value == .enumerated) q.value.enumerated else null;
}

fn bitsOf(p: ?*Property) ?events.TransitionBits {
    const q = p orelse return null;
    if (q.value != .bit_string) return null;
    return events.TransitionBits.fromBitString(.{ .unused_bits = q.value.bit_string.unused_bits, .bytes = q.value.bit_string.bytes });
}

/// The notification priority of a transition from the class's `priority`
/// array (three Unsigned), 255 (the lowest) when there is none.
fn classPriority(cls: ?*Object, tr: events.Transition) u8 {
    const c = cls orelse return 255;
    const p = c.find(.priority) orelse return 255;
    if (p.value != .raw) return 255;
    var r = tag.Reader.init(p.value.raw);
    var i: usize = 0;
    while (i <= @backingInt(tr)) : (i += 1) {
        const v = r.expectApp(.unsigned) catch return 255;
        if (i == @backingInt(tr)) return if (v.unsigned > 255) 255 else @intCast(v.unsigned);
    }
    return 255;
}

/// One `BACnetDestination` of a Notification Class's `recipient_list`.
const Destination = struct {
    address: ?BipAddress,
    process_id: u32,
    confirmed: bool,
    transitions: events.TransitionBits,
};

fn parseDestination(r: *tag.Reader) events.Error!Destination {
    _ = try r.expectApp(.bit_string); // valid days
    _ = try r.expectApp(.time); // from
    _ = try r.expectApp(.time); // to
    var addr: ?BipAddress = null;
    const t = try r.peek();
    if (t.isContext(0)) {
        _ = try r.ctxObjectId(0); // a device identifier: no address binding here
    } else {
        try r.expectOpen(1);
        const net = (try r.expectApp(.unsigned)).unsigned;
        const mac = (try r.expectApp(.octet_string)).octet_string;
        try r.expectClose(1);
        if (net == 0 and mac.len == BipAddress.wire_len) addr = BipAddress.decode(mac[0..6]);
    }
    const pid = (try r.expectApp(.unsigned)).unsigned;
    const conf = (try r.expectApp(.boolean)).boolean;
    const tr = try events.TransitionBits.decodeApp(r);
    return .{
        .address = addr,
        .process_id = if (pid > std.math.maxInt(u32)) return error.InvalidValue else @intCast(pid),
        .confirmed = conf,
        .transitions = tr,
    };
}

pub fn Device(comptime max_subscriptions: usize) type {
    return struct {
        const Self = @This();

        tp: Transport,
        config: Config,
        objects: []Object,
        subs: [max_subscriptions]Subscription = @splat(.{}),
        rx: [transport.max_datagram]u8 = undefined,
        tx: [transport.max_datagram]u8 = undefined,
        /// Invoke ids for confirmed COV notifications this device originates.
        next_invoke: u8 = 0,
        /// What `DeviceCommunicationControl` last set (clause 16.1).
        comm: service.CommunicationState = .enable,
        /// When a timed `disable` or `disable_initiation` lapses (`null`:
        /// until `enable` or a restart).
        comm_until_ms: ?u64 = null,
        /// The segmented reply in flight (clause 5.4.4), if any.
        seg: SegTx = .{},
        /// The segmented request being received (clause 5.4.5), if any.
        rx_seg: SegRx = .{},
        /// The last sequence number handed out as an event time stamp.
        event_seq: u32 = 0,

        pub fn init(tp: Transport, config: Config, objects: []Object) Self {
            return .{ .tp = tp, .config = config, .objects = objects };
        }

        /// This device's own Device object identifier.
        pub fn deviceId(self: *const Self) ObjectId {
            return .{ .type = .device, .instance = self.config.instance };
        }

        pub fn find(self: *Self, id: ObjectId) ?*Object {
            for (self.objects) |*o| {
                if (o.id.eql(id)) return o;
            }
            return null;
        }

        /// Broadcasts an unsolicited `I-Am`, which is what a device does on
        /// restart so controllers do not have to wait for the next Who-Is.
        ///
        /// Sends nothing while `DeviceCommunicationControl` has disabled
        /// initiation (clause 16.1.3): an unsolicited I-Am is an initiated
        /// message, the answer to a Who-Is is not.
        pub fn announce(self: *Self) Error!void {
            if (self.comm != .enable) return;
            return self.sendIAm(null);
        }

        /// Sends an `I-Am` to one address. A device that received a **unicast**
        /// Who-Is answers this way: the requester is on a subnet this device
        /// may not be able to broadcast onto (behind a BBMD, on loopback, or
        /// reached through a router), and a broadcast reply would simply never
        /// arrive. Clause 16.10.3 leaves the addressing to the device, and
        /// answering the way the question came is what interoperable stacks do.
        pub fn announceTo(self: *Self, to: BipAddress) Error!void {
            return self.sendIAm(to);
        }

        fn sendIAm(self: *Self, to: ?BipAddress) Error!void {
            var body: [32]u8 = undefined;
            var w = tag.Writer.init(&body);
            try self.iAmBody(&w);
            var a_buf: [64]u8 = undefined;
            const a = try apdu.encode(.{ .unconfirmed_request = .{
                .service = .i_am,
                .data = w.written(),
            } }, &a_buf);
            var n_buf: [96]u8 = undefined;
            if (to) |dest| {
                const n = try npdu.encode(.{}, a, &n_buf);
                const d = try bvll.wrap(.original_unicast_npdu, n, &self.tx);
                try self.tp.send(dest, d);
                return;
            }
            const n = try npdu.encode(
                .{ .destination = npdu.NetAddress.global, .hop_count = 255 },
                a,
                &n_buf,
            );
            const d = try bvll.wrap(.original_broadcast_npdu, n, &self.tx);
            try self.tp.broadcast(d);
        }

        /// Changes a property's value and notifies every COV subscriber
        /// watching it. This is the entry point a simulation drives.
        pub fn update(self: *Self, id: ObjectId, prop: PropertyIdentifier, v: Value, now_ms: u64) Error!void {
            const obj = self.find(id) orelse return;
            const p = obj.find(prop) orelse return;
            p.value = v;
            if (p.cov_reported and self.covDue(obj, p)) try self.notifyCov(obj, now_ms);
        }

        /// Receives at most one datagram, answers it, and expires at most one
        /// lapsed subscription.
        pub fn poll(self: *Self, now_ms: u64) Error!Event {
            self.expireSubscriptions(now_ms);
            try self.segmentTimer(now_ms);
            if (self.rx_seg.active and now_ms >= self.rx_seg.last_ms +| self.config.segment_timeout_ms) self.rx_seg.active = false;
            if (self.comm_until_ms) |t| if (now_ms >= t) {
                self.comm = .enable;
                self.comm_until_ms = null;
            };
            if (try self.evaluateEvents(now_ms)) |ev| return ev;
            const got = (try self.tp.recv(&self.rx)) orelse return .none;
            return self.handle(got.from, got.bytes, now_ms) catch |e| switch (e) {
                error.NotBvlc,
                error.LengthMismatch,
                error.UnknownFunction,
                error.InvalidBody,
                error.UnsupportedVersion,
                error.InvalidControl,
                error.UnknownMessageType,
                error.InvalidPduType,
                error.Truncated,
                error.InvalidTag,
                error.UnexpectedTag,
                error.InvalidLength,
                error.InvalidValue,
                error.MissingParameter,
                error.InvalidParameter,
                => .none,
                else => e,
            };
        }

        pub fn subscriptionCount(self: *const Self) usize {
            var n: usize = 0;
            for (self.subs) |s| {
                if (s.active) n += 1;
            }
            return n;
        }

        // ── internals ──────────────────────────────────────────────────────

        fn iAmBody(self: *Self, w: *tag.Writer) Error!void {
            try (service.IAm{
                .device = self.deviceId(),
                .max_apdu_accepted = try self.config.max_apdu.octets(),
                // Saying what this device cannot do up front is what keeps a
                // peer from ever trying.
                .segmentation = if (self.config.segmented_responses)
                    (if (self.config.reassembly != null) types.Segmentation.both else .transmit)
                else if (self.config.reassembly != null) .receive else .none,
                .vendor_id = self.config.vendor_id,
            }).encode(w);
        }

        fn handle(self: *Self, from: BipAddress, dgram: []u8, now_ms: u64) Error!Event {
            const b = try bvll.decode(dgram);
            const origin = switch (b) {
                .forwarded_npdu => |f| f.origin,
                else => from,
            };
            const npdu_bytes = b.npdu() orelse return .none;
            const n = try npdu.decode(npdu_bytes);
            const a_bytes = switch (n.payload) {
                .apdu => |x| x,
                .network => return .none,
            };
            const a = try apdu.decode(a_bytes);

            // `disable`: nothing is answered but the two services that can end
            // it (clause 16.1.3).
            if (self.comm == .disable) {
                const allowed = switch (a) {
                    .confirmed_request => |r| r.service == .device_communication_control or r.service == .reinitialize_device,
                    else => false,
                };
                if (!allowed) return .none;
            }

            switch (a) {
                .unconfirmed_request => |u| switch (u.service) {
                    .who_is => {
                        const wi = try service.WhoIs.decode(u.data);
                        if (!wi.matches(self.config.instance)) return .none;
                        // Answer the way the question arrived (see
                        // `announceTo`).
                        if (b.function() == .original_unicast_npdu) {
                            try self.announceTo(origin);
                        } else {
                            try self.sendIAm(null);
                        }
                        return .announced;
                    },
                    .who_has => return self.handleWhoHas(u.data, origin, b.function()),
                    .time_synchronization, .utc_time_synchronization => {
                        const ts = service.TimeSynchronization.decode(u.data) catch return .none;
                        return .{ .time_synchronized = .{ .time = ts.time, .utc = u.service == .utc_time_synchronization } };
                    },
                    else => return .unhandled,
                },
                .confirmed_request => |r| {
                    if (r.segment != null) {
                        if (self.config.reassembly == null) {
                            // Refuse rather than buffer: this device was not
                            // given room to reassemble, and said so in its I-Am.
                            try self.sendApdu(origin, apdu.segmentationNotSupported(r.invoke_id, true));
                            return .unhandled;
                        }
                        return self.handleRequestSegment(origin, r, now_ms);
                    }
                    return self.serveConfirmed(origin, r, now_ms);
                },
                .segment_ack => |sa| return self.handleSegmentAck(origin, sa, now_ms),
                .simple_ack => |s| {
                    // The acknowledgement of one of our confirmed COV
                    // notifications.
                    for (&self.subs) |*sub| {
                        if (sub.active and sub.outstanding == s.invoke_id) sub.outstanding = null;
                    }
                    return .none;
                },
                .abort, .reject, .err => {
                    if (self.seg.active and self.seg.invoke_id == a.invokeId() and self.seg.peer.eql(origin)) self.seg.active = false;
                    if (self.rx_seg.active and self.rx_seg.invoke_id == a.invokeId() and self.rx_seg.peer.eql(origin)) self.rx_seg.active = false;
                    for (&self.subs) |*sub| {
                        if (sub.active and sub.outstanding == a.invokeId()) sub.outstanding = null;
                    }
                    return .none;
                },
                else => return .unhandled,
            }
        }

        fn serveConfirmed(self: *Self, origin: BipAddress, r: apdu.ConfirmedRequest, now_ms: u64) Error!Event {
            return switch (r.service) {
                .read_property => self.handleReadProperty(origin, r, now_ms),
                .read_property_multiple => self.handleRpm(origin, r, now_ms),
                .write_property => self.handleWriteProperty(origin, r),
                .write_property_multiple => self.handleWpm(origin, r),
                .device_communication_control => self.handleDcc(origin, r, now_ms),
                .reinitialize_device => self.handleReinitialize(origin, r),
                .subscribe_cov => self.handleSubscribeCov(origin, r, now_ms),
                .acknowledge_alarm => self.handleAcknowledgeAlarm(origin, r),
                .get_event_information => self.handleGetEventInformation(origin, r),
                .get_alarm_summary => self.handleGetAlarmSummary(origin, r),
                else => blk: {
                    try self.sendApdu(origin, .{ .reject = .{
                        .invoke_id = r.invoke_id,
                        .reason = .unrecognized_service,
                    } });
                    break :blk .unhandled;
                },
            };
        }

        /// One segment of a segmented request (clause 5.4.5): in order, it is
        /// appended and acknowledged when the window is full or the last one
        /// arrived (and then the whole request is served); out of order or
        /// duplicate, it is answered with a negative `SegmentACK` naming the
        /// last in-order segment, which makes the sender go back to the one
        /// after it.
        fn handleRequestSegment(self: *Self, origin: BipAddress, r: apdu.ConfirmedRequest, now_ms: u64) Error!Event {
            const buf = self.config.reassembly.?;
            const seg = r.segment.?;
            const rs = &self.rx_seg;
            const mine = rs.active and rs.invoke_id == r.invoke_id and rs.peer.eql(origin);
            if (!mine) {
                if (seg.sequence_number != 0) {
                    // The middle of something never started (or given up).
                    try self.sendApdu(origin, .{ .abort = .{ .server = true, .invoke_id = r.invoke_id, .reason = .invalid_apdu_in_this_state } });
                    return .unhandled;
                }
                if (rs.active) {
                    try self.sendApdu(origin, .{ .abort = .{ .server = true, .invoke_id = r.invoke_id, .reason = .out_of_resources } });
                    return .{ .refused = .{ .class = .resources, .code = .abort_other } };
                }
                rs.* = .{
                    .active = true,
                    .invoke_id = r.invoke_id,
                    .peer = origin,
                    .svc = r.service,
                    .window = @max(1, @min(seg.window_size, self.config.segment_window)),
                    .last_ms = now_ms,
                };
            }
            if (seg.sequence_number != rs.expected or r.service != rs.svc) {
                try self.sendRequestSegmentAck(origin, r.invoke_id, true, rs.expected -% 1, rs.window);
                return .none;
            }
            if (r.data.len > buf.len - rs.len) {
                rs.active = false;
                try self.sendApdu(origin, .{ .abort = .{ .server = true, .invoke_id = r.invoke_id, .reason = .buffer_overflow } });
                return .{ .refused = .{ .class = .services, .code = .abort_buffer_overflow } };
            }
            @memcpy(buf[rs.len..][0..r.data.len], r.data);
            rs.len += r.data.len;
            rs.expected +%= 1;
            rs.since_ack += 1;
            rs.last_ms = now_ms;
            if (!seg.more_follows) {
                try self.sendRequestSegmentAck(origin, r.invoke_id, false, seg.sequence_number, rs.window);
                rs.active = false;
                var whole = r;
                whole.segment = null;
                whole.data = buf[0..rs.len];
                return self.serveConfirmed(origin, whole, now_ms);
            }
            if (rs.since_ack >= rs.window) {
                try self.sendRequestSegmentAck(origin, r.invoke_id, false, seg.sequence_number, rs.window);
                rs.since_ack = 0;
            }
            return .none;
        }

        fn sendRequestSegmentAck(self: *Self, to: BipAddress, invoke_id: u8, negative: bool, seq: u8, window: u8) Error!void {
            try self.sendApdu(to, .{ .segment_ack = .{
                .negative = negative,
                .server = true,
                .invoke_id = invoke_id,
                .sequence_number = seq,
                .actual_window_size = window,
            } });
        }

        // ── alarms and events (clause 13) ──────────────────────────────────

        /// One round of intrinsic reporting: every object with
        /// `Property.event` is tested against its limits; the first one whose
        /// condition has held for its delay makes the transition.
        fn evaluateEvents(self: *Self, now_ms: u64) Error!?Event {
            for (self.objects) |*obj| {
                const esp = obj.find(.event_state) orelse continue;
                const ed = esp.event orelse continue;
                const pv = realOf(obj.find(.present_value)) orelse continue;
                const hi = realOf(obj.find(.high_limit)) orelse continue;
                const lo = realOf(obj.find(.low_limit)) orelse continue;
                const db = realOf(obj.find(.deadband)) orelse 0;
                const lim = bitsOf(obj.find(.limit_enable)) orelse continue;
                const lo_en = lim.get(.to_offnormal); // bit 0: low limit enable
                const hi_en = lim.get(.to_fault); // bit 1: high limit enable
                const want: ?types.EventState = switch (ed.state) {
                    .normal => if (hi_en and pv > hi) .high_limit else if (lo_en and pv < lo) .low_limit else null,
                    .high_limit => if (lo_en and pv < lo) .low_limit else if (!hi_en or pv < hi - db) .normal else null,
                    .low_limit => if (hi_en and pv > hi) .high_limit else if (!lo_en or pv > lo + db) .normal else null,
                    else => null,
                };
                const to = want orelse {
                    ed.pending = null;
                    continue;
                };
                if (ed.pending != to) {
                    ed.pending = to;
                    ed.pending_since_ms = now_ms;
                }
                const delay_s: u32 = if (to == .normal)
                    unsignedOf(obj.find(.time_delay_normal)) orelse unsignedOf(obj.find(.time_delay)) orelse 0
                else
                    unsignedOf(obj.find(.time_delay)) orelse 0;
                if (now_ms -| ed.pending_since_ms < @as(u64, delay_s) * 1000) continue;

                const from = ed.state;
                ed.state = to;
                ed.pending = null;
                self.event_seq +%= 1;
                const tr = events.Transition.into(to);
                const stamp: events.TimeStamp = .{ .sequence_number = self.event_seq };
                ed.stamps[@backingInt(tr)] = stamp;
                ed.stamp_states[@backingInt(tr)] = to;
                const enabled = (bitsOf(obj.find(.event_enable)) orelse events.TransitionBits.all).get(tr);
                const cls = self.classOf(obj);
                const needs_ack = if (cls) |c| (bitsOf(c.find(.ack_required)) orelse events.TransitionBits{}).get(tr) else false;
                ed.acked.set(tr, !(enabled and needs_ack));
                ed.sync(obj.properties);
                if (enabled and self.comm == .enable) {
                    const exceeded: f32 = if (to == .high_limit or (to == .normal and from == .high_limit)) hi else lo;
                    var sf: types.StatusFlags = .{};
                    if (obj.find(.status_flags)) |p| {
                        if (p.value == .bit_string and p.value.bit_string.bytes.len > 0)
                            sf = types.StatusFlags.fromOctet(p.value.bit_string.bytes[0]);
                    }
                    sf.in_alarm = to != .normal;
                    var vbuf: [48]u8 = undefined;
                    var vw = tag.Writer.init(&vbuf);
                    try (events.OutOfRange{ .exceeding_value = pv, .status_flags = sf, .deadband = db, .exceeded_limit = exceeded }).encodeValues(&vw);
                    try self.distribute(obj, cls, tr, .{
                        .process_id = 0,
                        .initiating_device = self.deviceId(),
                        .event_object = obj.id,
                        .time_stamp = stamp,
                        .notification_class = unsignedOf(obj.find(.notification_class)) orelse 0,
                        .priority = classPriority(cls, tr),
                        .event_type = .out_of_range,
                        .notify_type = @fromBackingInt(enumOf(obj.find(.notify_type)) orelse 0),
                        .ack_required = needs_ack,
                        .from_state = from,
                        .to_state = to,
                        .values = vw.written()[1 .. vw.written().len - 1],
                    });
                }
                return .{ .event_transition = .{ .object = obj.id, .from = from, .to = to } };
            }
            return null;
        }

        /// The Notification Class object an event-initiating object names.
        fn classOf(self: *Self, obj: *Object) ?*Object {
            const n = unsignedOf(obj.find(.notification_class)) orelse return null;
            for (self.objects) |*o| {
                if (o.id.type == .notification_class and o.id.instance == n) return o;
            }
            return null;
        }

        /// Sends `base` to every recipient of the class whose `transitions`
        /// include `tr`. Only recipients given by **address** (network 0, a
        /// six-octet BACnet/IP address) are served: this device has no
        /// address binding to turn a device identifier into one. Valid days
        /// and times are not evaluated (no wall clock). A confirmed
        /// notification is sent once, not retried.
        fn distribute(self: *Self, obj: *Object, cls: ?*Object, tr: events.Transition, base: events.EventNotification) Error!void {
            _ = obj;
            const c = cls orelse return;
            const rl = c.find(.recipient_list) orelse return;
            if (rl.value != .raw) return;
            var r = tag.Reader.init(rl.value.raw);
            while (!r.atEnd()) {
                const d = parseDestination(&r) catch return;
                if (!d.transitions.get(tr)) continue;
                const to = d.address orelse continue;
                var n = base;
                n.process_id = d.process_id;
                var body: [192]u8 = undefined;
                var w = tag.Writer.init(&body);
                try n.encode(&w);
                if (d.confirmed) {
                    const id = self.next_invoke;
                    self.next_invoke +%= 1;
                    try self.sendApdu(to, .{ .confirmed_request = .{
                        .invoke_id = id,
                        .service = .confirmed_event_notification,
                        .max_apdu = self.config.max_apdu,
                        .data = w.written(),
                    } });
                } else {
                    try self.sendApdu(to, .{ .unconfirmed_request = .{
                        .service = .unconfirmed_event_notification,
                        .data = w.written(),
                    } });
                }
            }
        }

        fn handleAcknowledgeAlarm(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest) Error!Event {
            const ak = events.AcknowledgeAlarm.decode(r.data) catch {
                try self.sendApdu(to, .{ .reject = .{ .invoke_id = r.invoke_id, .reason = .invalid_tag } });
                return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
            };
            const obj = self.find(ak.event_object) orelse
                return self.refuse(to, r.invoke_id, .acknowledge_alarm, .object, .unknown_object);
            const ed = (obj.find(.event_state) orelse
                return self.refuse(to, r.invoke_id, .acknowledge_alarm, .object, .unknown_object)).event orelse
                return self.refuse(to, r.invoke_id, .acknowledge_alarm, .object, .unknown_object);
            const tr = events.Transition.into(ak.state);
            const ti = @backingInt(tr);
            if (ed.stamp_states[ti] != ak.state)
                return self.refuse(to, r.invoke_id, .acknowledge_alarm, .services, .invalid_event_state);
            if (!ak.time_stamp.eql(ed.stamps[ti]))
                return self.refuse(to, r.invoke_id, .acknowledge_alarm, .services, .invalid_time_stamp);
            try self.sendApdu(to, .{ .simple_ack = .{ .invoke_id = r.invoke_id, .service = .acknowledge_alarm } });
            // Acknowledging what is already acknowledged succeeds and says
            // nothing more.
            if (ed.acked.get(tr)) return .{ .alarm_acknowledged = .{ .object = obj.id, .state = ak.state } };
            ed.acked.set(tr, true);
            ed.sync(obj.properties);
            if (self.comm == .enable) {
                const cls = self.classOf(obj);
                try self.distribute(obj, cls, tr, .{
                    .process_id = 0,
                    .initiating_device = self.deviceId(),
                    .event_object = obj.id,
                    .time_stamp = ak.time_of_ack,
                    .notification_class = unsignedOf(obj.find(.notification_class)) orelse 0,
                    .priority = classPriority(cls, tr),
                    .event_type = .out_of_range,
                    .notify_type = .ack_notification,
                    .to_state = ak.state,
                });
            }
            return .{ .alarm_acknowledged = .{ .object = obj.id, .state = ak.state } };
        }

        /// The room a GetEventInformation / GetAlarmSummary answer may use.
        fn answerRoom(self: *Self, r: apdu.ConfirmedRequest) usize {
            const mine = self.config.max_apdu.octets() catch 1476;
            const theirs = r.max_apdu.octets() catch 50;
            // 3 octets of ComplexACK header, 3 of trailer (`moreEvents`).
            return @min(mine, theirs) - 6;
        }

        fn handleGetEventInformation(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest) Error!Event {
            const req = events.GetEventInformation.decode(r.data) catch {
                try self.sendApdu(to, .{ .reject = .{ .invoke_id = r.invoke_id, .reason = .invalid_tag } });
                return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
            };
            var skipping = req.last_received != null;
            if (req.last_received) |last| {
                if (self.find(last) == null)
                    return self.refuse(to, r.invoke_id, .get_event_information, .object, .unknown_object);
            }
            const room = self.answerRoom(r);
            var list: [transport.max_datagram]u8 = undefined;
            var lw = tag.Writer.init(list[0..@min(room, list.len)]);
            var more = false;
            for (self.objects) |*obj| {
                if (skipping) {
                    if (obj.id.eql(req.last_received.?)) skipping = false;
                    continue;
                }
                const ed = (obj.find(.event_state) orelse continue).event orelse continue;
                if (ed.state == .normal and ed.acked.bits == 0b111) continue;
                const cls = self.classOf(obj);
                var one: [96]u8 = undefined;
                var ow = tag.Writer.init(&one);
                try (events.EventSummary{
                    .object = obj.id,
                    .state = ed.state,
                    .acked_transitions = ed.acked,
                    .time_stamps = ed.stamps,
                    .notify_type = @fromBackingInt(enumOf(obj.find(.notify_type)) orelse 0),
                    .event_enable = bitsOf(obj.find(.event_enable)) orelse events.TransitionBits.all,
                    .priorities = .{ classPriority(cls, .to_offnormal), classPriority(cls, .to_fault), classPriority(cls, .to_normal) },
                }).encode(&ow);
                lw.raw(ow.written()) catch {
                    more = true;
                    break;
                };
            }
            var body: [transport.max_datagram]u8 = undefined;
            var w = tag.Writer.init(&body);
            try events.GetEventInformationAck.encode(lw.written(), more, &w);
            try self.sendApdu(to, .{ .complex_ack = .{
                .invoke_id = r.invoke_id,
                .service = .get_event_information,
                .data = w.written(),
            } });
            return .{ .read = .{ .object = self.deviceId(), .property = .event_state } };
        }

        fn handleGetAlarmSummary(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest) Error!Event {
            if (r.data.len != 0) {
                try self.sendApdu(to, .{ .reject = .{ .invoke_id = r.invoke_id, .reason = .too_many_arguments } });
                return .{ .refused = .{ .class = .services, .code = .reject_too_many_arguments } };
            }
            var body: [transport.max_datagram]u8 = undefined;
            const room = @min(self.answerRoom(r), body.len);
            var w = tag.Writer.init(body[0..room]);
            for (self.objects) |*obj| {
                const ed = (obj.find(.event_state) orelse continue).event orelse continue;
                if (ed.state == .normal) continue;
                if (enumOf(obj.find(.notify_type)) orelse 0 != @backingInt(events.NotifyType.alarm)) continue;
                (events.AlarmSummary{ .object = obj.id, .state = ed.state, .acked_transitions = ed.acked }).encode(&w) catch
                    return self.abortOverflow(to, r.invoke_id);
            }
            try self.sendApdu(to, .{ .complex_ack = .{
                .invoke_id = r.invoke_id,
                .service = .get_alarm_summary,
                .data = w.written(),
            } });
            return .{ .read = .{ .object = self.deviceId(), .property = .event_state } };
        }

        fn handleWhoHas(
            self: *Self,
            data: []const u8,
            origin: BipAddress,
            arrived_as: bvll.Function,
        ) Error!Event {
            const wh = try service.WhoHas.decode(data);
            if (wh.low) |lo| {
                const hi = wh.high orelse service.max_instance;
                if (self.config.instance < lo or self.config.instance > hi) return .none;
            }
            const obj: *Object = switch (wh.target) {
                .object_id => |oid| self.find(oid) orelse return .none,
                .object_name => |name| blk: {
                    for (self.objects) |*o| {
                        const p = o.find(.object_name) orelse continue;
                        switch (p.value) {
                            .string => |s| if (std.mem.eql(u8, s, name)) break :blk o,
                            else => {},
                        }
                    }
                    return .none;
                },
            };
            const name_prop = obj.find(.object_name);
            const name: []const u8 = if (name_prop) |p| switch (p.value) {
                .string => |s| s,
                else => "",
            } else "";

            var body: [128]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.IHave{
                .device = self.deviceId(),
                .object = obj.id,
                .object_name = name,
            }).encode(&w);
            var a_buf: [160]u8 = undefined;
            const a = try apdu.encode(.{ .unconfirmed_request = .{
                .service = .i_have,
                .data = w.written(),
            } }, &a_buf);
            var n_buf: [192]u8 = undefined;
            // Same rule as I-Am: answer the way the question arrived.
            if (arrived_as == .original_unicast_npdu) {
                const n = try npdu.encode(.{}, a, &n_buf);
                const d = try bvll.wrap(.original_unicast_npdu, n, &self.tx);
                try self.tp.send(origin, d);
                return .answered_who_has;
            }
            const n = try npdu.encode(
                .{ .destination = npdu.NetAddress.global, .hop_count = 255 },
                a,
                &n_buf,
            );
            const d = try bvll.wrap(.original_broadcast_npdu, n, &self.tx);
            try self.tp.broadcast(d);
            return .answered_who_has;
        }

        fn handleReadProperty(
            self: *Self,
            to: BipAddress,
            r: apdu.ConfirmedRequest,
            now_ms: u64,
        ) Error!Event {
            const rp = service.ReadProperty.decode(r.data) catch {
                try self.sendApdu(to, .{ .reject = .{
                    .invoke_id = r.invoke_id,
                    .reason = .invalid_tag,
                } });
                return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
            };
            const obj = self.find(rp.object) orelse
                return self.refuse(to, r.invoke_id, .read_property, .object, .unknown_object);
            const p = obj.find(rp.property) orelse
                return self.refuse(to, r.invoke_id, .read_property, .property, .unknown_property);
            // An array index on a property this device stores as a scalar is
            // an error, not something to ignore.
            if (rp.array_index != null and p.value != .raw and p.value != .priority_array) {
                return self.refuse(to, r.invoke_id, .read_property, .property, .property_is_not_an_array);
            }

            var body: [max_segmented_reply]u8 = undefined;
            var w = tag.Writer.init(if (self.config.segmented_responses) &body else body[0..transport.max_datagram]);
            var vbuf: [4096]u8 = undefined;
            var vw = tag.Writer.init(if (self.config.segmented_responses) &vbuf else vbuf[0..512]);
            if (rp.array_index != null and p.value == .priority_array) {
                // Index 0 is the array's size, 1..16 one slot.
                const ix = rp.array_index.?;
                const slots = p.value.priority_array;
                if (ix == 0) {
                    try vw.appUnsigned(16);
                } else if (ix <= 16) {
                    if (slots[ix - 1]) |v| try v.encode(&vw) else try vw.appNull();
                } else {
                    return self.refuse(to, r.invoke_id, .read_property, .property, .invalid_array_index);
                }
            } else {
                try p.value.encode(&vw);
            }
            (service.ReadPropertyAck{
                .object = rp.object,
                .property = rp.property,
                .array_index = rp.array_index,
                .value = vw.written(),
            }).encode(&w) catch
                return self.abortOverflow(to, r.invoke_id);

            if (try self.replyComplex(to, r, .read_property, w.written(), now_ms)) |ev| return ev;
            return .{ .read = .{ .object = rp.object, .property = rp.property } };
        }

        fn handleRpm(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest, now_ms: u64) Error!Event {
            var body: [max_segmented_reply]u8 = undefined;
            var w = tag.Writer.init(if (self.config.segmented_responses) &body else body[0..transport.max_datagram]);
            var b = service.RpmAckBuilder.init(&w);

            var it = service.RpmRequestIterator.init(r.data);
            var last: ObjectId = self.deviceId();
            var any = false;
            while (true) {
                const spec = (it.next() catch {
                    try self.sendApdu(to, .{ .reject = .{
                        .invoke_id = r.invoke_id,
                        .reason = .invalid_tag,
                    } });
                    return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
                }) orelse break;
                any = true;
                last = spec.object;
                b.object(spec.object) catch return self.abortOverflow(to, r.invoke_id);
                const obj = self.find(spec.object);

                var props = spec.properties();
                while (try props.next()) |ref| {
                    const o = obj orelse {
                        b.accessError(ref.property, ref.array_index, .object, .unknown_object) catch
                            return self.abortOverflow(to, r.invoke_id);
                        continue;
                    };
                    if (ref.property.isSpecial()) {
                        // ALL / REQUIRED / OPTIONAL expand to a group of the
                        // object's own properties. This is the whole reason
                        // the wildcards exist, and a device that answers them
                        // with `unknown_property` is a common interop bug.
                        for (o.properties) |*prop| {
                            const wanted = switch (ref.property) {
                                .all => true,
                                .required => prop.required,
                                .optional => !prop.required,
                                else => unreachable,
                            };
                            if (!wanted) continue;
                            self.emitValue(&b, prop) catch
                                return self.abortOverflow(to, r.invoke_id);
                        }
                        continue;
                    }
                    const prop = o.find(ref.property) orelse {
                        b.accessError(ref.property, ref.array_index, .property, .unknown_property) catch
                            return self.abortOverflow(to, r.invoke_id);
                        continue;
                    };
                    self.emitValue(&b, prop) catch return self.abortOverflow(to, r.invoke_id);
                }
            }
            if (!any) {
                try self.sendApdu(to, .{ .reject = .{
                    .invoke_id = r.invoke_id,
                    .reason = .missing_required_parameter,
                } });
                return .{ .refused = .{
                    .class = .services,
                    .code = .reject_missing_required_parameter,
                } };
            }
            b.finish() catch return self.abortOverflow(to, r.invoke_id);

            if (self.replyComplex(to, r, .read_property_multiple, w.written(), now_ms) catch
                return self.abortOverflow(to, r.invoke_id)) |ev| return ev;
            return .{ .read = .{ .object = last, .property = .all } };
        }

        fn emitValue(self: *Self, b: *service.RpmAckBuilder, prop: *const Property) Error!void {
            var vbuf: [4096]u8 = undefined;
            var vw = tag.Writer.init(if (self.config.segmented_responses) &vbuf else vbuf[0..512]);
            try prop.value.encode(&vw);
            try b.value(prop.id, null, vw.written());
        }

        fn handleWriteProperty(
            self: *Self,
            to: BipAddress,
            r: apdu.ConfirmedRequest,
        ) Error!Event {
            const wp = service.WriteProperty.decode(r.data) catch {
                try self.sendApdu(to, .{ .reject = .{
                    .invoke_id = r.invoke_id,
                    .reason = .invalid_tag,
                } });
                return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
            };
            const target = switch (self.checkWrite(wp.object, wp.property, wp.value, wp.isRelinquish(), wp.priority)) {
                .ok => |t| t,
                .refused => |e| return self.refuse(to, r.invoke_id, .write_property, e.class, e.code),
            };
            applyWrite(target, wp.priority);
            try self.sendApdu(to, .{ .simple_ack = .{
                .invoke_id = r.invoke_id,
                .service = .write_property,
            } });
            return .{ .wrote = .{ .object = wp.object, .property = wp.property } };
        }

        const WriteCheck = union(enum) {
            ok: struct { obj: *Object, prop: *Property, value: Value },
            refused: struct { class: types.ErrorClass, code: types.ErrorCode },
        };

        /// What clause 15.9.2 / 15.10.2 require of one write before it is
        /// applied: the object and property exist, the property is writable,
        /// a relinquish has something to hand back to, the datum has the
        /// property's type.
        fn checkWrite(self: *Self, oid: ObjectId, property: PropertyIdentifier, value: []const u8, relinquish: bool, priority: ?u8) WriteCheck {
            const obj = self.find(oid) orelse
                return .{ .refused = .{ .class = .object, .code = .unknown_object } };
            const p = obj.find(property) orelse
                return .{ .refused = .{ .class = .property, .code = .unknown_property } };
            if (!p.writable)
                return .{ .refused = .{ .class = .property, .code = .write_access_denied } };
            if (p.priority_slots != null) {
                // Commandable: a relinquish is a Null, whatever the kind of the
                // property; priority 6 belongs to the minimum on/off algorithm.
                if (priority != null and priority.? == 6)
                    return .{ .refused = .{ .class = .property, .code = .write_access_denied } };
                if (relinquish) return .{ .ok = .{ .obj = obj, .prop = p, .value = .null } };
                const cv = Value.parse(value) orelse
                    return .{ .refused = .{ .class = .property, .code = .invalid_data_type } };
                if (!Value.sameKind(cv, p.value))
                    return .{ .refused = .{ .class = .property, .code = .invalid_data_type } };
                return .{ .ok = .{ .obj = obj, .prop = p, .value = cv } };
            }
            // Relinquishing is not "write null": it hands the slot back, and a
            // property with no priority array has nothing to hand back to.
            if (relinquish and p.value != .null)
                return .{ .refused = .{ .class = .property, .code = .optional_functionality_not_supported } };
            const parsed = Value.parse(value) orelse
                return .{ .refused = .{ .class = .property, .code = .invalid_data_type } };
            if (!Value.sameKind(parsed, p.value))
                return .{ .refused = .{ .class = .property, .code = .invalid_data_type } };
            return .{ .ok = .{ .obj = obj, .prop = p, .value = parsed } };
        }

        /// Stores a checked write: a plain property takes the value, a
        /// commandable one fills or empties the slot at `priority` (16 when
        /// none) and takes the highest-priority command, else the
        /// `relinquish_default`.
        fn applyWrite(t: anytype, priority: ?u8) void {
            const slots = t.prop.priority_slots orelse {
                t.prop.value = t.value;
                return;
            };
            const ix: usize = (priority orelse 16) - 1;
            slots[ix] = if (t.value == .null) null else t.value;
            for (slots) |slot| {
                if (slot) |v| {
                    t.prop.value = v;
                    return;
                }
            }
            if (t.obj.find(.relinquish_default)) |d| t.prop.value = d.value;
        }

        /// `WritePropertyMultiple` (clause 15.10): the writes are applied in
        /// order and the first that fails ends the request, earlier ones
        /// stay applied. A request that cannot be decoded at all is rejected;
        /// one that breaks after a write was applied is an Error whose first
        /// failed attempt names object instance 4194303 (addendum 135-2016bl).
        /// Sends a ComplexACK. When the device may segment and the reply is
        /// larger than the requester's max APDU, it is sent as segments
        /// instead (null is returned when it went out whole).
        fn replyComplex(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest, svc: types.ConfirmedService, data: []const u8, now_ms: u64) Error!?Event {
            if (self.config.segmented_responses) {
                const mine = self.config.max_apdu.octets() catch 1476;
                const theirs = r.max_apdu.octets() catch 50;
                const limit = @min(mine, theirs);
                if (3 + data.len > limit) return try self.startSegments(to, r, svc, data, limit, now_ms);
            }
            try self.sendApdu(to, .{ .complex_ack = .{ .invoke_id = r.invoke_id, .service = svc, .data = data } });
            return null;
        }

        fn startSegments(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest, svc: types.ConfirmedService, data: []const u8, limit: usize, now_ms: u64) Error!?Event {
            if (!r.segmented_response_accepted) {
                try self.sendApdu(to, apdu.segmentationNotSupported(r.invoke_id, true));
                return .{ .refused = .{ .class = .services, .code = .abort_segmentation_not_supported } };
            }
            const seg_size = limit - 5;
            const total = (data.len + seg_size - 1) / seg_size;
            const accepted: usize = switch (r.max_segments) {
                .unspecified => 255,
                .two => 2,
                .four => 4,
                .eight => 8,
                .sixteen => 16,
                .thirty_two => 32,
                .sixty_four => 64,
                .more_than_64 => 255,
            };
            if (data.len > max_segmented_reply or total > 255 or total > accepted) {
                try self.sendApdu(to, .{ .abort = .{ .server = true, .invoke_id = r.invoke_id, .reason = .apdu_too_long } });
                return .{ .refused = .{ .class = .services, .code = .abort_buffer_overflow } };
            }
            if (self.seg.active) {
                try self.sendApdu(to, .{ .abort = .{ .server = true, .invoke_id = r.invoke_id, .reason = .out_of_resources } });
                return .{ .refused = .{ .class = .resources, .code = .abort_other } };
            }
            const sg = &self.seg;
            @memcpy(sg.data[0..data.len], data);
            sg.active = true;
            sg.peer = to;
            sg.invoke_id = r.invoke_id;
            sg.svc = svc;
            sg.len = data.len;
            sg.seg_size = seg_size;
            sg.total = @intCast(total);
            sg.next = 0;
            sg.base = 0;
            sg.window = @max(1, self.config.segment_window);
            sg.retries_left = self.config.segment_retries;
            try self.sendWindow(now_ms);
            return .{ .read = .{ .object = self.deviceId(), .property = .all } };
        }

        /// Sends the segments from `next` up to the end of the window.
        fn sendWindow(self: *Self, now_ms: u64) Error!void {
            const sg = &self.seg;
            while (sg.next < sg.total and sg.next < sg.base + sg.window) : (sg.next += 1) {
                const off = @as(usize, sg.next) * sg.seg_size;
                const chunk = sg.data[off..@min(off + sg.seg_size, sg.len)];
                try self.sendApdu(sg.peer, .{ .complex_ack = .{
                    .invoke_id = sg.invoke_id,
                    .service = sg.svc,
                    .segment = .{
                        .sequence_number = @truncate(sg.next),
                        .window_size = sg.window,
                        .more_follows = sg.next + 1 < sg.total,
                    },
                    .data = chunk,
                } });
            }
            sg.deadline_ms = now_ms + self.config.segment_timeout_ms;
        }

        /// A `SegmentACK` from the requester (clause 5.4.4): a positive one
        /// opens the next window, a negative one makes the sender go back to
        /// the segment after the one it names.
        fn handleSegmentAck(self: *Self, from: BipAddress, sa: apdu.SegmentAck, now_ms: u64) Error!Event {
            const sg = &self.seg;
            if (!sg.active or sa.server or sa.invoke_id != sg.invoke_id or !from.eql(sg.peer)) return .none;
            sg.base = @as(u16, sa.sequence_number) + 1;
            if (sa.negative) sg.next = sg.base;
            if (sg.base >= sg.total) {
                sg.active = false;
                return .{ .segmented_reply_sent = .{ .invoke_id = sa.invoke_id, .segments = sg.total } };
            }
            sg.window = @max(1, @min(sa.actual_window_size, self.config.segment_window));
            sg.retries_left = self.config.segment_retries;
            try self.sendWindow(now_ms);
            return .none;
        }

        /// The window was not acknowledged in time: send it again, or give
        /// the transfer up after the configured retries.
        fn segmentTimer(self: *Self, now_ms: u64) Error!void {
            const sg = &self.seg;
            if (!sg.active or now_ms < sg.deadline_ms) return;
            if (sg.retries_left == 0) {
                sg.active = false;
                try self.sendApdu(sg.peer, .{ .abort = .{ .server = true, .invoke_id = sg.invoke_id, .reason = .tsm_timeout } });
                return;
            }
            sg.retries_left -= 1;
            sg.next = sg.base;
            try self.sendWindow(now_ms);
        }

        fn handleWpm(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest) Error!Event {
            var it = service.WpmRequestIterator.init(r.data);
            var done: usize = 0;
            while (true) {
                const spec = (it.next() catch return self.wpmDecodeFailure(to, r.invoke_id, done)) orelse break;
                var wi = spec.writes();
                while (true) {
                    const pw = (wi.next() catch return self.wpmDecodeFailure(to, r.invoke_id, done)) orelse break;
                    switch (self.checkWrite(spec.object, pw.property, pw.value, pw.isRelinquish(), pw.priority)) {
                        .ok => |t| {
                            applyWrite(t, pw.priority);
                            done += 1;
                        },
                        .refused => |e| return self.wpmFailure(to, r.invoke_id, e.class, e.code, spec.object, pw.property, pw.array_index),
                    }
                }
            }
            if (done == 0) return self.wpmDecodeFailure(to, r.invoke_id, 0);
            try self.sendApdu(to, .{ .simple_ack = .{
                .invoke_id = r.invoke_id,
                .service = .write_property_multiple,
            } });
            return .{ .wrote_multiple = .{ .count = done } };
        }

        fn wpmDecodeFailure(self: *Self, to: BipAddress, invoke_id: u8, done: usize) Error!Event {
            if (done == 0) {
                try self.sendApdu(to, .{ .reject = .{ .invoke_id = invoke_id, .reason = .invalid_tag } });
                return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
            }
            return self.wpmFailure(
                to,
                invoke_id,
                .services,
                .invalid_tag,
                .{ .type = .device, .instance = service.max_instance },
                .object_identifier,
                null,
            );
        }

        fn wpmFailure(
            self: *Self,
            to: BipAddress,
            invoke_id: u8,
            class: types.ErrorClass,
            code: types.ErrorCode,
            object: ObjectId,
            property: PropertyIdentifier,
            array_index: ?u32,
        ) Error!Event {
            var xbuf: [32]u8 = undefined;
            var xw = tag.Writer.init(&xbuf);
            try service.encodeFirstFailedWrite(&xw, object, property, array_index);
            try self.sendApdu(to, .{ .err = .{
                .invoke_id = invoke_id,
                .service = .write_property_multiple,
                .class = class,
                .code = code,
                .extra = xw.written(),
            } });
            return .{ .refused = .{ .class = class, .code = code } };
        }

        fn passwordOk(self: *const Self, given: ?[]const u8) bool {
            const want = self.config.password orelse return true;
            const got = given orelse return false;
            return std.mem.eql(u8, want, got);
        }

        /// `DeviceCommunicationControl` (clause 16.1).
        fn handleDcc(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest, now_ms: u64) Error!Event {
            const req = service.DeviceCommunicationControl.decode(r.data) catch |e| {
                const reason: types.RejectReason = switch (e) {
                    error.InvalidValue, error.InvalidParameter => .parameter_out_of_range,
                    error.MissingParameter => .missing_required_parameter,
                    else => .invalid_tag,
                };
                try self.sendApdu(to, .{ .reject = .{ .invoke_id = r.invoke_id, .reason = reason } });
                return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
            };
            if (!self.passwordOk(req.password))
                return self.refuse(to, r.invoke_id, .device_communication_control, .security, .password_failure);
            self.comm = req.state;
            self.comm_until_ms = if (req.state == .enable) null else if (req.duration_minutes) |m|
                now_ms + @as(u64, m) * 60_000
            else
                null;
            try self.sendApdu(to, .{ .simple_ack = .{
                .invoke_id = r.invoke_id,
                .service = .device_communication_control,
            } });
            return .{ .communication_control = .{ .state = req.state, .duration_minutes = req.duration_minutes } };
        }

        /// `ReinitializeDevice` (clause 16.4). The device only acknowledges:
        /// restarting is the application's business (`Event.reinitialize`).
        /// The backup and restore procedures are not implemented.
        fn handleReinitialize(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest) Error!Event {
            const req = service.ReinitializeDevice.decode(r.data) catch |e| {
                const reason: types.RejectReason = switch (e) {
                    error.InvalidValue, error.InvalidParameter => .parameter_out_of_range,
                    error.MissingParameter => .missing_required_parameter,
                    else => .invalid_tag,
                };
                try self.sendApdu(to, .{ .reject = .{ .invoke_id = r.invoke_id, .reason = reason } });
                return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
            };
            if (!self.passwordOk(req.password))
                return self.refuse(to, r.invoke_id, .reinitialize_device, .security, .password_failure);
            switch (req.state) {
                .coldstart, .warmstart, .activate_changes => {},
                else => return self.refuse(to, r.invoke_id, .reinitialize_device, .services, .optional_functionality_not_supported),
            }
            try self.sendApdu(to, .{ .simple_ack = .{
                .invoke_id = r.invoke_id,
                .service = .reinitialize_device,
            } });
            return .{ .reinitialize = .{ .state = req.state } };
        }

        fn handleSubscribeCov(
            self: *Self,
            to: BipAddress,
            r: apdu.ConfirmedRequest,
            now_ms: u64,
        ) Error!Event {
            const sub = service.SubscribeCov.decode(r.data) catch {
                try self.sendApdu(to, .{ .reject = .{
                    .invoke_id = r.invoke_id,
                    .reason = .invalid_tag,
                } });
                return .{ .refused = .{ .class = .services, .code = .reject_invalid_tag } };
            };
            const obj = self.find(sub.object) orelse
                return self.refuse(to, r.invoke_id, .subscribe_cov, .object, .unknown_object);

            if (sub.isCancellation()) {
                for (&self.subs) |*s| {
                    if (s.active and s.process_id == sub.process_id and
                        s.object.eql(sub.object) and s.subscriber.eql(to))
                    {
                        s.active = false;
                    }
                }
                // Cancelling a subscription that does not exist succeeds:
                // clause 13.14.2 says so, and it makes a restarted client's
                // cleanup idempotent.
                try self.sendApdu(to, .{ .simple_ack = .{
                    .invoke_id = r.invoke_id,
                    .service = .subscribe_cov,
                } });
                return .{ .subscribed = .{ .object = sub.object, .cancelled = true } };
            }

            var slot: ?*Subscription = null;
            for (&self.subs) |*s| {
                if (s.active and s.process_id == sub.process_id and
                    s.object.eql(sub.object) and s.subscriber.eql(to))
                {
                    slot = s; // renewal of an existing subscription
                    break;
                }
            }
            if (slot == null) {
                for (&self.subs) |*s| {
                    if (!s.active) {
                        slot = s;
                        break;
                    }
                }
            }
            const s = slot orelse return self.refuse(
                to,
                r.invoke_id,
                .subscribe_cov,
                .resources,
                .no_space_to_add_list_element,
            );

            var lifetime = sub.lifetime.?;
            if (self.config.max_cov_lifetime_s != 0) {
                if (lifetime == 0 or lifetime > self.config.max_cov_lifetime_s) {
                    lifetime = self.config.max_cov_lifetime_s;
                }
            }
            s.* = .{
                .active = true,
                .subscriber = to,
                .process_id = sub.process_id,
                .object = sub.object,
                .confirmed = sub.confirmed.?,
                .expires_ms = if (lifetime == 0) null else now_ms + @as(u64, lifetime) * 1000,
            };

            try self.sendApdu(to, .{ .simple_ack = .{
                .invoke_id = r.invoke_id,
                .service = .subscribe_cov,
            } });
            // Clause 13.14.2: a successful subscription is immediately
            // followed by a notification carrying the current value, so the
            // subscriber never has to poll once for the initial state.
            try self.notifyOne(s, obj, now_ms);
            return .{ .subscribed = .{ .object = sub.object, .cancelled = false } };
        }

        fn expireSubscriptions(self: *Self, now_ms: u64) void {
            for (&self.subs) |*s| {
                if (!s.active) continue;
                const exp = s.expires_ms orelse continue;
                if (now_ms >= exp) s.active = false;
            }
        }

        /// `COV_Increment` (clause 13.1.2): a `present_value` that is a Real
        /// notifies only when it moved by at least the object's
        /// `cov_increment` property (a Real) since the last value notified;
        /// anything else, and an object without the property, always
        /// notifies.
        fn covDue(self: *Self, obj: *Object, p: *Property) bool {
            _ = self;
            if (p.id != .present_value or p.value != .real) return true;
            const inc_prop = obj.find(.cov_increment) orelse return true;
            if (inc_prop.value != .real) return true;
            const now = p.value.real;
            if (p.cov_last) |last| {
                if (@abs(now - last) < inc_prop.value.real) return false;
            }
            p.cov_last = now;
            return true;
        }

        fn notifyCov(self: *Self, obj: *Object, now_ms: u64) Error!void {
            // A notification is an initiated message (clause 16.1.3).
            if (self.comm != .enable) return;
            for (&self.subs) |*s| {
                if (!s.active or !s.object.eql(obj.id)) continue;
                try self.notifyOne(s, obj, now_ms);
            }
        }

        fn notifyOne(self: *Self, s: *Subscription, obj: *Object, now_ms: u64) Error!void {
            var vbuf: [512]u8 = undefined;
            var vw = tag.Writer.init(&vbuf);
            for (obj.properties) |*p| {
                if (!p.cov_reported) continue;
                var inner: [256]u8 = undefined;
                var iw = tag.Writer.init(&inner);
                try p.value.encode(&iw);
                try service.writeCovValue(&vw, .{ .property = p.id, .value = iw.written() });
            }

            const remaining: u32 = blk: {
                const exp = s.expires_ms orelse break :blk 0;
                if (exp <= now_ms) break :blk 0;
                break :blk @intCast((exp - now_ms) / 1000);
            };

            var body: [transport.max_datagram]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.CovNotification{
                .process_id = s.process_id,
                .initiating_device = self.deviceId(),
                .monitored_object = obj.id,
                .time_remaining = remaining,
                .values_block = vw.written(),
            }).encode(&w);

            if (s.confirmed) {
                const id = self.next_invoke;
                self.next_invoke +%= 1;
                s.outstanding = id;
                try self.sendApdu(s.subscriber, .{ .confirmed_request = .{
                    .invoke_id = id,
                    .service = .confirmed_cov_notification,
                    .max_apdu = self.config.max_apdu,
                    .data = w.written(),
                } });
            } else {
                try self.sendApdu(s.subscriber, .{ .unconfirmed_request = .{
                    .service = .unconfirmed_cov_notification,
                    .data = w.written(),
                } });
            }
        }

        fn refuse(
            self: *Self,
            to: BipAddress,
            invoke_id: u8,
            svc: types.ConfirmedService,
            class: types.ErrorClass,
            code: types.ErrorCode,
        ) Error!Event {
            try self.sendApdu(to, .{ .err = .{
                .invoke_id = invoke_id,
                .service = svc,
                .class = class,
                .code = code,
            } });
            return .{ .refused = .{ .class = class, .code = code } };
        }

        /// The answer a non-segmenting device owes when its reply does not fit
        /// (clause 5.4): `Abort(buffer_overflow)`, not a truncated ACK.
        fn abortOverflow(self: *Self, to: BipAddress, invoke_id: u8) Error!Event {
            try self.sendApdu(to, .{ .abort = .{
                .server = true,
                .invoke_id = invoke_id,
                .reason = .buffer_overflow,
            } });
            return .{ .refused = .{ .class = .services, .code = .abort_buffer_overflow } };
        }

        fn sendApdu(self: *Self, to: BipAddress, a: apdu.Apdu) Error!void {
            var a_buf: [transport.max_datagram]u8 = undefined;
            const ab = try apdu.encode(a, &a_buf);
            var n_buf: [transport.max_datagram]u8 = undefined;
            const nb = try npdu.encode(.{}, ab, &n_buf);
            const d = try bvll.wrap(.original_unicast_npdu, nb, &self.tx);
            try self.tp.send(to, d);
        }
    };
}

/// The device size a normal caller wants.
pub const DefaultDevice = Device(16);

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const client = @import("client.zig");
const testkit = @import("testkit");
const hex = testkit.hex.literal;

const Rig = struct {
    net: transport.LoopNetwork = .{},
    client_ep: transport.LoopTransport = transport.LoopTransport.init(.{ .ip = .{ 192, 0, 2, 1 } }),
    device_ep: transport.LoopTransport = transport.LoopTransport.init(.{ .ip = .{ 192, 0, 2, 2 } }),

    fn wire(self: *Rig) void {
        self.net.attach(&self.client_ep);
        self.net.attach(&self.device_ep);
    }
};

/// A small but realistic object database: a device object, an analog input
/// (read-only sensor) and an analog value (writable setpoint).
fn makeObjects() struct { objects: [3]Object, props: struct {
    dev: [5]Property,
    ai: [5]Property,
    av: [4]Property,
} } {
    return .{
        .objects = undefined,
        .props = .{
            .dev = .{
                .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .device, .instance = 599 } } },
                .{ .id = .object_name, .value = .{ .string = "SIM-DEVICE" } },
                .{ .id = .object_type, .value = .{ .enumerated = 8 } },
                .{ .id = .vendor_identifier, .value = .{ .unsigned = 999 } },
                .{ .id = .description, .value = .{ .string = "simulated" }, .required = false },
            },
            .ai = .{
                .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .analog_input, .instance = 5 } } },
                .{ .id = .object_name, .value = .{ .string = "ZONE-TEMP" } },
                .{ .id = .present_value, .value = .{ .real = 72.5 }, .cov_reported = true },
                .{ .id = .status_flags, .value = .{ .bit_string = .{ .unused_bits = 4, .bytes = &.{0x00} } }, .cov_reported = true },
                .{ .id = .units, .value = .{ .enumerated = 64 }, .required = false },
            },
            .av = .{
                .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .analog_value, .instance = 1 } } },
                .{ .id = .object_name, .value = .{ .string = "SETPOINT" } },
                .{ .id = .present_value, .value = .{ .real = 21.0 }, .writable = true, .cov_reported = true },
                .{ .id = .out_of_service, .value = .{ .boolean = false }, .writable = true },
            },
        },
    };
}

const Db = struct {
    dev: [5]Property,
    ai: [5]Property,
    av: [4]Property,
    objects: [3]Object = undefined,

    fn init() Db {
        const m = makeObjects();
        return .{ .dev = m.props.dev, .ai = m.props.ai, .av = m.props.av };
    }

    fn wire(self: *Db) []Object {
        self.objects = .{
            .{ .id = .{ .type = .device, .instance = 599 }, .properties = &self.dev },
            .{ .id = .{ .type = .analog_input, .instance = 5 }, .properties = &self.ai },
            .{ .id = .{ .type = .analog_value, .instance = 1 }, .properties = &self.av },
        };
        return &self.objects;
    }
};

/// Runs both peers until neither makes progress.
fn settle(c: anytype, d: anytype, now: u64) !void {
    var idle: usize = 0;
    while (idle < 3) {
        var progress = false;
        if (try d.poll(now) != .none) progress = true;
        if (try c.poll(now) != .none) progress = true;
        idle = if (progress) 0 else idle + 1;
    }
}

test "discovery: our client finds our device" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{
        .instance = 599,
        .vendor_id = 999,
    }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    try c.whoIs(null, null);
    try testing.expectEqual(device_event_announced, try dev.poll(0));

    const ev = try c.poll(0);
    try testing.expectEqual(@as(u22, 599), ev.i_am.info.device.instance);
    try testing.expectEqual(@as(u32, 1476), ev.i_am.info.max_apdu_accepted);
    try testing.expectEqual(types.Segmentation.none, ev.i_am.info.segmentation);
    try testing.expectEqual(@as(u16, 999), ev.i_am.info.vendor_id);

    // A Who-Is outside our range gets no answer at all.
    try c.whoIs(1, 100);
    try testing.expectEqual(device_event_none, try dev.poll(0));
    try testing.expectEqual(client.Event.none, try c.poll(0));
}

const device_event_announced: Event = .announced;
const device_event_none: Event = .none;

test "a unicast Who-Is is answered with a unicast I-Am" {
    // The interop rule that matters when the requester is not on a subnet this
    // device can broadcast onto: a broadcast reply would never arrive.
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    try c.whoIsTo(rig.device_ep.address, null, null);
    try testing.expectEqual(device_event_announced, try dev.poll(0));

    // It came back as a unicast Original-Unicast-NPDU, not a broadcast.
    var rx: [transport.max_datagram]u8 = undefined;
    const got = (try rig.client_ep.transport().recv(&rx)).?;
    const b = try bvll.decode(got.bytes);
    try testing.expectEqual(bvll.Function.original_unicast_npdu, b.function());
    // ... and a unicast NPDU carries no global-broadcast destination.
    const n = try npdu.decode(b.npdu().?);
    try testing.expectEqual(@as(?npdu.NetAddress, null), n.npci.destination);
    const iam = try service.IAm.decode((try apdu.decode(n.payload.apdu)).unconfirmed_request.data);
    try testing.expectEqual(@as(u22, 599), iam.device.instance);

    // A *broadcast* Who-Is still gets a broadcast I-Am with the global
    // destination, which is what lets it cross a BACnet router.
    try c.whoIs(null, null);
    _ = try dev.poll(1);
    const got2 = (try rig.client_ep.transport().recv(&rx)).?;
    const b2 = try bvll.decode(got2.bytes);
    try testing.expectEqual(bvll.Function.original_broadcast_npdu, b2.function());
    const n2 = try npdu.decode(b2.npdu().?);
    try testing.expectEqual(npdu.global_broadcast_net, n2.npci.destination.?.net);
    try testing.expectEqual(@as(u8, 255), n2.npci.hop_count);
}

test "ReadProperty against our own device, end to end" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    const id = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 5 },
        .present_value,
        null,
        0,
    );
    _ = try dev.poll(0);
    const ev = try c.poll(1);
    try testing.expectEqual(id, ev.complex_ack.invoke_id);
    const ack = try service.ReadPropertyAck.decode(ev.complex_ack.data);
    try testing.expectEqual(@as(f32, 72.5), (try ack.scalar()).real);

    // A string property.
    _ = try c.readProperty(rig.device_ep.address, .{ .type = .analog_input, .instance = 5 }, .object_name, null, 2);
    _ = try dev.poll(2);
    const ev2 = try c.poll(3);
    const ack2 = try service.ReadPropertyAck.decode(ev2.complex_ack.data);
    try testing.expectEqualStrings("ZONE-TEMP", (try ack2.scalar()).character_string.asUtf8().?);

    // Unknown object and unknown property become the standard errors.
    _ = try c.readProperty(rig.device_ep.address, .{ .type = .analog_input, .instance = 99 }, .present_value, null, 4);
    _ = try dev.poll(4);
    const ev3 = try c.poll(5);
    try testing.expectEqual(types.ErrorCode.unknown_object, ev3.err.code);

    _ = try c.readProperty(rig.device_ep.address, .{ .type = .analog_input, .instance = 5 }, .low_limit, null, 6);
    _ = try dev.poll(6);
    const ev4 = try c.poll(7);
    try testing.expectEqual(types.ErrorCode.unknown_property, ev4.err.code);
    try testing.expectEqual(types.ErrorClass.property, ev4.err.class);
}

test "WriteProperty: writable, read-only and wrong-type all get the right answer" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    var vbuf: [8]u8 = undefined;
    var vw = tag.Writer.init(&vbuf);
    try vw.appReal(23.5);
    const setpoint: ObjectId = .{ .type = .analog_value, .instance = 1 };

    _ = try c.writeProperty(rig.device_ep.address, setpoint, .present_value, null, vw.written(), null, 0);
    _ = try dev.poll(0);
    const ev = try c.poll(1);
    try testing.expectEqual(types.ConfirmedService.write_property, ev.simple_ack.svc);
    try testing.expectEqual(@as(f32, 23.5), db.av[2].value.real);

    // A read-only property.
    var vw2 = tag.Writer.init(&vbuf);
    try vw2.appReal(0.0);
    _ = try c.writeProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 5 },
        .present_value,
        null,
        vw2.written(),
        null,
        2,
    );
    _ = try dev.poll(2);
    const ev2 = try c.poll(3);
    try testing.expectEqual(types.ErrorCode.write_access_denied, ev2.err.code);
    try testing.expectEqual(@as(f32, 72.5), db.ai[2].value.real);

    // The right property, the wrong datatype.
    var vw3 = tag.Writer.init(&vbuf);
    try vw3.appUnsigned(30);
    _ = try c.writeProperty(rig.device_ep.address, setpoint, .present_value, null, vw3.written(), null, 4);
    _ = try dev.poll(4);
    const ev3 = try c.poll(5);
    try testing.expectEqual(types.ErrorCode.invalid_data_type, ev3.err.code);
    try testing.expectEqual(@as(f32, 23.5), db.av[2].value.real);

    // A boolean property, written correctly.
    var vw4 = tag.Writer.init(&vbuf);
    try vw4.appBool(true);
    _ = try c.writeProperty(rig.device_ep.address, setpoint, .out_of_service, null, vw4.written(), null, 6);
    _ = try dev.poll(6);
    _ = try c.poll(7);
    try testing.expectEqual(true, db.av[3].value.boolean);
}

test "ReadPropertyMultiple: several objects, the ALL wildcard, and a missing one" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    _ = try c.readPropertyMultiple(rig.device_ep.address, &.{
        .{
            .object = .{ .type = .analog_input, .instance = 5 },
            .properties = &.{
                .{ .property = .present_value },
                .{ .property = .status_flags },
                .{ .property = .low_limit }, // not there
            },
        },
        .{
            .object = .{ .type = .analog_value, .instance = 1 },
            .properties = &.{.{ .property = .all }},
        },
        .{
            .object = .{ .type = .analog_input, .instance = 77 }, // no such object
            .properties = &.{.{ .property = .present_value }},
        },
    }, 0);
    _ = try dev.poll(0);
    const ev = try c.poll(1);

    var it = service.RpmAckIterator.init(ev.complex_ack.data);

    // First object: two values and one per-property error.
    const r1 = (try it.next()).?;
    try testing.expect(r1.object.eql(.{ .type = .analog_input, .instance = 5 }));
    var e1 = r1.results();
    const pv = (try e1.next()).?;
    var pr = tag.Reader.init(pv.outcome.value);
    try testing.expectEqual(@as(f32, 72.5), (try pr.appValue()).real);
    _ = (try e1.next()).?; // status flags
    const missing = (try e1.next()).?;
    try testing.expectEqual(types.ErrorCode.unknown_property, missing.outcome.access_error.code);
    try testing.expectEqual(@as(?service.ResultElement, null), try e1.next());

    // Second object: ALL expands to every property it has.
    const r2 = (try it.next()).?;
    var e2 = r2.results();
    var n: usize = 0;
    while (try e2.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 4), n);

    // Third object: unknown, so the error is per-property inside its result.
    const r3 = (try it.next()).?;
    var e3 = r3.results();
    const unknown = (try e3.next()).?;
    try testing.expectEqual(types.ErrorCode.unknown_object, unknown.outcome.access_error.code);
    try testing.expectEqual(@as(?service.RpmAckIterator.Result, null), try it.next());
}

test "RPM REQUIRED and OPTIONAL select different groups" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    _ = try c.readPropertyMultiple(rig.device_ep.address, &.{.{
        .object = .{ .type = .analog_input, .instance = 5 },
        .properties = &.{.{ .property = .required }},
    }}, 0);
    _ = try dev.poll(0);
    const ev = try c.poll(1);
    var it = service.RpmAckIterator.init(ev.complex_ack.data);
    var els = (try it.next()).?.results();
    var req_count: usize = 0;
    while (try els.next()) |_| req_count += 1;
    try testing.expectEqual(@as(usize, 4), req_count); // `units` is optional

    _ = try c.readPropertyMultiple(rig.device_ep.address, &.{.{
        .object = .{ .type = .analog_input, .instance = 5 },
        .properties = &.{.{ .property = .optional }},
    }}, 2);
    _ = try dev.poll(2);
    const ev2 = try c.poll(3);
    var it2 = service.RpmAckIterator.init(ev2.complex_ack.data);
    var els2 = (try it2.next()).?.results();
    var opt_count: usize = 0;
    while (try els2.next()) |_| opt_count += 1;
    try testing.expectEqual(@as(usize, 1), opt_count);
}

test "COV: subscribe, get the initial value, then get changes" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    const ai: ObjectId = .{ .type = .analog_input, .instance = 5 };
    _ = try c.subscribeCov(rig.device_ep.address, 7, ai, false, 300, 0);
    const dev_ev = try dev.poll(0);
    try testing.expectEqual(false, dev_ev.subscribed.cancelled);
    try testing.expectEqual(@as(usize, 1), dev.subscriptionCount());

    // The SimpleACK, then the immediate initial notification.
    const a1 = try c.poll(1);
    try testing.expectEqual(types.ConfirmedService.subscribe_cov, a1.simple_ack.svc);
    const n1 = try c.poll(1);
    try testing.expectEqual(false, n1.cov.confirmed);
    try testing.expectEqual(@as(u32, 7), n1.cov.notification.process_id);
    var vals = n1.cov.notification.values();
    const first = (try vals.next()).?;
    try testing.expectEqual(types.PropertyIdentifier.present_value, first.property);
    var vr = tag.Reader.init(first.value);
    try testing.expectEqual(@as(f32, 72.5), (try vr.appValue()).real);
    // status_flags is the other cov_reported property.
    try testing.expectEqual(types.PropertyIdentifier.status_flags, (try vals.next()).?.property);

    // A change produces another notification.
    try dev.update(ai, .present_value, .{ .real = 73.75 }, 1000);
    const n2 = try c.poll(1000);
    var vals2 = n2.cov.notification.values();
    var vr2 = tag.Reader.init((try vals2.next()).?.value);
    try testing.expectEqual(@as(f32, 73.75), (try vr2.appValue()).real);
    // The time remaining has come down from the 300 s lifetime.
    try testing.expect(n2.cov.notification.time_remaining <= 300);

    // Writing a property nobody watches produces nothing.
    try dev.update(ai, .units, .{ .enumerated = 62 }, 2000);
    try testing.expectEqual(client.Event.none, try c.poll(2000));
}

/// A commandable analog value (instance 9) with a COV increment of 1.0.
const Cmd = struct {
    slots: [16]?Value = @splat(null),
    props: [6]Property = undefined,
    objects: [1]Object = undefined,

    fn wire(self: *Cmd) []Object {
        self.props = .{
            .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .analog_value, .instance = 9 } } },
            .{ .id = .object_name, .value = .{ .string = "CMD" } },
            .{ .id = .present_value, .value = .{ .real = 5.0 }, .writable = true, .cov_reported = true, .priority_slots = &self.slots },
            .{ .id = .priority_array, .value = .{ .priority_array = &self.slots } },
            .{ .id = .relinquish_default, .value = .{ .real = 5.0 }, .writable = true },
            .{ .id = .cov_increment, .value = .{ .real = 1.0 }, .writable = true, .required = false },
        };
        self.objects = .{.{ .id = .{ .type = .analog_value, .instance = 9 }, .properties = &self.props }};
        return &self.objects;
    }
};

fn writeReal(c: anytype, to: BipAddress, prio: ?u8, v: f32, now: u64) !void {
    var vb: [8]u8 = undefined;
    var vw = tag.Writer.init(&vb);
    try vw.appReal(v);
    _ = try c.writeProperty(to, .{ .type = .analog_value, .instance = 9 }, .present_value, null, vw.written(), prio, now);
}

test "commandable priority array: the highest priority wins, a relinquish falls through to the default" {
    var rig: Rig = .{};
    rig.wire();
    var cmd: Cmd = .{};
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, cmd.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const to = rig.device_ep.address;
    const av9: ObjectId = .{ .type = .analog_value, .instance = 9 };

    try writeReal(&c, to, 8, 20.0, 0);
    _ = try dev.poll(0);
    _ = try c.poll(1);
    try testing.expectEqual(@as(f32, 20.0), cmd.props[2].value.real);
    // A lower priority (a larger number) does not take over ...
    try writeReal(&c, to, 10, 30.0, 2);
    _ = try dev.poll(2);
    _ = try c.poll(3);
    try testing.expectEqual(@as(f32, 20.0), cmd.props[2].value.real);
    try testing.expectEqual(@as(f32, 30.0), cmd.slots[9].?.real);
    // ... until the higher one is relinquished.
    _ = try c.relinquish(to, av9, .present_value, 8, 4);
    _ = try dev.poll(4);
    try testing.expectEqual(types.ConfirmedService.write_property, (try c.poll(5)).simple_ack.svc);
    try testing.expectEqual(@as(f32, 30.0), cmd.props[2].value.real);
    try testing.expect(cmd.slots[7] == null);
    // Without a priority a write goes to slot 16.
    try writeReal(&c, to, null, 7.0, 6);
    _ = try dev.poll(6);
    _ = try c.poll(7);
    try testing.expectEqual(@as(f32, 7.0), cmd.slots[15].?.real);
    // Everything relinquished: the relinquish default.
    _ = try c.relinquish(to, av9, .present_value, 10, 8);
    _ = try dev.poll(8);
    _ = try c.poll(9);
    _ = try c.relinquish(to, av9, .present_value, 16, 10);
    _ = try dev.poll(10);
    _ = try c.poll(11);
    try testing.expectEqual(@as(f32, 5.0), cmd.props[2].value.real);

    // Priority 6 is the minimum on/off algorithm's, a wrong datatype is refused.
    try writeReal(&c, to, 6, 1.0, 12);
    _ = try dev.poll(12);
    try testing.expectEqual(types.ErrorCode.write_access_denied, (try c.poll(13)).err.code);
    var ub: [8]u8 = undefined;
    var uw = tag.Writer.init(&ub);
    try uw.appUnsigned(3);
    _ = try c.writeProperty(to, av9, .present_value, null, uw.written(), 8, 14);
    _ = try dev.poll(14);
    try testing.expectEqual(types.ErrorCode.invalid_data_type, (try c.poll(15)).err.code);

    // WritePropertyMultiple commands and relinquishes through the same path.
    var rb: [8]u8 = undefined;
    var rw = tag.Writer.init(&rb);
    try rw.appReal(12.5);
    _ = try c.writePropertyMultiple(to, &.{.{ .object = av9, .writes = &.{.{ .property = .present_value, .value = rw.written(), .priority = 3 }} }}, 16);
    _ = try dev.poll(16);
    _ = try c.poll(17);
    try testing.expectEqual(@as(f32, 12.5), cmd.props[2].value.real);
}

test "commandable priority array: priority_array and relinquish_default read back, by index too" {
    var rig: Rig = .{};
    rig.wire();
    var cmd: Cmd = .{};
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, cmd.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const to = rig.device_ep.address;
    const av9: ObjectId = .{ .type = .analog_value, .instance = 9 };
    try writeReal(&c, to, 2, 21.0, 0);
    _ = try dev.poll(0);
    _ = try c.poll(1);

    _ = try c.readProperty(to, av9, .priority_array, null, 2);
    _ = try dev.poll(2);
    const whole = (try c.poll(3)).complex_ack;
    var ack = try service.ReadPropertyAck.decode(whole.data);
    // 16 elements: Null, a Real at the second slot, then Nulls.
    var r = tag.Reader.init(ack.value);
    var n: usize = 0;
    while (!r.atEnd()) : (n += 1) {
        const v = try r.appValue();
        if (n == 1) try testing.expectEqual(@as(f32, 21.0), v.real) else try testing.expect(v == .null);
    }
    try testing.expectEqual(@as(usize, 16), n);
    ack = undefined;

    _ = try c.readProperty(to, av9, .priority_array, 0, 4);
    _ = try dev.poll(4);
    const size_ack = try service.ReadPropertyAck.decode((try c.poll(5)).complex_ack.data);
    var sr = tag.Reader.init(size_ack.value);
    try testing.expectEqual(@as(u64, 16), (try sr.appValue()).unsigned);
    _ = try c.readProperty(to, av9, .priority_array, 2, 6);
    _ = try dev.poll(6);
    const one = try service.ReadPropertyAck.decode((try c.poll(7)).complex_ack.data);
    var or_ = tag.Reader.init(one.value);
    try testing.expectEqual(@as(f32, 21.0), (try or_.appValue()).real);
    _ = try c.readProperty(to, av9, .priority_array, 17, 8);
    _ = try dev.poll(8);
    try testing.expectEqual(types.ErrorCode.invalid_array_index, (try c.poll(9)).err.code);
    // An array index on a plain property is still refused.
    _ = try c.readProperty(to, av9, .present_value, 1, 10);
    _ = try dev.poll(10);
    try testing.expectEqual(types.ErrorCode.property_is_not_an_array, (try c.poll(11)).err.code);
}

test "COV_Increment: a Real present_value notifies only after moving by the increment" {
    var rig: Rig = .{};
    rig.wire();
    var cmd: Cmd = .{};
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, cmd.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const av9: ObjectId = .{ .type = .analog_value, .instance = 9 };
    _ = try c.subscribeCov(rig.device_ep.address, 1, av9, false, 0, 0);
    _ = try dev.poll(0);
    _ = try c.poll(1); // the SimpleACK
    _ = try c.poll(1); // the initial notification

    // The first change notifies (nothing has been notified by `update` yet) ...
    try dev.update(av9, .present_value, .{ .real = 5.4 }, 10);
    try testing.expect((try c.poll(10)) == .cov);
    // ... a move of 0.5 from the last notified value does not ...
    try dev.update(av9, .present_value, .{ .real = 5.9 }, 20);
    try testing.expectEqual(client.Event.none, try c.poll(20));
    try dev.update(av9, .present_value, .{ .real = 4.9 }, 30);
    try testing.expectEqual(client.Event.none, try c.poll(30));
    // ... a move of 1.0 or more does, either way.
    try dev.update(av9, .present_value, .{ .real = 6.4 }, 40);
    try testing.expect((try c.poll(40)) == .cov);
    try dev.update(av9, .present_value, .{ .real = 5.3 }, 50);
    try testing.expect((try c.poll(50)) == .cov);
}

test "COV: confirmed notifications are acknowledged by the client" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    const ai: ObjectId = .{ .type = .analog_input, .instance = 5 };
    _ = try c.subscribeCov(rig.device_ep.address, 9, ai, true, 60, 0);
    _ = try dev.poll(0);
    _ = try c.poll(1); // SimpleACK
    const n1 = try c.poll(1); // initial notification
    try testing.expectEqual(true, n1.cov.confirmed);

    // The client acknowledged it; the device clears its outstanding marker.
    _ = try dev.poll(2);
    for (dev.subs) |s| {
        if (s.active) try testing.expectEqual(@as(?u8, null), s.outstanding);
    }
}

test "COV: cancellation, idempotent cancellation, and lifetime expiry" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    const ai: ObjectId = .{ .type = .analog_input, .instance = 5 };
    _ = try c.subscribeCov(rig.device_ep.address, 7, ai, false, 10, 0);
    try settle(&c, &dev, 0);
    try testing.expectEqual(@as(usize, 1), dev.subscriptionCount());

    _ = try c.cancelCov(rig.device_ep.address, 7, ai, 100);
    const ev = try dev.poll(100);
    try testing.expectEqual(true, ev.subscribed.cancelled);
    try testing.expectEqual(@as(usize, 0), dev.subscriptionCount());
    const ack = try c.poll(101);
    try testing.expectEqual(types.ConfirmedService.subscribe_cov, ack.simple_ack.svc);

    // Cancelling again still succeeds — a restarted client's cleanup must be
    // idempotent.
    _ = try c.cancelCov(rig.device_ep.address, 7, ai, 200);
    _ = try dev.poll(200);
    const ack2 = try c.poll(201);
    try testing.expectEqual(types.ConfirmedService.subscribe_cov, ack2.simple_ack.svc);

    // A lifetime that runs out drops the subscription without being asked.
    _ = try c.subscribeCov(rig.device_ep.address, 8, ai, false, 10, 300);
    try settle(&c, &dev, 300);
    try testing.expectEqual(@as(usize, 1), dev.subscriptionCount());
    _ = try dev.poll(300 + 10_000);
    try testing.expectEqual(@as(usize, 0), dev.subscriptionCount());
    // ... and a change after that notifies nobody.
    try dev.update(ai, .present_value, .{ .real = 80.0 }, 400_000);
    try testing.expectEqual(client.Event.none, try c.poll(400_000));
}

test "COV lifetime is clamped so a vanished subscriber cannot pin a slot forever" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{
        .instance = 599,
        .max_cov_lifetime_s = 60,
    }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    // Ask for "indefinite"; the device grants 60 s.
    _ = try c.subscribeCov(rig.device_ep.address, 7, .{ .type = .analog_input, .instance = 5 }, false, 0, 0);
    try settle(&c, &dev, 0);
    for (dev.subs) |s| {
        if (s.active) try testing.expectEqual(@as(?u64, 60_000), s.expires_ms);
    }
}

test "COV lifetime: the delivered default (3600 s) is the value actually granted" {
    // The prior test above pins the MECHANISM against a config value it
    // supplies itself (60), which stays green for any clamp value at all.
    // This one names the literal a caller who never touches `Config` actually
    // gets — an unauthenticated peer's only bound on its only held resource —
    // so a change to the shipped default is a red test, not a silent shift.
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    // Ask for "indefinite" (lifetime 0); the default config clamps it.
    _ = try c.subscribeCov(rig.device_ep.address, 7, .{ .type = .analog_input, .instance = 5 }, false, 0, 0);
    try settle(&c, &dev, 0);
    for (dev.subs) |s| {
        if (s.active) try testing.expectEqual(@as(?u64, 3_600_000), s.expires_ms);
    }
}

test "COV lifetime: max_cov_lifetime_s = 0 is a deliberate opt-out, not an accident" {
    // SPEC documents 0 as "clamp disabled" — the one config the campaign's
    // own re-audit flagged as indistinguishable from a bug by exit code alone
    // (both 0 and 1 left the suite green). Cover it explicitly, two ways:
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{
        .instance = 599,
        .max_cov_lifetime_s = 0,
    }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    // (a) An unauthenticated peer requesting an indefinite lifetime (0)
    // against a device configured with the clamp off gets exactly that — a
    // permanent slot — the vulnerability F7 names.
    _ = try c.subscribeCov(rig.device_ep.address, 7, .{ .type = .analog_input, .instance = 5 }, false, 0, 0);
    try settle(&c, &dev, 0);
    for (dev.subs) |s| {
        if (s.active) try testing.expectEqual(@as(?u64, null), s.expires_ms);
    }

    // (b) A degenerate all-zero request cannot distinguish "clamp disabled"
    // from "clamp to 0" — both give `expires_ms == null`. Request a large,
    // explicit, non-zero lifetime instead: the opt-out must leave it
    // UNTOUCHED (999_999 s), not silently cut it down to the config's own
    // (zero) value. This is what actually discriminates the guard from a
    // clamp-to-zero implementation of "0".
    _ = try c.subscribeCov(rig.device_ep.address, 9, .{ .type = .analog_input, .instance = 5 }, false, 999_999, 1);
    try settle(&c, &dev, 1);
    var found = false;
    for (dev.subs) |s| {
        if (s.active and s.process_id == 9) {
            found = true;
            try testing.expectEqual(@as(?u64, 1 + 999_999_000), s.expires_ms);
        }
    }
    try testing.expect(found);
}

test "Who-Has by name and by identifier, answered with I-Have" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    try c.whoHasName("ZONE-TEMP", null, null);
    _ = try dev.poll(0);
    const ev = try c.poll(1);
    try testing.expectEqualStrings("ZONE-TEMP", ev.i_have.info.object_name);
    try testing.expect(ev.i_have.info.object.eql(.{ .type = .analog_input, .instance = 5 }));
    try testing.expect(ev.i_have.info.device.eql(.{ .type = .device, .instance = 599 }));

    try c.whoHasId(.{ .type = .analog_value, .instance = 1 }, null, null);
    _ = try dev.poll(2);
    const ev2 = try c.poll(3);
    try testing.expectEqualStrings("SETPOINT", ev2.i_have.info.object_name);

    // A name nobody has produces silence, not an error.
    try c.whoHasName("NO-SUCH-POINT", null, null);
    try testing.expectEqual(device_event_none, try dev.poll(4));
    try testing.expectEqual(client.Event.none, try c.poll(5));
}

test "WritePropertyMultiple: applied in order, the first failure ends it, earlier writes stay" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const setpoint: ObjectId = .{ .type = .analog_value, .instance = 1 };

    // Two good writes to one object.
    var r1: [8]u8 = undefined;
    var rw = tag.Writer.init(&r1);
    try rw.appReal(30.0);
    var b1: [4]u8 = undefined;
    var bw = tag.Writer.init(&b1);
    try bw.appBool(true);
    _ = try c.writePropertyMultiple(rig.device_ep.address, &.{.{ .object = setpoint, .writes = &.{
        .{ .property = .present_value, .value = rw.written(), .priority = 8 },
        .{ .property = .out_of_service, .value = bw.written() },
    } }}, 0);
    try testing.expectEqual(@as(usize, 2), (try dev.poll(0)).wrote_multiple.count);
    const ev = try c.poll(1);
    try testing.expectEqual(types.ConfirmedService.write_property_multiple, ev.simple_ack.svc);
    try testing.expectEqual(@as(f32, 30.0), db.av[2].value.real);
    try testing.expectEqual(true, db.av[3].value.boolean);

    // The second write is to a read-only property: the first stays applied,
    // the third is never tried, and the Error names the second.
    var r2: [8]u8 = undefined;
    var rw2 = tag.Writer.init(&r2);
    try rw2.appReal(40.0);
    var r3: [8]u8 = undefined;
    var rw3 = tag.Writer.init(&r3);
    try rw3.appReal(50.0);
    const input: ObjectId = .{ .type = .analog_input, .instance = 5 };
    _ = try c.writePropertyMultiple(rig.device_ep.address, &.{
        .{ .object = setpoint, .writes = &.{.{ .property = .present_value, .value = rw2.written() }} },
        .{ .object = input, .writes = &.{.{ .property = .present_value, .value = rw3.written() }} },
        .{ .object = setpoint, .writes = &.{.{ .property = .present_value, .value = rw3.written() }} },
    }, 2);
    _ = try dev.poll(2);
    const ev2 = try c.poll(3);
    try testing.expectEqual(types.ErrorCode.write_access_denied, ev2.err.code);
    try testing.expectEqual(types.ErrorClass.property, ev2.err.class);
    const first = try service.FirstFailedWrite.decode(ev2.err.extra);
    try testing.expectEqual(input, first.object);
    try testing.expectEqual(types.PropertyIdentifier.present_value, first.property);
    try testing.expectEqual(@as(f32, 40.0), db.av[2].value.real);
    try testing.expectEqual(@as(f32, 72.5), db.ai[2].value.real);
}

test "DeviceCommunicationControl: password, disable, disable_initiation, timed lapse" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .password = "secret" }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const to = rig.device_ep.address;
    const dev_obj: ObjectId = .{ .type = .device, .instance = 599 };

    // No password, wrong password: Error(security, password_failure), still enabled.
    _ = try c.deviceCommunicationControl(to, .{ .state = .disable }, 0);
    _ = try dev.poll(0);
    try testing.expectEqual(types.ErrorCode.password_failure, (try c.poll(1)).err.code);
    _ = try c.deviceCommunicationControl(to, .{ .state = .disable, .password = "nope" }, 2);
    _ = try dev.poll(2);
    try testing.expectEqual(types.ErrorClass.security, (try c.poll(3)).err.class);
    try testing.expectEqual(service.CommunicationState.enable, dev.comm);

    // disable_initiation for one minute: still answers, initiates nothing.
    _ = try c.deviceCommunicationControl(to, .{ .state = .disable_initiation, .duration_minutes = 1, .password = "secret" }, 4);
    try testing.expectEqual(service.CommunicationState.disable_initiation, (try dev.poll(10)).communication_control.state);
    try testing.expectEqual(types.ConfirmedService.device_communication_control, (try c.poll(11)).simple_ack.svc);
    try dev.announce();
    var rx: [transport.max_datagram]u8 = undefined;
    try testing.expect((try rig.client_ep.transport().recv(&rx)) == null);
    _ = try c.readProperty(to, dev_obj, .object_name, null, 12);
    _ = try dev.poll(12);
    try testing.expectEqual(types.ConfirmedService.read_property, (try c.poll(13)).complex_ack.svc);
    try c.whoIs(null, null);
    try testing.expectEqual(device_event_announced, try dev.poll(14));
    _ = try c.poll(15);

    // The minute lapses on its own.
    _ = try dev.poll(60_011);
    try testing.expectEqual(service.CommunicationState.enable, dev.comm);

    // disable: nothing is answered but the two services that end it.
    _ = try c.deviceCommunicationControl(to, .{ .state = .disable, .password = "secret" }, 60_012);
    _ = try dev.poll(60_012);
    _ = try c.poll(60_013);
    _ = try c.readProperty(to, dev_obj, .object_name, null, 60_014);
    try testing.expectEqual(Event.none, try dev.poll(60_014));
    try c.whoIs(null, null);
    try testing.expectEqual(Event.none, try dev.poll(60_015));
    try testing.expect((try rig.client_ep.transport().recv(&rx)) == null);
    _ = try c.deviceCommunicationControl(to, .{ .state = .enable, .password = "secret" }, 60_016);
    try testing.expectEqual(service.CommunicationState.enable, (try dev.poll(60_016)).communication_control.state);
    _ = try c.poll(60_017);
    try testing.expectEqual(service.CommunicationState.enable, dev.comm);
}

test "ReinitializeDevice: password, acknowledged, handed to the application; backup is not served" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .password = "pw" }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const to = rig.device_ep.address;

    _ = try c.reinitializeDevice(to, .{ .state = .coldstart, .password = "bad" }, 0);
    try testing.expectEqual(types.ErrorCode.password_failure, blk: {
        _ = try dev.poll(0);
        break :blk (try c.poll(1)).err.code;
    });
    _ = try c.reinitializeDevice(to, .{ .state = .warmstart, .password = "pw" }, 2);
    try testing.expectEqual(service.ReinitializedState.warmstart, (try dev.poll(2)).reinitialize.state);
    try testing.expectEqual(types.ConfirmedService.reinitialize_device, (try c.poll(3)).simple_ack.svc);
    _ = try c.reinitializeDevice(to, .{ .state = .start_backup, .password = "pw" }, 4);
    _ = try dev.poll(4);
    try testing.expectEqual(types.ErrorCode.optional_functionality_not_supported, (try c.poll(5)).err.code);
}

test "TimeSynchronization and UTCTimeSynchronization reach the application, unconfirmed" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const t: service.DateTime = .{
        .date = .{ .year = 126, .month = 11, .day = 21, .weekday = 6 },
        .time = .{ .hour = 13, .minute = 5, .second = 9, .hundredths = 50 },
    };
    try c.timeSynchronization(rig.device_ep.address, t, false);
    const ev = try dev.poll(0);
    try testing.expectEqual(false, ev.time_synchronized.utc);
    try testing.expectEqual(@as(u8, 13), ev.time_synchronized.time.time.hour);
    try c.timeSynchronization(null, t, true);
    try testing.expectEqual(true, (try dev.poll(1)).time_synchronized.utc);
    var rx: [transport.max_datagram]u8 = undefined;
    try testing.expect((try rig.client_ep.transport().recv(&rx)) == null);
}

/// A device object whose `object_list` is `n` analog values: `5 * n` octets.
const BigList = struct {
    list: [3000]u8 = undefined,
    props: [3]Property = undefined,
    objects: [1]Object = undefined,
    list_len: usize = 0,

    fn wire(self: *BigList, n: usize) []Object {
        var w = tag.Writer.init(&self.list);
        for (0..n) |i| w.appObjectId(.{ .type = .analog_value, .instance = @intCast(i) }) catch unreachable;
        self.list_len = w.written().len;
        self.props = .{
            .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .device, .instance = 599 } } },
            .{ .id = .object_name, .value = .{ .string = "BIG" } },
            .{ .id = .object_list, .value = .{ .raw = self.list[0..self.list_len] } },
        };
        self.objects = .{.{ .id = .{ .type = .device, .instance = 599 }, .properties = &self.props }};
        return &self.objects;
    }
};

/// Runs device and client until the client reports `want` (a tag of its event) or 60 rounds pass.
fn pumpUntilComplex(dev: anytype, c: anytype, start_ms: u64) !client.Event {
    var now = start_ms;
    for (0..60) |_| {
        _ = try dev.poll(now);
        const ev = try c.poll(now);
        switch (ev) {
            .complex_ack, .abort, .err, .timeout, .segmented_response => return ev,
            else => {},
        }
        now += 10;
    }
    return error.NoAnswer;
}

test "segmented reply: a ReadProperty larger than the requester's max APDU is reassembled" {
    var rig: Rig = .{};
    rig.wire();
    var big: BigList = .{};
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .segmented_responses = true, .max_apdu = .up_to_1476 }, big.wire(300));
    var reasm: [4096]u8 = undefined;
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{ .max_apdu = .up_to_480, .reassembly = &reasm });

    // The device advertises that it can transmit segmented messages.
    try dev.announce();
    var iam_rx: [transport.max_datagram]u8 = undefined;
    const got = (try rig.client_ep.transport().recv(&iam_rx)).?;
    const iam = try service.IAm.decode((try apdu.decode((try npdu.decode((try bvll.decode(got.bytes)).npdu().?)).payload.apdu)).unconfirmed_request.data);
    try testing.expectEqual(types.Segmentation.transmit, iam.segmentation);

    _ = try c.readProperty(rig.device_ep.address, .{ .type = .device, .instance = 599 }, .object_list, null, 0);
    const ev = try pumpUntilComplex(&dev, &c, 0);
    try testing.expectEqual(types.ConfirmedService.read_property, ev.complex_ack.svc);
    const ack = try service.ReadPropertyAck.decode(ev.complex_ack.data);
    try testing.expectEqualSlices(u8, big.list[0..big.list_len], ack.value);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    // 1500 octets of values at 475 per segment: four segments, acknowledged as one window.
    try testing.expectEqual(@as(u16, 4), (try dev.poll(1_000)).segmented_reply_sent.segments);
}

test "segmented reply: a window of one is acknowledged segment by segment, a lost segment is resent" {
    var rig: Rig = .{};
    rig.wire();
    var big: BigList = .{};
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .segmented_responses = true, .segment_window = 4 }, big.wire(300));
    var reasm: [4096]u8 = undefined;
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{ .max_apdu = .up_to_480, .reassembly = &reasm, .segment_window = 4 });

    _ = try c.readProperty(rig.device_ep.address, .{ .type = .device, .instance = 599 }, .object_list, null, 0);
    _ = try dev.poll(0); // the request: four segments go out
    // Take them off the wire and hand the client segments 0, 2 and 3: segment 1 is lost.
    var datagrams: [4][transport.max_datagram]u8 = undefined;
    var lens: [4]usize = undefined;
    for (0..4) |i| {
        const d = (try rig.client_ep.transport().recv(&datagrams[i])).?;
        lens[i] = d.bytes.len;
    }
    for ([_]usize{ 0, 2, 3 }) |i| rig.client_ep.inject(rig.device_ep.address, datagrams[i][0..lens[i]]);
    _ = try c.poll(1); // segment 0 in order
    _ = try c.poll(1); // segment 2: out of order, a negative SegmentACK for 0
    _ = try c.poll(1); // segment 3: the same
    // The device goes back to segment 1 and sends the rest of the window.
    _ = try dev.poll(2);
    _ = try dev.poll(2);
    var done: ?client.Event = null;
    for (0..20) |i| {
        const ev = try c.poll(3 + i);
        if (ev == .complex_ack) {
            done = ev;
            break;
        }
    }
    const ack = try service.ReadPropertyAck.decode(done.?.complex_ack.data);
    try testing.expectEqualSlices(u8, big.list[0..big.list_len], ack.value);
}

test "segmented reply: the requester that does not accept segments is aborted, a silent one times out" {
    var rig: Rig = .{};
    rig.wire();
    var big: BigList = .{};
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .segmented_responses = true, .segment_timeout_ms = 100, .segment_retries = 2 }, big.wire(300));
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{ .max_apdu = .up_to_480 });
    _ = try c.readProperty(rig.device_ep.address, .{ .type = .device, .instance = 599 }, .object_list, null, 0);
    _ = try dev.poll(0);
    const ev = try c.poll(1);
    try testing.expectEqual(types.AbortReason.segmentation_not_supported, ev.abort.reason);

    // A requester that accepts segments and then says nothing: the window is
    // resent twice, then the transfer is abandoned.
    var reasm: [4096]u8 = undefined;
    var c2 = client.DefaultClient.init(rig.client_ep.transport(), .{ .max_apdu = .up_to_480, .reassembly = &reasm });
    _ = try c2.readProperty(rig.device_ep.address, .{ .type = .device, .instance = 599 }, .object_list, null, 10);
    _ = try dev.poll(10);
    var drop: [transport.max_datagram]u8 = undefined;
    while ((try rig.client_ep.transport().recv(&drop)) != null) {}
    const sent_before = rig.device_ep.sent_count;
    _ = try dev.poll(111); // first resend
    _ = try dev.poll(212); // second resend
    try testing.expect(rig.device_ep.sent_count > sent_before);
    _ = try dev.poll(313); // out of retries: Abort(tsm_timeout)
    try testing.expect(!dev.seg.active);
    var last: types.AbortReason = .other;
    while (try rig.client_ep.transport().recv(&drop)) |d| {
        const a = try apdu.decode((try npdu.decode((try bvll.decode(d.bytes)).npdu().?)).payload.apdu);
        if (a == .abort) last = a.abort.reason;
    }
    try testing.expectEqual(types.AbortReason.tsm_timeout, last);
}

test "the device refuses a segmented request rather than buffering it" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());

    // Hand-build a segmented ReadProperty.
    var a_buf: [64]u8 = undefined;
    const a = try apdu.encode(.{ .confirmed_request = .{
        .invoke_id = 3,
        .service = .read_property,
        .segment = .{ .sequence_number = 0, .window_size = 4, .more_follows = true },
        .data = &.{ 0x0C, 0x00, 0x00, 0x00, 0x05 },
    } }, &a_buf);
    var n_buf: [96]u8 = undefined;
    const n = try npdu.encode(.{ .expecting_reply = true }, a, &n_buf);
    var d_buf: [128]u8 = undefined;
    const d = try bvll.wrap(.original_unicast_npdu, n, &d_buf);
    rig.device_ep.inject(rig.client_ep.address, d);

    _ = try dev.poll(0);

    var rx: [transport.max_datagram]u8 = undefined;
    const got = (try rig.client_ep.transport().recv(&rx)).?;
    const back = try apdu.decode((try npdu.decode((try bvll.decode(got.bytes)).npdu().?)).payload.apdu);
    try testing.expectEqual(types.AbortReason.segmentation_not_supported, back.abort.reason);
    try testing.expectEqual(@as(u8, 3), back.abort.invoke_id);
    try testing.expectEqual(true, back.abort.server);
}

/// A WritePropertyMultiple of `n` writes of 30.0 to the Db's analog value:
/// about 11 octets each, so far more than one 480-octet APDU for a large `n`.
fn bigWpm(c: anytype, to: BipAddress, n: usize, now: u64) !u8 {
    var rb: [8]u8 = undefined;
    var rw = tag.Writer.init(&rb);
    try rw.appReal(30.0);
    var writes: [200]service.PropertyWrite = undefined;
    for (writes[0..n]) |*pw| pw.* = .{ .property = .present_value, .value = rw.written(), .priority = 8 };
    return c.writePropertyMultiple(to, &.{.{ .object = .{ .type = .analog_value, .instance = 1 }, .writes = writes[0..n] }}, now);
}

/// Announces the device and lets the client learn it from the I-Am.
fn learnDevice(dev: anytype, c: anytype, rig: *Rig) !service.IAm {
    _ = rig;
    try dev.announce();
    const ev = try c.poll(0);
    return ev.i_am.info;
}

test "segmented request: a WritePropertyMultiple larger than the device's max APDU is segmented and reassembled" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dbuf: [2048]u8 = undefined;
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .max_apdu = .up_to_480, .reassembly = &dbuf }, db.wire());
    var cbuf: [2048]u8 = undefined;
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{ .request_buffer = &cbuf });

    // The I-Am says the device receives segmented messages.
    const iam = try learnDevice(&dev, &c, &rig);
    try testing.expectEqual(types.Segmentation.receive, iam.segmentation);
    try testing.expectEqual(@as(u32, 480), iam.max_apdu_accepted);

    _ = try bigWpm(&c, rig.device_ep.address, 150, 1);
    var wrote: usize = 0;
    var acked = false;
    for (0..60) |i| {
        const ev = try dev.poll(2 + i);
        if (ev == .wrote_multiple) wrote = ev.wrote_multiple.count;
        const cev = try c.poll(2 + i);
        if (cev == .simple_ack) acked = true;
        if (acked) break;
    }
    try testing.expect(acked);
    try testing.expectEqual(@as(usize, 150), wrote);
    try testing.expectEqual(@as(f32, 30.0), db.av[2].value.real);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expect(!c.sq.active and !dev.rx_seg.active);
}

test "segmented request: a lost segment is answered with a negative SegmentACK and resent" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dbuf: [2048]u8 = undefined;
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .max_apdu = .up_to_480, .reassembly = &dbuf }, db.wire());
    var cbuf: [2048]u8 = undefined;
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{ .request_buffer = &cbuf, .segment_window = 4 });
    _ = try learnDevice(&dev, &c, &rig);

    _ = try bigWpm(&c, rig.device_ep.address, 150, 1); // four segments of 474 octets go out
    var datagrams: [4][transport.max_datagram]u8 = undefined;
    var lens: [4]usize = undefined;
    for (0..4) |i| lens[i] = (try rig.device_ep.transport().recv(&datagrams[i])).?.bytes.len;
    // Segment 1 is lost.
    for ([_]usize{ 0, 2, 3 }) |i| rig.device_ep.inject(rig.client_ep.address, datagrams[i][0..lens[i]]);
    for (0..3) |_| _ = try dev.poll(2);
    try testing.expectEqual(@as(u8, 1), dev.rx_seg.expected);
    var wrote: usize = 0;
    var acked = false;
    for (0..60) |i| {
        const cev = try c.poll(3 + i);
        if (cev == .simple_ack) acked = true;
        const ev = try dev.poll(3 + i);
        if (ev == .wrote_multiple) wrote = ev.wrote_multiple.count;
        if (acked) break;
    }
    try testing.expect(acked);
    try testing.expectEqual(@as(usize, 150), wrote);
}

test "segmented request: refused locally for a peer that cannot receive segments, aborted by one with a small buffer" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var cbuf: [2048]u8 = undefined;
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{ .request_buffer = &cbuf });

    // A device without a reassembly buffer says `none`: nothing is sent.
    var plain = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .max_apdu = .up_to_480 }, db.wire());
    const iam = try learnDevice(&plain, &c, &rig);
    try testing.expectEqual(types.Segmentation.none, iam.segmentation);
    try testing.expectError(error.RequestTooLarge, bigWpm(&c, rig.device_ep.address, 150, 1));
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    // A request that fits goes out whole.
    _ = try bigWpm(&c, rig.device_ep.address, 20, 1);
    try testing.expectEqual(@as(usize, 20), (try plain.poll(1)).wrote_multiple.count);
    try testing.expectEqual(types.ConfirmedService.write_property_multiple, (try c.poll(1)).simple_ack.svc);

    // A device that receives, but into a buffer too small for the request.
    var small: [600]u8 = undefined;
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .max_apdu = .up_to_480, .reassembly = &small }, db.wire());
    _ = try learnDevice(&dev, &c, &rig);
    _ = try bigWpm(&c, rig.device_ep.address, 150, 2);
    var got: ?client.Event = null;
    for (0..30) |i| {
        _ = try dev.poll(3 + i);
        const ev = try c.poll(3 + i);
        if (ev == .abort) {
            got = ev;
            break;
        }
    }
    try testing.expectEqual(types.AbortReason.buffer_overflow, got.?.abort.reason);
    try testing.expect(!dev.rx_seg.active and !c.sq.active);
}

test "segmented request: a silent sender's transfer is dropped, a stray middle segment is aborted" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dbuf: [2048]u8 = undefined;
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599, .max_apdu = .up_to_480, .reassembly = &dbuf, .segment_timeout_ms = 100 }, db.wire());
    var cbuf: [2048]u8 = undefined;
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{ .request_buffer = &cbuf, .segment_window = 1 });
    _ = try learnDevice(&dev, &c, &rig);

    _ = try bigWpm(&c, rig.device_ep.address, 150, 1); // window of one: only segment 0 goes out
    _ = try dev.poll(1);
    try testing.expect(dev.rx_seg.active);
    _ = try dev.poll(200); // silence for longer than the timeout
    try testing.expect(!dev.rx_seg.active);

    // A segment 1 of a transfer the device no longer has.
    var a_buf: [64]u8 = undefined;
    const a = try apdu.encode(.{ .confirmed_request = .{
        .invoke_id = c.sq.invoke_id,
        .service = .write_property_multiple,
        .segment = .{ .sequence_number = 1, .window_size = 1, .more_follows = false },
        .data = &.{0x00},
    } }, &a_buf);
    var n_buf: [96]u8 = undefined;
    const n = try npdu.encode(.{ .expecting_reply = true }, a, &n_buf);
    var d_buf: [128]u8 = undefined;
    const d = try bvll.wrap(.original_unicast_npdu, n, &d_buf);
    var drain: [transport.max_datagram]u8 = undefined;
    while ((try rig.client_ep.transport().recv(&drain)) != null) {}
    rig.device_ep.inject(rig.client_ep.address, d);
    _ = try dev.poll(201);
    const got = (try rig.client_ep.transport().recv(&drain)).?;
    const back = try apdu.decode((try npdu.decode((try bvll.decode(got.bytes)).npdu().?)).payload.apdu);
    try testing.expectEqual(types.AbortReason.invalid_apdu_in_this_state, back.abort.reason);
}

// Two destinations, both addressed to 192.0.2.1:47808 (the rig's client): process 7,
// unconfirmed, to-offnormal and to-normal; process 8, confirmed, to-offnormal only.
// The bytes of the first were emitted by bacpypes3 (`tools/event_goldens.py` recipe).
const alarm_recipients = hex("8201feb400000000b4173b3b631e21006506c0000201bac01f21071082" ++ "05a0") ++
    hex("8201feb400000000b4173b3b631e21006506c0000201bac01f21081182" ++ "0580");
const alarm_priorities = hex("21642196" ++ "21c8");

const AlarmDb = struct {
    ai: [14]Property = undefined,
    cls: [6]Property = undefined,
    objects: [2]Object = undefined,
    ed: EventData = .{},

    fn wire(self: *AlarmDb) []Object {
        self.ai = .{
            .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .analog_input, .instance = 1 } } },
            .{ .id = .object_name, .value = .{ .string = "TEMP" } },
            .{ .id = .present_value, .value = .{ .real = 50 }, .writable = true },
            .{ .id = .high_limit, .value = .{ .real = 80 } },
            .{ .id = .low_limit, .value = .{ .real = 10 } },
            .{ .id = .deadband, .value = .{ .real = 5 } },
            .{ .id = .limit_enable, .value = .{ .bit_string = .{ .unused_bits = 6, .bytes = &.{0xC0} } } },
            .{ .id = .event_enable, .value = .{ .bit_string = .{ .unused_bits = 5, .bytes = &.{0xE0} } } },
            .{ .id = .notification_class, .value = .{ .unsigned = 3 } },
            .{ .id = .time_delay, .value = .{ .unsigned = 2 } },
            .{ .id = .notify_type, .value = .{ .enumerated = 0 } },
            .{ .id = .event_state, .value = .{ .enumerated = 0 }, .event = &self.ed },
            .{ .id = .acked_transitions, .value = .null },
            .{ .id = .event_time_stamps, .value = .null },
        };
        self.cls = .{
            .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .notification_class, .instance = 3 } } },
            .{ .id = .object_name, .value = .{ .string = "NC" } },
            .{ .id = .notification_class, .value = .{ .unsigned = 3 } },
            .{ .id = .priority, .value = .{ .raw = &alarm_priorities } },
            .{ .id = .ack_required, .value = .{ .bit_string = .{ .unused_bits = 5, .bytes = &.{0xA0} } } },
            .{ .id = .recipient_list, .value = .{ .raw = &alarm_recipients } },
        };
        self.objects = .{
            .{ .id = .{ .type = .analog_input, .instance = 1 }, .properties = &self.ai },
            .{ .id = .{ .type = .notification_class, .instance = 3 }, .properties = &self.cls },
        };
        self.ed.sync(&self.ai);
        return &self.objects;
    }
};

/// What the client heard of one event notification.
const Heard = struct { confirmed: bool, process: u32, to: types.EventState, notify: events.NotifyType, ack_required: ?bool, priority: u8, seq: u32 };

/// Polls the client until quiet, collecting event notifications.
fn hearEvents(c: anytype, now: u64, out: []Heard) !usize {
    var n: usize = 0;
    while (true) {
        const ev = try c.poll(now);
        switch (ev) {
            .none => return n,
            .event_notification => |e| {
                out[n] = .{
                    .confirmed = e.confirmed,
                    .process = e.notification.process_id,
                    .to = e.notification.to_state,
                    .notify = e.notification.notify_type,
                    .ack_required = e.notification.ack_required,
                    .priority = e.notification.priority,
                    .seq = e.notification.time_stamp.sequence_number,
                };
                n += 1;
            },
            else => {},
        }
    }
}

fn pumpUntil(dev: anytype, c: anytype, now: u64, comptime tagname: []const u8) !client.Event {
    for (0..10) |_| {
        _ = try dev.poll(now);
        const ev = try c.poll(now);
        if (ev != .none and std.mem.eql(u8, @tagName(ev), tagname)) return ev;
    }
    return error.NoAnswer;
}

test "intrinsic reporting: limit crossed for the delay, notified, listed, acknowledged, back to normal" {
    var rig: Rig = .{};
    rig.wire();
    var adb: AlarmDb = .{};
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, adb.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const dev_addr = rig.device_ep.address;
    const ai1: ObjectId = .{ .type = .analog_input, .instance = 1 };
    var heard: [8]Heard = undefined;

    // Quiet while the value is inside the limits.
    try testing.expectEqual(Event.none, try dev.poll(0));
    try dev.update(ai1, .present_value, .{ .real = 90 }, 0);
    // Above the high limit, but only for 1 s of the 2 s delay.
    try testing.expectEqual(Event.none, try dev.poll(0));
    try testing.expectEqual(Event.none, try dev.poll(1_000));
    // A dip back inside restarts the delay.
    try dev.update(ai1, .present_value, .{ .real = 70 }, 1_500);
    try testing.expectEqual(Event.none, try dev.poll(1_500));
    try dev.update(ai1, .present_value, .{ .real = 90 }, 2_000);
    try testing.expectEqual(Event.none, try dev.poll(2_000));
    try testing.expectEqual(Event.none, try dev.poll(3_999));
    const tr = (try dev.poll(4_000)).event_transition;
    try testing.expectEqual(types.EventState.normal, tr.from);
    try testing.expectEqual(types.EventState.high_limit, tr.to);
    try testing.expectEqual(@as(u32, 3), adb.ai[11].value.enumerated);

    // Both destinations got one: the unconfirmed one to-offnormal (process 7) and the confirmed one (8).
    try testing.expectEqual(@as(usize, 2), try hearEvents(&c, 4_000, &heard));
    try testing.expect(!heard[0].confirmed and heard[0].process == 7);
    try testing.expect(heard[1].confirmed and heard[1].process == 8);
    try testing.expectEqual(types.EventState.high_limit, heard[0].to);
    try testing.expectEqual(events.NotifyType.alarm, heard[0].notify);
    try testing.expectEqual(@as(?bool, true), heard[0].ack_required);
    try testing.expectEqual(@as(u8, 100), heard[0].priority);
    try testing.expectEqual(@as(u32, 1), heard[0].seq);
    // The confirmed one was acknowledged by the client; the device takes it.
    _ = try dev.poll(4_000);

    // The properties follow the state machine: to-offnormal is waiting for an acknowledgement.
    try testing.expectEqual(@as(u8, 0x60), adb.ai[12].value.bit_string.bytes[0]);

    // GetEventInformation lists it with the time stamp, enable bits and priorities.
    _ = try c.getEventInformation(dev_addr, null, 4_001);
    var ev = try pumpUntil(&dev, &c, 4_001, "complex_ack");
    const gi = try events.GetEventInformationAck.decode(ev.complex_ack.data);
    try testing.expect(!gi.more_events);
    var it = gi.summaries();
    const sum = (try it.next()).?;
    try testing.expectEqual(types.EventState.high_limit, sum.state);
    try testing.expectEqual(@as(u3, 0b110), sum.acked_transitions.bits);
    try testing.expect(sum.time_stamps[0].eql(.{ .sequence_number = 1 }));
    try testing.expectEqual([3]u8{ 100, 150, 200 }, sum.priorities);
    try testing.expectEqual(@as(?events.EventSummary, null), try it.next());
    // Asking for the page after that object: nothing more.
    _ = try c.getEventInformation(dev_addr, ai1, 4_002);
    ev = try pumpUntil(&dev, &c, 4_002, "complex_ack");
    const none_after = try events.GetEventInformationAck.decode(ev.complex_ack.data);
    var none_it = none_after.summaries();
    try testing.expectEqual(@as(?events.EventSummary, null), try none_it.next());
    // After an unknown object: refused.
    _ = try c.getEventInformation(dev_addr, .{ .type = .analog_input, .instance = 77 }, 4_003);
    ev = try pumpUntil(&dev, &c, 4_003, "err");
    try testing.expectEqual(types.ErrorCode.unknown_object, ev.err.code);

    // GetAlarmSummary lists the same object.
    _ = try c.getAlarmSummary(dev_addr, 4_004);
    ev = try pumpUntil(&dev, &c, 4_004, "complex_ack");
    var sit = events.AlarmSummaryIterator.init(ev.complex_ack.data);
    const al = (try sit.next()).?;
    try testing.expectEqual(ai1, al.object);
    try testing.expectEqual(types.EventState.high_limit, al.state);
    try testing.expectEqual(@as(?events.AlarmSummary, null), try sit.next());

    // Acknowledging with the wrong state or the wrong time stamp is refused ...
    var ack: events.AcknowledgeAlarm = .{
        .process_id = 7,
        .event_object = ai1,
        .state = .low_limit,
        .time_stamp = .{ .sequence_number = 1 },
        .source = "op",
        .time_of_ack = .{ .sequence_number = 500 },
    };
    _ = try c.acknowledgeAlarm(dev_addr, ack, 4_005);
    ev = try pumpUntil(&dev, &c, 4_005, "err");
    try testing.expectEqual(types.ErrorCode.invalid_event_state, ev.err.code);
    ack.state = .high_limit;
    ack.time_stamp = .{ .sequence_number = 9 };
    _ = try c.acknowledgeAlarm(dev_addr, ack, 4_006);
    ev = try pumpUntil(&dev, &c, 4_006, "err");
    try testing.expectEqual(types.ErrorCode.invalid_time_stamp, ev.err.code);
    try testing.expectEqual(@as(u8, 0x60), adb.ai[12].value.bit_string.bytes[0]);
    // ... the right one succeeds and is itself announced (to both destinations).
    ack.time_stamp = .{ .sequence_number = 1 };
    _ = try c.acknowledgeAlarm(dev_addr, ack, 4_007);
    try testing.expectEqual(types.EventState.high_limit, (try dev.poll(4_007)).alarm_acknowledged.state);
    try testing.expectEqual(@as(u8, 0xE0), adb.ai[12].value.bit_string.bytes[0]);
    const simple = try c.poll(4_007);
    try testing.expectEqual(types.ConfirmedService.acknowledge_alarm, simple.simple_ack.svc);
    try testing.expectEqual(@as(usize, 2), try hearEvents(&c, 4_007, &heard));
    try testing.expectEqual(events.NotifyType.ack_notification, heard[0].notify);
    try testing.expectEqual(@as(?bool, null), heard[0].ack_required);
    try testing.expectEqual(@as(u32, 500), heard[0].seq);
    _ = try dev.poll(4_007);
    // Acknowledging again is a success that announces nothing.
    _ = try c.acknowledgeAlarm(dev_addr, ack, 4_008);
    _ = try pumpUntil(&dev, &c, 4_008, "simple_ack");
    try testing.expectEqual(@as(usize, 0), try hearEvents(&c, 4_008, &heard));

    // Inside the deadband (75..80) nothing happens; below it, after the delay, back to normal.
    try dev.update(ai1, .present_value, .{ .real = 78 }, 5_000);
    try testing.expectEqual(Event.none, try dev.poll(9_000));
    try dev.update(ai1, .present_value, .{ .real = 70 }, 9_000);
    try testing.expectEqual(Event.none, try dev.poll(9_000));
    const back = (try dev.poll(11_000)).event_transition;
    try testing.expectEqual(types.EventState.normal, back.to);
    // Only the first destination wants to-normal, and it asks for an acknowledgement.
    try testing.expectEqual(@as(usize, 1), try hearEvents(&c, 11_000, &heard));
    try testing.expectEqual(types.EventState.normal, heard[0].to);
    try testing.expectEqual(@as(u8, 200), heard[0].priority);
    try testing.expectEqual(@as(?bool, true), heard[0].ack_required);
    // No alarm is active any more, but the unacknowledged to-normal keeps it in the event list.
    _ = try c.getAlarmSummary(dev_addr, 11_001);
    ev = try pumpUntil(&dev, &c, 11_001, "complex_ack");
    try testing.expectEqual(@as(usize, 0), ev.complex_ack.data.len);
    _ = try c.getEventInformation(dev_addr, null, 11_002);
    ev = try pumpUntil(&dev, &c, 11_002, "complex_ack");
    const lastg = try events.GetEventInformationAck.decode(ev.complex_ack.data);
    var lit = lastg.summaries();
    const last = (try lit.next()).?;
    try testing.expectEqual(types.EventState.normal, last.state);
    try testing.expectEqual(@as(u3, 0b011), last.acked_transitions.bits);
}

test "intrinsic reporting: a disabled transition is not announced and needs no acknowledgement; no class, no notification" {
    var rig: Rig = .{};
    rig.wire();
    var adb: AlarmDb = .{};
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, adb.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});
    const ai1: ObjectId = .{ .type = .analog_input, .instance = 1 };
    var heard: [4]Heard = undefined;
    // to-offnormal disabled: Event_Enable = to-fault, to-normal only.
    adb.ai[7].value = .{ .bit_string = .{ .unused_bits = 5, .bytes = &.{0x60} } };
    try dev.update(ai1, .present_value, .{ .real = 5 }, 0); // below the low limit (10)
    _ = try dev.poll(0);
    try testing.expectEqual(types.EventState.low_limit, (try dev.poll(2_000)).event_transition.to);
    try testing.expectEqual(@as(usize, 0), try hearEvents(&c, 2_000, &heard));
    try testing.expectEqual(@as(u8, 0xE0), adb.ai[12].value.bit_string.bytes[0]);

    // An object that names a class that does not exist transitions silently.
    adb.ai[8].value = .{ .unsigned = 99 };
    adb.ai[7].value = .{ .bit_string = .{ .unused_bits = 5, .bytes = &.{0xE0} } };
    try dev.update(ai1, .present_value, .{ .real = 90 }, 3_000);
    _ = try dev.poll(3_000);
    try testing.expectEqual(types.EventState.high_limit, (try dev.poll(5_000)).event_transition.to);
    try testing.expectEqual(@as(usize, 0), try hearEvents(&c, 5_000, &heard));
}

test "an unsupported confirmed service is Rejected" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    _ = try c.readRange(
        rig.device_ep.address,
        .{ .type = .trend_log, .instance = 1 },
        .log_buffer,
        null,
        0,
    );
    _ = try dev.poll(0);
    const ev = try c.poll(1);
    try testing.expectEqual(types.RejectReason.unrecognized_service, ev.reject.reason);
}

test "garbage does not kill the device's poll loop" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());

    const junk = [_][]const u8{
        &.{0x00},
        &.{ 0x81, 0x0A, 0x00, 0x99, 0x01 },
        &.{ 0x81, 0x0A, 0x00, 0x06, 0x01, 0x80 }, // network message, no type
        &.{ 0x81, 0x0A, 0x00, 0x07, 0x01, 0x00, 0x00 }, // truncated confirmed request
        &.{ 0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x00, 0x05 },
    };
    for (junk) |j| rig.device_ep.inject(rig.client_ep.address, j);
    for (junk) |_| _ = try dev.poll(0);
    try testing.expectEqual(device_event_none, try dev.poll(0));

    // A ReadProperty whose body is nonsense gets a Reject, not silence.
    var a_buf: [32]u8 = undefined;
    const a = try apdu.encode(.{ .confirmed_request = .{
        .invoke_id = 8,
        .service = .read_property,
        .data = &.{ 0xFF, 0xFF },
    } }, &a_buf);
    var n_buf: [64]u8 = undefined;
    const n = try npdu.encode(.{}, a, &n_buf);
    var d_buf: [96]u8 = undefined;
    rig.device_ep.inject(
        rig.client_ep.address,
        try bvll.wrap(.original_unicast_npdu, n, &d_buf),
    );
    const ev = try dev.poll(0);
    try testing.expectEqual(types.ErrorCode.reject_invalid_tag, ev.refused.code);
}

test "a full subscription table is refused with a resources error" {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = Device(1).init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());
    var c = client.DefaultClient.init(rig.client_ep.transport(), .{});

    _ = try c.subscribeCov(rig.device_ep.address, 1, .{ .type = .analog_input, .instance = 5 }, false, 60, 0);
    try settle(&c, &dev, 0);
    _ = try c.subscribeCov(rig.device_ep.address, 2, .{ .type = .analog_value, .instance = 1 }, false, 60, 10);
    _ = try dev.poll(10);
    const ev = try c.poll(11);
    try testing.expectEqual(types.ErrorClass.resources, ev.err.class);
    try testing.expectEqual(types.ErrorCode.no_space_to_add_list_element, ev.err.code);

    // Renewing the *existing* subscription reuses its slot rather than
    // needing a free one.
    _ = try c.subscribeCov(rig.device_ep.address, 1, .{ .type = .analog_input, .instance = 5 }, false, 120, 20);
    _ = try dev.poll(20);
    const ev2 = try c.poll(21);
    try testing.expectEqual(types.ConfirmedService.subscribe_cov, ev2.simple_ack.svc);
    try testing.expectEqual(@as(usize, 1), dev.subscriptionCount());
}

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. Was a local copy in every file that needed it — 33 across 12
/// modules — each with its own note about the same trap (the array has to be
/// container-level or the returned slice dangles with the RIGHT length and
/// garbage behind it). It lives in `testkit.fuzz` now, with tests that drive the
/// real `std.testing.Smith` over what it produces.
const fuzzSeed = @import("testkit").fuzz.seedHex;
const fz = @import("fuzz_test.zig");

/// Whole BACnet/IP datagrams as they arrive on the wire — BVLC header, NPDU,
/// APDU — because that is what `inject` takes. Addressed at instance 599, which
/// is the device the rig below builds.
const device_seeds = [_][]const u8{
    fuzzSeed("810b000c0100100809011964"), // Who-Is, both limits
    fuzzSeed("810b000801001008"), // Who-Is, unrestricted
    fuzzSeed("810b001501001000c4020002572205c491032203e7"), // I-Am from a peer
    fuzzSeed("810a001101040005010c0c000000051955"), // confirmed ReadProperty, reply expected
    fuzzSeed("810a00090104000501"), // the same, truncated inside the APDU
    fuzzSeed("810a0009010020010f"), // a simple ACK nobody asked for
    fuzzSeed("81040012c0000205bac00100100809011964"), // Forwarded-NPDU
    fuzzSeed("81050006003c"), // Register-Foreign-Device at a device that is no BBMD
    fuzzSeed("810b000c0100100809011964ff"), // one octet past the declared length
    fuzzSeed("81ff0004"), // unknown BVLC function
    fuzzSeed("820b0004"), // not BACnet/IP at all
    fuzzSeed("810b0000"), // declared length zero
};

test "fuzz: the device never crashes on an arbitrary datagram" {
    try std.testing.fuzz({}, fuzzDeviceSmith, .{ .corpus = &device_seeds });
}

const fuzzDeviceMark = fz.Marker(enum { ran, nonempty });

fn fuzzDeviceSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzDevice(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzDevice(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());

    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length.
    // `Smith.bytes` consumes the whole remaining seed, and a ranged draw then
    // finds fewer than eight bytes left and returns the range MINIMUM — so the
    // length was 0 for every seed and the device was injected with a zero-byte
    // datagram, once. Measured over the corpus above: **0 of 12
    // non-empty and 0 that got past the BVLC header before, 12 of 12 non-empty
    // and 8 past it after.**
    const len: usize = fz.drawInput(S, src, &buf, &device_seeds);
    fuzzDeviceMark.mark(.ran);
    if (len != 0) fuzzDeviceMark.mark(.nonempty);
    rig.device_ep.inject(rig.client_ep.address, buf[0..len]);
    _ = dev.poll(0) catch {};
}

test "fuzz driver: BACNET_FUZZ (fuzzDevice)" {
    try fz.fuzz_driver.run(fuzzDevice, .{ .prefix = "BACNET_FUZZ", .name = "bacnet-device-device" });
}

test "fuzz harness: fuzzDevice, 400 seeds, reaches every outcome" {
    try fuzzDeviceMark.reach(fuzzDevice, "bacnet-device-device", 400);
}

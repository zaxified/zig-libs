// SPDX-License-Identifier: MIT

//! **Clause 15/16 — the services**, encoded and decoded on top of `tag`.
//!
//! Two conventions run through the whole file and are worth stating once:
//!
//! * **A "value" is never interpreted here.** `ReadProperty-ACK`'s
//!   `propertyValue`, `WriteProperty`'s value and a COV notification's values
//!   are `ABSTRACT-SYNTAX.&Type` in the standard: their datatype comes from the
//!   *property*, not from the wire, and only a device's own object model knows
//!   it. They are therefore handed back as the **raw tagged octets between the
//!   opening and closing brackets**, borrowed from the input, with
//!   `tag.Reader` available to walk them. Guessing a type from the tag alone
//!   is how a client ends up reading a two-element array as a scalar.
//! * **Optional parameters are `?T`, and their absence is meaningful.** A
//!   `SubscribeCOV` with neither `issueConfirmedNotifications` nor `lifetime`
//!   is a *cancellation*, not a subscription with defaults — so those two
//!   fields being optional is load-bearing, not tidiness.
//!
//! Nothing here allocates.

const std = @import("std");
const types = @import("types.zig");
const tag = @import("tag.zig");

pub const Error = tag.Error || error{
    /// A mandatory parameter is missing, or one appeared that the service does
    /// not define.
    MissingParameter,
    /// A parameter is present but impossible: a device instance above 2^22-1,
    /// a priority outside 1..16, or a wire integer too wide for the field it
    /// would land in (see `narrow`).
    InvalidParameter,
};

const ObjectId = tag.ObjectId;
const PropertyIdentifier = types.PropertyIdentifier;

/// The maximum BACnet device instance number (2^22 - 1). Instance
/// `4194303` is reserved for an unconfigured device and is also what a
/// `Who-Is` uses as its "no upper bound" sentinel.
pub const max_instance: u32 = 0x3FFFFF;

/// Narrows a **wire-supplied** integer to the width of the field it lands in,
/// refusing a value that does not fit instead of truncating it.
///
/// Every conversion in this file of a decoded 64-bit wire integer to a
/// narrower field goes through here. A bare `@intCast` is wrong twice over:
/// in Debug/ReleaseSafe it *panics*, so an unauthenticated 14-octet datagram
/// kills the device; in ReleaseFast it *silently wraps*, so a peer asking for
/// array index 2^32 is served index 0 — which in BACnet is not the first
/// element but the array's **length**, an entirely different read.
///
/// `error.InvalidParameter` is the same answer the hand-guarded sites already
/// give (`WhoIs.decode`, `IAm.decode`, `WriteProperty`'s priority), so the
/// reject path a peer sees does not depend on which parameter was oversized.
fn narrow(comptime T: type, v: anytype) Error!T {
    const V = @TypeOf(v);
    if (@typeInfo(V).int.signedness == .signed and v < std.math.minInt(T)) {
        return error.InvalidParameter;
    }
    if (v > std.math.maxInt(T)) return error.InvalidParameter;
    return @intCast(v);
}

// ── Who-Is / I-Am (clause 16.10, 16.11) ────────────────────────────────────

/// `Who-Is` — the discovery broadcast. With no limits it asks every device on
/// the internetwork to answer; with limits it asks only devices whose instance
/// falls in `[low, high]`. Both limits are present or both absent; one alone
/// is malformed.
pub const WhoIs = struct {
    low: ?u32 = null,
    high: ?u32 = null,

    pub fn encode(self: WhoIs, w: *tag.Writer) Error!void {
        if ((self.low == null) != (self.high == null)) return error.InvalidParameter;
        const lo = self.low orelse return;
        const hi = self.high.?;
        if (lo > max_instance or hi > max_instance) return error.InvalidParameter;
        try w.ctxUnsigned(0, lo);
        try w.ctxUnsigned(1, hi);
    }

    pub fn decode(data: []const u8) Error!WhoIs {
        var r = tag.Reader.init(data);
        if (r.atEnd()) return .{};
        const lo = try r.ctxUnsigned(0);
        const hi = try r.ctxUnsigned(1);
        if (lo > max_instance or hi > max_instance) return error.InvalidParameter;
        return .{ .low = @intCast(lo), .high = @intCast(hi) };
    }

    /// True when `instance` should answer this Who-Is.
    pub fn matches(self: WhoIs, instance: u32) bool {
        const lo = self.low orelse return true;
        return instance >= lo and instance <= (self.high orelse max_instance);
    }
};

/// `I-Am` — the answer to Who-Is, and also what a device broadcasts when it
/// restarts. All four parameters are **application**-tagged (no context tags),
/// which is unusual enough to be worth noticing when reading the wire.
pub const IAm = struct {
    device: ObjectId,
    max_apdu_accepted: u32,
    segmentation: types.Segmentation,
    vendor_id: u16,

    pub fn encode(self: IAm, w: *tag.Writer) Error!void {
        try w.appObjectId(self.device);
        try w.appUnsigned(self.max_apdu_accepted);
        try w.appEnumerated(@intFromEnum(self.segmentation));
        try w.appUnsigned(self.vendor_id);
    }

    pub fn decode(data: []const u8) Error!IAm {
        var r = tag.Reader.init(data);
        const oid = (try r.expectApp(.object_identifier)).object_identifier;
        const max_apdu = (try r.expectApp(.unsigned)).unsigned;
        const seg = (try r.expectApp(.enumerated)).enumerated;
        const vendor = (try r.expectApp(.unsigned)).unsigned;
        if (max_apdu > std.math.maxInt(u32)) return error.InvalidParameter;
        if (seg > std.math.maxInt(u8)) return error.InvalidParameter;
        if (vendor > std.math.maxInt(u16)) return error.InvalidParameter;
        return .{
            .device = oid,
            .max_apdu_accepted = @intCast(max_apdu),
            .segmentation = @enumFromInt(@as(u8, @intCast(seg))),
            .vendor_id = @intCast(vendor),
        };
    }
};

// ── Who-Has / I-Have (clause 16.9, 16.8) ───────────────────────────────────

/// `Who-Has` — "which device holds this object?", by identifier or by name.
pub const WhoHas = struct {
    low: ?u32 = null,
    high: ?u32 = null,
    target: Target,

    pub const Target = union(enum) {
        /// Context tag 2.
        object_id: ObjectId,
        /// Context tag 3, with the character-string encoding octet.
        object_name: []const u8,
    };

    pub fn encode(self: WhoHas, w: *tag.Writer) Error!void {
        if ((self.low == null) != (self.high == null)) return error.InvalidParameter;
        if (self.low) |lo| {
            try w.ctxUnsigned(0, lo);
            try w.ctxUnsigned(1, self.high.?);
        }
        switch (self.target) {
            .object_id => |o| try w.ctxObjectId(2, o),
            .object_name => |n| try w.ctxString(3, n),
        }
    }

    pub fn decode(data: []const u8) Error!WhoHas {
        var r = tag.Reader.init(data);
        var out: WhoHas = .{ .target = .{ .object_id = .{ .type = .device, .instance = 0 } } };
        var t = try r.peek();
        if (t.isContext(0)) {
            out.low = try narrow(u32, try r.ctxUnsigned(0));
            out.high = try narrow(u32, try r.ctxUnsigned(1));
            t = try r.peek();
        }
        if (t.isContext(2)) {
            out.target = .{ .object_id = try r.ctxObjectId(2) };
        } else if (t.isContext(3)) {
            out.target = .{ .object_name = (try r.ctxString(3)).bytes };
        } else return error.MissingParameter;
        return out;
    }
};

/// `I-Have` — the answer to Who-Has. Application-tagged like `I-Am`.
pub const IHave = struct {
    device: ObjectId,
    object: ObjectId,
    object_name: []const u8,

    pub fn encode(self: IHave, w: *tag.Writer) Error!void {
        try w.appObjectId(self.device);
        try w.appObjectId(self.object);
        try w.appString(self.object_name);
    }

    pub fn decode(data: []const u8) Error!IHave {
        var r = tag.Reader.init(data);
        return .{
            .device = (try r.expectApp(.object_identifier)).object_identifier,
            .object = (try r.expectApp(.object_identifier)).object_identifier,
            .object_name = (try r.expectApp(.character_string)).character_string.bytes,
        };
    }
};

// ── ReadProperty (clause 15.5) ─────────────────────────────────────────────

/// `ReadProperty` request: object, property, and an optional array index.
/// **Array index 0 is not "the first element"** — it is the array's *length*,
/// which is why the index is `?u32` and not a `u32` defaulting to zero.
pub const ReadProperty = struct {
    object: ObjectId,
    property: PropertyIdentifier,
    array_index: ?u32 = null,

    pub fn encode(self: ReadProperty, w: *tag.Writer) Error!void {
        try w.ctxObjectId(0, self.object);
        try w.ctxEnumerated(1, @intFromEnum(self.property));
        if (self.array_index) |i| try w.ctxUnsigned(2, i);
    }

    pub fn decode(data: []const u8) Error!ReadProperty {
        var r = tag.Reader.init(data);
        const obj = try r.ctxObjectId(0);
        const prop: PropertyIdentifier = @enumFromInt(try r.ctxEnumerated(1));
        var idx: ?u32 = null;
        if (!r.atEnd()) {
            const t = try r.peek();
            if (t.isContext(2)) idx = try narrow(u32, try r.ctxUnsigned(2));
        }
        return .{ .object = obj, .property = prop, .array_index = idx };
    }
};

/// `ReadProperty-ACK`. `value` is the raw tagged block between `[3]` and
/// `]3` — see the note at the top of this file about why it is not decoded.
pub const ReadPropertyAck = struct {
    object: ObjectId,
    property: PropertyIdentifier,
    array_index: ?u32 = null,
    value: []const u8,

    pub fn encode(self: ReadPropertyAck, w: *tag.Writer) Error!void {
        try w.ctxObjectId(0, self.object);
        try w.ctxEnumerated(1, @intFromEnum(self.property));
        if (self.array_index) |i| try w.ctxUnsigned(2, i);
        try w.open(3);
        try w.raw(self.value);
        try w.close(3);
    }

    pub fn decode(data: []const u8) Error!ReadPropertyAck {
        var r = tag.Reader.init(data);
        const obj = try r.ctxObjectId(0);
        const prop: PropertyIdentifier = @enumFromInt(try r.ctxEnumerated(1));
        var idx: ?u32 = null;
        var t = try r.peek();
        if (t.isContext(2)) {
            idx = try narrow(u32, try r.ctxUnsigned(2));
            t = try r.peek();
        }
        return .{
            .object = obj,
            .property = prop,
            .array_index = idx,
            .value = try r.openedBlock(3),
        };
    }

    /// The value as a single application-tagged datum, for the common case of
    /// a scalar property. `error.UnexpectedTag` when the block holds something
    /// richer (a list, a constructed type) — which is the right answer, not a
    /// reason to reach into `value` blindly.
    pub fn scalar(self: ReadPropertyAck) Error!tag.Value {
        var r = tag.Reader.init(self.value);
        const v = try r.appValue();
        if (!r.atEnd()) return error.UnexpectedTag;
        return v;
    }
};

// ── WriteProperty (clause 15.9) ────────────────────────────────────────────

/// `WriteProperty`. Two things make this service more than a mirror of
/// ReadProperty:
///
/// * **`priority`** selects a slot in the object's 16-element *priority
///   array*. 1 is highest (manual life safety), 16 lowest; 8 is the
///   conventional "manual operator" level. Absent means "write the
///   relinquish-default level".
/// * **Writing `Null` at a priority does not write null** — it *relinquishes*
///   that slot, letting the next-lower priority take over. That is why
///   `relinquish()` exists as its own constructor: it is a different
///   operation with the same encoding.
pub const WriteProperty = struct {
    object: ObjectId,
    property: PropertyIdentifier,
    array_index: ?u32 = null,
    /// Raw tagged octets for the `[3] ... ]3` block.
    value: []const u8,
    priority: ?u8 = null,

    /// A write that gives up control of `priority`, letting the next-lower
    /// priority (ultimately `relinquish_default`) drive the output.
    pub fn relinquish(object: ObjectId, property: PropertyIdentifier, priority: u8) WriteProperty {
        return .{
            .object = object,
            .property = property,
            // The application-tagged Null primitive: one octet, 0x00.
            .value = &[_]u8{0x00},
            .priority = priority,
        };
    }

    pub fn encode(self: WriteProperty, w: *tag.Writer) Error!void {
        if (self.priority) |p| {
            if (p < 1 or p > 16) return error.InvalidParameter;
        }
        try w.ctxObjectId(0, self.object);
        try w.ctxEnumerated(1, @intFromEnum(self.property));
        if (self.array_index) |i| try w.ctxUnsigned(2, i);
        try w.open(3);
        try w.raw(self.value);
        try w.close(3);
        if (self.priority) |p| try w.ctxUnsigned(4, p);
    }

    pub fn decode(data: []const u8) Error!WriteProperty {
        var r = tag.Reader.init(data);
        const obj = try r.ctxObjectId(0);
        const prop: PropertyIdentifier = @enumFromInt(try r.ctxEnumerated(1));
        var idx: ?u32 = null;
        var t = try r.peek();
        if (t.isContext(2)) {
            idx = try narrow(u32, try r.ctxUnsigned(2));
        }
        const value = try r.openedBlock(3);
        var prio: ?u8 = null;
        if (!r.atEnd()) {
            t = try r.peek();
            if (t.isContext(4)) {
                const p = try r.ctxUnsigned(4);
                if (p < 1 or p > 16) return error.InvalidParameter;
                prio = @intCast(p);
            }
        }
        return .{
            .object = obj,
            .property = prop,
            .array_index = idx,
            .value = value,
            .priority = prio,
        };
    }

    /// True when this write relinquishes rather than sets: the value block is
    /// a single application `Null`.
    pub fn isRelinquish(self: WriteProperty) bool {
        return self.value.len == 1 and self.value[0] == 0x00;
    }
};

// ── ReadPropertyMultiple (clause 15.7) ─────────────────────────────────────
//
// The list-of-lists shape is what makes RPM awkward: a request is a sequence
// of (object, [property references]) and the ACK is a sequence of
// (object, [(property, value-or-error)]). Both are modelled as builders +
// iterators rather than as slices of structs, so the whole thing stays
// allocation-free and borrows from the caller's buffer.

/// One property reference inside an RPM request: a property, optionally an
/// array index. `property` may be one of the three **special** identifiers
/// (`all`, `required`, `optional`), which stand for whole groups.
pub const PropertyReference = struct {
    property: PropertyIdentifier,
    array_index: ?u32 = null,
};

/// Builds a `ReadPropertyMultiple` request into a `tag.Writer`.
pub const RpmRequestBuilder = struct {
    w: *tag.Writer,
    open_spec: bool = false,

    pub fn init(w: *tag.Writer) RpmRequestBuilder {
        return .{ .w = w };
    }

    /// Starts a new read-access specification for `object`.
    pub fn object(self: *RpmRequestBuilder, oid: ObjectId) Error!void {
        if (self.open_spec) try self.endObject();
        try self.w.ctxObjectId(0, oid);
        try self.w.open(1);
        self.open_spec = true;
    }

    /// Adds a property reference to the current specification.
    pub fn property(self: *RpmRequestBuilder, ref: PropertyReference) Error!void {
        if (!self.open_spec) return error.MissingParameter;
        try self.w.ctxEnumerated(0, @intFromEnum(ref.property));
        if (ref.array_index) |i| try self.w.ctxUnsigned(1, i);
    }

    fn endObject(self: *RpmRequestBuilder) Error!void {
        try self.w.close(1);
        self.open_spec = false;
    }

    /// Closes the last specification. Must be called before the request is
    /// sent; forgetting it produces an unterminated constructed block, which
    /// the peer will reject.
    pub fn finish(self: *RpmRequestBuilder) Error!void {
        if (self.open_spec) try self.endObject();
    }
};

/// Walks the read-access specifications of an RPM request.
pub const RpmRequestIterator = struct {
    r: tag.Reader,

    pub fn init(data: []const u8) RpmRequestIterator {
        return .{ .r = tag.Reader.init(data) };
    }

    pub const Spec = struct {
        object: ObjectId,
        /// Raw octets of the `[1] ... ]1` block; walk with `properties`.
        references: []const u8,

        pub fn properties(self: Spec) PropertyReferenceIterator {
            return .{ .r = tag.Reader.init(self.references) };
        }
    };

    pub fn next(self: *RpmRequestIterator) Error!?Spec {
        if (self.r.atEnd()) return null;
        const oid = try self.r.ctxObjectId(0);
        return .{ .object = oid, .references = try self.r.openedBlock(1) };
    }
};

pub const PropertyReferenceIterator = struct {
    r: tag.Reader,

    pub fn next(self: *PropertyReferenceIterator) Error!?PropertyReference {
        if (self.r.atEnd()) return null;
        const prop: PropertyIdentifier = @enumFromInt(try self.r.ctxEnumerated(0));
        var idx: ?u32 = null;
        if (!self.r.atEnd()) {
            const t = try self.r.peek();
            if (t.isContext(1)) idx = try narrow(u32, try self.r.ctxUnsigned(1));
        }
        return .{ .property = prop, .array_index = idx };
    }
};

/// Builds a `ReadPropertyMultiple-ACK`.
pub const RpmAckBuilder = struct {
    w: *tag.Writer,
    open_result: bool = false,

    pub fn init(w: *tag.Writer) RpmAckBuilder {
        return .{ .w = w };
    }

    pub fn object(self: *RpmAckBuilder, oid: ObjectId) Error!void {
        if (self.open_result) try self.endObject();
        try self.w.ctxObjectId(0, oid);
        try self.w.open(1);
        self.open_result = true;
    }

    /// A property that read successfully: `value` is raw tagged octets.
    pub fn value(
        self: *RpmAckBuilder,
        prop: PropertyIdentifier,
        array_index: ?u32,
        bytes: []const u8,
    ) Error!void {
        if (!self.open_result) return error.MissingParameter;
        try self.w.ctxEnumerated(2, @intFromEnum(prop));
        if (array_index) |i| try self.w.ctxUnsigned(3, i);
        try self.w.open(4);
        try self.w.raw(bytes);
        try self.w.close(4);
    }

    /// A property that failed. Per-property errors are the whole reason RPM
    /// exists: one unreadable property must not fail the other twenty.
    pub fn accessError(
        self: *RpmAckBuilder,
        prop: PropertyIdentifier,
        array_index: ?u32,
        class: types.ErrorClass,
        code: types.ErrorCode,
    ) Error!void {
        if (!self.open_result) return error.MissingParameter;
        try self.w.ctxEnumerated(2, @intFromEnum(prop));
        if (array_index) |i| try self.w.ctxUnsigned(3, i);
        try self.w.open(5);
        try self.w.appEnumerated(@intFromEnum(class));
        try self.w.appEnumerated(@intFromEnum(code));
        try self.w.close(5);
    }

    fn endObject(self: *RpmAckBuilder) Error!void {
        try self.w.close(1);
        self.open_result = false;
    }

    pub fn finish(self: *RpmAckBuilder) Error!void {
        if (self.open_result) try self.endObject();
    }
};

/// Walks the read-access results of an RPM ACK.
pub const RpmAckIterator = struct {
    r: tag.Reader,

    pub fn init(data: []const u8) RpmAckIterator {
        return .{ .r = tag.Reader.init(data) };
    }

    pub const Result = struct {
        object: ObjectId,
        /// Raw octets of the `[1] ... ]1` block; walk with `results`.
        elements: []const u8,

        pub fn results(self: Result) ResultElementIterator {
            return .{ .r = tag.Reader.init(self.elements) };
        }
    };

    pub fn next(self: *RpmAckIterator) Error!?Result {
        if (self.r.atEnd()) return null;
        const oid = try self.r.ctxObjectId(0);
        return .{ .object = oid, .elements = try self.r.openedBlock(1) };
    }
};

/// One (property, value-or-error) pair from an RPM ACK.
pub const ResultElement = struct {
    property: PropertyIdentifier,
    array_index: ?u32 = null,
    outcome: Outcome,

    pub const Outcome = union(enum) {
        /// Raw tagged octets between `[4]` and `]4`.
        value: []const u8,
        access_error: struct { class: types.ErrorClass, code: types.ErrorCode },
    };
};

pub const ResultElementIterator = struct {
    r: tag.Reader,

    pub fn next(self: *ResultElementIterator) Error!?ResultElement {
        if (self.r.atEnd()) return null;
        const prop: PropertyIdentifier = @enumFromInt(try self.r.ctxEnumerated(2));
        var idx: ?u32 = null;
        var t = try self.r.peek();
        if (t.isContext(3)) {
            idx = try narrow(u32, try self.r.ctxUnsigned(3));
            t = try self.r.peek();
        }
        if (t.isOpening(4)) {
            return .{
                .property = prop,
                .array_index = idx,
                .outcome = .{ .value = try self.r.openedBlock(4) },
            };
        }
        if (t.isOpening(5)) {
            const body = try self.r.openedBlock(5);
            var er = tag.Reader.init(body);
            const class = (try er.expectApp(.enumerated)).enumerated;
            const code = (try er.expectApp(.enumerated)).enumerated;
            if (class > std.math.maxInt(u16) or code > std.math.maxInt(u16)) {
                return error.InvalidParameter;
            }
            return .{
                .property = prop,
                .array_index = idx,
                .outcome = .{ .access_error = .{
                    .class = @enumFromInt(@as(u16, @intCast(class))),
                    .code = @enumFromInt(@as(u16, @intCast(code))),
                } },
            };
        }
        return error.UnexpectedTag;
    }
};

// ── SubscribeCOV + notifications (clause 13.14, 13.1, 13.2) ────────────────

/// `SubscribeCOV`. The **cancellation** form omits both
/// `issueConfirmedNotifications` and `lifetime`; sending either one turns it
/// back into a subscription, so they move together.
pub const SubscribeCov = struct {
    /// The subscriber's handle for this subscription. It comes back in every
    /// notification, which is how one client distinguishes its subscriptions.
    process_id: u32,
    object: ObjectId,
    /// Null = this is a cancellation.
    confirmed: ?bool = null,
    /// Seconds. 0 means "indefinite" (until cancelled or the device restarts);
    /// null means this is a cancellation.
    lifetime: ?u32 = null,

    pub fn cancel(process_id: u32, object: ObjectId) SubscribeCov {
        return .{ .process_id = process_id, .object = object };
    }

    pub fn isCancellation(self: SubscribeCov) bool {
        return self.confirmed == null and self.lifetime == null;
    }

    pub fn encode(self: SubscribeCov, w: *tag.Writer) Error!void {
        if ((self.confirmed == null) != (self.lifetime == null)) return error.InvalidParameter;
        try w.ctxUnsigned(0, self.process_id);
        try w.ctxObjectId(1, self.object);
        if (self.confirmed) |c| {
            try w.ctxBool(2, c);
            try w.ctxUnsigned(3, self.lifetime.?);
        }
    }

    pub fn decode(data: []const u8) Error!SubscribeCov {
        var r = tag.Reader.init(data);
        const pid = try r.ctxUnsigned(0);
        const obj = try r.ctxObjectId(1);
        if (r.atEnd()) {
            return .{ .process_id = try narrow(u32, pid), .object = obj };
        }
        const c = try r.ctxBool(2);
        const lt = try r.ctxUnsigned(3);
        return .{
            .process_id = try narrow(u32, pid),
            .object = obj,
            .confirmed = c,
            .lifetime = try narrow(u32, lt),
        };
    }
};

/// One `(property, value)` pair inside a COV notification's list.
pub const CovValue = struct {
    property: PropertyIdentifier,
    array_index: ?u32 = null,
    /// Raw tagged octets between `[2]` and `]2`.
    value: []const u8,
    priority: ?u8 = null,
};

/// A COV notification. Confirmed and unconfirmed forms have **identical**
/// parameters; only the APDU type and service choice differ, so one struct
/// covers both.
pub const CovNotification = struct {
    process_id: u32,
    initiating_device: ObjectId,
    monitored_object: ObjectId,
    /// Seconds left on the subscription. 0 for an indefinite one.
    time_remaining: u32,
    /// Raw octets of the `[4] ... ]4` list block; walk with `values`.
    values_block: []const u8,

    pub fn values(self: CovNotification) CovValueIterator {
        return .{ .r = tag.Reader.init(self.values_block) };
    }

    pub fn decode(data: []const u8) Error!CovNotification {
        var r = tag.Reader.init(data);
        return .{
            .process_id = try narrow(u32, try r.ctxUnsigned(0)),
            .initiating_device = try r.ctxObjectId(1),
            .monitored_object = try r.ctxObjectId(2),
            .time_remaining = try narrow(u32, try r.ctxUnsigned(3)),
            .values_block = try r.openedBlock(4),
        };
    }

    pub fn encode(self: CovNotification, w: *tag.Writer) Error!void {
        try w.ctxUnsigned(0, self.process_id);
        try w.ctxObjectId(1, self.initiating_device);
        try w.ctxObjectId(2, self.monitored_object);
        try w.ctxUnsigned(3, self.time_remaining);
        try w.open(4);
        try w.raw(self.values_block);
        try w.close(4);
    }
};

pub const CovValueIterator = struct {
    r: tag.Reader,

    pub fn next(self: *CovValueIterator) Error!?CovValue {
        if (self.r.atEnd()) return null;
        const prop: PropertyIdentifier = @enumFromInt(try self.r.ctxEnumerated(0));
        var idx: ?u32 = null;
        var t = try self.r.peek();
        if (t.isContext(1)) {
            idx = try narrow(u32, try self.r.ctxUnsigned(1));
            t = try self.r.peek();
        }
        const value = try self.r.openedBlock(2);
        var prio: ?u8 = null;
        if (!self.r.atEnd()) {
            t = try self.r.peek();
            if (t.isContext(3)) prio = try narrow(u8, try self.r.ctxUnsigned(3));
        }
        return .{ .property = prop, .array_index = idx, .value = value, .priority = prio };
    }
};

/// Writes one `(property, value)` pair into a COV notification's list block.
pub fn writeCovValue(w: *tag.Writer, v: CovValue) Error!void {
    try w.ctxEnumerated(0, @intFromEnum(v.property));
    if (v.array_index) |i| try w.ctxUnsigned(1, i);
    try w.open(2);
    try w.raw(v.value);
    try w.close(2);
    if (v.priority) |p| try w.ctxUnsigned(3, p);
}

// ── ReadRange (clause 15.8) ────────────────────────────────────────────────

/// `ReadRange` — pulls a slice of a list property, which is how trend-log and
/// event-log buffers are read without asking for megabytes at once. The range
/// selector is a CHOICE of three constructed alternatives, distinguished by
/// their context tag number (3, 6 or 7); omitting it reads everything.
pub const ReadRange = struct {
    object: ObjectId,
    property: PropertyIdentifier,
    array_index: ?u32 = null,
    range: ?Range = null,

    pub const Range = union(enum) {
        /// `[3]` — start at a 1-based index; a negative count reads backwards.
        by_position: struct { reference_index: u32, count: i32 },
        /// `[6]` — start at a timestamp.
        by_time: struct { time: DateTime, count: i32 },
        /// `[7]` — start at a log record's sequence number.
        by_sequence: struct { sequence_number: u32, count: i32 },
    };

    pub fn encode(self: ReadRange, w: *tag.Writer) Error!void {
        try w.ctxObjectId(0, self.object);
        try w.ctxEnumerated(1, @intFromEnum(self.property));
        if (self.array_index) |i| try w.ctxUnsigned(2, i);
        const range = self.range orelse return;
        switch (range) {
            .by_position => |p| {
                try w.open(3);
                try w.appUnsigned(p.reference_index);
                try w.appSigned(p.count);
                try w.close(3);
            },
            .by_time => |t| {
                try w.open(6);
                try t.time.encode(w);
                try w.appSigned(t.count);
                try w.close(6);
            },
            .by_sequence => |s| {
                try w.open(7);
                try w.appUnsigned(s.sequence_number);
                try w.appSigned(s.count);
                try w.close(7);
            },
        }
    }

    pub fn decode(data: []const u8) Error!ReadRange {
        var r = tag.Reader.init(data);
        const obj = try r.ctxObjectId(0);
        const prop: PropertyIdentifier = @enumFromInt(try r.ctxEnumerated(1));
        var idx: ?u32 = null;
        var out: ReadRange = .{ .object = obj, .property = prop };
        if (r.atEnd()) return out;
        var t = try r.peek();
        if (t.isContext(2)) {
            idx = try narrow(u32, try r.ctxUnsigned(2));
            out.array_index = idx;
            if (r.atEnd()) return out;
            t = try r.peek();
        }
        if (t.isOpening(3)) {
            const body = try r.openedBlock(3);
            var br = tag.Reader.init(body);
            const ref = (try br.expectApp(.unsigned)).unsigned;
            const count = (try br.expectApp(.signed)).signed;
            out.range = .{ .by_position = .{
                .reference_index = try narrow(u32, ref),
                .count = try narrow(i32, count),
            } };
        } else if (t.isOpening(7)) {
            const body = try r.openedBlock(7);
            var br = tag.Reader.init(body);
            const seq = (try br.expectApp(.unsigned)).unsigned;
            const count = (try br.expectApp(.signed)).signed;
            out.range = .{ .by_sequence = .{
                .sequence_number = try narrow(u32, seq),
                .count = try narrow(i32, count),
            } };
        } else if (t.isOpening(6)) {
            const body = try r.openedBlock(6);
            var br = tag.Reader.init(body);
            const dt = try DateTime.decodeFrom(&br);
            const count = (try br.expectApp(.signed)).signed;
            out.range = .{ .by_time = .{ .time = dt, .count = try narrow(i32, count) } };
        }
        return out;
    }
};

/// `BACnetDateTime` (clause 21) — a Date immediately followed by a Time, both
/// application-tagged. It is a *sequence*, not a constructed block, so there
/// are no brackets around it.
pub const DateTime = struct {
    date: tag.Date,
    time: tag.Time,

    pub fn encode(self: DateTime, w: *tag.Writer) Error!void {
        try w.appDate(self.date);
        try w.appTime(self.time);
    }

    pub fn decodeFrom(r: *tag.Reader) Error!DateTime {
        return .{
            .date = (try r.expectApp(.date)).date,
            .time = (try r.expectApp(.time)).time,
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn enc(svc: anytype, buf: []u8) ![]const u8 {
    var w = tag.Writer.init(buf);
    try svc.encode(&w);
    return w.written();
}

test "Who-Is: unbounded, ranged and single" {
    var buf: [32]u8 = undefined;

    try testing.expectEqualSlices(u8, &.{}, try enc(WhoIs{}, &buf));
    try testing.expectEqualSlices(u8, &hex("09011964"), try enc(WhoIs{ .low = 1, .high = 100 }, &buf));
    try testing.expectEqualSlices(u8, &hex("0a02571a0257"), try enc(WhoIs{ .low = 599, .high = 599 }, &buf));
    try testing.expectEqualSlices(u8, &hex("09001b3fffff"), try enc(WhoIs{ .low = 0, .high = 4194303 }, &buf));

    const w = try WhoIs.decode(&hex("09011964"));
    try testing.expectEqual(@as(?u32, 1), w.low);
    try testing.expectEqual(@as(?u32, 100), w.high);
    try testing.expect(w.matches(1) and w.matches(100) and w.matches(50));
    try testing.expect(!w.matches(0) and !w.matches(101));

    const all = try WhoIs.decode(&.{});
    try testing.expect(all.matches(0) and all.matches(4194303));

    // One limit without the other is malformed on encode ...
    try testing.expectError(error.InvalidParameter, enc(WhoIs{ .low = 1 }, &buf));
    // ... and truncated on decode.
    try testing.expectError(error.Truncated, WhoIs.decode(&hex("0901")));
    try testing.expectError(error.InvalidParameter, enc(WhoIs{ .low = 0, .high = 4194304 }, &buf));
}

test "I-Am is entirely application-tagged" {
    var buf: [32]u8 = undefined;
    const iam: IAm = .{
        .device = .{ .type = .device, .instance = 599 },
        .max_apdu_accepted = 1476,
        .segmentation = .none,
        .vendor_id = 999,
    };
    try testing.expectEqualSlices(u8, &hex("c4020002572205c491032203e7"), try enc(iam, &buf));

    const back = try IAm.decode(&hex("c4020002572205c491032203e7"));
    try testing.expect(back.device.eql(iam.device));
    try testing.expectEqual(@as(u32, 1476), back.max_apdu_accepted);
    try testing.expectEqual(types.Segmentation.none, back.segmentation);
    try testing.expectEqual(@as(u16, 999), back.vendor_id);

    // An unconfigured device advertising segmentation.
    const seg = try IAm.decode(&hex("c4023fffff2201e09100210f"));
    try testing.expectEqual(tag.ObjectId.unconfigured_instance, seg.device.instance);
    try testing.expectEqual(types.Segmentation.both, seg.segmentation);
    try testing.expectEqual(@as(u16, 15), seg.vendor_id);

    // Context tags where application tags belong.
    try testing.expectError(error.UnexpectedTag, IAm.decode(&hex("0c02000257")));
}

test "Who-Has by name and by identifier; I-Have" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        &hex("3d0a005a4f4e452d54454d50"),
        try enc(WhoHas{ .target = .{ .object_name = "ZONE-TEMP" } }, &buf),
    );
    try testing.expectEqualSlices(
        u8,
        &hex("090119642c00000003"),
        try enc(WhoHas{
            .low = 1,
            .high = 100,
            .target = .{ .object_id = .{ .type = .analog_input, .instance = 3 } },
        }, &buf),
    );

    const byname = try WhoHas.decode(&hex("3d0a005a4f4e452d54454d50"));
    try testing.expectEqualStrings("ZONE-TEMP", byname.target.object_name);
    try testing.expectEqual(@as(?u32, null), byname.low);

    const byid = try WhoHas.decode(&hex("090119642c00000003"));
    try testing.expectEqual(@as(?u32, 1), byid.low);
    try testing.expect(byid.target.object_id.eql(.{ .type = .analog_input, .instance = 3 }));

    // Limits present, but the target is neither a `[2]` object id nor a `[3]`
    // name — the one case that is genuinely "missing a parameter" rather than
    // simply truncated.
    try testing.expectError(error.MissingParameter, WhoHas.decode(&hex("090119642100")));
    try testing.expectError(error.Truncated, WhoHas.decode(&hex("0901")));

    const ih: IHave = .{
        .device = .{ .type = .device, .instance = 599 },
        .object = .{ .type = .analog_input, .instance = 3 },
        .object_name = "ZONE-TEMP",
    };
    try testing.expectEqualSlices(
        u8,
        &hex("c402000257c400000003750a005a4f4e452d54454d50"),
        try enc(ih, &buf),
    );
    const ihb = try IHave.decode(&hex("c402000257c400000003750a005a4f4e452d54454d50"));
    try testing.expectEqualStrings("ZONE-TEMP", ihb.object_name);
}

test "ReadProperty request and ACK, with and without an array index" {
    var buf: [64]u8 = undefined;
    const rp: ReadProperty = .{
        .object = .{ .type = .analog_input, .instance = 5 },
        .property = .present_value,
    };
    try testing.expectEqualSlices(u8, &hex("0c000000051955"), try enc(rp, &buf));

    const rp2: ReadProperty = .{
        .object = .{ .type = .device, .instance = 599 },
        .property = .object_list,
        .array_index = 2,
    };
    try testing.expectEqualSlices(u8, &hex("0c02000257194c2902"), try enc(rp2, &buf));

    const back = try ReadProperty.decode(&hex("0c02000257194c2902"));
    try testing.expectEqual(PropertyIdentifier.object_list, back.property);
    try testing.expectEqual(@as(?u32, 2), back.array_index);

    // A proprietary property identifier (>= 512) is carried, not rejected.
    const prop = try ReadProperty.decode(&hex("0c008000011a0200"));
    try testing.expectEqual(@as(u32, 512), @intFromEnum(prop.property));
    try testing.expect(prop.property.isProprietary());

    // ACK: value block is handed back raw.
    const ack = try ReadPropertyAck.decode(&hex("0c000000051955" ++ "3e" ++ "4442910000" ++ "3f"));
    try testing.expect(ack.object.eql(.{ .type = .analog_input, .instance = 5 }));
    try testing.expectEqual(PropertyIdentifier.present_value, ack.property);
    try testing.expectEqualSlices(u8, &hex("4442910000"), ack.value);
    try testing.expectEqual(@as(f32, 72.5), (try ack.scalar()).real);

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        &hex("0c0000000519553e44429100003f"),
        try enc(ack, &out),
    );

    // Array index 0 = "how long is the array", which is a real answer, not an
    // absent index.
    const len_ack = try ReadPropertyAck.decode(&hex("0c02000257194c29003e21043f"));
    try testing.expectEqual(@as(?u32, 0), len_ack.array_index);
    try testing.expectEqual(@as(u64, 4), (try len_ack.scalar()).unsigned);

    // A value block holding two data items is not a scalar.
    const multi = try ReadPropertyAck.decode(&hex("0c000000051955" ++ "3e" ++ "21012102" ++ "3f"));
    try testing.expectError(error.UnexpectedTag, multi.scalar());
}

test "WriteProperty: priority array and NULL relinquish" {
    var buf: [64]u8 = undefined;
    const wp: WriteProperty = .{
        .object = .{ .type = .analog_value, .instance = 1 },
        .property = .present_value,
        .value = &hex("4441a80000"),
    };
    try testing.expectEqualSlices(u8, &hex("0c0080000119553e4441a800003f"), try enc(wp, &buf));

    const wp2: WriteProperty = .{
        .object = .{ .type = .analog_output, .instance = 1 },
        .property = .present_value,
        .value = &hex("4441a80000"),
        .priority = 8,
    };
    try testing.expectEqualSlices(u8, &hex("0c0040000119553e4441a800003f4908"), try enc(wp2, &buf));

    // Relinquish: an application Null in the value block, at a priority.
    const rel = WriteProperty.relinquish(
        .{ .type = .analog_output, .instance = 1 },
        .present_value,
        8,
    );
    try testing.expectEqualSlices(u8, &hex("0c0040000119553e003f4908"), try enc(rel, &buf));
    try testing.expect(rel.isRelinquish());
    try testing.expect(!wp2.isRelinquish());

    const back = try WriteProperty.decode(&hex("0c0040000119553e003f4908"));
    try testing.expectEqual(@as(?u8, 8), back.priority);
    try testing.expect(back.isRelinquish());

    // Priorities outside 1..16 are refused on both sides.
    var bad = wp2;
    bad.priority = 0;
    try testing.expectError(error.InvalidParameter, enc(bad, &buf));
    bad.priority = 17;
    try testing.expectError(error.InvalidParameter, enc(bad, &buf));
    try testing.expectError(error.InvalidParameter, WriteProperty.decode(&hex("0c0040000119553e003f4911")));

    // With an array index.
    const idx = try WriteProperty.decode(&hex("0c02000257194c29033ec4000000093f"));
    try testing.expectEqual(@as(?u32, 3), idx.array_index);
    try testing.expectEqualSlices(u8, &hex("c400000009"), idx.value);
}

test "ReadPropertyMultiple: request builder and iterator" {
    var buf: [128]u8 = undefined;
    var w = tag.Writer.init(&buf);
    var b = RpmRequestBuilder.init(&w);
    try b.object(.{ .type = .analog_input, .instance = 5 });
    try b.property(.{ .property = .present_value });
    try b.property(.{ .property = .status_flags });
    try b.finish();
    try testing.expectEqualSlices(u8, &hex("0c000000051e0955096f1f"), w.written());

    var it = RpmRequestIterator.init(w.written());
    const spec = (try it.next()).?;
    try testing.expect(spec.object.eql(.{ .type = .analog_input, .instance = 5 }));
    var props = spec.properties();
    try testing.expectEqual(PropertyIdentifier.present_value, (try props.next()).?.property);
    try testing.expectEqual(PropertyIdentifier.status_flags, (try props.next()).?.property);
    try testing.expectEqual(@as(?PropertyReference, null), try props.next());
    try testing.expectEqual(@as(?RpmRequestIterator.Spec, null), try it.next());
}

test "ReadPropertyMultiple: the ALL / REQUIRED / OPTIONAL wildcards" {
    var buf: [128]u8 = undefined;
    var w = tag.Writer.init(&buf);
    var b = RpmRequestBuilder.init(&w);
    try b.object(.{ .type = .analog_input, .instance = 5 });
    try b.property(.{ .property = .all });
    try b.object(.{ .type = .device, .instance = 599 });
    try b.property(.{ .property = .required });
    try b.property(.{ .property = .optional });
    try b.finish();
    try testing.expectEqualSlices(
        u8,
        &hex("0c000000051e09081f0c020002571e096909501f"),
        w.written(),
    );

    var it = RpmRequestIterator.init(w.written());
    const first = (try it.next()).?;
    var p1 = first.properties();
    const wildcard = (try p1.next()).?;
    try testing.expect(wildcard.property.isSpecial());
    try testing.expectEqual(PropertyIdentifier.all, wildcard.property);

    const second = (try it.next()).?;
    try testing.expect(second.object.eql(.{ .type = .device, .instance = 599 }));
    var p2 = second.properties();
    try testing.expectEqual(PropertyIdentifier.required, (try p2.next()).?.property);
    try testing.expectEqual(PropertyIdentifier.optional, (try p2.next()).?.property);
    try testing.expectEqual(@as(?RpmRequestIterator.Spec, null), try it.next());

    // With an array index on the reference.
    var w2 = tag.Writer.init(&buf);
    var b2 = RpmRequestBuilder.init(&w2);
    try b2.object(.{ .type = .device, .instance = 599 });
    try b2.property(.{ .property = .object_list, .array_index = 1 });
    try b2.finish();
    try testing.expectEqualSlices(u8, &hex("0c020002571e094c19011f"), w2.written());
    var it2 = RpmRequestIterator.init(w2.written());
    var p3 = (try it2.next()).?.properties();
    const ref = (try p3.next()).?;
    try testing.expectEqual(@as(?u32, 1), ref.array_index);

    // A property added before any object is a programming error, not a
    // silently-misplaced tag.
    var w3 = tag.Writer.init(&buf);
    var b3 = RpmRequestBuilder.init(&w3);
    try testing.expectError(error.MissingParameter, b3.property(.{ .property = .all }));
}

test "ReadPropertyMultiple ACK: values and per-property errors side by side" {
    var buf: [128]u8 = undefined;
    var w = tag.Writer.init(&buf);
    var b = RpmAckBuilder.init(&w);
    try b.object(.{ .type = .analog_input, .instance = 5 });
    try b.value(.present_value, null, &hex("4442910000"));
    try b.value(.status_flags, null, &hex("820400"));
    try b.finish();
    try testing.expectEqualSlices(
        u8,
        &hex("0c000000051e29554e44429100004f296f4e8204004f1f"),
        w.written(),
    );

    var it = RpmAckIterator.init(w.written());
    const res = (try it.next()).?;
    var els = res.results();
    const e1 = (try els.next()).?;
    try testing.expectEqual(PropertyIdentifier.present_value, e1.property);
    try testing.expectEqualSlices(u8, &hex("4442910000"), e1.outcome.value);
    const e2 = (try els.next()).?;
    try testing.expectEqual(PropertyIdentifier.status_flags, e2.property);
    try testing.expectEqual(@as(?ResultElement, null), try els.next());

    // One failing property must not fail the rest.
    var w2 = tag.Writer.init(&buf);
    var b2 = RpmAckBuilder.init(&w2);
    try b2.object(.{ .type = .analog_input, .instance = 9 });
    try b2.accessError(.present_value, null, .object, .unknown_object);
    try b2.finish();
    try testing.expectEqualSlices(u8, &hex("0c000000091e29555e9101911f5f1f"), w2.written());

    var it2 = RpmAckIterator.init(w2.written());
    var els2 = (try it2.next()).?.results();
    const err_el = (try els2.next()).?;
    try testing.expectEqual(types.ErrorClass.object, err_el.outcome.access_error.class);
    try testing.expectEqual(types.ErrorCode.unknown_object, err_el.outcome.access_error.code);

    var w3 = tag.Writer.init(&buf);
    var b3 = RpmAckBuilder.init(&w3);
    try testing.expectError(error.MissingParameter, b3.value(.all, null, &.{}));
}

test "SubscribeCOV: subscription versus cancellation" {
    var buf: [64]u8 = undefined;
    const sub: SubscribeCov = .{
        .process_id = 7,
        .object = .{ .type = .analog_input, .instance = 5 },
        .confirmed = true,
        .lifetime = 300,
    };
    try testing.expectEqualSlices(u8, &hex("09071c0000000529013a012c"), try enc(sub, &buf));
    try testing.expect(!sub.isCancellation());

    const cancel = SubscribeCov.cancel(7, .{ .type = .analog_input, .instance = 5 });
    try testing.expectEqualSlices(u8, &hex("09071c00000005"), try enc(cancel, &buf));
    try testing.expect(cancel.isCancellation());

    // Unconfirmed, indefinite lifetime.
    const indef: SubscribeCov = .{
        .process_id = 7,
        .object = .{ .type = .analog_input, .instance = 5 },
        .confirmed = false,
        .lifetime = 0,
    };
    try testing.expectEqualSlices(u8, &hex("09071c0000000529003900"), try enc(indef, &buf));

    const back = try SubscribeCov.decode(&hex("09071c0000000529013a012c"));
    try testing.expectEqual(@as(?bool, true), back.confirmed);
    try testing.expectEqual(@as(?u32, 300), back.lifetime);

    const cb = try SubscribeCov.decode(&hex("09071c00000005"));
    try testing.expect(cb.isCancellation());

    // Half a subscription is not a subscription.
    var half = sub;
    half.lifetime = null;
    try testing.expectError(error.InvalidParameter, enc(half, &buf));
}

test "COV notification: both forms share one encoding" {
    var vbuf: [64]u8 = undefined;
    var vw = tag.Writer.init(&vbuf);
    try writeCovValue(&vw, .{ .property = .present_value, .value = &hex("4442910000") });
    try writeCovValue(&vw, .{ .property = .status_flags, .value = &hex("820400") });
    try testing.expectEqualSlices(u8, &hex("09552e44429100002f096f2e8204002f"), vw.written());

    var buf: [128]u8 = undefined;
    const n: CovNotification = .{
        .process_id = 7,
        .initiating_device = .{ .type = .device, .instance = 599 },
        .monitored_object = .{ .type = .analog_input, .instance = 5 },
        .time_remaining = 280,
        .values_block = vw.written(),
    };
    try testing.expectEqualSlices(
        u8,
        &hex("09071c020002572c000000053a01184e09552e44429100002f096f2e8204002f4f"),
        try enc(n, &buf),
    );

    const back = try CovNotification.decode(&hex(
        "09071c020002572c000000053a01184e09552e44429100002f096f2e8204002f4f",
    ));
    try testing.expectEqual(@as(u32, 7), back.process_id);
    try testing.expectEqual(@as(u32, 280), back.time_remaining);
    try testing.expect(back.monitored_object.eql(.{ .type = .analog_input, .instance = 5 }));

    var vals = back.values();
    const v1 = (try vals.next()).?;
    try testing.expectEqual(PropertyIdentifier.present_value, v1.property);
    var vr = tag.Reader.init(v1.value);
    try testing.expectEqual(@as(f32, 72.5), (try vr.appValue()).real);
    const v2 = (try vals.next()).?;
    try testing.expectEqual(PropertyIdentifier.status_flags, v2.property);
    try testing.expectEqual(@as(?CovValue, null), try vals.next());
}

test "ReadRange: the three range selectors and the no-range form" {
    var buf: [64]u8 = undefined;
    const rr: ReadRange = .{
        .object = .{ .type = .trend_log, .instance = 1 },
        .property = .log_buffer,
        .range = .{ .by_position = .{ .reference_index = 1, .count = 10 } },
    };
    try testing.expectEqualSlices(u8, &hex("0c0500000119833e2101310a3f"), try enc(rr, &buf));

    const all: ReadRange = .{
        .object = .{ .type = .trend_log, .instance = 1 },
        .property = .log_buffer,
    };
    try testing.expectEqualSlices(u8, &hex("0c050000011983"), try enc(all, &buf));

    const back = try ReadRange.decode(&hex("0c0500000119833e2101310a3f"));
    try testing.expectEqual(@as(u32, 1), back.range.?.by_position.reference_index);
    try testing.expectEqual(@as(i32, 10), back.range.?.by_position.count);

    const none = try ReadRange.decode(&hex("0c050000011983"));
    try testing.expectEqual(@as(?ReadRange.Range, null), none.range);

    // A backwards read: negative count.
    const rev: ReadRange = .{
        .object = .{ .type = .trend_log, .instance = 1 },
        .property = .log_buffer,
        .range = .{ .by_sequence = .{ .sequence_number = 100, .count = -5 } },
    };
    const wire = try enc(rev, &buf);
    const rb = try ReadRange.decode(wire);
    try testing.expectEqual(@as(i32, -5), rb.range.?.by_sequence.count);
    try testing.expectEqual(@as(u32, 100), rb.range.?.by_sequence.sequence_number);

    // By time.
    const bt: ReadRange = .{
        .object = .{ .type = .trend_log, .instance = 1 },
        .property = .log_buffer,
        .range = .{ .by_time = .{
            .time = .{
                .date = .{ .year = 126, .month = 7, .day = 23, .weekday = 4 },
                .time = .{ .hour = 8, .minute = 0, .second = 0, .hundredths = 0 },
            },
            .count = 20,
        } },
    };
    const bw = try enc(bt, &buf);
    const bb = try ReadRange.decode(bw);
    try testing.expectEqual(@as(u8, 126), bb.range.?.by_time.time.date.year);
    try testing.expectEqual(@as(u8, 8), bb.range.?.by_time.time.time.hour);
    try testing.expectEqual(@as(i32, 20), bb.range.?.by_time.count);
}

test "hostile service bodies are typed errors" {
    // Truncated everywhere.
    try testing.expectError(error.Truncated, ReadProperty.decode(&.{}));
    try testing.expectError(error.Truncated, ReadProperty.decode(&hex("0c000000")));
    try testing.expectError(error.UnexpectedTag, ReadProperty.decode(&hex("2100")));
    try testing.expectError(error.Truncated, ReadPropertyAck.decode(&hex("0c0000000519553e")));
    // A value block that is not an opening bracket at all.
    try testing.expectError(error.UnexpectedTag, ReadPropertyAck.decode(&hex("0c0000000519552100")));
    try testing.expectError(error.Truncated, ReadPropertyAck.decode(&hex("0c000000051955")));
    try testing.expectError(error.Truncated, SubscribeCov.decode(&hex("0907")));
    try testing.expectError(error.Truncated, CovNotification.decode(&hex("09071c02000257")));
    try testing.expectError(error.Truncated, IAm.decode(&hex("c402")));

    // An RPM request whose bracket never closes.
    var it = RpmRequestIterator.init(&hex("0c000000051e0955"));
    try testing.expectError(error.Truncated, it.next());

    // An RPM ACK element that is neither a value nor an error.
    var it2 = RpmAckIterator.init(&hex("0c000000051e295521011f"));
    const res = (try it2.next()).?;
    var els = res.results();
    try testing.expectError(error.UnexpectedTag, els.next());
}

test "ReadProperty-ACK: a value block closed by the wrong bracket is refused" {
    // W2-05 on a real wire path, not just on `tag.Reader` directly. The peer
    // opens `[3`, writes an application Real, and closes with `]99`. The old
    // `openedBlock` measured the body from the *opening* number's width, so
    // `FF` — the first octet of the two-octet closing header — was handed back
    // as part of the property value: `ack.value` came out `4442910000ff`
    // instead of `4442910000`, i.e. the caller's Real gained a trailing octet.
    const bytes = hex("0c000000051955" ++ "3e" ++ "4442910000" ++ "ff63");
    try testing.expectError(error.UnexpectedTag, ReadPropertyAck.decode(&bytes));

    // The well-formed neighbour still decodes, so the guard rejects the framing
    // error and nothing else.
    const ok = hex("0c000000051955" ++ "3e" ++ "4442910000" ++ "3f");
    const ack = try ReadPropertyAck.decode(&ok);
    try testing.expectEqualSlices(u8, &hex("4442910000"), ack.value);
}

// Entry points that reach a narrowing site which is not at the top level of a
// service body, so the whole table below can be one shape.
fn firstCovValue(data: []const u8) Error!CovValue {
    var vals = (try CovNotification.decode(data)).values();
    return (try vals.next()) orelse error.MissingParameter;
}
fn firstRpmPropertyRef(data: []const u8) Error!PropertyReference {
    var it = RpmRequestIterator.init(data);
    var props = ((try it.next()) orelse return error.MissingParameter).properties();
    return (try props.next()) orelse error.MissingParameter;
}
fn firstRpmResultElement(data: []const u8) Error!ResultElement {
    var it = RpmAckIterator.init(data);
    var els = ((try it.next()) orelse return error.MissingParameter).results();
    return (try els.next()) orelse error.MissingParameter;
}

test "wire integers wider than the field they land in are refused, not truncated" {
    // W2-01. Every vector below carries a five-octet context or application
    // integer worth 2^32 where the field it lands in is a u32, u8 or i32.
    // Before the fix each of these was a bare `@intCast`: in Debug/ReleaseSafe
    // a *panic*, so a 14-octet datagram from unauthenticated UDP 47808 kills
    // the device; under ReleaseFast a silent wrap, so an array index of 2^32
    // becomes index 0 — which in BACnet is not the first element but the
    // array's **length**. The device then answers a different question than
    // the one it was asked and nothing on either side notices.
    //
    // The table is the *whole* narrowing surface of this file, not a sample.
    // Its last three rows were already guarded by hand before W2-01 and are
    // included so the set is closed by enumeration rather than by choice: the
    // invariant is "every conversion of a decoded wire integer to a narrower
    // field appears here", and `@intCast` may appear in this file only inside
    // `narrow` or on a value one of these rows has already range-checked.
    //
    // Asserting `error.InvalidParameter` specifically — rather than "some
    // error" — is what makes a row evidence: a mistake in the vector's framing
    // would surface as `Truncated`/`UnexpectedTag` and the row would go red.
    const oversized = .{
        // decoder, vector, the parameter that is out of range
        .{ WhoHas.decode, "0d05010000000019012c00000005", "Who-Has low" },
        .{ WhoHas.decode, "09011d0501000000002c00000005", "Who-Has high" },
        .{ ReadProperty.decode, "0c0000000519552d050100000000", "ReadProperty arrayIndex" },
        .{ ReadPropertyAck.decode, "0c0000000519552d0501000000003e21053f", "ReadProperty-ACK arrayIndex" },
        .{ WriteProperty.decode, "0c0000000519552d0501000000003e21053f", "WriteProperty arrayIndex" },
        .{ SubscribeCov.decode, "0d0501000000001c00000005", "SubscribeCOV processId (cancellation)" },
        .{ SubscribeCov.decode, "0d0501000000001c0000000529013901", "SubscribeCOV processId (subscription)" },
        .{ SubscribeCov.decode, "09011c0000000529013d050100000000", "SubscribeCOV lifetime" },
        .{ CovNotification.decode, "0d0501000000001c000000052c0000000539014e4f", "COV processId" },
        .{ CovNotification.decode, "09011c000000052c000000053d0501000000004e4f", "COV timeRemaining" },
        .{ firstCovValue, "09011c000000052c0000000539014e09551d0501000000002e21052f4f", "COV value arrayIndex" },
        .{ firstCovValue, "09011c000000052c0000000539014e09552e21052f3d0501000000004f", "COV value priority (u8)" },
        .{ firstRpmPropertyRef, "0c000000051e09551d0501000000001f", "RPM property-ref arrayIndex" },
        .{ firstRpmResultElement, "0c000000051e29553d0501000000004e21054f1f", "RPM result arrayIndex" },
        .{ ReadRange.decode, "0c0000000519552d050100000000", "ReadRange arrayIndex" },
        .{ ReadRange.decode, "0c0000000519553e2505010000000031053f", "ReadRange by-position referenceIndex" },
        .{ ReadRange.decode, "0c0000000519553e2105350501000000003f", "ReadRange by-position count (i32)" },
        .{ ReadRange.decode, "0c0000000519557e2505010000000031057f", "ReadRange by-sequence sequenceNumber" },
        .{ ReadRange.decode, "0c0000000519557e2105350501000000007f", "ReadRange by-sequence count (i32)" },
        .{ ReadRange.decode, "0c0000000519556ea4ffffffffb4ffffffff350501000000006f", "ReadRange by-time count (i32)" },
        .{ WriteProperty.decode, "0c0000000519553e21053f4d050100000000", "WriteProperty priority (guarded before W2-01)" },
        .{ WhoIs.decode, "0d0501000000001901", "Who-Is low (guarded before W2-01)" },
        .{ IAm.decode, "c4000000052505010000000091002103", "I-Am maxAPDU (guarded before W2-01)" },
    };

    // Counted rather than short-circuited, so one run reports how many of the
    // sites are open, not merely that the first one is.
    var accepted: usize = 0;
    inline for (oversized) |case| {
        const bytes = hex(case[1]);
        if (case[0](&bytes)) |_| {
            accepted += 1;
            std.debug.print("truncated instead of refused: {s}\n", .{case[2]});
        } else |e| if (e != error.InvalidParameter) {
            std.debug.print("{s}: got {s}, want InvalidParameter\n", .{ case[2], @errorName(e) });
            return e;
        }
    }
    try testing.expectEqual(@as(usize, 0), accepted);

    // The in-range neighbour of the first vector still decodes, so the guard
    // refuses the value and not the shape.
    const ok = try ReadProperty.decode(&hex("0c0000000519552905"));
    try testing.expectEqual(@as(?u32, 5), ok.array_index);
}

test "fuzz: service decoders never crash on arbitrary bodies" {
    try std.testing.fuzz({}, fuzzServices, .{});
}

fn fuzzServices(_: void, smith: *std.testing.Smith) !void {
    var buf: [192]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const data = buf[0..len];

    _ = WhoIs.decode(data) catch {};
    _ = IAm.decode(data) catch {};
    _ = WhoHas.decode(data) catch {};
    _ = IHave.decode(data) catch {};
    _ = ReadProperty.decode(data) catch {};
    _ = ReadPropertyAck.decode(data) catch {};
    _ = WriteProperty.decode(data) catch {};
    _ = SubscribeCov.decode(data) catch {};
    _ = CovNotification.decode(data) catch {};
    _ = ReadRange.decode(data) catch {};

    var it = RpmRequestIterator.init(data);
    var guard: usize = 0;
    while (guard < 256) : (guard += 1) {
        const spec = (it.next() catch break) orelse break;
        var props = spec.properties();
        var g2: usize = 0;
        while (g2 < 256) : (g2 += 1) {
            _ = (props.next() catch break) orelse break;
        }
    }

    var ait = RpmAckIterator.init(data);
    guard = 0;
    while (guard < 256) : (guard += 1) {
        const res = (ait.next() catch break) orelse break;
        var els = res.results();
        var g2: usize = 0;
        while (g2 < 256) : (g2 += 1) {
            _ = (els.next() catch break) orelse break;
        }
    }
}

// ── a structure-aware harness for the wire-integer sites ───────────────────
//
// W2-01 survived 180 s of clean coverage-guided fuzzing even though
// `fuzzServices` above *calls* every decoder it lives in. The harness's reach
// was never the problem: before a decoder gets as far as an array index or a
// process id it must first accept a structured prefix (`0c <objid> 19 <prop>`),
// and a corpus of arbitrary bytes never invented one. So the oversized-integer
// paths were not merely under-explored — they were never entered at all.
//
// This harness supplies the structure and lets the fuzzer choose only what a
// peer chooses: which service, and how many octets each integer field is
// spelled in. One octet is ordinary traffic; five is `2^32` landing in a `u32`.

/// Emits a context tag `number` carrying `data`, in the short or the extended
/// length form, exactly as a peer would spell it.
fn wireCtx(out: []u8, number: u8, data: []const u8) usize {
    var i: usize = 0;
    if (data.len < 5) {
        out[0] = (number << 4) | 0x08 | @as(u8, @intCast(data.len));
        i = 1;
    } else {
        out[0] = (number << 4) | 0x0D;
        out[1] = @intCast(data.len);
        i = 2;
    }
    @memcpy(out[i..][0..data.len], data);
    return i + data.len;
}

/// The same for an application tag.
fn wireApp(out: []u8, number: u8, data: []const u8) usize {
    var i: usize = 0;
    if (data.len < 5) {
        out[0] = (number << 4) | @as(u8, @intCast(data.len));
        i = 1;
    } else {
        out[0] = (number << 4) | 0x05;
        out[1] = @intCast(data.len);
        i = 2;
    }
    @memcpy(out[i..][0..data.len], data);
    return i + data.len;
}

fn wireRaw(out: []u8, data: []const u8) usize {
    @memcpy(out[0..data.len], data);
    return data.len;
}

test "fuzz: a wire integer of any width never truncates into a service field" {
    try std.testing.fuzz({}, fuzzServiceIntegers, .{});
}

fn fuzzServiceIntegers(_: void, smith: *std.testing.Smith) !void {
    var digits: [8]u8 = undefined;
    smith.bytes(&digits);
    const width: usize = smith.valueRangeAtMost(u8, 1, 8);
    const int = digits[0..width];
    const which = smith.valueRangeAtMost(u8, 0, 18);

    const oid = [_]u8{ 0x00, 0x00, 0x00, 0x05 };
    const present_value = [_]u8{0x55};
    const one = [_]u8{0x01};

    var buf: [128]u8 = undefined;
    var n: usize = 0;
    switch (which) {
        // ReadProperty / -ACK / WriteProperty arrayIndex.
        0, 1, 2 => {
            n += wireCtx(buf[n..], 0, &oid);
            n += wireCtx(buf[n..], 1, &present_value);
            n += wireCtx(buf[n..], 2, int);
            if (which == 0) {
                _ = ReadProperty.decode(buf[0..n]) catch {};
                return;
            }
            n += wireRaw(buf[n..], &.{ 0x3E, 0x21, 0x05, 0x3F });
            if (which == 1) {
                _ = ReadPropertyAck.decode(buf[0..n]) catch {};
            } else {
                _ = WriteProperty.decode(buf[0..n]) catch {};
            }
        },
        // WriteProperty priority.
        3 => {
            n += wireCtx(buf[n..], 0, &oid);
            n += wireCtx(buf[n..], 1, &present_value);
            n += wireRaw(buf[n..], &.{ 0x3E, 0x21, 0x05, 0x3F });
            n += wireCtx(buf[n..], 4, int);
            _ = WriteProperty.decode(buf[0..n]) catch {};
        },
        // SubscribeCOV processId, cancellation form.
        4 => {
            n += wireCtx(buf[n..], 0, int);
            n += wireCtx(buf[n..], 1, &oid);
            _ = SubscribeCov.decode(buf[0..n]) catch {};
        },
        // SubscribeCOV processId and lifetime, subscription form.
        5, 6 => {
            n += wireCtx(buf[n..], 0, if (which == 5) int else &one);
            n += wireCtx(buf[n..], 1, &oid);
            n += wireCtx(buf[n..], 2, &one);
            n += wireCtx(buf[n..], 3, if (which == 6) int else &one);
            _ = SubscribeCov.decode(buf[0..n]) catch {};
        },
        // COV notification processId / timeRemaining, and its value list's
        // arrayIndex / priority.
        7, 8, 9, 10 => {
            n += wireCtx(buf[n..], 0, if (which == 7) int else &one);
            n += wireCtx(buf[n..], 1, &oid);
            n += wireCtx(buf[n..], 2, &oid);
            n += wireCtx(buf[n..], 3, if (which == 8) int else &one);
            n += wireRaw(buf[n..], &.{0x4E});
            if (which == 9 or which == 10) {
                n += wireCtx(buf[n..], 0, &present_value);
                if (which == 9) n += wireCtx(buf[n..], 1, int);
                n += wireRaw(buf[n..], &.{ 0x2E, 0x21, 0x05, 0x2F });
                if (which == 10) n += wireCtx(buf[n..], 3, int);
            }
            n += wireRaw(buf[n..], &.{0x4F});
            const notif = CovNotification.decode(buf[0..n]) catch return;
            var vals = notif.values();
            var guard: usize = 0;
            while (guard < 8) : (guard += 1) {
                _ = (vals.next() catch break) orelse break;
            }
        },
        // ReadRange arrayIndex, and the index/count of all three range forms.
        11, 12, 13, 14, 15, 16, 17 => {
            n += wireCtx(buf[n..], 0, &oid);
            n += wireCtx(buf[n..], 1, &present_value);
            if (which == 11) n += wireCtx(buf[n..], 2, int);
            switch (which) {
                12, 13 => { // by position: [3] Unsigned, Signed
                    n += wireRaw(buf[n..], &.{0x3E});
                    n += wireApp(buf[n..], 2, if (which == 12) int else &one);
                    n += wireApp(buf[n..], 3, if (which == 13) int else &one);
                    n += wireRaw(buf[n..], &.{0x3F});
                },
                14, 15 => { // by sequence: [7] Unsigned, Signed
                    n += wireRaw(buf[n..], &.{0x7E});
                    n += wireApp(buf[n..], 2, if (which == 14) int else &one);
                    n += wireApp(buf[n..], 3, if (which == 15) int else &one);
                    n += wireRaw(buf[n..], &.{0x7F});
                },
                16, 17 => { // by time: [6] Date, Time, Signed
                    n += wireRaw(buf[n..], &.{0x6E});
                    n += wireApp(buf[n..], 10, &.{ 0xFF, 0xFF, 0xFF, 0xFF });
                    n += wireApp(buf[n..], 11, &.{ 0xFF, 0xFF, 0xFF, 0xFF });
                    n += wireApp(buf[n..], 3, if (which == 17) int else &one);
                    n += wireRaw(buf[n..], &.{0x6F});
                },
                else => {},
            }
            _ = ReadRange.decode(buf[0..n]) catch {};
        },
        // Who-Has low/high, then the two RPM iterators' arrayIndex.
        else => {
            n += wireCtx(buf[n..], 0, int);
            n += wireCtx(buf[n..], 1, int);
            n += wireCtx(buf[n..], 2, &oid);
            _ = WhoHas.decode(buf[0..n]) catch {};

            n = 0;
            n += wireCtx(buf[n..], 0, &oid);
            n += wireRaw(buf[n..], &.{0x1E});
            n += wireCtx(buf[n..], 0, &present_value);
            n += wireCtx(buf[n..], 1, int);
            n += wireRaw(buf[n..], &.{0x1F});
            var req = RpmRequestIterator.init(buf[0..n]);
            if (req.next() catch null) |spec| {
                var props = spec.properties();
                var guard: usize = 0;
                while (guard < 8) : (guard += 1) {
                    _ = (props.next() catch break) orelse break;
                }
            }

            n = 0;
            n += wireCtx(buf[n..], 0, &oid);
            n += wireRaw(buf[n..], &.{0x1E});
            n += wireCtx(buf[n..], 2, &present_value);
            n += wireCtx(buf[n..], 3, int);
            n += wireRaw(buf[n..], &.{ 0x4E, 0x21, 0x05, 0x4F, 0x1F });
            var ack = RpmAckIterator.init(buf[0..n]);
            if (ack.next() catch null) |res| {
                var els = res.results();
                var guard: usize = 0;
                while (guard < 8) : (guard += 1) {
                    _ = (els.next() catch break) orelse break;
                }
            }
        },
    }
}

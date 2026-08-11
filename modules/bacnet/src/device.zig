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
//! * **It never segments.** Its Device object advertises
//!   `segmentation_supported = none` and it answers a request that would
//!   overflow the peer's `max-APDU-length-accepted` with
//!   `Abort(buffer_overflow)`, which is what clause 5.4 prescribes. A
//!   ReadPropertyMultiple over a large object list therefore fails cleanly
//!   rather than silently truncating.
//! * **It has no persistence and no allocator.** The object table is the
//!   caller's slice; property values live in it.

const std = @import("std");
const types = @import("types.zig");
const tag = @import("tag.zig");
const bvll = @import("bvll.zig");
const npdu = @import("npdu.zig");
const apdu = @import("apdu.zig");
const service = @import("service.zig");
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
};

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
    /// Refused a request.
    refused: struct { class: types.ErrorClass, code: types.ErrorCode },
    /// Something arrived that this device does not serve.
    unhandled,
};

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
        pub fn announce(self: *Self) Error!void {
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
            if (p.cov_reported) try self.notifyCov(obj, now_ms);
        }

        /// Receives at most one datagram, answers it, and expires at most one
        /// lapsed subscription.
        pub fn poll(self: *Self, now_ms: u64) Error!Event {
            self.expireSubscriptions(now_ms);
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
                // This device does not reassemble and does not segment; saying
                // so up front is what keeps a peer from ever trying.
                .segmentation = .none,
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
                            try self.announce();
                        }
                        return .announced;
                    },
                    .who_has => return self.handleWhoHas(u.data, origin, b.function()),
                    else => return .unhandled,
                },
                .confirmed_request => |r| {
                    if (r.segment != null) {
                        // Refuse rather than buffer: this device does not
                        // reassemble, and it said so in its I-Am.
                        try self.sendApdu(origin, apdu.segmentationNotSupported(r.invoke_id, true));
                        return .unhandled;
                    }
                    return switch (r.service) {
                        .read_property => self.handleReadProperty(origin, r),
                        .read_property_multiple => self.handleRpm(origin, r),
                        .write_property => self.handleWriteProperty(origin, r),
                        .subscribe_cov => self.handleSubscribeCov(origin, r, now_ms),
                        else => blk: {
                            try self.sendApdu(origin, .{ .reject = .{
                                .invoke_id = r.invoke_id,
                                .reason = .unrecognized_service,
                            } });
                            break :blk .unhandled;
                        },
                    };
                },
                .simple_ack => |s| {
                    // The acknowledgement of one of our confirmed COV
                    // notifications.
                    for (&self.subs) |*sub| {
                        if (sub.active and sub.outstanding == s.invoke_id) sub.outstanding = null;
                    }
                    return .none;
                },
                .abort, .reject, .err => {
                    for (&self.subs) |*sub| {
                        if (sub.active and sub.outstanding == a.invokeId()) sub.outstanding = null;
                    }
                    return .none;
                },
                else => return .unhandled,
            }
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
            if (rp.array_index != null and p.value != .raw) {
                return self.refuse(to, r.invoke_id, .read_property, .property, .property_is_not_an_array);
            }

            var body: [transport.max_datagram]u8 = undefined;
            var w = tag.Writer.init(&body);
            var vbuf: [512]u8 = undefined;
            var vw = tag.Writer.init(&vbuf);
            try p.value.encode(&vw);
            (service.ReadPropertyAck{
                .object = rp.object,
                .property = rp.property,
                .array_index = rp.array_index,
                .value = vw.written(),
            }).encode(&w) catch
                return self.abortOverflow(to, r.invoke_id);

            try self.sendApdu(to, .{ .complex_ack = .{
                .invoke_id = r.invoke_id,
                .service = .read_property,
                .data = w.written(),
            } });
            return .{ .read = .{ .object = rp.object, .property = rp.property } };
        }

        fn handleRpm(self: *Self, to: BipAddress, r: apdu.ConfirmedRequest) Error!Event {
            var body: [transport.max_datagram]u8 = undefined;
            var w = tag.Writer.init(&body);
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

            self.sendApdu(to, .{ .complex_ack = .{
                .invoke_id = r.invoke_id,
                .service = .read_property_multiple,
                .data = w.written(),
            } }) catch return self.abortOverflow(to, r.invoke_id);
            return .{ .read = .{ .object = last, .property = .all } };
        }

        fn emitValue(self: *Self, b: *service.RpmAckBuilder, prop: *const Property) Error!void {
            _ = self;
            var vbuf: [512]u8 = undefined;
            var vw = tag.Writer.init(&vbuf);
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
            const obj = self.find(wp.object) orelse
                return self.refuse(to, r.invoke_id, .write_property, .object, .unknown_object);
            const p = obj.find(wp.property) orelse
                return self.refuse(to, r.invoke_id, .write_property, .property, .unknown_property);
            if (!p.writable)
                return self.refuse(to, r.invoke_id, .write_property, .property, .write_access_denied);

            // Relinquishing is not "write null": it hands the slot back, and a
            // device with no priority array has nothing to hand back to.
            if (wp.isRelinquish() and p.value != .null) {
                return self.refuse(
                    to,
                    r.invoke_id,
                    .write_property,
                    .property,
                    .optional_functionality_not_supported,
                );
            }

            const parsed = Value.parse(wp.value) orelse
                return self.refuse(to, r.invoke_id, .write_property, .property, .invalid_data_type);
            if (!Value.sameKind(parsed, p.value))
                return self.refuse(to, r.invoke_id, .write_property, .property, .invalid_data_type);

            p.value = parsed;
            try self.sendApdu(to, .{ .simple_ack = .{
                .invoke_id = r.invoke_id,
                .service = .write_property,
            } });
            return .{ .wrote = .{ .object = wp.object, .property = wp.property } };
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

        fn notifyCov(self: *Self, obj: *Object, now_ms: u64) Error!void {
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

test "fuzz: the device never crashes on an arbitrary datagram" {
    try std.testing.fuzz({}, fuzzDevice, .{});
}

fn fuzzDevice(_: void, smith: *std.testing.Smith) !void {
    var rig: Rig = .{};
    rig.wire();
    var db = Db.init();
    var dev = DefaultDevice.init(rig.device_ep.transport(), .{ .instance = 599 }, db.wire());

    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    rig.device_ep.inject(rig.client_ep.address, buf[0..len]);
    _ = dev.poll(0) catch {};
}

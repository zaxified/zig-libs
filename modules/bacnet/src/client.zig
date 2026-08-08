// SPDX-License-Identifier: MIT

//! A BACnet/IP **client** over the datagram seam: discover devices, read and
//! write properties, subscribe to change-of-value.
//!
//! Shape, and why:
//!
//! * **No clock, no thread, no socket.** The caller supplies `now_ms` to every
//!   entry point and performs no I/O itself beyond handing this a `Transport`.
//!   That makes the APDU timeout and the retry ladder testable with a fake
//!   clock, which matters because BACnet's default APDU timeout is 3 seconds
//!   with 3 retries — nobody wants a unit test that takes 12.
//! * **Confirmed requests are tracked in a fixed table.** Each gets an invoke
//!   id, a deadline and a retry count; `poll` expires them. The table is
//!   fixed-size (no allocator anywhere in this module), so the number of
//!   concurrent transactions is a compile-time choice, not a runtime surprise.
//! * **Invoke ids are recycled, never reused while live.** `nextInvokeId`
//!   skips ids that are still outstanding; a client that reuses a live id
//!   cannot tell which response belongs to which request, and BACnet gives it
//!   no other correlator.
//! * **A transaction is keyed on (invoke id, peer address), not on the invoke
//!   id alone.** Clause 5.4's TSM state machine is indexed by the pair, and it
//!   has to be: base BACnet/IP has no authentication whatsoever, invoke ids are
//!   8-bit and handed out sequentially, so a host that can put a datagram on
//!   the segment could otherwise cancel someone else's outstanding transaction
//!   by guessing an id — or, worse, have a forged ComplexACK delivered to the
//!   application as that transaction's answer. A response whose origin does not
//!   match the address the request went to is reported as `.unhandled` and the
//!   transaction stays outstanding, so the genuine answer (or the timeout) still
//!   happens.
//! * **A segmented response is refused explicitly.** This client advertises
//!   `max_segments = .unspecified` and does not set the
//!   segmented-response-accepted bit, so a conforming device will never send
//!   one; if one arrives anyway, the client answers `Abort` with
//!   `segmentation_not_supported` and reports `.segmented_response` rather
//!   than mis-parsing the fragment.

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
const Transport = transport.Transport;

pub const Error = tag.Error || apdu.Error || service.Error || bvll.Error ||
    npdu.Error || transport.TransportError || error{
    /// Every invoke id is outstanding; retire some transactions first.
    TooManyTransactions,
    /// The peer offered a segmented message this client will not reassemble.
    SegmentationNotSupported,
};

pub const Config = struct {
    /// Milliseconds before an unanswered confirmed request is retried.
    /// ASHRAE 135's default `APDU_Timeout` is 3000.
    apdu_timeout_ms: u32 = 3000,
    /// Retries after the first attempt. The standard's default
    /// `Number_Of_APDU_Retries` is 3.
    retries: u8 = 3,
    /// What this client advertises it can receive in one APDU.
    max_apdu: apdu.MaxApdu = .up_to_1476,
    /// Concurrent confirmed transactions. Fixed at compile time via the
    /// client's table size; this is the *soft* cap used by `nextInvokeId`.
    max_pending: u8 = 16,
};

/// One outstanding confirmed request.
pub const Pending = struct {
    invoke_id: u8,
    peer: BipAddress,
    svc: types.ConfirmedService,
    deadline_ms: u64,
    attempts_left: u8,
    /// The encoded datagram, kept so a retry is a resend rather than a
    /// re-encode (which could differ if the caller's inputs moved). Sized to
    /// `transport.max_datagram` (W2 `bacnet` F5) — a fixed 256-octet cap here
    /// used to refuse (fail-closed, but undocumented) any confirmed request
    /// whose encoded datagram exceeded it, even though `Config.max_apdu`
    /// negotiates up to 1476 octets of APDU with the peer (e.g. a
    /// `ReadPropertyMultiple` over roughly a dozen properties routinely
    /// exceeded 256 bytes while staying well inside the negotiated max-APDU).
    /// Matching `transport.max_datagram` — what `sendConfirmed` already
    /// bounds the encoded datagram to via `self.tx`/`bvll.wrap` — means the
    /// retry buffer can hold anything this client is capable of sending in
    /// the first place; `error.NoSpace` now fires only for something that
    /// could not have been transmitted at all, never for an ordinary
    /// negotiated-size request.
    datagram: [transport.max_datagram]u8 = undefined,
    datagram_len: usize = 0,
    active: bool = false,
};

/// What `poll` reports. Slice-carrying variants borrow from the client's own
/// receive buffer and are **invalidated by the next `poll`** — copy anything
/// that must outlive the call.
pub const Event = union(enum) {
    /// Nothing happened this round.
    none,
    /// A device answered a Who-Is (or announced itself on restart).
    i_am: struct { from: BipAddress, info: service.IAm },
    /// A device answered a Who-Has.
    i_have: struct { from: BipAddress, info: service.IHave },
    /// A change-of-value notification. `confirmed` notifications have been
    /// acknowledged automatically before this is reported.
    cov: struct {
        from: BipAddress,
        confirmed: bool,
        notification: service.CovNotification,
    },
    /// A confirmed request completed with no result data.
    simple_ack: struct { from: BipAddress, invoke_id: u8, svc: types.ConfirmedService },
    /// A confirmed request completed with result data.
    complex_ack: struct {
        from: BipAddress,
        invoke_id: u8,
        svc: types.ConfirmedService,
        data: []const u8,
    },
    /// The device understood the request and refused it.
    err: struct {
        from: BipAddress,
        invoke_id: u8,
        svc: types.ConfirmedService,
        class: types.ErrorClass,
        code: types.ErrorCode,
    },
    /// The device could not interpret the request.
    reject: struct { from: BipAddress, invoke_id: u8, reason: types.RejectReason },
    /// The device tore the transaction down.
    abort: struct { from: BipAddress, invoke_id: u8, reason: types.AbortReason },
    /// A confirmed request ran out of retries.
    timeout: struct { peer: BipAddress, invoke_id: u8, svc: types.ConfirmedService },
    /// A device sent a segmented response this client will not reassemble. An
    /// `Abort(segmentation_not_supported)` has already been sent back.
    segmented_response: struct { from: BipAddress, invoke_id: u8 },
    /// A network-layer message (routing). Reported, not acted on.
    network_message: struct { from: BipAddress, kind: npdu.MessageType },
    /// Something arrived that this client does not model — **or** a response
    /// PDU that no outstanding transaction claims: an unknown invoke id, or a
    /// known invoke id from an address the matching request never went to.
    /// Reported rather than dropped, so a caller can log it; the transaction,
    /// if there was one, is left outstanding.
    unhandled: struct { from: BipAddress, pdu_type: apdu.PduType },
};

/// A read-access specification for `readPropertyMultiple`.
pub const RpmSpec = struct {
    object: ObjectId,
    properties: []const service.PropertyReference,
};

pub fn Client(comptime max_pending: usize) type {
    return struct {
        const Self = @This();

        tp: Transport,
        config: Config,
        pending: [max_pending]Pending = @splat(.{
            .invoke_id = 0,
            .peer = .{ .ip = @splat(0) },
            .svc = .read_property,
            .deadline_ms = 0,
            .attempts_left = 0,
        }),
        next_id: u8 = 0,
        rx: [transport.max_datagram]u8 = undefined,
        tx: [transport.max_datagram]u8 = undefined,

        pub fn init(tp: Transport, config: Config) Self {
            return .{ .tp = tp, .config = config };
        }

        // ── unconfirmed requests (fire and forget) ─────────────────────────

        /// Broadcasts a `Who-Is`. With no limits this asks every device on the
        /// local network to answer; devices answer at a random delay, so
        /// expect the `.i_am` events to trickle in over a second or two.
        pub fn whoIs(self: *Self, low: ?u32, high: ?u32) Error!void {
            var body: [16]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.WhoIs{ .low = low, .high = high }).encode(&w);
            const dgram = try self.buildUnconfirmed(.who_is, w.written());
            try self.tp.broadcast(dgram);
        }

        /// Sends a `Who-Is` to **one** address rather than broadcasting.
        /// Every conforming device answers a unicast Who-Is — clause 16.10
        /// puts no restriction on how the request arrives — which is what
        /// makes it the way to probe a device whose address is known but which
        /// is not on a subnet this host can broadcast onto (a device behind a
        /// BBMD, a peer bound to loopback, or a device on a foreign subnet).
        pub fn whoIsTo(self: *Self, to: BipAddress, low: ?u32, high: ?u32) Error!void {
            var body: [16]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.WhoIs{ .low = low, .high = high }).encode(&w);
            var a_buf: [transport.max_datagram]u8 = undefined;
            const a = try apdu.encode(
                .{ .unconfirmed_request = .{ .service = .who_is, .data = w.written() } },
                &a_buf,
            );
            var n_buf: [transport.max_datagram]u8 = undefined;
            const n = try npdu.encode(.{}, a, &n_buf);
            const dgram = try bvll.wrap(.original_unicast_npdu, n, &self.tx);
            try self.tp.send(to, dgram);
        }

        /// Broadcasts a `Who-Has` for an object identifier.
        pub fn whoHasId(self: *Self, object: ObjectId, low: ?u32, high: ?u32) Error!void {
            var body: [32]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.WhoHas{
                .low = low,
                .high = high,
                .target = .{ .object_id = object },
            }).encode(&w);
            const dgram = try self.buildUnconfirmed(.who_has, w.written());
            try self.tp.broadcast(dgram);
        }

        /// Broadcasts a `Who-Has` for an object name.
        pub fn whoHasName(self: *Self, name: []const u8, low: ?u32, high: ?u32) Error!void {
            var body: [128]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.WhoHas{
                .low = low,
                .high = high,
                .target = .{ .object_name = name },
            }).encode(&w);
            const dgram = try self.buildUnconfirmed(.who_has, w.written());
            try self.tp.broadcast(dgram);
        }

        // ── confirmed requests ─────────────────────────────────────────────

        /// Reads one property. Returns the invoke id, which is what correlates
        /// the eventual `.complex_ack`/`.err`/`.timeout` event with this call.
        pub fn readProperty(
            self: *Self,
            to: BipAddress,
            object: ObjectId,
            property: types.PropertyIdentifier,
            array_index: ?u32,
            now_ms: u64,
        ) Error!u8 {
            var body: [32]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.ReadProperty{
                .object = object,
                .property = property,
                .array_index = array_index,
            }).encode(&w);
            return self.sendConfirmed(to, .read_property, w.written(), now_ms);
        }

        /// Writes one property. `value` is raw tagged octets — build it with a
        /// `tag.Writer`, e.g. `try w.appReal(21.0)`.
        pub fn writeProperty(
            self: *Self,
            to: BipAddress,
            object: ObjectId,
            property: types.PropertyIdentifier,
            array_index: ?u32,
            value: []const u8,
            priority: ?u8,
            now_ms: u64,
        ) Error!u8 {
            var body: [200]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.WriteProperty{
                .object = object,
                .property = property,
                .array_index = array_index,
                .value = value,
                .priority = priority,
            }).encode(&w);
            return self.sendConfirmed(to, .write_property, w.written(), now_ms);
        }

        /// Relinquishes control of a commandable property at `priority`,
        /// letting the next-lower priority drive the output.
        pub fn relinquish(
            self: *Self,
            to: BipAddress,
            object: ObjectId,
            property: types.PropertyIdentifier,
            priority: u8,
            now_ms: u64,
        ) Error!u8 {
            var body: [32]u8 = undefined;
            var w = tag.Writer.init(&body);
            try service.WriteProperty.relinquish(object, property, priority).encode(&w);
            return self.sendConfirmed(to, .write_property, w.written(), now_ms);
        }

        /// Reads several properties of several objects in one round trip.
        pub fn readPropertyMultiple(
            self: *Self,
            to: BipAddress,
            specs: []const RpmSpec,
            now_ms: u64,
        ) Error!u8 {
            var body: [400]u8 = undefined;
            var w = tag.Writer.init(&body);
            var b = service.RpmRequestBuilder.init(&w);
            for (specs) |s| {
                try b.object(s.object);
                for (s.properties) |p| try b.property(p);
            }
            try b.finish();
            return self.sendConfirmed(to, .read_property_multiple, w.written(), now_ms);
        }

        /// Subscribes to change-of-value on `object`. `lifetime_seconds` of 0
        /// means indefinite; a real client normally picks a few minutes and
        /// resubscribes, so a crashed client's subscription eventually expires.
        pub fn subscribeCov(
            self: *Self,
            to: BipAddress,
            process_id: u32,
            object: ObjectId,
            confirmed: bool,
            lifetime_seconds: u32,
            now_ms: u64,
        ) Error!u8 {
            var body: [32]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.SubscribeCov{
                .process_id = process_id,
                .object = object,
                .confirmed = confirmed,
                .lifetime = lifetime_seconds,
            }).encode(&w);
            return self.sendConfirmed(to, .subscribe_cov, w.written(), now_ms);
        }

        /// Cancels a subscription.
        pub fn cancelCov(
            self: *Self,
            to: BipAddress,
            process_id: u32,
            object: ObjectId,
            now_ms: u64,
        ) Error!u8 {
            var body: [32]u8 = undefined;
            var w = tag.Writer.init(&body);
            try service.SubscribeCov.cancel(process_id, object).encode(&w);
            return self.sendConfirmed(to, .subscribe_cov, w.written(), now_ms);
        }

        /// Reads a slice of a list property (a trend log's buffer, typically).
        pub fn readRange(
            self: *Self,
            to: BipAddress,
            object: ObjectId,
            property: types.PropertyIdentifier,
            range: ?service.ReadRange.Range,
            now_ms: u64,
        ) Error!u8 {
            var body: [64]u8 = undefined;
            var w = tag.Writer.init(&body);
            try (service.ReadRange{
                .object = object,
                .property = property,
                .range = range,
            }).encode(&w);
            return self.sendConfirmed(to, .read_range, w.written(), now_ms);
        }

        // ── the poll loop ──────────────────────────────────────────────────

        /// Receives at most one datagram, expires at most one transaction, and
        /// reports what happened. Call it until it returns `.none`.
        pub fn poll(self: *Self, now_ms: u64) Error!Event {
            if (try self.expire(now_ms)) |e| return e;
            const got = (try self.tp.recv(&self.rx)) orelse return .none;
            return self.handle(got.from, got.bytes) catch |e| switch (e) {
                // A malformed datagram from a stranger must not kill the loop.
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

        /// Milliseconds until the earliest transaction deadline, or null when
        /// nothing is outstanding. An event loop sleeps on this.
        pub fn nextDeadline(self: *const Self, now_ms: u64) ?u64 {
            var soonest: ?u64 = null;
            for (self.pending) |p| {
                if (!p.active) continue;
                const remain = if (p.deadline_ms > now_ms) p.deadline_ms - now_ms else 0;
                if (soonest == null or remain < soonest.?) soonest = remain;
            }
            return soonest;
        }

        pub fn pendingCount(self: *const Self) usize {
            var n: usize = 0;
            for (self.pending) |p| {
                if (p.active) n += 1;
            }
            return n;
        }

        // ── internals ──────────────────────────────────────────────────────

        fn expire(self: *Self, now_ms: u64) Error!?Event {
            for (&self.pending) |*p| {
                if (!p.active or now_ms < p.deadline_ms) continue;
                if (p.attempts_left == 0) {
                    p.active = false;
                    return .{ .timeout = .{
                        .peer = p.peer,
                        .invoke_id = p.invoke_id,
                        .svc = p.svc,
                    } };
                }
                p.attempts_left -= 1;
                p.deadline_ms = now_ms + self.config.apdu_timeout_ms;
                try self.tp.send(p.peer, p.datagram[0..p.datagram_len]);
                // A retry is not an event: the caller asked for a result, not
                // for a play-by-play of the transport.
                return null;
            }
            return null;
        }

        fn handle(self: *Self, from: BipAddress, dgram: []u8) Error!Event {
            const b = try bvll.decode(dgram);
            // A Forwarded-NPDU carries the *original* sender's address; a BBMD
            // relaying for a device is not itself the device, and replying to
            // the relay would go to the wrong place.
            const origin = switch (b) {
                .forwarded_npdu => |f| f.origin,
                else => from,
            };
            const npdu_bytes = b.npdu() orelse return .none;
            const n = try npdu.decode(npdu_bytes);
            const a_bytes = switch (n.payload) {
                .apdu => |x| x,
                .network => |m| return .{ .network_message = .{
                    .from = origin,
                    .kind = m.kind(),
                } },
            };
            const a = try apdu.decode(a_bytes);

            switch (a) {
                .unconfirmed_request => |u| return self.handleUnconfirmed(origin, u),
                .simple_ack => |s| {
                    if (!self.retire(s.invoke_id, origin)) return unclaimed(origin, .simple_ack);
                    return .{ .simple_ack = .{
                        .from = origin,
                        .invoke_id = s.invoke_id,
                        .svc = s.service,
                    } };
                },
                .complex_ack => |c| {
                    if (!self.retire(c.invoke_id, origin)) return unclaimed(origin, .complex_ack);
                    if (c.segment != null) {
                        // Refuse explicitly. Answering nothing would leave the
                        // device retransmitting the whole transfer.
                        try self.sendApdu(origin, apdu.segmentationNotSupported(c.invoke_id, false));
                        return .{ .segmented_response = .{
                            .from = origin,
                            .invoke_id = c.invoke_id,
                        } };
                    }
                    return .{ .complex_ack = .{
                        .from = origin,
                        .invoke_id = c.invoke_id,
                        .svc = c.service,
                        .data = c.data,
                    } };
                },
                .err => |e| {
                    if (!self.retire(e.invoke_id, origin)) return unclaimed(origin, .err);
                    return .{ .err = .{
                        .from = origin,
                        .invoke_id = e.invoke_id,
                        .svc = e.service,
                        .class = e.class,
                        .code = e.code,
                    } };
                },
                .reject => |r| {
                    if (!self.retire(r.invoke_id, origin)) return unclaimed(origin, .reject);
                    return .{ .reject = .{
                        .from = origin,
                        .invoke_id = r.invoke_id,
                        .reason = r.reason,
                    } };
                },
                .abort => |ab| {
                    if (!self.retire(ab.invoke_id, origin)) return unclaimed(origin, .abort);
                    return .{ .abort = .{
                        .from = origin,
                        .invoke_id = ab.invoke_id,
                        .reason = ab.reason,
                    } };
                },
                .confirmed_request => |r| {
                    // A device may confirm a COV notification to us. Anything
                    // else a client is asked to do, it declines.
                    if (r.segment != null) {
                        try self.sendApdu(origin, apdu.segmentationNotSupported(r.invoke_id, true));
                        return .{ .segmented_response = .{
                            .from = origin,
                            .invoke_id = r.invoke_id,
                        } };
                    }
                    if (r.service == .confirmed_cov_notification) {
                        const note = try service.CovNotification.decode(r.data);
                        try self.sendApdu(origin, .{ .simple_ack = .{
                            .invoke_id = r.invoke_id,
                            .service = .confirmed_cov_notification,
                        } });
                        return .{ .cov = .{
                            .from = origin,
                            .confirmed = true,
                            .notification = note,
                        } };
                    }
                    try self.sendApdu(origin, .{ .reject = .{
                        .invoke_id = r.invoke_id,
                        .reason = .unrecognized_service,
                    } });
                    return .{ .unhandled = .{ .from = origin, .pdu_type = .confirmed_request } };
                },
                .segment_ack => return .{ .unhandled = .{
                    .from = origin,
                    .pdu_type = .segment_ack,
                } },
            }
        }

        fn handleUnconfirmed(
            self: *Self,
            origin: BipAddress,
            u: apdu.UnconfirmedRequest,
        ) Error!Event {
            _ = self;
            switch (u.service) {
                .i_am => return .{ .i_am = .{
                    .from = origin,
                    .info = try service.IAm.decode(u.data),
                } },
                .i_have => return .{ .i_have = .{
                    .from = origin,
                    .info = try service.IHave.decode(u.data),
                } },
                .unconfirmed_cov_notification => return .{ .cov = .{
                    .from = origin,
                    .confirmed = false,
                    .notification = try service.CovNotification.decode(u.data),
                } },
                else => return .{ .unhandled = .{
                    .from = origin,
                    .pdu_type = .unconfirmed_request,
                } },
            }
        }

        /// A response PDU no outstanding transaction claims. Surfaced so a
        /// caller can log it — on a real segment this is what a spoofing
        /// attempt looks like from the client's side — and deliberately NOT
        /// turned into a completion event.
        fn unclaimed(origin: BipAddress, pdu_type: apdu.PduType) Event {
            return .{ .unhandled = .{ .from = origin, .pdu_type = pdu_type } };
        }

        /// Retires the transaction matching **both** `invoke_id` and the
        /// address the response came from. Clause 5.4 keys a TSM entry on the
        /// (invoke id, peer address) pair — `bacnet-stack`'s `tsm.c` does the
        /// same address match — because the invoke id alone is an 8-bit,
        /// sequentially-allocated, unauthenticated correlator: matching on it
        /// alone lets any host that can reach this socket cancel a transaction
        /// it knows nothing about.
        ///
        /// Returns whether a transaction was actually retired. `false` means
        /// the response is unclaimed: an id nobody asked about, a late answer
        /// to an already-timed-out request, or the right id from the wrong
        /// host.
        fn retire(self: *Self, invoke_id: u8, origin: BipAddress) bool {
            var retired = false;
            for (&self.pending) |*p| {
                if (p.active and p.invoke_id == invoke_id and p.peer.eql(origin)) {
                    p.active = false;
                    retired = true;
                }
            }
            return retired;
        }

        fn slot(self: *Self) ?*Pending {
            for (&self.pending) |*p| {
                if (!p.active) return p;
            }
            return null;
        }

        /// Picks an invoke id not currently outstanding.
        fn nextInvokeId(self: *Self) Error!u8 {
            var tries: usize = 0;
            while (tries < 256) : (tries += 1) {
                const id = self.next_id;
                self.next_id +%= 1;
                var live = false;
                for (self.pending) |p| {
                    if (p.active and p.invoke_id == id) live = true;
                }
                if (!live) return id;
            }
            return error.TooManyTransactions;
        }

        fn buildUnconfirmed(
            self: *Self,
            svc: types.UnconfirmedService,
            body: []const u8,
        ) Error![]u8 {
            var a_buf: [transport.max_datagram]u8 = undefined;
            const a = try apdu.encode(
                .{ .unconfirmed_request = .{ .service = svc, .data = body } },
                &a_buf,
            );
            var n_buf: [transport.max_datagram]u8 = undefined;
            // A Who-Is/Who-Has that must cross a BACnet router needs the
            // global-broadcast destination; a purely local one does not. The
            // global form is what a discovery sweep wants, and a device on the
            // local subnet accepts it either way.
            const n = try npdu.encode(
                .{ .destination = npdu.NetAddress.global, .hop_count = 255 },
                a,
                &n_buf,
            );
            return bvll.wrap(.original_broadcast_npdu, n, &self.tx);
        }

        fn sendApdu(self: *Self, to: BipAddress, a: apdu.Apdu) Error!void {
            var a_buf: [transport.max_datagram]u8 = undefined;
            const a_bytes = try apdu.encode(a, &a_buf);
            var n_buf: [transport.max_datagram]u8 = undefined;
            const n = try npdu.encode(.{}, a_bytes, &n_buf);
            var d_buf: [transport.max_datagram]u8 = undefined;
            const d = try bvll.wrap(.original_unicast_npdu, n, &d_buf);
            try self.tp.send(to, d);
        }

        fn sendConfirmed(
            self: *Self,
            to: BipAddress,
            svc: types.ConfirmedService,
            body: []const u8,
            now_ms: u64,
        ) Error!u8 {
            const p = self.slot() orelse return error.TooManyTransactions;
            const id = try self.nextInvokeId();

            var a_buf: [transport.max_datagram]u8 = undefined;
            const a = try apdu.encode(.{
                .confirmed_request = .{
                    .invoke_id = id,
                    .service = svc,
                    .max_apdu = self.config.max_apdu,
                    // Deliberately `.unspecified` + SA clear: this client does not
                    // reassemble, and saying so is what stops a device segmenting.
                    .max_segments = .unspecified,
                    .segmented_response_accepted = false,
                    .data = body,
                },
            }, &a_buf);
            var n_buf: [transport.max_datagram]u8 = undefined;
            const n = try npdu.encode(.{ .expecting_reply = true }, a, &n_buf);
            const dgram = try bvll.wrap(.original_unicast_npdu, n, &self.tx);
            if (dgram.len > p.datagram.len) return error.NoSpace;

            p.* = .{
                .invoke_id = id,
                .peer = to,
                .svc = svc,
                .deadline_ms = now_ms + self.config.apdu_timeout_ms,
                .attempts_left = self.config.retries,
                .active = true,
            };
            @memcpy(p.datagram[0..dgram.len], dgram);
            p.datagram_len = dgram.len;

            try self.tp.send(to, dgram);
            return id;
        }
    };
}

/// The client size a normal caller wants.
pub const DefaultClient = Client(16);

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A fake device that answers whatever the test needs it to.
const Peer = struct {
    tp: *transport.LoopTransport,
    rx: [transport.max_datagram]u8 = undefined,

    fn recvApdu(self: *Peer) !?struct { from: BipAddress, a: apdu.Apdu } {
        const got = (try self.tp.transport().recv(&self.rx)) orelse return null;
        const b = try bvll.decode(got.bytes);
        const n = try npdu.decode(b.npdu().?);
        return .{ .from = got.from, .a = try apdu.decode(n.payload.apdu) };
    }

    fn reply(self: *Peer, to: BipAddress, a: apdu.Apdu) !void {
        var a_buf: [transport.max_datagram]u8 = undefined;
        const ab = try apdu.encode(a, &a_buf);
        var n_buf: [transport.max_datagram]u8 = undefined;
        const nb = try npdu.encode(.{}, ab, &n_buf);
        var d_buf: [transport.max_datagram]u8 = undefined;
        const d = try bvll.wrap(.original_unicast_npdu, nb, &d_buf);
        try self.tp.transport().send(to, d);
    }

    fn announce(self: *Peer, a: apdu.Apdu) !void {
        var a_buf: [transport.max_datagram]u8 = undefined;
        const ab = try apdu.encode(a, &a_buf);
        var n_buf: [transport.max_datagram]u8 = undefined;
        const nb = try npdu.encode(.{}, ab, &n_buf);
        var d_buf: [transport.max_datagram]u8 = undefined;
        const d = try bvll.wrap(.original_broadcast_npdu, nb, &d_buf);
        try self.tp.transport().broadcast(d);
    }
};

const Rig = struct {
    net: transport.LoopNetwork = .{},
    client_ep: transport.LoopTransport = transport.LoopTransport.init(.{ .ip = .{ 192, 0, 2, 1 } }),
    device_ep: transport.LoopTransport = transport.LoopTransport.init(.{ .ip = .{ 192, 0, 2, 2 } }),

    fn wire(self: *Rig) void {
        self.net.attach(&self.client_ep);
        self.net.attach(&self.device_ep);
    }
};

test "Who-Is goes out as a global broadcast and I-Am comes back" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    try c.whoIs(1, 100);

    const req = (try peer.recvApdu()).?;
    try testing.expectEqual(types.UnconfirmedService.who_is, req.a.unconfirmed_request.service);
    const wi = try service.WhoIs.decode(req.a.unconfirmed_request.data);
    try testing.expectEqual(@as(?u32, 1), wi.low);
    try testing.expect(wi.matches(599 % 100));

    // Answer.
    var body: [32]u8 = undefined;
    var w = tag.Writer.init(&body);
    try (service.IAm{
        .device = .{ .type = .device, .instance = 599 },
        .max_apdu_accepted = 1476,
        .segmentation = .none,
        .vendor_id = 999,
    }).encode(&w);
    try peer.announce(.{ .unconfirmed_request = .{ .service = .i_am, .data = w.written() } });

    const ev = try c.poll(0);
    try testing.expectEqual(@as(u22, 599), ev.i_am.info.device.instance);
    try testing.expectEqual(types.Segmentation.none, ev.i_am.info.segmentation);
    try testing.expect(ev.i_am.from.eql(rig.device_ep.address));
    try testing.expectEqual(Event.none, try c.poll(0));
}

test "ReadProperty round trip: request, ComplexACK, correlated by invoke id" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    const id = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 5 },
        .present_value,
        null,
        0,
    );
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    try testing.expectEqual(@as(?u64, 3000), c.nextDeadline(0));

    const req = (try peer.recvApdu()).?;
    const cr = req.a.confirmed_request;
    try testing.expectEqual(id, cr.invoke_id);
    try testing.expectEqual(types.ConfirmedService.read_property, cr.service);
    // The client must NOT offer to accept a segmented response.
    try testing.expectEqual(false, cr.segmented_response_accepted);
    try testing.expectEqual(apdu.MaxSegments.unspecified, cr.max_segments);
    const rp = try service.ReadProperty.decode(cr.data);
    try testing.expect(rp.object.eql(.{ .type = .analog_input, .instance = 5 }));

    var ack_body: [64]u8 = undefined;
    var w = tag.Writer.init(&ack_body);
    var val: [8]u8 = undefined;
    var vw = tag.Writer.init(&val);
    try vw.appReal(72.5);
    try (service.ReadPropertyAck{
        .object = rp.object,
        .property = rp.property,
        .value = vw.written(),
    }).encode(&w);
    try peer.reply(req.from, .{ .complex_ack = .{
        .invoke_id = id,
        .service = .read_property,
        .data = w.written(),
    } });

    const ev = try c.poll(1);
    try testing.expectEqual(id, ev.complex_ack.invoke_id);
    const ack = try service.ReadPropertyAck.decode(ev.complex_ack.data);
    try testing.expectEqual(@as(f32, 72.5), (try ack.scalar()).real);
    // The transaction is retired, so the deadline is gone.
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(?u64, null), c.nextDeadline(1));
}

test "WriteProperty round trip with a priority, answered by SimpleACK" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    var val: [8]u8 = undefined;
    var vw = tag.Writer.init(&val);
    try vw.appReal(21.0);
    const id = try c.writeProperty(
        rig.device_ep.address,
        .{ .type = .analog_output, .instance = 1 },
        .present_value,
        null,
        vw.written(),
        8,
        0,
    );

    const req = (try peer.recvApdu()).?;
    const wp = try service.WriteProperty.decode(req.a.confirmed_request.data);
    try testing.expectEqual(@as(?u8, 8), wp.priority);
    try testing.expect(!wp.isRelinquish());

    try peer.reply(req.from, .{ .simple_ack = .{
        .invoke_id = id,
        .service = .write_property,
    } });
    const ev = try c.poll(1);
    try testing.expectEqual(id, ev.simple_ack.invoke_id);

    // And the relinquish form.
    const rid = try c.relinquish(
        rig.device_ep.address,
        .{ .type = .analog_output, .instance = 1 },
        .present_value,
        8,
        1,
    );
    const req2 = (try peer.recvApdu()).?;
    const wp2 = try service.WriteProperty.decode(req2.a.confirmed_request.data);
    try testing.expect(wp2.isRelinquish());
    try testing.expectEqual(rid, req2.a.confirmed_request.invoke_id);
}

test "an Error PDU completes the transaction with the device's reason" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    const id = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 99 },
        .present_value,
        null,
        0,
    );
    const req = (try peer.recvApdu()).?;
    try peer.reply(req.from, .{ .err = .{
        .invoke_id = id,
        .service = .read_property,
        .class = .object,
        .code = .unknown_object,
    } });
    const ev = try c.poll(1);
    try testing.expectEqual(types.ErrorClass.object, ev.err.class);
    try testing.expectEqual(types.ErrorCode.unknown_object, ev.err.code);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());

    // Reject and Abort retire it too.
    const id2 = try c.readProperty(rig.device_ep.address, .{ .type = .device, .instance = 1 }, .all, null, 1);
    const req2 = (try peer.recvApdu()).?;
    try peer.reply(req2.from, .{ .reject = .{ .invoke_id = id2, .reason = .undefined_enumeration } });
    const ev2 = try c.poll(2);
    try testing.expectEqual(types.RejectReason.undefined_enumeration, ev2.reject.reason);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "APDU timeout: the request is retried, then reported timed out" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{
        .apdu_timeout_ms = 1000,
        .retries = 2,
    });

    const id = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 5 },
        .present_value,
        null,
        0,
    );
    try testing.expectEqual(@as(usize, 1), rig.client_ep.sent_count);

    // Nothing before the deadline.
    try testing.expectEqual(Event.none, try c.poll(999));
    try testing.expectEqual(@as(usize, 1), rig.client_ep.sent_count);

    // First retry at the deadline: a resend, not an event.
    try testing.expectEqual(Event.none, try c.poll(1000));
    try testing.expectEqual(@as(usize, 2), rig.client_ep.sent_count);
    // Second retry.
    try testing.expectEqual(Event.none, try c.poll(2000));
    try testing.expectEqual(@as(usize, 3), rig.client_ep.sent_count);
    // Out of retries.
    const ev = try c.poll(3000);
    try testing.expectEqual(id, ev.timeout.invoke_id);
    try testing.expectEqual(types.ConfirmedService.read_property, ev.timeout.svc);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    // ... and it stays retired.
    try testing.expectEqual(Event.none, try c.poll(9999));
}

test "invoke ids are never reused while outstanding" {
    var rig: Rig = .{};
    rig.wire();
    var c = Client(4).init(rig.client_ep.transport(), .{});

    var ids: [4]u8 = undefined;
    for (&ids) |*id| {
        id.* = try c.readProperty(
            rig.device_ep.address,
            .{ .type = .analog_input, .instance = 1 },
            .present_value,
            null,
            0,
        );
    }
    for (ids, 0..) |a, i| {
        for (ids[i + 1 ..]) |b| try testing.expect(a != b);
    }
    try testing.expectEqual(@as(usize, 4), c.pendingCount());

    // The table is full.
    try testing.expectError(error.TooManyTransactions, c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 1 },
        .present_value,
        null,
        0,
    ));

    // Retiring one frees a slot, and the freed id may then come round again.
    var peer: Peer = .{ .tp = &rig.device_ep };
    const req = (try peer.recvApdu()).?;
    try peer.reply(req.from, .{ .simple_ack = .{
        .invoke_id = req.a.confirmed_request.invoke_id,
        .service = .read_property,
    } });
    _ = try c.poll(1);
    try testing.expectEqual(@as(usize, 3), c.pendingCount());
    _ = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 1 },
        .present_value,
        null,
        0,
    );
}

test "a segmented ComplexACK is refused with an Abort, not mis-parsed" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    const id = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .device, .instance = 599 },
        .object_list,
        null,
        0,
    );
    const req = (try peer.recvApdu()).?;

    // The device ignores the client's "no segmentation" and segments anyway.
    try peer.reply(req.from, .{ .complex_ack = .{
        .invoke_id = id,
        .service = .read_property,
        .segment = .{ .sequence_number = 0, .window_size = 4, .more_follows = true },
        .data = &.{ 0x0C, 0x02, 0x00, 0x02, 0x57 },
    } });

    const ev = try c.poll(1);
    try testing.expectEqual(id, ev.segmented_response.invoke_id);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());

    // The client sent an Abort back.
    const back = (try peer.recvApdu()).?;
    try testing.expectEqual(types.AbortReason.segmentation_not_supported, back.a.abort.reason);
    try testing.expectEqual(id, back.a.abort.invoke_id);
}

test "COV: unconfirmed is reported, confirmed is acknowledged first" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    const id = try c.subscribeCov(
        rig.device_ep.address,
        7,
        .{ .type = .analog_input, .instance = 5 },
        false,
        300,
        0,
    );
    const req = (try peer.recvApdu()).?;
    const sub = try service.SubscribeCov.decode(req.a.confirmed_request.data);
    try testing.expectEqual(@as(u32, 7), sub.process_id);
    try testing.expectEqual(@as(?u32, 300), sub.lifetime);
    try testing.expect(!sub.isCancellation());
    try peer.reply(req.from, .{ .simple_ack = .{ .invoke_id = id, .service = .subscribe_cov } });
    _ = try c.poll(1);

    // Build a notification.
    var vbuf: [64]u8 = undefined;
    var vw = tag.Writer.init(&vbuf);
    var inner: [8]u8 = undefined;
    var iw = tag.Writer.init(&inner);
    try iw.appReal(73.25);
    try service.writeCovValue(&vw, .{ .property = .present_value, .value = iw.written() });

    var nbuf: [128]u8 = undefined;
    var nw = tag.Writer.init(&nbuf);
    try (service.CovNotification{
        .process_id = 7,
        .initiating_device = .{ .type = .device, .instance = 599 },
        .monitored_object = .{ .type = .analog_input, .instance = 5 },
        .time_remaining = 280,
        .values_block = vw.written(),
    }).encode(&nw);

    // Unconfirmed: reported, nothing sent back.
    try peer.announce(.{ .unconfirmed_request = .{
        .service = .unconfirmed_cov_notification,
        .data = nw.written(),
    } });
    const ev = try c.poll(2);
    try testing.expectEqual(false, ev.cov.confirmed);
    try testing.expectEqual(@as(u32, 7), ev.cov.notification.process_id);
    var vals = ev.cov.notification.values();
    const v = (try vals.next()).?;
    var vr = tag.Reader.init(v.value);
    try testing.expectEqual(@as(f32, 73.25), (try vr.appValue()).real);
    try testing.expectEqual(@as(?transport.Received, null), try rig.device_ep.transport().recv(&peer.rx));

    // Confirmed: reported AND acknowledged.
    try peer.reply(rig.client_ep.address, .{ .confirmed_request = .{
        .invoke_id = 77,
        .service = .confirmed_cov_notification,
        .data = nw.written(),
    } });
    const ev2 = try c.poll(3);
    try testing.expectEqual(true, ev2.cov.confirmed);
    const ack = (try peer.recvApdu()).?;
    try testing.expectEqual(@as(u8, 77), ack.a.simple_ack.invoke_id);
    try testing.expectEqual(
        types.ConfirmedService.confirmed_cov_notification,
        ack.a.simple_ack.service,
    );
}

test "a confirmed request a client cannot serve is Rejected, not ignored" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    try peer.reply(rig.client_ep.address, .{ .confirmed_request = .{
        .invoke_id = 5,
        .service = .read_property,
        .data = &.{},
    } });
    const ev = try c.poll(0);
    try testing.expectEqual(apdu.PduType.confirmed_request, ev.unhandled.pdu_type);
    const back = (try peer.recvApdu()).?;
    try testing.expectEqual(types.RejectReason.unrecognized_service, back.a.reject.reason);
}

test "a Forwarded-NPDU is attributed to the original sender, not the BBMD" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});

    var body: [32]u8 = undefined;
    var w = tag.Writer.init(&body);
    try (service.IAm{
        .device = .{ .type = .device, .instance = 42 },
        .max_apdu_accepted = 480,
        .segmentation = .both,
        .vendor_id = 15,
    }).encode(&w);
    var a_buf: [64]u8 = undefined;
    const ab = try apdu.encode(
        .{ .unconfirmed_request = .{ .service = .i_am, .data = w.written() } },
        &a_buf,
    );
    var n_buf: [64]u8 = undefined;
    const nb = try npdu.encode(.{}, ab, &n_buf);
    var d_buf: [128]u8 = undefined;
    const origin: BipAddress = .{ .ip = .{ 198, 51, 100, 77 }, .port = 47808 };
    const d = try bvll.encode(.{ .forwarded_npdu = .{ .origin = origin, .npdu = nb } }, &d_buf);

    // The BBMD relays it.
    rig.client_ep.inject(rig.device_ep.address, d);
    const ev = try c.poll(0);
    try testing.expect(ev.i_am.from.eql(origin));
    try testing.expect(!ev.i_am.from.eql(rig.device_ep.address));
}

// Regression (audit W2 `bacnet` F5): a confirmed request whose encoded
// datagram exceeds the OLD 256-octet `Pending.datagram` cap, but stays well
// inside the negotiated 1476-octet max-APDU, must now succeed instead of
// `error.NoSpace` — the retry buffer is sized to `transport.max_datagram`
// (1500), matching what `sendConfirmed` already bounds the encoded datagram
// to via `bvll.wrap`.
test "F5: a ReadPropertyMultiple whose datagram exceeds the old 256-octet cap still sends" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    const two_props = [_]service.PropertyReference{
        .{ .property = .present_value },
        .{ .property = .status_flags },
    };
    // 30 objects x 2 properties: comfortably past the old 256-byte ceiling
    // (each object costs roughly a dozen encoded bytes) while staying well
    // under both the 400-byte local RPM-body buffer and the new 1500-byte
    // datagram cap.
    var specs: [30]RpmSpec = undefined;
    for (&specs, 0..) |*s, i| {
        s.* = .{
            .object = .{ .type = .analog_input, .instance = @intCast(i) },
            .properties = &two_props,
        };
    }

    const id = try c.readPropertyMultiple(rig.device_ep.address, &specs, 0);

    const req = (try peer.recvApdu()).?;
    try testing.expectEqual(id, req.a.confirmed_request.invoke_id);
    // The whole point: the RPM body alone already exceeds what used to be
    // the entire datagram's ceiling.
    try testing.expect(req.a.confirmed_request.data.len > 256);

    // Every object round-trips — nothing was silently truncated to fit.
    var it = service.RpmRequestIterator.init(req.a.confirmed_request.data);
    var seen: usize = 0;
    while (try it.next()) |s| {
        try testing.expect(s.object.eql(.{ .type = .analog_input, .instance = @intCast(seen) }));
        seen += 1;
    }
    try testing.expectEqual(specs.len, seen);

    // And the pending transaction really did retain the full datagram for a
    // resend — not just accept the initial send.
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
}

test "garbage from a stranger does not kill the poll loop" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});

    const junk = [_][]const u8{
        &.{ 0x00, 0x00 }, // not BVLC
        &.{ 0x81, 0x0B, 0xFF, 0xFF, 0x01 }, // length lies
        &.{ 0x81, 0x0B, 0x00, 0x06, 0x01, 0x20 }, // NPDU promises a destination
        &.{ 0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x0C, 0x05 }, // segmented, truncated
        &.{ 0x81, 0xFF, 0x00, 0x04 }, // unknown BVLC function
        &.{ 0x81, 0x0B, 0x00, 0x07, 0x01, 0x00, 0xF0 }, // impossible PDU type
    };
    for (junk) |j| rig.client_ep.inject(.{ .ip = .{ 10, 0, 0, 1 } }, j);
    for (junk) |_| try testing.expectEqual(Event.none, try c.poll(0));
    try testing.expectEqual(Event.none, try c.poll(0));
}

test "ReadPropertyMultiple carries several objects in one request" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    const id = try c.readPropertyMultiple(rig.device_ep.address, &.{
        .{
            .object = .{ .type = .analog_input, .instance = 5 },
            .properties = &.{
                .{ .property = .present_value },
                .{ .property = .status_flags },
            },
        },
        .{
            .object = .{ .type = .device, .instance = 599 },
            .properties = &.{.{ .property = .all }},
        },
    }, 0);

    const req = (try peer.recvApdu()).?;
    try testing.expectEqual(id, req.a.confirmed_request.invoke_id);
    var it = service.RpmRequestIterator.init(req.a.confirmed_request.data);
    const s1 = (try it.next()).?;
    try testing.expect(s1.object.eql(.{ .type = .analog_input, .instance = 5 }));
    var p1 = s1.properties();
    try testing.expectEqual(types.PropertyIdentifier.present_value, (try p1.next()).?.property);
    try testing.expectEqual(types.PropertyIdentifier.status_flags, (try p1.next()).?.property);
    const s2 = (try it.next()).?;
    try testing.expect(s2.object.eql(.{ .type = .device, .instance = 599 }));
    try testing.expectEqual(@as(?service.RpmRequestIterator.Spec, null), try it.next());

    // Answer with a value and a per-property error.
    var buf: [128]u8 = undefined;
    var w = tag.Writer.init(&buf);
    var b = service.RpmAckBuilder.init(&w);
    try b.object(.{ .type = .analog_input, .instance = 5 });
    var vbuf: [8]u8 = undefined;
    var vw = tag.Writer.init(&vbuf);
    try vw.appReal(72.5);
    try b.value(.present_value, null, vw.written());
    try b.accessError(.status_flags, null, .property, .unknown_property);
    try b.finish();
    try peer.reply(req.from, .{ .complex_ack = .{
        .invoke_id = id,
        .service = .read_property_multiple,
        .data = w.written(),
    } });

    const ev = try c.poll(1);
    var ait = service.RpmAckIterator.init(ev.complex_ack.data);
    var els = (try ait.next()).?.results();
    const e1 = (try els.next()).?;
    var er = tag.Reader.init(e1.outcome.value);
    try testing.expectEqual(@as(f32, 72.5), (try er.appValue()).real);
    const e2 = (try els.next()).?;
    try testing.expectEqual(types.ErrorCode.unknown_property, e2.outcome.access_error.code);
}

test "Who-Has by name and by id both go out as broadcasts" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    try c.whoHasName("ZONE-TEMP", null, null);
    const r1 = (try peer.recvApdu()).?;
    const wh1 = try service.WhoHas.decode(r1.a.unconfirmed_request.data);
    try testing.expectEqualStrings("ZONE-TEMP", wh1.target.object_name);

    try c.whoHasId(.{ .type = .analog_input, .instance = 3 }, 1, 100);
    const r2 = (try peer.recvApdu()).?;
    const wh2 = try service.WhoHas.decode(r2.a.unconfirmed_request.data);
    try testing.expect(wh2.target.object_id.eql(.{ .type = .analog_input, .instance = 3 }));
    try testing.expectEqual(@as(?u32, 1), wh2.low);

    // And the answer comes back as an event.
    var body: [64]u8 = undefined;
    var w = tag.Writer.init(&body);
    try (service.IHave{
        .device = .{ .type = .device, .instance = 599 },
        .object = .{ .type = .analog_input, .instance = 3 },
        .object_name = "ZONE-TEMP",
    }).encode(&w);
    try peer.announce(.{ .unconfirmed_request = .{ .service = .i_have, .data = w.written() } });
    const ev = try c.poll(0);
    try testing.expectEqualStrings("ZONE-TEMP", ev.i_have.info.object_name);
}

test "ReadRange asks for a slice of a trend log" {
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var peer: Peer = .{ .tp = &rig.device_ep };

    _ = try c.readRange(
        rig.device_ep.address,
        .{ .type = .trend_log, .instance = 1 },
        .log_buffer,
        .{ .by_position = .{ .reference_index = 1, .count = 10 } },
        0,
    );
    const req = (try peer.recvApdu()).?;
    try testing.expectEqual(types.ConfirmedService.read_range, req.a.confirmed_request.service);
    const rr = try service.ReadRange.decode(req.a.confirmed_request.data);
    try testing.expectEqual(@as(i32, 10), rr.range.?.by_position.count);
}

// ── the TSM is keyed on (invoke id, peer address), not the id alone ─────────
//
// Base BACnet/IP is unauthenticated: any host that can put a UDP datagram on
// the client's port is a peer. Invoke ids are 8 bits wide and handed out
// sequentially, so a response that correlates on the id alone is a response an
// off-path guess can forge. Clause 5.4 keys a TSM entry on the pair, and
// `bacnet-stack`'s `tsm.c` compares the address before it touches the entry.
//
// Everything the impostor below sends is *well formed* — right BVLC framing,
// right PDU type, right service, right invoke id. The only thing wrong with it
// is who it came from.

/// A third host on the segment, and the fake device that speaks from it.
const Impostor = struct {
    ep: transport.LoopTransport = transport.LoopTransport.init(.{ .ip = .{ 192, 0, 2, 66 } }),

    fn join(self: *Impostor, rig: *Rig) Peer {
        rig.net.attach(&self.ep);
        return .{ .tp = &self.ep };
    }
};

/// A perfectly valid ReadPropertyAck body carrying `value`.
fn readPropertyAckBody(buf: []u8, value_buf: []u8, value: f32) ![]const u8 {
    var vw = tag.Writer.init(value_buf);
    try vw.appReal(value);
    var w = tag.Writer.init(buf);
    try (service.ReadPropertyAck{
        .object = .{ .type = .analog_input, .instance = 5 },
        .property = .present_value,
        .value = vw.written(),
    }).encode(&w);
    return w.written();
}

test "a forged ComplexACK from another host is not this transaction's answer" {
    var rig: Rig = .{};
    rig.wire();
    var imp: Impostor = .{};
    var impostor = imp.join(&rig);
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var device: Peer = .{ .tp = &rig.device_ep };

    const id = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 5 },
        .present_value,
        null,
        0,
    );
    const req = (try device.recvApdu()).?;
    try testing.expectEqual(id, req.a.confirmed_request.invoke_id);

    // The impostor answers first, with the id it guessed and a value of its
    // choosing.
    var ack_buf: [64]u8 = undefined;
    var val_buf: [8]u8 = undefined;
    try impostor.reply(rig.client_ep.address, .{ .complex_ack = .{
        .invoke_id = id,
        .service = .read_property,
        .data = try readPropertyAckBody(&ack_buf, &val_buf, -999.0),
    } });

    const ev = try c.poll(1);
    try testing.expectEqual(std.meta.Tag(Event).unhandled, std.meta.activeTag(ev));
    try testing.expectEqual(apdu.PduType.complex_ack, ev.unhandled.pdu_type);
    try testing.expect(ev.unhandled.from.eql(imp.ep.address));
    // The transaction the client actually opened is untouched.
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    try testing.expectEqual(@as(?u64, 2999), c.nextDeadline(1));

    // ... and the real device's answer still completes it, with the real value.
    var real_buf: [64]u8 = undefined;
    var real_val: [8]u8 = undefined;
    try device.reply(req.from, .{ .complex_ack = .{
        .invoke_id = id,
        .service = .read_property,
        .data = try readPropertyAckBody(&real_buf, &real_val, 72.5),
    } });
    const good = try c.poll(2);
    try testing.expectEqual(std.meta.Tag(Event).complex_ack, std.meta.activeTag(good));
    try testing.expectEqual(id, good.complex_ack.invoke_id);
    const ack = try service.ReadPropertyAck.decode(good.complex_ack.data);
    try testing.expectEqual(@as(f32, 72.5), (try ack.scalar()).real);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "no response PDU from a stranger can cancel an outstanding transaction" {
    // The other four completion PDUs: each one, sent from the wrong address
    // with the right invoke id, is a free transaction-cancel if the TSM
    // matches on the id alone.
    var rig: Rig = .{};
    rig.wire();
    var imp: Impostor = .{};
    var impostor = imp.join(&rig);
    // No retries, so the deadline below is the timeout rather than a resend.
    var c = DefaultClient.init(rig.client_ep.transport(), .{ .retries = 0 });
    var device: Peer = .{ .tp = &rig.device_ep };

    const id = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 5 },
        .present_value,
        null,
        0,
    );
    _ = (try device.recvApdu()).?;

    const forgeries = [_]apdu.Apdu{
        .{ .simple_ack = .{ .invoke_id = id, .service = .read_property } },
        .{ .err = .{
            .invoke_id = id,
            .service = .read_property,
            .class = .object,
            .code = .unknown_object,
        } },
        .{ .reject = .{ .invoke_id = id, .reason = .undefined_enumeration } },
        .{ .abort = .{ .invoke_id = id, .reason = .other } },
    };
    const expected = [_]apdu.PduType{ .simple_ack, .err, .reject, .abort };
    for (forgeries, expected) |f, pdu_type| {
        try impostor.reply(rig.client_ep.address, f);
        const ev = try c.poll(1);
        try testing.expectEqual(std.meta.Tag(Event).unhandled, std.meta.activeTag(ev));
        try testing.expectEqual(pdu_type, ev.unhandled.pdu_type);
        try testing.expectEqual(@as(usize, 1), c.pendingCount());
    }

    // A forged *segmented* ComplexACK is likewise not this transaction's, so
    // the client does not tear the transaction down — nor send an Abort to a
    // host it has no transaction with.
    try impostor.reply(rig.client_ep.address, .{ .complex_ack = .{
        .invoke_id = id,
        .service = .read_property,
        .segment = .{ .sequence_number = 0, .window_size = 4, .more_follows = true },
        .data = &.{ 0x0C, 0x02, 0x00, 0x02, 0x57 },
    } });
    const ev = try c.poll(1);
    try testing.expectEqual(std.meta.Tag(Event).unhandled, std.meta.activeTag(ev));
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    try testing.expectEqual(@as(?transport.Received, null), try imp.ep.transport().recv(&impostor.rx));

    // The genuine device still owns the transaction, and still times it out.
    const ev_timeout = try c.poll(3000);
    try testing.expectEqual(std.meta.Tag(Event).timeout, std.meta.activeTag(ev_timeout));
    try testing.expectEqual(id, ev_timeout.timeout.invoke_id);
}

test "a stale response to an already-retired transaction is not a second answer" {
    // The same guard, arrived at from the other side: the peer address matches
    // but nothing is outstanding, because the answer already came.
    var rig: Rig = .{};
    rig.wire();
    var c = DefaultClient.init(rig.client_ep.transport(), .{});
    var device: Peer = .{ .tp = &rig.device_ep };

    const id = try c.readProperty(
        rig.device_ep.address,
        .{ .type = .analog_input, .instance = 5 },
        .present_value,
        null,
        0,
    );
    const req = (try device.recvApdu()).?;
    var buf: [64]u8 = undefined;
    var vbuf: [8]u8 = undefined;
    const body = try readPropertyAckBody(&buf, &vbuf, 72.5);
    try device.reply(req.from, .{ .complex_ack = .{
        .invoke_id = id,
        .service = .read_property,
        .data = body,
    } });
    try testing.expectEqual(std.meta.Tag(Event).complex_ack, std.meta.activeTag(try c.poll(1)));

    // A duplicate of the very same datagram — a retransmission, or a replay.
    try device.reply(req.from, .{ .complex_ack = .{
        .invoke_id = id,
        .service = .read_property,
        .data = body,
    } });
    const ev = try c.poll(2);
    try testing.expectEqual(std.meta.Tag(Event).unhandled, std.meta.activeTag(ev));
    try testing.expectEqual(apdu.PduType.complex_ack, ev.unhandled.pdu_type);
}

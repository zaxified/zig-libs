// SPDX-License-Identifier: MIT

//! Seven adapters, one seam. Each of these wraps a responder from its own
//! module and presents it as a `Node`. **Nothing here modifies a responder** —
//! the whole point is that the seven modules stay independent of the fleet, and
//! the fleet knows how to hold each of them.
//!
//! Three shapes turn up:
//!
//!   1. *Already packet-to-packet* — Modbus (`handleAdu`), S7 (`handle`),
//!      ENIP (`handle`): the adapter is a signature translation and an error
//!      map, nothing more.
//!   2. *Framed session* — DNP3 (`Session.feedFrame`), OPC UA
//!      (`Connection.feed` into a `std.Io.Writer`): the adapter owns the
//!      session buffers.
//!   3. *Transport-driven* — IEC 104 (`Server.poll`) and BACnet
//!      (`Device.poll`) pull from a `Transport` vtable. For those the adapter
//!      supplies a **shim transport** from `shim.zig`: one injected
//!      datagram/chunk in, an output buffer out. Both modules ship a
//!      `LoopTransport` of their own, but those are built for peer-to-peer
//!      offline tests (16-slot mailbox, 1.5 kB per slot) and would cost ~24 kB
//!      per simulated node; the shim is the same idea sized for a 1000-node
//!      fleet. See `shim.zig`'s header for why it lives in this module.
//!
//! **Restart** is uniform: every adapter snapshots its responder's value at
//! construction and restores it on `Control.restart`. That is a genuine
//! power-cycle for these responders (their state is plain data over
//! caller-owned storage), and it is what makes a master see DNP3's IIN1.7,
//! S7's re-negotiated PDU size or OPC UA's closed channel.
//!
//! **Trouble** is native in all seven, each in the vocabulary its own protocol
//! gives a degraded device:
//!
//! | protocol | what a master sees |
//! |---|---|
//! | Modbus | exception `0x04 SlaveDeviceFailure` on every request |
//! | DNP3 | `IIN1.6 device_trouble` |
//! | IEC 104 | the `iv` quality bit on every point that carries quality |
//! | S7comm | SZL `0x0424` CPU status `STOP` |
//! | BACnet | `Reliability = unreliable-other`, `StatusFlags{fault,in_alarm,out_of_service}`, `Out_Of_Service = true` |
//! | EtherNet/IP | Identity status word major-fault bits; CIP data services answer `0x10 Device State Conflict` |
//! | OPC UA | `ServerStatus.State = Failed`, and `BadDeviceFailure` on the variables the caller nominated |
//!
//! Where the state that expresses trouble belongs to the *caller* (BACnet
//! object properties, an OPC UA `NodeStore`), the adapter reaches it through
//! the responder module's own public API and reports honestly — `control`
//! returns false, and the fleet records `control_unsupported`, when the caller
//! gave it nothing to degrade (a BACnet device whose objects carry none of the
//! three fault properties).

const std = @import("std");

const modbus = @import("modbus");
const dnp3 = @import("dnp3");
const iec104 = @import("iec104");
const s7comm = @import("s7comm");
const bacnet = @import("bacnet");
const enip = @import("enip");
const opcua = @import("opcua");

const node_mod = @import("node.zig");
const shim_mod = @import("shim.zig");

pub const StreamShim = shim_mod.StreamShim;
pub const DatagramShim = shim_mod.DatagramShim;

pub const Node = node_mod.Node;
pub const NodeError = node_mod.NodeError;
pub const Control = node_mod.Control;
pub const Time = node_mod.Time;

// ── Modbus ──────────────────────────────────────────────────────────────────

/// A simulated Modbus slave. Pin the value in place before calling `node()` —
/// the vtable closes over this struct's address.
pub const Modbus = struct {
    server: modbus.server.Server,
    saved: modbus.server.Server,
    trouble: bool = false,

    pub fn init(config: modbus.server.Config, db: modbus.server.DataBank) Modbus {
        const s = modbus.server.Server.init(config, db);
        return .{ .server = s, .saved = s };
    }

    pub fn node(self: *Modbus) Node {
        return .{
            .ctx = self,
            .protocol = .modbus,
            .framing = switch (self.server.config.framing) {
                .tcp => .modbus_tcp,
                .rtu => .opaque_whole,
            },
            .vtable = &.{ .deliver = deliverFn, .control = controlFn },
        };
    }

    fn cast(ctx: *anyopaque) *Modbus {
        return @ptrCast(@alignCast(ctx));
    }

    fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        _ = now_ms; // a Modbus slave has no timers at all
        const self = cast(ctx);
        if (self.trouble) return self.troubleReply(bytes, out);
        return self.server.handleAdu(bytes, out) catch |err| switch (err) {
            error.BufferTooSmall => error.OutputTooSmall,
        };
    }

    /// §7: `SlaveDeviceFailure` (0x04) is the exception a device returns when
    /// "an unrecoverable error occurred while the server was attempting to
    /// perform the requested action" — the closest thing Modbus has to
    /// "I am broken", and what a fault-injection run wants a master to see.
    fn troubleReply(self: *Modbus, adu: []const u8, out: []u8) NodeError!?[]const u8 {
        const failure: u8 = @intFromEnum(modbus.ExceptionCode.server_device_failure);
        switch (self.server.config.framing) {
            .tcp => {
                const frame = modbus.tcp.decodeAdu(adu) catch return null;
                if (frame.pdu.len == 0) return null;
                const pdu = [_]u8{ frame.pdu[0] | 0x80, failure };
                return modbus.tcp.encodeAdu(out, frame.transaction_id, frame.unit, &pdu) catch
                    error.OutputTooSmall;
            },
            .rtu => {
                const frame = modbus.rtu.decodeAdu(adu) catch return null;
                if (frame.pdu.len == 0 or frame.unit == 0) return null;
                const pdu = [_]u8{ frame.pdu[0] | 0x80, failure };
                return modbus.rtu.encodeAdu(out, frame.unit, &pdu) catch error.OutputTooSmall;
            },
        }
    }

    fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
        _ = now_ms;
        const self = cast(ctx);
        switch (op) {
            .restart => {
                self.server = self.saved;
                self.trouble = false;
            },
            .trouble_on => self.trouble = true,
            .trouble_off => self.trouble = false,
        }
        return true;
    }
};

// ── DNP3 ────────────────────────────────────────────────────────────────────

/// A simulated DNP3 outstation, framed at the data-link layer (which is what
/// DNP3-over-TCP puts on the wire).
///
/// This adapter used to re-implement unsolicited framing over `dnp3`'s public
/// `link`/`transport` API, because `Session.sendFragment` is private. It no
/// longer does: `dnp3.outstation.Session.unsolicitedFrames` is the public
/// counterpart of `nextFrames`, and it owns `tx_seq` — which is exactly why the
/// duplicate was a bug waiting to happen.
pub const Dnp3 = struct {
    station: dnp3.outstation.Outstation,
    saved: dnp3.outstation.Outstation,
    session: dnp3.outstation.Session = undefined,
    rx_buf: []u8,
    scratch: []u8,
    tx_fragment: []u8,

    /// Fills `self` in place: `Session` holds a pointer to `station`, so the
    /// pair cannot be returned by value.
    pub fn init(
        self: *Dnp3,
        config: dnp3.outstation.Config,
        db: dnp3.outstation.Database,
        events: dnp3.outstation.EventBuffer,
        rx_buf: []u8,
        scratch: []u8,
        tx_fragment: []u8,
    ) void {
        const st = dnp3.outstation.Outstation.init(config, db, events);
        self.* = .{
            .station = st,
            .saved = st,
            .rx_buf = rx_buf,
            .scratch = scratch,
            .tx_fragment = tx_fragment,
        };
        self.session = dnp3.outstation.Session.init(&self.station, rx_buf, scratch, tx_fragment);
    }

    pub fn node(self: *Dnp3) Node {
        return .{
            .ctx = self,
            .protocol = .dnp3,
            .framing = .dnp3_link,
            .vtable = &.{
                .deliver = deliverFn,
                .tick = tickFn,
                .nextDeadline = deadlineFn,
                .control = controlFn,
            },
        };
    }

    fn cast(ctx: *anyopaque) *Dnp3 {
        return @ptrCast(@alignCast(ctx));
    }

    fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        const self = cast(ctx);
        const reply = self.session.feedFrame(bytes, now_ms, out) catch |err| switch (err) {
            error.BufferTooSmall => return error.OutputTooSmall,
            // Every remaining case is a peer that sent nonsense (bad CRC, bad
            // start bytes, a transport-sequence break). A real outstation
            // discards those without a word.
            else => return null,
        };
        return reply;
    }

    fn tickFn(ctx: *anyopaque, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        const self = cast(ctx);
        self.station.tick(now_ms);
        const unsolicited = self.session.unsolicitedFrames(now_ms, out) catch |err| switch (err) {
            error.BufferTooSmall => return error.OutputTooSmall,
            else => null,
        };
        if (unsolicited) |frames| return frames;
        const more = self.session.nextFrames(now_ms, out) catch |err| switch (err) {
            error.BufferTooSmall => return error.OutputTooSmall,
            else => return null,
        };
        return more;
    }

    fn deadlineFn(ctx: *anyopaque, now_ms: Time) ?Time {
        _ = now_ms;
        const self = cast(ctx);
        return self.station.nextDeadline();
    }

    fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
        _ = now_ms;
        const self = cast(ctx);
        switch (op) {
            .restart => {
                // §5.1.4.1: after a restart IIN1.7 is set again and only an
                // explicit WRITE of g80v1 index 7 clears it.
                self.station = self.saved;
                self.session = dnp3.outstation.Session.init(
                    &self.station,
                    self.rx_buf,
                    self.scratch,
                    self.tx_fragment,
                );
            },
            .trouble_on => self.station.device_trouble = true,
            .trouble_off => self.station.device_trouble = false,
        }
        return true;
    }
};

// ── IEC 60870-5-104 ─────────────────────────────────────────────────────────

pub const Iec104 = struct {
    server: iec104.OutstationServer = undefined,
    saved: iec104.OutstationServer = undefined,
    shim: StreamShim = .{},
    points: []iec104.Point,
    frame_buf: []u8,
    queue_buf: []u8,

    /// Bounds the poll loop: one inbound APDU can legitimately produce many
    /// queued ASDUs (a general interrogation), but never an unbounded number.
    const max_poll_rounds = 512;

    pub fn init(
        self: *Iec104,
        opts: iec104.outstation.Options,
        points: []iec104.Point,
        frame_buf: []u8,
        queue_buf: []u8,
        config: iec104.Config,
    ) !void {
        self.* = .{ .points = points, .frame_buf = frame_buf, .queue_buf = queue_buf };
        self.server = try iec104.OutstationServer.init(
            opts,
            points,
            self.shim.transport(),
            frame_buf,
            queue_buf,
            config,
        );
        self.saved = self.server;
        self.server.onConnected(0);
    }

    pub fn node(self: *Iec104) Node {
        return .{
            .ctx = self,
            .protocol = .iec104,
            .framing = .iec104_apci,
            .vtable = &.{
                .deliver = deliverFn,
                .tick = tickFn,
                .nextDeadline = deadlineFn,
                .control = controlFn,
            },
        };
    }

    fn cast(ctx: *anyopaque) *Iec104 {
        return @ptrCast(@alignCast(ctx));
    }

    fn pump(self: *Iec104, input: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        self.shim.reset(input, out);
        // The Transport vtable ctx was bound to `&self.shim` at init; a moved
        // adapter would dangle, so re-point it every call. Cheap, and it makes
        // the struct movable, which a 1000-node ArrayList wants.
        self.server.transport = self.shim.transport();
        var rounds: usize = 0;
        while (rounds < max_poll_rounds) : (rounds += 1) {
            const ev = self.server.poll(now_ms) catch |err| switch (err) {
                error.WriteFailed => return error.OutputTooSmall,
                else => break, // a protocol error closes the connection
            };
            if (ev == .none and self.shim.window.drained()) break;
            if (ev == .closed) break;
        }
        if (self.shim.window.overflow) return error.OutputTooSmall;
        const w = self.shim.written();
        return if (w.len == 0) null else w;
    }

    fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        return cast(ctx).pump(bytes, out, now_ms);
    }

    fn tickFn(ctx: *anyopaque, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        return cast(ctx).pump(&.{}, out, now_ms);
    }

    fn deadlineFn(ctx: *anyopaque, now_ms: Time) ?Time {
        _ = now_ms;
        return cast(ctx).server.nextDeadline();
    }

    /// Queue a spontaneous report (cause 3) for one point — the "something
    /// changed in the field" path a simulation drives.
    pub fn reportSpontaneous(self: *Iec104, ioa: u32, now_ms: Time) !void {
        self.server.transport = self.shim.transport();
        try self.server.reportSpontaneous(ioa, now_ms);
    }

    fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
        const self = cast(ctx);
        switch (op) {
            .restart => {
                self.server = self.saved;
                self.server.transport = self.shim.transport();
                self.server.onConnected(now_ms);
            },
            // §7.2.6.3: `iv` marks a value the acquisition function knows is
            // not correct — a device reporting its own trouble.
            .trouble_on => setQuality(self.points, true),
            .trouble_off => setQuality(self.points, false),
        }
        return true;
    }

    fn setQuality(points: []iec104.Point, invalid: bool) void {
        for (points) |*p| {
            switch (p.element) {
                inline else => |*v| {
                    const T = @TypeOf(v.*);
                    if (@typeInfo(T) == .@"struct" and @hasField(T, "quality")) {
                        v.quality.iv = invalid;
                    }
                },
            }
        }
    }
};

// ── S7comm ──────────────────────────────────────────────────────────────────

pub const S7comm = struct {
    responder: s7comm.Responder,
    saved: s7comm.Responder,

    pub fn init(config: s7comm.ResponderConfig, areas: []const s7comm.AreaBinding) S7comm {
        const r = s7comm.Responder.init(config, areas);
        return .{ .responder = r, .saved = r };
    }

    pub fn node(self: *S7comm) Node {
        return .{
            .ctx = self,
            .protocol = .s7comm,
            .framing = .tpkt,
            .vtable = &.{ .deliver = deliverFn, .control = controlFn },
        };
    }

    fn cast(ctx: *anyopaque) *S7comm {
        return @ptrCast(@alignCast(ctx));
    }

    fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        _ = now_ms;
        const self = cast(ctx);
        return self.responder.handle(bytes, out) catch |err| switch (err) {
            error.BufferTooSmall => error.OutputTooSmall,
            // A real CPU drops a packet it cannot parse rather than answering.
            else => null,
        };
    }

    fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
        _ = now_ms;
        const self = cast(ctx);
        switch (op) {
            .restart => self.responder = self.saved,
            // SZL 0x0424 reports the operating mode; STOP is how a real CPU
            // announces it is not running the program.
            .trouble_on => self.responder.config.cpu_status = .stop,
            .trouble_off => self.responder.config.cpu_status = .run,
        }
        return true;
    }
};

// ── BACnet/IP ───────────────────────────────────────────────────────────────

/// `Reliability` (clause 21) as an enumerated property value. A simulated
/// device that is "just broken" reports `unreliable-other`: every other member
/// of the enumeration claims a specific failure mode (no-sensor, over-range,
/// open-loop) that this adapter has no basis to assert.
const reliability_no_fault: u32 = 0;
const reliability_unreliable_other: u32 = 7;

/// The two `StatusFlags` octets a simulated point can be in. Both are comptime
/// constants, so no per-object storage is needed: every degraded object in a
/// simulated device is degraded the same way.
const status_flags_healthy = [_]u8{(bacnet.StatusFlags{}).toOctet()};
const status_flags_trouble = [_]u8{(bacnet.StatusFlags{
    .in_alarm = true,
    .fault = true,
    .out_of_service = true,
}).toOctet()};

/// A simulated BACnet/IP device. `max_subscriptions` bounds the COV table.
pub fn Bacnet(comptime max_subscriptions: usize) type {
    return struct {
        const Self = @This();
        pub const DeviceType = bacnet.DeviceWith(max_subscriptions);

        device: DeviceType = undefined,
        saved: DeviceType = undefined,
        shim: DatagramShim,
        trouble: bool = false,
        /// Set when trouble was applied and the COV subscribers have not been
        /// told yet: `control` has no output buffer, so the notification goes
        /// out on the next `tick`, which does.
        cov_pending: bool = false,

        pub fn init(
            self: *Self,
            config: bacnet.device.Config,
            objects: []bacnet.Object,
            address: bacnet.BipAddress,
            peer: bacnet.BipAddress,
        ) void {
            self.* = .{ .shim = .{ .address = address, .peer = peer } };
            self.device = DeviceType.init(self.shim.transport(), config, objects);
            self.saved = self.device;
        }

        pub fn node(self: *Self) Node {
            return .{
                .ctx = self,
                .protocol = .bacnet,
                .framing = .bacnet_bvll,
                .vtable = &.{
                    .deliver = deliverFn,
                    .tick = tickFn,
                    .control = controlFn,
                },
            };
        }

        fn cast(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }

        fn pump(self: *Self, dgram: ?[]const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
            self.shim.reset(dgram orelse &.{}, out);
            self.device.tp = self.shim.transport();
            // One datagram in, then one drain round for anything the device
            // wants to say on its own (an expiring subscription).
            var rounds: usize = 0;
            while (rounds < 4) : (rounds += 1) {
                const ev = self.device.poll(now_ms) catch |err| switch (err) {
                    error.SendFailed => return error.OutputTooSmall,
                    else => break,
                };
                if (ev == .none) break;
            }
            if (self.shim.window.overflow) return error.OutputTooSmall;
            const w = self.shim.written();
            return if (w.len == 0) null else w;
        }

        fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
            return cast(ctx).pump(bytes, out, now_ms);
        }

        fn tickFn(ctx: *anyopaque, out: []u8, now_ms: Time) NodeError!?[]const u8 {
            const self = cast(ctx);
            if (self.cov_pending) {
                self.cov_pending = false;
                return self.notifyTrouble(out, now_ms);
            }
            return self.pump(null, out, now_ms);
        }

        /// Re-publish `status_flags` on every object that reports it by COV, so
        /// a master with a live subscription learns about the fault instead of
        /// having to poll for it. Re-writing the identical value is what drives
        /// the notification — `Device.update` notifies on every write of a
        /// `cov_reported` property.
        fn notifyTrouble(self: *Self, out: []u8, now_ms: Time) NodeError!?[]const u8 {
            self.shim.reset(&.{}, out);
            self.device.tp = self.shim.transport();
            for (self.device.objects) |*obj| {
                const p = obj.find(.status_flags) orelse continue;
                if (!p.cov_reported) continue;
                self.device.update(obj.id, .status_flags, p.value, now_ms) catch break;
            }
            if (self.shim.window.overflow) return error.OutputTooSmall;
            const w = self.shim.written();
            return if (w.len == 0) null else w;
        }

        /// Change a property and notify every COV subscriber — the entry point
        /// a signal sink drives.
        pub fn update(
            self: *Self,
            id: bacnet.ObjectId,
            prop: bacnet.PropertyIdentifier,
            v: bacnet.PropertyValue,
            now_ms: Time,
            out: []u8,
        ) NodeError!?[]const u8 {
            self.shim.reset(&.{}, out);
            self.device.tp = self.shim.transport();
            self.device.update(id, prop, v, now_ms) catch return error.ResponderFailed;
            const w = self.shim.written();
            return if (w.len == 0) null else w;
        }

        /// Clause 12: a BACnet object says it is broken through three
        /// properties — `Reliability` (*why* it is untrustworthy),
        /// `Status_Flags` (the summary bits every present-value-carrying object
        /// exposes) and `Out_Of_Service` (the value is decoupled from the
        /// physical input). Set all three that the caller's object model
        /// actually declares, and report how many properties were touched so
        /// `control` can refuse honestly when the model declares none.
        fn applyTrouble(self: *Self, on: bool) usize {
            var touched: usize = 0;
            for (self.device.objects) |*obj| {
                if (obj.find(.reliability)) |p| {
                    p.value = .{ .enumerated = if (on) reliability_unreliable_other else reliability_no_fault };
                    touched += 1;
                }
                if (obj.find(.status_flags)) |p| {
                    p.value = .{ .bit_string = .{
                        .unused_bits = 4,
                        .bytes = if (on) &status_flags_trouble else &status_flags_healthy,
                    } };
                    touched += 1;
                }
                if (obj.find(.out_of_service)) |p| {
                    p.value = .{ .boolean = on };
                    touched += 1;
                }
            }
            return touched;
        }

        fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
            _ = now_ms;
            const self = cast(ctx);
            switch (op) {
                .restart => {
                    self.device = self.saved;
                    self.device.tp = self.shim.transport();
                    // Only undo trouble this adapter injected: the object
                    // model may carry a fault the simulation put there for its
                    // own reasons, and a power cycle does not invent facts.
                    if (self.trouble) _ = self.applyTrouble(false);
                    self.trouble = false;
                    self.cov_pending = false;
                    return true;
                },
                .trouble_on, .trouble_off => {
                    const on = op == .trouble_on;
                    if (self.applyTrouble(on) == 0) return false;
                    self.trouble = on;
                    self.cov_pending = true;
                    return true;
                },
            }
        }
    };
}

pub const DefaultBacnet = Bacnet(8);

// ── EtherNet/IP ─────────────────────────────────────────────────────────────

/// CIP Vol 1 §5-2.2, the Identity object's Status word. Bits 4-7 are the
/// *extended* device status (5 = "major fault"); bit 10 is "major recoverable
/// fault". A device in trouble reports both, which is what a scanner reads out
/// of `ListIdentity` and out of Identity attribute 5.
const identity_status_major_fault: u16 = 0x0450;

pub const Enip = struct {
    adapter: enip.Adapter,
    saved: enip.Adapter,
    trouble: bool = false,

    /// Room for the two CPF items of a rebuilt reply envelope.
    const cpf_items = 4;

    pub fn init(cfg: enip.AdapterConfig, tags: []const enip.TagBinding) Enip {
        const a = enip.Adapter.init(cfg, tags);
        return .{ .adapter = a, .saved = a };
    }

    pub fn node(self: *Enip) Node {
        return .{
            .ctx = self,
            .protocol = .enip,
            .framing = .enip_encap,
            .vtable = &.{ .deliver = deliverFn, .control = controlFn },
        };
    }

    fn cast(ctx: *anyopaque) *Enip {
        return @ptrCast(@alignCast(ctx));
    }

    fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        _ = now_ms;
        const self = cast(ctx);
        if (self.trouble) {
            if (try troubleReply(bytes, out)) |r| return r;
        }
        return self.adapter.handle(bytes, out) catch |err| switch (err) {
            error.BufferTooSmall => error.OutputTooSmall,
            error.Malformed => null,
        };
    }

    /// A faulted device still answers *encapsulation* — session management and
    /// `ListIdentity` keep working, and the Identity status word is where the
    /// fault is reported (that is the whole point of a status word). What it
    /// refuses is CIP *object* traffic: `SendRRData` / `SendUnitData` come back
    /// as a CIP error reply with general status `0x10 Device State Conflict` —
    /// Vol 1 §B-1.1, "the device's current mode/state prohibits the execution
    /// of the requested service". Returning `null` here means "not my case,
    /// let the responder answer normally".
    ///
    /// Synthesised by this adapter rather than by the responder, exactly like
    /// the Modbus 0x04 path: `enip.Adapter` has no "be broken" switch, and
    /// teaching it one would be a change to a module this file must not touch.
    fn troubleReply(bytes: []const u8, out: []u8) NodeError!?[]const u8 {
        const msg = enip.encap.decode(bytes) catch return null;
        switch (msg.command) {
            .send_rr_data, .send_unit_data => {},
            else => return null,
        }
        var in_items: [cpf_items]enip.cpf.Item = undefined;
        const env = enip.cpf.decodeEnvelope(msg.data, &in_items) catch return null;
        const data_item = env.list.dataItem() orelse return null;

        // A connected data item carries a 2-byte sequence count before the CIP
        // message; an unconnected one does not.
        const connected = data_item.type_id == .connected_data;
        var seq: u16 = 0;
        const cip_bytes = if (connected) blk: {
            const cd = enip.cpf.ConnectedData.decode(data_item) catch return null;
            seq = cd.sequence_count;
            break :blk cd.payload;
        } else data_item.data;

        const req = enip.cip.Request.decode(cip_bytes) catch return null;
        var reply_buf: [8]u8 = undefined;
        const reply = (enip.cip.Reply{
            .service = req.service,
            .general_status = .device_state_conflict,
            .additional_status = &.{},
            .data = &.{},
        }).encode(&reply_buf) catch return error.OutputTooSmall;

        // Rebuild the envelope with the same address item, so a connected
        // session stays addressable and only the payload says "no".
        var body_buf: [64]u8 = undefined;
        var out_items: [2]enip.cpf.Item = undefined;
        const payload = if (connected)
            enip.cpf.ConnectedData.encode(seq, reply, &body_buf) catch return error.OutputTooSmall
        else
            reply;
        out_items[0] = env.list.addressItem() orelse return null;
        out_items[1] = .{ .type_id = data_item.type_id, .data = payload };

        var env_buf: [128]u8 = undefined;
        const encoded = enip.cpf.encodeEnvelope(
            env.interface_handle,
            0,
            &out_items,
            &env_buf,
        ) catch return error.OutputTooSmall;

        return enip.encap.encode(.{
            .command = msg.command,
            .session_handle = msg.session_handle,
            .status = .success,
            .sender_context = msg.sender_context,
            .options = 0,
            .data = encoded,
            .total_len = 0, // `encode` derives it from `data`
        }, out) catch return error.OutputTooSmall;
    }

    fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
        _ = now_ms;
        const self = cast(ctx);
        switch (op) {
            .restart => {
                self.adapter = self.saved;
                self.trouble = false;
                return true;
            },
            .trouble_on => {
                self.adapter.cfg.identity_status = identity_status_major_fault;
                self.adapter.cfg.state = .major_unrecoverable_fault;
                self.trouble = true;
                return true;
            },
            .trouble_off => {
                self.adapter.cfg.identity_status = self.saved.cfg.identity_status;
                self.adapter.cfg.state = self.saved.cfg.state;
                self.trouble = false;
                return true;
            },
        }
    }
};

// ── OPC UA ──────────────────────────────────────────────────────────────────

/// A simulated OPC UA server endpoint (one connection). The heaviest of the
/// seven by far — it needs an allocator, a `NodeStore` and two buffers sized by
/// the negotiated limits — so a fleet of these is measured in hundreds, not
/// thousands. `SPEC.md` has the numbers.
pub const Opcua = struct {
    server: *opcua.server.Server,
    conn: opcua.server.Connection,
    recv_buf: []u8,
    msg_buf: []u8,
    /// The Variables this device's *process* values live in. `trouble_on`
    /// stamps `trouble_status` on each of them; a client reading one gets a
    /// Bad DataValue instead of a number, which is how OPC UA says "this
    /// point is not to be trusted" (OPC 10000-4 §7.34). Empty is legal —
    /// `ServerStatus.State` alone still moves.
    trouble_nodes: []const opcua.encoding.NodeId = &.{},
    /// `BadDeviceFailure` (0x808B0000) by default. `BadOutOfService`
    /// (0x808D0000) is the other honest choice, for a point a technician has
    /// deliberately taken off scan; `status.bad_out_of_service` below.
    trouble_status: opcua.encoding.StatusCode = status_bad_device_failure,
    /// Supplied when the caller wants the whole `ServerStatus` structure
    /// (i=2256) re-encoded, not just the `State` variable (i=2259). A client
    /// that reads the structure — which is what most browsers show — sees the
    /// state only if it is re-encoded, because it is an ExtensionObject.
    status_info: ?opcua.nodestore.NodeStore.ServerStatusInfo = null,
    trouble: bool = false,

    /// OPC 10000-4 Table B.1. Neither code is in `opcua.server.status`'s table
    /// (that one lists the codes the *services* return), so they are named
    /// here: these are the codes a *device* attaches to a value.
    pub const status_bad_device_failure: opcua.encoding.StatusCode = 0x808B_0000;
    pub const status_bad_out_of_service: opcua.encoding.StatusCode = 0x808D_0000;

    /// `ServerState` (OPC 10000-5 §12.6).
    const server_state_running: i32 = 0;
    const server_state_failed: i32 = 1;

    pub fn init(
        self: *Opcua,
        server: *opcua.server.Server,
        recv_buf: []u8,
        msg_buf: []u8,
    ) !void {
        self.* = .{
            .server = server,
            .conn = undefined,
            .recv_buf = recv_buf,
            .msg_buf = msg_buf,
        };
        self.conn = try opcua.server.Connection.init(server, recv_buf, msg_buf);
    }

    pub fn node(self: *Opcua) Node {
        return .{
            .ctx = self,
            .protocol = .opcua,
            .framing = .opcua_uatcp,
            .vtable = &.{
                .deliver = deliverFn,
                .tick = tickFn,
                .control = controlFn,
            },
        };
    }

    fn cast(ctx: *anyopaque) *Opcua {
        return @ptrCast(@alignCast(ctx));
    }

    fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        const self = cast(ctx);
        var w: std.Io.Writer = .fixed(out);
        self.conn.feed(bytes, &w, @intCast(now_ms)) catch |err| switch (err) {
            // The server's error set says "the answer did not fit"; the fleet
            // has one word for that.
            error.WriteFailed, error.ResponseTooLarge, error.ValueTooLarge => return error.OutputTooSmall,
            else => return error.ResponderFailed,
        };
        const written = w.buffered();
        return if (written.len == 0) null else written;
    }

    fn tickFn(ctx: *anyopaque, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        const self = cast(ctx);
        var w: std.Io.Writer = .fixed(out);
        self.conn.tick(&w, @intCast(now_ms)) catch |err| switch (err) {
            // The server's error set says "the answer did not fit"; the fleet
            // has one word for that.
            error.WriteFailed, error.ResponseTooLarge, error.ValueTooLarge => return error.OutputTooSmall,
            else => return error.ResponderFailed,
        };
        const written = w.buffered();
        return if (written.len == 0) null else written;
    }

    /// Stamp `code` on every nominated Variable's `DataValue` and move
    /// `ServerStatus.State`. The `NodeStore` belongs to the caller, but it is
    /// reached entirely through `opcua`'s own public API (`getNode`,
    /// `setValue`, `refreshServerStatus`) — no `opcua` source changes.
    fn applyTrouble(self: *Opcua, on: bool) bool {
        const store = self.server.store;
        const code: opcua.encoding.StatusCode = if (on) self.trouble_status else 0;
        for (self.trouble_nodes) |id| {
            const n = store.getNode(id) orelse continue;
            switch (n.attributes) {
                .variable => |*v| v.value.status = code,
                else => {},
            }
        }

        const state: i32 = if (on) server_state_failed else server_state_running;
        const state_id = opcua.encoding.NodeId{
            .numeric = .{ .namespace = 0, .id = opcua.nodestore.id.server_status_state },
        };
        _ = store.setValue(state_id, .{ .scalar = .{ .int32 = state } }, null) catch return false;
        if (self.status_info) |info| {
            var updated = info;
            updated.state = state;
            store.refreshServerStatus(updated) catch return false;
        }
        return true;
    }

    fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
        _ = now_ms;
        const self = cast(ctx);
        switch (op) {
            .restart => {
                // A restarted server drops the secure channel; the client must
                // re-`HEL` and re-open. That is exactly what a fresh
                // `Connection` is.
                self.conn = opcua.server.Connection.init(self.server, self.recv_buf, self.msg_buf) catch
                    return false;
                if (self.trouble) _ = self.applyTrouble(false);
                self.trouble = false;
                return true;
            },
            .trouble_on, .trouble_off => {
                const on = op == .trouble_on;
                if (!self.applyTrouble(on)) return false;
                self.trouble = on;
                return true;
            },
        }
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "modbus adapter: a real read round-trips, and trouble turns it into 0x04" {
    var holdings = [_]u16{ 0x1111, 0x2222, 0x3333, 0x4444 };
    var slave = Modbus.init(
        .{ .unit_id = 5, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const n = slave.node();
    try testing.expectEqual(node_mod.Framing.modbus_tcp, n.framing);

    var req_buf: [modbus.tcp.max_adu_len]u8 = undefined;
    var out: [modbus.tcp.max_adu_len]u8 = undefined;
    const req = try modbus.tcp.encodeAdu(&req_buf, 0x1234, 5, &.{ 0x03, 0x00, 0x00, 0x00, 0x02 });

    const reply = (try n.deliver(req, &out, 0)).?;
    try testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, reply[0..2], .big));
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x04, 0x11, 0x11, 0x22, 0x22 }, reply[7..]);

    try testing.expect(n.control(.trouble_on, 0));
    const bad = (try n.deliver(req, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{ 0x83, 0x04 }, bad[7..]);

    try testing.expect(n.control(.trouble_off, 0));
    try testing.expect((try n.deliver(req, &out, 0)) != null);
}

test "modbus adapter: restart returns counters and listen-only mode to as-built" {
    var coils = [_]bool{false} ** 8;
    var slave = Modbus.init(
        .{ .unit_id = 1, .framing = .rtu },
        .{ .coils = .{ .base = 0, .values = &coils } },
    );
    const n = slave.node();
    var req_buf: [modbus.rtu.max_adu_len]u8 = undefined;
    var out: [modbus.rtu.max_adu_len]u8 = undefined;
    const req = try modbus.rtu.encodeAdu(&req_buf, 1, &.{ 0x01, 0x00, 0x00, 0x00, 0x08 });
    _ = try n.deliver(req, &out, 0);
    try testing.expect(slave.server.counters.bus_message > 0);

    try testing.expect(n.control(.restart, 0));
    try testing.expectEqual(@as(u16, 0), slave.server.counters.bus_message);
}

test "dnp3 adapter: a link-layer reset gets a link-layer answer; restart re-arms IIN1.7" {
    var binaries = [_]dnp3.outstation.BinaryInput{.{ .value = true, .class = .class1 }} ** 4;
    var analogs = [_]dnp3.outstation.AnalogInput{.{ .value = 7, .class = .class2 }} ** 2;
    var event_storage: [16]dnp3.outstation.Event = undefined;
    var rx_buf: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx_fragment: [2048]u8 = undefined;

    var station: Dnp3 = undefined;
    station.init(
        .{ .address = 1024, .master_address = 1 },
        .{ .binary_inputs = &binaries, .analog_inputs = &analogs },
        dnp3.outstation.EventBuffer.init(&event_storage),
        &rx_buf,
        &scratch,
        &tx_fragment,
    );
    const n = station.node();

    // RESET_LINK_STATES (function 0, PRM=1) must be ACKed.
    var frame_buf: [64]u8 = undefined;
    const reset = try dnp3.link.encodeFrame(
        .{ .dir = true, .prm = true, .function = @intFromEnum(dnp3.link.PrimaryFunction.reset_link_states) },
        1024,
        1,
        &.{},
        &frame_buf,
    );
    var out: [512]u8 = undefined;
    const ack = (try n.deliver(reset, &out, 0)).?;
    try testing.expectEqual(@as(usize, 10), ack.len);
    try testing.expectEqual(@as(?usize, 10), try node_mod.Framing.dnp3_link.frameLen(ack));

    // Clear the restart bit, then power-cycle: it must come back.
    station.station.restart = false;
    try testing.expect(n.control(.restart, 0));
    try testing.expect(station.station.restart);
}

test "iec104 adapter: STARTDT act is answered STARTDT con through the shim" {
    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 105, .type_id = .m_me_nc_1, .element = .{ .short_float = .{ .value = 1.5, .quality = .{} } } },
    };
    var frame_buf: [512]u8 = undefined;
    var queue_buf: [4096]u8 = undefined;
    var rtu: Iec104 = undefined;
    try rtu.init(.{ .common_address = 47 }, &points, &frame_buf, &queue_buf, .{});
    const n = rtu.node();

    var out: [1024]u8 = undefined;
    const startdt = [_]u8{ 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 };
    const reply = (try n.deliver(&startdt, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{ 0x68, 0x04, 0x0B, 0x00, 0x00, 0x00 }, reply);
    try testing.expect(rtu.server.isStarted());

    // Trouble flags every point that carries a quality descriptor.
    try testing.expect(n.control(.trouble_on, 0));
    try testing.expect(points[0].element.siq.quality.iv);
    try testing.expect(points[1].element.short_float.quality.iv);
    try testing.expect(n.control(.trouble_off, 0));
    try testing.expect(!points[1].element.short_float.quality.iv);
}

test "s7comm adapter: a COTP connect is answered, and STOP is visible as trouble" {
    var db1 = [_]u8{0} ** 32;
    const areas = [_]s7comm.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var plc = S7comm.init(.{}, &areas);
    const n = plc.node();

    var out: [512]u8 = undefined;
    // TPKT + COTP CR with src/dst TSAPs (rack 0 slot 2).
    const cr = [_]u8{
        0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
    };
    const cc = (try n.deliver(&cr, &out, 0)).?;
    try testing.expectEqual(@as(u8, 0x03), cc[0]);
    try testing.expect(plc.responder.connected);

    try testing.expect(n.control(.trouble_on, 0));
    try testing.expectEqual(s7comm.CpuStatus.stop, plc.responder.config.cpu_status);
    try testing.expect(n.control(.restart, 0));
    try testing.expect(!plc.responder.connected); // power-cycled
}

test "s7comm adapter: garbage is dropped silently, never answered" {
    var db1 = [_]u8{0} ** 8;
    const areas = [_]s7comm.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var plc = S7comm.init(.{}, &areas);
    const n = plc.node();
    var out: [128]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), try n.deliver(&.{ 0xFF, 0xFF, 0xFF, 0xFF }, &out, 0));
}

test "enip adapter: RegisterSession round-trips and restart clears the handle" {
    var tag_bytes = [_]u8{0} ** 8;
    const tags = [_]enip.TagBinding{.{ .name = "Speed", .type = .dint, .bytes = &tag_bytes }};
    var dev = Enip.init(.{}, &tags);
    const n = dev.node();

    var out: [512]u8 = undefined;
    var req: [28]u8 = @splat(0);
    std.mem.writeInt(u16, req[0..2], @intFromEnum(enip.Command.register_session), .little);
    std.mem.writeInt(u16, req[2..4], 4, .little);
    std.mem.writeInt(u16, req[24..26], 1, .little); // protocol version
    const reply = (try n.deliver(&req, &out, 0)).?;
    try testing.expectEqual(@as(?usize, reply.len), try node_mod.Framing.enip_encap.frameLen(reply));
    try testing.expect(dev.adapter.session_handle != 0);

    try testing.expect(n.control(.restart, 0));
    try testing.expectEqual(@as(u32, 0), dev.adapter.session_handle);
}

test "enip adapter: trouble sets the Identity status word and refuses CIP with 0x10" {
    var tag_bytes = [_]u8{0} ** 8;
    const tags = [_]enip.TagBinding{.{ .name = "Speed", .type = .dint, .bytes = &tag_bytes }};
    var dev = Enip.init(.{}, &tags);
    const n = dev.node();
    var out: [512]u8 = undefined;

    // Register a session first, so the CIP path is reachable.
    var reg: [28]u8 = @splat(0);
    std.mem.writeInt(u16, reg[0..2], @intFromEnum(enip.Command.register_session), .little);
    std.mem.writeInt(u16, reg[2..4], 4, .little);
    std.mem.writeInt(u16, reg[24..26], 1, .little);
    _ = (try n.deliver(&reg, &out, 0)).?;
    const handle = dev.adapter.session_handle;

    // An unconnected Get_Attributes_All on the Identity object, healthy.
    var cip_buf: [32]u8 = undefined;
    const cip_req = try enip.cip.getAttributesAll(
        @intFromEnum(enip.cip.ClassCode.identity),
        1,
        &cip_buf,
    );
    var env_buf: [96]u8 = undefined;
    const env = try enip.cpf.encodeEnvelope(0, 5, &enip.cpf.unconnectedItems(cip_req), &env_buf);
    var rr_buf: [160]u8 = undefined;
    const rr = try enip.encap.encode(.{
        .command = .send_rr_data,
        .session_handle = handle,
        .status = .success,
        .sender_context = @splat(0),
        .options = 0,
        .data = env,
        .total_len = 0,
    }, &rr_buf);

    const healthy = (try n.deliver(rr, &out, 0)).?;
    try testing.expectEqual(enip.cip.GeneralStatus.success, try cipStatusOf(healthy));

    // Trouble: the Identity status word carries the major-fault bits …
    try testing.expect(n.control(.trouble_on, 0));
    try testing.expectEqual(identity_status_major_fault, dev.adapter.cfg.identity_status);
    try testing.expectEqual(enip.encap.DeviceState.major_unrecoverable_fault, dev.adapter.cfg.state);

    // … ListIdentity still answers, and reports the fault …
    var li: [24]u8 = @splat(0);
    std.mem.writeInt(u16, li[0..2], @intFromEnum(enip.Command.list_identity), .little);
    const ident_reply = (try n.deliver(&li, &out, 0)).?;
    try testing.expect(std.mem.indexOfScalar(
        u8,
        ident_reply,
        @intCast(identity_status_major_fault & 0xFF),
    ) != null);

    // … and the CIP data path answers Device State Conflict instead.
    const refused = (try n.deliver(rr, &out, 0)).?;
    try testing.expectEqual(enip.cip.GeneralStatus.device_state_conflict, try cipStatusOf(refused));
    try testing.expectEqual(@as(?usize, refused.len), try node_mod.Framing.enip_encap.frameLen(refused));

    try testing.expect(n.control(.trouble_off, 0));
    try testing.expectEqual(enip.cip.GeneralStatus.success, try cipStatusOf((try n.deliver(rr, &out, 0)).?));
}

/// Digs the CIP general status out of a `SendRRData`/`SendUnitData` reply.
fn cipStatusOf(bytes: []const u8) !enip.cip.GeneralStatus {
    const msg = try enip.encap.decode(bytes);
    var items: [4]enip.cpf.Item = undefined;
    const env = try enip.cpf.decodeEnvelope(msg.data, &items);
    const item = env.list.dataItem() orelse return error.TestUnexpectedResult;
    const payload = if (item.type_id == .connected_data)
        (try enip.cpf.ConnectedData.decode(item)).payload
    else
        item.data;
    return (try enip.cip.Reply.decode(payload)).general_status;
}

test "bacnet adapter: a broadcast Who-Is draws an I-Am out of the shim" {
    var props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "AI-1" } },
        .{ .id = .present_value, .value = .{ .real = 21.5 } },
    };
    var objects = [_]bacnet.Object{.{
        .id = .{ .type = .analog_input, .instance = 1 },
        .properties = &props,
    }};

    var dev: DefaultBacnet = undefined;
    dev.init(
        .{ .instance = 260_001, .vendor_id = 999 },
        &objects,
        .{ .ip = .{ 10, 0, 0, 2 }, .port = 47808 },
        .{ .ip = .{ 10, 0, 0, 1 }, .port = 47808 },
    );
    const n = dev.node();

    // BVLC Original-Broadcast-NPDU carrying an unconfirmed Who-Is (no limits).
    const who_is = [_]u8{ 0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08 };
    var out: [1024]u8 = undefined;
    const reply = (try n.deliver(&who_is, &out, 0)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 0x81), reply[0]);
    try testing.expectEqual(@as(?usize, reply.len), try node_mod.Framing.bacnet_bvll.frameLen(reply));
    // No object here declares Reliability / Status_Flags / Out_Of_Service, so
    // there is nothing to degrade and the adapter says so.
    try testing.expect(!n.control(.trouble_on, 0));
    try testing.expect(n.control(.restart, 0));
}

test "bacnet adapter: trouble moves Reliability, StatusFlags and Out_Of_Service" {
    var props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "Zone-1-Temp" } },
        .{ .id = .present_value, .value = .{ .real = 21.5 }, .cov_reported = true },
        .{ .id = .status_flags, .value = .{ .bit_string = .{
            .unused_bits = 4,
            .bytes = &status_flags_healthy,
        } }, .cov_reported = true },
        .{ .id = .reliability, .value = .{ .enumerated = reliability_no_fault } },
        .{ .id = .out_of_service, .value = .{ .boolean = false }, .writable = true },
    };
    var objects = [_]bacnet.Object{.{
        .id = .{ .type = .analog_input, .instance = 1 },
        .properties = &props,
    }};

    var dev: DefaultBacnet = undefined;
    dev.init(
        .{ .instance = 260_001, .vendor_id = 999 },
        &objects,
        .{ .ip = .{ 10, 0, 0, 2 }, .port = 47808 },
        .{ .ip = .{ 10, 0, 0, 1 }, .port = 47808 },
    );
    const n = dev.node();

    try testing.expect(n.control(.trouble_on, 0));
    const obj = &objects[0];
    try testing.expectEqual(
        reliability_unreliable_other,
        obj.find(.reliability).?.value.enumerated,
    );
    try testing.expectEqualSlices(
        u8,
        &status_flags_trouble,
        obj.find(.status_flags).?.value.bit_string.bytes,
    );
    const flags = bacnet.StatusFlags.fromOctet(obj.find(.status_flags).?.value.bit_string.bytes[0]);
    try testing.expect(flags.fault and flags.in_alarm and flags.out_of_service);
    try testing.expect(obj.find(.out_of_service).?.value.boolean);

    // A ReadProperty of Reliability now really returns the degraded value: the
    // frame a master would see, not just the struct field.
    var out: [512]u8 = undefined;
    const read_reliability = [_]u8{
        0x81, 0x0A, 0x00, 0x11, // BVLC original-unicast, 17 octets
        0x01, 0x04, // NPDU, expecting reply
        0x00, 0x05, 0x01, 0x0C, // confirmed-request, max APDU, invoke 1, ReadProperty
        0x0C, 0x00, 0x00, 0x00, 0x01, // context 0: object = analog-input,1
        0x19, 0x67, // context 1: property = reliability (103)
    };
    const rp = (try n.deliver(&read_reliability, &out, 0)) orelse return error.TestUnexpectedResult;
    // A ComplexACK whose property value is application-tagged Enumerated(7):
    // tag 9, length 1, value 7.
    try testing.expectEqual(@as(u8, 0x81), rp[0]);
    try testing.expect(std.mem.indexOf(
        u8,
        rp,
        &.{ 0x91, @as(u8, @intCast(reliability_unreliable_other)) },
    ) != null);

    // A COV notification is queued for the next tick rather than dropped:
    // `control` has no output buffer to write one into. (Nothing is on the
    // wire here because nobody has subscribed; the point is that the flag is
    // consumed by the tick that *does* have a buffer.)
    try testing.expect(dev.cov_pending);
    _ = try n.tick(&out, 10);
    try testing.expect(!dev.cov_pending);

    try testing.expect(n.control(.trouble_off, 0));
    try testing.expectEqual(reliability_no_fault, obj.find(.reliability).?.value.enumerated);
    try testing.expect(!obj.find(.out_of_service).?.value.boolean);
}

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
//!      supplies a **shim transport**: one injected datagram/chunk in, an
//!      output buffer out. Both modules ship a `LoopTransport` of their own,
//!      but those are built for peer-to-peer offline tests (16-slot mailbox,
//!      1.5 kB per slot) and would cost ~24 kB per simulated node; the shim is
//!      the same idea sized for a 1000-node fleet.
//!
//! **Restart** is uniform: every adapter snapshots its responder's value at
//! construction and restores it on `Control.restart`. That is a genuine
//! power-cycle for these responders (their state is plain data over
//! caller-owned storage), and it is what makes a master see DNP3's IIN1.7,
//! S7's re-negotiated PDU size or OPC UA's closed channel.
//!
//! **Trouble** is native where the protocol has a word for it (Modbus
//! exception 0x04, DNP3 IIN1.6, S7 CPU STOP, IEC 104 `iv` quality) and
//! honestly refused where it does not (`control` returns false, the fleet logs
//! `control_unsupported`).

const std = @import("std");

const modbus = @import("modbus");
const dnp3 = @import("dnp3");
const iec104 = @import("iec104");
const s7comm = @import("s7comm");
const bacnet = @import("bacnet");
const enip = @import("enip");
const opcua = @import("opcua");

const node_mod = @import("node.zig");

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
/// DRY candidate: `dnp3.outstation.Session` can frame a *solicited* fragment
/// (`feedFrame`, `nextFrames`) but exposes no way to frame an **unsolicited**
/// one — `Session.sendFragment` is private. `emitUnsolicited` below re-does
/// that eight-line job with the module's own public `link`/`transport` API.
/// It belongs in `dnp3.outstation.Session` as `unsolicitedFrames(now, out)`.
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
        if (self.station.unsolicited(now_ms, self.tx_fragment) catch null) |reply| {
            return self.emitUnsolicited(reply.fragment, out);
        }
        const more = self.session.nextFrames(now_ms, out) catch |err| switch (err) {
            error.BufferTooSmall => return error.OutputTooSmall,
            else => return null,
        };
        return more;
    }

    /// See the DRY note on the type: this mirrors `Session.sendFragment`.
    fn emitUnsolicited(self: *Dnp3, fragment: []const u8, out: []u8) NodeError!?[]const u8 {
        const control = dnp3.link.Control{
            .dir = false, // outstation -> master
            .prm = true,
            .function = @intFromEnum(dnp3.link.PrimaryFunction.unconfirmed_user_data),
        };
        var seg = dnp3.transport.Segmenter.init(fragment);
        seg.seq = self.session.tx_seq;
        var seg_buf: [1 + dnp3.transport.max_segment_payload]u8 = undefined;
        var pos: usize = 0;
        while (seg.next(&seg_buf)) |segment| {
            const frame = dnp3.link.encodeFrame(
                control,
                self.station.config.master_address,
                self.station.config.address,
                segment,
                out[pos..],
            ) catch return error.OutputTooSmall;
            pos += frame.len;
        }
        self.session.tx_seq = seg.seq;
        return if (pos == 0) null else out[0..pos];
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

/// A byte-stream shim so a `Transport`-driven responder can be fed one chunk
/// and drained into one buffer, with no mailbox and no allocation.
const StreamShim = struct {
    input: []const u8 = &.{},
    in_pos: usize = 0,
    out: []u8 = &.{},
    out_used: usize = 0,
    overflow: bool = false,

    fn reset(self: *StreamShim, input: []const u8, out: []u8) void {
        self.input = input;
        self.in_pos = 0;
        self.out = out;
        self.out_used = 0;
        self.overflow = false;
    }

    fn written(self: *const StreamShim) []const u8 {
        return self.out[0..self.out_used];
    }
};

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
            .{ .ctx = &self.shim, .vtable = &shim_vtable },
            frame_buf,
            queue_buf,
            config,
        );
        self.saved = self.server;
        self.server.onConnected(0);
    }

    const shim_vtable = iec104.Transport.VTable{ .read = readFn, .write = writeFn };

    fn readFn(ctx: *anyopaque, buf: []u8) iec104.TransportError!usize {
        const shim: *StreamShim = @ptrCast(@alignCast(ctx));
        const n = @min(buf.len, shim.input.len - shim.in_pos);
        if (n == 0) return 0;
        @memcpy(buf[0..n], shim.input[shim.in_pos..][0..n]);
        shim.in_pos += n;
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) iec104.TransportError!void {
        const shim: *StreamShim = @ptrCast(@alignCast(ctx));
        if (shim.out_used + bytes.len > shim.out.len) {
            shim.overflow = true;
            return error.WriteFailed;
        }
        @memcpy(shim.out[shim.out_used..][0..bytes.len], bytes);
        shim.out_used += bytes.len;
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
        self.server.transport = .{ .ctx = &self.shim, .vtable = &shim_vtable };
        var rounds: usize = 0;
        while (rounds < max_poll_rounds) : (rounds += 1) {
            const ev = self.server.poll(now_ms) catch |err| switch (err) {
                error.WriteFailed => return error.OutputTooSmall,
                else => break, // a protocol error closes the connection
            };
            if (ev == .none and self.shim.in_pos >= self.shim.input.len) break;
            if (ev == .closed) break;
        }
        if (self.shim.overflow) return error.OutputTooSmall;
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
        self.server.transport = .{ .ctx = &self.shim, .vtable = &shim_vtable };
        try self.server.reportSpontaneous(ioa, now_ms);
    }

    fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
        const self = cast(ctx);
        switch (op) {
            .restart => {
                self.server = self.saved;
                self.server.transport = .{ .ctx = &self.shim, .vtable = &shim_vtable };
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

/// A datagram shim: one injected datagram in, every reply concatenated out.
/// BVLC is self-delimiting, so the fleet can split the output back into
/// individual datagrams.
const DatagramShim = struct {
    address: bacnet.BipAddress,
    peer: bacnet.BipAddress,
    input: ?[]const u8 = null,
    out: []u8 = &.{},
    out_used: usize = 0,
    overflow: bool = false,

    fn transport(self: *DatagramShim) bacnet.Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable = bacnet.Transport.VTable{
        .send = sendFn,
        .broadcast = broadcastFn,
        .recv = recvFn,
    };

    fn put(self: *DatagramShim, bytes: []const u8) bacnet.TransportError!void {
        if (self.out_used + bytes.len > self.out.len) {
            self.overflow = true;
            return error.SendFailed;
        }
        @memcpy(self.out[self.out_used..][0..bytes.len], bytes);
        self.out_used += bytes.len;
    }

    fn sendFn(ctx: *anyopaque, to: bacnet.BipAddress, bytes: []const u8) bacnet.TransportError!void {
        _ = to;
        const self: *DatagramShim = @ptrCast(@alignCast(ctx));
        return self.put(bytes);
    }

    fn broadcastFn(ctx: *anyopaque, bytes: []const u8) bacnet.TransportError!void {
        const self: *DatagramShim = @ptrCast(@alignCast(ctx));
        return self.put(bytes);
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) bacnet.TransportError!?bacnet.transport.Received {
        const self: *DatagramShim = @ptrCast(@alignCast(ctx));
        const dgram = self.input orelse return null;
        self.input = null;
        if (dgram.len > buf.len) return error.DatagramTooLarge;
        @memcpy(buf[0..dgram.len], dgram);
        return .{ .from = self.peer, .bytes = buf[0..dgram.len] };
    }
};

/// A simulated BACnet/IP device. `max_subscriptions` bounds the COV table.
pub fn Bacnet(comptime max_subscriptions: usize) type {
    return struct {
        const Self = @This();
        pub const DeviceType = bacnet.DeviceWith(max_subscriptions);

        device: DeviceType = undefined,
        saved: DeviceType = undefined,
        shim: DatagramShim,
        trouble: bool = false,

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
            self.shim.input = dgram;
            self.shim.out = out;
            self.shim.out_used = 0;
            self.shim.overflow = false;
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
            if (self.shim.overflow) return error.OutputTooSmall;
            const w = self.shim.out[0..self.shim.out_used];
            return if (w.len == 0) null else w;
        }

        fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
            return cast(ctx).pump(bytes, out, now_ms);
        }

        fn tickFn(ctx: *anyopaque, out: []u8, now_ms: Time) NodeError!?[]const u8 {
            return cast(ctx).pump(null, out, now_ms);
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
            self.shim.input = null;
            self.shim.out = out;
            self.shim.out_used = 0;
            self.shim.overflow = false;
            self.device.tp = self.shim.transport();
            self.device.update(id, prop, v, now_ms) catch return error.ResponderFailed;
            const w = self.shim.out[0..self.shim.out_used];
            return if (w.len == 0) null else w;
        }

        fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
            _ = now_ms;
            const self = cast(ctx);
            switch (op) {
                .restart => {
                    self.device = self.saved;
                    self.device.tp = self.shim.transport();
                    return true;
                },
                // BACnet expresses device trouble through per-object
                // StatusFlags/Reliability, which this device model does not
                // own; saying so beats faking it.
                .trouble_on, .trouble_off => return false,
            }
        }
    };
}

pub const DefaultBacnet = Bacnet(8);

// ── EtherNet/IP ─────────────────────────────────────────────────────────────

pub const Enip = struct {
    adapter: enip.Adapter,
    saved: enip.Adapter,

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
        return self.adapter.handle(bytes, out) catch |err| switch (err) {
            error.BufferTooSmall => error.OutputTooSmall,
            error.Malformed => null,
        };
    }

    fn controlFn(ctx: *anyopaque, op: Control, now_ms: Time) bool {
        _ = now_ms;
        const self = cast(ctx);
        switch (op) {
            .restart => {
                self.adapter = self.saved;
                return true;
            },
            // The CIP Identity object's status word carries device faults, but
            // this adapter treats it as configuration, not state.
            .trouble_on, .trouble_off => return false,
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
            error.WriteFailed, error.NoSpaceLeft => return error.OutputTooSmall,
            else => return error.ResponderFailed,
        };
        const written = w.buffered();
        return if (written.len == 0) null else written;
    }

    fn tickFn(ctx: *anyopaque, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        const self = cast(ctx);
        var w: std.Io.Writer = .fixed(out);
        self.conn.tick(&w, @intCast(now_ms)) catch |err| switch (err) {
            error.WriteFailed, error.NoSpaceLeft => return error.OutputTooSmall,
            else => return error.ResponderFailed,
        };
        const written = w.buffered();
        return if (written.len == 0) null else written;
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
                return true;
            },
            // OPC UA carries device trouble in a variable's StatusCode, which
            // belongs to the NodeStore, not the connection.
            .trouble_on, .trouble_off => return false,
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
    try testing.expect(!n.control(.trouble_on, 0)); // honestly refused
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
    try testing.expect(!n.control(.trouble_on, 0)); // honestly refused
    try testing.expect(n.control(.restart, 0));
}

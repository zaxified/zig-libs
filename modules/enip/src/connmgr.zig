// SPDX-License-Identifier: MIT

//! The **Connection Manager** object (class `0x06`, CIP Volume 1 chapter 3):
//! `Unconnected_Send`, `Forward_Open`, `Large_Forward_Open` and
//! `Forward_Close`.
//!
//! What this object is for: a CIP message addressed to a device *behind* a
//! gateway (the classic case is "the controller in slot 1 of a chassis whose
//! Ethernet module is what my socket is connected to") needs a route. There
//! are two ways to supply one:
//!
//! * **`Unconnected_Send` (0x52)** wraps the real message and carries the
//!   route path with it, per message. No state anywhere.
//! * **`Forward_Open` (0x54)** establishes a *connection*: the route is walked
//!   once, both ends allocate a connection id, and every later message rides
//!   the connection with a four-octet id and a sequence count instead of a
//!   route. `Large_Forward_Open` (0x5B) is the same thing with 32-bit network
//!   connection parameters, which is what raises the payload ceiling above
//!   511 octets.
//!
//! Three details that are easy to get wrong and hard to notice:
//!
//! 1. **The timeout is `2^tick_time` milliseconds × `timeout_ticks`**, not a
//!    number of milliseconds. `tick = 5, ticks = 157` is 5024 ms, not 157.
//! 2. **The embedded message inside `Unconnected_Send` is padded to even**,
//!    and the pad octet is *only* present when the message length is odd. A
//!    decoder that always skips it (or never does) mis-locates the route path.
//! 3. **The connection triple `{serial, originator vendor, originator
//!    serial}` is what `Forward_Close` matches on**, not the connection id.
//!    Two originators that pick the same serial number are told apart by their
//!    vendor id, which is why all three travel together everywhere.

const std = @import("std");
const cip = @import("cip.zig");
const epath = @import("epath.zig");

/// The Connection Manager's class code.
pub const class_code: u16 = 0x06;
/// Its only instance.
pub const instance: u16 = 1;

/// Connection Manager service codes. These collide with the Logix tag
/// services and are only meaningful on a path naming class 6.
pub const Service = struct {
    pub const forward_close: u8 = 0x4E;
    pub const unconnected_send: u8 = 0x52;
    pub const forward_open: u8 = 0x54;
    pub const get_connection_data: u8 = 0x56;
    pub const search_connection_data: u8 = 0x57;
    pub const get_connection_owner: u8 = 0x5A;
    pub const large_forward_open: u8 = 0x5B;
};

pub const DecodeError = error{
    Truncated,
    /// The embedded message's declared size runs past the request.
    EmbeddedOverruns,
    /// The route path's declared size runs past the request.
    RoutePathOverruns,
    /// A `Forward_Open` connection path whose size runs past the request.
    ConnectionPathOverruns,
    /// The reserved octet after a route-path size is not zero.
    BadReserved,
    /// Bytes remain after the last declared field. Unlike `encap.decode`
    /// (exact) and `cpf.decode` (`TrailingData`), these three bodies used
    /// to be silent prefix decoders with no name saying so -- a consumer
    /// calling `decode` alone would accept a padded body without knowing it
    /// (wave-2 audit finding `enip` F3).
    TrailingData,
};

pub const EncodeError = error{
    BufferTooSmall,
    /// A route or connection path longer than 255 words, or odd.
    BadPath,
    /// An embedded message larger than the 16-bit size field.
    TooLong,
};

/// The `{tick, ticks}` pair every Connection Manager service starts with.
///
/// Actual timeout = `2^priority_time_tick` ms × `timeout_ticks`.
pub const Timeout = struct {
    /// Low 4 bits are the tick exponent; the upper bits are the priority.
    priority_time_tick: u8 = 5,
    timeout_ticks: u8 = 157,

    /// The default a Logix client sends: 32 ms ticks × 157 = 5024 ms.
    pub const default: Timeout = .{};

    pub fn milliseconds(self: Timeout) u32 {
        const exp: u5 = @truncate(self.priority_time_tick & 0x0F);
        return (@as(u32, 1) << exp) * self.timeout_ticks;
    }

    /// The closest encodable timeout at or above `ms`, or null if none fits.
    pub fn fromMilliseconds(ms: u32) ?Timeout {
        var exp: u5 = 0;
        const want: u64 = ms;
        while (true) : (exp += 1) {
            const tick: u64 = @as(u64, 1) << exp;
            const ticks = (want + tick - 1) / tick;
            if (ticks >= 1 and ticks <= 255) {
                return .{ .priority_time_tick = exp, .timeout_ticks = @intCast(ticks) };
            }
            if (exp == 15) return null;
        }
    }
};

// ── Unconnected_Send (0x52) ────────────────────────────────────────────────

/// The `Unconnected_Send` body: a timeout, the embedded message, and the
/// route path that says where to deliver it.
pub const UnconnectedSend = struct {
    timeout: Timeout = .default,
    /// The real CIP message, unmodified.
    embedded: []const u8,
    /// EPATH octets; `01 00` is "port 1, link 0", the backplane.
    route_path: []const u8,

    pub fn encodedLen(self: UnconnectedSend) usize {
        return 2 + 2 + self.embedded.len + (self.embedded.len % 2) + 2 + self.route_path.len;
    }

    pub fn decode(bytes: []const u8) DecodeError!UnconnectedSend {
        if (bytes.len < 4) return error.Truncated;
        const size: usize = std.mem.readInt(u16, bytes[2..4], .little);
        if (4 + size > bytes.len) return error.EmbeddedOverruns;
        const embedded = bytes[4 .. 4 + size];
        // The pad octet exists only when the embedded message is odd.
        var off: usize = 4 + size + (size % 2);
        if (off + 2 > bytes.len) return error.Truncated;
        const route_words: usize = bytes[off];
        if (bytes[off + 1] != 0) return error.BadReserved;
        off += 2;
        if (off + route_words * 2 > bytes.len) return error.RoutePathOverruns;
        if (off + route_words * 2 != bytes.len) return error.TrailingData;
        return .{
            .timeout = .{ .priority_time_tick = bytes[0], .timeout_ticks = bytes[1] },
            .embedded = embedded,
            .route_path = bytes[off .. off + route_words * 2],
        };
    }

    pub fn encode(self: UnconnectedSend, out: []u8) EncodeError![]u8 {
        if (self.embedded.len > 0xFFFF) return error.TooLong;
        if (self.route_path.len % 2 != 0 or self.route_path.len / 2 > 255) return error.BadPath;
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        out[0] = self.timeout.priority_time_tick;
        out[1] = self.timeout.timeout_ticks;
        std.mem.writeInt(u16, out[2..4], @intCast(self.embedded.len), .little);
        @memcpy(out[4..][0..self.embedded.len], self.embedded);
        var off: usize = 4 + self.embedded.len;
        if (self.embedded.len % 2 == 1) {
            out[off] = 0;
            off += 1;
        }
        out[off] = @intCast(self.route_path.len / 2);
        out[off + 1] = 0;
        off += 2;
        @memcpy(out[off..][0..self.route_path.len], self.route_path);
        return out[0..total];
    }

    /// Wraps `embedded` in a complete `Unconnected_Send` Message Router
    /// request, path and all.
    pub fn wrap(self: UnconnectedSend, out: []u8) EncodeError![]u8 {
        var body_buf: [1024]u8 = undefined;
        if (self.encodedLen() > body_buf.len) return error.BufferTooSmall;
        const body = try self.encode(&body_buf);
        var path_buf: [8]u8 = undefined;
        const path = epath.logicalPath(class_code, instance, null, &path_buf) catch
            return error.BadPath;
        return (cip.Request{
            .service = Service.unconnected_send,
            .path = path,
            .data = body,
        }).encode(out) catch |e| switch (e) {
            error.BufferTooSmall => error.BufferTooSmall,
            else => error.BadPath,
        };
    }
};

/// The route path a Logix client sends by default: backplane port 1, slot 0.
pub const backplane_slot_0 = [_]u8{ 0x01, 0x00 };

/// Builds the `port 1 / link <slot>` route path into `out`.
pub fn backplaneRoute(slot: u8, out: []u8) EncodeError![]const u8 {
    var b = epath.Builder.init(out);
    b.port(1, &[_]u8{slot}) catch return error.BufferTooSmall;
    return b.bytes();
}

// ── connection parameters ──────────────────────────────────────────────────

pub const ConnectionType = enum(u2) {
    null_connection = 0,
    multicast = 1,
    point_to_point = 2,
    reserved = 3,
};

pub const Priority = enum(u2) {
    low = 0,
    high = 1,
    scheduled = 2,
    urgent = 3,
};

/// The network connection parameters, in the field layout shared by the 16-bit
/// (`Forward_Open`) and 32-bit (`Large_Forward_Open`) encodings.
///
/// The bit positions differ between the two — the 16-bit form packs the size
/// into 9 bits and everything else above it, the 32-bit form uses a full 16
/// and moves the flags to the top half — which is exactly the kind of detail
/// that produces a connection that opens and then never carries anything.
pub const ConnectionParameters = struct {
    /// Octets per packet on this connection.
    size: u16,
    /// True = the size above is a maximum; false = every packet is that size.
    variable: bool = true,
    priority: Priority = .low,
    connection_type: ConnectionType = .point_to_point,
    /// True = several originators may own this connection.
    redundant_owner: bool = false,
    /// The bits neither encoding assigns a meaning to, kept **in their wire
    /// positions** so a captured frame re-encodes byte-exactly.
    ///
    /// The 16-bit word leaves bit 12 unassigned; the 32-bit word leaves bits
    /// 16-24 and bit 28. A sender is required to zero them, and every frame in
    /// `goldens.zig` does — but "the sender must zero it" is not the same as
    /// "we may zero it for him". Dropping them made `fromU16`/`fromU32` lossy
    /// and `toU16`/`toU32` unable to reproduce what had just been accepted, so
    /// a `Forward_Open` relayed through this module came out as different
    /// octets than went in. Reserved bits are ignored on receipt rather than
    /// rejected — refusing them would be a new denial path on an
    /// unauthenticated listening surface for a field that changes nothing
    /// about the connection — so they are carried, exactly as `ForwardOpen`'s
    /// own `reserved: [3]u8` is.
    reserved: u32 = 0,

    /// The maximum a 16-bit `Forward_Open` can express (9 bits).
    pub const max_small_size: u16 = 511;

    /// Bit 12 of the 16-bit word. Cross-checked against Wireshark's CIP
    /// dissector, which maps 0x01FF/0x0200/0x0C00/0x6000/0x8000 and nothing
    /// else (`epan/dissectors/packet-cip.c`, `hf_cip_cm_fwo_*`).
    pub const reserved_mask_16: u16 = 0x1000;
    /// Bits 16-24 and bit 28 of the 32-bit word. Same cross-check:
    /// `hf_cip_cm_lfwo_*` maps 0xFFFF/0x02000000/0x0C000000/0x60000000/
    /// 0x80000000, leaving exactly these.
    pub const reserved_mask_32: u32 = 0x11FF_0000;

    pub fn toU16(self: ConnectionParameters) ?u16 {
        if (self.size > max_small_size) return null;
        var v: u16 = self.size & 0x01FF;
        if (self.variable) v |= 1 << 9;
        v |= @as(u16, @intFromEnum(self.priority)) << 10;
        v |= @as(u16, @intFromEnum(self.connection_type)) << 13;
        if (self.redundant_owner) v |= 1 << 15;
        v |= @as(u16, @truncate(self.reserved)) & reserved_mask_16;
        return v;
    }

    pub fn fromU16(v: u16) ConnectionParameters {
        return .{
            .size = v & 0x01FF,
            .variable = v & (1 << 9) != 0,
            .priority = @enumFromInt(@as(u2, @truncate(v >> 10))),
            .connection_type = @enumFromInt(@as(u2, @truncate(v >> 13))),
            .redundant_owner = v & (1 << 15) != 0,
            .reserved = v & reserved_mask_16,
        };
    }

    pub fn toU32(self: ConnectionParameters) u32 {
        var v: u32 = self.size;
        if (self.variable) v |= 1 << 25;
        v |= @as(u32, @intFromEnum(self.priority)) << 26;
        v |= @as(u32, @intFromEnum(self.connection_type)) << 29;
        if (self.redundant_owner) v |= @as(u32, 1) << 31;
        v |= self.reserved & reserved_mask_32;
        return v;
    }

    pub fn fromU32(v: u32) ConnectionParameters {
        return .{
            .size = @truncate(v),
            .variable = v & (1 << 25) != 0,
            .priority = @enumFromInt(@as(u2, @truncate(v >> 26))),
            .connection_type = @enumFromInt(@as(u2, @truncate(v >> 29))),
            .redundant_owner = v & (@as(u32, 1) << 31) != 0,
            .reserved = v & reserved_mask_32,
        };
    }
};

/// The transport class/trigger octet.
pub const TransportClass = struct {
    /// True = this end is the **server** of the connection.
    server: bool = true,
    /// 0 cyclic, 1 change of state, 2 application object.
    trigger: u3 = 2,
    /// 0..3; explicit messaging is class 3.
    class: u4 = 3,

    pub fn toByte(self: TransportClass) u8 {
        return (@as(u8, @intFromBool(self.server)) << 7) |
            (@as(u8, self.trigger) << 4) |
            @as(u8, self.class);
    }

    pub fn fromByte(b: u8) TransportClass {
        return .{
            .server = b & 0x80 != 0,
            .trigger = @truncate(b >> 4),
            .class = @truncate(b),
        };
    }

    /// What a client sends for a Class 3 explicit-messaging connection.
    pub const explicit_messaging: TransportClass = .{};
};

// ── Forward_Open (0x54) / Large_Forward_Open (0x5B) ────────────────────────

/// A `Forward_Open` request body. The `large` flag selects 32-bit network
/// connection parameters and the `0x5B` service code.
pub const ForwardOpen = struct {
    timeout: Timeout = .default,
    /// Originator→target connection id. A client that does not want an O→T
    /// connection sends 0 and lets the target assign.
    o_to_t_connection_id: u32,
    t_to_o_connection_id: u32,
    /// The originator's own per-connection serial number.
    connection_serial: u16,
    originator_vendor_id: u16,
    originator_serial: u32,
    /// The connection dies after `RPI × 2^multiplier × 4`.
    connection_timeout_multiplier: u8 = 0,
    /// Kept so a captured frame re-encodes exactly; senders set it to zero.
    reserved: [3]u8 = @splat(0),
    /// Requested packet interval, microseconds.
    o_to_t_rpi: u32,
    o_to_t_params: ConnectionParameters,
    t_to_o_rpi: u32,
    t_to_o_params: ConnectionParameters,
    transport_class: TransportClass = .explicit_messaging,
    /// EPATH to the object at the far end (usually `20 02 24 01`, the message
    /// router), prefixed by the route.
    connection_path: []const u8,
    large: bool = false,

    fn paramWidth(self: ForwardOpen) usize {
        return if (self.large) 4 else 2;
    }

    /// `Forward_Open` has **no** reserved octet after its connection-path
    /// size — unlike `Unconnected_Send` and `Forward_Close`, which both do.
    /// Assuming one shifts the whole connection path by an octet and produces
    /// a `Forward_Open` that a real target answers with a path-segment error.
    pub fn encodedLen(self: ForwardOpen) usize {
        return 2 + 4 + 4 + 2 + 2 + 4 + 1 + 3 + 4 + self.paramWidth() + 4 + self.paramWidth() +
            1 + 1 + self.connection_path.len;
    }

    /// The service code this body must be sent with.
    pub fn service(self: ForwardOpen) u8 {
        return if (self.large) Service.large_forward_open else Service.forward_open;
    }

    pub fn decode(bytes: []const u8, large: bool) DecodeError!ForwardOpen {
        const pw: usize = if (large) 4 else 2;
        const fixed = 2 + 4 + 4 + 2 + 2 + 4 + 1 + 3 + 4 + pw + 4 + pw + 1 + 1;
        if (bytes.len < fixed) return error.Truncated;
        var off: usize = 0;
        const timeout = Timeout{ .priority_time_tick = bytes[0], .timeout_ticks = bytes[1] };
        off = 2;
        const o_t_id = std.mem.readInt(u32, bytes[off..][0..4], .little);
        const t_o_id = std.mem.readInt(u32, bytes[off + 4 ..][0..4], .little);
        const serial = std.mem.readInt(u16, bytes[off + 8 ..][0..2], .little);
        const vendor = std.mem.readInt(u16, bytes[off + 10 ..][0..2], .little);
        const orig_serial = std.mem.readInt(u32, bytes[off + 12 ..][0..4], .little);
        const multiplier = bytes[off + 16];
        const reserved = bytes[off + 17 ..][0..3].*;
        off += 20;
        const o_t_rpi = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        const o_t_params = if (large)
            ConnectionParameters.fromU32(std.mem.readInt(u32, bytes[off..][0..4], .little))
        else
            ConnectionParameters.fromU16(std.mem.readInt(u16, bytes[off..][0..2], .little));
        off += pw;
        const t_o_rpi = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        const t_o_params = if (large)
            ConnectionParameters.fromU32(std.mem.readInt(u32, bytes[off..][0..4], .little))
        else
            ConnectionParameters.fromU16(std.mem.readInt(u16, bytes[off..][0..2], .little));
        off += pw;
        const transport = TransportClass.fromByte(bytes[off]);
        off += 1;
        const path_words: usize = bytes[off];
        off += 1;
        if (off + path_words * 2 > bytes.len) return error.ConnectionPathOverruns;
        if (off + path_words * 2 != bytes.len) return error.TrailingData;
        return .{
            .timeout = timeout,
            .o_to_t_connection_id = o_t_id,
            .t_to_o_connection_id = t_o_id,
            .connection_serial = serial,
            .originator_vendor_id = vendor,
            .originator_serial = orig_serial,
            .connection_timeout_multiplier = multiplier,
            .reserved = reserved,
            .o_to_t_rpi = o_t_rpi,
            .o_to_t_params = o_t_params,
            .t_to_o_rpi = t_o_rpi,
            .t_to_o_params = t_o_params,
            .transport_class = transport,
            .connection_path = bytes[off .. off + path_words * 2],
            .large = large,
        };
    }

    pub fn encode(self: ForwardOpen, out: []u8) EncodeError![]u8 {
        if (self.connection_path.len % 2 != 0 or self.connection_path.len / 2 > 255)
            return error.BadPath;
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        out[0] = self.timeout.priority_time_tick;
        out[1] = self.timeout.timeout_ticks;
        std.mem.writeInt(u32, out[2..6], self.o_to_t_connection_id, .little);
        std.mem.writeInt(u32, out[6..10], self.t_to_o_connection_id, .little);
        std.mem.writeInt(u16, out[10..12], self.connection_serial, .little);
        std.mem.writeInt(u16, out[12..14], self.originator_vendor_id, .little);
        std.mem.writeInt(u32, out[14..18], self.originator_serial, .little);
        out[18] = self.connection_timeout_multiplier;
        @memcpy(out[19..22], &self.reserved);
        var off: usize = 22;
        std.mem.writeInt(u32, out[off..][0..4], self.o_to_t_rpi, .little);
        off += 4;
        off += try self.writeParams(self.o_to_t_params, out[off..]);
        std.mem.writeInt(u32, out[off..][0..4], self.t_to_o_rpi, .little);
        off += 4;
        off += try self.writeParams(self.t_to_o_params, out[off..]);
        out[off] = self.transport_class.toByte();
        out[off + 1] = @intCast(self.connection_path.len / 2);
        off += 2;
        @memcpy(out[off..][0..self.connection_path.len], self.connection_path);
        return out[0..total];
    }

    fn writeParams(self: ForwardOpen, p: ConnectionParameters, out: []u8) EncodeError!usize {
        if (self.large) {
            std.mem.writeInt(u32, out[0..4], p.toU32(), .little);
            return 4;
        }
        const v = p.toU16() orelse return error.TooLong;
        std.mem.writeInt(u16, out[0..2], v, .little);
        return 2;
    }

    /// Wraps the body in a Message Router request addressed to class 6.
    pub fn wrap(self: ForwardOpen, out: []u8) EncodeError![]u8 {
        var body_buf: [512]u8 = undefined;
        if (self.encodedLen() > body_buf.len) return error.BufferTooSmall;
        const body = try self.encode(&body_buf);
        var path_buf: [8]u8 = undefined;
        const path = epath.logicalPath(class_code, instance, null, &path_buf) catch
            return error.BadPath;
        return (cip.Request{ .service = self.service(), .path = path, .data = body }).encode(out) catch
            error.BufferTooSmall;
    }
};

/// A successful `Forward_Open` reply.
pub const ForwardOpenReply = struct {
    o_to_t_connection_id: u32,
    t_to_o_connection_id: u32,
    connection_serial: u16,
    originator_vendor_id: u16,
    originator_serial: u32,
    /// The **actual** packet interval the target granted, which may differ
    /// from what was asked for.
    o_to_t_api: u32,
    t_to_o_api: u32,
    application_reply: []const u8,
    reserved: u8 = 0,

    pub const fixed_len: usize = 26;

    pub fn decode(bytes: []const u8) DecodeError!ForwardOpenReply {
        if (bytes.len < fixed_len) return error.Truncated;
        const words: usize = bytes[24];
        if (fixed_len + words * 2 > bytes.len) return error.Truncated;
        return .{
            .o_to_t_connection_id = std.mem.readInt(u32, bytes[0..4], .little),
            .t_to_o_connection_id = std.mem.readInt(u32, bytes[4..8], .little),
            .connection_serial = std.mem.readInt(u16, bytes[8..10], .little),
            .originator_vendor_id = std.mem.readInt(u16, bytes[10..12], .little),
            .originator_serial = std.mem.readInt(u32, bytes[12..16], .little),
            .o_to_t_api = std.mem.readInt(u32, bytes[16..20], .little),
            .t_to_o_api = std.mem.readInt(u32, bytes[20..24], .little),
            .application_reply = bytes[fixed_len .. fixed_len + words * 2],
            .reserved = bytes[25],
        };
    }

    pub fn encode(self: ForwardOpenReply, out: []u8) EncodeError![]u8 {
        if (self.application_reply.len % 2 != 0) return error.BadPath;
        const total = fixed_len + self.application_reply.len;
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.o_to_t_connection_id, .little);
        std.mem.writeInt(u32, out[4..8], self.t_to_o_connection_id, .little);
        std.mem.writeInt(u16, out[8..10], self.connection_serial, .little);
        std.mem.writeInt(u16, out[10..12], self.originator_vendor_id, .little);
        std.mem.writeInt(u32, out[12..16], self.originator_serial, .little);
        std.mem.writeInt(u32, out[16..20], self.o_to_t_api, .little);
        std.mem.writeInt(u32, out[20..24], self.t_to_o_api, .little);
        out[24] = @intCast(self.application_reply.len / 2);
        out[25] = self.reserved;
        @memcpy(out[fixed_len..][0..self.application_reply.len], self.application_reply);
        return out[0..total];
    }
};

// ── Forward_Close (0x4E) ───────────────────────────────────────────────────

/// A `Forward_Close` request body. It matches the connection by the
/// `{serial, vendor, originator serial}` triple, not by connection id.
pub const ForwardClose = struct {
    timeout: Timeout = .default,
    connection_serial: u16,
    originator_vendor_id: u16,
    originator_serial: u32,
    reserved: u8 = 0,
    connection_path: []const u8,

    pub fn encodedLen(self: ForwardClose) usize {
        return 2 + 2 + 2 + 4 + 2 + self.connection_path.len;
    }

    pub fn decode(bytes: []const u8) DecodeError!ForwardClose {
        if (bytes.len < 12) return error.Truncated;
        const words: usize = bytes[10];
        if (12 + words * 2 > bytes.len) return error.ConnectionPathOverruns;
        if (12 + words * 2 != bytes.len) return error.TrailingData;
        return .{
            .timeout = .{ .priority_time_tick = bytes[0], .timeout_ticks = bytes[1] },
            .connection_serial = std.mem.readInt(u16, bytes[2..4], .little),
            .originator_vendor_id = std.mem.readInt(u16, bytes[4..6], .little),
            .originator_serial = std.mem.readInt(u32, bytes[6..10], .little),
            .reserved = bytes[11],
            .connection_path = bytes[12 .. 12 + words * 2],
        };
    }

    pub fn encode(self: ForwardClose, out: []u8) EncodeError![]u8 {
        if (self.connection_path.len % 2 != 0 or self.connection_path.len / 2 > 255)
            return error.BadPath;
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        out[0] = self.timeout.priority_time_tick;
        out[1] = self.timeout.timeout_ticks;
        std.mem.writeInt(u16, out[2..4], self.connection_serial, .little);
        std.mem.writeInt(u16, out[4..6], self.originator_vendor_id, .little);
        std.mem.writeInt(u32, out[6..10], self.originator_serial, .little);
        out[10] = @intCast(self.connection_path.len / 2);
        out[11] = self.reserved;
        @memcpy(out[12..][0..self.connection_path.len], self.connection_path);
        return out[0..total];
    }

    pub fn wrap(self: ForwardClose, out: []u8) EncodeError![]u8 {
        var body_buf: [256]u8 = undefined;
        if (self.encodedLen() > body_buf.len) return error.BufferTooSmall;
        const body = try self.encode(&body_buf);
        var path_buf: [8]u8 = undefined;
        const path = epath.logicalPath(class_code, instance, null, &path_buf) catch
            return error.BadPath;
        return (cip.Request{ .service = Service.forward_close, .path = path, .data = body }).encode(out) catch
            error.BufferTooSmall;
    }
};

/// A `Forward_Close` reply.
pub const ForwardCloseReply = struct {
    connection_serial: u16,
    originator_vendor_id: u16,
    originator_serial: u32,
    application_reply: []const u8,
    reserved: u8 = 0,

    pub const fixed_len: usize = 10;

    pub fn decode(bytes: []const u8) DecodeError!ForwardCloseReply {
        if (bytes.len < fixed_len) return error.Truncated;
        const words: usize = bytes[8];
        if (fixed_len + words * 2 > bytes.len) return error.Truncated;
        return .{
            .connection_serial = std.mem.readInt(u16, bytes[0..2], .little),
            .originator_vendor_id = std.mem.readInt(u16, bytes[2..4], .little),
            .originator_serial = std.mem.readInt(u32, bytes[4..8], .little),
            .application_reply = bytes[fixed_len .. fixed_len + words * 2],
            .reserved = bytes[9],
        };
    }

    pub fn encode(self: ForwardCloseReply, out: []u8) EncodeError![]u8 {
        if (self.application_reply.len % 2 != 0) return error.BadPath;
        const total = fixed_len + self.application_reply.len;
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], self.connection_serial, .little);
        std.mem.writeInt(u16, out[2..4], self.originator_vendor_id, .little);
        std.mem.writeInt(u32, out[4..8], self.originator_serial, .little);
        out[8] = @intCast(self.application_reply.len / 2);
        out[9] = self.reserved;
        @memcpy(out[fixed_len..][0..self.application_reply.len], self.application_reply);
        return out[0..total];
    }
};

/// Connection Manager extended status codes, which arrive in the reply's
/// **additional status** word and are the only thing that says *why* a
/// `Forward_Open` was refused.
pub const ExtendedStatus = enum(u16) {
    connection_in_use = 0x0100,
    transport_class_trigger_not_supported = 0x0103,
    ownership_conflict = 0x0106,
    connection_not_found = 0x0107,
    invalid_connection_type = 0x0108,
    invalid_connection_size = 0x0109,
    device_not_configured = 0x0110,
    rpi_not_supported = 0x0111,
    connection_limit_reached = 0x0113,
    vendor_or_product_code_mismatch = 0x0114,
    device_type_mismatch = 0x0115,
    revision_mismatch = 0x0116,
    invalid_produced_or_consumed_path = 0x0117,
    invalid_configuration_path = 0x0118,
    non_listen_only_connection_not_opened = 0x0119,
    target_connection_entries_full = 0x011A,
    rpi_smaller_than_production_inhibit = 0x011B,
    connection_timed_out = 0x0203,
    unconnected_request_timed_out = 0x0204,
    parameter_error_in_unconnected_request = 0x0205,
    message_too_large_for_unconnected_send = 0x0206,
    unconnected_ack_without_reply = 0x0207,
    no_buffer_memory = 0x0301,
    bandwidth_not_available = 0x0302,
    no_screeners_available = 0x0303,
    not_configured_to_send_scheduled_data = 0x0311,
    invalid_port_id = 0x0312,
    invalid_link_address = 0x0315,
    invalid_segment_type_in_path = 0x0316,
    path_and_connection_size_mismatch = 0x0317,
    invalid_network_segment = 0x0318,
    no_available_link_consumer = 0x0319,
    port_not_available = 0x031C,
    link_address_not_available = 0x031D,
    invalid_segment_in_connection_path = 0x031E,
    _,
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the timeout is an exponent times a count, not milliseconds" {
    try testing.expectEqual(@as(u32, 5024), (Timeout{ .priority_time_tick = 5, .timeout_ticks = 157 }).milliseconds());
    try testing.expectEqual(@as(u32, 157), (Timeout{ .priority_time_tick = 0, .timeout_ticks = 157 }).milliseconds());
    const t = Timeout.fromMilliseconds(5000).?;
    try testing.expect(t.milliseconds() >= 5000);
    // The priority bits above the exponent must not change the arithmetic.
    try testing.expectEqual(@as(u32, 32), (Timeout{ .priority_time_tick = 0xF5, .timeout_ticks = 1 }).milliseconds());
    try testing.expectEqual(@as(?Timeout, null), Timeout.fromMilliseconds(0xFFFF_FFFF));
}

test "unconnected send pads an odd embedded message and not an even one" {
    const odd = [_]u8{ 0x4C, 0x03, 0x91, 0x05, 'S', 'C', 'A', 'D', 'A' }; // 9 octets
    var buf: [64]u8 = undefined;
    const wire = try (UnconnectedSend{ .embedded = &odd, .route_path = &backplane_slot_0 }).encode(&buf);
    // tick, ticks, size(2), 9 octets, pad, route size, reserved, route(2).
    try testing.expectEqual(@as(usize, 2 + 2 + 9 + 1 + 2 + 2), wire.len);
    try testing.expectEqual(@as(u8, 0), wire[4 + 9]);
    const back = try UnconnectedSend.decode(wire);
    try testing.expectEqualSlices(u8, &odd, back.embedded);
    try testing.expectEqualSlices(u8, &backplane_slot_0, back.route_path);

    const even = [_]u8{ 0x4C, 0x03, 0x91, 0x04, 'A', 'B', 'C', 'D' }; // 8 octets
    const wire2 = try (UnconnectedSend{ .embedded = &even, .route_path = &backplane_slot_0 }).encode(&buf);
    try testing.expectEqual(@as(usize, 2 + 2 + 8 + 2 + 2), wire2.len);
    const back2 = try UnconnectedSend.decode(wire2);
    try testing.expectEqualSlices(u8, &even, back2.embedded);

    // F3 regression: bytes past the declared route path used to be
    // silently accepted (`decode` was a prefix decoder with no name saying
    // so) -- wave-2 audit finding `enip` F3.
    var padded: [64]u8 = undefined;
    @memcpy(padded[0..wire2.len], wire2);
    padded[wire2.len] = 0xAA;
    try testing.expectError(error.TrailingData, UnconnectedSend.decode(padded[0 .. wire2.len + 1]));
}

test "an embedded size that overruns the request is refused" {
    // Claims 200 octets of embedded message with 4 present.
    try testing.expectError(
        error.EmbeddedOverruns,
        UnconnectedSend.decode(&[_]u8{ 0x05, 0x9D, 0xC8, 0x00, 1, 2, 3, 4 }),
    );
    // Claims a 100-word route path with 2 octets present.
    try testing.expectError(
        error.RoutePathOverruns,
        UnconnectedSend.decode(&[_]u8{ 0x05, 0x9D, 0x02, 0x00, 1, 2, 0x64, 0x00, 1, 2 }),
    );
    // A dirty reserved octet after the route size.
    try testing.expectError(
        error.BadReserved,
        UnconnectedSend.decode(&[_]u8{ 0x05, 0x9D, 0x02, 0x00, 1, 2, 0x01, 0xFF, 1, 2 }),
    );
}

test "connection parameters round trip in both widths" {
    const p = ConnectionParameters{
        .size = 500,
        .variable = true,
        .priority = .low,
        .connection_type = .point_to_point,
    };
    const small = p.toU16().?;
    try testing.expectEqual(@as(u16, 0x43F4), small);
    const back = ConnectionParameters.fromU16(small);
    try testing.expectEqual(p.size, back.size);
    try testing.expectEqual(p.connection_type, back.connection_type);
    try testing.expect(back.variable);

    // 4000 octets does not fit in nine bits — that is what "large" is for.
    const big = ConnectionParameters{ .size = 4000, .variable = true, .connection_type = .point_to_point };
    try testing.expectEqual(@as(?u16, null), big.toU16());
    const large = big.toU32();
    try testing.expectEqual(@as(u32, 0x42000FA0), large);
    const back2 = ConnectionParameters.fromU32(large);
    try testing.expectEqual(@as(u16, 4000), back2.size);
    try testing.expectEqual(ConnectionType.point_to_point, back2.connection_type);
    try testing.expect(back2.variable);
}

test "the reserved bits of a network-parameters word survive a decode" {
    // BD-24. The sweep reduced to a 46-octet `Forward_Open` whose parameter
    // word differed from its re-encode at exactly one bit — bit 12 of the
    // 16-bit form, which `fromU16` read past and `toU16` wrote back as zero.
    // The audit recorded this gap for the 32-bit form only and said the
    // 16-bit form "has no such gap"; it has one, and the fuzzer found that
    // one first.
    //
    // Wireshark's CIP dissector maps 0x01FF|0x0200|0x0C00|0x6000|0x8000 of
    // the small word and 0xFFFF|0x02000000|0x0C000000|0x60000000|0x80000000
    // of the large one, so the unassigned bits are exactly the two masks
    // asserted here.
    try testing.expectEqual(@as(u16, 0xEFFF), ~ConnectionParameters.reserved_mask_16);
    try testing.expectEqual(@as(u32, 0xEE00_FFFF), ~ConnectionParameters.reserved_mask_32);

    // Every reserved bit, one at a time, must come back out where it went in.
    for (0..16) |bit| {
        const m: u16 = @as(u16, 1) << @intCast(bit);
        if (m & ConnectionParameters.reserved_mask_16 == 0) continue;
        const v: u16 = 0x43F4 | m;
        try testing.expectEqual(v, ConnectionParameters.fromU16(v).toU16().?);
    }
    for (0..32) |bit| {
        const m: u32 = @as(u32, 1) << @intCast(bit);
        if (m & ConnectionParameters.reserved_mask_32 == 0) continue;
        const v: u32 = 0x4200_0FA0 | m;
        try testing.expectEqual(v, ConnectionParameters.fromU32(v).toU32());
    }

    // End to end, on the two captured `Forward_Open` bodies with a reserved
    // bit set in the o→t word: a decode/encode round trip must be byte-exact.
    const bodies = [_]struct { large: bool, off: usize, hex: []const u8 }{
        // cpppo's small Forward_Open; o→t parameters at octets 26-27.
        .{ .large = false, .off = 26, .hex = "059dfecc0000fffffffffecc3412010000000000000080841e00fe4380841e00fe43a303010020022401" },
        // pycomm3's Large_Forward_Open; o→t parameters at octets 26-29.
        .{ .large = true, .off = 26, .hex = "0a05000000005bbca9dc27040910ab4289180700000001402000a00f004201402000a00f0042a30220022401" },
    };
    for (bodies) |b| {
        var wire: [128]u8 = undefined;
        const n = (std.fmt.hexToBytes(&wire, b.hex) catch unreachable).len;
        // A clean capture must round-trip first, or the rest proves nothing.
        var round: [128]u8 = undefined;
        const fo0 = try ForwardOpen.decode(wire[0..n], b.large);
        try testing.expectEqualSlices(u8, wire[0..n], try fo0.encode(&round));
        // Now set a reserved bit the way a peer that ignores the "shall be
        // zero" rule would, and require the same octets back.
        if (b.large) {
            const v = std.mem.readInt(u32, wire[b.off..][0..4], .little);
            std.mem.writeInt(u32, wire[b.off..][0..4], v | 0x1000_0000, .little);
        } else {
            const v = std.mem.readInt(u16, wire[b.off..][0..2], .little);
            std.mem.writeInt(u16, wire[b.off..][0..2], v | 0x1000, .little);
        }
        const fo = try ForwardOpen.decode(wire[0..n], b.large);
        try testing.expectEqualSlices(u8, wire[0..n], try fo.encode(&round));
        // …and the fields a caller acts on are unchanged by that bit.
        try testing.expectEqual(fo0.o_to_t_params.size, fo.o_to_t_params.size);
        try testing.expectEqual(fo0.o_to_t_params.connection_type, fo.o_to_t_params.connection_type);
        try testing.expectEqual(fo0.o_to_t_params.priority, fo.o_to_t_params.priority);
        try testing.expectEqual(fo0.o_to_t_params.variable, fo.o_to_t_params.variable);
    }
}

test "transport class octet round trips" {
    const t = TransportClass.explicit_messaging;
    try testing.expectEqual(@as(u8, 0xA3), t.toByte());
    const back = TransportClass.fromByte(0xA3);
    try testing.expect(back.server);
    try testing.expectEqual(@as(u3, 2), back.trigger);
    try testing.expectEqual(@as(u4, 3), back.class);
}

test "forward open round trips in both sizes" {
    var path_buf: [16]u8 = undefined;
    var pb = epath.Builder.init(&path_buf);
    try pb.port(1, &[_]u8{0});
    try pb.class(0x02);
    try pb.instance(1);

    const fo = ForwardOpen{
        .o_to_t_connection_id = 0x0000CCFE,
        .t_to_o_connection_id = 0xFFFFFFFF,
        .connection_serial = 0xCCFE,
        .originator_vendor_id = 0x1234,
        .originator_serial = 1,
        .o_to_t_rpi = 2_000_000,
        .o_to_t_params = .{ .size = 510, .variable = true },
        .t_to_o_rpi = 2_000_000,
        .t_to_o_params = .{ .size = 510, .variable = true },
        .connection_path = pb.bytes(),
    };
    var buf: [128]u8 = undefined;
    const wire = try fo.encode(&buf);
    try testing.expectEqual(fo.encodedLen(), wire.len);
    const back = try ForwardOpen.decode(wire, false);
    try testing.expectEqual(fo.connection_serial, back.connection_serial);
    try testing.expectEqual(@as(u16, 510), back.o_to_t_params.size);
    try testing.expectEqualSlices(u8, pb.bytes(), back.connection_path);
    var round: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, wire, try back.encode(&round));

    var large = fo;
    large.large = true;
    large.o_to_t_params = .{ .size = 4000, .variable = true };
    large.t_to_o_params = .{ .size = 4000, .variable = true };
    const lwire = try large.encode(&buf);
    try testing.expectEqual(@as(u8, 0x5B), large.service());
    try testing.expectEqual(large.encodedLen(), lwire.len);
    const lback = try ForwardOpen.decode(lwire, true);
    try testing.expectEqual(@as(u16, 4000), lback.t_to_o_params.size);
    try testing.expectEqualSlices(u8, lwire, try lback.encode(&round));
}

test "a small forward open refuses a size it cannot express" {
    var buf: [128]u8 = undefined;
    const fo = ForwardOpen{
        .o_to_t_connection_id = 0,
        .t_to_o_connection_id = 0,
        .connection_serial = 1,
        .originator_vendor_id = 1,
        .originator_serial = 1,
        .o_to_t_rpi = 1000,
        .o_to_t_params = .{ .size = 4000 },
        .t_to_o_rpi = 1000,
        .t_to_o_params = .{ .size = 4000 },
        .connection_path = &[_]u8{ 0x20, 0x02, 0x24, 0x01 },
    };
    try testing.expectError(error.TooLong, fo.encode(&buf));
}

test "a forward open connection path that overruns is refused" {
    var buf: [128]u8 = undefined;
    const fo = ForwardOpen{
        .o_to_t_connection_id = 0,
        .t_to_o_connection_id = 0,
        .connection_serial = 1,
        .originator_vendor_id = 1,
        .originator_serial = 1,
        .o_to_t_rpi = 1000,
        .o_to_t_params = .{ .size = 500 },
        .t_to_o_rpi = 1000,
        .t_to_o_params = .{ .size = 500 },
        .connection_path = &[_]u8{ 0x20, 0x02, 0x24, 0x01 },
    };
    const wire = try fo.encode(&buf);
    // The connection-path size octet sits immediately before the path.
    var bad: [512]u8 = undefined;
    @memcpy(bad[0..wire.len], wire);
    bad[wire.len - 5] = 0x40; // claim 64 words of connection path
    try testing.expectError(error.ConnectionPathOverruns, ForwardOpen.decode(bad[0..wire.len], false));
    try testing.expectError(error.Truncated, ForwardOpen.decode(wire[0..10], false));

    // F3 regression: bytes past the declared connection path used to be
    // silently accepted (`decode` was a prefix decoder with no name saying
    // so) -- wave-2 audit finding `enip` F3.
    var padded: [512]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xAA; // one trailing octet past the declared body
    try testing.expectError(error.TrailingData, ForwardOpen.decode(padded[0 .. wire.len + 1], false));
}

test "forward open and close replies round trip" {
    const r = ForwardOpenReply{
        .o_to_t_connection_id = 0xFB142115,
        .t_to_o_connection_id = 0xFFFFFFFF,
        .connection_serial = 0xCCFE,
        .originator_vendor_id = 0x1234,
        .originator_serial = 1,
        .o_to_t_api = 2_000_000,
        .t_to_o_api = 2_000_000,
        .application_reply = &.{},
    };
    var buf: [64]u8 = undefined;
    const wire = try r.encode(&buf);
    try testing.expectEqual(@as(usize, 26), wire.len);
    const back = try ForwardOpenReply.decode(wire);
    try testing.expectEqual(r.o_to_t_connection_id, back.o_to_t_connection_id);
    try testing.expectError(error.Truncated, ForwardOpenReply.decode(wire[0..20]));

    const c = ForwardCloseReply{
        .connection_serial = 0xCCFE,
        .originator_vendor_id = 0x1234,
        .originator_serial = 1,
        .application_reply = &.{},
    };
    const cwire = try c.encode(&buf);
    try testing.expectEqual(@as(usize, 10), cwire.len);
    const cback = try ForwardCloseReply.decode(cwire);
    try testing.expectEqual(c.connection_serial, cback.connection_serial);
}

test "forward close round trips and matches on the triple" {
    const fc = ForwardClose{
        .connection_serial = 0xCCFE,
        .originator_vendor_id = 0x1234,
        .originator_serial = 1,
        .connection_path = &[_]u8{ 0x01, 0x00, 0x20, 0x02, 0x24, 0x01 },
    };
    var buf: [64]u8 = undefined;
    const wire = try fc.encode(&buf);
    const back = try ForwardClose.decode(wire);
    try testing.expectEqual(fc.connection_serial, back.connection_serial);
    try testing.expectEqual(fc.originator_vendor_id, back.originator_vendor_id);
    try testing.expectEqualSlices(u8, fc.connection_path, back.connection_path);
    var bad: [512]u8 = undefined;
    @memcpy(bad[0..wire.len], wire);
    bad[10] = 0x40;
    try testing.expectError(error.ConnectionPathOverruns, ForwardClose.decode(bad[0..wire.len]));

    // F3 regression (ForwardClose side): see the ForwardOpen test above.
    var padded: [512]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xAA;
    try testing.expectError(error.TrailingData, ForwardClose.decode(padded[0 .. wire.len + 1]));
}

test "wrapping produces a message router request addressed to class 6" {
    const embedded = [_]u8{ 0x4C, 0x03, 0x91, 0x05, 'S', 'C', 'A', 'D', 'A', 0x00, 0x28, 0x00 };
    var buf: [128]u8 = undefined;
    const wire = try (UnconnectedSend{ .embedded = &embedded, .route_path = &backplane_slot_0 }).wrap(&buf);
    const req = try cip.Request.decode(wire);
    try testing.expectEqual(Service.unconnected_send, req.service);
    try testing.expectEqual(@as(?u32, 6), try req.classCode());
    const body = try UnconnectedSend.decode(req.data);
    try testing.expectEqualSlices(u8, &embedded, body.embedded);
}

test "backplane route builds port 1 link slot" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x03 }, try backplaneRoute(3, &buf));
}

test "fuzz: connection manager decoders never panic" {
    try std.testing.fuzz({}, fuzzConnMgr, .{});
}

fn fuzzConnMgr(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var round: [1024]u8 = undefined;
    if (UnconnectedSend.decode(buf[0..len])) |us| {
        const again = try us.encode(&round);
        try testing.expectEqualSlices(u8, buf[0..again.len], again);
    } else |_| {}
    for ([_]bool{ false, true }) |large| {
        if (ForwardOpen.decode(buf[0..len], large)) |fo| {
            if (fo.encode(&round)) |again| {
                try testing.expectEqualSlices(u8, buf[0..again.len], again);
            } else |_| {}
        } else |_| {}
    }
    if (ForwardClose.decode(buf[0..len])) |fc| {
        const again = try fc.encode(&round);
        try testing.expectEqualSlices(u8, buf[0..again.len], again);
    } else |_| {}
    _ = ForwardOpenReply.decode(buf[0..len]) catch {};
    _ = ForwardCloseReply.decode(buf[0..len]) catch {};
}

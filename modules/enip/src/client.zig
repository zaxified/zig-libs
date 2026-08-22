// SPDX-License-Identifier: MIT

//! An **EtherNet/IP explicit-messaging client** over the transport seam.
//!
//! One `Client` owns one connection's buffers, session handle and sequence
//! counters. It performs one request/reply exchange per call and never
//! allocates, never starts a thread and never reads a clock — a caller that
//! wants timeouts puts them inside its own `Transport.read`.
//!
//! **Borrowed slices.** Everything a reply hands back (a tag's octets, an
//! attribute's value, an identity's product name) points into this client's
//! own receive buffer and is invalidated by the next call. Copy what you need.
//! This is the same contract the rest of the collection's codecs use, and it
//! is what keeps the client allocation-free.
//!
//! **Routing.** By default every request is wrapped in an `Unconnected_Send`
//! carrying a backplane route path, which is what a ControlLogix chassis
//! needs. A device that does not route (a MicroLogix, a drive, most adapters)
//! answers `path_segment_error` to exactly that message, so `route` can be set
//! to `.direct` to send the bare CIP message instead. Getting this wrong is
//! the single most common "it works against the simulator and not against the
//! device" failure.

const std = @import("std");
const encap = @import("encap.zig");
const cpf = @import("cpf.zig");
const cip = @import("cip.zig");
const epath = @import("epath.zig");
const connmgr = @import("connmgr.zig");
const types = @import("types.zig");
const tagpath = @import("tagpath.zig");
const transport = @import("transport.zig");

pub const Transport = transport.Transport;

pub const Error = error{
    /// The transport failed or the peer went away.
    ReadFailed,
    WriteFailed,
    EndOfStream,
    /// The blocking operation was canceled through the `std.Io` cancellation
    /// protocol (`Future.cancel`). Surfaced instead of `ReadFailed`/
    /// `WriteFailed` so a caller can tell a canceled wait from a real
    /// transport failure.
    Canceled,
    /// The peer answered a different command than was asked.
    UnexpectedCommand,
    /// The peer answered with a non-zero encapsulation status.
    EncapsulationError,
    /// The peer's session handle did not match the one it issued.
    SessionMismatch,
    /// The reply's CPF item list was not the shape a reply must have.
    BadReply,
    /// The CIP reply carried a non-success general status.
    CipError,
    /// A call that needs a registered session was made before one existed.
    NoSession,
    /// A connected call was made with no connection open.
    NoConnection,
    /// The client's buffers cannot hold this request or reply.
    BufferTooSmall,
    /// The tag path could not be parsed or encoded.
    BadTagPath,
    /// The reply's payload did not match the service that was sent.
    MalformedReply,
    /// The peer answered a connected message with the wrong sequence count.
    SequenceMismatch,
};

/// How a request reaches the object it names.
pub const Routing = union(enum) {
    /// Wrap in `Unconnected_Send` with this route path. `01 00` (backplane,
    /// slot 0) is what a ControlLogix expects.
    unconnected_send: []const u8,
    /// Send the bare CIP message. Correct for devices that do not route.
    direct,
};

pub const Config = struct {
    routing: Routing = .{ .unconnected_send = &connmgr.backplane_slot_0 },
    /// Echoed back by the target; the only correlation this protocol has.
    sender_context: [8]u8 = "zig-enip".*,
    /// The encapsulation-layer timeout field, in seconds. Advisory.
    encapsulation_timeout: u16 = 10,
    /// The Connection Manager tick/ticks pair.
    cm_timeout: connmgr.Timeout = .default,
    /// Identifies this originator in `Forward_Open`. A real deployment sets
    /// its own ODVA-assigned vendor id.
    originator_vendor_id: u16 = 0x1234,
    originator_serial: u32 = 1,
};

/// A `Forward_Open`-established Class 3 connection.
pub const Connection = struct {
    o_to_t_id: u32,
    t_to_o_id: u32,
    serial: u16,
    sequence: u16 = 0,
    /// The largest CIP message this connection carries.
    size: u16,
};

/// The smallest buffer `init` accepts. Two of these (transmit and receive)
/// come out of the caller's slice.
pub const min_buffer: usize = 1024;

/// Widens a `TransportError` into the client's error set.
///
/// Written as an exhaustive switch rather than a catch-all so that a variant
/// added to the seam cannot silently arrive here as something else — which is
/// exactly how `Canceled` used to come out as `ReadFailed`, telling a caller
/// its connection had died when it had only been shut down.
fn fromTransport(e: transport.TransportError) Error {
    return switch (e) {
        error.ReadFailed => error.ReadFailed,
        error.WriteFailed => error.WriteFailed,
        error.EndOfStream => error.EndOfStream,
        error.Canceled => error.Canceled,
    };
}

pub const Client = struct {
    t: Transport,
    tx: []u8,
    rx: []u8,
    cfg: Config,
    session_handle: u32 = 0,
    connection: ?Connection = null,
    /// Set once `registerSession` succeeded.
    registered: bool = false,

    /// `buf` is split in half into a transmit and a receive scratch area, so a
    /// caller sizes exactly one thing. 4096 is comfortable for Logix traffic;
    /// a `Large_Forward_Open` at 4000 octets wants 16 KiB.
    pub fn init(t: Transport, buf: []u8, cfg: Config) Error!Client {
        if (buf.len < min_buffer * 2) return error.BufferTooSmall;
        const half = buf.len / 2;
        return .{ .t = t, .tx = buf[0..half], .rx = buf[half..], .cfg = cfg };
    }

    // ── encapsulation plumbing ──────────────────────────────────────────────

    fn exchange(self: *Client, command: encap.Command, data: []const u8) Error!encap.Message {
        // The transmit buffer holds the header plus the data; the data itself
        // was built in the front of `tx`, so build the framed message in `rx`
        // and then write it. Doing it the other way round would overwrite the
        // payload while framing it.
        const total = encap.header_len + data.len;
        if (total > self.rx.len) return error.BufferTooSmall;
        const framed = encap.encode(.{
            .command = command,
            .session_handle = self.session_handle,
            .status = .success,
            .sender_context = self.cfg.sender_context,
            .options = 0,
            .data = data,
            .total_len = 0,
        }, self.rx) catch return error.BufferTooSmall;
        self.t.write(framed) catch |e| return fromTransport(e);
        return self.readMessage(command);
    }

    fn readMessage(self: *Client, expect: encap.Command) Error!encap.Message {
        var got: usize = 0;
        // A transport may hand back a short read; keep going until a whole
        // message is present, and stop rather than spin if it never is.
        var rounds: usize = 0;
        while (rounds < 4096) : (rounds += 1) {
            const n = self.t.read(self.rx[got..]) catch |e| return fromTransport(e);
            got += n;
            if (got < encap.header_len) continue;
            const total = encap.peekTotalLen(self.rx[0..encap.header_len]) catch
                return error.BadReply;
            if (total > self.rx.len) return error.BufferTooSmall;
            if (got >= total) {
                const msg = encap.decodePrefix(self.rx[0..total]) catch return error.BadReply;
                if (msg.command != expect) return error.UnexpectedCommand;
                if (!msg.status.isSuccess()) return error.EncapsulationError;
                if (self.registered and !expect.isSessionless() and
                    msg.session_handle != self.session_handle)
                {
                    return error.SessionMismatch;
                }
                return msg;
            }
        }
        return error.ReadFailed;
    }

    // ── session management ─────────────────────────────────────────────────

    /// `RegisterSession`. Everything except the three list commands and `NOP`
    /// needs one.
    pub fn registerSession(self: *Client) Error!u32 {
        var payload: [4]u8 = undefined;
        const data = (encap.RegisterSessionData{}).encode(&payload) catch
            return error.BufferTooSmall;
        const reply = try self.exchange(.register_session, data);
        const rs = encap.RegisterSessionData.decode(reply.data) catch return error.BadReply;
        if (rs.version != encap.protocol_version) return error.BadReply;
        self.session_handle = reply.session_handle;
        self.registered = true;
        return self.session_handle;
    }

    /// `UnRegisterSession`. The target answers nothing and closes; this
    /// therefore writes and returns without reading.
    pub fn unregisterSession(self: *Client) Error!void {
        if (!self.registered) return;
        const framed = encap.encode(.{
            .command = .unregister_session,
            .session_handle = self.session_handle,
            .status = .success,
            .sender_context = self.cfg.sender_context,
            .options = 0,
            .data = &.{},
            .total_len = 0,
        }, self.rx) catch return error.BufferTooSmall;
        self.t.write(framed) catch |e| return fromTransport(e);
        self.registered = false;
        self.session_handle = 0;
        self.connection = null;
    }

    /// `NOP`: a keepalive with no reply at all.
    pub fn nop(self: *Client) Error!void {
        const framed = encap.encode(.{
            .command = .nop,
            .session_handle = self.session_handle,
            .status = .success,
            .sender_context = self.cfg.sender_context,
            .options = 0,
            .data = &.{},
            .total_len = 0,
        }, self.rx) catch return error.BufferTooSmall;
        self.t.write(framed) catch |e| return fromTransport(e);
    }

    // ── the list commands ──────────────────────────────────────────────────

    /// `ListIdentity` over the open TCP connection. On UDP this is a
    /// broadcast; use `encodeListIdentityRequest` / `decodeListIdentityReply`
    /// with `transport.UdpDiscovery` for that.
    pub fn listIdentity(self: *Client) Error!encap.Identity {
        const reply = try self.exchange(.list_identity, &.{});
        var storage: [4]cpf.Item = undefined;
        const list = cpf.decode(reply.data, &storage) catch return error.BadReply;
        const item = list.find(.list_identity_response) orelse return error.BadReply;
        return encap.Identity.decode(item.data) catch error.BadReply;
    }

    /// `ListServices`.
    pub fn listServices(self: *Client) Error!encap.Service {
        const reply = try self.exchange(.list_services, &.{});
        var storage: [4]cpf.Item = undefined;
        const list = cpf.decode(reply.data, &storage) catch return error.BadReply;
        const item = list.find(.list_services_response) orelse return error.BadReply;
        return encap.Service.decode(item.data) catch error.BadReply;
    }

    /// `ListInterfaces`. Most devices answer with an empty list, which is a
    /// legal answer and not an error.
    pub fn listInterfaces(self: *Client) Error!usize {
        const reply = try self.exchange(.list_interfaces, &.{});
        var storage: [8]cpf.Item = undefined;
        const list = cpf.decode(reply.data, &storage) catch return error.BadReply;
        return list.items.len;
    }

    // ── CIP messaging ──────────────────────────────────────────────────────

    /// Sends one already-encoded CIP message and returns its reply.
    ///
    /// Applies the configured routing, wraps in CPF, frames, writes, reads and
    /// unwraps. The reply's slices point into the receive buffer.
    pub fn sendCip(self: *Client, request: []const u8) Error!cip.Reply {
        if (!self.registered) return error.NoSession;
        const outgoing = try self.applyRouting(request);
        const items = cpf.unconnectedItems(outgoing);
        // The CPF envelope is built at the *end* of the transmit buffer so it
        // does not overwrite the request sitting at the front.
        const env_start = self.tx.len / 2;
        const env = cpf.encodeEnvelope(
            cpf.cip_interface_handle,
            self.cfg.encapsulation_timeout,
            &items,
            self.tx[env_start..],
        ) catch return error.BufferTooSmall;
        const reply = try self.exchange(.send_rr_data, env);
        return try unwrapUnconnected(reply.data);
    }

    /// Sends a CIP message over an open Class 3 connection.
    pub fn sendConnectedCip(self: *Client, request: []const u8) Error!cip.Reply {
        if (self.connection == null) return error.NoConnection;
        const conn = &self.connection.?;
        var id_le: [4]u8 = undefined;
        std.mem.writeInt(u32, &id_le, conn.o_to_t_id, .little);
        const env_start = self.tx.len / 2;
        var body_buf = self.tx[env_start..];
        if (body_buf.len < 2 + request.len + 64) return error.BufferTooSmall;
        conn.sequence +%= 1;
        const sent_sequence = conn.sequence;
        const body = cpf.ConnectedData.encode(sent_sequence, request, body_buf) catch
            return error.BufferTooSmall;
        const items = cpf.connectedItems(&id_le, body);
        const env = cpf.encodeEnvelope(
            cpf.cip_interface_handle,
            0, // a connection's own timeout governs; the field is unused
            &items,
            body_buf[body.len..],
        ) catch return error.BufferTooSmall;
        const reply = try self.exchange(.send_unit_data, env);

        var storage: [4]cpf.Item = undefined;
        const rep_env = cpf.decodeEnvelope(reply.data, &storage) catch return error.BadReply;
        cpf.validateDataOrder(rep_env.list) catch return error.BadReply;
        const data_item = rep_env.list.dataItem() orelse return error.BadReply;
        const cd = cpf.ConnectedData.decode(data_item) catch return error.BadReply;
        if (cd.sequence_count != sent_sequence) return error.SequenceMismatch;
        return cip.Reply.decode(cd.payload) catch error.BadReply;
    }

    fn applyRouting(self: *Client, request: []const u8) Error![]const u8 {
        switch (self.cfg.routing) {
            .direct => {
                if (request.len > self.tx.len / 2) return error.BufferTooSmall;
                @memcpy(self.tx[0..request.len], request);
                return self.tx[0..request.len];
            },
            .unconnected_send => |route| {
                const us = connmgr.UnconnectedSend{
                    .timeout = self.cfg.cm_timeout,
                    .embedded = request,
                    .route_path = route,
                };
                // Build the wrapper in the front half of `tx`; the request was
                // handed in from the caller's own storage or from a scratch
                // area past it.
                const wrapped = us.wrap(self.tx[0 .. self.tx.len / 2]) catch
                    return error.BufferTooSmall;
                return wrapped;
            },
        }
    }

    fn unwrapUnconnected(data: []const u8) Error!cip.Reply {
        var storage: [4]cpf.Item = undefined;
        const env = cpf.decodeEnvelope(data, &storage) catch return error.BadReply;
        cpf.validateDataOrder(env.list) catch return error.BadReply;
        const item = env.list.dataItem() orelse return error.BadReply;
        if (item.type_id != .unconnected_data) return error.BadReply;
        return cip.Reply.decode(item.data) catch error.BadReply;
    }

    // ── attribute services ─────────────────────────────────────────────────

    /// `Get_Attribute_Single`. The value points into the receive buffer.
    pub fn getAttributeSingle(
        self: *Client,
        class_id: u32,
        instance: u32,
        attribute: u32,
    ) Error![]const u8 {
        var req: [32]u8 = undefined;
        const wire = cip.getAttributeSingle(class_id, instance, attribute, &req) catch
            return error.BufferTooSmall;
        const reply = try self.sendCip(wire);
        if (!reply.general_status.isSuccess()) return error.CipError;
        return reply.data;
    }

    /// `Get_Attributes_All`. The value points into the receive buffer.
    pub fn getAttributesAll(self: *Client, class_id: u32, instance: u32) Error![]const u8 {
        var req: [32]u8 = undefined;
        const wire = cip.getAttributesAll(class_id, instance, &req) catch
            return error.BufferTooSmall;
        const reply = try self.sendCip(wire);
        if (!reply.general_status.isSuccess()) return error.CipError;
        return reply.data;
    }

    /// `Set_Attribute_Single`.
    pub fn setAttributeSingle(
        self: *Client,
        class_id: u32,
        instance: u32,
        attribute: u32,
        value: []const u8,
    ) Error!void {
        var req: [256]u8 = undefined;
        const wire = cip.setAttributeSingle(class_id, instance, attribute, value, &req) catch
            return error.BufferTooSmall;
        const reply = try self.sendCip(wire);
        if (!reply.general_status.isSuccess()) return error.CipError;
    }

    /// `Reset` (service 0x05) on an object.
    ///
    /// On the Identity object this **reboots the device**. It is spelled out
    /// in full at every call site for that reason; nothing here calls it
    /// implicitly.
    pub fn reset(self: *Client, class_id: u32, instance: u32) Error!void {
        var path_buf: [16]u8 = undefined;
        const path = epath.logicalPath(class_id, instance, null, &path_buf) catch
            return error.BufferTooSmall;
        var req: [32]u8 = undefined;
        const wire = (cip.Request{
            .service = @intFromEnum(cip.Service.reset),
            .path = path,
            .data = &.{},
        }).encode(&req) catch return error.BufferTooSmall;
        const reply = try self.sendCip(wire);
        if (!reply.general_status.isSuccess()) return error.CipError;
    }

    // ── Logix tag services ─────────────────────────────────────────────────

    /// `Read Tag` (0x4C) by symbolic name. The returned octets point into the
    /// receive buffer.
    pub fn readTag(self: *Client, name: []const u8, count: u16) Error!types.TagData {
        var req_buf: [512]u8 = undefined;
        const wire = try encodeReadTag(name, count, &req_buf);
        const reply = try self.sendCip(wire);
        if (!reply.general_status.hasData()) return error.CipError;
        return types.TagData.decode(reply.data) catch error.MalformedReply;
    }

    /// `Read Tag Fragmented` (0x52), looping until the target stops answering
    /// `partial_transfer`. The accumulated octets land in `out`.
    ///
    /// The offset advances by the **octets received**, not by elements —
    /// which is what the service's own field means.
    pub fn readTagFragmented(
        self: *Client,
        name: []const u8,
        count: u16,
        out: []u8,
    ) Error!types.TagData {
        var offset: u32 = 0;
        var written: usize = 0;
        var result_type: types.DataType = .bool;
        var handle: ?u16 = null;
        var rounds: usize = 0;
        while (rounds < 1024) : (rounds += 1) {
            var req_buf: [512]u8 = undefined;
            var path_buf: [256]u8 = undefined;
            const path = tagpath.encodePath(name, &path_buf) catch return error.BadTagPath;
            var data_buf: [6]u8 = undefined;
            const data = (types.ReadTagFragmentedRequest{
                .count = count,
                .byte_offset = offset,
            }).encode(&data_buf) catch return error.BufferTooSmall;
            const wire = (cip.Request{
                .service = cip.LogixService.read_tag_fragmented,
                .path = path,
                .data = data,
            }).encode(&req_buf) catch return error.BufferTooSmall;

            const reply = try self.sendCip(wire);
            if (!reply.general_status.hasData()) return error.CipError;
            const td = types.TagData.decode(reply.data) catch return error.MalformedReply;
            if (rounds == 0) {
                result_type = td.type;
                handle = td.structure_handle;
            } else if (td.type != result_type) {
                return error.MalformedReply;
            }
            if (written + td.data.len > out.len) return error.BufferTooSmall;
            @memcpy(out[written..][0..td.data.len], td.data);
            written += td.data.len;
            offset = @intCast(written);
            if (reply.general_status != .partial_transfer) break;
            // A target that reports "more follows" but sends nothing would
            // loop forever.
            if (td.data.len == 0) return error.MalformedReply;
        }
        return .{ .type = result_type, .structure_handle = handle, .data = out[0..written] };
    }

    /// `Write Tag` (0x4D) by symbolic name.
    pub fn writeTag(
        self: *Client,
        name: []const u8,
        data_type: types.DataType,
        count: u16,
        values: []const u8,
    ) Error!void {
        var req_buf: [1024]u8 = undefined;
        var path_buf: [256]u8 = undefined;
        const path = tagpath.encodePath(name, &path_buf) catch return error.BadTagPath;
        var data_buf: [512]u8 = undefined;
        const data = (types.WriteTagRequest{
            .type = data_type,
            .count = count,
            .values = values,
        }).encode(&data_buf) catch return error.BufferTooSmall;
        const wire = (cip.Request{
            .service = cip.LogixService.write_tag,
            .path = path,
            .data = data,
        }).encode(&req_buf) catch return error.BufferTooSmall;
        const reply = try self.sendCip(wire);
        if (!reply.general_status.isSuccess()) return error.CipError;
    }

    /// `Write Tag Fragmented` (0x53), splitting `values` into chunks of
    /// `chunk` octets. `count` is the tag's **total** element count and is
    /// repeated in every fragment, which is what the service expects.
    pub fn writeTagFragmented(
        self: *Client,
        name: []const u8,
        data_type: types.DataType,
        count: u16,
        values: []const u8,
        chunk: usize,
    ) Error!void {
        const element = data_type.elementSize() orelse return error.MalformedReply;
        // A fragment must never split an element.
        const step = @max(element, (chunk / element) * element);
        var off: usize = 0;
        while (off < values.len) {
            const n = @min(step, values.len - off);
            var req_buf: [1024]u8 = undefined;
            var path_buf: [256]u8 = undefined;
            const path = tagpath.encodePath(name, &path_buf) catch return error.BadTagPath;
            var data_buf: [512]u8 = undefined;
            const data = (types.WriteTagFragmentedRequest{
                .type = data_type,
                .count = count,
                .byte_offset = @intCast(off),
                .values = values[off..][0..n],
            }).encode(&data_buf) catch return error.BufferTooSmall;
            const wire = (cip.Request{
                .service = cip.LogixService.write_tag_fragmented,
                .path = path,
                .data = data,
            }).encode(&req_buf) catch return error.BufferTooSmall;
            const reply = try self.sendCip(wire);
            if (!reply.general_status.isSuccess()) return error.CipError;
            off += n;
        }
    }

    // ── Multiple Service Packet ────────────────────────────────────────────

    /// Batches already-encoded CIP requests into one `Multiple_Service_Packet`
    /// and fills `replies` with the embedded replies, in order.
    ///
    /// A per-request failure is reported **in its own reply's general
    /// status**, not as an error — the outer service succeeds even when every
    /// embedded one failed, which is exactly what makes this service worth
    /// having and exactly what a naive caller misreads.
    pub fn multipleServices(
        self: *Client,
        requests: []const []const u8,
        replies: []cip.Reply,
    ) Error!usize {
        if (replies.len < requests.len) return error.BufferTooSmall;
        var payload_buf: [1024]u8 = undefined;
        const payload = cip.MultipleService.encode(requests, &payload_buf) catch
            return error.BufferTooSmall;
        var path_buf: [8]u8 = undefined;
        const path = epath.logicalPath(
            @intFromEnum(cip.ClassCode.message_router),
            1,
            null,
            &path_buf,
        ) catch return error.BufferTooSmall;
        var req_buf: [1200]u8 = undefined;
        const wire = (cip.Request{
            .service = @intFromEnum(cip.Service.multiple_service_packet),
            .path = path,
            .data = payload,
        }).encode(&req_buf) catch return error.BufferTooSmall;

        const reply = try self.sendCip(wire);
        if (!reply.general_status.hasData()) return error.CipError;
        const ms = cip.MultipleService.decode(reply.data) catch return error.MalformedReply;
        const n = @min(ms.count, requests.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const embedded = ms.at(i) catch return error.MalformedReply;
            replies[i] = cip.Reply.decode(embedded) catch return error.MalformedReply;
        }
        return n;
    }

    /// The everyday batched read: several tags in one round trip.
    /// `results[i]` is null when that tag's embedded reply failed.
    pub fn readTags(
        self: *Client,
        names: []const []const u8,
        results: []?types.TagData,
    ) Error!usize {
        if (results.len < names.len) return error.BufferTooSmall;
        var storage: [8][512]u8 = undefined;
        var requests: [8][]const u8 = undefined;
        if (names.len > storage.len) return error.BufferTooSmall;
        for (names, 0..) |name, i| {
            requests[i] = try encodeReadTag(name, 1, &storage[i]);
        }
        var replies: [8]cip.Reply = undefined;
        const n = try self.multipleServices(requests[0..names.len], replies[0..names.len]);
        for (replies[0..n], 0..) |r, i| {
            results[i] = if (r.general_status.hasData())
                (types.TagData.decode(r.data) catch null)
            else
                null;
        }
        return n;
    }

    // ── connected messaging ────────────────────────────────────────────────

    pub const ForwardOpenOptions = struct {
        /// Octets per packet. Above 511 the `Large_Forward_Open` form is used
        /// automatically, because the small form cannot express it.
        size: u16 = 500,
        /// Microseconds between packets. Meaningless for Class 3 explicit
        /// messaging but still required on the wire.
        rpi: u32 = 2_000_000,
        connection_serial: u16 = 0x0001,
        /// The object at the far end. Defaults to the Message Router, which
        /// is what an explicit-messaging connection targets.
        connection_path: ?[]const u8 = null,
        /// Prepended to the connection path. Defaults to the configured
        /// unconnected route, because a connection has to be routed once too.
        route_path: ?[]const u8 = null,
    };

    /// Opens a Class 3 explicit-messaging connection. Afterwards
    /// `sendConnectedCip` works and carries a sequence count instead of a
    /// route path on every message.
    pub fn forwardOpen(self: *Client, options: ForwardOpenOptions) Error!Connection {
        var path_buf: [64]u8 = undefined;
        var b = epath.Builder.init(&path_buf);
        const route = options.route_path orelse switch (self.cfg.routing) {
            .unconnected_send => |r| r,
            .direct => &[_]u8{},
        };
        if (options.connection_path) |p| {
            if (route.len + p.len > path_buf.len) return error.BufferTooSmall;
            @memcpy(path_buf[0..route.len], route);
            @memcpy(path_buf[route.len..][0..p.len], p);
            b.len = route.len + p.len;
        } else {
            if (route.len > 0) {
                var it = epath.Iterator.init(route);
                while (it.next() catch return error.BufferTooSmall) |seg| {
                    b.segment(seg) catch return error.BufferTooSmall;
                }
            }
            b.class(@intFromEnum(cip.ClassCode.message_router)) catch return error.BufferTooSmall;
            b.instance(1) catch return error.BufferTooSmall;
        }

        const large = options.size > connmgr.ConnectionParameters.max_small_size;
        const params = connmgr.ConnectionParameters{ .size = options.size, .variable = true };
        const fo = connmgr.ForwardOpen{
            .timeout = self.cfg.cm_timeout,
            .o_to_t_connection_id = 0,
            .t_to_o_connection_id = 0,
            .connection_serial = options.connection_serial,
            .originator_vendor_id = self.cfg.originator_vendor_id,
            .originator_serial = self.cfg.originator_serial,
            .o_to_t_rpi = options.rpi,
            .o_to_t_params = params,
            .t_to_o_rpi = options.rpi,
            .t_to_o_params = params,
            .connection_path = b.bytes(),
            .large = large,
        };
        var req_buf: [256]u8 = undefined;
        const wire = fo.wrap(&req_buf) catch return error.BufferTooSmall;
        // A Forward_Open is addressed to the Connection Manager on the local
        // device and carries its own route, so it is never wrapped again.
        const saved = self.cfg.routing;
        self.cfg.routing = .direct;
        defer self.cfg.routing = saved;
        const reply = try self.sendCip(wire);
        if (!reply.general_status.isSuccess()) return error.CipError;
        const fr = connmgr.ForwardOpenReply.decode(reply.data) catch return error.MalformedReply;
        const conn = Connection{
            .o_to_t_id = fr.o_to_t_connection_id,
            .t_to_o_id = fr.t_to_o_connection_id,
            .serial = fr.connection_serial,
            .size = options.size,
        };
        self.connection = conn;
        return conn;
    }

    /// Closes the connection opened by `forwardOpen`.
    pub fn forwardClose(self: *Client) Error!void {
        const conn = self.connection orelse return error.NoConnection;
        var path_buf: [32]u8 = undefined;
        var b = epath.Builder.init(&path_buf);
        const route = switch (self.cfg.routing) {
            .unconnected_send => |r| r,
            .direct => &[_]u8{},
        };
        if (route.len > 0) {
            var it = epath.Iterator.init(route);
            while (it.next() catch return error.BufferTooSmall) |seg| {
                b.segment(seg) catch return error.BufferTooSmall;
            }
        }
        b.class(@intFromEnum(cip.ClassCode.message_router)) catch return error.BufferTooSmall;
        b.instance(1) catch return error.BufferTooSmall;

        const fc = connmgr.ForwardClose{
            .timeout = self.cfg.cm_timeout,
            .connection_serial = conn.serial,
            .originator_vendor_id = self.cfg.originator_vendor_id,
            .originator_serial = self.cfg.originator_serial,
            .connection_path = b.bytes(),
        };
        var req_buf: [128]u8 = undefined;
        const wire = fc.wrap(&req_buf) catch return error.BufferTooSmall;
        const saved = self.cfg.routing;
        self.cfg.routing = .direct;
        defer self.cfg.routing = saved;
        const reply = try self.sendCip(wire);
        self.connection = null;
        if (!reply.general_status.isSuccess()) return error.CipError;
    }
};

/// Encodes a `Read Tag` request for `name`.
pub fn encodeReadTag(name: []const u8, count: u16, out: []u8) Error![]const u8 {
    var path_buf: [256]u8 = undefined;
    const path = tagpath.encodePath(name, &path_buf) catch return error.BadTagPath;
    var data_buf: [2]u8 = undefined;
    const data = (types.ReadTagRequest{ .count = count }).encode(&data_buf) catch
        return error.BufferTooSmall;
    return (cip.Request{
        .service = cip.LogixService.read_tag,
        .path = path,
        .data = data,
    }).encode(out) catch error.BufferTooSmall;
}

// ── UDP discovery helpers ──────────────────────────────────────────────────

/// The `ListIdentity` request as it goes out on UDP — 24 octets and nothing
/// else. Broadcast it and collect every answer.
pub fn encodeListIdentityRequest(sender_context: [8]u8, out: []u8) Error![]const u8 {
    return encap.encode(.{
        .command = .list_identity,
        .session_handle = 0,
        .status = .success,
        .sender_context = sender_context,
        .options = 0,
        .data = &.{},
        .total_len = 0,
    }, out) catch error.BufferTooSmall;
}

/// Decodes one device's answer to a broadcast `ListIdentity`.
pub fn decodeListIdentityReply(datagram: []const u8) Error!encap.Identity {
    const msg = encap.decode(datagram) catch return error.BadReply;
    if (msg.command != .list_identity) return error.UnexpectedCommand;
    if (!msg.status.isSuccess()) return error.EncapsulationError;
    var storage: [4]cpf.Item = undefined;
    const list = cpf.decode(msg.data, &storage) catch return error.BadReply;
    const item = list.find(.list_identity_response) orelse return error.BadReply;
    return encap.Identity.decode(item.data) catch error.BadReply;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "read tag request encodes the shape a controller expects" {
    var buf: [64]u8 = undefined;
    const wire = try encodeReadTag("SCADA", 1, &buf);
    // Path size 4 words: `91 05` + five characters + the pad. The element
    // segment is absent because the name named no element, which reads from
    // the start of the tag.
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x4C, 0x04, 0x91, 0x05, 'S', 'C', 'A', 'D', 'A', 0x00, 0x01, 0x00 },
        wire,
    );
    // …and with an element index it is the five-word form both reference
    // clients emit.
    const indexed = try encodeReadTag("SCADA[0]", 2, &buf);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x4C, 0x05, 0x91, 0x05, 'S', 'C', 'A', 'D', 'A', 0x00, 0x28, 0x00, 0x02, 0x00 },
        indexed,
    );
}

test "a list identity request is 24 octets and nothing else" {
    var buf: [64]u8 = undefined;
    const wire = try encodeListIdentityRequest("zig-enip".*, &buf);
    try testing.expectEqual(@as(usize, 24), wire.len);
    try testing.expectEqual(@as(u8, 0x63), wire[0]);
    try testing.expectEqual(@as(u8, 0x00), wire[2]);
}

test "init refuses a buffer too small to hold a request and a reply" {
    var lt: transport.LoopTransport = .{};
    var small: [64]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Client.init(lt.transport(), &small, .{}));
}

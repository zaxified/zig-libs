// SPDX-License-Identifier: MIT

//! The **target side**: an EtherNet/IP adapter as a pure function from one
//! encapsulation message to one encapsulation message, backed by
//! caller-owned tag storage.
//!
//! No socket, no thread, no clock and no allocation — `handle` takes the
//! octets that arrived and the buffer to answer in, and returns the reply (or
//! `null` when the protocol says to answer nothing and close, which is what
//! `UnRegisterSession` and `NOP` mean). Stand up one per simulated device for
//! fleet simulation, or drive one from a real accept loop.
//!
//! What it answers:
//!
//! * `NOP`, `ListIdentity`, `ListServices`, `ListInterfaces`,
//!   `RegisterSession`, `UnRegisterSession`;
//! * `SendRRData` carrying a UCMM message, including an `Unconnected_Send`
//!   wrapper it unwraps and re-dispatches;
//! * `SendUnitData` on a connection opened by `Forward_Open` /
//!   `Large_Forward_Open`, with the sequence count echoed;
//! * on the Message Router: `Get_Attributes_All` and `Get_Attribute_Single`
//!   on the Identity object, `Multiple_Service_Packet`, and the Logix tag
//!   services `Read Tag`, `Write Tag`, `Read Tag Fragmented` and
//!   `Write Tag Fragmented` against bound tags.
//!
//! It is a **simulator, not a controller**: it runs no program, enforces no
//! access control and implements no CIP Security. Do not put one where
//! something might mistake it for real equipment.

const std = @import("std");
const encap = @import("encap.zig");
const cpf = @import("cpf.zig");
const cip = @import("cip.zig");
const epath = @import("epath.zig");
const connmgr = @import("connmgr.zig");
const types = @import("types.zig");

pub const Error = error{
    /// The request could not be parsed far enough to answer it at all.
    Malformed,
    /// The output buffer cannot hold the reply.
    BufferTooSmall,
};

/// One tag this adapter serves.
pub const TagBinding = struct {
    name: []const u8,
    type: types.DataType,
    /// The tag's octets. Element count is `bytes.len / type.elementSize()`.
    bytes: []u8,

    pub fn elementSize(self: TagBinding) usize {
        return self.type.elementSize() orelse 1;
    }

    pub fn elementCount(self: TagBinding) usize {
        return self.bytes.len / self.elementSize();
    }
};

pub const Config = struct {
    vendor_id: u16 = 0x1234,
    device_type: u16 = @intFromEnum(encap.DeviceType.programmable_logic_controller),
    product_code: u16 = 1,
    revision_major: u8 = 1,
    revision_minor: u8 = 0,
    identity_status: u16 = 0x0030,
    serial_number: u32 = 0x00C0FFEE,
    product_name: []const u8 = "zig-enip adapter",
    state: encap.DeviceState = .operational,
    /// What `ListIdentity` reports as its own socket address.
    socket_address: encap.SocketAddress = .{
        .port = encap.default_tcp_port,
        .addr = .{ 0, 0, 0, 0 },
    },
    /// Largest CIP reply this adapter will build.
    max_reply: usize = 4000,
    /// `Reset` reboots a real device. Refused unless this is set.
    allow_reset: bool = false,
};

/// An open Class 3 connection.
const OpenConnection = struct {
    in_use: bool = false,
    o_to_t_id: u32 = 0,
    t_to_o_id: u32 = 0,
    serial: u16 = 0,
    vendor: u16 = 0,
    originator_serial: u32 = 0,
};

pub const Adapter = struct {
    cfg: Config,
    tags: []const TagBinding,
    /// Non-zero once a session is registered.
    session_handle: u32 = 0,
    /// Counters a test or a simulator can assert on.
    reads: usize = 0,
    writes: usize = 0,
    identity_requests: usize = 0,
    connections: [4]OpenConnection = @splat(.{}),
    /// Assigned to the next `Forward_Open`; incremented so two connections
    /// never share an id.
    next_connection_id: u32 = 0x0100_0001,
    /// Set when a `Reset` was received and allowed, so a simulator can act.
    reset_requested: bool = false,

    pub fn init(cfg: Config, tags: []const TagBinding) Adapter {
        return .{ .cfg = cfg, .tags = tags };
    }

    fn identity(self: *const Adapter) encap.Identity {
        return .{
            .socket_address = self.cfg.socket_address,
            .vendor_id = self.cfg.vendor_id,
            .device_type = self.cfg.device_type,
            .product_code = self.cfg.product_code,
            .revision_major = self.cfg.revision_major,
            .revision_minor = self.cfg.revision_minor,
            .status = self.cfg.identity_status,
            .serial_number = self.cfg.serial_number,
            .product_name = self.cfg.product_name,
            .state = self.cfg.state,
        };
    }

    /// Answers one encapsulation message. Returns `null` when the protocol
    /// says to send nothing (`NOP`, `UnRegisterSession`).
    ///
    /// The reply body is built in a scratch area and only then framed into
    /// `out`, rather than being written past the header and framed in place —
    /// an in-place frame is a `@memcpy` of a region onto itself, which Zig's
    /// non-overlap contract does not permit.
    pub fn handle(self: *Adapter, request: []const u8, out: []u8) Error!?[]const u8 {
        const msg = encap.decode(request) catch return error.Malformed;
        if (out.len < encap.header_len) return error.BufferTooSmall;

        var scratch: [4096]u8 = undefined;
        var status: encap.Status = .success;
        var handle_out: u32 = msg.session_handle;
        var data: []const u8 = &.{};

        switch (msg.command) {
            .nop => return null,
            .unregister_session => {
                self.session_handle = 0;
                for (&self.connections) |*c| c.in_use = false;
                return null;
            },
            .register_session => {
                if (encap.RegisterSessionData.decode(msg.data)) |rs| {
                    if (rs.version != encap.protocol_version) {
                        status = .unsupported_protocol_revision;
                    } else {
                        // Any non-zero handle works; a real device makes it
                        // unguessable, which is the only "authentication" this
                        // protocol has — and it is not one.
                        self.session_handle = 0xA5A5_0001;
                        handle_out = self.session_handle;
                        data = encap.RegisterSessionData.encode(.{}, &scratch) catch
                            return error.BufferTooSmall;
                    }
                } else |_| {
                    status = .incorrect_data;
                }
            },
            .list_identity => {
                self.identity_requests += 1;
                var item_buf: [512]u8 = undefined;
                const ident = self.identity().encode(&item_buf) catch
                    return error.BufferTooSmall;
                const items = [_]cpf.Item{
                    .{ .type_id = .list_identity_response, .data = ident },
                };
                data = cpf.encode(&items, &scratch) catch return error.BufferTooSmall;
            },
            .list_services => {
                var item_buf: [64]u8 = undefined;
                const svc = (encap.Service{
                    .capability_flags = encap.Service.supports_tcp_encapsulation,
                    .name = "Communications\x00",
                }).encode(&item_buf) catch return error.BufferTooSmall;
                const items = [_]cpf.Item{
                    .{ .type_id = .list_services_response, .data = svc },
                };
                data = cpf.encode(&items, &scratch) catch return error.BufferTooSmall;
            },
            .list_interfaces => {
                data = cpf.encode(&.{}, &scratch) catch return error.BufferTooSmall;
            },
            .send_rr_data, .send_unit_data => {
                if (self.session_handle == 0 or msg.session_handle != self.session_handle) {
                    status = .invalid_session_handle;
                } else if (self.handleData(msg.command, msg.data, &scratch)) |body| {
                    data = body;
                } else |e| switch (e) {
                    error.BufferTooSmall => return error.BufferTooSmall,
                    // A CPF envelope this adapter cannot parse is answered at
                    // the encapsulation layer, because there is no CIP message
                    // to answer with.
                    else => status = .incorrect_data,
                }
            },
            else => status = .invalid_command,
        }
        if (!status.isSuccess()) data = &.{};

        return encap.encode(.{
            .command = msg.command,
            .session_handle = handle_out,
            .status = status,
            .sender_context = msg.sender_context,
            .options = 0,
            .data = data,
            .total_len = 0,
        }, out) catch error.BufferTooSmall;
    }

    // ── CPF and CIP dispatch ───────────────────────────────────────────────

    fn handleData(
        self: *Adapter,
        command: encap.Command,
        payload: []const u8,
        out: []u8,
    ) Error![]const u8 {
        var storage: [8]cpf.Item = undefined;
        const env = cpf.decodeEnvelope(payload, &storage) catch return error.Malformed;
        cpf.validateDataOrder(env.list) catch return error.Malformed;
        const addr = env.list.addressItem().?;
        const data_item = env.list.dataItem().?;

        // Build the CIP reply into a scratch area at the far end of `out`, so
        // the CPF envelope can be written at the front without overlapping.
        var scratch: [4096]u8 = undefined;

        if (command == .send_unit_data) {
            const id = cpf.connectionId(addr) catch return error.Malformed;
            const conn = self.findConnection(id) orelse return error.Malformed;
            _ = conn;
            const cd = cpf.ConnectedData.decode(data_item) catch return error.Malformed;
            const reply = try self.messageRouter(cd.payload, &scratch);
            var body_buf: [4096]u8 = undefined;
            const body = cpf.ConnectedData.encode(cd.sequence_count, reply, &body_buf) catch
                return error.BufferTooSmall;
            var id_le: [4]u8 = undefined;
            std.mem.writeInt(u32, &id_le, id, .little);
            const items = cpf.connectedItems(&id_le, body);
            return cpf.encodeEnvelope(cpf.cip_interface_handle, 0, &items, out) catch
                error.BufferTooSmall;
        }

        const reply = try self.messageRouter(data_item.data, &scratch);
        const items = cpf.unconnectedItems(reply);
        return cpf.encodeEnvelope(cpf.cip_interface_handle, env.timeout, &items, out) catch
            error.BufferTooSmall;
    }

    fn findConnection(self: *Adapter, id: u32) ?*OpenConnection {
        for (&self.connections) |*c| {
            if (c.in_use and c.o_to_t_id == id) return c;
        }
        return null;
    }

    /// How deeply a request may nest an `Unconnected_Send` or a
    /// `Multiple_Service_Packet` inside another one. Unbounded nesting is a
    /// stack-exhaustion primitive a hostile peer controls, so it is capped.
    pub const max_nesting: usize = 4;

    /// The Message Router: one CIP request in, one CIP reply out.
    pub fn messageRouter(self: *Adapter, request: []const u8, out: []u8) Error![]const u8 {
        return self.route(request, out, 0);
    }

    fn route(self: *Adapter, request: []const u8, out: []u8, depth: usize) Error![]const u8 {
        if (depth > max_nesting) return errorReply(0x00, .resource_unavailable, out);
        const req = cip.Request.decode(request) catch
            return errorReply(0x00, .message_format_error, out);
        const class = req.classCode() catch null;

        // Service codes collide across classes, so the class in the path is
        // consulted *before* the code is interpreted.
        if (class != null and class.? == connmgr.class_code) {
            return self.connectionManager(req, out, depth);
        }
        switch (req.service) {
            @intFromEnum(cip.Service.multiple_service_packet) => return self.multipleService(req, out, depth),
            @intFromEnum(cip.Service.get_attributes_all) => return self.getAttributesAll(req, class, out),
            @intFromEnum(cip.Service.get_attribute_single) => return self.getAttributeSingle(req, class, out),
            @intFromEnum(cip.Service.reset) => {
                if (!self.cfg.allow_reset) return errorReply(req.service, .privilege_violation, out);
                self.reset_requested = true;
                return (cip.Reply{
                    .service = req.service,
                    .general_status = .success,
                    .additional_status = &.{},
                    .data = &.{},
                }).encode(out) catch error.BufferTooSmall;
            },
            cip.LogixService.read_tag => return self.readTag(req, false, out),
            cip.LogixService.read_tag_fragmented => return self.readTag(req, true, out),
            cip.LogixService.write_tag => return self.writeTag(req, false, out),
            cip.LogixService.write_tag_fragmented => return self.writeTag(req, true, out),
            else => return errorReply(req.service, .service_not_supported, out),
        }
    }

    fn connectionManager(self: *Adapter, req: cip.Request, out: []u8, depth: usize) Error![]const u8 {
        switch (req.service) {
            connmgr.Service.unconnected_send => {
                const us = connmgr.UnconnectedSend.decode(req.data) catch
                    return errorReply(req.service, .invalid_parameter_value, out);
                // The route is walked by a real gateway; a leaf device just
                // answers, which is what a simulator is.
                var scratch: [4096]u8 = undefined;
                const inner = try self.route(us.embedded, &scratch, depth + 1);
                if (out.len < inner.len) return error.BufferTooSmall;
                @memcpy(out[0..inner.len], inner);
                return out[0..inner.len];
            },
            connmgr.Service.forward_open, connmgr.Service.large_forward_open => {
                const large = req.service == connmgr.Service.large_forward_open;
                const fo = connmgr.ForwardOpen.decode(req.data, large) catch
                    return errorReply(req.service, .invalid_parameter_value, out);
                const slot = self.freeConnection() orelse
                    return extendedErrorReply(
                        req.service,
                        .connection_failure,
                        @intFromEnum(connmgr.ExtendedStatus.connection_limit_reached),
                        out,
                    );
                const o_t = self.next_connection_id;
                self.next_connection_id +%= 1;
                const t_o = self.next_connection_id;
                self.next_connection_id +%= 1;
                slot.* = .{
                    .in_use = true,
                    .o_to_t_id = o_t,
                    .t_to_o_id = t_o,
                    .serial = fo.connection_serial,
                    .vendor = fo.originator_vendor_id,
                    .originator_serial = fo.originator_serial,
                };
                var body: [64]u8 = undefined;
                const encoded = (connmgr.ForwardOpenReply{
                    .o_to_t_connection_id = o_t,
                    .t_to_o_connection_id = t_o,
                    .connection_serial = fo.connection_serial,
                    .originator_vendor_id = fo.originator_vendor_id,
                    .originator_serial = fo.originator_serial,
                    .o_to_t_api = fo.o_to_t_rpi,
                    .t_to_o_api = fo.t_to_o_rpi,
                    .application_reply = &.{},
                }).encode(&body) catch return error.BufferTooSmall;
                return (cip.Reply{
                    .service = req.service,
                    .general_status = .success,
                    .additional_status = &.{},
                    .data = encoded,
                }).encode(out) catch error.BufferTooSmall;
            },
            connmgr.Service.forward_close => {
                const fc = connmgr.ForwardClose.decode(req.data) catch
                    return errorReply(req.service, .invalid_parameter_value, out);
                var found = false;
                for (&self.connections) |*c| {
                    // Matched on the triple, not on a connection id — the
                    // close message does not carry one.
                    if (c.in_use and c.serial == fc.connection_serial and
                        c.vendor == fc.originator_vendor_id and
                        c.originator_serial == fc.originator_serial)
                    {
                        c.in_use = false;
                        found = true;
                    }
                }
                if (!found) {
                    return extendedErrorReply(
                        req.service,
                        .connection_failure,
                        @intFromEnum(connmgr.ExtendedStatus.connection_not_found),
                        out,
                    );
                }
                var body: [32]u8 = undefined;
                const encoded = (connmgr.ForwardCloseReply{
                    .connection_serial = fc.connection_serial,
                    .originator_vendor_id = fc.originator_vendor_id,
                    .originator_serial = fc.originator_serial,
                    .application_reply = &.{},
                }).encode(&body) catch return error.BufferTooSmall;
                return (cip.Reply{
                    .service = req.service,
                    .general_status = .success,
                    .additional_status = &.{},
                    .data = encoded,
                }).encode(out) catch error.BufferTooSmall;
            },
            else => return errorReply(req.service, .service_not_supported, out),
        }
    }

    fn freeConnection(self: *Adapter) ?*OpenConnection {
        for (&self.connections) |*c| if (!c.in_use) return c;
        return null;
    }

    fn multipleService(self: *Adapter, req: cip.Request, out: []u8, depth: usize) Error![]const u8 {
        const ms = cip.MultipleService.decode(req.data) catch
            return errorReply(req.service, .invalid_parameter_value, out);
        var replies: [16][]const u8 = undefined;
        var scratch: [4096]u8 = undefined;
        var used: usize = 0;
        const n = @min(ms.count, replies.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const embedded = ms.at(i) catch
                return errorReply(req.service, .invalid_parameter_value, out);
            const r = try self.route(embedded, scratch[used..], depth + 1);
            replies[i] = r;
            used += r.len;
        }
        var payload: [4096]u8 = undefined;
        const encoded = cip.MultipleService.encode(replies[0..n], &payload) catch
            return error.BufferTooSmall;
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = encoded,
        }).encode(out) catch error.BufferTooSmall;
    }

    fn getAttributesAll(
        self: *Adapter,
        req: cip.Request,
        class: ?u32,
        out: []u8,
    ) Error![]const u8 {
        if (class == null or class.? != @intFromEnum(cip.ClassCode.identity)) {
            return errorReply(req.service, .path_destination_unknown, out);
        }
        self.identity_requests += 1;
        if (self.cfg.product_name.len > 200) return error.BufferTooSmall;
        var body: [256]u8 = undefined;
        var off: usize = 0;
        std.mem.writeInt(u16, body[0..2], self.cfg.vendor_id, .little);
        std.mem.writeInt(u16, body[2..4], self.cfg.device_type, .little);
        std.mem.writeInt(u16, body[4..6], self.cfg.product_code, .little);
        body[6] = self.cfg.revision_major;
        body[7] = self.cfg.revision_minor;
        std.mem.writeInt(u16, body[8..10], self.cfg.identity_status, .little);
        std.mem.writeInt(u32, body[10..14], self.cfg.serial_number, .little);
        body[14] = @intCast(self.cfg.product_name.len);
        @memcpy(body[15..][0..self.cfg.product_name.len], self.cfg.product_name);
        off = 15 + self.cfg.product_name.len;
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = body[0..off],
        }).encode(out) catch error.BufferTooSmall;
    }

    fn getAttributeSingle(
        self: *Adapter,
        req: cip.Request,
        class: ?u32,
        out: []u8,
    ) Error![]const u8 {
        if (class == null or class.? != @intFromEnum(cip.ClassCode.identity)) {
            return errorReply(req.service, .path_destination_unknown, out);
        }
        const attr = (epath.findLogical(req.path, .attribute) catch null) orelse
            return errorReply(req.service, .path_segment_error, out);
        var body: [256]u8 = undefined;
        const value: []const u8 = switch (attr) {
            1 => blk: {
                std.mem.writeInt(u16, body[0..2], self.cfg.vendor_id, .little);
                break :blk body[0..2];
            },
            2 => blk: {
                std.mem.writeInt(u16, body[0..2], self.cfg.device_type, .little);
                break :blk body[0..2];
            },
            3 => blk: {
                std.mem.writeInt(u16, body[0..2], self.cfg.product_code, .little);
                break :blk body[0..2];
            },
            4 => blk: {
                body[0] = self.cfg.revision_major;
                body[1] = self.cfg.revision_minor;
                break :blk body[0..2];
            },
            5 => blk: {
                std.mem.writeInt(u16, body[0..2], self.cfg.identity_status, .little);
                break :blk body[0..2];
            },
            6 => blk: {
                std.mem.writeInt(u32, body[0..4], self.cfg.serial_number, .little);
                break :blk body[0..4];
            },
            7 => blk: {
                if (self.cfg.product_name.len > 200) return error.BufferTooSmall;
                body[0] = @intCast(self.cfg.product_name.len);
                @memcpy(body[1..][0..self.cfg.product_name.len], self.cfg.product_name);
                break :blk body[0 .. 1 + self.cfg.product_name.len];
            },
            8 => blk: {
                body[0] = @intFromEnum(self.cfg.state);
                break :blk body[0..1];
            },
            else => return errorReply(req.service, .attribute_not_supported, out),
        };
        self.identity_requests += 1;
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = value,
        }).encode(out) catch error.BufferTooSmall;
    }

    // ── tag services ───────────────────────────────────────────────────────

    fn findTag(self: *Adapter, path: []const u8) ?*const TagBinding {
        const name = (epath.findSymbol(path) catch null) orelse return null;
        for (self.tags) |*t| {
            if (std.mem.eql(u8, t.name, name)) return t;
        }
        return null;
    }

    /// The element index a path names, from its first member segment.
    fn pathElement(path: []const u8) usize {
        const v = (epath.findLogical(path, .member) catch null) orelse return 0;
        return v;
    }

    fn readTag(self: *Adapter, req: cip.Request, fragmented: bool, out: []u8) Error![]const u8 {
        const tag = self.findTag(req.path) orelse
            return errorReply(req.service, .path_destination_unknown, out);
        var count: usize = 1;
        var byte_offset: usize = 0;
        if (fragmented) {
            const r = types.ReadTagFragmentedRequest.decode(req.data) catch
                return errorReply(req.service, .not_enough_data, out);
            count = r.count;
            byte_offset = r.byte_offset;
        } else {
            const r = types.ReadTagRequest.decode(req.data) catch
                return errorReply(req.service, .not_enough_data, out);
            count = r.count;
        }

        const esize = tag.elementSize();
        const start_element = pathElement(req.path);
        const start = start_element * esize + byte_offset;
        if (start > tag.bytes.len) return errorReply(req.service, .invalid_parameter_value, out);
        const want = @min(count * esize, tag.bytes.len - start);
        // The reply must fit both the caller's buffer and the configured
        // ceiling; whatever does not fit comes back as a partial transfer,
        // which is exactly what the fragmented service is for.
        const room = @min(self.cfg.max_reply, out.len) -| 8;
        const give = @min(want, room);
        const partial = give < want;

        var body: [4096]u8 = undefined;
        const td = types.TagData{ .type = tag.type, .data = tag.bytes[start..][0..give] };
        const encoded = td.encode(&body) catch return error.BufferTooSmall;
        self.reads += 1;
        return (cip.Reply{
            .service = req.service,
            .general_status = if (partial) .partial_transfer else .success,
            .additional_status = &.{},
            .data = encoded,
        }).encode(out) catch error.BufferTooSmall;
    }

    fn writeTag(self: *Adapter, req: cip.Request, fragmented: bool, out: []u8) Error![]const u8 {
        const tag = self.findTag(req.path) orelse
            return errorReply(req.service, .path_destination_unknown, out);
        var value_type: types.DataType = undefined;
        var values: []const u8 = undefined;
        var byte_offset: usize = 0;
        if (fragmented) {
            const w = types.WriteTagFragmentedRequest.decode(req.data) catch
                return errorReply(req.service, .not_enough_data, out);
            value_type = w.type;
            values = w.values;
            byte_offset = w.byte_offset;
        } else {
            const w = types.WriteTagRequest.decode(req.data) catch
                return errorReply(req.service, .not_enough_data, out);
            value_type = w.type;
            values = w.values;
        }
        // A write of the wrong type is refused rather than reinterpreted.
        if (value_type != tag.type) {
            return errorReply(req.service, .invalid_attribute_value, out);
        }
        const esize = tag.elementSize();
        const start = pathElement(req.path) * esize + byte_offset;
        if (start + values.len > tag.bytes.len) {
            return errorReply(req.service, .too_much_data, out);
        }
        @memcpy(tag.bytes[start..][0..values.len], values);
        self.writes += 1;
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = &.{},
        }).encode(out) catch error.BufferTooSmall;
    }
};

fn errorReply(service: u8, status: cip.GeneralStatus, out: []u8) Error![]const u8 {
    return (cip.Reply{
        .service = service,
        .general_status = status,
        .additional_status = &.{},
        .data = &.{},
    }).encode(out) catch error.BufferTooSmall;
}

fn extendedErrorReply(
    service: u8,
    status: cip.GeneralStatus,
    extended: u16,
    out: []u8,
) Error![]const u8 {
    var extra: [2]u8 = undefined;
    std.mem.writeInt(u16, &extra, extended, .little);
    return (cip.Reply{
        .service = service,
        .general_status = status,
        .additional_status = &extra,
        .data = &.{},
    }).encode(out) catch error.BufferTooSmall;
}

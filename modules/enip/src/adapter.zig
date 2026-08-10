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
//!   `Write Tag Fragmented` against bound tags;
//! * enough **discovery** for a browsing tool to find those tags without
//!   being told them: the Program Name object (class 0x64) and the Symbol
//!   Object's `Get_Instance_Attribute_List` (class 0x6B, service 0x55). See
//!   "What discovery covers" below for where that stops.
//!
//! It is a **simulator, not a controller**: it runs no program, enforces no
//! access control and implements no CIP Security. Do not put one where
//! something might mistake it for real equipment.
//!
//! ## What discovery covers, and what it deliberately does not
//!
//! The goal is a narrow one: a stock Logix driver should be able to open a
//! session and upload a tag list, so that the tags this adapter serves are
//! *discoverable* rather than having to be configured into the client. It is
//! **not** an attempt to model a ControlLogix controller's object graph.
//!
//! Implemented:
//!
//! * class 0x64 instance 1, `Get_Attributes_All` → the program name as a
//!   `STRING` (16-bit length prefix);
//! * class 0x6B, `Get_Instance_Attribute_List` → one record per enumerable
//!   binding, with attributes 1 (name), 2 (symbol type), 3 (symbol address),
//!   5 (symbol object address), 6 (software control), 8 (array dimensions)
//!   and 10 (external access), returned in the order the request asked for
//!   them, resuming across replies through `partial_transfer` when the whole
//!   list does not fit one message.
//!
//! Deliberately absent, because a simulator that pretends otherwise is worse
//! than one with an honest edge:
//!
//! * the **Template Object** (class 0x6C) and therefore user-defined types —
//!   `TagBinding.isEnumerable` explains why struct-typed bindings are left
//!   out of the list rather than advertised and then unexplainable;
//! * **program-scoped tags**: there are no `Program:` symbols, so a tool that
//!   asks for a program's scope gets an empty list, and the Program Name
//!   object names one program that owns nothing;
//! * everything else on the Symbol Object — no other attribute, no other
//!   service, no writes to it, and no way to create or delete a symbol.
//!
//! Symbol **instance addressing** (`20 6B 24 <id>` in place of a symbolic
//! path) is *not* on that list: `findTag` accepts it, because the tag list
//! hands the ids out and a client switches to them unprompted once the
//! reported major revision is high enough.

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

    /// Whether this binding appears in the Symbol Object tag list a browsing
    /// tool uploads (class 0x6B, `Get_Instance_Attribute_List`).
    ///
    /// Only types with a **known fixed element size** are enumerated, because
    /// only for those is the element count recoverable from `bytes.len` — the
    /// adapter stores octets and nothing else. That excludes the structured
    /// codes (`structure`, `abbreviated_structure`), and excluding them is
    /// deliberate rather than incidental: advertising a struct-typed symbol
    /// promises a Template Object (class 0x6C) describing its members, and
    /// this adapter does not implement one. It also excludes the strings and
    /// `date_and_time`, whose width `DataType.elementSize` refuses to guess.
    ///
    /// A non-enumerable binding is still fully readable and writable **by
    /// name** — it is invisible to discovery, not absent from the device.
    pub fn isEnumerable(self: TagBinding) bool {
        return self.type.elementSize() != null;
    }

    /// Array dimensions this binding advertises: 0 (a scalar) or 1.
    ///
    /// A one-element binding is advertised as a **scalar**, because nothing in
    /// `TagBinding` distinguishes `DINT` from `DINT[1]` — the two are the same
    /// four octets. Multi-dimensional arrays are likewise beyond what this
    /// model can express; a Logix `DINT[2,3]` would be advertised flat, as
    /// `DINT[6]`.
    pub fn dimensionCount(self: TagBinding) u2 {
        return if (self.elementCount() > 1) 1 else 0;
    }

    /// The Symbol Object's attribute 2, the `symbol_type` word: the atomic
    /// type code in the low octet, the number of array dimensions in bits
    /// 13-14. Bit 15 (structure) and bit 12 (system tag) are always clear
    /// here — see `isEnumerable` for why there is no structure case.
    pub fn symbolType(self: TagBinding) u16 {
        const code: u16 = @truncate(@intFromEnum(self.type));
        return (code & 0x00FF) | (@as(u16, self.dimensionCount()) << 13);
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
    /// What the **Program Name** object (class 0x64, instance 1) reports —
    /// the name of the running program, which is the first thing a Logix tool
    /// asks for after the Identity object and the thing whose absence stops
    /// `open()` dead.
    ///
    /// Set it empty to withhold the object entirely: the class then answers
    /// `path_destination_unknown`, which is what a device that has no Program
    /// Name object genuinely says.
    program_name: []const u8 = "zig-enip",
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
            // Guarded on the class for the same reason `connmgr`'s services
            // are: 0x55 means `Get_Instance_Attribute_List` only because the
            // path said Symbol Object. On any other class it is unclaimed.
            cip.LogixService.get_instance_attribute_list => {
                if (class != null and class.? == @intFromEnum(cip.ClassCode.symbol)) {
                    return self.symbolInstanceList(req, out);
                }
                return errorReply(req.service, .service_not_supported, out);
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

    /// The number of embedded requests one `Multiple_Service_Packet` can
    /// batch. Fixed so the reply table (`replies` below) stays a bounded
    /// stack array rather than an unbounded allocation; a batch larger than
    /// this is refused outright (see `multipleService`), never silently cut
    /// down to this many.
    pub const max_batch: usize = 16;

    fn multipleService(self: *Adapter, req: cip.Request, out: []u8, depth: usize) Error![]const u8 {
        const ms = cip.MultipleService.decode(req.data) catch
            return errorReply(req.service, .invalid_parameter_value, out);
        // A batch that does not fit the reply table must be reported as an
        // error, not silently truncated: a truncated-but-`success` reply
        // makes a dropped embedded request (e.g. a write) invisible to the
        // caller. `too_much_data` is this module's own convention for "more
        // was supplied than this operation can hold" — see `writeTag`'s use
        // of the same status when a write overruns its tag's storage.
        if (ms.count > max_batch) return errorReply(req.service, .too_much_data, out);
        var replies: [max_batch][]const u8 = undefined;
        var scratch: [4096]u8 = undefined;
        var used: usize = 0;
        var i: usize = 0;
        while (i < ms.count) : (i += 1) {
            const embedded = ms.at(i) catch
                return errorReply(req.service, .invalid_parameter_value, out);
            const r = try self.route(embedded, scratch[used..], depth + 1);
            replies[i] = r;
            used += r.len;
        }
        var payload: [4096]u8 = undefined;
        const encoded = cip.MultipleService.encode(replies[0..ms.count], &payload) catch
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
        if (class != null and class.? == @intFromEnum(cip.ClassCode.program_name)) {
            return self.programName(req, out);
        }
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

    // ── discovery ──────────────────────────────────────────────────────────

    /// The Program Name object (class 0x64, instance 1): one `STRING`.
    ///
    /// Vendor-specific and absent from ODVA's object library; Rockwell KB
    /// 23341 is the only published description of it. What a Logix tool
    /// actually does is `Get_Attributes_All` on instance 1 and decode the
    /// whole reply body as a `STRING`, so that is what is served — a single
    /// attribute, not a modelled object with an attribute table.
    fn programName(self: *Adapter, req: cip.Request, out: []u8) Error![]const u8 {
        if (self.cfg.program_name.len == 0) {
            return errorReply(req.service, .path_destination_unknown, out);
        }
        // Instance 1 is the running program; there is no other. An instance
        // that does not exist is exactly what status 0x05 reports, and it is
        // the same answer this class gave for everything before it existed.
        const instance = (epath.findLogical(req.path, .instance) catch null) orelse 0;
        if (instance != 1) return errorReply(req.service, .path_destination_unknown, out);

        var body: [258]u8 = undefined;
        if (self.cfg.program_name.len > body.len - 2) return error.BufferTooSmall;
        std.mem.writeInt(u16, body[0..2], @intCast(self.cfg.program_name.len), .little);
        @memcpy(body[2..][0..self.cfg.program_name.len], self.cfg.program_name);
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = body[0 .. 2 + self.cfg.program_name.len],
        }).encode(out) catch error.BufferTooSmall;
    }

    /// Bit 26 of the Symbol Object's `software_control` word: Logix's "this is
    /// a base tag" flag. A client that does not see it reads the symbol as an
    /// **alias** for another one, which none of these bindings are.
    pub const base_tag_bit: u32 = 1 << 26;

    /// Attribute 10, external access. 0 is read/write, which is what every
    /// binding here is — this adapter has no access control to report.
    const external_access_read_write: u8 = 0;

    fn symbolAttributeSupported(attr: u16) bool {
        return switch (attr) {
            1, 2, 3, 5, 6, 8, 10 => true,
            else => false,
        };
    }

    fn writeSymbolAttribute(tag: TagBinding, attr: u16, out: []u8) error{NoRoom}!usize {
        switch (attr) {
            // 1: symbol name, a `STRING` — 16-bit length, then the octets,
            // with no padding to an even boundary.
            1 => {
                if (tag.name.len > 0xFFFF) return error.NoRoom;
                const n = 2 + tag.name.len;
                if (out.len < n) return error.NoRoom;
                std.mem.writeInt(u16, out[0..2], @intCast(tag.name.len), .little);
                @memcpy(out[2..][0..tag.name.len], tag.name);
                return n;
            },
            // 2: the symbol type word.
            2 => {
                if (out.len < 2) return error.NoRoom;
                std.mem.writeInt(u16, out[0..2], tag.symbolType(), .little);
                return 2;
            },
            // 3 and 5: where the tag's data and its descriptor sit in
            // controller memory. This adapter has no controller memory to
            // describe, and a client does nothing with the value but carry it.
            3, 5 => {
                if (out.len < 4) return error.NoRoom;
                std.mem.writeInt(u32, out[0..4], 0, .little);
                return 4;
            },
            6 => {
                if (out.len < 4) return error.NoRoom;
                std.mem.writeInt(u32, out[0..4], base_tag_bit, .little);
                return 4;
            },
            // 8: the three array dimensions. Only the first is ever non-zero
            // here — see `TagBinding.dimensionCount`.
            8 => {
                if (out.len < 12) return error.NoRoom;
                const elems: u32 = @intCast(@min(tag.elementCount(), @as(usize, std.math.maxInt(u32))));
                const dims = [3]u32{ if (tag.dimensionCount() > 0) elems else 0, 0, 0 };
                for (dims, 0..) |d, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], d, .little);
                return 12;
            },
            10 => {
                if (out.len < 1) return error.NoRoom;
                out[0] = external_access_read_write;
                return 1;
            },
            else => unreachable, // rejected by `symbolAttributeSupported`
        }
    }

    fn writeSymbolRecord(id: u32, tag: TagBinding, attrs: []const u8, out: []u8) error{NoRoom}!usize {
        if (out.len < 4) return error.NoRoom;
        std.mem.writeInt(u32, out[0..4], id, .little);
        var n: usize = 4;
        var i: usize = 0;
        while (i + 2 <= attrs.len) : (i += 2) {
            const attr = std.mem.readInt(u16, attrs[i..][0..2], .little);
            n += try writeSymbolAttribute(tag, attr, out[n..]);
        }
        return n;
    }

    /// `Get_Instance_Attribute_List` (0x55) on the Symbol Object (0x6B): the
    /// tag-list upload a browsing tool performs, and the reason it does not
    /// have to be told what this device serves.
    ///
    /// The instance id in the request path is a **resume point**, not an
    /// object being addressed. The reply carries every enumerable binding at
    /// or above it, ascending, each as its instance id followed by the
    /// requested attributes *in the order they were requested*; it ends with
    /// `partial_transfer` if it stopped early, whereupon the client asks again
    /// starting one past the last id it decoded. That continuation is the
    /// whole of the protocol — a device that answered only the first page and
    /// said `success` would silently hide every tag after it.
    ///
    /// Instance ids are one-based positions in the binding table, so they are
    /// ascending by construction and stable for as long as the table is.
    fn symbolInstanceList(self: *Adapter, req: cip.Request, out: []u8) Error![]const u8 {
        if (req.data.len < 2) return errorReply(req.service, .not_enough_data, out);
        const attr_count = std.mem.readInt(u16, req.data[0..2], .little);
        const attrs_len = @as(usize, attr_count) * 2;
        if (req.data.len < 2 + attrs_len) return errorReply(req.service, .not_enough_data, out);
        const attrs = req.data[2..][0..attrs_len];

        // The whole list is checked before a single record is built: an
        // unsupported attribute has to be refused outright, not after a prefix
        // of the reply has been encoded around it.
        var i: usize = 0;
        while (i < attrs_len) : (i += 2) {
            if (!symbolAttributeSupported(std.mem.readInt(u16, attrs[i..][0..2], .little))) {
                return errorReply(req.service, .attribute_not_supported, out);
            }
        }

        const start = (epath.findLogical(req.path, .instance) catch null) orelse 0;
        var body: [3072]u8 = undefined;
        const room = @min(@min(self.cfg.max_reply, out.len) -| 8, body.len);
        var used: usize = 0;
        var emitted: usize = 0;
        var truncated = false;
        for (self.tags, 1..) |tag, id| {
            if (id < start) continue;
            if (!tag.isEnumerable()) continue;
            const n = writeSymbolRecord(@intCast(id), tag, attrs, body[used..room]) catch {
                truncated = true;
                break;
            };
            used += n;
            emitted += 1;
        }
        // One record too large for an empty reply would otherwise make the
        // client resume forever at the same instance.
        if (truncated and emitted == 0) {
            return errorReply(req.service, .reply_data_too_large, out);
        }
        return (cip.Reply{
            .service = req.service,
            .general_status = if (truncated) .partial_transfer else .success,
            .additional_status = &.{},
            .data = body[0..used],
        }).encode(out) catch error.BufferTooSmall;
    }

    // ── tag services ───────────────────────────────────────────────────────

    /// The binding a request path names, addressed either way a Logix client
    /// addresses one:
    ///
    /// * **symbolically** — `91 <len> "Name"`, what a client uses by default;
    /// * by **symbol instance id** — `20 6B 24 <id>`, the v21+ optimisation a
    ///   client switches to on its own once the reported major revision is
    ///   high enough, using the ids the tag list handed out.
    ///
    /// Both are supported because this adapter enumerates instance ids, and a
    /// device that enumerates them and then refuses them as addresses is one
    /// that browses and cannot be read — strictly worse than one that never
    /// enumerated. Measured, not assumed: a client told the revision is 21
    /// sends no symbolic path at all.
    fn findTag(self: *Adapter, path: []const u8) ?*const TagBinding {
        if (epath.findSymbol(path) catch null) |name| {
            for (self.tags) |*t| {
                if (std.mem.eql(u8, t.name, name)) return t;
            }
            return null;
        }
        const class = (epath.findLogical(path, .class) catch null) orelse return null;
        if (class != @intFromEnum(cip.ClassCode.symbol)) return null;
        const id = (epath.findLogical(path, .instance) catch null) orelse return null;
        return self.tagByInstance(id);
    }

    /// The binding a Symbol Object instance id names: a one-based position in
    /// the binding table.
    ///
    /// Counted over the whole table rather than over the enumerable bindings
    /// only, so that an id keeps naming the same binding when a neighbour's
    /// type changes. A binding the tag list does not advertise has no id to be
    /// named by, and is refused here rather than reachable by guessing.
    fn tagByInstance(self: *Adapter, id: u32) ?*const TagBinding {
        if (id == 0 or id > self.tags.len) return null;
        const t = &self.tags[id - 1];
        return if (t.isEnumerable()) t else null;
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

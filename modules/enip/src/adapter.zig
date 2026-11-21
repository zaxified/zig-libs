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
//! * **implicit I/O** (transport class 0/1 `Forward_Open` over `Config.assemblies`,
//!   `ioReceive` / `ioPoll`, over the `implicit` engine);
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
//! * class 0x6C, the **Template Object**, for the user-defined types of
//!   `Config.udts`: `Get_Attribute_List` (attributes 1, 2, 4, 5) and the
//!   template read, so a structure tag reads as named members.
//!
//! Deliberately absent, because a simulator that pretends otherwise is worse
//! than one with an honest edge:
//!
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
const stdobj = @import("stdobj.zig");
const implicit = @import("implicit.zig");

pub const Error = error{
    /// The request could not be parsed far enough to answer it at all.
    Malformed,
    /// The output buffer cannot hold the reply.
    BufferTooSmall,
};

/// One member of a user-defined type (a Template Object member, 8 octets on
/// the wire: info, type word, offset).
pub const UdtMember = struct {
    name: []const u8,
    /// The member's atomic type, or `.structure` for a nested UDT (then `udt`
    /// is set). Strings and bit members are not modelled: give them as the
    /// `sint`/`dint` host they sit in.
    type: types.DataType,
    /// For `.structure`: the nested UDT (its template instance id goes into
    /// the type word).
    udt: ?*const Udt = null,
    /// 0 for a scalar, else the array length.
    array_len: u16 = 0,
    /// Offset of the member in the structure, in octets.
    offset: u32,
};

/// A user-defined type, served by the Template Object (class 0x6C). `id` is
/// the template instance number (1..4095, what the symbol type word carries
/// in its low 12 bits); `handle` the structure handle a Read Tag of a tag of
/// this type reports (a CRC of the definition on a real controller).
pub const Udt = struct {
    id: u16,
    name: []const u8,
    handle: u16,
    /// Size of one value in octets.
    size: u32,
    members: []const UdtMember,
};

/// One tag this adapter serves.
pub const TagBinding = struct {
    name: []const u8,
    type: types.DataType,
    /// The tag's octets. Element count is `bytes.len / type.elementSize()`.
    bytes: []u8,
    /// The tag's user-defined type, for `type == .structure`: the tag is then
    /// listed with the structure bit and the template id, and a Read Tag
    /// carries the handle. The `Udt` must also be in `Config.udts`.
    udt: ?*const Udt = null,

    pub fn elementSize(self: TagBinding) usize {
        if (self.udt) |u| return @max(1, u.size);
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
    /// adapter stores octets and nothing else. A structure is known by its
    /// `udt` (its size is the type's, and the Template Object describes its
    /// members); one without a `udt` is left out, because advertising a
    /// struct-typed symbol promises that description. The strings and
    /// `date_and_time` are excluded too, their width `DataType.elementSize`
    /// refuses to guess.
    ///
    /// A non-enumerable binding is still fully readable and writable **by
    /// name** — it is invisible to discovery, not absent from the device.
    pub fn isEnumerable(self: TagBinding) bool {
        return self.udt != null or self.type.elementSize() != null;
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
    /// 13-14. A structure sets bit 15 and carries its template id in the low
    /// 12 bits; bit 12 (system tag) is always clear.
    pub fn symbolType(self: TagBinding) u16 {
        const dims = @as(u16, self.dimensionCount()) << 13;
        if (self.udt) |u| return 0x8000 | (u.id & 0x0FFF) | dims;
        const code: u16 = @truncate(@backingInt(self.type));
        return (code & 0x00FF) | dims;
    }
};

pub const Config = struct {
    vendor_id: u16 = 0x1234,
    device_type: u16 = @backingInt(encap.DeviceType.programmable_logic_controller),
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
    /// What the **TCP/IP Interface** object (class 0xF5, instance 1) reports.
    /// Served by default (the values are the caller's, nothing is read from
    /// the OS); `null` withholds the object, which then answers
    /// `path_destination_unknown` like a device that has none.
    tcpip: ?stdobj.TcpIpConfig = .{},
    /// `Set_Attribute_Single` on the TCP/IP Interface object (attributes 3, 5
    /// and 6: configuration control, interface configuration, host name)
    /// changes what the adapter reports afterwards. Off by default: the
    /// attributes are then refused `attribute_not_settable`, as on a device
    /// whose network settings are fixed. The adapter only *records* the
    /// values; applying them is the caller's business.
    allow_tcpip_set: bool = false,
    /// What the **Ethernet Link** object (class 0xF6, instance 1) reports
    /// (speed, flags, MAC address). Served by default; `null` withholds it.
    /// It is read-only: `Set_Attribute_Single` on it is `service_not_supported`.
    ethernet_link: ?stdobj.EthLinkConfig = .{},
    /// The user-defined types the **Template Object** (class 0x6C) serves,
    /// one instance each (`Udt.id`): `Get_Attribute_List` of attributes 1, 2,
    /// 4 and 5 and `Read Tag` of the member definitions, which is how a
    /// Logix driver turns a structure read into named members. Empty
    /// withholds the class.
    udts: []const Udt = &.{},
    /// The **Assembly** object (class 0x04): the instances a scanner reads
    /// (and, where `writable`, writes) as raw octets. Empty by default, which
    /// withholds the class (`path_destination_unknown`); with at least one
    /// entry the class answers `Get_Attribute_Single` / `Set_Attribute_Single`
    /// on attributes 3 (data) and 4 (size) and on its class attributes. The
    /// buffers are the caller's and stay owned by it.
    assemblies: []const stdobj.Assembly = &.{},
    /// What `ListIdentity` reports as its own socket address.
    socket_address: encap.SocketAddress = .{
        .port = encap.default_tcp_port,
        .addr = .{ 0, 0, 0, 0 },
    },
    /// Largest CIP reply this adapter will build.
    max_reply: usize = 4000,
    /// `Reset` reboots a real device. Refused unless this is set.
    allow_reset: bool = false,
    /// The group addresses given to a `Forward_Open` whose target-to-originator
    /// connection is **multicast** (the TCP/IP Interface object's
    /// `Num_Mcast` / `Mcast_Start_Addr`), handed out round-robin.
    io_multicast: implicit.MulticastPool = .{},
};

/// One datagram `ioPoll` has for the network.
pub const IoDatagram = struct {
    /// Where to send it. `null`: to the originator's host (the peer of the
    /// TCP session that opened the connection, which only the caller knows),
    /// UDP port 2222.
    to: ?encap.SocketAddress,
    /// Sent to a multicast group (`to` is that group).
    multicast: bool,
    bytes: []const u8,
};

/// What `ioReceive` did with a datagram.
pub const IoReceived = union(enum) {
    /// Not for any open I/O connection (or not an I/O datagram).
    unknown_connection,
    /// New data was written into the consuming assembly.
    applied: struct { connection_id: u32, missed: u32 },
    /// New data under an **Idle** header: the assembly was left alone.
    idle: struct { connection_id: u32 },
    /// The same data again; the watchdog was restarted.
    heartbeat: struct { connection_id: u32 },
    /// Refused by the connection (stale, malformed, closed) or by the size
    /// check (`wrong_size`).
    dropped: struct { connection_id: u32, reason: enum { stale, malformed, closed, wrong_size } },
};

/// An open Class 3 connection.
const OpenConnection = struct {
    in_use: bool = false,
    o_to_t_id: u32 = 0,
    t_to_o_id: u32 = 0,
    serial: u16 = 0,
    vendor: u16 = 0,
    originator_serial: u32 = 0,
    /// The implicit (Class 0/1) engine, when this connection carries I/O.
    io: ?implicit.Connection = null,
    /// The assemblies the I/O connection consumes (O→T) and produces (T→O).
    consume_asm: ?u16 = null,
    produce_asm: ?u16 = null,
    /// An Idle header, or the size, is checked against these.
    consume_len: usize = 0,
    produce_len: usize = 0,
    /// The T→O destination the originator asked for, or the multicast group.
    dest: ?encap.SocketAddress = null,
    multicast: bool = false,
    /// A hash of the last data produced, for change-of-state triggers.
    last_hash: u64 = 0,
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
    /// What `Set_Attribute_Single` changed on the TCP/IP Interface object.
    tcpip_state: stdobj.TcpIpState = .{},
    /// Implicit I/O counters: datagrams consumed and produced, connections
    /// closed by their watchdog.
    io_consumed: u64 = 0,
    io_produced: u64 = 0,
    io_timeouts: u64 = 0,
    io_multicast: implicit.MulticastPool,
    /// The Sockaddr Info (T→O) item of the `SendRRData` being served, and the
    /// one its reply must carry.
    rr_t_to_o: ?encap.SocketAddress = null,
    rr_reply_sockaddr: ?encap.SocketAddress = null,
    /// The time the engines were last told, so that a connection opened by
    /// `Forward_Open` starts its watchdog and its first production from it.
    /// `ioReceive` and `ioPoll` keep it current; before the first call it is
    /// 0, which is only right when the caller's clock starts there.
    io_now_us: u64 = 0,

    pub fn init(cfg: Config, tags: []const TagBinding) Adapter {
        return .{ .cfg = cfg, .tags = tags, .io_multicast = cfg.io_multicast };
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
            // An I/O connection speaks UDP 2222, not SendUnitData.
            if (conn.io != null) return error.Malformed;
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

        self.rr_t_to_o = null;
        if (env.list.find(.sockaddr_info_t_to_o)) |it| self.rr_t_to_o = cpf.socketAddress(it) catch null;
        self.rr_reply_sockaddr = null;
        const reply = try self.messageRouter(data_item.data, &scratch);
        const base = cpf.unconnectedItems(reply);
        if (self.rr_reply_sockaddr) |sa| {
            var sa_buf: [encap.SocketAddress.encoded_len]u8 = undefined;
            const sa_bytes = sa.encode(&sa_buf) catch return error.BufferTooSmall;
            const items = [_]cpf.Item{ base[0], base[1], .{ .type_id = .sockaddr_info_t_to_o, .data = sa_bytes } };
            return cpf.encodeEnvelope(cpf.cip_interface_handle, env.timeout, &items, out) catch
                error.BufferTooSmall;
        }
        return cpf.encodeEnvelope(cpf.cip_interface_handle, env.timeout, &base, out) catch
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
            @backingInt(cip.Service.multiple_service_packet) => return self.multipleService(req, out, depth),
            @backingInt(cip.Service.get_attributes_all) => return self.getAttributesAll(req, class, out),
            @backingInt(cip.Service.get_attribute_list) => {
                if (class != null and class.? == @backingInt(cip.ClassCode.template)) {
                    return self.templateAttributeList(req, out);
                }
                return errorReply(req.service, .service_not_supported, out);
            },
            @backingInt(cip.Service.get_attribute_single) => return self.getAttributeSingle(req, class, out),
            @backingInt(cip.Service.set_attribute_single) => {
                if (class != null and class.? == @backingInt(cip.ClassCode.tcp_ip_interface)) {
                    return self.tcpipSet(req, out);
                }
                if (class != null and class.? == @backingInt(cip.ClassCode.assembly) and
                    self.cfg.assemblies.len != 0)
                {
                    return self.assemblySetAttr(req, out);
                }
                return errorReply(req.service, .service_not_supported, out);
            },
            @backingInt(cip.Service.reset) => {
                if (!self.cfg.allow_reset) return errorReply(req.service, .privilege_violation, out);
                if (out.len < 4) return error.BufferTooSmall;
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
                if (class != null and class.? == @backingInt(cip.ClassCode.symbol)) {
                    return self.symbolInstanceList(req, out);
                }
                return errorReply(req.service, .service_not_supported, out);
            },
            // 0x4C is Read Tag on a symbol and Read Template on the Template
            // Object: the class in the path decides.
            cip.LogixService.read_tag => {
                if (class != null and class.? == @backingInt(cip.ClassCode.template)) {
                    return self.templateRead(req, out);
                }
                return self.readTag(req, false, out);
            },
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
                // answers, which is what a simulator is. The inner reply is
                // built straight into `out` (the request lives elsewhere, so
                // nothing overlaps). A private 4096-octet scratch used to size
                // it to itself rather than to the room the caller has, which
                // inside a `Multiple_Service_Packet` turned a read that could
                // have come back `partial_transfer` into
                // `error.BufferTooSmall` (review 2026-10-06).
                return self.route(us.embedded, out, depth + 1);
            },
            connmgr.Service.forward_open, connmgr.Service.large_forward_open => {
                const large = req.service == connmgr.Service.large_forward_open;
                const fo = connmgr.ForwardOpen.decode(req.data, large) catch
                    return errorReply(req.service, .invalid_parameter_value, out);
                // Room for the reply is checked before a slot is taken, so a
                // reply that cannot be built leaves no connection behind.
                if (out.len < 4 + connmgr.ForwardOpenReply.fixed_len) return error.BufferTooSmall;
                // Transport class 0 and 1 carry implicit I/O over UDP.
                if (fo.transport_class.class <= 1) return self.openIo(req.service, fo, out);
                const slot = self.freeConnection() orelse
                    return extendedErrorReply(
                        req.service,
                        .connection_failure,
                        @backingInt(connmgr.ExtendedStatus.connection_limit_reached),
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
                // As for Forward_Open: no state change without room to say so.
                if (out.len < 4 + connmgr.ForwardCloseReply.fixed_len) return error.BufferTooSmall;
                var found = false;
                for (&self.connections) |*c| {
                    // Matched on the triple, not on a connection id — the
                    // close message does not carry one.
                    if (c.in_use and c.serial == fc.connection_serial and
                        c.vendor == fc.originator_vendor_id and
                        c.originator_serial == fc.originator_serial)
                    {
                        c.in_use = false;
                        c.io = null;
                        found = true;
                    }
                }
                if (!found) {
                    return extendedErrorReply(
                        req.service,
                        .connection_failure,
                        @backingInt(connmgr.ExtendedStatus.connection_not_found),
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

    // ── implicit (Class 0/1) I/O ───────────────────────────────────────────

    fn ioRefusal(service: u8, status: connmgr.ExtendedStatus, out: []u8) Error![]const u8 {
        return extendedErrorReply(service, .connection_failure, @backingInt(status), out);
    }

    /// The octets a consumed or produced packet carries around an assembly's
    /// data for a connection of this class: the 16-bit count of Class 1 and,
    /// when `header`, the 32-bit Run/Idle header.
    fn ioOverhead(class: implicit.TransportClass, header: bool) usize {
        return (if (class == .class1) @as(usize, 2) else 0) + (if (header) @as(usize, 4) else 0);
    }

    /// A `Forward_Open` of transport class 0 or 1 (clause 3-5 of Vol 1): the
    /// connection path names a configuration assembly and the connection
    /// points this end consumes (the first) and produces (the second); a
    /// single connection point serves the one direction the parameters leave
    /// non-null. The sizes must be an assembly's size plus the count and the
    /// optional header, and say whether the header is there.
    fn openIo(self: *Adapter, svc: u8, fo: connmgr.ForwardOpen, out: []u8) Error![]const u8 {
        const tc = fo.transport_class;
        if (tc.class > 1 or tc.trigger > 2) return ioRefusal(svc, .transport_class_trigger_not_supported, out);
        const class: implicit.TransportClass = if (tc.class == 1) .class1 else .class0;
        const trigger: implicit.Trigger = @fromBackingInt(tc.trigger);
        if (fo.o_to_t_rpi == 0 or fo.t_to_o_rpi == 0) return ioRefusal(svc, .rpi_not_supported, out);
        const o_null = fo.o_to_t_params.connection_type == .null_connection;
        const t_null = fo.t_to_o_params.connection_type == .null_connection;
        if (o_null and t_null) return ioRefusal(svc, .invalid_connection_type, out);
        if (fo.o_to_t_params.connection_type == .reserved or fo.t_to_o_params.connection_type == .reserved)
            return ioRefusal(svc, .invalid_connection_type, out);

        // The path: class 0x04, then instance (configuration) and the
        // connection points, in order.
        var points: [2]u32 = undefined;
        var npoints: usize = 0;
        var saw_class = false;
        var it = epath.Iterator.init(fo.connection_path);
        while (it.next() catch return ioRefusal(svc, .invalid_segment_in_connection_path, out)) |seg| switch (seg) {
            .logical => |l| switch (l.what) {
                .class => saw_class = l.value == @backingInt(cip.ClassCode.assembly),
                .connection_point => {
                    if (npoints == points.len) return ioRefusal(svc, .invalid_produced_or_consumed_path, out);
                    points[npoints] = l.value;
                    npoints += 1;
                },
                else => {},
            },
            else => {},
        };
        if (!saw_class or npoints == 0) return ioRefusal(svc, .invalid_produced_or_consumed_path, out);
        var consume: ?u16 = null;
        var produce: ?u16 = null;
        if (npoints == 2) {
            if (!o_null) consume = @intCast(@min(points[0], 0xFFFF));
            if (!t_null) produce = @intCast(@min(points[1], 0xFFFF));
        } else if (o_null) {
            produce = @intCast(@min(points[0], 0xFFFF));
        } else if (t_null) {
            consume = @intCast(@min(points[0], 0xFFFF));
        } else {
            return ioRefusal(svc, .invalid_produced_or_consumed_path, out);
        }
        var consume_len: usize = 0;
        var produce_len: usize = 0;
        var consume_header = false;
        var produce_header = false;
        if (consume) |id| {
            const a = stdobj.assemblyFind(self.cfg.assemblies, id) orelse
                return ioRefusal(svc, .invalid_produced_or_consumed_path, out);
            if (!a.writable) return ioRefusal(svc, .invalid_produced_or_consumed_path, out);
            consume_len = a.data.len;
            const size: usize = fo.o_to_t_params.size;
            if (size == consume_len + ioOverhead(class, false)) {
                consume_header = false;
            } else if (size == consume_len + ioOverhead(class, true)) {
                consume_header = true;
            } else {
                return ioRefusal(svc, .invalid_connection_size, out);
            }
        }
        if (produce) |id| {
            const a = stdobj.assemblyFind(self.cfg.assemblies, id) orelse
                return ioRefusal(svc, .invalid_produced_or_consumed_path, out);
            produce_len = a.data.len;
            const size: usize = fo.t_to_o_params.size;
            if (size == produce_len + ioOverhead(class, false)) {
                produce_header = false;
            } else if (size == produce_len + ioOverhead(class, true)) {
                produce_header = true;
            } else {
                return ioRefusal(svc, .invalid_connection_size, out);
            }
        }
        const slot = self.freeConnection() orelse return ioRefusal(svc, .connection_limit_reached, out);

        const o_t = self.next_connection_id;
        self.next_connection_id +%= 1;
        var t_o = self.next_connection_id;
        self.next_connection_id +%= 1;
        const multicast = fo.t_to_o_params.connection_type == .multicast;
        var dest: ?encap.SocketAddress = null;
        if (multicast) {
            const group = self.io_multicast.take() orelse return ioRefusal(svc, .no_available_link_consumer, out);
            dest = .{ .port = encap.io_udp_port, .addr = group };
            self.rr_reply_sockaddr = dest;
        } else {
            // Point to point: the originator names the T→O connection id,
            // and may name the address it wants the data sent to.
            if (fo.t_to_o_connection_id != 0) t_o = fo.t_to_o_connection_id;
            dest = self.rr_t_to_o;
        }
        slot.* = .{
            .in_use = true,
            .o_to_t_id = o_t,
            .t_to_o_id = t_o,
            .serial = fo.connection_serial,
            .vendor = fo.originator_vendor_id,
            .originator_serial = fo.originator_serial,
            .io = implicit.Connection.init(.{
                .class = class,
                .trigger = trigger,
                .produce_id = t_o,
                .consume_id = o_t,
                .produce_rpi_us = fo.t_to_o_rpi,
                .consume_rpi_us = fo.o_to_t_rpi,
                .timeout_multiplier = fo.connection_timeout_multiplier,
                .produce_header = produce_header,
                .consume_header = consume_header,
                .consume_len = if (consume != null) consume_len else null,
            }, self.io_now_us),
            .consume_asm = consume,
            .produce_asm = produce,
            .consume_len = consume_len,
            .produce_len = produce_len,
            .dest = dest,
            .multicast = multicast,
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
            .service = svc,
            .general_status = .success,
            .additional_status = &.{},
            .data = encoded,
        }).encode(out) catch error.BufferTooSmall;
    }

    fn findIo(self: *Adapter, connection_id: u32) ?*OpenConnection {
        for (&self.connections) |*c| {
            if (c.in_use and c.io != null and c.io.?.cfg.consume_id == connection_id) return c;
        }
        return null;
    }

    /// Takes one datagram that arrived on UDP 2222 (or on a multicast group
    /// the caller joined) at `now_us`. New data is written into the
    /// connection's consuming assembly and its `after_set` hook runs; data
    /// under an Idle header is not applied.
    pub fn ioReceive(self: *Adapter, now_us: u64, datagram: []const u8) IoReceived {
        self.io_now_us = now_us;
        var storage: [4]cpf.Item = undefined;
        const list = cpf.decode(datagram, &storage) catch return .unknown_connection;
        const addr = cpf.SequencedAddress.decode(list.addressItem() orelse return .unknown_connection) catch
            return .unknown_connection;
        const c = self.findIo(addr.connection_id) orelse return .unknown_connection;
        const id = addr.connection_id;
        switch (c.io.?.receive(now_us, datagram)) {
            .dropped => |why| return .{ .dropped = .{ .connection_id = id, .reason = switch (why) {
                .closed => .closed,
                .stale => .stale,
                .wrong_size => .wrong_size,
                else => .malformed,
            } } },
            .heartbeat => return .{ .heartbeat = .{ .connection_id = id } },
            .data => |d| {
                const a = stdobj.assemblyFind(self.cfg.assemblies, c.consume_asm orelse return .unknown_connection) orelse
                    return .unknown_connection;
                if (!d.run) return .{ .idle = .{ .connection_id = id } };
                @memcpy(a.data, d.payload);
                if (a.after_set) |hook| _ = hook(a.ctx, a.data);
                self.io_consumed += 1;
                return .{ .applied = .{ .connection_id = id, .missed = d.missed } };
            },
        }
    }

    /// The next datagram an I/O connection has due, built into `out`; call it
    /// until it returns `null`. It also retires every connection whose
    /// watchdog ran out (`io_timeouts`), so call it on a timer as well as
    /// after receiving; `ioNextDueUs` says when.
    pub fn ioPoll(self: *Adapter, now_us: u64, out: []u8) ?IoDatagram {
        self.io_now_us = now_us;
        for (&self.connections) |*c| {
            if (!c.in_use) continue;
            const io = &(c.io orelse continue);
            if (io.check(now_us) != null) {
                c.in_use = false;
                c.io = null;
                self.io_timeouts += 1;
                continue;
            }
            const pid = c.produce_asm orelse continue;
            const a = stdobj.assemblyFind(self.cfg.assemblies, pid) orelse continue;
            if (a.before_get) |hook| hook(a.ctx, a.data);
            const h = std.hash.Wyhash.hash(0, a.data);
            const changed = h != c.last_hash;
            const bytes = io.produce(now_us, a.data, changed, true, out) catch continue;
            if (bytes) |b| {
                c.last_hash = h;
                self.io_produced += 1;
                return .{ .to = c.dest, .multicast = c.multicast, .bytes = b };
            }
        }
        return null;
    }

    /// The earliest time `ioPoll` has something to do, or `null` when no I/O
    /// connection is open.
    pub fn ioNextDueUs(self: *const Adapter) ?u64 {
        var best: ?u64 = null;
        for (self.connections) |c| {
            if (!c.in_use) continue;
            const io = c.io orelse continue;
            const t = io.nextDueUs() orelse continue;
            if (best == null or t < best.?) best = t;
        }
        return best;
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
        // The whole offset table is validated BEFORE any embedded request
        // runs. `at(i)` checks entries `i` and `i + 1` only, so validating
        // lazily applied a write in entry 0 and then refused the packet over
        // entry 2 — a refusal that reads as "nothing happened" to the
        // originator while the tag had changed (review 2026-10-06).
        var embedded: [max_batch][]const u8 = undefined;
        for (0..ms.count) |i| {
            embedded[i] = ms.at(i) catch
                return errorReply(req.service, .invalid_parameter_value, out);
        }

        // Every octet of the reply is budgeted before anything runs: the
        // reply header (4), the count and offset table, and one minimal
        // reply (4) for each embedded request still to come. Without that a
        // large read early in the batch exhausted the space, and the overflow
        // left `handle` as `error.BufferTooSmall` — no reply at all — after
        // earlier writes in the same batch had been applied (review
        // 2026-10-06). `max_reply` binds here as it does for a single read.
        var scratch: [4096]u8 = undefined;
        var payload: [4096]u8 = undefined;
        const min_reply: usize = 4;
        const cap = @min(@min(out.len, self.cfg.max_reply), @min(scratch.len, payload.len));
        const overhead = 4 + 2 + 2 * ms.count;
        if (cap < overhead + min_reply * ms.count) {
            return errorReply(req.service, .reply_data_too_large, out);
        }
        const budget = cap - overhead;

        var replies: [max_batch][]const u8 = undefined;
        var used: usize = 0;
        for (0..ms.count) |i| {
            // Invariant: `used <= budget - min_reply * (count - i)`, so `room`
            // always holds at least one minimal reply.
            const limit = budget - min_reply * (ms.count - i - 1);
            const room = scratch[used..limit];
            const r = self.route(embedded[i], room, depth + 1) catch |e| switch (e) {
                // Every handler that changes state checks its reply fits
                // before changing it, so an overflow here has changed
                // nothing: this entry alone is answered as too large.
                error.BufferTooSmall => try errorReply(
                    if (embedded[i].len > 0) embedded[i][0] & 0x7F else 0,
                    .reply_data_too_large,
                    room,
                ),
                else => return e,
            };
            replies[i] = r;
            used += r.len;
        }
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
        if (class != null and class.? == @backingInt(cip.ClassCode.program_name)) {
            return self.programName(req, out);
        }
        if (class != null and class.? == @backingInt(cip.ClassCode.tcp_ip_interface)) {
            return self.tcpipGet(req, null, out);
        }
        if (class != null and class.? == @backingInt(cip.ClassCode.ethernet_link)) {
            return self.ethLinkGet(req, null, out);
        }
        // The Assembly class has no Get_Attributes_All service (OpENer
        // registers only the single-attribute pair on it).
        if (class != null and class.? == @backingInt(cip.ClassCode.assembly) and
            self.cfg.assemblies.len != 0)
        {
            return errorReply(req.service, .service_not_supported, out);
        }
        if (class == null or class.? != @backingInt(cip.ClassCode.identity)) {
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
        if (class != null and class.? == @backingInt(cip.ClassCode.tcp_ip_interface)) {
            return self.tcpipGet(req, (epath.findLogical(req.path, .attribute) catch null), out);
        }
        if (class != null and class.? == @backingInt(cip.ClassCode.ethernet_link)) {
            return self.ethLinkGet(req, (epath.findLogical(req.path, .attribute) catch null), out);
        }
        if (class != null and class.? == @backingInt(cip.ClassCode.assembly) and
            self.cfg.assemblies.len != 0)
        {
            return self.assemblyGet(req, out);
        }
        if (class == null or class.? != @backingInt(cip.ClassCode.identity)) {
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
                body[0] = @backingInt(self.cfg.state);
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

    /// The TCP/IP Interface object (class 0xF5, instance 1). `attr == null`
    /// is `Get_Attributes_All`; a `Get_Attribute_Single` without an attribute
    /// segment is told apart by the caller passing the service.
    fn tcpipGet(self: *Adapter, req: cip.Request, attr: ?u32, out: []u8) Error![]const u8 {
        const cfg = self.cfg.tcpip orelse
            return errorReply(req.service, .path_destination_unknown, out);
        const instance = (epath.findLogical(req.path, .instance) catch null) orelse 0;
        if (instance != 1) return errorReply(req.service, .path_destination_unknown, out);
        var body: [256]u8 = undefined;
        const n: usize = blk: {
            if (req.service == @backingInt(cip.Service.get_attributes_all)) {
                break :blk stdobj.tcpipAll(cfg, &self.tcpip_state, self.cfg.allow_tcpip_set, &body) catch
                    return error.BufferTooSmall;
            }
            const a = attr orelse return errorReply(req.service, .path_segment_error, out);
            if (a > std.math.maxInt(u16)) return errorReply(req.service, .attribute_not_supported, out);
            const got = stdobj.tcpipAttribute(cfg, &self.tcpip_state, self.cfg.allow_tcpip_set, @intCast(a), &body) catch
                return error.BufferTooSmall;
            break :blk got orelse return errorReply(req.service, .attribute_not_supported, out);
        };
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = body[0..n],
        }).encode(out) catch error.BufferTooSmall;
    }

    /// The Ethernet Link object (class 0xF6, instance 1): attributes 1 to 3.
    fn ethLinkGet(self: *Adapter, req: cip.Request, attr: ?u32, out: []u8) Error![]const u8 {
        const cfg = self.cfg.ethernet_link orelse
            return errorReply(req.service, .path_destination_unknown, out);
        const instance = (epath.findLogical(req.path, .instance) catch null) orelse 0;
        if (instance != 1) return errorReply(req.service, .path_destination_unknown, out);
        var body: [16]u8 = undefined;
        const n: usize = blk: {
            if (req.service == @backingInt(cip.Service.get_attributes_all)) {
                break :blk stdobj.ethLinkAll(cfg, &body);
            }
            const a = attr orelse return errorReply(req.service, .path_segment_error, out);
            if (a > std.math.maxInt(u16)) return errorReply(req.service, .attribute_not_supported, out);
            break :blk stdobj.ethLinkAttribute(cfg, @intCast(a), &body) orelse
                return errorReply(req.service, .attribute_not_supported, out);
        };
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = body[0..n],
        }).encode(out) catch error.BufferTooSmall;
    }

    /// The Assembly object (class 0x04): `Get_Attribute_Single` on the class
    /// (instance 0) or on an instance (attributes 3 and 4).
    fn assemblyGet(self: *Adapter, req: cip.Request, out: []u8) Error![]const u8 {
        const instance = (epath.findLogical(req.path, .instance) catch null) orelse 0;
        const attr = (epath.findLogical(req.path, .attribute) catch null) orelse
            return errorReply(req.service, .path_segment_error, out);
        if (instance == 0) {
            var cb: [2]u8 = undefined;
            const n = if (attr > std.math.maxInt(u16)) null else stdobj.assemblyClassAttribute(self.cfg.assemblies, @intCast(attr), &cb);
            return (cip.Reply{
                .service = req.service,
                .general_status = if (n == null) .attribute_not_supported else .success,
                .additional_status = &.{},
                .data = if (n) |len| cb[0..len] else &.{},
            }).encode(out) catch error.BufferTooSmall;
        }
        const a = stdobj.assemblyFind(self.cfg.assemblies, instance) orelse
            return errorReply(req.service, .path_destination_unknown, out);
        var size: [2]u8 = undefined;
        const value: []const u8 = switch (attr) {
            stdobj.AssemblyAttr.data => blk: {
                if (a.before_get) |hook| hook(a.ctx, a.data);
                break :blk a.data;
            },
            stdobj.AssemblyAttr.size => blk: {
                std.mem.writeInt(u16, &size, @intCast(a.data.len), .little);
                break :blk &size;
            },
            else => return errorReply(req.service, .attribute_not_supported, out),
        };
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = value,
        }).encode(out) catch error.BufferTooSmall;
    }

    /// `Set_Attribute_Single` on the Assembly class: the class has no such
    /// service (instance 0, `service_not_supported`); on an instance only
    /// attribute 3 of a writable one is settable.
    fn assemblySetAttr(self: *Adapter, req: cip.Request, out: []u8) Error![]const u8 {
        const instance = (epath.findLogical(req.path, .instance) catch null) orelse 0;
        if (instance == 0) return errorReply(req.service, .service_not_supported, out);
        const a = stdobj.assemblyFind(self.cfg.assemblies, instance) orelse
            return errorReply(req.service, .path_destination_unknown, out);
        const attr = (epath.findLogical(req.path, .attribute) catch null) orelse
            return errorReply(req.service, .path_segment_error, out);
        if (attr > std.math.maxInt(u16)) return errorReply(req.service, .attribute_not_supported, out);
        return errorReply(req.service, stdobj.assemblySet(a, @intCast(attr), req.data), out);
    }

    fn tcpipSet(self: *Adapter, req: cip.Request, out: []u8) Error![]const u8 {
        const cfg = self.cfg.tcpip orelse
            return errorReply(req.service, .path_destination_unknown, out);
        const instance = (epath.findLogical(req.path, .instance) catch null) orelse 0;
        if (instance != 1) return errorReply(req.service, .path_destination_unknown, out);
        const attr = (epath.findLogical(req.path, .attribute) catch null) orelse
            return errorReply(req.service, .path_segment_error, out);
        if (attr > std.math.maxInt(u16)) return errorReply(req.service, .attribute_not_supported, out);
        const status = stdobj.tcpipSet(cfg, &self.tcpip_state, self.cfg.allow_tcpip_set, @intCast(attr), req.data);
        return errorReply(req.service, status, out);
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

    // ── the Template Object (class 0x6C) ──────────────────────────────────

    /// What a Template Object reads as: the member definitions (8 octets
    /// each: `info` = array length, `type` = the symbol type word, `offset`),
    /// then the template name with its `;n` suffix and the member names, each
    /// NUL-terminated, and NULs up to the length the definition size
    /// (attribute 4, in 32-bit words, less the 23 octets a Logix controller
    /// does not return) promises. Written into `out`; null when it does not
    /// fit.
    fn templateBytes(u: *const Udt, out: []u8) ?[]const u8 {
        var n: usize = 0;
        for (u.members) |m| {
            if (out.len < n + 8) return null;
            const ty: u16 = if (m.udt) |nested|
                0x8000 | (nested.id & 0x0FFF)
            else
                @as(u16, @truncate(@backingInt(m.type))) & 0x00FF;
            const type_word = ty | (if (m.array_len > 0) @as(u16, 0x2000) else 0);
            std.mem.writeInt(u16, out[n..][0..2], m.array_len, .little);
            std.mem.writeInt(u16, out[n + 2 ..][0..2], type_word, .little);
            std.mem.writeInt(u32, out[n + 4 ..][0..4], m.offset, .little);
            n += 8;
        }
        if (out.len < n + u.name.len + 3) return null;
        @memcpy(out[n..][0..u.name.len], u.name);
        n += u.name.len;
        out[n] = ';';
        out[n + 1] = 'n';
        out[n + 2] = 0;
        n += 3;
        for (u.members) |m| {
            if (out.len < n + m.name.len + 1) return null;
            @memcpy(out[n..][0..m.name.len], m.name);
            n += m.name.len;
            out[n] = 0;
            n += 1;
        }
        const padded = templateLen(n);
        if (out.len < padded) return null;
        @memset(out[n..padded], 0);
        return out[0..padded];
    }

    /// The template read length for `n` octets of definition: the least
    /// length that makes `(n + 23)` a whole number of 32-bit words, which is
    /// what attribute 4 can express.
    fn templateLen(n: usize) usize {
        const words = (n + 23 + 3) / 4;
        return words * 4 - 23;
    }

    fn findTemplate(self: *const Adapter, path: []const u8) ?*const Udt {
        const id = (epath.findLogical(path, .instance) catch null) orelse return null;
        for (self.cfg.udts) |*u| {
            if (u.id == id) return u;
        }
        return null;
    }

    /// `Get_Attribute_List` (0x03) on a template instance: attributes 1
    /// (structure handle, UINT), 2 (member count, UINT), 4 (definition size in
    /// 32-bit words, UDINT) and 5 (structure size in octets, UDINT). The reply
    /// is the count, then per attribute its id, a status (0, or 0x14 for one
    /// that is not served, with no value) and the value.
    fn templateAttributeList(self: *Adapter, req: cip.Request, out: []u8) Error![]const u8 {
        const u = self.findTemplate(req.path) orelse
            return errorReply(req.service, .path_destination_unknown, out);
        if (req.data.len < 2) return errorReply(req.service, .not_enough_data, out);
        const count = std.mem.readInt(u16, req.data[0..2], .little);
        if (req.data.len < 2 + @as(usize, count) * 2) return errorReply(req.service, .not_enough_data, out);
        var scratch: [4096]u8 = undefined;
        const body_len = templateBytes(u, &scratch) orelse return errorReply(req.service, .reply_data_too_large, out);
        const def_words: u32 = @intCast((body_len.len + 23) / 4);

        var body: [128]u8 = undefined;
        std.mem.writeInt(u16, body[0..2], count, .little);
        var n: usize = 2;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const attr = std.mem.readInt(u16, req.data[2 + i * 2 ..][0..2], .little);
            if (n + 4 + 4 > body.len) return errorReply(req.service, .reply_data_too_large, out);
            std.mem.writeInt(u16, body[n..][0..2], attr, .little);
            switch (attr) {
                1 => {
                    std.mem.writeInt(u16, body[n + 2 ..][0..2], 0, .little);
                    std.mem.writeInt(u16, body[n + 4 ..][0..2], u.handle, .little);
                    n += 6;
                },
                2 => {
                    std.mem.writeInt(u16, body[n + 2 ..][0..2], 0, .little);
                    std.mem.writeInt(u16, body[n + 4 ..][0..2], @intCast(u.members.len), .little);
                    n += 6;
                },
                4 => {
                    std.mem.writeInt(u16, body[n + 2 ..][0..2], 0, .little);
                    std.mem.writeInt(u32, body[n + 4 ..][0..4], def_words, .little);
                    n += 8;
                },
                5 => {
                    std.mem.writeInt(u16, body[n + 2 ..][0..2], 0, .little);
                    std.mem.writeInt(u32, body[n + 4 ..][0..4], u.size, .little);
                    n += 8;
                },
                else => {
                    std.mem.writeInt(u16, body[n + 2 ..][0..2], @backingInt(cip.GeneralStatus.attribute_not_supported), .little);
                    n += 4;
                },
            }
        }
        return (cip.Reply{
            .service = req.service,
            .general_status = .success,
            .additional_status = &.{},
            .data = body[0..n],
        }).encode(out) catch error.BufferTooSmall;
    }

    /// Read Template (0x4C on class 0x6C): `UDINT offset, UINT count` in, the
    /// definition octets from there out, as `partial_transfer` when they do not
    /// fit one reply.
    fn templateRead(self: *Adapter, req: cip.Request, out: []u8) Error![]const u8 {
        const u = self.findTemplate(req.path) orelse
            return errorReply(req.service, .path_destination_unknown, out);
        if (req.data.len < 6) return errorReply(req.service, .not_enough_data, out);
        const offset = std.mem.readInt(u32, req.data[0..4], .little);
        const want = std.mem.readInt(u16, req.data[4..6], .little);
        var scratch: [4096]u8 = undefined;
        const all = templateBytes(u, &scratch) orelse return errorReply(req.service, .reply_data_too_large, out);
        if (offset > all.len) return errorReply(req.service, .invalid_parameter_value, out);
        const room = @min(self.cfg.max_reply, out.len) -| 8;
        const avail = all[offset..];
        const give = @min(@min(avail.len, want), room);
        return (cip.Reply{
            .service = req.service,
            .general_status = if (give < @min(avail.len, want)) .partial_transfer else .success,
            .additional_status = &.{},
            .data = avail[0..give],
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
        if (class != @backingInt(cip.ClassCode.symbol)) return null;
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

    /// `pathElement(path) * esize + byte_offset`, or null when that does not
    /// fit a `usize`.
    fn elementOffset(path: []const u8, esize: usize, byte_offset: usize) ?usize {
        const elem = std.math.mul(usize, pathElement(path), esize) catch return null;
        return std.math.add(usize, elem, byte_offset) catch null;
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
        // The member id and `byte_offset` are both peer-supplied u32s; their
        // octet offset can overflow a 32-bit `usize`, and one that does is
        // out of range, not a trap (review 2026-10-06).
        const start = elementOffset(req.path, esize, byte_offset) orelse
            return errorReply(req.service, .invalid_parameter_value, out);
        if (start > tag.bytes.len) return errorReply(req.service, .invalid_parameter_value, out);
        const want = @min(count * esize, tag.bytes.len - start);
        // The reply must fit both the caller's buffer and the configured
        // ceiling; whatever does not fit comes back as a partial transfer,
        // which is exactly what the fragmented service is for.
        const room = @min(self.cfg.max_reply, out.len) -| 8;
        const give = @min(want, room);
        const partial = give < want;

        var body: [4096]u8 = undefined;
        const td = types.TagData{
            .type = tag.type,
            .structure_handle = if (tag.udt) |u| u.handle else null,
            .data = tag.bytes[start..][0..give],
        };
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
        const start = elementOffset(req.path, esize, byte_offset) orelse
            return errorReply(req.service, .too_much_data, out);
        if (start > tag.bytes.len or values.len > tag.bytes.len - start) {
            return errorReply(req.service, .too_much_data, out);
        }
        // No state change without room to report it (see `multipleService`).
        if (out.len < 4) return error.BufferTooSmall;
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
